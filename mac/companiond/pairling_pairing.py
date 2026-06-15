#!/usr/bin/env python3
"""Short-lived Pairling pairing records and claim flow."""

from __future__ import annotations

import base64
import json
import os
import secrets
import socket
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from pairling_devices import CreatedDevice, DeviceRegistry
from runtime_contract import DEFAULT_DEVICE_SCOPES, PAIR_SERVICE_TYPE, PORT
from runtime_paths import app_support_root

try:
    from runtime_contract import RUNTIME_NAME
except Exception:
    RUNTIME_NAME = "pairling-mac-runtime"

try:
    from pairling_relay_claims import RelayClaimError, RelayClaimVerifier
except Exception:
    RelayClaimError = None
    RelayClaimVerifier = None

try:
    from app_attest_lan import direct_attest_required as _direct_attest_required
    from app_attest_lan import verify_attestation as _verify_direct_attestation
except Exception:
    def _direct_attest_required() -> bool:
        return False
    _verify_direct_attestation = None

try:
    import pairling_psk as _psk
except Exception:
    _psk = None


def _psk_required() -> bool:
    # PSK-authenticated ECDH is the only MITM-safe pairing path, so it is REQUIRED by
    # default. Only an explicit opt-out ("0"/"false"/"no"/"off") permits the legacy
    # plaintext /pair/claim — used by contract tests that exercise the legacy branch on
    # purpose, and as a break-glass if the crypto module is ever unavailable.
    return os.environ.get("PAIRLING_PSK_REQUIRED", "on").strip().lower() not in {"0", "false", "no", "off"}


# Boot-time hard-dependency assertion. With PSK required by default, the cryptography
# module (imported by pairling_psk) is a hard runtime dependency: if it failed to import,
# fail LOUD here at daemon startup instead of silently returning 503 from every
# /pair/psk-claim while legacy is closed — which would brick pairing entirely. Set
# PAIRLING_PSK_REQUIRED=0 to fall back to legacy plaintext pairing when crypto is absent.
if _psk is None and _psk_required():
    raise RuntimeError(
        "Pairling pairing requires the 'cryptography' package (pairling_psk failed to "
        "import) because PAIRLING_PSK_REQUIRED is on by default. Install cryptography, or "
        "set PAIRLING_PSK_REQUIRED=0 to permit the legacy plaintext claim."
    )


DEFAULT_PAIR_TTL_SECONDS = 180
MIN_PAIR_TTL_SECONDS = 60
MAX_PAIR_TTL_SECONDS = 300


def _nonce_required() -> bool:
    return os.environ.get("PAIRLING_NONCE_REQUIRED", "").strip().lower() in {"1", "true", "yes", "on"}


def verify_p256_signature(point_b64: str, message: bytes, signature_der: bytes) -> bool:
    """Verify an ECDSA-P256-SHA256 signature from the iOS Secure Enclave.

    point_b64 is the base64 X9.63 public key (04 || X || Y) returned by
    SecKeyCopyExternalRepresentation; signature_der is the DER (X9.62) ECDSA
    signature from SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256).
    Constant-time / exception-safe: any malformed input returns False.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
    except Exception:
        return False
    if not point_b64 or not signature_der:
        return False
    try:
        point = base64.b64decode(point_b64)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        public_key.verify(signature_der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class ReauthStore:
    """WS4: short-lived per-device challenges for zero-interaction re-pair.

    A challenge is issued for ANY device_id (even unknown) so the endpoint is
    not a device-existence oracle. Verification fails uniformly when the device
    is unknown, revoked, has no SE key, or the signature does not check out.
    """

    def __init__(self, registry: DeviceRegistry, *, ttl_seconds: int = 120):
        self.registry = registry
        self.ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._challenges: dict[str, tuple[str, float]] = {}

    def issue_challenge(self, device_id: str) -> str:
        challenge = secrets.token_hex(32)
        with self._lock:
            self._challenges[device_id] = (challenge, time.time() + self.ttl_seconds)
        return challenge

    def verify_and_consume(self, device_id: str, challenge: str, signature_der: bytes) -> bool:
        # Single-use: pop regardless of outcome so a captured challenge cannot
        # be replayed even if the first signature was wrong.
        with self._lock:
            entry = self._challenges.pop(device_id, None)
        if entry is None:
            return False
        stored_challenge, expires_at = entry
        if time.time() > expires_at:
            return False
        if not secrets.compare_digest(stored_challenge, challenge or ""):
            return False
        point_b64 = self.registry.get_se_pubkey(device_id)
        if not point_b64:
            return False
        return verify_p256_signature(point_b64, challenge.encode("ascii"), signature_der)


@dataclass(frozen=True)
class PairStart:
    pair_id: str
    secret: str
    expires_at: float
    install_id: str
    service_type: str
    txt: dict[str, str]
    pairing_nonce: str = ""
    attest_challenge: str = ""
    mac_ake_pub: str = ""


@dataclass(frozen=True)
class PairClaim:
    device: CreatedDevice
    host_chain: tuple[str, ...]
    runtime_port: int
    cert_pin: str | None
    relay_device_id: str | None = None
    attestation_status: str = "none"


class PairingError(Exception):
    def __init__(self, code: str, status: int, message: str):
        super().__init__(message)
        self.code = code
        self.status = status
        self.message = message


class PairingStore:
    def __init__(
        self,
        pair_root: Path,
        registry: DeviceRegistry,
        *,
        runtime_port: int = PORT,
        install_id: str | None = None,
    ):
        self.pair_root = pair_root
        self.registry = registry
        self.runtime_port = runtime_port
        self.install_id = install_id or self._load_install_id_from_config()
        self._claim_lock = threading.Lock()
        # P0-B: per-pair_id wrong-guess counter, pre-checked before secret
        # comparison so a racing attacker cannot brute the secret/nonce.
        # In-process only; the pair_id TTL is the outer bound on staleness.
        self._claim_attempts: dict[str, int] = {}

    def _computer_name(self) -> str:
        try:
            proc = subprocess.run(
                ["/usr/sbin/scutil", "--get", "ComputerName"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            value = (proc.stdout or "").strip()
            if proc.returncode == 0 and value:
                return value[:64]
        except Exception:
            pass
        return socket.gethostname()[:64]

    def _mac_model(self) -> str:
        try:
            proc = subprocess.run(
                ["/usr/sbin/sysctl", "-n", "hw.model"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            value = (proc.stdout or "").strip()
            if proc.returncode == 0 and value:
                return value[:64]
        except Exception:
            pass
        return "Mac"

    def _runtime_version(self) -> str:
        return os.environ.get("COMPANION_RUNTIME_VERSION", RUNTIME_NAME)[:64]

    def _load_install_id_from_config(self) -> str:
        config = self.pair_root.parent / "config.json"
        try:
            payload = json.loads(config.read_text())
            value = payload.get("install_id")
            if isinstance(value, str) and value:
                return value
        except Exception:
            pass
        return "inst_" + secrets.token_hex(16)

    def _ensure_pair_root(self) -> None:
        self.pair_root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.pair_root, stat.S_IRWXU)
        except OSError:
            pass

    def _record_path(self, pair_id: str) -> Path:
        if not pair_id or not all(c.isalnum() or c in {"_", "-"} for c in pair_id):
            raise PairingError("invalid_pair_id", 400, "invalid pair id")
        return self.pair_root / f"{pair_id}.json"

    def _claim_marker_path(self, pair_id: str) -> Path:
        return self._record_path(pair_id).with_suffix(".claim")

    def _create_claim_marker(self, pair_id: str) -> Path:
        self._ensure_pair_root()
        marker = self._claim_marker_path(pair_id)
        try:
            fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise PairingError("pair_already_claimed", 409, "pair record already claimed")
        else:
            os.close(fd)
        return marker

    def start_pair(self, *, ttl_seconds: int = DEFAULT_PAIR_TTL_SECONDS) -> PairStart:
        ttl = max(MIN_PAIR_TTL_SECONDS, min(int(ttl_seconds), MAX_PAIR_TTL_SECONDS))
        pair_id = "pair_" + secrets.token_hex(8)
        secret = secrets.token_urlsafe(24)
        # P0-A: the nonce now lives in the on-disk record (it used to be
        # generated only into the Bonjour TXT, so claim_pair() could never
        # verify it). Both the Bonjour TXT and the QR claim payload carry it,
        # so either path can present it back.
        pairing_nonce = secrets.token_urlsafe(9)
        # WS2: per-invitation App Attest challenge. The iOS app binds its
        # attestation to canonical(pair_id, attest_challenge); the Mac verifies
        # against this stored value, so a MITM cannot swap it (Blocker #6).
        attest_challenge = secrets.token_hex(32)
        # WS3: per-invitation Mac ephemeral ECDH key. A_pub goes in the OOB
        # payload (QR/paste); the private half is stored in this mode-600 record
        # so the claim can run a PSK-authenticated ECDH and the secret is never
        # transmitted. Absent when the crypto module is unavailable (legacy only).
        mac_ake_pub = ""
        mac_ake_priv_b64 = ""
        if _psk is not None:
            _ake_priv, _ake_pub = _psk.mac_keygen()
            mac_ake_pub = base64.urlsafe_b64encode(_ake_pub).rstrip(b"=").decode("ascii")
            mac_ake_priv_b64 = base64.b64encode(_psk.dump_private(_ake_priv)).decode("ascii")
        expires_at = time.time() + ttl
        record = {
            "pair_id": pair_id,
            "secret": secret,
            "pairing_nonce": pairing_nonce,
            "attest_challenge": attest_challenge,
            "mac_ake_pub": mac_ake_pub,
            "mac_ake_priv": mac_ake_priv_b64,
            "created_at": time.time(),
            "expires_at": expires_at,
            "claimed_at": None,
            "install_id": self.install_id,
            "runtime_port": self.runtime_port,
        }
        self._ensure_pair_root()
        path = self._record_path(pair_id)
        tmp = path.with_suffix(".json.tmp")
        with tmp.open("w") as fh:
            json.dump(record, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        txt = {
            "pair_id": pair_id,
            "version": "2",
            "expires": str(int(expires_at)),
            "install_id": self.install_id,
            "runtime_port": str(self.runtime_port),
            "mac_name": self._computer_name(),
            "mac_model": self._mac_model(),
            "runtime_version": self._runtime_version(),
            "pairing_nonce": pairing_nonce,
            "route_hint": os.environ.get("PAIRLING_ROUTE_HINT", "lan,bonjour,tailnet")[:64],
        }
        return PairStart(
            pair_id, secret, expires_at, self.install_id, PAIR_SERVICE_TYPE, txt,
            pairing_nonce, attest_challenge, mac_ake_pub,
        )

    def _load_record(self, pair_id: str) -> tuple[dict, Path]:
        path = self._record_path(pair_id)
        try:
            record = json.loads(path.read_text())
        except FileNotFoundError:
            raise PairingError("pair_not_found", 404, "pair record not found")
        except json.JSONDecodeError as exc:
            raise PairingError("pair_corrupt", 500, f"pair record is corrupt: {exc}")
        if not isinstance(record, dict):
            raise PairingError("pair_corrupt", 500, "pair record is not an object")
        return record, path

    def claim_pair(
        self,
        *,
        pair_id: str,
        secret: str,
        device_name: str,
        host_chain: Iterable[str],
        scopes: Iterable[str] | None = None,
        cert_pin: str | None = None,
        pairing_nonce: str = "",
        se_public_key_der: str = "",
        attest_object: dict | None = None,
        attest_key_id: str = "",
        attest_environment: str = "",
        attested_claim_ticket: str | None = None,
        relay_device_id: str | None = None,
        relay_required: bool = False,
        relay_claim_verifier=None,
    ) -> PairClaim:
        with self._claim_lock:
            record, path, now = self._precheck_claim(pair_id)
            # WS3: once PSK pairing is mandatory, reject legacy plaintext-secret
            # claims outright — the secret must never cross the wire. New clients
            # use /pair/psk-claim instead.
            if _psk_required():
                raise PairingError("psk_required", 403, "psk-authenticated pairing required")
            if not secrets.compare_digest(str(record.get("secret") or ""), secret or ""):
                raise PairingError("invalid_secret", 403, "invalid pair secret")
            # P0-A: nonce gate (default off via PAIRLING_NONCE_REQUIRED). Both
            # the QR claim payload and the Bonjour TXT carry pairing_nonce, so
            # legitimate claims on either path present it; an attacker who only
            # hit /pair/start blind (never saw the TXT/QR) cannot.
            if _nonce_required():
                if not secrets.compare_digest(str(record.get("pairing_nonce") or ""), pairing_nonce or ""):
                    raise PairingError("invalid_pairing_nonce", 403, "invalid pairing nonce")
            return self._finalize_claim(
                pair_id=pair_id, record=record, path=path, now=now,
                device_name=device_name, host_chain=host_chain, scopes=scopes,
                cert_pin=cert_pin, se_public_key_der=se_public_key_der,
                attest_object=attest_object, attest_key_id=attest_key_id,
                attest_environment=attest_environment,
                attested_claim_ticket=attested_claim_ticket,
                relay_device_id=relay_device_id, relay_required=relay_required,
                relay_claim_verifier=relay_claim_verifier,
            )

    def _precheck_claim(self, pair_id: str) -> tuple[dict, Path, float]:
        """Shared front-matter for both claim paths (caller holds _claim_lock):
        load the record, reject already-claimed/expired, and pre-increment the
        per-pair_id attempt counter so wrong guesses lock out after 5 (P0-B)."""
        record, path = self._load_record(pair_id)
        now = time.time()
        if record.get("claimed_at") is not None:
            raise PairingError("pair_already_claimed", 409, "pair record already claimed")
        if now > float(record.get("expires_at") or 0):
            self._delete_record(path)
            self._claim_attempts.pop(pair_id, None)
            raise PairingError("pair_expired", 410, "pair record expired")
        attempts = self._claim_attempts.get(pair_id, 0) + 1
        self._claim_attempts[pair_id] = attempts
        if attempts > 5:
            raise PairingError("pair_locked", 429, "too many claim attempts")
        return record, path, now

    def _finalize_claim(
        self,
        *,
        pair_id: str,
        record: dict,
        path: Path,
        now: float,
        device_name: str,
        host_chain: Iterable[str],
        scopes: Iterable[str] | None,
        cert_pin: str | None,
        se_public_key_der: str,
        attest_object: dict | None,
        attest_key_id: str,
        attest_environment: str,
        attested_claim_ticket: str | None,
        relay_device_id: str | None,
        relay_required: bool,
        relay_claim_verifier,
    ) -> PairClaim:
        """Post-authentication finalize, shared by legacy and PSK claims. The
        caller holds _claim_lock and has already proven secret-knowledge (legacy
        compare or PSK key-confirmation): App Attest, relay ticket, device
        creation, SE pubkey registration, record teardown."""
        # WS2: direct-LAN App Attest. When required (or opportunistically
        # supplied), the claimant must present a valid Apple attestation bound to
        # this invitation. Fails closed if the validator is unavailable while on.
        if _direct_attest_required() or attest_object:
            if not attest_object:
                raise PairingError("direct_attest_required", 403, "app attest required")
            if _verify_direct_attestation is None:
                raise PairingError("direct_attest_unavailable", 503, "app attest validator unavailable")
            try:
                _verify_direct_attestation(
                    attestation=attest_object,
                    pair_id=pair_id,
                    attest_challenge=str(record.get("attest_challenge") or ""),
                    key_id=attest_key_id,
                    environment=attest_environment,
                )
            except PairingError:
                raise
            except Exception:
                raise PairingError("direct_attest_invalid", 403, "app attest validation failed")
        relay_status = "none"
        verified_relay_device_id = relay_device_id
        relay_pair_secret = None
        relay_pair_secret_ref = None
        if relay_required or attested_claim_ticket:
            if not attested_claim_ticket:
                raise PairingError("attested_claim_required", 403, "relay claim ticket required")
            if relay_claim_verifier is None:
                raise PairingError("attested_claim_invalid", 403, "relay claim verifier unavailable")
            try:
                verification = relay_claim_verifier.verify(
                    attested_claim_ticket,
                    pair_id=pair_id,
                    relay_device_id=relay_device_id,
                    device_name=device_name,
                )
            except Exception as exc:
                code = getattr(exc, "code", "attested_claim_invalid")
                message = getattr(exc, "message", str(exc))
                raise PairingError(code, 403, message)
            verified_relay_device_id = verification.relay_device_id
            relay_status = verification.attestation_status
            relay_pair_secret = getattr(verification, "relay_pair_secret", None)
            relay_pair_secret_ref = getattr(verification, "relay_pair_secret_ref", None)
        normalized_hosts = tuple(h for h in host_chain if isinstance(h, str) and h)
        if not normalized_hosts:
            raise PairingError("missing_host_chain", 500, "host chain is empty")
        marker = self._create_claim_marker(pair_id)
        try:
            device = self.registry.create_device(
                device_name=device_name or "Pairling iPhone",
                install_id=str(record.get("install_id") or self.install_id),
                scopes=scopes or DEFAULT_DEVICE_SCOPES,
                relay_device_id=verified_relay_device_id,
                attestation_status=relay_status,
                device_display_name=device_name or "Pairling iPhone",
                relay_pair_secret_ref=relay_pair_secret_ref,
            )
            if relay_pair_secret and verified_relay_device_id:
                self._store_relay_pair_secret(
                    device_id=device.device_id,
                    relay_device_id=verified_relay_device_id,
                    mac_install_id=str(record.get("install_id") or self.install_id),
                    relay_pair_secret=str(relay_pair_secret),
                    relay_pair_secret_ref=str(relay_pair_secret_ref or ""),
                )
            # WS4: register the device's Secure-Enclave public key so future
            # connections can re-pair with a Face ID signature (no QR/PIN).
            if se_public_key_der:
                self.registry.register_se_pubkey(device.device_id, se_public_key_der)
            record["claimed_at"] = now
            record["device_id"] = device.device_id
            path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            self._delete_record(path)
            self._delete_record(marker)
            self._claim_attempts.pop(pair_id, None)
            return PairClaim(
                device,
                normalized_hosts,
                int(record.get("runtime_port") or self.runtime_port),
                cert_pin,
                verified_relay_device_id,
                relay_status,
            )
        except Exception:
            self._delete_record(marker)
            raise

    def psk_claim_pair(
        self,
        *,
        pair_id: str,
        b_pub_b64: str,
        confirm_b64: str,
        device_name: str,
        host_chain: Iterable[str],
        scopes: Iterable[str] | None = None,
        cert_pin: str | None = None,
        se_public_key_der: str = "",
        attest_object: dict | None = None,
        attest_key_id: str = "",
        attest_environment: str = "",
        attested_claim_ticket: str | None = None,
        relay_device_id: str | None = None,
        relay_required: bool = False,
        relay_claim_verifier=None,
    ) -> tuple[PairClaim, bytes, bytes, bytes]:
        """WS3 PSK-authenticated ECDH claim. The secret is NEVER received; the
        caller proves knowledge of it by completing the authenticated key
        exchange (phone confirm tag under K_confirm). Returns
        (PairClaim, K_token, aad, mac_confirm) so the handler can seal the bearer
        token under K_token and echo the Mac key-confirmation."""
        if _psk is None:
            raise PairingError("psk_unavailable", 503, "psk crypto unavailable")
        try:
            b_pub = base64.b64decode(b_pub_b64, validate=True)
            confirm = base64.b64decode(confirm_b64, validate=True)
        except Exception:
            raise PairingError("psk_bad_key", 400, "invalid psk material")
        with self._claim_lock:
            record, path, now = self._precheck_claim(pair_id)
            secret = str(record.get("secret") or "")
            mac_priv_b64 = str(record.get("mac_ake_priv") or "")
            mac_pub_b64url = str(record.get("mac_ake_pub") or "")
            if not mac_priv_b64 or not mac_pub_b64url:
                raise PairingError("psk_unavailable", 409, "invitation has no psk key")
            try:
                a_priv = _psk.load_private(base64.b64decode(mac_priv_b64))
                a_pub = base64.urlsafe_b64decode(mac_pub_b64url + "=" * (-len(mac_pub_b64url) % 4))
                z = _psk.shared_secret(a_priv, b_pub)
                k_confirm, k_token = _psk.derive_keys(
                    pair_id=pair_id, a_pub=a_pub, b_pub=b_pub, z=z, secret=secret
                )
            except PairingError:
                raise
            except Exception:
                raise PairingError("psk_bad_key", 400, "invalid psk material")
            expected = _psk.confirm_tag(k_confirm, _psk.CONFIRM_PHONE, pair_id, a_pub, b_pub)
            if not secrets.compare_digest(expected, confirm):
                raise PairingError("psk_confirm_invalid", 403, "psk confirmation invalid")
            claim = self._finalize_claim(
                pair_id=pair_id, record=record, path=path, now=now,
                device_name=device_name, host_chain=host_chain, scopes=scopes,
                cert_pin=cert_pin, se_public_key_der=se_public_key_der,
                attest_object=attest_object, attest_key_id=attest_key_id,
                attest_environment=attest_environment,
                attested_claim_ticket=attested_claim_ticket,
                relay_device_id=relay_device_id, relay_required=relay_required,
                relay_claim_verifier=relay_claim_verifier,
            )
            aad = _psk.transcript(pair_id, a_pub, b_pub)
            mac_confirm = _psk.confirm_tag(k_confirm, _psk.CONFIRM_MAC, pair_id, a_pub, b_pub)
            return claim, k_token, aad, mac_confirm

    def seal_psk_token(self, k_token: bytes, token: str, aad: bytes) -> tuple[bytes, bytes]:
        """AES-256-GCM the bearer token under K_token so only the phone (which
        derived the same key) can read it. Returns (nonce, ciphertext‖tag)."""
        if _psk is None:
            raise PairingError("psk_unavailable", 503, "psk crypto unavailable")
        return _psk.seal_token(k_token, token, aad=aad)

    def _delete_record(self, path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def _store_relay_pair_secret(
        self,
        *,
        device_id: str,
        relay_device_id: str,
        mac_install_id: str,
        relay_pair_secret: str,
        relay_pair_secret_ref: str,
    ) -> None:
        secret_path = app_support_root() / "push-secrets.json"
        try:
            payload = json.loads(secret_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        payload.setdefault("schema_version", 1)
        devices = payload.setdefault("devices", {})
        device = devices.setdefault(device_id, {})
        device["relay_device_id"] = relay_device_id
        device["mac_install_id"] = mac_install_id
        device["relay_pair_secret"] = relay_pair_secret
        device["relay_pair_secret_ref"] = relay_pair_secret_ref
        device["updated_at"] = time.time()
        secret_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(secret_path.parent, stat.S_IRWXU)
        except OSError:
            pass
        tmp = secret_path.with_suffix(secret_path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, secret_path)
        try:
            os.chmod(secret_path, 0o600)
        except OSError:
            pass


class PairingAdvertiser:
    """Pair-only Bonjour advertiser backed by macOS dns-sd."""

    def __init__(
        self,
        *,
        dns_sd_path: str = "/usr/bin/dns-sd",
        popen_factory: Callable[..., subprocess.Popen] = subprocess.Popen,
    ):
        self.dns_sd_path = dns_sd_path
        self.popen_factory = popen_factory
        self._lock = threading.Lock()
        self._proc = None
        self._timer: threading.Timer | None = None

    def start(self, started: PairStart, *, port: int) -> dict:
        # When PSK pairing is required (the default), the Bonjour-advertised
        # phone-initiated path can no longer complete a claim — legacy /pair/claim
        # returns 403 — so publishing the service is dead surface and a needless
        # LAN signal. Self-disable here rather than editing the pairlingd.py call
        # site. PAIRLING_PSK_REQUIRED=0 (the legacy break-glass) re-enables it.
        if _psk_required():
            return {"ok": False, "reason": "psk_required"}
        if os.environ.get("PAIRLING_DISABLE_BONJOUR") in {"1", "true", "TRUE"}:
            return {"ok": False, "reason": "disabled"}
        if not Path(self.dns_sd_path).exists():
            return {"ok": False, "reason": "dns-sd_missing"}
        txt_args = [f"{key}={value}" for key, value in sorted(started.txt.items())]
        cmd = [
            self.dns_sd_path,
            "-R",
            "Pairling",
            started.service_type,
            "local",
            str(port),
            *txt_args,
        ]
        with self._lock:
            self.stop()
            try:
                proc = self.popen_factory(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError as exc:
                return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}
            self._proc = proc
            ttl = max(1.0, started.expires_at - time.time())
            self._timer = threading.Timer(ttl, self.stop)
            self._timer.daemon = True
            self._timer.start()
        return {
            "ok": True,
            "service_type": started.service_type,
            "runtime_api_advertised": False,
            "pid": getattr(proc, "pid", None),
        }

    def stop(self) -> None:
        timer = self._timer
        self._timer = None
        if timer is not None:
            timer.cancel()
        proc = self._proc
        self._proc = None
        if proc is not None and proc.poll() is None:
            proc.terminate()
