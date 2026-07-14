#!/usr/bin/env python3
"""Short-lived Pairling pairing records and claim flow."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import socket
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from collections import OrderedDict
from pathlib import Path
from typing import Callable, Iterable

from pairling_devices import (
    CreatedDevice,
    DeviceRegistryError,
    DeviceRegistry,
    PairActivationResult,
    generate_device_id,
    generate_proof_secret,
    generate_token,
)
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
PAIR_RECORD_PRUNE_SCAN_LIMIT = 256
PAIR_RECORD_PRUNE_DELETE_LIMIT = 128
PAIR_RECORD_MAX_BYTES = 64 * 1024
PENDING_CLAIM_TTL_SECONDS = 180
PAIR_CLAIM_REQUEST_CONTRACT = "pairling.psk.claim.request.v2"
PAIR_CLAIM_PHONE_CONFIRM_V2_DOMAIN = b"pairling.psk.confirm.phone.v2"
PAIR_CLAIM_RESULT_CONTRACT = "pairling.psk.claim.result.v2"
SMOKE_DEVICE_PURPOSE = "runtime_truth_smoke"
DEFAULT_SMOKE_LEASE_TTL_SECONDS = 600
MIN_SMOKE_LEASE_TTL_SECONDS = 60
MAX_SMOKE_LEASE_TTL_SECONDS = 3600
SMOKE_ALLOWED_SCOPES = frozenset({
    "health:read",
    "manifest:read",
    "sessions:read",
    "transcript:read",
    "session:send",
    "session:spawn",
    "session:signal",
    "files:upload",
    "pair:admin",
})


def _claim_request_scalar(value, field: str) -> str:
    if not isinstance(value, str) or "\n" in value or "\r" in value:
        raise ValueError(f"{field} is not a safe claim request scalar")
    return value


def _claim_request_integer(value, field: str) -> str:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} is not a claim request integer")
    return str(value)


def _append_claim_request_optional(lines: list[str], value, field: str) -> None:
    if value is None:
        lines.append("0")
        return
    lines.extend(("1", _claim_request_scalar(value, field)))


def _claim_request_decoded_digest(value, field: str) -> str:
    encoded = _claim_request_scalar(value, field)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise ValueError(f"{field} is not valid base64") from exc
    return hashlib.sha256(decoded).hexdigest()


def pair_claim_request_canonical(
    *,
    request_contract: str,
    pair_id: str,
    device_name: str,
    protocol_version: int,
    seal_proof_secret: bool,
    activation_contract: str,
    se_public_key_der: str | None = None,
    direct_attest_object: dict | None = None,
    attest_key_id: str | None = None,
    attest_environment: str | None = None,
    enc_attested_claim_ticket: str | None = None,
    attested_claim_ticket_nonce: str | None = None,
    relay_device_id: str | None = None,
) -> bytes:
    """Canonical PSK-v2 request policy bytes used by the phone confirmation."""
    contract = _claim_request_scalar(request_contract, "request_contract")
    if contract != PAIR_CLAIM_REQUEST_CONTRACT:
        raise ValueError("request_contract is unsupported")
    if not isinstance(seal_proof_secret, bool):
        raise ValueError("seal_proof_secret is not a claim request boolean")
    lines = [
        contract,
        _claim_request_scalar(pair_id, "pair_id"),
        _claim_request_scalar(device_name, "device_name"),
        _claim_request_integer(protocol_version, "pv"),
        "1" if seal_proof_secret else "0",
        _claim_request_scalar(activation_contract, "activation_contract"),
    ]
    _append_claim_request_optional(
        lines, se_public_key_der, "se_public_key_der"
    )

    if direct_attest_object is None:
        lines.append("0")
    else:
        if not isinstance(direct_attest_object, dict):
            raise ValueError("direct_attest_object is not a claim request object")
        normalized_attestation = []
        for key, value in direct_attest_object.items():
            normalized_attestation.append(
                (
                    _claim_request_scalar(key, "direct_attest_object key"),
                    _claim_request_scalar(value, f"direct_attest_object[{key}]"),
                )
            )
        normalized_attestation.sort(key=lambda item: item[0])
        lines.extend(("1", str(len(normalized_attestation))))
        for key, value in normalized_attestation:
            lines.extend((key, value))

    _append_claim_request_optional(lines, attest_key_id, "attest_key_id")
    _append_claim_request_optional(
        lines, attest_environment, "attest_environment"
    )
    if (enc_attested_claim_ticket is None) != (
        attested_claim_ticket_nonce is None
    ):
        raise ValueError("encrypted relay ticket fields must be supplied together")
    if enc_attested_claim_ticket is None:
        lines.append("0")
    else:
        lines.extend(
            (
                "1",
                _claim_request_decoded_digest(
                    enc_attested_claim_ticket, "enc_attested_claim_ticket"
                ),
                _claim_request_decoded_digest(
                    attested_claim_ticket_nonce, "attested_claim_ticket_nonce"
                ),
            )
        )
    _append_claim_request_optional(lines, relay_device_id, "relay_device_id")
    return "\n".join(lines).encode("utf-8")


def pair_claim_request_binding(**kwargs) -> str:
    return hashlib.sha256(pair_claim_request_canonical(**kwargs)).hexdigest()


def pair_claim_phone_confirm_v2(
    *,
    k_confirm: bytes,
    pair_id: str,
    a_pub: bytes,
    b_pub: bytes,
    request_binding: str,
) -> bytes:
    if (
        not isinstance(request_binding, str)
        or len(request_binding) != 64
        or request_binding != request_binding.lower()
        or any(char not in "0123456789abcdef" for char in request_binding)
    ):
        raise ValueError("request_binding is not lowercase SHA256 hex")
    if _psk is None:
        raise ValueError("psk crypto unavailable")
    message = (
        PAIR_CLAIM_PHONE_CONFIRM_V2_DOMAIN
        + _psk.transcript(pair_id, a_pub, b_pub)
        + request_binding.encode("ascii")
    )
    return hmac.new(k_confirm, message, hashlib.sha256).digest()


def _claim_result_scalar(value, field: str) -> str:
    if not isinstance(value, str) or "\n" in value or "\r" in value:
        raise ValueError(f"{field} is not a safe claim result scalar")
    return value


def _claim_result_integer(value, field: str) -> str:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} is not a claim result integer")
    return str(value)


def _claim_result_object(value, field: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{field} is not a claim result object")
    return value


def _claim_result_list(value, field: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{field} is not a claim result list")
    return value


def _append_claim_result_optional(
    lines: list[str], value, field: str, *, integer: bool = False
) -> None:
    if value is None:
        lines.append("0")
        return
    lines.append("1")
    lines.append(
        _claim_result_integer(value, field)
        if integer
        else _claim_result_scalar(value, field)
    )


def pair_claim_result_canonical(payload: dict) -> bytes:
    """Canonical authenticated PSK-v2 claim response bytes."""
    response = _claim_result_object(payload, "response")
    contract = _claim_result_scalar(
        response.get("claim_result_contract"), "claim_result_contract"
    )
    if contract != PAIR_CLAIM_RESULT_CONTRACT:
        raise ValueError("claim_result_contract is unsupported")
    ok = response.get("ok")
    if not isinstance(ok, bool):
        raise ValueError("ok is not a claim result boolean")
    device = _claim_result_object(response.get("device"), "device")
    runtime = _claim_result_object(response.get("runtime"), "runtime")
    activation = _claim_result_object(response.get("activation"), "activation")

    lines = [
        contract,
        "1" if ok else "0",
        _claim_result_scalar(response.get("pairing_state"), "pairing_state"),
        _claim_result_scalar(response.get("pair_id"), "pair_id"),
        _claim_result_integer(response.get("pv"), "pv"),
        _claim_result_scalar(response.get("request_binding"), "request_binding"),
        _claim_result_scalar(device.get("id"), "device.id"),
    ]

    scopes = [
        _claim_result_scalar(scope, "device.scope")
        for scope in _claim_result_list(device.get("scopes"), "device.scopes")
    ]
    normalized_scopes = sorted(set(scopes))
    if scopes != normalized_scopes:
        raise ValueError("device.scopes must be sorted and unique")
    lines.extend((str(len(scopes)), *scopes))
    _append_claim_result_optional(
        lines, device.get("relay_device_id"), "device.relay_device_id"
    )
    _append_claim_result_optional(
        lines, device.get("attestation_status"), "device.attestation_status"
    )
    lines.extend(
        (
            _claim_result_scalar(response.get("install_id"), "install_id"),
            _claim_result_integer(runtime.get("port"), "runtime.port"),
        )
    )

    hosts = [
        _claim_result_scalar(host, "runtime.host")
        for host in _claim_result_list(runtime.get("host_chain"), "runtime.host_chain")
    ]
    lines.extend((str(len(hosts)), *hosts))
    _append_claim_result_optional(lines, runtime.get("cert_pin"), "runtime.cert_pin")
    _append_claim_result_optional(lines, runtime.get("transport"), "runtime.transport")

    routes = _claim_result_list(runtime.get("routes"), "runtime.routes")
    lines.append(str(len(routes)))
    for index, raw_route in enumerate(routes):
        route = _claim_result_object(raw_route, f"runtime.routes[{index}]")
        prefix = f"runtime.routes[{index}]"
        _append_claim_result_optional(lines, route.get("id"), f"{prefix}.id")
        lines.extend(
            (
                _claim_result_scalar(route.get("kind"), f"{prefix}.kind"),
                _claim_result_scalar(route.get("source"), f"{prefix}.source"),
            )
        )
        _append_claim_result_optional(
            lines, route.get("priority"), f"{prefix}.priority", integer=True
        )
        _append_claim_result_optional(
            lines, route.get("base_url"), f"{prefix}.base_url"
        )
        lines.extend(
            (
                _claim_result_scalar(route.get("host"), f"{prefix}.host"),
                _claim_result_integer(route.get("port"), f"{prefix}.port"),
            )
        )
        _append_claim_result_optional(lines, route.get("status"), f"{prefix}.status")

    expires_at_ms = activation.get("expires_at_ms")
    expires_at_ms_line = _claim_result_integer(
        expires_at_ms, "activation.expires_at_ms"
    )
    expires_at = activation.get("expires_at")
    if (
        isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
        or not math.isfinite(float(expires_at))
        or float(expires_at) != expires_at_ms / 1000.0
    ):
        raise ValueError("activation.expires_at does not match expires_at_ms")
    lines.extend(
        (
            _claim_result_scalar(activation.get("path"), "activation.path"),
            _claim_result_scalar(activation.get("pair_id"), "activation.pair_id"),
            _claim_result_scalar(activation.get("device_id"), "activation.device_id"),
            _claim_result_scalar(activation.get("nonce"), "activation.nonce"),
            expires_at_ms_line,
            _claim_result_scalar(
                activation.get("proof_version"), "activation.proof_version"
            ),
        )
    )

    encoded_fields = (
        (response.get("enc_token"), "enc_token"),
        (response.get("nonce"), "nonce"),
        (device.get("enc_proof_secret"), "device.enc_proof_secret"),
        (device.get("proof_secret_nonce"), "device.proof_secret_nonce"),
        (response.get("mac_confirm"), "mac_confirm"),
    )
    for encoded_value, field in encoded_fields:
        encoded = _claim_result_scalar(encoded_value, field)
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise ValueError(f"{field} is not valid base64") from exc
        lines.append(hashlib.sha256(decoded).hexdigest())

    return "\n".join(lines).encode("utf-8")


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

    def __init__(
        self,
        registry: DeviceRegistry,
        *,
        ttl_seconds: int = 120,
        max_entries: int = 512,
    ):
        self.registry = registry
        self.ttl_seconds = max(1, min(int(ttl_seconds), 300))
        self.max_entries = max(1, min(int(max_entries), 4096))
        self._lock = threading.Lock()
        # Key by the random challenge instead of device id. Concurrent recovery
        # attempts for one phone must not invalidate each other. Store only a
        # fixed-size digest of the untrusted device id so arbitrary input cannot
        # turn this short-lived table into an unbounded memory sink.
        self._challenges: OrderedDict[str, tuple[bytes, float]] = OrderedDict()

    @staticmethod
    def _device_key(device_id: str) -> bytes:
        return hashlib.sha256(str(device_id or "").encode("utf-8")).digest()

    def _prune_expired_locked(self, now: float) -> None:
        expired = [
            challenge
            for challenge, (_, expires_at) in self._challenges.items()
            if expires_at <= now
        ]
        for challenge in expired:
            self._challenges.pop(challenge, None)

    def issue_challenge(self, device_id: str) -> str:
        challenge = secrets.token_hex(32)
        now = time.time()
        with self._lock:
            self._prune_expired_locked(now)
            while len(self._challenges) >= self.max_entries:
                self._challenges.popitem(last=False)
            self._challenges[challenge] = (
                self._device_key(device_id),
                now + self.ttl_seconds,
            )
        return challenge

    def verify_and_consume(self, device_id: str, challenge: str, signature_der: bytes) -> bool:
        challenge = str(challenge or "")
        if len(challenge) != 64:
            return False
        try:
            bytes.fromhex(challenge)
        except ValueError:
            return False
        if not signature_der or len(signature_der) > 256:
            return False
        # Single-use: pop regardless of outcome so a captured challenge cannot
        # be replayed even if the first signature was wrong.
        now = time.time()
        with self._lock:
            self._prune_expired_locked(now)
            entry = self._challenges.pop(challenge, None)
        if entry is None:
            return False
        stored_device_key, expires_at = entry
        if now > expires_at:
            return False
        if not secrets.compare_digest(stored_device_key, self._device_key(device_id)):
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
    purpose: str | None = None
    lease_expires_at: float | None = None


@dataclass(frozen=True)
class PairClaim:
    device: CreatedDevice
    host_chain: tuple[str, ...]
    runtime_port: int
    cert_pin: str | None
    relay_device_id: str | None = None
    attestation_status: str = "none"
    # Increment 5: True only when a direct App Attest attestation was verified for
    # this claim. Distinct from attestation_status, which is the relay-path field.
    direct_attestation_verified: bool = False


@dataclass(frozen=True)
class SealedPSKPairClaim:
    claim: PairClaim
    enc_token: bytes
    token_nonce: bytes
    mac_confirm: bytes
    enc_proof_secret: bytes
    proof_secret_nonce: bytes
    pair_id: str = ""
    activation_nonce: str = ""
    pending_expires_at: float = 0.0
    response_payload: dict | None = None


class PairingError(Exception):
    def __init__(
        self,
        code: str,
        status: int,
        message: str,
        *,
        activation_result: dict | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.status = status
        self.message = message
        self.activation_result = activation_result


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
        # A retained scandir iterator gives each bounded cleanup pass a new
        # section of the directory. Without it, an undeletable prefix could
        # permanently hide expired invitations beyond the scan limit.
        self._prune_scan_fd: int | None = None
        self._prune_scan_entries = None
        try:
            self._cleanup_pending_claims()
            self.registry.revoke_expired_smoke_leases()
        except Exception:
            # Auth independently rejects expired pending and smoke credentials.
            # Maintenance storage trouble must not make the daemon disappear at
            # import time; the next pairing operation retries the cleanup.
            pass
        self._prune_expired_records()

    def __del__(self):
        # The process normally owns one PairingStore for its lifetime. Tests
        # create many short-lived stores, so close a retained bounded scan when
        # an instance is collected instead of leaking its directory descriptor.
        try:
            self._close_prune_scan_locked()
        except Exception:
            pass

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

    @staticmethod
    def _raise_registry_error(exc: DeviceRegistryError) -> None:
        raise PairingError(
            exc.code,
            exc.status,
            exc.message,
            activation_result=exc.activation_result,
        ) from exc

    def _cleanup_pending_claims(self, *, now: float | None = None) -> int:
        cleanup = self.registry.prune_pending_claims(now=now)
        cleaned = 0
        for item in cleanup:
            pair_id = str(item.get("pair_id") or "")
            device_id = str(item.get("device_id") or "")
            if not pair_id or not device_id:
                continue
            try:
                if item.get("relay_secret_expected"):
                    self._delete_relay_pair_secret(device_id)
                self.registry.mark_pending_secret_cleaned(pair_id, device_id)
                cleaned += 1
            except Exception:
                # The registry keeps secret_cleaned=0, so the next startup or
                # pairing operation retries the external secret cleanup.
                continue
        return cleaned

    def _open_pair_root(self, *, create: bool) -> int:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory = getattr(os, "O_DIRECTORY", 0)
        if not nofollow or not directory:
            raise PairingError(
                "pair_storage_unavailable",
                503,
                "secure pairing storage is unavailable",
            )
        if create:
            try:
                self.pair_root.parent.mkdir(parents=True, exist_ok=True)
                os.mkdir(self.pair_root, 0o700)
            except FileExistsError:
                pass
            except OSError as exc:
                raise PairingError(
                    "pair_storage_unavailable",
                    503,
                    "pairing storage could not be created",
                ) from exc
        flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(self.pair_root, flags)
        except FileNotFoundError as exc:
            if not create:
                raise PairingError("pair_not_found", 404, "pair record not found") from exc
            raise PairingError(
                "pair_storage_unavailable",
                503,
                "pairing storage is unavailable",
            ) from exc
        except OSError as exc:
            raise PairingError(
                "pair_storage_unavailable",
                503,
                "pairing storage is not a secure directory",
            ) from exc
        try:
            opened_stat = os.fstat(fd)
            if not stat.S_ISDIR(opened_stat.st_mode):
                raise PairingError(
                    "pair_storage_unavailable",
                    503,
                    "pairing storage is not a directory",
                )
            if create:
                os.fchmod(fd, stat.S_IRWXU)
            return fd
        except PairingError:
            os.close(fd)
            raise
        except OSError as exc:
            os.close(fd)
            raise PairingError(
                "pair_storage_unavailable",
                503,
                "pairing storage could not be verified",
            ) from exc

    def _prune_expired_records(self, *, now: float | None = None) -> int:
        with self._claim_lock:
            return self._prune_expired_records_locked(time.time() if now is None else now)

    def _close_prune_scan_locked(self) -> None:
        entries = getattr(self, "_prune_scan_entries", None)
        self._prune_scan_entries = None
        if entries is not None:
            try:
                entries.close()
            except Exception:
                pass
        fd = getattr(self, "_prune_scan_fd", None)
        self._prune_scan_fd = None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def _start_prune_scan_locked(self) -> bool:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory = getattr(os, "O_DIRECTORY", 0)
        if not nofollow or not directory:
            return False
        flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(self.pair_root, flags)
        except OSError:
            # A missing, unreadable, non-directory, or symlinked root is not a
            # startup failure. In particular, never prune through a root link.
            return False
        try:
            opened_stat = os.fstat(fd)
            if not stat.S_ISDIR(opened_stat.st_mode):
                os.close(fd)
                return False
            entries = os.scandir(fd)
        except OSError:
            os.close(fd)
            return False
        self._prune_scan_fd = fd
        self._prune_scan_entries = entries
        return True

    def _open_prune_entry_locked(self, name: str) -> tuple[int, bytes, os.stat_result] | None:
        root_fd = self._prune_scan_fd
        if root_fd is None:
            return None
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            fd = os.open(name, flags, dir_fd=root_fd)
        except OSError:
            return None
        try:
            opened_stat = os.fstat(fd)
            if not stat.S_ISREG(opened_stat.st_mode) or opened_stat.st_size > PAIR_RECORD_MAX_BYTES:
                os.close(fd)
                return None
            chunks = []
            remaining = PAIR_RECORD_MAX_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > PAIR_RECORD_MAX_BYTES:
                os.close(fd)
                return None
            return fd, raw, opened_stat
        except OSError:
            os.close(fd)
            return None

    def _unlink_prune_entry_locked(
        self,
        name: str,
        opened_stat: os.stat_result,
    ) -> bool:
        root_fd = self._prune_scan_fd
        if root_fd is None:
            return False
        try:
            # Keep the candidate fd open while comparing its inode. macOS does
            # not expose a compare-and-unlink operation, so a same-user process
            # can still replace the name after this stat and before unlink.
            current_stat = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(current_stat.st_mode)
                or current_stat.st_dev != opened_stat.st_dev
                or current_stat.st_ino != opened_stat.st_ino
            ):
                return False
            os.unlink(name, dir_fd=root_fd)
            return True
        except OSError:
            return False

    def _record_is_expired(self, raw: bytes, *, pair_id: str, now: float) -> bool:
        try:
            record = json.loads(raw.decode("utf-8"))
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            OverflowError,
            RecursionError,
            TypeError,
            ValueError,
        ):
            return False
        if not isinstance(record, dict) or record.get("pair_id") != pair_id:
            return False
        expires_value = record.get("expires_at")
        if isinstance(expires_value, bool) or not isinstance(expires_value, (int, float)):
            return False
        try:
            expires_at = float(expires_value)
        except (OverflowError, TypeError, ValueError):
            return False
        return math.isfinite(expires_at) and expires_at < now

    def _valid_prune_pair_id(self, pair_id: str) -> bool:
        try:
            self._record_path(pair_id)
            return True
        except PairingError:
            return False

    def _delete_orphan_claim_locked(self, pair_id: str, *, now: float) -> bool:
        if not self._valid_prune_pair_id(pair_id):
            return False
        root_fd = self._prune_scan_fd
        if root_fd is None:
            return False
        record_name = f"{pair_id}.json"
        try:
            os.stat(record_name, dir_fd=root_fd, follow_symlinks=False)
            return False
        except FileNotFoundError:
            pass
        except OSError:
            return False

        marker_name = f"{pair_id}.claim"
        opened = self._open_prune_entry_locked(marker_name)
        if opened is None:
            return False
        marker_fd, raw, opened_stat = opened
        try:
            # Current claim markers are hard links to the invitation record.
            # Empty markers are safe residue from older builds. A non-empty
            # orphan is removed only after its validated invitation expires.
            if raw and not self._record_is_expired(raw, pair_id=pair_id, now=now):
                return False
            if not self._unlink_prune_entry_locked(marker_name, opened_stat):
                return False
            self._claim_attempts.pop(pair_id, None)
            return True
        finally:
            os.close(marker_fd)

    def _prune_entry_locked(self, name: str, *, now: float, delete_budget: int) -> int:
        if delete_budget <= 0 or not name.startswith("pair_"):
            return 0

        is_record = name.endswith(".json")
        is_temp = name.endswith(".json.tmp")
        is_claim = name.endswith(".claim")
        if is_temp:
            pair_id = name[: -len(".json.tmp")]
        elif is_record:
            pair_id = name[: -len(".json")]
        elif is_claim:
            pair_id = name[: -len(".claim")]
        else:
            return 0
        if not self._valid_prune_pair_id(pair_id):
            return 0

        if is_claim:
            return 1 if self._delete_orphan_claim_locked(pair_id, now=now) else 0

        opened = self._open_prune_entry_locked(name)
        if opened is None:
            return 0
        record_fd, raw, opened_stat = opened
        try:
            if not self._record_is_expired(raw, pair_id=pair_id, now=now):
                return 0
            if not self._unlink_prune_entry_locked(name, opened_stat):
                return 0
        finally:
            os.close(record_fd)

        self._claim_attempts.pop(pair_id, None)
        deleted = 1
        if delete_budget > deleted and self._delete_orphan_claim_locked(pair_id, now=now):
            deleted += 1
        return deleted

    def _prune_expired_records_locked(self, now: float) -> int:
        deleted = 0
        scanned = 0
        if self._prune_scan_entries is None and not self._start_prune_scan_locked():
            return 0

        while scanned < PAIR_RECORD_PRUNE_SCAN_LIMIT and deleted < PAIR_RECORD_PRUNE_DELETE_LIMIT:
            entries = self._prune_scan_entries
            if entries is None:
                break
            try:
                entry = next(entries)
            except StopIteration:
                self._close_prune_scan_locked()
                break
            except OSError:
                # Directory iteration can fail after scandir() succeeds. Cleanup
                # is maintenance work and must never take down daemon startup.
                self._close_prune_scan_locked()
                break
            scanned += 1
            try:
                name = entry.name
                deleted += self._prune_entry_locked(
                    name,
                    now=now,
                    delete_budget=PAIR_RECORD_PRUNE_DELETE_LIMIT - deleted,
                )
            except (OSError, TypeError, ValueError):
                continue
        return deleted

    def _record_path(self, pair_id: str) -> Path:
        if not pair_id or not all(c.isalnum() or c in {"_", "-"} for c in pair_id):
            raise PairingError("invalid_pair_id", 400, "invalid pair id")
        return self.pair_root / f"{pair_id}.json"

    def _claim_marker_path(self, pair_id: str) -> Path:
        return self._record_path(pair_id).with_suffix(".claim")

    def _create_claim_marker(self, pair_id: str) -> Path:
        record = self._record_path(pair_id)
        marker = self._claim_marker_path(pair_id)
        root_fd = self._open_pair_root(create=False)
        record_fd = None
        try:
            record_fd = os.open(
                record.name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=root_fd,
            )
            record_stat = os.fstat(record_fd)
            if not stat.S_ISREG(record_stat.st_mode):
                raise PairingError("pair_corrupt", 500, "pair record is not a regular file")
            os.link(
                record.name,
                marker.name,
                src_dir_fd=root_fd,
                dst_dir_fd=root_fd,
                follow_symlinks=False,
            )
            marker_stat = os.stat(marker.name, dir_fd=root_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(marker_stat.st_mode)
                or marker_stat.st_dev != record_stat.st_dev
                or marker_stat.st_ino != record_stat.st_ino
            ):
                try:
                    os.unlink(marker.name, dir_fd=root_fd)
                except OSError:
                    pass
                raise PairingError("pair_storage_unavailable", 503, "pair record changed during claim")
        except FileExistsError:
            raise PairingError("pair_already_claimed", 409, "pair record already claimed")
        except FileNotFoundError as exc:
            raise PairingError("pair_not_found", 404, "pair record not found") from exc
        except PairingError:
            raise
        except OSError as exc:
            raise PairingError(
                "pair_storage_unavailable",
                503,
                "pair claim marker could not be created",
            ) from exc
        finally:
            if record_fd is not None:
                os.close(record_fd)
            os.close(root_fd)
        return marker

    def start_pair(
        self,
        *,
        ttl_seconds: int = DEFAULT_PAIR_TTL_SECONDS,
        purpose: str | None = None,
        scopes: Iterable[str] | None = None,
        lease_ttl_seconds: int | None = None,
    ) -> PairStart:
        self._cleanup_pending_claims()
        self.registry.revoke_expired_smoke_leases()
        self._prune_expired_records()
        normalized_purpose = str(purpose or "").strip()
        normalized_scopes: tuple[str, ...] | None = None
        smoke_lease_ttl: int | None = None
        if normalized_purpose:
            if normalized_purpose != SMOKE_DEVICE_PURPOSE:
                raise PairingError("invalid_pair_purpose", 400, "unsupported pairing purpose")
            normalized_scopes = tuple(sorted(set(scopes or SMOKE_ALLOWED_SCOPES)))
            if not normalized_scopes or not set(normalized_scopes).issubset(SMOKE_ALLOWED_SCOPES):
                raise PairingError(
                    "invalid_smoke_scopes",
                    400,
                    "runtime truth smoke requested unsupported scopes",
                )
            raw_lease_ttl = (
                DEFAULT_SMOKE_LEASE_TTL_SECONDS
                if lease_ttl_seconds is None
                else int(lease_ttl_seconds)
            )
            smoke_lease_ttl = max(
                MIN_SMOKE_LEASE_TTL_SECONDS,
                min(raw_lease_ttl, MAX_SMOKE_LEASE_TTL_SECONDS),
            )
        elif scopes is not None or lease_ttl_seconds is not None:
            raise PairingError(
                "invalid_pair_purpose", 400, "scoped leases require runtime_truth_smoke"
            )
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
            "purpose": normalized_purpose or None,
            "scopes": list(normalized_scopes or ()),
            "lease_ttl_seconds": smoke_lease_ttl,
        }
        path = self._record_path(pair_id)
        tmp = path.with_suffix(".json.tmp")
        root_fd = self._open_pair_root(create=True)
        tmp_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            tmp_fd = os.open(tmp.name, tmp_flags, 0o600, dir_fd=root_fd)
            try:
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                    json.dump(record, fh, indent=2, sort_keys=True)
                    fh.write("\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            except Exception:
                try:
                    os.close(tmp_fd)
                except OSError:
                    pass
                raise
            os.replace(
                tmp.name,
                path.name,
                src_dir_fd=root_fd,
                dst_dir_fd=root_fd,
            )
        except OSError as exc:
            try:
                os.unlink(tmp.name, dir_fd=root_fd)
            except OSError:
                pass
            raise PairingError(
                "pair_storage_unavailable",
                503,
                "pair invitation could not be stored",
            ) from exc
        except Exception:
            try:
                os.unlink(tmp.name, dir_fd=root_fd)
            except OSError:
                pass
            raise
        finally:
            os.close(root_fd)
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
            normalized_purpose or None,
            (time.time() + smoke_lease_ttl) if smoke_lease_ttl is not None else None,
        )

    def _load_record(self, pair_id: str) -> tuple[dict, Path]:
        path = self._record_path(pair_id)
        root_fd = self._open_pair_root(create=False)
        record_fd = None
        try:
            record_fd = os.open(
                path.name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=root_fd,
            )
            opened_stat = os.fstat(record_fd)
            if not stat.S_ISREG(opened_stat.st_mode) or opened_stat.st_size > PAIR_RECORD_MAX_BYTES:
                raise PairingError("pair_corrupt", 500, "pair record is not a valid regular file")
            chunks = []
            remaining = PAIR_RECORD_MAX_BYTES + 1
            while remaining > 0:
                chunk = os.read(record_fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > PAIR_RECORD_MAX_BYTES:
                raise PairingError("pair_corrupt", 500, "pair record is too large")
            record = json.loads(raw.decode("utf-8"))
        except FileNotFoundError as exc:
            raise PairingError("pair_not_found", 404, "pair record not found") from exc
        except UnicodeDecodeError as exc:
            raise PairingError("pair_corrupt", 500, "pair record is not UTF-8 JSON") from exc
        except (ValueError, OverflowError, RecursionError) as exc:
            raise PairingError("pair_corrupt", 500, f"pair record is corrupt: {exc}")
        except PairingError:
            raise
        except OSError as exc:
            raise PairingError(
                "pair_storage_unavailable",
                503,
                "pair record could not be read securely",
            ) from exc
        finally:
            if record_fd is not None:
                os.close(record_fd)
            os.close(root_fd)
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
        require_direct_attest: bool = False,
    ) -> PairClaim:
        with self._claim_lock:
            # WS3: once PSK pairing is mandatory, reject legacy plaintext-secret
            # claims before looking up a pair id or charging its attempt budget.
            # This path can never succeed, so it must not be an invitation oracle
            # or a lockout primitive.
            if _psk_required():
                raise PairingError("psk_required", 403, "psk-authenticated pairing required")
            record, path, now = self._precheck_claim(pair_id)
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
                require_direct_attest=require_direct_attest,
            )

    def _precheck_claim(self, pair_id: str) -> tuple[dict, Path, float]:
        """Shared front-matter for both claim paths (caller holds _claim_lock):
        load the record, reject already-claimed/expired, and pre-increment the
        per-pair_id attempt counter so wrong guesses lock out after 5 (P0-B)."""
        record, path = self._load_record(pair_id)
        now = time.time()
        if record.get("claimed_at") is not None:
            raise PairingError("pair_already_claimed", 409, "pair record already claimed")
        expires_value = record.get("expires_at")
        if isinstance(expires_value, bool) or not isinstance(expires_value, (int, float)):
            raise PairingError("pair_corrupt", 500, "pair record has an invalid expiry")
        try:
            expires_at = float(expires_value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise PairingError("pair_corrupt", 500, "pair record has an invalid expiry") from exc
        if not math.isfinite(expires_at):
            raise PairingError("pair_corrupt", 500, "pair record has an invalid expiry")
        if now > expires_at:
            self._delete_record(path)
            self._claim_attempts.pop(pair_id, None)
            raise PairingError("pair_expired", 410, "pair record expired")
        attempts = self._claim_attempts.get(pair_id, 0) + 1
        self._claim_attempts[pair_id] = attempts
        if attempts > 5:
            raise PairingError("pair_locked", 429, "too many claim attempts")
        return record, path, now

    def _verify_claim_attestation(
        self,
        *,
        pair_id: str,
        record: dict,
        attest_object: dict | None,
        attest_key_id: str,
        attest_environment: str,
        require: bool,
        force_production: bool,
    ) -> bool:
        """Verify direct App Attest. Returns True when a valid attestation was
        verified, False when none was required and none supplied. Raises on
        failure or when required-and-missing. force_production pins the
        environment so a funnel client cannot send 'development'."""
        if not (require or _direct_attest_required() or attest_object):
            return False
        if not attest_object:
            raise PairingError("direct_attest_required", 403, "app attest required")
        if _verify_direct_attestation is None:
            raise PairingError("direct_attest_unavailable", 503, "app attest validator unavailable")
        environment = "production" if force_production else attest_environment
        try:
            _verify_direct_attestation(
                attestation=attest_object,
                pair_id=pair_id,
                attest_challenge=str(record.get("attest_challenge") or ""),
                key_id=attest_key_id,
                environment=environment,
            )
        except PairingError:
            raise
        except Exception:
            raise PairingError("direct_attest_invalid", 403, "app attest validation failed")
        return True

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
        funnel_origin: bool = False,
        require_direct_attest: bool = False,
        attestation_verified: bool | None = None,
        token: str | None = None,
        proof_secret: str | None = None,
        device_id: str | None = None,
    ) -> PairClaim:
        """Post-authentication finalize, shared by legacy and PSK claims. The
        caller holds _claim_lock and has already proven secret-knowledge (legacy
        compare or PSK key-confirmation): App Attest, relay ticket, device
        creation, SE pubkey registration, record teardown."""
        # WS2 + Increment 5: direct App Attest. For a funnel-origin claim it is a
        # hard, fail-closed requirement (verified earlier, before the derive). For
        # LAN and tailnet claims it stays opportunistic. attestation_verified
        # carries a result the caller already computed (the funnel pre-derive
        # check); otherwise verify here.
        if attestation_verified is None:
            attestation_verified = self._verify_claim_attestation(
                pair_id=pair_id, record=record, attest_object=attest_object,
                attest_key_id=attest_key_id, attest_environment=attest_environment,
                require=funnel_origin or require_direct_attest,
                force_production=funnel_origin or require_direct_attest,
            )
        relay_status = "none"
        # A caller-supplied relay id has no authority by itself. Only a verified
        # relay ticket may bind the new local credential to an existing phone.
        verified_relay_device_id = None
        relay_pair_secret = None
        relay_pair_secret_ref = None
        verification = None
        normalized_hosts = tuple(h for h in host_chain if isinstance(h, str) and h)
        if not normalized_hosts:
            raise PairingError("missing_host_chain", 500, "host chain is empty")
        try:
            runtime_port = int(record.get("runtime_port") or self.runtime_port)
        except (TypeError, ValueError, OverflowError) as exc:
            raise PairingError("pair_corrupt", 500, "pair record has an invalid runtime port") from exc
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
        marker = None
        device = None
        relay_secret_expected = bool(relay_pair_secret and verified_relay_device_id)
        try:
            marker = self._create_claim_marker(pair_id)
            device = self.registry.create_device(
                device_name=device_name or "Pairling iPhone",
                install_id=str(record.get("install_id") or self.install_id),
                scopes=scopes or DEFAULT_DEVICE_SCOPES,
                relay_device_id=verified_relay_device_id,
                attestation_status=relay_status,
                device_display_name=device_name or "Pairling iPhone",
                relay_pair_secret_ref=relay_pair_secret_ref,
                se_public_key_der=se_public_key_der,
                token=token,
                proof_secret=proof_secret,
                device_id=device_id,
            )
            if relay_secret_expected:
                self._store_relay_pair_secret(
                    device_id=device.device_id,
                    relay_device_id=verified_relay_device_id,
                    mac_install_id=str(record.get("install_id") or self.install_id),
                    relay_pair_secret=str(relay_pair_secret),
                    relay_pair_secret_ref=str(relay_pair_secret_ref or ""),
                )
            # Consume the record name before removing its hard-linked claim
            # marker. A competing store can never recreate the marker from a
            # cached record after the invitation name has gone away.
            self._delete_record(path)
            self._claim_attempts.pop(pair_id, None)
            result = PairClaim(
                device,
                normalized_hosts,
                runtime_port,
                cert_pin,
                verified_relay_device_id,
                relay_status,
                bool(attestation_verified),
            )
        except Exception as exc:
            compensation_errors = []
            if device is not None and relay_secret_expected:
                try:
                    self._delete_relay_pair_secret(device.device_id)
                except Exception as cleanup_exc:
                    compensation_errors.append(cleanup_exc)
            if device is not None:
                try:
                    if not self.registry.rollback_created_device(
                        device.device_id,
                        reason=f"pair_finalize_failed:{type(exc).__name__}",
                    ):
                        compensation_errors.append(RuntimeError("created device was not found"))
                except Exception as cleanup_exc:
                    compensation_errors.append(cleanup_exc)
            if not compensation_errors and verification is not None:
                release_verification = getattr(relay_claim_verifier, "release", None)
                if callable(release_verification):
                    try:
                        release_verification(verification)
                    except Exception as cleanup_exc:
                        compensation_errors.append(cleanup_exc)
            if not compensation_errors and marker is not None:
                try:
                    self._delete_record(marker)
                except Exception as cleanup_exc:
                    compensation_errors.append(cleanup_exc)
            if compensation_errors:
                raise PairingError(
                    "pair_finalize_rollback_failed",
                    503,
                    "pairing failed and cleanup could not be completed",
                ) from exc
            if isinstance(exc, PairingError):
                raise
            raise PairingError(
                "pair_finalize_failed",
                503,
                "pairing could not be finalized",
            ) from exc
        # The invitation name is already gone, so a leftover hard-link marker
        # cannot be claimed. Expiry pruning will remove it if this unlink fails.
        if marker is not None:
            try:
                self._delete_record(marker)
            except Exception:
                pass
        return result

    @staticmethod
    def _psk_claim_request_hash(
        *,
        pair_id: str,
        b_pub: bytes,
        confirm: bytes,
        device_name: str,
        scopes: Iterable[str] | None,
        cert_pin: str | None,
        se_public_key_der: str,
        attest_object: dict | None,
        attest_key_id: str,
        attest_environment: str,
        attested_claim_ticket: str | None,
        relay_device_id: str | None,
        relay_required: bool,
        funnel_origin: bool,
        require_direct_attest: bool,
        seal_proof_secret: bool,
        request_binding: str,
    ) -> str:
        ticket_digest = hashlib.sha256(
            str(attested_claim_ticket or "").encode("utf-8")
        ).hexdigest()
        canonical = {
            "pair_id": pair_id,
            "b_pub": base64.b64encode(b_pub).decode("ascii"),
            "confirm": base64.b64encode(confirm).decode("ascii"),
            "device_name": device_name,
            "scopes": sorted(set(scopes or ())),
            "cert_pin": cert_pin or "",
            "se_public_key_der": se_public_key_der,
            "attest_object": attest_object or {},
            "attest_key_id": attest_key_id,
            "attest_environment": attest_environment,
            "attested_claim_ticket_sha256": ticket_digest,
            "relay_device_id": relay_device_id or "",
            "relay_required": bool(relay_required),
            "funnel_origin": bool(funnel_origin),
            "require_direct_attest": bool(require_direct_attest),
            "seal_proof_secret": bool(seal_proof_secret),
            "request_binding": request_binding,
        }
        return hashlib.sha256(
            json.dumps(
                canonical,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _sealed_claim_from_response(response_json: str) -> SealedPSKPairClaim:
        try:
            payload = json.loads(response_json)
            device_payload = payload["device"]
            runtime_payload = payload["runtime"]
            activation_payload = payload["activation"]
            device = CreatedDevice(
                str(device_payload["id"]),
                "",
                "",
                tuple(str(scope) for scope in device_payload["scopes"]),
                str(payload["install_id"]),
                device_payload.get("relay_device_id"),
                str(device_payload.get("attestation_status") or "none"),
            )
            claim = PairClaim(
                device=device,
                host_chain=tuple(str(host) for host in runtime_payload["host_chain"]),
                runtime_port=int(runtime_payload["port"]),
                cert_pin=runtime_payload.get("cert_pin"),
                relay_device_id=device_payload.get("relay_device_id"),
                attestation_status=str(device_payload.get("attestation_status") or "none"),
                direct_attestation_verified=bool(
                    device_payload.get("direct_attestation_verified")
                ),
            )
            return SealedPSKPairClaim(
                claim=claim,
                enc_token=base64.b64decode(str(payload["enc_token"]), validate=True),
                token_nonce=base64.b64decode(str(payload["nonce"]), validate=True),
                mac_confirm=base64.b64decode(str(payload["mac_confirm"]), validate=True),
                enc_proof_secret=base64.b64decode(
                    str(device_payload["enc_proof_secret"]), validate=True
                ),
                proof_secret_nonce=base64.b64decode(
                    str(device_payload["proof_secret_nonce"]), validate=True
                ),
                pair_id=str(activation_payload["pair_id"]),
                activation_nonce=str(activation_payload["nonce"]),
                pending_expires_at=float(activation_payload["expires_at"]),
                response_payload=payload,
            )
        except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise PairingError(
                "pair_response_corrupt", 500, "saved pairing response is corrupt"
            ) from exc

    def _finalize_pending_psk_claim(
        self,
        *,
        pair_id: str,
        request_hash: str,
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
        funnel_origin: bool,
        require_direct_attest: bool,
        attestation_verified: bool | None,
        token: str,
        proof_secret: str,
        device_id: str,
        enc_token: bytes,
        token_nonce: bytes,
        mac_confirm: bytes,
        enc_proof_secret: bytes,
        proof_secret_nonce: bytes,
        k_confirm: bytes,
        request_binding: str,
        runtime_routes: Iterable[dict] | None,
        transport: str,
    ) -> SealedPSKPairClaim:
        if attestation_verified is None:
            attestation_verified = self._verify_claim_attestation(
                pair_id=pair_id,
                record=record,
                attest_object=attest_object,
                attest_key_id=attest_key_id,
                attest_environment=attest_environment,
                require=funnel_origin or require_direct_attest,
                force_production=funnel_origin or require_direct_attest,
            )
        normalized_hosts = tuple(h for h in host_chain if isinstance(h, str) and h)
        if not normalized_hosts:
            raise PairingError("missing_host_chain", 500, "host chain is empty")
        try:
            runtime_port = int(record.get("runtime_port") or self.runtime_port)
        except (TypeError, ValueError, OverflowError) as exc:
            raise PairingError(
                "pair_corrupt", 500, "pair record has an invalid runtime port"
            ) from exc
        try:
            normalized_routes = json.loads(json.dumps(list(runtime_routes or ())))
        except (TypeError, ValueError, RecursionError) as exc:
            raise PairingError(
                "pair_response_invalid", 500, "pairing routes are not serializable"
            ) from exc

        record_purpose = str(record.get("purpose") or "").strip() or None
        if record_purpose == SMOKE_DEVICE_PURPOSE:
            normalized_scopes = tuple(sorted(set(record.get("scopes") or ())))
            if not normalized_scopes or not set(normalized_scopes).issubset(SMOKE_ALLOWED_SCOPES):
                raise PairingError("pair_corrupt", 500, "smoke pairing scopes are invalid")
            try:
                lease_ttl = int(record.get("lease_ttl_seconds"))
            except (TypeError, ValueError, OverflowError) as exc:
                raise PairingError("pair_corrupt", 500, "smoke pairing lease is invalid") from exc
            if not MIN_SMOKE_LEASE_TTL_SECONDS <= lease_ttl <= MAX_SMOKE_LEASE_TTL_SECONDS:
                raise PairingError("pair_corrupt", 500, "smoke pairing lease is invalid")
            lease_expires_at = now + lease_ttl
        elif record_purpose is None:
            normalized_scopes = tuple(sorted(set(scopes or DEFAULT_DEVICE_SCOPES)))
            lease_expires_at = None
        else:
            raise PairingError("pair_corrupt", 500, "pair purpose is invalid")

        relay_status = "none"
        # Keep repair identity fail-closed. The request field is only the value
        # the signed relay ticket must match; it is not trusted metadata.
        verified_relay_device_id = None
        relay_pair_secret = None
        relay_pair_secret_ref = None
        verification = None
        if relay_required or attested_claim_ticket:
            if not attested_claim_ticket:
                raise PairingError("attested_claim_required", 403, "relay claim ticket required")
            if relay_claim_verifier is None:
                raise PairingError(
                    "attested_claim_invalid", 403, "relay claim verifier unavailable"
                )
            try:
                verification = relay_claim_verifier.verify(
                    attested_claim_ticket,
                    pair_id=pair_id,
                    relay_device_id=relay_device_id,
                    device_name=device_name,
                )
            except Exception as exc:
                raise PairingError(
                    getattr(exc, "code", "attested_claim_invalid"),
                    403,
                    getattr(exc, "message", str(exc)),
                ) from exc
            verified_relay_device_id = verification.relay_device_id
            relay_status = verification.attestation_status
            relay_pair_secret = getattr(verification, "relay_pair_secret", None)
            relay_pair_secret_ref = getattr(verification, "relay_pair_secret_ref", None)

        pending_expires_at_ms = math.ceil(
            (now + PENDING_CLAIM_TTL_SECONDS) * 1000
        )
        pending_expires_at = pending_expires_at_ms / 1000.0
        activation_nonce = secrets.token_urlsafe(24)
        response = {
            "claim_result_contract": PAIR_CLAIM_RESULT_CONTRACT,
            "ok": True,
            "pairing_state": "pending_activation",
            "pair_id": pair_id,
            "pv": 2,
            "request_binding": request_binding,
            "device": {
                "id": device_id,
                "scopes": list(normalized_scopes),
                "relay_device_id": verified_relay_device_id,
                "attestation_status": relay_status,
                "direct_attestation_verified": bool(attestation_verified),
                "enc_proof_secret": base64.b64encode(enc_proof_secret).decode("ascii"),
                "proof_secret_nonce": base64.b64encode(proof_secret_nonce).decode("ascii"),
                "purpose": record_purpose,
                "lease_expires_at": lease_expires_at,
            },
            "enc_token": base64.b64encode(enc_token).decode("ascii"),
            "nonce": base64.b64encode(token_nonce).decode("ascii"),
            "mac_confirm": base64.b64encode(mac_confirm).decode("ascii"),
            "install_id": str(record.get("install_id") or self.install_id),
            "runtime": {
                "port": runtime_port,
                "host_chain": list(normalized_hosts),
                "cert_pin": cert_pin,
                "transport": transport or "http-local",
                "routes": normalized_routes,
            },
            "activation": {
                "path": "/pair/psk-activate",
                "pair_id": pair_id,
                "device_id": device_id,
                "nonce": activation_nonce,
                "expires_at": pending_expires_at,
                "expires_at_ms": pending_expires_at_ms,
                "proof_version": "pairling.psk.activate.v1",
            },
        }
        try:
            canonical = pair_claim_result_canonical(response)
        except ValueError as exc:
            raise PairingError(
                "pair_response_invalid", 500, "pairing response could not be authenticated"
            ) from exc
        response["claim_result_proof"] = hmac.new(
            k_confirm, canonical, hashlib.sha256
        ).hexdigest()
        response_json = json.dumps(
            response, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        marker = None
        created = None
        relay_secret_expected = bool(relay_pair_secret and verified_relay_device_id)
        try:
            marker = self._create_claim_marker(pair_id)
            created = self.registry.create_pending_device(
                pair_id=pair_id,
                request_hash=request_hash,
                response_json=response_json,
                pending_expires_at=pending_expires_at,
                activation_nonce=activation_nonce,
                device_name=device_name or "Pairling iPhone",
                token=token,
                proof_secret=proof_secret,
                device_id=device_id,
                scopes=normalized_scopes,
                install_id=str(record.get("install_id") or self.install_id),
                relay_device_id=verified_relay_device_id,
                attestation_status=relay_status,
                device_display_name=device_name or "Pairling iPhone",
                relay_pair_secret_ref=relay_pair_secret_ref,
                se_public_key_der=se_public_key_der,
                purpose=record_purpose,
                lease_expires_at=lease_expires_at,
            )
            if relay_secret_expected:
                self._store_relay_pair_secret(
                    device_id=device_id,
                    relay_device_id=verified_relay_device_id,
                    mac_install_id=str(record.get("install_id") or self.install_id),
                    relay_pair_secret=str(relay_pair_secret),
                    relay_pair_secret_ref=str(relay_pair_secret_ref or ""),
                )
            self._delete_record(path)
            self._claim_attempts.pop(pair_id, None)
        except Exception as exc:
            compensation_errors = []
            if created is not None and relay_secret_expected:
                try:
                    self._delete_relay_pair_secret(device_id)
                except Exception as cleanup_exc:
                    compensation_errors.append(cleanup_exc)
            if created is not None:
                try:
                    if not self.registry.rollback_created_device(
                        device_id,
                        reason=f"pair_pending_finalize_failed:{type(exc).__name__}",
                    ):
                        compensation_errors.append(RuntimeError("pending device was not found"))
                except Exception as cleanup_exc:
                    compensation_errors.append(cleanup_exc)
            if not compensation_errors and verification is not None:
                release_verification = getattr(relay_claim_verifier, "release", None)
                if callable(release_verification):
                    try:
                        release_verification(verification)
                    except Exception as cleanup_exc:
                        compensation_errors.append(cleanup_exc)
            if not compensation_errors and marker is not None:
                try:
                    self._delete_record(marker)
                except Exception as cleanup_exc:
                    compensation_errors.append(cleanup_exc)
            if compensation_errors:
                raise PairingError(
                    "pair_finalize_rollback_failed",
                    503,
                    "pairing failed and cleanup could not be completed",
                ) from exc
            if isinstance(exc, PairingError):
                raise
            if isinstance(exc, DeviceRegistryError):
                self._raise_registry_error(exc)
            raise PairingError(
                "pair_finalize_failed", 503, "pairing could not be finalized"
            ) from exc
        if marker is not None:
            try:
                self._delete_record(marker)
            except Exception:
                pass
        return self._sealed_claim_from_response(response_json)

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
        se_public_key_der: str | None = None,
        attest_object: dict | None = None,
        attest_key_id: str | None = None,
        attest_environment: str | None = None,
        attested_claim_ticket: str | None = None,
        enc_attested_claim_ticket: str | None = None,
        attested_claim_ticket_nonce: str | None = None,
        relay_device_id: str | None = None,
        relay_required: bool = False,
        relay_claim_verifier=None,
        funnel_origin: bool = False,
        require_direct_attest: bool = False,
        seal_proof_secret: bool = False,
        request_contract: str | None = None,
        request_binding: str | None = None,
        protocol_version: int = 2,
        activation_contract: str = "pairling.psk.activate.v1",
        require_request_binding: bool = False,
        runtime_routes: Iterable[dict] | None = None,
        transport: str = "http-local",
    ) -> SealedPSKPairClaim:
        """WS3 PSK-authenticated ECDH claim. The secret is NEVER received; the
        caller proves knowledge of it by completing the authenticated key
        exchange (phone confirm tag under K_confirm). Both durable credentials
        are sealed before finalization, so a crypto failure leaves the invitation
        available for a safe retry."""
        if _psk is None:
            raise PairingError("psk_unavailable", 503, "psk crypto unavailable")
        if not seal_proof_secret:
            raise PairingError(
                "upgrade_required",
                426,
                "this Pairling version requires sealed proof credentials",
            )
        accepted_request_binding = ""
        if require_request_binding:
            if attested_claim_ticket is not None:
                raise PairingError(
                    "plaintext_attested_claim_forbidden",
                    400,
                    "v2 pairing requires an encrypted relay claim ticket",
                )
            if protocol_version != 2:
                raise PairingError(
                    "upgrade_required", 426, "unsupported pairing protocol version"
                )
            try:
                expected_request_binding = pair_claim_request_binding(
                    request_contract=request_contract,
                    pair_id=pair_id,
                    device_name=device_name,
                    protocol_version=protocol_version,
                    seal_proof_secret=seal_proof_secret,
                    activation_contract=activation_contract,
                    se_public_key_der=se_public_key_der,
                    direct_attest_object=attest_object,
                    attest_key_id=attest_key_id,
                    attest_environment=attest_environment,
                    enc_attested_claim_ticket=enc_attested_claim_ticket,
                    attested_claim_ticket_nonce=attested_claim_ticket_nonce,
                    relay_device_id=relay_device_id,
                )
            except ValueError as exc:
                raise PairingError(
                    "psk_request_binding_invalid",
                    400,
                    "pairing request binding is invalid",
                ) from exc
            if not isinstance(request_binding, str) or not secrets.compare_digest(
                expected_request_binding, request_binding
            ):
                raise PairingError(
                    "psk_request_binding_invalid",
                    403,
                    "pairing request binding could not be verified",
                )
            accepted_request_binding = expected_request_binding
        elif (
            enc_attested_claim_ticket is not None
            or attested_claim_ticket_nonce is not None
        ):
            raise PairingError(
                "psk_request_binding_required",
                426,
                "encrypted relay claims require the v2 request binding",
            )
        try:
            b_pub = base64.b64decode(b_pub_b64, validate=True)
            confirm = base64.b64decode(confirm_b64, validate=True)
        except Exception:
            raise PairingError("psk_bad_key", 400, "invalid psk material")
        request_hash = self._psk_claim_request_hash(
            pair_id=pair_id,
            b_pub=b_pub,
            confirm=confirm,
            device_name=device_name,
            scopes=scopes,
            cert_pin=cert_pin,
            se_public_key_der=se_public_key_der or "",
            attest_object=attest_object,
            attest_key_id=attest_key_id or "",
            attest_environment=attest_environment or "",
            attested_claim_ticket=(
                None if require_request_binding else attested_claim_ticket
            ),
            relay_device_id=relay_device_id,
            relay_required=relay_required,
            funnel_origin=funnel_origin,
            require_direct_attest=require_direct_attest,
            seal_proof_secret=seal_proof_secret,
            request_binding=accepted_request_binding,
        )
        with self._claim_lock:
            self._cleanup_pending_claims()
            try:
                saved = self.registry.resumable_pair_claim(pair_id, request_hash)
            except DeviceRegistryError as exc:
                self._raise_registry_error(exc)
            if saved is not None:
                return self._sealed_claim_from_response(saved.response_json)
            attestation_verified = None
            if funnel_origin or require_direct_attest:
                # Public network claims prove a genuine device BEFORE the attempt counter
                # and the ECDH derive, so an un-attested spray cannot lock out a
                # live invitation or force crypto work. Fail closed regardless of
                # the env default, with the environment pinned to production.
                hard_attest_record, _ = self._load_record(pair_id)
                attestation_verified = self._verify_claim_attestation(
                    pair_id=pair_id, record=hard_attest_record, attest_object=attest_object,
                    attest_key_id=attest_key_id or "",
                    attest_environment=attest_environment or "",
                    require=True, force_production=True,
                )
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
            if require_request_binding:
                expected = pair_claim_phone_confirm_v2(
                    k_confirm=k_confirm,
                    pair_id=pair_id,
                    a_pub=a_pub,
                    b_pub=b_pub,
                    request_binding=accepted_request_binding,
                )
            else:
                expected = _psk.confirm_tag(
                    k_confirm, _psk.CONFIRM_PHONE, pair_id, a_pub, b_pub
                )
            if not secrets.compare_digest(expected, confirm):
                raise PairingError("psk_confirm_invalid", 403, "psk confirmation invalid")
            aad = _psk.transcript(pair_id, a_pub, b_pub)
            effective_attested_claim_ticket = attested_claim_ticket
            if require_request_binding and enc_attested_claim_ticket is not None:
                try:
                    relay_ticket_ciphertext = base64.b64decode(
                        enc_attested_claim_ticket, validate=True
                    )
                    relay_ticket_nonce = base64.b64decode(
                        attested_claim_ticket_nonce, validate=True
                    )
                    effective_attested_claim_ticket = _psk.open_token(
                        k_token,
                        relay_ticket_nonce,
                        relay_ticket_ciphertext,
                        aad=aad + b"\npairling.psk.relay_ticket.v1",
                    )
                except Exception as exc:
                    raise PairingError(
                        "attested_claim_invalid",
                        403,
                        "encrypted relay claim ticket could not be verified",
                    ) from exc
            mac_confirm = _psk.confirm_tag(k_confirm, _psk.CONFIRM_MAC, pair_id, a_pub, b_pub)
            token = generate_token()
            proof_secret = generate_proof_secret()
            device_id = generate_device_id()
            try:
                token_nonce, enc_token = _psk.seal_token(k_token, token, aad=aad)
                proof_secret_aad = aad + b"\npairling.psk.proof_secret.v1"
                proof_secret_nonce, enc_proof_secret = _psk.seal_token(
                    k_token,
                    proof_secret,
                    aad=proof_secret_aad,
                )
            except Exception as exc:
                raise PairingError(
                    "psk_seal_failed",
                    503,
                    "pair credentials could not be sealed",
                ) from exc
            return self._finalize_pending_psk_claim(
                pair_id=pair_id,
                request_hash=request_hash,
                record=record,
                path=path,
                now=now,
                device_name=device_name,
                host_chain=host_chain,
                scopes=scopes,
                cert_pin=cert_pin,
                se_public_key_der=se_public_key_der or "",
                attest_object=attest_object,
                attest_key_id=attest_key_id or "",
                attest_environment=attest_environment or "",
                attested_claim_ticket=effective_attested_claim_ticket,
                relay_device_id=relay_device_id,
                relay_required=relay_required,
                relay_claim_verifier=relay_claim_verifier,
                funnel_origin=funnel_origin,
                require_direct_attest=require_direct_attest,
                attestation_verified=attestation_verified,
                token=token,
                proof_secret=proof_secret,
                device_id=device_id,
                enc_token=enc_token,
                token_nonce=token_nonce,
                mac_confirm=mac_confirm,
                enc_proof_secret=enc_proof_secret,
                proof_secret_nonce=proof_secret_nonce,
                k_confirm=k_confirm,
                request_binding=accepted_request_binding,
                runtime_routes=runtime_routes,
                transport=transport,
            )

    def activate_psk_claim(
        self,
        *,
        pair_id: str,
        device_id: str,
        activation_nonce: str,
        token_hash: str,
        activation_proof: str,
        before_activation: Callable[[], None] | None = None,
    ) -> PairActivationResult:
        with self._claim_lock:
            self._cleanup_pending_claims()
            try:
                return self.registry.activate_pending_claim(
                    pair_id=pair_id,
                    device_id=device_id,
                    activation_nonce=activation_nonce,
                    token_hash=token_hash,
                    activation_proof=activation_proof,
                    before_activation=before_activation,
                )
            except DeviceRegistryError as exc:
                if exc.code == "pair_activation_superseded" and exc.device_id:
                    try:
                        if exc.relay_secret_expected:
                            self._delete_relay_pair_secret(exc.device_id)
                        self.registry.mark_pending_secret_cleaned(pair_id, exc.device_id)
                    except Exception:
                        pass
                self._raise_registry_error(exc)

    def seal_psk_token(self, k_token: bytes, token: str, aad: bytes) -> tuple[bytes, bytes]:
        """AES-256-GCM the bearer token under K_token so only the phone (which
        derived the same key) can read it. Returns (nonce, ciphertext‖tag)."""
        if _psk is None:
            raise PairingError("psk_unavailable", 503, "psk crypto unavailable")
        return _psk.seal_token(k_token, token, aad=aad)

    def _delete_record(self, path: Path) -> None:
        if path.parent != self.pair_root:
            raise PairingError("pair_storage_unavailable", 503, "invalid pairing storage path")
        try:
            root_fd = self._open_pair_root(create=False)
        except PairingError as exc:
            if exc.code == "pair_not_found":
                return
            raise
        try:
            os.unlink(path.name, dir_fd=root_fd)
        except FileNotFoundError:
            pass
        finally:
            os.close(root_fd)

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

        def store_secret(payload: dict) -> None:
            device = payload["devices"].setdefault(device_id, {})
            device["relay_device_id"] = relay_device_id
            device["mac_install_id"] = mac_install_id
            device["relay_pair_secret"] = relay_pair_secret
            device["relay_pair_secret_ref"] = relay_pair_secret_ref
            device["updated_at"] = time.time()

        try:
            from push_dispatcher import mutate_push_secrets

            mutate_push_secrets(secret_path, store_secret)
        except Exception as exc:
            raise PairingError(
                "pair_secret_store_unavailable",
                503,
                "relay pairing secret could not be stored",
            ) from exc

    def _delete_relay_pair_secret(self, device_id: str) -> None:
        secret_path = app_support_root() / "push-secrets.json"

        def delete_secret(payload: dict) -> None:
            payload["devices"].pop(device_id, None)

        try:
            from push_dispatcher import mutate_push_secrets

            mutate_push_secrets(secret_path, delete_secret)
        except Exception as exc:
            raise PairingError(
                "pair_secret_store_unavailable",
                503,
                "relay pairing secret could not be removed",
            ) from exc


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
