#!/usr/bin/env python3
"""Short-lived Pairling pairing records and claim flow."""

from __future__ import annotations

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


DEFAULT_PAIR_TTL_SECONDS = 180
MIN_PAIR_TTL_SECONDS = 60
MAX_PAIR_TTL_SECONDS = 300


@dataclass(frozen=True)
class PairStart:
    pair_id: str
    secret: str
    expires_at: float
    install_id: str
    service_type: str
    txt: dict[str, str]


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
        expires_at = time.time() + ttl
        record = {
            "pair_id": pair_id,
            "secret": secret,
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
            "pairing_nonce": secrets.token_urlsafe(9),
            "route_hint": os.environ.get("PAIRLING_ROUTE_HINT", "lan,bonjour,tailnet")[:64],
        }
        return PairStart(pair_id, secret, expires_at, self.install_id, PAIR_SERVICE_TYPE, txt)

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
        attested_claim_ticket: str | None = None,
        relay_device_id: str | None = None,
        relay_required: bool = False,
        relay_claim_verifier=None,
    ) -> PairClaim:
        with self._claim_lock:
            record, path = self._load_record(pair_id)
            now = time.time()
            if record.get("claimed_at") is not None:
                raise PairingError("pair_already_claimed", 409, "pair record already claimed")
            if now > float(record.get("expires_at") or 0):
                self._delete_record(path)
                raise PairingError("pair_expired", 410, "pair record expired")
            if not secrets.compare_digest(str(record.get("secret") or ""), secret or ""):
                raise PairingError("invalid_secret", 403, "invalid pair secret")
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
                record["claimed_at"] = now
                record["device_id"] = device.device_id
                path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
                self._delete_record(path)
                self._delete_record(marker)
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
