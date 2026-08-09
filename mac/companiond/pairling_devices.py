#!/usr/bin/env python3
"""Per-device token registry for the Pairling Mac runtime."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from runtime_contract import (
    DEFAULT_DEVICE_SCOPES,
    DEVICE_ROLE_CUSTOM,
    DEVICE_ROLE_INTERNAL,
    DEVICE_ROLE_OPERATOR,
    DEVICE_ROLE_READER,
    LOCAL_MCP_DISPATCH_SCOPE,
    MIGRATABLE_OPERATOR_DEVICE_SCOPES,
    OPERATOR_DEVICE_SCOPES,
    READER_DEVICE_SCOPES,
    device_scopes_for_role,
)
from runtime_paths import app_support_root, audit_log_path, devices_db_path


SQLITE_BUSY_TIMEOUT_MS = int(os.environ.get("PAIRLING_SQLITE_BUSY_TIMEOUT_MS", "5000"))
QUERY_ONLY_DB_ATTEMPTS = 4
QUERY_ONLY_DB_INITIAL_DELAY_SECONDS = 0.05
PAIR_ACTIVATION_PROOF_VERSION = "pairling.psk.activate.v1"
PAIR_ACTIVATION_RESULT_CONTRACT = "pairling.psk.activate.result.v1"
SMOKE_DEVICE_PURPOSE = "runtime_truth_smoke"
LOCAL_MCP_DEVICE_PURPOSE = "local_mcp_bridge"
INTERNAL_DEVICE_PURPOSES = (
    SMOKE_DEVICE_PURPOSE,
    LOCAL_MCP_DEVICE_PURPOSE,
)
INSTALL_ID_PATTERN = re.compile(r"\Ainst_[A-Za-z0-9_-]+\Z")
INSTALL_ID_MAX_LENGTH = 256
PHONE_TOOL_ACTIVITY_EVENT = "pairling_tools.run"
PHONE_TOOL_ACTIVITY_MAX_ITEMS = 100
PHONE_TOOL_ACTIVITY_READ_BYTES = 2 * 1024 * 1024

def _device_role_for_scopes(
    *,
    role: str | None,
    scopes: Iterable[str],
    purpose: str | None,
) -> str:
    normalized_role = str(role or "").strip().lower()
    normalized_scopes = frozenset(scopes)
    if normalized_role:
        if normalized_role not in {
            DEVICE_ROLE_READER,
            DEVICE_ROLE_OPERATOR,
            DEVICE_ROLE_INTERNAL,
            DEVICE_ROLE_CUSTOM,
        }:
            raise ValueError(f"unsupported device role: {normalized_role}")
        expected = {
            DEVICE_ROLE_READER: READER_DEVICE_SCOPES,
            DEVICE_ROLE_OPERATOR: OPERATOR_DEVICE_SCOPES,
        }.get(normalized_role)
        if expected is not None and normalized_scopes != expected:
            raise ValueError(f"{normalized_role} device scopes do not match its role profile")
        return normalized_role
    if str(purpose or "").strip() in INTERNAL_DEVICE_PURPOSES:
        return DEVICE_ROLE_INTERNAL
    if normalized_scopes == READER_DEVICE_SCOPES:
        return DEVICE_ROLE_READER
    if normalized_scopes in MIGRATABLE_OPERATOR_DEVICE_SCOPES:
        return DEVICE_ROLE_OPERATOR
    return DEVICE_ROLE_CUSTOM


def utc_epoch() -> float:
    return time.time()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> str:
    return "pld_" + secrets.token_urlsafe(32)


def generate_device_id() -> str:
    return "dev_" + secrets.token_hex(16)


def generate_proof_secret() -> str:
    return "prf_" + secrets.token_urlsafe(32)


def _connect_query_only_database(path: Path) -> sqlite3.Connection:
    for attempt in range(QUERY_ONLY_DB_ATTEMPTS):
        connection = None
        try:
            connection = sqlite3.connect(
                str(path),
                timeout=max(SQLITE_BUSY_TIMEOUT_MS, 1) / 1000,
            )
            connection.execute("PRAGMA query_only=ON")
            return connection
        except sqlite3.Error:
            if connection is not None:
                connection.close()
            if attempt + 1 >= QUERY_ONLY_DB_ATTEMPTS:
                raise
            time.sleep(QUERY_ONLY_DB_INITIAL_DELAY_SECONDS * (2**attempt))
    raise AssertionError("query-only database retry loop exhausted")


def _redact_for_audit(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in ("token", "secret", "proof", "authorization")):
                redacted[str(key)] = "[redacted]"
            else:
                redacted[str(key)] = _redact_for_audit(item)
        return redacted
    if isinstance(value, list):
        return [_redact_for_audit(item) for item in value]
    return value


class InstallIdentityError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def normalize_install_id(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > INSTALL_ID_MAX_LENGTH
        or INSTALL_ID_PATTERN.fullmatch(normalized) is None
    ):
        return ""
    return normalized


def _require_identity_directory(
    path: Path,
    *,
    create: bool,
    error_code: str,
    label: str,
) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if not create:
            return False
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = path.lstat()
    except OSError as exc:
        raise InstallIdentityError(
            error_code,
            f"{label} could not be inspected.",
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise InstallIdentityError(
            error_code,
            f"{label} must be a real directory, not a symlink or another file type.",
        )
    if create:
        try:
            os.chmod(path, 0o700, follow_symlinks=False)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        except (NotImplementedError, OSError):
            pass
    return True


def _read_identity_text(
    support_root: Path,
    path: Path,
    *,
    kind: str,
) -> str | None:
    error_prefix = f"install_identity_{kind}"
    if not _require_identity_directory(
        support_root,
        create=False,
        error_code=f"{error_prefix}_unsafe",
        label="Pairling app support",
    ):
        return None
    if path.parent != support_root and not _require_identity_directory(
        path.parent,
        create=False,
        error_code=f"{error_prefix}_unsafe",
        label=f"Pairling {kind} parent",
    ):
        return None
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InstallIdentityError(
            f"{error_prefix}_unreadable",
            f"Pairling {kind} identity exists but could not be inspected.",
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise InstallIdentityError(
            f"{error_prefix}_unsafe",
            f"Pairling {kind} identity must be a regular file, not a symlink or another file type.",
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise InstallIdentityError(
            f"{error_prefix}_unsafe",
            f"Pairling {kind} identity exists but could not be opened safely.",
        ) from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise InstallIdentityError(
                f"{error_prefix}_unsafe",
                f"Pairling {kind} identity must be a regular file.",
            )
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            return handle.read()
    except UnicodeError as exc:
        raise InstallIdentityError(
            f"{error_prefix}_invalid",
            f"Pairling {kind} identity is not valid UTF-8 and was left unchanged.",
        ) from exc
    finally:
        if fd >= 0:
            os.close(fd)


def _write_private_text(
    support_root: Path,
    path: Path,
    text: str,
    *,
    kind: str,
    repair_invalid_regular: bool = False,
) -> None:
    error_prefix = f"install_identity_{kind}"
    _require_identity_directory(
        support_root,
        create=True,
        error_code=f"{error_prefix}_unsafe",
        label="Pairling app support",
    )
    if path.parent != support_root:
        _require_identity_directory(
            path.parent,
            create=True,
            error_code=f"{error_prefix}_unsafe",
            label=f"Pairling {kind} parent",
        )
    try:
        current = _read_identity_text(support_root, path, kind=kind)
    except InstallIdentityError as exc:
        if not repair_invalid_regular or exc.code != f"{error_prefix}_invalid":
            raise
        current = None
    if current == text:
        try:
            os.chmod(path, 0o600, follow_symlinks=False)
        except (NotImplementedError, OSError):
            pass
        return
    tmp = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        try:
            directory_fd = os.open(
                path.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
    try:
        os.chmod(path, 0o600, follow_symlinks=False)
    except (NotImplementedError, OSError):
        pass


def _read_install_config(root: Path) -> dict[str, Any]:
    path = root / "config.json"
    raw = _read_identity_text(root, path, kind="config")
    if raw is None:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InstallIdentityError(
            "install_identity_config_invalid",
            "Pairling config.json is malformed and was left unchanged.",
        ) from exc
    if not isinstance(payload, dict):
        raise InstallIdentityError(
            "install_identity_config_invalid",
            "Pairling config.json must contain a JSON object and was left unchanged.",
        )
    return payload


def _config_install_id(root: Path) -> str:
    payload = _read_install_config(root)
    raw_value = payload.get("install_id")
    if raw_value is None or (isinstance(raw_value, str) and not raw_value.strip()):
        return ""
    value = normalize_install_id(raw_value)
    if not value:
        raise InstallIdentityError(
            "install_identity_config_invalid",
            "Pairling config.json contains an invalid install identity and was left unchanged.",
        )
    return value


def _state_install_id(path: Path) -> str:
    support_root = path.parent.parent
    raw = _read_identity_text(support_root, path, kind="state")
    if raw is None:
        return ""
    value = normalize_install_id(raw)
    if not value:
        raise InstallIdentityError(
            "install_identity_state_invalid",
            "Pairling state/install-id is invalid and was left unchanged.",
        )
    return value


def _active_external_install_ids(path: Path) -> tuple[str, ...]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return ()
    except OSError as exc:
        raise InstallIdentityError(
            "install_identity_registry_unavailable",
            "Pairling could not inspect the device registry while recovering its install identity.",
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise InstallIdentityError(
            "install_identity_registry_invalid",
            "Pairling devices.sqlite must be a regular file, not a symlink or another file type.",
        )
    try:
        with closing(_connect_query_only_database(path)) as conn:
            tables = {
                str(row[0])
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            if "devices" not in tables:
                return ()
            columns = {
                str(row[1])
                for row in conn.execute("PRAGMA table_info(devices)").fetchall()
            }
            has_activation_state = "activation_state" in columns
            has_purpose = "purpose" in columns
            if has_activation_state and has_purpose:
                rows = conn.execute(
                    "SELECT DISTINCT install_id FROM devices "
                    "WHERE revoked_at IS NULL "
                    "AND COALESCE(activation_state, 'active') = 'active' "
                    "AND COALESCE(purpose, '') NOT IN (?, ?)",
                    INTERNAL_DEVICE_PURPOSES,
                ).fetchall()
            elif has_activation_state:
                rows = conn.execute(
                    "SELECT DISTINCT install_id FROM devices "
                    "WHERE revoked_at IS NULL "
                    "AND COALESCE(activation_state, 'active') = 'active'"
                ).fetchall()
            elif has_purpose:
                rows = conn.execute(
                    "SELECT DISTINCT install_id FROM devices "
                    "WHERE revoked_at IS NULL "
                    "AND COALESCE(purpose, '') NOT IN (?, ?)",
                    INTERNAL_DEVICE_PURPOSES,
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT DISTINCT install_id FROM devices WHERE revoked_at IS NULL"
                ).fetchall()
    except sqlite3.Error as exc:
        raise InstallIdentityError(
            "install_identity_registry_unavailable",
            "Pairling could not read the device registry while recovering its install identity.",
        ) from exc
    values = tuple(sorted({normalize_install_id(row[0]) for row in rows}))
    if any(not value for value in values):
        raise InstallIdentityError(
            "install_identity_registry_invalid",
            "An active Pairling device has no install identity.",
        )
    return values


def resolve_install_id(
    root: Path | None = None,
    *,
    allow_generate: bool = False,
) -> str:
    """Resolve one Mac identity and keep the state mirror in sync.

    A valid config is authoritative. Recovery without config prefers one
    unambiguous active external device identity, then the state mirror. Only
    setup passes allow_generate=True.
    """
    support_root = root or app_support_root()
    state_path = support_root / "state" / "install-id"
    config_value = _config_install_id(support_root)
    active_values = _active_external_install_ids(support_root / "devices.sqlite")
    if len(active_values) > 1:
        raise InstallIdentityError(
            "install_identity_ambiguous",
            "Pairling found multiple active install identities and will not choose one.",
        )
    if (
        config_value
        and active_values
        and not secrets.compare_digest(config_value, active_values[0])
    ):
        raise InstallIdentityError(
            "install_identity_mismatch",
            "Pairling config.json does not match the active device registry identity.",
        )
    if config_value:
        _write_private_text(
            support_root,
            state_path,
            config_value + "\n",
            kind="state",
            repair_invalid_regular=True,
        )
        return config_value
    if active_values:
        value = active_values[0]
        _write_private_text(support_root, state_path, value + "\n", kind="state")
        return value

    state_value = _state_install_id(state_path)
    if state_value:
        _write_private_text(support_root, state_path, state_value + "\n", kind="state")
        return state_value
    if not allow_generate:
        raise InstallIdentityError(
            "install_identity_missing",
            "Pairling setup must create this Mac's install identity before the runtime starts.",
        )
    value = "inst_" + secrets.token_urlsafe(18)
    _write_private_text(support_root, state_path, value + "\n", kind="state")
    return value


def ensure_install_identity(
    root: Path | None = None,
    *,
    runtime_port: int,
) -> str:
    """Create or recover setup-owned config and its private state mirror."""
    support_root = root or app_support_root()
    config_path = support_root / "config.json"
    existing_payload = _read_install_config(support_root)
    existing_value = normalize_install_id(existing_payload.get("install_id"))
    value = resolve_install_id(support_root, allow_generate=True)
    if existing_value:
        try:
            os.chmod(config_path, 0o600, follow_symlinks=False)
        except (NotImplementedError, OSError):
            pass
        return value

    payload = existing_payload
    payload["schema_version"] = 1
    payload["product"] = "Pairling"
    payload["install_id"] = value
    runtime = payload.get("runtime") if isinstance(payload.get("runtime"), dict) else {}
    runtime["label"] = "dev.pairling.companiond"
    runtime["port"] = int(runtime_port)
    payload["runtime"] = runtime
    payload.setdefault(
        "created_at",
        datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    )
    _write_private_text(
        support_root,
        config_path,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        kind="config",
    )
    return value


def persist_pairdrop_root(root: Path, pairdrop_path: Path) -> Path:
    """Persist the setup-selected PairDrop vault without replacing config identity."""
    support_root = Path(root)
    canonical = Path(pairdrop_path).expanduser()
    if not canonical.is_absolute():
        raise InstallIdentityError(
            "pairdrop_root_invalid",
            "PairDrop storage must use an absolute path.",
        )
    canonical = canonical.resolve(strict=False)
    payload = _read_install_config(support_root)
    if not normalize_install_id(payload.get("install_id")):
        raise InstallIdentityError(
            "install_identity_config_invalid",
            "Pairling config.json must contain an install identity before PairDrop is configured.",
        )
    paths = payload.get("paths") if isinstance(payload.get("paths"), dict) else {}
    paths["pairdrop"] = str(canonical)
    payload["paths"] = paths
    _write_private_text(
        support_root,
        support_root / "config.json",
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        kind="config",
        repair_invalid_regular=True,
    )
    return canonical


def persist_push_provider_defaults(
    root: Path,
    relay_url: str = "https://relay.pairling.dev",
) -> dict[str, str]:
    """Give new installs a managed push route without replacing explicit choices."""
    support_root = Path(root)
    payload = _read_install_config(support_root)
    if not normalize_install_id(payload.get("install_id")):
        raise InstallIdentityError(
            "install_identity_config_invalid",
            "Pairling config.json must contain an install identity before push is configured.",
        )
    normalized_relay_url = str(relay_url or "").strip().rstrip("/")
    if not normalized_relay_url.startswith("https://"):
        raise InstallIdentityError(
            "push_relay_url_invalid",
            "Pairling's managed relay must use an HTTPS URL.",
        )

    push = payload.get("push") if isinstance(payload.get("push"), dict) else {}
    provider_mode = str(push.get("provider_mode") or "").strip()
    if not provider_mode:
        provider_mode = "relay"
        push["provider_mode"] = provider_mode
    if provider_mode == "relay" and not str(push.get("relay_url") or "").strip():
        push["relay_url"] = normalized_relay_url
    payload["push"] = push
    _write_private_text(
        support_root,
        support_root / "config.json",
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        kind="config",
        repair_invalid_regular=True,
    )
    return {
        "provider_mode": provider_mode,
        "relay_url": str(push.get("relay_url") or ""),
    }


@dataclass(frozen=True)
class DeviceAuthResult:
    ok: bool
    status: int
    reason: str
    device_id: str | None = None
    install_id: str | None = None
    proof_secret: str | None = None
    token_hash: str | None = None
    scopes: frozenset[str] = frozenset()
    activation_state: str = "active"
    role: str | None = None
    credential_expires_at: float | None = None

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


@dataclass(frozen=True)
class CreatedDevice:
    device_id: str
    token: str
    proof_secret: str
    scopes: tuple[str, ...]
    install_id: str
    relay_device_id: str | None = None
    attestation_status: str = "none"
    role: str | None = None


@dataclass(frozen=True)
class PendingClaimRecord:
    pair_id: str
    device_id: str
    request_hash: str
    response_json: str
    state: str
    expires_at: float



@dataclass(frozen=True)
class PendingActivationContext:
    purpose: str | None



@dataclass(frozen=True)
class PairActivationResult:
    device_id: str
    pair_id: str
    already_active: bool
    superseded_device_ids: tuple[str, ...]
    activation_result: dict[str, Any] | None = None


class DeviceRegistryError(Exception):
    def __init__(
        self,
        code: str,
        status: int,
        message: str,
        *,
        device_id: str | None = None,
        relay_secret_expected: bool = False,
        activation_result: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.status = status
        self.message = message
        self.device_id = device_id
        self.relay_secret_expected = relay_secret_expected
        self.activation_result = activation_result


def _activation_result_scalar(value: str, field: str) -> str:
    text = str(value)
    if not text or "\n" in text or "\r" in text:
        raise ValueError(f"{field} is not a safe activation result scalar")
    return text


def pair_activation_result_canonical(
    *,
    ok: bool,
    pair_id: str,
    device_id: str,
    install_id: str,
    activation_nonce: str,
    token_hash: str,
    activation_proof: str,
    pairing_state: str,
    outcome: str,
    already_active: bool,
    superseded_device_ids: Iterable[str] = (),
) -> bytes:
    sorted_ids = sorted(
        {
            _activation_result_scalar(value, "superseded_device_id")
            for value in superseded_device_ids
        }
    )
    scalars = [
        PAIR_ACTIVATION_RESULT_CONTRACT,
        "1" if ok else "0",
        _activation_result_scalar(pair_id, "pair_id"),
        _activation_result_scalar(device_id, "device_id"),
        _activation_result_scalar(install_id, "install_id"),
        _activation_result_scalar(activation_nonce, "activation_nonce"),
        _activation_result_scalar(token_hash, "token_hash").lower(),
        _activation_result_scalar(activation_proof, "activation_proof").lower(),
        _activation_result_scalar(pairing_state, "pairing_state"),
        _activation_result_scalar(outcome, "outcome"),
        "1" if already_active else "0",
        str(len(sorted_ids)),
        *sorted_ids,
    ]
    return "\n".join(scalars).encode("utf-8")


def signed_pair_activation_result(
    *,
    proof_secret: str,
    ok: bool,
    pair_id: str,
    device_id: str,
    install_id: str,
    activation_nonce: str,
    token_hash: str,
    activation_proof: str,
    pairing_state: str,
    outcome: str,
    already_active: bool,
    superseded_device_ids: Iterable[str] = (),
) -> dict[str, Any]:
    sorted_ids = tuple(sorted(set(str(value) for value in superseded_device_ids)))
    canonical = pair_activation_result_canonical(
        ok=ok,
        pair_id=pair_id,
        device_id=device_id,
        install_id=install_id,
        activation_nonce=activation_nonce,
        token_hash=token_hash,
        activation_proof=activation_proof,
        pairing_state=pairing_state,
        outcome=outcome,
        already_active=already_active,
        superseded_device_ids=sorted_ids,
    )
    return {
        "result_contract": PAIR_ACTIVATION_RESULT_CONTRACT,
        "ok": bool(ok),
        "pairing_state": pairing_state,
        "outcome": outcome,
        "pair_id": pair_id,
        "device_id": device_id,
        "install_id": install_id,
        "activation_nonce": activation_nonce,
        "token_hash": token_hash.lower(),
        "activation_proof": activation_proof.lower(),
        "already_active": bool(already_active),
        "superseded_device_ids": list(sorted_ids),
        "result_proof": hmac.new(
            proof_secret.encode("utf-8"), canonical, hashlib.sha256
        ).hexdigest(),
    }


def pair_activation_canonical(
    *,
    pair_id: str,
    device_id: str,
    activation_nonce: str,
    token_hash: str,
    install_id: str,
) -> bytes:
    return (
        f"{PAIR_ACTIVATION_PROOF_VERSION}\n{pair_id}\n{device_id}\n"
        f"{activation_nonce}\n{token_hash}\n{install_id}"
    ).encode("utf-8")


class DeviceRegistry:
    def __init__(self, db_path: Path | None = None, audit_path: Path | None = None):
        self.db_path = db_path or devices_db_path()
        self.audit_path = audit_path or audit_log_path()
        self._last_seen_lock = threading.Lock()
        self._last_seen_marks: dict[str, float] = {}
        self._flushed_marks: dict[str, float] = {}

    @contextmanager
    def connect(self, *, immediate: bool = False):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.db_path.parent, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        except OSError:
            pass
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=max(SQLITE_BUSY_TIMEOUT_MS, 1) / 1000,
        )
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            self._ensure_schema(conn)
            conn.commit()
            if immediate:
                conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                scopes_json TEXT NOT NULL,
                role TEXT,
                install_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                last_seen_at REAL,
                revoked_at REAL
            )
            """
        )
        existing = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(devices)").fetchall()
        }
        additive_columns = {
            "role": "ALTER TABLE devices ADD COLUMN role TEXT",
            "relay_device_id": "ALTER TABLE devices ADD COLUMN relay_device_id TEXT",
            "attestation_status": "ALTER TABLE devices ADD COLUMN attestation_status TEXT DEFAULT 'none'",
            "apns_registered_at": "ALTER TABLE devices ADD COLUMN apns_registered_at REAL",
            "relay_pair_secret_ref": "ALTER TABLE devices ADD COLUMN relay_pair_secret_ref TEXT",
            "device_display_name": "ALTER TABLE devices ADD COLUMN device_display_name TEXT",
            "superseded_by_device_id": "ALTER TABLE devices ADD COLUMN superseded_by_device_id TEXT",
            "proof_secret": "ALTER TABLE devices ADD COLUMN proof_secret TEXT",
            "tailnet_node_id": "ALTER TABLE devices ADD COLUMN tailnet_node_id TEXT",
            # WS4: base64 X9.63 (uncompressed P-256 point) of the device's
            # Secure-Enclave public key, registered at first pair. Used to
            # verify zero-interaction re-pair challenge signatures.
            "se_public_key_der": "ALTER TABLE devices ADD COLUMN se_public_key_der TEXT",
            "activation_state": "ALTER TABLE devices ADD COLUMN activation_state TEXT NOT NULL DEFAULT 'active'",
            "pending_pair_id": "ALTER TABLE devices ADD COLUMN pending_pair_id TEXT",
            "pending_expires_at": "ALTER TABLE devices ADD COLUMN pending_expires_at REAL",
            "activation_nonce": "ALTER TABLE devices ADD COLUMN activation_nonce TEXT",
            "activated_at": "ALTER TABLE devices ADD COLUMN activated_at REAL",
            "purpose": "ALTER TABLE devices ADD COLUMN purpose TEXT",
            "lease_expires_at": "ALTER TABLE devices ADD COLUMN lease_expires_at REAL",
        }
        role_was_added = "role" not in existing
        for column, statement in additive_columns.items():
            if column not in existing:
                conn.execute(statement)
        rows = conn.execute(
            "SELECT device_id, scopes_json, purpose, role FROM devices"
        ).fetchall()
        for row in rows:
            try:
                saved_scopes = frozenset(json.loads(row["scopes_json"] or "[]"))
            except (json.JSONDecodeError, TypeError, ValueError):
                saved_scopes = frozenset()
            purpose = str(row["purpose"] or "").strip()
            saved_role = str(row["role"] or "").strip().lower()
            is_internal = (
                purpose in INTERNAL_DEVICE_PURPOSES
                or LOCAL_MCP_DISPATCH_SCOPE in saved_scopes
            )
            if is_internal:
                migrated_role = DEVICE_ROLE_INTERNAL
            elif not purpose and (
                saved_role == DEVICE_ROLE_OPERATOR
                or saved_scopes in MIGRATABLE_OPERATOR_DEVICE_SCOPES
            ):
                # Preserve the exact authority that the local Mac previously
                # granted. A role migration may classify historical human
                # pairings, but it must never add scopes as new controls ship.
                # Fresh Operator scopes require a new explicit local pairing.
                migrated_role = DEVICE_ROLE_OPERATOR
            elif saved_role:
                migrated_role = saved_role
            elif saved_scopes == READER_DEVICE_SCOPES:
                migrated_role = DEVICE_ROLE_READER
            else:
                migrated_role = DEVICE_ROLE_CUSTOM
            if role_was_added or migrated_role != saved_role:
                conn.execute(
                    "UPDATE devices SET role = ? WHERE device_id = ?",
                    (migrated_role, row["device_id"]),
                )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_token_hash ON devices(token_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_relay_device_id ON devices(relay_device_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_pending_pair_id ON devices(pending_pair_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_lease_expiry ON devices(purpose, lease_expires_at)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_pair_claims (
                pair_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL UNIQUE,
                request_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                state TEXT NOT NULL,
                expires_at REAL NOT NULL,
                created_at REAL NOT NULL,
                activated_at REAL,
                retain_until REAL NOT NULL,
                secret_cleaned INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pending_pair_claims_expiry "
            "ON pending_pair_claims(state, expires_at, retain_until)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                event TEXT NOT NULL,
                device_id TEXT,
                outcome TEXT NOT NULL,
                path TEXT,
                detail_json TEXT NOT NULL
            )
            """
        )

    def create_device(
        self,
        *,
        device_name: str,
        install_id: str,
        scopes: Iterable[str] | None = None,
        role: str | None = None,
        token: str | None = None,
        proof_secret: str | None = None,
        device_id: str | None = None,
        relay_device_id: str | None = None,
        attestation_status: str = "none",
        device_display_name: str | None = None,
        relay_pair_secret_ref: str | None = None,
        se_public_key_der: str | None = None,
        purpose: str | None = None,
        lease_expires_at: float | None = None,
    ) -> CreatedDevice:
        requested_role = str(role or "").strip().lower()
        if scopes is None and requested_role in {
            DEVICE_ROLE_READER,
            DEVICE_ROLE_OPERATOR,
        }:
            selected_scopes = device_scopes_for_role(requested_role)
        else:
            selected_scopes = DEFAULT_DEVICE_SCOPES if scopes is None else scopes
        normalized_scopes = tuple(sorted(set(selected_scopes)))
        normalized_role = _device_role_for_scopes(
            role=requested_role or None,
            scopes=normalized_scopes,
            purpose=purpose,
        )
        token_value = token or generate_token()
        proof_secret_value = proof_secret or generate_proof_secret()
        device_id_value = device_id or generate_device_id()
        install_id_value = normalize_install_id(install_id)
        if not install_id_value:
            raise ValueError("install_id must be a nonblank string")
        attestation_value = attestation_status if attestation_status in {
            "none",
            "development",
            "production",
            "unsupported",
            "failed",
        } else "failed"
        now = utc_epoch()
        with self.connect() as conn:
            if relay_device_id:
                superseded = conn.execute(
                    """
                    SELECT device_id FROM devices
                    WHERE relay_device_id = ?
                      AND revoked_at IS NULL
                      AND activation_state = 'active'
                    """,
                    (relay_device_id,),
                ).fetchall()
                for row in superseded:
                    old_device_id = row["device_id"]
                    conn.execute(
                        """
                        UPDATE devices
                        SET revoked_at = ?, superseded_by_device_id = ?
                        WHERE device_id = ?
                        """,
                        (now, device_id_value, old_device_id),
                    )
                    self.record_audit(
                        "device.superseded",
                        device_id=old_device_id,
                        outcome="ok",
                        detail={
                            "relay_device_id": relay_device_id,
                            "new_device_id": device_id_value,
                            "policy": "relay_repair_supersedes_old_local_token",
                        },
                        conn=conn,
                    )
            conn.execute(
                """
                INSERT INTO devices
                    (device_id, device_name, token_hash, scopes_json, role, install_id,
                     created_at, last_seen_at, revoked_at, relay_device_id,
                     attestation_status, apns_registered_at, relay_pair_secret_ref,
                     device_display_name, proof_secret, se_public_key_der,
                     activation_state, activated_at, purpose, lease_expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, NULL, ?, ?, ?, ?,
                        'active', ?, ?, ?)
                """,
                (
                    device_id_value,
                    device_name,
                    hash_token(token_value),
                    json.dumps(normalized_scopes),
                    normalized_role,
                    install_id_value,
                    now,
                    relay_device_id,
                    attestation_value,
                    relay_pair_secret_ref,
                    device_display_name or device_name,
                    proof_secret_value,
                    se_public_key_der or None,
                    now,
                    purpose or None,
                    lease_expires_at,
                ),
            )
            self.record_audit(
                "device.created",
                device_id=device_id_value,
                outcome="ok",
                detail={
                    "scopes": list(normalized_scopes),
                    "role": normalized_role,
                    "attestation_status": attestation_value,
                    "relay_device_id": relay_device_id,
                    "purpose": purpose or None,
                },
                conn=conn,
            )
            if se_public_key_der:
                self.record_audit(
                    "device.register_se_pubkey",
                    device_id=device_id_value,
                    outcome="ok",
                    conn=conn,
                )
        return CreatedDevice(
            device_id_value,
            token_value,
            proof_secret_value,
            normalized_scopes,
            install_id_value,
            relay_device_id,
            attestation_value,
            normalized_role,
        )

    def create_pending_device(
        self,
        *,
        pair_id: str,
        request_hash: str,
        response_json: str,
        pending_expires_at: float,
        activation_nonce: str,
        device_name: str,
        token: str,
        proof_secret: str,
        device_id: str,
        scopes: Iterable[str],
        install_id: str,
        role: str | None = None,
        relay_device_id: str | None = None,
        attestation_status: str = "none",
        device_display_name: str | None = None,
        relay_pair_secret_ref: str | None = None,
        se_public_key_der: str | None = None,
        purpose: str | None = None,
        lease_expires_at: float | None = None,
    ) -> CreatedDevice:
        """Atomically persist a non-authoritative device and its sealed reply."""
        install_id_value = normalize_install_id(install_id)
        if not install_id_value:
            raise ValueError("install_id must be a nonblank string")
        normalized_scopes = tuple(sorted(set(scopes)))
        if not normalized_scopes:
            raise DeviceRegistryError("invalid_scopes", 400, "pending device scopes are empty")
        normalized_role = _device_role_for_scopes(
            role=role,
            scopes=normalized_scopes,
            purpose=purpose,
        )
        try:
            decoded_response = json.loads(response_json)
        except (TypeError, ValueError, RecursionError) as exc:
            raise DeviceRegistryError(
                "pair_response_invalid", 500, "sealed pairing response is invalid"
            ) from exc
        if not isinstance(decoded_response, dict):
            raise DeviceRegistryError(
                "pair_response_invalid", 500, "sealed pairing response is invalid"
            )
        attestation_value = attestation_status if attestation_status in {
            "none",
            "development",
            "production",
            "unsupported",
            "failed",
        } else "failed"
        now = utc_epoch()
        with self.connect(immediate=True) as conn:
            existing = conn.execute(
                "SELECT request_hash, state, response_json, expires_at, device_id "
                "FROM pending_pair_claims WHERE pair_id = ?",
                (pair_id,),
            ).fetchone()
            if existing is not None:
                if not secrets.compare_digest(str(existing["request_hash"]), request_hash):
                    raise DeviceRegistryError(
                        "pair_claim_conflict", 409, "pairing claim does not match the saved claim"
                    )
                if existing["state"] in {"pending", "active"} and existing["response_json"]:
                    raise DeviceRegistryError(
                        "pair_claim_already_saved", 409, "pairing claim response is already saved"
                    )
                raise DeviceRegistryError(
                    "pair_claim_expired", 410, "saved pairing claim is no longer usable"
                )
            conn.execute(
                """
                INSERT INTO devices
                    (device_id, device_name, token_hash, scopes_json, role, install_id,
                     created_at, last_seen_at, revoked_at, relay_device_id,
                     attestation_status, apns_registered_at, relay_pair_secret_ref,
                     device_display_name, proof_secret, se_public_key_der,
                     activation_state, pending_pair_id, pending_expires_at,
                     activation_nonce, activated_at, purpose, lease_expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, NULL, ?, ?, ?, ?,
                        'pending', ?, ?, ?, NULL, ?, ?)
                """,
                (
                    device_id,
                    device_name,
                    hash_token(token),
                    json.dumps(normalized_scopes),
                    normalized_role,
                    install_id_value,
                    now,
                    relay_device_id,
                    attestation_value,
                    relay_pair_secret_ref,
                    device_display_name or device_name,
                    proof_secret,
                    se_public_key_der or None,
                    pair_id,
                    float(pending_expires_at),
                    activation_nonce,
                    purpose or None,
                    lease_expires_at,
                ),
            )
            conn.execute(
                """
                INSERT INTO pending_pair_claims
                    (pair_id, device_id, request_hash, response_json, state,
                     expires_at, created_at, activated_at, retain_until, secret_cleaned)
                VALUES (?, ?, ?, ?, 'pending', ?, ?, NULL, ?, 0)
                """,
                (
                    pair_id,
                    device_id,
                    request_hash,
                    response_json,
                    float(pending_expires_at),
                    now,
                    float(pending_expires_at) + 600.0,
                ),
            )
            self.record_audit(
                "device.pending_created",
                device_id=device_id,
                outcome="ok",
                detail={
                    "pair_id": pair_id,
                    "scopes": list(normalized_scopes),
                    "role": normalized_role,
                    "relay_device_id": relay_device_id,
                    "purpose": purpose or None,
                    "pending_expires_at": float(pending_expires_at),
                    "lease_expires_at": lease_expires_at,
                },
                conn=conn,
            )
        return CreatedDevice(
            device_id,
            token,
            proof_secret,
            normalized_scopes,
            install_id_value,
            relay_device_id,
            attestation_value,
            normalized_role,
        )

    def resumable_pair_claim(
        self,
        pair_id: str,
        request_hash: str,
        *,
        install_id: str,
    ) -> PendingClaimRecord | None:
        expected_install_id = normalize_install_id(install_id)
        with self.connect() as conn:
            row = conn.execute(
                "SELECT c.*, d.install_id AS device_install_id "
                "FROM pending_pair_claims AS c "
                "LEFT JOIN devices AS d ON d.device_id = c.device_id "
                "WHERE c.pair_id = ?",
                (pair_id,),
            ).fetchone()
        if row is None:
            return None
        saved_install_id = normalize_install_id(row["device_install_id"])
        if (
            not expected_install_id
            or not saved_install_id
            or not secrets.compare_digest(saved_install_id, expected_install_id)
        ):
            raise DeviceRegistryError(
                "pair_install_id_mismatch",
                409,
                "saved pairing claim belongs to a different Pairling install",
            )
        if not secrets.compare_digest(str(row["request_hash"]), request_hash):
            raise DeviceRegistryError(
                "pair_claim_conflict", 409, "pairing claim does not match the saved claim"
            )
        if row["state"] not in {"pending", "active"} or not row["response_json"]:
            raise DeviceRegistryError(
                "pair_claim_expired", 410, "saved pairing claim is no longer usable"
            )
        if row["state"] == "pending" and utc_epoch() > float(row["expires_at"]):
            raise DeviceRegistryError(
                "pair_claim_expired", 410, "saved pairing claim has expired"
            )
        return PendingClaimRecord(
            pair_id=str(row["pair_id"]),
            device_id=str(row["device_id"]),
            request_hash=str(row["request_hash"]),
            response_json=str(row["response_json"]),
            state=str(row["state"]),
            expires_at=float(row["expires_at"]),
        )

    def prune_pending_claims(self, *, now: float | None = None) -> list[dict[str, Any]]:
        current = utc_epoch() if now is None else float(now)
        cleanup: list[dict[str, Any]] = []
        with self.connect(immediate=True) as conn:
            expiring = conn.execute(
                """
                SELECT c.pair_id, c.device_id, d.relay_pair_secret_ref
                FROM pending_pair_claims c
                LEFT JOIN devices d ON d.device_id = c.device_id
                WHERE c.state = 'pending' AND c.expires_at <= ?
                """,
                (current,),
            ).fetchall()
            for row in expiring:
                cleanup.append({
                    "pair_id": str(row["pair_id"]),
                    "device_id": str(row["device_id"]),
                    "relay_secret_expected": bool(row["relay_pair_secret_ref"]),
                })
                # Keep the proof secret only for the existing rejection-retention
                # window. The activation endpoint needs it to authenticate a
                # terminal 410 after expiry. revoked_at makes the bearer unusable
                # before any route-specific pending-token exception is considered.
                conn.execute(
                    "UPDATE devices SET activation_state = 'expired', revoked_at = ? "
                    "WHERE device_id = ? AND activation_state = 'pending'",
                    (current, row["device_id"]),
                )
                conn.execute(
                    """
                    UPDATE pending_pair_claims
                    SET state = 'expired', response_json = '', retain_until = ?,
                        secret_cleaned = CASE WHEN ? THEN 0 ELSE 1 END
                    WHERE pair_id = ?
                    """,
                    (current + 600.0, bool(row["relay_pair_secret_ref"]), row["pair_id"]),
                )
                self.record_audit(
                    "device.pending_expired",
                    device_id=str(row["device_id"]),
                    outcome="ok",
                    detail={"pair_id": str(row["pair_id"])},
                    conn=conn,
                )
            outstanding = conn.execute(
                """
                SELECT pair_id, device_id FROM pending_pair_claims
                WHERE state IN ('expired', 'superseded') AND secret_cleaned = 0
                """
            ).fetchall()
            seen = {item["device_id"] for item in cleanup}
            for row in outstanding:
                device_id = str(row["device_id"])
                if device_id not in seen:
                    cleanup.append({
                        "pair_id": str(row["pair_id"]),
                        "device_id": device_id,
                        "relay_secret_expected": True,
                    })
            conn.execute(
                "DELETE FROM pending_pair_claims "
                "WHERE state = 'active' AND retain_until <= ?",
                (current,),
            )
            conn.execute(
                """
                DELETE FROM devices
                WHERE activation_state IN ('expired', 'superseded')
                  AND device_id IN (
                      SELECT device_id FROM pending_pair_claims
                      WHERE state IN ('expired', 'superseded')
                        AND secret_cleaned = 1 AND retain_until <= ?
                  )
                """,
                (current,),
            )
            conn.execute(
                "DELETE FROM pending_pair_claims "
                "WHERE state IN ('expired', 'superseded') "
                "AND secret_cleaned = 1 AND retain_until <= ?",
                (current,),
            )
        return cleanup

    def mark_pending_secret_cleaned(self, pair_id: str, device_id: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE pending_pair_claims SET secret_cleaned = 1 "
                "WHERE pair_id = ? AND device_id = ?",
                (pair_id, device_id),
            )

    def pending_pair_activation_context(
        self,
        *,
        pair_id: str,
        device_id: str,
        install_id: str,
        now: float | None = None,
    ) -> PendingActivationContext | None:
        """Return a live pending claim's non-secret purpose, if it still exists."""
        expected_install_id = normalize_install_id(install_id)
        if not expected_install_id:
            return None
        current = utc_epoch() if now is None else float(now)
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT d.install_id, d.activation_state, d.pending_pair_id,
                       d.pending_expires_at, d.revoked_at, d.purpose,
                       c.device_id AS claim_device_id, c.state AS claim_state,
                       c.expires_at AS claim_expires_at
                FROM devices AS d
                LEFT JOIN pending_pair_claims AS c ON c.pair_id = d.pending_pair_id
                WHERE d.device_id = ?
                """,
                (device_id,),
            ).fetchone()
        if row is None:
            return None
        saved_install_id = normalize_install_id(row["install_id"])
        if (
            not saved_install_id
            or not secrets.compare_digest(saved_install_id, expected_install_id)
            or str(row["activation_state"] or "") != "pending"
            or not secrets.compare_digest(str(row["pending_pair_id"] or ""), pair_id)
            or row["revoked_at"] is not None
            or not secrets.compare_digest(str(row["claim_device_id"] or ""), device_id)
            or str(row["claim_state"] or "") != "pending"
        ):
            return None
        try:
            pending_expires_at = float(row["pending_expires_at"])
            claim_expires_at = float(row["claim_expires_at"])
        except (TypeError, ValueError, OverflowError):
            return None
        if (
            not math.isfinite(pending_expires_at)
            or not math.isfinite(claim_expires_at)
            or current >= pending_expires_at
            or current > claim_expires_at
        ):
            return None
        purpose = str(row["purpose"] or "").strip() or None
        return PendingActivationContext(purpose=purpose)

    def activate_pending_claim(
        self,
        *,
        pair_id: str,
        device_id: str,
        install_id: str,
        activation_nonce: str,
        token_hash: str,
        activation_proof: str,
        before_activation: Callable[[], None] | None = None,
        now: float | None = None,
    ) -> PairActivationResult:
        current = utc_epoch() if now is None else float(now)
        expected_install_id = normalize_install_id(install_id)
        with self.connect(immediate=True) as conn:
            claim = conn.execute(
                "SELECT * FROM pending_pair_claims WHERE pair_id = ?",
                (pair_id,),
            ).fetchone()
            device = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()

            def activation_error(
                code: str,
                status: int,
                message: str,
                *,
                relay_secret_expected: bool = False,
            ) -> DeviceRegistryError:
                pairing_state = {
                    "pair_activation_expired": "expired",
                    "pair_activation_superseded": "superseded",
                }.get(code, "rejected")
                activation_result = None
                if device is not None and str(device["proof_secret"] or ""):
                    try:
                        activation_result = signed_pair_activation_result(
                            proof_secret=str(device["proof_secret"]),
                            ok=False,
                            pair_id=pair_id,
                            device_id=device_id,
                            install_id=str(device["install_id"]),
                            activation_nonce=activation_nonce,
                            token_hash=token_hash,
                            activation_proof=activation_proof,
                            pairing_state=pairing_state,
                            outcome=code,
                            already_active=False,
                        )
                    except ValueError:
                        activation_result = None
                return DeviceRegistryError(
                    code,
                    status,
                    message,
                    device_id=device_id if device is not None else None,
                    relay_secret_expected=relay_secret_expected,
                    activation_result=activation_result,
                )

            if device is None:
                raise activation_error(
                    "pair_activation_invalid", 403, "pairing activation was rejected"
                )
            saved_install_id = normalize_install_id(device["install_id"])
            if (
                not expected_install_id
                or not saved_install_id
                or not secrets.compare_digest(saved_install_id, expected_install_id)
            ):
                raise activation_error(
                    "pair_install_id_mismatch",
                    409,
                    "saved pairing claim belongs to a different Pairling install",
                )
            if claim is not None and claim["state"] in {"expired", "superseded"}:
                code = (
                    "pair_activation_superseded"
                    if claim["state"] == "superseded"
                    else "pair_activation_expired"
                )
                raise activation_error(
                    code,
                    409 if code == "pair_activation_superseded" else 410,
                    "pairing activation is no longer usable",
                )
            if claim is None and (
                str(device["activation_state"] or "") != "active"
                or str(device["pending_pair_id"] or "") != pair_id
            ):
                raise activation_error(
                    "pair_activation_invalid", 403, "pairing activation was rejected"
                )
            if claim is not None and str(claim["device_id"]) != device_id:
                raise activation_error(
                    "pair_activation_invalid", 403, "pairing activation was rejected"
                )
            if device["revoked_at"] is not None:
                raise activation_error(
                    "pair_activation_expired", 410, "pairing activation is no longer usable",
                )
            if (
                device["lease_expires_at"] is not None
                and current >= float(device["lease_expires_at"])
            ):
                raise activation_error(
                    "pair_activation_expired", 410, "pairing credential lease has expired",
                )
            if (
                claim is not None
                and claim["state"] == "pending"
                and current > float(claim["expires_at"])
            ):
                raise activation_error(
                    "pair_activation_expired", 410, "pairing activation has expired",
                )
            stored_nonce = str(device["activation_nonce"] or "")
            stored_token_hash = str(device["token_hash"] or "")
            if (
                not stored_nonce
                or not secrets.compare_digest(stored_nonce, activation_nonce)
                or not secrets.compare_digest(stored_token_hash, token_hash)
            ):
                raise activation_error(
                    "pair_activation_invalid", 403, "pairing activation was rejected"
                )
            canonical = pair_activation_canonical(
                pair_id=pair_id,
                device_id=device_id,
                activation_nonce=activation_nonce,
                token_hash=token_hash,
                install_id=str(device["install_id"]),
            )
            expected = hmac.new(
                str(device["proof_secret"] or "").encode("utf-8"),
                canonical,
                hashlib.sha256,
            ).hexdigest()
            if not activation_proof or not secrets.compare_digest(expected, activation_proof):
                raise activation_error(
                    "pair_activation_invalid", 403, "pairing activation was rejected"
                )
            if (
                device["activation_state"] == "active"
                and (claim is None or claim["state"] == "active")
            ):
                if before_activation is not None:
                    before_activation()
                superseded_rows = conn.execute(
                    """
                    SELECT device_id FROM devices
                    WHERE superseded_by_device_id = ? AND revoked_at IS NOT NULL
                    ORDER BY created_at, device_id
                    """,
                    (device_id,),
                ).fetchall()
                superseded_ids = tuple(
                    str(row["device_id"]) for row in superseded_rows
                )
                activation_result = signed_pair_activation_result(
                    proof_secret=str(device["proof_secret"]),
                    ok=True,
                    pair_id=pair_id,
                    device_id=device_id,
                    install_id=str(device["install_id"]),
                    activation_nonce=activation_nonce,
                    token_hash=token_hash,
                    activation_proof=activation_proof,
                    pairing_state="active",
                    outcome="already_active",
                    already_active=True,
                    superseded_device_ids=superseded_ids,
                )
                return PairActivationResult(
                    device_id,
                    pair_id,
                    True,
                    superseded_ids,
                    activation_result,
                )

            relay_device_id = device["relay_device_id"]
            if relay_device_id:
                newer = conn.execute(
                    """
                    SELECT device_id FROM devices
                    WHERE relay_device_id = ? AND activation_state = 'active'
                      AND revoked_at IS NULL AND created_at > ? AND device_id != ?
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (relay_device_id, device["created_at"], device_id),
                ).fetchone()
                if newer is not None:
                    conn.execute(
                        "UPDATE devices SET activation_state = 'superseded', revoked_at = ?, "
                        "superseded_by_device_id = ? WHERE device_id = ?",
                        (current, newer["device_id"], device_id),
                    )
                    conn.execute(
                        "UPDATE pending_pair_claims SET state = 'superseded', response_json = '', "
                        "retain_until = ? WHERE pair_id = ?",
                        (current + 600.0, pair_id),
                    )
                    self.record_audit(
                        "device.pending_superseded",
                        device_id=device_id,
                        outcome="rejected",
                        detail={"newer_device_id": str(newer["device_id"])},
                        conn=conn,
                    )
                    # Preserve the rejection tombstone before returning the typed
                    # conflict. The context manager would otherwise roll it back
                    # when the exception leaves this block.
                    conn.commit()
                    raise activation_error(
                        "pair_activation_superseded", 409,
                        "a newer repair is already active",
                        relay_secret_expected=bool(device["relay_pair_secret_ref"]),
                    )

            if before_activation is not None:
                before_activation()

            superseded_rows = []
            if relay_device_id:
                superseded_rows = conn.execute(
                    """
                    SELECT device_id FROM devices
                    WHERE relay_device_id = ? AND activation_state = 'active'
                      AND revoked_at IS NULL AND device_id != ?
                    """,
                    (relay_device_id, device_id),
                ).fetchall()
                for row in superseded_rows:
                    old_device_id = str(row["device_id"])
                    conn.execute(
                        "UPDATE devices SET revoked_at = ?, superseded_by_device_id = ? "
                        "WHERE device_id = ?",
                        (current, device_id, old_device_id),
                    )
                    self.record_audit(
                        "device.superseded",
                        device_id=old_device_id,
                        outcome="ok",
                        detail={
                            "relay_device_id": str(relay_device_id),
                            "new_device_id": device_id,
                            "policy": "relay_repair_activates_saved_credentials",
                        },
                        conn=conn,
                    )
            conn.execute(
                """
                UPDATE devices
                SET activation_state = 'active', activated_at = ?,
                    pending_expires_at = NULL
                WHERE device_id = ?
                """,
                (current, device_id),
            )
            conn.execute(
                """
                UPDATE pending_pair_claims
                SET state = 'active', activated_at = ?, retain_until = ?
                WHERE pair_id = ?
                """,
                (current, current + 86400.0, pair_id),
            )
            self.record_audit(
                "device.pending_activated",
                device_id=device_id,
                outcome="ok",
                detail={
                    "pair_id": pair_id,
                    "superseded_device_ids": [str(row["device_id"]) for row in superseded_rows],
                },
                conn=conn,
            )
            superseded_ids = tuple(str(row["device_id"]) for row in superseded_rows)
            activation_result = signed_pair_activation_result(
                proof_secret=str(device["proof_secret"]),
                ok=True,
                pair_id=pair_id,
                device_id=device_id,
                install_id=str(device["install_id"]),
                activation_nonce=activation_nonce,
                token_hash=token_hash,
                activation_proof=activation_proof,
                pairing_state="active",
                outcome="activated",
                already_active=False,
                superseded_device_ids=superseded_ids,
            )
            return PairActivationResult(
                device_id,
                pair_id,
                False,
                superseded_ids,
                activation_result,
            )

    def revoke_expired_smoke_leases(self, *, now: float | None = None) -> list[str]:
        current = utc_epoch() if now is None else float(now)
        with self.connect(immediate=True) as conn:
            rows = conn.execute(
                """
                SELECT device_id FROM devices
                WHERE purpose = ? AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= ? AND revoked_at IS NULL
                """,
                (SMOKE_DEVICE_PURPOSE, current),
            ).fetchall()
            for row in rows:
                device_id = str(row["device_id"])
                conn.execute(
                    "UPDATE devices SET revoked_at = ? WHERE device_id = ?",
                    (current, device_id),
                )
                self.record_audit(
                    "device.smoke_lease_expired",
                    device_id=device_id,
                    outcome="ok",
                    detail={"purpose": SMOKE_DEVICE_PURPOSE},
                    conn=conn,
                )
            return [str(row["device_id"]) for row in rows]

    def rollback_created_device(self, device_id: str, *, reason: str) -> bool:
        """Remove one failed finalize and reactivate only devices it superseded."""
        with self.connect() as conn:
            created = conn.execute(
                """
                SELECT relay_device_id, created_at, revoked_at, superseded_by_device_id
                FROM devices WHERE device_id = ?
                """,
                (device_id,),
            ).fetchone()
            if created is None:
                return False
            restored = [
                str(row["device_id"])
                for row in conn.execute(
                    """
                    SELECT device_id FROM devices
                    WHERE superseded_by_device_id = ? AND revoked_at = ?
                    """,
                    (device_id, created["created_at"]),
                ).fetchall()
            ]
            successor_id = created["superseded_by_device_id"]
            if successor_id:
                live_successor = conn.execute(
                    "SELECT 1 FROM devices WHERE device_id = ? AND revoked_at IS NULL",
                    (successor_id,),
                ).fetchone()
                if live_successor is None:
                    successor_id = None
            if not successor_id and created["relay_device_id"]:
                successor = conn.execute(
                    """
                    SELECT device_id FROM devices
                    WHERE relay_device_id = ?
                      AND device_id != ?
                      AND revoked_at IS NULL
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (created["relay_device_id"], device_id),
                ).fetchone()
                successor_id = successor["device_id"] if successor is not None else None
            if successor_id:
                # A newer successful repair already superseded this failed row.
                # Keep its predecessors revoked and point their history at the
                # live successor instead of reactivating two relay identities.
                conn.execute(
                    """
                    UPDATE devices SET superseded_by_device_id = ?
                    WHERE superseded_by_device_id = ?
                    """,
                    (successor_id, device_id),
                )
                restored = []
            else:
                conn.execute(
                    """
                    UPDATE devices
                    SET revoked_at = NULL, superseded_by_device_id = NULL
                    WHERE superseded_by_device_id = ? AND revoked_at = ?
                    """,
                    (device_id, created["created_at"]),
                )
                conn.execute(
                    """
                    UPDATE devices SET superseded_by_device_id = NULL
                    WHERE superseded_by_device_id = ?
                    """,
                    (device_id,),
                )
            conn.execute("DELETE FROM pending_pair_claims WHERE device_id = ?", (device_id,))
            conn.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
            self.record_audit(
                "device.create_rolled_back",
                device_id=device_id,
                outcome="ok",
                detail={"reason": reason, "restored_device_ids": restored},
                conn=conn,
            )
            return True

    def authorization_for_device(self, device_id: str) -> dict[str, Any] | None:
        """Return current non-secret authorization for one active push target."""
        normalized_device_id = str(device_id or "").strip()
        if not normalized_device_id:
            return None
        with self.connect() as conn:
            row = conn.execute(
                "SELECT device_id, install_id, scopes_json, role, purpose, "
                "activation_state, revoked_at, lease_expires_at "
                "FROM devices WHERE device_id = ?",
                (normalized_device_id,),
            ).fetchone()
        if (
            row is None
            or row["revoked_at"] is not None
            or str(row["activation_state"] or "active") != "active"
        ):
            return None
        lease_expires_at = row["lease_expires_at"]
        if lease_expires_at is not None and utc_epoch() >= float(lease_expires_at):
            return None
        try:
            scopes = frozenset(json.loads(row["scopes_json"] or "[]"))
            role = _device_role_for_scopes(
                role=row["role"],
                scopes=scopes,
                purpose=row["purpose"],
            )
        except (json.JSONDecodeError, TypeError, ValueError):
            return None
        return {
            "device_id": str(row["device_id"]),
            "install_id": str(row["install_id"]),
            "role": role,
            "scopes": tuple(sorted(scopes)),
            "credential_expires_at": (
                float(lease_expires_at) if lease_expires_at is not None else None
            ),
        }

    def authenticate(
        self,
        token: str | None,
        *,
        required_scopes: Iterable[str] = (),
        path: str | None = None,
        allow_pending: bool = False,
    ) -> DeviceAuthResult:
        if not token:
            return DeviceAuthResult(False, 401, "missing_token")
        required = set(required_scopes)
        token_hash = hash_token(token)
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is None:
                self.record_audit(
                    "auth.denied",
                    device_id=None,
                    outcome="invalid_token",
                    path=path,
                    conn=conn,
                )
                return DeviceAuthResult(False, 403, "invalid_token")
            now = time.time()
            lease_expires_at = row["lease_expires_at"]
            if lease_expires_at is not None and now >= float(lease_expires_at):
                self.record_audit(
                    "auth.denied",
                    device_id=row["device_id"],
                    outcome="lease_expired",
                    path=path,
                    conn=conn,
                )
                return DeviceAuthResult(False, 403, "lease_expired")
            if row["revoked_at"] is not None:
                self.record_audit(
                    "auth.denied",
                    device_id=row["device_id"],
                    outcome="revoked",
                    path=path,
                    conn=conn,
                )
                return DeviceAuthResult(False, 403, "revoked")
            activation_state = str(row["activation_state"] or "active")
            pending_expires_at = row["pending_expires_at"]
            if activation_state != "active":
                pending_usable = (
                    activation_state == "pending"
                    and allow_pending
                    and pending_expires_at is not None
                    and now < float(pending_expires_at)
                )
                if not pending_usable:
                    reason = (
                        "pending_expired"
                        if activation_state == "pending"
                        and pending_expires_at is not None
                        and now >= float(pending_expires_at)
                        else "pending_activation"
                    )
                    self.record_audit(
                        "auth.denied",
                        device_id=row["device_id"],
                        outcome=reason,
                        path=path,
                        conn=conn,
                    )
                    return DeviceAuthResult(False, 403, reason)
            scopes = frozenset(json.loads(row["scopes_json"] or "[]"))
            missing = sorted(required.difference(scopes))
            if missing:
                self.record_audit(
                    "auth.denied",
                    device_id=row["device_id"],
                    outcome="missing_scope",
                    path=path,
                    detail={"missing": missing},
                    conn=conn,
                )
                return DeviceAuthResult(
                    False,
                    403,
                    "missing_scope",
                    device_id=row["device_id"],
                    install_id=row["install_id"],
                    proof_secret=row["proof_secret"],
                    scopes=scopes,
                    activation_state=activation_state,
                    role=str(row["role"] or "") or None,
                    credential_expires_at=(
                        min(
                            value
                            for value in (
                                float(lease_expires_at) if lease_expires_at is not None else None,
                                float(pending_expires_at)
                                if activation_state == "pending" and pending_expires_at is not None
                                else None,
                            )
                            if value is not None
                        )
                        if lease_expires_at is not None
                        or (activation_state == "pending" and pending_expires_at is not None)
                        else None
                    ),
                )
            # Record the sighting in memory only. The auth hot path is pinned
            # write-free (test_device_registry_uses_wal_and_no_successful_auth
            # _write): every request authenticates, and a write per request
            # would churn WAL for nothing. flush_last_seen() persists the
            # newest sighting lazily, off this path.
            with self._last_seen_lock:
                self._last_seen_marks[row["device_id"]] = time.time()
            return DeviceAuthResult(
                True,
                200,
                "ok",
                device_id=row["device_id"],
                install_id=row["install_id"],
                proof_secret=row["proof_secret"],
                token_hash=token_hash,
                scopes=scopes,
                activation_state=activation_state,
                role=str(row["role"] or "") or None,
                credential_expires_at=(
                    min(
                        value
                        for value in (
                            float(lease_expires_at) if lease_expires_at is not None else None,
                            float(pending_expires_at)
                            if activation_state == "pending" and pending_expires_at is not None
                            else None,
                        )
                        if value is not None
                    )
                    if lease_expires_at is not None
                    or (activation_state == "pending" and pending_expires_at is not None)
                    else None
                ),
            )

    def tailnet_node_id(self, device_id: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT tailnet_node_id FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            return None if row is None else row["tailnet_node_id"]

    def set_tailnet_node_id_if_absent(self, device_id: str, node_id: str) -> bool:
        node_id = str(node_id or "").strip()
        if not device_id or not node_id:
            return False
        with self.connect() as conn:
            cur = conn.execute(
                """
                UPDATE devices
                SET tailnet_node_id = ?
                WHERE device_id = ?
                  AND revoked_at IS NULL
                  AND activation_state = 'active'
                  AND (lease_expires_at IS NULL OR lease_expires_at > ?)
                  AND (tailnet_node_id IS NULL OR tailnet_node_id = '')
                """,
                (node_id, device_id, utc_epoch()),
            )
            changed = cur.rowcount > 0
            if changed:
                self.record_audit(
                    "device.tailnet_node_id.bound",
                    device_id=device_id,
                    outcome="ok",
                    detail={"tailnet_node_id": node_id},
                    conn=conn,
                )
            return changed

    def flush_last_seen(self) -> int:
        """Persist in-memory auth sightings, newest-wins, skipping anything
        already persisted. The auth path itself never writes; this runs on
        the evidence read and costs nothing when there is nothing new."""
        with self._last_seen_lock:
            pending = {
                device_id: seen_at
                for device_id, seen_at in self._last_seen_marks.items()
                if seen_at > self._flushed_marks.get(device_id, 0.0)
            }
        if not pending:
            return 0
        persisted: dict[str, float] = {}
        with self.connect() as conn:
            for device_id, seen_at in pending.items():
                try:
                    conn.execute(
                        "UPDATE devices SET last_seen_at = ? "
                        "WHERE device_id = ? AND COALESCE(last_seen_at, 0) < ?",
                        (seen_at, device_id, seen_at),
                    )
                    persisted[device_id] = seen_at
                except sqlite3.Error:
                    continue
        with self._last_seen_lock:
            for device_id, seen_at in persisted.items():
                self._flushed_marks[device_id] = max(
                    seen_at,
                    self._flushed_marks.get(device_id, 0.0),
                )
        return len(persisted)

    def any_device_seen_within(self, seconds: float) -> bool:
        """Human-pairing evidence: an unrevoked device authenticated (or was
        created) within the window. Drives next_action so a paired, active
        Mac stops telling its user to scan a pairing code. Flushes pending
        sightings first so fresh evidence counts immediately."""
        self.flush_last_seen()
        cutoff = time.time() - max(0.0, float(seconds))
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM devices "
                "WHERE revoked_at IS NULL "
                "AND activation_state = 'active' "
                "AND COALESCE(purpose, '') NOT IN (?, ?) "
                "AND (lease_expires_at IS NULL OR lease_expires_at > ?) "
                "AND (COALESCE(last_seen_at, 0) >= ? OR COALESCE(created_at, 0) >= ?)",
                (*INTERNAL_DEVICE_PURPOSES, time.time(), cutoff, cutoff),
            ).fetchone()
            return bool(row["n"])

    def revoked_device_ids(self) -> list[str]:
        """Every device id that has ever been revoked. Feeds the push
        dispatcher's boot-time GC so revoked pairings cannot keep push
        registrations (stale tokens burned APNs calls and cluttered the
        delivery audit for weeks before the 2026-07-09 cleanup)."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT device_id FROM devices WHERE revoked_at IS NOT NULL"
            ).fetchall()
            return [str(row["device_id"]) for row in rows]

    def revoke_device(self, device_id: str, *, reason: str = "revoked") -> bool:
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE devices SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL",
                (utc_epoch(), device_id),
            )
            changed = cur.rowcount > 0
            self.record_audit(
                "device.revoked",
                device_id=device_id,
                outcome="ok" if changed else "not_found",
                detail={"reason": reason},
                conn=conn,
            )
            return changed

    def revoke_device_if_named(
        self,
        device_id: str,
        device_name: str,
        *,
        reason: str = "revoked",
    ) -> bool:
        now = utc_epoch()
        with self.connect() as conn:
            changed = conn.execute(
                "UPDATE devices SET revoked_at = ? "
                "WHERE device_id = ? AND device_name = ? AND revoked_at IS NULL",
                (now, device_id, device_name),
            ).rowcount
            if changed:
                self.record_audit(
                    "device.revoked",
                    device_id=device_id,
                    outcome="ok",
                    detail={"reason": reason, "device_name": device_name},
                    conn=conn,
                )
            return changed > 0

    def canonicalize_legacy_device_for_credential(
        self,
        *,
        token: str,
        credential_device_id: str,
        credential_install_id: str,
        device_name: str,
        accepted_scope_sets: Iterable[Iterable[str]],
        purpose: str,
        reason: str,
    ) -> bool:
        """Bind one credential-proven legacy device and retire exact duplicates.

        The first pass is read-only. A corrupt or forged credential therefore
        cannot trigger schema migration or any other database write. The second
        pass repeats every proof inside one immediate transaction before it tags
        the canonical row and revokes only existing purpose-tagged rows or
        untagged rows with the exact legacy name and one accepted scope set.
        """
        install_id = normalize_install_id(credential_install_id)
        accepted = frozenset(
            frozenset(str(scope) for scope in scopes)
            for scopes in accepted_scope_sets
        )
        if (
            not token
            or not credential_device_id
            or not install_id
            or not device_name
            or not accepted
            or not purpose
        ):
            return False
        token_digest = hash_token(token)

        def decoded_scopes(raw: Any) -> frozenset[str] | None:
            try:
                value = json.loads(str(raw or ""))
            except (json.JSONDecodeError, TypeError, ValueError):
                return None
            if not isinstance(value, list) or any(
                not isinstance(scope, str) for scope in value
            ):
                return None
            return frozenset(value)

        def row_matches(row: sqlite3.Row, columns: set[str]) -> bool:
            if not secrets.compare_digest(
                str(row["device_id"] or ""),
                credential_device_id,
            ):
                return False
            if not secrets.compare_digest(
                str(row["token_hash"] or ""),
                token_digest,
            ):
                return False
            if str(row["device_name"] or "") != device_name:
                return False
            if normalize_install_id(row["install_id"]) != install_id:
                return False
            if row["revoked_at"] is not None:
                return False
            if (
                "activation_state" in columns
                and str(row["activation_state"] or "active") != "active"
            ):
                return False
            existing_purpose = (
                str(row["purpose"] or "") if "purpose" in columns else ""
            )
            if existing_purpose not in {"", purpose}:
                return False
            if decoded_scopes(row["scopes_json"]) not in accepted:
                return False
            return True

        try:
            metadata = self.db_path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                return False
            with closing(_connect_query_only_database(self.db_path)) as read_only:
                read_only.row_factory = sqlite3.Row
                columns = {
                    str(row[1])
                    for row in read_only.execute("PRAGMA table_info(devices)").fetchall()
                }
                required_columns = {
                    "device_id",
                    "device_name",
                    "token_hash",
                    "scopes_json",
                    "install_id",
                    "revoked_at",
                }
                if not required_columns.issubset(columns):
                    return False
                row = read_only.execute(
                    "SELECT * FROM devices WHERE token_hash = ?",
                    (token_digest,),
                ).fetchone()
                if row is None or not row_matches(row, columns):
                    return False
        except (OSError, sqlite3.Error):
            return False

        with self.connect(immediate=True) as conn:
            columns = {
                str(row[1])
                for row in conn.execute("PRAGMA table_info(devices)").fetchall()
            }
            canonical = conn.execute(
                "SELECT * FROM devices WHERE token_hash = ?",
                (token_digest,),
            ).fetchone()
            if canonical is None or not row_matches(canonical, columns):
                return False

            if not str(canonical["purpose"] or ""):
                conn.execute(
                    "UPDATE devices SET purpose = ? WHERE device_id = ?",
                    (purpose, credential_device_id),
                )
                self.record_audit(
                    "device.purpose_bound",
                    device_id=credential_device_id,
                    outcome="ok",
                    detail={"purpose": purpose, "proof": "credential_token"},
                    conn=conn,
                )

            candidates = conn.execute(
                "SELECT device_id, device_name, scopes_json, purpose "
                "FROM devices WHERE device_id != ? AND revoked_at IS NULL "
                "AND COALESCE(activation_state, 'active') = 'active'",
                (credential_device_id,),
            ).fetchall()
            now = utc_epoch()
            for candidate in candidates:
                candidate_purpose = str(candidate["purpose"] or "")
                is_tagged_duplicate = candidate_purpose == purpose
                is_exact_legacy_duplicate = (
                    not candidate_purpose
                    and str(candidate["device_name"] or "") == device_name
                    and decoded_scopes(candidate["scopes_json"]) in accepted
                )
                if not is_tagged_duplicate and not is_exact_legacy_duplicate:
                    continue
                candidate_id = str(candidate["device_id"])
                conn.execute(
                    "UPDATE devices SET revoked_at = ? WHERE device_id = ?",
                    (now, candidate_id),
                )
                self.record_audit(
                    "device.revoked",
                    device_id=candidate_id,
                    outcome="ok",
                    detail={"reason": reason, "purpose": purpose},
                    conn=conn,
                )
        return True

    def bind_device_purpose_if_named(
        self,
        device_id: str,
        device_name: str,
        purpose: str,
    ) -> bool:
        """Tag a token-proven legacy device so interrupted cleanup is retryable."""
        with self.connect(immediate=True) as conn:
            row = conn.execute(
                "SELECT purpose FROM devices "
                "WHERE device_id = ? AND device_name = ? AND revoked_at IS NULL",
                (device_id, device_name),
            ).fetchone()
            if row is None:
                return False
            existing_purpose = str(row["purpose"] or "")
            if existing_purpose == purpose:
                return True
            if existing_purpose:
                return False
            changed = conn.execute(
                "UPDATE devices SET purpose = ? "
                "WHERE device_id = ? AND device_name = ? AND revoked_at IS NULL "
                "AND COALESCE(purpose, '') = ''",
                (purpose, device_id, device_name),
            ).rowcount
            if not changed:
                return False
            self.record_audit(
                "device.purpose_bound",
                device_id=device_id,
                outcome="ok",
                detail={"purpose": purpose},
                conn=conn,
            )
            return True

    def revoke_devices_by_purpose_except(
        self,
        purpose: str,
        keep_device_id: str,
        *,
        reason: str = "revoked",
    ) -> int:
        now = utc_epoch()
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT device_id FROM devices "
                "WHERE purpose = ? AND device_id != ? AND revoked_at IS NULL",
                (purpose, keep_device_id),
            ).fetchall()
            for row in rows:
                device_id = str(row["device_id"])
                conn.execute(
                    "UPDATE devices SET revoked_at = ? WHERE device_id = ?",
                    (now, device_id),
                )
                self.record_audit(
                    "device.revoked",
                    device_id=device_id,
                    outcome="ok",
                    detail={"reason": reason, "purpose": purpose},
                    conn=conn,
                )
            return len(rows)

    def active_device_ids_for_purpose(self, purpose: str) -> tuple[str, ...]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT device_id FROM devices "
                "WHERE purpose = ? AND revoked_at IS NULL "
                "AND COALESCE(activation_state, 'active') = 'active' "
                "ORDER BY created_at, device_id",
                (purpose,),
            ).fetchall()
        return tuple(str(row["device_id"]) for row in rows)

    def active_device_ids_for_purpose_or_legacy_shape(
        self,
        *,
        purpose: str,
        device_name: str,
        accepted_scope_sets: Iterable[Iterable[str]],
    ) -> tuple[str, ...]:
        """Return tagged internal rows plus exact untagged legacy rows."""
        accepted = frozenset(
            frozenset(str(scope) for scope in scopes)
            for scopes in accepted_scope_sets
        )
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT device_id, device_name, scopes_json, purpose "
                "FROM devices WHERE revoked_at IS NULL "
                "AND COALESCE(activation_state, 'active') = 'active' "
                "AND (purpose = ? OR (COALESCE(purpose, '') = '' AND device_name = ?)) "
                "ORDER BY created_at, device_id",
                (purpose, device_name),
            ).fetchall()
        matched: list[str] = []
        for row in rows:
            if str(row["purpose"] or "") == purpose:
                matched.append(str(row["device_id"]))
                continue
            try:
                scopes = json.loads(str(row["scopes_json"] or ""))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
            if (
                isinstance(scopes, list)
                and all(isinstance(scope, str) for scope in scopes)
                and frozenset(scopes) in accepted
            ):
                matched.append(str(row["device_id"]))
        return tuple(matched)

    def revoke_devices_named(self, device_name: str, *, reason: str = "revoked") -> int:
        now = utc_epoch()
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT device_id FROM devices WHERE device_name = ? AND revoked_at IS NULL",
                (device_name,),
            ).fetchall()
            for row in rows:
                device_id = row["device_id"]
                conn.execute(
                    "UPDATE devices SET revoked_at = ? WHERE device_id = ?",
                    (now, device_id),
                )
                self.record_audit(
                    "device.revoked",
                    device_id=device_id,
                    outcome="ok",
                    detail={"reason": reason, "device_name": device_name},
                    conn=conn,
                )
            return len(rows)

    def rotation_token_hash(self, device_id: str) -> str | None:
        """Return the credential generation for one currently rotatable device."""
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT token_hash FROM devices
                WHERE device_id = ?
                  AND revoked_at IS NULL
                  AND superseded_by_device_id IS NULL
                  AND COALESCE(activation_state, 'active') = 'active'
                  AND (lease_expires_at IS NULL OR lease_expires_at > ?)
                """,
                (device_id, utc_epoch()),
            ).fetchone()
        return None if row is None else str(row["token_hash"])

    def rotate_token(
        self,
        device_id: str,
        *,
        expected_token_hash: str | None = None,
    ) -> str | None:
        if expected_token_hash is not None and not re.fullmatch(
            r"[0-9a-f]{64}",
            expected_token_hash,
        ):
            raise DeviceRegistryError(
                "device_token_rotation_forbidden",
                403,
                "device token rotation authorization is invalid",
                device_id=device_id,
            )

        conflict: DeviceRegistryError | None = None
        token: str | None = None
        with self.connect(immediate=True) as conn:
            authorized_token_hash = expected_token_hash
            if authorized_token_hash is None:
                row = conn.execute(
                    """
                    SELECT token_hash FROM devices
                    WHERE device_id = ?
                      AND revoked_at IS NULL
                      AND superseded_by_device_id IS NULL
                      AND COALESCE(activation_state, 'active') = 'active'
                      AND (lease_expires_at IS NULL OR lease_expires_at > ?)
                    """,
                    (device_id, utc_epoch()),
                ).fetchone()
                if row is None:
                    self.record_audit(
                        "device.rotate_token",
                        device_id=device_id,
                        outcome="not_found",
                        conn=conn,
                    )
                    return None
                authorized_token_hash = str(row["token_hash"])

            token = generate_token()
            cur = conn.execute(
                """
                UPDATE devices
                SET token_hash = ?
                WHERE device_id = ?
                  AND token_hash = ?
                  AND revoked_at IS NULL
                  AND superseded_by_device_id IS NULL
                  AND COALESCE(activation_state, 'active') = 'active'
                  AND (lease_expires_at IS NULL OR lease_expires_at > ?)
                """,
                (
                    hash_token(token),
                    device_id,
                    authorized_token_hash,
                    utc_epoch(),
                ),
            )
            if cur.rowcount <= 0:
                self.record_audit(
                    "device.rotate_token",
                    device_id=device_id,
                    outcome="conflict",
                    conn=conn,
                )
                conflict = DeviceRegistryError(
                    "device_token_rotation_conflict",
                    409,
                    "device token rotation authorization is stale",
                    device_id=device_id,
                )
            else:
                self.record_audit(
                    "device.rotate_token",
                    device_id=device_id,
                    outcome="ok",
                    conn=conn,
                )
        if conflict is not None:
            raise conflict
        return token

    def register_se_pubkey(self, device_id: str, se_public_key_der: str) -> bool:
        """WS4: store the device's Secure-Enclave public key (base64 X9.63)."""
        if not se_public_key_der:
            return False
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE devices SET se_public_key_der = ? WHERE device_id = ?",
                (se_public_key_der, device_id),
            )
            ok = cur.rowcount > 0
            self.record_audit(
                "device.register_se_pubkey",
                device_id=device_id,
                outcome="ok" if ok else "not_found",
                conn=conn,
            )
            return ok

    def get_se_pubkey(self, device_id: str) -> str | None:
        """The registered SE public key for an ACTIVE device. Revoked devices
        return None, so revocation also blocks zero-interaction re-pair."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT se_public_key_der FROM devices WHERE device_id = ? "
                "AND revoked_at IS NULL AND activation_state = 'active' "
                "AND (lease_expires_at IS NULL OR lease_expires_at > ?)",
                (device_id, utc_epoch()),
            ).fetchone()
        if row is None:
            return None
        value = row["se_public_key_der"]
        return value if value else None

    def record_audit(
        self,
        event: str,
        *,
        device_id: str | None,
        outcome: str,
        path: str | None = None,
        detail: dict[str, Any] | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        audit_detail = _redact_for_audit(detail or {})
        payload = json.dumps(audit_detail, sort_keys=True)
        if conn is not None:
            conn.execute(
                """
                INSERT INTO audit_events (ts, event, device_id, outcome, path, detail_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (utc_epoch(), event, device_id, outcome, path, payload),
            )
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({
            "ts": utc_epoch(),
            "event": event,
            "device_id": device_id,
            "outcome": outcome,
            "path": path,
            "detail": audit_detail,
        }, sort_keys=True)
        with self.audit_path.open("a") as fh:
            fh.write(line + "\n")
        try:
            os.chmod(self.audit_path, 0o600)
        except OSError:
            pass

    def recent_phone_tool_activity(
        self,
        *,
        limit: int = 50,
        agent_provider: str | None = None,
        session_identity: str | None = None,
    ) -> dict[str, Any]:
        """Return a bounded, display-only view of durable Phone Tools runs."""
        bounded_limit = max(1, min(int(limit), PHONE_TOOL_ACTIVITY_MAX_ITEMS))
        filtered = agent_provider is not None or session_identity is not None
        if filtered and (agent_provider is None or session_identity is None):
            raise ValueError("Phone Tools activity requires provider and session together")
        try:
            descriptor = os.open(
                self.audit_path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            return {
                "items": [],
                "filtered": filtered,
                "unbound_count": 0,
            }
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("Pairling audit history must be a regular file")
            if metadata.st_uid != os.getuid():
                raise ValueError("Pairling audit history must be owned by the current user")
            if metadata.st_mode & 0o022:
                raise ValueError("Pairling audit history must not be group or world writable")
            path_metadata = os.stat(self.audit_path, follow_symlinks=False)
            if (
                not stat.S_ISREG(path_metadata.st_mode)
                or path_metadata.st_dev != metadata.st_dev
                or path_metadata.st_ino != metadata.st_ino
            ):
                raise ValueError("Pairling audit history changed while it was opened")
            offset = max(0, metadata.st_size - PHONE_TOOL_ACTIVITY_READ_BYTES)
            raw = os.pread(descriptor, min(metadata.st_size, PHONE_TOOL_ACTIVITY_READ_BYTES), offset)
        finally:
            os.close(descriptor)

        lines = raw.splitlines()
        if offset > 0 and lines:
            lines = lines[1:]

        items: list[dict[str, Any]] = []
        unbound_count = 0
        for line in reversed(lines):
            try:
                event = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            projected = _phone_tool_activity_projection(event)
            if projected is None:
                continue
            if filtered:
                projected_provider = projected.get("agent_provider")
                projected_session = projected.get("session_identity")
                if not projected_provider or not projected_session:
                    unbound_count += 1
                    continue
                if (
                    projected_provider != agent_provider
                    or projected_session != session_identity
                ):
                    continue
            if len(items) < bounded_limit:
                items.append(projected)
        return {
            "items": items,
            "filtered": filtered,
            "unbound_count": unbound_count,
        }


def _bounded_audit_label(value: Any, *, maximum: int, pattern: str) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or re.fullmatch(pattern, normalized) is None:
        return None
    return normalized


def _phone_tool_activity_projection(event: Any) -> dict[str, Any] | None:
    if not isinstance(event, dict) or event.get("event") != PHONE_TOOL_ACTIVITY_EVENT:
        return None
    detail = event.get("detail")
    if not isinstance(detail, dict):
        return None
    tool = _bounded_audit_label(
        detail.get("tool"),
        maximum=80,
        pattern=r"[A-Za-z0-9_.-]+",
    )
    if tool is None:
        return None
    try:
        timestamp = float(event.get("ts"))
        latency_ms = max(0, min(int(detail.get("latency_ms") or 0), 86_400_000))
    except (TypeError, ValueError, OverflowError):
        return None
    if not (timestamp > 0 and timestamp < float("inf")):
        return None

    outcome = _bounded_audit_label(
        event.get("outcome"),
        maximum=80,
        pattern=r"[A-Za-z0-9_.-]+",
    ) or "error"
    provider = detail.get("provider")
    if provider not in {"iphone", "mac_fallback"}:
        provider = None
    fallback_reason = _bounded_audit_label(
        detail.get("fallback_reason"),
        maximum=160,
        pattern=r"[A-Za-z0-9_.:-]+",
    )
    agent_provider = _bounded_audit_label(
        detail.get("agent_provider"),
        maximum=48,
        pattern=r"[a-z0-9_-]+",
    )
    session_identity = _bounded_audit_label(
        detail.get("session_identity"),
        maximum=160,
        pattern=r"[A-Za-z0-9._:-]+",
    )
    identity_payload = json.dumps(
        [timestamp, tool, outcome, provider, fallback_reason, latency_ms, agent_provider, session_identity],
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "id": hashlib.sha256(identity_payload).hexdigest(),
        "tool": tool,
        "outcome": outcome,
        "provider": provider,
        "fallback_reason": fallback_reason,
        "latency_ms": latency_ms,
        "timestamp": timestamp,
        "agent_provider": agent_provider,
        "session_identity": session_identity,
    }
