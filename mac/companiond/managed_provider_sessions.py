"""Durable ownership and normalized history for structured provider sessions.

Only sessions launched through :class:`ManagedProviderSessionManager` enter this
store. Hook, process-discovery, and PTY sessions remain owned by their existing
registries and are never adopted here.
"""
from __future__ import annotations

import dataclasses
import hashlib
import math
import json
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable


_TERMINAL_CAPABILITIES = frozenset({
    "terminal_output", "terminal_surface", "terminal_control", "terminal_input"
})
_PUBLIC_EVENT_KINDS = frozenset({
    "block_text", "block_thinking", "tool_call", "tool_result", "lifecycle", "partial_text"
})
_SECRET_KEYS = re.compile(
    r"(?:authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"password|passwd|secret|credential|cookie|provider[_-]?raw|"
    r"(?:^|[_-])raw(?:$|[_-]))",
    re.IGNORECASE,
)
_SECRET_VALUES = re.compile(
    r"(?i)(?:"
    r"(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{8,}|"
    r"\bgh[pousr]_[A-Za-z0-9]{20,}|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}|"
    r"\bAIza[A-Za-z0-9_-]{20,}|"
    r"\bAKIA[0-9A-Z]{16}|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*\S+"
    r")"
)
_METADATA_KEYS = frozenset({
    "provider_id", "provider", "binding_id", "capability_generation", "generation",
    "turn_id", "item_id", "event_id", "status", "usage", "tool_name", "model",
    "reasoning", "permission", "command_id", "session_update", "plan_step",
})
_LIVE_LIFECYCLES = frozenset({"launching", "running", "waiting", "blocked", "closing"})
_MAX_VISIBLE_TEXT = 64 * 1024
_MAX_INPUT_TEXT = 16 * 1024
_MAX_METADATA_TEXT = 2048
_CANARY_ATTESTATION_FIELDS = frozenset({
    "schema_version", "provider_id", "provider_version", "provider_channel",
    "profile_digest", "managed_config_digest", "binding_id", "session_id",
    "capability_generation", "canaries", "evidence_digest", "observed_at",
    "expires_at",
})


class ManagedProviderSessionError(RuntimeError):
    code = "managed_session_error"


class ManagedProviderSessionCollision(ManagedProviderSessionError):
    code = "managed_session_id_collision"


class ManagedProviderDriverUnavailable(ManagedProviderSessionError):
    code = "managed_provider_unavailable"


class ManagedProviderAuthUnavailable(ManagedProviderDriverUnavailable):
    code = "managed_provider_auth_unavailable"


class ManagedProviderVersionUnavailable(ManagedProviderDriverUnavailable):
    code = "managed_provider_version_unavailable"


class ManagedProviderProfileStale(ManagedProviderDriverUnavailable):
    code = "managed_provider_profile_stale"


class ManagedProviderAttestationMismatch(ManagedProviderDriverUnavailable):
    code = "managed_provider_attestation_mismatch"


class ManagedProviderAttestationExpired(ManagedProviderDriverUnavailable):
    code = "managed_provider_attestation_expired"


class ManagedProviderForkOutcomeUnknown(ManagedProviderSessionError):
    code = "managed_provider_fork_outcome_unknown"


class ManagedProviderBindingStale(ManagedProviderSessionError):
    code = "managed_session_binding_stale"


def _qualified_session_id(provider: str, native_id: str) -> str:
    provider = str(provider or "").strip().lower()
    native_id = str(native_id or "").strip()
    if not provider or not re.fullmatch(r"[a-z0-9_]{1,48}", provider):
        raise ValueError("invalid provider id")
    if not native_id or len(native_id) > 512 or any(ch in native_id for ch in "\r\n\0"):
        raise ValueError("invalid native session id")
    return f"{provider}:{native_id}"


def _object_dict(value: Any) -> dict:
    if isinstance(value, dict):
        return dict(value)
    if dataclasses.is_dataclass(value):
        return dataclasses.asdict(value)
    result = getattr(value, "__dict__", None)
    return dict(result) if isinstance(result, dict) else {}


def _operation_result_payload(value: Any) -> dict:
    to_payload = getattr(value, "to_payload", None)
    payload = to_payload() if callable(to_payload) else value
    if not isinstance(payload, dict):
        raise ManagedProviderForkOutcomeUnknown(
            "provider fork proof is not a result object"
        )
    return dict(payload)


def _fork_child_native_id(result_payload: dict) -> str:
    public = result_payload.get("public_result")
    if not isinstance(public, dict):
        raise ManagedProviderForkOutcomeUnknown(
            "provider fork proof has no public child identity"
        )
    candidates: list[str] = []
    for key in ("native_session_id", "session_id", "new_session_id"):
        value = public.get(key)
        if isinstance(value, str) and value.strip():
            candidates.append(value.strip())
    nested = public.get("session")
    if isinstance(nested, dict):
        for key in ("native_session_id", "session_id", "id"):
            value = nested.get(key)
            if isinstance(value, str) and value.strip():
                candidates.append(value.strip())
    unique = set(candidates)
    if len(unique) != 1:
        raise ManagedProviderForkOutcomeUnknown(
            "provider fork proof has an absent or ambiguous child identity"
        )
    native_id = next(iter(unique))
    if len(native_id) > 512 or any(ch in native_id for ch in "\r\n\0"):
        raise ManagedProviderForkOutcomeUnknown(
            "provider fork proof child identity is invalid"
        )
    return native_id


def managed_provider_launch_profile(
    driver: Any,
    provider: str,
    *,
    display_name: str | None = None,
) -> dict:
    """Return the one exact stable safe-profile identity for this driver."""

    provider_id = str(provider or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9_]{1,48}", provider_id):
        raise ManagedProviderProfileStale("managed provider id is invalid")
    profile = getattr(driver, "profile", None)
    profile_digest = getattr(profile, "safe_launch_digest", None)
    if (
        isinstance(profile_digest, str)
        and re.fullmatch(r"[a-f0-9]{64}", profile_digest)
    ):
        profile_id = f"{provider_id}:acp:{profile_digest[:24]}"
        label_suffix = "Managed ACP"
    else:
        safe_profile = getattr(driver, "safe_launch_profile", None)
        if isinstance(safe_profile, dict):
            digest = hashlib.sha256(
                json.dumps(
                    safe_profile,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("utf-8")
            ).hexdigest()
            profile_id = f"{provider_id}:managed:{digest[:24]}"
        else:
            profile_id = f"{provider_id}:managed"
        label_suffix = "Managed"
    label = _bounded_text(
        f"{display_name or provider_id.replace('_', ' ').title()} "
        f"{label_suffix}",
        160,
    )
    return {
        "id": profile_id,
        "display_name": label,
        "spawn_backends": ["managed_provider"],
    }


def _bounded_text(value: Any, limit: int) -> str:
    text = str(value or "")
    if len(text) > limit:
        return text[: max(0, limit - 3)] + "..."
    return text


def _attestation_expiry(attestation: Any) -> float | None:
    if not isinstance(attestation, dict):
        return None
    value = attestation.get("expires_at")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    expiry = float(value)
    return expiry if math.isfinite(expiry) else None


def _driver_launch_attestation(
    driver: Any,
    *,
    provider: str,
    provider_version: str,
    provider_channel: str,
    binding_id: str,
    session_id: str,
    capability_generation: int,
) -> tuple[bool, dict | None, list[str], float | None]:
    """Read and validate only the server-owned driver's launch qualification."""

    profile = getattr(driver, "profile", None)
    required_canaries = tuple(getattr(profile, "required_canaries", ()) or ())
    read_attestation = getattr(driver, "provider_canary_attestation", None)
    read_missing = getattr(driver, "missing_canaries", None)
    required = bool(required_canaries or callable(read_attestation) or callable(read_missing))
    if not required:
        return False, None, [], None
    if not callable(read_attestation) or not callable(read_missing):
        raise ManagedProviderAttestationMismatch(
            f"{provider} managed launch does not expose server-owned canary proof"
        )
    try:
        missing_value = read_missing()
        attestation = read_attestation()
    except Exception as exc:
        raise ManagedProviderAttestationMismatch(
            f"{provider} managed launch canary proof is unavailable"
        ) from exc
    if not isinstance(missing_value, (tuple, list)):
        raise ManagedProviderAttestationMismatch(
            f"{provider} managed launch missing-canary proof is invalid"
        )
    missing = [
        _bounded_text(item, 160)
        for item in missing_value
        if isinstance(item, str) and item
    ][:64]
    if len(missing) != len(missing_value):
        raise ManagedProviderAttestationMismatch(
            f"{provider} managed launch missing-canary proof is invalid"
        )
    if missing:
        if attestation is not None:
            raise ManagedProviderAttestationMismatch(
                f"{provider} managed launch canary proof is inconsistent"
            )
        return True, None, missing, None
    if not isinstance(attestation, dict) or set(attestation) != _CANARY_ATTESTATION_FIELDS:
        raise ManagedProviderAttestationMismatch(
            f"{provider} managed launch canary attestation has an invalid shape"
        )
    try:
        from providers.acp_profiles import (
            AcpProfileUnavailable,
            validate_canary_attestation,
        )
    except ImportError:
        AcpProfileUnavailable = None
        validate_canary_attestation = None
    if profile is not None and callable(validate_canary_attestation):
        validated = validate_canary_attestation(
            profile,
            attestation,
            binding_id=binding_id,
            session_id=session_id,
            capability_generation=int(capability_generation),
        )
        if AcpProfileUnavailable is not None and isinstance(
            validated, AcpProfileUnavailable
        ):
            if validated.code == "canary_attestation_stale":
                raise ManagedProviderAttestationExpired(validated.reason)
            raise ManagedProviderAttestationMismatch(validated.reason)
    else:
        identity_matches = (
            attestation.get("schema_version") == 1
            and attestation.get("provider_id") == provider
            and attestation.get("provider_version") == provider_version
            and attestation.get("provider_channel") == provider_channel
            and attestation.get("binding_id") == binding_id
            and attestation.get("session_id") == session_id
            and attestation.get("capability_generation")
            == int(capability_generation)
        )
        if not identity_matches:
            raise ManagedProviderAttestationMismatch(
                f"{provider} managed launch canary attestation identity is stale"
            )
    expiry = _attestation_expiry(attestation)
    if expiry is None or time.time() > expiry:
        raise ManagedProviderAttestationExpired(
            f"{provider} managed launch canary attestation is expired"
        )
    return True, dict(attestation), [], expiry


def _redact_value(value: Any, *, depth: int = 0, text_limit: int = _MAX_INPUT_TEXT) -> Any:
    if depth >= 5:
        return "[TRUNCATED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        bounded = _bounded_text(value, text_limit)
        if bounded.startswith("data:"):
            return "[INLINE DATA OMITTED]"
        return _SECRET_VALUES.sub("[REDACTED]", bounded)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "[BINARY OMITTED]"
    if isinstance(value, (list, tuple)):
        return [_redact_value(item, depth=depth + 1, text_limit=text_limit) for item in value[:32]]
    if isinstance(value, dict):
        result = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 32:
                break
            public_key = _bounded_text(key, 128)
            if _SECRET_KEYS.search(public_key):
                result[public_key] = "[REDACTED]"
            else:
                result[public_key] = _redact_value(
                    item, depth=depth + 1, text_limit=text_limit
                )
        return result
    return _bounded_text(value, text_limit)


def _event_payload(event: dict) -> dict:
    payload = event.get("payload")
    if not isinstance(payload, dict):
        payload = {}
    merged = dict(payload)
    for key in (
        "text", "content", "role", "name", "tool_name", "call_id", "item_id",
        "input", "is_error", "status", "reason", "message", "error", "subtype",
    ):
        if key in event and key not in merged:
            merged[key] = event[key]
    return merged


def _normalize_kind(event: dict, payload: dict) -> tuple[str, str | None]:
    source = str(event.get("kind") or event.get("type") or payload.get("type") or "status").strip().lower()
    if source in _PUBLIC_EVENT_KINDS:
        return source, str(payload.get("subtype") or source) if source == "lifecycle" else None
    if source in {"assistant.message", "user.message"}:
        return "block_text", None
    if source in {"assistant.message_delta", "assistant.text_delta"}:
        return "partial_text", None
    if source in {"assistant.reasoning", "assistant.reasoning_delta"}:
        return "block_thinking", None
    if source in {"assistant.turn_start", "model.call_start"}:
        return "lifecycle", "running"
    if source == "assistant.turn_end":
        return "lifecycle", "completed"
    if source in {"assistant.idle", "session.idle"}:
        return "lifecycle", "idle"
    if source in {"content", "message", "assistant", "assistant_message", "text", "output"}:
        return "block_text", None
    if source in {"delta", "content_delta", "text_delta", "stream_delta"}:
        return "partial_text", None
    if source in {"thought", "thinking", "reasoning"}:
        return "block_thinking", None
    if source in {"tool", "tool_use", "tool_call", "command", "command_start"}:
        return "tool_call", None
    if source in {"tool_result", "tool_call_update", "command_result", "command_update"}:
        return "tool_result", None
    return "lifecycle", source or "status"


def normalize_driver_event(event_value: Any, *, provider: str, binding_id: str,
                           generation: int) -> dict:
    """Return the bounded public record. Raw provider objects never survive."""
    event = _object_dict(event_value)
    payload = _event_payload(event)
    kind, subtype = _normalize_kind(event, payload)
    observed_at = event.get("observed_at", event.get("timestamp", event.get("ts", time.time())))
    try:
        observed_at = float(observed_at)
    except (TypeError, ValueError):
        observed_at = time.time()

    public_payload: dict[str, Any] = {}
    role = _bounded_text(payload.get("role") or event.get("role"), 64)
    if not role:
        source_role = str(event.get("kind") or event.get("type") or "").partition(".")[0]
        if source_role in {"assistant", "user", "system"}:
            role = source_role
    if kind in {"block_text", "block_thinking", "partial_text"}:
        text = payload.get("text", payload.get("content", payload.get("message", "")))
        public_payload["text"] = _redact_value(text, text_limit=_MAX_VISIBLE_TEXT)
        if role:
            public_payload["role"] = role
    elif kind == "tool_call":
        public_payload["name"] = _bounded_text(
            payload.get("name") or payload.get("tool_name") or "tool", 160
        )
        call_id = payload.get("call_id") or payload.get("item_id") or event.get("item_id")
        if call_id:
            public_payload["call_id"] = _bounded_text(call_id, 256)
        if "input" in payload:
            public_payload["input"] = _redact_value(payload.get("input"))
    elif kind == "tool_result":
        call_id = payload.get("call_id") or payload.get("item_id") or event.get("item_id")
        if call_id:
            public_payload["call_id"] = _bounded_text(call_id, 256)
        content = payload.get("content", payload.get("text", payload.get("message", "")))
        public_payload["content"] = _redact_value(content, text_limit=_MAX_VISIBLE_TEXT)
        public_payload["is_error"] = bool(payload.get("is_error"))
    else:
        public_payload["subtype"] = _bounded_text(subtype or "status", 128)
        status = payload.get("status") or event.get("status")
        if status:
            public_payload["status"] = _bounded_text(status, 128)
        reason = payload.get("reason") or payload.get("message") or payload.get("error")
        if reason:
            public_payload["reason"] = _redact_value(reason, text_limit=_MAX_METADATA_TEXT)

    metadata = {
        "provider_id": provider,
        "binding_id": binding_id,
        "capability_generation": int(generation),
    }
    for source in (event, payload):
        for key in _METADATA_KEYS:
            if key in source and key not in {"provider_raw", "raw"}:
                canonical = "provider_id" if key == "provider" else (
                    "capability_generation" if key == "generation" else key
                )
                if canonical in {"provider_id", "binding_id", "capability_generation"}:
                    continue
                metadata[canonical] = _redact_value(
                    source[key], text_limit=_MAX_METADATA_TEXT
                )
    cursor = event.get("cursor") or event.get("provider_cursor")
    event_id = event.get("event_id")
    if cursor is None:
        identity = json.dumps(
            {"kind": kind, "payload": public_payload, "metadata": metadata, "event_id": event_id},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        )
        cursor = "event:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return {
        "provider_cursor": _bounded_text(cursor, 512),
        "observed_at": observed_at,
        "kind": kind,
        "payload": public_payload,
        "metadata": metadata,
    }


def _derive_state(current_lifecycle: str, current_turn_state: str, event: dict) -> tuple[str, str, str | None]:
    kind = event["kind"]
    payload = event["payload"]
    subtype = str(payload.get("subtype") or "").lower()
    status = str(payload.get("status") or "").lower()
    reason = str(payload.get("reason") or "").strip() or None
    marker = status or subtype
    if "." in marker:
        suffix = marker.rsplit(".", 1)[-1]
        if suffix in {
            "closed", "terminated", "complete", "completed", "ended", "archived",
            "permission_request", "approval_required", "blocked", "protocol_error",
            "error", "failed", "waiting", "idle", "ready", "running", "started",
            "thinking", "tool_call", "command",
        }:
            marker = suffix
    if marker in {"closed", "terminated", "complete", "completed", "ended", "archived"}:
        if marker in {"complete", "completed"}:
            return "waiting", "idle", None
        return "closed", "closed", reason
    if marker in {"permission_request", "approval_required", "blocked", "protocol_error", "error", "failed"}:
        return "blocked", "blocked", reason or marker.replace("_", " ")
    if marker in {"waiting", "idle", "ready"}:
        return "waiting", "waiting", None
    if marker in {"running", "started", "thinking", "tool_call", "command"}:
        return "running", "running", None
    if kind in {"partial_text", "block_thinking", "tool_call"}:
        return "running", "running", None
    if current_lifecycle not in _LIVE_LIFECYCLES and current_lifecycle != "closed":
        current_lifecycle = "running"
    return current_lifecycle, current_turn_state or "running", None


class ManagedProviderSessionStore:
    """SQLite owner record and append-only normalized event history."""

    def __init__(self, db_path: str | Path) -> None:
        path = Path(db_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = str(path)
        self._lock = threading.RLock()
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS managed_provider_sessions (
                    session_id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    native_id TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    capability_generation INTEGER NOT NULL,
                    project TEXT NOT NULL,
                    title TEXT NOT NULL,
                    source_install_id TEXT NOT NULL,
                    lifecycle TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    provider_cursor TEXT,
                    turn_state TEXT NOT NULL,
                    blocked_reason TEXT,
                    driver_available INTEGER NOT NULL,
                    provider_version TEXT,
                    provider_channel TEXT,
                    provider_profile_id TEXT NOT NULL,
                    session_instance_id TEXT NOT NULL,
                    launch_action_id TEXT,
                    launch_body_hash TEXT,
                    provider_attestation_json TEXT,
                    missing_canaries_json TEXT,
                    provider_attestation_required INTEGER NOT NULL DEFAULT 0,
                    provider_attestation_expires_at REAL,
                    fork_parent_session_id TEXT,
                    fork_action_id TEXT,
                    fork_reservation_token TEXT,
                    fork_provider_operation_id TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    closed_at REAL,
                    UNIQUE(provider, native_id),
                    UNIQUE(binding_id)
                );
                CREATE INDEX IF NOT EXISTS idx_managed_provider_sessions_recent
                    ON managed_provider_sessions(provider, updated_at DESC);
                CREATE TABLE IF NOT EXISTS managed_provider_events (
                    session_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    binding_id TEXT NOT NULL,
                    capability_generation INTEGER NOT NULL,
                    provider_cursor TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    PRIMARY KEY(session_id, seq),
                    UNIQUE(session_id, binding_id, capability_generation, provider_cursor),
                    FOREIGN KEY(session_id) REFERENCES managed_provider_sessions(session_id)
                );
                CREATE INDEX IF NOT EXISTS idx_managed_provider_events_cursor
                    ON managed_provider_events(session_id, seq);
                CREATE TABLE IF NOT EXISTS managed_provider_forks (
                    reservation_token TEXT PRIMARY KEY,
                    parent_session_id TEXT NOT NULL,
                    client_action_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    provider_version TEXT NOT NULL,
                    provider_channel TEXT NOT NULL,
                    provider_profile_id TEXT NOT NULL,
                    parent_binding_id TEXT NOT NULL,
                    parent_capability_generation INTEGER NOT NULL,
                    parent_session_instance_id TEXT NOT NULL,
                    provider_operation_id TEXT,
                    provider_cursor TEXT,
                    child_binding_id TEXT NOT NULL UNIQUE,
                    child_capability_generation INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    child_native_id TEXT,
                    child_session_id TEXT,
                    reason TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    UNIQUE(parent_session_id, client_action_id),
                    FOREIGN KEY(parent_session_id)
                        REFERENCES managed_provider_sessions(session_id),
                    FOREIGN KEY(child_session_id)
                        REFERENCES managed_provider_sessions(session_id)
                );
                CREATE INDEX IF NOT EXISTS idx_managed_provider_forks_state
                    ON managed_provider_forks(state, updated_at);
                """
            )
            session_columns = {
                str(row["name"])
                for row in conn.execute(
                    "PRAGMA table_info(managed_provider_sessions)"
                ).fetchall()
            }
            if "session_instance_id" not in session_columns:
                conn.execute(
                    "ALTER TABLE managed_provider_sessions "
                    "ADD COLUMN session_instance_id TEXT NOT NULL DEFAULT ''"
                )
            if "provider_attestation_json" not in session_columns:
                conn.execute(
                    "ALTER TABLE managed_provider_sessions "
                    "ADD COLUMN provider_attestation_json TEXT"
                )
            if "missing_canaries_json" not in session_columns:
                conn.execute(
                    "ALTER TABLE managed_provider_sessions "
                    "ADD COLUMN missing_canaries_json TEXT"
                )
            migrations = {
                "provider_attestation_required":
                    "INTEGER NOT NULL DEFAULT 0",
                "provider_attestation_expires_at": "REAL",
                "provider_profile_id": "TEXT NOT NULL DEFAULT ''",
                "fork_parent_session_id": "TEXT",
                "fork_action_id": "TEXT",
                "fork_reservation_token": "TEXT",
                "fork_provider_operation_id": "TEXT",
            }
            for column, declaration in migrations.items():
                if column not in session_columns:
                    conn.execute(
                        "ALTER TABLE managed_provider_sessions "
                        f"ADD COLUMN {column} {declaration}"
                    )
            fork_columns = {
                str(row["name"])
                for row in conn.execute(
                    "PRAGMA table_info(managed_provider_forks)"
                ).fetchall()
            }
            if "provider_profile_id" not in fork_columns:
                conn.execute(
                    "ALTER TABLE managed_provider_forks "
                    "ADD COLUMN provider_profile_id TEXT NOT NULL DEFAULT ''"
                )

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=3.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=3000")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        result = dict(row)
        result["id"] = result["session_id"]
        result["managed"] = True
        result["owner"] = "provider_driver"
        result["terminal_backed"] = False
        result["terminal_tty"] = ""
        result["pid"] = 0
        result["claude_pid"] = 0
        result["started_at"] = int(float(result.pop("created_at") or 0))
        result["last_heartbeat"] = int(float(result.get("updated_at") or 0))
        closed_at = result.get("closed_at")
        result["closed_at"] = int(float(closed_at)) if closed_at is not None else None
        result["working_on"] = result.get("title") or None
        result["first_prompt"] = None
        attestation_json = result.pop("provider_attestation_json", None)
        result.pop("missing_canaries_json", None)
        result.pop("fork_reservation_token", None)
        required_attestation = bool(
            result.pop("provider_attestation_required", 0)
        )
        persisted_expiry = result.pop(
            "provider_attestation_expires_at", None
        )
        try:
            attestation = json.loads(attestation_json)
            if not isinstance(attestation, dict):
                attestation = None
        except (TypeError, ValueError):
            attestation = None
        expiry = _attestation_expiry(attestation)
        if expiry is None and isinstance(persisted_expiry, (int, float)):
            expiry = float(persisted_expiry)
        attestation_current = bool(
            attestation is not None
            and expiry is not None
            and time.time() <= expiry
        )
        result["provider_attested"] = bool(attestation is not None)
        result["provider_attestation_current"] = attestation_current
        qualification_current = not required_attestation or attestation_current
        try:
            capabilities = json.loads(result.pop("capabilities_json") or "[]")
        except (TypeError, ValueError):
            capabilities = []
        result["capabilities"] = [
            value for value in capabilities
            if isinstance(value, str) and value not in _TERMINAL_CAPABILITIES
        ]
        lifecycle = str(result.get("lifecycle") or "blocked")
        available = bool(result.pop("driver_available", 0))
        result["driver_available"] = available
        result["readable_state"] = (
            "closed" if lifecycle == "closed" else ("live" if available and lifecycle in _LIVE_LIFECYCLES else "stale")
        )
        result["control_state"] = (
            "controllable"
            if (
                available
                and qualification_current
                and lifecycle in _LIVE_LIFECYCLES - {"blocked", "closing"}
            )
            else "read_only"
        )
        control_reason = result.get("blocked_reason")
        if lifecycle == "closed":
            control_reason = control_reason or "Session is closed; normalized history remains readable."
        elif required_attestation and not qualification_current:
            control_reason = (
                "Provider canary attestation is missing or expired; "
                "the session remains read-only."
            )
        elif not available:
            control_reason = control_reason or "Provider driver unavailable; normalized history remains readable."
        controllable = result["control_state"] == "controllable"
        result["controllability"] = {
            "can_send_text": controllable,
            "can_interrupt": controllable,
            "can_terminate": controllable,
            "reason": None if controllable else control_reason,
        }
        result["state"] = result.get("turn_state")
        result["history_source"] = "managed_provider_events"
        result["normalized_history_location"] = f"sqlite:{result['session_id']}"
        return result

    def register(
        self,
        *,
        provider: str,
        native_id: str,
        binding_id: str,
        capability_generation: int,
        project: str,
        title: str,
        source_install_id: str,
        capabilities: Iterable[str],
        provider_profile_id: str,
        provider_cursor: str | None = None,
        provider_version: str | None = None,
        provider_channel: str | None = None,
        launch_action_id: str | None = None,
        launch_body_hash: str | None = None,
        provider_canary_attestation: dict | None = None,
        missing_canaries: Iterable[str] = (),
        provider_attestation_required: bool = False,
        provider_attestation_expires_at: float | None = None,
        session_instance_id: str | None = None,
        ambient_identity_exists: Callable[[str], bool] | None = None,
    ) -> dict:
        session_id = _qualified_session_id(provider, native_id)
        project = str(Path(project).expanduser().resolve(strict=False))
        binding_id = str(binding_id or "").strip()
        if not binding_id:
            raise ValueError("binding_id required")
        generation = int(capability_generation)
        if generation < 0:
            raise ValueError("capability_generation must be non-negative")
        profile_id = _bounded_text(provider_profile_id, 256)
        if (
            not profile_id
            or any(ch in profile_id for ch in "\r\n\0")
            or not profile_id.startswith(str(provider).lower() + ":")
        ):
            raise ManagedProviderProfileStale(
                "managed provider profile identity is invalid"
            )
        now = time.time()
        missing_canary_values = [
            _bounded_text(item, 160)
            for item in list(missing_canaries or ())[:64]
            if isinstance(item, str) and item
        ]
        required_attestation = bool(
            provider_attestation_required
            or provider_canary_attestation is not None
            or missing_canary_values
        )
        attestation_expiry = (
            float(provider_attestation_expires_at)
            if provider_attestation_expires_at is not None
            else _attestation_expiry(provider_canary_attestation)
        )
        invalid_attestation = (
            provider_canary_attestation is not None
            and (
                not isinstance(provider_canary_attestation, dict)
                or attestation_expiry is None
                or not math.isfinite(attestation_expiry)
                or now > attestation_expiry
            )
        )
        missing_all_proof = bool(
            required_attestation
            and provider_canary_attestation is None
            and not missing_canary_values
        )
        if invalid_attestation or missing_all_proof:
            raise ManagedProviderAttestationExpired(
                "managed provider attestation is missing or expired"
            )
        if ambient_identity_exists is not None and ambient_identity_exists(session_id):
            raise ManagedProviderSessionCollision(
                f"{session_id} is already owned by an ambient hook or PTY session"
            )
        caps = sorted({
            str(cap).strip() for cap in capabilities
            if str(cap).strip() and str(cap).strip() not in _TERMINAL_CAPABILITIES
        } | {"transcript", "live_state"})
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM managed_provider_sessions WHERE session_id=? OR binding_id=?",
                (session_id, binding_id),
            ).fetchone()
            if existing is not None:
                same = (
                    str(existing["session_id"]) == session_id
                    and str(existing["provider"]) == str(provider).lower()
                    and str(existing["native_id"]) == str(native_id)
                    and str(existing["binding_id"]) == binding_id
                    and int(existing["capability_generation"]) == generation
                    and str(existing["project"]) == project
                    and str(existing["provider_profile_id"]) == profile_id
                    and str(existing["provider_version"] or "")
                    == (_bounded_text(provider_version, 160) or "")
                    and str(existing["provider_channel"] or "")
                    == (_bounded_text(provider_channel, 80) or "")
                )
                if not same:
                    raise ManagedProviderSessionCollision(
                        f"managed session identity already bound: {session_id}"
                    )
                return self._row(existing)
            conn.execute(
                """
                INSERT INTO managed_provider_sessions(
                    session_id, provider, native_id, binding_id,
                    capability_generation, project, title, source_install_id,
                    lifecycle, capabilities_json, provider_cursor, turn_state,
                    blocked_reason, driver_available, provider_version,
                    provider_channel, provider_profile_id,
                    session_instance_id, launch_action_id, launch_body_hash,
                    provider_attestation_json, missing_canaries_json,
                    provider_attestation_required,
                    provider_attestation_expires_at, created_at, updated_at,
                    closed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, 'running',
                          NULL, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    session_id, str(provider).lower(), str(native_id), binding_id,
                    generation, project,
                    _redact_value(title or "Managed session", text_limit=500),
                    _bounded_text(source_install_id, 256), json.dumps(caps),
                    _bounded_text(provider_cursor, 512) if provider_cursor is not None else None,
                    _bounded_text(provider_version, 160) or None,
                    _bounded_text(provider_channel, 80) or None,
                    profile_id,
                    _bounded_text(
                        session_instance_id
                        or f"{binding_id}:{generation}:{native_id}",
                        512,
                    ),
                    _bounded_text(launch_action_id, 256) or None,
                    _bounded_text(launch_body_hash, 256) or None,
                    (
                        json.dumps(
                            provider_canary_attestation,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        if isinstance(provider_canary_attestation, dict)
                        else None
                    ),
                    json.dumps(
                        missing_canary_values, separators=(",", ":")
                    ),
                    1 if required_attestation else 0,
                    attestation_expiry,
                    now, now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM managed_provider_sessions WHERE session_id=?", (session_id,)
            ).fetchone()
            return self._row(row)

    def get(self, session_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM managed_provider_sessions WHERE session_id=?", (str(session_id),)
            ).fetchone()
        return self._row(row)

    def _private_launch_proof(self, session_id: str) -> tuple[dict | None, list[str]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT provider_attestation_json, missing_canaries_json "
                "FROM managed_provider_sessions WHERE session_id=?",
                (str(session_id),),
            ).fetchone()
        if row is None:
            return None, []
        try:
            attestation = json.loads(row["provider_attestation_json"])
            if not isinstance(attestation, dict):
                attestation = None
        except (TypeError, ValueError):
            attestation = None
        try:
            missing = json.loads(row["missing_canaries_json"] or "[]")
            if not isinstance(missing, list):
                missing = []
        except (TypeError, ValueError):
            missing = []
        return attestation, [
            _bounded_text(item, 160) for item in missing[:64]
        ]

    def find_launch(self, launch_action_id: str, launch_body_hash: str | None = None) -> dict | None:
        if not launch_action_id:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM managed_provider_sessions WHERE launch_action_id=?",
                (str(launch_action_id),),
            ).fetchone()
        result = self._row(row)
        if result is not None and launch_body_hash and result.get("launch_body_hash") != launch_body_hash:
            raise ManagedProviderSessionCollision("launch action is bound to different request data")
        return result


    @staticmethod
    def _fork_row(row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        result = dict(row)
        result["id"] = result["reservation_token"]
        result["parent_generation"] = int(
            result["parent_capability_generation"]
        )
        result["child_generation"] = int(
            result["child_capability_generation"]
        )
        return result

    def prepare_fork(
        self,
        parent_session_id: str,
        client_action_id: str,
        *,
        provider_operation_id: str | None,
        provider_cursor: str | None,
    ) -> dict:
        parent_id = str(parent_session_id or "").strip()
        action_id = _bounded_text(client_action_id, 256)
        operation_id = _bounded_text(provider_operation_id, 512) or None
        cursor = (
            _bounded_text(provider_cursor, 512)
            if provider_cursor is not None
            else None
        )
        if not parent_id or not action_id:
            raise ValueError("fork parent and client action id are required")
        now = time.time()
        with self._lock, self._connect() as conn:
            parent = conn.execute(
                "SELECT * FROM managed_provider_sessions WHERE session_id=?",
                (parent_id,),
            ).fetchone()
            public_parent = self._row(parent)
            if (
                parent is None
                or public_parent is None
                or public_parent["control_state"] != "controllable"
                or not parent["provider_version"]
                or not parent["provider_channel"]
                or not parent["provider_profile_id"]
                or not parent["session_instance_id"]
            ):
                raise ManagedProviderBindingStale(
                    "fork parent is not an exact live managed binding"
                )
            existing = conn.execute(
                """
                SELECT * FROM managed_provider_forks
                WHERE parent_session_id=? AND client_action_id=?
                """,
                (parent_id, action_id),
            ).fetchone()
            if existing is not None:
                same = (
                    str(existing["parent_binding_id"])
                    == str(parent["binding_id"])
                    and int(existing["parent_capability_generation"])
                    == int(parent["capability_generation"])
                    and str(existing["parent_session_instance_id"])
                    == str(parent["session_instance_id"])
                    and (
                        existing["provider_operation_id"] == operation_id
                    )
                    and existing["provider_cursor"] == cursor
                )
                if not same:
                    raise ManagedProviderSessionCollision(
                        "fork action is bound to different parent proof"
                    )
                return self._fork_row(existing)
            token = "fork_" + secrets.token_hex(24)
            child_binding_id = "managed_" + secrets.token_hex(24)
            child_generation = max(
                1, int(parent["capability_generation"]) + 1
            )
            conn.execute(
                """
                INSERT INTO managed_provider_forks(
                    reservation_token, parent_session_id, client_action_id,
                    provider, provider_version, provider_channel,
                    provider_profile_id, parent_binding_id,
                    parent_capability_generation, parent_session_instance_id,
                    provider_operation_id, provider_cursor, child_binding_id,
                    child_capability_generation, state, child_native_id,
                    child_session_id, reason, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          'prepared', NULL, NULL, NULL, ?, ?)
                """,
                (
                    token,
                    parent_id,
                    action_id,
                    str(parent["provider"]),
                    str(parent["provider_version"]),
                    str(parent["provider_channel"]),
                    str(parent["provider_profile_id"]),
                    str(parent["binding_id"]),
                    int(parent["capability_generation"]),
                    str(parent["session_instance_id"]),
                    operation_id,
                    cursor,
                    child_binding_id,
                    child_generation,
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM managed_provider_forks "
                "WHERE reservation_token=?",
                (token,),
            ).fetchone()
            return self._fork_row(row)

    def fork_reservation(self, reservation_token: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM managed_provider_forks "
                "WHERE reservation_token=?",
                (str(reservation_token),),
            ).fetchone()
        return self._fork_row(row)

    def list_forks(
        self,
        *,
        state: str | None = None,
        parent_session_id: str | None = None,
        limit: int = 500,
    ) -> list[dict]:
        where = []
        params: list[Any] = []
        if state is not None:
            where.append("state=?")
            params.append(str(state))
        if parent_session_id is not None:
            where.append("parent_session_id=?")
            params.append(str(parent_session_id))
        statement = "SELECT * FROM managed_provider_forks"
        if where:
            statement += " WHERE " + " AND ".join(where)
        statement += " ORDER BY created_at ASC LIMIT ?"
        params.append(max(1, min(int(limit), 1000)))
        with self._connect() as conn:
            rows = conn.execute(statement, params).fetchall()
        return [self._fork_row(row) for row in rows]

    def mark_fork_outcome_unknown(
        self,
        reservation_token: str,
        *,
        reason: str,
    ) -> dict | None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE managed_provider_forks
                SET state='outcome_unknown', reason=?, updated_at=?
                WHERE reservation_token=? AND state='prepared'
                """,
                (
                    _bounded_text(reason or "fork outcome is unknown", 500),
                    time.time(),
                    str(reservation_token),
                ),
            )
            row = conn.execute(
                "SELECT * FROM managed_provider_forks "
                "WHERE reservation_token=?",
                (str(reservation_token),),
            ).fetchone()
        return self._fork_row(row)

    def register_fork_child(
        self,
        *,
        reservation_token: str,
        parent_session_id: str,
        child_native_id: str,
        provider_operation_id: str,
        provider_cursor: str | None,
        ambient_identity_exists: Callable[[str], bool] | None = None,
    ) -> dict:
        token = str(reservation_token or "").strip()
        parent_id = str(parent_session_id or "").strip()
        operation_id = _bounded_text(provider_operation_id, 512)
        child_id = _qualified_session_id(
            self.fork_reservation(token)["provider"],
            child_native_id,
        ) if self.fork_reservation(token) is not None else ""
        if not token or not parent_id or not operation_id or not child_id:
            raise ManagedProviderForkOutcomeUnknown(
                "fork registration proof is incomplete"
            )
        now = time.time()
        with self._lock, self._connect() as conn:
            reservation = conn.execute(
                "SELECT * FROM managed_provider_forks "
                "WHERE reservation_token=?",
                (token,),
            ).fetchone()
            if reservation is None or str(
                reservation["parent_session_id"]
            ) != parent_id:
                raise ManagedProviderForkOutcomeUnknown(
                    "fork reservation does not match its parent"
                )
            if reservation["state"] == "registered":
                if (
                    str(reservation["child_native_id"]) != str(child_native_id)
                    or str(reservation["child_session_id"]) != child_id
                    or str(reservation["provider_operation_id"])
                    != operation_id
                ):
                    raise ManagedProviderSessionCollision(
                        "fork reservation was already registered differently"
                    )
                row = conn.execute(
                    "SELECT * FROM managed_provider_sessions "
                    "WHERE session_id=?",
                    (child_id,),
                ).fetchone()
                if row is None:
                    raise ManagedProviderForkOutcomeUnknown(
                        "registered fork child ownership is missing"
                    )
                return self._row(row)
            if reservation["state"] != "prepared":
                raise ManagedProviderForkOutcomeUnknown(
                    "fork reservation is sealed outcome_unknown"
                )
            if reservation["provider_operation_id"] != operation_id:
                raise ManagedProviderForkOutcomeUnknown(
                    "fork provider correlation does not match reservation"
                )
            parent = conn.execute(
                "SELECT * FROM managed_provider_sessions "
                "WHERE session_id=?",
                (parent_id,),
            ).fetchone()
            if (
                parent is None
                or str(parent["binding_id"])
                != str(reservation["parent_binding_id"])
                or int(parent["capability_generation"])
                != int(reservation["parent_capability_generation"])
                or str(parent["session_instance_id"])
                != str(reservation["parent_session_instance_id"])
                or str(parent["provider_profile_id"])
                != str(reservation["provider_profile_id"])
            ):
                raise ManagedProviderBindingStale(
                    "fork parent binding changed before child registration"
                )
            if ambient_identity_exists is not None and ambient_identity_exists(
                child_id
            ):
                raise ManagedProviderSessionCollision(
                    f"{child_id} is already owned by an ambient session"
                )
            existing = conn.execute(
                "SELECT * FROM managed_provider_sessions "
                "WHERE session_id=? OR binding_id=?",
                (child_id, str(reservation["child_binding_id"])),
            ).fetchone()
            if existing is not None:
                raise ManagedProviderSessionCollision(
                    f"fork child identity already exists: {child_id}"
                )
            capabilities_json = str(parent["capabilities_json"])
            attestation_required = int(
                parent["provider_attestation_required"] or 0
            )
            missing = []
            if attestation_required:
                try:
                    parent_attestation = json.loads(
                        parent["provider_attestation_json"] or "null"
                    )
                    parent_missing = json.loads(
                        parent["missing_canaries_json"] or "[]"
                    )
                except (TypeError, ValueError):
                    parent_attestation = None
                    parent_missing = []
                canaries = (
                    parent_attestation.get("canaries")
                    if isinstance(parent_attestation, dict)
                    else None
                )
                source = canaries if isinstance(canaries, list) else parent_missing
                if isinstance(source, list):
                    missing = [
                        _bounded_text(item, 160)
                        for item in source
                        if isinstance(item, str) and item
                    ][:64]
                if not missing:
                    missing = ["provider_canary_attestation"]
            child_generation = int(
                reservation["child_capability_generation"]
            )
            child_binding = str(reservation["child_binding_id"])
            child_instance = (
                f"{child_binding}:{child_generation}:{child_native_id}"
            )
            try:
                conn.execute(
                    """
                    INSERT INTO managed_provider_sessions(
                        session_id, provider, native_id, binding_id,
                        capability_generation, project, title,
                        source_install_id, lifecycle, capabilities_json,
                        provider_cursor, turn_state, blocked_reason,
                        driver_available, provider_version, provider_channel,
                        provider_profile_id, session_instance_id,
                        launch_action_id, launch_body_hash,
                        provider_attestation_json, missing_canaries_json,
                        provider_attestation_required,
                        provider_attestation_expires_at,
                        fork_parent_session_id, fork_action_id,
                        fork_reservation_token, fork_provider_operation_id,
                        created_at, updated_at, closed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'blocked', ?, ?,
                              'blocked', ?, 0, ?, ?, ?, ?, NULL, NULL, NULL,
                              ?, ?, NULL, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        child_id,
                        str(reservation["provider"]),
                        str(child_native_id),
                        child_binding,
                        child_generation,
                        str(parent["project"]),
                        _bounded_text(
                            f"Fork of {parent['title']}", 500
                        ),
                        str(parent["source_install_id"]),
                        capabilities_json,
                        (
                            _bounded_text(provider_cursor, 512)
                            if provider_cursor is not None
                            else None
                        ),
                        (
                            "Fork registered; live provider attachment "
                            "has not been qualified."
                        ),
                        str(reservation["provider_version"]),
                        str(reservation["provider_channel"]),
                        str(reservation["provider_profile_id"]),
                        child_instance,
                        json.dumps(missing, separators=(",", ":")),
                        attestation_required,
                        parent_id,
                        str(reservation["client_action_id"]),
                        token,
                        operation_id,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ManagedProviderSessionCollision(
                    f"fork child identity already exists: {child_id}"
                ) from exc
            updated = conn.execute(
                """
                UPDATE managed_provider_forks
                SET state='registered', child_native_id=?,
                    child_session_id=?, provider_cursor=?, reason=NULL,
                    updated_at=?
                WHERE reservation_token=? AND state='prepared'
                """,
                (
                    str(child_native_id),
                    child_id,
                    (
                        _bounded_text(provider_cursor, 512)
                        if provider_cursor is not None
                        else None
                    ),
                    now,
                    token,
                ),
            )
            if updated.rowcount != 1:
                raise ManagedProviderForkOutcomeUnknown(
                    "fork reservation changed during child registration"
                )
            row = conn.execute(
                "SELECT * FROM managed_provider_sessions "
                "WHERE session_id=?",
                (child_id,),
            ).fetchone()
            return self._row(row)

    def list(self, *, provider: str = "all", live_only: bool = False,
             active_within_min: int | None = None, limit: int = 500) -> list[dict]:
        where = []
        params: list[Any] = []
        if provider and provider != "all":
            where.append("provider=?")
            params.append(str(provider).lower())
        if live_only:
            where.append("closed_at IS NULL")
            where.append("lifecycle IN ('launching','running','waiting','blocked','closing')")
        if active_within_min is not None:
            where.append("updated_at>=?")
            params.append(time.time() - max(1, int(active_within_min)) * 60)
        statement = "SELECT * FROM managed_provider_sessions"
        if where:
            statement += " WHERE " + " AND ".join(where)
        statement += " ORDER BY updated_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 1000)))
        with self._connect() as conn:
            rows = conn.execute(statement, params).fetchall()
        return [self._row(row) for row in rows]

    def session_truth(self, session_id: str) -> dict | None:
        row = self.get(session_id)
        if row is None:
            return None
        generation = int(row["capability_generation"])
        lifecycle = str(row["lifecycle"])
        is_live = bool(
            row["driver_available"]
            and row["control_state"] == "controllable"
            and lifecycle in _LIVE_LIFECYCLES
            and lifecycle not in {"blocked", "closing"}
        )
        attestation, missing_canaries = self._private_launch_proof(session_id)
        fork_outcomes = [
            {
                "client_action_id": fork["client_action_id"],
                "state": fork["state"],
                "child_session_id": fork.get("child_session_id"),
                "reason": fork.get("reason"),
            }
            for fork in self.list_forks(
                parent_session_id=session_id,
                limit=100,
            )
        ]
        return {
            "session_id": row["session_id"],
            "provider": row["provider"],
            "provider_id": row["provider"],
            "native_id": row["native_id"],
            "managed": True,
            "owner": "provider_driver",
            "project": row["project"],
            "cwd": row["project"],
            "binding_id": row["binding_id"],
            "provider_version": row.get("provider_version"),
            "provider_channel": row.get("provider_channel"),
            "provider_profile_id": row.get("provider_profile_id"),
            "capability_generation": generation,
            "lifecycle": lifecycle,
            "is_live": is_live,
            "controllable": is_live,
            "driver_available": bool(row["driver_available"]),
            "session_instance_id": row["session_instance_id"],
            "provider_canary_attestation": attestation,
            "missing_canaries": missing_canaries,
            "provider_attestation_current": bool(
                row.get("provider_attestation_current")
            ),
            "fork_parent_session_id": row.get("fork_parent_session_id"),
            "fork_action_id": row.get("fork_action_id"),
            "fork_provider_operation_id": row.get(
                "fork_provider_operation_id"
            ),
            "fork_outcomes": fork_outcomes,
            "terminal_backed": False,
        }

    def append_driver_events(
        self,
        session_id: str,
        binding_id: str,
        capability_generation: int,
        events: Iterable[Any],
        *,
        resume_cursor: Any = None,
    ) -> int:
        values = list(events or [])
        if not values and resume_cursor is None:
            return 0
        with self._lock, self._connect() as conn:
            session = conn.execute(
                "SELECT * FROM managed_provider_sessions WHERE session_id=?", (str(session_id),)
            ).fetchone()
            if session is None:
                return 0
            if (
                str(session["binding_id"]) != str(binding_id)
                or int(session["capability_generation"]) != int(capability_generation)
            ):
                return 0
            seq = int(conn.execute(
                "SELECT COALESCE(MAX(seq), 0) FROM managed_provider_events WHERE session_id=?",
                (str(session_id),),
            ).fetchone()[0])
            inserted = 0
            lifecycle = str(session["lifecycle"])
            turn_state = str(session["turn_state"])
            blocked_reason = session["blocked_reason"]
            last_cursor = session["provider_cursor"]
            updated_at = float(session["updated_at"])
            normalized_resume_cursor = (
                _bounded_text(resume_cursor, 512)
                if resume_cursor is not None
                else None
            )
            for value in values:
                event = normalize_driver_event(
                    value,
                    provider=str(session["provider"]),
                    binding_id=str(binding_id),
                    generation=int(capability_generation),
                )
                cursor = event["provider_cursor"]
                try:
                    conn.execute(
                        """
                        INSERT INTO managed_provider_events(
                            session_id, seq, binding_id, capability_generation,
                            provider_cursor, observed_at, kind, payload_json, metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(session_id), seq + 1, str(binding_id), int(capability_generation),
                            cursor, event["observed_at"], event["kind"],
                            json.dumps(event["payload"], ensure_ascii=False, separators=(",", ":")),
                            json.dumps(event["metadata"], ensure_ascii=False, separators=(",", ":")),
                        ),
                    )
                except sqlite3.IntegrityError:
                    continue
                seq += 1
                inserted += 1
                last_cursor = cursor
                updated_at = max(updated_at, float(event["observed_at"]))
                lifecycle, turn_state, derived_reason = _derive_state(
                    lifecycle, turn_state, event
                )
                if derived_reason is not None:
                    blocked_reason = derived_reason
                elif lifecycle not in {"blocked", "closed"}:
                    blocked_reason = None
            if inserted or normalized_resume_cursor is not None:
                closed_at = updated_at if lifecycle == "closed" else session["closed_at"]
                available = 0 if lifecycle == "closed" else int(session["driver_available"])
                conn.execute(
                    """
                    UPDATE managed_provider_sessions
                    SET provider_cursor=?, lifecycle=?, turn_state=?, blocked_reason=?,
                        updated_at=?, closed_at=?, driver_available=?
                    WHERE session_id=? AND binding_id=? AND capability_generation=?
                    """,
                    (
                        normalized_resume_cursor
                        if normalized_resume_cursor is not None
                        else last_cursor,
                        lifecycle, turn_state, blocked_reason, updated_at,
                        closed_at, available, str(session_id), str(binding_id),
                        int(capability_generation),
                    ),
                )
            return inserted

    def history(self, session_id: str, *, since_seq: int = 0, limit: int = 500) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT seq, provider_cursor, observed_at, kind, payload_json, metadata_json
                FROM managed_provider_events
                WHERE session_id=? AND seq>?
                ORDER BY seq ASC LIMIT ?
                """,
                (str(session_id), max(0, int(since_seq)), max(1, min(int(limit), 1000))),
            ).fetchall()
        result = []
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, ValueError):
                payload = {}
            try:
                metadata = json.loads(row["metadata_json"])
            except (TypeError, ValueError):
                metadata = {}
            result.append({
                "seq": int(row["seq"]),
                "cursor": str(row["provider_cursor"]),

                "observed_at": float(row["observed_at"]),
                "kind": str(row["kind"]),
                "payload": payload,
                "metadata": metadata,
            })
        return result
    def refresh_generation(
        self,
        session_id: str,
        *,
        binding_id: str,
        expected_generation: int,
        capability_generation: int,
    ) -> dict | None:
        """CAS a reviewed live binding's capability generation.

        The manager calls this only through a driver's explicit
        ``generation_refresh_safe`` proof seam. Historical records keep the
        generation under which they were observed.
        """
        new_generation = int(capability_generation)
        if new_generation < 0:
            raise ValueError("capability_generation must be non-negative")
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE managed_provider_sessions
                SET capability_generation=?, updated_at=?
                WHERE session_id=? AND binding_id=? AND capability_generation=?
                """,
                (
                    new_generation,
                    time.time(),
                    str(session_id),
                    str(binding_id),
                    int(expected_generation),
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = conn.execute(
                "SELECT * FROM managed_provider_sessions WHERE session_id=?",
                (str(session_id),),
            ).fetchone()
        return self._row(row)


    def qualify_driver(
        self,
        session_id: str,
        *,
        binding_id: str,
        capability_generation: int,
        provider_canary_attestation: dict | None,
        missing_canaries: Iterable[str],
        provider_attestation_required: bool,
        provider_attestation_expires_at: float | None,
    ) -> dict | None:
        required = bool(provider_attestation_required)
        expiry = (
            float(provider_attestation_expires_at)
            if provider_attestation_expires_at is not None
            else _attestation_expiry(provider_canary_attestation)
        )
        if required and (
            not isinstance(provider_canary_attestation, dict)
            or tuple(missing_canaries or ())
            or expiry is None
            or time.time() > expiry
        ):
            return None
        with self._lock, self._connect() as conn:
            updated = conn.execute(
                """
                UPDATE managed_provider_sessions
                SET lifecycle='running', turn_state='running',
                    blocked_reason=NULL, driver_available=1,
                    provider_attestation_json=?,
                    missing_canaries_json=?,
                    provider_attestation_required=?,
                    provider_attestation_expires_at=?, updated_at=?,
                    closed_at=NULL
                WHERE session_id=? AND binding_id=?
                  AND capability_generation=? AND closed_at IS NULL
                """,
                (
                    (
                        json.dumps(
                            provider_canary_attestation,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        if isinstance(provider_canary_attestation, dict)
                        else None
                    ),
                    json.dumps([
                        _bounded_text(item, 160)
                        for item in list(missing_canaries or ())[:64]
                    ], separators=(",", ":")),
                    1 if required else 0,
                    expiry,
                    time.time(),
                    str(session_id),
                    str(binding_id),
                    int(capability_generation),
                ),
            )
            if updated.rowcount != 1:
                return None
            row = conn.execute(
                "SELECT * FROM managed_provider_sessions "
                "WHERE session_id=?",
                (str(session_id),),
            ).fetchone()
        return self._row(row)

    def last_seq(self, session_id: str) -> int:
        with self._connect() as conn:
            return int(conn.execute(
                "SELECT COALESCE(MAX(seq), 0) FROM managed_provider_events WHERE session_id=?",
                (str(session_id),),
            ).fetchone()[0])

    def mark_driver_unavailable(self, session_id: str, *, reason: str,
                                stale_generation: int | None = None) -> dict | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM managed_provider_sessions WHERE session_id=?", (str(session_id),)
            ).fetchone()
            if row is None:
                return None
            reason = _bounded_text(reason or "provider driver unavailable", 500)
            conn.execute(
                """
                UPDATE managed_provider_sessions
                SET lifecycle=CASE WHEN lifecycle='closed' THEN lifecycle ELSE 'blocked' END,
                    turn_state=CASE WHEN lifecycle='closed' THEN turn_state ELSE 'blocked' END,
                    blocked_reason=CASE WHEN lifecycle='closed' THEN blocked_reason ELSE ? END,
                    driver_available=0, updated_at=?
                WHERE session_id=?
                """,
                (reason, time.time(), str(session_id)),
            )
            updated = conn.execute(
                "SELECT * FROM managed_provider_sessions WHERE session_id=?", (str(session_id),)
            ).fetchone()
            return self._row(updated)

    def mark_closed(self, session_id: str, *, reason: str | None = None) -> dict | None:
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE managed_provider_sessions
                SET lifecycle='closed', turn_state='closed', blocked_reason=?,
                    driver_available=0, updated_at=?, closed_at=?
                WHERE session_id=?
                """,
                (_bounded_text(reason, 500) or None, now, now, str(session_id)),
            )
            row = conn.execute(
                "SELECT * FROM managed_provider_sessions WHERE session_id=?", (str(session_id),)
            ).fetchone()
        return self._row(row)


class ManagedProviderSessionManager:
    """In-process driver bindings around the durable owner store.

    Driver instances are deliberately not reconstructed by launching on daemon
    restart. A driver must explicitly reconcile the persisted binding; otherwise
    the durable row becomes blocked/read-only while its history stays intact.
    """

    def __init__(
        self,
        store: ManagedProviderSessionStore,
        *,
        driver_factory: Callable[[str, str], Any],
        ambient_identity_exists: Callable[[str], bool] | None = None,
        event_publisher: Callable[[str, dict], None] | None = None,
        fork_recovery: Callable[[dict], Any] | None = None,
    ) -> None:
        self.store = store
        self._driver_factory = driver_factory
        self._ambient_identity_exists = ambient_identity_exists
        self._event_publisher = event_publisher
        self._fork_recovery = fork_recovery
        self._drivers: dict[str, Any] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _binding_field(driver: Any, key: str, default: Any = None) -> Any:
        binding = getattr(driver, "binding", None)
        if isinstance(binding, dict):
            return binding.get(key, default)
        return getattr(binding, key, default)

    def launch(
        self,
        *,
        provider: str,
        project: str,
        title: str,
        source_install_id: str,
        provider_profile_id: str,
        first_prompt: str = "",
        capabilities: Iterable[str] = ("transcript", "live_state", "provider_control"),
        binding_id: str | None = None,
        launch_action_id: str | None = None,
        launch_body_hash: str | None = None,
    ) -> dict:
        binding_id = str(binding_id or f"managed_{secrets.token_hex(16)}")
        driver = self._driver_factory(str(provider).lower(), binding_id)
        if driver is None or not callable(getattr(driver, "launch_session", None)):
            raise ManagedProviderDriverUnavailable(
                f"{provider} does not expose a reviewed structured launch driver"
            )
        provider_id = str(provider).lower()
        binding_provider = str(
            self._binding_field(driver, "provider_id", "")
        )
        provider_version = str(
            self._binding_field(driver, "provider_version", "")
        )
        provider_channel = str(
            self._binding_field(driver, "provider_channel", "")
        )
        if binding_provider != provider_id:
            raise ManagedProviderBindingStale(
                "provider launch driver has a stale provider binding"
            )
        if not provider_version:
            raise ManagedProviderVersionUnavailable(
                f"{provider} managed launch has no exact provider version"
            )
        if not provider_channel:
            raise ManagedProviderProfileStale(
                f"{provider} managed launch has no exact provider channel"
            )
        if getattr(driver, "safe_launch_profile", True) is False:
            raise ManagedProviderProfileStale(
                f"{provider} managed launch profile is not reviewed"
            )
        expected_profile = managed_provider_launch_profile(
            driver, provider_id
        )
        if str(provider_profile_id or "") != expected_profile["id"]:
            raise ManagedProviderProfileStale(
                f"{provider} managed launch profile is stale or unsupported"
            )
        try:
            attach_launch = getattr(driver, "attach_managed_launch", None)
            if callable(attach_launch):
                workspace_root = str(Path(project).expanduser().resolve(strict=True))
                session_root = str(
                    Path(self.store.db_path).parent.expanduser().resolve(strict=True)
                )
                attach_launch(
                    workspace_root=workspace_root,
                    session_root=session_root,
                    launch_identity={
                        "binding_id": binding_id,
                        "launch_action_id": launch_action_id or binding_id,
                        "source_install_id": str(source_install_id),
                    },
                )
            result = _object_dict(driver.launch_session(
                project=str(project), title=str(title), first_prompt=str(first_prompt or "")
            ))
            native_id = str(
                result.get("native_session_id") or result.get("session_id") or ""
            ).strip()
            generation = int(
                result.get("capability_generation", result.get("generation", 0))
            )
            for key, expected in (
                ("binding_id", binding_id),
                ("provider_id", provider_id),
                ("provider_version", provider_version),
                ("provider_channel", provider_channel),
            ):
                returned = result.get(key)
                if returned is not None and str(returned) != expected:
                    raise ManagedProviderBindingStale(
                        f"provider launch returned a different {key}"
                    )
            verify_launch = getattr(driver, "verify_managed_launch", None)
            if callable(verify_launch) and verify_launch(result) is not True:
                raise ManagedProviderProfileStale(
                    f"{provider} owned launch failed post-launch verification"
                )
            if not native_id:
                raise ManagedProviderDriverUnavailable(
                    f"{provider} driver did not return a native session id"
                )
            session_id = _qualified_session_id(provider_id, native_id)
            (
                attestation_required,
                attestation,
                missing_canaries,
                attestation_expiry,
            ) = _driver_launch_attestation(
                driver,
                provider=provider_id,
                provider_version=provider_version,
                provider_channel=provider_channel,
                binding_id=binding_id,
                session_id=session_id,
                capability_generation=generation,
            )
            row = self.store.register(
                provider=provider_id,
                native_id=native_id,
                binding_id=binding_id,
                capability_generation=generation,
                project=str(project),
                title=str(title),
                source_install_id=str(source_install_id),
                capabilities=capabilities,
                provider_profile_id=expected_profile["id"],
                provider_cursor=result.get("provider_cursor"),
                provider_version=provider_version,
                provider_channel=provider_channel,
                launch_action_id=launch_action_id,
                launch_body_hash=launch_body_hash,
                provider_canary_attestation=attestation,
                missing_canaries=missing_canaries,
                provider_attestation_required=attestation_required,
                provider_attestation_expires_at=attestation_expiry,
                session_instance_id=result.get("session_instance_id"),
                ambient_identity_exists=self._ambient_identity_exists,
            )
        except Exception:
            try:
                driver.close()
            except Exception:
                pass
            raise
        with self._lock:
            self._drivers[row["id"]] = driver
        self.poll(row["id"])
        return self.store.get(row["id"]) or row

    def driver(self, session_id: str) -> Any | None:
        with self._lock:
            return self._drivers.get(str(session_id))


    def prepare_fork(
        self,
        parent_session_id: str,
        client_action_id: str,
        *,
        provider_operation_id: str | None = None,
        provider_cursor: str | None = None,
    ) -> str:
        reservation = self.store.prepare_fork(
            parent_session_id,
            client_action_id,
            provider_operation_id=provider_operation_id,
            provider_cursor=provider_cursor,
        )
        return str(reservation["reservation_token"])

    def register_fork(
        self,
        parent_session_id: str,
        result: Any,
        *,
        reservation_token: str,
    ) -> dict:
        payload = _operation_result_payload(result)
        reservation = self.store.fork_reservation(reservation_token)
        if (
            reservation is None
            or reservation["parent_session_id"] != str(parent_session_id)
        ):
            raise ManagedProviderForkOutcomeUnknown(
                "fork reservation does not match its parent"
            )
        try:
            if (
                payload.get("operation_id") != "session.fork"
                or payload.get("status") != "applied"
            ):
                raise ManagedProviderForkOutcomeUnknown(
                    "provider did not prove an applied fork"
                )
            provider_operation_id = str(
                payload.get("provider_operation_id") or ""
            )
            if (
                not provider_operation_id
                or reservation.get("provider_operation_id")
                != provider_operation_id
            ):
                raise ManagedProviderForkOutcomeUnknown(
                    "provider fork correlation does not match reservation"
                )
            child_native_id = _fork_child_native_id(payload)
            child = self.store.register_fork_child(
                reservation_token=reservation_token,
                parent_session_id=parent_session_id,
                child_native_id=child_native_id,
                provider_operation_id=provider_operation_id,
                provider_cursor=payload.get("provider_cursor"),
                ambient_identity_exists=self._ambient_identity_exists,
            )
        except Exception as exc:
            self.store.mark_fork_outcome_unknown(
                reservation_token,
                reason=(
                    "provider fork child registration could not be proven: "
                    f"{type(exc).__name__}: {str(exc)[:300]}"
                ),
            )
            raise
        # The committed child is deliberately read-only. A standard exact
        # reconciliation may qualify it, but no child control is exposed first.
        self._reconcile_row(child)
        return self.store.get(child["id"]) or child

    @staticmethod
    def _reported_generation(value: Any) -> int | None:
        public = _object_dict(value)
        candidates = [public]
        for key in ("payload", "metadata"):
            nested = public.get(key)
            if isinstance(nested, dict):
                candidates.append(nested)
        for candidate in candidates:
            for key in ("capability_generation", "generation"):
                if key not in candidate or candidate[key] is None:
                    continue
                return int(candidate[key])
        return None

    def _mark_stale(self, session_id: str, reason: str) -> None:
        self.store.mark_driver_unavailable(session_id, reason=reason)
        with self._lock:
            driver = self._drivers.pop(str(session_id), None)
        close = getattr(driver, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                # The durable fail-closed state is already committed. A driver
                # close failure must not restore or retain its control binding.
                pass

    def _refresh_live_generation(
        self,
        row: dict,
        driver: Any,
        reported_generation: int,
    ) -> dict | None:
        expected_generation = int(row["capability_generation"])
        if reported_generation == expected_generation:
            return row
        if (
            getattr(driver, "generation_refresh_safe", False) is not True
            or not callable(getattr(driver, "refresh_session_binding", None))
        ):
            return None
        refreshed = _object_dict(
            driver.refresh_session_binding(self.store.session_truth(row["id"]))
        )
        if (
            str(refreshed.get("binding_id") or "") != str(row["binding_id"])
            or str(refreshed.get("session_id") or row["id"]) != str(row["id"])
            or str(refreshed.get("native_session_id") or row["native_id"])
            != str(row["native_id"])
            or refreshed.get("driver_available") is not True
            or str(refreshed.get("lifecycle") or "") != "live"
            or int(refreshed.get("capability_generation", -1))
            != int(reported_generation)
        ):
            return None
        updated = self.store.refresh_generation(
            row["id"],
            binding_id=row["binding_id"],
            expected_generation=expected_generation,
            capability_generation=reported_generation,
        )
        if updated is None:
            return None
        try:
            (
                attestation_required,
                attestation,
                missing_canaries,
                attestation_expiry,
            ) = _driver_launch_attestation(
                driver,
                provider=str(updated["provider"]),
                provider_version=str(updated["provider_version"]),
                provider_channel=str(updated["provider_channel"]),
                binding_id=str(updated["binding_id"]),
                session_id=str(updated["id"]),
                capability_generation=int(reported_generation),
            )
        except ManagedProviderDriverUnavailable:
            return None
        return self.store.qualify_driver(
            updated["id"],
            binding_id=updated["binding_id"],
            capability_generation=int(reported_generation),
            provider_canary_attestation=attestation,
            missing_canaries=missing_canaries,
            provider_attestation_required=attestation_required,
            provider_attestation_expires_at=attestation_expiry,
        )

    @staticmethod
    def _exact_event_identity(row: dict, event: Any) -> bool:
        value = _object_dict(event)
        generation = value.get("capability_generation")
        return (
            value.get("provider") == row["provider"]
            and value.get("provider_id") == row["provider"]
            and value.get("session_id") == row["native_id"]
            and value.get("native_session_id") == row["native_id"]
            and value.get("binding_id") == row["binding_id"]
            and isinstance(generation, int)
            and not isinstance(generation, bool)
            and generation == int(row["capability_generation"])
        )

    def poll(self, session_id: str) -> int:
        row = self.store.get(session_id)
        driver = self.driver(session_id)
        if row is None or driver is None:
            return 0
        if str(self._binding_field(driver, "binding_id", "")) != str(row["binding_id"]):
            self._mark_stale(session_id, "provider driver binding is stale")
            return 0
        try:
            live_generation_value = getattr(
                driver, "capability_generation", None
            )
            if callable(live_generation_value):
                live_generation_value = live_generation_value()
            if live_generation_value is not None:
                live_generation = int(live_generation_value)
                if live_generation != int(row["capability_generation"]):
                    row = self._refresh_live_generation(
                        row, driver, live_generation
                    )
                    if row is None:
                        self._mark_stale(
                            session_id,
                            "provider driver capability generation is stale",
                        )
                        return 0
            result = driver.poll_events(row.get("provider_cursor"))
        except Exception as exc:
            self._mark_stale(
                session_id,
                (
                    "provider driver unavailable: "
                    f"{type(exc).__name__}: {str(exc)[:240]}"
                ),
            )
            return 0
        result_mapping = _object_dict(result)
        if isinstance(result, dict) or "events" in result_mapping:
            events = list(result_mapping.get("events") or [])
            if "provider_cursor" in result_mapping:
                resume_cursor = result_mapping.get("provider_cursor")
            else:
                resume_cursor = result_mapping.get("cursor")
            try:
                envelope_generation = self._reported_generation(result_mapping)
            except (TypeError, ValueError):
                self._mark_stale(
                    session_id,
                    "provider event envelope capability generation is invalid",
                )
                return 0
        else:
            events = list(result or [])
            resume_cursor = None
            envelope_generation = None
        if getattr(driver, "requires_exact_event_identity", False) is True:
            if (
                isinstance(result, dict)
                and not self._exact_event_identity(row, result_mapping)
            ):
                return 0
            events = [
                event
                for event in events
                if self._exact_event_identity(row, event)
            ]
        generations: set[int] = set()
        if envelope_generation is not None:
            generations.add(envelope_generation)
        try:
            for event in events:
                generation = self._reported_generation(event)
                if generation is not None:
                    generations.add(generation)
        except (TypeError, ValueError):
            self._mark_stale(
                session_id,
                "provider event capability generation is invalid",
            )
            return 0
        if len(generations) > 1:
            self._mark_stale(
                session_id,
                "provider event batch spans multiple capability generations",
            )
            return 0
        if generations:
            reported_generation = next(iter(generations))
            if reported_generation != int(row["capability_generation"]):
                try:
                    row = self._refresh_live_generation(
                        row, driver, reported_generation
                    )
                except Exception:
                    row = None
                if row is None:
                    self._mark_stale(
                        session_id,
                        "provider event capability generation is stale",
                    )
                    return 0
        if resume_cursor is not None:
            cursor_text = _bounded_text(resume_cursor, 512)
            prepared_events = []
            for index, event in enumerate(events):
                public = _object_dict(event)
                if (
                    "cursor" not in public
                    and "provider_cursor" not in public
                ):
                    public["cursor"] = (
                        cursor_text
                        if len(events) == 1
                        else f"{cursor_text}:{index}"
                    )
                prepared_events.append(public)
            events = prepared_events
        inserted = self.store.append_driver_events(
            session_id,
            row["binding_id"],
            int(row["capability_generation"]),
            events,
            resume_cursor=resume_cursor,
        )
        if inserted and self._event_publisher is not None:
            for event in self.store.history(
                session_id,
                since_seq=max(0, self.store.last_seq(session_id) - inserted),
            ):
                self._event_publisher(session_id, event)
        return inserted

    def list_rows(self, *, provider: str = "all", live_only: bool = False,
                  active_within_min: int | None = None, limit: int = 500,
                  poll_live: bool = True) -> list[dict]:
        rows = self.store.list(
            provider=provider, live_only=live_only,
            active_within_min=active_within_min, limit=limit,
        )
        if poll_live:
            for row in rows:
                if row["driver_available"] and row["lifecycle"] in _LIVE_LIFECYCLES:
                    self.poll(row["id"])
            rows = self.store.list(
                provider=provider, live_only=live_only,
                active_within_min=active_within_min, limit=limit,
            )
        return rows

    def _reconcile_row(self, row: dict) -> bool:
        if self.driver(row["id"]) is not None:
            self.poll(row["id"])
            return bool(
                (self.store.get(row["id"]) or {}).get("control_state")
                == "controllable"
            )
        restart_blocked_reason = (
            "provider driver unavailable after daemon restart"
        )
        try:
            driver = self._driver_factory(
                row["provider"], row["binding_id"]
            )
        except Exception:
            driver = None
        reconcile = (
            getattr(driver, "reconcile_session", None)
            if driver is not None else None
        )
        if not callable(reconcile):
            self.store.mark_driver_unavailable(
                row["id"],
                reason=restart_blocked_reason,
            )
            return False
        try:
            for key, expected in (
                ("provider_id", row["provider"]),
                ("provider_version", row["provider_version"]),
                ("provider_channel", row["provider_channel"]),
                ("binding_id", row["binding_id"]),
            ):
                if str(self._binding_field(driver, key, "")) != str(expected):
                    raise ManagedProviderBindingStale(
                        f"provider driver {key} is stale"
                    )
            expected_profile = managed_provider_launch_profile(
                driver, str(row["provider"])
            )
            if row.get("provider_profile_id") != expected_profile["id"]:
                raise ManagedProviderProfileStale(
                    "provider launch profile is stale"
                )
            truth = self.store.session_truth(row["id"])
            result = _object_dict(reconcile(truth))
            actual_generation = int(
                result.get(
                    "capability_generation",
                    result.get("generation", -1),
                )
            )
            if actual_generation != int(row["capability_generation"]):
                raise ManagedProviderBindingStale(
                    "provider driver generation is stale"
                )
            if (
                str(result.get("binding_id") or row["binding_id"])
                != str(row["binding_id"])
                or str(result.get("session_id") or row["id"])
                != str(row["id"])
                or str(
                    result.get("native_session_id") or row["native_id"]
                )
                != str(row["native_id"])
                or str(
                    result.get("provider_version")
                    or row["provider_version"]
                )
                != str(row["provider_version"])
                or str(
                    result.get("provider_channel")
                    or row["provider_channel"]
                )
                != str(row["provider_channel"])
                or result.get("driver_available", True) is not True
            ):
                raise ManagedProviderBindingStale(
                    "provider driver reconciliation identity is stale"
                )
            (
                attestation_required,
                attestation,
                missing_canaries,
                attestation_expiry,
            ) = _driver_launch_attestation(
                driver,
                provider=str(row["provider"]),
                provider_version=str(row["provider_version"]),
                provider_channel=str(row["provider_channel"]),
                binding_id=str(row["binding_id"]),
                session_id=str(row["id"]),
                capability_generation=int(row["capability_generation"]),
            )
            qualified = self.store.qualify_driver(
                row["id"],
                binding_id=row["binding_id"],
                capability_generation=int(row["capability_generation"]),
                provider_canary_attestation=attestation,
                missing_canaries=missing_canaries,
                provider_attestation_required=attestation_required,
                provider_attestation_expires_at=attestation_expiry,
            )
            if qualified is None:
                raise ManagedProviderBindingStale(
                    "provider driver qualification did not commit"
                )
        except Exception as exc:
            try:
                driver.close()
            except Exception:
                pass
            self.store.mark_driver_unavailable(
                row["id"],
                reason=(
                    "provider driver unavailable after daemon restart: "
                    f"{type(exc).__name__}: {str(exc)[:200]}"
                ),
            )
            return False
        with self._lock:
            self._drivers[row["id"]] = driver
        self.poll(row["id"])
        return bool(
            (self.store.get(row["id"]) or {}).get("control_state")
            == "controllable"
        )

    def _reconcile_prepared_forks(self) -> None:
        for reservation in self.store.list_forks(
            state="prepared", limit=1000
        ):
            token = reservation["reservation_token"]
            if (
                not reservation.get("provider_operation_id")
                or self._fork_recovery is None
            ):
                self.store.mark_fork_outcome_unknown(
                    token,
                    reason=(
                        "fork recovery has no exact durable provider "
                        "correlation"
                    ),
                )
                continue
            try:
                result = self._fork_recovery(dict(reservation))
                if result is None:
                    raise ManagedProviderForkOutcomeUnknown(
                        "provider returned no exact fork recovery proof"
                    )
                self.register_fork(
                    reservation["parent_session_id"],
                    result,
                    reservation_token=token,
                )
            except Exception as exc:
                self.store.mark_fork_outcome_unknown(
                    token,
                    reason=(
                        "fork recovery could not prove child ownership: "
                        f"{type(exc).__name__}: {str(exc)[:300]}"
                    ),
                )

    def reconcile(self) -> None:
        for row in self.store.list(live_only=True, limit=1000):
            self._reconcile_row(row)
        self._reconcile_prepared_forks()

    def close(self, session_id: str, *, reason: str | None = None) -> dict | None:
        driver = self.driver(session_id)
        if driver is not None:
            # Drain the provider's final normalized events before releasing the
            # live binding. This never manufactures terminal output.
            self.poll(session_id)
            try:
                driver.close()
            except Exception as exc:
                return self.store.mark_driver_unavailable(
                    session_id,
                    reason=f"provider close failed: {type(exc).__name__}: {str(exc)[:200]}",
                )
            with self._lock:
                self._drivers.pop(str(session_id), None)
        return self.store.mark_closed(session_id, reason=reason)
