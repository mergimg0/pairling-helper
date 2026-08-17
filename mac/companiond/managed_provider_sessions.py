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
from typing import Any, Callable, Iterable, Mapping

from providers.controls import (
    OperationResultStatus,
    ProviderOperationCorrelation,
    ProviderSessionIdentity,
    execute_provider_operation,
)


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
_PROTOCOL_SESSION_ID_RE = re.compile(r"ses_[A-Za-z0-9_-]{16,128}\Z")
_PROTOCOL_ID_PATTERNS = {
    "request": re.compile(r"req_[A-Za-z0-9_-]{16,128}\Z"),
    "negotiation context": re.compile(r"neg_[A-Za-z0-9_-]{16,128}\Z"),
    "action": re.compile(r"act_[A-Za-z0-9_-]{16,128}\Z"),
    "snapshot": re.compile(r"snp_[A-Za-z0-9_-]{16,128}\Z"),
    "lease": re.compile(r"lea_[A-Za-z0-9_-]{16,128}\Z"),
    "confirmation": re.compile(r"cnf_[A-Za-z0-9_-]{16,128}\Z"),
    "recovery": re.compile(r"rec_[A-Za-z0-9_-]{16,128}\Z"),
    "event": re.compile(r"evt_[A-Za-z0-9_-]{16,128}\Z"),
}
_PROTOCOL_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PROTOCOL_ACTION_STATES = frozenset({
    "reserved",
    "dispatch_started",
    "applied",
    "rejected",
    "in_progress",
    "outcome_unknown",
})
_PROTOCOL_ACTION_TRANSITIONS = {
    "reserved": frozenset({"rejected", "dispatch_started"}),
    "dispatch_started": frozenset({
        "applied", "rejected", "in_progress", "outcome_unknown",
    }),
    "in_progress": frozenset({
        "applied", "rejected", "in_progress", "outcome_unknown",
    }),
    "outcome_unknown": frozenset({
        "applied", "rejected", "outcome_unknown",
    }),
    "applied": frozenset({"applied"}),
    "rejected": frozenset({"rejected"}),
}
_MAX_PROTOCOL_RECORD_BYTES = 2 * 1024 * 1024
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


class ManagedProviderFirstPromptOutcomeUnknown(ManagedProviderSessionError):
    code = "managed_provider_first_prompt_outcome_unknown"
    outcome_indeterminate = True

    def __init__(self, message: str, *, session_id: str):
        super().__init__(message)
        self.session_id = str(session_id)


class ManagedProviderBindingStale(ManagedProviderSessionError):
    code = "managed_session_binding_stale"


class ManagedSessionControlStateError(ManagedProviderSessionError):
    code = "managed_session_control_state_invalid"


def _qualified_session_id(provider: str, native_id: str) -> str:
    provider = str(provider or "").strip().lower()
    native_id = str(native_id or "").strip()
    if not provider or not re.fullmatch(r"[a-z0-9_]{1,48}", provider):
        raise ValueError("invalid provider id")
    if not native_id or len(native_id) > 512 or any(ch in native_id for ch in "\r\n\0"):
        raise ValueError("invalid native session id")
    return f"{provider}:{native_id}"


def _new_protocol_session_id() -> str:
    return f"ses_{secrets.token_urlsafe(24)}"


def _validate_protocol_session_id(value: Any) -> str:
    protocol_session_id = str(value or "")
    if _PROTOCOL_SESSION_ID_RE.fullmatch(protocol_session_id) is None:
        raise ManagedProviderSessionError(
            "managed protocol session identity is invalid"
        )
    return protocol_session_id


def _validate_protocol_id(kind: str, value: Any) -> str:
    identity = str(value or "")
    pattern = _PROTOCOL_ID_PATTERNS[kind]
    if pattern.fullmatch(identity) is None:
        raise ManagedSessionControlStateError(
            f"protocol {kind} identity is invalid"
        )
    return identity


def _validate_protocol_digest(value: Any) -> str:
    digest = str(value or "")
    if _PROTOCOL_DIGEST_RE.fullmatch(digest) is None:
        raise ManagedSessionControlStateError("protocol digest is invalid")
    return digest


def _protocol_text(name: str, value: Any, *, limit: int = 512) -> str:
    text = str(value or "")
    if (
        not text
        or len(text) > limit
        or any(character in text for character in "\r\n\0")
    ):
        raise ManagedSessionControlStateError(
            f"protocol {name} is invalid"
        )
    return text


def _protocol_time(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ManagedSessionControlStateError(f"protocol {name} is invalid")
    result = float(value)
    if not math.isfinite(result):
        raise ManagedSessionControlStateError(f"protocol {name} is invalid")
    return result


def _protocol_record(
    value: bytes,
    *,
    expected_digest: str | None = None,
) -> tuple[str, str]:
    if not isinstance(value, bytes) or not value:
        raise ManagedSessionControlStateError(
            "canonical protocol record must be nonempty bytes"
        )
    if len(value) > _MAX_PROTOCOL_RECORD_BYTES:
        raise ManagedSessionControlStateError(
            "canonical protocol record exceeds the persistence limit"
        )
    try:
        text = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ManagedSessionControlStateError(
            "canonical protocol record is not UTF-8"
        ) from exc
    try:
        decoded = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise ManagedSessionControlStateError(
            "canonical protocol record is not JSON"
        ) from exc
    if not isinstance(decoded, dict):
        raise ManagedSessionControlStateError(
            "canonical protocol record must be an object"
        )
    digest = f"sha256:{hashlib.sha256(value).hexdigest()}"
    if expected_digest is not None and (
        _validate_protocol_digest(expected_digest) != digest
    ):
        raise ManagedSessionControlStateError(
            "canonical protocol record digest is mismatched"
        )
    return text, digest


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
        "text", "content", "delta", "role", "name", "tool_name", "call_id", "item_id",
        "source_uuid", "message_id", "block_index", "input", "is_error",
        "status", "reason", "message", "error", "subtype",
    ):
        if key in event and key not in merged:
            merged[key] = event[key]
    return merged


def _managed_source_uuid(provider: str, value: Any) -> str:
    """Return a stable public identity without exposing the provider's value."""
    identity = _bounded_text(value, 1024).strip()
    if not identity:
        return ""
    digest = hashlib.sha256(
        f"{provider}\0{identity}".encode("utf-8", errors="replace")
    ).hexdigest()
    return f"managed:{digest}"


def _normalize_kind(event: dict, payload: dict) -> tuple[str, str | None]:
    source = str(event.get("kind") or event.get("type") or payload.get("type") or "status").strip().lower()
    if source in _PUBLIC_EVENT_KINDS:
        return source, str(payload.get("subtype") or source) if source == "lifecycle" else None
    if source in {"assistant.message", "user.message"}:
        return "block_text", None
    if source in {
        "assistant.message_delta",
        "assistant.text_delta",
        "message.delta",
    }:
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
        source = str(event.get("kind") or event.get("type") or "").strip().lower()
        if source == "message.delta":
            role = "assistant"
        else:
            source_role = source.partition(".")[0]
            if source_role in {"assistant", "user", "system"}:
                role = source_role
    if kind in {"block_text", "block_thinking", "partial_text"}:
        text = payload.get(
            "text",
            payload.get(
                "content",
                payload.get("message", payload.get("delta", "")),
            ),
        )
        public_payload["text"] = _redact_value(
            text,
            text_limit=_MAX_VISIBLE_TEXT,
        )
        if role:
            public_payload["role"] = role
        source_uuid = _managed_source_uuid(
            provider,
            payload.get("source_uuid") or payload.get("message_id"),
        )
        if source_uuid:
            public_payload["source_uuid"] = source_uuid
        block_index = payload.get("block_index")
        if (
            isinstance(block_index, int)
            and not isinstance(block_index, bool)
            and 0 <= block_index <= 1_000_000
        ):
            public_payload["block_index"] = block_index
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
    # ``cursor`` may be only an event position while ``provider_cursor`` is
    # the adapter's opaque resumable token. Persist the latter whenever the
    # adapter supplies both; feeding the position back can invalidate the
    # provider's generation or launch-identity proof.
    cursor = event.get("provider_cursor")
    if cursor is None:
        cursor = event.get("cursor")
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
                    protocol_session_id TEXT NOT NULL UNIQUE,
                    protocol_owner_id TEXT,
                    protocol_ownership_epoch INTEGER NOT NULL DEFAULT 0,
                    protocol_state TEXT,
                    protocol_state_version INTEGER NOT NULL DEFAULT 0,
                    protocol_event_stream_id TEXT,
                    protocol_last_event_sequence INTEGER NOT NULL DEFAULT -1,
                    protocol_last_event_digest TEXT,
                    protocol_terminal INTEGER NOT NULL DEFAULT 0,
                    protocol_terminal_at REAL,
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
                CREATE TABLE IF NOT EXISTS session_control_negotiations (
                    context_id TEXT PRIMARY KEY,
                    principal_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    version_major INTEGER NOT NULL,
                    version_minor INTEGER NOT NULL,
                    transport_profile TEXT NOT NULL,
                    extensions_json TEXT NOT NULL,
                    schema_digest TEXT NOT NULL,
                    runtime_revision TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    response_digest TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    last_seen_at REAL NOT NULL,
                    revoked_at REAL,
                    UNIQUE(principal_id, request_id)
                );
                CREATE INDEX IF NOT EXISTS idx_session_control_negotiations_expiry
                    ON session_control_negotiations(expires_at, revoked_at);
                CREATE TABLE IF NOT EXISTS session_control_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    protocol_session_id TEXT NOT NULL,
                    context_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    binding_digest TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    snapshot_digest TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE(protocol_session_id, generation, snapshot_digest),
                    FOREIGN KEY(protocol_session_id)
                        REFERENCES managed_provider_sessions(protocol_session_id),
                    FOREIGN KEY(context_id)
                        REFERENCES session_control_negotiations(context_id)
                );
                CREATE INDEX IF NOT EXISTS idx_session_control_snapshots_current
                    ON session_control_snapshots(
                        protocol_session_id, generation, expires_at DESC
                    );
                CREATE TABLE IF NOT EXISTS session_control_actions (
                    action_id TEXT PRIMARY KEY,
                    protocol_session_id TEXT NOT NULL,
                    context_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    binding_digest TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    implementation_operation_id TEXT NOT NULL,
                    semantic_digest TEXT NOT NULL,
                    arguments_digest TEXT NOT NULL,
                    mutation INTEGER NOT NULL,
                    request_json TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    provider_operation_id TEXT,
                    provider_cursor TEXT,
                    result_json TEXT,
                    result_digest TEXT,
                    reserved_at REAL NOT NULL,
                    dispatch_started_at REAL,
                    completed_at REAL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY(protocol_session_id)
                        REFERENCES managed_provider_sessions(protocol_session_id),
                    FOREIGN KEY(context_id)
                        REFERENCES session_control_negotiations(context_id),
                    FOREIGN KEY(snapshot_id)
                        REFERENCES session_control_snapshots(snapshot_id)
                );
                CREATE INDEX IF NOT EXISTS idx_session_control_actions_recovery
                    ON session_control_actions(
                        protocol_session_id, state, updated_at
                    );
                CREATE TABLE IF NOT EXISTS session_control_authority_keys (
                    key_id TEXT PRIMARY KEY,
                    algorithm TEXT NOT NULL,
                    public_key_format TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    hardware_backed INTEGER NOT NULL,
                    activated_at REAL NOT NULL,
                    retired_at REAL,
                    verify_until REAL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS
                    idx_session_control_authority_keys_active
                    ON session_control_authority_keys(retired_at)
                    WHERE retired_at IS NULL;
                CREATE TABLE IF NOT EXISTS session_control_leases (
                    lease_id TEXT PRIMARY KEY,
                    protocol_session_id TEXT NOT NULL,
                    context_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    binding_digest TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    lease_json TEXT NOT NULL,
                    lease_digest TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked_at REAL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(protocol_session_id)
                        REFERENCES managed_provider_sessions(protocol_session_id),
                    FOREIGN KEY(context_id)
                        REFERENCES session_control_negotiations(context_id)
                );
                CREATE INDEX IF NOT EXISTS idx_session_control_leases_active
                    ON session_control_leases(
                        protocol_session_id, scope, expires_at, revoked_at
                    );
                CREATE TABLE IF NOT EXISTS session_control_confirmations (
                    confirmation_id TEXT PRIMARY KEY,
                    protocol_session_id TEXT NOT NULL,
                    context_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    binding_digest TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    implementation_operation_id TEXT NOT NULL,
                    semantic_digest TEXT NOT NULL,
                    arguments_digest TEXT NOT NULL,
                    confirmation_json TEXT NOT NULL,
                    confirmation_digest TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked_at REAL,
                    consumed_action_id TEXT UNIQUE,
                    consumed_at REAL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(protocol_session_id)
                        REFERENCES managed_provider_sessions(protocol_session_id),
                    FOREIGN KEY(context_id)
                        REFERENCES session_control_negotiations(context_id),
                    FOREIGN KEY(snapshot_id)
                        REFERENCES session_control_snapshots(snapshot_id),
                    FOREIGN KEY(consumed_action_id)
                        REFERENCES session_control_actions(action_id)
                );
                CREATE INDEX IF NOT EXISTS idx_session_control_confirmations_live
                    ON session_control_confirmations(
                        protocol_session_id, principal_id, expires_at
                    );
                CREATE TABLE IF NOT EXISTS session_control_recovery (
                    recovery_id TEXT PRIMARY KEY,
                    action_id TEXT NOT NULL UNIQUE,
                    protocol_session_id TEXT NOT NULL,
                    context_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    strategy TEXT NOT NULL,
                    handle_json TEXT NOT NULL,
                    handle_digest TEXT NOT NULL,
                    not_before REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    state TEXT NOT NULL,
                    result_json TEXT,
                    result_digest TEXT,
                    created_at REAL NOT NULL,
                    resolved_at REAL,
                    FOREIGN KEY(action_id)
                        REFERENCES session_control_actions(action_id),
                    FOREIGN KEY(protocol_session_id)
                        REFERENCES managed_provider_sessions(protocol_session_id),
                    FOREIGN KEY(context_id)
                        REFERENCES session_control_negotiations(context_id)
                );
                CREATE INDEX IF NOT EXISTS idx_session_control_recovery_live
                    ON session_control_recovery(state, not_before, expires_at);
                CREATE TABLE IF NOT EXISTS session_control_recovery_attempts (
                    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recovery_id TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    response_json TEXT,
                    response_digest TEXT,
                    outcome TEXT,
                    started_at REAL NOT NULL,
                    completed_at REAL,
                    UNIQUE(recovery_id, request_digest),
                    FOREIGN KEY(recovery_id)
                        REFERENCES session_control_recovery(recovery_id)
                );
                CREATE TABLE IF NOT EXISTS session_control_events (
                    event_id TEXT PRIMARY KEY,
                    protocol_session_id TEXT NOT NULL,
                    action_id TEXT,
                    generation INTEGER NOT NULL,
                    stream_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    previous_event_digest TEXT,
                    event_digest TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    binding_digest TEXT NOT NULL,
                    before_state TEXT,
                    before_state_version INTEGER,
                    after_state TEXT NOT NULL,
                    after_state_version INTEGER NOT NULL,
                    terminal INTEGER NOT NULL,
                    event_json TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE(protocol_session_id, generation, sequence),
                    UNIQUE(protocol_session_id, generation, event_digest),
                    FOREIGN KEY(protocol_session_id)
                        REFERENCES managed_provider_sessions(protocol_session_id),
                    FOREIGN KEY(action_id)
                        REFERENCES session_control_actions(action_id)
                );
                CREATE INDEX IF NOT EXISTS idx_session_control_events_cursor
                    ON session_control_events(
                        protocol_session_id, generation, sequence
                    );
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
                "protocol_owner_id": "TEXT",
                "protocol_ownership_epoch": "INTEGER NOT NULL DEFAULT 0",
                "protocol_state": "TEXT",
                "protocol_state_version": "INTEGER NOT NULL DEFAULT 0",
                "protocol_event_stream_id": "TEXT",
                "protocol_last_event_sequence": "INTEGER NOT NULL DEFAULT -1",
                "protocol_last_event_digest": "TEXT",
                "protocol_terminal": "INTEGER NOT NULL DEFAULT 0",
                "protocol_terminal_at": "REAL",
            }
            for column, declaration in migrations.items():
                if column not in session_columns:
                    conn.execute(
                        "ALTER TABLE managed_provider_sessions "
                        f"ADD COLUMN {column} {declaration}"
                    )
            if "protocol_session_id" not in session_columns:
                conn.execute(
                    "ALTER TABLE managed_provider_sessions "
                    "ADD COLUMN protocol_session_id TEXT"
                )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "idx_managed_provider_sessions_protocol_identity "
                "ON managed_provider_sessions(protocol_session_id)"
            )
            protocol_identity_rows = conn.execute(
                "SELECT session_id, protocol_session_id "
                "FROM managed_provider_sessions ORDER BY session_id"
            ).fetchall()
            seen_protocol_session_ids: set[str] = set()
            for row in protocol_identity_rows:
                raw_identity = row["protocol_session_id"]
                if raw_identity is None or not str(raw_identity):
                    protocol_session_id = _new_protocol_session_id()
                    while protocol_session_id in seen_protocol_session_ids:
                        protocol_session_id = _new_protocol_session_id()
                    conn.execute(
                        "UPDATE managed_provider_sessions "
                        "SET protocol_session_id=? WHERE session_id=?",
                        (protocol_session_id, str(row["session_id"])),
                    )
                else:
                    protocol_session_id = _validate_protocol_session_id(
                        raw_identity
                    )
                if protocol_session_id in seen_protocol_session_ids:
                    raise ManagedProviderSessionError(
                        "managed protocol session identity is duplicated"
                    )
                seen_protocol_session_ids.add(protocol_session_id)
            conn.execute(
                "UPDATE managed_provider_sessions "
                "SET protocol_last_event_sequence=-1 "
                "WHERE protocol_last_event_sequence=0 "
                "AND protocol_state IS NULL "
                "AND NOT EXISTS ("
                "SELECT 1 FROM session_control_events "
                "WHERE session_control_events.protocol_session_id="
                "managed_provider_sessions.protocol_session_id"
                ")"
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
            confirmation_columns = {
                str(row["name"])
                for row in conn.execute(
                    "PRAGMA table_info(session_control_confirmations)"
                ).fetchall()
            }
            if "revoked_at" not in confirmation_columns:
                conn.execute(
                    "ALTER TABLE session_control_confirmations "
                    "ADD COLUMN revoked_at REAL"
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
    def _allocate_protocol_session_id(conn: sqlite3.Connection) -> str:
        for _attempt in range(8):
            candidate = _new_protocol_session_id()
            exists = conn.execute(
                "SELECT 1 FROM managed_provider_sessions "
                "WHERE protocol_session_id=?",
                (candidate,),
            ).fetchone()
            if exists is None:
                return candidate
        raise ManagedProviderSessionError(
            "could not allocate a unique protocol session identity"
        )

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
            protocol_session_id = self._allocate_protocol_session_id(conn)
            conn.execute(
                """
                INSERT INTO managed_provider_sessions(
                    session_id, protocol_session_id, provider, native_id,
                    binding_id,
                    capability_generation, project, title, source_install_id,
                    lifecycle, capabilities_json, provider_cursor, turn_state,
                    blocked_reason, driver_available, provider_version,
                    provider_channel, provider_profile_id,
                    session_instance_id, launch_action_id, launch_body_hash,
                    provider_attestation_json, missing_canaries_json,
                    provider_attestation_required,
                    provider_attestation_expires_at, created_at, updated_at,
                    closed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, 'running',
                          NULL, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    session_id, protocol_session_id,
                    str(provider).lower(), str(native_id), binding_id,
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

    def get_by_protocol_session_id(
        self,
        protocol_session_id: str,
    ) -> dict | None:
        identity = _validate_protocol_session_id(protocol_session_id)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM managed_provider_sessions "
                "WHERE protocol_session_id=?",
                (identity,),
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
            child_protocol_session_id = self._allocate_protocol_session_id(conn)
            try:
                conn.execute(
                    """
                    INSERT INTO managed_provider_sessions(
                        session_id, protocol_session_id, provider, native_id,
                        binding_id,
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
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'blocked', ?, ?,
                              'blocked', ?, 0, ?, ?, ?, ?, NULL, NULL, NULL,
                              ?, ?, NULL, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        child_id,
                        child_protocol_session_id,
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
            where.append("driver_available=1")
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
            "protocol_session_id": row["protocol_session_id"],
            "protocol_ownership": {
                "owner_id": row.get("protocol_owner_id"),
                "epoch": int(row.get("protocol_ownership_epoch") or 0),
            },
            "protocol_typestate": {
                "state": row.get("protocol_state"),
                "state_version": int(row.get("protocol_state_version") or 0),
                "terminal": bool(row.get("protocol_terminal")),
            },
            "protocol_cursor": {
                "stream_id": row.get("protocol_event_stream_id"),
                "sequence": int(
                    row["protocol_last_event_sequence"]
                    if row.get("protocol_last_event_sequence") is not None
                    else -1
                ),
                "previous_event_digest": row.get(
                    "protocol_last_event_digest"
                ),
            },
            "provider": row["provider"],
            "provider_id": row["provider"],
            "native_id": row["native_id"],
            "turn_state": row.get("turn_state"),
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
        provider_cursor: str | None,
    ) -> dict | None:
        """CAS a reviewed live binding's generation and resume cursor.

        The manager calls this only through a driver's explicit
        ``generation_refresh_safe`` proof seam. Historical records keep the
        generation under which they were observed, while the owner row moves
        to the exact cursor from which the new generation can resume.
        """
        new_generation = int(capability_generation)
        if new_generation < 0:
            raise ValueError("capability_generation must be non-negative")
        normalized_cursor = (
            _bounded_text(provider_cursor, 512)
            if provider_cursor is not None
            else None
        )
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE managed_provider_sessions
                SET capability_generation=?, provider_cursor=?, updated_at=?
                WHERE session_id=? AND binding_id=? AND capability_generation=?
                """,
                (
                    new_generation,
                    normalized_cursor,
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


    @staticmethod
    def _protocol_persistence_row(row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        result = dict(row)
        extensions_json = result.get("extensions_json")
        if extensions_json is not None:
            try:
                extensions = json.loads(extensions_json)
            except (TypeError, ValueError) as exc:
                raise ManagedSessionControlStateError(
                    "persisted negotiation extensions are invalid"
                ) from exc
            if not isinstance(extensions, list) or not all(
                isinstance(item, str) for item in extensions
            ):
                raise ManagedSessionControlStateError(
                    "persisted negotiation extensions are invalid"
                )
            result["extensions"] = tuple(extensions)
        return result

    @staticmethod
    def _active_protocol_negotiation_locked(
        conn: sqlite3.Connection,
        context_id: str,
        principal_id: str,
        *,
        now: float,
    ) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM session_control_negotiations WHERE context_id=?",
            (context_id,),
        ).fetchone()
        if row is None:
            raise ManagedSessionControlStateError(
                "protocol negotiation context is unknown"
            )
        if str(row["principal_id"]) != principal_id:
            raise ManagedSessionControlStateError(
                "protocol negotiation principal is mismatched"
            )
        if row["revoked_at"] is not None or now >= float(row["expires_at"]):
            raise ManagedSessionControlStateError(
                "protocol negotiation context is expired or revoked"
            )
        return row

    def create_protocol_negotiation(
        self,
        *,
        context_id: str,
        principal_id: str,
        request_id: str,
        version_major: int,
        version_minor: int,
        transport_profile: str,
        extensions: Iterable[str],
        schema_digest: str,
        runtime_revision: str,
        request_record: bytes,
        response_record: bytes,
        expires_at: float,
        now: float | None = None,
    ) -> tuple[dict, bool]:
        context = _validate_protocol_id("negotiation context", context_id)
        principal = _protocol_text("principal identity", principal_id, limit=256)
        request = _validate_protocol_id("request", request_id)
        major = int(version_major)
        minor = int(version_minor)
        if major < 0 or minor < 0:
            raise ManagedSessionControlStateError(
                "protocol negotiation version is invalid"
            )
        profile = _protocol_text(
            "transport profile",
            transport_profile,
            limit=64,
        )
        extension_values = tuple(sorted({
            _protocol_text("extension identity", item, limit=256)
            for item in extensions
        }))
        schema = _validate_protocol_digest(schema_digest)
        revision = _protocol_text(
            "runtime revision",
            runtime_revision,
            limit=256,
        )
        request_json, request_digest = _protocol_record(request_record)
        response_json, response_digest = _protocol_record(response_record)
        created_at = time.time() if now is None else _protocol_time("time", now)
        expiry = _protocol_time("negotiation expiry", expires_at)
        if expiry <= created_at:
            raise ManagedSessionControlStateError(
                "protocol negotiation expiry is not in the future"
            )
        extensions_json = json.dumps(
            extension_values,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM session_control_negotiations "
                "WHERE context_id=? OR (principal_id=? AND request_id=?)",
                (context, principal, request),
            ).fetchone()
            if existing is not None:
                expected = {
                    "context_id": context,
                    "principal_id": principal,
                    "request_id": request,
                    "version_major": major,
                    "version_minor": minor,
                    "transport_profile": profile,
                    "extensions_json": extensions_json,
                    "schema_digest": schema,
                    "runtime_revision": revision,
                    "request_digest": request_digest,
                    "response_digest": response_digest,
                    "expires_at": expiry,
                }
                if any(existing[key] != value for key, value in expected.items()):
                    raise ManagedSessionControlStateError(
                        "protocol negotiation identity is already bound"
                    )
                return self._protocol_persistence_row(existing), True
            conn.execute(
                """
                INSERT INTO session_control_negotiations(
                    context_id, principal_id, request_id,
                    version_major, version_minor, transport_profile,
                    extensions_json, schema_digest, runtime_revision,
                    request_json, request_digest, response_json,
                    response_digest, created_at, expires_at,
                    last_seen_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    context,
                    principal,
                    request,
                    major,
                    minor,
                    profile,
                    extensions_json,
                    schema,
                    revision,
                    request_json,
                    request_digest,
                    response_json,
                    response_digest,
                    created_at,
                    expiry,
                    created_at,
                ),
            )
            row = conn.execute(
                "SELECT * FROM session_control_negotiations WHERE context_id=?",
                (context,),
            ).fetchone()
        return self._protocol_persistence_row(row), False

    def protocol_negotiation(
        self,
        context_id: str,
        *,
        principal_id: str,
        now: float | None = None,
    ) -> dict:
        context = _validate_protocol_id("negotiation context", context_id)
        principal = _protocol_text("principal identity", principal_id, limit=256)
        observed_at = time.time() if now is None else _protocol_time("time", now)
        with self._lock, self._connect() as conn:
            row = self._active_protocol_negotiation_locked(
                conn,
                context,
                principal,
                now=observed_at,
            )
            conn.execute(
                "UPDATE session_control_negotiations "
                "SET last_seen_at=? WHERE context_id=?",
                (observed_at, context),
            )
        return self._protocol_persistence_row(row)

    def revoke_protocol_negotiation(
        self,
        context_id: str,
        *,
        principal_id: str,
        now: float | None = None,
    ) -> None:
        context = _validate_protocol_id("negotiation context", context_id)
        principal = _protocol_text("principal identity", principal_id, limit=256)
        revoked_at = time.time() if now is None else _protocol_time("time", now)
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT principal_id, revoked_at "
                "FROM session_control_negotiations WHERE context_id=?",
                (context,),
            ).fetchone()
            if row is None or str(row["principal_id"]) != principal:
                raise ManagedSessionControlStateError(
                    "protocol negotiation context is unknown"
                )
            if row["revoked_at"] is None:
                conn.execute(
                    "UPDATE session_control_negotiations "
                    "SET revoked_at=?, last_seen_at=? WHERE context_id=?",
                    (revoked_at, revoked_at, context),
                )

    def publish_protocol_snapshot(
        self,
        *,
        snapshot_id: str,
        protocol_session_id: str,
        context_id: str,
        principal_id: str,
        generation: int,
        binding_digest: str,
        snapshot_record: bytes,
        issued_at: float,
        expires_at: float,
        now: float | None = None,
    ) -> tuple[dict, bool]:
        snapshot = _validate_protocol_id("snapshot", snapshot_id)
        session = _validate_protocol_session_id(protocol_session_id)
        context = _validate_protocol_id("negotiation context", context_id)
        principal = _protocol_text("principal identity", principal_id, limit=256)
        capability_generation = int(generation)
        if capability_generation < 1:
            raise ManagedSessionControlStateError(
                "protocol snapshot generation is invalid"
            )
        binding = _validate_protocol_digest(binding_digest)
        snapshot_json, snapshot_digest = _protocol_record(snapshot_record)
        issued = _protocol_time("snapshot issue time", issued_at)
        expiry = _protocol_time("snapshot expiry", expires_at)
        observed_at = time.time() if now is None else _protocol_time("time", now)
        if expiry <= issued or expiry <= observed_at:
            raise ManagedSessionControlStateError(
                "protocol snapshot is already expired"
            )
        with self._lock, self._connect() as conn:
            negotiation = self._active_protocol_negotiation_locked(
                conn,
                context,
                principal,
                now=observed_at,
            )
            if expiry > float(negotiation["expires_at"]):
                raise ManagedSessionControlStateError(
                    "protocol snapshot outlives its negotiation context"
                )
            owner = conn.execute(
                "SELECT capability_generation, closed_at "
                "FROM managed_provider_sessions WHERE protocol_session_id=?",
                (session,),
            ).fetchone()
            if (
                owner is None
                or int(owner["capability_generation"]) != capability_generation
            ):
                raise ManagedSessionControlStateError(
                    "protocol snapshot session generation is stale"
                )
            existing = conn.execute(
                "SELECT * FROM session_control_snapshots "
                "WHERE snapshot_id=? OR "
                "(protocol_session_id=? AND generation=? AND snapshot_digest=?)",
                (
                    snapshot,
                    session,
                    capability_generation,
                    snapshot_digest,
                ),
            ).fetchone()
            if existing is not None:
                expected = {
                    "snapshot_id": snapshot,
                    "protocol_session_id": session,
                    "context_id": context,
                    "principal_id": principal,
                    "generation": capability_generation,
                    "binding_digest": binding,
                    "snapshot_digest": snapshot_digest,
                    "issued_at": issued,
                    "expires_at": expiry,
                }
                if any(existing[key] != value for key, value in expected.items()):
                    raise ManagedSessionControlStateError(
                        "protocol snapshot identity is already bound"
                    )
                return self._protocol_persistence_row(existing), True
            conn.execute(
                """
                INSERT INTO session_control_snapshots(
                    snapshot_id, protocol_session_id, context_id,
                    principal_id, generation, binding_digest,
                    snapshot_json, snapshot_digest, issued_at,
                    expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot,
                    session,
                    context,
                    principal,
                    capability_generation,
                    binding,
                    snapshot_json,
                    snapshot_digest,
                    issued,
                    expiry,
                    observed_at,
                ),
            )
            row = conn.execute(
                "SELECT * FROM session_control_snapshots WHERE snapshot_id=?",
                (snapshot,),
            ).fetchone()
        return self._protocol_persistence_row(row), False

    def current_protocol_snapshot(
        self,
        protocol_session_id: str,
        *,
        context_id: str,
        principal_id: str,
        now: float | None = None,
    ) -> dict | None:
        session = _validate_protocol_session_id(protocol_session_id)
        context = _validate_protocol_id("negotiation context", context_id)
        principal = _protocol_text("principal identity", principal_id, limit=256)
        observed_at = time.time() if now is None else _protocol_time("time", now)
        with self._connect() as conn:
            self._active_protocol_negotiation_locked(
                conn,
                context,
                principal,
                now=observed_at,
            )
            row = conn.execute(
                "SELECT * FROM session_control_snapshots "
                "WHERE protocol_session_id=? AND context_id=? "
                "AND principal_id=? AND expires_at>? "
                "ORDER BY generation DESC, issued_at DESC LIMIT 1",
                (session, context, principal, observed_at),
            ).fetchone()
        return self._protocol_persistence_row(row)


    def protocol_snapshot(self, snapshot_id: str) -> dict | None:
        snapshot = _validate_protocol_id("snapshot", snapshot_id)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM session_control_snapshots WHERE snapshot_id=?",
                (snapshot,),
            ).fetchone()
        return self._protocol_persistence_row(row)

    def reserve_protocol_action(
        self,
        *,
        action_id: str,
        protocol_session_id: str,
        context_id: str,
        principal_id: str,
        snapshot_id: str,
        generation: int,
        binding_digest: str,
        operation_id: str,
        implementation_operation_id: str,
        semantic_digest: str,
        arguments_digest: str,
        mutation: bool,
        request_record: bytes,
        request_digest: str | None = None,
        now: float | None = None,
    ) -> tuple[dict, bool]:
        action = _validate_protocol_id("action", action_id)
        session = _validate_protocol_session_id(protocol_session_id)
        context = _validate_protocol_id("negotiation context", context_id)
        principal = _protocol_text("principal identity", principal_id, limit=256)
        snapshot = _validate_protocol_id("snapshot", snapshot_id)
        capability_generation = int(generation)
        if capability_generation < 1 or not isinstance(mutation, bool):
            raise ManagedSessionControlStateError(
                "protocol action generation or mutation class is invalid"
            )
        binding = _validate_protocol_digest(binding_digest)
        operation = _protocol_text("operation identity", operation_id, limit=128)
        implementation = _protocol_text(
            "implementation operation identity",
            implementation_operation_id,
            limit=256,
        )
        semantic = _validate_protocol_digest(semantic_digest)
        arguments = _validate_protocol_digest(arguments_digest)
        request_json, calculated_request_digest = _protocol_record(
            request_record,
            expected_digest=request_digest,
        )
        reserved_at = time.time() if now is None else _protocol_time("time", now)
        with self._lock, self._connect() as conn:
            self._active_protocol_negotiation_locked(
                conn,
                context,
                principal,
                now=reserved_at,
            )
            snapshot_row = conn.execute(
                "SELECT * FROM session_control_snapshots WHERE snapshot_id=?",
                (snapshot,),
            ).fetchone()
            if (
                snapshot_row is None
                or str(snapshot_row["protocol_session_id"]) != session
                or str(snapshot_row["context_id"]) != context
                or str(snapshot_row["principal_id"]) != principal
                or int(snapshot_row["generation"]) != capability_generation
                or str(snapshot_row["binding_digest"]) != binding
                or reserved_at >= float(snapshot_row["expires_at"])
            ):
                raise ManagedSessionControlStateError(
                    "protocol action snapshot authority is stale"
                )
            owner = conn.execute(
                "SELECT capability_generation, closed_at "
                "FROM managed_provider_sessions WHERE protocol_session_id=?",
                (session,),
            ).fetchone()
            if (
                owner is None
                or owner["closed_at"] is not None
                or int(owner["capability_generation"]) != capability_generation
            ):
                raise ManagedSessionControlStateError(
                    "protocol action session authority is stale"
                )
            existing = conn.execute(
                "SELECT * FROM session_control_actions WHERE action_id=?",
                (action,),
            ).fetchone()
            if existing is not None:
                expected = {
                    "protocol_session_id": session,
                    "context_id": context,
                    "principal_id": principal,
                    "snapshot_id": snapshot,
                    "generation": capability_generation,
                    "binding_digest": binding,
                    "operation_id": operation,
                    "implementation_operation_id": implementation,
                    "semantic_digest": semantic,
                    "arguments_digest": arguments,
                    "mutation": 1 if mutation else 0,
                    "request_digest": calculated_request_digest,
                }
                if any(existing[key] != value for key, value in expected.items()):
                    raise ManagedSessionControlStateError(
                        "protocol action identity is already bound"
                    )
                return self._protocol_persistence_row(existing), True
            conn.execute(
                """
                INSERT INTO session_control_actions(
                    action_id, protocol_session_id, context_id,
                    principal_id, snapshot_id, generation,
                    binding_digest, operation_id,
                    implementation_operation_id, semantic_digest,
                    arguments_digest, mutation, request_json,
                    request_digest, state, provider_operation_id,
                    provider_cursor, result_json, result_digest,
                    reserved_at, dispatch_started_at, completed_at,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved',
                          NULL, NULL, NULL, NULL, ?, NULL, NULL, ?)
                """,
                (
                    action,
                    session,
                    context,
                    principal,
                    snapshot,
                    capability_generation,
                    binding,
                    operation,
                    implementation,
                    semantic,
                    arguments,
                    1 if mutation else 0,
                    request_json,
                    calculated_request_digest,
                    reserved_at,
                    reserved_at,
                ),
            )
            row = conn.execute(
                "SELECT * FROM session_control_actions WHERE action_id=?",
                (action,),
            ).fetchone()
        return self._protocol_persistence_row(row), False

    def protocol_action(self, action_id: str) -> dict | None:
        action = _validate_protocol_id("action", action_id)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM session_control_actions WHERE action_id=?",
                (action,),
            ).fetchone()
        return self._protocol_persistence_row(row)

    def mark_protocol_action_dispatch_started(
        self,
        action_id: str,
        *,
        provider_operation_id: str | None,
        provider_cursor: str | None,
        now: float | None = None,
    ) -> dict:
        action = _validate_protocol_id("action", action_id)
        provider_operation = (
            _protocol_text(
                "provider operation identity",
                provider_operation_id,
                limit=512,
            )
            if provider_operation_id is not None
            else None
        )
        cursor = (
            _protocol_text("provider cursor", provider_cursor, limit=512)
            if provider_cursor is not None
            else None
        )
        started_at = time.time() if now is None else _protocol_time("time", now)
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM session_control_actions WHERE action_id=?",
                (action,),
            ).fetchone()
            if row is None:
                raise ManagedSessionControlStateError(
                    "protocol action identity is unknown"
                )
            state = str(row["state"])
            if state == "dispatch_started":
                if (
                    row["provider_operation_id"] != provider_operation
                    or row["provider_cursor"] != cursor
                ):
                    raise ManagedSessionControlStateError(
                        "protocol dispatch identity is already bound"
                    )
                return self._protocol_persistence_row(row)
            if state != "reserved":
                raise ManagedSessionControlStateError(
                    "protocol action is not reservable for dispatch"
                )
            updated = conn.execute(
                "UPDATE session_control_actions "
                "SET state='dispatch_started', provider_operation_id=?, "
                "provider_cursor=?, dispatch_started_at=?, updated_at=? "
                "WHERE action_id=? AND state='reserved'",
                (
                    provider_operation,
                    cursor,
                    started_at,
                    started_at,
                    action,
                ),
            )
            if updated.rowcount != 1:
                raise ManagedSessionControlStateError(
                    "protocol action changed during dispatch reservation"
                )
            row = conn.execute(
                "SELECT * FROM session_control_actions WHERE action_id=?",
                (action,),
            ).fetchone()
        return self._protocol_persistence_row(row)

    def complete_protocol_action(
        self,
        action_id: str,
        *,
        state: str,
        result_record: bytes,
        result_digest: str | None = None,
        now: float | None = None,
    ) -> tuple[dict, bool]:
        action = _validate_protocol_id("action", action_id)
        target_state = str(state or "")
        if target_state not in _PROTOCOL_ACTION_STATES - {
            "reserved",
            "dispatch_started",
        }:
            raise ManagedSessionControlStateError(
                "protocol action result state is invalid"
            )
        result_json, calculated_result_digest = _protocol_record(
            result_record,
            expected_digest=result_digest,
        )
        completed_at = time.time() if now is None else _protocol_time("time", now)
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM session_control_actions WHERE action_id=?",
                (action,),
            ).fetchone()
            if row is None:
                raise ManagedSessionControlStateError(
                    "protocol action identity is unknown"
                )
            current_state = str(row["state"])
            if (
                current_state == target_state
                and row["result_digest"] == calculated_result_digest
            ):
                return self._protocol_persistence_row(row), True
            if target_state not in _PROTOCOL_ACTION_TRANSITIONS.get(
                current_state,
                frozenset(),
            ):
                raise ManagedSessionControlStateError(
                    "protocol action state transition is invalid"
                )
            terminal_at = (
                completed_at
                if target_state in {"applied", "rejected"}
                else None
            )
            updated = conn.execute(
                "UPDATE session_control_actions "
                "SET state=?, result_json=?, result_digest=?, "
                "completed_at=?, updated_at=? "
                "WHERE action_id=? AND state=?",
                (
                    target_state,
                    result_json,
                    calculated_result_digest,
                    terminal_at,
                    completed_at,
                    action,
                    current_state,
                ),
            )
            if updated.rowcount != 1:
                raise ManagedSessionControlStateError(
                    "protocol action changed during result persistence"
                )
            row = conn.execute(
                "SELECT * FROM session_control_actions WHERE action_id=?",
                (action,),
            ).fetchone()
        return self._protocol_persistence_row(row), False

    def interrupted_protocol_actions(
        self,
        *,
        limit: int = 1000,
    ) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM session_control_actions "
                "WHERE state='dispatch_started' "
                "ORDER BY dispatch_started_at, action_id LIMIT ?",
                (max(1, min(int(limit), 1000)),),
            ).fetchall()
        return [
            self._protocol_persistence_row(row)
            for row in rows
        ]

    def issue_protocol_lease(
        self,
        *,
        lease_id: str,
        protocol_session_id: str,
        context_id: str,
        principal_id: str,
        scope: str,
        generation: int,
        binding_digest: str,
        epoch: int,
        lease_record: bytes,
        issued_at: float,
        expires_at: float,
        now: float | None = None,
    ) -> tuple[dict, bool]:
        lease = _validate_protocol_id("lease", lease_id)
        session = _validate_protocol_session_id(protocol_session_id)
        context = _validate_protocol_id("negotiation context", context_id)
        principal = _protocol_text("principal identity", principal_id, limit=256)
        lease_scope = str(scope or "")
        if lease_scope not in {"input", "mutation", "approval"}:
            raise ManagedSessionControlStateError(
                "protocol lease scope is invalid"
            )
        capability_generation = int(generation)
        ownership_epoch = int(epoch)
        if capability_generation < 1 or ownership_epoch < 1:
            raise ManagedSessionControlStateError(
                "protocol lease generation or epoch is invalid"
            )
        binding = _validate_protocol_digest(binding_digest)
        lease_json, lease_digest = _protocol_record(lease_record)
        issued = _protocol_time("lease issue time", issued_at)
        expiry = _protocol_time("lease expiry", expires_at)
        observed_at = time.time() if now is None else _protocol_time("time", now)
        if issued > observed_at or expiry <= observed_at:
            raise ManagedSessionControlStateError(
                "protocol lease is not currently valid"
            )
        with self._lock, self._connect() as conn:
            negotiation = self._active_protocol_negotiation_locked(
                conn,
                context,
                principal,
                now=observed_at,
            )
            if expiry > float(negotiation["expires_at"]):
                raise ManagedSessionControlStateError(
                    "protocol lease outlives its negotiation context"
                )
            owner = conn.execute(
                "SELECT capability_generation, protocol_ownership_epoch, "
                "protocol_terminal FROM managed_provider_sessions "
                "WHERE protocol_session_id=?",
                (session,),
            ).fetchone()
            if (
                owner is None
                or int(owner["capability_generation"]) != capability_generation
                or int(owner["protocol_ownership_epoch"]) != ownership_epoch
                or bool(owner["protocol_terminal"])
            ):
                raise ManagedSessionControlStateError(
                    "protocol lease session authority is stale"
                )
            existing = conn.execute(
                "SELECT * FROM session_control_leases WHERE lease_id=?",
                (lease,),
            ).fetchone()
            if existing is not None:
                expected = {
                    "protocol_session_id": session,
                    "context_id": context,
                    "principal_id": principal,
                    "scope": lease_scope,
                    "generation": capability_generation,
                    "binding_digest": binding,
                    "epoch": ownership_epoch,
                    "lease_digest": lease_digest,
                    "issued_at": issued,
                    "expires_at": expiry,
                }
                if any(existing[key] != value for key, value in expected.items()):
                    raise ManagedSessionControlStateError(
                        "protocol lease identity is already bound"
                    )
                return self._protocol_persistence_row(existing), True
            conflict = conn.execute(
                "SELECT lease_id FROM session_control_leases "
                "WHERE protocol_session_id=? AND scope=? "
                "AND revoked_at IS NULL AND expires_at>?",
                (session, lease_scope, observed_at),
            ).fetchone()
            if conflict is not None:
                raise ManagedSessionControlStateError(
                    "protocol lease scope already has an active holder"
                )
            conn.execute(
                """
                INSERT INTO session_control_leases(
                    lease_id, protocol_session_id, context_id,
                    principal_id, scope, generation, binding_digest,
                    epoch, lease_json, lease_digest, issued_at,
                    expires_at, revoked_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
                """,
                (
                    lease,
                    session,
                    context,
                    principal,
                    lease_scope,
                    capability_generation,
                    binding,
                    ownership_epoch,
                    lease_json,
                    lease_digest,
                    issued,
                    expiry,
                    observed_at,
                ),
            )
            row = conn.execute(
                "SELECT * FROM session_control_leases WHERE lease_id=?",
                (lease,),
            ).fetchone()
        return self._protocol_persistence_row(row), False

    def active_protocol_leases(
        self,
        protocol_session_id: str,
        *,
        principal_id: str | None = None,
        now: float | None = None,
    ) -> list[dict]:
        session = _validate_protocol_session_id(protocol_session_id)
        observed_at = time.time() if now is None else _protocol_time("time", now)
        parameters: list[Any] = [session, observed_at]
        principal_clause = ""
        if principal_id is not None:
            principal_clause = " AND principal_id=?"
            parameters.append(
                _protocol_text("principal identity", principal_id, limit=256)
            )
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM session_control_leases "
                "WHERE protocol_session_id=? AND revoked_at IS NULL "
                "AND expires_at>?" + principal_clause + " ORDER BY scope, lease_id",
                parameters,
            ).fetchall()
        return [self._protocol_persistence_row(row) for row in rows]

    def revoke_protocol_lease(
        self,
        lease_id: str,
        *,
        principal_id: str,
        now: float | None = None,
    ) -> None:
        lease = _validate_protocol_id("lease", lease_id)
        principal = _protocol_text("principal identity", principal_id, limit=256)
        revoked_at = time.time() if now is None else _protocol_time("time", now)
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT principal_id, revoked_at FROM session_control_leases "
                "WHERE lease_id=?",
                (lease,),
            ).fetchone()
            if row is None or str(row["principal_id"]) != principal:
                raise ManagedSessionControlStateError(
                    "protocol lease identity is unknown"
                )
            if row["revoked_at"] is None:
                conn.execute(
                    "UPDATE session_control_leases SET revoked_at=? "
                    "WHERE lease_id=?",
                    (revoked_at, lease),
                )

    def issue_protocol_confirmation(
        self,
        *,
        confirmation_id: str,
        protocol_session_id: str,
        context_id: str,
        principal_id: str,
        snapshot_id: str,
        generation: int,
        binding_digest: str,
        operation_id: str,
        implementation_operation_id: str,
        semantic_digest: str,
        arguments_digest: str,
        confirmation_record: bytes,
        issued_at: float,
        expires_at: float,
        now: float | None = None,
    ) -> tuple[dict, bool]:
        confirmation = _validate_protocol_id("confirmation", confirmation_id)
        session = _validate_protocol_session_id(protocol_session_id)
        context = _validate_protocol_id("negotiation context", context_id)
        principal = _protocol_text("principal identity", principal_id, limit=256)
        snapshot = _validate_protocol_id("snapshot", snapshot_id)
        capability_generation = int(generation)
        if capability_generation < 1:
            raise ManagedSessionControlStateError(
                "protocol confirmation generation is invalid"
            )
        binding = _validate_protocol_digest(binding_digest)
        operation = _protocol_text("operation identity", operation_id, limit=128)
        implementation = _protocol_text(
            "implementation operation identity",
            implementation_operation_id,
            limit=256,
        )
        semantic = _validate_protocol_digest(semantic_digest)
        arguments = _validate_protocol_digest(arguments_digest)
        confirmation_json, confirmation_digest = _protocol_record(
            confirmation_record
        )
        issued = _protocol_time("confirmation issue time", issued_at)
        expiry = _protocol_time("confirmation expiry", expires_at)
        observed_at = time.time() if now is None else _protocol_time("time", now)
        if issued > observed_at or expiry <= observed_at:
            raise ManagedSessionControlStateError(
                "protocol confirmation is not currently valid"
            )
        with self._lock, self._connect() as conn:
            negotiation = self._active_protocol_negotiation_locked(
                conn,
                context,
                principal,
                now=observed_at,
            )
            snapshot_row = conn.execute(
                "SELECT * FROM session_control_snapshots WHERE snapshot_id=?",
                (snapshot,),
            ).fetchone()
            if (
                snapshot_row is None
                or str(snapshot_row["protocol_session_id"]) != session
                or str(snapshot_row["context_id"]) != context
                or str(snapshot_row["principal_id"]) != principal
                or int(snapshot_row["generation"]) != capability_generation
                or str(snapshot_row["binding_digest"]) != binding
                or expiry > float(snapshot_row["expires_at"])
                or expiry > float(negotiation["expires_at"])
            ):
                raise ManagedSessionControlStateError(
                    "protocol confirmation snapshot authority is stale"
                )
            existing = conn.execute(
                "SELECT * FROM session_control_confirmations "
                "WHERE confirmation_id=?",
                (confirmation,),
            ).fetchone()
            if existing is not None:
                expected = {
                    "protocol_session_id": session,
                    "context_id": context,
                    "principal_id": principal,
                    "snapshot_id": snapshot,
                    "generation": capability_generation,
                    "binding_digest": binding,
                    "operation_id": operation,
                    "implementation_operation_id": implementation,
                    "semantic_digest": semantic,
                    "arguments_digest": arguments,
                    "confirmation_digest": confirmation_digest,
                    "issued_at": issued,
                    "expires_at": expiry,
                }
                if any(existing[key] != value for key, value in expected.items()):
                    raise ManagedSessionControlStateError(
                        "protocol confirmation identity is already bound"
                    )
                return self._protocol_persistence_row(existing), True
            conn.execute(
                """
                INSERT INTO session_control_confirmations(
                    confirmation_id, protocol_session_id, context_id,
                    principal_id, snapshot_id, generation,
                    binding_digest, operation_id,
                    implementation_operation_id, semantic_digest,
                    arguments_digest, confirmation_json,
                    confirmation_digest, issued_at, expires_at,
                    revoked_at, consumed_action_id, consumed_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          NULL, NULL, NULL, ?)
                """,
                (
                    confirmation,
                    session,
                    context,
                    principal,
                    snapshot,
                    capability_generation,
                    binding,
                    operation,
                    implementation,
                    semantic,
                    arguments,
                    confirmation_json,
                    confirmation_digest,
                    issued,
                    expiry,
                    observed_at,
                ),
            )
            row = conn.execute(
                "SELECT * FROM session_control_confirmations "
                "WHERE confirmation_id=?",
                (confirmation,),
            ).fetchone()
        return self._protocol_persistence_row(row), False

    def consume_protocol_confirmation(
        self,
        confirmation_id: str,
        *,
        action_id: str,
        principal_id: str,
        now: float | None = None,
    ) -> dict:
        confirmation = _validate_protocol_id("confirmation", confirmation_id)
        action = _validate_protocol_id("action", action_id)
        principal = _protocol_text("principal identity", principal_id, limit=256)
        consumed_at = time.time() if now is None else _protocol_time("time", now)
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM session_control_confirmations "
                "WHERE confirmation_id=?",
                (confirmation,),
            ).fetchone()
            action_row = conn.execute(
                "SELECT * FROM session_control_actions WHERE action_id=?",
                (action,),
            ).fetchone()
            if row is None or action_row is None:
                raise ManagedSessionControlStateError(
                    "protocol confirmation or action is unknown"
                )
            identity_fields = (
                "protocol_session_id",
                "context_id",
                "principal_id",
                "snapshot_id",
                "generation",
                "binding_digest",
                "operation_id",
                "implementation_operation_id",
                "semantic_digest",
                "arguments_digest",
            )
            if (
                principal != str(row["principal_id"])
                or row["revoked_at"] is not None
                or consumed_at >= float(row["expires_at"])
                or str(action_row["state"]) != "reserved"
                or any(row[field] != action_row[field] for field in identity_fields)
            ):
                raise ManagedSessionControlStateError(
                    "protocol confirmation does not authorize this action"
                )
            prior_action = row["consumed_action_id"]
            if prior_action is not None:
                if str(prior_action) != action:
                    raise ManagedSessionControlStateError(
                        "protocol confirmation was already consumed"
                    )
                return self._protocol_persistence_row(row)
            conn.execute(
                "UPDATE session_control_confirmations "
                "SET consumed_action_id=?, consumed_at=? "
                "WHERE confirmation_id=? AND consumed_action_id IS NULL",
                (action, consumed_at, confirmation),
            )
            row = conn.execute(
                "SELECT * FROM session_control_confirmations "
                "WHERE confirmation_id=?",
                (confirmation,),
            ).fetchone()
        return self._protocol_persistence_row(row)

    def issue_protocol_recovery(
        self,
        *,
        recovery_id: str,
        action_id: str,
        context_id: str,
        principal_id: str,
        strategy: str,
        handle_record: bytes,
        not_before: float,
        expires_at: float,
        now: float | None = None,
    ) -> tuple[dict, bool]:
        recovery = _validate_protocol_id("recovery", recovery_id)
        action = _validate_protocol_id("action", action_id)
        context = _validate_protocol_id("negotiation context", context_id)
        principal = _protocol_text("principal identity", principal_id, limit=256)
        recovery_strategy = str(strategy or "")
        if recovery_strategy not in {
            "provider_status",
            "provider_event",
            "manager_receipt",
            "process_observation",
            "unavailable",
        }:
            raise ManagedSessionControlStateError(
                "protocol recovery strategy is invalid"
            )
        handle_json, handle_digest = _protocol_record(handle_record)
        available_at = _protocol_time("recovery not-before", not_before)
        expiry = _protocol_time("recovery expiry", expires_at)
        created_at = time.time() if now is None else _protocol_time("time", now)
        if expiry <= available_at or expiry <= created_at:
            raise ManagedSessionControlStateError(
                "protocol recovery window is invalid"
            )
        with self._lock, self._connect() as conn:
            self._active_protocol_negotiation_locked(
                conn,
                context,
                principal,
                now=created_at,
            )
            action_row = conn.execute(
                "SELECT * FROM session_control_actions WHERE action_id=?",
                (action,),
            ).fetchone()
            if (
                action_row is None
                or str(action_row["principal_id"]) != principal
                or str(action_row["state"])
                not in {"in_progress", "outcome_unknown"}
            ):
                raise ManagedSessionControlStateError(
                    "protocol recovery action is not recoverable"
                )
            existing = conn.execute(
                "SELECT * FROM session_control_recovery "
                "WHERE recovery_id=? OR action_id=?",
                (recovery, action),
            ).fetchone()
            if existing is not None:
                expected = {
                    "recovery_id": recovery,
                    "action_id": action,
                    "protocol_session_id": action_row["protocol_session_id"],
                    "principal_id": principal,
                    "strategy": recovery_strategy,
                    "handle_digest": handle_digest,
                    "not_before": available_at,
                    "expires_at": expiry,
                }
                if any(existing[key] != value for key, value in expected.items()):
                    raise ManagedSessionControlStateError(
                        "protocol recovery identity is already bound"
                    )
                return self._protocol_persistence_row(existing), True
            conn.execute(
                """
                INSERT INTO session_control_recovery(
                    recovery_id, action_id, protocol_session_id,
                    context_id, principal_id, strategy, handle_json,
                    handle_digest, not_before, expires_at, state,
                    result_json, result_digest, created_at, resolved_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending',
                          NULL, NULL, ?, NULL)
                """,
                (
                    recovery,
                    action,
                    action_row["protocol_session_id"],
                    context,
                    principal,
                    recovery_strategy,
                    handle_json,
                    handle_digest,
                    available_at,
                    expiry,
                    created_at,
                ),
            )
            row = conn.execute(
                "SELECT * FROM session_control_recovery WHERE recovery_id=?",
                (recovery,),
            ).fetchone()
        return self._protocol_persistence_row(row), False

    def protocol_recovery(self, recovery_id: str) -> dict | None:
        recovery = _validate_protocol_id("recovery", recovery_id)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM session_control_recovery WHERE recovery_id=?",
                (recovery,),
            ).fetchone()
        return self._protocol_persistence_row(row)

    def begin_protocol_recovery_attempt(
        self,
        recovery_id: str,
        *,
        context_id: str,
        principal_id: str,
        request_record: bytes,
        now: float | None = None,
    ) -> tuple[dict, bool]:

        recovery = _validate_protocol_id("recovery", recovery_id)
        context = _validate_protocol_id("negotiation context", context_id)
        principal = _protocol_text("principal identity", principal_id, limit=256)
        request_json, request_digest = _protocol_record(request_record)
        started_at = time.time() if now is None else _protocol_time("time", now)
        with self._lock, self._connect() as conn:
            self._active_protocol_negotiation_locked(
                conn,
                context,
                principal,
                now=started_at,
            )
            handle = conn.execute(
                "SELECT * FROM session_control_recovery WHERE recovery_id=?",
                (recovery,),
            ).fetchone()
            if (
                handle is None
                or str(handle["principal_id"]) != principal
                or started_at < float(handle["not_before"])
                or started_at >= float(handle["expires_at"])
            ):
                raise ManagedSessionControlStateError(
                    "protocol recovery handle is unavailable"
                )
            existing = conn.execute(
                "SELECT * FROM session_control_recovery_attempts "
                "WHERE recovery_id=? AND request_digest=?",
                (recovery, request_digest),
            ).fetchone()
            if existing is not None:
                return self._protocol_persistence_row(existing), True
            if str(handle["state"]) != "pending":
                raise ManagedSessionControlStateError(
                    "protocol recovery handle is unavailable"
                )
            conn.execute(
                """
                INSERT INTO session_control_recovery_attempts(
                    recovery_id, request_json, request_digest,
                    response_json, response_digest, outcome,
                    started_at, completed_at
                ) VALUES (?, ?, ?, NULL, NULL, NULL, ?, NULL)
                """,
                (recovery, request_json, request_digest, started_at),
            )
            row = conn.execute(
                "SELECT * FROM session_control_recovery_attempts "
                "WHERE recovery_id=? AND request_digest=?",
                (recovery, request_digest),
            ).fetchone()
        return self._protocol_persistence_row(row), False

    def complete_protocol_recovery_attempt(
        self,
        attempt_id: int,
        *,
        outcome: str,
        response_record: bytes,
        now: float | None = None,
    ) -> tuple[dict, bool]:
        attempt = int(attempt_id)
        recovery_outcome = str(outcome or "")
        if recovery_outcome not in {
            "applied",
            "rejected",
            "in_progress",
            "outcome_unknown",
        }:
            raise ManagedSessionControlStateError(
                "protocol recovery outcome is invalid"
            )
        response_json, response_digest = _protocol_record(response_record)
        completed_at = time.time() if now is None else _protocol_time("time", now)
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM session_control_recovery_attempts "
                "WHERE attempt_id=?",
                (attempt,),
            ).fetchone()
            if row is None:
                raise ManagedSessionControlStateError(
                    "protocol recovery attempt is unknown"
                )
            if row["completed_at"] is not None:
                if (
                    str(row["outcome"]) != recovery_outcome
                    or str(row["response_digest"]) != response_digest
                ):
                    raise ManagedSessionControlStateError(
                        "protocol recovery attempt is already resolved"
                    )
                return self._protocol_persistence_row(row), True
            conn.execute(
                "UPDATE session_control_recovery_attempts "
                "SET response_json=?, response_digest=?, outcome=?, "
                "completed_at=? WHERE attempt_id=? AND completed_at IS NULL",
                (
                    response_json,
                    response_digest,
                    recovery_outcome,
                    completed_at,
                    attempt,
                ),
            )
            if recovery_outcome in {"applied", "rejected"}:
                conn.execute(
                    "UPDATE session_control_recovery "
                    "SET state='resolved', result_json=?, result_digest=?, "
                    "resolved_at=? WHERE recovery_id=? AND state='pending'",
                    (
                        response_json,
                        response_digest,
                        completed_at,
                        row["recovery_id"],
                    ),
                )
            row = conn.execute(
                "SELECT * FROM session_control_recovery_attempts "
                "WHERE attempt_id=?",
                (attempt,),
            ).fetchone()
        return self._protocol_persistence_row(row), False

    def append_protocol_event(
        self,
        *,
        event_id: str,
        protocol_session_id: str,
        generation: int,
        stream_id: str,
        sequence: int,
        previous_event_digest: str | None,
        event_type: str,
        binding_digest: str,
        before_state: str | None,
        before_state_version: int | None,
        after_state: str,
        after_state_version: int,
        terminal: bool,
        event_record: bytes,
        observed_at: float,
        action_id: str | None = None,
        owner_id: str | None = None,
        ownership_epoch: int | None = None,
        complete_action_state: str | None = None,
        complete_action_record: bytes | None = None,
        now: float | None = None,
    ) -> tuple[dict, bool]:
        event = _validate_protocol_id("event", event_id)
        session = _validate_protocol_session_id(protocol_session_id)
        capability_generation = int(generation)
        event_sequence = int(sequence)
        if capability_generation < 1 or event_sequence < 0:
            raise ManagedSessionControlStateError(
                "protocol event generation or sequence is invalid"
            )
        stream = _protocol_text("event stream identity", stream_id, limit=256)
        predecessor = (
            _validate_protocol_digest(previous_event_digest)
            if previous_event_digest is not None
            else None
        )
        event_kind = _protocol_text("event type", event_type, limit=64)
        binding = _validate_protocol_digest(binding_digest)
        prior_state = (
            _protocol_text("event prior state", before_state, limit=64)
            if before_state is not None
            else None
        )
        prior_version = (
            int(before_state_version)
            if before_state_version is not None
            else None
        )
        next_state = _protocol_text("event resulting state", after_state, limit=64)
        next_version = int(after_state_version)
        if (
            next_version < 1
            or not isinstance(terminal, bool)
            or terminal != (next_state == "terminated")
        ):
            raise ManagedSessionControlStateError(
                "protocol event resulting typestate is invalid"
            )
        event_json, event_digest = _protocol_record(event_record)
        event_observed_at = _protocol_time("event observation time", observed_at)
        created_at = time.time() if now is None else _protocol_time("time", now)
        correlated_action = (
            _validate_protocol_id("action", action_id)
            if action_id is not None
            else None
        )
        owner = (
            _protocol_text("owner identity", owner_id, limit=256)
            if owner_id is not None
            else None
        )
        epoch = int(ownership_epoch) if ownership_epoch is not None else None
        completion_state = (
            str(complete_action_state)
            if complete_action_state is not None
            else None
        )
        if (completion_state is None) != (complete_action_record is None):
            raise ManagedSessionControlStateError(
                "protocol event action completion is incomplete"
            )
        completion_json = None
        completion_digest = None
        if completion_state is not None:
            if (
                correlated_action is None
                or completion_state
                not in _PROTOCOL_ACTION_STATES - {
                    "reserved",
                    "dispatch_started",
                }
            ):
                raise ManagedSessionControlStateError(
                    "protocol event action completion is invalid"
                )
            completion_json, completion_digest = _protocol_record(
                complete_action_record
            )
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM session_control_events WHERE event_id=?",
                (event,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["protocol_session_id"]) != session
                    or int(existing["generation"]) != capability_generation
                    or int(existing["sequence"]) != event_sequence
                    or str(existing["event_digest"]) != event_digest
                ):
                    raise ManagedSessionControlStateError(
                        "protocol event identity is already bound"
                    )
                return self._protocol_persistence_row(existing), True
            session_row = conn.execute(
                "SELECT * FROM managed_provider_sessions "
                "WHERE protocol_session_id=?",
                (session,),
            ).fetchone()
            if (
                session_row is None
                or int(session_row["capability_generation"])
                != capability_generation
                or bool(session_row["protocol_terminal"])
            ):
                raise ManagedSessionControlStateError(
                    "protocol event session authority is stale or terminal"
                )
            current_sequence = int(
                session_row["protocol_last_event_sequence"]
                if session_row["protocol_last_event_sequence"] is not None
                else -1
            )
            current_digest = session_row["protocol_last_event_digest"]
            current_state = session_row["protocol_state"]
            current_version = int(session_row["protocol_state_version"] or 0)
            current_stream = session_row["protocol_event_stream_id"]
            if (
                event_sequence != current_sequence + 1
                or predecessor != current_digest
                or (current_stream is not None and str(current_stream) != stream)
            ):
                raise ManagedSessionControlStateError(
                    "protocol event cursor has a gap or wrong predecessor"
                )
            if current_state is None:
                if prior_state is not None or prior_version is not None:
                    raise ManagedSessionControlStateError(
                        "first protocol event has a nonempty prior state"
                    )
            elif (
                prior_state != str(current_state)
                or prior_version != current_version
            ):
                raise ManagedSessionControlStateError(
                    "protocol event prior typestate is stale"
                )
            if next_version != current_version + 1:
                raise ManagedSessionControlStateError(
                    "protocol event state version is not contiguous"
                )
            action_row = None
            if correlated_action is not None:
                action_row = conn.execute(
                    "SELECT * FROM session_control_actions "
                    "WHERE action_id=?",
                    (correlated_action,),
                ).fetchone()
                if (
                    action_row is None
                    or str(action_row["protocol_session_id"]) != session
                ):
                    raise ManagedSessionControlStateError(
                        "protocol event action correlation is invalid"
                    )
            if completion_state is not None:
                current_action_state = str(action_row["state"])
                if completion_state not in _PROTOCOL_ACTION_TRANSITIONS.get(
                    current_action_state,
                    frozenset(),
                ):
                    raise ManagedSessionControlStateError(
                        "protocol event action state transition is invalid"
                    )
            current_epoch = int(
                session_row["protocol_ownership_epoch"] or 0
            )
            next_owner = session_row["protocol_owner_id"]
            next_epoch = current_epoch
            if event_kind == "ownership.acquired":
                if owner is None or epoch is None or epoch <= current_epoch:
                    raise ManagedSessionControlStateError(
                        "protocol ownership acquisition is invalid"
                    )
                next_owner = owner
                next_epoch = epoch
            elif event_kind == "ownership.lost":
                if owner is not None or epoch != current_epoch:
                    raise ManagedSessionControlStateError(
                        "protocol ownership loss is invalid"
                    )
                next_owner = None
            elif owner is not None or epoch is not None:
                raise ManagedSessionControlStateError(
                    "protocol ownership fields are unexpected"
                )
            conn.execute(
                """
                INSERT INTO session_control_events(
                    event_id, protocol_session_id, action_id,
                    generation, stream_id, sequence,
                    previous_event_digest, event_digest, event_type,
                    binding_digest, before_state, before_state_version,
                    after_state, after_state_version, terminal,
                    event_json, observed_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event,
                    session,
                    correlated_action,
                    capability_generation,
                    stream,
                    event_sequence,
                    predecessor,
                    event_digest,
                    event_kind,
                    binding,
                    prior_state,
                    prior_version,
                    next_state,
                    next_version,
                    1 if terminal else 0,
                    event_json,
                    event_observed_at,
                    created_at,
                ),
            )
            updated = conn.execute(
                "UPDATE managed_provider_sessions "
                "SET protocol_owner_id=?, protocol_ownership_epoch=?, "
                "protocol_state=?, protocol_state_version=?, "
                "protocol_event_stream_id=?, "
                "protocol_last_event_sequence=?, "
                "protocol_last_event_digest=?, protocol_terminal=?, "
                "protocol_terminal_at=? WHERE protocol_session_id=? "
                "AND protocol_last_event_sequence=? AND protocol_terminal=0",
                (
                    next_owner,
                    next_epoch,
                    next_state,
                    next_version,
                    stream,
                    event_sequence,
                    event_digest,
                    1 if terminal else 0,
                    created_at if terminal else None,
                    session,
                    current_sequence,
                ),
            )
            if updated.rowcount != 1:
                raise ManagedSessionControlStateError(
                    "protocol typestate changed during event persistence"
                )
            if completion_state is not None:
                terminal_at = (
                    created_at
                    if completion_state in {"applied", "rejected"}
                    else None
                )
                completed = conn.execute(
                    "UPDATE session_control_actions "
                    "SET state=?, result_json=?, result_digest=?, "
                    "completed_at=?, updated_at=? "
                    "WHERE action_id=? AND state=?",
                    (
                        completion_state,
                        completion_json,
                        completion_digest,
                        terminal_at,
                        created_at,
                        correlated_action,
                        current_action_state,
                    ),
                )
                if completed.rowcount != 1:
                    raise ManagedSessionControlStateError(
                        "protocol action changed during event persistence"
                    )
            if terminal:
                conn.execute(
                    "UPDATE session_control_leases SET revoked_at=? "
                    "WHERE protocol_session_id=? AND revoked_at IS NULL",
                    (created_at, session),
                )
                conn.execute(
                    "UPDATE session_control_confirmations SET revoked_at=? "
                    "WHERE protocol_session_id=? AND revoked_at IS NULL "
                    "AND consumed_action_id IS NULL",
                    (created_at, session),
                )
            row = conn.execute(
                "SELECT * FROM session_control_events WHERE event_id=?",
                (event,),
            ).fetchone()
        return self._protocol_persistence_row(row), False

    def protocol_events(
        self,
        protocol_session_id: str,
        *,
        generation: int,
        after_sequence: int,
        predecessor_digest: str | None,
        limit: int = 500,
    ) -> list[dict]:
        session = _validate_protocol_session_id(protocol_session_id)
        capability_generation = int(generation)
        sequence = int(after_sequence)
        if capability_generation < 1 or sequence < -1:
            raise ManagedSessionControlStateError(
                "protocol event cursor is invalid"
            )
        predecessor = (
            _validate_protocol_digest(predecessor_digest)
            if predecessor_digest is not None
            else None
        )
        with self._connect() as conn:
            if sequence == -1:
                if predecessor is not None:
                    raise ManagedSessionControlStateError(
                        "initial protocol event cursor has a predecessor"
                    )
            else:
                prior = conn.execute(
                    "SELECT event_digest FROM session_control_events "
                    "WHERE protocol_session_id=? AND generation=? "
                    "AND sequence=?",
                    (session, capability_generation, sequence),
                ).fetchone()
                if prior is None or str(prior["event_digest"]) != predecessor:
                    raise ManagedSessionControlStateError(
                        "protocol event cursor predecessor is unknown"
                    )
            rows = conn.execute(
                "SELECT * FROM session_control_events "
                "WHERE protocol_session_id=? AND generation=? "
                "AND sequence>? ORDER BY sequence LIMIT ?",
                (
                    session,
                    capability_generation,
                    sequence,
                    max(1, min(int(limit), 1000)),
                ),
            ).fetchall()
        return [self._protocol_persistence_row(row) for row in rows]

    def protocol_typestate(self, protocol_session_id: str) -> dict:
        session = _validate_protocol_session_id(protocol_session_id)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT protocol_owner_id, protocol_ownership_epoch, "
                "protocol_state, protocol_state_version, "
                "protocol_event_stream_id, protocol_last_event_sequence, "
                "protocol_last_event_digest, protocol_terminal, "
                "protocol_terminal_at FROM managed_provider_sessions "
                "WHERE protocol_session_id=?",
                (session,),
            ).fetchone()
        if row is None:
            raise ManagedSessionControlStateError(
                "protocol session identity is unknown"
            )
        return dict(row)

    def register_protocol_authority_key(
        self,
        record: Mapping[str, Any],
        *,
        now: float | None = None,
    ) -> tuple[dict, bool]:
        if not isinstance(record, Mapping) or set(record) != {
            "key_id",
            "algorithm",
            "public_key_format",
            "public_key",
            "hardware_backed",
        }:
            raise ManagedSessionControlStateError(
                "protocol authority key record is invalid"
            )
        key_id = _protocol_text("authority key identity", record["key_id"], limit=256)
        algorithm = _protocol_text(
            "authority key algorithm",
            record["algorithm"],
            limit=64,
        )
        public_key_format = _protocol_text(
            "authority public-key format",
            record["public_key_format"],
            limit=64,
        )
        public_key = _protocol_text(
            "authority public key",
            record["public_key"],
            limit=512,
        )
        hardware_backed = record["hardware_backed"]
        if (
            not isinstance(hardware_backed, bool)
            or algorithm != "p256-sha256"
            or public_key_format != "x963-base64url"
            or not key_id.startswith("pairling.control_authority.")
        ):
            raise ManagedSessionControlStateError(
                "protocol authority key record is unsupported"
            )
        activated_at = time.time() if now is None else _protocol_time("time", now)
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM session_control_authority_keys WHERE key_id=?",
                (key_id,),
            ).fetchone()
            if existing is not None:
                expected = {
                    "algorithm": algorithm,
                    "public_key_format": public_key_format,
                    "public_key": public_key,
                    "hardware_backed": 1 if hardware_backed else 0,
                }
                if (
                    existing["retired_at"] is not None
                    or any(existing[key] != value for key, value in expected.items())
                ):
                    raise ManagedSessionControlStateError(
                        "protocol authority key identity is already bound"
                    )
                return dict(existing), True
            active = conn.execute(
                "SELECT key_id FROM session_control_authority_keys "
                "WHERE retired_at IS NULL"
            ).fetchone()
            if active is not None:
                raise ManagedSessionControlStateError(
                    "protocol authority key continuity would change"
                )
            conn.execute(
                """
                INSERT INTO session_control_authority_keys(
                    key_id, algorithm, public_key_format, public_key,
                    hardware_backed, activated_at, retired_at, verify_until
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                (
                    key_id,
                    algorithm,
                    public_key_format,
                    public_key,
                    1 if hardware_backed else 0,
                    activated_at,
                ),
            )
            row = conn.execute(
                "SELECT * FROM session_control_authority_keys WHERE key_id=?",
                (key_id,),
            ).fetchone()
        return dict(row), False

    def current_protocol_authority_key(self) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM session_control_authority_keys "
                "WHERE retired_at IS NULL"
            ).fetchone()
        return dict(row) if row is not None else None

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
        before_first_prompt: Callable[[dict[str, Any]], None] | None = None,
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
        prompt = str(first_prompt or "")
        deferred_prompt = bool(
            prompt
            and getattr(
                driver,
                "requires_post_registration_first_prompt",
                False,
            )
            is True
        )
        if deferred_prompt and (
            not launch_action_id
            or not callable(before_first_prompt)
            or not callable(
                getattr(
                    driver,
                    "arm_operation_dispatch_boundary",
                    None,
                )
            )
        ):
            raise ManagedProviderDriverUnavailable(
                f"{provider} managed first prompt has no durable dispatch boundary"
            )

        row: dict | None = None
        attached = False
        prompt_boundary_crossed = False
        prompt_rejected = False
        try:
            attach_launch = getattr(driver, "attach_managed_launch", None)
            if callable(attach_launch):
                workspace_root = str(
                    Path(project).expanduser().resolve(strict=True)
                )
                session_root = str(
                    Path(self.store.db_path).parent.expanduser().resolve(
                        strict=True
                    )
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
            result = _object_dict(
                driver.launch_session(
                    project=str(project),
                    title=str(title),
                    first_prompt="" if deferred_prompt else prompt,
                )
            )
            native_id = str(
                result.get("native_session_id")
                or result.get("session_id")
                or ""
            ).strip()
            generation = int(
                result.get(
                    "capability_generation",
                    result.get("generation", 0),
                )
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
            if deferred_prompt:
                with self._lock:
                    self._drivers[row["id"]] = driver
                attached = True
                truth = self.store.session_truth(row["id"])
                if not isinstance(truth, dict):
                    raise ManagedProviderDriverUnavailable(
                        f"{provider} managed session truth is unavailable"
                    )
                identity = ProviderSessionIdentity(
                    provider_id=provider_id,
                    session_id=row["id"],
                    binding_id=binding_id,
                    capability_generation=generation,
                )
                correlate = getattr(driver, "operation_correlation", None)
                if not callable(correlate):
                    raise ManagedProviderDriverUnavailable(
                        f"{provider} managed first prompt correlation is unavailable"
                    )
                correlation = correlate(
                    operation_id="session.prompt.send",
                    client_action_id=str(launch_action_id),
                    capability_generation=generation,
                    session_id=row["id"],
                    session_truth=truth,
                )
                if not isinstance(
                    correlation,
                    ProviderOperationCorrelation,
                ):
                    raise ManagedProviderDriverUnavailable(
                        f"{provider} managed first prompt correlation is invalid"
                    )

                def commit_prompt_boundary() -> None:
                    nonlocal prompt_boundary_crossed
                    before_first_prompt({
                        "provider_id": provider_id,
                        "provider_version": provider_version,
                        "provider_channel": provider_channel,
                        "operation_id": "session.prompt.send",
                        "binding_id": binding_id,
                        "capability_generation": generation,
                        "provider_operation_id":
                            correlation.provider_operation_id,
                        "provider_cursor": correlation.provider_cursor,
                        "session_id": row["id"],
                    })
                    prompt_boundary_crossed = True

                driver.arm_operation_dispatch_boundary(
                    operation_id="session.prompt.send",
                    client_action_id=str(launch_action_id),
                    session_id=row["id"],
                    provider_correlation=correlation,
                    before_write=commit_prompt_boundary,
                )
                prompt_result = execute_provider_operation(
                    driver,
                    operation_id="session.prompt.send",
                    input_payload={
                        "session": identity.to_payload(),
                        "prompt": prompt,
                    },
                    binding_id=binding_id,
                    capability_generation=generation,
                    session_id=row["id"],
                    session_truth=truth,
                    client_action_id=str(launch_action_id),
                    prepared_attachments=(),
                    provider_correlation=correlation,
                )
                if prompt_result.status is not OperationResultStatus.APPLIED:
                    prompt_rejected = True
                    raise ManagedProviderDriverUnavailable(
                        f"{provider} rejected the managed first prompt"
                    )
        except Exception as exc:
            if row is not None and attached:
                if prompt_boundary_crossed and not prompt_rejected:
                    try:
                        self.store.mark_driver_unavailable(
                            row["id"],
                            reason=(
                                "managed first prompt outcome is unknown; "
                                "inspect provider state before sending again"
                            ),
                        )
                    except Exception:
                        pass
                    raise ManagedProviderFirstPromptOutcomeUnknown(
                        (
                            f"{provider} could not prove whether the managed "
                            "first prompt started"
                        ),
                        session_id=row["id"],
                    ) from exc
                with self._lock:
                    self._drivers.pop(row["id"], None)
                try:
                    self.store.mark_closed(
                        row["id"],
                        reason="managed first prompt was not accepted",
                    )
                except Exception:
                    pass
            try:
                driver.close()
            except Exception:
                pass
            raise
        if not attached:
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
        refreshed_generation = refreshed.get("capability_generation")
        live_generation = getattr(driver, "capability_generation", None)
        if callable(live_generation):
            live_generation = live_generation()
        if (
            isinstance(refreshed_generation, bool)
            or not isinstance(refreshed_generation, int)
            or isinstance(live_generation, bool)
        ):
            return None
        try:
            live_generation = int(live_generation)
        except (TypeError, ValueError):
            return None
        if (
            str(refreshed.get("binding_id") or "") != str(row["binding_id"])
            or str(refreshed.get("session_id") or row["id"]) != str(row["id"])
            or str(refreshed.get("native_session_id") or row["native_id"])
            != str(row["native_id"])
            or refreshed.get("driver_available") is not True
            or str(refreshed.get("lifecycle") or "") != "live"
            or refreshed_generation <= expected_generation
            or refreshed_generation < int(reported_generation)
            or live_generation != refreshed_generation
        ):
            return None
        generation_resume_cursor = refreshed.get(
            "generation_resume_cursor",
            row.get("provider_cursor"),
        )
        if (
            generation_resume_cursor is not None
            and not isinstance(generation_resume_cursor, str)
        ):
            return None
        updated = self.store.refresh_generation(
            row["id"],
            binding_id=row["binding_id"],
            expected_generation=expected_generation,
            capability_generation=refreshed_generation,
            provider_cursor=generation_resume_cursor,
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
                capability_generation=refreshed_generation,
            )
        except ManagedProviderDriverUnavailable:
            return None
        return self.store.qualify_driver(
            updated["id"],
            binding_id=updated["binding_id"],
            capability_generation=refreshed_generation,
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
