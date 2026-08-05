from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from . import registry_data
from .base import (
    ProviderAdapter,
    ProviderAvailability,
    ProviderDescriptor,
    ProviderDiagnostics,
    ProviderProbeResult,
    managed_child_environment,
    cli_version,
    resolve_executable,
)
from ._sidecar_process import close_owned_process
from .controls import (
    ControlChoice,
    ControlChoices,
    OperationResultStatus,
    ProviderControlBinding,
    ProviderControlSnapshot,
    ProviderOperationResult,
    ProviderOperationCorrelation,
    ProviderSessionIdentity,
    ControlValue,
)


_SUPPORTED_SDK_PACKAGE = "@github/copilot-sdk"
_SUPPORTED_SDK_VERSION = "1.0.8"
_SUPPORTED_CLI_VERSION = "1.0.78"
_SUPPORTED_CLI_CHANNEL = "stable"
_SUPPORTED_SDK_PROTOCOL = 3
_SIDECAR_PROTOCOL = 1
_MAX_LINE_BYTES = 1024 * 1024
_MAX_EVENT_COUNT = 512
_MAX_ATTACHMENT_COUNT = 8
_MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024
_MAX_ATTACHMENTS_BYTES = 8 * 1024 * 1024
_MAX_TEXT_BYTES = 64 * 1024

_ALLOWED_SIDECAR_OPERATIONS = frozenset(
    {
        "handshake",
        "discover",
        "create_session",
        "resume_session",
        "events",
        "send",
        "steer",
        "abort",
        "set_model",
        "approval_decide",
        "read_usage",
        "read_mcp",
        "read_diagnostics",
    }
)
_SECRET_KEY_PARTS = (
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "github_token",
    "password",
    "private_key",
    "refresh_token",
    "secret",
)

_FALLBACK_DESCRIPTOR = ProviderDescriptor(
    provider_id="copilot",
    display_name="GitHub Copilot CLI",
    kind="terminal_cli",
    builtin=True,
    docs_url="https://docs.github.com/en/copilot/how-tos/copilot-sdk",
    adapter_depth="standard",
)
_ENTRY = registry_data.entry_or_none("copilot")


class CopilotSDKError(RuntimeError):
    pass


class CopilotSDKUnavailable(CopilotSDKError):
    pass


class CopilotSDKPackageUnavailable(CopilotSDKUnavailable):
    pass


class CopilotSidecarEOF(CopilotSDKUnavailable):
    pass


class CopilotSidecarTimeout(CopilotSDKUnavailable):
    pass


class CopilotSidecarProtocolError(CopilotSDKUnavailable):
    pass


class CopilotSidecarRPCError(CopilotSDKError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"Copilot SDK sidecar error {code}: {_redact_error_text(message)}")


class CopilotUnsupportedOperation(CopilotSDKError):
    pass


class CopilotApprovalCorrelationError(CopilotSDKError):
    pass


class CopilotStaleBinding(CopilotSDKError):
    pass


@dataclass(frozen=True)
class ResolvedCopilotSDKPackage:
    root: Path
    entrypoint: Path
    version: str


@dataclass
class _PendingResponse:
    completed: threading.Event
    result: Any = None
    error: BaseException | None = None


@dataclass(frozen=True)
class _PendingApproval:
    request_id: str
    session_id: str
    tool_call_id: str | None
    permission_kind: str
    title: str
    session_approval_available: bool
    received_generation: int
    received_at: float


def _bounded_text(value: Any, limit: int = _MAX_TEXT_BYTES) -> str:
    text = value if isinstance(value, str) else str(value)
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= limit:
        return text
    return raw[:limit].decode("utf-8", errors="ignore") + "…"


def _redact_error_text(value: Any) -> str:
    text = _bounded_text(value, 512)
    text = re.sub(
        r"(?i)\b(bearer)\s+[a-z0-9._~+/=-]+",
        r"\1 [redacted]",
        text,
    )
    return re.sub(
        r"(?i)\b(token|secret|password|authorization|cookie|api[_-]?key|credential)"
        r"(\s*[:=]\s*)([^\s,;]+)",
        r"\1\2[redacted]",
        text,
    )


def _safe_identifier(value: Any, limit: int = 512) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value if len(value.encode("utf-8", errors="replace")) <= limit else None


def _version_from_output(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"(?:^|[/\s])v?(\d+\.\d+\.\d+)(?=[\s.]|$)", value.strip())
    return match.group(1) if match else None


def is_compatible_copilot_cli_version(value: str | None) -> bool:
    return _version_from_output(value) == _SUPPORTED_CLI_VERSION


def _sdk_export_entrypoint(root: Path, manifest: Mapping[str, Any]) -> Path | None:
    exports = manifest.get("exports")
    candidate: Any = exports.get(".") if isinstance(exports, Mapping) else None
    if isinstance(candidate, Mapping):
        candidate = candidate.get("import", candidate.get("default"))
    if isinstance(candidate, Mapping):
        candidate = candidate.get("default")
    if not isinstance(candidate, str) or not candidate:
        main = manifest.get("module") or manifest.get("main")
        candidate = main if isinstance(main, str) else None
    if not candidate:
        return None
    entrypoint = (root / candidate).resolve()
    try:
        entrypoint.relative_to(root.resolve())
    except ValueError:
        return None
    return entrypoint if entrypoint.is_file() else None


def resolve_copilot_sdk_package(candidates: Iterable[Path | str]) -> ResolvedCopilotSDKPackage:
    failures: list[str] = []
    seen: set[str] = set()
    for raw_candidate in candidates:
        root = Path(raw_candidate).expanduser()
        if str(root) in seen:
            continue
        seen.add(str(root))
        manifest_path = root / "package.json"
        if not manifest_path.is_file():
            failures.append(f"{root}: package.json missing")
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            failures.append(f"{root}: package.json unreadable")
            continue
        if not isinstance(manifest, Mapping) or manifest.get("name") != _SUPPORTED_SDK_PACKAGE:
            failures.append(f"{root}: package identity mismatch")
            continue
        version = manifest.get("version")
        if version != _SUPPORTED_SDK_VERSION:
            failures.append(f"{root}: SDK version {version!r} is not reviewed")
            continue
        entrypoint = _sdk_export_entrypoint(root, manifest)
        if entrypoint is None:
            failures.append(f"{root}: stable import entrypoint missing")
            continue
        return ResolvedCopilotSDKPackage(root.resolve(), entrypoint, version)
    detail = "; ".join(failures[:4]) or "no SDK package candidates"
    raise CopilotSDKPackageUnavailable(
        f"official {_SUPPORTED_SDK_PACKAGE}@{_SUPPORTED_SDK_VERSION} could not be resolved: {detail}"
    )


def _redact(value: Any, *, key: str = "", depth: int = 0) -> Any:
    lowered = key.casefold().replace("-", "_")
    if key and any(part in lowered for part in _SECRET_KEY_PARTS):
        return "[redacted]"
    if depth > 8:
        return "[truncated]"
    if isinstance(value, Mapping):
        return {
            _bounded_text(child_key, 128): _redact(child_value, key=str(child_key), depth=depth + 1)
            for child_key, child_value in list(value.items())[:128]
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item, depth=depth + 1) for item in list(value)[:256]]
    if isinstance(value, str):
        return _bounded_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _bounded_text(value)


def _safe_public_result(value: Any) -> dict[str, Any]:
    redacted = _redact(value)
    return redacted if isinstance(redacted, dict) else {}




class _CopilotSDKSidecarProcess:
    """Owns one fixed local Node sidecar and its correlated request/event state."""

    def __init__(
        self,
        *,
        argv: Sequence[str],
        env: Mapping[str, str] | None = None,
        request_timeout: float = 15.0,
        provider_settings: Mapping[str, str] | None = None,
        handshake_timeout: float = 10.0,
        expected_cli_version: str = _SUPPORTED_CLI_VERSION,
        max_line_bytes: int = _MAX_LINE_BYTES,
    ):
        if not argv or any(not isinstance(part, str) or not part for part in argv):
            raise ValueError("Copilot SDK sidecar argv must contain non-empty strings")
        if request_timeout <= 0 or handshake_timeout <= 0:
            raise ValueError("Copilot SDK sidecar timeouts must be positive")
        if expected_cli_version != _SUPPORTED_CLI_VERSION:
            raise CopilotSDKUnavailable("Copilot CLI version has not been reviewed")
        self._argv = tuple(argv)
        self._env = managed_child_environment(
            source=env,
            provider_settings=provider_settings,
        )
        self._request_timeout = request_timeout
        self._handshake_timeout = handshake_timeout
        self._expected_cli_version = expected_cli_version
        self._max_line_bytes = max_line_bytes
        self._state_lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._start_lock = threading.Lock()
        self._process: subprocess.Popen[bytes] | None = None
        self._reader: threading.Thread | None = None
        self._pending: dict[str, _PendingResponse] = {}
        self._approvals: dict[str, _PendingApproval] = {}
        self._events: deque[dict[str, Any]] = deque(maxlen=_MAX_EVENT_COUNT)
        self._next_request_id = 0
        self._generation = 0
        self._cursor = 0
        self._handshake: dict[str, Any] | None = None

    @property
    def capability_generation(self) -> int:
        with self._state_lock:
            return self._generation

    @property
    def provider_cursor(self) -> int:
        with self._state_lock:
            return self._cursor

    @property
    def is_available(self) -> bool:
        with self._state_lock:
            return self._process is not None and self._handshake is not None

    def start(self) -> None:
        with self._start_lock:
            with self._state_lock:
                if self._process is not None and self._handshake is not None:
                    return
                if self._process is not None:
                    raise CopilotSDKUnavailable("Copilot SDK sidecar is still starting")
                try:
                    process = subprocess.Popen(
                        self._argv,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        env=self._env,
                        start_new_session=True,
                    )
                except OSError as exc:
                    raise CopilotSDKUnavailable(f"failed to start Copilot SDK sidecar: {exc}") from exc
                if process.stdin is None or process.stdout is None:
                    close_owned_process(process, process_group=True)
                    raise CopilotSDKUnavailable("Copilot SDK sidecar did not expose stdio")
                self._process = process
                self._generation += 1
                reader = threading.Thread(
                    target=self._reader_loop,
                    args=(process,),
                    name="pairling-copilot-sdk-reader",
                    daemon=True,
                )
                self._reader = reader
                try:
                    reader.start()
                except BaseException:
                    self._process = None
                    self._reader = None
                    close_owned_process(process, process_group=True)
                    raise
            try:
                handshake = self._request_started(
                    "handshake",
                    {
                        "sidecar_protocol": _SIDECAR_PROTOCOL,
                        "expected_sdk_package": _SUPPORTED_SDK_PACKAGE,
                        "expected_sdk_version": _SUPPORTED_SDK_VERSION,
                        "expected_cli_version": self._expected_cli_version,
                        "expected_cli_channel": _SUPPORTED_CLI_CHANNEL,
                        "expected_sdk_protocol": _SUPPORTED_SDK_PROTOCOL,
                    },
                    timeout=self._handshake_timeout,
                )
                self._validate_handshake(handshake)
                with self._state_lock:
                    self._handshake = dict(handshake)
            except BaseException:
                self._invalidate(CopilotSDKUnavailable("Copilot SDK handshake failed"), process)
                raise

    def _validate_handshake(self, handshake: Any) -> None:
        if not isinstance(handshake, Mapping):
            raise CopilotSidecarProtocolError("Copilot SDK handshake is not an object")
        expected = {
            "sidecar_protocol": _SIDECAR_PROTOCOL,
            "sdk_package": _SUPPORTED_SDK_PACKAGE,
            "sdk_version": _SUPPORTED_SDK_VERSION,
            "cli_version": self._expected_cli_version,
            "cli_channel": _SUPPORTED_CLI_CHANNEL,
            "sdk_protocol_version": _SUPPORTED_SDK_PROTOCOL,
            "transport": "stdio-jsonrpc",
        }
        for key, value in expected.items():
            if handshake.get(key) != value:
                raise CopilotSidecarProtocolError(
                    f"Copilot SDK handshake {key} mismatch: {handshake.get(key)!r}"
                )

    def request(self, operation: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if operation not in _ALLOWED_SIDECAR_OPERATIONS:
            raise CopilotUnsupportedOperation(f"unreviewed Copilot SDK sidecar operation: {operation}")
        self.start()
        return self._request_started(operation, payload, timeout=self._request_timeout)

    def _request_started(self, operation: str, payload: Mapping[str, Any], *, timeout: float) -> dict[str, Any]:
        if operation not in _ALLOWED_SIDECAR_OPERATIONS:
            raise CopilotUnsupportedOperation(f"unreviewed Copilot SDK sidecar operation: {operation}")
        if not isinstance(payload, Mapping):
            raise CopilotSidecarProtocolError("Copilot SDK request payload must be an object")
        with self._state_lock:
            process = self._process
            if process is None or process.stdin is None:
                raise CopilotSDKUnavailable("Copilot SDK sidecar is not running")
            self._next_request_id += 1
            request_id = f"pairling-{self._next_request_id}"
            pending = _PendingResponse(threading.Event())
            self._pending[request_id] = pending
        message = {"id": request_id, "op": operation, **dict(payload)}
        try:
            encoded = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
        except (TypeError, ValueError) as exc:
            with self._state_lock:
                self._pending.pop(request_id, None)
            raise CopilotSidecarProtocolError("Copilot SDK request is not safe JSON") from exc
        if len(encoded) > self._max_line_bytes:
            with self._state_lock:
                self._pending.pop(request_id, None)
            raise CopilotSidecarProtocolError("Copilot SDK request exceeds the sidecar bound")
        try:
            with self._write_lock:
                process.stdin.write(encoded)
                process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            self._invalidate(CopilotSidecarEOF("Copilot SDK sidecar input closed"), process)
            raise CopilotSidecarEOF("Copilot SDK sidecar input closed") from exc
        if not pending.completed.wait(timeout):
            error = CopilotSidecarTimeout(f"Copilot SDK sidecar {operation} timed out")
            self._invalidate(error, process)
            raise error
        if pending.error is not None:
            raise pending.error
        if not isinstance(pending.result, Mapping):
            raise CopilotSidecarProtocolError("Copilot SDK sidecar result is not an object")
        return dict(pending.result)

    def create_session(
        self,
        *,
        working_directory: str,
        model: str | None = None,
        correlation: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"working_directory": working_directory}
        if model is not None:
            payload["model"] = model
        if correlation:
            payload.update(correlation)
        return self.request("create_session", payload)

    def resume_session(
        self,
        *,
        native_session_id: str,
        working_directory: str,
        correlation: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "native_session_id": native_session_id,
            "working_directory": working_directory,
        }
        if correlation:
            payload.update(correlation)
        return self.request("resume_session", payload)

    def discover(
        self,
        *,
        native_session_id: str | None,
        working_directory: str | None,
        binding_id: str,
        capability_generation: int,
        pairling_session_id: str | None,
    ) -> dict[str, Any]:
        return self.request(
            "discover",
            {
                "native_session_id": native_session_id,
                "working_directory": working_directory,
                "binding_id": binding_id,
                "capability_generation": capability_generation,
                "pairling_session_id": pairling_session_id,
            },
        )

    def poll_events(self, after_cursor: int | str | None = 0) -> list[dict[str, Any]]:
        try:
            cursor = 0 if after_cursor is None else int(after_cursor)
        except (TypeError, ValueError) as exc:
            raise CopilotSidecarProtocolError("Copilot SDK event cursor is invalid") from exc
        if isinstance(after_cursor, bool) or cursor < 0:
            raise CopilotSidecarProtocolError("Copilot SDK event cursor is invalid")
        with self._state_lock:
            return [dict(event) for event in self._events if event["cursor"] > cursor]

    def _rebind_approvals_unlocked(self) -> None:
        self._approvals = {
            request_id: _PendingApproval(
                item.request_id,
                item.session_id,
                item.tool_call_id,
                item.permission_kind,
                item.title,
                item.session_approval_available,
                self._generation,
                item.received_at,
            )
            for request_id, item in self._approvals.items()
        }

    def pending_approvals(self, *, session_id: str | None = None) -> tuple[_PendingApproval, ...]:
        with self._state_lock:
            approvals = tuple(self._approvals.values())
        if session_id is None:
            return approvals
        return tuple(item for item in approvals if item.session_id == session_id)

    def respond_approval(
        self,
        *,
        request_id: str,
        session_id: str,
        decision: str,
        correlation: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if decision not in {"once", "session", "deny"}:
            raise CopilotApprovalCorrelationError("approval decision is not reviewed")
        with self._state_lock:
            pending = self._approvals.get(request_id)
            if pending is None or pending.session_id != session_id:
                raise CopilotApprovalCorrelationError("approval request is missing or belongs to another session")
            if pending.received_generation != self._generation:
                raise CopilotApprovalCorrelationError("approval request belongs to a stale sidecar generation")
            del self._approvals[request_id]
            self._generation += 1
            self._rebind_approvals_unlocked()
        result = self.request(
            "approval_decide",
            {
                "request_id": pending.request_id,
                "session_id": pending.session_id,
                "tool_call_id": pending.tool_call_id,
                "permission_kind": pending.permission_kind,
                "decision": decision,
                **dict(correlation or {}),
            },
        )
        return result

    def _reader_loop(self, process: subprocess.Popen[bytes]) -> None:
        stdout = process.stdout
        if stdout is None:
            self._invalidate(CopilotSidecarEOF("Copilot SDK sidecar has no output"), process)
            return
        try:
            while True:
                line = stdout.readline(self._max_line_bytes + 1)
                if not line:
                    raise CopilotSidecarEOF("Copilot SDK sidecar exited")
                if len(line) > self._max_line_bytes or not line.endswith(b"\n"):
                    raise CopilotSidecarProtocolError("Copilot SDK sidecar response line exceeds bound")
                try:
                    message = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise CopilotSidecarProtocolError("Copilot SDK sidecar emitted invalid JSON") from exc
                if not isinstance(message, Mapping):
                    raise CopilotSidecarProtocolError("Copilot SDK sidecar message is not an object")
                if message.get("type") == "response":
                    self._handle_response(message)
                elif message.get("type") == "event":
                    self._handle_event(message.get("event"))
                else:
                    raise CopilotSidecarProtocolError("Copilot SDK sidecar emitted an unknown envelope")
        except BaseException as exc:
            error = exc if isinstance(exc, CopilotSDKError) else CopilotSidecarEOF(str(exc))
            self._invalidate(error, process)

    def _handle_response(self, message: Mapping[str, Any]) -> None:
        request_id = _safe_identifier(message.get("id"), 128)
        if request_id is None:
            raise CopilotSidecarProtocolError("Copilot SDK response lacks a request id")
        with self._state_lock:
            pending = self._pending.pop(request_id, None)
        if pending is None:
            raise CopilotSidecarProtocolError("Copilot SDK response has no pending request")
        if message.get("ok") is True:
            pending.result = message.get("result", {})
        else:
            error = message.get("error")
            code = error.get("code") if isinstance(error, Mapping) and isinstance(error.get("code"), str) else "rpc_error"
            detail = error.get("message") if isinstance(error, Mapping) and isinstance(error.get("message"), str) else "Copilot SDK request failed"
            pending.error = CopilotSidecarRPCError(code, detail)
        pending.completed.set()

    def _handle_event(self, event: Any) -> None:
        if not isinstance(event, Mapping):
            raise CopilotSidecarProtocolError("Copilot SDK event is not an object")
        event_id = _safe_identifier(event.get("event_id"), 512)
        session_id = _safe_identifier(event.get("session_id"), 512)
        kind = _safe_identifier(event.get("kind"), 128)
        payload = event.get("payload", {})
        if event_id is None or session_id is None or kind is None or not isinstance(payload, Mapping):
            raise CopilotSidecarProtocolError("Copilot SDK event lacks a safe identity")
        safe_payload = _safe_public_result(payload)
        with self._state_lock:
            self._cursor += 1
            self._events.append(
                {
                    "cursor": self._cursor,
                    "event_id": event_id,
                    "session_id": session_id,
                    "kind": kind,
                    "payload": safe_payload,
                }
            )
            if kind == "permission.requested":
                if (
                    payload.get("resolved_by_hook") is True
                    or payload.get("sandbox_bypass_requested") is True
                ):
                    return
                request_id = _safe_identifier(payload.get("request_id"), 256)
                tool_call_id = _safe_identifier(payload.get("tool_call_id"), 256)
                permission_kind = _safe_identifier(payload.get("permission_kind"), 64)
                session_approval_available = payload.get("session_approval_available") is True
                title = _safe_identifier(payload.get("title"), 512)
                if request_id is None or permission_kind is None:
                    raise CopilotSidecarProtocolError("permission event lacks exact correlation")
                self._approvals[request_id] = _PendingApproval(
                    request_id,
                    session_id,
                    tool_call_id,
                    permission_kind,
                    title or permission_kind,
                    session_approval_available,
                    self._generation,
                    time.time(),
                )
                self._generation += 1
                self._rebind_approvals_unlocked()
            elif kind == "permission.completed":
                request_id = _safe_identifier(payload.get("request_id"), 256)
                if request_id is not None and request_id in self._approvals:
                    del self._approvals[request_id]
                    self._generation += 1
                    self._rebind_approvals_unlocked()

    def _invalidate(self, error: BaseException, process: subprocess.Popen[bytes]) -> None:
        with self._state_lock:
            if self._process is not process:
                return
            reader = self._reader
            self._process = None
            self._handshake = None
            self._generation += 1
            self._approvals.clear()
            pending = tuple(self._pending.values())
            self._pending.clear()
        for waiter in pending:
            waiter.error = error
            waiter.completed.set()
        close_owned_process(process, reader=reader, process_group=True)
        with self._state_lock:
            if self._reader is reader:
                self._reader = None

    def close(self) -> None:
        with self._state_lock:
            process = self._process
            reader = self._reader
        if process is not None:
            self._invalidate(CopilotSidecarEOF("Copilot SDK sidecar closed"), process)
        elif reader is not None and reader is not threading.current_thread() and reader.ident is not None:
            reader.join(timeout=1)


class CopilotSDKDriver:
    def __init__(self, binding: ProviderControlBinding, *, process: _CopilotSDKSidecarProcess):
        if binding.provider_id != "copilot":
            raise CopilotSDKUnavailable("Copilot driver binding provider is invalid")
        if binding.provider_version != _SUPPORTED_CLI_VERSION:
            raise CopilotSDKUnavailable("Copilot CLI version has not been reviewed")
        if binding.provider_channel != _SUPPORTED_CLI_CHANNEL:
            raise CopilotSDKUnavailable("Copilot CLI preview or unknown channel is not supported")
        self.binding = binding
        self.process = process
        self._attached_sessions: dict[str, str] = {}
        self._last_signature: str | None = None
        self._capability_generation = 0
        self._current_models: frozenset[str] = frozenset()
        self._last_discovery: dict[str, Any] = {}
        self._action_lock = threading.RLock()
        self._action_results: OrderedDict[
            tuple[int, str],
            tuple[str, str | None, ProviderOperationResult],
        ] = OrderedDict()

    def launch_session(
        self,
        *,
        project: str,
        title: str = "",
        first_prompt: str = "",
        model: str | None = None,
        client_action_id: str | None = None,
    ) -> dict[str, Any]:
        working_directory = self._safe_working_directory(project)
        action_id = client_action_id or f"launch:{time.time_ns()}"
        result = self.process.create_session(
            working_directory=working_directory,
            model=model,
            correlation={
                "binding_id": self.binding.binding_id,
                "capability_generation": self._effective_generation(),
                "pairling_session_id": "",
                "client_action_id": action_id,
            },
        )
        native_id = _safe_identifier(result.get("native_session_id"), 512)
        if native_id is None:
            raise CopilotSidecarProtocolError("Copilot SDK create did not return a session id")
        if result.get("working_directory") != working_directory:
            raise CopilotSidecarProtocolError(
                "Copilot SDK create changed the managed working directory"
            )
        self._attached_sessions[native_id] = working_directory
        pairling_session_id = f"copilot:{native_id}"
        try:
            discovery, canary_generation = self._discover(
                native_session_id=native_id,
                working_directory=working_directory,
                pairling_session_id=pairling_session_id,
            )
            blocked = self._discovery_blocked_reason(
                discovery,
                native_session_id=native_id,
                working_directory=working_directory,
                binding_id=self.binding.binding_id,
                capability_generation=canary_generation,
                pairling_session_id=pairling_session_id,
            )
            if blocked is not None:
                raise CopilotSDKUnavailable(
                    f"Copilot managed launch canary failed: {blocked}"
                )
        except BaseException:
            self._attached_sessions.pop(native_id, None)
            raise
        public = _safe_public_result(result)
        public.update(
            {
                "binding_id": self.binding.binding_id,
                "provider_id": self.binding.provider_id,
                "provider_version": self.binding.provider_version,
                "provider_channel": self.binding.provider_channel,
                "capability_generation": self._effective_generation(),
                "provider_cursor": str(self.process.provider_cursor),
            }
        )
        if first_prompt:
            prompt_result = self.process.request(
                "send",
                {
                    "native_session_id": native_id,
                    "prompt": first_prompt,
                    "attachments": [],
                    "binding_id": self.binding.binding_id,
                    "capability_generation": self._effective_generation(),
                    "pairling_session_id": pairling_session_id,
                    "client_action_id": f"{action_id}:initial-prompt",
                },
            )
            provider_operation_id = _safe_identifier(
                prompt_result.get("provider_operation_id"),
                512,
            )
            if provider_operation_id is not None:
                public["initial_prompt_provider_operation_id"] = provider_operation_id
        return public

    def close(self) -> None:
        self._attached_sessions.clear()
        self.process.close()

    def list_sessions(self) -> tuple[dict[str, Any], ...]:
        discovery, canary_generation = self._discover(
            native_session_id=None,
            working_directory=None,
            pairling_session_id=None,
        )
        if self._discovery_blocked_reason(
            discovery,
            native_session_id=None,
            working_directory=None,
            binding_id=self.binding.binding_id,
            capability_generation=canary_generation,
            pairling_session_id=None,
        ) is not None:
            return ()
        sessions = discovery.get("sessions")
        if not isinstance(sessions, list):
            return ()
        attached = dict(self._attached_sessions)
        result: list[dict[str, Any]] = []
        for item in sessions[:256]:
            if not isinstance(item, Mapping):
                continue
            native_id = _safe_identifier(item.get("session_id"), 512)
            owned_cwd = attached.get(native_id) if native_id is not None else None
            if native_id is None or owned_cwd is None:
                continue
            discovered_cwd = item.get("working_directory")
            if discovered_cwd is not None:
                try:
                    if self._safe_working_directory(discovered_cwd) != owned_cwd:
                        continue
                except CopilotSDKUnavailable:
                    continue
            safe = _safe_public_result(item)
            safe["working_directory"] = owned_cwd
            result.append(safe)
        return tuple(result)

    def _discover(
        self,
        *,
        native_session_id: str | None,
        working_directory: str | None,
        pairling_session_id: str | None,
    ) -> tuple[dict[str, Any], int]:
        for _ in range(3):
            generation = self._effective_generation()
            discovery = self.process.discover(
                native_session_id=native_session_id,
                working_directory=working_directory,
                binding_id=self.binding.binding_id,
                capability_generation=generation,
                pairling_session_id=pairling_session_id,
            )
            if self._effective_generation() == generation:
                return discovery, generation
        raise CopilotSDKUnavailable(
            "Copilot capability generation changed during discovery"
        )

    def get_history(self, *, session_id: str) -> tuple[dict[str, Any], ...]:
        native_id = self._native_session_id(session_id)
        history: list[dict[str, Any]] = []
        after_cursor = 0
        total_events: int | None = None
        for _ in range(_MAX_EVENT_COUNT + 1):
            result = self.process.request(
                "events",
                {
                    "native_session_id": native_id,
                    "binding_id": self.binding.binding_id,
                    "capability_generation": self._effective_generation(),
                    "pairling_session_id": session_id,
                    "client_action_id": f"history:{self.binding.binding_id}:{native_id}",
                    "after_cursor": after_cursor,
                },
            )
            events = result.get("events")
            cursor = result.get("cursor")
            next_cursor = result.get("next_cursor")
            partial = result.get("partial")
            page_total = result.get("total_events")
            if (
                not isinstance(events, list)
                or any(not isinstance(event, Mapping) for event in events)
                or isinstance(cursor, bool)
                or not isinstance(cursor, int)
                or isinstance(next_cursor, bool)
                or not isinstance(next_cursor, int)
                or isinstance(page_total, bool)
                or not isinstance(page_total, int)
                or not isinstance(partial, bool)
                or cursor != after_cursor
                or cursor < 0
                or next_cursor != cursor + len(events)
                or next_cursor > page_total
                or page_total < 0
                or page_total > _MAX_EVENT_COUNT
                or partial != (next_cursor < page_total)
            ):
                raise CopilotSidecarProtocolError(
                    "Copilot SDK history page metadata is invalid"
                )
            if total_events is None:
                total_events = page_total
            elif page_total != total_events:
                raise CopilotSidecarProtocolError(
                    "Copilot SDK history changed during pagination"
                )
            if len(history) + len(events) > _MAX_EVENT_COUNT:
                raise CopilotSidecarProtocolError(
                    "Copilot SDK history exceeds the retained event bound"
                )
            history.extend(_safe_public_result(event) for event in events)
            if not partial:
                return tuple(history)
            if next_cursor <= after_cursor:
                raise CopilotSidecarProtocolError(
                    "Copilot SDK history pagination made no progress"
                )
            after_cursor = next_cursor
        raise CopilotSidecarProtocolError(
            "Copilot SDK history pagination exceeds the retained event bound"
        )

    def poll_events(self, after_cursor: int | str | None = 0) -> list[dict[str, Any]]:
        return self.process.poll_events(after_cursor)

    def pending_approvals(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            {
                "approval_id": item.request_id,
                "session_id": item.session_id,
                "tool_call_id": item.tool_call_id,
                "permission_kind": item.permission_kind,
                "title": item.title,
                "capability_generation": self._effective_generation(),
            }
            for item in self.process.pending_approvals()
        )

    def respond_approval(
        self,
        *,
        approval_id: str,
        session_id: str,
        decision: str,
        client_action_id: str | None = None,
    ) -> dict[str, Any]:
        native_id = self._native_session_id(session_id)
        working_directory = self._attached_sessions[native_id]
        if not any(
            pending.request_id == approval_id
            for pending in self.process.pending_approvals(session_id=native_id)
        ):
            raise CopilotApprovalCorrelationError(
                "approval request is missing or belongs to another session"
            )
        discovery, canary_generation = self._discover(
            native_session_id=native_id,
            working_directory=working_directory,
            pairling_session_id=session_id,
        )
        blocked = self._discovery_blocked_reason(
            discovery,
            native_session_id=native_id,
            working_directory=working_directory,
            binding_id=self.binding.binding_id,
            capability_generation=canary_generation,
            pairling_session_id=session_id,
        )
        if blocked is not None:
            raise CopilotApprovalCorrelationError(
                f"approval conformance canary failed: {blocked}"
            )
        return self.process.respond_approval(
            request_id=approval_id,
            session_id=native_id,
            decision=decision,
            correlation={
                "binding_id": self.binding.binding_id,
                "capability_generation": canary_generation,
                "pairling_session_id": session_id,
                "client_action_id": client_action_id or approval_id,
            },
        )

    def refresh_capabilities(
        self,
        *,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderControlSnapshot:
        return self.snapshot(session_id=session_id, session_truth=session_truth)

    def snapshot(
        self,
        *,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderControlSnapshot:
        if session_id is not None and not self._is_owned_session(session_id, session_truth):
            return self._blocked_snapshot("session_not_owned_by_copilot_sdk_driver")

        native_id: str | None = None
        working_directory: str | None = None
        if session_id is not None:
            assert session_truth is not None
            native_id = _safe_identifier(session_truth.get("native_id"), 512)
            working_directory = self._safe_working_directory(
                session_truth.get("cwd")
            )
            if native_id is None:
                return self._blocked_snapshot("session_native_identity_missing")
            if self._attached_sessions.get(native_id) != working_directory:
                resumed = self.process.resume_session(
                    native_session_id=native_id,
                    working_directory=working_directory,
                    correlation={
                        "binding_id": self.binding.binding_id,
                        "capability_generation": self._effective_generation(),
                        "pairling_session_id": session_id,
                        "client_action_id": f"attach:{self.binding.binding_id}:{native_id}",
                    },
                )
                if resumed.get("native_session_id") != native_id:
                    return self._blocked_snapshot("session_resume_identity_mismatch")
                if resumed.get("working_directory") != working_directory:
                    return self._blocked_snapshot("session_resume_cwd_mismatch")
                self._attached_sessions[native_id] = working_directory

        try:
            discovery, canary_generation = self._discover(
                native_session_id=native_id,
                working_directory=working_directory,
                pairling_session_id=session_id,
            )
        except CopilotSDKError as exc:
            return self._blocked_snapshot(f"sdk_discovery_failed:{type(exc).__name__}")
        blocked = self._discovery_blocked_reason(
            discovery,
            native_session_id=native_id,
            working_directory=working_directory,
            binding_id=self.binding.binding_id,
            capability_generation=canary_generation,
            pairling_session_id=session_id,
        )
        if blocked is not None:
            return self._blocked_snapshot(blocked)

        capabilities = frozenset(item for item in discovery.get("capabilities", ()) if isinstance(item, str))
        models = self._models(discovery.get("models"))
        operations: list[str] = []
        choices: list[ControlChoices] = []
        if session_id is None:
            # Authentication is a visibility canary only. Pairling never exposes
            # Copilot credential state or login/logout controls through this driver.
            if "usage" in capabilities:
                operations.append("provider.usage.read")
            if "mcp_metadata" in capabilities:
                operations.append("provider.mcp.read")
            operations.append("provider.diagnostics.read")
        else:
            resume_targets = self._resume_targets(
                discovery,
                current_native_id=native_id,
                working_directory=working_directory,
            )
            if "sessions" in capabilities and resume_targets:
                operations.append("session.resume")
                choices.append(
                    ControlChoices(
                        "session.resume",
                        "target_session",
                        tuple(
                            ControlChoice(target_id, label)
                            for target_id, label in resume_targets
                        ),
                    )
                )
            if "message_enqueue" in capabilities:
                operations.append("session.prompt.send")
            if "message_immediate" in capabilities:
                operations.append("session.turn.steer")
            if "abort" in capabilities:
                operations.append("session.turn.interrupt")
            if "set_model" in capabilities and models:
                operations.append("session.model.set")
                choices.append(
                    ControlChoices(
                        "session.model.set",
                        "model",
                        tuple(ControlChoice(model_id, label) for model_id, label in models),
                    )
                )
            approvals = self.process.pending_approvals(session_id=native_id)
            if "approval_response" in capabilities and approvals:
                operations.append("session.approval.decide")
                choices.extend(
                    (
                        ControlChoices(
                            "session.approval.decide",
                            "approval_id",
                            tuple(ControlChoice(item.request_id, item.title) for item in approvals),
                        ),
                        ControlChoices(
                            "session.approval.decide",
                            "decision",
                            (
                                ControlChoice("once", "Approve once"),
                                *(
                                    (ControlChoice("session", "Approve for this session"),)
                                    if all(item.session_approval_available for item in approvals)
                                    else ()
                                ),
                                ControlChoice("deny", "Deny"),
                            ),
                        ),
                    )
                )

        signature = json.dumps(
            {
                "operations": operations,
                "models": models,
                "approvals": [item.request_id for item in self.process.pending_approvals()],
                "resume_targets": resume_targets if session_id is not None else (),
                "process_generation": self.process.capability_generation,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        if self._last_signature is not None and signature != self._last_signature:
            self._capability_generation += 1
        self._last_signature = signature
        self._current_models = frozenset(model_id for model_id, _ in models)
        generation = self._effective_generation()
        if generation != canary_generation:
            try:
                attested, attested_generation = self._discover(
                    native_session_id=native_id,
                    working_directory=working_directory,
                    pairling_session_id=session_id,
                )
            except CopilotSDKError as exc:
                return self._blocked_snapshot(
                    f"generation_reattestation_failed:{type(exc).__name__}"
                )
            blocked = self._discovery_blocked_reason(
                attested,
                native_session_id=native_id,
                working_directory=working_directory,
                binding_id=self.binding.binding_id,
                capability_generation=attested_generation,
                pairling_session_id=session_id,
            )
            if blocked is not None:
                return self._blocked_snapshot(blocked)
            evidence_keys = (
                "capabilities",
                "models",
                "sessions",
                "native_session_id",
                "working_directory",
            )
            if any(attested.get(key) != discovery.get(key) for key in evidence_keys):
                return self._blocked_snapshot(
                    "capability_shape_changed_during_generation_attestation"
                )
            discovery = attested
            generation = attested_generation
        self._last_discovery = _safe_public_result(discovery)
        if (
            session_id is not None
            and session_truth is not None
            and session_truth.get("capability_generation") != generation
        ):
            return self._blocked_snapshot(
                "session_capability_generation_mismatch"
            )
        values: tuple[ControlValue, ...] = ()
        if session_id is not None:
            identity = ProviderSessionIdentity(
                self.binding.provider_id,
                session_id,
                self.binding.binding_id,
                generation,
            )
            values = tuple(
                ControlValue(operation_id, "session", identity)
                for operation_id in operations
                if operation_id.startswith("session.")
            )
        now = time.time()
        return ProviderControlSnapshot(
            provider_id=self.binding.provider_id,
            provider_version=self.binding.provider_version,
            provider_channel=self.binding.provider_channel,
            binding_id=self.binding.binding_id,
            capability_generation=generation,
            observed_at=now,
            valid_until=now + 5.0,
            advertised_operations=tuple(operations),
            values=values,
            choices=tuple(choices),
            blocked_reason=None,
            provider_cursor=str(self.process.provider_cursor),
        )

    def operation_correlation(
        self,
        *,
        operation_id: str,
        client_action_id: str,
        capability_generation: int,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderOperationCorrelation:
        if (
            session_id is None
            or not self._is_owned_session(session_id, session_truth)
        ):
            raise CopilotStaleBinding(
                "Copilot operation correlation requires an owned session"
            )
        snapshot = self.snapshot(
            session_id=session_id,
            session_truth=session_truth,
        )
        if (
            snapshot.capability_generation != capability_generation
            or operation_id not in snapshot.advertised_operations
        ):
            raise CopilotStaleBinding(
                "Copilot operation correlation proof is unavailable"
            )
        snapshot.validate()
        return ProviderOperationCorrelation(
            _copilot_operation_id(
                self.binding.binding_id,
                capability_generation,
                client_action_id,
            ),
            snapshot.provider_cursor,
        )

    def execute(
        self,
        *,
        operation_id: str,
        input_payload: dict[str, Any],
        binding_id: str,
        capability_generation: int,
        session_id: str | None,
        client_action_id: str,
        prepared_attachments: tuple[Any, ...] = (),
        provider_correlation: ProviderOperationCorrelation | None = None,
    ) -> ProviderOperationResult:
        if binding_id != self.binding.binding_id:
            raise CopilotStaleBinding("Copilot binding is stale")
        if capability_generation != self._effective_generation():
            raise CopilotStaleBinding("Copilot capability generation is stale")
        if "attachments" in input_payload:
            raise CopilotUnsupportedOperation("serialized attachment inputs cannot reach the provider driver")
        fingerprint_payload = {
            "operation_id": operation_id,
            "input": input_payload,
            "session_id": session_id,
            "attachments": [
                {
                    "handle_id": getattr(item, "handle_id", None),
                    "sha256": getattr(item, "sha256", None),
                    "size_bytes": getattr(item, "size_bytes", None),
                    "mime_type": getattr(item, "mime_type", None),
                }
                for item in prepared_attachments
            ],
        }
        try:
            action_fingerprint = hashlib.sha256(
                json.dumps(
                    fingerprint_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
        except (TypeError, ValueError) as exc:
            raise CopilotUnsupportedOperation(
                "Copilot operation payload is not canonical JSON"
            ) from exc
        cache_key = (capability_generation, client_action_id)
        with self._action_lock:
            cached = self._action_results.get(cache_key)
        if cached is not None:
            if (
                cached[0] != action_fingerprint
                or cached[1] != session_id
                or cached[2].operation_id != operation_id
            ):
                raise CopilotStaleBinding(
                    "Copilot client action id was already used"
                )
            return cached[2]
        if provider_correlation is not None:
            expected_operation_id = _copilot_operation_id(
                self.binding.binding_id,
                capability_generation,
                client_action_id,
            )
            if (
                not isinstance(
                    provider_correlation,
                    ProviderOperationCorrelation,
                )
                or provider_correlation.provider_operation_id
                != expected_operation_id
            ):
                raise CopilotStaleBinding(
                    "Copilot operation correlation proof is stale"
                )
        native_id = self._native_session_id(session_id) if session_id is not None else None
        payload: dict[str, Any] = {
            "binding_id": self.binding.binding_id,
            "capability_generation": capability_generation,
            "pairling_session_id": session_id,
            "client_action_id": client_action_id,
        }
        status = OperationResultStatus.APPLIED

        if operation_id == "session.prompt.send" and native_id is not None:
            payload.update(
                {
                    "native_session_id": native_id,
                    "prompt": input_payload["prompt"],
                    "attachments": self._encode_prepared_attachments(prepared_attachments),
                }
            )
            result = self.process.request("send", payload)
        elif operation_id == "session.turn.steer" and native_id is not None:
            if prepared_attachments:
                raise CopilotUnsupportedOperation("steering attachments are not reviewed")
            payload.update({"native_session_id": native_id, "instruction": input_payload["instruction"]})
            result = self.process.request("steer", payload)
        elif operation_id == "session.turn.interrupt" and native_id is not None:
            if prepared_attachments:
                raise CopilotUnsupportedOperation("interrupt cannot carry attachments")
            payload["native_session_id"] = native_id
            result = self.process.request("abort", payload)
        elif operation_id == "session.resume" and native_id is not None:
            if prepared_attachments:
                raise CopilotUnsupportedOperation("resume cannot carry attachments")
            working_directory = self._attached_sessions.get(native_id)
            target_id = _safe_identifier(
                input_payload.get("target_session"),
                512,
            )
            if not working_directory or target_id is None:
                raise CopilotUnsupportedOperation(
                    "resume target is not attached to this binding"
                )
            discovery, canary_generation = self._discover(
                native_session_id=native_id,
                working_directory=working_directory,
                pairling_session_id=session_id,
            )
            blocked = self._discovery_blocked_reason(
                discovery,
                native_session_id=native_id,
                working_directory=working_directory,
                binding_id=self.binding.binding_id,
                capability_generation=canary_generation,
                pairling_session_id=session_id,
            )
            if blocked is not None:
                raise CopilotUnsupportedOperation(
                    f"resume conformance canary failed: {blocked}"
                )
            payload["source_native_session_id"] = native_id
            resume_targets = dict(
                self._resume_targets(
                    discovery,
                    current_native_id=native_id,
                    working_directory=working_directory,
                )
            )
            if target_id not in resume_targets:
                raise CopilotUnsupportedOperation(
                    "resume target is stale or not owned by this binding"
                )
            result = self.process.resume_session(
                native_session_id=target_id,
                working_directory=working_directory,
                correlation=payload,
            )
            if (
                result.get("native_session_id") != target_id
                or result.get("working_directory") != working_directory
            ):
                raise CopilotUnsupportedOperation(
                    "resume target identity changed"
                )
            self._attached_sessions[target_id] = working_directory
        elif operation_id == "session.model.set" and native_id is not None:
            if prepared_attachments:
                raise CopilotUnsupportedOperation("model selection cannot carry attachments")
            model = input_payload.get("model")
            if model not in self._current_models:
                raise CopilotUnsupportedOperation("model was not returned by live Copilot discovery")
            payload.update({"native_session_id": native_id, "model": model})
            result = self.process.request("set_model", payload)
        elif operation_id == "session.approval.decide" and native_id is not None:
            if prepared_attachments:
                raise CopilotUnsupportedOperation("approval decisions cannot carry attachments")
            result = self.process.respond_approval(
                request_id=input_payload["approval_id"],
                session_id=native_id,
                decision=input_payload["decision"],
                correlation=payload,
            )
        elif operation_id == "provider.usage.read" and native_id is None:
            result = self.process.request("read_usage", payload)
        elif operation_id == "provider.mcp.read" and native_id is None:
            result = self.process.request("read_mcp", payload)
        elif operation_id == "provider.diagnostics.read" and native_id is None:
            result = self.process.request("read_diagnostics", payload)
        else:
            raise CopilotUnsupportedOperation(f"unreviewed Copilot operation: {operation_id}")

        provider_operation_id = _safe_identifier(result.get("provider_operation_id"), 512)
        if provider_operation_id is None:
            raise CopilotSidecarProtocolError("Copilot SDK result lacks provider correlation")
        operation_result = ProviderOperationResult(
            operation_id=operation_id,
            provider_operation_id=(
                provider_correlation.provider_operation_id
                if provider_correlation is not None
                else provider_operation_id
            ),
            status=status,
            public_result=_safe_public_result(result),
            provider_cursor=(
                provider_correlation.provider_cursor
                if provider_correlation is not None
                else str(self.process.provider_cursor)
            ),
        )
        with self._action_lock:
            self._action_results[cache_key] = (
                action_fingerprint,
                session_id,
                operation_result,
            )
            self._action_results.move_to_end(cache_key)
            while len(self._action_results) > 256:
                self._action_results.popitem(last=False)
        return operation_result

    def recover(
        self,
        *,
        operation_id: str,
        binding_id: str,
        capability_generation: int,
        session_id: str | None,
        client_action_id: str,
        provider_correlation: ProviderOperationCorrelation,
        session_truth: dict[str, Any] | None,
    ) -> ProviderOperationResult | None:
        del session_truth
        if (
            binding_id != self.binding.binding_id
            or not isinstance(
                provider_correlation,
                ProviderOperationCorrelation,
            )
        ):
            return None
        with self._action_lock:
            cached = self._action_results.get(
                (capability_generation, client_action_id)
            )
        if (
            cached is None
            or cached[1] != session_id
            or cached[2].operation_id != operation_id
            or cached[2].provider_operation_id
            != provider_correlation.provider_operation_id
            or cached[2].provider_cursor
            != provider_correlation.provider_cursor
            or cached[2].status
            not in {
                OperationResultStatus.APPLIED,
                OperationResultStatus.REJECTED,
            }
        ):
            return None
        return cached[2]


    def _encode_prepared_attachments(self, attachments: tuple[Any, ...]) -> list[dict[str, Any]]:
        if not isinstance(attachments, tuple):
            raise CopilotUnsupportedOperation("prepared attachments must be an immutable tuple")
        if len(attachments) > _MAX_ATTACHMENT_COUNT:
            raise CopilotUnsupportedOperation("too many prepared attachments")
        total = 0
        result: list[dict[str, Any]] = []
        for item in attachments:
            size = getattr(item, "size_bytes", None)
            digest = getattr(item, "sha256", None)
            mime_type = _safe_identifier(getattr(item, "mime_type", None), 128)
            display_name = getattr(item, "display_name", None)
            opener = getattr(item, "open_verified", None)
            if (
                isinstance(size, bool)
                or not isinstance(size, int)
                or size < 0
                or size > _MAX_ATTACHMENT_BYTES
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or mime_type is None
                or not callable(opener)
            ):
                raise CopilotUnsupportedOperation("prepared attachment metadata is invalid")
            total += size
            if total > _MAX_ATTACHMENTS_BYTES:
                raise CopilotUnsupportedOperation("prepared attachments exceed the aggregate bound")
            if display_name is not None:
                display_name = _safe_identifier(display_name, 128)
                if display_name is None:
                    raise CopilotUnsupportedOperation("prepared attachment display name is invalid")
            try:
                with opener() as handle:
                    data = handle.read(size + 1)
            except Exception as exc:
                raise CopilotUnsupportedOperation("prepared attachment verification failed") from exc
            if not isinstance(data, bytes) or len(data) != size:
                raise CopilotUnsupportedOperation("prepared attachment size changed")
            if hashlib.sha256(data).hexdigest() != digest:
                raise CopilotUnsupportedOperation("prepared attachment hash changed")
            blob: dict[str, Any] = {
                "type": "blob",
                "data": base64.b64encode(data).decode("ascii"),
                "mimeType": mime_type,
            }
            if display_name is not None:
                blob["displayName"] = display_name
            result.append(blob)
        return result

    def _discovery_blocked_reason(
        self,
        discovery: Mapping[str, Any],
        *,
        native_session_id: str | None,
        working_directory: str | None,
        binding_id: str,
        capability_generation: int,
        pairling_session_id: str | None,
    ) -> str | None:
        checks = (
            (discovery.get("sdk_version") == _SUPPORTED_SDK_VERSION, "sdk_version_mismatch"),
            (discovery.get("cli_version") == self.binding.provider_version, "cli_version_mismatch"),
            (discovery.get("cli_channel") == self.binding.provider_channel, "cli_channel_mismatch"),
            (discovery.get("sdk_protocol_version") == _SUPPORTED_SDK_PROTOCOL, "sdk_protocol_mismatch"),
            (discovery.get("transport") == "stdio-jsonrpc", "transport_not_local_stdio"),
            (discovery.get("authenticated") is True, "copilot_not_authenticated"),
            (discovery.get("permission_policy") == "scoped-pending", "permission_policy_not_scoped"),
            (discovery.get("sandbox_bypass_allowed") is False, "sandbox_bypass_not_disabled"),
            (discovery.get("binding_id") == binding_id, "binding_canary_mismatch"),
            (
                type(discovery.get("capability_generation")) is int
                and discovery.get("capability_generation") == capability_generation,
                "capability_generation_canary_mismatch",
            ),
            (
                discovery.get("pairling_session_id") == pairling_session_id,
                "public_session_identity_mismatch",
            ),
        )
        for passed, reason in checks:
            if not passed:
                return reason
        capabilities = discovery.get("capabilities")
        if not isinstance(capabilities, list) or not capabilities:
            return "live_capability_discovery_empty"
        if native_session_id is not None:
            if pairling_session_id != f"copilot:{native_session_id}":
                return "public_native_session_identity_mismatch"
            if discovery.get("native_session_id") != native_session_id:
                return "session_identity_mismatch"
            if discovery.get("working_directory") != working_directory:
                return "session_cwd_mismatch"
        elif (
            discovery.get("native_session_id") is not None
            or discovery.get("working_directory") is not None
        ):
            return "provider_scope_identity_mismatch"
        return None

    @staticmethod
    def _models(raw_models: Any) -> tuple[tuple[str, str], ...]:
        if not isinstance(raw_models, list):
            return ()
        result: list[tuple[str, str]] = []
        seen: set[str] = set()
        for raw in raw_models[:128]:
            if not isinstance(raw, Mapping):
                continue
            model_id = _safe_identifier(raw.get("id"), 160)
            name = _safe_identifier(raw.get("name"), 160)
            if model_id is None or name is None or model_id in seen:
                continue
            seen.add(model_id)
            result.append((model_id, name))
        return tuple(result)
    @staticmethod
    def _resume_targets(
        discovery: Mapping[str, Any],
        *,
        current_native_id: str | None,
        working_directory: str | None,
    ) -> tuple[tuple[str, str], ...]:
        if current_native_id is None or working_directory is None:
            return ()
        sessions = discovery.get("sessions")
        if not isinstance(sessions, list):
            return ()
        result: list[tuple[str, str]] = []
        seen: set[str] = set()
        for raw in sessions[:256]:
            if not isinstance(raw, Mapping):
                continue
            target_id = _safe_identifier(raw.get("session_id"), 512)
            if (
                target_id is None
                or target_id == current_native_id
                or target_id in seen
                or raw.get("working_directory") != working_directory
            ):
                continue
            summary = _safe_identifier(raw.get("summary"), 160)
            result.append(
                (
                    target_id,
                    summary or f"Copilot session {target_id[:24]}",
                )
            )
            seen.add(target_id)
        return tuple(result)


    def _blocked_snapshot(self, reason: str) -> ProviderControlSnapshot:
        now = time.time()
        return ProviderControlSnapshot(
            provider_id=self.binding.provider_id,
            provider_version=self.binding.provider_version,
            provider_channel=self.binding.provider_channel,
            binding_id=self.binding.binding_id,
            capability_generation=self._effective_generation(),
            observed_at=now,
            valid_until=now + 5.0,
            advertised_operations=(),
            values=(),
            choices=(),
            blocked_reason=_bounded_text(reason, 512),
            provider_cursor=str(self.process.provider_cursor),
        )

    def _effective_generation(self) -> int:
        return max(1, self._capability_generation + self.process.capability_generation)

    def _is_owned_session(self, session_id: str, truth: dict[str, Any] | None) -> bool:
        native_id = _safe_identifier(
            truth.get("native_id") if isinstance(truth, dict) else None,
            512,
        )
        project = truth.get("project") if isinstance(truth, dict) else None
        cwd = truth.get("cwd") if isinstance(truth, dict) else None
        return bool(
            isinstance(truth, dict)
            and native_id is not None
            and session_id == f"copilot:{native_id}"
            and truth.get("provider_id") == "copilot"
            and truth.get("session_id") == session_id
            and truth.get("managed") is True
            and truth.get("owner") == "provider_driver"
            and truth.get("terminal_backed") is False
            and truth.get("binding_id") == self.binding.binding_id
            and type(truth.get("capability_generation")) is int
            and truth.get("capability_generation") == self._effective_generation()
            and truth.get("is_live") is True
            and truth.get("controllable") is True
            and _safe_identifier(truth.get("session_instance_id"), 512) is not None
            and isinstance(project, str)
            and project == cwd
        )

    @staticmethod
    def _safe_working_directory(value: Any) -> str:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise CopilotSDKUnavailable("Copilot session working directory is invalid")
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise CopilotSDKUnavailable("Copilot session working directory must be absolute")
        return str(path.resolve())

    def _native_session_id(self, session_id: str | None) -> str:
        if session_id is None:
            raise CopilotUnsupportedOperation("Copilot session operation lacks an identity")
        if not session_id.startswith("copilot:"):
            raise CopilotUnsupportedOperation("Copilot public session identity is invalid")
        native_id = session_id.removeprefix("copilot:")
        if _safe_identifier(native_id, 512) is None or native_id not in self._attached_sessions:
            raise CopilotUnsupportedOperation("Copilot session is not attached to this driver")
        return native_id


class CopilotProviderAdapter(ProviderAdapter):
    descriptor = registry_data.descriptor_for(_ENTRY) if _ENTRY else _FALLBACK_DESCRIPTOR

    def __init__(self, home: Path | None = None):
        self.home = home or Path.home()

    @property
    def candidates(self) -> list[Path]:
        if _ENTRY is not None and _ENTRY.binary_candidates:
            return registry_data.candidate_paths(_ENTRY, home=self.home)
        return [
            self.home / ".local" / "bin" / "copilot",
            Path("/opt/homebrew/bin/copilot"),
            Path("/usr/local/bin/copilot"),
        ]

    @property
    def sdk_candidates(self) -> tuple[Path, ...]:
        candidates: list[Path] = []
        configured = os.environ.get("PAIRLING_COPILOT_SDK_ROOT")
        if configured:
            candidates.append(Path(configured).expanduser())
        python_path = Path(sys.executable).resolve()
        if len(python_path.parents) >= 3:
            candidates.append(
                python_path.parents[2] / "node_modules" / "@github" / "copilot-sdk"
            )
        runtime_root = os.environ.get("PAIRLING_RUNTIME_PACKAGE_ROOT")
        if runtime_root:
            candidates.append(
                Path(runtime_root).expanduser() / "node_modules" / "@github" / "copilot-sdk"
            )
        candidates.extend(
            (
                Path(__file__).resolve().parent / "node_modules" / "@github" / "copilot-sdk",
                self.home / ".local" / "lib" / "node_modules" / "@github" / "copilot-sdk",
                Path("/opt/homebrew/lib/node_modules/@github/copilot-sdk"),
                Path("/usr/local/lib/node_modules/@github/copilot-sdk"),
            )
        )
        return tuple(candidates)

    @property
    def node_candidates(self) -> list[Path]:
        return [
            Path("/opt/homebrew/bin/node"),
            Path("/usr/local/bin/node"),
            self.home / ".local" / "bin" / "node",
        ]

    def supports(self, capability: str) -> bool:
        return capability in {
            "detect",
            "status",
            "list_sessions",
            "read_transcript",
            "spawn",
            "live_state",
            "send_text",
            "interrupt",
            "terminate",
            "terminal_output",
        }

    def probe(self) -> ProviderProbeResult:
        env_var = _ENTRY.env_override if _ENTRY is not None else "PAIRLING_COPILOT_BIN"
        resolved = resolve_executable("copilot", self.candidates, env_var=env_var)
        version_output = cli_version(resolved.path) if resolved else None
        installed = resolved is not None
        compatible_cli = is_compatible_copilot_cli_version(version_output)
        node = resolve_executable("node", self.node_candidates, env_var="PAIRLING_NODE_BIN")
        notes: list[str] = []
        setup_actions: list[str] = []
        if not installed:
            notes.append("GitHub Copilot CLI not found")
            setup_actions.append("install_cli")
        elif not compatible_cli:
            notes.append(f"Copilot CLI must be exactly {_SUPPORTED_CLI_VERSION} stable for SDK control")
        try:
            sdk = resolve_copilot_sdk_package(self.sdk_candidates)
        except CopilotSDKPackageUnavailable as exc:
            sdk = None
            notes.append(str(exc))
        if node is None:
            notes.append("Node.js runtime required by the official Copilot SDK was not found")
        control_ready = installed and compatible_cli and node is not None and sdk is not None
        capabilities = (
            "detect",
            "status",
            "list_sessions",
            "read_transcript",
            "spawn",
            "live_state",
            "send_text",
            "interrupt",
            "terminate",
            "terminal_output",
        ) if control_ready else ("detect", "status")
        availability = ProviderAvailability(
            provider_id=self.descriptor.provider_id,
            display_name=self.descriptor.display_name,
            kind=self.descriptor.kind,
            installed=installed,
            usable=control_ready,
            launchable=control_ready,
            auth_state="unknown" if installed else "missing_cli",
            config_state="sdk_resolved" if control_ready else "sdk_unavailable",
            readable_sessions=0,
            live_sessions=0,
            controllable_sessions=0,
            capabilities=capabilities,
            setup_actions=tuple(dict.fromkeys(setup_actions)),
            notes=tuple(notes),
        )
        diagnostics = ProviderDiagnostics(
            cli_path=str(resolved.path) if resolved else None,
            cli_path_source=resolved.source if resolved else None,
            version=_version_from_output(version_output),
            config_path=str(sdk.root) if sdk else None,
            config_exists=sdk is not None,
        )
        return ProviderProbeResult(
            descriptor=self.descriptor,
            availability=availability,
            diagnostics=diagnostics,
            observed_at=time.time(),
        )

    def create_control_driver(self, binding: ProviderControlBinding) -> CopilotSDKDriver | None:
        if (
            binding.provider_id != "copilot"
            or binding.provider_version != _SUPPORTED_CLI_VERSION
            or binding.provider_channel != _SUPPORTED_CLI_CHANNEL
        ):
            return None
        env_var = _ENTRY.env_override if _ENTRY is not None else "PAIRLING_COPILOT_BIN"
        cli = resolve_executable("copilot", self.candidates, env_var=env_var)
        node = resolve_executable("node", self.node_candidates, env_var="PAIRLING_NODE_BIN")
        if cli is None or node is None or not is_compatible_copilot_cli_version(cli_version(cli.path)):
            return None
        try:
            sdk = resolve_copilot_sdk_package(self.sdk_candidates)
        except CopilotSDKPackageUnavailable:
            return None
        sidecar = Path(__file__).with_name("copilot_sdk_sidecar.mjs")
        if not sidecar.is_file():
            return None
        argv = (
            str(node.path),
            str(sidecar),
            "--sdk-entry",
            str(sdk.entrypoint),
            "--sdk-version",
            sdk.version,
            "--cli-path",
            str(cli.path),
            "--expected-cli-version",
            binding.provider_version,
            "--base-directory",
            str(self.home / ".copilot"),
        )
        process = _CopilotSDKSidecarProcess(
            argv=argv,
            expected_cli_version=binding.provider_version,
        )
        return CopilotSDKDriver(binding, process=process)


def _copilot_operation_id(
    binding_id: str,
    capability_generation: int,
    client_action_id: str,
) -> str:
    material = (
        f"{binding_id}\0{capability_generation}\0{client_action_id}"
    ).encode("utf-8")
    return "copilot:" + hashlib.sha256(material).hexdigest()[:40]

def create_control_driver(binding: ProviderControlBinding) -> CopilotSDKDriver | None:
    return CopilotProviderAdapter().create_control_driver(binding)
