"""Reviewed ACP v1 stdio driver for Pairling-owned provider sessions.

This module is intentionally not a generic JSON-RPC bridge.  Outbound methods
are fixed here, provider extensions remain inert metadata, and a reviewed
profile plus a live, exact ACP capability snapshot is required before any
Pairling operation is advertised.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import math
import os
import re
import secrets
import signal
import subprocess
import threading
import sys
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from . import registry_data
from .acp_profiles import (
    AcpLaunchProfile,
    AcpProfileUnavailable,
    validate_canary_attestation,
    reviewed_acp_profile,
)
from .operations import (
    OperationCatalogError,
    REVIEWED_OPERATION_CATALOG,
    provider_binding_has_release_membership,
    released_operation_ids_for_provider,
)
from .base import (
    ProviderAdapter,
    ProviderAvailability,
    ProviderDiagnostics,
    ProviderProbeResult,
    cli_version,
    managed_child_environment,
    resolve_executable,
)
from .controls import (
    ControlChoice,
    ControlChoices,
    ControlValue,
    OperationResultStatus,
    ProviderControlBinding,
    ProviderControlSnapshot,
    ProviderOperationResult,
    ProviderOperationCorrelation,
    ProviderSessionIdentity,
)


# Only these reviewed ACP v1 methods can ever leave this process.  Membership
# here is necessary, never sufficient: the driver also checks the negotiated
# live capability or a typed baseline operation at each call site.
_ACP_V1_METHODS = frozenset(
    {
        "initialize",
        "session/new",
        "session/load",
        "session/list",
        "session/resume",
        "session/prompt",
        "session/cancel",
        "session/set_mode",
        "session/set_config_option",
        # Legacy/draft overlay.  It is callable only when an exact reviewed
        # profile names it; no bundled profile currently does.
        "session/set_model",
    }
)
_REVERSE_PERMISSION_METHODS = frozenset(
    {"session/request_permission", "session/requestPermission"}
)
_REVERSE_ELICITATION_METHODS = frozenset({"elicitation/create"})
_KNOWN_NOTIFICATIONS = frozenset(
    {
        "session/update",
        "session/current_mode_update",
        "session/currentModeUpdate",
        "session/config_option_update",
        "session/configOptionUpdate",
        "session/info_update",
        "session/infoUpdate",
    }
)
_MAX_REQUEST_BYTES = 512 * 1024
_MAX_MESSAGE_BYTES = 2 * 1024 * 1024
_MAX_EVENTS = 512
_MAX_PENDING_REQUESTS = 64
_MAX_PENDING_PERMISSIONS = 32
_MAX_SAFE_STRING_BYTES = 64 * 1024
_MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024
_MAX_ATTACHMENT_TOTAL_BYTES = 8 * 1024 * 1024
_PERMISSION_TIMEOUT_SECONDS = 120.0
_DEFAULT_REQUEST_TIMEOUT = 300.0
_MAX_LISTED_SESSIONS = 256
_SAFE_MODE_BAD_WORDS = frozenset(
    {
        "allowalways",
        "alwaysallow",
        "autoapprove",
        "autonomous",
        "bypass",
        "danger",
        "dontask",
        "fullauto",
        "noprompt",
        "unrestricted",
        "yolo",
    }
)
_SECRET_KEY_WORDS = (
    "accesskey",
    "apikey",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "password",
    "privatekey",
    "refreshtoken",
    "secret",
    "sessiontoken",
)
_MAX_PENDING_ELICITATIONS = 1
_ELICITATION_TIMEOUT_SECONDS = 11 * 60
_SECRET_TEXT_RE = re.compile(
    r"(?i)(?:bearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"\b(?:sk|ghp|github_pat|xoxb|xoxp|xoxa|xoxr|AKIA)[-_A-Za-z0-9]{8,}\b|"
    r"\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+)"
)
_USAGE_TOKEN_KEYS = frozenset(
    {
        "cachedtokens",
        "inputtokens",
        "outputtokens",
        "thoughtstokens",
        "totaltokens",
    }
)
_CURSOR_RE = re.compile(r"acp:(\d+):(\d+)\Z")


class AcpError(RuntimeError):
    """Base class for fail-closed ACP failures."""


class AcpUnavailableError(AcpError):
    code = "acp_unavailable"


class AcpProtocolError(AcpUnavailableError):
    code = "acp_protocol_error"


class AcpTimeoutError(AcpUnavailableError):
    code = "acp_timeout"


class AcpEOFError(AcpUnavailableError):
    code = "acp_eof"


class AcpMethodNotAllowed(AcpError):
    code = "acp_method_not_allowed"


class AcpStaleBinding(AcpError):
    code = "acp_stale_binding"


class AcpCursorExpired(AcpError):
    code = "acp_cursor_expired"


class AcpRPCError(AcpError):
    def __init__(self, code: int | None, message: Any):
        self.code = code
        super().__init__(f"ACP error {code}: {_bounded_text(message, 512)}")


@dataclass
class _PendingResponse:
    completed: threading.Event
    result: Any = None
    error: BaseException | None = None


@dataclass(frozen=True)
class _PendingPermission:
    provider_request_id: str | int
    approval_id: str
    native_session_id: str
    tool_call_id: str
    received_at: float
    generation: int
    options: Mapping[str, tuple[str, str]]


@dataclass(frozen=True)
class _PendingElicitation:
    provider_request_id: str | int
    question_request_id: str
    session_id: str
    received_at: float
    generation: int
    message: str
    questions: tuple[dict[str, Any], ...]
    field_specs: tuple[dict[str, Any], ...]


class _AcpJsonRpcChild:
    """Bounded JSONL JSON-RPC 2.0 child transport with a static method set."""

    def __init__(
        self,
        *,
        executable: Path,
        argv: tuple[str, ...],
        cwd: Path,
        allowed_methods: frozenset[str],
        on_notification: Callable[[Mapping[str, Any]], None],
        on_request: Callable[[Mapping[str, Any]], bool],
        on_disconnect: Callable[[str], None],
        max_message_bytes: int = _MAX_MESSAGE_BYTES,
        env: Mapping[str, str] | None = None,
        provider_settings: Mapping[str, str] | None = None,
    ) -> None:
        self._executable = Path(executable)
        self._argv = tuple(argv)
        self._cwd = Path(cwd)
        self._allowed_methods = frozenset(allowed_methods)
        self._on_notification = on_notification
        self._on_request = on_request
        self._on_disconnect = on_disconnect
        self._max_message_bytes = max(1024, min(int(max_message_bytes), 8 * 1024 * 1024))
        child_settings = {"NO_COLOR": "1"}
        child_settings.update(provider_settings or {})
        self._env = managed_child_environment(
            source=env,
            provider_settings=child_settings,
        )
        self._process: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._cleanup_process: subprocess.Popen | None = None
        self._cleanup_complete: threading.Event | None = None
        self._stderr_reader: threading.Thread | None = None
        self._write_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._pending: dict[int, _PendingResponse] = {}
        self._next_request_id = 1
        self._available = False
        self._closing = False
        self._disconnect_reason: str | None = None
        self._stderr_tail = deque(maxlen=32)

    @property
    def is_available(self) -> bool:
        with self._state_lock:
            return self._available

    @property
    def disconnect_reason(self) -> str | None:
        with self._state_lock:
            return self._disconnect_reason

    def start(self) -> None:
        start_error: BaseException | None = None
        with self._state_lock:
            if self._available:
                return
            if (
                self._process is not None
                or self._cleanup_process is not None
                or self._closing
            ):
                raise AcpUnavailableError("ACP child cannot be started twice")
            try:
                process = subprocess.Popen(
                    [str(self._executable), *self._argv],
                    cwd=str(self._cwd),
                    env=self._env,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=0,
                    start_new_session=True,
                    close_fds=True,
                )
            except (OSError, ValueError) as exc:
                raise AcpUnavailableError(
                    f"failed to start reviewed ACP child: {_bounded_text(exc, 240)}"
                ) from exc
            if process.stdin is None or process.stdout is None or process.stderr is None:
                self._terminate_process(process)
                self._close_process_streams(process)
                raise AcpUnavailableError("ACP child did not expose bounded stdio")
            self._process = process
            self._cleanup_process = process
            self._cleanup_complete = threading.Event()
            self._available = True
            try:
                stdout_reader = threading.Thread(
                    target=self._read_stdout,
                    name=f"pairling-acp-stdout-{process.pid}",
                    daemon=True,
                )
                stderr_reader = threading.Thread(
                    target=self._drain_stderr,
                    name=f"pairling-acp-stderr-{process.pid}",
                    daemon=True,
                )
                self._reader = stdout_reader
                self._stderr_reader = stderr_reader
                stdout_reader.start()
                stderr_reader.start()
            except BaseException as exc:
                start_error = exc
        if start_error is not None:
            self.close()
            raise start_error

    def request(self, method: str, params: Mapping[str, Any], *, timeout: float = _DEFAULT_REQUEST_TIMEOUT) -> Any:
        if method not in self._allowed_methods:
            raise AcpMethodNotAllowed(f"ACP method is not reviewed: {_bounded_text(method, 160)}")
        if not isinstance(params, Mapping):
            raise AcpProtocolError("ACP request params must be an object")
        with self._state_lock:
            if not self._available:
                raise AcpUnavailableError(self._disconnect_reason or "ACP child is unavailable")
            if len(self._pending) >= _MAX_PENDING_REQUESTS:
                raise AcpUnavailableError("ACP pending request bound reached")
            request_id = self._next_request_id
            self._next_request_id += 1
            pending = _PendingResponse(threading.Event())
            self._pending[request_id] = pending
        try:
            self._write_message(
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)}
            )
        except BaseException:
            with self._state_lock:
                self._pending.pop(request_id, None)
            raise
        if not pending.completed.wait(max(0.01, min(float(timeout), 600.0))):
            with self._state_lock:
                self._pending.pop(request_id, None)
            error = AcpTimeoutError(f"ACP request timed out: {method}")
            self._fail(str(error), error)
            raise error
        if pending.error is not None:
            raise pending.error
        return pending.result

    def notify(self, method: str, params: Mapping[str, Any]) -> None:
        if method not in self._allowed_methods:
            raise AcpMethodNotAllowed(f"ACP method is not reviewed: {_bounded_text(method, 160)}")
        self._write_message({"jsonrpc": "2.0", "method": method, "params": dict(params)})

    def respond(self, request_id: str | int, *, result: Any = None, error: Mapping[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
        if error is not None:
            message["error"] = dict(error)
        else:
            message["result"] = result
        self._write_message(message)

    def close(self) -> None:
        self._shutdown(
            reason="ACP child closed",
            error=AcpEOFError("ACP child closed"),
            closing=True,
            notify_disconnect=False,
        )

    def _shutdown(
        self,
        *,
        reason: str,
        error: BaseException,
        closing: bool,
        notify_disconnect: bool,
    ) -> None:
        pending: tuple[_PendingResponse, ...] = ()
        process: subprocess.Popen | None = None
        cleanup_process: subprocess.Popen | None = None
        cleanup_complete: threading.Event | None = None
        stdout_reader: threading.Thread | None = None
        stderr_reader: threading.Thread | None = None
        disconnect_reason: str | None = None
        owns_cleanup = False
        with self._state_lock:
            if closing:
                self._closing = True
            elif self._closing or not self._available:
                return
            self._available = False
            if not closing:
                self._disconnect_reason = _bounded_text(reason, 512)
                disconnect_reason = self._disconnect_reason
            pending = tuple(self._pending.values())
            self._pending.clear()
            for item in pending:
                item.error = error
            process = self._process
            cleanup_process = self._cleanup_process
            cleanup_complete = self._cleanup_complete
            stdout_reader = self._reader
            stderr_reader = self._stderr_reader
            if process is not None:
                owns_cleanup = True
                self._process = None

        if owns_cleanup and process is not None:
            self._terminate_process(process)
            self._close_process_streams(process)
            self._join_readers(stdout_reader, stderr_reader)
            with self._state_lock:
                self._clear_stopped_readers(stdout_reader, stderr_reader)
                if self._cleanup_process is process:
                    self._cleanup_process = None
                if cleanup_complete is not None:
                    cleanup_complete.set()
                if self._cleanup_complete is cleanup_complete:
                    self._cleanup_complete = None
        elif (
            cleanup_process is not None
            and cleanup_complete is not None
            and threading.current_thread() not in (stdout_reader, stderr_reader)
        ):
            cleanup_complete.wait()
        if not owns_cleanup:
            self._join_readers(stdout_reader, stderr_reader)
            with self._state_lock:
                self._clear_stopped_readers(stdout_reader, stderr_reader)

        if notify_disconnect and disconnect_reason is not None:
            try:
                self._on_disconnect(disconnect_reason)
            except Exception:
                pass
        for item in pending:
            item.completed.set()

    @staticmethod
    def _terminate_process(process: subprocess.Popen) -> None:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    process.terminate()
                except OSError:
                    pass
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.wait()
            except OSError:
                pass
        except OSError:
            pass

    @staticmethod
    def _close_process_streams(process: subprocess.Popen) -> None:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is None or getattr(stream, "closed", False):
                continue
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    @staticmethod
    def _join_readers(*readers: threading.Thread | None) -> None:
        current = threading.current_thread()
        for reader in readers:
            if reader is None or reader is current or reader.ident is None:
                continue
            reader.join(timeout=1.0)

    def _clear_stopped_readers(
        self,
        stdout_reader: threading.Thread | None,
        stderr_reader: threading.Thread | None,
    ) -> None:
        if self._reader is stdout_reader and (
            stdout_reader is None or not stdout_reader.is_alive()
        ):
            self._reader = None
        if self._stderr_reader is stderr_reader and (
            stderr_reader is None or not stderr_reader.is_alive()
        ):
            self._stderr_reader = None

    def _write_message(self, message: Mapping[str, Any]) -> None:
        try:
            encoded = json.dumps(
                message,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8") + b"\n"
        except (TypeError, ValueError) as exc:
            raise AcpProtocolError("ACP message is not safe JSON") from exc
        if len(encoded) > _MAX_REQUEST_BYTES:
            raise AcpProtocolError("ACP request exceeds the bounded message size")
        with self._write_lock:
            with self._state_lock:
                process = self._process
                if not self._available or process is None or process.stdin is None:
                    raise AcpUnavailableError(self._disconnect_reason or "ACP child is unavailable")
            try:
                process.stdin.write(encoded)
                process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                self._fail("ACP child stdin closed", AcpEOFError("ACP child stdin closed"))
                raise AcpEOFError("ACP child stdin closed") from exc

    def _read_stdout(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        buffer = bytearray()
        try:
            while True:
                chunk = process.stdout.read(64 * 1024)
                if not chunk:
                    if buffer:
                        raise AcpProtocolError("ACP stdout ended with a partial JSONL frame")
                    raise AcpEOFError("ACP child stdout reached EOF")
                buffer.extend(chunk)
                while True:
                    newline = buffer.find(b"\n")
                    if newline < 0:
                        break
                    if newline > self._max_message_bytes:
                        raise AcpProtocolError("ACP stdout frame is oversized")
                    raw = bytes(buffer[:newline])
                    del buffer[: newline + 1]
                    if raw.endswith(b"\r"):
                        raw = raw[:-1]
                    if not raw:
                        continue
                    self._handle_frame(raw)
                if len(buffer) > self._max_message_bytes:
                    raise AcpProtocolError("ACP stdout frame is oversized")
        except BaseException as exc:
            if isinstance(exc, AcpProtocolError):
                reason = str(exc)
                error: BaseException = exc
            elif isinstance(exc, AcpEOFError):
                reason = str(exc)
                error = exc
            else:
                reason = f"ACP stdout failed: {_bounded_text(exc, 240)}"
                error = AcpProtocolError(reason)
            self._fail(reason, error)

    def _handle_frame(self, raw: bytes) -> None:
        try:
            message = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise AcpProtocolError("ACP stdout contained invalid JSON") from exc
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            raise AcpProtocolError("ACP stdout contained an invalid JSON-RPC envelope")
        method = message.get("method")
        if isinstance(method, str):
            if "id" in message:
                try:
                    handled = bool(self._on_request(message))
                except Exception:
                    handled = False
                if not handled:
                    self.respond(
                        message.get("id"),
                        error={"code": -32601, "message": "Method not found"},
                    )
            else:
                try:
                    self._on_notification(message)
                except Exception:
                    # Provider notifications cannot kill the reader.  The driver
                    # records only known, bounded notifications.
                    return
            return
        if "id" not in message:
            raise AcpProtocolError("ACP response lacks an id")
        response_id = message.get("id")
        if isinstance(response_id, bool) or not isinstance(response_id, int):
            # Pairling originates integer IDs only.  Foreign/late responses are
            # ignored rather than correlated to another request.
            return
        with self._state_lock:
            pending = self._pending.pop(response_id, None)
        if pending is None:
            return
        error = message.get("error")
        if error is not None:
            if isinstance(error, Mapping):
                code = error.get("code") if isinstance(error.get("code"), int) else None
                text = error.get("message", "request failed")
            else:
                code, text = None, "malformed ACP error"
            pending.error = AcpRPCError(code, text)
        elif "result" not in message:
            pending.error = AcpProtocolError("ACP response has neither result nor error")
        else:
            pending.result = message.get("result")
        pending.completed.set()

    def _drain_stderr(self) -> None:
        process = self._process
        if process is None or process.stderr is None:
            return
        buffer = bytearray()
        try:
            while True:
                chunk = process.stderr.read(4096)
                if not chunk:
                    return
                buffer.extend(chunk)
                while b"\n" in buffer:
                    raw, _, remainder = buffer.partition(b"\n")
                    buffer = bytearray(remainder)
                    self._stderr_tail.append(_bounded_text(raw.decode("utf-8", "replace"), 512))
                if len(buffer) > 4096:
                    self._stderr_tail.append(_bounded_text(buffer.decode("utf-8", "replace"), 512))
                    buffer.clear()
        except (OSError, ValueError):
            return

    def _fail(self, reason: str, error: BaseException) -> None:
        self._shutdown(
            reason=reason,
            error=error,
            closing=False,
            notify_disconnect=True,
        )


class ACPControlDriver:
    """One exact ACP child and one exact Pairling-managed session binding."""

    def __init__(
        self,
        *,
        binding: ProviderControlBinding,
        profile: AcpLaunchProfile,
        executable: Path,
        request_timeout: float = _DEFAULT_REQUEST_TIMEOUT,
        version_command: tuple[str, ...] | None = None,
    ) -> None:
        if profile.provider_id != binding.provider_id:
            raise AcpUnavailableError("ACP profile does not match provider binding")
        if binding.provider_version not in profile.accepted_versions:
            raise AcpUnavailableError("ACP profile does not match installed version")
        if binding.provider_channel not in profile.allowed_channels:
            raise AcpUnavailableError("ACP profile does not match provider channel")
        resolved = _resolved_executable(executable)
        self.binding = binding
        self.profile = profile
        self.executable = resolved
        self._request_timeout = max(0.1, min(float(request_timeout), 600.0))
        self._version_command = tuple(version_command) if version_command is not None else None
        if self._version_command is not None:
            observed = _canonical_acp_version(
                self.binding.provider_id,
                cli_version(self.executable, list(self._version_command)),
            )
            if observed != self.binding.provider_version:
                raise AcpUnavailableError(
                    "resolved ACP executable does not match the exact provider binding version"
                )
        self._executable_identity = _file_identity(self.executable)
        self._state_lock = threading.RLock()
        self._rpc: _AcpJsonRpcChild | None = None
        self._generation = 1
        self._event_seq = 0
        self._events: deque[dict[str, Any]] = deque(maxlen=_MAX_EVENTS)
        self._blocked_reason: str | None = "managed ACP launch context is not attached"
        self._workspace_root: Path | None = None
        self._session_root: Path | None = None
        self._launch_identity: dict[str, str] | None = None
        self._process_dir: Path | None = None
        self._cwd: Path | None = None
        self._native_session_id: str | None = None
        self._pairling_session_id: str | None = None
        self._session_instance_id: str | None = None
        self._initialize_result: dict[str, Any] = {}
        self._agent_capabilities: dict[str, Any] = {}
        self._session_state: dict[str, Any] = {}
        self._extension_metadata: dict[str, Any] = {
            "profile": _sanitize_json(profile.overlay_metadata),
            "initialize": {},
        }
        self._active_prompt = False
        self._pending_permissions: dict[str, _PendingPermission] = {}
        self._pending_elicitations: dict[str, _PendingElicitation] = {}
        self._latest_usage: dict[str, Any] | None = None
        self._latest_commands: list[dict[str, Any]] = []
        self._last_stop_reason: str | None = None
        self._canary_observations: dict[str, str] = {}
        self._auto_reject_permissions = False
        self._cancel_requested = False
        self._generation_invalidated = False
        self._sandbox_active = False
        self._last_advertised_operations: tuple[str, ...] = ()
        self._last_snapshot_session_id: str | None = None
        self._last_snapshot_generation = 0
        self._last_snapshot_valid_until = 0.0
        self._receipts: dict[
            tuple[int, str],
            tuple[str, str | None, str, ProviderOperationResult],
        ] = {}
        self._receipt_order: deque[tuple[int, str]] = deque(maxlen=512)

    @property
    def capability_generation(self) -> int:
        with self._state_lock:
            return self._generation

    @property
    def extension_metadata(self) -> dict[str, Any]:
        with self._state_lock:
            return _sanitize_json(self._extension_metadata)

    @property
    def is_available(self) -> bool:
        with self._state_lock:
            return bool(self._rpc and self._rpc.is_available and self._native_session_id and not self._blocked_reason)

    def _assert_executable_identity(self) -> None:
        if _file_identity(self.executable) != self._executable_identity:
            raise AcpUnavailableError("resolved ACP executable identity changed before launch")
        if self._version_command is not None:
            observed = _canonical_acp_version(
                self.binding.provider_id,
                cli_version(self.executable, list(self._version_command)),
            )
            if observed != self.binding.provider_version:
                raise AcpUnavailableError(
                    "resolved ACP executable version changed before launch"
                )

    def attach_managed_launch(
        self,
        *,
        workspace_root: str,
        session_root: str,
        launch_identity: Mapping[str, Any],
    ) -> None:
        """Attach the one server-owned launch boundary; never accepts operation input."""

        expected_keys = {"binding_id", "launch_action_id", "source_install_id"}
        if not isinstance(launch_identity, Mapping) or set(launch_identity) != expected_keys:
            raise AcpUnavailableError("managed launch identity has an invalid shape")
        normalized_identity: dict[str, str] = {}
        for key in sorted(expected_keys):
            value = launch_identity.get(key)
            if not isinstance(value, str) or not value or len(value) > 256 or any(ch in value for ch in "\r\n\0"):
                raise AcpUnavailableError(f"managed launch identity has invalid {key}")
            normalized_identity[key] = value
        if normalized_identity["binding_id"] != self.binding.binding_id:
            raise AcpStaleBinding("managed launch binding is stale")
        workspace = _existing_absolute_directory(workspace_root, "workspace_root")
        state = _existing_absolute_directory(session_root, "session_root")
        if _is_within(workspace, state) or _is_within(state, workspace):
            raise AcpUnavailableError("managed workspace and process state roots must be disjoint")
        with self._state_lock:
            incoming = (workspace, state, normalized_identity)
            existing = (self._workspace_root, self._session_root, self._launch_identity)
            if self._workspace_root is not None:
                if existing != incoming:
                    raise AcpStaleBinding("managed ACP launch context cannot be rebound")
                return
            self._workspace_root = workspace
            self._session_root = state
            self._launch_identity = normalized_identity
            self._blocked_reason = "structured ACP session has not been launched"

    def launch_session(
        self,
        *,
        project: str,
        title: str,
        first_prompt: str = "",
        pairling_session_id: str | None = None,
    ) -> dict[str, Any]:
        del title  # ACP v1 session/new has no title field.
        with self._state_lock:
            workspace_root = self._workspace_root
            session_root = self._session_root
            if workspace_root is None or session_root is None or self._launch_identity is None:
                raise AcpUnavailableError("managed ACP launch context is not attached")
            if self._rpc is not None:
                raise AcpUnavailableError("ACP driver already owns a child session")
        cwd = _existing_absolute_directory(project, "project")
        if cwd != workspace_root:
            raise AcpUnavailableError("launch project does not match the server-owned workspace root")
        process_root = _secure_child_directory(session_root, "acp-provider-sessions")
        session_name = hashlib.sha256(
            f"{self.binding.binding_id}\0{self._launch_identity['launch_action_id']}".encode("utf-8")
        ).hexdigest()[:32]
        process_dir = _secure_child_directory(process_root, session_name, exclusive=True)
        config_dir: Path | None = None
        if self.profile.managed_files:
            config_dir = _secure_child_directory(process_dir, "managed-config", exclusive=True)
            _write_managed_profile_files(config_dir, self.profile)
        rendered = self.profile.materialize(
            cwd=cwd,
            session_dir=process_dir,
            trusted_workspace_root=workspace_root,
            trusted_session_root=process_root,
            managed_config_path=config_dir,
            mcp_allowlist=(),
        )
        if isinstance(rendered, AcpProfileUnavailable):
            raise AcpUnavailableError(f"{rendered.code}: {rendered.reason}")
        self._assert_executable_identity()
        rpc_executable = self.executable
        rpc_argv = rendered
        rpc_provider_settings: Mapping[str, str] | None = None
        seatbelt = self.profile.overlay_metadata.get("seatbelt")
        if isinstance(seatbelt, Mapping):
            if sys.platform != "darwin":
                raise AcpUnavailableError("reviewed ACP seatbelt profile requires macOS")
            policy_name = seatbelt.get("profile")
            expected_digest = seatbelt.get("sha256")
            if not isinstance(policy_name, str) or "/" in policy_name or not policy_name.endswith(".sb"):
                raise AcpUnavailableError("reviewed ACP seatbelt profile name is invalid")
            if not isinstance(expected_digest, str) or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
                raise AcpUnavailableError("reviewed ACP seatbelt profile digest is invalid")
            policy_path = Path(__file__).with_name(policy_name).resolve()
            try:
                policy_bytes = policy_path.read_bytes()
            except OSError as exc:
                raise AcpUnavailableError("reviewed ACP seatbelt profile is unavailable") from exc
            if hashlib.sha256(policy_bytes).hexdigest() != expected_digest:
                raise AcpUnavailableError("reviewed ACP seatbelt profile digest changed")
            sandbox_exec = Path("/usr/bin/sandbox-exec")
            if not sandbox_exec.is_file() or not os.access(sandbox_exec, os.X_OK):
                raise AcpUnavailableError("macOS sandbox-exec is unavailable")
            temporary_root = Path(os.environ.get("TMPDIR") or "/tmp").expanduser().resolve()
            home_root = Path(os.environ.get("HOME") or str(Path.home())).expanduser().resolve()
            definitions = (
                ("TARGET_DIR", cwd),
                ("TMP_DIR", temporary_root),
                ("HOME_DIR", home_root),
                ("CACHE_DIR", temporary_root),
                ("INCLUDE_DIR_0", Path("/dev/null")),
                ("INCLUDE_DIR_1", Path("/dev/null")),
                ("INCLUDE_DIR_2", Path("/dev/null")),
                ("INCLUDE_DIR_3", Path("/dev/null")),
                ("INCLUDE_DIR_4", Path("/dev/null")),
            )
            seatbelt_args: list[str] = []
            for name, value in definitions:
                seatbelt_args.extend(("-D", f"{name}={value}"))
            rpc_executable = sandbox_exec
            rpc_argv = (
                *seatbelt_args,
                "-f",
                str(policy_path),
                str(self.executable),
                *rendered,
            )
            rpc_provider_settings = {"SANDBOX": "sandbox-exec"}
            self._sandbox_active = True
        rpc = _AcpJsonRpcChild(
            executable=rpc_executable,
            argv=rpc_argv,
            cwd=cwd,
            allowed_methods=_allowed_methods_for_profile(self.profile),
            on_notification=self._on_notification,
            on_request=self._on_request,
            on_disconnect=self._on_disconnect,
            provider_settings=rpc_provider_settings,
        )
        with self._state_lock:
            self._generation += 1
            generation = self._generation
            self._rpc = rpc
            self._cwd = cwd
            self._process_dir = process_dir
            self._blocked_reason = "ACP initialize has not completed"
            self._generation_invalidated = False
        try:
            rpc.start()
            initialize = rpc.request(
                "initialize",
                {
                    "protocolVersion": self.profile.protocol_version,
                    "clientCapabilities": {
                        "fs": {"readTextFile": False, "writeTextFile": False},
                        "terminal": False,
                        "elicitation": {"form": {}},
                    },
                    "clientInfo": {"name": "Pairling", "version": "1"},
                },
                timeout=min(self._request_timeout, 30.0),
            )
            initialize_result = _require_mapping(initialize, "ACP initialize result")
            if initialize_result.get("protocolVersion") != 1:
                raise AcpUnavailableError("ACP protocol version is not the reviewed v1")
            agent_capabilities = _plain_mapping(initialize_result.get("agentCapabilities"))
            failures = _required_initialize_failures(self.profile, initialize_result)
            if failures:
                raise AcpUnavailableError(
                    "reviewed ACP capability mismatch: " + ", ".join(failures[:8])
                )
            with self._state_lock:
                self._initialize_result = _sanitize_json(initialize_result)
                self._agent_capabilities = agent_capabilities
                self._extension_metadata["initialize"] = _sanitize_json(
                    initialize_result.get("_meta") if isinstance(initialize_result.get("_meta"), Mapping) else {}
                )
            session_result = rpc.request(
                "session/new",
                {"cwd": str(cwd), "mcpServers": []},
                timeout=self._request_timeout,
            )
            session = _require_mapping(session_result, "ACP session/new result")
            native_id = _safe_id(session.get("sessionId"), "native ACP session id")
            default_pairling = f"{self.binding.provider_id}:{native_id}"
            managed_id = _safe_id(pairling_session_id or default_pairling, "Pairling session id")
            session_instance_id = f"{self.binding.binding_id}:{generation}:{native_id}"
            with self._state_lock:
                self._native_session_id = native_id
                self._pairling_session_id = managed_id
                self._session_instance_id = session_instance_id
                self._session_state = _sanitize_json(session)
                self._blocked_reason = None
                baseline_cursor = self._cursor()
            self._update_session_state(session)
            self._observe_launch_canaries(
                rendered=rendered,
                initialize=initialize_result,
                session=session,
                cwd=cwd,
            )
            self._publish("lifecycle", {"status": "running", "native_session_id": native_id})
            if first_prompt:
                if not isinstance(first_prompt, str) or len(first_prompt.encode("utf-8")) > 200_000:
                    raise AcpUnavailableError("first prompt exceeds the reviewed bound")
                self._auto_reject_permissions = True
                try:
                    self._prompt(first_prompt, ())
                finally:
                    self._auto_reject_permissions = False
            attestation = self.provider_canary_attestation()
            return {
                "native_session_id": native_id,
                "session_id": native_id,
                "capability_generation": generation,
                "provider_cursor": baseline_cursor,
                "session_instance_id": session_instance_id,
                "provider_canary_attestation": attestation,
                "missing_canaries": list(self.missing_canaries()),
            }
        except BaseException as exc:
            self._invalidate(f"ACP launch failed: {_bounded_text(exc, 320)}")
            raise

    def verify_managed_launch(self, result: Mapping[str, Any]) -> bool:
        expected_fields = {
            "native_session_id",
            "session_id",
            "capability_generation",
            "provider_cursor",
            "session_instance_id",
            "provider_canary_attestation",
            "missing_canaries",
        }
        try:
            with self._state_lock:
                rpc = self._rpc
                native_id = self._native_session_id
                pairling_session_id = self._pairling_session_id
                session_instance_id = self._session_instance_id
                generation = self._generation
                blocked_reason = self._blocked_reason
                cwd = self._cwd
            if (
                set(result) != expected_fields
                or rpc is None
                or not rpc.is_available
                or native_id is None
                or pairling_session_id is None
                or session_instance_id is None
                or cwd is None
                or blocked_reason is not None
                or result.get("native_session_id") != native_id
                or result.get("session_id") != native_id
                or result.get("capability_generation") != generation
                or result.get("session_instance_id") != session_instance_id
                or result.get("missing_canaries") != []
                or not isinstance(result.get("provider_cursor"), str)
                or not result["provider_cursor"].startswith(f"acp:{generation}:")
            ):
                return False
            attestation = validate_canary_attestation(
                self.profile,
                result.get("provider_canary_attestation"),
                binding_id=self.binding.binding_id,
                session_id=pairling_session_id,
                capability_generation=generation,
            )
            return not isinstance(attestation, AcpProfileUnavailable)
        except Exception:
            return False

    def load_session(self, *, native_session_id: str, project: str) -> dict[str, Any]:
        rpc, native_id, cwd = self._live_rpc()
        requested = _safe_id(native_session_id, "native ACP session id")
        if requested != native_id:
            raise AcpStaleBinding("session/load cannot replace the owned native session identity")
        if _existing_absolute_directory(project, "project") != cwd:
            raise AcpUnavailableError("load project does not match the owned workspace")
        if not _capability_bool(self._agent_capabilities, "loadSession"):
            raise AcpUnavailableError("ACP agent did not negotiate session/load")
        result = _require_mapping(
            rpc.request(
                "session/load",
                {"sessionId": requested, "cwd": str(cwd), "mcpServers": []},
                timeout=self._request_timeout,
            ),
            "ACP session/load result",
        )
        returned = result.get("sessionId", requested)
        if returned != requested:
            raise AcpProtocolError("ACP session/load returned a different session")
        self._update_session_state(result)
        return {"native_session_id": requested, "provider_cursor": self._cursor()}

    def list_sessions(self, *, cwd: str) -> dict[str, Any]:
        rpc, _, owned_cwd = self._live_rpc()
        if _existing_absolute_directory(cwd, "cwd") != owned_cwd:
            raise AcpUnavailableError("session/list cwd does not match the owned workspace")
        if not _nested_bool(self._agent_capabilities, "sessionCapabilities", "list"):
            raise AcpUnavailableError("ACP agent did not negotiate session/list")
        result = _require_mapping(
            rpc.request(
                "session/list",
                {"cwd": str(owned_cwd), "cursor": None},
                timeout=self._request_timeout,
            ),
            "ACP session/list result",
        )
        sessions: list[dict[str, Any]] = []
        raw_sessions = result.get("sessions")
        if isinstance(raw_sessions, list):
            for item in raw_sessions[:_MAX_LISTED_SESSIONS]:
                if not isinstance(item, Mapping):
                    continue
                session_id = item.get("sessionId")
                if not isinstance(session_id, str) or not session_id:
                    continue
                safe = {"session_id": _bounded_text(session_id, 512)}
                for source, target in (("title", "title"), ("updatedAt", "updated_at")):
                    value = item.get(source)
                    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                        safe[target] = _sanitize_json(value)
                sessions.append(safe)
        cursor = result.get("nextCursor")
        return {
            "sessions": sessions,
            "next_cursor": _bounded_text(cursor, 512) if isinstance(cursor, str) else None,
        }
    def missing_canaries(self) -> tuple[str, ...]:
        with self._state_lock:
            observed = set(self._canary_observations)
        return tuple(name for name in self.profile.required_canaries if name not in observed)

    def provider_canary_attestation(self) -> dict[str, Any] | None:
        """Return an exact validator-compatible proof only after every canary."""

        missing = self.missing_canaries()
        with self._state_lock:
            session_id = self._pairling_session_id
            generation = self._generation
            observations = {
                name: self._canary_observations[name]
                for name in self.profile.required_canaries
                if name in self._canary_observations
            }
        if missing or not session_id:
            return None
        now = time.time()
        evidence = json.dumps(
            observations,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        payload = {
            "schema_version": 1,
            "provider_id": self.binding.provider_id,
            "provider_version": self.binding.provider_version,
            "provider_channel": self.binding.provider_channel,
            "profile_digest": self.profile.safe_launch_digest,
            "managed_config_digest": self.profile.managed_config_digest,
            "binding_id": self.binding.binding_id,
            "session_id": session_id,
            "capability_generation": generation,
            "canaries": list(self.profile.required_canaries),
            "evidence_digest": hashlib.sha256(evidence).hexdigest(),
            "observed_at": now,
            "expires_at": now + 300.0,
        }
        from .acp_profiles import validate_canary_attestation

        validated = validate_canary_attestation(
            self.profile,
            payload,
            binding_id=self.binding.binding_id,
            session_id=session_id,
            capability_generation=generation,
            now=now,
        )
        return None if isinstance(validated, AcpProfileUnavailable) else payload

    def _observe_canary(self, name: str, evidence: Any) -> None:
        if name not in self.profile.required_canaries:
            return
        encoded = json.dumps(
            _sanitize_json(evidence),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        with self._state_lock:
            self._canary_observations.setdefault(name, hashlib.sha256(encoded).hexdigest())

    def _observe_launch_canaries(
        self,
        *,
        rendered: tuple[str, ...],
        initialize: Mapping[str, Any],
        session: Mapping[str, Any],
        cwd: Path,
    ) -> None:
        self._observe_canary(
            "initialize_capabilities",
            {
                "protocol_version": initialize.get("protocolVersion"),
                "agent_info": initialize.get("agentInfo"),
                "capabilities": initialize.get("agentCapabilities"),
            },
        )
        self._observe_canary(
            "cwd_boundary",
            {"cwd": str(cwd), "process_cwd": str(self._cwd), "mcp_servers": []},
        )
        self._observe_canary(
            "binding_generation_session_action_correlation",
            {
                "binding_id": self.binding.binding_id,
                "generation": self._generation,
                "session_id": session.get("sessionId"),
            },
        )
        modes = session.get("modes")
        if isinstance(modes, Mapping):
            current = modes.get("currentModeId")
            available = modes.get("availableModes")
            if current == "default" or (
                isinstance(available, list)
                and any(isinstance(item, Mapping) and item.get("id") == "default" for item in available)
            ):
                self._observe_canary("session_mode_default", modes)
        if self._models():
            self._observe_canary("model_catalog_nonempty", {"models": self._models()})
            self._observe_canary("model_state_present", {"models": self._models()})
        if "--approval-mode=default" in rendered or (
            "--permission-mode" in rendered and "default" in rendered
        ):
            self._observe_canary("approval_mode_default", rendered)
        if "--approval-mode" in rendered and "always-ask" in rendered:
            self._observe_canary("approval_mode_always_ask", rendered)
        if "--sandbox" in rendered or self._sandbox_active:
            self._observe_canary("sandbox_active", rendered)
        if "--sandbox" in rendered and "workspace" in rendered:
            self._observe_canary("workspace_sandbox_active", rendered)
        if str(cwd) == str(self._cwd):
            self._observe_canary("folder_trust_exact_cwd", str(cwd))
        if "--allowed-mcp-server-names=pairling-no-mcp" in rendered:
            self._observe_canary("mcp_allowlist_enforced", rendered)
        self._observe_canary(
            "client_fs_root_only",
            {
                "read_text_file": False,
                "write_text_file": False,
                "terminal": False,
                "elicitation_form": True,
            },
        )
        if all(flag in rendered for flag in ("--no-extensions", "--no-skills", "--no-rules")):
            self._observe_canary("extensions_skills_rules_plan_disabled", rendered)
        if "--no-leader" in rendered:
            self._observe_canary("no_leader_local_process", rendered)
        if self.profile.provider_id == "hermes_agent" and "--accept-hooks" not in rendered:
            self._observe_canary("no_accept_hooks_arg", rendered)
        meta = initialize.get("_meta")
        if isinstance(meta, Mapping):
            if meta.get("grokShell") is True:
                self._observe_canary("grok_shell_metadata", meta)
            if isinstance(meta.get("agentVersion"), str):
                self._observe_canary("agent_version_metadata", meta.get("agentVersion"))
        if not self.profile.allow_mcp:
            self._observe_canary("no_transport_mcp", {"mcp_servers": [], "allow_mcp": False})
        if initialize.get("protocolVersion") == 1:
            self._observe_canary(
                "negotiated_documented_acp_only",
                {"protocol_version": 1, "allowed_methods": sorted(_allowed_methods_for_profile(self.profile))},
            )

    def snapshot(
        self,
        *,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderControlSnapshot:
        self._expire_pending_inputs()
        with self._state_lock:
            now = time.time()
            operations: list[str] = []
            values: list[ControlValue] = []
            choices: list[ControlChoices] = []
            blocked = self._blocked_reason
            rpc_live = bool(self._rpc and self._rpc.is_available)
            exact_session = self._exact_session_truth(session_id, session_truth)
            attested = self._canaries_attested(session_truth) if exact_session else False
            if session_id is None:
                # Canary attestations are bound to one Pairling-owned session.
                # Provider-wide RPC remains an internal read-only diagnostic
                # surface until a separate provider attestation contract exists.
                operations = []
                if blocked is None:
                    blocked = "provider-wide ACP controls lack a session-bound canary attestation"
            elif rpc_live and exact_session and attested and blocked is None:
                operations.append("session.prompt.send")
                if self._active_prompt:
                    operations.append("session.turn.interrupt")
                models = self._models()
                if models and self._model_setter_available():
                    operations.append("session.model.set")
                    choices.append(
                        ControlChoices(
                            "session.model.set",
                            "model",
                            tuple(ControlChoice(value, label) for value, label in models),
                        )
                    )
                modes = self._safe_modes()
                if modes:
                    operations.append("session.permissions.set")
                    choices.append(
                        ControlChoices(
                            "session.permissions.set",
                            "permissions",
                            tuple(ControlChoice(value, label) for value, label in modes),
                        )
                    )
                pending = tuple(self._pending_permissions.values())
                if pending:
                    operations.append("session.approval.decide")
                    approval_choices = tuple(
                        ControlChoice(item.approval_id, "Pending permission request") for item in pending
                    )
                    decisions: dict[str, str] = {}
                    for item in pending:
                        for public_decision, (_, label) in item.options.items():
                            decisions.setdefault(public_decision, label)
                    choices.extend(
                        (
                            ControlChoices("session.approval.decide", "approval_id", approval_choices),
                            ControlChoices(
                                "session.approval.decide",
                                "decision",
                                tuple(ControlChoice(value, label) for value, label in decisions.items()),
                            ),
                        )
                    )
                pending_questions = tuple(self._pending_elicitations.values())
                if pending_questions:
                    operations.append("session.question.answer")
                    choices.extend(
                        (
                            ControlChoices(
                                "session.question.answer",
                                "question_request_id",
                                tuple(
                                    ControlChoice(
                                        item.question_request_id,
                                        _bounded_text(item.message, 160),
                                    )
                                    for item in pending_questions
                                ),
                            ),
                            ControlChoices(
                                "session.question.answer",
                                "decision",
                                (
                                    ControlChoice("accept", "Submit answers"),
                                    ControlChoice("cancel", "Cancel request"),
                                ),
                            ),
                        )
                    )
                    for item in pending_questions:
                        values.extend(
                            (
                                ControlValue(
                                    "session.question.answer",
                                    "question_request_id",
                                    item.question_request_id,
                                ),
                                ControlValue(
                                    "session.question.answer",
                                    "answers",
                                    list(item.questions),
                                ),
                            )
                        )
                released = released_operation_ids_for_provider(
                    self.binding.provider_id
                )
                operations = [
                    operation_id
                    for operation_id in operations
                    if operation_id in released
                ]
                identity = ProviderSessionIdentity(
                    self.binding.provider_id,
                    session_id,
                    self.binding.binding_id,
                    self._generation,
                ).to_payload()
                for operation_id in operations:
                    if operation_id.startswith("session."):
                        values.append(ControlValue(operation_id, "session", identity))
            elif session_id is not None and blocked is None:
                if not exact_session:
                    blocked = "managed ACP session identity is stale or mismatched"
                elif not attested:
                    blocked = "provider canary attestation is missing or stale"
                else:
                    blocked = "managed ACP child is disconnected"
            self._last_advertised_operations = tuple(operations)
            self._last_snapshot_session_id = session_id
            self._last_snapshot_generation = self._generation
            self._last_snapshot_valid_until = now + 5.0
            return ProviderControlSnapshot(
                provider_id=self.binding.provider_id,
                provider_version=self.binding.provider_version,
                provider_channel=self.binding.provider_channel,
                binding_id=self.binding.binding_id,
                capability_generation=self._generation,
                observed_at=now,
                valid_until=now + 5.0,
                advertised_operations=tuple(operations),
                values=tuple(values),
                choices=tuple(choices),
                blocked_reason=blocked,
                provider_cursor=self._cursor(),
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
            or capability_generation != self.capability_generation
            or not self._exact_session_truth(session_id, session_truth)
            or not self._canaries_attested(session_truth)
            or self._last_snapshot_session_id != session_id
            or self._last_snapshot_generation != capability_generation
            or operation_id not in self._last_advertised_operations
            or time.time() > self._last_snapshot_valid_until
        ):
            raise AcpStaleBinding(
                "ACP operation correlation proof is unavailable"
            )
        return ProviderOperationCorrelation(
            _operation_receipt_id(
                capability_generation,
                client_action_id,
            ),
            self._cursor(),
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
        if binding_id != self.binding.binding_id or capability_generation != self.capability_generation:
            raise AcpStaleBinding("ACP provider binding or generation is stale")
        try:
            definition = REVIEWED_OPERATION_CATALOG.require(operation_id)
            payload = definition.validate_input_payload(input_payload)
        except OperationCatalogError as exc:
            raise AcpUnavailableError(str(exc)) from exc
        with self._state_lock:
            snapshot_is_live = (
                self._last_snapshot_generation == self._generation
                and self._last_snapshot_session_id == session_id
                and time.time() <= self._last_snapshot_valid_until
                and operation_id in self._last_advertised_operations
            )
        if not snapshot_is_live:
            raise AcpUnavailableError(f"ACP operation is not currently negotiated: {operation_id}")
        expected_operation_id = _operation_receipt_id(
            self._generation,
            client_action_id,
        )
        if provider_correlation is None:
            provider_correlation = ProviderOperationCorrelation(
                expected_operation_id,
                self._cursor(),
            )
        elif (
            not isinstance(provider_correlation, ProviderOperationCorrelation)
            or provider_correlation.provider_operation_id
            != expected_operation_id
        ):
            raise AcpStaleBinding("ACP operation correlation is stale")
        if session_id is not None and "session" in payload:
            self._validate_session_payload(payload, session_id)
        request_digest = _operation_request_digest(
            operation_id,
            payload,
            prepared_attachments,
        )
        receipt_key = (self._generation, client_action_id)
        with self._state_lock:
            prior = self._receipts.get(receipt_key)
        if prior is not None:
            prior_operation, prior_session, prior_digest, prior_result = prior
            if (
                prior_operation != operation_id
                or prior_session != session_id
                or not secrets.compare_digest(prior_digest, request_digest)
            ):
                raise AcpStaleBinding("client action id is already bound to another ACP request")
            return prior_result
        public: dict[str, Any]
        if operation_id == "session.prompt.send":
            result = self._prompt(str(payload["prompt"]), prepared_attachments)
            public = {
                "stop_reason": _bounded_text(result.get("stopReason", "unknown"), 160),
                "client_action_id": _bounded_text(client_action_id, 256),
            }
        elif operation_id == "session.turn.interrupt":
            rpc, native_id, _ = self._live_rpc()
            if not self._active_prompt:
                raise AcpUnavailableError("ACP session has no active prompt to cancel")
            self._cancel_requested = True
            rpc.notify("session/cancel", {"sessionId": native_id})
            self._publish("lifecycle", {"status": "cancelling"})
            public = {"cancelled": True}
        elif operation_id == "session.model.set":
            public = self._set_model(str(payload["model"]))
        elif operation_id == "session.permissions.set":
            public = self._set_mode(str(payload["permissions"]))
        elif operation_id == "session.approval.decide":
            public = self._decide_permission(
                approval_id=str(payload["approval_id"]),
                decision=str(payload["decision"]),
            )
        elif operation_id == "session.question.answer":
            public = self._answer_elicitation(
                question_request_id=str(payload["question_request_id"]),
                decision=str(payload["decision"]),
                answers=payload.get("answers"),
            )
        elif operation_id == "provider.auth.read":
            public = self._auth_status()
        elif operation_id == "provider.config.read":
            public = {
                "models": [{"id": value, "name": label} for value, label in self._models()],
                "modes": [{"id": value, "name": label} for value, label in self._safe_modes()],
            }
        elif operation_id == "provider.commands.read":
            public = {"commands": _sanitize_json(self._latest_commands)}
        elif operation_id == "provider.usage.read":
            public = {"usage": _sanitize_json(self._latest_usage or {})}
        elif operation_id == "provider.diagnostics.read":
            public = self._diagnostics()
        else:
            raise AcpUnavailableError(f"reviewed ACP operation has no driver mapping: {operation_id}")
        result = ProviderOperationResult(
            operation_id=operation_id,
            provider_operation_id=provider_correlation.provider_operation_id,
            status=OperationResultStatus.APPLIED,
            public_result=_sanitize_json(public),
            provider_cursor=provider_correlation.provider_cursor,
        )
        result.validate()
        with self._state_lock:
            if len(self._receipt_order) == self._receipt_order.maxlen:
                oldest = self._receipt_order.popleft()
                self._receipts.pop(oldest, None)
            self._receipt_order.append(receipt_key)
            self._receipts[receipt_key] = (
                operation_id,
                session_id,
                request_digest,
                result,
            )
        return result
 
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
        if (
            binding_id != self.binding.binding_id
            or capability_generation != self.capability_generation
            or (session_id is not None and not self._exact_session_truth(session_id, session_truth))
            or (session_id is not None and not self._canaries_attested(session_truth))
        ):
            raise AcpStaleBinding("ACP recovery binding is stale")
        with self._state_lock:
            prior = self._receipts.get((capability_generation, client_action_id))
        if prior is None:
            return None
        prior_operation, prior_session, _, result = prior
        if prior_operation != operation_id or prior_session != session_id:
            raise AcpStaleBinding("ACP recovery action identity is mismatched")
        if result.provider_operation_id != provider_correlation.provider_operation_id:
            return None
        if (
            provider_correlation.provider_cursor is not None
            and result.provider_cursor != provider_correlation.provider_cursor
        ):
            return None
        return result

    def poll_events(self, cursor: str | None) -> list[dict[str, Any]]:
        self._expire_pending_inputs()
        with self._state_lock:
            if cursor in (None, ""):
                after = 0
            else:
                match = _CURSOR_RE.fullmatch(str(cursor))
                if match is None or int(match.group(1)) != self._generation:
                    raise AcpCursorExpired("ACP event cursor belongs to another generation")
                after = int(match.group(2))
            if self._events and after < self._events[0]["sequence"] - 1:
                raise AcpCursorExpired("ACP event cursor fell behind the bounded queue")
            return [dict(event) for event in self._events if event["sequence"] > after]

    def close(self) -> None:
        with self._state_lock:
            publish_closed = self._blocked_reason != "managed ACP session is closed"
            rpc = self._rpc
            self._blocked_reason = "managed ACP session is closed"
            self._active_prompt = False
            self._pending_permissions.clear()
            self._pending_elicitations.clear()
        if rpc is not None:
            rpc.close()
        if publish_closed:
            self._publish("lifecycle", {"status": "closed"})

    def _prompt(self, prompt: str, prepared_attachments: tuple[Any, ...]) -> dict[str, Any]:
        rpc, native_id, _ = self._live_rpc()
        blocks: list[dict[str, Any]] = [{"type": "text", "text": prompt}]
        blocks.extend(self._attachment_blocks(prepared_attachments))
        with self._state_lock:
            if self._active_prompt:
                raise AcpUnavailableError("ACP session already has an active prompt")
            self._active_prompt = True
        self._publish("lifecycle", {"status": "running"})
        try:
            result = _require_mapping(
                rpc.request(
                    "session/prompt",
                    {"sessionId": native_id, "prompt": blocks},
                    timeout=self._request_timeout,
                ),
                "ACP session/prompt result",
            )
            stop = result.get("stopReason")
            with self._state_lock:
                self._last_stop_reason = _bounded_text(stop, 160) if stop is not None else None
                cancelled = self._cancel_requested
                self._cancel_requested = False
            if cancelled and isinstance(stop, str) and "cancel" in stop.casefold():
                correlation = {
                    "session_id": native_id,
                    "stop_reason": _bounded_text(stop, 160),
                    "generation": self._generation,
                }
                self._observe_canary("cancel_correlation", correlation)
                self._observe_canary("cancellation_exact_request", correlation)
            self._publish(
                "lifecycle",
                {"status": "waiting", "stop_reason": self._last_stop_reason or "unknown"},
            )
            return dict(result)
        except (AcpTimeoutError, AcpEOFError, AcpProtocolError) as exc:
            self._invalidate(f"ACP prompt failed: {_bounded_text(exc, 320)}")
            raise AcpUnavailableError(str(exc)) from exc
        finally:
            with self._state_lock:
                self._active_prompt = False

    def _set_model(self, model: str) -> dict[str, Any]:
        models = {value for value, _ in self._models()}
        if model not in models:
            raise AcpUnavailableError("ACP model is not in the live negotiated choices")
        rpc, native_id, _ = self._live_rpc()
        config_id = self._model_config_id()
        if config_id is not None:
            result = rpc.request(
                "session/set_config_option",
                {"sessionId": native_id, "configId": config_id, "value": model},
                timeout=self._request_timeout,
            )
        elif "session/set_model" in _reviewed_extension_methods(self.profile):
            result = rpc.request(
                "session/set_model",
                {"sessionId": native_id, "modelId": model},
                timeout=self._request_timeout,
            )
        else:
            raise AcpUnavailableError("ACP model selector has no reviewed method")
        if isinstance(result, Mapping):
            self._update_session_state(result)
        return {"model": model}

    def _set_mode(self, mode: str) -> dict[str, Any]:
        modes = {value for value, _ in self._safe_modes()}
        if mode not in modes:
            raise AcpUnavailableError("ACP mode is unsafe or not live-negotiated")
        rpc, native_id, _ = self._live_rpc()
        result = rpc.request(
            "session/set_mode",
            {"sessionId": native_id, "modeId": mode},
            timeout=self._request_timeout,
        )
        if isinstance(result, Mapping):
            self._update_session_state(result)
        return {"mode": mode}

    def _decide_permission(self, *, approval_id: str, decision: str) -> dict[str, Any]:
        with self._state_lock:
            pending = self._pending_permissions.get(approval_id)
            if pending is None:
                raise AcpUnavailableError("ACP permission request is not pending")
            if pending.generation != self._generation or pending.native_session_id != self._native_session_id:
                raise AcpStaleBinding("ACP permission request binding is stale")
            selected = pending.options.get(decision)
            if selected is None:
                raise AcpUnavailableError("ACP permission decision is not offered or is unsafe")
            self._pending_permissions.pop(approval_id, None)
            rpc = self._rpc
        if rpc is None:
            raise AcpUnavailableError("ACP child is unavailable")
        option_id, _ = selected
        rpc.respond(
            pending.provider_request_id,
            result={"outcome": {"outcome": "selected", "optionId": option_id}},
        )
        self._publish(
            "permission_decision",
            {
                "approval_id": approval_id,
                "decision": decision,
                "tool_call_id": pending.tool_call_id,
            },
        )
        return {"approval_id": approval_id, "decision": decision}

    def _auth_status(self) -> dict[str, Any]:
        with self._state_lock:
            methods = self._initialize_result.get("authMethods")
            agent = self._initialize_result.get("agentInfo")
        safe_methods: list[dict[str, Any]] = []
        if isinstance(methods, list):
            for method in methods[:32]:
                if not isinstance(method, Mapping):
                    continue
                safe = {}
                for key in ("id", "name", "description"):
                    value = method.get(key)
                    if isinstance(value, str):
                        safe[key] = _bounded_text(value, 512)
                if safe:
                    safe_methods.append(safe)
        safe_agent = {}
        if isinstance(agent, Mapping):
            for key in ("name", "title", "version"):
                value = agent.get(key)
                if isinstance(value, str):
                    safe_agent[key] = _redacted_public_text(value, 512)
        return {
            "agent": safe_agent,
            "available_auth_methods": safe_methods,
            "authenticate_exposed": False,
        }

    def _diagnostics(self) -> dict[str, Any]:
        with self._state_lock:
            return {
                "transport": "acp_v1_stdio",
                "connected": bool(self._rpc and self._rpc.is_available),
                "agent": _sanitize_json(self._initialize_result.get("agentInfo", {})),
                "protocol_version": self._initialize_result.get("protocolVersion"),
                "capability_generation": self._generation,
                "profile_digest": self.profile.safe_launch_digest,
                "blocked_reason": self._blocked_reason,
            }

    def _on_notification(self, message: Mapping[str, Any]) -> None:
        method = message.get("method")
        if method not in _KNOWN_NOTIFICATIONS:
            return
        params = message.get("params")
        if not isinstance(params, Mapping):
            return
        native = params.get("sessionId")
        with self._state_lock:
            if native != self._native_session_id:
                return
        if method == "session/update":
            update = params.get("update")
            if not isinstance(update, Mapping):
                return
            kind, payload = _normalize_session_update(str(native), update)
            self._observe_canary(
                "typed_session_updates",
                {"kind": kind, "session_id": native, "sequence": self._event_seq + 1},
            )
            if kind == "usage":
                with self._state_lock:
                    self._latest_usage = _sanitize_json(payload.get("update", payload))
            elif kind == "commands":
                raw_commands = update.get("availableCommands") or update.get("commands")
                with self._state_lock:
                    self._latest_commands = _normalize_commands(raw_commands)
            self._publish(kind, payload)
            return
        if method in {"session/current_mode_update", "session/currentModeUpdate"}:
            value = params.get("currentModeId") or params.get("modeId")
            if isinstance(value, str):
                with self._state_lock:
                    modes = _plain_mapping(self._session_state.get("modes"))
                    modes["currentModeId"] = value
                    self._session_state["modes"] = modes
            self._publish("session_update", {"mode": _sanitize_json(value)})
            return
        if method in {"session/config_option_update", "session/configOptionUpdate"}:
            self._update_config_option(params)
            self._publish("session_update", {"config_option": _sanitize_json(params)})
            return
        self._publish("session_update", {"info": _sanitize_json(params)})

    def _on_request(self, message: Mapping[str, Any]) -> bool:
        method = message.get("method")
        if method in _REVERSE_ELICITATION_METHODS:
            return self._on_elicitation_request(message)
        if method not in _REVERSE_PERMISSION_METHODS:
            return False
        request_id = message.get("id")
        if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
            return False
        params = message.get("params")
        if not isinstance(params, Mapping):
            return False
        native_id = params.get("sessionId")
        with self._state_lock:
            if native_id != self._native_session_id or len(self._pending_permissions) >= _MAX_PENDING_PERMISSIONS:
                rpc = self._rpc
            else:
                rpc = None
        if rpc is not None:
            rpc.respond(request_id, result={"outcome": {"outcome": "cancelled"}})
            return True
        tool_call = params.get("toolCall")
        tool = tool_call if isinstance(tool_call, Mapping) else {}
        tool_call_id = tool.get("toolCallId") or tool.get("id")
        if not isinstance(tool_call_id, str) or not tool_call_id:
            tool_call_id = "unknown"
        options = _safe_permission_options(params.get("options"))
        if not options:
            with self._state_lock:
                rpc = self._rpc
            if rpc is not None:
                rpc.respond(request_id, result={"outcome": {"outcome": "cancelled"}})
            return True
        raw_options = params.get("options")
        raw_kinds = {
            str(item.get("kind") or "").casefold().replace("-", "_")
            for item in raw_options
            if isinstance(raw_options, list) and isinstance(item, Mapping)
        }
        permission_evidence = {
            "session_id": native_id,
            "request_id": str(request_id),
            "tool_call_id": tool_call_id,
            "kinds": sorted(raw_kinds),
        }
        self._observe_canary("permission_request_round_trip", permission_evidence)
        self._observe_canary("manual_permission_policy", permission_evidence)
        self._observe_canary("auto_approval_disabled", permission_evidence)
        if not any("always" in kind or "permanent" in kind for kind in raw_kinds):
            self._observe_canary("no_permanent_tool_approval", permission_evidence)
            self._observe_canary("permission_options.allow_once_only", permission_evidence)
        if "allow_once" in raw_kinds or "allow" in raw_kinds:
            self._observe_canary("permission_options.allow_once", permission_evidence)
        if "reject_once" in raw_kinds or "reject" in raw_kinds:
            self._observe_canary("permission_options.reject", permission_evidence)
        if {"allow", "reject"}.issubset(options):
            self._observe_canary("permission_outcomes.allow_once_reject", permission_evidence)
        if self._auto_reject_permissions and "reject" in options:
            with self._state_lock:
                rpc = self._rpc
            if rpc is None:
                return False
            rpc.respond(
                request_id,
                result={"outcome": {"outcome": "selected", "optionId": options["reject"][0]}},
            )
            self._observe_canary("permission_denial", permission_evidence)
            self._observe_canary("denied_write_no_side_effect", permission_evidence)
            self._publish(
                "permission_decision",
                {
                    "decision": "reject",
                    "tool_call_id": _bounded_text(tool_call_id, 512),
                    "qualification_canary": True,
                },
            )
            return True
        approval_id = "acp_" + secrets.token_urlsafe(18)
        pending = _PendingPermission(
            provider_request_id=request_id,
            approval_id=approval_id,
            native_session_id=str(native_id),
            tool_call_id=_bounded_text(tool_call_id, 512),
            received_at=time.monotonic(),
            generation=self.capability_generation,
            options=options,
        )
        with self._state_lock:
            self._pending_permissions[approval_id] = pending
        safe_tool = {}
        for key in ("toolCallId", "title", "status", "kind"):
            value = tool.get(key)
            if isinstance(value, str):
                safe_tool[_camel_to_snake(key)] = (
                    _bounded_text(value, 512)
                    if key == "toolCallId"
                    else _redacted_public_text(value, 1024)
                )
        self._publish(
            "permission_request",
            {
                "approval_id": approval_id,
                "tool_call": safe_tool,
                "tool_call_id": pending.tool_call_id,
                "decisions": list(options),
            },
        )
        return True

    def _on_elicitation_request(self, message: Mapping[str, Any]) -> bool:
        request_id = message.get("id")
        if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
            return False
        params = message.get("params")
        if not isinstance(params, Mapping):
            return False
        try:
            native_id, safe_message, questions, field_specs = _normalize_form_elicitation(params)
        except AcpProtocolError:
            with self._state_lock:
                rpc = self._rpc
            if rpc is not None:
                rpc.respond(request_id, result={"action": "cancel"})
            return True
        with self._state_lock:
            rpc = self._rpc
            invalid = (
                native_id != self._native_session_id
                or self._pairling_session_id is None
                or len(self._pending_elicitations) >= _MAX_PENDING_ELICITATIONS
            )
        if invalid:
            if rpc is not None:
                rpc.respond(request_id, result={"action": "cancel"})
            return True
        question_request_id = "acp_question_" + secrets.token_urlsafe(18)
        pending = _PendingElicitation(
            provider_request_id=request_id,
            question_request_id=question_request_id,
            session_id=native_id,
            received_at=time.monotonic(),
            generation=self.capability_generation,
            message=safe_message,
            questions=questions,
            field_specs=field_specs,
        )
        with self._state_lock:
            self._pending_elicitations[question_request_id] = pending
        self._publish(
            "questionnaire_requested",
            {
                "question_request_id": question_request_id,
                "message": safe_message,
                "questions": list(questions),
            },
        )
        return True

    def _answer_elicitation(
        self,
        *,
        question_request_id: str,
        decision: str,
        answers: Any,
    ) -> dict[str, Any]:
        with self._state_lock:
            pending = self._pending_elicitations.get(question_request_id)
            rpc = self._rpc
            native_id = self._native_session_id
            generation = self._generation
        if (
            pending is None
            or rpc is None
            or pending.session_id != native_id
            or pending.generation != generation
        ):
            raise AcpStaleBinding("ACP elicitation is no longer current")
        if decision == "cancel":
            if answers not in (None, []):
                raise AcpProtocolError("cancelled ACP elicitation must not include answers")
            content: dict[str, Any] | None = None
            response = {"action": "cancel"}
        elif decision == "accept":
            content = _validate_elicitation_answers(
                answers,
                pending.questions,
                pending.field_specs,
            )
            response = {"action": "accept", "content": content}
        else:
            raise AcpProtocolError("ACP elicitation decision is invalid")
        with self._state_lock:
            current = self._pending_elicitations.get(question_request_id)
            if current is not pending:
                raise AcpStaleBinding("ACP elicitation is no longer current")
            del self._pending_elicitations[question_request_id]
        try:
            rpc.respond(pending.provider_request_id, result=response)
        except AcpError:
            raise
        self._publish(
            "questionnaire_decision",
            {
                "question_request_id": question_request_id,
                "decision": decision,
                "answer_count": len(content or {}),
            },
        )
        return {"decision": decision, "answer_count": len(content or {})}

    def _on_disconnect(self, reason: str) -> None:
        self._invalidate(f"ACP child disconnected: {reason}", close_rpc=False)

    def _invalidate(self, reason: str, *, close_rpc: bool = True) -> None:
        with self._state_lock:
            rpc = self._rpc
            self._blocked_reason = _bounded_text(reason, 512)
            self._active_prompt = False
            self._pending_permissions.clear()
            self._pending_elicitations.clear()
            self._last_advertised_operations = ()
            self._last_snapshot_valid_until = 0.0
            if not self._generation_invalidated:
                self._generation += 1
                self._generation_invalidated = True
        if close_rpc and rpc is not None:
            rpc.close()
        self._publish("provider_unavailable", {"reason": self._blocked_reason})

    def _expire_pending_inputs(self) -> None:
        now = time.monotonic()
        expired_permissions: list[_PendingPermission] = []
        expired_elicitations: list[_PendingElicitation] = []
        with self._state_lock:
            for approval_id, pending in tuple(self._pending_permissions.items()):
                if now - pending.received_at >= _PERMISSION_TIMEOUT_SECONDS:
                    expired_permissions.append(self._pending_permissions.pop(approval_id))
            for question_id, pending in tuple(self._pending_elicitations.items()):
                if now - pending.received_at >= _ELICITATION_TIMEOUT_SECONDS:
                    expired_elicitations.append(self._pending_elicitations.pop(question_id))
            rpc = self._rpc
        if rpc is not None:
            for pending in expired_permissions:
                try:
                    rpc.respond(
                        pending.provider_request_id,
                        result={"outcome": {"outcome": "cancelled"}},
                    )
                except AcpError:
                    pass
                self._publish(
                    "permission_decision",
                    {"approval_id": pending.approval_id, "decision": "expired"},
                )
            for pending in expired_elicitations:
                try:
                    rpc.respond(pending.provider_request_id, result={"action": "cancel"})
                except AcpError:
                    pass
                self._publish(
                    "questionnaire_decision",
                    {
                        "question_request_id": pending.question_request_id,
                        "decision": "expired",
                    },
                )

    def _publish(self, kind: str, payload: Mapping[str, Any]) -> None:
        with self._state_lock:
            self._event_seq += 1
            event = {
                "sequence": self._event_seq,
                "provider_cursor": self._cursor(self._event_seq),
                "observed_at": time.time(),
                "kind": _bounded_text(kind, 80),
                "payload": _sanitize_json(payload),
                "provider_id": self.binding.provider_id,
                "binding_id": self.binding.binding_id,
                "capability_generation": self._generation,
            }
            if self._pairling_session_id is not None:
                event["session_id"] = self._pairling_session_id
            self._events.append(event)

    def _cursor(self, sequence: int | None = None) -> str:
        return f"acp:{self._generation}:{self._event_seq if sequence is None else sequence}"

    def _live_rpc(self) -> tuple[_AcpJsonRpcChild, str, Path]:
        with self._state_lock:
            rpc, native_id, cwd = self._rpc, self._native_session_id, self._cwd
            blocked = self._blocked_reason
        if rpc is None or not rpc.is_available or native_id is None or cwd is None or blocked is not None:
            raise AcpUnavailableError(blocked or "managed ACP child is unavailable")
        return rpc, native_id, cwd

    def _exact_session_truth(self, session_id: str | None, truth: Mapping[str, Any] | None) -> bool:
        if session_id is None or not isinstance(truth, Mapping):
            return False
        with self._state_lock:
            cwd = self._cwd
            expected = {
                "provider_id": self.binding.provider_id,
                "session_id": self._pairling_session_id,
                "binding_id": self.binding.binding_id,
                "capability_generation": self._generation,
                "native_id": self._native_session_id,
                "session_instance_id": self._session_instance_id,
            }
        if any(truth.get(key) != value for key, value in expected.items()):
            return False
        if session_id != self._pairling_session_id:
            return False
        if truth.get("managed") is not True or truth.get("owner") != "provider_driver":
            return False
        if truth.get("is_live") is not True or truth.get("controllable") is not True:
            return False
        if cwd is None:
            return False
        try:
            truth_cwd = Path(str(truth.get("cwd"))).resolve(strict=True)
            truth_project = Path(str(truth.get("project"))).resolve(strict=True)
        except (OSError, ValueError):
            return False
        return truth_cwd == cwd and truth_project == cwd

    def _canaries_attested(self, truth: Mapping[str, Any] | None) -> bool:
        if not self.profile.required_canaries:
            return True
        if not isinstance(truth, Mapping):
            return False
        raw = truth.get("provider_canary_attestation")
        # The profile module may provide the signature validator as canary
        # plumbing lands.  Until a server-owned proof is present and validates,
        # the snapshot is deliberately empty.
        try:
            from .acp_profiles import validate_canary_attestation
        except ImportError:
            return False
        try:
            result = validate_canary_attestation(
                self.profile,
                raw,
                binding_id=self.binding.binding_id,
                session_id=str(self._pairling_session_id or ""),
                capability_generation=self._generation,
            )
            return not isinstance(result, AcpProfileUnavailable)
        except (TypeError, ValueError):
            return False


    def _validate_session_payload(self, payload: Mapping[str, Any], session_id: str) -> None:
        raw = payload.get("session")
        try:
            identity = ProviderSessionIdentity.from_payload(raw)
        except Exception as exc:
            raise AcpStaleBinding("ACP operation has invalid session identity") from exc
        if (
            identity.provider_id != self.binding.provider_id
            or identity.session_id != session_id
            or identity.binding_id != self.binding.binding_id
            or identity.capability_generation != self.capability_generation
            or session_id != self._pairling_session_id
        ):
            raise AcpStaleBinding("ACP operation session identity is stale or mismatched")

    def _update_session_state(self, value: Mapping[str, Any]) -> None:
        safe = _sanitize_json(value)
        with self._state_lock:
            if isinstance(safe, dict):
                self._session_state.update(safe)

    def _update_config_option(self, params: Mapping[str, Any]) -> None:
        config = params.get("configOption") or params.get("option")
        if not isinstance(config, Mapping):
            return
        config_id = config.get("id")
        if not isinstance(config_id, str):
            return
        with self._state_lock:
            options = self._session_state.get("configOptions")
            normalized = list(options) if isinstance(options, list) else []
            for index, item in enumerate(normalized):
                if isinstance(item, Mapping) and item.get("id") == config_id:
                    normalized[index] = _sanitize_json(config)
                    break
            else:
                normalized.append(_sanitize_json(config))
            self._session_state["configOptions"] = normalized

    def _models(self) -> list[tuple[str, str]]:
        with self._state_lock:
            state = _sanitize_json(self._session_state)
        result: list[tuple[str, str]] = []
        seen: set[str] = set()
        config = state.get("configOptions") if isinstance(state, dict) else None
        if isinstance(config, list):
            for item in config:
                if not isinstance(item, Mapping):
                    continue
                category = str(item.get("category") or "").casefold()
                config_id = str(item.get("id") or "").casefold()
                if category != "model" and config_id != "model":
                    continue
                options = item.get("options")
                if not isinstance(options, list):
                    continue
                for option in options[:512]:
                    if not isinstance(option, Mapping):
                        continue
                    value = option.get("value", option.get("id"))
                    label = option.get("name", option.get("label", value))
                    if isinstance(value, str) and value and value not in seen:
                        seen.add(value)
                        result.append((_bounded_text(value, 256), _bounded_text(label, 160)))
        models = state.get("models") if isinstance(state, dict) else None
        if isinstance(models, Mapping):
            available = models.get("availableModels") or models.get("available")
        else:
            available = None
        if isinstance(available, list):
            for item in available[:512]:
                if not isinstance(item, Mapping):
                    continue
                value = item.get("modelId", item.get("id"))
                label = item.get("name", value)
                if isinstance(value, str) and value and value not in seen:
                    seen.add(value)
                    result.append((_bounded_text(value, 256), _bounded_text(label, 160)))
        return result

    def _model_config_id(self) -> str | None:
        with self._state_lock:
            config = self._session_state.get("configOptions")
        if not isinstance(config, list):
            return None
        for item in config:
            if not isinstance(item, Mapping):
                continue
            config_id = item.get("id")
            category = str(item.get("category") or "").casefold()
            if isinstance(config_id, str) and (category == "model" or config_id.casefold() == "model"):
                return config_id
        return None

    def _model_setter_available(self) -> bool:
        return (
            self._model_config_id() is not None
            or "session/set_model"
            in _reviewed_extension_methods(self.profile)
        )

    def _safe_modes(self) -> list[tuple[str, str]]:
        with self._state_lock:
            modes = self._session_state.get("modes")
        if not isinstance(modes, Mapping):
            return []
        available = modes.get("availableModes") or modes.get("available")
        if not isinstance(available, list):
            return []
        result: list[tuple[str, str]] = []
        seen: set[str] = set()
        for item in available[:128]:
            if not isinstance(item, Mapping):
                continue
            value = item.get("id")
            label = item.get("name", value)
            if not isinstance(value, str) or not value or value in seen:
                continue
            if not _safe_mode(value, label):
                continue
            seen.add(value)
            result.append((_bounded_text(value, 128), _bounded_text(label, 160)))
        return result

    def _attachment_blocks(self, prepared: tuple[Any, ...]) -> list[dict[str, Any]]:
        if not prepared:
            return []
        if len(prepared) > 8:
            raise AcpUnavailableError("too many ACP prompt attachments")
        prompt_caps = _plain_mapping(self._agent_capabilities.get("promptCapabilities"))
        total = 0
        blocks: list[dict[str, Any]] = []
        for item in prepared:
            size = getattr(item, "size_bytes", None)
            mime = getattr(item, "mime_type", None)
            handle_id = getattr(item, "handle_id", None)
            expected_digest = getattr(item, "sha256", None)
            if (
                isinstance(size, bool)
                or not isinstance(size, int)
                or size < 0
                or size > _MAX_ATTACHMENT_BYTES
                or not isinstance(mime, str)
                or not isinstance(handle_id, str)
                or not isinstance(expected_digest, str)
            ):
                raise AcpUnavailableError("prepared ACP attachment metadata is invalid")
            total += size
            if total > _MAX_ATTACHMENT_TOTAL_BYTES:
                raise AcpUnavailableError("ACP prompt attachments exceed the total bound")
            opener = getattr(item, "open_verified", None)
            if not callable(opener):
                raise AcpUnavailableError("prepared ACP attachment cannot be reopened safely")
            opened = opener()
            manager = opened if hasattr(opened, "__enter__") else contextlib.closing(opened)
            with manager as stream:
                data = stream.read(size + 1)
            if not isinstance(data, bytes) or len(data) != size:
                raise AcpUnavailableError("prepared ACP attachment size changed")
            if not secrets.compare_digest(hashlib.sha256(data).hexdigest(), expected_digest):
                raise AcpUnavailableError("prepared ACP attachment digest changed")
            if mime.startswith("image/"):
                if prompt_caps.get("image") is not True:
                    raise AcpUnavailableError("ACP agent did not negotiate image prompts")
                blocks.append(
                    {"type": "image", "data": base64.b64encode(data).decode("ascii"), "mimeType": mime}
                )
            elif mime.startswith("audio/"):
                if prompt_caps.get("audio") is not True:
                    raise AcpUnavailableError("ACP agent did not negotiate audio prompts")
                blocks.append(
                    {"type": "audio", "data": base64.b64encode(data).decode("ascii"), "mimeType": mime}
                )
            elif mime.startswith("text/") or mime in {"application/json", "application/xml"}:
                if prompt_caps.get("embeddedContext") is not True:
                    raise AcpUnavailableError("ACP agent did not negotiate embedded context")
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise AcpUnavailableError("text ACP attachment is not UTF-8") from exc
                blocks.append(
                    {
                        "type": "resource",
                        "resource": {
                            "uri": f"pairling-attachment://{handle_id}",
                            "mimeType": mime,
                            "text": text,
                        },
                    }
                )
            else:
                raise AcpUnavailableError("ACP attachment type has no reviewed content block")
        return blocks


class AcpProviderAdapter(ProviderAdapter):
    """Standard adapter for only registry rows with exact reviewed ACP profiles."""

    def __init__(self, entry: registry_data.RegistryEntry, home: Path | None = None):
        self.entry = entry
        self.home = home or Path.home()
        self.descriptor = registry_data.descriptor_for(entry)

    @property
    def candidates(self) -> list[Path]:
        return registry_data.candidate_paths(self.entry, home=self.home)

    def supports(self, capability: str) -> bool:
        # These are adapter/probe properties, not live operation grants.
        return capability in {"detect", "status", "managed_acp_probe"}

    def create_control_driver(self, binding: ProviderControlBinding):
        if binding.provider_id != self.descriptor.provider_id:
            return None
        if not provider_binding_has_release_membership(
            binding.provider_id,
            binding.provider_version,
            binding.provider_channel,
        ):
            return None
        profile = reviewed_acp_profile(
            binding.provider_id,
            binding.provider_version,
            binding.provider_channel,
        )
        if isinstance(profile, AcpProfileUnavailable):
            return _UnavailableACPDriver(
                binding,
                f"{profile.code}: {profile.reason}",
            )
        resolved = resolve_executable(
            self.entry.binary_name,
            self.candidates,
            env_var=self.entry.env_override,
        )
        if resolved is None:
            return _UnavailableACPDriver(binding, "reviewed ACP executable is not installed")
        observed = _canonical_acp_version(
            binding.provider_id,
            cli_version(resolved.path, list(self.entry.version_command)),
        )
        if observed != binding.provider_version:
            return _UnavailableACPDriver(
                binding,
                "ACP executable version changed after the provider binding was issued",
            )
        try:
            return ACPControlDriver(
                binding=binding,
                profile=profile,
                executable=resolved.path,
                version_command=tuple(self.entry.version_command),
            )
        except AcpError as exc:
            return _UnavailableACPDriver(binding, str(exc))

    def probe(self) -> ProviderProbeResult:
        resolved = resolve_executable(
            self.entry.binary_name,
            self.candidates,
            env_var=self.entry.env_override,
        )
        installed = resolved is not None
        version = (
            _canonical_acp_version(
                self.entry.provider_id,
                cli_version(resolved.path, list(self.entry.version_command)),
            )
            if resolved is not None
            else None
        )
        profile = (
            reviewed_acp_profile(self.entry.provider_id, version or "", "stable")
            if installed
            else AcpProfileUnavailable(
                self.entry.provider_id,
                "reviewed ACP executable is not installed",
                "missing_cli",
            )
        )
        reviewed = isinstance(profile, AcpLaunchProfile)
        if not installed:
            notes = (
                f"{self.entry.display_name} CLI not found in configured, known, or daemon PATH locations",
            )
            setup_actions = ("install_cli",)
        elif not reviewed:
            notes = (
                "Detected version has no exact reviewed ACP launch profile; PTY fallback remains available.",
            )
            setup_actions = ("provider_review_required",)
        else:
            notes = (
                "Exact ACP profile detected; managed launch and session-bound canary attestation remain required.",
            )
            setup_actions = ()
        capabilities = (
            ("detect", "status", "managed_acp_probe")
            if reviewed
            else ("detect", "status")
        )
        availability = ProviderAvailability(
            provider_id=self.descriptor.provider_id,
            display_name=self.descriptor.display_name,
            kind=self.descriptor.kind,
            installed=installed,
            usable=reviewed,
            launchable=reviewed,
            auth_state="unknown" if installed else "missing_cli",
            config_state=(
                "pairling_managed"
                if reviewed and isinstance(profile, AcpLaunchProfile) and profile.managed_files
                else ("ready" if reviewed else "unsupported")
            ),
            readable_sessions=0,
            live_sessions=0,
            controllable_sessions=0,
            capabilities=capabilities,
            setup_actions=setup_actions,
            notes=notes,
        )
        diagnostics = ProviderDiagnostics(
            cli_path=str(resolved.path) if resolved else None,
            cli_path_source=resolved.source if resolved else None,
            version=version,
            config_path=None,
            config_exists=None,
        )
        return ProviderProbeResult(
            descriptor=self.descriptor,
            availability=availability,
            diagnostics=diagnostics,
            observed_at=time.time(),
        )


class _UnavailableACPDriver:
    """Typed empty driver for detected but unreviewed/unresolved providers."""

    def __init__(self, binding: ProviderControlBinding, reason: str):
        self.binding = binding
        self.reason = _bounded_text(reason, 512)
        self.capability_generation = 1

    def snapshot(self, *, session_id: str | None, session_truth: dict[str, Any] | None) -> ProviderControlSnapshot:
        del session_id, session_truth
        now = time.time()
        return ProviderControlSnapshot(
            provider_id=self.binding.provider_id,
            provider_version=self.binding.provider_version,
            provider_channel=self.binding.provider_channel,
            binding_id=self.binding.binding_id,
            capability_generation=1,
            observed_at=now,
            valid_until=now + 5.0,
            advertised_operations=(),
            values=(),
            choices=(),
            blocked_reason=self.reason,
            provider_cursor="acp:1:0",
        )

    def execute(self, **kwargs):
        del kwargs
        raise AcpUnavailableError(self.reason)

    def attach_managed_launch(self, **kwargs):
        del kwargs
        raise AcpUnavailableError(self.reason)

    def launch_session(self, **kwargs):
        del kwargs
        raise AcpUnavailableError(self.reason)

    def poll_events(self, cursor):
        del cursor
        return []

    def close(self) -> None:
        return None


def create_control_driver(binding: ProviderControlBinding):
    """Create an unattached ACP driver from only reviewed registry/profile data."""

    if not isinstance(binding, ProviderControlBinding):
        return None
    if not provider_binding_has_release_membership(
        binding.provider_id,
        binding.provider_version,
        binding.provider_channel,
    ):
        return None
    profile = reviewed_acp_profile(
        binding.provider_id,
        binding.provider_version,
        binding.provider_channel,
    )
    if isinstance(profile, AcpProfileUnavailable):
        return _UnavailableACPDriver(binding, f"{profile.code}: {profile.reason}")
    entry = next(
        (
            item
            for item in registry_data.load_entries(path=registry_data.DEFAULT_PATH)
            if item.provider_id == binding.provider_id
        ),
        None,
    )
    if entry is None:
        return _UnavailableACPDriver(binding, "provider registry entry is missing")
    resolved = resolve_executable(
        entry.binary_name,
        registry_data.candidate_paths(entry),
        env_var=entry.env_override,
    )
    if resolved is None:
        return _UnavailableACPDriver(binding, "reviewed ACP executable is not installed")
    observed = _canonical_acp_version(
        binding.provider_id,
        cli_version(resolved.path, list(entry.version_command)),
    )
    if observed != binding.provider_version:
        return _UnavailableACPDriver(
            binding,
            "ACP executable version changed after the provider binding was issued",
        )
    try:
        return ACPControlDriver(
            binding=binding,
            profile=profile,
            executable=resolved.path,
            version_command=tuple(entry.version_command),
        )
    except AcpError as exc:
        return _UnavailableACPDriver(binding, str(exc))


def _normalize_session_update(native_session_id: str, update: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    discriminator = update.get("sessionUpdate") or update.get("session_update") or update.get("type")
    mapping = {
        "agent_message_chunk": "content",
        "agent_thought_chunk": "thought",
        "tool_call": "tool_call",
        "tool_call_update": "tool_call_update",
        "plan": "plan",
        "available_commands_update": "commands",
        "usage_update": "usage",
        "session_info_update": "session_update",
        "current_mode_update": "session_update",
        "config_option_update": "session_update",
    }
    kind = mapping.get(str(discriminator), "session_update")
    safe_update = {
        str(key): _sanitize_json(value)
        for key, value in list(update.items())[:128]
        if key not in {"jsonrpc", "method"}
    }
    payload: dict[str, Any] = {
        "session_id": _bounded_text(native_session_id, 512),
        "update": safe_update,
    }
    if kind in {"content", "thought"}:
        content = update.get("content")
        text = content.get("text") if isinstance(content, Mapping) else update.get("text")
        payload["text"] = _redacted_public_text(text or "", _MAX_SAFE_STRING_BYTES)
        payload["role"] = "assistant"
    elif kind == "tool_call":
        payload["name"] = _redacted_public_text(
            update.get("title") or update.get("name") or update.get("kind") or "tool",
            160,
        )
        call_id = update.get("toolCallId") or update.get("callId") or update.get("id")
        if isinstance(call_id, str):
            payload["call_id"] = _bounded_text(call_id, 256)
        if "rawInput" in update:
            payload["input"] = _sanitize_json(update.get("rawInput"))
    elif kind == "tool_call_update":
        call_id = update.get("toolCallId") or update.get("callId") or update.get("id")
        if isinstance(call_id, str):
            payload["call_id"] = _bounded_text(call_id, 256)
        payload["content"] = _sanitize_json(
            update.get("content") or update.get("rawOutput") or update.get("status") or ""
        )
        payload["is_error"] = str(update.get("status") or "").casefold() in {"failed", "error"}
    elif kind == "plan":
        payload["plan_step"] = _sanitize_json(update.get("entries") or update.get("plan") or safe_update)
    elif kind == "usage":
        payload["usage"] = _sanitize_json(update.get("usage") or safe_update)
    elif kind == "commands":
        payload["session_update"] = {
            "commands": _normalize_commands(
                update.get("availableCommands") or update.get("commands")
            )
        }
    else:
        payload["session_update"] = safe_update
    return kind, payload




def _resolved_executable(raw: Path) -> Path:
    try:
        path = Path(raw)
        if not path.is_absolute() or path.is_symlink():
            # Symlinks are resolved once here and never passed through as a
            # mutable launch target.
            path = path.resolve(strict=True)
        else:
            path = path.resolve(strict=True)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise OSError("not executable")
    except (OSError, ValueError, TypeError) as exc:
        raise AcpUnavailableError("ACP executable is not a resolved absolute executable") from exc
    return path


def _canonical_acp_version(provider_id: str, raw: str | None) -> str | None:
    if not isinstance(raw, str) or not raw:
        return None
    if provider_id == "hermes_agent":
        match = re.search(
            r"^Hermes Agent v(\d+\.\d+\.\d+) \(([^)\r\n]+)\) · upstream ([0-9a-f]{8,40})",
            raw,
        )
        if match is None:
            return None
        return f"Hermes Agent v{match.group(1)} ({match.group(2)}) · upstream {match.group(3)}"
    if provider_id == "omp":
        match = re.fullmatch(r"(?:omp/)?(\d+\.\d+\.\d+)", raw.strip())
        return match.group(1) if match is not None else None
    return raw

def _file_identity(path: Path) -> tuple[int, int, int, int, int]:
    try:
        stat_result = path.stat()
    except OSError as exc:
        raise AcpUnavailableError("resolved ACP executable disappeared") from exc
    return (
        int(stat_result.st_dev),
        int(stat_result.st_ino),
        int(stat_result.st_size),
        int(stat_result.st_mtime_ns),
        int(stat_result.st_mode),
    )


def _existing_absolute_directory(raw: Any, field: str) -> Path:
    if not isinstance(raw, (str, os.PathLike)):
        raise AcpUnavailableError(f"{field} is not a path")
    path = Path(raw)
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path) or "\n" in str(path):
        raise AcpUnavailableError(f"{field} must be an absolute contained path")
    try:
        if path.is_symlink() or not path.is_dir():
            raise OSError("not a real directory")
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise AcpUnavailableError(f"{field} must be an existing non-symlink directory") from exc
    if resolved == Path(resolved.anchor):
        raise AcpUnavailableError(f"{field} may not be a filesystem root")
    return resolved


def _secure_child_directory(parent: Path, name: str, *, exclusive: bool = False) -> Path:
    if not re.fullmatch(r"[a-zA-Z0-9._-]{1,64}", name):
        raise AcpUnavailableError("managed process directory name is invalid")
    target = parent / name
    try:
        target.mkdir(mode=0o700, parents=False, exist_ok=not exclusive)
        if target.is_symlink() or not target.is_dir():
            raise OSError("not a real directory")
        resolved = target.resolve(strict=True)
        resolved.relative_to(parent.resolve(strict=True))
        os.chmod(resolved, 0o700)
    except (OSError, ValueError) as exc:
        raise AcpUnavailableError("managed ACP process directory is unsafe or already exists") from exc
    return resolved


def _write_managed_profile_files(root: Path, profile: AcpLaunchProfile) -> None:
    for managed in profile.managed_files:
        relative = Path(managed.relative_path)
        parent = root.joinpath(*relative.parts[:-1]) if len(relative.parts) > 1 else root
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = parent / relative.name
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(target, flags, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(managed.content.encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise AcpUnavailableError("failed to create Pairling-owned ACP profile") from exc


def _allowed_methods_for_profile(profile: AcpLaunchProfile) -> frozenset[str]:
    extensions = _reviewed_extension_methods(profile)
    allowed = set(_ACP_V1_METHODS) - {"session/set_model"}
    if "session/set_model" in extensions:
        allowed.add("session/set_model")
    return frozenset(allowed)


def _reviewed_extension_methods(profile: AcpLaunchProfile) -> frozenset[str]:
    raw = profile.overlay_metadata.get("reviewed_extension_methods")
    if not isinstance(raw, (tuple, list)):
        return frozenset()
    # The overlay can preserve arbitrary data, but executable extension methods
    # remain an intersection with the one statically reviewed legacy method.
    return frozenset(value for value in raw if value == "session/set_model")




def _normalize_form_elicitation(
    params: Mapping[str, Any],
) -> tuple[str, str, tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    native_id = _safe_id(params.get("sessionId"), "ACP elicitation session id")
    if params.get("mode") != "form":
        raise AcpProtocolError("Pairling supports only ACP form elicitation")
    message = params.get("message")
    if not isinstance(message, str) or not message.strip() or len(message.encode("utf-8")) > 2_000:
        raise AcpProtocolError("ACP elicitation message is invalid")
    if _looks_sensitive_prompt(message):
        raise AcpProtocolError("ACP form elicitation must not request sensitive data")
    schema = _require_mapping(params.get("requestedSchema"), "ACP elicitation schema")
    if schema.get("type") != "object":
        raise AcpProtocolError("ACP elicitation schema must be an object")
    if schema.get("additionalProperties") is True:
        raise AcpProtocolError("ACP elicitation schema must reject additional properties")
    properties = schema.get("properties")
    if not isinstance(properties, Mapping) or not 1 <= len(properties) <= 12:
        raise AcpProtocolError("ACP elicitation must contain one to twelve fields")
    raw_required = schema.get("required", [])
    if (
        not isinstance(raw_required, list)
        or len(raw_required) > len(properties)
        or any(not isinstance(item, str) for item in raw_required)
        or len(set(raw_required)) != len(raw_required)
    ):
        raise AcpProtocolError("ACP elicitation required fields are invalid")
    required = set(raw_required)
    if not required.issubset(properties):
        raise AcpProtocolError("ACP elicitation required fields are unknown")

    def options_from(
        enum: Any,
        one_of: Any,
    ) -> tuple[list[str], dict[str, str]]:
        if enum is not None and one_of is not None:
            raise AcpProtocolError("ACP elicitation choices are ambiguous")
        if one_of is not None:
            if not isinstance(one_of, list) or not 1 <= len(one_of) <= 20:
                raise AcpProtocolError("ACP elicitation choices are invalid")
            labels: list[str] = []
            values: dict[str, str] = {}
            seen_values: set[str] = set()
            for option in one_of:
                if not isinstance(option, Mapping):
                    raise AcpProtocolError("ACP elicitation choices are invalid")
                value = option.get("const")
                label = option.get("title")
                if (
                    not isinstance(value, str)
                    or not value
                    or len(value.encode("utf-8")) > 256
                    or _looks_sensitive_prompt(value)
                    or value in seen_values
                    or not isinstance(label, str)
                    or not label
                    or len(label.encode("utf-8")) > 256
                    or _looks_sensitive_prompt(label)
                    or label in values
                ):
                    raise AcpProtocolError("ACP elicitation choices are invalid")
                labels.append(label)
                values[label] = value
                seen_values.add(value)
            return labels, values
        if enum is None:
            return [], {}
        if (
            not isinstance(enum, list)
            or not 1 <= len(enum) <= 20
            or any(
                not isinstance(item, str)
                or not item
                or len(item.encode("utf-8")) > 256
                or _looks_sensitive_prompt(item)
                for item in enum
            )
            or len(set(enum)) != len(enum)
        ):
            raise AcpProtocolError("ACP elicitation choices are invalid")
        return list(enum), {value: value for value in enum}

    questions: list[dict[str, Any]] = []
    field_specs: list[dict[str, Any]] = []
    for index, (raw_key, raw_property) in enumerate(properties.items(), start=1):
        if (
            not isinstance(raw_key, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", raw_key) is None
            or _looks_sensitive_prompt(raw_key)
            or not isinstance(raw_property, Mapping)
        ):
            raise AcpProtocolError("ACP elicitation field is invalid")
        prop = dict(raw_property)
        value_type = prop.get("type")
        if value_type not in {"string", "boolean", "number", "integer", "array"}:
            raise AcpProtocolError("ACP elicitation field type is unsupported")
        title = prop.get("title") or raw_key
        description = prop.get("description") or title
        if (
            not isinstance(title, str)
            or not title.strip()
            or len(title.encode("utf-8")) > 160
            or not isinstance(description, str)
            or not description.strip()
            or len(description.encode("utf-8")) > 2_000
            or _looks_sensitive_prompt(title)
            or _looks_sensitive_prompt(description)
        ):
            raise AcpProtocolError("ACP elicitation field text is invalid")
        is_required = raw_key in required
        question: dict[str, Any] = {
            "index": index,
            "topic": title,
            "question": description,
            "options": [],
            "required": is_required,
            "answer": "",
        }
        spec: dict[str, Any] = {
            "key": raw_key,
            "type": value_type,
            "required": is_required,
        }
        common = {"type", "title", "description", "_meta"}
        if value_type == "boolean":
            if set(prop) - common - {"default"}:
                raise AcpProtocolError("ACP boolean elicitation schema is unsupported")
            question["options"] = ["Yes", "No"]
            default = prop.get("default")
            if default is not None:
                if not isinstance(default, bool):
                    raise AcpProtocolError("ACP boolean elicitation default is invalid")
                question["answer"] = "Yes" if default else "No"
        elif value_type in {"number", "integer"}:
            if set(prop) - common - {"minimum", "maximum", "default"}:
                raise AcpProtocolError("ACP numeric elicitation schema is unsupported")
            minimum = prop.get("minimum")
            maximum = prop.get("maximum")
            default = prop.get("default")
            for value in (minimum, maximum, default):
                if value is None:
                    continue
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or not math.isfinite(float(value))
                    or abs(float(value)) > 1e15
                    or (value_type == "integer" and not float(value).is_integer())
                ):
                    raise AcpProtocolError("ACP numeric elicitation bound is invalid")
            if minimum is not None and maximum is not None and minimum > maximum:
                raise AcpProtocolError("ACP numeric elicitation bounds are invalid")
            if default is not None and (
                (minimum is not None and default < minimum)
                or (maximum is not None and default > maximum)
            ):
                raise AcpProtocolError("ACP numeric elicitation default is invalid")
            spec["minimum"] = minimum
            spec["maximum"] = maximum
            if default is not None:
                question["answer"] = str(
                    int(default) if value_type == "integer" else default
                )
        elif value_type == "array":
            if set(prop) - common - {"items", "minItems", "maxItems", "default"}:
                raise AcpProtocolError("ACP multi-select schema is unsupported")
            items = prop.get("items")
            if not isinstance(items, Mapping):
                raise AcpProtocolError("ACP multi-select items are invalid")
            item_keys = set(items)
            if items.get("type") == "string":
                if item_keys - {"type", "enum", "_meta"}:
                    raise AcpProtocolError("ACP multi-select items are unsupported")
                options, choice_map = options_from(items.get("enum"), None)
            elif "anyOf" in items:
                if item_keys - {"anyOf", "_meta"}:
                    raise AcpProtocolError("ACP multi-select items are unsupported")
                options, choice_map = options_from(None, items.get("anyOf"))
            else:
                raise AcpProtocolError("ACP multi-select items are unsupported")
            minimum = prop.get("minItems", 0)
            maximum = prop.get("maxItems", len(options))
            if (
                isinstance(minimum, bool)
                or not isinstance(minimum, int)
                or isinstance(maximum, bool)
                or not isinstance(maximum, int)
                or not 0 <= minimum <= maximum <= len(options)
            ):
                raise AcpProtocolError("ACP multi-select bounds are invalid")
            default = prop.get("default", [])
            if (
                not isinstance(default, list)
                or len(default) != len(set(default))
                or any(value not in choice_map.values() for value in default)
                or not minimum <= len(default) <= maximum
            ):
                raise AcpProtocolError("ACP multi-select default is invalid")
            inverse = {value: label for label, value in choice_map.items()}
            question.update({
                "options": options,
                "multiple": True,
                "custom": False,
                "selections": [inverse[value] for value in default],
                "required": minimum > 0,
            })
            spec.update({
                "choice_map": choice_map,
                "minimum": minimum,
                "maximum": maximum,
            })
        else:
            if set(prop) - common - {
                "default",
                "enum",
                "oneOf",
                "minLength",
                "maxLength",
                "pattern",
                "format",
            }:
                raise AcpProtocolError("ACP string elicitation schema is unsupported")
            if prop.get("pattern") is not None or prop.get("format") is not None:
                raise AcpProtocolError("ACP formatted string elicitation is unsupported")
            options, choice_map = options_from(prop.get("enum"), prop.get("oneOf"))
            question["options"] = options
            if options:
                spec["choice_map"] = choice_map
            minimum = prop.get("minLength", 0)
            maximum = prop.get("maxLength", 10_000)
            if (
                isinstance(minimum, bool)
                or not isinstance(minimum, int)
                or isinstance(maximum, bool)
                or not isinstance(maximum, int)
                or not 0 <= minimum <= maximum <= 10_000
            ):
                raise AcpProtocolError("ACP elicitation string bounds are invalid")
            spec["min_length"] = minimum
            spec["max_length"] = maximum
            default = prop.get("default")
            if default is not None:
                if (
                    not isinstance(default, str)
                    or not minimum <= len(default) <= maximum
                    or (
                        choice_map
                        and default not in choice_map.values()
                    )
                ):
                    raise AcpProtocolError("ACP string elicitation default is invalid")
                inverse = {value: label for label, value in choice_map.items()}
                question["answer"] = inverse.get(default, default)
        questions.append(question)
        field_specs.append(spec)
    return (
        native_id,
        _redacted_public_text(message, 2_000),
        tuple(questions),
        tuple(field_specs),
    )


def _validate_elicitation_answers(
    answers: Any,
    questions: tuple[dict[str, Any], ...],
    field_specs: tuple[dict[str, Any], ...],
) -> dict[str, Any]:
    if not isinstance(answers, list) or len(answers) != len(questions):
        raise AcpProtocolError("ACP elicitation answers do not match the pending fields")
    content: dict[str, Any] = {}
    for row, question, spec in zip(answers, questions, field_specs, strict=True):
        if not isinstance(row, Mapping):
            raise AcpProtocolError("ACP elicitation answer is invalid")
        for key in ("index", "topic", "question", "options"):
            if row.get(key) != question.get(key):
                raise AcpProtocolError("ACP elicitation answer changed the pending question")
        if (
            row.get("required", True) != question.get("required", True)
            or row.get("multiple", False) != question.get("multiple", False)
            or row.get("custom", not question.get("options")) != question.get(
                "custom", not question.get("options")
            )
        ):
            raise AcpProtocolError("ACP elicitation answer changed the pending question")
        unexpected = set(row) - {
            "index",
            "topic",
            "question",
            "options",
            "required",
            "multiple",
            "custom",
            "selections",
            "answer",
        }
        if unexpected:
            raise AcpProtocolError("ACP elicitation answer contains unexpected fields")
        answer = row.get("answer", "")
        if not isinstance(answer, str) or "\x00" in answer or len(answer.encode("utf-8")) > 10_000:
            raise AcpProtocolError("ACP elicitation answer is invalid")
        if spec["type"] == "array":
            selections = row.get("selections", [])
            if (
                not isinstance(selections, list)
                or len(selections) != len(set(selections))
                or any(
                    not isinstance(value, str)
                    or value not in spec["choice_map"]
                    for value in selections
                )
                or not spec["minimum"] <= len(selections) <= spec["maximum"]
                or answer
            ):
                raise AcpProtocolError("ACP multi-select answer is invalid")
            values = [spec["choice_map"][value] for value in selections]
            if spec["required"] or values:
                content[spec["key"]] = values
            continue
        if row.get("selections"):
            raise AcpProtocolError("ACP single-value answer has selections")
        if spec["type"] == "boolean":
            if answer == "Yes":
                content[spec["key"]] = True
            elif answer == "No":
                content[spec["key"]] = False
            elif spec["required"]:
                raise AcpProtocolError("ACP elicitation is missing a required answer")
            continue
        if not answer.strip():
            if spec["required"]:
                raise AcpProtocolError("ACP elicitation is missing a required answer")
            continue
        if spec["type"] in {"number", "integer"}:
            try:
                value = float(answer)
            except ValueError as exc:
                raise AcpProtocolError("ACP numeric elicitation answer is invalid") from exc
            if (
                not math.isfinite(value)
                or abs(value) > 1e15
                or (spec["type"] == "integer" and not value.is_integer())
                or (
                    spec.get("minimum") is not None
                    and value < spec["minimum"]
                )
                or (
                    spec.get("maximum") is not None
                    and value > spec["maximum"]
                )
            ):
                raise AcpProtocolError("ACP numeric elicitation answer is invalid")
            content[spec["key"]] = int(value) if spec["type"] == "integer" else value
            continue
        if not spec["min_length"] <= len(answer) <= spec["max_length"]:
            raise AcpProtocolError("ACP elicitation answer violates string bounds")
        choices = spec.get("choice_map")
        if choices:
            if answer not in choices:
                raise AcpProtocolError("ACP elicitation answer is not an offered choice")
            content[spec["key"]] = choices[answer]
        else:
            content[spec["key"]] = answer
    return content


def _looks_sensitive_prompt(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
    return any(
        marker in normalized
        for marker in (
            "apikey",
            "authtoken",
            "bearertoken",
            "credential",
            "password",
            "privatekey",
            "refreshtoken",
            "secretkey",
            "sessiontoken",
        )
    )
def _required_initialize_failures(profile: AcpLaunchProfile, result: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    agent_caps = _plain_mapping(result.get("agentCapabilities"))
    for requirement in profile.required_capabilities:
        if requirement == "protocolVersion=1":
            if result.get("protocolVersion") != 1:
                failures.append(requirement)
        elif requirement.startswith("agentInfo.") and "=" in requirement:
            path, expected = requirement.split("=", 1)
            info = _plain_mapping(result.get("agentInfo"))
            if str(info.get(path.split(".", 1)[1])) != expected:
                failures.append(requirement)
        elif requirement.startswith("agentCapabilities.") and requirement.endswith("=true"):
            path = requirement[len("agentCapabilities.") : -len("=true")]
            if _deep_value(agent_caps, path.split(".")) is not True:
                failures.append(requirement)
        elif requirement.startswith("promptCapabilities.") and "=" in requirement:
            path, expected = requirement.split("=", 1)
            if expected not in {"true", "false"}:
                failures.append(f"unsupported:{requirement}")
                continue
            actual = _deep_value(agent_caps, path.split("."))
            wanted = expected == "true"
            if actual is not wanted:
                failures.append(requirement)
        elif requirement.startswith("mcpCapabilities.") and requirement.endswith("=true"):
            path = requirement[len("mcpCapabilities.") : -len("=true")]
            mcp = _plain_mapping(agent_caps.get("mcpCapabilities"))
            if _deep_value(mcp, path.split(".")) is not True:
                failures.append(requirement)
        elif requirement.startswith("sessionCapabilities.") and requirement.endswith("=true"):
            path = requirement[len("sessionCapabilities.") : -len("=true")]
            session_caps = _plain_mapping(agent_caps.get("sessionCapabilities"))
            if not _capability_supported(_deep_value(session_caps, path.split("."))):
                failures.append(requirement)
        else:
            failures.append(f"unsupported:{requirement}")
    return failures


def _capability_bool(agent_caps: Mapping[str, Any], key: str) -> bool:
    return agent_caps.get(key) is True


def _capability_supported(value: Any) -> bool:
    """ACP capability objects use an empty object to mean supported."""
    return value is True or isinstance(value, Mapping)


def _nested_bool(agent_caps: Mapping[str, Any], parent: str, key: str) -> bool:
    nested = agent_caps.get(parent)
    return isinstance(nested, Mapping) and _capability_supported(nested.get(key))


def _safe_mode(value: Any, label: Any) -> bool:
    combined = re.sub(r"[^a-z0-9]", "", f"{value} {label}".casefold())
    return bool(combined) and not any(word in combined for word in _SAFE_MODE_BAD_WORDS)


def _safe_permission_options(raw: Any) -> dict[str, tuple[str, str]]:
    if not isinstance(raw, list):
        return {}
    result: dict[str, tuple[str, str]] = {}
    for item in raw[:32]:
        if not isinstance(item, Mapping):
            continue
        option_id = item.get("optionId") or item.get("id")
        kind = str(item.get("kind") or "").casefold().replace("-", "_")
        label = item.get("name") or item.get("label") or kind
        if not isinstance(option_id, str) or not option_id or not isinstance(label, str):
            continue
        if kind in {"allow_once", "allow"} and "allow" not in result:
            result["allow"] = (_bounded_text(option_id, 256), _bounded_text(label, 160))
        elif kind in {"reject_once", "reject"} and "reject" not in result:
            result["reject"] = (_bounded_text(option_id, 256), _bounded_text(label, 160))
    return result


def _normalize_commands(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    result = []
    for item in raw[:256]:
        if not isinstance(item, Mapping):
            continue
        safe = {}
        for key in ("name", "description", "inputHint"):
            value = item.get(key)
            if isinstance(value, str):
                safe[_camel_to_snake(key)] = _redacted_public_text(value, 1024)
        if safe.get("name"):
            result.append(safe)
    return result


def _sanitize_json(value: Any, *, key: str = "", depth: int = 0) -> Any:
    if depth > 8:
        return "[depth omitted]"
    normalized_key = re.sub(r"[^a-z0-9]", "", key.casefold())
    secret = any(word in normalized_key for word in _SECRET_KEY_WORDS)
    if "token" in normalized_key and normalized_key not in _USAGE_TOKEN_KEYS:
        secret = True
    if key and secret:
        return "[REDACTED]"
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if value == value and abs(value) != float("inf") else None
    if isinstance(value, str):
        return _redacted_public_text(value, _MAX_SAFE_STRING_BYTES)
    if isinstance(value, Mapping):
        result = {}
        for child_key, child in list(value.items())[:128]:
            if not isinstance(child_key, str):
                continue
            result[_bounded_text(child_key, 128)] = _sanitize_json(
                child, key=child_key, depth=depth + 1
            )
        return result
    if isinstance(value, (list, tuple)):
        return [_sanitize_json(item, depth=depth + 1) for item in list(value)[:256]]
    return _bounded_text(value, 512)


def _redacted_public_text(value: Any, limit: int) -> str:
    text = value if isinstance(value, str) else str(value or "")
    return _bounded_text(_SECRET_TEXT_RE.sub("[REDACTED]", text), limit)


def _plain_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): _plain_value(child) for key, child in value.items() if isinstance(key, str)}


def _plain_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _plain_mapping(value)
    if isinstance(value, (tuple, list)):
        return [_plain_value(item) for item in value]
    return value


def _require_mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AcpProtocolError(f"{name} must be an object")
    return dict(value)


def _safe_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or any(ch in value for ch in "\r\n\0"):
        raise AcpProtocolError(f"{name} is invalid")
    return value


def _deep_value(value: Mapping[str, Any], parts: list[str]) -> Any:
    current: Any = value
    for part in parts:
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def _operation_request_digest(
    operation_id: str,
    payload: Mapping[str, Any],
    prepared_attachments: tuple[Any, ...],
) -> str:
    attachments = []
    for item in prepared_attachments:
        attachments.append(
            {
                "handle_id": getattr(item, "handle_id", None),
                "sha256": getattr(item, "sha256", None),
                "size_bytes": getattr(item, "size_bytes", None),
                "mime_type": getattr(item, "mime_type", None),
            }
        )
    encoded = json.dumps(
        {
            "operation_id": operation_id,
            "payload": _sanitize_json(payload),
            "attachments": _sanitize_json(attachments),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _operation_receipt_id(generation: int, client_action_id: Any) -> str:
    action = _bounded_text(client_action_id, 512)
    digest = hashlib.sha256(action.encode("utf-8")).hexdigest()[:32]
    return f"acp:{generation}:{digest}"


def _bounded_text(value: Any, limit: int) -> str:
    text = value if isinstance(value, str) else str(value)
    raw = text.encode("utf-8", "replace")
    if len(raw) <= limit:
        return text
    return raw[:limit].decode("utf-8", "ignore") + "…"


def _camel_to_snake(value: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", value).lower()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
