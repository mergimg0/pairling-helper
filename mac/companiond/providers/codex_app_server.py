from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import signal
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .base import managed_child_environment
from .controls import (
    ControlChoice,
    ControlChoices,
    ControlValue,
    OperationResultStatus,
    ProviderControlBinding,
    ProviderControlSnapshot,
    ProviderOperationCorrelation,
    ProviderOperationResult,
    ProviderSessionIdentity,
)
from .operations import (
    CODEX_APP_SERVER_SAFE_LAUNCH_PROFILE,
    released_operation_ids_for_provider,
)

_SUPPORTED_VERSION = (0, 147, 0)
_MAX_REQUEST_BYTES = 256 * 1024
_MAX_RESPONSE_LINE_BYTES = 1024 * 1024
_MAX_TEXT_FIELD_BYTES = 64 * 1024
_MAX_EVENTS = 512
_MAX_RAW_DIAGNOSTIC_EVENTS = 8
_MAX_PENDING_REQUESTS = 32
_MAX_INTERACTIVE_REQUESTS_PER_WINDOW = 32
_INTERACTIVE_REQUEST_WINDOW_SECONDS = 10.0

# Every outbound app-server method is named here. There is intentionally no
# public dynamic-RPC entry point and no auth, command/exec, filesystem, config
# write, remote-control, or experimental method in this allowlist.
_SUPPORTED_METHODS = frozenset({
    "initialize",
    "thread/start",
    "thread/resume",
    "thread/fork",
    "thread/archive",
    "thread/name/set",
    "thread/compact/start",
    "thread/list",
    "thread/read",
    "turn/start",
    "turn/steer",
    "turn/interrupt",
    "review/start",
    "model/list",
    "collaborationMode/list",
    "thread/settings/update",
    "config/read",
    "account/read",
    "account/rateLimits/read",
    "account/usage/read",
    "mcpServerStatus/list",
})

_EXPERIMENTAL_METHODS = frozenset({
    "thread/inject_items",
    "thread/rollback",
})

_APPROVAL_METHODS = frozenset({
    "item/commandExecution/requestApproval",
    "item/fileChange/requestApproval",
})
_QUESTION_METHODS = frozenset({
    "item/tool/requestUserInput",
})

_NOTIFICATION_KINDS = {
    "thread/started": "thread.started",
    "thread/archived": "thread.archived",
    "thread/status/changed": "thread.status_changed",
    "turn/started": "turn.started",
    "turn/completed": "turn.completed",
    "item/started": "item.started",
    "item/completed": "item.completed",
    "item/agentMessage/delta": "item.agent_message_delta",
    "item/reasoning/summaryTextDelta": "item.reasoning_summary_delta",
    "item/reasoning/textDelta": "item.reasoning_delta",
    "item/commandExecution/outputDelta": "item.command_output_delta",
    "item/mcpToolCall/progress": "item.mcp_progress",
    "item/fileChange/patchUpdated": "item.file_patch_updated",
    "turn/diff/updated": "turn.diff_updated",
    "turn/plan/updated": "turn.plan_updated",
    "thread/tokenUsage/updated": "thread.token_usage_updated",
    "account/updated": "account.updated",
    "account/rateLimits/updated": "account.rate_limits_updated",
    "serverRequest/resolved": "approval.resolved",
    "error": "provider.error",
    "warning": "provider.warning",
}

_SECRET_KEY_NAMES = frozenset({
    "accesstoken",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "credentials",
    "env",
    "password",
    "privatekey",
    "refreshtoken",
    "secret",
    "token",
})
_SECRET_TEXT = re.compile(
    r"(?i)(?:bearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"\bsk-[A-Za-z0-9_-]{8,}|"
    r"\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*\S+)"
)


class CodexAppServerError(RuntimeError):
    """Base class for fail-closed local app-server failures."""


class CodexAppServerUnavailable(CodexAppServerError):
    pass


class CodexAppServerEOF(CodexAppServerUnavailable):
    pass


class CodexAppServerTimeout(CodexAppServerUnavailable):
    pass


class CodexAppServerProtocolError(CodexAppServerUnavailable):
    pass


class CodexAppServerRPCError(CodexAppServerError):
    def __init__(self, code: int | None, message: str):
        self.code = code
        super().__init__(f"Codex app-server error {code}: {_bounded_text(message, 512)}")


class CodexUnsupportedOperation(CodexAppServerError):
    pass



class CodexQuestionCorrelationError(CodexAppServerError):
    pass

class CodexApprovalCorrelationError(CodexAppServerError):
    pass


class CodexEventCursorExpired(CodexAppServerError):
    pass


@dataclass
class _PendingRequest:
    completed: threading.Event
    result: Any = None
    error: BaseException | None = None


@dataclass(frozen=True)
class _ApprovalRequest:
    provider_request_id: str | int
    method: str
    public_approval_id: str
    thread_id: str
    turn_id: str
    item_id: str
    approval_id: str | None
    received_generation: int

    def proof(self) -> dict[str, Any]:
        return {
            "provider_request_id": self.provider_request_id,
            "public_approval_id": self.public_approval_id,
            "approval_method": self.method,
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "item_id": self.item_id,
            "approval_id": self.approval_id,
            "capability_generation": self.received_generation,
        }


@dataclass(frozen=True)
class _QuestionRequest:
    provider_request_id: str | int
    public_question_request_id: str
    thread_id: str
    turn_id: str
    item_id: str
    received_generation: int
    questions: tuple[dict[str, Any], ...]

    def proof(self) -> dict[str, Any]:
        return {
            "provider_request_id": self.provider_request_id,
            "public_question_request_id": self.public_question_request_id,
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "item_id": self.item_id,
            "capability_generation": self.received_generation,
            "questions": [dict(question) for question in self.questions],
        }


def _bounded_text(value: Any, limit: int = _MAX_TEXT_FIELD_BYTES) -> str:
    text = value if isinstance(value, str) else str(value)
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= limit:
        return text
    return raw[:limit].decode("utf-8", errors="ignore") + "…"

def _redacted_public_text(
    value: Any,
    limit: int = _MAX_TEXT_FIELD_BYTES,
) -> str:
    return _SECRET_TEXT.sub("[redacted]", _bounded_text(value, limit))


def _safe_identifier(value: Any) -> str | None:
    if isinstance(value, str) and value and len(value.encode("utf-8")) <= 512:
        return value
    return None


def _safe_opaque(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and 0 < len(value.encode("utf-8")) <= 512
        and all(ord(character) >= 32 for character in value)
    )


def _codex_question_rows(value: Any) -> tuple[dict[str, Any], ...] | None:
    if not isinstance(value, list) or not 1 <= len(value) <= 12:
        return None
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            return None
        provider_question_id = _safe_identifier(item.get("id"))
        question = item.get("question")
        header = item.get("header")
        is_secret = item.get("isSecret", False)
        raw_options = item.get("options")
        if (
            provider_question_id is None
            or provider_question_id in seen_ids
            or not isinstance(question, str)
            or not question.strip()
            or len(question) > 10_000
            or "\x00" in question
            or not isinstance(header, str)
            or not header.strip()
            or len(header) > 160
            or "\x00" in header
            or type(is_secret) is not bool
            or is_secret
            or (raw_options is not None and not isinstance(raw_options, list))
        ):
            return None
        options: list[str] = []
        if isinstance(raw_options, list):
            if len(raw_options) > 20:
                return None
            for option in raw_options:
                if not isinstance(option, Mapping):
                    return None
                label = option.get("label")
                if (
                    not isinstance(label, str)
                    or not label
                    or len(label) > 512
                    or "\x00" in label
                    or label in options
                ):
                    return None
                options.append(label)
        seen_ids.add(provider_question_id)
        rows.append({
            "provider_question_id": provider_question_id,
            "index": index + 1,
            "topic": _bounded_text(header, 160),
            "question": _bounded_text(question, 10_000),
            "options": options,
        })
    return tuple(rows)


def _codex_operation_id(
    binding_id: str,
    capability_generation: int,
    client_action_id: str,
) -> str:
    digest = hashlib.sha256(
        (
            f"{binding_id}\0{capability_generation}\0"
            f"{client_action_id}"
        ).encode("utf-8")
    ).hexdigest()
    return f"codex:{capability_generation}:{digest}"


def _version_tuple(value: str | None) -> tuple[int, int, int] | None:
    if not value:
        return None
    match = re.search(r"(?:^|[/\s])v?(\d+)\.(\d+)\.(\d+)(?:\D|$)", value)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def is_compatible_codex_app_server_version(value: str | None) -> bool:
    return _version_tuple(value) == _SUPPORTED_VERSION

def normalized_codex_app_server_version(value: str | None) -> str | None:
    parsed = _version_tuple(value)
    return ".".join(str(part) for part in parsed) if parsed else None


def _redact_secrets(value: Any, *, key: str = "") -> Any:
    compact_key = re.sub(r"[^a-z0-9]", "", key.casefold())
    secret_key = compact_key in _SECRET_KEY_NAMES or compact_key.endswith(
        ("apikey", "password", "privatekey", "refreshtoken", "secret")
    )
    if key and secret_key and not isinstance(value, bool):
        return "[redacted]"
    if isinstance(value, Mapping):
        return {
            str(child_key): _redact_secrets(child_value, key=str(child_key))
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_secrets(item) for item in value]
    if isinstance(value, str):
        return _redacted_public_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _bounded_text(value)


def _sanitized_account(result: Mapping[str, Any]) -> dict[str, Any]:
    account = result.get("account")
    safe_account: dict[str, Any] | None = None
    if isinstance(account, Mapping):
        safe_account = {}
        for key in ("type", "planType", "usesCodexManagedCredentials"):
            value = account.get(key)
            if value is None or isinstance(value, (str, bool)):
                safe_account[key] = value
    return {
        "account": safe_account,
        "requiresOpenaiAuth": bool(result.get("requiresOpenaiAuth", False)),
    }


def _sanitized_mcp_status(result: Mapping[str, Any]) -> dict[str, Any]:
    servers: list[dict[str, Any]] = []
    raw_servers = result.get("data")
    if isinstance(raw_servers, list):
        for server in raw_servers[:256]:
            if not isinstance(server, Mapping):
                continue
            safe: dict[str, Any] = {}
            for key in ("name", "authStatus", "serverInfo"):
                if key in server:
                    safe[key] = _redact_secrets(server[key], key=key)
            tools = server.get("tools")
            if isinstance(tools, Mapping):
                safe["tools"] = [
                    _bounded_text(name, 512)
                    for name in list(tools.keys())[:512]
                    if isinstance(name, str)
                ]
            resources = server.get("resources")
            if isinstance(resources, list):
                safe["resourceCount"] = len(resources)
            templates = server.get("resourceTemplates")
            if isinstance(templates, list):
                safe["resourceTemplateCount"] = len(templates)
            servers.append(safe)
    next_cursor = result.get("nextCursor")
    return {
        "data": servers,
        "nextCursor": next_cursor if isinstance(next_cursor, str) else None,
    }


class _CodexAppServerProcess:
    """Owns one local Codex app-server child and its JSONL correlation state."""

    def __init__(
        self,
        *,
        argv: Sequence[str],
        env: Mapping[str, str] | None = None,
        provider_settings: Mapping[str, str] | None = None,
        client_version: str,
        request_timeout: float = 15.0,
        max_line_bytes: int = _MAX_RESPONSE_LINE_BYTES,
        internal_diagnostics: bool = False,
    ):
        if not argv or any(not isinstance(part, str) or not part for part in argv):
            raise ValueError("Codex app-server argv must contain non-empty strings")
        if request_timeout <= 0:
            raise ValueError("request_timeout must be positive")
        self._argv = tuple(argv)
        self._env = managed_child_environment(
            source=env,
            provider_settings=provider_settings,
        )
        self._client_version = _bounded_text(client_version, 128)
        self._request_timeout = request_timeout
        self._max_line_bytes = max_line_bytes
        self._internal_diagnostics_enabled = internal_diagnostics

        self._state_lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._start_lock = threading.Lock()
        self._approval_ready = threading.Condition(self._state_lock)
        self._process: subprocess.Popen[bytes] | None = None
        self._reader: threading.Thread | None = None
        self._cleanup_process: subprocess.Popen[bytes] | None = None
        self._cleanup_complete: threading.Event | None = None
        self._pending: dict[str, _PendingRequest] = {}
        self._approvals: dict[str | int, _ApprovalRequest] = {}
        self._questions: dict[str | int, _QuestionRequest] = {}
        self._interactive_request_times: deque[float] = deque()
        self._events: deque[dict[str, Any]] = deque(maxlen=_MAX_EVENTS)
        self._raw_events: deque[dict[str, Any]] = deque(
            maxlen=_MAX_RAW_DIAGNOSTIC_EVENTS
        )
        self._next_request_id = 0
        self._generation = 0
        self._cursor = 0
        self._initialized = False
        self._provider_version: str | None = None
        self._current_thread_id: str | None = None
        self._current_turn_id: str | None = None
        self._current_item_id: str | None = None
        self._turn_active = False

    @property
    def capability_generation(self) -> int:
        with self._state_lock:
            return self._generation

    @property
    def provider_cursor(self) -> int:
        with self._state_lock:
            return self._cursor

    @property
    def provider_version(self) -> str | None:
        with self._state_lock:
            return self._provider_version

    @property
    def is_available(self) -> bool:
        with self._state_lock:
            return self._process is not None and self._initialized

    @property
    def current_thread_id(self) -> str | None:
        with self._state_lock:
            return self._current_thread_id

    @property
    def current_turn_id(self) -> str | None:
        with self._state_lock:
            return self._current_turn_id

    @property
    def turn_active(self) -> bool:
        with self._state_lock:
            return self._turn_active

    def start(self) -> None:
        with self._start_lock:
            start_error: BaseException | None = None
            with self._state_lock:
                if self._process is not None and self._initialized:
                    return
                if self._process is not None or self._cleanup_process is not None:
                    raise CodexAppServerUnavailable("Codex app-server is still starting")
                try:
                    process = subprocess.Popen(
                        self._argv,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        env=self._env,
                        bufsize=0,
                        start_new_session=True,
                    )
                except OSError as exc:
                    self._generation += 1
                    raise CodexAppServerUnavailable(
                        f"Unable to start local Codex app-server: {_bounded_text(exc, 256)}"
                    ) from exc
                self._process = process
                self._cleanup_process = process
                self._cleanup_complete = threading.Event()
                self._generation += 1
                generation = self._generation
                self._initialized = False
                self._provider_version = None
                self._approvals.clear()
                self._questions.clear()
                self._interactive_request_times.clear()
                self._current_turn_id = None
                self._current_item_id = None
                self._turn_active = False
                try:
                    reader = threading.Thread(
                        target=self._reader_main,
                        args=(process,),
                        name=f"pairling-codex-app-server-{generation}",
                        daemon=True,
                    )
                    self._reader = reader
                    reader.start()
                except BaseException as exc:
                    start_error = exc

            try:
                if start_error is not None:
                    raise start_error
                response = self._request(
                    "initialize",
                    {
                        "clientInfo": {
                            "name": "pairling",
                            "title": "Pairling",
                            "version": self._client_version,
                        },
                        "capabilities": {
                            "experimentalApi": True,
                            "requestAttestation": False,
                            "mcpServerOpenaiFormElicitation": False,
                        },
                    },
                    allow_before_initialized=True,
                )
                if not isinstance(response, Mapping):
                    raise CodexAppServerProtocolError("initialize result was not an object")
                for required in ("userAgent", "codexHome", "platformFamily", "platformOs"):
                    if not isinstance(response.get(required), str):
                        raise CodexAppServerProtocolError(
                            f"initialize result omitted {required}"
                        )
                user_agent = response["userAgent"]
                if not is_compatible_codex_app_server_version(user_agent):
                    raise CodexAppServerProtocolError(
                        "Codex app-server requires the reviewed 0.147.0 protocol"
                    )
                self._write_message({"method": "initialized", "params": {}})
                with self._state_lock:
                    if self._process is not process:
                        raise CodexAppServerUnavailable(
                            "Codex app-server became unavailable during initialization"
                        )
                    parsed = _version_tuple(user_agent)
                    self._provider_version = (
                        ".".join(str(part) for part in parsed) if parsed else None
                    )
                    self._initialized = True
            except BaseException as exc:
                self._invalidate_current(process, exc)
                raise

    def restart(self) -> None:
        self.close()
        self.start()

    def close(self) -> None:
        with self._state_lock:
            process = self._process
            cleanup_process = self._cleanup_process
            cleanup_complete = self._cleanup_complete
            reader = self._reader
        if process is not None:
            self._invalidate_current(
                process,
                CodexAppServerUnavailable("Codex app-server closed"),
                emit_event=False,
            )
            return
        if (
            cleanup_process is not None
            and cleanup_complete is not None
            and threading.current_thread() is not reader
        ):
            cleanup_complete.wait()
        self._join_reader(reader)
        with self._state_lock:
            self._clear_stopped_reader(reader)

    def _clear_stopped_reader(self, reader: threading.Thread | None) -> None:
        if self._reader is reader and (
            reader is None or not reader.is_alive()
        ):
            self._reader = None

    def _terminate_process(self, process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    process.terminate()
                except OSError:
                    pass
        try:
            process.wait(timeout=0.75)
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
    def _close_process_streams(process: subprocess.Popen[bytes]) -> None:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is None or getattr(stream, "closed", False):
                continue
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    @staticmethod
    def _join_reader(reader: threading.Thread | None) -> None:
        if (
            reader is None
            or reader is threading.current_thread()
            or reader.ident is None
        ):
            return
        reader.join(timeout=1.0)

    def _invalidate_current(
        self,
        process: subprocess.Popen[bytes],
        error: BaseException,
        *,
        emit_event: bool = True,
    ) -> None:
        pending: list[_PendingRequest] = []
        cleanup_complete: threading.Event | None = None
        reader: threading.Thread | None = None
        owns_cleanup = False
        with self._state_lock:
            if self._process is not process:
                if self._cleanup_process is process:
                    cleanup_complete = self._cleanup_complete
                    reader = self._reader
                else:
                    return
            else:
                owns_cleanup = True
                cleanup_complete = self._cleanup_complete
                reader = self._reader
                self._process = None
                self._initialized = False
                self._provider_version = None
                self._generation += 1
                self._approvals.clear()
                self._questions.clear()
                self._current_thread_id = None
                self._current_turn_id = None
                self._current_item_id = None
                self._turn_active = False
                pending = list(self._pending.values())
                self._pending.clear()
                for item in pending:
                    item.error = error
                self._approval_ready.notify_all()
                if emit_event:
                    self._append_event_locked({
                        "kind": "driver.unavailable",
                        "status": "unavailable",
                        "reason": type(error).__name__,
                    })
        if not owns_cleanup:
            if (
                cleanup_complete is not None
                and threading.current_thread() is not reader
            ):
                cleanup_complete.wait()
            return

        self._terminate_process(process)
        self._close_process_streams(process)
        self._join_reader(reader)
        with self._state_lock:
            self._clear_stopped_reader(reader)
            if self._cleanup_process is process:
                self._cleanup_process = None
            if cleanup_complete is not None:
                cleanup_complete.set()
            if self._cleanup_complete is cleanup_complete:
                self._cleanup_complete = None
        for item in pending:
            item.completed.set()

    def _reader_main(self, process: subprocess.Popen[bytes]) -> None:
        stdout = process.stdout
        if stdout is None:
            self._invalidate_current(
                process,
                CodexAppServerProtocolError("Codex app-server stdout was unavailable"),
            )
            return
        while True:
            try:
                line = stdout.readline(self._max_line_bytes + 1)
            except (OSError, ValueError) as exc:
                self._invalidate_current(
                    process,
                    CodexAppServerEOF(
                        f"Codex app-server stdout failed: {_bounded_text(exc, 256)}"
                    ),
                )
                return
            if not line:
                self._invalidate_current(
                    process,
                    CodexAppServerEOF("Codex app-server closed stdout"),
                )
                return
            if len(line) > self._max_line_bytes or not line.endswith(b"\n"):
                self._invalidate_current(
                    process,
                    CodexAppServerProtocolError(
                        "Codex app-server emitted an oversized JSONL record"
                    ),
                )
                return
            try:
                message = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._invalidate_current(
                    process,
                    CodexAppServerProtocolError(
                        "Codex app-server emitted invalid JSONL"
                    ),
                )
                return
            if not isinstance(message, dict):
                self._invalidate_current(
                    process,
                    CodexAppServerProtocolError(
                        "Codex app-server emitted a non-object JSONL record"
                    ),
                )
                return
            self._handle_message(process, message)

    def _handle_message(
        self,
        process: subprocess.Popen[bytes],
        message: dict[str, Any],
    ) -> None:
        method = message.get("method")
        request_id = message.get("id")
        if method is None and request_id is not None:
            key = str(request_id)
            with self._state_lock:
                if self._process is not process:
                    return
                pending = self._pending.pop(key, None)
                if pending is None:
                    return
                error = message.get("error")
                if isinstance(error, Mapping):
                    code = error.get("code")
                    pending.error = CodexAppServerRPCError(
                        code if isinstance(code, int) else None,
                        error.get("message", "request failed"),
                    )
                elif "result" in message:
                    pending.result = message["result"]
                else:
                    pending.error = CodexAppServerProtocolError(
                        "Codex app-server response omitted result and error"
                    )
                pending.completed.set()
            return
        if not isinstance(method, str):
            self._invalidate_current(
                process,
                CodexAppServerProtocolError(
                    "Codex app-server message omitted a valid method"
                ),
            )
            return
        params = message.get("params")
        if params is None:
            params = {}
        if not isinstance(params, Mapping):
            self._invalidate_current(
                process,
                CodexAppServerProtocolError(
                    "Codex app-server method params were not an object"
                ),
            )
            return
        if request_id is not None:
            self._handle_server_request(method, request_id, params)
        else:
            self._handle_notification(method, params, message)

    def _admit_interactive_request(self) -> bool:
        now = time.monotonic()
        cutoff = now - _INTERACTIVE_REQUEST_WINDOW_SECONDS
        with self._state_lock:
            while (
                self._interactive_request_times
                and self._interactive_request_times[0] <= cutoff
            ):
                self._interactive_request_times.popleft()
            if (
                len(self._interactive_request_times)
                >= _MAX_INTERACTIVE_REQUESTS_PER_WINDOW
                or len(self._approvals) + len(self._questions)
                >= _MAX_INTERACTIVE_REQUESTS_PER_WINDOW
            ):
                return False
            self._interactive_request_times.append(now)
            return True


    def _handle_server_request(
        self,
        method: str,
        request_id: str | int,
        params: Mapping[str, Any],
    ) -> None:
        if method in _QUESTION_METHODS or method in _APPROVAL_METHODS:
            if not self._admit_interactive_request():
                self._write_message({
                    "id": request_id,
                    "error": {
                        "code": -32000,
                        "message": "Provider interactive request rate limit reached",
                    },
                })
                return
        if method in _QUESTION_METHODS:
            self._handle_question_request(request_id, params)
            return
        if method not in _APPROVAL_METHODS:
            # Never implement server-request methods Pairling has not reviewed.
            self._write_message({
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": "Pairling does not support this server request",
                },
            })
            return
        thread_id = _safe_identifier(params.get("threadId"))
        turn_id = _safe_identifier(params.get("turnId"))
        item_id = _safe_identifier(params.get("itemId"))
        approval_id = _safe_identifier(params.get("approvalId"))
        if thread_id is None or turn_id is None or item_id is None:
            self._write_message({
                "id": request_id,
                "error": {
                    "code": -32602,
                    "message": "Approval request lacks correlation proof",
                },
            })
            return
        with self._state_lock:
            approval = _ApprovalRequest(
                provider_request_id=request_id,
                method=method,
                thread_id=thread_id,
                turn_id=turn_id,
                public_approval_id=secrets.token_urlsafe(18),
                item_id=item_id,
                approval_id=approval_id,
                received_generation=self._generation,
            )
            self._approvals[request_id] = approval
            self._current_thread_id = thread_id
            self._current_turn_id = turn_id
            self._current_item_id = item_id
            self._turn_active = True
            event: dict[str, Any] = {
                "kind": "approval.requested",
                **approval.proof(),
                "decision_choices": ["accept", "decline", "cancel"],
            }
            reason = params.get("reason")
            if isinstance(reason, str):
                event["reason"] = _redacted_public_text(reason, 2048)
            command = params.get("command")
            if isinstance(command, str):
                event["command"] = _redacted_public_text(command, 4096)
            cwd = params.get("cwd")
            if isinstance(cwd, str):
                event["cwd"] = _bounded_text(cwd, 4096)
            self._append_event_locked(event)
            self._approval_ready.notify_all()

    def _handle_question_request(
        self,
        request_id: str | int,
        params: Mapping[str, Any],
    ) -> None:
        thread_id = _safe_identifier(params.get("threadId"))
        turn_id = _safe_identifier(params.get("turnId"))
        item_id = _safe_identifier(params.get("itemId"))
        questions = _codex_question_rows(params.get("questions"))
        if (
            thread_id is None
            or turn_id is None
            or item_id is None
            or questions is None
        ):
            self._write_message({
                "id": request_id,
                "error": {
                    "code": -32602,
                    "message": "Question request is malformed or requests secret input",
                },
            })
            return
        with self._state_lock:
            if request_id in self._questions:
                self._write_message({
                    "id": request_id,
                    "error": {
                        "code": -32600,
                        "message": "Question request identity was reused",
                    },
                })
                return
            pending = _QuestionRequest(
                provider_request_id=request_id,
                public_question_request_id=secrets.token_urlsafe(18),
                thread_id=thread_id,
                turn_id=turn_id,
                item_id=item_id,
                received_generation=self._generation,
                questions=questions,
            )
            self._questions[request_id] = pending
            self._current_thread_id = thread_id
            self._current_turn_id = turn_id
            self._current_item_id = item_id
            self._turn_active = True
            self._append_event_locked({
                "kind": "question.requested",
                **pending.proof(),
            })
            self._approval_ready.notify_all()

    def _handle_notification(
        self,
        method: str,
        params: Mapping[str, Any],
        raw_message: Mapping[str, Any],
    ) -> None:
        with self._state_lock:
            if self._internal_diagnostics_enabled:
                self._raw_events.append(dict(raw_message))
            event = self._normalize_notification(method, params)
            if event is not None:
                self._append_event_locked(event)
            self._update_correlation_locked(method, params)

    def _normalize_notification(
        self,
        method: str,
        params: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        kind = _NOTIFICATION_KINDS.get(method)
        if kind is None:
            return None
        event: dict[str, Any] = {"kind": kind}
        thread_id = _safe_identifier(params.get("threadId"))
        turn_id = _safe_identifier(params.get("turnId"))
        item_id = _safe_identifier(params.get("itemId"))
        turn = params.get("turn")
        item = params.get("item")
        if turn_id is None and isinstance(turn, Mapping):
            turn_id = _safe_identifier(turn.get("id"))
        if item_id is None and isinstance(item, Mapping):
            item_id = _safe_identifier(item.get("id"))
        if thread_id is not None:
            event["thread_id"] = thread_id
        if turn_id is not None:
            event["turn_id"] = turn_id
        if item_id is not None:
            event["item_id"] = item_id
        status = params.get("status")
        if isinstance(status, Mapping):
            status = status.get("type")
        if status is None and isinstance(turn, Mapping):
            status = turn.get("status")
        if isinstance(status, str):
            event["status"] = _bounded_text(status, 128)
        delta = params.get("delta")
        if isinstance(delta, str):
            if method == "item/agentMessage/delta":
                event.update({
                    "kind": "partial_text",
                    "text": _redacted_public_text(delta),
                    "role": "assistant",
                })
                return event
            if method in {
                "item/reasoning/summaryTextDelta",
                "item/reasoning/textDelta",
            }:
                event.update({
                    "kind": "partial_text",
                    "text": _redacted_public_text(delta),
                    "role": "thinking",
                })
                return event
            if method == "item/commandExecution/outputDelta":
                event.update({
                    "kind": "tool_result",
                    "content": _redacted_public_text(delta),
                    "is_error": False,
                })
                return event
        if method == "item/completed" and isinstance(item, Mapping):
            item_type = item.get("type")
            if item_type in {"agentMessage", "plan"}:
                text = item.get("text")
                if isinstance(text, str):
                    event.update({
                        "kind": "block_text",
                        "text": _redacted_public_text(text),
                        "role": "assistant",
                    })
            elif item_type == "reasoning":
                parts = [
                    part
                    for key in ("summary", "content")
                    for part in (item.get(key) or [])
                    if isinstance(part, str)
                ]
                event.update({
                    "kind": "block_thinking",
                    "content": _redacted_public_text("\n".join(parts)),
                    "role": "thinking",
                })
            elif item_type == "commandExecution":
                output = item.get("aggregatedOutput")
                event.update({
                    "kind": "tool_result",
                    "content": _redacted_public_text(output or ""),
                    "is_error": bool(
                        item.get("status") == "failed"
                        or (
                            isinstance(item.get("exitCode"), int)
                            and item["exitCode"] != 0
                        )
                    ),
                })
            elif item_type == "mcpToolCall":
                body = (
                    item.get("error")
                    if item.get("error") is not None
                    else item.get("result")
                )
                event.update({
                    "kind": "tool_result",
                    "content": _redacted_public_text(
                        json.dumps(
                            _redact_secrets(body),
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                    ),
                    "is_error": item.get("error") is not None,
                })
            return event
        for source_key, public_key in (
            ("delta", "delta"),
            ("message", "message"),
            ("warning", "message"),
            ("error", "message"),
        ):
            value = params.get(source_key)
            if isinstance(value, str):
                event[public_key] = _redacted_public_text(value)
                break
            if isinstance(value, Mapping) and isinstance(value.get("message"), str):
                event[public_key] = _redacted_public_text(value["message"])
                code = value.get("code")
                if isinstance(code, str):
                    event["code"] = _bounded_text(code, 128)
                break
        request_id = params.get("requestId")
        if kind == "approval.resolved" and isinstance(request_id, (str, int)):
            event["provider_request_id"] = request_id
        return event

    def _update_correlation_locked(
        self,
        method: str,
        params: Mapping[str, Any],
    ) -> None:
        thread_id = _safe_identifier(params.get("threadId"))
        turn_id = _safe_identifier(params.get("turnId"))
        item_id = _safe_identifier(params.get("itemId"))
        turn = params.get("turn")
        item = params.get("item")
        if turn_id is None and isinstance(turn, Mapping):
            turn_id = _safe_identifier(turn.get("id"))
        if item_id is None and isinstance(item, Mapping):
            item_id = _safe_identifier(item.get("id"))
        if thread_id is not None:
            self._current_thread_id = thread_id
        if turn_id is not None:
            self._current_turn_id = turn_id
        if item_id is not None:
            self._current_item_id = item_id
        if method == "serverRequest/resolved":
            request_id = params.get("requestId")
            if isinstance(request_id, (str, int)):
                self._approvals.pop(request_id, None)
                self._questions.pop(request_id, None)
        if method == "turn/started":
            self._turn_active = True
        if method == "turn/completed":
            completed_thread = thread_id or self._current_thread_id
            completed_turn = turn_id or self._current_turn_id
            self._approvals = {
                request_id: approval
                for request_id, approval in self._approvals.items()
                if not (
                    approval.thread_id == completed_thread
                    and approval.turn_id == completed_turn
                )
            }
            self._questions = {
                request_id: question
                for request_id, question in self._questions.items()
                if not (
                    question.thread_id == completed_thread
                    and question.turn_id == completed_turn
                )
            }
            self._current_item_id = None
            self._turn_active = False
        if method == "thread/archived":
            self._approvals.clear()
            self._questions.clear()

    def _append_event_locked(self, event: Mapping[str, Any]) -> None:
        self._cursor += 1
        normalized = {
            "provider_id": "codex",
            "cursor": self._cursor,
            "provider_cursor": self._cursor,
            "capability_generation": self._generation,
            "observed_at": time.time(),
        }
        normalized.update(event)
        self._events.append(normalized)

    def _request(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        omit_params: bool = False,
        allow_before_initialized: bool = False,
    ) -> Any:
        if method in _EXPERIMENTAL_METHODS:
            raise CodexUnsupportedOperation(
                f"Experimental Codex app-server method is not enabled: {method}"
            )
        if method not in _SUPPORTED_METHODS:
            raise CodexUnsupportedOperation(
                f"Unreviewed Codex app-server method is not supported: {method}"
            )
        with self._state_lock:
            process = self._process
            if process is None:
                raise CodexAppServerUnavailable("Codex app-server is unavailable")
            if not allow_before_initialized and not self._initialized:
                raise CodexAppServerUnavailable("Codex app-server is not initialized")
            if len(self._pending) >= _MAX_PENDING_REQUESTS:
                raise CodexAppServerUnavailable(
                    "Codex app-server pending request limit reached"
                )
            self._next_request_id += 1
            request_id = f"pairling-{self._generation}-{self._next_request_id}"
            pending = _PendingRequest(threading.Event())
            self._pending[request_id] = pending
        message: dict[str, Any] = {"method": method, "id": request_id}
        if not omit_params:
            message["params"] = dict(params or {})
        try:
            self._write_message(message)
        except BaseException as exc:
            with self._state_lock:
                self._pending.pop(request_id, None)
            self._invalidate_current(process, exc)
            raise
        if not pending.completed.wait(self._request_timeout):
            error = CodexAppServerTimeout(
                f"Codex app-server request timed out: {method}"
            )
            with self._state_lock:
                self._pending.pop(request_id, None)
            self._invalidate_current(process, error)
            raise error
        if pending.error is not None:
            raise pending.error
        return pending.result

    def _write_message(self, message: Mapping[str, Any]) -> None:
        try:
            payload = json.dumps(
                message,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8") + b"\n"
        except (TypeError, ValueError) as exc:
            raise CodexAppServerProtocolError(
                "Codex app-server request was not valid JSON"
            ) from exc
        if len(payload) > _MAX_REQUEST_BYTES:
            raise CodexAppServerProtocolError(
                "Codex app-server request exceeded the local size limit"
            )
        with self._write_lock:
            with self._state_lock:
                process = self._process
                stdin = process.stdin if process is not None else None
            if process is None or stdin is None:
                raise CodexAppServerUnavailable("Codex app-server is unavailable")
            try:
                stdin.write(payload)
                stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise CodexAppServerEOF(
                    "Codex app-server closed stdin"
                ) from exc

    def poll_events(self, cursor: int | None = None) -> list[dict[str, Any]]:
        if cursor is None:
            cursor = 0
        if not isinstance(cursor, int) or cursor < 0:
            raise ValueError("provider cursor must be a non-negative integer")
        with self._state_lock:
            if self._events:
                oldest = self._events[0]["cursor"]
                if cursor < oldest - 1:
                    raise CodexEventCursorExpired(
                        "Codex provider event cursor is no longer retained"
                    )
            if cursor > self._cursor:
                raise CodexEventCursorExpired(
                    "Codex provider event cursor is ahead of this driver"
                )
            return [dict(event) for event in self._events if event["cursor"] > cursor]

    def internal_diagnostic_payloads(self) -> list[dict[str, Any]]:
        if not self._internal_diagnostics_enabled:
            raise CodexUnsupportedOperation("Internal provider diagnostics are disabled")
        with self._state_lock:
            return [dict(event) for event in self._raw_events]

    def wait_for_approval(self, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        with self._approval_ready:
            while not self._approvals:
                if self._process is None:
                    raise CodexAppServerUnavailable("Codex app-server is unavailable")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CodexAppServerTimeout("Timed out waiting for Codex approval")
                self._approval_ready.wait(remaining)
            approval = next(iter(self._approvals.values()))
            return approval.proof()

    def pending_approvals(self) -> list[dict[str, Any]]:
        with self._state_lock:
            return [approval.proof() for approval in self._approvals.values()]

    def pending_questions(self) -> list[dict[str, Any]]:
        with self._state_lock:
            return [question.proof() for question in self._questions.values()]

    def respond_question(
        self,
        *,
        provider_request_id: str | int,
        thread_id: str,
        turn_id: str,
        item_id: str,
        capability_generation: int,
        decision: str,
        submitted_answers: list[Mapping[str, Any]] | None,
    ) -> None:
        with self._state_lock:
            pending = self._questions.get(provider_request_id)
            if pending is None:
                raise CodexQuestionCorrelationError(
                    "Codex question request is stale or already resolved"
                )
            if (
                pending.thread_id != thread_id
                or pending.turn_id != turn_id
                or pending.item_id != item_id
                or pending.received_generation != capability_generation
                or self._generation != capability_generation
            ):
                raise CodexQuestionCorrelationError(
                    "Codex question correlation proof does not match"
                )
            if decision == "cancel" and submitted_answers in (None, []):
                response_answers: dict[str, dict[str, list[str]]] = {}
            elif decision == "accept" and isinstance(submitted_answers, list):
                if len(submitted_answers) != len(pending.questions):
                    raise CodexQuestionCorrelationError(
                        "Codex question response is incomplete"
                    )
                submitted_by_index: dict[int, Mapping[str, Any]] = {}
                for answer in submitted_answers:
                    index = answer.get("index")
                    if (
                        type(index) is not int
                        or index in submitted_by_index
                        or index < 1
                        or index > len(pending.questions)
                    ):
                        raise CodexQuestionCorrelationError(
                            "Codex question response indexes are invalid"
                        )
                    submitted_by_index[index] = answer
                response_answers = {}
                for question in pending.questions:
                    index = question["index"]
                    answer = submitted_by_index.get(index)
                    if (
                        answer is None
                        or answer.get("topic") != question["topic"]
                        or answer.get("question") != question["question"]
                        or answer.get("options") != question["options"]
                    ):
                        raise CodexQuestionCorrelationError(
                            "Codex question response does not match the pending form"
                        )
                    value = answer.get("answer")
                    if not isinstance(value, str) or "\x00" in value:
                        raise CodexQuestionCorrelationError(
                            "Codex question answer is invalid"
                        )
                    if question["options"] and value not in question["options"]:
                        raise CodexQuestionCorrelationError(
                            "Codex question answer was not an offered option"
                        )
                    response_answers[question["provider_question_id"]] = {
                        "answers": [value],
                    }
            else:
                raise CodexQuestionCorrelationError(
                    "Codex question decision or answers are invalid"
                )
            self._questions.pop(provider_request_id)
        self._write_message({
            "id": provider_request_id,
            "result": {"answers": response_answers},
        })

    def respond_approval(
        self,
        *,
        provider_request_id: str | int,
        thread_id: str,
        turn_id: str,
        item_id: str,
        approval_id: str | None,
        decision: str,
    ) -> None:
        if decision not in {"accept", "decline", "cancel"}:
            raise CodexUnsupportedOperation(
                "Codex approval decision must be accept, decline, or cancel"
            )
        with self._state_lock:
            approval = self._approvals.get(provider_request_id)
            if approval is None:
                raise CodexApprovalCorrelationError(
                    "Codex approval request is absent or already resolved"
                )
            expected = (
                approval.thread_id,
                approval.turn_id,
                approval.item_id,
                approval.approval_id,
                approval.received_generation,
            )
            supplied = (
                thread_id,
                turn_id,
                item_id,
                approval_id,
                self._generation,
            )
            if supplied != expected:
                raise CodexApprovalCorrelationError(
                    "Codex approval correlation proof does not match"
                )
            if (
                self._current_thread_id != thread_id
                or self._current_turn_id != turn_id
                or self._current_item_id != item_id
            ):
                raise CodexApprovalCorrelationError(
                    "Codex approval is no longer current"
                )
            self._approvals.pop(provider_request_id)
        try:
            self._write_message({
                "id": provider_request_id,
                "result": {"decision": decision},
            })
        except BaseException:
            # The response cannot be retried safely after correlation was consumed.
            raise

    def start_thread(
        self,
        *,
        cwd: str,
        model: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "cwd": cwd,
            "approvalPolicy": "on-request",
            "approvalsReviewer": "user",
            "sandbox": "workspace-write",
        }
        if model is not None:
            params["model"] = model
        result = self._request("thread/start", params)
        if not isinstance(result, Mapping) or not isinstance(result.get("thread"), Mapping):
            raise CodexAppServerProtocolError("thread/start result omitted thread")
        thread_id = _safe_identifier(result["thread"].get("id"))
        if thread_id is None:
            raise CodexAppServerProtocolError("thread/start result omitted thread id")
        with self._state_lock:
            self._current_thread_id = thread_id
        return dict(result)

    def set_thread_name(self, thread_id: str, name: str) -> dict[str, Any]:
        result = self._request(
            "thread/name/set",
            {"threadId": thread_id, "name": _bounded_text(name, 512)},
        )
        return dict(result) if isinstance(result, Mapping) else {}

    def resume_thread(self, thread_id: str) -> dict[str, Any]:
        result = self._request("thread/resume", {
            "threadId": thread_id,
            "approvalPolicy": "on-request",
            "approvalsReviewer": "user",
            "sandbox": "workspace-write",
        })
        if (
            not isinstance(result, Mapping)
            or not isinstance(result.get("thread"), Mapping)
            or result["thread"].get("id") != thread_id
        ):
            raise CodexAppServerProtocolError(
                "thread/resume result omitted the requested thread"
            )
        turns = result["thread"].get("turns")
        active_turn_id: str | None = None
        if isinstance(turns, list) and turns:
            last_turn = turns[-1]
            if (
                isinstance(last_turn, Mapping)
                and last_turn.get("status") == "inProgress"
            ):
                active_turn_id = _safe_identifier(last_turn.get("id"))
        with self._state_lock:
            self._current_thread_id = thread_id
            self._current_turn_id = active_turn_id
            self._turn_active = active_turn_id is not None
        return dict(result)

    def fork_thread(
        self,
        thread_id: str,
        *,
        last_turn_id: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "threadId": thread_id,
            "ephemeral": False,
            "approvalPolicy": "on-request",
            "approvalsReviewer": "user",
            "sandbox": "workspace-write",
        }
        if last_turn_id is not None:
            params["lastTurnId"] = last_turn_id
        result = self._request("thread/fork", params)
        if not isinstance(result, Mapping) or not isinstance(result.get("thread"), Mapping):
            raise CodexAppServerProtocolError("thread/fork result omitted thread")
        new_thread_id = _safe_identifier(result["thread"].get("id"))
        if new_thread_id is None:
            raise CodexAppServerProtocolError("thread/fork result omitted thread id")
        return dict(result)

    def archive_thread(self, thread_id: str) -> dict[str, Any]:
        result = self._request("thread/archive", {"threadId": thread_id})
        with self._state_lock:
            self._approvals.clear()
        return dict(result) if isinstance(result, Mapping) else {}

    def compact_thread(self, thread_id: str) -> dict[str, Any]:
        result = self._request("thread/compact/start", {"threadId": thread_id})
        return dict(result) if isinstance(result, Mapping) else {}

    def list_threads(self, *, limit: int | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
                raise ValueError("thread list limit must be between 1 and 100")
            params["limit"] = limit
        result = self._request("thread/list", params)
        if not isinstance(result, Mapping):
            raise CodexAppServerProtocolError("thread/list result was not an object")
        return dict(result)

    def read_thread(self, thread_id: str, *, include_turns: bool = True) -> dict[str, Any]:
        result = self._request(
            "thread/read",
            {"threadId": thread_id, "includeTurns": include_turns},
        )
        if not isinstance(result, Mapping):
            raise CodexAppServerProtocolError("thread/read result was not an object")
        return dict(result)

    def start_turn(
        self,
        thread_id: str,
        text: str,
        *,
        model: str | None = None,
        effort: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(text, str) or not text.strip():
            raise ValueError("Codex prompt text must not be empty")
        params: dict[str, Any] = {
            "threadId": thread_id,
            "input": [{"type": "text", "text": text}],
        }
        if model is not None:
            params["model"] = model
        if effort is not None:
            params["effort"] = effort
        result = self._request("turn/start", params)
        if not isinstance(result, Mapping) or not isinstance(result.get("turn"), Mapping):
            raise CodexAppServerProtocolError("turn/start result omitted turn")
        turn_id = _safe_identifier(result["turn"].get("id"))
        if turn_id is None:
            raise CodexAppServerProtocolError("turn/start result omitted turn id")
        with self._state_lock:
            self._current_thread_id = thread_id
            self._current_turn_id = turn_id
            self._turn_active = True
        return dict(result)

    def steer_turn(
        self,
        thread_id: str,
        expected_turn_id: str,
        text: str,
    ) -> dict[str, Any]:
        if not isinstance(text, str) or not text.strip():
            raise ValueError("Codex steer text must not be empty")
        result = self._request(
            "turn/steer",
            {
                "threadId": thread_id,
                "expectedTurnId": expected_turn_id,
                "input": [{"type": "text", "text": text}],
            },
        )
        if not isinstance(result, Mapping):
            raise CodexAppServerProtocolError("turn/steer result was not an object")
        return dict(result)

    def interrupt_turn(self, thread_id: str, turn_id: str) -> dict[str, Any]:
        result = self._request(
            "turn/interrupt",
            {"threadId": thread_id, "turnId": turn_id},
        )
        return dict(result) if isinstance(result, Mapping) else {}

    def start_review(
        self,
        thread_id: str,
        target: Mapping[str, Any],
    ) -> dict[str, Any]:
        validated = self._validated_review_target(target)
        result = self._request(
            "review/start",
            {"threadId": thread_id, "target": validated, "delivery": "inline"},
        )
        if not isinstance(result, Mapping) or not isinstance(
            result.get("turn"),
            Mapping,
        ):
            raise CodexAppServerProtocolError(
                "review/start result omitted turn"
            )
        turn_id = _safe_identifier(result["turn"].get("id"))
        if turn_id is None:
            raise CodexAppServerProtocolError(
                "review/start result omitted turn id"
            )
        with self._state_lock:
            self._current_thread_id = thread_id
            self._current_turn_id = turn_id
            self._turn_active = True
        return dict(result)

    @staticmethod
    def _validated_review_target(target: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(target, Mapping):
            raise ValueError("review target must be an object")
        target_type = target.get("type")
        if target_type == "uncommittedChanges" and set(target) == {"type"}:
            return {"type": target_type}
        if target_type == "baseBranch" and set(target) == {"type", "branch"}:
            branch = _safe_identifier(target.get("branch"))
            if branch:
                return {"type": target_type, "branch": branch}
        if target_type == "commit" and set(target) <= {"type", "sha", "title"}:
            sha = _safe_identifier(target.get("sha"))
            title = target.get("title")
            if sha and (title is None or isinstance(title, str)):
                return {"type": target_type, "sha": sha, "title": title}
        if target_type == "custom" and set(target) == {"type", "instructions"}:
            instructions = target.get("instructions")
            if isinstance(instructions, str) and instructions.strip():
                return {
                    "type": target_type,
                    "instructions": _bounded_text(instructions),
                }
        raise ValueError("unsupported or malformed review target")

    def list_models(self) -> dict[str, Any]:
        result = self._request("model/list", {})
        if not isinstance(result, Mapping):
            raise CodexAppServerProtocolError("model/list result was not an object")
        return _redact_secrets(result)

    def list_collaboration_modes(self) -> dict[str, Any]:
        result = self._request("collaborationMode/list", {})
        if not isinstance(result, Mapping) or not isinstance(result.get("data"), list):
            raise CodexAppServerProtocolError(
                "collaborationMode/list result was not a catalog"
            )
        return dict(result)

    def update_collaboration_mode(
        self,
        thread_id: str,
        collaboration_mode: Mapping[str, Any],
    ) -> dict[str, Any]:
        result = self._request(
            "thread/settings/update",
            {
                "threadId": thread_id,
                "collaborationMode": dict(collaboration_mode),
            },
        )
        if not isinstance(result, Mapping):
            raise CodexAppServerProtocolError(
                "thread/settings/update result was not an object"
            )
        return dict(result)

    def read_config(self, *, cwd: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"includeLayers": False}
        if cwd is not None:
            params["cwd"] = cwd
        result = self._request("config/read", params)
        if not isinstance(result, Mapping):
            raise CodexAppServerProtocolError("config/read result was not an object")
        return _redact_secrets(result)

    def read_account(self) -> dict[str, Any]:
        result = self._request("account/read", {"refreshToken": False})
        if not isinstance(result, Mapping):
            raise CodexAppServerProtocolError("account/read result was not an object")
        return _sanitized_account(result)

    def read_usage(self) -> dict[str, Any]:
        usage = self._request("account/usage/read", omit_params=True)
        rate_limits = self._request("account/rateLimits/read", omit_params=True)
        if not isinstance(usage, Mapping) or not isinstance(rate_limits, Mapping):
            raise CodexAppServerProtocolError("account usage result was not an object")
        return {
            "usage": _redact_secrets(usage),
            "rate_limits": _redact_secrets(rate_limits),
        }

    def list_mcp_status(self) -> dict[str, Any]:
        result = self._request(
            "mcpServerStatus/list",
            {"limit": 100, "detail": "toolsAndAuthOnly"},
        )
        if not isinstance(result, Mapping):
            raise CodexAppServerProtocolError(
                "mcpServerStatus/list result was not an object"
            )
        return _sanitized_mcp_status(result)



_PROVIDER_READ_OPERATIONS = (
    "provider.config.read",
    "provider.mcp.read",
    "provider.auth.read",
    "provider.usage.read",
    "provider.diagnostics.read",
)
_CODEX_RELEASED_OPERATIONS = released_operation_ids_for_provider("codex")
_MUTATING_OPERATIONS = frozenset({
    "session.prompt.send",
    "session.turn.steer",
    "session.turn.interrupt",
    "session.terminate",
    "session.resume",
    "session.fork",
    "session.compact",
    "session.approval.decide",
    "session.question.answer",
    "session.collaboration_mode.set",
    "session.review.start",
})
_OWNED_LIFECYCLES = frozenset({
    "launching",
    "running",
    "waiting",
    "blocked",
    "closing",
})


class CodexAppServerDriver:
    """Reviewed Pairling control surface for one driver-owned Codex child."""

    def __init__(
        self,
        *,
        binding: ProviderControlBinding,
        argv: Sequence[str],
        env: Mapping[str, str] | None = None,
        provider_settings: Mapping[str, str] | None = None,
        client_version: str = "companiond",
        request_timeout: float = 15.0,
        internal_diagnostics: bool = False,
    ):
        if (
            binding.provider_id != "codex"
            or binding.provider_channel != "app-server-stdio"
        ):
            raise ValueError("Codex driver requires an exact app-server binding")
        if not is_compatible_codex_app_server_version(binding.provider_version):
            raise CodexUnsupportedOperation(
                "Codex driver requires the reviewed 0.147.0 app-server protocol"
            )
        self.binding = binding
        self._safe_launch_profile = {
            "provider_id": "codex",
            "provider_version": normalized_codex_app_server_version(
                binding.provider_version
            ),
            "provider_channel": binding.provider_channel,
            "argv_suffix": tuple(argv[1:]),
            "client_version": client_version,
        }
        self._process = _CodexAppServerProcess(
            argv=argv,
            env=env,
            provider_settings=provider_settings,
            client_version=client_version,
            request_timeout=request_timeout,
            internal_diagnostics=internal_diagnostics,
        )
        self._execute_lock = threading.Lock()
        self._result_lock = threading.Lock()
        self._results: dict[tuple[int, str], ProviderOperationResult] = {}
        self._result_order: deque[tuple[int, str]] = deque()
        self._owned_lock = threading.RLock()
        self._owned_thread_id: str | None = None
        self._owned_project: str | None = None
        self._collaboration_modes: tuple[dict[str, str | None], ...] = ()
        self._selected_collaboration_mode: str | None = None
        self._current_model: str | None = None
        self._owned_threads: dict[str, str] = {}

    @property
    def safe_launch_profile(self) -> dict[str, Any]:
        return dict(self._safe_launch_profile)

    def _refresh_collaboration_modes(self) -> None:
        rows: list[dict[str, str | None]] = []
        seen: set[str] = set()
        try:
            result = self._process.list_collaboration_modes()
            raw_rows = result["data"]
            if len(raw_rows) > 16:
                raise CodexAppServerProtocolError(
                    "Codex collaboration mode catalog is too large"
                )
            for raw in raw_rows:
                if not isinstance(raw, Mapping):
                    continue
                mode = _safe_identifier(raw.get("mode"))
                if mode not in {"plan", "default"} or mode in seen:
                    continue
                raw_name = raw.get("name")
                name = (
                    _bounded_text(raw_name, 128)
                    if isinstance(raw_name, str) and raw_name.strip()
                    else mode.title()
                )
                model = _safe_identifier(raw.get("model"))
                reasoning_effort = _safe_identifier(raw.get("reasoning_effort"))
                rows.append({
                    "mode": mode,
                    "name": name,
                    "model": model,
                    "reasoning_effort": reasoning_effort,
                })
                seen.add(mode)
        except CodexAppServerError:
            rows = []
        with self._owned_lock:
            self._collaboration_modes = tuple(rows)
            if self._selected_collaboration_mode not in seen:
                self._selected_collaboration_mode = (
                    "default" if "default" in seen else None
                )

    def _default_model(self) -> str:
        with self._owned_lock:
            current = self._current_model
        if current is not None:
            return current
        result = self._process.list_models()
        rows = result.get("data")
        if not isinstance(rows, list):
            raise CodexAppServerProtocolError("model/list result omitted models")
        candidates = [
            _safe_identifier(row.get("id") or row.get("model"))
            for row in rows
            if isinstance(row, Mapping)
        ]
        selected = next(
            (
                candidate
                for row, candidate in zip(rows, candidates)
                if isinstance(row, Mapping)
                and row.get("isDefault") is True
                and candidate is not None
            ),
            next((candidate for candidate in candidates if candidate is not None), None),
        )
        if selected is None:
            raise CodexAppServerProtocolError(
                "Codex model catalog has no usable default"
            )
        with self._owned_lock:
            self._current_model = selected
        return selected

    @property
    def capability_generation(self) -> int:
        return self._process.capability_generation

    @property
    def provider_cursor(self) -> str:
        return str(self._process.provider_cursor)

    @property
    def native_session_id(self) -> str | None:
        with self._owned_lock:
            return self._owned_thread_id

    def _ensure_started(self) -> None:
        self._process.start()
        actual = normalized_codex_app_server_version(
            self._process.provider_version
        )
        expected = normalized_codex_app_server_version(
            self.binding.provider_version
        )
        if actual != expected:
            self.close()
            raise CodexAppServerProtocolError(
                "Codex app-server version does not match the provider binding"
            )

    def launch_session(
        self,
        *,
        project: str,
        title: str,
        first_prompt: str = "",
    ) -> dict[str, Any]:
        project_path = Path(project).expanduser()
        resolved_project = str(project_path.resolve())
        with self._owned_lock:
            if self._owned_thread_id is not None:
                raise CodexUnsupportedOperation(
                    "Codex driver already owns a thread"
                )
        self._ensure_started()
        try:
            result = self._process.start_thread(cwd=resolved_project)
            thread = result["thread"]
            thread_id = str(thread["id"])
            with self._owned_lock:
                self._owned_thread_id = thread_id
                self._owned_project = resolved_project
                self._owned_threads[thread_id] = resolved_project
                self._current_model = _safe_identifier(result.get("model"))
                self._selected_collaboration_mode = None
            self._refresh_collaboration_modes()
            if title.strip():
                self._process.set_thread_name(thread_id, title.strip())
            turn_id = None
            if first_prompt.strip():
                turn_result = self._process.start_turn(
                    thread_id,
                    first_prompt,
                )
                turn_id = str(turn_result["turn"]["id"])
            return {
                "native_session_id": thread_id,
                "capability_generation": self.capability_generation,
                "provider_cursor": "0",
                "turn_id": turn_id,
            }
        except BaseException:
            with self._owned_lock:
                self._owned_thread_id = None
                self._owned_project = None
                self._collaboration_modes = ()
                self._selected_collaboration_mode = None
                self._current_model = None
            raise

    def reconcile_session(self, session_truth: dict[str, Any]) -> dict[str, Any]:
        self._ensure_started()
        session_id = session_truth.get("session_id")
        if not isinstance(session_id, str) or not self._owned_session_truth(
            session_id,
            session_truth,
        ):
            raise CodexAppServerUnavailable(
                "Codex managed session ownership proof is stale or mismatched"
            )
        native_id = self._native_id_for_session(session_id)
        self._process.resume_thread(native_id)
        with self._owned_lock:
            self._owned_thread_id = native_id
            self._owned_project = session_truth["project"]
            self._current_model = None
            self._selected_collaboration_mode = None
        self._refresh_collaboration_modes()
        return {
            "native_session_id": native_id,
            "capability_generation": self.capability_generation,
            "provider_cursor": self.provider_cursor,
        }

    def close(self) -> None:
        self._process.close()
        with self._owned_lock:
            self._collaboration_modes = ()
            self._selected_collaboration_mode = None
            self._current_model = None
            self._owned_thread_id = None
            self._owned_project = None

    def poll_events(self, cursor: str | int | None = None) -> list[dict[str, Any]]:
        parsed_cursor: int
        if cursor is None or cursor == "":
            parsed_cursor = 0
        elif isinstance(cursor, int) and not isinstance(cursor, bool):
            parsed_cursor = cursor
        elif isinstance(cursor, str) and cursor.isdigit():
            parsed_cursor = int(cursor)
        else:
            raise CodexEventCursorExpired("Codex provider cursor is malformed")
        events = self._process.poll_events(parsed_cursor)
        public_events: list[dict[str, Any]] = []
        filtered_cursor: int | None = None
        for value in events:
            event = dict(value)
            owned_thread_id = self.native_session_id
            event_thread_id = event.get("thread_id")
            if (
                owned_thread_id is not None
                and event_thread_id is not None
                and event_thread_id != owned_thread_id
            ):
                filtered_cursor = int(event["cursor"])
                continue
            event["binding_id"] = self.binding.binding_id
            event["provider_cursor"] = str(event["provider_cursor"])
            public_approval_id = event.pop("public_approval_id", None)
            public_question_request_id = event.pop(
                "public_question_request_id",
                None,
            )
            event.pop("provider_request_id", None)
            if public_approval_id is not None:
                event["approval_id"] = public_approval_id
            if public_question_request_id is not None:
                event["question_request_id"] = public_question_request_id
            public_events.append(event)
        if filtered_cursor is not None and (
            not public_events
            or int(public_events[-1]["cursor"]) < filtered_cursor
        ):
            public_events.append({
                "provider_id": "codex",
                "binding_id": self.binding.binding_id,
                "capability_generation": self.capability_generation,
                "cursor": filtered_cursor,
                "provider_cursor": str(filtered_cursor),
                "observed_at": time.time(),
                "kind": "lifecycle",
                "status": "cursor_advanced",
            })
        return public_events

    def list_sessions(self) -> list[dict[str, Any]]:
        """Return only threads proven through this driver binding."""
        rows = self._owned_target_rows()
        return [row for _, _, row in rows]

    def read_thread(self, thread_id: str) -> dict[str, Any]:
        if thread_id != self.native_session_id:
            raise CodexUnsupportedOperation(
                "Codex structured reads are limited to this driver-owned thread"
            )
        return _redact_secrets(
            self._process.read_thread(thread_id, include_turns=True)
        )

    def read_status(self) -> dict[str, Any]:
        return {
            "available": self._process.is_available,
            "capability_generation": self.capability_generation,
            "provider_cursor": self.provider_cursor,
            "native_session_id": self.native_session_id,
            "turn_id": self._process.current_turn_id,
            "turn_active": self._process.turn_active,
            "pending_approval_count": len(self._process.pending_approvals()),
            "pending_question_count": len(self._process.pending_questions()),
        }

    def snapshot(
        self,
        *,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderControlSnapshot:
        observed_at = time.time()
        blocked_reason: str | None = None
        try:
            self._ensure_started()
        except CodexAppServerError as exc:
            blocked_reason = f"codex_app_server_unavailable:{type(exc).__name__}"

        operations: tuple[str, ...] = ()
        values: list[ControlValue] = []
        choices: list[ControlChoices] = []
        if blocked_reason is None and session_id is None:
            if session_truth is not None:
                blocked_reason = "provider_wide_snapshot_has_session_truth"
            else:
                operations = tuple(
                    operation_id
                    for operation_id in _PROVIDER_READ_OPERATIONS
                    if operation_id in _CODEX_RELEASED_OPERATIONS
                )
        elif blocked_reason is None:
            if not self._owned_session_truth(session_id, session_truth):
                blocked_reason = "session_not_owned_by_codex_driver"
            else:
                operations_list = ["session.terminate"]
                if self._process.turn_active and self._process.current_turn_id:
                    operations_list.extend((
                        "session.turn.steer",
                        "session.turn.interrupt",
                    ))
                else:
                    operations_list.extend((
                        "session.prompt.send",
                        "session.compact",
                        "session.review.start",
                    ))
                    with self._owned_lock:
                        collaboration_modes = self._collaboration_modes
                        selected_collaboration_mode = (
                            self._selected_collaboration_mode
                        )
                    if collaboration_modes:
                        operations_list.append(
                            "session.collaboration_mode.set"
                        )
                        choices.append(ControlChoices(
                            "session.collaboration_mode.set",
                            "collaboration_mode",
                            tuple(
                                ControlChoice(
                                    str(row["mode"]),
                                    str(row["name"]),
                                )
                                for row in collaboration_modes
                            ),
                        ))
                        if selected_collaboration_mode is not None:
                            values.append(ControlValue(
                                "session.collaboration_mode.set",
                                "collaboration_mode",
                                selected_collaboration_mode,
                            ))
                    target_rows = self._owned_target_rows()
                    current_native_id = self.native_session_id
                    resume_choices = tuple(
                        ControlChoice(target_id, label)
                        for target_id, label, _ in target_rows
                        if target_id == current_native_id
                    )
                    if resume_choices:
                        operations_list.append("session.resume")
                        choices.append(
                            ControlChoices(
                                "session.resume",
                                "target_session",
                                resume_choices,
                            )
                        )
                    fork_choices = tuple(
                        ControlChoice(target_id, label)
                        for target_id, label, _ in target_rows
                        if target_id == current_native_id
                    )
                    if fork_choices:
                        operations_list.append("session.fork")
                        choices.append(
                            ControlChoices(
                                "session.fork",
                                "target_session",
                                fork_choices,
                            )
                        )
                approvals = [
                    item
                    for item in self._process.pending_approvals()
                    if item["thread_id"] == self.native_session_id
                ]
                if approvals:
                    operations_list.append("session.approval.decide")
                    choices.append(ControlChoices(
                        "session.approval.decide",
                        "approval_id",
                        tuple(
                            ControlChoice(
                                item["public_approval_id"],
                                "Pending Codex approval",
                            )
                            for item in approvals
                        ),
                    ))
                    choices.append(ControlChoices(
                        "session.approval.decide",
                        "decision",
                        (
                            ControlChoice("accept", "Approve once"),
                            ControlChoice("decline", "Decline"),
                            ControlChoice("cancel", "Cancel turn"),
                        ),
                    ))
                questions = [
                    item
                    for item in self._process.pending_questions()
                    if item["thread_id"] == self.native_session_id
                ]
                if questions:
                    pending = questions[0]
                    operations_list.append("session.question.answer")
                    choices.append(ControlChoices(
                        "session.question.answer",
                        "decision",
                        (
                            ControlChoice("accept", "Submit answers"),
                            ControlChoice("cancel", "Cancel request"),
                        ),
                    ))
                    choices.append(ControlChoices(
                        "session.question.answer",
                        "question_request_id",
                        (
                            ControlChoice(
                                pending["public_question_request_id"],
                                "Pending Codex question",
                            ),
                        ),
                    ))
                    values.append(ControlValue(
                        "session.question.answer",
                        "answers",
                        [
                            {
                                "index": question["index"],
                                "topic": question["topic"],
                                "question": question["question"],
                                "options": list(question["options"]),
                                "answer": "",
                            }
                            for question in pending["questions"]
                        ],
                    ))
                operations = tuple(
                    operation_id
                    for operation_id in operations_list
                    if operation_id in _CODEX_RELEASED_OPERATIONS
                )
                identity = ProviderSessionIdentity(
                    provider_id="codex",
                    session_id=session_id,
                    binding_id=self.binding.binding_id,
                    capability_generation=self.capability_generation,
                )
                values.extend(
                    ControlValue(operation_id, "session", identity)
                    for operation_id in operations
                )

        return ProviderControlSnapshot(
            provider_id=self.binding.provider_id,
            provider_version=self.binding.provider_version,
            provider_channel=self.binding.provider_channel,
            binding_id=self.binding.binding_id,
            capability_generation=self.capability_generation,
            observed_at=observed_at,
            valid_until=observed_at + 5.0,
            advertised_operations=operations,
            values=tuple(values),
            choices=tuple(choices),
            blocked_reason=blocked_reason,
            provider_cursor=self.provider_cursor,
        )

    def _owned_session_truth(
        self,
        session_id: str,
        session_truth: dict[str, Any] | None,
        *,
        allow_registered_fork: bool = False,
    ) -> bool:
        if not isinstance(session_id, str) or not isinstance(session_truth, dict):
            return False
        try:
            native_id = self._native_id_for_session(session_id)
        except CodexUnsupportedOperation:
            return False
        project = session_truth.get("project")
        cwd = session_truth.get("cwd")
        current = self.native_session_id
        with self._owned_lock:
            owned_project = self._owned_project
        live_attachment = (
            session_truth.get("lifecycle") in _OWNED_LIFECYCLES
            and session_truth.get("driver_available") is True
            and session_truth.get("is_live") is True
            and session_truth.get("controllable") is True
        )
        registered_fork = (
            allow_registered_fork
            and session_truth.get("lifecycle") == "blocked"
            and session_truth.get("driver_available") is False
            and session_truth.get("is_live") is False
            and session_truth.get("controllable") is False
            and _safe_opaque(session_truth.get("fork_parent_session_id"))
            and _safe_opaque(session_truth.get("fork_action_id"))
            and _safe_opaque(session_truth.get("fork_provider_operation_id"))
            and session_truth.get("fork_parent_session_id") != session_id
        )
        if registered_fork:
            try:
                self._native_id_for_session(
                    str(session_truth["fork_parent_session_id"])
                )
            except CodexUnsupportedOperation:
                return False
        return (
            session_truth.get("provider_id") == "codex"
            and session_truth.get("provider") == "codex"
            and session_truth.get("session_id") == session_id
            and session_truth.get("native_id") == native_id
            and session_truth.get("managed") is True
            and session_truth.get("owner") == "provider_driver"
            and isinstance(project, str)
            and Path(project).is_absolute()
            and cwd == project
            and (owned_project is None or project == owned_project)
            and session_truth.get("binding_id") == self.binding.binding_id
            and session_truth.get("capability_generation")
            == self.capability_generation
            and (live_attachment or registered_fork)
            and session_truth.get("terminal_backed") is False
            and (current is None or current == native_id)
        )

    @staticmethod
    def _native_id_for_session(session_id: str) -> str:
        if not session_id.startswith("codex:"):
            raise CodexUnsupportedOperation("Codex session identity is malformed")
        native_id = session_id.removeprefix("codex:")
        if _safe_identifier(native_id) is None:
            raise CodexUnsupportedOperation("Codex native session identity is malformed")
        return native_id

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
            or not self._owned_session_truth(session_id, session_truth)
        ):
            raise CodexUnsupportedOperation(
                "Codex operation correlation proof is unavailable"
            )
        snapshot = self.snapshot(
            session_id=session_id,
            session_truth=session_truth,
        )
        if operation_id not in snapshot.advertised_operations:
            raise CodexUnsupportedOperation(
                "Codex operation is not currently advertised"
            )
        return ProviderOperationCorrelation(
            _codex_operation_id(
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
        cache_key = (capability_generation, client_action_id)
        with self._result_lock:
            cached = self._results.get(cache_key)
            if cached is not None:
                if cached.operation_id != operation_id:
                    raise CodexUnsupportedOperation(
                        "client action id was already used for another operation"
                    )
                return cached
        with self._execute_lock:
            with self._result_lock:
                cached = self._results.get(cache_key)
                if cached is not None:
                    return cached
            expected_operation_id = _codex_operation_id(
                self.binding.binding_id,
                capability_generation,
                client_action_id,
            )
            if provider_correlation is None:
                provider_correlation = ProviderOperationCorrelation(
                    expected_operation_id,
                    self.provider_cursor,
                )
            elif (
                not isinstance(
                    provider_correlation,
                    ProviderOperationCorrelation,
                )
                or provider_correlation.provider_operation_id
                != expected_operation_id
            ):
                raise CodexUnsupportedOperation(
                    "Codex operation correlation is stale"
                )
            provider_operation_id = provider_correlation.provider_operation_id
            result = self._execute_once(
                operation_id=operation_id,
                input_payload=input_payload,
                binding_id=binding_id,
                capability_generation=capability_generation,
                session_id=session_id,
                provider_operation_id=provider_operation_id,
                prepared_attachments=prepared_attachments,
                provider_cursor=provider_correlation.provider_cursor,
            )
            self._remember_result(cache_key, result)
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
            or not isinstance(provider_correlation, ProviderOperationCorrelation)
        ):
            return None
        if session_id is None:
            if session_truth is not None:
                return None
        elif not self._owned_session_truth(session_id, session_truth):
            return None
        with self._result_lock:
            result = self._results.get(
                (capability_generation, client_action_id)
            )
        if (
            result is None
            or result.operation_id != operation_id
            or result.provider_operation_id
            != provider_correlation.provider_operation_id
            or result.provider_cursor != provider_correlation.provider_cursor
            or result.status
            not in {
                OperationResultStatus.APPLIED,
                OperationResultStatus.REJECTED,
            }
        ):
            return None
        return result

    def _remember_result(
        self,
        key: tuple[int, str],
        result: ProviderOperationResult,
    ) -> None:
        with self._result_lock:
            if key not in self._results:
                self._result_order.append(key)
            self._results[key] = result
            while len(self._result_order) > 256:
                oldest = self._result_order.popleft()
                self._results.pop(oldest, None)

    def _execute_once(
        self,
        *,
        operation_id: str,
        input_payload: dict[str, Any],
        binding_id: str,
        capability_generation: int,
        session_id: str | None,
        provider_operation_id: str,
        prepared_attachments: tuple[Any, ...],
        provider_cursor: str | None,
    ) -> ProviderOperationResult:
        if (
            binding_id != self.binding.binding_id
            or capability_generation != self.capability_generation
        ):
            raise CodexAppServerUnavailable(
                "Codex control binding or generation is stale"
            )
        try:
            public_result, status = self._dispatch_operation(
                operation_id,
                input_payload,
                session_id,
                prepared_attachments,
            )
        except (CodexAppServerTimeout, CodexAppServerEOF) as exc:
            status = (
                OperationResultStatus.OUTCOME_UNKNOWN
                if operation_id in _MUTATING_OPERATIONS
                else OperationResultStatus.REJECTED
            )
            public_result = {
                "error": "provider_unavailable",
                "reason": type(exc).__name__,
            }
        except CodexAppServerRPCError as exc:
            status = OperationResultStatus.REJECTED
            public_result = {
                "error": "provider_rejected",
                "provider_code": exc.code,
            }
        except (
            CodexAppServerUnavailable,
            CodexAppServerProtocolError,
            CodexUnsupportedOperation,
            CodexApprovalCorrelationError,
            ValueError,
        ) as exc:
            status = OperationResultStatus.REJECTED
            public_result = {
                "error": "operation_rejected",
                "reason": type(exc).__name__,
            }
        return ProviderOperationResult(
            operation_id=operation_id,
            provider_operation_id=provider_operation_id,
            status=status,
            public_result=_redact_secrets(public_result),
            provider_cursor=provider_cursor,
        )

    def _dispatch_operation(
        self,
        operation_id: str,
        input_payload: dict[str, Any],
        session_id: str | None,
        prepared_attachments: tuple[Any, ...],
    ) -> tuple[dict[str, Any], OperationResultStatus]:
        if operation_id in _PROVIDER_READ_OPERATIONS:
            if session_id is not None:
                raise CodexUnsupportedOperation(
                    "Provider-wide Codex read cannot carry a session"
                )
            if operation_id == "provider.config.read":
                return self._process.read_config(), OperationResultStatus.APPLIED
            if operation_id == "provider.mcp.read":
                return self._process.list_mcp_status(), OperationResultStatus.APPLIED
            if operation_id == "provider.auth.read":
                return self._process.read_account(), OperationResultStatus.APPLIED
            if operation_id == "provider.usage.read":
                return self._process.read_usage(), OperationResultStatus.APPLIED
            models = self._process.list_models()
            return {
                **self.read_status(),
                "models": models,
            }, OperationResultStatus.APPLIED

        native_id = self._validated_operation_session(input_payload, session_id)
        if (
            operation_id in {
                "session.prompt.send",
                "session.collaboration_mode.set",
                "session.resume",
                "session.fork",
                "session.compact",
                "session.review.start",
            }
            and self._process.turn_active
        ):
            raise CodexUnsupportedOperation(
                "Codex operation requires an inactive turn"
            )
        if operation_id == "session.prompt.send":
            if prepared_attachments:
                raise CodexUnsupportedOperation(
                    "Codex app-server attachment forwarding is not reviewed"
                )
            result = self._process.start_turn(native_id, input_payload["prompt"])
            return {
                "thread_id": native_id,
                "turn_id": result["turn"]["id"],
            }, OperationResultStatus.APPLIED
        if operation_id == "session.collaboration_mode.set":
            if prepared_attachments:
                raise CodexUnsupportedOperation(
                    "Codex collaboration mode cannot carry attachments"
                )
            requested_mode = input_payload["collaboration_mode"]
            with self._owned_lock:
                matches = [
                    row
                    for row in self._collaboration_modes
                    if row["mode"] == requested_mode
                ]
            if len(matches) != 1:
                raise CodexUnsupportedOperation(
                    "Codex collaboration mode is not in the live catalog"
                )
            mode = matches[0]
            model = mode["model"] or self._default_model()
            settings: dict[str, Any] = {"model": model}
            if mode["reasoning_effort"] is not None:
                settings["reasoning_effort"] = mode["reasoning_effort"]
            self._process.update_collaboration_mode(
                native_id,
                {
                    "mode": requested_mode,
                    "settings": settings,
                },
            )
            with self._owned_lock:
                self._selected_collaboration_mode = requested_mode
                self._current_model = model
            return {
                "thread_id": native_id,
                "collaboration_mode": requested_mode,
            }, OperationResultStatus.APPLIED
        if operation_id == "session.turn.steer":
            turn_id = self._process.current_turn_id
            if not self._process.turn_active or turn_id is None:
                raise CodexUnsupportedOperation("Codex turn is not active")
            result = self._process.steer_turn(
                native_id,
                turn_id,
                input_payload["instruction"],
            )
            return {
                "thread_id": native_id,
                "turn_id": result.get("turnId", turn_id),
            }, OperationResultStatus.APPLIED
        if operation_id == "session.turn.interrupt":
            turn_id = self._process.current_turn_id
            if not self._process.turn_active or turn_id is None:
                raise CodexUnsupportedOperation("Codex turn is not active")
            self._process.interrupt_turn(native_id, turn_id)
            return {
                "thread_id": native_id,
                "turn_id": turn_id,
            }, OperationResultStatus.APPLIED
        if operation_id == "session.terminate":
            self._process.archive_thread(native_id)
            self.close()
            return {"thread_id": native_id, "archived": True}, OperationResultStatus.APPLIED
        if operation_id == "session.resume":
            target_id = self._validated_target_session(
                input_payload.get("target_session")
            )
            if target_id != native_id:
                raise CodexUnsupportedOperation(
                    "Codex resume target is not the current bound session"
                )
            self._process.resume_thread(target_id)
            return {"thread_id": target_id}, OperationResultStatus.APPLIED
        if operation_id == "session.fork":
            target_id = self._validated_target_session(
                input_payload.get("target_session")
            )
            if target_id != native_id:
                raise CodexUnsupportedOperation(
                    "Codex fork target is not the current bound session"
                )
            result = self._process.fork_thread(target_id)
            new_id = result["thread"]["id"]
            with self._owned_lock:
                project = self._owned_threads.get(target_id)
                if project is None:
                    raise CodexUnsupportedOperation(
                        "Codex fork target ownership changed"
                    )
                self._owned_threads[new_id] = project
            return {
                "source_thread_id": target_id,
                "native_session_id": new_id,
            }, OperationResultStatus.APPLIED
        if operation_id == "session.compact":
            self._process.compact_thread(native_id)
            return {"thread_id": native_id}, OperationResultStatus.APPLIED
        if operation_id == "session.review.start":
            result = self._process.start_review(
                native_id,
                {"type": "uncommittedChanges"},
            )
            turn = result.get("turn")
            return {
                "thread_id": native_id,
                "turn_id": turn.get("id") if isinstance(turn, Mapping) else None,
            }, OperationResultStatus.APPLIED
        if operation_id == "session.approval.decide":
            public_approval_id = input_payload["approval_id"]
            matches = [
                proof
                for proof in self._process.pending_approvals()
                if proof["public_approval_id"] == public_approval_id
                and proof["thread_id"] == native_id
            ]
            if len(matches) != 1:
                raise CodexApprovalCorrelationError(
                    "Codex approval nonce is absent or ambiguous"
                )
            proof = matches[0]
            self._process.respond_approval(
                provider_request_id=proof["provider_request_id"],
                thread_id=proof["thread_id"],
                turn_id=proof["turn_id"],
                item_id=proof["item_id"],
                approval_id=proof["approval_id"],
                decision=input_payload["decision"],
            )
            return {
                "thread_id": native_id,
                "approval_id": public_approval_id,
                "decision": input_payload["decision"],
            }, OperationResultStatus.APPLIED
        if operation_id == "session.question.answer":
            public_question_request_id = input_payload["question_request_id"]
            matches = [
                proof
                for proof in self._process.pending_questions()
                if proof["public_question_request_id"] == public_question_request_id
                and proof["thread_id"] == native_id
            ]
            if len(matches) != 1:
                raise CodexQuestionCorrelationError(
                    "Codex question nonce is absent or ambiguous"
                )
            proof = matches[0]
            self._process.respond_question(
                provider_request_id=proof["provider_request_id"],
                thread_id=proof["thread_id"],
                turn_id=proof["turn_id"],
                item_id=proof["item_id"],
                capability_generation=proof["capability_generation"],
                decision=input_payload["decision"],
                submitted_answers=input_payload.get("answers"),
            )
            return {
                "thread_id": native_id,
                "question_request_id": public_question_request_id,
                "decision": input_payload["decision"],
                "answer_count": len(input_payload.get("answers") or []),
            }, OperationResultStatus.APPLIED
        raise CodexUnsupportedOperation(
            f"Codex driver does not implement reviewed operation: {operation_id}"
        )

    def _validated_operation_session(
        self,
        input_payload: Mapping[str, Any],
        session_id: str | None,
    ) -> str:
        if session_id is None:
            raise CodexUnsupportedOperation("Codex session operation lacks a session")
        session_value = input_payload.get("session")
        identity = (
            session_value
            if isinstance(session_value, ProviderSessionIdentity)
            else ProviderSessionIdentity.from_payload(session_value)
        )
        if (
            identity.provider_id != "codex"
            or identity.session_id != session_id
            or identity.binding_id != self.binding.binding_id
            or identity.capability_generation != self.capability_generation
        ):
            raise CodexUnsupportedOperation(
                "Codex session operation identity is stale or mismatched"
            )
        native_id = self._native_id_for_session(session_id)
        current = self.native_session_id
        if current is not None and current != native_id:
            raise CodexUnsupportedOperation(
                "Codex driver is bound to another native thread"
            )
        return native_id

    def _owned_target_rows(
        self,
    ) -> tuple[tuple[str, str, dict[str, Any]], ...]:
        try:
            payload = self._process.list_threads(limit=100)
        except CodexAppServerError:
            return ()
        rows = payload.get("data")
        if not isinstance(rows, list):
            return ()
        with self._owned_lock:
            owned = dict(self._owned_threads)
            project = self._owned_project
        result: list[tuple[str, str, dict[str, Any]]] = []
        seen: set[str] = set()
        for raw in rows:
            if not isinstance(raw, Mapping):
                continue
            target_id = _safe_identifier(raw.get("id"))
            if (
                target_id is None
                or target_id in seen
                or owned.get(target_id) != project
            ):
                continue
            name = raw.get("name")
            label = (
                name[:160]
                if isinstance(name, str)
                and name
                and all(ord(char) >= 32 for char in name[:160])
                else f"Codex session {target_id[:24]}"
            )
            result.append(
                (target_id, label, _redact_secrets(dict(raw)))
            )
            seen.add(target_id)
        return tuple(result)

    def _validated_target_session(self, value: Any) -> str:
        target_id = _safe_identifier(value)
        if target_id is None:
            raise CodexUnsupportedOperation(
                "Codex target session identity is malformed"
            )
        if target_id not in {
            candidate_id
            for candidate_id, _, _ in self._owned_target_rows()
        }:
            raise CodexUnsupportedOperation(
                "Codex target session is stale or not owned by this binding"
            )
        return target_id
