"""Managed Claude Agent SDK driver over a local bounded JSONL sidecar.

This module only controls sessions whose SDK process it launched. Ambient Claude
TUI processes remain outside this driver and keep the raw PTY fallback.
"""

from __future__ import annotations

import collections
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Mapping

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
from .operations import InputType, REVIEWED_OPERATION_CATALOG, OperationCatalogError
from ._sidecar_process import close_owned_process
from .base import managed_child_environment

CLAUDE_SIDECAR_PROTOCOL_VERSION = 2
CLAUDE_AGENT_SDK_VERSION = "0.3.220"
CLAUDE_CODE_VERSION = "2.1.220"


def _is_reviewed_claude_code_version(value: str) -> bool:
    return value in {
        CLAUDE_CODE_VERSION,
        f"{CLAUDE_CODE_VERSION} (Claude Code)",
    }


CLAUDE_AGENT_SDK_PACKAGE = "@anthropic-ai/claude-agent-sdk"
_MAX_LINE_BYTES = 256 * 1024
_MAX_EVENTS = 1024
_MAX_ACTION_RESULTS = 256
_SAFE_PERMISSION_MODES = ("default", "plan")
_APPROVAL_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_APPROVAL_PREVIEW_LENGTH = 4096
_MAX_APPROVAL_LIFETIME_SECONDS = 5 * 60
_RESOLVED_APPROVAL_LIMIT = 1024
_MAX_QUESTION_LIFETIME_SECONDS = 11 * 60
_REVIEWED_DISCOVERY_CAPABILITIES = frozenset({
    "stream_input",
    "interrupt",
    "close",
    "set_model",
    "set_permission_mode",
    "supported_commands",
    "supported_models",
    "mcp_status",
    "account_info",
    "rewind_files",
    "provider.agents.read",
    "provider.status.read",
    "provider.mcp.reconnect",
    "provider.mcp.set_enabled",
    "session.context.read",
    "session.history.read",
    "ask_user_question",
})

class ClaudeSidecarError(RuntimeError):
    """Base class for typed local sidecar failures."""


class ClaudeSidecarUnavailable(ClaudeSidecarError):
    pass


class ClaudeSidecarTimeout(ClaudeSidecarUnavailable):
    pass


class ClaudeSidecarEOF(ClaudeSidecarUnavailable):
    pass


class ClaudeSidecarProtocolError(ClaudeSidecarUnavailable):
    pass


class ClaudeUnsupportedOperation(ClaudeSidecarError):
    pass


class ClaudePermissionCorrelationError(ClaudeSidecarError):
    pass
class ClaudeQuestionCorrelationError(ClaudeSidecarError):
    pass




class ClaudeStaleBinding(ClaudeSidecarError):
    pass


class _ClaudeSidecarResponseError(ClaudeSidecarError):
    def __init__(self, code: str, message: str):
        self.code = _bounded_string(code, 96) or "provider_rejected"
        super().__init__(_bounded_string(message, 300) or "Claude sidecar rejected the operation")


_REQUEST_FIELDS: dict[str, frozenset[str]] = {
    "handshake": frozenset({"protocol_version"}),
    "launch": frozenset({"project", "title", "first_prompt", "binding_id"}),
    "discover": frozenset(),
    "prompt": frozenset({"session_id", "prompt", "client_action_id"}),
    "steer": frozenset({"session_id", "instruction", "client_action_id"}),
    "interrupt": frozenset({"session_id", "client_action_id"}),
    "terminate": frozenset({"session_id", "client_action_id"}),
    "compact": frozenset({"session_id", "client_action_id"}),
    "rewind": frozenset({"session_id", "message_id", "client_action_id"}),
    "set_model": frozenset({"session_id", "model", "client_action_id"}),
    "set_permission_mode": frozenset({"session_id", "mode", "client_action_id"}),
    "permission_decision": frozenset({
        "approval_id",
        "session_id",
        "binding_id",
        "tool_use_id",
        "approval_digest",
        "decision",
    }),
    "question_response": frozenset({
        "question_request_id",
        "session_id",
        "binding_id",
        "tool_use_id",
        "question_digest",
        "decision",
        "answers",
    }),
    "read_commands": frozenset(),
    "read_agents": frozenset({"session_id"}),
    "read_status": frozenset({"session_id"}),
    "read_mcp": frozenset(),
    "mcp_reconnect": frozenset({"session_id", "server_id", "client_action_id"}),
    "mcp_set_enabled": frozenset({"session_id", "server_id", "enabled", "client_action_id"}),
    "read_account": frozenset(),
    "read_context": frozenset({"session_id"}),
    "read_history": frozenset({"session_id"}),
    "read_diagnostics": frozenset(),
}

_TEXT_LIMITS = {
    "project": 4096,
    "title": 500,
    "first_prompt": 200_000,
    "binding_id": 256,
    "session_id": 512,
    "prompt": 200_000,
    "instruction": 200_000,
    "client_action_id": 512,
    "message_id": 256,
    "model": 256,
    "mode": 64,
    "approval_id": 256,
    "question_request_id": 256,
    "question_digest": 64,
    "approval_digest": 64,
    "tool_use_id": 256,
    "decision": 64,
    "server_id": 256,
}

_EVENT_KIND_MAP = {
    "message.delta": "stream_delta",
    "message.assistant": "assistant_message",
    "message.user": "message",
    "tool.use": "tool_use",
    "tool.result": "tool_result",
}

_SECRET_KEY_RE = re.compile(
    r"(?:authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret|credential|private[_-]?key)",
    re.IGNORECASE,
)
_SECRET_TEXT_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{12,}"),
    re.compile(r"\b[A-Z][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD)\s*=\s*[^\s]+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
)


def default_claude_sidecar_command() -> tuple[str, ...] | None:
    """Resolve a fixed local Node executable and the vendored sidecar source."""

    configured = os.environ.get("PAIRLING_NODE_BIN")
    candidates = [configured] if configured else []
    candidates.extend(("/opt/homebrew/bin/node", "/usr/local/bin/node", shutil.which("node")))
    node = next(
        (
            str(Path(value).expanduser())
            for value in candidates
            if value and Path(value).expanduser().is_file() and os.access(Path(value).expanduser(), os.X_OK)
        ),
        None,
    )
    sidecar = Path(__file__).with_name("claude_agent_sidecar.mjs")
    if node is None or not sidecar.is_file() or sidecar.is_symlink():
        return None
    return (node, str(sidecar))


class _ClaudeAgentSidecarProcess:
    """One local SDK child with request correlation and bounded output."""

    def __init__(
        self,
        *,
        argv: tuple[str, ...],
        env: Mapping[str, str] | None = None,
        provider_settings: Mapping[str, str] | None = None,
        request_timeout: float = 8.0,
        handshake_timeout: float = 8.0,
        max_line_bytes: int = _MAX_LINE_BYTES,
        event_limit: int = _MAX_EVENTS,
    ):
        if not argv or not all(isinstance(item, str) and item for item in argv):
            raise ValueError("Claude sidecar argv must be a fixed non-empty tuple")
        self.argv = tuple(argv)
        ambient = os.environ if env is None else env
        settings = dict(provider_settings or {})
        sdk_root = ambient.get("PAIRLING_CLAUDE_AGENT_SDK_ROOT")
        if isinstance(sdk_root, str) and sdk_root:
            settings["PAIRLING_CLAUDE_AGENT_SDK_ROOT"] = sdk_root
        self.env = managed_child_environment(
            source=ambient,
            provider_settings=settings,
        )
        self.request_timeout = max(0.01, float(request_timeout))
        self.handshake_timeout = max(0.01, float(handshake_timeout))
        self.max_line_bytes = max(4096, min(int(max_line_bytes), _MAX_LINE_BYTES))
        self.event_limit = max(16, min(int(event_limit), _MAX_EVENTS))

        self._process: subprocess.Popen[bytes] | None = None
        self._reader: threading.Thread | None = None
        self._write_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._pending: dict[str, queue.Queue[Any]] = {}
        self._events: collections.deque[dict[str, Any]] = collections.deque(maxlen=self.event_limit)
        self._pending_permissions: dict[str, dict[str, Any]] = {}
        self._pending_questions: dict[str, dict[str, Any]] = {}
        self._resolved_permissions: collections.OrderedDict[
            str, tuple[str, str, str, str]
        ] = collections.OrderedDict()
        self._event_cursor = 0
        self._generation = 1
        self._available = False
        self._closing = False
        self._discovery_fingerprint: str | None = None
        self._last_discovery: dict[str, Any] | None = None
        self.native_session_id: str | None = None
        self.binding_id: str | None = None
        self.sdk_version: str | None = None
        self.claude_code_version: str | None = None
        self.node_version: str | None = None

    @property
    def capability_generation(self) -> int:
        with self._state_lock:
            return self._generation

    @property
    def is_available(self) -> bool:
        with self._state_lock:
            process = self._process
            return self._available and process is not None and process.poll() is None

    @property
    def last_discovery(self) -> dict[str, Any] | None:
        with self._state_lock:
            return dict(self._last_discovery) if self._last_discovery is not None else None

    def start(self) -> None:
        with self._state_lock:
            if self.is_available:
                return
            self._closing = False
            try:
                process = subprocess.Popen(
                    self.argv,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    env=self.env,
                    bufsize=0,
                    close_fds=True,
                )
            except OSError as exc:
                raise ClaudeSidecarUnavailable(f"unable to start Claude Agent SDK sidecar: {exc}") from exc
            if process.stdin is None or process.stdout is None:
                close_owned_process(process)
                raise ClaudeSidecarUnavailable("Claude Agent SDK sidecar did not expose stdio")
            self._process = process
            self._available = True
            self._generation += 1
            reader = threading.Thread(
                target=self._reader_loop,
                name="pairling-claude-agent-sdk-reader",
                daemon=True,
            )
            self._reader = reader
            try:
                reader.start()
            except BaseException:
                self._process = None
                self._reader = None
                self._available = False
                close_owned_process(process)
                raise

        try:
            result = self._request(
                "handshake",
                {"protocol_version": CLAUDE_SIDECAR_PROTOCOL_VERSION},
                timeout=self.handshake_timeout,
            )
            self._validate_handshake(result)
        except Exception as exc:
            error = exc if isinstance(exc, ClaudeSidecarUnavailable) else ClaudeSidecarUnavailable(
                "Claude Agent SDK handshake failed"
            )
            self._invalidate(error)
            raise error from exc

    def restart(self) -> None:
        self.close()
        self.start()

    def launch(self, *, project: str, title: str, first_prompt: str, binding_id: str = "test-binding") -> dict[str, Any]:
        self.start()
        project_path = Path(project).expanduser()
        if not project_path.is_absolute() or not project_path.is_dir():
            raise ClaudeUnsupportedOperation("structured Claude sessions require an existing absolute project directory")
        with self._state_lock:
            if self.binding_id is not None and self.binding_id != binding_id:
                raise ClaudeStaleBinding("Claude sidecar launch binding changed")
            self.binding_id = binding_id
        result = self.request(
            "launch",
            {
                "project": str(project_path.resolve()),
                "title": _bounded_string(title, 500),
                "first_prompt": first_prompt,
                "binding_id": binding_id,
            },
        )
        native_id = result.get("native_session_id")
        if not isinstance(native_id, str) or not native_id or len(native_id) > 256:
            self._invalidate(ClaudeSidecarProtocolError("Claude sidecar returned an invalid session identity"))
            raise ClaudeSidecarProtocolError("Claude sidecar returned an invalid session identity")
        with self._state_lock:
            if self.native_session_id is not None and self.native_session_id != native_id:
                self._invalidate(ClaudeSidecarProtocolError("Claude sidecar changed its session identity"))
                raise ClaudeSidecarProtocolError("Claude sidecar changed its session identity")
            self.native_session_id = native_id
            self._generation += 1
        return result

    def discover(self) -> dict[str, Any]:
        result = self.request("discover", {})
        discovery = _normalize_discovery(result, expected_session_id=self.native_session_id)
        fingerprint = json.dumps(discovery, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self._state_lock:
            if self._discovery_fingerprint is not None and self._discovery_fingerprint != fingerprint:
                self._generation += 1
            self._discovery_fingerprint = fingerprint
            self._last_discovery = discovery
        return dict(discovery)

    def request(self, operation: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if operation not in _REQUEST_FIELDS:
            raise ClaudeUnsupportedOperation(f"Claude sidecar operation is not reviewed: {operation}")
        normalized = _validate_request_payload(operation, payload or {})
        return self._request(operation, normalized, timeout=self.request_timeout)

    def respond_permission(
        self,
        *,
        approval_id: str,
        session_id: str,
        binding_id: str,
        capability_generation: int,
        tool_use_id: str,
        approval_digest: str,
        tool_name: str,
        input_preview: str,
        input_redacted: bool,
        input_truncated: bool,
        input_renderable: bool,
        expires_at: int,
        decision: str,
    ) -> dict[str, Any]:
        if decision not in {"allow", "deny"}:
            raise ClaudePermissionCorrelationError("permission decision must be allow or deny")
        with self._state_lock:
            proof = self._pending_permissions.get(approval_id)
            if proof is None or proof.get("responding") is True:
                raise ClaudePermissionCorrelationError(
                    "permission request is missing, stale, or already resolving"
                )
            exact_proof = (
                proof.get("session_id") == session_id
                and proof.get("binding_id") == binding_id == self.binding_id
                and proof.get("tool_use_id") == tool_use_id
                and proof.get("approval_digest") == approval_digest
                and proof.get("tool_name") == tool_name
                and proof.get("input_preview") == input_preview
                and proof.get("input_redacted") is input_redacted
                and proof.get("input_truncated") is input_truncated
                and proof.get("input_renderable") is input_renderable
                and proof.get("expires_at") == expires_at
                and capability_generation == self._generation
                and time.time() < expires_at
            )
            allow_safe = (
                exact_proof
                and input_renderable
                and not input_truncated
            )
            correlation_error = None
            if not exact_proof or (decision == "allow" and not allow_safe):
                correlation_error = ClaudePermissionCorrelationError(
                    "permission proof is stale, hidden, expired, or mismatched"
                )
            proof["responding"] = True
            outbound_decision = "deny" if correlation_error is not None else decision
            sidecar_payload = {
                "approval_id": approval_id,
                "session_id": str(proof["session_id"]),
                "binding_id": str(proof["binding_id"]),
                "tool_use_id": str(proof["tool_use_id"]),
                "approval_digest": str(proof["approval_digest"]),
                "decision": outbound_decision,
            }
        try:
            result = self.request("permission_decision", sidecar_payload)
        except Exception as exc:
            with self._state_lock:
                current = self._pending_permissions.get(approval_id)
                if current is proof:
                    current["responding"] = False
            if correlation_error is not None:
                raise correlation_error from exc
            raise
        with self._state_lock:
            if self._pending_permissions.get(approval_id) is proof:
                del self._pending_permissions[approval_id]
                self._remember_resolved_permission(approval_id, proof)
                self._generation += 1
        if correlation_error is not None:
            raise correlation_error
        return result

    def pending_permissions(self, session_id: str | None = None) -> tuple[dict[str, Any], ...]:
        with self._state_lock:
            rows = []
            for approval_id, proof in self._pending_permissions.items():
                if session_id is not None and proof.get("session_id") != session_id:
                    continue
                rows.append({"approval_id": approval_id, **proof})
            return tuple(rows)
    def respond_question(
        self,
        *,
        question_request_id: str,
        session_id: str,
        binding_id: str,
        capability_generation: int,
        decision: str,
        answers: Any,
    ) -> dict[str, Any]:
        with self._state_lock:
            proof = self._pending_questions.get(question_request_id)
            if proof is None or proof.get("responding") is True:
                raise ClaudeQuestionCorrelationError(
                    "question request is missing, stale, or already resolving"
                )
            if decision == "accept":
                normalized_answers = _normalize_question_answer_rows(
                    answers,
                    expected_questions=proof.get("questions"),
                )
            elif decision == "cancel" and answers in (None, []):
                normalized_answers = []
            else:
                raise ClaudeQuestionCorrelationError(
                    "question decision or answers are invalid"
                )
            exact_proof = (
                proof.get("session_id") == session_id
                and proof.get("binding_id") == binding_id == self.binding_id
                and capability_generation == self._generation
                and time.time() < proof.get("expires_at", 0)
            )
            if not exact_proof:
                raise ClaudeQuestionCorrelationError(
                    "question proof is stale, expired, or mismatched"
                )
            proof["responding"] = True
            sidecar_payload = {
                "question_request_id": question_request_id,
                "session_id": str(proof["session_id"]),
                "binding_id": str(proof["binding_id"]),
                "tool_use_id": str(proof["tool_use_id"]),
                "question_digest": str(proof["question_digest"]),
                "decision": decision,
                "answers": normalized_answers,
            }
        try:
            result = self.request("question_response", sidecar_payload)
        except Exception:
            with self._state_lock:
                current = self._pending_questions.get(question_request_id)
                if current is proof:
                    current["responding"] = False
            raise
        with self._state_lock:
            if self._pending_questions.get(question_request_id) is proof:
                del self._pending_questions[question_request_id]
                self._generation += 1
        return result

    def pending_questions(self, session_id: str | None = None) -> tuple[dict[str, Any], ...]:
        with self._state_lock:
            rows = []
            for question_request_id, proof in self._pending_questions.items():
                if session_id is not None and proof.get("session_id") != session_id:
                    continue
                rows.append({"question_request_id": question_request_id, **proof})
            return tuple(rows)


    def _remember_resolved_permission(
        self,
        approval_id: str,
        proof: Mapping[str, Any],
    ) -> None:
        self._resolved_permissions[approval_id] = (
            str(proof.get("session_id") or ""),
            str(proof.get("tool_use_id") or ""),
            str(proof.get("approval_digest") or ""),
            str(proof.get("binding_id") or ""),
        )
        self._resolved_permissions.move_to_end(approval_id)
        while len(self._resolved_permissions) > _RESOLVED_APPROVAL_LIMIT:
            self._resolved_permissions.popitem(last=False)

    def poll_events(self, cursor: int | str | None = 0) -> list[dict[str, Any]]:
        try:
            after = int(cursor or 0)
        except (TypeError, ValueError):
            after = 0
        with self._state_lock:
            return [dict(item) for item in self._events if int(item["cursor"]) > after]

    def close(self) -> None:
        with self._state_lock:
            process = self._process
            reader = self._reader
            if process is not None:
                self._closing = True
                self._available = False
                self._generation += 1
                self._process = None
                pending = tuple(self._pending.values())
                self._pending.clear()
                self._pending_permissions.clear()
                self._pending_questions.clear()
            else:
                pending = ()
        error = ClaudeSidecarEOF("Claude Agent SDK sidecar closed")
        for waiter in pending:
            _deliver(waiter, error)
        if process is not None:
            close_owned_process(process, reader=reader)
        elif reader is not None and reader is not threading.current_thread() and reader.ident is not None:
            reader.join(timeout=1)
        with self._state_lock:
            if self._reader is reader:
                self._reader = None

    def _request(self, operation: str, payload: dict[str, Any], *, timeout: float) -> dict[str, Any]:
        if not self.is_available:
            raise ClaudeSidecarUnavailable("Claude Agent SDK sidecar is unavailable")
        request_id = uuid.uuid4().hex
        message = {"id": request_id, "op": operation, **payload}
        encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(encoded) > self.max_line_bytes:
            raise ClaudeUnsupportedOperation("Claude sidecar request exceeds the bounded JSONL limit")
        waiter: queue.Queue[Any] = queue.Queue(maxsize=1)
        with self._state_lock:
            if not self.is_available:
                raise ClaudeSidecarUnavailable("Claude Agent SDK sidecar is unavailable")
            self._pending[request_id] = waiter
            process = self._process
        assert process is not None and process.stdin is not None
        try:
            with self._write_lock:
                process.stdin.write(encoded)
                process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            with self._state_lock:
                self._pending.pop(request_id, None)
            error = ClaudeSidecarEOF("Claude Agent SDK sidecar stdin closed")
            self._invalidate(error)
            raise error from exc
        try:
            response = waiter.get(timeout=timeout)
        except queue.Empty as exc:
            with self._state_lock:
                self._pending.pop(request_id, None)
            error = ClaudeSidecarTimeout(f"Claude Agent SDK sidecar timed out during {operation}")
            self._invalidate(error)
            raise error from exc
        if isinstance(response, BaseException):
            raise response
        if not isinstance(response, dict):
            raise ClaudeSidecarProtocolError("Claude sidecar returned a non-object response")
        return response

    def _reader_loop(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        while True:
            try:
                line = process.stdout.readline(self.max_line_bytes + 1)
            except OSError as exc:
                if not self._closing:
                    self._invalidate(ClaudeSidecarEOF(f"Claude sidecar stdout failed: {exc}"))
                return
            if not line:
                if not self._closing:
                    self._invalidate(ClaudeSidecarEOF("Claude Agent SDK sidecar reached EOF"))
                return
            if len(line) > self.max_line_bytes or not line.endswith(b"\n"):
                self._invalidate(ClaudeSidecarProtocolError("Claude sidecar emitted an oversized JSONL frame"))
                return
            try:
                message = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._invalidate(ClaudeSidecarProtocolError("Claude sidecar emitted malformed JSON"))
                return
            if not isinstance(message, dict):
                self._invalidate(ClaudeSidecarProtocolError("Claude sidecar frame must be an object"))
                return
            if message.get("type") == "event":
                try:
                    self._accept_event(message.get("event"))
                except ClaudeSidecarProtocolError as exc:
                    self._invalidate(exc)
                    return
                continue
            if message.get("type") != "response" or not isinstance(message.get("id"), str):
                self._invalidate(ClaudeSidecarProtocolError("Claude sidecar emitted an unknown frame"))
                return
            request_id = message["id"]
            with self._state_lock:
                waiter = self._pending.pop(request_id, None)
            if waiter is None:
                continue
            if message.get("ok") is True and isinstance(message.get("result"), dict):
                _deliver(waiter, _sanitize_json(message["result"]))
                continue
            error = message.get("error") if isinstance(message.get("error"), dict) else {}
            code = error.get("code") if isinstance(error.get("code"), str) else "provider_rejected"
            detail = error.get("message") if isinstance(error.get("message"), str) else "Claude sidecar rejected the request"
            if code in {"unsupported_operation", "safe_mode_required", "invalid_input"}:
                _deliver(waiter, ClaudeUnsupportedOperation(_bounded_string(detail, 300)))
            else:
                _deliver(waiter, _ClaudeSidecarResponseError(code, detail))

    def _accept_event(self, raw: Any) -> None:
        if not isinstance(raw, dict):
            raise ClaudeSidecarProtocolError("Claude sidecar event must be an object")
        session_id = raw.get("session_id")
        with self._state_lock:
            expected = self.native_session_id
            if expected is not None and session_id != expected:
                raise ClaudeSidecarProtocolError("Claude sidecar event session identity changed")
            if not isinstance(session_id, str) or not session_id or len(session_id) > 256:
                raise ClaudeSidecarProtocolError("Claude sidecar event lacks a session identity")
            kind = raw.get("kind")
            if not isinstance(kind, str) or re.fullmatch(r"[a-z][a-z0-9_.-]{0,95}", kind) is None:
                kind = "provider.message"
            kind = _EVENT_KIND_MAP.get(kind, kind)
            payload = _sanitize_json(
                raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
            )
            now = time.time()
            if kind == "permission.request":
                approval_id = payload.get("approval_id")
                tool_use_id = payload.get("tool_use_id")
                approval_digest = payload.get("approval_digest")
                binding_id = payload.get("binding_id")
                tool_name = payload.get("tool_name")
                input_preview = payload.get("input_preview")
                input_redacted = payload.get("input_redacted")
                input_truncated = payload.get("input_truncated")
                input_renderable = payload.get("input_renderable")
                expires_at = payload.get("expires_at")
                if (
                    not _event_text(approval_id, 256)
                    or not _event_text(tool_use_id, 256)
                    or not isinstance(approval_digest, str)
                    or _APPROVAL_DIGEST_RE.fullmatch(approval_digest) is None
                    or not _event_text(binding_id, 256)
                    or binding_id != self.binding_id
                    or not _event_text(tool_name, 160)
                    or not _event_text(input_preview, _MAX_APPROVAL_PREVIEW_LENGTH)
                    or type(input_redacted) is not bool
                    or type(input_truncated) is not bool
                    or type(input_renderable) is not bool
                    or type(expires_at) is not int
                    or expires_at <= now
                    or expires_at > now + _MAX_APPROVAL_LIFETIME_SECONDS
                ):
                    raise ClaudeSidecarProtocolError(
                        "Claude permission event lacks exact bounded input proof"
                    )
                if approval_id in self._resolved_permissions:
                    raise ClaudeSidecarProtocolError(
                        "Claude permission request replayed a resolved identity"
                    )
                proof = {
                    "session_id": session_id,
                    "binding_id": binding_id,
                    "tool_use_id": tool_use_id,
                    "approval_digest": approval_digest,
                    "tool_name": tool_name,
                    "input_preview": input_preview,
                    "input_redacted": input_redacted,
                    "input_truncated": input_truncated,
                    "input_renderable": input_renderable,
                    "expires_at": expires_at,
                    "responding": False,
                }
                current = self._pending_permissions.get(approval_id)
                if current is not None and any(
                    current.get(key) != value
                    for key, value in proof.items()
                    if key != "responding"
                ):
                    raise ClaudeSidecarProtocolError(
                        "Claude permission request reused an identity with different proof"
                    )
                if current is None:
                    self._pending_permissions[approval_id] = proof
                    self._generation += 1
            elif kind == "permission.resolved":
                approval_id = payload.get("approval_id")
                tool_use_id = payload.get("tool_use_id")
                approval_digest = payload.get("approval_digest")
                if (
                    not _event_text(approval_id, 256)
                    or not _event_text(tool_use_id, 256)
                    or not isinstance(approval_digest, str)
                    or _APPROVAL_DIGEST_RE.fullmatch(approval_digest) is None
                ):
                    raise ClaudeSidecarProtocolError(
                        "Claude permission resolution lacks correlation proof"
                    )
                current = self._pending_permissions.get(approval_id)
                if current is not None:
                    if (
                        current.get("session_id") != session_id
                        or current.get("tool_use_id") != tool_use_id
                        or current.get("approval_digest") != approval_digest
                    ):
                        raise ClaudeSidecarProtocolError(
                            "Claude permission resolution mismatches pending proof"
                        )
                    del self._pending_permissions[approval_id]
                    self._remember_resolved_permission(approval_id, current)
                    self._generation += 1
                else:
                    resolved = self._resolved_permissions.get(approval_id)
                    if (
                        resolved is None
                        or resolved[0] != session_id
                        or resolved[1] != tool_use_id
                        or resolved[2] != approval_digest
                    ):
                        raise ClaudeSidecarProtocolError(
                            "Claude permission resolution is stale or unknown"
                        )
            elif kind == "question.requested":
                question_request_id = payload.get("question_request_id")
                tool_use_id = payload.get("tool_use_id")
                question_digest = payload.get("question_digest")
                binding_id = payload.get("binding_id")
                expires_at = payload.get("expires_at")
                questions = _normalize_question_rows(payload.get("questions"))
                if (
                    not _event_text(question_request_id, 256)
                    or not _event_text(tool_use_id, 256)
                    or not isinstance(question_digest, str)
                    or _APPROVAL_DIGEST_RE.fullmatch(question_digest) is None
                    or not _event_text(binding_id, 256)
                    or binding_id != self.binding_id
                    or type(expires_at) is not int
                    or expires_at <= now
                    or expires_at > now + _MAX_QUESTION_LIFETIME_SECONDS
                ):
                    raise ClaudeSidecarProtocolError(
                        "Claude question event lacks exact bounded input proof"
                    )
                proof = {
                    "session_id": session_id,
                    "binding_id": binding_id,
                    "tool_use_id": tool_use_id,
                    "question_digest": question_digest,
                    "questions": questions,
                    "expires_at": expires_at,
                    "responding": False,
                }
                current = self._pending_questions.get(question_request_id)
                if current is not None and any(
                    current.get(key) != value
                    for key, value in proof.items()
                    if key != "responding"
                ):
                    raise ClaudeSidecarProtocolError(
                        "Claude question request reused an identity with different proof"
                    )
                if current is None:
                    self._pending_questions[question_request_id] = proof
                    self._generation += 1
            elif kind == "question.resolved":
                question_request_id = payload.get("question_request_id")
                tool_use_id = payload.get("tool_use_id")
                question_digest = payload.get("question_digest")
                if (
                    not _event_text(question_request_id, 256)
                    or not _event_text(tool_use_id, 256)
                    or not isinstance(question_digest, str)
                    or _APPROVAL_DIGEST_RE.fullmatch(question_digest) is None
                ):
                    raise ClaudeSidecarProtocolError(
                        "Claude question resolution lacks correlation proof"
                    )
                current = self._pending_questions.get(question_request_id)
                if current is not None:
                    if (
                        current.get("session_id") != session_id
                        or current.get("tool_use_id") != tool_use_id
                        or current.get("question_digest") != question_digest
                    ):
                        raise ClaudeSidecarProtocolError(
                            "Claude question resolution mismatches pending proof"
                        )
                    del self._pending_questions[question_request_id]
                    self._generation += 1
            self._event_cursor += 1
            cursor = self._event_cursor
            event_id = raw.get("event_id")
            if not isinstance(event_id, str) or not event_id or len(event_id) > 256:
                event_id = f"claude-event-{cursor}"
            self._events.append({
                "cursor": cursor,
                "provider_cursor": str(cursor),
                "event_id": event_id,
                "session_id": session_id,
                "provider_id": "claude",
                "observed_at": now,
                "kind": kind,
                "payload": payload,
            })

    def _validate_handshake(self, result: Mapping[str, Any]) -> None:
        expected = {
            "protocol_version": CLAUDE_SIDECAR_PROTOCOL_VERSION,
            "sdk_package": CLAUDE_AGENT_SDK_PACKAGE,
            "sdk_version": CLAUDE_AGENT_SDK_VERSION,
            "claude_code_version": CLAUDE_CODE_VERSION,
        }
        for key, value in expected.items():
            if result.get(key) != value:
                raise ClaudeSidecarProtocolError(f"Claude sidecar {key} is incompatible")
        node_version = result.get("node_version")
        if not isinstance(node_version, str) or _major_version(node_version) < 18:
            raise ClaudeSidecarProtocolError("Claude sidecar requires Node 18 or newer")
        self.sdk_version = CLAUDE_AGENT_SDK_VERSION
        self.claude_code_version = CLAUDE_CODE_VERSION
        self.node_version = node_version

    def _invalidate(self, error: BaseException) -> None:
        with self._state_lock:
            process = self._process
            reader = self._reader
            was_live = self._available or process is not None
            self._closing = True
            self._available = False
            self._process = None
            self._pending_permissions.clear()
            self._pending_questions.clear()
            pending = tuple(self._pending.values())
            self._pending.clear()
            if was_live:
                self._generation += 1
        for waiter in pending:
            _deliver(waiter, error)
        if process is not None:
            close_owned_process(process, reader=reader)
        elif reader is not None and reader is not threading.current_thread() and reader.ident is not None:
            reader.join(timeout=1)
        with self._state_lock:
            if self._reader is reader:
                self._reader = None


class ClaudeAgentSDKDriver:
    """Typed reviewed operations for one driver-owned Claude SDK session."""
    generation_refresh_safe = True


    def __init__(
        self,
        binding: ProviderControlBinding,
        *,
        process: _ClaudeAgentSidecarProcess | None = None,
        sidecar_command: tuple[str, ...] | None = None,
    ):
        if (
            binding.provider_id != "claude"
            or not _is_reviewed_claude_code_version(binding.provider_version)
            or binding.provider_channel != "agent-sdk"
        ):
            raise ValueError(
                "Claude Agent SDK driver requires the exact reviewed Claude binding"
            )
        self.binding = binding
        if process is None:
            command = sidecar_command or default_claude_sidecar_command()
            if command is None:
                raise ClaudeSidecarUnavailable("Node or the vendored Claude Agent SDK sidecar is unavailable")
            process = _ClaudeAgentSidecarProcess(argv=command)
        self.process = process
        self.native_session_id: str | None = None
        self.session_id: str | None = None
        self.project: str | None = None
        self._terminated = False
        self._discovery: dict[str, Any] | None = None
        self._action_lock = threading.RLock()
        self._actions: dict[
            tuple[int, str],
            tuple[str, str | None, ProviderOperationResult],
        ] = {}
        self._action_order: collections.deque[tuple[int, str]] = collections.deque()

    @property
    def capability_generation(self) -> int:
        return self.process.capability_generation

    def launch_session(self, *, project: str, title: str, first_prompt: str = "") -> dict[str, Any]:
        if self.native_session_id is not None or self._terminated:
            raise ClaudeUnsupportedOperation("Claude SDK driver already owns a session")
        if not isinstance(first_prompt, str) or len(first_prompt) > 200_000:
            raise ClaudeUnsupportedOperation("first prompt is invalid or too large")
        result = self.process.launch(
            project=project,
            title=title,
            first_prompt=first_prompt,
            binding_id=self.binding.binding_id,
        )
        self.native_session_id = str(result["native_session_id"])
        self.session_id = f"claude:{self.native_session_id}"
        self.project = str(Path(project).expanduser().resolve())
        self._discovery = self.process.discover()
        return {
            "native_session_id": self.native_session_id,
            "binding_id": self.binding.binding_id,
            "capability_generation": self.capability_generation,
            "provider_cursor": str(self.process.poll_events(0)[-1]["cursor"] if self.process.poll_events(0) else 0),
        }
    def verify_managed_launch(self, result: Mapping[str, Any]) -> bool:
        return bool(
            self.native_session_id
            and result.get("native_session_id") == self.native_session_id
            and result.get("binding_id") == self.binding.binding_id
            and result.get("capability_generation") == self.capability_generation
            and self.process.is_available
            and self._discovery is not None
        )

    def refresh_session_binding(self, session_truth: dict[str, Any] | None) -> dict[str, Any]:
        session_id = session_truth.get("session_id") if isinstance(session_truth, dict) else None
        persisted_generation = (
            session_truth.get("capability_generation")
            if isinstance(session_truth, dict)
            else None
        )
        if (
            not isinstance(session_id, str)
            or not self._session_identity_matches(session_id, session_truth)
            or not isinstance(persisted_generation, int)
            or isinstance(persisted_generation, bool)
            or persisted_generation < 1
            or persisted_generation > self.capability_generation
        ):
            raise ClaudeStaleBinding("Claude SDK session binding cannot be refreshed")
        if self._terminated or not self.process.is_available or self.native_session_id is None:
            raise ClaudeSidecarUnavailable("Claude Agent SDK session is unavailable")
        return {
            "binding_id": self.binding.binding_id,
            "session_id": self.session_id,
            "native_session_id": self.native_session_id,
            "capability_generation": self.capability_generation,
            "lifecycle": "live",
            "driver_available": True,
        }


    def reconcile_session(self, session_truth: dict[str, Any] | None) -> dict[str, Any]:
        del session_truth
        raise ClaudeSidecarUnavailable(
            "Claude Agent SDK child ownership cannot be reattached after daemon restart; history remains read-only"
        )

    def snapshot(
        self,
        *,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderControlSnapshot:
        if session_id is not None and not self._owns_session(session_id, session_truth):
            return self._blocked_snapshot("session_not_owned_by_claude_agent_sdk_driver")
        if session_id is None and session_truth is not None:
            return self._blocked_snapshot("provider_snapshot_cannot_use_session_truth")
        if self._terminated:
            return self._blocked_snapshot("claude_agent_sdk_session_terminated")
        if self.native_session_id is None or not self.process.is_available:
            return self._blocked_snapshot("claude_agent_sdk_sidecar_unavailable")
        try:
            self._discovery = self.process.discover()
        except ClaudeSidecarUnavailable:
            return self._blocked_snapshot("claude_agent_sdk_sidecar_unavailable")
        return self._snapshot_from_discovery(session_id=session_id)

    def refresh_capabilities(
        self,
        *,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderControlSnapshot:
        if session_id is not None and not self._owns_session(session_id, session_truth):
            return self._blocked_snapshot("session_not_owned_by_claude_agent_sdk_driver")
        self._discovery = self.process.discover()
        return self._snapshot_from_discovery(session_id=session_id)

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
            or not self._owns_session(session_id, session_truth)
            or operation_id not in self._advertised_operations(
                session_id=session_id
            )
        ):
            raise ClaudeUnsupportedOperation(
                "Claude SDK operation correlation proof is unavailable"
            )
        return ProviderOperationCorrelation(
            f"claude:{client_action_id}",
            self._provider_cursor(),
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
        if operation_id == "session.approval.decide" and (
            binding_id != self.binding.binding_id
            or capability_generation != self.capability_generation
        ):
            self._deny_current_permission_if_allow(input_payload)
        if (
            binding_id != self.binding.binding_id
            or capability_generation != self.capability_generation
        ):
            raise ClaudeStaleBinding(
                "Claude SDK binding or capability generation is stale"
            )
        if self._discovery is None or not self.process.is_available or self._terminated:
            raise ClaudeSidecarUnavailable("Claude Agent SDK session is unavailable")
        try:
            definition = REVIEWED_OPERATION_CATALOG.require(operation_id)
            normalized_input = definition.validate_input_payload(input_payload)
        except OperationCatalogError as exc:
            if operation_id == "session.approval.decide":
                self._deny_current_permission_if_allow(input_payload)
            raise ClaudeUnsupportedOperation(str(exc)) from exc
        session_bound = _operation_is_session_bound(operation_id)
        if session_bound:
            if session_id is None or session_id != self.session_id:
                if operation_id == "session.approval.decide":
                    self._deny_current_permission_if_allow(normalized_input)
                raise ClaudeStaleBinding("Claude SDK operation targets another session")
            try:
                identity = ProviderSessionIdentity.from_payload(
                    normalized_input.get("session")
                )
            except Exception as exc:
                if operation_id == "session.approval.decide":
                    self._deny_current_permission_if_allow(normalized_input)
                raise ClaudeStaleBinding(
                    "Claude SDK operation has invalid session identity"
                ) from exc
            if (
                identity.provider_id != self.binding.provider_id
                or identity.session_id != session_id
                or identity.binding_id != self.binding.binding_id
                or identity.capability_generation != self.capability_generation
            ):
                if operation_id == "session.approval.decide":
                    self._deny_current_permission_if_allow(normalized_input)
                raise ClaudeStaleBinding(
                    "Claude SDK operation session identity is stale"
                )
        elif session_id is not None:
            raise ClaudeStaleBinding(
                "provider-wide Claude operation cannot target a session"
            )
        if prepared_attachments:
            raise ClaudeUnsupportedOperation(
                "Claude SDK prompt attachments are not enabled for this driver"
            )
        advertised = self._advertised_operations(session_id=session_id)
        if operation_id not in advertised:
            raise ClaudeUnsupportedOperation(
                f"Claude SDK did not advertise {operation_id}"
            )
        expected_operation_id = _bounded_string(
            f"claude:{client_action_id}",
            512,
        )
        if provider_correlation is not None and (
            not isinstance(provider_correlation, ProviderOperationCorrelation)
            or provider_correlation.provider_operation_id
            != expected_operation_id
        ):
            raise ClaudeStaleBinding(
                "Claude SDK operation correlation is stale"
            )

        fingerprint = _operation_fingerprint(
            operation_id,
            normalized_input,
            session_id,
        )
        receipt_key = (capability_generation, client_action_id)
        with self._action_lock:
            previous = self._actions.get(receipt_key)
        if previous is not None:
            if previous[0] == fingerprint and previous[1] == session_id:
                return previous[2]
            return ProviderOperationResult(
                operation_id=operation_id,
                provider_operation_id=(
                    provider_correlation.provider_operation_id
                    if provider_correlation is not None
                    else _bounded_string(
                        f"claude:{client_action_id}:reused",
                        512,
                    )
                ),
                status=OperationResultStatus.REJECTED,
                public_result={"error": "client_action_id_reused"},
                provider_cursor=(
                    provider_correlation.provider_cursor
                    if provider_correlation is not None
                    else self._provider_cursor()
                ),
            )

        payload = dict(normalized_input)
        payload.pop("session", None)
        sidecar_operation, sidecar_payload = self._map_operation(
            operation_id,
            payload,
            binding_id=binding_id,
            capability_generation=capability_generation,
            client_action_id=client_action_id,
        )
        if sidecar_operation == "__already_applied__":
            native_result = sidecar_payload
        else:
            try:
                native_result = self.process.request(
                    sidecar_operation,
                    sidecar_payload,
                )
            except _ClaudeSidecarResponseError as exc:
                result = ProviderOperationResult(
                    operation_id=operation_id,
                    provider_operation_id=(
                        provider_correlation.provider_operation_id
                        if provider_correlation is not None
                        else f"claude:{client_action_id}"
                    ),
                    status=OperationResultStatus.REJECTED,
                    public_result={"error": exc.code},
                    provider_cursor=(
                        provider_correlation.provider_cursor
                        if provider_correlation is not None
                        else self._provider_cursor()
                    ),
                )
                self._remember_action(
                    receipt_key,
                    fingerprint,
                    session_id,
                    result,
                )
                return result

        if operation_id == "session.terminate":
            self._terminated = True
        public_result = self._public_result(operation_id, native_result, payload)
        native_provider_operation_id = native_result.get(
            "provider_operation_id"
        )
        if (
            not isinstance(native_provider_operation_id, str)
            or not native_provider_operation_id
        ):
            native_provider_operation_id = f"claude:{client_action_id}"
        result_operation_id = (
            provider_correlation.provider_operation_id
            if provider_correlation is not None
            else _bounded_string(native_provider_operation_id, 512)
        )
        result_cursor = (
            provider_correlation.provider_cursor
            if provider_correlation is not None
            else self._provider_cursor()
        )
        status = OperationResultStatus.APPLIED
        result = ProviderOperationResult(
            operation_id=operation_id,
            provider_operation_id=result_operation_id,
            status=status,
            public_result=public_result,
            provider_cursor=result_cursor,
        )
        self._remember_action(
            receipt_key,
            fingerprint,
            session_id,
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
            or not isinstance(provider_correlation, ProviderOperationCorrelation)
        ):
            return None
        if session_id is None:
            if session_truth is not None:
                return None
        elif not self._owns_session(session_id, session_truth):
            return None
        with self._action_lock:
            receipt = self._actions.get(
                (capability_generation, client_action_id)
            )
        if receipt is None:
            return None
        _, receipt_session_id, result = receipt
        if (
            receipt_session_id != session_id
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

    def _remember_action(
        self,
        key: tuple[int, str],
        fingerprint: str,
        session_id: str | None,
        result: ProviderOperationResult,
    ) -> None:
        with self._action_lock:
            if key in self._actions:
                return
            self._actions[key] = (fingerprint, session_id, result)
            self._action_order.append(key)
            while len(self._action_order) > _MAX_ACTION_RESULTS:
                oldest = self._action_order.popleft()
                self._actions.pop(oldest, None)

    def respond_permission(
        self,
        *,
        approval_id: str,
        session_id: str,
        binding_id: str,
        capability_generation: int,
        tool_use_id: str,
        approval_digest: str,
        tool_name: str,
        input_preview: str,
        input_redacted: bool,
        input_truncated: bool,
        input_renderable: bool,
        expires_at: int,
        decision: str,
    ) -> dict[str, Any]:
        if session_id != self.session_id or self.native_session_id is None:
            raise ClaudePermissionCorrelationError(
                "permission request targets another Claude session"
            )
        return self.process.respond_permission(
            approval_id=approval_id,
            session_id=self.native_session_id,
            binding_id=binding_id,
            capability_generation=capability_generation,
            tool_use_id=tool_use_id,
            approval_digest=approval_digest,
            tool_name=tool_name,
            input_preview=input_preview,
            input_redacted=input_redacted,
            input_truncated=input_truncated,
            input_renderable=input_renderable,
            expires_at=expires_at,
            decision=decision,
        )

    def _current_pending_permission(
        self,
        *,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        observed_at = time.time() if now is None else now
        for proof in self.process.pending_permissions(self.native_session_id):
            expires_at = proof.get("expires_at")
            if (
                proof.get("responding") is not True
                and type(expires_at) is int
                and observed_at < expires_at
            ):
                return proof
        return None
    def _current_pending_question(
        self,
        *,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        observed_at = time.time() if now is None else now
        for proof in self.process.pending_questions(self.native_session_id):
            expires_at = proof.get("expires_at")
            if (
                proof.get("responding") is not True
                and type(expires_at) is int
                and observed_at < expires_at
            ):
                return proof
        return None

    def respond_question(
        self,
        *,
        question_request_id: str,
        decision: str,
        answers: Any,
        session_id: str,
        binding_id: str,
        capability_generation: int,
    ) -> dict[str, Any]:
        if session_id != self.session_id or self.native_session_id is None:
            raise ClaudeQuestionCorrelationError(
                "question request targets another Claude session"
            )
        return self.process.respond_question(
            question_request_id=question_request_id,
            session_id=self.native_session_id,
            binding_id=binding_id,
            capability_generation=capability_generation,
            decision=decision,
            answers=answers,
        )


    def _deny_current_permission_if_allow(
        self,
        payload: Mapping[str, Any],
    ) -> None:
        if payload.get("decision") != "allow":
            return
        approval_id = payload.get("approval_id")
        if not isinstance(approval_id, str) or not approval_id:
            return
        proof = next(
            (
                row
                for row in self.process.pending_permissions(self.native_session_id)
                if row.get("approval_id") == approval_id
            ),
            None,
        )
        if proof is None:
            return
        try:
            self.respond_permission(
                approval_id=approval_id,
                session_id=self.session_id or "",
                binding_id=self.binding.binding_id,
                capability_generation=self.capability_generation,
                tool_use_id=str(proof["tool_use_id"]),
                approval_digest=str(proof["approval_digest"]),
                tool_name=str(proof["tool_name"]),
                input_preview=str(proof["input_preview"]),
                input_redacted=bool(proof["input_redacted"]),
                input_truncated=bool(proof["input_truncated"]),
                input_renderable=bool(proof["input_renderable"]),
                expires_at=int(proof["expires_at"]),
                decision="deny",
            )
        except ClaudeSidecarError:
            pass

    def poll_events(self, cursor: int | str | None = 0) -> list[dict[str, Any]]:
        return self.process.poll_events(cursor)

    def close(self) -> None:
        self._terminated = True
        self.process.close()

    def _session_identity_matches(
        self,
        session_id: str,
        truth: dict[str, Any] | None,
    ) -> bool:
        instance_id = truth.get("session_instance_id") if isinstance(truth, dict) else None
        return bool(
            self.session_id is not None
            and session_id == self.session_id
            and isinstance(truth, dict)
            and truth.get("provider_id") == "claude"
            and truth.get("provider") == "claude"
            and truth.get("session_id") == self.session_id
            and truth.get("native_id") == self.native_session_id
            and truth.get("managed") is True
            and truth.get("owner") == "provider_driver"
            and truth.get("terminal_backed") is False
            and truth.get("binding_id") == self.binding.binding_id
            and truth.get("is_live") is True
            and truth.get("controllable") is True
            and isinstance(instance_id, str)
            and 0 < len(instance_id) <= 512
        )

    def _owns_session(self, session_id: str, truth: dict[str, Any] | None) -> bool:
        return bool(
            self._session_identity_matches(session_id, truth)
            and truth.get("capability_generation") == self.capability_generation
        )

    def _blocked_snapshot(self, reason: str) -> ProviderControlSnapshot:
        now = time.time()
        return ProviderControlSnapshot(
            provider_id=self.binding.provider_id,
            provider_version=self.binding.provider_version,
            provider_channel=self.binding.provider_channel,
            binding_id=self.binding.binding_id,
            capability_generation=self.capability_generation,
            observed_at=now,
            valid_until=now + 5.0,
            advertised_operations=(),
            values=(),
            choices=(),
            blocked_reason=reason,
            provider_cursor=self._provider_cursor(),
        )

    def _snapshot_from_discovery(self, *, session_id: str | None) -> ProviderControlSnapshot:
        now = time.time()
        pending_approval = self._current_pending_permission(now=now)
        operations = self._advertised_operations(session_id=session_id)
        pending_question = self._current_pending_question(now=now)
        values: list[ControlValue] = []
        choices: list[ControlChoices] = []
        if session_id is not None:
            identity = ProviderSessionIdentity(
                provider_id="claude",
                session_id=session_id,
                binding_id=self.binding.binding_id,
                capability_generation=self.capability_generation,
            )
            for operation_id in operations:
                if _operation_is_session_bound(operation_id):
                    values.append(ControlValue(operation_id, "session", identity))
        discovery = self._discovery or {}
        if "session.model.set" in operations:
            choices.append(ControlChoices(
                "session.model.set",
                "model",
                tuple(
                    ControlChoice(row["value"], row.get("display_name") or row["value"])
                    for row in discovery.get("models", ())
                ),
            ))
        if "session.permissions.set" in operations:
            modes = tuple(mode for mode in discovery.get("permission_modes", ()) if mode in _SAFE_PERMISSION_MODES)
            choices.append(ControlChoices(
                "session.permissions.set",
                "permissions",
                tuple(ControlChoice(mode, "Ask for approval" if mode == "default" else "Plan only") for mode in modes),
            ))
        if "session.approval.decide" in operations and pending_approval is not None:
            allow_safe = (
                pending_approval["input_renderable"]
                and not pending_approval["input_truncated"]
            )
            decision_choices = (
                (ControlChoice("allow", "Allow once"), ControlChoice("deny", "Deny"))
                if allow_safe
                else (ControlChoice("deny", "Deny"),)
            )
            choices.append(ControlChoices(
                "session.approval.decide",
                "decision",
                decision_choices,
            ))
            for input_id, key in (
                ("approval_id", "approval_id"),
                ("approval_digest", "approval_digest"),
                ("approval_tool_use_id", "tool_use_id"),
                ("approval_tool_name", "tool_name"),
                ("approval_preview", "input_preview"),
                ("approval_input_redacted", "input_redacted"),
                ("approval_input_truncated", "input_truncated"),
                ("approval_input_renderable", "input_renderable"),
                ("approval_expires_at", "expires_at"),
            ):
                values.append(ControlValue(
                    "session.approval.decide",
                    input_id,
                    pending_approval[key],
                ))
        if "session.question.answer" in operations and pending_question is not None:
            choices.append(ControlChoices(
                "session.question.answer",
                "question_request_id",
                (
                    ControlChoice(
                        pending_question["question_request_id"],
                        "Pending Claude question",
                    ),
                ),
            ))
            values.append(ControlValue(
                "session.question.answer",
                "question_request_id",
                pending_question["question_request_id"],
            ))
            values.append(ControlValue(
                "session.question.answer",
                "answers",
                pending_question["questions"],
            ))
            choices.append(ControlChoices(
                "session.question.answer",
                "decision",
                (
                    ControlChoice("accept", "Submit answers"),
                    ControlChoice("cancel", "Cancel request"),
                ),
            ))
        for operation_id in ("provider.mcp.reconnect", "provider.mcp.set_enabled"):
            if operation_id not in operations:
                continue
            choices.append(ControlChoices(
                operation_id,
                "server_id",
                tuple(
                    ControlChoice(row["name"], row["name"])
                    for row in discovery.get("mcp_servers", ())
                ),
            ))
        snapshot = ProviderControlSnapshot(
            provider_id=self.binding.provider_id,
            provider_version=self.binding.provider_version,
            provider_channel=self.binding.provider_channel,
            binding_id=self.binding.binding_id,
            capability_generation=self.capability_generation,
            observed_at=now,
            valid_until=now + 5.0,
            advertised_operations=operations,
            values=tuple(values),
            choices=tuple(choices),
            blocked_reason=None,
            provider_cursor=self._provider_cursor(),
        )
        snapshot.validate(now=now)
        return snapshot

    def _advertised_operations(self, *, session_id: str | None) -> tuple[str, ...]:
        discovery = self._discovery or {}
        capabilities = set(discovery.get("capabilities") or ())
        if session_id is None:
            operations: list[str] = []
            if "supported_commands" in capabilities:
                operations.append("provider.commands.read")
            if "mcp_status" in capabilities:
                operations.append("provider.mcp.read")
            if "account_info" in capabilities:
                operations.append("provider.auth.read")
            if "provider.status.read" in capabilities:
                operations.append("provider.diagnostics.read")
            return tuple(operations)
        if session_id != self.session_id:
            return ()
        operations = []
        if "stream_input" in capabilities:
            operations.extend(("session.prompt.send", "session.turn.steer"))
        if "interrupt" in capabilities:
            operations.append("session.turn.interrupt")
        if "close" in capabilities:
            operations.append("session.terminate")
        command_names = {str(row.get("name") or "").lstrip("/").lower() for row in discovery.get("commands", ())}
        if "supported_commands" in capabilities and "compact" in command_names:
            operations.append("session.compact")
        if "rewind_files" in capabilities:
            operations.append("session.rewind")
        if "set_model" in capabilities and discovery.get("models"):
            operations.append("session.model.set")
        safe_modes = set(discovery.get("permission_modes") or ()) & set(_SAFE_PERMISSION_MODES)
        if "set_permission_mode" in capabilities and safe_modes:
            operations.append("session.permissions.set")
        if self.native_session_id and self._current_pending_permission() is not None:
            operations.append("session.approval.decide")
        if self.native_session_id and self._current_pending_question() is not None:
            operations.append("session.question.answer")
        if "provider.agents.read" in capabilities:
            operations.append("provider.agents.read")
        if "provider.status.read" in capabilities:
            operations.append("provider.status.read")
        if (
            "provider.mcp.reconnect" in capabilities
            and discovery.get("mcp_servers")
        ):
            operations.append("provider.mcp.reconnect")
        if (
            "provider.mcp.set_enabled" in capabilities
            and discovery.get("mcp_servers")
        ):
            operations.append("provider.mcp.set_enabled")
        if "session.context.read" in capabilities:
            operations.append("session.context.read")
        if "session.history.read" in capabilities:
            operations.append("session.history.read")
        return tuple(operations)

    def _map_operation(
        self,
        operation_id: str,
        payload: dict[str, Any],
        *,
        binding_id: str,
        capability_generation: int,
        client_action_id: str,
    ) -> tuple[str, dict[str, Any]]:
        native_id = self.native_session_id
        session_base = {"session_id": native_id, "client_action_id": client_action_id}
        if operation_id == "session.prompt.send":
            return "prompt", {**session_base, "prompt": _required_text(payload, "prompt", 200_000)}
        if operation_id == "session.turn.steer":
            return "steer", {**session_base, "instruction": _required_text(payload, "instruction", 200_000)}
        if operation_id == "session.turn.interrupt":
            return "interrupt", session_base
        if operation_id == "session.terminate":
            return "terminate", session_base
        if operation_id == "session.compact":
            return "compact", session_base
        if operation_id == "session.rewind":
            return "rewind", {**session_base, "message_id": _required_text(payload, "turn_id", 256)}
        if operation_id == "session.model.set":
            model = _required_text(payload, "model", 256)
            if model not in {row.get("value") for row in (self._discovery or {}).get("models", ())}:
                raise ClaudeUnsupportedOperation("model is not in the live SDK model catalog")
            return "set_model", {**session_base, "model": model}
        if operation_id == "session.permissions.set":
            mode = _required_text(payload, "permissions", 64)
            if mode not in _SAFE_PERMISSION_MODES:
                raise ClaudeUnsupportedOperation("Claude permission mode is not safe for remote control")
            return "set_permission_mode", {**session_base, "mode": mode}
        if operation_id == "session.approval.decide":
            try:
                approval_id = _required_text(payload, "approval_id", 256)
                approval_digest = _required_digest(payload, "approval_digest")
                tool_use_id = _required_text(payload, "approval_tool_use_id", 256)
                tool_name = _required_text(payload, "approval_tool_name", 160)
                input_preview = _required_text(
                    payload,
                    "approval_preview",
                    _MAX_APPROVAL_PREVIEW_LENGTH,
                )
                input_redacted = _required_bool(payload, "approval_input_redacted")
                input_truncated = _required_bool(payload, "approval_input_truncated")
                input_renderable = _required_bool(payload, "approval_input_renderable")
                expires_at = _required_int(payload, "approval_expires_at")
                decision = _required_text(payload, "decision", 64)
                if decision not in {"allow", "deny"}:
                    raise ClaudePermissionCorrelationError(
                        "permission decision is not advertised"
                    )
            except ClaudeSidecarError:
                self._deny_current_permission_if_allow(payload)
                raise
            result = self.respond_permission(
                approval_id=approval_id,
                session_id=self.session_id or "",
                binding_id=binding_id,
                capability_generation=capability_generation,
                tool_use_id=tool_use_id,
                approval_digest=approval_digest,
                tool_name=tool_name,
                input_preview=input_preview,
                input_redacted=input_redacted,
                input_truncated=input_truncated,
                input_renderable=input_renderable,
                expires_at=expires_at,
                decision=decision,
            )
            return "__already_applied__", result
        if operation_id == "session.question.answer":
            result = self.respond_question(
                question_request_id=_required_text(
                    payload,
                    "question_request_id",
                    256,
                ),
                decision=str(payload["decision"]),
                answers=payload.get("answers"),
                session_id=self.session_id or "",
                binding_id=binding_id,
                capability_generation=capability_generation,
            )
            return "__already_applied__", result
        if operation_id == "provider.commands.read":
            return "read_commands", {}
        if operation_id == "provider.agents.read":
            return "read_agents", {"session_id": native_id}
        if operation_id == "provider.status.read":
            return "read_status", {"session_id": native_id}
        if operation_id == "provider.mcp.read":
            return "read_mcp", {}
        if operation_id in {"provider.mcp.reconnect", "provider.mcp.set_enabled"}:
            server_id = _required_text(payload, "server_id", 256)
            if server_id not in {row.get("name") for row in (self._discovery or {}).get("mcp_servers", ())}:
                raise ClaudeUnsupportedOperation("MCP server is not in the live SDK catalog")
            if operation_id == "provider.mcp.reconnect":
                return "mcp_reconnect", {**session_base, "server_id": server_id}
            return "mcp_set_enabled", {
                **session_base,
                "server_id": server_id,
                "enabled": _required_bool(payload, "enabled"),
            }
        if operation_id == "provider.auth.read":
            return "read_account", {}
        if operation_id == "session.context.read":
            return "read_context", {"session_id": native_id}
        if operation_id == "session.history.read":
            return "read_history", {"session_id": native_id}
        if operation_id == "provider.diagnostics.read":
            return "read_diagnostics", {}
        raise ClaudeUnsupportedOperation(f"Claude SDK operation is not reviewed: {operation_id}")

    def _public_result(self, operation_id: str, result: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        if operation_id == "session.approval.decide":
            return {"decision": result.get("decision")}
        if operation_id == "session.question.answer":
            return {
                "decision": result.get("decision", payload.get("decision")),
                "answer_count": result.get("answer_count", 0),
            }
        if operation_id == "session.turn.interrupt":
            return {
                "still_queued": _string_list(result.get("still_queued"), 128, 256),
                "cancelled": _string_list(result.get("cancelled"), 128, 256),
            }
        if operation_id == "session.model.set":
            return {"model": payload.get("model")}
        if operation_id == "session.permissions.set":
            return {"permissions": payload.get("permissions")}
        if operation_id == "provider.mcp.reconnect":
            return {"server_id": payload.get("server_id"), "reconnected": True}
        if operation_id == "provider.mcp.set_enabled":
            return {"server_id": payload.get("server_id"), "enabled": payload.get("enabled")}
        if operation_id.startswith("provider.") or operation_id in {
            "session.rewind",
            "session.context.read",
            "session.history.read",
        }:
            return _sanitize_json(result)
        if operation_id == "session.terminate":
            return {"terminated": True}
        return {"accepted": bool(result.get("accepted", True))}

    def _provider_cursor(self) -> str:
        events = self.process.poll_events(0)
        return str(events[-1]["cursor"] if events else 0)


def _normalize_question_rows(
    value: Any,
    *,
    answer_required: bool = False,
    expected_questions: Any = None,
    error_type: type[ClaudeSidecarError] = ClaudeSidecarProtocolError,
) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= 4:
        raise error_type("Claude question form must contain one to four questions")
    expected = expected_questions if isinstance(expected_questions, (list, tuple)) else None
    normalized: list[dict[str, Any]] = []
    seen_indexes: set[int] = set()
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {
            "index",
            "topic",
            "question",
            "options",
            "answer",
        }:
            raise error_type("Claude question row shape is invalid")
        index = item.get("index")
        topic = item.get("topic")
        question = item.get("question")
        options = item.get("options")
        answer = item.get("answer")
        if (
            type(index) is not int
            or index < 1
            or index > len(value)
            or index in seen_indexes
            or not _event_text(topic, 100)
            or not _event_text(question, 2_000)
            or not isinstance(options, (list, tuple))
            or not 2 <= len(options) <= 4
            or not all(_event_text(option, 1_000) for option in options)
            or len(set(options)) != len(options)
            or not isinstance(answer, str)
            or "\x00" in answer
        ):
            raise error_type("Claude question row is invalid")
        if answer_required:
            if answer not in options:
                raise error_type("Claude question answer is not an offered option")
        elif answer:
            raise error_type("Claude pending question unexpectedly contains an answer")
        seen_indexes.add(index)
        normalized.append({
            "index": index,
            "topic": topic,
            "question": question,
            "options": list(options),
            "answer": answer,
        })
    normalized.sort(key=lambda row: row["index"])
    if [row["index"] for row in normalized] != list(range(1, len(normalized) + 1)):
        raise error_type("Claude question indexes are not contiguous")
    if expected is not None:
        pending = _normalize_question_rows(
            expected,
            error_type=error_type,
        )
        if len(pending) != len(normalized):
            raise error_type("Claude question response is incomplete")
        for submitted, original in zip(normalized, pending, strict=True):
            if any(
                submitted[key] != original[key]
                for key in ("index", "topic", "question", "options")
            ):
                raise error_type("Claude question response does not match the pending form")
    return normalized


def _normalize_question_answer_rows(
    value: Any,
    *,
    expected_questions: Any,
) -> list[dict[str, Any]]:
    return _normalize_question_rows(
        value,
        answer_required=True,
        expected_questions=expected_questions,
        error_type=ClaudeQuestionCorrelationError,
    )


def _validate_request_payload(operation: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ClaudeUnsupportedOperation("Claude sidecar payload must be an object")
    expected = _REQUEST_FIELDS[operation]
    if set(payload) != set(expected):
        raise ClaudeUnsupportedOperation(f"Claude sidecar {operation} payload shape is not reviewed")
    result: dict[str, Any] = {}
    for key, value in payload.items():
        if key == "answers":
            if (
                operation == "question_response"
                and payload.get("decision") == "cancel"
                and value == []
            ):
                result[key] = []
            else:
                result[key] = _normalize_question_rows(
                    value,
                    answer_required=True,
                    error_type=ClaudeUnsupportedOperation,
                )
            continue
        limit = _TEXT_LIMITS.get(key)
        if limit is None or not isinstance(value, str) or not value or len(value) > limit:
            if key in {"title", "first_prompt"} and isinstance(value, str) and len(value) <= (limit or 0):
                result[key] = value
                continue
            if key == "enabled" and type(value) is bool:
                result[key] = value
                continue
            if key == "protocol_version" and type(value) is int and value == CLAUDE_SIDECAR_PROTOCOL_VERSION:
                result[key] = value
                continue
            raise ClaudeUnsupportedOperation(f"Claude sidecar {operation}.{key} is invalid")
        if any(ord(char) == 0 for char in value):
            raise ClaudeUnsupportedOperation(f"Claude sidecar {operation}.{key} contains a NUL")
        result[key] = value
    if operation == "set_permission_mode" and result["mode"] not in _SAFE_PERMISSION_MODES:
        raise ClaudeUnsupportedOperation("Claude permission mode is not safe for remote control")
    if operation == "permission_decision" and result["decision"] not in {"allow", "deny"}:
        raise ClaudeUnsupportedOperation("Claude permission decision is not reviewed")
    if (
        operation == "permission_decision"
        and _APPROVAL_DIGEST_RE.fullmatch(result["approval_digest"]) is None
    ):
        raise ClaudeUnsupportedOperation("Claude permission digest is invalid")
    if (
        operation == "question_response"
        and _APPROVAL_DIGEST_RE.fullmatch(result["question_digest"]) is None
    ):
        raise ClaudeUnsupportedOperation("Claude question digest is invalid")
    return result


def _normalize_discovery(value: Mapping[str, Any], *, expected_session_id: str | None) -> dict[str, Any]:
    session_id = value.get("native_session_id")
    if expected_session_id is not None and session_id != expected_session_id:
        raise ClaudeSidecarProtocolError("Claude discovery belongs to another session")
    capabilities = tuple(
        sorted(
            {
                item
                for item in value.get("capabilities", ())
                if item in _REVIEWED_DISCOVERY_CAPABILITIES
            }
        )
    )
    models = _normalize_named_rows(value.get("models"), value_key="value", label_key="display_name")
    commands = _normalize_named_rows(value.get("commands"), value_key="name", label_key="description", extra="argument_hint")
    agents = _normalize_named_rows(value.get("agents"), value_key="name", label_key="description", extra="model")
    mcp_servers = []
    for row in value.get("mcp_servers", ()) if isinstance(value.get("mcp_servers"), list) else ():
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        status = row.get("status")
        if isinstance(name, str) and name and len(name) <= 256 and status in {"connected", "failed", "needs-auth", "pending", "disabled"}:
            mcp_servers.append({"name": name, "status": status})
    permission_modes = tuple(
        mode for mode in value.get("permission_modes", ())
        if isinstance(mode, str) and mode in _SAFE_PERMISSION_MODES
    )
    status = value.get("status") if isinstance(value.get("status"), dict) else {}
    return {
        "native_session_id": session_id,
        "capabilities": capabilities,
        "models": models,
        "commands": commands,
        "agents": agents,
        "mcp_servers": mcp_servers,
        "permission_modes": permission_modes,
        "status": _sanitize_json(status),
    }


def _normalize_named_rows(value: Any, *, value_key: str, label_key: str, extra: str | None = None) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in value if isinstance(value, list) else ():
        if not isinstance(item, dict):
            continue
        raw_value = item.get(value_key)
        if not isinstance(raw_value, str) or not raw_value or len(raw_value) > 256 or raw_value in seen:
            continue
        seen.add(raw_value)
        row = {value_key: raw_value}
        label = item.get(label_key)
        row[label_key] = _bounded_string(label, 500) if isinstance(label, str) and label else raw_value
        if extra and isinstance(item.get(extra), str):
            row[extra] = _bounded_string(item[extra], 500)
        rows.append(row)
    return rows




def _sanitize_json(value: Any, *, depth: int = 0) -> Any:
    if depth > 8:
        return "[truncated]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        text = _bounded_string(value, 16_384)
        for pattern in _SECRET_TEXT_PATTERNS:
            text = pattern.sub("[REDACTED]", text)
        return text
    if isinstance(value, list) or isinstance(value, tuple):
        return [_sanitize_json(item, depth=depth + 1) for item in value[:128]]
    if isinstance(value, dict) or isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, item in list(value.items())[:128]:
            key = _bounded_string(raw_key, 160)
            if not key:
                continue
            result[key] = "[REDACTED]" if _SECRET_KEY_RE.search(key) else _sanitize_json(item, depth=depth + 1)
        return result
    return _bounded_string(str(value), 500)


def _bounded_string(value: Any, limit: int) -> str:
    if value is None:
        return ""
    text = str(value).replace("\x00", "")
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 16)] + "…[truncated]"


def _event_text(value: Any, limit: int) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= limit
        and "\x00" not in value
    )


def _required_text(payload: Mapping[str, Any], key: str, limit: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value or len(value) > limit or "\x00" in value:
        raise ClaudeUnsupportedOperation(f"Claude operation input {key} is invalid")
    return value

def _required_digest(payload: Mapping[str, Any], key: str) -> str:
    value = _required_text(payload, key, 64)
    if _APPROVAL_DIGEST_RE.fullmatch(value) is None:
        raise ClaudeUnsupportedOperation(
            f"Claude operation input {key} is not a SHA-256 digest"
        )
    return value




def _required_bool(payload: Mapping[str, Any], key: str) -> bool:
    value = payload.get(key)
    if type(value) is not bool:
        raise ClaudeUnsupportedOperation(f"Claude operation input {key} is invalid")
    return value

def _required_int(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if type(value) is not int:
        raise ClaudeUnsupportedOperation(f"Claude operation input {key} is invalid")
    return value


def _string_list(value: Any, limit: int, text_limit: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_bounded_string(item, text_limit) for item in value[:limit] if isinstance(item, str)]


def _major_version(value: str) -> int:
    match = re.search(r"(?:^|v)(\d+)", value)
    return int(match.group(1)) if match else 0


def _operation_fingerprint(
    operation_id: str,
    input_payload: Mapping[str, Any],
    session_id: str | None,
) -> str:
    canonical = json.dumps(
        {
            "operation_id": operation_id,
            "input": input_payload,
            "session_id": session_id,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _operation_is_session_bound(operation_id: str) -> bool:
    try:
        definition = REVIEWED_OPERATION_CATALOG.require(operation_id)
    except Exception as exc:
        raise ClaudeUnsupportedOperation(f"Claude SDK operation is not reviewed: {operation_id}") from exc
    return any(item.input_type is InputType.PROVIDER_SESSION for item in definition.inputs)


def _deliver(waiter: queue.Queue[Any], value: Any) -> None:
    try:
        waiter.put_nowait(value)
    except queue.Full:
        pass


