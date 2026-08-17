from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass
from urllib.parse import urlsplit
from pathlib import Path
from typing import Any, Callable, Mapping

from ._sidecar_process import close_owned_process
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

DROID_JSONRPC_VERSION = "2.0"
DROID_API_VERSION = "1.0.0"
DROID_PROTOCOL_VERSION = "1.143.0"
DROID_SUPPORTED_VERSION = "0.185.0"
DROID_CHANNEL = "stable"

_FIXED_EXEC_ARGS = (
    "exec",
    "--input-format",
    "stream-jsonrpc",
    "--output-format",
    "stream-jsonrpc",
)
_READ_ONLY_INTERACTION_MODE = "auto"
_READ_ONLY_AUTONOMY_LEVEL = "off"
_REQUIRED_HELP_TOKENS = (
    "--input-format",
    "stream-jsonrpc",
    "--output-format",
    "--auto",
    "--cwd",
)
_UNSTABLE_CHANNEL_MARKERS = (
    "alpha",
    "beta",
    "canary",
    "dev",
    "nightly",
    "preview",
)
_MAX_LINE_BYTES = 2 * 1024 * 1024
_MAX_REQUEST_BYTES = 256 * 1024
_MAX_TEXT_BYTES = 64 * 1024
_MAX_EVENTS = 512
_MAX_ACTION_RESULTS = 512
_ALLOWED_REASONING = frozenset({"none", "dynamic", "off", "minimal", "low", "medium", "high", "xhigh", "max"})
_SAFE_PERMISSION_DECISIONS = ("cancel", "proceed_once")
_CONTROLLED_SETTING_KEYS = frozenset(
    {
        "modelId",
        "reasoningEffort",
        "interactionMode",
        "autonomyLevel",
        "specModeModelId",
        "specModeReasoningEffort",
        "enabledToolIds",
        "disabledToolIds",
        "missionSettings",
    }
)
_SECRET_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "password",
    "private_key",
    "secret",
)

# This is the entire provider method surface. There is deliberately no public
# method-string entry point and no credential, MCP mutation, raw tool, shell,
# daemon, remote-computer, or unsafe-permission method here.
_ALLOWED_RPC_METHODS = frozenset(
    {
        "droid.initialize_session",
        "droid.load_session",
        "droid.add_user_message",
        "droid.close_session",
        "droid.interrupt_session",
        "droid.update_session_settings",
        "droid.list_tools",
        "droid.list_mcp_tools",
        "droid.list_mcp_servers",
        "droid.list_commands",
        "droid.get_context_stats",
        "droid.get_context_breakdown",
        "droid.fork_session",
        "droid.compact_session",
    }
)


class FactoryDroidError(RuntimeError):
    code = "droid_error"

    def __init__(self, message: str, *, request_id: str | None = None):
        self.request_id = request_id
        super().__init__(message)


class FactoryDroidUnavailable(FactoryDroidError):
    code = "droid_unavailable"


class FactoryDroidProtocolError(FactoryDroidUnavailable):
    code = "protocol_mismatch"


class FactoryDroidTimeout(FactoryDroidUnavailable):
    code = "provider_timeout"


class FactoryDroidDisconnected(FactoryDroidUnavailable):
    code = "provider_disconnected"


class FactoryDroidUnsupportedOperation(FactoryDroidError):
    code = "operation_not_supported"


class FactoryDroidStaleControl(FactoryDroidError):
    code = "stale_provider_control"


class FactoryDroidRPCError(FactoryDroidError):
    code = "provider_rejected"

    def __init__(self, rpc_code: int | None, message: str, *, request_id: str | None = None):
        self.rpc_code = rpc_code
        super().__init__(_bounded_text(message, 512), request_id=request_id)


@dataclass(frozen=True)
class FactoryDroidLaunchEvidence:
    executable: Path
    version: str
    channel: str
    protocol_version: str
    help_digest: str
    executable_fingerprint: str
    config_fingerprint: str
    launch_digest: str
    auth_source: str | None


@dataclass
class _PendingRequest:
    event: threading.Event
    result: Any = None
    error: BaseException | None = None


@dataclass(frozen=True)
class _RpcResult:
    request_id: str
    result: Any


@dataclass(frozen=True)
class _PendingApproval:
    approval_id: str
    session_id: str
    capability_generation: int
    offered: tuple[str, ...]

@dataclass(frozen=True)
class _PendingQuestionnaire:
    request_id: str
    session_id: str
    capability_generation: int
    tool_call_id: str
    questions: tuple[dict[str, Any], ...]

@dataclass(frozen=True)
class _DroidSessionTarget:
    session_id: str
    binding_id: str
    capability_generation: int
    cwd: Path
    observed_monotonic: float


def _bounded_text(value: Any, limit: int = _MAX_TEXT_BYTES) -> str:
    text = value if isinstance(value, str) else str(value)
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", errors="ignore") + "…"


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _strict_json_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _safe_identifier(value: Any, *, limit: int = 512) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or any(ord(char) < 32 for char in value)
    ):
        return None
    if len(value.encode("utf-8")) > limit:
        return None
    return value


def _droid_session_id_matches(
    requested_session_id: str | None,
    native_session_id: str,
) -> bool:
    return requested_session_id in {
        native_session_id,
        f"droid:{native_session_id}",
    }


def _native_control_session_id(
    session_id: Any,
    session_truth: Mapping[str, Any] | None,
    *,
    binding_id: str,
) -> str:
    requested = _safe_identifier(session_id)
    if requested is None:
        raise FactoryDroidUnavailable("invalid_session_id")
    if not requested.startswith("droid:"):
        if (
            isinstance(session_truth, Mapping)
            and session_truth.get("native_id") is not None
        ):
            native_id = _safe_identifier(
                session_truth.get("native_id")
            )
            if (
                native_id != requested
                or session_truth.get("provider_id") != "droid"
                or session_truth.get("session_id") != requested
                or session_truth.get("binding_id") != binding_id
            ):
                raise FactoryDroidStaleControl(
                    "session_truth_identity_stale"
                )
        return requested
    if not isinstance(session_truth, Mapping):
        raise FactoryDroidStaleControl(
            "session_truth_identity_stale"
        )
    native_id = _safe_identifier(session_truth.get("native_id"))
    if (
        native_id is None
        or requested != f"droid:{native_id}"
        or session_truth.get("provider_id") != "droid"
        or session_truth.get("session_id") != requested
        or session_truth.get("binding_id") != binding_id
    ):
        raise FactoryDroidStaleControl(
            "session_truth_identity_stale"
        )
    return native_id


def _droid_operation_id(
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
    return f"droid:{capability_generation}:{digest}"


def _safe_cwd(value: str | Path) -> Path:
    try:
        path = Path(value).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise FactoryDroidUnavailable("cwd_unavailable") from exc
    if not path.is_dir():
        raise FactoryDroidUnavailable("cwd_not_directory")
    return path


def _extract_version(raw: str) -> str | None:
    match = re.search(r"(?<!\d)(\d+\.\d+\.\d+)(?!\d)", raw or "")
    return match.group(1) if match else None


def _run_probe(executable: Path, args: tuple[str, ...], *, environ: Mapping[str, str], timeout: float = 3.0) -> str:
    try:
        completed = subprocess.run(
            [str(executable), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=timeout,
            env=dict(environ),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FactoryDroidUnavailable("cli_probe_failed") from exc
    output = completed.stdout.decode("utf-8", errors="replace")[:128_000]
    if completed.returncode != 0:
        raise FactoryDroidUnavailable("cli_probe_failed")
    return output


def _executable_fingerprint(executable: Path) -> str:
    try:
        before = executable.stat()
        digest = hashlib.sha256(
            (
                f"{executable}:{before.st_dev}:{before.st_ino}:"
                f"{before.st_size}:{before.st_mtime_ns}:"
            ).encode()
        )
        with executable.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
        after = executable.stat()
    except OSError as exc:
        raise FactoryDroidUnavailable("cli_stat_failed") from exc
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise FactoryDroidUnavailable("cli_changed_during_probe")
    return digest.hexdigest()


def _config_fingerprint(environ: Mapping[str, str]) -> str:
    home = Path(environ.get("HOME") or str(Path.home())).expanduser()
    path = home / ".factory" / "settings.json"
    digest = hashlib.sha256(str(path).encode("utf-8"))
    try:
        stat = path.stat()
    except FileNotFoundError:
        digest.update(b":missing")
        return digest.hexdigest()
    except OSError as exc:
        raise FactoryDroidUnavailable("config_canary_failed") from exc
    if not path.is_file() or stat.st_size > 1024 * 1024:
        raise FactoryDroidUnavailable("config_canary_failed")
    digest.update(
        f":{stat.st_dev}:{stat.st_ino}:{stat.st_size}:{stat.st_mtime_ns}:".encode()
    )
    try:
        with path.open("rb") as stream:
            while block := stream.read(64 * 1024):
                digest.update(block)
        after = path.stat()
    except OSError as exc:
        raise FactoryDroidUnavailable("config_canary_failed") from exc
    if (
        stat.st_dev,
        stat.st_ino,
        stat.st_size,
        stat.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise FactoryDroidUnavailable("config_changed_during_probe")
    return digest.hexdigest()

def _provider_credential_store_available(environ: Mapping[str, str]) -> bool:
    home = Path(environ.get("HOME") or str(Path.home())).expanduser()
    credential_root = home / ".factory"
    try:
        return credential_root.is_dir() and os.access(credential_root, os.R_OK | os.X_OK)
    except OSError:
        return False




def probe_factory_droid_launch(
    executable: str | Path,
    *,
    environ: Mapping[str, str] | None = None,
    require_auth: bool = True,
) -> FactoryDroidLaunchEvidence:
    source_environment = os.environ if environ is None else environ
    env = managed_child_environment(
        source=source_environment,
        home=source_environment.get("HOME"),
    )
    try:
        resolved = Path(executable).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise FactoryDroidUnavailable("cli_missing") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise FactoryDroidUnavailable("cli_not_executable")
    before_fingerprint = _executable_fingerprint(resolved)
    raw_version = _run_probe(resolved, ("--version",), environ=env)
    version = _extract_version(raw_version)
    if version != DROID_SUPPORTED_VERSION:
        raise FactoryDroidUnavailable("unsupported_cli_version")
    normalized_version = raw_version.casefold()
    if (
        re.search(
            rf"{re.escape(DROID_SUPPORTED_VERSION)}[-+][0-9a-z]",
            normalized_version,
        )
        or any(
            re.search(rf"\b{re.escape(marker)}\b", normalized_version)
            for marker in _UNSTABLE_CHANNEL_MARKERS
        )
    ):
        raise FactoryDroidUnavailable("unsupported_cli_channel")
    help_text = _run_probe(resolved, ("exec", "--help"), environ=env)
    if any(token not in help_text for token in _REQUIRED_HELP_TOKENS):
        raise FactoryDroidUnavailable("jsonrpc_capability_missing")
    auth_source = (
        "provider_credential_store"
        if _provider_credential_store_available(env)
        else None
    )
    if require_auth and auth_source is None:
        raise FactoryDroidUnavailable("auth_canary_missing")
    help_digest = hashlib.sha256(help_text.encode("utf-8")).hexdigest()
    executable_fingerprint = _executable_fingerprint(resolved)
    if executable_fingerprint != before_fingerprint:
        raise FactoryDroidUnavailable("cli_changed_during_probe")
    config_fingerprint = _config_fingerprint(env)
    launch_material = json.dumps(
        {
            "executable": str(resolved),
            "executable_fingerprint": executable_fingerprint,
            "config_fingerprint": config_fingerprint,
            "args": _FIXED_EXEC_ARGS,
            "version": version,
            "protocol": DROID_PROTOCOL_VERSION,
            "default_mode": _READ_ONLY_INTERACTION_MODE,
            "default_autonomy": _READ_ONLY_AUTONOMY_LEVEL,
            "skip_permissions_unsafe": False,
            "help_digest": help_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return FactoryDroidLaunchEvidence(
        executable=resolved,
        version=version,
        channel=DROID_CHANNEL,
        protocol_version=DROID_PROTOCOL_VERSION,
        help_digest=help_digest,
        executable_fingerprint=executable_fingerprint,
        config_fingerprint=config_fingerprint,
        launch_digest=hashlib.sha256(launch_material).hexdigest(),
        auth_source=auth_source,
    )


def _redacted_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "[redacted-url]"
    if not parsed.scheme or not parsed.netloc:
        return "[redacted-url]"
    return f"{parsed.scheme}://[redacted]"


def _is_secret_key(lowered: str) -> bool:
    if any(part in lowered for part in _SECRET_PARTS):
        return True
    compact = lowered.replace("_", "")
    return (
        compact == "token"
        or (
            compact.endswith("token")
            and not compact.endswith("tokens")
        )
    )


def _sanitize(value: Any, *, key: str = "", depth: int = 0) -> Any:
    lowered = key.casefold().replace("-", "_")
    if _is_secret_key(lowered):
        return "[redacted]"
    if lowered in {"env", "headers"}:
        return "[redacted]"
    if lowered in {"url", "uri", "endpoint"} and isinstance(value, str):
        return _redacted_url(value)
    if depth > 8:
        return "[truncated]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _bounded_text(value)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, item in list(value.items())[:128]:
            safe_key = _bounded_text(raw_key, 128)
            result[safe_key] = _sanitize(
                item, key=safe_key, depth=depth + 1
            )
        return result
    if isinstance(value, (list, tuple)):
        return [
            _sanitize(item, depth=depth + 1)
            for item in value[:128]
        ]
    return _bounded_text(value)


def _public_provider_event(
    notification_type: str,
    notification: Mapping[str, Any],
) -> dict[str, Any]:
    if notification_type == "tool_call":
        tool_use = notification.get("toolUse")
        return {
            "tool_use_id": (
                _safe_identifier(tool_use.get("id"))
                if isinstance(tool_use, Mapping)
                else None
            ),
            "tool_name": (
                _bounded_text(tool_use.get("name", ""), 160)
                if isinstance(tool_use, Mapping)
                else None
            ),
        }
    if notification_type == "tool_result":
        return {
            key: _sanitize(notification.get(key))
            for key in (
                "toolUseId",
                "toolName",
                "status",
                "isError",
            )
            if key in notification
        }
    if notification_type == "tool_progress_update":
        update = notification.get("update")
        return {
            "tool_use_id": notification.get("toolUseId"),
            "tool_name": notification.get("toolName"),
            "update": (
                {
                    key: _sanitize(update.get(key))
                    for key in ("type", "status", "timestamp")
                    if key in update
                }
                if isinstance(update, Mapping)
                else {}
            ),
        }
    if notification_type == "create_message":
        message = notification.get("message")
        return {
            "message": (
                {
                    key: _sanitize(message.get(key))
                    for key in ("id", "role", "visibility")
                    if key in message
                }
                if isinstance(message, Mapping)
                else {}
            ),
            "parent_id": notification.get("parentId"),
            "request_id": notification.get("requestId"),
        }
    if notification_type == "session_compacted":
        return {
            key: _sanitize(notification.get(key))
            for key in (
                "summaryId",
                "removedCount",
                "visibleBoundaryMessageId",
            )
            if key in notification
        }
    if notification_type == "structured_output":
        return {
            "message_id": notification.get("messageId"),
            "present": notification.get("structuredOutput") is not None,
        }
    if notification_type == "session_title_updated":
        return {
            "request_id": notification.get("requestId"),
            "title": _bounded_text(notification.get("title", ""), 512),
        }
    if notification_type in {
        "mcp_auth_required",
        "mcp_auth_completed",
    }:
        return {
            key: _sanitize(notification.get(key))
            for key in ("serverName", "outcome", "message")
            if key in notification
        }
    return {
        "keys": sorted(
            _bounded_text(key, 128)
            for key in notification
            if isinstance(key, str)
        )[:128]
    }


def _public_mission_snapshot(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    features = value.get("features")
    progress = value.get("progressLog")
    workers = value.get("workerSessionIds")
    feature_counts: dict[str, int] = {}
    if isinstance(features, list):
        for feature in features:
            status = (
                feature.get("status")
                if isinstance(feature, Mapping)
                else None
            )
            key = status if isinstance(status, str) else "unknown"
            feature_counts[key] = feature_counts.get(key, 0) + 1
    return {
        "state": _sanitize(value.get("state")),
        "updated_at": _sanitize(value.get("updatedAt")),
        "feature_counts": feature_counts,
        "progress_entry_count": (
            len(progress) if isinstance(progress, list) else 0
        ),
        "worker_count": (
            len(workers) if isinstance(workers, list) else 0
        ),
        "token_usage": _sanitize(value.get("tokenUsage")),
    }


class _DroidJsonRpcProcess:
    def __init__(
        self,
        evidence: FactoryDroidLaunchEvidence,
        *,
        environ: Mapping[str, str],
        request_timeout: float,
        on_notification: Callable[[dict[str, Any]], None],
        on_server_request: Callable[[dict[str, Any]], None],
        on_disconnect: Callable[[BaseException], None],
    ) -> None:
        self.evidence = evidence
        self._environ = dict(environ)
        self._request_timeout = max(0.05, float(request_timeout))
        self._on_notification = on_notification
        self._on_server_request = on_server_request
        self._on_disconnect = on_disconnect
        self._process: subprocess.Popen[bytes] | None = None
        self._reader: threading.Thread | None = None
        self._lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._pending: dict[str, _PendingRequest] = {}
        self._closed = False
        self._error: BaseException | None = None

    @property
    def healthy(self) -> bool:
        with self._lock:
            return self._process is not None and self._process.poll() is None and self._error is None and not self._closed

    def start(self, cwd: Path) -> None:
        current = probe_factory_droid_launch(self.evidence.executable, environ=self._environ)
        if current != self.evidence:
            raise FactoryDroidUnavailable("launch_digest_changed")
        try:
            process = subprocess.Popen(
                [str(self.evidence.executable), *_FIXED_EXEC_ARGS],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=str(cwd),
                env=self._environ,
                bufsize=0,
            )
        except OSError as exc:
            raise FactoryDroidUnavailable("process_launch_failed") from exc
        if process.stdin is None or process.stdout is None:
            close_owned_process(process)
            raise FactoryDroidUnavailable("process_pipe_missing")
        with self._lock:
            self._process = process
            self._closed = False
            self._error = None
        reader = threading.Thread(
            target=self._read_loop,
            args=(process,),
            name="pairling-droid-jsonrpc",
            daemon=True,
        )
        self._reader = reader
        try:
            reader.start()
        except BaseException:
            with self._lock:
                if self._process is process:
                    self._process = None
                if self._reader is reader:
                    self._reader = None
            close_owned_process(process)
            raise

    def request(
        self,
        method: str,
        params: Mapping[str, Any],
        *,
        on_request_id: Callable[[str], None] | None = None,
        request_id: str | None = None,
    ) -> _RpcResult:
        if method not in _ALLOWED_RPC_METHODS:
            raise FactoryDroidUnsupportedOperation("unreviewed_droid_method")
        if request_id is None:
            request_id = f"pairling-{uuid.uuid4()}"
        elif _safe_identifier(request_id) is None:
            raise FactoryDroidProtocolError("invalid_pairling_request_id")
        pending = _PendingRequest(threading.Event())
        with self._lock:
            if not self.healthy:
                raise FactoryDroidDisconnected("provider_process_unavailable", request_id=request_id)
            self._pending[request_id] = pending
        if on_request_id is not None:
            try:
                on_request_id(request_id)
            except BaseException:
                with self._lock:
                    self._pending.pop(request_id, None)
                raise
        try:
            self._write(self._envelope("request", id=request_id, method=method, params=dict(params)))
        except BaseException as exc:
            with self._lock:
                self._pending.pop(request_id, None)
            self._fail(exc)
            raise FactoryDroidDisconnected("provider_write_failed", request_id=request_id) from exc
        if not pending.event.wait(self._request_timeout):
            error = FactoryDroidTimeout("provider_request_timed_out", request_id=request_id)
            with self._lock:
                self._pending.pop(request_id, None)
            self._fail(error)
            raise error
        if pending.error is not None:
            if isinstance(pending.error, FactoryDroidError):
                raise pending.error
            raise FactoryDroidDisconnected("provider_request_failed", request_id=request_id) from pending.error
        return _RpcResult(request_id, pending.result)

    def send_result(self, request_id: str, result: Mapping[str, Any]) -> None:
        if _safe_identifier(request_id) is None:
            raise FactoryDroidProtocolError("invalid_provider_request_id")
        self._write(self._envelope("response", id=request_id, result=dict(result)))

    def send_error(self, request_id: str, code: int, message: str) -> None:
        if _safe_identifier(request_id) is None:
            return
        try:
            self._write(self._envelope("response", id=request_id, error={"code": int(code), "message": _bounded_text(message, 512)}))
        except FactoryDroidError:
            return

    def close(self) -> None:
        with self._lock:
            process = self._process
            reader = self._reader
            if not self._closed:
                self._closed = True
                self._process = None
                pending = list(self._pending.values())
                self._pending.clear()
            else:
                pending = []
        for item in pending:
            item.error = FactoryDroidDisconnected("provider_process_closed")
            item.event.set()
        if process is not None:
            close_owned_process(process, reader=reader)
        elif reader is not None and reader is not threading.current_thread() and reader.ident is not None:
            reader.join(timeout=1.0)
        with self._lock:
            if self._reader is reader:
                self._reader = None

    def _envelope(self, message_type: str, **fields: Any) -> dict[str, Any]:
        return {
            "jsonrpc": DROID_JSONRPC_VERSION,
            "factoryApiVersion": DROID_API_VERSION,
            "factoryProtocolVersion": DROID_PROTOCOL_VERSION,
            "type": message_type,
            **fields,
        }

    def _write(self, message: Mapping[str, Any]) -> None:
        try:
            payload = json.dumps(message, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
        except (TypeError, ValueError) as exc:
            raise FactoryDroidProtocolError("outbound_json_invalid") from exc
        if len(payload) > _MAX_REQUEST_BYTES:
            raise FactoryDroidProtocolError("outbound_request_too_large")
        with self._write_lock:
            with self._lock:
                process = self._process
                stream = process.stdin if process is not None else None
            if process is None or stream is None or process.poll() is not None:
                raise FactoryDroidDisconnected("provider_process_unavailable")
            try:
                stream.write(payload)
                stream.flush()
            except OSError as exc:
                raise FactoryDroidDisconnected("provider_pipe_closed") from exc

    def _read_loop(self, process: subprocess.Popen[bytes]) -> None:
        stream = process.stdout
        if stream is None:
            self._fail(FactoryDroidDisconnected("provider_stdout_missing"))
            return
        try:
            while True:
                line = stream.readline(_MAX_LINE_BYTES + 1)
                if not line:
                    break
                if len(line) > _MAX_LINE_BYTES or not line.endswith(b"\n"):
                    raise FactoryDroidProtocolError("provider_line_too_large")
                try:
                    raw = json.loads(
                        line,
                        parse_constant=_reject_json_constant,
                        object_pairs_hook=_strict_json_object,
                    )
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                    raise FactoryDroidProtocolError(
                        "malformed_provider_json"
                    ) from exc
                message = self._validate_inbound(raw)
                if message["type"] == "response":
                    self._handle_response(message)
                elif message["type"] == "notification":
                    self._on_notification(message)
                else:
                    self._on_server_request(message)
            if not self._closed:
                raise FactoryDroidDisconnected("provider_process_eof")
        except BaseException as exc:
            if not self._closed:
                self._fail(exc)

    def _validate_inbound(self, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise FactoryDroidProtocolError("provider_envelope_not_object")
        required = {
            "jsonrpc": DROID_JSONRPC_VERSION,
            "factoryApiVersion": DROID_API_VERSION,
            "factoryProtocolVersion": DROID_PROTOCOL_VERSION,
        }
        if any(raw.get(key) != expected for key, expected in required.items()):
            raise FactoryDroidProtocolError("provider_protocol_version_mismatch")
        if raw.get("type") not in {"request", "response", "notification"}:
            raise FactoryDroidProtocolError("provider_message_type_invalid")
        return raw

    def _handle_response(self, message: Mapping[str, Any]) -> None:
        request_id = _safe_identifier(message.get("id"))
        if request_id is None:
            raise FactoryDroidProtocolError(
                "provider_response_id_invalid"
            )
        has_result = "result" in message
        has_error = "error" in message
        if has_result == has_error:
            raise FactoryDroidProtocolError(
                "provider_response_shape_invalid",
                request_id=request_id,
            )
        error = message.get("error")
        if has_error and (
            not isinstance(error, Mapping)
            or not isinstance(error.get("code"), int)
            or isinstance(error.get("code"), bool)
            or not isinstance(error.get("message"), str)
        ):
            raise FactoryDroidProtocolError(
                "provider_error_invalid",
                request_id=request_id,
            )
        with self._lock:
            pending = self._pending.pop(request_id, None)
        if pending is None:
            return
        if has_error:
            pending.error = FactoryDroidRPCError(
                error["code"],
                error["message"],
                request_id=request_id,
            )
        else:
            pending.result = message["result"]
        pending.event.set()

    def _fail(self, error: BaseException) -> None:
        with self._lock:
            if self._error is not None or self._closed:
                return
            self._error = error
            process = self._process
            reader = self._reader
            self._process = None
            pending = list(self._pending.values())
            self._pending.clear()
        for item in pending:
            item.error = error
            item.event.set()
        if process is not None:
            close_owned_process(process, reader=reader)
        elif reader is not None and reader is not threading.current_thread() and reader.ident is not None:
            reader.join(timeout=1.0)
        with self._lock:
            if self._reader is reader:
                self._reader = None
        self._on_disconnect(error)


class FactoryDroidJsonRpcDriver:
    """Pinned, local, public JSON-RPC driver for one Factory Droid binding."""
    generation_refresh_safe = True


    binding: ProviderControlBinding

    def __init__(
        self,
        binding: ProviderControlBinding,
        launch_evidence: FactoryDroidLaunchEvidence,
        *,
        environ: Mapping[str, str] | None = None,
        request_timeout: float = 5.0,
        provider_settings: Mapping[str, str] | None = None,
        snapshot_ttl: float = 15.0,
    ) -> None:
        if binding.provider_id != "droid":
            raise FactoryDroidUnavailable("binding_provider_mismatch")
        if (
            binding.provider_version != launch_evidence.version
            or binding.provider_channel != launch_evidence.channel
        ):
            raise FactoryDroidUnavailable("binding_version_mismatch")
        if (
            launch_evidence.protocol_version != DROID_PROTOCOL_VERSION
            or launch_evidence.auth_source is None
        ):
            raise FactoryDroidUnavailable("launch_evidence_incomplete")
        self.binding = binding
        self.launch_evidence = launch_evidence
        self._environ = managed_child_environment(
            source=environ,
            provider_settings=provider_settings,
        )
        self._request_timeout = request_timeout
        self._snapshot_ttl = max(1.0, min(float(snapshot_ttl), 30.0))
        self._state_lock = threading.RLock()
        self._connect_lock = threading.Lock()
        self._event_ready = threading.Condition(self._state_lock)
        self._transport: _DroidJsonRpcProcess | None = None
        self._capability_generation = 1
        self._event_cursor = 0
        self._events: deque[dict[str, Any]] = deque(maxlen=_MAX_EVENTS)
        self._current_session_id: str | None = None
        self._cwd: Path | None = None
        self._session_target: _DroidSessionTarget | None = None
        self._settings: dict[str, Any] = {}
        self._models: list[dict[str, Any]] = []
        self._tools: list[dict[str, Any]] = []
        self._mcp_servers: dict[str, Any] = {"servers": [], "summary": {}}
        self._mcp_tools: list[dict[str, Any]] = []
        self._commands: list[dict[str, Any]] = []
        self._context_stats: dict[str, Any] | None = None
        self._context_breakdown: dict[str, Any] | None = None
        self._usage: dict[str, Any] | None = None
        self._expected_settings_updates: OrderedDict[
            str, dict[str, Any]
        ] = OrderedDict()
        self._worktree: dict[str, Any] | None = None
        self._mission: dict[str, Any] | None = None
        self._working_state = "idle"
        self._pending_approvals: dict[str, _PendingApproval] = {}
        self._pending_questionnaires: dict[str, _PendingQuestionnaire] = {}
        self._last_error: str | None = None
        self._action_results: OrderedDict[
            str,
            tuple[str, int, str | None, ProviderOperationResult],
        ] = OrderedDict()

    @property
    def capability_generation(self) -> int:
        with self._state_lock:
            return self._capability_generation

    def refresh_session_binding(
        self,
        session_truth: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        if not isinstance(session_truth, Mapping):
            raise FactoryDroidStaleControl(
                "managed_generation_truth_shape_stale"
            )
        persisted_generation = session_truth.get(
            "capability_generation"
        )
        cwd_value = session_truth.get("cwd")
        if (
            isinstance(persisted_generation, bool)
            or not isinstance(persisted_generation, int)
            or not isinstance(cwd_value, (str, Path))
        ):
            raise FactoryDroidStaleControl(
                "managed_generation_truth_shape_stale"
            )
        try:
            expected_cwd = _safe_cwd(cwd_value)
        except FactoryDroidError as exc:
            raise FactoryDroidStaleControl(
                "managed_generation_workspace_stale"
            ) from exc
        with self._state_lock:
            current_id = self._current_session_id
            generation = self._capability_generation
            target = self._session_target
            transport = self._transport
            if (
                current_id is None
                or session_truth.get("provider_id") != "droid"
                or session_truth.get("binding_id")
                != self.binding.binding_id
                or session_truth.get("provider_version")
                != self.binding.provider_version
                or session_truth.get("provider_channel")
                != self.binding.provider_channel
                or session_truth.get("session_id")
                != f"droid:{current_id}"
                or session_truth.get("native_id") != current_id
                or session_truth.get("managed") is not True
                or session_truth.get("owner") != "provider_driver"
            ):
                raise FactoryDroidStaleControl(
                    "managed_generation_truth_identity_stale"
                )
            if (
                session_truth.get("driver_available") is not True
                or session_truth.get("lifecycle")
                not in {"launching", "running", "waiting"}
                or persisted_generation < 1
                or persisted_generation >= generation
            ):
                raise FactoryDroidStaleControl(
                    "managed_generation_truth_state_stale"
                )
            if self._cwd != expected_cwd:
                raise FactoryDroidStaleControl(
                    "managed_generation_workspace_stale"
                )
            reconnect_required = (
                transport is None
                or not transport.healthy
                or target is None
                or target.session_id != current_id
                or target.binding_id != self.binding.binding_id
                or target.capability_generation != generation
                or target.cwd != expected_cwd
            )
        if reconnect_required:
            self.attach_session(
                current_id,
                expected_cwd=expected_cwd,
            )
        with self._state_lock:
            current_id = self._current_session_id
            generation = self._capability_generation
            target = self._session_target
            if (
                current_id is None
                or session_truth.get("session_id")
                != f"droid:{current_id}"
                or session_truth.get("native_id") != current_id
            ):
                raise FactoryDroidStaleControl(
                    "managed_generation_reconnect_identity_stale"
                )
            if persisted_generation >= generation:
                raise FactoryDroidStaleControl(
                    "managed_generation_reconnect_state_stale"
                )
            if self._cwd != expected_cwd:
                raise FactoryDroidStaleControl(
                    "managed_generation_reconnect_workspace_stale"
                )
            if (
                target is None
                or target.session_id != current_id
                or target.binding_id != self.binding.binding_id
                or target.capability_generation != generation
                or target.cwd != expected_cwd
            ):
                raise FactoryDroidStaleControl(
                    "managed_generation_reconnect_target_stale"
                )
            return {
                "binding_id": self.binding.binding_id,
                "session_id": f"droid:{current_id}",
                "native_session_id": current_id,
                "capability_generation": generation,
                "generation_resume_cursor": (
                    f"{generation}:0:"
                    f"{self.launch_evidence.launch_digest[:16]}"
                ),
                "lifecycle": "live",
                "driver_available": True,
            }

    @property
    def session_id(self) -> str | None:
        with self._state_lock:
            return self._current_session_id

    def create_owned_session(
        self,
        cwd: str | Path,
        *,
        worktree: bool = False,
        session_id: str | None = None,
    ) -> str:
        safe_cwd = _safe_cwd(cwd)
        if session_id is not None and _safe_identifier(session_id) is None:
            raise FactoryDroidUnavailable("invalid_session_id")
        self._start_transport(safe_cwd)
        params: dict[str, Any] = {
            "machineId": "pairling-local",
            "cwd": str(safe_cwd),
            "interactionMode": _READ_ONLY_INTERACTION_MODE,
            "autonomyLevel": _READ_ONLY_AUTONOMY_LEVEL,
            "skipPermissionsUnsafe": False,
            "worktree": bool(worktree),
        }
        if session_id is not None:
            params["sessionId"] = session_id
        try:
            call = self._rpc("droid.initialize_session", params)
            result = self._require_object(call.result, "initialize result")
            actual_session_id = _safe_identifier(result.get("sessionId"))
            if actual_session_id is None:
                raise FactoryDroidProtocolError("initialize_session_id_missing")
            worktree_info = result.get("worktree")
            if worktree and (
                not isinstance(worktree_info, Mapping)
                or not isinstance(worktree_info.get("path"), str)
            ):
                raise FactoryDroidUnavailable("worktree_canary_failed")
            self._adopt_session(
                actual_session_id,
                result,
                expected_cwd=None if worktree else safe_cwd,
            )
            if not self._is_read_only():
                raise FactoryDroidUnavailable(
                    "owned_session_not_read_only"
                )
            self._verify_capability_canaries()
        except BaseException:
            self.close()
            raise
        with self._state_lock:
            self._append_event_locked("session_attached", {"owned": True})
        return actual_session_id

    def launch_session(
        self,
        *,
        project: str,
        title: str,
        first_prompt: str = "",
    ) -> dict[str, Any]:
        del title
        native_id = self.create_owned_session(project)
        try:
            if first_prompt:
                if not isinstance(first_prompt, str) or len(first_prompt) > 200_000:
                    raise FactoryDroidUnavailable("message_text_invalid")
                with self._state_lock:
                    self._working_state = "running"
                self._rpc(
                    "droid.add_user_message",
                    {
                        "messageId": str(uuid.uuid4()).lower(),
                        "text": first_prompt,
                    },
                )
            with self._state_lock:
                generation = self._capability_generation
                generation_resume_cursor = (
                    f"{generation}:0:"
                    f"{self.launch_evidence.launch_digest[:16]}"
                )
            return {
                "provider_id": self.binding.provider_id,
                "provider_version": self.binding.provider_version,
                "provider_channel": self.binding.provider_channel,
                "binding_id": self.binding.binding_id,
                "native_session_id": native_id,
                "capability_generation": generation,
                "provider_cursor": generation_resume_cursor,
            }
        except BaseException:
            self.close()
            raise

    def attach_session(
        self,
        session_id: str,
        *,
        expected_cwd: str | Path | None = None,
    ) -> None:
        safe_session_id = _safe_identifier(session_id)
        if safe_session_id is None:
            raise FactoryDroidUnavailable("invalid_session_id")
        expected = _safe_cwd(expected_cwd) if expected_cwd is not None else None
        launch_cwd = expected or Path.cwd().resolve()
        self._start_transport(launch_cwd)
        try:
            call = self._rpc(
                "droid.load_session",
                {"sessionId": safe_session_id, "loadAllMessages": False},
            )
            result = self._require_object(call.result, "load result")
            self._adopt_session(safe_session_id, result, expected_cwd=expected)
            if not self._is_read_only():
                self._update_settings(
                    {
                        "interactionMode": _READ_ONLY_INTERACTION_MODE,
                        "autonomyLevel": _READ_ONLY_AUTONOMY_LEVEL,
                    }
                )
                self._cancel_pending_approvals(
                    "attach_lowered_to_read_only"
                )
            self._verify_capability_canaries()
        except BaseException:
            self.close()
            raise
        with self._state_lock:
            self._append_event_locked("session_attached", {"owned": False})

    def snapshot(
        self,
        *,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderControlSnapshot:
        blocked: str | None = None
        if session_id is not None:
            try:
                self._ensure_snapshot_session(session_id, session_truth)
            except FactoryDroidError as exc:
                blocked = exc.code
                with self._state_lock:
                    self._last_error = exc.code
        target: _DroidSessionTarget | None = None
        if blocked is None:
            with self._state_lock:
                candidate = self._reviewed_target_locked(
                    require_fresh=False
                )
            if candidate is not None:
                target = self._discover_reviewed_target(
                    require_fresh=False
                )
        with self._state_lock:
            generation = self._capability_generation
            current_id = self._current_session_id if blocked is None else None
            operations: list[str] = [
                "provider.auth.read",
                "provider.diagnostics.read",
            ]
            values: list[ControlValue] = []
            choices: list[ControlChoices] = []
            if (
                current_id is not None
                and self._transport is not None
                and self._transport.healthy
            ):
                operations.extend(
                    [
                        "provider.config.read",
                        "provider.commands.read",
                        "provider.mcp.read",
                        "provider.usage.read",
                    ]
                )
                if session_id is not None:
                    if self._working_state == "idle":
                        operations.extend(
                            [
                                "session.prompt.send",
                                "session.compact",
                                "session.model.set",
                                "session.reasoning.set",
                                "session.permissions.set",
                            ]
                        )
                        reviewed_target = self._reviewed_target_locked(
                            require_fresh=True
                        )
                        if (
                            target is not None
                            and reviewed_target is not None
                            and target == reviewed_target
                        ):
                            target_choices = (
                                ControlChoice(
                                    reviewed_target.session_id,
                                    "Current Factory Droid session",
                                ),
                            )
                            operations.extend(
                                ["session.resume", "session.fork"]
                            )
                            choices.extend(
                                (
                                    ControlChoices(
                                        "session.resume",
                                        "target_session",
                                        target_choices,
                                    ),
                                    ControlChoices(
                                        "session.fork",
                                        "target_session",
                                        target_choices,
                                    ),
                                )
                            )
                    else:
                        operations.extend(
                            ["session.turn.steer", "session.turn.interrupt"]
                        )
                    operations.append("session.terminate")
                    identity = ProviderSessionIdentity(
                        "droid",
                        session_id,
                        self.binding.binding_id,
                        generation,
                    )
                    for operation_id in operations:
                        if operation_id.startswith("session."):
                            values.append(
                                ControlValue(operation_id, "session", identity)
                            )
                    self._append_model_choices(operations, values, choices)
                    self._append_permission_choices(operations, values, choices)
                    self._append_approval_choices(operations, choices)
                    self._append_questionnaire_values(operations, values, choices)
            observed = time.time()
            return ProviderControlSnapshot(
                provider_id="droid",
                provider_version=self.binding.provider_version,
                provider_channel=self.binding.provider_channel,
                binding_id=self.binding.binding_id,
                capability_generation=generation,
                observed_at=observed,
                valid_until=observed + self._snapshot_ttl,
                advertised_operations=tuple(
                    dict.fromkeys(operations if blocked is None else ())
                ),
                values=tuple(values if blocked is None else ()),
                choices=tuple(choices if blocked is None else ()),
                blocked_reason=blocked,
                provider_cursor=self._provider_cursor_locked(),
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
        if session_id is None:
            raise FactoryDroidUnsupportedOperation(
                "operation_correlation_not_supported"
            )
        native_session_id = _native_control_session_id(
            session_id,
            session_truth,
            binding_id=self.binding.binding_id,
        )
        with self._state_lock:
            current_session_id = self._current_session_id
            current_generation = self._capability_generation
            healthy = (
                self._transport is not None
                and self._transport.healthy
            )
            cursor = self._provider_cursor_locked()
        if (
            not healthy
            or current_session_id != native_session_id
            or capability_generation != current_generation
            or not isinstance(session_truth, dict)
            or session_truth.get("provider_id") != "droid"
            or session_truth.get("session_id") != session_id
            or session_truth.get("binding_id") != self.binding.binding_id
            or session_truth.get("capability_generation")
            != capability_generation
            or session_truth.get("is_live") is not True
            or session_truth.get("controllable") is not True
        ):
            raise FactoryDroidStaleControl(
                "operation_correlation_truth_stale"
            )
        snapshot = self.snapshot(
            session_id=session_id,
            session_truth=session_truth,
        )
        if operation_id not in snapshot.advertised_operations:
            raise FactoryDroidStaleControl(
                "operation_correlation_truth_stale"
            )
        return ProviderOperationCorrelation(
            _droid_operation_id(
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
        if prepared_attachments:
            raise FactoryDroidUnsupportedOperation("attachments_not_supported")
        supported = {
            "session.prompt.send",
            "session.turn.steer",
            "session.turn.interrupt",
            "session.terminate",
            "session.resume",
            "session.fork",
            "session.compact",
            "session.model.set",
            "session.reasoning.set",
            "session.permissions.set",
            "session.approval.decide",
            "session.question.answer",
            "provider.config.read",
            "provider.commands.read",
            "provider.mcp.read",
            "provider.auth.read",
            "provider.usage.read",
            "provider.diagnostics.read",
        }
        if operation_id not in supported:
            raise FactoryDroidUnsupportedOperation(
                "unreviewed_pairling_operation"
            )
        expected_operation_id = _droid_operation_id(
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
            not isinstance(provider_correlation, ProviderOperationCorrelation)
            or provider_correlation.provider_operation_id
            != expected_operation_id
        ):
            raise FactoryDroidStaleControl(
                "operation_correlation_truth_stale"
            )
        digest = self._action_digest(
            operation_id, input_payload, prepared_attachments
        )
        with self._state_lock:
            self._validate_execution_context(
                binding_id, capability_generation, session_id, operation_id
            )
            cached = self._action_results.get(client_action_id)
            if cached is not None:
                if (
                    cached[0] != digest
                    or cached[1] != capability_generation
                    or cached[2] != session_id
                ):
                    raise FactoryDroidStaleControl("client_action_id_reused")
                return cached[3]
        try:
            result = self._execute_uncached(
                operation_id, input_payload, session_id, client_action_id
            )
        except (
            FactoryDroidTimeout,
            FactoryDroidDisconnected,
            FactoryDroidProtocolError,
        ) as exc:
            result = ProviderOperationResult(
                operation_id,
                exc.request_id or f"pairling:{client_action_id}",
                OperationResultStatus.OUTCOME_UNKNOWN,
                {"error": exc.code, "retry_safe": False},
                self.provider_cursor,
            )
        result = ProviderOperationResult(
            operation_id=result.operation_id,
            provider_operation_id=provider_correlation.provider_operation_id,
            status=result.status,
            public_result=result.public_result,
            provider_cursor=provider_correlation.provider_cursor,
        )
        self._cache_action_result(
            client_action_id,
            digest,
            capability_generation,
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
        del session_truth
        if (
            binding_id != self.binding.binding_id
            or not isinstance(
                provider_correlation,
                ProviderOperationCorrelation,
            )
        ):
            return None
        with self._state_lock:
            cached = self._action_results.get(client_action_id)
        if (
            cached is None
            or cached[1] != capability_generation
            or cached[2] != session_id
            or cached[3].operation_id != operation_id
            or cached[3].provider_operation_id
            != provider_correlation.provider_operation_id
            or cached[3].provider_cursor
            != provider_correlation.provider_cursor
            or cached[3].status
            not in {
                OperationResultStatus.APPLIED,
                OperationResultStatus.REJECTED,
            }
        ):
            return None
        return cached[3]

    @property
    def provider_cursor(self) -> str:
        with self._state_lock:
            return self._provider_cursor_locked()

    def poll_events(
        self, provider_cursor: str | None = None
    ) -> tuple[dict[str, Any], ...]:
        with self._state_lock:
            generation, cursor = self._parse_cursor(provider_cursor)
            if generation != self._capability_generation:
                raise FactoryDroidStaleControl(
                    "provider_event_generation_stale"
                )
            if self._events:
                oldest = int(self._events[0]["cursor"])
                if cursor < oldest - 1:
                    raise FactoryDroidStaleControl(
                        "provider_event_cursor_expired"
                    )
            if cursor > self._event_cursor:
                raise FactoryDroidStaleControl("provider_event_cursor_ahead")
            return tuple(
                dict(event)
                for event in self._events
                if int(event["cursor"]) > cursor
            )

    def wait_for_event(self, kind: str, *, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + max(0.0, timeout)
        with self._event_ready:
            while True:
                for event in self._events:
                    if event.get("kind") == kind:
                        return dict(event)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise FactoryDroidTimeout("event_wait_timed_out")
                self._event_ready.wait(remaining)

    def close(self) -> None:
        with self._connect_lock:
            with self._state_lock:
                transport = self._transport
                self._transport = None
                self._session_target = None
                self._pending_approvals.clear()
                self._pending_questionnaires.clear()
                self._expected_settings_updates.clear()
                self._working_state = "idle"
            if transport is not None:
                transport.close()

    def _start_transport(self, cwd: Path) -> None:
        with self._connect_lock:
            with self._state_lock:
                previous = self._transport
                self._transport = None
                self._session_target = None
            if previous is not None:
                previous.close()
            transport = _DroidJsonRpcProcess(
                self.launch_evidence,
                environ=self._environ,
                request_timeout=self._request_timeout,
                on_notification=self._on_notification,
                on_server_request=self._on_server_request,
                on_disconnect=self._on_disconnect,
            )
            transport.start(cwd)
            with self._state_lock:
                self._transport = transport
                self._capability_generation += 1
                self._event_cursor = 0
                self._events.clear()
                self._pending_approvals.clear()
                self._pending_questionnaires.clear()
                self._expected_settings_updates.clear()
                self._last_error = None

    def _rpc(
        self,
        method: str,
        params: Mapping[str, Any],
        *,
        on_request_id: Callable[[str], None] | None = None,
        request_id: str | None = None,
    ) -> _RpcResult:
        with self._state_lock:
            transport = self._transport
        if transport is None or not transport.healthy:
            raise FactoryDroidDisconnected("provider_process_unavailable")
        return transport.request(
            method,
            params,
            on_request_id=on_request_id,
            request_id=request_id,
        )

    def _update_settings(
        self, patch: Mapping[str, Any]
    ) -> _RpcResult:
        expected = dict(patch)
        request_ids: list[str] = []

        def remember(request_id: str) -> None:
            with self._state_lock:
                if len(self._expected_settings_updates) >= 32:
                    raise FactoryDroidUnavailable(
                        "settings_correlation_capacity_exceeded"
                    )
                self._expected_settings_updates[request_id] = expected
                request_ids.append(request_id)

        try:
            call = self._rpc(
                "droid.update_session_settings",
                expected,
                on_request_id=remember,
            )
        except BaseException:
            with self._state_lock:
                for request_id in request_ids:
                    self._expected_settings_updates.pop(
                        request_id, None
                    )
            raise
        with self._state_lock:
            self._settings.update(expected)
        return call

    def _consume_settings_update(
        self,
        settings: Mapping[str, Any],
        request_id: Any,
    ) -> None:
        with self._state_lock:
            expected: dict[str, Any] | None = None
            correlation_id: str | None = None
            if request_id is not None:
                correlation_id = _safe_identifier(request_id)
                if correlation_id is None:
                    raise FactoryDroidProtocolError(
                        "settings_request_id_invalid"
                    )
                expected = self._expected_settings_updates.pop(
                    correlation_id, None
                )
            else:
                for candidate_id, candidate in (
                    self._expected_settings_updates.items()
                ):
                    if all(
                        key in settings
                        and settings[key] == value
                        for key, value in candidate.items()
                    ):
                        correlation_id = candidate_id
                        expected = candidate
                        break
                if correlation_id is not None:
                    self._expected_settings_updates.pop(
                        correlation_id, None
                    )
            if expected is None and self._current_session_id is None:
                self._settings = dict(settings)
                return
            if expected is None:
                controlled = {
                    key: value
                    for key, value in settings.items()
                    if key in _CONTROLLED_SETTING_KEYS
                }
                if controlled and all(
                    key in self._settings and self._settings[key] == value
                    for key, value in controlled.items()
                ):
                    self._settings.update(settings)
                    return
                raise FactoryDroidProtocolError(
                    "uncorrelated_settings_update"
                )
            allowed_couplings = self._allowed_coupled_setting_changes(
                expected,
                settings,
            )
            if any(
                key not in settings or settings[key] != value
                for key, value in expected.items()
            ):
                raise FactoryDroidProtocolError(
                    "settings_update_does_not_match_request"
                )
            for key in _CONTROLLED_SETTING_KEYS:
                if (
                    key in settings
                    and key not in expected
                    and key not in allowed_couplings
                    and self._settings.get(key) != settings[key]
                ):
                    raise FactoryDroidProtocolError(
                        "settings_update_contains_unrequested_change"
                    )
            self._settings.update(settings)

    def _allowed_coupled_setting_changes(
        self,
        expected: Mapping[str, Any],
        settings: Mapping[str, Any],
    ) -> frozenset[str]:
        if set(expected) != {"modelId"}:
            return frozenset()
        model_id = expected.get("modelId")
        if settings.get("modelId") != model_id:
            return frozenset()
        reasoning = settings.get("reasoningEffort")
        for model in self._models:
            if model.get("id") != model_id:
                continue
            supported = model.get("supportedReasoningEfforts", ())
            if reasoning in supported or (
                reasoning == "none" and "off" in supported
            ):
                return frozenset({"reasoningEffort"})
            break
        return frozenset()

    @staticmethod
    def _require_object(value: Any, name: str) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise FactoryDroidProtocolError(
                f"{name.replace(' ', '_')}_invalid"
            )
        return dict(value)

    def _adopt_session(
        self,
        session_id: str,
        result: Mapping[str, Any],
        *,
        expected_cwd: Path | None,
    ) -> None:
        settings = result.get("settings")
        if not isinstance(settings, Mapping):
            raise FactoryDroidProtocolError("session_settings_missing")
        worktree = result.get("worktree")
        raw_cwd = (
            result.get("cwd")
            or (
                worktree.get("path")
                if isinstance(worktree, Mapping)
                else None
            )
            or (str(expected_cwd) if expected_cwd is not None else None)
        )
        if not isinstance(raw_cwd, str):
            raise FactoryDroidProtocolError("session_cwd_missing")
        actual_cwd = _safe_cwd(raw_cwd)
        if expected_cwd is not None and actual_cwd != expected_cwd:
            raise FactoryDroidUnavailable("session_cwd_mismatch")
        models = result.get("availableModels")
        if not isinstance(models, list) or not models:
            raise FactoryDroidProtocolError("available_models_missing")
        normalized_models: list[dict[str, Any]] = []
        for model in models:
            if not isinstance(model, Mapping):
                continue
            model_id = _safe_identifier(model.get("id"), limit=256)
            display = _safe_identifier(model.get("displayName"), limit=160)
            efforts = model.get("supportedReasoningEfforts")
            if (
                model_id is None
                or display is None
                or not isinstance(efforts, list)
            ):
                continue
            safe_efforts = [
                item
                for item in efforts
                if isinstance(item, str) and item in _ALLOWED_REASONING
            ]
            if safe_efforts:
                normalized_models.append(
                    {
                        "id": model_id,
                        "displayName": display,
                        "supportedReasoningEfforts": safe_efforts,
                    }
                )
        if not normalized_models:
            raise FactoryDroidProtocolError("available_models_invalid")
        pending_asks = result.get("pendingAskUserRequests")
        if pending_asks is not None and not isinstance(pending_asks, list):
            raise FactoryDroidProtocolError(
                "pending_ask_user_requests_invalid"
            )
        pending_permissions = result.get("pendingPermissions")
        if (
            pending_permissions is not None
            and not isinstance(pending_permissions, list)
        ):
            raise FactoryDroidProtocolError(
                "pending_permissions_invalid"
            )
        for pending in pending_permissions or ():
            if (
                not isinstance(pending, Mapping)
                or _safe_identifier(pending.get("requestId")) is None
            ):
                raise FactoryDroidProtocolError(
                    "pending_permission_record_invalid"
                )
        with self._state_lock:
            self._current_session_id = session_id
            self._cwd = actual_cwd
            self._session_target = _DroidSessionTarget(
                session_id=session_id,
                binding_id=self.binding.binding_id,
                capability_generation=self._capability_generation,
                cwd=actual_cwd,
                observed_monotonic=time.monotonic(),
            )
            self._settings = dict(settings)
            self._models = normalized_models
            self._worktree = (
                _sanitize(result.get("worktree"))
                if isinstance(result.get("worktree"), Mapping)
                else None
            )
            self._mission = (
                _sanitize(result.get("mission"))
                if isinstance(result.get("mission"), Mapping)
                else None
            )
            self._usage = (
                _sanitize(result.get("tokenUsage"))
                if isinstance(result.get("tokenUsage"), Mapping)
                else None
            )
            self._working_state = (
                "running"
                if result.get("isAgentLoopInProgress") is True
                else "idle"
            )
            self._pending_approvals.clear()
            self._pending_questionnaires.clear()
            for pending in pending_permissions or ():
                request_id = pending["requestId"]
                self._record_approval_locked(request_id, pending)
            for pending in pending_asks or ():
                request_id = pending.get("requestId")
                if _safe_identifier(request_id) is None:
                    raise FactoryDroidProtocolError(
                        "pending_ask_user_record_invalid"
                    )
                self._record_questionnaire_locked(request_id, pending)

    def _verify_capability_canaries(self) -> None:
        with self._state_lock:
            settings = dict(self._settings)
            cwd = self._cwd
        if cwd is None or not cwd.is_dir():
            raise FactoryDroidUnavailable("cwd_canary_failed")
        mode = settings.get("interactionMode")
        autonomy = settings.get("autonomyLevel")
        if (mode, autonomy) not in {
            (
                _READ_ONLY_INTERACTION_MODE,
                _READ_ONLY_AUTONOMY_LEVEL,
            ),
            ("auto", "low"),
        }:
            raise FactoryDroidUnavailable("permission_policy_canary_failed")
        tools = self._require_object(
            self._rpc(
                "droid.list_tools",
                {
                    "interactionMode": mode,
                    "autonomyLevel": autonomy,
                    "skipPermissionsUnsafe": False,
                },
            ).result,
            "tools result",
        ).get("tools")
        if not isinstance(tools, list):
            raise FactoryDroidProtocolError("tools_canary_failed")
        normalized_tools: list[dict[str, Any]] = []
        for tool in tools:
            if not isinstance(tool, Mapping):
                raise FactoryDroidProtocolError("tool_record_invalid")
            tool_id = _safe_identifier(tool.get("id"), limit=256)
            category = tool.get("category")
            allowed = tool.get("currentlyAllowed")
            if (
                tool_id is None
                or category not in {"read", "edit", "execute", "other"}
                or not isinstance(allowed, bool)
            ):
                raise FactoryDroidProtocolError("tool_record_invalid")
            if (
                mode == "auto"
                and autonomy == "low"
                and allowed
                and category == "other"
            ):
                raise FactoryDroidUnavailable("elevated_tool_canary_failed")
            normalized_tools.append(
                {"id": tool_id, "category": category, "allowed": allowed}
            )
        context_stats = self._require_object(
            self._rpc("droid.get_context_stats", {}).result,
            "context result",
        )
        context_breakdown = self._require_object(
            self._rpc("droid.get_context_breakdown", {}).result,
            "context breakdown",
        )
        mcp = self._require_object(
            self._rpc("droid.list_mcp_servers", {}).result,
            "mcp servers",
        )
        mcp_tools_result = self._require_object(
            self._rpc("droid.list_mcp_tools", {}).result,
            "mcp tools",
        )
        commands_result = self._require_object(
            self._rpc("droid.list_commands", {}).result,
            "commands result",
        )
        if (
            not isinstance(mcp.get("servers"), list)
            or not isinstance(mcp_tools_result.get("tools"), list)
            or not isinstance(commands_result.get("commands"), list)
        ):
            raise FactoryDroidProtocolError("read_capability_canary_failed")
        with self._state_lock:
            self._tools = normalized_tools
            self._context_stats = _sanitize(context_stats)
            self._context_breakdown = _sanitize(context_breakdown)
            self._mcp_servers = _sanitize(mcp)
            self._mcp_tools = _sanitize(mcp_tools_result["tools"])
            self._commands = _sanitize(commands_result["commands"])

    def _is_read_only(self) -> bool:
        with self._state_lock:
            return (
                self._settings.get("interactionMode")
                == _READ_ONLY_INTERACTION_MODE
                and self._settings.get("autonomyLevel")
                == _READ_ONLY_AUTONOMY_LEVEL
            )

    def _reviewed_target_locked(
        self,
        *,
        require_fresh: bool,
    ) -> _DroidSessionTarget | None:
        target = self._session_target
        transport = self._transport
        if (
            target is None
            or target.session_id != self._current_session_id
            or target.binding_id != self.binding.binding_id
            or target.capability_generation != self._capability_generation
            or target.cwd != self._cwd
            or transport is None
            or not transport.healthy
            or self._working_state != "idle"
        ):
            return None
        try:
            if not target.cwd.is_dir():
                return None
        except OSError:
            return None
        if (
            require_fresh
            and time.monotonic() - target.observed_monotonic
            > self._snapshot_ttl
        ):
            return None
        return target

    def _discover_reviewed_target(
        self,
        *,
        require_fresh: bool,
    ) -> _DroidSessionTarget | None:
        with self._state_lock:
            candidate = self._reviewed_target_locked(
                require_fresh=require_fresh
            )
        if candidate is None:
            return None
        try:
            context = self._require_object(
                self._rpc("droid.get_context_stats", {}).result,
                "target context",
            )
        except FactoryDroidError as exc:
            with self._state_lock:
                self._last_error = exc.code
            return None
        with self._state_lock:
            current = self._reviewed_target_locked(
                require_fresh=False
            )
            if (
                current is None
                or current.session_id != candidate.session_id
                or current.binding_id != candidate.binding_id
                or current.capability_generation
                != candidate.capability_generation
                or current.cwd != candidate.cwd
            ):
                return None
            target = _DroidSessionTarget(
                session_id=current.session_id,
                binding_id=current.binding_id,
                capability_generation=current.capability_generation,
                cwd=current.cwd,
                observed_monotonic=time.monotonic(),
            )
            self._session_target = target
            self._context_stats = _sanitize(context)
            return target

    def _validated_target_session(
        self,
        value: Any,
    ) -> _DroidSessionTarget:
        target_id = _safe_identifier(value)
        if target_id is None:
            raise FactoryDroidUnsupportedOperation(
                "target_session_invalid"
            )
        with self._state_lock:
            target = self._reviewed_target_locked(
                require_fresh=True
            )
            if target is None or target.session_id != target_id:
                raise FactoryDroidStaleControl(
                    "target_session_stale_or_not_owned"
                )
            return target

    def _revalidated_target_session(
        self,
        value: Any,
    ) -> _DroidSessionTarget:
        target = self._validated_target_session(value)
        discovered = self._discover_reviewed_target(
            require_fresh=True
        )
        if (
            discovered is None
            or discovered.session_id != target.session_id
            or discovered.binding_id != target.binding_id
            or discovered.capability_generation
            != target.capability_generation
            or discovered.cwd != target.cwd
        ):
            raise FactoryDroidStaleControl(
                "target_session_stale_or_not_owned"
            )
        return discovered

    def _ensure_snapshot_session(
        self,
        session_id: str,
        session_truth: Mapping[str, Any] | None,
    ) -> None:
        safe_session_id = _native_control_session_id(
            session_id,
            session_truth,
            binding_id=self.binding.binding_id,
        )
        expected_cwd = None
        if (
            isinstance(session_truth, Mapping)
            and session_truth.get("cwd") is not None
        ):
            expected_cwd = _safe_cwd(session_truth["cwd"])
        with self._state_lock:
            transport = self._transport
            current = self._current_session_id
            current_cwd = self._cwd
            healthy = transport is not None and transport.healthy
        if healthy and current == safe_session_id:
            if expected_cwd is not None and current_cwd != expected_cwd:
                raise FactoryDroidUnavailable("session_cwd_mismatch")
            return
        self.attach_session(safe_session_id, expected_cwd=expected_cwd)

    def _validate_execution_context(
        self,
        binding_id: str,
        generation: int,
        session_id: str | None,
        operation_id: str,
    ) -> None:
        if binding_id != self.binding.binding_id:
            raise FactoryDroidStaleControl("binding_id_stale")
        if generation != self._capability_generation:
            raise FactoryDroidStaleControl("capability_generation_stale")
        if operation_id.startswith("session."):
            if (
                session_id is None
                or self._current_session_id is None
                or not _droid_session_id_matches(
                    session_id,
                    self._current_session_id,
                )
            ):
                raise FactoryDroidStaleControl("session_id_stale")
            if self._transport is None or not self._transport.healthy:
                raise FactoryDroidStaleControl("provider_connection_stale")

    def _execute_uncached(
        self,
        operation_id: str,
        payload: dict[str, Any],
        session_id: str | None,
        client_action_id: str,
    ) -> ProviderOperationResult:
        if operation_id == "provider.auth.read":
            return self._local_result(
                operation_id,
                client_action_id,
                {
                    "authenticated": self.launch_evidence.auth_source is not None,
                    "source": self.launch_evidence.auth_source,
                },
            )
        if operation_id == "provider.config.read":
            with self._state_lock:
                public = {
                    "mode": self._settings.get("interactionMode"),
                    "autonomy": self._settings.get("autonomyLevel"),
                    "model": self._settings.get("modelId"),
                    "reasoning": self._settings.get("reasoningEffort"),
                    "available_models": list(self._models),
                    "cwd": str(self._cwd) if self._cwd is not None else None,
                    "sandbox": _sanitize(self._settings.get("sandbox")),
                    "worktree": self._worktree,
                    "mission": self._mission,
                }
            return self._local_result(
                operation_id, client_action_id, public
            )
        if operation_id == "provider.commands.read":
            with self._state_lock:
                commands = [
                    {
                        "name": item.get("name"),
                        "description": item.get("description"),
                        "is_executable": bool(item.get("isExecutable")),
                    }
                    for item in self._commands
                    if isinstance(item, Mapping)
                ]
            return self._local_result(
                operation_id, client_action_id, {"commands": commands}
            )
        if operation_id == "provider.mcp.read":
            mcp = self._require_object(
                self._rpc("droid.list_mcp_servers", {}).result,
                "mcp servers",
            )
            mcp_tools = self._require_object(
                self._rpc("droid.list_mcp_tools", {}).result,
                "mcp tools",
            )
            with self._state_lock:
                tools = list(self._tools)
                self._mcp_servers = _sanitize(mcp)
                self._mcp_tools = _sanitize(mcp_tools.get("tools", []))
            public = {
                "servers": _sanitize(mcp.get("servers", [])),
                "summary": _sanitize(mcp.get("summary", {})),
                "mcp_tools": _sanitize(mcp_tools.get("tools", [])),
                "tools": tools,
            }
            return self._local_result(
                operation_id, client_action_id, public
            )
        if operation_id == "provider.usage.read":
            with self._state_lock:
                usage = self._usage
            return self._local_result(
                operation_id,
                client_action_id,
                {"token_usage": usage},
            )
        if operation_id == "provider.diagnostics.read":
            with self._state_lock:
                has_current_session = self._current_session_id is not None
            context = (
                self._require_object(
                    self._rpc("droid.get_context_stats", {}).result,
                    "context stats",
                )
                if has_current_session
                else None
            )
            breakdown = (
                self._require_object(
                    self._rpc("droid.get_context_breakdown", {}).result,
                    "context breakdown",
                )
                if has_current_session
                else None
            )
            with self._state_lock:
                public = {
                    "protocol_version": DROID_PROTOCOL_VERSION,
                    "read_only": self._is_read_only(),
                    "session_id": self._current_session_id,
                    "cwd": str(self._cwd) if self._cwd is not None else None,
                    "sandbox": _sanitize(self._settings.get("sandbox")),
                    "context": _sanitize(context),
                    "context_breakdown": _sanitize(breakdown),
                    "worktree": self._worktree,
                    "mission": self._mission,
                    "pending_approvals": len(self._pending_approvals),
                    "pending_questionnaires": len(self._pending_questionnaires),
                    "working_state": self._working_state,
                    "last_error": self._last_error,
                }
            return self._local_result(
                operation_id, client_action_id, public
            )
        if session_id is None:
            raise FactoryDroidStaleControl("session_required")
        if operation_id in {
            "session.prompt.send",
            "session.turn.steer",
        }:
            field = (
                "prompt"
                if operation_id == "session.prompt.send"
                else "instruction"
            )
            text = payload.get(field)
            if not isinstance(text, str) or not text.strip():
                raise FactoryDroidUnsupportedOperation(
                    "message_text_invalid"
                )
            params: dict[str, Any] = {
                "messageId": client_action_id,
                "text": text,
            }
            if operation_id == "session.turn.steer":
                params["queuePlacement"] = "end_of_turn"
            with self._state_lock:
                self._working_state = "running"
            call = self._rpc("droid.add_user_message", params)
            return self._rpc_result(
                operation_id,
                call,
                OperationResultStatus.APPLIED,
                {"accepted": True, "session_id": session_id},
            )
        if operation_id == "session.turn.interrupt":
            call = self._rpc("droid.interrupt_session", {})
            return self._rpc_result(
                operation_id,
                call,
                OperationResultStatus.APPLIED,
                {"interrupted": True},
            )
        if operation_id == "session.terminate":
            call = self._rpc(
                "droid.close_session", {"reason": "other"}
            )
            result = self._rpc_result(
                operation_id,
                call,
                OperationResultStatus.APPLIED,
                {"terminated": True},
            )
            self.close()
            return result
        if operation_id == "session.resume":
            target = self._revalidated_target_session(
                payload.get("target_session")
            )
            self.attach_session(
                target.session_id,
                expected_cwd=target.cwd,
            )
            return self._local_result(
                operation_id,
                client_action_id,
                {
                    "resumed": True,
                    "session_id": session_id,
                    "target_session_id": target.session_id,
                },
            )
        if operation_id == "session.fork":
            target = self._revalidated_target_session(
                payload.get("target_session")
            )
            call = self._rpc(
                "droid.fork_session",
                {},
                request_id=_droid_operation_id(
                    self.binding.binding_id,
                    self._capability_generation,
                    client_action_id,
                ),
            )
            result = self._require_object(call.result, "fork result")
            new_id = _safe_identifier(result.get("newSessionId"))
            if new_id is None:
                raise FactoryDroidProtocolError(
                    "fork_session_id_missing"
                )
            return self._rpc_result(
                operation_id,
                call,
                OperationResultStatus.APPLIED,
                {
                    "source_session_id": target.session_id,
                    "new_session_id": new_id,
                },
            )
        if operation_id == "session.compact":
            call = self._rpc("droid.compact_session", {})
            result = self._require_object(call.result, "compact result")
            new_id = _safe_identifier(result.get("newSessionId"))
            if new_id is None:
                raise FactoryDroidProtocolError(
                    "compact_session_id_missing"
                )
            return self._rpc_result(
                operation_id,
                call,
                OperationResultStatus.APPLIED,
                {
                    "new_session_id": new_id,
                    "removed_count": result.get("removedCount"),
                },
            )
        if operation_id == "session.model.set":
            model = payload.get("model")
            with self._state_lock:
                available = {item["id"] for item in self._models}
            if model not in available:
                raise FactoryDroidUnsupportedOperation(
                    "model_not_advertised"
                )
            call = self._update_settings({"modelId": model})
            return self._rpc_result(
                operation_id,
                call,
                OperationResultStatus.APPLIED,
                {"model": model},
            )
        if operation_id == "session.reasoning.set":
            reasoning = payload.get("reasoning")
            if reasoning not in self._reasoning_choices():
                raise FactoryDroidUnsupportedOperation(
                    "reasoning_not_advertised"
                )
            provider_reasoning = (
                "none" if reasoning == "off" else reasoning
            )
            call = self._update_settings(
                {"reasoningEffort": provider_reasoning}
            )
            return self._rpc_result(
                operation_id,
                call,
                OperationResultStatus.APPLIED,
                {"reasoning": reasoning},
            )
        if operation_id == "session.permissions.set":
            permission = payload.get("permissions")
            if permission == "read-only":
                params = {
                    "interactionMode": _READ_ONLY_INTERACTION_MODE,
                    "autonomyLevel": _READ_ONLY_AUTONOMY_LEVEL,
                }
            elif permission == "auto-low":
                with self._state_lock:
                    sandbox = self._settings.get("sandbox")
                    cwd = self._cwd
                if (
                    not isinstance(sandbox, Mapping)
                    or sandbox.get("enabled") is not True
                    or cwd is None
                    or not cwd.is_dir()
                ):
                    raise FactoryDroidUnavailable(
                        "write_elevation_canary_failed"
                    )
                params = {
                    "interactionMode": "auto",
                    "autonomyLevel": "low",
                }
            else:
                raise FactoryDroidUnsupportedOperation(
                    "permission_mode_not_advertised"
                )
            call = self._update_settings(params)
            if permission == "read-only":
                self._cancel_pending_approvals(
                    "permissions_lowered_to_read_only"
                )
            self._verify_capability_canaries()
            return self._rpc_result(
                operation_id,
                call,
                OperationResultStatus.APPLIED,
                {"permissions": permission},
            )
        if operation_id == "session.approval.decide":
            return self._decide_approval(payload)
        if operation_id == "session.question.answer":
            return self._answer_questionnaire(payload)
        raise FactoryDroidUnsupportedOperation(
            "unreviewed_pairling_operation"
        )

    def _cancel_pending_approvals(self, reason: str) -> None:
        with self._state_lock:
            pending = tuple(self._pending_approvals.values())
            transport = self._transport
        if not pending:
            return
        if transport is None or not transport.healthy:
            raise FactoryDroidStaleControl(
                "approval_transport_stale"
            )
        for approval in pending:
            transport.send_result(
                approval.approval_id,
                {"selectedOption": "cancel"},
            )
        with self._state_lock:
            for approval in pending:
                self._pending_approvals.pop(
                    approval.approval_id, None
                )
            self._append_event_locked(
                "approvals_cancelled",
                {
                    "reason": reason,
                    "approval_ids": [
                        approval.approval_id
                        for approval in pending
                    ],
                },
            )

    def _decide_approval(
        self, payload: Mapping[str, Any]
    ) -> ProviderOperationResult:
        approval_id = payload.get("approval_id")
        decision = payload.get("decision")
        if (
            not isinstance(approval_id, str)
            or decision not in _SAFE_PERMISSION_DECISIONS
        ):
            raise FactoryDroidUnsupportedOperation(
                "approval_decision_invalid"
            )
        with self._state_lock:
            approval = self._pending_approvals.get(approval_id)
            transport = self._transport
            if approval is None:
                raise FactoryDroidStaleControl(
                    "approval_absent_or_resolved"
                )
            if (
                approval.session_id != self._current_session_id
                or approval.capability_generation
                != self._capability_generation
            ):
                raise FactoryDroidStaleControl(
                    "approval_correlation_stale"
                )
            if decision not in approval.offered:
                raise FactoryDroidUnsupportedOperation(
                    "approval_decision_not_offered"
                )
            self._pending_approvals.pop(approval_id)
        if transport is None or not transport.healthy:
            raise FactoryDroidStaleControl("approval_transport_stale")
        try:
            transport.send_result(
                approval_id, {"selectedOption": decision}
            )
        except BaseException as exc:
            raise FactoryDroidStaleControl(
                "approval_response_outcome_unknown"
            ) from exc
        return ProviderOperationResult(
            "session.approval.decide",
            approval_id,
            OperationResultStatus.APPLIED,
            {"approval_id": approval_id, "decision": decision},
            self.provider_cursor,
        )

    def _answer_questionnaire(
        self, payload: Mapping[str, Any]
    ) -> ProviderOperationResult:
        request_id = payload.get("question_request_id")
        decision = payload.get("decision")
        submitted = payload.get("answers")
        if (
            not isinstance(request_id, str)
            or decision not in {"accept", "decline", "cancel"}
            or (decision == "accept" and not isinstance(submitted, list))
        ):
            raise FactoryDroidUnsupportedOperation(
                "questionnaire_answer_invalid"
            )
        with self._state_lock:
            pending = self._pending_questionnaires.get(request_id)
            transport = self._transport
            if pending is None:
                raise FactoryDroidStaleControl(
                    "questionnaire_absent_or_resolved"
                )
            if (
                pending.session_id != self._current_session_id
                or pending.capability_generation
                != self._capability_generation
            ):
                raise FactoryDroidStaleControl(
                    "questionnaire_correlation_stale"
                )
            if decision != "accept":
                self._pending_questionnaires.pop(request_id)
                if transport is None or not transport.healthy:
                    raise FactoryDroidStaleControl(
                        "questionnaire_transport_stale"
                    )
                try:
                    transport.send_result(request_id, {"cancelled": True})
                except BaseException as exc:
                    raise FactoryDroidStaleControl(
                        "questionnaire_response_outcome_unknown"
                    ) from exc
                return ProviderOperationResult(
                    "session.question.answer",
                    request_id,
                    OperationResultStatus.APPLIED,
                    {
                        "question_request_id": request_id,
                        "decision": decision,
                        "answer_count": 0,
                    },
                    self.provider_cursor,
                )
            assert isinstance(submitted, list)
            expected_by_index = {
                question["index"]: question
                for question in pending.questions
            }
            answers: list[dict[str, Any]] = []
            seen_indexes: set[int] = set()
            for item in submitted:
                if not isinstance(item, Mapping):
                    raise FactoryDroidUnsupportedOperation(
                        "questionnaire_answer_invalid"
                    )
                index = item.get("index")
                expected = expected_by_index.get(index)
                answer = item.get("answer")
                if (
                    expected is None
                    or index in seen_indexes
                    or item.get("topic") != expected["topic"]
                    or item.get("question") != expected["question"]
                    or item.get("options") != expected["options"]
                    or not isinstance(answer, str)
                    or not answer.strip()
                ):
                    raise FactoryDroidUnsupportedOperation(
                        "questionnaire_answer_invalid"
                    )
                seen_indexes.add(index)
                answers.append(
                    {
                        "index": index,
                        "question": expected["question"],
                        "answer": answer.strip(),
                    }
                )
            if seen_indexes != set(expected_by_index):
                raise FactoryDroidUnsupportedOperation(
                    "questionnaire_incomplete"
                )
            self._pending_questionnaires.pop(request_id)
        if transport is None or not transport.healthy:
            raise FactoryDroidStaleControl(
                "questionnaire_transport_stale"
            )
        try:
            transport.send_result(request_id, {"answers": answers})
        except BaseException as exc:
            raise FactoryDroidStaleControl(
                "questionnaire_response_outcome_unknown"
            ) from exc
        with self._state_lock:
            self._working_state = "running"
            self._append_event_locked(
                "questionnaire_answered",
                {
                    "question_request_id": request_id,
                    "answer_count": len(answers),
                },
            )
        return ProviderOperationResult(
            "session.question.answer",
            request_id,
            OperationResultStatus.APPLIED,
            {
                "question_request_id": request_id,
                "decision": "accept",
                "answer_count": len(answers),
            },
            self.provider_cursor,
        )

    def _local_result(
        self,
        operation_id: str,
        action_id: str,
        public: dict[str, Any],
    ) -> ProviderOperationResult:
        return ProviderOperationResult(
            operation_id,
            f"pairling:{action_id}",
            OperationResultStatus.APPLIED,
            _sanitize(public),
            self.provider_cursor,
        )

    def _rpc_result(
        self,
        operation_id: str,
        call: _RpcResult,
        status: OperationResultStatus,
        public: dict[str, Any],
    ) -> ProviderOperationResult:
        return ProviderOperationResult(
            operation_id,
            call.request_id,
            status,
            _sanitize(public),
            self.provider_cursor,
        )

    def _append_model_choices(
        self,
        operations: list[str],
        values: list[ControlValue],
        choices: list[ControlChoices],
    ) -> None:
        if "session.model.set" in operations:
            model_choices = tuple(
                ControlChoice(item["id"], item["displayName"])
                for item in self._models
            )
            choices.append(
                ControlChoices(
                    "session.model.set", "model", model_choices
                )
            )
            current = self._settings.get("modelId")
            if current in {item["id"] for item in self._models}:
                values.append(
                    ControlValue(
                        "session.model.set", "model", current
                    )
                )
        if "session.reasoning.set" in operations:
            reasoning_choices = tuple(
                ControlChoice(
                    item,
                    item.replace("xhigh", "Extra high").title(),
                )
                for item in self._reasoning_choices()
            )
            choices.append(
                ControlChoices(
                    "session.reasoning.set",
                    "reasoning",
                    reasoning_choices,
                )
            )
            current = self._settings.get("reasoningEffort")
            public_current = "off" if current == "none" else current
            if public_current in self._reasoning_choices():
                values.append(
                    ControlValue(
                        "session.reasoning.set",
                        "reasoning",
                        public_current,
                    )
                )

    def _reasoning_choices(self) -> tuple[str, ...]:
        current_model = self._settings.get("modelId")
        for model in self._models:
            if model.get("id") == current_model:
                return tuple(
                    item
                    for item in model.get(
                        "supportedReasoningEfforts", ()
                    )
                    if item in _ALLOWED_REASONING
                )
        return ()

    def _append_permission_choices(
        self,
        operations: list[str],
        values: list[ControlValue],
        choices: list[ControlChoices],
    ) -> None:
        if "session.permissions.set" not in operations:
            return
        permission_choices = [
            ControlChoice("read-only", "Read-only")
        ]
        sandbox = self._settings.get("sandbox")
        if (
            isinstance(sandbox, Mapping)
            and sandbox.get("enabled") is True
            and self._cwd is not None
        ):
            permission_choices.append(
                ControlChoice("auto-low", "Low-risk writes")
            )
        choices.append(
            ControlChoices(
                "session.permissions.set",
                "permissions",
                tuple(permission_choices),
            )
        )
        current = (
            "auto-low"
            if self._settings.get("interactionMode") == "auto"
            and self._settings.get("autonomyLevel") == "low"
            else "read-only"
        )
        values.append(
            ControlValue(
                "session.permissions.set",
                "permissions",
                current,
            )
        )

    def _append_approval_choices(
        self,
        operations: list[str],
        choices: list[ControlChoices],
    ) -> None:
        approvals = tuple(
            ControlChoice(
                item.approval_id,
                "Pending Factory Droid permission request",
            )
            for item in self._pending_approvals.values()
        )
        if not approvals:
            return
        operations.append("session.approval.decide")
        offered = {
            decision
            for item in self._pending_approvals.values()
            for decision in item.offered
        }
        decisions = tuple(
            ControlChoice(
                item,
                "Cancel" if item == "cancel" else "Allow once",
            )
            for item in _SAFE_PERMISSION_DECISIONS
            if item in offered
        )
        choices.append(
            ControlChoices(
                "session.approval.decide",
                "approval_id",
                approvals,
            )
        )
        choices.append(
            ControlChoices(
                "session.approval.decide",
                "decision",
                decisions,
            )
        )

    def _append_questionnaire_values(
        self,
        operations: list[str],
        values: list[ControlValue],
        choices: list[ControlChoices],
    ) -> None:
        pending = tuple(self._pending_questionnaires.values())
        if not pending:
            return
        operations.append("session.question.answer")
        choices.append(
            ControlChoices(
                "session.question.answer",
                "decision",
                (
                    ControlChoice("accept", "Answer"),
                    ControlChoice("decline", "Decline"),
                    ControlChoice("cancel", "Cancel"),
                ),
            )
        )
        choices.append(
            ControlChoices(
                "session.question.answer",
                "question_request_id",
                tuple(
                    ControlChoice(
                        item.request_id,
                        "Pending Factory Droid question",
                    )
                    for item in pending
                ),
            )
        )
        selected = pending[0]
        values.append(
            ControlValue(
                "session.question.answer",
                "question_request_id",
                selected.request_id,
            )
        )
        values.append(
            ControlValue(
                "session.question.answer",
                "decision",
                "accept",
            )
        )
        values.append(
            ControlValue(
                "session.question.answer",
                "answers",
                list(selected.questions),
            )
        )

    def _on_notification(self, message: dict[str, Any]) -> None:
        if message.get("method") != "droid.session_notification":
            with self._state_lock:
                self._append_event_locked(
                    "provider_extension",
                    {"notification": _sanitize(message.get("params"))},
                )
            return
        params = message.get("params")
        notification = (
            params.get("notification")
            if isinstance(params, Mapping)
            else None
        )
        if not isinstance(notification, Mapping):
            raise FactoryDroidProtocolError(
                "session_notification_invalid"
            )
        notification_type = notification.get("type")
        with self._state_lock:
            if notification_type == "droid_working_state_changed":
                state = notification.get("newState")
                if not isinstance(state, str) or not state:
                    raise FactoryDroidProtocolError(
                        "working_state_notification_invalid"
                    )
                self._working_state = state
                public_state = (
                    "idle" if state == "idle" else "running"
                )
                self._append_event_locked(
                    "lifecycle",
                    {
                        "subtype": public_state,
                        "status": public_state,
                        "provider_state": state,
                    },
                )
            elif notification_type in {
                "assistant_text_delta",
                "thinking_text_delta",
            }:
                self._append_event_locked(
                    (
                        "partial_text"
                        if notification_type
                        == "assistant_text_delta"
                        else "block_thinking"
                    ),
                    {
                        "message_id": notification.get("messageId"),
                        "block_index": notification.get("blockIndex"),
                        "role": "assistant",
                        "text": _bounded_text(
                            notification.get("textDelta", "")
                        ),
                    },
                )
            elif notification_type in {
                "assistant_text_complete",
                "thinking_text_complete",
            }:
                self._append_event_locked(
                    notification_type,
                    {
                        "message_id": notification.get("messageId"),
                        "block_index": notification.get("blockIndex"),
                    },
                )
            elif notification_type == "agent_turn_completed":
                self._append_event_locked(
                    "lifecycle",
                    {
                        "subtype": "completed",
                        "status": "completed",
                        "message_id": notification.get("messageId"),
                    },
                )
            elif notification_type == "settings_updated":
                settings = notification.get("settings")
                if not isinstance(settings, Mapping):
                    raise FactoryDroidProtocolError(
                        "settings_notification_invalid"
                    )
                self._consume_settings_update(
                    settings,
                    notification.get("requestId"),
                )
                self._append_event_locked(
                    "settings_updated",
                    {"settings": _sanitize(settings)},
                )
            elif notification_type == "session_token_usage_changed":
                usage = notification.get("tokenUsage")
                if isinstance(usage, Mapping):
                    self._usage = _sanitize(usage)
                self._append_event_locked(
                    "usage_updated", {"token_usage": self._usage}
                )
            elif notification_type == "mcp_status_changed":
                self._mcp_servers = _sanitize(
                    {
                        "servers": notification.get("servers", []),
                        "summary": notification.get("summary", {}),
                    }
                )
                self._append_event_locked(
                    "mcp_status", self._mcp_servers
                )
            elif notification_type in {
                "mission_state_changed",
                "mission_features_changed",
                "mission_progress_entry",
                "mission_worker_started",
                "mission_worker_completed",
            }:
                self._mission = {
                    **(self._mission or {}),
                    str(notification_type): _sanitize(notification),
                }
                self._append_event_locked(
                    "mission_status",
                    {
                        "event": notification_type,
                        "status": _sanitize(notification),
                    },
                )
            elif notification_type == "permission_resolved":
                request_id = _safe_identifier(
                    notification.get("requestId")
                )
                if request_id is not None:
                    self._pending_approvals.pop(request_id, None)
                self._append_event_locked(
                    "approval_resolved",
                    {
                        "approval_id": request_id,
                        "decision": notification.get(
                            "selectedOption"
                        ),
                    },
                )
            elif notification_type == "error":
                self._append_event_locked(
                    "error",
                    {
                        "error_type": notification.get("errorType"),
                        "message": _bounded_text(
                            notification.get("message", ""), 2048
                        ),
                    },
                )
            elif notification_type in {
                "tool_call",
                "tool_result",
                "tool_progress_update",
                "create_message",
                "session_compacted",
                "structured_output",
                "session_title_updated",
                "mcp_auth_required",
                "mcp_auth_completed",
            }:
                self._append_event_locked(
                    "provider_event",
                    {
                        "type": notification_type,
                        "data": _sanitize(notification),
                    },
                )
            else:
                self._append_event_locked(
                    "provider_extension",
                    {
                        "type": _bounded_text(
                            notification_type, 128
                        ),
                        "data": _sanitize(notification),
                    },
                )

    def _on_server_request(self, message: dict[str, Any]) -> None:
        request_id = _safe_identifier(message.get("id"))
        method = message.get("method")
        params = message.get("params")
        with self._state_lock:
            transport = self._transport
        if request_id is None:
            raise FactoryDroidProtocolError(
                "provider_request_id_invalid"
            )
        if transport is None:
            raise FactoryDroidDisconnected(
                "provider_request_transport_missing"
            )
        if method == "droid.request_permission":
            if not isinstance(params, Mapping):
                raise FactoryDroidProtocolError(
                    "permission_request_invalid"
                )
            with self._state_lock:
                self._record_approval_locked(request_id, params)
            return
        if method == "droid.ask_user":
            if not isinstance(params, Mapping):
                raise FactoryDroidProtocolError(
                    "ask_user_request_invalid"
                )
            with self._state_lock:
                self._record_questionnaire_locked(request_id, params)
            return
        transport.send_error(
            request_id, -32601, "Method not reviewed by Pairling"
        )
        with self._state_lock:
            self._append_event_locked(
                "provider_extension",
                {"request": "unreviewed", "handled": False},
            )

    def _record_approval_locked(
        self, request_id: str, params: Mapping[str, Any]
    ) -> None:
        if request_id in self._pending_approvals:
            raise FactoryDroidProtocolError(
                "duplicate_permission_request_id"
            )
        options = params.get("options")
        offered: list[str] = []
        if isinstance(options, list):
            for option in options:
                value = (
                    option.get("value")
                    if isinstance(option, Mapping)
                    else None
                )
                if (
                    isinstance(value, str)
                    and value in _SAFE_PERMISSION_DECISIONS
                    and value not in offered
                ):
                    offered.append(value)
        if "cancel" not in offered:
            raise FactoryDroidProtocolError(
                "permission_request_has_no_safe_cancel"
            )
        if (
            self._settings.get("interactionMode")
            == _READ_ONLY_INTERACTION_MODE
            and self._settings.get("autonomyLevel")
            == _READ_ONLY_AUTONOMY_LEVEL
        ):
            offered = ["cancel"]
        tool_uses = params.get("toolUses")
        if not isinstance(tool_uses, list):
            raise FactoryDroidProtocolError(
                "permission_tool_uses_invalid"
            )
        if not tool_uses:
            offered = ["cancel"]
        tools: list[dict[str, Any]] = []
        for item in tool_uses:
            if not isinstance(item, Mapping):
                raise FactoryDroidProtocolError(
                    "permission_tool_use_invalid"
                )
            tool_use = item.get("toolUse")
            tool_use_id = (
                _safe_identifier(tool_use.get("id"))
                if isinstance(tool_use, Mapping)
                else None
            )
            tool_name = (
                _safe_identifier(tool_use.get("name"), limit=160)
                if isinstance(tool_use, Mapping)
                else None
            )
            confirmation_type = _safe_identifier(
                item.get("confirmationType"), limit=160
            )
            if (
                tool_use_id is None
                or tool_name is None
                or confirmation_type is None
            ):
                raise FactoryDroidProtocolError(
                    "permission_tool_correlation_invalid"
                )
            details = item.get("details")
            target = (
                {
                    key: details.get(key)
                    for key in (
                        "type",
                        "filePath",
                        "fileName",
                        "toolName",
                        "serverName",
                        "impactLevel",
                    )
                    if key in details
                }
                if isinstance(details, Mapping)
                else {}
            )
            tools.append(
                {
                    "tool_use_id": tool_use_id,
                    "tool_name": tool_name,
                    "confirmation_type": confirmation_type,
                    "target": _sanitize(target),
                }
            )
        public = {
            "approval_id": request_id,
            "tools": tools,
            "decisions": offered,
        }
        self._pending_approvals[request_id] = _PendingApproval(
            request_id,
            self._current_session_id or "",
            self._capability_generation,
            tuple(offered),
        )
        self._working_state = "waiting_for_tool_confirmation"
        self._append_event_locked("approval_requested", public)

    def _record_questionnaire_locked(
        self,
        request_id: str,
        params: Mapping[str, Any],
    ) -> None:
        if request_id in self._pending_questionnaires:
            raise FactoryDroidProtocolError(
                "duplicate_ask_user_request_id"
            )
        if self._pending_questionnaires:
            raise FactoryDroidProtocolError(
                "concurrent_ask_user_unsupported"
            )
        tool_call_id = _safe_identifier(params.get("toolCallId"))
        raw_questions = params.get("questions")
        if (
            tool_call_id is None
            or not isinstance(raw_questions, list)
            or not 1 <= len(raw_questions) <= 12
        ):
            raise FactoryDroidProtocolError(
                "ask_user_request_invalid"
            )
        questions: list[dict[str, Any]] = []
        seen_indexes: set[int] = set()
        for raw in raw_questions:
            if not isinstance(raw, Mapping):
                raise FactoryDroidProtocolError(
                    "ask_user_question_invalid"
                )
            index = raw.get("index")
            topic = raw.get("topic")
            question = raw.get("question")
            options = raw.get("options")
            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or not 1 <= index <= 100
                or index in seen_indexes
                or not isinstance(topic, str)
                or len(topic) > 160
                or "\x00" in topic
                or not isinstance(question, str)
                or not question
                or len(question) > 2_000
                or "\x00" in question
                or not isinstance(options, list)
                or len(options) > 20
                or not all(
                    isinstance(option, str)
                    and bool(option)
                    and len(option) <= 512
                    and "\x00" not in option
                    for option in options
                )
            ):
                raise FactoryDroidProtocolError(
                    "ask_user_question_invalid"
                )
            seen_indexes.add(index)
            questions.append(
                {
                    "index": index,
                    "topic": topic,
                    "question": question,
                    "options": list(options),
                    "answer": "",
                }
            )
        self._pending_questionnaires[request_id] = _PendingQuestionnaire(
            request_id=request_id,
            session_id=self._current_session_id or "",
            capability_generation=self._capability_generation,
            tool_call_id=tool_call_id,
            questions=tuple(questions),
        )
        self._working_state = "waiting_for_user_input"
        self._append_event_locked(
            "questionnaire_requested",
            {
                "question_request_id": request_id,
                "tool_call_id": tool_call_id,
                "questions": questions,
            },
        )

    def _on_disconnect(self, error: BaseException) -> None:
        with self._state_lock:
            self._last_error = (
                error.code
                if isinstance(error, FactoryDroidError)
                else "provider_disconnected"
            )
            self._pending_approvals.clear()
            self._pending_questionnaires.clear()
            self._expected_settings_updates.clear()
            self._working_state = "idle"
            self._append_event_locked(
                "disconnected", {"reason": self._last_error}
            )

    def _append_event_locked(
        self, kind: str, payload: Mapping[str, Any]
    ) -> None:
        self._event_cursor += 1
        event = {
            "schema_version": 1,
            "provider_id": "droid",
            "session_id": self._current_session_id,
            "capability_generation": self._capability_generation,
            "cursor": self._event_cursor,
            "provider_cursor": self._provider_cursor_locked(),
            "observed_at": time.time(),
            "kind": kind,
            "payload": _sanitize(payload),
        }
        self._events.append(event)
        self._event_ready.notify_all()

    def _provider_cursor_locked(self) -> str:
        return (
            f"{self._capability_generation}:{self._event_cursor}:"
            f"{self.launch_evidence.launch_digest[:16]}"
        )

    def _parse_cursor(self, value: str | None) -> tuple[int, int]:
        if value is None:
            return self._capability_generation, 0
        parts = value.split(":", 2)
        if (
            len(parts) != 3
            or parts[2] != self.launch_evidence.launch_digest[:16]
        ):
            raise FactoryDroidStaleControl(
                "provider_event_cursor_invalid"
            )
        try:
            generation, cursor = int(parts[0]), int(parts[1])
        except ValueError as exc:
            raise FactoryDroidStaleControl(
                "provider_event_cursor_invalid"
            ) from exc
        if generation < 1 or cursor < 0:
            raise FactoryDroidStaleControl(
                "provider_event_cursor_invalid"
            )
        return generation, cursor

    @staticmethod
    def _action_digest(
        operation_id: str,
        payload: Mapping[str, Any],
        prepared: tuple[Any, ...],
    ) -> str:
        try:
            encoded = json.dumps(
                [operation_id, payload, len(prepared)],
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise FactoryDroidUnsupportedOperation(
                "operation_payload_not_json"
            ) from exc
        return hashlib.sha256(encoded).hexdigest()

    def _cache_action_result(
        self,
        action_id: str,
        digest: str,
        capability_generation: int,
        session_id: str | None,
        result: ProviderOperationResult,
    ) -> None:
        with self._state_lock:
            self._action_results[action_id] = (
                digest,
                capability_generation,
                session_id,
                result,
            )
            self._action_results.move_to_end(action_id)
            while len(self._action_results) > _MAX_ACTION_RESULTS:
                self._action_results.popitem(last=False)
