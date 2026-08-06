from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import stat
import subprocess
import threading
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping

from . import registry_data
from .base import (
    ProviderAdapter,
    ProviderAvailability,
    ProviderDescriptor,
    ProviderDiagnostics,
    ProviderProbeResult,
    managed_child_environment,
    resolve_executable,
)
from ._sidecar_process import close_owned_process
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

QWEN_CLI_VERSION = "0.21.4"
QWEN_SDK_VERSION = "0.1.8"
_QWEN_PACKAGE = "@qwen-code/qwen-code"
_SDK_PACKAGE = "@qwen-code/sdk"
_PROTOCOL = "pairling-qwen-sdk-v1"
_REQUIRED_METHODS = (
    "streamInput",
    "interrupt",
    "setPermissionMode",
    "setModel",
    "setEffort",
    "getContextUsage",
    "getAvailableModels",
    "getUsageInfo",
    "mcpServerStatus",
)
_SAFE_PERMISSION_MODES = ("default", "plan")
_SAFE_EFFORTS = ("low", "medium", "high", "xhigh", "max")
_MAX_LINE_BYTES = 1024 * 1024
_MAX_REQUEST_BYTES = 256 * 1024
_MAX_EVENTS = 1024
_MAX_ACTION_RESULTS = 512
_SNAPSHOT_TTL = 5.0
_VERSION_RE = re.compile(r"(?<![0-9])([0-9]+\.[0-9]+\.[0-9]+)(?![0-9])")
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+\-]{0,255}\Z")
_MANAGED_LIVE_LIFECYCLES = ("running", "waiting")
_PROVIDER_ID = "qwen_code"
_EVENT_LIFECYCLE_STATUS = {
    "session_started": "started",
    "session_ended": "ended",
    "session_failed": "failed",
    "permission_requested": "running",
    "permission_resolved": "running",
}

_FALLBACK_DESCRIPTOR = ProviderDescriptor(
    provider_id=_PROVIDER_ID,
    display_name="Qwen Code",
    kind="terminal_cli",
    builtin=True,
    docs_url="https://qwenlm.github.io/qwen-code-docs/",
    adapter_depth="standard",
)
_ENTRY = registry_data.entry_or_none(_PROVIDER_ID)


class QwenUnavailableError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class QwenRuntimeEvidence:
    node_path: Path
    node_version: str
    cli_path: Path
    cli_entry: Path
    cli_version: str
    sdk_root: Path
    sdk_entry: Path
    sdk_version: str
    sidecar_path: Path
    launch_digest: str
    capability_methods: tuple[str, ...]

    @classmethod
    def fixture(
        cls,
        *,
        cli_version: str = QWEN_CLI_VERSION,
        sdk_version: str = QWEN_SDK_VERSION,
        capability_methods: tuple[str, ...] = _REQUIRED_METHODS,
        node_path: Path | None = None,
        sdk_entry: Path | None = None,
        cli_entry: Path | None = None,
    ) -> "QwenRuntimeEvidence":
        sdk_entry = sdk_entry or Path("/nonexistent/qwen-sdk/dist/index.mjs")
        cli_entry = cli_entry or Path("/nonexistent/qwen-cli/dist/index.js")
        return cls(
            node_path=node_path or Path("/usr/bin/node"),
            node_version="22.0.0",
            cli_path=cli_entry,
            cli_entry=cli_entry,
            cli_version=cli_version,
            sdk_root=sdk_entry.parent.parent,
            sdk_entry=sdk_entry,
            sdk_version=sdk_version,
            sidecar_path=Path(__file__).with_name("qwen_sdk_sidecar.mjs"),
            launch_digest="fixture",
            capability_methods=tuple(capability_methods),
        )


@dataclass(frozen=True)
class SidecarReply:
    request_id: str
    result: dict[str, Any]


@dataclass
class _QwenSession:
    session_id: str
    cwd: str
    state: str
    permission_mode: str
    model: str | None
    effort: str | None
    models: tuple[str, ...]
    max_session_turns: int | None
    max_tool_calls: int | None
    max_subagent_depth: int | None
    config_digest: str
    generation: int


def _safe_manifest(path: Path, expected_name: str, expected_version: str, missing_code: str) -> dict[str, Any]:
    if not path.is_file():
        raise QwenUnavailableError(missing_code)
    _require_safe_regular_file(path, missing_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise QwenUnavailableError(missing_code) from exc
    if not isinstance(payload, dict) or payload.get("name") != expected_name:
        raise QwenUnavailableError(missing_code)
    if payload.get("version") != expected_version:
        code = "sdk_version_unsupported" if expected_name == _SDK_PACKAGE else "cli_version_unsupported"
        raise QwenUnavailableError(code)
    return payload


def _require_safe_regular_file(path: Path, code: str) -> None:
    try:
        info = path.stat()
    except OSError as exc:
        raise QwenUnavailableError(code) from exc
    if not stat.S_ISREG(info.st_mode) or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise QwenUnavailableError("unsafe_runtime_file")


def _find_package_root(entry: Path, package_name: str) -> Path | None:
    current = entry.resolve().parent
    for _ in range(6):
        manifest = current / "package.json"
        if manifest.is_file():
            try:
                payload = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                payload = None
            if isinstance(payload, dict) and payload.get("name") == package_name:
                return current
        if current.parent == current:
            break
        current = current.parent
    return None


def _run_version(command: list[str], code: str) -> str:
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
            stdin=subprocess.DEVNULL,
            env=managed_child_environment(),
        )
    except Exception as exc:
        raise QwenUnavailableError(code) from exc
    if proc.returncode != 0:
        raise QwenUnavailableError(code)
    text = (proc.stdout or proc.stderr or "").strip()[:160]
    match = _VERSION_RE.search(text)
    if match is None:
        raise QwenUnavailableError(code)
    return match.group(1)


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _probe_sidecar(runtime: QwenRuntimeEvidence) -> dict[str, Any]:
    request_id = str(uuid.uuid4())
    request = json.dumps({"id": request_id, "operation": "handshake", "payload": {}}, separators=(",", ":")) + "\n"
    env = managed_child_environment()
    try:
        proc = subprocess.run(
            [
                str(runtime.node_path),
                str(runtime.sidecar_path),
                "--serve",
                str(runtime.sdk_entry),
                str(runtime.cli_entry),
            ],
            input=request.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
            env=env,
        )
    except Exception as exc:
        raise QwenUnavailableError("sdk_handshake_failed") from exc
    lines = proc.stdout.splitlines()
    if not lines or len(lines[0]) > _MAX_LINE_BYTES:
        raise QwenUnavailableError("sdk_handshake_failed")
    try:
        response = json.loads(lines[0])
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise QwenUnavailableError("sdk_handshake_failed") from exc
    if (
        not isinstance(response, dict)
        or response.get("type") != "response"
        or response.get("id") != request_id
        or response.get("ok") is not True
        or not isinstance(response.get("result"), dict)
    ):
        code = response.get("error", {}).get("code") if isinstance(response, dict) else None
        raise QwenUnavailableError(code if isinstance(code, str) else "sdk_handshake_failed")
    return response["result"]


def inspect_qwen_runtime(
    *,
    qwen_path: Path,
    node_path: Path,
    sidecar_path: Path | None = None,
) -> QwenRuntimeEvidence:
    qwen_path = qwen_path.expanduser().resolve()
    node_path = node_path.expanduser().resolve()
    sidecar_path = (sidecar_path or Path(__file__).with_name("qwen_sdk_sidecar.mjs")).resolve()
    _require_safe_regular_file(qwen_path, "cli_missing")
    _require_safe_regular_file(node_path, "node_missing")
    _require_safe_regular_file(sidecar_path, "sidecar_missing")


    cli_root = _find_package_root(qwen_path, _QWEN_PACKAGE)
    if cli_root is None:
        raise QwenUnavailableError("cli_manifest_missing")
    _safe_manifest(cli_root / "package.json", _QWEN_PACKAGE, QWEN_CLI_VERSION, "cli_manifest_missing")

    sdk_candidates = (
        cli_root / "node_modules" / "@qwen-code" / "sdk",
        cli_root.parent / "sdk",
    )
    sdk_root = next((candidate for candidate in sdk_candidates if candidate.joinpath("package.json").is_file()), None)
    if sdk_root is None:
        raise QwenUnavailableError("sdk_missing")
    sdk_manifest = _safe_manifest(sdk_root / "package.json", _SDK_PACKAGE, QWEN_SDK_VERSION, "sdk_missing")
    expected_module = "./dist/index.mjs"
    exported = sdk_manifest.get("module")
    exports = sdk_manifest.get("exports")
    if isinstance(exports, dict):
        root_export = exports.get(".")
        if isinstance(root_export, dict):
            exported = root_export.get("import", exported)
        elif isinstance(root_export, str):
            exported = root_export
    if exported != expected_module:
        raise QwenUnavailableError("sdk_entry_unsupported")
    sdk_entry = (sdk_root / "dist" / "index.mjs").resolve()
    sdk_root = sdk_root.resolve()
    if sdk_root not in sdk_entry.parents:
        raise QwenUnavailableError("sdk_entry_unsafe")
    _require_safe_regular_file(sdk_entry, "sdk_entry_missing")
    cli_version = _run_version([str(qwen_path), "--version"], "cli_version_unavailable")
    if cli_version != QWEN_CLI_VERSION:
        raise QwenUnavailableError("cli_version_unsupported")
    node_version = _run_version([str(node_path), "--version"], "node_version_unavailable")
    if int(node_version.split(".", 1)[0]) < 22:
        raise QwenUnavailableError("node_version_unsupported")

    digest_payload = {
        "cli": _file_digest(qwen_path),
        "node": str(node_path),
        "sdk": _file_digest(sdk_entry),
        "sidecar": _file_digest(sidecar_path),
        "cli_version": cli_version,
        "sdk_version": QWEN_SDK_VERSION,
    }
    launch_digest = hashlib.sha256(
        json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    runtime = QwenRuntimeEvidence(
        node_path=node_path,
        node_version=node_version,
        cli_path=qwen_path,
        cli_entry=qwen_path,
        cli_version=cli_version,
        sdk_root=sdk_root.resolve(),
        sdk_entry=sdk_entry,
        sdk_version=QWEN_SDK_VERSION,
        sidecar_path=sidecar_path,
        launch_digest=launch_digest,
        capability_methods=(),
    )
    handshake = _probe_sidecar(runtime)
    methods = handshake.get("capability_methods")
    if (
        handshake.get("protocol") != _PROTOCOL
        or handshake.get("sdk_version") != QWEN_SDK_VERSION
        or handshake.get("cli_version") != QWEN_CLI_VERSION
        or not isinstance(methods, list)
        or tuple(methods) != _REQUIRED_METHODS
        or handshake.get("safe_permission_modes") != list(_SAFE_PERMISSION_MODES)
        or handshake.get("schema_output") is not False
        or handshake.get("acp_fallback") is not False
    ):
        raise QwenUnavailableError("sdk_capability_mismatch")
    return replace(runtime, capability_methods=tuple(methods))


def discover_qwen_runtime(home: Path | None = None) -> QwenRuntimeEvidence:
    home = home or Path.home()
    if _ENTRY is not None and _ENTRY.binary_candidates:
        candidates = registry_data.candidate_paths(_ENTRY, home=home)
        env_var = _ENTRY.env_override
    else:
        candidates = [home / ".local" / "bin" / "qwen", Path("/opt/homebrew/bin/qwen"), Path("/usr/local/bin/qwen")]
        env_var = "PAIRLING_QWEN_BIN"
    qwen = resolve_executable("qwen", candidates, env_var=env_var)
    if qwen is None:
        raise QwenUnavailableError("cli_missing")
    node = resolve_executable(
        "node",
        [Path("/opt/homebrew/bin/node"), Path("/usr/local/bin/node"), home / ".local" / "bin" / "node"],
    )
    if node is None:
        raise QwenUnavailableError("node_missing")
    return inspect_qwen_runtime(qwen_path=qwen.path, node_path=node.path)


class QwenSidecarClient:
    def __init__(
        self,
        runtime: QwenRuntimeEvidence,
        *,
        environment_source: Mapping[str, str] | None = None,
        provider_settings: Mapping[str, str] | None = None,
    ):
        self.runtime = runtime
        self._pending: dict[str, queue.Queue] = {}
        self._pending_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._events = deque(maxlen=_MAX_EVENTS)
        self._event_condition = threading.Condition()
        self._pending_approvals: dict[str, dict[str, str]] = {}
        self._closed_error: QwenUnavailableError | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._reader: threading.Thread | None = None
        env = managed_child_environment(
            source=environment_source,
            provider_settings=provider_settings,
        )
        try:
            process = subprocess.Popen(
                [
                    str(runtime.node_path),
                    str(runtime.sidecar_path),
                    "--serve",
                    str(runtime.sdk_entry),
                    str(runtime.cli_entry),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=env,
                cwd=str(runtime.sidecar_path.parent),
                bufsize=0,
                start_new_session=True,
            )
        except Exception as exc:
            raise QwenUnavailableError("sidecar_launch_failed") from exc
        self._process = process
        reader = threading.Thread(
            target=self._read_loop,
            args=(process,),
            name="pairling-qwen-sdk",
            daemon=True,
        )
        self._reader = reader
        try:
            reader.start()
            reply = self.request("handshake", {}, timeout=8.0)
        except BaseException:
            self.close()
            raise
        handshake = reply.result
        if (
            handshake.get("protocol") != _PROTOCOL
            or handshake.get("sdk_version") != runtime.sdk_version
            or handshake.get("cli_version") != runtime.cli_version
            or tuple(handshake.get("capability_methods") or ()) != runtime.capability_methods
            or handshake.get("safe_permission_modes") != list(_SAFE_PERMISSION_MODES)
        ):
            self.close()
            raise QwenUnavailableError("sdk_capability_mismatch")
        self.handshake = handshake

    @property
    def alive(self) -> bool:
        with self._close_lock:
            process = self._process
            return process is not None and process.poll() is None and self._closed_error is None

    @property
    def cursor(self) -> int:
        with self._event_condition:
            return int(self._events[-1]["cursor"]) if self._events else 0

    @property
    def pending_approvals(self) -> list[dict[str, str]]:
        with self._event_condition:
            return [dict(value) for _, value in sorted(self._pending_approvals.items())]

    def request(self, operation: str, payload: dict[str, Any], timeout: float = 10.0) -> SidecarReply:
        with self._close_lock:
            process = self._process
            if process is None or process.poll() is not None or self._closed_error is not None:
                raise self._closed_error or QwenUnavailableError("sidecar_closed")
        request_id = str(uuid.uuid4())
        encoded = (json.dumps(
            {"id": request_id, "operation": operation, "payload": payload},
            ensure_ascii=False,
            separators=(",", ":"),
        ) + "\n").encode("utf-8")
        if len(encoded) > _MAX_REQUEST_BYTES:
            raise QwenUnavailableError("request_too_large")
        result_queue: queue.Queue = queue.Queue(maxsize=1)
        with self._pending_lock:
            self._pending[request_id] = result_queue
        try:
            try:
                with self._write_lock:
                    if process.stdin is None:
                        raise QwenUnavailableError("sidecar_closed")
                    process.stdin.write(encoded)
                    process.stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as exc:
                self._shutdown(process, "sidecar_closed")
                raise QwenUnavailableError("sidecar_closed") from exc
            try:
                response = result_queue.get(timeout=timeout)
            except queue.Empty as exc:
                raise QwenUnavailableError("sidecar_timeout") from exc
        finally:
            with self._pending_lock:
                self._pending.pop(request_id, None)
        if isinstance(response, Exception):
            raise response
        if not isinstance(response, dict) or response.get("ok") is not True:
            error = response.get("error") if isinstance(response, dict) else None
            code = error.get("code") if isinstance(error, dict) else None
            raise QwenUnavailableError(code if isinstance(code, str) else "provider_error")
        result = response.get("result")
        if not isinstance(result, dict):
            raise QwenUnavailableError("invalid_sidecar_response")
        return SidecarReply(request_id, result)

    def wait_for_event(
        self,
        event_type: str,
        *,
        session_id: str,
        after_cursor: int = 0,
        timeout: float = 5.0,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        with self._event_condition:
            while True:
                for event in self._events:
                    if (
                        event["cursor"] > after_cursor
                        and event["event_type"] == event_type
                        and event["session_id"] == session_id
                    ):
                        return dict(event)
                if self._closed_error is not None:
                    raise self._closed_error
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise QwenUnavailableError("event_timeout")
                self._event_condition.wait(remaining)

    def poll_events(self, after_cursor: int = 0) -> list[dict[str, Any]]:
        with self._event_condition:
            return [dict(event) for event in self._events if event["cursor"] > after_cursor]

    def close(self) -> None:
        self._shutdown(None, "sidecar_closed")

    def _read_loop(self, process: subprocess.Popen[bytes]) -> None:
        stdout = process.stdout
        if stdout is None:
            self._fail_all("sidecar_closed")
            self._shutdown(process, "sidecar_closed")
            return
        try:
            while True:
                line = stdout.readline(_MAX_LINE_BYTES + 1)
                if not line:
                    break
                if len(line) > _MAX_LINE_BYTES or not line.endswith(b"\n"):
                    self._fail_all("sidecar_protocol_error")
                    return
                try:
                    message = json.loads(line)
                except (UnicodeError, json.JSONDecodeError):
                    self._fail_all("sidecar_protocol_error")
                    return
                if not isinstance(message, dict):
                    self._fail_all("sidecar_protocol_error")
                    return
                if message.get("type") == "response":
                    request_id = message.get("id")
                    with self._pending_lock:
                        target = self._pending.get(request_id) if isinstance(request_id, str) else None
                    if target is not None:
                        try:
                            target.put_nowait(message)
                        except queue.Full:
                            pass
                elif message.get("type") == "event":
                    self._record_event(message)
                else:
                    self._fail_all("sidecar_protocol_error")
                    return
        finally:
            self._shutdown(process, "sidecar_closed")

    def _record_event(self, message: dict[str, Any]) -> None:
        required = {"cursor", "event_id", "session_id", "provider", "event_type", "observed_at", "payload"}
        if (
            not required.issubset(message)
            or message.get("provider") != _PROVIDER_ID
            or not isinstance(message.get("cursor"), int)
            or not isinstance(message.get("event_id"), str)
            or not isinstance(message.get("session_id"), str)
            or not isinstance(message.get("event_type"), str)
            or not isinstance(message.get("payload"), dict)
        ):
            self._fail_all("sidecar_protocol_error")
            return
        event = {key: message[key] for key in required}
        with self._event_condition:
            self._events.append(event)
            payload = event["payload"]
            if event["event_type"] == "permission_requested":
                approval_id = payload.get("approval_id")
                tool_name = payload.get("tool_name")
                if isinstance(approval_id, str) and isinstance(tool_name, str):
                    self._pending_approvals[approval_id] = {
                        "approval_id": approval_id,
                        "session_id": event["session_id"],
                        "tool_name": tool_name,
                    }
            elif event["event_type"] == "permission_resolved":
                approval_id = payload.get("approval_id")
                if isinstance(approval_id, str):
                    self._pending_approvals.pop(approval_id, None)
            self._event_condition.notify_all()

    def _fail_all(self, code: str) -> None:
        error = QwenUnavailableError(code)
        with self._event_condition:
            if self._closed_error is None:
                self._closed_error = error
            self._event_condition.notify_all()
        with self._pending_lock:
            targets = list(self._pending.values())
        for target in targets:
            try:
                target.put_nowait(error)
            except queue.Full:
                pass

    def _shutdown(self, expected: subprocess.Popen[bytes] | None, code: str) -> None:
        with self._close_lock:
            process = self._process
            reader = self._reader
            if expected is not None and process is not expected:
                process = None
            elif process is not None:
                self._process = None
        self._fail_all(code)
        if process is not None:
            close_owned_process(process, reader=reader, process_group=True)
        elif reader is not None and reader is not threading.current_thread() and reader.ident is not None:
            reader.join(timeout=1)
        with self._close_lock:
            if self._reader is reader:
                self._reader = None


class QwenControlDriver:
    requires_exact_event_identity = True

    def __init__(
        self,
        binding: ProviderControlBinding,
        runtime: QwenRuntimeEvidence | None,
        *,
        client: Any | None = None,
        blocked_reason: str | None = None,
    ):
        self.binding = binding
        self.runtime = runtime
        self._blocked_reason = blocked_reason
        self._sessions: dict[str, _QwenSession] = {}
        self._generation = 1
        self._lock = threading.RLock()
        self._last_event_cursor = 0
        self._validated_snapshots: dict[
            str,
            tuple[str, int, str, frozenset[str], float],
        ] = {}
        self._action_results: OrderedDict[
            tuple[int, str],
            tuple[str, str | None, ProviderOperationResult],
        ] = OrderedDict()
        if blocked_reason is not None or runtime is None:
            self._client = None
        else:
            try:
                self._client = client or QwenSidecarClient(runtime)
            except QwenUnavailableError as exc:
                self._client = None
                self._blocked_reason = exc.code

    def launch_session(
        self,
        *,
        cwd: str | Path | None = None,
        project: str | Path | None = None,
        title: str | None = None,
        first_prompt: str | None = None,
        permission_mode: str = "default",
        model: str | None = None,
        effort: str | None = None,
        max_session_turns: int | None = None,
        max_tool_calls: int | None = None,
        max_subagent_depth: int | None = None,
        resume_session_id: str | None = None,
        fork: bool = False,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        del title
        client = self._require_client()
        if permission_mode not in _SAFE_PERMISSION_MODES:
            raise ValueError("unsafe Qwen permission mode")
        if effort is not None and effort not in _SAFE_EFFORTS:
            raise ValueError("unsupported Qwen reasoning effort")
        if model is not None and _MODEL_RE.fullmatch(model) is None:
            raise ValueError("invalid Qwen model")
        if first_prompt == "":
            first_prompt = None
        if first_prompt is not None and (not isinstance(first_prompt, str) or len(first_prompt) > 200_000):
            raise ValueError("invalid Qwen prompt")
        if cwd is not None and project is not None:
            raise ValueError("Qwen launch root is ambiguous")
        launch_root = project if project is not None else cwd
        if launch_root is None:
            raise ValueError("Qwen launch root is required")
        canonical_cwd = Path(launch_root).expanduser().resolve(strict=True)
        if not canonical_cwd.is_dir():
            raise ValueError("Qwen cwd must be a directory")
        for value, maximum, name in (
            (max_session_turns, 10_000, "max_session_turns"),
            (max_tool_calls, 100_000, "max_tool_calls"),
            (max_subagent_depth, 100, "max_subagent_depth"),
        ):
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > maximum):
                raise ValueError(f"invalid Qwen {name}")
        if resume_session_id is not None:
            _require_uuid(resume_session_id, "resume session")
        session_id = session_id or str(uuid.uuid4())
        _require_uuid(session_id, "session")
        payload: dict[str, Any] = {
            "session_id": session_id,
            "cwd": str(canonical_cwd),
            "permission_mode": permission_mode,
            "sandbox": True,
            "safe_mode": True,
        }
        for key, value in (
            ("first_prompt", first_prompt),
            ("model", model),
            ("effort", effort),
            ("max_session_turns", max_session_turns),
            ("max_tool_calls", max_tool_calls),
            ("max_subagent_depth", max_subagent_depth),
            ("resume_session_id", resume_session_id),
        ):
            if value is not None:
                payload[key] = value
        if fork:
            payload["fork"] = True
        config_digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        try:
            reply = client.request("session.start", payload, timeout=40.0)
        except QwenUnavailableError as exc:
            if exc.code == "session_initialize_failed":
                self._blocked_reason = "auth_or_session_initialization_failed"
            raise
        if (
            reply.result.get("session_id") != session_id
            or reply.result.get("permission_mode") != permission_mode
        ):
            self._blocked_reason = "session_identity_mismatch"
            client.close()
            raise QwenUnavailableError("session_identity_mismatch")
        models = _model_tuple(reply.result.get("models"))
        with self._lock:
            self._generation += 1
            self._blocked_reason = None
            self._sessions[session_id] = _QwenSession(
                session_id=session_id,
                cwd=str(canonical_cwd),
                state="live",
                permission_mode=permission_mode,
                model=model,
                effort=effort,
                models=models,
                max_session_turns=max_session_turns,
                max_tool_calls=max_tool_calls,
                max_subagent_depth=max_subagent_depth,
                config_digest=config_digest,
                generation=self._generation,
            )
            generation = self._generation
        return {
            "session_id": session_id,
            "native_session_id": session_id,
            "capability_generation": generation,
            "provider_operation_id": reply.request_id,
            "provider_cursor": _session_event_cursor(session_id, 0),
            "provider_id": self.binding.provider_id,
            "binding_id": self.binding.binding_id,
            "provider_version": self.binding.provider_version,
            "provider_channel": self.binding.provider_channel,
            "models": list(models),
            "launch_config_digest": config_digest,
        }

    def snapshot(
        self,
        *,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderControlSnapshot:
        with self._lock:
            self._sync_session_events()
            now = time.time()
            blocked = self._blocked_reason
            client = self._client
            if blocked is None and (client is None or not client.alive):
                blocked = "sidecar_unavailable"
            native_id = _native_session_id(session_id)
            session = (
                self._sessions.get(native_id)
                if native_id is not None
                else None
            )
            operations: list[str] = []
            values: list[ControlValue] = []
            choices: list[ControlChoices] = []
            if blocked is None and session_id is None:
                if session_truth is not None:
                    blocked = "provider_snapshot_cannot_use_session_truth"
            elif blocked is None and session is None:
                blocked = "session_not_driver_owned"
            elif blocked is None and not self._exact_session_truth(
                session_id,
                session_truth,
                session,
            ):
                blocked = "session_truth_mismatch"
            elif blocked is None and session.state != "live":
                blocked = "session_not_live"
            if blocked is None and session is not None and session_id is not None:
                operations.extend((
                    "provider.config.read",
                    "provider.mcp.read",
                    "provider.usage.read",
                    "session.prompt.send",
                    "session.turn.steer",
                    "session.turn.interrupt",
                    "session.terminate",
                    "session.reasoning.set",
                    "session.permissions.set",
                ))
                resume_targets = tuple(
                    target
                    for target in sorted(
                        self._sessions.values(),
                        key=lambda item: item.session_id,
                    )
                    if target.cwd == session.cwd
                    and target.state in {"ended", "failed"}
                )
                if resume_targets:
                    operations.append("session.resume")
                    choices.append(
                        ControlChoices(
                            "session.resume",
                            "target_session",
                            tuple(
                                ControlChoice(
                                    _qualified_session_id(target.session_id),
                                    f"Qwen session {target.session_id[:12]}",
                                )
                                for target in resume_targets
                            ),
                        )
                    )
                operations.append("session.fork")
                choices.append(
                    ControlChoices(
                        "session.fork",
                        "target_session",
                        (
                            ControlChoice(
                                session_id,
                                f"Qwen session {session.session_id[:12]}",
                            ),
                        ),
                    )
                )
                if session.models:
                    operations.append("session.model.set")
                    choices.append(ControlChoices(
                        "session.model.set",
                        "model",
                        tuple(
                            ControlChoice(model, model)
                            for model in session.models
                        ),
                    ))
                    if session.model in session.models:
                        values.append(
                            ControlValue(
                                "session.model.set",
                                "model",
                                session.model,
                            )
                        )
                choices.extend((
                    ControlChoices(
                        "session.reasoning.set",
                        "reasoning",
                        tuple(
                            ControlChoice(value, value)
                            for value in _SAFE_EFFORTS
                        ),
                    ),
                    ControlChoices(
                        "session.permissions.set",
                        "permissions",
                        (
                            ControlChoice(
                                "default",
                                "Ask before tool mutations",
                            ),
                            ControlChoice("plan", "Read-only planning"),
                        ),
                    ),
                ))
                if session.effort in _SAFE_EFFORTS:
                    values.append(
                        ControlValue(
                            "session.reasoning.set",
                            "reasoning",
                            session.effort,
                        )
                    )
                values.append(
                    ControlValue(
                        "session.permissions.set",
                        "permissions",
                        session.permission_mode,
                    )
                )
                approvals = [
                    item
                    for item in (
                        client.pending_approvals
                        if client is not None
                        else []
                    )
                    if item.get("session_id") == session.session_id
                ]
                if approvals:
                    operations.append("session.approval.decide")
                    choices.extend((
                        ControlChoices(
                            "session.approval.decide",
                            "approval_id",
                            tuple(
                                ControlChoice(
                                    item["approval_id"],
                                    item["tool_name"][:160],
                                )
                                for item in approvals
                            ),
                        ),
                        ControlChoices(
                            "session.approval.decide",
                            "decision",
                            (
                                ControlChoice("allow", "Allow once"),
                                ControlChoice("deny", "Deny"),
                            ),
                        ),
                    ))
                identity = ProviderSessionIdentity(
                    self.binding.provider_id,
                    session_id,
                    self.binding.binding_id,
                    session.generation,
                )
                values.extend(
                    ControlValue(operation_id, "session", identity)
                    for operation_id in operations
                    if operation_id.startswith("session.")
                )
                self._validated_snapshots[session_id] = (
                    session.session_id,
                    session.generation,
                    session.cwd,
                    frozenset(operations),
                    now + _SNAPSHOT_TTL,
                )
            elif session_id is not None:
                self._validated_snapshots.pop(session_id, None)
            generation = (
                session.generation
                if session is not None
                else self._generation
            )
            return ProviderControlSnapshot(
                provider_id=self.binding.provider_id,
                provider_version=self.binding.provider_version,
                provider_channel=self.binding.provider_channel,
                binding_id=self.binding.binding_id,
                capability_generation=generation,
                observed_at=now,
                valid_until=now + _SNAPSHOT_TTL,
                advertised_operations=tuple(operations),
                values=tuple(values),
                choices=tuple(choices),
                blocked_reason=blocked,
                provider_cursor=self._provider_cursor(session),
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
        native_id = _native_session_id(session_id)
        with self._lock:
            self._sync_session_events()
            session = (
                self._sessions.get(native_id)
                if native_id is not None
                else None
            )
            proof = (
                self._validated_snapshots.get(session_id)
                if session_id is not None
                else None
            )
            if (
                session is None
                or session.state != "live"
                or capability_generation != session.generation
                or not self._exact_session_truth(
                    session_id,
                    session_truth,
                    session,
                )
                or proof is None
                or proof[:3] != (
                    session.session_id,
                    session.generation,
                    session.cwd,
                )
                or operation_id not in proof[3]
                or proof[4] < time.time()
            ):
                raise QwenUnavailableError(
                    "operation_correlation_truth_stale"
                )
            return ProviderOperationCorrelation(
                _operation_correlation_id(
                    self.binding.binding_id,
                    session.generation,
                    client_action_id,
                ),
                self._provider_cursor(session),
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
        provider_operation_id = _operation_correlation_id(
            self.binding.binding_id,
            capability_generation,
            client_action_id,
        )
        if provider_correlation is not None and (
            not isinstance(provider_correlation, ProviderOperationCorrelation)
            or provider_correlation.provider_operation_id
            != provider_operation_id
        ):
            raise QwenUnavailableError("operation_correlation_truth_stale")

        def rejected(code: str) -> ProviderOperationResult:
            result = self._rejected(
                operation_id,
                code,
                provider_operation_id=provider_operation_id,
            )
            if provider_correlation is not None:
                result = ProviderOperationResult(
                    operation_id=result.operation_id,
                    provider_operation_id=provider_correlation.provider_operation_id,
                    status=result.status,
                    public_result=result.public_result,
                    provider_cursor=provider_correlation.provider_cursor,
                )
            return finish(result)

        client = self._client
        self._sync_session_events()
        native_id = _native_session_id(session_id)
        with self._lock:
            session = (
                self._sessions.get(native_id)
                if native_id is not None
                else None
            )
            proof = (
                self._validated_snapshots.get(session_id)
                if session_id is not None
                else None
            )
        reserved_cursor = (
            provider_correlation.provider_cursor
            if provider_correlation is not None
            else self._provider_cursor(session)
        )

        def finish(result: ProviderOperationResult) -> ProviderOperationResult:
            if provider_correlation is not None and (
                result.provider_operation_id
                != provider_correlation.provider_operation_id
                or result.provider_cursor != provider_correlation.provider_cursor
            ):
                result = ProviderOperationResult(
                    operation_id=result.operation_id,
                    provider_operation_id=provider_correlation.provider_operation_id,
                    status=result.status,
                    public_result=result.public_result,
                    provider_cursor=provider_correlation.provider_cursor,
                )
            if result.status in {
                OperationResultStatus.APPLIED,
                OperationResultStatus.REJECTED,
            }:
                with self._lock:
                    key = (capability_generation, client_action_id)
                    self._action_results[key] = (
                        operation_id,
                        session_id,
                        result,
                    )
                    self._action_results.move_to_end(key)
                    while len(self._action_results) > _MAX_ACTION_RESULTS:
                        self._action_results.popitem(last=False)
            return result
        if binding_id != self.binding.binding_id:
            return rejected("stale_binding")
        if session is None:
            return rejected("session_not_driver_owned")
        if capability_generation != session.generation:
            return rejected("stale_generation")
        if (
            proof is None
            or proof[:3] != (
                session.session_id,
                session.generation,
                session.cwd,
            )
            or operation_id not in proof[3]
            or proof[4] < time.time()
            or session.state != "live"
        ):
            return rejected("stale_session_truth")
        if prepared_attachments:
            return rejected("attachments_unsupported")
        if client is None or not client.alive:
            return rejected(
                self._blocked_reason or "sidecar_unavailable"
            )
        if operation_id.startswith("session."):
            identity = input_payload.get("session")
            if not _exact_session_identity(
                identity,
                self.binding,
                session.generation,
                session_id,
            ):
                return rejected("stale_session")
        if operation_id == "session.approval.decide":
            approval_id = input_payload.get("approval_id")
            pending = {
                item.get("approval_id"): item
                for item in client.pending_approvals
                if item.get("session_id") == session.session_id
            }
            if approval_id not in pending:
                return rejected("stale_approval")
        target: _QwenSession | None = None
        if operation_id in {"session.resume", "session.fork"}:
            target_native_id = _native_session_id(
                input_payload.get("target_session")
            )
            target = (
                self._sessions.get(target_native_id)
                if target_native_id is not None
                else None
            )
            if (
                target is None
                or target.cwd != session.cwd
            ):
                return rejected("target_session_not_driver_owned")
        try:
            if operation_id == "session.resume":
                if target is None or target.state not in {
                    "ended",
                    "failed",
                }:
                    return rejected("target_session_not_resumable")
                launched = self.launch_session(
                    cwd=target.cwd,
                    permission_mode=target.permission_mode,
                    model=target.model,
                    effort=target.effort,
                    max_session_turns=target.max_session_turns,
                    max_tool_calls=target.max_tool_calls,
                    max_subagent_depth=target.max_subagent_depth,
                    resume_session_id=target.session_id,
                    session_id=target.session_id,
                )
                return finish(ProviderOperationResult(
                    operation_id,
                    provider_operation_id,
                    OperationResultStatus.APPLIED,
                    {
                        "session_id": _qualified_session_id(
                            launched["native_session_id"]
                        ),
                        "native_session_id": launched[
                            "native_session_id"
                        ],
                        "capability_generation": launched[
                            "capability_generation"
                        ],
                    },
                    reserved_cursor,
                ))
            if operation_id == "session.fork":
                if target is not session:
                    return rejected("target_session_not_forkable")
                launched = self.launch_session(
                    cwd=target.cwd,
                    permission_mode=target.permission_mode,
                    model=target.model,
                    effort=target.effort,
                    max_session_turns=target.max_session_turns,
                    max_tool_calls=target.max_tool_calls,
                    max_subagent_depth=target.max_subagent_depth,
                    resume_session_id=target.session_id,
                    fork=True,
                )
                child_native_id = launched["native_session_id"]
                child = self._sessions.get(child_native_id)
                if (
                    child is None
                    or child.state != "live"
                    or child.cwd != target.cwd
                    or child.generation
                    != launched["capability_generation"]
                ):
                    return rejected("fork_child_identity_unproven")
                return finish(ProviderOperationResult(
                    operation_id,
                    provider_operation_id,
                    OperationResultStatus.APPLIED,
                    {
                        "native_session_id": child_native_id,
                        "session_id": child_native_id,
                        "capability_generation": child.generation,
                    },
                    reserved_cursor,
                ))
            sidecar_payload = self._sidecar_payload(
                operation_id,
                input_payload,
                session,
                client_action_id,
            )
            reply = client.request(
                operation_id,
                sidecar_payload,
                timeout=(
                    35.0
                    if operation_id.startswith("provider.")
                    else 12.0
                ),
            )
        except (QwenUnavailableError, ValueError, OSError) as exc:
            code = (
                exc.code
                if isinstance(exc, QwenUnavailableError)
                else "provider_operation_failed"
            )
            return rejected(code)
        if operation_id == "session.terminate":
            with self._lock:
                session.state = "ended"
                self._generation += 1
        elif operation_id == "session.model.set":
            session.model = input_payload["model"]
        elif operation_id == "session.reasoning.set":
            session.effort = input_payload["reasoning"]
        elif operation_id == "session.permissions.set":
            session.permission_mode = input_payload["permissions"]
        status = OperationResultStatus.APPLIED
        return finish(ProviderOperationResult(
            operation_id=operation_id,
            provider_operation_id=provider_operation_id,
            status=status,
            public_result=_public_result(
                operation_id,
                reply.result,
                session_id,
            ),
            provider_cursor=reserved_cursor,
        ))

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
        expected_operation_id = _operation_correlation_id(
            self.binding.binding_id,
            capability_generation,
            client_action_id,
        )
        if (
            binding_id != self.binding.binding_id
            or not isinstance(
                provider_correlation,
                ProviderOperationCorrelation,
            )
            or provider_correlation.provider_operation_id
            != expected_operation_id
        ):
            raise QwenUnavailableError(
                "operation_correlation_truth_stale"
            )
        with self._lock:
            cached = self._action_results.get(
                (capability_generation, client_action_id)
            )
            if cached is not None:
                self._action_results.move_to_end(
                    (capability_generation, client_action_id)
                )
        if cached is None:
            return None
        cached_operation_id, cached_session_id, result = cached
        if (
            cached_operation_id != operation_id
            or cached_session_id != session_id
            or result.operation_id != operation_id
            or result.provider_operation_id
            != provider_correlation.provider_operation_id
            or result.provider_cursor
            != provider_correlation.provider_cursor
            or result.status
            not in {
                OperationResultStatus.APPLIED,
                OperationResultStatus.REJECTED,
            }
        ):
            return None
        return result


    def poll_events(self, after_cursor: Any = 0) -> dict[str, Any]:
        self._sync_session_events()
        client = self._client
        native_id, cursor = _decode_session_event_cursor(after_cursor)
        if native_id is None:
            sole = self._sole_live_session()
            native_id = sole.session_id if sole is not None else None
        session = (
            self._sessions.get(native_id)
            if native_id is not None
            else None
        )
        events: list[dict[str, Any]] = []
        if client is not None and session is not None:
            for value in client.poll_events(cursor):
                if value.get("session_id") != session.session_id:
                    continue
                event = dict(value)
                event_type = event.get("event_type")
                lifecycle_status = _EVENT_LIFECYCLE_STATUS.get(event_type)
                if lifecycle_status is not None:
                    event["kind"] = "lifecycle"
                    event["status"] = lifecycle_status
                event["provider_id"] = self.binding.provider_id
                event["native_session_id"] = session.session_id
                event["binding_id"] = self.binding.binding_id
                event["capability_generation"] = session.generation
                events.append(event)
        return {
            "events": events,
            "provider_cursor": _session_event_cursor(
                session.session_id,
                client.cursor if client is not None else cursor,
            ) if session is not None else str(cursor),
            "provider": self.binding.provider_id,
            "provider_id": self.binding.provider_id,
            "session_id": (
                session.session_id if session is not None else None
            ),
            "native_session_id": (
                session.session_id if session is not None else None
            ),
            "binding_id": self.binding.binding_id,
            "capability_generation": (
                session.generation
                if session is not None
                else self._generation
            ),
        }

    def close(self) -> None:
        client = self._client
        if client is not None:
            client.close()

    def _sync_session_events(self) -> None:
        client = self._client
        if client is None:
            return
        events = client.poll_events(self._last_event_cursor)
        with self._lock:
            for event in events:
                cursor = event.get("cursor")
                if isinstance(cursor, int):
                    self._last_event_cursor = max(self._last_event_cursor, cursor)
                event_type = event.get("event_type")
                session_id = event.get("session_id")
                session = self._sessions.get(session_id) if isinstance(session_id, str) else None
                if session is None or event_type not in {"session_ended", "session_failed"}:
                    continue
                next_state = "failed" if event_type == "session_failed" else "ended"
                if session.state != next_state:
                    session.state = next_state
                    self._validated_snapshots.pop(
                        _qualified_session_id(session.session_id),
                        None,
                    )
                    self._generation += 1

    def _provider_cursor(
        self,
        session: _QwenSession | None = None,
    ) -> str:
        client = self._client
        cursor = client.cursor if client is not None else 0
        if session is not None:
            return _session_event_cursor(session.session_id, cursor)
        runtime_digest = (
            self.runtime.launch_digest[:16]
            if self.runtime is not None
            else "unavailable"
        )
        config_material = ",".join(
            sorted(
                item.config_digest
                for item in self._sessions.values()
                if item.state == "live"
            )
        )
        config_digest = hashlib.sha256(
            config_material.encode("ascii")
        ).hexdigest()[:16]
        return f"{cursor}:{runtime_digest}:{config_digest}"

    def _sidecar_payload(
        self,
        operation_id: str,
        input_payload: dict[str, Any],
        session: _QwenSession | None,
        action_id: str,
    ) -> dict[str, Any]:
        if operation_id.startswith("provider."):
            if session is None:
                raise QwenUnavailableError("session_required")
            return {"session_id": session.session_id}
        if session is None:
            raise QwenUnavailableError("session_not_driver_owned")
        payload: dict[str, Any] = {"session_id": session.session_id, "action_id": action_id}
        field_by_operation = {
            "session.prompt.send": "prompt",
            "session.turn.steer": "instruction",
            "session.model.set": "model",
            "session.reasoning.set": "reasoning",
            "session.permissions.set": "permissions",
        }
        field = field_by_operation.get(operation_id)
        if field is not None:
            payload[field] = input_payload[field]
        elif operation_id == "session.approval.decide":
            payload["approval_id"] = input_payload["approval_id"]
            payload["decision"] = input_payload["decision"]
        elif operation_id not in {"session.turn.interrupt", "session.terminate"}:
            raise QwenUnavailableError("operation_not_supported")
        return payload

    def _exact_session_truth(
        self,
        session_id: str | None,
        truth: Mapping[str, Any] | None,
        session: _QwenSession | None,
    ) -> bool:
        if (
            session is None
            or not isinstance(session_id, str)
            or not isinstance(truth, Mapping)
        ):
            return False
        return (
            session_id == _qualified_session_id(session.session_id)
            and truth.get("session_id") == session_id
            and truth.get("provider") == self.binding.provider_id
            and truth.get("provider_id") == self.binding.provider_id
            and truth.get("native_id") == session.session_id
            and truth.get("binding_id") == self.binding.binding_id
            and truth.get("capability_generation")
            == session.generation
            and truth.get("provider_version")
            == self.binding.provider_version
            and truth.get("provider_channel")
            == self.binding.provider_channel
            and truth.get("project") == session.cwd
            and truth.get("cwd") == session.cwd
            and truth.get("managed") is True
            and truth.get("owner") == "provider_driver"
            and truth.get("terminal_backed") is False
            and truth.get("driver_available") is True
            and truth.get("is_live") is True
            and truth.get("controllable") is True
            and truth.get("lifecycle")
            in _MANAGED_LIVE_LIFECYCLES
        )

    def _sole_live_session(self) -> _QwenSession | None:
        live = [session for session in self._sessions.values() if session.state == "live"]
        return live[0] if len(live) == 1 else None

    def _require_client(self):
        if self._client is None or not self._client.alive:
            raise QwenUnavailableError(self._blocked_reason or "sidecar_unavailable")
        return self._client

    def _rejected(
        self,
        operation_id: str,
        code: str,
        *,
        provider_operation_id: str | None = None,
    ) -> ProviderOperationResult:
        return ProviderOperationResult(
            operation_id=operation_id,
            provider_operation_id=(
                provider_operation_id
                or f"qwen-rejected-{uuid.uuid4()}"
            ),
            status=OperationResultStatus.REJECTED,
            public_result={"code": code},
            provider_cursor=self._provider_cursor(),
        )


class QwenCodeProviderAdapter(ProviderAdapter):
    descriptor = registry_data.descriptor_for(_ENTRY) if _ENTRY else _FALLBACK_DESCRIPTOR

    def __init__(self, home: Path | None = None):
        self.home = home or Path.home()
        self._last_runtime: QwenRuntimeEvidence | None = None
        self._last_error: str | None = None

    @property
    def candidates(self) -> list[Path]:
        if _ENTRY is not None and _ENTRY.binary_candidates:
            return registry_data.candidate_paths(_ENTRY, home=self.home)
        return [self.home / ".local" / "bin" / "qwen", Path("/opt/homebrew/bin/qwen"), Path("/usr/local/bin/qwen")]

    def supports(self, capability: str) -> bool:
        return capability in {
            "detect", "status", "spawn", "live_state", "send_text", "interrupt", "terminate", "mcp", "worker_telemetry"
        }

    def probe(self) -> ProviderProbeResult:
        notes: list[str] = []
        setup_actions: list[str] = []
        runtime: QwenRuntimeEvidence | None = None
        error_code: str | None = None
        try:
            runtime = discover_qwen_runtime(self.home)
            self._last_runtime = runtime
            self._last_error = None
        except QwenUnavailableError as exc:
            error_code = exc.code
            self._last_runtime = None
            self._last_error = error_code
            notes.append(error_code)
            if error_code == "cli_missing":
                setup_actions.append("install_cli")
            elif error_code in {"cli_version_unsupported", "sdk_version_unsupported", "node_version_unsupported"}:
                setup_actions.append("update_cli")
            else:
                setup_actions.append("repair_provider")
        installed = error_code != "cli_missing"
        usable = runtime is not None
        capabilities = (
            "detect", "status", "spawn", "live_state", "send_text", "interrupt", "terminate", "mcp", "worker_telemetry"
        ) if usable else ("detect", "status")
        if usable:
            notes.extend((
                "Authentication is verified when a safe SDK session initializes",
                "ACP fallback is disabled unless separately versioned and conformance-gated",
                "SDK 0.1.8 does not advertise schema-constrained output",
            ))
        config_path = self.home / ".qwen" / "settings.json"
        availability = ProviderAvailability(
            provider_id=self.descriptor.provider_id,
            display_name=self.descriptor.display_name,
            kind=self.descriptor.kind,
            installed=installed,
            usable=usable,
            launchable=usable,
            auth_state="unknown" if usable else "unavailable",
            config_state="present" if config_path.is_file() else "unknown",
            readable_sessions=0,
            live_sessions=0,
            controllable_sessions=0,
            capabilities=capabilities,
            setup_actions=tuple(setup_actions),
            notes=tuple(notes),
        )
        diagnostics = ProviderDiagnostics(
            cli_path=str(runtime.cli_path) if runtime else None,
            cli_path_source="verified_package" if runtime else None,
            version=runtime.cli_version if runtime else None,
            config_path=str(config_path),
            config_exists=config_path.is_file(),
        )
        return ProviderProbeResult(self.descriptor, availability, diagnostics, time.time())

    def create_control_driver(self, binding: ProviderControlBinding) -> QwenControlDriver:
        if binding.provider_id != self.descriptor.provider_id:
            return QwenControlDriver(binding, None, blocked_reason="provider_binding_mismatch")
        try:
            runtime = discover_qwen_runtime(self.home)
        except QwenUnavailableError as exc:
            return QwenControlDriver(binding, None, blocked_reason=exc.code)
        binding_version = _VERSION_RE.search(binding.provider_version)
        if binding_version is None or binding_version.group(1) != runtime.cli_version:
            return QwenControlDriver(binding, runtime, blocked_reason="provider_version_mismatch")
        if binding.provider_channel != "stable":
            return QwenControlDriver(binding, runtime, blocked_reason="provider_channel_unsupported")
        return QwenControlDriver(binding, runtime)


def create_control_driver(binding: ProviderControlBinding) -> QwenControlDriver:
    return QwenCodeProviderAdapter().create_control_driver(binding)


def _require_uuid(value: str, label: str) -> None:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid Qwen {label} id") from exc
    if str(parsed) != value.lower():
        raise ValueError(f"invalid Qwen {label} id")


def _qualified_session_id(native_session_id: str) -> str:
    _require_uuid(native_session_id, "session")
    return f"{_PROVIDER_ID}:{native_session_id}"


def _native_session_id(session_id: Any) -> str | None:
    if not isinstance(session_id, str):
        return None
    prefix = f"{_PROVIDER_ID}:"
    if not session_id.startswith(prefix):
        return None
    native_id = session_id[len(prefix):]
    try:
        _require_uuid(native_id, "session")
    except ValueError:
        return None
    return native_id


def _operation_correlation_id(
    binding_id: str,
    generation: int,
    client_action_id: str,
) -> str:
    material = "\0".join((
        _PROVIDER_ID,
        str(binding_id),
        str(generation),
        str(client_action_id),
    )).encode("utf-8")
    return "qwen-operation-" + hashlib.sha256(material).hexdigest()


def _session_event_cursor(native_session_id: str, cursor: int) -> str:
    return f"{_qualified_session_id(native_session_id)}@{max(0, int(cursor))}"


def _decode_session_event_cursor(value: Any) -> tuple[str | None, int]:
    if isinstance(value, bool):
        return None, 0
    if isinstance(value, int):
        return None, max(0, value)
    if not isinstance(value, str):
        return None, 0
    session_id, separator, cursor_text = value.rpartition("@")
    if separator:
        native_id = _native_session_id(session_id)
        if native_id is not None and cursor_text.isdigit():
            return native_id, int(cursor_text)
    if value.isdigit():
        return None, int(value)
    return None, 0


def _model_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    result: list[str] = []
    for item in value[:128]:
        if isinstance(item, str) and _MODEL_RE.fullmatch(item) is not None and item not in result:
            result.append(item)
    return tuple(result)


def _exact_session_identity(
    value: Any,
    binding: ProviderControlBinding,
    generation: int,
    session_id: str,
) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value) == {"provider_id", "session_id", "binding_id", "capability_generation"}
        and value.get("provider_id") == binding.provider_id
        and value.get("session_id") == session_id
        and value.get("binding_id") == binding.binding_id
        and value.get("capability_generation") == generation
    )


def _public_result(operation_id: str, result: dict[str, Any], session_id: str | None) -> dict[str, Any]:
    if operation_id.startswith("provider."):
        return {"provider": _PROVIDER_ID, "data": result}
    safe: dict[str, Any] = {"session_id": session_id}
    for key in (
        "accepted", "interrupted", "terminated", "model", "reasoning", "applied", "permissions", "approval_id", "decision"
    ):
        value = result.get(key)
        if isinstance(value, (str, bool, int, float)) or value is None:
            safe[key] = value
    return safe
