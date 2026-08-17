from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol

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
from .operations import REVIEWED_OPERATION_CATALOG, OperationCatalogError


SUPPORTED_HERMES_VERSION = "0.19.0"
SUPPORTED_HERMES_CHANNEL = "upstream-937222f4"
_DENIED_WRITE_CANARY_PATH = "/v1/runs/pairling-canary-nonexistent/stop"
_MAX_JSON_BYTES = 1024 * 1024
_MAX_EVENT_BYTES = 256 * 1024
_MAX_TEXT_BYTES = 64 * 1024
_MAX_EVENTS = 512
_MAX_ACTION_RESULTS = 256
_TARGET_SESSION_TTL_SECONDS = 2.0
_EVENT_FILE_BYTES = 4 * 1024 * 1024
_RUN_ID_RE = re.compile(r"run_[A-Za-z0-9_-]{1,200}\Z")
_SESSION_ID_RE = re.compile(r"[^\r\n\x00/]{1,512}\Z")
_ACTION_ID_RE = re.compile(r"[^\r\n\x00]{1,512}\Z")

_REQUIRED_FEATURES = frozenset({
    "run_submission",
    "run_status",
    "run_events_sse",
    "run_stop",
    "run_approval_response",
    "tool_progress_events",
    "approval_events",
    "session_fork",
})
_REQUIRED_ENDPOINTS = {
    "runs": ("POST", "/v1/runs"),
    "run_status": ("GET", "/v1/runs/{run_id}"),
    "run_events": ("GET", "/v1/runs/{run_id}/events"),
    "run_approval": ("POST", "/v1/runs/{run_id}/approval"),
    "run_stop": ("POST", "/v1/runs/{run_id}/stop"),
    "session": ("GET", "/api/sessions/{session_id}"),
    "session_fork": ("POST", "/api/sessions/{session_id}/fork"),
}
_SECRET_KEY_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "env",
    "password",
    "private_key",
    "refresh_token",
    "secret",
)


class HermesRunsError(RuntimeError):
    pass


class HermesRunsUnavailable(HermesRunsError):
    pass


class HermesRunsProtocolError(HermesRunsUnavailable):
    pass


class HermesEventCursorExpired(HermesRunsError):
    pass


@dataclass(frozen=True)
class HermesHTTPResponse:
    status: int
    headers: Mapping[str, str]
    body: dict[str, Any]


@dataclass(frozen=True)
class HermesPolicyState:
    approval_mode: str
    cron_mode: str
    yolo_enabled: bool
    launch_digest: str


@dataclass(frozen=True)
class HermesOwnedServerRecord:
    schema_version: int
    binding_id: str
    provider_version: str
    provider_channel: str
    capability_generation: int
    base_url: str
    pid: int
    binary_path: str
    hermes_home: str
    cwd: str
    approval_mode: str
    cron_mode: str
    yolo_enabled: bool
    launch_digest: str
    owner_nonce: str

    def validate(self) -> None:
        if self.schema_version != 1:
            raise HermesRunsProtocolError("unknown owned server record schema")
        if not self.binding_id or len(self.binding_id) > 256:
            raise HermesRunsProtocolError("invalid owned server binding")
        if self.provider_version != SUPPORTED_HERMES_VERSION:
            raise HermesRunsProtocolError("unsupported Hermes version")
        if self.provider_channel != SUPPORTED_HERMES_CHANNEL:
            raise HermesRunsProtocolError("unsupported Hermes channel")
        if not isinstance(self.capability_generation, int) or self.capability_generation < 1:
            raise HermesRunsProtocolError("invalid Hermes capability generation")
        if not isinstance(self.pid, int) or self.pid < 2:
            raise HermesRunsProtocolError("invalid owned Hermes pid")
        _validated_loopback_base_url(self.base_url)
        if self.approval_mode != "manual" or self.cron_mode != "deny" or self.yolo_enabled:
            raise HermesRunsProtocolError("unsafe Hermes approval policy")
        for value in (
            self.binary_path,
            self.hermes_home,
            self.cwd,
            self.launch_digest,
            self.owner_nonce,
        ):
            if not isinstance(value, str) or not value or len(value) > 4096:
                raise HermesRunsProtocolError("owned Hermes record is incomplete")

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return dict(self.__dict__)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "HermesOwnedServerRecord":
        expected = {
            "schema_version",
            "binding_id",
            "provider_version",
            "provider_channel",
            "capability_generation",
            "base_url",
            "pid",
            "binary_path",
            "hermes_home",
            "cwd",
            "approval_mode",
            "cron_mode",
            "yolo_enabled",
            "launch_digest",
            "owner_nonce",
        }
        if not isinstance(payload, Mapping) or set(payload) != expected:
            raise HermesRunsProtocolError("owned Hermes record fields differ from schema")
        record = cls(**{key: payload[key] for key in expected})
        record.validate()
        return record


class HermesTransport(Protocol):
    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        authenticated: bool = True,
    ) -> HermesHTTPResponse:
        ...

    def stream_sse(
        self,
        path: str,
        *,
        authenticated: bool = True,
    ) -> Iterable[dict[str, Any]]:
        ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HermesRunsHTTPTransport:
    """Fixed-route loopback HTTP/SSE client. It has no arbitrary endpoint API."""

    def __init__(self, base_url: str, bearer: str, *, timeout_seconds: float = 5.0):
        self._base_url = _validated_loopback_base_url(base_url)
        if not isinstance(bearer, str) or len(bearer.encode("utf-8")) < 32:
            raise HermesRunsProtocolError("Hermes bearer is missing or too short")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._bearer = bearer
        self._timeout_seconds = timeout_seconds
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        authenticated: bool = True,
    ) -> HermesHTTPResponse:
        url = self._url(path)
        if not _fixed_request_route(method, path):
            raise HermesRunsProtocolError("Hermes transport rejected an unreviewed route")
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if len(data) > _MAX_JSON_BYTES:
                raise HermesRunsProtocolError("Hermes request exceeds size limit")
            headers["Content-Type"] = "application/json"
        if authenticated:
            headers["Authorization"] = f"Bearer {self._bearer}"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            response = self._opener.open(
                request, timeout=self._timeout_seconds
            )
            try:
                status = int(response.status)
                response_headers = {
                    str(k).lower(): str(v)
                    for k, v in response.headers.items()
                }
                raw = _bounded_read(response, _MAX_JSON_BYTES)
            finally:
                response.close()
        except urllib.error.HTTPError as exc:
            try:
                status = int(exc.code)
                response_headers = {
                    str(k).lower(): str(v)
                    for k, v in exc.headers.items()
                }
                raw = _bounded_read(exc, _MAX_JSON_BYTES)
            finally:
                exc.close()
        except (OSError, urllib.error.URLError) as exc:
            raise HermesRunsUnavailable(f"Hermes loopback request failed: {_bounded_text(exc, 256)}") from exc
        body = _decode_json_object(raw)
        return HermesHTTPResponse(status, response_headers, body)

    def stream_sse(
        self,
        path: str,
        *,
        authenticated: bool = True,
    ) -> Iterable[dict[str, Any]]:
        if not _fixed_request_route("STREAM", path):
            raise HermesRunsProtocolError("Hermes transport rejected an unreviewed event route")
        headers = {"Accept": "text/event-stream"}
        if authenticated:
            headers["Authorization"] = f"Bearer {self._bearer}"
        request = urllib.request.Request(self._url(path), headers=headers, method="GET")
        try:
            response = self._opener.open(
                request, timeout=max(self._timeout_seconds, 35.0)
            )
        except urllib.error.HTTPError as exc:
            try:
                raise HermesRunsUnavailable(
                    f"Hermes event stream returned HTTP {exc.code}"
                ) from exc
            finally:
                exc.close()
        except (OSError, urllib.error.URLError) as exc:
            raise HermesRunsUnavailable(
                f"Hermes event stream failed: {_bounded_text(exc, 256)}"
            ) from exc
        try:
            content_type = str(
                response.headers.get("Content-Type") or ""
            ).lower()
            if (
                int(response.status) != 200
                or "text/event-stream" not in content_type
            ):
                raise HermesRunsProtocolError(
                    "Hermes event stream did not return SSE"
                )
            data_lines: list[bytes] = []
            data_size = 0
            for raw_line in response:
                if len(raw_line) > _MAX_EVENT_BYTES:
                    raise HermesRunsProtocolError(
                        "Hermes SSE line exceeds size limit"
                    )
                line = raw_line.rstrip(b"\r\n")
                if not line:
                    if data_lines:
                        raw_data = b"\n".join(data_lines)
                        yield _decode_json_object(raw_data)
                        data_lines.clear()
                        data_size = 0
                    continue
                if line.startswith(b":"):
                    continue
                if line.startswith(b"data:"):
                    chunk = line[5:].lstrip(b" ")
                    data_size += len(chunk)
                    if data_size > _MAX_EVENT_BYTES:
                        raise HermesRunsProtocolError(
                            "Hermes SSE event exceeds size limit"
                        )
                    data_lines.append(chunk)
            if data_lines:
                yield _decode_json_object(b"\n".join(data_lines))
        finally:
            response.close()

    def _url(self, path: str) -> str:
        if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
            raise HermesRunsProtocolError("invalid Hermes route")
        if "?" in path or "#" in path or ".." in path:
            raise HermesRunsProtocolError("Hermes route must be a fixed path")
        return self._base_url + path


@dataclass(frozen=True)
class _PendingApproval:
    approval_id: str
    run_id: str
    session_id: str
    generation: int
    choices: tuple[str, ...]


@dataclass(frozen=True)
class _ProbeResult:
    blocked_reason: str | None
    capabilities: dict[str, Any]
    model_aliases: tuple[str, ...]
    status: dict[str, Any]


@dataclass(frozen=True)
class _ActionResult:
    fingerprint: str
    session_id: str | None
    result: ProviderOperationResult

@dataclass(frozen=True)
class _TargetAuthorization:
    operation_id: str
    source_session_id: str
    target_identity: ProviderSessionIdentity
    valid_until: float


class _EventJournal:
    def __init__(self, root: Path, binding_id: str, generation: int):
        self._lock = threading.RLock()
        self._generation = generation
        self._rows: deque[dict[str, Any]] = deque(maxlen=_MAX_EVENTS)
        self._next_sequence = 1
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(root, 0o700)
        except OSError:
            pass
        name = hashlib.sha256(binding_id.encode("utf-8")).hexdigest() + ".events.jsonl"
        self._path = root / name
        self._load()

    @property
    def cursor(self) -> str:
        with self._lock:
            sequence = self._rows[-1]["sequence"] if self._rows else 0
            return self._format_cursor(sequence)

    def records(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(row) for row in self._rows)

    def append(
        self,
        run_id: str,
        event: Mapping[str, Any],
        *,
        durable: bool = False,
    ) -> dict[str, Any]:
        with self._lock:
            sequence = self._next_sequence
            self._next_sequence += 1
            row = dict(event)
            row.update({
                "schema_version": 1,
                "run_id": run_id,
                "sequence": sequence,
                "cursor": self._format_cursor(sequence),
            })
            encoded = json.dumps(row, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
            if len(encoded) > _MAX_EVENT_BYTES:
                raise HermesRunsProtocolError("normalized Hermes event exceeds size limit")
            self._rows.append(row)
            fd = os.open(self._path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
            try:
                os.write(fd, encoded)
                if durable:
                    os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass
            if self._path.stat().st_size > _EVENT_FILE_BYTES:
                self._compact()
            return dict(row)

    def after(self, run_id: str, cursor: str | None) -> list[dict[str, Any]]:
        with self._lock:
            rows = [row for row in self._rows if row.get("run_id") == run_id]
            if cursor is None:
                return [dict(row) for row in rows]
            generation, sequence = self._parse_cursor(cursor)
            if generation != self._generation:
                raise HermesEventCursorExpired("Hermes event cursor belongs to a stale binding")
            matching = next((row for row in rows if row.get("sequence") == sequence), None)
            if matching is None:
                raise HermesEventCursorExpired("Hermes event cursor is no longer retained")
            return [dict(row) for row in rows if int(row.get("sequence", 0)) > sequence]

    def _load(self) -> None:
        if not self._path.is_file():
            return
        try:
            if self._path.stat().st_mode & 0o077:
                raise HermesRunsProtocolError("Hermes event journal permissions are unsafe")
            raw_lines = self._path.read_bytes().splitlines()[-_MAX_EVENTS:]
            for raw in raw_lines:
                if len(raw) > _MAX_EVENT_BYTES:
                    continue
                row = json.loads(raw)
                if not isinstance(row, dict):
                    continue
                generation, sequence = self._parse_cursor(str(row.get("cursor") or ""))
                if generation != self._generation or sequence < 1:
                    continue
                self._rows.append(row)
                self._next_sequence = max(self._next_sequence, sequence + 1)
        except HermesRunsProtocolError:
            raise
        except Exception as exc:
            raise HermesRunsProtocolError("Hermes event journal is corrupt") from exc

    def _compact(self) -> None:
        temporary = self._path.with_suffix(".tmp")
        content = b"".join(
            json.dumps(row, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
            for row in self._rows
        )
        fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        try:
            os.write(fd, content)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, self._path)

    def _format_cursor(self, sequence: int) -> str:
        return f"hermes:{self._generation}:{sequence}"

    @staticmethod
    def _parse_cursor(cursor: str) -> tuple[int, int]:
        match = re.fullmatch(r"hermes:(\d+):(\d+)", cursor)
        if match is None:
            raise HermesEventCursorExpired("invalid Hermes event cursor")
        return int(match.group(1)), int(match.group(2))


class HermesRunsControlDriver:
    def __init__(
        self,
        binding: ProviderControlBinding,
        *,
        record: HermesOwnedServerRecord,
        bearer: str,
        transport: HermesTransport | None = None,
        policy_probe: Callable[[HermesOwnedServerRecord], HermesPolicyState],
        ownership_probe: Callable[[HermesOwnedServerRecord], bool],
        event_dir: Path,
        auto_stream: bool = True,
    ):
        self.binding = binding
        self._record = record
        self._bearer = bearer
        self._transport = transport or HermesRunsHTTPTransport(record.base_url, bearer)
        self._policy_probe = policy_probe
        self._ownership_probe = ownership_probe
        self._auto_stream = auto_stream
        self._lock = threading.RLock()
        self._execute_lock = threading.Lock()
        self._journal = _EventJournal(event_dir, binding.binding_id, record.capability_generation)
        self._active_runs: dict[str, str] = {}
        self._run_sessions: dict[str, str] = {}
        self._pending_approvals: dict[str, _PendingApproval] = {}
        self._pending_by_run: dict[str, str] = {}
        self._stream_threads: dict[str, threading.Thread] = {}
        self._actions: dict[str, _ActionResult] = {}
        self._action_order: deque[str] = deque()
        self._prepared_prompt_correlations: dict[
            tuple[str, str],
            ProviderOperationCorrelation,
        ] = {}
        self._dispatch_boundaries: dict[str, Callable[[], None]] = {}
        self._last_statuses: dict[str, dict[str, Any]] = {}
        self._unsafe_runtime_reason: str | None = None
        self._target_authorizations: dict[
            tuple[str, str, str],
            _TargetAuthorization,
        ] = {}
        self._restore_correlated_prompt_actions()

    @property
    def capability_generation(self) -> int:
        return self._record.capability_generation

    def snapshot(
        self,
        *,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderControlSnapshot:
        now = time.time()
        if session_id is not None:
            self._replace_target_authorizations(session_id, (), now=now)
        blocked_reason: str | None = None
        if session_id is None:
            if session_truth is not None:
                blocked_reason = "hermes_provider_snapshot_has_session_truth"
        elif not _session_truth_matches(
            self.binding,
            self._record.capability_generation,
            session_id,
            session_truth,
        ):
            blocked_reason = "hermes_session_truth_mismatch"

        probe = (
            self._probe_runtime()
            if blocked_reason is None
            else _ProbeResult(blocked_reason, {}, (), {})
        )
        blocked_reason = probe.blocked_reason or self._unsafe_runtime_reason
        advertised: list[str] = []
        values: list[ControlValue] = []
        choices: list[ControlChoices] = []
        if blocked_reason is None:
            if session_id is None:
                advertised.extend(("provider.usage.read", "provider.diagnostics.read"))
            elif _safe_session_id(session_id):
                session_response = self._transport.request(
                    "GET", _session_path(session_id), authenticated=True
                )
                if session_response.status != 200 or not _session_matches(
                    session_response.body, session_id
                ):
                    blocked_reason = "hermes_session_unavailable"
                else:
                    resume_targets, fork_targets = self._snapshot_target_choices(
                        session_id=session_id,
                        session_response=session_response,
                        now=now,
                    )
                    if resume_targets:
                        advertised.append("session.resume")
                        choices.append(ControlChoices(
                            "session.resume",
                            "target_session",
                            resume_targets,
                        ))
                    if fork_targets:
                        advertised.append("session.fork")
                        choices.append(ControlChoices(
                            "session.fork",
                            "target_session",
                            fork_targets,
                        ))
                    active_run = self._active_runs.get(session_id)
                    active = bool(active_run and self._run_is_active(active_run))
                    if active:
                        advertised.append("session.turn.interrupt")
                    else:
                        advertised.append("session.prompt.send")
                    if (
                        probe.model_aliases
                        and _feature_enabled(probe.capabilities, "session_model_lock")
                        and _endpoint_matches(
                            probe.capabilities,
                            "session_model_lock",
                            "POST",
                            "/api/sessions/{session_id}/model",
                        )
                    ):
                        advertised.append("session.model.set")
                        choices.append(
                            ControlChoices(
                                "session.model.set",
                                "model",
                                tuple(
                                    ControlChoice(model, model)
                                    for model in probe.model_aliases
                                ),
                            )
                        )
                    pending = self._pending_for_session(session_id)
                    if pending is not None:
                        advertised.append("session.approval.decide")
                        choices.append(
                            ControlChoices(
                                "session.approval.decide",
                                "approval_id",
                                (
                                    ControlChoice(
                                        pending.approval_id,
                                        "Pending Hermes approval",
                                    ),
                                ),
                            )
                        )
                        choices.append(
                            ControlChoices(
                                "session.approval.decide",
                                "decision",
                                tuple(
                                    ControlChoice(
                                        value,
                                        "Allow once" if value == "once" else "Deny",
                                    )
                                    for value in pending.choices
                                ),
                            )
                        )
                    identity = ProviderSessionIdentity(
                        self.binding.provider_id,
                        session_id,
                        self.binding.binding_id,
                        self._record.capability_generation,
                    )
                    values.extend(
                        ControlValue(operation_id, "session", identity)
                        for operation_id in advertised
                    )
            else:
                blocked_reason = "hermes_session_identity_invalid"
        snapshot = ProviderControlSnapshot(
            provider_id=self.binding.provider_id,
            provider_version=self.binding.provider_version,
            provider_channel=self.binding.provider_channel,
            binding_id=self.binding.binding_id,
            capability_generation=self._record.capability_generation,
            observed_at=now,
            valid_until=now + _TARGET_SESSION_TTL_SECONDS,
            advertised_operations=tuple(advertised),
            values=tuple(values),
            choices=tuple(choices),
            blocked_reason=blocked_reason,
            provider_cursor=self._journal.cursor,
        )
        snapshot.validate(now=now)
        return snapshot

    def _snapshot_target_choices(
        self,
        *,
        session_id: str,
        session_response: HermesHTTPResponse,
        now: float,
    ) -> tuple[tuple[ControlChoice, ...], tuple[ControlChoice, ...]]:
        target_identity = ProviderSessionIdentity(
            self.binding.provider_id,
            session_id,
            self.binding.binding_id,
            self.capability_generation,
        )
        authorizations = [
            _TargetAuthorization(
                "session.fork",
                session_id,
                target_identity,
                now + _TARGET_SESSION_TTL_SECONDS,
            )
        ]
        fork_targets = (
            ControlChoice(session_id, "Current Hermes session"),
        )
        with self._lock:
            resume_session_ids = tuple(sorted(set(self._run_sessions.values())))
        resume_targets: list[ControlChoice] = []
        for target_index, target_session_id in enumerate(
            resume_session_ids,
            start=1,
        ):
            if not _safe_session_id(target_session_id):
                continue
            target_response = (
                session_response
                if target_session_id == session_id
                else self._transport.request(
                    "GET",
                    _session_path(target_session_id),
                    authenticated=True,
                )
            )
            if target_response.status != 200 or not _session_matches(
                target_response.body,
                target_session_id,
            ):
                continue
            identity = ProviderSessionIdentity(
                self.binding.provider_id,
                target_session_id,
                self.binding.binding_id,
                self.capability_generation,
            )
            authorizations.append(_TargetAuthorization(
                "session.resume",
                session_id,
                identity,
                now + _TARGET_SESSION_TTL_SECONDS,
            ))
            resume_targets.append(ControlChoice(
                target_session_id,
                f"Hermes owned session {target_index}",
            ))
        self._replace_target_authorizations(
            session_id,
            tuple(authorizations),
            now=now,
        )
        return tuple(resume_targets), fork_targets

    def _replace_target_authorizations(
        self,
        source_session_id: str,
        authorizations: tuple[_TargetAuthorization, ...],
        *,
        now: float,
    ) -> None:
        with self._lock:
            retained = {
                key: authorization
                for key, authorization in self._target_authorizations.items()
                if authorization.source_session_id != source_session_id
                and now < authorization.valid_until
            }
            retained.update({
                (
                    authorization.operation_id,
                    authorization.source_session_id,
                    authorization.target_identity.session_id,
                ): authorization
                for authorization in authorizations
            })
            self._target_authorizations = retained

    def _authorized_target_session(
        self,
        operation_id: str,
        source_session_id: str | None,
        value: Any,
    ) -> str | None:
        if (
            source_session_id is None
            or not _safe_session_id(source_session_id)
            or not _safe_session_id(value)
        ):
            return None
        now = time.time()
        key = (operation_id, source_session_id, value)
        with self._lock:
            authorization = self._target_authorizations.get(key)
            resume_owned = value in self._run_sessions.values()
        if (
            authorization is None
            or now >= authorization.valid_until
            or authorization.operation_id != operation_id
            or authorization.source_session_id != source_session_id
            or authorization.target_identity.provider_id
            != self.binding.provider_id
            or authorization.target_identity.session_id != value
            or authorization.target_identity.binding_id
            != self.binding.binding_id
            or authorization.target_identity.capability_generation
            != self.capability_generation
            or (operation_id == "session.fork" and value != source_session_id)
            or (operation_id == "session.resume" and not resume_owned)
        ):
            return None
        return value

    def _revalidate_target_session(
        self,
        operation_id: str,
        source_session_id: str | None,
        value: Any,
    ) -> tuple[tuple[str, dict[str, Any]] | None, str | None]:
        target_session_id = self._authorized_target_session(
            operation_id,
            source_session_id,
            value,
        )
        if target_session_id is None:
            return None, "target_session_not_owned_or_stale"
        response = self._transport.request(
            "GET",
            _session_path(target_session_id),
            authenticated=True,
        )
        if response.status != 200 or not _session_matches(
            response.body,
            target_session_id,
        ):
            with self._lock:
                self._target_authorizations.pop(
                    (operation_id, source_session_id, target_session_id),
                    None,
                )
            return None, "target_session_unavailable"
        return (
            target_session_id,
            _sanitize_session(response.body.get("session")),
        ), None

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
            or _ACTION_ID_RE.fullmatch(client_action_id or "") is None
            or capability_generation != self.capability_generation
            or not _session_truth_matches(
                self.binding,
                capability_generation,
                session_id,
                session_truth,
            )
        ):
            raise HermesRunsProtocolError(
                "Hermes operation correlation proof is unavailable"
            )
        snapshot = self.snapshot(
            session_id=session_id,
            session_truth=session_truth,
        )
        if operation_id not in snapshot.advertised_operations:
            raise HermesRunsProtocolError(
                "Hermes operation is not currently advertised"
            )
        correlation = ProviderOperationCorrelation(
            client_action_id,
            snapshot.provider_cursor,
        )
        if operation_id != "session.prompt.send":
            return correlation
        key = (client_action_id, session_id)
        with self._lock:
            existing = self._prepared_prompt_correlations.get(key)
            if existing is not None:
                return existing
            self._journal.append(
                "",
                {
                    "type": "operation.prepared",
                    "operation_id": operation_id,
                    "client_action_id": client_action_id,
                    "provider_cursor": correlation.provider_cursor,
                    "session_id": session_id,
                },
                durable=True,
            )
            self._prepared_prompt_correlations[key] = correlation
            while (
                len(self._prepared_prompt_correlations)
                > _MAX_ACTION_RESULTS
            ):
                oldest = next(
                    iter(self._prepared_prompt_correlations)
                )
                self._prepared_prompt_correlations.pop(oldest, None)
        return correlation

    def arm_operation_dispatch_boundary(
        self,
        *,
        operation_id: str,
        client_action_id: str,
        session_id: str,
        provider_correlation: ProviderOperationCorrelation,
        before_write: Callable[[], None],
    ) -> None:
        key = (client_action_id, session_id)
        with self._lock:
            if (
                operation_id != "session.prompt.send"
                or not callable(before_write)
                or self._prepared_prompt_correlations.get(key)
                != provider_correlation
                or client_action_id in self._dispatch_boundaries
            ):
                raise HermesRunsProtocolError(
                    "Hermes operation dispatch boundary is unavailable"
                )
            self._dispatch_boundaries[client_action_id] = before_write

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
        has_reserved_correlation = provider_correlation is not None
        if provider_correlation is None:
            provider_correlation = ProviderOperationCorrelation(
                client_action_id,
                self._journal.cursor,
            )
        elif (
            not isinstance(provider_correlation, ProviderOperationCorrelation)
            or provider_correlation.provider_operation_id
            != client_action_id
        ):
            raise HermesRunsProtocolError(
                "Hermes operation correlation proof is unavailable"
            )
        with self._execute_lock:
            try:
                result = self._execute_locked(
                    operation_id=operation_id,
                    input_payload=input_payload,
                    binding_id=binding_id,
                    capability_generation=capability_generation,
                    session_id=session_id,
                    client_action_id=client_action_id,
                    prepared_attachments=prepared_attachments,
                    provider_correlation=provider_correlation,
                )
            finally:
                if operation_id == "session.prompt.send":
                    with self._lock:
                        self._dispatch_boundaries.pop(
                            client_action_id,
                            None,
                        )
        if not has_reserved_correlation:
            return result
        normalized = ProviderOperationResult(
            operation_id=result.operation_id,
            provider_operation_id=provider_correlation.provider_operation_id,
            status=result.status,
            public_result=result.public_result,
            provider_cursor=provider_correlation.provider_cursor,
        )
        with self._lock:
            cached = self._actions.get(client_action_id)
            if cached is not None:
                self._actions[client_action_id] = _ActionResult(
                    cached.fingerprint,
                    cached.session_id,
                    normalized,
                )
        return normalized

    def _execute_locked(
        self,
        *,
        operation_id: str,
        input_payload: dict[str, Any],
        binding_id: str,
        capability_generation: int,
        session_id: str | None,
        client_action_id: str,
        prepared_attachments: tuple[Any, ...] = (),
        provider_correlation: ProviderOperationCorrelation,
    ) -> ProviderOperationResult:
        if (
            binding_id != self.binding.binding_id
            or capability_generation != self._record.capability_generation
        ):
            return self._result(
                operation_id,
                client_action_id or "invalid-action",
                OperationResultStatus.REJECTED,
                {"reason": "stale_binding"},
            )
        if _ACTION_ID_RE.fullmatch(client_action_id or "") is None:
            return self._result(
                operation_id,
                "invalid-action",
                OperationResultStatus.REJECTED,
                {"reason": "invalid_client_action_id"},
            )
        try:
            definition = REVIEWED_OPERATION_CATALOG.require(operation_id)
            normalized_input = definition.validate_input_payload(input_payload)
        except OperationCatalogError:
            return self._result(
                operation_id,
                client_action_id,
                OperationResultStatus.REJECTED,
                {"reason": "operation_input_not_reviewed"},
            )
        fingerprint = _action_fingerprint(operation_id, normalized_input, session_id)
        with self._lock:
            previous = self._actions.get(client_action_id)
        if previous is not None:
            if previous.fingerprint == fingerprint:
                return previous.result
            return self._result(
                operation_id,
                client_action_id,
                OperationResultStatus.REJECTED,
                {"reason": "client_action_id_reused"},
            )
        if prepared_attachments:
            result = self._result(
                operation_id,
                client_action_id,
                OperationResultStatus.REJECTED,
                {"reason": "attachments_not_supported"},
            )
            self._remember_action(client_action_id, fingerprint, session_id, result)
            return result
        if operation_id.startswith("session."):
            identity = _session_identity(normalized_input.get("session"))
            if (
                not session_id
                or identity is None
                or identity.provider_id != self.binding.provider_id
                or identity.session_id != session_id
                or identity.binding_id != self.binding.binding_id
                or identity.capability_generation != self.capability_generation
            ):
                result = self._result(
                    operation_id,
                    client_action_id,
                    OperationResultStatus.REJECTED,
                    {"reason": "session_identity_mismatch"},
                )
                self._remember_action(
                    client_action_id,
                    fingerprint,
                    session_id,
                    result,
                )
                return result
        elif session_id is not None:
            result = self._result(
                operation_id,
                client_action_id,
                OperationResultStatus.REJECTED,
                {"reason": "provider_operation_has_session"},
            )
            self._remember_action(client_action_id, fingerprint, session_id, result)
            return result
        if (
            operation_id in {"session.resume", "session.fork"}
            and self._authorized_target_session(
                operation_id,
                session_id,
                normalized_input.get("target_session"),
            )
            is None
        ):
            result = self._result(
                operation_id,
                client_action_id,
                OperationResultStatus.REJECTED,
                {"reason": "target_session_not_owned_or_stale"},
            )
            self._remember_action(client_action_id, fingerprint, session_id, result)
            return result
        if operation_id == "session.approval.decide":
            approval_id = normalized_input.get("approval_id")
            decision = normalized_input.get("decision")
            with self._lock:
                pending = self._pending_approvals.get(approval_id)
                approval_is_pending = (
                    pending is not None
                    and pending.session_id == session_id
                    and pending.generation == self._record.capability_generation
                    and decision in pending.choices
                )
            if not approval_is_pending:
                result = self._result(
                    operation_id,
                    client_action_id,
                    OperationResultStatus.REJECTED,
                    {"reason": "approval_not_pending"},
                )
                self._remember_action(
                    client_action_id,
                    fingerprint,
                    session_id,
                    result,
                )
                return result
        probe = self._probe_runtime()
        blocked = probe.blocked_reason or self._unsafe_runtime_reason
        if blocked is not None:
            result = self._result(
                operation_id,
                client_action_id,
                OperationResultStatus.REJECTED,
                {"reason": blocked},
            )
            self._remember_action(client_action_id, fingerprint, session_id, result)
            return result
        handler = {
            "session.prompt.send": self._execute_prompt,
            "session.turn.interrupt": self._execute_interrupt,
            "session.resume": self._execute_resume,
            "session.fork": self._execute_fork,
            "session.model.set": self._execute_model_set,
            "session.approval.decide": self._execute_approval,
            "provider.usage.read": self._execute_usage,
            "provider.diagnostics.read": self._execute_diagnostics,
        }.get(operation_id)
        if handler is None:
            result = self._result(
                operation_id,
                client_action_id,
                OperationResultStatus.REJECTED,
                {"reason": "operation_not_supported"},
            )
        else:
            execute_args = {
                "operation_id": operation_id,
                "payload": normalized_input,
                "session_id": session_id,
                "client_action_id": client_action_id,
                "probe": probe,
            }
            if operation_id == "session.prompt.send":
                execute_args["provider_correlation"] = provider_correlation
            result = handler(**execute_args)
        self._remember_action(
            client_action_id,
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
        elif not _session_truth_matches(
            self.binding,
            capability_generation,
            session_id,
            session_truth,
        ):
            return None
        with self._lock:
            action = self._actions.get(client_action_id)
        if (
            action is None
            or action.session_id != session_id
            or action.result.operation_id != operation_id
            or action.result.provider_operation_id
            != provider_correlation.provider_operation_id
            or action.result.provider_cursor != provider_correlation.provider_cursor
            or action.result.status
            not in {
                OperationResultStatus.APPLIED,
                OperationResultStatus.REJECTED,
            }
        ):
            return None
        return action.result

    def consume_run_events(self, run_id: str) -> None:
        if not _safe_run_id(run_id):
            raise HermesRunsProtocolError("invalid Hermes run id")
        with self._lock:
            if run_id not in self._run_sessions:
                raise HermesRunsProtocolError(
                    "Hermes run is not owned by this driver"
                )
        terminal_seen = False
        try:
            for provider_event in self._transport.stream_sse(
                _run_path(run_id, "/events"),
                authenticated=True,
            ):
                normalized = self._normalize_event(run_id, provider_event)
                if normalized is None:
                    continue
                self._journal.append(run_id, normalized)
                terminal_seen = normalized["type"] in {
                    "run.completed",
                    "run.failed",
                    "run.cancelled",
                }
        except Exception as exc:
            self._journal.append(
                run_id,
                {
                    "type": "transport.disconnected",
                    "reason": _bounded_text(exc, 256),
                },
            )
        if not terminal_seen:
            self._reconcile_run_status(run_id)

    def events_after(self, run_id: str, *, cursor: str | None) -> list[dict[str, Any]]:
        if not _safe_run_id(run_id):
            raise HermesRunsProtocolError("invalid Hermes run id")
        return [self._safe_value(row) for row in self._journal.after(run_id, cursor)]

    def _probe_runtime(self) -> _ProbeResult:
        try:
            self._record.validate()
        except HermesRunsError:
            return _ProbeResult("hermes_owned_server_record_invalid", {}, (), {})
        if (
            self.binding.provider_id != "hermes_agent"
            or self._record.binding_id != self.binding.binding_id
            or self._record.provider_version != self.binding.provider_version
            or self._record.provider_channel != self.binding.provider_channel
        ):
            return _ProbeResult("hermes_owned_binding_stale", {}, (), {})
        if self.binding.provider_version != SUPPORTED_HERMES_VERSION:
            return _ProbeResult("hermes_version_unsupported", {}, (), {})
        if self.binding.provider_channel != SUPPORTED_HERMES_CHANNEL:
            return _ProbeResult("hermes_channel_unsupported", {}, (), {})
        if not isinstance(self._bearer, str) or len(self._bearer.encode("utf-8")) < 32:
            return _ProbeResult("hermes_internal_bearer_unavailable", {}, (), {})
        try:
            if not self._ownership_probe(self._record):
                return _ProbeResult("hermes_owned_process_handle_required", {}, (), {})
        except Exception:
            return _ProbeResult("hermes_ownership_probe_failed", {}, (), {})
        try:
            policy = self._policy_probe(self._record)
        except Exception:
            return _ProbeResult("hermes_policy_probe_failed", {}, (), {})
        if policy.approval_mode != "manual":
            return _ProbeResult("hermes_manual_approval_required", {}, (), {})
        if policy.cron_mode != "deny":
            return _ProbeResult("hermes_cron_auto_approval_rejected", {}, (), {})
        if policy.yolo_enabled:
            return _ProbeResult("hermes_yolo_mode_rejected", {}, (), {})
        if policy.launch_digest != self._record.launch_digest:
            return _ProbeResult("hermes_launch_config_stale", {}, (), {})
        try:
            health = self._transport.request("GET", "/health/detailed", authenticated=True)
            if health.status != 200:
                return _ProbeResult("hermes_owned_server_unreachable", {}, (), {})
            status = health.body
            if (
                status.get("platform") != "hermes-agent"
                or status.get("version") != self.binding.provider_version
                or status.get("pid") != self._record.pid
            ):
                return _ProbeResult("hermes_owned_process_identity_mismatch", {}, (), status)
            if status.get("status") not in {"ok", "ready"}:
                return _ProbeResult("hermes_runtime_not_ready", {}, (), status)
            readiness = status.get("readiness")
            if (
                isinstance(readiness, Mapping)
                and readiness.get("status") not in {"ok", "ready"}
            ):
                return _ProbeResult("hermes_runtime_not_ready", {}, (), status)
            if not _api_server_isolated(status.get("platforms")):
                return _ProbeResult("hermes_owned_process_not_isolated", {}, (), status)
            unauthenticated = self._transport.request(
                "GET", "/v1/capabilities", authenticated=False
            )
            if unauthenticated.status != 401:
                return _ProbeResult("hermes_unauthenticated_server_rejected", {}, (), status)
            denied_stop = self._transport.request(
                "POST", _DENIED_WRITE_CANARY_PATH, authenticated=False
            )
            if denied_stop.status != 401:
                return _ProbeResult("hermes_denied_write_canary_failed", {}, (), status)
            authenticated_stop = self._transport.request(
                "POST", _DENIED_WRITE_CANARY_PATH, authenticated=True
            )
            if authenticated_stop.status != 404:
                return _ProbeResult("hermes_denied_write_canary_ambiguous", {}, (), status)
            capabilities_response = self._transport.request(
                "GET", "/v1/capabilities", authenticated=True
            )
            if capabilities_response.status != 200:
                return _ProbeResult("hermes_capability_probe_failed", {}, (), status)
            capabilities = capabilities_response.body
            reason = _capability_rejection(capabilities)
            if reason is not None:
                return _ProbeResult(reason, capabilities, (), status)
            model_aliases: tuple[str, ...] = ()
            if _feature_enabled(capabilities, "session_model_lock"):
                models_response = self._transport.request("GET", "/v1/models", authenticated=True)
                if models_response.status == 200:
                    model_aliases = _routable_model_aliases(models_response.body)
            return _ProbeResult(None, capabilities, model_aliases, status)
        except HermesRunsError:
            return _ProbeResult("hermes_transport_probe_failed", {}, (), {})

    def _execute_prompt(
        self,
        *,
        operation_id,
        payload,
        session_id,
        client_action_id,
        probe,
        provider_correlation,
    ):
        del probe
        prompt = payload.get("prompt")
        if not isinstance(prompt, str) or not prompt:
            return self._result(
                operation_id,
                client_action_id,
                OperationResultStatus.REJECTED,
                {"reason": "prompt_required"},
            )
        with self._lock:
            existing_run = self._active_runs.get(session_id)
        if existing_run and self._run_is_active(existing_run):
            return self._result(
                operation_id,
                existing_run,
                OperationResultStatus.REJECTED,
                {
                    "reason": "run_already_active",
                    "run_id": existing_run,
                },
            )
        with self._lock:
            before_write = self._dispatch_boundaries.pop(
                client_action_id,
                None,
            )
        if before_write is not None:
            before_write()
        response = self._transport.request(
            "POST",
            "/v1/runs",
            payload={"input": prompt, "session_id": session_id},
            authenticated=True,
        )
        run_id = (
            response.body.get("run_id")
            if response.status == 202
            else None
        )
        if (
            not _safe_run_id(run_id)
            or response.body.get("status") != "started"
        ):
            return self._result(
                operation_id,
                client_action_id,
                OperationResultStatus.REJECTED,
                {"reason": "run_start_rejected"},
            )
        with self._lock:
            self._active_runs[session_id] = run_id
            self._run_sessions[run_id] = session_id
        self._journal.append(
            run_id,
            {
                "type": "run.started",
                "session_id": session_id,
                "operation_id": operation_id,
                "client_action_id": client_action_id,
                "provider_cursor": provider_correlation.provider_cursor,
            },
            durable=True,
        )
        if self._auto_stream:
            thread = threading.Thread(
                target=self.consume_run_events,
                args=(run_id,),
                daemon=True,
                name=f"pairling-hermes-{run_id[:24]}",
            )
            with self._lock:
                self._stream_threads[run_id] = thread
            thread.start()
        return self._result(
            operation_id,
            run_id,
            OperationResultStatus.APPLIED,
            {
                "run_id": run_id,
                "session_id": session_id,
                "status": "started",
            },
        )

    def _execute_interrupt(self, *, operation_id, payload, session_id, client_action_id, probe):
        del payload, probe
        with self._lock:
            run_id = self._active_runs.get(session_id)
        if not run_id or not self._run_is_active(run_id):
            return self._result(operation_id, client_action_id, OperationResultStatus.REJECTED, {"reason": "run_not_active"})
        response = self._transport.request("POST", _run_path(run_id, "/stop"), authenticated=True)
        if response.status != 200 or response.body.get("status") != "stopping":
            return self._result(operation_id, run_id, OperationResultStatus.OUTCOME_UNKNOWN, {"run_id": run_id, "status": "outcome_unknown"})
        self._journal.append(run_id, {"type": "run.stopping"})
        return self._result(operation_id, run_id, OperationResultStatus.APPLIED, {"run_id": run_id, "status": "stopping"})

    def _execute_resume(
        self,
        *,
        operation_id,
        payload,
        session_id,
        client_action_id,
        probe,
    ):
        del probe
        target, reason = self._revalidate_target_session(
            operation_id,
            session_id,
            payload.get("target_session"),
        )
        if target is None:
            return self._result(
                operation_id,
                client_action_id,
                OperationResultStatus.REJECTED,
                {"reason": reason},
            )
        target_session_id, session = target
        return self._result(
            operation_id,
            f"session:{target_session_id}",
            OperationResultStatus.APPLIED,
            {"session": session, "resumed": True},
        )

    def _execute_fork(self, *, operation_id, payload, session_id, client_action_id, probe):
        del probe
        target, reason = self._revalidate_target_session(
            operation_id,
            session_id,
            payload.get("target_session"),
        )
        if target is None:
            return self._result(
                operation_id,
                client_action_id,
                OperationResultStatus.REJECTED,
                {"reason": reason},
            )
        target_session_id, _ = target
        response = self._transport.request(
            "POST",
            _session_path(target_session_id, "/fork"),
            payload={},
            authenticated=True,
        )
        child = response.body.get("session") if response.status == 201 else None
        child_id = child.get("id") if isinstance(child, Mapping) else None
        if not _safe_session_id(child_id):
            return self._result(
                operation_id,
                client_action_id,
                OperationResultStatus.REJECTED,
                {"reason": "session_fork_rejected"},
            )
        return self._result(
            operation_id,
            f"session:{child_id}",
            OperationResultStatus.APPLIED,
            {"session": _sanitize_session(child)},
        )

    def _execute_model_set(self, *, operation_id, payload, session_id, client_action_id, probe):
        model = payload.get("model")
        if not isinstance(model, str) or model not in probe.model_aliases:
            return self._result(operation_id, client_action_id, OperationResultStatus.REJECTED, {"reason": "model_not_advertised"})
        response = self._transport.request(
            "POST", _session_path(session_id, "/model"), payload={"model": model}, authenticated=True
        )
        runtime = response.body.get("runtime") if response.status == 200 else None
        if (
            response.body.get("object") != "hermes.session.model_lock"
            or response.body.get("session_id") != session_id
            or not isinstance(runtime, Mapping)
            or runtime.get("model") != model
            or runtime.get("model_lock") != "accepted"
        ):
            return self._result(operation_id, client_action_id, OperationResultStatus.OUTCOME_UNKNOWN, {"reason": "model_lock_not_acknowledged"})
        return self._result(operation_id, f"session:{session_id}:model", OperationResultStatus.APPLIED, {"session_id": session_id, "model": model})

    def _execute_approval(self, *, operation_id, payload, session_id, client_action_id, probe):
        del probe
        approval_id = payload.get("approval_id")
        decision = payload.get("decision")
        with self._lock:
            pending = self._pending_approvals.get(approval_id)
            if (
                pending is None
                or pending.session_id != session_id
                or pending.generation != self._record.capability_generation
                or decision not in pending.choices
            ):
                return self._result(
                    operation_id,
                    client_action_id,
                    OperationResultStatus.REJECTED,
                    {"reason": "approval_not_pending"},
                )
            status_response = self._transport.request(
                "GET",
                _run_path(pending.run_id),
                authenticated=True,
            )
            if (
                status_response.status != 200
                or status_response.body.get("status") != "waiting_for_approval"
                or self._pending_approvals.get(approval_id) != pending
            ):
                self._drop_pending(approval_id)
                return self._result(
                    operation_id,
                    pending.run_id,
                    OperationResultStatus.REJECTED,
                    {"reason": "approval_no_longer_pending"},
                )
            response = self._transport.request(
                "POST",
                _run_path(pending.run_id, "/approval"),
                payload={"choice": decision, "all": False},
                authenticated=True,
            )
            if (
                response.status != 200
                or response.body.get("object") != "hermes.run.approval_response"
                or response.body.get("run_id") != pending.run_id
                or response.body.get("choice") != decision
                or response.body.get("resolved") != 1
            ):
                return self._result(
                    operation_id,
                    pending.run_id,
                    OperationResultStatus.OUTCOME_UNKNOWN,
                    {
                        "run_id": pending.run_id,
                        "reason": "approval_outcome_unknown",
                    },
                )
            self._drop_pending(approval_id)
        self._journal.append(
            pending.run_id,
            {
                "type": "approval.responded",
                "approval_id": approval_id,
                "decision": decision,
                "resolved": 1,
            },
        )
        return self._result(
            operation_id,
            f"{pending.run_id}:{approval_id}",
            OperationResultStatus.APPLIED,
            {
                "run_id": pending.run_id,
                "decision": decision,
                "resolved": 1,
            },
        )

    def _execute_usage(self, *, operation_id, payload, session_id, client_action_id, probe):
        del payload, session_id, probe
        rows = []
        with self._lock:
            run_ids = tuple(self._run_sessions)
        for run_id in run_ids[-64:]:
            response = self._transport.request("GET", _run_path(run_id), authenticated=True)
            if response.status != 200:
                continue
            status = response.body
            usage = status.get("usage")
            if isinstance(usage, Mapping):
                rows.append({"run_id": run_id, "session_id": status.get("session_id"), "status": status.get("status"), "model": status.get("model"), "usage": _sanitize_usage(usage)})
        return self._result(operation_id, f"usage:{self._journal.cursor}", OperationResultStatus.APPLIED, {"runs": rows})

    def _execute_diagnostics(self, *, operation_id, payload, session_id, client_action_id, probe):
        del payload, session_id
        return self._result(
            operation_id,
            f"diagnostics:{self._journal.cursor}",
            OperationResultStatus.APPLIED,
            {
                "provider": "hermes-agent",
                "version": self.binding.provider_version,
                "channel": self.binding.provider_channel,
                "authenticated": True,
                "approval_mode": "manual",
                "cron_mode": "deny",
                "runtime_status": probe.status.get("status"),
                "model": probe.capabilities.get("model"),
                "event_cursor": self._journal.cursor,
            },
        )

    def _normalize_event(self, run_id: str, raw: Mapping[str, Any]) -> dict[str, Any] | None:
        if not isinstance(raw, Mapping):
            return None
        event_type = raw.get("event")
        if not isinstance(event_type, str) or not event_type:
            return None
        session_id = self._run_sessions.get(run_id, "")
        if raw.get("run_id") not in (None, run_id):
            self._unsafe_runtime_reason = "hermes_event_run_mismatch"
            return None
        if event_type == "message.delta":
            return {"type": event_type, "delta": self._safe_text(raw.get("delta", ""))}
        if event_type in {"tool.started", "tool.completed", "tool.failed"}:
            return {
                "type": event_type,
                "tool": self._safe_text(raw.get("tool", ""), 512),
                "preview": self._safe_text(raw.get("preview", ""), 4096),
                "duration": _finite_number_or_none(raw.get("duration")),
                "error": bool(raw.get("error", event_type == "tool.failed")),
            }
        if event_type == "approval.request":
            if raw.get("smart_denied"):
                self._unsafe_runtime_reason = "hermes_smart_approval_event_rejected"
                return {"type": "approval.rejected", "reason": "smart_approval_not_supported"}
            choices = tuple(choice for choice in ("once", "deny") if choice in _approval_choices(raw.get("choices")))
            if choices != ("once", "deny"):
                self._unsafe_runtime_reason = "hermes_approval_choices_unsafe"
                return {"type": "approval.rejected", "reason": "approval_choices_unsafe"}
            approval_id = _approval_id(run_id, raw, self._record.capability_generation)
            pending = _PendingApproval(approval_id, run_id, session_id, self._record.capability_generation, choices)
            with self._lock:
                existing_id = self._pending_by_run.get(run_id)
                if existing_id and existing_id != approval_id:
                    self._unsafe_runtime_reason = "hermes_approval_correlation_ambiguous"
                    self._drop_pending(existing_id)
                    return {"type": "approval.rejected", "reason": "approval_correlation_ambiguous"}
                self._pending_approvals[approval_id] = pending
                self._pending_by_run[run_id] = approval_id
            return {
                "type": event_type,
                "approval_id": approval_id,
                "command": self._safe_text(raw.get("command", ""), 4096),
                "pattern_key": self._safe_text(raw.get("pattern_key", ""), 512),
                "choices": list(choices),
            }
        if event_type == "approval.responded":
            return {"type": event_type, "decision": self._safe_text(raw.get("choice", ""), 64), "resolved": int(raw.get("resolved") or 0)}
        if event_type in {"run.completed", "run.failed", "run.cancelled"}:
            usage = _sanitize_usage(raw.get("usage")) if isinstance(raw.get("usage"), Mapping) else None
            with self._lock:
                if self._active_runs.get(session_id) == run_id:
                    self._active_runs.pop(session_id, None)
                pending_id = self._pending_by_run.get(run_id)
                if pending_id:
                    self._drop_pending(pending_id)
            normalized = {"type": event_type}
            if event_type == "run.completed":
                normalized["output"] = self._safe_text(raw.get("output", ""))
            else:
                normalized["error"] = self._safe_text(raw.get("error", ""), 4096)
            if usage is not None:
                normalized["usage"] = usage
            return normalized
        if event_type in {"subagent.start", "subagent.complete", "reasoning.available"}:
            return {"type": event_type, "data": self._safe_value(raw)}
        return {
            "type": "provider.extension",
            "provider_event": self._safe_text(event_type, 256),
            "data": self._safe_value(raw),
        }

    def _safe_text(self, value: Any, limit: int = _MAX_TEXT_BYTES) -> str:
        return _bounded_text(_redact_exact_secret(value, self._bearer), limit)

    def _safe_value(self, value: Any) -> Any:
        return _redact_exact_secret(_sanitize(value), self._bearer)

    def _reconcile_run_status(self, run_id: str) -> None:
        response = self._transport.request("GET", _run_path(run_id), authenticated=True)
        if response.status != 200:
            return
        status = response.body
        with self._lock:
            self._last_statuses[run_id] = dict(status)
        state = status.get("status")
        if state in {"completed", "failed", "cancelled"}:
            event = {"event": f"run.{state}", "run_id": run_id}
            if state == "completed":
                event["output"] = status.get("output", "")
                event["usage"] = status.get("usage", {})
            else:
                event["error"] = status.get("error", "")
            normalized = self._normalize_event(run_id, event)
            if normalized is not None:
                self._journal.append(run_id, normalized)

    def _run_is_active(self, run_id: str) -> bool:
        response = self._transport.request("GET", _run_path(run_id), authenticated=True)
        if response.status != 200:
            return False
        with self._lock:
            self._last_statuses[run_id] = dict(response.body)
        return response.body.get("status") in {"queued", "running", "waiting_for_approval", "stopping"}

    def _pending_for_session(self, session_id: str) -> _PendingApproval | None:
        with self._lock:
            matches = [item for item in self._pending_approvals.values() if item.session_id == session_id]
        if len(matches) != 1:
            if len(matches) > 1:
                self._unsafe_runtime_reason = "hermes_approval_correlation_ambiguous"
            return None
        return matches[0]

    def _drop_pending(self, approval_id: str) -> None:
        pending = self._pending_approvals.pop(approval_id, None)
        if pending is not None and self._pending_by_run.get(pending.run_id) == approval_id:
            self._pending_by_run.pop(pending.run_id, None)

    def _restore_correlated_prompt_actions(self) -> None:
        rows = self._journal.records()
        for row in rows:
            if (
                row.get("type") != "operation.prepared"
                or row.get("operation_id") != "session.prompt.send"
            ):
                continue
            action_id = row.get("client_action_id")
            session_id = row.get("session_id")
            provider_cursor = row.get("provider_cursor")
            if (
                not isinstance(action_id, str)
                or _ACTION_ID_RE.fullmatch(action_id) is None
                or not _safe_session_id(session_id)
                or not isinstance(provider_cursor, str)
            ):
                continue
            try:
                generation, _ = self._journal._parse_cursor(
                    provider_cursor
                )
            except HermesEventCursorExpired:
                continue
            if generation != self.capability_generation:
                continue
            self._prepared_prompt_correlations[(action_id, session_id)] = (
                ProviderOperationCorrelation(action_id, provider_cursor)
            )
        for row in rows:
            if (
                row.get("type") != "run.started"
                or row.get("operation_id") != "session.prompt.send"
            ):
                continue
            action_id = row.get("client_action_id")
            run_id = row.get("run_id")
            session_id = row.get("session_id")
            provider_cursor = row.get("provider_cursor")
            if (
                not isinstance(action_id, str)
                or _ACTION_ID_RE.fullmatch(action_id) is None
                or not _safe_run_id(run_id)
                or not _safe_session_id(session_id)
                or not isinstance(provider_cursor, str)
            ):
                continue
            try:
                generation, _ = self._journal._parse_cursor(
                    provider_cursor
                )
            except HermesEventCursorExpired:
                continue
            if generation != self.capability_generation:
                continue
            correlation = ProviderOperationCorrelation(
                action_id,
                provider_cursor,
            )
            self._prepared_prompt_correlations[
                (action_id, session_id)
            ] = correlation
            result = ProviderOperationResult(
                operation_id="session.prompt.send",
                provider_operation_id=action_id,
                status=OperationResultStatus.APPLIED,
                public_result={
                    "run_id": run_id,
                    "session_id": session_id,
                    "status": "started",
                },
                provider_cursor=provider_cursor,
            )
            self._actions[action_id] = _ActionResult(
                f"journal:{row.get('cursor')}",
                session_id,
                result,
            )
            self._action_order.append(action_id)
            self._active_runs[session_id] = run_id
            self._run_sessions[run_id] = session_id
        while len(self._action_order) > _MAX_ACTION_RESULTS:
            oldest = self._action_order.popleft()
            self._actions.pop(oldest, None)
        while (
            len(self._prepared_prompt_correlations)
            > _MAX_ACTION_RESULTS
        ):
            oldest = next(iter(self._prepared_prompt_correlations))
            self._prepared_prompt_correlations.pop(oldest, None)

    def _remember_action(
        self,
        action_id: str,
        fingerprint: str,
        session_id: str | None,
        result: ProviderOperationResult,
    ) -> None:
        with self._lock:
            if action_id in self._actions:
                return
            self._actions[action_id] = _ActionResult(
                fingerprint,
                session_id,
                result,
            )
            self._action_order.append(action_id)
            while len(self._action_order) > _MAX_ACTION_RESULTS:
                oldest = self._action_order.popleft()
                self._actions.pop(oldest, None)

    def _result(
        self,
        operation_id,
        provider_operation_id,
        status,
        public_result,
    ):
        return ProviderOperationResult(
            operation_id=operation_id,
            provider_operation_id=self._safe_text(
                provider_operation_id,
                512,
            ),
            status=status,
            public_result=self._safe_value(public_result),
            provider_cursor=self._journal.cursor,
        )


def _validated_loopback_base_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or parsed.port is None
        or not (1 <= parsed.port <= 65535)
    ):
        raise HermesRunsProtocolError(
            "Hermes server must use authenticated loopback HTTP"
        )
    host = (
        f"[{parsed.hostname}]"
        if ":" in parsed.hostname
        else parsed.hostname
    )
    return f"http://{host}:{parsed.port}"


def _bounded_read(response, limit: int) -> bytes:
    raw = response.read(limit + 1)
    if len(raw) > limit:
        raise HermesRunsProtocolError(
            "Hermes response exceeds size limit"
        )
    return raw


def _decode_json_object(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise HermesRunsProtocolError(
            "Hermes returned invalid JSON"
        ) from exc
    if not isinstance(value, dict):
        raise HermesRunsProtocolError(
            "Hermes returned a non-object JSON payload"
        )
    return value


def _bounded_text(value: Any, limit: int = _MAX_TEXT_BYTES) -> str:
    text = value if isinstance(value, str) else str(value)
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= limit:
        return text
    return raw[:limit].decode("utf-8", errors="ignore") + "…"


def _sanitize(value: Any, *, key: str = "", depth: int = 0) -> Any:
    lowered = key.casefold().replace("-", "_")
    if key and any(part in lowered for part in _SECRET_KEY_PARTS):
        return "[redacted]"
    if depth > 8:
        return "[bounded]"
    if isinstance(value, Mapping):
        result = {}
        for index, (child_key, child_value) in enumerate(value.items()):
            if index >= 128:
                break
            safe_key = _bounded_text(child_key, 256)
            result[safe_key] = _sanitize(child_value, key=safe_key, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [_sanitize(item, depth=depth + 1) for item in list(value)[:256]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _bounded_text(value)

def _redact_exact_secret(value: Any, secret: str) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _redact_exact_secret(child, secret) for key, child in value.items()}
    if isinstance(value, list):
        return [_redact_exact_secret(item, secret) for item in value]
    if isinstance(value, tuple):
        return [_redact_exact_secret(item, secret) for item in value]
    if isinstance(value, str) and secret:
        return value.replace(secret, "[redacted]")
    return value


def _safe_session_id(value: Any) -> bool:
    return isinstance(value, str) and _SESSION_ID_RE.fullmatch(value) is not None


def _safe_run_id(value: Any) -> bool:
    return isinstance(value, str) and _RUN_ID_RE.fullmatch(value) is not None


def _fixed_request_route(method: str, path: str) -> bool:
    if (method, path) in {
        ("GET", "/health/detailed"),
        ("GET", "/v1/capabilities"),
        ("GET", "/v1/models"),
        ("POST", "/api/sessions"),
        ("POST", "/v1/runs"),
        ("POST", _DENIED_WRITE_CANARY_PATH),
    }:
        return True
    if path.startswith("/v1/runs/"):
        remainder = path.removeprefix("/v1/runs/")
        run_id, separator, suffix = remainder.partition("/")
        if not _safe_run_id(run_id):
            return False
        return (method, suffix if separator else "") in {
            ("GET", ""),
            ("STREAM", "events"),
            ("POST", "approval"),
            ("POST", "stop"),
        }
    if path.startswith("/api/sessions/"):
        remainder = path.removeprefix("/api/sessions/")
        encoded_id, separator, suffix = remainder.partition("/")
        session_id = urllib.parse.unquote(encoded_id)
        if (
            not _safe_session_id(session_id)
            or urllib.parse.quote(session_id, safe="") != encoded_id
        ):
            return False
        return (method, suffix if separator else "") in {
            ("GET", ""),
            ("POST", "fork"),
            ("POST", "model"),
        }
    return False


def _session_path(session_id: str, suffix: str = "") -> str:
    if not _safe_session_id(session_id):
        raise HermesRunsProtocolError("invalid Hermes session id")
    return "/api/sessions/" + urllib.parse.quote(session_id, safe="") + suffix


def _run_path(run_id: str, suffix: str = "") -> str:
    if not _safe_run_id(run_id):
        raise HermesRunsProtocolError("invalid Hermes run id")
    return "/v1/runs/" + run_id + suffix


def _session_matches(payload: Mapping[str, Any], session_id: str) -> bool:
    session = payload.get("session")
    return payload.get("object") == "hermes.session" and isinstance(session, Mapping) and session.get("id") == session_id


def _session_truth_matches(
    binding: ProviderControlBinding,
    capability_generation: int,
    session_id: str,
    truth: Mapping[str, Any] | None,
) -> bool:
    if not isinstance(truth, Mapping):
        return False
    expected = {
        "provider_id": binding.provider_id,
        "session_id": session_id,
        "binding_id": binding.binding_id,
        "capability_generation": capability_generation,
        "is_live": True,
        "controllable": True,
    }
    if any(truth.get(key) != value for key, value in expected.items()):
        return False
    instance_id = truth.get("session_instance_id")
    return isinstance(instance_id, str) and 0 < len(instance_id) <= 512


def _session_identity(value: Any) -> ProviderSessionIdentity | None:
    try:
        return ProviderSessionIdentity.from_payload(value)
    except Exception:
        return None


def _sanitize_session(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    allowed = (
        "id",
        "title",
        "model",
        "source",
        "parent_session_id",
        "end_reason",
        "started_at",
        "last_active",
        "message_count",
        "input_tokens",
        "output_tokens",
    )
    return {key: _sanitize(value[key], key=key) for key in allowed if key in value}


def _sanitize_usage(value: Mapping[str, Any]) -> dict[str, Any]:
    allowed = ("input_tokens", "output_tokens", "total_tokens", "reasoning_tokens", "cost_usd", "api_calls")
    result = {}
    for key in allowed:
        item = value.get(key)
        if isinstance(item, (int, float)) and not isinstance(item, bool):
            result[key] = item
    return result


def _finite_number_or_none(value: Any) -> int | float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    return None


def _capability_rejection(payload: Mapping[str, Any]) -> str | None:
    if payload.get("object") != "hermes.api_server.capabilities" or payload.get("platform") != "hermes-agent":
        return "hermes_capability_identity_mismatch"
    auth = payload.get("auth")
    if not isinstance(auth, Mapping) or auth.get("type") != "bearer" or auth.get("required") is not True:
        return "hermes_bearer_auth_required"
    runtime = payload.get("runtime")
    if (
        not isinstance(runtime, Mapping)
        or runtime.get("mode") != "server_agent"
        or runtime.get("tool_execution") != "server"
        or runtime.get("split_runtime") is not False
    ):
        return "hermes_runtime_mode_unsafe"
    features = payload.get("features")
    if not isinstance(features, Mapping) or any(features.get(name) is not True for name in _REQUIRED_FEATURES):
        return "hermes_required_capability_missing"
    if features.get("admin_config_rw") is not False:
        return "hermes_admin_config_surface_rejected"
    endpoints = payload.get("endpoints")
    if not isinstance(endpoints, Mapping):
        return "hermes_endpoint_manifest_missing"
    for name, (method, path) in _REQUIRED_ENDPOINTS.items():
        row = endpoints.get(name)
        if not isinstance(row, Mapping) or row.get("method") != method or row.get("path") != path:
            return "hermes_endpoint_manifest_mismatch"
    return None


def _feature_enabled(capabilities: Mapping[str, Any], feature: str) -> bool:
    features = capabilities.get("features")
    return isinstance(features, Mapping) and features.get(feature) is True


def _endpoint_matches(
    capabilities: Mapping[str, Any],
    name: str,
    method: str,
    path: str,
) -> bool:
    endpoints = capabilities.get("endpoints")
    row = endpoints.get(name) if isinstance(endpoints, Mapping) else None
    return (
        isinstance(row, Mapping)
        and row.get("method") == method
        and row.get("path") == path
    )


def _routable_model_aliases(payload: Mapping[str, Any]) -> tuple[str, ...]:
    rows = payload.get("data")
    if not isinstance(rows, list):
        return ()
    aliases = []
    for row in rows[:256]:
        if not isinstance(row, Mapping) or not isinstance(row.get("parent"), str):
            continue
        model_id = row.get("id")
        if isinstance(model_id, str) and 0 < len(model_id) <= 256 and "\x00" not in model_id:
            aliases.append(model_id)
    return tuple(dict.fromkeys(aliases))


def _api_server_isolated(platforms: Any) -> bool:
    if not isinstance(platforms, Mapping):
        return False
    api = platforms.get("api_server")
    if not _platform_active(api):
        return False
    for name, value in platforms.items():
        if name != "api_server" and _platform_active(value):
            return False
    return True


def _platform_active(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.casefold() in {"connected", "ready", "running", "started"}
    if isinstance(value, Mapping):
        if value.get("connected") is True or value.get("enabled") is True:
            return True
        return str(value.get("status") or value.get("state") or "").casefold() in {
            "connected",
            "ready",
            "running",
            "started",
        }
    return False


def _approval_choices(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    choices = set()
    for item in value:
        if isinstance(item, str):
            choices.add(item)
        elif isinstance(item, Mapping) and isinstance(item.get("id"), str):
            choices.add(item["id"])
        elif isinstance(item, Mapping) and isinstance(item.get("choice"), str):
            choices.add(item["choice"])
    return choices


def _approval_id(run_id: str, raw: Mapping[str, Any], generation: int) -> str:
    proof = {
        "run_id": run_id,
        "generation": generation,
        "timestamp": raw.get("timestamp"),
        "command": raw.get("command"),
        "pattern_key": raw.get("pattern_key"),
        "pattern_keys": raw.get("pattern_keys"),
    }
    digest = hashlib.sha256(json.dumps(proof, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()
    return "hermes-approval-" + digest[:32]


def _action_fingerprint(operation_id: str, payload: Mapping[str, Any], session_id: str | None) -> str:
    canonical = json.dumps({"operation_id": operation_id, "payload": payload, "session_id": session_id}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
