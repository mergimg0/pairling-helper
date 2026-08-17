from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping

from . import registry_data
from .base import (
    ProviderAvailability,
    ProviderDescriptor,
    ProviderDiagnostics,
    ProviderProbeResult,
    managed_child_environment,
    resolve_executable,
)
from .controls import (
    ControlValue,
    ProviderControlBinding,
    ProviderControlSnapshot,
    ProviderOperationResult,
    ProviderOperationCorrelation,
    ProviderSessionIdentity,
    OperationResultStatus,
)
from .hermes_runs import (
    SUPPORTED_HERMES_CHANNEL,
    SUPPORTED_HERMES_VERSION,
    HermesEventCursorExpired,
    HermesHTTPResponse,
    HermesOwnedServerRecord,
    HermesPolicyState,
    HermesRunsControlDriver,
    HermesRunsError,
    HermesRunsProtocolError,
    HermesRunsUnavailable,
)


_VERSION_RE = re.compile(
    r"^Hermes Agent v(?P<version>\d+\.\d+\.\d+) \([^\r\n]+\) · upstream (?P<commit>[0-9a-f]{8,40})$",
    re.MULTILINE,
)
_STATE_ENV = "PAIRLING_HERMES_CONTROL_STATE_DIR"
_DEFAULT_STATE_ROOT = Path.home() / "Library" / "Application Support" / "Pairling" / "provider-control" / "hermes"
_MANAGED_MODEL_PROVIDER = "openai-codex"
_MANAGED_MODEL_DEFAULT = "gpt-5.5"
_MANAGED_CONFIG = (
    "_config_version: 33\n"
    "model:\n"
    f"  provider: {_MANAGED_MODEL_PROVIDER}\n"
    f"  default: {_MANAGED_MODEL_DEFAULT}\n"
    "approvals:\n"
    "  mode: manual\n"
    "  cron_mode: deny\n"
).encode("utf-8")

_FALLBACK_DESCRIPTOR = ProviderDescriptor(
    provider_id="hermes_agent",
    display_name="Hermes Agent",
    kind="terminal_cli",
    builtin=True,
    docs_url="https://hermes-agent.nousresearch.com/docs/user-guide/features/api-server",
    adapter_depth="standard",
)
_ENTRY = registry_data.entry_or_none("hermes_agent")
_DESCRIPTOR = (
    replace(registry_data.descriptor_for(_ENTRY), adapter_depth="standard")
    if _ENTRY is not None
    else _FALLBACK_DESCRIPTOR
)
_DRIVERS: dict[tuple[str, str, str], HermesRunsControlDriver] = {}
_DRIVERS_LOCK = threading.RLock()
_OWNED_PROCESSES: dict[
    str,
    tuple[str, subprocess.Popen[bytes]],
] = {}
_OWNED_PROCESSES_LOCK = threading.RLock()


@dataclass(frozen=True)
class HermesInstalledVersion:
    version: str
    channel: str


class HermesOwnedServerStore:
    def __init__(self, root: Path | None = None):
        self.root = (root or _state_root()).expanduser()

    def load(self, binding: ProviderControlBinding) -> tuple[HermesOwnedServerRecord, str]:
        record_path, token_path = self._paths(binding.binding_id)
        _require_private_file(record_path, "Hermes owned server record")
        _require_private_file(token_path, "Hermes internal bearer")
        try:
            record_payload = json.loads(record_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise HermesRunsProtocolError("Hermes owned server record is unreadable") from exc
        record = HermesOwnedServerRecord.from_payload(record_payload)
        bearer = token_path.read_text(encoding="utf-8").strip()
        if len(bearer.encode("utf-8")) < 32:
            raise HermesRunsProtocolError("Hermes internal bearer is invalid")
        return record, bearer

    def save(
        self,
        binding: ProviderControlBinding,
        record: HermesOwnedServerRecord,
        bearer: str,
    ) -> None:
        if record.binding_id != binding.binding_id:
            raise HermesRunsProtocolError("Hermes owned server binding differs")
        if len(bearer.encode("utf-8")) < 32:
            raise HermesRunsProtocolError("Hermes internal bearer is invalid")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        record_path, token_path = self._paths(binding.binding_id)
        _atomic_private_write(
            token_path,
            (bearer + "\n").encode("utf-8"),
        )
        try:
            _atomic_private_write(
                record_path,
                (json.dumps(record.to_payload(), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
            )
        except Exception:
            try:
                token_path.unlink()
            except OSError:
                pass
            raise

    def remove(self, binding_id: str) -> None:
        for path in self._paths(binding_id):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def event_dir(self) -> Path:
        return self.root / "events"

    def log_path(self, binding_id: str) -> Path:
        digest = _binding_digest(binding_id)
        return self.root / "logs" / f"{digest}.log"

    def event_path(self, binding_id: str) -> Path:
        digest = _binding_digest(binding_id)
        return self.event_dir() / f"{digest}.events.jsonl"

    def managed_profile_root(self, binding_id: str) -> Path:
        return self.root / "profiles" / _binding_digest(binding_id)

    def remove_runtime_artifacts(self, binding_id: str) -> None:
        for path in (self.log_path(binding_id), self.event_path(binding_id)):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def _paths(self, binding_id: str) -> tuple[Path, Path]:
        digest = _binding_digest(binding_id)
        return self.root / f"{digest}.json", self.root / f"{digest}.token"


class HermesCLIPolicyProbe:
    def __call__(self, record: HermesOwnedServerRecord) -> HermesPolicyState:
        hermes_home = Path(record.hermes_home)
        sibling_state = hermes_home.parent / "state"
        profile_state = (
            sibling_state
            if sibling_state.is_dir()
            else hermes_home / ".pairling-state"
        )
        _require_private_file(
            hermes_home / "config.yaml",
            "Hermes managed profile config",
        )
        env = _managed_profile_environment(
            hermes_home,
            profile_state,
        )
        model_provider = str(
            _config_get(record.binary_path, env, "model.provider") or ""
        ).strip().lower()
        model_default = str(
            _config_get(record.binary_path, env, "model.default") or ""
        ).strip()
        approval_mode = _config_get(record.binary_path, env, "approvals.mode")
        cron_mode = _config_get(record.binary_path, env, "approvals.cron_mode")
        if (
            model_provider != _MANAGED_MODEL_PROVIDER
            or model_default != _MANAGED_MODEL_DEFAULT
        ):
            raise HermesRunsUnavailable(
                "Hermes managed model settings changed after launch"
            )
        return HermesPolicyState(
            approval_mode=str(approval_mode or "").strip().lower(),
            cron_mode=str(cron_mode or "").strip().lower(),
            yolo_enabled=record.yolo_enabled,
            launch_digest=_launch_digest(
                binary_path=record.binary_path,
                hermes_home=record.hermes_home,
                cwd=record.cwd,
                base_url=record.base_url,
                provider_version=record.provider_version,
                provider_channel=record.provider_channel,
                approval_mode=str(approval_mode or "").strip().lower(),
                cron_mode=str(cron_mode or "").strip().lower(),
                yolo_enabled=record.yolo_enabled,
            ),
        )


class UnavailableHermesControlDriver:
    def __init__(self, binding: ProviderControlBinding, reason: str):
        self.binding = binding
        self._reason = reason

    def snapshot(self, *, session_id, session_truth):
        del session_id, session_truth
        now = time.time()
        return ProviderControlSnapshot(
            provider_id=self.binding.provider_id,
            provider_version=self.binding.provider_version,
            provider_channel=self.binding.provider_channel,
            binding_id=self.binding.binding_id,
            capability_generation=1,
            observed_at=now,
            valid_until=now + 2.0,
            advertised_operations=(),
            values=(),
            choices=(),
            blocked_reason=self._reason,
            provider_cursor="hermes:1:0",
        )

    def execute(
        self,
        *,
        operation_id,
        input_payload,
        binding_id,
        capability_generation,
        session_id,
        client_action_id,
        prepared_attachments=(),
    ):
        del input_payload, binding_id, capability_generation, session_id, prepared_attachments
        return ProviderOperationResult(
            operation_id=operation_id,
            provider_operation_id=str(client_action_id)[:512] or "hermes-unavailable",
            status=OperationResultStatus.REJECTED,
            public_result={"reason": self._reason},
            provider_cursor="hermes:1:0",
        )


class DeferredHermesManagedLaunchDriver:
    """Launch one reviewed Hermes server lazily for a managed Pairling session."""

    requires_post_registration_first_prompt = True

    safe_launch_profile = {
        "reviewed": True,
        "establishes_loopback_auth": True,
        "provider_id": "hermes_agent",
        "provider_version": SUPPORTED_HERMES_VERSION,
        "provider_channel": SUPPORTED_HERMES_CHANNEL,
        "profile_scope": "pairling_owned_dedicated",
        "model.provider": _MANAGED_MODEL_PROVIDER,
        "model.default": _MANAGED_MODEL_DEFAULT,
        "approvals.mode": "manual",
        "approvals.cron_mode": "deny",
        "ambient_credentials": "denied",
    }

    def __init__(
        self,
        binding: ProviderControlBinding,
        *,
        store: HermesOwnedServerStore,
        binary_path: Path,
        profile_parent: Path | None = None,
    ):
        self.binding = binding
        self._store = store
        self._binary_path = binary_path
        self._profile_parent = profile_parent
        self._lock = threading.RLock()
        self._runtime: HermesRunsControlDriver | None = None
        self._native_session_id: str | None = None
        self._managed_run_id: str | None = None
        self._managed_run_baseline: str | None = None
        self._profile_root: Path | None = None
        self._profile_home: Path | None = None
        self._profile_identity: tuple[int, int] | None = None
        self._owner_nonce: str | None = None
        self._owns_server = False
        self._closed = False

    @property
    def capability_generation(self) -> int:
        with self._lock:
            runtime = self._runtime
        return runtime.capability_generation if runtime is not None else 1

    @property
    def provider_cursor(self) -> str:
        with self._lock:
            runtime = self._runtime
        if runtime is None:
            return "hermes:1:0"
        return runtime.snapshot(
            session_id=None,
            session_truth=None,
        ).provider_cursor

    def launch_session(
        self,
        *,
        project: str,
        title: str,
        first_prompt: str = "",
    ) -> dict[str, Any]:
        if not isinstance(first_prompt, str):
            raise HermesRunsProtocolError("Hermes first prompt must be text")
        if first_prompt != "":
            raise HermesRunsUnavailable(
                "Hermes managed launch rejects a non-empty first prompt "
                "without durable post-readiness operation correlation"
            )
        workspace = Path(project).expanduser().resolve(strict=True)
        if not workspace.is_dir():
            raise HermesRunsProtocolError("Hermes managed project must be a directory")
        managed_title = _managed_session_title(title)
        with self._lock:
            if self._closed:
                raise HermesRunsUnavailable("Hermes managed launch driver is closed")
            if self._runtime is not None:
                raise HermesRunsUnavailable("Hermes managed launch driver already owns a server")
            (
                profile_root,
                profile_home,
                profile_state,
                profile_identity,
            ) = _create_managed_profile(
                self._store,
                self.binding,
                profile_parent=self._profile_parent,
            )
            self._profile_root = profile_root
            self._profile_home = profile_home
            self._profile_identity = profile_identity
            runtime: HermesRunsControlDriver | None = None
            try:
                runtime = launch_owned_server(
                    self.binding,
                    hermes_home=profile_home,
                    profile_state=profile_state,
                    cwd=workspace,
                    binary_path=self._binary_path,
                    state_root=self._store.root,
                )
                self._runtime = runtime
                self._owns_server = True
                self._owner_nonce = runtime._record.owner_nonce
                native_id = _managed_native_session_id(self.binding.binding_id)
                response = _create_empty_managed_session(
                    runtime,
                    session_id=native_id,
                    title=managed_title,
                )
                if not _managed_session_response_matches(response, native_id):
                    raise HermesRunsUnavailable(
                        "Hermes did not create the reviewed empty managed session"
                    )
                readiness = runtime.snapshot(
                    session_id=None,
                    session_truth=None,
                )
                if readiness.blocked_reason is not None:
                    raise HermesRunsUnavailable(readiness.blocked_reason)
                self._native_session_id = native_id
                return {
                    "native_session_id": native_id,
                    "binding_id": self.binding.binding_id,
                    "provider_version": self.binding.provider_version,
                    "provider_channel": self.binding.provider_channel,
                    "capability_generation": runtime.capability_generation,
                    "provider_cursor": readiness.provider_cursor,
                }
            except BaseException:
                stopped = runtime is None
                if runtime is not None:
                    try:
                        stopped = stop_owned_server(
                            self.binding,
                            state_root=self._store.root,
                            owner_nonce=self._owner_nonce,
                        )
                    except Exception:
                        stopped = False
                if stopped:
                    self._store.remove_runtime_artifacts(
                        self.binding.binding_id,
                    )
                    self._remove_profile()
                else:
                    self._closed = True
                self._runtime = None
                self._native_session_id = None
                self._owner_nonce = None
                self._owns_server = False
                raise

    def verify_managed_launch(
        self,
        launch_result: Mapping[str, Any],
    ) -> bool:
        expected_keys = {
            "native_session_id",
            "binding_id",
            "provider_version",
            "provider_channel",
            "capability_generation",
            "provider_cursor",
        }
        try:
            with self._lock:
                runtime = self._runtime
                native_id = self._native_session_id
                profile_root = self._profile_root
                profile_home = self._profile_home
                owns_server = self._owns_server
            if (
                runtime is None
                or native_id is None
                or profile_root is None
                or profile_home is None
                or not owns_server
                or set(launch_result) != expected_keys
                or launch_result.get("native_session_id") != native_id
                or launch_result.get("binding_id") != self.binding.binding_id
                or launch_result.get("provider_version")
                != self.binding.provider_version
                or launch_result.get("provider_channel")
                != self.binding.provider_channel
                or launch_result.get("capability_generation")
                != runtime.capability_generation
            ):
                return False
            config_path = profile_home / "config.yaml"
            _require_private_file(
                config_path,
                "Hermes managed profile config",
            )
            if config_path.read_bytes() != _MANAGED_CONFIG:
                return False
            readiness = runtime.snapshot(
                session_id=None,
                session_truth=None,
            )
            if (
                readiness.blocked_reason is not None
                or launch_result.get("provider_cursor") != readiness.provider_cursor
            ):
                return False
            transport = getattr(runtime, "_transport", None)
            response = transport.request(
                "GET",
                f"/api/sessions/{native_id}",
                authenticated=True,
            )
            return _managed_session_response_matches(response, native_id)
        except Exception:
            return False

    def poll_events(
        self,
        provider_cursor: str | None = None,
    ) -> dict[str, Any]:
        runtime = self._require_runtime()
        with self._lock:
            run_id = self._managed_run_id
            baseline = self._managed_run_baseline
        if run_id is None:
            return {
                "events": [],
                "provider_cursor": runtime.snapshot(
                    session_id=None,
                    session_truth=None,
                ).provider_cursor,
            }
        event_cursor = (
            None
            if provider_cursor is None or provider_cursor == baseline
            else provider_cursor
        )
        events = runtime.events_after(run_id, cursor=event_cursor)
        cursor = (
            str(events[-1].get("cursor"))
            if events
            else provider_cursor
            if provider_cursor is not None
            else baseline
        )
        return {"events": events, "provider_cursor": cursor}

    def snapshot(
        self,
        *,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderControlSnapshot:
        with self._lock:
            runtime = self._runtime
            native_id = self._native_session_id
            closed = self._closed
        if runtime is None:
            reason = (
                "hermes_managed_launch_closed"
                if closed
                else "hermes_managed_launch_not_started"
            )
            return UnavailableHermesControlDriver(
                self.binding,
                reason,
            ).snapshot(session_id=session_id, session_truth=session_truth)
        if session_id is None:
            return runtime.snapshot(session_id=None, session_truth=session_truth)
        if native_id is None:
            raise HermesRunsProtocolError(
                "Hermes managed native session is unavailable"
            )
        qualified_id = _qualified_managed_session_id(native_id)
        if session_id != qualified_id:
            provider_snapshot = runtime.snapshot(
                session_id=None,
                session_truth=None,
            )
            return replace(
                provider_snapshot,
                advertised_operations=(),
                values=(),
                choices=(),
                blocked_reason="hermes_managed_session_identity_mismatch",
            )
        native_truth = _native_managed_session_truth(
            session_truth,
            native_id,
        )
        snapshot = runtime.snapshot(
            session_id=native_id,
            session_truth=native_truth,
        )
        return _qualify_managed_snapshot(snapshot, qualified_id)

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
        provider_correlation=None,
    ) -> ProviderOperationResult:
        runtime = self._require_runtime()
        native_id = self._native_session_for(session_id)
        if native_id is None:
            payload = dict(input_payload)
        else:
            payload = _native_managed_input(
                input_payload,
                qualified_id=_qualified_managed_session_id(native_id),
                native_id=native_id,
            )
        if operation_id == "session.terminate":
            identity = payload.get("session")
            if isinstance(identity, ProviderSessionIdentity):
                identity_matches = (
                    identity.provider_id == self.binding.provider_id
                    and identity.session_id == native_id
                    and identity.binding_id == self.binding.binding_id
                    and identity.capability_generation
                    == runtime.capability_generation
                )
            elif isinstance(identity, Mapping):
                identity_matches = (
                    identity.get("provider_id") == self.binding.provider_id
                    and identity.get("session_id") == native_id
                    and identity.get("binding_id") == self.binding.binding_id
                    and identity.get("capability_generation")
                    == runtime.capability_generation
                )
            else:
                identity_matches = False
            if (
                binding_id != self.binding.binding_id
                or capability_generation != runtime.capability_generation
            ):
                status = OperationResultStatus.REJECTED
                public_result = {"reason": "stale_binding"}
            elif not identity_matches:
                status = OperationResultStatus.REJECTED
                public_result = {"reason": "session_identity_mismatch"}
            elif prepared_attachments:
                status = OperationResultStatus.REJECTED
                public_result = {"reason": "attachments_not_supported"}
            else:
                status = OperationResultStatus.APPLIED
                public_result = {"status": "terminating"}
            return ProviderOperationResult(
                operation_id=operation_id,
                provider_operation_id=client_action_id,
                status=status,
                public_result=public_result,
                provider_cursor=runtime.snapshot(
                    session_id=None,
                    session_truth=None,
                ).provider_cursor,
            )
        baseline = (
            provider_correlation.provider_cursor
            if isinstance(
                provider_correlation,
                ProviderOperationCorrelation,
            )
            else runtime.snapshot(
                session_id=None,
                session_truth=None,
            ).provider_cursor
        )
        result = runtime.execute(
            operation_id=operation_id,
            input_payload=payload,
            binding_id=binding_id,
            capability_generation=capability_generation,
            session_id=native_id,
            client_action_id=client_action_id,
            prepared_attachments=prepared_attachments,
            provider_correlation=provider_correlation,
        )
        run_id = result.public_result.get("run_id")
        if isinstance(run_id, str) and run_id:
            with self._lock:
                self._managed_run_id = run_id
                self._managed_run_baseline = baseline
        return result

    def operation_correlation(
        self,
        *,
        operation_id: str,
        client_action_id: str,
        capability_generation: int,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderOperationCorrelation:
        runtime = self._require_runtime()
        native_id = self._native_session_for(session_id)
        if operation_id == "session.terminate":
            snapshot = self.snapshot(
                session_id=session_id,
                session_truth=session_truth,
            )
            if (
                native_id is None
                or capability_generation != snapshot.capability_generation
                or operation_id not in snapshot.advertised_operations
            ):
                raise HermesRunsProtocolError(
                    "Hermes managed termination correlation proof is unavailable"
                )
            return ProviderOperationCorrelation(
                client_action_id,
                snapshot.provider_cursor,
            )
        return runtime.operation_correlation(
            operation_id=operation_id,
            client_action_id=client_action_id,
            capability_generation=capability_generation,
            session_id=native_id,
            session_truth=_native_managed_session_truth(
                session_truth,
                native_id,
            ),
        )

    def arm_operation_dispatch_boundary(
        self,
        *,
        operation_id: str,
        client_action_id: str,
        session_id: str,
        provider_correlation: ProviderOperationCorrelation,
        before_write,
    ) -> None:
        runtime = self._require_runtime()
        native_id = self._native_session_for(session_id)
        if native_id is None:
            raise HermesRunsProtocolError(
                "Hermes operation dispatch boundary is unavailable"
            )
        runtime.arm_operation_dispatch_boundary(
            operation_id=operation_id,
            client_action_id=client_action_id,
            session_id=native_id,
            provider_correlation=provider_correlation,
            before_write=before_write,
        )

    def recover(
        self,
        *,
        operation_id: str,
        binding_id: str,
        capability_generation: int,
        session_id: str | None,
        client_action_id: str,
        provider_correlation,
        session_truth: dict[str, Any] | None,
    ):
        runtime = self._require_runtime()
        native_id = self._native_session_for(session_id)
        return runtime.recover(
            operation_id=operation_id,
            binding_id=binding_id,
            capability_generation=capability_generation,
            session_id=native_id,
            client_action_id=client_action_id,
            provider_correlation=provider_correlation,
            session_truth=_native_managed_session_truth(
                session_truth,
                native_id,
            ),
        )

    def events_after(
        self,
        run_id: str,
        *,
        cursor: str | None,
    ) -> list[dict[str, Any]]:
        return self._require_runtime().events_after(run_id, cursor=cursor)

    def consume_run_events(self, run_id: str) -> None:
        self._require_runtime().consume_run_events(run_id)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            owns_server = self._owns_server
            owner_nonce = self._owner_nonce
            self._owns_server = False
            self._runtime = None
            self._native_session_id = None
            self._owner_nonce = None
            self._managed_run_id = None
            self._managed_run_baseline = None
        if not owns_server or owner_nonce is None:
            return
        stopped = stop_owned_server(
            self.binding,
            state_root=self._store.root,
            owner_nonce=owner_nonce,
        )
        if not stopped:
            return
        self._store.remove_runtime_artifacts(self.binding.binding_id)
        self._remove_profile()

    def terminate(self) -> None:
        self.close()

    def _require_runtime(self) -> HermesRunsControlDriver:
        with self._lock:
            runtime = self._runtime
        if runtime is None:
            raise HermesRunsUnavailable("Hermes managed server is not running")
        return runtime

    def _native_session_for(self, session_id: str | None) -> str | None:
        if session_id is None:
            return None
        with self._lock:
            native_id = self._native_session_id
        if native_id is None or session_id != _qualified_managed_session_id(native_id):
            raise HermesRunsProtocolError("Hermes managed session identity is stale")
        return native_id

    def _remove_profile(self) -> None:
        with self._lock:
            profile_root = self._profile_root
            profile_identity = self._profile_identity
            self._profile_root = None
            self._profile_home = None
            self._profile_identity = None
        _remove_owned_profile(profile_root, profile_identity)




class HermesProviderAdapter:
    descriptor = _DESCRIPTOR

    def __init__(self, home: Path | None = None, state_root: Path | None = None):
        self.home = home or Path.home()
        self._store = HermesOwnedServerStore(state_root)

    @property
    def candidates(self) -> list[Path]:
        if _ENTRY is not None and _ENTRY.binary_candidates:
            return registry_data.candidate_paths(_ENTRY, home=self.home)
        return [
            self.home / ".local" / "bin" / "hermes",
            self.home / ".hermes" / "bin" / "hermes",
            Path("/opt/homebrew/bin/hermes"),
            Path("/usr/local/bin/hermes"),
        ]

    def supports(self, capability: str) -> bool:
        return capability in {
            "detect",
            "status",
            "spawn",
            "list_sessions",
            "read_transcript",
            "live_state",
            "send_text",
            "interrupt",
            "resume",
        }

    def probe(self) -> ProviderProbeResult:
        resolved = resolve_executable(
            "hermes",
            self.candidates,
            env_var=_ENTRY.env_override if _ENTRY is not None else "PAIRLING_HERMES_BIN",
        )
        raw_version = _hermes_cli_version(resolved.path) if resolved else None
        installed_version = parse_hermes_version(raw_version)
        supported = (
            installed_version is not None
            and installed_version.version == SUPPORTED_HERMES_VERSION
            and installed_version.channel == SUPPORTED_HERMES_CHANNEL
        )
        notes: list[str] = []
        setup_actions: list[str] = []
        if resolved is None:
            notes.append("hermes_cli_not_found")
            setup_actions.append("install_cli")
        elif not supported:
            notes.append("hermes_exact_version_or_channel_unsupported")
            setup_actions.append("upgrade_cli")
        capabilities = ("detect", "status", "spawn")
        if supported:
            capabilities += (
                "list_sessions",
                "read_transcript",
                "live_state",
                "send_text",
                "interrupt",
                "resume",
            )
        availability = ProviderAvailability(
            provider_id=self.descriptor.provider_id,
            display_name=self.descriptor.display_name,
            kind=self.descriptor.kind,
            installed=resolved is not None,
            usable=supported,
            launchable=supported,
            auth_state="owned_server_required" if supported else ("missing_cli" if resolved is None else "unsupported_version"),
            config_state="manual_approval_required" if supported else "unknown",
            readable_sessions=0,
            live_sessions=0,
            controllable_sessions=0,
            capabilities=capabilities,
            setup_actions=tuple(setup_actions),
            notes=tuple(notes),
        )
        return ProviderProbeResult(
            descriptor=self.descriptor,
            availability=availability,
            diagnostics=ProviderDiagnostics(
                cli_path=str(resolved.path) if resolved else None,
                cli_path_source=resolved.source if resolved else None,
                version=installed_version.version if installed_version else raw_version,
                config_path=str(self.home / ".hermes" / "config.yaml"),
                config_exists=(self.home / ".hermes" / "config.yaml").is_file(),
            ),
            observed_at=time.time(),
        )

    def create_control_driver(self, binding: ProviderControlBinding):
        return create_control_driver(
            binding,
            store=self._store,
            home=self.home,
        )


def create_control_driver(
    binding: ProviderControlBinding,
    *,
    store: HermesOwnedServerStore | None = None,
    binary_path: Path | None = None,
    home: Path | None = None,
):
    if binding.provider_id != "hermes_agent":
        return None
    if binding.provider_version != SUPPORTED_HERMES_VERSION:
        return UnavailableHermesControlDriver(binding, "hermes_version_unsupported")
    if binding.provider_channel != SUPPORTED_HERMES_CHANNEL:
        return UnavailableHermesControlDriver(binding, "hermes_channel_unsupported")
    owned_store = store or HermesOwnedServerStore()
    try:
        record, bearer = owned_store.load(binding)
    except FileNotFoundError:
        executable = _resolve_reviewed_binary(
            binding,
            binary_path=binary_path,
            home=home or Path.home(),
        )
        if executable is None:
            return UnavailableHermesControlDriver(
                binding,
                "hermes_exact_binary_unavailable",
            )
        return DeferredHermesManagedLaunchDriver(
            binding,
            store=owned_store,
            binary_path=executable,
            profile_parent=(
                home.expanduser() / ".hermes" / "profiles"
                if home is not None
                else None
            ),
        )
    except HermesRunsError:
        return UnavailableHermesControlDriver(binding, "hermes_owned_server_record_invalid")
    if not _owned_process_matches(record):
        return UnavailableHermesControlDriver(binding, "hermes_owned_process_handle_required")
    key = (binding.binding_id, record.owner_nonce, record.launch_digest)
    with _DRIVERS_LOCK:
        existing = _DRIVERS.get(key)
        if existing is not None:
            return existing
        driver = HermesRunsControlDriver(
            binding,
            record=record,
            bearer=bearer,
            policy_probe=HermesCLIPolicyProbe(),
            ownership_probe=_owned_process_matches,
            event_dir=owned_store.event_dir(),
        )
        _DRIVERS[key] = driver
        return driver


def launch_owned_server(
    binding: ProviderControlBinding,
    *,
    hermes_home: Path,
    cwd: Path,
    binary_path: Path | None = None,
    state_root: Path | None = None,
    profile_state: Path | None = None,
    port: int | None = None,
    startup_timeout: float = 20.0,
):
    """Launch a fixed Hermes gateway with one authenticated loopback API server.

    The caller must supply a dedicated Hermes profile home. Runtime readiness
    rejects any active platform other than api_server before controls are shown.
    The generated bearer is stored in a mode-0600 file and is never returned.
    """
    if binding.provider_id != "hermes_agent":
        raise HermesRunsProtocolError("Hermes launcher received another provider binding")
    hermes_home = hermes_home.expanduser().resolve()
    cwd = cwd.expanduser().resolve()
    if not hermes_home.is_dir() or not cwd.is_dir():
        raise HermesRunsProtocolError("Hermes profile home and cwd must exist")
    if hermes_home.stat().st_mode & 0o077:
        raise HermesRunsProtocolError("Hermes profile home permissions must be owner-only")
    managed_state = (
        profile_state.expanduser().resolve()
        if profile_state is not None
        else hermes_home / ".pairling-state"
    )
    _ensure_private_directory(managed_state)
    executable = binary_path.expanduser().resolve() if binary_path else None
    if executable is None:
        resolved = resolve_executable(
            "hermes",
            [
                Path.home() / ".local" / "bin" / "hermes",
                Path.home() / ".hermes" / "bin" / "hermes",
                Path("/opt/homebrew/bin/hermes"),
                Path("/usr/local/bin/hermes"),
            ],
            env_var="PAIRLING_HERMES_BIN",
        )
        executable = resolved.path.resolve() if resolved else None
    if executable is None or not executable.is_file() or not os.access(executable, os.X_OK):
        raise HermesRunsUnavailable("Hermes executable is unavailable")
    policy_env = _managed_profile_environment(
        hermes_home,
        managed_state,
    )
    raw_version = _hermes_cli_version(executable, env=policy_env)
    installed = parse_hermes_version(raw_version)
    if installed is None or installed.version != binding.provider_version or installed.channel != binding.provider_channel:
        raise HermesRunsUnavailable("Hermes executable does not match the exact control binding")
    model_provider = str(
        _config_get(str(executable), policy_env, "model.provider") or ""
    ).strip().lower()
    model_default = str(
        _config_get(str(executable), policy_env, "model.default") or ""
    ).strip()
    approval_mode = str(
        _config_get(str(executable), policy_env, "approvals.mode") or ""
    ).strip().lower()
    cron_mode = str(
        _config_get(str(executable), policy_env, "approvals.cron_mode") or ""
    ).strip().lower()
    if (
        model_provider != _MANAGED_MODEL_PROVIDER
        or model_default != _MANAGED_MODEL_DEFAULT
        or approval_mode != "manual"
        or cron_mode != "deny"
    ):
        raise HermesRunsUnavailable(
            "Hermes dedicated profile does not match the reviewed safe settings"
        )
    selected_port = port if port is not None else _available_loopback_port()
    if not isinstance(selected_port, int) or not (1 <= selected_port <= 65535):
        raise HermesRunsProtocolError("invalid Hermes loopback port")
    base_url = f"http://127.0.0.1:{selected_port}"
    bearer = secrets.token_urlsafe(48)
    owner_nonce = secrets.token_urlsafe(32)
    env = managed_child_environment(
        source=policy_env,
        provider_settings={
            "HERMES_HOME": str(hermes_home),
            "API_SERVER_ENABLED": "true",
            "API_SERVER_HOST": "127.0.0.1",
            "API_SERVER_PORT": str(selected_port),
            "API_SERVER_CORS_ORIGINS": "",
        },
        private_runtime_settings={"API_SERVER_KEY": bearer},
    )
    store = HermesOwnedServerStore(state_root)
    log_path = store.log_path(binding.binding_id)
    log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(log_path.parent, 0o700)
    except OSError:
        pass
    log_fd = os.open(log_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    try:
        process = subprocess.Popen(
            [str(executable), "gateway", "run", "--external-supervisor"],
            cwd=str(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_fd,
            stderr=log_fd,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        os.close(log_fd)
        raise HermesRunsUnavailable("Unable to start owned Hermes gateway") from exc
    os.close(log_fd)
    try:
        digest = _launch_digest(
            binary_path=str(executable),
            hermes_home=str(hermes_home),
            cwd=str(cwd),
            base_url=base_url,
            provider_version=binding.provider_version,
            provider_channel=binding.provider_channel,
            approval_mode=approval_mode,
            cron_mode=cron_mode,
            yolo_enabled=False,
        )
        record = HermesOwnedServerRecord(
            schema_version=1,
            binding_id=binding.binding_id,
            provider_version=binding.provider_version,
            provider_channel=binding.provider_channel,
            capability_generation=max(1, int(time.time_ns() & 0x7FFFFFFF)),
            base_url=base_url,
            pid=int(process.pid),
            binary_path=str(executable),
            hermes_home=str(hermes_home),
            cwd=str(cwd),
            approval_mode=approval_mode,
            cron_mode=cron_mode,
            yolo_enabled=False,
            launch_digest=digest,
            owner_nonce=owner_nonce,
        )
        with _OWNED_PROCESSES_LOCK:
            _OWNED_PROCESSES[binding.binding_id] = (
                owner_nonce,
                process,
            )
        store.save(binding, record, bearer)
        driver = HermesRunsControlDriver(
            binding,
            record=record,
            bearer=bearer,
            policy_probe=HermesCLIPolicyProbe(),
            ownership_probe=_owned_process_matches,
            event_dir=store.event_dir(),
        )
        deadline = time.monotonic() + startup_timeout
        blocked_reason = "hermes_owned_server_unreachable"
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise HermesRunsUnavailable("Owned Hermes gateway exited during startup")
            snapshot = driver.snapshot(session_id=None, session_truth=None)
            blocked_reason = snapshot.blocked_reason or ""
            if blocked_reason == "":
                key = (binding.binding_id, record.owner_nonce, record.launch_digest)
                with _DRIVERS_LOCK:
                    _DRIVERS[key] = driver
                return driver
            if blocked_reason not in {
                "hermes_owned_server_unreachable",
                "hermes_transport_probe_failed",
                "hermes_runtime_not_ready",
            }:
                raise HermesRunsUnavailable(blocked_reason)
            time.sleep(0.1)
        raise HermesRunsUnavailable(blocked_reason)
    except Exception:
        _terminate_current_process(binding.binding_id, process)
        store.remove(binding.binding_id)
        raise


def stop_owned_server(
    binding: ProviderControlBinding,
    *,
    state_root: Path | None = None,
    owner_nonce: str | None = None,
    timeout: float = 5.0,
) -> bool:
    """Stop only an exact process object launched by this Pairling daemon."""
    with _OWNED_PROCESSES_LOCK:
        entry = _OWNED_PROCESSES.get(binding.binding_id)
    if entry is None:
        return False
    recorded_nonce, process = entry
    if owner_nonce is not None and owner_nonce != recorded_nonce:
        return False
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=timeout)
    with _OWNED_PROCESSES_LOCK:
        if _OWNED_PROCESSES.get(binding.binding_id) != entry:
            return False
        _OWNED_PROCESSES.pop(binding.binding_id, None)
    HermesOwnedServerStore(state_root).remove(binding.binding_id)
    with _DRIVERS_LOCK:
        for key in [key for key in _DRIVERS if key[0] == binding.binding_id]:
            if owner_nonce is None or key[1] == owner_nonce:
                _DRIVERS.pop(key, None)
    return True


def parse_hermes_version(raw: str | None) -> HermesInstalledVersion | None:
    if not raw:
        return None
    match = _VERSION_RE.search(raw.strip())
    if match is None:
        return None
    return HermesInstalledVersion(
        version=match.group("version"),
        channel="upstream-" + match.group("commit")[:8],
    )


def _state_root() -> Path:
    configured = os.environ.get(_STATE_ENV)
    return Path(configured).expanduser() if configured else _DEFAULT_STATE_ROOT


def _hermes_cli_version(
    binary_path: Path,
    *,
    env: Mapping[str, str] | None = None,
) -> str | None:
    child_env = managed_child_environment() if env is None else dict(env)
    try:
        process = subprocess.run(
            [str(binary_path), "--version"],
            env=child_env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if process.returncode != 0:
        return None
    return (
        (process.stdout or process.stderr or "").strip()[:160]
        or None
    )


def _resolve_reviewed_binary(
    binding: ProviderControlBinding,
    *,
    binary_path: Path | None,
    home: Path,
) -> Path | None:
    executable = binary_path.expanduser().resolve() if binary_path else None
    if executable is None:
        resolved = resolve_executable(
            "hermes",
            [
                home / ".local" / "bin" / "hermes",
                home / ".hermes" / "bin" / "hermes",
                Path("/opt/homebrew/bin/hermes"),
                Path("/usr/local/bin/hermes"),
            ],
            env_var=(
                _ENTRY.env_override
                if _ENTRY is not None
                else "PAIRLING_HERMES_BIN"
            ),
        )
        executable = resolved.path.resolve() if resolved else None
    if (
        executable is None
        or not executable.is_file()
        or not os.access(executable, os.X_OK)
    ):
        return None
    installed = parse_hermes_version(_hermes_cli_version(executable))
    if (
        installed is None
        or installed.version != binding.provider_version
        or installed.channel != binding.provider_channel
    ):
        return None
    return executable


def _create_managed_profile(
    store: HermesOwnedServerStore,
    binding: ProviderControlBinding,
    *,
    profile_parent: Path | None = None,
) -> tuple[Path, Path, Path, tuple[int, int]]:
    _ensure_private_directory(store.root)
    if profile_parent is None:
        profiles_root = store.root / "profiles"
        profile_root = store.managed_profile_root(binding.binding_id)
        profile_home = profile_root / "home"
        profile_state = profile_root / "state"
    else:
        profiles_root = profile_parent.expanduser()
        _ensure_private_directory(profiles_root.parent)
        profile_root = (
            profiles_root
            / f"pairling-{_binding_digest(binding.binding_id)}"
        )
        profile_home = profile_root
        profile_state = profile_root / ".pairling-state"
    _ensure_private_directory(profiles_root)
    try:
        profile_root.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise HermesRunsUnavailable(
            "Hermes managed profile already exists for this binding"
        ) from exc
    try:
        _ensure_private_directory(profile_root)
        _ensure_private_directory(profile_home)
        _ensure_private_directory(profile_state)
        _managed_profile_environment(profile_home, profile_state, source={})
        _atomic_private_write(profile_home / "config.yaml", _MANAGED_CONFIG)
        identity = profile_root.lstat()
        return (
            profile_root,
            profile_home,
            profile_state,
            (int(identity.st_dev), int(identity.st_ino)),
        )
    except BaseException:
        shutil.rmtree(profile_root, ignore_errors=True)
        raise


def _managed_profile_environment(
    hermes_home: Path,
    profile_state: Path,
    *,
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    _ensure_private_directory(hermes_home)
    _ensure_private_directory(profile_state)
    locations = {
        "XDG_CACHE_HOME": profile_state / "cache",
        "XDG_CONFIG_HOME": profile_state / "config",
        "XDG_DATA_HOME": profile_state / "data",
        "XDG_RUNTIME_DIR": profile_state / "runtime",
        "XDG_STATE_HOME": profile_state / "state",
    }
    for location in locations.values():
        _ensure_private_directory(location)
    return managed_child_environment(
        source=source,
        home=hermes_home,
        provider_settings={
            "HERMES_HOME": str(hermes_home),
            **{
                key: str(location)
                for key, location in locations.items()
            },
        },
    )


def _managed_session_title(value: Any) -> str:
    if not isinstance(value, str):
        raise HermesRunsProtocolError("Hermes managed session title must be text")
    title = value or "Pairling Hermes session"
    if len(title) > 500 or any(character in title for character in "\r\n\0"):
        raise HermesRunsProtocolError("Hermes managed session title is invalid")
    return title


def _managed_native_session_id(binding_id: str) -> str:
    return f"pairling_{_binding_digest(binding_id)[:32]}"


def _create_empty_managed_session(
    runtime: HermesRunsControlDriver,
    *,
    session_id: str,
    title: str,
) -> HermesHTTPResponse:
    transport = getattr(runtime, "_transport", None)
    request = getattr(transport, "request", None)
    if not callable(request):
        raise HermesRunsUnavailable("Hermes authenticated session transport is unavailable")
    return request(
        "POST",
        "/api/sessions",
        payload={
            "id": session_id,
            "title": title,
            "model": _MANAGED_MODEL_DEFAULT,
            "source": "api_server",
        },
        authenticated=True,
    )


def _managed_session_response_matches(
    response: HermesHTTPResponse,
    session_id: str,
) -> bool:
    if response.status not in {200, 201} or not isinstance(response.body, Mapping):
        return False
    session = response.body.get("session")
    return (
        response.body.get("object") == "hermes.session"
        and isinstance(session, Mapping)
        and session.get("id") == session_id
        and session.get("model") == _MANAGED_MODEL_DEFAULT
        and session.get("source") == "api_server"
    )


def _qualified_managed_session_id(native_id: str | None) -> str:
    if not isinstance(native_id, str) or not native_id:
        raise HermesRunsProtocolError("Hermes managed native session is unavailable")
    return f"hermes_agent:{native_id}"


def _native_managed_session_truth(
    session_truth: Mapping[str, Any] | None,
    native_id: str,
) -> dict[str, Any] | None:
    if not isinstance(session_truth, Mapping):
        return None
    native_truth = dict(session_truth)
    native_truth["session_id"] = native_id
    return native_truth


def _qualify_managed_snapshot(
    snapshot: ProviderControlSnapshot,
    qualified_id: str,
) -> ProviderControlSnapshot:
    advertised = list(snapshot.advertised_operations)
    values = []
    for value in snapshot.values:
        identity = value.value
        if isinstance(identity, ProviderSessionIdentity):
            identity = replace(identity, session_id=qualified_id)
        values.append(replace(value, value=identity))
    if (
        snapshot.blocked_reason is None
        and "session.terminate" not in advertised
    ):
        advertised.append("session.terminate")
        values.append(
            ControlValue(
                "session.terminate",
                "session",
                ProviderSessionIdentity(
                    snapshot.provider_id,
                    qualified_id,
                    snapshot.binding_id,
                    snapshot.capability_generation,
                ),
            )
        )
    qualified = replace(
        snapshot,
        advertised_operations=tuple(advertised),
        values=tuple(values),
    )
    qualified.validate(now=snapshot.observed_at)
    return qualified


def _native_managed_input(
    input_payload: Mapping[str, Any],
    *,
    qualified_id: str,
    native_id: str,
) -> dict[str, Any]:
    payload = dict(input_payload)
    identity = payload.get("session")
    if isinstance(identity, ProviderSessionIdentity):
        if identity.session_id != qualified_id:
            raise HermesRunsProtocolError("Hermes managed input session is stale")
        payload["session"] = replace(identity, session_id=native_id)
    elif isinstance(identity, Mapping):
        if identity.get("session_id") != qualified_id:
            raise HermesRunsProtocolError("Hermes managed input session is stale")
        payload["session"] = {**identity, "session_id": native_id}
    return payload


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise HermesRunsProtocolError("Hermes managed profile path is unsafe")
    if path.stat().st_mode & 0o077:
        raise HermesRunsProtocolError("Hermes managed profile permissions are unsafe")


def _remove_owned_profile(
    profile_root: Path | None,
    profile_identity: tuple[int, int] | None,
) -> None:
    if profile_root is None or profile_identity is None:
        return
    try:
        current = profile_root.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISDIR(current.st_mode)
        or (int(current.st_dev), int(current.st_ino)) != profile_identity
    ):
        return
    shutil.rmtree(profile_root)




def _config_get(binary_path: str, env: Mapping[str, str], key: str) -> Any:
    try:
        process = subprocess.run(
            [binary_path, "config", "get", "--json", key],
            env=dict(env),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HermesRunsUnavailable("Hermes policy probe failed") from exc
    if process.returncode != 0:
        raise HermesRunsUnavailable("Hermes policy key is unavailable")
    try:
        return json.loads(process.stdout)
    except Exception as exc:
        raise HermesRunsProtocolError("Hermes policy probe returned invalid JSON") from exc


def _launch_digest(
    *,
    binary_path: str,
    hermes_home: str,
    cwd: str,
    base_url: str,
    provider_version: str,
    provider_channel: str,
    approval_mode: str,
    cron_mode: str,
    yolo_enabled: bool,
) -> str:
    payload = {
        "argv": [binary_path, "gateway", "run", "--external-supervisor"],
        "binary_path": binary_path,
        "hermes_home": hermes_home,
        "cwd": cwd,
        "base_url": base_url,
        "provider_version": provider_version,
        "provider_channel": provider_channel,
        "approval_mode": approval_mode,
        "cron_mode": cron_mode,
        "yolo_enabled": yolo_enabled,
        "host": "127.0.0.1",
        "cors_origins": "",
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _binding_digest(binding_id: str) -> str:
    if not isinstance(binding_id, str) or not binding_id or len(binding_id) > 256:
        raise HermesRunsProtocolError("invalid Hermes binding id")
    return hashlib.sha256(binding_id.encode("utf-8")).hexdigest()


def _atomic_private_write(path: Path, content: bytes) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    try:
        os.write(fd, content)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def _require_private_file(path: Path, label: str) -> None:
    try:
        stat_result = path.stat()
    except FileNotFoundError:
        raise
    if not path.is_file() or stat_result.st_mode & 0o077:
        raise HermesRunsProtocolError(f"{label} permissions are unsafe")


def _owned_process_matches(record: HermesOwnedServerRecord) -> bool:
    with _OWNED_PROCESSES_LOCK:
        entry = _OWNED_PROCESSES.get(record.binding_id)
    if entry is None:
        return False
    owner_nonce, process = entry
    return (
        owner_nonce == record.owner_nonce
        and process.poll() is None
        and int(process.pid) == record.pid
    )


def _available_loopback_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _terminate_current_process(binding_id: str, process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    with _OWNED_PROCESSES_LOCK:
        entry = _OWNED_PROCESSES.get(binding_id)
        if entry is not None and entry[1] is process:
            _OWNED_PROCESSES.pop(binding_id, None)
