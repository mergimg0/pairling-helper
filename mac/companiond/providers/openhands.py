"""Authenticated, Pairling-owned OpenHands Agent Server control driver.

Only the pinned public Agent Server contract is used.  The adapter never exposes
an arbitrary REST method, shell endpoint, credential surface, or NeverConfirm
policy.  Mutations are advertised only after exact version, owned-loopback,
authentication, workspace, and live confirmation-policy canaries pass.
"""

from __future__ import annotations

import atexit
import base64
import hashlib
import json
import os
import secrets
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

from .base import (
    ManagedAuthVerification,
    ManagedLaunchContract,
    ProviderAdapter,
    ProviderAvailability,
    ProviderDescriptor,
    ProviderDiagnostics,
    ProviderProbeResult,
    ResolvedExecutable,
    managed_child_environment,
    resolve_executable,
)
from . import registry_data
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
from .operations import REVIEWED_OPERATION_CATALOG, OperationCatalogError


OPENHANDS_PROVIDER_ID = "openhands"
OPENHANDS_VERSION = "1.40.0"
OPENHANDS_CHANNEL = "stable"
OPENHANDS_PROFILE_ENV = "PAIRLING_OPENHANDS_AGENT_PROFILE_ID"
_ENTRY = registry_data.entry_or_none(OPENHANDS_PROVIDER_ID)
OPENHANDS_DESCRIPTOR = (
    registry_data.descriptor_for(_ENTRY)
    if _ENTRY is not None
    else ProviderDescriptor(
        provider_id=OPENHANDS_PROVIDER_ID,
        display_name="OpenHands Agent Server",
        kind="agent_server",
        builtin=True,
        docs_url="https://docs.openhands.dev/sdk/arch/agent-server",
        adapter_depth="deep",
        managed_launch=ManagedLaunchContract(
            control_channel=OPENHANDS_CHANNEL,
            ready_auth_states=("owned_session_key",),
            ready_config_states=("pinned",),
            auth_verification=ManagedAuthVerification.RUNTIME,
        ),
    )
)

_READ_OPERATIONS = (
    "provider.auth.read",
    "provider.config.read",
    "provider.usage.read",
    "provider.diagnostics.read",
)
_SESSION_MUTATIONS = (
    "session.prompt.send",
    "session.turn.interrupt",
    "session.compact",
    "session.rewind",
)
_TARGET_SESSION_MUTATIONS = ("session.resume", "session.fork")
_ACTIVE_CONFIRMATION_POLICIES = frozenset({"AlwaysConfirm", "ConfirmRisky"})
_MAX_JSON_BYTES = 8 * 1024 * 1024
_MAX_WS_FRAME_BYTES = 8 * 1024 * 1024
_MAX_ACTION_RESULTS = 256
_MANAGED_CANARIES = (
    "owned_loopback_exact_version",
    "authenticated_api_boundary",
    "managed_workspace_profile",
    "manager_identity",
)


class OpenHandsControlError(RuntimeError):
    def __init__(self, code: str, detail: str | None = None):
        self.code = code
        self.detail = detail or code
        super().__init__(self.detail)


class OpenHandsHttpError(OpenHandsControlError):
    def __init__(self, code: str, status: int | None, detail: str | None = None):
        self.status = status
        super().__init__(code, detail)

class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class OpenHandsTransport(Protocol):
    def request_json(
        self,
        method: str,
        target: str,
        body: Mapping[str, Any] | None = None,
        *,
        authenticated: bool = True,
        correlation_id: str | None = None,
    ) -> Any:
        ...



class UrllibOpenHandsTransport:
    """Small fixed-origin HTTP client; callers supply only driver-owned routes."""

    def __init__(self, endpoint: str, session_api_key: str, *, timeout: float = 5.0):
        self.endpoint = _validate_loopback_endpoint(endpoint)
        if not isinstance(session_api_key, str) or len(session_api_key) < 24:
            raise OpenHandsControlError("internal_auth_missing")
        self._session_api_key = session_api_key
        self.timeout = timeout
        self._opener = build_opener(ProxyHandler({}), _NoRedirectHandler())

    def request_json(
        self,
        method: str,
        target: str,
        body: Mapping[str, Any] | None = None,
        *,
        authenticated: bool = True,
        correlation_id: str | None = None,
    ) -> Any:
        data = self._request(
            method,
            target,
            body=body,
            authenticated=authenticated,
            correlation_id=correlation_id,
            max_bytes=_MAX_JSON_BYTES,
        )
        if not data:
            return None
        try:
            return json.loads(data)
        except (UnicodeDecodeError, ValueError) as exc:
            raise OpenHandsHttpError("invalid_json_response", None) from exc


    def _request(
        self,
        method: str,
        target: str,
        *,
        body: Mapping[str, Any] | None,
        authenticated: bool,
        correlation_id: str | None,
        max_bytes: int,
    ) -> bytes:
        if method not in {"GET", "POST"}:
            raise OpenHandsControlError("http_method_not_allowed")
        _validate_relative_target(target)
        if not _reviewed_http_route(method, target):
            raise OpenHandsControlError("http_route_not_reviewed")
        payload = None
        headers = {"Accept": "application/json"}
        if authenticated:
            headers["X-Session-API-Key"] = self._session_api_key
        if correlation_id:
            headers["X-Pairling-Client-Action-ID"] = correlation_id
        if body is not None:
            payload = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(
            f"{self.endpoint}{target}",
            data=payload,
            headers=headers,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                declared = response.headers.get("Content-Length")
                if declared and declared.isdigit() and int(declared) > max_bytes:
                    raise OpenHandsHttpError("response_too_large", response.status)
                data = response.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise OpenHandsHttpError("response_too_large", response.status)
                return data
        except HTTPError as exc:
            status = exc.code
            code = "authentication_failed" if status in {401, 403} else "provider_http_error"
            try:
                exc.close()
            except (OSError, ValueError):
                pass
            raise OpenHandsHttpError(code, status) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise OpenHandsHttpError("provider_unreachable", None) from exc


class OwnedOpenHandsAgentServer:
    """Lifecycle for an authenticated Agent Server owned by this Pairling daemon."""

    def __init__(
        self,
        *,
        executable: Path,
        version: str,
        binding_id: str,
        workspace_root: Path,
        home: Path,
    ):
        self.executable = executable.resolve()
        self.version = version
        self.binding_id = binding_id
        self.workspace_root = workspace_root.resolve()
        self.home = home.resolve()
        self.endpoint: str | None = None
        self.session_api_key: str | None = None
        self.instance_id = "not-started"
        self.launch_config_digest = ""
        self._process: subprocess.Popen[bytes] | None = None
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def ensure_started(self) -> UrllibOpenHandsTransport:
        with self._lock:
            if self.running and self.endpoint and self.session_api_key:
                return UrllibOpenHandsTransport(self.endpoint, self.session_api_key)
            self._stop_locked()
            if self.version != OPENHANDS_VERSION:
                raise OpenHandsControlError("unsupported_provider_version")
            if not self.executable.is_file() or not os.access(self.executable, os.X_OK):
                raise OpenHandsControlError("server_binary_missing")
            if _installed_agent_server_version(self.executable) != OPENHANDS_VERSION:
                raise OpenHandsControlError("unsupported_provider_version")
            if not self.workspace_root.is_dir():
                raise OpenHandsControlError("workspace_root_unavailable")

            port = _reserve_loopback_port()
            endpoint = f"http://127.0.0.1:{port}"
            session_api_key = secrets.token_urlsafe(48)
            secret_key = secrets.token_urlsafe(48)
            instance_id = secrets.token_hex(16)
            data_dir = (
                self.home
                / "Library"
                / "Application Support"
                / "Pairling"
                / "OpenHands"
                / hashlib.sha256(self.binding_id.encode("utf-8")).hexdigest()[:20]
            )
            data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                data_dir.chmod(0o700)
            except OSError:
                pass
            env = _safe_server_environment(
                self.home,
                session_api_key=session_api_key,
                secret_key=secret_key,
            )
            launch_shape = {
                "binary": str(self.executable),
                "binary_sha256": _sha256_file(self.executable),
                "version": self.version,
                "channel": OPENHANDS_CHANNEL,
                "host": "127.0.0.1",
                "port": port,
                "cwd": str(data_dir),
                "workspace_root": str(self.workspace_root),
                "auth": "OH_SESSION_API_KEYS_0",
                "confirmation": "AlwaysConfirm",
                "path_sha256": hashlib.sha256(
                    env.get("PATH", "").encode("utf-8")
                ).hexdigest(),
            }
            launch_config_digest = hashlib.sha256(
                json.dumps(launch_shape, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            try:
                process = subprocess.Popen(
                    [
                        str(self.executable),
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(port),
                    ],
                    cwd=data_dir,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except OSError as exc:
                raise OpenHandsControlError("server_launch_failed") from exc

            self._process = process
            self.endpoint = endpoint
            self.session_api_key = session_api_key
            self.instance_id = instance_id
            self.launch_config_digest = launch_config_digest
            transport = UrllibOpenHandsTransport(endpoint, session_api_key, timeout=1.0)
            deadline = time.monotonic() + 12.0
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    self._stop_locked()
                    raise OpenHandsControlError("server_exited_during_start")
                try:
                    ready = transport.request_json("GET", "/ready", authenticated=False)
                    if isinstance(ready, dict):
                        return transport
                except OpenHandsControlError:
                    pass
                time.sleep(0.05)
            self._stop_locked()
            raise OpenHandsControlError("server_readiness_timeout")

    def stop(self) -> None:
        with self._lock:
            self._stop_locked()

    def _stop_locked(self) -> None:
        process = self._process
        self._process = None
        self.endpoint = None
        self.session_api_key = None
        if process is not None:
            close_owned_process(
                process,
                process_group=True,
                terminate_timeout=3.0,
            )


_OWNED_SERVERS: dict[str, OwnedOpenHandsAgentServer] = {}
_OWNED_SERVERS_LOCK = threading.Lock()


def _stop_owned_servers() -> None:
    with _OWNED_SERVERS_LOCK:
        servers = list(_OWNED_SERVERS.values())
        _OWNED_SERVERS.clear()
    for server in servers:
        try:
            server.stop()
        except Exception:
            pass


atexit.register(_stop_owned_servers)


class OpenHandsProviderAdapter(ProviderAdapter):
    descriptor = OPENHANDS_DESCRIPTOR

    def __init__(self, home: Path | None = None):
        self.home = (home or Path.home()).resolve()

    def supports(self, capability: str) -> bool:
        return capability in {"detect", "owned_agent_server", "authenticated_control"}

    def _resolve(self) -> ResolvedExecutable | None:
        return resolve_executable(
            "agent-server",
            (
                self.home / ".local" / "bin" / "agent-server",
                "/opt/homebrew/bin/agent-server",
                "/usr/local/bin/agent-server",
            ),
            env_var="PAIRLING_OPENHANDS_AGENT_SERVER_BIN",
        )

    def probe(self) -> ProviderProbeResult:
        resolved = self._resolve()
        version = _installed_agent_server_version(resolved.path) if resolved else None
        exact = version == OPENHANDS_VERSION
        configured_root = os.environ.get("PAIRLING_OPENHANDS_WORKSPACE_ROOT", "").strip()
        workspace_root = (
            Path(configured_root).expanduser().resolve() if configured_root else None
        )
        root_ready = workspace_root is not None and workspace_root.is_dir()
        profile_ready = _configured_openhands_profile_id() is not None
        ready = exact and root_ready and profile_ready
        notes: tuple[str, ...]
        if resolved is None:
            notes = ("OpenHands Agent Server not found.",)
        elif not exact:
            notes = (f"Requires exact OpenHands Agent Server {OPENHANDS_VERSION}.",)
        elif not root_ready:
            notes = ("Set PAIRLING_OPENHANDS_WORKSPACE_ROOT to an allowed workspace directory.",)
        elif not profile_ready:
            notes = (
                f"Set {OPENHANDS_PROFILE_ENV} to the reviewed OpenHands agent profile UUID.",
            )
        else:
            notes = ("Pairling launches an authenticated loopback-only owned server on demand.",)
        availability = ProviderAvailability(
            provider_id=OPENHANDS_PROVIDER_ID,
            display_name=OPENHANDS_DESCRIPTOR.display_name,
            kind=OPENHANDS_DESCRIPTOR.kind,
            installed=resolved is not None,
            usable=ready,
            launchable=ready,
            auth_state="owned_session_key" if ready else "unavailable",
            config_state=(
                "pinned" if ready
                else "workspace_root_required" if exact and not root_ready
                else "agent_profile_required" if exact and root_ready
                else "unsupported_version"
            ),
            readable_sessions=0,
            live_sessions=0,
            controllable_sessions=0,
            capabilities=(
                ("detect", "owned_agent_server", "authenticated_control")
                if ready
                else ("detect",)
            ),
            setup_actions=(
                () if ready
                else ("configure_openhands_workspace_root",) if exact and not root_ready
                else ("configure_openhands_agent_profile",) if exact and root_ready
                else ("install_pinned_openhands_agent_server",)
            ),
            notes=notes,
        )
        diagnostics = ProviderDiagnostics(
            cli_path=str(resolved.path) if resolved else None,
            cli_path_source=resolved.source if resolved else None,
            version=version,
        )
        return ProviderProbeResult(
            descriptor=self.descriptor,
            availability=availability,
            diagnostics=diagnostics,
            observed_at=time.time(),
        )

    def create_control_driver(
        self, binding: ProviderControlBinding
    ) -> OpenHandsControlDriver | None:
        if (
            binding.provider_id != OPENHANDS_PROVIDER_ID
            or binding.provider_version != OPENHANDS_VERSION
            or binding.provider_channel != OPENHANDS_CHANNEL
        ):
            return None
        resolved = self._resolve()
        if resolved is None or _installed_agent_server_version(resolved.path) != OPENHANDS_VERSION:
            return None
        configured_root = os.environ.get("PAIRLING_OPENHANDS_WORKSPACE_ROOT", "").strip()
        profile_id = _configured_openhands_profile_id()
        if not configured_root or profile_id is None:
            return None
        workspace_root = Path(configured_root).expanduser().resolve()
        if not workspace_root.is_dir():
            return None
        with _OWNED_SERVERS_LOCK:
            server = _OWNED_SERVERS.get(binding.binding_id)
            if server is None:
                server = OwnedOpenHandsAgentServer(
                    executable=resolved.path,
                    version=OPENHANDS_VERSION,
                    binding_id=binding.binding_id,
                    workspace_root=workspace_root,
                    home=self.home,
                )
                _OWNED_SERVERS[binding.binding_id] = server
        return OpenHandsControlDriver(
            binding,
            server=server,
            workspace_root=workspace_root,
            owned=True,
            managed_profile_id=profile_id,
        )


@dataclass(frozen=True)
class _OpenHandsActionReceipt:
    fingerprint: str
    session_id: str | None
    result: ProviderOperationResult

@dataclass(frozen=True)
class _OpenHandsTargetRecord:
    session_id: str
    provider_id: str
    binding_id: str
    instance_id: str
    freshness: str



class OpenHandsControlDriver:
    def __init__(
        self,
        binding: ProviderControlBinding,
        *,
        transport: OpenHandsTransport | None = None,
        server: OwnedOpenHandsAgentServer | None = None,
        workspace_root: Path,
        owned: bool,
        endpoint: str | None = None,
        session_api_key: str | None = None,
        instance_id: str | None = None,
        start_review_verifier: Callable[[str, str, str, Path], bool] | None = None,
        managed_profile_id: str | None = None,
        clock: Callable[[], float] = time.time,
        snapshot_ttl: float = 5.0,
    ):
        if binding.provider_id != OPENHANDS_PROVIDER_ID:
            raise OpenHandsControlError("wrong_provider_binding")
        if transport is not None and (
            not isinstance(session_api_key, str) or len(session_api_key) < 24
        ):
            raise OpenHandsControlError("internal_auth_missing")
        self.binding = binding
        self._transport = transport
        self._server = server
        self.workspace_root = workspace_root.resolve()
        self.owned = bool(owned)
        self.endpoint = _validate_loopback_endpoint(endpoint) if endpoint else None
        self._session_api_key = session_api_key
        self._instance_id = instance_id or "unknown-instance"
        self._start_review_verifier = start_review_verifier
        self._clock = clock
        self._snapshot_ttl = snapshot_ttl
        self._managed_profile_id = _canonical_uuid_or_none(managed_profile_id)
        self.safe_launch_profile: dict[str, Any] | bool = (
            {
                "reviewed": True,
                "provider_id": OPENHANDS_PROVIDER_ID,
                "provider_version": OPENHANDS_VERSION,
                "provider_channel": OPENHANDS_CHANNEL,
                "agent_profile_id": self._managed_profile_id,
                "confirmation_policy": "AlwaysConfirm",
            }
            if self._managed_profile_id is not None
            else False
        )
        self._managed_launch_context: tuple[Path, Path, dict[str, str]] | None = None
        self._managed_launch_started = False
        self._managed_public_session_id: str | None = None
        self._managed_native_session_id: str | None = None
        self._managed_workspace: Path | None = None
        self._managed_generation = 0
        self._managed_provider_cursor: str | None = None
        self._managed_session_instance_id: str | None = None
        self._managed_server_instance_id: str | None = None
        self._snapshot_native_ids: dict[str, tuple[int, str]] = {}
        self._managed_canary_observations: dict[str, str] = {}
        self._closed = False
        self._generation_records: dict[str, tuple[str, int]] = {}
        self._generation_counters: dict[str, int] = {}
        self._last_snapshots: dict[str, ProviderControlSnapshot] = {}
        self._last_conversations: dict[str, dict[str, Any]] = {}
        self._startup_error: str | None = None
        self._authenticated = False
        self._action_lock = threading.RLock()
        self._actions: dict[
            tuple[int, str],
            _OpenHandsActionReceipt,
        ] = {}
        self._action_order: list[tuple[int, str]] = []
        self._target_records: dict[
            tuple[str, int, str],
            dict[str, _OpenHandsTargetRecord],
        ] = {}

    generation_refresh_safe = True

    @property
    def capability_generation(self) -> int | None:
        return self._managed_generation or None

    def attach_managed_launch(
        self,
        *,
        workspace_root: str,
        session_root: str,
        launch_identity: Mapping[str, Any],
    ) -> None:
        expected_keys = {"binding_id", "launch_action_id", "source_install_id"}
        if not isinstance(launch_identity, Mapping) or set(launch_identity) != expected_keys:
            raise OpenHandsControlError("managed_launch_identity_invalid")
        identity: dict[str, str] = {}
        for key in sorted(expected_keys):
            value = launch_identity.get(key)
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 256
                or any(character in value for character in "\r\n\0")
            ):
                raise OpenHandsControlError("managed_launch_identity_invalid")
            identity[key] = value
        if identity["binding_id"] != self.binding.binding_id:
            raise OpenHandsControlError("managed_launch_binding_stale")
        try:
            workspace = Path(workspace_root).expanduser().resolve(strict=True)
            state = Path(session_root).expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise OpenHandsControlError("managed_launch_root_unavailable") from exc
        if (
            not workspace.is_dir()
            or not state.is_dir()
            or workspace != self.workspace_root
        ):
            raise OpenHandsControlError("managed_launch_root_invalid")
        incoming = (workspace, state, identity)
        with self._action_lock:
            if self._closed:
                raise OpenHandsControlError("managed_driver_closed")
            if self._managed_launch_context is not None:
                if self._managed_launch_context != incoming:
                    raise OpenHandsControlError("managed_launch_context_rebound")
                return
            self._managed_launch_context = incoming

    def _managed_start_reviewed(
        self,
        binding_id: str,
        client_action_id: str,
        profile_id: str,
        cwd: Path,
    ) -> bool:
        context = self._managed_launch_context
        return bool(
            context is not None
            and binding_id == self.binding.binding_id
            and binding_id == context[2]["binding_id"]
            and client_action_id == context[2]["launch_action_id"]
            and profile_id == self._managed_profile_id
            and cwd == context[0]
            and cwd == self.workspace_root
        )

    def _managed_session_truth(
        self,
        *,
        public_session_id: str,
        native_session_id: str,
        generation: int,
        session_instance_id: str,
    ) -> dict[str, Any]:
        return {
            "provider_id": OPENHANDS_PROVIDER_ID,
            "provider": OPENHANDS_PROVIDER_ID,
            "session_id": public_session_id,
            "native_id": native_session_id,
            "binding_id": self.binding.binding_id,
            "provider_version": self.binding.provider_version,
            "provider_channel": self.binding.provider_channel,
            "project": str(self._managed_workspace or self.workspace_root),
            "cwd": str(self._managed_workspace or self.workspace_root),
            "capability_generation": max(1, int(generation)),
            "managed": True,
            "owner": "provider_driver",
            "terminal_backed": False,
            "is_live": True,
            "controllable": True,
            "session_instance_id": session_instance_id,
        }

    def _validated_launched_profile(
        self,
        conversation: Mapping[str, Any],
        profile_id: str,
    ) -> None:
        launched = conversation.get("launched_agent_profile")
        if (
            not isinstance(launched, Mapping)
            or launched.get("agent_profile_id") != profile_id
            or isinstance(launched.get("revision"), bool)
            or not isinstance(launched.get("revision"), int)
            or int(launched["revision"]) < 1
        ):
            raise OpenHandsControlError("launched_profile_mismatch")

    def launch_session(
        self,
        *,
        project: str,
        title: str,
        first_prompt: str = "",
    ) -> dict[str, Any]:
        if self._managed_profile_id is None or self.safe_launch_profile is False:
            raise OpenHandsControlError("managed_profile_unavailable")
        if (
            not isinstance(title, str)
            or len(title) > 1000
            or any(character in title for character in "\r\0")
        ):
            raise OpenHandsControlError("managed_title_invalid")
        if (
            not isinstance(first_prompt, str)
            or len(first_prompt.encode("utf-8")) > 200_000
        ):
            raise OpenHandsControlError("managed_first_prompt_invalid")
        with self._action_lock:
            context = self._managed_launch_context
            if context is None:
                raise OpenHandsControlError("managed_launch_context_missing")
            if self._managed_launch_started:
                raise OpenHandsControlError("managed_session_already_launched")
            self._managed_launch_started = True
        try:
            workspace = Path(project).expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise OpenHandsControlError("managed_project_unavailable") from exc
        if workspace != context[0] or workspace != self.workspace_root:
            raise OpenHandsControlError("managed_project_mismatch")
        action_id = context[2]["launch_action_id"]
        started = self.start_conversation(
            profile_id=self._managed_profile_id,
            working_dir=workspace,
            client_action_id=action_id,
        )
        native_id = _canonical_uuid(started.get("session_id"))
        public_id = _qualified_openhands_session_id(native_id)
        conversation = self._conversation(native_id)
        self._validated_launched_profile(conversation, self._managed_profile_id)
        if self._validated_workspace(conversation) != workspace:
            raise OpenHandsControlError("managed_workspace_mismatch")
        if self._instance_id in {"", "unknown-instance", "not-started"}:
            raise OpenHandsControlError("managed_instance_unproven")
        instance_id = f"{self.binding.binding_id}:{self._instance_id}:{native_id}"
        with self._action_lock:
            self._managed_public_session_id = public_id
            self._managed_native_session_id = native_id
            self._managed_workspace = workspace
            self._managed_session_instance_id = instance_id
            self._managed_server_instance_id = self._instance_id
        truth = self._managed_session_truth(
            public_session_id=public_id,
            native_session_id=native_id,
            generation=1,
            session_instance_id=instance_id,
        )
        snapshot = self.snapshot(session_id=public_id, session_truth=truth)
        if (
            snapshot.blocked_reason is not None
            or "session.prompt.send" not in snapshot.advertised_operations
        ):
            raise OpenHandsControlError("managed_launch_canary_failed")
        if first_prompt:
            self.execute(
                operation_id="session.prompt.send",
                input_payload={
                    "session": self.session_identity(public_id).to_payload(),
                    "prompt": first_prompt,
                },
                binding_id=self.binding.binding_id,
                capability_generation=snapshot.capability_generation,
                session_id=public_id,
                client_action_id=f"{action_id}:first-prompt",
            )
            snapshot = self.snapshot(session_id=public_id, session_truth=truth)
        if (
            snapshot.blocked_reason is not None
            or "session.prompt.send" not in snapshot.advertised_operations
        ):
            raise OpenHandsControlError("managed_launch_canary_failed")
        with self._action_lock:
            self._managed_generation = snapshot.capability_generation
            self._managed_provider_cursor = None
        self._record_managed_canaries()
        return {
            "native_session_id": native_id,
            "session_id": native_id,
            "public_session_id": public_id,
            "provider_id": OPENHANDS_PROVIDER_ID,
            "provider_version": self.binding.provider_version,
            "provider_channel": self.binding.provider_channel,
            "binding_id": self.binding.binding_id,
            "capability_generation": snapshot.capability_generation,
            "workspace": str(workspace),
            "provider_cursor": None,
            "session_instance_id": instance_id,
        }

    def _record_managed_canaries(self) -> None:
        public_id = self._managed_public_session_id
        native_id = self._managed_native_session_id
        workspace = self._managed_workspace
        generation = self._managed_generation
        if (
            public_id is None
            or native_id is None
            or workspace is None
            or generation < 1
            or not self._authenticated
            or self.endpoint is None
            or self._instance_id in {"", "unknown-instance", "not-started"}
            or self._instance_id != self._managed_server_instance_id
        ):
            raise OpenHandsControlError("managed_canary_identity_unproven")
        evidence = {
            "owned_loopback_exact_version": {
                "provider_version": self.binding.provider_version,
                "provider_channel": self.binding.provider_channel,
                "endpoint": _validate_loopback_endpoint(self.endpoint),
                "instance_id": self._instance_id,
            },
            "authenticated_api_boundary": {
                "authenticated": self._authenticated,
                "scheme": "X-Session-API-Key",
                "owned": self.owned,
            },
            "managed_workspace_profile": {
                "workspace": str(workspace),
                "profile_id": self._managed_profile_id,
            },
            "manager_identity": {
                "binding_id": self.binding.binding_id,
                "session_id": public_id,
                "native_session_id": native_id,
                "capability_generation": generation,
            },
        }
        self._managed_canary_observations = {
            name: hashlib.sha256(
                json.dumps(
                    evidence[name],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            for name in _MANAGED_CANARIES
        }

    def missing_canaries(self) -> tuple[str, ...]:
        return tuple(
            name
            for name in _MANAGED_CANARIES
            if name not in self._managed_canary_observations
        )

    def provider_canary_attestation(self) -> dict[str, Any] | None:
        missing = self.missing_canaries()
        public_id = self._managed_public_session_id
        generation = self._managed_generation
        if (
            missing
            or public_id is None
            or generation < 1
            or not self._authenticated
            or self._closed
        ):
            return None
        safe_profile = self.safe_launch_profile
        if not isinstance(safe_profile, dict):
            return None
        evidence_digest = hashlib.sha256(
            json.dumps(
                self._managed_canary_observations,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        profile_digest = hashlib.sha256(
            json.dumps(
                safe_profile,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        server_digest = (
            self._server.launch_config_digest
            if self._server is not None
            else "fixture-owned"
        )
        managed_config_digest = hashlib.sha256(
            str(server_digest).encode("utf-8")
        ).hexdigest()
        now = time.time()
        return {
            "schema_version": 1,
            "provider_id": OPENHANDS_PROVIDER_ID,
            "provider_version": self.binding.provider_version,
            "provider_channel": self.binding.provider_channel,
            "profile_digest": profile_digest,
            "managed_config_digest": managed_config_digest,
            "binding_id": self.binding.binding_id,
            "session_id": public_id,
            "capability_generation": generation,
            "canaries": list(_MANAGED_CANARIES),
            "evidence_digest": evidence_digest,
            "observed_at": now,
            "expires_at": now + 300.0,
        }

    def verify_managed_launch(self, result: Mapping[str, Any]) -> bool:
        try:
            if not isinstance(result, Mapping):
                return False
            native_id = _canonical_uuid(result.get("native_session_id"))
            public_id = _qualified_openhands_session_id(native_id)
            generation = result.get("capability_generation")
            if (
                result.get("session_id") != native_id
                or result.get("public_session_id") != public_id
                or result.get("provider_id") != OPENHANDS_PROVIDER_ID
                or result.get("provider_version") != self.binding.provider_version
                or result.get("provider_channel") != self.binding.provider_channel
                or result.get("binding_id") != self.binding.binding_id
                or isinstance(generation, bool)
                or not isinstance(generation, int)
                or generation != self._managed_generation
                or result.get("provider_cursor") != self._managed_provider_cursor
                or result.get("session_instance_id")
                != self._managed_session_instance_id
                or result.get("workspace")
                != str(self._managed_workspace)
                or native_id != self._managed_native_session_id
                or public_id != self._managed_public_session_id
            ):
                return False
            self._global_canary()
            if self._instance_id != self._managed_server_instance_id:
                return False
            conversation = self._conversation(native_id)
            self._validated_launched_profile(
                conversation,
                str(self._managed_profile_id),
            )
            return self._validated_workspace(conversation) == self._managed_workspace
        except Exception:
            return False

    def refresh_session_binding(
        self,
        session_truth: Mapping[str, Any],
    ) -> dict[str, Any]:
        public_id = self._managed_public_session_id
        native_id = self._managed_native_session_id
        workspace = self._managed_workspace
        generation = self._managed_generation
        if (
            public_id is None
            or native_id is None
            or workspace is None
            or generation < 1
            or not isinstance(session_truth, dict)
        ):
            raise OpenHandsControlError("managed_refresh_identity_stale")
        if self._validate_session_truth(
            public_id,
            session_truth,
            allow_stale_generation=True,
        ) != native_id:
            raise OpenHandsControlError("managed_refresh_identity_stale")
        self._global_canary()
        if self._instance_id != self._managed_server_instance_id:
            raise OpenHandsControlError("managed_server_instance_changed")
        conversation = self._conversation(native_id)
        self._validated_launched_profile(
            conversation,
            str(self._managed_profile_id),
        )
        if self._validated_workspace(conversation) != workspace:
            raise OpenHandsControlError("managed_workspace_mismatch")
        return {
            "binding_id": self.binding.binding_id,
            "session_id": public_id,
            "native_session_id": native_id,
            "capability_generation": generation,
            "driver_available": True,
            "lifecycle": "live",
            "provider_cursor": self._managed_provider_cursor,
        }


    def poll_events(
        self,
        provider_cursor: str | None = None,
    ) -> dict[str, Any]:
        public_id = self._managed_public_session_id
        native_id = self._managed_native_session_id
        generation = self._managed_generation
        workspace = self._managed_workspace
        session_instance_id = self._managed_session_instance_id
        if (
            public_id is None
            or native_id is None
            or generation < 1
            or workspace is None
            or session_instance_id is None
        ):
            raise OpenHandsControlError("managed_session_unavailable")
        self._global_canary()
        if self._instance_id != self._managed_server_instance_id:
            raise OpenHandsControlError("managed_server_instance_changed")
        conversation = self._conversation(native_id)
        if self._validated_workspace(conversation) != workspace:
            raise OpenHandsControlError("managed_workspace_mismatch")
        self._validated_launched_profile(
            conversation,
            str(self._managed_profile_id),
        )
        truth = self._managed_session_truth(
            public_session_id=public_id,
            native_session_id=native_id,
            generation=generation,
            session_instance_id=session_instance_id,
        )
        snapshot = self.snapshot(session_id=public_id, session_truth=truth)
        if (
            snapshot.blocked_reason is not None
            or "session.prompt.send" not in snapshot.advertised_operations
        ):
            raise OpenHandsControlError("managed_session_canary_failed")
        generation = snapshot.capability_generation
        self._managed_generation = generation
        self._record_managed_canaries()
        target = (
            f"/api/conversations/{quote(native_id, safe='')}/events/search?"
            + urlencode({"limit": 100, "sort_order": "TIMESTAMP_DESC"})
        )
        payload = self._ensure_transport().request_json("GET", target)
        items = payload.get("items") if isinstance(payload, Mapping) else None
        if not isinstance(items, list):
            raise OpenHandsControlError("managed_event_history_invalid")
        normalized: list[OpenHandsEvent] = []
        for item in items:
            if not isinstance(item, Mapping):
                raise OpenHandsControlError("managed_event_history_invalid")
            normalized.append(_normalize_event(public_id, item))
        normalized.sort(key=lambda event: (event.timestamp, event.event_id))
        start = 0
        if provider_cursor not in (None, ""):
            matches = [
                index
                for index, event in enumerate(normalized)
                if provider_cursor in {event.cursor, event.event_id}
            ]
            if len(matches) != 1:
                raise OpenHandsControlError("managed_event_cursor_invalid")
            start = matches[0] + 1
        events = [
            _managed_openhands_event_payload(event, generation, self._clock())
            for event in normalized[start:]
        ]
        next_cursor = (
            normalized[-1].cursor
            if events
            else provider_cursor or self._managed_provider_cursor
        )
        if next_cursor is not None:
            self._managed_provider_cursor = str(next_cursor)
        return {
            "events": events,
            "provider_cursor": next_cursor,
            "capability_generation": generation,
        }

    def close(self) -> None:
        with self._action_lock:
            if self._closed:
                return
            self._closed = True
            server = self._server
            self._transport = None
            self.endpoint = None
            self._session_api_key = None
            self._authenticated = False
            self._snapshot_native_ids.clear()
            self._managed_canary_observations.clear()
        if server is None or not self.owned:
            return
        with _OWNED_SERVERS_LOCK:
            if _OWNED_SERVERS.get(self.binding.binding_id) is server:
                _OWNED_SERVERS.pop(self.binding.binding_id, None)
        server.stop()


    def _ensure_transport(self) -> OpenHandsTransport:
        if self._closed:
            raise OpenHandsControlError("managed_driver_closed")
        if self._server is not None and not self._server.running:
            self._transport = None
            self.endpoint = None
            self._session_api_key = None
        if self._transport is not None:
            return self._transport
        if self._server is None:
            raise OpenHandsControlError(self._startup_error or "owned_server_unavailable")
        try:
            transport = self._server.ensure_started()
        except OpenHandsControlError as exc:
            self._startup_error = exc.code
            raise
        self._transport = transport
        self.endpoint = self._server.endpoint
        self._session_api_key = self._server.session_api_key
        self._instance_id = self._server.instance_id
        self._startup_error = None
        return transport

    def _global_canary(self) -> dict[str, Any]:
        self._authenticated = False
        if not self.owned:
            raise OpenHandsControlError("server_not_owned")
        if self.binding.provider_version != OPENHANDS_VERSION:
            raise OpenHandsControlError("unsupported_provider_version")
        if self.binding.provider_channel != OPENHANDS_CHANNEL:
            raise OpenHandsControlError("unsupported_provider_channel")
        if not self.workspace_root.is_dir():
            raise OpenHandsControlError("workspace_root_unavailable")
        transport = self._ensure_transport()
        if self.endpoint is None or self._session_api_key is None:
            raise OpenHandsControlError("internal_auth_missing")
        _validate_loopback_endpoint(self.endpoint)
        try:
            info = transport.request_json("GET", "/server_info", authenticated=False)
        except OpenHandsHttpError as exc:
            raise OpenHandsControlError(exc.code) from exc
        if not isinstance(info, dict):
            raise OpenHandsControlError("server_info_invalid")
        if info.get("title") != "OpenHands Agent Server":
            raise OpenHandsControlError("server_capability_mismatch")
        if info.get("version") != OPENHANDS_VERSION:
            raise OpenHandsControlError("unsupported_provider_version")
        try:
            count = transport.request_json("GET", "/api/conversations/count")
        except OpenHandsHttpError as exc:
            raise OpenHandsControlError(exc.code) from exc
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise OpenHandsControlError("authenticated_canary_invalid")
        try:
            transport.request_json(
                "GET", "/api/conversations/count", authenticated=False
            )
        except OpenHandsHttpError as exc:
            if exc.status not in {401, 403}:
                raise OpenHandsControlError("anonymous_canary_invalid") from exc
        else:
            raise OpenHandsControlError("anonymous_api_accessible")
        self._authenticated = True
        reported_instance = info.get("instance_id")
        if isinstance(reported_instance, str) and reported_instance:
            self._instance_id = reported_instance[:160]
        return info

    def _conversation(self, session_id: str) -> dict[str, Any]:
        transport = self._ensure_transport()
        try:
            payload = transport.request_json(
                "GET", f"/api/conversations/{quote(session_id, safe='')}"
            )
        except OpenHandsHttpError as exc:
            code = "session_not_found" if exc.status == 404 else exc.code
            raise OpenHandsControlError(code) from exc
        if not isinstance(payload, dict) or str(payload.get("id")) != session_id:
            raise OpenHandsControlError("session_identity_mismatch")
        self._validated_workspace(payload)
        self._last_conversations[session_id] = payload
        return payload

    def _validated_workspace(self, conversation: Mapping[str, Any]) -> Path:
        workspace = conversation.get("workspace")
        if not isinstance(workspace, Mapping) or workspace.get("kind") != "LocalWorkspace":
            raise OpenHandsControlError("workspace_capability_unsupported")
        raw = workspace.get("working_dir")
        if not isinstance(raw, str) or not raw:
            raise OpenHandsControlError("workspace_missing")
        path = Path(raw).expanduser().resolve()
        if not path.is_dir() or not _is_within(path, self.workspace_root):
            raise OpenHandsControlError("workspace_outside_owned_root")
        return path

    def _target_record_from_conversation(
        self,
        conversation: Mapping[str, Any],
    ) -> _OpenHandsTargetRecord:
        session_id = conversation.get("id")
        try:
            canonical_id = str(UUID(session_id))
        except (TypeError, ValueError) as exc:
            raise OpenHandsControlError("target_session_identity_invalid") from exc
        if canonical_id != session_id:
            raise OpenHandsControlError("target_session_identity_invalid")
        if self._instance_id in {"", "unknown-instance", "not-started"}:
            raise OpenHandsControlError("target_session_instance_unproven")
        policy = conversation.get("confirmation_policy")
        policy_kind = policy.get("kind") if isinstance(policy, Mapping) else None
        if policy_kind not in _ACTIVE_CONFIRMATION_POLICIES:
            raise OpenHandsControlError("target_session_policy_inactive")
        if not _provider_permission_policy_safe(conversation):
            raise OpenHandsControlError("target_session_permission_mode_unsafe")
        updated_at = conversation.get("updated_at")
        execution_status = conversation.get("execution_status")
        leaf_event_id = conversation.get("leaf_event_id")
        if (
            not isinstance(updated_at, str)
            or not updated_at
            or len(updated_at) > 512
            or not isinstance(execution_status, str)
            or not execution_status
            or len(execution_status) > 160
            or (
                leaf_event_id is not None
                and (
                    not isinstance(leaf_event_id, str)
                    or not leaf_event_id
                    or len(leaf_event_id) > 512
                )
            )
        ):
            raise OpenHandsControlError("target_session_freshness_unavailable")
        workspace = self._validated_workspace(conversation)
        agent = conversation.get("agent")
        permission_mode = (
            agent.get("acp_session_mode")
            if isinstance(agent, Mapping)
            else None
        )
        freshness = hashlib.sha256(
            json.dumps(
                {
                    "id": canonical_id,
                    "updated_at": updated_at,
                    "leaf_event_id": leaf_event_id,
                    "execution_status": execution_status,
                    "confirmation_policy": policy_kind,
                    "permission_mode": permission_mode,
                    "workspace": hashlib.sha256(
                        str(workspace).encode("utf-8")
                    ).hexdigest(),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return _OpenHandsTargetRecord(
            canonical_id,
            OPENHANDS_PROVIDER_ID,
            self.binding.binding_id,
            self._instance_id,
            freshness,
        )

    def _owned_conversation_targets(
        self,
    ) -> tuple[_OpenHandsTargetRecord, ...]:
        payload = self._ensure_transport().request_json(
            "GET",
            "/api/conversations/search?limit=100",
        )
        items = payload.get("items") if isinstance(payload, Mapping) else None
        if not isinstance(items, list):
            raise OpenHandsControlError("conversation_search_invalid")
        records: dict[str, _OpenHandsTargetRecord] = {}
        duplicates: set[str] = set()
        for item in items:
            if not isinstance(item, Mapping):
                continue
            try:
                record = self._target_record_from_conversation(item)
            except OpenHandsControlError:
                continue
            if record.session_id in records:
                duplicates.add(record.session_id)
                records.pop(record.session_id, None)
                continue
            if record.session_id not in duplicates:
                records[record.session_id] = record
        return tuple(records.values())


    def _pending_action_ids(self, session_id: str, conversation: Mapping[str, Any]) -> tuple[str, ...]:
        if conversation.get("execution_status") != "waiting_for_confirmation":
            return ()
        transport = self._ensure_transport()
        target = (
            f"/api/conversations/{quote(session_id, safe='')}/events/search?"
            + urlencode({"limit": 100, "sort_order": "TIMESTAMP_DESC"})
        )
        payload = transport.request_json("GET", target)
        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            raise OpenHandsControlError("event_capability_invalid")
        observed: set[str] = set()
        actions: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            kind = item.get("kind")
            action_id = item.get("action_id")
            if kind in {"ObservationEvent", "UserRejectObservation"} and isinstance(action_id, str):
                observed.add(action_id)
            if kind == "ActionEvent" and isinstance(item.get("id"), str):
                actions.append(item["id"])
        return tuple(action_id for action_id in actions if action_id not in observed)

    def snapshot(
        self,
        *,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderControlSnapshot:
        observed_at = self._clock()
        operations: list[str] = []
        blocked_reason: str | None = None
        policy_kind = "unavailable"
        pending_ids: tuple[str, ...] = ()
        model_choices: tuple[ControlChoice, ...] = ()
        current_model: str | None = None
        resume_targets: tuple[_OpenHandsTargetRecord, ...] = ()
        fork_targets: tuple[_OpenHandsTargetRecord, ...] = ()
        cursor = self._instance_id
        conversation: dict[str, Any] | None = None
        native_session_id: str | None = None
        try:
            native_session_id = self._validate_session_truth(
                session_id,
                session_truth,
            )
            self._global_canary()
            operations = list(_READ_OPERATIONS) if session_id is None else []
            if session_id is not None and native_session_id is not None:
                conversation = self._conversation(native_session_id)
                policy = conversation.get("confirmation_policy")
                policy_kind = policy.get("kind") if isinstance(policy, dict) else "unknown"
                pending_ids = self._pending_action_ids(native_session_id, conversation)
                cursor_value = conversation.get("leaf_event_id") or conversation.get("updated_at")
                if isinstance(cursor_value, str) and cursor_value:
                    cursor = cursor_value[:512]
                if policy_kind not in _ACTIVE_CONFIRMATION_POLICIES:
                    blocked_reason = "confirmation_policy_inactive"
                elif not _provider_permission_policy_safe(conversation):
                    blocked_reason = "provider_permission_mode_unsafe"
                elif len(pending_ids) > 1:
                    blocked_reason = "pending_confirmation_ambiguous"
                else:
                    operations.extend(_SESSION_MUTATIONS)
                    try:
                        resume_targets = self._owned_conversation_targets()
                    except OpenHandsControlError:
                        resume_targets = ()
                    if resume_targets:
                        operations.append(_TARGET_SESSION_MUTATIONS[0])
                    fork_targets = tuple(
                        target
                        for target in resume_targets
                        if target.session_id == native_session_id
                    )
                    if fork_targets:
                        operations.append(_TARGET_SESSION_MUTATIONS[1])
                    available = conversation.get("available_models")
                    if conversation.get("supports_runtime_model_switch") is True and isinstance(available, list):
                        choices: list[ControlChoice] = []
                        for item in available:
                            if not isinstance(item, dict):
                                continue
                            model_id = item.get("model_id")
                            if not isinstance(model_id, str) or not model_id or len(model_id) > 256:
                                continue
                            label = item.get("name")
                            if not isinstance(label, str) or not label:
                                label = model_id
                            choices.append(ControlChoice(model_id, label[:160]))
                        if choices:
                            model_choices = tuple(choices)
                            operations.append("session.model.set")
                            raw_current = conversation.get("current_model_id")
                            if isinstance(raw_current, str) and any(c.value == raw_current for c in choices):
                                current_model = raw_current
                    if len(pending_ids) == 1:
                        operations.append("session.approval.decide")
        except OpenHandsControlError as exc:
            blocked_reason = exc.code

        operations_tuple = (
            tuple(dict.fromkeys(operations))
            if blocked_reason is None
            else ()
        )
        fingerprint = json.dumps(
            {
                "instance": self._instance_id,
                "operations": operations_tuple,
                "blocked": blocked_reason,
                "policy": policy_kind,
                "pending": pending_ids,
                "models": [(choice.value, choice.label) for choice in model_choices],
                "current_model": current_model,
                "resume_targets": [
                    (target.session_id, target.freshness)
                    for target in resume_targets
                ],
                "fork_targets": [
                    (target.session_id, target.freshness)
                    for target in fork_targets
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        key = session_id or "__provider__"
        generation = self._generation(key, fingerprint)
        values: list[ControlValue] = []
        choices_groups: list[ControlChoices] = []
        if session_id is not None:
            identity = ProviderSessionIdentity(
                OPENHANDS_PROVIDER_ID,
                session_id,
                self.binding.binding_id,
                generation,
            )
            for operation_id in operations_tuple:
                if operation_id.startswith("session."):
                    values.append(ControlValue(operation_id, "session", identity))
            if resume_targets and "session.resume" in operations_tuple:
                choices_groups.append(
                    ControlChoices(
                        "session.resume",
                        "target_session",
                        tuple(
                            ControlChoice(
                                _qualified_openhands_session_id(target.session_id),
                                f"OpenHands conversation {index}",
                            )
                            for index, target in enumerate(
                                resume_targets,
                                start=1,
                            )
                        ),
                    )
                )
            if fork_targets and "session.fork" in operations_tuple:
                choices_groups.append(
                    ControlChoices(
                        "session.fork",
                        "target_session",
                        (
                            ControlChoice(
                                _qualified_openhands_session_id(
                                    fork_targets[0].session_id
                                ),
                                "Current OpenHands conversation",
                            ),
                        ),
                    )
                )
            if current_model is not None and "session.model.set" in operations_tuple:
                values.append(ControlValue("session.model.set", "model", current_model))
            if model_choices and "session.model.set" in operations_tuple:
                choices_groups.append(ControlChoices("session.model.set", "model", model_choices))
            if len(pending_ids) == 1 and "session.approval.decide" in operations_tuple:
                values.append(
                    ControlValue("session.approval.decide", "approval_id", pending_ids[0])
                )
                choices_groups.append(
                    ControlChoices(
                        "session.approval.decide",
                        "decision",
                        (
                            ControlChoice("accept", "Approve once"),
                            ControlChoice("reject", "Reject"),
                        ),
                    )
                )
        snapshot = ProviderControlSnapshot(
            provider_id=OPENHANDS_PROVIDER_ID,
            provider_version=self.binding.provider_version,
            provider_channel=self.binding.provider_channel,
            binding_id=self.binding.binding_id,
            capability_generation=generation,
            observed_at=observed_at,
            valid_until=observed_at + self._snapshot_ttl,
            advertised_operations=operations_tuple,
            values=tuple(values),
            choices=tuple(choices_groups),
            blocked_reason=blocked_reason,
            provider_cursor=cursor or self._instance_id,
        )
        snapshot.validate(now=observed_at)
        self._last_snapshots[key] = snapshot
        if (
            session_id is not None
            and native_session_id is not None
            and blocked_reason is None
        ):
            self._snapshot_native_ids[session_id] = (
                generation,
                native_session_id,
            )
        if session_id is not None:
            with self._action_lock:
                stale_target_keys = tuple(
                    target_key
                    for target_key in self._target_records
                    if target_key[0] == session_id
                )
                for target_key in stale_target_keys:
                    self._target_records.pop(target_key, None)
                if "session.resume" in operations_tuple:
                    self._target_records[
                        (session_id, generation, "session.resume")
                    ] = {
                        _qualified_openhands_session_id(target.session_id): target
                        for target in resume_targets
                    }
                if "session.fork" in operations_tuple:
                    self._target_records[
                        (session_id, generation, "session.fork")
                    ] = {
                        _qualified_openhands_session_id(target.session_id): target
                        for target in fork_targets
                    }
        return snapshot

    def _generation(self, key: str, fingerprint: str) -> int:
        previous = self._generation_records.get(key)
        if previous is not None and previous[0] == fingerprint:
            return previous[1]
        generation = self._generation_counters.get(key, 0) + 1
        self._generation_counters[key] = generation
        self._generation_records[key] = (fingerprint, generation)
        return generation

    def _invalidate(self, session_id: str | None) -> None:
        key = session_id or "__provider__"
        self._generation_records.pop(key, None)

    def _validate_session_truth(
        self,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
        *,
        allow_stale_generation: bool = False,
    ) -> str | None:
        if session_id is None:
            if session_truth is not None:
                raise OpenHandsControlError("provider_snapshot_has_session_truth")
            return None
        if not isinstance(session_truth, dict):
            raise OpenHandsControlError("session_truth_required")
        native_id = _native_openhands_session_id(session_id)
        instance_id = session_truth.get("session_instance_id")
        expected = {
            "provider_id": OPENHANDS_PROVIDER_ID,
            "provider": OPENHANDS_PROVIDER_ID,
            "session_id": session_id,
            "native_id": native_id,
            "binding_id": self.binding.binding_id,
            "managed": True,
            "owner": "provider_driver",
            "terminal_backed": False,
            "is_live": True,
            "controllable": True,
        }
        if any(session_truth.get(key) != value for key, value in expected.items()):
            raise OpenHandsControlError("session_truth_mismatch")
        generation = session_truth.get("capability_generation")
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 1
            or not isinstance(instance_id, str)
            or not instance_id
            or len(instance_id) > 512
        ):
            raise OpenHandsControlError("session_truth_invalid")
        if self._managed_public_session_id is not None:
            managed_expected = {
                "session_id": self._managed_public_session_id,
                "native_id": self._managed_native_session_id,
                "provider_version": self.binding.provider_version,
                "provider_channel": self.binding.provider_channel,
                "project": str(self._managed_workspace),
                "cwd": str(self._managed_workspace),
            }
            if any(
                session_truth.get(key) != value
                for key, value in managed_expected.items()
            ) or (
                not allow_stale_generation
                and self._managed_generation > 0
                and generation != self._managed_generation
            ):
                raise OpenHandsControlError("managed_session_truth_stale")
        return native_id

    def session_identity(self, session_id: str) -> ProviderSessionIdentity:
        key = session_id
        snapshot = self._last_snapshots.get(key)
        if snapshot is None:
            raise OpenHandsControlError("snapshot_required")
        return ProviderSessionIdentity(
            OPENHANDS_PROVIDER_ID,
            session_id,
            self.binding.binding_id,
            snapshot.capability_generation,
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
            raise OpenHandsControlError("operation_correlation_not_supported")
        self._validate_session_truth(session_id, session_truth)
        snapshot = self._last_snapshots.get(session_id)
        if (
            snapshot is None
            or snapshot.capability_generation != capability_generation
            or operation_id not in snapshot.advertised_operations
        ):
            raise OpenHandsControlError("operation_correlation_truth_stale")
        snapshot.validate(now=self._clock())
        return ProviderOperationCorrelation(
            f"openhands:{client_action_id}",
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
            raise OpenHandsControlError("binding_mismatch")
        if (
            not isinstance(client_action_id, str)
            or not client_action_id
            or len(client_action_id) > 512
            or any(ord(character) < 32 for character in client_action_id)
        ):
            raise OpenHandsControlError("client_action_id_invalid")
        try:
            definition = REVIEWED_OPERATION_CATALOG.require(operation_id)
            input_payload = definition.validate_input_payload(input_payload)
        except OperationCatalogError as exc:
            raise OpenHandsControlError("operation_input_not_reviewed") from exc
        key = session_id or "__provider__"
        fresh = self._last_snapshots.get(key)
        if fresh is None:
            raise OpenHandsControlError("snapshot_required")
        try:
            fresh.validate(now=self._clock())
        except Exception as exc:
            raise OpenHandsControlError("snapshot_expired") from exc
        if capability_generation != fresh.capability_generation:
            raise OpenHandsControlError("stale_capability_generation")
        if operation_id not in fresh.advertised_operations:
            raise OpenHandsControlError("operation_not_advertised")
        expected_operation_id = f"openhands:{client_action_id}"
        if provider_correlation is None:
            provider_correlation = ProviderOperationCorrelation(
                expected_operation_id,
                fresh.provider_cursor,
            )
        elif (
            not isinstance(provider_correlation, ProviderOperationCorrelation)
            or provider_correlation.provider_operation_id
            != expected_operation_id
        ):
            raise OpenHandsControlError(
                "operation_correlation_truth_stale"
            )
        self._validate_input_session(
            input_payload,
            session_id,
            capability_generation,
        )
        native_session_id: str | None = None
        if session_id is not None:
            native_record = self._snapshot_native_ids.get(session_id)
            if (
                native_record is None
                or native_record[0] != capability_generation
            ):
                raise OpenHandsControlError("session_native_identity_unproven")
            native_session_id = native_record[1]
        fingerprint = _operation_fingerprint(
            operation_id,
            input_payload,
            session_id,
        )
        receipt_key = (capability_generation, client_action_id)
        with self._action_lock:
            previous = self._actions.get(receipt_key)
        if previous is not None:
            if (
                previous.fingerprint == fingerprint
                and previous.session_id == session_id
            ):
                return previous.result
            raise OpenHandsControlError("client_action_id_reused")
        if prepared_attachments:
            raise OpenHandsControlError("attachments_not_supported")

        self._global_canary()
        if session_id is not None and native_session_id is not None:
            conversation = self._conversation(native_session_id)
            policy = conversation.get("confirmation_policy")
            policy_kind = policy.get("kind") if isinstance(policy, Mapping) else None
            if policy_kind not in _ACTIVE_CONFIRMATION_POLICIES:
                raise OpenHandsControlError("confirmation_policy_inactive")
            if not _provider_permission_policy_safe(conversation):
                raise OpenHandsControlError("provider_permission_mode_unsafe")
        status = OperationResultStatus.APPLIED
        public_result: dict[str, Any]
        transport = self._ensure_transport()
        correlation = client_action_id
        try:
            if operation_id == "provider.auth.read":
                public_result = self._auth_status(fresh)
            elif operation_id == "provider.diagnostics.read":
                public_result = self._diagnostics(fresh)
            elif operation_id == "provider.config.read":
                public_result = self._config_status(native_session_id)
            elif operation_id == "provider.usage.read":
                public_result = self._usage_status()
            elif session_id is None:
                raise OpenHandsControlError("session_required")
            elif operation_id == "session.prompt.send":
                prompt = input_payload["prompt"]
                target = f"/api/conversations/{quote(native_session_id, safe='')}/events"
                transport.request_json(
                    "POST",
                    target,
                    {"role": "user", "content": [{"text": prompt}], "run": True},
                    correlation_id=correlation,
                )
                public_result = {"accepted": True}
            elif operation_id == "session.turn.interrupt":
                transport.request_json(
                    "POST",
                    f"/api/conversations/{quote(native_session_id, safe='')}/interrupt",
                    {},
                    correlation_id=correlation,
                )
                public_result = {"interrupted": True}
            elif operation_id == "session.resume":
                target_session_id = self._validated_target_session(
                    operation_id=operation_id,
                    value=input_payload.get("target_session"),
                    proof_session_id=session_id,
                    generation=capability_generation,
                )
                self._ensure_transport().request_json(
                    "POST",
                    f"/api/conversations/{quote(target_session_id, safe='')}/run",
                    {},
                    correlation_id=correlation,
                )
                public_result = {"running": True}
            elif operation_id == "session.fork":
                target_session_id = self._validated_target_session(
                    operation_id=operation_id,
                    value=input_payload.get("target_session"),
                    proof_session_id=session_id,
                    generation=capability_generation,
                )
                fork = self._ensure_transport().request_json(
                    "POST",
                    f"/api/conversations/{quote(target_session_id, safe='')}/fork",
                    {},
                    correlation_id=correlation,
                )
                fork_id = _canonical_uuid(
                    fork.get("id") if isinstance(fork, dict) else None
                )
                public_result = {"session_id": fork_id}
            elif operation_id == "session.compact":
                transport.request_json(
                    "POST",
                    f"/api/conversations/{quote(native_session_id, safe='')}/condense",
                    {},
                    correlation_id=correlation,
                )
                public_result = {"condensed": True}
            elif operation_id == "session.rewind":
                transport.request_json(
                    "POST",
                    f"/api/conversations/{quote(native_session_id, safe='')}/navigate",
                    {"event_id": input_payload["turn_id"]},
                    correlation_id=correlation,
                )
                public_result = {"event_id": input_payload["turn_id"]}
            elif operation_id == "session.model.set":
                transport.request_json(
                    "POST",
                    f"/api/conversations/{quote(native_session_id, safe='')}/switch_acp_model",
                    {"model": input_payload["model"]},
                    correlation_id=correlation,
                )
                public_result = {"model": input_payload["model"]}
            elif operation_id == "session.approval.decide":
                conversation = self._conversation(native_session_id)
                pending = self._pending_action_ids(native_session_id, conversation)
                if pending != (input_payload["approval_id"],):
                    raise OpenHandsControlError("pending_confirmation_changed")
                accepted = input_payload["decision"] == "accept"
                transport.request_json(
                    "POST",
                    f"/api/conversations/{quote(native_session_id, safe='')}/events/respond_to_confirmation",
                    {"accept": accepted, "reason": "" if accepted else "Rejected by reviewed Pairling action."},
                    correlation_id=correlation,
                )
                public_result = {"approval_id": pending[0], "accepted": accepted}
            else:
                raise OpenHandsControlError("operation_not_implemented")
        except OpenHandsHttpError as exc:
            result_status = (
                OperationResultStatus.REJECTED
                if exc.status in {400, 401, 403, 404, 409, 422}
                else OperationResultStatus.OUTCOME_UNKNOWN
            )
            result = ProviderOperationResult(
                operation_id,
                provider_correlation.provider_operation_id,
                result_status,
                {"error": exc.code},
                provider_correlation.provider_cursor,
            )
            self._remember_action(
                receipt_key,
                fingerprint,
                session_id,
                result,
            )
            return result

        if operation_id.startswith("session."):
            self._invalidate(session_id)
        result = ProviderOperationResult(
            operation_id=operation_id,
            provider_operation_id=provider_correlation.provider_operation_id,
            status=status,
            public_result=_redact_json(public_result),
            provider_cursor=provider_correlation.provider_cursor,
        )
        result.validate()
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
            or not isinstance(provider_correlation, ProviderOperationCorrelation)
        ):
            return None
        try:
            self._validate_session_truth(session_id, session_truth)
        except OpenHandsControlError:
            return None
        if (
            session_id is not None
            and session_truth.get("capability_generation")
            != capability_generation
        ):
            return None
        with self._action_lock:
            receipt = self._actions.get(
                (capability_generation, client_action_id)
            )
        if (
            receipt is None
            or receipt.session_id != session_id
            or receipt.result.operation_id != operation_id
            or receipt.result.provider_operation_id
            != provider_correlation.provider_operation_id
            or receipt.result.provider_cursor
            != provider_correlation.provider_cursor
            or receipt.result.status
            not in {
                OperationResultStatus.APPLIED,
                OperationResultStatus.REJECTED,
            }
        ):
            return None
        return receipt.result

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
            self._actions[key] = _OpenHandsActionReceipt(
                fingerprint,
                session_id,
                result,
            )
            self._action_order.append(key)
            while len(self._action_order) > _MAX_ACTION_RESULTS:
                oldest = self._action_order.pop(0)
                self._actions.pop(oldest, None)

    def _validate_input_session(
        self,
        input_payload: Mapping[str, Any],
        session_id: str | None,
        generation: int,
    ) -> None:
        raw = input_payload.get("session")
        if raw is None:
            return
        if not isinstance(raw, Mapping):
            raise OpenHandsControlError("provider_session_invalid")
        try:
            identity = ProviderSessionIdentity.from_payload(raw)
        except Exception as exc:
            raise OpenHandsControlError("provider_session_invalid") from exc
        if (
            identity.provider_id != OPENHANDS_PROVIDER_ID
            or identity.session_id != session_id
            or identity.binding_id != self.binding.binding_id
            or identity.capability_generation != generation
        ):
            raise OpenHandsControlError("provider_session_mismatch")

    def _validated_target_session(
        self,
        *,
        operation_id: str,
        value: Any,
        proof_session_id: str,
        generation: int,
    ) -> str:
        if operation_id not in _TARGET_SESSION_MUTATIONS:
            raise OpenHandsControlError("target_session_operation_invalid")
        try:
            public_id = str(value)
            native_id = _native_openhands_session_id(public_id)
        except OpenHandsControlError as exc:
            raise OpenHandsControlError("target_session_invalid") from exc
        with self._action_lock:
            record = self._target_records.get(
                (proof_session_id, generation, operation_id),
                {},
            ).get(public_id)
        if record is None:
            raise OpenHandsControlError("target_session_not_owned")
        self._global_canary()
        if (
            record.provider_id != OPENHANDS_PROVIDER_ID
            or record.binding_id != self.binding.binding_id
            or record.instance_id != self._instance_id
        ):
            raise OpenHandsControlError("target_session_not_owned")
        try:
            conversation = self._conversation(native_id)
        except OpenHandsControlError as exc:
            if exc.code == "session_not_found":
                raise OpenHandsControlError("target_session_not_found") from exc
            raise
        try:
            current = self._target_record_from_conversation(conversation)
        except OpenHandsControlError as exc:
            raise OpenHandsControlError("target_session_stale") from exc
        if current != record:
            raise OpenHandsControlError("target_session_stale")
        return native_id


    def _auth_status(self, snapshot: ProviderControlSnapshot) -> dict[str, Any]:
        return {
            "authenticated": self._authenticated,
            "scheme": "X-Session-API-Key",
            "owned": self.owned,
            "loopback_only": bool(self.endpoint),
        }

    def _diagnostics(self, snapshot: ProviderControlSnapshot) -> dict[str, Any]:
        server_running = self._server.running if self._server is not None else self._transport is not None
        digest = self._server.launch_config_digest if self._server is not None else "fixture-owned"
        return {
            "provider_id": OPENHANDS_PROVIDER_ID,
            "version": self.binding.provider_version,
            "channel": self.binding.provider_channel,
            "owned": self.owned,
            "loopback_only": bool(self.endpoint),
            "authenticated": self._auth_status(snapshot)["authenticated"],
            "server_running": server_running,
            "launch_config_digest": digest,
            "blocked_reason": snapshot.blocked_reason,
        }

    def _config_status(self, session_id: str | None) -> dict[str, Any]:
        if session_id is None:
            info = self._global_canary()
            return {"server_title": info.get("title"), "version": info.get("version")}
        conversation = self._conversation(session_id)
        policy = conversation.get("confirmation_policy")
        profile_id = None
        profile_revision = None
        current_model = conversation.get("current_model_id")
        if not isinstance(current_model, str):
            agent = conversation.get("agent")
            llm = agent.get("llm") if isinstance(agent, dict) else None
            current_model = llm.get("model") if isinstance(llm, dict) else None
        launched = conversation.get("launched_agent_profile")
        if isinstance(launched, dict):
            raw_profile_id = launched.get("agent_profile_id")
            if raw_profile_id is not None:
                profile_id = str(raw_profile_id)
            raw_revision = launched.get("revision")
            if isinstance(raw_revision, int) and not isinstance(raw_revision, bool):
                profile_revision = raw_revision
        models = []
        for item in conversation.get("available_models", []):
            if isinstance(item, dict) and isinstance(item.get("model_id"), str):
                models.append(
                    {
                        "model_id": item["model_id"],
                        "name": item.get("name") if isinstance(item.get("name"), str) else item["model_id"],
                    }
                )
        return {
            "session_id": _qualified_openhands_session_id(session_id),
            "execution_status": conversation.get("execution_status"),
            "confirmation_policy": policy.get("kind") if isinstance(policy, dict) else None,
            "current_model_id": current_model,
            "available_models": models,
            "profile_id": profile_id,
            "profile_revision": profile_revision,
            "workspace": str(self._validated_workspace(conversation)),
        }

    def _usage_status(self) -> dict[str, Any]:
        payload = self._ensure_transport().request_json(
            "GET", "/api/conversations/search?" + urlencode({"limit": 100})
        )
        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            raise OpenHandsControlError("usage_response_invalid")
        conversations = []
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                continue
            metrics = item.get("metrics")
            try:
                public_session_id = _qualified_openhands_session_id(
                    _canonical_uuid(item["id"])
                )
            except OpenHandsControlError:
                continue
            conversations.append(
                {
                    "session_id": public_session_id,
                    "metrics": _redact_json(metrics) if isinstance(metrics, dict) else {},
                }
            )
        return {"conversations": conversations}

    def start_conversation(
        self,
        *,
        profile_id: str,
        working_dir: Path,
        client_action_id: str,
    ) -> dict[str, Any]:
        try:
            profile_id = _canonical_uuid(profile_id)
        except OpenHandsControlError as exc:
            raise OpenHandsControlError("profile_id_invalid") from exc
        cwd = working_dir.expanduser().resolve()
        if not cwd.is_dir() or not _is_within(cwd, self.workspace_root):
            raise OpenHandsControlError("workspace_outside_owned_root")
        verifier = self._start_review_verifier
        reviewed = (
            verifier(
                self.binding.binding_id,
                client_action_id,
                profile_id,
                cwd,
            )
            if verifier is not None
            else self._managed_start_reviewed(
                self.binding.binding_id,
                client_action_id,
                profile_id,
                cwd,
            )
        )
        if reviewed is not True:
            raise OpenHandsControlError("start_review_required")
        self._global_canary()
        payload = {
            "workspace": {"kind": "LocalWorkspace", "working_dir": str(cwd)},
            "agent_profile_id": profile_id,
            "confirmation_policy": {"kind": "AlwaysConfirm"},
        }
        response = self._ensure_transport().request_json(
            "POST",
            "/api/conversations",
            payload,
            correlation_id=client_action_id,
        )
        if not isinstance(response, dict):
            raise OpenHandsControlError("conversation_start_response_invalid")
        native_id = _canonical_uuid(response.get("id"))
        policy = response.get("confirmation_policy")
        if not isinstance(policy, dict) or policy.get("kind") not in _ACTIVE_CONFIRMATION_POLICIES:
            raise OpenHandsControlError("confirmation_policy_inactive")
        if not _provider_permission_policy_safe(response):
            raise OpenHandsControlError("provider_permission_mode_unsafe")
        if self._validated_workspace(response) != cwd:
            raise OpenHandsControlError("conversation_workspace_mismatch")
        self._validated_launched_profile(response, profile_id)
        return {
            "session_id": native_id,
            "execution_status": response.get("execution_status"),
            "workspace": str(cwd),
            "confirmation_policy": policy["kind"],
        }


    def stream_events(
        self,
        session_id: str,
        *,
        socket_factory: OpenHandsEventSocketFactory | None = None,
        max_reconnects: int = 3,
        reconnect_delay: float = 0.25,
    ) -> OpenHandsEventStream:
        self._global_canary()
        conversation = self._conversation(session_id)
        self._validated_workspace(conversation)
        if self.endpoint is None or self._session_api_key is None:
            raise OpenHandsControlError("internal_auth_missing")
        return OpenHandsEventStream(
            endpoint=self.endpoint,
            session_api_key=self._session_api_key,
            session_id=session_id,
            socket_factory=socket_factory or StdlibOpenHandsEventSocketFactory(),
            max_reconnects=max_reconnects,
            reconnect_delay=reconnect_delay,
        )


@dataclass(frozen=True)
class OpenHandsEvent:
    provider_id: str
    session_id: str
    event_id: str
    kind: str
    timestamp: str
    cursor: str
    public_payload: dict[str, Any]


class OpenHandsEventSocket(Protocol):
    def recv_json(self) -> dict[str, Any]:
        ...

    def close(self) -> None:
        ...


class OpenHandsEventSocketFactory(Protocol):
    def connect(
        self,
        *,
        endpoint: str,
        session_api_key: str,
        session_id: str,
        after_timestamp: str | None,
    ) -> OpenHandsEventSocket:
        ...


class OpenHandsEventStream(Iterator[OpenHandsEvent]):
    def __init__(
        self,
        *,
        endpoint: str,
        session_api_key: str,
        session_id: str,
        socket_factory: OpenHandsEventSocketFactory,
        max_reconnects: int,
        reconnect_delay: float,
    ):
        self.endpoint = _validate_loopback_endpoint(endpoint)
        self._session_api_key = session_api_key
        self.session_id = session_id
        self.socket_factory = socket_factory
        self.max_reconnects = max(0, max_reconnects)
        self.reconnect_delay = max(0.0, reconnect_delay)
        self._socket: OpenHandsEventSocket | None = None
        self._after_timestamp: str | None = None
        self._seen_event_ids: set[str] = set()
        self._reconnects = 0
        self._closed = False

    def __iter__(self) -> OpenHandsEventStream:
        return self

    def __next__(self) -> OpenHandsEvent:
        while not self._closed:
            try:
                if self._socket is None:
                    self._socket = self.socket_factory.connect(
                        endpoint=self.endpoint,
                        session_api_key=self._session_api_key,
                        session_id=self.session_id,
                        after_timestamp=self._after_timestamp,
                    )
                raw = self._socket.recv_json()
                event = _normalize_event(self.session_id, raw)
                if event.event_id in self._seen_event_ids:
                    continue
                self._seen_event_ids.add(event.event_id)
                if len(self._seen_event_ids) > 4096:
                    self._seen_event_ids = {event.event_id}
                self._after_timestamp = event.timestamp
                return event
            except (ConnectionError, TimeoutError, OSError, StopIteration, OpenHandsControlError):
                if self._socket is not None:
                    try:
                        self._socket.close()
                    finally:
                        self._socket = None
                if self._reconnects >= self.max_reconnects:
                    self.close()
                    raise OpenHandsControlError("event_stream_reconnect_exhausted")
                self._reconnects += 1
                if self.reconnect_delay:
                    time.sleep(self.reconnect_delay)
        raise StopIteration

    def close(self) -> None:
        self._closed = True
        if self._socket is not None:
            self._socket.close()
            self._socket = None


class StdlibOpenHandsEventSocketFactory:
    def connect(
        self,
        *,
        endpoint: str,
        session_api_key: str,
        session_id: str,
        after_timestamp: str | None,
    ) -> OpenHandsEventSocket:
        return _StdlibWebSocket(
            endpoint=endpoint,
            session_api_key=session_api_key,
            session_id=session_id,
            after_timestamp=after_timestamp,
        )


class _StdlibWebSocket:
    """Bounded RFC 6455 client for the fixed loopback JSON event socket."""

    def __init__(
        self,
        *,
        endpoint: str,
        session_api_key: str,
        session_id: str,
        after_timestamp: str | None,
    ):
        parsed = urlsplit(_validate_loopback_endpoint(endpoint))
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
            raise OpenHandsControlError("event_socket_endpoint_invalid")
        query = {"resend_mode": "since" if after_timestamp else "all"}
        if after_timestamp:
            query["after_timestamp"] = after_timestamp
        target = (
            f"/sockets/events/{quote(session_id, safe='')}?" + urlencode(query)
        )
        self._socket = socket.create_connection((parsed.hostname, parsed.port), timeout=5.0)
        self._socket.settimeout(30.0)
        self._recv_buffer = bytearray()
        nonce = secrets.token_bytes(16)
        websocket_key = base64.b64encode(nonce).decode("ascii")
        request = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {websocket_key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        self._socket.sendall(request)
        response = self._read_headers()
        status_line = response.split(b"\r\n", 1)[0]
        if b" 101 " not in status_line:
            self.close()
            raise OpenHandsControlError("event_socket_upgrade_failed")
        accept = None
        for line in response.split(b"\r\n")[1:]:
            if line.lower().startswith(b"sec-websocket-accept:"):
                accept = line.split(b":", 1)[1].strip().decode("ascii", "strict")
                break
        expected = base64.b64encode(
            hashlib.sha1(websocket_key.encode("ascii") + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
        ).decode("ascii")
        if not accept or not secrets.compare_digest(accept, expected):
            self.close()
            raise OpenHandsControlError("event_socket_upgrade_invalid")
        self._send_frame(
            0x1,
            json.dumps(
                {"type": "auth", "session_api_key": session_api_key},
                separators=(",", ":"),
            ).encode("utf-8"),
        )

    def _read_headers(self) -> bytes:
        chunks = bytearray()
        while b"\r\n\r\n" not in chunks:
            part = self._socket.recv(4096)
            if not part:
                raise ConnectionError("event socket closed during upgrade")
            chunks.extend(part)
            if len(chunks) > 32768:
                raise OpenHandsControlError("event_socket_headers_too_large")
        header, _separator, extra = bytes(chunks).partition(b"\r\n\r\n")
        self._recv_buffer.extend(extra)
        return header + b"\r\n"

    def recv_json(self) -> dict[str, Any]:
        fragments = bytearray()
        opcode: int | None = None
        while True:
            first, payload = self._recv_frame()
            frame_opcode = first & 0x0F
            final = bool(first & 0x80)
            if frame_opcode == 0x8:
                raise ConnectionError("event socket closed")
            if frame_opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if frame_opcode == 0xA:
                continue
            if frame_opcode in {0x1, 0x2}:
                if opcode is not None:
                    raise OpenHandsControlError("event_socket_fragment_invalid")
                opcode = frame_opcode
            elif frame_opcode != 0x0 or opcode is None:
                raise OpenHandsControlError("event_socket_opcode_invalid")
            fragments.extend(payload)
            if len(fragments) > _MAX_WS_FRAME_BYTES:
                raise OpenHandsControlError("event_socket_message_too_large")
            if not final:
                continue
            if opcode != 0x1:
                raise OpenHandsControlError("event_socket_non_text_message")
            try:
                value = json.loads(bytes(fragments).decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise OpenHandsControlError("event_socket_json_invalid") from exc
            if not isinstance(value, dict):
                raise OpenHandsControlError("event_socket_event_invalid")
            return value

    def _recv_frame(self) -> tuple[int, bytes]:
        head = self._read_exact(2)
        first, second = head
        if second & 0x80:
            raise OpenHandsControlError("event_socket_masked_server_frame")
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._read_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read_exact(8))[0]
        if length > _MAX_WS_FRAME_BYTES:
            raise OpenHandsControlError("event_socket_frame_too_large")
        return first, self._read_exact(length)

    def _read_exact(self, count: int) -> bytes:
        while len(self._recv_buffer) < count:
            part = self._socket.recv(count - len(self._recv_buffer))
            if not part:
                raise ConnectionError("event socket closed")
            self._recv_buffer.extend(part)
        result = bytes(self._recv_buffer[:count])
        del self._recv_buffer[:count]
        return result

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        mask = secrets.token_bytes(4)
        length = len(payload)
        header = bytearray([0x80 | opcode])
        if length < 126:
            header.append(0x80 | length)
        elif length <= 0xFFFF:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self._socket.sendall(bytes(header) + mask + masked)

    def close(self) -> None:
        sock = getattr(self, "_socket", None)
        self._socket = None  # type: ignore[assignment]
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def create_control_driver(binding: ProviderControlBinding) -> OpenHandsControlDriver | None:
    """Provider-module factory used by registry wiring."""
    return OpenHandsProviderAdapter().create_control_driver(binding)


def _validate_loopback_endpoint(endpoint: str) -> str:
    if not isinstance(endpoint, str):
        raise OpenHandsControlError("endpoint_invalid")
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise OpenHandsControlError("endpoint_not_loopback")
    return f"http://127.0.0.1:{parsed.port}"


def _validate_relative_target(target: str) -> None:
    if not isinstance(target, str) or not target.startswith("/") or len(target) > 4096:
        raise OpenHandsControlError("http_target_invalid")
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise OpenHandsControlError("http_target_invalid")


def _reviewed_http_route(method: str, target: str) -> bool:
    if (method, target) in {
        ("GET", "/ready"),
        ("GET", "/server_info"),
        ("GET", "/api/conversations/count"),
        ("GET", "/api/conversations/search?limit=100"),
        ("POST", "/api/conversations"),
    }:
        return True
    parsed = urlsplit(target)
    prefix = "/api/conversations/"
    if not parsed.path.startswith(prefix):
        return False
    remainder = parsed.path.removeprefix(prefix)
    encoded_id, separator, suffix = remainder.partition("/")
    decoded_id = unquote(encoded_id)
    try:
        canonical_id = str(UUID(decoded_id))
    except (TypeError, ValueError):
        return False
    if (
        canonical_id != decoded_id
        or quote(decoded_id, safe="") != encoded_id
    ):
        return False
    route = suffix if separator else ""
    if method == "GET" and route == "" and not parsed.query:
        return True
    if (
        method == "GET"
        and route == "events/search"
        and parsed.query == "limit=100&sort_order=TIMESTAMP_DESC"
    ):
        return True
    if parsed.query:
        return False
    return method == "POST" and route in {
        "events",
        "interrupt",
        "run",
        "fork",
        "condense",
        "navigate",
        "switch_acp_model",
        "events/respond_to_confirmation",
    }


def _reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _safe_server_environment(
    home: Path,
    *,
    session_api_key: str,
    secret_key: str,
) -> dict[str, str]:
    inherited_provider_settings = {
        key: os.environ[key]
        for key in ("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE")
        if key in os.environ
    }
    inherited_provider_settings["PYTHONUNBUFFERED"] = "1"
    return managed_child_environment(
        home=home,
        provider_settings=inherited_provider_settings,
        private_runtime_settings={
            "OH_SESSION_API_KEYS_0": session_api_key,
            "OH_SECRET_KEY": secret_key,
        },
    )


def _installed_agent_server_version(executable: Path) -> str | None:
    """Read the entry-point's own venv dist-info without executing provider code."""
    executable = executable.resolve()
    roots = [executable.parent.parent / "lib", executable.parent.parent / "Lib"]
    for root in roots:
        if not root.is_dir():
            continue
        for metadata in root.glob("python*/site-packages/openhands_agent_server-*.dist-info/METADATA"):
            try:
                for line in metadata.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("Version: "):
                        return line.removeprefix("Version: ").strip() or None
            except OSError:
                continue
        for metadata in root.glob("site-packages/openhands_agent_server-*.dist-info/METADATA"):
            try:
                for line in metadata.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("Version: "):
                        return line.removeprefix("Version: ").strip() or None
            except OSError:
                continue
    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False

def _canonical_uuid(value: Any) -> str:
    try:
        canonical = str(UUID(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise OpenHandsControlError("session_identity_invalid") from exc
    if canonical != value:
        raise OpenHandsControlError("session_identity_invalid")
    return canonical


def _canonical_uuid_or_none(value: Any) -> str | None:
    try:
        return _canonical_uuid(value)
    except OpenHandsControlError:
        return None


def _configured_openhands_profile_id() -> str | None:
    return _canonical_uuid_or_none(os.environ.get(OPENHANDS_PROFILE_ENV, "").strip())


def _qualified_openhands_session_id(native_session_id: str) -> str:
    return f"{OPENHANDS_PROVIDER_ID}:{_canonical_uuid(native_session_id)}"


def _native_openhands_session_id(public_session_id: str) -> str:
    prefix = f"{OPENHANDS_PROVIDER_ID}:"
    if (
        not isinstance(public_session_id, str)
        or not public_session_id.startswith(prefix)
    ):
        raise OpenHandsControlError("session_identity_invalid")
    return _canonical_uuid(public_session_id.removeprefix(prefix))


def _managed_openhands_event_payload(
    event: OpenHandsEvent,
    generation: int,
    observed_at: float,
) -> dict[str, Any]:
    public = dict(event.public_payload)
    payload: dict[str, Any]
    kind: str
    if event.kind == "ActionEvent" and isinstance(public.get("tool_name"), str):
        kind = "tool_call"
        payload = {
            "name": public["tool_name"],
            "call_id": public.get("tool_call_id") or event.event_id,
        }
        if public.get("summary") is not None:
            payload["input"] = {"summary": public["summary"]}
    elif event.kind in {"ObservationEvent", "UserRejectObservation"}:
        kind = "tool_result"
        payload = {
            "call_id": public.get("tool_call_id")
            or public.get("action_id")
            or event.event_id,
            "content": public.get("summary") or public.get("content") or "",
            "is_error": event.kind == "UserRejectObservation",
        }
    elif isinstance(public.get("content"), list):
        kind = "block_text"
        payload = {
            "text": "".join(
                str(item.get("text") or "")
                for item in public["content"]
                if isinstance(item, Mapping)
            ),
            "role": public.get("source") or "assistant",
        }
    else:
        kind = "lifecycle"
        payload = {
            "subtype": event.kind,
            "status": public.get("summary") or event.kind,
        }
    return {
        "event_id": event.event_id,
        "cursor": event.cursor,
        "observed_at": observed_at,
        "kind": kind,
        "payload": payload,
        "provider_id": OPENHANDS_PROVIDER_ID,
        "capability_generation": generation,
        "session_update": {
            "session_id": event.session_id,
            "native_id": _native_openhands_session_id(event.session_id),
        },
    }




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


def _redact_json(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if _is_sensitive_key(lowered):
                continue
            result[key_text] = _redact_json(item)
        return result
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _is_sensitive_key(key: str) -> bool:
    if key in {
        "token",
        "access_token",
        "refresh_token",
        "api_token",
        "api_key",
        "session_api_key",
        "secret",
        "secrets",
        "password",
        "credential",
        "credentials",
    }:
        return True
    return key.endswith(("_secret", "_password", "_credential", "_api_key"))



def _provider_permission_policy_safe(conversation: Mapping[str, Any]) -> bool:
    agent = conversation.get("agent")
    if not isinstance(agent, Mapping):
        return False
    if agent.get("kind") != "ACPAgent":
        return True
    mode = agent.get("acp_session_mode")
    if not isinstance(mode, str):
        return False
    normalized = "".join(character for character in mode.lower() if character.isalnum())
    if any(
        forbidden in normalized
        for forbidden in ("bypass", "yolo", "neverconfirm", "alwaysapprove", "allowall")
    ):
        return False
    return normalized in {"default", "ask", "manual", "plan"}

def _normalize_event(session_id: str, raw: Mapping[str, Any]) -> OpenHandsEvent:
    event_id = raw.get("id")
    kind = raw.get("kind")
    timestamp = raw.get("timestamp")
    if not all(isinstance(item, str) and item for item in (event_id, kind, timestamp)):
        raise OpenHandsControlError("event_shape_invalid")
    public: dict[str, Any] = {}
    for key in (
        "source",
        "summary",
        "tool_name",
        "tool_call_id",
        "action_id",
        "key",
        "value",
    ):
        if key in raw:
            public[key] = _redact_json(raw[key])
    content = raw.get("content")
    if isinstance(content, list):
        text_parts = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                text_parts.append({"text": item["text"]})
        if text_parts:
            public["content"] = text_parts
    return OpenHandsEvent(
        provider_id=OPENHANDS_PROVIDER_ID,
        session_id=session_id,
        event_id=event_id,
        kind=kind,
        timestamp=timestamp,
        cursor=f"{timestamp}:{event_id}",
        public_payload=public,
    )


