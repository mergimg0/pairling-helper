from __future__ import annotations

import time
from pathlib import Path

from . import registry_data
from .base import (
    ProviderAvailability,
    ProviderDescriptor,
    ProviderDiagnostics,
    ProviderProbeResult,
    ResolvedExecutable,
    resolve_executable,
)
from .controls import ProviderControlBinding, ProviderControlDriver
from .droid_jsonrpc import (
    DROID_SUPPORTED_VERSION,
    FactoryDroidError,
    FactoryDroidJsonRpcDriver,
    probe_factory_droid_launch,
)

_FALLBACK_DESCRIPTOR = ProviderDescriptor(
    provider_id="droid",
    display_name="Factory Droid",
    kind="terminal_cli",
    builtin=True,
    docs_url="https://docs.factory.ai/droid-cli/cli-reference",
    adapter_depth="deep",
)
_ENTRY = registry_data.entry_or_none("droid")


class FactoryDroidProviderAdapter:
    descriptor = (
        registry_data.descriptor_for(_ENTRY)
        if _ENTRY is not None
        else _FALLBACK_DESCRIPTOR
    )

    def __init__(self, home: Path | None = None):
        self.home = home or Path.home()

    @property
    def candidates(self) -> list[Path]:
        if _ENTRY is not None and _ENTRY.binary_candidates:
            return registry_data.candidate_paths(_ENTRY, home=self.home)
        return [
            self.home / ".local" / "bin" / "droid",
            Path("/opt/homebrew/bin/droid"),
            Path("/usr/local/bin/droid"),
        ]

    def _resolved(self) -> ResolvedExecutable | None:
        env_var = _ENTRY.env_override if _ENTRY is not None else "PAIRLING_DROID_BIN"
        return resolve_executable("droid", self.candidates, env_var=env_var)

    def supports(self, capability: str) -> bool:
        return capability in {
            "detect",
            "status",
            "spawn",
            "live_state",
            "send_text",
            "interrupt",
            "terminate",
            "commands",
            "mcp",
            "resume",
            "structured_control",
            "permissions",
            "fork",
            "compact",
            "context",
            "mission_status",
            "worktree_status",
        }

    def probe(self) -> ProviderProbeResult:
        resolved = self._resolved()
        installed = resolved is not None
        auth = False
        compatible = False
        version: str | None = None
        failure: str | None = None
        if resolved is not None:
            try:
                evidence = probe_factory_droid_launch(
                    resolved.path,
                    require_auth=False,
                )
                compatible = True
                version = evidence.version
                auth = evidence.auth_source is not None
            except FactoryDroidError as exc:
                failure = str(exc)
        capabilities = tuple(
            capability
            for capability in (
                "detect",
                "status",
                "spawn",
                "live_state",
                "send_text",
                "interrupt",
                "terminate",
                "commands",
                "mcp",
                "resume",
                "structured_control",
                "permissions",
                "fork",
                "compact",
                "context",
                "mission_status",
                "worktree_status",
            )
            if self.supports(capability)
        )
        notes: list[str] = [
            "Public Factory stream-jsonrpc; default structured sessions are spec/off.",
            f"Structured controls require the exact supported Droid CLI {DROID_SUPPORTED_VERSION}.",
        ]
        if failure:
            notes.append(f"Structured control unavailable: {failure}.")
        if installed and not auth:
            notes.append("Sign in with Droid so its protected local credential store is available.")
        availability = ProviderAvailability(
            provider_id="droid",
            display_name="Factory Droid",
            kind="terminal_cli",
            installed=installed,
            usable=installed and compatible and auth,
            launchable=installed,
            auth_state="configured" if auth else ("missing_cli" if not installed else "missing"),
            config_state="compatible" if compatible else "unsupported",
            readable_sessions=0,
            live_sessions=0,
            controllable_sessions=0,
            capabilities=capabilities,
            setup_actions=("authenticate_provider_locally",) if installed and not auth else (),
            notes=tuple(notes),
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
        self,
        binding: ProviderControlBinding,
    ) -> ProviderControlDriver | None:
        if (
            binding.provider_id != "droid"
            or binding.provider_version != DROID_SUPPORTED_VERSION
            or binding.provider_channel != "stable"
        ):
            return None
        resolved = self._resolved()
        if resolved is None:
            return None
        try:
            evidence = probe_factory_droid_launch(resolved.path)
            return FactoryDroidJsonRpcDriver(binding, evidence)
        except FactoryDroidError:
            return None
