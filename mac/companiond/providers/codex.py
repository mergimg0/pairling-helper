from __future__ import annotations

import time
from pathlib import Path

from .base import (
    ProviderAdapter,
    ProviderAvailability,
    ProviderDescriptor,
    ProviderDiagnostics,
    ProviderProbeResult,
    cli_version,
    command_line_count,
    count_dirs,
    json_hook_count,
    resolve_executable,
)


class CodexProviderAdapter(ProviderAdapter):
    descriptor = ProviderDescriptor(
        provider_id="codex",
        display_name="Codex",
        kind="terminal_cli",
        builtin=True,
        docs_url="https://developers.openai.com/codex",
    )

    def __init__(self, home: Path | None = None):
        self.home = home or Path.home()

    @property
    def candidates(self) -> list[Path]:
        return [
            self.home / ".local" / "bin" / "codex",
            Path("/opt/homebrew/bin/codex"),
            Path("/usr/local/bin/codex"),
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
            "commands",
            "search",
            "terminal_output",
            "mcp",
            "export",
            "orchestration_launch",
            "worker_telemetry",
        }

    def probe(self) -> ProviderProbeResult:
        resolved = resolve_executable("codex", self.candidates, env_var="PAIRLING_CODEX_BIN")
        config_path = self.home / ".codex" / "config.toml"
        hooks_path = self.home / ".codex" / "hooks.json"
        hook_count = json_hook_count(hooks_path)
        installed = resolved is not None
        notes: list[str] = []
        setup_actions: list[str] = []
        if not installed:
            notes.append("Codex CLI not found in configured, known, or daemon PATH locations")
            setup_actions.append("install_cli")
        if not config_path.is_file():
            notes.append("Codex config.toml not found")
            setup_actions.append("configure_provider")
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
            "commands",
            "search",
            "terminal_output",
            "mcp",
            "export",
            "orchestration_launch",
            "worker_telemetry",
        ) if installed else ("detect", "status")
        availability = ProviderAvailability(
            provider_id=self.descriptor.provider_id,
            display_name=self.descriptor.display_name,
            kind=self.descriptor.kind,
            installed=installed,
            usable=installed,
            launchable=installed,
            auth_state="ready" if installed else "missing_cli",
            config_state="ready" if config_path.is_file() else "missing",
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
            version=cli_version(resolved.path) if resolved else None,
            config_path=str(config_path),
            config_exists=config_path.is_file(),
            hook_count=hook_count,
            hooks_configured=hook_count > 0,
            mcp_count=command_line_count(resolved.path, ["mcp", "list"], timeout=0.75) if resolved else None,
            plugin_count=count_dirs(self.home / ".codex" / "plugins"),
        )
        return ProviderProbeResult(
            descriptor=self.descriptor,
            availability=availability,
            diagnostics=diagnostics,
            observed_at=time.time(),
        )
