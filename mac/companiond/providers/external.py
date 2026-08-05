from __future__ import annotations

import re
import time
from pathlib import Path

from . import registry_data
from .base import (
    ProviderAdapter,
    ProviderAvailability,
    ProviderDiagnostics,
    ProviderProbeResult,
    cli_version,
    resolve_executable,
)


class RecognizedProviderAdapter(ProviderAdapter):
    """Recognized tier: detection only — name, version, path (SPEC-p1 §2.2).

    Detection is honest and free, so it is always on: no experimental env
    flag. The adapter never enumerates sessions and never claims control;
    setup prints these entries as "recognized, not yet controllable".
    """

    def __init__(self, entry: registry_data.RegistryEntry, home: Path | None = None):
        self.entry = entry
        self.home = home or Path.home()
        self.descriptor = registry_data.descriptor_for(entry)

    def supports(self, capability: str) -> bool:
        return capability == "detect"
    def create_control_driver(self, binding):
        # Detection-only adapters never become actionable from registry data.
        return None


    def probe(self) -> ProviderProbeResult:
        resolved = resolve_executable(
            self.entry.binary_name,
            registry_data.candidate_paths(self.entry, home=self.home),
            env_var=self.entry.env_override,
        )
        version = cli_version(resolved.path, list(self.entry.version_command)) if resolved else None
        identity_pattern = self.entry.version_identity_pattern
        identity_matches = (
            resolved is not None
            and (
                identity_pattern is None
                or (version is not None and re.search(identity_pattern, version) is not None)
            )
        )
        installed = identity_matches
        config_candidates = registry_data.config_file_paths(self.entry, home=self.home)
        primary_config = config_candidates[0] if config_candidates else None
        if installed:
            notes = ("Recognized, not yet controllable.",)
        elif resolved is not None:
            notes = (
                f"Executable at {resolved.path} did not identify as {self.entry.display_name}.",
            )
        else:
            notes = (
                f"{self.entry.display_name} CLI not found in configured, known, or daemon PATH locations",
            )
        availability = ProviderAvailability(
            provider_id=self.descriptor.provider_id,
            display_name=self.descriptor.display_name,
            kind=self.descriptor.kind,
            installed=installed,
            usable=False,
            launchable=False,
            auth_state="unsupported",
            config_state="unsupported",
            readable_sessions=0,
            live_sessions=0,
            controllable_sessions=0,
            capabilities=("detect",),
            setup_actions=("provider_sprint_required",),
            notes=notes,
        )
        diagnostics = ProviderDiagnostics(
            cli_path=str(resolved.path) if resolved else None,
            cli_path_source=resolved.source if resolved else None,
            version=version,
            config_path=str(primary_config) if primary_config else None,
            config_exists=primary_config.is_file() if primary_config else None,
        )
        return ProviderProbeResult(
            descriptor=self.descriptor,
            availability=availability,
            diagnostics=diagnostics,
            observed_at=time.time(),
        )
