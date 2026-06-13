from __future__ import annotations

import time

from .base import ProviderAdapter, ProviderAvailability, ProviderDescriptor, ProviderDiagnostics, ProviderProbeResult


EXTERNAL_DESCRIPTORS = [
    ProviderDescriptor("aider", "Aider", "terminal_cli", builtin=False, docs_url="https://aider.chat/docs/"),
    ProviderDescriptor("opencode", "OpenCode", "terminal_cli", builtin=False, docs_url="https://opencode.ai/docs"),
    ProviderDescriptor("hermes_agent", "Hermes Agent", "terminal_cli", builtin=False, docs_url="https://hermes-agent.nousresearch.com/docs/user-guide/cli"),
    ProviderDescriptor("grok_build", "Grok Build", "terminal_cli", builtin=False, docs_url="https://x.ai/cli"),
    ProviderDescriptor("antigravity", "Antigravity", "agent_platform", builtin=False, docs_url="https://developers.googleblog.com/en/build-with-google-antigravity-our-new-agentic-development-platform/"),
]


class DisabledExternalProviderAdapter(ProviderAdapter):
    def __init__(self, descriptor: ProviderDescriptor):
        self.descriptor = descriptor

    def supports(self, capability: str) -> bool:
        return capability == "detect"

    def probe(self) -> ProviderProbeResult:
        availability = ProviderAvailability(
            provider_id=self.descriptor.provider_id,
            display_name=self.descriptor.display_name,
            kind=self.descriptor.kind,
            installed=False,
            usable=False,
            launchable=False,
            auth_state="unsupported",
            config_state="unsupported",
            readable_sessions=0,
            live_sessions=0,
            controllable_sessions=0,
            capabilities=("detect",),
            setup_actions=("provider_sprint_required",),
            notes=("Provider descriptor is present for future integration; adapter is disabled.",),
        )
        return ProviderProbeResult(
            descriptor=self.descriptor,
            availability=availability,
            diagnostics=ProviderDiagnostics(),
            observed_at=time.time(),
        )
