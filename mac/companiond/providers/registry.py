from __future__ import annotations

from pathlib import Path

from . import registry_data
from .base import ProviderAdapter, ProviderDescriptor, failed_probe, normalize_provider_id
from .controls import (
    ProviderControlBinding,
    ProviderControlDriver,
    control_driver_for_adapter,
)
from .acp import AcpProviderAdapter
from .acp_profiles import ACTIVE_ACP_PROVIDER_IDS
from .claude import ClaudeProviderAdapter
from .codex import CodexProviderAdapter
from .copilot import CopilotProviderAdapter
from .droid import FactoryDroidProviderAdapter
from .external import RecognizedProviderAdapter
from .hermes import HermesProviderAdapter
from .opencode import OpenCodeProviderAdapter
from .openhands import OpenHandsProviderAdapter
from .qwen import QwenCodeProviderAdapter
from .operations import provider_has_release_membership


# Provider-specific adapters take precedence when a provider also exposes ACP.
# Registry depth alone never promotes a detection adapter into a session or
# control source.
_DIRECT_ADAPTER_IDS = {
    "claude",
    "codex",
    "copilot",
    "droid",
    "hermes_agent",
    "opencode",
    "openhands",
    "qwen_code",
}
_SPECIALIZED_ADAPTER_IDS = _DIRECT_ADAPTER_IDS | set(ACTIVE_ACP_PROVIDER_IDS)


def provider_adapters(home: Path | None = None) -> list[ProviderAdapter]:
    adapters: list[ProviderAdapter] = [
        ClaudeProviderAdapter(home=home),
        CodexProviderAdapter(home=home),
        CopilotProviderAdapter(home=home),
        FactoryDroidProviderAdapter(home=home),
        HermesProviderAdapter(home=home),
        OpenCodeProviderAdapter(home=home),
        OpenHandsProviderAdapter(home=home),
        QwenCodeProviderAdapter(home=home),
    ]
    for entry in registry_data.load_entries():
        if entry.provider_id in _DIRECT_ADAPTER_IDS:
            continue
        if entry.provider_id in ACTIVE_ACP_PROVIDER_IDS:
            adapters.append(AcpProviderAdapter(entry, home=home))
            continue
        adapters.append(RecognizedProviderAdapter(entry, home=home))
    return adapters


def provider_ids() -> set[str]:
    return {adapter.descriptor.provider_id for adapter in provider_adapters()}


def provider_descriptors() -> list[ProviderDescriptor]:
    return [adapter.descriptor for adapter in provider_adapters()]


def known_provider_ids() -> set[str]:
    return _SPECIALIZED_ADAPTER_IDS | {entry.provider_id for entry in registry_data.load_entries()}


def session_capable_provider_ids() -> set[str]:
    """Return only providers backed by a provider-specific adapter.

    A registry row and its adapter-depth label are descriptive metadata, not a
    grant of session access or control.
    """
    ids = {
        adapter.descriptor.provider_id
        for adapter in provider_adapters()
        if not isinstance(adapter, RecognizedProviderAdapter)
        and adapter.descriptor.adapter_depth in {"deep", "standard"}
        and provider_has_release_membership(adapter.descriptor.provider_id)
    }
    return ids


def get_provider(provider_id: str, home: Path | None = None) -> ProviderAdapter | None:
    wanted = normalize_provider_id(provider_id)
    for adapter in provider_adapters(home=home):
        if adapter.descriptor.provider_id == wanted:
            return adapter
    return None

def get_control_driver(
    binding: ProviderControlBinding,
    home: Path | None = None,
) -> ProviderControlDriver | None:
    adapter = get_provider(binding.provider_id, home=home)
    if adapter is None:
        return None
    return control_driver_for_adapter(adapter, binding)



def iter_providers(provider_filter: str = "all", home: Path | None = None) -> list[ProviderAdapter]:
    provider_filter = normalize_provider_id(provider_filter or "all")
    adapters = provider_adapters(home=home)
    if provider_filter == "all":
        return adapters
    return [adapter for adapter in adapters if adapter.descriptor.provider_id == provider_filter]


def probe_all(provider_filter: str = "all", home: Path | None = None):
    results = []
    for adapter in iter_providers(provider_filter=provider_filter, home=home):
        try:
            results.append(adapter.probe())
        except Exception as exc:
            results.append(failed_probe(adapter.descriptor, exc))
    return results
