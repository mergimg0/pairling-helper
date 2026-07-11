from __future__ import annotations

from pathlib import Path

from . import registry_data
from .base import ProviderAdapter, ProviderDescriptor, failed_probe, normalize_provider_id
from .claude import ClaudeProviderAdapter
from .codex import CodexProviderAdapter
from .external import RecognizedProviderAdapter


# Deep adapters keep bespoke Python (hooks, session feeds, probes); every
# other registry-data entry is served by the detection-only recognized
# adapter. There is no enable flag: detection is honest and free (SPEC-p1).
_DEEP_ADAPTER_IDS = {"claude", "codex"}


def provider_adapters(home: Path | None = None) -> list[ProviderAdapter]:
    adapters: list[ProviderAdapter] = [
        ClaudeProviderAdapter(home=home),
        CodexProviderAdapter(home=home),
    ]
    for entry in registry_data.load_entries():
        if entry.provider_id in _DEEP_ADAPTER_IDS:
            continue
        adapters.append(RecognizedProviderAdapter(entry, home=home))
    return adapters


def provider_ids() -> set[str]:
    return {adapter.descriptor.provider_id for adapter in provider_adapters()}


def provider_descriptors() -> list[ProviderDescriptor]:
    return [adapter.descriptor for adapter in provider_adapters()]


def known_provider_ids() -> set[str]:
    return _DEEP_ADAPTER_IDS | {entry.provider_id for entry in registry_data.load_entries()}


def session_capable_provider_ids() -> set[str]:
    """Providers whose sessions Pairling can enumerate and drive: registry
    entries at depth deep or standard (SPEC-p2 §2.1). Recognized entries are
    detect-only and never a session source. Falls back to the deep pair when
    the data file is missing or empty so a corrupt file cannot lobotomize
    the daemon."""
    ids = {
        entry.provider_id
        for entry in registry_data.load_entries()
        if entry.adapter_depth in {"deep", "standard"}
    }
    return ids or set(_DEEP_ADAPTER_IDS)


def get_provider(provider_id: str, home: Path | None = None) -> ProviderAdapter | None:
    wanted = normalize_provider_id(provider_id)
    for adapter in provider_adapters(home=home):
        if adapter.descriptor.provider_id == wanted:
            return adapter
    return None


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
