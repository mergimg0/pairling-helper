from __future__ import annotations

import os
from pathlib import Path

from .base import ProviderAdapter, ProviderDescriptor, failed_probe, is_valid_provider_id, normalize_provider_id
from .claude import ClaudeProviderAdapter
from .codex import CodexProviderAdapter
from .external import DisabledExternalProviderAdapter, EXTERNAL_DESCRIPTORS


def _external_enabled_ids() -> set[str]:
    raw = os.environ.get("PAIRLING_EXPERIMENTAL_PROVIDERS", "")
    if raw.strip().lower() in {"1", "true", "yes", "all", "*"}:
        return {d.provider_id for d in EXTERNAL_DESCRIPTORS}
    return {
        normalize_provider_id(item)
        for item in raw.split(",")
        if is_valid_provider_id(item)
    }


def provider_adapters(home: Path | None = None, include_external: bool | None = None) -> list[ProviderAdapter]:
    adapters: list[ProviderAdapter] = [
        ClaudeProviderAdapter(home=home),
        CodexProviderAdapter(home=home),
    ]
    enabled = _external_enabled_ids() if include_external is None else ({d.provider_id for d in EXTERNAL_DESCRIPTORS} if include_external else set())
    for descriptor in EXTERNAL_DESCRIPTORS:
        if descriptor.provider_id in enabled:
            adapters.append(DisabledExternalProviderAdapter(descriptor))
    return adapters


def provider_ids(include_external: bool | None = None) -> set[str]:
    return {adapter.descriptor.provider_id for adapter in provider_adapters(include_external=include_external)}


def provider_descriptors(include_external: bool | None = None) -> list[ProviderDescriptor]:
    return [adapter.descriptor for adapter in provider_adapters(include_external=include_external)]


def known_provider_ids() -> set[str]:
    return {"claude", "codex", *(d.provider_id for d in EXTERNAL_DESCRIPTORS)}


def get_provider(provider_id: str, home: Path | None = None, include_external: bool | None = None) -> ProviderAdapter | None:
    wanted = normalize_provider_id(provider_id)
    for adapter in provider_adapters(home=home, include_external=include_external):
        if adapter.descriptor.provider_id == wanted:
            return adapter
    return None


def iter_providers(provider_filter: str = "all", home: Path | None = None, include_external: bool | None = None) -> list[ProviderAdapter]:
    provider_filter = normalize_provider_id(provider_filter or "all")
    adapters = provider_adapters(home=home, include_external=include_external)
    if provider_filter == "all":
        return adapters
    return [adapter for adapter in adapters if adapter.descriptor.provider_id == provider_filter]


def probe_all(provider_filter: str = "all", home: Path | None = None, include_external: bool | None = None):
    results = []
    for adapter in iter_providers(provider_filter=provider_filter, home=home, include_external=include_external):
        try:
            results.append(adapter.probe())
        except Exception as exc:
            results.append(failed_probe(adapter.descriptor, exc))
    return results
