"""registry-data.json loader — the single source for provider identity.

SPEC-p1 §2.1: one data file drives the CLI's detection table, the daemon's
adapters, /provider-status, and (later) a docs providers section. Entries
carry the internal, automatic `adapter_depth` taxonomy (deep | standard |
recognized). Malformed entries are skipped, never fatal: a bad edit to the
data file degrades to a smaller honest table, not a dead daemon.

The default path is the file packaged next to this module. The
PAIRLING_PROVIDER_REGISTRY_DATA env var points the loader elsewhere — a
development/testing seam, not a user surface.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .base import (
    ManagedAuthVerification,
    ManagedLaunchContract,
    ProviderDescriptor,
    TerminalLaunchContract,
    TerminalLaunchProfile,
    is_valid_provider_id,
    normalize_provider_id,
)


DEFAULT_PATH = Path(__file__).resolve().parent / "registry-data.json"
VALID_DEPTHS = {"deep", "standard", "recognized"}


@dataclass(frozen=True)
class RegistryEntry:
    provider_id: str
    display_name: str
    kind: str
    adapter_depth: str
    binary_name: str
    builtin: bool = False
    binary_candidates: tuple[str, ...] = ()
    env_override: str | None = None
    config_paths: tuple[str, ...] = ()
    version_command: tuple[str, ...] = ("--version",)
    version_identity_pattern: str | None = None
    docs_url: str | None = None
    notes: tuple[str, ...] = ()
    managed_launch: ManagedLaunchContract | None = None
    terminal_launch: TerminalLaunchContract | None = None


def registry_data_path() -> Path:
    override = os.environ.get("PAIRLING_PROVIDER_REGISTRY_DATA", "").strip()
    if override:
        return Path(override).expanduser()
    return DEFAULT_PATH


# mtime-keyed so an edited data file is picked up on the next call without a
# daemon restart (Law 1: no stale catalog), while steady-state reads stay one
# stat() cheap.
_CACHE: dict[str, tuple[int, tuple[RegistryEntry, ...]]] = {}


def load_entries(path: Path | None = None) -> list[RegistryEntry]:
    target = Path(path) if path is not None else registry_data_path()
    try:
        mtime_ns = target.stat().st_mtime_ns
    except OSError:
        return []
    key = str(target)
    cached = _CACHE.get(key)
    if cached is not None and cached[0] == mtime_ns:
        return list(cached[1])
    entries = tuple(_parse_entries(target))
    _CACHE[key] = (mtime_ns, entries)
    if len(_CACHE) > 8:
        for old_key in [k for k in _CACHE if k != key][:4]:
            _CACHE.pop(old_key, None)
    return list(entries)


def _parse_entries(target: Path):
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    raw = payload.get("providers") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return
    seen: set[str] = set()
    for item in raw:
        entry = _entry_from(item)
        if entry is None or entry.provider_id in seen:
            continue
        seen.add(entry.provider_id)
        yield entry


def _string_tuple(item: dict, key: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    value = item.get(key)
    if not isinstance(value, list):
        return tuple(default)
    return tuple(str(v).strip() for v in value if isinstance(v, str) and str(v).strip())


def _optional_string(item: dict, key: str) -> str | None:
    value = item.get(key)
    if not isinstance(value, str):
        return None
    return value.strip() or None



def _managed_launch_contract(item: dict) -> ManagedLaunchContract | None:
    raw = item.get("managed_launch")
    if raw is None:
        return None
    if not isinstance(raw, dict) or not set(raw).issubset(
        {
            "control_channel",
            "ready_auth_states",
            "ready_config_states",
            "auth_verification",
            "require_post_launch_verification",
        }
    ):
        raise ValueError("managed_launch must be a reviewed contract object")
    channel = raw.get("control_channel")
    auth_states = raw.get("ready_auth_states")
    config_states = raw.get("ready_config_states")
    verification = raw.get("auth_verification", "probe")
    if (
        not isinstance(channel, str)
        or not isinstance(auth_states, list)
        or not isinstance(config_states, list)
        or not all(isinstance(value, str) for value in auth_states + config_states)
        or not isinstance(verification, str)
    ):
        raise ValueError("managed_launch contract fields are invalid")
    return ManagedLaunchContract(
        control_channel=channel,
        ready_auth_states=tuple(auth_states),
        ready_config_states=tuple(config_states),
        auth_verification=ManagedAuthVerification(verification),
        require_post_launch_verification=bool(
            raw.get("require_post_launch_verification", False)
        ),
    )


def _terminal_launch_contract(item: dict) -> TerminalLaunchContract | None:
    raw = item.get("terminal_launch")
    if raw is None:
        return None
    if (
        not isinstance(raw, dict)
        or set(raw) != {"profile", "backends"}
        or not isinstance(raw.get("profile"), str)
        or not isinstance(raw.get("backends"), list)
        or not all(isinstance(value, str) for value in raw["backends"])
    ):
        raise ValueError("terminal_launch must be an exact reviewed contract object")
    return TerminalLaunchContract(
        profile=TerminalLaunchProfile(raw["profile"]),
        backends=tuple(raw["backends"]),
    )

def _entry_from(item) -> RegistryEntry | None:
    if not isinstance(item, dict):
        return None
    provider_id = normalize_provider_id(str(item.get("id") or ""))
    display_name = str(item.get("display_name") or "").strip()
    binary_name = str(item.get("binary_name") or "").strip()
    adapter_depth = str(item.get("adapter_depth") or "").strip().lower()
    if not is_valid_provider_id(provider_id) or not display_name or not binary_name:
        return None
    if adapter_depth not in VALID_DEPTHS:
        return None
    version_command = _string_tuple(item, "version_command", ("--version",)) or ("--version",)
    try:
        managed_launch = _managed_launch_contract(item)
        terminal_launch = _terminal_launch_contract(item)
    except ValueError:
        return None
    return RegistryEntry(
        provider_id=provider_id,
        display_name=display_name,
        kind=str(item.get("kind") or "terminal_cli").strip() or "terminal_cli",
        adapter_depth=adapter_depth,
        binary_name=binary_name,
        builtin=bool(item.get("builtin", False)),
        binary_candidates=_string_tuple(item, "binary_candidates"),
        env_override=_optional_string(item, "env_override"),
        config_paths=_string_tuple(item, "config_paths"),
        version_command=version_command,
        version_identity_pattern=_optional_string(item, "version_identity_pattern"),
        docs_url=_optional_string(item, "docs_url"),
        notes=_string_tuple(item, "notes"),
        managed_launch=managed_launch,
        terminal_launch=terminal_launch,
    )


def entry_for(provider_id: str, path: Path | None = None) -> RegistryEntry:
    wanted = normalize_provider_id(provider_id)
    for entry in load_entries(path=path):
        if entry.provider_id == wanted:
            return entry
    raise KeyError(f"provider not in registry data: {provider_id}")


def entry_or_none(provider_id: str, path: Path | None = None) -> RegistryEntry | None:
    try:
        return entry_for(provider_id, path=path)
    except KeyError:
        return None


def descriptor_for(entry: RegistryEntry) -> ProviderDescriptor:
    return ProviderDescriptor(
        provider_id=entry.provider_id,
        display_name=entry.display_name,
        kind=entry.kind,
        builtin=entry.builtin,
        docs_url=entry.docs_url,
        adapter_depth=entry.adapter_depth,
        managed_launch=entry.managed_launch,
        terminal_launch=entry.terminal_launch,
    )


def _expand(raw: str, home: Path) -> Path:
    if raw == "~":
        return home
    if raw.startswith("~/"):
        return home / raw[2:]
    return Path(raw)


def candidate_paths(entry: RegistryEntry, home: Path | None = None) -> list[Path]:
    base = home or Path.home()
    return [_expand(raw, base) for raw in entry.binary_candidates]


def config_file_paths(entry: RegistryEntry, home: Path | None = None) -> list[Path]:
    base = home or Path.home()
    return [_expand(raw, base) for raw in entry.config_paths]


def adapter_depths(path: Path | None = None) -> dict[str, str]:
    return {entry.provider_id: entry.adapter_depth for entry in load_entries(path=path)}
