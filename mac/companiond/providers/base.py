from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Iterable, Protocol


ProviderCapability = str


@dataclass(frozen=True)
class ProviderDescriptor:
    provider_id: str
    display_name: str
    kind: str
    builtin: bool = True
    docs_url: str | None = None


@dataclass(frozen=True)
class ProviderAvailability:
    provider_id: str
    display_name: str
    kind: str
    installed: bool
    usable: bool
    launchable: bool
    auth_state: str
    config_state: str
    readable_sessions: int
    live_sessions: int
    controllable_sessions: int
    capabilities: tuple[ProviderCapability, ...]
    setup_actions: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProviderDiagnostics:
    cli_path: str | None = None
    cli_path_source: str | None = None
    version: str | None = None
    config_path: str | None = None
    config_exists: bool | None = None
    hook_count: int | None = None
    hooks_configured: bool | None = None
    mcp_count: int | None = None
    plugin_count: int | None = None
    registry_count: int | None = None
    registry_live_count: int | None = None


@dataclass(frozen=True)
class ProviderProbeResult:
    descriptor: ProviderDescriptor
    availability: ProviderAvailability
    diagnostics: ProviderDiagnostics
    observed_at: float

    def with_availability(self, **changes) -> "ProviderProbeResult":
        return replace(self, availability=replace(self.availability, **changes))

    def with_diagnostics(self, **changes) -> "ProviderProbeResult":
        return replace(self, diagnostics=replace(self.diagnostics, **changes))


class ProviderAdapter(Protocol):
    descriptor: ProviderDescriptor

    def probe(self) -> ProviderProbeResult:
        ...

    def supports(self, capability: ProviderCapability) -> bool:
        ...


@dataclass(frozen=True)
class ResolvedExecutable:
    path: Path
    source: str


def normalize_provider_id(raw: str) -> str:
    return (raw or "").strip().lower()


def is_valid_provider_id(raw: str) -> bool:
    provider_id = normalize_provider_id(raw)
    return bool(provider_id) and len(provider_id) <= 48 and re.fullmatch(r"[a-z0-9_]+", provider_id) is not None


def executable_candidates(name: str, known: Iterable[Path | str], env_var: str | None = None) -> list[tuple[Path, str]]:
    candidates: list[tuple[Path, str]] = []
    if env_var:
        configured = os.environ.get(env_var)
        if configured:
            candidates.append((Path(configured).expanduser(), f"env:{env_var}"))
    for candidate in known:
        candidates.append((Path(candidate).expanduser(), "known"))
    for prefix in os.environ.get("PATH", "").split(":"):
        if prefix:
            candidates.append((Path(prefix).expanduser() / name, "path"))
    return candidates


def resolve_executable(name: str, known: Iterable[Path | str], env_var: str | None = None) -> ResolvedExecutable | None:
    seen: set[str] = set()
    for candidate, source in executable_candidates(name, known, env_var=env_var):
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if candidate.exists() and os.access(candidate, os.X_OK):
            return ResolvedExecutable(candidate, source)
    return None


def cli_version(bin_path: Path | str | None, args: list[str] | None = None, timeout: int = 3) -> str | None:
    if not bin_path:
        return None
    try:
        proc = subprocess.run([str(bin_path), *(args or ["--version"])], capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    return (proc.stdout or proc.stderr or "").strip()[:160] or None


def count_dirs(root: Path, excluded: set[str] | None = None) -> int:
    excluded = excluded or set()
    if not root.is_dir():
        return 0
    try:
        return sum(1 for p in root.iterdir() if p.is_dir() and not p.name.startswith(".") and p.name not in excluded)
    except OSError:
        return 0


def command_line_count(bin_path: Path | str | None, args: list[str], timeout: int = 5) -> int | None:
    if not bin_path:
        return None
    try:
        proc = subprocess.run([str(bin_path), *args], capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None
    text = (proc.stdout or proc.stderr or "").strip()
    if not text:
        return 0 if proc.returncode == 0 else None
    lines: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        low = s.lower()
        if not s:
            continue
        if low.startswith("no ") or "no mcp" in low:
            continue
        if low.startswith("name ") or set(s) <= {"-", " "}:
            continue
        lines.append(s)
    return len(lines)


def hook_command_count(obj) -> int:
    if isinstance(obj, dict):
        own = 1 if isinstance(obj.get("command"), str) and obj.get("command") else 0
        return own + sum(hook_command_count(v) for k, v in obj.items() if k != "command")
    if isinstance(obj, list):
        return sum(hook_command_count(v) for v in obj)
    return 0


def json_hook_count(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        obj = json.loads(path.read_text(errors="replace"))
    except Exception:
        return 0
    return hook_command_count(obj.get("hooks") if isinstance(obj, dict) and "hooks" in obj else obj)


def availability_dict(availability: ProviderAvailability) -> dict:
    data = asdict(availability)
    data["capabilities"] = list(availability.capabilities)
    data["setup_actions"] = list(availability.setup_actions)
    data["notes"] = list(availability.notes)
    return data


def diagnostics_dict(diagnostics: ProviderDiagnostics) -> dict:
    return asdict(diagnostics)


def provider_detail_payload(result: ProviderProbeResult) -> dict:
    payload = availability_dict(result.availability)
    payload.update(diagnostics_dict(result.diagnostics))
    payload["provider"] = result.availability.provider_id
    payload["ok"] = result.availability.usable
    payload["session_count"] = result.availability.readable_sessions
    payload["controllable_count"] = result.availability.controllable_sessions
    return payload


def provider_snapshot_payload(results: list[ProviderProbeResult], source: str = "live_probe", observed_at: float | None = None) -> dict:
    usable = [r.availability for r in results if r.availability.usable]
    default_provider_id: str | None = None
    default_filter = "all"
    if len(usable) == 1:
        default_provider_id = usable[0].provider_id
        default_filter = usable[0].provider_id
    elif len(usable) > 1:
        launchable = [p for p in usable if p.launchable]
        default_provider_id = launchable[0].provider_id if launchable else usable[0].provider_id

    ts = observed_at if observed_at is not None else time.time()
    return {
        "schema_version": 1,
        "providers": [availability_dict(r.availability) for r in results],
        "default_provider_id": default_provider_id,
        "default_filter": default_filter,
        "observed_at": ts,
        "source": source,
    }


def failed_probe(descriptor: ProviderDescriptor, exc: Exception) -> ProviderProbeResult:
    note = f"{type(exc).__name__}: {str(exc)[:160]}"
    availability = ProviderAvailability(
        provider_id=descriptor.provider_id,
        display_name=descriptor.display_name,
        kind=descriptor.kind,
        installed=False,
        usable=False,
        launchable=False,
        auth_state="unknown",
        config_state="unknown",
        readable_sessions=0,
        live_sessions=0,
        controllable_sessions=0,
        capabilities=("detect",),
        setup_actions=("repair_provider_probe",),
        notes=(note,),
    )
    return ProviderProbeResult(
        descriptor=descriptor,
        availability=availability,
        diagnostics=ProviderDiagnostics(),
        observed_at=time.time(),
    )
