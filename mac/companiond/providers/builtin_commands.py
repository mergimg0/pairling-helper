"""Version-verified builtin command catalogs (SPEC-p2 §2.1).

Neither claude nor codex enumerates its slash builtins from --help (spiked
2026-07-04: both print CLI flags/subcommands only), so the builtin catalog is
a data file recording which CLI version each list was verified against, plus
a live --version probe. When the installed version drifts from the verified
one, the catalog is served labeled `stale_for_version` so the phone renders
"catalog from vX, installed vY" instead of silently lying (Law 1).

The probe is memoized by (binary path, mtime_ns): the 5s catalog signature
loop stays a stat walk and never execs an unchanged binary; a binary upgrade
(new mtime) re-probes on the next call, which covers daemon boot and
binary-change detection (acceptance 2).
"""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path

from . import registry_data
from .base import cli_version, resolve_executable


DATA_PATH = Path(__file__).resolve().parent / "builtin-commands.json"

_VERSION_TOKEN_RE = re.compile(r"\d+(?:\.\d+)+")

_LOCK = threading.Lock()
_DATA_CACHE: tuple[int, dict] | None = None
_PROBE_CACHE: dict[tuple[str, int], str | None] = {}


def _load_data() -> dict:
    global _DATA_CACHE
    try:
        mtime_ns = DATA_PATH.stat().st_mtime_ns
    except OSError:
        return {}
    with _LOCK:
        if _DATA_CACHE is not None and _DATA_CACHE[0] == mtime_ns:
            return _DATA_CACHE[1]
    try:
        payload = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    providers = payload.get("providers") if isinstance(payload, dict) else None
    data = providers if isinstance(providers, dict) else {}
    with _LOCK:
        _DATA_CACHE = (mtime_ns, data)
    return data


def entries(provider: str) -> list[dict]:
    block = _load_data().get((provider or "").strip().lower())
    if not isinstance(block, dict):
        return []
    raw = block.get("commands")
    if not isinstance(raw, list):
        return []
    out: list[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name.startswith("/"):
            continue
        out.append({
            "name": name,
            "description": str(item.get("description") or ""),
            "args": item.get("args"),
        })
    return out


def verified_version(provider: str) -> str | None:
    block = _load_data().get((provider or "").strip().lower())
    if not isinstance(block, dict):
        return None
    value = str(block.get("verified_version") or "").strip()
    return value or None


def version_token(raw: str | None) -> str | None:
    if not raw:
        return None
    match = _VERSION_TOKEN_RE.search(raw)
    return match.group(0) if match else None


def _probe_version(path: Path, version_command: list[str]) -> str | None:
    return cli_version(path, version_command)


def reset_probe_cache_for_tests() -> None:
    with _LOCK:
        _PROBE_CACHE.clear()


def _installed_version(provider: str, home: Path | None = None) -> tuple[str | None, bool]:
    """Returns (raw version string or None, binary_present)."""
    entry = registry_data.entry_or_none(provider)
    if entry is None:
        return None, False
    resolved = resolve_executable(
        entry.binary_name,
        registry_data.candidate_paths(entry, home=home),
        env_var=entry.env_override,
    )
    if resolved is None:
        return None, False
    try:
        mtime_ns = resolved.path.stat().st_mtime_ns
    except OSError:
        mtime_ns = 0
    key = (str(resolved.path), mtime_ns)
    with _LOCK:
        if key in _PROBE_CACHE:
            return _PROBE_CACHE[key], True
    version = _probe_version(resolved.path, list(entry.version_command))
    with _LOCK:
        _PROBE_CACHE[key] = version
        if len(_PROBE_CACHE) > 32:
            for old_key in [k for k in _PROBE_CACHE if k != key][:16]:
                _PROBE_CACHE.pop(old_key, None)
    return version, True


def catalog_meta(provider: str, home: Path | None = None) -> dict:
    provider = (provider or "").strip().lower()
    verified = verified_version(provider)
    installed_raw, binary_present = _installed_version(provider, home=home)
    installed_token = version_token(installed_raw)
    verified_token = version_token(verified)
    if not binary_present:
        stale = None
    elif installed_raw is None or installed_token is None:
        stale = "unknown"
    elif verified_token is not None and installed_token != verified_token:
        stale = installed_token
    else:
        stale = None
    return {
        "provider": provider,
        "verified_version": verified,
        "installed_version": installed_raw,
        "stale_for_version": stale,
        "source": "version-verified-data",
    }
