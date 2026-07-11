"""Provider visibility store — the only user choice (SPEC-p1 §2.3).

Truth lives in ~/.pairling/providers.json as {"excluded": [...]}. Default is
everything detected is included: a missing or corrupt file means "hide
nothing". ~/.pairling is Pairling's OWN config home — this module never reads
or writes a provider's dotdir (Law 3: exclusion hides; it never touches the
provider's config or processes).

Reads are mtime-cached and re-checked per call, so a toggle from the phone or
the wizard lands on the very next request with no daemon restart.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .base import is_valid_provider_id, normalize_provider_id


SCHEMA_VERSION = 1

_LOCK = threading.Lock()
_CACHE: dict[str, tuple[int, frozenset[str]]] = {}


def visibility_path(home: Path | None = None) -> Path:
    base = home or Path.home()
    return base / ".pairling" / "providers.json"


def read_excluded(home: Path | None = None) -> set[str]:
    path = visibility_path(home)
    try:
        mtime_ns = path.stat().st_mtime_ns
    except OSError:
        return set()
    key = str(path)
    with _LOCK:
        cached = _CACHE.get(key)
        if cached is not None and cached[0] == mtime_ns:
            return set(cached[1])
    excluded = _parse_excluded(path)
    with _LOCK:
        _CACHE[key] = (mtime_ns, frozenset(excluded))
        if len(_CACHE) > 8:
            for old_key in [k for k in _CACHE if k != key][:4]:
                _CACHE.pop(old_key, None)
    return excluded


def _parse_excluded(path: Path) -> set[str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    raw = payload.get("excluded") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return set()
    return {
        normalize_provider_id(item)
        for item in raw
        if isinstance(item, str) and is_valid_provider_id(item)
    }


def write_excluded(excluded: set[str], home: Path | None = None) -> None:
    path = visibility_path(home)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "excluded": sorted(
            normalize_provider_id(item) for item in excluded if is_valid_provider_id(item)
        ),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def set_provider_included(provider_id: str, included: bool, home: Path | None = None) -> set[str]:
    wanted = normalize_provider_id(provider_id)
    excluded = read_excluded(home=home)
    if included:
        excluded.discard(wanted)
    else:
        excluded.add(wanted)
    write_excluded(excluded, home=home)
    return read_excluded(home=home)
