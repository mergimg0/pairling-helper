"""first_seen persistence for catalog entries (SPEC-p2 §2.2).

The companion side-file records when each catalog entry was first observed,
keyed per provider by name|source. The file is written ONLY when a new key
appears: the 5s signature loop and steady-state /commands fetches never touch
disk (acceptance 5). Keys are never pruned on absence — project-scoped
entries come and go with the cwd — but each provider block is capped, oldest
first, so the file stays bounded.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path


MAX_KEYS_PER_PROVIDER = 2000

_LOCK = threading.Lock()
_CACHE: dict[str, tuple[int, dict]] = {}


def state_path(home: Path | None = None) -> Path:
    base = home or Path.home()
    return base / ".claude" / "companion" / "command-catalog-state.json"


def _load(path: Path) -> dict:
    try:
        mtime_ns = path.stat().st_mtime_ns
    except OSError:
        return {}
    key = str(path)
    with _LOCK:
        cached = _CACHE.get(key)
        if cached is not None and cached[0] == mtime_ns:
            return json.loads(json.dumps(cached[1]))
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(payload, dict):
        return {}
    providers = payload.get("providers")
    data = providers if isinstance(providers, dict) else {}
    with _LOCK:
        _CACHE[key] = (mtime_ns, json.loads(json.dumps(data)))
    return json.loads(json.dumps(data))


def _write(path: Path, providers: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    payload = {"schema_version": 1, "providers": providers}
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=1, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    try:
        with _LOCK:
            _CACHE[str(path)] = (path.stat().st_mtime_ns, json.loads(json.dumps(providers)))
    except OSError:
        pass


def _entry_key(item: dict) -> str:
    name = str(item.get("name") or "")
    source = str(item.get("source") or "")
    return f"{name}|{source}"


def annotate_first_seen(provider: str, items: list[dict], home: Path | None = None, now: str | None = None) -> list[dict]:
    """Stamp every item with first_seen; persist newly-appeared keys only."""
    provider = (provider or "").strip().lower()
    path = state_path(home)
    providers = _load(path)
    block = providers.get(provider)
    if not isinstance(block, dict):
        block = {}
    stamp = now or datetime.now(timezone.utc).isoformat(timespec="seconds")
    changed = False
    annotated: list[dict] = []
    for item in items:
        key = _entry_key(item)
        first_seen = block.get(key)
        if not isinstance(first_seen, str) or not first_seen:
            first_seen = stamp
            block[key] = first_seen
            changed = True
        annotated.append({**item, "first_seen": first_seen})
    if changed:
        if len(block) > MAX_KEYS_PER_PROVIDER:
            oldest_first = sorted(block.items(), key=lambda kv: kv[1])
            block = dict(oldest_first[len(block) - MAX_KEYS_PER_PROVIDER:])
        providers[provider] = block
        try:
            _write(path, providers)
        except OSError:
            pass
    return annotated
