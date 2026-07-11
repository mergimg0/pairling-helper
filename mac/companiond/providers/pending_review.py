"""Capabilities held by the CLI's own gate (SPEC-p2 §2.3).

Pairling REPORTS the CLI's own pending/blocked state and never trusts,
untrusts, or edits anything on the user's behalf (Law 3). Detectors read real
artifacts only. Today that is one signal: a Claude plugin that is installed
AND present in Claude Code's own blocklist.json. Neither claude 2.1.201 nor
codex 0.142.5 exposes a hook-review state file (spiked 2026-07-04); new
detectors are added here as the CLIs grow readable gate state.
"""

from __future__ import annotations

import json
from pathlib import Path


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _claude_blocked_installed_plugins(home: Path) -> list[dict]:
    plugins_dir = home / ".claude" / "plugins"
    installed_payload = _read_json(plugins_dir / "installed_plugins.json")
    blocklist_payload = _read_json(plugins_dir / "blocklist.json")
    if not isinstance(installed_payload, dict) or not isinstance(blocklist_payload, dict):
        return []
    installed = installed_payload.get("plugins")
    blocked_raw = blocklist_payload.get("plugins")
    if not isinstance(installed, dict) or not isinstance(blocked_raw, list):
        return []
    blocked: dict[str, dict] = {}
    for item in blocked_raw:
        if isinstance(item, dict) and isinstance(item.get("plugin"), str):
            blocked[item["plugin"]] = item
    out: list[dict] = []
    for name in sorted(installed):
        if name in blocked:
            entry = blocked[name]
            out.append({
                "provider": "claude",
                "kind": "plugin",
                "name": name,
                "reason": str(entry.get("reason") or "blocklisted"),
            })
    return out


def collect(home: Path | None = None) -> list[dict]:
    base = home or Path.home()
    items: list[dict] = []
    items.extend(_claude_blocked_installed_plugins(base))
    return items
