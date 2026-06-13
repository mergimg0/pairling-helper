"""Read-only workstate feed contract for the Pairling Mac daemon."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Mapping


DEFAULT_SINCE = "0000-01-01T00:00:00.000Z"
DEFAULT_LIMIT = 50
DEFAULT_MAX_LIMIT = 200
DEFAULT_ORGANIZER_BIN = str(Path.home() / "projects" / "metal-perception-memory-substrate" / "organizer")
DEFAULT_ORGANIZER_CONFIG = str(Path.home() / "projects" / "metal-perception-memory-substrate" / "organizer.yaml")


class WorkstateFeedError(ValueError):
    pass


def _env(env: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if env is None else env


def workstate_feed_max_limit(env: Mapping[str, str] | None = None) -> int:
    current_env = _env(env)
    try:
        value = int(current_env.get("COMPANION_WORKSTATE_FEED_MAX_LIMIT", str(DEFAULT_MAX_LIMIT)))
    except ValueError:
        return DEFAULT_MAX_LIMIT
    return max(1, min(value, 1000))


def organizer_bin(env: Mapping[str, str] | None = None) -> str:
    return _env(env).get("WORKSTATE_ORGANIZER_BIN") or DEFAULT_ORGANIZER_BIN


def organizer_config(env: Mapping[str, str] | None = None) -> str:
    return _env(env).get("WORKSTATE_ORGANIZER_CONFIG") or DEFAULT_ORGANIZER_CONFIG


def build_workstate_feed_command(
    run: str | Path,
    since: str = DEFAULT_SINCE,
    limit: int = DEFAULT_LIMIT,
    event_types: list[str] | None = None,
    *,
    organizer: str | None = None,
    config: str | None = None,
    env: Mapping[str, str] | None = None,
) -> list[str]:
    if not str(run).strip():
        raise WorkstateFeedError("run is required")
    if limit <= 0:
        raise WorkstateFeedError("limit must be positive")

    current_limit = min(limit, workstate_feed_max_limit(env))
    command = [
        organizer or organizer_bin(env),
        "--config",
        config or organizer_config(env),
        "workstate",
        "feed",
        "--run",
        str(run),
        "--since",
        since,
        "--limit",
        str(current_limit),
        "--json",
    ]
    for event_type in event_types or []:
        if not event_type or len(event_type) > 120:
            raise WorkstateFeedError("event type must be a non-empty bounded string")
        command.extend(["--type", event_type])
    return command


def fetch_workstate_feed(
    run: str | Path,
    since: str = DEFAULT_SINCE,
    limit: int = DEFAULT_LIMIT,
    event_types: list[str] | None = None,
    *,
    timeout_seconds: float = 5.0,
    env: Mapping[str, str] | None = None,
) -> dict:
    command = build_workstate_feed_command(run, since=since, limit=limit, event_types=event_types, env=env)
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds, check=False)
    except OSError as exc:
        raise WorkstateFeedError(f"could not execute workstate feed adapter: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise WorkstateFeedError("workstate feed adapter timed out") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()[:500]
        raise WorkstateFeedError(f"workstate feed adapter failed: {detail}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise WorkstateFeedError("workstate feed adapter returned invalid JSON") from exc
    if payload.get("feed") != "workstate.readonly.v1" or payload.get("read_only") is not True:
        raise WorkstateFeedError("workstate feed adapter returned an unexpected contract")
    payload["consumer"] = "pairling"
    payload["adapter"] = "pairling.workstate_feed"
    return payload
