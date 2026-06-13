"""Read-only operational substrate status contract for the Pairling Mac daemon."""

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


class SubstrateStatusError(ValueError):
    pass


def _env(env: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if env is None else env


def substrate_status_max_limit(env: Mapping[str, str] | None = None) -> int:
    current_env = _env(env)
    try:
        value = int(current_env.get("COMPANION_SUBSTRATE_STATUS_MAX_LIMIT", str(DEFAULT_MAX_LIMIT)))
    except ValueError:
        return DEFAULT_MAX_LIMIT
    return max(1, min(value, 1000))


def organizer_bin(env: Mapping[str, str] | None = None) -> str:
    return _env(env).get("SUBSTRATE_ORGANIZER_BIN") or DEFAULT_ORGANIZER_BIN


def organizer_config(env: Mapping[str, str] | None = None) -> str:
    return _env(env).get("SUBSTRATE_ORGANIZER_CONFIG") or DEFAULT_ORGANIZER_CONFIG


def build_substrate_status_command(
    run: str | Path,
    since: str = DEFAULT_SINCE,
    limit: int = DEFAULT_LIMIT,
    *,
    organizer: str | None = None,
    config: str | None = None,
    env: Mapping[str, str] | None = None,
) -> list[str]:
    if not str(run).strip():
        raise SubstrateStatusError("run is required")
    if limit <= 0:
        raise SubstrateStatusError("limit must be positive")
    current_limit = min(limit, substrate_status_max_limit(env))
    return [
        organizer or organizer_bin(env),
        "--config",
        config or organizer_config(env),
        "substrate",
        "status",
        "--run",
        str(run),
        "--since",
        since,
        "--limit",
        str(current_limit),
        "--json",
    ]


def build_substrate_feed_command(
    run: str | Path,
    since: str = DEFAULT_SINCE,
    limit: int = DEFAULT_LIMIT,
    event_types: list[str] | None = None,
    *,
    organizer: str | None = None,
    config: str | None = None,
    env: Mapping[str, str] | None = None,
) -> list[str]:
    command = build_substrate_status_command(run, since=since, limit=limit, organizer=organizer, config=config, env=env)
    command[command.index("status")] = "feed"
    for event_type in event_types or []:
        if not event_type or len(event_type) > 120:
            raise SubstrateStatusError("event type must be a non-empty bounded string")
        command.extend(["--type", event_type])
    return command


def fetch_substrate_status(
    run: str | Path,
    since: str = DEFAULT_SINCE,
    limit: int = DEFAULT_LIMIT,
    *,
    timeout_seconds: float = 5.0,
    env: Mapping[str, str] | None = None,
) -> dict:
    payload = _run_json(build_substrate_status_command(run, since=since, limit=limit, env=env), timeout_seconds)
    if payload.get("feed") != "substrate.status.readonly.v1" or payload.get("read_only") is not True or payload.get("writes_performed") is not False:
        raise SubstrateStatusError("substrate status adapter returned an unexpected contract")
    payload["consumer"] = "pairling"
    payload["adapter"] = "pairling.substrate_status"
    return payload


def fetch_substrate_feed(
    run: str | Path,
    since: str = DEFAULT_SINCE,
    limit: int = DEFAULT_LIMIT,
    event_types: list[str] | None = None,
    *,
    timeout_seconds: float = 5.0,
    env: Mapping[str, str] | None = None,
) -> dict:
    payload = _run_json(build_substrate_feed_command(run, since=since, limit=limit, event_types=event_types, env=env), timeout_seconds)
    if payload.get("feed") != "substrate.feed.readonly.v1" or payload.get("read_only") is not True or payload.get("writes_performed") is not False:
        raise SubstrateStatusError("substrate feed adapter returned an unexpected contract")
    payload["consumer"] = "pairling"
    payload["adapter"] = "pairling.substrate_feed"
    return payload


def _run_json(command: list[str], timeout_seconds: float) -> dict:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds, check=False)
    except OSError as exc:
        raise SubstrateStatusError(f"could not execute substrate adapter: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SubstrateStatusError("substrate adapter timed out") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()[:500]
        raise SubstrateStatusError(f"substrate adapter failed: {detail}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SubstrateStatusError("substrate adapter returned invalid JSON") from exc
