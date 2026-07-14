#!/usr/bin/env python3
"""Path resolver for the Pairling runtime."""

from __future__ import annotations

import json
import os
from pathlib import Path

from runtime_contract import LEGACY_TOKEN_RELATIVE_PATH


def home() -> Path:
    return Path.home()


def app_support_root() -> Path:
    return Path(
        os.environ.get(
            "PAIRLING_APP_SUPPORT_ROOT",
            os.environ.get(
                "COMPANION_APP_SUPPORT_ROOT",
                str(home() / "Library" / "Application Support" / "Pairling"),
            ),
        )
    )


def logs_root() -> Path:
    return Path(
        os.environ.get(
            "PAIRLING_LOGS_ROOT",
            os.environ.get(
                "COMPANION_LOGS_ROOT",
                str(home() / "Library" / "Logs" / "Pairling"),
            ),
        )
    )


def runtime_root() -> Path:
    return app_support_root() / "runtime"


def current_release() -> Path:
    return runtime_root() / "current"


def state_root() -> Path:
    return app_support_root() / "state"


def install_history_path() -> Path:
    return state_root() / "install-history.jsonl"


def install_id_path() -> Path:
    return state_root() / "install-id"


def devices_db_path() -> Path:
    return app_support_root() / "devices.sqlite"


def _absolute_persisted_path(value: object, *, source: str) -> Path:
    path = Path(str(value or "")).expanduser()
    if not str(value or "").strip() or not path.is_absolute():
        raise ValueError(f"{source} must be an absolute path")
    return path.resolve(strict=False)


def pairdrop_root() -> Path:
    """Resolve the one setup-owned PairDrop vault used by the daemon and CLI."""
    configured = os.environ.get("PAIRLING_PAIRDROP_ROOT")
    if configured is not None:
        return _absolute_persisted_path(configured, source="PAIRLING_PAIRDROP_ROOT")

    support_root = app_support_root()
    config_path = support_root / "config.json"
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        config = None
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Pairling config.json cannot resolve the PairDrop vault") from exc
    if isinstance(config, dict):
        paths = config.get("paths")
        if isinstance(paths, dict) and paths.get("pairdrop") is not None:
            return _absolute_persisted_path(
                paths.get("pairdrop"),
                source="config.json paths.pairdrop",
            )

    manifest_path = current_release() / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        manifest = None
    if isinstance(manifest, dict):
        paths = manifest.get("paths")
        if isinstance(paths, dict) and paths.get("pairdrop") is not None:
            return _absolute_persisted_path(
                paths.get("pairdrop"),
                source="runtime manifest paths.pairdrop",
            )

    return (home() / "PairDrop").resolve(strict=False)


def audit_log_path() -> Path:
    return logs_root() / "audit.jsonl"


def token_path() -> Path:
    return Path(os.environ.get("NOTIFY_TOKEN_FILE", str(home() / LEGACY_TOKEN_RELATIVE_PATH)))


def legacy_scripts_root() -> Path:
    return home() / ".claude" / "scripts"


def release_root_for(script_path: str | Path) -> Path | None:
    path = Path(script_path).resolve()
    parent = path.parent
    if parent.name == "companiond":
        root = parent.parent
        if (root / "manifest.json").is_file():
            return root
    return None
