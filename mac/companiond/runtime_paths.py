#!/usr/bin/env python3
"""Path resolver for the Pairling runtime."""

from __future__ import annotations

import os
from pathlib import Path

from runtime_contract import LEGACY_TOKEN_RELATIVE_PATH, POWER_STATE_PATH


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


def audit_log_path() -> Path:
    return logs_root() / "audit.jsonl"


def token_path() -> Path:
    return Path(os.environ.get("NOTIFY_TOKEN_FILE", str(home() / LEGACY_TOKEN_RELATIVE_PATH)))


def guardian_state_path() -> Path:
    return Path(os.environ.get("COMPANION_POWER_STATE_PATH", POWER_STATE_PATH))


def legacy_scripts_root() -> Path:
    return home() / ".claude" / "scripts"


def release_root_for(script_path: str | Path) -> Path | None:
    path = Path(script_path).resolve()
    parent = path.parent
    if parent.name in {"companiond", "guardian"}:
        root = parent.parent
        if (root / "manifest.json").is_file():
            return root
    return None
