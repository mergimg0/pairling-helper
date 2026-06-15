#!/usr/bin/env python3
"""Render Pairling launchd plists with absolute runtime paths."""

from __future__ import annotations

import argparse
import plistlib
from pathlib import Path

PAIRLING_DAEMON_LABEL = "dev.pairling.companiond"
PAIRLING_GUARDIAN_LABEL = "dev.pairling.power-guardian"
PAIRLING_CONNECTD_LABEL = "dev.pairling.connectd"
PAIRLING_PTYBROKER_LABEL = "dev.pairling.ptybroker"
PAIRLING_RUNTIME_PORT = "7773"


def write_plist(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        plistlib.dump(payload, fh, sort_keys=False)


def daemon_plist(current: Path, logs: Path, python_bin: str) -> dict:
    return {
        "Label": PAIRLING_DAEMON_LABEL,
        "ProgramArguments": [
            python_bin,
            str(current / "companiond" / "pairlingd.py"),
        ],
        "EnvironmentVariables": {
            "PAIRLING_RUNTIME_PORT": PAIRLING_RUNTIME_PORT,
            "COMPANION_DAEMON_PORT": PAIRLING_RUNTIME_PORT,
            "PAIRLING_BIND_MODE": "all",
            "PAIRLING_APP_SUPPORT_ROOT": str(current.parent.parent),
            "PAIRLING_LOGS_ROOT": str(logs),
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        },
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "StandardOutPath": str(logs / "companiond.log"),
        "StandardErrorPath": str(logs / "companiond.err"),
    }


def guardian_plist(current: Path, logs: Path, python_bin: str) -> dict:
    return {
        "Label": PAIRLING_GUARDIAN_LABEL,
        "ProgramArguments": [
            python_bin,
            str(current / "guardian" / "companion-power-guardian.py"),
        ],
        "EnvironmentVariables": {
            "PAIRLING_RUNTIME_PORT": PAIRLING_RUNTIME_PORT,
            "COMPANION_DAEMON_PORT": PAIRLING_RUNTIME_PORT,
            "COMPANION_COORDINATOR_HOST": "pairling-mac",
            "COMPANION_GUARDIAN_ENFORCE": "0",
            "COMPANION_LOW_POWER_MODE_POLICY": "preserve",
            "COMPANION_POWER_INTERVAL_SECONDS": "20",
            "COMPANION_POWER_STATE_PATH": "/var/run/pairling-power-state.json",
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        },
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": str(logs / "power-guardian.log"),
        "StandardErrorPath": str(logs / "power-guardian.err"),
    }


def connectd_plist(current: Path, logs: Path) -> dict:
    app_support = current.parent.parent
    return {
        "Label": PAIRLING_CONNECTD_LABEL,
        "ProgramArguments": [
            str(current / "connectd" / "pairling-connectd"),
            "--upstream",
            f"http://127.0.0.1:{PAIRLING_RUNTIME_PORT}",
            "--listen",
            f":{PAIRLING_RUNTIME_PORT}",
            "--status-addr",
            "127.0.0.1:7774",
            "--state-dir",
            str(app_support / "connectd" / "tsnet-state"),
        ],
        "EnvironmentVariables": {
            "PAIRLING_RUNTIME_PORT": PAIRLING_RUNTIME_PORT,
            "PAIRLING_APP_SUPPORT_ROOT": str(app_support),
            "PAIRLING_LOGS_ROOT": str(logs),
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        },
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "StandardOutPath": str(logs / "connectd.log"),
        "StandardErrorPath": str(logs / "connectd.err"),
    }


def ptybroker_plist(current: Path, logs: Path, python_bin: str) -> dict:
    app_support = current.parent.parent
    return {
        "Label": PAIRLING_PTYBROKER_LABEL,
        "ProgramArguments": [
            python_bin,
            str(current / "companiond" / "pty_broker_service.py"),
        ],
        "EnvironmentVariables": {
            "PAIRLING_APP_SUPPORT_ROOT": str(app_support),
            "PAIRLING_LOGS_ROOT": str(logs),
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        },
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "StandardOutPath": str(logs / "ptybroker.log"),
        "StandardErrorPath": str(logs / "ptybroker.err"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--current-root", required=True)
    parser.add_argument("--logs-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--daemon-python", default="/usr/local/bin/python3")
    parser.add_argument("--guardian-python", default="/usr/bin/python3")
    parser.add_argument("--mirror-python", default="/usr/local/bin/python3", help=argparse.SUPPRESS)
    args = parser.parse_args()

    current = Path(args.current_root)
    logs = Path(args.logs_root)
    out = Path(args.output_dir)

    write_plist(out / f"{PAIRLING_DAEMON_LABEL}.plist", daemon_plist(current, logs, args.daemon_python))
    write_plist(out / f"{PAIRLING_PTYBROKER_LABEL}.plist", ptybroker_plist(current, logs, args.daemon_python))
    write_plist(out / f"{PAIRLING_GUARDIAN_LABEL}.plist", guardian_plist(current, logs, args.guardian_python))
    write_plist(out / f"{PAIRLING_CONNECTD_LABEL}.plist", connectd_plist(current, logs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
