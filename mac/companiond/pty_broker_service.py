#!/usr/bin/env python3
from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

from pty_broker import PTYBrokerManager, ensure_pty_broker_token


def _app_support_root() -> Path:
    raw = os.environ.get("PAIRLING_APP_SUPPORT_ROOT")
    if raw:
        return Path(raw).expanduser()
    return Path.home() / "Library" / "Application Support" / "Pairling"


def _runtime_root() -> Path:
    return Path(__file__).absolute().parent.parent


def _source_revision(runtime_root: Path) -> str | None:
    for path in [runtime_root / "manifest.json", runtime_root / "mac" / "SOURCE_REVISION", runtime_root / "SOURCE_REVISION"]:
        try:
            if path.name == "manifest.json":
                import json

                payload = json.loads(path.read_text(encoding="utf-8"))
                revision = payload.get("source_revision")
                return str(revision) if revision else None
            revision = path.read_text(encoding="utf-8").strip()
            return revision or None
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return None


def main() -> int:
    home = Path.home()
    companion_dir = home / ".claude" / "companion"
    terminal_capture_dir = companion_dir / "terminal-capture"
    token = ensure_pty_broker_token(companion_dir)
    socket_path = companion_dir / "pty-broker.sock"
    runtime_root = _runtime_root()
    manager = PTYBrokerManager(
        socket_path=socket_path,
        log_dir=terminal_capture_dir,
        token=token,
        runtime_root=runtime_root,
        script_path=Path(__file__).absolute(),
        source_revision=_source_revision(runtime_root),
    )

    stopping = False

    def _handle_signal(signum, _frame) -> None:
        nonlocal stopping
        stopping = True
        print(
            f"pairling pty broker received {signal.Signals(signum).name}; live PTYs will hang up if the service exits",
            file=sys.stderr,
            flush=True,
        )

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    print(
        f"pairling pty broker starting socket={socket_path} app_support={_app_support_root()}",
        file=sys.stderr,
        flush=True,
    )
    manager.start_attach_server()
    while not stopping:
        time.sleep(1.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
