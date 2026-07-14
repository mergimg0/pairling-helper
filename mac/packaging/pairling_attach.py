#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import select
import socket
import sys
import termios
import tty
from pathlib import Path


def _socket_path() -> Path:
    override = os.environ.get("PAIRLING_PTY_BROKER_SOCKET")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".claude" / "companion" / "pty-broker.sock"


def _broker_token() -> str:
    override = os.environ.get("PAIRLING_PTY_BROKER_TOKEN")
    if override:
        return override.strip()
    token_path = Path(os.environ.get("PAIRLING_PTY_BROKER_TOKEN_FILE") or Path.home() / ".claude" / "companion" / "pty-broker-token")
    try:
        return token_path.expanduser().read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def main(argv: list[str]) -> int:
    if len(argv) != 1 or not argv[0].strip():
        print("usage: pairling attach <session-id>", file=sys.stderr)
        return 2
    session_id = argv[0].strip()
    sock_path = _socket_path()
    if not sock_path.exists():
        print(f"pairling attach: broker socket not found at {sock_path}", file=sys.stderr)
        return 1
    token = _broker_token()
    if not token:
        print("pairling attach: broker token not found; update Pairling runtime and retry", file=sys.stderr)
        return 1

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(str(sock_path))
    sock.sendall(json.dumps({"op": "attach", "session_id": session_id, "token": token}).encode() + b"\n")

    stdin_fd = sys.stdin.fileno()
    old_attrs = termios.tcgetattr(stdin_fd) if sys.stdin.isatty() else None
    if old_attrs is not None:
        tty.setraw(stdin_fd)
    try:
        while True:
            readable, _, _ = select.select([stdin_fd, sock], [], [])
            if sock in readable:
                data = sock.recv(8192)
                if not data:
                    return 0
                os.write(sys.stdout.fileno(), data)
            if stdin_fd in readable:
                data = os.read(stdin_fd, 8192)
                if not data:
                    return 0
                sock.sendall(data)
    finally:
        if old_attrs is not None:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_attrs)
        sock.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
