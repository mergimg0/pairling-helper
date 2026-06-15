from __future__ import annotations

import base64
import json
import os
import secrets
import signal
import socket
import struct
import time
from pathlib import Path
from typing import Any


_RPC_MAX_FRAME_BYTES = 8 * 1024 * 1024


def ensure_pty_broker_token(companion_dir: Path) -> str:
    token_path = companion_dir / "pty-broker-token"
    try:
        companion_dir.mkdir(parents=True, exist_ok=True)
        if token_path.exists():
            token = token_path.read_text(encoding="utf-8").strip()
            if len(token) == 64 and all(ch in "0123456789abcdef" for ch in token):
                try:
                    os.chmod(token_path, 0o600)
                except OSError:
                    pass
                return token
        token = secrets.token_hex(32)
        tmp = token_path.with_name(token_path.name + f".tmp.{os.getpid()}")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(token + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, token_path)
        return token
    except OSError:
        return secrets.token_hex(32)


def _read_exact(conn: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise EOFError("socket closed while reading frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_frame(conn: socket.socket) -> dict[str, Any]:
    header = _read_exact(conn, 4)
    length = struct.unpack(">I", header)[0]
    if length <= 0 or length > _RPC_MAX_FRAME_BYTES:
        raise ValueError("invalid broker RPC frame length")
    payload = _read_exact(conn, length)
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("broker RPC response must be an object")
    return value


def _write_frame(conn: socket.socket, payload: dict[str, Any]) -> None:
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    conn.sendall(struct.pack(">I", len(data)) + data)


class PTYBrokerClient:
    def __init__(self, socket_path: Path, token: str, *, timeout: float = 5.0) -> None:
        self.socket_path = socket_path
        self.token = token
        self.timeout = timeout

    def _rpc(self, op: str, **fields) -> dict:
        request = {"op": op, "token": self.token, **fields}
        deadline = time.time() + self.timeout
        last_error: Exception | None = None
        while True:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                    conn.settimeout(max(0.25, min(1.0, deadline - time.time())))
                    conn.connect(str(self.socket_path))
                    _write_frame(conn, request)
                    response = _read_frame(conn)
                if not response.get("ok"):
                    error = response.get("error") if isinstance(response.get("error"), dict) else {}
                    raise RuntimeError(str(error.get("message") or error.get("code") or "broker RPC failed"))
                return response
            except (FileNotFoundError, ConnectionRefusedError, socket.timeout, OSError) as exc:
                last_error = exc
                if time.time() >= deadline:
                    raise RuntimeError(f"PTY broker unavailable: {type(exc).__name__}: {exc}") from exc
                time.sleep(0.05)
            except Exception:
                raise

    def spawn(self, *, session_id: str, provider: str, native_id: str, project: str, command: str,
              rows: int = 30, columns: int = 120, env: dict[str, str] | None = None) -> dict:
        return self._rpc(
            "spawn",
            session_id=session_id,
            provider=provider,
            native_id=native_id,
            project=project,
            command=command,
            rows=rows,
            columns=columns,
            env=env or {},
        )["session"]

    def get(self, session_id: str) -> dict | None:
        return self._rpc("get", session_id=session_id).get("session")

    def get_by_tty(self, tty: str) -> dict | None:
        return self._rpc("get_by_tty", tty=tty).get("session")

    def register_alias(self, alias: str, session: str | dict) -> None:
        session_id = session.get("session_id") if isinstance(session, dict) else str(session or "")
        if session_id:
            self._rpc("register_alias", alias=alias, session_id=session_id)

    def snapshot(self, session_id: str, public_session_id: str | None = None) -> dict | None:
        return self._rpc("snapshot", session_id=session_id, public_session_id=public_session_id or "").get("snapshot")

    def snapshot_v2(self, session_id: str, public_session_id: str | None = None) -> dict | None:
        return self._rpc("snapshot_v2", session_id=session_id, public_session_id=public_session_id or "").get("surface")

    def raw_tail(self, session_id: str, since: int = 0) -> tuple[bytes, int, int, bool] | None:
        tail = self._rpc("raw_tail", session_id=session_id, since=max(0, int(since or 0))).get("tail")
        if not isinstance(tail, dict):
            return None
        data = base64.b64decode(str(tail.get("b64") or ""))
        return data, int(tail.get("next_offset") or 0), int(tail.get("total") or 0), bool(tail.get("reset"))

    def control(self, session_id: str, action: dict) -> dict:
        return self._rpc("control", session_id=session_id, action=action).get("result") or {"ok": False, "reason": "empty broker result"}

    def send_text(self, session_id: str, text: str) -> dict:
        return self._rpc("send_text", session_id=session_id, text=text).get("result") or {"ok": False, "reason": "empty broker result"}

    def terminate(self, session_id: str, sig: int = signal.SIGTERM) -> dict:
        return self._rpc("terminate", session_id=session_id, sig=int(sig)).get("result") or {"ok": False, "reason": "empty broker result"}

    def status(self) -> dict:
        status = self._rpc("status").get("status")
        return status if isinstance(status, dict) else {}

    def list_sessions(self) -> list[dict]:
        sessions = self._rpc("list_sessions").get("sessions")
        return sessions if isinstance(sessions, list) else []

    def live_sessions(self) -> list[dict]:
        return [
            {
                "broker_id": item.get("session_id"),
                "provider": item.get("provider"),
                "native_id": item.get("native_id"),
                "slave_tty": item.get("slave_tty"),
                "pid": item.get("pid"),
            }
            for item in self.list_sessions()
            if isinstance(item, dict)
        ]
