from __future__ import annotations

import base64
import errno
import json
import os
import secrets
import signal
import socket
import stat
import struct
import time
from pathlib import Path
from typing import Any


_RPC_MAX_FRAME_BYTES = 16 * 1024 * 1024
_READ_RPC_TIMEOUT_SECONDS = 0.35
_LARGE_SURFACE_RPC_TIMEOUT_SECONDS = 2.0
_RETRYABLE_SOCKET_ERRNOS = {
    errno.EAGAIN,
    errno.ECONNREFUSED,
    errno.ECONNRESET,
    errno.ENOENT,
    errno.ETIMEDOUT,
}


class PTYBrokerOutcomeUnknownError(RuntimeError):
    """A mutating request may have reached the broker without a response."""


def _secure_companion_directory(companion_dir: Path) -> None:
    companion_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = companion_dir.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError(f"broker credential path must be a real directory: {companion_dir}")
    if metadata.st_uid != os.geteuid():
        raise PermissionError("broker credential path must be owned by the current user")
    os.chmod(companion_dir, 0o700, follow_symlinks=False)


def ensure_pty_broker_token(companion_dir: Path) -> str:
    token_path = companion_dir / "pty-broker-token"
    try:
        _secure_companion_directory(companion_dir)
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


def _encode_frame(payload: dict[str, Any]) -> bytes:
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(data) <= 0 or len(data) > _RPC_MAX_FRAME_BYTES:
        raise ValueError("broker RPC request exceeds bounded transport limit")
    return struct.pack(">I", len(data)) + data


def _write_frame(conn: socket.socket, payload: dict[str, Any]) -> None:
    conn.sendall(_encode_frame(payload))


class PTYBrokerClient:
    def __init__(self, socket_path: Path, token: str, *, timeout: float = 5.0) -> None:
        self.socket_path = socket_path
        self.token = token
        self.timeout = timeout

    def _rpc(
        self,
        op: str,
        *,
        rpc_timeout: float | None = None,
        mutating: bool = False,
        **fields,
    ) -> dict:
        request = {"op": op, "token": self.token, **fields}
        request_frame = _encode_frame(request)
        timeout = self.timeout if rpc_timeout is None else max(0.05, float(rpc_timeout))
        deadline = time.time() + timeout
        while True:
            request_may_have_reached_broker = False
            response_received = False
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        raise socket.timeout("broker RPC deadline exceeded")
                    conn.settimeout(max(0.001, remaining))
                    conn.connect(str(self.socket_path))
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        raise socket.timeout("broker RPC deadline exceeded")
                    conn.settimeout(max(0.001, remaining))
                    # sendall can fail after a partial write. From this point a
                    # mutating request has an unknown outcome unless the broker
                    # returns a complete response.
                    request_may_have_reached_broker = True
                    conn.sendall(request_frame)
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        raise socket.timeout("broker RPC deadline exceeded")
                    conn.settimeout(max(0.001, remaining))
                    response = _read_frame(conn)
                    response_received = True
                if not response.get("ok"):
                    error = response.get("error") if isinstance(response.get("error"), dict) else {}
                    raise RuntimeError(str(error.get("message") or error.get("code") or "broker RPC failed"))
                return response
            except (FileNotFoundError, ConnectionRefusedError, socket.timeout, OSError) as exc:
                if mutating and request_may_have_reached_broker and not response_received:
                    raise PTYBrokerOutcomeUnknownError(
                        f"PTY broker {op} outcome unknown after request transmission: "
                        f"{type(exc).__name__}: {exc}"
                    ) from exc
                if (
                    isinstance(exc, OSError)
                    and not isinstance(exc, (FileNotFoundError, ConnectionRefusedError, socket.timeout))
                    and exc.errno not in _RETRYABLE_SOCKET_ERRNOS
                ):
                    raise RuntimeError(
                        f"PTY broker unavailable: {type(exc).__name__}: {exc}"
                    ) from exc
                if time.time() >= deadline:
                    raise RuntimeError(f"PTY broker unavailable: {type(exc).__name__}: {exc}") from exc
                time.sleep(0.05)
            except Exception as exc:
                if mutating and request_may_have_reached_broker and not response_received:
                    raise PTYBrokerOutcomeUnknownError(
                        f"PTY broker {op} outcome unknown after request transmission: "
                        f"{type(exc).__name__}: {exc}"
                    ) from exc
                raise

    def _read_rpc(self, op: str, **fields) -> dict:
        return self._rpc(op, rpc_timeout=min(self.timeout, _READ_RPC_TIMEOUT_SECONDS), **fields)

    def spawn(self, *, session_id: str, provider: str, native_id: str, project: str, command: str,
              rows: int = 30, columns: int = 120, env: dict[str, str] | None = None) -> dict:
        return self._rpc(
            "spawn",
            mutating=True,
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
        return self._read_rpc("get", session_id=session_id).get("session")

    def get_by_tty(self, tty: str) -> dict | None:
        return self._read_rpc("get_by_tty", tty=tty).get("session")

    def register_alias(self, alias: str, session: str | dict) -> None:
        session_id = session.get("session_id") if isinstance(session, dict) else str(session or "")
        if session_id:
            self._rpc("register_alias", mutating=True, alias=alias, session_id=session_id)

    def snapshot(self, session_id: str, public_session_id: str | None = None) -> dict | None:
        return self._read_rpc("snapshot", session_id=session_id, public_session_id=public_session_id or "").get("snapshot")

    def snapshot_v2(
        self,
        session_id: str,
        public_session_id: str | None = None,
        window_start: int | None = None,
        window_size: int | None = None,
    ) -> dict | None:
        kwargs: dict = {"session_id": session_id, "public_session_id": public_session_id or ""}
        if window_start is not None:
            kwargs["window_start"] = int(window_start)
        if window_size is not None:
            kwargs["window_size"] = int(window_size)
        return self._rpc(
            "snapshot_v2",
            rpc_timeout=min(self.timeout, _LARGE_SURFACE_RPC_TIMEOUT_SECONDS),
            **kwargs,
        ).get("surface")

    def snapshot_pair(
        self,
        session_id: str,
        public_session_id: str | None = None,
    ) -> dict | None:
        pair = self._rpc(
            "snapshot_pair",
            rpc_timeout=min(self.timeout, _LARGE_SURFACE_RPC_TIMEOUT_SECONDS),
            session_id=session_id,
            public_session_id=public_session_id or "",
        ).get("pair")
        return pair if isinstance(pair, dict) else None

    def delta_v2(self, session_id: str, since_generation: int, public_session_id: str | None = None) -> dict | None:
        return self._rpc(
            "delta_v2",
            rpc_timeout=min(self.timeout, _LARGE_SURFACE_RPC_TIMEOUT_SECONDS),
            session_id=session_id,
            since_generation=max(0, int(since_generation or 0)),
            public_session_id=public_session_id or "",
        ).get("delta")

    def raw_tail(self, session_id: str, since: int = 0) -> tuple[bytes, int, int, bool, int, float | None] | None:
        tail = self._read_rpc("raw_tail", session_id=session_id, since=max(0, int(since or 0))).get("tail")
        if not isinstance(tail, dict):
            return None
        data = base64.b64decode(str(tail.get("b64") or ""))
        raw_feed_at = tail.get("feed_at")
        return (
            data,
            int(tail.get("next_offset") or 0),
            int(tail.get("total") or 0),
            bool(tail.get("reset")),
            int(tail.get("gap_bytes") or 0),
            float(raw_feed_at) if isinstance(raw_feed_at, (int, float)) else None,
        )

    def control(self, session_id: str, action: dict) -> dict:
        return self._rpc("control", mutating=True, session_id=session_id, action=action).get("result") or {"ok": False, "reason": "empty broker result"}

    def interrupt(self, session_id: str) -> dict:
        return self._rpc("interrupt", mutating=True, session_id=session_id).get("result") or {"ok": False, "reason": "empty broker result"}

    def send_text(self, session_id: str, text: str) -> dict:
        return self._rpc("send_text", mutating=True, session_id=session_id, text=text).get("result") or {"ok": False, "reason": "empty broker result"}

    def terminate(self, session_id: str, sig: int = signal.SIGTERM) -> dict:
        return self._rpc("terminate", mutating=True, session_id=session_id, sig=int(sig)).get("result") or {"ok": False, "reason": "empty broker result"}

    def status(self) -> dict:
        status = self._read_rpc("status").get("status")
        return status if isinstance(status, dict) else {}

    def list_sessions(self) -> list[dict]:
        sessions = self._read_rpc("list_sessions").get("sessions")
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
