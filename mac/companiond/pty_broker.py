from __future__ import annotations

import fcntl
import base64
import codecs
from collections import deque
import hashlib
import json
import os
import pty
import re
import select
import shlex
import signal
import socket
import secrets
import stat
import struct
import subprocess
import sys
import termios
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Iterable

from terminal_text_sanitizer import TERMINAL_TEXT_MAX_CHARS, sanitize_terminal_text_input
from terminal_screen_backend import create_terminal_screen_backend, detect_terminal_pending_input
from runtime_manifest import ptybroker_payload_sha256


_ABSOLUTE_PATH_ROOT_TOKENS = {
    "Applications",
    "Library",
    "System",
    "Users",
    "Volumes",
    "bin",
    "dev",
    "etc",
    "home",
    "opt",
    "private",
    "sbin",
    "tmp",
    "usr",
    "var",
}
_ANSI_COLOR_NAMES = ("black", "red", "green", "yellow", "blue", "magenta", "cyan", "white")
# A fully styled 200x500 TerminalSurfaceV2 frame is larger than 8 MiB. Keep
# the local-socket contract bounded, but large enough for the maximum grid the
# broker itself permits.
_RPC_MAX_FRAME_BYTES = 16 * 1024 * 1024

# Capture retention (Wave A): recordings are the replay corpus and the
# forensic record, but they must not grow without bound or keep old
# sessions' bytes at rest forever. On session close each file truncates
# from the head to the tail cap, recording the dropped byte count in a
# .pruned sidecar so nothing vanishes silently; the directory prunes
# oldest-first to the budget at broker startup and on spawn.
CAPTURE_TAIL_BYTES = max(64 * 1024, int(os.environ.get("PAIRLING_CAPTURE_TAIL_BYTES", str(4 * 1024 * 1024))))
CAPTURE_DIR_BUDGET_BYTES = max(16 * 1024 * 1024, int(os.environ.get("PAIRLING_CAPTURE_DIR_BUDGET_BYTES", str(512 * 1024 * 1024))))
SCROLLBACK_DISK_BUDGET_BYTES = max(
    8 * 1024 * 1024,
    int(os.environ.get("PAIRLING_SCROLLBACK_DISK_BUDGET_BYTES", str(256 * 1024 * 1024))),
)
SCROLLBACK_SPARSE_INDEX_BYTES = 64 * 1024


def _secure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError(f"private storage path must be a real directory: {path}")
    if metadata.st_uid != os.geteuid():
        raise PermissionError(f"private storage path must be owned by the current user: {path}")
    os.chmod(path, 0o700, follow_symlinks=False)


def _secure_private_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise OSError(f"private storage path must be a regular file: {path}")
    if metadata.st_uid != os.geteuid():
        raise PermissionError(f"private storage file must be owned by the current user: {path}")
    os.chmod(path, 0o600, follow_symlinks=False)


def secure_sensitive_local_storage(
    companion_dir: Path,
    terminal_capture_dir: Path,
    *,
    audit_dir: Path | None = None,
    logs_dir: Path | None = None,
) -> None:
    """Create and repair private modes for local terminal and receipt data."""
    companion_dir = Path(companion_dir)
    terminal_capture_dir = Path(terminal_capture_dir)
    private_dirs = [companion_dir, terminal_capture_dir]
    if audit_dir is not None:
        private_dirs.append(Path(audit_dir))
    if logs_dir is not None:
        private_dirs.append(Path(logs_dir))
    for directory in private_dirs:
        _secure_private_directory(directory)

    for entry in terminal_capture_dir.rglob("*"):
        metadata = entry.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise OSError(f"terminal capture storage must not contain links: {entry}")
        if stat.S_ISDIR(metadata.st_mode):
            _secure_private_directory(entry)
        elif stat.S_ISREG(metadata.st_mode):
            _secure_private_file(entry)

    private_suffixes = (".sqlite", ".sqlite-wal", ".sqlite-shm", ".jsonl")
    for entry in companion_dir.iterdir():
        if entry.name == "pty-broker-token" or entry.name.endswith(private_suffixes):
            _secure_private_file(entry)
    for directory in (audit_dir, logs_dir):
        if directory is None:
            continue
        for entry in Path(directory).iterdir():
            metadata = entry.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise OSError(f"private storage must not contain links: {entry}")
            if stat.S_ISREG(metadata.st_mode):
                _secure_private_file(entry)


def _capture_path_identity(path: Path | str) -> str:
    return os.path.abspath(os.fspath(path))


def _capture_pruned_bytes(sidecar: Path) -> int:
    try:
        _secure_private_file(sidecar)
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
        value = payload.get("dropped_bytes") if isinstance(payload, dict) else None
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return 0


def truncate_capture_tail(path, tail_bytes: int = CAPTURE_TAIL_BYTES) -> int:
    """Keeps the newest tail_bytes of a recording, writes a .pruned sidecar
    naming the dropped byte count, and returns it. 0 means untouched."""
    try:
        if path is None:
            return 0
        path = Path(path)
        _secure_private_file(path)
        size = path.stat().st_size
        if size <= tail_bytes:
            return 0
        with open(path, "rb") as handle:
            handle.seek(size - tail_bytes)
            tail = handle.read()
        unique = f"{os.getpid()}.{secrets.token_hex(4)}"
        tmp = path.with_name(path.name + f".tmp.{unique}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(tmp, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(tail)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(path)
        _secure_private_file(path)
        dropped = size - tail_bytes
        sidecar = path.with_name(path.name + ".pruned")
        total_dropped = _capture_pruned_bytes(sidecar) + dropped
        sidecar_tmp = sidecar.with_name(sidecar.name + f".tmp.{unique}")
        sidecar_payload = json.dumps({
            "dropped_bytes": total_dropped,
            "last_dropped_bytes": dropped,
            "retained_bytes": len(tail),
            "pruned_at": time.time(),
        }, sort_keys=True) + "\n"
        descriptor = os.open(sidecar_tmp, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(sidecar_payload)
            handle.flush()
            os.fsync(handle.fileno())
        sidecar_tmp.replace(sidecar)
        _secure_private_file(sidecar)
        return dropped
    except OSError:
        return 0


def _open_capture_append(path: Path) -> BinaryIO:
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "ab")


def _bound_live_capture(
    handle: BinaryIO,
    path: Path,
    *,
    tail_bytes: int,
) -> BinaryIO | None:
    """Compact an active capture at a bounded high-water mark.

    Keeping twice the final tail avoids rewriting a multi-megabyte file for
    every PTY chunk while still placing a hard bound on a session that runs for
    days. A failed compaction disables further disk capture for this session so
    a forensic write can never exhaust the user's disk.
    """

    tail_bytes = max(1, int(tail_bytes))
    live_limit = tail_bytes * 2
    try:
        size = os.fstat(handle.fileno()).st_size
    except OSError:
        handle.close()
        return None
    if size <= live_limit:
        return handle

    handle.close()
    dropped = truncate_capture_tail(path, tail_bytes=tail_bytes)
    try:
        retained_size = path.stat().st_size
    except OSError:
        return None
    if dropped <= 0 or retained_size > tail_bytes:
        return None
    try:
        return _open_capture_append(path)
    except OSError:
        return None


def prune_capture_dir(
    log_dir,
    budget_bytes: int = CAPTURE_DIR_BUDGET_BYTES,
    *,
    excluded_paths: Iterable[Path | str] = (),
) -> list[str]:
    """Removes oldest recordings (and their sidecars) until the directory
    fits the budget. Returns the removed file names, oldest first."""
    removed: list[str] = []
    try:
        log_dir = Path(log_dir)
        _secure_private_directory(log_dir)
        excluded = {_capture_path_identity(path) for path in excluded_paths}
        entries = []
        total = 0
        for entry in log_dir.glob("broker-*.log"):
            try:
                stat = entry.stat()
            except OSError:
                continue
            entries.append((stat.st_mtime, stat.st_size, entry))
            total += stat.st_size
        entries.sort()
        for _mtime, size, entry in entries:
            if total <= budget_bytes:
                break
            if _capture_path_identity(entry) in excluded:
                continue
            try:
                entry.unlink()
                entry.with_name(entry.name + ".pruned").unlink(missing_ok=True)
                removed.append(entry.name)
                total -= size
            except OSError:
                continue
    except OSError:
        pass
    return removed


def cleanup_orphan_scrollback(log_dir) -> list[str]:
    """Remove scrollback spools left by a broker process that no longer owns PTYs."""
    removed: list[str] = []
    try:
        log_dir = Path(log_dir)
        _secure_private_directory(log_dir)
        for entry in log_dir.glob("broker-*.log.scrollback.jsonl"):
            try:
                entry.unlink()
                removed.append(entry.name)
            except OSError:
                continue
    except OSError:
        pass
    return removed
_TERMINAL_SURFACE_V2_NONCE_SALT = os.urandom(16).hex()
BROKER_PROTOCOL_VERSION = 2
BROKER_CODE_VERSION = "pty-broker-v2"


def _read_broker_source_revision(runtime_root: Path | None) -> str | None:
    if runtime_root is None:
        return None
    candidates = [
        runtime_root / "manifest.json",
        runtime_root / "mac" / "SOURCE_REVISION",
        runtime_root / "SOURCE_REVISION",
    ]
    for path in candidates:
        try:
            if path.name == "manifest.json":
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


def _file_sha256(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return None


def ensure_pty_broker_token(companion_dir: Path) -> str:
    token_path = companion_dir / "pty-broker-token"
    try:
        _secure_private_directory(companion_dir)
        if token_path.exists():
            token = token_path.read_text(encoding="utf-8").strip()
            if re.fullmatch(r"[0-9a-f]{64}", token):
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
        # Fallback keeps the broker functional for test fixtures; production
        # launchd and the daemon both use the file-backed path.
        return secrets.token_hex(32)


def _sha256_prefixed(material: dict) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _parse_session_ref(session_id: str) -> tuple[str, str]:
    if ":" in session_id:
        provider, native_id = session_id.split(":", 1)
        return provider, native_id
    return "claude", session_id


def _terminal_surface_v2_cell_payload(cell) -> dict:
    payload = {"text": str(getattr(cell, "text", ""))}
    width = int(getattr(cell, "width", 1) or 1)
    fg = str(getattr(cell, "fg", "default") or "default")
    bg = str(getattr(cell, "bg", "default") or "default")
    bold = bool(getattr(cell, "bold", False))
    italic = bool(getattr(cell, "italic", False))
    underline = bool(getattr(cell, "underline", False))
    inverse = bool(getattr(cell, "inverse", False))
    link_id = getattr(cell, "link_id", None)
    if width != 1:
        payload["width"] = width
    if fg != "default":
        payload["fg"] = fg
    if bg != "default":
        payload["bg"] = bg
    if bold:
        payload["bold"] = True
    if italic:
        payload["italic"] = True
    if underline:
        payload["underline"] = True
    if inverse:
        payload["inverse"] = True
    if link_id is not None:
        payload["link_id"] = link_id
    return payload


def terminal_surface_v2_payload_from_state(
    session_id: str,
    state,
    scrollback_rows: list[list[dict]] | None = None,
    scrollback_total: int = 0,
    scrollback_retained_start: int = 0,
    window_start: int | None = None,
    input_epoch: int = 0,
) -> dict:
    provider, native_id = _parse_session_ref(session_id)
    row_payloads: list[dict] = []
    links_payload: dict[str, dict] = {}
    for link_id, link_value in (getattr(state, "links", None) or {}).items():
        if isinstance(link_value, dict):
            url = link_value.get("url")
            label = link_value.get("label")
        else:
            url = str(link_value)
            label = None
        links_payload[str(link_id)] = {
            "url": str(url) if url is not None else None,
            "label": str(label) if label is not None else None,
        }
    if scrollback_rows is not None and window_start is not None:
        # History window (SPEC-p4 §2.3): serve the requested slice with
        # ABSOLUTE indexes so the phone can stitch pages above the live view.
        for offset, history_cells in enumerate(scrollback_rows):
            cells = [dict(cell) for cell in history_cells]
            row_material = {
                "index": int(window_start) + offset,
                "wrapped": False,
                "cells": cells,
            }
            row_payloads.append({
                "index": row_material["index"],
                "wrapped": False,
                "dirty_generation": 0,
                "cells_hash": _sha256_prefixed(row_material),
                "cells": cells,
            })
    else:
        live_window_start = max(0, int(scrollback_total or 0))
        for row in getattr(state, "visible_rows", ()):
            cells = [_terminal_surface_v2_cell_payload(cell) for cell in getattr(row, "cells", ())]
            row_material = {
                "index": live_window_start + int(getattr(row, "index", 0)),
                "wrapped": bool(getattr(row, "wrapped", False)),
                "cells": cells,
            }
            row_payloads.append({
                "index": row_material["index"],
                "wrapped": row_material["wrapped"],
                "dirty_generation": int(getattr(row, "dirty_generation", 0) or 0),
                "cells_hash": _sha256_prefixed(row_material),
                "cells": cells,
            })
    cursor = getattr(state, "cursor", None)
    cursor_payload = {
        "row": getattr(cursor, "row", None),
        "column": getattr(cursor, "column", None),
        "visible": bool(getattr(cursor, "visible", True)),
        "style": str(getattr(cursor, "style", "block") or "block"),
    }
    dimensions = {
        "rows": int(getattr(state, "rows", 0) or 0),
        "columns": int(getattr(state, "columns", 0) or 0),
    }
    capabilities = list(getattr(state, "capabilities", ()) or ())
    history_total = max(0, int(scrollback_total or 0))
    retained_start = max(0, min(int(scrollback_retained_start or 0), history_total))
    if scrollback_rows is not None and window_start is not None:
        actual_window_start = max(retained_start, int(window_start))
        scrollback = {
            "window_start": actual_window_start,
            "window_size": len(row_payloads),
            "total_rows": history_total + len(getattr(state, "visible_rows", ()) or ()),
            "retained_start": retained_start,
            "has_more_before": actual_window_start > retained_start,
            "truncated_before": retained_start > 0,
        }
    else:
        # Live view: the visible screen sits AFTER the retained history, and
        # retained_start says whether any older rows were actually discarded.
        scrollback = {
            "window_start": history_total,
            "window_size": len(row_payloads),
            "total_rows": history_total + len(row_payloads),
            "retained_start": retained_start,
            "has_more_before": history_total > retained_start,
            "truncated_before": retained_start > 0,
        }
    pending_input = getattr(state, "pending_input", None)
    pending_input_detection = getattr(state, "pending_input_detection", None)
    if pending_input_detection is None:
        pending_input_detection = {
            "status": "unknown",
            "parser_version": None,
            "surface": "v2",
            "confidence": None,
            "reason": "detection_metadata_missing",
        }
    pending_input_state = "present" if isinstance(pending_input, dict) else (
        "none" if pending_input_detection.get("status") == "ran" else "unknown"
    )
    hash_material = {
        "schema_version": 2,
        "session_id": session_id,
        "provider": provider,
        "native_id": native_id,
        "source": getattr(state, "source", "broker_vt"),
        "backend": getattr(state, "backend", "pty_broker"),
        "capabilities": capabilities,
        "degraded_reason": getattr(state, "degraded_reason", None),
        "generation": int(getattr(state, "generation", 0) or 0),
        "raw_offset": int(getattr(state, "raw_offset", 0) or 0),
        "dimensions": dimensions,
        "title": getattr(state, "title", None),
        "alternate_screen": bool(getattr(state, "alternate_screen", False)),
        "cursor": cursor_payload,
        "scrollback": scrollback,
        "rows": row_payloads,
        "links": links_payload,
        "pending_input": pending_input,
        "pending_input_state": pending_input_state,
        "pending_input_detection": pending_input_detection,
    }
    screen_hash = _sha256_prefixed(hash_material)
    nonce = _sha256_prefixed({
        "screen_hash": screen_hash,
        "generation": hash_material["generation"],
        "raw_offset": hash_material["raw_offset"],
        # The rendered screen may not repaint immediately after local input.
        # Bind the proof to every PTY write so a previously observed prompt
        # cannot be answered twice while its pixels still look unchanged.
        "input_epoch": max(0, int(input_epoch or 0)),
        "server_salt": _TERMINAL_SURFACE_V2_NONCE_SALT,
    })
    return {
        **hash_material,
        "screen_hash": screen_hash,
        "nonce": nonce,
        "changed_at": time.time(),
        "event_limits": {
            "max_event_bytes": 64 * 1024,
            "truncated": False,
            "truncation_reason": None,
        },
    }


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


def _read_rpc_frame(conn: socket.socket) -> dict[str, Any]:
    header = _read_exact(conn, 4)
    length = struct.unpack(">I", header)[0]
    if length <= 0 or length > _RPC_MAX_FRAME_BYTES:
        raise ValueError("invalid RPC frame length")
    payload = _read_exact(conn, length)
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("RPC frame must be a JSON object")
    return value


def _write_rpc_frame(conn: socket.socket, payload: dict[str, Any]) -> None:
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(data) <= 0 or len(data) > _RPC_MAX_FRAME_BYTES:
        raise ValueError("broker RPC frame exceeds bounded transport limit")
    conn.sendall(struct.pack(">I", len(data)) + data)


class PTYWriteError(RuntimeError):
    """A PTY write failure with the exact committed byte count."""

    def __init__(self, message: str, *, bytes_written: int, total_bytes: int) -> None:
        super().__init__(message)
        self.bytes_written = max(0, int(bytes_written))
        self.total_bytes = max(0, int(total_bytes))


def _pty_write_failure_result(error: PTYWriteError) -> dict:
    partial = error.bytes_written > 0
    return {
        "ok": False,
        "reason": "pty_write_partial" if partial else "pty_write_failed",
        "error_code": "pty_write_partial" if partial else "pty_write_failed",
        "error": str(error)[:200],
        "status": 502,
        "pty_written": partial,
        "bytes_written": error.bytes_written,
        "bytes_expected": error.total_bytes,
        "write_outcome": "partial" if partial else "none",
        "outcome_indeterminate": partial,
    }


def _is_direct_slash_invocation_text(text: str) -> bool:
    if "\n" in text or not text.startswith("/") or text.startswith("//"):
        return False
    token = text.split(maxsplit=1)[0]
    if "/" in token[1:]:
        return False
    command = token[1:]
    if not command or command in _ABSOLUTE_PATH_ROOT_TOKENS:
        return False
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*(?::[A-Za-z][A-Za-z0-9_-]*)*", command))


def _pending_input(rows: list[str]) -> dict | None:
    return detect_terminal_pending_input(rows)


class VTScreen:
    SCROLLBACK_MEMORY_ROWS = 5000

    def __init__(
        self,
        rows: int = 30,
        columns: int = 120,
        *,
        scrollback_path: Path | None = None,
        scrollback_budget_bytes: int | None = None,
    ) -> None:
        self.rows = max(1, min(int(rows or 30), 200))
        self.columns = max(1, min(int(columns or 120), 500))
        self.grid = [self._blank_text_row() for _ in range(self.rows)]
        self.attrs = [self._blank_attr_row() for _ in range(self.rows)]
        self.wrapped = [False for _ in range(self.rows)]
        self.cursor_row = 0
        self.cursor_col = 0
        self.cursor_visible = True
        self._state = "normal"
        self._csi = ""
        self._osc = ""
        self._utf8_decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.title: str | None = None
        self.alternate_screen = False
        self.scroll_top = 0
        self.scroll_bottom = self.rows - 1
        self.current_attr = self._default_attr()
        self.current_link_id: str | None = None
        self._saved_cursor: dict | None = None
        self.links: dict[str, str] = {}
        self._primary_state: dict | None = None
        # SPEC-p4 §2.3: rows that scroll off the top of the PRIMARY screen are
        # real scrollback, retained bounded so the phone can page history.
        # Alt-screen output and scroll-region tricks never land here — a real
        # emulator's semantics.
        self._scrollback: deque = deque(maxlen=self.SCROLLBACK_MEMORY_ROWS)
        self._scrollback_count = 0
        self._scrollback_path = Path(scrollback_path) if scrollback_path is not None else None
        self._scrollback_budget_bytes = max(
            1024,
            int(scrollback_budget_bytes or SCROLLBACK_DISK_BUDGET_BYTES),
        )
        self._scrollback_index_stride_bytes = max(
            1024,
            min(SCROLLBACK_SPARSE_INDEX_BYTES, self._scrollback_budget_bytes // 4),
        )
        self._scrollback_disk_start = 0
        self._scrollback_sparse_offsets: list[tuple[int, int]] = []
        self._scrollback_fd: int | None = None
        self._scrollback_disk_complete = False
        if self._scrollback_path is not None:
            _secure_private_directory(self._scrollback_path.parent)
            _secure_private_file(self._scrollback_path)
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            self._scrollback_fd = os.open(self._scrollback_path, flags, 0o600)
            self._scrollback_disk_complete = True
        # Rows touched since the last consume_dirty(). Every mutation path
        # marks here; the replay conformance corpus proves completeness by
        # reconstructing screens from dirty rows alone.
        self._dirty: set[int] = set(range(self.rows))

    @staticmethod
    def _default_attr() -> dict:
        return {
            "fg": "default",
            "bg": "default",
            "bold": False,
            "italic": False,
            "underline": False,
            "inverse": False,
            "link_id": None,
        }

    def _blank_text_row(self) -> list[str]:
        return [" " for _ in range(self.columns)]

    def _blank_attr_row(self) -> list[dict]:
        return [self._default_attr().copy() for _ in range(self.columns)]

    def feed(self, data: bytes) -> None:
        # PTY reads split UTF-8 sequences at arbitrary byte boundaries; a
        # per-chunk decode turns the split character into replacement glyphs.
        # The incremental decoder buffers the partial tail until it completes.
        text = self._utf8_decoder.decode(data)
        for ch in text:
            self._feed_char(ch)

    def text_rows(self) -> list[str]:
        return ["".join(row).rstrip() for row in self.grid]

    def cell_rows(self) -> list[list[dict]]:
        rows: list[list[dict]] = []
        for row, attr_row in zip(self.grid, self.attrs):
            last = -1
            for idx, ch in enumerate(row):
                if ch not in {" ", ""}:
                    last = idx
            cells: list[dict] = []
            for idx in range(last + 1):
                ch = row[idx]
                if ch == "":
                    continue
                attr = attr_row[idx]
                cells.append({
                    "text": ch,
                    "width": max(1, self._char_width(ch)),
                    **attr,
                })
            rows.append(cells)
        return rows

    def snapshot(self, session_id: str, generation: int, source: str = "broker_vt") -> dict:
        rows = self.text_rows()
        dimensions = {"columns": self.columns, "rows": self.rows}
        cursor = {
            "row": self.cursor_row,
            "column": self.cursor_col,
            "visible": self.cursor_visible,
        }
        material = {
            "session_id": session_id,
            "source": source,
            "generation": generation,
            "dimensions": dimensions,
            "rows": rows,
            "cursor": cursor,
            "title": self.title,
        }
        screen_hash = hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()
        payload = {
            "session_id": session_id,
            "source": source,
            "screen_hash": screen_hash,
            "nonce": screen_hash,
            "generation": generation,
            "dimensions": dimensions,
            "rows": rows,
            "cursor": cursor,
            "title": self.title,
            "changed_at": time.time(),
        }
        pending = _pending_input(rows)
        if pending is not None:
            payload["pending_input"] = pending
        return payload

    def _touch(self, row: int) -> None:
        if 0 <= row < self.rows:
            self._dirty.add(row)

    def _touch_span(self, top: int, bottom: int) -> None:
        self._dirty.update(range(max(0, top), min(self.rows - 1, bottom) + 1))

    def _touch_all(self) -> None:
        self._dirty.update(range(self.rows))

    def consume_dirty(self) -> tuple[int, ...]:
        dirty = tuple(sorted(self._dirty))
        self._dirty.clear()
        return dirty

    def _feed_char(self, ch: str) -> None:
        if self._state == "osc":
            if ch == "\x07":
                self._handle_osc(self._osc)
                self._state = "normal"
            elif ch == "\x1b":
                self._state = "osc_esc"
            else:
                self._osc += ch
            return
        if self._state == "osc_esc":
            if ch == "\\":
                self._handle_osc(self._osc)
                self._state = "normal"
            else:
                self._osc += "\x1b" + ch
                self._state = "osc"
            return
        if self._state == "esc_intermediate":
            self._state = "normal"
            return
        if self._state == "esc":
            if ch == "[":
                self._state = "csi"
                self._csi = ""
            elif ch == "]":
                self._state = "osc"
                self._osc = ""
            elif ch == "c":
                self._reset()
                self._state = "normal"
            elif ch == "7":
                self._save_cursor()
                self._state = "normal"
            elif ch == "8":
                self._restore_cursor()
                self._state = "normal"
            elif ch == "D":
                self._linefeed()
                self._state = "normal"
            elif ch == "E":
                self.cursor_col = 0
                self._linefeed()
                self._state = "normal"
            elif ch == "M":
                self._reverse_index()
                self._state = "normal"
            elif ch in {"(", ")", "*", "+", "-", ".", "/", "#", "%"}:
                self._state = "esc_intermediate"
            else:
                self._state = "normal"
            return
        if self._state == "csi":
            if "@" <= ch <= "~":
                self._handle_csi(self._csi, ch)
                self._state = "normal"
                self._csi = ""
            else:
                self._csi += ch
            return

        if ch == "\x1b":
            self._state = "esc"
        elif ch == "\r":
            self.cursor_col = 0
        elif ch == "\n":
            self._linefeed()
        elif ch == "\b":
            self.cursor_col = max(0, self.cursor_col - 1)
        elif ch == "\t":
            next_tab = min(self.columns - 1, ((self.cursor_col // 8) + 1) * 8)
            while self.cursor_col < next_tab:
                self._put(" ")
        elif ch >= " ":
            self._put(ch)

    def _put(self, ch: str) -> None:
        width = self._char_width(ch)
        if width == 0:
            self._append_combining(ch)
            return
        if self.cursor_col >= self.columns or self.cursor_col + width > self.columns:
            self.wrapped[self.cursor_row] = True
            self.cursor_col = 0
            self._linefeed()
        attr = self.current_attr.copy()
        attr["link_id"] = self.current_link_id
        self.grid[self.cursor_row][self.cursor_col] = ch
        self.attrs[self.cursor_row][self.cursor_col] = attr
        if width == 2 and self.cursor_col + 1 < self.columns:
            self.grid[self.cursor_row][self.cursor_col + 1] = ""
            self.attrs[self.cursor_row][self.cursor_col + 1] = attr.copy()
        self._touch(self.cursor_row)
        self.cursor_col += width

    def _linefeed(self) -> None:
        if self.cursor_row >= self.scroll_bottom:
            self._scroll_up(self.scroll_top, self.scroll_bottom, 1)
            self.cursor_row = self.scroll_bottom
        else:
            self.cursor_row += 1

    def _handle_csi(self, params: str, final: str) -> None:
        private = params.startswith("?")
        clean = params[1:] if private else params
        parts = [p for p in clean.split(";") if p != ""]

        def value(index: int, default: int) -> int:
            try:
                return int(parts[index])
            except Exception:
                return default

        if final == "A":
            self.cursor_row = max(0, self.cursor_row - value(0, 1))
        elif final == "B":
            self.cursor_row = min(self.rows - 1, self.cursor_row + value(0, 1))
        elif final == "C":
            self.cursor_col = min(self.columns - 1, self.cursor_col + value(0, 1))
        elif final == "D":
            self.cursor_col = max(0, self.cursor_col - value(0, 1))
        elif final in {"G", "`"}:
            self.cursor_col = max(0, min(self.columns - 1, value(0, 1) - 1))
        elif final == "E":
            self.cursor_row = min(self.rows - 1, self.cursor_row + value(0, 1))
            self.cursor_col = 0
        elif final == "F":
            self.cursor_row = max(0, self.cursor_row - value(0, 1))
            self.cursor_col = 0
        elif final == "d":
            self.cursor_row = max(0, min(self.rows - 1, value(0, 1) - 1))
        elif final in {"H", "f"}:
            self.cursor_row = max(0, min(self.rows - 1, value(0, 1) - 1))
            self.cursor_col = max(0, min(self.columns - 1, value(1, 1) - 1))
        elif final == "J":
            mode = value(0, 0)
            if mode == 2:
                self.grid = [self._blank_text_row() for _ in range(self.rows)]
                self.attrs = [self._blank_attr_row() for _ in range(self.rows)]
                self.wrapped = [False for _ in range(self.rows)]
                self.cursor_row = 0
                self.cursor_col = 0
                self._touch_all()
            elif mode == 0:
                for c in range(self.cursor_col, self.columns):
                    self.grid[self.cursor_row][c] = " "
                    self.attrs[self.cursor_row][c] = self._default_attr().copy()
                for r in range(self.cursor_row + 1, self.rows):
                    self.grid[r] = self._blank_text_row()
                    self.attrs[r] = self._blank_attr_row()
                    self.wrapped[r] = False
                self._touch_span(self.cursor_row, self.rows - 1)
        elif final == "K":
            mode = value(0, 0)
            if mode == 2:
                self.grid[self.cursor_row] = self._blank_text_row()
                self.attrs[self.cursor_row] = self._blank_attr_row()
                self.wrapped[self.cursor_row] = False
                self._touch(self.cursor_row)
            elif mode == 1:
                for c in range(0, self.cursor_col + 1):
                    self.grid[self.cursor_row][c] = " "
                    self.attrs[self.cursor_row][c] = self._default_attr().copy()
                self._touch(self.cursor_row)
            else:
                for c in range(self.cursor_col, self.columns):
                    self.grid[self.cursor_row][c] = " "
                    self.attrs[self.cursor_row][c] = self._default_attr().copy()
                self._touch(self.cursor_row)
        elif final == "m":
            self._handle_sgr([int(p) if p.isdigit() else 0 for p in parts] or [0])
        elif final == "@":
            self._insert_characters(value(0, 1))
        elif final == "P":
            self._delete_characters(value(0, 1))
        elif final == "X":
            self._erase_characters(value(0, 1))
        elif final == "L":
            self._insert_lines(value(0, 1))
        elif final == "M":
            self._delete_lines(value(0, 1))
        elif final == "r":
            top = max(0, min(self.rows - 1, value(0, 1) - 1))
            bottom = max(top, min(self.rows - 1, value(1, self.rows) - 1))
            self.scroll_top = top
            self.scroll_bottom = bottom
            self.cursor_row = 0
            self.cursor_col = 0
        elif final == "S":
            self._scroll_up(self.scroll_top, self.scroll_bottom, value(0, 1))
        elif final == "T":
            self._scroll_down(self.scroll_top, self.scroll_bottom, value(0, 1))
        elif final in {"h", "l"} and private:
            modes = [value(i, 0) for i in range(len(parts) or 1)]
            enabled = final == "h"
            if 25 in modes:
                self.cursor_visible = enabled
            if any(mode in {47, 1047, 1049} for mode in modes):
                if enabled:
                    self._enter_alternate_screen()
                else:
                    self._exit_alternate_screen()
        elif final == "s" and not private and not clean:
            self._save_cursor()
        elif final == "u" and not private and not clean:
            self._restore_cursor()

    @staticmethod
    def _char_width(ch: str) -> int:
        if not ch:
            return 0
        if unicodedata.combining(ch):
            return 0
        if unicodedata.east_asian_width(ch) in {"W", "F"}:
            return 2
        return 1

    def _append_combining(self, ch: str) -> None:
        positions = [(self.cursor_row, self.cursor_col - 1)]
        if self.cursor_col == 0 and self.cursor_row > 0:
            positions.append((self.cursor_row - 1, self.columns - 1))
        for row, col in positions:
            if 0 <= row < self.rows and 0 <= col < self.columns and self.grid[row][col] not in {"", " "}:
                self.grid[row][col] = unicodedata.normalize("NFC", self.grid[row][col] + ch)
                self._touch(row)
                return

    def _handle_sgr(self, params: list[int]) -> None:
        i = 0
        while i < len(params):
            p = params[i]
            if p == 0:
                self.current_attr = self._default_attr()
            elif p == 1:
                self.current_attr["bold"] = True
            elif p == 3:
                self.current_attr["italic"] = True
            elif p == 4:
                self.current_attr["underline"] = True
            elif p == 7:
                self.current_attr["inverse"] = True
            elif p == 22:
                self.current_attr["bold"] = False
            elif p == 23:
                self.current_attr["italic"] = False
            elif p == 24:
                self.current_attr["underline"] = False
            elif p == 27:
                self.current_attr["inverse"] = False
            elif 30 <= p <= 37:
                self.current_attr["fg"] = f"ansi_{_ANSI_COLOR_NAMES[p - 30]}"
            elif 90 <= p <= 97:
                self.current_attr["fg"] = f"ansi_bright_{_ANSI_COLOR_NAMES[p - 90]}"
            elif p == 39:
                self.current_attr["fg"] = "default"
            elif 40 <= p <= 47:
                self.current_attr["bg"] = f"ansi_{_ANSI_COLOR_NAMES[p - 40]}"
            elif 100 <= p <= 107:
                self.current_attr["bg"] = f"ansi_bright_{_ANSI_COLOR_NAMES[p - 100]}"
            elif p == 49:
                self.current_attr["bg"] = "default"
            elif p in {38, 48} and i + 2 < len(params):
                target = "fg" if p == 38 else "bg"
                mode = params[i + 1]
                if mode == 5 and i + 2 < len(params):
                    self.current_attr[target] = f"ansi256_{params[i + 2]}"
                    i += 2
                elif mode == 2 and i + 4 < len(params):
                    self.current_attr[target] = f"rgb({params[i + 2]},{params[i + 3]},{params[i + 4]})"
                    i += 4
            i += 1

    def _insert_characters(self, count: int) -> None:
        count = max(1, min(count, self.columns - self.cursor_col))
        row = self.grid[self.cursor_row]
        attrs = self.attrs[self.cursor_row]
        for _ in range(count):
            row.insert(self.cursor_col, " ")
            attrs.insert(self.cursor_col, self._default_attr().copy())
            row.pop()
            attrs.pop()
        self._touch(self.cursor_row)

    def _delete_characters(self, count: int) -> None:
        count = max(1, min(count, self.columns - self.cursor_col))
        row = self.grid[self.cursor_row]
        attrs = self.attrs[self.cursor_row]
        for _ in range(count):
            row.pop(self.cursor_col)
            attrs.pop(self.cursor_col)
            row.append(" ")
            attrs.append(self._default_attr().copy())
        self._touch(self.cursor_row)

    def _erase_characters(self, count: int) -> None:
        count = max(1, min(count, self.columns - self.cursor_col))
        for col in range(self.cursor_col, self.cursor_col + count):
            self.grid[self.cursor_row][col] = " "
            self.attrs[self.cursor_row][col] = self._default_attr().copy()
        self._touch(self.cursor_row)

    def _save_cursor(self) -> None:
        self._saved_cursor = {
            "row": self.cursor_row,
            "column": self.cursor_col,
            "attr": self.current_attr.copy(),
            "link_id": self.current_link_id,
        }

    def _restore_cursor(self) -> None:
        if self._saved_cursor is None:
            return
        self.cursor_row = max(0, min(self.rows - 1, int(self._saved_cursor["row"])))
        self.cursor_col = max(0, min(self.columns - 1, int(self._saved_cursor["column"])))
        self.current_attr = dict(self._saved_cursor["attr"])
        self.current_link_id = self._saved_cursor["link_id"]

    def _reverse_index(self) -> None:
        if self.cursor_row <= self.scroll_top:
            self._scroll_down(self.scroll_top, self.scroll_bottom, 1)
            self.cursor_row = self.scroll_top
        else:
            self.cursor_row -= 1

    def _insert_lines(self, count: int) -> None:
        if not (self.scroll_top <= self.cursor_row <= self.scroll_bottom):
            return
        count = max(1, min(count, self.scroll_bottom - self.cursor_row + 1))
        for _ in range(count):
            self.grid.insert(self.cursor_row, self._blank_text_row())
            self.attrs.insert(self.cursor_row, self._blank_attr_row())
            self.wrapped.insert(self.cursor_row, False)
            del self.grid[self.scroll_bottom + 1]
            del self.attrs[self.scroll_bottom + 1]
            del self.wrapped[self.scroll_bottom + 1]
        self._touch_span(self.cursor_row, self.scroll_bottom)

    def _delete_lines(self, count: int) -> None:
        if not (self.scroll_top <= self.cursor_row <= self.scroll_bottom):
            return
        count = max(1, min(count, self.scroll_bottom - self.cursor_row + 1))
        for _ in range(count):
            del self.grid[self.cursor_row]
            del self.attrs[self.cursor_row]
            del self.wrapped[self.cursor_row]
            self.grid.insert(self.scroll_bottom, self._blank_text_row())
            self.attrs.insert(self.scroll_bottom, self._blank_attr_row())
            self.wrapped.insert(self.scroll_bottom, False)
        self._touch_span(self.cursor_row, self.scroll_bottom)

    def _scroll_up(self, top: int, bottom: int, count: int) -> None:
        for _ in range(max(1, count)):
            if top == 0 and not self.alternate_screen:
                self._append_scrollback(self._capture_cell_row(0))
            del self.grid[top]
            del self.attrs[top]
            del self.wrapped[top]
            self.grid.insert(bottom, self._blank_text_row())
            self.attrs.insert(bottom, self._blank_attr_row())
            self.wrapped.insert(bottom, False)
        self._touch_span(top, bottom)

    def _capture_cell_row(self, index: int) -> list[dict]:
        row = self.grid[index]
        attr_row = self.attrs[index]
        last = -1
        for idx, ch in enumerate(row):
            if ch not in {" ", ""}:
                last = idx
        cells: list[dict] = []
        for idx in range(last + 1):
            ch = row[idx]
            if ch == "":
                continue
            cells.append({
                "text": ch,
                "width": max(1, self._char_width(ch)),
                **attr_row[idx],
            })
        return cells

    def _append_scrollback(self, row: list[dict]) -> None:
        row_index = self._scrollback_count
        self._scrollback.append(row)
        self._scrollback_count += 1
        if self._scrollback_fd is None or not self._scrollback_disk_complete:
            return
        try:
            payload = json.dumps(
                row,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
            offset = os.lseek(self._scrollback_fd, 0, os.SEEK_END)
            if (
                not self._scrollback_sparse_offsets
                or offset - self._scrollback_sparse_offsets[-1][1]
                >= self._scrollback_index_stride_bytes
            ):
                self._scrollback_sparse_offsets.append((row_index, offset))
            written = 0
            while written < len(payload):
                count = os.write(self._scrollback_fd, payload[written:])
                if count <= 0:
                    raise OSError("scrollback write made no progress")
                written += count
            if offset + written > self._scrollback_budget_bytes:
                self._compact_scrollback_spool(offset + written)
        except OSError:
            self._scrollback_disk_complete = False
            self._scrollback_sparse_offsets.clear()
            self.close_scrollback()

    def _compact_scrollback_spool(self, file_size: int) -> None:
        if (
            self._scrollback_fd is None
            or self._scrollback_path is None
            or not self._scrollback_sparse_offsets
        ):
            return
        target_offset = max(1, file_size - (self._scrollback_budget_bytes // 2))
        retained_index, retained_offset = next(
            (
                (index, offset)
                for index, offset in self._scrollback_sparse_offsets
                if offset >= target_offset
            ),
            self._scrollback_sparse_offsets[-1],
        )
        if retained_index <= self._scrollback_disk_start:
            return

        os.fsync(self._scrollback_fd)
        tmp = self._scrollback_path.with_name(
            self._scrollback_path.name + f".tmp.{os.getpid()}"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        output_fd = os.open(tmp, flags, 0o600)
        try:
            with open(self._scrollback_path, "rb") as source, os.fdopen(output_fd, "wb") as output:
                output_fd = -1
                source.seek(retained_offset)
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            os.close(self._scrollback_fd)
            self._scrollback_fd = None
            tmp.replace(self._scrollback_path)
            _secure_private_file(self._scrollback_path)
            append_flags = os.O_WRONLY | os.O_APPEND
            if hasattr(os, "O_NOFOLLOW"):
                append_flags |= os.O_NOFOLLOW
            self._scrollback_fd = os.open(self._scrollback_path, append_flags)
            self._scrollback_disk_start = retained_index
            self._rebuild_scrollback_sparse_index()
        finally:
            if output_fd >= 0:
                os.close(output_fd)
            tmp.unlink(missing_ok=True)

    def _rebuild_scrollback_sparse_index(self) -> None:
        if self._scrollback_path is None:
            self._scrollback_sparse_offsets = []
            return
        offsets: list[tuple[int, int]] = []
        row_index = self._scrollback_disk_start
        with open(self._scrollback_path, "rb") as handle:
            while True:
                offset = handle.tell()
                line = handle.readline()
                if not line:
                    break
                if (
                    not offsets
                    or offset - offsets[-1][1] >= self._scrollback_index_stride_bytes
                ):
                    offsets.append((row_index, offset))
                row_index += 1
        self._scrollback_sparse_offsets = offsets

    @property
    def scrollback_total(self) -> int:
        return self._scrollback_count

    @property
    def scrollback_retained_start(self) -> int:
        if (
            self._scrollback_disk_complete
            and self._scrollback_path is not None
            and self._scrollback_fd is not None
        ):
            return self._scrollback_disk_start
        return max(0, self._scrollback_count - len(self._scrollback))

    def scrollback_window_start(self, start: int) -> int:
        return max(
            self.scrollback_retained_start,
            min(int(start or 0), self._scrollback_count),
        )

    def scrollback_window(self, start: int, size: int) -> list[list[dict]]:
        total = self._scrollback_count
        start = self.scrollback_window_start(start)
        size = max(0, min(int(size or 0), total - start))
        if size == 0:
            return []
        if (
            self._scrollback_disk_complete
            and self._scrollback_path is not None
            and self._scrollback_fd is not None
            and self._scrollback_sparse_offsets
        ):
            rows: list[list[dict]] = []
            checkpoint_index, checkpoint_offset = max(
                (
                    (index, offset)
                    for index, offset in self._scrollback_sparse_offsets
                    if index <= start
                ),
                key=lambda item: item[0],
            )
            with open(self._scrollback_path, "rb") as handle:
                handle.seek(checkpoint_offset)
                for _ in range(checkpoint_index, start):
                    if not handle.readline():
                        raise ValueError("scrollback row is missing")
                for _ in range(size):
                    line = handle.readline()
                    if not line:
                        raise ValueError("scrollback row is missing")
                    decoded = json.loads(line)
                    if not isinstance(decoded, list):
                        raise ValueError("scrollback row is not a list")
                    rows.append(decoded)
            return rows
        relative_start = start - self.scrollback_retained_start
        return [
            list(self._scrollback[index])
            for index in range(relative_start, relative_start + size)
        ]

    def close_scrollback(self, *, remove: bool = False) -> None:
        descriptor = self._scrollback_fd
        self._scrollback_fd = None
        if descriptor is not None:
            try:
                os.fsync(descriptor)
            except OSError:
                pass
            try:
                os.close(descriptor)
            except OSError:
                pass
        if remove and self._scrollback_path is not None:
            try:
                self._scrollback_path.unlink(missing_ok=True)
            except OSError:
                pass

    def _scroll_down(self, top: int, bottom: int, count: int) -> None:
        for _ in range(max(1, count)):
            del self.grid[bottom]
            del self.attrs[bottom]
            del self.wrapped[bottom]
            self.grid.insert(top, self._blank_text_row())
            self.attrs.insert(top, self._blank_attr_row())
            self.wrapped.insert(top, False)
        self._touch_span(top, bottom)

    def _handle_osc(self, payload: str) -> None:
        if payload.startswith(("0;", "2;")):
            self.title = payload.split(";", 1)[1]
        elif payload.startswith("8;"):
            parts = payload.split(";", 2)
            uri = parts[2] if len(parts) >= 3 else ""
            if uri:
                link_id = "link-" + hashlib.sha256(uri.encode("utf-8")).hexdigest()[:12]
                self.links[link_id] = uri
                self.current_link_id = link_id
            else:
                self.current_link_id = None

    def _reset(self) -> None:
        self.grid = [self._blank_text_row() for _ in range(self.rows)]
        self.attrs = [self._blank_attr_row() for _ in range(self.rows)]
        self.wrapped = [False for _ in range(self.rows)]
        self.cursor_row = 0
        self.cursor_col = 0
        self.cursor_visible = True
        self.scroll_top = 0
        self.scroll_bottom = self.rows - 1
        self.current_attr = self._default_attr()
        self.current_link_id = None
        self._touch_all()

    def _enter_alternate_screen(self) -> None:
        if self.alternate_screen:
            return
        self._primary_state = {
            "grid": [row[:] for row in self.grid],
            "attrs": [[cell.copy() for cell in row] for row in self.attrs],
            "wrapped": self.wrapped[:],
            "cursor_row": self.cursor_row,
            "cursor_col": self.cursor_col,
            "cursor_visible": self.cursor_visible,
        }
        self._reset()
        self.alternate_screen = True

    def _exit_alternate_screen(self) -> None:
        if not self.alternate_screen:
            return
        if self._primary_state:
            self.grid = [row[:] for row in self._primary_state["grid"]]
            self.attrs = [[cell.copy() for cell in row] for row in self._primary_state["attrs"]]
            self.wrapped = self._primary_state["wrapped"][:]
            self.cursor_row = self._primary_state["cursor_row"]
            self.cursor_col = self._primary_state["cursor_col"]
            self.cursor_visible = self._primary_state["cursor_visible"]
        self.alternate_screen = False
        self._primary_state = None
        self._touch_all()

    def resize(self, rows: int, columns: int) -> None:
        old_text = self.text_rows()
        self.rows = max(1, min(int(rows or self.rows), 200))
        self.columns = max(1, min(int(columns or self.columns), 500))
        self.grid = [self._blank_text_row() for _ in range(self.rows)]
        self.attrs = [self._blank_attr_row() for _ in range(self.rows)]
        self.wrapped = [False for _ in range(self.rows)]
        tail = old_text[-self.rows:]
        for idx, text in enumerate(tail):
            for col, ch in enumerate(text[:self.columns]):
                self.grid[idx][col] = ch
        self.cursor_row = min(self.cursor_row, self.rows - 1)
        self.cursor_col = min(self.cursor_col, self.columns - 1)
        self.scroll_top = 0
        self.scroll_bottom = self.rows - 1
        self._dirty = set(range(self.rows))


@dataclass
class PTYBrokerSession:
    session_id: str
    provider: str
    native_id: str
    project: str
    argv: list[str]
    env: dict[str, str]
    rows: int = 30
    columns: int = 120
    generation: int = 1
    raw_log_path: Path | None = None
    pid: int = 0
    slave_tty: str = ""
    started_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        scrollback_path = None
        if self.raw_log_path is not None:
            scrollback_path = self.raw_log_path.with_name(
                self.raw_log_path.name + ".scrollback.jsonl"
            )
        self.screen = VTScreen(
            rows=self.rows,
            columns=self.columns,
            scrollback_path=scrollback_path,
        )
        self.screen_backend = create_terminal_screen_backend(self.screen)
        self.master_fd = -1
        self.process: subprocess.Popen | None = None
        self.process_group_id = 0
        self._closed = False
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        # Guards the master_fd check-close-null so the two close sites (the
        # read loop's finally and the terminate/signal path) cannot both close
        # the same descriptor. Without it, one thread could close the fd and,
        # before nulling it, another thread reads it as still-open and closes
        # it a second time — closing an unrelated descriptor if the number was
        # already reused by a new open. A dedicated lock, not self._lock, so a
        # close never contends with the RLock the read/write paths hold.
        self._fd_lock = threading.Lock()
        self._raw = bytearray()
        self._raw_offset = 0
        # Changes on every PTY input, before the child has time to repaint.
        # Folding this into the snapshot nonce closes the local-Enter race
        # where the rendered approval still looks current for a few ms.
        self._input_epoch = 0
        self._type_mode_epoch = ""
        self._type_mode_device_id = ""
        self._type_mode_last_sequence = 0
        self._type_mode_receipts: dict[int, tuple[str, dict]] = {}
        self._feed_marks: deque[tuple[int, float]] = deque(maxlen=4096)
        self._reader_thread: threading.Thread | None = None
        self._reader_finished = threading.Event()
        self._capture_finalize_lock = threading.Lock()
        self._capture_finalized = False
        # Installed by the manager; invoked after each ingest so subscribers
        # learn about output at write time instead of polling raw_tail.
        self.on_output = None
        # Installed by the manager. A naturally-ended child must relinquish
        # every session id and TTY index just as an explicit terminate does.
        self.on_exit = None

    def start(self) -> None:
        master_fd, slave_fd = pty.openpty()
        self.master_fd = master_fd
        try:
            self.slave_tty = os.ttyname(slave_fd)
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", self.rows, self.columns, 0, 0))
            self.process = subprocess.Popen(
                self.argv,
                cwd=self.project,
                env=self.env,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                start_new_session=True,
                close_fds=True,
            )
            self.pid = int(self.process.pid)
            # start_new_session makes the child the leader of its own process
            # group. Keep that identity even after the leader exits so final
            # termination proof can also account for surviving descendants.
            self.process_group_id = self.pid
            os.set_blocking(self.master_fd, False)
            self._reader_thread = threading.Thread(
                target=self._read_loop,
                name=f"pairling-pty-{self.session_id}",
                daemon=True,
            )
            self._reader_thread.start()
        except BaseException:
            self.terminate(signal.SIGTERM)
            raise
        finally:
            try:
                os.close(slave_fd)
            except OSError:
                pass

    def is_alive(self) -> bool:
        return bool(self.process and self.process.poll() is None)

    def ownership_liveness(self) -> str:
        state, _error = self._process_group_liveness()
        return state

    def _close_master_fd(self) -> None:
        """Close the PTY master exactly once, atomically. The read loop's
        finally and the terminate/signal path both end a session and both must
        release the master; this serializes the check-close-null so they never
        close the same descriptor twice (which, after fd-number reuse, would
        close an unrelated open file)."""
        with self._fd_lock:
            fd = self.master_fd
            if fd < 0:
                return
            self.master_fd = -1
        try:
            os.close(fd)
        except OSError:
            pass

    def close(self) -> None:
        self.terminate(signal.SIGTERM)

    def _process_group_liveness(self) -> tuple[str, str | None]:
        """Return alive, gone, or unknown for the child and its process group."""
        child_state = "unknown"
        if self.process is None:
            child_state = "gone"
        else:
            try:
                child_state = "alive" if self.process.poll() is None else "gone"
            except Exception:
                child_state = "unknown"

        pgid = int(self.process_group_id or self.pid or 0)
        if pgid <= 0:
            return child_state, None
        try:
            os.killpg(pgid, 0)
            return "alive", None
        except ProcessLookupError:
            if child_state == "alive":
                return "unknown", "child is alive but its process group was not found"
            return "gone", None
        except PermissionError as exc:
            if child_state == "alive":
                return "alive", None
            return "unknown", f"{type(exc).__name__}: {exc}"
        except OSError as exc:
            if child_state == "alive":
                return "alive", None
            return "unknown", f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _signal_process_group(pgid: int, sig: int) -> tuple[bool, bool, str | None]:
        """Return sent, mutation-may-have-happened, and an error string."""
        try:
            os.killpg(pgid, sig)
            return True, True, None
        except ProcessLookupError:
            return False, False, None
        except PermissionError as exc:
            return False, False, f"{type(exc).__name__}: {exc}"
        except OSError as exc:
            # An interrupted or unusual kernel failure does not prove that the
            # group observed no signal. Reconcile before deciding finality.
            return False, True, f"{type(exc).__name__}: {exc}"

    def _finalize_capture(self) -> None:
        with self._capture_finalize_lock:
            if self._capture_finalized:
                return
            self._capture_finalized = True
        self.screen.close_scrollback(remove=True)
        dropped = truncate_capture_tail(
            self.raw_log_path,
            tail_bytes=CAPTURE_TAIL_BYTES,
        )
        if dropped:
            print(
                f"pairling pty broker pruned {dropped} bytes from "
                f"{getattr(self.raw_log_path, 'name', self.raw_log_path)}",
                file=sys.stderr,
                flush=True,
            )

    def _finalize_confirmed_termination(self) -> None:
        self._closed = True
        self._close_master_fd()
        with self._condition:
            self._condition.notify_all()
        if self._reader_thread is None:
            self._finalize_capture()
            self._reader_finished.set()
        else:
            # The read loop closes its log handle before it truncates the tail.
            # Waiting here keeps an explicit terminate response aligned with
            # that durable cleanup without ever truncating an open log.
            self._reader_finished.wait(timeout=1.0)

    def terminate(self, sig: int = signal.SIGTERM, wait_timeout: float = 2.0) -> dict:
        pgid = int(self.process_group_id or self.pid or 0)
        signal_name = signal.Signals(sig).name
        errors: list[str] = []
        mutation_may_have_happened = False
        signal_sent = False

        initial_state, initial_error = self._process_group_liveness()
        if initial_error:
            errors.append(initial_error)
        if initial_state != "gone" and pgid > 0:
            sent, mutation_possible, send_error = self._signal_process_group(pgid, sig)
            signal_sent = sent
            mutation_may_have_happened = mutation_possible
            if send_error:
                errors.append(send_error)

        if signal_sent and self.process is not None:
            try:
                self.process.wait(timeout=wait_timeout if sig == signal.SIGTERM else 1.0)
            except subprocess.TimeoutExpired:
                pass
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")

        state, state_error = self._process_group_liveness()
        if state_error:
            errors.append(state_error)

        # SIGTERM may reap the group immediately, or it may leave the leader or
        # a descendant alive. Escalate only while liveness is positively known.
        if sig == signal.SIGTERM and state == "alive" and pgid > 0:
            sent, mutation_possible, kill_error = self._signal_process_group(pgid, signal.SIGKILL)
            mutation_may_have_happened = mutation_may_have_happened or mutation_possible
            if kill_error:
                errors.append(kill_error)
            if sent and self.process is not None:
                try:
                    self.process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
                except Exception as exc:
                    errors.append(f"{type(exc).__name__}: {exc}")
            state, state_error = self._process_group_liveness()
            if state_error:
                errors.append(state_error)

        error = "; ".join(dict.fromkeys(errors)) or None
        if state == "gone":
            self._finalize_confirmed_termination()
            return {
                "ok": True,
                "applied": bool(mutation_may_have_happened),
                "termination_confirmed": True,
                "outcome_indeterminate": False,
                "mutation_may_have_happened": mutation_may_have_happened,
                "alive": False,
                "pid": self.pid,
                "process_group_id": pgid or None,
                "signal": signal_name,
                "error": error,
            }

        outcome_indeterminate = state == "unknown" or mutation_may_have_happened
        return {
            "ok": False,
            "applied": None if outcome_indeterminate else False,
            "termination_confirmed": False,
            "outcome_indeterminate": outcome_indeterminate,
            "mutation_may_have_happened": mutation_may_have_happened,
            "alive": True if state == "alive" else None,
            "pid": self.pid,
            "process_group_id": pgid or None,
            "signal": signal_name,
            "error": error or "process-group termination was not confirmed",
            "reason": "termination_outcome_unknown" if outcome_indeterminate else "termination_failed",
            "error_code": "termination_outcome_unknown" if outcome_indeterminate else "termination_failed",
            "status": 502,
        }

    def snapshot(self, public_session_id: str | None = None) -> dict:
        with self._lock:
            return self._snapshot_locked(public_session_id or self.session_id)

    def _snapshot_locked(self, public_session_id: str, *, generation: int | None = None) -> dict:
        snapshot = self.screen.snapshot(
            public_session_id,
            self.generation if generation is None else int(generation),
        )
        snapshot["nonce"] = hashlib.sha256(json.dumps({
            "screen_hash": snapshot.get("screen_hash"),
            "generation": snapshot.get("generation"),
            "input_epoch": self._input_epoch,
            "session_id": public_session_id,
        }, sort_keys=True).encode()).hexdigest()
        return snapshot

    def snapshot_v2(self):
        with self._lock:
            return self.screen_backend.snapshot()

    def snapshot_v2_bundle(
        self,
        window_start: int | None = None,
        window_size: int | None = None,
    ) -> tuple[Any, list[list[dict]] | None, int, int, int | None, int]:
        """Capture the screen, optional history, and input epoch atomically."""
        with self._lock:
            state = self.screen_backend.snapshot()
            rows = None
            actual_start = None
            if window_start is not None and window_size is not None:
                actual_start = self.screen.scrollback_window_start(int(window_start))
                rows = self.screen.scrollback_window(actual_start, int(window_size))
            return (
                state,
                rows,
                self.screen.scrollback_total,
                self.screen.scrollback_retained_start,
                actual_start,
                self._input_epoch,
            )

    def snapshot_pair(self, public_session_id: str | None = None) -> dict:
        """Capture v1 and v2 from one lock-held terminal generation."""
        public_session_id = public_session_id or self.session_id
        with self._lock:
            v2_state = self.screen_backend.snapshot()
            v1 = self._snapshot_locked(
                public_session_id,
                generation=v2_state.generation,
            )
            v2 = terminal_surface_v2_payload_from_state(
                public_session_id,
                v2_state,
                scrollback_total=self.screen.scrollback_total,
                scrollback_retained_start=self.screen.scrollback_retained_start,
                input_epoch=self._input_epoch,
            )
            # Keep the control proof in the broker's internal hash domain and
            # native generation, even when the public id happens to match it.
            internal_v1 = self._snapshot_locked(self.session_id)
            control_proof = {
                "session_id": self.session_id,
                "screen_hash": internal_v1.get("screen_hash"),
                "nonce": internal_v1.get("nonce"),
                "generation": internal_v1.get("generation"),
            }
            return {"v1": v1, "v2": v2, "control_proof": control_proof}

    def dirty_delta_v2(self, since_generation: int):
        with self._lock:
            return self.screen_backend.dirty_delta(since_generation=since_generation)

    def dirty_delta_v2_bundle(self, since_generation: int) -> tuple[Any, int, int, int]:
        with self._lock:
            return (
                self.screen_backend.dirty_delta(since_generation=since_generation),
                self.screen.scrollback_total,
                self.screen.scrollback_retained_start,
                self._input_epoch,
            )

    def scrollback_slice(self, window_start: int, window_size: int) -> tuple[list[list[dict]], int]:
        with self._lock:
            return (
                self.screen.scrollback_window(window_start, window_size),
                self.screen.scrollback_total,
            )

    def scrollback_total(self) -> int:
        with self._lock:
            return self.screen.scrollback_total

    def _ingest_output(self, data: bytes) -> None:
        arrived_at = time.time()
        with self._condition:
            self._raw_offset += len(data)
            self._raw.extend(data)
            if len(self._raw) > 2_000_000:
                del self._raw[:1_000_000]
            # (end offset, arrival time) marks let raw_tail report when the
            # oldest unserved byte actually arrived, which is the honest start
            # of the delivery-latency clock.
            self._feed_marks.append((self._raw_offset, arrived_at))
            self.screen_backend.feed(data, raw_offset=self._raw_offset)
            self.generation = self.screen_backend.generation
            self.last_activity = time.time()
            offset_after = self._raw_offset
            self._condition.notify_all()
        hook = self.on_output
        if hook is not None:
            try:
                hook(self.session_id, offset_after, arrived_at)
            except Exception:
                pass

    def raw_tail(self, since: int = 0) -> tuple[bytes, int, int, bool, int, float | None]:
        # Offsets are stream-absolute (total bytes ever produced), not
        # ring-relative: a ring trim must surface as an explicit gap for a
        # lagging consumer, never as a silent skip or a spurious reset.
        with self._lock:
            total = self._raw_offset
            earliest = total - len(self._raw)
            since_abs = max(0, int(since or 0))
            reset = since_abs > total
            if reset:
                start_abs = earliest
                gap = 0
            else:
                start_abs = max(since_abs, earliest)
                gap = start_abs - since_abs
            feed_at = None
            if start_abs < total:
                for end_offset, arrived_at in self._feed_marks:
                    if end_offset > start_abs:
                        feed_at = arrived_at
                        break
            return bytes(self._raw[start_abs - earliest:]), total, total, reset, gap, feed_at

    def _write_locked(self, data: bytes) -> int:
        if self.master_fd < 0:
            raise PTYWriteError(
                "session is not started",
                bytes_written=0,
                total_bytes=len(data),
            )
        self._input_epoch += 1
        # The master fd is non-blocking; a type-mode burst (or a paste) can
        # hit EAGAIN when the slave side is momentarily full. Apply bounded
        # backpressure instead of failing the keystroke: wait for
        # writability up to 1s total, then surface the error honestly.
        view = memoryview(data)
        total_written = 0
        deadline = time.time() + 1.0
        while view:
            try:
                written = os.write(self.master_fd, view)
                if written <= 0:
                    raise OSError("PTY write returned zero bytes")
                total_written += written
                view = view[written:]
            except BlockingIOError as exc:
                if time.time() >= deadline:
                    raise PTYWriteError(
                        f"{type(exc).__name__}: {exc}",
                        bytes_written=total_written,
                        total_bytes=len(data),
                    ) from exc
                try:
                    select.select([], [self.master_fd], [], 0.02)
                except Exception as select_exc:
                    raise PTYWriteError(
                        f"{type(select_exc).__name__}: {select_exc}",
                        bytes_written=total_written,
                        total_bytes=len(data),
                    ) from select_exc
            except PTYWriteError:
                raise
            except Exception as exc:
                raise PTYWriteError(
                    f"{type(exc).__name__}: {exc}",
                    bytes_written=total_written,
                    total_bytes=len(data),
                ) from exc
        self.last_activity = time.time()
        return total_written

    def write(self, data: bytes) -> None:
        # Serialize every PTY input with proofed controls. A local attached
        # terminal must not slip a key between a permission screen check and
        # Pairling's Enter/Escape write.
        with self._lock:
            self._write_locked(data)

    def _write_control_bytes(self, data: bytes, action: dict) -> dict:
        if action.get("require_screen_proof") is not True:
            return {
                "ok": False,
                "reason": "screen_proof_missing",
                "status": 409,
                "pty_written": False,
            }

        expected_hash = str(action.get("expected_screen_hash") or "")
        expected_nonce = str(action.get("expected_nonce") or "")
        raw_generation = action.get("expected_generation")
        if (
            not expected_hash
            or not expected_nonce
            or type(raw_generation) is not int
        ):
            return {
                "ok": False,
                "reason": "screen_proof_missing",
                "status": 409,
                "pty_written": False,
            }
        expected_generation = raw_generation

        with self._lock:
            current = self._snapshot_locked(self.session_id)
            if (
                str(current.get("screen_hash") or "") != expected_hash
                or str(current.get("nonce") or "") != expected_nonce
                or int(current.get("generation") or 0) != expected_generation
            ):
                return {
                    "ok": False,
                    "reason": "stale_screen",
                    "error_code": "stale_screen",
                    "status": 409,
                    "pty_written": False,
                    "screen_hash": current.get("screen_hash"),
                    "nonce": current.get("nonce"),
                    "generation": current.get("generation"),
                }
            try:
                bytes_written = self._write_locked(data)
            except PTYWriteError as exc:
                return _pty_write_failure_result(exc)
            return {
                "ok": True,
                "pty_written": True,
                "bytes_written": bytes_written,
                "bytes_expected": len(data),
                "write_outcome": "complete",
                "screen_proof_verified": True,
                "screen_hash": current.get("screen_hash"),
                "nonce": current.get("nonce"),
                "generation": current.get("generation"),
            }

    def interrupt(self) -> dict:
        """Interrupt an owned session after the daemon's identity gate.

        Interrupt intent is not tied to a rendered prompt. The authenticated
        session-signal path calls this only after it verifies broker ownership.
        """
        with self._lock:
            try:
                bytes_written = self._write_locked(b"\x03")
            except PTYWriteError as exc:
                return _pty_write_failure_result(exc)
            return {
                "ok": True,
                "pty_written": True,
                "bytes_written": bytes_written,
                "bytes_expected": 1,
                "write_outcome": "complete",
            }

    def control(self, action: dict) -> dict:
        kind = action.get("type")
        if kind == "input_mode_enter":
            epoch = str(action.get("input_epoch") or "").strip()
            device_id = str(action.get("device_id") or "").strip()
            if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", epoch):
                return {"ok": False, "reason": "bad_input_epoch"}
            if not device_id:
                return {"ok": False, "reason": "device_id_required"}
            with self._lock:
                if epoch == self._type_mode_epoch and device_id != self._type_mode_device_id:
                    return {"ok": False, "reason": "type_mode_identity_changed"}
                if epoch != self._type_mode_epoch:
                    self._type_mode_epoch = epoch
                    self._type_mode_device_id = device_id
                    self._type_mode_last_sequence = 0
                    self._type_mode_receipts.clear()
                return {
                    "ok": True,
                    "input_epoch": self._type_mode_epoch,
                    "next_sequence": self._type_mode_last_sequence + 1,
                    "generation": int(self.generation),
                }
        if kind == "input_mode_status":
            device_id = str(action.get("device_id") or "").strip()
            with self._lock:
                if not self._type_mode_epoch:
                    return {"ok": False, "reason": "type_mode_not_active"}
                if not device_id or device_id != self._type_mode_device_id:
                    return {"ok": False, "reason": "type_mode_identity_changed"}
                return {
                    "ok": True,
                    "input_epoch": self._type_mode_epoch,
                    "next_sequence": self._type_mode_last_sequence + 1,
                    "generation": int(self.generation),
                }
        if kind == "input_mode_exit":
            epoch = str(action.get("input_epoch") or "").strip()
            device_id = str(action.get("device_id") or "").strip()
            with self._lock:
                if (
                    epoch != self._type_mode_epoch
                    or not device_id
                    or device_id != self._type_mode_device_id
                ):
                    return {"ok": False, "reason": "type_mode_identity_changed"}
                self._type_mode_epoch = ""
                self._type_mode_device_id = ""
                self._type_mode_last_sequence = 0
                self._type_mode_receipts.clear()
                return {"ok": True}
        if kind == "key":
            key = action.get("key")
            mapping = {
                "enter": b"\r",
                "escape": b"\x1b",
                "up": b"\x1b[A",
                "down": b"\x1b[B",
                "left": b"\x1b[D",
                "right": b"\x1b[C",
                "tab": b"\t",
                "ctrl_c": b"\x03",
            }
            data = mapping.get(str(key))
            if data is None:
                return {"ok": False, "reason": "unsupported key"}
            return self._write_control_bytes(data, action)
        if kind == "choice":
            choice_id = str(action.get("choice_id") or "")
            if not re.match(r"^[A-Za-z0-9_.:-]{1,64}$", choice_id):
                return {"ok": False, "reason": "bad choice_id"}
            return self._write_control_bytes(choice_id.encode() + b"\r", action)
        if kind == "text":
            text = str(action.get("text") or "")
            if action.get("mode") != "submit" or "\n" in text:
                return {"ok": False, "reason": "unsupported text mode"}
            return self._write_control_bytes(text.encode() + b"\r", action)
        if kind == "input":
            # Type mode (SPEC-p4 §2.2): small raw byte chunks straight to the
            # PTY, no per-keystroke confirm. The generation guard lives HERE
            # because this session owns the per-frame generation counter. The
            # check is epoch-shaped: a client ahead of us saw a screen that
            # has since been reset/replaced (reject), and a client more than
            # 1000 frames behind is typing blind (reject). Both surface as
            # stale_generation for the daemon's receipt.
            try:
                data = base64.b64decode(str(action.get("b64") or ""), validate=True)
            except Exception:
                return {"ok": False, "reason": "bad_input_encoding"}
            if not data or len(data) > 1024:
                return {"ok": False, "reason": "input_size", "generation": int(self.generation)}
            expected = action.get("expected_generation")
            if not isinstance(expected, int) or isinstance(expected, bool):
                return {"ok": False, "reason": "bad_generation"}
            input_epoch = str(action.get("input_epoch") or "").strip()
            device_id = str(action.get("device_id") or "").strip()
            input_sequence = action.get("input_sequence")
            if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", input_epoch):
                return {"ok": False, "reason": "bad_input_epoch"}
            if (
                not isinstance(input_sequence, int)
                or isinstance(input_sequence, bool)
                or input_sequence < 1
            ):
                return {"ok": False, "reason": "bad_input_sequence"}
            input_hash = hashlib.sha256(data).hexdigest()
            # Decode first, then keep the generation decision and write inside
            # one lock. Output cannot replace the frame after validation but
            # before these bytes reach the PTY.
            with self._lock:
                current = int(self.generation)
                if (
                    input_epoch != self._type_mode_epoch
                    or not device_id
                    or device_id != self._type_mode_device_id
                ):
                    return {
                        "ok": False,
                        "reason": "input_epoch_changed",
                        "generation": current,
                        "next_sequence": self._type_mode_last_sequence + 1,
                    }
                cached = self._type_mode_receipts.get(input_sequence)
                if cached is not None:
                    cached_hash, cached_result = cached
                    if cached_hash != input_hash:
                        return {
                            "ok": False,
                            "reason": "input_sequence_conflict",
                            "generation": current,
                            "next_sequence": self._type_mode_last_sequence + 1,
                        }
                    replay = dict(cached_result)
                    replay["deduped"] = True
                    return replay
                if input_sequence <= self._type_mode_last_sequence:
                    return {
                        "ok": False,
                        "reason": "input_sequence_already_finished",
                        "generation": current,
                        "next_sequence": self._type_mode_last_sequence + 1,
                    }
                if input_sequence != self._type_mode_last_sequence + 1:
                    return {
                        "ok": False,
                        "reason": "input_sequence_gap",
                        "generation": current,
                        "next_sequence": self._type_mode_last_sequence + 1,
                    }
                if expected > current or (current - expected) > 1000:
                    result = {
                        "ok": False,
                        "reason": "stale_generation",
                        "generation": current,
                        "input_epoch": input_epoch,
                        "input_sequence": input_sequence,
                        "next_sequence": input_sequence + 1,
                    }
                    self._type_mode_last_sequence = input_sequence
                    self._type_mode_receipts[input_sequence] = (input_hash, result)
                    return result
                try:
                    bytes_written = self._write_locked(data)
                except PTYWriteError as exc:
                    result = _pty_write_failure_result(exc)
                    result["generation"] = int(self.generation)
                    result["input_epoch"] = input_epoch
                    result["input_sequence"] = input_sequence
                    result["next_sequence"] = input_sequence + 1
                    self._type_mode_last_sequence = input_sequence
                    self._type_mode_receipts[input_sequence] = (input_hash, result)
                    return result
                result = {
                    "ok": True,
                    "generation": int(self.generation),
                    "pty_written": True,
                    "bytes_written": bytes_written,
                    "bytes_expected": len(data),
                    "write_outcome": "complete",
                    "input_epoch": input_epoch,
                    "input_sequence": input_sequence,
                    "next_sequence": input_sequence + 1,
                }
                self._type_mode_last_sequence = input_sequence
                self._type_mode_receipts[input_sequence] = (input_hash, result)
                if len(self._type_mode_receipts) > 256:
                    cutoff = self._type_mode_last_sequence - 256
                    self._type_mode_receipts = {
                        sequence: receipt
                        for sequence, receipt in self._type_mode_receipts.items()
                        if sequence > cutoff
                    }
                return result
        return {"ok": False, "reason": "unsupported action"}

    def send_text(self, text: str) -> dict:
        text, err = sanitize_terminal_text_input(
            str(text or ""),
            allow_newline=True,
            max_chars=TERMINAL_TEXT_MAX_CHARS,
        )
        if err:
            return {"ok": False, "reason": err["code"], "message": err["message"], "status": err["status"]}
        is_slash = _is_direct_slash_invocation_text(text)
        if is_slash:
            data = text.encode() + b"\r"
        else:
            data = b"\x1b[200~" + text.encode() + b"\x1b[201~\r"
        with self._lock:
            try:
                bytes_written = self._write_locked(data)
            except PTYWriteError as exc:
                return _pty_write_failure_result(exc)
        return {
            "ok": True,
            "pty_written": True,
            "bytes_written": bytes_written,
            "bytes_expected": len(data),
            "write_outcome": "complete",
            "outcome_indeterminate": False,
        }

    def attach(self, conn: socket.socket) -> None:
        with self._lock:
            offset = max(0, len(self._raw) - 8192)
            initial = bytes(self._raw[offset:])
        if initial:
            conn.sendall(initial)

        stop = threading.Event()

        def pump_output() -> None:
            nonlocal offset
            while not stop.is_set():
                with self._condition:
                    self._condition.wait(timeout=0.5)
                    chunk = bytes(self._raw[offset:])
                    offset = len(self._raw)
                if chunk:
                    try:
                        conn.sendall(chunk)
                    except OSError:
                        stop.set()
                        return

        thread = threading.Thread(target=pump_output, daemon=True)
        thread.start()
        try:
            while not stop.is_set():
                data = conn.recv(4096)
                if not data:
                    break
                self.write(data)
        finally:
            stop.set()

    def _read_loop(self) -> None:
        log_f = None
        capture_tail_bytes = max(1, int(CAPTURE_TAIL_BYTES))
        try:
            if self.raw_log_path is not None:
                _secure_private_directory(self.raw_log_path.parent)
                log_f = _open_capture_append(self.raw_log_path)
            while not self._closed:
                if self.process and self.process.poll() is not None:
                    break
                try:
                    ready, _, _ = select.select([self.master_fd], [], [], 0.25)
                except OSError:
                    break
                if not ready:
                    continue
                try:
                    data = os.read(self.master_fd, 8192)
                except BlockingIOError:
                    continue
                except OSError:
                    break
                if not data:
                    break
                if log_f:
                    log_f.write(data)
                    log_f.flush()
                    log_f = _bound_live_capture(
                        log_f,
                        self.raw_log_path,
                        tail_bytes=capture_tail_bytes,
                    )
                self._ingest_output(data)
        finally:
            if log_f:
                log_f.close()
            # Tail retention must happen only after the append handle closes.
            # This one idempotent path covers both natural child exit and an
            # explicit confirmed terminate.
            self._finalize_capture()
            self._reader_finished.set()
            if self.process:
                try:
                    self.process.wait(timeout=0)
                except subprocess.TimeoutExpired:
                    pass
                except Exception:
                    pass
            # Close the PTY master here, not only in the signal path. A child
            # that exits on its own (a finished agent, a `sleep` that returns)
            # ends this loop at EOF; without this close the /dev/ptmx master
            # leaked one descriptor per naturally-ended session, which is the
            # workload-triggered FD leak that drove the daemon to EMFILE on
            # 2026-07-06/07. The close is serialized with the signal path via
            # _close_master_fd so the two sites cannot double-close.
            self._close_master_fd()
            self._closed = True
            with self._condition:
                self._condition.notify_all()
            hook = self.on_exit
            if hook is not None:
                try:
                    hook(self)
                except Exception:
                    pass


class PTYBrokerManager:
    def __init__(
        self,
        socket_path: Path,
        log_dir: Path,
        token: str | None = None,
        *,
        runtime_root: Path | None = None,
        script_path: Path | None = None,
        source_revision: str | None = None,
        started_at: float | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.log_dir = log_dir
        self.token = token or secrets.token_hex(32)
        self.script_path = Path(script_path or __file__).resolve(strict=False)
        self.runtime_root = (
            Path(runtime_root).resolve(strict=False)
            if runtime_root is not None
            else self.script_path.parent.parent
        )
        self.source_revision = source_revision if source_revision is not None else _read_broker_source_revision(self.runtime_root)
        self.started_at = float(started_at or time.time())
        try:
            script_stat = self.script_path.stat()
        except OSError:
            script_stat = None
        self.script_mtime = script_stat.st_mtime if script_stat is not None else None
        self.script_sha256 = _file_sha256(self.script_path)
        self.payload_sha256 = ptybroker_payload_sha256(self.runtime_root)
        self._sessions: dict[str, PTYBrokerSession] = {}
        self._reserved_session_ids: set[str] = set()
        self._active_capture_paths: set[str] = set()
        self._by_tty: dict[str, str] = {}
        self._lock = threading.RLock()
        self._server_started = False
        self._output_lock = threading.Lock()
        self._output_cond = threading.Condition(self._output_lock)
        self._output_subscribers: list[dict] = []

    # ----- output push: subscribers learn about PTY output at write time ---

    def notify_output(self, session_id: str, raw_offset: int, feed_at: float) -> None:
        with self._output_cond:
            for entry in self._output_subscribers:
                queue = entry["queue"]
                if len(queue) >= 4096:
                    queue.popleft()
                    entry["dropped"] += 1
                queue.append((session_id, raw_offset, feed_at))
            self._output_cond.notify_all()

    def _serve_output_subscriber(self, conn: socket.socket) -> None:
        entry = {"queue": deque(), "dropped": 0}
        with self._output_cond:
            self._output_subscribers.append(entry)
        try:
            _write_rpc_frame(conn, {"ok": True, "subscribed": True})
            while True:
                with self._output_cond:
                    if not entry["queue"] and not entry["dropped"]:
                        self._output_cond.wait(timeout=20.0)
                    items = list(entry["queue"])
                    entry["queue"].clear()
                    dropped = entry["dropped"]
                    entry["dropped"] = 0
                if dropped:
                    _write_rpc_frame(conn, {"event": "output_gap", "dropped": dropped})
                if not items:
                    # Heartbeat doubles as dead-peer detection: the write
                    # raises once the subscriber went away.
                    _write_rpc_frame(conn, {"event": "heartbeat"})
                    continue
                # Coalesce bursts per session; the consumer drains the full
                # range from its cursor, so only the latest offset matters.
                latest: dict[str, tuple[int, float]] = {}
                for session_id, raw_offset, feed_at in items:
                    known = latest.get(session_id)
                    if known is None or raw_offset > known[0]:
                        earliest_feed = known[1] if known is not None else feed_at
                        latest[session_id] = (raw_offset, min(feed_at, earliest_feed))
                for session_id, (raw_offset, feed_at) in latest.items():
                    _write_rpc_frame(conn, {
                        "event": "output",
                        "session_id": session_id,
                        "raw_offset": raw_offset,
                        "feed_at": feed_at,
                    })
        except OSError:
            pass
        finally:
            with self._output_cond:
                self._output_subscribers = [e for e in self._output_subscribers if e is not entry]
            try:
                conn.close()
            except OSError:
                pass

    def start_attach_server(self) -> None:
        with self._lock:
            if self._server_started:
                return
            _secure_private_directory(self.socket_path.parent)
            _secure_private_directory(self.log_dir)
            try:
                self.socket_path.unlink()
            except FileNotFoundError:
                pass
            thread = threading.Thread(target=self._serve_attach_socket, name="pairling-pty-attach", daemon=True)
            thread.start()
            self._server_started = True
        deadline = time.time() + 1.0
        while time.time() < deadline:
            if self.socket_path.exists():
                return
            time.sleep(0.01)

    def spawn(self, *, session_id: str, provider: str, native_id: str, project: str, command: str,
              rows: int = 30, columns: int = 120, env: dict[str, str] | None = None) -> PTYBrokerSession:
        self.start_attach_server()
        raw_log = self.log_dir / f"broker-{provider}-{native_id}.log"
        capture_identity = _capture_path_identity(raw_log)
        with self._lock:
            if not session_id:
                raise ValueError("broker session id is required")
            existing = self._sessions.get(session_id)
            if existing is not None and existing.ownership_liveness() == "gone":
                self._evict_session_locked(existing)
            if session_id in self._sessions or session_id in self._reserved_session_ids:
                raise ValueError(f"broker session id already exists: {session_id}")
            if capture_identity in self._active_capture_paths:
                raise ValueError(f"broker capture identity already exists: {raw_log.name}")
            self._reserved_session_ids.add(session_id)
            self._active_capture_paths.add(capture_identity)
            excluded_capture_paths = tuple(self._active_capture_paths)

        session: PTYBrokerSession | None = None
        try:
            safe_command = command
            argv = ["/bin/zsh", "-ic", safe_command]
            prune_capture_dir(
                self.log_dir,
                budget_bytes=CAPTURE_DIR_BUDGET_BYTES,
                excluded_paths=excluded_capture_paths,
            )
            merged_env = dict(os.environ)
            if env:
                merged_env.update(env)
            session = PTYBrokerSession(
                session_id=session_id,
                provider=provider,
                native_id=native_id,
                project=project,
                argv=argv,
                env=merged_env,
                rows=rows,
                columns=columns,
                raw_log_path=raw_log,
            )
            session.on_output = self.notify_output
            session.on_exit = self._session_exited
            session.start()
            with self._lock:
                self._reserved_session_ids.discard(session_id)
                if session_id in self._sessions:
                    raise RuntimeError(f"broker session ownership changed during spawn: {session_id}")
                # A short-lived command may finish before start() returns and
                # before the exit callback can find it in the manager. Do not
                # publish a dead owner in that race.
                if session.ownership_liveness() != "gone":
                    self._sessions[session_id] = session
                    if session.slave_tty:
                        self._by_tty[session.slave_tty] = session_id
            return session
        except BaseException:
            with self._lock:
                self._reserved_session_ids.discard(session_id)
                if session is None:
                    self._active_capture_paths.discard(capture_identity)
            if session is not None:
                session.terminate(sig=signal.SIGTERM)
                with self._lock:
                    if session._reader_finished.is_set():
                        self._active_capture_paths.discard(capture_identity)
            raise

    def descriptor(self, session: PTYBrokerSession) -> dict:
        liveness = session.ownership_liveness()
        return {
            "session_id": session.session_id,
            "provider": session.provider,
            "native_id": session.native_id,
            "project": session.project,
            "slave_tty": session.slave_tty,
            "pid": session.pid,
            "raw_log_path": str(session.raw_log_path) if session.raw_log_path else None,
            "generation": session.generation,
            "started_at": session.started_at,
            "alive": True if liveness == "alive" else (False if liveness == "gone" else None),
            "liveness": liveness,
        }

    def _evict_session_locked(self, session: PTYBrokerSession) -> None:
        for sid, existing in list(self._sessions.items()):
            if existing is session:
                self._sessions.pop(sid, None)
        for tty, sid in list(self._by_tty.items()):
            if self._sessions.get(sid) is None:
                self._by_tty.pop(tty, None)
        if session._reader_finished.is_set() and session.raw_log_path is not None:
            self._active_capture_paths.discard(
                _capture_path_identity(session.raw_log_path)
            )

    def _session_exited(self, session: PTYBrokerSession) -> None:
        with self._lock:
            if session.ownership_liveness() == "gone":
                self._evict_session_locked(session)

    def get(self, session_id: str) -> PTYBrokerSession | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is not None and session.ownership_liveness() == "gone":
                self._evict_session_locked(session)
                return None
            return session

    def get_by_tty(self, tty_path: str) -> PTYBrokerSession | None:
        with self._lock:
            sid = self._by_tty.get(tty_path)
            session = self._sessions.get(sid or "")
            if session is not None and session.ownership_liveness() == "gone":
                self._evict_session_locked(session)
                return None
            if session is None and sid is not None:
                self._by_tty.pop(tty_path, None)
            return session

    def register_alias(self, alias_session_id: str, session: PTYBrokerSession | str) -> None:
        if isinstance(session, str):
            resolved = self.get(session)
            if resolved is None:
                return
            session = resolved
        with self._lock:
            if not alias_session_id:
                raise ValueError("broker alias session id is required")
            existing = self._sessions.get(alias_session_id)
            if existing is not None and existing.ownership_liveness() == "gone":
                self._evict_session_locked(existing)
                existing = None
            if existing is not None and existing is not session:
                raise ValueError(f"broker alias session id already exists: {alias_session_id}")
            if alias_session_id in self._reserved_session_ids:
                raise ValueError(f"broker alias session id is being spawned: {alias_session_id}")
            self._sessions[alias_session_id] = session

    def list_sessions(self) -> list[dict]:
        out: list[dict] = []
        with self._lock:
            seen: set[int] = set()
            stale: list[PTYBrokerSession] = []
            for session in list(self._sessions.values()):
                ident = id(session)
                if ident in seen:
                    continue
                seen.add(ident)
                if session.ownership_liveness() != "gone":
                    out.append(self.descriptor(session))
                else:
                    stale.append(session)
            for session in stale:
                self._evict_session_locked(session)
        return out

    def live_sessions(self) -> list[dict]:
        return [
            {
                "broker_id": item["session_id"],
                "provider": item["provider"],
                "native_id": item["native_id"],
                "slave_tty": item["slave_tty"],
                "pid": item["pid"],
            }
            for item in self.list_sessions()
        ]

    def status(self) -> dict:
        with self._lock:
            live_sessions = self.list_sessions()
            inflight_spawn_count = len(self._reserved_session_ids)
            live_session_count = len(live_sessions)
        return {
            "schema_version": 1,
            "protocol_version": BROKER_PROTOCOL_VERSION,
            "code_version": BROKER_CODE_VERSION,
            "pid": os.getpid(),
            "started_at": self.started_at,
            "socket_path": str(self.socket_path),
            "runtime_root": str(self.runtime_root),
            "script_path": str(self.script_path),
            "script_mtime": self.script_mtime,
            "script_sha256": self.script_sha256,
            "payload_sha256": self.payload_sha256,
            "source_revision": self.source_revision,
            "live_session_count": live_session_count,
            "inflight_spawn_count": inflight_spawn_count,
            "restart_blocker_count": live_session_count + inflight_spawn_count,
        }

    def snapshot(self, session_id: str, public_session_id: str | None = None) -> dict | None:
        session = self.get(session_id)
        if not session:
            return None
        return session.snapshot(public_session_id=public_session_id or session_id)

    def snapshot_v2(
        self,
        session_id: str,
        public_session_id: str | None = None,
        window_start: int | None = None,
        window_size: int | None = None,
    ) -> dict | None:
        session = self.get(session_id)
        if not session:
            return None
        (
            state,
            history_rows,
            history_total,
            history_retained_start,
            actual_start,
            input_epoch,
        ) = session.snapshot_v2_bundle(
            window_start=window_start,
            window_size=window_size,
        )
        if window_start is not None and window_size is not None:
            assert actual_start is not None
            bounded_rows = list(history_rows or [])
            while True:
                surface = terminal_surface_v2_payload_from_state(
                    public_session_id or session_id,
                    state,
                    scrollback_rows=bounded_rows,
                    scrollback_total=history_total,
                    scrollback_retained_start=history_retained_start,
                    window_start=actual_start,
                    input_epoch=input_epoch,
                )
                encoded = json.dumps(
                    {"ok": True, "surface": surface},
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
                if len(encoded) <= _RPC_MAX_FRAME_BYTES or not bounded_rows:
                    return surface
                # Preserve the rows nearest the live surface. Reporting the
                # adjusted absolute start lets the next request continue
                # directly above this page without a gap.
                drop_count = max(1, len(bounded_rows) // 2)
                bounded_rows = bounded_rows[drop_count:]
                actual_start += drop_count
        return terminal_surface_v2_payload_from_state(
            public_session_id or session_id,
            state,
            scrollback_total=history_total,
            scrollback_retained_start=history_retained_start,
            input_epoch=input_epoch,
        )

    def snapshot_pair(
        self,
        session_id: str,
        public_session_id: str | None = None,
    ) -> dict | None:
        session = self.get(session_id)
        if not session:
            return None
        return session.snapshot_pair(public_session_id=public_session_id or session_id)

    def delta_v2(self, session_id: str, since_generation: int, public_session_id: str | None = None) -> dict | None:
        """A TerminalSurfaceV2Delta wire payload: only the rows changed after
        since_generation, on the exact contract the phone's applying(delta:)
        already implements. None when nothing changed."""
        session = self.get(session_id)
        if not session:
            return None
        state, history_total, history_retained_start, input_epoch = session.dirty_delta_v2_bundle(
            int(since_generation or 0)
        )
        if state is None:
            return None
        snapshot = terminal_surface_v2_payload_from_state(
            public_session_id or session_id,
            state,
            scrollback_total=history_total,
            scrollback_retained_start=history_retained_start,
            input_epoch=input_epoch,
        )
        dirty = set(state.dirty_row_indexes)
        # Dirty indexes are visible-row positions; the payload rows list is
        # in visible order, so filter by position and keep each row's own
        # index value for the phone's merge-by-index.
        dirty_rows = [
            row for offset, row in enumerate(snapshot["rows"])
            if offset in dirty
        ]
        return {
            "schema_version": snapshot["schema_version"],
            "event": "delta",
            "session_id": snapshot["session_id"],
            "generation": snapshot["generation"],
            "base_generation": int(since_generation or 0),
            "raw_offset": snapshot["raw_offset"],
            "screen_hash": snapshot["screen_hash"],
            "nonce": snapshot["nonce"],
            "dirty_rows": dirty_rows,
            "source": snapshot.get("source"),
            "backend": snapshot.get("backend"),
            "capabilities": snapshot.get("capabilities"),
            "degraded_reason": snapshot.get("degraded_reason"),
            "dimensions": snapshot.get("dimensions"),
            "cursor": snapshot.get("cursor"),
            "scrollback": snapshot.get("scrollback"),
            "links": snapshot.get("links"),
            "alternate_screen": snapshot.get("alternate_screen"),
            "title": snapshot.get("title"),
            "pending_input": snapshot.get("pending_input"),
            "pending_input_state": snapshot.get("pending_input_state"),
            "pending_input_detection": snapshot.get("pending_input_detection"),
            "event_limits": snapshot.get("event_limits"),
        }

    def control(self, session_id: str, action: dict) -> dict:
        session = self.get(session_id)
        if not session:
            return {"ok": False, "reason": "broker session not found", "status": 404}
        return session.control(action)

    def interrupt(self, session_id: str) -> dict:
        session = self.get(session_id)
        if not session:
            return {"ok": False, "reason": "broker session not found", "status": 404}
        return session.interrupt()

    def terminate(self, session_id: str, sig: int = signal.SIGTERM) -> dict:
        session = self.get(session_id)
        if not session:
            return {"ok": False, "reason": "broker session not found", "status": 404}
        result = session.terminate(sig=sig)
        if result.get("termination_confirmed") is True:
            with self._lock:
                self._evict_session_locked(session)
        return result

    def send_text(self, session_id: str, text: str) -> dict:
        session = self.get(session_id)
        if not session:
            return {"ok": False, "reason": "broker session not found", "status": 404}
        return session.send_text(text)

    def raw_tail(self, session_id: str, since: int = 0) -> tuple[bytes, int, int, bool, int, float | None] | None:
        session = self.get(session_id)
        if not session:
            return None
        return session.raw_tail(since=since)

    def _peer_uid_ok(self, conn: socket.socket) -> bool:
        try:
            if hasattr(os, "getpeereid"):
                uid, _gid = os.getpeereid(conn.fileno())
                return int(uid) == os.getuid()
            if hasattr(socket, "SO_PEERCRED"):
                data = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                _pid, uid, _gid = struct.unpack("3i", data)
                return int(uid) == os.getuid()
        except Exception:
            return False
        return True

    def _validate_token(self, value: object) -> bool:
        return isinstance(value, str) and secrets.compare_digest(value, self.token)

    def _serve_attach_socket(self) -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        server.listen(8)
        while True:
            conn, _ = server.accept()
            threading.Thread(target=self._handle_socket_client, args=(conn,), daemon=True).start()

    def _handle_socket_client(self, conn: socket.socket) -> None:
        try:
            first = conn.recv(1, socket.MSG_PEEK)
        except OSError:
            conn.close()
            return
        if first == b"{":
            self._handle_attach_client(conn)
        else:
            self._handle_rpc_client(conn)

    def _handle_rpc_client(self, conn: socket.socket) -> None:
        with conn:
            try:
                if not self._peer_uid_ok(conn):
                    _write_rpc_frame(conn, {"ok": False, "error": {"code": "unauthorized_peer", "message": "same-uid broker peer required"}})
                    return
                request = _read_rpc_frame(conn)
                if not self._validate_token(request.get("token")):
                    _write_rpc_frame(conn, {"ok": False, "error": {"code": "unauthorized", "message": "pty broker token required"}})
                    return
                if str(request.get("op") or "") == "subscribe_output":
                    # Long-lived push connection; the serve loop owns it now.
                    self._serve_output_subscriber(conn)
                    return
                response = self._dispatch_rpc(request)
            except Exception as exc:
                response = {"ok": False, "error": {"code": type(exc).__name__, "message": str(exc)[:300]}}
            try:
                _write_rpc_frame(conn, response)
            except ValueError:
                # Never silently close when a future payload exceeds the
                # bounded contract. Return a small typed error instead.
                try:
                    _write_rpc_frame(conn, {
                        "ok": False,
                        "error": {
                            "code": "rpc_response_too_large",
                            "message": "broker response exceeds bounded transport limit",
                        },
                    })
                except OSError:
                    return
            except OSError:
                # Read-only clients use a short deadline so a slow broker
                # cannot stall the session viewer. The request can finish
                # after that client has closed; this is a normal disconnect,
                # not an unhandled broker-thread failure.
                return

    def _dispatch_rpc(self, request: dict[str, Any]) -> dict[str, Any]:
        op = str(request.get("op") or "")
        if op == "spawn":
            session = self.spawn(
                session_id=str(request.get("session_id") or ""),
                provider=str(request.get("provider") or ""),
                native_id=str(request.get("native_id") or ""),
                project=str(request.get("project") or ""),
                command=str(request.get("command") or ""),
                rows=int(request.get("rows") or 30),
                columns=int(request.get("columns") or 120),
                env=request.get("env") if isinstance(request.get("env"), dict) else None,
            )
            return {"ok": True, "session": self.descriptor(session)}
        if op == "get":
            session = self.get(str(request.get("session_id") or ""))
            return {"ok": True, "session": self.descriptor(session) if session else None}
        if op == "get_by_tty":
            session = self.get_by_tty(str(request.get("tty") or ""))
            return {"ok": True, "session": self.descriptor(session) if session else None}
        if op == "register_alias":
            self.register_alias(str(request.get("alias") or ""), str(request.get("session_id") or ""))
            return {"ok": True}
        if op == "snapshot":
            return {"ok": True, "snapshot": self.snapshot(
                str(request.get("session_id") or ""),
                public_session_id=str(request.get("public_session_id") or "") or None,
            )}
        if op == "snapshot_v2":
            raw_window_start = request.get("window_start")
            raw_window_size = request.get("window_size")
            return {"ok": True, "surface": self.snapshot_v2(
                str(request.get("session_id") or ""),
                public_session_id=str(request.get("public_session_id") or "") or None,
                window_start=int(raw_window_start) if raw_window_start is not None else None,
                window_size=int(raw_window_size) if raw_window_size is not None else None,
            )}
        if op == "snapshot_pair":
            return {"ok": True, "pair": self.snapshot_pair(
                str(request.get("session_id") or ""),
                public_session_id=str(request.get("public_session_id") or "") or None,
            )}
        if op == "delta_v2":
            raw_since = request.get("since_generation")
            return {"ok": True, "delta": self.delta_v2(
                str(request.get("session_id") or ""),
                int(raw_since or 0),
                public_session_id=str(request.get("public_session_id") or "") or None,
            )}
        if op == "raw_tail":
            tail = self.raw_tail(str(request.get("session_id") or ""), since=int(request.get("since") or 0))
            if tail is None:
                return {"ok": True, "tail": None}
            data, next_offset, total, reset, gap_bytes, feed_at = tail
            return {
                "ok": True,
                "tail": {
                    "b64": base64.b64encode(data).decode("ascii"),
                    "next_offset": next_offset,
                    "total": total,
                    "reset": reset,
                    "gap_bytes": gap_bytes,
                    "feed_at": feed_at,
                },
            }
        if op == "control":
            return {"ok": True, "result": self.control(str(request.get("session_id") or ""), request.get("action") if isinstance(request.get("action"), dict) else {})}
        if op == "interrupt":
            return {"ok": True, "result": self.interrupt(str(request.get("session_id") or ""))}
        if op == "send_text":
            return {"ok": True, "result": self.send_text(str(request.get("session_id") or ""), str(request.get("text") or ""))}
        if op == "terminate":
            return {"ok": True, "result": self.terminate(str(request.get("session_id") or ""), sig=int(request.get("sig") or signal.SIGTERM))}
        if op == "list_sessions":
            return {"ok": True, "sessions": self.list_sessions()}
        if op == "status":
            return {"ok": True, "status": self.status()}
        return {"ok": False, "error": {"code": "unknown_op", "message": f"unknown broker op: {op}"}}

    def _handle_attach_client(self, conn: socket.socket) -> None:
        with conn:
            if not self._peer_uid_ok(conn):
                conn.sendall(b"pairling attach: same-uid broker peer required\n")
                return
            line = b""
            while not line.endswith(b"\n") and len(line) < 4096:
                chunk = conn.recv(1)
                if not chunk:
                    return
                line += chunk
            try:
                hello = json.loads(line.decode("utf-8"))
            except Exception:
                conn.sendall(b"pairling attach: bad hello\n")
                return
            if str(hello.get("op") or "attach") != "attach":
                conn.sendall(b"pairling attach: bad operation\n")
                return
            if not self._validate_token(hello.get("token")):
                conn.sendall(b"pairling attach: broker token required; update Pairling runtime and retry\n")
                return
            session_id = str(hello.get("session_id") or "").strip()
            session = self.get(session_id)
            if not session:
                conn.sendall(f"pairling attach: no broker session {shlex.quote(session_id)}\n".encode())
                return
            session.attach(conn)
