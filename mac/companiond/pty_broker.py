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
import struct
import subprocess
import sys
import termios
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from terminal_text_sanitizer import TERMINAL_TEXT_MAX_CHARS, sanitize_terminal_text_input
from terminal_screen_backend import create_terminal_screen_backend, detect_terminal_pending_input


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
_RPC_MAX_FRAME_BYTES = 8 * 1024 * 1024

# Capture retention (Wave A): recordings are the replay corpus and the
# forensic record, but they must not grow without bound or keep old
# sessions' bytes at rest forever. On session close each file truncates
# from the head to the tail cap, recording the dropped byte count in a
# .pruned sidecar so nothing vanishes silently; the directory prunes
# oldest-first to the budget at broker startup and on spawn.
CAPTURE_TAIL_BYTES = max(64 * 1024, int(os.environ.get("PAIRLING_CAPTURE_TAIL_BYTES", str(4 * 1024 * 1024))))
CAPTURE_DIR_BUDGET_BYTES = max(16 * 1024 * 1024, int(os.environ.get("PAIRLING_CAPTURE_DIR_BUDGET_BYTES", str(512 * 1024 * 1024))))


def truncate_capture_tail(path, tail_bytes: int = CAPTURE_TAIL_BYTES) -> int:
    """Keeps the newest tail_bytes of a recording, writes a .pruned sidecar
    naming the dropped byte count, and returns it. 0 means untouched."""
    try:
        if path is None:
            return 0
        path = Path(path)
        size = path.stat().st_size
        if size <= tail_bytes:
            return 0
        with open(path, "rb") as handle:
            handle.seek(size - tail_bytes)
            tail = handle.read()
        tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
        tmp.write_bytes(tail)
        tmp.replace(path)
        dropped = size - tail_bytes
        sidecar = path.with_name(path.name + ".pruned")
        sidecar.write_text(json.dumps({
            "dropped_bytes": dropped,
            "pruned_at": time.time(),
        }, sort_keys=True) + "\n", encoding="utf-8")
        return dropped
    except OSError:
        return 0


def prune_capture_dir(log_dir, budget_bytes: int = CAPTURE_DIR_BUDGET_BYTES) -> list[str]:
    """Removes oldest recordings (and their sidecars) until the directory
    fits the budget. Returns the removed file names, oldest first."""
    removed: list[str] = []
    try:
        log_dir = Path(log_dir)
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
_TERMINAL_SURFACE_V2_NONCE_SALT = os.urandom(16).hex()
BROKER_PROTOCOL_VERSION = 1
BROKER_CODE_VERSION = "pty-broker-v1"


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
        companion_dir.mkdir(parents=True, exist_ok=True)
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
    window_start: int | None = None,
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
        for row in getattr(state, "visible_rows", ()):
            cells = [_terminal_surface_v2_cell_payload(cell) for cell in getattr(row, "cells", ())]
            row_material = {
                "index": int(getattr(row, "index", 0)),
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
    if scrollback_rows is not None and window_start is not None:
        scrollback = {
            "window_start": int(window_start),
            "window_size": len(row_payloads),
            "total_rows": history_total + len(getattr(state, "visible_rows", ()) or ()),
            "truncated_before": int(window_start) > 0,
        }
    else:
        # Live view: the visible screen sits AFTER the retained history, and
        # truncated_before discloses that older rows exist to page back to.
        scrollback = {
            "window_start": history_total,
            "window_size": len(row_payloads),
            "total_rows": history_total + len(row_payloads),
            "truncated_before": history_total > 0,
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
    conn.sendall(struct.pack(">I", len(data)) + data)


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
    def __init__(self, rows: int = 30, columns: int = 120) -> None:
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
        self._scrollback: deque = deque(maxlen=5000)
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
                self._scrollback.append(self._capture_cell_row(0))
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

    @property
    def scrollback_total(self) -> int:
        return len(self._scrollback)

    def scrollback_window(self, start: int, size: int) -> list[list[dict]]:
        total = len(self._scrollback)
        start = max(0, min(int(start or 0), total))
        size = max(0, min(int(size or 0), total - start))
        if size == 0:
            return []
        return [list(self._scrollback[i]) for i in range(start, start + size)]

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
        self.screen = VTScreen(rows=self.rows, columns=self.columns)
        self.screen_backend = create_terminal_screen_backend(self.screen)
        self.master_fd = -1
        self.process: subprocess.Popen | None = None
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
        self._feed_marks: deque[tuple[int, float]] = deque(maxlen=4096)
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
            os.set_blocking(self.master_fd, False)
            threading.Thread(target=self._read_loop, name=f"pairling-pty-{self.session_id}", daemon=True).start()
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
        dropped = truncate_capture_tail(self.raw_log_path)
        if dropped:
            print(f"pairling pty broker pruned {dropped} bytes from {getattr(self.raw_log_path, 'name', self.raw_log_path)}", file=sys.stderr, flush=True)

    def terminate(self, sig: int = signal.SIGTERM, wait_timeout: float = 2.0) -> dict:
        self._closed = True
        ok = True
        error: str | None = None
        try:
            if self.process and self.process.poll() is None:
                try:
                    os.killpg(os.getpgid(self.process.pid), sig)
                except ProcessLookupError:
                    pass
                if sig == signal.SIGTERM:
                    try:
                        self.process.wait(timeout=wait_timeout)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        self.process.wait(timeout=1.0)
            elif self.process:
                self.process.poll()
        except Exception as exc:
            ok = False
            error = f"{type(exc).__name__}: {exc}"
        self._close_master_fd()
        with self._condition:
            self._condition.notify_all()
        return {"ok": ok, "pid": self.pid, "signal": signal.Signals(sig).name, "error": error}

    def snapshot(self, public_session_id: str | None = None) -> dict:
        with self._lock:
            return self._snapshot_locked(public_session_id or self.session_id)

    def _snapshot_locked(self, public_session_id: str) -> dict:
        snapshot = self.screen.snapshot(public_session_id, self.generation)
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

    def dirty_delta_v2(self, since_generation: int):
        with self._lock:
            return self.screen_backend.dirty_delta(since_generation=since_generation)

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

    def _write_locked(self, data: bytes) -> None:
        if self.master_fd < 0:
            raise RuntimeError("session is not started")
        self._input_epoch += 1
        # The master fd is non-blocking; a type-mode burst (or a paste) can
        # hit EAGAIN when the slave side is momentarily full. Apply bounded
        # backpressure instead of failing the keystroke: wait for
        # writability up to 1s total, then surface the error honestly.
        view = memoryview(data)
        deadline = time.time() + 1.0
        while view:
            try:
                written = os.write(self.master_fd, view)
                view = view[written:]
            except BlockingIOError:
                if time.time() >= deadline:
                    raise
                select.select([], [self.master_fd], [], 0.02)
        self.last_activity = time.time()

    def write(self, data: bytes) -> None:
        # Serialize every PTY input with proofed controls. A local attached
        # terminal must not slip a key between a permission screen check and
        # Pairling's Enter/Escape write.
        with self._lock:
            self._write_locked(data)

    def control(self, action: dict) -> dict:
        kind = action.get("type")
        if kind == "key":
            key = action.get("key")
            mapping = {
                "enter": b"\r",
                "escape": b"\x1b",
                "up": b"\x1b[A",
                "down": b"\x1b[B",
                "left": b"\x1b[D",
                "right": b"\x1b[C",
                "ctrl_c": b"\x03",
            }
            data = mapping.get(str(key))
            if data is None:
                return {"ok": False, "reason": "unsupported key"}
            if action.get("require_screen_proof") is True:
                expected_hash = str(action.get("expected_screen_hash") or "")
                expected_nonce = str(action.get("expected_nonce") or "")
                try:
                    expected_generation = int(action.get("expected_generation"))
                except (TypeError, ValueError):
                    return {"ok": False, "reason": "screen_proof_missing", "pty_written": False}
                if not expected_hash or not expected_nonce:
                    return {"ok": False, "reason": "screen_proof_missing", "pty_written": False}
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
                            "pty_written": False,
                            "screen_hash": current.get("screen_hash"),
                            "nonce": current.get("nonce"),
                            "generation": current.get("generation"),
                        }
                    self._write_locked(data)
                    return {
                        "ok": True,
                        "pty_written": True,
                        "screen_proof_verified": True,
                        "screen_hash": current.get("screen_hash"),
                        "nonce": current.get("nonce"),
                        "generation": current.get("generation"),
                    }
            self.write(data)
            return {"ok": True}
        if kind == "choice":
            choice_id = str(action.get("choice_id") or "")
            if not re.match(r"^[A-Za-z0-9_.:-]{1,64}$", choice_id):
                return {"ok": False, "reason": "bad choice_id"}
            self.write(choice_id.encode() + b"\r")
            return {"ok": True}
        if kind == "text":
            text = str(action.get("text") or "")
            if action.get("mode") != "submit" or "\n" in text:
                return {"ok": False, "reason": "unsupported text mode"}
            self.write(text.encode() + b"\r")
            return {"ok": True}
        if kind == "raw_key" and action.get("debug") is True:
            key_code = int(action.get("key_code") or 0)
            self.write(bytes([key_code]))
            return {"ok": True}
        if kind == "input":
            # Type mode (SPEC-p4 §2.2): small raw byte chunks straight to the
            # PTY, no per-keystroke confirm. The generation guard lives HERE
            # because this session owns the per-frame generation counter. The
            # check is epoch-shaped: a client ahead of us saw a screen that
            # has since been reset/replaced (reject), and a client more than
            # 1000 frames behind is typing blind (reject). Both surface as
            # stale_generation for the daemon's receipt.
            expected = action.get("expected_generation")
            if expected is not None:
                try:
                    expected = int(expected)
                except (TypeError, ValueError):
                    return {"ok": False, "reason": "bad_generation"}
                current = int(self.generation)
                if expected > current or (current - expected) > 1000:
                    return {"ok": False, "reason": "stale_generation", "generation": current}
            try:
                data = base64.b64decode(str(action.get("b64") or ""), validate=True)
            except Exception:
                return {"ok": False, "reason": "bad_input_encoding"}
            if not data or len(data) > 1024:
                return {"ok": False, "reason": "input_size"}
            self.write(data)
            return {"ok": True, "generation": int(self.generation)}
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
        self.write(data)
        return {"ok": True}

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
        try:
            if self.raw_log_path is not None:
                self.raw_log_path.parent.mkdir(parents=True, exist_ok=True)
                log_f = open(self.raw_log_path, "ab")
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
                self._ingest_output(data)
        finally:
            if log_f:
                log_f.close()
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
        self.script_path = Path(script_path or __file__).absolute()
        self.runtime_root = Path(runtime_root).absolute() if runtime_root is not None else self.script_path.parent.parent
        self.source_revision = source_revision if source_revision is not None else _read_broker_source_revision(self.runtime_root)
        self.started_at = float(started_at or time.time())
        self._sessions: dict[str, PTYBrokerSession] = {}
        self._reserved_session_ids: set[str] = set()
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
            self.socket_path.parent.mkdir(parents=True, exist_ok=True)
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
        with self._lock:
            if not session_id:
                raise ValueError("broker session id is required")
            existing = self._sessions.get(session_id)
            if existing is not None and not existing.is_alive():
                self._evict_session_locked(existing)
            if session_id in self._sessions or session_id in self._reserved_session_ids:
                raise ValueError(f"broker session id already exists: {session_id}")
            self._reserved_session_ids.add(session_id)

        session: PTYBrokerSession | None = None
        try:
            safe_command = command
            argv = ["/bin/zsh", "-ic", safe_command]
            prune_capture_dir(self.log_dir)
            raw_log = self.log_dir / f"broker-{provider}-{native_id}.log"
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
                if session.is_alive():
                    self._sessions[session_id] = session
                    if session.slave_tty:
                        self._by_tty[session.slave_tty] = session_id
            return session
        except BaseException:
            with self._lock:
                self._reserved_session_ids.discard(session_id)
            if session is not None:
                session.terminate(sig=signal.SIGTERM)
            raise

    def descriptor(self, session: PTYBrokerSession) -> dict:
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
            "alive": session.is_alive(),
        }

    def _evict_session_locked(self, session: PTYBrokerSession) -> None:
        for sid, existing in list(self._sessions.items()):
            if existing is session:
                self._sessions.pop(sid, None)
        for tty, sid in list(self._by_tty.items()):
            if self._sessions.get(sid) is None:
                self._by_tty.pop(tty, None)

    def _session_exited(self, session: PTYBrokerSession) -> None:
        with self._lock:
            self._evict_session_locked(session)

    def get(self, session_id: str) -> PTYBrokerSession | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is not None and not session.is_alive():
                self._evict_session_locked(session)
                return None
            return session

    def get_by_tty(self, tty_path: str) -> PTYBrokerSession | None:
        with self._lock:
            sid = self._by_tty.get(tty_path)
            session = self._sessions.get(sid or "")
            if session is not None and not session.is_alive():
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
            if existing is not None and not existing.is_alive():
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
                if session.is_alive():
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
        live_sessions = self.list_sessions()
        script_stat = None
        try:
            script_stat = self.script_path.stat()
        except OSError:
            pass
        return {
            "schema_version": 1,
            "protocol_version": BROKER_PROTOCOL_VERSION,
            "code_version": BROKER_CODE_VERSION,
            "pid": os.getpid(),
            "started_at": self.started_at,
            "socket_path": str(self.socket_path),
            "runtime_root": str(self.runtime_root),
            "script_path": str(self.script_path),
            "script_mtime": script_stat.st_mtime if script_stat is not None else None,
            "script_sha256": _file_sha256(self.script_path),
            "source_revision": self.source_revision,
            "live_session_count": len(live_sessions),
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
        if window_start is not None and window_size is not None:
            rows, total = session.scrollback_slice(int(window_start), int(window_size))
            return terminal_surface_v2_payload_from_state(
                public_session_id or session_id,
                session.snapshot_v2(),
                scrollback_rows=rows,
                scrollback_total=total,
                window_start=int(window_start),
            )
        return terminal_surface_v2_payload_from_state(
            public_session_id or session_id,
            session.snapshot_v2(),
            scrollback_total=session.scrollback_total(),
        )

    def delta_v2(self, session_id: str, since_generation: int, public_session_id: str | None = None) -> dict | None:
        """A TerminalSurfaceV2Delta wire payload: only the rows changed after
        since_generation, on the exact contract the phone's applying(delta:)
        already implements. None when nothing changed."""
        session = self.get(session_id)
        if not session:
            return None
        state = session.dirty_delta_v2(int(since_generation or 0))
        if state is None:
            return None
        snapshot = terminal_surface_v2_payload_from_state(
            public_session_id or session_id,
            state,
            scrollback_total=session.scrollback_total(),
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
            "cursor": snapshot.get("cursor"),
            "scrollback": snapshot.get("scrollback"),
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

    def terminate(self, session_id: str, sig: int = signal.SIGTERM) -> dict:
        session = self.get(session_id)
        if not session:
            return {"ok": False, "reason": "broker session not found", "status": 404}
        result = session.terminate(sig=sig)
        if sig in {signal.SIGTERM, signal.SIGKILL}:
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
