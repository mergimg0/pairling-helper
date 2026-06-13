from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pty
import re
import select
import shlex
import signal
import socket
import struct
import subprocess
import termios
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

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
        self._state = "normal"
        self._csi = ""
        self._osc = ""
        self.title: str | None = None
        self.alternate_screen = False
        self.scroll_top = 0
        self.scroll_bottom = self.rows - 1
        self.current_attr = self._default_attr()
        self.current_link_id: str | None = None
        self.links: dict[str, str] = {}
        self._primary_state: dict | None = None

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
        text = data.decode("utf-8", errors="replace")
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
        cursor = {"row": self.cursor_row, "column": self.cursor_col, "visible": True}
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
            elif mode == 0:
                for c in range(self.cursor_col, self.columns):
                    self.grid[self.cursor_row][c] = " "
                    self.attrs[self.cursor_row][c] = self._default_attr().copy()
                for r in range(self.cursor_row + 1, self.rows):
                    self.grid[r] = self._blank_text_row()
                    self.attrs[r] = self._blank_attr_row()
                    self.wrapped[r] = False
        elif final == "K":
            mode = value(0, 0)
            if mode == 2:
                self.grid[self.cursor_row] = self._blank_text_row()
                self.attrs[self.cursor_row] = self._blank_attr_row()
                self.wrapped[self.cursor_row] = False
            elif mode == 1:
                for c in range(0, self.cursor_col + 1):
                    self.grid[self.cursor_row][c] = " "
                    self.attrs[self.cursor_row][c] = self._default_attr().copy()
            else:
                for c in range(self.cursor_col, self.columns):
                    self.grid[self.cursor_row][c] = " "
                    self.attrs[self.cursor_row][c] = self._default_attr().copy()
        elif final == "m":
            self._handle_sgr([int(p) if p.isdigit() else 0 for p in parts] or [0])
        elif final == "@":
            self._insert_characters(value(0, 1))
        elif final == "P":
            self._delete_characters(value(0, 1))
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
        elif final == "h" and private and 1049 in [value(i, 0) for i in range(len(parts) or 1)]:
            self._enter_alternate_screen()
        elif final == "l" and private and 1049 in [value(i, 0) for i in range(len(parts) or 1)]:
            self._exit_alternate_screen()

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

    def _delete_characters(self, count: int) -> None:
        count = max(1, min(count, self.columns - self.cursor_col))
        row = self.grid[self.cursor_row]
        attrs = self.attrs[self.cursor_row]
        for _ in range(count):
            row.pop(self.cursor_col)
            attrs.pop(self.cursor_col)
            row.append(" ")
            attrs.append(self._default_attr().copy())

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

    def _scroll_up(self, top: int, bottom: int, count: int) -> None:
        for _ in range(max(1, count)):
            del self.grid[top]
            del self.attrs[top]
            del self.wrapped[top]
            self.grid.insert(bottom, self._blank_text_row())
            self.attrs.insert(bottom, self._blank_attr_row())
            self.wrapped.insert(bottom, False)

    def _scroll_down(self, top: int, bottom: int, count: int) -> None:
        for _ in range(max(1, count)):
            del self.grid[bottom]
            del self.attrs[bottom]
            del self.wrapped[bottom]
            self.grid.insert(top, self._blank_text_row())
            self.attrs.insert(top, self._blank_attr_row())
            self.wrapped.insert(top, False)

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
        self.scroll_top = 0
        self.scroll_bottom = self.rows - 1
        self.current_attr = self._default_attr()
        self.current_link_id = None

    def _enter_alternate_screen(self) -> None:
        if self.alternate_screen:
            return
        self._primary_state = {
            "grid": [row[:] for row in self.grid],
            "attrs": [[cell.copy() for cell in row] for row in self.attrs],
            "wrapped": self.wrapped[:],
            "cursor_row": self.cursor_row,
            "cursor_col": self.cursor_col,
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
        self.alternate_screen = False
        self._primary_state = None

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
        self._raw = bytearray()
        self._raw_offset = 0

    def start(self) -> None:
        master_fd, slave_fd = pty.openpty()
        self.master_fd = master_fd
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
        os.close(slave_fd)
        os.set_blocking(self.master_fd, False)
        threading.Thread(target=self._read_loop, name=f"pairling-pty-{self.session_id}", daemon=True).start()

    def is_alive(self) -> bool:
        return bool(self.process and self.process.poll() is None)

    def close(self) -> None:
        self.terminate(signal.SIGTERM)

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
        try:
            if self.master_fd >= 0:
                os.close(self.master_fd)
                self.master_fd = -1
        except Exception:
            pass
        with self._condition:
            self._condition.notify_all()
        return {"ok": ok, "pid": self.pid, "signal": signal.Signals(sig).name, "error": error}

    def snapshot(self, public_session_id: str | None = None) -> dict:
        with self._lock:
            return self.screen.snapshot(public_session_id or self.session_id, self.generation)

    def snapshot_v2(self):
        with self._lock:
            return self.screen_backend.snapshot()

    def raw_tail(self, since: int = 0) -> tuple[bytes, int, int, bool]:
        with self._lock:
            total = len(self._raw)
            reset = since > total
            start = 0 if reset else max(0, since)
            return bytes(self._raw[start:]), total, total, reset

    def write(self, data: bytes) -> None:
        if self.master_fd < 0:
            raise RuntimeError("session is not started")
        os.write(self.master_fd, data)
        self.last_activity = time.time()

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
                with self._condition:
                    self._raw_offset += len(data)
                    self._raw.extend(data)
                    if len(self._raw) > 2_000_000:
                        del self._raw[:1_000_000]
                    self.screen_backend.feed(data, raw_offset=self._raw_offset)
                    self.generation = self.screen_backend.generation
                    self.last_activity = time.time()
                    self._condition.notify_all()
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
            self._closed = True
            with self._condition:
                self._condition.notify_all()


class PTYBrokerManager:
    def __init__(self, socket_path: Path, log_dir: Path) -> None:
        self.socket_path = socket_path
        self.log_dir = log_dir
        self._sessions: dict[str, PTYBrokerSession] = {}
        self._by_tty: dict[str, str] = {}
        self._lock = threading.RLock()
        self._server_started = False

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
        safe_command = command
        argv = ["/bin/zsh", "-ic", safe_command]
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
        session.start()
        with self._lock:
            self._sessions[session_id] = session
            if session.slave_tty:
                self._by_tty[session.slave_tty] = session_id
        return session

    def get(self, session_id: str) -> PTYBrokerSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    def get_by_tty(self, tty_path: str) -> PTYBrokerSession | None:
        with self._lock:
            sid = self._by_tty.get(tty_path)
            return self._sessions.get(sid or "")

    def register_alias(self, alias_session_id: str, session: PTYBrokerSession) -> None:
        with self._lock:
            self._sessions[alias_session_id] = session

    def snapshot(self, session_id: str, public_session_id: str | None = None) -> dict | None:
        session = self.get(session_id)
        if not session:
            return None
        return session.snapshot(public_session_id=public_session_id or session_id)

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
                for sid, existing in list(self._sessions.items()):
                    if existing is session:
                        self._sessions.pop(sid, None)
                for tty, sid in list(self._by_tty.items()):
                    if sid == session_id or self._sessions.get(sid) is None:
                        self._by_tty.pop(tty, None)
        return result

    def send_text(self, session_id: str, text: str) -> dict:
        session = self.get(session_id)
        if not session:
            return {"ok": False, "reason": "broker session not found", "status": 404}
        return session.send_text(text)

    def raw_tail(self, session_id: str, since: int = 0) -> tuple[bytes, int, int, bool] | None:
        session = self.get(session_id)
        if not session:
            return None
        return session.raw_tail(since=since)

    def _serve_attach_socket(self) -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        server.listen(8)
        while True:
            conn, _ = server.accept()
            threading.Thread(target=self._handle_attach_client, args=(conn,), daemon=True).start()

    def _handle_attach_client(self, conn: socket.socket) -> None:
        with conn:
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
            session_id = str(hello.get("session_id") or "").strip()
            session = self.get(session_id)
            if not session:
                conn.sendall(f"pairling attach: no broker session {shlex.quote(session_id)}\n".encode())
                return
            session.attach(conn)
