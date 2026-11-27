"""What a provider's own session files say about a session right now.

No hook is needed for any of it. Each provider appends to a JSONL transcript,
and its last few hundred kilobytes state the turn (thinking, tool, idle), the
tool in flight, what the agent said it is doing, and the model, effort and
title in use. Claude Code also keeps one small file per running process that
names the transcript and says busy, idle or waiting.
"""
from __future__ import annotations

import json
import os
import re
import stat
import unicodedata
import uuid
from datetime import datetime
from pathlib import Path

try:  # Codex states a command as JavaScript; the transcript parser reads it.
    from session_event_ingest import codex_exec_call as _codex_exec_call
except Exception:  # pragma: no cover - the parser is absent only in a broken install
    _codex_exec_call = None
try:  # What a question tool asks and why a request failed, in one shape for every provider.
    from session_event_log import agent_questions as _agent_questions, error_line
except Exception:  # pragma: no cover - absent only in a broken install
    _agent_questions = None

    def error_line(value) -> str:
        return "The turn stopped on an error."

TAIL_BYTES = 512 * 1024
# For a session met mid-turn, whose model and effort lie further back.
DEEP_TAIL_BYTES = 8 * 1024 * 1024
HEAD_BYTES = 256 * 1024
DETAIL_MAX_CHARS = 140
FIRST_PROMPT_MAX_CHARS = 200
_MAX_PROCESS_RECORD_BYTES = 64 * 1024
_MAX_CACHE_ENTRIES = 512
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

# (provider, path, window) -> ((device, inode, size, mtime_ns), facts)
_FACTS_CACHE: dict[tuple[str, str, int], tuple[tuple[int, int, int, int], dict]] = {}

_CLAUDE_TURN_END_REASONS = frozenset({
    "end_turn", "stop_sequence", "max_tokens", "refusal",
    "model_context_window_exceeded",
})
# A slash command typed at the keyboard is logged as a user entry in these
# wrappers. It starts no turn of its own: the answer it leads to, if any, does.
_CLAUDE_COMMAND_ENTRY = (
    "<command-name>", "<command-message>", "<local-command-", "<bash-input>",
    "<bash-stdout>", "<bash-stderr>",
)
_CODEX_CALL_TYPES = frozenset({
    "custom_tool_call", "function_call", "local_shell_call", "tool_search_call",
})
_CODEX_OUTPUT_TYPES = frozenset({
    "custom_tool_call_output", "function_call_output", "tool_search_output",
})
_PATCH_FILE = re.compile(r"^\*\*\* (?:Update|Add|Delete) File: (.+)$", re.MULTILINE)


def _epoch(value) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, OverflowError):
        return None


def _clean(value, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text[:limit] if text else None


def _title(value) -> str | None:
    """A title as text. An agent may lead its title with an icon from a
    terminal font's private range, which a phone draws as an empty box."""
    if not isinstance(value, str):
        return None
    return _clean(
        "".join(ch for ch in value if unicodedata.category(ch) != "Co"), 240
    )


def _first_line(value, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    for line in value.splitlines():
        line = line.strip()
        if line:
            return line[:limit]
    return None


def tool_detail(name, tool_input) -> str | None:
    """The short line a tool call is known by, as the phone's viewer words it:
    the agent's own stated intent, else the tool and the first line it runs."""
    if not isinstance(tool_input, dict):
        return None
    for key in ("i", "description", "intent"):
        stated = _first_line(tool_input.get(key), DETAIL_MAX_CHARS)
        if stated:
            return stated
    for key in ("command", "file_path", "pattern", "prompt", "path"):
        ran = _first_line(tool_input.get(key), DETAIL_MAX_CHARS)
        if ran:
            return f"{name}: {ran}"[:DETAIL_MAX_CHARS] if name else ran
    patch = tool_input.get("input")
    if isinstance(patch, str):
        named = _PATCH_FILE.search(patch)
        if named:
            return f"{name}: {named.group(1).strip()}"[:DETAIL_MAX_CHARS]
    return None


def _asked(name, tool_input) -> dict | None:
    """What a tool call puts to the person, when it asks: its first question
    to show, and every row of its form to answer by."""
    rows = _agent_questions(name, tool_input) if _agent_questions is not None else None
    first = next(
        (row for row in rows or [] if row["kind"] in ("single", "multiple", "text")), None
    )
    if first is None:
        return None
    return {
        "prompt": _clean(first.get("question"), DETAIL_MAX_CHARS)
        or tool_detail(name, tool_input),
        "kind": first["kind"],
        "rows": rows,
    }


def _read_window(path: Path, max_bytes: int, *, from_end: bool):
    """Complete lines of the first or last `max_bytes`, and the file's identity."""
    descriptor = -1
    try:
        descriptor = os.open(path, _OPEN_FLAGS)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            return None
        start = max(0, info.st_size - max_bytes) if from_end else 0
        data = os.pread(descriptor, min(info.st_size, max_bytes), start)
    except OSError:
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if start > 0:
        # The window opens mid-line: that line's start is unknown.
        _, newline, data = data.partition(b"\n")
        if not newline:
            data = b""
    # Bytes after the last newline are a line still being written.
    data = data[:data.rfind(b"\n") + 1]
    key = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    return data.splitlines(), key, info.st_mtime


def _entries(lines: list[bytes]):
    for raw in lines:
        try:
            entry = json.loads(raw)
        except ValueError:
            continue
        if isinstance(entry, dict):
            yield entry


class _Turn:
    """Folds transcript entries, oldest first, into the state of the turn."""

    def __init__(self) -> None:
        self.state: str | None = None
        self.detail: str | None = None
        self.last_update: float | None = None
        self.turn_started_at: float | None = None
        self.model: str | None = None
        self.effort: str | None = None
        self.title: str | None = None
        # Why the provider gave up on the turn, until something moves again.
        self.failed: str | None = None
        self._pending: dict[str, str | None] = {}
        self._asking: dict[str, dict] = {}
        # Calls a failed message made, whose results say nothing is running.
        self._abandoned: set[str] = set()

    def _touch(self, at: float | None) -> None:
        if at is not None:
            self.last_update = at

    def begin(self, at: float | None) -> None:
        self._pending.clear()
        self._asking.clear()
        self._abandoned.clear()
        self.state, self.detail, self.turn_started_at = "thinking", None, at
        self.failed = None
        self._touch(at)

    def call(self, call_id, name, detail: str | None, at: float | None,
             asked: dict | None = None) -> None:
        key = str(call_id or len(self._pending))
        self._pending[key] = _clean(name, 128)
        if asked:
            self._asking[key] = {**asked, "call_id": str(call_id or ""), "asked_at": at}
        self.state, self.failed = "tool", None
        if detail:
            self.detail = detail
        self._touch(at)

    def result(self, call_id, at: float | None) -> None:
        key = str(call_id or "")
        if key in self._abandoned:
            self._abandoned.discard(key)
            return
        self._pending.pop(key, None)
        self._asking.pop(key, None)
        self.state, self.failed = "tool" if self._pending else "thinking", None
        self._touch(at)

    def working(self, at: float | None) -> None:
        self.state, self.failed = "tool" if self._pending else "thinking", None
        self._touch(at)

    def end(self, at: float | None, *, marker: bool = False) -> None:
        """`marker` is the provider's own note that a turn is over. It follows
        a failure as it follows an answer, so it leaves the failure standing."""
        self._pending.clear()
        self._asking.clear()
        self.state, self.detail = "idle", None
        if not marker:
            self.failed = None
        self._touch(at)

    def fail(self, message, at: float | None, calls=()) -> None:
        """The provider gave up on the turn and said why. Nothing runs until
        its person or its own retry moves it."""
        self._pending.clear()
        self._asking.clear()
        self._abandoned = {str(call_id) for call_id in calls if call_id}
        self.state, self.detail = "idle", None
        self.failed = error_line(message)
        self._touch(at)

    def facts(self, fallback_update: float) -> dict:
        tool = next(reversed(self._pending.values()), None) if self._pending else None
        busy = self.state in ("thinking", "tool")
        return {
            "state": self.state,
            "tool": tool if self.state == "tool" else None,
            "detail": self.detail if busy else None,
            "last_update": self.last_update or fallback_update,
            "turn_started_at": self.turn_started_at if busy else None,
            "model": self.model,
            "effort": self.effort,
            "title": self.title,
            # The question an unanswered call has put to the person.
            "waiting_on": next(reversed(self._asking.values()), None),
            "failed": self.failed if self.state == "idle" else None,
        }


def _text_blocks(content) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "\n".join(
        block["text"] for block in content
        if isinstance(block, dict) and isinstance(block.get("text"), str)
    )


def _fold_claude(entries, turn: _Turn) -> None:
    custom_title = None
    for entry in entries:
        kind = entry.get("type")
        if kind == "ai-title":
            turn.title = _title(entry.get("aiTitle")) or turn.title
            continue
        if kind == "custom-title":
            custom_title = _title(entry.get("customTitle")) or custom_title
            continue
        if entry.get("isSidechain"):
            continue
        at = _epoch(entry.get("timestamp"))
        message = entry.get("message") if isinstance(entry.get("message"), dict) else {}
        content = message.get("content")
        if kind == "attachment":
            attachment = entry.get("attachment")
            identity = attachment.get("identity") if isinstance(attachment, dict) else None
            if turn.model is None and isinstance(identity, dict):
                turn.model = _clean(identity.get("modelId"), 120)
        elif kind == "user" and not entry.get("isMeta"):
            results = [
                block for block in content if isinstance(block, dict)
                and block.get("type") == "tool_result"
            ] if isinstance(content, list) else []
            text = _text_blocks(content).lstrip()
            if results:
                for block in results:
                    turn.result(block.get("tool_use_id"), at)
            elif text.startswith("[Request interrupted by user"):
                turn.end(at)
            elif not text.startswith(_CLAUDE_COMMAND_ENTRY):
                turn.begin(at)
        elif kind == "assistant":
            model = _clean(message.get("model"), 120)
            # Claude Code writes "<synthetic>" on a message it made up itself.
            if model and not model.startswith("<"):
                turn.model = model
            turn.effort = _clean(entry.get("effort"), 32) or turn.effort
            calls = [
                block for block in content if isinstance(block, dict)
                and block.get("type") == "tool_use"
            ] if isinstance(content, list) else []
            for block in calls:
                name, tool_input = block.get("name"), block.get("input")
                turn.call(block.get("id"), name, tool_detail(name, tool_input), at,
                          _asked(name, tool_input))
            if not calls:
                if entry.get("isApiErrorMessage"):
                    # Claude Code retried, gave up, and wrote why as its answer.
                    turn.fail(_text_blocks(content), at)
                elif message.get("stop_reason") in _CLAUDE_TURN_END_REASONS:
                    turn.end(at)
                else:
                    turn.working(at)
        elif kind == "system" and entry.get("subtype") == "turn_duration":
            turn.end(at, marker=True)
    # A title Claude wrote says what the session is about; a custom one is the
    # name it was started with, which for a phone spawn is the project's name.
    turn.title = turn.title or custom_title


def _codex_call_detail(payload: dict) -> str | None:
    name = payload.get("name")
    tool_input = payload.get("input")
    if tool_input is None:
        tool_input = payload.get("arguments")
    if isinstance(tool_input, str):
        if payload.get("type") == "custom_tool_call" and _codex_exec_call is not None:
            try:
                shown = _codex_exec_call(tool_input)
            except Exception:
                shown = None
            if shown:
                return tool_detail(shown[0], shown[1])
            return None
        try:
            tool_input = json.loads(tool_input)
        except ValueError:
            return None
    return tool_detail(name, tool_input)


def _fold_codex(entries, turn: _Turn) -> None:
    for entry in entries:
        payload = entry.get("payload")
        if not isinstance(payload, dict):
            continue
        kind, item = entry.get("type"), payload.get("type")
        at = _epoch(entry.get("timestamp"))
        if kind == "turn_context":
            turn.model = _clean(payload.get("model"), 120) or turn.model
            turn.effort = _clean(payload.get("effort"), 32) or turn.effort
        elif kind == "event_msg":
            if item == "task_started":
                turn.begin(_epoch(payload.get("started_at")) or at)
            elif item == "error":
                turn.fail(payload.get("message"), at)
            elif item in ("task_complete", "turn_aborted"):
                turn.end(at, marker=True)
        elif kind == "response_item":
            if item in _CODEX_CALL_TYPES:
                asked = None
                if payload.get("name") == "request_user_input":
                    try:
                        asked = _asked("request_user_input", json.loads(payload.get("arguments")))
                    except (TypeError, ValueError):
                        asked = None
                turn.call(
                    payload.get("call_id") or payload.get("id"),
                    payload.get("name") or item,
                    _codex_call_detail(payload),
                    at,
                    asked,
                )
            elif item in _CODEX_OUTPUT_TYPES:
                turn.result(payload.get("call_id") or payload.get("id"), at)
            elif item == "message" and payload.get("role") == "assistant":
                # An answer after an error: the turn went on.
                turn.failed = None


def _fold_omp(entries, turn: _Turn) -> None:
    for entry in entries:
        kind = entry.get("type")
        if kind == "model_change":
            turn.model = _clean(entry.get("model"), 256) or turn.model
            continue
        if kind == "thinking_level_change":
            turn.effort = _clean(entry.get("thinkingLevel"), 32) or turn.effort
            continue
        message = entry.get("message")
        if kind != "message" or not isinstance(message, dict):
            continue
        at = _epoch(entry.get("timestamp"))
        role = message.get("role")
        if role == "user":
            turn.begin(at)
        elif role == "toolResult":
            turn.result(message.get("toolCallId"), at)
        elif role == "assistant":
            content = message.get("content")
            calls = [
                block for block in content if isinstance(block, dict)
                and block.get("type") == "toolCall"
            ] if isinstance(content, list) else []
            if message.get("stopReason") == "error":
                # The calls of a message that failed are answered at once
                # with nothing run.
                turn.fail(message.get("errorMessage"), at,
                          calls=[block.get("id") for block in calls])
                continue
            for block in calls:
                name, tool_input = block.get("name"), block.get("arguments")
                turn.call(block.get("id"), name, tool_detail(name, tool_input), at,
                          _asked(name, tool_input))
            if not calls:
                turn.end(at)


_FOLDS = {"claude": _fold_claude, "codex": _fold_codex, "omp": _fold_omp}


def session_facts(provider: str, path, *, deep: bool = False) -> dict | None:
    """Turn state, tool, stated work, model, effort and title from the end of a
    transcript. A fact the window does not hold is None. None when the file is
    unreadable or the provider has no transcript reader."""
    fold = _FOLDS.get(provider)
    if fold is None or not path:
        return None
    window = DEEP_TAIL_BYTES if deep else TAIL_BYTES
    cache_key = (provider, str(path), window)
    cached = _FACTS_CACHE.get(cache_key)
    if cached is not None:
        try:
            info = os.stat(path)
        except OSError:
            return None
        if cached[0] == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            return dict(cached[1])
    read = _read_window(Path(path), window, from_end=True)
    if read is None:
        return None
    lines, file_key, modified_at = read
    turn = _Turn()
    fold(_entries(lines), turn)
    facts = turn.facts(modified_at)
    if len(_FACTS_CACHE) >= _MAX_CACHE_ENTRIES:
        _FACTS_CACHE.clear()
    _FACTS_CACHE[cache_key] = (file_key, facts)
    return dict(facts)


def omp_first_prompt(path) -> str | None:
    """First line of the first message the user sent in an OMP session."""
    read = _read_window(Path(path), HEAD_BYTES, from_end=False) if path else None
    if read is None:
        return None
    for entry in _entries(read[0]):
        message = entry.get("message")
        if entry.get("type") == "message" and isinstance(message, dict) \
                and message.get("role") == "user":
            line = _first_line(_text_blocks(message.get("content")), FIRST_PROMPT_MAX_CHARS)
            if line:
                return line
    return None

def omp_title(path) -> str | None:
    """The title at the head of an OMP session file. OMP rewrites that line in
    place once it has named the session, so it is read again on a change."""
    read = _read_window(Path(path), 8192, from_end=False) if path else None
    if read is None:
        return None
    for entry in _entries(read[0]):
        if entry.get("type") == "title":
            return _title(entry.get("title"))
    return None



def claude_process_record(pid: int, *, home: Path | None = None) -> dict | None:
    """Claude Code's own record of one running process: which transcript it is
    writing and whether it is busy, idle or waiting on the person.

    The file outlives a process that was killed, so the caller must match
    `process_started_at` (or `started_at`) against the live process."""
    pid = int(pid or 0)
    if pid <= 0:
        return None
    path = (home or Path.home()) / ".claude" / "sessions" / f"{pid}.json"
    descriptor = -1
    try:
        descriptor = os.open(path, _OPEN_FLAGS)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_PROCESS_RECORD_BYTES:
            return None
        record = json.loads(os.pread(descriptor, _MAX_PROCESS_RECORD_BYTES, 0))
    except (OSError, ValueError):
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(record, dict) or record.get("pid") != pid:
        return None
    try:
        session_id = str(uuid.UUID(str(record.get("sessionId") or "")))
    except ValueError:
        return None
    process_started_at = None
    try:
        # The format `ps -o lstart=` prints, in local time.
        process_started_at = datetime.strptime(
            str(record.get("procStart") or ""), "%a %b %d %H:%M:%S %Y"
        ).timestamp()
    except ValueError:
        pass

    def seconds(key: str) -> float | None:
        value = record.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
            return float(value) / 1000.0
        return None

    return {
        "pid": pid,
        "session_id": session_id,
        "cwd": _clean(record.get("cwd"), 4096),
        "process_started_at": process_started_at,
        "started_at": seconds("startedAt"),
        "status": _clean(record.get("status"), 32),
        "status_updated_at": seconds("statusUpdatedAt"),
        "waiting_for": _clean(record.get("waitingFor"), 120),
        "path": str(path),
    }
