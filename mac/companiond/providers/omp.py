from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import registry_data
from .base import (
    ProviderAdapter,
    ProviderAvailability,
    ProviderDescriptor,
    ProviderDiagnostics,
    ProviderProbeResult,
    cli_version,
    resolve_executable,
)


_FALLBACK_DESCRIPTOR = ProviderDescriptor(
    provider_id="omp",
    display_name="OMP",
    kind="agent_platform",
    builtin=False,
    docs_url="https://omp.sh",
    adapter_depth="standard",
)
_ENTRY = registry_data.entry_or_none("omp")

_TERMINAL_RECORD_NAME = re.compile(r"ttys\d{3,}")
_MAX_TERMINAL_RECORD_BYTES = 8192
_MAX_SESSION_HEADER_BYTES = 65536
_SUPPORTED_SESSION_VERSIONS = {3}
_MAX_TERMINAL_RECORDS = 512
_MAX_SESSION_METADATA_LINE_BYTES = 65536
_MAX_SESSION_METADATA_CACHE_ENTRIES = 512
_SESSION_TURN_STATE_CHUNK_BYTES = 262144
_MAX_SESSION_TURN_STATE_SCAN_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class _SessionMetadataCacheEntry:
    device: int
    inode: int
    size: int
    modified_ns: int
    scanned_offset: int
    model: str | None
    effort: str | None


_SESSION_METADATA_CACHE: dict[str, _SessionMetadataCacheEntry] = {}
# Canonical path -> ((device, inode, size, mtime_ns), state or None).
_SESSION_TURN_STATE_CACHE: dict[str, tuple[tuple[int, int, int, int], dict | None]] = {}


@dataclass(frozen=True)
class OmpTerminalRecord:
    session_id: str
    project: str
    session_path: str
    terminal_tty: str
    title: str | None
    record_mtime: float
    fresh: bool
    @property
    def native_id(self) -> str:
        return self.session_id


@dataclass(frozen=True)
class OmpSavedSession:
    session_id: str
    project: str
    session_path: str
    title: str | None
    modified_at: float

    @property
    def native_id(self) -> str:
        return self.session_id


def _canonical_existing_path(path: Path) -> Path | None:
    try:
        return path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        return None


def _session_header(path: Path) -> tuple[str, str, str | None] | None:
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return None
        title = None
        consumed = 0
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            for _ in range(64):
                remaining = _MAX_SESSION_HEADER_BYTES - consumed
                if remaining <= 0:
                    return None
                raw_line = handle.readline(remaining + 1)
                if not raw_line or len(raw_line) > remaining:
                    return None
                consumed += len(raw_line)
                line = raw_line.decode("utf-8")
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    return None
                if not isinstance(payload, dict):
                    return None
                if payload.get("type") == "title":
                    value = payload.get("title")
                    if isinstance(value, str) and value.strip():
                        title = value.strip()[:240]
                    continue
                if payload.get("type") != "session":
                    continue
                if payload.get("version") not in _SUPPORTED_SESSION_VERSIONS:
                    return None
                raw_id = payload.get("id")
                raw_cwd = payload.get("cwd")
                if not isinstance(raw_id, str) or not isinstance(raw_cwd, str):
                    return None
                try:
                    session_id = str(uuid.UUID(raw_id))
                except ValueError:
                    return None
                return session_id, raw_cwd, title
    except (OSError, UnicodeError):
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return None

def session_runtime_metadata(path: Path) -> dict[str, str | None]:
    """Read the latest explicit model and effort from an append-only OMP JSONL."""
    canonical_path = _canonical_existing_path(path)
    if canonical_path is None:
        return {"model": None, "effort": None}

    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(canonical_path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return {"model": None, "effort": None}

        cache_key = str(canonical_path)
        cached = _SESSION_METADATA_CACHE.get(cache_key)
        can_resume = (
            cached is not None
            and cached.device == metadata.st_dev
            and cached.inode == metadata.st_ino
            and metadata.st_size >= cached.size
            and (
                metadata.st_size > cached.size
                or metadata.st_mtime_ns == cached.modified_ns
            )
        )
        if can_resume and cached is not None and metadata.st_size == cached.size:
            return {"model": cached.model, "effort": cached.effort}

        scan_offset = cached.scanned_offset if can_resume and cached is not None else 0
        model = cached.model if can_resume and cached is not None else None
        effort = cached.effort if can_resume and cached is not None else None
        os.lseek(descriptor, scan_offset, os.SEEK_SET)

        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            while True:
                line_start = handle.tell()
                raw_line = handle.readline(_MAX_SESSION_METADATA_LINE_BYTES + 1)
                if not raw_line:
                    break
                if not raw_line.endswith(b"\n"):
                    if len(raw_line) <= _MAX_SESSION_METADATA_LINE_BYTES:
                        handle.seek(line_start)
                        break
                    while raw_line and not raw_line.endswith(b"\n"):
                        raw_line = handle.readline(_MAX_SESSION_METADATA_LINE_BYTES + 1)
                    scan_offset = handle.tell()
                    continue

                scan_offset = handle.tell()
                if len(raw_line) > _MAX_SESSION_METADATA_LINE_BYTES:
                    continue
                if (
                    b'"type":"model_change"' not in raw_line
                    and b'"type": "model_change"' not in raw_line
                    and b'"type":"thinking_level_change"' not in raw_line
                    and b'"type": "thinking_level_change"' not in raw_line
                ):
                    continue
                try:
                    payload = json.loads(raw_line)
                except (json.JSONDecodeError, UnicodeError):
                    continue
                if not isinstance(payload, dict):
                    continue
                if payload.get("type") == "model_change":
                    value = payload.get("model")
                    if isinstance(value, str) and value.strip():
                        model = value.strip()[:256]
                elif payload.get("type") == "thinking_level_change":
                    value = payload.get("thinkingLevel")
                    if isinstance(value, str) and value.strip():
                        effort = value.strip()[:32]

        if len(_SESSION_METADATA_CACHE) >= _MAX_SESSION_METADATA_CACHE_ENTRIES:
            _SESSION_METADATA_CACHE.clear()
        _SESSION_METADATA_CACHE[cache_key] = _SessionMetadataCacheEntry(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            size=metadata.st_size,
            modified_ns=metadata.st_mtime_ns,
            scanned_offset=scan_offset,
            model=model,
            effort=effort,
        )
        return {"model": model, "effort": effort}
    except OSError:
        return {"model": None, "effort": None}
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _message_turn_state(raw_line: bytes) -> dict | None:
    """Turn state stated by one JSONL line; None when it is not a message entry."""
    if b'"type":"message"' not in raw_line and b'"type": "message"' not in raw_line:
        return None
    try:
        entry = json.loads(raw_line)
    except ValueError:
        return None
    if not isinstance(entry, dict) or entry.get("type") != "message":
        return None
    message = entry.get("message")
    if not isinstance(message, dict):
        return None
    role = message.get("role")
    tool = None
    if role in ("user", "toolResult"):
        state = "thinking"
    elif role != "assistant":
        return None
    elif message.get("stopReason") == "toolUse":
        state = "tool"
        content = message.get("content")
        for block in reversed(content if isinstance(content, list) else []):
            if isinstance(block, dict) and block.get("type") == "toolCall":
                name = block.get("name")
                if isinstance(name, str) and name.strip():
                    tool = name.strip()[:128]
                break
    else:
        state = "idle"
    last_update = None
    timestamp = entry.get("timestamp")
    if isinstance(timestamp, str):
        try:
            last_update = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            ).timestamp()
        except (ValueError, OverflowError):
            last_update = None
    return {"state": state, "tool": tool, "last_update": last_update}


def _last_message_turn_state(descriptor: int, size: int) -> dict | None:
    """Scan complete lines backwards from the end, up to the scan cap."""
    floor = max(0, size - _MAX_SESSION_TURN_STATE_SCAN_BYTES)
    position = size
    # `tail` is the start-unknown line that ends where the scanned region begins.
    # Bytes after the file's last newline are a line still being written.
    tail = b""
    tail_terminated = False
    while position > floor:
        start = max(floor, position - _SESSION_TURN_STATE_CHUNK_BYTES)
        chunk = os.pread(descriptor, position - start, start)
        if len(chunk) != position - start:
            return None
        position = start
        head, newline, rest = chunk.partition(b"\n")
        if not newline:
            tail = chunk + tail
            continue
        lines = rest.split(b"\n")
        lines[-1] += tail
        if not tail_terminated:
            lines.pop()
        for line in reversed(lines):
            state = _message_turn_state(line)
            if state is not None:
                return state
        tail, tail_terminated = head, True
    if floor == 0 and tail_terminated:
        return _message_turn_state(tail)
    return None


def session_turn_state(path: Path) -> dict | None:
    """Read the turn state from the last message of an append-only OMP JSONL.

    `tool` while the assistant waits on tool calls, `thinking` after a user
    message or tool result, `idle` once the assistant stopped. None when the
    file is unreadable or no message lies within the scan cap.
    """
    canonical_path = _canonical_existing_path(path)
    if canonical_path is None:
        return None

    cache_key = str(canonical_path)
    descriptor = -1
    try:
        metadata = os.lstat(canonical_path)
        if not stat.S_ISREG(metadata.st_mode):
            return None
        cached = _SESSION_TURN_STATE_CACHE.get(cache_key)
        if cached is not None and cached[0] == (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        ):
            return dict(cached[1]) if cached[1] is not None else None

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(canonical_path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return None
        state = _last_message_turn_state(descriptor, metadata.st_size)
        if state is not None and state["last_update"] is None:
            state["last_update"] = metadata.st_mtime

        if len(_SESSION_TURN_STATE_CACHE) >= _MAX_SESSION_METADATA_CACHE_ENTRIES:
            _SESSION_TURN_STATE_CACHE.clear()
        _SESSION_TURN_STATE_CACHE[cache_key] = (
            (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
            ),
            state,
        )
        return dict(state) if state is not None else None
    except OSError:
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_terminal_record(path: Path, *, home: Path | None = None) -> OmpTerminalRecord | None:
    home = home or Path.home()
    if not _TERMINAL_RECORD_NAME.fullmatch(path.name):
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_TERMINAL_RECORD_BYTES:
            return None
        chunks: list[bytes] = []
        remaining = _MAX_TERMINAL_RECORD_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_TERMINAL_RECORD_BYTES:
            return None
        lines = raw.decode("utf-8").splitlines()
        record_mtime = metadata.st_mtime
    except (OSError, UnicodeError):
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(lines) < 2 or not all(line.strip() for line in lines[:2]):
        return None
    # After the two paths OMP may add `fresh` and, in newer releases, its own
    # stamp of the working directory as `cwdstat <dev> <ino>`. The stamp is not
    # compared: the device number changes across restarts, and the path, header
    # and process checks already bind the record. Any other line is a format
    # this reader does not know, so the record is refused.
    fresh = False
    stamped = False
    for annotation in lines[2:]:
        fields = annotation.split()
        if annotation.strip().lower() == "fresh" and not fresh:
            fresh = True
        elif (
            not stamped
            and len(fields) == 3
            and fields[0] == "cwdstat"
            and fields[1].isdigit()
            and fields[2].isdigit()
        ):
            stamped = True
        else:
            return None

    project = _canonical_existing_path(Path(lines[0]))
    session_path = _canonical_existing_path(Path(lines[1]))
    agent_sessions_root = _canonical_existing_path(
        home / ".omp" / "agent" / "sessions"
    )
    security_root = _canonical_existing_path(home / ".omp" / "security")
    in_agent_sessions = (
        agent_sessions_root is not None
        and session_path is not None
        and session_path.is_relative_to(agent_sessions_root)
    )
    in_security_sessions = (
        security_root is not None
        and session_path is not None
        and session_path.parent.name == "sessions"
        and session_path.parent.parent.parent == security_root
    )
    if (
        project is None
        or not project.is_dir()
        or session_path is None
        or not session_path.is_file()
        or not (in_agent_sessions or in_security_sessions)
    ):
        return None

    header = _session_header(session_path)
    if header is None:
        return None
    session_id, header_cwd, title = header
    header_project = _canonical_existing_path(Path(header_cwd))
    if header_project is None or header_project != project:
        return None
    return OmpTerminalRecord(
        session_id=session_id,
        project=str(project),
        session_path=str(session_path),
        terminal_tty=f"/dev/{path.name}",
        title=title,
        record_mtime=record_mtime,
        fresh=fresh,
    )


def terminal_session_records(*, home: Path | None = None) -> list[OmpTerminalRecord]:
    home = home or Path.home()
    records_dir = home / ".omp" / "agent" / "terminal-sessions"
    try:
        paths: list[Path] = []
        with os.scandir(records_dir) as entries:
            for examined_count, entry in enumerate(entries):
                if examined_count >= _MAX_TERMINAL_RECORDS:
                    break
                if not _TERMINAL_RECORD_NAME.fullmatch(entry.name):
                    continue
                try:
                    if not entry.is_file(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                paths.append(Path(entry.path))
        paths.sort(key=lambda item: item.name)
    except OSError:
        return []
    return [
        record
        for path in paths
        if (record := read_terminal_record(path, home=home)) is not None
    ]


def saved_sessions(
    *,
    home: Path | None = None,
    project: str | None = None,
    limit: int = 80,
) -> list[OmpSavedSession]:
    """Discover bounded, resumable OMP sessions from the canonical user store."""
    home = home or Path.home()
    sessions_root = _canonical_existing_path(home / ".omp" / "agent" / "sessions")
    if sessions_root is None or not sessions_root.is_dir():
        return []
    canonical_project = _canonical_existing_path(Path(project)) if project else None
    if project and (canonical_project is None or not canonical_project.is_dir()):
        return []
    result_limit = max(1, min(int(limit), 200))
    candidates: list[OmpSavedSession] = []
    examined_directories = 0
    examined_files = 0
    try:
        with os.scandir(sessions_root) as directories:
            for directory in directories:
                if examined_directories >= _MAX_TERMINAL_RECORDS:
                    break
                examined_directories += 1
                try:
                    if not directory.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                try:
                    with os.scandir(directory.path) as files:
                        for entry in files:
                            if examined_files >= 4096:
                                break
                            examined_files += 1
                            if not entry.name.endswith(".jsonl"):
                                continue
                            try:
                                if not entry.is_file(follow_symlinks=False):
                                    continue
                                metadata = entry.stat(follow_symlinks=False)
                            except OSError:
                                continue
                            session_path = Path(entry.path)
                            header = _session_header(session_path)
                            if header is None:
                                continue
                            session_id, raw_cwd, title = header
                            header_project = _canonical_existing_path(Path(raw_cwd))
                            if (
                                header_project is None
                                or not header_project.is_dir()
                                or (canonical_project is not None and header_project != canonical_project)
                            ):
                                continue
                            resolved_session = _canonical_existing_path(session_path)
                            if (
                                resolved_session is None
                                or not resolved_session.is_relative_to(sessions_root)
                            ):
                                continue
                            candidates.append(OmpSavedSession(
                                session_id=session_id,
                                project=str(header_project),
                                session_path=str(resolved_session),
                                title=title,
                                modified_at=metadata.st_mtime,
                            ))
                except OSError:
                    continue
                if examined_files >= 4096:
                    break
    except OSError:
        return []

    candidates.sort(key=lambda item: item.modified_at, reverse=True)
    unique: list[OmpSavedSession] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate.session_id in seen:
            continue
        seen.add(candidate.session_id)
        unique.append(candidate)
        if len(unique) >= result_limit:
            break
    return unique

# While a question's form is open in a terminal, the Pairling ask extension
# (omp_ask_extension.mjs) keeps `<session id>.<call key>.pending` here, holding
# the id of the OMP process that shows the form. An answer renamed into place
# beside it as `<session id>.<call key>.answer.json` is the one the agent
# gets, and the extension removes both when the form closes. The call key is
# a digest of the call's id, which is the model provider's and may hold any
# character.
_ASKS_DIRECTORY = (".claude", "companion", "omp-asks")
_ASK_SESSION_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
ASK_ANSWER_TEXT_MAX = 8000
# How long the extension is given to take an answer. It reads on the file
# event, so this is slack for a busy terminal, not a wait anyone sees.
ASK_ANSWER_TAKEN_SECONDS = 3.0


def asks_directory(*, home: Path | None = None) -> Path:
    return (home or Path.home()).joinpath(*_ASKS_DIRECTORY)


def _ask_file(session_id, call_id, suffix: str, *, home: Path | None = None) -> Path | None:
    if (
        not isinstance(session_id, str) or not _ASK_SESSION_ID.fullmatch(session_id)
        or not isinstance(call_id, str) or not call_id
    ):
        return None
    call_key = hashlib.sha256(call_id.encode("utf-8")).hexdigest()[:32]
    return asks_directory(home=home) / f"{session_id}.{call_key}{suffix}"


def ask_can_be_answered(session_id, call_id, *, home: Path | None = None) -> bool:
    """Whether a live OMP process holds this question's form open through the
    extension. Only then does an answer written for it reach the agent."""
    marker = _ask_file(session_id, call_id, ".pending", home=home)
    if marker is None:
        return False
    try:
        descriptor = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return False
        holder = int(os.read(descriptor, 32))
        if holder <= 1:
            return False
        # A process that was killed leaves its marker behind.
        os.kill(holder, 0)
    except (OSError, ValueError):
        return False
    finally:
        os.close(descriptor)
    return True


def _ask_choice(row: dict, answered: bool, given) -> tuple[object, str | None]:
    """A choice field's value, and what is wrong with it if anything, by the
    rules of OMP's own dialog: one value, or a list when several boxes can be
    ticked, with a typed answer taking the place of or joining the choices."""
    options = [option for option in row.get("options") or [] if isinstance(option, dict)]
    offered = [option["value"] for option in options if not option.get("disabled")]
    several = row["kind"] == "multiple" and len(options) > 1
    typed = ""
    if not answered:
        chosen = {option["value"] for option in options if option.get("checked")}
    else:
        chosen = set()
        for item in given if isinstance(given, list) else [given]:
            if item is None:
                continue
            if not isinstance(item, str) or len(item) > ASK_ANSWER_TEXT_MAX:
                return None, "An answer must be text"
            if item in offered:
                chosen.add(item)
            elif not item.strip():
                continue
            elif row.get("custom") and not typed:
                typed = item.strip()
            else:
                return None, f"{item[:80]!r} is not one of the choices"
    picked = [value for value in dict.fromkeys(offered) if value in chosen]
    if several:
        value = picked + [typed] if typed else picked
    else:
        value = typed or (picked[0] if picked else None)
    if row.get("required") and (value is None or value == []):
        return value, "Select at least one" if several else "Required"
    return value, None


def _ask_text(row: dict, answered: bool, given) -> tuple[object, str | None]:
    """A typed field's value, and what is wrong with it if anything, by the
    rules of OMP's own dialog."""
    given = given if answered else row.get("value")
    if given is None:
        given = ""
    if isinstance(given, bool) or not isinstance(given, (str, int, float)):
        return None, "An answer must be text"
    text = str(given)
    if len(text) > ASK_ANSWER_TEXT_MAX:
        return None, f"At most {ASK_ANSWER_TEXT_MAX} characters"
    if not text.strip():
        return text, "Required" if row.get("required") else None
    value: object = text
    if row.get("input") in ("number", "range"):
        try:
            number = float(text) if "_" not in text else math.nan
        except ValueError:
            number = math.nan
        if not math.isfinite(number):
            return text, "Enter a number"
        value = int(number) if number.is_integer() else number
        if row.get("min") is not None and value < row["min"]:
            return value, f"Must be at least {row['min']}"
        if row.get("max") is not None and value > row["max"]:
            return value, f"Must be at most {row['max']}"
    if row.get("minlength") is not None and len(text) < row["minlength"]:
        return value, f"Needs at least {row['minlength']} characters"
    if row.get("maxlength") is not None and len(text) > row["maxlength"]:
        return value, f"At most {row['maxlength']} characters"
    if row.get("input") == "email" and not re.fullmatch(r"[^\s@]+@[^\s@]+", text):
        return value, "Enter an email address"
    if row.get("input") == "url" and not re.match(r"[A-Za-z][A-Za-z0-9+.-]*:.", text):
        return value, "Enter a full URL"
    if row.get("pattern"):
        try:
            fits = re.fullmatch(row["pattern"], text) is not None
        except re.error:
            fits = True
        if not fits:
            return value, f"Must match {row['pattern'][:40]}"
    return value, None


def _ask_said(row: dict, value) -> str:
    """How an answer reads beside its question in the session's own record."""
    if value is None:
        return ""
    if row["kind"] == "text":
        return str(value)

    def said(item) -> str:
        for option in row.get("options") or []:
            if isinstance(option, dict) and option.get("value") == item:
                return option.get("label") or item
        return f"Other: {item}" if row.get("custom") else item

    return ", ".join(said(item) for item in value) if isinstance(value, list) else said(value)


def ask_answer(rows, values) -> dict:
    """The answer OMP's own form would give for what a person chose:
    `data` keyed by field name, and `answers` saying each in words.

    `rows` are the form's rows as `agent_questions` reads them. `values` holds
    the person's choice for a field by its name: text for a typed field or one
    choice, a list for boxes. A field left out keeps what the form started
    with. Raises ValueError, naming the question, for an answer the form does
    not take."""
    if not isinstance(values, dict):
        raise ValueError("answers must be keyed by field name")
    rows = [row for row in rows or [] if isinstance(row, dict) and row.get("name")]
    fields = [row for row in rows if row.get("kind") in ("single", "multiple", "text")]
    if not fields:
        raise ValueError("the form asks nothing")
    unknown = sorted(str(name) for name in values if name not in {row["name"] for row in fields})
    if unknown:
        raise ValueError(f"the form has no field named {unknown[0]!r}")
    data: dict = {
        row["name"]: str(row.get("value") or "") for row in rows if row.get("kind") == "hidden"
    }
    answers: list[dict] = []
    for row in fields:
        name, options = row["name"], row.get("options") or []
        # A lone box with no question of its own is asked by its label.
        lone = options[0].get("label") if len(options) == 1 and isinstance(options[0], dict) else ""
        question = row.get("question") or lone or name
        read = _ask_text if row["kind"] == "text" else _ask_choice
        value, fault = read(row, name in values, values.get(name))
        if fault:
            raise ValueError(f"{question}: {fault}")
        if value is None:
            data.pop(name, None)
        else:
            data[name] = value
        answers.append({"name": name, "question": question, "answer": _ask_said(row, value)})
    return {"data": data, "answers": answers}


def give_ask_answer(
    session_id, call_id, answer: dict, *,
    home: Path | None = None, patience: float = ASK_ANSWER_TAKEN_SECONDS,
) -> str:
    """Hand an answer to the extension holding the question's form open, and
    wait for the form to close on it.

    "taken": the form closed with the answer in place.
    "closed": no live form is open for the question, and nothing was written.
    "ignored": the form stayed open, and the answer was withdrawn so that it
    cannot land later."""
    if not ask_can_be_answered(session_id, call_id, home=home):
        return "closed"
    marker = _ask_file(session_id, call_id, ".pending", home=home)
    target = _ask_file(session_id, call_id, ".answer.json", home=home)
    scratch = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(scratch, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(answer, handle, ensure_ascii=False)
        # A whole file renamed into place: the extension reads on the event.
        os.replace(scratch, target)
        deadline = time.monotonic() + patience
        while os.path.lexists(marker):
            if time.monotonic() >= deadline:
                os.unlink(target)
                return "ignored"
            time.sleep(0.02)
    except OSError:
        for left in (scratch, target):
            try:
                os.unlink(left)
            except OSError:
                pass
        return "ignored"
    return "taken"


class OmpProviderAdapter(ProviderAdapter):
    descriptor = registry_data.descriptor_for(_ENTRY) if _ENTRY else _FALLBACK_DESCRIPTOR

    def __init__(self, home: Path | None = None):
        self.home = home or Path.home()

    @property
    def candidates(self) -> list[Path]:
        if _ENTRY is not None and _ENTRY.binary_candidates:
            return registry_data.candidate_paths(_ENTRY, home=self.home)
        return [
            self.home / ".local" / "bin" / "omp",
            Path("/opt/homebrew/bin/omp"),
            Path("/usr/local/bin/omp"),
        ]

    # Exact Terminal.app sessions support receipted text and process signals.
    # Atomic terminal-key control still requires Pairling's PTY broker.
    def supports(self, capability: str) -> bool:
        return capability in {
            "commands",
            "detect",
            "saved_sessions",
            "status",
            "list_sessions",
            "terminal_output",
            "terminal_surface",
            "terminal_control",
            "send_text",
            "interrupt",
            "terminate",
            "resume",
            "spawn",
        }

    def create_control_driver(self, binding):
        """Use the reviewed ACP profile for Pairling-owned OMP sessions."""
        if _ENTRY is None:
            return None
        from .acp import AcpProviderAdapter

        return AcpProviderAdapter(_ENTRY, home=self.home).create_control_driver(binding)

    def probe(self) -> ProviderProbeResult:
        env_var = _ENTRY.env_override if _ENTRY is not None else "PAIRLING_OMP_BIN"
        resolved = resolve_executable("omp", self.candidates, env_var=env_var)
        installed = resolved is not None
        config_path = self.home / ".omp" / "agent" / "config.yml"
        managed_probe = None
        if installed and _ENTRY is not None:
            from .acp import AcpProviderAdapter

            managed_probe = AcpProviderAdapter(_ENTRY, home=self.home).probe()
        managed_launchable = bool(
            managed_probe is not None and managed_probe.availability.launchable
        )
        terminal_launchable = bool(
            installed and self.descriptor.terminal_launch is not None
        )
        launchable = managed_launchable or terminal_launchable
        capabilities = (
            "commands",
            "detect",
            "saved_sessions",
            "status",
            "list_sessions",
            "terminal_output",
            "terminal_surface",
            "terminal_control",
            "send_text",
            "interrupt",
            "terminate",
            "resume",
            "spawn",
        ) if installed else ("detect", "status")
        if not installed:
            notes = (
                "OMP CLI not found in configured, known, or daemon PATH locations",
            )
            setup_actions = ("install_cli",)
        elif managed_probe is not None:
            notes = managed_probe.availability.notes
            setup_actions = managed_probe.availability.setup_actions
        else:
            notes = ("OMP has no reviewed managed launch entry.",)
            setup_actions = ("provider_review_required",)
        return ProviderProbeResult(
            descriptor=self.descriptor,
            availability=ProviderAvailability(
                provider_id=self.descriptor.provider_id,
                display_name=self.descriptor.display_name,
                kind=self.descriptor.kind,
                installed=installed,
                usable=installed,
                launchable=launchable,
                auth_state="unknown" if installed else "missing_cli",
                config_state=(
                    "pairling_managed"
                    if managed_launchable
                    else ("ready" if config_path.is_file() else "missing")
                ),
                readable_sessions=0,
                live_sessions=0,
                controllable_sessions=0,
                capabilities=capabilities,
                setup_actions=setup_actions,
                notes=notes,
            ),
            diagnostics=ProviderDiagnostics(
                cli_path=str(resolved.path) if resolved else None,
                cli_path_source=resolved.source if resolved else None,
                version=(
                    managed_probe.diagnostics.version
                    if managed_probe is not None
                    else (cli_version(resolved.path) if resolved else None)
                ),
                config_path=str(config_path),
                config_exists=config_path.is_file(),
            ),
            observed_at=time.time(),
        )
