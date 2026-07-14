"""Durable per-session event log and the provider-neutral schema (contract v2).

Phase 2 of the session viewer evolution. Provider adapters parse transcript
lines ONCE on the Mac into neutral events; everything downstream (live
streams, archive reads, search, export, push triggers) reads this log, so
live and history stop being two code paths. The raw provider line rides along
on the first event parsed from it. Records beyond the safe parse cap live in a
private file-backed store so retrieval stays exact without putting the whole
record in memory. Inline attachment bytes are redacted from parsed copies
because the source transcript remains their canonical store.

Neutral kinds: block_text, block_thinking, tool_call, tool_result,
lifecycle, plus PARTIAL_TEXT_KIND reserved for managed sessions that can
stream token deltas. Interactive sessions can never emit partial_text from
the file adapter, because a JSONL line does not exist until it is complete.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import shutil
import sqlite3
import stat
import threading
from contextlib import contextmanager
from pathlib import Path

PARTIAL_TEXT_KIND = "partial_text"
VISIBLE_BLOCK_TEXT_MAX = 2048
RAW_BLOB_COPY_CHUNK = 1024 * 1024
SESSION_EVENT_ROW_OVERHEAD = 512
DEFAULT_SESSION_EVENT_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
DEFAULT_SESSION_EVENT_PER_SESSION_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_SESSION_EVENT_MIN_FREE_BYTES = 2 * 1024 * 1024 * 1024

KINDS = (
    "block_text",
    "block_thinking",
    "tool_call",
    "tool_result",
    "lifecycle",
    PARTIAL_TEXT_KIND,
)


class SessionEventStorageLimitError(OSError):
    """A durable event write would exceed a configured or physical budget."""


def _positive_byte_setting(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return int(default)
    return value if value > 0 else int(default)


def source_file_version(info) -> tuple[int, int, int, int, int]:
    """The stable fields used to reject an in-place transcript rewrite."""
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
    )


def _bounded_visible_text(value, limit: int = VISIBLE_BLOCK_TEXT_MAX) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError):
            value = str(value)
    text = " ".join(value.split())
    if text.startswith("data:"):
        return "[inline data omitted]"
    if len(text) <= limit:
        return text
    return text[:max(0, limit - 3)] + "..."


def _attachment_label(kind: str, block: dict) -> str:
    source = block.get("source") if isinstance(block.get("source"), dict) else {}
    details: list[str] = []
    name = block.get("title") or block.get("name") or block.get("filename")
    if name:
        details.append(_bounded_visible_text(name, 160))
    media_type = source.get("media_type") or block.get("media_type")
    if media_type:
        details.append(_bounded_visible_text(media_type, 80))
    suffix = f" ({', '.join(details)})" if details else ""
    return _bounded_visible_text(f"[{kind} attachment{suffix}]")


def _fallback_label(block: dict) -> str:
    source = block.get("from") if isinstance(block.get("from"), dict) else {}
    destination = block.get("to") if isinstance(block.get("to"), dict) else {}
    from_model = _bounded_visible_text(source.get("model"), 120)
    to_model = _bounded_visible_text(destination.get("model"), 120)
    if from_model and to_model:
        return f"[Model fallback: {from_model} to {to_model}]"
    return "[Model fallback]"


def _unknown_block_label(block_type: str, block: dict) -> str:
    safe_type = _bounded_visible_text(block_type or "unknown", 80)
    candidate = block.get("text") or block.get("content")
    if isinstance(candidate, str) and candidate:
        prefix = f"[Unsupported content block: {safe_type}] "
        return prefix + _bounded_visible_text(candidate, VISIBLE_BLOCK_TEXT_MAX - len(prefix))
    return f"[Unsupported content block: {safe_type}]"


def _redact_inline_binary(value):
    if isinstance(value, list):
        return [_redact_inline_binary(item) for item in value]
    if isinstance(value, str) and value.startswith("data:"):
        return f"[data URL omitted: {len(value)} chars]"
    if not isinstance(value, dict):
        return value
    result = {}
    source_type = str(value.get("type") or "")
    for key, item in value.items():
        if key == "data" and isinstance(item, str) and (
            source_type == "base64" or len(item) > 256
        ):
            result[key] = f"[base64 omitted: {len(item)} chars]"
        elif key in ("image_url", "url") and isinstance(item, str) and item.startswith("data:"):
            result[key] = f"[data URL omitted: {len(item)} chars]"
        else:
            result[key] = _redact_inline_binary(item)
    return result


def parse_claude_transcript_line(line: str) -> list[dict]:
    """Map one provider JSONL line to neutral events. Never raises: anything
    unparseable becomes an explicit lifecycle event carrying the raw line."""
    raw = line.rstrip("\n")
    try:
        entry = json.loads(raw)
        if not isinstance(entry, dict):
            raise ValueError("not an object")
    except Exception:
        return [{
            "kind": "lifecycle",
            "subtype": "unparsed",
            "source_uuid": None,
            "role": None,
            "ts": None,
            "raw": raw,
        }]

    entry_type = str(entry.get("type") or "unknown")
    source_uuid = entry.get("uuid")
    ts = entry.get("timestamp")
    message = entry.get("message") if isinstance(entry.get("message"), dict) else None

    if message is None:
        return [{
            "kind": "lifecycle",
            "subtype": entry_type,
            "source_uuid": source_uuid,
            "role": None,
            "ts": ts,
            "raw": raw,
        }]

    role = message.get("role") or entry_type
    content = message.get("content")
    events: list[dict] = []

    def _base() -> dict:
        return {"source_uuid": source_uuid, "role": role, "ts": ts, "raw": None}

    if isinstance(content, str):
        if content:
            events.append({**_base(), "kind": "block_text", "block_index": 0, "text": content})
    elif isinstance(content, list):
        for block_index, block in enumerate(content):
            if not isinstance(block, dict):
                events.append({**_base(), "kind": "block_text", "block_index": block_index,
                               "text": "[Unsupported content block]"})
                continue
            block_type = str(block.get("type") or "")
            if block_type == "text":
                events.append({**_base(), "kind": "block_text", "block_index": block_index,
                               "text": str(block.get("text") or "")})
            elif block_type == "thinking":
                events.append({**_base(), "kind": "block_thinking", "block_index": block_index,
                               "text": str(block.get("thinking") or block.get("text") or "")})
            elif block_type == "tool_use":
                events.append({**_base(), "kind": "tool_call", "block_index": block_index,
                               "call_id": block.get("id"),
                               "name": block.get("name"),
                               "input": block.get("input")})
            elif block_type == "tool_result":
                block_content = _redact_inline_binary(block.get("content"))
                if not isinstance(block_content, str):
                    block_content = json.dumps(
                        block_content,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                events.append({**_base(), "kind": "tool_result", "block_index": block_index,
                               "call_id": block.get("tool_use_id"),
                               "content": block_content,
                               "is_error": bool(block.get("is_error"))})
            elif block_type == "image":
                events.append({**_base(), "kind": "block_text", "block_index": block_index,
                               "text": _attachment_label("Image", block)})
            elif block_type == "document":
                events.append({**_base(), "kind": "block_text", "block_index": block_index,
                               "text": _attachment_label("Document", block)})
            elif block_type == "fallback":
                events.append({**_base(), "kind": "block_text", "block_index": block_index,
                               "text": _fallback_label(block)})
            else:
                events.append({**_base(), "kind": "block_text", "block_index": block_index,
                               "text": _unknown_block_label(block_type, block)})

    if not events:
        events.append({**_base(), "kind": "lifecycle", "subtype": entry_type, "block_index": 0})
    events = [_redact_inline_binary(event) for event in events]
    redacted_entry = _redact_inline_binary(entry)
    if redacted_entry != entry:
        events[0]["raw"] = json.dumps(
            redacted_entry, ensure_ascii=False, separators=(",", ":")
        )
    else:
        events[0]["raw"] = raw
    return events


class SessionEventLog:
    """Append-only per-session event log in SQLite (WAL). seq is a dense
    monotonic counter per session_key; readers resume from any seq."""

    def __init__(
        self,
        db_path,
        *,
        max_total_bytes: int | None = None,
        max_session_bytes: int | None = None,
        min_free_bytes: int | None = None,
        disk_free_provider=None,
    ) -> None:
        db_path = Path(db_path).expanduser()
        self._db_path = str(db_path)
        self._blob_dir = db_path.parent / f".{db_path.name}.raw"
        self._lock = threading.Lock()
        self._max_total_bytes = int(max_total_bytes or _positive_byte_setting(
            "PAIRLING_SESSION_EVENT_TOTAL_MAX_BYTES",
            DEFAULT_SESSION_EVENT_TOTAL_BYTES,
        ))
        self._max_session_bytes = int(max_session_bytes or _positive_byte_setting(
            "PAIRLING_SESSION_EVENT_SESSION_MAX_BYTES",
            DEFAULT_SESSION_EVENT_PER_SESSION_BYTES,
        ))
        self._min_free_bytes = max(0, int(
            DEFAULT_SESSION_EVENT_MIN_FREE_BYTES
            if min_free_bytes is None else min_free_bytes
        ))
        if min_free_bytes is None:
            self._min_free_bytes = _positive_byte_setting(
                "PAIRLING_SESSION_EVENT_MIN_FREE_BYTES",
                DEFAULT_SESSION_EVENT_MIN_FREE_BYTES,
            )
        self._disk_free_provider = disk_free_provider or (
            lambda path: int(shutil.disk_usage(path).free)
        )
        self._reserved_total_bytes = 0
        self._reserved_session_bytes: dict[str, int] = {}
        self._ensure_private_blob_dir()
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS session_events ("
                " session_key TEXT NOT NULL,"
                " seq INTEGER NOT NULL,"
                " ingested_at REAL NOT NULL,"
                " kind TEXT NOT NULL,"
                " payload TEXT NOT NULL,"
                " raw TEXT,"
                " PRIMARY KEY (session_key, seq))"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS ingest_cursors ("
                " session_key TEXT PRIMARY KEY,"
                " byte_offset INTEGER NOT NULL,"
                " parser_version INTEGER NOT NULL DEFAULT 1,"
                " generation INTEGER NOT NULL DEFAULT 1,"
                " source_dev INTEGER,"
                " source_ino INTEGER)"
            )
            cursor_columns = {
                str(row["name"]) for row in conn.execute("PRAGMA table_info(ingest_cursors)").fetchall()
            }
            if "parser_version" not in cursor_columns:
                conn.execute(
                    "ALTER TABLE ingest_cursors ADD COLUMN parser_version INTEGER NOT NULL DEFAULT 1"
                )
            if "generation" not in cursor_columns:
                conn.execute(
                    "ALTER TABLE ingest_cursors ADD COLUMN generation INTEGER NOT NULL DEFAULT 1"
                )
            if "source_dev" not in cursor_columns:
                conn.execute("ALTER TABLE ingest_cursors ADD COLUMN source_dev INTEGER")
            if "source_ino" not in cursor_columns:
                conn.execute("ALTER TABLE ingest_cursors ADD COLUMN source_ino INTEGER")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS session_event_raw_blobs ("
                " session_key TEXT NOT NULL,"
                " generation INTEGER NOT NULL,"
                " seq INTEGER NOT NULL,"
                " blob_name TEXT NOT NULL UNIQUE,"
                " byte_count INTEGER NOT NULL,"
                " sha256 TEXT NOT NULL,"
                " PRIMARY KEY (session_key, generation, seq))"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS session_event_storage_usage ("
                " session_key TEXT PRIMARY KEY,"
                " byte_count INTEGER NOT NULL)"
            )
            self._rebuild_storage_usage(conn)
        self._prune_orphaned_blobs()

    @staticmethod
    def _serialized_event(event: dict) -> tuple[str, str, object, int]:
        payload = {key: value for key, value in event.items() if key != "raw"}
        payload_json = json.dumps(payload, ensure_ascii=False)
        raw = event.get("raw")
        raw_bytes = len(raw.encode("utf-8")) if isinstance(raw, str) else 0
        stored_bytes = (
            len(payload_json.encode("utf-8"))
            + raw_bytes
            + SESSION_EVENT_ROW_OVERHEAD
        )
        return str(event.get("kind") or "lifecycle"), payload_json, raw, stored_bytes

    def _rebuild_storage_usage(self, conn) -> None:
        usage: dict[str, int] = {}
        for row in conn.execute(
            "SELECT session_key, "
            "COALESCE(SUM(length(CAST(payload AS BLOB)) + "
            "COALESCE(length(CAST(raw AS BLOB)), 0) + ?), 0) AS bytes "
            "FROM session_events GROUP BY session_key",
            (SESSION_EVENT_ROW_OVERHEAD,),
        ).fetchall():
            usage[str(row["session_key"])] = int(row["bytes"] or 0)
        for row in conn.execute(
            "SELECT session_key, COALESCE(SUM(byte_count), 0) AS bytes "
            "FROM session_event_raw_blobs GROUP BY session_key"
        ).fetchall():
            key = str(row["session_key"])
            usage[key] = usage.get(key, 0) + int(row["bytes"] or 0)
        conn.execute("DELETE FROM session_event_storage_usage")
        conn.executemany(
            "INSERT INTO session_event_storage_usage (session_key, byte_count) VALUES (?, ?)",
            sorted(usage.items()),
        )

    @staticmethod
    def _session_usage_locked(conn, session_key: str) -> int:
        row = conn.execute(
            "SELECT byte_count FROM session_event_storage_usage WHERE session_key=?",
            (session_key,),
        ).fetchone()
        return max(0, int(row["byte_count"])) if row else 0

    @staticmethod
    def _total_usage_locked(conn) -> int:
        row = conn.execute(
            "SELECT COALESCE(SUM(byte_count), 0) AS bytes FROM session_event_storage_usage"
        ).fetchone()
        return max(0, int(row["bytes"] or 0))

    @staticmethod
    def _increment_usage_locked(conn, session_key: str, added_bytes: int) -> None:
        conn.execute(
            "INSERT INTO session_event_storage_usage (session_key, byte_count) VALUES (?, ?) "
            "ON CONFLICT(session_key) DO UPDATE SET byte_count=byte_count+excluded.byte_count",
            (session_key, max(0, int(added_bytes))),
        )

    @staticmethod
    def _clear_usage_locked(conn, session_key: str) -> None:
        conn.execute(
            "DELETE FROM session_event_storage_usage WHERE session_key=?",
            (session_key,),
        )

    def _check_storage_capacity_locked(
        self,
        conn,
        session_key: str,
        added_bytes: int,
    ) -> None:
        added = max(0, int(added_bytes))
        session_reserved = self._reserved_session_bytes.get(session_key, 0)
        session_projected = (
            self._session_usage_locked(conn, session_key)
            + session_reserved
            + added
        )
        if session_projected > self._max_session_bytes:
            raise SessionEventStorageLimitError(
                "session event storage limit reached for this session; "
                "delete an old session or raise PAIRLING_SESSION_EVENT_SESSION_MAX_BYTES"
            )
        total_projected = (
            self._total_usage_locked(conn)
            + self._reserved_total_bytes
            + added
        )
        if total_projected > self._max_total_bytes:
            raise SessionEventStorageLimitError(
                "session event storage limit reached; delete old sessions or raise "
                "PAIRLING_SESSION_EVENT_TOTAL_MAX_BYTES"
            )
        try:
            available = int(self._disk_free_provider(self._blob_dir))
        except Exception as error:
            raise SessionEventStorageLimitError(
                "could not verify free disk space for the session event log"
            ) from error
        if available < self._min_free_bytes + self._reserved_total_bytes + added:
            raise SessionEventStorageLimitError(
                "the Mac does not have enough free space to preserve more session history"
            )

    @contextmanager
    def _storage_reservation(self, session_key: str, byte_count: int):
        reserved = max(0, int(byte_count))
        with self._lock, self._connect() as conn:
            self._check_storage_capacity_locked(conn, session_key, reserved)
            self._reserved_total_bytes += reserved
            self._reserved_session_bytes[session_key] = (
                self._reserved_session_bytes.get(session_key, 0) + reserved
            )
        try:
            yield
        finally:
            with self._lock:
                self._reserved_total_bytes = max(
                    0, self._reserved_total_bytes - reserved
                )
                remaining = max(
                    0,
                    self._reserved_session_bytes.get(session_key, 0) - reserved,
                )
                if remaining:
                    self._reserved_session_bytes[session_key] = remaining
                else:
                    self._reserved_session_bytes.pop(session_key, None)

    def storage_status(self) -> dict:
        with self._lock, self._connect() as conn:
            return {
                "used_bytes": self._total_usage_locked(conn),
                "reserved_bytes": self._reserved_total_bytes,
                "max_total_bytes": self._max_total_bytes,
                "max_session_bytes": self._max_session_bytes,
                "min_free_bytes": self._min_free_bytes,
            }

    def _ensure_private_blob_dir(self) -> None:
        try:
            os.mkdir(self._blob_dir, 0o700)
        except FileExistsError:
            pass
        info = os.lstat(self._blob_dir)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise OSError("session event raw store is not a private directory")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise PermissionError("session event raw store has the wrong owner")
        os.chmod(self._blob_dir, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions - owner was verified above and 0700 is the required private mode.

    @staticmethod
    def _valid_blob_name(name: str, suffix: str = ".raw") -> bool:
        if not isinstance(name, str) or not name.endswith(suffix):
            return False
        token = name[:-len(suffix)]
        return len(token) == 64 and all(char in "0123456789abcdef" for char in token)

    def _blob_path(self, name: str, *, suffix: str = ".raw") -> Path:
        if not self._valid_blob_name(name, suffix):
            raise ValueError("invalid session event raw identifier")
        return self._blob_dir / name

    def _open_blob_for_read(self, name: str, expected_size: int):
        path = self._blob_path(name)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError("session event raw object is not a private regular file")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise PermissionError("session event raw object has the wrong owner")
            if int(info.st_size) != int(expected_size):
                raise OSError("session event raw object size does not match its record")
            return os.fdopen(descriptor, "rb", closefd=True)
        except Exception:
            os.close(descriptor)
            raise

    def _prune_orphaned_blobs(self) -> None:
        with self._connect() as conn:
            referenced = {
                str(row["blob_name"])
                for row in conn.execute(
                    "SELECT blob_name FROM session_event_raw_blobs"
                ).fetchall()
            }
        with os.scandir(self._blob_dir) as entries:
            for entry in entries:
                name = entry.name
                is_managed = (
                    self._valid_blob_name(name)
                    or self._valid_blob_name(name, ".tmp")
                )
                if not is_managed or name in referenced:
                    continue
                try:
                    os.unlink(entry.path)
                except FileNotFoundError:
                    pass

    @staticmethod
    def _blob_names_for_session(conn, session_key: str) -> list[str]:
        return [
            str(row["blob_name"])
            for row in conn.execute(
                "SELECT blob_name FROM session_event_raw_blobs WHERE session_key=?",
                (session_key,),
            ).fetchall()
        ]

    def _remove_blob_files(self, blob_names: list[str]) -> None:
        first_error = None
        for name in blob_names:
            try:
                path = self._blob_path(name)
                os.unlink(path)
            except FileNotFoundError:
                pass
            except (OSError, ValueError) as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise OSError(
                "one or more session event raw objects could not be removed"
            ) from first_error

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=3000")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def append(self, session_key: str, events: list[dict]) -> int:
        if not events:
            return self.last_seq(session_key)
        import time as _time
        now = _time.time()
        serialized = [self._serialized_event(event) for event in events]
        added_bytes = sum(item[3] for item in serialized)
        with self._lock, self._connect() as conn:
            self._check_storage_capacity_locked(conn, session_key, added_bytes)
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS last FROM session_events WHERE session_key=?",
                (session_key,),
            ).fetchone()
            seq = int(row["last"])
            for kind, payload_json, raw, _stored_bytes in serialized:
                seq += 1
                conn.execute(
                    "INSERT INTO session_events (session_key, seq, ingested_at, kind, payload, raw)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (session_key, seq, now, kind, payload_json, raw),
                )
            self._increment_usage_locked(conn, session_key, added_bytes)
            conn.commit()
            return seq

    def append_and_advance(self, session_key: str, events: list[dict],
                           byte_offset: int, *, expected_byte_offset: int,
                           expected_source_identity: tuple[int, int] | None = None) -> int | None:
        """Append parsed events and advance the source cursor in one commit.

        The expected cursor makes a stale concurrent drain a no-op. Without
        this check, two readers can parse the same transcript bytes and append
        duplicate events before either one advances the durable cursor.
        """
        import time as _time
        now = _time.time()
        serialized = [self._serialized_event(event) for event in events]
        added_bytes = sum(item[3] for item in serialized)
        with self._lock, self._connect() as conn:
            cursor_row = conn.execute(
                "SELECT byte_offset, source_dev, source_ino FROM ingest_cursors WHERE session_key=?",
                (session_key,),
            ).fetchone()
            current_offset = int(cursor_row["byte_offset"]) if cursor_row else 0
            if current_offset != int(expected_byte_offset):
                return None
            if expected_source_identity is not None:
                current_identity = None
                if cursor_row and cursor_row["source_dev"] is not None and cursor_row["source_ino"] is not None:
                    current_identity = (int(cursor_row["source_dev"]), int(cursor_row["source_ino"]))
                if current_identity != tuple(expected_source_identity):
                    return None
            self._check_storage_capacity_locked(conn, session_key, added_bytes)
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS last FROM session_events WHERE session_key=?",
                (session_key,),
            ).fetchone()
            seq = int(row["last"])
            for kind, payload_json, raw, _stored_bytes in serialized:
                seq += 1
                conn.execute(
                    "INSERT INTO session_events (session_key, seq, ingested_at, kind, payload, raw)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (session_key, seq, now, kind, payload_json, raw),
                )
            conn.execute(
                "INSERT INTO ingest_cursors (session_key, byte_offset) VALUES (?, ?)"
                " ON CONFLICT(session_key) DO UPDATE SET byte_offset=excluded.byte_offset",
                (session_key, int(byte_offset)),
            )
            self._increment_usage_locked(conn, session_key, added_bytes)
            conn.commit()
            return seq

    def append_preserved_raw_and_advance(
        self,
        session_key: str,
        event: dict,
        byte_offset: int,
        *,
        expected_byte_offset: int,
        expected_source_identity: tuple[int, int],
        source_handle,
        source_start: int,
        source_bytes: int,
        expected_source_version: tuple[int, int, int, int, int] | None = None,
    ) -> int | None:
        """Copy one beyond-parse-cap source record without loading it whole.

        The private object and its SQLite reference are committed only if the
        source cursor still matches. The metadata row binds later reads to the
        exact session generation and event sequence.
        """
        byte_count = max(0, int(source_bytes))
        if byte_count <= 0:
            raise ValueError("source_bytes must be positive")
        source_position = max(0, int(source_start))
        initial_version = source_file_version(os.fstat(source_handle.fileno()))
        if initial_version[:2] != tuple(expected_source_identity):
            return None
        if (expected_source_version is not None
                and initial_version != tuple(expected_source_version)):
            return None
        if source_position + byte_count > initial_version[2]:
            return None
        reserved_event = dict(event)
        reserved_event["raw"] = None
        reserved_event["raw_preserved"] = True
        reserved_event["raw_bytes"] = byte_count
        reserved_event["raw_sha256"] = "0" * 64
        reserved_inline_bytes = self._serialized_event(reserved_event)[3]
        reservation_bytes = reserved_inline_bytes + byte_count
        with self._storage_reservation(session_key, reservation_bytes):
            return self._copy_preserved_raw_and_advance(
                session_key=session_key,
                event=event,
                byte_offset=byte_offset,
                expected_byte_offset=expected_byte_offset,
                expected_source_identity=expected_source_identity,
                source_handle=source_handle,
                source_position=source_position,
                byte_count=byte_count,
                initial_version=initial_version,
                reservation_bytes=reservation_bytes,
            )

    def _copy_preserved_raw_and_advance(
        self,
        *,
        session_key: str,
        event: dict,
        byte_offset: int,
        expected_byte_offset: int,
        expected_source_identity: tuple[int, int],
        source_handle,
        source_position: int,
        byte_count: int,
        initial_version: tuple[int, int, int, int, int],
        reservation_bytes: int,
    ) -> int | None:
        token = secrets.token_hex(32)
        temporary_name = f"{token}.tmp"
        blob_name = f"{token}.raw"
        temporary_path = self._blob_path(temporary_name, suffix=".tmp")
        blob_path = self._blob_path(blob_name)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary_path, flags, 0o600)
        digest = hashlib.sha256()
        remaining = byte_count
        try:
            try:
                os.fchmod(descriptor, 0o600)
                while remaining:
                    chunk = os.pread(
                        source_handle.fileno(),
                        min(RAW_BLOB_COPY_CHUNK, remaining),
                        source_position,
                    )
                    if not chunk:
                        raise OSError("transcript ended while preserving a large record")
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise OSError("could not preserve a large transcript record")
                        view = view[written:]
                    source_position += len(chunk)
                    remaining -= len(chunk)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except Exception:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            raise

        try:
            copied_version = source_file_version(os.fstat(source_handle.fileno()))
        except Exception:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            raise
        if copied_version != initial_version:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            return None

        checksum = digest.hexdigest()
        committed = False
        try:
            import time as _time
            now = _time.time()
            with self._lock, self._connect() as conn:
                cursor_row = conn.execute(
                    "SELECT byte_offset, generation, source_dev, source_ino "
                    "FROM ingest_cursors WHERE session_key=?",
                    (session_key,),
                ).fetchone()
                current_offset = int(cursor_row["byte_offset"]) if cursor_row else 0
                current_identity = None
                if (cursor_row is not None
                        and cursor_row["source_dev"] is not None
                        and cursor_row["source_ino"] is not None):
                    current_identity = (
                        int(cursor_row["source_dev"]),
                        int(cursor_row["source_ino"]),
                    )
                if (current_offset != int(expected_byte_offset)
                        or current_identity != tuple(expected_source_identity)):
                    return None
                if source_file_version(os.fstat(source_handle.fileno())) != initial_version:
                    return None
                generation = max(1, int(cursor_row["generation"]))
                row = conn.execute(
                    "SELECT COALESCE(MAX(seq), 0) AS last FROM session_events WHERE session_key=?",
                    (session_key,),
                ).fetchone()
                seq = int(row["last"]) + 1
                event_with_reference = dict(event)
                event_with_reference["raw"] = None
                event_with_reference["raw_preserved"] = True
                event_with_reference["raw_bytes"] = byte_count
                event_with_reference["raw_sha256"] = checksum
                kind, payload_json, _raw, inline_bytes = self._serialized_event(
                    event_with_reference
                )
                stored_bytes = inline_bytes + byte_count
                if stored_bytes > reservation_bytes:
                    raise SessionEventStorageLimitError(
                        "session event storage reservation changed before commit"
                    )
                os.rename(temporary_path, blob_path)
                conn.execute(
                    "INSERT INTO session_events (session_key, seq, ingested_at, kind, payload, raw)"
                    " VALUES (?, ?, ?, ?, ?, NULL)",
                    (
                        session_key,
                        seq,
                        now,
                        kind,
                        payload_json,
                    ),
                )
                conn.execute(
                    "INSERT INTO session_event_raw_blobs "
                    "(session_key, generation, seq, blob_name, byte_count, sha256) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (session_key, generation, seq, blob_name, byte_count, checksum),
                )
                conn.execute(
                    "UPDATE ingest_cursors SET byte_offset=? WHERE session_key=?",
                    (int(byte_offset), session_key),
                )
                self._increment_usage_locked(conn, session_key, stored_bytes)
                conn.commit()
                committed = True
                return seq
        finally:
            for candidate in (temporary_path, blob_path if not committed else None):
                if candidate is None:
                    continue
                try:
                    os.unlink(candidate)
                except FileNotFoundError:
                    pass

    @contextmanager
    def open_raw_at_generation(self, session_key: str, generation: int, seq: int):
        """Open raw bytes after checking their session, generation, and seq.

        External records stay file-backed so the caller can stream them with a
        fixed buffer. No storage name or path leaves this class.
        """
        stream = None
        byte_count = 0
        checksum = None
        with self._lock, self._connect() as conn:
            generation_row = conn.execute(
                "SELECT generation FROM ingest_cursors WHERE session_key=?",
                (session_key,),
            ).fetchone()
            current = max(1, int(generation_row["generation"])) if generation_row else 1
            if int(generation) == current:
                row = conn.execute(
                    "SELECT raw FROM session_events WHERE session_key=? AND seq=?",
                    (session_key, int(seq)),
                ).fetchone()
                if row is not None and row["raw"] is not None:
                    body = str(row["raw"]).encode("utf-8", errors="replace")
                    stream = io.BytesIO(body)
                    byte_count = len(body)
                    checksum = hashlib.sha256(body).hexdigest()
                elif row is not None:
                    blob = conn.execute(
                        "SELECT blob_name, byte_count, sha256 "
                        "FROM session_event_raw_blobs "
                        "WHERE session_key=? AND generation=? AND seq=?",
                        (session_key, current, int(seq)),
                    ).fetchone()
                    if blob is not None:
                        byte_count = int(blob["byte_count"])
                        checksum = str(blob["sha256"])
                        stream = self._open_blob_for_read(
                            str(blob["blob_name"]), byte_count
                        )
        try:
            yield current, stream, byte_count, checksum
        finally:
            if stream is not None:
                stream.close()

    def read(self, session_key: str, since_seq: int = 0, limit: int = 500) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT seq, ingested_at, kind, payload, raw FROM session_events"
                " WHERE session_key=? AND seq>? ORDER BY seq ASC LIMIT ?",
                (session_key, int(since_seq), max(1, int(limit))),
            ).fetchall()
        return self._decode_rows(rows)

    def read_at_generation(self, session_key: str, generation: int,
                           since_seq: int = 0, limit: int = 500) -> tuple[int, list[dict]]:
        """Check generation and read rows in one locked transaction. This
        prevents a rebuilt seq from being mistaken for the row a client saw."""
        with self._lock, self._connect() as conn:
            generation_row = conn.execute(
                "SELECT generation FROM ingest_cursors WHERE session_key=?",
                (session_key,),
            ).fetchone()
            current = max(1, int(generation_row["generation"])) if generation_row else 1
            if int(generation) != current:
                return current, []
            rows = conn.execute(
                "SELECT seq, ingested_at, kind, payload, raw FROM session_events"
                " WHERE session_key=? AND seq>? ORDER BY seq ASC LIMIT ?",
                (session_key, int(since_seq), max(1, int(limit))),
            ).fetchall()
        return current, self._decode_rows(rows)

    def read_with_generation(self, session_key: str, since_seq: int = 0,
                             limit: int = 500) -> tuple[int, list[dict], int]:
        """Read the generation, page, and last seq from one transaction."""
        with self._lock, self._connect() as conn:
            generation_row = conn.execute(
                "SELECT generation FROM ingest_cursors WHERE session_key=?",
                (session_key,),
            ).fetchone()
            generation = max(1, int(generation_row["generation"])) if generation_row else 1
            rows = conn.execute(
                "SELECT seq, ingested_at, kind, payload, raw FROM session_events"
                " WHERE session_key=? AND seq>? ORDER BY seq ASC LIMIT ?",
                (session_key, int(since_seq), max(1, int(limit))),
            ).fetchall()
            last_row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS last FROM session_events WHERE session_key=?",
                (session_key,),
            ).fetchone()
        return generation, self._decode_rows(rows), int(last_row["last"])

    def read_with_generation_bounded(
        self,
        session_key: str,
        since_seq: int = 0,
        limit: int = 500,
        source_byte_limit: int = 8 * 1024 * 1024,
    ) -> tuple[int, list[dict], int, int, bool]:
        """Read a forward page without first materializing every large row.

        The byte limit applies to the SQLite payload and raw columns before
        JSON decoding. One row is always allowed so a single large provider
        record cannot leave the cursor stuck forever.
        """
        row_limit = max(1, int(limit))
        byte_limit = max(1, int(source_byte_limit))
        with self._lock, self._connect() as conn:
            generation_row = conn.execute(
                "SELECT generation FROM ingest_cursors WHERE session_key=?",
                (session_key,),
            ).fetchone()
            generation = max(1, int(generation_row["generation"])) if generation_row else 1
            cursor = conn.execute(
                "SELECT seq, ingested_at, kind, payload, raw, "
                "length(CAST(payload AS BLOB)) + "
                "COALESCE(length(CAST(raw AS BLOB)), 0) AS source_bytes "
                "FROM session_events WHERE session_key=? AND seq>? "
                "ORDER BY seq ASC LIMIT ?",
                (session_key, int(since_seq), row_limit + 1),
            )
            selected = []
            selected_bytes = 0
            source_limited = False
            while len(selected) < row_limit:
                row = cursor.fetchone()
                if row is None:
                    break
                row_bytes = max(0, int(row["source_bytes"] or 0))
                if selected and selected_bytes + row_bytes > byte_limit:
                    source_limited = True
                    break
                selected.append(row)
                selected_bytes += row_bytes
            if not source_limited and len(selected) >= row_limit:
                source_limited = cursor.fetchone() is not None
            last_row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS last FROM session_events WHERE session_key=?",
                (session_key,),
            ).fetchone()
        return (
            generation,
            self._decode_rows(selected),
            int(last_row["last"]),
            selected_bytes,
            source_limited,
        )

    def read_history_page_bounded(
        self,
        session_key: str,
        since_seq: int = 0,
        limit: int = 500,
        source_byte_limit: int = 8 * 1024 * 1024,
    ) -> tuple[int, list[dict], int, int, bool]:
        """Read the suffix of one requested history range within a byte cap.

        History pages must keep the rows nearest the phone's current oldest
        row. Reading in descending order lets SQLite stop before older large
        rows are decoded, then the result is reversed back to transcript order.
        """
        row_limit = max(1, int(limit))
        byte_limit = max(1, int(source_byte_limit))
        start = max(0, int(since_seq))
        end = start + row_limit
        with self._lock, self._connect() as conn:
            generation_row = conn.execute(
                "SELECT generation FROM ingest_cursors WHERE session_key=?",
                (session_key,),
            ).fetchone()
            generation = max(1, int(generation_row["generation"])) if generation_row else 1
            cursor = conn.execute(
                "SELECT seq, ingested_at, kind, payload, raw, "
                "length(CAST(payload AS BLOB)) + "
                "COALESCE(length(CAST(raw AS BLOB)), 0) AS source_bytes "
                "FROM session_events WHERE session_key=? AND seq>? AND seq<=? "
                "ORDER BY seq DESC LIMIT ?",
                (session_key, start, end, row_limit + 1),
            )
            selected = []
            selected_bytes = 0
            source_limited = False
            while len(selected) < row_limit:
                row = cursor.fetchone()
                if row is None:
                    break
                row_bytes = max(0, int(row["source_bytes"] or 0))
                if selected and selected_bytes + row_bytes > byte_limit:
                    source_limited = True
                    break
                selected.append(row)
                selected_bytes += row_bytes
            if not source_limited and len(selected) >= row_limit:
                source_limited = cursor.fetchone() is not None
            last_row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS last FROM session_events WHERE session_key=?",
                (session_key,),
            ).fetchone()
        selected.reverse()
        return (
            generation,
            self._decode_rows(selected),
            int(last_row["last"]),
            selected_bytes,
            source_limited,
        )

    @staticmethod
    def _decode_rows(rows) -> list[dict]:
        result = []
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except Exception:
                payload = {}
            result.append({
                "seq": int(row["seq"]),
                "ingested_at": float(row["ingested_at"]),
                "kind": row["kind"],
                "payload": payload,
                "raw": row["raw"],
            })
        return result

    def last_seq(self, session_key: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS last FROM session_events WHERE session_key=?",
                (session_key,),
            ).fetchone()
            return int(row["last"])

    def get_ingest_offset(self, session_key: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT byte_offset FROM ingest_cursors WHERE session_key=?",
                (session_key,),
            ).fetchone()
            return int(row["byte_offset"]) if row else 0

    def reconcile_ingest_source(self, session_key: str, source_identity: tuple[int, int],
                                *, observed_size: int, force_reset: bool = False) -> tuple[int, int | None]:
        """Bind a cursor to the opened source file and detect replacements.

        Source identity lives beside the byte cursor so a daemon restart does
        not forget which inode produced the existing durable rows. A changed
        inode, a truncated file, or an explicit rotation resets the log before
        any bytes from the new source can be mixed into the old generation.
        """
        source_dev, source_ino = (int(source_identity[0]), int(source_identity[1]))
        blob_names: list[str] = []
        result: tuple[int, int | None]
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT byte_offset, generation, source_dev, source_ino "
                    "FROM ingest_cursors WHERE session_key=?",
                    (session_key,),
                ).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO ingest_cursors "
                        "(session_key, byte_offset, parser_version, generation, source_dev, source_ino) "
                        "VALUES (?, 0, 1, 1, ?, ?)",
                        (session_key, source_dev, source_ino),
                    )
                    conn.commit()
                    result = (0, None)
                else:
                    offset = int(row["byte_offset"])
                    stored_identity = None
                    if row["source_dev"] is not None and row["source_ino"] is not None:
                        stored_identity = (int(row["source_dev"]), int(row["source_ino"]))
                    must_reset = (
                        bool(force_reset)
                        or offset > max(0, int(observed_size))
                        or (stored_identity is not None and stored_identity != (source_dev, source_ino))
                    )
                    if must_reset:
                        generation = max(1, int(row["generation"])) + 1
                        blob_names = self._blob_names_for_session(conn, session_key)
                        conn.execute(
                            "DELETE FROM session_event_raw_blobs WHERE session_key=?",
                            (session_key,),
                        )
                        conn.execute("DELETE FROM session_events WHERE session_key=?", (session_key,))
                        self._clear_usage_locked(conn, session_key)
                        conn.execute(
                            "UPDATE ingest_cursors SET byte_offset=0, generation=?, source_dev=?, source_ino=? "
                            "WHERE session_key=?",
                            (generation, source_dev, source_ino, session_key),
                        )
                        conn.commit()
                        result = (0, generation)
                    else:
                        if stored_identity is None:
                            conn.execute(
                                "UPDATE ingest_cursors SET source_dev=?, source_ino=? WHERE session_key=?",
                                (source_dev, source_ino, session_key),
                            )
                            conn.commit()
                        result = (offset, None)
            self._remove_blob_files(blob_names)
        return result

    def get_generation(self, session_key: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT generation FROM ingest_cursors WHERE session_key=?",
                (session_key,),
            ).fetchone()
            return max(1, int(row["generation"])) if row else 1

    def prepare_ingest(self, session_key: str, parser_version: int) -> int:
        """Return the cursor for this parser. A parser change rebuilds the
        session log from byte zero so newly supported provider records also
        appear in existing sessions."""
        version = max(1, int(parser_version))
        blob_names: list[str] = []
        result = 0
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT byte_offset, parser_version, generation FROM ingest_cursors WHERE session_key=?",
                    (session_key,),
                ).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO ingest_cursors "
                        "(session_key, byte_offset, parser_version, generation) VALUES (?, 0, ?, 1)",
                        (session_key, version),
                    )
                    conn.commit()
                elif int(row["parser_version"]) == version:
                    result = int(row["byte_offset"])
                else:
                    blob_names = self._blob_names_for_session(conn, session_key)
                    conn.execute(
                        "DELETE FROM session_event_raw_blobs WHERE session_key=?",
                        (session_key,),
                    )
                    conn.execute("DELETE FROM session_events WHERE session_key=?", (session_key,))
                    self._clear_usage_locked(conn, session_key)
                    conn.execute(
                        "UPDATE ingest_cursors SET byte_offset=0, parser_version=?, generation=? "
                        "WHERE session_key=?",
                        (version, max(1, int(row["generation"])) + 1, session_key),
                    )
                    conn.commit()
            self._remove_blob_files(blob_names)
        return result

    def reset_ingest(self, session_key: str) -> int:
        """Atomically discard mixed history after a source rewrite and move
        the generation forward so every connected or resumed reader resets."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT generation FROM ingest_cursors WHERE session_key=?",
                    (session_key,),
                ).fetchone()
                generation = max(1, int(row["generation"])) + 1 if row else 2
                blob_names = self._blob_names_for_session(conn, session_key)
                conn.execute(
                    "DELETE FROM session_event_raw_blobs WHERE session_key=?",
                    (session_key,),
                )
                conn.execute("DELETE FROM session_events WHERE session_key=?", (session_key,))
                self._clear_usage_locked(conn, session_key)
                if row is None:
                    conn.execute(
                        "INSERT INTO ingest_cursors "
                        "(session_key, byte_offset, parser_version, generation) VALUES (?, 0, 1, ?)",
                        (session_key, generation),
                    )
                else:
                    conn.execute(
                        "UPDATE ingest_cursors SET byte_offset=0, generation=?, source_dev=NULL, source_ino=NULL "
                        "WHERE session_key=?",
                        (generation, session_key),
                    )
                conn.commit()
            self._remove_blob_files(blob_names)
        return generation

    def set_ingest_offset(self, session_key: str, byte_offset: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO ingest_cursors (session_key, byte_offset) VALUES (?, ?)"
                " ON CONFLICT(session_key) DO UPDATE SET byte_offset=excluded.byte_offset",
                (session_key, int(byte_offset)),
            )
            conn.commit()

    def purge_session(self, session_key: str) -> dict:
        """Remove every durable event and ingest identity for one session."""
        checkpoint_error = None
        blob_cleanup_error = None
        with self._lock:
            with self._connect() as conn:
                conn.execute("PRAGMA secure_delete=ON")
                event_count = int(conn.execute(
                    "SELECT COUNT(*) AS count FROM session_events WHERE session_key=?",
                    (session_key,),
                ).fetchone()["count"])
                cursor_count = int(conn.execute(
                    "SELECT COUNT(*) AS count FROM ingest_cursors WHERE session_key=?",
                    (session_key,),
                ).fetchone()["count"])
                blob_names = self._blob_names_for_session(conn, session_key)
                conn.execute(
                    "DELETE FROM session_event_raw_blobs WHERE session_key=?",
                    (session_key,),
                )
                conn.execute("DELETE FROM session_events WHERE session_key=?", (session_key,))
                self._clear_usage_locked(conn, session_key)
                conn.execute("DELETE FROM ingest_cursors WHERE session_key=?", (session_key,))
                conn.commit()
                try:
                    checkpoint = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                    if checkpoint is not None and int(checkpoint[0] or 0) != 0:
                        checkpoint_error = sqlite3.OperationalError(
                            "session event log WAL is busy; secure purge is incomplete"
                        )
                except sqlite3.Error as error:
                    checkpoint_error = error
            try:
                self._remove_blob_files(blob_names)
            except OSError as error:
                blob_cleanup_error = error
        if checkpoint_error is not None:
            if blob_cleanup_error is not None:
                raise sqlite3.OperationalError(
                    "session event log checkpoint and raw cleanup are incomplete"
                ) from blob_cleanup_error
            raise checkpoint_error
        if blob_cleanup_error is not None:
            raise blob_cleanup_error
        return {"events": event_count, "cursors": cursor_count}
