"""Durable per-session event log and the provider-neutral schema (contract v2).

Phase 2 of the session viewer evolution. Provider adapters parse transcript
lines ONCE on the Mac into neutral events; everything downstream (live
streams, archive reads, search, export, push triggers) reads this log, so
live and history stop being two code paths. The raw provider line rides
along on the first event parsed from it. Inline attachment bytes are redacted
from that copy because the source transcript remains their canonical store.

Neutral kinds: block_text, block_thinking, tool_call, tool_result,
lifecycle, plus PARTIAL_TEXT_KIND reserved for managed sessions that can
stream token deltas. Interactive sessions can never emit partial_text from
the file adapter, because a JSONL line does not exist until it is complete.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

PARTIAL_TEXT_KIND = "partial_text"
VISIBLE_BLOCK_TEXT_MAX = 2048

KINDS = (
    "block_text",
    "block_thinking",
    "tool_call",
    "tool_result",
    "lifecycle",
    PARTIAL_TEXT_KIND,
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
                block_content = block.get("content")
                if not isinstance(block_content, str):
                    block_content = json.dumps(block_content, ensure_ascii=False)
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

    def __init__(self, db_path) -> None:
        self._db_path = str(db_path)
        self._lock = threading.Lock()
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
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS last FROM session_events WHERE session_key=?",
                (session_key,),
            ).fetchone()
            seq = int(row["last"])
            for event in events:
                seq += 1
                payload = {k: v for k, v in event.items() if k != "raw"}
                conn.execute(
                    "INSERT INTO session_events (session_key, seq, ingested_at, kind, payload, raw)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (session_key, seq, now, str(event.get("kind") or "lifecycle"),
                     json.dumps(payload, ensure_ascii=False), event.get("raw")),
                )
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
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS last FROM session_events WHERE session_key=?",
                (session_key,),
            ).fetchone()
            seq = int(row["last"])
            for event in events:
                seq += 1
                payload = {k: v for k, v in event.items() if k != "raw"}
                conn.execute(
                    "INSERT INTO session_events (session_key, seq, ingested_at, kind, payload, raw)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (session_key, seq, now, str(event.get("kind") or "lifecycle"),
                     json.dumps(payload, ensure_ascii=False), event.get("raw")),
                )
            conn.execute(
                "INSERT INTO ingest_cursors (session_key, byte_offset) VALUES (?, ?)"
                " ON CONFLICT(session_key) DO UPDATE SET byte_offset=excluded.byte_offset",
                (session_key, int(byte_offset)),
            )
            conn.commit()
            return seq

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
        with self._lock, self._connect() as conn:
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
                return 0, None

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
                conn.execute("DELETE FROM session_events WHERE session_key=?", (session_key,))
                conn.execute(
                    "UPDATE ingest_cursors SET byte_offset=0, generation=?, source_dev=?, source_ino=? "
                    "WHERE session_key=?",
                    (generation, source_dev, source_ino, session_key),
                )
                conn.commit()
                return 0, generation
            if stored_identity is None:
                conn.execute(
                    "UPDATE ingest_cursors SET source_dev=?, source_ino=? WHERE session_key=?",
                    (source_dev, source_ino, session_key),
                )
                conn.commit()
            return offset, None

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
        with self._lock, self._connect() as conn:
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
                return 0
            if int(row["parser_version"]) == version:
                return int(row["byte_offset"])
            conn.execute("DELETE FROM session_events WHERE session_key=?", (session_key,))
            conn.execute(
                "UPDATE ingest_cursors SET byte_offset=0, parser_version=?, generation=? "
                "WHERE session_key=?",
                (version, max(1, int(row["generation"])) + 1, session_key),
            )
            conn.commit()
            return 0

    def reset_ingest(self, session_key: str) -> int:
        """Atomically discard mixed history after a source rewrite and move
        the generation forward so every connected or resumed reader resets."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT generation FROM ingest_cursors WHERE session_key=?",
                (session_key,),
            ).fetchone()
            generation = max(1, int(row["generation"])) + 1 if row else 2
            conn.execute("DELETE FROM session_events WHERE session_key=?", (session_key,))
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
        with self._lock, self._connect() as conn:
            conn.execute("PRAGMA secure_delete=ON")
            event_count = int(conn.execute(
                "SELECT COUNT(*) AS count FROM session_events WHERE session_key=?",
                (session_key,),
            ).fetchone()["count"])
            cursor_count = int(conn.execute(
                "SELECT COUNT(*) AS count FROM ingest_cursors WHERE session_key=?",
                (session_key,),
            ).fetchone()["count"])
            conn.execute("DELETE FROM session_events WHERE session_key=?", (session_key,))
            conn.execute("DELETE FROM ingest_cursors WHERE session_key=?", (session_key,))
            conn.commit()
            checkpoint = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint is not None and int(checkpoint[0] or 0) != 0:
                raise sqlite3.OperationalError(
                    "session event log WAL is busy; secure purge is incomplete"
                )
        return {"events": event_count, "cursors": cursor_count}
