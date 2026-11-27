"""Durable, privacy-bounded cross-session coding-agent activity projection.

The canonical payload remains in the provider-neutral session event stores.
This module retains only bounded/redacted list and search material plus exact
session/generation/sequence locators for deliberate content retrieval.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager
from typing import Any, Iterable

SCHEMA_VERSION = 1
PREVIEW_LIMIT = 2_048
SUMMARY_LIMIT = 320
SEARCH_LIMIT = 4_096
MAX_PAGE = 100
VALID_CATEGORIES = {"tool", "edit", "error", "thinking"}
VALID_STATUSES = {"running", "succeeded", "failed", "unknown"}
EDIT_TOOLS = {
    "apply_patch", "edit", "multiedit", "multi_edit", "write", "write_file",
    "create_file", "delete_file", "str_replace_editor", "notebookedit",
}
SENSITIVE_KEY = re.compile(
    r"(?:^|_)(?:api_?key|authorization|cookie|credential|passwd|password|private_?key|secret|token)(?:$|_)",
    re.IGNORECASE,
)
SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*=\s*([^\s]+)"
)


def _bounded(value: Any, limit: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            value = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        except (TypeError, ValueError):
            value = str(value)
    value = value.replace("\x00", "")
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 3)] + "..."


def _redact_text(value: str) -> str:
    home = str(Path.home())
    if home and home != "/":
        value = value.replace(home, "~")
    value = SENSITIVE_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)
    value = re.sub(
        r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+",
        r"\1[REDACTED]",
        value,
    )
    value = re.sub(r"data:[^;,\s]+;base64,[A-Za-z0-9+/=]{32,}", "[inline data omitted]", value)
    return value


def _redact(value: Any, key: str = "") -> Any:
    if SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item, key) for item in value[:32]]
    if isinstance(value, str):
        if value.startswith("data:"):
            return f"[inline data omitted: {len(value)} chars]"
        return _redact_text(value)
    return value


def _safe_json(value: Any, limit: int = PREVIEW_LIMIT) -> str:
    try:
        text = json.dumps(_redact(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError):
        text = _redact_text(str(value))
    return _bounded(text, limit)

def _json_byte_count(value: Any) -> int:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        text = str(value)
    return len(text.encode("utf-8", errors="replace"))


def _epoch(value: Any, fallback: float) -> float:
    if isinstance(value, (int, float)) and float(value) > 0:
        return float(value)
    if isinstance(value, str) and value:
        text = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            return datetime.fromisoformat(text).timestamp()
        except ValueError:
            pass
    return float(fallback)


def _activity_id(session_key: str, generation: int, identity: str) -> str:
    material = f"{session_key}\0{generation}\0{identity}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _provider_from_session(session_key: str) -> str:
    provider, separator, _native = session_key.partition(":")
    return provider.lower() if separator else "unknown"


def _project_identity(project: str | None) -> tuple[str | None, str]:
    if not project:
        return None, "Unknown project"
    normalized = str(Path(project).expanduser())
    project_id = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:24]
    name = Path(normalized).name or normalized
    return project_id, _bounded(name, 160)


def _tool_summary(name: str, value: Any) -> str:
    if isinstance(value, dict):
        for key, label in (
            ("command", "Command"), ("cmd", "Command"), ("file_path", "File"),
            ("path", "Path"), ("target", "Target"), ("cwd", "Directory"),
            ("workdir", "Directory"), ("pattern", "Pattern"),
        ):
            candidate = value.get(key)
            if candidate not in (None, ""):
                return _bounded(f"{label}: {_redact_text(str(candidate))}", SUMMARY_LIMIT)
    return _bounded(f"{name} call", SUMMARY_LIMIT)


def _output_summary(content: Any, failed: bool) -> str:
    text = _redact_text(_bounded(content, PREVIEW_LIMIT))
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    if first:
        return _bounded(first, SUMMARY_LIMIT)
    return "Tool failed without output." if failed else "Tool completed without output."


class AgentActivityStore:
    """SQLite projection queried by the production Activity tab."""

    def __init__(self, db_path: str | Path):
        self._db_path = str(Path(db_path).expanduser())
        self._lock = threading.RLock()
        self._fts = False
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def _connection(self):
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        with self._lock, self._connection() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS agent_activity_sessions ("
                " session_key TEXT PRIMARY KEY, provider_id TEXT NOT NULL, native_id TEXT NOT NULL,"
                " project_id TEXT, project_name TEXT NOT NULL, generation INTEGER NOT NULL,"
                " indexed_seq INTEGER NOT NULL DEFAULT 0, updated_at REAL NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS agent_activity_items ("
                " id TEXT PRIMARY KEY, session_key TEXT NOT NULL, generation INTEGER NOT NULL,"
                " provider_id TEXT NOT NULL, project_id TEXT, project_name TEXT NOT NULL,"
                " category TEXT NOT NULL, status TEXT NOT NULL, call_id TEXT, tool_name TEXT,"
                " call_seq INTEGER, result_seq INTEGER, target_seq INTEGER NOT NULL,"
                " occurred_at REAL NOT NULL, completed_at REAL, duration_ms INTEGER,"
                " title TEXT NOT NULL, summary TEXT, input_preview TEXT, input_bytes INTEGER,"
                " output_preview TEXT, output_bytes INTEGER, search_text TEXT NOT NULL,"
                " updated_version INTEGER NOT NULL,"
                " FOREIGN KEY(session_key) REFERENCES agent_activity_sessions(session_key) ON DELETE CASCADE)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent_activity_time "
                "ON agent_activity_items(occurred_at DESC, id DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent_activity_scope "
                "ON agent_activity_items(provider_id, category, occurred_at DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent_activity_session "
                "ON agent_activity_items(session_key, generation, target_seq)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS agent_activity_meta ("
                " key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            conn.execute(
                "INSERT OR IGNORE INTO agent_activity_meta(key, value) VALUES"
                " ('version', '0'), ('index_state', 'backfilling'), ('indexed_through', '0'),"
                " ('index_message', '')"
            )
            try:
                conn.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS agent_activity_fts USING fts5("
                    " search_text, content='agent_activity_items', content_rowid='rowid')"
                )
                conn.executescript(
                    "CREATE TRIGGER IF NOT EXISTS agent_activity_ai AFTER INSERT ON agent_activity_items BEGIN "
                    " INSERT INTO agent_activity_fts(rowid, search_text) VALUES (new.rowid, new.search_text); END;"
                    "CREATE TRIGGER IF NOT EXISTS agent_activity_ad AFTER DELETE ON agent_activity_items BEGIN "
                    " INSERT INTO agent_activity_fts(agent_activity_fts, rowid, search_text)"
                    " VALUES('delete', old.rowid, old.search_text); END;"
                    "CREATE TRIGGER IF NOT EXISTS agent_activity_au AFTER UPDATE ON agent_activity_items BEGIN "
                    " INSERT INTO agent_activity_fts(agent_activity_fts, rowid, search_text)"
                    " VALUES('delete', old.rowid, old.search_text);"
                    " INSERT INTO agent_activity_fts(rowid, search_text) VALUES (new.rowid, new.search_text); END;"
                )
                self._fts = True
            except sqlite3.OperationalError:
                self._fts = False

    @staticmethod
    def _meta(conn: sqlite3.Connection, key: str, default: str = "") -> str:
        row = conn.execute("SELECT value FROM agent_activity_meta WHERE key=?", (key,)).fetchone()
        return str(row["value"]) if row is not None else default

    @classmethod
    def _next_version(cls, conn: sqlite3.Connection) -> int:
        version = int(cls._meta(conn, "version", "0")) + 1
        conn.execute(
            "INSERT INTO agent_activity_meta(key, value) VALUES('version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(version),),
        )
        return version

    def set_index_state(self, state: str, *, indexed_through: float = 0, message: str = "") -> None:
        if state not in {"ready", "backfilling", "degraded"}:
            raise ValueError("invalid activity index state")
        with self._lock, self._connection() as conn:
            version = self._next_version(conn)
            values = {
                "index_state": state,
                "indexed_through": str(max(0.0, float(indexed_through))),
                "index_message": _bounded(message, 240),
                "index_version": str(version),
            }
            for key, value in values.items():
                conn.execute(
                    "INSERT INTO agent_activity_meta(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, value),
                )

    def register_session(
        self,
        session_key: str,
        *,
        provider_id: str | None = None,
        native_id: str | None = None,
        project: str | None = None,
        generation: int = 1,
    ) -> None:
        provider = (provider_id or _provider_from_session(session_key)).strip().lower() or "unknown"
        native = native_id or session_key.partition(":")[2] or session_key
        project_id, project_name = _project_identity(project)
        generation = max(1, int(generation))
        now = time.time()
        with self._lock, self._connection() as conn:
            prior = conn.execute(
                "SELECT generation FROM agent_activity_sessions WHERE session_key=?", (session_key,)
            ).fetchone()
            if prior is not None and int(prior["generation"]) != generation:
                conn.execute("DELETE FROM agent_activity_items WHERE session_key=?", (session_key,))
            conn.execute(
                "INSERT INTO agent_activity_sessions("
                " session_key, provider_id, native_id, project_id, project_name, generation, indexed_seq, updated_at)"
                " VALUES(?, ?, ?, ?, ?, ?, 0, ?) ON CONFLICT(session_key) DO UPDATE SET"
                " provider_id=excluded.provider_id, native_id=excluded.native_id,"
                " project_id=COALESCE(excluded.project_id, agent_activity_sessions.project_id),"
                " project_name=CASE WHEN excluded.project_id IS NULL THEN agent_activity_sessions.project_name"
                " ELSE excluded.project_name END,"
                " indexed_seq=CASE WHEN agent_activity_sessions.generation<>excluded.generation"
                " THEN 0 ELSE agent_activity_sessions.indexed_seq END,"
                " generation=excluded.generation, updated_at=excluded.updated_at",
                (
                    session_key,
                    provider,
                    native,
                    project_id,
                    project_name,
                    generation,
                    now,
                ),
            )

    def remove_session(self, session_key: str) -> None:
        with self._lock, self._connection() as conn:
            exists = conn.execute(
                "SELECT 1 FROM agent_activity_sessions WHERE session_key=?",
                (session_key,),
            ).fetchone()
            if exists is None:
                return
            conn.execute(
                "DELETE FROM agent_activity_sessions WHERE session_key=?",
                (session_key,),
            )
            self._next_version(conn)

    def indexed_seq(self, session_key: str, generation: int) -> int:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT indexed_seq, generation FROM agent_activity_sessions WHERE session_key=?",
                (session_key,),
            ).fetchone()
        if row is None or int(row["generation"]) != int(generation):
            return 0
        return max(0, int(row["indexed_seq"]))

    def project_events(
        self,
        session_key: str,
        generation: int,
        events: Iterable[dict[str, Any]],
        *,
        provider_id: str | None = None,
        native_id: str | None = None,
        project: str | None = None,
    ) -> int:
        self.register_session(
            session_key,
            provider_id=provider_id,
            native_id=native_id,
            project=project,
            generation=generation,
        )
        projected = 0
        last_seq = self.indexed_seq(session_key, generation)
        with self._lock, self._connection() as conn:
            session = conn.execute(
                "SELECT * FROM agent_activity_sessions WHERE session_key=?", (session_key,)
            ).fetchone()
            assert session is not None
            for event in events:
                seq = max(0, int(event.get("seq") or 0))
                if seq <= last_seq:
                    continue
                kind = str(event.get("kind") or "")
                payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
                observed = _epoch(payload.get("ts"), float(event.get("ingested_at") or time.time()))
                if kind == "tool_call":
                    self._project_call(conn, session, generation, seq, observed, payload)
                    projected += 1
                elif kind == "tool_result":
                    self._project_result(conn, session, generation, seq, observed, payload)
                    projected += 1
                elif kind == "block_thinking":
                    self._project_thinking(conn, session, generation, seq, observed, payload)
                    projected += 1
                elif kind == "lifecycle" and str(payload.get("subtype") or "").lower() in {
                    "error", "failed", "failure", "unparsed", "oversized_line",
                }:
                    self._project_lifecycle_error(conn, session, generation, seq, observed, payload)
                    projected += 1
                last_seq = max(last_seq, seq)
            conn.execute(
                "UPDATE agent_activity_sessions SET indexed_seq=?, updated_at=? WHERE session_key=?",
                (last_seq, time.time(), session_key),
            )
        return projected

    def _base_values(self, session: sqlite3.Row, generation: int) -> dict[str, Any]:
        return {
            "session_key": str(session["session_key"]),
            "generation": generation,
            "provider_id": str(session["provider_id"]),
            "project_id": session["project_id"],
            "project_name": str(session["project_name"]),
        }

    def _upsert(self, conn: sqlite3.Connection, values: dict[str, Any]) -> None:
        version = self._next_version(conn)
        values["updated_version"] = version
        columns = (
            "id", "session_key", "generation", "provider_id", "project_id", "project_name",
            "category", "status", "call_id", "tool_name", "call_seq", "result_seq",
            "target_seq", "occurred_at", "completed_at", "duration_ms", "title", "summary",
            "input_preview", "input_bytes", "output_preview", "output_bytes", "search_text",
            "updated_version",
        )
        placeholders = ",".join("?" for _ in columns)
        updates = ",".join(f"{column}=excluded.{column}" for column in columns if column != "id")
        conn.execute(
            f"INSERT INTO agent_activity_items({','.join(columns)}) VALUES({placeholders}) "
            f"ON CONFLICT(id) DO UPDATE SET {updates}",
            tuple(values.get(column) for column in columns),
        )

    def _project_call(
        self, conn: sqlite3.Connection, session: sqlite3.Row, generation: int,
        seq: int, observed: float, payload: dict[str, Any],
    ) -> None:
        name = _bounded(payload.get("name") or "Tool", 160)
        normalized_name = name.lower().replace(" ", "_")
        category = "edit" if normalized_name in EDIT_TOOLS else "tool"
        call_id = _bounded(payload.get("call_id") or f"seq-{seq}", 256)
        input_value = payload.get("input")
        input_preview = _safe_json(input_value)
        input_bytes = payload.get("input_bytes")
        if not isinstance(input_bytes, int):
            input_bytes = _json_byte_count(input_value)
        summary = _tool_summary(name, _redact(input_value))
        title = f"Edited with {name}" if category == "edit" else name
        identity = f"call:{call_id}:{seq}"
        values = {
            **self._base_values(session, generation),
            "id": _activity_id(str(session["session_key"]), generation, identity),
            "category": category,
            "status": "running",
            "call_id": call_id,
            "tool_name": name,
            "call_seq": seq,
            "result_seq": None,
            "target_seq": seq,
            "occurred_at": observed,
            "completed_at": None,
            "duration_ms": None,
            "title": _bounded(title, 200),
            "summary": summary,
            "input_preview": input_preview,
            "input_bytes": max(0, int(input_bytes)),
            "output_preview": None,
            "output_bytes": None,
        }
        values["search_text"] = _bounded(
            " ".join(filter(None, [name, title, summary, input_preview, str(session["project_name"])])),
            SEARCH_LIMIT,
        )
        self._upsert(conn, values)

    def _project_result(
        self, conn: sqlite3.Connection, session: sqlite3.Row, generation: int,
        seq: int, observed: float, payload: dict[str, Any],
    ) -> None:
        call_id = _bounded(payload.get("call_id") or "", 256)
        call = conn.execute(
            "SELECT * FROM agent_activity_items WHERE session_key=? AND generation=? AND call_id=? "
            "ORDER BY call_seq DESC LIMIT 1",
            (session["session_key"], generation, call_id),
        ).fetchone() if call_id else None
        failed = bool(payload.get("is_error"))
        content = payload.get("content")
        output_preview = _bounded(_redact_text(str(content or "")), PREVIEW_LIMIT)
        output_bytes = payload.get("content_bytes")
        if not isinstance(output_bytes, int):
            output_bytes = len(str(content or "").encode("utf-8"))
        if call is not None:
            occurred = float(call["occurred_at"])
            duration = max(0, int((observed - occurred) * 1000))
            category = str(call["category"])
            title = str(call["title"])
            summary = _output_summary(content, failed)
            values = {column: call[column] for column in call.keys()}
            values.update({
                "status": "failed" if failed else "succeeded",
                "result_seq": seq,
                "target_seq": int(call["call_seq"] or seq),
                "completed_at": observed,
                "duration_ms": duration,
                "summary": summary,
                "output_preview": output_preview,
                "output_bytes": max(0, int(output_bytes)),
            })
            values["search_text"] = _bounded(
                " ".join(filter(None, [str(call["search_text"]), summary, output_preview])),
                SEARCH_LIMIT,
            )
            self._upsert(conn, values)
            return
        summary = _output_summary(content, failed)
        values = {
            **self._base_values(session, generation),
            "id": _activity_id(str(session["session_key"]), generation, f"orphan-result:{seq}"),
            "category": "error" if failed else "tool",
            "status": "failed" if failed else "unknown",
            "call_id": call_id or None,
            "tool_name": None,
            "call_seq": None,
            "result_seq": seq,
            "target_seq": seq,
            "occurred_at": observed,
            "completed_at": observed,
            "duration_ms": None,
            "title": "Unmatched tool result",
            "summary": summary,
            "input_preview": None,
            "input_bytes": None,
            "output_preview": output_preview,
            "output_bytes": max(0, int(output_bytes)),
            "search_text": _bounded(f"Unmatched tool result {summary} {output_preview}", SEARCH_LIMIT),
        }
        self._upsert(conn, values)

    def _project_thinking(
        self, conn: sqlite3.Connection, session: sqlite3.Row, generation: int,
        seq: int, observed: float, payload: dict[str, Any],
    ) -> None:
        text = _bounded(_redact_text(str(payload.get("text") or "")), PREVIEW_LIMIT)
        summary = _bounded(" ".join(text.split()), SUMMARY_LIMIT) or "Thinking"
        values = {
            **self._base_values(session, generation),
            "id": _activity_id(str(session["session_key"]), generation, f"thinking:{seq}"),
            "category": "thinking", "status": "succeeded", "call_id": None,
            "tool_name": None, "call_seq": None, "result_seq": None, "target_seq": seq,
            "occurred_at": observed, "completed_at": observed, "duration_ms": None,
            "title": "Thinking", "summary": summary, "input_preview": None,
            "input_bytes": None, "output_preview": text,
            "output_bytes": max(0, int(payload.get("text_bytes") or len(str(payload.get("text") or "").encode("utf-8")))),
            "search_text": _bounded(f"Thinking {summary} {text} {session['project_name']}", SEARCH_LIMIT),
        }
        self._upsert(conn, values)

    def _project_lifecycle_error(
        self, conn: sqlite3.Connection, session: sqlite3.Row, generation: int,
        seq: int, observed: float, payload: dict[str, Any],
    ) -> None:
        subtype = _bounded(payload.get("subtype") or "error", 120)
        summary = _bounded(_redact_text(str(payload.get("text") or payload.get("content") or "")), SUMMARY_LIMIT)
        values = {
            **self._base_values(session, generation),
            "id": _activity_id(str(session["session_key"]), generation, f"error:{seq}"),
            "category": "error", "status": "failed", "call_id": None, "tool_name": None,
            "call_seq": None, "result_seq": None, "target_seq": seq,
            "occurred_at": observed, "completed_at": observed, "duration_ms": None,
            "title": _bounded(subtype.replace("_", " ").title(), 200), "summary": summary,
            "input_preview": None, "input_bytes": None, "output_preview": None,
            "output_bytes": None,
            "search_text": _bounded(f"{subtype} {summary} {session['project_name']}", SEARCH_LIMIT),
        }
        self._upsert(conn, values)

    @staticmethod
    def _encode_cursor(occurred_at: float, item_id: str) -> str:
        raw = json.dumps([float(occurred_at), item_id], separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_cursor(cursor: str | None) -> tuple[float, str] | None:
        if not cursor:
            return None
        try:
            padded = cursor + "=" * (-len(cursor) % 4)
            value = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
            if not isinstance(value, list) or len(value) != 2:
                raise ValueError
            return float(value[0]), str(value[1])
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError, base64.binascii.Error) as exc:
            raise ValueError("invalid activity cursor") from exc

    @staticmethod
    def _fts_query(query: str) -> str:
        tokens = re.findall(r"[\w./:-]+", query, flags=re.UNICODE)[:12]
        return " AND ".join('"' + token.replace('"', '""') + '"' for token in tokens)

    def query(
        self,
        *,
        before: str | None = None,
        limit: int = 50,
        since: float = 0,
        provider: str | None = None,
        category: str | None = None,
        project_id: str | None = None,
        search: str | None = None,
    ) -> dict[str, Any]:
        limit = max(1, min(int(limit), MAX_PAGE))
        if category and category not in VALID_CATEGORIES and category != "all":
            raise ValueError("invalid activity category")
        cursor = self._decode_cursor(before)
        clauses = ["i.occurred_at>=?"]
        args: list[Any] = [max(0.0, float(since))]
        if cursor:
            clauses.append("(i.occurred_at<? OR (i.occurred_at=? AND i.id<?))")
            args.extend([cursor[0], cursor[0], cursor[1]])
        if provider and provider != "all":
            clauses.append("i.provider_id=?")
            args.append(provider.strip().lower())
        if category and category != "all":
            if category == "error":
                clauses.append("(i.category='error' OR i.status='failed')")
            else:
                clauses.append("i.category=?")
                args.append(category)
        if project_id:
            clauses.append("i.project_id=?")
            args.append(project_id)
        join = ""
        query_text = (search or "").strip()
        if query_text:
            fts = self._fts_query(query_text)
            if self._fts and fts:
                join = " JOIN agent_activity_fts f ON f.rowid=i.rowid"
                clauses.append("f.search_text MATCH ?")
                args.append(fts)
            else:
                clauses.append("LOWER(i.search_text) LIKE ?")
                args.append("%" + query_text.lower()[:256] + "%")
        sql = (
            "SELECT i.* FROM agent_activity_items i" + join + " WHERE "
            + " AND ".join(clauses)
            + " ORDER BY i.occurred_at DESC, i.id DESC LIMIT ?"
        )
        args.append(limit + 1)
        with self._lock, self._connection() as conn:
            rows = conn.execute(sql, tuple(args)).fetchall()
            state = self._meta(conn, "index_state", "backfilling")
            indexed_through = float(self._meta(conn, "indexed_through", "0") or 0)
            message = self._meta(conn, "index_message", "")
            version = int(self._meta(conn, "version", "0") or 0)
        has_more = len(rows) > limit
        visible = rows[:limit]
        items = [self._item(row) for row in visible]
        next_cursor = (
            self._encode_cursor(float(visible[-1]["occurred_at"]), str(visible[-1]["id"]))
            if has_more and visible else None
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "items": items,
            "next_cursor": next_cursor,
            "has_more": has_more,
            "index_state": state,
            "indexed_through": indexed_through,
            "index_message": message or None,
            "version": version,
        }

    def changes_after(self, version: int, limit: int = 100) -> dict[str, Any]:
        with self._lock, self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM agent_activity_items WHERE updated_version>? "
                "ORDER BY updated_version ASC LIMIT ?",
                (max(0, int(version)), max(1, min(int(limit), MAX_PAGE))),
            ).fetchall()
            current = int(self._meta(conn, "version", "0") or 0)
            state = self._meta(conn, "index_state", "backfilling")
            indexed_through = float(
                self._meta(conn, "indexed_through", "0") or 0
            )
        return {
            "schema_version": SCHEMA_VERSION,
            "items": [self._item(row) for row in rows],
            "version": current,
            "index_state": state,
            "indexed_through": indexed_through,
        }

    @staticmethod
    def _descriptor(
        row: sqlite3.Row,
        prefix: str,
        seq: int | None,
        field: str,
    ) -> dict | None:
        preview = row[f"{prefix}_preview"]
        byte_count = row[f"{prefix}_bytes"]
        if seq is None or (preview is None and byte_count is None):
            return None
        return {
            "sequence": int(seq),
            "field": field,
            "bytes": max(0, int(byte_count or 0)),
            "preview": str(preview or ""),
            "full_content_available": True,
        }

    @classmethod
    def _item(cls, row: sqlite3.Row) -> dict[str, Any]:
        category = str(row["category"])
        output_sequence = row["result_seq"]
        output_field = "content"
        if category == "thinking":
            output_sequence = row["target_seq"]
            output_field = "text"
        return {
            "id": str(row["id"]),
            "provider_id": str(row["provider_id"]),
            "session_id": str(row["session_key"]),
            "generation": int(row["generation"]),
            "category": category,
            "status": str(row["status"]),
            "call_sequence": int(row["call_seq"])
                if row["call_seq"] is not None else None,
            "result_sequence": int(row["result_seq"])
                if row["result_seq"] is not None else None,
            "target_sequence": int(row["target_seq"]),
            "occurred_at": float(row["occurred_at"]),
            "completed_at": float(row["completed_at"])
                if row["completed_at"] is not None else None,
            "duration_ms": int(row["duration_ms"])
                if row["duration_ms"] is not None else None,
            "project_id": row["project_id"],
            "project_name": str(row["project_name"]),
            "tool_name": row["tool_name"],
            "title": str(row["title"]),
            "summary": row["summary"],
            "input": cls._descriptor(
                row,
                "input",
                row["call_seq"],
                "input",
            ),
            "output": cls._descriptor(
                row,
                "output",
                output_sequence,
                output_field,
            ),
        }
