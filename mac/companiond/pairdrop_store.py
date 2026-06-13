#!/usr/bin/env python3
"""Mac-local PairDrop vault storage.

PairDrop stores user files under a Pairling-owned root and exposes files by
opaque ids, never by client-supplied paths. This module intentionally has no
HTTP dependency so daemon tests can exercise the storage contract directly.
"""

from __future__ import annotations

import hashlib
import errno
import json
import os
import re
import secrets
import sqlite3
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class PairDropStoreError(ValueError):
    def __init__(self, code: str, message: str | None = None):
        super().__init__(message or code)
        self.code = code


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _safe_display_name(filename: str) -> str:
    base = os.path.basename(str(filename or "").strip())
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", base).strip("._")
    if not safe:
        return "upload.bin"
    if len(safe) <= 120:
        return safe
    stem, dot, ext = safe.rpartition(".")
    if dot and 1 <= len(ext) <= 12:
        return stem[: 120 - len(ext) - 1] + "." + ext
    return safe[:120]


def _json_list(value: Any) -> str:
    return json.dumps(value if isinstance(value, list) else [])


class PairDropStore:
    schema_version = 1

    def __init__(self, root: Path):
        self.root = Path(root).expanduser()
        self.objects_dir = self.root / "objects"
        self.partials_dir = self.root / "partials"
        self.thumbnails_dir = self.root / "thumbnails"
        self.exports_dir = self.root / "exports"
        self.db_path = self.root / "index.sqlite"
        self.audit_path = self.root / "audit.jsonl"
        self._ensure_root()

    def _ensure_root(self) -> None:
        for path in [
            self.root,
            self.objects_dir,
            self.partials_dir,
            self.thumbnails_dir,
            self.exports_dir,
        ]:
            path.mkdir(parents=True, exist_ok=True)
        try:
            # PairDrop stores private user files; the vault root must not be world-readable.
            os.chmod(self.root, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        except OSError:
            pass
        with self._connect() as conn:
            self._ensure_schema(conn)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                parent_id TEXT,
                kind TEXT NOT NULL,
                display_name TEXT NOT NULL,
                original_name TEXT NOT NULL,
                content_type TEXT NOT NULL,
                byte_size INTEGER NOT NULL,
                sha256 TEXT,
                storage_relpath TEXT,
                source_device_id TEXT,
                source_install_id TEXT,
                source_route TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                deleted_at TEXT,
                last_opened_at TEXT,
                session_hint TEXT,
                tags_json TEXT NOT NULL DEFAULT '[]'
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                file_id TEXT,
                created_at TEXT NOT NULL,
                summary_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS upload_sessions (
                upload_id TEXT PRIMARY KEY,
                file_id TEXT,
                display_name TEXT NOT NULL,
                original_name TEXT NOT NULL,
                content_type TEXT NOT NULL,
                total_byte_count INTEGER NOT NULL,
                expected_sha256 TEXT NOT NULL,
                verified_offset INTEGER NOT NULL DEFAULT 0,
                source_device_id TEXT,
                source_install_id TEXT,
                source_route TEXT,
                state TEXT NOT NULL,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS upload_chunks (
                upload_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                offset INTEGER NOT NULL,
                byte_count INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (upload_id, idempotency_key)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pairdrop_files_deleted ON files(deleted_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pairdrop_files_created ON files(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pairdrop_upload_sessions_state ON upload_sessions(state)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pairdrop_upload_sessions_expires ON upload_sessions(expires_at)")

    def upload_bytes(
        self,
        *,
        filename: str,
        content_type: str,
        data: bytes,
        source_device_id: str,
        source_install_id: str,
        source_route: str = "pairling-connectd",
        session_hint: str = "",
        expected_sha256: str | None = None,
        parent_id: str | None = None,
    ) -> dict[str, Any]:
        if not data:
            raise PairDropStoreError("empty_body")
        display_name = _safe_display_name(filename)
        digest = hashlib.sha256(data).hexdigest()
        if expected_sha256 and expected_sha256.lower() != digest:
            raise PairDropStoreError("sha256_mismatch")
        if parent_id:
            parent = self.get_file(parent_id)
            if parent.get("kind") != "folder":
                raise PairDropStoreError("bad_parent")

        file_id = "pd_" + secrets.token_hex(16)
        relpath = Path("objects") / digest[:2] / f"{file_id}.blob"
        partial = self.partials_dir / f"{file_id}.partial"
        target = self.root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        partial.write_bytes(data)
        os.replace(partial, target)
        now = _now_iso()
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute(
                """
                INSERT INTO files (
                    id, parent_id, kind, display_name, original_name, content_type,
                    byte_size, sha256, storage_relpath, source_device_id,
                    source_install_id, source_route, created_at, updated_at,
                    deleted_at, last_opened_at, session_hint, tags_json
                ) VALUES (?, ?, 'file', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
                """,
                (
                    file_id,
                    parent_id,
                    display_name,
                    str(filename or ""),
                    content_type or "application/octet-stream",
                    len(data),
                    digest,
                    str(relpath),
                    source_device_id,
                    source_install_id,
                    source_route,
                    now,
                    now,
                    session_hint,
                    _json_list([]),
                ),
            )
            self._record_event(conn, "created", file_id, {
                "byte_size": len(data),
                "content_type": content_type or "application/octet-stream",
                "sha256": digest,
            })
            conn.commit()
        item = self.get_file(file_id)
        self._audit("file.created", {
            "file_id": file_id,
            "byte_size": len(data),
            "content_type": content_type or "application/octet-stream",
            "sha256": digest,
        })
        return item

    def create_upload_session(
        self,
        *,
        filename: str,
        content_type: str,
        total_byte_count: int,
        expected_sha256: str,
        source_device_id: str,
        source_install_id: str,
        source_route: str = "pairling-connectd",
        expires_in_seconds: int = 24 * 60 * 60,
    ) -> dict[str, Any]:
        total = int(total_byte_count)
        digest = str(expected_sha256 or "").strip().lower()
        if total <= 0:
            raise PairDropStoreError("bad_total_byte_count")
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise PairDropStoreError("bad_expected_sha256")
        upload_id = "pu_" + secrets.token_hex(16)
        display_name = _safe_display_name(filename)
        now = _now_iso()
        expires_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + max(60, int(expires_in_seconds))))
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute(
                """
                INSERT INTO upload_sessions (
                    upload_id, file_id, display_name, original_name, content_type,
                    total_byte_count, expected_sha256, verified_offset,
                    source_device_id, source_install_id, source_route, state,
                    last_error, created_at, updated_at, expires_at
                ) VALUES (?, NULL, ?, ?, ?, ?, ?, 0, ?, ?, ?, 'created', NULL, ?, ?, ?)
                """,
                (
                    upload_id,
                    display_name,
                    str(filename or ""),
                    content_type or "application/octet-stream",
                    total,
                    digest,
                    source_device_id,
                    source_install_id,
                    source_route,
                    now,
                    now,
                    expires_at,
                ),
            )
            self._record_event(conn, "upload_session_created", None, {
                "upload_id": upload_id,
                "byte_size": total,
                "content_type": content_type or "application/octet-stream",
            })
            conn.commit()
        self._audit("upload_session.created", {
            "upload_id": upload_id,
            "byte_size": total,
            "content_type": content_type or "application/octet-stream",
        })
        return self.get_upload_session(upload_id)

    def get_upload_session(self, upload_id: str) -> dict[str, Any]:
        if not self._valid_upload_id(upload_id):
            raise PairDropStoreError("bad_upload_id")
        with self._connect() as conn:
            self._ensure_schema(conn)
            row = conn.execute("SELECT * FROM upload_sessions WHERE upload_id = ?", (upload_id,)).fetchone()
        if row is None:
            raise PairDropStoreError("upload_not_found")
        return self._public_upload_row(row)

    def write_upload_chunk(
        self,
        upload_id: str,
        *,
        offset: int,
        data: bytes,
        chunk_sha256: str,
        idempotency_key: str,
        source_device_id: str,
        source_install_id: str,
    ) -> dict[str, Any]:
        if not self._valid_upload_id(upload_id):
            raise PairDropStoreError("bad_upload_id")
        if not data:
            raise PairDropStoreError("empty_chunk")
        offset = int(offset)
        if offset < 0:
            raise PairDropStoreError("bad_offset")
        chunk_hash = str(chunk_sha256 or "").strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", chunk_hash):
            raise PairDropStoreError("bad_chunk_sha256")
        actual_hash = hashlib.sha256(data).hexdigest()
        if actual_hash != chunk_hash:
            raise PairDropStoreError("chunk_hash_mismatch")
        idem = str(idempotency_key or "").strip()
        if not idem or len(idem) > 160:
            raise PairDropStoreError("bad_idempotency_key")

        with self._connect() as conn:
            self._ensure_schema(conn)
            row = conn.execute("SELECT * FROM upload_sessions WHERE upload_id = ?", (upload_id,)).fetchone()
            if row is None:
                raise PairDropStoreError("upload_not_found")
            session = self._public_upload_row(row)
            self._assert_upload_source(session, source_device_id, source_install_id)
            if session["state"] in {"committed", "cancelled", "expired", "failed_terminal"}:
                raise PairDropStoreError("upload_not_writable")

            previous = conn.execute(
                "SELECT * FROM upload_chunks WHERE upload_id = ? AND idempotency_key = ?",
                (upload_id, idem),
            ).fetchone()
            if previous is not None:
                if previous["offset"] != offset or previous["byte_count"] != len(data) or previous["sha256"] != chunk_hash:
                    raise PairDropStoreError("idempotency_conflict")
                if self._partial_range_hash(upload_id, offset, len(data)) != chunk_hash:
                    raise PairDropStoreError("chunk_mismatch")
                return {
                    **session,
                    "idempotent": True,
                    "verified_offset": max(session["verified_offset"], offset + len(data)),
                }

            verified_offset = int(session["verified_offset"] or 0)
            if offset < verified_offset:
                if self._partial_range_hash(upload_id, offset, len(data)) == chunk_hash:
                    return {**session, "idempotent": True}
                raise PairDropStoreError("chunk_mismatch")
            if offset != verified_offset:
                raise PairDropStoreError("unexpected_offset")
            if offset + len(data) > int(session["total_byte_count"]):
                raise PairDropStoreError("chunk_exceeds_total")

            self._write_partial_range(upload_id, offset, data)
            new_offset = offset + len(data)
            now = _now_iso()
            conn.execute(
                """
                INSERT INTO upload_chunks (
                    upload_id, idempotency_key, offset, byte_count, sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (upload_id, idem, offset, len(data), chunk_hash, now),
            )
            conn.execute(
                """
                UPDATE upload_sessions
                   SET verified_offset = ?, state = 'receiving', updated_at = ?, last_error = NULL
                 WHERE upload_id = ?
                """,
                (new_offset, now, upload_id),
            )
            self._record_event(conn, "upload_session_progress", None, {
                "upload_id": upload_id,
                "verified_offset": new_offset,
            })
            conn.commit()

        self._audit("upload_session.chunk", {
            "upload_id": upload_id,
            "offset": offset,
            "byte_count": len(data),
        })
        updated = self.get_upload_session(upload_id)
        return {**updated, "idempotent": False}

    def complete_upload_session(
        self,
        upload_id: str,
        *,
        source_device_id: str,
        source_install_id: str,
    ) -> dict[str, Any]:
        session = self.get_upload_session(upload_id)
        self._assert_upload_source(session, source_device_id, source_install_id)
        if session["state"] == "committed" and session.get("file_id"):
            return {"ok": True, "state": "committed", "file": self.get_file(session["file_id"])}
        if session["state"] in {"cancelled", "expired", "failed_terminal"}:
            raise PairDropStoreError("upload_not_completable")

        partial = self._partial_path(upload_id)
        if partial.is_symlink():
            self._mark_upload_error(upload_id, "failed_retryable", "missing_partial")
            raise PairDropStoreError("missing_partial")
        if not partial.is_file():
            recovered = self._recover_completed_upload_session(session)
            if recovered is not None:
                return recovered
            self._mark_upload_error(upload_id, "failed_retryable", "missing_partial")
            raise PairDropStoreError("missing_partial")
        byte_size = partial.stat().st_size
        if byte_size != int(session["total_byte_count"]):
            self._mark_upload_error(upload_id, "failed_retryable", "byte_count_mismatch")
            raise PairDropStoreError("byte_count_mismatch")
        digest = self._sha256_file(partial)
        if digest != session["expected_sha256"]:
            self._mark_upload_error(upload_id, "failed_terminal", "sha256_mismatch")
            raise PairDropStoreError("sha256_mismatch")

        file_id = session["file_id"] if self._valid_id(str(session.get("file_id") or "")) else "pd_" + secrets.token_hex(16)
        relpath = Path("objects") / digest[:2] / f"{file_id}.blob"
        target = self.root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        now = _now_iso()
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute(
                """
                UPDATE upload_sessions
                   SET file_id = ?, state = 'completing', updated_at = ?, last_error = NULL
                 WHERE upload_id = ?
                """,
                (file_id, now, upload_id),
            )
            conn.commit()
        os.replace(partial, target)
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute(
                """
                INSERT INTO files (
                    id, parent_id, kind, display_name, original_name, content_type,
                    byte_size, sha256, storage_relpath, source_device_id,
                    source_install_id, source_route, created_at, updated_at,
                    deleted_at, last_opened_at, session_hint, tags_json
                ) VALUES (?, NULL, 'file', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, '', ?)
                """,
                (
                    file_id,
                    session["display_name"],
                    session["original_name"],
                    session["content_type"],
                    byte_size,
                    digest,
                    str(relpath),
                    session["source_device_id"],
                    session["source_install_id"],
                    session["source_route"],
                    now,
                    now,
                    _json_list([]),
                ),
            )
            conn.execute(
                """
                UPDATE upload_sessions
                   SET file_id = ?, state = 'committed', verified_offset = ?,
                       updated_at = ?, last_error = NULL
                 WHERE upload_id = ?
                """,
                (file_id, byte_size, now, upload_id),
            )
            self._record_event(conn, "created", file_id, {
                "byte_size": byte_size,
                "content_type": session["content_type"],
                "sha256": digest,
            })
            self._record_event(conn, "upload_session_committed", file_id, {"upload_id": upload_id})
            conn.commit()
        item = self.get_file(file_id)
        self._audit("upload_session.committed", {
            "upload_id": upload_id,
            "file_id": file_id,
            "byte_size": byte_size,
            "content_type": session["content_type"],
            "sha256": digest,
        })
        return {"ok": True, "state": "committed", "upload_id": upload_id, "file": item}

    def _recover_completed_upload_session(self, session: dict[str, Any]) -> dict[str, Any] | None:
        upload_id = str(session.get("upload_id") or "")
        expected_sha256 = str(session.get("expected_sha256") or "")
        total_byte_count = int(session.get("total_byte_count") or 0)
        file_id = str(session.get("file_id") or "")
        candidates: list[Path] = []
        if self._valid_id(file_id):
            candidates.append(self.objects_dir / expected_sha256[:2] / f"{file_id}.blob")
        else:
            candidates.extend((self.objects_dir / expected_sha256[:2]).glob("pd_*.blob"))

        for candidate in candidates:
            try:
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                recovered_file_id = candidate.stem
                if not self._valid_id(recovered_file_id):
                    continue
                if candidate.stat().st_size != total_byte_count:
                    continue
                if self._sha256_file(candidate) != expected_sha256:
                    continue
                return self._commit_recovered_upload_session(session, recovered_file_id, candidate)
            except FileNotFoundError:
                continue
        return None

    def _commit_recovered_upload_session(self, session: dict[str, Any], file_id: str, object_path: Path) -> dict[str, Any]:
        upload_id = str(session["upload_id"])
        byte_size = int(session["total_byte_count"])
        digest = str(session["expected_sha256"])
        relpath = object_path.relative_to(self.root)
        now = _now_iso()
        with self._connect() as conn:
            self._ensure_schema(conn)
            existing = conn.execute("SELECT id FROM files WHERE id = ?", (file_id,)).fetchone()
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO files (
                        id, parent_id, kind, display_name, original_name, content_type,
                        byte_size, sha256, storage_relpath, source_device_id,
                        source_install_id, source_route, created_at, updated_at,
                        deleted_at, last_opened_at, session_hint, tags_json
                    ) VALUES (?, NULL, 'file', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, '', ?)
                    """,
                    (
                        file_id,
                        session["display_name"],
                        session["original_name"],
                        session["content_type"],
                        byte_size,
                        digest,
                        str(relpath),
                        session["source_device_id"],
                        session["source_install_id"],
                        session["source_route"],
                        now,
                        now,
                        _json_list([]),
                    ),
                )
                self._record_event(conn, "created", file_id, {
                    "byte_size": byte_size,
                    "content_type": session["content_type"],
                    "sha256": digest,
                })
            conn.execute(
                """
                UPDATE upload_sessions
                   SET file_id = ?, state = 'committed', verified_offset = ?,
                       updated_at = ?, last_error = NULL
                 WHERE upload_id = ?
                """,
                (file_id, byte_size, now, upload_id),
            )
            self._record_event(conn, "upload_session_recovered", file_id, {"upload_id": upload_id})
            conn.commit()
        item = self.get_file(file_id)
        self._audit("upload_session.recovered", {
            "upload_id": upload_id,
            "file_id": file_id,
            "byte_size": byte_size,
            "content_type": session["content_type"],
            "sha256": digest,
        })
        return {"ok": True, "state": "committed", "upload_id": upload_id, "file": item}

    def cancel_upload_session(
        self,
        upload_id: str,
        *,
        source_device_id: str,
        source_install_id: str,
    ) -> dict[str, Any]:
        session = self.get_upload_session(upload_id)
        self._assert_upload_source(session, source_device_id, source_install_id)
        if session["state"] == "committed":
            raise PairDropStoreError("upload_already_committed")
        now = _now_iso()
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute(
                "UPDATE upload_sessions SET state = 'cancelled', updated_at = ? WHERE upload_id = ?",
                (now, upload_id),
            )
            self._record_event(conn, "upload_session_cancelled", None, {"upload_id": upload_id})
            conn.commit()
        self._audit("upload_session.cancelled", {"upload_id": upload_id})
        return self.get_upload_session(upload_id)

    def list_files(self, *, include_deleted: bool = False) -> list[dict[str, Any]]:
        query = (
            "SELECT * FROM files ORDER BY created_at DESC, id DESC"
            if include_deleted
            else "SELECT * FROM files WHERE deleted_at IS NULL ORDER BY created_at DESC, id DESC"
        )
        with self._connect() as conn:
            self._ensure_schema(conn)
            rows = conn.execute(query).fetchall()
        return [self._public_row(row) for row in rows]

    def get_file(self, file_id: str, *, include_deleted: bool = False) -> dict[str, Any]:
        if not self._valid_id(file_id):
            raise PairDropStoreError("bad_file_id")
        with self._connect() as conn:
            self._ensure_schema(conn)
            row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        if row is None:
            raise PairDropStoreError("not_found")
        if row["deleted_at"] and not include_deleted:
            raise PairDropStoreError("deleted")
        return self._public_row(row)

    def delete_file(self, file_id: str) -> dict[str, Any]:
        item = self.get_file(file_id)
        now = _now_iso()
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute(
                "UPDATE files SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL",
                (now, now, file_id),
            )
            self._record_event(conn, "deleted", file_id, {"byte_size": item.get("byte_size", 0)})
            conn.commit()
        self._audit("file.deleted", {"file_id": file_id, "byte_size": item.get("byte_size", 0)})
        return {"ok": True, "id": file_id, "deleted_at": now}

    def attach_descriptor(self, file_id: str, *, session_id: str = "") -> dict[str, Any]:
        item = self.get_file(file_id)
        path = self._object_path(item)
        if not path.is_file():
            raise PairDropStoreError("missing_object")
        now = _now_iso()
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute(
                "UPDATE files SET last_opened_at = ?, updated_at = ? WHERE id = ?",
                (now, now, file_id),
            )
            self._record_event(conn, "attached", file_id, {"session": bool(session_id)})
            conn.commit()
        self._audit("file.attached", {"file_id": file_id, "session": bool(session_id)})
        return {
            "ok": True,
            "id": file_id,
            "display_name": item["display_name"],
            "content_type": item["content_type"],
            "byte_size": item["byte_size"],
            "sha256": item["sha256"],
            "path": str(path),
        }

    def download_descriptor(self, file_id: str) -> dict[str, Any]:
        item = self.get_file(file_id)
        path = self._object_path(item)
        if path.is_symlink() or not path.is_file():
            raise PairDropStoreError("missing_object")
        resolved_root = self.root.resolve()
        resolved_path = path.resolve()
        if not str(resolved_path).startswith(str(resolved_root) + os.sep):
            raise PairDropStoreError("object_escape")
        stat_result = path.stat()
        if int(item.get("byte_size") or 0) != stat_result.st_size:
            raise PairDropStoreError("byte_size_mismatch")
        now = _now_iso()
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute(
                "UPDATE files SET last_opened_at = ?, updated_at = ? WHERE id = ?",
                (now, now, file_id),
            )
            self._record_event(conn, "downloaded", file_id, {"byte_size": item.get("byte_size", 0)})
            conn.commit()
        self._audit("file.downloaded", {"file_id": file_id, "byte_size": item.get("byte_size", 0)})
        updated = self.get_file(file_id)
        return {"item": updated, "path": path}

    def events_since(self, seq: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        seq = max(0, int(seq or 0))
        limit = max(1, min(int(limit or 100), 500))
        with self._connect() as conn:
            self._ensure_schema(conn)
            rows = conn.execute(
                "SELECT * FROM events WHERE seq > ? ORDER BY seq ASC LIMIT ?",
                (seq, limit),
            ).fetchall()
        return [
            {
                "seq": row["seq"],
                "type": row["type"],
                "file_id": row["file_id"],
                "created_at": row["created_at"],
                "summary": json.loads(row["summary_json"] or "{}"),
            }
            for row in rows
        ]

    def cleanup_partials(self, *, older_than_seconds: int = 3600) -> dict[str, Any]:
        cutoff = time.time() - max(0, older_than_seconds)
        removed = 0
        skipped_symlinks = 0
        for path in self.partials_dir.glob("*.partial"):
            try:
                stat = path.lstat()
                if path.is_symlink():
                    skipped_symlinks += 1
                    continue
                if stat.st_mtime < cutoff:
                    path.unlink()
                    removed += 1
            except FileNotFoundError:
                continue
        expired = 0
        now = _now_iso()
        with self._connect() as conn:
            self._ensure_schema(conn)
            rows = conn.execute(
                """
                SELECT upload_id FROM upload_sessions
                 WHERE state NOT IN ('committed', 'cancelled', 'expired')
                   AND expires_at <= ?
                """,
                (now,),
            ).fetchall()
            for row in rows:
                conn.execute(
                    "UPDATE upload_sessions SET state = 'expired', updated_at = ? WHERE upload_id = ?",
                    (now, row["upload_id"]),
                )
                expired += 1
            conn.commit()
        self._audit("partials.cleaned", {"removed": removed, "skipped_symlinks": skipped_symlinks, "expired_sessions": expired})
        return {"ok": True, "removed": removed, "skipped_symlinks": skipped_symlinks, "expired_sessions": expired}

    def _object_path(self, item: dict[str, Any]) -> Path:
        relpath = str(item.get("storage_relpath") or "")
        if relpath.startswith("/") or ".." in Path(relpath).parts:
            raise PairDropStoreError("unsafe_object_path")
        path = (self.root / relpath).resolve()
        root = self.root.resolve()
        if root not in path.parents and path != root:
            raise PairDropStoreError("unsafe_object_path")
        return path

    def _partial_path(self, upload_id: str) -> Path:
        if not self._valid_upload_id(upload_id):
            raise PairDropStoreError("bad_upload_id")
        path = self.partials_dir / f"{upload_id}.partial"
        parent = path.parent.resolve()
        if parent != self.partials_dir.resolve():
            raise PairDropStoreError("unsafe_partial_path")
        return path

    def _write_partial_range(self, upload_id: str, offset: int, data: bytes) -> None:
        path = self._partial_path(upload_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        if no_follow:
            flags |= no_follow
        fd = -1
        try:
            fd = os.open(str(path), flags, 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise PairDropStoreError("unsafe_partial_path")
            with os.fdopen(fd, "r+b", closefd=True) as handle:
                fd = -1
                handle.seek(offset)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                raise PairDropStoreError("unsafe_partial_path") from exc
            raise
        finally:
            if fd >= 0:
                os.close(fd)

    def _partial_range_hash(self, upload_id: str, offset: int, byte_count: int) -> str:
        path = self._partial_path(upload_id)
        if path.is_symlink() or not path.is_file():
            raise PairDropStoreError("missing_partial")
        with path.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(byte_count)
        if len(data) != byte_count:
            raise PairDropStoreError("chunk_mismatch")
        return hashlib.sha256(data).hexdigest()

    def _sha256_file(self, path: Path) -> str:
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()

    def _assert_upload_source(self, session: dict[str, Any], device_id: str, install_id: str) -> None:
        if session.get("source_device_id") != device_id or session.get("source_install_id") != install_id:
            raise PairDropStoreError("wrong_source")

    def _mark_upload_error(self, upload_id: str, state: str, error: str) -> None:
        now = _now_iso()
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute(
                "UPDATE upload_sessions SET state = ?, last_error = ?, updated_at = ? WHERE upload_id = ?",
                (state, error, now, upload_id),
            )
            conn.commit()

    def _public_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "parent_id": row["parent_id"],
            "kind": row["kind"],
            "display_name": row["display_name"],
            "content_type": row["content_type"],
            "byte_size": row["byte_size"],
            "sha256": row["sha256"],
            "source_device_id": row["source_device_id"],
            "source_install_id": row["source_install_id"],
            "source_route": row["source_route"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "deleted_at": row["deleted_at"],
            "last_opened_at": row["last_opened_at"],
            "session_hint": row["session_hint"],
            "storage_relpath": row["storage_relpath"],
            "tags": json.loads(row["tags_json"] or "[]"),
        }

    def _public_upload_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "upload_id": row["upload_id"],
            "file_id": row["file_id"],
            "display_name": row["display_name"],
            "original_name": row["original_name"],
            "content_type": row["content_type"],
            "total_byte_count": row["total_byte_count"],
            "expected_sha256": row["expected_sha256"],
            "verified_offset": row["verified_offset"],
            "source_device_id": row["source_device_id"],
            "source_install_id": row["source_install_id"],
            "source_route": row["source_route"],
            "state": row["state"],
            "last_error": row["last_error"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "expires_at": row["expires_at"],
        }

    def _record_event(self, conn: sqlite3.Connection, event_type: str, file_id: str | None, summary: dict[str, Any]) -> None:
        conn.execute(
            "INSERT INTO events (type, file_id, created_at, summary_json) VALUES (?, ?, ?, ?)",
            (event_type, file_id, _now_iso(), json.dumps(summary, sort_keys=True)),
        )

    def _audit(self, event: str, detail: dict[str, Any]) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        safe_detail = {
            key: value for key, value in detail.items()
            if key not in {"path", "body", "request_body", "contents"}
        }
        record = {
            "ts": _now_iso(),
            "event": event,
            "detail": safe_detail,
        }
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    @staticmethod
    def _valid_id(file_id: str) -> bool:
        return bool(re.fullmatch(r"pd_[a-f0-9]{32}", str(file_id or "")))

    @staticmethod
    def _valid_upload_id(upload_id: str) -> bool:
        return bool(re.fullmatch(r"pu_[a-f0-9]{32}", str(upload_id or "")))
