#!/usr/bin/env python3
"""Mac-local PairDrop vault storage.

PairDrop stores user files under a Pairling-owned root and exposes files by
opaque ids, never by client-supplied paths. This module intentionally has no
HTTP dependency so daemon tests can exercise the storage contract directly.
"""

from __future__ import annotations

import hashlib
import errno
import fcntl
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import tempfile
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
    sqlite_busy_timeout_ms = 10_000

    def __init__(self, root: Path, *, legacy_root: Path | None = None, migrate_legacy: bool = True):
        self.root = Path(root).expanduser()
        self.objects_dir = self.root / "objects"
        self.partials_dir = self.root / "partials"
        self.thumbnails_dir = self.root / "thumbnails"
        self.exports_dir = self.root / "exports"
        self.db_path = self.root / "index.sqlite"
        self.audit_path = self.root / "audit.jsonl"
        if legacy_root is not None:
            self.legacy_root = Path(legacy_root).expanduser()
        elif self.root.name == "PairDrop":
            self.legacy_root = self.root.parent / "Pairling" / "PairDrop" / "v1"
        else:
            self.legacy_root = None
        self.migration_lock_path = self.root / ".legacy-v1-migration.lock"
        self.migration_receipt_path = self.root / ".legacy-v1-migration.json"
        self.initialization_lock_path = self.root / ".store-initialization.lock"
        self._ensure_root()
        if migrate_legacy:
            self._migrate_legacy_vault()

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
        with self._initialization_lock():
            with self._connect() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                self._ensure_schema(conn)

    @contextmanager
    def _initialization_lock(self) -> Iterator[None]:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = -1
        try:
            fd = os.open(str(self.initialization_lock_path), flags, 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise PairDropStoreError("unsafe_initialization_lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                raise PairDropStoreError("unsafe_initialization_lock") from exc
            raise
        finally:
            if fd >= 0:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    @contextmanager
    def _upload_operation_lock(self, upload_id: str) -> Iterator[None]:
        """Serialize one upload's file and database state across processes."""

        if not self._valid_upload_id(upload_id):
            raise PairDropStoreError("bad_upload_id")
        path = self.partials_dir / f".{upload_id}.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = -1
        try:
            fd = os.open(str(path), flags, 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise PairDropStoreError("unsafe_upload_lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                raise PairDropStoreError("unsafe_upload_lock") from exc
            raise
        finally:
            if fd >= 0:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=self.sqlite_busy_timeout_ms / 1000,
        )
        conn.execute(f"PRAGMA busy_timeout={self.sqlite_busy_timeout_ms}")
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

    def _migrate_legacy_vault(self) -> None:
        legacy_root = self.legacy_root
        if legacy_root is None or not legacy_root.exists():
            return
        if legacy_root.is_symlink() or not legacy_root.is_dir():
            raise PairDropStoreError("legacy_migration_unsafe_root")
        legacy_db = legacy_root / "index.sqlite"
        if not legacy_db.exists():
            return
        if legacy_db.is_symlink() or not legacy_db.is_file():
            raise PairDropStoreError("legacy_migration_unsafe_database")

        with self._migration_lock():
            if self._migration_receipt_is_current(legacy_root):
                return
            rows = self._read_verified_legacy_rows(legacy_root, legacy_db)
            source_signature = self._legacy_source_signature(legacy_root, legacy_db, rows)
            migrated = self._merge_legacy_rows(legacy_root, rows)
            self._verify_migrated_rows(migrated)
            final_signature = self._legacy_source_signature(legacy_root, legacy_db, rows)
            if final_signature != source_signature:
                raise PairDropStoreError("legacy_migration_source_changed")
            receipt = {
                "schema_version": 1,
                "verified": True,
                "completed_at": _now_iso(),
                "source_root": str(legacy_root.resolve()),
                "destination_root": str(self.root.resolve()),
                "source_files": final_signature,
                "mappings": [
                    {
                        "source_id": item["source_id"],
                        "destination_id": item["destination_id"],
                        "kind": item["kind"],
                        "byte_size": item["byte_size"],
                        "sha256": item["sha256"],
                    }
                    for item in migrated
                ],
            }
            self._write_migration_receipt(receipt)
            self._audit("legacy_v1_migration.completed", {
                "rows": len(migrated),
                "files": sum(1 for item in migrated if item["kind"] == "file"),
                "collisions": sum(1 for item in migrated if item["source_id"] != item["destination_id"]),
            })

    @contextmanager
    def _migration_lock(self) -> Iterator[None]:
        flags = os.O_RDWR | os.O_CREAT
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        if no_follow:
            flags |= no_follow
        fd = -1
        try:
            fd = os.open(str(self.migration_lock_path), flags, 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise PairDropStoreError("legacy_migration_unsafe_lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                raise PairDropStoreError("legacy_migration_unsafe_lock") from exc
            raise
        finally:
            if fd >= 0:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    def _migration_receipt_is_current(self, legacy_root: Path) -> bool:
        try:
            if self.migration_receipt_path.is_symlink() or not self.migration_receipt_path.is_file():
                return False
            receipt = json.loads(self.migration_receipt_path.read_text(encoding="utf-8"))
            if receipt.get("verified") is not True:
                return False
            if receipt.get("source_root") != str(legacy_root.resolve()):
                return False
            source_files = receipt.get("source_files")
            if not isinstance(source_files, list) or not source_files:
                return False
            for expected in source_files:
                if not isinstance(expected, dict):
                    return False
                relative = str(expected.get("path") or "")
                path = self._safe_path_under(legacy_root, relative, "legacy_migration_unsafe_source")
                identity = self._regular_file_identity(path, "legacy_migration_unsafe_source")
                actual = {
                    "path": relative,
                    **{key: identity[key] for key in ("size", "mtime_ns", "inode", "device")},
                }
                if actual != expected:
                    return False
            return True
        except (OSError, ValueError, TypeError, json.JSONDecodeError, PairDropStoreError):
            return False

    def _read_verified_legacy_rows(self, legacy_root: Path, legacy_db: Path) -> list[dict[str, Any]]:
        with tempfile.TemporaryDirectory(prefix="pairdrop-legacy-db.") as temporary:
            snapshot_db = Path(temporary) / "index.sqlite"
            shutil.copyfile(legacy_db, snapshot_db)
            legacy_wal = Path(str(legacy_db) + "-wal")
            if legacy_wal.exists():
                self._regular_file_identity(legacy_wal, "legacy_migration_unsafe_database")
                shutil.copyfile(legacy_wal, Path(str(snapshot_db) + "-wal"))
            try:
                conn = sqlite3.connect(str(snapshot_db), timeout=self.sqlite_busy_timeout_ms / 1000)
                conn.row_factory = sqlite3.Row
                conn.execute(f"PRAGMA busy_timeout={self.sqlite_busy_timeout_ms}")
                conn.execute("PRAGMA query_only=ON")
                table = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'files'"
                ).fetchone()
                if table is None:
                    raise PairDropStoreError("legacy_migration_missing_files_table")
                raw_rows = conn.execute("SELECT * FROM files ORDER BY created_at ASC, id ASC").fetchall()
            except sqlite3.Error as exc:
                raise PairDropStoreError("legacy_migration_database_error") from exc
            finally:
                if "conn" in locals():
                    conn.close()

        rows: list[dict[str, Any]] = []
        for raw in raw_rows:
            row = dict(raw)
            source_id = str(row.get("id") or "")
            kind = str(row.get("kind") or "")
            if not self._valid_id(source_id) or kind not in {"file", "folder"}:
                raise PairDropStoreError("legacy_migration_invalid_row")
            try:
                byte_size = int(row.get("byte_size") or 0)
            except (TypeError, ValueError) as exc:
                raise PairDropStoreError("legacy_migration_invalid_row") from exc
            if byte_size < 0:
                raise PairDropStoreError("legacy_migration_invalid_row")
            digest = str(row.get("sha256") or "").strip().lower()
            source_path = None
            source_identity = None
            if kind == "file":
                if not re.fullmatch(r"[a-f0-9]{64}", digest):
                    raise PairDropStoreError("legacy_migration_invalid_row")
                source_path = self._safe_path_under(
                    legacy_root,
                    str(row.get("storage_relpath") or ""),
                    "legacy_migration_unsafe_object",
                )
                source_identity = self._verify_legacy_object(source_path, byte_size, digest)
            rows.append({
                **row,
                "id": source_id,
                "kind": kind,
                "byte_size": byte_size,
                "sha256": digest or None,
                "source_path": source_path,
                "source_identity": source_identity,
            })
        return rows

    def _legacy_source_signature(
        self,
        legacy_root: Path,
        legacy_db: Path,
        rows: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        paths = [legacy_db]
        wal = Path(str(legacy_db) + "-wal")
        if wal.exists():
            paths.append(wal)
        paths.extend(row["source_path"] for row in rows if row.get("source_path") is not None)
        signature = []
        for path in sorted(set(paths), key=lambda item: str(item)):
            identity = self._regular_file_identity(path, "legacy_migration_unsafe_source")
            signature.append({
                "path": str(path.relative_to(legacy_root)),
                **{key: identity[key] for key in ("size", "mtime_ns", "inode", "device")},
            })
        return signature

    def _merge_legacy_rows(self, legacy_root: Path, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        migrated: list[dict[str, Any]] = []
        mappings: dict[str, str] = {}
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            destination_rows = {
                str(row["id"]): row
                for row in conn.execute("SELECT * FROM files").fetchall()
            }

            for source in rows:
                destination_id = self._migration_destination_id(
                    legacy_root,
                    source,
                    destination_rows,
                )
                mappings[source["id"]] = destination_id

            for source in rows:
                destination_id = mappings[source["id"]]
                existing = destination_rows.get(destination_id)
                if existing is not None and self._migration_row_matches(existing, source):
                    storage_relpath = existing["storage_relpath"]
                else:
                    storage_relpath = None
                    if source["kind"] == "file":
                        storage_relpath = str(
                            Path("objects") / str(source["sha256"])[:2] / f"{destination_id}.blob"
                        )
                        target = self.root / storage_relpath
                        if not self._destination_object_matches(
                            target,
                            int(source["byte_size"]),
                            str(source["sha256"]),
                        ):
                            self._copy_verified_legacy_object(
                                source["source_path"],
                                target,
                                int(source["byte_size"]),
                                str(source["sha256"]),
                            )
                    parent_id = str(source.get("parent_id") or "")
                    destination_parent_id = mappings.get(parent_id)
                    tags_json = str(source.get("tags_json") or "[]")
                    try:
                        if not isinstance(json.loads(tags_json), list):
                            tags_json = "[]"
                    except json.JSONDecodeError:
                        tags_json = "[]"
                    now = _now_iso()
                    conn.execute(
                        """
                        INSERT INTO files (
                            id, parent_id, kind, display_name, original_name, content_type,
                            byte_size, sha256, storage_relpath, source_device_id,
                            source_install_id, source_route, created_at, updated_at,
                            deleted_at, last_opened_at, session_hint, tags_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            destination_id,
                            destination_parent_id,
                            source["kind"],
                            str(source.get("display_name") or "untitled"),
                            str(source.get("original_name") or source.get("display_name") or "untitled"),
                            str(source.get("content_type") or "application/octet-stream"),
                            int(source["byte_size"]),
                            source.get("sha256"),
                            storage_relpath,
                            source.get("source_device_id"),
                            source.get("source_install_id"),
                            str(source.get("source_route") or "legacy-v1"),
                            str(source.get("created_at") or now),
                            str(source.get("updated_at") or now),
                            source.get("deleted_at"),
                            source.get("last_opened_at"),
                            str(source.get("session_hint") or ""),
                            tags_json,
                        ),
                    )
                    destination_rows[destination_id] = conn.execute(
                        "SELECT * FROM files WHERE id = ?",
                        (destination_id,),
                    ).fetchone()
                migrated.append({
                    "source_id": source["id"],
                    "destination_id": destination_id,
                    "kind": source["kind"],
                    "byte_size": int(source["byte_size"]),
                    "sha256": source.get("sha256"),
                })
            self._record_event(conn, "legacy_v1_migrated", None, {
                "rows": len(migrated),
                "collisions": sum(1 for item in migrated if item["source_id"] != item["destination_id"]),
            })
            conn.commit()
        return migrated

    def _migration_destination_id(
        self,
        legacy_root: Path,
        source: dict[str, Any],
        destination_rows: dict[str, sqlite3.Row],
    ) -> str:
        source_id = str(source["id"])
        existing = destination_rows.get(source_id)
        if existing is None:
            if not self._migration_object_slot_conflicts(source_id, source):
                return source_id
        elif self._migration_row_matches(existing, source):
            if source["kind"] != "file" or self._destination_object_matches(
                self._object_path(self._public_row(existing)),
                int(source["byte_size"]),
                str(source["sha256"]),
            ):
                return source_id

        seed = "\0".join([
            str(legacy_root.resolve()),
            source_id,
            str(source.get("sha256") or source.get("display_name") or ""),
        ])
        for counter in range(10_000):
            suffix = hashlib.sha256(f"{seed}\0{counter}".encode("utf-8")).hexdigest()[:32]
            candidate = "pd_" + suffix
            existing = destination_rows.get(candidate)
            if existing is None:
                if not self._migration_object_slot_conflicts(candidate, source):
                    return candidate
            elif self._migration_row_matches(existing, source):
                if source["kind"] != "file" or self._destination_object_matches(
                    self._object_path(self._public_row(existing)),
                    int(source["byte_size"]),
                    str(source["sha256"]),
                ):
                    return candidate
        raise PairDropStoreError("legacy_migration_id_exhausted")

    def _migration_object_slot_conflicts(self, file_id: str, source: dict[str, Any]) -> bool:
        if source["kind"] != "file":
            return False
        target = self.objects_dir / str(source["sha256"])[:2] / f"{file_id}.blob"
        if not target.exists() and not target.is_symlink():
            return False
        return not self._destination_object_matches(
            target,
            int(source["byte_size"]),
            str(source["sha256"]),
        )

    @staticmethod
    def _migration_row_matches(destination: sqlite3.Row, source: dict[str, Any]) -> bool:
        return (
            str(destination["kind"]) == str(source["kind"])
            and int(destination["byte_size"] or 0) == int(source["byte_size"])
            and str(destination["sha256"] or "") == str(source.get("sha256") or "")
        )

    def _verify_migrated_rows(self, migrated: list[dict[str, Any]]) -> None:
        with self._connect() as conn:
            self._ensure_schema(conn)
            for expected in migrated:
                row = conn.execute(
                    "SELECT * FROM files WHERE id = ?",
                    (expected["destination_id"],),
                ).fetchone()
                if row is None or not self._migration_row_matches(row, expected):
                    raise PairDropStoreError("legacy_migration_destination_mismatch")
                if expected["kind"] == "file":
                    path = self._object_path(self._public_row(row))
                    if not self._destination_object_matches(
                        path,
                        int(expected["byte_size"]),
                        str(expected["sha256"]),
                    ):
                        raise PairDropStoreError("legacy_migration_destination_mismatch")

    def _verify_legacy_object(self, path: Path, byte_size: int, digest: str) -> dict[str, Any]:
        identity = self._regular_file_identity(path, "legacy_migration_unsafe_object")
        if identity["size"] != byte_size or self._sha256_regular_file(path) != digest:
            raise PairDropStoreError("legacy_migration_corrupt_object")
        if self._regular_file_identity(path, "legacy_migration_unsafe_object") != identity:
            raise PairDropStoreError("legacy_migration_source_changed")
        return identity

    def _copy_verified_legacy_object(self, source: Path, target: Path, byte_size: int, digest: str) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        partial = self.partials_dir / f".legacy-migration-{target.stem}-{os.getpid()}.partial"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        if no_follow:
            flags |= no_follow
        source_fd = -1
        target_fd = -1
        hasher = hashlib.sha256()
        copied = 0
        try:
            source_flags = os.O_RDONLY | no_follow
            source_fd = os.open(str(source), source_flags)
            if not stat.S_ISREG(os.fstat(source_fd).st_mode):
                raise PairDropStoreError("legacy_migration_unsafe_object")
            target_fd = os.open(str(partial), flags, 0o600)
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
                copied += len(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(target_fd, view)
                    view = view[written:]
            os.fsync(target_fd)
            if copied != byte_size or hasher.hexdigest() != digest:
                raise PairDropStoreError("legacy_migration_corrupt_object")
            os.close(target_fd)
            target_fd = -1
            os.replace(partial, target)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                raise PairDropStoreError("legacy_migration_unsafe_object") from exc
            raise
        finally:
            if source_fd >= 0:
                os.close(source_fd)
            if target_fd >= 0:
                os.close(target_fd)
            try:
                partial.unlink()
            except FileNotFoundError:
                pass
        if not self._destination_object_matches(target, byte_size, digest):
            raise PairDropStoreError("legacy_migration_destination_mismatch")

    def _destination_object_matches(self, path: Path, byte_size: int, digest: str) -> bool:
        try:
            return (
                self._regular_file_identity(path, "legacy_migration_unsafe_destination")["size"] == byte_size
                and self._sha256_regular_file(path) == digest
            )
        except PairDropStoreError:
            return False

    def _sha256_regular_file(self, path: Path) -> str:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = -1
        hasher = hashlib.sha256()
        try:
            fd = os.open(str(path), flags)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise PairDropStoreError("legacy_migration_unsafe_source")
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise PairDropStoreError("legacy_migration_source_changed")
            return hasher.hexdigest()
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                raise PairDropStoreError("legacy_migration_unsafe_source") from exc
            raise
        finally:
            if fd >= 0:
                os.close(fd)

    def _regular_file_identity(self, path: Path, error_code: str) -> dict[str, Any]:
        try:
            result = path.lstat()
        except OSError as exc:
            raise PairDropStoreError(error_code) from exc
        if stat.S_ISLNK(result.st_mode) or not stat.S_ISREG(result.st_mode):
            raise PairDropStoreError(error_code)
        return {
            "path": str(path),
            "size": result.st_size,
            "mtime_ns": result.st_mtime_ns,
            "inode": result.st_ino,
            "device": result.st_dev,
        }

    @staticmethod
    def _safe_path_under(root: Path, relative: str, error_code: str) -> Path:
        relpath = Path(str(relative or ""))
        if not relative or relpath.is_absolute() or ".." in relpath.parts:
            raise PairDropStoreError(error_code)
        candidate = root / relpath
        try:
            resolved_root = root.resolve(strict=True)
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise PairDropStoreError(error_code) from exc
        if resolved != resolved_root and resolved_root not in resolved.parents:
            raise PairDropStoreError(error_code)
        current = root
        for part in relpath.parts:
            current = current / part
            try:
                if stat.S_ISLNK(current.lstat().st_mode):
                    raise PairDropStoreError(error_code)
            except OSError as exc:
                raise PairDropStoreError(error_code) from exc
        return candidate

    def _write_migration_receipt(self, receipt: dict[str, Any]) -> None:
        payload = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
        temporary = self.root / f".{self.migration_receipt_path.name}.{os.getpid()}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = -1
        try:
            fd = os.open(str(temporary), flags, 0o600)
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(temporary, self.migration_receipt_path)
            directory_fd = os.open(str(self.root), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

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

    def get_upload_session(
        self,
        upload_id: str,
        *,
        source_device_id: str | None = None,
        source_install_id: str | None = None,
    ) -> dict[str, Any]:
        if not self._valid_upload_id(upload_id):
            raise PairDropStoreError("bad_upload_id")
        with self._connect() as conn:
            self._ensure_schema(conn)
            row = conn.execute("SELECT * FROM upload_sessions WHERE upload_id = ?", (upload_id,)).fetchone()
        if row is None:
            raise PairDropStoreError("upload_not_found")
        session = self._public_upload_row(row)
        if source_device_id is not None or source_install_id is not None:
            self._assert_upload_source(
                session,
                str(source_device_id or ""),
                str(source_install_id or ""),
            )
        return session

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
        with self._upload_operation_lock(upload_id):
            return self._write_upload_chunk_locked(
                upload_id,
                offset=offset,
                data=data,
                chunk_sha256=chunk_sha256,
                idempotency_key=idempotency_key,
                source_device_id=source_device_id,
                source_install_id=source_install_id,
            )

    def _write_upload_chunk_locked(
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
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM upload_sessions WHERE upload_id = ?", (upload_id,)).fetchone()
            if row is None:
                raise PairDropStoreError("upload_not_found")
            session = self._public_upload_row(row)
            self._assert_upload_source(session, source_device_id, source_install_id)
            if session["state"] in {"completing", "committed", "cancelled", "expired", "failed_terminal"}:
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
        with self._upload_operation_lock(upload_id):
            return self._complete_upload_session_locked(
                upload_id,
                source_device_id=source_device_id,
                source_install_id=source_install_id,
            )

    def _complete_upload_session_locked(
        self,
        upload_id: str,
        *,
        source_device_id: str,
        source_install_id: str,
    ) -> dict[str, Any]:
        session = self.get_upload_session(
            upload_id,
            source_device_id=source_device_id,
            source_install_id=source_install_id,
        )
        if session["state"] == "committed" and session.get("file_id"):
            return {
                "ok": True,
                "state": "committed",
                "upload_id": upload_id,
                "file": self.get_file(session["file_id"]),
            }
        if session["state"] in {"cancelled", "expired", "failed_terminal"}:
            raise PairDropStoreError("upload_not_completable")

        if session["state"] == "completing":
            recovered = self._recover_completed_upload_session(session)
            if recovered is not None:
                return recovered
        else:
            partial = self._partial_path(upload_id)
            if partial.is_symlink() or not partial.is_file():
                self._mark_upload_error(upload_id, "failed_retryable", "missing_partial")
                raise PairDropStoreError("missing_partial")
            byte_size = partial.stat().st_size
            if byte_size != int(session["total_byte_count"]):
                self._mark_upload_error(upload_id, "failed_retryable", "byte_count_mismatch")
                raise PairDropStoreError("byte_count_mismatch")
            if int(session["verified_offset"] or 0) != byte_size:
                self._mark_upload_error(upload_id, "failed_retryable", "verified_offset_mismatch")
                raise PairDropStoreError("verified_offset_mismatch")
            digest = self._sha256_file(partial)
            if digest != session["expected_sha256"]:
                self._mark_upload_error(upload_id, "failed_terminal", "sha256_mismatch")
                raise PairDropStoreError("sha256_mismatch")
            session = self._claim_upload_completion(session)

        file_id = str(session.get("file_id") or "")
        if session["state"] != "completing" or not self._valid_id(file_id):
            raise PairDropStoreError("upload_completion_ownership_lost")
        digest = str(session["expected_sha256"])
        partial = self._partial_path(upload_id)
        target = self.objects_dir / digest[:2] / f"{file_id}.blob"
        target.parent.mkdir(parents=True, exist_ok=True)

        if target.exists() or target.is_symlink():
            recovered = self._recover_completed_upload_session(session)
            if recovered is not None:
                try:
                    partial.unlink()
                except FileNotFoundError:
                    pass
                return recovered
            raise PairDropStoreError("completion_file_conflict")
        if partial.is_symlink() or not partial.is_file():
            raise PairDropStoreError("missing_partial")
        if partial.stat().st_size != int(session["total_byte_count"]):
            raise PairDropStoreError("byte_count_mismatch")
        if self._sha256_file(partial) != digest:
            raise PairDropStoreError("sha256_mismatch")

        os.replace(partial, target)
        return self._commit_recovered_upload_session(
            session,
            file_id,
            target,
            event_type="upload_session_committed",
        )

    def _claim_upload_completion(self, session: dict[str, Any]) -> dict[str, Any]:
        upload_id = str(session["upload_id"])
        expected_state = str(session["state"])
        if expected_state not in {"created", "receiving", "failed_retryable"}:
            raise PairDropStoreError("upload_not_completable")
        file_id = "pd_" + secrets.token_hex(16)
        now = _now_iso()
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM upload_sessions WHERE upload_id = ?",
                (upload_id,),
            ).fetchone()
            if row is None:
                raise PairDropStoreError("upload_not_found")
            current = self._public_upload_row(row)
            self._assert_upload_source(
                current,
                str(session["source_device_id"] or ""),
                str(session["source_install_id"] or ""),
            )
            changed = conn.execute(
                """
                UPDATE upload_sessions
                   SET file_id = ?, state = 'completing', updated_at = ?, last_error = NULL
                 WHERE upload_id = ? AND state = ?
                """,
                (file_id, now, upload_id, expected_state),
            ).rowcount
            if changed != 1:
                raise PairDropStoreError(
                    "upload_already_completing"
                    if current["state"] == "completing"
                    else "upload_not_completable"
                )
            conn.commit()
        return self.get_upload_session(upload_id)

    def _recover_completed_upload_session(self, session: dict[str, Any]) -> dict[str, Any] | None:
        upload_id = str(session.get("upload_id") or "")
        expected_sha256 = str(session.get("expected_sha256") or "")
        total_byte_count = int(session.get("total_byte_count") or 0)
        file_id = str(session.get("file_id") or "")
        if session.get("state") != "completing" or not self._valid_id(file_id):
            return None
        candidate = self.objects_dir / expected_sha256[:2] / f"{file_id}.blob"
        try:
            if candidate.is_symlink() or not candidate.is_file():
                return None
            if candidate.stat().st_size != total_byte_count:
                return None
            if self._sha256_file(candidate) != expected_sha256:
                return None
            return self._commit_recovered_upload_session(session, file_id, candidate)
        except FileNotFoundError:
            return None
        return None

    def _commit_recovered_upload_session(
        self,
        session: dict[str, Any],
        file_id: str,
        object_path: Path,
        *,
        event_type: str = "upload_session_recovered",
    ) -> dict[str, Any]:
        upload_id = str(session["upload_id"])
        byte_size = int(session["total_byte_count"])
        digest = str(session["expected_sha256"])
        if session.get("state") != "completing" or str(session.get("file_id") or "") != file_id:
            raise PairDropStoreError("upload_completion_ownership_lost")
        if object_path.is_symlink() or not object_path.is_file():
            raise PairDropStoreError("missing_object")
        if object_path.stat().st_size != byte_size or self._sha256_file(object_path) != digest:
            raise PairDropStoreError("completion_file_conflict")
        relpath = object_path.relative_to(self.root)
        now = _now_iso()
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            upload_row = conn.execute(
                "SELECT * FROM upload_sessions WHERE upload_id = ?",
                (upload_id,),
            ).fetchone()
            if upload_row is None:
                raise PairDropStoreError("upload_not_found")
            current = self._public_upload_row(upload_row)
            self._assert_upload_source(
                current,
                str(session["source_device_id"] or ""),
                str(session["source_install_id"] or ""),
            )
            if current["state"] != "completing" or str(current.get("file_id") or "") != file_id:
                raise PairDropStoreError("upload_completion_ownership_lost")
            existing = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
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
            else:
                existing_item = self._public_row(existing)
                if (
                    existing_item["kind"] != "file"
                    or int(existing_item["byte_size"] or 0) != byte_size
                    or str(existing_item["sha256"] or "") != digest
                    or str(existing_item["storage_relpath"] or "") != str(relpath)
                    or existing_item["deleted_at"] is not None
                ):
                    raise PairDropStoreError("completion_file_conflict")
            changed = conn.execute(
                """
                UPDATE upload_sessions
                   SET file_id = ?, state = 'committed', verified_offset = ?,
                       updated_at = ?, last_error = NULL
                 WHERE upload_id = ? AND state = 'completing' AND file_id = ?
                """,
                (file_id, byte_size, now, upload_id, file_id),
            ).rowcount
            if changed != 1:
                raise PairDropStoreError("upload_completion_ownership_lost")
            self._record_event(conn, event_type, file_id, {"upload_id": upload_id})
            conn.commit()
        item = self.get_file(file_id)
        audit_event = (
            "upload_session.committed"
            if event_type == "upload_session_committed"
            else "upload_session.recovered"
        )
        self._audit(audit_event, {
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
        now = _now_iso()
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM upload_sessions WHERE upload_id = ?",
                (upload_id,),
            ).fetchone()
            if row is None:
                raise PairDropStoreError("upload_not_found")
            session = self._public_upload_row(row)
            self._assert_upload_source(session, source_device_id, source_install_id)
            if session["state"] == "committed":
                raise PairDropStoreError("upload_already_committed")
            if session["state"] == "completing":
                raise PairDropStoreError("upload_already_completing")
            if session["state"] == "cancelled":
                return session
            changed = conn.execute(
                """
                UPDATE upload_sessions
                   SET state = 'cancelled', updated_at = ?, last_error = NULL
                 WHERE upload_id = ? AND state = ?
                """,
                (now, upload_id, session["state"]),
            ).rowcount
            if changed != 1:
                raise PairDropStoreError("upload_not_cancellable")
            self._record_event(conn, "upload_session_cancelled", None, {"upload_id": upload_id})
            conn.commit()
        self._audit("upload_session.cancelled", {"upload_id": upload_id})
        return self.get_upload_session(
            upload_id,
            source_device_id=source_device_id,
            source_install_id=source_install_id,
        )

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

    def verified_read_descriptor(
        self,
        file_id: str,
        *,
        source_device_id: str | None = None,
        source_install_id: str | None = None,
        required_source_route: str | None = None,
    ) -> dict[str, Any]:
        """Resolve a committed file without changing metadata or audit state."""

        item = self.get_file(file_id)
        if source_device_id is not None or source_install_id is not None:
            if (
                item.get("source_device_id") != str(source_device_id or "")
                or item.get("source_install_id") != str(source_install_id or "")
            ):
                raise PairDropStoreError("wrong_source")
        if required_source_route is not None and item.get("source_route") != required_source_route:
            raise PairDropStoreError("wrong_source_route")
        path = self._object_path(item)
        if path.is_symlink() or not path.is_file():
            raise PairDropStoreError("missing_object")
        root = self.root.resolve()
        resolved = path.resolve()
        if resolved != root and root not in resolved.parents:
            raise PairDropStoreError("object_escape")
        byte_size = int(item.get("byte_size") or 0)
        if path.stat().st_size != byte_size:
            raise PairDropStoreError("byte_size_mismatch")
        expected_sha256 = str(item.get("sha256") or "")
        if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
            raise PairDropStoreError("missing_sha256")
        if self._sha256_regular_file(path) != expected_sha256:
            raise PairDropStoreError("sha256_mismatch")
        return {"item": item, "path": path}

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
        now = _now_iso()
        expired = 0
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """
                SELECT upload_id FROM upload_sessions
                 WHERE state NOT IN ('completing', 'committed', 'cancelled', 'expired', 'failed_terminal')
                   AND expires_at <= ?
                """,
                (now,),
            ).fetchall()
            for row in rows:
                conn.execute(
                    """
                    UPDATE upload_sessions
                       SET state = 'expired', updated_at = ?
                     WHERE upload_id = ?
                       AND state NOT IN ('completing', 'committed', 'cancelled', 'expired', 'failed_terminal')
                    """,
                    (now, row["upload_id"]),
                )
                expired += int(conn.execute("SELECT changes()").fetchone()[0])
            active_upload_ids = {
                str(row["upload_id"])
                for row in conn.execute(
                    """
                    SELECT upload_id FROM upload_sessions
                     WHERE state = 'completing'
                        OR (
                            state NOT IN ('committed', 'cancelled', 'expired', 'failed_terminal')
                            AND expires_at > ?
                        )
                    """,
                    (now,),
                ).fetchall()
            }
            conn.commit()

        removed = 0
        preserved_active = 0
        skipped_symlinks = 0
        for path in self.partials_dir.glob("*.partial"):
            try:
                path_stat = path.lstat()
                if path.is_symlink():
                    skipped_symlinks += 1
                    continue
                upload_id = path.name.removesuffix(".partial")
                if upload_id in active_upload_ids:
                    preserved_active += 1
                    continue
                if path_stat.st_mtime < cutoff:
                    path.unlink()
                    removed += 1
            except FileNotFoundError:
                continue
        self._audit("partials.cleaned", {
            "removed": removed,
            "preserved_active": preserved_active,
            "skipped_symlinks": skipped_symlinks,
            "expired_sessions": expired,
        })
        return {
            "ok": True,
            "removed": removed,
            "preserved_active": preserved_active,
            "skipped_symlinks": skipped_symlinks,
            "expired_sessions": expired,
        }

    def _object_path(self, item: dict[str, Any]) -> Path:
        relpath = str(item.get("storage_relpath") or "")
        if relpath.startswith("/") or ".." in Path(relpath).parts:
            raise PairDropStoreError("unsafe_object_path")
        path = self.root / relpath
        if path.is_symlink():
            raise PairDropStoreError("unsafe_object_path")
        resolved = path.resolve()
        root = self.root.resolve()
        if root not in resolved.parents and resolved != root:
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
        if state not in {"failed_retryable", "failed_terminal"}:
            raise PairDropStoreError("bad_upload_error_state")
        now = _now_iso()
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute(
                """
                UPDATE upload_sessions
                   SET state = ?, last_error = ?, updated_at = ?
                 WHERE upload_id = ?
                   AND state IN ('created', 'receiving', 'failed_retryable')
                """,
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
