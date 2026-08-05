#!/usr/bin/env python3
"""Mac-local PairDrop vault storage.

PairDrop stores user files under a Pairling-owned root and exposes files by
opaque ids, never by client-supplied paths. This module intentionally has no
HTTP dependency so daemon tests can exercise the storage contract directly.
"""

from __future__ import annotations

import base64
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
import unicodedata
from dataclasses import dataclass, field
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from public_diagnostics import redact_public_diagnostic
from typing import Any


class PairDropStoreError(ValueError):
    def __init__(self, code: str, message: str | None = None):
        super().__init__(message or code)
        self.code = code


GIB = 1024 * 1024 * 1024
DEFAULT_MAX_TRANSFER_BYTES = 4 * GIB
MIN_MAX_TRANSFER_BYTES = 1 * GIB
MAX_MAX_TRANSFER_BYTES = 16 * GIB
MAX_INLINE_UPLOAD_BYTES = 10 * 1024 * 1024
DEFAULT_FREE_SPACE_RESERVE_BYTES = 256 * 1024 * 1024
MAX_FREE_SPACE_RESERVE_BYTES = 4 * GIB
MAX_ORIGINAL_NAME_LENGTH = 255
MAX_CONTENT_TYPE_LENGTH = 127
DEFAULT_LIST_PAGE_SIZE = 100
MAX_LIST_PAGE_SIZE = 200
MAX_CREATE_IDEMPOTENCY_KEY_LENGTH = 200
UPLOAD_LEASE_SECONDS = 24 * 60 * 60
UPLOAD_PROGRESS_EVENT_BYTES = 64 * 1024 * 1024
UPLOAD_TERMINAL_STATES = frozenset({"committed", "cancelled", "expired", "failed_terminal"})
DEFAULT_ATTACHMENT_TTL_SECONDS = 24 * 60 * 60
MAX_ATTACHMENT_TTL_SECONDS = 7 * 24 * 60 * 60
SEND_STAGING_RETENTION_SECONDS = MAX_ATTACHMENT_TTL_SECONDS
MAX_ATTACHMENT_IDEMPOTENCY_KEY_LENGTH = 200
ATTACHMENT_HANDLE_PATTERN = re.compile(r"att_[a-f0-9]{48}")
PROVIDER_QUALIFIED_SESSION_PATTERN = re.compile(
    r"[a-z][a-z0-9_-]{0,31}:[A-Za-z0-9._:-]{1,256}"
)

@dataclass(frozen=True)
class PreparedAttachment:
    handle_id: str
    sha256: str
    size_bytes: int
    mime_type: str
    display_name: str | None

    def materialize_local_path_for_send(self) -> Path:
        """Copy verified bytes to a private, immutable path for deferred reads."""

        return self._materialize_local_path()

    _open_verified: Callable[[], Any] = field(repr=False, compare=False)
    _materialize_local_path: Callable[[], Path] = field(repr=False, compare=False)

    def open_verified(self):
        """Open the same verified object without exposing its local path."""

        return self._open_verified()


def _bounded_environment_bytes(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        configured = int(str(os.environ.get(name, default)).strip())
    except (TypeError, ValueError):
        configured = default
    return max(minimum, min(configured, maximum))


PAIRLING_PAIRDROP_MAX_TRANSFER_BYTES = _bounded_environment_bytes(
    "PAIRLING_PAIRDROP_MAX_TRANSFER_BYTES",
    DEFAULT_MAX_TRANSFER_BYTES,
    MIN_MAX_TRANSFER_BYTES,
    MAX_MAX_TRANSFER_BYTES,
)
PAIRLING_PAIRDROP_FREE_SPACE_RESERVE_BYTES = _bounded_environment_bytes(
    "PAIRLING_PAIRDROP_FREE_SPACE_RESERVE_BYTES",
    DEFAULT_FREE_SPACE_RESERVE_BYTES,
    0,
    MAX_FREE_SPACE_RESERVE_BYTES,
)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _iso_from_epoch(value: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))


def _safe_display_name(filename: str) -> str:
    normalized = unicodedata.normalize("NFC", str(filename or "").strip())
    base = re.split(r"[/\\]", normalized)[-1]
    safe = "".join(
        character
        for character in base
        if unicodedata.category(character) not in {"Cc", "Cf"}
    ).strip()
    if not safe:
        return "upload.bin"
    if len(safe) <= 120:
        return safe
    stem, dot, ext = safe.rpartition(".")
    if dot and 1 <= len(ext) <= 12:
        return stem[: 120 - len(ext) - 1] + "." + ext
    return safe[:120]


def _validated_original_name(filename: Any) -> str:
    if not isinstance(filename, str):
        raise PairDropStoreError("bad_filename")
    value = filename.strip()
    if not value:
        raise PairDropStoreError("filename_required")
    if len(value) > MAX_ORIGINAL_NAME_LENGTH:
        raise PairDropStoreError("filename_too_long")
    return value


def _normalized_content_type(content_type: Any) -> str:
    if content_type is None or content_type == "":
        return "application/octet-stream"
    if not isinstance(content_type, str):
        raise PairDropStoreError("bad_content_type")
    value = content_type.strip().lower()
    if (
        not value
        or len(value) > MAX_CONTENT_TYPE_LENGTH
        or not re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", value)
    ):
        raise PairDropStoreError("bad_content_type")
    return value


def _normalized_create_idempotency_key(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise PairDropStoreError("bad_create_idempotency_key")
    key = value.strip()
    if (
        not key
        or len(key) > MAX_CREATE_IDEMPOTENCY_KEY_LENGTH
        or not re.fullmatch(r"[A-Za-z0-9._:-]+", key)
    ):
        raise PairDropStoreError("bad_create_idempotency_key")
    return key


def _encode_file_cursor(created_at: str, file_id: str) -> str:
    payload = json.dumps(
        {"created_at": created_at, "id": file_id},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _decode_file_cursor(cursor: Any) -> tuple[str, str]:
    if not isinstance(cursor, str) or not cursor or len(cursor) > 512:
        raise PairDropStoreError("bad_cursor")
    try:
        padding = "=" * (-len(cursor) % 4)
        payload = base64.b64decode(
            cursor + padding,
            altchars=b"-_",
            validate=True,
        )
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise PairDropStoreError("bad_cursor") from exc
    if not isinstance(value, dict):
        raise PairDropStoreError("bad_cursor")
    created_at = value.get("created_at")
    file_id = value.get("id")
    if (
        not isinstance(created_at, str)
        or not created_at
        or len(created_at) > 40
        or not isinstance(file_id, str)
        or not re.fullmatch(r"pd_[a-f0-9]{32}", file_id)
    ):
        raise PairDropStoreError("bad_cursor")
    return created_at, file_id


def _json_list(value: Any) -> str:
    return json.dumps(value if isinstance(value, list) else [])


class PairDropStore:
    schema_version = 1
    sqlite_busy_timeout_ms = 10_000

    def __init__(
        self,
        root: Path,
        *,
        legacy_root: Path | None = None,
        migrate_legacy: bool = True,
        max_transfer_bytes: int = PAIRLING_PAIRDROP_MAX_TRANSFER_BYTES,
        free_space_reserve_bytes: int = PAIRLING_PAIRDROP_FREE_SPACE_RESERVE_BYTES,
        free_space_provider: Callable[[Path], int] | None = None,
    ):
        self._schema_ready = False
        self.root = Path(root).expanduser()
        self.max_transfer_bytes = max(
            MIN_MAX_TRANSFER_BYTES,
            min(int(max_transfer_bytes), MAX_MAX_TRANSFER_BYTES),
        )
        self.free_space_reserve_bytes = max(
            0,
            min(int(free_space_reserve_bytes), MAX_FREE_SPACE_RESERVE_BYTES),
        )
        self._free_space_provider = free_space_provider or (
            lambda path: int(shutil.disk_usage(path).free)
        )
        self.objects_dir = self.root / "objects"
        self.partials_dir = self.root / "partials"
        self.purge_dir = self.root / ".purge-recovery"
        self.thumbnails_dir = self.root / "thumbnails"
        self.exports_dir = self.root / "exports"
        self.send_staging_dir = self.root / "send-staging"
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
        owned_directories = [
            self.root,
            self.objects_dir,
            self.partials_dir,
            self.purge_dir,
            self.thumbnails_dir,
            self.exports_dir,
            self.send_staging_dir,
        ]
        for path in owned_directories:
            path.mkdir(parents=True, exist_ok=True)
            try:
                path_stat = path.lstat()
            except OSError as exc:
                raise PairDropStoreError("unsafe_owned_directory") from exc
            if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISDIR(path_stat.st_mode):
                raise PairDropStoreError("unsafe_owned_directory")
        try:
            # PairDrop stores private user files; the vault root must not be world-readable.
            os.chmod(self.root, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            os.chmod(self.purge_dir, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            os.chmod(self.send_staging_dir, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        except OSError:
            pass
        with self._initialization_lock():
            with self._connect() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                self._ensure_schema(conn)

    @contextmanager
    def _purge_directory_fd(self) -> Iterator[int]:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        root_fd = -1
        purge_fd = -1
        try:
            try:
                root_fd = os.open(self.root, flags)
                if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
                    raise PairDropStoreError("unsafe_purge_recovery_path")
                purge_fd = os.open(".purge-recovery", flags, dir_fd=root_fd)
                if not stat.S_ISDIR(os.fstat(purge_fd).st_mode):
                    raise PairDropStoreError("unsafe_purge_recovery_path")
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR, errno.ENOENT}:
                    raise PairDropStoreError("unsafe_purge_recovery_path") from exc
                raise
            yield purge_fd
        finally:
            if purge_fd >= 0:
                os.close(purge_fd)
            if root_fd >= 0:
                os.close(root_fd)

    @contextmanager
    def _object_parent_directory_fd(
        self,
        storage_relpath: str,
        *,
        create_shard: bool = False,
    ) -> Iterator[tuple[int, str]]:
        relative = Path(str(storage_relpath or ""))
        if (
            not storage_relpath
            or relative.is_absolute()
            or len(relative.parts) != 3
            or relative.parts[0] != "objects"
            or re.fullmatch(r"[a-f0-9]{2}", relative.parts[1]) is None
            or re.fullmatch(r"pd_[a-f0-9]{32}\.blob", relative.name) is None
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise PairDropStoreError("unsafe_object_path")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptors: list[int] = []
        try:
            try:
                current_fd = os.open(self.root, flags)
                descriptors.append(current_fd)
                if not stat.S_ISDIR(os.fstat(current_fd).st_mode):
                    raise PairDropStoreError("unsafe_object_path")
                for index, component in enumerate(relative.parts[:-1]):
                    if create_shard and index == len(relative.parts[:-1]) - 1:
                        try:
                            os.mkdir(component, 0o700, dir_fd=current_fd)
                        except FileExistsError:
                            pass
                    current_fd = os.open(component, flags, dir_fd=current_fd)
                    descriptors.append(current_fd)
                    if not stat.S_ISDIR(os.fstat(current_fd).st_mode):
                        raise PairDropStoreError("unsafe_object_path")
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR, errno.ENOENT}:
                    raise PairDropStoreError("unsafe_object_path") from exc
                raise
            yield descriptors[-1], relative.name
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    @contextmanager
    def _owned_child_directory_fd(self, name: str, error_code: str) -> Iterator[int]:
        if name not in {"objects", "partials", "send-staging"}:
            raise PairDropStoreError(error_code)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        root_fd = -1
        child_fd = -1
        try:
            try:
                root_fd = os.open(self.root, flags)
                if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
                    raise PairDropStoreError(error_code)
                child_fd = os.open(name, flags, dir_fd=root_fd)
                if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
                    raise PairDropStoreError(error_code)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR, errno.ENOENT}:
                    raise PairDropStoreError(error_code) from exc
                raise
            yield child_fd
        finally:
            if child_fd >= 0:
                os.close(child_fd)
            if root_fd >= 0:
                os.close(root_fd)

    def _fsync_published_object(self, storage_relpath: str, expected_size: int) -> None:
        object_fd = -1
        try:
            with (
                self._owned_child_directory_fd("partials", "unsafe_partial_path") as partials_fd,
                self._owned_child_directory_fd("objects", "unsafe_object_path") as objects_fd,
                self._object_parent_directory_fd(storage_relpath) as (object_parent_fd, object_name),
            ):
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                try:
                    object_fd = os.open(object_name, flags, dir_fd=object_parent_fd)
                except FileNotFoundError as exc:
                    raise PairDropStoreError("missing_object") from exc
                object_stat = os.fstat(object_fd)
                if not stat.S_ISREG(object_stat.st_mode):
                    raise PairDropStoreError("unsafe_object_path")
                if object_stat.st_size != expected_size:
                    raise PairDropStoreError("byte_size_mismatch")
                os.fsync(object_fd)
                self._fsync_directory_pair(partials_fd, object_parent_fd)
                os.fsync(objects_fd)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                raise PairDropStoreError("unsafe_object_path") from exc
            raise
        finally:
            if object_fd >= 0:
                os.close(object_fd)

    def _write_inline_object(
        self,
        storage_relpath: str,
        partial_name: str,
        data: bytes,
    ) -> None:
        descriptor = -1
        moved = False
        try:
            with (
                self._owned_child_directory_fd("partials", "unsafe_partial_path") as partials_fd,
                self._object_parent_directory_fd(
                    storage_relpath,
                    create_shard=True,
                ) as (object_parent_fd, object_name),
            ):
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(partial_name, flags, 0o600, dir_fd=partials_fd)
                view = memoryview(data)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError(errno.EIO, "short PairDrop write")
                    view = view[written:]
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                os.replace(
                    partial_name,
                    object_name,
                    src_dir_fd=partials_fd,
                    dst_dir_fd=object_parent_fd,
                )
                moved = True
            self._fsync_published_object(storage_relpath, len(data))
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                raise PairDropStoreError(
                    "unsafe_object_path" if moved else "unsafe_partial_path"
                ) from exc
            if exc.errno in {errno.ENOSPC, getattr(errno, "EDQUOT", -1)}:
                raise PairDropStoreError("insufficient_storage") from exc
            raise
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _unlink_object_if_present(self, storage_relpath: str) -> bool:
        with (
            self._owned_child_directory_fd("objects", "unsafe_object_path") as objects_fd,
            self._object_parent_directory_fd(storage_relpath) as (object_parent_fd, object_name),
        ):
            object_stat = self._purge_entry_stat(object_parent_fd, object_name)
            if object_stat is not None and (
                stat.S_ISLNK(object_stat.st_mode) or not stat.S_ISREG(object_stat.st_mode)
            ):
                raise PairDropStoreError("unsafe_object_path")
            removed = object_stat is not None
            if removed:
                os.unlink(object_name, dir_fd=object_parent_fd)
            os.fsync(object_parent_fd)
            os.fsync(objects_fd)
            return removed

    @staticmethod
    def _fsync_directory_pair(source_fd: int, destination_fd: int) -> None:
        first_error: OSError | None = None
        try:
            os.fsync(source_fd)
        except OSError as exc:
            first_error = exc
        if destination_fd != source_fd:
            try:
                os.fsync(destination_fd)
            except OSError as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error

    @staticmethod
    def _purge_entry_stat(directory_fd: int, name: str) -> os.stat_result | None:
        try:
            return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    @staticmethod
    def _require_regular_purge_entry(info: os.stat_result | None) -> None:
        if info is not None and not stat.S_ISREG(info.st_mode):
            raise PairDropStoreError("unsafe_purge_recovery_path")

    @staticmethod
    def _unlink_purge_entry(directory_fd: int, name: str) -> None:
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass

    def _write_purge_recovery_record(
        self,
        directory_fd: int,
        name: str,
        *,
        file_id: str,
        display_name_sha256: str,
        storage_relpath: str,
    ) -> None:
        payload = json.dumps(
            {
                "contract": "pairdrop-purge-recovery-v1",
                "file_id": file_id,
                "display_name_sha256": display_name_sha256,
                "storage_relpath": storage_relpath,
                "reason": "commit_state_unavailable",
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8") + b"\n"
        temporary_name = f".{name}.{secrets.token_hex(8)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
            written = 0
            while written < len(payload):
                written += os.write(descriptor, payload[written:])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(
                temporary_name,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.fsync(directory_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass

    def _fresh_file_row_state(self, file_id: str) -> bool | None:
        connection = None
        try:
            connection = sqlite3.connect(
                str(self.db_path),
                timeout=self.sqlite_busy_timeout_ms / 1000,
            )
            connection.execute("PRAGMA busy_timeout=10000")
            return connection.execute(
                "SELECT 1 FROM files WHERE id = ?",
                (file_id,),
            ).fetchone() is not None
        except Exception:
            return None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass

    def _open_purge_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.db_path),
            timeout=self.sqlite_busy_timeout_ms / 1000,
        )
        connection.execute("PRAGMA busy_timeout=10000")
        connection.row_factory = sqlite3.Row
        return connection

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
    def _upload_operation_lock(
        self,
        upload_id: str,
        *,
        remove_if_terminal: bool = False,
    ) -> Iterator[None]:
        """Serialize one upload's file and database state across processes."""

        if not self._valid_upload_id(upload_id):
            raise PairDropStoreError("bad_upload_id")
        path = self.partials_dir / f".{upload_id}.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = -1
        locked = False
        try:
            fd = os.open(str(path), flags, 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise PairDropStoreError("unsafe_upload_lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            locked = True
            yield
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                raise PairDropStoreError("unsafe_upload_lock") from exc
            raise
        finally:
            if fd >= 0:
                try:
                    if locked and remove_if_terminal:
                        self._remove_terminal_upload_lock(upload_id, fd)
                    if locked:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    def _remove_terminal_upload_lock(self, upload_id: str, lock_fd: int) -> None:
        """Remove this lock inode once its upload can no longer mutate."""

        try:
            with self._connect() as conn:
                self._ensure_schema(conn)
                row = conn.execute(
                    "SELECT state FROM upload_sessions WHERE upload_id = ?",
                    (upload_id,),
                ).fetchone()
            if row is not None and str(row["state"] or "") not in UPLOAD_TERMINAL_STATES:
                return
            owned_stat = os.fstat(lock_fd)
            name = f".{upload_id}.lock"
            with self._owned_child_directory_fd(
                "partials",
                "unsafe_partial_path",
            ) as partials_fd:
                current_stat = os.stat(name, dir_fd=partials_fd, follow_symlinks=False)
                if (
                    not stat.S_ISREG(current_stat.st_mode)
                    or current_stat.st_dev != owned_stat.st_dev
                    or current_stat.st_ino != owned_stat.st_ino
                ):
                    return
                os.unlink(name, dir_fd=partials_fd)
                os.fsync(partials_fd)
        except (OSError, PairDropStoreError, sqlite3.Error):
            # Lock cleanup is best-effort. Keeping the lock inode is safe and
            # cleanup_partials can collect it after the operation is terminal.
            return

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=self.sqlite_busy_timeout_ms / 1000,
        )
        conn.execute("PRAGMA busy_timeout=10000")
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
        if self._schema_ready:
            return
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
                create_idempotency_key TEXT,
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attachment_handles (
                handle TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                source_device_id TEXT NOT NULL,
                source_install_id TEXT NOT NULL,
                idempotency_key TEXT,
                file_sha256 TEXT NOT NULL,
                file_byte_size INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at REAL NOT NULL,
                revoked_at TEXT,
                consumed_binding_id TEXT,
                consumed_client_action_id TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pairdrop_files_deleted ON files(deleted_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pairdrop_files_created ON files(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pairdrop_upload_sessions_state ON upload_sessions(state)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pairdrop_upload_sessions_expires ON upload_sessions(expires_at)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_attachment_handles_file "
            "ON attachment_handles(file_id, revoked_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_attachment_handles_session "
            "ON attachment_handles(session_id, revoked_at)"
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_attachment_handles_idempotency
                ON attachment_handles(
                    session_id,
                    source_device_id,
                    source_install_id,
                    idempotency_key
                )
             WHERE idempotency_key IS NOT NULL
            """
        )
        upload_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(upload_sessions)").fetchall()
        }
        if "create_idempotency_key" not in upload_columns:
            conn.execute(
                "ALTER TABLE upload_sessions ADD COLUMN create_idempotency_key TEXT"
            )
        attachment_columns = {
            row[1] for row in conn.execute(
                "PRAGMA table_info(attachment_handles)"
            ).fetchall()
        }
        for column in ("consumed_binding_id", "consumed_client_action_id"):
            if column not in attachment_columns:
                conn.execute(
                    f"ALTER TABLE attachment_handles ADD COLUMN {column} TEXT"
                )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_pairdrop_upload_create_idempotency
                ON upload_sessions(
                    source_device_id,
                    source_install_id,
                    create_idempotency_key
                )
             WHERE create_idempotency_key IS NOT NULL
            """
        )
        self._schema_ready = True

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
                conn.execute("PRAGMA busy_timeout=10000")
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
        if len(data) > MAX_INLINE_UPLOAD_BYTES:
            raise PairDropStoreError("transfer_too_large")
        original_name = _validated_original_name(filename)
        normalized_content_type = _normalized_content_type(content_type)
        display_name = _safe_display_name(original_name)
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
        now = _now_iso()
        try:
            with self._connect() as conn:
                self._ensure_schema(conn)
                conn.execute("BEGIN IMMEDIATE")
                self._expire_upload_reservations(conn, now)
                self._require_reserved_capacity(conn, additional_bytes=len(data))
                self._write_inline_object(str(relpath), partial.name, data)
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
                        original_name,
                        normalized_content_type,
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
                    "content_type": normalized_content_type,
                    "sha256": digest,
                })
        except Exception as exc:
            durable_row_state = self._fresh_file_row_state(file_id)
            if durable_row_state is False:
                try:
                    partial.unlink(missing_ok=True)
                except (OSError, TypeError):
                    pass
                try:
                    self._unlink_object_if_present(str(relpath))
                except (OSError, PairDropStoreError):
                    pass
            if durable_row_state is True:
                self._fsync_published_object(str(relpath), len(data))
            else:
                if isinstance(exc, OSError) and exc.errno in {
                    errno.ENOSPC,
                    getattr(errno, "EDQUOT", -1),
                }:
                    raise PairDropStoreError("insufficient_storage") from exc
                raise
        item = self.get_file(file_id)
        self._audit("file.created", {
            "file_id": file_id,
            "byte_size": len(data),
            "content_type": normalized_content_type,
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
        create_idempotency_key: str | None = None,
        expires_in_seconds: int = 24 * 60 * 60,
    ) -> dict[str, Any]:
        if type(total_byte_count) is not int:
            raise PairDropStoreError("bad_total_byte_count")
        total = total_byte_count
        digest = str(expected_sha256 or "").strip().lower()
        if total <= 0:
            raise PairDropStoreError("bad_total_byte_count")
        if total > self.max_transfer_bytes:
            raise PairDropStoreError("transfer_too_large")
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise PairDropStoreError("bad_expected_sha256")
        original_name = _validated_original_name(filename)
        normalized_content_type = _normalized_content_type(content_type)
        idempotency_key = _normalized_create_idempotency_key(
            create_idempotency_key
        )
        if idempotency_key and (not source_device_id or not source_install_id):
            raise PairDropStoreError("create_idempotency_source_required")
        # Reap terminal partials before evaluating current free space. Active
        # sessions stay protected by cleanup_partials.
        self.cleanup_partials(older_than_seconds=0)
        upload_id = "pu_" + secrets.token_hex(16)
        display_name = _safe_display_name(original_name)
        now = _now_iso()
        expires_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + max(60, int(expires_in_seconds))))
        reused_upload_id: str | None = None
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            self._expire_upload_reservations(conn, now)
            existing = None
            if idempotency_key:
                existing = conn.execute(
                    """
                    SELECT * FROM upload_sessions
                     WHERE source_device_id = ?
                       AND source_install_id = ?
                       AND create_idempotency_key = ?
                    """,
                    (source_device_id, source_install_id, idempotency_key),
                ).fetchone()
            if existing is not None:
                same_request = (
                    existing["original_name"] == original_name
                    and existing["content_type"] == normalized_content_type
                    and existing["total_byte_count"] == total
                    and existing["expected_sha256"] == digest
                )
                if not same_request:
                    raise PairDropStoreError("create_idempotency_conflict")
                if existing["state"] in {"cancelled", "expired", "failed_terminal"}:
                    conn.execute(
                        """
                        UPDATE upload_sessions
                           SET create_idempotency_key = NULL
                         WHERE upload_id = ?
                        """,
                        (existing["upload_id"],),
                    )
                else:
                    reused_upload_id = existing["upload_id"]

            if reused_upload_id is None:
                self._require_reserved_capacity(conn, additional_bytes=total)
                conn.execute(
                    """
                    INSERT INTO upload_sessions (
                        upload_id, file_id, display_name, original_name, content_type,
                        total_byte_count, expected_sha256, verified_offset,
                        source_device_id, source_install_id, source_route,
                        create_idempotency_key, state, last_error, created_at,
                        updated_at, expires_at
                    ) VALUES (?, NULL, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, 'created', NULL, ?, ?, ?)
                    """,
                    (
                        upload_id,
                        display_name,
                        original_name,
                        normalized_content_type,
                        total,
                        digest,
                        source_device_id,
                        source_install_id,
                        source_route,
                        idempotency_key,
                        now,
                        now,
                        expires_at,
                    ),
                )
                self._record_event(conn, "upload_session_created", None, {
                    "upload_id": upload_id,
                    "byte_size": total,
                    "content_type": normalized_content_type,
                })
            conn.commit()
        if reused_upload_id is not None:
            return self.get_upload_session(
                reused_upload_id,
                source_device_id=source_device_id,
                source_install_id=source_install_id,
            )
        self._audit("upload_session.created", {
            "upload_id": upload_id,
            "byte_size": total,
            "content_type": normalized_content_type,
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
        if session["state"] == "committed":
            self._verified_committed_upload_file(session)
        return session

    def _verified_committed_upload_file(self, session: dict[str, Any]) -> dict[str, Any]:
        file_id = str(session.get("file_id") or "")
        if session.get("state") != "committed" or not self._valid_id(file_id):
            raise PairDropStoreError("completion_file_conflict")
        item = self.get_file(file_id)
        expected_size = int(session.get("total_byte_count") or 0)
        expected_sha256 = str(session.get("expected_sha256") or "")
        expected_relpath = str(
            Path("objects") / expected_sha256[:2] / f"{file_id}.blob"
        )
        if (
            item.get("kind") != "file"
            or int(item.get("byte_size") or 0) != expected_size
            or str(item.get("sha256") or "") != expected_sha256
            or str(item.get("storage_relpath") or "") != expected_relpath
        ):
            raise PairDropStoreError("completion_file_conflict")
        with self._object_parent_directory_fd(expected_relpath) as (
            object_parent_fd,
            object_name,
        ):
            object_stat = self._purge_entry_stat(object_parent_fd, object_name)
            if object_stat is None:
                raise PairDropStoreError("missing_object")
            if stat.S_ISLNK(object_stat.st_mode) or not stat.S_ISREG(object_stat.st_mode):
                raise PairDropStoreError("unsafe_object_path")
            if object_stat.st_size != expected_size:
                raise PairDropStoreError("byte_size_mismatch")
        return item

    def write_upload_chunk(
        self,
        upload_id: str,
        *,
        offset: int,
        declared_total_byte_count: int | None = None,
        data: bytes,
        chunk_sha256: str,
        idempotency_key: str,
        source_device_id: str,
        source_install_id: str,
    ) -> dict[str, Any]:
        # Reject invented or foreign IDs before creating the durable
        # cross-process lock file. Real sessions are bounded by capacity;
        # attacker-chosen IDs are not.
        self.get_upload_session(
            upload_id,
            source_device_id=source_device_id,
            source_install_id=source_install_id,
        )
        with self._upload_operation_lock(upload_id):
            return self._write_upload_chunk_locked(
                upload_id,
                offset=offset,
                declared_total_byte_count=declared_total_byte_count,
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
        declared_total_byte_count: int | None,
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
            self._expire_upload_reservations(conn, _now_iso())
            row = conn.execute("SELECT * FROM upload_sessions WHERE upload_id = ?", (upload_id,)).fetchone()
            if row is None:
                raise PairDropStoreError("upload_not_found")
            session = self._public_upload_row(row)
            self._assert_upload_source(session, source_device_id, source_install_id)
            if session["state"] in {"completing", "committed", "cancelled", "expired", "failed_terminal"}:
                conn.commit()
                raise PairDropStoreError("upload_not_writable")
            if (
                declared_total_byte_count is not None
                and int(declared_total_byte_count) != int(session["total_byte_count"])
            ):
                raise PairDropStoreError("content_range_total_mismatch")

            verified_offset = int(session["verified_offset"] or 0)
            partial = self._partial_path(upload_id)
            if partial.is_symlink() or (partial.exists() and not partial.is_file()):
                raise PairDropStoreError("unsafe_partial_path")
            partial_size = partial.stat().st_size if partial.exists() else None
            if partial_size is None and verified_offset > 0 or (
                partial_size is not None and partial_size < verified_offset
            ):
                partial.unlink(missing_ok=True)
                conn.execute(
                    """
                    UPDATE upload_sessions
                       SET verified_offset = 0, state = 'failed_retryable',
                           last_error = 'upload_restart_required', updated_at = ?
                     WHERE upload_id = ?
                    """,
                    (_now_iso(), upload_id),
                )
                conn.execute(
                    "DELETE FROM upload_chunks WHERE upload_id = ?",
                    (upload_id,),
                )
                self._record_event(
                    conn,
                    "upload_session_restart_required",
                    None,
                    {"upload_id": upload_id},
                )
                conn.commit()
                raise PairDropStoreError("upload_restart_required")
            if partial_size is not None and partial_size > verified_offset:
                self._truncate_partial(upload_id, verified_offset)

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

            if offset < verified_offset:
                if self._partial_range_hash(upload_id, offset, len(data)) == chunk_hash:
                    return {**session, "idempotent": True}
                raise PairDropStoreError("chunk_mismatch")
            if offset != verified_offset:
                raise PairDropStoreError("unexpected_offset")
            if offset + len(data) > int(session["total_byte_count"]):
                raise PairDropStoreError("chunk_exceeds_total")

            self._require_reserved_capacity(conn)
            self._write_partial_range(upload_id, offset, data)
            new_offset = offset + len(data)
            now = _now_iso()
            expires_at = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(time.time() + UPLOAD_LEASE_SECONDS),
            )
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
                   SET verified_offset = ?, state = 'receiving', updated_at = ?,
                       expires_at = ?, last_error = NULL
                 WHERE upload_id = ?
                """,
                (new_offset, now, expires_at, upload_id),
            )
            records_progress = (
                new_offset == int(session["total_byte_count"])
                or new_offset // UPLOAD_PROGRESS_EVENT_BYTES
                > verified_offset // UPLOAD_PROGRESS_EVENT_BYTES
            )
            if records_progress:
                self._record_event(conn, "upload_session_progress", None, {
                    "upload_id": upload_id,
                    "verified_offset": new_offset,
                })
            conn.commit()

        if records_progress:
            self._audit("upload_session.progress", {
                "upload_id": upload_id,
                "verified_offset": new_offset,
                "total_byte_count": session["total_byte_count"],
            })
        updated = self.get_upload_session(upload_id)
        return {**updated, "idempotent": False}

    def _expire_upload_reservations(self, conn: sqlite3.Connection, now: str) -> None:
        conn.execute(
            """
            UPDATE upload_sessions
               SET state = 'expired', updated_at = ?
             WHERE state NOT IN ('completing', 'committed', 'cancelled', 'expired', 'failed_terminal')
               AND expires_at <= ?
            """,
            (now, now),
        )
        conn.execute(
            """
            DELETE FROM upload_chunks
             WHERE upload_id IN (
                SELECT upload_id FROM upload_sessions
                 WHERE state IN ('committed', 'cancelled', 'expired', 'failed_terminal')
             )
            """
        )

    def _reserved_upload_bytes(self, conn: sqlite3.Connection) -> int:
        row = conn.execute(
            """
            SELECT COALESCE(SUM(
                CASE
                    WHEN total_byte_count > verified_offset
                    THEN total_byte_count - verified_offset
                    ELSE 0
                END
            ), 0)
              FROM upload_sessions
             WHERE state NOT IN ('committed', 'cancelled', 'expired', 'failed_terminal')
            """
        ).fetchone()
        return max(0, int(row[0] if row is not None else 0))

    def _require_reserved_capacity(
        self,
        conn: sqlite3.Connection,
        *,
        additional_bytes: int = 0,
    ) -> None:
        reserved = self._reserved_upload_bytes(conn) + max(0, int(additional_bytes))
        required = reserved + self.free_space_reserve_bytes
        try:
            available = max(0, int(self._free_space_provider(self.root)))
        except (OSError, TypeError, ValueError) as exc:
            raise PairDropStoreError("free_space_unavailable") from exc
        if available < required:
            raise PairDropStoreError("insufficient_storage")

    def complete_upload_session(
        self,
        upload_id: str,
        *,
        source_device_id: str,
        source_install_id: str,
    ) -> dict[str, Any]:
        self.get_upload_session(
            upload_id,
            source_device_id=source_device_id,
            source_install_id=source_install_id,
        )
        with self._upload_operation_lock(upload_id, remove_if_terminal=True):
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
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            self._expire_upload_reservations(conn, _now_iso())
            row = conn.execute(
                "SELECT * FROM upload_sessions WHERE upload_id = ?",
                (upload_id,),
            ).fetchone()
            if row is None:
                raise PairDropStoreError("upload_not_found")
            session = self._public_upload_row(row)
            self._assert_upload_source(session, source_device_id, source_install_id)
            conn.commit()
        if session["state"] == "committed" and session.get("file_id"):
            return {
                "ok": True,
                "state": "committed",
                "upload_id": upload_id,
                "file": self._verified_committed_upload_file(session),
            }
        if session["state"] in {"cancelled", "expired", "failed_terminal"}:
            raise PairDropStoreError("upload_not_completable")

        verified_partial_identity: tuple[int, ...] | None = None
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
            verified_partial_identity = self._file_identity(partial)
            digest = self._sha256_file(partial)
            if self._file_identity(partial) != verified_partial_identity:
                self._mark_upload_error(upload_id, "failed_retryable", "partial_changed")
                raise PairDropStoreError("partial_changed")
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
        current_identity = self._file_identity(partial)
        if verified_partial_identity is None:
            verified_partial_identity = current_identity
            if self._sha256_file(partial) != digest:
                raise PairDropStoreError("sha256_mismatch")
            if self._file_identity(partial) != verified_partial_identity:
                raise PairDropStoreError("partial_changed")
        elif current_identity != verified_partial_identity:
            raise PairDropStoreError("partial_changed")

        storage_relpath = str(Path("objects") / digest[:2] / f"{file_id}.blob")
        with (
            self._owned_child_directory_fd("partials", "unsafe_partial_path") as partials_fd,
            self._object_parent_directory_fd(
                storage_relpath,
                create_shard=True,
            ) as (object_parent_fd, object_name),
        ):
            existing = self._purge_entry_stat(object_parent_fd, object_name)
            if existing is not None:
                raise PairDropStoreError("completion_file_conflict")
            os.replace(
                partial.name,
                object_name,
                src_dir_fd=partials_fd,
                dst_dir_fd=object_parent_fd,
            )
        # Rename updates ctime on macOS even though it moves the same inode and
        # content. Compare every stable content-identity field except ctime.
        if self._file_identity(target)[:-1] != verified_partial_identity[:-1]:
            raise PairDropStoreError("completion_file_conflict")
        return self._commit_recovered_upload_session(
            session,
            file_id,
            target,
            event_type="upload_session_committed",
            object_verified=True,
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
            candidate_identity = self._file_identity(candidate)
            if self._sha256_file(candidate) != expected_sha256:
                return None
            if self._file_identity(candidate) != candidate_identity:
                return None
            return self._commit_recovered_upload_session(
                session,
                file_id,
                candidate,
                object_verified=True,
            )
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
        object_verified: bool = False,
    ) -> dict[str, Any]:
        upload_id = str(session["upload_id"])
        byte_size = int(session["total_byte_count"])
        digest = str(session["expected_sha256"])
        if session.get("state") != "completing" or str(session.get("file_id") or "") != file_id:
            raise PairDropStoreError("upload_completion_ownership_lost")
        if object_path.is_symlink() or not object_path.is_file():
            raise PairDropStoreError("missing_object")
        if object_path.stat().st_size != byte_size:
            raise PairDropStoreError("completion_file_conflict")
        if not object_verified and self._sha256_file(object_path) != digest:
            raise PairDropStoreError("completion_file_conflict")
        relpath = object_path.relative_to(self.root)
        self._fsync_published_object(str(relpath), byte_size)
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
            conn.execute(
                "DELETE FROM upload_chunks WHERE upload_id = ?",
                (upload_id,),
            )
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
            conn.execute(
                "DELETE FROM upload_chunks WHERE upload_id = ?",
                (upload_id,),
            )
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

    def list_files_page(
        self,
        *,
        limit: int = DEFAULT_LIST_PAGE_SIZE,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        if type(limit) is not int or limit < 1 or limit > MAX_LIST_PAGE_SIZE:
            raise PairDropStoreError("bad_limit")
        cursor_values = _decode_file_cursor(cursor) if cursor is not None else None
        parameters: list[Any]
        if cursor_values is not None:
            created_at, file_id = cursor_values
            query = """
                SELECT * FROM files
                 WHERE deleted_at IS NULL
                   AND (created_at < ? OR (created_at = ? AND id < ?))
                 ORDER BY created_at DESC, id DESC
                 LIMIT ?
            """
            parameters = [created_at, created_at, file_id, limit + 1]
        else:
            query = """
                SELECT * FROM files
                 WHERE deleted_at IS NULL
                 ORDER BY created_at DESC, id DESC
                 LIMIT ?
            """
            parameters = [limit + 1]
        with self._connect() as conn:
            self._ensure_schema(conn)
            rows = conn.execute(query, parameters).fetchall()
        has_more = len(rows) > limit
        page_rows = rows[:limit]
        next_cursor = None
        if has_more and page_rows:
            last = page_rows[-1]
            next_cursor = _encode_file_cursor(last["created_at"], last["id"])
        return {
            "files": [self._public_row(row) for row in page_rows],
            "limit": limit,
            "has_more": has_more,
            "next_cursor": next_cursor,
        }

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
        if not self._valid_id(file_id):
            raise PairDropStoreError("bad_file_id")
        newly_deleted = False
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
            if row is None:
                raise PairDropStoreError("not_found")
            item = self._public_row(row)
            deleted_at = str(row["deleted_at"] or "")
            if not deleted_at:
                deleted_at = _now_iso()
                changed = conn.execute(
                    """
                    UPDATE files
                       SET deleted_at = ?, updated_at = ?
                     WHERE id = ? AND deleted_at IS NULL
                    """,
                    (deleted_at, deleted_at, file_id),
                ).rowcount
                if changed != 1:
                    raise PairDropStoreError("delete_conflict")
                conn.execute(
                    """
                    UPDATE upload_sessions
                       SET create_idempotency_key = NULL
                     WHERE file_id = ?
                    """,
                    (file_id,),
                )
                conn.execute(
                    """
                    UPDATE attachment_handles
                       SET revoked_at = ?
                     WHERE file_id = ? AND revoked_at IS NULL
                    """,
                    (deleted_at, file_id),
                )
                self._record_event(
                    conn,
                    "deleted",
                    file_id,
                    {"byte_size": item.get("byte_size", 0)},
                )
                newly_deleted = True
            conn.commit()
        if item.get("kind") == "file":
            self._unlink_object_if_present(str(item.get("storage_relpath") or ""))
        if newly_deleted:
            self._audit(
                "file.deleted",
                {"file_id": file_id, "byte_size": item.get("byte_size", 0)},
            )
        return {
            "ok": True,
            "id": file_id,
            "deleted_at": deleted_at,
            "idempotent": not newly_deleted,
        }

    def purge_deleted_file(self, file_id: str, *, expected_display_name: str) -> dict[str, Any]:
        """Physically remove one known deleted fixture.

        This is intentionally not exposed by the HTTP API. Maintenance tools
        must name the exact deleted file so they cannot turn a stale id into a
        broad data-deletion primitive.
        """
        if not self._valid_id(file_id):
            raise PairDropStoreError("bad_file_id")
        if not isinstance(expected_display_name, str) or not expected_display_name:
            raise PairDropStoreError("expected_display_name_required")
        display_digest = hashlib.sha256(expected_display_name.encode("utf-8")).hexdigest()
        display_tag = display_digest[:16]
        quarantine_name = f"{file_id}-{display_tag}.blob"
        recovery_name = f"{file_id}-{display_tag}.json"
        recovered_cleanup = False
        committed = False
        with self._purge_directory_fd() as purge_fd:
            quarantine_stat = self._purge_entry_stat(purge_fd, quarantine_name)
            recovery_stat = self._purge_entry_stat(purge_fd, recovery_name)
            self._require_regular_purge_entry(quarantine_stat)
            self._require_regular_purge_entry(recovery_stat)

            conn = self._open_purge_connection()
            try:
                self._ensure_schema(conn)
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
                if row is None:
                    if quarantine_stat is None and recovery_stat is None:
                        raise PairDropStoreError("not_found")
                    self._unlink_purge_entry(purge_fd, quarantine_name)
                    self._unlink_purge_entry(purge_fd, recovery_name)
                    os.fsync(purge_fd)
                    recovered_cleanup = True
                    committed = True
                else:
                    item = self._public_row(row)
                    if not row["deleted_at"]:
                        raise PairDropStoreError("not_deleted")
                    if row["display_name"] != expected_display_name:
                        raise PairDropStoreError("display_name_mismatch")
                    storage_relpath = str(item.get("storage_relpath") or "")
                    with self._object_parent_directory_fd(storage_relpath) as (
                        object_parent_fd,
                        object_name,
                    ):
                        path_stat = self._purge_entry_stat(object_parent_fd, object_name)
                    if path_stat is not None and (
                        stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode)
                    ):
                        raise PairDropStoreError("unsafe_object_path")
                    if path_stat is not None and quarantine_stat is not None:
                        raise PairDropStoreError("ambiguous_purge_recovery_state")

                    moved_to_quarantine = False
                    try:
                        if path_stat is not None:
                            with self._object_parent_directory_fd(storage_relpath) as (
                                object_parent_fd,
                                object_name,
                            ):
                                current_stat = self._purge_entry_stat(object_parent_fd, object_name)
                                if (
                                    current_stat is None
                                    or not stat.S_ISREG(current_stat.st_mode)
                                    or current_stat.st_dev != path_stat.st_dev
                                    or current_stat.st_ino != path_stat.st_ino
                                ):
                                    raise PairDropStoreError("unsafe_object_path")
                                os.replace(
                                    object_name,
                                    quarantine_name,
                                    src_dir_fd=object_parent_fd,
                                    dst_dir_fd=purge_fd,
                                )
                                moved_to_quarantine = True
                                self._fsync_directory_pair(object_parent_fd, purge_fd)
                        upload_ids = [
                            str(upload["upload_id"])
                            for upload in conn.execute(
                                "SELECT upload_id FROM upload_sessions WHERE file_id = ?",
                                (file_id,),
                            ).fetchall()
                        ]
                        for upload_id in upload_ids:
                            conn.execute("DELETE FROM upload_chunks WHERE upload_id = ?", (upload_id,))
                            candidate_events = conn.execute(
                                """
                                SELECT seq, summary_json FROM events
                                 WHERE file_id IS NULL AND summary_json LIKE ?
                                """,
                                (f"%{upload_id}%",),
                            ).fetchall()
                            for event in candidate_events:
                                try:
                                    summary = json.loads(event["summary_json"] or "{}")
                                except (TypeError, json.JSONDecodeError):
                                    continue
                                if (
                                    isinstance(summary, dict)
                                    and summary.get("upload_id") == upload_id
                                ):
                                    conn.execute(
                                        "DELETE FROM events WHERE seq = ?",
                                        (event["seq"],),
                                    )
                        conn.execute("DELETE FROM upload_sessions WHERE file_id = ?", (file_id,))
                        conn.execute("DELETE FROM events WHERE file_id = ?", (file_id,))
                        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
                        conn.commit()
                        committed = True
                    except BaseException as exc:
                        try:
                            conn.rollback()
                        except Exception:
                            pass
                        durable_row_state = self._fresh_file_row_state(file_id)
                        if durable_row_state is False:
                            committed = True
                        elif durable_row_state is True:
                            if moved_to_quarantine:
                                with self._object_parent_directory_fd(storage_relpath) as (
                                    object_parent_fd,
                                    object_name,
                                ):
                                    restored_stat = self._purge_entry_stat(
                                        object_parent_fd,
                                        object_name,
                                    )
                                if restored_stat is None:
                                    try:
                                        with self._object_parent_directory_fd(storage_relpath) as (
                                            object_parent_fd,
                                            object_name,
                                        ):
                                            quarantine_entry = self._purge_entry_stat(
                                                purge_fd,
                                                quarantine_name,
                                            )
                                            self._require_regular_purge_entry(quarantine_entry)
                                            if quarantine_entry is None:
                                                raise PairDropStoreError(
                                                    "purge_recovery_required",
                                                    "PairDrop lost its quarantine file while restoring a failed purge.",
                                                )
                                            os.replace(
                                                quarantine_name,
                                                object_name,
                                                src_dir_fd=purge_fd,
                                                dst_dir_fd=object_parent_fd,
                                            )
                                            self._fsync_directory_pair(
                                                purge_fd,
                                                object_parent_fd,
                                            )
                                    except (OSError, PairDropStoreError) as restore_exc:
                                        self._write_purge_recovery_record(
                                            purge_fd,
                                            recovery_name,
                                            file_id=file_id,
                                            display_name_sha256=display_digest,
                                            storage_relpath=storage_relpath,
                                        )
                                        raise PairDropStoreError(
                                            "purge_recovery_required",
                                            "PairDrop could not restore a file after purge commit failed; retry the exact purge.",
                                        ) from restore_exc
                                else:
                                    self._write_purge_recovery_record(
                                        purge_fd,
                                        recovery_name,
                                        file_id=file_id,
                                        display_name_sha256=display_digest,
                                        storage_relpath=storage_relpath,
                                    )
                                    raise PairDropStoreError(
                                        "purge_recovery_required",
                                        "PairDrop found a live object while restoring a failed purge; retry the exact purge.",
                                    ) from exc
                            self._unlink_purge_entry(purge_fd, recovery_name)
                            os.fsync(purge_fd)
                            raise
                        else:
                            self._write_purge_recovery_record(
                                purge_fd,
                                recovery_name,
                                file_id=file_id,
                                display_name_sha256=display_digest,
                                storage_relpath=storage_relpath,
                            )
                            if isinstance(exc, Exception):
                                raise PairDropStoreError(
                                    "purge_recovery_required",
                                    "PairDrop could not prove whether the purge committed; retry the exact purge.",
                                ) from exc
                            raise
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

            if committed and not recovered_cleanup:
                try:
                    self._unlink_purge_entry(purge_fd, quarantine_name)
                    self._unlink_purge_entry(purge_fd, recovery_name)
                    os.fsync(purge_fd)
                except OSError as exc:
                    raise PairDropStoreError(
                        "purge_cleanup_pending",
                        "PairDrop committed the purge but could not remove its recovery file; retry the exact purge.",
                    ) from exc
        self._audit("file.purged", {
            "file_id": file_id,
            "display_name_sha256": display_digest,
        })
        return {
            "ok": True,
            "id": file_id,
            "purged": True,
            "recovered_cleanup": recovered_cleanup,
        }

    @staticmethod
    def _validate_attachment_owner(
        *,
        session_id: str,
        source_device_id: str,
        source_install_id: str,
    ) -> None:
        if not PROVIDER_QUALIFIED_SESSION_PATTERN.fullmatch(str(session_id or "")):
            raise PairDropStoreError("bad_attachment_session")
        if not str(source_device_id or "") or not str(source_install_id or ""):
            raise PairDropStoreError("attachment_owner_required")

    @staticmethod
    def _attachment_row_matches_owner(
        row: sqlite3.Row,
        *,
        session_id: str,
        source_device_id: str,
        source_install_id: str,
    ) -> None:
        if (
            str(row["session_id"] or "") != session_id
            or str(row["source_device_id"] or "") != source_device_id
            or str(row["source_install_id"] or "") != source_install_id
        ):
            raise PairDropStoreError("attachment_owner_mismatch")
        if row["revoked_at"] is not None:
            raise PairDropStoreError("attachment_revoked")
        if float(row["expires_at"] or 0) <= time.time():
            raise PairDropStoreError("attachment_expired")

    def create_attachment_handle(
        self,
        file_id: str,
        *,
        session_id: str,
        source_device_id: str,
        source_install_id: str,
        idempotency_key: str | None = None,
        expires_in_seconds: int = DEFAULT_ATTACHMENT_TTL_SECONDS,
    ) -> dict[str, Any]:
        self._validate_attachment_owner(
            session_id=session_id,
            source_device_id=source_device_id,
            source_install_id=source_install_id,
        )
        key = str(idempotency_key or "").strip() or None
        if key is not None and (
            len(key) > MAX_ATTACHMENT_IDEMPOTENCY_KEY_LENGTH
            or not re.fullmatch(r"[A-Za-z0-9._:-]{8,200}", key)
        ):
            raise PairDropStoreError("bad_attachment_idempotency_key")
        if type(expires_in_seconds) is not int or expires_in_seconds <= 0:
            raise PairDropStoreError("bad_attachment_expiry")
        ttl = min(expires_in_seconds, MAX_ATTACHMENT_TTL_SECONDS)
        descriptor = self.verified_read_descriptor(file_id)
        item = descriptor["item"]
        now_epoch = time.time()
        now = _iso_from_epoch(now_epoch)
        expires_at = now_epoch + ttl
        handle_id = "att_" + secrets.token_hex(24)
        idempotent = False
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            existing = None
            if key is not None:
                existing = conn.execute(
                    """
                    SELECT * FROM attachment_handles
                     WHERE session_id = ?
                       AND source_device_id = ?
                       AND source_install_id = ?
                       AND idempotency_key = ?
                    """,
                    (session_id, source_device_id, source_install_id, key),
                ).fetchone()
            if existing is not None:
                if str(existing["file_id"] or "") != file_id:
                    raise PairDropStoreError("attachment_idempotency_conflict")
                handle_id = str(existing["handle"])
                expires_at = float(existing["expires_at"])
                idempotent = True
            else:
                conn.execute(
                    """
                    INSERT INTO attachment_handles(
                        handle, file_id, session_id, source_device_id,
                        source_install_id, idempotency_key, file_sha256,
                        file_byte_size, created_at, expires_at, revoked_at,
                        consumed_binding_id, consumed_client_action_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
                    """,
                    (
                        handle_id,
                        file_id,
                        session_id,
                        source_device_id,
                        source_install_id,
                        key,
                        str(item["sha256"]),
                        int(item["byte_size"]),
                        now,
                        expires_at,
                    ),
                )
                self._record_event(
                    conn,
                    "attached",
                    file_id,
                    {"handle_sha256": hashlib.sha256(handle_id.encode()).hexdigest()},
                )
            conn.execute(
                "UPDATE files SET last_opened_at = ?, updated_at = ? WHERE id = ?",
                (now, now, file_id),
            )
        if not idempotent:
            self._audit(
                "file.attached",
                {
                    "file_id": file_id,
                    "handle_sha256": hashlib.sha256(handle_id.encode()).hexdigest(),
                },
            )
        return {
            "ok": True,
            "id": file_id,
            "display_name": item["display_name"],
            "content_type": item["content_type"],
            "byte_size": int(item["byte_size"]),
            "sha256": item["sha256"],
            "handle_id": handle_id,
            "expires_at": _iso_from_epoch(expires_at),
            "idempotent": idempotent,
        }

    def _attachment_row(
        self,
        handle_id: str,
        *,
        session_id: str,
        source_device_id: str,
        source_install_id: str,
    ) -> sqlite3.Row:
        if not ATTACHMENT_HANDLE_PATTERN.fullmatch(str(handle_id or "")):
            raise PairDropStoreError("bad_attachment_handle")
        self._validate_attachment_owner(
            session_id=session_id,
            source_device_id=source_device_id,
            source_install_id=source_install_id,
        )
        with self._connect() as conn:
            self._ensure_schema(conn)
            row = conn.execute(
                "SELECT * FROM attachment_handles WHERE handle = ?",
                (handle_id,),
            ).fetchone()
        if row is None:
            raise PairDropStoreError("attachment_not_found")
        self._attachment_row_matches_owner(
            row,
            session_id=session_id,
            source_device_id=source_device_id,
            source_install_id=source_install_id,
        )
        return row

    def _bind_attachment_consumption(
        self,
        handle_ids: list[str],
        *,
        session_id: str,
        source_device_id: str,
        source_install_id: str,
        binding_id: str,
        client_action_id: str,
    ) -> None:
        if not binding_id or not client_action_id:
            raise PairDropStoreError("attachment_consumer_required")
        with self._connect() as conn:
            self._ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            for handle_id in handle_ids:
                row = conn.execute(
                    "SELECT * FROM attachment_handles WHERE handle = ?",
                    (handle_id,),
                ).fetchone()
                if row is None:
                    raise PairDropStoreError("attachment_not_found")
                self._attachment_row_matches_owner(
                    row,
                    session_id=session_id,
                    source_device_id=source_device_id,
                    source_install_id=source_install_id,
                )
                consumed_binding = str(row["consumed_binding_id"] or "")
                consumed_action = str(row["consumed_client_action_id"] or "")
                if consumed_binding or consumed_action:
                    if (
                        consumed_binding != binding_id
                        or consumed_action != client_action_id
                    ):
                        raise PairDropStoreError("attachment_consume_conflict")
                    continue
                changed = conn.execute(
                    """
                    UPDATE attachment_handles
                       SET consumed_binding_id = ?,
                           consumed_client_action_id = ?
                     WHERE handle = ?
                       AND consumed_binding_id IS NULL
                       AND consumed_client_action_id IS NULL
                    """,
                    (binding_id, client_action_id, handle_id),
                ).rowcount
                if changed != 1:
                    raise PairDropStoreError("attachment_consume_conflict")

    def resolve_attachment_handle(
        self,
        handle_id: str,
        *,
        session_id: str,
        source_device_id: str,
        source_install_id: str,
        binding_id: str = "send-text",
        client_action_id: str = "send-text-direct",
    ) -> dict[str, Any]:
        row = self._attachment_row(
            handle_id,
            session_id=session_id,
            source_device_id=source_device_id,
            source_install_id=source_install_id,
        )
        self._bind_attachment_consumption(
            [handle_id],
            session_id=session_id,
            source_device_id=source_device_id,
            source_install_id=source_install_id,
            binding_id=binding_id,
            client_action_id=client_action_id,
        )
        descriptor = self.verified_read_descriptor(str(row["file_id"]))
        item = descriptor["item"]
        if (
            str(item.get("sha256") or "") != str(row["file_sha256"] or "")
            or int(item.get("byte_size") or 0) != int(row["file_byte_size"] or 0)
        ):
            raise PairDropStoreError("attachment_metadata_mismatch")
        return descriptor

    def _open_committed_object_fd(self, item: dict[str, Any]) -> int:
        relpath = str(item.get("storage_relpath") or "")
        fd = -1
        try:
            with self._object_parent_directory_fd(relpath) as (parent_fd, name):
                fd = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_fd,
                )
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                raise PairDropStoreError("unsafe_object_path")
            return fd
        except OSError as exc:
            if fd >= 0:
                os.close(fd)
            if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                raise PairDropStoreError("unsafe_object_path") from exc
            if exc.errno == errno.ENOENT:
                raise PairDropStoreError("missing_object") from exc
            raise
        except Exception:
            if fd >= 0:
                os.close(fd)
            raise


    @contextmanager
    def _open_prepared_attachment(
        self,
        file_id: str,
        expected_sha256: str,
        expected_size: int,
    ) -> Iterator[Any]:
        item = self.get_file(file_id)
        if (
            str(item.get("sha256") or "") != expected_sha256
            or int(item.get("byte_size") or 0) != expected_size
        ):
            raise PairDropStoreError("attachment_metadata_mismatch")
        fd = -1
        handle = None
        try:
            fd = self._open_committed_object_fd(item)
            before = os.fstat(fd)
            if before.st_size != expected_size:
                raise PairDropStoreError("byte_size_mismatch")
            hasher = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
            after = os.fstat(fd)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise PairDropStoreError("attachment_changed")
            if hasher.hexdigest() != expected_sha256:
                raise PairDropStoreError("sha256_mismatch")
            os.lseek(fd, 0, os.SEEK_SET)
            handle = os.fdopen(fd, "rb")
            fd = -1
            yield handle
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                raise PairDropStoreError("missing_object") from exc
            raise
        finally:
            if handle is not None:
                handle.close()
            if fd >= 0:
                os.close(fd)

    def _cleanup_send_staging(self, *, now: float | None = None) -> None:
        cutoff = (
            time.time() if now is None else float(now)
        ) - SEND_STAGING_RETENTION_SECONDS
        with self._owned_child_directory_fd(
            "send-staging",
            "unsafe_send_staging_path",
        ) as staging_fd:
            for name in os.listdir(staging_fd):
                if not (
                    name.startswith("send_")
                    or (name.startswith(".send_") and name.endswith(".tmp"))
                ):
                    continue
                try:
                    entry = os.stat(
                        name,
                        dir_fd=staging_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(entry.st_mode):
                    os.unlink(name, dir_fd=staging_fd)
                    continue
                if not stat.S_ISREG(entry.st_mode):
                    raise PairDropStoreError("unsafe_send_staging_path")
                if entry.st_mtime <= cutoff:
                    os.unlink(name, dir_fd=staging_fd)
            os.fsync(staging_fd)

    def _materialize_prepared_attachment(
        self,
        file_id: str,
        expected_sha256: str,
        expected_size: int,
        display_name: str | None,
    ) -> Path:
        self._cleanup_send_staging()
        token = secrets.token_hex(16)
        temporary_name = f".send_{token}.tmp"
        final_name = f"send_{token}_{_safe_display_name(display_name or 'attachment.bin')}"
        descriptor = -1
        published = False
        try:
            with (
                self._open_prepared_attachment(
                    file_id,
                    expected_sha256,
                    expected_size,
                ) as source,
                self._owned_child_directory_fd(
                    "send-staging",
                    "unsafe_send_staging_path",
                ) as staging_fd,
            ):
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(
                    temporary_name,
                    flags,
                    0o600,
                    dir_fd=staging_fd,
                )
                copied = 0
                hasher = hashlib.sha256()
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > expected_size:
                        raise PairDropStoreError("byte_size_mismatch")
                    hasher.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise OSError(errno.EIO, "short attachment staging write")
                        view = view[written:]
                if copied != expected_size:
                    raise PairDropStoreError("byte_size_mismatch")
                if hasher.hexdigest() != expected_sha256:
                    raise PairDropStoreError("sha256_mismatch")
                os.fchmod(descriptor, 0o400)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                os.replace(
                    temporary_name,
                    final_name,
                    src_dir_fd=staging_fd,
                    dst_dir_fd=staging_fd,
                )
                published = True
                os.fsync(staging_fd)
                return self.send_staging_dir / final_name
        except OSError as exc:
            if exc.errno in {
                errno.ELOOP,
                errno.EISDIR,
                errno.ENOTDIR,
            }:
                raise PairDropStoreError("unsafe_send_staging_path") from exc
            if exc.errno in {errno.ENOSPC, getattr(errno, "EDQUOT", -1)}:
                raise PairDropStoreError("insufficient_storage") from exc
            raise
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if not published:
                try:
                    with self._owned_child_directory_fd(
                        "send-staging",
                        "unsafe_send_staging_path",
                    ) as staging_fd:
                        os.unlink(temporary_name, dir_fd=staging_fd)
                except FileNotFoundError:
                    pass

    def prepare_attachment_handles(
        self,
        records: Any,
        *,
        session_id: str,
        source_device_id: str,
        source_install_id: str,
        binding_id: str,
        client_action_id: str,
    ) -> tuple[PreparedAttachment, ...]:
        if not isinstance(records, list):
            raise PairDropStoreError("bad_attachment_records")
        if len(records) > 8:
            raise PairDropStoreError("too_many_attachments")
        prepared_rows: list[tuple[sqlite3.Row, dict[str, Any]]] = []
        aggregate_size = 0
        for record in records:
            if not isinstance(record, dict) or set(record) - {
                "handle_id",
                "sha256",
                "size_bytes",
                "mime_type",
                "display_name",
            }:
                raise PairDropStoreError("bad_attachment_records")
            handle_id = str(record.get("handle_id") or "")
            digest = str(record.get("sha256") or "")
            size = record.get("size_bytes")
            mime_type = str(record.get("mime_type") or "")
            display_name = record.get("display_name")
            if (
                not ATTACHMENT_HANDLE_PATTERN.fullmatch(handle_id)
                or not re.fullmatch(r"[a-f0-9]{64}", digest)
                or type(size) is not int
                or size < 1
                or not mime_type
                or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9.+-]*/[A-Za-z0-9][A-Za-z0-9.+-]*",
                    mime_type,
                )
                or (display_name is not None and not isinstance(display_name, str))
            ):
                raise PairDropStoreError("bad_attachment_records")
            if size > 2 * 1024 * 1024:
                raise PairDropStoreError("attachment_too_large")
            aggregate_size += size
            if aggregate_size > 8 * 1024 * 1024:
                raise PairDropStoreError("attachments_too_large")
            row = self._attachment_row(
                handle_id,
                session_id=session_id,
                source_device_id=source_device_id,
                source_install_id=source_install_id,
            )
            descriptor = self.verified_read_descriptor(str(row["file_id"]))
            item = descriptor["item"]
            expected_name = str(item.get("display_name") or "")
            if (
                digest != str(row["file_sha256"] or "")
                or size != int(row["file_byte_size"] or 0)
                or digest != str(item.get("sha256") or "")
                or size != int(item.get("byte_size") or 0)
                or mime_type != str(item.get("content_type") or "")
                or (
                    display_name is not None
                    and str(display_name) != expected_name
                )
            ):
                raise PairDropStoreError("attachment_metadata_mismatch")
            prepared_rows.append((row, item))
        self._bind_attachment_consumption(
            [str(row["handle"]) for row, _item in prepared_rows],
            session_id=session_id,
            source_device_id=source_device_id,
            source_install_id=source_install_id,
            binding_id=binding_id,
            client_action_id=client_action_id,
        )
        return tuple(
            PreparedAttachment(
                handle_id=str(row["handle"]),
                sha256=str(row["file_sha256"]),
                size_bytes=int(row["file_byte_size"]),
                mime_type=str(item.get("content_type") or ""),
                display_name=str(item.get("display_name") or "") or None,
                _open_verified=lambda file_id=str(row["file_id"]),
                digest=str(row["file_sha256"]),
                size=int(row["file_byte_size"]): self._open_prepared_attachment(
                    file_id,
                    digest,
                    size,
                ),
                _materialize_local_path=lambda file_id=str(row["file_id"]),
                digest=str(row["file_sha256"]),
                size=int(row["file_byte_size"]),
                name=str(item.get("display_name") or "") or None:
                    self._materialize_prepared_attachment(
                        file_id,
                        digest,
                        size,
                        name,
                    ),
            )
            for row, item in prepared_rows
        )

    def revoke_attachments_for_session(self, session_id: str) -> int:
        if not PROVIDER_QUALIFIED_SESSION_PATTERN.fullmatch(str(session_id or "")):
            return 0
        now = _now_iso()
        with self._connect() as conn:
            self._ensure_schema(conn)
            return conn.execute(
                """
                UPDATE attachment_handles
                   SET revoked_at = ?
                 WHERE session_id = ? AND revoked_at IS NULL
                """,
                (now, session_id),
            ).rowcount

    def download_descriptor(self, file_id: str) -> dict[str, Any]:
        item = self.get_file(file_id)
        descriptor = self._open_committed_object_fd(item)
        try:
            opened = os.fstat(descriptor)
            if int(item.get("byte_size") or 0) != opened.st_size:
                raise PairDropStoreError("byte_size_mismatch")
        finally:
            os.close(descriptor)
        path = self.root / str(item.get("storage_relpath") or "")
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

    @contextmanager
    def open_download(self, file_id: str) -> Iterator[dict[str, Any]]:
        """Open the audited object once and keep that verified inode for streaming."""
        descriptor = self.download_descriptor(file_id)
        item = descriptor["item"]
        fd = self._open_committed_object_fd(item)
        handle = None
        try:
            opened = os.fstat(fd)
            if int(item.get("byte_size") or 0) != opened.st_size:
                raise PairDropStoreError("byte_size_mismatch")
            handle = os.fdopen(fd, "rb", closefd=True)
            fd = -1
            yield {
                "item": item,
                "path": descriptor["path"],
                "handle": handle,
                "stat": opened,
            }
        finally:
            if handle is not None:
                handle.close()
            if fd >= 0:
                os.close(fd)

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
        fd = self._open_committed_object_fd(item)
        path = self.root / str(item.get("storage_relpath") or "")
        try:
            before = os.fstat(fd)
            byte_size = int(item.get("byte_size") or 0)
            if before.st_size != byte_size:
                raise PairDropStoreError("byte_size_mismatch")
            expected_sha256 = str(item.get("sha256") or "")
            if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
                raise PairDropStoreError("missing_sha256")
            hasher = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
            after = os.fstat(fd)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise PairDropStoreError("object_changed")
            if hasher.hexdigest() != expected_sha256:
                raise PairDropStoreError("sha256_mismatch")
        finally:
            os.close(fd)
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

    def recover_stale_completions(
        self,
        *,
        older_than_seconds: int = 300,
    ) -> dict[str, int]:
        cutoff = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() - max(0, older_than_seconds)),
        )
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM upload_sessions
                 WHERE state = 'completing' AND updated_at <= ?
                 ORDER BY updated_at ASC
                 LIMIT 100
                """,
                (cutoff,),
            ).fetchall()

        recovered = 0
        restarted = 0
        deferred = 0
        restart_errors = {
            "missing_partial",
            "byte_count_mismatch",
            "verified_offset_mismatch",
            "sha256_mismatch",
            "partial_changed",
        }
        for row in rows:
            session = self._public_upload_row(row)
            upload_id = str(session["upload_id"])
            with self._upload_operation_lock(upload_id, remove_if_terminal=True):
                try:
                    self._complete_upload_session_locked(
                        upload_id,
                        source_device_id=str(session["source_device_id"] or ""),
                        source_install_id=str(session["source_install_id"] or ""),
                    )
                    recovered += 1
                    continue
                except PairDropStoreError as exc:
                    if exc.code not in restart_errors:
                        deferred += 1
                        continue

                partial = self._partial_path(upload_id)
                if partial.is_symlink() or partial.is_file():
                    partial.unlink(missing_ok=True)
                now = _now_iso()
                expires_at = time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ",
                    time.gmtime(time.time() + UPLOAD_LEASE_SECONDS),
                )
                with self._connect() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    changed = conn.execute(
                        """
                        UPDATE upload_sessions
                           SET file_id = NULL, verified_offset = 0,
                               state = 'failed_retryable',
                               last_error = 'upload_restart_required',
                               updated_at = ?, expires_at = ?
                         WHERE upload_id = ? AND state = 'completing'
                        """,
                        (now, expires_at, upload_id),
                    ).rowcount
                    if changed:
                        conn.execute(
                            "DELETE FROM upload_chunks WHERE upload_id = ?",
                            (upload_id,),
                        )
                        self._record_event(
                            conn,
                            "upload_session_restart_required",
                            None,
                            {"upload_id": upload_id, "reason": "stale_completion"},
                        )
                    conn.commit()
                restarted += int(bool(changed))
        return {
            "recovered": recovered,
            "restarted": restarted,
            "deferred": deferred,
        }

    def cleanup_partials(self, *, older_than_seconds: int = 3600) -> dict[str, Any]:
        completion_recovery = self.recover_stale_completions()
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
        removed_locks = 0
        preserved_active = 0
        preserved_active_locks = 0
        skipped_symlinks = 0
        with self._owned_child_directory_fd(
            "partials",
            "unsafe_partial_path",
        ) as partials_fd:
            for name in os.listdir(partials_fd):
                partial_match = name.endswith(".partial")
                lock_match = re.fullmatch(r"\.(pu_[a-f0-9]{32})\.lock", name)
                if not partial_match and lock_match is None:
                    continue
                try:
                    path_stat = os.stat(
                        name,
                        dir_fd=partials_fd,
                        follow_symlinks=False,
                    )
                    if stat.S_ISLNK(path_stat.st_mode):
                        skipped_symlinks += 1
                        continue
                    if not stat.S_ISREG(path_stat.st_mode):
                        continue
                    upload_id = (
                        name.removesuffix(".partial")
                        if partial_match
                        else str(lock_match.group(1))
                    )
                    if upload_id in active_upload_ids:
                        if partial_match:
                            preserved_active += 1
                        else:
                            preserved_active_locks += 1
                        continue
                    if path_stat.st_mtime >= cutoff:
                        continue
                    if partial_match:
                        os.unlink(name, dir_fd=partials_fd)
                        removed += 1
                        continue

                    lock_fd = -1
                    locked = False
                    try:
                        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                        lock_fd = os.open(name, flags, dir_fd=partials_fd)
                        opened_stat = os.fstat(lock_fd)
                        if (
                            not stat.S_ISREG(opened_stat.st_mode)
                            or opened_stat.st_dev != path_stat.st_dev
                            or opened_stat.st_ino != path_stat.st_ino
                        ):
                            continue
                        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        locked = True
                        current_stat = os.stat(
                            name,
                            dir_fd=partials_fd,
                            follow_symlinks=False,
                        )
                        if (
                            current_stat.st_dev == opened_stat.st_dev
                            and current_stat.st_ino == opened_stat.st_ino
                        ):
                            os.unlink(name, dir_fd=partials_fd)
                            removed_locks += 1
                    except BlockingIOError:
                        preserved_active_locks += 1
                    except OSError as exc:
                        if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                            skipped_symlinks += 1
                        else:
                            raise
                    finally:
                        if lock_fd >= 0:
                            if locked:
                                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                            os.close(lock_fd)
                except FileNotFoundError:
                    continue
            if removed or removed_locks:
                os.fsync(partials_fd)
        self._audit("partials.cleaned", {
            "removed": removed,
            "removed_locks": removed_locks,
            "preserved_active": preserved_active,
            "preserved_active_locks": preserved_active_locks,
            "skipped_symlinks": skipped_symlinks,
            "expired_sessions": expired,
            "completion_recovery": completion_recovery,
        })
        return {
            "ok": True,
            "removed": removed,
            "removed_locks": removed_locks,
            "preserved_active": preserved_active,
            "preserved_active_locks": preserved_active_locks,
            "skipped_symlinks": skipped_symlinks,
            "expired_sessions": expired,
            "completion_recovery": completion_recovery,
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
        if not self._valid_upload_id(upload_id):
            raise PairDropStoreError("bad_upload_id")
        partial_name = f"{upload_id}.partial"
        flags = os.O_RDWR | os.O_CREAT
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        if no_follow:
            flags |= no_follow
        fd = -1
        try:
            with self._owned_child_directory_fd(
                "partials",
                "unsafe_partial_path",
            ) as partials_fd:
                fd = os.open(partial_name, flags, 0o600, dir_fd=partials_fd)
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise PairDropStoreError("unsafe_partial_path")
                with os.fdopen(fd, "r+b", closefd=True) as handle:
                    fd = -1
                    handle.seek(offset)
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                # The SQLite offset is not allowed to become durable before
                # the partial's directory entry. This matters on the first
                # chunk, when the file itself has just been created.
                os.fsync(partials_fd)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                raise PairDropStoreError("unsafe_partial_path") from exc
            if exc.errno in {errno.ENOSPC, getattr(errno, "EDQUOT", -1)}:
                raise PairDropStoreError("insufficient_storage") from exc
            raise
        finally:
            if fd >= 0:
                os.close(fd)

    def _truncate_partial(self, upload_id: str, byte_count: int) -> None:
        if not self._valid_upload_id(upload_id):
            raise PairDropStoreError("bad_upload_id")
        partial_name = f"{upload_id}.partial"
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = -1
        try:
            with self._owned_child_directory_fd(
                "partials",
                "unsafe_partial_path",
            ) as partials_fd:
                fd = os.open(partial_name, flags, dir_fd=partials_fd)
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise PairDropStoreError("unsafe_partial_path")
                os.ftruncate(fd, byte_count)
                os.fsync(fd)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                raise PairDropStoreError("unsafe_partial_path") from exc
            raise
        finally:
            if fd >= 0:
                os.close(fd)

    def _partial_range_hash(self, upload_id: str, offset: int, byte_count: int) -> str:
        if not self._valid_upload_id(upload_id):
            raise PairDropStoreError("bad_upload_id")
        partial_name = f"{upload_id}.partial"
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = -1
        try:
            with self._owned_child_directory_fd(
                "partials",
                "unsafe_partial_path",
            ) as partials_fd:
                try:
                    fd = os.open(partial_name, flags, dir_fd=partials_fd)
                except FileNotFoundError as exc:
                    raise PairDropStoreError("missing_partial") from exc
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise PairDropStoreError("unsafe_partial_path")
                os.lseek(fd, offset, os.SEEK_SET)
                data = bytearray()
                while len(data) < byte_count:
                    chunk = os.read(fd, min(1024 * 1024, byte_count - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                raise PairDropStoreError("unsafe_partial_path") from exc
            raise
        finally:
            if fd >= 0:
                os.close(fd)
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

    @staticmethod
    def _file_identity(path: Path) -> tuple[int, ...]:
        stat_result = path.lstat()
        return (
            stat_result.st_dev,
            stat_result.st_ino,
            stat_result.st_mode,
            stat_result.st_size,
            stat_result.st_mtime_ns,
            stat_result.st_ctime_ns,
        )

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
            if state == "failed_terminal":
                conn.execute(
                    "DELETE FROM upload_chunks WHERE upload_id = ?",
                    (upload_id,),
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

    def _audit(self, event: str, detail: dict[str, Any]) -> bool:
        """Write the secondary JSONL audit without changing primary operation truth."""

        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            safe_detail = redact_public_diagnostic({
                key: value for key, value in detail.items()
                if key not in {"path", "body", "request_body", "contents"}
            })
            record = {
                "ts": _now_iso(),
                "event": event,
                "detail": safe_detail,
            }
            with self.audit_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
            return True
        except (OSError, TypeError, ValueError):
            # Every state-changing operation also records its durable event in
            # SQLite. A failed secondary sink must not turn an already-committed
            # operation into a 500 that the client will retry.
            return False

    @staticmethod
    def _valid_id(file_id: str) -> bool:
        return bool(re.fullmatch(r"pd_[a-f0-9]{32}", str(file_id or "")))

    @staticmethod
    def _valid_upload_id(upload_id: str) -> bool:
        return bool(re.fullmatch(r"pu_[a-f0-9]{32}", str(upload_id or "")))
