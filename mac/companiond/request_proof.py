#!/usr/bin/env python3
"""Request-bound HMAC proof verification for mutating Pairling endpoints."""

from __future__ import annotations

import hashlib
import hmac
import re
import sqlite3
import stat
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


INSTALL_ID_HEADER = "Pairling-Install-ID"
REQUEST_ID_HEADER = "Pairling-Request-ID"
TIMESTAMP_HEADER = "Pairling-Timestamp"
BODY_SHA256_HEADER = "Pairling-Body-SHA256"
PROOF_HEADER = "Pairling-Proof"
SKEW_MS = 10 * 60 * 1000
REPLAY_DB_BUSY_TIMEOUT_MS = 5_000
REPLAY_HEALTH_CACHE_SECONDS = 2.0
REPLAY_WRITE_PROBE_INTERVAL_SECONDS = 30.0
_REPLAY_DB_INIT_LOCK = threading.Lock()
REQUEST_ID_MAX_LENGTH = 128
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
SHA256_HEX_PATTERN = re.compile(r"^[0-9A-Fa-f]{64}$")
TIMESTAMP_PATTERN = re.compile(r"^[0-9]{1,20}$")


@dataclass(frozen=True)
class ProofVerificationResult:
    ok: bool
    status: int = 200
    code: str = "ok"
    message: str = "ok"


class ReplayCacheOutcome(str, Enum):
    ACCEPTED = "accepted"
    REPLAYED = "replayed"
    FULL = "full"


class ReplayCacheError(RuntimeError):
    pass


class ReplayCache:
    def __init__(
        self,
        *,
        retention_seconds: int = 600,
        max_entries: int = 4096,
        max_entries_per_device: int | None = None,
        database_path: str | Path | None = None,
    ):
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        if max_entries_per_device is not None and max_entries_per_device < 1:
            raise ValueError("max_entries_per_device must be at least 1")
        self.retention_seconds = retention_seconds
        self.max_entries = max_entries
        self.max_entries_per_device = min(max_entries, max_entries_per_device or max_entries)
        self.database_path = Path(database_path) if database_path is not None else None
        self._seen: dict[tuple[str, str], float] = {}
        self._device_counts: dict[str, int] = {}
        self._lock = threading.Lock()
        self._db: sqlite3.Connection | None = None
        self._status_cache: tuple[float, dict[str, Any]] | None = None
        self._last_write_probe_monotonic: float | None = None
        self._storage_failed = False

    def check_and_store(
        self,
        *,
        device_id: str,
        request_id: str,
        now: float | None = None,
        expires_at: float | None = None,
    ) -> ReplayCacheOutcome:
        key = (device_id, hashlib.sha256(request_id.encode("utf-8")).hexdigest())
        with self._lock:
            current = time.time() if now is None else now
            expiry = current + self.retention_seconds if expires_at is None else expires_at
            if self.database_path is not None:
                try:
                    outcome = self._check_and_store_database(
                        key=key,
                        current=current,
                        expires_at=expiry,
                    )
                    self._status_cache = None
                    self._last_write_probe_monotonic = time.monotonic()
                    self._storage_failed = False
                    return outcome
                except (OSError, RuntimeError, sqlite3.Error, ReplayCacheError) as exc:
                    self._mark_storage_failed()
                    if isinstance(exc, ReplayCacheError):
                        raise
                    raise ReplayCacheError("Request proof storage is unavailable") from exc
            outcome = self._check_and_store_memory(
                key=key,
                current=current,
                expires_at=expiry,
            )
            self._status_cache = None
            return outcome

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None
            self._status_cache = None
            self._last_write_probe_monotonic = None
            self._storage_failed = False

    def __del__(self) -> None:
        database = getattr(self, "_db", None)
        if database is None:
            return
        self._db = None
        try:
            database.close()
        except Exception:
            pass

    def status(self, *, now: float | None = None) -> dict[str, Any]:
        """Return a non-consuming health check for request-proof storage."""
        with self._lock:
            current = time.time() if now is None else now
            monotonic_now = time.monotonic()
            if (
                self._status_cache is not None
                and not self._storage_failed
                and monotonic_now - self._status_cache[0] < REPLAY_HEALTH_CACHE_SECONDS
            ):
                return dict(self._status_cache[1])
            try:
                if self.database_path is None:
                    active = sum(1 for expiry in self._seen.values() if expiry >= current)
                    full = active >= self.max_entries
                    payload = self._status_payload(
                        ok=not full,
                        entry_count=active,
                        full=full,
                        durable=False,
                        reason="cache_full" if full else "ok",
                    )
                    self._status_cache = (monotonic_now, payload)
                    return dict(payload)
                connection = self._database()
                journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
                if journal_mode != "wal":
                    raise ReplayCacheError("Replay cache is not using SQLite WAL mode")
                state_row = connection.execute(
                    "SELECT entry_count FROM request_proof_cache_state WHERE singleton = 1"
                ).fetchone()
                if state_row is None:
                    raise ReplayCacheError("Replay cache entry metadata is unavailable")
                stored_count = int(state_row[0])
                earliest_row = connection.execute(
                    "SELECT expires_at FROM request_proofs ORDER BY expires_at LIMIT 1"
                ).fetchone()
                earliest_expiry = float(earliest_row[0]) if earliest_row is not None else None
                if (
                    self._storage_failed
                    or
                    self._last_write_probe_monotonic is None
                    or monotonic_now - self._last_write_probe_monotonic
                    >= REPLAY_WRITE_PROBE_INTERVAL_SECONDS
                ):
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute("ROLLBACK")
                    self._last_write_probe_monotonic = monotonic_now
                    self._storage_failed = False
                expired_entries_pending = (
                    earliest_expiry is not None and earliest_expiry < current
                )
                full = stored_count >= self.max_entries and not expired_entries_pending
                payload = self._status_payload(
                    ok=not full,
                    entry_count=stored_count,
                    full=full,
                    durable=True,
                    reason="cache_full" if full else "ok",
                )
                payload["expired_entries_pending"] = expired_entries_pending
                self._status_cache = (monotonic_now, payload)
                return dict(payload)
            except (OSError, RuntimeError, sqlite3.Error, ReplayCacheError):
                self._mark_storage_failed()
                payload = self._status_payload(
                    ok=False,
                    entry_count=None,
                    full=False,
                    durable=self.database_path is not None,
                    reason="storage_unavailable",
                )
                self._status_cache = (monotonic_now, payload)
                return dict(payload)

    def _status_payload(
        self,
        *,
        ok: bool,
        entry_count: int | None,
        full: bool,
        durable: bool,
        reason: str,
    ) -> dict[str, Any]:
        return {
            "contract_version": "pairling-request-proof-health-v1",
            "ok": ok,
            "durable": durable,
            "writable": ok or full,
            "entry_count": entry_count,
            "max_entries": self.max_entries,
            "max_entries_per_device": self.max_entries_per_device,
            "full": full,
            "reason": reason,
        }

    def _check_and_store_memory(
        self,
        *,
        key: tuple[str, str],
        current: float,
        expires_at: float,
    ) -> ReplayCacheOutcome:
        expired = [seen_key for seen_key, expiry in self._seen.items() if expiry < current]
        for seen_key in expired:
            del self._seen[seen_key]
            device_id = seen_key[0]
            remaining = self._device_counts.get(device_id, 0) - 1
            if remaining > 0:
                self._device_counts[device_id] = remaining
            else:
                self._device_counts.pop(device_id, None)

        if key in self._seen:
            return ReplayCacheOutcome.REPLAYED

        if len(self._seen) >= self.max_entries:
            return ReplayCacheOutcome.FULL
        if self._device_counts.get(key[0], 0) >= self.max_entries_per_device:
            return ReplayCacheOutcome.FULL

        self._seen[key] = expires_at
        self._device_counts[key[0]] = self._device_counts.get(key[0], 0) + 1
        return ReplayCacheOutcome.ACCEPTED

    def _check_and_store_database(
        self,
        *,
        key: tuple[str, str],
        current: float,
        expires_at: float,
    ) -> ReplayCacheOutcome:
        connection = self._database()
        connection.execute("BEGIN IMMEDIATE")
        try:
            earliest_expiry = connection.execute(
                "SELECT expires_at FROM request_proofs ORDER BY expires_at LIMIT 1"
            ).fetchone()
            if earliest_expiry is not None and float(earliest_expiry[0]) < current:
                expired_device_counts = connection.execute(
                    """
                    SELECT device_id, COUNT(*)
                    FROM request_proofs
                    WHERE expires_at < ?
                    GROUP BY device_id
                    """,
                    (current,),
                ).fetchall()
                deleted = connection.execute(
                    "DELETE FROM request_proofs WHERE expires_at < ?",
                    (current,),
                ).rowcount
                connection.execute(
                    """
                    UPDATE request_proof_cache_state
                    SET entry_count = MAX(0, entry_count - ?)
                    WHERE singleton = 1
                    """,
                    (deleted,),
                )
                for expired_device_id, expired_count in expired_device_counts:
                    connection.execute(
                        """
                        UPDATE request_proof_device_cache_state
                        SET entry_count = MAX(0, entry_count - ?)
                        WHERE device_id = ?
                        """,
                        (int(expired_count), str(expired_device_id)),
                    )
                connection.execute(
                    "DELETE FROM request_proof_device_cache_state WHERE entry_count = 0"
                )
            replayed = connection.execute(
                "SELECT 1 FROM request_proofs WHERE device_id = ? AND request_id = ?",
                key,
            ).fetchone()
            if replayed is not None:
                connection.execute("COMMIT")
                return ReplayCacheOutcome.REPLAYED

            count = int(connection.execute(
                "SELECT entry_count FROM request_proof_cache_state WHERE singleton = 1"
            ).fetchone()[0])
            if count >= self.max_entries:
                connection.execute("COMMIT")
                return ReplayCacheOutcome.FULL
            device_state = connection.execute(
                "SELECT entry_count FROM request_proof_device_cache_state WHERE device_id = ?",
                (key[0],),
            ).fetchone()
            device_count = int(device_state[0]) if device_state is not None else 0
            if device_count >= self.max_entries_per_device:
                connection.execute("COMMIT")
                return ReplayCacheOutcome.FULL

            connection.execute(
                "INSERT INTO request_proofs (device_id, request_id, expires_at) VALUES (?, ?, ?)",
                (key[0], key[1], expires_at),
            )
            connection.execute(
                """
                UPDATE request_proof_cache_state
                SET entry_count = entry_count + 1
                WHERE singleton = 1
                """
            )
            connection.execute(
                """
                INSERT INTO request_proof_device_cache_state (device_id, entry_count)
                VALUES (?, 1)
                ON CONFLICT(device_id) DO UPDATE SET entry_count = entry_count + 1
                """,
                (key[0],),
            )
            connection.execute("COMMIT")
            return ReplayCacheOutcome.ACCEPTED
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    def _database(self) -> sqlite3.Connection:
        if self._db is not None:
            return self._db
        if self.database_path is None:
            raise RuntimeError("Replay cache database path is not configured")

        database_parent = self.database_path.parent
        if database_parent.is_symlink():
            raise ReplayCacheError("Replay cache directory must not be a symlink")
        database_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if database_parent.is_symlink():
            raise ReplayCacheError("Replay cache directory must not be a symlink")
        database_parent.chmod(0o700)
        try:
            database_stat = self.database_path.lstat()
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(database_stat.st_mode) or not stat.S_ISREG(database_stat.st_mode):
                raise ReplayCacheError("Replay cache database must be a regular file")

        database_uri = self.database_path.absolute().as_uri() + "?mode=rwc&nofollow=1"
        with _REPLAY_DB_INIT_LOCK:
            # Separate ReplayCache instances can share this file. SQLite does
            # not reliably wait on simultaneous journal-mode transitions, so
            # serialize schema setup before normal WAL transactions begin.
            if self._db is not None:
                return self._db
            return self._open_database_connection(database_uri)

    def _open_database_connection(self, database_uri: str) -> sqlite3.Connection:
        connection = sqlite3.connect(
            database_uri,
            timeout=REPLAY_DB_BUSY_TIMEOUT_MS / 1000,
            isolation_level=None,
            check_same_thread=False,
            uri=True,
        )
        try:
            connection.execute("PRAGMA busy_timeout=5000")
            journal_mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
            if journal_mode != "wal":
                raise RuntimeError(f"Replay cache requires SQLite WAL mode, got {journal_mode}")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS request_proofs (
                    device_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (device_id, request_id)
                ) WITHOUT ROWID
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS request_proofs_expiry_idx ON request_proofs (expires_at)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS request_proof_cache_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    entry_count INTEGER NOT NULL CHECK (entry_count >= 0)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS request_proof_device_cache_state (
                    device_id TEXT PRIMARY KEY,
                    entry_count INTEGER NOT NULL CHECK (entry_count >= 0)
                ) WITHOUT ROWID
                """
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO request_proof_cache_state (singleton, entry_count)
                SELECT 1, COUNT(*) FROM request_proofs
                """
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO request_proof_device_cache_state (device_id, entry_count)
                SELECT device_id, COUNT(*) FROM request_proofs GROUP BY device_id
                """
            )
            stored_count = int(connection.execute(
                "SELECT COUNT(*) FROM request_proofs"
            ).fetchone()[0])
            state_row = connection.execute(
                "SELECT entry_count FROM request_proof_cache_state WHERE singleton = 1"
            ).fetchone()
            if state_row is None or int(state_row[0]) != stored_count:
                raise ReplayCacheError("Replay cache entry metadata is inconsistent")
            inconsistent_device_state = connection.execute(
                """
                SELECT 1
                FROM (
                    SELECT device_id, COUNT(*) AS entry_count
                    FROM request_proofs
                    GROUP BY device_id
                ) AS actual
                LEFT JOIN request_proof_device_cache_state AS cached
                    ON cached.device_id = actual.device_id
                WHERE cached.device_id IS NULL OR cached.entry_count != actual.entry_count
                UNION ALL
                SELECT 1
                FROM request_proof_device_cache_state AS cached
                LEFT JOIN request_proofs AS proof ON proof.device_id = cached.device_id
                WHERE proof.device_id IS NULL OR cached.entry_count < 1
                LIMIT 1
                """
            ).fetchone()
            if inconsistent_device_state is not None:
                raise ReplayCacheError("Replay cache per-device metadata is inconsistent")
            database_stat = self.database_path.lstat()
            if stat.S_ISLNK(database_stat.st_mode) or not stat.S_ISREG(database_stat.st_mode):
                raise ReplayCacheError("Replay cache database must be a regular file")
            self.database_path.chmod(0o600)
        except BaseException:
            connection.close()
            raise
        self._db = connection
        self._last_write_probe_monotonic = time.monotonic()
        return connection

    def _mark_storage_failed(self) -> None:
        self._storage_failed = True
        self._status_cache = None
        self._last_write_probe_monotonic = None
        if self._db is not None:
            try:
                self._db.close()
            except sqlite3.Error:
                pass
            self._db = None


def body_sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_request(
    *,
    method: str,
    path_and_query: str,
    timestamp_ms: str,
    request_id: str,
    body_sha256: str,
    install_id: str,
    device_id: str,
) -> str:
    return "\n".join([
        method.upper(),
        path_and_query,
        timestamp_ms,
        request_id,
        body_sha256,
        install_id,
        device_id,
    ])


def proof_hex(*, secret: str, canonical: str) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_request_proof(
    *,
    headers: Any,
    method: str,
    path_and_query: str,
    body: bytes,
    auth_result: Any,
    local_install_id: str,
    replay_cache: ReplayCache,
    now_ms: int | None = None,
) -> ProofVerificationResult:
    authenticated_install_id = str(getattr(auth_result, "install_id", "") or "").strip()
    canonical_install_id = str(local_install_id or "").strip()
    if (
        not authenticated_install_id
        or not canonical_install_id
        or not hmac.compare_digest(authenticated_install_id, canonical_install_id)
    ):
        return ProofVerificationResult(False, 403, "install_id_mismatch", "Request proof was for a different Mac.")

    proof_secret = str(getattr(auth_result, "proof_secret", "") or "").strip()
    if not proof_secret:
        return ProofVerificationResult(False, 403, "missing_proof_secret", "Pair this Mac again to enable request proof.")

    install_id = _header(headers, INSTALL_ID_HEADER)
    request_id = _header(headers, REQUEST_ID_HEADER)
    timestamp_ms = _header(headers, TIMESTAMP_HEADER)
    body_hash = _header(headers, BODY_SHA256_HEADER)
    proof = _header(headers, PROOF_HEADER)

    if not install_id or not request_id or not timestamp_ms or not body_hash or not proof:
        return ProofVerificationResult(False, 401, "missing_proof", "Request proof headers are required.")
    normalized_request_id = _normalized_request_id(request_id)
    if normalized_request_id is None:
        return ProofVerificationResult(
            False,
            401,
            "invalid_request_id",
            "Pairling-Request-ID format is invalid.",
        )
    if install_id != local_install_id:
        return ProofVerificationResult(False, 403, "install_id_mismatch", "Request proof was for a different Mac.")
    if TIMESTAMP_PATTERN.fullmatch(timestamp_ms) is None:
        return ProofVerificationResult(False, 401, "bad_timestamp", "Request proof timestamp is invalid.")
    try:
        parsed_ts = int(timestamp_ms)
    except ValueError:
        return ProofVerificationResult(False, 401, "bad_timestamp", "Request proof timestamp is invalid.")
    current_ms = int(time.time() * 1000) if now_ms is None else now_ms
    if abs(current_ms - parsed_ts) > SKEW_MS:
        return ProofVerificationResult(False, 401, "stale_timestamp", "Request proof timestamp is stale.")

    expected_body_hash = body_sha256_hex(body)
    if SHA256_HEX_PATTERN.fullmatch(body_hash) is None:
        return ProofVerificationResult(False, 401, "bad_body_hash", "Request body hash is invalid.")
    if not hmac.compare_digest(body_hash.lower(), expected_body_hash):
        return ProofVerificationResult(False, 401, "body_hash_mismatch", "Request body hash does not match.")

    device_id = str(getattr(auth_result, "device_id", "") or "")
    canonical = canonical_request(
        method=method,
        path_and_query=path_and_query,
        timestamp_ms=timestamp_ms,
        request_id=request_id,
        body_sha256=expected_body_hash,
        install_id=install_id,
        device_id=device_id,
    )
    expected_proof = proof_hex(secret=proof_secret, canonical=canonical)
    if SHA256_HEX_PATTERN.fullmatch(proof) is None:
        return ProofVerificationResult(False, 401, "bad_proof", "Request proof did not verify.")
    if not hmac.compare_digest(proof.lower(), expected_proof):
        return ProofVerificationResult(False, 401, "bad_proof", "Request proof did not verify.")
    try:
        replay_outcome = replay_cache.check_and_store(
            device_id=device_id,
            request_id=normalized_request_id,
            now=current_ms / 1000,
            expires_at=(parsed_ts + SKEW_MS) / 1000,
        )
    except ReplayCacheError:
        return ProofVerificationResult(
            False,
            503,
            "proof_unavailable",
            "Request proof storage is temporarily unavailable.",
        )
    if replay_outcome is ReplayCacheOutcome.REPLAYED:
        return ProofVerificationResult(False, 409, "replayed_request", "Request proof was already used.")
    if replay_outcome is ReplayCacheOutcome.FULL:
        return ProofVerificationResult(
            False,
            503,
            "proof_cache_full",
            "Request proof cache is full. Retry after existing proofs expire.",
        )
    return ProofVerificationResult(True)


def _normalized_request_id(value: str) -> str | None:
    if not 1 <= len(value) <= REQUEST_ID_MAX_LENGTH:
        return None
    if REQUEST_ID_PATTERN.fullmatch(value) is None:
        return None
    if len(value) == 36:
        try:
            normalized_uuid = str(uuid.UUID(value))
        except (AttributeError, ValueError):
            pass
        else:
            if value.lower() == normalized_uuid:
                return normalized_uuid
    return value


def _header(headers: Any, name: str) -> str:
    try:
        return str(headers.get(name, "") or "").strip()
    except AttributeError:
        return str((headers or {}).get(name, "") or "").strip()
