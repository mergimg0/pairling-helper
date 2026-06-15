#!/usr/bin/env python3
"""Per-device token registry for the Pairling Mac runtime."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from runtime_contract import DEFAULT_DEVICE_SCOPES
from runtime_paths import audit_log_path, devices_db_path, install_id_path


SQLITE_BUSY_TIMEOUT_MS = int(os.environ.get("PAIRLING_SQLITE_BUSY_TIMEOUT_MS", "5000"))


def utc_epoch() -> float:
    return time.time()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> str:
    return "pld_" + secrets.token_urlsafe(32)


def generate_device_id() -> str:
    return "dev_" + secrets.token_hex(16)


def generate_proof_secret() -> str:
    return "prf_" + secrets.token_urlsafe(32)


def _redact_for_audit(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in ("token", "secret", "proof", "authorization")):
                redacted[str(key)] = "[redacted]"
            else:
                redacted[str(key)] = _redact_for_audit(item)
        return redacted
    if isinstance(value, list):
        return [_redact_for_audit(item) for item in value]
    return value


def _write_private_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_or_create_install_id(path: Path | None = None) -> str:
    target = path or install_id_path()
    try:
        value = target.read_text().strip()
        if value:
            return value
    except FileNotFoundError:
        pass
    value = "inst_" + secrets.token_hex(16)
    _write_private_text(target, value + "\n")
    return value


@dataclass(frozen=True)
class DeviceAuthResult:
    ok: bool
    status: int
    reason: str
    device_id: str | None = None
    install_id: str | None = None
    proof_secret: str | None = None
    scopes: frozenset[str] = frozenset()

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


@dataclass(frozen=True)
class CreatedDevice:
    device_id: str
    token: str
    proof_secret: str
    scopes: tuple[str, ...]
    install_id: str
    relay_device_id: str | None = None
    attestation_status: str = "none"


class DeviceRegistry:
    def __init__(self, db_path: Path | None = None, audit_path: Path | None = None):
        self.db_path = db_path or devices_db_path()
        self.audit_path = audit_path or audit_log_path()

    @contextmanager
    def connect(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.db_path.parent, 0o700)
        except OSError:
            pass
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=max(SQLITE_BUSY_TIMEOUT_MS, 1) / 1000,
        )
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            self._ensure_schema(conn)
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                scopes_json TEXT NOT NULL,
                install_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                last_seen_at REAL,
                revoked_at REAL
            )
            """
        )
        existing = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(devices)").fetchall()
        }
        additive_columns = {
            "relay_device_id": "ALTER TABLE devices ADD COLUMN relay_device_id TEXT",
            "attestation_status": "ALTER TABLE devices ADD COLUMN attestation_status TEXT DEFAULT 'none'",
            "apns_registered_at": "ALTER TABLE devices ADD COLUMN apns_registered_at REAL",
            "relay_pair_secret_ref": "ALTER TABLE devices ADD COLUMN relay_pair_secret_ref TEXT",
            "device_display_name": "ALTER TABLE devices ADD COLUMN device_display_name TEXT",
            "superseded_by_device_id": "ALTER TABLE devices ADD COLUMN superseded_by_device_id TEXT",
            "proof_secret": "ALTER TABLE devices ADD COLUMN proof_secret TEXT",
            # WS4: base64 X9.63 (uncompressed P-256 point) of the device's
            # Secure-Enclave public key, registered at first pair. Used to
            # verify zero-interaction re-pair challenge signatures.
            "se_public_key_der": "ALTER TABLE devices ADD COLUMN se_public_key_der TEXT",
        }
        for column, statement in additive_columns.items():
            if column not in existing:
                conn.execute(statement)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_token_hash ON devices(token_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_relay_device_id ON devices(relay_device_id)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                event TEXT NOT NULL,
                device_id TEXT,
                outcome TEXT NOT NULL,
                path TEXT,
                detail_json TEXT NOT NULL
            )
            """
        )

    def create_device(
        self,
        *,
        device_name: str,
        scopes: Iterable[str] | None = None,
        install_id: str | None = None,
        token: str | None = None,
        proof_secret: str | None = None,
        device_id: str | None = None,
        relay_device_id: str | None = None,
        attestation_status: str = "none",
        device_display_name: str | None = None,
        relay_pair_secret_ref: str | None = None,
    ) -> CreatedDevice:
        normalized_scopes = tuple(sorted(set(scopes or DEFAULT_DEVICE_SCOPES)))
        token_value = token or generate_token()
        proof_secret_value = proof_secret or generate_proof_secret()
        device_id_value = device_id or generate_device_id()
        install_id_value = install_id or load_or_create_install_id()
        attestation_value = attestation_status if attestation_status in {
            "none",
            "development",
            "production",
            "unsupported",
            "failed",
        } else "failed"
        now = utc_epoch()
        with self.connect() as conn:
            if relay_device_id:
                superseded = conn.execute(
                    """
                    SELECT device_id FROM devices
                    WHERE relay_device_id = ?
                      AND revoked_at IS NULL
                    """,
                    (relay_device_id,),
                ).fetchall()
                for row in superseded:
                    old_device_id = row["device_id"]
                    conn.execute(
                        """
                        UPDATE devices
                        SET revoked_at = ?, superseded_by_device_id = ?
                        WHERE device_id = ?
                        """,
                        (now, device_id_value, old_device_id),
                    )
                    self.record_audit(
                        "device.superseded",
                        device_id=old_device_id,
                        outcome="ok",
                        detail={
                            "relay_device_id": relay_device_id,
                            "new_device_id": device_id_value,
                            "policy": "relay_repair_supersedes_old_local_token",
                        },
                        conn=conn,
                    )
            conn.execute(
                """
                INSERT INTO devices
                    (device_id, device_name, token_hash, scopes_json, install_id,
                     created_at, last_seen_at, revoked_at, relay_device_id,
                     attestation_status, apns_registered_at, relay_pair_secret_ref,
                     device_display_name, proof_secret)
                VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, NULL, ?, ?, ?)
                """,
                (
                    device_id_value,
                    device_name,
                    hash_token(token_value),
                    json.dumps(normalized_scopes),
                    install_id_value,
                    now,
                    relay_device_id,
                    attestation_value,
                    relay_pair_secret_ref,
                    device_display_name or device_name,
                    proof_secret_value,
                ),
            )
            self.record_audit(
                "device.created",
                device_id=device_id_value,
                outcome="ok",
                detail={
                    "scopes": list(normalized_scopes),
                    "attestation_status": attestation_value,
                    "relay_device_id": relay_device_id,
                },
                conn=conn,
            )
        return CreatedDevice(
            device_id_value,
            token_value,
            proof_secret_value,
            normalized_scopes,
            install_id_value,
            relay_device_id,
            attestation_value,
        )

    def authenticate(
        self,
        token: str | None,
        *,
        required_scopes: Iterable[str] = (),
        path: str | None = None,
    ) -> DeviceAuthResult:
        if not token:
            return DeviceAuthResult(False, 401, "missing_token")
        required = set(required_scopes)
        token_hash = hash_token(token)
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is None:
                self.record_audit(
                    "auth.denied",
                    device_id=None,
                    outcome="invalid_token",
                    path=path,
                    conn=conn,
                )
                return DeviceAuthResult(False, 403, "invalid_token")
            if row["revoked_at"] is not None:
                self.record_audit(
                    "auth.denied",
                    device_id=row["device_id"],
                    outcome="revoked",
                    path=path,
                    conn=conn,
                )
                return DeviceAuthResult(False, 403, "revoked")
            scopes = frozenset(json.loads(row["scopes_json"] or "[]"))
            missing = sorted(required.difference(scopes))
            if missing:
                self.record_audit(
                    "auth.denied",
                    device_id=row["device_id"],
                    outcome="missing_scope",
                    path=path,
                    detail={"missing": missing},
                    conn=conn,
                )
                return DeviceAuthResult(
                    False,
                    403,
                    "missing_scope",
                    device_id=row["device_id"],
                    install_id=row["install_id"],
                    proof_secret=row["proof_secret"],
                    scopes=scopes,
                )
            return DeviceAuthResult(
                True,
                200,
                "ok",
                device_id=row["device_id"],
                install_id=row["install_id"],
                proof_secret=row["proof_secret"],
                scopes=scopes,
            )

    def revoke_device(self, device_id: str, *, reason: str = "revoked") -> bool:
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE devices SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL",
                (utc_epoch(), device_id),
            )
            changed = cur.rowcount > 0
            self.record_audit(
                "device.revoked",
                device_id=device_id,
                outcome="ok" if changed else "not_found",
                detail={"reason": reason},
                conn=conn,
            )
            return changed

    def revoke_devices_named(self, device_name: str, *, reason: str = "revoked") -> int:
        now = utc_epoch()
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT device_id FROM devices WHERE device_name = ? AND revoked_at IS NULL",
                (device_name,),
            ).fetchall()
            for row in rows:
                device_id = row["device_id"]
                conn.execute(
                    "UPDATE devices SET revoked_at = ? WHERE device_id = ?",
                    (now, device_id),
                )
                self.record_audit(
                    "device.revoked",
                    device_id=device_id,
                    outcome="ok",
                    detail={"reason": reason, "device_name": device_name},
                    conn=conn,
                )
            return len(rows)

    def rotate_token(self, device_id: str) -> str | None:
        token = generate_token()
        with self.connect() as conn:
            cur = conn.execute(
                """
                UPDATE devices
                SET token_hash = ?, revoked_at = NULL
                WHERE device_id = ?
                """,
                (hash_token(token), device_id),
            )
            if cur.rowcount <= 0:
                self.record_audit(
                    "device.rotate_token",
                    device_id=device_id,
                    outcome="not_found",
                    conn=conn,
                )
                return None
            self.record_audit(
                "device.rotate_token",
                device_id=device_id,
                outcome="ok",
                conn=conn,
            )
            return token

    def register_se_pubkey(self, device_id: str, se_public_key_der: str) -> bool:
        """WS4: store the device's Secure-Enclave public key (base64 X9.63)."""
        if not se_public_key_der:
            return False
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE devices SET se_public_key_der = ? WHERE device_id = ?",
                (se_public_key_der, device_id),
            )
            ok = cur.rowcount > 0
            self.record_audit(
                "device.register_se_pubkey",
                device_id=device_id,
                outcome="ok" if ok else "not_found",
                conn=conn,
            )
            return ok

    def get_se_pubkey(self, device_id: str) -> str | None:
        """The registered SE public key for an ACTIVE device. Revoked devices
        return None, so revocation also blocks zero-interaction re-pair."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT se_public_key_der FROM devices WHERE device_id = ? AND revoked_at IS NULL",
                (device_id,),
            ).fetchone()
        if row is None:
            return None
        value = row["se_public_key_der"]
        return value if value else None

    def record_audit(
        self,
        event: str,
        *,
        device_id: str | None,
        outcome: str,
        path: str | None = None,
        detail: dict[str, Any] | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        audit_detail = _redact_for_audit(detail or {})
        payload = json.dumps(audit_detail, sort_keys=True)
        if conn is not None:
            conn.execute(
                """
                INSERT INTO audit_events (ts, event, device_id, outcome, path, detail_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (utc_epoch(), event, device_id, outcome, path, payload),
            )
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({
            "ts": utc_epoch(),
            "event": event,
            "device_id": device_id,
            "outcome": outcome,
            "path": path,
            "detail": audit_detail,
        }, sort_keys=True)
        with self.audit_path.open("a") as fh:
            fh.write(line + "\n")
        try:
            os.chmod(self.audit_path, 0o600)
        except OSError:
            pass
