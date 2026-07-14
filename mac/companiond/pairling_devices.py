#!/usr/bin/env python3
"""Per-device token registry for the Pairling Mac runtime."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from runtime_contract import DEFAULT_DEVICE_SCOPES
from runtime_paths import audit_log_path, devices_db_path, install_id_path


SQLITE_BUSY_TIMEOUT_MS = int(os.environ.get("PAIRLING_SQLITE_BUSY_TIMEOUT_MS", "5000"))
PAIR_ACTIVATION_PROOF_VERSION = "pairling.psk.activate.v1"
PAIR_ACTIVATION_RESULT_CONTRACT = "pairling.psk.activate.result.v1"
SMOKE_DEVICE_PURPOSE = "runtime_truth_smoke"


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
        os.chmod(path.parent, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
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
    activation_state: str = "active"
    credential_expires_at: float | None = None

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


@dataclass(frozen=True)
class PendingClaimRecord:
    pair_id: str
    device_id: str
    request_hash: str
    response_json: str
    state: str
    expires_at: float


@dataclass(frozen=True)
class PairActivationResult:
    device_id: str
    pair_id: str
    already_active: bool
    superseded_device_ids: tuple[str, ...]
    activation_result: dict[str, Any] | None = None


class DeviceRegistryError(Exception):
    def __init__(
        self,
        code: str,
        status: int,
        message: str,
        *,
        device_id: str | None = None,
        relay_secret_expected: bool = False,
        activation_result: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.status = status
        self.message = message
        self.device_id = device_id
        self.relay_secret_expected = relay_secret_expected
        self.activation_result = activation_result


def _activation_result_scalar(value: str, field: str) -> str:
    text = str(value)
    if not text or "\n" in text or "\r" in text:
        raise ValueError(f"{field} is not a safe activation result scalar")
    return text


def pair_activation_result_canonical(
    *,
    ok: bool,
    pair_id: str,
    device_id: str,
    install_id: str,
    activation_nonce: str,
    token_hash: str,
    activation_proof: str,
    pairing_state: str,
    outcome: str,
    already_active: bool,
    superseded_device_ids: Iterable[str] = (),
) -> bytes:
    sorted_ids = sorted(
        {
            _activation_result_scalar(value, "superseded_device_id")
            for value in superseded_device_ids
        }
    )
    scalars = [
        PAIR_ACTIVATION_RESULT_CONTRACT,
        "1" if ok else "0",
        _activation_result_scalar(pair_id, "pair_id"),
        _activation_result_scalar(device_id, "device_id"),
        _activation_result_scalar(install_id, "install_id"),
        _activation_result_scalar(activation_nonce, "activation_nonce"),
        _activation_result_scalar(token_hash, "token_hash").lower(),
        _activation_result_scalar(activation_proof, "activation_proof").lower(),
        _activation_result_scalar(pairing_state, "pairing_state"),
        _activation_result_scalar(outcome, "outcome"),
        "1" if already_active else "0",
        str(len(sorted_ids)),
        *sorted_ids,
    ]
    return "\n".join(scalars).encode("utf-8")


def signed_pair_activation_result(
    *,
    proof_secret: str,
    ok: bool,
    pair_id: str,
    device_id: str,
    install_id: str,
    activation_nonce: str,
    token_hash: str,
    activation_proof: str,
    pairing_state: str,
    outcome: str,
    already_active: bool,
    superseded_device_ids: Iterable[str] = (),
) -> dict[str, Any]:
    sorted_ids = tuple(sorted(set(str(value) for value in superseded_device_ids)))
    canonical = pair_activation_result_canonical(
        ok=ok,
        pair_id=pair_id,
        device_id=device_id,
        install_id=install_id,
        activation_nonce=activation_nonce,
        token_hash=token_hash,
        activation_proof=activation_proof,
        pairing_state=pairing_state,
        outcome=outcome,
        already_active=already_active,
        superseded_device_ids=sorted_ids,
    )
    return {
        "result_contract": PAIR_ACTIVATION_RESULT_CONTRACT,
        "ok": bool(ok),
        "pairing_state": pairing_state,
        "outcome": outcome,
        "pair_id": pair_id,
        "device_id": device_id,
        "install_id": install_id,
        "activation_nonce": activation_nonce,
        "token_hash": token_hash.lower(),
        "activation_proof": activation_proof.lower(),
        "already_active": bool(already_active),
        "superseded_device_ids": list(sorted_ids),
        "result_proof": hmac.new(
            proof_secret.encode("utf-8"), canonical, hashlib.sha256
        ).hexdigest(),
    }


def pair_activation_canonical(
    *,
    pair_id: str,
    device_id: str,
    activation_nonce: str,
    token_hash: str,
    install_id: str,
) -> bytes:
    return (
        f"{PAIR_ACTIVATION_PROOF_VERSION}\n{pair_id}\n{device_id}\n"
        f"{activation_nonce}\n{token_hash}\n{install_id}"
    ).encode("utf-8")


class DeviceRegistry:
    def __init__(self, db_path: Path | None = None, audit_path: Path | None = None):
        self.db_path = db_path or devices_db_path()
        self.audit_path = audit_path or audit_log_path()
        self._last_seen_lock = threading.Lock()
        self._last_seen_marks: dict[str, float] = {}
        self._flushed_marks: dict[str, float] = {}

    @contextmanager
    def connect(self, *, immediate: bool = False):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.db_path.parent, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
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
            if immediate:
                conn.execute("BEGIN IMMEDIATE")
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
            "tailnet_node_id": "ALTER TABLE devices ADD COLUMN tailnet_node_id TEXT",
            # WS4: base64 X9.63 (uncompressed P-256 point) of the device's
            # Secure-Enclave public key, registered at first pair. Used to
            # verify zero-interaction re-pair challenge signatures.
            "se_public_key_der": "ALTER TABLE devices ADD COLUMN se_public_key_der TEXT",
            "activation_state": "ALTER TABLE devices ADD COLUMN activation_state TEXT NOT NULL DEFAULT 'active'",
            "pending_pair_id": "ALTER TABLE devices ADD COLUMN pending_pair_id TEXT",
            "pending_expires_at": "ALTER TABLE devices ADD COLUMN pending_expires_at REAL",
            "activation_nonce": "ALTER TABLE devices ADD COLUMN activation_nonce TEXT",
            "activated_at": "ALTER TABLE devices ADD COLUMN activated_at REAL",
            "purpose": "ALTER TABLE devices ADD COLUMN purpose TEXT",
            "lease_expires_at": "ALTER TABLE devices ADD COLUMN lease_expires_at REAL",
        }
        for column, statement in additive_columns.items():
            if column not in existing:
                conn.execute(statement)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_token_hash ON devices(token_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_relay_device_id ON devices(relay_device_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_pending_pair_id ON devices(pending_pair_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_lease_expiry ON devices(purpose, lease_expires_at)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_pair_claims (
                pair_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL UNIQUE,
                request_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                state TEXT NOT NULL,
                expires_at REAL NOT NULL,
                created_at REAL NOT NULL,
                activated_at REAL,
                retain_until REAL NOT NULL,
                secret_cleaned INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pending_pair_claims_expiry "
            "ON pending_pair_claims(state, expires_at, retain_until)"
        )
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
        se_public_key_der: str | None = None,
        purpose: str | None = None,
        lease_expires_at: float | None = None,
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
                      AND activation_state = 'active'
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
                     device_display_name, proof_secret, se_public_key_der,
                     activation_state, activated_at, purpose, lease_expires_at)
                VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, NULL, ?, ?, ?, ?,
                        'active', ?, ?, ?)
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
                    se_public_key_der or None,
                    now,
                    purpose or None,
                    lease_expires_at,
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
                    "purpose": purpose or None,
                },
                conn=conn,
            )
            if se_public_key_der:
                self.record_audit(
                    "device.register_se_pubkey",
                    device_id=device_id_value,
                    outcome="ok",
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

    def create_pending_device(
        self,
        *,
        pair_id: str,
        request_hash: str,
        response_json: str,
        pending_expires_at: float,
        activation_nonce: str,
        device_name: str,
        token: str,
        proof_secret: str,
        device_id: str,
        scopes: Iterable[str],
        install_id: str,
        relay_device_id: str | None = None,
        attestation_status: str = "none",
        device_display_name: str | None = None,
        relay_pair_secret_ref: str | None = None,
        se_public_key_der: str | None = None,
        purpose: str | None = None,
        lease_expires_at: float | None = None,
    ) -> CreatedDevice:
        """Atomically persist a non-authoritative device and its sealed reply."""
        normalized_scopes = tuple(sorted(set(scopes)))
        if not normalized_scopes:
            raise DeviceRegistryError("invalid_scopes", 400, "pending device scopes are empty")
        try:
            decoded_response = json.loads(response_json)
        except (TypeError, ValueError, RecursionError) as exc:
            raise DeviceRegistryError(
                "pair_response_invalid", 500, "sealed pairing response is invalid"
            ) from exc
        if not isinstance(decoded_response, dict):
            raise DeviceRegistryError(
                "pair_response_invalid", 500, "sealed pairing response is invalid"
            )
        attestation_value = attestation_status if attestation_status in {
            "none",
            "development",
            "production",
            "unsupported",
            "failed",
        } else "failed"
        now = utc_epoch()
        with self.connect(immediate=True) as conn:
            existing = conn.execute(
                "SELECT request_hash, state, response_json, expires_at, device_id "
                "FROM pending_pair_claims WHERE pair_id = ?",
                (pair_id,),
            ).fetchone()
            if existing is not None:
                if not secrets.compare_digest(str(existing["request_hash"]), request_hash):
                    raise DeviceRegistryError(
                        "pair_claim_conflict", 409, "pairing claim does not match the saved claim"
                    )
                if existing["state"] in {"pending", "active"} and existing["response_json"]:
                    raise DeviceRegistryError(
                        "pair_claim_already_saved", 409, "pairing claim response is already saved"
                    )
                raise DeviceRegistryError(
                    "pair_claim_expired", 410, "saved pairing claim is no longer usable"
                )
            conn.execute(
                """
                INSERT INTO devices
                    (device_id, device_name, token_hash, scopes_json, install_id,
                     created_at, last_seen_at, revoked_at, relay_device_id,
                     attestation_status, apns_registered_at, relay_pair_secret_ref,
                     device_display_name, proof_secret, se_public_key_der,
                     activation_state, pending_pair_id, pending_expires_at,
                     activation_nonce, activated_at, purpose, lease_expires_at)
                VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, NULL, ?, ?, ?, ?,
                        'pending', ?, ?, ?, NULL, ?, ?)
                """,
                (
                    device_id,
                    device_name,
                    hash_token(token),
                    json.dumps(normalized_scopes),
                    install_id,
                    now,
                    relay_device_id,
                    attestation_value,
                    relay_pair_secret_ref,
                    device_display_name or device_name,
                    proof_secret,
                    se_public_key_der or None,
                    pair_id,
                    float(pending_expires_at),
                    activation_nonce,
                    purpose or None,
                    lease_expires_at,
                ),
            )
            conn.execute(
                """
                INSERT INTO pending_pair_claims
                    (pair_id, device_id, request_hash, response_json, state,
                     expires_at, created_at, activated_at, retain_until, secret_cleaned)
                VALUES (?, ?, ?, ?, 'pending', ?, ?, NULL, ?, 0)
                """,
                (
                    pair_id,
                    device_id,
                    request_hash,
                    response_json,
                    float(pending_expires_at),
                    now,
                    float(pending_expires_at) + 600.0,
                ),
            )
            self.record_audit(
                "device.pending_created",
                device_id=device_id,
                outcome="ok",
                detail={
                    "pair_id": pair_id,
                    "scopes": list(normalized_scopes),
                    "relay_device_id": relay_device_id,
                    "purpose": purpose or None,
                    "pending_expires_at": float(pending_expires_at),
                    "lease_expires_at": lease_expires_at,
                },
                conn=conn,
            )
        return CreatedDevice(
            device_id,
            token,
            proof_secret,
            normalized_scopes,
            install_id,
            relay_device_id,
            attestation_value,
        )

    def resumable_pair_claim(self, pair_id: str, request_hash: str) -> PendingClaimRecord | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM pending_pair_claims WHERE pair_id = ?",
                (pair_id,),
            ).fetchone()
        if row is None:
            return None
        if not secrets.compare_digest(str(row["request_hash"]), request_hash):
            raise DeviceRegistryError(
                "pair_claim_conflict", 409, "pairing claim does not match the saved claim"
            )
        if row["state"] not in {"pending", "active"} or not row["response_json"]:
            raise DeviceRegistryError(
                "pair_claim_expired", 410, "saved pairing claim is no longer usable"
            )
        if row["state"] == "pending" and utc_epoch() > float(row["expires_at"]):
            raise DeviceRegistryError(
                "pair_claim_expired", 410, "saved pairing claim has expired"
            )
        return PendingClaimRecord(
            pair_id=str(row["pair_id"]),
            device_id=str(row["device_id"]),
            request_hash=str(row["request_hash"]),
            response_json=str(row["response_json"]),
            state=str(row["state"]),
            expires_at=float(row["expires_at"]),
        )

    def prune_pending_claims(self, *, now: float | None = None) -> list[dict[str, Any]]:
        current = utc_epoch() if now is None else float(now)
        cleanup: list[dict[str, Any]] = []
        with self.connect(immediate=True) as conn:
            expiring = conn.execute(
                """
                SELECT c.pair_id, c.device_id, d.relay_pair_secret_ref
                FROM pending_pair_claims c
                LEFT JOIN devices d ON d.device_id = c.device_id
                WHERE c.state = 'pending' AND c.expires_at <= ?
                """,
                (current,),
            ).fetchall()
            for row in expiring:
                cleanup.append({
                    "pair_id": str(row["pair_id"]),
                    "device_id": str(row["device_id"]),
                    "relay_secret_expected": bool(row["relay_pair_secret_ref"]),
                })
                # Keep the proof secret only for the existing rejection-retention
                # window. The activation endpoint needs it to authenticate a
                # terminal 410 after expiry. revoked_at makes the bearer unusable
                # before any route-specific pending-token exception is considered.
                conn.execute(
                    "UPDATE devices SET activation_state = 'expired', revoked_at = ? "
                    "WHERE device_id = ? AND activation_state = 'pending'",
                    (current, row["device_id"]),
                )
                conn.execute(
                    """
                    UPDATE pending_pair_claims
                    SET state = 'expired', response_json = '', retain_until = ?,
                        secret_cleaned = CASE WHEN ? THEN 0 ELSE 1 END
                    WHERE pair_id = ?
                    """,
                    (current + 600.0, bool(row["relay_pair_secret_ref"]), row["pair_id"]),
                )
                self.record_audit(
                    "device.pending_expired",
                    device_id=str(row["device_id"]),
                    outcome="ok",
                    detail={"pair_id": str(row["pair_id"])},
                    conn=conn,
                )
            outstanding = conn.execute(
                """
                SELECT pair_id, device_id FROM pending_pair_claims
                WHERE state IN ('expired', 'superseded') AND secret_cleaned = 0
                """
            ).fetchall()
            seen = {item["device_id"] for item in cleanup}
            for row in outstanding:
                device_id = str(row["device_id"])
                if device_id not in seen:
                    cleanup.append({
                        "pair_id": str(row["pair_id"]),
                        "device_id": device_id,
                        "relay_secret_expected": True,
                    })
            conn.execute(
                "DELETE FROM pending_pair_claims "
                "WHERE state = 'active' AND retain_until <= ?",
                (current,),
            )
            conn.execute(
                """
                DELETE FROM devices
                WHERE activation_state IN ('expired', 'superseded')
                  AND device_id IN (
                      SELECT device_id FROM pending_pair_claims
                      WHERE state IN ('expired', 'superseded')
                        AND secret_cleaned = 1 AND retain_until <= ?
                  )
                """,
                (current,),
            )
            conn.execute(
                "DELETE FROM pending_pair_claims "
                "WHERE state IN ('expired', 'superseded') "
                "AND secret_cleaned = 1 AND retain_until <= ?",
                (current,),
            )
        return cleanup

    def mark_pending_secret_cleaned(self, pair_id: str, device_id: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE pending_pair_claims SET secret_cleaned = 1 "
                "WHERE pair_id = ? AND device_id = ?",
                (pair_id, device_id),
            )

    def activate_pending_claim(
        self,
        *,
        pair_id: str,
        device_id: str,
        activation_nonce: str,
        token_hash: str,
        activation_proof: str,
        before_activation: Callable[[], None] | None = None,
        now: float | None = None,
    ) -> PairActivationResult:
        current = utc_epoch() if now is None else float(now)
        with self.connect(immediate=True) as conn:
            claim = conn.execute(
                "SELECT * FROM pending_pair_claims WHERE pair_id = ?",
                (pair_id,),
            ).fetchone()
            device = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()

            def activation_error(
                code: str,
                status: int,
                message: str,
                *,
                relay_secret_expected: bool = False,
            ) -> DeviceRegistryError:
                pairing_state = {
                    "pair_activation_expired": "expired",
                    "pair_activation_superseded": "superseded",
                }.get(code, "rejected")
                activation_result = None
                if device is not None and str(device["proof_secret"] or ""):
                    try:
                        activation_result = signed_pair_activation_result(
                            proof_secret=str(device["proof_secret"]),
                            ok=False,
                            pair_id=pair_id,
                            device_id=device_id,
                            install_id=str(device["install_id"]),
                            activation_nonce=activation_nonce,
                            token_hash=token_hash,
                            activation_proof=activation_proof,
                            pairing_state=pairing_state,
                            outcome=code,
                            already_active=False,
                        )
                    except ValueError:
                        activation_result = None
                return DeviceRegistryError(
                    code,
                    status,
                    message,
                    device_id=device_id if device is not None else None,
                    relay_secret_expected=relay_secret_expected,
                    activation_result=activation_result,
                )

            if claim is not None and claim["state"] in {"expired", "superseded"}:
                code = (
                    "pair_activation_superseded"
                    if claim["state"] == "superseded"
                    else "pair_activation_expired"
                )
                raise activation_error(
                    code,
                    409 if code == "pair_activation_superseded" else 410,
                    "pairing activation is no longer usable",
                )
            if device is None:
                raise activation_error(
                    "pair_activation_invalid", 403, "pairing activation was rejected"
                )
            if claim is None and (
                str(device["activation_state"] or "") != "active"
                or str(device["pending_pair_id"] or "") != pair_id
            ):
                raise activation_error(
                    "pair_activation_invalid", 403, "pairing activation was rejected"
                )
            if claim is not None and str(claim["device_id"]) != device_id:
                raise activation_error(
                    "pair_activation_invalid", 403, "pairing activation was rejected"
                )
            if device["revoked_at"] is not None:
                raise activation_error(
                    "pair_activation_expired", 410, "pairing activation is no longer usable",
                )
            if (
                device["lease_expires_at"] is not None
                and current >= float(device["lease_expires_at"])
            ):
                raise activation_error(
                    "pair_activation_expired", 410, "pairing credential lease has expired",
                )
            if (
                claim is not None
                and claim["state"] == "pending"
                and current > float(claim["expires_at"])
            ):
                raise activation_error(
                    "pair_activation_expired", 410, "pairing activation has expired",
                )
            stored_nonce = str(device["activation_nonce"] or "")
            stored_token_hash = str(device["token_hash"] or "")
            if (
                not stored_nonce
                or not secrets.compare_digest(stored_nonce, activation_nonce)
                or not secrets.compare_digest(stored_token_hash, token_hash)
            ):
                raise activation_error(
                    "pair_activation_invalid", 403, "pairing activation was rejected"
                )
            canonical = pair_activation_canonical(
                pair_id=pair_id,
                device_id=device_id,
                activation_nonce=activation_nonce,
                token_hash=token_hash,
                install_id=str(device["install_id"]),
            )
            expected = hmac.new(
                str(device["proof_secret"] or "").encode("utf-8"),
                canonical,
                hashlib.sha256,
            ).hexdigest()
            if not activation_proof or not secrets.compare_digest(expected, activation_proof):
                raise activation_error(
                    "pair_activation_invalid", 403, "pairing activation was rejected"
                )
            if (
                device["activation_state"] == "active"
                and (claim is None or claim["state"] == "active")
            ):
                if before_activation is not None:
                    before_activation()
                superseded_rows = conn.execute(
                    """
                    SELECT device_id FROM devices
                    WHERE superseded_by_device_id = ? AND revoked_at IS NOT NULL
                    ORDER BY created_at, device_id
                    """,
                    (device_id,),
                ).fetchall()
                superseded_ids = tuple(
                    str(row["device_id"]) for row in superseded_rows
                )
                activation_result = signed_pair_activation_result(
                    proof_secret=str(device["proof_secret"]),
                    ok=True,
                    pair_id=pair_id,
                    device_id=device_id,
                    install_id=str(device["install_id"]),
                    activation_nonce=activation_nonce,
                    token_hash=token_hash,
                    activation_proof=activation_proof,
                    pairing_state="active",
                    outcome="already_active",
                    already_active=True,
                    superseded_device_ids=superseded_ids,
                )
                return PairActivationResult(
                    device_id,
                    pair_id,
                    True,
                    superseded_ids,
                    activation_result,
                )

            relay_device_id = device["relay_device_id"]
            if relay_device_id:
                newer = conn.execute(
                    """
                    SELECT device_id FROM devices
                    WHERE relay_device_id = ? AND activation_state = 'active'
                      AND revoked_at IS NULL AND created_at > ? AND device_id != ?
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (relay_device_id, device["created_at"], device_id),
                ).fetchone()
                if newer is not None:
                    conn.execute(
                        "UPDATE devices SET activation_state = 'superseded', revoked_at = ?, "
                        "superseded_by_device_id = ? WHERE device_id = ?",
                        (current, newer["device_id"], device_id),
                    )
                    conn.execute(
                        "UPDATE pending_pair_claims SET state = 'superseded', response_json = '', "
                        "retain_until = ? WHERE pair_id = ?",
                        (current + 600.0, pair_id),
                    )
                    self.record_audit(
                        "device.pending_superseded",
                        device_id=device_id,
                        outcome="rejected",
                        detail={"newer_device_id": str(newer["device_id"])},
                        conn=conn,
                    )
                    # Preserve the rejection tombstone before returning the typed
                    # conflict. The context manager would otherwise roll it back
                    # when the exception leaves this block.
                    conn.commit()
                    raise activation_error(
                        "pair_activation_superseded", 409,
                        "a newer repair is already active",
                        relay_secret_expected=bool(device["relay_pair_secret_ref"]),
                    )

            if before_activation is not None:
                before_activation()

            superseded_rows = []
            if relay_device_id:
                superseded_rows = conn.execute(
                    """
                    SELECT device_id FROM devices
                    WHERE relay_device_id = ? AND activation_state = 'active'
                      AND revoked_at IS NULL AND device_id != ?
                    """,
                    (relay_device_id, device_id),
                ).fetchall()
                for row in superseded_rows:
                    old_device_id = str(row["device_id"])
                    conn.execute(
                        "UPDATE devices SET revoked_at = ?, superseded_by_device_id = ? "
                        "WHERE device_id = ?",
                        (current, device_id, old_device_id),
                    )
                    self.record_audit(
                        "device.superseded",
                        device_id=old_device_id,
                        outcome="ok",
                        detail={
                            "relay_device_id": str(relay_device_id),
                            "new_device_id": device_id,
                            "policy": "relay_repair_activates_saved_credentials",
                        },
                        conn=conn,
                    )
            conn.execute(
                """
                UPDATE devices
                SET activation_state = 'active', activated_at = ?,
                    pending_expires_at = NULL
                WHERE device_id = ?
                """,
                (current, device_id),
            )
            conn.execute(
                """
                UPDATE pending_pair_claims
                SET state = 'active', activated_at = ?, retain_until = ?
                WHERE pair_id = ?
                """,
                (current, current + 86400.0, pair_id),
            )
            self.record_audit(
                "device.pending_activated",
                device_id=device_id,
                outcome="ok",
                detail={
                    "pair_id": pair_id,
                    "superseded_device_ids": [str(row["device_id"]) for row in superseded_rows],
                },
                conn=conn,
            )
            superseded_ids = tuple(str(row["device_id"]) for row in superseded_rows)
            activation_result = signed_pair_activation_result(
                proof_secret=str(device["proof_secret"]),
                ok=True,
                pair_id=pair_id,
                device_id=device_id,
                install_id=str(device["install_id"]),
                activation_nonce=activation_nonce,
                token_hash=token_hash,
                activation_proof=activation_proof,
                pairing_state="active",
                outcome="activated",
                already_active=False,
                superseded_device_ids=superseded_ids,
            )
            return PairActivationResult(
                device_id,
                pair_id,
                False,
                superseded_ids,
                activation_result,
            )

    def revoke_expired_smoke_leases(self, *, now: float | None = None) -> list[str]:
        current = utc_epoch() if now is None else float(now)
        with self.connect(immediate=True) as conn:
            rows = conn.execute(
                """
                SELECT device_id FROM devices
                WHERE purpose = ? AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= ? AND revoked_at IS NULL
                """,
                (SMOKE_DEVICE_PURPOSE, current),
            ).fetchall()
            for row in rows:
                device_id = str(row["device_id"])
                conn.execute(
                    "UPDATE devices SET revoked_at = ? WHERE device_id = ?",
                    (current, device_id),
                )
                self.record_audit(
                    "device.smoke_lease_expired",
                    device_id=device_id,
                    outcome="ok",
                    detail={"purpose": SMOKE_DEVICE_PURPOSE},
                    conn=conn,
                )
            return [str(row["device_id"]) for row in rows]

    def rollback_created_device(self, device_id: str, *, reason: str) -> bool:
        """Remove one failed finalize and reactivate only devices it superseded."""
        with self.connect() as conn:
            created = conn.execute(
                """
                SELECT relay_device_id, created_at, revoked_at, superseded_by_device_id
                FROM devices WHERE device_id = ?
                """,
                (device_id,),
            ).fetchone()
            if created is None:
                return False
            restored = [
                str(row["device_id"])
                for row in conn.execute(
                    """
                    SELECT device_id FROM devices
                    WHERE superseded_by_device_id = ? AND revoked_at = ?
                    """,
                    (device_id, created["created_at"]),
                ).fetchall()
            ]
            successor_id = created["superseded_by_device_id"]
            if successor_id:
                live_successor = conn.execute(
                    "SELECT 1 FROM devices WHERE device_id = ? AND revoked_at IS NULL",
                    (successor_id,),
                ).fetchone()
                if live_successor is None:
                    successor_id = None
            if not successor_id and created["relay_device_id"]:
                successor = conn.execute(
                    """
                    SELECT device_id FROM devices
                    WHERE relay_device_id = ?
                      AND device_id != ?
                      AND revoked_at IS NULL
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (created["relay_device_id"], device_id),
                ).fetchone()
                successor_id = successor["device_id"] if successor is not None else None
            if successor_id:
                # A newer successful repair already superseded this failed row.
                # Keep its predecessors revoked and point their history at the
                # live successor instead of reactivating two relay identities.
                conn.execute(
                    """
                    UPDATE devices SET superseded_by_device_id = ?
                    WHERE superseded_by_device_id = ?
                    """,
                    (successor_id, device_id),
                )
                restored = []
            else:
                conn.execute(
                    """
                    UPDATE devices
                    SET revoked_at = NULL, superseded_by_device_id = NULL
                    WHERE superseded_by_device_id = ? AND revoked_at = ?
                    """,
                    (device_id, created["created_at"]),
                )
                conn.execute(
                    """
                    UPDATE devices SET superseded_by_device_id = NULL
                    WHERE superseded_by_device_id = ?
                    """,
                    (device_id,),
                )
            conn.execute("DELETE FROM pending_pair_claims WHERE device_id = ?", (device_id,))
            conn.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
            self.record_audit(
                "device.create_rolled_back",
                device_id=device_id,
                outcome="ok",
                detail={"reason": reason, "restored_device_ids": restored},
                conn=conn,
            )
            return True

    def authenticate(
        self,
        token: str | None,
        *,
        required_scopes: Iterable[str] = (),
        path: str | None = None,
        allow_pending: bool = False,
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
            now = time.time()
            lease_expires_at = row["lease_expires_at"]
            if lease_expires_at is not None and now >= float(lease_expires_at):
                self.record_audit(
                    "auth.denied",
                    device_id=row["device_id"],
                    outcome="lease_expired",
                    path=path,
                    conn=conn,
                )
                return DeviceAuthResult(False, 403, "lease_expired")
            if row["revoked_at"] is not None:
                self.record_audit(
                    "auth.denied",
                    device_id=row["device_id"],
                    outcome="revoked",
                    path=path,
                    conn=conn,
                )
                return DeviceAuthResult(False, 403, "revoked")
            activation_state = str(row["activation_state"] or "active")
            pending_expires_at = row["pending_expires_at"]
            if activation_state != "active":
                pending_usable = (
                    activation_state == "pending"
                    and allow_pending
                    and pending_expires_at is not None
                    and now < float(pending_expires_at)
                )
                if not pending_usable:
                    reason = (
                        "pending_expired"
                        if activation_state == "pending"
                        and pending_expires_at is not None
                        and now >= float(pending_expires_at)
                        else "pending_activation"
                    )
                    self.record_audit(
                        "auth.denied",
                        device_id=row["device_id"],
                        outcome=reason,
                        path=path,
                        conn=conn,
                    )
                    return DeviceAuthResult(False, 403, reason)
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
                    activation_state=activation_state,
                    credential_expires_at=(
                        min(
                            value
                            for value in (
                                float(lease_expires_at) if lease_expires_at is not None else None,
                                float(pending_expires_at)
                                if activation_state == "pending" and pending_expires_at is not None
                                else None,
                            )
                            if value is not None
                        )
                        if lease_expires_at is not None
                        or (activation_state == "pending" and pending_expires_at is not None)
                        else None
                    ),
                )
            # Record the sighting in memory only. The auth hot path is pinned
            # write-free (test_device_registry_uses_wal_and_no_successful_auth
            # _write): every request authenticates, and a write per request
            # would churn WAL for nothing. flush_last_seen() persists the
            # newest sighting lazily, off this path.
            with self._last_seen_lock:
                self._last_seen_marks[row["device_id"]] = time.time()
            return DeviceAuthResult(
                True,
                200,
                "ok",
                device_id=row["device_id"],
                install_id=row["install_id"],
                proof_secret=row["proof_secret"],
                scopes=scopes,
                activation_state=activation_state,
                credential_expires_at=(
                    min(
                        value
                        for value in (
                            float(lease_expires_at) if lease_expires_at is not None else None,
                            float(pending_expires_at)
                            if activation_state == "pending" and pending_expires_at is not None
                            else None,
                        )
                        if value is not None
                    )
                    if lease_expires_at is not None
                    or (activation_state == "pending" and pending_expires_at is not None)
                    else None
                ),
            )

    def tailnet_node_id(self, device_id: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT tailnet_node_id FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            return None if row is None else row["tailnet_node_id"]

    def set_tailnet_node_id_if_absent(self, device_id: str, node_id: str) -> bool:
        node_id = str(node_id or "").strip()
        if not device_id or not node_id:
            return False
        with self.connect() as conn:
            cur = conn.execute(
                """
                UPDATE devices
                SET tailnet_node_id = ?
                WHERE device_id = ?
                  AND revoked_at IS NULL
                  AND activation_state = 'active'
                  AND (lease_expires_at IS NULL OR lease_expires_at > ?)
                  AND (tailnet_node_id IS NULL OR tailnet_node_id = '')
                """,
                (node_id, device_id, utc_epoch()),
            )
            changed = cur.rowcount > 0
            if changed:
                self.record_audit(
                    "device.tailnet_node_id.bound",
                    device_id=device_id,
                    outcome="ok",
                    detail={"tailnet_node_id": node_id},
                    conn=conn,
                )
            return changed

    def flush_last_seen(self) -> int:
        """Persist in-memory auth sightings, newest-wins, skipping anything
        already persisted. The auth path itself never writes; this runs on
        the evidence read and costs nothing when there is nothing new."""
        with self._last_seen_lock:
            pending = {
                device_id: seen_at
                for device_id, seen_at in self._last_seen_marks.items()
                if seen_at > self._flushed_marks.get(device_id, 0.0)
            }
        if not pending:
            return 0
        persisted: dict[str, float] = {}
        with self.connect() as conn:
            for device_id, seen_at in pending.items():
                try:
                    conn.execute(
                        "UPDATE devices SET last_seen_at = ? "
                        "WHERE device_id = ? AND COALESCE(last_seen_at, 0) < ?",
                        (seen_at, device_id, seen_at),
                    )
                    persisted[device_id] = seen_at
                except sqlite3.Error:
                    continue
        with self._last_seen_lock:
            for device_id, seen_at in persisted.items():
                self._flushed_marks[device_id] = max(
                    seen_at,
                    self._flushed_marks.get(device_id, 0.0),
                )
        return len(persisted)

    def any_device_seen_within(self, seconds: float) -> bool:
        """Human-pairing evidence: an unrevoked device authenticated (or was
        created) within the window. Drives next_action so a paired, active
        Mac stops telling its user to scan a pairing code. Flushes pending
        sightings first so fresh evidence counts immediately."""
        self.flush_last_seen()
        cutoff = time.time() - max(0.0, float(seconds))
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM devices "
                "WHERE revoked_at IS NULL "
                "AND activation_state = 'active' "
                "AND COALESCE(purpose, '') != ? "
                "AND (lease_expires_at IS NULL OR lease_expires_at > ?) "
                "AND (COALESCE(last_seen_at, 0) >= ? OR COALESCE(created_at, 0) >= ?)",
                (SMOKE_DEVICE_PURPOSE, time.time(), cutoff, cutoff),
            ).fetchone()
            return bool(row["n"])

    def revoked_device_ids(self) -> list[str]:
        """Every device id that has ever been revoked. Feeds the push
        dispatcher's boot-time GC so revoked pairings cannot keep push
        registrations (stale tokens burned APNs calls and cluttered the
        delivery audit for weeks before the 2026-07-09 cleanup)."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT device_id FROM devices WHERE revoked_at IS NOT NULL"
            ).fetchall()
            return [str(row["device_id"]) for row in rows]

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
                "SELECT se_public_key_der FROM devices WHERE device_id = ? "
                "AND revoked_at IS NULL AND activation_state = 'active' "
                "AND (lease_expires_at IS NULL OR lease_expires_at > ?)",
                (device_id, utc_epoch()),
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
