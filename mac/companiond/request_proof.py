#!/usr/bin/env python3
"""Request-bound HMAC proof verification for mutating Pairling endpoints."""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Any


INSTALL_ID_HEADER = "Pairling-Install-ID"
REQUEST_ID_HEADER = "Pairling-Request-ID"
TIMESTAMP_HEADER = "Pairling-Timestamp"
BODY_SHA256_HEADER = "Pairling-Body-SHA256"
PROOF_HEADER = "Pairling-Proof"
SKEW_MS = 10 * 60 * 1000


@dataclass(frozen=True)
class ProofVerificationResult:
    ok: bool
    status: int = 200
    code: str = "ok"
    message: str = "ok"


class ReplayCache:
    def __init__(self, *, retention_seconds: int = 600, max_entries: int = 4096):
        self.retention_seconds = retention_seconds
        self.max_entries = max_entries
        self._seen: dict[tuple[str, str], float] = {}

    def check_and_store(self, *, device_id: str, request_id: str, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        cutoff = current - self.retention_seconds
        if len(self._seen) > self.max_entries:
            self._seen = {
                key: ts for key, ts in self._seen.items()
                if ts >= cutoff
            }
        key = (device_id, request_id)
        if key in self._seen and self._seen[key] >= cutoff:
            return False
        self._seen[key] = current
        return True


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
    if install_id != local_install_id:
        return ProofVerificationResult(False, 403, "install_id_mismatch", "Request proof was for a different Mac.")
    try:
        parsed_ts = int(timestamp_ms)
    except ValueError:
        return ProofVerificationResult(False, 401, "bad_timestamp", "Request proof timestamp is invalid.")
    current_ms = int(time.time() * 1000) if now_ms is None else now_ms
    if abs(current_ms - parsed_ts) > SKEW_MS:
        return ProofVerificationResult(False, 401, "stale_timestamp", "Request proof timestamp is stale.")

    expected_body_hash = body_sha256_hex(body)
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
    if not hmac.compare_digest(proof.lower(), expected_proof):
        return ProofVerificationResult(False, 401, "bad_proof", "Request proof did not verify.")
    if not replay_cache.check_and_store(device_id=device_id, request_id=request_id, now=current_ms / 1000):
        return ProofVerificationResult(False, 409, "replayed_request", "Request proof was already used.")
    return ProofVerificationResult(True)


def _header(headers: Any, name: str) -> str:
    try:
        return str(headers.get(name, "") or "").strip()
    except AttributeError:
        return str((headers or {}).get(name, "") or "").strip()
