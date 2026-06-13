#!/usr/bin/env python3
"""Relay-signed pairing claim ticket validation.

The production relay should sign compact JWS tickets with an asymmetric key
whose public key is pinned in the Mac runtime. The stdlib path below supports
HS256 for local development and tests so the relay-required behavior can be
exercised before the hosted relay exists.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
except Exception:  # pragma: no cover - dependency may be absent in local-only installs.
    InvalidSignature = None
    hashes = None
    serialization = None
    ec = None
    utils = None


EXPECTED_ISSUER = "pairling-relay"
EXPECTED_AUDIENCE = "dev.pairling.mac-runtime"


class RelayClaimError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class RelayClaimVerification:
    payload: dict[str, Any]
    relay_device_id: str
    attestation_status: str
    relay_pair_secret: str | None = None
    relay_pair_secret_ref: str | None = None


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _b64url_json(value: str) -> dict[str, Any]:
    try:
        decoded = json.loads(_b64url_decode(value).decode("utf-8"))
    except Exception as exc:
        raise RelayClaimError("attested_claim_invalid", f"invalid claim json: {exc}")
    if not isinstance(decoded, dict):
        raise RelayClaimError("attested_claim_invalid", "claim component is not an object")
    return decoded


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class RelayClaimVerifier:
    def __init__(
        self,
        *,
        mac_install_id: str,
        hs256_secret: str | None = None,
        public_key_paths: list[Path] | tuple[Path, ...] | None = None,
        audience: str = EXPECTED_AUDIENCE,
        now_fn=time.time,
    ):
        self.mac_install_id = mac_install_id
        self.hs256_secret = hs256_secret
        self.audience = audience
        self.now_fn = now_fn
        self._used_nonces: set[str] = set()
        self._public_keys = self._load_public_keys(public_key_paths or [])

    @classmethod
    def from_environment(cls, *, mac_install_id: str) -> "RelayClaimVerifier":
        return cls(
            mac_install_id=mac_install_id,
            hs256_secret=os.environ.get("PAIRLING_RELAY_CLAIM_HS256_SECRET") or None,
            public_key_paths=configured_public_key_paths(),
        )

    @property
    def can_verify(self) -> bool:
        return bool(self.hs256_secret) or bool(self._public_keys)

    def verify(
        self,
        ticket: str,
        *,
        pair_id: str,
        relay_device_id: str | None,
        device_name: str | None = None,
    ) -> RelayClaimVerification:
        parts = ticket.split(".")
        if len(parts) != 3 or not all(parts):
            raise RelayClaimError("attested_claim_invalid", "claim ticket is not compact JWS")

        header = _b64url_json(parts[0])
        payload = _b64url_json(parts[1])
        alg = str(header.get("alg") or "")
        if alg == "HS256":
            self._verify_hs256(parts)
        elif alg == "ES256":
            self._verify_es256(parts, kid=str(header.get("kid") or ""))
        else:
            raise RelayClaimError("attested_claim_invalid", f"unsupported relay claim alg {alg or 'missing'}")

        now = float(self.now_fn())
        exp = float(payload.get("exp") or 0)
        iat = float(payload.get("iat") or 0)
        if exp <= now:
            raise RelayClaimError("attested_claim_expired", "relay claim ticket expired")
        if iat > now + 60:
            raise RelayClaimError("attested_claim_invalid", "relay claim issued in the future")
        if payload.get("iss") != EXPECTED_ISSUER:
            raise RelayClaimError("attested_claim_invalid", "relay claim issuer mismatch")
        if payload.get("aud") != self.audience:
            raise RelayClaimError("attested_claim_invalid", "relay claim audience mismatch")
        if payload.get("pair_id") != pair_id:
            raise RelayClaimError("attested_claim_invalid", "relay claim pair id mismatch")
        if payload.get("mac_install_id") != self.mac_install_id:
            raise RelayClaimError("attested_claim_invalid", "relay claim Mac install id mismatch")
        subject = str(payload.get("sub") or "")
        if relay_device_id and subject and subject != relay_device_id:
            raise RelayClaimError("attested_claim_invalid", "relay device id mismatch")
        nonce = str(payload.get("nonce") or "")
        if not nonce:
            raise RelayClaimError("attested_claim_invalid", "relay claim nonce missing")
        if nonce in self._used_nonces:
            raise RelayClaimError("attested_claim_replayed", "relay claim nonce already used")

        expected_device_name_hash = payload.get("device_name_hash")
        if expected_device_name_hash and device_name:
            if expected_device_name_hash != _sha256_hex(device_name):
                raise RelayClaimError("attested_claim_invalid", "relay claim device name hash mismatch")

        relay_pair_secret = payload.get("relay_pair_secret")
        relay_pair_secret_ref = payload.get("relay_pair_secret_ref")
        if relay_pair_secret is not None:
            relay_pair_secret = str(relay_pair_secret)
            computed_ref = _sha256_hex(relay_pair_secret)
            if relay_pair_secret_ref and str(relay_pair_secret_ref) != computed_ref:
                raise RelayClaimError("attested_claim_invalid", "relay pair secret reference mismatch")
            relay_pair_secret_ref = str(relay_pair_secret_ref or computed_ref)

        self._used_nonces.add(nonce)
        return RelayClaimVerification(
            payload=payload,
            relay_device_id=relay_device_id or subject,
            attestation_status=str(payload.get("app_attest_environment") or "production"),
            relay_pair_secret=relay_pair_secret,
            relay_pair_secret_ref=relay_pair_secret_ref,
        )

    def _verify_hs256(self, parts: list[str]) -> None:
        if not self.hs256_secret:
            raise RelayClaimError("attested_claim_invalid", "relay claim verifier is not configured for HS256")
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        expected = hmac.new(self.hs256_secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        supplied = _b64url_decode(parts[2])
        if not hmac.compare_digest(expected, supplied):
            raise RelayClaimError("attested_claim_invalid", "relay claim signature is invalid")

    def _verify_es256(self, parts: list[str], *, kid: str) -> None:
        if not self._public_keys:
            raise RelayClaimError("attested_claim_invalid", "relay claim verifier is not configured for ES256")
        if not all([InvalidSignature, hashes, serialization, ec, utils]):
            raise RelayClaimError("attested_claim_invalid", "ES256 relay claim verifier dependency is unavailable")
        supplied = _b64url_decode(parts[2])
        if len(supplied) != 64:
            raise RelayClaimError("attested_claim_invalid", "relay claim ES256 signature has invalid length")
        r = int.from_bytes(supplied[:32], "big")
        s = int.from_bytes(supplied[32:], "big")
        der_signature = utils.encode_dss_signature(r, s)
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        candidates = [
            public_key for key_id, public_key in self._public_keys
            if not kid or key_id == kid
        ]
        if not candidates:
            raise RelayClaimError("attested_claim_invalid", "relay claim key id is not pinned")
        for public_key in candidates:
            try:
                public_key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
                return
            except InvalidSignature:
                continue
        raise RelayClaimError("attested_claim_invalid", "relay claim signature is invalid")

    def _load_public_keys(self, paths: list[Path] | tuple[Path, ...]) -> list[tuple[str, Any]]:
        keys: list[tuple[str, Any]] = []
        if not paths:
            return keys
        if not serialization:
            raise RelayClaimError("attested_claim_invalid", "ES256 relay public key dependency is unavailable")
        for path in paths:
            try:
                public_key = serialization.load_pem_public_key(path.read_bytes())
            except Exception as exc:
                raise RelayClaimError("attested_claim_invalid", f"invalid relay public key {path}: {exc}")
            keys.append((path.stem, public_key))
        return keys


def relay_claims_required() -> bool:
    return os.environ.get("PAIRLING_RELAY_CLAIMS_REQUIRED", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "required",
    }


def configured_public_key_paths() -> list[Path]:
    raw = os.environ.get("PAIRLING_RELAY_PUBLIC_KEYS", "")
    return [Path(item).expanduser() for item in raw.split(":") if item.strip()]
