#!/usr/bin/env python3
"""WS2: direct-LAN Apple App Attest verification for /pair/claim.

Reuses the canonical AppleAppAttestValidator (relay/app_attest_validator.py) so
the intricate attestation crypto (CBOR parse, X.509 chain to Apple's App Attest
root, nonce binding, counter) lives in exactly one place.

Purpose: turning this gate on stops the trivial "published 30-line PoC" LAN
race — a non-genuine client cannot produce a valid Apple attestation. The
clientData canonical binds the attestation to (pair_id, attest_challenge), so a
MITM cannot swap the challenge for one it pre-attested against (Blocker #6).

Fail-closed: when required but the validator/root cert is unavailable, callers
treat a verification error as a rejected claim.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

LAN_CANONICAL_PREFIX = "pair.lan.claim.v1"


def direct_attest_required() -> bool:
    return os.environ.get("PAIRLING_DIRECT_ATTEST_REQUIRED", "").strip().lower() in {"1", "true", "yes", "on"}


def canonical(pair_id: str, attest_challenge: str) -> str:
    """The frozen clientData string the iOS app hashes and the Mac re-derives.
    Binds the attestation to this specific pairing invitation."""
    return f"{LAN_CANONICAL_PREFIX}\n{pair_id}\n{attest_challenge}"


def _team_id() -> str:
    return os.environ.get("PAIRLING_APP_ATTEST_TEAM_ID", "965AVD34A3").strip()


def _bundle_id() -> str:
    return os.environ.get("PAIRLING_APP_ATTEST_BUNDLE_ID", "dev.pairling.ios").strip()


_validator = None
_validator_error: Exception | None = None


def _load_validator():
    global _validator, _validator_error
    if _validator is not None:
        return _validator
    if _validator_error is not None:
        return None
    try:
        try:
            from app_attest_validator import AppleAppAttestValidator  # staged copy
        except Exception:
            relay_dir = Path(__file__).resolve().parents[2] / "relay"
            if str(relay_dir) not in sys.path:
                sys.path.insert(0, str(relay_dir))
            from app_attest_validator import AppleAppAttestValidator
        root_path = os.environ.get("PAIRLING_APP_ATTEST_ROOT_CERT")
        if not root_path:
            local = Path(__file__).resolve().parent / "apple-app-attest-root-ca.pem"
            root_path = str(local) if local.exists() else None
        _validator = AppleAppAttestValidator(root_cert_path=root_path)
        return _validator
    except Exception as exc:  # missing cryptography, missing root cert, etc.
        _validator_error = exc
        return None


def verify_attestation(*, attestation: dict, pair_id: str, attest_challenge: str, key_id: str, environment: str) -> bool:
    """Raise on any failure; return True only on a fully-valid Apple attestation
    bound to this invitation. Fail-closed when the validator is unavailable."""
    validator = _load_validator()
    if validator is None:
        raise RuntimeError(f"app attest validator unavailable: {_validator_error}")
    validator.validate_attestation(
        attestation=attestation,
        challenge=canonical(pair_id, attest_challenge),
        key_id=key_id,
        bundle_id=_bundle_id(),
        team_id=_team_id(),
        environment=(environment or "production"),
    )
    return True
