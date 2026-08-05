#!/usr/bin/env python3
"""Always-available configuration policy for pairing assurance gates."""

from __future__ import annotations

import os


def direct_attest_required() -> bool:
    return os.environ.get("PAIRLING_DIRECT_ATTEST_REQUIRED", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def relay_claims_required() -> bool:
    return os.environ.get("PAIRLING_RELAY_CLAIMS_REQUIRED", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "required",
    }
