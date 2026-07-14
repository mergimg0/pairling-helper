#!/usr/bin/env python3
"""Shared constants for the Pairling Mac runtime."""

from __future__ import annotations

import os

SCHEMA_VERSION = 1
RUNTIME_NAME = "pairling-mac-runtime"
CONTRACT_VERSION = "pairling-runtime-v1"
PAIRLING_CONTRACT_VERSION = CONTRACT_VERSION
COMPAT_MODE = "pairling-v1"
PORT = int(os.environ.get("PAIRLING_RUNTIME_PORT", "7773"))
LEGACY_PORT = 7723
DAEMON_LABEL = "dev.pairling.companiond"
LEGACY_TOKEN_RELATIVE_PATH = ".claude/scripts/.notify-token"
# Pairling owns its route through pairling-connectd's embedded tsnet node. This
# does not describe any unrelated Tailscale software installed on the Mac.
TAILSCALE_VARIANT = "embedded_tsnet"
AUTH_MODE = "scoped-device-bearer"
PAIR_SERVICE_TYPE = "_pairling-pair._tcp"
RUNTIME_BONJOUR_ADVERTISED = False
LOCAL_MCP_DISPATCH_SCOPE = "pairling-tools:dispatch"
PAIR_CLAIM_REQUEST_CONTRACT = "pairling.psk.claim.request.v2"
PAIR_CLAIM_RESULT_CONTRACT = "pairling.psk.claim.result.v2"
PAIR_ACTIVATION_CONTRACT = "pairling.psk.activate.v1"
PAIR_ACTIVATION_RESULT_CONTRACT = "pairling.psk.activate.result.v1"
PAIRING_CONTRACTS = {
    "request": PAIR_CLAIM_REQUEST_CONTRACT,
    "claim_result": PAIR_CLAIM_RESULT_CONTRACT,
    "activation": PAIR_ACTIVATION_CONTRACT,
    "activation_result": PAIR_ACTIVATION_RESULT_CONTRACT,
}

DEFAULT_DEVICE_SCOPES = frozenset({
    "health:read",
    "manifest:read",
    "sessions:read",
    "transcript:read",
    "session:send",
    "session:spawn",
    "session:signal",
    "worker:read",
    "worker:control",
    "llm:route",
    "pairling-tools:run",
    "files:upload",
    "files:read",
    "files:write",
    "files:delete",
    "pair:admin",
    "phone-tools:reverse",
})

SUPPORTED_CONTRACTS = {CONTRACT_VERSION}
