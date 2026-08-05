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

DEVICE_ROLE_READER = "reader"
DEVICE_ROLE_OPERATOR = "operator"
DEVICE_ROLE_INTERNAL = "internal"
DEVICE_ROLE_CUSTOM = "custom"
PAIRABLE_DEVICE_ROLES = frozenset({DEVICE_ROLE_READER, DEVICE_ROLE_OPERATOR})

READER_DEVICE_SCOPES = frozenset({
    "health:read",
    "manifest:read",
    "sessions:read",
    "push:manage",
    "transcript:read",
    "worker:read",
    "files:read",
})

OPERATOR_DEVICE_SCOPES = READER_DEVICE_SCOPES | frozenset({
    "approval:decide",
    "session:send",
    "session:spawn",
    "session:signal",
    "worker:control",
    "provider:control",
    "llm:route",
    "pairling-tools:run",
    "files:upload",
    "files:write",
    "files:delete",
    "pair:admin",
    "phone-tools:reverse",
})
LEGACY_OPERATOR_DEVICE_SCOPES = OPERATOR_DEVICE_SCOPES - frozenset({
    "approval:decide",
    "provider:control",
    "push:manage",
})
MIGRATABLE_OPERATOR_DEVICE_SCOPES = frozenset({
    LEGACY_OPERATOR_DEVICE_SCOPES,
    OPERATOR_DEVICE_SCOPES - frozenset({"provider:control"}),
    OPERATOR_DEVICE_SCOPES - frozenset({"approval:decide", "provider:control"}),
    OPERATOR_DEVICE_SCOPES - frozenset({"provider:control", "push:manage"}),
    OPERATOR_DEVICE_SCOPES - frozenset({"approval:decide"}),
    OPERATOR_DEVICE_SCOPES - frozenset({"push:manage"}),
    OPERATOR_DEVICE_SCOPES,
})
# Ordinary human invitations are Reader unless the local Mac operator
# explicitly selects Operator before minting the invitation.
DEFAULT_DEVICE_ROLE = DEVICE_ROLE_READER
DEFAULT_DEVICE_SCOPES = READER_DEVICE_SCOPES


def device_scopes_for_role(role: str) -> frozenset[str]:
    normalized = str(role or "").strip().lower()
    if normalized == DEVICE_ROLE_READER:
        return READER_DEVICE_SCOPES
    if normalized == DEVICE_ROLE_OPERATOR:
        return OPERATOR_DEVICE_SCOPES
    raise ValueError(f"unsupported paired-device role: {normalized or '<empty>'}")

SUPPORTED_CONTRACTS = {CONTRACT_VERSION}
