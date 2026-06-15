#!/usr/bin/env python3
"""Shared constants for the Pairling Mac runtime."""

from __future__ import annotations

import os

SCHEMA_VERSION = 1
POWER_STATE_SCHEMA_VERSION = 1
RUNTIME_NAME = "pairling-mac-runtime"
CONTRACT_VERSION = "pairling-runtime-v1"
PAIRLING_CONTRACT_VERSION = CONTRACT_VERSION
COMPAT_MODE = "pairling-v1"
PORT = int(os.environ.get("PAIRLING_RUNTIME_PORT", "7773"))
LEGACY_PORT = 7723
DAEMON_LABEL = "dev.pairling.companiond"
GUARDIAN_LABEL = "dev.pairling.power-guardian"
LEGACY_TOKEN_RELATIVE_PATH = ".claude/scripts/.notify-token"
POWER_STATE_PATH = "/var/run/pairling-power-state.json"
TAILSCALE_VARIANT = "standalone"
AUTH_MODE = "scoped-device-bearer"
PAIR_SERVICE_TYPE = "_pairling-pair._tcp"
RUNTIME_BONJOUR_ADVERTISED = False

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
