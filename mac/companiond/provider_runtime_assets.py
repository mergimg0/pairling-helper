#!/usr/bin/env python3
"""Immutable source identities for staged provider runtime assets."""

from __future__ import annotations

from pathlib import Path


PROVIDER_RUNTIME_ASSETS = (
    (
        "claude_agent_sidecar.mjs",
        "4c27ae18ff7553b4587562e24ce7c7ada3c80c8e382c0363953b71a60f1846fc",
    ),
    (
        "copilot_sdk_sidecar.mjs",
        "46336ebe88a38f9b29d88175d61e4ac8f68bd6fc6c3a9ae8c9ca9ad9a5186275",
    ),
    (
        "qwen_sdk_sidecar.mjs",
        "2027f817fcf2774fd50a7fa753895dc92049ce9e63c47aebd6d7a95ddbbae924",
    ),
    (
        "gemini-seatbelt.sb",
        "c7e33f2d243ec3d1579488aff4e7e437449322e4750aa0f53abf78f33b197425",
    ),
)
PROVIDER_RUNTIME_ASSET_DIGESTS = dict(PROVIDER_RUNTIME_ASSETS)
PROVIDER_RUNTIME_ASSET_NAMES = tuple(PROVIDER_RUNTIME_ASSET_DIGESTS)
PROVIDER_RUNTIME_ASSET_RELATIVE_PATHS = tuple(
    f"{directory}/{name}"
    for directory in ("companiond/providers", "mac/companiond/providers")
    for name in PROVIDER_RUNTIME_ASSET_NAMES
)
PROVIDER_RUNTIME_ASSET_DIRECTORIES = frozenset(
    Path(relative).parent.as_posix()
    for relative in PROVIDER_RUNTIME_ASSET_RELATIVE_PATHS
)
