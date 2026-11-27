#!/usr/bin/env python3
"""Immutable source identities for staged provider runtime assets."""

from __future__ import annotations

from pathlib import Path


PROVIDER_RUNTIME_ASSETS = (
    (
        "claude_agent_sidecar.mjs",
        "b954174325421c182fb961af57109facb929b76fc3ce51010ab05f87695e22f9",
    ),
    (
        "copilot_sdk_sidecar.mjs",
        "56a172ac502c7d160c0b3b5c042db2187ed6a1e04aa80501f285bf554c92ce27",
    ),
    (
        "qwen_sdk_sidecar.mjs",
        "342a99ddba666f0f227d46885d47c0f0e1c2d1256de193d7706d7b8dcb5db2bc",
    ),
    (
        "gemini-seatbelt.sb",
        "c7e33f2d243ec3d1579488aff4e7e437449322e4750aa0f53abf78f33b197425",
    ),
    (
        "omp_ask_extension.mjs",
        "e823e6a71f16bd66e32b387bf03de39b1f8940c8f9d4ace966a7811345485dfb",
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
