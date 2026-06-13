#!/usr/bin/env python3
"""Manifest metadata helpers for the privileged power guardian."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
CONTRACT_VERSION = "pairling-runtime-v1"
GUARDIAN_LABEL = "dev.pairling.power-guardian"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_guardian_info(script_path: str | Path) -> dict[str, Any]:
    script = Path(script_path).resolve()
    root = script.parent.parent if script.parent.name == "guardian" else None
    manifest_path = root / "manifest.json" if root else None
    runtime_version = os.environ.get("COMPANION_RUNTIME_VERSION", "legacy")
    source_revision = os.environ.get("COMPANION_SOURCE_REVISION", "unknown")
    source_hash = None
    verified = False
    manifest_error = "manifest not found for script path"

    try:
        source_hash = sha256_file(script)
    except Exception as exc:
        manifest_error = f"{type(exc).__name__}: {exc}"

    if manifest_path and manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text())
            runtime_version = str(manifest.get("runtime_version") or runtime_version)
            source_revision = str(manifest.get("source_revision") or source_revision)
            expected_hash = None
            for item in manifest.get("files") or []:
                if isinstance(item, dict) and item.get("path") == "guardian/companion-power-guardian.py":
                    expected_hash = item.get("sha256")
                    break
            if expected_hash and source_hash:
                verified = expected_hash == source_hash
                manifest_error = None if verified else "hash mismatch for guardian/companion-power-guardian.py"
            else:
                manifest_error = "manifest missing hash for guardian/companion-power-guardian.py"
        except Exception as exc:
            manifest_error = f"{type(exc).__name__}: {exc}"

    return {
        "runtime_version": runtime_version,
        "contract_version": CONTRACT_VERSION,
        "source_revision": source_revision,
        "launchd_label": GUARDIAN_LABEL,
        "verified": verified,
        "source_hash": source_hash,
        "manifest_path": str(manifest_path) if manifest_path else None,
        "manifest_error": manifest_error,
    }
