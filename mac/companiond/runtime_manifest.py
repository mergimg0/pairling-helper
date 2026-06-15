#!/usr/bin/env python3
"""Runtime manifest loading and verification for the Mac companion daemon."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime_contract import (
    AUTH_MODE,
    COMPAT_MODE,
    CONTRACT_VERSION,
    DAEMON_LABEL,
    PAIR_SERVICE_TYPE,
    PORT,
    RUNTIME_BONJOUR_ADVERTISED,
    RUNTIME_NAME,
    TAILSCALE_VARIANT,
)
from runtime_paths import release_root_for


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_manifest_for(script_path: str | Path) -> tuple[dict[str, Any] | None, Path | None, str | None]:
    root = release_root_for(script_path)
    if root is None:
        return None, None, "manifest not found for script path"
    path = root / "manifest.json"
    try:
        data = json.loads(path.read_text())
    except Exception as exc:
        return None, path, f"{type(exc).__name__}: {exc}"
    if not isinstance(data, dict):
        return None, path, "manifest root is not an object"
    return data, path, None


def _manifest_file_hash(manifest: dict[str, Any], relative_path: str) -> str | None:
    for item in manifest.get("files") or []:
        if isinstance(item, dict) and item.get("path") == relative_path:
            value = item.get("sha256")
            return value if isinstance(value, str) else None
    return None


def build_runtime_info(
    script_path: str | Path,
    *,
    relative_path: str = "companiond/pairlingd.py",
    launchd_label: str = DAEMON_LABEL,
) -> dict[str, Any]:
    script = Path(script_path).resolve()
    manifest, manifest_path, manifest_error = load_manifest_for(script)
    runtime_version = os.environ.get("COMPANION_RUNTIME_VERSION", "legacy")
    source_revision = os.environ.get("COMPANION_SOURCE_REVISION", "unknown")
    source_branch = os.environ.get("COMPANION_SOURCE_BRANCH", "unknown")
    source_dirty = None
    installed_at = os.environ.get("COMPANION_INSTALLED_AT")
    install_root = str(script.parent.parent) if script.parent.name in {"companiond", "guardian"} else str(script.parent)
    source_hash = None
    verified = False
    verification_error = manifest_error

    try:
        source_hash = sha256_file(script)
    except Exception as exc:
        verification_error = f"{type(exc).__name__}: {exc}"

    if manifest:
        runtime_version = str(manifest.get("runtime_version") or runtime_version)
        source_revision = str(manifest.get("source_revision") or source_revision)
        source_branch = str(manifest.get("source_branch") or source_branch)
        if "source_dirty" in manifest:
            source_dirty = bool(manifest.get("source_dirty"))
        installed_at = str(manifest.get("installed_at") or installed_at or "")
        install_root = str(manifest.get("install_root") or install_root)
        expected_hash = _manifest_file_hash(manifest, relative_path)
        if expected_hash and source_hash:
            verified = expected_hash == source_hash
            if not verified:
                verification_error = f"hash mismatch for {relative_path}"
        else:
            verification_error = f"manifest missing hash for {relative_path}"

    return {
        "name": RUNTIME_NAME,
        "runtime_version": runtime_version,
        "contract_version": CONTRACT_VERSION,
        "source_revision": source_revision,
        "source_branch": source_branch,
        "source_dirty": source_dirty,
        "installed_at": installed_at or None,
        "install_root": install_root,
        "compat_mode": COMPAT_MODE,
        "launchd_label": launchd_label,
        "port": PORT,
        "tailscale_variant": TAILSCALE_VARIANT,
        "verified": verified,
        "source_hash": source_hash,
        "manifest_path": str(manifest_path) if manifest_path else None,
        "manifest_error": verification_error,
    }


def public_runtime_info(info: dict[str, Any]) -> dict[str, Any]:
    """Return the unauthenticated-safe subset of runtime metadata."""
    return {
        "name": info.get("name") or RUNTIME_NAME,
        "runtime_version": info.get("runtime_version"),
        "contract_version": info.get("contract_version") or CONTRACT_VERSION,
        "compat_mode": info.get("compat_mode") or COMPAT_MODE,
        "launchd_label": info.get("launchd_label") or DAEMON_LABEL,
        "port": info.get("port") or PORT,
        "tailscale_variant": info.get("tailscale_variant") or TAILSCALE_VARIANT,
        "verified": bool(info.get("verified")),
    }


def build_manifest_payload(
    runtime_info: dict[str, Any],
    *,
    authenticated: bool,
    device_id: str | None = None,
    scopes: list[str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ok": True,
        "schema_version": 1,
        "contract_version": CONTRACT_VERSION,
        "runtime": public_runtime_info(runtime_info),
        "auth": {
            "mode": AUTH_MODE,
            "required": True,
            "legacy_global_token": False,
            "authenticated": authenticated,
        },
        "network": {
            "runtime_port": PORT,
            "pair_service_type": PAIR_SERVICE_TYPE,
            "runtime_bonjour_advertised": RUNTIME_BONJOUR_ADVERTISED,
            "route_diagnostics": {
                "bonjour": {
                    "service_type": PAIR_SERVICE_TYPE,
                    "runtime_port": PORT,
                    "txt_version": "2",
                },
                "tailnet": {
                    "variant": TAILSCALE_VARIANT,
                },
            },
        },
        "endpoints": {
            "public": ["/health", "/manifest", "/pair/start", "/pair/claim", "/pair/psk-claim"],
            "authenticated": [
                "/manifest",
                "/sessions",
                "/sessions-stream",
                "/session-live-events",
                "/transcript",
                "/transcript-stream",
                "/send-text",
                "/inject-now",
                "/worker-kill",
                "/pairling-tools/run",
                "/phone-tools/availability",
                "/phone-tools/next",
                "/phone-tools/result",
                "/sentinel/status",
                "/sentinel/preferences",
                "/sentinel/snooze",
                "/sentinel/evaluate-now",
                "/sentinel/events",
                "/pair/revoke",
                "/pair/rotate-token",
            ],
        },
    }
    if authenticated:
        payload["runtime"] = runtime_info
        payload["auth"]["device_id"] = device_id
        payload["auth"]["scopes"] = sorted(scopes or [])
    return payload
