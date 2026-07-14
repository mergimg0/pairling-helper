#!/usr/bin/env python3
"""Runtime manifest loading and verification for the Mac companion daemon."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime_contract import (
    AUTH_MODE,
    COMPAT_MODE,
    CONTRACT_VERSION,
    DAEMON_LABEL,
    PAIR_SERVICE_TYPE,
    PAIRING_CONTRACTS,
    PORT,
    RUNTIME_BONJOUR_ADVERTISED,
    RUNTIME_NAME,
    TAILSCALE_VARIANT,
)
from runtime_paths import pairdrop_root, release_root_for


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


_VERIFY_CACHE_LOCK = threading.Lock()
_VERIFY_CACHE: dict[str, tuple[tuple[int, int, str, str], bool, str | None]] = {}
_VERIFY_CACHE_MAX_ENTRIES = 64


def _runtime_payload_entries(root: Path) -> dict[str, tuple[Path, str, str | None]]:
    entries: dict[str, tuple[Path, str, str | None]] = {}

    def visit(directory: Path) -> None:
        for path in sorted(directory.iterdir(), key=lambda item: item.name):
            rel = path.relative_to(root).as_posix()
            if rel == "manifest.json":
                continue
            if path.is_symlink():
                kind = "symlink"
                target = os.readlink(path)
                entries[rel] = (path, kind, target)
            elif path.is_dir():
                visit(path)
                continue
            elif path.is_file():
                kind = "file"
                target = None
                entries[rel] = (path, kind, target)
            else:
                kind = "unsupported"
                target = None
                entries[rel] = (path, kind, target)

    visit(root)
    return entries


def _payload_inventory_marker(
    entries: dict[str, tuple[Path, str, str | None]],
) -> str:
    """Fingerprint payload identity and mutation metadata without reading bodies."""

    digest = hashlib.sha256()
    for rel in sorted(entries):
        path, kind, target = entries[rel]
        stat = path.lstat()
        row = (
            rel,
            kind,
            target or "",
            stat.st_mode,
            stat.st_size,
            stat.st_mtime_ns,
            stat.st_ctime_ns,
            stat.st_ino,
        )
        digest.update(json.dumps(row, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _verify_runtime_payload(
    root: Path,
    manifest: dict[str, Any],
    manifest_path: Path,
) -> tuple[bool, str | None]:
    try:
        manifest_stat = manifest_path.stat()
        manifest_marker = hashlib.sha256(
            json.dumps(
                manifest,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        actual = _runtime_payload_entries(root)
        inventory_marker = _payload_inventory_marker(actual)
    except Exception as exc:
        return False, f"runtime inventory failed: {type(exc).__name__}: {exc}"

    verification_marker = (
        manifest_stat.st_mtime_ns,
        manifest_stat.st_size,
        manifest_marker,
        inventory_marker,
    )
    cache_key = str(manifest_path.resolve())
    with _VERIFY_CACHE_LOCK:
        cached = _VERIFY_CACHE.get(cache_key)
        if cached and cached[0] == verification_marker:
            return cached[1], cached[2]

    expected: dict[str, dict[str, Any]] = {}
    error: str | None = None
    raw_entries = manifest.get("files")
    if not isinstance(raw_entries, list):
        error = "manifest files is not an array"
    else:
        for item in raw_entries:
            if not isinstance(item, dict):
                error = "manifest contains a non-object file entry"
                break
            rel = item.get("path")
            if (
                not isinstance(rel, str)
                or not rel
                or rel.startswith("/")
                or "\\" in rel
                or any(part in ("", ".", "..") for part in rel.split("/"))
            ):
                error = f"manifest contains unsafe path {rel!r}"
                break
            if rel in expected:
                error = f"manifest contains duplicate path {rel}"
                break
            expected[rel] = item

    if error is None:
        bytecode = sorted(
            rel
            for rel in actual
            if rel.endswith(".pyc") or "__pycache__" in rel.split("/")
        )
        if bytecode:
            error = "runtime contains forbidden Python bytecode: " + ", ".join(bytecode[:5])

    if error is None:
        missing = sorted(set(expected) - set(actual))
        unexpected = sorted(set(actual) - set(expected))
        if missing:
            error = "runtime files missing from disk: " + ", ".join(missing[:5])
        elif unexpected:
            error = "runtime files absent from manifest: " + ", ".join(unexpected[:5])

    if error is None:
        for rel in sorted(expected):
            item = expected[rel]
            path, actual_kind, actual_target = actual[rel]
            expected_kind = item.get("kind") or "file"
            if expected_kind != actual_kind:
                error = f"kind mismatch for {rel}: expected {expected_kind}, got {actual_kind}"
                break
            expected_hash = item.get("sha256")
            if not isinstance(expected_hash, str) or len(expected_hash) != 64:
                error = f"manifest has invalid hash for {rel}"
                break
            if actual_kind == "symlink":
                if item.get("target") != actual_target:
                    error = f"symlink target mismatch for {rel}"
                    break
                actual_hash = hashlib.sha256((actual_target or "").encode("utf-8")).hexdigest()
            elif actual_kind == "file":
                actual_hash = sha256_file(path)
            else:
                error = f"unsupported runtime entry kind for {rel}"
                break
            if actual_hash != expected_hash:
                error = f"hash mismatch for {rel}"
                break

    if error is None:
        try:
            final_inventory_marker = _payload_inventory_marker(
                _runtime_payload_entries(root)
            )
        except Exception as exc:
            error = f"runtime inventory failed: {type(exc).__name__}: {exc}"
        else:
            if final_inventory_marker != inventory_marker:
                error = "runtime payload changed during verification"

    verified = error is None
    with _VERIFY_CACHE_LOCK:
        _VERIFY_CACHE[cache_key] = (
            verification_marker,
            verified,
            error,
        )
        while len(_VERIFY_CACHE) > _VERIFY_CACHE_MAX_ENTRIES:
            _VERIFY_CACHE.pop(next(iter(_VERIFY_CACHE)))
    return verified, error


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
    # Process provenance must come from the executing script. The manifest is
    # data inside that runtime and cannot redirect health checks to another
    # directory by naming a different install_root.
    install_root = str(script.parent.parent) if script.parent.name == "companiond" else str(script.parent)
    source_hash = None
    verified = False
    verification_error = manifest_error

    try:
        source_hash = sha256_file(script)
    except Exception as exc:
        verification_error = f"{type(exc).__name__}: {exc}"

    if manifest is not None:
        runtime_version = str(manifest.get("runtime_version") or runtime_version)
        source_revision = str(manifest.get("source_revision") or source_revision)
        source_branch = str(manifest.get("source_branch") or source_branch)
        if "source_dirty" in manifest:
            source_dirty = bool(manifest.get("source_dirty"))
        installed_at = str(manifest.get("installed_at") or installed_at or "")
    try:
        resolved_pairdrop_root = str(pairdrop_root())
    except (OSError, ValueError):
        resolved_pairdrop_root = None

    if manifest is not None:
        expected_hash = _manifest_file_hash(manifest, relative_path)
        if not expected_hash:
            verification_error = f"manifest missing hash for {relative_path}"
        elif not source_hash or expected_hash != source_hash:
            verification_error = f"hash mismatch for {relative_path}"
        elif manifest_path is not None:
            verified, verification_error = _verify_runtime_payload(
                manifest_path.parent,
                manifest,
                manifest_path,
            )

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
        "pairdrop_root": resolved_pairdrop_root,
    }


def public_runtime_info(info: dict[str, Any]) -> dict[str, Any]:
    """Return the unauthenticated-safe subset of runtime metadata."""
    return {
        "name": info.get("name") or RUNTIME_NAME,
        "runtime_version": info.get("runtime_version"),
        "source_revision": info.get("source_revision"),
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
        "pairing_contracts": dict(PAIRING_CONTRACTS),
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
            "public": ["/health", "/manifest", "/pair/start", "/pair/claim", "/pair/psk-activate", "/pair/psk-claim", "/pair/psk-claim-v2"],
            "authenticated": [
                "/manifest",
                "/sessions",
                "/sessions-stream",
                "/sessions/remove",
                "/sessions/delete-transcript",
                "/compose/recordings/sync",
                "/session-live-events",
                "/session-events-v2",
                "/session-events-v2-raw",
                "/session-events-v2-content",
                "/device-events",
                "/transcript",
                "/transcript-stream",
                "/send-text",
                "/inject-now",
                "/worker-kill",
                "/pairling-tools/run",
                "/phone-tools/activity",
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
