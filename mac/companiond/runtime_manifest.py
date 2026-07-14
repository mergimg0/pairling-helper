#!/usr/bin/env python3
"""Runtime manifest loading and verification for the Mac companion daemon."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import stat
import sys
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
    if path.is_symlink():
        return None, path, "manifest must not be a symlink"
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
_VERIFY_CACHE: dict[str, tuple[tuple[int, int, str, str, str], bool, str | None]] = {}
_VERIFY_CACHE_MAX_ENTRIES = 64


def _runtime_payload_entries(root: Path) -> dict[str, tuple[Path, str, str | None, str]]:
    if root.is_symlink() or not root.is_dir():
        raise OSError(f"runtime release root is not a real directory: {root}")
    entries: dict[str, tuple[Path, str, str | None, str]] = {}

    def visit(directory: Path) -> None:
        for path in sorted(directory.iterdir(), key=lambda item: item.name):
            rel = path.relative_to(root).as_posix()
            if rel == "manifest.json":
                continue
            metadata = path.lstat()
            mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
            if stat.S_ISLNK(metadata.st_mode):
                kind = "symlink"
                target = os.readlink(path)
                entries[rel] = (path, kind, target, mode)
            elif stat.S_ISDIR(metadata.st_mode):
                visit(path)
                continue
            elif stat.S_ISREG(metadata.st_mode):
                kind = "file"
                target = None
                entries[rel] = (path, kind, target, mode)
            else:
                kind = "unsupported"
                target = None
                entries[rel] = (path, kind, target, mode)

    visit(root)
    return entries


def _runtime_directory_entries(root: Path) -> dict[str, str]:
    if root.is_symlink() or not root.is_dir():
        raise OSError(f"runtime release root is not a real directory: {root}")
    directories: dict[str, str] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            directories[path.relative_to(root).as_posix()] = f"{stat.S_IMODE(metadata.st_mode):04o}"
    return directories


def _payload_inventory_marker(
    entries: dict[str, tuple[Path, str, str | None, str]],
) -> str:
    """Fingerprint payload identity and mutation metadata without reading bodies."""

    digest = hashlib.sha256()
    for rel in sorted(entries):
        path, kind, target, mode = entries[rel]
        metadata = path.lstat()
        row = (
            rel,
            kind,
            target or "",
            mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            metadata.st_ino,
        )
        digest.update(json.dumps(row, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _release_seal_marker(root: Path) -> tuple[str, list[str]]:
    digest = hashlib.sha256()
    writable: list[str] = []
    paths = [root, *sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())]
    for path in paths:
        metadata = path.lstat()
        if path.is_symlink():
            continue
        relative = "." if path == root else path.relative_to(root).as_posix()
        mode = metadata.st_mode & 0o7777
        digest.update(f"{relative}\0{mode:04o}\0{metadata.st_ctime_ns}\n".encode("utf-8"))
        if mode & 0o222:
            writable.append(relative)
    return digest.hexdigest(), writable


def _extended_acl_paths(root: Path) -> list[str]:
    if sys.platform != "darwin":
        return []
    libc = ctypes.CDLL(None, use_errno=True)
    libc.acl_get_file.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.acl_get_file.restype = ctypes.c_void_p
    libc.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    libc.acl_get_entry.restype = ctypes.c_int
    libc.acl_free.argtypes = [ctypes.c_void_p]
    libc.acl_free.restype = ctypes.c_int

    found: list[str] = []
    paths = [root, *sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())]
    for path in paths:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            continue
        ctypes.set_errno(0)
        acl = libc.acl_get_file(os.fsencode(path), 0x00000100)
        if not acl:
            error = ctypes.get_errno()
            if error in (0, errno.ENOENT):
                continue
            raise OSError(error, os.strerror(error), path)
        try:
            entry = ctypes.c_void_p()
            if libc.acl_get_entry(acl, 0, ctypes.byref(entry)) == 0:
                found.append("." if path == root else path.relative_to(root).as_posix())
        finally:
            libc.acl_free(acl)
    return found


def classify_ptybroker_identity(
    live: object,
    desired: dict[str, Any],
) -> tuple[str, list[str]]:
    """Classify whether a live broker can be preserved during activation."""

    if not isinstance(live, dict):
        return "incompatible", ["status_not_object"]
    reasons: list[str] = []
    live_root = live.get("runtime_root")
    if live_root:
        if os.path.realpath(str(live_root)) != str(desired.get("runtime_root") or ""):
            reasons.append("runtime_root_mismatch")
    else:
        reasons.append("runtime_root_missing")
    live_script = live.get("script_path")
    if live_script:
        if os.path.realpath(str(live_script)) != str(desired.get("script_path") or ""):
            reasons.append("script_path_mismatch")
    else:
        reasons.append("script_path_missing")
    live_revision = live.get("source_revision")
    desired_revision = desired.get("source_revision")
    if desired_revision and not live_revision:
        reasons.append("source_revision_missing")
    elif live_revision and desired_revision and str(live_revision) != str(desired_revision):
        reasons.append("source_revision_mismatch")
    try:
        live_protocol = int(live.get("protocol_version") or 0)
    except (TypeError, ValueError):
        live_protocol = 0
    if live_protocol != int(desired.get("protocol_version") or 0):
        reasons.append("protocol_version_missing" if not live.get("protocol_version") else "protocol_version_mismatch")
    pid = live.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        reasons.append("pid_missing")
    live_session_count = live.get("live_session_count")
    if (
        not isinstance(live_session_count, int)
        or isinstance(live_session_count, bool)
        or live_session_count < 0
    ):
        reasons.append("live_session_count_missing")
    fatal_reasons = {
        "status_not_object",
        "runtime_root_missing",
        "script_path_missing",
        "source_revision_missing",
        "protocol_version_missing",
        "protocol_version_mismatch",
        "pid_missing",
        "live_session_count_missing",
    }
    if fatal_reasons.intersection(reasons):
        return "incompatible", reasons
    return ("stale_deferred", reasons) if reasons else ("current", reasons)


def _verify_runtime_payload(
    root: Path,
    manifest: dict[str, Any],
    manifest_path: Path,
) -> tuple[bool, str | None]:
    if root.is_symlink() or not root.is_dir():
        return False, "runtime release root must be a real directory"
    if manifest_path.is_symlink():
        return False, "runtime manifest must not be a symlink"
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
        actual_directories = _runtime_directory_entries(root)
        inventory_marker = _payload_inventory_marker(actual)
        seal_marker, writable = _release_seal_marker(root)
    except Exception as exc:
        return False, f"runtime inventory failed: {type(exc).__name__}: {exc}"

    verification_marker = (
        manifest_stat.st_mtime_ns,
        manifest_stat.st_size,
        manifest_marker,
        inventory_marker,
        seal_marker,
    )
    cache_key = str(manifest_path.resolve())
    with _VERIFY_CACHE_LOCK:
        cached = _VERIFY_CACHE.get(cache_key)
        if cached and cached[0] == verification_marker:
            return cached[1], cached[2]

    expected: dict[str, dict[str, Any]] = {}
    expected_directories: dict[str, str] = {}
    error: str | None = None
    if manifest.get("schema_version") != 2:
        error = "unsupported runtime manifest schema"
    root_mode = f"{stat.S_IMODE(root.lstat().st_mode):04o}"
    manifest_mode = f"{stat.S_IMODE(manifest_path.lstat().st_mode):04o}"
    if error is None and manifest.get("root_mode") != root_mode:
        error = "runtime release root mode does not match manifest"
    if error is None and manifest.get("manifest_mode") != manifest_mode:
        error = "runtime manifest mode does not match manifest"
    raw_entries = manifest.get("files")
    if error is None and not isinstance(raw_entries, list):
        error = "manifest files is not an array"
    elif error is None:
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
            kind = item.get("kind") or "file"
            mode = item.get("mode")
            if kind != "file":
                error = f"manifest contains unsupported runtime entry kind for {rel}"
                break
            if not isinstance(mode, str) or len(mode) != 4 or any(char not in "01234567" for char in mode):
                error = f"manifest has invalid mode for {rel}"
                break
            expected[rel] = item

    raw_directories = manifest.get("directories")
    if error is None and not isinstance(raw_directories, list):
        error = "manifest directories is not an array"
    elif error is None:
        for item in raw_directories:
            if not isinstance(item, dict):
                error = "manifest contains a non-object directory entry"
                break
            rel = item.get("path")
            mode = item.get("mode")
            if (
                not isinstance(rel, str)
                or not rel
                or rel.startswith("/")
                or "\\" in rel
                or any(part in ("", ".", "..") for part in rel.split("/"))
            ):
                error = f"manifest contains unsafe directory path {rel!r}"
                break
            if rel in expected_directories:
                error = f"manifest contains duplicate directory path {rel}"
                break
            if not isinstance(mode, str) or len(mode) != 4 or any(char not in "01234567" for char in mode):
                error = f"manifest has invalid directory mode for {rel}"
                break
            expected_directories[rel] = mode

    if error is None:
        if writable:
            error = "runtime release contains writable entries: " + ", ".join(writable[:5])

    if error is None:
        try:
            acl_paths = _extended_acl_paths(root)
        except Exception as exc:
            error = f"runtime ACL inventory failed: {type(exc).__name__}: {exc}"
        else:
            if acl_paths:
                error = "runtime release contains extended ACLs: " + ", ".join(acl_paths[:5])

    if error is None:
        forbidden_directories = sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.name == "__pycache__"
        )
        bytecode = sorted(
            rel
            for rel in actual
            if rel.endswith(".pyc") or "__pycache__" in rel.split("/")
        )
        if bytecode:
            error = "runtime contains forbidden Python bytecode: " + ", ".join(bytecode[:5])
        elif forbidden_directories:
            error = "runtime contains forbidden Python bytecode cache directories: " + ", ".join(forbidden_directories[:5])

    if error is None:
        missing_directories = sorted(set(expected_directories) - set(actual_directories))
        unexpected_directories = sorted(set(actual_directories) - set(expected_directories))
        if missing_directories:
            error = "runtime directories missing from disk: " + ", ".join(missing_directories[:5])
        elif unexpected_directories:
            error = "runtime directories absent from manifest: " + ", ".join(unexpected_directories[:5])

    if error is None:
        for rel in sorted(expected_directories):
            if expected_directories[rel] != actual_directories[rel]:
                error = (
                    f"directory mode mismatch for {rel}: expected "
                    f"{expected_directories[rel]}, got {actual_directories[rel]}"
                )
                break

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
            path, actual_kind, actual_target, actual_mode = actual[rel]
            expected_kind = item.get("kind") or "file"
            if expected_kind != actual_kind:
                error = f"kind mismatch for {rel}: expected {expected_kind}, got {actual_kind}"
                break
            expected_hash = item.get("sha256")
            if (
                not isinstance(expected_hash, str)
                or len(expected_hash) != 64
                or any(char not in "0123456789abcdef" for char in expected_hash.lower())
            ):
                error = f"manifest has invalid hash for {rel}"
                break
            if item.get("mode") != actual_mode:
                error = f"mode mismatch for {rel}: expected {item.get('mode')}, got {actual_mode}"
                break
            if actual_kind == "file":
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
            final_seal_marker, final_writable = _release_seal_marker(root)
            final_acl_paths = _extended_acl_paths(root)
        except Exception as exc:
            error = f"runtime inventory failed: {type(exc).__name__}: {exc}"
        else:
            if final_inventory_marker != inventory_marker:
                error = "runtime payload changed during verification"
            elif final_seal_marker != seal_marker:
                error = "runtime release permissions changed during verification"
            elif final_writable:
                error = "runtime release contains writable entries: " + ", ".join(final_writable[:5])
            elif final_acl_paths:
                error = "runtime release contains extended ACLs: " + ", ".join(final_acl_paths[:5])

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


def verified_managed_release_identity(
    target: str | Path,
    releases_root: str | Path,
) -> dict[str, Any]:
    """Load one rollback-eligible release and prove its complete identity."""

    target_path = Path(target)
    releases_path = Path(releases_root)
    if not target_path.is_absolute():
        raise ValueError("release target must be absolute")
    if releases_path.is_symlink() or not releases_path.is_dir():
        raise ValueError("managed releases root must be a real directory")
    resolved_releases = releases_path.resolve(strict=True)
    lexical_target = target_path.parent.resolve(strict=True) / target_path.name
    if lexical_target.parent != resolved_releases:
        raise ValueError("release target must be a direct child of the managed releases directory")
    if target_path.is_symlink() or not target_path.is_dir():
        raise ValueError("release target must be a real directory")
    resolved_target = target_path.resolve(strict=True)
    if lexical_target != resolved_target:
        raise ValueError("release target names a linked or aliased directory")

    manifest_path = resolved_target / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("release manifest must be a real file")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"release manifest cannot be read: {type(exc).__name__}: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 2:
        raise ValueError("release is not rollback eligible: schema 2 manifest required")

    install_root = Path(str(manifest.get("install_root") or ""))
    if not install_root.is_absolute():
        raise ValueError("release manifest install_root must be absolute")
    manifest_lexical_root = install_root.parent.resolve(strict=True) / install_root.name
    if manifest_lexical_root != resolved_target:
        raise ValueError("release manifest install_root does not match the selected release")

    verified, error = _verify_runtime_payload(resolved_target, manifest, manifest_path)
    if not verified:
        raise ValueError(error or "release manifest verification failed")

    def stamp(relative: str) -> str:
        path = resolved_target / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"release identity stamp is missing or linked: {relative}")
        return path.read_text(encoding="utf-8").strip()

    version = stamp("mac/VERSION")
    revision = stamp("mac/SOURCE_REVISION")
    dirty_text = stamp("mac/SOURCE_DIRTY").lower()
    if dirty_text not in {"true", "false"}:
        raise ValueError("release SOURCE_DIRTY stamp is invalid")
    dirty = dirty_text == "true"
    if manifest.get("runtime_version") != version:
        raise ValueError("release version stamp does not match its manifest")
    if manifest.get("source_revision") != revision:
        raise ValueError("release revision stamp does not match its manifest")
    if manifest.get("source_dirty") is not dirty:
        raise ValueError("release source state stamp does not match its manifest")
    return {
        "root": str(resolved_target),
        "runtime_version": version,
        "source_revision": revision,
        "source_dirty": dirty,
    }


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
