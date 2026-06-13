#!/usr/bin/env python3
"""Local credential provisioning for the Pairling MCP bridge."""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any

from pairling_devices import DeviceRegistry, load_or_create_install_id, utc_epoch
from runtime_paths import app_support_root


LOCAL_MCP_DEVICE_NAME = "Pairling MCP Bridge"
LOCAL_MCP_SCOPE = "pairling-tools:run"


def mcp_bridge_credential_path() -> Path:
    return Path(
        os.environ.get(
            "PAIRLING_MCP_CREDENTIAL",
            str(app_support_root() / "mcp-bridge.json"),
        )
    )


def _pairling_install_id() -> str:
    config = app_support_root() / "config.json"
    try:
        payload = json.loads(config.read_text())
        value = payload.get("install_id")
        if isinstance(value, str) and value.strip():
            return value.strip()
    except Exception:
        pass
    return load_or_create_install_id()


def ensure_local_mcp_bridge_device(
    *,
    registry: DeviceRegistry | None = None,
    credential_path: Path | None = None,
    install_id: str | None = None,
) -> dict[str, Any]:
    target = credential_path or mcp_bridge_credential_path()
    device_registry = registry or DeviceRegistry()
    install_id_value = install_id or _pairling_install_id()

    existing = _read_credential(target)
    if existing:
        token = str(existing.get("token") or "")
        auth = device_registry.authenticate(
            token,
            required_scopes=[LOCAL_MCP_SCOPE],
            path="/pairling-tools/run",
        )
        if auth.ok and str(auth.install_id or "") == install_id_value:
            normalized = {
                "device_id": auth.device_id or str(existing.get("device_id") or ""),
                "install_id": install_id_value,
                "token": token,
                "proof_secret": auth.proof_secret or str(existing.get("proof_secret") or ""),
                "scopes": sorted(auth.scopes or {LOCAL_MCP_SCOPE}),
                "created_at": float(existing.get("created_at") or utc_epoch()),
            }
            _write_private_json(target, normalized)
            return normalized
        stale_device_id = str(existing.get("device_id") or "")
        if stale_device_id:
            device_registry.revoke_device(stale_device_id, reason="local_mcp_bridge_invalid")

    if hasattr(device_registry, "revoke_devices_named"):
        device_registry.revoke_devices_named(LOCAL_MCP_DEVICE_NAME, reason="local_mcp_bridge_rotated")

    created = device_registry.create_device(
        device_name=LOCAL_MCP_DEVICE_NAME,
        scopes=[LOCAL_MCP_SCOPE],
        install_id=install_id_value,
        device_id="dev_local_mcp_" + secrets.token_hex(12),
    )
    credential = {
        "device_id": created.device_id,
        "install_id": created.install_id,
        "token": created.token,
        "proof_secret": created.proof_secret,
        "scopes": list(created.scopes),
        "created_at": utc_epoch(),
    }
    _write_private_json(target, credential)
    return credential


def validate_local_mcp_bridge_credential(
    *,
    registry: DeviceRegistry | None = None,
    credential_path: Path | None = None,
    install_id: str | None = None,
) -> tuple[bool, str]:
    target = credential_path or mcp_bridge_credential_path()
    credential = _read_credential(target)
    if credential is None:
        return False, f"credential missing or unreadable: {target}"
    expected_install_id = install_id or _pairling_install_id()
    if str(credential.get("install_id") or "") != expected_install_id:
        return False, "credential install_id does not match this Mac"
    directory_mode = target.parent.stat().st_mode & 0o777
    file_mode = target.stat().st_mode & 0o777
    if directory_mode & 0o077:
        return False, f"credential directory is not private: {oct(directory_mode)}"
    if file_mode & 0o077:
        return False, f"credential file is not private: {oct(file_mode)}"
    token = str(credential.get("token") or "")
    auth = (registry or DeviceRegistry()).authenticate(
        token,
        required_scopes=[LOCAL_MCP_SCOPE],
        path="/pairling-tools/run",
    )
    if not auth.ok:
        return False, f"credential rejected: {auth.reason}"
    if str(auth.install_id or "") != expected_install_id:
        return False, "credential registry install_id does not match this Mac"
    return True, str(target)


def _read_credential(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text())
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    required = ("device_id", "install_id", "token", "proof_secret")
    if not all(str(payload.get(key) or "").strip() for key in required):
        return None
    return payload


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions - credential directory must be user-only.
    except OSError:
        pass
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
