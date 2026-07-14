#!/usr/bin/env python3
"""Local credential provisioning for the Pairling MCP bridge."""

from __future__ import annotations

import fcntl
import json
import math
import os
import secrets
import stat
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from pairling_devices import (
    LOCAL_MCP_DEVICE_PURPOSE,
    DeviceRegistry,
    normalize_install_id,
    resolve_install_id,
    utc_epoch,
)
from runtime_contract import LOCAL_MCP_DISPATCH_SCOPE
from runtime_paths import app_support_root


LOCAL_MCP_DEVICE_NAME = "Pairling MCP Bridge"
LOCAL_MCP_SCOPE = "pairling-tools:run"
LOCAL_MCP_SCOPES = frozenset({LOCAL_MCP_SCOPE, LOCAL_MCP_DISPATCH_SCOPE})
LOCAL_MCP_CREDENTIAL_FILENAME = "mcp-bridge.json"
LOCAL_MCP_LOCK_FILENAME = ".mcp-bridge.lock"
LOCAL_MCP_LEGACY_SCOPE_SETS = (
    frozenset({LOCAL_MCP_SCOPE}),
    LOCAL_MCP_SCOPES,
)
_LOCAL_MCP_PROCESS_LOCK = threading.RLock()


class LocalMCPCredentialPathError(RuntimeError):
    pass


def mcp_bridge_credential_path() -> Path:
    return Path(
        os.environ.get(
            "PAIRLING_MCP_CREDENTIAL",
            str(app_support_root() / LOCAL_MCP_CREDENTIAL_FILENAME),
        )
    )


def _pairling_install_id() -> str:
    return resolve_install_id(app_support_root())


def migrate_legacy_local_mcp_bridge_identity(
    *,
    registry: DeviceRegistry | None = None,
    credential_path: Path | None = None,
) -> bool:
    """Tag only the legacy bridge row proven by its on-disk bearer token."""
    device_registry = registry or DeviceRegistry()
    try:
        target, trusted_root = _credential_context(
            credential_path or mcp_bridge_credential_path(),
            device_registry,
        )
        with _credential_transaction_lock(target, trusted_root=trusted_root):
            return _migrate_legacy_local_mcp_bridge_identity_locked(
                registry=device_registry,
                target=target,
                trusted_root=trusted_root,
            )
    except LocalMCPCredentialPathError:
        return False


def _migrate_legacy_local_mcp_bridge_identity_locked(
    *,
    registry: DeviceRegistry,
    target: Path,
    trusted_root: Path,
) -> bool:
    try:
        credential = _read_credential(target, trusted_root=trusted_root)
    except LocalMCPCredentialPathError:
        return False
    if credential is None:
        return False
    return registry.canonicalize_legacy_device_for_credential(
        token=str(credential.get("token") or ""),
        credential_device_id=str(credential.get("device_id") or ""),
        credential_install_id=str(credential.get("install_id") or ""),
        device_name=LOCAL_MCP_DEVICE_NAME,
        accepted_scope_sets=LOCAL_MCP_LEGACY_SCOPE_SETS,
        purpose=LOCAL_MCP_DEVICE_PURPOSE,
        reason="local_mcp_bridge_legacy_duplicate",
    )


def _active_local_mcp_bridge_ids(registry: DeviceRegistry) -> tuple[str, ...]:
    if hasattr(registry, "active_device_ids_for_purpose_or_legacy_shape"):
        return registry.active_device_ids_for_purpose_or_legacy_shape(
            purpose=LOCAL_MCP_DEVICE_PURPOSE,
            device_name=LOCAL_MCP_DEVICE_NAME,
            accepted_scope_sets=LOCAL_MCP_LEGACY_SCOPE_SETS,
        )
    if hasattr(registry, "active_device_ids_for_purpose"):
        return registry.active_device_ids_for_purpose(LOCAL_MCP_DEVICE_PURPOSE)
    return ()


def ensure_local_mcp_bridge_device(
    *,
    registry: DeviceRegistry | None = None,
    credential_path: Path | None = None,
    install_id: str | None = None,
    planned_device_id: str | None = None,
    planned_token: str | None = None,
    planned_proof_secret: str | None = None,
) -> dict[str, Any]:
    device_registry = registry or DeviceRegistry()
    target, trusted_root = _credential_context(
        credential_path or mcp_bridge_credential_path(),
        device_registry,
    )
    with _credential_transaction_lock(target, trusted_root=trusted_root):
        return _ensure_local_mcp_bridge_device_locked(
            device_registry=device_registry,
            target=target,
            trusted_root=trusted_root,
            install_id=install_id,
            planned_device_id=planned_device_id,
            planned_token=planned_token,
            planned_proof_secret=planned_proof_secret,
        )


def _ensure_local_mcp_bridge_device_locked(
    *,
    device_registry: DeviceRegistry,
    target: Path,
    trusted_root: Path,
    install_id: str | None,
    planned_device_id: str | None,
    planned_token: str | None,
    planned_proof_secret: str | None,
) -> dict[str, Any]:
    planned_values = (planned_device_id, planned_token, planned_proof_secret)
    if any(value is not None for value in planned_values):
        if not all(isinstance(value, str) and value for value in planned_values):
            raise ValueError("planned local MCP identity must provide all credential values")
        if (
            not str(planned_device_id).startswith("dev_local_mcp_")
            or not str(planned_token).startswith("pld_")
            or not str(planned_proof_secret).startswith("prf_")
        ):
            raise ValueError("planned local MCP identity has an invalid format")
    install_id_value = (
        _pairling_install_id()
        if install_id is None
        else normalize_install_id(install_id)
    )
    if not install_id_value:
        raise ValueError("install_id must be a nonblank string")
    parent_fd = _open_credential_parent(
        target,
        trusted_root=trusted_root,
        create=True,
    )
    if parent_fd is None:
        raise LocalMCPCredentialPathError(
            f"credential directory could not be created safely: {target.parent}"
        )
    os.close(parent_fd)

    _migrate_legacy_local_mcp_bridge_identity_locked(
        registry=device_registry,
        target=target,
        trusted_root=trusted_root,
    )

    existing = _read_credential(target, trusted_root=trusted_root)
    stale_authenticated_device_id = ""
    if existing:
        token = str(existing.get("token") or "")
        auth = device_registry.authenticate(
            token,
            required_scopes=LOCAL_MCP_SCOPES,
            path="/pairling-tools/run",
        )
        token_proves_bridge = (
            bool(auth.device_id)
            and str(auth.install_id or "") == install_id_value
            and LOCAL_MCP_SCOPE in auth.scopes
        )
        if token_proves_bridge:
            stale_authenticated_device_id = str(auth.device_id or "")
            if hasattr(device_registry, "bind_device_purpose_if_named"):
                device_registry.bind_device_purpose_if_named(
                    stale_authenticated_device_id,
                    LOCAL_MCP_DEVICE_NAME,
                    LOCAL_MCP_DEVICE_PURPOSE,
                )
        active_bridge_ids = _active_local_mcp_bridge_ids(device_registry)
        if (
            auth.ok
            and str(auth.install_id or "") == install_id_value
            and active_bridge_ids == (str(auth.device_id or ""),)
        ):
            normalized = {
                "device_id": auth.device_id or str(existing.get("device_id") or ""),
                "install_id": install_id_value,
                "token": token,
                "proof_secret": auth.proof_secret or str(existing.get("proof_secret") or ""),
                "scopes": sorted(auth.scopes or LOCAL_MCP_SCOPES),
                "created_at": _valid_created_at(existing.get("created_at")),
            }
            _write_private_json(
                target,
                normalized,
                trusted_root=trusted_root,
            )
            return normalized
    created = device_registry.create_device(
        device_name=LOCAL_MCP_DEVICE_NAME,
        scopes=LOCAL_MCP_SCOPES,
        install_id=install_id_value,
        device_id=planned_device_id or "dev_local_mcp_" + secrets.token_hex(12),
        token=planned_token,
        proof_secret=planned_proof_secret,
        purpose=LOCAL_MCP_DEVICE_PURPOSE,
    )
    credential = {
        "device_id": created.device_id,
        "install_id": created.install_id,
        "token": created.token,
        "proof_secret": created.proof_secret,
        "scopes": list(created.scopes),
        "created_at": utc_epoch(),
    }

    def retire_previous_bridges() -> None:
        if stale_authenticated_device_id and hasattr(
            device_registry,
            "revoke_device_if_named",
        ):
            device_registry.revoke_device_if_named(
                stale_authenticated_device_id,
                LOCAL_MCP_DEVICE_NAME,
                reason="local_mcp_bridge_rotated",
            )
        canonicalized = device_registry.canonicalize_legacy_device_for_credential(
            token=created.token,
            credential_device_id=created.device_id,
            credential_install_id=created.install_id,
            device_name=LOCAL_MCP_DEVICE_NAME,
            accepted_scope_sets=LOCAL_MCP_LEGACY_SCOPE_SETS,
            purpose=LOCAL_MCP_DEVICE_PURPOSE,
            reason="local_mcp_bridge_rotated",
        )
        if not canonicalized:
            raise RuntimeError(
                "new local MCP bridge credential could not be canonicalized"
            )
        if hasattr(device_registry, "revoke_devices_by_purpose_except"):
            device_registry.revoke_devices_by_purpose_except(
                LOCAL_MCP_DEVICE_PURPOSE,
                created.device_id,
                reason="local_mcp_bridge_rotated",
            )

    try:
        _write_private_json(
            target,
            credential,
            trusted_root=trusted_root,
        )
    except BaseException:
        if _credential_matches_payload(
            target,
            credential,
            trusted_root=trusted_root,
        ):
            try:
                retire_previous_bridges()
            except Exception:
                pass
        else:
            try:
                device_registry.revoke_device(
                    created.device_id,
                    reason="local_mcp_bridge_credential_write_failed",
                )
            except Exception:
                pass
        raise
    retire_previous_bridges()
    return credential


def validate_local_mcp_bridge_credential(
    *,
    registry: DeviceRegistry | None = None,
    credential_path: Path | None = None,
    install_id: str | None = None,
) -> tuple[bool, str]:
    device_registry = registry or DeviceRegistry()
    try:
        target, trusted_root = _credential_context(
            credential_path or mcp_bridge_credential_path(),
            device_registry,
        )
        with _credential_transaction_lock(target, trusted_root=trusted_root):
            return _validate_local_mcp_bridge_credential_locked(
                device_registry=device_registry,
                target=target,
                trusted_root=trusted_root,
                install_id=install_id,
            )
    except LocalMCPCredentialPathError as exc:
        return False, str(exc)


def _validate_local_mcp_bridge_credential_locked(
    *,
    device_registry: DeviceRegistry,
    target: Path,
    trusted_root: Path,
    install_id: str | None,
) -> tuple[bool, str]:
    credential = _read_credential(target, trusted_root=trusted_root)
    if credential is None:
        return False, f"credential missing or unreadable: {target}"
    expected_install_id = (
        _pairling_install_id()
        if install_id is None
        else normalize_install_id(install_id)
    )
    if not expected_install_id:
        return False, "install_id is missing"
    if str(credential.get("install_id") or "") != expected_install_id:
        return False, "credential install_id does not match this Mac"
    try:
        directory_mode, file_mode = _credential_modes(
            target,
            trusted_root=trusted_root,
        )
    except LocalMCPCredentialPathError as exc:
        return False, str(exc)
    if directory_mode & 0o077:
        return False, f"credential directory is not private: {oct(directory_mode)}"
    if file_mode & 0o077:
        return False, f"credential file is not private: {oct(file_mode)}"
    token = str(credential.get("token") or "")
    auth = device_registry.authenticate(
        token,
        required_scopes=LOCAL_MCP_SCOPES,
        path="/pairling-tools/run",
    )
    if not auth.ok:
        return False, f"credential rejected: {auth.reason}"
    if str(auth.install_id or "") != expected_install_id:
        return False, "credential registry install_id does not match this Mac"
    credential_device_id = str(credential.get("device_id") or "")
    if credential_device_id != str(auth.device_id or ""):
        return False, "credential device_id does not match its registry token"
    credential_proof_secret = str(credential.get("proof_secret") or "")
    registry_proof_secret = str(auth.proof_secret or "")
    if (
        not registry_proof_secret
        or not secrets.compare_digest(
            credential_proof_secret,
            registry_proof_secret,
        )
    ):
        return False, "credential proof_secret does not match its registry token"
    if hasattr(device_registry, "active_device_ids_for_purpose"):
        active_bridge_ids = _active_local_mcp_bridge_ids(device_registry)
        if active_bridge_ids != (str(auth.device_id or ""),):
            return False, "credential registry does not contain exactly one active MCP bridge"
    return True, str(target)


def _credential_matches_payload(
    path: Path,
    payload: dict[str, Any],
    *,
    trusted_root: Path,
) -> bool:
    try:
        observed = _read_credential(path, trusted_root=trusted_root)
    except LocalMCPCredentialPathError:
        return False
    if observed is None:
        return False
    for key in ("device_id", "install_id", "token", "proof_secret"):
        expected = str(payload.get(key) or "")
        actual = str(observed.get(key) or "")
        if not expected or not secrets.compare_digest(expected, actual):
            return False
    return True


def _read_credential(
    path: Path,
    *,
    trusted_root: Path,
) -> dict[str, Any] | None:
    parent_fd = _open_credential_parent(
        path,
        trusted_root=trusted_root,
        create=False,
    )
    if parent_fd is None:
        return None
    try:
        file_fd = _open_credential_file(parent_fd, path.name)
        if file_fd is None:
            return None
        try:
            try:
                with os.fdopen(file_fd, "r", encoding="utf-8") as handle:
                    file_fd = -1
                    raw = handle.read()
            except UnicodeError:
                return None
        finally:
            if file_fd >= 0:
                os.close(file_fd)
    finally:
        os.close(parent_fd)
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError):
        return None
    if not isinstance(payload, dict):
        return None
    required = ("device_id", "install_id", "token", "proof_secret")
    if not all(str(payload.get(key) or "").strip() for key in required):
        return None
    return payload


def _write_private_json(
    path: Path,
    payload: dict[str, Any],
    *,
    trusted_root: Path,
) -> None:
    parent_fd = _open_credential_parent(
        path,
        trusted_root=trusted_root,
        create=True,
    )
    if parent_fd is None:
        raise LocalMCPCredentialPathError(
            f"credential directory could not be created safely: {path.parent}"
        )
    name = _credential_filename(path)
    temporary_name = f".{name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    temporary_fd = -1
    temporary_exists = False
    try:
        try:
            existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise LocalMCPCredentialPathError(
                f"credential file could not be inspected safely: {path}"
            ) from exc
        if existing is not None and (
            not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1
        ):
            raise LocalMCPCredentialPathError(
                f"credential file must be a regular file, not a symlink or hard-link alias: {path}"
            )

        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        temporary_fd = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
        temporary_exists = True
        with os.fdopen(temporary_fd, "w", encoding="utf-8") as handle:
            temporary_fd = -1
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary_name,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temporary_exists = False
        os.fsync(parent_fd)

        final_fd = _open_credential_file(parent_fd, name)
        if final_fd is None:
            raise LocalMCPCredentialPathError(
                f"credential file disappeared after its atomic write: {path}"
            )
        try:
            os.fchmod(final_fd, 0o600)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions - credential file must be user-only.
        finally:
            os.close(final_fd)
    except LocalMCPCredentialPathError:
        raise
    except OSError as exc:
        raise LocalMCPCredentialPathError(
            f"credential file could not be written safely: {path}"
        ) from exc
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_exists:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def _credential_filename(path: Path) -> str:
    name = path.name
    if not name or name in {".", ".."}:
        raise LocalMCPCredentialPathError(f"credential path has no filename: {path}")
    return name


def _credential_context(path: Path, registry: DeviceRegistry) -> tuple[Path, Path]:
    requested = Path(path)
    absolute_target = Path(os.path.abspath(os.fspath(requested)))
    db_path = getattr(registry, "db_path", None)
    if db_path is None:
        raise LocalMCPCredentialPathError(
            "credential registry does not expose a trusted storage root"
        )
    absolute_root = Path(os.path.abspath(os.fspath(Path(db_path).parent)))
    target = _normalize_root_owned_private_alias(absolute_target)
    trusted_root = _normalize_root_owned_private_alias(absolute_root)
    if trusted_root == Path(trusted_root.anchor):
        raise LocalMCPCredentialPathError(
            "credential registry storage root is too broad to trust"
        )
    expected = trusted_root / LOCAL_MCP_CREDENTIAL_FILENAME
    if not requested.is_absolute() or requested != absolute_target:
        raise LocalMCPCredentialPathError(
            f"credential path must use its exact canonical spelling: {expected}"
        )
    if target != expected:
        raise LocalMCPCredentialPathError(
            f"credential path must be the dedicated MCP credential file: {expected}"
        )
    return target, trusted_root


def _normalize_root_owned_private_alias(path: Path) -> Path:
    """Accept only macOS's root-owned top-level aliases into /private."""
    anchor = Path(path.anchor)
    try:
        first_name = path.relative_to(anchor).parts[0]
    except (IndexError, ValueError):
        return path
    first = anchor / first_name
    try:
        metadata = first.lstat()
    except OSError:
        return path
    if not stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0:
        return path
    expected = anchor / "private" / first_name
    try:
        destination = Path(os.readlink(first))
        resolved = (
            destination
            if destination.is_absolute()
            else first.parent / destination
        ).resolve(strict=True)
    except OSError:
        return path
    if resolved != expected:
        return path
    relative = path.relative_to(first)
    return resolved / relative


@contextmanager
def _credential_transaction_lock(
    target: Path,
    *,
    trusted_root: Path,
) -> Iterator[None]:
    """Serialize the complete credential and registry transaction."""
    if target != trusted_root / LOCAL_MCP_CREDENTIAL_FILENAME:
        raise LocalMCPCredentialPathError("credential lock target is not canonical")
    with _LOCAL_MCP_PROCESS_LOCK:
        parent_fd = _open_credential_parent(
            target,
            trusted_root=trusted_root,
            create=True,
        )
        if parent_fd is None:
            raise LocalMCPCredentialPathError(
                f"credential storage root could not be locked: {trusted_root}"
            )
        lock_fd = -1
        try:
            lock_fd = _open_private_lock_file(parent_fd, LOCAL_MCP_LOCK_FILENAME)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            if lock_fd >= 0:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
            os.close(parent_fd)


def _open_private_lock_file(parent_fd: int, name: str) -> int:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        before = None
    except OSError as exc:
        raise LocalMCPCredentialPathError(
            "MCP credential lock could not be inspected safely"
        ) from exc
    if before is not None and (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size != 0
    ):
        raise LocalMCPCredentialPathError(
            "MCP credential lock must be a private empty regular file, not an alias"
        )
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        lock_fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
    except OSError as exc:
        raise LocalMCPCredentialPathError(
            "MCP credential lock could not be opened safely"
        ) from exc
    try:
        opened = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != 0
            or (
                before is not None
                and (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            )
        ):
            raise LocalMCPCredentialPathError(
                "MCP credential lock must be a private empty regular file, not an alias"
            )
        os.fchmod(lock_fd, 0o600)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions - the transaction lock is user-only.
        return lock_fd
    except BaseException:
        os.close(lock_fd)
        raise


def _open_credential_parent(
    path: Path,
    *,
    trusted_root: Path,
    create: bool,
) -> int | None:
    parent = path.parent
    try:
        relative_parent = parent.relative_to(trusted_root)
    except ValueError as exc:
        raise LocalMCPCredentialPathError(
            f"credential path escaped its trusted storage root: {path}"
        ) from exc

    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory_fd = _open_absolute_directory_without_symlinks(trusted_root, flags)
    except LocalMCPCredentialPathError:
        raise
    except OSError as exc:
        raise LocalMCPCredentialPathError(
            f"credential storage root must be a real directory without symlink aliases: {trusted_root}"
        ) from exc

    for component in relative_parent.parts:
        child_fd = -1
        try:
            try:
                child_fd = os.open(component, flags, dir_fd=directory_fd)
            except FileNotFoundError:
                if not create:
                    os.close(directory_fd)
                    return None
                try:
                    os.mkdir(component, mode=0o700, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                child_fd = os.open(component, flags, dir_fd=directory_fd)
            if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
                raise LocalMCPCredentialPathError(
                    f"credential directory must be a real directory: {parent}"
                )
        except LocalMCPCredentialPathError:
            if child_fd >= 0:
                os.close(child_fd)
            os.close(directory_fd)
            raise
        except OSError as exc:
            if child_fd >= 0:
                os.close(child_fd)
            os.close(directory_fd)
            raise LocalMCPCredentialPathError(
                f"credential directory must be a real directory, not a symlink: {parent}"
            ) from exc
        os.close(directory_fd)
        directory_fd = child_fd

    if create:
        try:
            os.fchmod(directory_fd, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions - credential directory must be user-only.
        except OSError as exc:
            os.close(directory_fd)
            raise LocalMCPCredentialPathError(
                f"credential directory permissions could not be secured: {parent}"
            ) from exc
    return directory_fd


def _open_absolute_directory_without_symlinks(path: Path, flags: int) -> int:
    anchor = Path(path.anchor)
    if not path.is_absolute() or anchor == path:
        if anchor == path:
            raise LocalMCPCredentialPathError(
                "credential storage root is too broad to trust"
            )
        raise LocalMCPCredentialPathError(
            "credential storage root must be absolute"
        )
    try:
        directory_fd = os.open(anchor, flags)
    except OSError as exc:
        raise LocalMCPCredentialPathError(
            f"credential storage root anchor could not be opened: {anchor}"
        ) from exc
    for component in path.relative_to(anchor).parts:
        child_fd = -1
        try:
            child_fd = os.open(component, flags, dir_fd=directory_fd)
            if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
                raise LocalMCPCredentialPathError(
                    f"credential storage root component is not a directory: {path}"
                )
        except BaseException:
            if child_fd >= 0:
                os.close(child_fd)
            os.close(directory_fd)
            raise
        os.close(directory_fd)
        directory_fd = child_fd
    return directory_fd


def _open_credential_file(parent_fd: int, name: str) -> int | None:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise LocalMCPCredentialPathError(
            "credential file could not be inspected safely"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise LocalMCPCredentialPathError(
            "credential file must be a regular file, not a symlink or hard-link alias"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        file_fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise LocalMCPCredentialPathError(
            "credential file could not be opened safely"
        ) from exc
    opened = os.fstat(file_fd)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
    ):
        os.close(file_fd)
        raise LocalMCPCredentialPathError(
            "credential file must be a stable regular file, not an alias"
        )
    return file_fd


def _credential_modes(
    path: Path,
    *,
    trusted_root: Path,
) -> tuple[int, int]:
    parent_fd = _open_credential_parent(
        path,
        trusted_root=trusted_root,
        create=False,
    )
    if parent_fd is None:
        raise LocalMCPCredentialPathError(f"credential directory is missing: {path.parent}")
    try:
        file_fd = _open_credential_file(parent_fd, _credential_filename(path))
        if file_fd is None:
            raise LocalMCPCredentialPathError(f"credential file is missing: {path}")
        try:
            return os.fstat(parent_fd).st_mode & 0o777, os.fstat(file_fd).st_mode & 0o777
        finally:
            os.close(file_fd)
    finally:
        os.close(parent_fd)


def _valid_created_at(value: Any) -> float:
    try:
        candidate = float(value)
    except (TypeError, ValueError, OverflowError):
        return utc_epoch()
    if not math.isfinite(candidate) or candidate <= 0:
        return utc_epoch()
    return candidate
