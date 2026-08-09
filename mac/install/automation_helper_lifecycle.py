#!/usr/bin/env python3
"""Install and verify the stable Pairling macOS automation helper.

The immutable runtime release supplies a signed app bundle. This module moves a
verified copy to the version-independent Application Support path that macOS
uses as the Automation requester identity. It deliberately owns only the
Pairling automation directory and never inspects or alters the TCC database.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import json
import os
import plistlib
import secrets
import shutil
import stat
import subprocess
import time
import sys
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Callable, Sequence


UTC = timezone.utc
AUTOMATION_HELPER_BUNDLE_ID = "dev.pairling.automation"
AUTOMATION_HELPER_TEAM_ID = "965AVD34A3"
AUTOMATION_APP_NAME = "Pairling.app"
AUTOMATION_ROLLBACK_APP_NAME = ".Pairling.rollback.app"
AUTOMATION_ABSENT_MARKER_NAME = ".Pairling.rollback-absent"
AUTOMATION_EXECUTABLE_NAME = "PairlingAutomation"
AUTOMATION_ROOT_NAME = "automation"
AUTOMATION_SECRET_NAME = "local-secret"
AUTOMATION_SOCKET_NAME = "automation.sock"
AUTOMATION_SETUP_CAPABILITY_NAME = "setup-capability.json"
AUTOMATION_PROBE_EVIDENCE_NAME = "last-terminal-probe.json"
AUTOMATION_MIGRATION_NAME = "legacy-migration.json"
KNOWN_LEGACY_BUNDLE_ID = "com.mghome.ClaudeInjector"
KNOWN_LEGACY_EXECUTABLE_SHA256 = "ca7005538f4b44adc0e17a06a595c3fa97299b2dc9094a97eef4bf48ae4fee82"

SETUP_CAPABILITY_TTL_SECONDS = 300
SETUP_CAPABILITY_MAX_TTL_SECONDS = 900
_SWIFT_REFERENCE_DATE = datetime(2001, 1, 1, tzinfo=UTC)


class HelperLifecycleError(RuntimeError):
    """A lifecycle boundary could not be verified safely."""


def scan_bundle_archive(archive: zipfile.ZipFile) -> set[str]:
    """Reject an archive that could unpack outside the one expected app bundle."""

    required = {
        AUTOMATION_APP_NAME,
        f"{AUTOMATION_APP_NAME}/Contents",
        f"{AUTOMATION_APP_NAME}/Contents/Info.plist",
        f"{AUTOMATION_APP_NAME}/Contents/MacOS",
        f"{AUTOMATION_APP_NAME}/Contents/MacOS/{AUTOMATION_EXECUTABLE_NAME}",
    }
    seen: set[str] = set()
    total_size = 0
    for member in archive.infolist():
        name = member.filename
        normalized = name.removesuffix("/")
        raw_parts = normalized.split("/")
        path = PurePosixPath(normalized)
        if (
            not normalized
            or "\\" in name
            or path.is_absolute()
            or any(part in ("", ".", "..") for part in raw_parts)
            or path.parts[0] != AUTOMATION_APP_NAME
            or normalized in seen
        ):
            raise HelperLifecycleError("Pairling automation helper archive is invalid.")

        mode = member.external_attr >> 16
        entry_type = stat.S_IFMT(mode)
        is_directory = member.is_dir()
        if (
            entry_type == stat.S_IFLNK
            or (entry_type not in (0, stat.S_IFDIR, stat.S_IFREG))
            or (entry_type == stat.S_IFDIR and not is_directory)
            or (entry_type == stat.S_IFREG and is_directory)
        ):
            raise HelperLifecycleError("Pairling automation helper archive is invalid.")
        if is_directory:
            if member.file_size != 0:
                raise HelperLifecycleError("Pairling automation helper archive is invalid.")
        else:
            total_size += member.file_size
            if total_size > 512 * 1024 * 1024:
                raise HelperLifecycleError("Pairling automation helper archive is too large.")
        seen.add(normalized)
        if len(seen) > 10_000:
            raise HelperLifecycleError("Pairling automation helper archive is too large.")

    if not required <= seen:
        raise HelperLifecycleError("Pairling automation helper archive is incomplete.")
    return seen



def extract_bundle_archive(
    archive_path: Path,
    destination: Path,
    *,
    expected_sha256: str,
) -> Path:
    """Safely unpack one digest-pinned helper archive into a fresh directory."""

    archive_path = Path(archive_path)
    destination = Path(destination)
    _require_owned_regular_file(archive_path)
    if (
        len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
        or _sha256(archive_path) != expected_sha256
    ):
        raise HelperLifecycleError("Pairling automation helper archive is invalid.")
    if destination.exists() or destination.is_symlink():
        raise HelperLifecycleError("Pairling automation helper extraction path is unavailable.")
    _require_owned_directory(destination.parent)

    try:
        with zipfile.ZipFile(archive_path) as archive:
            scan_bundle_archive(archive)
    except (OSError, zipfile.BadZipFile) as exc:
        raise HelperLifecycleError("Pairling automation helper archive is invalid.") from exc

    created = False
    succeeded = False
    try:
        os.mkdir(destination, 0o700)
        created = True
        completed = subprocess.run(
            ["/usr/bin/ditto", "-x", "-k", str(archive_path), str(destination)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if completed.returncode != 0:
            raise HelperLifecycleError("Pairling automation helper archive is invalid.")
        if {path.name for path in destination.iterdir()} != {AUTOMATION_APP_NAME}:
            raise HelperLifecycleError("Pairling automation helper archive is invalid.")
        app = destination / AUTOMATION_APP_NAME
        verify_bundle_layout(app)
        succeeded = True
        return app
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HelperLifecycleError("Pairling automation helper archive is unavailable.") from exc
    finally:
        if not succeeded and created and (destination.exists() or destination.is_symlink()):
            try:
                shutil.rmtree(destination)
            except OSError as exc:
                raise HelperLifecycleError(
                    "Pairling automation helper extraction cleanup failed."
                ) from exc

@dataclass(frozen=True)
class HelperInstallResult:
    root: Path
    app_path: Path
    secret_path: Path


def _lstat(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise HelperLifecycleError("Pairling automation helper path is unavailable.") from exc


def _is_owned_directory(path: Path, *, mode: int | None = None) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and (mode is None or stat.S_IMODE(metadata.st_mode) == mode)
    )


def _require_owned_directory(path: Path, *, mode: int | None = None) -> None:
    if not _is_owned_directory(path, mode=mode):
        raise HelperLifecycleError("Pairling automation helper path is unavailable.")


def _require_owned_regular_file(path: Path, *, mode: int | None = None) -> None:
    metadata = _lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or (mode is not None and stat.S_IMODE(metadata.st_mode) != mode)
    ):
        raise HelperLifecycleError("Pairling automation helper file is invalid.")


def _require_real_bundle_tree(bundle: Path) -> None:
    _require_owned_directory(bundle)
    for parent, directories, filenames in os.walk(bundle, followlinks=False):
        current = Path(parent)
        metadata = _lstat(current)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise HelperLifecycleError("Pairling automation helper bundle is invalid.")
        for name in [*directories, *filenames]:
            entry = current / name
            entry_metadata = _lstat(entry)
            if entry_metadata.st_uid != os.geteuid() or stat.S_ISLNK(entry_metadata.st_mode) or not (
                stat.S_ISDIR(entry_metadata.st_mode) or stat.S_ISREG(entry_metadata.st_mode)
            ):
                raise HelperLifecycleError("Pairling automation helper bundle is invalid.")


def ensure_private_root(root: Path) -> Path:
    """Create or verify the exact uid-owned 0700 automation root."""

    root = Path(root)
    try:
        metadata = root.lstat()
    except FileNotFoundError:
        parent = root.parent
        _require_owned_directory(parent)
        try:
            os.mkdir(root, 0o700)
        except OSError as exc:
            raise HelperLifecycleError("Pairling automation helper path is unavailable.") from exc
        metadata = _lstat(root)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise HelperLifecycleError("Pairling automation helper path is unavailable.")
    return root


def _automation_root(app_support: Path) -> Path:
    app_support = Path(app_support)
    _require_owned_directory(app_support)
    return ensure_private_root(app_support / AUTOMATION_ROOT_NAME)


def ensure_local_secret(root: Path) -> Path:
    """Create the 32-byte local helper secret once, or validate the existing one."""

    root = ensure_private_root(root)
    secret_path = root / AUTOMATION_SECRET_NAME
    try:
        metadata = secret_path.lstat()
    except FileNotFoundError:
        descriptor = -1
        try:
            descriptor = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            secret = secrets.token_bytes(32)
            os.write(descriptor, secret)
            os.fsync(descriptor)
        except OSError as exc:
            raise HelperLifecycleError("Pairling automation helper secret is unavailable.") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    else:
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise HelperLifecycleError("Pairling automation helper secret is invalid.")

    _require_owned_regular_file(secret_path, mode=0o600)
    try:
        secret = secret_path.read_bytes()
    except OSError as exc:
        raise HelperLifecycleError("Pairling automation helper secret is unavailable.") from exc
    if len(secret) != 32:
        raise HelperLifecycleError("Pairling automation helper secret is invalid.")
    return secret_path


def issue_setup_capability(
    root: Path,
    *,
    now: datetime | None = None,
    ttl_seconds: int = SETUP_CAPABILITY_TTL_SECONDS,
    token_factory: Callable[[int], str] = secrets.token_urlsafe,
) -> str:
    """Write one short-lived local capability consumable by the running helper.

    Swift's default ``JSONDecoder`` Date strategy expects seconds after Apple's
    2001 reference date, not an ISO-8601 string. The capability is intentionally
    returned only to the explicit local setup caller and is never persisted in
    installer output or logs.
    """

    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or not 1 <= ttl_seconds <= SETUP_CAPABILITY_MAX_TTL_SECONDS
    ):
        raise HelperLifecycleError("Pairling automation setup capability is invalid.")
    if now is None:
        now = datetime.now(UTC)
    if now.tzinfo is None:
        raise HelperLifecycleError("Pairling automation setup capability is invalid.")

    root = ensure_private_root(root)
    capability = token_factory(32)
    if (
        not isinstance(capability, str)
        or not capability
        or len(capability.encode("utf-8")) > 256
    ):
        raise HelperLifecycleError("Pairling automation setup capability is invalid.")

    expires_at = now.astimezone(UTC) + timedelta(seconds=ttl_seconds)
    record = {
        "capability": capability,
        "expiresAt": (expires_at - _SWIFT_REFERENCE_DATE).total_seconds(),
        "used": False,
    }
    try:
        encoded = json.dumps(record, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HelperLifecycleError("Pairling automation setup capability is invalid.") from exc

    destination = root / AUTOMATION_SETUP_CAPABILITY_NAME
    if destination.exists() or destination.is_symlink():
        _require_owned_regular_file(destination, mode=0o600)
    temporary = root / f".{AUTOMATION_SETUP_CAPABILITY_NAME}.{secrets.token_hex(16)}"
    descriptor = -1
    replaced = False
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError("could not write setup capability")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, destination)
        replaced = True
        _require_owned_regular_file(destination, mode=0o600)
    except OSError as exc:
        raise HelperLifecycleError("Pairling automation setup capability is unavailable.") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not replaced:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
    return capability


def verify_bundle_layout(bundle: Path) -> None:
    """Verify the unsigned structural properties common to every helper copy."""

    bundle = Path(bundle)
    _require_real_bundle_tree(bundle)
    contents = bundle / "Contents"
    info_path = contents / "Info.plist"
    executable = contents / "MacOS" / AUTOMATION_EXECUTABLE_NAME
    _require_owned_regular_file(info_path)
    _require_owned_regular_file(executable)
    try:
        info = plistlib.loads(info_path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise HelperLifecycleError("Pairling automation helper bundle is invalid.") from exc
    if not isinstance(info, dict) or (
        info.get("CFBundleIdentifier") != AUTOMATION_HELPER_BUNDLE_ID
        or info.get("CFBundleDisplayName") != "Pairling"
        or info.get("CFBundleExecutable") != AUTOMATION_EXECUTABLE_NAME
        or info.get("CFBundlePackageType") not in {None, "APPL"}
    ):
        raise HelperLifecycleError("Pairling automation helper bundle is invalid.")
    if stat.S_IMODE(_lstat(executable).st_mode) & 0o111 == 0:
        raise HelperLifecycleError("Pairling automation helper executable is invalid.")


def _run_checked(arguments: Sequence[str], *, stdout_only: bool = False) -> str:
    try:
        completed = subprocess.run(
            list(arguments),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HelperLifecycleError("Pairling could not verify the automation helper.") from exc
    output = completed.stdout if stdout_only else f"{completed.stdout}\n{completed.stderr}"
    if completed.returncode != 0:
        raise HelperLifecycleError("Pairling could not verify the automation helper.")
    return output


def verify_signed_bundle(bundle: Path, *, architecture: str) -> None:
    """Verify the release bundle's signing, entitlement, architecture, and ticket."""

    verify_bundle_layout(bundle)
    bundle = Path(bundle)
    executable = bundle / "Contents" / "MacOS" / AUTOMATION_EXECUTABLE_NAME
    _run_checked(["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(bundle)])
    identity = _run_checked(["/usr/bin/codesign", "-dv", "--verbose=4", str(bundle)])
    if (
        f"Identifier={AUTOMATION_HELPER_BUNDLE_ID}" not in identity
        or f"TeamIdentifier={AUTOMATION_HELPER_TEAM_ID}" not in identity
        or "runtime" not in identity
    ):
        raise HelperLifecycleError("Pairling automation helper identity is invalid.")
    entitlement_output = _run_checked(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(bundle)],
        stdout_only=True,
    )
    try:
        entitlement_start = entitlement_output.index("<?xml")
        entitlements = plistlib.loads(entitlement_output[entitlement_start:].encode("utf-8"))
    except (ValueError, plistlib.InvalidFileException) as exc:
        raise HelperLifecycleError("Pairling automation helper entitlement is invalid.") from exc
    if entitlements.get("com.apple.security.automation.apple-events") is not True:
        raise HelperLifecycleError("Pairling automation helper entitlement is invalid.")
    architectures = _run_checked(["/usr/bin/lipo", "-archs", str(executable)]).split()
    if architectures != [architecture]:
        raise HelperLifecycleError("Pairling automation helper architecture is invalid.")
    assessment = _run_checked(["/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", str(bundle)])
    if "Notarized Developer ID" not in assessment:
        raise HelperLifecycleError("Pairling automation helper notarization is invalid.")


def verify_install_bundle(
    bundle: Path,
    *,
    architecture: str,
    allow_unsigned_development: bool = False,
) -> None:
    """Verify a helper copy before it becomes the stable Automation requester.

    Production always requires the pinned Developer ID signature.  The explicit
    development escape hatch exists only for local ad-hoc package builds; it
    still verifies the app bundle's real, owned layout before any copy occurs.
    """

    if allow_unsigned_development:
        verify_bundle_layout(bundle)
        return
    verify_signed_bundle(bundle, architecture=architecture)


def _remove_owned_bundle(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    _require_real_bundle_tree(path)
    for parent, _directories, _filenames in os.walk(path, followlinks=False):
        descriptor = -1
        try:
            descriptor = os.open(
                parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise HelperLifecycleError("Pairling automation helper bundle is invalid.")
            os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode) | stat.S_IWUSR)
        except OSError as exc:
            raise HelperLifecycleError("Pairling automation helper bundle is unavailable.") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    shutil.rmtree(path)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def prepare_helper_promotion(*, app_support: Path) -> None:
    """Move the current helper aside so the outer runtime transaction owns rollback."""

    root = _automation_root(app_support)
    app = root / AUTOMATION_APP_NAME
    rollback = root / AUTOMATION_ROLLBACK_APP_NAME
    absent = root / AUTOMATION_ABSENT_MARKER_NAME
    if rollback.exists() or rollback.is_symlink() or absent.exists() or absent.is_symlink():
        raise HelperLifecycleError("An earlier Pairling automation helper update needs recovery.")
    if app.exists() or app.is_symlink():
        verify_bundle_layout(app)
        os.rename(app, rollback)
        _fsync_directory(root)
        return
    descriptor = os.open(absent, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        payload = b"absent\n"
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise HelperLifecycleError("Pairling automation helper rollback state is unavailable.")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(root)


def restore_helper_promotion(*, app_support: Path) -> None:
    """Restore the exact helper state that existed before runtime activation."""

    root = Path(app_support) / AUTOMATION_ROOT_NAME
    if not root.exists() and not root.is_symlink():
        return
    root = ensure_private_root(root)
    app = root / AUTOMATION_APP_NAME
    rollback = root / AUTOMATION_ROLLBACK_APP_NAME
    absent = root / AUTOMATION_ABSENT_MARKER_NAME
    has_rollback = rollback.exists() or rollback.is_symlink()
    has_absent = absent.exists() or absent.is_symlink()
    if has_rollback and has_absent:
        raise HelperLifecycleError("Pairling automation helper rollback state is invalid.")
    if not has_rollback and not has_absent:
        return
    if app.exists() or app.is_symlink():
        verify_bundle_layout(app)
        _remove_owned_bundle(app)
    if has_rollback:
        verify_bundle_layout(rollback)
        os.rename(rollback, app)
    else:
        _require_owned_regular_file(absent, mode=0o600)
        if absent.read_bytes() != b"absent\n":
            raise HelperLifecycleError("Pairling automation helper rollback state is invalid.")
        absent.unlink()
    _fsync_directory(root)


def commit_helper_promotion(*, app_support: Path) -> None:
    """Delete only the verified helper rollback marker after runtime commit."""

    root = Path(app_support) / AUTOMATION_ROOT_NAME
    if not root.exists() and not root.is_symlink():
        return
    root = ensure_private_root(root)
    rollback = root / AUTOMATION_ROLLBACK_APP_NAME
    absent = root / AUTOMATION_ABSENT_MARKER_NAME
    has_rollback = rollback.exists() or rollback.is_symlink()
    has_absent = absent.exists() or absent.is_symlink()
    if has_rollback and has_absent:
        raise HelperLifecycleError("Pairling automation helper rollback state is invalid.")
    if has_rollback:
        verify_bundle_layout(rollback)
        _remove_owned_bundle(rollback)
    elif has_absent:
        _require_owned_regular_file(absent, mode=0o600)
        if absent.read_bytes() != b"absent\n":
            raise HelperLifecycleError("Pairling automation helper rollback state is invalid.")
        absent.unlink()
    if has_rollback or has_absent:
        _fsync_directory(root)

def _remove_owned_regular_file(path: Path, *, mode: int) -> None:
    if not path.exists() and not path.is_symlink():
        return
    _require_owned_regular_file(path, mode=mode)
    path.unlink()

def _remove_owned_setup_capability(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    _require_owned_regular_file(path, mode=0o600)
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HelperLifecycleError("Pairling automation setup capability is invalid.") from exc
    expires_at = record.get("expiresAt") if isinstance(record, dict) else None
    if not (
        isinstance(record, dict)
        and isinstance(record.get("capability"), str)
        and isinstance(expires_at, (int, float))
        and not isinstance(expires_at, bool)
        and (isinstance(expires_at, int) or math.isfinite(expires_at))
        and isinstance(record.get("used"), bool)
    ):
        raise HelperLifecycleError("Pairling automation setup capability is invalid.")
    path.unlink()


def _validate_owned_launch_agent_plist(*, launch_agent_plist: Path, root: Path) -> None:
    launch_agent_plist = Path(launch_agent_plist)
    if launch_agent_plist.name != f"{AUTOMATION_HELPER_BUNDLE_ID}.plist":
        raise HelperLifecycleError("Pairling automation LaunchAgent is invalid.")
    _require_owned_directory(launch_agent_plist.parent)
    _require_owned_regular_file(launch_agent_plist, mode=0o644)
    try:
        plist = plistlib.loads(launch_agent_plist.read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise HelperLifecycleError("Pairling automation LaunchAgent is invalid.") from exc
    executable = root / AUTOMATION_APP_NAME / "Contents" / "MacOS" / AUTOMATION_EXECUTABLE_NAME
    environment = plist.get("EnvironmentVariables") if isinstance(plist, dict) else None
    if not (
        isinstance(plist, dict)
        and plist.get("Label") == AUTOMATION_HELPER_BUNDLE_ID
        and plist.get("ProgramArguments") == [str(executable)]
        and isinstance(environment, dict)
        and environment.get("PAIRLING_AUTOMATION_ROOT") == str(root)
        and environment.get("PATH") == "/usr/bin:/bin:/usr/sbin:/sbin"
        and plist.get("RunAtLoad") is True
        and plist.get("KeepAlive") == {"Crashed": True}
        and plist.get("ProcessType") == "Background"
        and plist.get("ThrottleInterval") == 10
        and plist.get("Umask") == 0o077
        and isinstance(plist.get("StandardOutPath"), str)
        and isinstance(plist.get("StandardErrorPath"), str)
    ):
        raise HelperLifecycleError("Pairling automation LaunchAgent is invalid.")


def _remove_owned_socket(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    metadata = _lstat(path)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise HelperLifecycleError("Pairling automation helper socket is invalid.")
    path.unlink()


def remove_installed_helper_state(
    *,
    app_support: Path,
    launch_agent_plist: Path | None = None,
) -> None:
    """Remove only verified helper state and the generated LaunchAgent."""

    root = Path(app_support) / AUTOMATION_ROOT_NAME
    if root.exists() or root.is_symlink():
        root = ensure_private_root(root)

    if launch_agent_plist is not None:
        if root.exists() or root.is_symlink():
            _validate_owned_launch_agent_plist(
                launch_agent_plist=launch_agent_plist,
                root=root,
            )
        elif Path(launch_agent_plist).exists() or Path(launch_agent_plist).is_symlink():
            raise HelperLifecycleError("Pairling automation LaunchAgent is invalid.")

    if root.exists() or root.is_symlink():
        app_path = root / AUTOMATION_APP_NAME
        if app_path.exists() or app_path.is_symlink():
            verify_bundle_layout(app_path)
            _remove_owned_bundle(app_path)
        _remove_owned_socket(root / AUTOMATION_SOCKET_NAME)
        _remove_owned_regular_file(root / AUTOMATION_SECRET_NAME, mode=0o600)
        _remove_owned_setup_capability(root / AUTOMATION_SETUP_CAPABILITY_NAME)
        _remove_owned_regular_file(root / AUTOMATION_PROBE_EVIDENCE_NAME, mode=0o600)

    if launch_agent_plist is not None and (
        Path(launch_agent_plist).exists() or Path(launch_agent_plist).is_symlink()
    ):
        Path(launch_agent_plist).unlink()


def _launchctl(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(arguments),
        capture_output=True,
        check=False,
        text=True,
    )


def _is_ready_socket(socket_path: Path) -> bool:
    try:
        metadata = socket_path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISSOCK(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o600
    )


def _validate_launch_agent(
    *,
    app_path: Path,
    launch_agent_plist: Path,
) -> tuple[Path, Path]:
    """Return the exact stable executable and socket after validating its job."""

    app_path = Path(app_path)
    root = app_path.parent
    _require_owned_directory(root, mode=0o700)
    if app_path.name != AUTOMATION_APP_NAME:
        raise HelperLifecycleError("Pairling automation helper path is invalid.")
    _require_real_bundle_tree(app_path)
    executable = app_path / "Contents" / "MacOS" / AUTOMATION_EXECUTABLE_NAME
    _require_owned_regular_file(executable)
    launch_agent_plist = Path(launch_agent_plist)
    _require_owned_regular_file(launch_agent_plist)
    try:
        plist = plistlib.loads(launch_agent_plist.read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise HelperLifecycleError("Pairling automation LaunchAgent is invalid.") from exc
    if not isinstance(plist, dict):
        raise HelperLifecycleError("Pairling automation LaunchAgent is invalid.")
    if (
        plist.get("Label") != AUTOMATION_HELPER_BUNDLE_ID
        or plist.get("ProgramArguments") != [str(executable)]
        or not isinstance(plist.get("EnvironmentVariables"), dict)
        or plist["EnvironmentVariables"].get("PAIRLING_AUTOMATION_ROOT") != str(root)
    ):
        raise HelperLifecycleError("Pairling automation LaunchAgent is invalid.")
    return executable, root / AUTOMATION_SOCKET_NAME


def activate_launch_agent(
    *,
    app_path: Path,
    launch_agent_plist: Path,
    command_runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] = _launchctl,
    socket_ready: Callable[[Path], bool] = _is_ready_socket,
) -> None:
    """Replace the user LaunchAgent and prove it serves the stable helper."""

    executable, socket_path = _validate_launch_agent(
        app_path=app_path,
        launch_agent_plist=launch_agent_plist,
    )
    domain = f"gui/{os.geteuid()}"
    target = f"{domain}/{AUTOMATION_HELPER_BUNDLE_ID}"
    command_runner(("/bin/launchctl", "bootout", target))
    for arguments in (
        ("/bin/launchctl", "bootstrap", domain, str(launch_agent_plist)),
        ("/bin/launchctl", "kickstart", "-k", target),
    ):
        result = command_runner(arguments)
        if result.returncode != 0:
            raise HelperLifecycleError("Pairling automation helper could not start.")
    result = command_runner(("/bin/launchctl", "print", target))
    if result.returncode != 0 or str(executable) not in (result.stdout or ""):
        raise HelperLifecycleError("Pairling automation helper could not start.")
    for _ in range(50):
        if socket_ready(socket_path):
            return
        time.sleep(0.1)
    raise HelperLifecycleError("Pairling automation helper did not become available.")


def install_helper_bundle(
    *,
    source_app: Path,
    app_support: Path,
    verify_bundle: Callable[[Path], None],
    activate: Callable[[Path], None] | None = None,
) -> HelperInstallResult:
    """Verify, stage, atomically replace, and optionally activate the stable app."""

    source_app = Path(source_app)
    app_support = Path(app_support)
    root = _automation_root(app_support)
    secret_path = ensure_local_secret(root)
    verify_bundle(source_app)

    app_path = root / AUTOMATION_APP_NAME
    staging = root / ".Pairling.app.staging"
    previous = root / ".Pairling.app.previous"
    if staging.exists() or staging.is_symlink() or previous.exists() or previous.is_symlink():
        raise HelperLifecycleError("Pairling automation helper update could not start safely.")
    if app_path.exists() or app_path.is_symlink():
        _require_real_bundle_tree(app_path)

    had_previous = False
    moved_previous = False
    installed_staging = False
    try:
        shutil.copytree(source_app, staging, symlinks=False)
        verify_bundle(staging)
        had_previous = app_path.exists()
        if had_previous:
            os.rename(app_path, previous)
            moved_previous = True
        os.rename(staging, app_path)
        installed_staging = True
        verify_bundle(app_path)
        if activate is not None:
            activate(app_path)
    except Exception as exc:
        restore_error: Exception | None = None
        try:
            if installed_staging and (app_path.exists() or app_path.is_symlink()):
                _remove_owned_bundle(app_path)
            if moved_previous and (previous.exists() or previous.is_symlink()):
                os.rename(previous, app_path)
        except Exception as recovery_exc:
            restore_error = recovery_exc
        if moved_previous and activate is not None and app_path.exists():
            try:
                activate(app_path)
            except Exception as recovery_exc:
                restore_error = restore_error or recovery_exc
        try:
            if staging.exists() or staging.is_symlink():
                _remove_owned_bundle(staging)
        except Exception as cleanup_exc:
            restore_error = restore_error or cleanup_exc
        if restore_error is not None:
            raise HelperLifecycleError(
                "Pairling could not restore the previous automation helper."
            ) from restore_error
        if isinstance(exc, HelperLifecycleError):
            raise
        raise HelperLifecycleError("Pairling could not install the automation helper.") from exc

    if had_previous:
        _remove_owned_bundle(previous)

    return HelperInstallResult(root=root, app_path=app_path, secret_path=secret_path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def migrate_legacy_injector(
    *,
    legacy_app: Path,
    automation_root: Path,
    expected_executable_sha256: str = KNOWN_LEGACY_EXECUTABLE_SHA256,
) -> dict[str, str]:
    """Move only the exact historic shell wrapper; preserve every unknown app."""

    legacy_app = Path(legacy_app)
    if not legacy_app.exists() and not legacy_app.is_symlink():
        return {"outcome": "legacy_helper_absent"}
    try:
        _require_real_bundle_tree(legacy_app)
        info_path = legacy_app / "Contents" / "Info.plist"
        info = plistlib.loads(info_path.read_bytes())
        executable_name = str(info.get("CFBundleExecutable") or "")
        executable = legacy_app / "Contents" / "MacOS" / executable_name
        _require_owned_regular_file(executable)
        executable_sha256 = _sha256(executable)
    except (HelperLifecycleError, OSError, plistlib.InvalidFileException):
        return {"outcome": "legacy_helper_requires_manual_review"}
    if (
        info.get("CFBundleIdentifier") != KNOWN_LEGACY_BUNDLE_ID
        or executable_sha256 != expected_executable_sha256
    ):
        return {"outcome": "legacy_helper_requires_manual_review"}

    root = ensure_private_root(automation_root)
    legacy_root = root / "legacy"
    if legacy_root.exists() or legacy_root.is_symlink():
        raise HelperLifecycleError("Pairling legacy helper backup path is unavailable.")
    os.mkdir(legacy_root, 0o700)
    destination = legacy_root / "ClaudeInjector.app"
    os.rename(legacy_app, destination)
    record = {
        "source_path": str(legacy_app),
        "bundle_id": KNOWN_LEGACY_BUNDLE_ID,
        "executable_sha256": executable_sha256,
        "migrated_at": datetime.now(UTC).isoformat(),
        "outcome": "migrated",
    }
    record_path = root / AUTOMATION_MIGRATION_NAME
    descriptor = os.open(record_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        payload = json.dumps(record, separators=(",", ":"), sort_keys=True).encode("utf-8")
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise HelperLifecycleError("Pairling legacy helper migration record is unavailable.")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {"outcome": "migrated"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    verify = commands.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--architecture", required=True, choices=("arm64", "x86_64"))
    verify.add_argument("--allow-unsigned-development", action="store_true")

    extract = commands.add_parser("extract-verify")
    extract.add_argument("--archive", type=Path, required=True)
    extract.add_argument("--destination", type=Path, required=True)
    extract.add_argument("--expected-sha256", required=True)
    extract.add_argument("--architecture", required=True, choices=("arm64", "x86_64"))

    install = commands.add_parser("install")
    install.add_argument("--source", type=Path, required=True)
    install.add_argument("--app-support", type=Path, required=True)
    install.add_argument("--architecture", required=True, choices=("arm64", "x86_64"))
    install.add_argument("--allow-unsigned-development", action="store_true")
    install.add_argument("--launch-agent-plist", type=Path)

    prepare_promotion = commands.add_parser("prepare-promotion")
    prepare_promotion.add_argument("--app-support", type=Path, required=True)

    restore_promotion = commands.add_parser("restore-promotion")
    restore_promotion.add_argument("--app-support", type=Path, required=True)

    commit_promotion = commands.add_parser("commit-promotion")
    commit_promotion.add_argument("--app-support", type=Path, required=True)

    migrate_legacy = commands.add_parser("migrate-legacy")
    migrate_legacy.add_argument("--legacy-app", type=Path, required=True)
    migrate_legacy.add_argument("--app-support", type=Path, required=True)

    issue_setup_capability = commands.add_parser("issue-setup-capability")
    issue_setup_capability.add_argument("--app-support", type=Path, required=True)
    issue_setup_capability.add_argument(
        "--ttl-seconds",
        type=int,
        default=SETUP_CAPABILITY_TTL_SECONDS,
    )
    uninstall = commands.add_parser("uninstall")
    uninstall.add_argument("--app-support", type=Path, required=True)
    uninstall.add_argument("--launch-agent-plist", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "verify":
        verify_install_bundle(
            args.bundle,
            architecture=args.architecture,
            allow_unsigned_development=args.allow_unsigned_development,
        )
        return 0
    if args.command == "extract-verify":
        app = extract_bundle_archive(
            archive_path=args.archive,
            destination=args.destination,
            expected_sha256=args.expected_sha256,
        )
        verify_signed_bundle(app, architecture=args.architecture)
        return 0
    if args.command == "issue-setup-capability":
        print(
            issue_setup_capability(
                args.app_support / AUTOMATION_ROOT_NAME,
                ttl_seconds=args.ttl_seconds,
            )
        )
        return 0
    if args.command == "install":
        activate = (
            None
            if args.launch_agent_plist is None
            else lambda app_path: activate_launch_agent(
                app_path=app_path,
                launch_agent_plist=args.launch_agent_plist,
            )
        )
        install_helper_bundle(
            source_app=args.source,
            app_support=args.app_support,
            verify_bundle=lambda path: verify_install_bundle(
                path,
                architecture=args.architecture,
                allow_unsigned_development=args.allow_unsigned_development,
            ),
            activate=activate,
        )
        return 0
    if args.command == "prepare-promotion":
        prepare_helper_promotion(app_support=args.app_support)
        return 0
    if args.command == "restore-promotion":
        restore_helper_promotion(app_support=args.app_support)
        return 0
    if args.command == "commit-promotion":
        commit_helper_promotion(app_support=args.app_support)
        return 0
    if args.command == "migrate-legacy":
        print(
            json.dumps(
                migrate_legacy_injector(
                    legacy_app=args.legacy_app,
                    automation_root=args.app_support / AUTOMATION_ROOT_NAME,
                ),
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    if args.command == "uninstall":
        remove_installed_helper_state(
            app_support=args.app_support,
            launch_agent_plist=args.launch_agent_plist,
        )
        return 0
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HelperLifecycleError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
