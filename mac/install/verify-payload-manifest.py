#!/usr/bin/env python3
from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import stat
import sys
import urllib.parse
from pathlib import Path


UNSAFE_MODE_BITS = 0o7022
FORBIDDEN_DEPENDENCY_KEYS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "bundledDependencies",
    "bundleDependencies",
)
ALLOWED_REPOSITORY_SHA256 = "33abebc9c629f9877e31b8c9f39670427ad5055d80ccdc8a51588101087a042a"


def valid_repository(value: object) -> bool:
    if not isinstance(value, dict) or value.get("type") != "git":
        return False
    url = value.get("url")
    if not isinstance(url, str):
        return False
    parsed = urllib.parse.urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    if not (
        parsed.scheme == "https"
        and parsed.hostname == "github.com"
        and parsed.netloc.casefold() == "github.com"
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
        and len(parts) == 2
    ):
        return False
    canonical = f"github.com/{parts[0].casefold()}/{parts[1].removesuffix('.git').casefold()}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest() == ALLOWED_REPOSITORY_SHA256


def fail(message: str) -> int:
    print(f"payload manifest verification failed: {message}", file=sys.stderr)
    return 1


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def payload_path(payload_root: Path, value: object) -> tuple[str, Path] | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    path = Path(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        return None
    if not path.parts or path.parts[0] != "payload":
        return None
    return path.as_posix(), payload_root.joinpath(*path.parts[1:])


def parse_expected_mode(value: object, relative: str, *, directory: bool) -> tuple[int, str] | str:
    if (
        not isinstance(value, str)
        or len(value) != 4
        or any(character not in "01234567" for character in value)
    ):
        return f"manifest contains an invalid mode for {relative!r}"
    mode = int(value, 8)
    if mode & UNSAFE_MODE_BITS:
        return f"manifest contains unsafe permissions for {relative!r}"
    if not mode & stat.S_IRUSR:
        return f"manifest omits owner read permission for {relative!r}"
    if directory and not mode & stat.S_IXUSR:
        return f"manifest directory is not owner-searchable: {relative!r}"
    return mode, value


def reduced_mode_error(expected: int, actual: int, relative: str, *, directory: bool) -> str | None:
    if actual & UNSAFE_MODE_BITS:
        return f"payload contains unsafe permissions for {relative!r}"
    if actual & ~expected:
        return f"payload permissions exceed the manifest for {relative!r}"
    if not actual & stat.S_IRUSR:
        return f"payload omits owner read permission for {relative!r}"
    if (directory or expected & 0o111) and not actual & stat.S_IXUSR:
        return f"payload omits required owner execute permission for {relative!r}"
    return None


def extended_acl_paths(root: Path) -> list[str]:
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


def scan_payload(payload_root: Path) -> tuple[dict[str, tuple[Path, int]], dict[str, tuple[Path, int]], str | None]:
    root_mode = stat.S_IMODE(payload_root.lstat().st_mode)
    files: dict[str, tuple[Path, int]] = {}
    directories = {"payload": (payload_root, root_mode)}
    for path in sorted(payload_root.rglob("*"), key=lambda item: item.relative_to(payload_root).as_posix()):
        metadata = path.lstat()
        relative = "payload/" + path.relative_to(payload_root).as_posix()
        if path.name == "__pycache__" or path.suffix == ".pyc":
            return {}, {}, f"payload contains forbidden Python bytecode {relative!r}"
        if stat.S_ISLNK(metadata.st_mode):
            return {}, {}, f"payload contains a symlink {relative!r}"
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            directories[relative] = (path, mode)
        elif stat.S_ISREG(metadata.st_mode):
            files[relative] = (path, mode)
        else:
            return {}, {}, f"payload contains an unsupported entry {relative!r}"
    return files, directories, None


def verify_manifest_entries(
    payload_root: Path,
    manifest: dict[str, object],
) -> tuple[int, int, str | None]:
    raw_files = manifest.get("files")
    raw_directories = manifest.get("directories")
    if not isinstance(raw_files, list) or not raw_files:
        return 0, 0, "manifest has no files"
    if not isinstance(raw_directories, list) or not raw_directories:
        return 0, 0, "manifest has no directories"

    expected_files: dict[str, tuple[str, int]] = {}
    for item in raw_files:
        if not isinstance(item, dict):
            return 0, 0, "manifest file entry is not an object"
        resolved = payload_path(payload_root, item.get("path"))
        if resolved is None:
            return 0, 0, f"bad payload path {item.get('path')!r}"
        relative, _ = resolved
        if relative == "payload":
            return 0, 0, "manifest file path names the payload directory"
        if relative.endswith(".pyc") or "__pycache__" in Path(relative).parts:
            return 0, 0, f"manifest contains forbidden Python bytecode {relative!r}"
        if relative in expected_files:
            return 0, 0, f"duplicate payload path {relative!r}"
        expected_hash = item.get("sha256")
        if (
            not isinstance(expected_hash, str)
            or len(expected_hash) != 64
            or any(character not in "0123456789abcdef" for character in expected_hash.lower())
        ):
            return 0, 0, f"bad sha256 for {relative!r}"
        parsed_mode = parse_expected_mode(item.get("mode"), relative, directory=False)
        if isinstance(parsed_mode, str):
            return 0, 0, parsed_mode
        expected_files[relative] = (expected_hash.lower(), parsed_mode[0])

    expected_directories: dict[str, int] = {}
    for item in raw_directories:
        if not isinstance(item, dict):
            return 0, 0, "manifest directory entry is not an object"
        resolved = payload_path(payload_root, item.get("path"))
        if resolved is None:
            return 0, 0, f"bad payload directory path {item.get('path')!r}"
        relative, _ = resolved
        if relative in expected_directories:
            return 0, 0, f"duplicate payload directory path {relative!r}"
        if relative in expected_files:
            return 0, 0, f"payload path is both a file and directory {relative!r}"
        parsed_mode = parse_expected_mode(item.get("mode"), relative, directory=True)
        if isinstance(parsed_mode, str):
            return 0, 0, parsed_mode
        expected_directories[relative] = parsed_mode[0]

    actual_files, actual_directories, inventory_error = scan_payload(payload_root)
    if inventory_error:
        return 0, 0, inventory_error
    missing_files = sorted(set(expected_files) - set(actual_files))
    unexpected_files = sorted(set(actual_files) - set(expected_files))
    missing_directories = sorted(set(expected_directories) - set(actual_directories))
    unexpected_directories = sorted(set(actual_directories) - set(expected_directories))
    if missing_files:
        return 0, 0, "manifested payload files are missing: " + ", ".join(missing_files[:5])
    if unexpected_files:
        return 0, 0, "payload files are absent from manifest: " + ", ".join(unexpected_files[:5])
    if missing_directories:
        return 0, 0, "manifested payload directories are missing: " + ", ".join(missing_directories[:5])
    if unexpected_directories:
        return 0, 0, "payload directories are absent from manifest: " + ", ".join(unexpected_directories[:5])

    for relative, (expected_hash, expected_mode) in expected_files.items():
        path, actual_mode = actual_files[relative]
        mode_error = reduced_mode_error(expected_mode, actual_mode, relative, directory=False)
        if mode_error:
            return 0, 0, mode_error
        if sha256(path).lower() != expected_hash:
            return 0, 0, f"sha256 mismatch for {relative}"
    for relative, expected_mode in expected_directories.items():
        _, actual_mode = actual_directories[relative]
        mode_error = reduced_mode_error(expected_mode, actual_mode, relative, directory=True)
        if mode_error:
            return 0, 0, mode_error

    return len(expected_files), len(expected_directories), None


def safe_archive_entry(path: Path, *, directory: bool, executable: bool = False) -> str | None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        return f"archive entry must not be a symlink: {path.name}"
    expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_kind(metadata.st_mode):
        return f"archive entry has the wrong type: {path.name}"
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & UNSAFE_MODE_BITS:
        return f"archive entry has unsafe permissions: {path.name}"
    if not mode & stat.S_IRUSR:
        return f"archive entry is not owner-readable: {path.name}"
    if (directory or executable) and not mode & stat.S_IXUSR:
        return f"archive entry is not owner-executable: {path.name}"
    return None


def verify_package_json(path: Path, manifest: dict[str, object]) -> str | None:
    try:
        package = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return f"cannot read package.json: {exc}"
    version = manifest.get("package_version")
    expected_optional = {
        "@pairling/runtime-darwin-arm64": version,
        "@pairling/runtime-darwin-x64": version,
    }
    required = {
        "name": "pairling",
        "version": version,
        "type": "module",
        "bin": {"pairling": "bin/pairling.mjs"},
        "files": ["bin/pairling.mjs", "payload", "payload-manifest.json"],
        "os": ["darwin"],
        "engines": {"node": ">=20"},
        "publishConfig": {"access": "public"},
        "optionalDependencies": expected_optional,
    }
    for key, expected in required.items():
        if package.get(key) != expected:
            return f"package.json {key} does not match the publish policy"
    if not valid_repository(package.get("repository")):
        return "package.json repository does not match the publish policy"
    if "scripts" in package:
        return "package.json lifecycle scripts are forbidden"
    for key in FORBIDDEN_DEPENDENCY_KEYS:
        if key in package:
            return f"package.json {key} is forbidden"
    return None


def verify_archive_shape(
    package_root: Path,
    payload_root: Path,
    manifest_path: Path,
    manifest: dict[str, object],
) -> str | None:
    if payload_root.parent != package_root or payload_root.name != "payload":
        return "payload root is not the package payload directory"
    if manifest_path.parent != package_root or manifest_path.name != "payload-manifest.json":
        return "payload manifest is not at the package root"
    expected_root = {"README.md", "bin", "package.json", "payload", "payload-manifest.json"}
    actual_root = {path.name for path in package_root.iterdir()}
    missing = sorted(expected_root - actual_root)
    unexpected = sorted(actual_root - expected_root)
    if missing:
        return "archive root entries are missing: " + ", ".join(missing)
    if unexpected:
        return "archive root has unexpected entries: " + ", ".join(unexpected)

    checks = (
        (package_root, True, False),
        (package_root / "bin", True, False),
        (package_root / "README.md", False, False),
        (package_root / "package.json", False, False),
        (manifest_path, False, False),
        (package_root / "bin" / "pairling.mjs", False, True),
    )
    for path, directory, executable in checks:
        entry_error = safe_archive_entry(path, directory=directory, executable=executable)
        if entry_error:
            return entry_error
    bin_entries = {path.name for path in (package_root / "bin").iterdir()}
    if bin_entries != {"pairling.mjs"}:
        return "archive bin directory has unexpected entries"
    policy_error = verify_package_json(package_root / "package.json", manifest)
    if policy_error:
        return policy_error
    try:
        acl_paths = extended_acl_paths(package_root)
    except OSError as exc:
        return f"could not inspect archive ACLs: {exc}"
    if acl_paths:
        return "archive contains extended ACLs: " + ", ".join(acl_paths[:5])
    return None


def main() -> int:
    args = sys.argv[1:]
    archive_mode = bool(args and args[0] == "--archive")
    if archive_mode:
        args = args[1:]
    if len(args) != 2:
        return fail(
            "usage: verify-payload-manifest.py [--archive] "
            "<payload-root> <payload-manifest.json>"
        )
    payload_input = Path(args[0])
    manifest_input = Path(args[1])
    if payload_input.is_symlink() or not payload_input.is_dir():
        return fail("payload root must be a real directory")
    if manifest_input.is_symlink() or not manifest_input.is_file():
        return fail("payload manifest must be a regular file, not a symlink")
    payload_root = payload_input.resolve()
    manifest_path = manifest_input.resolve()
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return fail(f"cannot read manifest: {exc}")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 2:
        return fail("unsupported manifest schema")
    if manifest.get("package") != "pairling" or not isinstance(manifest.get("package_version"), str):
        return fail("manifest package identity is invalid")
    if not isinstance(manifest.get("source_revision"), str):
        return fail("manifest source revision is invalid")
    if not isinstance(manifest.get("source_dirty"), bool):
        return fail("manifest source dirty flag is invalid")
    evidence_sha256 = manifest.get("release_evidence_sha256")
    if evidence_sha256 is not None and (
        not isinstance(evidence_sha256, str)
        or len(evidence_sha256) != 64
        or any(character not in "0123456789abcdef" for character in evidence_sha256)
    ):
        return fail("manifest release evidence digest is invalid")
    python_archives = manifest.get("python_archives")
    if not isinstance(python_archives, dict) or set(python_archives) != {"darwin-arm64", "darwin-x64"}:
        return fail("manifest Python archive architecture map is invalid")
    for architecture in ("arm64", "x64"):
        digest = python_archives.get(f"darwin-{architecture}")
        if digest is not None and (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            return fail(f"manifest Python archive {architecture} digest is invalid")
    runtime_manifests = manifest.get("runtime_manifests")
    if not isinstance(runtime_manifests, dict) or set(runtime_manifests) != {"darwin-arm64", "darwin-x64"}:
        return fail("manifest runtime architecture map is invalid")
    for architecture in ("arm64", "x64"):
        digest = runtime_manifests.get(f"darwin-{architecture}")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            return fail(f"manifest runtime {architecture} digest is invalid")
    connectd = manifest.get("connectd")
    if not isinstance(connectd, dict) or set(connectd) != {"darwin-arm64", "darwin-x64"}:
        return fail("manifest connectd architecture map is invalid")
    for architecture in ("arm64", "x64"):
        identity = connectd.get(f"darwin-{architecture}")
        if not isinstance(identity, dict):
            return fail(f"manifest connectd {architecture} identity is invalid")
        digest = identity.get("sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or identity.get("identifier") != "dev.pairling.connectd"
            or identity.get("architecture") != architecture
            or (identity.get("team_id") is not None and not isinstance(identity.get("team_id"), str))
        ):
            return fail(f"manifest connectd {architecture} identity is invalid")

    file_count, directory_count, entry_error = verify_manifest_entries(payload_root, manifest)
    if entry_error:
        return fail(entry_error)
    try:
        acl_paths = extended_acl_paths(payload_root)
    except OSError as exc:
        return fail(f"could not inspect payload ACLs: {exc}")
    if acl_paths:
        return fail("payload contains extended ACLs: " + ", ".join(acl_paths[:5]))
    if archive_mode:
        shape_error = verify_archive_shape(manifest_path.parent, payload_root, manifest_path, manifest)
        if shape_error:
            return fail(shape_error)
    print(f"payload manifest verified: {file_count} files, {directory_count} directories")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
