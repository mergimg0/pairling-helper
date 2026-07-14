#!/usr/bin/env python3
"""Verify an npm platform runtime package and its publishable archive shape."""

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
    "optionalDependencies",
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
    print(f"runtime package manifest verification failed: {message}", file=sys.stderr)
    return 1


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_relative(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    path = Path(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        return None
    if not path.parts or path.parts[0] not in {"bin", "python"}:
        return None
    return path.as_posix()


def parse_expected_mode(value: object, relative: str, *, directory: bool) -> tuple[int, str] | str:
    if (
        not isinstance(value, str)
        or len(value) != 4
        or any(character not in "01234567" for character in value)
    ):
        return f"manifest contains an invalid mode for {relative}"
    mode = int(value, 8)
    if mode & UNSAFE_MODE_BITS:
        return f"manifest contains unsafe permissions for {relative}"
    if not mode & stat.S_IRUSR:
        return f"manifest omits owner read permission for {relative}"
    if directory and not mode & stat.S_IXUSR:
        return f"manifest directory is not owner-searchable: {relative}"
    return mode, value


def reduced_mode_error(expected: int, actual: int, relative: str, *, directory: bool) -> str | None:
    if actual & UNSAFE_MODE_BITS:
        return f"runtime package contains unsafe permissions for {relative}"
    if actual & ~expected:
        return f"runtime package permissions exceed the manifest for {relative}"
    if not actual & stat.S_IRUSR:
        return f"runtime package omits owner read permission for {relative}"
    if (directory or expected & 0o111) and not actual & stat.S_IXUSR:
        return f"runtime package omits required owner execute permission for {relative}"
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


def inventory(
    root: Path,
    *,
    require_python: bool,
) -> tuple[dict[str, tuple[Path, int]], dict[str, tuple[Path, int]], str | None]:
    files: dict[str, tuple[Path, int]] = {}
    directories: dict[str, tuple[Path, int]] = {}
    tops = [root / "bin"]
    if require_python or (root / "python").exists():
        tops.append(root / "python")
    for top in tops:
        if not top.is_dir() or top.is_symlink():
            return {}, {}, f"required runtime directory is missing or linked: {top.name}"
        top_relative = top.relative_to(root).as_posix()
        directories[top_relative] = (top, stat.S_IMODE(top.lstat().st_mode))
        for path in sorted(top.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if path.name == "__pycache__" or path.suffix == ".pyc":
                return {}, {}, f"runtime package contains forbidden Python bytecode: {relative}"
            if stat.S_ISLNK(metadata.st_mode):
                return {}, {}, f"runtime package contains a forbidden symlink: {relative}"
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISDIR(metadata.st_mode):
                directories[relative] = (path, mode)
            elif stat.S_ISREG(metadata.st_mode):
                files[relative] = (path, mode)
            else:
                return {}, {}, f"runtime package contains an unsupported entry: {relative}"
    return files, directories, None


def verify_manifest_entries(root: Path, manifest: dict[str, object]) -> tuple[int, int, str | None]:
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
        relative = safe_relative(item.get("path"))
        if relative is None:
            return 0, 0, f"manifest contains an unsafe path: {item.get('path')!r}"
        if relative in expected_files:
            return 0, 0, f"manifest contains a duplicate path: {relative}"
        if relative.endswith(".pyc") or "__pycache__" in Path(relative).parts:
            return 0, 0, f"manifest contains forbidden Python bytecode: {relative}"
        if (item.get("kind") or "file") != "file":
            return 0, 0, f"manifest contains an unsupported kind for {relative}"
        digest = item.get("sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest.lower())
        ):
            return 0, 0, f"manifest contains an invalid hash for {relative}"
        parsed_mode = parse_expected_mode(item.get("mode"), relative, directory=False)
        if isinstance(parsed_mode, str):
            return 0, 0, parsed_mode
        expected_files[relative] = (digest.lower(), parsed_mode[0])

    expected_directories: dict[str, int] = {}
    for item in raw_directories:
        if not isinstance(item, dict):
            return 0, 0, "manifest directory entry is not an object"
        relative = safe_relative(item.get("path"))
        if relative is None:
            return 0, 0, f"manifest contains an unsafe directory path: {item.get('path')!r}"
        if relative in expected_directories:
            return 0, 0, f"manifest contains a duplicate directory path: {relative}"
        if relative in expected_files:
            return 0, 0, f"manifest path is both a file and directory: {relative}"
        parsed_mode = parse_expected_mode(item.get("mode"), relative, directory=True)
        if isinstance(parsed_mode, str):
            return 0, 0, parsed_mode
        expected_directories[relative] = parsed_mode[0]

    require_python = any(path == "python" or path.startswith("python/") for path in expected_directories)
    actual_files, actual_directories, inventory_error = inventory(root, require_python=require_python)
    if inventory_error:
        return 0, 0, inventory_error
    missing_files = sorted(set(expected_files) - set(actual_files))
    unexpected_files = sorted(set(actual_files) - set(expected_files))
    missing_directories = sorted(set(expected_directories) - set(actual_directories))
    unexpected_directories = sorted(set(actual_directories) - set(expected_directories))
    if missing_files:
        return 0, 0, "runtime package files are missing: " + ", ".join(missing_files[:5])
    if unexpected_files:
        return 0, 0, "runtime package files are absent from manifest: " + ", ".join(unexpected_files[:5])
    if missing_directories:
        return 0, 0, "runtime package directories are missing: " + ", ".join(missing_directories[:5])
    if unexpected_directories:
        return 0, 0, "runtime package directories are absent from manifest: " + ", ".join(unexpected_directories[:5])

    for relative, (expected_hash, expected_mode) in expected_files.items():
        path, actual_mode = actual_files[relative]
        mode_error = reduced_mode_error(expected_mode, actual_mode, relative, directory=False)
        if mode_error:
            return 0, 0, mode_error
        if sha256_file(path).lower() != expected_hash:
            return 0, 0, f"runtime package entry mismatch for {relative}"
    for relative, expected_mode in expected_directories.items():
        _, actual_mode = actual_directories[relative]
        mode_error = reduced_mode_error(expected_mode, actual_mode, relative, directory=True)
        if mode_error:
            return 0, 0, mode_error
    return len(expected_files), len(expected_directories), None


def safe_archive_entry(path: Path, *, directory: bool) -> str | None:
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
    if directory and not mode & stat.S_IXUSR:
        return f"archive directory is not owner-searchable: {path.name}"
    return None


def verify_package_json(path: Path, version: str) -> tuple[bool, str | None]:
    try:
        package = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"cannot read package.json: {exc}"
    cpu = package.get("cpu")
    if cpu not in (["arm64"], ["x64"]):
        return False, "package.json cpu does not match the publish policy"
    arch = cpu[0]
    required = {
        "name": f"@pairling/runtime-darwin-{arch}",
        "version": version,
        "files": ["bin", "python", "manifest.json"],
        "os": ["darwin"],
        "engines": {"node": ">=20"},
        "publishConfig": {"access": "public"},
    }
    for key, expected in required.items():
        if package.get(key) != expected:
            return False, f"package.json {key} does not match the publish policy"
    if not valid_repository(package.get("repository")):
        return False, "package.json repository does not match the publish policy"
    if "bin" in package:
        return False, "runtime package must not expose commands"
    if "scripts" in package:
        return False, "package.json lifecycle scripts are forbidden"
    for key in FORBIDDEN_DEPENDENCY_KEYS:
        if key in package:
            return False, f"package.json {key} is forbidden"
    return True, None


def verify_archive_shape(root: Path, manifest: dict[str, object], version: str) -> str | None:
    has_python = any(
        isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and (item["path"] == "python" or item["path"].startswith("python/"))
        for item in manifest.get("directories", [])
    )
    expected_root = {"README.md", "bin", "manifest.json", "package.json"}
    if has_python:
        expected_root.add("python")
    actual_root = {path.name for path in root.iterdir()}
    missing = sorted(expected_root - actual_root)
    unexpected = sorted(actual_root - expected_root)
    if missing:
        return "archive root entries are missing: " + ", ".join(missing)
    if unexpected:
        return "archive root has unexpected entries: " + ", ".join(unexpected)
    checks = (
        (root, True),
        (root / "bin", True),
        (root / "README.md", False),
        (root / "manifest.json", False),
        (root / "package.json", False),
    )
    for path, directory in checks:
        entry_error = safe_archive_entry(path, directory=directory)
        if entry_error:
            return entry_error
    _, policy_error = verify_package_json(root / "package.json", version)
    if policy_error:
        return policy_error
    try:
        acl_paths = extended_acl_paths(root)
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
    if len(args) != 3:
        return fail(
            "usage: verify-runtime-package-manifest.py [--archive] "
            "<runtime-package-root> <expected-version> <expected-source-revision>"
        )
    root_input = Path(args[0])
    if root_input.is_symlink() or not root_input.is_dir():
        return fail("runtime package root must be a real directory")
    root = root_input.resolve()
    expected_version = args[1]
    expected_revision = args[2]
    manifest_path = root / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        return fail("runtime package manifest must be a regular file, not a symlink")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return fail(f"cannot read manifest: {exc}")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 2:
        return fail("unsupported manifest schema")
    if manifest.get("package_version") != expected_version:
        return fail("package version does not match the Pairling payload")
    if manifest.get("source_revision") != expected_revision:
        return fail("source revision does not match the Pairling payload")
    architecture = manifest.get("architecture")
    if architecture not in ("arm64", "x64"):
        return fail("runtime package architecture is missing or unsupported")
    evidence_sha256 = manifest.get("release_evidence_sha256")
    if evidence_sha256 is not None and (
        not isinstance(evidence_sha256, str)
        or len(evidence_sha256) != 64
        or any(character not in "0123456789abcdef" for character in evidence_sha256)
    ):
        return fail("runtime package release evidence digest is invalid")
    if "python_archive_sha256" not in manifest:
        return fail("runtime package Python archive digest is missing")
    python_archive_sha256 = manifest.get("python_archive_sha256")
    if python_archive_sha256 is not None and (
        not isinstance(python_archive_sha256, str)
        or len(python_archive_sha256) != 64
        or any(character not in "0123456789abcdef" for character in python_archive_sha256)
    ):
        return fail("runtime package Python archive digest is invalid")
    identity_entries = {
        item.get("path"): item
        for item in manifest.get("files", [])
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    connectd = identity_entries.get("bin/pairling-connectd")
    if not isinstance(connectd, dict) or connectd.get("identifier") != "dev.pairling.connectd" \
            or connectd.get("architecture") != architecture:
        return fail("connectd identity is missing or does not match the runtime architecture")
    python_entry = identity_entries.get("python/bin/python3")
    if (python_entry is None) != (python_archive_sha256 is None):
        return fail("runtime package Python archive digest does not match vendored Python presence")
    if python_entry is not None and (
        not isinstance(python_entry, dict)
        or python_entry.get("identifier") != "dev.pairling.python"
        or python_entry.get("architecture") != architecture
        or (connectd.get("team_id") and python_entry.get("team_id") != connectd.get("team_id"))
    ):
        return fail("vendored Python identity is missing or does not match connectd")

    file_count, directory_count, entry_error = verify_manifest_entries(root, manifest)
    if entry_error:
        return fail(entry_error)
    scope_roots = [root / "bin"]
    if (root / "python").exists():
        scope_roots.append(root / "python")
    try:
        acl_paths = [
            f"{scope.name}/{relative}" if relative != "." else scope.name
            for scope in scope_roots
            for relative in extended_acl_paths(scope)
        ]
    except OSError as exc:
        return fail(f"could not inspect runtime package ACLs: {exc}")
    if acl_paths:
        return fail("runtime package contains extended ACLs: " + ", ".join(acl_paths[:5]))
    if archive_mode:
        shape_error = verify_archive_shape(root, manifest, expected_version)
        if shape_error:
            return fail(shape_error)
    print(f"runtime package manifest verified: {file_count} files, {directory_count} directories")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
