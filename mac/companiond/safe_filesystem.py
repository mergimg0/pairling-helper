#!/usr/bin/env python3
"""Descriptor-relative filesystem boundaries for remotely supplied paths."""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class UnsafeFilesystemPath(PermissionError):
    pass


@dataclass(frozen=True)
class AuthorizedPath:
    root: Path
    path: Path


_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_UNSAFE_OPEN_ERRNOS = {errno.ELOOP, errno.ENOTDIR}


def _absolute_path(value: str | Path, *, label: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    if ".." in path.parts:
        raise ValueError("path traversal rejected")
    return Path(os.path.abspath(path))


def _same_opened_inode(metadata: os.stat_result, descriptor: int) -> bool:
    opened = os.fstat(descriptor)
    return metadata.st_dev == opened.st_dev and metadata.st_ino == opened.st_ino


def _open_directory_component(parent_fd: int, name: str, path: Path) -> int:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        raise
    if stat.S_ISLNK(metadata.st_mode):
        raise UnsafeFilesystemPath(f"symlink directory component rejected: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise NotADirectoryError(str(path))
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in _UNSAFE_OPEN_ERRNOS:
            raise UnsafeFilesystemPath(f"unsafe directory component rejected: {path}") from exc
        raise
    try:
        if not _same_opened_inode(metadata, descriptor):
            raise UnsafeFilesystemPath(f"directory component changed while opening: {path}")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise

def open_child_directory_fd(parent_fd: int, name: str) -> int:
    """Open one directory entry relative to an already-authorized descriptor."""
    if not name or name in {".", ".."} or Path(name).name != name:
        raise ValueError("directory entry name is invalid")
    return _open_directory_component(parent_fd, name, Path(name))


def open_directory_fd(path: str | Path, *, root: str | Path | None = None) -> int:
    """Open an existing directory without following any component or target symlink."""

    target = _absolute_path(path, label="directory path")
    boundary = _absolute_path(root, label="authorized root") if root is not None else Path(target.anchor)
    try:
        relative = target.relative_to(boundary)
    except ValueError as exc:
        raise UnsafeFilesystemPath(f"path is outside authorized root: {target}") from exc

    descriptor = os.open(boundary.anchor, _DIRECTORY_FLAGS)
    current = Path(boundary.anchor)
    try:
        for component in boundary.parts[1:]:
            current = current / component
            child_fd = _open_directory_component(descriptor, component, current)
            os.close(descriptor)
            descriptor = child_fd
        for component in relative.parts:
            current = current / component
            child_fd = _open_directory_component(descriptor, component, current)
            os.close(descriptor)
            descriptor = child_fd
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def ensure_directory_fd(
    path: str | Path,
    *,
    root: str | Path,
    mode: int = 0o700,
) -> int:
    """Create a directory beneath an existing root without following symlinks."""

    target = _absolute_path(path, label="directory path")
    boundary = _absolute_path(root, label="authorized root")
    try:
        relative = target.relative_to(boundary)
    except ValueError as exc:
        raise UnsafeFilesystemPath(f"path is outside authorized root: {target}") from exc

    descriptor = open_directory_fd(boundary)
    current = boundary
    try:
        for component in relative.parts:
            current = current / component
            try:
                child_fd = _open_directory_component(descriptor, component, current)
            except FileNotFoundError:
                os.mkdir(component, mode, dir_fd=descriptor)
                child_fd = _open_directory_component(descriptor, component, current)
            os.close(descriptor)
            descriptor = child_fd
        os.fchmod(descriptor, mode)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_regular_file_component(parent_fd: int, name: str, path: Path) -> int:
    metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if stat.S_ISLNK(metadata.st_mode):
        raise UnsafeFilesystemPath(f"symlink file target rejected: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise UnsafeFilesystemPath(f"non-regular file target rejected: {path}")
    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in _UNSAFE_OPEN_ERRNOS:
            raise UnsafeFilesystemPath(f"unsafe file target rejected: {path}") from exc
        raise
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_opened_inode(metadata, descriptor):
            raise UnsafeFilesystemPath(f"file changed while opening: {path}")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def open_child_regular_file_fd(parent_fd: int, name: str) -> int:
    """Open one regular file relative to an already-authorized descriptor."""
    if not name or name in {".", ".."} or Path(name).name != name:
        raise ValueError("file entry name is invalid")
    return _open_regular_file_component(parent_fd, name, Path(name))


def open_regular_file_fd(path: str | Path, *, root: str | Path) -> int:
    """Open a regular file beneath root with descriptor-stable containment."""

    target = _absolute_path(path, label="file path")
    boundary = _absolute_path(root, label="authorized root")
    try:
        relative = target.relative_to(boundary)
    except ValueError as exc:
        raise UnsafeFilesystemPath(f"path is outside authorized root: {target}") from exc
    if not relative.parts:
        raise IsADirectoryError(str(target))

    parent = boundary.joinpath(*relative.parts[:-1])
    parent_fd = open_directory_fd(parent, root=boundary)
    try:
        return _open_regular_file_component(
            parent_fd,
            relative.parts[-1],
            target,
        )
    finally:
        os.close(parent_fd)


def authorize_path(raw_path: str | Path, *, roots: Iterable[str | Path]) -> AuthorizedPath:
    """Map a lexical path into one trusted canonical root without resolving the path."""

    candidate = _absolute_path(raw_path, label="path")
    for raw_root in roots:
        configured_root = _absolute_path(raw_root, label="authorized root")
        canonical_root = configured_root.resolve(strict=True)
        for prefix in (configured_root, canonical_root):
            try:
                relative = candidate.relative_to(prefix)
            except ValueError:
                continue
            return AuthorizedPath(canonical_root, canonical_root / relative)
    raise UnsafeFilesystemPath(f"path is outside authorized roots: {candidate}")


def validate_directory(path: str | Path, *, root: str | Path) -> Path:
    target = _absolute_path(path, label="directory path")
    descriptor = open_directory_fd(target, root=root)
    os.close(descriptor)
    return target


def validate_regular_file(path: str | Path, *, root: str | Path) -> Path:
    target = _absolute_path(path, label="file path")
    descriptor = open_regular_file_fd(target, root=root)
    os.close(descriptor)
    return target
