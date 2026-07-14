#!/usr/bin/env python3
"""Local Mac commands for the PairDrop managed vault."""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import BinaryIO

from pairdrop_store import PairDropStore, PairDropStoreError
from runtime_paths import pairdrop_root


CHUNK_BYTES = 4 * 1024 * 1024
SOURCE_DEVICE_ID = "pairling-mac-cli"
SOURCE_INSTALL_ID = "local-mac"
SOURCE_ROUTE = "pairling-mac-cli"


class PairDropCLIError(ValueError):
    pass


def _vault_root() -> Path:
    return pairdrop_root()


def _snapshot(handle: BinaryIO) -> tuple[int, int, int, int, int]:
    value = os.fstat(handle.fileno())
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _open_regular_file(path: Path) -> BinaryIO:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PairDropCLIError(f"Could not open {path}: {exc.strerror or exc}") from exc
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISREG(value.st_mode):
            raise PairDropCLIError("PairDrop can add regular files only.")
        if value.st_size <= 0:
            raise PairDropCLIError("PairDrop cannot add an empty file.")
        return os.fdopen(descriptor, "rb", closefd=True)
    except Exception:
        os.close(descriptor)
        raise


def _hash_open_file(handle: BinaryIO, identity: tuple[int, int, int, int, int]) -> str:
    digest = hashlib.sha256()
    handle.seek(0)
    while True:
        chunk = handle.read(CHUNK_BYTES)
        if not chunk:
            break
        digest.update(chunk)
    if _snapshot(handle) != identity:
        raise PairDropCLIError("The source file changed while PairDrop was reading it.")
    return digest.hexdigest()


def _create_key(path: Path, identity: tuple[int, int, int, int, int], digest: str) -> str:
    value = "\0".join((os.path.abspath(path), str(identity[2]), str(identity[3]), digest))
    return "mac-cli-" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _public_file(item: dict) -> dict:
    return {
        key: item.get(key)
        for key in (
            "id",
            "kind",
            "display_name",
            "content_type",
            "byte_size",
            "sha256",
            "created_at",
            "updated_at",
        )
    }


def _emit(value: dict, *, json_mode: bool, message: str) -> None:
    if json_mode:
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    else:
        print(message)


def _add(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser()
    store = PairDropStore(_vault_root())
    with _open_regular_file(path) as handle:
        identity = _snapshot(handle)
        if identity[2] > store.max_transfer_bytes:
            raise PairDropCLIError(
                f"The file exceeds PairDrop's {store.max_transfer_bytes}-byte transfer limit."
            )
        digest = _hash_open_file(handle, identity)
        session = store.create_upload_session(
            filename=path.name,
            content_type=mimetypes.guess_type(path.name)[0] or "application/octet-stream",
            total_byte_count=identity[2],
            expected_sha256=digest,
            source_device_id=SOURCE_DEVICE_ID,
            source_install_id=SOURCE_INSTALL_ID,
            source_route=SOURCE_ROUTE,
            create_idempotency_key=_create_key(path, identity, digest),
        )
        upload_id = str(session["upload_id"])
        try:
            offset = int(session.get("verified_offset") or 0)
            if offset < 0 or offset > identity[2]:
                raise PairDropCLIError("PairDrop returned an invalid saved upload offset.")
            handle.seek(offset)
            while offset < identity[2]:
                if _snapshot(handle) != identity:
                    raise PairDropCLIError("The source file changed while PairDrop was adding it.")
                chunk = handle.read(min(CHUNK_BYTES, identity[2] - offset))
                if not chunk:
                    raise PairDropCLIError("The source file ended before its recorded size.")
                chunk_digest = hashlib.sha256(chunk).hexdigest()
                session = store.write_upload_chunk(
                    upload_id,
                    offset=offset,
                    declared_total_byte_count=identity[2],
                    data=chunk,
                    chunk_sha256=chunk_digest,
                    idempotency_key=f"mac-cli:{offset}:{chunk_digest}",
                    source_device_id=SOURCE_DEVICE_ID,
                    source_install_id=SOURCE_INSTALL_ID,
                )
                offset = int(session.get("verified_offset") or (offset + len(chunk)))
            if _snapshot(handle) != identity:
                raise PairDropCLIError("The source file changed before PairDrop finished adding it.")
            result = store.complete_upload_session(
                upload_id,
                source_device_id=SOURCE_DEVICE_ID,
                source_install_id=SOURCE_INSTALL_ID,
            )
        except PairDropCLIError:
            try:
                store.cancel_upload_session(
                    upload_id,
                    source_device_id=SOURCE_DEVICE_ID,
                    source_install_id=SOURCE_INSTALL_ID,
                )
            except (OSError, PairDropStoreError):
                pass
            raise

    item = _public_file(result["file"])
    _emit(
        {"ok": True, "file": item, "vault": str(store.root)},
        json_mode=args.json,
        message=f"Added {item['display_name']} to PairDrop ({item['id']}).",
    )
    return 0


def _list(args: argparse.Namespace) -> int:
    store = PairDropStore(_vault_root())
    page = store.list_files_page(limit=args.limit)
    files = [_public_file(item) for item in page["files"]]
    if args.json:
        _emit(
            {"ok": True, "files": files, "has_more": page["has_more"], "vault": str(store.root)},
            json_mode=True,
            message="",
        )
        return 0
    if not files:
        print(f"PairDrop is empty. Managed vault: {store.root}")
        return 0
    for item in files:
        print(f"{item['id']}\t{item['byte_size']}\t{item['display_name']}")
    if page["has_more"]:
        print(f"Showing the newest {len(files)} files. Use --limit to change the page size.", file=sys.stderr)
    return 0


def _destination_file(directory: Path, filename: str) -> Path:
    directory = directory.expanduser()
    try:
        value = directory.lstat()
    except OSError as exc:
        raise PairDropCLIError(f"Could not open export folder {directory}: {exc.strerror or exc}") from exc
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISDIR(value.st_mode):
        raise PairDropCLIError("The export destination must be a real folder, not a symlink.")
    destination = directory / filename
    if destination.exists() or destination.is_symlink():
        raise PairDropCLIError(f"Refusing to replace existing file: {destination}")
    return destination


def _export(args: argparse.Namespace) -> int:
    store = PairDropStore(_vault_root())
    descriptor = store.download_descriptor(args.file_id)
    item = descriptor["item"]
    source = Path(descriptor["path"])
    destination = _destination_file(Path(args.to), str(item["display_name"]))
    temporary_fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.pairdrop-",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    byte_count = 0
    try:
        with os.fdopen(temporary_fd, "wb") as output_handle, _open_regular_file(source) as input_handle:
            identity = _snapshot(input_handle)
            while True:
                chunk = input_handle.read(CHUNK_BYTES)
                if not chunk:
                    break
                output_handle.write(chunk)
                digest.update(chunk)
                byte_count += len(chunk)
            output_handle.flush()
            os.fsync(output_handle.fileno())
            if _snapshot(input_handle) != identity:
                raise PairDropCLIError("The PairDrop object changed while it was exported.")
        if byte_count != int(item["byte_size"]) or digest.hexdigest() != str(item["sha256"]):
            raise PairDropCLIError("PairDrop export verification failed.")
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError as exc:
            raise PairDropCLIError(f"Refusing to replace existing file: {destination}") from exc
        temporary.unlink()
        directory_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
    _emit(
        {"ok": True, "file": _public_file(item), "path": str(destination)},
        json_mode=args.json,
        message=f"Exported {item['display_name']} to {destination}.",
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pairling pairdrop", description="Manage Pairling's local PairDrop vault.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    add = subparsers.add_parser("add", help="Add a Mac file to PairDrop.")
    add.add_argument("path")
    add.add_argument("--json", action="store_true")
    add.set_defaults(run=_add)

    listing = subparsers.add_parser("list", help="List files in PairDrop.")
    listing.add_argument("--limit", type=int, choices=range(1, 201), default=100, metavar="1-200")
    listing.add_argument("--json", action="store_true")
    listing.set_defaults(run=_list)

    export = subparsers.add_parser("export", help="Export a verified PairDrop file to a Mac folder.")
    export.add_argument("file_id")
    export.add_argument("--to", default="~/Downloads", metavar="FOLDER")
    export.add_argument("--json", action="store_true")
    export.set_defaults(run=_export)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        return int(args.run(args))
    except (ValueError, PairDropStoreError, OSError) as exc:
        code = exc.code if isinstance(exc, PairDropStoreError) else "pairdrop_cli_error"
        if getattr(args, "json", False):
            print(json.dumps({"ok": False, "error": {"code": code, "message": str(exc)}}))
        else:
            print(f"PairDrop: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
