"""User-authored prompt postures stored as markdown files on the Mac.

The daemon is not the only possible writer. A user may edit these files in an
editor, so every mutating API can compare a content revision before changing a
file. Daemon writers also share an in-process lock and a filesystem lock so the
threaded HTTP server and another daemon process cannot race each other.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Callable, Iterator

POSTURE_MAX_BYTES = 8 * 1024
_SLUG_RE = re.compile(r"^[a-z0-9-]{1,64}$")
_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?", re.DOTALL)
_PROCESS_LOCK = threading.RLock()
_RENAME_SWAP = 0x00000002
_RENAME_EXCL = 0x00000004
_TRANSACTION_DIR_NAME = ".posture-transactions"
_CONFLICT_DIR_NAME = "Pairling Posture Conflicts"


class PostureTooLarge(ValueError):
    """The posture body exceeds POSTURE_MAX_BYTES."""


class PostureConflict(ValueError):
    """A mutation was based on stale state or would replace another posture."""

    def __init__(
        self,
        message: str,
        *,
        current: dict | None = None,
        conflict_copies: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.current = current
        self.conflict_copies = list(conflict_copies or [])


class PostureNotFound(PostureConflict):
    """A versioned mutation targeted a posture that was removed elsewhere."""


class PostureIOError(OSError):
    """A posture path exists but could not be read or written safely."""

    code = "posture_io_failed"


class PostureInvalidEncoding(PostureIOError):
    """A posture file is not valid UTF-8."""

    code = "posture_invalid_encoding"


class PostureCrashSimulation(BaseException):
    """Test-only process-stop checkpoint that deliberately skips cleanup."""


def default_root() -> Path:
    return Path(os.path.expanduser("~")) / ".pairling" / "postures"


def valid_slug(slug: str) -> bool:
    return bool(_SLUG_RE.match(slug or ""))


def slug_for_name(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return slug[:64]


def _parse_frontmatter(source: str) -> tuple[dict, str]:
    match = _FRONTMATTER_RE.match(source)
    if not match:
        return {}, source
    fields: dict = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip().lower()] = value.strip()
    return fields, source[match.end():]


def _revision(source: bytes) -> str:
    return hashlib.sha256(source).hexdigest()


def _read_path(path: Path, slug: str, *, include_source: bool) -> dict | None:
    try:
        with path.open("rb") as handle:
            source_bytes = handle.read()
            stat = os.fstat(handle.fileno())
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PostureIOError(f"could not read posture file {path.name}") from exc
    try:
        source = source_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PostureInvalidEncoding(f"posture file {path.name} is not valid UTF-8") from exc
    fields, body = _parse_frontmatter(source)
    row = {
        "slug": slug,
        "name": fields.get("name") or slug,
        "description": fields.get("description") or "",
        "mtime": stat.st_mtime,
        "revision": _revision(source_bytes),
    }
    if include_source:
        row.update({"body": body.strip(), "source": source})
    return row


@contextlib.contextmanager
def _store_lock(root: Path) -> Iterator[None]:
    try:
        root.mkdir(parents=True, exist_ok=True)
        lock_path = root / ".postures.lock"
        with _PROCESS_LOCK:
            descriptor = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                _recover_transactions(root)
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
    except PostureIOError:
        raise
    except OSError as exc:
        raise PostureIOError("could not lock the posture store") from exc


def _fsync_directory(root: Path) -> None:
    descriptor = os.open(str(root), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _path_revision(path: Path) -> str | None:
    try:
        return _revision(path.read_bytes())
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PostureIOError(f"could not read posture transaction file {path.name}") from exc


def _atomic_swap(first: Path, second: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renamex_np = getattr(libc, "renamex_np", None)
    if renamex_np is None:
        raise PostureIOError("this Mac does not provide atomic posture swaps")
    renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    renamex_np.restype = ctypes.c_int
    result = renamex_np(os.fsencode(first), os.fsencode(second), _RENAME_SWAP)
    if result != 0:
        error_number = ctypes.get_errno()
        raise PostureIOError(
            f"atomic posture swap failed: {os.strerror(error_number)}"
        ) from OSError(error_number, os.strerror(error_number))


def _atomic_move_exclusive(source: Path, destination: Path) -> None:
    """Move one name without a link/unlink window or target replacement."""

    libc = ctypes.CDLL(None, use_errno=True)
    renamex_np = getattr(libc, "renamex_np", None)
    if renamex_np is None:
        raise PostureIOError("this Mac does not provide exclusive posture renames")
    renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    renamex_np.restype = ctypes.c_int
    result = renamex_np(
        os.fsencode(source),
        os.fsencode(destination),
        _RENAME_EXCL,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise FileExistsError(
            error_number,
            os.strerror(error_number),
            str(destination),
        )
    if error_number == errno.ENOENT:
        raise FileNotFoundError(
            error_number,
            os.strerror(error_number),
            str(source),
        )
    raise PostureIOError(
        f"atomic posture rename failed: {os.strerror(error_number)}"
    ) from OSError(error_number, os.strerror(error_number))


def _transaction_dir(root: Path) -> Path:
    path = root / _TRANSACTION_DIR_NAME
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def _write_transaction_marker(root: Path, transaction: dict) -> Path:
    directory = _transaction_dir(root)
    transaction_id = str(transaction["id"])
    marker = directory / f"{transaction_id}.json"
    descriptor, raw_temp = tempfile.mkstemp(prefix=f".{transaction_id}.", suffix=".tmp", dir=str(directory))
    temp = Path(raw_temp)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(transaction, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, marker)
        _fsync_directory(directory)
        _fsync_directory(root)
        return marker
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        temp.unlink(missing_ok=True)
        raise


def _remove_transaction_marker(root: Path, marker: Path) -> None:
    marker.unlink(missing_ok=True)
    _fsync_directory(marker.parent)
    _fsync_directory(root)


def _preserve_conflict_copy(root: Path, slug: str, source: Path, label: str) -> str:
    directory = root / _CONFLICT_DIR_NAME
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    safe_label = re.sub(r"[^a-z0-9-]+", "-", label.lower()).strip("-") or "conflict"
    destination = directory / f"{slug}.{safe_label}.{uuid.uuid4().hex}.md"
    try:
        os.link(source, destination)
        _fsync_directory(directory)
        _fsync_directory(root)
    except OSError as exc:
        raise PostureIOError("could not preserve a concurrent posture edit") from exc
    return str(destination.relative_to(root))


def _safe_transaction_path(root: Path, raw_name: object) -> Path | None:
    name = str(raw_name or "")
    if not name or Path(name).name != name:
        return None
    return root / name


def _recover_transactions(root: Path) -> None:
    directory = root / _TRANSACTION_DIR_NAME
    if not directory.exists():
        return
    try:
        markers = sorted(directory.glob("*.json"))
    except OSError as exc:
        raise PostureIOError("could not inspect posture recovery records") from exc
    for marker in markers:
        try:
            transaction = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PostureIOError(f"posture recovery record {marker.name} is unreadable") from exc
        if not isinstance(transaction, dict) or transaction.get("version") != 1:
            raise PostureIOError(f"posture recovery record {marker.name} is invalid")
        original = _safe_transaction_path(root, transaction.get("original"))
        target = _safe_transaction_path(root, transaction.get("target"))
        swap = _safe_transaction_path(root, transaction.get("swap"))
        slug = str(transaction.get("slug") or "posture")
        expected_revision = str(transaction.get("expected_revision") or "")
        new_revision = str(transaction.get("new_revision") or "")
        if original is None or target is None or swap is None:
            raise PostureIOError(f"posture recovery record {marker.name} has unsafe paths")

        original_revision = _path_revision(original)
        target_revision = _path_revision(target)
        swap_revision = _path_revision(swap)
        conflict_paths: list[str] = []

        if transaction.get("kind") == "delete":
            if swap_revision is not None:
                if swap_revision != expected_revision:
                    conflict_paths.append(_preserve_conflict_copy(root, slug, swap, "recovered-delete"))
                if original_revision is None:
                    os.replace(swap, original)
                else:
                    conflict_paths.append(_preserve_conflict_copy(root, slug, swap, "interrupted-delete"))
                    swap.unlink(missing_ok=True)
        elif original == target:
            if target_revision == new_revision and swap_revision is not None:
                if swap_revision != expected_revision:
                    conflict_paths.append(_preserve_conflict_copy(root, slug, swap, "recovered-editor-write"))
                _atomic_swap(swap, target)
                swap.unlink(missing_ok=True)
            elif target_revision == expected_revision and swap_revision == new_revision:
                swap.unlink(missing_ok=True)
            else:
                if target_revision not in {None, expected_revision, new_revision}:
                    conflict_paths.append(_preserve_conflict_copy(root, slug, target, "recovered-target"))
                if swap_revision not in {None, new_revision}:
                    conflict_paths.append(_preserve_conflict_copy(root, slug, swap, "recovered-swap"))
                if target_revision is None and swap_revision is not None:
                    os.replace(swap, target)
                else:
                    swap.unlink(missing_ok=True)
        else:
            # A rename transaction first swaps the new source into the old
            # path, then publishes it at the target. Roll every incomplete
            # shape back to the original path before exposing the store.
            if original_revision == new_revision and swap_revision is not None:
                if swap_revision != expected_revision:
                    conflict_paths.append(_preserve_conflict_copy(root, slug, swap, "recovered-editor-write"))
                if target_revision == new_revision:
                    target.unlink(missing_ok=True)
                _atomic_swap(swap, original)
                swap.unlink(missing_ok=True)
            elif original_revision is None and target_revision == new_revision and swap_revision is not None:
                if swap_revision != expected_revision:
                    conflict_paths.append(_preserve_conflict_copy(root, slug, swap, "recovered-editor-write"))
                target.unlink(missing_ok=True)
                os.replace(swap, original)
            elif original_revision == expected_revision and swap_revision == new_revision:
                swap.unlink(missing_ok=True)
            else:
                for path, revision, label in (
                    (original, original_revision, "recovered-original"),
                    (target, target_revision, "recovered-target"),
                    (swap, swap_revision, "recovered-swap"),
                ):
                    if revision not in {None, expected_revision, new_revision}:
                        conflict_paths.append(_preserve_conflict_copy(root, slug, path, label))
                swap.unlink(missing_ok=True)

        marker.unlink(missing_ok=True)
        _fsync_directory(root)
        _fsync_directory(directory)


def _frontmatter_value(value: str) -> str:
    # The on-disk parser is intentionally small. Keep a name or description
    # from injecting another frontmatter field while preserving readable text.
    return " ".join((value or "").strip().splitlines())


def _encoded_source(*, name: str, description: str, body: str) -> bytes:
    normalized_name = _frontmatter_value(name)
    normalized_description = _frontmatter_value(description)
    normalized_body = (body or "").strip()
    if len(normalized_body.encode("utf-8")) > POSTURE_MAX_BYTES:
        raise PostureTooLarge(f"posture body exceeds {POSTURE_MAX_BYTES} bytes")
    return (
        f"---\nname: {normalized_name}\ndescription: {normalized_description}\n---\n"
        f"{normalized_body}\n"
    ).encode("utf-8")


def _write_unique_temp(root: Path, target_slug: str, source: bytes) -> Path:
    descriptor, raw_path = tempfile.mkstemp(
        prefix=f".{target_slug}.",
        suffix=".tmp",
        dir=str(root),
    )
    path = Path(raw_path)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(source)
            handle.flush()
            os.fsync(handle.fileno())
        return path
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        path.unlink(missing_ok=True)
        raise


def list_postures(root: Path) -> list[dict]:
    rows: list[dict] = []
    if not root.exists():
        return rows
    with _store_lock(root):
        try:
            paths = sorted(root.glob("*.md"))
        except OSError as exc:
            raise PostureIOError("could not list posture files") from exc
        for path in paths:
            slug = path.stem
            if not valid_slug(slug):
                continue
            row = _read_path(path, slug, include_source=False)
            if row is not None:
                rows.append(row)
    return rows


def read_posture(root: Path, slug: str) -> dict | None:
    if not valid_slug(slug):
        return None
    if not root.exists():
        return None
    with _store_lock(root):
        return _read_path(root / f"{slug}.md", slug, include_source=True)


def mutate_posture(
    root: Path,
    *,
    name: str,
    description: str,
    body: str,
    original_slug: str | None = None,
    expected_revision: str | None = None,
    create_only: bool = False,
    checkpoint: Callable[[str, Path], None] | None = None,
) -> dict:
    """Create, edit, or rename a posture as one checked server operation.

    Creation requires ``create_only``. Edits provide ``original_slug`` and
    ``expected_revision`` so an external Mac edit cannot be overwritten.
    """

    target_slug = slug_for_name(name)
    if not valid_slug(target_slug):
        raise ValueError("posture name yields no usable slug")
    if original_slug is not None and not valid_slug(original_slug):
        raise ValueError("original posture slug is invalid")
    if original_slug is not None and not expected_revision:
        raise ValueError("expected_revision is required when editing a posture")
    if original_slug is None and not create_only:
        raise ValueError("create_only is required when creating a posture")

    source = _encoded_source(name=name, description=description, body=body)
    target_path = root / f"{target_slug}.md"
    original_path = root / f"{original_slug}.md" if original_slug else None

    with _store_lock(root):
        current: dict | None = None
        if original_path is not None and original_slug is not None:
            current = _read_path(original_path, original_slug, include_source=True)
            if current is None:
                raise PostureNotFound("This posture was removed from your Mac. Reload the posture list.")
            if current["revision"] != expected_revision:
                raise PostureConflict(
                    "This posture changed on your Mac. Reload it before saving.",
                    current=current,
                )

        if create_only and target_path.exists():
            existing = _read_path(target_path, target_slug, include_source=False)
            raise PostureConflict(
                "A posture with this name already exists. Choose another name or edit the existing posture.",
                current=existing,
            )

        renaming = original_path is not None and original_path != target_path
        if renaming and target_path.exists():
            existing = _read_path(target_path, target_slug, include_source=False)
            raise PostureConflict(
                "Another posture already uses this name. Choose another name.",
                current=existing,
            )

        temp_path = _write_unique_temp(root, target_slug, source)
        intended_revision = _revision(source)
        overwrote = target_path.exists()
        marker: Path | None = None
        preserve_transaction = False
        transaction_finished = False
        swap_started = False
        try:
            if create_only:
                try:
                    os.link(temp_path, target_path)
                except FileExistsError as exc:
                    existing = _read_path(target_path, target_slug, include_source=False)
                    raise PostureConflict(
                        "A posture with this name already exists. Choose another name or edit the existing posture.",
                        current=existing,
                    ) from exc
                temp_path.unlink()
                overwrote = False
            elif original_path is not None and original_slug is not None and expected_revision is not None:
                if checkpoint is not None:
                    checkpoint("before_revalidate", original_path)
                revalidated = _read_path(original_path, original_slug, include_source=True)
                if revalidated is None:
                    raise PostureNotFound("This posture was removed from your Mac. Reload the posture list.")
                if revalidated["revision"] != expected_revision:
                    raise PostureConflict(
                        "This posture changed on your Mac. Reload it before saving.",
                        current=revalidated,
                    )
                if renaming and target_path.exists():
                    existing = _read_path(target_path, target_slug, include_source=False)
                    raise PostureConflict(
                        "Another posture already uses this name. Choose another name.",
                        current=existing,
                    )

                transaction = {
                    "version": 1,
                    "id": uuid.uuid4().hex,
                    "kind": "rename" if renaming else "edit",
                    "slug": original_slug,
                    "original": original_path.name,
                    "target": target_path.name,
                    "swap": temp_path.name,
                    "expected_revision": expected_revision,
                    "new_revision": intended_revision,
                }
                marker = _write_transaction_marker(root, transaction)
                if checkpoint is not None:
                    checkpoint("before_publish", original_path)

                _atomic_swap(temp_path, original_path)
                swap_started = True
                try:
                    if checkpoint is not None:
                        checkpoint("after_first_swap", original_path)
                except PostureCrashSimulation:
                    preserve_transaction = True
                    raise

                swapped_out = _read_path(temp_path, original_slug, include_source=True)
                if swapped_out is None:
                    preserve_transaction = True
                    raise PostureIOError("the atomic posture swap lost its prior file")
                if swapped_out["revision"] != expected_revision:
                    conflict_copies = [
                        _preserve_conflict_copy(root, original_slug, temp_path, "editor-write")
                    ]
                    published_revision = _path_revision(original_path)
                    if published_revision != intended_revision:
                        conflict_copies.append(
                            _preserve_conflict_copy(root, original_slug, original_path, "editor-write-after-swap")
                        )
                    _atomic_swap(temp_path, original_path)
                    swap_started = False
                    _remove_transaction_marker(root, marker)
                    marker = None
                    transaction_finished = True
                    raise PostureConflict(
                        "This posture changed during save. Pairling restored the Mac copy and preserved the concurrent edit.",
                        current=swapped_out,
                        conflict_copies=conflict_copies,
                    )

                if renaming:
                    try:
                        if checkpoint is not None:
                            checkpoint("before_target_move", original_path)
                        _atomic_move_exclusive(original_path, target_path)
                    except FileExistsError as exc:
                        current_original_revision = _path_revision(original_path)
                        if current_original_revision == intended_revision:
                            _atomic_swap(temp_path, original_path)
                        elif current_original_revision is None:
                            try:
                                _atomic_move_exclusive(temp_path, original_path)
                            except FileExistsError:
                                pass
                        swap_started = False
                        _remove_transaction_marker(root, marker)
                        marker = None
                        transaction_finished = True
                        existing = _read_path(target_path, target_slug, include_source=False)
                        raise PostureConflict(
                            "Another posture already uses this name. Choose another name.",
                            current=existing,
                        ) from exc
                    except FileNotFoundError as exc:
                        try:
                            _atomic_move_exclusive(temp_path, original_path)
                        except FileExistsError:
                            pass
                        swap_started = False
                        _remove_transaction_marker(root, marker)
                        marker = None
                        transaction_finished = True
                        current_after_move = _read_path(
                            original_path,
                            original_slug,
                            include_source=False,
                        )
                        raise PostureConflict(
                            "This posture changed during rename. Pairling did not remove the newer Mac copy.",
                            current=current_after_move,
                        ) from exc
                    if checkpoint is not None:
                        checkpoint("after_target_move", target_path)
                    published_path = target_path
                    overwrote = False
                else:
                    published_path = original_path

                published = _read_path(published_path, target_slug, include_source=True)
                if published is None or published["revision"] != intended_revision:
                    conflict_copies: list[str] = []
                    if published is not None:
                        conflict_copies.append(
                            _preserve_conflict_copy(root, target_slug, published_path, "editor-write-after-swap")
                        )
                    if renaming:
                        try:
                            _atomic_move_exclusive(published_path, original_path)
                        except FileExistsError:
                            published_path.unlink(missing_ok=True)
                    else:
                        _atomic_swap(temp_path, original_path)
                    swap_started = False
                    _remove_transaction_marker(root, marker)
                    marker = None
                    transaction_finished = True
                    current_after_publish = _read_path(
                        original_path if renaming else published_path,
                        original_slug if renaming else target_slug,
                        include_source=False,
                    )
                    raise PostureConflict(
                        "This posture changed during save. Pairling did not accept the write as successful.",
                        current=current_after_publish,
                        conflict_copies=conflict_copies,
                    )

                _remove_transaction_marker(root, marker)
                marker = None
                transaction_finished = True
                temp_path.unlink(missing_ok=True)
                swap_started = False
            else:
                raise ValueError("current posture mutations require an explicit create or edit mode")
            _fsync_directory(root)
        except PostureCrashSimulation:
            preserve_transaction = True
            raise
        except Exception:
            if swap_started and not transaction_finished:
                preserve_transaction = True
            raise
        finally:
            if not preserve_transaction:
                if marker is not None:
                    _remove_transaction_marker(root, marker)
                temp_path.unlink(missing_ok=True)

        written = _read_path(target_path, target_slug, include_source=False)
        if written is None:
            raise PostureIOError("posture write could not be verified")
        return {
            **written,
            "overwrote": overwrote,
            "renamed_from": original_slug if renaming else None,
        }


def delete_posture(
    root: Path,
    slug: str,
    *,
    expected_revision: str,
    checkpoint: Callable[[str, Path], None] | None = None,
) -> bool:
    if not valid_slug(slug):
        return False
    if not expected_revision:
        raise ValueError("expected_revision is required when deleting a posture")
    path = root / f"{slug}.md"
    with _store_lock(root):
        current = _read_path(path, slug, include_source=True)
        if current is None:
            raise PostureNotFound("This posture was removed from your Mac. Reload the posture list.")
        if current["revision"] != expected_revision:
            raise PostureConflict(
                "This posture changed on your Mac. Reload it before deleting.",
                current=current,
            )

        if checkpoint is not None:
            checkpoint("before_revalidate", path)
        revalidated = _read_path(path, slug, include_source=True)
        if revalidated is None:
            raise PostureNotFound("This posture was removed from your Mac. Reload the posture list.")
        if revalidated["revision"] != expected_revision:
            raise PostureConflict(
                "This posture changed on your Mac. Reload it before deleting.",
                current=revalidated,
            )

        tombstone = _write_unique_temp(root, slug, b"")
        tombstone.unlink()
        marker = _write_transaction_marker(root, {
            "version": 1,
            "id": uuid.uuid4().hex,
            "kind": "delete",
            "slug": slug,
            "original": path.name,
            "target": path.name,
            "swap": tombstone.name,
            "expected_revision": expected_revision,
            "new_revision": "",
        })
        preserve_transaction = False
        try:
            if checkpoint is not None:
                checkpoint("before_publish", path)
            os.rename(path, tombstone)
            try:
                if checkpoint is not None:
                    checkpoint("after_first_swap", path)
            except PostureCrashSimulation:
                preserve_transaction = True
                raise
            removed = _read_path(tombstone, slug, include_source=True)
            if removed is None:
                preserve_transaction = True
                raise PostureIOError("the posture delete transaction lost its file")
            if removed["revision"] != expected_revision:
                conflict_copy = _preserve_conflict_copy(root, slug, tombstone, "editor-write")
                if not path.exists():
                    os.replace(tombstone, path)
                _remove_transaction_marker(root, marker)
                marker = None
                raise PostureConflict(
                    "This posture changed during delete. Pairling kept the Mac copy.",
                    current=removed,
                    conflict_copies=[conflict_copy],
                )
            if path.exists():
                current_after_move = _read_path(path, slug, include_source=True)
                conflict_copy = _preserve_conflict_copy(root, slug, tombstone, "interrupted-delete")
                tombstone.unlink(missing_ok=True)
                _remove_transaction_marker(root, marker)
                marker = None
                raise PostureConflict(
                    "This posture was recreated during delete. Pairling left the new Mac copy in place.",
                    current=current_after_move,
                    conflict_copies=[conflict_copy],
                )
            tombstone.unlink()
            _remove_transaction_marker(root, marker)
            marker = None
            _fsync_directory(root)
            return True
        except PostureCrashSimulation:
            preserve_transaction = True
            raise
        except Exception:
            if marker is not None and tombstone.exists():
                preserve_transaction = True
            raise
        finally:
            if not preserve_transaction:
                tombstone.unlink(missing_ok=True)
                if marker is not None:
                    _remove_transaction_marker(root, marker)
