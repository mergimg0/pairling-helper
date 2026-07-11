#!/usr/bin/env python3
"""Mac-local Compose recording library fed by verified PairDrop objects."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import shutil
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator


class ComposeRecordingStoreError(ValueError):
    def __init__(self, code: str, message: str | None = None, *, status: int = 400):
        super().__init__(message or code)
        self.code = code
        self.status = status


class ComposeRecordingStore:
    schema_version = 1
    transcript_max_bytes = 750_000
    synthesis_max_bytes = 200_000
    prompt_max_bytes = 200_000
    metadata_max_bytes = 64 * 1024

    _item_id_re = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
    _file_id_re = re.compile(r"pd_[a-f0-9]{32}")
    _sha256_re = re.compile(r"[a-f0-9]{64}")
    _audio_types = {
        "aac": {"audio/aac"},
        "aif": {"audio/aiff", "audio/x-aiff"},
        "aiff": {"audio/aiff", "audio/x-aiff"},
        "caf": {"audio/x-caf"},
        "flac": {"audio/flac", "audio/x-flac"},
        "m4a": {"audio/m4a", "audio/mp4", "audio/x-m4a"},
        "mp3": {"audio/mp3", "audio/mpeg"},
        "ogg": {"audio/ogg"},
        "opus": {"audio/ogg", "audio/opus"},
        "wav": {"audio/wav", "audio/wave", "audio/x-wav"},
    }
    _fixed_text_files = ("transcript.txt", "synthesis.md", "prompt.md")

    def __init__(self, home: Path, *, now: Callable[[], str] | None = None) -> None:
        self.home = Path(home).expanduser()
        self.root = self.home / "Pairling" / "Compose" / "Recordings"
        self.display_root = "~/Pairling/Compose/Recordings"
        self._now = now or self._now_iso

    @staticmethod
    def _now_iso() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def sync(
        self,
        *,
        item_id: str,
        audio_descriptor: dict[str, Any],
        transcript: str,
        synthesis: str | list[str],
        prompt: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        item_id = self._validate_item_id(item_id)
        transcript_bytes = self._validated_text(
            transcript, "transcript", self.transcript_max_bytes
        )
        synthesis_bytes = self._validated_synthesis(synthesis)
        prompt_bytes = self._validated_text(prompt, "prompt", self.prompt_max_bytes)
        user_metadata = self._validated_metadata(metadata)
        audio = self._validated_audio_descriptor(audio_descriptor)
        audio_name = f"audio.{audio['extension']}"
        library_path = f"{self.display_root}/{item_id}"
        text_payloads = {
            "transcript.txt": transcript_bytes,
            "synthesis.md": synthesis_bytes,
            "prompt.md": prompt_bytes,
        }
        content_files = {
            name: {
                "byte_size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for name, data in text_payloads.items()
        }
        content_files[audio_name] = {
            "byte_size": audio["byte_size"],
            "sha256": audio["sha256"],
        }
        metadata_identity = {
            "schema_version": self.schema_version,
            "item_id": item_id,
            "library_path": library_path,
            "audio": {
                "file_name": audio_name,
                "pairdrop_file_id": audio["file_id"],
                "content_type": audio["content_type"],
                "byte_size": audio["byte_size"],
                "sha256": audio["sha256"],
                "source_device_id": audio["source_device_id"],
                "source_install_id": audio["source_install_id"],
                "source_route": audio["source_route"],
            },
            "files": content_files,
            "metadata": user_metadata,
        }
        receipt_id = hashlib.sha256(self._canonical_json(metadata_identity)).hexdigest()
        metadata_identity["sync_receipt"] = receipt_id

        self._ensure_root()
        with self._sync_lock():
            self._cleanup_stale_stages()
            item_dir = self.root / item_id
            existing = self._read_existing_item(item_dir)
            if existing is None:
                created_at = self._now()
                stored_metadata = {
                    **metadata_identity,
                    "created_at": created_at,
                    "updated_at": created_at,
                }
                self._create_item(
                    item_dir=item_dir,
                    audio_name=audio_name,
                    audio=audio,
                    text_payloads=text_payloads,
                    metadata=stored_metadata,
                )
                return self._receipt(
                    item_id=item_id,
                    library_path=library_path,
                    audio_name=audio_name,
                    metadata=stored_metadata,
                    idempotent=False,
                )

            self._assert_existing_audio_identity(
                item_dir=item_dir,
                existing=existing,
                audio_name=audio_name,
                audio=audio,
            )
            files_match = self._text_files_match(item_dir, text_payloads)
            existing_identity = {
                key: existing.get(key)
                for key in metadata_identity
                if key != "sync_receipt"
            }
            metadata_matches = (
                existing_identity
                == {key: value for key, value in metadata_identity.items() if key != "sync_receipt"}
                and existing.get("sync_receipt") == receipt_id
            )
            if files_match and metadata_matches:
                return self._receipt(
                    item_id=item_id,
                    library_path=library_path,
                    audio_name=audio_name,
                    metadata=existing,
                    idempotent=True,
                )

            for name, data in text_payloads.items():
                if self._regular_file_bytes(item_dir / name) != data:
                    self._atomic_write(item_dir, name, data)
            created_at = str(existing.get("created_at") or self._now())
            stored_metadata = {
                **metadata_identity,
                "created_at": created_at,
                "updated_at": self._now(),
            }
            self._atomic_write(
                item_dir,
                "metadata.json",
                self._canonical_json(stored_metadata) + b"\n",
            )
            return self._receipt(
                item_id=item_id,
                library_path=library_path,
                audio_name=audio_name,
                metadata=stored_metadata,
                idempotent=False,
            )

    def _validate_item_id(self, value: Any) -> str:
        if not isinstance(value, str) or self._item_id_re.fullmatch(value) is None:
            raise ComposeRecordingStoreError("bad_compose_item_id")
        return value

    def _validated_text(self, value: Any, field: str, limit: int) -> bytes:
        if not isinstance(value, str):
            raise ComposeRecordingStoreError(f"bad_{field}")
        encoded = value.encode("utf-8")
        if len(encoded) > limit:
            raise ComposeRecordingStoreError(f"{field}_too_large", status=413)
        return encoded

    def _validated_synthesis(self, value: Any) -> bytes:
        if isinstance(value, list):
            if len(value) > 256 or not all(isinstance(part, str) for part in value):
                raise ComposeRecordingStoreError("bad_synthesis")
            value = "\n\n".join(value)
        return self._validated_text(value, "synthesis", self.synthesis_max_bytes)

    def _validated_metadata(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ComposeRecordingStoreError("bad_metadata")
        self._validate_json_value(value, depth=0)
        try:
            encoded = self._canonical_json(value)
        except (TypeError, ValueError) as error:
            raise ComposeRecordingStoreError("bad_metadata") from error
        if len(encoded) > self.metadata_max_bytes:
            raise ComposeRecordingStoreError("metadata_too_large", status=413)
        normalized = json.loads(encoded.decode("utf-8"))
        required = {
            "source",
            "created_at",
            "duration_seconds",
            "original_audio_name",
            "item_state",
        }
        allowed = required | {"locale_identifier"}
        if set(normalized) - allowed or not required.issubset(normalized):
            raise ComposeRecordingStoreError("bad_metadata_schema")
        if normalized["source"] not in {"recorded", "imported"}:
            raise ComposeRecordingStoreError("bad_metadata_source")
        created_at = normalized["created_at"]
        if not isinstance(created_at, str) or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", created_at
        ) is None:
            raise ComposeRecordingStoreError("bad_metadata_created_at")
        duration = normalized["duration_seconds"]
        if duration is not None and (
            not isinstance(duration, (int, float))
            or isinstance(duration, bool)
            or not math.isfinite(duration)
            or duration < 0
        ):
            raise ComposeRecordingStoreError("bad_metadata_duration")
        original_name = normalized["original_audio_name"]
        if (
            not isinstance(original_name, str)
            or not original_name
            or len(original_name.encode("utf-8")) > 255
            or os.path.basename(original_name) != original_name
            or "\x00" in original_name
        ):
            raise ComposeRecordingStoreError("bad_metadata_original_audio_name")
        if normalized["item_state"] != "ready":
            raise ComposeRecordingStoreError("bad_metadata_item_state")
        locale = normalized.get("locale_identifier")
        if locale is not None and (
            not isinstance(locale, str)
            or not locale
            or len(locale.encode("utf-8")) > 128
        ):
            raise ComposeRecordingStoreError("bad_metadata_locale")
        return normalized

    def _validate_json_value(self, value: Any, *, depth: int) -> None:
        if depth > 16:
            raise ComposeRecordingStoreError("bad_metadata")
        if value is None or isinstance(value, (str, bool, int)):
            return
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ComposeRecordingStoreError("bad_metadata")
            return
        if isinstance(value, list):
            if len(value) > 2_000:
                raise ComposeRecordingStoreError("bad_metadata")
            for item in value:
                self._validate_json_value(item, depth=depth + 1)
            return
        if isinstance(value, dict):
            if len(value) > 1_000:
                raise ComposeRecordingStoreError("bad_metadata")
            for key, item in value.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > 256:
                    raise ComposeRecordingStoreError("bad_metadata")
                self._validate_json_value(item, depth=depth + 1)
            return
        raise ComposeRecordingStoreError("bad_metadata")

    def _validated_audio_descriptor(self, descriptor: Any) -> dict[str, Any]:
        if not isinstance(descriptor, dict):
            raise ComposeRecordingStoreError("bad_audio_descriptor")
        item = descriptor.get("item")
        path = descriptor.get("path")
        if not isinstance(item, dict) or not isinstance(path, (str, os.PathLike, Path)):
            raise ComposeRecordingStoreError("bad_audio_descriptor")
        file_id = str(item.get("id") or "")
        if self._file_id_re.fullmatch(file_id) is None or item.get("kind") != "file":
            raise ComposeRecordingStoreError("bad_pairdrop_file_id")
        sha256 = str(item.get("sha256") or "")
        if self._sha256_re.fullmatch(sha256) is None:
            raise ComposeRecordingStoreError("bad_audio_sha256")
        try:
            byte_size = int(item.get("byte_size"))
        except (TypeError, ValueError):
            raise ComposeRecordingStoreError("bad_audio_byte_size")
        if byte_size <= 0:
            raise ComposeRecordingStoreError("bad_audio_byte_size")
        display_name = str(item.get("display_name") or "")
        extension = Path(display_name).suffix.removeprefix(".").lower()
        content_type = str(item.get("content_type") or "").split(";", 1)[0].strip().lower()
        allowed_types = self._audio_types.get(extension)
        if allowed_types is None:
            raise ComposeRecordingStoreError("unsupported_audio_extension", status=422)
        if content_type not in allowed_types:
            raise ComposeRecordingStoreError("unsupported_audio_content_type", status=422)
        provenance: dict[str, str] = {}
        for key in ("source_device_id", "source_install_id", "source_route"):
            raw = item.get(key)
            if raw is not None and not isinstance(raw, str):
                raise ComposeRecordingStoreError("bad_audio_provenance")
            text = str(raw or "")
            if len(text.encode("utf-8")) > 512:
                raise ComposeRecordingStoreError("bad_audio_provenance")
            provenance[key] = text
        return {
            "file_id": file_id,
            "path": Path(path),
            "extension": extension,
            "content_type": content_type,
            "byte_size": byte_size,
            "sha256": sha256,
            **provenance,
        }

    def _ensure_root(self) -> None:
        try:
            home_mode = os.lstat(self.home).st_mode
        except OSError as error:
            raise ComposeRecordingStoreError("compose_home_unavailable", status=503) from error
        if stat.S_ISLNK(home_mode) or not stat.S_ISDIR(home_mode):
            raise ComposeRecordingStoreError("compose_home_unavailable", status=503)
        current = self.home
        for component in ("Pairling", "Compose", "Recordings"):
            candidate = current / component
            try:
                os.mkdir(candidate, 0o700)
            except FileExistsError:
                pass
            except OSError as error:
                raise ComposeRecordingStoreError(
                    "compose_library_unavailable", status=503
                ) from error
            try:
                mode = os.lstat(candidate).st_mode
            except OSError as error:
                raise ComposeRecordingStoreError(
                    "compose_library_unavailable", status=503
                ) from error
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise ComposeRecordingStoreError("unsafe_compose_library_path", status=409)
            current = candidate

    @contextmanager
    def _sync_lock(self) -> Iterator[None]:
        path = self.root / ".sync.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = -1
        try:
            fd = os.open(path, flags, 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ComposeRecordingStoreError("unsafe_compose_sync_lock", status=409)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
                raise ComposeRecordingStoreError(
                    "unsafe_compose_sync_lock", status=409
                ) from error
            raise
        finally:
            if fd >= 0:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    def _read_existing_item(self, item_dir: Path) -> dict[str, Any] | None:
        try:
            mode = os.lstat(item_dir).st_mode
        except FileNotFoundError:
            return None
        except OSError as error:
            raise ComposeRecordingStoreError("compose_item_unavailable", status=503) from error
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise ComposeRecordingStoreError("unsafe_compose_item_path", status=409)
        metadata_bytes = self._regular_file_bytes(item_dir / "metadata.json")
        if metadata_bytes is None or len(metadata_bytes) > self.metadata_max_bytes * 4:
            raise ComposeRecordingStoreError("compose_metadata_corrupt", status=409)
        try:
            metadata = json.loads(metadata_bytes)
        except (ValueError, json.JSONDecodeError) as error:
            raise ComposeRecordingStoreError("compose_metadata_corrupt", status=409) from error
        if not isinstance(metadata, dict):
            raise ComposeRecordingStoreError("compose_metadata_corrupt", status=409)
        return metadata

    def _create_item(
        self,
        *,
        item_dir: Path,
        audio_name: str,
        audio: dict[str, Any],
        text_payloads: dict[str, bytes],
        metadata: dict[str, Any],
    ) -> None:
        stage = self.root / f".{item_dir.name}.{secrets.token_hex(8)}.partial"
        try:
            os.mkdir(stage, 0o700)
            self._copy_verified_audio(audio, stage / audio_name)
            for name, data in text_payloads.items():
                self._atomic_write(stage, name, data)
            self._atomic_write(
                stage,
                "metadata.json",
                self._canonical_json(metadata) + b"\n",
            )
            self._fsync_directory(stage)
            os.rename(stage, item_dir)
            self._fsync_directory(self.root)
        except FileExistsError as error:
            raise ComposeRecordingStoreError("compose_item_conflict", status=409) from error
        except ComposeRecordingStoreError:
            raise
        except OSError as error:
            raise ComposeRecordingStoreError("compose_sync_failed", status=500) from error
        finally:
            if stage.exists() and not stage.is_symlink():
                shutil.rmtree(stage, ignore_errors=True)

    def _cleanup_stale_stages(self) -> None:
        removed = False
        try:
            entries = list(os.scandir(self.root))
        except OSError as error:
            raise ComposeRecordingStoreError(
                "compose_library_unavailable", status=503
            ) from error
        for entry in entries:
            if not re.fullmatch(
                r"\.[A-Za-z0-9][A-Za-z0-9_-]{0,127}\.[a-f0-9]{16}\.partial",
                entry.name,
            ):
                continue
            try:
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    continue
                shutil.rmtree(entry.path)
                removed = True
            except FileNotFoundError:
                continue
            except OSError as error:
                raise ComposeRecordingStoreError(
                    "compose_staging_cleanup_failed", status=503
                ) from error
        if removed:
            self._fsync_directory(self.root)

    def _copy_verified_audio(self, audio: dict[str, Any], destination: Path) -> None:
        source_fd = -1
        destination_fd = -1
        digest = hashlib.sha256()
        byte_count = 0
        prefix = bytearray()
        try:
            source_fd = os.open(
                audio["path"], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
            source_stat = os.fstat(source_fd)
            if not stat.S_ISREG(source_stat.st_mode):
                raise ComposeRecordingStoreError("unsafe_pairdrop_audio_source", status=409)
        except ComposeRecordingStoreError:
            if source_fd >= 0:
                os.close(source_fd)
                source_fd = -1
            raise
        except OSError as error:
            if source_fd >= 0:
                os.close(source_fd)
                source_fd = -1
            raise ComposeRecordingStoreError(
                "unsafe_pairdrop_audio_source", status=409
            ) from error
        try:
            destination_fd = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            while True:
                try:
                    chunk = os.read(source_fd, 1024 * 1024)
                except OSError as error:
                    raise ComposeRecordingStoreError(
                        "unsafe_pairdrop_audio_source", status=409
                    ) from error
                if not chunk:
                    break
                digest.update(chunk)
                byte_count += len(chunk)
                if len(prefix) < 32:
                    prefix.extend(chunk[: 32 - len(prefix)])
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise OSError(errno.EIO, "short Compose audio write")
                    view = view[written:]
            os.fsync(destination_fd)
        except ComposeRecordingStoreError:
            raise
        except OSError as error:
            if error.errno in {errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)}:
                raise ComposeRecordingStoreError(
                    "compose_storage_full", status=507
                ) from error
            raise ComposeRecordingStoreError("compose_storage_write_failed", status=500) from error
        finally:
            if destination_fd >= 0:
                os.close(destination_fd)
            if source_fd >= 0:
                os.close(source_fd)
        if (
            byte_count != audio["byte_size"]
            or digest.hexdigest() != audio["sha256"]
            or not self._audio_signature_matches(audio["extension"], bytes(prefix))
        ):
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
            code = (
                "unsupported_audio_signature"
                if not self._audio_signature_matches(audio["extension"], bytes(prefix))
                else "pairdrop_audio_changed"
            )
            raise ComposeRecordingStoreError(code, status=422 if code.startswith("unsupported") else 409)

    def _assert_existing_audio_identity(
        self,
        *,
        item_dir: Path,
        existing: dict[str, Any],
        audio_name: str,
        audio: dict[str, Any],
    ) -> None:
        expected = existing.get("audio")
        current = {
            "file_name": audio_name,
            "pairdrop_file_id": audio["file_id"],
            "content_type": audio["content_type"],
            "byte_size": audio["byte_size"],
            "sha256": audio["sha256"],
            "source_device_id": audio["source_device_id"],
            "source_install_id": audio["source_install_id"],
            "source_route": audio["source_route"],
        }
        if expected != current:
            raise ComposeRecordingStoreError("compose_audio_identity_conflict", status=409)
        actual_size, actual_sha256 = self._regular_file_identity(item_dir / audio_name)
        if actual_size != audio["byte_size"] or actual_sha256 != audio["sha256"]:
            raise ComposeRecordingStoreError("compose_audio_identity_conflict", status=409)

    def _text_files_match(self, item_dir: Path, payloads: dict[str, bytes]) -> bool:
        return all(self._regular_file_bytes(item_dir / name) == data for name, data in payloads.items())

    def _regular_file_identity(self, path: Path) -> tuple[int, str]:
        fd = -1
        digest = hashlib.sha256()
        byte_count = 0
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ComposeRecordingStoreError("unsafe_compose_item_file", status=409)
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                byte_count += len(chunk)
        except ComposeRecordingStoreError:
            raise
        except OSError as error:
            raise ComposeRecordingStoreError("unsafe_compose_item_file", status=409) from error
        finally:
            if fd >= 0:
                os.close(fd)
        return byte_count, digest.hexdigest()

    def _regular_file_bytes(self, path: Path) -> bytes | None:
        fd = -1
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            file_stat = os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode):
                raise ComposeRecordingStoreError("unsafe_compose_item_file", status=409)
            size = int(file_stat.st_size)
            if size > max(
                self.transcript_max_bytes,
                self.synthesis_max_bytes,
                self.prompt_max_bytes,
                self.metadata_max_bytes * 4,
            ):
                raise ComposeRecordingStoreError("compose_item_file_too_large", status=409)
            chunks = []
            remaining = size + 1
            while remaining > 0:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) != size:
                raise ComposeRecordingStoreError("compose_item_changed", status=409)
            return data
        except FileNotFoundError:
            return None
        except ComposeRecordingStoreError:
            raise
        except OSError as error:
            raise ComposeRecordingStoreError("unsafe_compose_item_file", status=409) from error
        finally:
            if fd >= 0:
                os.close(fd)

    def _atomic_write(self, directory: Path, name: str, data: bytes) -> None:
        target = directory / name
        if target.exists() or target.is_symlink():
            try:
                mode = os.lstat(target).st_mode
            except OSError as error:
                raise ComposeRecordingStoreError("unsafe_compose_item_file", status=409) from error
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                raise ComposeRecordingStoreError("unsafe_compose_item_file", status=409)
        temporary = directory / f".{name}.{secrets.token_hex(8)}.tmp"
        fd = -1
        try:
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(temporary, target)
            self._fsync_directory(directory)
        except ComposeRecordingStoreError:
            raise
        except OSError as error:
            raise ComposeRecordingStoreError("compose_sync_failed", status=500) from error
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _receipt(
        self,
        *,
        item_id: str,
        library_path: str,
        audio_name: str,
        metadata: dict[str, Any],
        idempotent: bool,
    ) -> dict[str, Any]:
        item_dir = self.root / item_id
        metadata_size, metadata_sha256 = self._regular_file_identity(item_dir / "metadata.json")
        files = dict(metadata["files"])
        files["metadata.json"] = {
            "byte_size": metadata_size,
            "sha256": metadata_sha256,
        }
        return {
            "ok": True,
            "schema_version": self.schema_version,
            "item_id": item_id,
            "library_path": library_path,
            "audio_path": f"{library_path}/{audio_name}",
            "sync_receipt": metadata["sync_receipt"],
            "files": files,
            "idempotent": idempotent,
            "updated_at": metadata["updated_at"],
        }

    @staticmethod
    def _audio_signature_matches(extension: str, prefix: bytes) -> bool:
        if extension == "m4a":
            return len(prefix) >= 12 and prefix[4:8] == b"ftyp"
        if extension == "mp3":
            return prefix.startswith(b"ID3") or (
                len(prefix) >= 2 and prefix[0] == 0xFF and prefix[1] & 0xE0 == 0xE0
            )
        if extension == "wav":
            return len(prefix) >= 12 and prefix[:4] == b"RIFF" and prefix[8:12] == b"WAVE"
        if extension == "caf":
            return prefix.startswith(b"caff")
        if extension == "flac":
            return prefix.startswith(b"fLaC")
        if extension in {"ogg", "opus"}:
            return prefix.startswith(b"OggS")
        if extension in {"aif", "aiff"}:
            return (
                len(prefix) >= 12
                and prefix[:4] == b"FORM"
                and prefix[8:12] in {b"AIFF", b"AIFC"}
            )
        if extension == "aac":
            return len(prefix) >= 2 and prefix[0] == 0xFF and prefix[1] & 0xF6 == 0xF0
        return False

    @staticmethod
    def _canonical_json(value: Any) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
