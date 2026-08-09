from __future__ import annotations

import json
import os
import re
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import registry_data
from .base import (
    ProviderAdapter,
    ProviderAvailability,
    ProviderDescriptor,
    ProviderDiagnostics,
    ProviderProbeResult,
    cli_version,
    resolve_executable,
)


_FALLBACK_DESCRIPTOR = ProviderDescriptor(
    provider_id="omp",
    display_name="OMP",
    kind="agent_platform",
    builtin=False,
    docs_url="https://omp.sh",
    adapter_depth="standard",
)
_ENTRY = registry_data.entry_or_none("omp")

_TERMINAL_RECORD_NAME = re.compile(r"ttys\d{3,}")
_MAX_TERMINAL_RECORD_BYTES = 8192
_MAX_SESSION_HEADER_BYTES = 65536
_SUPPORTED_SESSION_VERSIONS = {3}
_MAX_TERMINAL_RECORDS = 512
_MAX_SESSION_METADATA_LINE_BYTES = 65536
_MAX_SESSION_METADATA_CACHE_ENTRIES = 512


@dataclass(frozen=True)
class _SessionMetadataCacheEntry:
    device: int
    inode: int
    size: int
    modified_ns: int
    scanned_offset: int
    model: str | None
    effort: str | None


_SESSION_METADATA_CACHE: dict[str, _SessionMetadataCacheEntry] = {}


@dataclass(frozen=True)
class OmpTerminalRecord:
    session_id: str
    project: str
    session_path: str
    terminal_tty: str
    title: str | None
    record_mtime: float
    fresh: bool
    @property
    def native_id(self) -> str:
        return self.session_id


@dataclass(frozen=True)
class OmpSavedSession:
    session_id: str
    project: str
    session_path: str
    title: str | None
    modified_at: float

    @property
    def native_id(self) -> str:
        return self.session_id


def _canonical_existing_path(path: Path) -> Path | None:
    try:
        return path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        return None


def _session_header(path: Path) -> tuple[str, str, str | None] | None:
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return None
        title = None
        consumed = 0
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            for _ in range(64):
                remaining = _MAX_SESSION_HEADER_BYTES - consumed
                if remaining <= 0:
                    return None
                raw_line = handle.readline(remaining + 1)
                if not raw_line or len(raw_line) > remaining:
                    return None
                consumed += len(raw_line)
                line = raw_line.decode("utf-8")
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    return None
                if not isinstance(payload, dict):
                    return None
                if payload.get("type") == "title":
                    value = payload.get("title")
                    if isinstance(value, str) and value.strip():
                        title = value.strip()[:240]
                    continue
                if payload.get("type") != "session":
                    continue
                if payload.get("version") not in _SUPPORTED_SESSION_VERSIONS:
                    return None
                raw_id = payload.get("id")
                raw_cwd = payload.get("cwd")
                if not isinstance(raw_id, str) or not isinstance(raw_cwd, str):
                    return None
                try:
                    session_id = str(uuid.UUID(raw_id))
                except ValueError:
                    return None
                return session_id, raw_cwd, title
    except (OSError, UnicodeError):
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return None

def session_runtime_metadata(path: Path) -> dict[str, str | None]:
    """Read the latest explicit model and effort from an append-only OMP JSONL."""
    canonical_path = _canonical_existing_path(path)
    if canonical_path is None:
        return {"model": None, "effort": None}

    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(canonical_path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return {"model": None, "effort": None}

        cache_key = str(canonical_path)
        cached = _SESSION_METADATA_CACHE.get(cache_key)
        can_resume = (
            cached is not None
            and cached.device == metadata.st_dev
            and cached.inode == metadata.st_ino
            and metadata.st_size >= cached.size
            and (
                metadata.st_size > cached.size
                or metadata.st_mtime_ns == cached.modified_ns
            )
        )
        if can_resume and cached is not None and metadata.st_size == cached.size:
            return {"model": cached.model, "effort": cached.effort}

        scan_offset = cached.scanned_offset if can_resume and cached is not None else 0
        model = cached.model if can_resume and cached is not None else None
        effort = cached.effort if can_resume and cached is not None else None
        os.lseek(descriptor, scan_offset, os.SEEK_SET)

        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            while True:
                line_start = handle.tell()
                raw_line = handle.readline(_MAX_SESSION_METADATA_LINE_BYTES + 1)
                if not raw_line:
                    break
                if not raw_line.endswith(b"\n"):
                    if len(raw_line) <= _MAX_SESSION_METADATA_LINE_BYTES:
                        handle.seek(line_start)
                        break
                    while raw_line and not raw_line.endswith(b"\n"):
                        raw_line = handle.readline(_MAX_SESSION_METADATA_LINE_BYTES + 1)
                    scan_offset = handle.tell()
                    continue

                scan_offset = handle.tell()
                if len(raw_line) > _MAX_SESSION_METADATA_LINE_BYTES:
                    continue
                if (
                    b'"type":"model_change"' not in raw_line
                    and b'"type": "model_change"' not in raw_line
                    and b'"type":"thinking_level_change"' not in raw_line
                    and b'"type": "thinking_level_change"' not in raw_line
                ):
                    continue
                try:
                    payload = json.loads(raw_line)
                except (json.JSONDecodeError, UnicodeError):
                    continue
                if not isinstance(payload, dict):
                    continue
                if payload.get("type") == "model_change":
                    value = payload.get("model")
                    if isinstance(value, str) and value.strip():
                        model = value.strip()[:256]
                elif payload.get("type") == "thinking_level_change":
                    value = payload.get("thinkingLevel")
                    if isinstance(value, str) and value.strip():
                        effort = value.strip()[:32]

        if len(_SESSION_METADATA_CACHE) >= _MAX_SESSION_METADATA_CACHE_ENTRIES:
            _SESSION_METADATA_CACHE.clear()
        _SESSION_METADATA_CACHE[cache_key] = _SessionMetadataCacheEntry(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            size=metadata.st_size,
            modified_ns=metadata.st_mtime_ns,
            scanned_offset=scan_offset,
            model=model,
            effort=effort,
        )
        return {"model": model, "effort": effort}
    except OSError:
        return {"model": None, "effort": None}
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_terminal_record(path: Path, *, home: Path | None = None) -> OmpTerminalRecord | None:
    home = home or Path.home()
    if not _TERMINAL_RECORD_NAME.fullmatch(path.name):
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_TERMINAL_RECORD_BYTES:
            return None
        chunks: list[bytes] = []
        remaining = _MAX_TERMINAL_RECORD_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_TERMINAL_RECORD_BYTES:
            return None
        lines = raw.decode("utf-8").splitlines()
        record_mtime = metadata.st_mtime
    except (OSError, UnicodeError):
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(lines) not in {2, 3} or not all(line.strip() for line in lines[:2]):
        return None
    if len(lines) == 3 and lines[2].strip().lower() != "fresh":
        return None

    project = _canonical_existing_path(Path(lines[0]))
    session_path = _canonical_existing_path(Path(lines[1]))
    agent_sessions_root = _canonical_existing_path(
        home / ".omp" / "agent" / "sessions"
    )
    security_root = _canonical_existing_path(home / ".omp" / "security")
    in_agent_sessions = (
        agent_sessions_root is not None
        and session_path is not None
        and session_path.is_relative_to(agent_sessions_root)
    )
    in_security_sessions = (
        security_root is not None
        and session_path is not None
        and session_path.parent.name == "sessions"
        and session_path.parent.parent.parent == security_root
    )
    if (
        project is None
        or not project.is_dir()
        or session_path is None
        or not session_path.is_file()
        or not (in_agent_sessions or in_security_sessions)
    ):
        return None

    header = _session_header(session_path)
    if header is None:
        return None
    session_id, header_cwd, title = header
    header_project = _canonical_existing_path(Path(header_cwd))
    if header_project is None or header_project != project:
        return None
    return OmpTerminalRecord(
        session_id=session_id,
        project=str(project),
        session_path=str(session_path),
        terminal_tty=f"/dev/{path.name}",
        title=title,
        record_mtime=record_mtime,
        fresh=len(lines) == 3,
    )


def terminal_session_records(*, home: Path | None = None) -> list[OmpTerminalRecord]:
    home = home or Path.home()
    records_dir = home / ".omp" / "agent" / "terminal-sessions"
    try:
        paths: list[Path] = []
        with os.scandir(records_dir) as entries:
            for examined_count, entry in enumerate(entries):
                if examined_count >= _MAX_TERMINAL_RECORDS:
                    break
                if not _TERMINAL_RECORD_NAME.fullmatch(entry.name):
                    continue
                try:
                    if not entry.is_file(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                paths.append(Path(entry.path))
        paths.sort(key=lambda item: item.name)
    except OSError:
        return []
    return [
        record
        for path in paths
        if (record := read_terminal_record(path, home=home)) is not None
    ]


def saved_sessions(
    *,
    home: Path | None = None,
    project: str | None = None,
    limit: int = 80,
) -> list[OmpSavedSession]:
    """Discover bounded, resumable OMP sessions from the canonical user store."""
    home = home or Path.home()
    sessions_root = _canonical_existing_path(home / ".omp" / "agent" / "sessions")
    if sessions_root is None or not sessions_root.is_dir():
        return []
    canonical_project = _canonical_existing_path(Path(project)) if project else None
    if project and (canonical_project is None or not canonical_project.is_dir()):
        return []
    result_limit = max(1, min(int(limit), 200))
    candidates: list[OmpSavedSession] = []
    examined_directories = 0
    examined_files = 0
    try:
        with os.scandir(sessions_root) as directories:
            for directory in directories:
                if examined_directories >= _MAX_TERMINAL_RECORDS:
                    break
                examined_directories += 1
                try:
                    if not directory.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                try:
                    with os.scandir(directory.path) as files:
                        for entry in files:
                            if examined_files >= 4096:
                                break
                            examined_files += 1
                            if not entry.name.endswith(".jsonl"):
                                continue
                            try:
                                if not entry.is_file(follow_symlinks=False):
                                    continue
                                metadata = entry.stat(follow_symlinks=False)
                            except OSError:
                                continue
                            session_path = Path(entry.path)
                            header = _session_header(session_path)
                            if header is None:
                                continue
                            session_id, raw_cwd, title = header
                            header_project = _canonical_existing_path(Path(raw_cwd))
                            if (
                                header_project is None
                                or not header_project.is_dir()
                                or (canonical_project is not None and header_project != canonical_project)
                            ):
                                continue
                            resolved_session = _canonical_existing_path(session_path)
                            if (
                                resolved_session is None
                                or not resolved_session.is_relative_to(sessions_root)
                            ):
                                continue
                            candidates.append(OmpSavedSession(
                                session_id=session_id,
                                project=str(header_project),
                                session_path=str(resolved_session),
                                title=title,
                                modified_at=metadata.st_mtime,
                            ))
                except OSError:
                    continue
                if examined_files >= 4096:
                    break
    except OSError:
        return []

    candidates.sort(key=lambda item: item.modified_at, reverse=True)
    unique: list[OmpSavedSession] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate.session_id in seen:
            continue
        seen.add(candidate.session_id)
        unique.append(candidate)
        if len(unique) >= result_limit:
            break
    return unique


class OmpProviderAdapter(ProviderAdapter):
    descriptor = registry_data.descriptor_for(_ENTRY) if _ENTRY else _FALLBACK_DESCRIPTOR

    def __init__(self, home: Path | None = None):
        self.home = home or Path.home()

    @property
    def candidates(self) -> list[Path]:
        if _ENTRY is not None and _ENTRY.binary_candidates:
            return registry_data.candidate_paths(_ENTRY, home=self.home)
        return [
            self.home / ".local" / "bin" / "omp",
            Path("/opt/homebrew/bin/omp"),
            Path("/usr/local/bin/omp"),
        ]

    # External Terminal.app sessions stay read-only. Terminal control is
    # available only after Pairling resumes the OMP session into its PTY broker.
    def supports(self, capability: str) -> bool:
        return capability in {
            "commands",
            "detect",
            "saved_sessions",
            "status",
            "list_sessions",
            "terminal_output",
            "terminal_surface",
            "terminal_control",
            "send_text",
            "interrupt",
            "terminate",
            "resume",
        }

    def create_control_driver(self, binding):
        """Use the reviewed ACP profile for Pairling-owned OMP sessions."""
        if _ENTRY is None:
            return None
        from .acp import AcpProviderAdapter

        return AcpProviderAdapter(_ENTRY, home=self.home).create_control_driver(binding)

    def probe(self) -> ProviderProbeResult:
        env_var = _ENTRY.env_override if _ENTRY is not None else "PAIRLING_OMP_BIN"
        resolved = resolve_executable("omp", self.candidates, env_var=env_var)
        installed = resolved is not None
        config_path = self.home / ".omp" / "agent" / "config.yml"
        managed_probe = None
        if installed and _ENTRY is not None:
            from .acp import AcpProviderAdapter

            managed_probe = AcpProviderAdapter(_ENTRY, home=self.home).probe()
        launchable = bool(
            managed_probe is not None and managed_probe.availability.launchable
        )
        capabilities = (
            "commands",
            "detect",
            "saved_sessions",
            "status",
            "list_sessions",
            "terminal_output",
            "terminal_surface",
            "terminal_control",
            "send_text",
            "interrupt",
            "terminate",
            "resume",
        ) if installed else ("detect", "status")
        if not installed:
            notes = (
                "OMP CLI not found in configured, known, or daemon PATH locations",
            )
            setup_actions = ("install_cli",)
        elif managed_probe is not None:
            notes = managed_probe.availability.notes
            setup_actions = managed_probe.availability.setup_actions
        else:
            notes = ("OMP has no reviewed managed launch entry.",)
            setup_actions = ("provider_review_required",)
        return ProviderProbeResult(
            descriptor=self.descriptor,
            availability=ProviderAvailability(
                provider_id=self.descriptor.provider_id,
                display_name=self.descriptor.display_name,
                kind=self.descriptor.kind,
                installed=installed,
                usable=installed,
                launchable=launchable,
                auth_state="unknown" if installed else "missing_cli",
                config_state="pairling_managed" if launchable else ("ready" if config_path.is_file() else "missing"),
                readable_sessions=0,
                live_sessions=0,
                controllable_sessions=0,
                capabilities=capabilities,
                setup_actions=setup_actions,
                notes=notes,
            ),
            diagnostics=ProviderDiagnostics(
                cli_path=str(resolved.path) if resolved else None,
                cli_path_source=resolved.source if resolved else None,
                version=(
                    managed_probe.diagnostics.version
                    if managed_probe is not None
                    else (cli_version(resolved.path) if resolved else None)
                ),
                config_path=str(config_path),
                config_exists=config_path.is_file(),
            ),
            observed_at=time.time(),
        )
