from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import threading
import time
from dataclasses import asdict, dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping, Protocol


ProviderCapability = str
_BASE_CHILD_ENVIRONMENT_KEYS = (
    "HOME",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
    "PATH",
    "SHELL",
    "TEMP",
    "TMP",
    "TMPDIR",
    "TZ",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_STATE_HOME",
)
_ENVIRONMENT_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_SECRET_ENVIRONMENT_MARKERS = (
    "CREDENTIAL",
    "KEY",
    "PASSWORD",
    "PASSWD",
    "PSK",
    "SECRET",
    "TOKEN",
)

_CLI_VERSION_CACHE_TTL_SECONDS = 300.0
_CLI_VERSION_CACHE_MAX_ENTRIES = 128
_CLI_VERSION_CACHE: dict[
    tuple[str, tuple[str, ...], int],
    tuple[tuple[int, int, int, int], float, str | None],
] = {}
_CLI_VERSION_CACHE_LOCK = threading.Lock()


def managed_child_environment(
    source: Mapping[str, str] | None = None,
    *,
    home: Path | str | None = None,
    provider_settings: Mapping[str, str] | None = None,
    private_runtime_settings: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the complete environment for one Pairling-managed provider child.

    Ambient input is limited to basic process, locale, and state paths. Provider
    settings must be named with exact, non-secret values by the driver. The
    private runtime channel is only for newly generated, child-scoped values
    such as a loopback server credential; it must never receive ambient values.
    """

    ambient = os.environ if source is None else source
    environment = {
        key: value
        for key in _BASE_CHILD_ENVIRONMENT_KEYS
        if isinstance((value := ambient.get(key)), str) and "\x00" not in value
    }
    if home is not None:
        environment["HOME"] = _required_environment_value("HOME", str(home))
    for key, value in (provider_settings or {}).items():
        normalized = _required_environment_name(key)
        if any(marker in normalized.upper() for marker in _SECRET_ENVIRONMENT_MARKERS):
            raise ValueError(f"provider environment setting {normalized!r} may contain a credential")
        environment[normalized] = _required_environment_value(normalized, value)
    for key, value in (private_runtime_settings or {}).items():
        normalized = _required_environment_name(key)
        environment[normalized] = _required_environment_value(normalized, value)
    return environment


def _required_environment_name(value: str) -> str:
    if not isinstance(value, str) or _ENVIRONMENT_NAME_RE.fullmatch(value) is None:
        raise ValueError("invalid child environment setting name")
    return value


def _required_environment_value(name: str, value: str) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError(f"invalid child environment setting {name!r}")
    return value



class ManagedAuthVerification(str, Enum):
    PROBE = "probe"
    RUNTIME = "runtime"


class TerminalLaunchProfile(str, Enum):
    CLAUDE_PHONE = "claude_phone"
    CODEX_WORKSPACE = "codex_workspace"


@dataclass(frozen=True)
class ManagedLaunchSetupDiagnostic:
    code: str
    category: str
    message: str
    setup_actions: tuple[str, ...] = ()

    def to_payload(self) -> dict:
        return {
            "code": self.code,
            "category": self.category,
            "message": self.message,
            "setup_actions": list(self.setup_actions),
        }


@dataclass(frozen=True)
class ManagedLaunchContract:
    control_channel: str
    ready_auth_states: tuple[str, ...]
    ready_config_states: tuple[str, ...]
    auth_verification: ManagedAuthVerification = ManagedAuthVerification.PROBE
    require_post_launch_verification: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.control_channel, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", self.control_channel)
            is None
        ):
            raise ValueError("managed launch control channel is invalid")
        for states, label in (
            (self.ready_auth_states, "auth"),
            (self.ready_config_states, "config"),
        ):
            if (
                not isinstance(states, tuple)
                or not states
                or len(states) != len(set(states))
                or any(
                    not isinstance(value, str)
                    or re.fullmatch(r"[a-z0-9_]{1,64}", value) is None
                    for value in states
                )
            ):
                raise ValueError(f"managed launch {label} states are invalid")
        if (
            "unknown" in self.ready_auth_states
            and self.auth_verification is not ManagedAuthVerification.RUNTIME
        ):
            raise ValueError(
                "unknown authentication requires explicit runtime verification"
            )

    def setup_diagnostic(
        self,
        availability,
        *,
        version: str | None,
    ) -> ManagedLaunchSetupDiagnostic | None:
        actions = tuple(getattr(availability, "setup_actions", ()) or ())
        if not bool(getattr(availability, "installed", False)):
            return ManagedLaunchSetupDiagnostic(
                "managed_provider_not_installed",
                "installation",
                "The reviewed provider executable is not installed.",
                actions,
            )
        if not isinstance(version, str) or not version.strip():
            return ManagedLaunchSetupDiagnostic(
                "managed_provider_version_unverified",
                "version",
                "The installed provider version could not be verified.",
                actions,
            )
        config_state = str(getattr(availability, "config_state", "") or "")
        if config_state not in self.ready_config_states:
            return ManagedLaunchSetupDiagnostic(
                "managed_provider_config_unavailable",
                "configuration",
                "The provider does not satisfy its reviewed managed-launch configuration.",
                actions,
            )
        auth_state = str(getattr(availability, "auth_state", "") or "")
        if auth_state not in self.ready_auth_states:
            return ManagedLaunchSetupDiagnostic(
                "managed_provider_auth_unavailable",
                "authentication",
                "The provider does not satisfy its reviewed authentication posture.",
                actions,
            )
        if not bool(getattr(availability, "usable", False)) or not bool(
            getattr(availability, "launchable", False)
        ):
            return ManagedLaunchSetupDiagnostic(
                "managed_provider_not_launchable",
                "availability",
                "The provider is not ready for a managed launch.",
                actions,
            )
        return None


@dataclass(frozen=True)
class TerminalLaunchContract:
    profile: TerminalLaunchProfile
    backends: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.profile, TerminalLaunchProfile):
            raise ValueError("terminal launch profile is invalid")
        if (
            not isinstance(self.backends, tuple)
            or not self.backends
            or len(self.backends) != len(set(self.backends))
            or any(value not in {"terminal_app", "broker"} for value in self.backends)
        ):
            raise ValueError("terminal launch backends are invalid")

@dataclass(frozen=True)
class ProviderDescriptor:
    provider_id: str
    display_name: str
    kind: str
    builtin: bool = True
    docs_url: str | None = None
    # Internal, automatic integration tier (deep | standard | recognized).
    # Never a permission, never a gate on the raw-PTY floor (SPEC-p1 §2.2).
    adapter_depth: str = "deep"
    managed_launch: ManagedLaunchContract | None = None
    terminal_launch: TerminalLaunchContract | None = None


@dataclass(frozen=True)
class ProviderAvailability:
    provider_id: str
    display_name: str
    kind: str
    installed: bool
    usable: bool
    launchable: bool
    auth_state: str
    config_state: str
    readable_sessions: int
    live_sessions: int
    controllable_sessions: int
    capabilities: tuple[ProviderCapability, ...]
    setup_actions: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProviderDiagnostics:
    cli_path: str | None = None
    cli_path_source: str | None = None
    version: str | None = None
    config_path: str | None = None
    config_exists: bool | None = None
    hook_count: int | None = None
    hooks_configured: bool | None = None
    mcp_count: int | None = None
    plugin_count: int | None = None
    registry_count: int | None = None
    registry_live_count: int | None = None


@dataclass(frozen=True)
class ProviderProbeResult:
    descriptor: ProviderDescriptor
    availability: ProviderAvailability
    diagnostics: ProviderDiagnostics
    observed_at: float

    def with_availability(self, **changes) -> "ProviderProbeResult":
        return replace(self, availability=replace(self.availability, **changes))

    def with_diagnostics(self, **changes) -> "ProviderProbeResult":
        return replace(self, diagnostics=replace(self.diagnostics, **changes))


class ProviderAdapter(Protocol):
    descriptor: ProviderDescriptor

    def probe(self) -> ProviderProbeResult:
        ...

    def supports(self, capability: ProviderCapability) -> bool:
        ...


@dataclass(frozen=True)
class ResolvedExecutable:
    path: Path
    source: str


def normalize_provider_id(raw: str) -> str:
    return (raw or "").strip().lower()


def is_valid_provider_id(raw: str) -> bool:
    provider_id = normalize_provider_id(raw)
    return bool(provider_id) and len(provider_id) <= 48 and re.fullmatch(r"[a-z0-9_]+", provider_id) is not None


def executable_candidates(name: str, known: Iterable[Path | str], env_var: str | None = None) -> list[tuple[Path, str]]:
    candidates: list[tuple[Path, str]] = []
    if env_var:
        configured = os.environ.get(env_var)
        if configured:
            candidates.append((Path(configured).expanduser(), f"env:{env_var}"))
    for candidate in known:
        candidates.append((Path(candidate).expanduser(), "known"))
    for prefix in os.environ.get("PATH", "").split(":"):
        if prefix:
            candidates.append((Path(prefix).expanduser() / name, "path"))
    return candidates


def resolve_executable(name: str, known: Iterable[Path | str], env_var: str | None = None) -> ResolvedExecutable | None:
    seen: set[str] = set()
    for candidate, source in executable_candidates(name, known, env_var=env_var):
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if candidate.exists() and os.access(candidate, os.X_OK):
            return ResolvedExecutable(candidate, source)
    return None
def resolve_pinned_executable(
    name: str,
    *,
    path_env_var: str,
    sha256_env_var: str,
) -> ResolvedExecutable | None:
    raw_path = os.environ.get(path_env_var, "").strip()
    expected_digest = os.environ.get(sha256_env_var, "").strip().lower()
    if (
        not raw_path
        or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
    ):
        return None
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        return None
    descriptor = -1
    try:
        descriptor = os.open(
            candidate,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.getuid()}
            or metadata.st_mode & 0o022
            or not os.access(candidate, os.X_OK)
        ):
            return None
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    except OSError:
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not hmac.compare_digest(digest.hexdigest(), expected_digest):
        return None
    return ResolvedExecutable(candidate, f"pinned:{path_env_var}")




def cli_version(
    bin_path: Path | str | None,
    args: list[str] | None = None,
    timeout: int = 3,
) -> str | None:
    if not bin_path:
        return None
    path = Path(bin_path)
    command_args = tuple(args or ["--version"])
    try:
        metadata = path.stat()
    except OSError:
        return None
    signature = (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )
    cache_key = (str(path), command_args, timeout)
    now = time.monotonic()
    with _CLI_VERSION_CACHE_LOCK:
        cached = _CLI_VERSION_CACHE.get(cache_key)
        if cached is not None:
            cached_signature, expires_at, value = cached
            if cached_signature == signature and expires_at > now:
                return value
            _CLI_VERSION_CACHE.pop(cache_key, None)
    try:
        proc = subprocess.run(
            [str(path), *command_args],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            env=managed_child_environment(),
        )
    except Exception:
        value = None
    else:
        value = (
            (proc.stdout or proc.stderr or "").strip()[:160] or None
            if proc.returncode == 0
            else None
        )
    with _CLI_VERSION_CACHE_LOCK:
        if len(_CLI_VERSION_CACHE) >= _CLI_VERSION_CACHE_MAX_ENTRIES:
            _CLI_VERSION_CACHE.pop(next(iter(_CLI_VERSION_CACHE)), None)
        _CLI_VERSION_CACHE[cache_key] = (
            signature,
            now + _CLI_VERSION_CACHE_TTL_SECONDS,
            value,
        )
    return value


def _clear_cli_version_cache_for_tests() -> None:
    with _CLI_VERSION_CACHE_LOCK:
        _CLI_VERSION_CACHE.clear()


def count_dirs(root: Path, excluded: set[str] | None = None) -> int:
    excluded = excluded or set()
    if not root.is_dir():
        return 0
    try:
        return sum(1 for p in root.iterdir() if p.is_dir() and not p.name.startswith(".") and p.name not in excluded)
    except OSError:
        return 0


def command_line_count(bin_path: Path | str | None, args: list[str], timeout: int = 5) -> int | None:
    if not bin_path:
        return None
    try:
        proc = subprocess.run(
            [str(bin_path), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            env=managed_child_environment(),
        )
    except Exception:
        return None
    text = (proc.stdout or proc.stderr or "").strip()
    if not text:
        return 0 if proc.returncode == 0 else None
    lines: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        low = s.lower()
        if not s:
            continue
        if low.startswith("no ") or "no mcp" in low:
            continue
        if low.startswith("name ") or set(s) <= {"-", " "}:
            continue
        lines.append(s)
    return len(lines)


def hook_command_count(obj) -> int:
    if isinstance(obj, dict):
        own = 1 if isinstance(obj.get("command"), str) and obj.get("command") else 0
        return own + sum(hook_command_count(v) for k, v in obj.items() if k != "command")
    if isinstance(obj, list):
        return sum(hook_command_count(v) for v in obj)
    return 0


def json_hook_count(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        obj = json.loads(path.read_text(errors="replace"))
    except Exception:
        return 0
    return hook_command_count(obj.get("hooks") if isinstance(obj, dict) and "hooks" in obj else obj)


def availability_dict(availability: ProviderAvailability) -> dict:
    data = asdict(availability)
    data["capabilities"] = list(availability.capabilities)
    data["setup_actions"] = list(availability.setup_actions)
    data["notes"] = list(availability.notes)
    return data


def diagnostics_dict(diagnostics: ProviderDiagnostics) -> dict:
    return asdict(diagnostics)


def provider_detail_payload(result: ProviderProbeResult) -> dict:
    payload = availability_dict(result.availability)
    payload.update(diagnostics_dict(result.diagnostics))
    payload["provider"] = result.availability.provider_id
    payload["ok"] = result.availability.usable
    payload["session_count"] = result.availability.readable_sessions
    payload["controllable_count"] = result.availability.controllable_sessions
    return payload


def provider_snapshot_payload(results: list[ProviderProbeResult], source: str = "live_probe", observed_at: float | None = None) -> dict:
    usable = [r.availability for r in results if r.availability.usable]
    default_provider_id: str | None = None
    default_filter = "all"
    if len(usable) == 1:
        default_provider_id = usable[0].provider_id
        default_filter = usable[0].provider_id
    elif len(usable) > 1:
        launchable = [p for p in usable if p.launchable]
        default_provider_id = launchable[0].provider_id if launchable else usable[0].provider_id

    ts = observed_at if observed_at is not None else time.time()
    return {
        "schema_version": 1,
        "providers": [availability_dict(r.availability) for r in results],
        "default_provider_id": default_provider_id,
        "default_filter": default_filter,
        "observed_at": ts,
        "source": source,
    }


def failed_probe(descriptor: ProviderDescriptor, exc: Exception) -> ProviderProbeResult:
    note = f"{type(exc).__name__}: {str(exc)[:160]}"
    availability = ProviderAvailability(
        provider_id=descriptor.provider_id,
        display_name=descriptor.display_name,
        kind=descriptor.kind,
        installed=False,
        usable=False,
        launchable=False,
        auth_state="unknown",
        config_state="unknown",
        readable_sessions=0,
        live_sessions=0,
        controllable_sessions=0,
        capabilities=("detect",),
        setup_actions=("repair_provider_probe",),
        notes=(note,),
    )
    return ProviderProbeResult(
        descriptor=descriptor,
        availability=availability,
        diagnostics=ProviderDiagnostics(),
        observed_at=time.time(),
    )
