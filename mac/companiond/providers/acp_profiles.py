"""Fail-closed, provider-owned launch profiles for reviewed ACP transports.

Profiles contain only arguments Pairling reviewed. Runtime values are inserted as
individual argv elements after filesystem validation; no shell string or
caller-provided argv is accepted. A profile is not a capability grant: the ACP
driver must still pass every declared initialize, permission, boundary, and
correlation canary before advertising operations.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


_SAFE_MCP_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_FORBIDDEN_FIXED_ARGUMENTS = frozenset(
    {
        "--add-dir",
        "--allow-all",
        "--allow-all-tools",
        "--always-approve",
        "--auto-approve",
        "--dangerously-skip-permissions",
        "--dangerously-unauthenticated",
        "--experimental-acp",
        "--include-directories",
        "--raw-output",
        "--skip-trust",
        "--yolo",
        "--yes-always",
        "bypassPermissions",
        "off",
    }
)
_FORBIDDEN_ARGUMENT_PREFIXES = (
    "--add-dir=",
    "--allow-all",
    "--allow-home",
    "--api-key",
    "--auto-approve",
    "--dangerously-",
    "--extension",
    "--hook",
    "--host-uri",
    "--include-directories=",
    "--plugin-dir",
    "--raw-output=",
    "--set-host-uri",
    "--skip-trust=",
    "--yolo=",
)
_SHA256_RE = re.compile(r"[a-f0-9]{64}\Z")
_CANARY_ATTESTATION_FIELDS = frozenset(
    {
        "schema_version",
        "provider_id",
        "provider_version",
        "provider_channel",
        "profile_digest",
        "managed_config_digest",
        "binding_id",
        "session_id",
        "capability_generation",
        "canaries",
        "evidence_digest",
        "observed_at",
        "expires_at",
    }
)


@dataclass(frozen=True)
class ManagedProfileFile:
    relative_path: str
    content: str
    sha256: str = field(init=False)

    def __post_init__(self) -> None:
        relative = Path(self.relative_path)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise ValueError("managed profile path must be relative and contained")
        object.__setattr__(
            self,
            "sha256",
            hashlib.sha256(self.content.encode("utf-8")).hexdigest(),
        )


@dataclass(frozen=True)
class ExperimentalOverlay:
    overlay_id: str
    provider_id: str
    transport: str
    executable: bool
    reason: str

@dataclass(frozen=True)
class DeferredAcpProfile:
    provider_id: str
    argv_suffix: tuple[str, ...]
    required_canaries: tuple[str, ...]
    executable: bool
    reason: str


@dataclass(frozen=True)
class AcpProfileUnavailable:
    provider_id: str
    reason: str
    code: str = "acp_unavailable"
    expected_versions: tuple[str, ...] = ()

@dataclass(frozen=True)
class AcpCanaryAttestation:
    schema_version: int
    provider_id: str
    provider_version: str
    provider_channel: str
    profile_digest: str
    managed_config_digest: str
    binding_id: str
    session_id: str
    capability_generation: int
    canaries: tuple[str, ...]
    evidence_digest: str
    observed_at: float
    expires_at: float


@dataclass(frozen=True)
class AcpLaunchProfile:
    provider_id: str
    accepted_versions: tuple[str, ...]
    allowed_channels: tuple[str, ...]
    argv_template: tuple[str, ...]
    protocol_version: int = 1
    managed_files: tuple[ManagedProfileFile, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    required_canaries: tuple[str, ...] = ()
    overlay_metadata: Mapping[str, Any] = field(default_factory=dict)
    allow_mcp: bool = False
    managed_config_digest: str = field(init=False)
    safe_launch_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if re.fullmatch(r"[a-z0-9_]{1,64}", self.provider_id) is None:
            raise ValueError("profile provider_id must be canonical")
        if not isinstance(self.argv_template, tuple) or not self.argv_template:
            raise ValueError("active ACP profiles require an immutable argv suffix")
        if (
            not isinstance(self.managed_files, tuple)
            or not all(isinstance(item, ManagedProfileFile) for item in self.managed_files)
            or len({item.relative_path for item in self.managed_files}) != len(self.managed_files)
        ):
            raise ValueError("managed profile files must be unique immutable definitions")
        for values, label in (
            (self.accepted_versions, "versions"),
            (self.allowed_channels, "channels"),
            (self.required_capabilities, "capabilities"),
            (self.required_canaries, "canaries"),
        ):
            if (
                not isinstance(values, tuple)
                or any(
                    not isinstance(value, str)
                    or not value
                    or len(value) > 256
                    or any(ord(character) < 32 for character in value)
                    for value in values
                )
            ):
                raise ValueError(f"profile {label} must be bounded string tuples")
            if len(values) != len(set(values)):
                raise ValueError(f"profile {label} must not contain duplicates")
        if self.protocol_version != 1:
            raise ValueError("only reviewed ACP protocol v1 profiles may execute")
        if (
            not self.accepted_versions
            or not self.allowed_channels
            or not self.required_capabilities
            or not self.required_canaries
        ):
            raise ValueError(
                "active ACP profiles require exact versions, channels, capabilities, and canaries"
            )
        for argument in self.argv_template:
            if not isinstance(argument, str) or not argument or "\x00" in argument or "\n" in argument:
                raise ValueError("profile argv contains an invalid argument")
            if _is_forbidden_argument(argument):
                raise ValueError(f"forbidden argument in ACP profile: {argument}")
        metadata = _frozen_json_mapping(self.overlay_metadata)
        object.__setattr__(self, "overlay_metadata", metadata)
        managed_payload = [
            {"relative_path": item.relative_path, "sha256": item.sha256}
            for item in self.managed_files
        ]
        managed_encoded = json.dumps(
            managed_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        object.__setattr__(
            self,
            "managed_config_digest",
            hashlib.sha256(managed_encoded).hexdigest(),
        )
        digest_versions = self.accepted_versions
        digest_capabilities = self.required_capabilities
        if self.provider_id == "omp":
            digest_versions = ("semver:*",)
            digest_capabilities = tuple(
                "agentInfo.version=semver:*"
                if capability.startswith("agentInfo.version=")
                else capability
                for capability in self.required_capabilities
            )
        digest_payload = {
            "provider_id": self.provider_id,
            "accepted_versions": digest_versions,
            "allowed_channels": self.allowed_channels,
            "argv_template": self.argv_template,
            "protocol_version": self.protocol_version,
            "managed_files": managed_payload,
            "required_capabilities": digest_capabilities,
            "required_canaries": self.required_canaries,
            "overlay_metadata": _plain_json(metadata),
            "allow_mcp": self.allow_mcp,
        }
        encoded = json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        object.__setattr__(self, "safe_launch_digest", hashlib.sha256(encoded).hexdigest())

    def materialize(
        self,
        *,
        cwd: Path,
        session_dir: Path,
        trusted_workspace_root: Path,
        trusted_session_root: Path,
        managed_config_path: Path | None = None,
        mcp_allowlist: tuple[str, ...] = (),
    ) -> tuple[str, ...] | AcpProfileUnavailable:
        """Render argv only inside explicit Pairling-owned path boundaries."""

        workspace_root = _validated_trusted_root(
            self.provider_id, trusted_workspace_root, "workspace_root"
        )
        if isinstance(workspace_root, AcpProfileUnavailable):
            return workspace_root
        checked_cwd = _validated_directory(self.provider_id, cwd, "cwd")
        if isinstance(checked_cwd, AcpProfileUnavailable):
            return checked_cwd
        if not _is_within(checked_cwd, workspace_root):
            return AcpProfileUnavailable(
                self.provider_id,
                "workspace is outside the trusted workspace root",
                "cwd_outside_trusted_root",
            )

        session_root = _validated_trusted_root(
            self.provider_id, trusted_session_root, "session_root"
        )
        if isinstance(session_root, AcpProfileUnavailable):
            return session_root
        checked_session = _validated_directory(self.provider_id, session_dir, "session_dir")
        if isinstance(checked_session, AcpProfileUnavailable):
            return checked_session
        if checked_session == session_root or not _is_within(checked_session, session_root):
            return AcpProfileUnavailable(
                self.provider_id,
                "provider session directory is outside its Pairling-owned root",
                "session_dir_outside_trusted_root",
            )
        if _is_within(checked_session, workspace_root) or _is_within(checked_cwd, session_root):
            return AcpProfileUnavailable(
                self.provider_id,
                "workspace and provider session roots must be disjoint",
                "unsafe_root_overlap",
            )

        normalized_mcp = tuple(mcp_allowlist)
        if normalized_mcp:
            if not self.allow_mcp:
                return AcpProfileUnavailable(
                    self.provider_id,
                    "no non-empty MCP allowlist is reviewed for this profile",
                    "mcp_not_reviewed",
                )
            if (
                len(normalized_mcp) > 16
                or len(set(normalized_mcp)) != len(normalized_mcp)
                or tuple(sorted(normalized_mcp)) != normalized_mcp
                or any(_SAFE_MCP_NAME.fullmatch(name) is None for name in normalized_mcp)
            ):
                return AcpProfileUnavailable(
                    self.provider_id,
                    "MCP allowlist must be sorted, unique, bounded provider names",
                    "unsafe_mcp_allowlist",
                )

        checked_config: Path | None = None
        if self.managed_files:
            checked_config = _validated_config_root(
                self.provider_id,
                managed_config_path,
                self.managed_files,
            )
            if isinstance(checked_config, AcpProfileUnavailable):
                return checked_config
        elif managed_config_path is not None:
            candidate = _validated_directory(self.provider_id, managed_config_path, "managed_config")
            if isinstance(candidate, AcpProfileUnavailable):
                return candidate
            checked_config = candidate
        if checked_config is not None and not _is_within(checked_config, checked_session):
            return AcpProfileUnavailable(
                self.provider_id,
                "managed configuration must live under the provider-owned session directory",
                "config_outside_session_root",
            )

        substitutions = {
            "{cwd}": str(checked_cwd),
            "{session_dir}": str(checked_session),
            "{mcp_allowlist}": ",".join(normalized_mcp),
        }
        if checked_config is not None:
            substitutions["{config_root}"] = str(checked_config)

        rendered: list[str] = []
        for template in self.argv_template:
            argument = template
            for marker, value in substitutions.items():
                argument = argument.replace(marker, value)
            if "{" in argument or "}" in argument or not argument or "\x00" in argument or "\n" in argument:
                return AcpProfileUnavailable(
                    self.provider_id,
                    "launch profile contains an unresolved or unsafe placeholder",
                    "profile_materialization_failed",
                )
            if _is_forbidden_argument(argument):
                return AcpProfileUnavailable(
                    self.provider_id,
                    "launch profile materialized a forbidden argument",
                    "forbidden_argument",
                )
            rendered.append(argument)
        return tuple(rendered)

def validate_canary_attestation(
    profile: AcpLaunchProfile,
    raw: Mapping[str, Any] | AcpCanaryAttestation,
    *,
    binding_id: str,
    session_id: str,
    capability_generation: int,
    now: float | None = None,
) -> AcpCanaryAttestation | AcpProfileUnavailable:
    """Validate trusted session truth without accepting a client-side boolean."""

    if isinstance(raw, AcpCanaryAttestation):
        payload: Mapping[str, Any] = {
            "schema_version": raw.schema_version,
            "provider_id": raw.provider_id,
            "provider_version": raw.provider_version,
            "provider_channel": raw.provider_channel,
            "profile_digest": raw.profile_digest,
            "managed_config_digest": raw.managed_config_digest,
            "binding_id": raw.binding_id,
            "session_id": raw.session_id,
            "capability_generation": raw.capability_generation,
            "canaries": list(raw.canaries),
            "evidence_digest": raw.evidence_digest,
            "observed_at": raw.observed_at,
            "expires_at": raw.expires_at,
        }
    elif isinstance(raw, Mapping):
        payload = raw
    else:
        return AcpProfileUnavailable(
            profile.provider_id,
            "provider canary attestation is not an object",
            "canary_attestation_invalid",
            profile.accepted_versions,
        )

    if set(payload) != _CANARY_ATTESTATION_FIELDS:
        return AcpProfileUnavailable(
            profile.provider_id,
            "provider canary attestation fields are missing or unknown",
            "canary_attestation_invalid",
            profile.accepted_versions,
        )

    strings: dict[str, str] = {}
    for key in (
        "provider_id",
        "provider_version",
        "provider_channel",
        "profile_digest",
        "managed_config_digest",
        "binding_id",
        "session_id",
        "evidence_digest",
    ):
        value = payload.get(key)
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 512
            or any(ord(character) < 32 for character in value)
        ):
            return AcpProfileUnavailable(
                profile.provider_id,
                f"provider canary attestation has invalid {key}",
                "canary_attestation_invalid",
                profile.accepted_versions,
            )
        strings[key] = value

    schema_version = payload.get("schema_version")
    generation = payload.get("capability_generation")
    canaries = payload.get("canaries")
    observed_at = payload.get("observed_at")
    expires_at = payload.get("expires_at")
    if (
        isinstance(schema_version, bool)
        or schema_version != 1
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 1
        or not isinstance(canaries, list)
        or not all(isinstance(item, str) and item for item in canaries)
        or isinstance(observed_at, bool)
        or not isinstance(observed_at, (int, float))
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
        or not math.isfinite(float(observed_at))
        or not math.isfinite(float(expires_at))
        or _SHA256_RE.fullmatch(strings["profile_digest"]) is None
        or _SHA256_RE.fullmatch(strings["managed_config_digest"]) is None
        or _SHA256_RE.fullmatch(strings["evidence_digest"]) is None
    ):
        return AcpProfileUnavailable(
            profile.provider_id,
            "provider canary attestation values are malformed",
            "canary_attestation_invalid",
            profile.accepted_versions,
        )

    identity_matches = (
        strings["provider_id"] == profile.provider_id
        and strings["provider_version"] in profile.accepted_versions
        and strings["provider_channel"] in profile.allowed_channels
        and strings["profile_digest"] == profile.safe_launch_digest
        and strings["managed_config_digest"] == profile.managed_config_digest
        and strings["binding_id"] == binding_id
        and strings["session_id"] == session_id
        and generation == capability_generation
    )
    if not identity_matches:
        return AcpProfileUnavailable(
            profile.provider_id,
            "provider canary attestation does not match the live binding",
            "canary_attestation_mismatch",
            profile.accepted_versions,
        )

    normalized_canaries = tuple(canaries)
    if normalized_canaries != profile.required_canaries:
        return AcpProfileUnavailable(
            profile.provider_id,
            "provider canary attestation does not cover the exact reviewed canary set",
            "canary_attestation_incomplete",
            profile.accepted_versions,
        )

    observed = float(observed_at)
    expires = float(expires_at)
    current = time.time() if now is None else float(now)
    if (
        expires <= observed
        or expires - observed > 24 * 60 * 60
        or current < observed - 300
        or current > expires
    ):
        return AcpProfileUnavailable(
            profile.provider_id,
            "provider canary attestation is stale or has an invalid lifetime",
            "canary_attestation_stale",
            profile.accepted_versions,
        )

    return AcpCanaryAttestation(
        schema_version=1,
        provider_id=strings["provider_id"],
        provider_version=strings["provider_version"],
        provider_channel=strings["provider_channel"],
        profile_digest=strings["profile_digest"],
        managed_config_digest=strings["managed_config_digest"],
        binding_id=strings["binding_id"],
        session_id=strings["session_id"],
        capability_generation=generation,
        canaries=normalized_canaries,
        evidence_digest=strings["evidence_digest"],
        observed_at=observed,
        expires_at=expires,
    )


def _is_forbidden_argument(argument: str) -> bool:
    lowered = argument.strip().lower()
    normalized_argument = re.sub(r"[^a-z0-9]", "", lowered)
    _, separator, raw_value = lowered.partition("=")
    normalized_value = re.sub(r"[^a-z0-9]", "", raw_value) if separator else ""
    return (
        lowered in _FORBIDDEN_FIXED_ARGUMENTS
        or normalized_argument in {
            "auto", "autoapprove", "bypasspermissions", "neverconfirm", "off", "yolo"
        }
        or normalized_value in {
            "auto", "autoapprove", "bypasspermissions", "neverconfirm", "off", "yolo"
        }
        or any(lowered.startswith(prefix) for prefix in _FORBIDDEN_ARGUMENT_PREFIXES)
    )


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain_json(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_plain_json(child) for child in value]
    return value


def _frozen_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _frozen_json_value(child) for key, child in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_frozen_json_value(child) for child in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError("overlay metadata must contain JSON-safe values only")


def _frozen_json_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    frozen = _frozen_json_value(value)
    if not isinstance(frozen, Mapping):
        raise ValueError("overlay metadata must be an object")
    return frozen


def _validated_directory(
    provider_id: str,
    raw_path: Path,
    field_name: str,
) -> Path | AcpProfileUnavailable:
    try:
        path = Path(raw_path)
    except TypeError:
        return AcpProfileUnavailable(provider_id, f"{field_name} is not a path", f"unsafe_{field_name}")
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path) or "\n" in str(path):
        return AcpProfileUnavailable(
            provider_id,
            f"{field_name} must be an absolute contained path",
            f"unsafe_{field_name}",
        )
    try:
        if path.is_symlink() or not path.is_dir():
            raise OSError("not a real directory")
        resolved = path.resolve(strict=True)
    except OSError:
        return AcpProfileUnavailable(
            provider_id,
            f"{field_name} must be an existing non-symlink directory",
            f"unsafe_{field_name}",
        )
    return resolved

def _validated_trusted_root(
    provider_id: str,
    raw_path: Path,
    field_name: str,
) -> Path | AcpProfileUnavailable:
    root = _validated_directory(provider_id, raw_path, field_name)
    if isinstance(root, AcpProfileUnavailable):
        return root
    if root == Path(root.anchor):
        return AcpProfileUnavailable(
            provider_id,
            f"{field_name} must not be a filesystem root",
            f"unsafe_{field_name}",
        )
    return root


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _validated_config_root(
    provider_id: str,
    raw_root: Path | None,
    managed_files: tuple[ManagedProfileFile, ...],
) -> Path | AcpProfileUnavailable:
    if raw_root is None:
        return AcpProfileUnavailable(
            provider_id,
            "the Pairling-owned managed configuration is required",
            "managed_config_required",
        )
    root = _validated_directory(provider_id, raw_root, "managed_config")
    if isinstance(root, AcpProfileUnavailable):
        return root
    for expected in managed_files:
        target = root / expected.relative_path
        try:
            if target.is_symlink() or not target.is_file():
                raise OSError("not a regular managed file")
            resolved = target.resolve(strict=True)
            resolved.relative_to(root)
            stat_result = resolved.stat()
            if stat_result.st_mode & 0o022:
                return AcpProfileUnavailable(
                    provider_id,
                    f"managed configuration is group/world writable: {expected.relative_path}",
                    "unsafe_managed_config_permissions",
                )
            if hasattr(os, "getuid") and stat_result.st_uid != os.getuid():
                return AcpProfileUnavailable(
                    provider_id,
                    f"managed configuration has an unexpected owner: {expected.relative_path}",
                    "unsafe_managed_config_owner",
                )
            content = resolved.read_bytes()
        except (OSError, ValueError):
            return AcpProfileUnavailable(
                provider_id,
                f"managed configuration is missing or escapes its root: {expected.relative_path}",
                "managed_config_invalid",
            )
        if len(content) > 128 * 1024 or hashlib.sha256(content).hexdigest() != expected.sha256:
            return AcpProfileUnavailable(
                provider_id,
                f"managed configuration digest changed: {expected.relative_path}",
                "config_digest_mismatch",
            )
    return root


_GEMINI_USER_POLICY = """# Pairling-owned Gemini policy. Do not merge workspace policy into this file.\n[[rule]]\ntoolName = \"run_shell_command\"\ndecision = \"ask_user\"\npriority = 999\n\n[[rule]]\ntoolName = \"write_file\"\ndecision = \"ask_user\"\npriority = 999\n\n[[rule]]\ntoolName = \"replace\"\ndecision = \"ask_user\"\npriority = 999\n"""

_GEMINI_ADMIN_POLICY = """# Pairling-owned admin policy. Admin-tier denials win over lower tiers.\n[[rule]]\ntoolName = \"web_fetch\"\ndecision = \"deny\"\npriority = 999\n\n[[rule]]\ntoolName = \"mcp_*\"\ndecision = \"deny\"\npriority = 999\n\n[[rule]]\ntoolName = \"run_shell_command\"\ndecision = \"ask_user\"\npriority = 999\n\n[[rule]]\ntoolName = \"write_file\"\ndecision = \"ask_user\"\npriority = 999\n\n[[rule]]\ntoolName = \"replace\"\ndecision = \"ask_user\"\npriority = 999\n"""

_OMP_CONFIG = """plan:\n  enabled: false\ntools:\n  approvalMode: always-ask\n  approval:\n    bash: prompt\n    edit: prompt\n    write: prompt\n    delete: prompt\n    move: prompt\n    lsp: prompt\n    eval: deny\n    python: deny\n    notebook: deny\n    browser: deny\n    computer: deny\n    task: deny\n    github: deny\n"""

_COMMON_CANARIES = (
    # Live attestation is intentionally limited to facts observable before
    # operations are exposed. Permission, update, and cancellation behavior is
    # enforced by the driver and protocol tests, never used as a circular gate.
    "initialize_capabilities",
    "cwd_boundary",
    "binding_generation_session_action_correlation",
)

_PROFILES: dict[str, AcpLaunchProfile] = {
    "gemini_cli": AcpLaunchProfile(
        provider_id="gemini_cli",
        accepted_versions=("0.53.1",),
        allowed_channels=("stable",),
        argv_template=(
            "--acp",
            "--approval-mode=default",
            "--allowed-mcp-server-names=pairling-no-mcp",
            "--policy",
            "{config_root}/user-policy.toml",
            "--admin-policy",
            "{config_root}/admin-policy.toml",
        ),
        managed_files=(
            ManagedProfileFile("user-policy.toml", _GEMINI_USER_POLICY),
            ManagedProfileFile("admin-policy.toml", _GEMINI_ADMIN_POLICY),
        ),
        required_capabilities=(
            "agentInfo.name=gemini-cli",
            "agentInfo.version=0.53.1",
            "agentCapabilities.loadSession=true",
            "promptCapabilities.image=true",
            "promptCapabilities.audio=true",
            "promptCapabilities.embeddedContext=true",
            "mcpCapabilities.http=true",
            "mcpCapabilities.sse=true",
        ),
        required_canaries=_COMMON_CANARIES
        + (
            "approval_mode_default",
            "sandbox_active",
            "folder_trust_exact_cwd",
            "mcp_allowlist_enforced",
            "client_fs_root_only",
        ),
        overlay_metadata={
            "settings": {
                "general.defaultApprovalMode": "default",
                "security.folderTrust.enabled": True,
                "security.disableAlwaysAllow": True,
                "security.enablePermanentToolApproval": False,
                "security.toolSandboxing": True,
                "tools.sandboxNetworkAccess": False,
                "context.includeDirectories": [],
                "admin.extensions.enabled": False,
                "admin.skills.enabled": False,
                "hooks.enabled": False,
                "experimental.enableAgents": False,
            },
            "permission_options": ["allow_once", "reject"],
            "unknown_extensions": "data_only",
            "reviewed_extension_methods": ["session/set_model"],
            "seatbelt": {
                "profile": "gemini-seatbelt.sb",
                "sha256": "c7e33f2d243ec3d1579488aff4e7e437449322e4750aa0f53abf78f33b197425",
            },
        },
    ),
    "omp": AcpLaunchProfile(
        provider_id="omp",
        accepted_versions=("semver:*",),
        allowed_channels=("stable",),
        argv_template=(
            "--profile",
            "pairling",
            "--cwd",
            "{cwd}",
            "--session-dir",
            "{session_dir}",
            "--approval-mode",
            "always-ask",
            "--no-pty",
            "--no-extensions",
            "--no-skills",
            "--no-rules",
            "--tools=read,grep,glob,ast_grep,lsp,edit,write,bash,todo",
            "--config",
            "{config_root}/omp.yml",
            "acp",
        ),
        managed_files=(ManagedProfileFile("omp.yml", _OMP_CONFIG),),
        required_capabilities=(
            "agentInfo.name=oh-my-pi",
            "agentInfo.version=semver:*",
            "agentCapabilities.loadSession=true",
            "sessionCapabilities.list=true",
            "sessionCapabilities.resume=true",
            "sessionCapabilities.close=true",
        ),
        required_canaries=_COMMON_CANARIES
        + (
            "approval_mode_always_ask",
            "extensions_skills_rules_plan_disabled",
        ),
        overlay_metadata={
            "profile": "pairling",
            "disabled": ["plan", "extensions", "skills", "rules", "task", "browser", "computer"],
            "permission_options": ["allow_once", "reject"],
            "unknown_extensions": "data_only",
        },
    ),
    "grok_build": AcpLaunchProfile(
        provider_id="grok_build",
        accepted_versions=("grok 0.2.118 (1e1687c1cf6a) [stable]",),
        allowed_channels=("stable",),
        argv_template=(
            "--no-auto-update",
            "--cwd",
            "{cwd}",
            "--sandbox",
            "workspace",
            "--permission-mode",
            "default",
            "--deny",
            "Bash(rm -rf *)",
            "--deny",
            "Bash(sudo*)",
            "--deny",
            "Bash(git push*)",
            "--deny",
            "Bash(git reset --hard*)",
            "--deny",
            "Bash(git clean*)",
            "agent",
            "--no-leader",
            "stdio",
        ),
        required_capabilities=(
            "protocolVersion=1",
            "agentCapabilities.loadSession=true",
        ),
        required_canaries=_COMMON_CANARIES
        + (
            "grok_shell_metadata",
            "agent_version_metadata",
            "workspace_sandbox_active",
            "no_leader_local_process",
        ),
        overlay_metadata={
            "sandbox": "workspace",
            "sandbox_deny_globs": ["**/.env", "**/*.pem", "**/*credentials*"],
            "network": "not_trusted_as_containment",
            "unknown_extensions": "data_only",
            "reviewed_extension_methods": ["session/set_model"],
        },
    ),
    "kimi_code": AcpLaunchProfile(
        provider_id="kimi_code",
        accepted_versions=("0.31.1",),
        allowed_channels=("stable",),
        argv_template=("acp",),
        required_capabilities=(
            "agentCapabilities.loadSession=true",
            "promptCapabilities.image=true",
            "promptCapabilities.audio=false",
            "promptCapabilities.embeddedContext=true",
            "mcpCapabilities.http=true",
            "mcpCapabilities.sse=true",
            "sessionCapabilities.list=true",
            "sessionCapabilities.resume=true",
        ),
        required_canaries=_COMMON_CANARIES
        + (
            "no_transport_mcp",
        ),
        overlay_metadata={
            "experimental_model_control": {
                "method": "session/set_config_option:model",
                "executable": False,
            },
            "unstable_methods": "data_only",
            "unknown_extensions": "data_only",
        },
    ),
    "hermes_agent": AcpLaunchProfile(
        provider_id="hermes_agent",
        accepted_versions=("Hermes Agent v0.19.0 (2026.7.20) · upstream 937222f4",),
        allowed_channels=("stable",),
        argv_template=("acp",),
        required_capabilities=(
            "agentInfo.name=hermes-agent",
            "agentInfo.version=0.19.0",
            "agentCapabilities.loadSession=true",
            "promptCapabilities.image=true",
            "sessionCapabilities.list=true",
            "sessionCapabilities.resume=true",
        ),
        required_canaries=_COMMON_CANARIES
        + (
            "model_state_present",
            "no_accept_hooks_arg",
            "no_transport_mcp",
            "client_fs_root_only",
        ),
        overlay_metadata={
            "hooks": "not_accepted",
            "permission_options_exposed": ["allow_once", "reject"],
            "persistent_permission_options": "filtered",
            "authenticate": "status_only",
            "unknown_extensions": "data_only",
        },
    ),
    "cline_cli": AcpLaunchProfile(
        provider_id="cline_cli",
        accepted_versions=("3.0.49",),
        allowed_channels=("stable",),
        argv_template=("--acp",),
        required_capabilities=(
            "protocolVersion=1",
        ),
        required_canaries=_COMMON_CANARIES
        + (
            "negotiated_documented_acp_only",
        ),
        overlay_metadata={
            "hub_websocket": "not_exposed",
            "connectors": "disabled_until_allowlisted",
            "unknown_extensions": "data_only",
        },
    ),
}


ACTIVE_ACP_PROVIDER_IDS = tuple(_PROFILES)

def active_acp_profiles() -> tuple[AcpLaunchProfile, ...]:
    """Return the exact immutable profiles that can back registry ACP adapters."""
    return tuple(_PROFILES.values())

DEFERRED_ACP_PROFILES = MappingProxyType(
    {
        "cursor_agent": DeferredAcpProfile(
            provider_id="cursor_agent",
            argv_suffix=("acp",),
            required_canaries=(
                "exact_installed_version",
                "initialize_capabilities",
                "auto_approval_disabled",
                "permission_denial",
                "cancel_correlation",
            ),
            executable=False,
            reason="Cursor's live ACP documentation does not publish an exact CLI build identity",
        ),
        "opencode": DeferredAcpProfile(
            provider_id="opencode",
            argv_suffix=("acp",),
            required_canaries=(
                "exact_installed_version",
                "initialize_capabilities",
                "auto_approval_disabled",
                "permission_denial",
            ),
            executable=False,
            reason="OpenCode 1.15.10 ACP auto-approves permission requests and is not safe for remote control",
        ),
    }
)

EXPERIMENTAL_OVERLAYS = (
    ExperimentalOverlay(
        "omp.rpc_ui.v2",
        "omp",
        "stdio_rpc_v2",
        False,
        "OMP-specific RPC controls are row-level experimental and include unsafe raw command surfaces",
    ),
    ExperimentalOverlay(
        "kimi.web",
        "kimi_code",
        "web",
        False,
        "Kimi web transport is not part of the reviewed authenticated ACP binding",
    ),
    ExperimentalOverlay(
        "provider.extension_rpc",
        "all",
        "extension_rpc",
        False,
        "unknown provider extensions are inert data until separately reviewed",
    ),
    ExperimentalOverlay(
        "goose.acp",
        "goose",
        "stdio_acp_experimental",
        False,
        "Goose documents ACP as experimental; unauthenticated server modes are forbidden",
    ),
)

_PROVIDER_ALIASES = {
    "cline": "cline_cli",
    "cursor": "cursor_agent",
    "cursor_agent_cli": "cursor_agent",
    "gemini": "gemini_cli",
    "grok": "grok_build",
    "grokbuild": "grok_build",
    "hermes": "hermes_agent",
    "hermes_agent_cli": "hermes_agent",
    "kimi": "kimi_code",
    "kimi_cli": "kimi_code",
    "oh_my_pi": "omp",
}


def reviewed_acp_profile(
    provider_id: str,
    installed_version: str,
    channel: str,
) -> AcpLaunchProfile | AcpProfileUnavailable:
    """Return an executable profile bound to the exact installed build/channel."""

    normalized = str(provider_id or "").strip().lower().replace("-", "_")
    normalized = _PROVIDER_ALIASES.get(normalized, normalized)
    version = str(installed_version or "").strip()
    normalized_channel = str(channel or "").strip().lower()

    if normalized == "goose":
        return AcpProfileUnavailable(
            normalized,
            "Goose ACP remains experimental and is not executable",
            "experimental_transport",
            ("1.45.0",),
        )
    if normalized == "cursor_agent":
        return AcpProfileUnavailable(
            normalized,
            "Cursor's live ACP documentation does not publish an exact CLI build identity",
            "version_not_reviewed",
        )
    deferred = DEFERRED_ACP_PROFILES.get(normalized)
    if deferred is not None:
        return AcpProfileUnavailable(
            normalized,
            deferred.reason,
            "profile_not_reviewed",
        )
    profile = _PROFILES.get(normalized)
    if profile is None:
        return AcpProfileUnavailable(
            normalized,
            "provider has no reviewed ACP launch profile",
            "profile_not_reviewed",
        )
    if normalized_channel not in profile.allowed_channels:
        return AcpProfileUnavailable(
            normalized,
            f"provider channel is not reviewed: {normalized_channel or '<empty>'}",
            "channel_not_reviewed",
            profile.accepted_versions,
        )
    if normalized == "omp":
        if re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", version) is None:
            return AcpProfileUnavailable(
                normalized,
                f"installed provider version is not canonical: {version or '<empty>'}",
                "version_not_reviewed",
                profile.accepted_versions,
            )
        return replace(
            profile,
            accepted_versions=(version,),
            required_capabilities=tuple(
                f"agentInfo.version={version}"
                if capability.startswith("agentInfo.version=")
                else capability
                for capability in profile.required_capabilities
            ),
        )
    if version not in profile.accepted_versions:
        return AcpProfileUnavailable(
            normalized,
            f"installed provider version is not reviewed: {version or '<empty>'}",
            "version_not_reviewed",
            profile.accepted_versions,
        )
    return profile
