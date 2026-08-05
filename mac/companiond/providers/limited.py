"""Honest limited/map-only provider profiles.

These profiles describe what Pairling may show after exact version and canary
checks. They do not create a structured control driver. The existing PTY path
remains the execution floor for Aider and Kiro, and experimental transports are
never promoted by detection alone.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LimitedProfileUnavailable:
    provider_id: str
    reason: str
    code: str = "limited_unavailable"
    expected_versions: tuple[str, ...] = ()


@dataclass(frozen=True)
class LimitedProviderProfile:
    provider_id: str
    accepted_versions: tuple[str, ...]
    transport: str
    launch_argv: tuple[str, ...]
    observed_features: tuple[str, ...]
    eligible_operations: tuple[str, ...]
    advertised_operations: tuple[str, ...]
    mutations_executable: bool
    required_canaries: tuple[str, ...] = ()
    experimental: bool = False
    notes: tuple[str, ...] = ()


_LIMITED_PROFILES = {
    "pi_coding_agent": LimitedProviderProfile(
        provider_id="pi_coding_agent",
        accepted_versions=("0.83.0",),
        transport="rpc_read_only",
        launch_argv=("pi", "--mode", "rpc"),
        observed_features=("observation", "history", "tree", "usage", "interrupt"),
        eligible_operations=("session.turn.interrupt", "provider.usage.read"),
        advertised_operations=(),
        mutations_executable=False,
        required_canaries=("driver_owned_session", "read_only_rpc"),
        notes=(
            "Never expose Pi RPC bash, raw commands, model changes, or session mutation.",
            "History and tree remain observation data, not executable operation IDs.",
        ),
    ),
    "aider": LimitedProviderProfile(
        provider_id="aider",
        accepted_versions=("0.86.0",),
        transport="pty",
        launch_argv=("aider",),
        observed_features=("terminal", "repo_map", "diff", "history"),
        eligible_operations=(),
        advertised_operations=(),
        mutations_executable=False,
        notes=(
            "No supported structured event/control protocol was verified.",
            "Never add --yes-always or remotely execute slash commands.",
        ),
    ),
    "kiro_cli": LimitedProviderProfile(
        provider_id="kiro_cli",
        accepted_versions=("2.16.0",),
        transport="pty",
        launch_argv=("kiro-cli",),
        observed_features=("terminal", "history", "queued_input"),
        eligible_operations=(),
        advertised_operations=(),
        mutations_executable=False,
        notes=(
            "No public structured control protocol was verified.",
            "V3 tangent/spec/unified harness features remain early access and hidden.",
        ),
    ),
    "goose": LimitedProviderProfile(
        provider_id="goose",
        accepted_versions=("1.45.0",),
        transport="acp_experimental_map_only",
        launch_argv=("goose", "acp"),
        observed_features=("session_list", "session_export", "resume", "fork"),
        eligible_operations=(),
        advertised_operations=(),
        mutations_executable=False,
        experimental=True,
        notes=(
            "Goose ACP remains experimental and is not executable through this adapter.",
            "Never expose goose serve --dangerously-unauthenticated.",
        ),
    ),
}

_ALIASES = {
    "kiro": "kiro_cli",
    "pi": "pi_coding_agent",
}


def limited_provider_profile(
    provider_id: str,
    installed_version: str,
    *,
    canaries: tuple[str, ...] = (),
) -> LimitedProviderProfile | LimitedProfileUnavailable:
    """Return a limited profile only after exact version/canary qualification."""

    normalized = str(provider_id or "").strip().lower().replace("-", "_")
    normalized = _ALIASES.get(normalized, normalized)
    profile = _LIMITED_PROFILES.get(normalized)
    if profile is None:
        return LimitedProfileUnavailable(
            normalized,
            "provider has no reviewed limited profile",
            "profile_not_reviewed",
        )
    version = str(installed_version or "").strip()
    if version not in profile.accepted_versions:
        return LimitedProfileUnavailable(
            normalized,
            f"installed provider version is not reviewed: {version or '<empty>'}",
            "version_not_reviewed",
            profile.accepted_versions,
        )
    supplied = frozenset(str(item) for item in canaries)
    missing = tuple(item for item in profile.required_canaries if item not in supplied)
    if missing:
        return LimitedProfileUnavailable(
            normalized,
            f"required limited-provider canaries have not passed: {', '.join(missing)}",
            "canary_required",
            profile.accepted_versions,
        )
    return profile


def create_control_driver(binding):
    """Limited/map-only detection never manufactures a structured driver.

    Pi becomes eligible for a future read-only driver only after a driver-owned
    process has produced both required canaries. This module deliberately has no
    process/session transport, so returning a driver here would silently promote
    detection evidence into control authority.
    """

    del binding
    return None
