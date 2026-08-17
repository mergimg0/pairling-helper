"""Typed capability-graph loading, semantic validation, and runtime lookup."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from datetime import datetime
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


CAPABILITY_GRAPH_SCHEMA_VERSION = "2.0.0"
CAPABILITY_GRAPH_SCHEMA_REF = "./coding-agent-remote-control-capability-map.schema.json"
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ID_RE = re.compile(r"[a-z][a-z0-9_.-]{1,255}\Z")
_OPERATION_RE = re.compile(r"(?:session|provider)(?:\.[a-z][a-z0-9_]*){1,3}\Z")
_STABLE_SEMVER_RE = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\Z")
_TOP_LEVEL_FIELDS = frozenset(
    {
        "$schema",
        "schema_version",
        "observed_at",
        "evidence_policy",
        "evidence_sources",
        "providers",
        "implementations",
        "transports",
        "capabilities",
        "operation_bindings",
        "evidence_claims",
        "exclusions",
    }
)
_PROVIDER_FIELDS = frozenset(
    {"provider_id", "display_name", "implementation_eligibility", "source_refs"}
)
_IMPLEMENTATION_FIELDS = frozenset(
    {
        "implementation_id",
        "provider_id",
        "identity_status",
        "provider_version",
        "provider_channel",
        "observed_versions",
        "observed_channels",
        "transport_ids",
        "release_membership",
    }
)
_TRANSPORT_FIELDS = frozenset({"transport_id", "provider_id", "description", "kind"})
_CAPABILITY_FIELDS = frozenset(
    {
        "capability_id",
        "provider_id",
        "implementation_ids",
        "plane",
        "behavior",
        "exact_exposure",
        "lifecycle",
        "machine_readable",
        "maturity",
        "version_constraints",
        "remote_safety",
        "required_pairling_addition",
        "shared_semantics",
        "provider_overlay",
        "source_refs",
    }
)
_BINDING_FIELDS = frozenset(
    {
        "implementation_operation_id",
        "implementation_id",
        "operation_id",
        "capability_ids",
        "implementation_status",
        "release_status",
        "requires",
        "effects",
        "invalidates",
        "forbids",
        "retry",
        "runtime_proofs_required",
        "evidence_claim_ids",
        "source_refs",
        "required_pairling_addition",
        "semantic_digest",
    }
)
_CLAIM_FIELDS = frozenset(
    {"claim_id", "subject_type", "subject_id", "classification", "assertion", "source_refs"}
)
_RELEASE_FIELDS = frozenset(
    {
        "runtime_provider_id",
        "provider_version",
        "provider_channel",
        "launch_config_digest",
        "physical_device_required",
    }
)
_REQUIRED_BINDING_REQUIREMENTS = frozenset(
    {
        "release_membership",
        "fresh_snapshot",
        "exact_identity",
        "device_scope",
        "resource_proof",
        "confirmation",
    }
)
_READ_EFFECT = "return_data"
_EVIDENCE_POLICY_FIELDS = frozenset(
    {
        "rule",
        "direct_sources_required",
        "machine_readable_values",
        "support_values",
        "safety_rule",
        "machine_readable_qualification",
        "missing_evidence_is_unsupported",
    }
)
_SOURCE_KINDS = frozenset(
    {
        "checked_in_source",
        "official_protocol",
        "draft_protocol",
        "official_release",
        "official_docs",
        "tagged_source",
        "official_package",
        "official_notice",
    }
)
_IMPLEMENTATION_ELIGIBILITY = frozenset(
    {"implementation_candidate", "research_candidate", "terminal_floor", "map_only"}
)
_IDENTITY_STATUSES = frozenset(
    {"release_pinned", "source_pinned", "observed", "unversioned"}
)
_TRANSPORT_KINDS = frozenset(
    {
        "acp_stdio",
        "sdk_subprocess",
        "jsonrpc_stdio",
        "http_loopback",
        "websocket_loopback",
        "cli_process",
        "pty",
        "cloud_service",
        "editor_extension",
        "unknown",
    }
)
_PLANES = frozenset({"receive", "read", "control", "steer"})
_LIFECYCLES = frozenset(
    {"before_turn", "during_turn", "after_turn", "provider_wide"}
)
_MATURITIES = frozenset(
    {"public", "experimental", "draft", "version_specific", "unsafe", "unknown"}
)
_REMOTE_SAFETY = frozenset(
    {"safe", "confirmation", "required_local_only", "do_not_expose"}
)
_RELEASABLE_MATURITIES = frozenset({"public", "experimental", "version_specific"})
_RELEASABLE_REMOTE_SAFETY = frozenset({"safe", "confirmation"})
_IMPLEMENTATION_STATUSES = frozenset({"implemented", "mapped", "excluded"})
_RELEASE_STATUSES = frozenset({"released", "not_released"})
_CLAIM_CLASSIFICATIONS = frozenset(
    {"vendor_surface", "pairling_support", "runtime_behavior", "exclusion"}
)
_RUNTIME_PROOFS = frozenset(
    {
        "operation_discovered",
        "release_member",
        "exact_implementation",
        "fresh_generation",
        "exact_session",
        "owned_process_live",
        "provider_authenticated",
        "safe_policy_active",
        "pending_request_correlated",
        "safe_choices_discovered",
    }
)
_RETRY_FIELDS = frozenset({"replay", "recovery", "ambiguity", "correlation"})
_REPLAY_VALUES = frozenset({"safe", "same_action_only", "recover_only", "forbidden"})
_RECOVERY_VALUES = frozenset(
    {
        "provider_status",
        "provider_event",
        "manager_receipt",
        "process_observation",
        "unavailable",
    }
)
_AMBIGUITY_VALUES = frozenset({"outcome_unknown", "rejected"})
_CORRELATION_VALUES = frozenset(
    {"none", "client_action_id", "provider_operation_id", "client_and_provider"}
)
_REQUIREMENT_FIELDS = {
    "release_membership": frozenset({"kind"}),
    "fresh_snapshot": frozenset({"kind", "max_age_seconds"}),
    "exact_identity": frozenset({"kind", "dimensions"}),
    "device_scope": frozenset({"kind", "scope"}),
    "resource_proof": frozenset({"kind", "proof_kind"}),
    "confirmation": frozenset({"kind", "mode"}),
    "owned_process": frozenset({"kind", "owner"}),
}
_IDENTITY_DIMENSIONS = frozenset(
    {
        "provider",
        "implementation",
        "binding",
        "session",
        "generation",
        "request",
        "arguments",
    }
)
_CONFIRMATION_MODES = frozenset(
    {"none", "user_confirmation", "point_of_risk"}
)
_RESOURCE_PROOF_KINDS = frozenset(
    {
        "none",
        "provider_binding",
        "session_truth",
        "screen_v2",
        "approval_nonce",
        "input_lease",
    }
)
_EFFECT_KINDS = frozenset(
    {
        "return_data",
        "start_inference",
        "steer_turn",
        "interrupt_turn",
        "terminate_session",
        "create_session",
        "mutate_context",
        "update_setting",
        "decide_request",
        "start_workflow",
        "reload_integration",
        "reconnect_integration",
        "enable_integration",
    }
)
_INVALIDATION_KINDS = frozenset(
    {
        "snapshot",
        "input_lease",
        "approval_nonce",
        "active_turn",
        "context_generation",
        "mutation_authority",
        "driver_availability",
    }
)
_FORBIDDEN_KINDS = frozenset(
    {
        "identity_fallback",
        "terminal_injection",
        "raw_transport_escape",
        "start_replacement_session",
        "replay_without_recovery",
        "scope_expansion",
        "credential_exposure",
    }
)


class CapabilityGraphError(ValueError):
    pass


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CapabilityGraphError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_json_bytes(value: Any) -> bytes:
    """Encode the graph's restricted JSON domain deterministically."""
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def operation_binding_digest(binding: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in binding.items() if key != "semantic_digest"}
    return "sha256:" + hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def capability_graph_digest(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def read_capability_graph(path: str | Path) -> dict[str, Any]:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise CapabilityGraphError(f"capability graph is unreadable: {candidate}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CapabilityGraphError(f"capability graph must be a regular file: {candidate}")
    try:
        payload = json.loads(
            candidate.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_object,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CapabilityGraphError(f"cannot parse capability graph: {exc}") from exc
    if not isinstance(payload, dict):
        raise CapabilityGraphError("capability graph must be an object")
    return payload


def default_capability_graph_path() -> Path:
    adjacent = Path(__file__).resolve().with_name("provider-control-capability-map.json")
    source = (
        Path(__file__).resolve().parents[3]
        / "thoughts/shared/specs/coding-agent-remote-control-capability-map.json"
    )
    for candidate in (adjacent, source):
        try:
            metadata = candidate.lstat()
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            return candidate
    raise CapabilityGraphError("no reviewed capability graph is installed")


def _exact_fields(value: Any, expected: frozenset[str], label: str, errors: list[str]) -> bool:
    if not isinstance(value, Mapping):
        errors.append(f"{label} must be an object")
        return False
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        if missing:
            errors.append(f"{label} missing fields: {', '.join(missing)}")
        if unknown:
            errors.append(f"{label} has unknown fields: {', '.join(unknown)}")
        return False
    return True
def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _enum_value(
    value: Any,
    allowed: frozenset[Any],
    label: str,
    errors: list[str],
) -> None:
    if value not in allowed:
        errors.append(f"{label} is unknown")


def _string_array(
    value: Any,
    label: str,
    errors: list[str],
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or not all(_nonempty_string(item) for item in value)
    ):
        errors.append(
            f"{label} must be a {'possibly empty' if allow_empty else 'nonempty'} string array"
        )
        return ()
    strings = tuple(map(str, value))
    if len(set(strings)) != len(strings):
        errors.append(f"{label} contains duplicate values")
    return strings


def _direct_source_uri(value: Any, kind: Any) -> bool:
    if not _nonempty_string(value):
        return False
    text = str(value)
    parsed = urlsplit(text)
    if parsed.scheme == "https":
        return bool(parsed.netloc) and parsed.username is None and parsed.password is None
    if kind != "checked_in_source" or parsed.scheme or text.startswith(("/", "~")):
        return False
    return all(part not in {"", ".", ".."} for part in text.split("/"))


def _indexed_rows(
    payload: Mapping[str, Any],
    field: str,
    id_field: str,
    expected_fields: frozenset[str],
    errors: list[str],
) -> dict[str, Mapping[str, Any]]:
    rows = payload.get(field)
    if not isinstance(rows, list) or not rows:
        errors.append(f"capability graph {field} must be a nonempty array")
        return {}
    indexed: dict[str, Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        label = f"{field}[{index}]"
        if not _exact_fields(row, expected_fields, label, errors):
            continue
        row_id = row.get(id_field)
        if not isinstance(row_id, str) or _ID_RE.fullmatch(row_id) is None:
            errors.append(f"{label}.{id_field} is invalid")
            continue
        if row_id in indexed:
            errors.append(f"duplicate {id_field}: {row_id}")
            continue
        indexed[row_id] = row
    return indexed


def _string_refs(
    value: Any,
    known: Mapping[str, Any] | set[str],
    label: str,
    errors: list[str],
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        errors.append(f"{label} must be {'an' if allow_empty else 'a nonempty'} reference array")
        return ()
    refs: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            errors.append(f"{label} contains an invalid reference")
            continue
        if item in refs:
            errors.append(f"{label} contains duplicate reference {item}")
        refs.append(item)
        if item not in known:
            errors.append(f"{label} references unknown id {item}")
    return tuple(refs)


def _manifest_indexes(
    operation_manifest: Any,
    errors: list[str],
) -> tuple[dict[str, Mapping[str, Any]], dict[str, Mapping[str, Any]], dict[str, set[str]]]:
    if not isinstance(operation_manifest, Mapping):
        errors.append("reviewed operation manifest must be an object")
        return {}, {}, {}
    operations: dict[str, Mapping[str, Any]] = {}
    rows = operation_manifest.get("operations")
    if not isinstance(rows, list):
        errors.append("reviewed operation manifest operations must be an array")
        rows = []
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("id"), str):
            continue
        operations[str(row["id"])] = row
    memberships: dict[str, Mapping[str, Any]] = {}
    released: dict[str, set[str]] = {}
    rows = operation_manifest.get("release_memberships")
    if not isinstance(rows, list):
        errors.append("reviewed operation manifest release_memberships must be an array")
        rows = []
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("map_provider_id"), str):
            continue
        provider_id = str(row["map_provider_id"])
        memberships[provider_id] = row
        operation_ids: set[str] = set()
        for capability in row.get("capabilities", []):
            if isinstance(capability, Mapping) and isinstance(capability.get("operation_ids"), list):
                operation_ids.update(str(item) for item in capability["operation_ids"])
        released[provider_id] = operation_ids
    return operations, memberships, released


def validate_capability_graph(
    payload: Any,
    *,
    operation_manifest: Any | None = None,
) -> list[str]:
    """Return structural, referential, authority, and release-join errors."""
    errors: list[str] = []
    if not isinstance(payload, Mapping):
        return ["capability graph must be an object"]
    _exact_fields(payload, _TOP_LEVEL_FIELDS, "capability graph", errors)
    if payload.get("$schema") != CAPABILITY_GRAPH_SCHEMA_REF:
        errors.append("capability graph $schema is unknown")
    if payload.get("schema_version") != CAPABILITY_GRAPH_SCHEMA_VERSION:
        errors.append("capability graph schema_version is unknown")
    observed_at = payload.get("observed_at")
    if not isinstance(observed_at, str) or not observed_at.endswith("Z"):
        errors.append("capability graph observed_at must be an RFC 3339 UTC timestamp")
    else:
        try:
            datetime.fromisoformat(observed_at[:-1] + "+00:00")
        except ValueError:
            errors.append("capability graph observed_at must be an RFC 3339 UTC timestamp")
    evidence_policy = payload.get("evidence_policy")
    if _exact_fields(
        evidence_policy,
        _EVIDENCE_POLICY_FIELDS,
        "capability graph evidence_policy",
        errors,
    ):
        if not _nonempty_string(evidence_policy.get("rule")):
            errors.append("capability graph evidence_policy.rule must be explicit")
        if evidence_policy.get("direct_sources_required") is not True:
            errors.append(
                "capability graph evidence_policy.direct_sources_required must be true"
            )
        machine_values = evidence_policy.get("machine_readable_values")
        if not (
            isinstance(machine_values, list)
            and len(machine_values) == 3
            and sum(item is True for item in machine_values) == 1
            and sum(item is False for item in machine_values) == 1
            and machine_values.count("qualified") == 1
        ):
            errors.append(
                "capability graph evidence_policy.machine_readable_values is invalid"
            )
        support_values = evidence_policy.get("support_values")
        if not (
            isinstance(support_values, list)
            and support_values
            == ["supported", "partial", "missing", "not_applicable"]
        ):
            errors.append("capability graph evidence_policy.support_values is invalid")
        if not _nonempty_string(
            evidence_policy.get("machine_readable_qualification")
        ):
            errors.append(
                "capability graph evidence_policy.machine_readable_qualification "
                "must be explicit"
            )
        if not _nonempty_string(evidence_policy.get("safety_rule")):
            errors.append(
                "capability graph evidence_policy.safety_rule must be explicit"
            )
        if evidence_policy.get("missing_evidence_is_unsupported") is not True:
            errors.append(
                "capability graph evidence_policy.missing_evidence_is_unsupported "
                "must be true"
            )


    sources = _indexed_rows(
        payload,
        "evidence_sources",
        "source_id",
        frozenset({"source_id", "uri", "kind"}),
        errors,
    )
    providers = _indexed_rows(payload, "providers", "provider_id", _PROVIDER_FIELDS, errors)
    implementations = _indexed_rows(
        payload,
        "implementations",
        "implementation_id",
        _IMPLEMENTATION_FIELDS,
        errors,
    )
    transports = _indexed_rows(payload, "transports", "transport_id", _TRANSPORT_FIELDS, errors)
    capabilities = _indexed_rows(payload, "capabilities", "capability_id", _CAPABILITY_FIELDS, errors)
    bindings = _indexed_rows(
        payload,
        "operation_bindings",
        "implementation_operation_id",
        _BINDING_FIELDS,
        errors,
    )
    claims = _indexed_rows(payload, "evidence_claims", "claim_id", _CLAIM_FIELDS, errors)

    for source_id, source in sources.items():
        if source.get("kind") not in _SOURCE_KINDS:
            errors.append(f"evidence source {source_id} kind is unknown")
        if not _direct_source_uri(source.get("uri"), source.get("kind")):
            errors.append(
                f"evidence source {source_id} uri must be a direct HTTPS URL "
                "or checked-in repository path"
            )

    for provider_id, provider in providers.items():
        if not _nonempty_string(provider.get("display_name")):
            errors.append(f"provider {provider_id} display_name must be explicit")
        eligibility = provider.get("implementation_eligibility")
        if _exact_fields(
            eligibility,
            frozenset({"status", "reason"}),
            f"provider {provider_id} implementation_eligibility",
            errors,
        ):
            if eligibility.get("status") not in _IMPLEMENTATION_ELIGIBILITY:
                errors.append(
                    f"provider {provider_id} implementation eligibility status is unknown"
                )
            if not _nonempty_string(eligibility.get("reason")):
                errors.append(
                    f"provider {provider_id} implementation eligibility reason "
                    "must be explicit"
                )
        _string_refs(
            provider.get("source_refs"),
            sources,
            f"provider {provider_id} source_refs",
            errors,
        )

    exact_runtime_implementations: dict[tuple[str, str, str], str] = {}
    implementation_provider: dict[str, str] = {}
    for implementation_id, implementation in implementations.items():
        provider_id = implementation.get("provider_id")
        if provider_id not in providers:
            errors.append(
                f"implementation {implementation_id} references unknown provider "
                f"{provider_id}"
            )
            continue
        implementation_provider[implementation_id] = str(provider_id)
        _enum_value(
            implementation.get("identity_status"),
            _IDENTITY_STATUSES,
            f"implementation {implementation_id} identity_status",
            errors,
        )
        for field in ("provider_version", "provider_channel"):
            if not _nonempty_string(implementation.get(field)):
                errors.append(
                    f"implementation {implementation_id} {field} must be explicit"
                )
        _string_array(
            implementation.get("observed_versions"),
            f"implementation {implementation_id} observed_versions",
            errors,
        )
        _string_array(
            implementation.get("observed_channels"),
            f"implementation {implementation_id} observed_channels",
            errors,
        )
        _string_refs(
            implementation.get("transport_ids"),
            transports,
            f"implementation {implementation_id} transport_ids",
            errors,
        )
        release = implementation.get("release_membership")
        if release is None:
            if implementation.get("identity_status") == "release_pinned":
                errors.append(
                    f"unreleased implementation {implementation_id} is release_pinned"
                )
            continue
        if not _exact_fields(
            release,
            _RELEASE_FIELDS,
            f"implementation {implementation_id} release_membership",
            errors,
        ):
            continue
        for field in (
            "runtime_provider_id",
            "provider_version",
            "provider_channel",
        ):
            if not _nonempty_string(release.get(field)):
                errors.append(
                    f"implementation {implementation_id} release {field} "
                    "must be explicit"
                )
        if (
            not isinstance(release.get("launch_config_digest"), str)
            or _DIGEST_RE.fullmatch(str(release.get("launch_config_digest"))) is None
        ):
            errors.append(
                f"implementation {implementation_id} release launch_config_digest "
                "is invalid"
            )
        if not isinstance(release.get("physical_device_required"), bool):
            errors.append(
                f"implementation {implementation_id} release "
                "physical_device_required must be boolean"
            )
        identity = (
            str(release.get("runtime_provider_id")),
            str(release.get("provider_version")),
            str(release.get("provider_channel")),
        )
        prior = exact_runtime_implementations.setdefault(identity, implementation_id)
        if prior != implementation_id:
            errors.append(f"runtime implementation identity is ambiguous: {identity}")
        if implementation.get("identity_status") != "release_pinned":
            errors.append(
                f"released implementation {implementation_id} is not release_pinned"
            )
        if implementation.get("provider_version") != release.get("provider_version"):
            errors.append(
                f"implementation {implementation_id} version differs from "
                "release membership"
            )
        if implementation.get("provider_channel") != release.get("provider_channel"):
            errors.append(
                f"implementation {implementation_id} channel differs from "
                "release membership"
            )

    for transport_id, transport in transports.items():
        if transport.get("provider_id") not in providers:
            errors.append(f"transport {transport_id} references an unknown provider")
        if not _nonempty_string(transport.get("description")):
            errors.append(f"transport {transport_id} description must be explicit")
        _enum_value(
            transport.get("kind"),
            _TRANSPORT_KINDS,
            f"transport {transport_id} kind",
            errors,
        )

    for capability_id, capability in capabilities.items():
        provider_id = capability.get("provider_id")
        if provider_id not in providers:
            errors.append(f"capability {capability_id} references an unknown provider")
        implementation_ids = _string_refs(
            capability.get("implementation_ids"),
            implementations,
            f"capability {capability_id} implementation_ids",
            errors,
        )
        if any(
            implementation_provider.get(item) != provider_id
            for item in implementation_ids
        ):
            errors.append(
                f"capability {capability_id} crosses provider implementations"
            )
        for field in ("behavior", "version_constraints"):
            if not _nonempty_string(capability.get(field)):
                errors.append(f"capability {capability_id} {field} must be explicit")
        _string_array(
            capability.get("exact_exposure"),
            f"capability {capability_id} exact_exposure",
            errors,
            allow_empty=True,
        )
        for field, allowed in (
            ("plane", _PLANES),
            ("lifecycle", _LIFECYCLES),
            ("maturity", _MATURITIES),
            ("remote_safety", _REMOTE_SAFETY),
        ):
            _enum_value(
                capability.get(field),
                allowed,
                f"capability {capability_id} {field}",
                errors,
            )
        machine_readable = capability.get("machine_readable")
        if not (
            isinstance(machine_readable, bool)
            or machine_readable == "qualified"
        ):
            errors.append(
                f"capability {capability_id} machine_readable is unknown"
            )
        if not isinstance(capability.get("required_pairling_addition"), str):
            errors.append(
                f"capability {capability_id} required_pairling_addition "
                "must be a string"
            )
        shared_semantics = capability.get("shared_semantics")
        if shared_semantics is not None and not _nonempty_string(shared_semantics):
            errors.append(
                f"capability {capability_id} shared_semantics must be null "
                "or explicit"
            )
        if not isinstance(capability.get("provider_overlay"), bool):
            errors.append(
                f"capability {capability_id} provider_overlay must be boolean"
            )
        if (
            capability.get("remote_safety")
            in {"required_local_only", "do_not_expose"}
            and not _nonempty_string(capability.get("required_pairling_addition"))
        ):
            errors.append(
                f"capability {capability_id} required_pairling_addition "
                "must explain exclusion"
            )
        _string_refs(
            capability.get("source_refs"),
            sources,
            f"capability {capability_id} source_refs",
            errors,
        )

    subject_indexes = {
        "implementation": implementations,
        "capability": capabilities,
        "operation_binding": bindings,
    }
    for claim_id, claim in claims.items():
        subject_type = claim.get("subject_type")
        subject_index = subject_indexes.get(str(subject_type))
        if subject_index is None or claim.get("subject_id") not in subject_index:
            errors.append(f"evidence claim {claim_id} references an unknown subject")
        _enum_value(
            claim.get("classification"),
            _CLAIM_CLASSIFICATIONS,
            f"evidence claim {claim_id} classification",
            errors,
        )
        if not _nonempty_string(claim.get("assertion")):
            errors.append(f"evidence claim {claim_id} assertion must be explicit")
        _string_refs(
            claim.get("source_refs"),
            sources,
            f"evidence claim {claim_id} source_refs",
            errors,
        )

    exclusions = payload.get("exclusions")
    if not isinstance(exclusions, list) or not exclusions:
        errors.append("capability graph exclusions must be a nonempty array")
    else:
        exclusion_items: set[str] = set()
        for index, exclusion in enumerate(exclusions):
            label = f"exclusions[{index}]"
            if not isinstance(exclusion, Mapping):
                errors.append(f"{label} must be an object")
                continue
            actual = set(exclusion)
            required = {"item", "reason"}
            allowed = required | {"source_refs"}
            if not required.issubset(actual):
                errors.append(
                    f"{label} missing fields: "
                    + ", ".join(sorted(required - actual))
                )
            if actual - allowed:
                errors.append(
                    f"{label} has unknown fields: "
                    + ", ".join(sorted(actual - allowed))
                )
            item = exclusion.get("item")
            if not _nonempty_string(item):
                errors.append(f"{label}.item must be explicit")
            elif str(item) in exclusion_items:
                errors.append(f"duplicate exclusion item: {item}")
            else:
                exclusion_items.add(str(item))
            if not _nonempty_string(exclusion.get("reason")):
                errors.append(f"{label}.reason must be explicit")
            if "source_refs" in exclusion:
                _string_refs(
                    exclusion.get("source_refs"),
                    sources,
                    f"{label}.source_refs",
                    errors,
                )

    manifest_operations: dict[str, Mapping[str, Any]] = {}
    manifest_memberships: dict[str, Mapping[str, Any]] = {}
    manifest_released: dict[str, set[str]] = {}
    if operation_manifest is not None:
        manifest_operations, manifest_memberships, manifest_released = _manifest_indexes(
            operation_manifest,
            errors,
        )
    graph_operations: set[str] = set()
    graph_released: dict[str, set[str]] = {}
    for binding_id, binding in bindings.items():
        implementation_id = binding.get("implementation_id")
        if implementation_id not in implementations:
            errors.append(f"operation binding {binding_id} references an unknown implementation")
            continue
        provider_id = implementation_provider.get(str(implementation_id), "")
        operation_id = binding.get("operation_id")
        if not isinstance(operation_id, str) or _OPERATION_RE.fullmatch(operation_id) is None:
            errors.append(f"operation binding {binding_id} has an invalid operation id")
            continue
        graph_operations.add(operation_id)
        capability_refs = _string_refs(
            binding.get("capability_ids"),
            capabilities,
            f"operation binding {binding_id} capability_ids",
            errors,
        )
        if any(
            str(implementation_id)
            not in capabilities[capability_id].get("implementation_ids", [])
            for capability_id in capability_refs
            if capability_id in capabilities
        ):
            errors.append(
                f"operation binding {binding_id} crosses capability implementations"
            )
        evidence_refs = _string_refs(
            binding.get("evidence_claim_ids"),
            claims,
            f"operation binding {binding_id} evidence_claim_ids",
            errors,
        )
        if any(
            claims[claim_id].get("subject_id")
            not in {*capability_refs, binding_id}
            for claim_id in evidence_refs
            if claim_id in claims
        ):
            errors.append(
                f"operation binding {binding_id} cites unrelated evidence"
            )
        _string_refs(
            binding.get("source_refs"),
            sources,
            f"operation binding {binding_id} source_refs",
            errors,
        )
        _enum_value(
            binding.get("implementation_status"),
            _IMPLEMENTATION_STATUSES,
            f"operation binding {binding_id} implementation_status",
            errors,
        )
        _enum_value(
            binding.get("release_status"),
            _RELEASE_STATUSES,
            f"operation binding {binding_id} release_status",
            errors,
        )
        digest = binding.get("semantic_digest")
        if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
            errors.append(f"operation binding {binding_id} semantic digest is invalid")
        else:
            try:
                expected_digest = operation_binding_digest(binding)
            except (TypeError, ValueError):
                errors.append(
                    f"operation binding {binding_id} is not canonical JSON"
                )
            else:
                if digest != expected_digest:
                    errors.append(
                        f"operation binding {binding_id} semantic digest is stale"
                    )

        requirement_rows = binding.get("requires")
        requirement_kinds: set[str] = set()
        if not isinstance(requirement_rows, list) or not requirement_rows:
            errors.append(
                f"operation binding {binding_id} requires must be nonempty"
            )
            requirement_rows = []
        for index, requirement in enumerate(requirement_rows):
            label = f"operation binding {binding_id} requires[{index}]"
            if not isinstance(requirement, Mapping):
                errors.append(f"{label} must be an object")
                continue
            kind = str(requirement.get("kind"))
            expected_fields = _REQUIREMENT_FIELDS.get(kind)
            if expected_fields is None:
                errors.append(f"{label} kind is unknown")
                continue
            _exact_fields(requirement, expected_fields, label, errors)
            if kind in requirement_kinds:
                errors.append(
                    f"operation binding {binding_id} repeats requirement {kind}"
                )
            requirement_kinds.add(kind)
            if kind == "fresh_snapshot":
                maximum_age = requirement.get("max_age_seconds")
                if (
                    isinstance(maximum_age, bool)
                    or not isinstance(maximum_age, int)
                    or maximum_age < 1
                    or maximum_age > 30
                ):
                    errors.append(f"{label}.max_age_seconds must be from 1 to 30")
            elif kind == "exact_identity":
                dimensions = _string_array(
                    requirement.get("dimensions"),
                    f"{label}.dimensions",
                    errors,
                )
                if any(item not in _IDENTITY_DIMENSIONS for item in dimensions):
                    errors.append(f"{label}.dimensions contains an unknown identity")
                if not {"provider", "implementation", "binding"}.issubset(
                    dimensions
                ):
                    errors.append(
                        f"{label}.dimensions lacks exact implementation identity"
                    )
                if ("session" in dimensions) != ("generation" in dimensions):
                    errors.append(
                        f"{label}.dimensions must bind session and generation together"
                    )
            elif kind == "device_scope":
                scope = requirement.get("scope")
                if (
                    not isinstance(scope, str)
                    or re.fullmatch(r"[a-z]+:[a-z]+", scope) is None
                ):
                    errors.append(f"{label}.scope is invalid")
            elif kind == "resource_proof":
                _enum_value(
                    requirement.get("proof_kind"),
                    _RESOURCE_PROOF_KINDS,
                    f"{label}.proof_kind",
                    errors,
                )
            elif kind == "confirmation":
                _enum_value(
                    requirement.get("mode"),
                    _CONFIRMATION_MODES,
                    f"{label}.mode",
                    errors,
                )
            elif kind == "owned_process" and requirement.get("owner") not in {
                "driver",
                "manager",
            }:
                errors.append(f"{label}.owner is unknown")
        missing_requirements = sorted(
            _REQUIRED_BINDING_REQUIREMENTS - requirement_kinds
        )
        if missing_requirements:
            errors.append(
                f"operation binding {binding_id} lacks authority requirements: "
                + ", ".join(missing_requirements)
            )

        effect_rows = binding.get("effects")
        if not isinstance(effect_rows, list) or not effect_rows:
            errors.append(f"operation binding {binding_id} has no effects")
            effect_rows = []
        for index, effect in enumerate(effect_rows):
            label = f"operation binding {binding_id} effects[{index}]"
            if not isinstance(effect, Mapping):
                errors.append(f"{label} must be an object")
                continue
            if not set(effect).issubset({"kind", "target"}) or "kind" not in effect:
                errors.append(f"{label} has invalid fields")
            _enum_value(effect.get("kind"), _EFFECT_KINDS, f"{label}.kind", errors)
            if "target" in effect and not _nonempty_string(effect.get("target")):
                errors.append(f"{label}.target must be explicit")
        read_only = (
            len(effect_rows) == 1
            and isinstance(effect_rows[0], Mapping)
            and effect_rows[0].get("kind") == _READ_EFFECT
        )

        invalidations = binding.get("invalidates")
        if not isinstance(invalidations, list):
            errors.append(
                f"operation binding {binding_id} invalidates must be an array"
            )
            invalidations = []
        for index, invalidation in enumerate(invalidations):
            label = f"operation binding {binding_id} invalidates[{index}]"
            if not _exact_fields(
                invalidation,
                frozenset({"kind"}),
                label,
                errors,
            ):
                continue
            _enum_value(
                invalidation.get("kind"),
                _INVALIDATION_KINDS,
                f"{label}.kind",
                errors,
            )

        forbidden_rows = binding.get("forbids")
        if not isinstance(forbidden_rows, list) or not forbidden_rows:
            errors.append(
                f"operation binding {binding_id} forbids must be nonempty"
            )
            forbidden_rows = []
        forbidden_kinds: set[str] = set()
        for index, forbidden in enumerate(forbidden_rows):
            label = f"operation binding {binding_id} forbids[{index}]"
            if not _exact_fields(
                forbidden,
                frozenset({"kind"}),
                label,
                errors,
            ):
                continue
            kind = forbidden.get("kind")
            _enum_value(kind, _FORBIDDEN_KINDS, f"{label}.kind", errors)
            if isinstance(kind, str):
                if kind in forbidden_kinds:
                    errors.append(
                        f"operation binding {binding_id} repeats forbidden action {kind}"
                    )
                forbidden_kinds.add(kind)

        retry = binding.get("retry")
        if not _exact_fields(
            retry,
            _RETRY_FIELDS,
            f"operation binding {binding_id} retry",
            errors,
        ):
            retry = {}
        _enum_value(
            retry.get("replay"),
            _REPLAY_VALUES,
            f"operation binding {binding_id} retry.replay",
            errors,
        )
        _enum_value(
            retry.get("recovery"),
            _RECOVERY_VALUES,
            f"operation binding {binding_id} retry.recovery",
            errors,
        )
        _enum_value(
            retry.get("ambiguity"),
            _AMBIGUITY_VALUES,
            f"operation binding {binding_id} retry.ambiguity",
            errors,
        )
        _enum_value(
            retry.get("correlation"),
            _CORRELATION_VALUES,
            f"operation binding {binding_id} retry.correlation",
            errors,
        )
        if not read_only and retry.get("replay") == "safe":
            errors.append(f"mutating operation binding {binding_id} is replay-safe")
        if (
            retry.get("replay") == "recover_only"
            and retry.get("recovery") == "unavailable"
        ):
            errors.append(
                f"operation binding {binding_id} requires unavailable recovery"
            )
        if (
            retry.get("ambiguity") == "outcome_unknown"
            and retry.get("correlation") == "none"
        ):
            errors.append(
                f"operation binding {binding_id} has uncorrelated ambiguity"
            )

        runtime_proofs = _string_array(
            binding.get("runtime_proofs_required"),
            f"operation binding {binding_id} runtime_proofs_required",
            errors,
        )
        if any(proof not in _RUNTIME_PROOFS for proof in runtime_proofs):
            errors.append(
                f"operation binding {binding_id} has an unknown runtime proof"
            )
        addition = binding.get("required_pairling_addition")
        if not isinstance(addition, str):
            errors.append(
                f"operation binding {binding_id} required_pairling_addition "
                "must be a string"
            )
        if (
            binding.get("release_status") == "not_released"
            and not _nonempty_string(addition)
        ):
            errors.append(
                f"operation binding {binding_id} exclusion lacks an explicit reason"
            )

        if binding.get("release_status") == "released":
            graph_released.setdefault(provider_id, set()).add(operation_id)
            if binding.get("implementation_status") != "implemented":
                errors.append(
                    f"released operation binding {binding_id} is not implemented"
                )
            implementation = implementations[str(implementation_id)]
            if implementation.get("release_membership") is None:
                errors.append(
                    f"released operation binding {binding_id} lacks "
                    "implementation membership"
                )
            provider = providers.get(provider_id)
            eligibility = (
                provider.get("implementation_eligibility")
                if isinstance(provider, Mapping)
                else None
            )
            if (
                not isinstance(eligibility, Mapping)
                or eligibility.get("status") != "implementation_candidate"
            ):
                errors.append(
                    f"released operation binding {binding_id} provider is not releasable"
                )
        if manifest_operations:
            definition = manifest_operations.get(operation_id)
            if definition is None:
                errors.append(f"operation binding {binding_id} references an unreviewed operation")
                continue
            requirement_by_kind = {
                str(row.get("kind")): row
                for row in requirement_rows
                if isinstance(row, Mapping)
            }
            expected_pairs = {
                "device_scope": ("scope", definition.get("required_device_scope")),
                "resource_proof": ("proof_kind", definition.get("resource_proof_kind")),
                "confirmation": ("mode", definition.get("confirmation_requirement")),
            }
            for kind, (field, expected) in expected_pairs.items():
                row = requirement_by_kind.get(kind)
                if not isinstance(row, Mapping) or row.get(field) != expected:
                    errors.append(
                        f"operation binding {binding_id} {kind} differs from reviewed catalog"
                    )

    if manifest_operations:
        missing = sorted(set(manifest_operations) - graph_operations)
        if missing:
            errors.append("reviewed operations missing graph bindings: " + ", ".join(missing))
        extra_memberships = sorted(set(manifest_memberships) - set(providers))
        if extra_memberships:
            errors.append("release memberships reference unknown graph providers: " + ", ".join(extra_memberships))
        for provider_id in sorted(set(manifest_released) | set(graph_released)):
            expected = manifest_released.get(provider_id, set())
            actual = graph_released.get(provider_id, set())
            if actual != expected:
                errors.append(
                    f"released operation bindings differ for {provider_id}: "
                    f"expected {sorted(expected)}, got {sorted(actual)}"
                )
            membership = manifest_memberships.get(provider_id)
            implementation = next(
                (
                    row
                    for row in implementations.values()
                    if row.get("provider_id") == provider_id
                    and row.get("release_membership") is not None
                ),
                None,
            )
            if membership is None or implementation is None:
                continue
            release = implementation["release_membership"]
            for field in ("runtime_provider_id", "provider_version", "provider_channel", "launch_config_digest", "physical_device_required"):
                if release.get(field) != membership.get(field):
                    errors.append(f"graph release identity differs for {provider_id}.{field}")
    return errors


@dataclass(frozen=True)
class GraphOperationContract:
    implementation_operation_id: str
    operation_id: str
    semantic_digest: str
    runtime_proofs_required: tuple[str, ...]
    implementation_id: str
    runtime_provider_id: str
    provider_version: str
    provider_channel: str
    launch_config_digest: str
    physical_device_required: bool
    retry_replay: str
    retry_recovery: str
    retry_ambiguity: str
    retry_correlation: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "implementation_operation_id": self.implementation_operation_id,
            "semantic_digest": self.semantic_digest,
            "proofs": list(self.runtime_proofs_required),
        }

    def protocol_binding_payload(self, graph_digest: str) -> dict[str, Any]:
        return {
            "graph_digest": graph_digest,
            "provider_id": self.runtime_provider_id,
            "implementation_id": self.implementation_id,
            "provider_version": self.provider_version,
            "provider_channel": self.provider_channel,
            "launch_config_digest": self.launch_config_digest,
        }

    def retry_payload(self) -> dict[str, str]:
        return {
            "replay": self.retry_replay,
            "recovery": self.retry_recovery,
            "ambiguity": self.retry_ambiguity,
            "correlation": self.retry_correlation,
        }


class CapabilityGraphCatalog:
    """Immutable lookup over exact released implementation-operation contracts."""

    def __init__(self, payload: Mapping[str, Any], *, operation_manifest: Any | None = None):
        errors = validate_capability_graph(payload, operation_manifest=operation_manifest)
        if errors:
            raise CapabilityGraphError("; ".join(errors))
        implementations = {
            str(row["implementation_id"]): row
            for row in payload["implementations"]
        }
        by_runtime: dict[tuple[str, str, str, str], GraphOperationContract] = {}
        for binding in payload["operation_bindings"]:
            if (
                binding["implementation_status"] != "implemented"
                or binding["release_status"] != "released"
            ):
                continue
            implementation = implementations[str(binding["implementation_id"])]
            release = implementation.get("release_membership")
            if not isinstance(release, Mapping):
                continue
            key = (
                str(release["runtime_provider_id"]),
                str(release["provider_version"]),
                str(release["provider_channel"]),
                str(binding["operation_id"]),
            )
            contract = GraphOperationContract(
                implementation_operation_id=str(binding["implementation_operation_id"]),
                operation_id=str(binding["operation_id"]),
                semantic_digest=str(binding["semantic_digest"]),
                runtime_proofs_required=tuple(map(str, binding["runtime_proofs_required"])),
                implementation_id=str(binding["implementation_id"]),
                runtime_provider_id=str(release["runtime_provider_id"]),
                provider_version=str(release["provider_version"]),
                provider_channel=str(release["provider_channel"]),
                launch_config_digest=str(release["launch_config_digest"]),
                physical_device_required=bool(
                    release["physical_device_required"]
                ),
                retry_replay=str(binding["retry"]["replay"]),
                retry_recovery=str(binding["retry"]["recovery"]),
                retry_ambiguity=str(binding["retry"]["ambiguity"]),
                retry_correlation=str(binding["retry"]["correlation"]),
            )
            if key in by_runtime:
                raise CapabilityGraphError(f"duplicate runtime operation contract: {key}")
            by_runtime[key] = contract
        self._payload = json.loads(json.dumps(payload))
        self._by_runtime = MappingProxyType(by_runtime)
        self.graph_digest = capability_graph_digest(payload)

    @classmethod
    def from_path(
        cls,
        path: str | Path | None = None,
        *,
        operation_manifest: Any | None = None,
    ) -> "CapabilityGraphCatalog":
        return cls(
            read_capability_graph(path or default_capability_graph_path()),
            operation_manifest=operation_manifest,
        )

    def require_operation(
        self,
        provider_id: str,
        provider_version: str,
        provider_channel: str,
        operation_id: str,
    ) -> GraphOperationContract:
        key = (provider_id, provider_version, provider_channel, operation_id)
        contract = self._by_runtime.get(key)
        if contract is not None:
            return contract
        if (
            provider_id == "omp"
            and provider_channel == "stable"
            and _STABLE_SEMVER_RE.fullmatch(provider_version) is not None
        ):
            policy_key = (provider_id, "semver:*", provider_channel, operation_id)
            policy_contract = self._by_runtime.get(policy_key)
            if policy_contract is not None:
                return replace(policy_contract, provider_version=provider_version)
        raise CapabilityGraphError(
            "no exact released semantic contract for "
            f"{provider_id} {provider_version} {provider_channel} {operation_id}"
        )

    def attest_operations(
        self,
        provider_id: str,
        provider_version: str,
        provider_channel: str,
        operation_ids: Iterable[str],
    ) -> tuple[GraphOperationContract, ...]:
        return tuple(
            self.require_operation(
                provider_id,
                provider_version,
                provider_channel,
                operation_id,
            )
            for operation_id in operation_ids
        )
