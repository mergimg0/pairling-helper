"""Fail-closed runtime contracts for provider control drivers."""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from .operations import (
    InputType,
    OperationCatalog,
    OperationCatalogError,
    REVIEWED_OPERATION_CATALOG,
    provider_binding_has_release_membership,
    released_operation_ids_for_provider,
)


class ControlContractError(ValueError):
    pass


class OperationResultStatus(str, Enum):
    APPLIED = "applied"
    REJECTED = "rejected"
    IN_PROGRESS = "in_progress"
    OUTCOME_UNKNOWN = "outcome_unknown"


_PROVIDER_ID_RE = re.compile(r"[a-z0-9_]{1,48}\Z")
_SNAPSHOT_FIELDS = {
    "schema_version",
    "provider_id",
    "provider_version",
    "provider_channel",
    "binding_id",
    "capability_generation",
    "observed_at",
    "valid_until",
    "advertised_operations",
    "values",
    "choices",
    "blocked_reason",
    "provider_cursor",
}
_SESSION_FIELDS = {"provider_id", "session_id", "binding_id", "capability_generation"}
_RESULT_FIELDS = {
    "schema_version",
    "operation_id",
    "provider_operation_id",
    "status",
    "public_result",
    "provider_cursor",
}
_CHOICE_FIELDS = {"value", "label"}
_CORRELATION_FIELDS = {"provider_operation_id", "provider_cursor"}
_MAX_SNAPSHOT_TTL_SECONDS = 30.0
_MAX_FUTURE_CLOCK_SKEW_SECONDS = 5.0
_MAX_CHOICES_PER_INPUT = 512
_MAX_PUBLIC_RESULT_BYTES = 512 * 1024
_MAX_PUBLIC_STRING_LENGTH = 64 * 1024

class _FrozenJSONDict(dict):
    def _immutable(self, *args, **kwargs):
        raise TypeError("provider operation public_result is immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable
    __ior__ = _immutable

    def __deepcopy__(self, memo):
        return self


class _FrozenJSONList(list):
    def _immutable(self, *args, **kwargs):
        raise TypeError("provider operation public_result is immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    append = _immutable
    clear = _immutable
    extend = _immutable
    insert = _immutable
    pop = _immutable
    remove = _immutable
    reverse = _immutable
    sort = _immutable
    __iadd__ = _immutable
    __imul__ = _immutable

    def __deepcopy__(self, memo):
        return self


def _freeze_public_json(value, *, depth: int = 0):
    if depth > 8:
        return value
    if isinstance(value, dict):
        frozen = _FrozenJSONDict()
        for key, item in value.items():
            dict.__setitem__(
                frozen,
                key,
                _freeze_public_json(item, depth=depth + 1),
            )
        return frozen
    if isinstance(value, list):
        frozen = _FrozenJSONList()
        list.extend(
            frozen,
            (
                _freeze_public_json(item, depth=depth + 1)
                for item in value
            ),
        )
        return frozen
    return value


def _copy_public_json(value):
    if isinstance(value, dict):
        return {key: _copy_public_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_copy_public_json(item) for item in value]
    return value


@dataclass(frozen=True)
class ProviderControlBinding:
    provider_id: str
    provider_version: str
    provider_channel: str
    binding_id: str

    def __post_init__(self) -> None:
        _validate_provider_id(self.provider_id)
        _validate_opaque("provider_version", self.provider_version, 160)
        _validate_opaque("provider_channel", self.provider_channel, 80)
        _validate_opaque("binding_id", self.binding_id, 256)


@dataclass(frozen=True)
class ProviderSessionIdentity:
    provider_id: str
    session_id: str
    binding_id: str
    capability_generation: int

    def __post_init__(self) -> None:
        _validate_provider_id(self.provider_id)
        _validate_opaque("session_id", self.session_id, 512)
        _validate_opaque("binding_id", self.binding_id, 256)
        _validate_generation(self.capability_generation)

    def to_payload(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "session_id": self.session_id,
            "binding_id": self.binding_id,
            "capability_generation": self.capability_generation,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ProviderSessionIdentity":
        _require_exact_object(payload, _SESSION_FIELDS, "provider session identity")
        return cls(
            provider_id=payload["provider_id"],
            session_id=payload["session_id"],
            binding_id=payload["binding_id"],
            capability_generation=payload["capability_generation"],
        )


@dataclass(frozen=True)
class ControlValue:
    operation_id: str
    input_id: str
    value: Any


@dataclass(frozen=True)
class ControlChoice:
    value: Any
    label: str

    def __post_init__(self) -> None:
        _validate_opaque("choice label", self.label, 160)

    def to_payload(self) -> dict[str, Any]:
        return {"value": _wire_value(self.value), "label": self.label}


@dataclass(frozen=True)
class ControlChoices:
    operation_id: str
    input_id: str
    choices: tuple[ControlChoice, ...]


@dataclass(frozen=True)
class ProviderControlSnapshot:
    provider_id: str
    provider_version: str
    provider_channel: str
    binding_id: str
    capability_generation: int
    observed_at: float
    valid_until: float
    advertised_operations: tuple[str, ...]
    values: tuple[ControlValue, ...]
    choices: tuple[ControlChoices, ...]
    blocked_reason: str | None
    provider_cursor: str

    @property
    def binding(self) -> ProviderControlBinding:
        return ProviderControlBinding(
            self.provider_id,
            self.provider_version,
            self.provider_channel,
            self.binding_id,
        )

    def validate(
        self,
        *,
        now: float | None = None,
        catalog: OperationCatalog = REVIEWED_OPERATION_CATALOG,
    ) -> None:
        _validate_provider_id(self.provider_id)
        _validate_opaque("provider_version", self.provider_version, 160)
        _validate_opaque("provider_channel", self.provider_channel, 80)
        _validate_opaque("binding_id", self.binding_id, 256)
        _validate_generation(self.capability_generation)
        if not _finite_number(self.observed_at) or not _finite_number(self.valid_until):
            raise ControlContractError("snapshot freshness values must be finite numbers")
        if self.valid_until <= self.observed_at:
            raise ControlContractError("snapshot valid_until must be after observed_at")
        if self.valid_until - self.observed_at > _MAX_SNAPSHOT_TTL_SECONDS:
            raise ControlContractError("provider control snapshot TTL exceeds the live bound")
        current = time.time() if now is None else now
        if not _finite_number(current):
            raise ControlContractError("snapshot validation time must be finite")
        if self.observed_at > current + _MAX_FUTURE_CLOCK_SKEW_SECONDS:
            raise ControlContractError("provider control snapshot is from the future")
        if current >= self.valid_until:
            raise ControlContractError("provider control snapshot is stale")
        if not isinstance(self.advertised_operations, tuple):
            raise ControlContractError("advertised_operations must be an immutable tuple")
        if len(set(self.advertised_operations)) != len(self.advertised_operations):
            raise ControlContractError("advertised_operations contains duplicates")
        definitions = {}
        for operation_id in self.advertised_operations:
            try:
                definitions[operation_id] = catalog.require(operation_id)
            except OperationCatalogError as exc:
                raise ControlContractError(str(exc)) from exc

        seen_values: set[tuple[str, str]] = set()
        for item in self.values:
            if not isinstance(item, ControlValue):
                raise ControlContractError("snapshot contains an invalid control value")
            definition = _advertised_definition(definitions, item.operation_id)
            descriptor = _input_descriptor(definition, item.input_id)
            _validate_descriptor_value(definition, descriptor, item.value)
            _validate_session_value(self, descriptor.input_type, item.value)
            key = (item.operation_id, item.input_id)
            if key in seen_values:
                raise ControlContractError(f"duplicate value for {item.operation_id}.{item.input_id}")
            seen_values.add(key)

        seen_choices: set[tuple[str, str]] = set()
        choices_by_input: dict[tuple[str, str], ControlChoices] = {}
        for group in self.choices:
            if not isinstance(group, ControlChoices):
                raise ControlContractError("snapshot contains invalid choices")
            definition = _advertised_definition(definitions, group.operation_id)
            descriptor = _input_descriptor(definition, group.input_id)
            if descriptor.input_type not in {InputType.CHOICE, InputType.PROVIDER_SESSION, InputType.RESOURCE_ID}:
                raise ControlContractError(f"{group.operation_id}.{group.input_id} cannot advertise choices")
            key = (group.operation_id, group.input_id)
            if key in seen_choices:
                raise ControlContractError(f"duplicate choices for {group.operation_id}.{group.input_id}")
            seen_choices.add(key)
            choices_by_input[key] = group
            if (
                not isinstance(group.choices, tuple)
                or not group.choices
                or len(group.choices) > _MAX_CHOICES_PER_INPUT
            ):
                raise ControlContractError(
                    f"{group.operation_id}.{group.input_id} choices must contain 1..{_MAX_CHOICES_PER_INPUT} items"
                )
            seen_choice_values: set[str] = set()
            for choice in group.choices:
                if not isinstance(choice, ControlChoice):
                    raise ControlContractError("snapshot contains an invalid choice")
                _validate_descriptor_value(definition, descriptor, choice.value)
                _validate_session_value(self, descriptor.input_type, choice.value)
                choice_key = _canonical_value(choice.value)
                if choice_key in seen_choice_values:
                    raise ControlContractError(f"duplicate choice for {group.operation_id}.{group.input_id}")
                seen_choice_values.add(choice_key)

        for operation_id, definition in definitions.items():
            for descriptor in definition.inputs:
                if descriptor.required and descriptor.input_type is InputType.CHOICE:
                    if (operation_id, descriptor.input_id) not in choices_by_input:
                        raise ControlContractError(
                            f"{operation_id}.{descriptor.input_id} lacks driver-advertised choices"
                        )
        if self.blocked_reason is not None:
            _validate_opaque("blocked_reason", self.blocked_reason, 512)
        _validate_opaque("provider_cursor", self.provider_cursor, 512)


@dataclass(frozen=True)
class ProviderOperationResult:
    operation_id: str
    provider_operation_id: str
    status: OperationResultStatus
    public_result: dict[str, Any]
    provider_cursor: str

    def __post_init__(self) -> None:
        if isinstance(self.public_result, dict):
            object.__setattr__(
                self,
                "public_result",
                _freeze_public_json(self.public_result),
            )

    def validate(self, catalog: OperationCatalog = REVIEWED_OPERATION_CATALOG) -> None:
        try:
            catalog.require(self.operation_id)
        except OperationCatalogError as exc:
            raise ControlContractError(str(exc)) from exc
        _validate_opaque("provider_operation_id", self.provider_operation_id, 512)
        if not isinstance(self.status, OperationResultStatus):
            raise ControlContractError("provider operation result has an unknown status")
        if not isinstance(self.public_result, dict) or not _json_safe(self.public_result):
            raise ControlContractError("provider operation public_result is not safe JSON")
        encoded = json.dumps(
            self.public_result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        if len(encoded) > _MAX_PUBLIC_RESULT_BYTES:
            raise ControlContractError("provider operation public_result exceeds the wire bound")
        _validate_opaque("provider_cursor", self.provider_cursor, 512)

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": 1,
            "operation_id": self.operation_id,
            "provider_operation_id": self.provider_operation_id,
            "status": self.status.value,
            "public_result": _copy_public_json(self.public_result),
            "provider_cursor": self.provider_cursor,
        }

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
        catalog: OperationCatalog = REVIEWED_OPERATION_CATALOG,
    ) -> "ProviderOperationResult":
        _require_exact_object(payload, _RESULT_FIELDS, "provider operation result")
        if payload["schema_version"] != 1:
            raise ControlContractError("unknown provider operation result schema version")
        try:
            status = OperationResultStatus(payload["status"])
        except (TypeError, ValueError) as exc:
            raise ControlContractError("unknown provider operation result status") from exc
        result = cls(
            operation_id=payload["operation_id"],
            provider_operation_id=payload["provider_operation_id"],
            status=status,
            public_result=payload["public_result"],
            provider_cursor=payload["provider_cursor"],
        )
        result.validate(catalog)
        return result

@dataclass(frozen=True)
class ProviderOperationCorrelation:
    provider_operation_id: str
    provider_cursor: str | None = None

    def __post_init__(self) -> None:
        _validate_opaque("provider_operation_id", self.provider_operation_id, 512)
        if self.provider_cursor is not None:
            _validate_opaque("provider_cursor", self.provider_cursor, 512)

    def to_payload(self) -> dict[str, Any]:
        return {
            "provider_operation_id": self.provider_operation_id,
            "provider_cursor": self.provider_cursor,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ProviderOperationCorrelation":
        _require_exact_object(payload, _CORRELATION_FIELDS, "provider operation correlation")
        return cls(
            provider_operation_id=payload["provider_operation_id"],
            provider_cursor=payload["provider_cursor"],
        )


@runtime_checkable
class ProviderControlDriver(Protocol):
    binding: ProviderControlBinding

    def snapshot(
        self,
        *,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderControlSnapshot:
        ...

    def execute(
        self,
        *,
        operation_id: str,
        input_payload: dict[str, Any],
        binding_id: str,
        capability_generation: int,
        session_id: str | None,
        client_action_id: str,
        prepared_attachments: tuple[Any, ...] = (),
        provider_correlation: ProviderOperationCorrelation | None = None,
    ) -> ProviderOperationResult:
        ...

@runtime_checkable
class ProviderOperationRecoveryDriver(Protocol):
    binding: ProviderControlBinding

    def recover(
        self,
        *,
        operation_id: str,
        binding_id: str,
        capability_generation: int,
        session_id: str | None,
        client_action_id: str,
        provider_correlation: ProviderOperationCorrelation,
        session_truth: dict[str, Any] | None,
    ) -> ProviderOperationResult | None:
        ...


@runtime_checkable
class ProviderControlAdapter(Protocol):
    def create_control_driver(
        self,
        binding: ProviderControlBinding,
    ) -> ProviderControlDriver | None:
        ...

@runtime_checkable
class AttachmentHandleResolver(Protocol):
    def prepare_attachment_handles(
        self,
        records: list[dict[str, Any]],
        *,
        session_id: str,
        source_device_id: str,
        source_install_id: str,
        binding_id: str,
        client_action_id: str,
    ) -> tuple[Any, ...]:
        ...


def control_driver_for_adapter(
    adapter: Any,
    binding: ProviderControlBinding,
) -> ProviderControlDriver | None:
    descriptor = getattr(adapter, "descriptor", None)
    if descriptor is None:
        raise ControlContractError("provider adapter has no descriptor")
    if getattr(descriptor, "provider_id", None) != binding.provider_id:
        raise ControlContractError("provider adapter and binding identities differ")
    if getattr(descriptor, "adapter_depth", None) not in {"deep", "standard"}:
        return None
    if not provider_binding_has_release_membership(
        binding.provider_id,
        binding.provider_version,
        binding.provider_channel,
    ):
        return None
    factory = getattr(adapter, "create_control_driver", None)
    if not callable(factory):
        return None
    driver = factory(binding)
    if driver is None:
        return None
    driver_binding = getattr(driver, "binding", None)
    if not isinstance(driver_binding, ProviderControlBinding) or driver_binding != binding:
        raise ControlContractError("provider control driver returned the wrong binding")
    if not callable(getattr(driver, "snapshot", None)) or not callable(getattr(driver, "execute", None)):
        raise ControlContractError("provider control driver is missing typed control methods")
    return driver


def _filter_snapshot_to_release_membership(
    snapshot: ProviderControlSnapshot,
) -> ProviderControlSnapshot:
    released = released_operation_ids_for_provider(snapshot.provider_id)
    advertised = tuple(
        operation_id
        for operation_id in snapshot.advertised_operations
        if operation_id in released
    )
    advertised_set = frozenset(advertised)
    return replace(
        snapshot,
        advertised_operations=advertised,
        values=tuple(
            value
            for value in snapshot.values
            if value.operation_id in advertised_set
        ),
        choices=tuple(
            choices
            for choices in snapshot.choices
            if choices.operation_id in advertised_set
        ),
    )


def validated_driver_snapshot(
    driver: ProviderControlDriver,
    *,
    session_id: str | None,
    session_truth: dict[str, Any] | None,
    now: float | None = None,
    catalog: OperationCatalog = REVIEWED_OPERATION_CATALOG,
) -> ProviderControlSnapshot:
    binding = getattr(driver, "binding", None)
    if not isinstance(binding, ProviderControlBinding):
        raise ControlContractError("provider control driver has no valid binding")
    if not provider_binding_has_release_membership(
        binding.provider_id,
        binding.provider_version,
        binding.provider_channel,
    ):
        raise ControlContractError("provider control driver lacks exact release membership")
    _validate_session_truth(binding, session_id, session_truth)
    snapshot = driver.snapshot(session_id=session_id, session_truth=session_truth)
    if not isinstance(snapshot, ProviderControlSnapshot):
        raise ControlContractError("provider driver returned an invalid control snapshot")
    if snapshot.binding != binding:
        raise ControlContractError("provider snapshot does not match the driver binding")
    snapshot.validate(now=now, catalog=catalog)
    snapshot = _filter_snapshot_to_release_membership(snapshot)
    snapshot.validate(now=now, catalog=catalog)
    return snapshot


def execute_provider_operation(
    driver: ProviderControlDriver,
    *,
    operation_id: str,
    input_payload: dict[str, Any],
    binding_id: str,
    capability_generation: int,
    session_id: str | None,
    session_truth: dict[str, Any] | None,
    client_action_id: str,
    prepared_attachments: tuple[Any, ...] | None = None,
    provider_correlation: ProviderOperationCorrelation | None = None,
    attachment_resolver: AttachmentHandleResolver | None = None,
    source_device_id: str | None = None,
    source_install_id: str | None = None,
    before_execute: Callable[[], None] | None = None,
    now: float | None = None,
    catalog: OperationCatalog = REVIEWED_OPERATION_CATALOG,
) -> ProviderOperationResult:
    _validate_opaque("client_action_id", client_action_id, 512)
    snapshot = validated_driver_snapshot(
        driver,
        session_id=session_id,
        session_truth=session_truth,
        now=now,
        catalog=catalog,
    )
    if binding_id != snapshot.binding_id:
        raise ControlContractError("provider control binding is stale")
    _validate_generation(capability_generation)
    if capability_generation != snapshot.capability_generation:
        raise ControlContractError("provider capability generation is stale")
    if snapshot.blocked_reason is not None:
        raise ControlContractError(f"provider control is blocked: {snapshot.blocked_reason}")
    if operation_id not in snapshot.advertised_operations:
        raise ControlContractError("provider did not advertise this operation")
    _validate_executable_session_truth(snapshot, session_id, session_truth)
    try:
        definition = catalog.require(operation_id)
        normalized = definition.validate_input_payload(input_payload)
    except OperationCatalogError as exc:
        raise ControlContractError(str(exc)) from exc
    _validate_operation_session(snapshot, definition, normalized, session_id)
    _validate_selected_choices(snapshot, definition, normalized)
    normalized, prepared = _prepare_attachments(
        normalized,
        prepared_attachments=prepared_attachments,
        attachment_resolver=attachment_resolver,
        session_id=session_id,
        source_device_id=source_device_id,
        source_install_id=source_install_id,
        binding_id=binding_id,
        client_action_id=client_action_id,
    )
    execute_args = {
        "operation_id": operation_id,
        "input_payload": normalized,
        "binding_id": binding_id,
        "capability_generation": capability_generation,
        "session_id": session_id,
        "client_action_id": client_action_id,
    }
    if prepared:
        execute_args["prepared_attachments"] = prepared
    if provider_correlation is not None:
        if not isinstance(provider_correlation, ProviderOperationCorrelation):
            raise ControlContractError("provider operation correlation is invalid")
        execute_args["provider_correlation"] = provider_correlation
    if before_execute is not None:
        if not callable(before_execute):
            raise ControlContractError("before_execute must be callable")
        before_execute()
    result = driver.execute(**execute_args)
    if not isinstance(result, ProviderOperationResult):
        raise ControlContractError("provider driver returned an invalid operation result")
    result.validate(catalog)
    if result.operation_id != operation_id:
        raise ControlContractError("provider operation result changed the operation identity")
    if provider_correlation is not None and (
        result.provider_operation_id
        != provider_correlation.provider_operation_id
        or result.provider_cursor
        != provider_correlation.provider_cursor
    ):
        raise ControlContractError(
            "provider result changed the reserved action identity"
        )
    return result

def recover_provider_operation(
    driver: ProviderControlDriver,
    *,
    operation_id: str,
    binding_id: str,
    capability_generation: int,
    session_id: str | None,
    client_action_id: str,
    provider_correlation: ProviderOperationCorrelation,
    session_truth: dict[str, Any] | None,
    catalog: OperationCatalog = REVIEWED_OPERATION_CATALOG,
) -> ProviderOperationResult | None:
    """Recover a prior action from provider proof without invoking execute."""
    binding = getattr(driver, "binding", None)
    if not isinstance(binding, ProviderControlBinding) or binding.binding_id != binding_id:
        raise ControlContractError("provider recovery binding is stale")
    if not provider_binding_has_release_membership(
        binding.provider_id,
        binding.provider_version,
        binding.provider_channel,
    ):
        raise ControlContractError("provider recovery lacks exact release membership")
    if operation_id not in released_operation_ids_for_provider(binding.provider_id):
        raise ControlContractError("provider operation is not in release membership")
    _validate_generation(capability_generation)
    _validate_opaque("client_action_id", client_action_id, 512)
    if not isinstance(provider_correlation, ProviderOperationCorrelation):
        raise ControlContractError("provider recovery correlation is invalid")
    try:
        definition = catalog.require(operation_id)
    except OperationCatalogError as exc:
        raise ControlContractError(str(exc)) from exc
    session_bound = any(item.input_type is InputType.PROVIDER_SESSION for item in definition.inputs)
    if session_bound != (session_id is not None):
        raise ControlContractError("provider recovery session identity is mismatched")
    _validate_session_truth(binding, session_id, session_truth)
    if session_truth is not None and (
        session_truth.get("capability_generation") != capability_generation
    ):
        raise ControlContractError("provider recovery generation is stale")
    recover = getattr(driver, "recover", None)
    if not callable(recover):
        return None
    result = recover(
        operation_id=operation_id,
        binding_id=binding_id,
        capability_generation=capability_generation,
        session_id=session_id,
        client_action_id=client_action_id,
        provider_correlation=provider_correlation,
        session_truth=session_truth,
    )
    if result is None:
        return None
    if not isinstance(result, ProviderOperationResult):
        raise ControlContractError("provider recovery returned an invalid result")
    result.validate(catalog)
    if (
        result.operation_id != operation_id
        or result.provider_operation_id != provider_correlation.provider_operation_id
    ):
        raise ControlContractError("provider recovery proof changed action identity")
    if result.status not in {OperationResultStatus.APPLIED, OperationResultStatus.REJECTED}:
        return None
    return result

def _prepare_attachments(
    payload: dict[str, Any],
    *,
    prepared_attachments: tuple[Any, ...] | None,
    attachment_resolver: AttachmentHandleResolver | None,
    session_id: str | None,
    source_device_id: str | None,
    source_install_id: str | None,
    binding_id: str,
    client_action_id: str,
) -> tuple[dict[str, Any], tuple[Any, ...]]:
    has_attachment_input = "attachments" in payload
    records = payload.get("attachments")
    supplied = prepared_attachments or ()
    if not has_attachment_input:
        if supplied:
            raise ControlContractError("prepared attachments lack reviewed handle inputs")
        return payload, ()
    if not records:
        if supplied:
            raise ControlContractError("prepared attachments lack reviewed handle inputs")
        resolved = dict(payload)
        resolved.pop("attachments", None)
        return resolved, ()
    if session_id is None:
        raise ControlContractError("attachment handles require a session identity")
    if prepared_attachments is not None and attachment_resolver is not None:
        raise ControlContractError("attachments must have exactly one preparation source")
    if prepared_attachments is not None:
        prepared = prepared_attachments
    else:
        if attachment_resolver is None or source_device_id is None or source_install_id is None:
            raise ControlContractError("attachment handles require scoped companion resolution")
        _validate_opaque("source_device_id", source_device_id, 512)
        _validate_opaque("source_install_id", source_install_id, 512)
        prepared = attachment_resolver.prepare_attachment_handles(
            records,
            session_id=session_id,
            source_device_id=source_device_id,
            source_install_id=source_install_id,
            binding_id=binding_id,
            client_action_id=client_action_id,
        )
    _validate_prepared_attachments(records, prepared)
    resolved = dict(payload)
    resolved.pop("attachments", None)
    return resolved, prepared


def _validate_prepared_attachments(
    records: list[dict[str, Any]],
    prepared: tuple[Any, ...],
) -> None:
    if not isinstance(prepared, tuple) or len(prepared) != len(records):
        raise ControlContractError("attachment resolver returned an invalid prepared set")
    for record, item in zip(records, prepared):
        if not callable(getattr(item, "open_verified", None)):
            raise ControlContractError("prepared attachment lacks verified access")
        for field in ("handle_id", "sha256", "size_bytes", "mime_type"):
            if getattr(item, field, None) != record[field]:
                raise ControlContractError(f"prepared attachment {field} mismatch")
        if getattr(item, "display_name", None) != record.get("display_name"):
            raise ControlContractError("prepared attachment display_name mismatch")



def provider_control_status_payload(
    snapshot: ProviderControlSnapshot,
    *,
    now: float | None = None,
    catalog: OperationCatalog = REVIEWED_OPERATION_CATALOG,
) -> dict[str, Any]:
    snapshot.validate(now=now, catalog=catalog)
    values: dict[str, dict[str, Any]] = {}
    for item in snapshot.values:
        values.setdefault(item.operation_id, {})[item.input_id] = _wire_value(item.value)
    choices: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for group in snapshot.choices:
        choices.setdefault(group.operation_id, {})[group.input_id] = [choice.to_payload() for choice in group.choices]
    return {
        "schema_version": 1,
        "provider_id": snapshot.provider_id,
        "provider_version": snapshot.provider_version,
        "provider_channel": snapshot.provider_channel,
        "binding_id": snapshot.binding_id,
        "capability_generation": snapshot.capability_generation,
        "observed_at": snapshot.observed_at,
        "valid_until": snapshot.valid_until,
        "advertised_operations": list(snapshot.advertised_operations),
        "values": values,
        "choices": choices,
        "blocked_reason": snapshot.blocked_reason,
        "provider_cursor": snapshot.provider_cursor,
    }


def parse_provider_control_status(
    payload: Mapping[str, Any],
    *,
    now: float | None = None,
    catalog: OperationCatalog = REVIEWED_OPERATION_CATALOG,
) -> ProviderControlSnapshot:
    _require_exact_object(payload, _SNAPSHOT_FIELDS, "provider control snapshot")
    if payload["schema_version"] != 1:
        raise ControlContractError("unknown provider control snapshot schema version")
    advertised = payload["advertised_operations"]
    if not isinstance(advertised, list) or not all(isinstance(item, str) for item in advertised):
        raise ControlContractError("advertised_operations must be a string list")
    values_payload = payload["values"]
    choices_payload = payload["choices"]
    if not isinstance(values_payload, Mapping) or not isinstance(choices_payload, Mapping):
        raise ControlContractError("snapshot values and choices must be objects")
    values: list[ControlValue] = []
    for operation_id, operation_values in values_payload.items():
        definition = _catalog_definition(catalog, operation_id)
        if not isinstance(operation_values, Mapping):
            raise ControlContractError("operation values must be objects")
        for input_id, value in operation_values.items():
            descriptor = _input_descriptor(definition, input_id)
            values.append(ControlValue(operation_id, input_id, _decode_wire_value(descriptor.input_type, value)))
    choices: list[ControlChoices] = []
    for operation_id, operation_choices in choices_payload.items():
        definition = _catalog_definition(catalog, operation_id)
        if not isinstance(operation_choices, Mapping):
            raise ControlContractError("operation choices must be objects")
        for input_id, rows in operation_choices.items():
            descriptor = _input_descriptor(definition, input_id)
            if not isinstance(rows, list):
                raise ControlContractError("input choices must be arrays")
            parsed_rows = []
            for row in rows:
                _require_exact_object(row, _CHOICE_FIELDS, "control choice")
                parsed_rows.append(
                    ControlChoice(_decode_wire_value(descriptor.input_type, row["value"]), row["label"])
                )
            choices.append(ControlChoices(operation_id, input_id, tuple(parsed_rows)))
    try:
        snapshot = ProviderControlSnapshot(
            provider_id=payload["provider_id"],
            provider_version=payload["provider_version"],
            provider_channel=payload["provider_channel"],
            binding_id=payload["binding_id"],
            capability_generation=payload["capability_generation"],
            observed_at=payload["observed_at"],
            valid_until=payload["valid_until"],
            advertised_operations=tuple(advertised),
            values=tuple(values),
            choices=tuple(choices),
            blocked_reason=payload["blocked_reason"],
            provider_cursor=payload["provider_cursor"],
        )
        snapshot.validate(now=now, catalog=catalog)
        return snapshot
    except (TypeError, ValueError, OperationCatalogError) as exc:
        if isinstance(exc, ControlContractError):
            raise
        raise ControlContractError(str(exc)) from exc


def _validate_operation_session(snapshot, definition, payload, session_id) -> None:
    session_descriptors = [item for item in definition.inputs if item.input_type is InputType.PROVIDER_SESSION]
    if not session_descriptors:
        if session_id is not None:
            raise ControlContractError("provider-wide operation cannot carry a session identity")
        return
    if session_id is None:
        raise ControlContractError("session operation requires an exact session id")
    value = payload[session_descriptors[0].input_id]
    identity = value if isinstance(value, ProviderSessionIdentity) else ProviderSessionIdentity.from_payload(value)
    if (
        identity.provider_id != snapshot.provider_id
        or identity.session_id != session_id
        or identity.binding_id != snapshot.binding_id
        or identity.capability_generation != snapshot.capability_generation
    ):
        raise ControlContractError("provider session identity is stale or mismatched")
    payload[session_descriptors[0].input_id] = identity.to_payload()


def _validate_selected_choices(snapshot, definition, payload) -> None:
    groups = {(item.operation_id, item.input_id): item for item in snapshot.choices}
    for descriptor in definition.inputs:
        if descriptor.input_id not in payload:
            continue
        group = groups.get((definition.operation_id, descriptor.input_id))
        if group is None:
            if descriptor.input_type is InputType.CHOICE:
                raise ControlContractError(
                    f"{definition.operation_id}.{descriptor.input_id} has no advertised choices"
                )
            continue
        selected = _canonical_value(payload[descriptor.input_id])
        if selected not in {_canonical_value(choice.value) for choice in group.choices}:
            raise ControlContractError(f"{definition.operation_id}.{descriptor.input_id} is not advertised")


def _validate_session_truth(binding, session_id, session_truth) -> None:
    if session_id is None:
        if session_truth is not None:
            raise ControlContractError("provider-wide snapshot cannot carry session truth")
        return
    _validate_opaque("session_id", session_id, 512)
    if not isinstance(session_truth, dict):
        raise ControlContractError("session snapshot requires runtime truth")
    if (
        session_truth.get("provider_id") != binding.provider_id
        or session_truth.get("session_id") != session_id
        or session_truth.get("binding_id") != binding.binding_id
    ):
        raise ControlContractError("session runtime truth identity is mismatched")
    _validate_generation(session_truth.get("capability_generation"))
    if not isinstance(session_truth.get("is_live"), bool) or not isinstance(
        session_truth.get("controllable"), bool
    ):
        raise ControlContractError("session runtime truth lacks lifecycle state")
    _validate_opaque("session_instance_id", session_truth.get("session_instance_id"), 512)


def _validate_executable_session_truth(snapshot, session_id, session_truth) -> None:
    if session_id is None:
        return
    if (
        session_truth.get("capability_generation") != snapshot.capability_generation
        or session_truth.get("is_live") is not True
        or session_truth.get("controllable") is not True
    ):
        raise ControlContractError("session runtime truth is stale or not controllable")


def _advertised_definition(definitions, operation_id):
    try:
        return definitions[operation_id]
    except (KeyError, TypeError) as exc:
        raise ControlContractError(f"runtime data references unadvertised operation: {operation_id}") from exc


def _catalog_definition(catalog, operation_id):
    if not isinstance(operation_id, str):
        raise ControlContractError("operation id must be a string")
    try:
        return catalog.require(operation_id)
    except OperationCatalogError as exc:
        raise ControlContractError(str(exc)) from exc


def _input_descriptor(definition, input_id):
    if not isinstance(input_id, str):
        raise ControlContractError("input id must be a string")
    try:
        return definition.input_for(input_id)
    except OperationCatalogError as exc:
        raise ControlContractError(str(exc)) from exc


def _validate_descriptor_value(definition, descriptor, value):
    try:
        definition.validate_input_value(descriptor.input_id, _wire_value(value))
    except OperationCatalogError as exc:
        raise ControlContractError(str(exc)) from exc


def _validate_session_value(snapshot, input_type, value):
    if input_type is not InputType.PROVIDER_SESSION:
        return
    identity = value if isinstance(value, ProviderSessionIdentity) else ProviderSessionIdentity.from_payload(value)
    if (
        identity.provider_id != snapshot.provider_id
        or identity.binding_id != snapshot.binding_id
        or identity.capability_generation != snapshot.capability_generation
    ):
        raise ControlContractError("snapshot contains mismatched provider session identity")


def _decode_wire_value(input_type, value):
    if input_type is InputType.PROVIDER_SESSION:
        return ProviderSessionIdentity.from_payload(value)
    return value


def _wire_value(value):
    if isinstance(value, ProviderSessionIdentity):
        return value.to_payload()
    return value


def _canonical_value(value):
    try:
        return json.dumps(_wire_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ControlContractError("control value is not serializable") from exc


def _require_exact_object(payload, fields, name):
    if not isinstance(payload, Mapping):
        raise ControlContractError(f"{name} must be an object")
    actual = set(payload)
    if actual != fields:
        missing = sorted(fields - actual)
        unknown = sorted(actual - fields)
        raise ControlContractError(f"{name} fields mismatch; missing={missing}, unknown={unknown}")


def _validate_provider_id(value):
    if not isinstance(value, str) or _PROVIDER_ID_RE.fullmatch(value) is None:
        raise ControlContractError("invalid provider_id")


def _validate_generation(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ControlContractError("capability_generation must be a positive integer")


def _validate_opaque(name, value, max_length):
    if not isinstance(value, str) or not value or len(value) > max_length or any(ord(char) < 32 for char in value):
        raise ControlContractError(f"invalid {name}")


def _finite_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _json_safe(value, depth=0):
    if depth > 8:
        return False
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, str):
        return len(value) <= _MAX_PUBLIC_STRING_LENGTH
    if isinstance(value, int):
        return not isinstance(value, bool)
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return len(value) <= 1024 and all(_json_safe(item, depth + 1) for item in value)
    if isinstance(value, dict):
        return len(value) <= 1024 and all(
            isinstance(key, str) and len(key) <= 128 and _json_safe(item, depth + 1)
            for key, item in value.items()
        )
    return False
