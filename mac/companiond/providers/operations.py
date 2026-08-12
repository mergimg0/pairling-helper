"""Statically reviewed Pairling provider operations.

Catalog membership describes a wire contract, not runtime capability. A provider
must separately advertise an operation from a fresh, binding-qualified control
snapshot before the operation can be executed.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Iterator, Mapping



class OperationCatalogError(ValueError):
    pass


class Lifecycle(str, Enum):
    BEFORE_TURN = "before_turn"
    DURING_TURN = "during_turn"
    AFTER_TURN = "after_turn"
    PROVIDER_WIDE = "provider_wide"


class Risk(str, Enum):
    READ = "read"
    MUTATION = "mutation"
    DESTRUCTIVE = "destructive"
    CREDENTIAL = "credential"
    EXTERNAL_SIDE_EFFECT = "external_side_effect"


class ResourceProofKind(str, Enum):
    NONE = "none"
    PROVIDER_BINDING = "provider_binding"
    SESSION_TRUTH = "session_truth"
    SCREEN_V2 = "screen_v2"
    APPROVAL_NONCE = "approval_nonce"
    INPUT_LEASE = "input_lease"


class ConfirmationRequirement(str, Enum):
    NONE = "none"
    USER_CONFIRMATION = "user_confirmation"
    POINT_OF_RISK = "point_of_risk"


class RendererID(str, Enum):
    NATIVE_BUTTON = "native_button"
    NATIVE_MENU = "native_menu"
    NATIVE_PICKER = "native_picker"
    NATIVE_TOGGLE = "native_toggle"
    NATIVE_FORM = "native_form"
    READ_ONLY_DETAIL = "read_only_detail"


class InputType(str, Enum):
    ATTACHMENT_HANDLES = "attachment_handles"
    BOOLEAN = "boolean"
    CHOICE = "choice"
    QUESTIONNAIRE = "questionnaire"
    INTEGER = "integer"
    PROVIDER_SESSION = "provider_session"
    RESOURCE_ID = "resource_id"
    TEXT = "text"

_OPERATION_ID_RE = re.compile(r"(?:session|provider)(?:\.[a-z][a-z0-9_]*){1,3}\Z")
_INPUT_ID_RE = re.compile(r"[a-z][a-z0-9_]{0,47}\Z")
_DEVICE_SCOPES = {
    "health:read",
    "pair:admin",
    "session:send",
    "session:signal",
    "session:spawn",
    "sessions:read",
}
_FORBIDDEN_OPERATION_TOKENS = {"jsonrpc", "method", "path", "raw", "shell"}
_FORBIDDEN_INPUT_IDS = {"args", "argv", "command", "jsonrpc", "method", "path", "raw", "shell"}
_ATTACHMENT_FIELDS = {"handle_id", "sha256", "size_bytes", "mime_type"}
_ATTACHMENT_OPTIONAL_FIELDS = {"display_name"}
_MAX_ATTACHMENTS = 8
_MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024
_MAX_ATTACHMENT_TOTAL_BYTES = 8 * 1024 * 1024
_REVIEWED_OPERATION_IDS = frozenset(
    {
        "session.prompt.send",
        "session.turn.steer",
        "session.turn.interrupt",
        "session.terminate",
        "session.resume",
        "session.fork",
        "session.compact",
        "session.rewind",
        "session.model.set",
        "session.reasoning.set",
        "session.permissions.set",
        "session.collaboration_mode.set",
        "session.approval.decide",
        "session.question.answer",
        "session.review.start",
        "session.plan.start",
        "provider.config.read",
        "provider.commands.read",
        "provider.agents.read",
        "provider.status.read",
        "provider.mcp.read",
        "provider.mcp.reload",
        "provider.mcp.reconnect",
        "provider.mcp.set_enabled",
        "provider.auth.read",
        "provider.usage.read",
        "provider.diagnostics.read",
        "session.context.read",
        "session.history.read",
    }
)


@dataclass(frozen=True)
class OperationInputDescriptor:
    input_id: str
    input_type: InputType
    required: bool = True
    max_length: int | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.input_id,
            "type": self.input_type.value,
            "required": self.required,
            "max_length": self.max_length,
        }


@dataclass(frozen=True)
class PairlingOperationDefinition:
    operation_id: str
    lifecycle: Lifecycle
    risk: Risk
    inputs: tuple[OperationInputDescriptor, ...]
    required_device_scope: str
    resource_proof_kind: ResourceProofKind
    confirmation_requirement: ConfirmationRequirement
    receipt_required: bool
    audit_owner: str
    rate_limit_owner: str
    renderer_id: RendererID

    def input_for(self, input_id: str) -> OperationInputDescriptor:
        for descriptor in self.inputs:
            if descriptor.input_id == input_id:
                return descriptor
        raise OperationCatalogError(f"unknown input for {self.operation_id}: {input_id}")
    def validate_input_value(self, input_id: str, value: Any) -> None:
        descriptor = self.input_for(input_id)
        _validate_input_value(self.operation_id, descriptor, value)


    def validate_input_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise OperationCatalogError(f"{self.operation_id} input must be an object")
        expected = {descriptor.input_id for descriptor in self.inputs}
        actual = set(payload)
        unknown = actual - expected
        if unknown:
            raise OperationCatalogError(
                f"{self.operation_id} has unknown inputs: {', '.join(sorted(map(str, unknown)))}"
            )
        missing = {descriptor.input_id for descriptor in self.inputs if descriptor.required} - actual
        if missing:
            raise OperationCatalogError(
                f"{self.operation_id} is missing inputs: {', '.join(sorted(missing))}"
            )
        result: dict[str, Any] = {}
        for descriptor in self.inputs:
            if descriptor.input_id not in payload:
                continue
            value = payload[descriptor.input_id]
            _validate_input_value(self.operation_id, descriptor, value)
            result[descriptor.input_id] = value
        return result

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.operation_id,
            "lifecycle": self.lifecycle.value,
            "risk": self.risk.value,
            "inputs": [item.to_payload() for item in self.inputs],
            "required_device_scope": self.required_device_scope,
            "resource_proof_kind": self.resource_proof_kind.value,
            "confirmation_requirement": self.confirmation_requirement.value,
            "receipt_required": self.receipt_required,
            "audit_owner": self.audit_owner,
            "rate_limit_owner": self.rate_limit_owner,
            "renderer_id": self.renderer_id.value,
        }


class OperationCatalog:
    def __init__(self, definitions: Iterable[PairlingOperationDefinition]):
        by_id: dict[str, PairlingOperationDefinition] = {}
        for definition in definitions:
            _validate_definition(definition)
            if definition.operation_id in by_id:
                raise OperationCatalogError(f"duplicate operation id: {definition.operation_id}")
            by_id[definition.operation_id] = definition
        self._by_id = MappingProxyType(by_id)

    @property
    def ids(self) -> tuple[str, ...]:
        return tuple(self._by_id)

    def __iter__(self) -> Iterator[PairlingOperationDefinition]:
        return iter(self._by_id.values())

    def __len__(self) -> int:
        return len(self._by_id)

    def require(self, operation_id: str) -> PairlingOperationDefinition:
        try:
            return self._by_id[operation_id]
        except KeyError as exc:
            raise OperationCatalogError(f"operation is not reviewed: {operation_id}") from exc


_SESSION = OperationInputDescriptor("session", InputType.PROVIDER_SESSION)
_PROMPT = OperationInputDescriptor("prompt", InputType.TEXT, max_length=200_000)
_ATTACHMENTS = OperationInputDescriptor("attachments", InputType.ATTACHMENT_HANDLES, required=False)
_INSTRUCTION = OperationInputDescriptor("instruction", InputType.TEXT, max_length=200_000)
_TURN_ID = OperationInputDescriptor("turn_id", InputType.RESOURCE_ID, max_length=256)
_MODEL = OperationInputDescriptor("model", InputType.CHOICE, max_length=256)
_REASONING = OperationInputDescriptor("reasoning", InputType.CHOICE, max_length=128)
_COLLABORATION_MODE = OperationInputDescriptor(
    "collaboration_mode", InputType.CHOICE, max_length=64
)
_PERMISSIONS = OperationInputDescriptor("permissions", InputType.CHOICE, max_length=128)
_APPROVAL_ID = OperationInputDescriptor("approval_id", InputType.RESOURCE_ID, max_length=256)
_APPROVAL_DIGEST = OperationInputDescriptor(
    "approval_digest",
    InputType.RESOURCE_ID,
    required=False,
    max_length=64,
)
_APPROVAL_TOOL_USE_ID = OperationInputDescriptor(
    "approval_tool_use_id",
    InputType.RESOURCE_ID,
    required=False,
    max_length=256,
)
_APPROVAL_TOOL_NAME = OperationInputDescriptor(
    "approval_tool_name",
    InputType.TEXT,
    required=False,
    max_length=160,
)
_APPROVAL_PREVIEW = OperationInputDescriptor(
    "approval_preview",
    InputType.TEXT,
    required=False,
    max_length=4096,
)
_APPROVAL_INPUT_REDACTED = OperationInputDescriptor(
    "approval_input_redacted",
    InputType.BOOLEAN,
    required=False,
)
_APPROVAL_INPUT_TRUNCATED = OperationInputDescriptor(
    "approval_input_truncated",
    InputType.BOOLEAN,
    required=False,
)
_APPROVAL_INPUT_RENDERABLE = OperationInputDescriptor(
    "approval_input_renderable",
    InputType.BOOLEAN,
    required=False,
)
_APPROVAL_EXPIRES_AT = OperationInputDescriptor(
    "approval_expires_at",
    InputType.INTEGER,
    required=False,
)
_DECISION = OperationInputDescriptor("decision", InputType.CHOICE, max_length=64)
_QUESTION_REQUEST_ID = OperationInputDescriptor(
    "question_request_id",
    InputType.CHOICE,
    max_length=256,
)
_QUESTION_ANSWERS = OperationInputDescriptor(
    "answers",
    InputType.QUESTIONNAIRE,
    required=False,
)
_MCP_SERVER = OperationInputDescriptor("server_id", InputType.CHOICE, max_length=256)
_TARGET_SESSION = OperationInputDescriptor(
    "target_session",
    InputType.CHOICE,
    max_length=512,
)

_MCP_ENABLED = OperationInputDescriptor("enabled", InputType.BOOLEAN)


def _operation(
    operation_id: str,
    lifecycle: Lifecycle,
    risk: Risk,
    inputs: tuple[OperationInputDescriptor, ...],
    scope: str,
    proof: ResourceProofKind,
    confirmation: ConfirmationRequirement,
    renderer: RendererID,
) -> PairlingOperationDefinition:
    return PairlingOperationDefinition(
        operation_id=operation_id,
        lifecycle=lifecycle,
        risk=risk,
        inputs=inputs,
        required_device_scope=scope,
        resource_proof_kind=proof,
        confirmation_requirement=confirmation,
        receipt_required=risk is not Risk.READ,
        audit_owner="pairlingd",
        rate_limit_owner="pairlingd",
        renderer_id=renderer,
    )


def _session_operation(
    operation_id: str,
    lifecycle: Lifecycle,
    risk: Risk,
    *inputs: OperationInputDescriptor,
    scope: str = "session:signal",
    proof: ResourceProofKind = ResourceProofKind.SESSION_TRUTH,
    confirmation: ConfirmationRequirement = ConfirmationRequirement.USER_CONFIRMATION,
    renderer: RendererID = RendererID.NATIVE_BUTTON,
) -> PairlingOperationDefinition:
    return _operation(operation_id, lifecycle, risk, (_SESSION, *inputs), scope, proof, confirmation, renderer)


def _provider_read(operation_id: str) -> PairlingOperationDefinition:
    return _operation(
        operation_id,
        Lifecycle.PROVIDER_WIDE,
        Risk.READ,
        (),
        "health:read",
        ResourceProofKind.PROVIDER_BINDING,
        ConfirmationRequirement.NONE,
        RendererID.READ_ONLY_DETAIL,
    )




def _validate_definition(definition: PairlingOperationDefinition) -> None:
    if not isinstance(definition, PairlingOperationDefinition):
        raise OperationCatalogError("operation definition has the wrong type")
    if definition.operation_id not in _REVIEWED_OPERATION_IDS:
        raise OperationCatalogError(f"operation is not statically reviewed: {definition.operation_id}")
    if _OPERATION_ID_RE.fullmatch(definition.operation_id) is None:
        raise OperationCatalogError(f"invalid operation id: {definition.operation_id}")
    if set(definition.operation_id.split(".")) & _FORBIDDEN_OPERATION_TOKENS:
        raise OperationCatalogError(f"unsafe operation id: {definition.operation_id}")
    for field_name, enum_type in (
        ("lifecycle", Lifecycle),
        ("risk", Risk),
        ("resource_proof_kind", ResourceProofKind),
        ("confirmation_requirement", ConfirmationRequirement),
        ("renderer_id", RendererID),
    ):
        if not isinstance(getattr(definition, field_name), enum_type):
            raise OperationCatalogError(f"{definition.operation_id} has unknown {field_name}")
    if definition.required_device_scope not in _DEVICE_SCOPES:
        raise OperationCatalogError(f"{definition.operation_id} has an unknown device scope")
    if not _safe_owner(definition.audit_owner) or not _safe_owner(definition.rate_limit_owner):
        raise OperationCatalogError(f"{definition.operation_id} has an invalid enforcement owner")
    input_ids: set[str] = set()
    for descriptor in definition.inputs:
        _validate_input_descriptor(definition.operation_id, descriptor)
        if descriptor.input_id in input_ids:
            raise OperationCatalogError(f"{definition.operation_id} has duplicate input {descriptor.input_id}")
        input_ids.add(descriptor.input_id)
    is_read = definition.risk is Risk.READ
    if is_read:
        if definition.receipt_required or definition.confirmation_requirement is not ConfirmationRequirement.NONE:
            raise OperationCatalogError(f"read-only operation has mutation posture: {definition.operation_id}")
    elif not definition.receipt_required or definition.confirmation_requirement is ConfirmationRequirement.NONE:
        raise OperationCatalogError(f"unsafe operation posture: {definition.operation_id}")
    if definition.risk in {Risk.DESTRUCTIVE, Risk.CREDENTIAL} and (
        definition.confirmation_requirement is not ConfirmationRequirement.POINT_OF_RISK
    ):
        raise OperationCatalogError(f"high-risk operation lacks point-of-risk confirmation: {definition.operation_id}")
    if definition.operation_id.startswith("session."):
        session_inputs = [item for item in definition.inputs if item.input_type is InputType.PROVIDER_SESSION]
        if len(session_inputs) != 1 or definition.resource_proof_kind is ResourceProofKind.NONE:
            raise OperationCatalogError(f"session operation lacks exact runtime identity: {definition.operation_id}")


def _validate_input_descriptor(operation_id: str, descriptor: OperationInputDescriptor) -> None:
    if not isinstance(descriptor, OperationInputDescriptor):
        raise OperationCatalogError(f"{operation_id} has an invalid input descriptor")
    if _INPUT_ID_RE.fullmatch(descriptor.input_id) is None or descriptor.input_id in _FORBIDDEN_INPUT_IDS:
        raise OperationCatalogError(f"{operation_id} has unsafe input id: {descriptor.input_id}")
    if not isinstance(descriptor.input_type, InputType):
        raise OperationCatalogError(f"{operation_id} has unknown input type: {descriptor.input_type}")
    if not isinstance(descriptor.required, bool):
        raise OperationCatalogError(f"{operation_id} input required flag must be boolean")
    if descriptor.max_length is not None and (
        isinstance(descriptor.max_length, bool) or not isinstance(descriptor.max_length, int) or descriptor.max_length < 1
    ):
        raise OperationCatalogError(f"{operation_id} input max_length is invalid")
    if descriptor.input_type in {
        InputType.ATTACHMENT_HANDLES,
        InputType.BOOLEAN,
        InputType.INTEGER,
        InputType.QUESTIONNAIRE,
        InputType.PROVIDER_SESSION,
    } and descriptor.max_length is not None:
        raise OperationCatalogError(f"{operation_id} input type cannot have max_length")


def _validate_input_value(
    operation_id: str,
    descriptor: OperationInputDescriptor,
    value: Any,
) -> None:
    kind = descriptor.input_type
    if kind is InputType.BOOLEAN:
        valid = isinstance(value, bool)
    elif kind is InputType.INTEGER:
        valid = isinstance(value, int) and not isinstance(value, bool)
    elif kind is InputType.PROVIDER_SESSION:
        valid = _valid_provider_session_payload(value)
    elif kind is InputType.ATTACHMENT_HANDLES:
        valid = _valid_attachment_handles(value)
    elif kind is InputType.QUESTIONNAIRE:
        valid = _valid_questionnaire_answers(value)
    else:
        valid = isinstance(value, str) and bool(value) and "\x00" not in value
        if valid and descriptor.max_length is not None:
            valid = len(value) <= descriptor.max_length
    if not valid:
        raise OperationCatalogError(f"{operation_id} input {descriptor.input_id} has the wrong type")


def _valid_provider_session_payload(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    if set(value) != {"provider_id", "session_id", "binding_id", "capability_generation"}:
        return False
    generation = value.get("capability_generation")
    return (
        all(isinstance(value.get(key), str) and bool(value.get(key)) for key in ("provider_id", "session_id", "binding_id"))
        and isinstance(generation, int)
        and not isinstance(generation, bool)
        and generation >= 1
    )


def _valid_attachment_handles(value: Any) -> bool:
    if not isinstance(value, list) or len(value) > _MAX_ATTACHMENTS:
        return False
    total_bytes = 0
    handle_ids: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping):
            return False
        keys = set(item)
        if not _ATTACHMENT_FIELDS.issubset(keys) or keys - _ATTACHMENT_FIELDS - _ATTACHMENT_OPTIONAL_FIELDS:
            return False
        handle_id = item.get("handle_id")
        sha256 = item.get("sha256")
        size_bytes = item.get("size_bytes")
        mime_type = item.get("mime_type")
        display_name = item.get("display_name")
        if (
            not _safe_text(handle_id, 256)
            or handle_id in handle_ids
            or not isinstance(sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
            or isinstance(size_bytes, bool)
            or not isinstance(size_bytes, int)
            or size_bytes < 0
            or size_bytes > _MAX_ATTACHMENT_BYTES
            or not _safe_text(mime_type, 128)
            or (display_name is not None and not _safe_text(display_name, 128))
        ):
            return False
        handle_ids.add(handle_id)
        total_bytes += size_bytes
        if total_bytes > _MAX_ATTACHMENT_TOTAL_BYTES:
            return False
    return True


def _valid_questionnaire_answers(value: Any) -> bool:
    if not isinstance(value, list) or not 1 <= len(value) <= 12:
        return False
    seen_indexes: set[int] = set()
    for item in value:
        if not isinstance(item, Mapping):
            return False
        keys = set(item)
        if not {"index", "topic", "question", "options", "answer"}.issubset(keys):
            return False
        if keys - {
            "index",
            "topic",
            "question",
            "options",
            "answer",
            "required",
            "multiple",
            "custom",
            "selections",
        }:
            return False
        index = item.get("index")
        topic = item.get("topic")
        question = item.get("question")
        options = item.get("options")
        answer = item.get("answer")
        required = item.get("required")
        multiple = item.get("multiple", False)
        custom = item.get("custom", not options)
        selections = item.get("selections", [])
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or not 1 <= index <= 100
            or index in seen_indexes
        ):
            return False
        if (
            not isinstance(topic, str)
            or len(topic) > 160
            or "\x00" in topic
            or not isinstance(question, str)
            or not question
            or len(question) > 2_000
            or "\x00" in question
            or not isinstance(options, list)
            or len(options) > 20
            or not all(
                isinstance(option, str)
                and bool(option)
                and len(option) <= 512
                and "\x00" not in option
                for option in options
            )
            or not isinstance(answer, str)
            or len(answer) > 10_000
            or "\x00" in answer
            or type(multiple) is not bool
            or type(custom) is not bool
            or not isinstance(selections, list)
            or not all(
                isinstance(selection, str)
                and bool(selection)
                and len(selection) <= 512
                and "\x00" not in selection
                for selection in selections
            )
            or len(selections) != len(set(selections))
            or (not multiple and bool(selections))
            or (
                not custom
                and any(selection not in options for selection in selections)
            )
            or (required is not None and type(required) is not bool)
        ):
            return False
        seen_indexes.add(index)
    return True

def _safe_text(value: Any, max_length: int) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= max_length
        and all(ord(char) >= 32 for char in value)
    )


def _safe_owner(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,47}", value) is not None
REVIEWED_OPERATION_CATALOG = OperationCatalog(
    (
        _session_operation(
            "session.prompt.send", Lifecycle.BEFORE_TURN, Risk.EXTERNAL_SIDE_EFFECT,
            _PROMPT, _ATTACHMENTS, scope="session:send", proof=ResourceProofKind.INPUT_LEASE,
            renderer=RendererID.NATIVE_FORM,
        ),
        _session_operation(
            "session.turn.steer", Lifecycle.DURING_TURN, Risk.EXTERNAL_SIDE_EFFECT,
            _INSTRUCTION, scope="session:send", proof=ResourceProofKind.INPUT_LEASE,
            renderer=RendererID.NATIVE_FORM,
        ),
        _session_operation("session.turn.interrupt", Lifecycle.DURING_TURN, Risk.MUTATION),
        _session_operation(
            "session.terminate", Lifecycle.DURING_TURN, Risk.DESTRUCTIVE,
            confirmation=ConfirmationRequirement.POINT_OF_RISK,
        ),
        _session_operation(
            "session.resume", Lifecycle.AFTER_TURN, Risk.MUTATION,
            _TARGET_SESSION,
            scope="session:spawn",
            renderer=RendererID.NATIVE_PICKER,
        ),
        _session_operation(
            "session.fork", Lifecycle.AFTER_TURN, Risk.EXTERNAL_SIDE_EFFECT,
            _TARGET_SESSION,
            scope="session:spawn",
            renderer=RendererID.NATIVE_PICKER,
        ),
        _session_operation("session.compact", Lifecycle.AFTER_TURN, Risk.EXTERNAL_SIDE_EFFECT),
        _session_operation(
            "session.rewind", Lifecycle.AFTER_TURN, Risk.DESTRUCTIVE, _TURN_ID,
            confirmation=ConfirmationRequirement.POINT_OF_RISK,
        ),
        _session_operation(
            "session.model.set", Lifecycle.BEFORE_TURN, Risk.MUTATION, _MODEL,
            renderer=RendererID.NATIVE_PICKER,
        ),
        _session_operation(
            "session.reasoning.set", Lifecycle.BEFORE_TURN, Risk.MUTATION, _REASONING,
            renderer=RendererID.NATIVE_PICKER,
        ),
        _session_operation(
            "session.collaboration_mode.set",
            Lifecycle.BEFORE_TURN,
            Risk.MUTATION,
            _COLLABORATION_MODE,
            renderer=RendererID.NATIVE_PICKER,
        ),
        _session_operation(
            "session.permissions.set", Lifecycle.BEFORE_TURN, Risk.CREDENTIAL, _PERMISSIONS,
            confirmation=ConfirmationRequirement.POINT_OF_RISK,
            renderer=RendererID.NATIVE_PICKER,
        ),
        _session_operation(
            "session.approval.decide", Lifecycle.DURING_TURN, Risk.EXTERNAL_SIDE_EFFECT,
            _APPROVAL_ID, _APPROVAL_DIGEST, _APPROVAL_TOOL_USE_ID,
            _APPROVAL_TOOL_NAME, _APPROVAL_PREVIEW, _APPROVAL_INPUT_REDACTED,
            _APPROVAL_INPUT_TRUNCATED, _APPROVAL_INPUT_RENDERABLE,
            _APPROVAL_EXPIRES_AT, _DECISION,
            proof=ResourceProofKind.APPROVAL_NONCE,
            confirmation=ConfirmationRequirement.POINT_OF_RISK,
            renderer=RendererID.NATIVE_MENU,
        ),
        _session_operation(
            "session.question.answer",
            Lifecycle.DURING_TURN,
            Risk.MUTATION,
            _QUESTION_REQUEST_ID,
            _DECISION,
            _QUESTION_ANSWERS,
            proof=ResourceProofKind.INPUT_LEASE,
            renderer=RendererID.NATIVE_FORM,
        ),
        _session_operation(
            "session.review.start", Lifecycle.BEFORE_TURN, Risk.EXTERNAL_SIDE_EFFECT,
            scope="session:spawn",
        ),
        _session_operation(
            "session.plan.start", Lifecycle.BEFORE_TURN, Risk.EXTERNAL_SIDE_EFFECT,
            scope="session:spawn",
        ),
        _provider_read("provider.config.read"),
        _provider_read("provider.commands.read"),
        _session_operation(
            "provider.agents.read",
            Lifecycle.AFTER_TURN,
            Risk.READ,
            scope="sessions:read",
            proof=ResourceProofKind.SESSION_TRUTH,
            confirmation=ConfirmationRequirement.NONE,
            renderer=RendererID.READ_ONLY_DETAIL,
        ),
        _session_operation(
            "provider.status.read",
            Lifecycle.AFTER_TURN,
            Risk.READ,
            scope="sessions:read",
            proof=ResourceProofKind.SESSION_TRUTH,
            confirmation=ConfirmationRequirement.NONE,
            renderer=RendererID.READ_ONLY_DETAIL,
        ),
        _provider_read("provider.mcp.read"),
        _operation(
            "provider.mcp.reload",
            Lifecycle.PROVIDER_WIDE,
            Risk.MUTATION,
            (_MCP_SERVER,),
            "pair:admin",
            ResourceProofKind.PROVIDER_BINDING,
            ConfirmationRequirement.POINT_OF_RISK,
            RendererID.NATIVE_BUTTON,
        ),
        _provider_read("provider.auth.read"),
        _session_operation(
            "provider.mcp.reconnect",
            Lifecycle.BEFORE_TURN,
            Risk.MUTATION,
            _MCP_SERVER,
            scope="pair:admin",
            proof=ResourceProofKind.SESSION_TRUTH,
            confirmation=ConfirmationRequirement.POINT_OF_RISK,
            renderer=RendererID.NATIVE_BUTTON,
        ),
        _session_operation(
            "provider.mcp.set_enabled",
            Lifecycle.BEFORE_TURN,
            Risk.MUTATION,
            _MCP_SERVER,
            _MCP_ENABLED,
            scope="pair:admin",
            proof=ResourceProofKind.SESSION_TRUTH,
            confirmation=ConfirmationRequirement.POINT_OF_RISK,
            renderer=RendererID.NATIVE_FORM,
        ),
        _provider_read("provider.usage.read"),
        _provider_read("provider.diagnostics.read"),
        _session_operation(
            "session.context.read",
            Lifecycle.AFTER_TURN,
            Risk.READ,
            scope="sessions:read",
            proof=ResourceProofKind.SESSION_TRUTH,
            confirmation=ConfirmationRequirement.NONE,
            renderer=RendererID.READ_ONLY_DETAIL,
        ),
        _session_operation(
            "session.history.read",
            Lifecycle.AFTER_TURN,
            Risk.READ,
            scope="sessions:read",
            proof=ResourceProofKind.SESSION_TRUTH,
            confirmation=ConfirmationRequirement.NONE,
            renderer=RendererID.READ_ONLY_DETAIL,
        ),
    )
)

CODEX_APP_SERVER_SAFE_LAUNCH_PROFILE = {
    "provider_id": "codex",
    "provider_version": "0.147.0",
    "provider_channel": "app-server-stdio",
    "argv_suffix": ("app-server", "--listen", "stdio://"),
    "client_version": "2026.08.03",
}

_COMMON_RELEASE_SOURCE_PATHS = (
    "mac/companiond/providers/operations.py",
    "mac/companiond/providers/controls.py",
    "mac/companiond/providers/registry.py",
)

_RELEASE_CAPABILITIES_BY_MAP_PROVIDER_ID = MappingProxyType(
    {
        "codex": (
            ("codex.session.lifecycle_discovery", ("session.resume", "session.fork")),
            (
                "codex.turn.input_steer_interrupt",
                (
                    "session.prompt.send",
                    "session.turn.steer",
                    "session.turn.interrupt",
                ),
            ),
            (
                "codex.approval_policy",
                ("session.approval.decide", "session.question.answer"),
            ),
            (
                "codex.models_config_integrations",
                (
                    "session.collaboration_mode.set",
                    "provider.config.read",
                    "provider.mcp.read",
                ),
            ),
            (
                "codex.subagents_plan_review_context",
                ("session.review.start", "session.compact", "session.fork"),
            ),
            (
                "codex.release_lifecycle_usage_diagnostics",
                (
                    "session.terminate",
                    "provider.usage.read",
                    "provider.diagnostics.read",
                ),
            ),
            ("codex.release_auth_status", ("provider.auth.read",)),
        ),
        "claude_code": (
            ("claude.session_history_lifecycle", ("session.history.read",)),
            (
                "claude.prompt_interrupt_permissions",
                (
                    "session.prompt.send",
                    "session.turn.steer",
                    "session.turn.interrupt",
                    "session.terminate",
                    "session.permissions.set",
                    "session.approval.decide",
                    "session.question.answer",
                ),
            ),
            (
                "claude.release_model_context_checkpoint",
                (
                    "session.context.read",
                    "session.model.set",
                    "session.compact",
                    "session.rewind",
                ),
            ),
            (
                "claude.release_integration_catalog",
                (
                    "provider.agents.read",
                    "provider.commands.read",
                    "provider.mcp.read",
                    "provider.mcp.reconnect",
                    "provider.mcp.set_enabled",
                ),
            ),
            (
                "claude.events_hooks_usage",
                ("provider.status.read", "provider.diagnostics.read"),
            ),
            ("claude.release_auth_status", ("provider.auth.read",)),
        ),
        "omp": (
            (
                "omp.acp_session",
                (
                    "session.prompt.send",
                    "session.turn.interrupt",
                    "session.model.set",
                    "session.permissions.set",
                    "session.approval.decide",
                    "session.question.answer",
                ),
            ),
            (
                "omp.rpc_rich_control",
                ("session.prompt.send", "session.turn.interrupt"),
            ),
            ("omp.release_model_selection", ("session.model.set",)),
        ),
        "opencode": (
            (
                "opencode.session_prompt_history",
                (
                    "session.prompt.send",
                    "session.turn.steer",
                    "session.turn.interrupt",
                    "session.resume",
                    "session.fork",
                    "session.approval.decide",
                    "session.question.answer",
                ),
            ),
            (
                "opencode.models_agents_context_vcs",
                ("session.model.set", "session.reasoning.set"),
            ),
            (
                "opencode.release_status_usage_auth",
                (
                    "provider.auth.read",
                    "provider.usage.read",
                    "provider.diagnostics.read",
                ),
            ),
        ),
        "hermes_agent": (
            (
                "hermes.session_input_control",
                (
                    "session.prompt.send",
                    "session.turn.interrupt",
                    "session.resume",
                    "session.fork",
                ),
            ),
            ("hermes.approvals_sandbox", ("session.approval.decide",)),
            ("hermes.models_integrations", ("session.model.set",)),
            (
                "hermes.events_files_usage",
                ("provider.usage.read", "provider.diagnostics.read"),
            ),
            ("hermes.release_diagnostics", ("provider.diagnostics.read",)),
        ),
        "gemini_cli": (
            (
                "gemini.release_prompt_cancel",
                ("session.prompt.send", "session.turn.interrupt"),
            ),
            (
                "gemini.approval_policy_sandbox",
                (
                    "session.permissions.set",
                    "session.approval.decide",
                    "session.question.answer",
                ),
            ),
            ("gemini.models_generation", ("session.model.set",)),
        ),
        "grok_build": (
            (
                "grok.session_headless_acp",
                ("session.prompt.send", "session.turn.interrupt"),
            ),
            ("grok.queue_interject", ("session.turn.interrupt",)),
            (
                "grok.release_permissions_approval_questions",
                (
                    "session.permissions.set",
                    "session.approval.decide",
                    "session.question.answer",
                ),
            ),
            ("grok.release_model_selection", ("session.model.set",)),
        ),
        "kimi_code": (
            (
                "kimi.prompt_queue_steer_abort",
                ("session.prompt.send", "session.turn.interrupt"),
            ),
            (
                "kimi.approvals_modes_trust",
                (
                    "session.permissions.set",
                    "session.approval.decide",
                    "session.question.answer",
                ),
            ),
            ("kimi.models_integrations_tasks", ("session.model.set",)),
        ),
        "github_copilot_cli": (
            ("copilot.sdk_session_lifecycle", ("session.resume",)),
            (
                "copilot.prompt_queue_abort",
                (
                    "session.prompt.send",
                    "session.turn.steer",
                    "session.turn.interrupt",
                ),
            ),
            ("copilot.permissions_handlers", ("session.approval.decide",)),
            (
                "copilot.models_integrations_context",
                ("session.model.set", "provider.mcp.read"),
            ),
            (
                "copilot.events_usage_attachments",
                ("provider.usage.read", "provider.diagnostics.read"),
            ),
        ),
        "qwen_code": (
            (
                "qwen.session_prompt_output",
                (
                    "session.prompt.send",
                    "session.turn.steer",
                    "session.turn.interrupt",
                    "session.terminate",
                    "session.resume",
                    "session.fork",
                ),
            ),
            (
                "qwen.release_permissions_model_usage",
                (
                    "session.permissions.set",
                    "session.approval.decide",
                    "session.model.set",
                    "session.reasoning.set",
                    "provider.usage.read",
                ),
            ),
            (
                "qwen.acp_events_integrations",
                ("provider.config.read", "provider.mcp.read"),
            ),
        ),
        "cline_cli": (
            (
                "cline.json_acp_session",
                (
                    "session.prompt.send",
                    "session.turn.interrupt",
                    "session.permissions.set",
                    "session.approval.decide",
                    "session.question.answer",
                ),
            ),
        ),
        "openhands": (
            (
                "openhands.server_sessions_events",
                (
                    "session.prompt.send",
                    "session.resume",
                    "provider.auth.read",
                    "provider.config.read",
                    "provider.usage.read",
                    "provider.diagnostics.read",
                ),
            ),
            (
                "openhands.control_context",
                (
                    "session.turn.interrupt",
                    "session.approval.decide",
                    "session.fork",
                    "session.compact",
                    "session.rewind",
                    "session.model.set",
                ),
            ),
        ),
        "droid": (
            (
                "droid.session_lifecycle_input",
                (
                    "session.prompt.send",
                    "session.turn.steer",
                    "session.turn.interrupt",
                    "session.terminate",
                    "session.resume",
                    "session.fork",
                    "session.compact",
                ),
            ),
            (
                "droid.settings_catalogs_context",
                (
                    "session.model.set",
                    "session.reasoning.set",
                    "session.permissions.set",
                    "session.plan.start",
                    "provider.config.read",
                    "provider.commands.read",
                    "provider.mcp.read",
                    "provider.auth.read",
                    "provider.usage.read",
                ),
            ),
            (
                "droid.notifications_permissions_questions",
                (
                    "session.approval.decide",
                    "session.question.answer",
                    "provider.diagnostics.read",
                ),
            ),
        ),
    }
)

_DIRECT_RELEASE_DRIVER_PROFILES = MappingProxyType(
    {
        "codex": {
            "map_provider_id": "codex",
            "provider_version": "0.147.0",
            "provider_channel": "app-server-stdio",
            "driver_contract": CODEX_APP_SERVER_SAFE_LAUNCH_PROFILE,
            "source_paths": (
                "mac/companiond/providers/codex.py",
                "mac/companiond/providers/codex_app_server.py",
            ),
        },
        "claude": {
            "map_provider_id": "claude_code",
            "provider_version": "2.1.220",
            "provider_channel": "agent-sdk",
            "driver_contract": {
                "driver": "claude-agent-sdk",
                "sdk_package": "@anthropic-ai/claude-agent-sdk",
                "sdk_version": "0.3.220",
                "sidecar_protocol": 2,
            },
            "source_paths": (
                "mac/companiond/providers/claude.py",
                "mac/companiond/providers/claude_agent_sdk.py",
                "mac/companiond/providers/claude_agent_sidecar.mjs",
            ),
        },
        "copilot": {
            "map_provider_id": "github_copilot_cli",
            "provider_version": "1.0.78",
            "provider_channel": "stable",
            "driver_contract": {
                "driver": "github-copilot-sdk",
                "sdk_package": "@github/copilot-sdk",
                "sdk_version": "1.0.8",
                "sdk_protocol": 3,
                "sidecar_protocol": 1,
            },
            "source_paths": (
                "mac/companiond/providers/copilot.py",
                "mac/companiond/providers/copilot_sdk_sidecar.mjs",
            ),
        },
        "droid": {
            "map_provider_id": "droid",
            "provider_version": "0.185.0",
            "provider_channel": "stable",
            "driver_contract": {
                "driver": "factory-droid-stream-jsonrpc",
                "jsonrpc_version": "2.0",
                "api_version": "1.0.0",
                "protocol_version": "1.143.0",
                "argv_suffix": (
                    "exec",
                    "--input-format",
                    "stream-jsonrpc",
                    "--output-format",
                    "stream-jsonrpc",
                ),
            },
            "source_paths": (
                "mac/companiond/providers/droid.py",
                "mac/companiond/providers/droid_jsonrpc.py",
            ),
        },
        "hermes_agent": {
            "map_provider_id": "hermes_agent",
            "provider_version": "0.19.0",
            "provider_channel": "upstream-937222f4",
            "driver_contract": {
                "driver": "hermes-runs-sse",
                "profile_scope": "pairling_owned_dedicated",
                "loopback_auth": "owned_bearer",
                "approval_mode": "manual",
                "cron_mode": "deny",
            },
            "source_paths": (
                "mac/companiond/providers/hermes.py",
                "mac/companiond/providers/hermes_runs.py",
            ),
        },
        "opencode": {
            "map_provider_id": "opencode",
            "provider_version": "1.15.10",
            "provider_channel": "stable",
            "driver_contract": {
                "driver": "opencode-owned-http-sse",
                "argv_suffix": (
                    "serve",
                    "--pure",
                    "--hostname",
                    "127.0.0.1",
                    "--port",
                    "0",
                ),
                "loopback_auth": "generated_basic",
            },
            "source_paths": (
                "mac/companiond/providers/opencode.py",
                "mac/companiond/providers/opencode_protocol.py",
            ),
        },
        "openhands": {
            "map_provider_id": "openhands",
            "provider_version": "1.40.0",
            "provider_channel": "stable",
            "driver_contract": {
                "driver": "openhands-agent-server",
                "host": "127.0.0.1",
                "port": "ephemeral",
                "auth": "owned_session_api_key",
                "confirmation_policy": "AlwaysConfirm",
            },
            "source_paths": ("mac/companiond/providers/openhands.py",),
        },
        "qwen_code": {
            "map_provider_id": "qwen_code",
            "provider_version": "0.21.4",
            "provider_channel": "stable",
            "driver_contract": {
                "driver": "qwen-code-sdk",
                "sdk_package": "@qwen-code/sdk",
                "sdk_version": "0.1.8",
                "sidecar_protocol": "pairling-qwen-sdk-v1",
                "minimum_node_major": 22,
            },
            "source_paths": (
                "mac/companiond/providers/qwen.py",
                "mac/companiond/providers/qwen_sdk_sidecar.mjs",
            ),
        },
    }
)


def _release_capabilities(map_provider_id: str) -> tuple[dict[str, Any], ...]:
    return tuple(
        {
            "capability_key": capability_key,
            "operation_ids": tuple(operation_ids),
        }
        for capability_key, operation_ids
        in _RELEASE_CAPABILITIES_BY_MAP_PROVIDER_ID[map_provider_id]
    )


def _release_driver_digest(profile: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        profile,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _release_membership_spec(
    *,
    map_provider_id: str,
    runtime_provider_id: str,
    provider_version: str,
    provider_channel: str,
    launch_config_digest: str,
    source_paths: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "map_provider_id": map_provider_id,
        "runtime_provider_id": runtime_provider_id,
        "provider_version": provider_version,
        "provider_channel": provider_channel,
        "launch_config_digest": launch_config_digest,
        "physical_device_required": runtime_provider_id == "omp",
        "source_paths": _COMMON_RELEASE_SOURCE_PATHS + source_paths,
        "capabilities": _release_capabilities(map_provider_id),
    }


_DIRECT_RELEASE_MEMBERSHIP_SPECS = tuple(
    _release_membership_spec(
        map_provider_id=str(profile["map_provider_id"]),
        runtime_provider_id=runtime_provider_id,
        provider_version=str(profile["provider_version"]),
        provider_channel=str(profile["provider_channel"]),
        launch_config_digest=_release_driver_digest(profile["driver_contract"]),
        source_paths=tuple(profile["source_paths"]),
    )
    for runtime_provider_id, profile in _DIRECT_RELEASE_DRIVER_PROFILES.items()
)


_ACP_RELEASE_PROFILE_PINS = MappingProxyType(
    {
        "gemini_cli": {
            "provider_version": "0.53.1",
            "provider_channel": "stable",
            "safe_launch_digest": (
                "2a13d565f12a54cf6cebd0a2c336fdae"
                "63e0f6580867eed15b5c477f9f7dbb10"
            ),
        },
        "omp": {
            "provider_version": "semver:*",
            "provider_channel": "stable",
            "safe_launch_digest": (
                "b23e87ba209c91cace6f5bb931fe36cda"
                "376a844141745276d113780c84d07b0"
            ),
        },
        "grok_build": {
            "provider_version": "grok 0.2.118 (1e1687c1cf6a) [stable]",
            "provider_channel": "stable",
            "safe_launch_digest": (
                "1206e54467db122bc5dfd09c961704b82"
                "4b775e7d3c8f2fefe3f06bad3950fd6"
            ),
        },
        "kimi_code": {
            "provider_version": "0.31.1",
            "provider_channel": "stable",
            "safe_launch_digest": (
                "61039cf84884f6237f1719170f83a352"
                "f341b24e9ebc428e4fafd188df216de9"
            ),
        },
        "hermes_agent": {
            "provider_version": (
                "Hermes Agent v0.19.0 (2026.7.20) · upstream 937222f4"
            ),
            "provider_channel": "stable",
            "safe_launch_digest": (
                "5ed7697ff7693c019f32e9e606cbd551"
                "e9b3ef9387397fb24e627c5b44ae3942"
            ),
        },
        "cline_cli": {
            "provider_version": "3.0.49",
            "provider_channel": "stable",
            "safe_launch_digest": (
                "3485cbb8bbbf86fc61a7f1d43e962d27"
                "1f19a8a4205f788c64d75d6cf612191a"
            ),
        },
    }
)
_ACP_RELEASE_RUNTIME_PROVIDER_IDS = (
    "gemini_cli",
    "omp",
    "grok_build",
    "kimi_code",
    "cline_cli",
)

_ACP_RELEASE_MEMBERSHIP_SPECS = tuple(
    _release_membership_spec(
        map_provider_id=runtime_provider_id,
        runtime_provider_id=runtime_provider_id,
        provider_version=str(
            _ACP_RELEASE_PROFILE_PINS[runtime_provider_id]["provider_version"]
        ),
        provider_channel=str(
            _ACP_RELEASE_PROFILE_PINS[runtime_provider_id]["provider_channel"]
        ),
        launch_config_digest=(
            "sha256:"
            + str(
                _ACP_RELEASE_PROFILE_PINS[
                    runtime_provider_id
                ]["safe_launch_digest"]
            )
        ),
        source_paths=(
            "mac/companiond/providers/acp.py",
            "mac/companiond/providers/acp_profiles.py",
        ),
    )
    for runtime_provider_id in _ACP_RELEASE_RUNTIME_PROVIDER_IDS
)

_RELEASE_MEMBERSHIP_SPECS = (
    _DIRECT_RELEASE_MEMBERSHIP_SPECS
    + _ACP_RELEASE_MEMBERSHIP_SPECS
)

_RELEASE_PROVIDER_IDS = frozenset(
    str(spec["runtime_provider_id"]) for spec in _RELEASE_MEMBERSHIP_SPECS
)
if len(_RELEASE_PROVIDER_IDS) != len(_RELEASE_MEMBERSHIP_SPECS):
    raise OperationCatalogError("release membership runtime provider ids must be unique")

_RELEASE_RUNTIME_ID_BY_PROVIDER_ID: dict[str, str] = {}
for _release_spec in _RELEASE_MEMBERSHIP_SPECS:
    _runtime_provider_id = str(_release_spec["runtime_provider_id"])
    for _provider_id in (
        _runtime_provider_id,
        str(_release_spec["map_provider_id"]),
    ):
        _prior_runtime_provider_id = _RELEASE_RUNTIME_ID_BY_PROVIDER_ID.setdefault(
            _provider_id,
            _runtime_provider_id,
        )
        if _prior_runtime_provider_id != _runtime_provider_id:
            raise OperationCatalogError(
                f"release provider alias is ambiguous: {_provider_id}"
            )
    for _release_capability in _release_spec["capabilities"]:
        for _released_operation_id in _release_capability["operation_ids"]:
            REVIEWED_OPERATION_CATALOG.require(str(_released_operation_id))


def _release_runtime_provider_id(provider_id: str) -> str | None:
    if not isinstance(provider_id, str):
        return None
    return _RELEASE_RUNTIME_ID_BY_PROVIDER_ID.get(provider_id)


def provider_has_release_membership(provider_id: str) -> bool:
    """Return whether a runtime or capability-map provider has reviewed membership."""
    return _release_runtime_provider_id(provider_id) is not None


def provider_binding_has_release_membership(
    provider_id: str,
    provider_version: str,
    provider_channel: str,
) -> bool:
    """Return whether an exact runtime provider binding belongs to this release."""
    runtime_provider_id = _release_runtime_provider_id(provider_id)
    if runtime_provider_id is None or runtime_provider_id != provider_id:
        return False
    if runtime_provider_id == "omp":
        return (
            provider_channel == "stable"
            and re.fullmatch(
                r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)",
                provider_version,
            ) is not None
        )
    return any(
        spec["runtime_provider_id"] == runtime_provider_id
        and spec["provider_version"] == provider_version
        and spec["provider_channel"] == provider_channel
        for spec in _RELEASE_MEMBERSHIP_SPECS
    )


def released_operation_ids_for_provider(provider_id: str) -> frozenset[str]:
    """Return the exact reviewed union for a runtime or capability-map provider."""
    runtime_provider_id = _release_runtime_provider_id(provider_id)
    if runtime_provider_id is None:
        return frozenset()
    released: set[str] = set()
    for spec in _RELEASE_MEMBERSHIP_SPECS:
        if spec["runtime_provider_id"] != runtime_provider_id:
            continue
        for capability in spec["capabilities"]:
            released.update(str(item) for item in capability["operation_ids"])
    return frozenset(released)


def operation_manifest_payload(
    catalog: OperationCatalog = REVIEWED_OPERATION_CATALOG,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "operations": [definition.to_payload() for definition in catalog],
    }


def release_operation_manifest_payload(
    *,
    source_revision: str,
    source_root: str | Path,
    catalog: OperationCatalog = REVIEWED_OPERATION_CATALOG,
) -> dict[str, Any]:
    """Bind exact release membership to its source revision and implementation bytes."""
    if re.fullmatch(r"[0-9a-f]{40,64}", source_revision) is None:
        raise OperationCatalogError("release source_revision must be a lowercase git object id")
    root = Path(source_root)
    memberships: list[dict[str, Any]] = []
    for spec in _RELEASE_MEMBERSHIP_SPECS:
        source_bindings: list[dict[str, str]] = []
        for relative in spec["source_paths"]:
            path = root / relative
            if path.is_symlink() or not path.is_file():
                raise OperationCatalogError(
                    f"release membership source is missing or unsafe: {relative}"
                )
            source_bindings.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        membership = {
            key: json.loads(json.dumps(value))
            for key, value in spec.items()
            if key != "source_paths"
        }
        membership["source_bindings"] = source_bindings
        memberships.append(membership)
    payload = operation_manifest_payload(catalog)
    return {
        "schema_version": 2,
        "source_revision": source_revision,
        "operations": payload["operations"],
        "release_memberships": memberships,
    }


def validate_release_operation_manifest(
    payload: Any,
    *,
    source_root: str | Path,
) -> list[str]:
    """Return exact catalog, membership, revision, and source-binding errors."""
    if not isinstance(payload, Mapping):
        return ["reviewed release operation manifest must be an object"]
    revision = payload.get("source_revision")
    if not isinstance(revision, str):
        return ["reviewed release operation manifest source_revision is missing"]
    try:
        expected = release_operation_manifest_payload(
            source_revision=revision,
            source_root=source_root,
        )
    except (OSError, OperationCatalogError) as exc:
        return [str(exc)]
    if payload != expected:
        return [
            "reviewed release operation manifest does not exactly match the "
            "packaged catalog, capability membership, and source bindings"
        ]
    return []
