"""Durable proof-carrying session-control orchestration.

This module owns protocol sequencing, not HTTP framing or Pairling authentication.
Callers supply an already authenticated transport peer and an exact managed-session
resolver. Provider execution always passes through :class:`ProviderControlService`.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from managed_provider_sessions import (
    ManagedProviderSessionManager,
    ManagedSessionControlStateError,
)
from protocols.session_control import (
    ProtocolValidationError,
    canonical_json_bytes,
    digest_value,
    expected_binding_digest,
    load_schema,
    negotiate as negotiate_protocol,
    parse_message,
    transport_profile,
    validate_message,
    with_integrity,
)
from provider_control_service import (
    PreparedProviderOperation,
    ProviderControlExecution,
    ProviderControlService,
    ProviderControlServiceError,
)
from providers.capability_graph import CapabilityGraphCatalog, CapabilityGraphError
from providers.controls import OperationResultStatus, ProviderOperationCorrelation
from session_control_trust import (
    PinnedP256TrustStore,
    SessionControlAuthority,
    SessionControlTrustError,
)


ProofVerifier = Callable[[bytes, Mapping[str, Any]], bool]
SignatureVerifier = Callable[[bytes, Mapping[str, Any]], bool]
TargetResolver = Callable[[str], Mapping[str, Any] | None]


@dataclass(frozen=True)
class SessionControlPeer:
    principal_id: str
    granted_scopes: frozenset[str]
    source_device_id: str | None = None
    source_install_id: str | None = None
    proof_verifier: ProofVerifier | None = None
    signature_verifier: SignatureVerifier | None = None
    attachment_resolver: Any = None


class SessionControlGatewayError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int,
        error_class: str = "protocol",
    ) -> None:
        super().__init__(message)
        self.code = str(code)
        self.message = str(message)[:1024]
        self.status = int(status)
        self.error_class = str(error_class)


@dataclass(frozen=True)
class _SnapshotProjection:
    status: dict[str, Any]
    binding: dict[str, Any]
    operations: tuple[dict[str, Any], ...]
    contracts: dict[str, Any]


class SessionControlGateway:
    def __init__(
        self,
        *,
        manager: ManagedProviderSessionManager,
        service: ProviderControlService,
        authority: SessionControlAuthority,
        target_resolver: TargetResolver,
        runtime_revision: str,
        schema: Mapping[str, Any] | None = None,
        graph: CapabilityGraphCatalog | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        revision = str(runtime_revision or "")
        if not revision or len(revision) > 256 or any(
            character in revision for character in "\r\n\0"
        ):
            raise SessionControlGatewayError(
                "invalid_runtime_revision",
                "session-control runtime revision is invalid",
                status=500,
            )
        self.manager = manager
        self.store = manager.store
        self.service = service
        self.authority = authority
        self.target_resolver = target_resolver
        self.runtime_revision = revision
        self.schema = deepcopy(dict(schema)) if schema is not None else load_schema()
        self.schema_digest = digest_value(self.schema)
        self.graph = graph or CapabilityGraphCatalog.from_path()
        self.clock = clock
        self.profile = transport_profile("https-json", schema=self.schema)
        self._server_trust = PinnedP256TrustStore([authority.public_key])
        try:
            self.store.register_protocol_authority_key(
                authority.public_key.to_payload(),
                now=self._now(),
            )
        except ManagedSessionControlStateError as exc:
            raise SessionControlGatewayError(
                "authority_continuity_invalid",
                str(exc),
                status=503,
                error_class="authority",
            ) from exc

    def _now(self, value: float | None = None) -> float:
        candidate = self.clock() if value is None else value
        if isinstance(candidate, bool) or not isinstance(candidate, (int, float)):
            raise SessionControlGatewayError(
                "invalid_clock",
                "session-control clock is invalid",
                status=500,
            )
        result = float(candidate)
        if result != result or result in {float("inf"), float("-inf")}:
            raise SessionControlGatewayError(
                "invalid_clock",
                "session-control clock is invalid",
                status=500,
            )
        return result

    @staticmethod
    def _timestamp(value: float) -> str:
        return (
            datetime.fromtimestamp(value, timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )

    @staticmethod
    def _timestamp_value(value: str) -> float:
        try:
            if not isinstance(value, str) or not value.endswith("Z"):
                raise ValueError
            parsed = datetime.fromisoformat(value[:-1] + "+00:00")
            if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
                raise ValueError
            return parsed.timestamp()
        except (TypeError, ValueError) as exc:
            raise SessionControlGatewayError(
                "invalid_message",
                "protocol timestamp is invalid",
                status=400,
            ) from exc

    @staticmethod
    def _new_id(prefix: str) -> str:
        return prefix + secrets.token_urlsafe(18)

    @staticmethod
    def _stable_id(prefix: str, *parts: Any) -> str:
        material = "\0".join(map(str, parts)).encode("utf-8")
        return prefix + hashlib.sha256(material).hexdigest()[:32]

    @staticmethod
    def _validate_peer(peer: SessionControlPeer) -> None:
        principal = str(peer.principal_id or "")
        if (
            not principal
            or len(principal) > 256
            or any(character in principal for character in "\r\n\0")
        ):
            raise SessionControlGatewayError(
                "authenticated_principal_invalid",
                "authenticated transport principal is invalid",
                status=401,
                error_class="authority",
            )
        if not isinstance(peer.granted_scopes, frozenset) or not all(
            isinstance(scope, str) and scope for scope in peer.granted_scopes
        ):
            raise SessionControlGatewayError(
                "authenticated_scope_invalid",
                "authenticated transport scopes are invalid",
                status=401,
                error_class="authority",
            )

    @staticmethod
    def _parse(payload: Mapping[str, Any] | str | bytes) -> dict[str, Any]:
        try:
            if isinstance(payload, (str, bytes)):
                return parse_message(payload)
            if not isinstance(payload, Mapping):
                raise ProtocolValidationError("protocol message must be an object")
            canonical_json_bytes(payload)
            return deepcopy(dict(payload))
        except ProtocolValidationError as exc:
            raise SessionControlGatewayError(
                "invalid_message",
                str(exc),
                status=400,
            ) from exc

    def _proof_verifier(self, peer: SessionControlPeer) -> ProofVerifier:
        def verify(canonical: bytes, token: Mapping[str, Any]) -> bool:
            if self._server_trust.verify_proof_token(canonical, token):
                return True
            if peer.proof_verifier is None:
                return False
            try:
                return bool(peer.proof_verifier(canonical, token))
            except Exception:
                return False

        return verify

    def _context(
        self,
        context_id: str,
        peer: SessionControlPeer,
        *,
        now: float,
    ) -> dict[str, Any]:
        self._validate_peer(peer)
        try:
            context = self.store.protocol_negotiation(
                context_id,
                principal_id=peer.principal_id,
                now=now,
            )
        except ManagedSessionControlStateError as exc:
            raise SessionControlGatewayError(
                "stale_negotiation",
                str(exc),
                status=409,
                error_class="freshness",
            ) from exc
        if (
            context.get("schema_digest") != self.schema_digest
            or context.get("runtime_revision") != self.runtime_revision
            or context.get("transport_profile") != "https-json"
        ):
            raise SessionControlGatewayError(
                "stale_negotiation",
                "negotiation context no longer matches this runtime",
                status=409,
                error_class="freshness",
            )
        return context

    def _validate_inbound(
        self,
        message: Mapping[str, Any],
        peer: SessionControlPeer,
        *,
        now: float,
        context: Mapping[str, Any] | None = None,
        negotiation_request: Mapping[str, Any] | None = None,
        execution_request: Mapping[str, Any] | None = None,
        recovery_request: Mapping[str, Any] | None = None,
    ) -> None:
        self._validate_peer(peer)
        try:
            validate_message(
                message,
                schema=self.schema,
                now=datetime.fromtimestamp(now, timezone.utc),
                enabled_extensions=frozenset(
                    context.get("extensions", ()) if context else ()
                ),
                negotiation_context_id=(
                    str(context["context_id"]) if context is not None else None
                ),
                authenticated_principal_id=peer.principal_id,
                authenticated_transport=True,
                authenticated_proof_boundary=False,
                signature_verifier=peer.signature_verifier,
                proof_verifier=self._proof_verifier(peer),
                negotiation_request=negotiation_request,
                execution_request=execution_request,
                recovery_request=recovery_request,
            )
        except ProtocolValidationError as exc:
            raise SessionControlGatewayError(
                "invalid_message",
                str(exc),
                status=400,
            ) from exc

    def _signed_message(
        self,
        kind: str,
        body: Mapping[str, Any],
        *,
        context_id: str | None,
        version: Mapping[str, Any],
        now: float,
        enabled_extensions: tuple[str, ...] = (),
        negotiation_request: Mapping[str, Any] | None = None,
        execution_request: Mapping[str, Any] | None = None,
        recovery_request: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        unsigned = {
            "protocol": "proof-carrying-session-control",
            "protocol_version": {
                "major": int(version["major"]),
                "minor": int(version["minor"]),
            },
            "message_id": self._new_id("msg_"),
            "negotiation_context_id": context_id,
            "sent_at": self._timestamp(now),
            "kind": kind,
            "body": deepcopy(dict(body)),
            "extensions": [],
        }
        signature = self.authority.envelope_signature(
            canonical_json_bytes(unsigned)
        )
        message = with_integrity(unsigned, signature=signature)
        try:
            validate_message(
                message,
                schema=self.schema,
                now=datetime.fromtimestamp(now, timezone.utc),
                enabled_extensions=frozenset(enabled_extensions),
                negotiation_context_id=context_id,
                signature_verifier=self._server_trust.verify_envelope_signature,
                proof_verifier=self._server_trust.verify_proof_token,
                negotiation_request=negotiation_request,
                execution_request=execution_request,
                recovery_request=recovery_request,
            )
        except ProtocolValidationError as exc:
            raise SessionControlGatewayError(
                "invalid_server_message",
                str(exc),
                status=500,
            ) from exc
        return message

    def negotiate(
        self,
        payload: Mapping[str, Any] | str | bytes,
        peer: SessionControlPeer,
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        observed_at = self._now(now)
        message = self._parse(payload)
        self._validate_inbound(message, peer, now=observed_at)
        if message.get("kind") != "negotiate.request":
            raise SessionControlGatewayError(
                "invalid_message",
                "negotiation route requires negotiate.request",
                status=400,
            )
        request_body = dict(message["body"])
        request_digest = digest_value(message)
        context_id = self._stable_id(
            "neg_",
            self.authority.key_id,
            peer.principal_id,
            request_body["request_id"],
            request_digest,
        )
        try:
            existing = self.store.protocol_negotiation(
                context_id,
                principal_id=peer.principal_id,
                now=observed_at,
            )
        except ManagedSessionControlStateError as exc:
            if "unknown" not in str(exc):
                raise SessionControlGatewayError(
                    "stale_negotiation",
                    str(exc),
                    status=409,
                    error_class="freshness",
                ) from exc
        else:
            if existing.get("request_digest") != request_digest:
                raise SessionControlGatewayError(
                    "negotiation_identity_conflict",
                    "negotiation request identity is already bound",
                    status=409,
                    error_class="authority",
                )
            try:
                return json.loads(str(existing["response_json"]))
            except (TypeError, ValueError) as exc:
                raise SessionControlGatewayError(
                    "persisted_protocol_state_invalid",
                    "persisted negotiation response is invalid",
                    status=500,
                ) from exc

        response_body = negotiate_protocol(
            request_body,
            schema=self.schema,
            negotiation_context_id=context_id,
            supported_transport_profiles=("https-json",),
        )
        accepted = bool(response_body["accepted"])
        selected_context = context_id if accepted else None
        version = (
            response_body["selected_version"]
            if accepted
            else self.schema["x-protocol-semantics"]["current_version"]
        )
        response = self._signed_message(
            "negotiate.response",
            response_body,
            context_id=selected_context,
            version=version,
            now=observed_at,
            enabled_extensions=tuple(
                response_body.get("enabled_extensions", ())
            ),
            negotiation_request=request_body,
        )
        if accepted:
            ttl = int(
                self.profile["limits"]["negotiation_context_ttl_seconds"]
            )
            try:
                self.store.create_protocol_negotiation(
                    context_id=context_id,
                    principal_id=peer.principal_id,
                    request_id=str(request_body["request_id"]),
                    version_major=int(version["major"]),
                    version_minor=int(version["minor"]),
                    transport_profile="https-json",
                    extensions=tuple(response_body["enabled_extensions"]),
                    schema_digest=self.schema_digest,
                    runtime_revision=self.runtime_revision,
                    request_record=canonical_json_bytes(message),
                    response_record=canonical_json_bytes(response),
                    expires_at=observed_at + ttl,
                    now=observed_at,
                )
            except ManagedSessionControlStateError as exc:
                raise SessionControlGatewayError(
                    "negotiation_identity_conflict",
                    str(exc),
                    status=409,
                    error_class="authority",
                ) from exc
        return response

    def _target(self, protocol_session_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        row = self.store.get_by_protocol_session_id(protocol_session_id)
        if not isinstance(row, dict):
            raise SessionControlGatewayError(
                "wrong_session",
                "managed protocol session is unknown",
                status=404,
                error_class="ownership",
            )
        target = self.target_resolver(str(row["session_id"]))
        if not isinstance(target, Mapping):
            raise SessionControlGatewayError(
                "ownership_required",
                "managed session target is unavailable",
                status=409,
                error_class="ownership",
            )
        result = dict(target)
        truth = result.get("session_truth")
        manager = result.get("manager")
        if (
            not result.get("managed")
            or manager is not self.manager
            or not isinstance(truth, Mapping)
            or truth.get("protocol_session_id") != protocol_session_id
            or truth.get("session_id") != row.get("session_id")
        ):
            raise SessionControlGatewayError(
                "ownership_required",
                "protocol session is not owned by the durable manager",
                status=409,
                error_class="ownership",
            )
        return result, row

    def _project_snapshot(
        self,
        target: Mapping[str, Any],
        *,
        now: float,
    ) -> _SnapshotProjection:
        try:
            status = self.service.snapshot_status(target, now=now)
        except ProviderControlServiceError as exc:
            raise self._service_gateway_error(exc) from exc
        if status.get("capability_graph_digest") != self.graph.graph_digest:
            raise SessionControlGatewayError(
                "semantic_contract_stale",
                "capability graph identity changed",
                status=409,
                error_class="authority",
            )
        operations: list[dict[str, Any]] = []
        contracts: dict[str, Any] = {}
        binding_base: dict[str, Any] | None = None
        for attestation in status.get("advertised_operations", ()):
            if not isinstance(attestation, Mapping):
                raise SessionControlGatewayError(
                    "semantic_contract_stale",
                    "provider operation attestation is invalid",
                    status=409,
                    error_class="authority",
                )
            operation_id = str(attestation.get("operation_id") or "")
            try:
                contract = self.graph.require_operation(
                    str(status["provider_id"]),
                    str(status["provider_version"]),
                    str(status["provider_channel"]),
                    operation_id,
                )
            except CapabilityGraphError as exc:
                raise SessionControlGatewayError(
                    "semantic_contract_stale",
                    str(exc),
                    status=409,
                    error_class="authority",
                ) from exc
            if (
                attestation.get("implementation_operation_id")
                != contract.implementation_operation_id
                or attestation.get("semantic_digest")
                != contract.semantic_digest
                or tuple(attestation.get("proofs", ()))
                != contract.runtime_proofs_required
            ):
                raise SessionControlGatewayError(
                    "semantic_contract_stale",
                    "provider operation semantic attestation changed",
                    status=409,
                    error_class="authority",
                )
            candidate_binding = contract.protocol_binding_payload(
                self.graph.graph_digest
            )
            if binding_base is None:
                binding_base = candidate_binding
            elif binding_base != candidate_binding:
                raise SessionControlGatewayError(
                    "semantic_contract_stale",
                    "snapshot operations span incompatible implementations",
                    status=409,
                    error_class="authority",
                )
            definition = self.service.definition(operation_id)
            risk = str(getattr(definition.risk, "value", definition.risk))
            lifecycle = str(
                getattr(definition.lifecycle, "value", definition.lifecycle)
            )
            confirmation = str(
                getattr(
                    definition.confirmation_requirement,
                    "value",
                    definition.confirmation_requirement,
                )
            )
            resource_proof = str(
                getattr(
                    definition.resource_proof_kind,
                    "value",
                    definition.resource_proof_kind,
                )
            )
            operations.append({
                "operation_id": operation_id,
                "implementation_operation_id": contract.implementation_operation_id,
                "semantic_digest": contract.semantic_digest,
                "authority_scope": (
                    "provider" if lifecycle == "provider_wide" else "session"
                ),
                "mutation": "read" if risk == "read" else "mutation",
                "confirmation": confirmation,
                "lease_scope": "input" if resource_proof == "input_lease" else None,
                "retry": contract.retry_payload(),
                "required_proof_kinds": list(
                    contract.runtime_proofs_required
                ),
            })
            contracts[operation_id] = contract
        if binding_base is None:
            raise SessionControlGatewayError(
                "operation_unsupported",
                "live session advertises no reviewed protocol operations",
                status=409,
                error_class="provider",
            )
        binding = dict(binding_base)
        binding["binding_digest"] = expected_binding_digest(binding)
        return _SnapshotProjection(
            status=dict(status),
            binding=binding,
            operations=tuple(operations),
            contracts=contracts,
        )

    def _make_proof(
        self,
        proof_kind: str,
        subject: Any,
        *,
        binding_digest: str,
        session_id: str | None,
        generation: int | None,
        issued_at: float,
        expires_at: float,
        proof_id: str | None = None,
        authority_class: str = "control_manager",
        authority_id: str | None = None,
    ) -> dict[str, Any]:
        if expires_at <= issued_at:
            raise SessionControlGatewayError(
                "proof_expired",
                "proof validity window is empty",
                status=409,
                error_class="freshness",
            )
        proof = {
            "proof_id": proof_id or self._new_id("prf_"),
            "proof_kind": proof_kind,
            "authority": {
                "authority_id": authority_id or self.authority.key_id,
                "authority_class": authority_class,
            },
            "subject_digest": digest_value(subject),
            "binding_digest": binding_digest,
            "session_id": session_id,
            "generation": generation,
            "issued_at": self._timestamp(issued_at),
            "expires_at": self._timestamp(expires_at),
            "claims_digest": digest_value({
                "proof_kind": proof_kind,
                "subject": subject,
            }),
        }
        proof["token"] = self.authority.proof_token(
            canonical_json_bytes(proof)
        )
        return proof

    def _current_typestate(self, protocol_session_id: str) -> dict[str, Any]:
        try:
            row = self.store.protocol_typestate(protocol_session_id)
        except ManagedSessionControlStateError as exc:
            raise SessionControlGatewayError(
                "wrong_session",
                str(exc),
                status=404,
                error_class="ownership",
            ) from exc
        state = row.get("protocol_state")
        version = int(row.get("protocol_state_version") or 0)
        terminal = bool(row.get("protocol_terminal"))
        if state is None:
            return {"state": None, "state_version": 0, "terminal": False}
        return {
            "state": str(state),
            "state_version": version,
            "terminal": terminal,
        }

    def _append_event(
        self,
        *,
        protocol_session_id: str,
        generation: int,
        binding_digest: str,
        context: Mapping[str, Any],
        event_type: str,
        after_state: str,
        now: float,
        data: Mapping[str, Any] | None = None,
        action_id: str | None = None,
        provider_operation_id: str | None = None,
        owner_id: str | None = None,
        ownership_epoch: int | None = None,
        complete_action_state: str | None = None,
        complete_action_body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        durable = self.store.protocol_typestate(protocol_session_id)
        before_state = durable.get("protocol_state")
        before_version = int(durable.get("protocol_state_version") or 0)
        sequence = int(durable.get("protocol_last_event_sequence")) + 1
        stream_id = durable.get("protocol_event_stream_id") or (
            "pairling.session_control."
            + hashlib.sha256(protocol_session_id.encode("utf-8")).hexdigest()[:24]
        )
        prior_digest = durable.get("protocol_last_event_digest")
        before = (
            None
            if before_state is None
            else {
                "state": str(before_state),
                "state_version": before_version,
                "terminal": bool(durable.get("protocol_terminal")),
            }
        )
        after = {
            "state": after_state,
            "state_version": before_version + 1,
            "terminal": after_state == "terminated",
        }
        event_id = self._stable_id(
            "evt_",
            protocol_session_id,
            generation,
            sequence,
            event_type,
            action_id or "",
        )
        event = {
            "event_id": event_id,
            "event_type": event_type,
            "binding_digest": binding_digest,
            "session_id": protocol_session_id,
            "generation": generation,
            "cursor": {
                "stream_id": stream_id,
                "generation": generation,
                "sequence": sequence,
                "previous_event_digest": prior_digest,
            },
            "observed_at": self._timestamp(now),
            "before": before,
            "after": after,
            "correlation": (
                None
                if action_id is None
                else {
                    "action_id": action_id,
                    "provider_operation_id": provider_operation_id,
                }
            ),
            "evidence": [],
            "data": deepcopy(dict(data or {})),
        }
        subject = {key: value for key, value in event.items() if key != "evidence"}
        proof_expiry = max(now + 1.0, float(context["expires_at"]))
        proof_kinds = list(
            self.schema["x-protocol-semantics"]["event_proof_requirements"][
                event_type
            ]
        )
        if after["terminal"] and "terminality_observed" not in proof_kinds:
            proof_kinds.append("terminality_observed")
        event["evidence"] = [
            self._make_proof(
                str(kind),
                subject,
                binding_digest=binding_digest,
                session_id=protocol_session_id,
                generation=generation,
                issued_at=now,
                expires_at=proof_expiry,
            )
            for kind in proof_kinds
        ]
        self._signed_message(
            "event.publish",
            {"event": event},
            context_id=str(context["context_id"]),
            version={
                "major": int(context["version_major"]),
                "minor": int(context["version_minor"]),
            },
            now=now,
            enabled_extensions=tuple(context.get("extensions", ())),
        )
        try:
            self.store.append_protocol_event(
                event_id=event_id,
                protocol_session_id=protocol_session_id,
                generation=generation,
                stream_id=str(stream_id),
                sequence=sequence,
                previous_event_digest=prior_digest,
                event_type=event_type,
                binding_digest=binding_digest,
                before_state=(str(before_state) if before_state is not None else None),
                before_state_version=(before_version if before_state is not None else None),
                after_state=after_state,
                after_state_version=before_version + 1,
                terminal=after["terminal"],
                event_record=canonical_json_bytes(event),
                observed_at=now,
                action_id=action_id,
                owner_id=owner_id,
                ownership_epoch=ownership_epoch,
                complete_action_state=complete_action_state,
                complete_action_record=(
                    canonical_json_bytes(complete_action_body)
                    if complete_action_body is not None
                    else None
                ),
                now=now,
            )
        except ManagedSessionControlStateError as exc:
            raise SessionControlGatewayError(
                "cursor_gap",
                str(exc),
                status=409,
                error_class="recovery",
            ) from exc
        return event

    def _ensure_owned_state(
        self,
        *,
        protocol_session_id: str,
        generation: int,
        binding_digest: str,
        target: Mapping[str, Any],
        context: Mapping[str, Any],
        now: float,
    ) -> dict[str, Any]:
        state = self._current_typestate(protocol_session_id)
        if state["state"] is None:
            self._append_event(
                protocol_session_id=protocol_session_id,
                generation=generation,
                binding_digest=binding_digest,
                context=context,
                event_type="session.observed",
                after_state="observed",
                now=now,
                data={},
            )
            state = self._current_typestate(protocol_session_id)
        if state["state"] in {"observed", "ownership_lost"}:
            durable = self.store.protocol_typestate(protocol_session_id)
            epoch = int(durable.get("protocol_ownership_epoch") or 0) + 1
            self._append_event(
                protocol_session_id=protocol_session_id,
                generation=generation,
                binding_digest=binding_digest,
                context=context,
                event_type="ownership.acquired",
                after_state="owned_idle",
                now=now,
                data={},
                owner_id=self.authority.key_id,
                ownership_epoch=epoch,
            )
            state = self._current_typestate(protocol_session_id)
        durable = self.store.protocol_typestate(protocol_session_id)
        if (
            state["state"] in {
                "owned_idle",
                "owned_running",
                "owned_waiting",
                "mutation_pending",
                "outcome_unknown",
            }
            and durable.get("protocol_owner_id") != self.authority.key_id
        ):
            raise SessionControlGatewayError(
                "ownership_required",
                "durable session owner does not match this authority",
                status=409,
                error_class="ownership",
            )
        turn_state = str(
            target.get("session_truth", {}).get("turn_state") or ""
        )
        if state["state"] == "owned_idle" and turn_state == "running":
            self._append_event(
                protocol_session_id=protocol_session_id,
                generation=generation,
                binding_digest=binding_digest,
                context=context,
                event_type="turn.started",
                after_state="owned_running",
                now=now,
                data={},
            )
            state = self._current_typestate(protocol_session_id)
        return state

    def _lease_for_scope(
        self,
        *,
        scope: str,
        protocol_session_id: str,
        generation: int,
        binding_digest: str,
        epoch: int,
        peer: SessionControlPeer,
        context: Mapping[str, Any],
        issued_at: float,
        expires_at: float,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        active = self.store.active_protocol_leases(
            protocol_session_id,
            now=issued_at,
        )
        matching: dict[str, Any] | None = None
        for row in active:
            if row.get("scope") != scope:
                continue
            stale = (
                int(row.get("generation") or 0) != generation
                or row.get("binding_digest") != binding_digest
                or int(row.get("epoch") or 0) != epoch
            )
            if stale:
                self.store.revoke_protocol_lease(
                    str(row["lease_id"]),
                    principal_id=str(row["principal_id"]),
                    now=issued_at,
                )
                continue
            if row.get("principal_id") != peer.principal_id:
                raise SessionControlGatewayError(
                    "lease_conflict",
                    f"{scope} lease is held by another authenticated principal",
                    status=409,
                    error_class="ownership",
                )
            matching = row
        if matching is None:
            proof_id = self._new_id("prf_")
            lease = {
                "lease_id": self._new_id("lea_"),
                "scope": scope,
                "holder_id": peer.principal_id,
                "binding_digest": binding_digest,
                "session_id": protocol_session_id,
                "generation": generation,
                "epoch": epoch,
                "issued_at": self._timestamp(issued_at),
                "expires_at": self._timestamp(expires_at),
                "proof_id": proof_id,
            }
            self.store.issue_protocol_lease(
                lease_id=lease["lease_id"],
                protocol_session_id=protocol_session_id,
                context_id=str(context["context_id"]),
                principal_id=peer.principal_id,
                scope=scope,
                generation=generation,
                binding_digest=binding_digest,
                epoch=epoch,
                lease_record=canonical_json_bytes(lease),
                issued_at=issued_at,
                expires_at=expires_at,
                now=issued_at,
            )
        else:
            try:
                lease = json.loads(str(matching["lease_json"]))
            except (TypeError, ValueError) as exc:
                raise SessionControlGatewayError(
                    "persisted_protocol_state_invalid",
                    "persisted protocol lease is invalid",
                    status=500,
                ) from exc
            proof_id = str(lease["proof_id"])
            issued_at = self._timestamp_value(str(lease["issued_at"]))
            expires_at = self._timestamp_value(str(lease["expires_at"]))
        subject = {key: value for key, value in lease.items() if key != "proof_id"}
        proof = self._make_proof(
            "lease_active",
            subject,
            binding_digest=binding_digest,
            session_id=protocol_session_id,
            generation=generation,
            issued_at=issued_at,
            expires_at=expires_at,
            proof_id=proof_id,
        )
        return lease, proof

    def snapshot(
        self,
        protocol_session_id: str,
        context_id: str,
        peer: SessionControlPeer,
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        observed_at = self._now(now)
        context = self._context(context_id, peer, now=observed_at)
        target, row = self._target(protocol_session_id)
        projection = self._project_snapshot(target, now=observed_at)
        generation = int(projection.status["capability_generation"])
        if generation != int(row["capability_generation"]):
            raise SessionControlGatewayError(
                "stale_snapshot",
                "managed session generation changed",
                status=409,
                error_class="freshness",
            )
        binding_digest = str(projection.binding["binding_digest"])
        self._ensure_owned_state(
            protocol_session_id=protocol_session_id,
            generation=generation,
            binding_digest=binding_digest,
            target=target,
            context=context,
            now=observed_at,
        )
        durable = self.store.protocol_typestate(protocol_session_id)
        state = {
            "state": str(durable["protocol_state"]),
            "state_version": int(durable["protocol_state_version"]),
            "terminal": bool(durable["protocol_terminal"]),
        }
        ownership = {
            "state": "owned" if durable.get("protocol_owner_id") else "unowned",
            "owner_id": durable.get("protocol_owner_id"),
            "epoch": int(durable.get("protocol_ownership_epoch") or 0),
        }
        expiry = min(
            float(projection.status["valid_until"]),
            float(context["expires_at"]),
            observed_at + 300.0,
        )
        if expiry <= observed_at:
            raise SessionControlGatewayError(
                "stale_snapshot",
                "live provider snapshot expired before publication",
                status=409,
                error_class="freshness",
            )
        operations = [
            operation
            for operation in projection.operations
            if not (state["terminal"] and operation["mutation"] == "mutation")
        ]
        leases: list[dict[str, Any]] = []
        lease_proofs: list[dict[str, Any]] = []
        for scope in sorted({
            str(operation["lease_scope"])
            for operation in operations
            if operation["lease_scope"] is not None
        }):
            lease, proof = self._lease_for_scope(
                scope=scope,
                protocol_session_id=protocol_session_id,
                generation=generation,
                binding_digest=binding_digest,
                epoch=ownership["epoch"],
                peer=peer,
                context=context,
                issued_at=observed_at,
                expires_at=expiry,
            )
            expiry = min(expiry, self._timestamp_value(lease["expires_at"]))
            leases.append(lease)
            lease_proofs.append(proof)
        proof_subjects: dict[str, list[str]] = {}
        for operation in operations:
            for kind in operation["required_proof_kinds"]:
                proof_subjects.setdefault(str(kind), []).append(
                    str(operation["operation_id"])
                )
        proofs = [
            self._make_proof(
                kind,
                {
                    "proof_kind": kind,
                    "binding_digest": binding_digest,
                    "session_id": protocol_session_id,
                    "generation": generation,
                    "operation_ids": sorted(operation_ids),
                },
                binding_digest=binding_digest,
                session_id=protocol_session_id,
                generation=generation,
                issued_at=observed_at,
                expires_at=expiry,
            )
            for kind, operation_ids in sorted(proof_subjects.items())
        ]
        proofs.extend(lease_proofs)
        sequence = int(durable["protocol_last_event_sequence"])
        cursor = (
            None
            if sequence < 0
            else {
                "stream_id": str(durable["protocol_event_stream_id"]),
                "generation": generation,
                "sequence": sequence,
                "previous_event_digest": durable["protocol_last_event_digest"],
            }
        )
        snapshot = {
            "snapshot_id": self._new_id("snp_"),
            "issued_at": self._timestamp(observed_at),
            "expires_at": self._timestamp(expiry),
            "binding": projection.binding,
            "session": {
                "session_id": protocol_session_id,
                "generation": generation,
                "binding_digest": binding_digest,
                "ownership": ownership,
                "typestate": state,
            },
            "operations": operations,
            "proofs": proofs,
            "leases": leases,
            "cursor": cursor,
        }
        message = self._signed_message(
            "snapshot.publish",
            {"snapshot": snapshot},
            context_id=context_id,
            version={
                "major": int(context["version_major"]),
                "minor": int(context["version_minor"]),
            },
            now=observed_at,
            enabled_extensions=tuple(context.get("extensions", ())),
        )
        try:
            self.store.publish_protocol_snapshot(
                snapshot_id=str(snapshot["snapshot_id"]),
                protocol_session_id=protocol_session_id,
                context_id=context_id,
                principal_id=peer.principal_id,
                generation=generation,
                binding_digest=binding_digest,
                snapshot_record=canonical_json_bytes(snapshot),
                issued_at=observed_at,
                expires_at=expiry,
                now=observed_at,
            )
        except ManagedSessionControlStateError as exc:
            raise SessionControlGatewayError(
                "stale_snapshot",
                str(exc),
                status=409,
                error_class="freshness",
            ) from exc
        return message

    def _stored_snapshot(
        self,
        candidate: Mapping[str, Any],
        *,
        confirmation: Mapping[str, Any] | None,
        protocol_session_id: str,
        context: Mapping[str, Any],
        peer: SessionControlPeer,
        now: float,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        row = self.store.protocol_snapshot(str(candidate.get("snapshot_id") or ""))
        if (
            not isinstance(row, dict)
            or row.get("protocol_session_id") != protocol_session_id
            or row.get("context_id") != context.get("context_id")
            or row.get("principal_id") != peer.principal_id
            or now >= float(row.get("expires_at") or 0)
        ):
            raise SessionControlGatewayError(
                "stale_snapshot",
                "request snapshot is not current durable authority",
                status=409,
                error_class="freshness",
            )
        try:
            stored = json.loads(str(row["snapshot_json"]))
        except (TypeError, ValueError) as exc:
            raise SessionControlGatewayError(
                "persisted_protocol_state_invalid",
                "persisted protocol snapshot is invalid",
                status=500,
            ) from exc
        comparable = deepcopy(dict(candidate))
        if confirmation is not None:
            proof_id = str(confirmation["proof_id"])
            matches = [
                proof
                for proof in comparable["proofs"]
                if proof.get("proof_id") == proof_id
            ]
            if len(matches) != 1:
                raise SessionControlGatewayError(
                    "confirmation_mismatch",
                    "confirmation proof is not unique",
                    status=409,
                    error_class="authority",
                )
            proof = matches[0]
            if (
                proof.get("proof_kind") != "confirmation_bound"
                or proof.get("authority", {}).get("authority_class") != "user_agent"
                or proof.get("authority", {}).get("authority_id")
                != peer.principal_id
                or confirmation.get("confirmer_id") != peer.principal_id
            ):
                raise SessionControlGatewayError(
                    "confirmation_mismatch",
                    "confirmation is not bound to the authenticated principal",
                    status=409,
                    error_class="authority",
                )
            comparable["proofs"] = [
                item for item in comparable["proofs"] if item is not proof
            ]
        if canonical_json_bytes(comparable) != canonical_json_bytes(stored):
            raise SessionControlGatewayError(
                "stale_snapshot",
                "embedded snapshot differs from the published authority",
                status=409,
                error_class="freshness",
            )
        return stored, row

    @staticmethod
    def _operation(
        snapshot: Mapping[str, Any],
        identity: Mapping[str, Any],
    ) -> dict[str, Any]:
        matches = [
            operation
            for operation in snapshot["operations"]
            if (
                operation["operation_id"],
                operation["implementation_operation_id"],
                operation["semantic_digest"],
            )
            == (
                identity["operation_id"],
                identity["implementation_operation_id"],
                identity["semantic_digest"],
            )
        ]
        if len(matches) != 1:
            raise SessionControlGatewayError(
                "operation_unsupported",
                "operation is not present in the exact snapshot",
                status=409,
                error_class="authority",
            )
        return dict(matches[0])

    @staticmethod
    def _service_gateway_error(exc: ProviderControlServiceError) -> SessionControlGatewayError:
        code = "provider_rejected"
        error_class = "provider"
        if exc.code in {
            "provider_binding_stale",
            "provider_control_stale",
            "provider_semantic_contract_stale",
        }:
            code, error_class = "semantic_contract_stale", "freshness"
        elif exc.code in {"unknown_operation", "operation_not_available"}:
            code = "operation_unsupported"
        elif exc.code == "confirmation_required":
            code, error_class = "confirmation_required", "authority"
        elif exc.code == "missing_operation_scope":
            code, error_class = "ownership_required", "authority"
        elif exc.code == "action_outcome_unknown":
            code, error_class = "outcome_unknown", "recovery"
        return SessionControlGatewayError(
            code,
            exc.message,
            status=exc.status,
            error_class=error_class,
        )

    @staticmethod
    def _error_payload(
        code: str,
        message: str,
        *,
        error_class: str,
        retryable: bool,
    ) -> dict[str, Any]:
        allowed_codes = {
            "invalid_message",
            "unsupported_version",
            "unsupported_feature",
            "unsupported_transport",
            "unknown_critical_extension",
            "stale_snapshot",
            "wrong_binding",
            "wrong_session",
            "ownership_required",
            "proof_missing",
            "proof_invalid",
            "proof_expired",
            "confirmation_required",
            "confirmation_mismatch",
            "lease_required",
            "lease_conflict",
            "operation_unsupported",
            "semantic_contract_stale",
            "credential_epoch_stale",
            "recovery_required",
            "cursor_gap",
            "terminal_session",
            "provider_rejected",
            "outcome_unknown",
        }
        selected = code if code in allowed_codes else "provider_rejected"
        return {
            "class": error_class if error_class in {
                "protocol",
                "authority",
                "freshness",
                "ownership",
                "provider",
                "transport",
                "recovery",
            } else "provider",
            "code": selected,
            "message": str(message or "operation was rejected")[:1024],
            "retryable": bool(retryable),
        }

    def _response_body(
        self,
        request_body: Mapping[str, Any],
        result: Mapping[str, Any],
        *,
        recovered_at: float | None = None,
    ) -> dict[str, Any]:
        body = {
            "action_id": request_body["action_id"],
            "binding_digest": request_body["binding_digest"],
            "session_id": request_body["session_id"],
            "generation": request_body["generation"],
            "operation": deepcopy(request_body["operation"]),
            "arguments_digest": request_body["arguments_digest"],
        }
        if recovered_at is not None:
            body["recovered_at"] = self._timestamp(recovered_at)
        body["result"] = deepcopy(dict(result))
        return body

    def admit_confirmation(
        self,
        confirmation: Mapping[str, Any],
        proof: Mapping[str, Any],
        *,
        context_id: str,
        peer: SessionControlPeer,
        now: float | None = None,
    ) -> dict[str, Any]:
        observed_at = self._now(now)
        context = self._context(context_id, peer, now=observed_at)
        if not isinstance(confirmation, Mapping) or not isinstance(proof, Mapping):
            raise SessionControlGatewayError(
                "confirmation_mismatch",
                "confirmation authority is malformed",
                status=400,
                error_class="authority",
            )
        confirmation_record = deepcopy(dict(confirmation))
        proof_record = deepcopy(dict(proof))
        try:
            canonical_json_bytes(confirmation_record)
            canonical_json_bytes(proof_record)
            snapshot = self.store.protocol_snapshot(
                str(confirmation_record["snapshot_id"])
            )
            operation = dict(confirmation_record["operation"])
            subject = {
                key: value
                for key, value in confirmation_record.items()
                if key != "proof_id"
            }
            proof_unsigned = {
                key: value for key, value in proof_record.items() if key != "token"
            }
            token = proof_record["token"]
        except (KeyError, TypeError, ProtocolValidationError) as exc:
            raise SessionControlGatewayError(
                "confirmation_mismatch",
                "confirmation authority is malformed",
                status=400,
                error_class="authority",
            ) from exc
        if (
            not isinstance(snapshot, dict)
            or snapshot.get("context_id") != context_id
            or snapshot.get("principal_id") != peer.principal_id
            or snapshot.get("protocol_session_id")
            != confirmation_record.get("session_id")
            or int(snapshot.get("generation") or 0)
            != confirmation_record.get("generation")
            or snapshot.get("binding_digest")
            != confirmation_record.get("binding_digest")
            or confirmation_record.get("confirmer_id") != peer.principal_id
            or proof_record.get("proof_id")
            != confirmation_record.get("proof_id")
            or proof_record.get("proof_kind") != "confirmation_bound"
            or proof_record.get("authority")
            != {
                "authority_id": peer.principal_id,
                "authority_class": "user_agent",
            }
            or proof_record.get("subject_digest") != digest_value(subject)
            or proof_record.get("claims_digest")
            != digest_value(
                {
                    "proof_kind": "confirmation_bound",
                    "subject": subject,
                }
            )
            or proof_record.get("binding_digest")
            != confirmation_record.get("binding_digest")
            or proof_record.get("session_id")
            != confirmation_record.get("session_id")
            or proof_record.get("generation")
            != confirmation_record.get("generation")
            or proof_record.get("issued_at")
            != confirmation_record.get("issued_at")
            or proof_record.get("expires_at")
            != confirmation_record.get("expires_at")
            or not self._proof_verifier(peer)(
                canonical_json_bytes(proof_unsigned),
                token,
            )
        ):
            raise SessionControlGatewayError(
                "confirmation_mismatch",
                "confirmation is not exact authenticated authority",
                status=409,
                error_class="authority",
            )
        try:
            row, _deduped = self.store.issue_protocol_confirmation(
                confirmation_id=str(confirmation_record["confirmation_id"]),
                protocol_session_id=str(confirmation_record["session_id"]),
                context_id=context_id,
                principal_id=peer.principal_id,
                snapshot_id=str(confirmation_record["snapshot_id"]),
                generation=int(confirmation_record["generation"]),
                binding_digest=str(confirmation_record["binding_digest"]),
                operation_id=str(operation["operation_id"]),
                implementation_operation_id=str(
                    operation["implementation_operation_id"]
                ),
                semantic_digest=str(operation["semantic_digest"]),
                arguments_digest=str(confirmation_record["arguments_digest"]),
                confirmation_record=canonical_json_bytes(confirmation_record),
                issued_at=self._timestamp_value(
                    str(confirmation_record["issued_at"])
                ),
                expires_at=self._timestamp_value(
                    str(confirmation_record["expires_at"])
                ),
                now=observed_at,
            )
        except (KeyError, TypeError, ValueError, ManagedSessionControlStateError) as exc:
            raise SessionControlGatewayError(
                "confirmation_mismatch",
                str(exc),
                status=409,
                error_class="authority",
            ) from exc
        return row

    def admit_execute_confirmation(
        self,
        payload: Mapping[str, Any] | str | bytes,
        peer: SessionControlPeer,
        *,
        now: float | None = None,
    ) -> bool:
        observed_at = self._now(now)
        message = self._parse(payload)
        context_id = str(message.get("negotiation_context_id") or "")
        context = self._context(context_id, peer, now=observed_at)
        self._validate_inbound(message, peer, now=observed_at, context=context)
        if message.get("kind") != "execute.request":
            raise SessionControlGatewayError(
                "invalid_message",
                "execute admission requires execute.request",
                status=400,
            )
        confirmation = message["body"].get("confirmation")
        if confirmation is None:
            return False
        matches = [
            proof
            for proof in message["body"]["snapshot"]["proofs"]
            if proof.get("proof_id") == confirmation.get("proof_id")
            and proof.get("proof_kind") == "confirmation_bound"
        ]
        if len(matches) != 1:
            raise SessionControlGatewayError(
                "confirmation_mismatch",
                "execute confirmation lacks one exact authority proof",
                status=409,
                error_class="authority",
            )
        self.admit_confirmation(
            confirmation,
            matches[0],
            context_id=context_id,
            peer=peer,
            now=observed_at,
        )
        return True

    def _consume_confirmation(
        self,
        confirmation: Mapping[str, Any],
        *,
        action_id: str,
        peer: SessionControlPeer,
        now: float,
    ) -> None:
        self.store.consume_protocol_confirmation(
            str(confirmation["confirmation_id"]),
            action_id=action_id,
            principal_id=peer.principal_id,
            now=now,
        )

    def _verify_lease(
        self,
        lease: Mapping[str, Any] | None,
        *,
        operation: Mapping[str, Any],
        protocol_session_id: str,
        peer: SessionControlPeer,
        now: float,
    ) -> None:
        if operation["lease_scope"] is None:
            return
        if lease is None:
            raise SessionControlGatewayError(
                "lease_required",
                "operation requires its exact active lease",
                status=409,
                error_class="ownership",
            )
        rows = self.store.active_protocol_leases(
            protocol_session_id,
            principal_id=peer.principal_id,
            now=now,
        )
        matches = [
            row
            for row in rows
            if row.get("lease_id") == lease.get("lease_id")
            and row.get("scope") == operation["lease_scope"]
        ]
        if len(matches) != 1:
            raise SessionControlGatewayError(
                "lease_conflict",
                "operation lease is no longer active",
                status=409,
                error_class="ownership",
            )
        try:
            persisted = json.loads(str(matches[0]["lease_json"]))
        except (TypeError, ValueError) as exc:
            raise SessionControlGatewayError(
                "persisted_protocol_state_invalid",
                "persisted protocol lease is invalid",
                status=500,
            ) from exc
        if canonical_json_bytes(persisted) != canonical_json_bytes(lease):
            raise SessionControlGatewayError(
                "lease_conflict",
                "operation lease differs from durable authority",
                status=409,
                error_class="ownership",
            )

    def _prepare(
        self,
        target: Mapping[str, Any],
        body: Mapping[str, Any],
        peer: SessionControlPeer,
    ) -> PreparedProviderOperation:
        truth = target["session_truth"]
        request = {
            "operation_id": body["operation"]["operation_id"],
            "input": deepcopy(body["arguments"]),
            "binding_id": truth["binding_id"],
            "capability_generation": body["generation"],
            "capability_graph_digest": body["snapshot"]["binding"][
                "graph_digest"
            ],
            "implementation_operation_id": body["operation"][
                "implementation_operation_id"
            ],
            "semantic_digest": body["operation"]["semantic_digest"],
        }
        try:
            return self.service.prepare(
                target,
                request,
                granted_scopes=peer.granted_scopes,
            )
        except ProviderControlServiceError as exc:
            raise self._service_gateway_error(exc) from exc

    def _recovery_handle(
        self,
        *,
        request_body: Mapping[str, Any],
        operation: Mapping[str, Any],
        provider_operation_id: str | None,
        context: Mapping[str, Any],
        now: float,
    ) -> dict[str, Any]:
        recovery_id = self._stable_id(
            "rec_", request_body["action_id"], request_body["arguments_digest"]
        )
        expiry = min(float(context["expires_at"]), now + 300.0)
        if expiry <= now:
            raise SessionControlGatewayError(
                "stale_negotiation",
                "negotiation expires before recovery can be issued",
                status=409,
                error_class="freshness",
            )
        handle = {
            "recovery_id": recovery_id,
            "strategy": operation["retry"]["recovery"],
            "correlation": {
                "action_id": request_body["action_id"],
                "provider_operation_id": provider_operation_id,
            },
            "operation": deepcopy(request_body["operation"]),
            "arguments_digest": request_body["arguments_digest"],
            "binding_digest": request_body["binding_digest"],
            "session_id": request_body["session_id"],
            "generation": request_body["generation"],
            "not_before": self._timestamp(now),
            "expires_at": self._timestamp(expiry),
        }
        handle["authority_proof"] = self._make_proof(
            "recovery_correlated",
            handle,
            binding_digest=str(request_body["binding_digest"]),
            session_id=str(request_body["session_id"]),
            generation=int(request_body["generation"]),
            issued_at=now,
            expires_at=expiry,
        )
        return handle

    def _persist_recovery(
        self,
        handle: Mapping[str, Any],
        *,
        context: Mapping[str, Any],
        peer: SessionControlPeer,
        now: float,
    ) -> None:
        self.store.issue_protocol_recovery(
            recovery_id=str(handle["recovery_id"]),
            action_id=str(handle["correlation"]["action_id"]),
            context_id=str(context["context_id"]),
            principal_id=peer.principal_id,
            strategy=str(handle["strategy"]),
            handle_record=canonical_json_bytes(handle),
            not_before=self._timestamp_value(str(handle["not_before"])),
            expires_at=self._timestamp_value(str(handle["expires_at"])),
            now=now,
        )

    def _complete_known_result(
        self,
        *,
        request_body: Mapping[str, Any],
        operation: Mapping[str, Any],
        status: str,
        public_result: Mapping[str, Any],
        provider_operation_id: str | None,
        protocol_session_id: str,
        context: Mapping[str, Any],
        peer: SessionControlPeer,
        now: float,
        prior_state: Mapping[str, Any],
        recovered_at: float | None = None,
        recovery_handle: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        mutation = operation["mutation"] == "mutation"
        current = self._current_typestate(protocol_session_id)
        if status == OperationResultStatus.APPLIED.value:
            if request_body["operation"]["operation_id"] == "session.terminate":
                resulting_state = "terminated"
            elif prior_state["state"] == "owned_running":
                resulting_state = "owned_running"
            else:
                resulting_state = "owned_idle"
            state_payload = {
                "state": resulting_state,
                "state_version": (
                    current["state_version"] + 1 if mutation else current["state_version"]
                ),
                "terminal": resulting_state == "terminated",
            }
            receipt = {
                "receipt_id": self._stable_id(
                    "rcp_", request_body["action_id"], "applied"
                ),
                "action_id": request_body["action_id"],
                "operation": deepcopy(request_body["operation"]),
                "arguments_digest": request_body["arguments_digest"],
                "binding_digest": request_body["binding_digest"],
                "session_id": request_body["session_id"],
                "generation": request_body["generation"],
                "provider_operation_id": provider_operation_id,
                "completed_at": self._timestamp(now),
                "resulting_state": state_payload,
                "output": deepcopy(dict(public_result)),
                "evidence": [],
            }
            receipt_subject = {
                key: value for key, value in receipt.items() if key != "evidence"
            }
            proof_expiry = min(float(context["expires_at"]), now + 300.0)
            proof_kinds = ["mutation_applied"]
            if state_payload["terminal"]:
                proof_kinds.append("terminality_observed")
            receipt["evidence"] = [
                self._make_proof(
                    kind,
                    receipt_subject,
                    binding_digest=str(request_body["binding_digest"]),
                    session_id=protocol_session_id,
                    generation=int(request_body["generation"]),
                    issued_at=now,
                    expires_at=proof_expiry,
                )
                for kind in proof_kinds
            ]
            result = {
                "status": "applied",
                "state": state_payload,
                "receipt": receipt,
            }
            body = self._response_body(
                request_body,
                result,
                recovered_at=recovered_at,
            )
            if mutation:
                event_type = (
                    "recovery.resolved"
                    if current["state"] == "outcome_unknown"
                    else "mutation.applied"
                )
                self._append_event(
                    protocol_session_id=protocol_session_id,
                    generation=int(request_body["generation"]),
                    binding_digest=str(request_body["binding_digest"]),
                    context=context,
                    event_type=event_type,
                    after_state=resulting_state,
                    now=now,
                    data={"status": "applied", "output": dict(public_result)},
                    action_id=str(request_body["action_id"]),
                    provider_operation_id=provider_operation_id,
                    complete_action_state="applied",
                    complete_action_body=body,
                )
            else:
                self.store.complete_protocol_action(
                    str(request_body["action_id"]),
                    state="applied",
                    result_record=canonical_json_bytes(body),
                    now=now,
                )
            return body

        if status == OperationResultStatus.REJECTED.value:
            if mutation and current["state"] in {"mutation_pending", "outcome_unknown"}:
                resulting_state = (
                    prior_state["state"]
                    if prior_state["state"] in {
                        "owned_idle",
                        "owned_running",
                        "owned_waiting",
                    }
                    else "owned_idle"
                )
                state_payload = {
                    "state": resulting_state,
                    "state_version": current["state_version"] + 1,
                    "terminal": False,
                }
            else:
                resulting_state = current["state"]
                state_payload = dict(current)
            result = {
                "status": "rejected",
                "state": state_payload,
                "error": self._error_payload(
                    "provider_rejected",
                    str(public_result.get("message") or "provider rejected operation"),
                    error_class="provider",
                    retryable=False,
                ),
            }
            body = self._response_body(
                request_body,
                result,
                recovered_at=recovered_at,
            )
            if mutation and current["state"] in {"mutation_pending", "outcome_unknown"}:
                event_type = (
                    "recovery.resolved"
                    if current["state"] == "outcome_unknown"
                    else "mutation.rejected"
                )
                self._append_event(
                    protocol_session_id=protocol_session_id,
                    generation=int(request_body["generation"]),
                    binding_digest=str(request_body["binding_digest"]),
                    context=context,
                    event_type=event_type,
                    after_state=str(resulting_state),
                    now=now,
                    data={"status": "rejected"},
                    action_id=str(request_body["action_id"]),
                    provider_operation_id=provider_operation_id,
                    complete_action_state="rejected",
                    complete_action_body=body,
                )
            else:
                self.store.complete_protocol_action(
                    str(request_body["action_id"]),
                    state="rejected",
                    result_record=canonical_json_bytes(body),
                    now=now,
                )
            return body

        if status == OperationResultStatus.IN_PROGRESS.value:
            if not mutation or current["state"] != "mutation_pending":
                raise SessionControlGatewayError(
                    "invalid_server_message",
                    "provider returned in_progress outside mutation_pending",
                    status=500,
                )
            handle = (
                deepcopy(dict(recovery_handle))
                if recovery_handle is not None
                else self._recovery_handle(
                    request_body=request_body,
                    operation=operation,
                    provider_operation_id=provider_operation_id,
                    context=context,
                    now=now,
                )
            )
            result = {
                "status": "in_progress",
                "state": dict(current),
                "recovery": handle,
            }
            body = self._response_body(
                request_body,
                result,
                recovered_at=recovered_at,
            )
            self.store.complete_protocol_action(
                str(request_body["action_id"]),
                state="in_progress",
                result_record=canonical_json_bytes(body),
                now=now,
            )
            self._persist_recovery(handle, context=context, peer=peer, now=now)
            return body

        if operation["retry"]["ambiguity"] == "rejected":
            return self._complete_known_result(
                request_body=request_body,
                operation=operation,
                status=OperationResultStatus.REJECTED.value,
                public_result={"message": "provider outcome was not applied"},
                provider_operation_id=provider_operation_id,
                protocol_session_id=protocol_session_id,
                context=context,
                peer=peer,
                now=now,
                prior_state=prior_state,
                recovered_at=recovered_at,
            )
        if not mutation:
            raise SessionControlGatewayError(
                "invalid_server_message",
                "read-only operation produced an ambiguous mutation outcome",
                status=500,
            )
        if current["state"] == "mutation_pending":
            state_payload = {
                "state": "outcome_unknown",
                "state_version": current["state_version"] + 1,
                "terminal": False,
            }
        elif current["state"] == "outcome_unknown":
            state_payload = dict(current)
        else:
            raise SessionControlGatewayError(
                "invalid_server_message",
                "ambiguous outcome lacks mutation_pending typestate",
                status=500,
            )
        handle = (
            deepcopy(dict(recovery_handle))
            if recovery_handle is not None
            else self._recovery_handle(
                request_body=request_body,
                operation=operation,
                provider_operation_id=provider_operation_id,
                context=context,
                now=now,
            )
        )
        result = {
            "status": "outcome_unknown",
            "state": state_payload,
            "recovery": handle,
            "error": self._error_payload(
                "outcome_unknown",
                "provider execution outcome is unknown; recover this action",
                error_class="recovery",
                retryable=False,
            ),
        }
        body = self._response_body(
            request_body,
            result,
            recovered_at=recovered_at,
        )
        if current["state"] == "mutation_pending":
            self._append_event(
                protocol_session_id=protocol_session_id,
                generation=int(request_body["generation"]),
                binding_digest=str(request_body["binding_digest"]),
                context=context,
                event_type="mutation.outcome_unknown",
                after_state="outcome_unknown",
                now=now,
                data={"status": "outcome_unknown"},
                action_id=str(request_body["action_id"]),
                provider_operation_id=provider_operation_id,
                complete_action_state="outcome_unknown",
                complete_action_body=body,
            )
        else:
            self.store.complete_protocol_action(
                str(request_body["action_id"]),
                state="outcome_unknown",
                result_record=canonical_json_bytes(body),
                now=now,
            )
        self._persist_recovery(handle, context=context, peer=peer, now=now)
        return body

    def _prior_state_for_action(
        self,
        *,
        protocol_session_id: str,
        generation: int,
        action_id: str,
        fallback: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            records = self.store.protocol_events(
                protocol_session_id,
                generation=generation,
                after_sequence=-1,
                predecessor_digest=None,
                limit=500,
            )
        except ManagedSessionControlStateError:
            return dict(fallback)
        for record in reversed(records):
            if (
                record.get("action_id") != action_id
                or record.get("event_type") != "mutation.started"
            ):
                continue
            try:
                event = json.loads(str(record["event_json"]))
                before = event["before"]
            except (KeyError, TypeError, ValueError):
                continue
            if isinstance(before, dict):
                return dict(before)
        return dict(fallback)

    def _response_from_persisted(
        self,
        action: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            body = json.loads(str(action["result_json"]))
        except (TypeError, ValueError) as exc:
            raise SessionControlGatewayError(
                "persisted_protocol_state_invalid",
                "persisted protocol action result is invalid",
                status=500,
            ) from exc
        if not isinstance(body, dict):
            raise SessionControlGatewayError(
                "persisted_protocol_state_invalid",
                "persisted protocol action result is invalid",
                status=500,
            )
        return body

    def execute(
        self,
        payload: Mapping[str, Any] | str | bytes,
        peer: SessionControlPeer,
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        observed_at = self._now(now)
        message = self._parse(payload)
        context_id = str(message.get("negotiation_context_id") or "")
        context = self._context(context_id, peer, now=observed_at)
        self._validate_inbound(message, peer, now=observed_at, context=context)
        if message.get("kind") != "execute.request":
            raise SessionControlGatewayError(
                "invalid_message",
                "execute route requires execute.request",
                status=400,
            )
        body = dict(message["body"])
        protocol_session_id = str(body["session_id"])
        target, _row = self._target(protocol_session_id)
        confirmation = body.get("confirmation")
        stored_snapshot, _snapshot_row = self._stored_snapshot(
            body["snapshot"],
            confirmation=confirmation,
            protocol_session_id=protocol_session_id,
            context=context,
            peer=peer,
            now=observed_at,
        )
        operation = self._operation(stored_snapshot, body["operation"])
        self._verify_lease(
            body.get("lease"),
            operation=operation,
            protocol_session_id=protocol_session_id,
            peer=peer,
            now=observed_at,
        )
        request_record = canonical_json_bytes(message)
        try:
            action, deduped = self.store.reserve_protocol_action(
                action_id=str(body["action_id"]),
                protocol_session_id=protocol_session_id,
                context_id=context_id,
                principal_id=peer.principal_id,
                snapshot_id=str(stored_snapshot["snapshot_id"]),
                generation=int(body["generation"]),
                binding_digest=str(body["binding_digest"]),
                operation_id=str(body["operation"]["operation_id"]),
                implementation_operation_id=str(
                    body["operation"]["implementation_operation_id"]
                ),
                semantic_digest=str(body["operation"]["semantic_digest"]),
                arguments_digest=str(body["arguments_digest"]),
                mutation=operation["mutation"] == "mutation",
                request_record=request_record,
                now=observed_at,
            )
        except ManagedSessionControlStateError as exc:
            raise SessionControlGatewayError(
                "action_identity_conflict",
                str(exc),
                status=409,
                error_class="authority",
            ) from exc
        if deduped and action["state"] in {
            "applied",
            "rejected",
            "in_progress",
            "outcome_unknown",
        }:
            response_body = self._response_from_persisted(action)
            recovery = response_body.get("result", {}).get("recovery")
            if isinstance(recovery, Mapping):
                self._persist_recovery(
                    recovery,
                    context=context,
                    peer=peer,
                    now=observed_at,
                )
            return self._signed_message(
                "execute.response",
                response_body,
                context_id=context_id,
                version={
                    "major": int(context["version_major"]),
                    "minor": int(context["version_minor"]),
                },
                now=observed_at,
                enabled_extensions=tuple(context.get("extensions", ())),
                execution_request=body,
            )
        if deduped and action["state"] == "dispatch_started":
            current_state = self._current_typestate(protocol_session_id)
            prior_state = self._prior_state_for_action(
                protocol_session_id=protocol_session_id,
                generation=int(body["generation"]),
                action_id=str(body["action_id"]),
                fallback=current_state,
            )
            if (
                operation["mutation"] == "mutation"
                and current_state["state"] in {
                    "owned_idle",
                    "owned_running",
                    "owned_waiting",
                }
            ):
                self._append_event(
                    protocol_session_id=protocol_session_id,
                    generation=int(body["generation"]),
                    binding_digest=str(body["binding_digest"]),
                    context=context,
                    event_type="mutation.started",
                    after_state="mutation_pending",
                    now=observed_at,
                    data={},
                    action_id=str(body["action_id"]),
                    provider_operation_id=action.get("provider_operation_id"),
                )
            response_body = self._complete_known_result(
                request_body=body,
                operation=operation,
                status=OperationResultStatus.OUTCOME_UNKNOWN.value,
                public_result={},
                provider_operation_id=action.get("provider_operation_id"),
                protocol_session_id=protocol_session_id,
                context=context,
                peer=peer,
                now=observed_at,
                prior_state=prior_state,
            )
            return self._signed_message(
                "execute.response",
                response_body,
                context_id=context_id,
                version={
                    "major": int(context["version_major"]),
                    "minor": int(context["version_minor"]),
                },
                now=observed_at,
                enabled_extensions=tuple(context.get("extensions", ())),
                execution_request=body,
            )
        try:
            prepared = self._prepare(target, body, peer)
        except SessionControlGatewayError as exc:
            state = self._current_typestate(protocol_session_id)
            response_body = self._response_body(
                body,
                {
                    "status": "rejected",
                    "state": state,
                    "error": self._error_payload(
                        exc.code,
                        exc.message,
                        error_class=exc.error_class,
                        retryable=False,
                    ),
                },
            )
            self.store.complete_protocol_action(
                str(body["action_id"]),
                state="rejected",
                result_record=canonical_json_bytes(response_body),
                now=observed_at,
            )
            return self._signed_message(
                "execute.response",
                response_body,
                context_id=context_id,
                version={
                    "major": int(context["version_major"]),
                    "minor": int(context["version_minor"]),
                },
                now=observed_at,
                enabled_extensions=tuple(context.get("extensions", ())),
                execution_request=body,
            )
        if confirmation is not None:
            try:
                self._consume_confirmation(
                    confirmation,
                    action_id=str(body["action_id"]),
                    peer=peer,
                    now=observed_at,
                )
            except ManagedSessionControlStateError as exc:
                raise SessionControlGatewayError(
                    "confirmation_mismatch",
                    str(exc),
                    status=409,
                    error_class="authority",
                ) from exc
        prior_state = self._current_typestate(protocol_session_id)
        if operation["mutation"] == "mutation" and prior_state["state"] not in {
            "owned_idle",
            "owned_running",
            "owned_waiting",
        }:
            raise SessionControlGatewayError(
                "ownership_required",
                "mutation requires a known owned typestate",
                status=409,
                error_class="ownership",
            )
        try:
            reservation = self.service.reserve_operation(
                prepared,
                client_action_id=str(body["action_id"]),
            )
        except ProviderControlServiceError as exc:
            gateway_error = self._service_gateway_error(exc)
            result = {
                "status": "rejected",
                "state": dict(prior_state),
                "error": self._error_payload(
                    gateway_error.code,
                    gateway_error.message,
                    error_class=gateway_error.error_class,
                    retryable=False,
                ),
            }
            response_body = self._response_body(body, result)
            self.store.complete_protocol_action(
                str(body["action_id"]),
                state="rejected",
                result_record=canonical_json_bytes(response_body),
                now=observed_at,
            )
            return self._signed_message(
                "execute.response",
                response_body,
                context_id=context_id,
                version={
                    "major": int(context["version_major"]),
                    "minor": int(context["version_minor"]),
                },
                now=observed_at,
                enabled_extensions=tuple(context.get("extensions", ())),
                execution_request=body,
            )

        dispatch_started = False

        def before_execute() -> None:
            nonlocal dispatch_started
            correlation = reservation.correlation
            self.store.mark_protocol_action_dispatch_started(
                str(body["action_id"]),
                provider_operation_id=(
                    correlation.provider_operation_id if correlation else None
                ),
                provider_cursor=(correlation.provider_cursor if correlation else None),
                now=observed_at,
            )
            if operation["mutation"] == "mutation":
                self._append_event(
                    protocol_session_id=protocol_session_id,
                    generation=int(body["generation"]),
                    binding_digest=str(body["binding_digest"]),
                    context=context,
                    event_type="mutation.started",
                    after_state="mutation_pending",
                    now=observed_at,
                    data={},
                    action_id=str(body["action_id"]),
                    provider_operation_id=(
                        correlation.provider_operation_id if correlation else None
                    ),
                )
            dispatch_started = True

        execution: ProviderControlExecution | None = None
        try:
            execution = self.service.execute(
                prepared,
                reservation,
                confirmation_verified=confirmation is not None,
                before_execute=before_execute,
                attachment_resolver=peer.attachment_resolver,
                source_device_id=peer.source_device_id,
                source_install_id=peer.source_install_id,
            )
        except ProviderControlServiceError as exc:
            if not dispatch_started or exc.code != "action_outcome_unknown":
                gateway_error = self._service_gateway_error(exc)
                result = {
                    "status": "rejected",
                    "state": dict(prior_state),
                    "error": self._error_payload(
                        gateway_error.code,
                        gateway_error.message,
                        error_class=gateway_error.error_class,
                        retryable=False,
                    ),
                }
                response_body = self._response_body(body, result)
                self.store.complete_protocol_action(
                    str(body["action_id"]),
                    state="rejected",
                    result_record=canonical_json_bytes(response_body),
                    now=observed_at,
                )
            else:
                correlation = reservation.correlation
                response_body = self._complete_known_result(
                    request_body=body,
                    operation=operation,
                    status=OperationResultStatus.OUTCOME_UNKNOWN.value,
                    public_result={},
                    provider_operation_id=(
                        correlation.provider_operation_id if correlation else None
                    ),
                    protocol_session_id=protocol_session_id,
                    context=context,
                    peer=peer,
                    now=observed_at,
                    prior_state=prior_state,
                )
        else:
            response_body = self._complete_known_result(
                request_body=body,
                operation=operation,
                status=execution.outcome,
                public_result=execution.result.public_result,
                provider_operation_id=execution.result.provider_operation_id,
                protocol_session_id=protocol_session_id,
                context=context,
                peer=peer,
                now=observed_at,
                prior_state=prior_state,
            )
        return self._signed_message(
            "execute.response",
            response_body,
            context_id=context_id,
            version={
                "major": int(context["version_major"]),
                "minor": int(context["version_minor"]),
            },
            now=observed_at,
            enabled_extensions=tuple(context.get("extensions", ())),
            execution_request=body,
        )

    def recover(
        self,
        payload: Mapping[str, Any] | str | bytes,
        peer: SessionControlPeer,
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        observed_at = self._now(now)
        message = self._parse(payload)
        context_id = str(message.get("negotiation_context_id") or "")
        context = self._context(context_id, peer, now=observed_at)
        self._validate_inbound(message, peer, now=observed_at, context=context)
        if message.get("kind") != "recover.request":
            raise SessionControlGatewayError(
                "invalid_message",
                "recover route requires recover.request",
                status=400,
            )
        body = dict(message["body"])
        protocol_session_id = str(body["session_id"])
        target, _row = self._target(protocol_session_id)
        stored_snapshot, _snapshot_row = self._stored_snapshot(
            body["snapshot"],
            confirmation=None,
            protocol_session_id=protocol_session_id,
            context=context,
            peer=peer,
            now=observed_at,
        )
        operation = self._operation(stored_snapshot, body["operation"])
        action = self.store.protocol_action(str(body["action_id"]))
        if (
            not isinstance(action, dict)
            or action.get("protocol_session_id") != protocol_session_id
            or action.get("principal_id") != peer.principal_id
            or action.get("binding_digest") != body["binding_digest"]
            or action.get("arguments_digest") != body["arguments_digest"]
            or action.get("operation_id") != body["operation"]["operation_id"]
            or action.get("implementation_operation_id")
            != body["operation"]["implementation_operation_id"]
            or action.get("semantic_digest") != body["operation"]["semantic_digest"]
        ):
            raise SessionControlGatewayError(
                "recovery_required",
                "recovery does not match a durable ambiguous action",
                status=409,
                error_class="recovery",
            )
        recovery = self.store.protocol_recovery(
            str(body["recovery"]["recovery_id"])
        )
        if (
            not isinstance(recovery, dict)
            or recovery.get("action_id") != body["action_id"]
            or recovery.get("principal_id") != peer.principal_id
        ):
            raise SessionControlGatewayError(
                "recovery_required",
                "recovery handle is not durable authority",
                status=409,
                error_class="recovery",
            )
        try:
            persisted_handle = json.loads(str(recovery["handle_json"]))
        except (TypeError, ValueError) as exc:
            raise SessionControlGatewayError(
                "persisted_protocol_state_invalid",
                "persisted recovery handle is invalid",
                status=500,
            ) from exc
        if canonical_json_bytes(persisted_handle) != canonical_json_bytes(
            body["recovery"]
        ):
            raise SessionControlGatewayError(
                "recovery_required",
                "recovery handle differs from durable authority",
                status=409,
                error_class="recovery",
            )
        try:
            attempt, deduped = self.store.begin_protocol_recovery_attempt(
                str(body["recovery"]["recovery_id"]),
                context_id=context_id,
                principal_id=peer.principal_id,
                request_record=canonical_json_bytes(message),
                now=observed_at,
            )
        except ManagedSessionControlStateError as exc:
            raise SessionControlGatewayError(
                "recovery_required",
                str(exc),
                status=409,
                error_class="recovery",
            ) from exc
        if deduped and attempt.get("response_json") is not None:
            response_body = json.loads(str(attempt["response_json"]))
            return self._signed_message(
                "recover.response",
                response_body,
                context_id=context_id,
                version={
                    "major": int(context["version_major"]),
                    "minor": int(context["version_minor"]),
                },
                now=observed_at,
                enabled_extensions=tuple(context.get("extensions", ())),
                recovery_request=body,
            )
        if action.get("state") not in {"in_progress", "outcome_unknown"}:
            raise SessionControlGatewayError(
                "recovery_required",
                "recovery does not match a durable ambiguous action",
                status=409,
                error_class="recovery",
            )
        provider_operation_id = body["recovery"]["correlation"][
            "provider_operation_id"
        ]
        prior_state = self._current_typestate(protocol_session_id)
        prior_state = self._prior_state_for_action(
            protocol_session_id=protocol_session_id,
            generation=int(body["generation"]),
            action_id=str(body["action_id"]),
            fallback=prior_state,
        )
        execution = None
        if provider_operation_id is not None:
            correlation = ProviderOperationCorrelation(
                provider_operation_id=str(provider_operation_id),
                provider_cursor=action.get("provider_cursor"),
            )
            try:
                execution = self.service.recover(
                    target,
                    operation_id=str(body["operation"]["operation_id"]),
                    binding_id=str(target["session_truth"]["binding_id"]),
                    capability_generation=int(body["generation"]),
                    client_action_id=str(body["action_id"]),
                    correlation=correlation,
                )
            except ProviderControlServiceError:
                execution = None
        if execution is None:
            status = str(action["state"])
            if status not in {"in_progress", "outcome_unknown"}:
                status = "outcome_unknown"
            response_body = self._complete_known_result(
                request_body=body,
                operation=operation,
                status=status,
                public_result={},
                provider_operation_id=(
                    str(provider_operation_id)
                    if provider_operation_id is not None
                    else None
                ),
                protocol_session_id=protocol_session_id,
                context=context,
                peer=peer,
                now=observed_at,
                prior_state=prior_state,
                recovered_at=observed_at,
                recovery_handle=body["recovery"],
            )
        else:
            response_body = self._complete_known_result(
                request_body=body,
                operation=operation,
                status=execution.outcome,
                public_result=execution.result.public_result,
                provider_operation_id=execution.result.provider_operation_id,
                protocol_session_id=protocol_session_id,
                context=context,
                peer=peer,
                now=observed_at,
                prior_state=prior_state,
                recovered_at=observed_at,
                recovery_handle=body["recovery"],
            )
        self.store.complete_protocol_recovery_attempt(
            int(attempt["attempt_id"]),
            outcome=str(response_body["result"]["status"]),
            response_record=canonical_json_bytes(response_body),
            now=observed_at,
        )
        return self._signed_message(
            "recover.response",
            response_body,
            context_id=context_id,
            version={
                "major": int(context["version_major"]),
                "minor": int(context["version_minor"]),
            },
            now=observed_at,
            enabled_extensions=tuple(context.get("extensions", ())),
            recovery_request=body,
        )

    def events(
        self,
        protocol_session_id: str,
        context_id: str,
        peer: SessionControlPeer,
        *,
        after_sequence: int,
        predecessor_digest: str | None,
        now: float | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        observed_at = self._now(now)
        context = self._context(context_id, peer, now=observed_at)
        _target, row = self._target(protocol_session_id)
        try:
            records = self.store.protocol_events(
                protocol_session_id,
                generation=int(row["capability_generation"]),
                after_sequence=int(after_sequence),
                predecessor_digest=predecessor_digest,
                limit=limit,
            )
        except ManagedSessionControlStateError as exc:
            raise SessionControlGatewayError(
                "cursor_gap",
                str(exc),
                status=409,
                error_class="recovery",
            ) from exc
        messages: list[dict[str, Any]] = []
        for record in records:
            try:
                event = json.loads(str(record["event_json"]))
            except (TypeError, ValueError) as exc:
                raise SessionControlGatewayError(
                    "persisted_protocol_state_invalid",
                    "persisted protocol event is invalid",
                    status=500,
                ) from exc
            messages.append(self._signed_message(
                "event.publish",
                {"event": event},
                context_id=context_id,
                version={
                    "major": int(context["version_major"]),
                    "minor": int(context["version_minor"]),
                },
                now=observed_at,
                enabled_extensions=tuple(context.get("extensions", ())),
            ))
        return messages

    def event_page(
        self,
        protocol_session_id: str,
        context_id: str,
        peer: SessionControlPeer,
        *,
        after_sequence: int,
        predecessor_digest: str | None,
        now: float | None = None,
        limit: int = 500,
    ) -> dict[str, Any]:
        messages = self.events(
            protocol_session_id,
            context_id,
            peer,
            after_sequence=after_sequence,
            predecessor_digest=predecessor_digest,
            now=now,
            limit=limit,
        )
        next_sequence = int(after_sequence)
        next_predecessor = predecessor_digest
        terminal = False
        for message in messages:
            event = message["body"]["event"]
            next_sequence = int(event["cursor"]["sequence"])
            next_predecessor = digest_value(event)
            terminal = bool(event["after"]["terminal"])
        if not messages:
            terminal = bool(
                self.store.protocol_typestate(protocol_session_id).get(
                    "protocol_terminal"
                )
            )
        return {
            "messages": messages,
            "after_sequence": next_sequence,
            "predecessor_digest": next_predecessor,
            "terminal": terminal,
        }

    def encode_message(
        self,
        message: Mapping[str, Any],
        *,
        event: bool = False,
    ) -> bytes:
        try:
            encoded = canonical_json_bytes(message)
        except ProtocolValidationError as exc:
            raise SessionControlGatewayError(
                "invalid_server_message",
                str(exc),
                status=500,
            ) from exc
        limit_key = "max_event_bytes" if event else "max_response_bytes"
        if len(encoded) > int(self.profile["limits"][limit_key]):
            raise SessionControlGatewayError(
                "response_too_large",
                "session-control response exceeds its transport bound",
                status=500,
                error_class="transport",
            )
        return encoded
