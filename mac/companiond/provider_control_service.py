"""Shared provider-control orchestration above exact driver contracts.

The service is transport-neutral. HTTP framing, authentication, receipts, and
wire serialization remain in their adapters; reviewed operation semantics and
manager-owned lifecycle transitions pass through this single execution seam.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from providers.controls import (
    ControlContractError,
    OperationResultStatus,
    ProviderOperationCorrelation,
    ProviderOperationResult,
    execute_provider_operation,
    provider_control_status_payload,
    recover_provider_operation,
    validated_driver_snapshot,
)
from providers.operations import REVIEWED_OPERATION_CATALOG


class ProviderControlServiceError(RuntimeError):
    """Stable transport-neutral provider-control failure."""

    def __init__(self, code: str, message: str, *, status: int) -> None:
        super().__init__(message)
        self.code = str(code)
        self.message = str(message)
        self.status = int(status)


@dataclass(frozen=True)
class PreparedProviderOperation:
    target: dict[str, Any]
    definition: Any
    request: dict[str, Any]
    normalized_input: dict[str, Any]
    status: dict[str, Any]
    execution_session_id: str | None
    execution_session_truth: dict[str, Any] | None
    fork_parent_session_id: str | None

    @property
    def operation_id(self) -> str:
        return str(self.request["operation_id"])


@dataclass(frozen=True)
class ProviderOperationReservation:
    operation_id: str
    client_action_id: str
    binding_id: str
    capability_generation: int
    correlation: ProviderOperationCorrelation | None
    fork_parent_session_id: str | None = None
    fork_reservation_token: str | None = None


@dataclass(frozen=True)
class ProviderControlExecution:
    result: ProviderOperationResult
    result_payload: dict[str, Any]
    correlation: ProviderOperationCorrelation | None

    @property
    def outcome(self) -> str:
        return str(getattr(self.result.status, "value", self.result.status))


class ProviderControlService:
    """One reviewed snapshot, preflight, dispatch, and recovery authority."""

    def __init__(self, *, catalog=REVIEWED_OPERATION_CATALOG) -> None:
        self._catalog = catalog

    @property
    def catalog(self):
        return self._catalog

    def definition(self, operation_id: str):
        try:
            return self._catalog.require(operation_id)
        except Exception as exc:
            raise ProviderControlServiceError(
                "unknown_operation",
                "operation_id is not in the reviewed operation catalog",
                status=400,
            ) from exc

    @staticmethod
    def require_operation_scope(definition, granted_scopes) -> None:
        required_scope = str(definition.required_device_scope)
        granted = frozenset(str(scope) for scope in (granted_scopes or ()))
        if required_scope not in granted:
            raise ProviderControlServiceError(
                "missing_operation_scope",
                f"operation requires {required_scope}",
                status=403,
            )

    @staticmethod
    def normalize_input(definition, input_payload: Any) -> dict[str, Any]:
        try:
            return definition.validate_input_payload(input_payload)
        except Exception as exc:
            raise ProviderControlServiceError(
                "invalid_operation_input",
                str(exc)[:300] or "operation input is invalid",
                status=400,
            ) from exc

    def snapshot_status(
        self,
        target: Mapping[str, Any],
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        driver = target.get("driver")
        if driver is None:
            raise ProviderControlServiceError(
                "provider_driver_unavailable",
                "the session has no live structured provider driver",
                status=409,
            )
        validation_now = None if now is None else float(now)
        try:
            try:
                provider_snapshot = validated_driver_snapshot(
                    driver,
                    session_id=None,
                    session_truth=None,
                    now=validation_now,
                    catalog=self._catalog,
                )
            except ControlContractError:
                provider_snapshot = None
            snapshot = validated_driver_snapshot(
                driver,
                session_id=target["session_id"],
                session_truth=target["session_truth"],
                now=validation_now,
                catalog=self._catalog,
            )
            observed_now = time.time() if now is None else float(now)
            status = provider_control_status_payload(
                snapshot,
                now=observed_now,
                catalog=self._catalog,
            )
            status = self._filter_fork_status(target, status)
            provider_status = None
            if provider_snapshot is not None:
                try:
                    provider_status = provider_control_status_payload(
                        provider_snapshot,
                        now=observed_now,
                        catalog=self._catalog,
                    )
                except ControlContractError:
                    provider_status = None
            if provider_status is not None:
                status = self._merge_provider_wide_status(status, provider_status)
            return status
        except ProviderControlServiceError:
            raise
        except ControlContractError as exc:
            raise self.contract_error(exc) from exc

    def prepare(
        self,
        target: Mapping[str, Any],
        request: Mapping[str, Any],
        *,
        granted_scopes,
    ) -> PreparedProviderOperation:
        operation_id = str(request.get("operation_id") or "")
        definition = self.definition(operation_id)
        self.require_operation_scope(definition, granted_scopes)
        normalized_input = self.normalize_input(definition, request.get("input"))
        return self.preflight(target, definition, request, normalized_input)

    def preflight(
        self,
        target: Mapping[str, Any],
        definition,
        request: Mapping[str, Any],
        normalized_input: Mapping[str, Any],
    ) -> PreparedProviderOperation:
        status = self.snapshot_status(target)
        if request.get("binding_id") != status.get("binding_id"):
            raise ProviderControlServiceError(
                "provider_binding_stale",
                "provider binding changed; refresh controls before retrying",
                status=409,
            )
        if request.get("capability_generation") != status.get(
            "capability_generation"
        ):
            raise ProviderControlServiceError(
                "provider_control_stale",
                "provider capability generation changed; refresh before retrying",
                status=409,
            )
        blocked_reason = status.get("blocked_reason")
        if blocked_reason is not None:
            raise ProviderControlServiceError(
                "provider_control_blocked",
                str(blocked_reason)[:300],
                status=409,
            )
        operation_id = str(request.get("operation_id") or "")
        advertised_operation = next(
            (
                attestation
                for attestation in status.get("advertised_operations", ())
                if self._advertised_operation_id(attestation) == operation_id
            ),
            None,
        )
        if advertised_operation is None:
            raise ProviderControlServiceError(
                "operation_not_available",
                "the live driver did not advertise this operation",
                status=409,
            )
        if (
            request.get("capability_graph_digest")
            != status.get("capability_graph_digest")
            or request.get("implementation_operation_id")
            != advertised_operation.get("implementation_operation_id")
            or request.get("semantic_digest")
            != advertised_operation.get("semantic_digest")
        ):
            raise ProviderControlServiceError(
                "provider_semantic_contract_stale",
                "provider semantic contract changed; refresh controls before retrying",
                status=409,
            )

        normalized = dict(normalized_input)
        operation_choices = self._operation_rows(status, "choices", operation_id)
        for descriptor in definition.inputs:
            input_id = str(descriptor.input_id)
            if input_id not in normalized:
                if descriptor.required:
                    raise ProviderControlServiceError(
                        "invalid_operation_input",
                        "operation input is missing a required descriptor",
                        status=400,
                    )
                continue
            input_type = str(
                getattr(descriptor.input_type, "value", descriptor.input_type)
            )
            rows = operation_choices.get(input_id)
            if input_type == "choice" and not isinstance(rows, list):
                raise ProviderControlServiceError(
                    "operation_choice_unavailable",
                    "the live provider did not advertise choices for this input",
                    status=409,
                )
            if isinstance(rows, list):
                advertised = [
                    row.get("value")
                    for row in rows
                    if isinstance(row, dict)
                    and set(row) == {"value", "label"}
                ]
                if advertised.count(normalized[input_id]) != 1:
                    raise ProviderControlServiceError(
                        "operation_choice_stale",
                        "the selected provider value is no longer uniquely advertised",
                        status=409,
                    )

        session_descriptors = [
            descriptor
            for descriptor in definition.inputs
            if str(
                getattr(
                    descriptor.input_type,
                    "value",
                    descriptor.input_type,
                )
            )
            == "provider_session"
        ]
        if session_descriptors:
            if len(session_descriptors) != 1:
                raise ProviderControlServiceError(
                    "unsupported_lifecycle",
                    "operation has an unsupported session identity contract",
                    status=409,
                )
            expected_session = {
                "provider_id": target["provider_id"],
                "session_id": target["session_id"],
                "binding_id": request.get("binding_id"),
                "capability_generation": request.get("capability_generation"),
            }
            if normalized.get(session_descriptors[0].input_id) != expected_session:
                raise ProviderControlServiceError(
                    "provider_session_mismatch",
                    "operation input does not match exact live session truth",
                    status=409,
                )
            execution_session_id = str(target["session_id"])
            execution_session_truth = dict(target["session_truth"])
        else:
            execution_session_id = None
            execution_session_truth = None

        proof_kind = str(
            getattr(
                definition.resource_proof_kind,
                "value",
                definition.resource_proof_kind,
            )
        )
        if proof_kind == "approval_nonce":
            self._validate_approval_proof(
                status,
                definition,
                operation_id,
                normalized,
                operation_choices,
            )

        fork_parent = (
            self.fork_parent(target, normalized)
            if operation_id == "session.fork"
            else None
        )
        return PreparedProviderOperation(
            target=dict(target),
            definition=definition,
            request=dict(request),
            normalized_input=normalized,
            status=status,
            execution_session_id=execution_session_id,
            execution_session_truth=execution_session_truth,
            fork_parent_session_id=fork_parent,
        )

    def reserve_operation(
        self,
        prepared: PreparedProviderOperation,
        *,
        client_action_id: str,
    ) -> ProviderOperationReservation:
        action_id = self._action_id(client_action_id)
        request = prepared.request
        if not bool(prepared.definition.receipt_required):
            return ProviderOperationReservation(
                operation_id=prepared.operation_id,
                client_action_id=action_id,
                binding_id=str(request["binding_id"]),
                capability_generation=int(request["capability_generation"]),
                correlation=None,
            )

        driver = prepared.target.get("driver")
        correlate = getattr(driver, "operation_correlation", None)
        if not callable(correlate):
            raise ProviderControlServiceError(
                "provider_operation_correlation_unavailable",
                "provider cannot reserve an exact operation identity",
                status=503,
            )
        try:
            correlation = correlate(
                operation_id=prepared.operation_id,
                client_action_id=action_id,
                capability_generation=int(request["capability_generation"]),
                session_id=prepared.execution_session_id,
                session_truth=prepared.execution_session_truth,
            )
        except Exception as exc:
            raise ProviderControlServiceError(
                "provider_operation_correlation_unavailable",
                "provider cannot reserve an exact operation identity",
                status=503,
            ) from exc
        if not isinstance(correlation, ProviderOperationCorrelation):
            raise ProviderControlServiceError(
                "provider_operation_correlation_unavailable",
                "provider cannot reserve an exact operation identity",
                status=503,
            )

        fork_token = None
        if prepared.operation_id == "session.fork":
            manager = prepared.target.get("manager")
            if manager is None or prepared.fork_parent_session_id is None:
                raise ProviderControlServiceError(
                    "unsupported_lifecycle",
                    "session.fork requires a managed provider session owner",
                    status=409,
                )
            try:
                fork_token = manager.prepare_fork(
                    prepared.fork_parent_session_id,
                    action_id,
                    provider_operation_id=correlation.provider_operation_id,
                    provider_cursor=correlation.provider_cursor,
                )
            except Exception as exc:
                raise ProviderControlServiceError(
                    "fork_registration_unavailable",
                    "managed fork registration is unavailable",
                    status=503,
                ) from exc

        return ProviderOperationReservation(
            operation_id=prepared.operation_id,
            client_action_id=action_id,
            binding_id=str(request["binding_id"]),
            capability_generation=int(request["capability_generation"]),
            correlation=correlation,
            fork_parent_session_id=prepared.fork_parent_session_id,
            fork_reservation_token=fork_token,
        )

    def execute(
        self,
        prepared: PreparedProviderOperation,
        reservation: ProviderOperationReservation,
        *,
        confirmation_verified: bool,
        before_execute: Callable[[], None] | None = None,
        prepared_attachments: tuple[Any, ...] | None = None,
        attachment_resolver=None,
        source_device_id: str | None = None,
        source_install_id: str | None = None,
    ) -> ProviderControlExecution:
        self._validate_reservation(prepared, reservation)
        confirmation = str(
            getattr(
                prepared.definition.confirmation_requirement,
                "value",
                prepared.definition.confirmation_requirement,
            )
        )
        if confirmation != "none" and not confirmation_verified:
            raise ProviderControlServiceError(
                "confirmation_required",
                "provider operation requires fresh confirmation",
                status=409,
            )
        if confirmation == "none" and confirmation_verified:
            raise ProviderControlServiceError(
                "confirmation_unexpected",
                "provider operation does not accept confirmation",
                status=400,
            )

        resource_args: dict[str, Any]
        if prepared_attachments is not None:
            resource_args = {"prepared_attachments": prepared_attachments}
        else:
            resource_args = {
                "attachment_resolver": attachment_resolver,
                "source_device_id": source_device_id,
                "source_install_id": source_install_id,
            }
        try:
            result = execute_provider_operation(
                prepared.target["driver"],
                operation_id=prepared.operation_id,
                input_payload=prepared.normalized_input,
                binding_id=reservation.binding_id,
                capability_generation=reservation.capability_generation,
                session_id=prepared.execution_session_id,
                session_truth=prepared.execution_session_truth,
                client_action_id=reservation.client_action_id,
                provider_correlation=reservation.correlation,
                before_execute=before_execute,
                catalog=self._catalog,
                **resource_args,
            )
            result_payload = result.to_payload()
            self._apply_manager_result(
                prepared.target,
                prepared.operation_id,
                result,
                result_payload,
                fork_parent_session_id=reservation.fork_parent_session_id,
                fork_reservation_token=reservation.fork_reservation_token,
            )
            return ProviderControlExecution(
                result=result,
                result_payload=result_payload,
                correlation=reservation.correlation,
            )
        except ProviderControlServiceError:
            raise
        except ControlContractError as exc:
            raise self.contract_error(exc) from exc
        except Exception as exc:
            raise ProviderControlServiceError(
                "action_outcome_unknown",
                "provider execution outcome is unknown",
                status=409,
            ) from exc

    def recover(
        self,
        target: Mapping[str, Any],
        *,
        operation_id: str,
        binding_id: str,
        capability_generation: int,
        client_action_id: str,
        correlation: ProviderOperationCorrelation,
        fork_parent_session_id: str | None = None,
        fork_reservation_token: str | None = None,
    ) -> ProviderControlExecution | None:
        definition = self.definition(operation_id)
        has_session = any(
            str(getattr(item.input_type, "value", item.input_type))
            == "provider_session"
            for item in definition.inputs
        )
        try:
            result = recover_provider_operation(
                target["driver"],
                operation_id=operation_id,
                binding_id=binding_id,
                capability_generation=capability_generation,
                session_id=str(target["session_id"]) if has_session else None,
                client_action_id=self._action_id(client_action_id),
                provider_correlation=correlation,
                session_truth=dict(target["session_truth"]) if has_session else None,
                catalog=self._catalog,
            )
            if result is None:
                return None
            result_payload = result.to_payload()
            self._apply_manager_result(
                target,
                operation_id,
                result,
                result_payload,
                fork_parent_session_id=fork_parent_session_id,
                fork_reservation_token=fork_reservation_token,
            )
            return ProviderControlExecution(
                result=result,
                result_payload=result_payload,
                correlation=correlation,
            )
        except ProviderControlServiceError:
            raise
        except ControlContractError as exc:
            raise self.contract_error(exc) from exc
        except Exception as exc:
            raise ProviderControlServiceError(
                "action_outcome_unknown",
                "provider recovery outcome is unknown",
                status=409,
            ) from exc

    @staticmethod
    def outcome(status) -> tuple[bool, int, str, str | None]:
        raw = str(getattr(status, "value", status))
        if raw == OperationResultStatus.APPLIED.value:
            return True, 200, "applied", None
        if raw == OperationResultStatus.REJECTED.value:
            return False, 409, "rejected", "provider_operation_rejected"
        if raw == OperationResultStatus.IN_PROGRESS.value:
            return True, 202, "indeterminate", None
        return False, 409, "indeterminate", "action_outcome_unknown"

    @staticmethod
    def contract_error(exc: Exception) -> ProviderControlServiceError:
        message = str(exc)[:300] or "provider control validation failed"
        lowered = message.lower()
        if "stale" in lowered or "generation" in lowered:
            code, status = "provider_control_stale", 409
        elif "blocked" in lowered:
            code, status = "provider_control_blocked", 409
        elif "did not advertise" in lowered or "unadvertised" in lowered:
            code, status = "operation_not_available", 409
        elif "runtime truth" in lowered or "not controllable" in lowered:
            code, status = "session_not_controllable", 409
        elif "unknown operation" in lowered or "not reviewed" in lowered:
            code, status = "unknown_operation", 400
        elif "provider operation result" in lowered:
            code, status = "provider_result_invalid", 409
        else:
            code, status = "invalid_operation_input", 400
        return ProviderControlServiceError(code, message, status=status)

    @staticmethod
    def fork_parent(
        target: Mapping[str, Any],
        normalized_input: Mapping[str, Any],
    ) -> str:
        manager = target.get("manager")
        driver = target.get("driver")
        truth = target.get("session_truth")
        if manager is None or driver is None or not isinstance(truth, dict):
            raise ProviderControlServiceError(
                "fork_parent_unavailable",
                "the fork parent could not be proven",
                status=409,
            )
        raw_target = normalized_input.get("target_session")
        provider = str(target.get("provider_id") or "").strip().lower()
        current_session_id = str(target.get("session_id") or "").strip()
        native_id = str(truth.get("native_id") or "").strip()
        if (
            not isinstance(raw_target, str)
            or not raw_target
            or raw_target not in {native_id, current_session_id}
        ):
            raise ProviderControlServiceError(
                "fork_parent_mismatch",
                "the fork parent does not map to this managed session",
                status=409,
            )
        row = manager.store.get(current_session_id)
        if (
            not isinstance(row, dict)
            or str(row.get("provider") or "").strip().lower() != provider
            or str(row.get("native_id") or "").strip() != native_id
            or str(row.get("binding_id") or "")
            != str(truth.get("binding_id") or "")
            or int(row.get("capability_generation") or 0)
            != int(truth.get("capability_generation") or 0)
            or str(row.get("provider_profile_id") or "")
            != str(truth.get("provider_profile_id") or "")
            or str(row.get("project") or "") != str(truth.get("project") or "")
            or str(row.get("lifecycle") or "")
            not in {"launching", "running", "waiting"}
            or manager.driver(current_session_id) is not driver
        ):
            raise ProviderControlServiceError(
                "fork_parent_stale",
                "the fork parent mapping is stale",
                status=409,
            )
        return current_session_id

    def _filter_fork_status(
        self,
        target: Mapping[str, Any],
        status: dict[str, Any],
    ) -> dict[str, Any]:
        operations = status.get("advertised_operations")
        operation_ids = {
            self._advertised_operation_id(item)
            for item in operations
        } if isinstance(operations, list) else set()
        if "session.fork" not in operation_ids:
            return status
        choices = status.get("choices")
        operation_choices = (
            choices.get("session.fork") if isinstance(choices, dict) else None
        )
        rows = (
            operation_choices.get("target_session")
            if isinstance(operation_choices, dict)
            else None
        )
        valid_rows = []
        if isinstance(rows, list):
            for row in rows:
                value = row.get("value") if isinstance(row, dict) else None
                try:
                    self.fork_parent(target, {"target_session": value})
                except ProviderControlServiceError:
                    continue
                valid_rows.append(row)
        if valid_rows:
            operation_choices["target_session"] = valid_rows
            return status
        status["advertised_operations"] = [
            attestation
            for attestation in (operations or ())
            if self._advertised_operation_id(attestation) != "session.fork"
        ]
        values = status.get("values")
        if isinstance(values, dict):
            values.pop("session.fork", None)
        if isinstance(choices, dict):
            choices.pop("session.fork", None)
        return status

    def _merge_provider_wide_status(
        self,
        session_status: Mapping[str, Any],
        provider_status: Mapping[str, Any],
    ) -> dict[str, Any]:
        identity_fields = (
            "provider_id",
            "provider_version",
            "provider_channel",
            "binding_id",
            "capability_generation",
            "capability_graph_digest",
        )
        if any(
            provider_status.get(field) != session_status.get(field)
            for field in identity_fields
        ) or provider_status.get("blocked_reason") is not None:
            return dict(session_status)
        observed_at = max(
            float(session_status["observed_at"]),
            float(provider_status["observed_at"]),
        )
        valid_until = min(
            float(session_status["valid_until"]),
            float(provider_status["valid_until"]),
        )
        if observed_at >= valid_until:
            return dict(session_status)
        session_operations = list(session_status.get("advertised_operations", ()))
        session_operation_ids = {
            self._advertised_operation_id(attestation)
            for attestation in session_operations
        }
        provider_operations = []
        for attestation in provider_status.get("advertised_operations", ()):
            operation_id = self._advertised_operation_id(attestation)
            if operation_id is None:
                return dict(session_status)
            definition = self._catalog.require(operation_id)
            lifecycle = str(
                getattr(definition.lifecycle, "value", definition.lifecycle)
            )
            if lifecycle == "provider_wide" and operation_id not in session_operation_ids:
                provider_operations.append(attestation)
        if not provider_operations:
            return dict(session_status)
        merged = dict(session_status)
        merged["observed_at"] = observed_at
        merged["valid_until"] = valid_until
        merged["advertised_operations"] = session_operations + provider_operations
        for field in ("values", "choices"):
            rows = {
                operation_id: dict(operation_rows)
                for operation_id, operation_rows in session_status.get(field, {}).items()
            }
            provider_rows = provider_status.get(field, {})
            for attestation in provider_operations:
                operation_id = self._advertised_operation_id(attestation)
                if operation_id in provider_rows:
                    rows[operation_id] = dict(provider_rows[operation_id])
            merged[field] = rows
        return merged

    @staticmethod
    def _validate_approval_proof(
        status: Mapping[str, Any],
        definition,
        operation_id: str,
        normalized: Mapping[str, Any],
        operation_choices: Mapping[str, Any],
    ) -> None:
        live_values = ProviderControlService._operation_rows(
            status,
            "values",
            operation_id,
        )
        for descriptor in definition.inputs:
            input_id = str(descriptor.input_id)
            input_type = str(
                getattr(descriptor.input_type, "value", descriptor.input_type)
            )
            if input_type == "choice":
                continue
            published_value = input_id in live_values
            choice_rows = operation_choices.get(input_id)
            if choice_rows is not None and not isinstance(choice_rows, list):
                raise ProviderControlServiceError(
                    "approval_proof_stale",
                    "the provider approval proof is no longer available",
                    status=409,
                )
            published_choices = isinstance(choice_rows, list)
            if not published_value and not published_choices:
                if descriptor.required:
                    raise ProviderControlServiceError(
                        "approval_proof_stale",
                        "the provider approval proof is no longer available",
                        status=409,
                    )
                continue
            if input_id not in normalized:
                raise ProviderControlServiceError(
                    "approval_proof_mismatch",
                    "the provider approval proof changed before confirmation",
                    status=409,
                )
            selected = normalized[input_id]
            if published_value and selected != live_values[input_id]:
                raise ProviderControlServiceError(
                    "approval_proof_mismatch",
                    "the provider approval proof changed before confirmation",
                    status=409,
                )
            if published_choices:
                matches = [
                    row
                    for row in choice_rows
                    if isinstance(row, dict)
                    and set(row) == {"value", "label"}
                    and row.get("value") == selected
                ]
                if len(matches) != 1:
                    raise ProviderControlServiceError(
                        "approval_proof_mismatch",
                        "the provider approval proof changed before confirmation",
                        status=409,
                    )

    @staticmethod
    def _operation_rows(
        status: Mapping[str, Any],
        field: str,
        operation_id: str,
    ) -> dict[str, Any]:
        all_rows = status.get(field)
        rows = all_rows.get(operation_id, {}) if isinstance(all_rows, dict) else {}
        return rows if isinstance(rows, dict) else {}

    @staticmethod
    def _advertised_operation_id(value: Any) -> str | None:
        if not isinstance(value, dict):
            return None
        operation_id = value.get("operation_id")
        return operation_id if isinstance(operation_id, str) and operation_id else None

    @staticmethod
    def _action_id(value: str) -> str:
        action_id = str(value or "")
        if (
            not action_id
            or len(action_id) > 512
            or any(character in action_id for character in "\r\n\0")
        ):
            raise ProviderControlServiceError(
                "invalid_client_action_id",
                "client action identity is invalid",
                status=400,
            )
        return action_id

    @staticmethod
    def _validate_reservation(
        prepared: PreparedProviderOperation,
        reservation: ProviderOperationReservation,
    ) -> None:
        if not isinstance(reservation, ProviderOperationReservation):
            raise ProviderControlServiceError(
                "provider_operation_reservation_invalid",
                "provider operation reservation is invalid",
                status=409,
            )
        request = prepared.request
        if (
            reservation.operation_id != prepared.operation_id
            or reservation.binding_id != request.get("binding_id")
            or reservation.capability_generation
            != request.get("capability_generation")
            or bool(reservation.correlation)
            != bool(prepared.definition.receipt_required)
        ):
            raise ProviderControlServiceError(
                "provider_operation_reservation_stale",
                "provider operation reservation no longer matches live authority",
                status=409,
            )

    @staticmethod
    def _apply_manager_result(
        target: Mapping[str, Any],
        operation_id: str,
        result: ProviderOperationResult,
        result_payload: dict[str, Any],
        *,
        fork_parent_session_id: str | None,
        fork_reservation_token: str | None,
    ) -> None:
        manager = target.get("manager")
        result_status = str(getattr(result.status, "value", result.status))
        if manager is None or result_status not in {"applied", "in_progress"}:
            return
        if operation_id == "session.fork" and result_status == "applied":
            if fork_parent_session_id is None or fork_reservation_token is None:
                raise ProviderControlServiceError(
                    "fork_registration_unavailable",
                    "managed fork registration is unavailable",
                    status=503,
                )
            child = manager.register_fork(
                fork_parent_session_id,
                result,
                reservation_token=fork_reservation_token,
            )
            child_session_id = (
                child.get("session_id") if isinstance(child, dict) else None
            )
            if not isinstance(child_session_id, str) or not child_session_id:
                raise ProviderControlServiceError(
                    "action_outcome_unknown",
                    "managed fork registration returned no child session",
                    status=409,
                )
            public_result = result_payload.get("public_result")
            if not isinstance(public_result, dict):
                public_result = {}
                result_payload["public_result"] = public_result
            public_result["session_id"] = child_session_id
        manager.poll(str(target["session_id"]))
        if operation_id == "session.terminate" and result_status == "applied":
            manager.close(
                str(target["session_id"]),
                reason="terminated by provider operation",
            )
