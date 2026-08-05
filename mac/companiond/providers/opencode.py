from __future__ import annotations

import hashlib
import threading
import time
import urllib.parse
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Mapping

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
from .controls import (
    ControlChoice,
    ControlChoices,
    ControlContractError,
    ControlValue,
    OperationResultStatus,
    ProviderControlBinding,
    ProviderControlSnapshot,
    ProviderOperationResult,
    ProviderOperationCorrelation,
    ProviderSessionIdentity,
)
from .opencode_protocol import (
    PAIRLING_PERMISSION_RULESET,
    SUPPORTED_VERSIONS,
    OpenCodeAuthenticationError,
    OpenCodeCapabilityError,
    OpenCodeEndpointDenied,
    OpenCodeError,
    OpenCodeEventState,
    OpenCodeEventStream,
    OpenCodeHTTPTransport,
    OpenCodeLaunchError,
    OpenCodeOwnedServer,
    OpenCodeProtocolProfile,
    OpenCodeTransportError,
    fingerprint,
    has_pairling_permission_rules,
    model_from_session,
    resource_id,
    safe_choice,
    safe_int,
    safe_label,
    safe_number,
    sanitize_diff,
    sanitize_message_history,
    sanitize_session,
    sanitize_status,
    session_matches_directory,
)


SNAPSHOT_TTL_SECONDS = 10.0


class OpenCodeControlError(ControlContractError):
    pass


class OpenCodeControlDriver:
    """Normalized controls over one exact, owned OpenCode server binding."""
    safe_launch_profile = {
        "reviewed": True,
        "establishes_loopback_auth": True,
        "provider_id": "opencode",
    }

    def __init__(
        self,
        binding: ProviderControlBinding,
        *,
        owned_server: OpenCodeOwnedServer | Any | None = None,
        server_factory: Callable[[Path], OpenCodeOwnedServer] | None = None,
        clock: Callable[[], float] = time.time,
        blocked_reason: str | None = None,
    ):
        if binding.provider_id != "opencode":
            raise OpenCodeControlError(
                "OpenCode driver received another provider binding"
            )
        self.binding = binding
        self._clock = clock
        self._server_factory = server_factory
        self._server = owned_server
        self._blocked_reason = blocked_reason
        self._lock = threading.RLock()
        self._generation = 1
        self._last_signature: str | None = None
        self._session_native_ids: dict[str, str] = {}
        self._attached_native_ids: set[str] = set()
        self._models: dict[str, tuple[str, str]] = {}
        self._managed_native_id: str | None = None
        self._variants: dict[str, str] = {}
        self._model_catalog: dict[str, dict[str, Any]] = {}
        self._action_results: OrderedDict[
            str,
            tuple[str, int, str | None, ProviderOperationResult],
        ] = OrderedDict()
        cwd = Path(getattr(owned_server, "cwd", Path("/")))
        self.event_state = OpenCodeEventState(cwd)
        self._event_stream: OpenCodeEventStream | None = None
        if owned_server is not None:
            try:
                self._activate_event_stream(
                    start_background=hasattr(owned_server, "process")
                )
            except Exception:
                stream = self._event_stream
                self._event_stream = None
                self._server = None
                try:
                    if stream is not None:
                        stream.close()
                except Exception:
                    pass
                try:
                    owned_server.close()
                except Exception:
                    pass
                raise

    def close(self) -> None:
        with self._lock:
            stream = self._event_stream
            server = self._server
            self._event_stream = None
            self._server = None
        try:
            if stream is not None:
                stream.close()
        finally:
            if server is not None:
                server.close()

    def verify_managed_launch(
        self,
        launch_result: Mapping[str, Any],
    ) -> bool:
        """Re-probe the exact owned binding before durable registration."""
        try:
            server = self._require_server()
            verify_inputs = getattr(
                server,
                "verify_launch_inputs",
                None,
            )
            if not callable(verify_inputs) or not verify_inputs():
                return False
            process = getattr(server, "process", None)
            if process is None or process.poll() is not None:
                return False
            parsed = urllib.parse.urlsplit(server.transport.base_url)
            if (
                parsed.scheme != "http"
                or parsed.hostname != "127.0.0.1"
                or parsed.port is None
            ):
                return False
            original = server.profile
            fresh = server.transport.negotiate(
                expected_version=self.binding.provider_version,
                launch_digest=server.launch_digest,
            )
            if (
                self.binding.provider_channel != "stable"
                or fresh.version != self.binding.provider_version
                or fresh.launch_digest != server.launch_digest
                or fresh.capability_digest != original.capability_digest
            ):
                return False
            native_id = resource_id(
                str(
                    launch_result.get("native_session_id")
                    or launch_result.get("session_id")
                    or ""
                )
            )
            generation = launch_result.get("capability_generation")
            if (
                native_id not in self._attached_native_ids
                or not isinstance(generation, int)
                or isinstance(generation, bool)
                or generation != self._generation
            ):
                return False
            session = server.transport.get_session(native_id)
            return (
                session_matches_directory(session, server.cwd)
                and has_pairling_permission_rules(session)
            )
        except Exception:
            return False

    def launch_session(
        self,
        *,
        project: str,
        title: str,
        first_prompt: str = "",
    ) -> dict[str, Any]:
        workspace = _trusted_project_path(project)
        server = self._ensure_server(workspace)
        self._refresh_model_catalog(server)
        session = self.create_session(title=title or "Pairling OpenCode session")
        native_id = resource_id(session["id"])
        self._managed_native_id = native_id
        if first_prompt:
            message_id = _message_id(
                f"launch:{self.binding.binding_id}:{native_id}"
            )
            server.transport.prompt_async(
                native_id,
                text=first_prompt,
                message_id=message_id,
                model=self._models.get(native_id),
                variant=self._variants.get(native_id),
            )
        return {
            "native_session_id": native_id,
            "binding_id": self.binding.binding_id,
            "provider_version": self.binding.provider_version,
            "provider_channel": self.binding.provider_channel,
            "capability_generation": self._generation,
            "provider_cursor": self._provider_cursor(),
            "session": session,
        }

    def reconcile_session(
        self,
        session_truth: Mapping[str, Any],
    ) -> dict[str, Any]:
        if (
            session_truth.get("provider_id") != "opencode"
            or session_truth.get("binding_id")
            != self.binding.binding_id
        ):
            raise OpenCodeControlError(
                "OpenCode persisted binding identity is stale"
            )
        native_id = _native_session_id(
            str(session_truth.get("session_id") or ""),
            session_truth,
        )
        expected_generation = session_truth.get(
            "capability_generation"
        )
        if (
            isinstance(expected_generation, bool)
            or not isinstance(expected_generation, int)
            or expected_generation < 1
        ):
            raise OpenCodeControlError(
                "OpenCode persisted generation is invalid"
            )
        workspace = _workspace_from_truth(
            session_truth,
            require_exists=True,
        )
        if workspace is None:
            raise OpenCodeControlError(
                "OpenCode persisted workspace is unavailable"
            )
        self._ensure_server(workspace)
        self._generation = max(1, expected_generation - 1)
        self._last_signature = None
        self.resume_session(
            native_id,
            expected_directory=workspace,
        )
        if self._generation != expected_generation:
            raise OpenCodeControlError(
                "OpenCode reconciled generation is stale"
            )
        qualified_id = str(
            session_truth.get("session_id") or f"opencode:{native_id}"
        )
        self._session_native_ids[qualified_id] = native_id
        self._managed_native_id = native_id
        return {
            "native_session_id": native_id,
            "binding_id": self.binding.binding_id,
            "provider_version": self.binding.provider_version,
            "provider_channel": self.binding.provider_channel,
            "capability_generation": self._generation,
            "provider_cursor": self._provider_cursor(),
        }

    def poll_events(
        self,
        _provider_cursor: str | None = None,
    ) -> dict[str, Any]:
        self._require_server()
        target_native_id = self._managed_native_id
        if target_native_id is None and len(self._attached_native_ids) == 1:
            target_native_id = next(iter(self._attached_native_ids))
        events = [
            _managed_event(event, self._clock())
            for event in self.event_state.public_events()
            if _event_belongs_to_session(event, target_native_id)
        ]
        return {
            "events": events,
            "provider_cursor": self._provider_cursor(),
        }

    # Provider-native session discovery and history stay on typed methods.
    # No generic route or provider argv reaches this module.
    def list_sessions(self) -> list[dict[str, Any]]:
        server = self._require_server()
        _require_provider_operations(server, "session.list")
        return [
            sanitize_session(session, server.cwd)
            for session in server.transport.list_sessions()
            if session_matches_directory(session, server.cwd)
        ]

    def read_session(self, session_id: str) -> dict[str, Any]:
        server = self._require_server()
        _require_provider_operations(
            server,
            "session.get",
            "session.messages",
            "session.diff",
            "session.status",
        )
        native_id = resource_id(session_id)
        session = server.transport.get_session(native_id)
        if not session_matches_directory(session, server.cwd):
            raise OpenCodeControlError(
                "OpenCode session is outside the bound workspace"
            )
        result = sanitize_session(session, server.cwd)
        messages = sanitize_message_history(
            server.transport.messages(native_id), server.cwd
        )
        result["messages"] = messages
        result["usage"] = _aggregate_public_usage(messages)
        self._refresh_model_catalog(server)
        result["context"] = self._context_metadata(
            native_id,
            messages,
        )
        result["diff"] = sanitize_diff(
            server.transport.diff(native_id), server.cwd
        )
        status = server.transport.statuses().get(native_id)
        result["status"] = (
            sanitize_status(status)
            if isinstance(status, Mapping)
            else {"type": "unknown"}
        )
        return result

    def create_session(
        self,
        *,
        title: str = "Pairling OpenCode session",
        model: str | None = None,
    ) -> dict[str, Any]:
        server = self._require_server()
        _require_provider_operations(server, "session.create")
        selected = self._decode_model(model) if model is not None else None
        session = server.transport.create_session(
            title=title,
            model=selected,
        )
        native_id = _session_id_from_payload(session)
        if not session_matches_directory(session, server.cwd):
            raise OpenCodeControlError(
                "OpenCode created a session outside the bound workspace"
            )
        if not has_pairling_permission_rules(session):
            raise OpenCodeControlError(
                "OpenCode did not confirm guarded session permissions"
            )
        self._attached_native_ids.add(native_id)
        if selected is not None:
            self._models[native_id] = selected
        self._bump_generation()
        return sanitize_session(session, server.cwd)

    def resume_session(
        self,
        session_id: str,
        *,
        expected_directory: Path,
    ) -> dict[str, Any]:
        server = self._require_server()
        _require_provider_operations(
            server,
            "session.list",
            "session.get",
            "session.update",
        )
        native_id = resource_id(session_id)
        if (
            expected_directory.resolve(strict=False)
            != server.cwd.resolve(strict=False)
        ):
            raise OpenCodeControlError(
                "OpenCode resume workspace differs from the owned child"
            )
        if native_id in self._attached_native_ids:
            raise OpenCodeControlError(
                "OpenCode target session is already resumed"
            )
        self._revalidate_target_session(server, native_id)
        updated = server.transport.update_permissions(native_id)
        if not has_pairling_permission_rules(updated):
            raise OpenCodeControlError(
                "OpenCode did not apply guarded session permissions"
            )
        self._attached_native_ids.add(native_id)
        model = model_from_session(updated)
        if model is not None:
            self._models[native_id] = model
        self._bump_generation()
        return sanitize_session(updated, server.cwd)

    def fork_session(
        self,
        session_id: str,
        message_id: str | None = None,
    ) -> dict[str, Any]:
        server = self._require_server()
        _require_provider_operations(
            server,
            "session.list",
            "session.get",
            "session.fork",
            "session.update",
        )
        native_id = resource_id(session_id)
        if native_id not in self._attached_native_ids:
            raise OpenCodeControlError(
                "OpenCode source session is not controlled"
            )
        self._revalidate_target_session(server, native_id)
        forked = server.transport.fork_session(
            native_id,
            message_id=message_id,
        )
        forked_id = _session_id_from_payload(forked)
        if not session_matches_directory(forked, server.cwd):
            raise OpenCodeControlError(
                "OpenCode fork escaped the bound workspace"
            )
        updated = server.transport.update_permissions(forked_id)
        if not has_pairling_permission_rules(updated):
            raise OpenCodeControlError(
                "OpenCode did not guard the forked session"
            )
        self._attached_native_ids.add(forked_id)
        if native_id in self._models:
            self._models[forked_id] = self._models[native_id]
        if native_id in self._variants:
            self._variants[forked_id] = self._variants[native_id]
        self._bump_generation()
        return sanitize_session(updated, server.cwd)

    def snapshot(
        self,
        *,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderControlSnapshot:
        now = float(self._clock())
        with self._lock:
            try:
                if session_id is None:
                    return self._provider_snapshot(
                        self._require_server(), now
                    )
                if not isinstance(session_truth, dict):
                    return self._blocked_snapshot(
                        now, "opencode_session_truth_missing"
                    )
                if (
                    session_truth.get("provider_id") != "opencode"
                    or session_truth.get("session_id") != session_id
                ):
                    return self._blocked_snapshot(
                        now, "opencode_session_truth_mismatch"
                    )
                workspace = _workspace_from_truth(
                    session_truth,
                    require_exists=self._server is None,
                )
                if workspace is None:
                    return self._blocked_snapshot(
                        now, "opencode_workspace_unproven"
                    )
                server = self._ensure_server(workspace)
                native_id = _native_session_id(
                    session_id, session_truth
                )
                session = server.transport.get_session(native_id)
                if not session_matches_directory(session, server.cwd):
                    return self._blocked_snapshot(
                        now, "opencode_session_workspace_mismatch"
                    )
                self._session_native_ids[session_id] = native_id
                self._refresh_model_catalog(server)
                if native_id not in self._models:
                    model = model_from_session(session)
                    if model is not None:
                        self._models[native_id] = model
                return self._session_snapshot(
                    server,
                    now,
                    session_id,
                    native_id,
                )
            except OpenCodeError as exc:
                self._blocked_reason = exc.code
                return self._blocked_snapshot(now, exc.code)
            except (OpenCodeControlError, OSError):
                reason = "opencode_control_precondition_failed"
                self._blocked_reason = reason
                return self._blocked_snapshot(now, reason)

    def operation_correlation(
        self,
        *,
        operation_id: str,
        client_action_id: str,
        capability_generation: int,
        session_id: str | None,
        session_truth: dict[str, Any] | None,
    ) -> ProviderOperationCorrelation:
        if session_id is None:
            raise OpenCodeControlError(
                "OpenCode operation correlation requires a session"
            )
        snapshot = self.snapshot(
            session_id=session_id,
            session_truth=session_truth,
        )
        if (
            snapshot.capability_generation != capability_generation
            or operation_id not in snapshot.advertised_operations
        ):
            raise OpenCodeControlError(
                "OpenCode operation correlation proof is unavailable"
            )
        snapshot.validate(now=self._clock())
        return ProviderOperationCorrelation(
            _provider_operation_id(client_action_id),
            snapshot.provider_cursor,
        )

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
        with self._lock:
            self._validate_execution(
                operation_id=operation_id,
                input_payload=input_payload,
                binding_id=binding_id,
                capability_generation=capability_generation,
                session_id=session_id,
                client_action_id=client_action_id,
            )
            action_fingerprint = fingerprint({
                "operation_id": operation_id,
                "input": input_payload,
                "session_id": session_id,
            })
            cached = self._action_results.get(client_action_id)
            if cached is not None:
                if provider_correlation is None:
                    raise OpenCodeControlError(
                        "OpenCode client action id was already used"
                    )
                if (
                    cached[0] != action_fingerprint
                    or cached[1] != capability_generation
                    or cached[2] != session_id
                    or cached[3].operation_id != operation_id
                ):
                    raise OpenCodeControlError(
                        "OpenCode client action id was already used"
                    )
                return cached[3]
            if prepared_attachments:
                # OpenCode accepts URL/file parts, but Pairling has no reviewed
                # byte-upload mapping yet. Never turn a verified handle into a
                # host file URI or arbitrary URL.
                raise OpenCodeControlError(
                    "OpenCode prepared attachments are not supported"
                )
            server = self._require_server()
            native_id = self._session_native_ids.get(session_id or "")
            expected_operation_id = _provider_operation_id(
                client_action_id
            )
            if provider_correlation is None:
                provider_correlation = ProviderOperationCorrelation(
                    expected_operation_id,
                    self._provider_cursor(),
                )
            elif (
                not isinstance(
                    provider_correlation,
                    ProviderOperationCorrelation,
                )
                or provider_correlation.provider_operation_id
                != expected_operation_id
            ):
                raise OpenCodeControlError(
                    "OpenCode operation correlation proof is unavailable"
                )

            if operation_id == "session.resume":
                public = {
                    "session": self.resume_session(
                        input_payload.get("target_session"),
                        expected_directory=server.cwd,
                    ),
                    "client_action_id": client_action_id,
                }
                status = OperationResultStatus.APPLIED
            elif operation_id == "session.fork":
                target_native_id = self._target_session_id(
                    input_payload.get("target_session")
                )
                if native_id is None or target_native_id != native_id:
                    raise OpenCodeControlError(
                        "OpenCode fork target is not the current bound session"
                    )
                public = {
                    "session": self.fork_session(target_native_id),
                    "client_action_id": client_action_id,
                }
                status = OperationResultStatus.APPLIED
            elif operation_id == "session.model.set":
                native_id = self._require_attached(native_id)
                model_value = input_payload["model"]
                self._models[native_id] = self._decode_model(model_value)
                available_variants = self._model_catalog.get(
                    model_value, {}
                ).get("variants", ())
                if self._variants.get(native_id) not in available_variants:
                    self._variants.pop(native_id, None)
                self._bump_generation()
                public = {
                    "model": model_value,
                    "client_action_id": client_action_id,
                }
                status = OperationResultStatus.APPLIED
            elif operation_id == "session.reasoning.set":
                native_id = self._require_attached(native_id)
                variant = input_payload["reasoning"]
                if variant not in self._variant_choices(native_id):
                    raise OpenCodeControlError(
                        "OpenCode variant is no longer available"
                    )
                self._variants[native_id] = variant
                self._bump_generation()
                public = {
                    "reasoning": variant,
                    "client_action_id": client_action_id,
                }
                status = OperationResultStatus.APPLIED
            elif operation_id == "session.prompt.send":
                native_id = self._require_attached(native_id)
                message_id = _message_id(client_action_id)
                server.transport.prompt_async(
                    native_id,
                    text=input_payload["prompt"],
                    message_id=message_id,
                    model=self._models.get(native_id),
                    variant=self._variants.get(native_id),
                )
                public = {
                    "accepted": True,
                    "message_id": message_id,
                    "client_action_id": client_action_id,
                }
                status = OperationResultStatus.APPLIED
            elif operation_id == "session.turn.steer":
                native_id = self._require_attached(native_id)
                message_id = _message_id(client_action_id)
                server.transport.queue_message(
                    native_id,
                    text=input_payload["instruction"],
                    message_id=message_id,
                    model=self._models.get(native_id),
                    variant=self._variants.get(native_id),
                )
                public = {
                    "queued": True,
                    "message_id": message_id,
                    "client_action_id": client_action_id,
                }
                status = OperationResultStatus.APPLIED
            elif operation_id == "session.turn.interrupt":
                native_id = self._require_attached(native_id)
                accepted = server.transport.abort(native_id)
                public = {
                    "accepted": accepted,
                    "client_action_id": client_action_id,
                }
                status = (
                    OperationResultStatus.APPLIED
                    if accepted
                    else OperationResultStatus.OUTCOME_UNKNOWN
                )
            elif operation_id == "session.approval.decide":
                native_id = self._require_attached(native_id)
                approval_id = input_payload["approval_id"]
                pending = self.event_state.pending_permissions.get(
                    approval_id
                )
                if (
                    pending is None
                    or pending.get("sessionID") != native_id
                ):
                    raise OpenCodeControlError(
                        "OpenCode permission request is stale or mismatched"
                    )
                accepted = server.transport.respond_permission(
                    native_id,
                    approval_id,
                    input_payload["decision"],
                )
                if not accepted:
                    raise OpenCodeControlError(
                        "OpenCode did not accept the permission decision"
                    )
                self.event_state.resolve_permission(approval_id)
                self._bump_generation()
                public = {
                    "approval_id": approval_id,
                    "decision": input_payload["decision"],
                    "client_action_id": client_action_id,
                }
                status = OperationResultStatus.APPLIED
            elif operation_id == "session.question.answer":
                native_id = self._require_attached(native_id)
                question_request_id = input_payload["question_request_id"]
                pending_question = self.event_state.pending_questions.get(
                    question_request_id
                )
                if (
                    pending_question is None
                    or pending_question.get("sessionID") != native_id
                ):
                    raise OpenCodeControlError(
                        "OpenCode question request is stale or mismatched"
                    )
                provider_answers = _validated_questionnaire_answers(
                    pending_question,
                    input_payload["decision"],
                    input_payload.get("answers"),
                )
                accepted = server.transport.respond_question(
                    question_request_id,
                    decision=input_payload["decision"],
                    answers=provider_answers,
                )
                if not accepted:
                    raise OpenCodeControlError(
                        "OpenCode did not accept the question response"
                    )
                self.event_state.resolve_question(question_request_id)
                self._bump_generation()
                public = {
                    "question_request_id": question_request_id,
                    "decision": input_payload["decision"],
                    "answer_count": len(provider_answers),
                    "client_action_id": client_action_id,
                }
                status = OperationResultStatus.APPLIED
            elif operation_id == "provider.auth.read":
                public = self._public_auth_state(server)
                status = OperationResultStatus.APPLIED
            elif operation_id == "provider.usage.read":
                public = self._public_usage(server)
                status = OperationResultStatus.APPLIED
            elif operation_id == "provider.diagnostics.read":
                public = self._public_diagnostics(server)
                status = OperationResultStatus.APPLIED
            else:
                raise OpenCodeControlError(
                    "OpenCode operation is outside the safe driver"
                )
            result = ProviderOperationResult(
                operation_id=operation_id,
                provider_operation_id=provider_correlation.provider_operation_id,
                status=status,
                public_result=public,
                provider_cursor=provider_correlation.provider_cursor,
            )
            self._action_results[client_action_id] = (
                action_fingerprint,
                capability_generation,
                session_id,
                result,
            )
            self._action_results.move_to_end(client_action_id)
            while len(self._action_results) > 2048:
                self._action_results.popitem(last=False)
            return result
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
        del session_truth
        if (
            binding_id != self.binding.binding_id
            or not isinstance(
                provider_correlation,
                ProviderOperationCorrelation,
            )
        ):
            return None
        with self._lock:
            cached = self._action_results.get(client_action_id)
        if (
            cached is None
            or cached[1] != capability_generation
            or cached[2] != session_id
            or cached[3].operation_id != operation_id
            or cached[3].provider_operation_id
            != provider_correlation.provider_operation_id
            or cached[3].provider_cursor
            != provider_correlation.provider_cursor
            or cached[3].status
            not in {
                OperationResultStatus.APPLIED,
                OperationResultStatus.REJECTED,
            }
        ):
            return None
        return cached[3]


    def _ensure_server(self, workspace: Path):
        resolved = workspace.expanduser().resolve(
            strict=self._server is None
        )
        if self._server is not None:
            if (
                self._server.cwd.resolve(strict=False)
                != resolved.resolve(strict=False)
            ):
                raise OpenCodeControlError(
                    "OpenCode driver is bound to another workspace"
                )
            return self._server
        if self._blocked_reason is not None:
            raise OpenCodeCapabilityError(self._blocked_reason)
        if self._server_factory is None:
            raise OpenCodeCapabilityError(
                "OpenCode owned child server is unavailable"
            )
        server = self._server_factory(resolved)
        if server.profile.version != self.binding.provider_version:
            server.close()
            raise OpenCodeCapabilityError(
                "OpenCode child version differs from its binding"
            )
        verify_inputs = getattr(server, "verify_launch_inputs", None)
        if not callable(verify_inputs) or not verify_inputs():
            server.close()
            raise OpenCodeCapabilityError(
                "OpenCode launch inputs changed during activation"
            )
        self._server = server
        self.event_state = OpenCodeEventState(server.cwd)
        try:
            self._activate_event_stream(start_background=True)
        except Exception:
            stream = self._event_stream
            self._event_stream = None
            self._server = None
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass
            try:
                server.close()
            except Exception:
                pass
            raise
        return server

    def _activate_event_stream(self, *, start_background: bool) -> None:
        server = self._require_server()
        self._event_stream = OpenCodeEventStream(
            server.transport, self.event_state
        )
        try:
            self._event_stream.reconnect()
        except OpenCodeError:
            pass
        if start_background:
            self._event_stream.start()

    def _require_server(self):
        if self._server is None:
            if self._blocked_reason:
                raise OpenCodeCapabilityError(self._blocked_reason)
            raise OpenCodeCapabilityError(
                "OpenCode owned child server has not been proven"
            )
        server = self._server
        if (
            isinstance(server, OpenCodeOwnedServer)
            and not server.verify_config_inputs()
        ):
            self._blocked_reason = "opencode_config_input_changed"
            self.close()
            raise OpenCodeCapabilityError(self._blocked_reason)
        return server

    def _provider_snapshot(
        self,
        server,
        now: float,
    ) -> ProviderControlSnapshot:
        operations = tuple(
            operation_id
            for operation_id in (
                "provider.auth.read",
                "provider.usage.read",
                "provider.diagnostics.read",
            )
            if server.profile.supports_pairling_operation(operation_id)
        )
        return self._make_snapshot(
            now=now,
            operations=operations,
            values=(),
            choices=(),
            blocked_reason=None,
        )

    def _session_snapshot(
        self,
        server,
        now: float,
        session_id: str,
        native_id: str,
    ) -> ProviderControlSnapshot:
        identity = ProviderSessionIdentity(
            "opencode",
            session_id,
            self.binding.binding_id,
            self._generation,
        )
        if native_id not in self._attached_native_ids:
            target_choices: tuple[ControlChoice, ...] = ()
            if server.profile.supports_pairling_operation(
                "session.resume"
            ):
                target_choices = tuple(
                    ControlChoice(target_id, label)
                    for target_id, label
                    in self._target_session_choice_rows(server)
                    if target_id not in self._attached_native_ids
                )
            operations = ("session.resume",) if target_choices else ()
            return self._make_snapshot(
                now=now,
                operations=operations,
                values=tuple(
                    ControlValue(operation_id, "session", identity)
                    for operation_id in operations
                ),
                choices=(
                    (
                        ControlChoices(
                            "session.resume",
                            "target_session",
                            target_choices,
                        ),
                    )
                    if target_choices
                    else ()
                ),
                blocked_reason=(
                    None
                    if operations
                    else "opencode_resume_unavailable"
                ),
            )

        operations: list[str] = []
        for operation_id in (
            "session.prompt.send",
            "session.turn.steer",
            "session.turn.interrupt",
        ):
            if server.profile.supports_pairling_operation(operation_id):
                operations.append(operation_id)
        fork_choices: tuple[ControlChoice, ...] = ()
        if server.profile.supports_pairling_operation("session.fork"):
            fork_choices = tuple(
                ControlChoice(target_id, label)
                for target_id, label
                in self._target_session_choice_rows(server)
                if target_id == native_id
            )
            if fork_choices:
                operations.append("session.fork")
        if (
            self._model_catalog
            and server.profile.supports_pairling_operation(
                "session.model.set"
            )
        ):
            operations.append("session.model.set")
        variants = self._variant_choices(native_id)
        if variants and server.profile.supports_pairling_operation(
            "session.reasoning.set"
        ):
            operations.append("session.reasoning.set")
        pending = {
            request_id: item
            for request_id, item in self.event_state.pending_permissions.items()
            if item.get("sessionID") == native_id
        }
        if pending and server.profile.supports_pairling_operation(
            "session.approval.decide"
        ):
            operations.append("session.approval.decide")
        pending_question: tuple[str, dict[str, Any]] | None = None
        if server.profile.supports_pairling_operation(
            "session.question.answer"
        ):
            matching_questions = sorted(
                (
                    request_id,
                    item,
                )
                for request_id, item
                in self.event_state.pending_questions.items()
                if item.get("sessionID") == native_id
            )
            if matching_questions:
                pending_question = matching_questions[0]
                operations.append("session.question.answer")

        values = [
            ControlValue(operation_id, "session", identity)
            for operation_id in operations
        ]
        selected_model = self._encoded_model(
            self._models.get(native_id)
        )
        if (
            "session.model.set" in operations
            and selected_model in self._model_catalog
        ):
            values.append(
                ControlValue(
                    "session.model.set", "model", selected_model
                )
            )
        if (
            "session.reasoning.set" in operations
            and self._variants.get(native_id) in variants
        ):
            values.append(
                ControlValue(
                    "session.reasoning.set",
                    "reasoning",
                    self._variants[native_id],
                )
            )

        if pending_question is not None:
            values.append(
                ControlValue(
                    "session.question.answer",
                    "answers",
                    _questionnaire_rows(pending_question[1]),
                )
            )
        choices: list[ControlChoices] = []
        if fork_choices:
            choices.append(
                ControlChoices(
                    "session.fork",
                    "target_session",
                    fork_choices,
                )
            )
        if "session.model.set" in operations:
            choices.append(
                ControlChoices(
                    "session.model.set",
                    "model",
                    tuple(
                        ControlChoice(model_id, data["label"])
                        for model_id, data in sorted(
                            self._model_catalog.items()
                        )
                    ),
                )
            )
        if "session.reasoning.set" in operations:
            choices.append(
                ControlChoices(
                    "session.reasoning.set",
                    "reasoning",
                    tuple(
                        ControlChoice(value, value)
                        for value in variants
                    ),
                )
            )
        if "session.approval.decide" in operations:
            choices.append(
                ControlChoices(
                    "session.approval.decide",
                    "approval_id",
                    tuple(
                        ControlChoice(
                            request_id,
                            _permission_label(item),
                        )
                        for request_id, item in sorted(
                            pending.items()
                        )
                    ),
                )
            )
            choices.append(
                ControlChoices(
                    "session.approval.decide",
                    "decision",
                    (
                        ControlChoice("once", "Allow once"),
                        ControlChoice(
                            "always",
                            "Allow for this OpenCode run",
                        ),
                        ControlChoice("reject", "Reject"),
                    ),
                )
            )
        if pending_question is not None:
            question_request_id, _ = pending_question
            choices.append(
                ControlChoices(
                    "session.question.answer",
                    "question_request_id",
                    (
                        ControlChoice(
                            question_request_id,
                            "Pending OpenCode question",
                        ),
                    ),
                )
            )
            choices.append(
                ControlChoices(
                    "session.question.answer",
                    "decision",
                    (
                        ControlChoice("accept", "Submit answers"),
                        ControlChoice("cancel", "Cancel request"),
                    ),
                )
            )
        return self._make_snapshot(
            now=now,
            operations=tuple(operations),
            values=tuple(values),
            choices=tuple(choices),
            blocked_reason=None,
        )

    def _blocked_snapshot(
        self,
        now: float,
        reason: str,
    ) -> ProviderControlSnapshot:
        return self._make_snapshot(
            now=now,
            operations=(),
            values=(),
            choices=(),
            blocked_reason=reason,
        )

    def _make_snapshot(
        self,
        *,
        now: float,
        operations: tuple[str, ...],
        values: tuple[ControlValue, ...],
        choices: tuple[ControlChoices, ...],
        blocked_reason: str | None,
    ) -> ProviderControlSnapshot:
        signature = fingerprint(
            {
                "operations": operations,
                "values": [
                    (
                        item.operation_id,
                        item.input_id,
                        _signature_value(item.value),
                    )
                    for item in values
                ],
                "choices": [
                    (
                        item.operation_id,
                        item.input_id,
                        [
                            (choice.value, choice.label)
                            for choice in item.choices
                        ],
                    )
                    for item in choices
                ],
                "blocked": blocked_reason,
            }
        )
        if (
            self._last_signature is not None
            and signature != self._last_signature
        ):
            self._generation += 1
            values = tuple(
                ControlValue(
                    item.operation_id,
                    item.input_id,
                    ProviderSessionIdentity(
                        item.value.provider_id,
                        item.value.session_id,
                        item.value.binding_id,
                        self._generation,
                    )
                    if isinstance(
                        item.value, ProviderSessionIdentity
                    )
                    else item.value,
                )
                for item in values
            )
        self._last_signature = signature
        return ProviderControlSnapshot(
            provider_id=self.binding.provider_id,
            provider_version=self.binding.provider_version,
            provider_channel=self.binding.provider_channel,
            binding_id=self.binding.binding_id,
            capability_generation=self._generation,
            observed_at=now,
            valid_until=now + SNAPSHOT_TTL_SECONDS,
            advertised_operations=operations,
            values=values,
            choices=choices,
            blocked_reason=blocked_reason,
            provider_cursor=self._provider_cursor(),
        )

    def _refresh_model_catalog(self, server) -> None:
        available = frozenset(server.profile.operation_ids)
        if not {"provider.list", "config.providers"}.issubset(available):
            self._model_catalog = {}
            return
        payload = server.transport.providers()
        configured = server.transport.config_providers()
        connected = (
            set(payload.get("connected") or ())
            if isinstance(payload, Mapping)
            else set()
        )
        defaults: dict[str, Any] = {}
        if isinstance(configured.get("default"), Mapping):
            defaults.update(configured["default"])
        if isinstance(payload.get("default"), Mapping):
            defaults.update(payload["default"])
        providers = payload.get("all")
        catalog: dict[str, dict[str, Any]] = {}
        if isinstance(providers, list):
            for provider in providers:
                if not isinstance(provider, Mapping):
                    continue
                provider_id = provider.get("id")
                models = provider.get("models")
                if (
                    not isinstance(provider_id, str)
                    or not isinstance(models, Mapping)
                ):
                    continue
                if connected and provider_id not in connected:
                    continue
                for model_key, model in models.items():
                    if (
                        not isinstance(model_key, str)
                        or not isinstance(model, Mapping)
                    ):
                        continue
                    model_id = (
                        model.get("id")
                        if isinstance(model.get("id"), str)
                        else model_key
                    )
                    encoded = f"{provider_id}/{model_id}"
                    if (
                        len(encoded) > 256
                        or not safe_choice(encoded)
                    ):
                        continue
                    label = (
                        model.get("name")
                        if isinstance(model.get("name"), str)
                        else model_id
                    )
                    variants = model.get("variants")
                    variant_names = (
                        tuple(
                            sorted(
                                value
                                for value in variants
                                if isinstance(value, str)
                                and safe_choice(value)
                                and len(value) <= 128
                            )
                        )
                        if isinstance(variants, Mapping)
                        else ()
                    )
                    catalog[encoded] = {
                        "label": safe_label(
                            f"{label} ({provider_id})"
                        ),
                        "provider_id": provider_id,
                        "model_id": model_id,
                        "variants": variant_names,
                        "context_limit": (
                            safe_int(model["limit"].get("context"))
                            if isinstance(model.get("limit"), Mapping)
                            else 0
                        ),
                        "output_limit": (
                            safe_int(model["limit"].get("output"))
                            if isinstance(model.get("limit"), Mapping)
                            else 0
                        ),
                        "default": (
                            defaults.get(provider_id) == model_id
                        ),
                    }
        self._model_catalog = catalog

    def _context_metadata(
        self,
        native_id: str,
        messages: list[dict[str, Any]],
    ) -> dict[str, Any]:
        context: dict[str, Any] = {}
        encoded_model = self._encoded_model(self._models.get(native_id))
        model = (
            self._model_catalog.get(encoded_model)
            if encoded_model is not None
            else None
        )
        if isinstance(model, Mapping):
            context["model"] = encoded_model
            if safe_int(model.get("context_limit")):
                context["context_window_tokens"] = safe_int(
                    model.get("context_limit")
                )
            if safe_int(model.get("output_limit")):
                context["output_limit_tokens"] = safe_int(
                    model.get("output_limit")
                )
        for message in reversed(messages):
            info = message.get("info")
            if (
                not isinstance(info, Mapping)
                or info.get("role") != "assistant"
                or not isinstance(info.get("tokens"), Mapping)
            ):
                continue
            tokens = info["tokens"]
            context["latest_input_tokens"] = safe_int(
                tokens.get("input")
            )
            context["latest_output_tokens"] = safe_int(
                tokens.get("output")
            )
            context["latest_reasoning_tokens"] = safe_int(
                tokens.get("reasoning")
            )
            cache = tokens.get("cache")
            if isinstance(cache, Mapping):
                context["latest_cache_read_tokens"] = safe_int(
                    cache.get("read")
                )
            break
        return context


    def _validate_execution(
        self,
        *,
        operation_id: str,
        input_payload: dict[str, Any],
        binding_id: str,
        capability_generation: int,
        session_id: str | None,
        client_action_id: str,
    ) -> None:
        if binding_id != self.binding.binding_id:
            raise OpenCodeControlError("OpenCode binding is stale")
        if capability_generation != self._generation:
            raise OpenCodeControlError(
                "OpenCode capability generation is stale"
            )
        if (
            not isinstance(client_action_id, str)
            or not client_action_id
            or len(client_action_id) > 512
        ):
            raise OpenCodeControlError(
                "OpenCode client action id is invalid"
            )
        if operation_id.startswith("session."):
            if (
                session_id is None
                or self._session_native_ids.get(session_id) is None
            ):
                raise OpenCodeControlError(
                    "OpenCode session was not proven by a fresh snapshot"
                )
            try:
                identity = ProviderSessionIdentity.from_payload(
                    input_payload.get("session")
                )
            except Exception as exc:
                raise OpenCodeControlError(
                    "OpenCode operation has invalid session identity"
                ) from exc
            if (
                identity.provider_id != "opencode"
                or identity.session_id != session_id
                or identity.binding_id != binding_id
                or identity.capability_generation
                != capability_generation
            ):
                raise OpenCodeControlError(
                    "OpenCode operation session identity is stale"
                )
        if operation_id == "session.resume":
            native = self._session_native_ids.get(session_id or "")
            if native in self._attached_native_ids:
                raise OpenCodeControlError(
                    "OpenCode session is already resumed"
                )
        elif operation_id.startswith("session."):
            if operation_id != "session.resume":
                self._require_attached(
                    self._session_native_ids.get(session_id or "")
                )


    def _decode_model(
        self,
        value: str | None,
    ) -> tuple[str, str] | None:
        if value is None:
            return None
        item = self._model_catalog.get(value)
        if item is None:
            raise OpenCodeControlError(
                "OpenCode model is no longer available"
            )
        return item["provider_id"], item["model_id"]

    @staticmethod
    def _encoded_model(
        value: tuple[str, str] | None,
    ) -> str | None:
        return f"{value[0]}/{value[1]}" if value else None

    def _variant_choices(self, native_id: str) -> tuple[str, ...]:
        model = self._encoded_model(self._models.get(native_id))
        item = self._model_catalog.get(model or "")
        return tuple(item.get("variants") or ()) if item else ()

    def _target_session_choice_rows(
        self,
        server,
    ) -> tuple[tuple[str, str], ...]:
        try:
            _require_provider_operations(server, "session.list")
            sessions = server.transport.list_sessions()
        except (OpenCodeControlError, OpenCodeError, OSError):
            return ()
        rows: list[tuple[str, str]] = []
        seen: set[str] = set()
        for session in sessions:
            if not isinstance(session, Mapping):
                continue
            try:
                native_id = _session_id_from_payload(session)
            except OpenCodeError:
                continue
            if (
                native_id in seen
                or not session_matches_directory(session, server.cwd)
            ):
                continue
            label = safe_label(
                f"OpenCode session {native_id[:24]}"
            )
            rows.append((native_id, label))
            seen.add(native_id)
        rows.sort(key=lambda row: row[0])
        return tuple(rows)

    @staticmethod
    def _target_session_id(value: Any) -> str:
        try:
            return resource_id(value)
        except OpenCodeError as exc:
            raise OpenCodeControlError(
                "OpenCode target session identity is malformed"
            ) from exc

    def _revalidate_target_session(self, server, native_id: str) -> None:
        target_id = self._target_session_id(native_id)
        listed = False
        for session in server.transport.list_sessions():
            if not isinstance(session, Mapping):
                continue
            try:
                candidate_id = _session_id_from_payload(session)
            except OpenCodeError:
                continue
            if (
                candidate_id == target_id
                and session_matches_directory(session, server.cwd)
            ):
                listed = True
                break
        if not listed:
            raise OpenCodeControlError(
                "OpenCode target session is stale or outside the owned workspace"
            )
        session = server.transport.get_session(target_id)
        try:
            exact_id = _session_id_from_payload(session)
        except OpenCodeError as exc:
            raise OpenCodeControlError(
                "OpenCode target session no longer exists"
            ) from exc
        if (
            exact_id != target_id
            or not session_matches_directory(session, server.cwd)
        ):
            raise OpenCodeControlError(
                "OpenCode target session ownership changed"
            )

    def _require_attached(self, native_id: str | None) -> str:
        if (
            native_id is None
            or native_id not in self._attached_native_ids
        ):
            raise OpenCodeControlError(
                "OpenCode session is not owned or safely resumed"
            )
        return native_id

    def _bump_generation(self) -> None:
        self._generation += 1
        self._last_signature = None

    def _provider_cursor(self) -> str:
        return f"opencode:{self.event_state.cursor}:{self._generation}"

    @staticmethod
    def _public_auth_state(server) -> dict[str, Any]:
        providers = server.transport.providers()
        connected = (
            providers.get("connected")
            if isinstance(providers, Mapping)
            else []
        )
        return {
            "connected_provider_ids": sorted(
                value
                for value in connected or []
                if isinstance(value, str) and safe_choice(value)
            ),
            "credentials_exposed": False,
        }

    @staticmethod
    def _public_usage(server) -> dict[str, Any]:
        totals: dict[str, Any] = {
            "cost": 0.0,
            "input_tokens": 0,
            "output_tokens": 0,
            "reasoning_tokens": 0,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
        }
        counted = 0
        for session in server.transport.list_sessions()[:50]:
            if (
                not isinstance(session, Mapping)
                or not session_matches_directory(
                    session, server.cwd
                )
            ):
                continue
            session_id = session.get("id")
            if not isinstance(session_id, str):
                continue
            for message in server.transport.messages(
                session_id, limit=100
            ):
                info = (
                    message.get("info")
                    if isinstance(message, Mapping)
                    else None
                )
                if (
                    not isinstance(info, Mapping)
                    or info.get("role") != "assistant"
                ):
                    continue
                counted += 1
                totals["cost"] += safe_number(info.get("cost"))
                tokens = info.get("tokens")
                if not isinstance(tokens, Mapping):
                    continue
                totals["input_tokens"] += safe_int(
                    tokens.get("input")
                )
                totals["output_tokens"] += safe_int(
                    tokens.get("output")
                )
                totals["reasoning_tokens"] += safe_int(
                    tokens.get("reasoning")
                )
                cache = tokens.get("cache")
                if isinstance(cache, Mapping):
                    totals["cache_read_tokens"] += safe_int(
                        cache.get("read")
                    )
                    totals["cache_write_tokens"] += safe_int(
                        cache.get("write")
                    )
        totals["assistant_messages"] = counted
        totals["cost"] = round(totals["cost"], 8)
        return totals

    @staticmethod
    def _public_diagnostics(server) -> dict[str, Any]:
        statuses = server.transport.statuses()
        return {
            "healthy": True,
            "version": server.profile.version,
            "capability_digest": server.profile.capability_digest,
            "launch_digest": server.launch_digest,
            "workspace": "<workspace>",
            "session_status": {
                session_id: sanitize_status(status)
                for session_id, status in statuses.items()
                if isinstance(session_id, str)
                and isinstance(status, Mapping)
            },
            "transport": "authenticated_loopback_http_sse",
            "unsafe_endpoints_exposed": False,
        }


_FALLBACK_DESCRIPTOR = ProviderDescriptor(
    provider_id="opencode",
    display_name="OpenCode",
    kind="terminal_cli",
    builtin=False,
    docs_url="https://opencode.ai/docs/server/",
    adapter_depth="deep",
)
_ENTRY = registry_data.entry_or_none("opencode")


class OpenCodeProviderAdapter(ProviderAdapter):
    descriptor = (
        registry_data.descriptor_for(_ENTRY)
        if _ENTRY
        else _FALLBACK_DESCRIPTOR
    )

    def __init__(self, home: Path | None = None):
        self.home = home or Path.home()
        self._drivers: dict[
            ProviderControlBinding, OpenCodeControlDriver
        ] = {}
        self._driver_lock = threading.RLock()

    @property
    def candidates(self) -> list[Path]:
        configured = (
            registry_data.candidate_paths(_ENTRY, home=self.home)
            if _ENTRY is not None and _ENTRY.binary_candidates
            else []
        )
        return [
            self.home / ".opencode" / "bin" / "opencode",
            *configured,
            Path("/opt/homebrew/bin/opencode"),
            Path("/usr/local/bin/opencode"),
        ]

    def supports(self, capability: str) -> bool:
        return capability in {
            "detect",
            "status",
            "list_sessions",
            "read_transcript",
            "spawn",
            "resume",
            "fork",
            "live_state",
            "send_text",
            "interrupt",
            "model_choices",
            "permissions",
            "usage",
            "provider_native_control",
        }

    def probe(self) -> ProviderProbeResult:
        env_var = (
            _ENTRY.env_override
            if _ENTRY is not None
            else "PAIRLING_OPENCODE_BIN"
        )
        resolved = resolve_executable(
            "opencode", self.candidates, env_var=env_var
        )
        version = cli_version(resolved.path) if resolved else None
        supported = (
            resolved is not None and version in SUPPORTED_VERSIONS
        )
        config_candidates = (
            registry_data.config_file_paths(
                _ENTRY, home=self.home
            )
            if _ENTRY is not None
            else [
                self.home
                / ".config"
                / "opencode"
                / "opencode.json"
            ]
        )
        config_path = (
            config_candidates[0] if config_candidates else None
        )
        notes: list[str] = []
        setup_actions: list[str] = []
        if resolved is None:
            notes.append(
                "OpenCode CLI not found in configured, known, or daemon PATH locations"
            )
            setup_actions.append("install_cli")
        elif not supported:
            notes.append(
                "Installed OpenCode version is outside the exact native-driver table"
            )
            setup_actions.append("install_supported_version")
        else:
            notes.append(
                "Native control starts only in a Pairling-owned authenticated child"
            )
        capabilities = (
            (
                "detect",
                "status",
                "list_sessions",
                "read_transcript",
                "spawn",
                "resume",
                "fork",
                "live_state",
                "send_text",
                "interrupt",
                "model_choices",
                "permissions",
                "usage",
                "provider_native_control",
            )
            if supported
            else ("detect", "status")
        )
        availability = ProviderAvailability(
            provider_id=self.descriptor.provider_id,
            display_name=self.descriptor.display_name,
            kind=self.descriptor.kind,
            installed=resolved is not None,
            usable=supported,
            launchable=supported,
            # The manager recognizes this state only together with the
            # reviewed safe_launch_profile, then requires a post-launch
            # verify_managed_launch re-probe before durable registration.
            auth_state=(
                "owned_child_required" if supported else "unavailable"
            ),
            config_state=(
                "ready"
                if config_path and config_path.is_file()
                else "default"
            ),
            readable_sessions=0,
            live_sessions=0,
            controllable_sessions=0,
            capabilities=capabilities,
            setup_actions=tuple(setup_actions),
            notes=tuple(notes),
        )
        return ProviderProbeResult(
            descriptor=self.descriptor,
            availability=availability,
            diagnostics=ProviderDiagnostics(
                cli_path=str(resolved.path) if resolved else None,
                cli_path_source=(
                    resolved.source if resolved else None
                ),
                version=version,
                config_path=(
                    str(config_path) if config_path else None
                ),
                config_exists=(
                    config_path.is_file() if config_path else None
                ),
            ),
            observed_at=time.time(),
        )

    def create_control_driver(
        self,
        binding: ProviderControlBinding,
    ) -> OpenCodeControlDriver | None:
        if binding.provider_id != "opencode":
            return None
        with self._driver_lock:
            existing = self._drivers.get(binding)
            if existing is not None:
                return existing
            env_var = (
                _ENTRY.env_override
                if _ENTRY is not None
                else "PAIRLING_OPENCODE_BIN"
            )
            resolved = resolve_executable(
                "opencode", self.candidates, env_var=env_var
            )
            observed_version = (
                cli_version(resolved.path) if resolved else None
            )
            blocked_reason = None
            factory = None
            if resolved is None:
                blocked_reason = "opencode_cli_missing"
            elif binding.provider_version != observed_version:
                blocked_reason = "opencode_binding_version_mismatch"
            elif observed_version not in SUPPORTED_VERSIONS:
                blocked_reason = "opencode_version_unsupported"
            elif binding.provider_channel != "stable":
                blocked_reason = "opencode_channel_unsupported"
            else:
                executable = resolved.path
                factory = lambda cwd: OpenCodeOwnedServer.start(
                    executable,
                    cwd=cwd,
                    expected_version=observed_version,
                )
            driver = OpenCodeControlDriver(
                binding,
                server_factory=factory,
                blocked_reason=blocked_reason,
            )
            self._drivers[binding] = driver
            return driver


def _require_provider_operations(
    server: OpenCodeOwnedServer | Any,
    *operation_ids: str,
) -> None:
    available = frozenset(server.profile.operation_ids)
    missing = sorted(set(operation_ids) - available)
    if missing:
        raise OpenCodeCapabilityError(
            "OpenCode runtime did not negotiate required operations: "
            + ", ".join(missing)
        )


def _aggregate_public_usage(
    messages: list[dict[str, Any]],
) -> dict[str, Any]:
    totals: dict[str, Any] = {
        "assistant_messages": 0,
        "cost": 0.0,
        "input_tokens": 0,
        "output_tokens": 0,
        "reasoning_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
    }
    for message in messages:
        info = message.get("info")
        if (
            not isinstance(info, Mapping)
            or info.get("role") != "assistant"
        ):
            continue
        totals["assistant_messages"] += 1
        totals["cost"] += safe_number(info.get("cost"))
        tokens = info.get("tokens")
        if not isinstance(tokens, Mapping):
            continue
        totals["input_tokens"] += safe_int(tokens.get("input"))
        totals["output_tokens"] += safe_int(tokens.get("output"))
        totals["reasoning_tokens"] += safe_int(
            tokens.get("reasoning")
        )
        cache = tokens.get("cache")
        if isinstance(cache, Mapping):
            totals["cache_read_tokens"] += safe_int(
                cache.get("read")
            )
            totals["cache_write_tokens"] += safe_int(
                cache.get("write")
            )
    totals["cost"] = round(float(totals["cost"]), 8)
    return totals


def _trusted_project_path(project: str) -> Path:
    if (
        not isinstance(project, str)
        or not project
        or "\x00" in project
    ):
        raise OpenCodeControlError(
            "OpenCode launch project is invalid"
        )
    try:
        path = Path(project).expanduser().resolve(strict=True)
    except OSError as exc:
        raise OpenCodeControlError(
            "OpenCode launch project is unavailable"
        ) from exc
    if not path.is_dir():
        raise OpenCodeControlError(
            "OpenCode launch project is not a directory"
        )
    return path


def _event_belongs_to_session(
    event: Mapping[str, Any],
    target_native_id: str | None,
) -> bool:
    if target_native_id is None:
        return False
    event_type = event.get("type")
    if event_type == "server.connected":
        return True
    properties = event.get("properties")
    if not isinstance(properties, Mapping):
        return False
    session_id = properties.get("sessionID")
    if not isinstance(session_id, str):
        part = properties.get("part")
        if isinstance(part, Mapping):
            session_id = part.get("sessionID")
    if not isinstance(session_id, str):
        info = properties.get("info")
        if isinstance(info, Mapping):
            session_id = info.get("sessionID")
    return session_id == target_native_id

def _questionnaire_rows(
    pending_question: Mapping[str, Any],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    questions = pending_question.get("questions")
    if not isinstance(questions, list):
        return rows
    for index, question in enumerate(questions, start=1):
        if not isinstance(question, Mapping):
            return []
        options = question.get("options")
        if not isinstance(options, list):
            return []
        rows.append({
            "index": index,
            "topic": str(question.get("header") or ""),
            "question": str(question.get("question") or ""),
            "options": list(options),
            "answer": "",
            "required": True,
            "multiple": question.get("multiple") is True,
            "custom": question.get("custom") is True or not options,
            "selections": [],
        })
    return rows


def _validated_questionnaire_answers(
    pending_question: Mapping[str, Any],
    decision: str,
    submitted: Any,
) -> list[list[str]]:
    if decision == "cancel" and submitted in (None, []):
        return []
    if decision != "accept" or not isinstance(submitted, list):
        raise OpenCodeControlError(
            "OpenCode question decision or answers are invalid"
        )
    expected = _questionnaire_rows(pending_question)
    if not expected or len(submitted) != len(expected):
        raise OpenCodeControlError(
            "OpenCode question response is incomplete"
        )
    provider_answers: list[list[str]] = []
    for proof, answer in zip(expected, submitted, strict=True):
        if not isinstance(answer, Mapping):
            raise OpenCodeControlError(
                "OpenCode question response is malformed"
            )
        for key in ("index", "topic", "question", "options"):
            if answer.get(key) != proof[key]:
                raise OpenCodeControlError(
                    "OpenCode question response does not match the pending form"
                )
        if (
            answer.get("required", True) != proof["required"]
            or answer.get("multiple", False) != proof["multiple"]
            or answer.get("custom", not proof["options"]) != proof["custom"]
        ):
            raise OpenCodeControlError(
                "OpenCode question response does not match the pending form"
            )
        raw_answer = answer.get("answer")
        raw_selections = answer.get("selections", [])
        if (
            not isinstance(raw_answer, str)
            or "\x00" in raw_answer
            or len(raw_answer) > 10_000
            or not isinstance(raw_selections, list)
            or len(raw_selections) > 20
            or not all(
                isinstance(value, str)
                and value
                and len(value) <= 512
                and "\x00" not in value
                for value in raw_selections
            )
            or len(raw_selections) != len(set(raw_selections))
        ):
            raise OpenCodeControlError(
                "OpenCode question answer is invalid"
            )
        custom_answer = raw_answer.strip()
        if proof["multiple"]:
            if any(
                selection not in proof["options"]
                for selection in raw_selections
            ):
                raise OpenCodeControlError(
                    "OpenCode question answer was not offered"
                )
            values = list(raw_selections)
            if custom_answer:
                if not proof["custom"] or custom_answer in values:
                    raise OpenCodeControlError(
                        "OpenCode custom question answer is invalid"
                    )
                values.append(custom_answer)
        else:
            if raw_selections:
                raise OpenCodeControlError(
                    "OpenCode single-choice response has multiple answers"
                )
            values = [custom_answer] if custom_answer else []
            if (
                values
                and proof["options"]
                and values[0] not in proof["options"]
                and not proof["custom"]
            ):
                raise OpenCodeControlError(
                    "OpenCode question answer was not offered"
                )
        if not values:
            raise OpenCodeControlError(
                "OpenCode question answer is required"
            )
        provider_answers.append(values)
    return provider_answers



def _managed_event(
    event: Mapping[str, Any],
    observed_at: float,
) -> dict[str, Any]:
    event_type = str(event.get("type") or "status")
    properties = (
        event.get("properties")
        if isinstance(event.get("properties"), Mapping)
        else {}
    )
    kind = "lifecycle"
    payload: dict[str, Any] = {"subtype": event_type}
    if event_type == "server.connected":
        payload = {"subtype": "connected", "status": "ready"}
    elif event_type == "session.status":
        status = properties.get("status")
        status_type = (
            status.get("type")
            if isinstance(status, Mapping)
            else "unknown"
        )
        marker = {
            "busy": "running",
            "idle": "idle",
            "retry": "running",
        }.get(str(status_type), "unknown")
        payload = {
            "subtype": "session_status",
            "status": marker,
        }
    elif event_type == "permission.asked":
        payload = {
            "subtype": "permission_request",
            "status": "permission_request",
            "reason": _permission_label(properties),
        }
    elif event_type == "permission.replied":
        payload = {
            "subtype": "permission_replied",
            "status": "running",
        }
    elif event_type == "question.asked":
        payload = {
            "subtype": "question_requested",
            "status": "question_request",
            "question_request_id": str(properties.get("id") or ""),
        }
    elif event_type in {"question.replied", "question.rejected"}:
        payload = {
            "subtype": event_type.replace(".", "_"),
            "status": "running",
        }
    elif event_type == "message.part.updated":
        part = properties.get("part")
        if isinstance(part, Mapping) and part.get("type") == "text":
            kind = "partial_text"
            payload = {
                "text": str(properties.get("delta") or part.get("text") or ""),
                "role": "assistant",
            }
        elif isinstance(part, Mapping) and part.get("type") == "tool":
            status = str(part.get("status") or "")
            call_id = str(part.get("id") or "")
            if status in {"pending", "running"}:
                kind = "tool_call"
                payload = {
                    "name": str(part.get("tool") or "tool"),
                    "call_id": call_id,
                }
            else:
                kind = "tool_result"
                payload = {
                    "call_id": call_id,
                    "content": "",
                    "is_error": status == "error",
                }
    return {
        "provider_cursor": "opencode-event:" + fingerprint(event),
        "observed_at": float(observed_at),
        "kind": kind,
        "payload": payload,
        "metadata": {"provider_event_type": event_type},
    }


def _workspace_from_truth(
    session_truth: Mapping[str, Any],
    *,
    require_exists: bool,
) -> Path | None:
    for key in (
        "directory",
        "project",
        "project_path",
        "cwd",
        "working_directory",
    ):
        value = session_truth.get(key)
        if (
            not isinstance(value, str)
            or not value
            or "\x00" in value
        ):
            continue
        path = Path(value).expanduser()
        try:
            resolved = path.resolve(strict=require_exists)
        except OSError:
            continue
        if not require_exists or resolved.is_dir():
            return resolved
    return None


def _native_session_id(
    session_id: str,
    session_truth: Mapping[str, Any],
) -> str:
    for key in ("native_id", "provider_session_id"):
        value = session_truth.get(key)
        if isinstance(value, str):
            return resource_id(value)
    prefix = "opencode:"
    value = (
        session_id[len(prefix) :]
        if session_id.startswith(prefix)
        else session_id
    )
    return resource_id(value)


def _session_id_from_payload(session: Mapping[str, Any]) -> str:
    value = session.get("id")
    if not isinstance(value, str):
        raise OpenCodeTransportError(
            "OpenCode session response has no id"
        )
    return resource_id(value)


def _permission_label(item: Mapping[str, Any]) -> str:
    permission = item.get("permission")
    patterns = item.get("patterns")
    label = (
        permission
        if isinstance(permission, str)
        else "Permission request"
    )
    if (
        isinstance(patterns, list)
        and patterns
        and isinstance(patterns[0], str)
    ):
        label = f"{label}: {patterns[0]}"
    return safe_label(label)


def _message_id(client_action_id: str) -> str:
    digest = hashlib.sha256(
        client_action_id.encode()
    ).hexdigest()[:24]
    return f"msg_pairling_{digest}"


def _provider_operation_id(client_action_id: str) -> str:
    digest = hashlib.sha256(
        client_action_id.encode()
    ).hexdigest()[:32]
    return f"opencode-{digest}"


def _signature_value(value: Any) -> Any:
    if isinstance(value, ProviderSessionIdentity):
        return {
            "provider_id": value.provider_id,
            "session_id": value.session_id,
            "binding_id": value.binding_id,
        }
    return value
