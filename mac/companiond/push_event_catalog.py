#!/usr/bin/env python3
"""Bounded Pairling APNs and Live Activity event catalog.

This module owns the user-facing push copy and APNs-safe Live Activity state.
It intentionally accepts only bounded semantic labels; raw transcript, prompt,
command output, credentials, filesystem dumps, and stack traces are ignored.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any


SUPPORTED_KINDS = {
    "action_required",
    "turn_result",
    "turn_failed",
    "tool_risk",
    "mac_route_risk",
    "worker_pressure",
    "deploy_result",
    "push_diagnostic",
}
CATALOG_KINDS = tuple(sorted(SUPPORTED_KINDS))
LEGACY_KIND_ALIASES = {
    "turn_done": "turn_result",
    "session_attention": "action_required",
    "mac_health": "mac_route_risk",
    "worker_sentinel": "worker_pressure",
}

PHASE_BY_KIND = {
    "action_required": "attention",
    "turn_result": "done",
    "turn_failed": "failed",
    "tool_risk": "risk",
    "mac_route_risk": "risk",
    "worker_pressure": "attention",
    "deploy_result": "done",
    "push_diagnostic": "done",
}

INTERRUPTION_BY_KIND = {
    "action_required": "time-sensitive",
    "turn_result": "active",
    "turn_failed": "time-sensitive",
    "tool_risk": "time-sensitive",
    "mac_route_risk": "time-sensitive",
    "worker_pressure": "time-sensitive",
    "deploy_result": "active",
    "push_diagnostic": "passive",
}

ALERT_COPY = {
    "action_required": ("Pairling needs approval", "Review the requested action before work continues."),
    "turn_result": ("Pairling turn complete", "A turn finished with a useful result."),
    "turn_failed": ("Pairling turn failed", "A turn failed and needs review."),
    "tool_risk": ("Pairling tool risk", "A tool signal needs review."),
    "mac_route_risk": ("Mac route timed out", "The paired Mac route needs attention."),
    "worker_pressure": ("Pairling worker pressure", "Worker or token pressure needs review."),
    "deploy_result": ("Deploy result ready", "A build or deploy result is available."),
    "push_diagnostic": ("Pairling push test", "Push delivery is configured for this device."),
}

PRIVATE_INPUT_KEYS = {
    "raw_transcript",
    "transcript",
    "transcript_text",
    "prompt",
    "prompt_text",
    "command_output",
    "stdout",
    "stderr",
    "credentials",
    "api_key",
    "provider_api_key",
    "filesystem_dump",
    "stack_trace",
    "traceback",
}


@dataclass
class PushEvent:
    kind: str
    event_id: str | None = None
    source: str = "unknown"
    provider: str | None = None
    session_id: str | None = None
    project: str | None = None
    session_title: str | None = None
    observed_at: float | None = None
    created_at: float | None = None
    phase: str | None = None
    status: str | None = None
    current_step: str | None = None
    latest_event: str | None = None
    result_summary: str | None = None
    required_action: str | None = None
    risk_level: str | None = None
    risk_summary: str | None = None
    route_health: str | None = None
    worker_summary: str | None = None
    build_label: str | None = None
    action_route: str | None = None
    freshness_seconds: int | None = None
    privacy_tier: str = "standard"
    dedupe_key: str | None = None
    thread_id: str | None = None
    collapse_id: str | None = None

    def __post_init__(self) -> None:
        normalized = catalog_event(
            kind=self.kind,
            event_id=self.event_id,
            source=self.source,
            provider=self.provider,
            session_id=self.session_id,
            project=self.project,
            session_title=self.session_title,
            observed_at=self.observed_at,
            created_at=self.created_at,
            phase=self.phase,
            status=self.status,
            current_step=self.current_step,
            latest_event=self.latest_event,
            result_summary=self.result_summary,
            required_action=self.required_action,
            risk_level=self.risk_level,
            risk_summary=self.risk_summary,
            route_health=self.route_health,
            worker_summary=self.worker_summary,
            build_label=self.build_label,
            action_route=self.action_route,
            freshness_seconds=self.freshness_seconds,
            privacy_tier=self.privacy_tier,
            dedupe_key=self.dedupe_key,
            thread_id=self.thread_id,
            collapse_id=self.collapse_id,
            _skip_push_event_init=True,
        )
        self.__dict__.update(normalized.__dict__)


def catalog_event(
    *,
    kind: str,
    source: str,
    provider: str | None = None,
    session_id: str | None = None,
    project: str | None = None,
    session_title: str | None = None,
    observed_at: float | None = None,
    created_at: float | None = None,
    phase: str | None = None,
    status: str | None = None,
    current_step: str | None = None,
    latest_event: str | None = None,
    result_summary: str | None = None,
    required_action: str | None = None,
    risk_level: str | None = None,
    risk_summary: str | None = None,
    route_health: str | None = None,
    worker_summary: str | None = None,
    build_label: str | None = None,
    action_route: str | None = None,
    freshness_seconds: int | None = None,
    privacy_tier: str = "standard",
    dedupe_key: str | None = None,
    thread_id: str | None = None,
    collapse_id: str | None = None,
    event_id: str | None = None,
    _skip_push_event_init: bool = False,
    **ignored_private_inputs: Any,
) -> PushEvent:
    """Build a bounded APNs-safe event.

    Unknown keyword inputs are intentionally ignored, which lets callers pass a
    larger observed event without accidentally forwarding private material.
    """

    del ignored_private_inputs
    normalized_kind = _canonical_kind(kind)
    now = float(created_at if created_at is not None else time.time())
    observed = float(observed_at if observed_at is not None else now)
    normalized_phase = _bounded_enum(phase or PHASE_BY_KIND[normalized_kind], 32)
    normalized_status = _bounded_enum(status or normalized_phase, 32)
    normalized_provider = _bounded_label(provider, 32)
    normalized_session_id = _bounded_id(session_id)
    route = _safe_route(action_route, session_id=normalized_session_id, kind=normalized_kind)
    normalized_project = _bounded_label(_project_name(project), 60)
    normalized_title = _bounded_label(session_title, 60)
    normalized_result = _bounded_summary(result_summary)
    normalized_required = _bounded_summary(required_action)
    normalized_risk = _bounded_enum(risk_level, 32)
    normalized_risk_summary = _bounded_summary(risk_summary)
    normalized_route_health = _bounded_summary(route_health)
    normalized_worker_summary = _bounded_summary(worker_summary)
    normalized_build_label = _bounded_label(build_label, 60)
    normalized_current_step = _bounded_label(current_step, 60)
    normalized_latest = _bounded_summary(latest_event) or _latest_event(
        normalized_kind,
        current_step=normalized_current_step,
        result_summary=normalized_result,
        required_action=normalized_required,
        risk_summary=normalized_risk_summary,
        worker_summary=normalized_worker_summary,
    )
    fresh = _bounded_int(freshness_seconds, minimum=0, maximum=86_400) if freshness_seconds is not None else None
    stable = {
        "kind": normalized_kind,
        "session_id": normalized_session_id,
        "project": normalized_project,
        "status": normalized_status,
        "result": normalized_result,
        "required": normalized_required,
        "risk": normalized_risk_summary,
        "observed_bucket": int(observed),
    }
    normalized_dedupe = _bounded_id(dedupe_key) or _stable_hash(stable)[:32]
    normalized_thread = _bounded_id(thread_id) or _default_thread_id(normalized_kind, normalized_session_id)
    normalized_collapse = _bounded_id(collapse_id) or f"pairling.{normalized_kind}.{normalized_dedupe}"[:160]
    normalized_event_id = _bounded_id(event_id) or f"push_{normalized_kind}_{_stable_hash(stable)[:24]}"
    if _skip_push_event_init:
        event = object.__new__(PushEvent)
        values = {
            "event_id": normalized_event_id,
            "kind": normalized_kind,
            "source": _bounded_enum(source, 32) or "unknown",
            "provider": normalized_provider,
            "session_id": normalized_session_id,
            "project": normalized_project,
            "session_title": normalized_title,
            "observed_at": observed,
            "created_at": now,
            "phase": normalized_phase,
            "status": normalized_status,
            "current_step": normalized_current_step,
            "latest_event": normalized_latest,
            "result_summary": normalized_result,
            "required_action": normalized_required,
            "risk_level": normalized_risk,
            "risk_summary": normalized_risk_summary,
            "route_health": normalized_route_health,
            "worker_summary": normalized_worker_summary,
            "build_label": normalized_build_label,
            "action_route": route,
            "freshness_seconds": fresh,
            "privacy_tier": _bounded_enum(privacy_tier, 32) or "standard",
            "dedupe_key": normalized_dedupe,
            "thread_id": normalized_thread,
            "collapse_id": normalized_collapse,
        }
        event.__dict__.update(values)
        return event
    return PushEvent(
        event_id=normalized_event_id,
        kind=normalized_kind,
        source=_bounded_enum(source, 32) or "unknown",
        provider=normalized_provider,
        session_id=normalized_session_id,
        project=normalized_project,
        session_title=normalized_title,
        observed_at=observed,
        created_at=now,
        phase=normalized_phase,
        status=normalized_status,
        current_step=normalized_current_step,
        latest_event=normalized_latest,
        result_summary=normalized_result,
        required_action=normalized_required,
        risk_level=normalized_risk,
        risk_summary=normalized_risk_summary,
        route_health=normalized_route_health,
        worker_summary=normalized_worker_summary,
        build_label=normalized_build_label,
        action_route=route,
        freshness_seconds=fresh,
        privacy_tier=_bounded_enum(privacy_tier, 32) or "standard",
        dedupe_key=normalized_dedupe,
        thread_id=normalized_thread,
        collapse_id=normalized_collapse,
    )


def build_push_event(**kwargs: Any) -> PushEvent:
    return catalog_event(**kwargs)


def standard_alert_payload(event: PushEvent) -> dict[str, Any]:
    title, default_body = ALERT_COPY[event.kind]
    if event.kind == "action_required" and event.required_action:
        body = _join_sentence(event.required_action, event.session_title or event.project)
    elif event.kind in {"turn_result", "deploy_result"} and event.result_summary:
        body = _join_sentence(event.result_summary, event.build_label or event.session_title or event.project)
    elif event.kind in {"turn_failed", "tool_risk", "mac_route_risk"} and (event.risk_summary or event.current_step):
        body = _join_sentence(event.risk_summary or event.current_step, event.route_health or event.session_title or event.project)
    elif event.kind == "worker_pressure" and event.worker_summary:
        body = _join_sentence(event.worker_summary, event.required_action or "Review workers.")
    else:
        body = default_body
    payload = {
        "event_id": event.event_id,
        "kind": event.kind,
        "route": event.action_route or "pairling://dashboard",
        "title": _bounded_label(_title_for_event(event, title), 60) or title,
        "body": _bounded_summary(body) or default_body,
        "thread_id": event.thread_id,
        "collapse_id": event.collapse_id,
        "interruption_level": INTERRUPTION_BY_KIND[event.kind],
        "source": event.source,
        "provider": event.provider,
        "session_id": event.session_id,
        "project": event.project,
        "phase": event.phase,
        "observed_at": event.observed_at,
        "privacy_tier": event.privacy_tier,
    }
    payload.update(_semantic_fields(event))
    return payload


def live_activity_payload(event: PushEvent) -> dict[str, Any]:
    activity_event = "end" if event.phase == "done" else "update"
    stale = 75
    dismissal = 300 if event.required_action or event.phase in {"failed", "attention"} else 120
    return {
        "session_id": event.session_id or "",
        "event": activity_event,
        "event_id": event.event_id,
        "content_state": live_activity_content_state(event),
        "stale_seconds": stale,
        "dismissal_seconds": dismissal,
        "source": event.source,
        "phase": event.phase,
        "project": event.project,
        "observed_at": event.observed_at,
        "collapse_id": event.collapse_id,
        "freshness_seconds": event.freshness_seconds,
    }


def live_activity_content_state(event: PushEvent) -> dict[str, Any]:
    state = event.phase
    payload = {
        "state": state,
        "phase": event.phase,
        "tool": event.current_step,
        "effort": None,
        "tokens": None,
        "verb": _verb_for_phase(event.phase),
        "attentionLevel": _attention_for_event(event),
        "updatedAtEpoch": event.observed_at,
        "eventId": event.event_id,
        "sessionTitle": event.session_title,
        "provider": event.provider,
        "project": event.project,
        "currentStep": event.current_step,
        "latestEvent": event.latest_event,
        "resultSummary": event.result_summary,
        "requiredAction": event.required_action,
        "freshness": _freshness_label(event.freshness_seconds),
        "riskLevel": event.risk_level,
        "riskSummary": event.risk_summary,
        "routeHealth": event.route_health,
        "workerSummary": event.worker_summary,
        "buildLabel": event.build_label,
        "actionRoute": event.action_route,
    }
    return {key: value for key, value in payload.items() if value is not None}


def outbox_metadata(
    event: PushEvent,
    *,
    content_state: dict[str, Any] | None = None,
    sent_at: float,
    apns_outcome: str | None = None,
) -> dict[str, Any]:
    content_state = content_state or live_activity_content_state(event)
    return {
        "source": event.source,
        "phase": event.phase,
        "project": event.project,
        "observed_at": event.observed_at,
        "sent_at": float(sent_at),
        "collapse_id": event.collapse_id,
        "freshness_seconds_at_send": _freshness_at_send(event, sent_at),
        "content_state_hash": _stable_hash(content_state),
        "apns_outcome": _bounded_enum(apns_outcome, 80),
    }


def _enum(value: Any, allowed: set[str], default: str) -> str:
    text = str(value or "").strip()
    return text if text in allowed else default


def _semantic_fields(event: PushEvent) -> dict[str, Any]:
    fields = {
        "status": event.status,
        "current_step": event.current_step,
        "latest_event": event.latest_event,
        "result_summary": event.result_summary,
        "required_action": event.required_action,
        "risk_level": event.risk_level,
        "risk_summary": event.risk_summary,
        "route_health": event.route_health,
        "worker_summary": event.worker_summary,
        "build_label": event.build_label,
        "action_route": event.action_route,
        "freshness_seconds": event.freshness_seconds,
        "dedupe_key": event.dedupe_key,
    }
    return {key: value for key, value in fields.items() if value not in (None, "")}


def _canonical_kind(value: Any) -> str:
    text = str(value or "").strip()
    text = LEGACY_KIND_ALIASES.get(text, text)
    return _enum(text, SUPPORTED_KINDS, "push_diagnostic")


def _bounded_enum(value: Any, limit: int) -> str | None:
    return _bounded_text(value, limit, strip_private=True)


def _bounded_id(value: Any) -> str | None:
    text = _bounded_text(value, 160, strip_private=True)
    if not text:
        return None
    return re.sub(r"[^A-Za-z0-9_.:/@#-]", "-", text)[:160]


def _bounded_label(value: Any, limit: int) -> str | None:
    return _bounded_text(value, limit, strip_private=True)


def _bounded_summary(value: Any) -> str | None:
    text = _bounded_text(value, 120, strip_private=True)
    if not text:
        return None
    text = re.sub(r"(?i)traceback.*", "Failure details require review.", text).strip()
    return text[:120] or None


def _bounded_text(value: Any, limit: int, *, strip_private: bool) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    if strip_private:
        text = re.sub(r"(?i)(prompt|token|api[_-]?key|credential|password|secret)=?[^&\\s]*", "[redacted]", text)
        text = re.sub(r"/Users/[^\\s?&]+", "[path]", text)
        text = re.sub(r"(?i)traceback \\(most recent call last\\):.*", "Failure details require review.", text)
    text = re.sub(r"\\s+", " ", text).strip()
    return text[:limit] if text else None


def _safe_route(value: Any, *, session_id: str | None, kind: str) -> str:
    text = _bounded_text(value, 300, strip_private=True)
    if text and text.startswith("pairling://"):
        return text
    if session_id:
        return "pairling://session/" + session_id
    if kind == "worker_pressure":
        return "pairling://workers"
    if kind == "mac_route_risk":
        return "pairling://health"
    if kind == "push_diagnostic":
        return "pairling://settings/push"
    if kind == "deploy_result":
        return "pairling://builds"
    return "pairling://dashboard"


def _project_name(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    return text.rstrip("/").rsplit("/", 1)[-1] or text


def _latest_event(kind: str, **parts: Any) -> str | None:
    for key in ["required_action", "risk_summary", "result_summary", "worker_summary", "current_step"]:
        if parts.get(key):
            return _bounded_summary(parts[key])
    return ALERT_COPY[kind][1]


def _title_for_event(event: PushEvent, default: str) -> str:
    if event.kind == "deploy_result" and event.build_label:
        return f"{event.build_label} result"
    if event.kind == "turn_result" and event.project:
        return f"{event.project} turn complete"
    return default


def _join_sentence(left: str | None, right: str | None) -> str:
    if left and right:
        return f"{left}. {right}."
    return left or right or ""


def _verb_for_phase(phase: str) -> str:
    return {
        "attention": "Review",
        "done": "Done",
        "failed": "Failed",
        "stale": "Stale",
        "tool": "Using",
        "responding": "Responding",
        "starting": "Starting",
    }.get(phase, "Thinking")


def _attention_for_event(event: PushEvent) -> str | None:
    if event.phase in {"attention", "stale"}:
        return "warning"
    if event.phase == "failed" or event.risk_level == "critical":
        return "critical"
    return None


def _freshness_label(seconds: int | None) -> str | None:
    if seconds is None:
        return "now"
    if seconds <= 0:
        return "now"
    if seconds < 60:
        return f"{seconds}s ago"
    return f"{seconds // 60}m ago"


def _freshness_at_send(event: PushEvent, sent_at: float) -> int:
    if event.freshness_seconds is not None:
        return int(event.freshness_seconds)
    return max(0, int(float(sent_at) - float(event.observed_at)))


def _bounded_int(value: Any, *, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = minimum
    return max(minimum, min(maximum, parsed))


def _default_thread_id(kind: str, session_id: str | None) -> str:
    if session_id:
        return ("pairling.session." + session_id)[:160]
    if kind == "worker_pressure":
        return "pairling.workers"
    if kind == "mac_route_risk":
        return "pairling.health"
    if kind == "deploy_result":
        return "pairling.deploy"
    return "pairling.push"


def _stable_hash(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()
