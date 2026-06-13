#!/usr/bin/env python3
"""Daemon-side Live Activity APNs publisher.

The iPhone can start a Live Activity and register its update token, but once
iOS suspends the app, Mac-side turn-state must drive APNs updates. This module
bridges Pairling's turn-state JSON files into PairlingPushDispatcher events.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable

from push_event_catalog import build_push_event, live_activity_content_state, live_activity_payload


class LiveActivityTurnStatePublisher:
    def __init__(
        self,
        *,
        turn_state_dir: Path,
        push_dispatcher,
        claude_uuid_resolver: Callable[[str], str] | None = None,
        now_fn=time.time,
        sleep_fn=time.sleep,
        poll_interval: float = 1.0,
        failed_retry_interval: float = 30.0,
        token_update_interval: float = 15.0,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self.turn_state_dir = turn_state_dir
        self.push_dispatcher = push_dispatcher
        self.claude_uuid_resolver = claude_uuid_resolver or (lambda _session_id: "")
        self.now_fn = now_fn
        self.sleep_fn = sleep_fn
        self.poll_interval = poll_interval
        self.failed_retry_interval = failed_retry_interval
        self.token_update_interval = token_update_interval
        self.logger = logger
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_attempts: dict[tuple[str, str], dict[str, Any]] = {}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self.run_forever,
            name="pairling-live-activity-publisher",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def run_forever(self) -> None:
        while not self._stop.is_set():
            try:
                self.scan_once()
            except Exception as exc:  # pragma: no cover - defensive daemon boundary.
                self._log(f"live activity publisher scan failed: {type(exc).__name__}: {exc}")
            self.sleep_fn(self.poll_interval)

    def scan_once(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        active = self._active_live_activities()
        seen_keys = {(item["device_id"], item["session_id"]) for item in active}
        for key in list(self._last_attempts):
            if key not in seen_keys:
                self._last_attempts.pop(key, None)

        for item in active:
            result = self._publish_for_activity(item)
            if result is not None:
                results.append(result)
        return results

    def publish_turn_state_payload(self, *, session_id: str, state_payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Fast path for hook-observed meaningful turn-state events.

        The scan loop remains as a safety net. This path lets callers publish
        immediately after writing a semantically meaningful transition instead
        of waiting for the next directory scan.
        """
        if not isinstance(state_payload, dict):
            return []
        results: list[dict[str, Any]] = []
        for item in self._active_live_activities():
            if item["session_id"] != session_id:
                continue
            result = self._publish_state_to_activity(item, state_payload)
            if result is not None:
                results.append(result)
        return results

    def _active_live_activities(self) -> list[dict[str, str]]:
        try:
            status = self.push_dispatcher.status()
        except Exception as exc:
            self._log(f"push status unavailable for live activity publisher: {type(exc).__name__}: {exc}")
            return []
        if not _provider_can_deliver(status):
            return []
        devices = status.get("devices") if isinstance(status, dict) else []
        out: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for device in devices if isinstance(devices, list) else []:
            if not isinstance(device, dict) or not device.get("live_activity_enabled"):
                continue
            device_id = str(device.get("device_id") or "").strip()
            if not device_id:
                continue
            for activity in device.get("live_activities") or []:
                if not isinstance(activity, dict) or activity.get("invalidated_at"):
                    continue
                session_id = str(activity.get("session_id") or "").strip()
                if not session_id:
                    continue
                key = (device_id, session_id)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"device_id": device_id, "session_id": session_id})
        return out

    def _publish_for_activity(self, item: dict[str, str]) -> dict[str, Any] | None:
        session_id = item["session_id"]
        state_payload = self._read_turn_state(session_id)
        if not state_payload:
            return None
        return self._publish_state_to_activity(item, state_payload)

    def _publish_state_to_activity(self, item: dict[str, str], state_payload: dict[str, Any]) -> dict[str, Any] | None:
        session_id = item["session_id"]
        payload, signature_visible = self._event_payload_from_turn_state(session_id, state_payload)
        key = (item["device_id"], session_id)
        signature = _stable_hash({
            "session_id": session_id,
            "event": payload["event"],
            "visible": signature_visible,
        })
        now = float(self.now_fn())
        previous = self._last_attempts.get(key)
        if previous and previous.get("signature") == signature:
            if previous.get("ok"):
                return None
            if now - float(previous.get("attempted_at") or 0) < self.failed_retry_interval:
                return None
        if previous and self._is_token_only_change(previous.get("visible"), signature_visible):
            if now - float(previous.get("attempted_at") or 0) < self.token_update_interval:
                return None

        event_id = "la_auto_" + signature[:32]
        payload["event_id"] = event_id
        payload["content_state"]["eventId"] = event_id
        delivery = self.push_dispatcher.record_live_activity_event(
            device_id=item["device_id"],
            payload=payload,
        )
        ok = bool(delivery.get("ok"))
        self._last_attempts[key] = {
            "signature": signature,
            "visible": signature_visible,
            "attempted_at": now,
            "ok": ok,
            "event_id": event_id,
        }
        return delivery

    def _read_turn_state(self, session_id: str) -> dict[str, Any] | None:
        provider, native_id = _parse_session_ref(session_id)
        candidates: list[Path] = []
        if provider == "claude":
            uuid = self.claude_uuid_resolver(native_id)
            if _safe_stem(uuid):
                candidates.append(self.turn_state_dir / f"{uuid}.json")
            if _safe_stem(native_id):
                candidates.append(self.turn_state_dir / f"{native_id}.json")
        elif _safe_stem(native_id):
            candidates.append(self.turn_state_dir / f"{native_id}.json")
        for path in candidates:
            try:
                if not path.is_file():
                    continue
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                return payload
        return None

    def _event_payload_from_turn_state(self, session_id: str, payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        raw_state = str(payload.get("state") or "starting").strip().lower()
        raw_event = str(payload.get("event") or "").strip().lower()
        done = raw_state in {"idle", "done", "completed"} or raw_event in {"stop", "session_end"}
        state = "done" if done else _activity_state(raw_state)
        tool = _bounded_optional(payload.get("tool"), 80)
        effort = _bounded_optional(payload.get("effort"), 40)
        tokens = _optional_int(payload.get("tokens", payload.get("total_tokens")))
        last_update = _optional_float(payload.get("last_update")) or float(self.now_fn())
        started_at = _optional_float(payload.get("started_at"))
        freshness = max(0, int(float(self.now_fn()) - last_update))
        kind = _catalog_kind_for_state(state)
        current_step = _current_step_for_state(state, tool, payload)
        event = build_push_event(
            kind=kind,
            source="turn-state",
            provider=_parse_session_ref(session_id)[0],
            session_id=session_id,
            session_title=_bounded_optional(payload.get("session_title"), 60),
            project=_bounded_optional(payload.get("project"), 120),
            observed_at=last_update,
            phase=state,
            current_step=current_step,
            latest_event=_bounded_optional(payload.get("latest_event") or payload.get("event_label"), 120),
            result_summary=_bounded_optional(
                payload.get("result_summary") or ("Turn finished." if done else None),
                120,
            ),
            required_action=_bounded_optional(
                payload.get("required_action") or ("Review the requested action." if state == "attention" else None),
                120,
            ),
            risk_level=_attention_level(state),
            risk_summary=_bounded_optional(payload.get("risk_summary"), 120),
            route_health=_bounded_optional(payload.get("route_health"), 80),
            worker_summary=_bounded_optional(payload.get("worker_summary"), 80),
            build_label=_bounded_optional(payload.get("build_label"), 60),
            action_route="pairling://session/" + session_id,
            freshness_seconds=freshness,
        )
        outgoing = live_activity_payload(event)
        outgoing["kind"] = event.kind
        outgoing["content_state"].update({
            "state": state,
            "phase": state,
            "tool": tool,
            "effort": effort,
            "tokens": tokens,
            "updatedAtEpoch": last_update,
        })
        if state == "tool" and tool:
            outgoing["content_state"]["currentStep"] = current_step or f"Running {tool}"
        outgoing["stale_seconds"] = 75
        outgoing["dismissal_seconds"] = 300 if state in {"attention", "failed"} else 120
        visible = {
            "state": state,
            "phase": state,
            "tool": tool,
            "effort": effort,
            "tokens": tokens,
            "attentionLevel": _attention_level(state),
            "started_at": started_at,
            "currentStep": outgoing["content_state"].get("currentStep"),
            "resultSummary": outgoing["content_state"].get("resultSummary"),
            "requiredAction": outgoing["content_state"].get("requiredAction"),
            "riskSummary": outgoing["content_state"].get("riskSummary"),
        }
        outgoing["content_state"]["verb"] = _verb_for_state(state, tool)
        return outgoing, visible

    def _is_token_only_change(self, previous: Any, current: dict[str, Any]) -> bool:
        if not isinstance(previous, dict):
            return False
        prior = dict(previous)
        new = dict(current)
        prior_tokens = prior.pop("tokens", None)
        new_tokens = new.pop("tokens", None)
        return prior == new and prior_tokens != new_tokens

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(message)


def _parse_session_ref(session_id: str) -> tuple[str, str]:
    text = str(session_id or "").strip()
    if ":" in text:
        provider, native_id = text.split(":", 1)
        if provider in {"claude", "codex"}:
            return provider, native_id
    return "claude", text


def _provider_can_deliver(status: dict[str, Any]) -> bool:
    provider = status.get("provider") if isinstance(status, dict) else None
    return not isinstance(provider, dict) or bool(provider.get("configured"))


def _activity_state(state: str) -> str:
    if state in {"starting", "thinking", "tool", "responding", "attention", "stale", "done", "failed", "idle"}:
        return state
    return "starting"


def _attention_level(state: str) -> str | None:
    if state == "attention":
        return "warning"
    if state == "failed":
        return "critical"
    return None


def _catalog_kind_for_state(state: str) -> str:
    if state == "done":
        return "turn_result"
    if state == "failed":
        return "turn_failed"
    if state == "attention":
        return "action_required"
    if state == "stale":
        return "mac_route_risk"
    return "push_diagnostic"


def _current_step_for_state(state: str, tool: str | None, payload: dict[str, Any]) -> str | None:
    explicit = _bounded_optional(payload.get("current_step"), 60)
    if explicit:
        return explicit
    if state == "tool" and tool:
        return f"Running {tool}"[:60]
    if state == "responding":
        return "Writing response"
    if state == "thinking":
        return "Reasoning"
    return None


def _verb_for_state(state: str, tool: str | None) -> str:
    if state == "done":
        return "Done"
    if state == "attention":
        return "Review"
    if state == "failed":
        return "Failed"
    if tool:
        return "Using"
    if state == "responding":
        return "Responding"
    return "Thinking"


def _stable_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()


def _safe_stem(value: str | None) -> bool:
    text = str(value or "")
    return bool(text) and len(text) <= 180 and re.match(r"^[A-Za-z0-9_-]+$", text) is not None


def _bounded_optional(value: Any, limit: int) -> str | None:
    if value in (None, ""):
        return None
    return str(value)[:limit]


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
