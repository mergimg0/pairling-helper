#!/usr/bin/env python3
"""Daemon-side production publishers for standard Pairling APNs alerts."""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable

from push_event_catalog import build_push_event, standard_alert_payload


class TurnStateAlertPublisher:
    """Publish attention and turn-done APNs events from turn-state JSON files."""

    def __init__(
        self,
        *,
        turn_state_dir: Path,
        push_dispatcher,
        claude_session_resolver: Callable[[str], str] | None = None,
        now_fn=time.time,
        sleep_fn=time.sleep,
        poll_interval: float = 2.0,
        failed_retry_interval: float = 30.0,
        max_state_age_seconds: float = 60 * 60 * 24,
        min_turn_done_seconds: float = 180.0,
        prime_existing: bool = True,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self.turn_state_dir = turn_state_dir
        self.push_dispatcher = push_dispatcher
        self.claude_session_resolver = claude_session_resolver or (lambda _uuid: "")
        self.now_fn = now_fn
        self.sleep_fn = sleep_fn
        self.poll_interval = poll_interval
        self.failed_retry_interval = failed_retry_interval
        self.max_state_age_seconds = max_state_age_seconds
        self.min_turn_done_seconds = min_turn_done_seconds
        self.prime_existing = prime_existing
        self.logger = logger
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_state: dict[str, dict[str, Any]] = {}
        self._last_attempts: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._primed = not prime_existing

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self.run_forever,
            name="pairling-standard-turn-publisher",
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
                self._log(f"standard turn publisher scan failed: {type(exc).__name__}: {exc}")
            self.sleep_fn(self.poll_interval)

    def scan_once(self) -> list[dict[str, Any]]:
        devices = self._standard_push_devices()
        if not devices:
            return []
        states = self._recent_turn_states()
        if not self._primed:
            self._last_state = {
                item["state_key"]: item["visible"]
                for item in states
            }
            self._primed = True
            return []

        results: list[dict[str, Any]] = []
        seen_state_keys = {item["state_key"] for item in states}
        for key in list(self._last_state):
            if key not in seen_state_keys:
                self._last_state.pop(key, None)

        for item in states:
            previous = self._last_state.get(item["state_key"])
            self._last_state[item["state_key"]] = item["visible"]
            events = self._events_for_transition(item, previous)
            for event in events:
                for device in devices:
                    if not self._device_wants_event(device, event["kind"]):
                        continue
                    result = self._publish(device["device_id"], event)
                    if result is not None:
                        results.append(result)
        return results

    def _recent_turn_states(self) -> list[dict[str, Any]]:
        now = float(self.now_fn())
        states: list[dict[str, Any]] = []
        try:
            paths = sorted(self.turn_state_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            return []
        for path in paths[:300]:
            try:
                if now - path.stat().st_mtime > self.max_state_age_seconds:
                    continue
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            state = self._visible_state(path, payload)
            if state is not None:
                states.append(state)
        return states

    def _visible_state(self, path: Path, payload: dict[str, Any]) -> dict[str, Any] | None:
        raw_session = str(payload.get("session_id") or path.stem).strip()
        provider, native_id = _parse_session_ref(raw_session)
        if provider == "codex":
            route_id = f"codex:{native_id}"
        else:
            route_id = raw_session
        raw_state = str(payload.get("state") or "idle").strip().lower()
        raw_event = str(payload.get("event") or "").strip().lower()
        started_at = _optional_float(payload.get("started_at"))
        last_update = _optional_float(payload.get("last_update")) or float(self.now_fn())
        visible = {
            "route_id": route_id,
            "raw_state": raw_state,
            "raw_event": raw_event,
            "started_at": started_at,
            "last_update": last_update,
            "provider": provider,
            "tool": _bounded_optional(payload.get("tool"), 80),
        }
        return {
            "state_key": path.stem,
            "session_id": route_id,
            "visible": visible,
        }

    def _events_for_transition(self, item: dict[str, Any], previous: dict[str, Any] | None) -> list[dict[str, Any]]:
        visible = item["visible"]
        raw_state = visible["raw_state"]
        raw_event = visible["raw_event"]
        was_done = bool(previous and _is_done_state(previous.get("raw_state"), previous.get("raw_event")))
        is_done = _is_done_state(raw_state, raw_event)
        events: list[dict[str, Any]] = []
        if is_done and previous and not was_done:
            started = _optional_float(visible.get("started_at"))
            duration = float(visible.get("last_update") or self.now_fn()) - started if started else 0.0
            if duration >= self.min_turn_done_seconds:
                events.append(self._event_payload("turn_result", item, duration_seconds=duration))
        if raw_state in {"attention", "failed"} and (not previous or previous.get("raw_state") != raw_state):
            events.append(self._event_payload("action_required" if raw_state == "attention" else "turn_failed", item))
        return events

    def _event_payload(self, kind: str, item: dict[str, Any], *, duration_seconds: float | None = None) -> dict[str, Any]:
        visible = item["visible"]
        session_id = self._route_session_id_for_event(item["session_id"])
        digest = _stable_hash({
            "kind": kind,
            "session_id": session_id,
            "last_update": int(float(visible.get("last_update") or self.now_fn())),
            "state": visible.get("raw_state"),
        })[:24]
        if kind == "turn_result":
            minutes = max(3, int(round((duration_seconds or 0) / 60)))
            result_summary = f"Turn finished after about {minutes} minutes"
            required_action = None
            risk_summary = None
        else:
            result_summary = None
            required_action = "A session is waiting for your decision." if kind == "action_required" else "Open the failed turn."
            risk_summary = "The session reported failure." if kind == "turn_failed" else None
        provider, native_id = _parse_session_ref(session_id)
        event = build_push_event(
            event_id=f"push_auto_{kind}_{digest}",
            kind=kind,
            source="turn-state",
            provider=provider,
            session_id=session_id,
            observed_at=float(visible.get("last_update") or self.now_fn()),
            phase="done" if kind == "turn_result" else ("failed" if kind == "turn_failed" else "attention"),
            current_step=visible.get("tool"),
            result_summary=result_summary,
            required_action=required_action,
            risk_summary=risk_summary,
            action_route="pairling://session/" + session_id,
        )
        payload = standard_alert_payload(event)
        payload.update({
            "result_summary": event.result_summary,
            "required_action": event.required_action,
            "risk_summary": event.risk_summary,
            "phase": event.phase,
            "collapse_id": event.collapse_id,
            "dedupe_key": event.dedupe_key,
            "kind": kind,
            "session_id": native_id,
            "provider": provider,
        })
        return payload

    def _route_session_id_for_event(self, session_id: str) -> str:
        provider, native_id = _parse_session_ref(session_id)
        if provider == "claude" and native_id:
            resolved = self.claude_session_resolver(native_id)
            if resolved:
                return f"claude:{resolved}"
        if provider == "codex" and native_id:
            return f"codex:{native_id}"
        return session_id

    def _standard_push_devices(self) -> list[dict[str, Any]]:
        try:
            status = self.push_dispatcher.status()
        except Exception as exc:
            self._log(f"push status unavailable for standard turn publisher: {type(exc).__name__}: {exc}")
            return []
        if not _provider_can_deliver(status):
            return []
        devices = status.get("devices") if isinstance(status, dict) else []
        out: list[dict[str, Any]] = []
        for device in devices if isinstance(devices, list) else []:
            if isinstance(device, dict) and device.get("standard_push_enabled") and device.get("device_id"):
                out.append(device)
        return out

    def _device_wants_event(self, device: dict[str, Any], kind: str) -> bool:
        if kind == "turn_result":
            return bool(device.get("turn_done_enabled"))
        return True

    def _publish(self, device_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        key = (device_id, payload["kind"], payload["event_id"])
        now = float(self.now_fn())
        previous = self._last_attempts.get(key)
        if previous and previous.get("ok"):
            return None
        if previous and now - float(previous.get("attempted_at") or 0) < self.failed_retry_interval:
            return None
        delivery = self.push_dispatcher.record_event(device_id=device_id, payload=payload)
        self._last_attempts[key] = {
            "attempted_at": now,
            "ok": bool(delivery.get("ok")),
        }
        return delivery

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(message)


class MacHealthAlertPublisher:
    """Publish a bounded Mac-health alert when coordinator posture becomes unsafe."""

    def __init__(
        self,
        *,
        push_dispatcher,
        health_snapshot_fn: Callable[[], dict[str, Any]],
        now_fn=time.time,
        sleep_fn=time.sleep,
        poll_interval: float = 30.0,
        cooldown_seconds: float = 30 * 60,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self.push_dispatcher = push_dispatcher
        self.health_snapshot_fn = health_snapshot_fn
        self.now_fn = now_fn
        self.sleep_fn = sleep_fn
        self.poll_interval = poll_interval
        self.cooldown_seconds = cooldown_seconds
        self.logger = logger
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_signature: str | None = None
        self._last_sent_at: dict[tuple[str, str], float] = {}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self.run_forever,
            name="pairling-mac-health-publisher",
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
                self._log(f"mac health publisher scan failed: {type(exc).__name__}: {exc}")
            self.sleep_fn(self.poll_interval)

    def scan_once(self) -> list[dict[str, Any]]:
        devices = self._standard_push_devices()
        if not devices:
            return []
        health = self.health_snapshot_fn()
        coordinator = health.get("coordinator") if isinstance(health.get("coordinator"), dict) else {}
        posture = str(coordinator.get("posture") or "unknown")[:40]
        severity = str(coordinator.get("severity") or posture)[:40]
        summary = str(coordinator.get("summary") or "The paired Mac helper needs attention.")[:180]
        unsafe = not bool(health.get("ok")) or posture not in {"ready", "warning"}
        signature = _stable_hash({"posture": posture, "severity": severity, "summary": summary})
        if not unsafe:
            self._last_signature = signature
            return []
        if signature == self._last_signature:
            return []
        self._last_signature = signature
        event_id = "push_auto_mac_health_" + signature[:24]
        event = build_push_event(
            event_id=event_id,
            kind="mac_route_risk",
            source="mac-health",
            observed_at=float(self.now_fn()),
            phase="stale",
            risk_level="critical" if severity == "critical" else "warning",
            risk_summary=summary,
            route_health=posture,
            action_route="pairling://health",
        )
        payload = standard_alert_payload(event)
        payload.update({
            "health_posture": posture,
            "health_severity": severity,
            "health_summary": summary,
            "phase": "risk",
            "route_health": event.route_health,
            "collapse_id": event.collapse_id,
            "dedupe_key": event.dedupe_key,
        })
        results: list[dict[str, Any]] = []
        for device in devices:
            key = (device["device_id"], signature)
            now = float(self.now_fn())
            if now - float(self._last_sent_at.get(key) or 0) < self.cooldown_seconds:
                continue
            delivery = self.push_dispatcher.record_event(device_id=device["device_id"], payload=payload)
            self._last_sent_at[key] = now
            results.append(delivery)
        return results

    def _standard_push_devices(self) -> list[dict[str, Any]]:
        try:
            status = self.push_dispatcher.status()
        except Exception as exc:
            self._log(f"push status unavailable for mac health publisher: {type(exc).__name__}: {exc}")
            return []
        if not _provider_can_deliver(status):
            return []
        devices = status.get("devices") if isinstance(status, dict) else []
        return [
            item for item in devices if isinstance(item, dict)
            and item.get("standard_push_enabled")
            and item.get("device_id")
        ]

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(message)


class SentinelBackgroundEvaluator:
    """Periodically evaluate worker/token sentinel state for opted-in devices."""

    def __init__(
        self,
        *,
        sentinel_center,
        push_dispatcher,
        worker_stats_fn: Callable[[], dict[str, Any]],
        human_idle_minutes_fn: Callable[[], float | None] | None = None,
        token_sessions_fn: Callable[[], list[dict[str, Any]]] | None = None,
        now_fn=time.time,
        sleep_fn=time.sleep,
        poll_interval: float = 60.0,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self.sentinel_center = sentinel_center
        self.push_dispatcher = push_dispatcher
        self.worker_stats_fn = worker_stats_fn
        self.human_idle_minutes_fn = human_idle_minutes_fn or (lambda: None)
        self.token_sessions_fn = token_sessions_fn or (lambda: [])
        self.now_fn = now_fn
        self.sleep_fn = sleep_fn
        self.poll_interval = poll_interval
        self.logger = logger
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self.run_forever,
            name="pairling-sentinel-publisher",
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
                self._log(f"sentinel publisher scan failed: {type(exc).__name__}: {exc}")
            self.sleep_fn(self.poll_interval)

    def scan_once(self) -> list[dict[str, Any]]:
        devices = self._sentinel_devices()
        if not devices:
            return []
        worker_stats = self.worker_stats_fn()
        token_sessions = self.token_sessions_fn()
        human_idle = self.human_idle_minutes_fn()
        results: list[dict[str, Any]] = []
        for device in devices:
            results.append(self.sentinel_center.evaluate_now(
                worker_stats=worker_stats,
                token_sessions=token_sessions,
                human_idle_minutes=human_idle,
                device_id=device["device_id"],
                force=False,
            ))
        return results

    def _sentinel_devices(self) -> list[dict[str, Any]]:
        try:
            status = self.push_dispatcher.status()
        except Exception as exc:
            self._log(f"push status unavailable for sentinel publisher: {type(exc).__name__}: {exc}")
            return []
        if not _provider_can_deliver(status):
            return []
        devices = status.get("devices") if isinstance(status, dict) else []
        return [
            item for item in devices if isinstance(item, dict)
            and item.get("standard_push_enabled")
            and item.get("worker_sentinel_enabled")
            and item.get("device_id")
        ]

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(message)


def _parse_session_ref(session_id: str) -> tuple[str, str]:
    text = str(session_id or "").strip()
    if ":" in text:
        provider, native_id = text.split(":", 1)
        if provider in {"claude", "codex"} and _safe_stem(native_id):
            return provider, native_id
    if _safe_stem(text):
        return "claude", text
    return "claude", ""


def _provider_can_deliver(status: dict[str, Any]) -> bool:
    provider = status.get("provider") if isinstance(status, dict) else None
    return not isinstance(provider, dict) or bool(provider.get("configured"))


def _safe_stem(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.:-]{1,180}", str(value or "")))


def _is_done_state(raw_state: Any, raw_event: Any) -> bool:
    state = str(raw_state or "").strip().lower()
    event = str(raw_event or "").strip().lower()
    return state in {"idle", "done", "completed"} or event in {"stop", "session_end"}


def _optional_float(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _bounded_optional(value: Any, limit: int) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    return text[:limit]


def _stable_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
