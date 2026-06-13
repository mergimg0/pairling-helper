#!/usr/bin/env python3
"""Worker/token sentinel notification classifier and local event ledger.

This module is deliberately payload-small. It turns worker/token counters into
bounded notification events and never accepts transcript text, prompts, or raw
provider credentials as inputs.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any

from push_event_catalog import build_push_event, standard_alert_payload


CONTRACT_VERSION = "pairling-sentinel-notifications-v1"

DEFAULT_PREFERENCES: dict[str, Any] = {
    "enabled": True,
    "push_enabled": True,
    "resolutions_enabled": False,
    "worker_warning_active": 12,
    "worker_critical_active": 25,
    "worker_watch_active": 8,
    "worker_watch_total": 15,
    "human_idle_warning_minutes": 15,
    "human_idle_critical_minutes": 30,
    "stale_worker_minutes": 60,
    "stale_cleanup_count": 5,
    "token_pressure_ratio": 0.70,
    "cooldown_warning_minutes": 30,
    "cooldown_critical_minutes": 60,
}

_INT_PREFS = {
    "worker_warning_active",
    "worker_critical_active",
    "worker_watch_active",
    "worker_watch_total",
    "human_idle_warning_minutes",
    "human_idle_critical_minutes",
    "stale_worker_minutes",
    "stale_cleanup_count",
    "cooldown_warning_minutes",
    "cooldown_critical_minutes",
}
_FLOAT_PREFS = {"token_pressure_ratio"}
_BOOL_PREFS = {"enabled", "push_enabled", "resolutions_enabled"}
_LEVEL_RANK = {"info": 0, "watch": 1, "stale_cleanup": 2, "token_pressure": 3, "warning": 4, "critical": 5}


class SentinelNotificationError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


class SentinelNotificationCenter:
    def __init__(self, root: Path, *, now_fn=time.time, push_dispatcher=None) -> None:
        self.root = Path(root)
        self.dir = self.root / "sentinel"
        self.preferences_path = self.dir / "preferences.json"
        self.state_path = self.dir / "state.json"
        self.events_path = self.dir / "events.jsonl"
        self.now_fn = now_fn
        self.push_dispatcher = push_dispatcher

    def preferences(self) -> dict[str, Any]:
        prefs = dict(DEFAULT_PREFERENCES)
        try:
            loaded = json.loads(self.preferences_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            loaded = {}
        if isinstance(loaded, dict):
            for key in DEFAULT_PREFERENCES:
                if key in loaded:
                    prefs[key] = self._normalize_pref(key, loaded[key])
        return {
            "ok": True,
            "contract_version": CONTRACT_VERSION,
            "preferences": prefs,
            "updated_at": self._state().get("updated_at"),
        }

    def update_preferences(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise SentinelNotificationError("invalid_preferences", "preferences body must be an object")
        prefs = self.preferences()["preferences"]
        unknown = [key for key in payload if key not in DEFAULT_PREFERENCES]
        if unknown:
            raise SentinelNotificationError("unknown_preference", "unknown sentinel preference: " + unknown[0])
        for key, value in payload.items():
            prefs[key] = self._normalize_pref(key, value)
        self._write_json(self.preferences_path, prefs)
        state = self._state()
        state["updated_at"] = self.now_fn()
        self._write_json(self.state_path, state)
        return self.preferences()

    def status(
        self,
        *,
        worker_stats: dict[str, Any] | None = None,
        token_sessions: list[dict[str, Any]] | None = None,
        human_idle_minutes: float | None = None,
    ) -> dict[str, Any]:
        prefs = self.preferences()["preferences"]
        classification = self.classify(
            worker_stats or {},
            token_sessions=token_sessions or [],
            human_idle_minutes=human_idle_minutes,
            prefs=prefs,
        )
        state = self._state()
        return {
            "ok": True,
            "contract_version": CONTRACT_VERSION,
            **classification,
            "snoozed_until": self._snoozed_until(classification["dedupe_key"], state),
            "last_push_event_id": state.get("last_push_event_id"),
            "preferences": prefs,
        }

    def evaluate_now(
        self,
        *,
        worker_stats: dict[str, Any],
        token_sessions: list[dict[str, Any]] | None = None,
        human_idle_minutes: float | None = None,
        device_id: str | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        status = self.status(
            worker_stats=worker_stats,
            token_sessions=token_sessions or [],
            human_idle_minutes=human_idle_minutes,
        )
        prefs = status["preferences"]
        state = self._state()
        event = self._event_from_status(status, device_id=device_id)
        suppressed = self._suppression_reason(status, prefs, state, force=force, device_id=device_id)
        delivery = None
        if suppressed is None and prefs.get("push_enabled") and self.push_dispatcher is not None and device_id:
            try:
                push_event = build_push_event(
                    kind="worker_pressure",
                    event_id=event["event_id"],
                    source="sentinel",
                    provider=str(worker_stats.get("provider") or "all"),
                    project=_project_scope(worker_stats),
                    observed_at=event["created_at"],
                    phase="attention",
                    required_action="Open workers to review pressure.",
                    risk_level=status["severity"],
                    risk_summary=status["body"],
                    worker_summary=status["summary"],
                    action_route=status["route"],
                    dedupe_key=status["dedupe_key"],
                )
                push_payload = standard_alert_payload(push_event)
                push_payload.update({
                    "sentinel_event_id": event["event_id"],
                    "sentinel_level": event["level"],
                    "sentinel_key": event["dedupe_key"],
                    "worker_summary": push_event.worker_summary,
                    "risk_summary": push_event.risk_summary,
                    "required_action": push_event.required_action,
                    "phase": push_event.phase,
                    "collapse_id": push_event.collapse_id,
                    "dedupe_key": push_event.dedupe_key,
                })
                delivery = self.push_dispatcher.record_event(
                    device_id=device_id,
                    payload=push_payload,
                )
                event["sent"] = bool(delivery.get("ok"))
                event["delivery_outcome"] = (delivery.get("delivery") or {}).get("outcome")
            except Exception as exc:  # keep classifier useful even if push is down.
                event["sent"] = False
                event["delivery_outcome"] = f"{type(exc).__name__}: {exc}"[:180]
        elif suppressed is None:
            event["sent"] = False
            event["delivery_outcome"] = "no_push_dispatcher_or_device"
        else:
            event["sent"] = False
            event["suppressed_reason"] = suppressed

        if suppressed is None:
            sent_events = state.setdefault("sent_events", {})
            sent_events[_sent_event_state_key(event["dedupe_key"], device_id)] = {
                "last_sent_at": self.now_fn(),
                "event_id": event["event_id"],
                "level": event["level"],
                "device_id": str(device_id or "")[:120] or None,
            }
            state["last_push_event_id"] = event["event_id"]
        state["updated_at"] = self.now_fn()
        self._write_json(self.state_path, state)
        self._append_event(event)
        return {
            "ok": True,
            "status": status,
            "event": event,
            "delivery": delivery,
        }

    def snooze(self, *, key: str | None = None, minutes: int = 60) -> dict[str, Any]:
        minutes = max(1, min(int(minutes or 60), 60 * 24))
        dedupe_key = str(key or "*").strip() or "*"
        state = self._state()
        snoozes = state.setdefault("snoozes", {})
        snoozes[dedupe_key] = self.now_fn() + minutes * 60
        state["updated_at"] = self.now_fn()
        self._write_json(self.state_path, state)
        return {
            "ok": True,
            "key": dedupe_key,
            "snoozed_until": snoozes[dedupe_key],
        }

    def events(self, *, since: float | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if not self.events_path.exists():
            return []
        since = float(since or 0)
        limit = max(1, min(int(limit or 100), 300))
        events: list[dict[str, Any]] = []
        try:
            for line in self.events_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue
                if float(event.get("created_at") or 0) > since:
                    events.append(event)
        except OSError:
            return []
        events.sort(key=lambda item: float(item.get("created_at") or 0), reverse=True)
        return events[:limit]

    def classify(
        self,
        worker_stats: dict[str, Any],
        *,
        token_sessions: list[dict[str, Any]],
        human_idle_minutes: float | None,
        prefs: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        prefs = prefs or self.preferences()["preferences"]
        active = _int(worker_stats.get("automated_active"))
        idle = _int(worker_stats.get("automated_idle"))
        total = _int(worker_stats.get("total"), active + idle)
        stale_ids = worker_stats.get("stale_session_ids") if isinstance(worker_stats.get("stale_session_ids"), list) else []
        stale_count = len(stale_ids)
        token_pressure_sessions = self._token_pressure_sessions(token_sessions, prefs)
        human_idle = float(human_idle_minutes) if human_idle_minutes is not None else None
        unattended_warning = human_idle is None or human_idle >= prefs["human_idle_warning_minutes"]
        unattended_critical = human_idle is None or human_idle >= prefs["human_idle_critical_minutes"]

        level = "info"
        kind = "quiet"
        severity = "info"
        title = "Pairling sentinel quiet"
        body = "No worker or token condition currently requires a push."

        if active >= prefs["worker_critical_active"] and unattended_critical:
            level = "critical"
            kind = "worker_swarm"
            severity = "critical"
            title = "Pairling automation needs review"
            body = f"{active} automated sessions are active. Review stale workers before token burn continues."
        elif active >= prefs["worker_warning_active"] and unattended_warning:
            level = "warning"
            kind = "worker_swarm"
            severity = "warning"
            title = "Pairling worker warning"
            idle_text = f" and you have been away for {int(human_idle)} minutes" if human_idle is not None else ""
            body = f"{active} automated sessions are active{idle_text}."
        elif stale_count >= prefs["stale_cleanup_count"]:
            level = "stale_cleanup"
            kind = "stale_cleanup"
            severity = "warning"
            title = "Pairling found stale workers"
            body = f"{stale_count} workers have been idle for over an hour."
        elif token_pressure_sessions and unattended_warning:
            level = "token_pressure"
            kind = "token_pressure"
            severity = "warning"
            title = "Pairling context pressure"
            body = "This turn is near the context limit. Open the session to review."
        elif active >= prefs["worker_watch_active"] or total >= prefs["worker_watch_total"]:
            level = "watch"
            kind = "worker_watch"
            severity = "info"
            title = "Pairling worker watch"
            body = f"{active} active workers, {idle} idle workers."

        project_scope = _project_scope(worker_stats)
        provider = str(worker_stats.get("provider") or "all")[:40]
        dedupe_key = f"sentinel:{kind}:{provider}:{project_scope}:{severity}"
        return {
            "level": level,
            "kind": kind,
            "severity": severity,
            "summary": f"{active} active workers, {idle} idle, {stale_count} stale",
            "active_workers": active,
            "idle_workers": idle,
            "total_workers": total,
            "stale_workers": stale_count,
            "stale_session_ids": [str(item)[:120] for item in stale_ids[:50]],
            "token_pressure_sessions": token_pressure_sessions,
            "human_idle_minutes": human_idle,
            "dedupe_key": dedupe_key,
            "title": title,
            "body": body,
            "route": "pairling://workers",
        }

    def _token_pressure_sessions(self, token_sessions: list[dict[str, Any]], prefs: dict[str, Any]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for item in token_sessions:
            if not isinstance(item, dict):
                continue
            tokens = _int(item.get("tokens") or item.get("total_tokens"))
            context_window = _int(item.get("context_window"))
            if tokens <= 0 or context_window <= 0:
                continue
            ratio = tokens / context_window
            if ratio >= float(prefs["token_pressure_ratio"]):
                rows.append({
                    "session_id": str(item.get("session_id") or "")[:120],
                    "provider": str(item.get("provider") or "all")[:40],
                    "tokens": tokens,
                    "context_window": context_window,
                    "ratio": round(ratio, 4),
                })
        return rows[:20]

    def _suppression_reason(
        self,
        status: dict[str, Any],
        prefs: dict[str, Any],
        state: dict[str, Any],
        *,
        force: bool,
        device_id: str | None,
    ) -> str | None:
        if force:
            return None
        if not prefs.get("enabled"):
            return "disabled"
        if status["level"] in {"info", "watch"}:
            return "not_push_level"
        key = status["dedupe_key"]
        snoozed_until = self._snoozed_until(key, state)
        if snoozed_until and snoozed_until > self.now_fn():
            return "snoozed"
        sent = state.get("sent_events", {}).get(_sent_event_state_key(key, device_id))
        if isinstance(sent, dict):
            last_sent_at = float(sent.get("last_sent_at") or 0)
            cooldown = prefs["cooldown_critical_minutes"] if status["severity"] == "critical" else prefs["cooldown_warning_minutes"]
            if self.now_fn() - last_sent_at < cooldown * 60:
                return "cooldown"
        human_idle = status.get("human_idle_minutes")
        if human_idle is not None:
            if status["severity"] == "critical" and human_idle < prefs["human_idle_critical_minutes"]:
                return "human_recent"
            if status["severity"] != "critical" and human_idle < prefs["human_idle_warning_minutes"]:
                return "human_recent"
        return None

    def _snoozed_until(self, key: str, state: dict[str, Any]) -> float | None:
        snoozes = state.get("snoozes") if isinstance(state.get("snoozes"), dict) else {}
        until = max(float(snoozes.get("*") or 0), float(snoozes.get(key) or 0))
        return until or None

    def _event_from_status(self, status: dict[str, Any], *, device_id: str | None) -> dict[str, Any]:
        created_at = self.now_fn()
        digest = hashlib.sha256(
            json.dumps({
                "created_at": int(created_at),
                "key": status["dedupe_key"],
                "level": status["level"],
            }, sort_keys=True).encode("utf-8")
        ).hexdigest()[:10]
        return {
            "event_id": f"sent_{int(created_at * 1000)}_{digest}",
            "created_at": created_at,
            "kind": status["kind"],
            "level": status["level"],
            "severity": status["severity"],
            "dedupe_key": status["dedupe_key"],
            "title": status["title"],
            "body": status["body"],
            "route": status["route"],
            "device_id": str(device_id or "")[:120] or None,
            "active_workers": status["active_workers"],
            "idle_workers": status["idle_workers"],
            "stale_workers": status["stale_workers"],
            "token_pressure_sessions": status["token_pressure_sessions"],
        }

    def _state(self) -> dict[str, Any]:
        try:
            loaded = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            loaded = {}
        if not isinstance(loaded, dict):
            loaded = {}
        loaded.setdefault("sent_events", {})
        loaded.setdefault("snoozes", {})
        return loaded

    def _append_event(self, event: dict[str, Any]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, stat.S_IRWXU)
        except OSError:
            pass
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
        try:
            os.chmod(self.events_path, 0o600)
        except OSError:
            pass

    def _write_json(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path.parent, stat.S_IRWXU)
        except OSError:
            pass
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def _normalize_pref(self, key: str, value: Any) -> Any:
        if key in _BOOL_PREFS:
            return bool(value)
        if key in _INT_PREFS:
            parsed = max(0, min(int(value), 10000))
            if key.startswith("cooldown") or key.startswith("human_idle") or key == "stale_worker_minutes":
                return max(1, parsed)
            return parsed
        if key in _FLOAT_PREFS:
            return max(0.05, min(float(value), 0.99))
        return value


def _sent_event_state_key(dedupe_key: str, device_id: str | None) -> str:
    device = str(device_id or "").strip()
    if not device:
        return dedupe_key
    return f"{dedupe_key}:device:{device[:120]}"


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _project_scope(worker_stats: dict[str, Any]) -> str:
    projects = worker_stats.get("projects")
    if not isinstance(projects, list) or not projects:
        return "all"
    first = projects[0] if isinstance(projects[0], dict) else {}
    path = str(first.get("path") or first.get("project") or "all")
    name = Path(path).name or "all"
    safe = "".join(ch for ch in name if ch.isalnum() or ch in {"-", "_"})[:60]
    return safe or "all"
