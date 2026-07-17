#!/usr/bin/env python3
"""Daemon-side router for Pairling MCP tools."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from llm_route import LLMRouteError, run_local_llm


SCHEMA_VERSION = 1
ALLOWED_TOOLS = {"vibe_check", "second_opinion", "user_likely_prefers", "corpus_recall"}
ALLOWED_STRATEGIES = {"auto", "iphone_only", "mac_only"}
PHONE_TOOL_LIST = sorted(ALLOWED_TOOLS)
MAX_INPUT_CHARS = 12_000
MAX_OUTPUT_CHARS = 2_000
IPHONE_TIMEOUT_MS_DEFAULT = 2_500
IPHONE_TIMEOUT_MS_MAX = 5_000
FAST_VIBE_CHECK_TIMEOUT_SECONDS = max(1, min(int(os.environ.get("PAIRLING_FAST_VIBE_TIMEOUT_SECONDS", "6")), 9))
IPHONE_HOST = os.environ.get("PHONE_TS_HOST", os.environ.get("PAIRLING_PHONE_TOOLS_HOST", "iphone-15-pro"))
IPHONE_PORT = int(os.environ.get("PHONE_TS_PORT", os.environ.get("PAIRLING_PHONE_TOOLS_PORT", "7724")))
WORKER_LEASE_SECONDS = 60
REVOKED_WORKER_TTL_SECONDS = 10 * 60
COMPLETION_TOMBSTONE_TTL_SECONDS = 10 * 60
MAX_TRACKED_PHONE_DEVICES = 64
MAX_REVOKED_WORKERS = 256
MAX_COMPLETION_TOMBSTONES = 256
CURRENT_WORKER_ID_PATTERN = re.compile(r"v3:[A-Za-z0-9][A-Za-z0-9._-]{0,96}\Z")


def current_worker_id(value: Any) -> str | None:
    if not isinstance(value, str) or value != value.strip():
        return None
    return value if CURRENT_WORKER_ID_PATTERN.fullmatch(value) is not None else None


@dataclass(frozen=True)
class ToolResult:
    ok: bool
    provider: str | None
    result: str = ""
    reason: str | None = None
    error_message: str | None = None


class PhoneToolAvailabilityStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._states: dict[str, dict[str, Any]] = {}

    def update(
        self,
        payload: dict[str, Any],
        *,
        device_id: str | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        current = time.time() if now is None else now
        normalized_device = str(device_id or payload.get("device_id") or "").strip()[:160]
        if not normalized_device:
            return self.snapshot(now=current)
        running = bool(payload.get("listener_running"))
        try:
            expires_in = int(payload.get("expires_in_seconds") or 30)
        except (TypeError, ValueError):
            expires_in = 30
        expires_in = max(1, min(expires_in, 120))
        tools = payload.get("tools")
        if not isinstance(tools, list):
            tools = PHONE_TOOL_LIST
        normalized_tools = sorted({str(tool) for tool in tools if str(tool) in ALLOWED_TOOLS})
        worker_id = current_worker_id(payload.get("worker_id"))
        if worker_id is None:
            return self.snapshot(device_id=normalized_device, now=current)
        with self._lock:
            self._prune_locked(current)
            active_worker = str(self._states.get(normalized_device, {}).get("worker_id") or "")
            # A delayed stop from an earlier lifecycle cannot turn off the
            # current worker for this phone.
            if not running and active_worker and active_worker != worker_id:
                return self.snapshot(device_id=normalized_device, now=current)
            self._states[normalized_device] = {
                "device_id": normalized_device,
                "last_seen_at": current,
                "expires_at": current + expires_in if running else current,
                "listener_running": running,
                "port": _bounded_int(payload.get("port"), default=IPHONE_PORT, minimum=0, maximum=65535),
                "tools": normalized_tools,
                "app_state": str(payload.get("app_state") or "unknown")[:40],
                "worker_id": worker_id,
            }
            self._bound_states_locked()
            return self.snapshot(device_id=normalized_device, now=current)

    def remove_device(self, device_id: str | None) -> None:
        normalized_device = str(device_id or "").strip()[:160]
        if not normalized_device:
            return
        with self._lock:
            self._states.pop(normalized_device, None)

    def snapshot(self, *, device_id: str | None = None, now: float | None = None) -> dict[str, Any]:
        current = time.time() if now is None else now
        with self._lock:
            self._prune_locked(current)
            normalized_device = str(device_id or "").strip()[:160]
            if normalized_device:
                state = dict(self._states.get(normalized_device, {}))
                state["fresh"] = self._state_is_fresh(state, current)
                return state
            states = [dict(state) for state in self._states.values()]
            fresh = [state for state in states if self._state_is_fresh(state, current)]
            aggregate: dict[str, Any] = {
                "fresh": len(fresh) == 1,
                "ambiguous": len(fresh) > 1,
                "devices": sorted(states, key=lambda state: str(state.get("device_id") or "")),
            }
            if len(fresh) == 1:
                aggregate.update(fresh[0])
            return aggregate

    def is_fresh(
        self,
        tool: str | None = None,
        *,
        device_id: str | None = None,
        now: float | None = None,
    ) -> bool:
        current = time.time() if now is None else now
        with self._lock:
            self._prune_locked(current)
            normalized_device = str(device_id or "").strip()[:160]
            candidates = [
                state
                for candidate_device, state in self._states.items()
                if (not normalized_device or candidate_device == normalized_device)
                and self._state_is_fresh(state, current)
                and (not tool or tool in set(state.get("tools") or []))
            ]
            return len(candidates) == 1

    @staticmethod
    def _state_is_fresh(state: dict[str, Any], current: float) -> bool:
        return (
            current_worker_id(state.get("worker_id")) is not None
            and bool(state.get("listener_running"))
            and float(state.get("expires_at") or 0) > current
        )

    def _prune_locked(self, current: float) -> None:
        stale_before = current - REVOKED_WORKER_TTL_SECONDS
        self._states = {
            device_id: state
            for device_id, state in self._states.items()
            if float(state.get("last_seen_at") or 0) > stale_before
        }

    def _bound_states_locked(self) -> None:
        if len(self._states) <= MAX_TRACKED_PHONE_DEVICES:
            return
        oldest = sorted(
            self._states,
            key=lambda device_id: float(self._states[device_id].get("last_seen_at") or 0),
        )
        for device_id in oldest[: len(self._states) - MAX_TRACKED_PHONE_DEVICES]:
            self._states.pop(device_id, None)


PHONE_TOOL_AVAILABILITY = PhoneToolAvailabilityStore()


class PhoneToolWorkQueue:
    def __init__(self) -> None:
        self._condition = threading.Condition(threading.RLock())
        self._pending: list[dict[str, Any]] = []
        self._inflight: dict[str, dict[str, Any]] = {}
        self._results: dict[str, ToolResult] = {}
        self._pollers: dict[str, dict[str, Any]] = {}
        self._active_workers: dict[str, dict[str, Any]] = {}
        self._revoked_workers: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._completion_tombstones: OrderedDict[str, float] = OrderedDict()

    @staticmethod
    def _worker_id(worker_id: str | None) -> str | None:
        return current_worker_id(worker_id)

    @staticmethod
    def _device_id(device_id: str | None) -> str:
        return str(device_id or "").strip()[:160]

    def activate_worker(
        self,
        *,
        device_id: str | None,
        worker_id: str | None,
        supersedes_worker_id: str | None = None,
        now: float | None = None,
    ) -> bool:
        normalized_device = self._device_id(device_id)
        normalized_worker = self._worker_id(worker_id)
        if not normalized_device or normalized_worker is None:
            return False
        supersedes = None
        if supersedes_worker_id is not None:
            supersedes = self._worker_id(supersedes_worker_id)
            if supersedes is None:
                return False
        current = time.time() if now is None else now
        with self._condition:
            self._prune_lifecycle_locked(current)
            worker_key = (normalized_device, normalized_worker)
            active_state = self._active_workers.get(normalized_device)
            active_worker = str(active_state.get("worker_id") or "") if active_state else ""
            if active_worker == normalized_worker:
                active_state["last_seen_at"] = current
                return True
            if worker_key in self._revoked_workers:
                return False
            # Replacement is a compare-and-swap against the worker lifecycle
            # remembered by the phone. A delayed start for an older lifecycle
            # cannot replace a newer worker merely because its request arrived
            # last.
            if active_worker:
                if supersedes != active_worker:
                    return False
                self._revoke_worker_locked(normalized_device, active_worker, current)
                self._cancel_worker_locked(
                    normalized_device,
                    active_worker,
                    reason="iphone_worker_replaced",
                )
            self._active_workers[normalized_device] = {
                "worker_id": normalized_worker,
                "activated_at": current,
                "last_seen_at": current,
            }
            self._bound_devices_locked(current)
            self._condition.notify_all()
            return True

    def deactivate_worker(
        self,
        *,
        device_id: str | None,
        worker_id: str | None,
        now: float | None = None,
    ) -> bool:
        normalized_device = self._device_id(device_id)
        normalized_worker = self._worker_id(worker_id)
        if not normalized_device or normalized_worker is None:
            return False
        current = time.time() if now is None else now
        with self._condition:
            self._prune_lifecycle_locked(current)
            self._revoke_worker_locked(normalized_device, normalized_worker, current)
            active = self._active_workers.get(normalized_device)
            if not active or active.get("worker_id") != normalized_worker:
                return False
            self._active_workers.pop(normalized_device, None)
            self._cancel_worker_locked(normalized_device, normalized_worker, reason="iphone_worker_stopped")
            self._condition.notify_all()
            return True

    def deactivate_device(self, device_id: str | None, *, reason: str = "iphone_credential_changed") -> bool:
        normalized_device = self._device_id(device_id)
        if not normalized_device:
            return False
        with self._condition:
            active = self._active_workers.pop(normalized_device, None)
            self._pollers.pop(normalized_device, None)
            if active:
                worker_id = str(active.get("worker_id") or "")
                self._revoke_worker_locked(normalized_device, worker_id, time.time())
                self._cancel_worker_locked(normalized_device, worker_id, reason=reason)
            # Credential invalidation is device-wide. Clear any stale request
            # left by an older worker lifecycle as well as the active worker.
            self._cancel_device_requests_locked(normalized_device, reason=reason)
            self._condition.notify_all()
            return active is not None

    def _cancel_worker_locked(self, device_id: str, worker_id: str, *, reason: str) -> None:
        poller = self._pollers.get(device_id)
        if poller and poller.get("worker_id") == worker_id:
            self._pollers.pop(device_id, None)

        cancelled_ids = [
            request_id
            for request_id, request in self._inflight.items()
            if request.get("assigned_device_id") == device_id
            and request.get("assigned_worker_id") == worker_id
        ]
        for request_id in cancelled_ids:
            self._inflight.pop(request_id, None)
            self._results[request_id] = ToolResult(
                False,
                "iphone",
                reason=reason,
                error_message=reason.replace("_", " "),
            )
            self._mark_completion_tombstone_locked(request_id, time.time())

        retained_pending: list[dict[str, Any]] = []
        for request in self._pending:
            if (
                request.get("target_device_id") != device_id
                or request.get("target_worker_id") != worker_id
            ):
                retained_pending.append(request)
                continue
            self._results[request["request_id"]] = ToolResult(
                False,
                "iphone",
                reason=reason,
                error_message=reason.replace("_", " "),
            )
            self._mark_completion_tombstone_locked(request["request_id"], time.time())
        self._pending = retained_pending

    def _cancel_device_requests_locked(self, device_id: str, *, reason: str) -> None:
        workers = {
            str(request.get("assigned_worker_id") or request.get("target_worker_id") or "")
            for request in [*self._pending, *self._inflight.values()]
            if request.get("assigned_device_id") == device_id or request.get("target_device_id") == device_id
        }
        workers.discard("")
        for worker_id in workers:
            self._cancel_worker_locked(device_id, worker_id, reason=reason)

    def worker_is_active(self, *, device_id: str | None, worker_id: str | None) -> bool:
        if not device_id:
            return False
        normalized_worker = self._worker_id(worker_id)
        if normalized_worker is None:
            return False
        with self._condition:
            self._prune_lifecycle_locked(time.time())
            active = self._active_workers.get(self._device_id(device_id))
            return bool(active and active.get("worker_id") == normalized_worker)

    def report_poller(
        self,
        *,
        device_id: str | None,
        tools: list[str] | None,
        worker_id: str | None = None,
        now: float | None = None,
        expires_in_seconds: int = 30,
    ) -> dict[str, Any]:
        current = time.time() if now is None else now
        normalized_tools = sorted({str(tool) for tool in (tools or PHONE_TOOL_LIST) if str(tool) in ALLOWED_TOOLS})
        expires = current + max(1, min(int(expires_in_seconds or 30), 120))
        normalized_worker = self._worker_id(worker_id)
        normalized_device = self._device_id(device_id)
        with self._condition:
            self._prune_lifecycle_locked(current)
            active = self._active_workers.get(normalized_device)
            if (
                normalized_worker is None
                or not normalized_device
                or not active
                or active.get("worker_id") != normalized_worker
            ):
                return self.snapshot(device_id=normalized_device, now=current)
            active["last_seen_at"] = current
            self._pollers[normalized_device] = {
                "device_id": normalized_device,
                "worker_id": normalized_worker,
                "last_seen_at": current,
                "expires_at": expires,
                "tools": normalized_tools,
            }
            self._condition.notify_all()
            return self.snapshot(device_id=normalized_device, now=current)

    def snapshot(self, *, device_id: str | None = None, now: float | None = None) -> dict[str, Any]:
        current = time.time() if now is None else now
        with self._condition:
            self._prune_lifecycle_locked(current)
            normalized_device = self._device_id(device_id)
            if normalized_device:
                state = dict(self._pollers.get(normalized_device, {}))
                state["fresh"] = self._poller_is_fresh_locked(state, current)
                return state
            fresh = self._fresh_pollers_locked(None, current)
            aggregate: dict[str, Any] = {
                "fresh": len(fresh) == 1,
                "ambiguous": len(fresh) > 1,
                "device_ids": sorted(str(state.get("device_id") or "") for state in fresh),
            }
            if len(fresh) == 1:
                aggregate.update(fresh[0])
            return aggregate

    def is_fresh(
        self,
        tool: str | None = None,
        *,
        target_device_id: str | None = None,
        now: float | None = None,
    ) -> bool:
        current = time.time() if now is None else now
        with self._condition:
            _, reason = self._resolve_target_locked(tool, target_device_id, current)
            return reason is None

    def unavailable_reason(
        self,
        tool: str | None = None,
        *,
        target_device_id: str | None = None,
        now: float | None = None,
    ) -> str | None:
        current = time.time() if now is None else now
        with self._condition:
            _, reason = self._resolve_target_locked(tool, target_device_id, current)
            return reason

    def next_request(
        self,
        *,
        device_id: str | None,
        tools: list[str] | None,
        wait_seconds: int,
        worker_id: str | None = None,
        now: Callable[[], float] = time.time,
    ) -> dict[str, Any] | None:
        normalized_tools = sorted({str(tool) for tool in (tools or PHONE_TOOL_LIST) if str(tool) in ALLOWED_TOOLS})
        wait_seconds = max(1, min(int(wait_seconds or 10), 25))
        deadline = now() + wait_seconds
        normalized_worker = self._worker_id(worker_id)
        if normalized_worker is None:
            return None
        with self._condition:
            self.report_poller(
                device_id=device_id,
                tools=normalized_tools,
                worker_id=normalized_worker,
                now=now(),
                expires_in_seconds=wait_seconds + 20,
            )
            while True:
                active = self._active_workers.get(self._device_id(device_id))
                if not device_id or not active or active.get("worker_id") != normalized_worker:
                    return None
                self._prune_locked(now())
                active = self._active_workers.get(self._device_id(device_id))
                if not active or active.get("worker_id") != normalized_worker:
                    return None
                for idx, request in enumerate(self._pending):
                    if (
                        request["tool"] in normalized_tools
                        and request.get("target_device_id") == device_id
                        and request.get("target_worker_id") == normalized_worker
                    ):
                        request = self._pending.pop(idx)
                        request["assigned_device_id"] = device_id
                        request["assigned_worker_id"] = normalized_worker
                        self._inflight[request["request_id"]] = request
                        return {
                            "request_id": request["request_id"],
                            "tool": request["tool"],
                            "input": request["input"],
                            "created_at": request["created_at"],
                            "deadline_at": request["expires_at"],
                        }
                remaining = deadline - now()
                if remaining <= 0:
                    return None
                self._condition.wait(timeout=remaining)

    def complete(
        self,
        *,
        request_id: str,
        ok: bool,
        result: str = "",
        error: str = "",
        device_id: str | None = None,
        worker_id: str | None = None,
    ) -> str:
        request_id = str(request_id or "")
        if not request_id:
            return "stale"
        normalized_worker = self._worker_id(worker_id)
        if normalized_worker is None:
            return "wrong_owner"
        with self._condition:
            self._prune_requests_locked(time.time())
            request = self._inflight.get(request_id)
            if request is None:
                return "stale"
            if device_id is not None and request.get("assigned_device_id") != device_id:
                return "wrong_owner"
            if request.get("assigned_worker_id") != normalized_worker:
                return "wrong_owner"
            self._inflight.pop(request_id, None)
            self._results[request_id] = ToolResult(
                bool(ok),
                "iphone",
                result=str(result or ""),
                reason=None if ok else "iphone_tool_failed",
                error_message="" if ok else str(error or "phone tool failed"),
            )
            self._condition.notify_all()
            return "accepted"

    def submit(
        self,
        tool: str,
        input_payload: dict[str, Any],
        *,
        timeout_ms: int,
        target_device_id: str | None = None,
        now: Callable[[], float] = time.time,
    ) -> ToolResult:
        timeout = max(0.05, min(timeout_ms, IPHONE_TIMEOUT_MS_MAX) / 1000)
        request_id = str(uuid.uuid4()).lower()
        deadline = now() + timeout
        request = {
            "request_id": request_id,
            "tool": tool,
            "input": input_payload,
            "created_at": now(),
            "expires_at": deadline,
        }
        with self._condition:
            self._prune_requests_locked(now())
            target, reason = self._resolve_target_locked(tool, target_device_id, now())
            if target is None:
                return ToolResult(False, "iphone", reason=reason, error_message=(reason or "iphone unavailable").replace("_", " "))
            request["target_device_id"] = target.get("device_id")
            request["target_worker_id"] = target.get("worker_id")
            if self._worker_has_work_locked(str(target.get("device_id")), str(target.get("worker_id"))):
                return ToolResult(False, "iphone", reason="iphone_worker_busy", error_message="phone tool worker is busy")
            self._pending.append(request)
            self._condition.notify_all()
            while True:
                result = self._results.pop(request_id, None)
                if result is not None:
                    return result
                remaining = deadline - now()
                if remaining <= 0:
                    self._pending = [item for item in self._pending if item["request_id"] != request_id]
                    self._inflight.pop(request_id, None)
                    self._mark_completion_tombstone_locked(request_id, now())
                    return ToolResult(False, "iphone", reason="iphone_timeout", error_message="timed out")
                self._condition.wait(timeout=remaining)

    def _resolve_target_locked(
        self,
        tool: str | None,
        target_device_id: str | None,
        current: float,
    ) -> tuple[dict[str, Any] | None, str | None]:
        self._prune_lifecycle_locked(current)
        normalized_target = self._device_id(target_device_id)
        candidates = self._fresh_pollers_locked(tool, current)
        if normalized_target:
            for state in candidates:
                if state.get("device_id") == normalized_target:
                    return state, None
            return None, "iphone_target_unavailable"
        if not candidates:
            return None, "iphone_no_reverse_worker"
        if len(candidates) > 1:
            return None, "iphone_owner_ambiguous"
        return candidates[0], None

    def _fresh_pollers_locked(self, tool: str | None, current: float) -> list[dict[str, Any]]:
        return [
            dict(state)
            for state in self._pollers.values()
            if self._poller_is_fresh_locked(state, current)
            and (not tool or tool in set(state.get("tools") or []))
        ]

    @staticmethod
    def _poller_is_fresh_locked(state: dict[str, Any], current: float) -> bool:
        return (
            bool(state.get("device_id"))
            and current_worker_id(state.get("worker_id")) is not None
            and float(state.get("expires_at") or 0) > current
        )

    def _worker_has_work_locked(self, device_id: str, worker_id: str) -> bool:
        return any(
            request.get("target_device_id") == device_id and request.get("target_worker_id") == worker_id
            for request in self._pending
        ) or any(
            request.get("assigned_device_id") == device_id and request.get("assigned_worker_id") == worker_id
            for request in self._inflight.values()
        )

    def _prune_requests_locked(self, current: float) -> None:
        expired_pending = [item for item in self._pending if float(item.get("expires_at") or 0) <= current]
        self._pending = [item for item in self._pending if float(item.get("expires_at") or 0) > current]
        for item in expired_pending:
            self._mark_completion_tombstone_locked(str(item.get("request_id") or ""), current)
        expired = [
            request_id
            for request_id, item in self._inflight.items()
            if float(item.get("expires_at") or 0) <= current
        ]
        for request_id in expired:
            self._inflight.pop(request_id, None)
            self._results.pop(request_id, None)
            self._mark_completion_tombstone_locked(request_id, current)

    def _prune_locked(self, current: float) -> None:
        self._prune_lifecycle_locked(current)
        self._prune_requests_locked(current)

    def _prune_lifecycle_locked(self, current: float) -> None:
        expired_pollers = [
            device_id
            for device_id, state in self._pollers.items()
            if float(state.get("expires_at") or 0) <= current
        ]
        for device_id in expired_pollers:
            self._pollers.pop(device_id, None)
        expired_workers = [
            (device_id, str(state.get("worker_id") or ""))
            for device_id, state in self._active_workers.items()
            if float(state.get("last_seen_at") or state.get("activated_at") or 0) + WORKER_LEASE_SECONDS <= current
        ]
        for device_id, worker_id in expired_workers:
            self._active_workers.pop(device_id, None)
            self._revoke_worker_locked(device_id, worker_id, current)
            self._cancel_worker_locked(device_id, worker_id, reason="iphone_worker_expired")
        if expired_workers:
            self._condition.notify_all()
        revoked_before = current - REVOKED_WORKER_TTL_SECONDS
        while self._revoked_workers:
            key, revoked_at = next(iter(self._revoked_workers.items()))
            if revoked_at > revoked_before and len(self._revoked_workers) <= MAX_REVOKED_WORKERS:
                break
            self._revoked_workers.pop(key, None)
        tombstone_before = current - COMPLETION_TOMBSTONE_TTL_SECONDS
        while self._completion_tombstones:
            request_id, cancelled_at = next(iter(self._completion_tombstones.items()))
            if cancelled_at > tombstone_before and len(self._completion_tombstones) <= MAX_COMPLETION_TOMBSTONES:
                break
            self._completion_tombstones.pop(request_id, None)

    def _revoke_worker_locked(self, device_id: str, worker_id: str, current: float) -> None:
        if not worker_id:
            return
        key = (device_id, worker_id)
        self._revoked_workers[key] = current
        self._revoked_workers.move_to_end(key)

    def _mark_completion_tombstone_locked(self, request_id: str, current: float) -> None:
        if not request_id:
            return
        self._completion_tombstones[request_id] = current
        self._completion_tombstones.move_to_end(request_id)

    def _bound_devices_locked(self, current: float) -> None:
        if len(self._active_workers) <= MAX_TRACKED_PHONE_DEVICES:
            return
        oldest = sorted(
            self._active_workers,
            key=lambda device_id: float(self._active_workers[device_id].get("last_seen_at") or 0),
        )
        for device_id in oldest[: len(self._active_workers) - MAX_TRACKED_PHONE_DEVICES]:
            state = self._active_workers.pop(device_id)
            worker_id = str(state.get("worker_id") or "")
            self._revoke_worker_locked(device_id, worker_id, current)
            self._cancel_worker_locked(device_id, worker_id, reason="iphone_worker_evicted")


PHONE_TOOL_WORK_QUEUE = PhoneToolWorkQueue()


class PhoneToolClient:
    def __init__(
        self,
        *,
        host: str = IPHONE_HOST,
        port: int = IPHONE_PORT,
        token: str | None = None,
        work_queue: PhoneToolWorkQueue | None = None,
        target_device_id: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.token = token if token is not None else _load_phone_token()
        self.work_queue = work_queue or PHONE_TOOL_WORK_QUEUE
        self.target_device_id = str(target_device_id or "").strip()[:160] or None

    def is_available(self, tool: str, *, now: float | None = None) -> bool:
        if os.environ.get("PAIRLING_PHONE_TOOLS_DIRECT_TCP") == "1":
            return True
        return self.work_queue.is_fresh(tool, target_device_id=self.target_device_id, now=now)

    def unavailable_reason(self, tool: str, *, now: float | None = None) -> str | None:
        if os.environ.get("PAIRLING_PHONE_TOOLS_DIRECT_TCP") == "1":
            return None
        return self.work_queue.unavailable_reason(
            tool,
            target_device_id=self.target_device_id,
            now=now,
        )

    def run(self, tool: str, input_payload: dict[str, Any], *, timeout_ms: int) -> ToolResult:
        if os.environ.get("PAIRLING_PHONE_TOOLS_DIRECT_TCP") != "1":
            return self.work_queue.submit(
                tool,
                input_payload,
                timeout_ms=timeout_ms,
                target_device_id=self.target_device_id,
            )
        if not self.token:
            return ToolResult(False, "iphone", reason="iphone_not_configured", error_message="phone token missing")
        request = json.dumps({
            "tool": tool,
            "token": self.token,
            "input": input_payload,
        }, separators=(",", ":")) + "\n"
        timeout = max(0.05, min(timeout_ms, IPHONE_TIMEOUT_MS_MAX) / 1000)
        try:
            with socket.create_connection((self.host, self.port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(request.encode("utf-8"))
                buf = bytearray()
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    if b"\n" in buf:
                        break
        except ConnectionRefusedError as exc:
            return ToolResult(False, "iphone", reason="iphone_connection_refused", error_message=str(exc))
        except socket.timeout as exc:
            return ToolResult(False, "iphone", reason="iphone_timeout", error_message=str(exc))
        except OSError as exc:
            return ToolResult(False, "iphone", reason="iphone_unavailable", error_message=str(exc))

        line = bytes(buf).split(b"\n", 1)[0]
        try:
            response = json.loads(line.decode("utf-8"))
        except Exception as exc:
            return ToolResult(False, "iphone", reason="iphone_bad_response", error_message=str(exc))
        if not response.get("ok"):
            message = str(response.get("error") or "unknown error")
            reason = "iphone_token_rejected" if "token" in message.lower() else "iphone_tool_failed"
            return ToolResult(False, "iphone", reason=reason, error_message=message)
        return ToolResult(True, "iphone", result=str(response.get("result") or ""))


class MacToolRunner:
    def run(
        self,
        tool: str,
        input_payload: dict[str, Any],
        *,
        model: str,
        max_output_chars: int,
    ) -> ToolResult:
        try:
            if tool == "corpus_recall":
                return ToolResult(
                    True,
                    "mac_fallback",
                    result=_truncate_output(_search_local_corpus(str(input_payload.get("query") or "")), max_output_chars),
                )
            system, prompt = _mac_prompt(tool, input_payload)
            result = run_local_llm(
                model=model,
                prompt=prompt,
                system=system,
                timeout_seconds=FAST_VIBE_CHECK_TIMEOUT_SECONDS if tool == "vibe_check" else 120,
            )
            return ToolResult(True, "mac_fallback", result=_truncate_output(result, max_output_chars))
        except LLMRouteError as exc:
            if tool == "vibe_check":
                return ToolResult(
                    True,
                    "mac_fallback",
                    result=_truncate_output(_deterministic_vibe_check(str(input_payload.get("draft") or ""), reason=exc.code), max_output_chars),
                    reason=f"fast_vibe_check_after_{exc.code}",
                )
            return ToolResult(False, "mac_fallback", reason=exc.code, error_message=exc.message)
        except Exception as exc:
            return ToolResult(False, "mac_fallback", reason=type(exc).__name__, error_message=str(exc))


def run_pairling_tool(
    payload: dict[str, Any],
    *,
    iphone_client: PhoneToolClient | None = None,
    mac_runner: Any | None = None,
    availability: PhoneToolAvailabilityStore | None = None,
    now: Callable[[], float] = time.time,
) -> dict[str, Any]:
    started = now()
    if not isinstance(payload, dict):
        return _error("bad_request", "request must be a JSON object", started, now)
    tool = str(payload.get("tool") or "")
    if tool not in ALLOWED_TOOLS:
        return _error("invalid_tool", "tool must be one of: " + ", ".join(sorted(ALLOWED_TOOLS)), started, now, tool=tool)
    strategy = str(payload.get("strategy") or "auto")
    if strategy not in ALLOWED_STRATEGIES:
        return _error("invalid_strategy", "strategy must be auto|iphone_only|mac_only", started, now, tool=tool)
    input_payload = _bounded_input(payload.get("input") if isinstance(payload.get("input"), dict) else {}, _bounded_int(payload.get("max_input_chars"), default=MAX_INPUT_CHARS, minimum=1, maximum=MAX_INPUT_CHARS))
    missing = _missing_required_field(tool, input_payload)
    if missing:
        return _error("missing_input", f"missing input field '{missing}'", started, now, tool=tool)
    iphone_timeout_ms = _bounded_int(payload.get("iphone_timeout_ms"), default=IPHONE_TIMEOUT_MS_DEFAULT, minimum=50, maximum=IPHONE_TIMEOUT_MS_MAX)
    max_output_chars = _bounded_int(payload.get("max_output_chars"), default=MAX_OUTPUT_CHARS, minimum=64, maximum=MAX_OUTPUT_CHARS)
    mac_model = str(payload.get("mac_model") or "sonnet")

    # The listener heartbeat is diagnostic only. Routing truth comes from a
    # live `/phone-tools/next` poll, because an advertised listener cannot
    # receive queued work by itself.
    del availability
    requested_phone_device = str(payload.get("iphone_device_id") or "").strip()[:160] or None
    phone = iphone_client or PhoneToolClient(target_device_id=requested_phone_device)
    mac = mac_runner or MacToolRunner()
    iphone_attempted = False
    iphone_reason: str | None = None
    iphone_error: str | None = None

    iphone_ready = hasattr(phone, "is_available") and bool(phone.is_available(tool, now=started))
    if strategy == "iphone_only" or (strategy == "auto" and iphone_ready):
        iphone_attempted = True
        phone_result = phone.run(tool, input_payload, timeout_ms=iphone_timeout_ms)
        if phone_result.ok:
            return _success(
                tool=tool,
                provider="iphone",
                strategy=strategy,
                result=_truncate_output(phone_result.result, max_output_chars),
                fallback_reason=None,
                started=started,
                now=now,
                diagnostics=_diagnostics(True, phone, mac_model),
            )
        iphone_reason = phone_result.reason or "iphone_unavailable"
        iphone_error = phone_result.error_message
        if strategy == "iphone_only":
            return _provider_error(
                tool=tool,
                strategy=strategy,
                provider="iphone",
                code=iphone_reason,
                message=iphone_error or iphone_reason,
                started=started,
                now=now,
                diagnostics=_diagnostics(True, phone, mac_model),
            )
    elif strategy == "auto":
        if hasattr(phone, "unavailable_reason"):
            iphone_reason = phone.unavailable_reason(tool, now=started) or "iphone_no_reverse_worker"
        else:
            iphone_reason = "iphone_no_reverse_worker"
    else:
        iphone_reason = "iphone_disabled_by_strategy"

    if strategy == "mac_only" or strategy == "auto":
        mac_result = mac.run(tool, input_payload, model=mac_model, max_output_chars=max_output_chars)
        if mac_result.ok:
            return _success(
                tool=tool,
                provider="mac_fallback",
                strategy=strategy,
                result=mac_result.result,
                fallback_reason=None if strategy == "mac_only" else iphone_reason,
                started=started,
                now=now,
                diagnostics=_diagnostics(iphone_attempted, phone, mac_model),
            )
        return _all_failed(tool, strategy, iphone_reason, mac_result.reason or "mac_failed", mac_result.error_message, started, now, iphone_error=iphone_error)

    return _error("invalid_strategy", "strategy did not select a provider", started, now, tool=tool)


def audit_detail_for_tool_run(request_payload: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    input_payload = request_payload.get("input") if isinstance(request_payload.get("input"), dict) else {}
    input_json = json.dumps(input_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    detail = {
        "tool": str(request_payload.get("tool") or result.get("tool") or "")[:80],
        "provider": result.get("provider"),
        "strategy": result.get("strategy"),
        "fallback_reason": result.get("fallback_reason"),
        "input_length": len(input_json),
        "input_sha256": hashlib.sha256(input_json.encode("utf-8")).hexdigest(),
        "latency_ms": result.get("latency_ms"),
        "ok": bool(result.get("ok")),
        "error_code": ((result.get("error") or {}) if isinstance(result.get("error"), dict) else {}).get("code"),
    }
    agent_provider = _bounded_audit_identity(
        request_payload.get("agent_provider"),
        maximum=48,
        pattern=r"[a-z0-9_-]+",
    )
    session_identity = _bounded_audit_identity(
        request_payload.get("session_identity"),
        maximum=160,
        pattern=r"[A-Za-z0-9._:-]+",
    )
    if agent_provider:
        detail["agent_provider"] = agent_provider
    if session_identity:
        detail["session_identity"] = session_identity
    return detail


def _bounded_audit_identity(value: Any, *, maximum: int, pattern: str) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or re.fullmatch(pattern, normalized) is None:
        return None
    return normalized


def _success(
    *,
    tool: str,
    provider: str,
    strategy: str,
    result: str,
    fallback_reason: str | None,
    started: float,
    now: Callable[[], float],
    diagnostics: dict[str, Any],
) -> dict[str, Any]:
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "tool": tool,
        "provider": provider,
        "strategy": strategy,
        "fallback_reason": fallback_reason,
        "latency_ms": max(0, int((now() - started) * 1000)),
        "result": result,
        "diagnostics": diagnostics,
    }


def _provider_error(
    *,
    tool: str,
    strategy: str,
    provider: str,
    code: str,
    message: str,
    started: float,
    now: Callable[[], float],
    diagnostics: dict[str, Any],
) -> dict[str, Any]:
    return {
        "ok": False,
        "schema_version": SCHEMA_VERSION,
        "tool": tool,
        "provider": provider,
        "strategy": strategy,
        "fallback_reason": code,
        "latency_ms": max(0, int((now() - started) * 1000)),
        "error": {"code": code, "message": message},
        "diagnostics": diagnostics,
    }


def _all_failed(
    tool: str,
    strategy: str,
    iphone_reason: str | None,
    mac_reason: str,
    mac_message: str | None,
    started: float,
    now: Callable[[], float],
    *,
    iphone_error: str | None = None,
) -> dict[str, Any]:
    return {
        "ok": False,
        "schema_version": SCHEMA_VERSION,
        "tool": tool,
        "provider": None,
        "strategy": strategy,
        "fallback_reason": iphone_reason,
        "latency_ms": max(0, int((now() - started) * 1000)),
        "error": {
            "code": "all_providers_failed",
            "message": "iPhone listener was unavailable and Mac fallback failed.",
            "iphone_reason": iphone_reason,
            "iphone_message": iphone_error,
            "mac_reason": mac_reason,
            "mac_message": mac_message,
        },
    }


def _error(code: str, message: str, started: float, now: Callable[[], float], *, tool: str = "") -> dict[str, Any]:
    return {
        "ok": False,
        "schema_version": SCHEMA_VERSION,
        "tool": tool,
        "provider": None,
        "latency_ms": max(0, int((now() - started) * 1000)),
        "error": {"code": code, "message": message},
    }


def _diagnostics(iphone_attempted: bool, phone: PhoneToolClient, mac_model: str) -> dict[str, Any]:
    return {
        "iphone_attempted": iphone_attempted,
        "iphone_host": phone.host,
        "iphone_port": phone.port,
        "mac_model": mac_model,
    }


def _missing_required_field(tool: str, input_payload: dict[str, Any]) -> str | None:
    if tool == "vibe_check":
        return None if input_payload.get("draft") else "draft"
    if tool == "second_opinion":
        return None if input_payload.get("claim") else "claim"
    if tool == "user_likely_prefers":
        if not input_payload.get("option_a"):
            return "option_a"
        if not input_payload.get("option_b"):
            return "option_b"
    if tool == "corpus_recall":
        return None if input_payload.get("query") else "query"
    return None


def _bounded_input(value: dict[str, Any], max_chars: int) -> dict[str, Any]:
    bounded: dict[str, Any] = {}
    for key, item in value.items():
        if isinstance(item, str):
            bounded[str(key)] = item[:max_chars]
        else:
            bounded[str(key)] = item
    return bounded


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _truncate_output(value: str, max_chars: int) -> str:
    text = str(value or "")
    if len(text) <= max_chars:
        return text
    suffix = "\n[output truncated]"
    if max_chars <= len(suffix):
        return text[:max_chars]
    return text[: max_chars - len(suffix)] + suffix


def _mac_prompt(tool: str, input_payload: dict[str, Any]) -> tuple[str, str]:
    if tool == "vibe_check":
        return (
            "You are checking whether a draft sounds like the user's usual voice. Return one of: yes, partial, no. Then give one concrete edit. Be concise. Do not rewrite the whole draft unless asked.",
            "Draft:\n" + str(input_payload.get("draft") or ""),
        )
    if tool == "second_opinion":
        return (
            "Give the strongest skeptical counterargument or risk in 2-3 sentences. Be specific and practical.",
            "Claim:\n" + str(input_payload.get("claim") or ""),
        )
    if tool == "user_likely_prefers":
        return (
            "Choose A or B based on the user's known preference for velocity, simplicity, and directness. Return exactly \"A - ...\" or \"B - ...\" with one sentence of rationale.",
            "Option A:\n"
            + str(input_payload.get("option_a") or "")
            + "\n\nOption B:\n"
            + str(input_payload.get("option_b") or ""),
        )
    raise ValueError(f"unsupported mac fallback tool: {tool}")


def _deterministic_vibe_check(draft: str, *, reason: str) -> str:
    text = " ".join(str(draft or "").split())
    lowered = text.lower()
    issues: list[str] = []
    edit = ""

    formal_phrases = [
        "thank you for sending this across",
        "please could you",
        "i am writing to",
        "i would like to",
        "kindly",
        "further to",
    ]
    if any(phrase in lowered for phrase in formal_phrases):
        issues.append("a little more formal than the user's usual direct style")
        edit = "open with the ask directly and drop the polite padding."
    if len(text) > 700:
        issues.append("too long for a quick operational message")
        edit = edit or "split the asks into short bullets or remove background detail."
    if re.search(r"\b(just|perhaps|maybe|i was wondering)\b", lowered):
        issues.append("slightly hedged")
        edit = edit or "remove the hedge and state the request plainly."
    if not issues:
        verdict = "yes"
        issue = "clear, practical, and direct"
        edit = "keep it as-is, or trim one greeting word if you want it tighter."
    else:
        verdict = "partial"
        issue = issues[0]

    return (
        f"{verdict} - Fast Pairling fallback ({reason}). The draft is {issue}. "
        f"One concrete edit: {edit}"
    )


def _search_local_corpus(query: str, *, limit: int = 5) -> str:
    terms = [term.lower() for term in re.findall(r"[A-Za-z0-9_./:-]{2,}", query)[:12]]
    if not terms:
        return "No matches in the local corpus."
    candidates: list[tuple[float, str, str, str]] = []
    roots = [
        Path.home() / ".claude" / "projects",
        Path.home() / ".codex" / "sessions",
    ]
    for root in roots:
        if not root.exists():
            continue
        files = sorted(root.rglob("*.jsonl"), key=lambda path: path.stat().st_mtime if path.exists() else 0, reverse=True)[:250]
        for path in files:
            try:
                text = path.read_text(errors="replace")
                mtime = path.stat().st_mtime
            except OSError:
                continue
            lowered = text.lower()
            score = sum(lowered.count(term) * (3 if any(ch in term for ch in "/_.:-") else 1) for term in terms)
            if score <= 0:
                continue
            snippet = _snippet_for_terms(text, terms)
            candidates.append((score + (mtime / 10_000_000_000), str(path), path.stem, snippet))
    candidates.sort(key=lambda item: item[0], reverse=True)
    if not candidates:
        return "No matches in the local corpus."
    lines = []
    for index, (_, path, session_id, snippet) in enumerate(candidates[:limit], start=1):
        project = _project_label(path)
        lines.append(f"{index}. [{project}] {session_id}: {snippet}")
    return "Top local matches:\n" + "\n".join(lines)


def _snippet_for_terms(text: str, terms: list[str]) -> str:
    lowered = text.lower()
    positions = [lowered.find(term) for term in terms if lowered.find(term) >= 0]
    start = max(0, min(positions) - 80) if positions else 0
    snippet = text[start:start + 260].replace("\n", " ")
    return re.sub(r"\s+", " ", snippet).strip()


def _project_label(path: str) -> str:
    parts = Path(path).parts
    for marker in ("projects", "sessions"):
        if marker in parts:
            idx = parts.index(marker)
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return Path(path).parent.name


def _load_phone_token() -> str | None:
    for key in ("PAIRLING_PHONE_TOOLS_TOKEN", "PHONE_TOKEN"):
        value = os.environ.get(key)
        if value:
            return value.strip()
    token_file = Path(os.environ.get("PHONE_TOKEN_FILE", str(Path.home() / ".claude" / "scripts" / ".notify-token")))
    try:
        value = token_file.read_text().strip()
        return value or None
    except OSError:
        return None
