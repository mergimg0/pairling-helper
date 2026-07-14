#!/usr/bin/env python3
"""Fleet Live Activity publisher.

Wires the pure fleet-tier evaluator to the push path. On each tick it reads the
current session rows, folds them into a fleet summary, and emits a Live Activity
update only when the fleet's active composition changed since the last emit. A
bare heartbeat, and idle sessions coming and going, change nothing, so no push
goes out. That is what keeps the one fleet activity inside the APNs budget and
stops it animating a stale timer next to frozen counts.

The publisher is pure of transport: it takes a rows provider and an emit
callback, so it is testable with a fake emitter and the daemon binds the emit
callback to its real push dispatcher at startup. Every payload carries a stale
window so a suspended app that stops receiving pushes fades the activity instead
of showing frozen counts as if they were live.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Callable

import fleet_tier


def fleet_activity_payload(summary: fleet_tier.FleetSummary, now: float) -> dict[str, Any]:
    """The Live Activity update for a fleet summary.

    `content_state` mirrors PairlingFleetActivityAttributes.ContentState on the
    client. `stale_seconds` becomes the ActivityKit staleDate so the activity
    de-emphasizes itself when pushes stop arriving.
    """
    return {
        "kind": "fleet_summary",
        "content_state": {
            "needsYou": summary.needs_you,
            "running": summary.running,
            "idle": summary.idle_live,
            "headline": summary.headline,
            "updatedAtEpoch": now,
            "eventId": "fleet_" + uuid.uuid4().hex,
        },
        "stale_seconds": int(fleet_tier.STALE_AFTER_SECONDS),
        # The fleet activity ends (not just fades) once nothing is worth a
        # glance; the client controller drops it when active_total hits zero.
        "active_total": summary.active_total,
    }


class FleetActivityPublisher:
    def __init__(
        self,
        *,
        targets_provider: Callable[[], tuple[str, ...]],
        rows_provider: Callable[[], list[dict[str, Any]]],
        emit: Callable[[dict[str, Any]], None],
        now_fn: Callable[[], float] = time.time,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self._targets_provider = targets_provider
        self._rows_provider = rows_provider
        self._emit = emit
        self._now_fn = now_fn
        self._logger = logger
        self._last_fingerprint: str | None = None
        self._last_target_signature: tuple[str, ...] | None = None
        self._pending_emit: dict[str, Any] | None = None

    def tick(self) -> bool:
        """Evaluate the fleet once and emit if the active composition changed.

        Returns True when it emitted, so a caller can log or meter pushes.
        Failure to read rows or emit is swallowed and logged, because one bad
        tick must not kill the publisher loop.
        """
        try:
            targets = tuple(sorted(set(self._targets_provider() or ())))
        except Exception as exc:  # noqa: BLE001 - a bad status read must not stop the loop
            self._log(f"fleet targets read failed: {exc}")
            return False
        if not targets:
            self.reset()
            return False

        try:
            rows = self._rows_provider() or []
        except Exception as exc:  # noqa: BLE001 - a bad read must not stop the loop
            self._log(f"fleet rows read failed: {exc}")
            return False

        now = float(self._now_fn())
        summary = fleet_tier.summarize_fleet(rows, now)
        if self._pending_emit is not None:
            if self._pending_emit["targets"] != targets:
                # A replacement activity must never inherit an event captured
                # for the old token. Exact-target outbox work can finish on its
                # own, while this publisher starts fresh for the new target.
                self._pending_emit = None
            else:
                return self._attempt_pending_emit()

        force_emit = targets != self._last_target_signature
        if not force_emit and not fleet_tier.should_push(self._last_fingerprint, summary):
            return False

        self._pending_emit = {
            "fingerprint": summary.fingerprint,
            "headline": summary.headline,
            "payload": fleet_activity_payload(summary, now),
            "targets": targets,
        }
        return self._attempt_pending_emit()

    def _attempt_pending_emit(self) -> bool:
        pending = self._pending_emit
        if pending is None:
            return False
        try:
            self._emit(pending["payload"])
        except Exception as exc:  # noqa: BLE001
            self._log(f"fleet emit failed: {exc}")
            return False

        # Log every emit: a silent success is indistinguishable from a dead
        # loop, and this line fires only on composition changes, so it stays
        # quiet in steady state.
        self._log(
            f"pushed fleet change {self._last_fingerprint or 'none'} -> "
            f"{pending['fingerprint']} ({pending['headline']})"
        )
        self._last_fingerprint = str(pending["fingerprint"])
        self._last_target_signature = tuple(pending["targets"])
        self._pending_emit = None
        return True

    def reset(self) -> None:
        """Forget the last fingerprint so the next tick re-emits. Used when the
        activity restarts and needs a fresh populated state."""
        self._last_fingerprint = None
        self._last_target_signature = None
        self._pending_emit = None

    def _log(self, message: str) -> None:
        if self._logger:
            self._logger(message)
