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
        rows_provider: Callable[[], list[dict[str, Any]]],
        emit: Callable[[dict[str, Any]], None],
        now_fn: Callable[[], float] = time.time,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self._rows_provider = rows_provider
        self._emit = emit
        self._now_fn = now_fn
        self._logger = logger
        self._last_fingerprint: str | None = None

    def tick(self) -> bool:
        """Evaluate the fleet once and emit if the active composition changed.

        Returns True when it emitted, so a caller can log or meter pushes.
        Failure to read rows or emit is swallowed and logged, because one bad
        tick must not kill the publisher loop.
        """
        try:
            rows = self._rows_provider() or []
        except Exception as exc:  # noqa: BLE001 - a bad read must not stop the loop
            self._log(f"fleet rows read failed: {exc}")
            return False

        now = float(self._now_fn())
        summary = fleet_tier.summarize_fleet(rows, now)
        if not fleet_tier.should_push(self._last_fingerprint, summary):
            return False

        try:
            self._emit(fleet_activity_payload(summary, now))
        except Exception as exc:  # noqa: BLE001
            self._log(f"fleet emit failed: {exc}")
            return False

        # Log every emit: a silent success is indistinguishable from a dead
        # loop, and this line fires only on composition changes, so it stays
        # quiet in steady state.
        self._log(
            f"pushed fleet change {self._last_fingerprint or 'none'} -> {summary.fingerprint} ({summary.headline})"
        )
        self._last_fingerprint = summary.fingerprint
        return True

    def reset(self) -> None:
        """Forget the last fingerprint so the next tick re-emits. Used when the
        activity restarts and needs a fresh populated state."""
        self._last_fingerprint = None

    def _log(self, message: str) -> None:
        if self._logger:
            self._logger(message)
