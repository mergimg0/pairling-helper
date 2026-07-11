#!/usr/bin/env python3
"""Fleet-tier evaluator for the fleet Live Activity.

One Live Activity for the whole fleet, not one per session. The Mac pushes an
update only when the fleet's active composition changes (a session enters
"needs you", a turn starts or ends, an anomaly lands), never on a bare
heartbeat. That keeps the activity inside the APNs budget and stops it from
animating a stale timer next to frozen text.

The tier definitions here MIRROR the iOS `SessionActivityRank` so the Mac-pushed
summary and the on-device dashboard agree on what each tier means. The parity is
pinned by `test_fleet_tier_contract.py`, which reads the Swift constants and
asserts they match `FRESHNESS_WINDOW_SECONDS` and `IN_FLIGHT_TURN_STATES` here.
This module is pure: it takes session rows and a clock, and returns counts. It
holds no state and touches no network, so the daemon can call it from the push
path and the tests can call it without a daemon.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

# Mirror of SessionActivityRank.turnStateFreshnessWindow (300s). A turn-state
# claim is only believed while the session has heartbeated within this window;
# a session that died mid-turn stops counting as running or blocked once its
# heartbeat ages past it.
FRESHNESS_WINDOW_SECONDS = 300.0

# Mirror of SessionActivityRank.inFlightTurnStates. These states mean a turn is
# genuinely running; "idle" and empty mean the last turn ended.
IN_FLIGHT_TURN_STATES = frozenset({"starting", "thinking", "tool", "responding"})

# Tier names, most urgent first. They mirror SessionActivityTier's cases.
NEEDS_YOU = "needs_you"
ATTENTION = "attention"
RUNNING = "running"
IDLE_LIVE = "idle_live"
DORMANT = "dormant"

# The tiers a glance cares about. The push fingerprint is built from these, so a
# session appearing or leaving the idle pool, and a bare heartbeat, never fire a
# fleet push.
ACTIVE_TIERS = (NEEDS_YOU, ATTENTION, RUNNING)

# How long the activity should trust a push before de-emphasizing itself. The
# wiring step sets this as the ActivityKit staleDate so a suspended app that
# stops receiving pushes fades the activity instead of showing frozen counts as
# if they were live.
STALE_AFTER_SECONDS = 90.0


def classify_session_tier(row: dict[str, Any], now: float) -> str:
    """Classify one daemon session row into a tier.

    Faithful mirror of `Session.activityTier(now:)`:
    a non-live or closed session is dormant; otherwise, while its heartbeat is
    fresh, a blocked terminal is needs-you, a recent anomaly is attention, and
    an in-flight turn is running; a fresh session doing none of those is
    idle-live; a session whose heartbeat has aged out is dormant.
    """
    readable = row.get("readable_state")
    closed = row.get("closed_at") is not None
    if closed or (readable is not None and readable != "live"):
        return DORMANT

    age = max(0.0, now - float(row.get("last_heartbeat") or 0.0))
    fresh = age < FRESHNESS_WINDOW_SECONDS

    attention = row.get("terminal_attention")
    needs_input = isinstance(attention, dict) and bool(attention.get("needs_input"))
    has_anomaly = row.get("recent_anomaly") is not None
    state = row.get("state")

    if fresh and needs_input:
        return NEEDS_YOU
    if fresh and has_anomaly:
        return ATTENTION
    if fresh and state in IN_FLIGHT_TURN_STATES:
        return RUNNING
    if not fresh:
        return DORMANT
    return IDLE_LIVE


@dataclass(frozen=True)
class FleetSummary:
    """The glanceable state of the whole fleet at one instant."""

    needs_you: int
    attention: int
    running: int
    idle_live: int
    dormant: int
    headline: str

    @property
    def active_total(self) -> int:
        """Sessions worth a glance right now: blocked, flagged, or running."""
        return self.needs_you + self.attention + self.running

    @property
    def fingerprint(self) -> str:
        """The push trigger. Built from the active tiers only, so idle churn and
        bare heartbeats leave it unchanged and fire no push."""
        return f"{self.needs_you}:{self.attention}:{self.running}"


def summarize_fleet(rows: Iterable[dict[str, Any]], now: float) -> FleetSummary:
    """Fold session rows into one fleet summary, classifying each with one clock."""
    counts = {NEEDS_YOU: 0, ATTENTION: 0, RUNNING: 0, IDLE_LIVE: 0, DORMANT: 0}
    for row in rows:
        counts[classify_session_tier(row, now)] += 1
    return FleetSummary(
        needs_you=counts[NEEDS_YOU],
        attention=counts[ATTENTION],
        running=counts[RUNNING],
        idle_live=counts[IDLE_LIVE],
        dormant=counts[DORMANT],
        headline=_headline(counts),
    )


def _headline(counts: dict[str, int]) -> str:
    """One line naming the fleet's most-pressing state, in tier order."""
    if counts[NEEDS_YOU] > 0:
        n = counts[NEEDS_YOU]
        return "1 needs you" if n == 1 else f"{n} need you"
    if counts[RUNNING] > 0:
        return f"{counts[RUNNING]} running"
    if counts[ATTENTION] > 0:
        n = counts[ATTENTION]
        return "1 needs a look" if n == 1 else f"{n} need a look"
    if counts[IDLE_LIVE] > 0:
        n = counts[IDLE_LIVE]
        return "1 session idle" if n == 1 else f"{n} sessions idle"
    return "Fleet quiet"


def should_push(previous_fingerprint: str | None, summary: FleetSummary) -> bool:
    """Whether the fleet's active composition changed enough to warrant a push.

    The very first summary (no previous fingerprint) pushes so the activity
    starts populated. After that, only a change in the active-tier counts
    pushes; a bare heartbeat that leaves those counts untouched does not.
    """
    return previous_fingerprint != summary.fingerprint
