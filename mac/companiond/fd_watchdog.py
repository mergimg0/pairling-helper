#!/usr/bin/env python3
"""File-descriptor watchdog: restart clean instead of limping dead.

On 2026-07-06 and 2026-07-07 the daemon leaked descriptors until EMFILE,
then kept serving requests while every publisher, probe, and push delivery
failed for hours (22 hours in the worst window). launchd restarts a crashed
daemon in seconds, so once descriptors near the limit, the honest move is a
loud log line and a deliberate exit. The PTY broker lives in its own
process and terminal sessions live in their own terminals, so a daemon
restart costs one SSE reconnect per client and nothing else.

The watchdog also raises a small soft limit toward the hard limit at start,
which buys runway without hiding the leak: the threshold scales with the
limit, so a leak still trips the restart, and every trip logs the count so
the leak stays visible while it is being hunted.
"""

from __future__ import annotations

import os
import resource
import threading
import time
from typing import Callable

# Restart once descriptors pass min(limit - HEADROOM, limit * FRACTION).
# HEADROOM keeps enough spare descriptors for the exit path itself; the
# fraction keeps the threshold meaningful on large limits.
HEADROOM = 32
FRACTION = 0.85

# Raise a small soft limit to this many descriptors (bounded by the hard
# limit). macOS gives launchd agents a small default; the raise buys runway
# between leak onset and restart without masking the leak.
RAISE_SOFT_TO = 8192

# Exit status for a watchdog-initiated restart, so launchd logs and humans
# can tell it apart from a crash.
EXIT_STATUS = 70


def fd_count() -> int:
    """This process's open descriptor count, without spawning anything.

    Returns -1 when /dev/fd itself cannot be listed. Listing needs a spare
    descriptor, so failing to list IS the exhaustion signal."""
    try:
        return len(os.listdir("/dev/fd"))
    except OSError:
        return -1


def soft_limit() -> int:
    try:
        return int(resource.getrlimit(resource.RLIMIT_NOFILE)[0])
    except Exception:  # noqa: BLE001 - a broken rlimit read must not crash the daemon
        return 0


def raise_soft_limit() -> tuple[int, int]:
    """Raise a small soft limit toward min(hard, RAISE_SOFT_TO).

    Returns (before, after). Best-effort: on failure the limits are simply
    left as they were."""
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = RAISE_SOFT_TO if hard == resource.RLIM_INFINITY else min(hard, RAISE_SOFT_TO)
        if soft >= target:
            return int(soft), int(soft)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        return int(soft), int(target)
    except Exception:  # noqa: BLE001
        return soft_limit(), soft_limit()


def should_restart(count: int, limit: int, *, headroom: int = HEADROOM, fraction: float = FRACTION) -> bool:
    """Whether the process is close enough to exhaustion to restart now.

    A negative count means counting itself failed, which is exhaustion. A
    non-positive limit means the limit is unknowable; never restart on an
    unknown limit, the count alone proves nothing against it."""
    if count < 0:
        return True
    if limit <= 0:
        return False
    return count >= min(limit - headroom, int(limit * fraction))


def start(
    *,
    logger: Callable[[str], None],
    exit_fn: Callable[[int], None] = os._exit,
    interval_seconds: float = 30.0,
    now_fn: Callable[[], float] = time.time,
) -> threading.Thread:
    """Raise the soft limit, then watch descriptors and exit for a launchd
    restart when they near the limit. Runs as a daemon thread; exit_fn is
    os._exit because sys.exit from a thread does not stop the process."""
    before, after = raise_soft_limit()
    logger(
        f"started (fds now {fd_count()}, soft limit {after}"
        + (f", raised from {before}" if after != before else "")
        + f", restart threshold {min(after - HEADROOM, int(after * FRACTION)) if after > 0 else 'n/a'})"
    )

    def run() -> None:
        while True:
            time.sleep(max(5.0, float(interval_seconds)))
            count = fd_count()
            limit = soft_limit()
            if should_restart(count, limit):
                logger(
                    f"file descriptors {count}/{limit} passed the restart threshold; "
                    f"exiting {EXIT_STATUS} so launchd starts a clean process"
                )
                exit_fn(EXIT_STATUS)

    thread = threading.Thread(target=run, name="pairling-fd-watchdog", daemon=True)
    thread.start()
    return thread
