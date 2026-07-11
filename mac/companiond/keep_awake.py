"""Session-scoped keep-awake (SPEC-p7): one managed caffeinate child.

The Mac stays awake exactly while supervised work is running — a phone
attached to a live stream, a registered session actively running, or an
orchestration worker — and goes back to the user's own power policy after a
linger. The mechanism is deliberately a visible child process:

- `pmset -g assertions` and Activity Monitor show it (disclosure test);
- the argv is `caffeinate -i -w <daemon pid>`: `-i` prevents IDLE sleep only
  (a closed lid on battery still sleeps — Pairling does not fight the lid),
  and `-w` makes caffeinate itself exit when the daemon dies, so a crashed
  daemon can never leak a wakelock;
- `PAIRLING_KEEP_AWAKE=0` disables the manager entirely.

The manager is passive and fully injectable (clock, spawner) so every
transition is contract-tested without real sleep (acceptance 6). The daemon
owns the activity predicate and calls evaluate() on events plus a 30s
reconcile tick.
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
from collections import deque


def _enabled_from_env() -> bool:
    raw = os.environ.get("PAIRLING_KEEP_AWAKE", "").strip().lower()
    return raw not in {"0", "false", "no", "off"}


class KeepAwakeManager:
    def __init__(
        self,
        *,
        enabled: bool | None = None,
        linger_seconds: float = 90.0,
        caffeinate_path: str = "/usr/bin/caffeinate",
        watch_pid: int | None = None,
        clock=time.monotonic,
        spawner=None,
    ):
        self.enabled = _enabled_from_env() if enabled is None else bool(enabled)
        self.linger_seconds = float(linger_seconds)
        self.caffeinate_path = caffeinate_path
        self.watch_pid = int(watch_pid if watch_pid is not None else os.getpid())
        self._clock = clock
        self._spawner = spawner if spawner is not None else self._default_spawner
        self._lock = threading.Lock()
        self._child = None
        self._reasons: dict[str, int] = {}
        self._since: float | None = None
        self._since_wall: float | None = None
        self._zero_since: float | None = None
        self._trace: deque = deque(maxlen=20)

    @staticmethod
    def _default_spawner(argv, **kwargs):
        return subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _record(self, event: str, count: int) -> None:
        self._trace.append({"ts": time.time(), "event": event, "count": count})

    def _child_alive(self) -> bool:
        return self._child is not None and self._child.poll() is None

    def _spawn(self, count: int) -> None:
        argv = [self.caffeinate_path, "-i", "-w", str(self.watch_pid)]
        try:
            self._child = self._spawner(argv)
        except Exception:
            self._child = None
            self._record("spawn_failed", count)
            return
        self._record("spawned", count)

    def _terminate(self, count: int, event: str) -> None:
        child = self._child
        self._child = None
        self._since = None
        self._since_wall = None
        if child is None:
            return
        try:
            child.terminate()
            child.wait(timeout=5)
        except Exception:
            try:
                child.kill()
            except Exception:
                pass
        self._record(event, count)

    def evaluate(self, reasons: dict[str, int], now: float | None = None) -> dict:
        """Apply the current activity reasons; spawn, hold, linger, or release."""
        with self._lock:
            self._reasons = {k: int(v) for k, v in (reasons or {}).items()}
            if not self.enabled:
                return self._status_locked()
            count = sum(v for v in self._reasons.values() if v > 0)
            tick = self._clock() if now is None else now
            if count > 0:
                self._zero_since = None
                if not self._child_alive():
                    self._spawn(count)
                if self._child is not None and self._since is None:
                    self._since = tick
                    self._since_wall = time.time()
            else:
                if self._child_alive():
                    if self._zero_since is None:
                        self._zero_since = tick
                        self._record("linger_started", count)
                    elif tick - self._zero_since >= self.linger_seconds:
                        self._terminate(count, "released")
                        self._zero_since = None
                else:
                    self._zero_since = None
            return self._status_locked()

    def status(self) -> dict:
        with self._lock:
            return self._status_locked()

    def _status_locked(self) -> dict:
        active = self.enabled and self._child_alive()
        return {
            "enabled": self.enabled,
            "active": active,
            "reasons": dict(self._reasons),
            "since": self._since_wall if active else None,
            "caffeinate_pid": self._child.pid if active else None,
            "linger_seconds": self.linger_seconds,
            "trace": list(self._trace),
        }

    def shutdown(self) -> None:
        with self._lock:
            if self._child is not None:
                self._terminate(0, "shutdown")
            self._zero_since = None
