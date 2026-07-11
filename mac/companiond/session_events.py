"""In-process publish/subscribe for the session plane.

Phase 1 of the session viewer evolution (thoughts/shared/specs/
session-viewer-evolution/CONTRACT.md). Wakeup sources (kqueue file watches,
the broker output push, and the daemon's own writes) publish here; SSE
handlers block on subscriptions instead of running private poll loops.

Backpressure is bounded and visible: a slow subscriber drops its oldest
events and receives a typed queue_gap notice naming exactly how many were
dropped. Nothing in this module polls.
"""
from __future__ import annotations

import os
import select
import threading
import time
from collections import deque
from pathlib import Path


class Subscription:
    """One subscriber's bounded queue. Use as a context manager or call
    close() explicitly; a closed subscription receives nothing."""

    def __init__(self, hub: "EventHub", topic: str, max_queue: int) -> None:
        self._hub = hub
        self.topic = topic
        self._registered_topics: set[str] = {topic}
        self._max_queue = max(1, int(max_queue))
        self._events: deque = deque()
        self._dropped = 0
        self._lock = threading.Lock()
        self._ready = threading.Condition(self._lock)
        self._closed = False

    def _offer(self, event: dict) -> None:
        with self._ready:
            if self._closed:
                return
            if len(self._events) >= self._max_queue:
                self._events.popleft()
                self._dropped += 1
            self._events.append(event)
            self._ready.notify()

    def get(self, timeout: float | None = None) -> dict | None:
        """Blocks until an event arrives, the timeout passes, or the
        subscription closes. A pending drop count is delivered first as
        {"type": "queue_gap", "dropped": n}."""
        with self._ready:
            if self._dropped:
                notice = {"type": "queue_gap", "dropped": self._dropped}
                self._dropped = 0
                return notice
            if not self._events:
                self._ready.wait(timeout=timeout)
            if self._dropped:
                notice = {"type": "queue_gap", "dropped": self._dropped}
                self._dropped = 0
                return notice
            if self._events:
                return self._events.popleft()
            return None

    def close(self) -> None:
        with self._ready:
            if self._closed:
                return
            self._closed = True
            self._events.clear()
            self._ready.notify_all()
        self._hub._remove(self)

    def __enter__(self) -> "Subscription":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class EventHub:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._topics: dict[str, list[Subscription]] = {}

    def subscribe(self, topic: str, *, max_queue: int = 256) -> Subscription:
        subscription = Subscription(self, str(topic), max_queue)
        with self._lock:
            self._topics.setdefault(subscription.topic, []).append(subscription)
        return subscription

    def subscribe_many(self, topics, *, max_queue: int = 256) -> Subscription:
        """One queue registered under several topics, so a consumer can block
        on a single get() for its whole interest set."""
        names = sorted({str(t) for t in topics if str(t)})
        label = "|".join(names) if names else "(empty)"
        subscription = Subscription(self, label, max_queue)
        subscription._registered_topics = set(names)
        with self._lock:
            for name in names:
                self._topics.setdefault(name, []).append(subscription)
        return subscription

    def publish(self, topic: str, event: dict) -> int:
        with self._lock:
            subscribers = list(self._topics.get(str(topic), ()))
        for subscription in subscribers:
            subscription._offer(event)
        return len(subscribers)

    def subscriber_count(self, topic: str) -> int:
        with self._lock:
            return len(self._topics.get(str(topic), ()))

    def _remove(self, subscription: Subscription) -> None:
        with self._lock:
            for name in subscription._registered_topics:
                remaining = [s for s in self._topics.get(name, ()) if s is not subscription]
                if remaining:
                    self._topics[name] = remaining
                else:
                    self._topics.pop(name, None)


_O_EVTONLY = getattr(os, "O_EVTONLY", 0x8000)


class _Watch:
    __slots__ = ("path", "fd", "topic_counts", "awaiting_recreate", "last_size", "degraded")

    def __init__(self, path: str) -> None:
        self.path = path
        self.fd: int | None = None
        self.topic_counts: dict[str, int] = {}
        self.awaiting_recreate = False
        self.last_size: int | None = None
        self.degraded = False


class WatchHandle:
    def __init__(self, watcher: "FileWatcher", path: str, topic: str) -> None:
        self._watcher = watcher
        self._path = path
        self._topic = topic
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._watcher._unwatch(self._path, self._topic)

    def __enter__(self) -> "WatchHandle":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class FileWatcher:
    """kqueue-driven file change publisher with an honest degraded fallback.

    One watch per path regardless of subscriber count. Append or truncate
    publishes {"type": "file_changed", "path": ...}; delete or rename
    publishes {"type": "file_rotated", ...} and the watcher retries the path
    until it reappears. When kqueue is unavailable the watcher polls at
    fallback_poll_seconds and stamps degraded_reason on every event, so
    consumers can see they are on the slow path.
    """

    def __init__(self, hub: EventHub, *, kqueue_factory=None, fallback_poll_seconds: float = 1.0) -> None:
        self._hub = hub
        self._fallback = max(0.05, float(fallback_poll_seconds))
        self._lock = threading.RLock()
        self._watches: dict[str, _Watch] = {}
        self._fd_map: dict[int, _Watch] = {}
        self._closed = False
        if kqueue_factory is None:
            kqueue_factory = getattr(select, "kqueue", None)
        kq = None
        if kqueue_factory is not None:
            try:
                kq = kqueue_factory()
            except Exception:
                kq = None
        self._kq = kq
        self._degraded_reason = None if kq is not None else "kqueue_unavailable"
        self._wake_r = self._wake_w = -1
        if self._kq is not None:
            self._wake_r, self._wake_w = os.pipe()
            os.set_blocking(self._wake_r, False)
            self._kq.control([select.kevent(
                self._wake_r,
                filter=select.KQ_FILTER_READ,
                flags=select.KQ_EV_ADD,
            )], 0, 0)
        self._thread = threading.Thread(target=self._run, name="session-file-watcher", daemon=True)
        self._thread.start()

    # -- public API --------------------------------------------------------

    def watch(self, path, topic: str) -> WatchHandle:
        key = str(Path(path))
        with self._lock:
            watch = self._watches.get(key)
            if watch is None:
                watch = _Watch(key)
                self._watches[key] = watch
                if self._kq is not None:
                    self._try_register(watch)
                else:
                    watch.degraded = True
                    watch.last_size = self._safe_size(key)
            watch.topic_counts[topic] = watch.topic_counts.get(topic, 0) + 1
        self._wake()
        return WatchHandle(self, key, topic)

    def active_watch_count(self) -> int:
        with self._lock:
            return len(self._watches)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._wake()
        self._thread.join(timeout=2)
        with self._lock:
            for watch in self._watches.values():
                self._close_fd(watch)
            self._watches.clear()
            if self._wake_r >= 0:
                os.close(self._wake_r)
                os.close(self._wake_w)
            if self._kq is not None:
                self._kq.close()

    # -- internals ---------------------------------------------------------

    def _wake(self) -> None:
        if self._wake_w >= 0:
            try:
                os.write(self._wake_w, b"x")
            except OSError:
                pass

    def _unwatch(self, path: str, topic: str) -> None:
        with self._lock:
            watch = self._watches.get(path)
            if watch is None:
                return
            count = watch.topic_counts.get(topic, 0) - 1
            if count > 0:
                watch.topic_counts[topic] = count
            else:
                watch.topic_counts.pop(topic, None)
            if not watch.topic_counts:
                self._close_fd(watch)
                self._watches.pop(path, None)

    def _safe_size(self, path: str) -> int | None:
        try:
            return os.stat(path).st_size
        except OSError:
            return None

    def _try_register(self, watch: _Watch) -> bool:
        try:
            fd = os.open(watch.path, _O_EVTONLY)
        except OSError:
            watch.fd = None
            watch.awaiting_recreate = True
            return False
        try:
            self._kq.control([select.kevent(
                fd,
                filter=select.KQ_FILTER_VNODE,
                flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                fflags=(select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND |
                        select.KQ_NOTE_DELETE | select.KQ_NOTE_RENAME),
            )], 0, 0)
        except OSError:
            os.close(fd)
            watch.degraded = True
            watch.last_size = self._safe_size(watch.path)
            return False
        watch.fd = fd
        watch.awaiting_recreate = False
        self._fd_map[fd] = watch
        return True

    def _close_fd(self, watch: _Watch) -> None:
        if watch.fd is not None:
            self._fd_map.pop(watch.fd, None)
            try:
                os.close(watch.fd)
            except OSError:
                pass
            watch.fd = None

    def _publish(self, watch: _Watch, event_type: str, *, degraded: bool = False) -> None:
        with self._lock:
            topics = list(watch.topic_counts)
        for topic in topics:
            event = {"type": event_type, "path": watch.path}
            if degraded or self._degraded_reason:
                event["degraded_reason"] = self._degraded_reason or "kqueue_register_failed"
            self._hub.publish(topic, event)

    def _needs_tick(self) -> bool:
        with self._lock:
            return any(w.awaiting_recreate or w.degraded for w in self._watches.values())

    def _run(self) -> None:
        while True:
            with self._lock:
                if self._closed:
                    return
            if self._kq is None:
                time.sleep(self._fallback)
                self._service_degraded()
                continue
            timeout = self._fallback if self._needs_tick() else 30.0
            try:
                events = self._kq.control(None, 64, timeout)
            except OSError:
                return
            for ev in events:
                if ev.ident == self._wake_r:
                    try:
                        os.read(self._wake_r, 4096)
                    except OSError:
                        pass
                    continue
                with self._lock:
                    watch = self._fd_map.get(ev.ident)
                if watch is None:
                    continue
                if ev.fflags & (select.KQ_NOTE_DELETE | select.KQ_NOTE_RENAME):
                    with self._lock:
                        self._close_fd(watch)
                        watch.awaiting_recreate = True
                    self._publish(watch, "file_rotated")
                elif ev.fflags & (select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND):
                    self._publish(watch, "file_changed")
            self._service_retries()
            self._service_degraded()

    def _service_retries(self) -> None:
        with self._lock:
            pending = [w for w in self._watches.values() if w.awaiting_recreate]
        for watch in pending:
            with self._lock:
                registered = self._try_register(watch)
            if registered:
                # The recreated file's existing content counts as a change.
                self._publish(watch, "file_changed")

    def _service_degraded(self) -> None:
        with self._lock:
            degraded = [w for w in self._watches.values() if w.degraded]
        for watch in degraded:
            size = self._safe_size(watch.path)
            if size is None:
                if watch.last_size is not None:
                    watch.last_size = None
                    self._publish(watch, "file_rotated", degraded=True)
            elif size != watch.last_size:
                watch.last_size = size
                self._publish(watch, "file_changed", degraded=True)
