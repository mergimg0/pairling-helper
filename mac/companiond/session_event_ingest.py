"""On-demand transcript ingestion into the session event log (contract v2).

A session starts ingesting when the first v2 subscriber asks for it. The
first drain backfills the whole existing transcript (that is the live and
archive unification: history is just earlier seq values), then a shared
FileWatcher wakes the single ingest thread on every append. Codex output is
normalized to the Claude line shape first, so one adapter serves both
providers. Parsed records store that normalized line inline. Beyond-cap
records preserve the exact source bytes outside SQLite.

Lines up to MAX_LINE_BYTES become normal provider-neutral events. Larger
records are never silently dropped: their exact source bytes are copied in
bounded chunks to the event log's private raw store and linked to an explicit
lifecycle event.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

from session_event_log import (
    VISIBLE_BLOCK_TEXT_MAX,
    SessionEventLog,
    parse_claude_transcript_line,
    source_file_version,
)

INGEST_TOPIC = "log-ingest"
MAX_LINE_BYTES = 32 * 1024 * 1024
READ_CHUNK = 1024 * 1024
CLAUDE_PARSER_VERSION = 3
CODEX_PARSER_VERSION = 4
SUPPORTED_TRANSCRIPT_PROVIDERS = frozenset({"claude", "codex"})

_CODEX_TEXT_BLOCK_TYPES = {"text", "output_text", "input_text"}


class UnsupportedTranscriptProviderError(ValueError):
    """Raised when a non-deep provider reaches the transcript parser."""

    code = "unsupported_provider"
    capability = "session_transcript"

    def __init__(self, provider: str) -> None:
        self.provider = str(provider or "").strip().lower() or "unknown"
        super().__init__(
            f"Provider {self.provider} does not support deep transcript ingestion."
        )


def _bounded_text(value, limit: int = VISIBLE_BLOCK_TEXT_MAX) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError):
            value = str(value)
    if value.startswith("data:"):
        return "[inline data omitted]"
    if len(value) <= limit:
        return value
    return value[:max(0, limit - 3)] + "..."


def _codex_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        pieces = []
        for item in value:
            if isinstance(item, str):
                pieces.append(item)
            elif isinstance(item, dict):
                text = item.get("text") or item.get("content") or item.get("output_text")
                if isinstance(text, str):
                    pieces.append(text)
        return "\n".join(pieces)
    if isinstance(value, dict):
        for key in ("text", "message", "content", "output_text"):
            if isinstance(value.get(key), str):
                return value[key]
    return ""


def _codex_message_needs_sanitized_path(content) -> bool:
    if not isinstance(content, list):
        return False
    for item in content:
        if not isinstance(item, (dict, str)):
            return True
        if isinstance(item, str):
            continue
        block_type = str(item.get("type") or "")
        if block_type in _CODEX_TEXT_BLOCK_TYPES or block_type == "reasoning":
            continue
        text = item.get("text") or item.get("content")
        if (block_type != "input_image" and isinstance(text, str) and text
                and not text.startswith("data:")):
            continue
        return True
    return False


def _sanitized_codex_message_events(obj: dict, payload: dict) -> list[dict]:
    role = payload.get("role") if payload.get("role") in ("user", "assistant") else "assistant"
    blocks = []
    for item in payload.get("content") or []:
        if isinstance(item, str):
            blocks.append({"type": "text", "text": item})
            continue
        if not isinstance(item, dict):
            blocks.append({"type": "text", "text": "[Unsupported content block]"})
            continue
        block_type = str(item.get("type") or "")
        if block_type in _CODEX_TEXT_BLOCK_TYPES:
            text = item.get("text") or item.get("content") or ""
            if text:
                blocks.append({"type": "text", "text": str(text)})
        elif block_type == "reasoning":
            text = _codex_text(item.get("summary") or item.get("content"))
            if text:
                blocks.append({"type": "thinking", "thinking": text})
        elif block_type == "input_image":
            detail = _bounded_text(item.get("detail"), 40)
            suffix = f" ({detail})" if detail else ""
            blocks.append({"type": "text", "text": f"[Image attachment{suffix}]"})
        else:
            safe_type = _bounded_text(block_type or "unknown", 80)
            text = item.get("text") or item.get("content")
            if isinstance(text, str) and text:
                prefix = f"[Unsupported content block: {safe_type}] "
                label = prefix + _bounded_text(text, VISIBLE_BLOCK_TEXT_MAX - len(prefix))
            else:
                label = f"[Unsupported content block: {safe_type}]"
            blocks.append({"type": "text", "text": label})
    if not blocks:
        return []
    source = json.dumps({
        "type": role,
        "uuid": payload.get("id"),
        "timestamp": obj.get("timestamp"),
        "message": {"role": role, "content": blocks},
    }, ensure_ascii=False, separators=(",", ":"))
    return parse_claude_transcript_line(source)


def _sanitized_image_generation_events(line: str, obj: dict, payload: dict) -> list[dict]:
    stable = hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()[:16]
    call_id = payload.get("call_id") or payload.get("id") or f"codex-image-{stable}"
    tool_input = {}
    for key in ("prompt", "revised_prompt", "size", "quality", "background", "output_format"):
        value = payload.get(key)
        if value is not None:
            if isinstance(value, (str, int, float, bool)):
                tool_input[key] = _bounded_text(value)
            else:
                tool_input[key] = "[structured value omitted]"
    blocks = [{
        "type": "tool_use",
        "id": call_id,
        "name": "image_generation",
        "input": tool_input,
    }]
    status = str(payload.get("status") or "")
    has_result = payload.get("result") is not None
    if has_result or status in ("completed", "failed", "cancelled"):
        if has_result:
            content = "Generated image available."
        elif status:
            content = f"Image generation {status}."
        else:
            content = "Image generation finished."
        error = _bounded_text(payload.get("error"))
        if error:
            content = f"{content} {error}"
        blocks.append({
            "type": "tool_result",
            "tool_use_id": call_id,
            "content": content,
            "is_error": status == "failed" or bool(error),
        })
    source = json.dumps({
        "type": "assistant",
        "uuid": f"codex-{stable}",
        "timestamp": obj.get("timestamp"),
        "message": {"role": "assistant", "content": blocks},
    }, ensure_ascii=False, separators=(",", ":"))
    return parse_claude_transcript_line(source)


def parse_codex_transcript_line(line: str, native_id: str, normalize_codex) -> list[dict]:
    """Preserve Codex records the shared normalizer cannot safely express."""
    try:
        obj = json.loads(line)
    except (TypeError, ValueError, json.JSONDecodeError):
        obj = None
    if isinstance(obj, dict) and obj.get("type") == "response_item":
        payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
        item_type = str(payload.get("type") or "")
        if item_type == "message" and payload.get("role") not in ("user", "assistant"):
            return []
        if item_type == "image_generation_call":
            return _sanitized_image_generation_events(line, obj, payload)
        if item_type == "message" and _codex_message_needs_sanitized_path(payload.get("content")):
            return _sanitized_codex_message_events(obj, payload)
    normalized = normalize_codex((line + "\n").encode("utf-8"), native_id)
    events: list[dict] = []
    for normalized_line in normalized.splitlines():
        if normalized_line.strip():
            events.extend(parse_claude_transcript_line(normalized_line))
    return events


class SessionLogIngestor:
    def __init__(self, log: SessionEventLog, hub, watcher, *, normalize_codex=None,
                 claude_parser_version: int = CLAUDE_PARSER_VERSION,
                 codex_parser_version: int = CODEX_PARSER_VERSION,
                 max_sessions: int = 128,
                 max_line_bytes: int = MAX_LINE_BYTES) -> None:
        self._log = log
        self._hub = hub
        self._watcher = watcher
        self._normalize_codex = normalize_codex
        self._claude_parser_version = max(1, int(claude_parser_version))
        self._codex_parser_version = max(1, int(codex_parser_version))
        self._max_sessions = max(1, int(max_sessions))
        self._max_line_bytes = max(READ_CHUNK, int(max_line_bytes))
        self._lock = threading.RLock()
        self._sessions: dict[str, dict] = {}
        self._by_path: dict[str, set[str]] = {}
        self._errors: dict[str, dict] = {}
        self._subscription = hub.subscribe(INGEST_TOPIC, max_queue=1024)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="session-log-ingest", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        self._subscription.close()
        self._thread.join(timeout=2)
        with self._lock:
            handles = [entry.get("watch") for entry in self._sessions.values()]
            self._sessions.clear()
            self._by_path.clear()
            self._errors.clear()
        for handle in handles:
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass

    def ensure(self, session_key: str, provider: str, native_id: str, transcript_path) -> bool:
        """Registers a session for ingestion. Returns True when registered
        (idempotent). The first drain backfills the whole file."""
        provider = str(provider or "").strip().lower()
        if provider not in SUPPORTED_TRANSCRIPT_PROVIDERS:
            return False
        if transcript_path is None:
            return False
        path = str(Path(transcript_path).expanduser().resolve(strict=False))
        created = False
        with self._lock:
            entry = self._sessions.get(session_key)
            if entry is None:
                drain_lock = threading.RLock()
                # Hold the binding lock before publishing the entry. A watcher
                # wake or a second subscriber cannot race the initial drain.
                drain_lock.acquire()
                entry = {
                    "session_key": session_key,
                    "provider": provider,
                    "native_id": native_id,
                    "path": path,
                    "watch": None,
                    "initialized": False,
                    "drain_lock": drain_lock,
                    "last_used_at": time.monotonic(),
                }
                self._sessions[session_key] = entry
                self._map_path_locked(path, session_key)
                created = True
        drain_lock = entry["drain_lock"]
        if created:
            try:
                result = self._ensure_locked(entry, provider, native_id, path)
            finally:
                drain_lock.release()
        else:
            with drain_lock:
                result = self._ensure_locked(entry, provider, native_id, path)
        self._evict_if_needed(excluding=session_key)
        return result

    def generation_for_open_source(
        self,
        session_key: str,
        provider: str,
        native_id: str,
        transcript_path,
        source_identity: tuple[int, int],
        observed_size: int,
    ) -> int | None:
        """Bind the durable generation to bytes from an already-open file.

        The caller must read from the same descriptor it used to obtain
        ``source_identity`` and ``observed_size``. This keeps a path replacement
        from tagging bytes from one inode with another inode's generation.
        """
        if not self.ensure(session_key, provider, native_id, transcript_path):
            return None
        resolved_path = str(Path(transcript_path).expanduser().resolve(strict=False))
        with self._lock:
            entry = self._sessions.get(session_key)
        if entry is None:
            return None
        with entry["drain_lock"]:
            with self._lock:
                if (
                    self._sessions.get(session_key) is not entry
                    or entry.get("path") != resolved_path
                ):
                    return None
                entry["last_used_at"] = time.monotonic()
            try:
                _offset, reset_generation = self._log.reconcile_ingest_source(
                    session_key,
                    (int(source_identity[0]), int(source_identity[1])),
                    observed_size=max(0, int(observed_size)),
                )
                generation = int(self._log.get_generation(session_key))
            except Exception as error:
                self._record_ingest_error(session_key, error)
                return None
            self._clear_ingest_error(session_key)
            if reset_generation is not None and self._hub is not None:
                self._hub.publish(f"log:{session_key}", {
                    "type": "log_reset",
                    "generation": reset_generation,
                    "last_seq": self._log.last_seq(session_key),
                })
            return generation if generation > 0 else None

    def _ensure_locked(self, entry: dict, provider: str, native_id: str, path: str) -> bool:
        if provider not in SUPPORTED_TRANSCRIPT_PROVIDERS:
            return False
        session_key = entry["session_key"]
        with self._lock:
            if self._sessions.get(session_key) is not entry:
                return False
            initialized = bool(entry.get("initialized"))
            binding_changed = initialized and (
                entry["path"] != path
                or entry["provider"] != provider
                or entry["native_id"] != native_id
            )
            if initialized and not binding_changed:
                entry["last_used_at"] = time.monotonic()
                return True
            old_watch = entry.get("watch") if binding_changed else None
            if binding_changed:
                self._unmap_path_locked(entry["path"], session_key)
                entry.update({
                    "provider": provider,
                    "native_id": native_id,
                    "path": path,
                    "watch": None,
                    "initialized": False,
                    "last_used_at": time.monotonic(),
                })
                self._map_path_locked(path, session_key)

        if old_watch is not None:
            try:
                old_watch.close()
            except Exception:
                pass

        if provider == "codex":
            parser_version = self._codex_parser_version
        elif provider == "claude":
            parser_version = self._claude_parser_version
        else:  # Defensive guard for a corrupted in-memory binding.
            raise UnsupportedTranscriptProviderError(provider)
        reset_generation = None
        if binding_changed:
            # The same Pairling session can point at a new provider transcript
            # after /resume or after sibling resolution becomes exact. The old
            # durable rows must not survive that source change.
            reset_generation = self._log.reset_ingest(session_key)
        else:
            prior_generation = self._log.get_generation(session_key)
            self._log.prepare_ingest(session_key, parser_version)
            current_generation = self._log.get_generation(session_key)
            if current_generation != prior_generation:
                reset_generation = current_generation

        watch = None
        if self._watcher is not None:
            try:
                watch = self._watcher.watch(path, INGEST_TOPIC)
            except Exception:
                watch = None
        with self._lock:
            if self._sessions.get(session_key) is not entry or entry["path"] != path:
                if watch is not None:
                    watch.close()
                return False
            entry["watch"] = watch
            entry["initialized"] = True
            entry["last_used_at"] = time.monotonic()

        if reset_generation is not None and self._hub is not None:
            self._hub.publish(f"log:{session_key}", {
                "type": "log_reset",
                "generation": reset_generation,
                "last_seq": self._log.last_seq(session_key),
            })
        # Backfill can be hundreds of megabytes. Queue it on the one ingest
        # worker so opening an HTTP stream never waits for a full transcript.
        if self._hub is not None:
            self._hub.publish(INGEST_TOPIC, {
                "type": "ingest_requested",
                "path": path,
                "session_key": session_key,
            })
        return True

    def remove(self, session_key: str) -> bool:
        """Stop watching one session before its transcript is removed."""
        with self._lock:
            entry = self._sessions.get(session_key)
        if entry is None:
            return False
        with entry["drain_lock"]:
            with self._lock:
                if self._sessions.get(session_key) is not entry:
                    return False
                self._sessions.pop(session_key, None)
                self._unmap_path_locked(entry["path"], session_key)
                self._errors.pop(session_key, None)
                watch = entry.get("watch")
                entry["watch"] = None
                entry["initialized"] = False
            if watch is not None:
                try:
                    watch.close()
                except Exception:
                    pass
        return True

    def active_session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def _evict_if_needed(self, *, excluding: str) -> None:
        while True:
            with self._lock:
                if len(self._sessions) <= self._max_sessions:
                    return
                candidates = [
                    entry for key, entry in self._sessions.items()
                    if key != excluding
                ]
                if not candidates:
                    return
                candidate = min(
                    candidates,
                    key=lambda item: float(item.get("last_used_at") or 0.0),
                )
                candidate_key = candidate["session_key"]
            with candidate["drain_lock"]:
                with self._lock:
                    if self._sessions.get(candidate_key) is not candidate:
                        continue
                    if len(self._sessions) <= self._max_sessions:
                        return
                    self._sessions.pop(candidate_key, None)
                    self._unmap_path_locked(candidate["path"], candidate_key)
                    self._errors.pop(candidate_key, None)
                    watch = candidate.get("watch")
                    candidate["watch"] = None
                    candidate["initialized"] = False
                if watch is not None:
                    try:
                        watch.close()
                    except Exception:
                        pass

    def _map_path_locked(self, path: str, session_key: str) -> None:
        self._by_path.setdefault(path, set()).add(session_key)

    def _unmap_path_locked(self, path: str, session_key: str) -> None:
        mapped = self._by_path.get(path)
        if not mapped:
            return
        mapped.discard(session_key)
        if not mapped:
            self._by_path.pop(path, None)

    def current_error(self, session_key: str) -> dict | None:
        with self._lock:
            error = self._errors.get(session_key)
            return dict(error) if error is not None else None

    def drain_now(self, session_key: str) -> dict:
        """Synchronously align one durable log with its transcript head."""
        with self._lock:
            entry = self._sessions.get(session_key)
        if entry is None:
            return {"ok": False, "reason": "session_not_registered"}
        with entry["drain_lock"]:
            for _attempt in range(4):
                if not self._attempt_drain_locked(entry):
                    return {"ok": False, "reason": "transcript_ingest_failed"}
                try:
                    source_size = int(Path(entry["path"]).stat().st_size)
                    source_offset = self._log.get_ingest_offset(session_key)
                    last_seq = self._log.last_seq(session_key)
                    generation = self._log.get_generation(session_key)
                except Exception as error:
                    self._record_ingest_error(session_key, error)
                    return {"ok": False, "reason": "transcript_inspection_failed"}
                if source_offset >= source_size:
                    return {
                        "ok": True,
                        "transcript_offset": source_size,
                        "log_seq": last_seq,
                        "log_generation": generation,
                    }
                time.sleep(0.01)
        return {"ok": False, "reason": "transcript_changed_during_boundary"}

    def _record_ingest_error(self, session_key: str, error: Exception) -> None:
        try:
            generation = self._log.get_generation(session_key)
        except Exception:
            generation = None
        payload = {
            "type": "log_ingest_error",
            "code": "transcript_ingest_failed",
            "message": str(error)[:240] or type(error).__name__,
            "error_type": type(error).__name__,
            "retryable": True,
            "session_key": session_key,
            "generation": generation,
        }
        with self._lock:
            previous = self._errors.get(session_key)
            self._errors[session_key] = payload
        if previous != payload and self._hub is not None:
            self._hub.publish(f"log:{session_key}", payload)

    def _clear_ingest_error(self, session_key: str) -> None:
        with self._lock:
            previous = self._errors.pop(session_key, None)
        if previous is not None and self._hub is not None:
            try:
                generation = self._log.get_generation(session_key)
            except Exception:
                generation = None
            self._hub.publish(f"log:{session_key}", {
                "type": "log_ingest_recovered",
                "code": "transcript_ingest_recovered",
                "session_key": session_key,
                "generation": generation,
            })

    def _attempt_drain_locked(self, entry: dict, *, force_reset: bool = False,
                              publish: bool = True) -> bool:
        try:
            completed = self._drain_entry_locked(
                entry, force_reset=force_reset, publish=publish
            )
        except Exception as error:
            self._record_ingest_error(entry["session_key"], error)
            return False
        if completed:
            self._clear_ingest_error(entry["session_key"])
        return completed

    def _run(self) -> None:
        while not self._stop.is_set():
            event = self._subscription.get(timeout=1.0)
            due: dict[str, bool] = {}
            while event is not None:
                if event.get("type") == "queue_gap":
                    with self._lock:
                        for session_key in self._sessions:
                            due.setdefault(session_key, False)
                else:
                    with self._lock:
                        session_keys = tuple(self._by_path.get(str(event.get("path") or ""), ()))
                    for session_key in session_keys:
                        due[session_key] = due.get(session_key, False) or event.get("type") == "file_rotated"
                event = self._subscription.get(timeout=0)
            # A failed drain may have consumed the only file-change wake. Keep
            # retrying only the sessions in a typed error state so a transient
            # parser or SQLite failure can recover without waiting for another
            # provider write.
            with self._lock:
                for session_key in self._errors:
                    due.setdefault(session_key, False)
            for session_key, force_reset in due.items():
                self._drain(session_key, force_reset=force_reset)

    def _drain(self, session_key: str, *, force_reset: bool = False) -> None:
        with self._lock:
            entry = self._sessions.get(session_key)
        if entry is None:
            return
        with entry["drain_lock"]:
            self._attempt_drain_locked(entry, force_reset=force_reset)

    def _drain_entry_locked(self, entry: dict, *, force_reset: bool = False,
                            publish: bool = True) -> bool:
        session_key = entry["session_key"]
        provider = str(entry.get("provider") or "").strip().lower()
        if provider not in SUPPORTED_TRANSCRIPT_PROVIDERS:
            raise UnsupportedTranscriptProviderError(provider)
        if provider == "codex" and self._normalize_codex is None:
            raise RuntimeError("Codex transcript normalizer is unavailable")
        path = Path(entry["path"])
        try:
            handle = open(path, "rb")
        except OSError as error:
            raise OSError(f"cannot open transcript: {error}") from error
        with handle:
            try:
                stat = os.fstat(handle.fileno())
            except OSError as error:
                raise OSError(f"cannot inspect transcript: {error}") from error
            size = int(stat.st_size)
            source_identity = (int(stat.st_dev), int(stat.st_ino))
            source_version = source_file_version(stat)
            offset, reset_generation = self._log.reconcile_ingest_source(
                session_key,
                source_identity,
                observed_size=size,
                force_reset=force_reset,
            )
            appended_any = False
            while offset < size:
                handle.seek(offset)
                data = handle.read(min(size - offset, READ_CHUNK))
                newline = data.rfind(b"\n")
                if newline < 0:
                    if len(data) < READ_CHUNK:
                        break
                    # The log is the archive, so ordinary large lines ingest
                    # whole and become neutral events. A pathological record
                    # beyond the parse cap is preserved exactly in the private
                    # raw store without materializing it in this process.
                    end = self._scan_line_end(handle, offset + len(data), size)
                    if end is None:
                        break
                    if end - offset <= self._max_line_bytes:
                        handle.seek(offset)
                        complete = handle.read(end - offset)
                    else:
                        advanced = self._log.append_preserved_raw_and_advance(
                            session_key,
                            {
                                "kind": "lifecycle",
                                "subtype": "oversized_line",
                                "source_uuid": None,
                                "role": None,
                                "ts": None,
                                "start": offset,
                                "end": end,
                                "bytes": end - offset,
                                "raw": None,
                            },
                            end,
                            expected_byte_offset=offset,
                            expected_source_identity=source_identity,
                            source_handle=handle,
                            source_start=offset,
                            source_bytes=end - offset,
                            expected_source_version=source_version,
                        )
                        if advanced is None:
                            # Another reader moved the cursor after this drain
                            # opened the file. Resume at that durable cursor so
                            # a suffix appended during the race is not stranded
                            # until some future wake.
                            durable_offset = self._log.get_ingest_offset(session_key)
                            if offset < durable_offset <= size:
                                offset = durable_offset
                                continue
                            return False
                        appended_any = True
                        offset = end
                        continue
                else:
                    complete = data[:newline + 1]
                text = complete.decode("utf-8", errors="replace")
                events: list[dict] = []
                for line in text.splitlines():
                    if line.strip():
                        if provider == "codex":
                            events.extend(parse_codex_transcript_line(
                                line, entry["native_id"], self._normalize_codex
                            ))
                        elif provider == "claude":
                            events.extend(parse_claude_transcript_line(line))
                        else:  # Defensive guard for a corrupted in-memory binding.
                            raise UnsupportedTranscriptProviderError(provider)
                next_offset = offset + len(complete)
                advanced = self._log.append_and_advance(
                    session_key,
                    events,
                    next_offset,
                    expected_byte_offset=offset,
                    expected_source_identity=source_identity,
                )
                if advanced is None:
                    durable_offset = self._log.get_ingest_offset(session_key)
                    if offset < durable_offset <= size:
                        offset = durable_offset
                        continue
                    return False
                appended_any = appended_any or bool(events)
                offset = next_offset
        if publish and (appended_any or reset_generation is not None) and self._hub is not None:
            self._hub.publish(f"log:{session_key}", {
                "type": "log_reset" if reset_generation is not None else "log_appended",
                "generation": reset_generation,
                "last_seq": self._log.last_seq(session_key),
            })
        return True

    @staticmethod
    def _scan_line_end(handle, scan_from: int, size: int) -> int | None:
        position = scan_from
        while position < size:
            handle.seek(position)
            chunk = handle.read(READ_CHUNK)
            if not chunk:
                return None
            found = chunk.find(b"\n")
            if found >= 0:
                return position + found + 1
            position += len(chunk)
        return None
