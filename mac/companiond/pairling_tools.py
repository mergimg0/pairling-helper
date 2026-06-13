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


@dataclass(frozen=True)
class ToolResult:
    ok: bool
    provider: str | None
    result: str = ""
    reason: str | None = None
    error_message: str | None = None


class PhoneToolAvailabilityStore:
    def __init__(self) -> None:
        self._state: dict[str, Any] = {}

    def update(self, payload: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
        current = time.time() if now is None else now
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
        state = {
            "last_seen_at": current,
            "expires_at": current + expires_in if running else current,
            "listener_running": running,
            "port": _bounded_int(payload.get("port"), default=IPHONE_PORT, minimum=1, maximum=65535),
            "tools": normalized_tools,
            "app_state": str(payload.get("app_state") or "unknown")[:40],
        }
        self._state = state
        return self.snapshot(now=current)

    def snapshot(self, *, now: float | None = None) -> dict[str, Any]:
        current = time.time() if now is None else now
        state = dict(self._state)
        state["fresh"] = self.is_fresh(now=current)
        return state

    def is_fresh(self, tool: str | None = None, *, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        if not self._state.get("listener_running"):
            return False
        if float(self._state.get("expires_at") or 0) <= current:
            return False
        if tool and tool not in set(self._state.get("tools") or []):
            return False
        return True


PHONE_TOOL_AVAILABILITY = PhoneToolAvailabilityStore()


class PhoneToolWorkQueue:
    def __init__(self) -> None:
        self._condition = threading.Condition(threading.RLock())
        self._pending: list[dict[str, Any]] = []
        self._inflight: dict[str, dict[str, Any]] = {}
        self._results: dict[str, ToolResult] = {}
        self._poller_state: dict[str, Any] = {}

    def report_poller(
        self,
        *,
        device_id: str | None,
        tools: list[str] | None,
        now: float | None = None,
        expires_in_seconds: int = 30,
    ) -> dict[str, Any]:
        current = time.time() if now is None else now
        normalized_tools = sorted({str(tool) for tool in (tools or PHONE_TOOL_LIST) if str(tool) in ALLOWED_TOOLS})
        expires = current + max(1, min(int(expires_in_seconds or 30), 120))
        with self._condition:
            self._poller_state = {
                "device_id": device_id,
                "last_seen_at": current,
                "expires_at": expires,
                "tools": normalized_tools,
            }
            self._condition.notify_all()
            return self.snapshot(now=current)

    def snapshot(self, *, now: float | None = None) -> dict[str, Any]:
        current = time.time() if now is None else now
        state = dict(self._poller_state)
        state["fresh"] = self.is_fresh(now=current)
        return state

    def is_fresh(self, tool: str | None = None, *, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        with self._condition:
            if float(self._poller_state.get("expires_at") or 0) <= current:
                return False
            if tool and tool not in set(self._poller_state.get("tools") or []):
                return False
            return bool(self._poller_state.get("device_id"))

    def next_request(
        self,
        *,
        device_id: str | None,
        tools: list[str] | None,
        wait_seconds: int,
        now: Callable[[], float] = time.time,
    ) -> dict[str, Any] | None:
        normalized_tools = sorted({str(tool) for tool in (tools or PHONE_TOOL_LIST) if str(tool) in ALLOWED_TOOLS})
        wait_seconds = max(1, min(int(wait_seconds or 10), 25))
        deadline = now() + wait_seconds
        with self._condition:
            self.report_poller(
                device_id=device_id,
                tools=normalized_tools,
                now=now(),
                expires_in_seconds=wait_seconds + 20,
            )
            while True:
                self._prune_locked(now())
                for idx, request in enumerate(self._pending):
                    if request["tool"] in normalized_tools:
                        request = self._pending.pop(idx)
                        request["assigned_device_id"] = device_id
                        self._inflight[request["request_id"]] = request
                        return {
                            "request_id": request["request_id"],
                            "tool": request["tool"],
                            "input": request["input"],
                            "created_at": request["created_at"],
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
    ) -> bool:
        request_id = str(request_id or "")
        if not request_id:
            return False
        with self._condition:
            request = self._inflight.pop(request_id, None)
            if request is None:
                return False
            self._results[request_id] = ToolResult(
                bool(ok),
                "iphone",
                result=str(result or ""),
                reason=None if ok else "iphone_tool_failed",
                error_message="" if ok else str(error or "phone tool failed"),
            )
            self._condition.notify_all()
            return True

    def submit(
        self,
        tool: str,
        input_payload: dict[str, Any],
        *,
        timeout_ms: int,
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
            if not self.is_fresh(tool, now=now()):
                return ToolResult(False, "iphone", reason="iphone_no_reverse_worker", error_message="no fresh phone tool worker")
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
                    return ToolResult(False, "iphone", reason="iphone_timeout", error_message="timed out")
                self._condition.wait(timeout=remaining)

    def _prune_locked(self, current: float) -> None:
        self._pending = [item for item in self._pending if float(item.get("expires_at") or 0) > current]
        expired = [
            request_id
            for request_id, item in self._inflight.items()
            if float(item.get("expires_at") or 0) <= current
        ]
        for request_id in expired:
            self._inflight.pop(request_id, None)
            self._results.pop(request_id, None)


PHONE_TOOL_WORK_QUEUE = PhoneToolWorkQueue()


class PhoneToolClient:
    def __init__(
        self,
        *,
        host: str = IPHONE_HOST,
        port: int = IPHONE_PORT,
        token: str | None = None,
        work_queue: PhoneToolWorkQueue | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.token = token if token is not None else _load_phone_token()
        self.work_queue = work_queue or PHONE_TOOL_WORK_QUEUE

    def is_available(self, tool: str, *, now: float | None = None) -> bool:
        if os.environ.get("PAIRLING_PHONE_TOOLS_DIRECT_TCP") == "1":
            return True
        return self.work_queue.is_fresh(tool, now=now)

    def run(self, tool: str, input_payload: dict[str, Any], *, timeout_ms: int) -> ToolResult:
        if os.environ.get("PAIRLING_PHONE_TOOLS_DIRECT_TCP") != "1":
            return self.work_queue.submit(tool, input_payload, timeout_ms=timeout_ms)
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

    store = availability or PHONE_TOOL_AVAILABILITY
    phone = iphone_client or PhoneToolClient()
    mac = mac_runner or MacToolRunner()
    iphone_attempted = False
    iphone_reason: str | None = None
    iphone_error: str | None = None

    iphone_ready = store.is_fresh(tool, now=started) or (
        hasattr(phone, "is_available") and bool(phone.is_available(tool, now=started))
    )
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
        iphone_reason = "iphone_heartbeat_stale"
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
    return {
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
            "You are checking whether a draft sounds like Mergim's usual voice. Return one of: yes, partial, no. Then give one concrete edit. Be concise. Do not rewrite the whole draft unless asked.",
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
        issues.append("a little more formal than Mergim's usual direct style")
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
