#!/usr/bin/env python3
"""
Pairling Mac daemon.

Runtime endpoints use per-device scoped Authorization: Bearer tokens:
  POST /open?path=<abs>&app=sublime|finder       open path on Mac
  GET  /sessions?active_within_min=<n>           list recent sessions from continuous-claude PG
  GET  /recent-projects?active_within_min=<n>    list recent project paths without transcript enrichment
  GET  /transcript?session=<id>&since=<bytes>    stream transcript JSONL since byte offset
  GET  /terminal-stream?session=<id>&since=<bytes> stream live terminal output since byte offset
  GET  /corpus?since=<unix-ts>                   list transcripts modified after ts
  POST /inject?session=<id>  body: text          queue text for next user prompt
  POST /inject-now?session=<id> body: text       AppleScript types text into matching Terminal
  POST /interrupt?session=<id>                   AppleScript sends Esc to matching Terminal
  GET  /session-meta?session=<id>                effort/model/type/sentinel-mode/etc
  GET  /personal-context                         contents of ~/.claude/personal-context.md
  POST /llm-route?model=sonnet|haiku  body:JSON  one-shot prompt via `claude -p` (subscription)
  POST /llm-route-stream?model=...    body:JSON  same as /llm-route but streams as SSE
  GET  /worker-stats?since_min=<n>               counts of automated worker sessions
  GET  /push/status                              APNs relay/provider registration state
  POST /push/preferences body:JSON               store per-device push preferences
  POST /push/test body:JSON                      queue a bounded push diagnostic event
  POST /push/live-activity-token body:JSON       store APNs Live Activity token privately
  POST /push/live-activity-test body:JSON        send/queue bounded Live Activity APNs test
  GET  /sentinel/status                          worker/token sentinel classification state
  GET  /sentinel/preferences                     worker/token sentinel preferences
  POST /sentinel/preferences body:JSON           update sentinel thresholds/cooldowns
  POST /sentinel/snooze body:JSON                snooze a sentinel dedupe key
  POST /sentinel/evaluate-now body:JSON          classify now and emit at most one sentinel push
  GET  /sentinel/events?since=<epoch>            local sentinel event ledger
  GET  /safety/status                            future Safety Monitor install/approval state
  GET  /safety/events?since=<id>                 redacted safety summaries, fixture-backed in phase 0
  POST /safety/ack body:JSON                     acknowledge visible safety summaries
  GET  /aperture-cli/status                      read-only Aperture CLI launcher status
  GET  /aperture-cli/providers                   read-only active Aperture provider/model inventory
  GET  /aperture-cli/launch-contexts             read-only generated Pairling launch contexts
  POST /aperture-cli/open body:JSON              proof-bound raw Aperture CLI TUI on the Mac
  GET  /workstate-feed?run=<path>&since=<iso>&limit=<n> read-only substrate workstate feed
  GET  /model-status?run=<path>&since=<iso>&limit=<n> read-only substrate model arbiter status
  GET  /substrate-status?run=<path>&since=<iso>&limit=<n> read-only operational substrate status
  GET  /substrate-feed?run=<path>&since=<iso>&limit=<n> read-only operational substrate feed
  POST /worker-kill body:JSON                    SIGTERM workers by id or filter:"stale"
  POST /pairling-tools/run body:JSON             daemon-first MCP tool router
  POST /phone-tools/availability body:JSON       foreground iPhone tool-listener availability

Listens on PAIRLING_WEBHOOK_HOST, loopback by default unless explicitly configured.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
import copy
import secrets
import shlex
import signal
import sqlite3
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

try:
    from runtime_contract import (
        AUTH_MODE as RUNTIME_AUTH_MODE,
        CONTRACT_VERSION as RUNTIME_CONTRACT_VERSION,
        DAEMON_LABEL as RUNTIME_DAEMON_LABEL,
        DEFAULT_DEVICE_SCOPES as RUNTIME_DEFAULT_DEVICE_SCOPES,
        LEGACY_TOKEN_RELATIVE_PATH,
        PORT as RUNTIME_PORT,
        RUNTIME_NAME as RUNTIME_NAME,
    )
    from runtime_paths import app_support_root, devices_db_path
    from pairling_devices import DeviceAuthResult, DeviceRegistry
    from pairling_connectd_status import (
        advertised_pairling_connect_routes,
        fetch_connectd_status,
        redacted_connectd_summary,
    )
    from pairling_pairing import DEFAULT_PAIR_TTL_SECONDS, PairingAdvertiser, PairingError, PairingStore, ReauthStore
    from pairdrop_store import PairDropStore, PairDropStoreError
except Exception:
    RUNTIME_AUTH_MODE = "scoped-device-bearer"
    RUNTIME_CONTRACT_VERSION = "pairling-runtime-v1"
    RUNTIME_DAEMON_LABEL = "dev.pairling.companiond"
    RUNTIME_DEFAULT_DEVICE_SCOPES = frozenset()
    LEGACY_TOKEN_RELATIVE_PATH = ".claude/scripts/.notify-token"
    RUNTIME_PORT = 7773
    RUNTIME_NAME = "pairling-mac-runtime"
    DeviceAuthResult = None
    DeviceRegistry = None
    advertised_pairling_connect_routes = None
    fetch_connectd_status = None
    redacted_connectd_summary = None
    DEFAULT_PAIR_TTL_SECONDS = 180
    PairingAdvertiser = None
    PairingError = None
    PairingStore = None
    ReauthStore = None
    PairDropStore = None
    PairDropStoreError = ValueError
    app_support_root = None
    devices_db_path = None

try:
    from runtime_manifest import (
        build_manifest_payload as _build_manifest_payload,
        build_runtime_info as _build_runtime_info,
        public_runtime_info as _public_runtime_info,
    )
except Exception:
    _build_manifest_payload = None
    _build_runtime_info = None
    _public_runtime_info = None

try:
    from pairling_relay_claims import RelayClaimVerifier, relay_claims_required
except Exception:
    RelayClaimVerifier = None
    relay_claims_required = None

try:
    from push_dispatcher import PairlingPushDispatcher, PushDispatcherError
except Exception:
    PairlingPushDispatcher = None
    PushDispatcherError = None

try:
    from request_proof import ReplayCache, verify_request_proof
except Exception:
    ReplayCache = None
    verify_request_proof = None

try:
    from integrations.aperture_cli import command_for_context as _aperture_cli_command_for_context
    from integrations.aperture_cli import contexts_payload as _aperture_cli_contexts_payload
    from integrations.aperture_cli import provider_payload as _aperture_cli_provider_payload
    from integrations.aperture_cli import status_payload as _aperture_cli_status_payload
    from integrations.aperture_cli import validate_launch_context as _aperture_cli_validate_launch_context
except Exception:
    _aperture_cli_command_for_context = None
    _aperture_cli_contexts_payload = None
    _aperture_cli_provider_payload = None
    _aperture_cli_status_payload = None
    _aperture_cli_validate_launch_context = None

try:
    from llm_route import LLMRouteError, llm_route_model_family, run_local_llm
except Exception:
    LLMRouteError = None
    llm_route_model_family = None
    run_local_llm = None

try:
    from pairling_tools import (
        PHONE_TOOL_AVAILABILITY,
        PHONE_TOOL_WORK_QUEUE,
        audit_detail_for_tool_run,
        run_pairling_tool,
    )
except Exception:
    PHONE_TOOL_AVAILABILITY = None
    PHONE_TOOL_WORK_QUEUE = None
    audit_detail_for_tool_run = None
    run_pairling_tool = None

try:
    from live_activity_publisher import LiveActivityTurnStatePublisher
except Exception:
    LiveActivityTurnStatePublisher = None

try:
    from standard_push_publisher import MacHealthAlertPublisher, SentinelBackgroundEvaluator, TurnStateAlertPublisher
except Exception:
    MacHealthAlertPublisher = None
    SentinelBackgroundEvaluator = None
    TurnStateAlertPublisher = None

try:
    from safety_monitor import SafetyMonitorBridge
except Exception:
    SafetyMonitorBridge = None

try:
    from pty_broker_client import PTYBrokerClient, ensure_pty_broker_token
except Exception:
    PTYBrokerClient = None
    ensure_pty_broker_token = None

try:
    from codex_approval import classify_codex_approval
except Exception:
    classify_codex_approval = None

try:
    from terminal_text_sanitizer import (
        TERMINAL_TEXT_MAX_CHARS,
        TERMINAL_TEXT_SUBMIT_MAX_CHARS,
        sanitize_terminal_text_input as _sanitize_terminal_text_input,
    )
except Exception:
    TERMINAL_TEXT_MAX_CHARS = 8000
    TERMINAL_TEXT_SUBMIT_MAX_CHARS = 2000

    def _sanitize_terminal_text_input(text: str, *, allow_newline: bool, max_chars: int) -> tuple[str | None, dict | None]:
        if "\x1b[200~" in text or "\x1b[201~" in text:
            return None, {"code": "bracketed_paste_delimiter", "message": "bracketed paste delimiters are not accepted from clients", "status": 400}
        for ch in text:
            code = ord(ch)
            if ch == "\n":
                if allow_newline:
                    continue
                return None, {"code": "multi_line_text", "message": "terminal text must be single-line", "status": 400}
            if ch == "\t" and allow_newline:
                continue
            if code == 0x1B:
                return None, {"code": "escape_not_allowed", "message": "ESC is not accepted in terminal text", "status": 400}
            if code in {0x061C, 0x200E, 0x200F} or 0x202A <= code <= 0x202E or 0x2066 <= code <= 0x2069:
                return None, {"code": "bidi_control_not_allowed", "message": "Unicode bidi controls are not accepted in terminal text", "status": 400}
            if code < 0x20:
                return None, {"code": "c0_not_allowed", "message": "C0 control characters are not accepted in terminal text", "status": 400}
            if code == 0x7F or 0x80 <= code <= 0x9F:
                return None, {"code": "c1_or_del_not_allowed", "message": "DEL and C1 control characters are not accepted in terminal text", "status": 400}
        cleaned = text.strip()
        if not cleaned:
            return None, {"code": "empty_text", "message": "terminal text cannot be empty", "status": 400}
        if len(cleaned) > max_chars:
            return None, {"code": "text_too_long", "message": f"terminal text exceeds {max_chars} chars", "status": 413}
        return cleaned, None

try:
    from sentinel_notifications import SentinelNotificationCenter, SentinelNotificationError
except Exception:
    SentinelNotificationCenter = None
    SentinelNotificationError = None

try:
    from providers.base import provider_detail_payload, provider_snapshot_payload
    from providers.registry import (
        known_provider_ids as _provider_known_ids,
        provider_ids as _provider_registry_ids,
        probe_all as _provider_probe_all,
    )
except Exception:
    provider_detail_payload = None
    provider_snapshot_payload = None
    _provider_known_ids = None
    _provider_registry_ids = None
    _provider_probe_all = None

from workstate_feed_contract import (
    DEFAULT_SINCE as WORKSTATE_FEED_DEFAULT_SINCE,
    WorkstateFeedError,
    fetch_workstate_feed as _fetch_workstate_feed,
)
from model_status_contract import (
    DEFAULT_SINCE as MODEL_STATUS_DEFAULT_SINCE,
    ModelStatusError,
    fetch_model_status as _fetch_model_status,
)
from substrate_status_contract import (
    DEFAULT_SINCE as SUBSTRATE_STATUS_DEFAULT_SINCE,
    SubstrateStatusError,
    fetch_substrate_feed as _fetch_substrate_feed,
    fetch_substrate_status as _fetch_substrate_status,
)

# launchd gives subprocesses a minimal PATH; prepend the locations of `docker`,
# `psql`, `osascript`, `open`, etc. so we can shell out reliably.
_USER_HOME = str(Path.home())
os.environ["PATH"] = (
    f"{_USER_HOME}/.local/bin:{_USER_HOME}/bin:"
    "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:"
    + os.environ.get("PATH", "")
)

PORT = RUNTIME_PORT
HOME = Path.home()
DEFAULT_COORDINATOR_HOST = (
    os.environ.get("PAIRLING_HOSTNAME")
    or os.environ.get("COMPANION_COORDINATOR_HOST")
    or os.uname().nodename.split(".")[0]
    or "pairling-mac"
)
LEGACY_TOKEN_FILE = HOME / LEGACY_TOKEN_RELATIVE_PATH
PROJECTS_DIR = HOME / ".claude" / "projects" / re.sub(r"[/._]", "-", str(HOME))
QUEUE_DIR = HOME / ".claude" / "hooks" / "queue"
COMPANION_DIR = HOME / ".claude" / "companion"
ORCHESTRATIONS_ROUTE = "/orchestrations"
ORCHESTRATIONS_DIR = COMPANION_DIR / "orchestrations"
HANDOFFS_DIR = COMPANION_DIR / "handoffs"
CROSS_PROVIDER_DIR = COMPANION_DIR / "cross-provider"
SUBLIME_APP = "Sublime Text"
CODEX_SESSIONS_DIR = HOME / ".codex" / "sessions"
CODEX_SESSION_INDEX = HOME / ".codex" / "session_index.jsonl"
CODEX_HISTORY = HOME / ".codex" / "history.jsonl"
TURN_STATE_DIR = HOME / ".claude" / "turn-state"
AGENT_REGISTRY_DB = COMPANION_DIR / "agent-sessions.sqlite"
TERMINAL_CAPTURE_DIR = COMPANION_DIR / "terminal-capture"
TERMINAL_CAPTURE_MAP_DIR = TERMINAL_CAPTURE_DIR / "by-tty"
PTY_BROKER_SOCKET = COMPANION_DIR / "pty-broker.sock"
PTY_BROKER_TOKEN = ensure_pty_broker_token(COMPANION_DIR) if ensure_pty_broker_token else ""
PTY_BROKER = PTYBrokerClient(PTY_BROKER_SOCKET, PTY_BROKER_TOKEN) if PTYBrokerClient and PTY_BROKER_TOKEN else None
APP_SUPPORT_ROOT = app_support_root() if app_support_root else Path(os.environ.get(
    "PAIRLING_APP_SUPPORT_ROOT",
    str(HOME / "Library" / "Application Support" / "Pairling"),
))
PROJECT_MIRROR_DIR = APP_SUPPORT_ROOT / "project-mirror"
PROJECT_MIRROR_STATE = PROJECT_MIRROR_DIR / "state.json"
PROJECT_MIRROR_CONFLICTS = PROJECT_MIRROR_DIR / "conflicts.json"
PROJECT_MIRROR_CONTRACT = "pairling-project-mirror-v1"

DEVICE_REGISTRY = DeviceRegistry(devices_db_path()) if DeviceRegistry and devices_db_path else None
PAIRING_STORE = (
    PairingStore(APP_SUPPORT_ROOT / "pair", DEVICE_REGISTRY, runtime_port=PORT)
    if PairingStore and DEVICE_REGISTRY
    else None
)
PAIRING_ADVERTISER = PairingAdvertiser() if PairingAdvertiser else None
REAUTH_STORE = ReauthStore(DEVICE_REGISTRY) if ReauthStore and DEVICE_REGISTRY else None
RELAY_CLAIM_VERIFIER = (
    RelayClaimVerifier.from_environment(mac_install_id=PAIRING_STORE.install_id)
    if RelayClaimVerifier and PAIRING_STORE
    else None
)
SAFETY_MONITOR = SafetyMonitorBridge(APP_SUPPORT_ROOT, HOME) if SafetyMonitorBridge else None
PUSH_DISPATCHER = (
    PairlingPushDispatcher(APP_SUPPORT_ROOT / "push-devices.json")
    if PairlingPushDispatcher
    else None
)
SENTINEL_NOTIFICATIONS = (
    SentinelNotificationCenter(APP_SUPPORT_ROOT, push_dispatcher=PUSH_DISPATCHER)
    if SentinelNotificationCenter
    else None
)
LIVE_ACTIVITY_PUBLISHER = None
STANDARD_TURN_PUSH_PUBLISHER = None
MAC_HEALTH_PUSH_PUBLISHER = None
SENTINEL_PUSH_PUBLISHER = None


def _broker_value(session, key: str, default=None):
    if isinstance(session, dict):
        value = session.get(key, default)
        return default if value is None else value
    return getattr(session, key, default)


def _broker_session_id(session) -> str:
    return str(_broker_value(session, "session_id", "") or "")


def _broker_slave_tty(session) -> str:
    return str(_broker_value(session, "slave_tty", "") or "")


def _broker_pid(session) -> int:
    try:
        return int(_broker_value(session, "pid", 0) or 0)
    except Exception:
        return 0


def _broker_raw_log_path(session) -> Path | None:
    raw = _broker_value(session, "raw_log_path", None)
    if isinstance(raw, Path):
        return raw
    if raw:
        return Path(str(raw))
    return None

QUEUE_DIR.mkdir(parents=True, exist_ok=True)
ORCHESTRATIONS_DIR.mkdir(parents=True, exist_ok=True)
HANDOFFS_DIR.mkdir(parents=True, exist_ok=True)
CROSS_PROVIDER_DIR.mkdir(parents=True, exist_ok=True)
TURN_STATE_DIR.mkdir(parents=True, exist_ok=True)
TERMINAL_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
TERMINAL_CAPTURE_MAP_DIR.mkdir(parents=True, exist_ok=True)


def _bind_host() -> str:
    if os.environ.get("PAIRLING_WEBHOOK_HOST"):
        return os.environ["PAIRLING_WEBHOOK_HOST"]
    mode = os.environ.get("PAIRLING_BIND_MODE", "loopback").strip().lower()
    if mode in ("all", "tailnet_lan"):
        return "0.0.0.0"
    if mode == "loopback":
        return "127.0.0.1"
    if mode == "lan":
        ok, out, _ = _run_text(["/sbin/ifconfig"], timeout=3)
        if ok:
            for match in re.finditer(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\b", out):
                ip = match.group(1)
                if not ip.startswith(("127.", "169.254.", "100.")):
                    return ip
    try:
        proc = subprocess.run(
            ["tailscale", "ip", "-4"],
            capture_output=True, text=True, timeout=2,
        )
        ip = (proc.stdout or "").strip().splitlines()[0]
        if ip.startswith("100."):
            return ip
    except Exception:
        pass
    return "127.0.0.1"

# Phase 4 A.3: simple per-session rate limit for /inject-now.
# Threshold: 1 inject per session per second. Bursts of 5/second across all
# sessions. Mitigates RCE blast radius if token leaks.
import threading
import time as _time

_inject_rate_lock = threading.Lock()
_inject_rate_state: dict[str, list[float]] = {}  # session_id -> [timestamps]
_request_rate_lock = threading.Lock()
_request_rate_state: dict[str, list[float]] = {}
_proof_replay_cache = ReplayCache() if ReplayCache is not None else None
SSE_MAX_EVENT_BYTES = 64 * 1024
SSE_TRANSCRIPT_MAX_EVENT_BYTES = 256 * 1024
SSE_TERMINAL_CHUNK_BYTES = 48 * 1024
TRANSCRIPT_INITIAL_STREAM_BYTES = 900_000
TRANSCRIPT_TAIL_SCAN_BYTES = 512 * 1024
TRANSCRIPT_STATS_MAX_SCAN_BYTES = 512 * 1024
RUNTIME_SNAPSHOT_CACHE_SECONDS = 2.0
PROVIDER_STATUS_CACHE_SECONDS = 8.0
FILESYSTEM_DIRECTORIES_CACHE_SECONDS = 2.0
RECENT_PROJECTS_CACHE_SECONDS = 5.0
CODEX_ROLLOUT_PATHS_CACHE_SECONDS = 5.0
AUTH_RESULT_CACHE_SECONDS = max(0.0, float(os.environ.get("PAIRLING_AUTH_RESULT_CACHE_SECONDS", "1.0")))
AUTH_RESULT_CACHE_MAX = max(16, int(os.environ.get("PAIRLING_AUTH_RESULT_CACHE_MAX", "512")))
RUNTIME_MAX_ACTIVE_FAST_REQUESTS = max(2, int(os.environ.get("PAIRLING_RUNTIME_MAX_ACTIVE_FAST_REQUESTS", "4")))
RUNTIME_MAX_ACTIVE_REQUESTS = max(4, int(os.environ.get("PAIRLING_RUNTIME_MAX_ACTIVE_REQUESTS", "12")))
RUNTIME_MAX_ACTIVE_STREAMS = max(2, int(os.environ.get("PAIRLING_RUNTIME_MAX_ACTIVE_STREAMS", "6")))
RUNTIME_MAX_ACTIVE_CONNECTIONS = max(
    RUNTIME_MAX_ACTIVE_FAST_REQUESTS + RUNTIME_MAX_ACTIVE_REQUESTS + RUNTIME_MAX_ACTIVE_STREAMS + 2,
    int(os.environ.get("PAIRLING_RUNTIME_MAX_ACTIVE_CONNECTIONS", "24")),
)
TERMINAL_TRUTH_OSASCRIPT_TIMEOUT_SECONDS = max(
    0.5,
    min(5.0, float(os.environ.get("PAIRLING_TERMINAL_TRUTH_OSASCRIPT_TIMEOUT_SECONDS", "3.0"))),
)
TERMINAL_SURFACE_V2_NONCE_SALT = os.urandom(16).hex()
LAST_HUMAN_ACTIVITY_AT = 0.0
DAEMON_STARTED_AT = _time.time()
BOUND_HOST = ""
POWER_STATE_PATH = Path(os.environ.get("COMPANION_POWER_STATE_PATH", "/var/run/pairling-power-state.json"))
POWER_STATE_FALLBACK_PATH = Path(os.environ.get("COMPANION_POWER_STATE_FALLBACK_PATH", "/tmp/pairling-power-state.json"))
POWER_STATE_STALE_SECONDS = 90
DAEMON_VERSION = "2026-05-07"

_sessions_health_lock = threading.Lock()
_sessions_health: dict[str, float | int] = {
    "last_scan_at": 0.0,
    "last_snapshot_count": 0,
}


def _sse_json_event(event: str, payload: dict, *, max_bytes: int = SSE_MAX_EVENT_BYTES) -> tuple[bytes, dict | None]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(data) <= max_bytes:
        return b"event: " + event.encode("utf-8") + b"\ndata: " + data + b"\n\n", None
    diagnostic = {
        "ok": False,
        "reason": "event_too_large",
        "event": event,
        "max_event_bytes": max_bytes,
        "actual_event_bytes": len(data),
    }
    diag = json.dumps(diagnostic, separators=(",", ":")).encode("utf-8")
    return b"event: error\ndata: " + diag[:max_bytes] + b"\n\n", diagnostic


def _sse_write_json_event(wfile, event: str, payload: dict, *, max_bytes: int = SSE_MAX_EVENT_BYTES) -> bool:
    body, diagnostic = _sse_json_event(event, payload, max_bytes=max_bytes)
    try:
        wfile.write(body)
        wfile.flush()
        return diagnostic is None
    except (BrokenPipeError, ConnectionResetError):
        return False


def _bounded_terminal_stream_chunk(
    data: bytes,
    *,
    last_offset: int,
    total_bytes: int,
    clean_text,
) -> tuple[bytes, dict]:
    max_len = min(len(data), SSE_TERMINAL_CHUNK_BYTES)
    while max_len > 0:
        send_data = data[:max_len]
        payload = {
            "next_since": last_offset + len(send_data),
            "total_bytes": total_bytes,
            "text": clean_text(send_data),
        }
        _, diagnostic = _sse_json_event("chunk", payload, max_bytes=SSE_MAX_EVENT_BYTES)
        if diagnostic is None:
            return send_data, payload
        max_len = max_len // 2
    send_data = data[:1]
    return send_data, {
        "next_since": last_offset + len(send_data),
        "total_bytes": total_bytes,
        "text": clean_text(send_data),
    }


_TERMINAL_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_TERMINAL_STRING_RE = re.compile(r"\x1b[P^_].*?(?:\x1b\\)", re.DOTALL)
_TERMINAL_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_TERMINAL_SINGLE_ESC_RE = re.compile(r"\x1b[@-Z\\-_]")
_TERMINAL_C0_DISPLAY_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean_terminal_display_text(text: str) -> str:
    text = text.replace("^D\x08\x08", "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _TERMINAL_OSC_RE.sub("", text)
    text = _TERMINAL_STRING_RE.sub("", text)
    text = _TERMINAL_CSI_RE.sub("", text)
    text = _TERMINAL_SINGLE_ESC_RE.sub("", text)
    text = _TERMINAL_C0_DISPLAY_RE.sub("", text)
    return "\n".join(line.rstrip() for line in text.split("\n"))


_HEALTH_PROBE_CACHE_SECONDS = 30.0
_HEALTH_PAYLOAD_CACHE_SECONDS = 5.0
_health_probe_cache_lock = threading.Lock()
_health_probe_cache: dict[str, tuple[float, object]] = {}
_health_payload_cache_lock = threading.Lock()
_health_payload_cache: dict[tuple, tuple[float, dict]] = {}
_runtime_snapshot_cache_lock = threading.Lock()
_runtime_snapshot_cache: dict[tuple, tuple[float, object]] = {}
_runtime_snapshot_key_locks: dict[tuple, threading.Lock] = {}
_auth_result_cache_lock = threading.Lock()
_auth_result_cache: dict[tuple, tuple[float, object]] = {}
_FAST_ADMISSION_SEMAPHORE = threading.BoundedSemaphore(RUNTIME_MAX_ACTIVE_FAST_REQUESTS)
_REQUEST_ADMISSION_SEMAPHORE = threading.BoundedSemaphore(RUNTIME_MAX_ACTIVE_REQUESTS)
_STREAM_ADMISSION_SEMAPHORE = threading.BoundedSemaphore(RUNTIME_MAX_ACTIVE_STREAMS)
_CONNECTION_ADMISSION_SEMAPHORE = threading.BoundedSemaphore(RUNTIME_MAX_ACTIVE_CONNECTIONS)
_STREAM_ENDPOINTS = {
    "/health-stream",
    "/sessions-stream",
    "/session-live-events",
    "/transcript-stream",
    "/terminal-stream",
    "/terminal-surface-stream",
    "/terminal-surface-stream-v2",
    "/session-runtime-truth-stream",
    "/terminal-workspace-stream",
    "/activity-stream",
    "/commands-stream",
    "/invocations-stream",
    "/turn-state-stream",
    "/llm-route-stream",
}
_FAST_ENDPOINTS = {"/health", "/healthz", "/readyz", "/routez", "/power-state", "/manifest"}


class _RuntimeAdmission:
    def __init__(self, semaphore: threading.BoundedSemaphore | None, allowed: bool, reason: str | None = None):
        self._semaphore = semaphore
        self.allowed = allowed
        self.reason = reason
        self._released = False

    def release(self) -> None:
        if self._released or self._semaphore is None:
            return
        try:
            self._semaphore.release()
        except ValueError:
            pass
        self._released = True

PUBLIC_ENDPOINTS = {"/health", "/healthz", "/readyz", "/manifest", "/pair/start", "/pair/claim", "/pair/psk-claim", "/pair/reauth-challenge", "/pair/reauth-claim"}

# Internal hook tier: loopback-only endpoints used by Claude Code hooks to
# write the session registry without device pairing. Gated by client IP AND
# the shared-secret token file the daemon mints at boot — these never count
# toward (or weaken) device Bearer auth.
INTERNAL_LOOPBACK_PATHS = {
    "/internal/session-register",
    "/internal/session-heartbeat",
    "/internal/session-close",
    "/internal/active-sessions",
    "/internal/permission-request",
}
INTERNAL_HOOK_TOKEN_FILE = COMPANION_DIR / "internal-hook-token"


def _ensure_internal_hook_token() -> str:
    """Mint (or read) the loopback hook token. 32-byte hex, mode 600.
    Created at boot so hooks can read it without racing the first request."""
    try:
        existing = INTERNAL_HOOK_TOKEN_FILE.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[0-9a-f]{64}", existing or ""):
            return existing
    except OSError:
        pass
    token = secrets.token_hex(32)
    try:
        INTERNAL_HOOK_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = INTERNAL_HOOK_TOKEN_FILE.with_name(INTERNAL_HOOK_TOKEN_FILE.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(token)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, INTERNAL_HOOK_TOKEN_FILE)
    except OSError:
        return ""
    return token


INTERNAL_HOOK_TOKEN = _ensure_internal_hook_token()


SPAWN_SETTINGS_PATH = COMPANION_DIR / "pairling-spawn-settings.json"


def _ensure_spawn_settings() -> None:
    """Write the per-spawn claude settings overlay (the PermissionRequest producer
    hook) into a Pairling-managed file passed to phone-spawned sessions via
    --settings. This keeps the user's GLOBAL ~/.claude/settings.json UNTOUCHED:
    the hook exists ONLY in sessions Pairling spawns, and the permission posture
    is still inherited from the user's own settings (we add an observer hook,
    never a mode). --settings hooks are auto-trusted (no review gate)."""
    payload = {
        "hooks": {
            "PermissionRequest": [
                {"hooks": [{
                    "type": "command",
                    "command": "node $HOME/.claude/hooks/dist/permission-request.mjs",
                    "timeout": 10,
                }]}
            ]
        }
    }
    try:
        SPAWN_SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = SPAWN_SETTINGS_PATH.with_name(SPAWN_SETTINGS_PATH.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, SPAWN_SETTINGS_PATH)
    except OSError:
        pass


_ensure_spawn_settings()


def _session_backend() -> str:
    """Which store serves claude session reads: 'pg' (Docker Postgres) or
    'sqlite' (daemon-owned agent registry). Rollback at any point is
    PAIRLING_SESSION_BACKEND=pg in the LaunchAgent env + kickstart."""
    backend = os.environ.get("PAIRLING_SESSION_BACKEND", "").strip().lower()
    if backend in ("pg", "sqlite"):
        return backend
    return "sqlite"

# In-process replacement for the PG LISTEN session_ready channel: the
# internal register endpoint sets the per-session event, /turn-state-stream
# waiters block on it instead of an asyncpg connection.
_SESSION_READY_EVENTS: dict[str, threading.Event] = {}
_SESSION_READY_EVENTS_LOCK = threading.Lock()


def _session_ready_event(session_id: str) -> threading.Event:
    with _SESSION_READY_EVENTS_LOCK:
        evt = _SESSION_READY_EVENTS.get(session_id)
        if evt is None:
            evt = threading.Event()
            _SESSION_READY_EVENTS[session_id] = evt
        return evt


def _signal_session_ready(session_id: str) -> None:
    with _SESSION_READY_EVENTS_LOCK:
        evt = _SESSION_READY_EVENTS.get(session_id)
        if evt is not None:
            evt.set()
        # Bound the dict: drop already-signalled events beyond a small cap.
        if len(_SESSION_READY_EVENTS) > 256:
            for key in [k for k, v in _SESSION_READY_EVENTS.items() if v.is_set()][:128]:
                _SESSION_READY_EVENTS.pop(key, None)


def _discard_session_ready_event(session_id: str) -> None:
    with _SESSION_READY_EVENTS_LOCK:
        _SESSION_READY_EVENTS.pop(session_id, None)

POST_ONLY_ENDPOINTS = {
    "/pair/start",
    "/pair/claim",
    "/pair/psk-claim",
    "/pair/reauth-challenge",
    "/pair/reauth-claim",
    "/pair/revoke",
    "/pair/rotate-token",
    "/aperture-cli/open",
    "/open",
    "/inject",
    "/inject-now",
    "/interrupt",
    "/llm-route",
    "/llm-route-stream",
    "/pairling-tools/run",
    "/phone-tools/availability",
    "/phone-tools/next",
    "/phone-tools/result",
    "/worker-kill",
    "/push/preferences",
    "/push/test",
    "/push/live-activity-token",
    "/push/live-activity-test",
    "/sentinel/snooze",
    "/sentinel/evaluate-now",
    "/safety/ack",
    "/safety/request-activation",
    "/safety/open-full-disk-access",
    "/safety/evidence-test",
    "/spawn-session",
    "/mirror/flush",
    "/mirror/resume",
    "/resume-session",
    "/cross-provider-action",
    "/send-text",
    "/terminal-control",
    "/push/permission/allow",
    "/sigint",
    "/sigterm",
    "/upload",
    "/pairdrop/maintenance/cleanup-partials",
    "/pairdrop/uploads",
}

HIGH_RISK_ENDPOINTS = {
    "/aperture-cli/open",
    "/open",
    "/inject",
    "/inject-now",
    "/interrupt",
    "/llm-route",
    "/llm-route-stream",
    "/push/permission/allow",
    "/pairling-tools/run",
    "/worker-kill",
    "/push/preferences",
    "/push/test",
    "/push/live-activity-token",
    "/push/live-activity-test",
    "/sentinel/snooze",
    "/sentinel/evaluate-now",
    "/safety/request-activation",
    "/safety/open-full-disk-access",
    "/safety/evidence-test",
    "/spawn-session",
    "/mirror/flush",
    "/mirror/resume",
    "/resume-session",
    "/cross-provider-action",
    "/send-text",
    "/terminal-control",
    "/sigint",
    "/sigterm",
    "/upload",
    "/pair/revoke",
    "/pair/rotate-token",
    "/pairdrop/files",
    "/pairdrop/maintenance/cleanup-partials",
    "/pairdrop/uploads",
}

PROOF_REQUIRED_ENDPOINTS = HIGH_RISK_ENDPOINTS | {
    "/sentinel/preferences",
    "/safety/ack",
    "/safety/request-activation",
    "/safety/open-full-disk-access",
    "/safety/evidence-test",
    "/phone-tools/availability",
    "/phone-tools/next",
    "/phone-tools/result",
}

MAX_REQUEST_BODY_BYTES = 1_000_000
MAX_UPLOAD_BODY_BYTES = 100 * 1024 * 1024
MAX_PAIRDROP_SMALL_BODY_BYTES = 10 * 1024 * 1024
MAX_PAIRDROP_UPLOAD_CHUNK_BYTES = 1024 * 1024


def _pairdrop_file_id_from_path(path: str) -> str | None:
    prefix = "/pairdrop/files/"
    if not path.startswith(prefix):
        return None
    suffix = path[len(prefix):].strip("/")
    if not suffix or "/" in suffix:
        return None
    return suffix


def _is_pairdrop_file_item_path(path: str) -> bool:
    return _pairdrop_file_id_from_path(path) is not None


def _pairdrop_file_content_id(path: str) -> str | None:
    prefix = "/pairdrop/files/"
    suffix = "/content"
    if not path.startswith(prefix) or not path.endswith(suffix):
        return None
    inner = path[len(prefix):-len(suffix)].strip("/")
    if not inner or "/" in inner:
        return None
    return inner


def _pairdrop_attach_file_id(path: str) -> str | None:
    prefix = "/pairdrop/files/"
    suffix = "/attach"
    if not path.startswith(prefix) or not path.endswith(suffix):
        return None
    inner = path[len(prefix):-len(suffix)].strip("/")
    if not inner or "/" in inner:
        return None
    return inner


def _pairdrop_upload_id_from_path(path: str) -> str | None:
    prefix = "/pairdrop/uploads/"
    if not path.startswith(prefix):
        return None
    suffix = path[len(prefix):].strip("/")
    if not suffix or "/" in suffix:
        return None
    return suffix


def _pairdrop_upload_bytes_id(path: str) -> str | None:
    prefix = "/pairdrop/uploads/"
    suffix = "/bytes"
    if not path.startswith(prefix) or not path.endswith(suffix):
        return None
    inner = path[len(prefix):-len(suffix)].strip("/")
    if not inner or "/" in inner:
        return None
    return inner


def _pairdrop_upload_complete_id(path: str) -> str | None:
    prefix = "/pairdrop/uploads/"
    suffix = "/complete"
    if not path.startswith(prefix) or not path.endswith(suffix):
        return None
    inner = path[len(prefix):-len(suffix)].strip("/")
    if not inner or "/" in inner:
        return None
    return inner


def _is_pairdrop_upload_path(path: str) -> bool:
    return (
        path == "/pairdrop/uploads"
        or _pairdrop_upload_id_from_path(path) is not None
        or _pairdrop_upload_bytes_id(path) is not None
        or _pairdrop_upload_complete_id(path) is not None
    )


def _is_pairdrop_path(path: str) -> bool:
    return path == "/pairdrop/events" or path.startswith("/pairdrop/")


def _pairdrop_gateway_provenance_ok(headers) -> bool:
    getter = headers.get if hasattr(headers, "get") else lambda key, default=None: default
    return str(getter("X-Pairling-Connect-Gateway", "") or "") == "pairling-connectd"


def _is_pairdrop_mutation(path: str, method: str) -> bool:
    method = method.upper()
    return (
        (method == "POST" and path == "/pairdrop/files")
        or (method == "DELETE" and _is_pairdrop_file_item_path(path))
        or (method == "POST" and _pairdrop_attach_file_id(path) is not None)
        or (method == "POST" and path == "/pairdrop/maintenance/cleanup-partials")
        or (method == "POST" and path == "/pairdrop/uploads")
        or (method == "PUT" and _pairdrop_upload_bytes_id(path) is not None)
        or (method == "POST" and _pairdrop_upload_complete_id(path) is not None)
        or (method == "DELETE" and _pairdrop_upload_id_from_path(path) is not None)
    )


def _required_scopes_for_request(path: str, method: str) -> set[str]:
    method = method.upper()
    if path == "/pairdrop/files" and method == "GET":
        return {"files:read"}
    if path == "/pairdrop/files" and method == "POST":
        return {"files:write"}
    if path == "/pairdrop/events" and method == "GET":
        return {"files:read"}
    if _pairdrop_file_content_id(path) is not None and method == "GET":
        return {"files:read"}
    if _is_pairdrop_file_item_path(path) and method == "GET":
        return {"files:read"}
    if _is_pairdrop_file_item_path(path) and method == "DELETE":
        return {"files:delete"}
    if _pairdrop_attach_file_id(path) is not None and method == "POST":
        return {"files:write"}
    if path == "/pairdrop/maintenance/cleanup-partials" and method == "POST":
        return {"files:write"}
    if path == "/pairdrop/uploads" and method == "POST":
        return {"files:write"}
    if _is_pairdrop_upload_path(path):
        return {"files:write"}
    if path in {"/health", "/healthz", "/readyz", "/routez", "/power-state", "/health-stream", "/provider-status", "/status", "/aperture-cli/status", "/aperture-cli/providers", "/aperture-cli/launch-contexts"}:
        return {"health:read"}
    if path == "/manifest":
        return {"manifest:read"}
    if path in {"/sessions", "/sessions-visible", "/sessions-stream", "/recent-projects", "/filesystem/directories", "/session-meta", "/activity", "/activity-stream"}:
        return {"sessions:read"}
    if path in {"/transcript", "/transcript-stream", "/session-live-events", "/terminal-stream", "/terminal-stream-diagnostics", "/terminal-surface", "/terminal-surface-stream", "/terminal-surface-v2", "/terminal-surface-stream-v2", "/session-runtime-truth", "/session-runtime-truth-stream", "/terminal-workspace", "/terminal-workspace-stream", "/corpus"}:
        return {"transcript:read"}
    if path.startswith("/sessions/") and path.endswith("/export"):
        return {"transcript:read"}
    if path in {"/workers", "/worker-stats"}:
        return {"worker:read"}
    if path == "/worker-kill":
        return {"worker:control"}
    if path == "/push/status":
        return {"health:read"}
    if path in {"/push/preferences", "/push/test", "/push/live-activity-token", "/push/live-activity-test"}:
        return {"pair:admin"}
    if path == "/push/permission/allow":
        return {"session:signal"}
    if path == "/sentinel/preferences" and method == "POST":
        return {"pair:admin"}
    if path in {"/sentinel/status", "/sentinel/preferences", "/sentinel/events"}:
        return {"worker:read"}
    if path in {"/sentinel/snooze", "/sentinel/evaluate-now"}:
        return {"pair:admin"}
    if path in {"/safety/status", "/safety/events", "/safety/ack"}:
        return {"health:read"}
    if path in {"/safety/request-activation", "/safety/open-full-disk-access", "/safety/evidence-test"}:
        return {"pair:admin"}
    if path == "/aperture-cli/open":
        return {"pair:admin"}
    if path in {"/inject", "/inject-now", "/send-text", "/terminal-control"}:
        return {"session:send"}
    if path in {"/interrupt", "/sigint", "/sigterm"}:
        return {"session:signal"}
    if path in {"/spawn-session", "/resume-session", "/cross-provider-action"}:
        return {"session:spawn"}
    if path == "/onestream-handoff":
        return {"session:spawn"} if method == "POST" else {"sessions:read"}
    if path in {"/llm-route", "/llm-route-stream"}:
        return {"llm:route"}
    if path == "/pairling-tools/run":
        return {"pairling-tools:run"}
    if path in {"/phone-tools/availability", "/phone-tools/next", "/phone-tools/result"}:
        return {"phone-tools:reverse"}
    if path == "/upload":
        return {"files:upload"}
    if path.startswith("/pair/") or path.startswith("/pickers/") or path.startswith("/mirror/"):
        return {"pair:admin"}
    if path in {"/commands", "/commands-stream", "/invocations", "/invocations-stream", "/personal-context", "/tokens"}:
        return {"manifest:read"}
    if path == ORCHESTRATIONS_ROUTE or path.startswith(f"{ORCHESTRATIONS_ROUTE}/"):
        return {"session:spawn" if method == "POST" else "sessions:read"}
    if path.startswith("/workstate") or path.startswith("/model-status") or path.startswith("/substrate"):
        return {"sessions:read"}
    return {"sessions:read"} if method == "GET" else {"pair:admin"}


def _bearer_token(headers) -> str | None:
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        return token or None
    return None


def _auth_cache_key(token: str, *, method: str, path: str, required_scopes: set[str]) -> tuple | None:
    if AUTH_RESULT_CACHE_SECONDS <= 0:
        return None
    if method.upper() not in {"GET", "HEAD"}:
        return None
    if _requires_request_proof(path, method):
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return (token_hash, method.upper(), path, tuple(sorted(required_scopes)))


def _authenticate_device(token: str, *, required_scopes: set[str], path: str, method: str):
    if DEVICE_REGISTRY is None:
        return None
    cache_key = _auth_cache_key(token, method=method, path=path, required_scopes=required_scopes)
    now = _time.time()
    if cache_key is not None:
        with _auth_result_cache_lock:
            cached = _auth_result_cache.get(cache_key)
            if cached is not None and now - cached[0] < AUTH_RESULT_CACHE_SECONDS:
                return cached[1]

    auth_result = DEVICE_REGISTRY.authenticate(
        token,
        required_scopes=required_scopes,
        path=path,
    )
    if cache_key is not None and getattr(auth_result, "ok", False):
        with _auth_result_cache_lock:
            _auth_result_cache[cache_key] = (now, auth_result)
            if len(_auth_result_cache) > AUTH_RESULT_CACHE_MAX:
                for old_key in list(_auth_result_cache.keys())[: max(1, AUTH_RESULT_CACHE_MAX // 4)]:
                    _auth_result_cache.pop(old_key, None)
    return auth_result


def _path_and_query(parsed) -> str:
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


def _requires_request_proof(path: str, method: str) -> bool:
    if method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return False
    return (
        _is_pairdrop_mutation(path, method)
        or path in PROOF_REQUIRED_ENDPOINTS
        or path.startswith("/pickers/")
        or path == ORCHESTRATIONS_ROUTE
        or path.startswith(f"{ORCHESTRATIONS_ROUTE}/")
    )


def _is_high_risk_endpoint(path: str) -> bool:
    return (
        path in HIGH_RISK_ENDPOINTS
        or _is_pairdrop_mutation(path, "POST")
        or _is_pairdrop_upload_path(path)
        or _is_pairdrop_mutation(path, "DELETE")
        or path == ORCHESTRATIONS_ROUTE
        or path.startswith(f"{ORCHESTRATIONS_ROUTE}/")
    )


def _rate_limit_for_high_risk_endpoint(path: str) -> int:
    if path == "/pairling-tools/run":
        return 30
    if path == ORCHESTRATIONS_ROUTE or path.startswith(f"{ORCHESTRATIONS_ROUTE}/"):
        return 30
    return 120


def _parse_single_byte_range(raw: str, total: int) -> tuple[int, int, bool]:
    if not raw:
        return 0, max(total - 1, 0), False
    match = re.fullmatch(r"bytes=(\d*)-(\d*)", raw)
    if not match:
        raise PairDropStoreError("bad_range")
    first, last = match.group(1), match.group(2)
    if first == "" and last == "":
        raise PairDropStoreError("bad_range")
    if first == "":
        suffix_len = int(last)
        if suffix_len <= 0:
            raise PairDropStoreError("range_not_satisfiable")
        start = max(total - suffix_len, 0)
        end = total - 1
    else:
        start = int(first)
        end = int(last) if last else total - 1
    if total <= 0 or start >= total or end < start:
        raise PairDropStoreError("range_not_satisfiable")
    end = min(end, total - 1)
    return start, end, True


def _pairdrop_attachment_filename(raw: str) -> str:
    base = os.path.basename(str(raw or "").strip())
    safe = re.sub(r"[^A-Za-z0-9_. -]", "_", base).strip(" ._")
    if not safe:
        return "pairdrop-file"
    return safe[:120].replace("\\", "_").replace('"', "_")


def _pairdrop_safe_content_type(raw: str) -> str:
    value = str(raw or "").strip()
    if re.fullmatch(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+", value):
        return value
    return "application/octet-stream"


def _request_rate_check(key: str, max_per_min: int = 120) -> tuple[bool, int]:
    now = _time.time()
    window_start = now - 60
    with _request_rate_lock:
        timestamps = [t for t in _request_rate_state.get(key, []) if t >= window_start]
        if len(timestamps) >= max_per_min:
            oldest = min(timestamps)
            _request_rate_state[key] = timestamps
            return False, max(1, int(60 - (now - oldest)))
        timestamps.append(now)
        _request_rate_state[key] = timestamps
    return True, 0


def _runtime_info_snapshot() -> dict:
    if _build_runtime_info is not None:
        try:
            return _build_runtime_info(__file__, launchd_label=RUNTIME_DAEMON_LABEL)
        except Exception as exc:
            return {
                "name": RUNTIME_NAME,
                "runtime_version": "legacy",
                "contract_version": RUNTIME_CONTRACT_VERSION,
                "source_revision": "unknown",
                "installed_at": None,
                "install_root": str(Path(__file__).resolve().parent),
                "compat_mode": "pairling-v1",
                "launchd_label": RUNTIME_DAEMON_LABEL,
                "port": PORT,
                "tailscale_variant": "standalone",
                "verified": False,
                "manifest_path": None,
                "manifest_error": f"{type(exc).__name__}: {exc}",
            }
    return {
        "name": RUNTIME_NAME,
        "runtime_version": os.environ.get("COMPANION_RUNTIME_VERSION", "legacy"),
        "contract_version": RUNTIME_CONTRACT_VERSION,
        "source_revision": os.environ.get("COMPANION_SOURCE_REVISION", "unknown"),
        "installed_at": os.environ.get("COMPANION_INSTALLED_AT"),
        "install_root": str(Path(__file__).resolve().parent),
        "compat_mode": "pairling-v1",
        "launchd_label": RUNTIME_DAEMON_LABEL,
        "port": PORT,
        "tailscale_variant": "standalone",
        "verified": False,
        "manifest_path": None,
        "manifest_error": "runtime manifest helpers unavailable",
    }


def _sessions_stream_source() -> dict:
    runtime_info = _runtime_info_snapshot()
    install_id = getattr(PAIRING_STORE, "install_id", "") if PAIRING_STORE else ""
    return {
        "schema_version": 1,
        "install_id": str(install_id or ""),
        "runtime_port": PORT,
        "runtime_version": runtime_info.get("runtime_version"),
        "contract_version": runtime_info.get("contract_version") or RUNTIME_CONTRACT_VERSION,
    }


_AGENT_REGISTRY_SCHEMA_LOCK = threading.Lock()
_AGENT_REGISTRY_SCHEMA_READY = False


def _agent_registry_bootstrap_schema(conn) -> None:
    """Idempotent schema bootstrap + extension migration.

    Runs the column/index migration once per daemon process (guarded by
    _AGENT_REGISTRY_SCHEMA_READY); the base CREATE TABLE/INDEX statements are
    cheap no-ops and run on every connection like they always have.
    """
    global _AGENT_REGISTRY_SCHEMA_READY
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS agent_sessions (
            provider TEXT NOT NULL,
            native_id TEXT NOT NULL,
            project TEXT NOT NULL,
            pid INTEGER,
            terminal_tty TEXT,
            state TEXT NOT NULL DEFAULT 'running',
            started_at REAL NOT NULL,
            last_heartbeat REAL NOT NULL,
            closed_at REAL,
            metadata_json TEXT,
            PRIMARY KEY (provider, native_id)
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_agent_sessions_provider_live "
        "ON agent_sessions(provider, closed_at, last_heartbeat)"
    )
    # Per-tool approval queue (Lock-Screen "Permission request" card, Phase 2).
    # Same daemon-owned DB. NO deadline/expiry columns by design: an unanswered
    # prompt hangs at its native dialog forever until the user acts (Allow
    # keystroke / in-app). Rows are recorded by the PermissionRequest hook via
    # POST /internal/permission-request and resolved by the Allow path (Phase 3).
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pending_approvals (
            request_nonce   TEXT PRIMARY KEY,
            provider        TEXT NOT NULL,
            session_id      TEXT NOT NULL,
            native_id       TEXT,
            broker_id       TEXT,
            terminal_tty    TEXT,
            tool_name       TEXT NOT NULL,
            tool_input_json TEXT NOT NULL,
            command_preview TEXT,
            permission_mode TEXT,
            state           TEXT NOT NULL DEFAULT 'pending',
            created_at      REAL NOT NULL,
            resolved_at     REAL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pending_approvals_session "
        "ON pending_approvals(session_id, state)"
    )
    if _AGENT_REGISTRY_SCHEMA_READY:
        return
    with _AGENT_REGISTRY_SCHEMA_LOCK:
        if _AGENT_REGISTRY_SCHEMA_READY:
            return
        existing = {
            row[1] for row in conn.execute("PRAGMA table_info(agent_sessions)").fetchall()
        }
        if "claude_uuid" not in existing:
            conn.execute("ALTER TABLE agent_sessions ADD COLUMN claude_uuid TEXT")
        if "working_on" not in existing:
            conn.execute("ALTER TABLE agent_sessions ADD COLUMN working_on TEXT")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_sessions_claude_uuid "
            "ON agent_sessions(provider, claude_uuid)"
        )
        _AGENT_REGISTRY_SCHEMA_READY = True


@contextmanager
def _agent_registry_conn():
    conn = sqlite3.connect(str(AGENT_REGISTRY_DB))
    try:
        conn.row_factory = sqlite3.Row
        # WAL + busy_timeout are mandatory before claude-volume writes land
        # here: hooks POST register/heartbeat from many processes while the
        # daemon reads, and the default rollback journal serializes hard.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=3000")
        conn.execute("PRAGMA synchronous=NORMAL")
        _agent_registry_bootstrap_schema(conn)
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _approval_command_preview(tool_name: str, tool_input: dict) -> str:
    """Render the one-line card text from a tool call's structured input."""
    try:
        if tool_name == "Bash":
            return str(tool_input.get("command") or "").strip()[:300]
        if tool_name in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
            fp = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "").strip()
            base = os.path.basename(fp) if fp else ""
            return f"{tool_name} {base}".strip()[:300]
        if tool_name == "WebFetch":
            url = str(tool_input.get("url") or "").strip()
            try:
                host = urlparse(url).netloc or url
            except Exception:
                host = url
            return f"Fetch {host}".strip()[:300]
        return tool_name[:300]
    except Exception:
        return tool_name[:300]


def _approval_resolve_session(provider: str, session_id: str) -> tuple[str, str, str]:
    """Best-effort map a hook's session_id -> (native_id, broker_id, terminal_tty)
    from the agent_sessions registry. For claude the hook session_id is the
    claude_uuid; for codex it is the registry native_id. Empties on miss — the
    Phase 3 Allow path re-resolves against the live broker before answering."""
    try:
        with _agent_registry_conn() as conn:
            if provider == "claude":
                row = conn.execute(
                    "SELECT native_id, terminal_tty FROM agent_sessions "
                    "WHERE provider='claude' AND claude_uuid=? AND closed_at IS NULL "
                    "ORDER BY last_heartbeat DESC LIMIT 1",
                    (session_id,),
                ).fetchone()
            else:
                lookup_native = session_id
                parsed_provider, parsed_native = _parse_agent_session_ref(session_id)
                if parsed_provider == provider and parsed_native:
                    lookup_native = parsed_native
                row = conn.execute(
                    "SELECT native_id, terminal_tty FROM agent_sessions "
                    "WHERE provider=? AND native_id=? AND closed_at IS NULL "
                    "ORDER BY last_heartbeat DESC LIMIT 1",
                    (provider, lookup_native),
                ).fetchone()
            if not row:
                return ("", "", "")
            native_id = str(row["native_id"] or "")
            broker_id = _qualified_session_id(provider, native_id) if native_id else ""
            return (native_id, broker_id, str(row["terminal_tty"] or ""))
    except Exception:
        return ("", "", "")


def _pending_approval_record(*, request_nonce: str, provider: str, session_id: str,
                             tool_name: str, tool_input: dict, command_preview: str = "",
                             permission_mode: str = "", broker_id: str = "",
                             state: str = "pending") -> bool:
    """Idempotently record a pending tool approval (INSERT OR IGNORE on the
    hook-minted request_nonce). No deadline/expiry — by design. broker_id, when
    supplied by the hook (from the broker's PAIRLING_BROKER_SESSION_ID env), is the
    AUTHORITATIVE live broker session id — far more reliable than registry
    reconciliation, since the SessionStart tty capture fails for broker PTYs (the
    claude_uuid and the broker tty land on two unlinked rows)."""
    now = _time.time()
    native_id, resolved_broker, terminal_tty = _approval_resolve_session(provider, session_id)
    if not broker_id:
        broker_id = resolved_broker
    row_state = state if state in {"pending", "attention"} else "pending"
    try:
        with _agent_registry_conn() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO pending_approvals
                    (request_nonce, provider, session_id, native_id, broker_id,
                     terminal_tty, tool_name, tool_input_json, command_preview,
                     permission_mode, state, created_at, resolved_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (request_nonce, provider, session_id, native_id, broker_id,
                 terminal_tty, tool_name, json.dumps(tool_input)[:8000],
                 (command_preview or "")[:300], permission_mode, row_state, now),
            )
        return True
    except Exception:
        return False


def _pending_approval_get(request_nonce: str) -> dict | None:
    try:
        with _agent_registry_conn() as conn:
            row = conn.execute(
                "SELECT * FROM pending_approvals WHERE request_nonce=?",
                (request_nonce,),
            ).fetchone()
            return dict(row) if row else None
    except Exception:
        return None


def _pending_approval_cas(request_nonce: str, expected: str, new: str) -> bool:
    """Compare-and-set the approval state. Returns True iff THIS call performed the
    transition — so a duplicate Allow (state already != expected) is a safe no-op."""
    try:
        with _agent_registry_conn() as conn:
            cur = conn.execute(
                "UPDATE pending_approvals SET state=?, resolved_at=? "
                "WHERE request_nonce=? AND state=?",
                (new, _time.time(), request_nonce, expected),
            )
            return cur.rowcount > 0
    except Exception:
        return False


def _pending_approvals_open() -> list[dict]:
    try:
        with _agent_registry_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM pending_approvals WHERE state IN ('pending', 'attention') "
                "ORDER BY created_at ASC LIMIT 500"
            ).fetchall()
            return [dict(row) for row in rows]
    except Exception:
        return []


def _pending_approval_resolve_terminal(request_nonce: str, new_state: str) -> bool:
    if new_state not in {"session_gone", "expired_session"}:
        return False
    try:
        with _agent_registry_conn() as conn:
            cur = conn.execute(
                "UPDATE pending_approvals SET state=?, resolved_at=? "
                "WHERE request_nonce=? AND state IN ('pending', 'attention')",
                (new_state, _time.time(), request_nonce),
            )
            return cur.rowcount > 0
    except Exception:
        return False


def _pretrust_claude_project(project: str) -> None:
    """Mark `project` trusted in ~/.claude.json before a headless claude spawn.

    Broker-owned PTYs have no human at the keyboard, so Claude Code's
    folder-trust prompt ("Is this a project you created or one you trust?")
    hangs the spawned session forever — the REPL never starts, hooks never
    fire, and the phone reports "spawned, but no heartbeat". The phone user
    explicitly chose this project for the spawn — that is the trust
    gesture — and the spawn handler has already validated the path is under
    $HOME or /tmp. Read-modify-write is atomic (tmp + fsync + os.replace)
    and preserves every other key in the file.
    """
    path = HOME / ".claude.json"
    try:
        if path.exists():
            with open(path, "r") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return
        else:
            data = {}
        projects = data.get("projects")
        if not isinstance(projects, dict):
            projects = {}
            data["projects"] = projects
        # Claude Code canonicalizes the cwd before the trust lookup
        # (e.g. /tmp/x -> /private/tmp/x on macOS), so trust both the
        # literal path and its resolved form.
        candidates = {project}
        try:
            candidates.add(os.path.realpath(project))
        except OSError:
            pass
        changed = False
        for key in candidates:
            entry = projects.get(key)
            if not isinstance(entry, dict):
                entry = {}
                projects[key] = entry
            if entry.get("hasTrustDialogAccepted") is not True:
                entry["hasTrustDialogAccepted"] = True
                changed = True
        if not changed:
            return
        tmp_path = path.with_name(path.name + ".pairling-tmp")
        with open(tmp_path, "w") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except (OSError, ValueError, json.JSONDecodeError):
        return


def _agent_registry_upsert(provider: str, native_id: str, project: str, *,
                           pid: int = 0, terminal_tty: str = "",
                           state: str = "running", metadata: dict | None = None,
                           claude_uuid: str = "", working_on: str = "") -> bool:
    # Conflict semantics mirror the PG sessions upsert exactly:
    # re-register reopens (closed_at = NULL), working_on is always replaced,
    # claude_uuid/tty/pid COALESCE so an empty re-register never blanks them,
    # started_at is preserved from the original insert.
    now = _time.time()
    try:
        with _agent_registry_conn() as conn:
            conn.execute(
                """
                INSERT INTO agent_sessions
                    (provider, native_id, project, pid, terminal_tty, state,
                     started_at, last_heartbeat, closed_at, metadata_json,
                     claude_uuid, working_on)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
                ON CONFLICT(provider, native_id) DO UPDATE SET
                    project = excluded.project,
                    pid = COALESCE(NULLIF(excluded.pid, 0), agent_sessions.pid),
                    terminal_tty = COALESCE(NULLIF(excluded.terminal_tty, ''), agent_sessions.terminal_tty),
                    state = excluded.state,
                    last_heartbeat = excluded.last_heartbeat,
                    closed_at = NULL,
                    metadata_json = excluded.metadata_json,
                    claude_uuid = COALESCE(NULLIF(excluded.claude_uuid, ''), agent_sessions.claude_uuid),
                    working_on = excluded.working_on
                """,
                (
                    provider,
                    native_id,
                    project,
                    int(pid or 0),
                    terminal_tty or "",
                    state,
                    now,
                    now,
                    json.dumps(metadata or {}, sort_keys=True),
                    claude_uuid or "",
                    working_on or "",
                ),
            )
        return True
    except Exception:
        return False


def _agent_registry_get(provider: str, native_id: str) -> dict | None:
    try:
        with _agent_registry_conn() as conn:
            row = conn.execute(
                "SELECT * FROM agent_sessions WHERE provider = ? AND native_id = ? LIMIT 1",
                (provider, native_id),
            ).fetchone()
            return dict(row) if row else None
    except Exception:
        return None


def _agent_registry_get_by_tty(provider: str, terminal_tty: str) -> dict | None:
    if not terminal_tty:
        return None
    try:
        with _agent_registry_conn() as conn:
            row = conn.execute(
                "SELECT * FROM agent_sessions WHERE provider = ? AND terminal_tty = ? "
                "ORDER BY last_heartbeat DESC LIMIT 1",
                (provider, terminal_tty),
            ).fetchone()
            return dict(row) if row else None
    except Exception:
        return None


def _agent_registry_get_by_claude_uuid(provider: str, claude_uuid: str) -> dict | None:
    """Most-recent row for a claude_uuid. Two s-ids may transiently share a
    uuid (CLAUDE.md §6) — ORDER BY last_heartbeat DESC resolves the collision
    the same way the PG lookup does today."""
    if not claude_uuid:
        return None
    try:
        with _agent_registry_conn() as conn:
            row = conn.execute(
                "SELECT * FROM agent_sessions WHERE provider = ? AND claude_uuid = ? "
                "ORDER BY last_heartbeat DESC LIMIT 1",
                (provider, claude_uuid),
            ).fetchone()
            return dict(row) if row else None
    except Exception:
        return None


def _agent_registry_heartbeat_by_claude_uuid(provider: str, claude_uuid: str, *,
                                             terminal_tty: str = "", pid: int = 0) -> bool:
    """Heartbeat keyed on claude_uuid, mirroring the PG hook UPDATE:
    last_heartbeat advances; tty/pid only backfill when currently missing
    (existing value wins — opposite precedence from register's upsert).
    Returns False when no row matched, preserving UPDATE-no-op semantics."""
    if not claude_uuid:
        return False
    try:
        with _agent_registry_conn() as conn:
            cur = conn.execute(
                "UPDATE agent_sessions SET last_heartbeat = ?, "
                "terminal_tty = COALESCE(NULLIF(terminal_tty, ''), NULLIF(?, ''), ''), "
                "pid = COALESCE(NULLIF(pid, 0), NULLIF(?, 0), 0) "
                "WHERE provider = ? AND claude_uuid = ?",
                (_time.time(), terminal_tty or "", int(pid or 0), provider, claude_uuid),
            )
            return cur.rowcount > 0
    except Exception:
        return False


def _agent_registry_mark_closed_by_claude_uuid(provider: str, claude_uuid: str) -> bool:
    """Tombstone keyed on claude_uuid (SessionEnd hook path). Idempotent —
    only rows without an existing closed_at are touched, like the PG
    `AND closed_at IS NULL` clause."""
    if not claude_uuid:
        return False
    try:
        with _agent_registry_conn() as conn:
            cur = conn.execute(
                "UPDATE agent_sessions SET closed_at = ?, state = 'terminated' "
                "WHERE provider = ? AND claude_uuid = ? AND closed_at IS NULL",
                (_time.time(), provider, claude_uuid),
            )
            return cur.rowcount > 0
    except Exception:
        return False


def _registry_metadata_from_row(row: dict | None) -> dict:
    if not row:
        return {}
    try:
        obj = json.loads(row.get("metadata_json") or "{}")
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _session_launch_context_from_metadata(metadata: dict | None) -> dict | None:
    if not isinstance(metadata, dict):
        return None
    strategy = str(metadata.get("launch_strategy") or "").strip()
    if strategy == "aperture_cli":
        redacted_env = metadata.get("generated_env_redacted")
        if not isinstance(redacted_env, dict):
            redacted_env = {}
        config_writes = metadata.get("config_writes")
        if not isinstance(config_writes, list):
            config_writes = []
        return {
            "strategy": "aperture_cli",
            "summary": "Launched through Aperture CLI",
            "client_id": metadata.get("client_id"),
            "endpoint_url": metadata.get("aperture_endpoint_url"),
            "endpoint_mode": metadata.get("aperture_endpoint_mode"),
            "aperture_provider_id": metadata.get("aperture_provider_id"),
            "backend_id": metadata.get("aperture_backend_id"),
            "model": metadata.get("aperture_model"),
            "danger_mode": bool(metadata.get("danger_mode")),
            "generated_config_home": redacted_env.get("CODEX_HOME"),
            "config_writes": [str(item) for item in config_writes if item],
            "aperture_cli_version": metadata.get("aperture_cli_version"),
        }
    if strategy == "direct_pairling":
        return {
            "strategy": "direct_pairling",
            "summary": "Launched directly by Pairling",
            "danger_mode": bool(metadata.get("danger_mode")),
        }
    return None


def _append_launch_frontmatter(front: list[str], launch_context: dict | None) -> None:
    if not isinstance(launch_context, dict):
        return
    strategy = str(launch_context.get("strategy") or "").strip()
    if not strategy:
        return
    front.append(f"launch_strategy: {strategy}")
    if strategy != "aperture_cli":
        return
    for key, value in [
        ("aperture_endpoint", launch_context.get("endpoint_url")),
        ("aperture_provider", launch_context.get("aperture_provider_id")),
        ("aperture_backend", launch_context.get("backend_id")),
        ("model", launch_context.get("model")),
        ("danger_mode", "true" if launch_context.get("danger_mode") is True else "false"),
    ]:
        if value is None:
            continue
        text = str(value).replace("\n", " ").strip()
        if text:
            front.append(f"{key}: {text}")


def _apply_launch_context_to_session_row(row: dict, metadata: dict | None) -> dict:
    launch_context = _session_launch_context_from_metadata(metadata)
    if launch_context is None:
        return row
    row["launch_context"] = launch_context
    if launch_context.get("strategy") == "aperture_cli" and launch_context.get("model") and not row.get("model"):
        row["model"] = launch_context.get("model")
    return row


def _agent_registry_live(provider: str) -> list[dict]:
    try:
        with _agent_registry_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM agent_sessions "
                "WHERE provider = ? AND closed_at IS NULL "
                "ORDER BY last_heartbeat DESC LIMIT 100",
                (provider,),
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


def _agent_registry_recent(provider: str, since_min: int = 60 * 24, limit: int = 300) -> list[dict]:
    cutoff = _time.time() - max(1, int(since_min or 1)) * 60
    limit = max(1, min(int(limit or 300), 1000))
    try:
        with _agent_registry_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM agent_sessions "
                "WHERE provider = ? AND last_heartbeat >= ? "
                "ORDER BY last_heartbeat DESC LIMIT ?",
                (provider, cutoff, limit),
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


def _codex_spawn_pending_registry_rows(project: str, observed_started_at: float) -> list[dict]:
    observed_started_at = float(observed_started_at or 0)
    return [
        row for row in _agent_registry_live("codex")
        if row.get("native_id", "").startswith("pending-")
        and row.get("project") == project
        and (
            observed_started_at <= 0
            or float(row.get("started_at") or 0) - 5 <= observed_started_at <= float(row.get("started_at") or 0) + 300
        )
    ]


def _agent_registry_mark_closed(provider: str, native_id: str) -> None:
    try:
        with _agent_registry_conn() as conn:
            conn.execute(
                "UPDATE agent_sessions SET closed_at = ?, state = 'terminated' "
                "WHERE provider = ? AND native_id = ? AND closed_at IS NULL",
                (_time.time(), provider, native_id),
            )
    except Exception:
        pass


def _agent_registry_update_control(provider: str, native_id: str, *,
                                   pid: int | None = None,
                                   terminal_tty: str | None = None,
                                   state: str | None = None,
                                   claude_uuid: str | None = None,
                                   working_on: str | None = None,
                                   reopen: bool = False) -> None:
    assignments = ["last_heartbeat = ?"]
    params: list[object] = [_time.time()]
    if pid is not None:
        assignments.append("pid = ?")
        params.append(int(pid or 0))
    if terminal_tty is not None:
        assignments.append("terminal_tty = ?")
        params.append(terminal_tty)
    if state is not None:
        assignments.append("state = ?")
        params.append(state)
    if claude_uuid is not None:
        assignments.append("claude_uuid = ?")
        params.append(claude_uuid)
    if working_on is not None:
        assignments.append("working_on = ?")
        params.append(working_on)
    if reopen:
        assignments.append("closed_at = NULL")
    params.extend([provider, native_id])
    try:
        with _agent_registry_conn() as conn:
            conn.execute(
                f"UPDATE agent_sessions SET {', '.join(assignments)} "
                "WHERE provider = ? AND native_id = ?",
                tuple(params),
            )
    except Exception:
        pass


def _agent_registry_promote_codex(native_id: str, project: str, observed_started_at: float) -> dict | None:
    exact = _agent_registry_get("codex", native_id)
    observed_started_at = float(observed_started_at or 0)
    if observed_started_at <= 0:
        return exact
    if exact:
        pid = int(exact.get("pid") or 0)
        tty = exact.get("terminal_tty") or ""
        if not exact.get("closed_at") and (pid and _process_alive(pid) or tty and _pid_for_tty_command(tty, "codex")):
            for row in _codex_spawn_pending_registry_rows(project, observed_started_at):
                _agent_registry_mark_closed("codex", row["native_id"])
            return exact
        discovered = _codex_discover_terminal_control(project, observed_started_at)
        if discovered:
            _agent_registry_upsert(
                "codex",
                native_id,
                project,
                pid=int(discovered.get("pid") or 0),
                terminal_tty=discovered.get("tty") or "",
                metadata={"discovered_by": "terminal_scan"},
            )
            for row in _codex_spawn_pending_registry_rows(project, observed_started_at):
                _agent_registry_mark_closed("codex", row["native_id"])
            return _agent_registry_get("codex", native_id) or exact
        return exact
    discovered = _codex_discover_terminal_control(project, observed_started_at)
    if discovered:
        _agent_registry_upsert(
            "codex",
            native_id,
            project,
            pid=int(discovered.get("pid") or 0),
            terminal_tty=discovered.get("tty") or "",
            metadata={"discovered_by": "terminal_scan"},
        )
        return _agent_registry_get("codex", native_id)
    pending = _codex_spawn_pending_registry_rows(project, observed_started_at)
    if not pending:
        return None
    row = sorted(pending, key=lambda r: r.get("started_at") or 0, reverse=True)[0]
    try:
        with _agent_registry_conn() as conn:
            conn.execute(
                "UPDATE agent_sessions SET native_id = ?, last_heartbeat = ? "
                "WHERE provider = 'codex' AND native_id = ?",
                (native_id, _time.time(), row["native_id"]),
            )
        row["native_id"] = native_id
        row["last_heartbeat"] = _time.time()
        return row
    except sqlite3.IntegrityError:
        _agent_registry_mark_closed("codex", row["native_id"])
        return _agent_registry_get("codex", native_id)
    except Exception:
        return None


def _process_alive(pid: int) -> bool:
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


def _record_sessions_scan(rows: list[dict]) -> None:
    with _sessions_health_lock:
        _sessions_health["last_scan_at"] = _time.time()
        _sessions_health["last_snapshot_count"] = len(rows)


def _sessions_health_snapshot() -> dict:
    with _sessions_health_lock:
        return dict(_sessions_health)


def _copy_cache_value(value):
    return copy.deepcopy(value)


def _runtime_admission_for_path(path: str) -> _RuntimeAdmission:
    if path in _FAST_ENDPOINTS:
        if _FAST_ADMISSION_SEMAPHORE.acquire(blocking=False):
            return _RuntimeAdmission(_FAST_ADMISSION_SEMAPHORE, True)
        return _RuntimeAdmission(None, False, "fast_capacity_exceeded")
    if path in _STREAM_ENDPOINTS:
        if _STREAM_ADMISSION_SEMAPHORE.acquire(blocking=False):
            return _RuntimeAdmission(_STREAM_ADMISSION_SEMAPHORE, True)
        return _RuntimeAdmission(None, False, "stream_capacity_exceeded")
    if _REQUEST_ADMISSION_SEMAPHORE.acquire(blocking=False):
        return _RuntimeAdmission(_REQUEST_ADMISSION_SEMAPHORE, True)
    return _RuntimeAdmission(None, False, "request_capacity_exceeded")


def _cached_runtime_snapshot(key: tuple, ttl_seconds: float, loader):
    now = _time.time()
    with _runtime_snapshot_cache_lock:
        cached = _runtime_snapshot_cache.get(key)
        if cached is not None and now - cached[0] < ttl_seconds:
            return _copy_cache_value(cached[1])
        key_lock = _runtime_snapshot_key_locks.get(key)
        if key_lock is None:
            key_lock = threading.Lock()
            _runtime_snapshot_key_locks[key] = key_lock
    with key_lock:
        now = _time.time()
        with _runtime_snapshot_cache_lock:
            cached = _runtime_snapshot_cache.get(key)
            if cached is not None and now - cached[0] < ttl_seconds:
                return _copy_cache_value(cached[1])
        value = loader()
        with _runtime_snapshot_cache_lock:
            _runtime_snapshot_cache[key] = (now, _copy_cache_value(value))
            if len(_runtime_snapshot_cache) > 256:
                for old_key in list(_runtime_snapshot_cache.keys())[:64]:
                    _runtime_snapshot_cache.pop(old_key, None)
                    _runtime_snapshot_key_locks.pop(old_key, None)
        return _copy_cache_value(value)


def _clear_runtime_load_caches_for_tests() -> None:
    with _runtime_snapshot_cache_lock:
        _runtime_snapshot_cache.clear()
        _runtime_snapshot_key_locks.clear()
    with _auth_result_cache_lock:
        _auth_result_cache.clear()
    _SESSION_TRANSCRIPT_STATS_CACHE.clear()
    _codex_rollout_paths_cache["ts"] = 0.0
    _codex_rollout_paths_cache["paths"] = []


def _cached_probe(key: str, ttl_seconds: float, loader):
    now = _time.time()
    with _health_probe_cache_lock:
        cached = _health_probe_cache.get(key)
        if cached is not None and now - cached[0] < ttl_seconds:
            return _copy_cache_value(cached[1])
    value = loader()
    with _health_probe_cache_lock:
        _health_probe_cache[key] = (now, _copy_cache_value(value))
    return _copy_cache_value(value)


def _clear_health_probe_caches_for_tests() -> None:
    with _health_probe_cache_lock:
        _health_probe_cache.clear()
    with _health_payload_cache_lock:
        _health_payload_cache.clear()


def _run_text(cmd: list[str], timeout: float = 3.0) -> tuple[bool, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode == 0, proc.stdout or "", proc.stderr or ""
    except Exception as exc:
        return False, "", f"{type(exc).__name__}: {exc}"


def _process_parent_pid(pid: int) -> int:
    if not pid:
        return 0
    ok, out, _ = _run_text(["/bin/ps", "-o", "ppid=", "-p", str(int(pid))], timeout=2)
    if not ok:
        return 0
    try:
        return int((out.strip().splitlines() or ["0"])[0].strip() or "0")
    except ValueError:
        return 0


def _process_tty(pid: int) -> str:
    if not pid:
        return ""
    ok, out, _ = _run_text(["/bin/ps", "-o", "tty=", "-p", str(int(pid))], timeout=2)
    if not ok:
        return ""
    tty = (out.strip().splitlines() or [""])[0].strip()
    if not tty or tty == "??":
        return ""
    return tty if tty.startswith("/dev/") else f"/dev/{tty}"


def _process_command(pid: int) -> str:
    if not pid:
        return ""
    ok, out, _ = _run_text(["/bin/ps", "-o", "command=", "-p", str(int(pid))], timeout=2)
    if not ok:
        return ""
    return (out.strip().splitlines() or [""])[0].strip()


def _codex_terminal_tty_candidates(reg: dict | None) -> list[str]:
    if not reg:
        return []
    candidates: list[str] = []

    def add(tty: str | None) -> None:
        if tty and re.match(r"^/dev/ttys[0-9]{3,}$", tty) and tty not in candidates:
            candidates.append(tty)

    project = reg.get("project") or ""
    original_tty = reg.get("terminal_tty") or ""
    pid = int(reg.get("pid") or 0)
    chain: list[tuple[int, str, str]] = []
    seen: set[int] = set()
    current = pid
    for _ in range(6):
        if not current or current in seen:
            break
        seen.add(current)
        chain.append((current, _process_tty(current), _process_command(current)))
        current = _process_parent_pid(current)

    # Phone-spawned Codex runs under /usr/bin/script. The real Codex child owns
    # a pseudo-tty, but Terminal.app only exposes the parent script tab tty.
    for _, tty, command in chain:
        if "/usr/bin/script" in command:
            add(tty)

    for row in _agent_registry_live("codex"):
        if row.get("native_id", "").startswith("pending-") and row.get("project") == project:
            add(row.get("terminal_tty") or "")

    for _, tty, _ in chain:
        add(tty)
    add(original_tty)
    return candidates


def _guardian_tailnet_ip(power_state: dict | None) -> str | None:
    if not isinstance(power_state, dict):
        return None
    for section_name in ("network", "facts"):
        section = power_state.get(section_name)
        if not isinstance(section, dict):
            continue
        ip = str(section.get("tailscale_ip") or "").strip()
        if ip.startswith("100."):
            return ip
    return None


def _probe_tailnet_ip() -> str | None:
    ok, out, _ = _run_text(["tailscale", "ip", "-4"], timeout=3)
    if not ok:
        return None
    for line in out.splitlines():
        ip = line.strip()
        if ip.startswith("100."):
            return ip
    return None


def _tailnet_ip(power_state: dict | None = None) -> str | None:
    guardian_ip = _guardian_tailnet_ip(power_state)
    if guardian_ip:
        return guardian_ip
    return _cached_probe("tailnet_ip", _HEALTH_PROBE_CACHE_SECONDS, _probe_tailnet_ip)


def _guardian_lan_ips(power_state: dict | None) -> list[str]:
    if not isinstance(power_state, dict):
        return []
    network = power_state.get("network")
    if not isinstance(network, dict):
        return []
    ips: list[str] = []
    for item in network.get("lan_ips") or []:
        ip = str(item or "").strip()
        if not ip or ip.startswith(("127.", "169.254.", "100.")):
            continue
        if ip not in ips:
            ips.append(ip)
    return ips


def _probe_lan_ips() -> list[str]:
    ok, out, _ = _run_text(["/sbin/ifconfig"], timeout=3)
    if not ok:
        return []
    ips: list[str] = []
    for match in re.finditer(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\b", out):
        ip = match.group(1)
        if ip.startswith(("127.", "169.254.", "100.")):
            continue
        if ip not in ips:
            ips.append(ip)
    return ips


def _lan_ips(power_state: dict | None = None) -> list[str]:
    guardian_ips = _guardian_lan_ips(power_state)
    if guardian_ips:
        return guardian_ips
    return _cached_probe("lan_ips", _HEALTH_PROBE_CACHE_SECONDS, _probe_lan_ips)


def _guardian_listener_entries(power_state: dict | None) -> list[str]:
    if not isinstance(power_state, dict):
        return []
    daemon = power_state.get("daemon")
    if not isinstance(daemon, dict):
        return []
    entries: list[str] = []
    for item in daemon.get("listen") or []:
        entry = str(item or "").strip()
        if entry and entry not in entries:
            entries.append(entry)
    return entries


def _probe_listener_entries() -> list[str]:
    host = BOUND_HOST or os.environ.get("PAIRLING_BOUND_HOST", "")
    entries: list[str] = []
    ok, out, _ = _run_text(["/usr/sbin/lsof", "-nP", f"-iTCP:{PORT}", "-sTCP:LISTEN"], timeout=3)
    if ok:
        for line in out.splitlines()[1:]:
            if " TCP " not in line:
                continue
            entry = line.split(" TCP ", 1)[1].replace(" (LISTEN)", "").strip()
            if entry and entry not in entries:
                entries.append(entry)
    if not entries and host:
        entries.append(f"{host}:{PORT}")
    return entries


def _listener_entries(power_state: dict | None = None) -> list[str]:
    guardian_entries = _guardian_listener_entries(power_state)
    if guardian_entries:
        return guardian_entries
    return _cached_probe("listener_entries", _HEALTH_PROBE_CACHE_SECONDS, _probe_listener_entries)


def _read_guardian_state() -> tuple[dict | None, str | None, float | None, str | None]:
    for path in (POWER_STATE_PATH, POWER_STATE_FALLBACK_PATH):
        try:
            if not path.exists():
                continue
            state = json.loads(path.read_text())
            generated = float(state.get("generated_at") or state.get("ts") or 0)
            age = max(0.0, _time.time() - generated) if generated else None
            return state, str(path), age, None
        except Exception as exc:
            return None, str(path), None, f"{type(exc).__name__}: {exc}"
    return None, None, None, "guardian state missing"


def _coordinator_from_guardian(state: dict | None, age: float | None, error: str | None) -> dict:
    if not state:
        return {
            "role": "primary_coordinator",
            "posture": "unknown",
            "severity": "unknown",
            "summary": error or "Guardian state is unavailable",
            "stale": True,
        }
    if isinstance(state.get("posture"), dict):
        posture = state.get("posture") or {}
        status = posture.get("status") or "unknown"
        severity = posture.get("severity") or ("ok" if status == "ready" else status)
        summary = posture.get("summary") or state.get("summary") or "Coordinator posture is unknown"
    else:
        status = state.get("posture") or "unknown"
        severity = state.get("severity") or ("ok" if status == "ready" else status)
        summary = state.get("summary") or "Coordinator posture is unknown"
    stale = age is None or age > POWER_STATE_STALE_SECONDS
    if stale:
        status = "unknown"
        severity = "unknown"
        summary = f"Guardian sample is stale ({int(age or 0)}s old)"
    return {
        "role": (state.get("host") or {}).get("role") if isinstance(state.get("host"), dict) else "primary_coordinator",
        "host": (state.get("host") or {}).get("name") if isinstance(state.get("host"), dict) else (state.get("host") or DEFAULT_COORDINATOR_HOST),
        "posture": status,
        "severity": severity,
        "summary": summary,
        "stale": stale,
        "sample_age_seconds": age,
    }


def _normalize_guardian_state(state: dict | None) -> dict | None:
    if not state:
        return None
    if isinstance(state.get("posture"), dict) and any(isinstance(state.get(key), dict) for key in ("host", "network", "daemon")):
        normalized = dict(state)
        host = normalized.get("host")
        if not isinstance(host, dict):
            normalized["host"] = {
                "name": str(host or DEFAULT_COORDINATOR_HOST),
                "role": "primary_coordinator",
            }
        return normalized

    facts = state.get("facts") if isinstance(state.get("facts"), dict) else {}
    checks_in = state.get("checks") if isinstance(state.get("checks"), list) else []
    checks: dict[str, str] = {}
    warnings: list[str] = []
    for item in checks_in:
        if not isinstance(item, dict):
            continue
        ident = str(item.get("id") or "check")
        ok = bool(item.get("ok"))
        message = str(item.get("message") or ("ok" if ok else "failed"))
        checks[ident] = "ok" if ok else message
        if not ok:
            warnings.append(message)

    sleep_minutes = facts.get("sleep_minutes")
    disk_sleep = facts.get("disk_sleep_minutes")
    thermal_speed = facts.get("thermal_cpu_speed_limit")
    thermal_scheduler = facts.get("thermal_cpu_scheduler_limit")
    thermal_state = "nominal"
    if isinstance(thermal_speed, (int, float)) and thermal_speed < 80:
        thermal_state = "warning"
    if isinstance(thermal_scheduler, (int, float)) and thermal_scheduler < 80:
        thermal_state = "warning"

    host_name = state.get("host") if isinstance(state.get("host"), str) else DEFAULT_COORDINATOR_HOST
    return {
        "schema_version": state.get("schema_version") or 1,
        "generated_at": state.get("generated_at") or state.get("ts") or _time.time(),
        "host": {
            "name": host_name or DEFAULT_COORDINATOR_HOST,
            "role": "primary_coordinator",
        },
        "posture": {
            "status": state.get("posture") or "unknown",
            "severity": state.get("severity") or "unknown",
            "summary": state.get("summary") or "Coordinator posture is unknown",
        },
        "power": {
            "ac_power": facts.get("ac_power"),
            "battery_percent": facts.get("battery_percent"),
            "low_power_mode": facts.get("low_power_mode"),
            "system_sleep_disabled": sleep_minutes == 0 if sleep_minutes is not None else None,
            "display_sleep_minutes": facts.get("display_sleep_minutes"),
            "disk_sleep_disabled": disk_sleep == 0 if disk_sleep is not None else None,
            "caffeinate_pid": facts.get("caffeinate_pid"),
            "prevent_system_sleep": facts.get("prevent_system_sleep"),
            "prevent_idle_system_sleep": facts.get("prevent_user_idle_system_sleep"),
            "prevent_display_sleep": facts.get("prevent_user_idle_display_sleep"),
        },
        "lid": {
            "closed": facts.get("lid_closed"),
            "apple_clamshell_causes_sleep": facts.get("clamshell_causes_sleep"),
            "supported_posture": facts.get("lid_closed") is False,
        },
        "thermal": {
            "state": thermal_state,
            "cpu_speed_limit": thermal_speed,
            "cpu_scheduler_limit": thermal_scheduler,
        },
        "network": {
            "tailscale_installed": facts.get("tailscale_ip") is not None,
            "tailscale_variant": "standalone",
            "tailscale_ip": facts.get("tailscale_ip"),
            "tailscale_status": "ok" if facts.get("tailscale_ip") else "missing",
            "default_interface": None,
            "lan_ips": [],
        },
        "daemon": {
            "pairling_pid": os.getpid(),
            "listen": (listener_entries := _listener_entries()),
            "reachable_local": bool(listener_entries),
            "reachable_tailnet": facts.get("daemon_reachable"),
        },
        "warnings": warnings,
        "checks": checks,
        "raw_schema": "legacy_flat_guardian",
    }


def _pairling_connect_health() -> dict:
    """Cached snapshot of the Pairling Connect (connectd) axis for health
    surfaces: {"ready": bool, "summary": dict | None, "routes": list}.

    connectd is the embedded-tailnet gateway on 127.0.0.1:7774. A ready
    connect route serves phones regardless of the standalone Tailscale app,
    so /health, route advertisement, and posture must treat it as a
    first-class tailnet axis instead of reporting critical whenever the
    standalone CLI has no 100.x IP.
    """
    def probe() -> dict:
        if fetch_connectd_status is None or advertised_pairling_connect_routes is None:
            return {"ready": False, "summary": None, "routes": []}
        try:
            status = fetch_connectd_status(timeout_seconds=0.7)
        except Exception:
            return {"ready": False, "summary": None, "routes": []}
        try:
            routes = advertised_pairling_connect_routes(status)
        except Exception:
            routes = []
        summary = None
        if redacted_connectd_summary is not None:
            try:
                summary = redacted_connectd_summary(status)
            except Exception:
                summary = None
        ready = any(
            route.get("source") == "pairling_connectd" and route.get("status") == "ready"
            for route in routes
        )
        return {"ready": ready, "summary": summary, "routes": routes}

    return _cached_probe("pairling_connect_health", _HEALTH_PROBE_CACHE_SECONDS, probe)


# Guardian checks whose failure is fully compensated by a ready Pairling
# Connect route: both only measure the standalone-Tailscale axis.
_TAILNET_AXIS_CHECK_IDS = {"tailscale_ip", "daemon_reachable"}


def _apply_pairling_connect_posture(coordinator: dict, power_state: dict | None, connect: dict) -> dict:
    """Downgrade tailnet-axis criticality when the Pairling Connect route is
    ready. The guardian historically measured only standalone Tailscale; a
    healthy embedded connectd route serves phones regardless, so its absence
    alone must not mark the coordinator unsafe. Any other failing check
    keeps the original posture untouched."""
    if not connect.get("ready"):
        return coordinator
    if coordinator.get("posture") != "unsafe":
        return coordinator
    checks = (power_state or {}).get("checks")
    if not isinstance(checks, dict) or not checks:
        return coordinator
    failing = {cid for cid, msg in checks.items() if msg != "ok"}
    if not failing or not failing.issubset(_TAILNET_AXIS_CHECK_IDS):
        return coordinator
    adjusted = dict(coordinator)
    adjusted["posture"] = "warning"
    adjusted["severity"] = "warning"
    adjusted["summary"] = (
        "Pairling Connect tailnet route is ready; standalone Tailscale is offline."
    )
    adjusted["tailnet_axis"] = "pairling_connect"
    return adjusted


def _health_routes(coordinator: dict, power_state: dict | None = None) -> list[dict]:
    now = _time.time()
    routes: list[dict] = []
    connect = _pairling_connect_health()
    for route in connect.get("routes") or []:
        base_url = route.get("base_url")
        if not isinstance(base_url, str) or not base_url:
            continue
        ready = route.get("status") == "ready"
        routes.append({
            "kind": str(route.get("kind") or "tailnet"),
            "base_url": base_url,
            "status": "ok" if ready else "degraded",
            "score": 90 if ready else 30,
            "last_ok_at": now if ready else None,
            "source": str(route.get("source") or "pairling_connectd"),
            "id": route.get("id"),
        })
    tailnet = _tailnet_ip(power_state)
    if tailnet:
        ok = coordinator.get("posture") in ("ready", "warning")
        routes.append({
            "kind": "tailnet",
            "base_url": f"http://{tailnet}:{PORT}",
            "status": "ok" if ok else "degraded",
            "score": 100 if ok else 40,
            "last_ok_at": now if ok else None,
        })
    for ip in _lan_ips(power_state)[:2]:
        routes.append({
            "kind": "lan",
            "base_url": f"http://{ip}:{PORT}",
            "status": "candidate",
            "score": 20,
            "last_ok_at": None,
        })
    if not routes:
        host = os.environ.get("PAIRLING_BOUND_HOST", f"0.0.0.0")
        base_url = host if host.startswith("http") else f"http://{host}:{PORT}"
        routes.append({
            "kind": "manual",
            "base_url": base_url,
            "status": "unknown",
            "score": 0,
            "last_ok_at": None,
        })
    return routes


def _daemon_snapshot(power_state: dict | None = None) -> dict:
    entries = _listener_entries(power_state)
    return {
        "name": "pairlingd",
        "pid": os.getpid(),
        "uptime_seconds": int(_time.time() - DAEMON_STARTED_AT),
        "version": DAEMON_VERSION,
        "bind": entries,
        "threaded": True,
    }


def _readyz_payload() -> dict:
    return {
        "ok": True,
        "schema_version": 1,
        "contract_version": RUNTIME_CONTRACT_VERSION,
        "ts": _time.time(),
        "daemon": {
            "name": "pairlingd",
            "pid": os.getpid(),
            "uptime_seconds": int(_time.time() - DAEMON_STARTED_AT),
            "version": DAEMON_VERSION,
            "threaded": True,
        },
    }


def _health_source_identity(auth_result=None, runtime_info: dict | None = None) -> dict:
    runtime_info = runtime_info or _runtime_info_snapshot()
    install_id = getattr(PAIRING_STORE, "install_id", "") if PAIRING_STORE else ""
    hostname = os.environ.get("PAIRLING_HOSTNAME") or os.uname().nodename.split(".")[0]
    return {
        "schema_version": 1,
        "install_id": str(install_id or getattr(auth_result, "install_id", "") or ""),
        "device_id": str(getattr(auth_result, "device_id", "") or ""),
        "runtime_port": PORT,
        "runtime_version": runtime_info.get("runtime_version"),
        "hostname": hostname,
    }


def _routez_payload(auth_result=None) -> dict:
    runtime_info = _runtime_info_snapshot()
    runtime_contract = runtime_info.get("contract_version") or RUNTIME_CONTRACT_VERSION
    verified = bool(runtime_info.get("verified"))
    ok = verified and runtime_contract == RUNTIME_CONTRACT_VERSION
    install_id = getattr(PAIRING_STORE, "install_id", "") if PAIRING_STORE else ""
    route_runtime = {
        "runtime_version": runtime_info.get("runtime_version"),
        "contract_version": runtime_contract,
        "source_revision": runtime_info.get("source_revision"),
        "source_branch": runtime_info.get("source_branch"),
        "source_dirty": runtime_info.get("source_dirty"),
        "verified": verified,
        "manifest_path": runtime_info.get("manifest_path"),
        "manifest_error": runtime_info.get("manifest_error"),
        "port": runtime_info.get("port") or PORT,
    }
    source = {
        "schema_version": 1,
        "install_id": str(install_id or getattr(auth_result, "install_id", "") or ""),
        "device_id": str(getattr(auth_result, "device_id", "") or ""),
        "runtime_port": PORT,
    }
    return {
        "ok": ok,
        "schema_version": 1,
        "contract_version": RUNTIME_CONTRACT_VERSION,
        "runtime": route_runtime,
        "source": source,
    }


def _health_payload(full_power: bool = False, authenticated: bool = False, auth_result=None) -> dict:
    state, path, age, error = _read_guardian_state()
    power_state = _normalize_guardian_state(state)
    coordinator = _coordinator_from_guardian(power_state, age, error)
    connect = _pairling_connect_health()
    coordinator = _apply_pairling_connect_posture(coordinator, power_state, connect)
    if connect.get("summary") is not None:
        coordinator = dict(coordinator)
        coordinator["pairling_connect"] = connect["summary"]
    routes = _health_routes(coordinator, power_state)
    ok = coordinator.get("posture") in ("ready", "warning")
    runtime_info = _runtime_info_snapshot()
    public_runtime = _public_runtime_info(runtime_info) if _public_runtime_info else runtime_info
    payload = {
        "ok": ok,
        "schema_version": 1,
        "contract_version": RUNTIME_CONTRACT_VERSION,
        "ts": _time.time(),
        "runtime": runtime_info if authenticated else public_runtime,
        "auth": {
            "mode": RUNTIME_AUTH_MODE,
            "required": True,
            "legacy_global_token": False,
        },
        "daemon": _daemon_snapshot(power_state),
        "coordinator": coordinator,
    }
    if authenticated:
        payload["source"] = _health_source_identity(auth_result, runtime_info=runtime_info)
        payload["routes"] = routes
        payload["sessions"] = _sessions_health_snapshot()
        payload["mirror"] = _mirror_cached_summary()
        payload["safety"] = SAFETY_MONITOR.status() if SAFETY_MONITOR else {
            "contract_version": "pairling-safety-v0",
            "mode": "absent",
            "installed": False,
            "approved": False,
            "running": False,
            "full_disk_access": "unknown",
            "visibility": "unavailable",
            "summary": "Pairling Safety Monitor bridge is unavailable.",
            "event_count": 0,
            "high_risk_count": 0,
            "updated_at": _time.time(),
        }
    if full_power:
        payload["guardian_path"] = path
        payload["guardian_error"] = error
        payload["guardian_sample_age_seconds"] = age
        payload["power_state"] = power_state
    return payload


def _cached_health_payload(full_power: bool = False, authenticated: bool = False, auth_result=None) -> dict:
    device_id = str(getattr(auth_result, "device_id", "") or "")
    install_id = str(getattr(auth_result, "install_id", "") or "")
    key = (bool(full_power), bool(authenticated), device_id, install_id)
    now = _time.time()
    with _health_payload_cache_lock:
        cached = _health_payload_cache.get(key)
        if cached is not None and now - cached[0] < _HEALTH_PAYLOAD_CACHE_SECONDS:
            return _copy_cache_value(cached[1])
    payload = _health_payload(full_power=full_power, authenticated=authenticated, auth_result=auth_result)
    with _health_payload_cache_lock:
        _health_payload_cache[key] = (now, _copy_cache_value(payload))
    return _copy_cache_value(payload)


def _mac_health_alert_snapshot() -> dict:
    state, _path, age, error = _read_guardian_state()
    coordinator = _coordinator_from_guardian(state, age, error)
    coordinator = _apply_pairling_connect_posture(
        coordinator, _normalize_guardian_state(state), _pairling_connect_health()
    )
    return {
        "ok": coordinator.get("posture") in ("ready", "warning"),
        "schema_version": 1,
        "contract_version": RUNTIME_CONTRACT_VERSION,
        "ts": _time.time(),
        "coordinator": coordinator,
    }


def _health_diff_digest(payload: dict) -> str:
    stable = json.loads(json.dumps(payload))
    stable.pop("ts", None)
    daemon = stable.get("daemon")
    if isinstance(daemon, dict):
        daemon.pop("uptime_seconds", None)
    coordinator = stable.get("coordinator")
    if isinstance(coordinator, dict):
        coordinator.pop("sample_age_seconds", None)
    for route in stable.get("routes") or []:
        if isinstance(route, dict):
            route.pop("last_ok_at", None)
    mirror = stable.get("mirror")
    if isinstance(mirror, dict):
        mirror.pop("updated_at", None)
    stable.pop("guardian_sample_age_seconds", None)
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()


def _orchestration_preflight_from_health(health: dict) -> tuple[dict, dict]:
    power_state = health.get("power_state") if isinstance(health.get("power_state"), dict) else None
    if power_state is None:
        power_state = (_read_guardian_state()[0] or {})
    coordinator = health.get("coordinator") or {}
    route = (health.get("routes") or [{}])[0]
    runtime_info = health.get("runtime") if isinstance(health.get("runtime"), dict) else {}
    power = power_state.get("power") if isinstance(power_state.get("power"), dict) else {}
    lid = power_state.get("lid") if isinstance(power_state.get("lid"), dict) else {}
    network = power_state.get("network") if isinstance(power_state.get("network"), dict) else {}
    thermal = power_state.get("thermal") if isinstance(power_state.get("thermal"), dict) else {}
    facts = power_state.get("facts") if isinstance(power_state.get("facts"), dict) else {}
    preflight = {
        "posture": coordinator.get("posture") or "unknown",
        "warnings": power_state.get("warnings") or [],
        "route": route.get("kind") or "unknown",
        "route_base": route.get("base_url"),
        "checked_at": health.get("ts"),
        "tailscale_ip": network.get("tailscale_ip") or facts.get("tailscale_ip"),
        "lid_closed": lid.get("closed") if "closed" in lid else facts.get("lid_closed"),
        "ac_power": power.get("ac_power") if "ac_power" in power else facts.get("ac_power"),
        "low_power_mode": power.get("low_power_mode") if "low_power_mode" in power else facts.get("low_power_mode"),
        "thermal": thermal.get("state") or (
            "throttled" if (
                (facts.get("thermal_cpu_speed_limit") is not None and facts.get("thermal_cpu_speed_limit") < 80) or
                (facts.get("thermal_cpu_scheduler_limit") is not None and facts.get("thermal_cpu_scheduler_limit") < 80)
            ) else "normal"
        ),
        "runtime_version": runtime_info.get("runtime_version"),
        "runtime_source_revision": runtime_info.get("source_revision"),
        "runtime_contract_version": runtime_info.get("contract_version") or RUNTIME_CONTRACT_VERSION,
        "summary": coordinator.get("summary"),
    }
    mirror = health.get("mirror")
    if isinstance(mirror, dict):
        preflight["mirror"] = mirror
    coordinator_meta = {
        "host": coordinator.get("host") or DEFAULT_COORDINATOR_HOST,
        "role": coordinator.get("role") or "primary_coordinator",
        "daemon_version": DAEMON_VERSION,
        "runtime_version": runtime_info.get("runtime_version"),
        "source_revision": runtime_info.get("source_revision"),
        "contract_version": runtime_info.get("contract_version") or RUNTIME_CONTRACT_VERSION,
    }
    return coordinator_meta, preflight


def _mirror_cli_path() -> Path:
    return Path(__file__).resolve().parent.parent / "mirror" / "companion-mirror"


def _mirror_cached_summary() -> dict:
    try:
        data = json.loads(PROJECT_MIRROR_STATE.read_text())
        summary = data.get("summary")
        if isinstance(summary, dict):
            return summary
    except Exception:
        pass
    return {
        "contract_version": PROJECT_MIRROR_CONTRACT,
        "status": "misconfigured",
        "ready": 0,
        "syncing": 0,
        "offline": 0,
        "conflicted": 0,
        "total": 0,
        "updated_at": None,
        "summary": "Project mirror state has not been initialized.",
    }


def _mirror_cli_json(args: list[str], timeout: int = 45) -> tuple[int, dict]:
    cli = _mirror_cli_path()
    if not cli.exists():
        return 127, {
            "ok": False,
            "contract_version": PROJECT_MIRROR_CONTRACT,
            "error": f"mirror CLI missing: {cli}",
        }
    try:
        proc = subprocess.run(
            [sys.executable, str(cli), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception as exc:
        return 1, {
            "ok": False,
            "contract_version": PROJECT_MIRROR_CONTRACT,
            "error": f"{type(exc).__name__}: {exc}",
        }
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        payload = {
            "ok": False,
            "contract_version": PROJECT_MIRROR_CONTRACT,
            "error": (proc.stderr or proc.stdout or "mirror command produced invalid JSON")[:2000],
        }
    if proc.returncode != 0 and "ok" not in payload:
        payload["ok"] = False
    if proc.stderr and "stderr" not in payload:
        payload["stderr"] = proc.stderr.strip()[:2000]
    return proc.returncode, payload


def _pid_for_tty_command(tty: str, command_name: str) -> int:
    tty_name = os.path.basename(tty or "")
    if not tty_name:
        return 0
    try:
        proc = subprocess.run(
            ["ps", "-t", tty_name, "-o", "pid=,comm=,args="],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except Exception:
        return 0
    if proc.returncode != 0:
        return 0
    for line in proc.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        haystack = " ".join(parts[1:]).lower()
        if command_name.lower() in haystack:
            return int(parts[0])
    return 0


_codex_terminal_scan_cache: dict[str, object] = {"ts": 0.0, "rows": []}
_codex_task_boundary_cache: dict[str, dict[str, object]] = {}


def _process_cwd(pid: int) -> str:
    try:
        proc = subprocess.run(
            ["lsof", "-a", "-p", str(int(pid)), "-d", "cwd", "-Fn"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except Exception:
        return ""
    if proc.returncode != 0:
        return ""
    for line in proc.stdout.splitlines():
        if line.startswith("n/"):
            return line[1:]
    return ""


def _is_codex_cli_command(command: str) -> bool:
    lower = (command or "").lower()
    return (
        "/usr/local/bin/codex" in lower
        or "@openai/codex" in lower
        or "/codex/codex" in lower
        or re.search(r"(^|/)codex(\s|$)", lower) is not None
    )


def _codex_live_terminal_rows() -> list[dict]:
    now = _time.time()
    cached_ts = float(_codex_terminal_scan_cache.get("ts") or 0)
    if now - cached_ts < 2:
        return list(_codex_terminal_scan_cache.get("rows") or [])
    try:
        proc = subprocess.run(
            ["ps", "-axo", "pid=,tty=,lstart=,command="],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except Exception:
        return []
    if proc.returncode != 0:
        return []

    by_tty: dict[str, dict] = {}
    for line in proc.stdout.splitlines():
        parts = line.strip().split(None, 7)
        if len(parts) < 8 or not parts[0].isdigit():
            continue
        tty_name = parts[1]
        command = parts[7]
        if tty_name == "??" or not _is_codex_cli_command(command):
            continue
        try:
            started = datetime.strptime(" ".join(parts[2:7]), "%a %b %d %H:%M:%S %Y").timestamp()
        except Exception:
            started = 0.0
        pid = int(parts[0])
        tty = f"/dev/{tty_name}"
        cwd = _process_cwd(pid)
        if not cwd:
            continue
        current = by_tty.get(tty)
        # The Node wrapper is the process we want for signals; it is usually
        # the lower pid on the same tty, while the native binary is its child.
        if current is None or pid < int(current.get("pid") or 0):
            by_tty[tty] = {
                "pid": pid,
                "tty": tty,
                "project": cwd,
                "started_at": started,
                "command": command,
            }
    rows = list(by_tty.values())
    _codex_terminal_scan_cache["ts"] = now
    _codex_terminal_scan_cache["rows"] = rows
    return rows


def _codex_discover_terminal_control(project: str, observed_started_at: float) -> dict | None:
    if not project or observed_started_at <= 0:
        return None
    candidates = [
        row for row in _codex_live_terminal_rows()
        if row.get("project") == project
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda row: abs(float(row.get("started_at") or 0) - observed_started_at))
    best = candidates[0]
    delta = abs(float(best.get("started_at") or 0) - observed_started_at)
    return best if delta <= 600 else None


# Phase 4 B.3: warm claude --continue pool. Maintains up to one long-running
# `claude` session per model. After 5 min idle, the worker exits.
# This turns 18-25s cold start into ~2s for repeat /llm-route calls.

class _WarmWorker:
    """A long-lived `claude` subprocess that we feed prompts via stdin."""

    def __init__(self, model: str):
        self.model = model
        self.proc: subprocess.Popen | None = None
        self.last_used: float = 0.0
        self.lock = threading.Lock()
        self.session_dir = HOME / ".claude" / "warm-workers" / model
        self.session_dir.mkdir(parents=True, exist_ok=True)

    def _spawn(self) -> bool:
        claude_bin = HOME / ".local" / "bin" / "claude"
        if not claude_bin.exists():
            return False
        # We use stream-json input so we can feed multiple prompts to one session.
        # Each input line is a UserMessage object; output is a stream of JSON events.
        cmd = [
            str(claude_bin), "-p",
            "--input-format", "stream-json",
            "--output-format", "stream-json",
            "--include-partial-messages",
            "--model", self.model,
            "--dangerously-skip-permissions",
            "--no-session-persistence",
        ]
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                cwd=str(self.session_dir),
            )
            return True
        except Exception:
            return False

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def shutdown(self):
        with self.lock:
            if self.proc and self.proc.stdin is not None:
                try:
                    self.proc.stdin.close()
                except Exception:
                    pass
                try:
                    self.proc.terminate()
                    self.proc.wait(timeout=2)
                except Exception:
                    try:
                        self.proc.kill()
                    except Exception:
                        pass
                self.proc = None


class _WarmPool:
    def __init__(self, idle_timeout: float = 300.0):
        self.workers: dict[str, _WarmWorker] = {}
        self.idle_timeout = idle_timeout
        self.global_lock = threading.Lock()
        # Background reaper for idle workers
        threading.Thread(target=self._reaper, daemon=True).start()

    def get(self, model: str) -> _WarmWorker:
        with self.global_lock:
            w = self.workers.get(model)
            if w is None:
                w = _WarmWorker(model)
                self.workers[model] = w
        return w

    def _reaper(self):
        while True:
            _time.sleep(60)
            now = _time.time()
            with self.global_lock:
                stale = [m for m, w in self.workers.items()
                         if w.alive() and (now - w.last_used) > self.idle_timeout]
            for m in stale:
                self.workers[m].shutdown()


_warm_pool = _WarmPool()


def _inject_rate_check(session_id: str, max_per_min: int = 30) -> tuple[bool, int]:
    """Returns (allowed, retry_after_seconds). Drops timestamps older than 60s."""
    now = _time.time()
    with _inject_rate_lock:
        timestamps = _inject_rate_state.get(session_id, [])
        timestamps = [t for t in timestamps if now - t < 60]
        if len(timestamps) >= max_per_min:
            oldest = min(timestamps)
            retry = max(1, int(60 - (now - oldest)))
            return False, retry
        # Also enforce a 1-second cooldown between consecutive injects
        if timestamps and now - max(timestamps) < 1.0:
            return False, 1
        timestamps.append(now)
        _inject_rate_state[session_id] = timestamps
    return True, 0

# Project paths matching any of these glob-ish substrings are filtered out of
# /corpus, /sessions, and bucket rollups. Users can accumulate many one-shot
# research scratch dirs that drown out signal — exclude by default.
PROJECT_EXCLUDE_PATTERNS = [
    "biotech-labs/synth-synth-",        # ephemeral synth-* worktrees
    "biotech-labs/crohns-research/scripts",   # bench-research scratch
    "biotech-research-",                # legacy biotech-research-<hash> dirs
    "/sentinel-orchestration-",                  # ephemeral Sentinel orchestration worktrees
]


def _is_excluded_project(project_path: str) -> bool:
    if not project_path:
        return False
    return any(p in project_path for p in PROJECT_EXCLUDE_PATTERNS)


def _is_recent_project_candidate(project_path: str) -> bool:
    """Recent-project picker should prefer user workspaces, not daemon/smoke dirs."""
    if not project_path or _is_excluded_project(project_path):
        return False
    normalized = project_path.rstrip("/")
    home_prefix = str(HOME) + os.sep
    if not (normalized == str(HOME) or normalized.startswith(home_prefix) or normalized.startswith(("/tmp/", "/private/tmp/"))):
        return False
    if normalized in (str(HOME), str(HOME / "projects"), "/tmp", "/private/tmp"):
        return False
    name = os.path.basename(normalized)
    if name in {"runs", "build", "dist", "DerivedData", "__pycache__", "node_modules"}:
        return False
    if normalized.startswith(("/tmp/", "/private/tmp/")):
        return False
    if normalized.endswith((".xcodeproj", ".xcworkspace", ".xcarchive", ".app", ".dSYM", ".bundle")):
        return False
    if normalized.startswith(str(HOME / ".claude")) or normalized.startswith(str(HOME / ".codex")):
        return False
    return True


def _looks_like_project_root(path: Path) -> bool:
    markers = {
        ".git", "project.yml", "Package.swift", "pyproject.toml", "package.json",
        "Cargo.toml", "go.mod", "Gemfile", "Makefile", "Justfile", "Podfile",
    }
    try:
        return any((path / marker).exists() for marker in markers) or any(path.glob("*.xcodeproj"))
    except OSError:
        return False


def _filesystem_project_candidates(limit: int = 80) -> list[tuple[str, int]]:
    """Return real local project folders for spawn-sheet autocomplete.

    This is intentionally shallow and cheap. It covers the user's normal
    workspace roots so a path can be suggested before it has ever appeared in
    Pairling's session history.
    """
    roots = [
        HOME / "projects",
        HOME / "Developer",
        HOME / "dev",
        HOME / "work",
        Path("/tmp"),
    ]
    skip_names = {
        ".git", ".venv", "__pycache__", "node_modules", "DerivedData",
        "Library", "Applications", "Downloads", "Movies", "Music", "Pictures",
    }
    candidates: dict[str, int] = {}

    def add(path: Path, *, require_marker: bool = False) -> None:
        try:
            resolved = str(path.resolve())
            if not path.is_dir() or not _is_recent_project_candidate(resolved):
                return
            if require_marker and not _looks_like_project_root(path):
                return
            st = path.stat()
        except OSError:
            return
        candidates[resolved] = max(candidates.get(resolved, 0), int(st.st_mtime))

    for root in roots:
        if not root.is_dir():
            continue
        try:
            children = list(root.iterdir())
        except OSError:
            continue
        for child in children[:400]:
            if child.name.startswith(".") or child.name in skip_names:
                continue
            add(child)
            try:
                grandchildren = list(child.iterdir())
            except OSError:
                continue
            for grandchild in grandchildren[:120]:
                if grandchild.name.startswith(".") or grandchild.name in skip_names:
                    continue
                add(grandchild, require_marker=True)

    return sorted(candidates.items(), key=lambda kv: kv[1], reverse=True)[:limit]


def _encode_project_dir(project_path: str) -> str:
    """Convert a project filesystem path to Claude Code's encoded transcript
    directory name under ~/.claude/projects/.

    Claude Code encodes ALL of `/`, `.`, and `_` as `-`. This means a path
    like /Users/example/.claude/state/sentinel/projects/onestream-378da5/terminals/orange_team
    becomes -Users-example--claude-state-sentinel-projects-onestream-378da5-terminals-orange-team
    (note: `.claude` → `-claude` so two consecutive `-`; `orange_team` → `orange-team`).

    The previous implementation only handled `/` and broke for sentinel
    sessions and any project path containing dots or underscores.
    """
    if not project_path:
        return ""
    return re.sub(r"[/._]", "-", project_path)


# Sentinel session paths look like:
#   /Users/example/.claude/state/sentinel/projects/<bucket>-<6hex>/terminals/<mode>
# We strip the sentinel prefix + the 6-hex suffix to recover the underlying
# project bucket name (e.g. "proofforge"). Regular projects use their basename.
_SENTINEL_PROJECTS_RE = re.compile(
    r"/\.claude/state/sentinel/projects/([^/]+?)-[0-9a-f]{6}(?:/|$)"
)
_HEX_SUFFIX_RE = re.compile(r"-[0-9a-f]{6}$")


# =============================================================================
# Slash command catalog (P15)
# =============================================================================

# Best-effort list of Claude Code's built-in commands. There's no JSON manifest
# for these — they're rendered text in the binary — so we hardcode a known set.
# When new built-ins ship, refresh this list.
_BUILTIN_COMMANDS = [
    {"name": "/help",      "description": "Get help with using Claude Code", "args": None},
    {"name": "/clear",     "description": "Clear conversation history", "args": None},
    {"name": "/compact",   "description": "Compact the conversation context", "args": None},
    {"name": "/resume",    "description": "Resume a previous session", "args": None},
    {"name": "/continue",  "description": "Continue the most recent session", "args": None},
    {"name": "/exit",      "description": "Exit Claude Code", "args": None},
    {"name": "/quit",      "description": "Quit Claude Code", "args": None},
    {"name": "/effort",    "description": "Set thinking effort level", "args": "<level>"},
    {"name": "/model",     "description": "Set the model", "args": "<model>"},
    {"name": "/status",    "description": "Show session status", "args": None},
    {"name": "/init",      "description": "Initialize CLAUDE.md", "args": None},
    {"name": "/config",    "description": "Edit Claude Code config", "args": None},
    {"name": "/login",     "description": "Authenticate with Anthropic", "args": None},
    {"name": "/logout",    "description": "Sign out", "args": None},
    {"name": "/mcp",       "description": "Manage MCP servers", "args": None},
    {"name": "/agents",    "description": "List or run agents", "args": None},
    {"name": "/tools",     "description": "List available tools", "args": None},
    {"name": "/skills",    "description": "List available skills", "args": None},
    {"name": "/cost",      "description": "Show session token cost", "args": None},
    {"name": "/review",    "description": "Run a code review on the current diff", "args": None},
    {"name": "/release-notes", "description": "Show what's new", "args": None},
    {"name": "/feedback",  "description": "Send feedback to Anthropic", "args": None},
]

_CODEX_BUILTIN_COMMANDS = [
    {"name": "/help", "description": "Show Codex interactive help", "source": "builtin", "args": None},
    {"name": "/status", "description": "Show Codex session status when available", "source": "builtin", "args": None},
    {"name": "/model", "description": "Change model if supported by the current Codex build", "source": "builtin", "args": "<model>"},
    {"name": "/resume", "description": "Resume a previous Codex session in this project", "source": "builtin", "args": "<session_id>"},
    {"name": "/mcp", "description": "Inspect or manage Codex MCP servers", "source": "builtin", "args": None},
    {"name": "/quit", "description": "Exit the Codex session", "source": "builtin", "args": None},
    {"name": "/exit", "description": "Exit the Codex session", "source": "builtin", "args": None},
]

_INVOCATION_SCHEMA_VERSION = 1
_INVOCATION_MAX_SKILL_FILE_SIZE = 256 * 1024
_INVOCATION_MAX_SKILL_FILES = 2500
_INVOCATION_MAX_TOTAL_BYTES = 32 * 1024 * 1024
_INVOCATION_MAX_TRAVERSAL_DEPTH = 8


def _title_from_invocation_name(name: str) -> str:
    parts = re.split(r"[-_\s]+", name.strip())
    return " ".join(p[:1].upper() + p[1:] for p in parts if p) or name


def _bool_frontmatter(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() not in {"false", "0", "no", "off"}


def _invocation_id(provider: str, trigger: str, kind: str, namespace: str, name: str) -> str:
    return f"{provider}:{trigger}:{kind}:{namespace}:{name}"


def _make_invocation(*, provider: str, trigger: str, name: str, description: str,
                     source: str, kind: str, namespace: str, args=None,
                     insert_text: str | None = None, display_name: str | None = None,
                     source_path: Path | str | None = None, trust: dict | None = None,
                     visibility: dict | None = None) -> dict:
    clean_name = name.lstrip("/$")
    return {
        "id": _invocation_id(provider, trigger, kind, namespace, clean_name),
        "provider": provider,
        "trigger": trigger,
        "name": clean_name,
        "display_name": display_name or _title_from_invocation_name(clean_name),
        "insert_text": insert_text or f"{trigger}{clean_name}",
        "kind": kind,
        "namespace": namespace,
        "source": source,
        "source_path": str(Path(source_path).resolve()) if source_path else None,
        "description": description or "",
        "args": args,
        "trust": trust,
        "visibility": visibility or {"user_invocable": True, "hidden": False},
    }


def _invocation_sort_key(item: dict) -> tuple:
    source = item.get("source", "")
    kind = item.get("kind", "")
    trigger = item.get("trigger", "")
    return (
        0 if trigger == "/" else 1,
        0 if kind == "builtin" else 1 if kind == "command" else 2 if kind == "skill" else 3,
        0 if source == "builtin" else 1 if source == "user" else 2 if source == "project" else 3 if source.startswith("plugin:") else 4,
        str(item.get("display_name") or item.get("name") or "").lower(),
        str(item.get("id") or ""),
    )


def _dedupe_invocations(items: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for item in sorted(items, key=_invocation_sort_key):
        item_id = str(item.get("id") or "")
        if not item_id or item_id in seen:
            continue
        seen.add(item_id)
        out.append(item)
    return out


def _legacy_command_from_invocation(item: dict) -> dict:
    insert_text = str(item.get("insert_text") or "")
    name = insert_text if insert_text.startswith("/") else f"/{item.get('name', '')}"
    return {
        "name": name,
        "description": item.get("description") or "",
        "source": item.get("source") or "",
        "args": item.get("args"),
    }


def _builtin_invocations(provider: str) -> list[dict]:
    raw = _CODEX_BUILTIN_COMMANDS if provider == "codex" else _BUILTIN_COMMANDS
    return [
        _make_invocation(
            provider=provider,
            trigger="/",
            name=str(cmd.get("name") or "").lstrip("/"),
            description=str(cmd.get("description") or ""),
            source="builtin",
            kind="builtin",
            namespace="builtin",
            args=cmd.get("args"),
            insert_text=str(cmd.get("name") or ""),
            source_path=None,
            trust={"local": True, "allowlisted_root": True, "signed": False},
        )
        for cmd in raw
    ]


def _parse_md_frontmatter(text: str) -> dict:
    """Pull simple key: value pairs from a YAML frontmatter block at the
    top of a markdown file. Doesn't handle nested YAML; that's fine — slash
    command frontmatter is flat (description, name, args, user-invocable)."""
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end < 0:
        return {}
    out: dict = {}
    for line in text[3:end].split("\n"):
        line = line.rstrip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _first_prose_line(text: str) -> str:
    """Fallback description: first non-empty, non-header line of the body."""
    in_frontmatter = text.startswith("---")
    body = text
    if in_frontmatter:
        end = text.find("\n---", 3)
        if end >= 0:
            body = text[end + 4:]
    for line in body.split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("---"):
            continue
        return line[:200]
    return ""


def _scan_md_dir_invocations(dir_path: Path, *, source_label: str, namespace: str,
                             provider: str, trigger: str = "/", kind: str = "command") -> list:
    items: list = []
    if not dir_path.is_dir():
        return items
    try:
        files = sorted(dir_path.glob("*.md"))
    except OSError:
        return items
    for p in files:
        try:
            resolved = p.resolve()
            text = p.read_text(errors="replace")
        except OSError:
            continue
        fm = _parse_md_frontmatter(text)
        if not _bool_frontmatter(fm.get("user-invocable"), True):
            continue
        desc = fm.get("description") or _first_prose_line(text)
        name = fm.get("name") or p.stem
        items.append(_make_invocation(
            provider=provider,
            trigger=trigger,
            name=name,
            description=desc,
            source=source_label,
            kind=kind,
            namespace=namespace,
            args=fm.get("args"),
            insert_text=f"{trigger}{name.lstrip('/$')}",
            source_path=resolved,
            trust={"local": True, "allowlisted_root": True, "signed": False},
            visibility={"user_invocable": True, "hidden": False},
        ))
    return items


def _scan_claude_skill_invocations() -> list:
    items: list = []
    skills_dir = HOME / ".claude" / "skills"
    if not skills_dir.is_dir():
        return items
    try:
        skill_dirs = sorted(d for d in skills_dir.iterdir() if d.is_dir() and not d.name.startswith("."))
    except OSError:
        return items
    for d in skill_dirs:
        skill_md = d / "SKILL.md"
        if not skill_md.is_file():
            continue
        try:
            text = skill_md.read_text(errors="replace")
        except OSError:
            continue
        fm = _parse_md_frontmatter(text)
        if not _bool_frontmatter(fm.get("user-invocable"), True):
            continue
        name = fm.get("name") or d.name
        items.append(_make_invocation(
            provider="claude",
            trigger="/",
            name=name,
            description=fm.get("description") or _first_prose_line(text),
            source="skill",
            kind="skill",
            namespace="skill",
            args=fm.get("args"),
            insert_text=f"/{name.lstrip('/')}",
            source_path=skill_md,
            trust={"local": True, "allowlisted_root": True, "signed": False},
            visibility={"user_invocable": True, "hidden": False},
        ))
    return items


def _scan_claude_plugin_invocations() -> list:
    items: list = []
    plugins_dir = HOME / ".claude" / "plugins"
    if not plugins_dir.is_dir():
        return items
    try:
        all_md = list(plugins_dir.glob("**/commands/*.md"))
    except OSError:
        return items
    for p in all_md:
        try:
            parts = p.parts
            idx = parts.index("plugins")
            plugin_name = parts[idx + 1]
        except (ValueError, IndexError):
            continue
        if plugin_name in ("cache",):
            continue
        if plugin_name == "marketplaces":
            try:
                plugin_name = parts[idx + 2]
            except IndexError:
                continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        fm = _parse_md_frontmatter(text)
        if not _bool_frontmatter(fm.get("user-invocable"), True):
            continue
        items.append(_make_invocation(
            provider="claude",
            trigger="/",
            name=fm.get("name") or p.stem,
            description=fm.get("description") or _first_prose_line(text),
            source=f"plugin:{plugin_name}",
            kind="plugin",
            namespace=plugin_name,
            args=fm.get("args"),
            insert_text=f"/{(fm.get('name') or p.stem).lstrip('/')}",
            source_path=p,
            trust={"local": True, "allowlisted_root": True, "signed": False},
            visibility={"user_invocable": True, "hidden": False},
        ))
    return items


def _path_is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _codex_skill_roots() -> list[Path]:
    roots = [
        HOME / ".codex" / "skills" / ".system",
        HOME / ".agents" / "skills",
    ]
    cache_root = HOME / ".codex" / "plugins" / "cache"
    if cache_root.is_dir():
        try:
            for p in sorted(cache_root.rglob("skills")):
                try:
                    rel_depth = len(p.resolve().relative_to(cache_root.resolve()).parts)
                except Exception:
                    continue
                if p.is_dir() and rel_depth <= _INVOCATION_MAX_TRAVERSAL_DEPTH:
                    roots.append(p)
        except OSError:
            pass
    out: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        try:
            resolved = root.resolve()
        except OSError:
            continue
        key = str(resolved)
        if key not in seen:
            seen.add(key)
            out.append(root)
    return out


def _codex_skill_namespace(skill_md: Path, root: Path) -> tuple[str, str]:
    try:
        root_resolved = root.resolve()
        skill_resolved = skill_md.resolve()
    except OSError:
        return ("unknown", "unknown")
    if root_resolved == (HOME / ".codex" / "skills" / ".system").resolve():
        return (".system", "system")
    if root_resolved == (HOME / ".agents" / "skills").resolve():
        return ("agents", "agents")
    parts = skill_resolved.parts
    namespace = "plugin"
    try:
        cache_idx = parts.index("cache")
        skills_idx = parts.index("skills")
        if skills_idx > cache_idx + 1:
            namespace = parts[cache_idx + 2] if len(parts) > cache_idx + 2 else parts[cache_idx + 1]
    except (ValueError, IndexError):
        namespace = root_resolved.name
    return (namespace, f"plugin:{namespace}")


def _scan_codex_dollar_skill_invocations() -> list:
    items: list = []
    total_bytes = 0
    files_seen = 0
    for root in _codex_skill_roots():
        if not root.is_dir():
            continue
        try:
            root_resolved = root.resolve()
            candidates = sorted(root.rglob("SKILL.md"))
        except OSError:
            continue
        for skill_md in candidates:
            if files_seen >= _INVOCATION_MAX_SKILL_FILES:
                return items
            try:
                resolved = skill_md.resolve()
                if not _path_is_relative_to(resolved, root_resolved):
                    continue
                rel_depth = len(resolved.relative_to(root_resolved).parts)
                if rel_depth > _INVOCATION_MAX_TRAVERSAL_DEPTH:
                    continue
                st = resolved.stat()
                if st.st_size > _INVOCATION_MAX_SKILL_FILE_SIZE:
                    continue
                if total_bytes + st.st_size > _INVOCATION_MAX_TOTAL_BYTES:
                    return items
                text = resolved.read_text(errors="replace")
            except OSError:
                continue
            files_seen += 1
            total_bytes += st.st_size
            fm = _parse_md_frontmatter(text)
            if not _bool_frontmatter(fm.get("user-invocable"), True):
                continue
            name = fm.get("name") or resolved.parent.name
            namespace, source = _codex_skill_namespace(resolved, root)
            hidden = str(fm.get("visibility") or "").strip().lower() == "hidden"
            items.append(_make_invocation(
                provider="codex",
                trigger="$",
                name=name,
                display_name=_title_from_invocation_name(name),
                description=fm.get("description") or fm.get("metadata.short-description") or _first_prose_line(text),
                source=source,
                kind="skill",
                namespace=namespace,
                args=fm.get("args"),
                insert_text=f"${name.lstrip('$')}",
                source_path=resolved,
                trust={"local": True, "allowlisted_root": True, "signed": False},
                visibility={"user_invocable": True, "hidden": hidden},
            ))
    return items


def _build_invocation_catalog(cwd: str = "", provider: str = "claude",
                              trigger: str | None = None) -> list:
    provider = (provider or "claude").strip().lower()
    if provider not in AGENT_PROVIDERS:
        return []
    items: list = []
    if trigger in (None, "/"):
        items.extend(_builtin_invocations(provider))
        user_root = HOME / (".codex" if provider == "codex" else ".claude") / "commands"
        items.extend(_scan_md_dir_invocations(
            user_root,
            source_label="user",
            namespace="user",
            provider=provider,
            trigger="/",
            kind="command",
        ))
        if cwd and os.path.isdir(cwd):
            project_root = Path(cwd) / (".codex" if provider == "codex" else ".claude") / "commands"
            items.extend(_scan_md_dir_invocations(
                project_root,
                source_label="project",
                namespace="project",
                provider=provider,
                trigger="/",
                kind="command",
            ))
        if provider == "claude":
            items.extend(_scan_claude_plugin_invocations())
            items.extend(_scan_claude_skill_invocations())
    if provider == "codex" and trigger in (None, "$"):
        items.extend(_scan_codex_dollar_skill_invocations())
    return _dedupe_invocations(items)


def _invocations_signature(cwd: str = "", provider: str = "claude",
                           trigger: str | None = None) -> str:
    provider = (provider or "claude").strip().lower()
    if provider not in AGENT_PROVIDERS:
        return f"unsupported:{provider}:{trigger or ''}"
    h = hashlib.sha256()
    roots: list[Path] = []
    if trigger in (None, "/"):
        roots.extend([
            HOME / (".codex" if provider == "codex" else ".claude") / "commands",
        ])
        if provider == "claude":
            roots.extend([HOME / ".claude" / "skills", HOME / ".claude" / "plugins"])
        if cwd and os.path.isdir(cwd):
            roots.append(Path(cwd) / (".codex" if provider == "codex" else ".claude") / "commands")
    if provider == "codex" and trigger in (None, "$"):
        roots.extend(_codex_skill_roots())
    for root in roots:
        try:
            resolved_root = root.resolve()
        except OSError:
            resolved_root = root
        if not root.is_dir():
            h.update(b"M:" + str(resolved_root).encode() + b"\n")
            continue
        try:
            entries: list[tuple[str, float, int]] = []
            for pattern in ("*.md", "SKILL.md"):
                for p in root.rglob(pattern):
                    try:
                        resolved = p.resolve()
                        if not _path_is_relative_to(resolved, resolved_root):
                            continue
                        st = resolved.stat()
                        entries.append((str(resolved), st.st_mtime, st.st_size))
                    except OSError:
                        continue
            entries.sort(key=lambda t: t[0])
            for path, mtime, size in entries:
                h.update(f"{path}|{mtime}|{size}\n".encode())
        except OSError:
            continue
    return h.hexdigest()


def _scan_md_dir(dir_path: Path, source_label: str, name_prefix: str = "/") -> list:
    """Generic scanner for `.md` slash command files in a directory.
    Each file becomes one command; name is the file stem (basename without
    extension), description from frontmatter `description:` or first body line."""
    items: list = []
    if not dir_path.is_dir():
        return items
    try:
        files = sorted(dir_path.glob("*.md"))
    except OSError:
        return items
    for p in files:
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        fm = _parse_md_frontmatter(text)
        desc = fm.get("description") or _first_prose_line(text)
        items.append({
            "name": f"{name_prefix}{p.stem}",
            "description": desc,
            "source": source_label,
            "args": fm.get("args"),
        })
    return items


def _scan_skills() -> list:
    """Skills live at ~/.claude/skills/<name>/SKILL.md with YAML frontmatter
    (name, description, user-invocable). Filter out skills explicitly marked
    user-invocable: false."""
    items: list = []
    skills_dir = HOME / ".claude" / "skills"
    if not skills_dir.is_dir():
        return items
    try:
        skill_dirs = sorted(d for d in skills_dir.iterdir() if d.is_dir() and not d.name.startswith("."))
    except OSError:
        return items
    for d in skill_dirs:
        skill_md = d / "SKILL.md"
        if not skill_md.is_file():
            continue
        try:
            text = skill_md.read_text(errors="replace")
        except OSError:
            continue
        fm = _parse_md_frontmatter(text)
        if fm.get("user-invocable", "true").lower() == "false":
            continue
        name = fm.get("name", d.name)
        items.append({
            "name": f"/{name}",
            "description": fm.get("description") or _first_prose_line(text),
            "source": "skill",
            "args": fm.get("args"),
        })
    return items


def _scan_plugins() -> list:
    """Plugin slash commands live under ~/.claude/plugins/<plugin>/commands/*.md
    or ~/.claude/plugins/marketplaces/<market>/.claude/commands/*.md.
    We walk the entire plugins tree shallowly and pick anything that ends in
    /commands/*.md, tagging by the highest-level plugin segment."""
    items: list = []
    plugins_dir = HOME / ".claude" / "plugins"
    if not plugins_dir.is_dir():
        return items
    try:
        all_md = list(plugins_dir.glob("**/commands/*.md"))
    except OSError:
        return items
    for p in all_md:
        # Identify plugin segment — the directory immediately under "plugins/".
        try:
            parts = p.parts
            idx = parts.index("plugins")
            plugin_name = parts[idx + 1]
        except (ValueError, IndexError):
            continue
        # Skip the plugin cache + marketplaces metadata files.
        if plugin_name in ("cache",):
            continue
        if plugin_name == "marketplaces":
            # Use the marketplace name as the source tag.
            try:
                plugin_name = parts[idx + 2]
            except IndexError:
                continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        fm = _parse_md_frontmatter(text)
        items.append({
            "name": f"/{p.stem}",
            "description": fm.get("description") or _first_prose_line(text),
            "source": f"plugin:{plugin_name}",
            "args": fm.get("args"),
        })
    return items


def _scan_user_commands() -> list:
    return _scan_md_dir(HOME / ".claude" / "commands", "user")


def _scan_project_commands(cwd: str) -> list:
    if not cwd or not os.path.isdir(cwd):
        return []
    return _scan_md_dir(Path(cwd) / ".claude" / "commands", "project")


def _commands_signature(cwd: str = "", provider: str = "claude") -> str:
    """Stable hash representing the current state of all command source dirs.
    Changes whenever a file is added, removed, or modified across any source.
    Used by /commands-stream to decide whether to re-emit the catalog.

    Cheap: ~1000 stat calls on local fs across 5 dirs is sub-millisecond.
    """
    provider = (provider or "claude").strip().lower()
    if provider not in AGENT_PROVIDERS:
        return f"unsupported:{provider}"
    h = hashlib.sha256()
    sources: list[Path] = [
        HOME / ".claude" / "commands",
        HOME / ".claude" / "skills",
        HOME / ".claude" / "plugins",
    ]
    if provider == "codex":
        sources = [
            HOME / ".codex" / "commands",
            HOME / ".codex" / "plugins",
            HOME / ".codex" / "skills",
        ]
    if cwd and os.path.isdir(cwd):
        sources.append(Path(cwd) / (".codex" if provider == "codex" else ".claude") / "commands")

    for root in sources:
        if not root.is_dir():
            h.update(b"M:" + str(root).encode() + b"\n")
            continue
        # Walk shallowly: directories matter for path; files we hash by
        # name + mtime + size. Sorted for determinism.
        try:
            entries: list[tuple[str, float, int]] = []
            for p in root.rglob("*.md"):
                try:
                    st = p.stat()
                    entries.append((str(p), st.st_mtime, st.st_size))
                except OSError:
                    continue
            entries.sort(key=lambda t: t[0])
            for path, mtime, size in entries:
                h.update(f"{path}|{mtime}|{size}\n".encode())
        except OSError:
            continue
    return h.hexdigest()


def _scan_codex_user_commands() -> list:
    return _scan_md_dir(HOME / ".codex" / "commands", "user")


def _scan_codex_project_commands(cwd: str) -> list:
    if not cwd or not os.path.isdir(cwd):
        return []
    return _scan_md_dir(Path(cwd) / ".codex" / "commands", "project")


def _build_codex_command_catalog(cwd: str = "") -> list:
    items = list(_CODEX_BUILTIN_COMMANDS)
    items.extend(_scan_codex_user_commands())
    items.extend(_scan_codex_project_commands(cwd))
    return sorted(items, key=lambda c: (
        0 if c["source"] == "builtin"
        else 1 if c["source"] == "user"
        else 2 if c["source"] == "project"
        else 3,
        c["name"].lower(),
    ))


def _build_command_catalog(cwd: str = "", provider: str = "claude") -> list:
    """Scan all five sources and return a deduplicated list of commands.
    Built-ins always first, then user, project, plugin, skill — matches Claude
    Code's resolution order for shadowing (later sources override earlier ones)."""
    return [
        _legacy_command_from_invocation(item)
        for item in _build_invocation_catalog(cwd=cwd, provider=provider, trigger="/")
    ]


def _derive_bucket_folder(project_path: str) -> str:
    """Derive the upload-folder bucket name from a session's project path.
    Sentinel sessions get unwrapped to their underlying project name; regular
    projects use their basename. Sanitized to filesystem-safe chars."""
    if not project_path:
        return "misc"
    m = _SENTINEL_PROJECTS_RE.search(project_path)
    if m:
        raw = m.group(1)
    else:
        raw = os.path.basename(project_path.rstrip("/")) or "misc"
        # Belt-and-suspenders: also strip a -<6hex> suffix from a non-sentinel
        # path if the user manually nests projects that pattern. Cheap.
        raw = _HEX_SUFFIX_RE.sub("", raw)
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", raw) or "misc"


def _is_excluded_project_dir_name(encoded: str) -> bool:
    """For walking ~/.claude/projects/<encoded-dir>, check exclusion against the
    encoded directory name (which has '-' instead of '/')."""
    if not encoded:
        return False
    for pattern in PROJECT_EXCLUDE_PATTERNS:
        encoded_pattern = "-" + pattern.replace("/", "-")
        if encoded_pattern in encoded:
            return True
    return False


def _safe_session_id(s: str) -> bool:
    """Whitelist the characters we expect in session ids (UUIDs or continuous-claude
    `s-...` ids) before passing into a SQL query."""
    if not s or len(s) > 64:
        return False
    return all(c.isalnum() or c in "-_" for c in s)


def _safe_agent_native_id(s: str) -> bool:
    """Whitelist provider-native ids before process/registry operations."""
    if not s or len(s) > 160:
        return False
    return all(c.isalnum() or c in "-_" for c in s)


AGENT_PROVIDERS = {"claude", "codex"}


def _registered_agent_provider_ids() -> set[str]:
    try:
        if _provider_registry_ids:
            return set(_provider_registry_ids())
    except Exception:
        pass
    return set(AGENT_PROVIDERS)


def _known_agent_provider_ids() -> set[str]:
    try:
        if _provider_known_ids:
            return set(_provider_known_ids())
    except Exception:
        pass
    return set(AGENT_PROVIDERS)


def _valid_provider_filter(provider: str, *, allow_all: bool = True) -> bool:
    provider = (provider or "").strip().lower()
    if allow_all and provider == "all":
        return True
    return provider in _registered_agent_provider_ids()


def _unknown_provider_payload(provider: str) -> dict:
    known = sorted(_registered_agent_provider_ids())
    future = sorted(_known_agent_provider_ids() - set(known))
    return {
        "ok": False,
        "error": {
            "code": "unknown_provider",
            "message": f"Unknown provider: {provider}",
            "known_providers": known,
            "known_future_providers": future,
        },
    }


def _send_unknown_provider(handler, provider: str):
    handler._send_json(_unknown_provider_payload(provider), status=400)


def _unsupported_provider_payload(provider: str, capability: str) -> dict:
    return {
        "ok": False,
        "error": {
            "code": "unsupported_provider",
            "message": f"Provider {provider} does not support {capability} in this Pairling runtime.",
            "provider": provider,
            "capability": capability,
        },
    }


def _send_unsupported_provider(handler, provider: str, capability: str, status: int = 400):
    handler._send_json(_unsupported_provider_payload(provider, capability), status=status)


CLAUDE_SESSION_CAPABILITIES = [
    "transcript",
    "live_state",
    "send_text",
    "interrupt",
    "terminate",
    "upload",
    "commands",
    "export",
    "resume",
]
TERMINAL_SURFACE_CAPABILITIES = [
    "terminal_output",
    "terminal_surface",
    "terminal_control",
]
CODEX_READ_ONLY_CAPABILITIES = [
    "transcript",
    "export",
]
CODEX_CONTROL_CAPABILITIES = [
    "transcript",
    "live_state",
    "send_text",
    "interrupt",
    "terminate",
    "upload",
    "commands",
    "terminal_output",
    "terminal_surface",
    "terminal_control",
    "export",
]

_SESSION_TRANSCRIPT_STATS_CACHE: dict[tuple[str, str, str, int, int], dict] = {}
_codex_rollout_paths_cache: dict[str, object] = {"ts": 0.0, "paths": []}


def _tail_lines(path: Path | str, *, max_lines: int = 240, max_bytes: int = TRANSCRIPT_TAIL_SCAN_BYTES) -> list[bytes]:
    target = Path(path)
    max_lines = max(1, int(max_lines or 1))
    max_bytes = max(1, int(max_bytes or 1))
    try:
        size = target.stat().st_size
        with target.open("rb") as f:
            start = max(0, size - max_bytes)
            f.seek(start)
            data = f.read(min(size, max_bytes))
    except OSError:
        return []
    if start > 0:
        first_newline = data.find(b"\n")
        if first_newline >= 0:
            data = data[first_newline + 1:]
        else:
            data = b""
    lines = data.splitlines()
    return lines[-max_lines:]


def _bounded_transcript_stream_start(*, since: int, size: int) -> int:
    since = max(0, int(since or 0))
    size = max(0, int(size or 0))
    if since == 0 and size > TRANSCRIPT_INITIAL_STREAM_BYTES:
        return max(0, size - TRANSCRIPT_INITIAL_STREAM_BYTES)
    return min(since, size)


def _session_transcript_stats(path: Path | str | None, provider: str, native_id: str) -> dict:
    if path is None:
        return {"turn_count": None, "bytes": None, "mtime": None}
    target = Path(path)
    try:
        stat = target.stat()
    except OSError:
        return {"turn_count": None, "bytes": None, "mtime": None}

    key = (
        str(target.resolve()),
        provider,
        native_id,
        int(stat.st_mtime_ns),
        int(stat.st_size),
    )
    cached = _SESSION_TRANSCRIPT_STATS_CACHE.get(key)
    if cached is not None:
        return dict(cached)

    turns = 0
    partial = stat.st_size > TRANSCRIPT_STATS_MAX_SCAN_BYTES
    try:
        if partial:
            iterable = [raw.decode("utf-8", errors="replace") for raw in _tail_lines(
                target,
                max_lines=2500,
                max_bytes=TRANSCRIPT_STATS_MAX_SCAN_BYTES,
            )]
        elif provider == "codex":
            with target.open(encoding="utf-8", errors="replace") as f:
                iterable = list(f)
        else:
            with target.open("rb") as f:
                iterable = list(f)
        if provider == "codex":
            for raw in iterable:
                if not raw.strip():
                    continue
                for row in _normalize_codex_line(raw, native_id):
                    msg = row.get("message") or {}
                    if msg.get("role") == "user":
                        turns += 1
        else:
            for raw in iterable:
                if not raw.strip():
                    continue
                try:
                    obj = json.loads(raw)
                except (ValueError, json.JSONDecodeError):
                    continue
                msg = obj.get("message") or {}
                if obj.get("type") == "user" and msg.get("role") == "user":
                    turns += 1
    except OSError:
        return {"turn_count": None, "bytes": stat.st_size, "mtime": int(stat.st_mtime), "partial": partial}

    stats = {"turn_count": turns, "bytes": stat.st_size, "mtime": int(stat.st_mtime), "partial": partial}
    _SESSION_TRANSCRIPT_STATS_CACHE[key] = stats
    if len(_SESSION_TRANSCRIPT_STATS_CACHE) > 512:
        for old_key in list(_SESSION_TRANSCRIPT_STATS_CACHE.keys())[:128]:
            _SESSION_TRANSCRIPT_STATS_CACHE.pop(old_key, None)
    return dict(stats)


def _parse_agent_session_ref(raw: str) -> tuple[str, str]:
    """Return (provider, native_id), treating legacy ids as Claude.

    Unknown provider prefixes are preserved so operation boundaries can return
    explicit unsupported-provider errors instead of silently relabeling future
    provider sessions as Claude.
    """
    raw = (raw or "").strip()
    if ":" in raw:
        provider, native_id = raw.split(":", 1)
        provider = provider.strip().lower()
        if provider and len(provider) <= 48 and re.fullmatch(r"[a-z0-9_]+", provider):
            return provider, native_id
    return "claude", raw


class ClaudeSessionsPgBackend:
    """Claude session reads from the Continuous-Claude Postgres via
    docker-exec psql. The legacy product path; retained behind
    PAIRLING_SESSION_BACKEND=pg as the rollback backend."""

    name = "pg"

    @staticmethod
    def _psql(sql: str, timeout: int = 3, tabbed: bool = False):
        args = ["docker", "exec", "continuous-claude-postgres",
                "psql", "-U", "claude", "-d", "continuous_claude"]
        if tabbed:
            args += ["-A", "-F", "\t", "-t"]
        else:
            args += ["-A", "-t"]
        args += ["-c", sql]
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)

    def uuid_for_session(self, session_id: str) -> str:
        sql = f"SELECT claude_uuid FROM sessions WHERE id = '{session_id}' LIMIT 1"
        try:
            proc = self._psql(sql)
            if proc.returncode != 0:
                return ""
            return (proc.stdout or "").strip()
        except Exception:
            return ""

    def session_for_uuid(self, claude_uuid: str) -> str:
        sql = f"SELECT id FROM sessions WHERE claude_uuid = '{claude_uuid}' ORDER BY last_heartbeat DESC LIMIT 1"
        try:
            proc = self._psql(sql)
            if proc.returncode != 0:
                return ""
            return (proc.stdout or "").strip()
        except Exception:
            return ""

    def worker_stats_rows(self, since_min: int) -> list[tuple[str, str, int]]:
        sql = (
            "SELECT id, project, "
            "EXTRACT(EPOCH FROM last_heartbeat)::bigint AS heartbeat "
            "FROM sessions "
            f"WHERE last_heartbeat > NOW() - INTERVAL '{since_min} minutes' "
            "ORDER BY last_heartbeat DESC;"
        )
        proc = self._psql(sql, timeout=5, tabbed=True)
        if proc.returncode != 0:
            raise RuntimeError(f"psql failed: {proc.stderr.strip()[:200]}")
        rows: list[tuple[str, str, int]] = []
        for line in proc.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            rows.append((parts[0], parts[1], int(parts[2] or 0)))
        return rows

    def recent_project_rows(self, within_min: int, limit: int) -> list[tuple[str, int]]:
        sql = (
            "SELECT project, MAX(EXTRACT(EPOCH FROM last_heartbeat)::bigint) AS last_heartbeat "
            "FROM sessions "
            f"WHERE last_heartbeat > NOW() - INTERVAL '{within_min} minutes' "
            "AND project IS NOT NULL AND project <> '' "
            "GROUP BY project "
            "ORDER BY last_heartbeat DESC "
            f"LIMIT {limit};"
        )
        try:
            proc = self._psql(sql, timeout=5, tabbed=True)
        except (OSError, subprocess.SubprocessError):
            return []
        if proc.returncode != 0:
            return []
        rows: list[tuple[str, int]] = []
        for line in proc.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            rows.append((parts[0], int(parts[1]) if parts[1].isdigit() else 0))
        return rows

    def sessions_rows(self, live_only: bool, within_min: int) -> list[dict]:
        if live_only:
            where_clause = (
                "WHERE closed_at IS NULL "
                "AND claude_uuid IS NOT NULL "
                f"AND last_heartbeat > NOW() - INTERVAL '{within_min} minutes' "
            )
        else:
            where_clause = (
                f"WHERE last_heartbeat > NOW() - INTERVAL '{within_min} minutes' "
            )
        sql = (
            "SELECT id, project, working_on, "
            "EXTRACT(EPOCH FROM started_at)::bigint AS started_at, "
            "EXTRACT(EPOCH FROM last_heartbeat)::bigint AS last_heartbeat, "
            "claude_pid, claude_uuid, terminal_tty "
            "FROM sessions "
            + where_clause +
            "ORDER BY last_heartbeat DESC LIMIT 50;"
        )
        proc = self._psql(sql, timeout=5, tabbed=True)
        if proc.returncode != 0:
            raise RuntimeError(f"psql failed: {proc.stderr.strip()[:200]}")
        rows: list[dict] = []
        for line in proc.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            claude_pid_str = parts[5] if len(parts) > 5 else ""
            rows.append({
                "id": parts[0],
                "project": parts[1],
                "working_on": parts[2] if parts[2] else None,
                "started_at": int(parts[3]) if parts[3] else 0,
                "last_heartbeat": int(parts[4]) if parts[4] else 0,
                "claude_pid": int(claude_pid_str) if claude_pid_str.isdigit() else 0,
                "claude_uuid": parts[6] if len(parts) > 6 else "",
                "terminal_tty": parts[7] if len(parts) > 7 else "",
            })
        return rows

    def tombstone_sessions(self, session_ids: list[str]) -> None:
        ids_sql = ",".join(f"'{i}'" for i in session_ids if _safe_session_id(i))
        if not ids_sql:
            return
        gc_sql = f"UPDATE sessions SET closed_at = NOW() WHERE id IN ({ids_sql}) AND closed_at IS NULL"
        try:
            subprocess.run(
                ["docker", "exec", "continuous-claude-postgres",
                 "psql", "-U", "claude", "-d", "continuous_claude",
                 "-c", gc_sql],
                capture_output=True, text=True, timeout=3,
            )
        except Exception:
            pass  # GC is best-effort

    def collect_rows(self, since_min: int, live_only: bool, limit: int) -> list[dict]:
        where = [
            f"last_heartbeat > NOW() - INTERVAL '{since_min} minutes'",
            "claude_uuid IS NOT NULL",
        ]
        if live_only:
            where.insert(0, "closed_at IS NULL")
        sql = (
            "SELECT id, project, working_on, "
            "EXTRACT(EPOCH FROM started_at)::bigint AS started_at, "
            "EXTRACT(EPOCH FROM last_heartbeat)::bigint AS last_heartbeat, "
            "claude_pid, claude_uuid, terminal_tty, "
            "EXTRACT(EPOCH FROM closed_at)::bigint AS closed_at "
            "FROM sessions WHERE " + " AND ".join(where) +
            f" ORDER BY last_heartbeat DESC LIMIT {limit};"
        )
        try:
            proc = self._psql(sql, timeout=5, tabbed=True)
        except Exception:
            return []
        if proc.returncode != 0:
            return []
        rows: list[dict] = []
        for line in proc.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 8:
                continue
            rows.append({
                "id": parts[0],
                "project": parts[1],
                "working_on": parts[2] if parts[2] else None,
                "started_at": int(parts[3] or 0),
                "last_heartbeat": int(parts[4] or 0),
                "claude_pid": int(parts[5]) if parts[5].isdigit() else None,
                "claude_uuid": parts[6] or None,
                "terminal_tty": parts[7] if len(parts) > 7 else "",
                "closed_at": int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else None,
            })
        return rows

    def lookup_field(self, session_id: str, field: str):
        try:
            proc = self._psql(
                f"SELECT {field} FROM sessions WHERE id='{session_id}'",
                timeout=4,
            )
        except Exception:
            return None
        if proc.returncode != 0:
            return None
        return proc.stdout.strip() or None

    def terminal_tty(self, session_id: str) -> str:
        sql = f"SELECT terminal_tty FROM sessions WHERE id = '{session_id}' LIMIT 1"
        try:
            proc = self._psql(sql)
            if proc.returncode != 0:
                return ""
            return proc.stdout.strip() or ""
        except Exception:
            return ""

    def claude_pid(self, session_id: str) -> int:
        sql = f"SELECT claude_pid FROM sessions WHERE id = '{session_id}' LIMIT 1"
        try:
            proc = self._psql(sql)
            if proc.returncode != 0:
                return 0
            out = (proc.stdout or "").strip()
            return int(out) if out.isdigit() else 0
        except Exception:
            return 0

    def session_age_seconds(self, session_id: str):
        sql = (
            f"SELECT EXTRACT(EPOCH FROM (NOW() - started_at)) "
            f"FROM sessions WHERE id = '{session_id}' LIMIT 1"
        )
        try:
            proc = self._psql(sql)
            if proc.returncode != 0:
                return None
            s = (proc.stdout or "").strip()
            return float(s) if s else None
        except Exception:
            return None

    def stale_session_ids(self) -> list[str]:
        sql = (
            "SELECT id FROM sessions "
            "WHERE last_heartbeat < NOW() - INTERVAL '60 minutes' "
            "AND last_heartbeat > NOW() - INTERVAL '24 hours';"
        )
        try:
            proc = self._psql(sql, timeout=5)
        except Exception:
            return []
        if proc.returncode != 0:
            return []
        return [sid.strip() for sid in proc.stdout.strip().split("\n") if sid.strip()]

    def idle_seconds(self, session_id: str) -> int:
        sql = f"SELECT EXTRACT(EPOCH FROM (NOW() - last_heartbeat))::int FROM sessions WHERE id='{session_id}';"
        try:
            proc = self._psql(sql)
        except Exception:
            return 0
        try:
            return int(proc.stdout.strip()) if proc.returncode == 0 else 0
        except ValueError:
            return 0


class ClaudeSessionsSqliteBackend:
    """Claude session reads from the daemon-owned SQLite agent registry —
    the product path. Row shapes are byte-compatible with the Pg backend
    (same dict keys, epoch ints, ''/None conventions) so /sessions payloads
    do not change when the backend flips."""

    name = "sqlite"

    def uuid_for_session(self, session_id: str) -> str:
        row = _agent_registry_get("claude", session_id)
        return str(row.get("claude_uuid") or "") if row else ""

    def session_for_uuid(self, claude_uuid: str) -> str:
        row = _agent_registry_get_by_claude_uuid("claude", claude_uuid)
        return str(row.get("native_id") or "") if row else ""

    def worker_stats_rows(self, since_min: int) -> list[tuple[str, str, int]]:
        return [
            (str(row.get("native_id") or ""), str(row.get("project") or ""),
             int(row.get("last_heartbeat") or 0))
            for row in _agent_registry_recent("claude", since_min=since_min, limit=1000)
        ]

    def recent_project_rows(self, within_min: int, limit: int) -> list[tuple[str, int]]:
        projects: dict[str, int] = {}
        for row in _agent_registry_recent("claude", since_min=within_min, limit=1000):
            project = str(row.get("project") or "").strip()
            if not project:
                continue
            hb = int(row.get("last_heartbeat") or 0)
            projects[project] = max(projects.get(project, 0), hb)
        ranked = sorted(projects.items(), key=lambda kv: kv[1], reverse=True)
        return ranked[:max(1, limit)]

    def sessions_rows(self, live_only: bool, within_min: int) -> list[dict]:
        cutoff = _time.time() - max(1, int(within_min)) * 60
        if live_only:
            source = [
                row for row in _agent_registry_live("claude")
                if row.get("claude_uuid")
                and float(row.get("last_heartbeat") or 0) > cutoff
            ]
        else:
            source = _agent_registry_recent("claude", since_min=within_min, limit=1000)
        rows: list[dict] = []
        for row in source[:50]:
            rows.append({
                "id": str(row.get("native_id") or ""),
                "project": str(row.get("project") or ""),
                "working_on": (row.get("working_on") or None),
                "started_at": int(row.get("started_at") or 0),
                "last_heartbeat": int(row.get("last_heartbeat") or 0),
                "claude_pid": int(row.get("pid") or 0),
                "claude_uuid": str(row.get("claude_uuid") or ""),
                "terminal_tty": str(row.get("terminal_tty") or ""),
            })
        return rows

    def tombstone_sessions(self, session_ids: list[str]) -> None:
        for sid in session_ids:
            if _safe_session_id(sid):
                _agent_registry_mark_closed("claude", sid)

    def collect_rows(self, since_min: int, live_only: bool, limit: int) -> list[dict]:
        rows: list[dict] = []
        for row in _agent_registry_recent("claude", since_min=since_min, limit=1000):
            if not row.get("claude_uuid"):
                continue
            if live_only and row.get("closed_at") is not None:
                continue
            closed_at = row.get("closed_at")
            rows.append({
                "id": str(row.get("native_id") or ""),
                "project": str(row.get("project") or ""),
                "working_on": (row.get("working_on") or None),
                "started_at": int(row.get("started_at") or 0),
                "last_heartbeat": int(row.get("last_heartbeat") or 0),
                "claude_pid": int(row.get("pid")) if row.get("pid") else None,
                "claude_uuid": str(row.get("claude_uuid")) or None,
                "terminal_tty": str(row.get("terminal_tty") or ""),
                "closed_at": int(closed_at) if closed_at else None,
            })
            if len(rows) >= limit:
                break
        return rows

    def lookup_field(self, session_id: str, field: str):
        row = _agent_registry_get("claude", session_id)
        if not row:
            return None
        column = "pid" if field == "claude_pid" else field
        value = row.get(column)
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def terminal_tty(self, session_id: str) -> str:
        row = _agent_registry_get("claude", session_id)
        return str(row.get("terminal_tty") or "") if row else ""

    def claude_pid(self, session_id: str) -> int:
        row = _agent_registry_get("claude", session_id)
        if not row:
            return 0
        try:
            return int(row.get("pid") or 0)
        except (TypeError, ValueError):
            return 0

    def session_age_seconds(self, session_id: str):
        row = _agent_registry_get("claude", session_id)
        if not row or not row.get("started_at"):
            return None
        return max(0.0, _time.time() - float(row["started_at"]))

    def stale_session_ids(self) -> list[str]:
        now = _time.time()
        return [
            str(row.get("native_id") or "")
            for row in _agent_registry_recent("claude", since_min=60 * 24, limit=1000)
            if now - float(row.get("last_heartbeat") or 0) >= 3600
        ]

    def idle_seconds(self, session_id: str) -> int:
        row = _agent_registry_get("claude", session_id)
        if not row or not row.get("last_heartbeat"):
            return 0
        return int(max(0, _time.time() - float(row["last_heartbeat"])))


_CLAUDE_SESSIONS_PG_BACKEND = ClaudeSessionsPgBackend()
_CLAUDE_SESSIONS_SQLITE_BACKEND = ClaudeSessionsSqliteBackend()


def _claude_sessions_backend():
    if _session_backend() == "sqlite":
        return _CLAUDE_SESSIONS_SQLITE_BACKEND
    return _CLAUDE_SESSIONS_PG_BACKEND


def _lookup_claude_uuid_for_session(session_id: str) -> str:
    session_id = _claude_native_session_id(session_id)
    if not session_id:
        return ""
    return _claude_sessions_backend().uuid_for_session(session_id)


def _lookup_claude_session_for_uuid(claude_uuid: str) -> str:
    claude_uuid = str(claude_uuid or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,180}", claude_uuid):
        return ""
    return _claude_sessions_backend().session_for_uuid(claude_uuid)


def _start_live_activity_publisher():
    if LiveActivityTurnStatePublisher is None or PUSH_DISPATCHER is None:
        return None
    publisher = LiveActivityTurnStatePublisher(
        turn_state_dir=TURN_STATE_DIR,
        push_dispatcher=PUSH_DISPATCHER,
        claude_uuid_resolver=_lookup_claude_uuid_for_session,
        logger=lambda msg: print(f"[live-activity-publisher] {msg}", file=sys.stderr, flush=True),
    )
    publisher.start()
    return publisher


def _start_standard_turn_push_publisher():
    if TurnStateAlertPublisher is None or PUSH_DISPATCHER is None:
        return None
    publisher = TurnStateAlertPublisher(
        turn_state_dir=TURN_STATE_DIR,
        push_dispatcher=PUSH_DISPATCHER,
        claude_session_resolver=_lookup_claude_session_for_uuid,
        logger=lambda msg: print(f"[standard-turn-publisher] {msg}", file=sys.stderr, flush=True),
    )
    publisher.start()
    return publisher


def _start_mac_health_push_publisher():
    if MacHealthAlertPublisher is None or PUSH_DISPATCHER is None:
        return None
    publisher = MacHealthAlertPublisher(
        push_dispatcher=PUSH_DISPATCHER,
        health_snapshot_fn=_mac_health_alert_snapshot,
        logger=lambda msg: print(f"[mac-health-publisher] {msg}", file=sys.stderr, flush=True),
    )
    publisher.start()
    return publisher


def _start_sentinel_push_publisher():
    if SentinelBackgroundEvaluator is None or SENTINEL_NOTIFICATIONS is None or PUSH_DISPATCHER is None:
        return None
    publisher = SentinelBackgroundEvaluator(
        sentinel_center=SENTINEL_NOTIFICATIONS,
        push_dispatcher=PUSH_DISPATCHER,
        worker_stats_fn=lambda: _worker_stats_payload(60),
        human_idle_minutes_fn=_human_idle_minutes,
        token_sessions_fn=lambda: [],
        logger=lambda msg: print(f"[sentinel-publisher] {msg}", file=sys.stderr, flush=True),
    )
    publisher.start()
    return publisher


def _tty_key(tty: str) -> str:
    """Return a filesystem-safe key for a Terminal tty path."""
    name = os.path.basename((tty or "").strip())
    if re.match(r"^ttys[0-9]{3,}$", name):
        return name
    return ""


def _terminal_capture_map_path(tty: str) -> Path | None:
    key = _tty_key(tty)
    if not key:
        return None
    return TERMINAL_CAPTURE_MAP_DIR / f"{key}.json"


def _is_terminal_capture_path(path: Path) -> bool:
    try:
        path.resolve().relative_to(TERMINAL_CAPTURE_DIR.resolve())
        return True
    except Exception:
        return False


def _write_terminal_capture_mapping(tty: str, log_path: Path, *, provider: str,
                                    project: str, capture_id: str) -> None:
    map_path = _terminal_capture_map_path(tty)
    if map_path is None or not _is_terminal_capture_path(log_path):
        return
    payload = {
        "tty": tty,
        "provider": provider,
        "project": project,
        "capture_id": capture_id,
        "terminal_log": str(log_path),
        "created_at": _time.time(),
        "backend": "script",
    }
    try:
        TERMINAL_CAPTURE_MAP_DIR.mkdir(parents=True, exist_ok=True)
        tmp = map_path.with_name(f"{map_path.name}.tmp.{os.getpid()}")
        tmp.write_text(json.dumps(payload, sort_keys=True))
        tmp.replace(map_path)
    except Exception:
        pass


def _terminal_capture_for_tty(tty: str, project: str | None = None) -> Path | None:
    map_path = _terminal_capture_map_path(tty)
    if map_path is None or not map_path.is_file():
        return None
    try:
        payload = json.loads(map_path.read_text())
        if project and payload.get("project") != project:
            return None
        raw_path = str(payload.get("terminal_log") or "")
        if not raw_path:
            return None
        path = Path(raw_path)
        if not _is_terminal_capture_path(path):
            return None
        if not path.is_file():
            return None
        return path
    except Exception:
        return None


def _terminal_capture_from_metadata(metadata: dict) -> Path | None:
    raw_path = str(metadata.get("terminal_log") or "")
    if not raw_path:
        return None
    path = Path(raw_path)
    if not _is_terminal_capture_path(path):
        return None
    if not path.is_file():
        return None
    return path


def _terminal_surface_pending_input(rows: list[str]) -> dict | None:
    from terminal_screen_backend import detect_terminal_pending_input

    return detect_terminal_pending_input(rows)


def _terminal_surface_snapshot_from_text(
    *,
    session_id: str,
    source: str,
    text: str,
    columns: int,
    rows: int,
    cursor: dict | None = None,
) -> dict:
    safe_columns = max(1, min(int(columns or 80), 500))
    safe_rows = max(1, min(int(rows or 24), 200))
    text_rows = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if len(text_rows) > safe_rows:
        text_rows = text_rows[-safe_rows:]
    cursor_payload = cursor or {"row": None, "column": None, "visible": False}
    dimensions = {"columns": safe_columns, "rows": safe_rows}
    hash_material = {
        "session_id": session_id,
        "source": source,
        "dimensions": dimensions,
        "rows": text_rows,
        "cursor": cursor_payload,
    }
    screen_hash = hashlib.sha256(json.dumps(hash_material, sort_keys=True).encode()).hexdigest()
    pending = _terminal_surface_pending_input(text_rows)
    payload = {
        "session_id": session_id,
        "source": source,
        "screen_hash": screen_hash,
        "nonce": screen_hash,
        "dimensions": dimensions,
        "rows": text_rows,
        "cursor": cursor_payload,
        "changed_at": _time.time(),
    }
    if pending is not None:
        payload["pending_input"] = pending
    return payload


def _sha256_prefixed(material: dict) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _terminal_surface_v2_cell_payload(cell) -> dict:
    payload = {"text": str(getattr(cell, "text", ""))}
    width = int(getattr(cell, "width", 1) or 1)
    fg = str(getattr(cell, "fg", "default") or "default")
    bg = str(getattr(cell, "bg", "default") or "default")
    bold = bool(getattr(cell, "bold", False))
    italic = bool(getattr(cell, "italic", False))
    underline = bool(getattr(cell, "underline", False))
    inverse = bool(getattr(cell, "inverse", False))
    link_id = getattr(cell, "link_id", None)
    if width != 1:
        payload["width"] = width
    if fg != "default":
        payload["fg"] = fg
    if bg != "default":
        payload["bg"] = bg
    if bold:
        payload["bold"] = True
    if italic:
        payload["italic"] = True
    if underline:
        payload["underline"] = True
    if inverse:
        payload["inverse"] = True
    if link_id is not None:
        payload["link_id"] = link_id
    return payload


def _terminal_surface_v2_payload_from_state(session_id: str, state) -> dict:
    provider, native_id = _parse_agent_session_ref(session_id)
    row_payloads: list[dict] = []
    links_payload: dict[str, dict] = {}
    for link_id, link_value in (getattr(state, "links", None) or {}).items():
        if isinstance(link_value, dict):
            url = link_value.get("url")
            label = link_value.get("label")
        else:
            url = str(link_value)
            label = None
        links_payload[str(link_id)] = {
            "url": str(url) if url is not None else None,
            "label": str(label) if label is not None else None,
        }
    for row in getattr(state, "visible_rows", ()):
        cells = [_terminal_surface_v2_cell_payload(cell) for cell in getattr(row, "cells", ())]
        row_material = {
            "index": int(getattr(row, "index", 0)),
            "wrapped": bool(getattr(row, "wrapped", False)),
            "cells": cells,
        }
        row_payloads.append({
            "index": row_material["index"],
            "wrapped": row_material["wrapped"],
            "dirty_generation": int(getattr(row, "dirty_generation", 0) or 0),
            "cells_hash": _sha256_prefixed(row_material),
            "cells": cells,
        })
    cursor = getattr(state, "cursor", None)
    cursor_payload = {
        "row": getattr(cursor, "row", None),
        "column": getattr(cursor, "column", None),
        "visible": bool(getattr(cursor, "visible", True)),
        "style": str(getattr(cursor, "style", "block") or "block"),
    }
    dimensions = {
        "rows": int(getattr(state, "rows", 0) or 0),
        "columns": int(getattr(state, "columns", 0) or 0),
    }
    capabilities = list(getattr(state, "capabilities", ()) or ())
    scrollback = {
        "window_start": 0,
        "window_size": len(row_payloads),
        "total_rows": len(row_payloads),
        "truncated_before": False,
    }
    pending_input = getattr(state, "pending_input", None)
    pending_input_detection = getattr(state, "pending_input_detection", None)
    if pending_input_detection is None:
        pending_input_detection = {
            "status": "unknown",
            "parser_version": None,
            "surface": "v2",
            "confidence": None,
            "reason": "detection_metadata_missing",
        }
    pending_input_state = "present" if isinstance(pending_input, dict) else (
        "none" if pending_input_detection.get("status") == "ran" else "unknown"
    )
    hash_material = {
        "schema_version": 2,
        "session_id": session_id,
        "provider": provider,
        "native_id": native_id,
        "source": getattr(state, "source", "broker_vt"),
        "backend": getattr(state, "backend", "pty_broker"),
        "capabilities": capabilities,
        "degraded_reason": getattr(state, "degraded_reason", None),
        "generation": int(getattr(state, "generation", 0) or 0),
        "raw_offset": int(getattr(state, "raw_offset", 0) or 0),
        "dimensions": dimensions,
        "title": getattr(state, "title", None),
        "alternate_screen": bool(getattr(state, "alternate_screen", False)),
        "cursor": cursor_payload,
        "scrollback": scrollback,
        "rows": row_payloads,
        "links": links_payload,
        "pending_input": pending_input,
        "pending_input_state": pending_input_state,
        "pending_input_detection": pending_input_detection,
    }
    screen_hash = _sha256_prefixed(hash_material)
    nonce = _sha256_prefixed({
        "screen_hash": screen_hash,
        "generation": hash_material["generation"],
        "raw_offset": hash_material["raw_offset"],
        "server_salt": TERMINAL_SURFACE_V2_NONCE_SALT,
    })
    return {
        **hash_material,
        "screen_hash": screen_hash,
        "nonce": nonce,
        "changed_at": _time.time(),
        "event_limits": {
            "max_event_bytes": SSE_MAX_EVENT_BYTES,
            "truncated": False,
            "truncation_reason": None,
        },
    }


def _terminal_surface_v2_degraded_from_v1(v1: dict, *, provider: str, native_id: str) -> dict:
    from terminal_screen_backend import TerminalCell, TerminalCursor, TerminalRow, TerminalScreenState

    rows = tuple(
        TerminalRow(
            index=index,
            cells=tuple(TerminalCell(text=ch) for ch in str(row)),
            wrapped=False,
            dirty_generation=int(v1.get("generation") or 0),
        )
        for index, row in enumerate(v1.get("rows") or [])
    )
    dims = v1.get("dimensions") or {}
    state = TerminalScreenState(
        rows=int(dims.get("rows") or len(rows) or 0),
        columns=int(dims.get("columns") or 0),
        generation=int(v1.get("generation") or 0),
        raw_offset=0,
        source=str(v1.get("source") or "terminal_app_contents"),
        backend="terminal_app",
        title=None,
        alternate_screen=False,
        cursor=TerminalCursor(row=None, column=None, visible=False),
        visible_rows=rows,
        dirty_row_indexes=tuple(row.index for row in rows),
        capabilities=("text_snapshot",),
        pending_input=v1.get("pending_input"),
        pending_input_detection={
            "status": "ran" if v1.get("pending_input") is not None else "not_applicable",
            "parser_version": "terminal_pending_input_v1_fallback",
            "surface": "v1_fallback",
            "confidence": (v1.get("pending_input") or {}).get("confidence") if isinstance(v1.get("pending_input"), dict) else None,
            "reason": "terminal_app_contents_is_text_only",
        },
        degraded_reason="terminal_app_contents_is_text_only",
        links=None,
    )
    return _terminal_surface_v2_payload_from_state(_qualified_session_id(provider, native_id), state)


def _terminal_surface_v2_unavailable(*, provider: str, native_id: str, reason: str) -> dict:
    from terminal_screen_backend import TerminalCell, TerminalCursor, TerminalRow, TerminalScreenState

    safe_reason = str(reason or "terminal surface unavailable")[:160]
    message = f"Terminal surface unavailable: {safe_reason}"
    state = TerminalScreenState(
        rows=1,
        columns=max(40, min(len(message), 120)),
        generation=0,
        raw_offset=0,
        source="unavailable",
        backend="unavailable",
        title=None,
        alternate_screen=False,
        cursor=TerminalCursor(row=None, column=None, visible=False),
        visible_rows=(
            TerminalRow(
                index=0,
                cells=(TerminalCell(text=message),),
                wrapped=False,
                dirty_generation=0,
            ),
        ),
        dirty_row_indexes=(0,),
        capabilities=(),
        pending_input=None,
        pending_input_detection={
            "status": "not_applicable",
            "parser_version": None,
            "surface": "v2",
            "confidence": None,
            "reason": safe_reason,
        },
        degraded_reason=safe_reason,
        links=None,
    )
    return _terminal_surface_v2_payload_from_state(_qualified_session_id(provider, native_id), state)


def _terminal_surface_source(raw_session: str) -> dict:
    provider, native_id = _parse_agent_session_ref(raw_session)
    qualified = _qualified_session_id(provider, native_id) if native_id else ""
    if not native_id:
        return {"available": False, "source": "unavailable", "reason": "bad_session"}
    if not re.fullmatch(r"[a-z0-9_]{1,48}", provider or ""):
        return {"available": False, "source": "unavailable", "reason": "bad_session"}
    if provider not in AGENT_PROVIDERS:
        return {"available": False, "source": "unavailable", "reason": "unsupported_provider"}

    if PTY_BROKER is not None:
        session = PTY_BROKER.get(qualified)
        if session is not None:
            return {
                "available": True,
                "source": "broker_vt",
                "reason": "broker_vt",
                "broker_id": _broker_session_id(session),
                "tty": _broker_slave_tty(session),
                "can_control": True,
            }

    if provider == "codex":
        reg = _agent_registry_get("codex", native_id) or {}
        metadata = {}
        try:
            metadata = json.loads(reg.get("metadata_json") or "{}")
            if not isinstance(metadata, dict):
                metadata = {}
        except Exception:
            metadata = {}
        broker_id = str(metadata.get("broker_id") or "").strip()
        if broker_id and PTY_BROKER is not None:
            session = PTY_BROKER.get(broker_id)
            if session is not None:
                PTY_BROKER.register_alias(qualified, _broker_session_id(session))
                return {
                    "available": True,
                    "source": "broker_vt",
                    "reason": "broker_vt",
                    "broker_id": _broker_session_id(session),
                    "tty": _broker_slave_tty(session),
                    "can_control": True,
                }
        capture_path = _terminal_capture_from_metadata(metadata)
        if capture_path and capture_path.exists():
            tty = reg.get("terminal_tty") or ""
            if not tty:
                candidates = _codex_terminal_tty_candidates(reg)
                tty = candidates[0] if candidates else ""
            return {
                "available": True,
                "source": "script_capture",
                "reason": "script_capture",
                "terminal_log": str(capture_path),
                "tty": tty,
                "can_control": False,
            }
        tty = reg.get("terminal_tty") or ""
        if not tty:
            candidates = _codex_terminal_tty_candidates(reg)
            tty = candidates[0] if candidates else ""
        if not tty:
            return {"available": False, "source": "unavailable", "reason": "no_terminal_tty"}
        if not re.match(r"^/dev/ttys[0-9]{3,}$", tty):
            return {"available": False, "source": "unavailable", "reason": "invalid_tty", "tty": tty}
        return {
            "available": True,
            "source": "terminal_app_contents",
            "reason": "terminal_app_contents",
            "tty": tty,
            "can_control": True,
        }

    return {"available": False, "source": "unavailable", "reason": "no_terminal_tty"}


def _terminal_surface_capabilities(raw_session: str) -> dict:
    source = _terminal_surface_source(raw_session)
    capabilities = []
    if source.get("available"):
        capabilities.extend(TERMINAL_SURFACE_CAPABILITIES)
    return {
        **source,
        "capabilities": capabilities,
        "can_surface": bool(source.get("available")),
        "can_control": bool(source.get("can_control") and source.get("available")),
    }


def _terminal_attention_from_snapshot(snapshot: dict | None) -> dict | None:
    if not snapshot:
        return None
    pending = snapshot.get("pending_input")
    if not isinstance(pending, dict):
        return None
    return {
        "needs_input": True,
        "state": pending.get("state"),
        "source": snapshot.get("source"),
        "changed_at": snapshot.get("changed_at"),
    }


def _truth_issue(code: str, severity: str, user_message: str, *, detail: str | None = None,
                 sources: list[str] | None = None, blocks_control: bool = False) -> dict:
    payload = {
        "code": code,
        "severity": severity,
        "user_message": user_message,
        "blocks_control": bool(blocks_control),
    }
    if detail:
        payload["detail"] = detail
    if sources:
        payload["sources"] = sources
    return payload


def _surface_pending_input_state(surface: dict | None, *, version: str) -> str:
    if not isinstance(surface, dict):
        return "unknown"
    if isinstance(surface.get("pending_input"), dict):
        return "present"
    if version == "v2":
        state = str(surface.get("pending_input_state") or "").strip()
        if state in {"present", "none", "unknown", "omitted"}:
            return state
        detection = surface.get("pending_input_detection") if isinstance(surface.get("pending_input_detection"), dict) else {}
        return "none" if detection.get("status") == "ran" else "unknown"
    return "none"


def _surface_detection(surface: dict | None, *, version: str) -> dict:
    if isinstance(surface, dict) and isinstance(surface.get("pending_input_detection"), dict):
        return dict(surface["pending_input_detection"])
    if version == "v1":
        return {
            "status": "ran" if isinstance((surface or {}).get("pending_input"), dict) else "not_applicable",
            "parser_version": "terminal_pending_input_v1",
            "surface": "v1",
            "confidence": ((surface or {}).get("pending_input") or {}).get("confidence") if isinstance((surface or {}).get("pending_input"), dict) else None,
            "reason": None,
        }
    return {
        "status": "unknown",
        "parser_version": None,
        "surface": "v2",
        "confidence": None,
        "reason": "detection_metadata_missing",
    }


def _runtime_freshness_truth(expected_source_revision: str | None = None) -> dict:
    info = _runtime_info_snapshot()
    expected = (
        expected_source_revision
        or os.environ.get("PAIRLING_EXPECTED_SOURCE_REVISION")
        or os.environ.get("PAIRLING_APP_SOURCE_REVISION")
        or ""
    ).strip()
    source_revision = str(info.get("source_revision") or "unknown")
    source_dirty = info.get("source_dirty")
    revision_matches = (
        source_revision == expected
        or (len(source_revision) >= 7 and expected.startswith(source_revision))
        or (len(expected) >= 7 and source_revision.startswith(expected))
    ) if expected and source_revision and source_revision != "unknown" else False
    if expected:
        if not revision_matches:
            if source_dirty is False:
                # Lockstep relaxation: a CLEAN tree on a different revision is
                # drift, not a hard mismatch. The app renders a warning banner
                # instead of quarantining, so a runtime install from a newer
                # commit no longer breaks the installed app until the matching
                # TestFlight build ships. Dirty trees stay hard mismatches.
                matches = None
                confidence = "revision_drift"
                mismatch_reason = "runtime_revision_drift"
            else:
                matches = False
                confidence = "mismatch"
                mismatch_reason = "runtime_source_mismatch"
        elif source_dirty is True:
            matches = False
            confidence = "mismatch"
            mismatch_reason = "runtime_source_dirty"
        elif source_dirty is None:
            matches = None
            confidence = "unknown"
            mismatch_reason = "runtime_source_dirty_unknown"
        else:
            matches = True
            confidence = "exact_revision" if source_revision == expected else "build_metadata_match"
            mismatch_reason = None
    else:
        matches = None
        confidence = "unknown"
        mismatch_reason = None
    return {
        "runtime_version": info.get("runtime_version"),
        "source_revision": source_revision,
        "branch": info.get("source_branch"),
        "installed_at": info.get("installed_at"),
        "runtime_root": info.get("install_root"),
        "source_dirty": source_dirty,
        "runtime_matches_app_source": matches,
        "runtime_match_confidence": confidence,
        "mismatch_reason": mismatch_reason,
    }


def _session_runtime_truth_from_parts(
    *,
    session_id: str,
    registry: dict | None,
    turn: dict | None,
    transcript: dict | None,
    v1_surface: dict | None,
    v2_surface: dict | None,
    runtime: dict | None,
    stream: dict | None,
    process: dict | None = None,
) -> dict:
    provider, native_id = _parse_agent_session_ref(session_id)
    registry = dict(registry or {})
    process = dict(process or {})
    turn = dict(turn or {})
    transcript = dict(transcript or {})
    runtime = dict(runtime or {})
    stream = dict(stream or {})
    contradictions: list[dict] = []
    degradations: list[dict] = []

    v1_pending_state = _surface_pending_input_state(v1_surface, version="v1")
    v2_pending_state = _surface_pending_input_state(v2_surface, version="v2")
    v1_pending = v1_surface.get("pending_input") if isinstance(v1_surface, dict) else None
    v2_pending = v2_surface.get("pending_input") if isinstance(v2_surface, dict) else None
    v2_detection = _surface_detection(v2_surface, version="v2")
    v2_capabilities = set((v2_surface or {}).get("capabilities") or []) if isinstance(v2_surface, dict) else set()
    terminal_unavailable_reason = None
    terminal_unavailable_sources: list[str] = []
    if isinstance(v2_surface, dict) and v2_surface.get("source") == "unavailable":
        terminal_unavailable_reason = (
            v2_surface.get("degraded_reason")
            or (v2_surface.get("pending_input_detection") or {}).get("reason")
            or terminal_unavailable_reason
        )
        terminal_unavailable_sources.append("terminal_surface_v2")
    if isinstance(v1_surface, dict) and v1_surface.get("source") == "unavailable":
        terminal_unavailable_reason = (
            v1_surface.get("degraded_reason")
            or v1_surface.get("reason")
            or terminal_unavailable_reason
        )
        terminal_unavailable_sources.append("terminal_surface_v1")
    if stream.get("surface_stream_available") is False:
        terminal_unavailable_reason = stream.get("fallback_reason") or terminal_unavailable_reason
        terminal_unavailable_sources.append("terminal_stream")
    v2_renderable = bool(
        isinstance(v2_surface, dict)
        and v2_surface.get("source") != "unavailable"
        and v2_capabilities
        and ({"cells", "text_snapshot"} & v2_capabilities)
    )
    v1_available = isinstance(v1_surface, dict) and v1_surface.get("source") != "unavailable"

    if v1_available and v2_renderable and v1_pending_state != v2_pending_state:
        if "present" in {v1_pending_state, v2_pending_state} and "none" in {v1_pending_state, v2_pending_state}:
            contradictions.append(_truth_issue(
                "terminal_v1_v2_pending_input_mismatch",
                "error",
                "Terminal state is inconsistent. Refresh the helper before sending input.",
                detail="v1 and v2 disagree about pending input",
                sources=["terminal_surface_v1", "terminal_surface_v2"],
                blocks_control=True,
            ))

    stream_source = str(stream.get("source") or stream.get("terminal_source") or "")
    stream_backend = str(stream.get("backend") or stream_source or "unknown")
    stream_live = bool(stream.get("byte_stream_available")) and stream_source in {
        "broker_vt",
        "script_capture",
    }
    stream_can_control = bool(stream.get("can_control"))

    if v2_renderable:
        selected_surface = "v2"
        selected = v2_surface or {}
        terminal_backend = str(selected.get("backend") or "unknown")
        surface_agreement = "agree"
    elif v1_available:
        selected_surface = "v1_fallback"
        selected = v1_surface or {}
        terminal_backend = str(selected.get("source") or "unknown")
        surface_agreement = "v2_unavailable"
        degradations.append(_truth_issue(
            "v1_terminal_fallback",
            "warning",
            "Read only fallback",
            sources=["terminal_surface_v1"],
        ))
    elif stream_live:
        selected_surface = "live_events"
        selected = {
            "source": stream_source,
            "backend": stream_backend,
            "generation": stream.get("generation"),
            "screen_hash": stream.get("screen_hash"),
            "nonce": stream.get("nonce"),
        }
        terminal_backend = stream_backend
        surface_agreement = "v2_unavailable"
        if terminal_unavailable_reason or terminal_unavailable_sources:
            reason_suffix = f" - {terminal_unavailable_reason}" if terminal_unavailable_reason else ""
            degradations.append(_truth_issue(
                "terminal_surface_v2_unavailable",
                "warning",
                f"Using live terminal events{reason_suffix}",
                sources=terminal_unavailable_sources or ["terminal_surface_v2"],
                blocks_control=False,
            ))
    else:
        selected_surface = "none"
        selected = {}
        terminal_backend = "unavailable"
        surface_agreement = "not_applicable"

    if any(issue["code"] == "terminal_v1_v2_pending_input_mismatch" for issue in contradictions):
        selected_surface = "blocked_by_contradiction"
        terminal_state = "contradictory"
        surface_agreement = "pending_input_mismatch"
    elif selected_surface == "v2" and v2_detection.get("status") not in {"ran", "not_applicable"}:
        terminal_state = "degraded"
        degradations.append(_truth_issue(
            "v2_pending_input_detection_unavailable",
            "warning",
            "Terminal input detection is unavailable on this helper.",
            sources=["terminal_surface_v2"],
            blocks_control=True,
        ))
    elif isinstance(selected.get("pending_input"), dict):
        terminal_state = "needs_input"
    elif selected_surface == "none":
        terminal_state = "unavailable"
        if terminal_unavailable_reason or terminal_unavailable_sources:
            reason_suffix = f" - {terminal_unavailable_reason}" if terminal_unavailable_reason else ""
            degradations.append(_truth_issue(
                "terminal_surface_unavailable",
                "warning",
                f"Terminal unavailable{reason_suffix}",
                sources=terminal_unavailable_sources or ["terminal_surface"],
                blocks_control=True,
            ))
    elif selected.get("degraded_reason"):
        terminal_state = "degraded"
    else:
        terminal_state = "live"

    transcript_state = str(transcript.get("state") or "unknown")
    if transcript_state in {"missing", "unresolvable", "unavailable"}:
        transcript.setdefault("durable", False)
        transcript.setdefault("searchable", False)
        transcript.setdefault("user_message", "Live terminal only - not in transcript")
        degradations.append(_truth_issue(
            f"transcript_{transcript_state}" if transcript_state != "missing" else "transcript_missing",
            "warning",
            str(transcript.get("user_message") or "Live terminal only - not in transcript"),
            sources=["transcript"],
        ))
    else:
        transcript.setdefault("durable", True)
        transcript.setdefault("searchable", True)

    if runtime.get("runtime_matches_app_source") is False:
        runtime_mismatch_code = str(runtime.get("mismatch_reason") or "runtime_source_mismatch")
        runtime_mismatch_message = (
            "Runtime source has uncommitted changes"
            if runtime_mismatch_code == "runtime_source_dirty"
            else "Runtime stale - source mismatch"
        )
        degradations.append(_truth_issue(
            runtime_mismatch_code,
            "warning",
            runtime_mismatch_message,
            sources=["runtime"],
        ))
    elif runtime.get("runtime_match_confidence") == "revision_drift":
        degradations.append(_truth_issue(
            "runtime_revision_drift",
            "warning",
            "Mac runtime is from a different commit than the app",
            sources=["runtime"],
        ))
    elif runtime.get("runtime_matches_app_source") is None or runtime.get("runtime_match_confidence") == "unknown":
        degradations.append(_truth_issue(
            "runtime_source_unknown",
            "warning",
            "Runtime source parity unknown",
            sources=["runtime"],
        ))

    if not process:
        process = {
            "state": "unknown",
            "source": "unverified",
            "reason": "process_truth_not_sampled",
        }
    if process.get("state") in {None, "", "unknown"}:
        degradations.append(_truth_issue(
            "process_truth_missing",
            "warning",
            "Process truth unavailable",
            sources=["process"],
        ))

    if selected_surface == "v2" and terminal_state in {"live", "needs_input"}:
        control_state = "eligible" if "control_receipts" in v2_capabilities and selected.get("screen_hash") and selected.get("nonce") else "read_only"
        blocked_reason = None if control_state == "eligible" else "surface_not_controllable"
    elif selected_surface == "live_events" and terminal_state in {"live", "needs_input"}:
        control_state = "eligible" if stream_can_control else "read_only"
        blocked_reason = None if control_state == "eligible" else "live_events_read_only"
    elif terminal_state in {"contradictory", "degraded"}:
        control_state = "blocked"
        blocked_reason = contradictions[0]["code"] if contradictions else "terminal_surface_degraded"
    elif selected_surface == "v1_fallback":
        control_state = "read_only"
        blocked_reason = "v1_fallback"
    else:
        control_state = "unavailable"
        blocked_reason = "terminal_surface_unavailable"

    control = {
        "state": control_state,
        "basis_surface": selected_surface,
        "schema_version": 2 if selected_surface == "v2" else 1,
        "screen_hash": selected.get("screen_hash"),
        "nonce": selected.get("nonce"),
        "generation": selected.get("generation"),
        "visible_surface_matches_control_basis": control_state == "eligible",
        "blocked_reason": blocked_reason,
        "supported_actions": (
            ["choice", "text", "key", "interrupt"]
            if control_state == "eligible" and selected_surface == "v2"
            else (["text", "interrupt"] if control_state == "eligible" else [])
        ),
    }

    if contradictions:
        primary = "Terminal state inconsistent"
        tone = "error"
    elif terminal_state == "needs_input":
        primary = "Terminal awaiting selection"
        tone = "attention"
    elif runtime.get("runtime_matches_app_source") is False:
        primary = "Runtime stale"
        tone = "warning"
    elif any(issue["code"] == "runtime_source_unknown" for issue in degradations):
        primary = str(registry.get("working_on") or "Runtime source unknown")
        tone = "warning"
    elif any(issue["code"] == "runtime_revision_drift" for issue in degradations):
        primary = str(registry.get("working_on") or "Runtime revision drift")
        tone = "warning"
    elif any(issue["code"] == "terminal_surface_unavailable" for issue in degradations):
        primary = str(registry.get("working_on") or "Terminal unavailable")
        tone = "warning"
    elif terminal_state == "degraded":
        primary = "Terminal degraded"
        tone = "warning"
    elif registry.get("working_on"):
        primary = str(registry.get("working_on"))
        tone = "normal"
    elif terminal_state == "live":
        primary = "Live terminal"
        tone = "normal"
    else:
        primary = "Terminal unavailable"
        tone = "muted"
    secondary_parts: list[str] = []
    for issue in degradations:
        if issue["code"] == "terminal_surface_unavailable" and issue.get("user_message"):
            secondary_parts.append(str(issue["user_message"]))
        if issue["code"] == "terminal_surface_v2_unavailable" and issue.get("user_message"):
            secondary_parts.append(str(issue["user_message"]))
        if issue["code"] == "runtime_source_unknown" and issue.get("user_message"):
            secondary_parts.append(str(issue["user_message"]))
        if issue["code"] == "runtime_revision_drift" and issue.get("user_message"):
            secondary_parts.append(str(issue["user_message"]))
    if transcript.get("user_message"):
        secondary_parts.append(str(transcript.get("user_message")))
    secondary = " · ".join(dict.fromkeys(part for part in secondary_parts if part))
    if not secondary and registry.get("readable_state") == "stale":
        secondary = "Registry stale"

    turn["reconciled_role"] = "secondary" if terminal_state in {"needs_input", "contradictory"} else turn.get("reconciled_role", "primary")
    terminal = {
        "state": terminal_state,
        "backend": terminal_backend,
        "selected_surface": selected_surface,
        "surface_agreement": surface_agreement,
        "v1": v1_surface,
        "v2": v2_surface,
        "pending_input": selected.get("pending_input") if selected_surface != "blocked_by_contradiction" else (v1_pending or v2_pending),
        "pending_input_detection": (
            v2_detection
            if selected_surface in {"v2", "blocked_by_contradiction"}
            else (
                {
                    "status": "not_applicable",
                    "parser_version": None,
                    "surface": "live_events",
                    "confidence": None,
                    "reason": "live event stream does not expose pending input semantics",
                }
                if selected_surface == "live_events"
                else _surface_detection(v1_surface, version="v1")
            )
        ),
        "stream": stream,
        "user_message": primary,
    }
    summary_blocks_control = bool(
        control_state == "blocked"
        or any(issue.get("blocks_control") for issue in [*contradictions, *degradations])
    )
    return {
        "schema_version": 1,
        "session_id": session_id,
        "provider": provider,
        "native_id": native_id,
        "project": registry.get("project"),
        "checked_at": _time.time(),
        "runtime": runtime,
        "registry": registry,
        "process": process,
        "turn": turn,
        "transcript": transcript,
        "terminal": terminal,
        "control": control,
        "summary": {
            "primary_label": primary,
            "secondary_label": secondary,
            "tone": tone,
            "requires_attention": terminal_state == "needs_input",
            "blocks_control": summary_blocks_control,
            "selected_surface": selected_surface,
            "degradation_codes": [issue["code"] for issue in degradations],
            "contradiction_codes": [issue["code"] for issue in contradictions],
        },
        "contradictions": contradictions,
        "degradations": degradations,
    }


def _session_runtime_truth_stream_digest(truth: dict) -> str:
    material = {
        "schema_version": truth.get("schema_version"),
        "session_id": truth.get("session_id"),
        "terminal": truth.get("terminal") or {},
        "transcript": truth.get("transcript") or {},
        "runtime": truth.get("runtime") or {},
        "process": truth.get("process") or {},
        "control": truth.get("control") or {},
        "summary": truth.get("summary") or {},
        "contradictions": truth.get("contradictions") or [],
        "degradations": truth.get("degradations") or [],
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _session_runtime_truth_stream_payload(truth: dict) -> dict:
    """Truth payload for SSE streams. The raw v1/v2 surface bodies are
    stripped: the phone's truth decoder ignores them, and a tall Terminal
    screen pushes the event past the 64KB SSE cap — which wedged
    session-live-events at `event_too_large` right after `hello` once the
    v1 surface read was repaired. Screen bodies ride the dedicated surface
    endpoints/streams instead."""
    terminal = truth.get("terminal")
    if not isinstance(terminal, dict):
        return truth
    slim = dict(truth)
    slim["terminal"] = {k: v for k, v in terminal.items() if k not in ("v1", "v2")}
    return slim


def _terminal_stream_diagnostics_from_truth(truth: dict) -> dict:
    terminal = truth.get("terminal") or {}
    v1 = terminal.get("v1") or {}
    v2 = terminal.get("v2") or {}
    return {
        "ok": True,
        "schema_version": 1,
        "session_id": truth.get("session_id"),
        "provider": truth.get("provider"),
        "native_id": truth.get("native_id"),
        "checked_at": _time.time(),
        "selected_source": v2.get("source") or v1.get("source") or "unavailable",
        "selected_backend": terminal.get("backend"),
        "stream": terminal.get("stream") or {},
        "surfaces": {
            "v1": {
                "available": bool(v1),
                "source": v1.get("source"),
                "generation": v1.get("generation"),
                "screen_hash": v1.get("screen_hash"),
                "pending_input_state": _surface_pending_input_state(v1, version="v1") if v1 else "unknown",
            },
            "v2": {
                "available": bool(v2),
                "source": v2.get("source"),
                "generation": v2.get("generation"),
                "screen_hash": v2.get("screen_hash"),
                "pending_input_state": _surface_pending_input_state(v2, version="v2") if v2 else "unknown",
                "pending_input_detection": _surface_detection(v2, version="v2") if v2 else None,
            },
            "agreement": terminal.get("surface_agreement"),
        },
        "transcript": truth.get("transcript") or {},
        "control": truth.get("control") or {},
        "runtime": {
            "source_revision": (truth.get("runtime") or {}).get("source_revision"),
            "runtime_matches_app_source": (truth.get("runtime") or {}).get("runtime_matches_app_source"),
        },
        "contradictions": truth.get("contradictions") or [],
        "degradations": truth.get("degradations") or [],
    }


def _terminal_workspace_from_truth(truth: dict) -> dict:
    terminal = truth.get("terminal") or {}
    v2 = terminal.get("v2") if isinstance(terminal.get("v2"), dict) else None
    workspace = {
        "ok": True,
        "schema_version": 1,
        "session_id": truth.get("session_id"),
        "provider": truth.get("provider"),
        "native_id": truth.get("native_id"),
        "checked_at": _time.time(),
        "truth": truth,
        "terminal_surface_v2": v2,
        "diagnostics": _terminal_stream_diagnostics_from_truth(truth),
        "transcript": truth.get("transcript") or {},
        "control": truth.get("control") or {},
        "summary": truth.get("summary") or {},
        "stream_policy": {
            "default_streams": ["terminal-workspace-stream"],
            "included": ["session_runtime_truth", "terminal_surface_v2", "stream_diagnostics", "transcript_truth", "control_basis"],
            "lazy_streams": ["transcript-stream"],
            "fallback_streams": ["terminal-surface-stream", "terminal-stream"],
            "v1_fallback_is_read_only": True,
        },
    }
    return workspace


def _terminal_workspace_stream_digest(workspace: dict) -> str:
    material = {
        "schema_version": workspace.get("schema_version"),
        "session_id": workspace.get("session_id"),
        "truth": workspace.get("truth") or {},
        "terminal_surface_v2": workspace.get("terminal_surface_v2") or {},
        "stream_policy": workspace.get("stream_policy") or {},
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


TERMINAL_CONTROL_AUDIT_PATH = HOME / ".claude" / "audit" / "terminal-control.jsonl"
CONTROL_RECEIPT_AUDIT_PATH = HOME / ".claude" / "audit" / "control-receipts.jsonl"
_CONTROL_RECEIPTS: dict[str, dict] = {}
_SESSION_LIVE_RECEIPTS_LOCK = threading.Lock()
_SESSION_LIVE_RECEIPTS: dict[str, list[dict]] = {}
_SESSION_LIVE_RECEIPT_SEQ = 0
_SESSION_LIVE_RECEIPT_RING_LIMIT = 500
TERMINAL_CONTROL_ALLOWED_KEYS = {
    "enter",
    "escape",
    "up",
    "down",
    "left",
    "right",
    "ctrl_c",
}
TERMINAL_CONTROL_KEY_CODES = {
    "enter": 36,
    "escape": 53,
    "up": 126,
    "down": 125,
    "left": 123,
    "right": 124,
}
TERMINAL_CONTROL_TEXT_MAX_CHARS = TERMINAL_TEXT_SUBMIT_MAX_CHARS


def _receipt_body_hash(material) -> str:
    if isinstance(material, bytes):
        data = material
    elif isinstance(material, str):
        data = material.encode()
    else:
        data = json.dumps(material, sort_keys=True).encode()
    return hashlib.sha256(data).hexdigest()


def _receipt_key(device_id: str | None, session_id: str, client_action_id: str) -> str:
    return "|".join([str(device_id or "legacy-device"), session_id, client_action_id])


def _session_live_receipt_aliases(session_id: str) -> set[str]:
    aliases = {str(session_id or "").strip()}
    provider, native_id = _parse_agent_session_ref(session_id)
    if native_id:
        aliases.add(_qualified_session_id(provider, native_id))
        aliases.add(native_id)
    return {alias for alias in aliases if alias}


def _append_session_live_control_receipt(
    *,
    device_id: str | None,
    session_id: str,
    client_action_id: str | None,
    action_kind: str,
    receipt: dict,
    audit_action: dict | None = None,
) -> dict:
    global _SESSION_LIVE_RECEIPT_SEQ
    with _SESSION_LIVE_RECEIPTS_LOCK:
        _SESSION_LIVE_RECEIPT_SEQ += 1
        event = {
            "receipt_seq": _SESSION_LIVE_RECEIPT_SEQ,
            "observed_at": _time.time(),
            "device_id": device_id,
            "session_id": session_id,
            "client_action_id": client_action_id,
            "action_kind": action_kind,
            "action": audit_action,
            "receipt": receipt,
        }
        for alias in _session_live_receipt_aliases(session_id):
            ring = _SESSION_LIVE_RECEIPTS.setdefault(alias, [])
            ring.append(event)
            if len(ring) > _SESSION_LIVE_RECEIPT_RING_LIMIT:
                del ring[: len(ring) - _SESSION_LIVE_RECEIPT_RING_LIMIT]
        return dict(event)


def _session_live_control_receipts_since(session_id: str, since_seq: int = 0) -> list[dict]:
    seen: set[int] = set()
    events: list[dict] = []
    with _SESSION_LIVE_RECEIPTS_LOCK:
        for alias in _session_live_receipt_aliases(session_id):
            for event in _SESSION_LIVE_RECEIPTS.get(alias, []):
                seq = int(event.get("receipt_seq") or 0)
                if seq <= since_seq or seq in seen:
                    continue
                seen.add(seq)
                events.append(dict(event))
    events.sort(key=lambda event: int(event.get("receipt_seq") or 0))
    return events


def _receipt_phases(*, validated: bool, applied: bool, pty_written: bool) -> dict:
    return {
        "received": True,
        "validated": bool(validated),
        "applied": bool(applied),
        "pty_written": bool(pty_written),
    }


def _make_action_receipt(
    *,
    client_action_id: str | None,
    state: str,
    deduped: bool = False,
    idempotent: bool | None = None,
    phases: dict | None = None,
    backend: str | None = None,
    tty: str | None = None,
    pid: int | None = None,
    source_offset_after: int | None = None,
    source_offset_reason: str | None = None,
) -> dict:
    if idempotent is None:
        idempotent = bool(client_action_id)
    receipt = {
        "client_action_id": client_action_id,
        "state": state,
        "deduped": bool(deduped),
        "idempotent": bool(idempotent),
        "phases": phases or _receipt_phases(validated=False, applied=False, pty_written=False),
        "backend": backend,
        "tty": tty,
        "pid": pid,
        "source_offset_after": source_offset_after,
        "source_offset_reason": source_offset_reason,
        "server_ts": _time.time(),
    }
    return {k: v for k, v in receipt.items() if v is not None}


def _append_control_receipt_audit(entry: dict) -> None:
    try:
        CONTROL_RECEIPT_AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONTROL_RECEIPT_AUDIT_PATH, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
    except Exception:
        pass


def _receipt_duplicate_response(device_id: str | None, session_id: str, client_action_id: str, body_hash: str) -> tuple[dict | None, dict | None]:
    if not client_action_id:
        return None, None
    key = _receipt_key(device_id, session_id, client_action_id)
    existing = _CONTROL_RECEIPTS.get(key)
    if not existing:
        return None, None
    if existing.get("body_hash") != body_hash:
        receipt = _make_action_receipt(
            client_action_id=client_action_id,
            state="rejected",
            deduped=True,
            phases=_receipt_phases(validated=False, applied=False, pty_written=False),
        )
        return None, {
            "ok": False,
            "session_id": session_id,
            "receipt": receipt,
            "error": {"code": "idempotency_conflict", "message": "client_action_id was reused with different content"},
            "status": 409,
        }
    receipt = dict(existing.get("receipt") or {})
    receipt["deduped"] = True
    return receipt, None


def _store_action_receipt(
    device_id: str | None,
    session_id: str,
    client_action_id: str | None,
    body_hash: str,
    receipt: dict,
    *,
    action_kind: str,
    audit_action: dict | None = None,
    persist: bool = True,
) -> None:
    if client_action_id and persist:
        key = _receipt_key(device_id, session_id, client_action_id)
        _CONTROL_RECEIPTS[key] = {
            "device_id": device_id,
            "session_id": session_id,
            "client_action_id": client_action_id,
            "action_kind": action_kind,
            "body_hash": body_hash,
            "receipt": receipt,
            "updated_at": _time.time(),
        }
        if len(_CONTROL_RECEIPTS) > 2000:
            for old_key in list(_CONTROL_RECEIPTS.keys())[:500]:
                _CONTROL_RECEIPTS.pop(old_key, None)
    _append_control_receipt_audit({
        "ts": _time.time(),
        "device_id": device_id,
        "session_id": session_id,
        "client_action_id": client_action_id,
        "action_kind": action_kind,
        "body_hash": body_hash,
        "action": audit_action,
        "persisted": bool(client_action_id and persist),
        "receipt": receipt,
    })
    _append_session_live_control_receipt(
        device_id=device_id,
        session_id=session_id,
        client_action_id=client_action_id,
        action_kind=action_kind,
        audit_action=audit_action,
        receipt=receipt,
    )


def _terminal_control_error(code: str, message: str, status: int) -> dict:
    return {"ok": False, "error": {"code": code, "message": message}, "status": status}


def _terminal_control_screen_token(payload: dict) -> str:
    return str(payload.get("screen_hash") or payload.get("nonce") or "").strip()


def _terminal_control_session_id(payload: dict, q: dict) -> tuple[str, dict | None]:
    body_session = str(payload.get("session_id") or "").strip()
    query_values = q.get("session", [""]) if isinstance(q, dict) else [""]
    query_session = str((query_values or [""])[0] or "").strip()
    if body_session and query_session and body_session != query_session:
        return "", _terminal_control_error("session_mismatch", "query session must match body session_id", 400)
    raw_session = body_session or query_session
    if not raw_session:
        return "", _terminal_control_error("missing_session", "session_id is required", 400)
    return raw_session, None


def _terminal_control_normalize_action(payload: dict) -> tuple[dict | None, dict | None]:
    raw_action = payload.get("action")
    if raw_action is None:
        raw_action = payload
    if not isinstance(raw_action, dict):
        return None, _terminal_control_error("bad_action", "action must be a JSON object", 400)

    action_type = str(raw_action.get("type") or raw_action.get("kind") or "").strip().lower()
    if action_type == "key":
        key = str(raw_action.get("key") or "").strip().lower()
        if key not in TERMINAL_CONTROL_ALLOWED_KEYS:
            return None, _terminal_control_error("key_not_allowed", "unsupported terminal key", 400)
        return {"type": "key", "key": key}, None

    if action_type == "choice":
        choice_id = str(raw_action.get("choice_id") or raw_action.get("id") or "").strip()
        if not re.match(r"^[A-Za-z0-9_.:-]{1,64}$", choice_id):
            return None, _terminal_control_error("bad_choice", "choice_id must be a stable symbolic id", 400)
        return {"type": "choice", "choice_id": choice_id}, None

    if action_type == "text":
        text = str(raw_action.get("text") or "")
        mode = str(raw_action.get("mode") or "").strip().lower()
        if mode not in {"submit"}:
            return None, _terminal_control_error("bad_text_mode", "text action requires explicit mode=submit", 400)
        text, sanitize_err = _sanitize_terminal_text_input(
            text,
            allow_newline=False,
            max_chars=TERMINAL_CONTROL_TEXT_MAX_CHARS,
        )
        if sanitize_err:
            return None, _terminal_control_error(
                str(sanitize_err["code"]),
                str(sanitize_err["message"]),
                int(sanitize_err["status"]),
            )
        return {"type": "text", "text": text, "mode": mode}, None

    if action_type == "raw_key":
        if raw_action.get("debug") is not True:
            return None, _terminal_control_error("raw_key_disabled", "raw_key requires explicit debug=true", 400)
        key_code = raw_action.get("key_code")
        if not isinstance(key_code, int) or key_code < 0 or key_code > 255:
            return None, _terminal_control_error("bad_raw_key", "raw_key requires a bounded key_code", 400)
        return {"type": "raw_key", "key_code": key_code, "debug": True}, None

    return None, _terminal_control_error("bad_action", "action type must be key, choice, text, or raw_key", 400)


def _terminal_control_validate_screen(payload: dict, snapshot: dict, action: dict) -> dict | None:
    token = _terminal_control_screen_token(payload)
    if action.get("type") != "raw_key":
        if not token:
            return _terminal_control_error("missing_screen_hash", "latest screen_hash or nonce is required", 409)
        if token != snapshot.get("screen_hash") and token != snapshot.get("nonce"):
            return {
                **_terminal_control_error("stale_screen", "terminal screen advanced; refresh before sending control", 409),
                "current_screen_hash": snapshot.get("screen_hash"),
                "current_nonce": snapshot.get("nonce"),
            }
        snapshot_generation = snapshot.get("generation")
        if snapshot_generation is not None:
            try:
                payload_generation = int(payload.get("generation"))
                snapshot_generation_int = int(snapshot_generation)
            except (TypeError, ValueError):
                return {
                    **_terminal_control_error("missing_generation", "latest terminal generation is required", 409),
                    "current_generation": snapshot_generation,
                }
            if payload_generation != snapshot_generation_int:
                return {
                    **_terminal_control_error("stale_screen", "terminal generation advanced; refresh before sending control", 409),
                    "current_screen_hash": snapshot.get("screen_hash"),
                    "current_nonce": snapshot.get("nonce"),
                    "current_generation": snapshot_generation,
                }

    if action.get("type") == "choice":
        pending = snapshot.get("pending_input") or {}
        choices = pending.get("choices") if isinstance(pending, dict) else []
        ids = {str(choice.get("id")) for choice in choices if isinstance(choice, dict)}
        if action.get("choice_id") not in ids:
            return _terminal_control_error("choice_unavailable", "choice is not present on the current terminal surface", 409)
    return None


def _terminal_control_surface_schema_version(payload: dict) -> tuple[int, dict | None]:
    raw = payload.get("surface_schema_version", 1)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 1, _terminal_control_error("bad_surface_schema_version", "surface_schema_version must be 1 or 2", 400)
    if value not in {1, 2}:
        return value, _terminal_control_error("bad_surface_schema_version", "surface_schema_version must be 1 or 2", 400)
    return value, None


def _terminal_control_v2_availability_error(snapshot: dict) -> dict | None:
    capabilities = set(snapshot.get("capabilities") or [])
    if snapshot.get("source") == "unavailable" or not capabilities:
        return _terminal_control_error("surface_unavailable", "terminal surface is not available for control", 409)
    if snapshot.get("degraded_reason") or "control_receipts" not in capabilities:
        return _terminal_control_error("surface_not_controllable", "terminal surface is read-only; refresh before sending control", 409)
    return None


def _append_terminal_control_audit(entry: dict) -> None:
    try:
        TERMINAL_CONTROL_AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(TERMINAL_CONTROL_AUDIT_PATH, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
    except Exception:
        pass


def _terminal_control_audit_action(action: dict | None) -> dict | None:
    if not isinstance(action, dict):
        return None
    if action.get("type") == "text":
        return {
            "type": "text",
            "mode": action.get("mode"),
            "chars": len(str(action.get("text") or "")),
        }
    return dict(action)


def _codex_terminal_capture_for_registry(reg: dict | None) -> Path | None:
    if not reg:
        return None
    try:
        metadata = json.loads(reg.get("metadata_json") or "{}")
    except Exception:
        return None
    return _terminal_capture_from_metadata(metadata)


def _terminal_script_command(log_path: Path, inner_cmd: str, *,
                             interactive_shell: bool = False) -> str:
    TERMINAL_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    shell_flag = "-ic" if interactive_shell else "-lc"
    return (
        f"/usr/bin/script -q -F -t 0 {shlex.quote(str(log_path))} "
        f"/bin/zsh {shell_flag} {shlex.quote(inner_cmd)}"
    )


def _qualified_session_id(provider: str, native_id: str) -> str:
    return f"{provider}:{native_id}"


def _turn_state_path(provider: str, native_id: str) -> Path:
    # Claude's state-track hook and the Codex hook bridge both write by
    # provider-native id. Claude native ids are mapped to claude_uuid before
    # this helper is used.
    return TURN_STATE_DIR / f"{native_id}.json"


def _write_agent_turn_state(provider: str, native_id: str, state: str, *,
                            tool: str | None = None, effort: str | None = None,
                            started_at: float | None = None,
                            event: str = "daemon",
                            request_nonce: str | None = None,
                            mac_install_id: str | None = None) -> dict:
    now = _time.time()
    prior: dict = {}
    path = _turn_state_path(provider, native_id)
    try:
        if path.is_file():
            prior = json.loads(path.read_text())
    except Exception:
        prior = {}
    payload = {
        "session_id": _qualified_session_id(provider, native_id) if provider == "codex" else native_id,
        "state": state,
        "tool": tool,
        "started_at": float(started_at or prior.get("started_at") or now),
        "last_update": now,
        "effort": effort if effort is not None else prior.get("effort"),
        "event": event,
    }
    if request_nonce:
        payload["request_nonce"] = str(request_nonce)
    if mac_install_id:
        payload["mac_install_id"] = str(mac_install_id)
    try:
        TURN_STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
        tmp.write_text(json.dumps(payload, sort_keys=True))
        tmp.replace(path)
    except Exception:
        pass
    _publish_live_activity_turn_state(provider, native_id, payload)
    return payload


_CODEX_APPROVAL_NONCES: dict[str, str] = {}
_CODEX_APPROVAL_SCREEN_KEYS: dict[str, str] = {}


def _rows_from_broker_snapshot(snapshot: dict | None) -> list[str]:
    if not isinstance(snapshot, dict):
        return []
    rows = snapshot.get("rows")
    if isinstance(rows, list):
        text_rows: list[str] = []
        for row in rows:
            if isinstance(row, str):
                text_rows.append(row)
            elif isinstance(row, dict):
                cells = row.get("cells")
                if isinstance(cells, list):
                    text_rows.append("".join(str(cell.get("text") or "") for cell in cells if isinstance(cell, dict)).rstrip())
        return text_rows
    return []


def _approval_screen_key(snapshot: dict | None) -> str:
    if not isinstance(snapshot, dict):
        return ""
    return ":".join(str(snapshot.get(key) or "") for key in ("screen_hash", "generation", "raw_offset", "nonce"))


def _clear_codex_approval(broker_id: str, session: dict) -> None:
    nonce = _CODEX_APPROVAL_NONCES.pop(broker_id, None)
    _CODEX_APPROVAL_SCREEN_KEYS.pop(broker_id, None)
    native_id = str(session.get("native_id") or "")
    if nonce:
        row = _pending_approval_get(nonce)
        row_state = str((row or {}).get("state") or "")
        if row_state in {"attention", "pending"}:
            _pending_approval_cas(nonce, row_state, "resolved_local")
    if native_id:
        _write_agent_turn_state("codex", native_id, "idle", event="codex_approval_cleared")


def _scan_codex_approvals_once() -> None:
    if PTY_BROKER is None or classify_codex_approval is None:
        return
    try:
        live = {
            str(session.get("session_id") or ""): session
            for session in PTY_BROKER.list_sessions()
            if isinstance(session, dict)
            and session.get("provider") == "codex"
            and session.get("session_id")
            and session.get("native_id")
        }
    except Exception:
        return
    for broker_id, session in live.items():
        try:
            snapshot = PTY_BROKER.snapshot(broker_id)
        except Exception:
            continue
        rows = _rows_from_broker_snapshot(snapshot)
        screen_key = _approval_screen_key(snapshot)
        if _CODEX_APPROVAL_SCREEN_KEYS.get(broker_id) == screen_key and _CODEX_APPROVAL_NONCES.get(broker_id):
            continue
        pending = (snapshot or {}).get("pending_input") if isinstance(snapshot, dict) else None
        if not isinstance(pending, dict):
            pending = None
        approval = classify_codex_approval(pending, rows, screen_key=screen_key)
        if not approval:
            if broker_id in _CODEX_APPROVAL_NONCES:
                _clear_codex_approval(broker_id, session)
            continue
        summary = str(approval.get("summary") or approval.get("command") or "codex approval")[:300]
        dialog_material = "|".join([broker_id, str(approval.get("dialog_key") or screen_key), summary])
        nonce = "codex-scrape-" + hashlib.sha256(dialog_material.encode("utf-8")).hexdigest()[:24]
        _CODEX_APPROVAL_SCREEN_KEYS[broker_id] = screen_key
        if _CODEX_APPROVAL_NONCES.get(broker_id) == nonce:
            continue
        native_id = str(session.get("native_id") or "")
        _pending_approval_record(
            request_nonce=nonce,
            provider="codex",
            session_id=_qualified_session_id("codex", native_id),
            tool_name="Bash",
            tool_input={"command": str(approval.get("command") or ""), "summary": summary},
            command_preview=summary,
            permission_mode="",
            broker_id=broker_id,
            state="attention",
        )
        _CODEX_APPROVAL_NONCES[broker_id] = nonce
        _write_agent_turn_state(
            "codex",
            native_id,
            "attention",
            tool=summary[:80],
            event="codex_approval",
            request_nonce=nonce,
            mac_install_id=getattr(PAIRING_STORE, "install_id", "") if PAIRING_STORE else "",
        )
    for broker_id in list(_CODEX_APPROVAL_NONCES.keys()):
        if broker_id not in live:
            _CODEX_APPROVAL_NONCES.pop(broker_id, None)
            _CODEX_APPROVAL_SCREEN_KEYS.pop(broker_id, None)


def _start_codex_approval_scanner() -> threading.Thread | None:
    if PTY_BROKER is None or classify_codex_approval is None:
        return None
    try:
        interval = max(0.25, float(os.environ.get("PAIRLING_CODEX_APPROVAL_POLL_S", "1.0")))
    except Exception:
        interval = 1.0

    def run() -> None:
        while True:
            try:
                _scan_codex_approvals_once()
            except Exception as exc:
                print(f"[codex-approval-scan] skipped: {type(exc).__name__}: {str(exc)[:120]}", file=sys.stderr, flush=True)
            _time.sleep(interval)

    thread = threading.Thread(target=run, name="pairling-codex-approval-scan", daemon=True)
    thread.start()
    return thread


def _publish_live_activity_turn_state(provider: str, native_id: str, payload: dict) -> None:
    publisher = LIVE_ACTIVITY_PUBLISHER
    if publisher is None or not hasattr(publisher, "publish_turn_state_payload"):
        return
    candidates = [_qualified_session_id(provider, native_id), native_id]
    if provider == "claude":
        resolved = _lookup_claude_session_for_uuid(native_id)
        if resolved:
            candidates.insert(0, f"claude:{resolved}")
    seen: set[str] = set()
    for session_id in candidates:
        session_id = str(session_id or "").strip()
        if not session_id or session_id in seen:
            continue
        seen.add(session_id)
        try:
            publisher.publish_turn_state_payload(session_id=session_id, state_payload=payload)
        except Exception:
            continue


def _claude_native_session_id(raw: str) -> str:
    provider, native_id = _parse_agent_session_ref(raw)
    if provider != "claude" or not _safe_session_id(native_id):
        return ""
    return native_id


def _decorate_claude_session_row(row: dict, native_id: str, claude_pid: int = 0,
                                 terminal_tty: str = "") -> dict:
    row["provider"] = "claude"
    row["native_id"] = native_id
    row["id"] = _qualified_session_id("claude", native_id)
    capabilities = list(CLAUDE_SESSION_CAPABILITIES)
    if terminal_tty and _terminal_capture_for_tty(terminal_tty, row.get("project")):
        capabilities.append("terminal_output")
    if terminal_tty and re.match(r"^/dev/ttys[0-9]{3,}$", terminal_tty):
        capabilities.extend(["terminal_surface", "terminal_control"])
    row["capabilities"] = capabilities
    reason = None
    if not terminal_tty:
        reason = "no terminal_tty for session yet"
    row["controllability"] = {
        "can_send_text": bool(terminal_tty),
        "can_interrupt": claude_pid > 0,
        "can_terminate": claude_pid > 0,
        "reason": reason,
    }
    if terminal_tty:
        _apply_launch_context_to_session_row(
            row,
            _registry_metadata_from_row(_agent_registry_get_by_tty("claude", terminal_tty)),
        )
    return row


def _refresh_claude_observed_activity(row: dict, project: str | None, claude_uuid: str | None) -> None:
    """Use transcript/turn-state evidence to correct stale PG heartbeats."""
    observed = int(row.get("last_heartbeat") or 0)
    turn_update = row.get("turn_state_updated_at")
    if isinstance(turn_update, (int, float)):
        observed = max(observed, int(turn_update))
    if project and claude_uuid:
        transcript = HOME / ".claude" / "projects" / _encode_project_dir(project) / f"{claude_uuid}.jsonl"
        try:
            if transcript.is_file():
                observed = max(observed, int(transcript.stat().st_mtime))
        except OSError:
            pass
    if observed:
        row["last_heartbeat"] = observed


def _iso_to_epoch(value: str | None) -> float:
    if not value:
        return 0.0
    try:
        s = value.replace("Z", "+00:00")
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return 0.0


def _read_jsonl_map(path: Path, id_key: str = "id") -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not path.is_file():
        return out
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except (ValueError, json.JSONDecodeError):
                    continue
                sid = obj.get(id_key)
                if isinstance(sid, str) and sid:
                    out[sid] = obj
    except OSError:
        pass
    return out


def _codex_history_map() -> dict[str, dict]:
    return _read_jsonl_map(CODEX_HISTORY, id_key="session_id")


def _codex_index_map() -> dict[str, dict]:
    return _read_jsonl_map(CODEX_SESSION_INDEX, id_key="id")


def _codex_rollout_meta(path: Path) -> dict | None:
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            first = f.readline()
        if not first:
            return None
        obj = json.loads(first)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
    sid = payload.get("id") or obj.get("id")
    cwd = payload.get("cwd") or obj.get("cwd")
    if not isinstance(sid, str) or not sid or not isinstance(cwd, str) or not cwd:
        return None
    return {
        "id": sid,
        "cwd": cwd,
        "timestamp": payload.get("timestamp") or obj.get("timestamp"),
        "model": payload.get("model"),
    }


def _codex_rollout_paths() -> list[Path]:
    if not CODEX_SESSIONS_DIR.is_dir():
        return []
    now = _time.time()
    cached_ts = float(_codex_rollout_paths_cache.get("ts") or 0)
    if now - cached_ts < CODEX_ROLLOUT_PATHS_CACHE_SECONDS:
        return list(_codex_rollout_paths_cache.get("paths") or [])
    paths: list[Path] = []
    try:
        for p in CODEX_SESSIONS_DIR.rglob("rollout-*.jsonl"):
            if p.is_file():
                paths.append(p)
    except OSError:
        return []
    paths.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    _codex_rollout_paths_cache["ts"] = now
    _codex_rollout_paths_cache["paths"] = paths
    return paths


def _approved_codex_transcript_path(path: Path, native_id: str) -> Path | None:
    if path.suffix != ".jsonl":
        return None
    try:
        root = CODEX_SESSIONS_DIR.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except OSError:
        return None
    try:
        resolved.relative_to(root)
    except ValueError:
        return None
    try:
        if path.is_symlink():
            return None
    except OSError:
        return None
    meta = _codex_rollout_meta(resolved)
    if meta is not None:
        return resolved if meta.get("id") == native_id else None
    return None


def _resolve_codex_transcript(native_id: str) -> Path | None:
    if not _safe_session_id(native_id):
        return None
    reg = _agent_registry_get("codex", native_id)
    if reg:
        try:
            metadata = json.loads(reg.get("metadata_json") or "{}")
            output_path = metadata.get("output_path") if isinstance(metadata, dict) else None
            if isinstance(output_path, str):
                approved = _approved_codex_transcript_path(Path(output_path), native_id)
                if approved is not None:
                    return approved
        except Exception:
            pass
    if not CODEX_SESSIONS_DIR.is_dir():
        return None
    matches = list(CODEX_SESSIONS_DIR.rglob(f"rollout-*{native_id}.jsonl"))
    if matches:
        matches.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
        for match in matches:
            approved = _approved_codex_transcript_path(match, native_id)
            if approved is not None:
                return approved
    for path in _codex_rollout_paths():
        approved = _approved_codex_transcript_path(path, native_id)
        if approved is not None:
            return approved
    return None


def _codex_project_for_session(native_id: str) -> str:
    reg = _agent_registry_get("codex", native_id)
    if reg and reg.get("project"):
        return str(reg["project"])
    path = _resolve_codex_transcript(native_id)
    if path:
        meta = _codex_rollout_meta(path)
        if meta and meta.get("cwd"):
            return meta["cwd"]
    return ""


def _codex_latest_task_boundary(path: Path) -> dict[str, object] | None:
    """Return the latest Codex task_started/task_complete event in a rollout.

    Codex provider sessions do not currently have a Stop hook that writes
    `idle` into Pairling's turn-state file. The rollout transcript does have
    explicit task boundary events, so we use them to end stale spinner state.
    """
    try:
        st = path.stat()
    except OSError:
        return None
    key = str(path)
    cached = _codex_task_boundary_cache.get(key)
    if (
        cached
        and cached.get("mtime_ns") == st.st_mtime_ns
        and cached.get("size") == st.st_size
    ):
        boundary = cached.get("boundary")
        return dict(boundary) if isinstance(boundary, dict) else None

    boundary: dict[str, object] | None = None
    try:
        for raw in _tail_lines(path, max_lines=2000, max_bytes=TRANSCRIPT_TAIL_SCAN_BYTES):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except (ValueError, json.JSONDecodeError):
                continue
            if obj.get("type") != "event_msg":
                continue
            payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
            event_type = payload.get("type")
            if event_type not in {"task_started", "task_complete"}:
                continue
            ts = _iso_to_epoch(obj.get("timestamp")) or st.st_mtime
            boundary = {
                "type": event_type,
                "timestamp": float(ts),
            }
    except OSError:
        boundary = None

    _codex_task_boundary_cache[key] = {
        "mtime_ns": st.st_mtime_ns,
        "size": st.st_size,
        "boundary": dict(boundary) if boundary else None,
    }
    return boundary


def _persist_codex_turn_state(path: Path, payload: dict) -> None:
    try:
        TURN_STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
        tmp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
    except Exception:
        pass
    provider, native_id = _parse_agent_session_ref(str(payload.get("session_id") or path.stem))
    _publish_live_activity_turn_state(provider, native_id or path.stem, payload)


def _apply_codex_task_boundary(native_id: str, payload: dict, state_path: Path) -> dict:
    transcript = _resolve_codex_transcript(native_id)
    if not transcript:
        return payload
    boundary = _codex_latest_task_boundary(transcript)
    if not boundary or boundary.get("type") != "task_complete":
        return payload

    boundary_ts = float(boundary.get("timestamp") or 0)
    last_update = float(payload.get("last_update") or 0)
    if boundary_ts + 0.001 < last_update:
        return payload

    state = str(payload.get("state") or "").strip().lower()
    if state not in {"thinking", "tool", "responding", "starting"}:
        return payload

    updated = dict(payload)
    updated["state"] = "idle"
    updated["tool"] = None
    updated["last_update"] = max(last_update, boundary_ts)
    updated["event"] = "task_complete"
    _persist_codex_turn_state(state_path, updated)
    return updated


def _codex_turn_state_payload(native_id: str, *, apply_boundary: bool = True) -> dict | None:
    if not _safe_agent_native_id(native_id):
        return None
    path = _turn_state_path("codex", native_id)
    if path.is_file():
        try:
            obj = json.loads(path.read_text())
            if isinstance(obj, dict):
                if apply_boundary:
                    obj = _apply_codex_task_boundary(native_id, obj, path)
                obj["session_id"] = _qualified_session_id("codex", native_id)
                obj["provider"] = "codex"
                obj["native_id"] = native_id
                return obj
        except Exception:
            pass
    reg = _agent_registry_get("codex", native_id)
    if not reg:
        return None
    pid = int(reg.get("pid") or 0)
    state = "idle"
    if pid and _process_alive(pid) and not reg.get("closed_at"):
        state = "idle"
    metadata = {}
    try:
        metadata = json.loads(reg.get("metadata_json") or "{}")
    except Exception:
        metadata = {}
    started = float(reg.get("started_at") or _time.time())
    last = float(reg.get("last_heartbeat") or started)
    payload = {
        "session_id": _qualified_session_id("codex", native_id),
        "provider": "codex",
        "native_id": native_id,
        "state": metadata.get("turn_state") or state,
        "tool": metadata.get("tool"),
        "started_at": float(metadata.get("turn_started_at") or started),
        "last_update": last,
        "effort": metadata.get("effort"),
        "event": metadata.get("turn_event") or "registry",
    }
    if apply_boundary:
        return _apply_codex_task_boundary(native_id, payload, path)
    return payload


def _codex_first_prompt(path: Path, session_id: str, history: dict[str, dict]) -> str | None:
    hist = history.get(session_id) or {}
    text = hist.get("text")
    if isinstance(text, str) and text.strip():
        return text.strip()[:500]
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            for _, line in zip(range(200), f):
                rows = _normalize_codex_line(line, session_id)
                for row in rows:
                    msg = row.get("message") or {}
                    if msg.get("role") == "user":
                        content = msg.get("content") or []
                        if content and isinstance(content, list):
                            first = content[0]
                            if isinstance(first, dict):
                                t = first.get("text")
                                if isinstance(t, str) and t.strip():
                                    return t.strip()[:500]
    except OSError:
        pass
    return None


def _codex_control_overlay(row: dict, observed_mtime: float | None = None, *, verify_process: bool = True) -> dict:
    if verify_process:
        reg = _agent_registry_promote_codex(
            row.get("native_id") or "",
            row.get("project") or "",
            float(row.get("started_at") or 0),
        )
    else:
        reg = _agent_registry_get("codex", row.get("native_id") or "")
    if not reg:
        return row
    metadata = _registry_metadata_from_row(reg)
    _apply_launch_context_to_session_row(row, metadata)
    if reg.get("closed_at"):
        row["closed_at"] = int(float(reg.get("closed_at") or _time.time()))
        row["state"] = "terminated"
        row["capabilities"] = [cap for cap in (row.get("capabilities") or []) if cap in {"transcript", "export", "live_state"}]
        row["controllability"] = {
            "can_send_text": False,
            "can_interrupt": False,
            "can_terminate": False,
            "reason": "Session is closed; transcript remains readable.",
        }
        return row
    pid = int(reg.get("pid") or 0)
    tty = reg.get("terminal_tty") or ""
    if verify_process and tty and (not pid or not _process_alive(pid)):
        fresh_pid = _pid_for_tty_command(tty, "codex")
        if fresh_pid:
            pid = fresh_pid
            _agent_registry_upsert("codex", row["native_id"], row["project"], pid=pid, terminal_tty=tty)
    if verify_process and pid and not _process_alive(pid):
        _agent_registry_mark_closed("codex", row["native_id"])
        return row
    state_payload = _codex_turn_state_payload(row.get("native_id") or "", apply_boundary=False)
    can_send = bool(tty)
    can_signal = bool(pid)
    caps = set(row.get("capabilities") or [])
    if state_payload or can_send or can_signal:
        caps.add("live_state")
    caps.update({"send_text", "upload", "commands"} if can_send else set())
    caps.update({"interrupt", "terminate"} if can_signal else set())
    if _codex_terminal_capture_for_registry(reg):
        caps.add("terminal_output")
    surface_caps = _terminal_surface_capabilities(_qualified_session_id("codex", row.get("native_id") or ""))
    caps.update(surface_caps.get("capabilities") or [])
    row["capabilities"] = [cap for cap in CODEX_CONTROL_CAPABILITIES if cap in caps]
    if surface_caps.get("source") == "broker_vt":
        row["terminal_attention"] = _terminal_attention_from_snapshot(
            PTY_BROKER.snapshot(surface_caps.get("broker_id")) if PTY_BROKER and surface_caps.get("broker_id") else None
        )
    row["controllability"] = {
        "can_send_text": can_send,
        "can_interrupt": can_signal,
        "can_terminate": can_signal,
        "reason": None if (can_send or can_signal) else "Codex control metadata is incomplete.",
    }
    if state_payload:
        row["state"] = state_payload.get("state")
        row["tool"] = state_payload.get("tool")
        row["turn_started_at"] = state_payload.get("started_at")
        row["effort"] = state_payload.get("effort")
    if row.get("launch_context") and row.get("model") is None:
        row["model"] = (row["launch_context"] or {}).get("model")
    row["last_heartbeat"] = max(int(row.get("last_heartbeat") or 0), int(reg.get("last_heartbeat") or 0))
    return row


def _codex_pending_registry_rows(seen: set[str], live_only: bool, active_within_min: int) -> list[dict]:
    cutoff = _time.time() - max(1, active_within_min) * 60
    rows: list[dict] = []
    for reg in _agent_registry_live("codex"):
        native_id = reg.get("native_id") or ""
        if not native_id or native_id in seen:
            continue
        heartbeat = float(reg.get("last_heartbeat") or reg.get("started_at") or 0)
        pid = int(reg.get("pid") or 0)
        tty = reg.get("terminal_tty") or ""
        if pid and not _process_alive(pid):
            _agent_registry_mark_closed("codex", native_id)
            continue
        process_alive = bool(pid and _process_alive(pid))
        if live_only and heartbeat < cutoff and not process_alive:
            continue
        stale_seconds = max(0, int(_time.time() - heartbeat)) if heartbeat else 0
        caps = (
            ["live_state"] +
            (["send_text", "upload", "commands"] if tty else []) +
            (["interrupt", "terminate"] if pid else [])
        )
        if _codex_terminal_capture_for_registry(reg):
            caps.append("terminal_output")
        surface_caps = _terminal_surface_capabilities(_qualified_session_id("codex", native_id))
        caps.extend(cap for cap in (surface_caps.get("capabilities") or []) if cap not in caps)
        metadata = _registry_metadata_from_row(reg)
        launch_context = _session_launch_context_from_metadata(metadata)
        row = {
            "id": _qualified_session_id("codex", native_id),
            "provider": "codex",
            "native_id": native_id,
            "project": reg.get("project") or str(HOME),
            "working_on": "New Codex session",
            "started_at": int(reg.get("started_at") or _time.time()),
            "last_heartbeat": int(heartbeat or _time.time()),
            "stale_seconds": stale_seconds,
            "source_freshness": "registry_stale_process_alive" if heartbeat < cutoff and process_alive else "registry_live",
            "first_prompt": None,
            "state": "running",
            "tool": None,
            "turn_started_at": None,
            "effort": None,
            "model": (launch_context or {}).get("model"),
            "context_pct": None,
            "capabilities": caps,
            "controllability": {
                "can_send_text": bool(tty),
                "can_interrupt": bool(pid),
                "can_terminate": bool(pid),
                "reason": None if (tty or pid) else "Codex control metadata is incomplete.",
            },
        }
        if launch_context is not None:
            row["launch_context"] = launch_context
        if surface_caps.get("source") == "broker_vt":
            row["terminal_attention"] = _terminal_attention_from_snapshot(
                PTY_BROKER.snapshot(surface_caps.get("broker_id")) if PTY_BROKER and surface_caps.get("broker_id") else None
            )
        rows.append(row)
    return rows


def _codex_recent_closed_registry_rows(seen: set[str], active_within_min: int) -> list[dict]:
    rows: list[dict] = []
    for reg in _agent_registry_recent("codex", since_min=active_within_min, limit=300):
        if not reg.get("closed_at"):
            continue
        native_id = reg.get("native_id") or ""
        if not native_id or native_id in seen:
            continue
        try:
            metadata = json.loads(reg.get("metadata_json") or "{}")
            if not isinstance(metadata, dict):
                metadata = {}
        except Exception:
            metadata = {}
        started_at = int(float(reg.get("started_at") or reg.get("last_heartbeat") or _time.time()))
        last_heartbeat = int(float(reg.get("last_heartbeat") or started_at))
        closed_at = int(float(reg.get("closed_at") or last_heartbeat))
        transcript_path = _resolve_codex_transcript(native_id)
        turn_stats = _session_transcript_stats(transcript_path, "codex", native_id)
        first_prompt = metadata.get("first_prompt")
        if not first_prompt and transcript_path:
            first_prompt = _codex_first_prompt(transcript_path, native_id, _codex_history_map())
        capabilities = ["live_state"]
        if transcript_path:
            capabilities = CODEX_READ_ONLY_CAPABILITIES + ["live_state"]
        row = {
            "id": _qualified_session_id("codex", native_id),
            "provider": "codex",
            "native_id": native_id,
            "project": reg.get("project") or str(HOME),
            "working_on": metadata.get("working_on") or "Closed Codex session",
            "started_at": started_at,
            "last_heartbeat": last_heartbeat,
            "closed_at": closed_at,
            "stale_seconds": max(0, int(_time.time() - last_heartbeat)) if last_heartbeat else 0,
            "source_freshness": "registry_closed",
            "first_prompt": first_prompt,
            "state": "terminated",
            "tool": None,
            "turn_started_at": None,
            "effort": metadata.get("effort"),
            "model": metadata.get("model"),
            "context_pct": None,
            "turn_count": turn_stats.get("turn_count"),
            "capabilities": capabilities,
            "controllability": {
                "can_send_text": False,
                "can_interrupt": False,
                "can_terminate": False,
                "reason": "Session is closed; transcript remains readable.",
            },
        }
        _apply_launch_context_to_session_row(row, metadata)
        rows.append(row)
        seen.add(native_id)
    return rows


def _list_codex_sessions(live_only: bool, active_within_min: int) -> list[dict]:
    return _cached_runtime_snapshot(
        ("list-codex-sessions", str(HOME), bool(live_only), int(active_within_min or 0)),
        RUNTIME_SNAPSHOT_CACHE_SECONDS,
        lambda: _list_codex_sessions_uncached(live_only, active_within_min),
    )


def _list_codex_sessions_uncached(live_only: bool, active_within_min: int) -> list[dict]:
    """Read-only Codex provider: persisted rollouts, no process control yet."""
    index = _codex_index_map()
    history = _codex_history_map()
    cutoff = _time.time() - max(1, active_within_min) * 60
    rows: list[dict] = []
    seen: set[str] = set()
    for path in _codex_rollout_paths():
        try:
            st = path.stat()
        except OSError:
            continue
        if live_only and st.st_mtime < cutoff:
            continue
        meta = _codex_rollout_meta(path)
        if not meta:
            continue
        sid = meta["id"]
        if sid in seen:
            continue
        seen.add(sid)
        idx = index.get(sid) or {}
        first_prompt = _codex_first_prompt(path, sid, history)
        started = int(_iso_to_epoch(meta.get("timestamp")) or st.st_mtime)
        working_on = idx.get("thread_name") if isinstance(idx.get("thread_name"), str) else None
        turn_stats = (
            _session_transcript_stats(path, "codex", sid)
            if st.st_size <= TRANSCRIPT_STATS_MAX_SCAN_BYTES
            else {"turn_count": None, "partial": True}
        )
        row = {
            "id": _qualified_session_id("codex", sid),
            "provider": "codex",
            "native_id": sid,
            "project": meta["cwd"],
            "working_on": working_on or first_prompt,
            "started_at": started,
            "last_heartbeat": int(st.st_mtime),
            "first_prompt": first_prompt,
            "state": None,
            "tool": None,
            "turn_started_at": None,
            "effort": None,
            "model": meta.get("model"),
            "context_pct": None,
            "turn_count": turn_stats.get("turn_count"),
            "capabilities": CODEX_READ_ONLY_CAPABILITIES,
            "controllability": {
                "can_send_text": False,
                "can_interrupt": False,
                "can_terminate": False,
                "reason": "Codex sessions are read-only until control metadata is captured.",
            },
        }
        state_payload = _codex_turn_state_payload(sid, apply_boundary=False)
        if state_payload:
            row["capabilities"] = CODEX_READ_ONLY_CAPABILITIES + ["live_state"]
            row["state"] = state_payload.get("state")
            row["tool"] = state_payload.get("tool")
            row["turn_started_at"] = state_payload.get("started_at")
            row["effort"] = state_payload.get("effort")
        rows.append(_codex_control_overlay(row, st.st_mtime, verify_process=False))
        if len(rows) >= 50:
            break
    rows.extend(_codex_pending_registry_rows(seen, live_only, active_within_min))
    if not live_only:
        rows.extend(_codex_recent_closed_registry_rows(seen, active_within_min))
    rows.sort(
        key=lambda r: (
            1 if (r.get("controllability") or {}).get("can_terminate") else 0,
            int(r.get("last_heartbeat") or 0),
        ),
        reverse=True,
    )
    rows = rows[:50]
    return rows


def _text_from_codex_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        pieces: list[str] = []
        for item in value:
            if isinstance(item, dict):
                t = item.get("text") or item.get("content") or item.get("output_text")
                if isinstance(t, str):
                    pieces.append(t)
            elif isinstance(item, str):
                pieces.append(item)
        return "\n".join(pieces)
    if isinstance(value, dict):
        for key in ("text", "message", "content", "output_text"):
            if isinstance(value.get(key), str):
                return value[key]
        try:
            return json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)
    return str(value)


def _codex_content_blocks(content) -> list[dict]:
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    if isinstance(content, list):
        blocks: list[dict] = []
        for item in content:
            if not isinstance(item, dict):
                if isinstance(item, str):
                    blocks.append({"type": "text", "text": item})
                continue
            typ = item.get("type")
            if typ in ("text", "output_text", "input_text"):
                text = item.get("text") or item.get("content") or ""
                if text:
                    blocks.append({"type": "text", "text": text})
            elif typ == "reasoning":
                text = _text_from_codex_value(item.get("summary") or item.get("content"))
                if text:
                    blocks.append({"type": "thinking", "thinking": text})
            else:
                text = item.get("text") or item.get("content")
                if isinstance(text, str) and text:
                    blocks.append({"type": "text", "text": text})
        return blocks
    text = _text_from_codex_value(content)
    return [{"type": "text", "text": text}] if text else []


def _codex_row_semantic_key(role: str, blocks: list[dict]) -> str:
    parts: list[str] = [role]
    for block in blocks:
        if not isinstance(block, dict):
            continue
        btype = str(block.get("type") or "")
        parts.append(btype)
        if btype == "text":
            parts.append(_text_from_codex_value(block.get("text")).strip())
        elif btype == "thinking":
            parts.append(_text_from_codex_value(block.get("thinking")).strip())
        elif btype == "tool_use":
            parts.append(str(block.get("id") or ""))
            parts.append(str(block.get("name") or ""))
        elif btype == "tool_result":
            parts.append(str(block.get("tool_use_id") or ""))
            parts.append(_text_from_codex_value(block.get("content")).strip())
        else:
            parts.append(_text_from_codex_value(block).strip())
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8", errors="replace")).hexdigest()
    return digest[:24]


def _strip_codex_row_metadata(row: dict) -> dict:
    if "_codex_source" not in row and "_codex_semantic_key" not in row:
        return row
    clean = dict(row)
    clean.pop("_codex_source", None)
    clean.pop("_codex_semantic_key", None)
    return clean


def _normalize_codex_line(
    line: str | bytes,
    session_id: str,
    *,
    include_event_messages: bool = False,
    with_metadata: bool = False,
) -> list[dict]:
    if isinstance(line, bytes):
        line = line.decode("utf-8", errors="replace")
    if not line.strip():
        return []
    try:
        obj = json.loads(line)
    except (ValueError, json.JSONDecodeError):
        return []
    ts = obj.get("timestamp")
    payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
    typ = obj.get("type")
    rows: list[dict] = []

    def row(role: str, blocks: list[dict], suffix: str, source: str) -> None:
        if not blocks:
            return
        stable = hashlib.sha256((line + suffix).encode("utf-8", errors="replace")).hexdigest()[:16]
        out = {
            "uuid": f"codex-{stable}",
            "type": role,
            "timestamp": ts,
            "sessionId": _qualified_session_id("codex", session_id),
            "message": {
                "role": role,
                "content": blocks,
            },
        }
        if with_metadata:
            out["_codex_source"] = source
            out["_codex_semantic_key"] = _codex_row_semantic_key(role, blocks)
        rows.append(out)

    if typ == "event_msg":
        if not include_event_messages:
            return rows
        event_type = payload.get("type")
        if event_type == "user_message":
            text = _text_from_codex_value(payload.get("message") or payload.get("text") or payload.get("content"))
            row("user", [{"type": "text", "text": text}], "user", "event_msg")
        elif event_type == "agent_message":
            text = _text_from_codex_value(payload.get("message") or payload.get("text") or payload.get("content"))
            row("assistant", [{"type": "text", "text": text}], "agent", "event_msg")
        elif event_type == "exec_command_end":
            text = _text_from_codex_value(payload.get("aggregated_output") or payload.get("stdout") or payload)
            row("assistant", [{"type": "tool_result", "tool_use_id": payload.get("call_id"), "content": text}], "exec-end", "event_msg")
        return rows

    if typ != "response_item":
        return rows

    item_type = payload.get("type")
    if item_type == "message":
        role = payload.get("role") if payload.get("role") in ("user", "assistant") else "assistant"
        blocks = _codex_content_blocks(payload.get("content"))
        row(role, blocks, "message", "response_item")
    elif item_type == "reasoning":
        text = _text_from_codex_value(payload.get("summary") or payload.get("content"))
        if text:
            row("assistant", [{"type": "thinking", "thinking": text}], "reasoning", "response_item")
    elif item_type == "function_call":
        args = payload.get("arguments") or payload.get("input") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (ValueError, json.JSONDecodeError):
                args = {"arguments": args}
        row("assistant", [{
            "type": "tool_use",
            "id": payload.get("call_id") or payload.get("id"),
            "name": payload.get("name") or payload.get("tool_name") or "tool",
            "input": args,
        }], "tool-use", "response_item")
    elif item_type == "function_call_output":
        content = payload.get("output") or payload.get("content") or payload.get("tool_response")
        row("assistant", [{
            "type": "tool_result",
            "tool_use_id": payload.get("call_id") or payload.get("tool_use_id"),
            "content": _text_from_codex_value(content),
        }], "tool-result", "response_item")
    return rows


def _normalize_codex_ndjson(
    data: bytes | str,
    session_id: str,
    *,
    include_event_fallback: bool = True,
) -> str:
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="replace")
    else:
        text = data
    rows: list[dict] = []
    canonical_keys: set[str] = set()
    for line in text.splitlines():
        for row in _normalize_codex_line(
            line,
            session_id,
            include_event_messages=include_event_fallback,
            with_metadata=True,
        ):
            if row.get("_codex_source") != "event_msg":
                key = row.get("_codex_semantic_key")
                if isinstance(key, str):
                    canonical_keys.add(key)
            rows.append(row)
    out: list[str] = []
    for row in rows:
        if row.get("_codex_source") == "event_msg":
            key = row.get("_codex_semantic_key")
            if isinstance(key, str) and key in canonical_keys:
                continue
        out.append(json.dumps(_strip_codex_row_metadata(row), ensure_ascii=False))
    return "\n".join(out) + ("\n" if out else "")


TRANSCRIPT_HARNESS_BLOCK_TAGS = (
    "system-reminder",
    "task-notification",
    "persisted-output",
    "command-name",
    "command-message",
    "command-args",
    "local-command-caveat",
    "local-command-stdout",
    "local-command-stderr",
    "oai-mem-citation",
)

_TRANSCRIPT_EXPORT_CLEANUP_PATTERNS = [
    (re.compile(r"\[Image: source: /(?:Users|var|tmp|private)/[^\]]+\]\s*"), ""),
    (re.compile(r"^\s*Output too large.*$\n?", re.MULTILINE), ""),
    (re.compile(r"^\s*Preview \(first.*$\n?", re.MULTILINE), ""),
]


def _strip_transcript_harness_blocks(text: str) -> str:
    for tag in TRANSCRIPT_HARNESS_BLOCK_TAGS:
        escaped = re.escape(tag)
        text = re.sub(rf"<{escaped}>.*?</{escaped}>\s*", "", text, flags=re.DOTALL)
    return text


def _clean_transcript_export_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    text = _strip_transcript_harness_blocks(text)
    for pat, repl in _TRANSCRIPT_EXPORT_CLEANUP_PATTERNS:
        text = pat.sub(repl, text)
    # Strip standalone "." lines — bracketed-paste flush artifact.
    text = re.sub(r"^\s*\.\s*$", "", text, flags=re.MULTILINE)
    # Collapse runs of blank lines.
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text


def _as_escape(s: str) -> str:
    """Escape a Python string for embedding in an AppleScript double-quoted literal."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


_ABSOLUTE_PATH_ROOT_TOKENS = {
    "Applications",
    "Library",
    "System",
    "Users",
    "Volumes",
    "bin",
    "dev",
    "etc",
    "home",
    "opt",
    "private",
    "sbin",
    "tmp",
    "usr",
    "var",
}


def _is_direct_slash_invocation_text(text: str) -> bool:
    """Return true only for slash commands that need typed input semantics.

    Absolute file paths also begin with "/", and uploaded-file feedback often
    starts with /Users/... . Those must stay on the bracketed-paste path so the
    agent receives a normal prompt instead of entering slash-command UI state.
    """
    if "\n" in text or not text.startswith("/") or text.startswith("//"):
        return False
    token = text.split(maxsplit=1)[0]
    if "/" in token[1:]:
        return False
    command = token[1:]
    if not command or command in _ABSOLUTE_PATH_ROOT_TOKENS:
        return False
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*(?::[A-Za-z][A-Za-z0-9_-]*)*", command))


CLAUDE_INJECTOR = HOME / "Applications" / "ClaudeInjector.app" / "Contents" / "MacOS" / "ClaudeInjector"


def _run_osascript(script: str, *, timeout: float = 15.0) -> dict:
    """Run AppleScript via ClaudeInjector.app wrapper if present (so macOS
    Accessibility can be granted to a normal .app instead of the hardened
    python3.13 runtime). Falls back to direct osascript."""
    if CLAUDE_INJECTOR.exists():
        cmd = [str(CLAUDE_INJECTOR), "-e", script]
    else:
        cmd = ["osascript", "-e", script]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "reason": "applescript timeout"}
    out = proc.stdout.strip()
    err = proc.stderr.strip()
    if proc.returncode != 0:
        # error -1719 / -1743 = Accessibility permission missing
        return {"ok": False, "reason": f"applescript err: {err[:200]}"}
    if out == "no_window":
        return {"ok": False, "reason": "no matching Terminal window"}
    if out == "ok":
        return {"ok": True}
    if out.startswith("ok\t"):
        return {"ok": True, "stdout": out}
    return {"ok": False, "reason": f"unexpected: {out[:120]}"}


def _peek_cwd_from_transcript(path: Path) -> str:
    """Return the `cwd` from the first transcript line that has one, else empty string."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i > 30:
                    break
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                cwd = obj.get("cwd")
                if isinstance(cwd, str) and cwd:
                    return cwd
    except Exception:
        pass
    return ""


def _peek_first_prompt(path: Path, max_chars: int = 200) -> str | None:
    """Return the first real (non-slash-command, non-system) user prompt as a snippet."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i > 200:
                    break
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if obj.get("type") != "user":
                    continue
                msg = obj.get("message") or {}
                content = msg.get("content")
                text = content if isinstance(content, str) else None
                if not text:
                    continue
                stripped = text.strip()
                if not stripped:
                    continue
                # Skip slash-command boilerplate / hook injections — anything
                # that's purely tag-wrapped meta is not a real user prompt.
                lower = stripped.lower()
                if any(tag in lower for tag in (
                    "<local-command-caveat>", "<local-command-stdout>",
                    "<local-command-stderr>", "<system-reminder>",
                    "<command-name>", "<command-message>", "<command-args>",
                    "<task-notification>", "<persisted-output>",
                )):
                    continue
                # Strip wrapping tag noise then re-check non-empty
                cleaned = re.sub(r"<[^>]+>", "", stripped).strip()
                if not cleaned or len(cleaned) < 4:
                    continue
                # Take first non-empty line of cleaned text
                first_line = cleaned.split("\n", 1)[0].strip()
                return first_line[:max_chars] if first_line else None
    except Exception:
        pass
    return None


def _peek_last_assistant_text(path: Path, max_chars: int = 4000) -> str | None:
    """Return the most recent assistant text content from the transcript JSONL."""
    try:
        # Read whole file in reverse-chunk-friendly form for v1
        last_text = None
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if obj.get("type") != "assistant":
                    continue
                msg = obj.get("message") or {}
                content = msg.get("content")
                if isinstance(content, list):
                    parts = []
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            t = block.get("text")
                            if isinstance(t, str):
                                parts.append(t)
                    joined = "\n\n".join(p for p in parts if p)
                    if joined:
                        last_text = joined
                elif isinstance(content, str) and content:
                    last_text = content
        if last_text:
            return last_text[:max_chars]
    except Exception:
        pass
    return None


def _worker_stats_payload(since_min: int = 60) -> dict:
    since_min = max(1, min(int(since_min or 60), 60 * 24))
    stat_rows = _claude_sessions_backend().worker_stats_rows(since_min)

    worker_patterns = [
        "biotech-labs/synth-synth-",
        "biotech-labs/crohns-research/scripts",
        "biotech-research-",
    ]
    now_epoch = int(_time.time())
    active_threshold = now_epoch - 5 * 60
    idle_threshold = now_epoch - 60 * 60
    active = 0
    idle = 0
    stale_ids: list[str] = []
    per_project: dict[str, dict] = {}

    for sid, project, heartbeat in stat_rows:
        if not any(pattern in project for pattern in worker_patterns):
            continue
        if heartbeat >= active_threshold:
            active += 1
        else:
            idle += 1
            if heartbeat < idle_threshold:
                stale_ids.append(sid)
        entry = per_project.setdefault(project, {
            "path": project,
            "count": 0,
            "last_heartbeat": 0,
        })
        entry["count"] += 1
        entry["last_heartbeat"] = max(entry["last_heartbeat"], heartbeat)

    return {
        "automated_active": active,
        "automated_idle": idle,
        "total": active + idle,
        "projects": sorted(
            per_project.values(),
            key=lambda item: item["last_heartbeat"],
            reverse=True,
        )[:20],
        "stale_session_ids": stale_ids[:50],
    }


def _human_idle_minutes() -> float | None:
    idle_candidates: list[float] = []
    ok, out, _ = _run_text(["/usr/sbin/ioreg", "-r", "-c", "IOHIDSystem"], timeout=2)
    if ok:
        match = re.search(r'"HIDIdleTime"\s*=\s*(\d+)', out)
        if match:
            idle_candidates.append(int(match.group(1)) / 1_000_000_000 / 60)
    if LAST_HUMAN_ACTIVITY_AT:
        idle_candidates.append(max(0.0, (_time.time() - LAST_HUMAN_ACTIVITY_AT) / 60))
    if not idle_candidates:
        return None
    return round(min(idle_candidates), 2)


class ClientDisconnected(Exception):
    pass


class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        try:
            return self._dispatch()
        except ClientDisconnected:
            return

    def do_POST(self):
        try:
            return self._dispatch()
        except ClientDisconnected:
            return

    def do_PUT(self):
        try:
            return self._dispatch()
        except ClientDisconnected:
            return

    def do_DELETE(self):
        try:
            return self._dispatch()
        except ClientDisconnected:
            return

    def _read_body(self) -> bytes:
        cached = getattr(self, "_cached_body", None)
        if cached is not None:
            return cached
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n) if n > 0 else b""
        self._cached_body = body
        return body

    def _dispatch(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        self._cached_body = None
        try:
            content_length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            self._send_json({"ok": False, "error": {"code": "bad_content_length"}}, status=400)
            return
        if u.path == "/upload":
            max_body = MAX_UPLOAD_BODY_BYTES
        elif u.path == "/pairdrop/files" and self.command == "POST":
            max_body = MAX_PAIRDROP_SMALL_BODY_BYTES
        elif _pairdrop_upload_bytes_id(u.path) is not None and self.command == "PUT":
            max_body = MAX_PAIRDROP_UPLOAD_CHUNK_BYTES
        else:
            max_body = MAX_REQUEST_BODY_BYTES
        if content_length > max_body:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "request_too_large",
                    "message": f"request body exceeds {max_body} bytes",
                },
            }, status=413)
            return

        admission = _runtime_admission_for_path(u.path)
        if not admission.allowed:
            self._send_json({
                "ok": False,
                "error": {
                    "code": admission.reason or "runtime_busy",
                    "message": "Pairling runtime is busy; retry shortly",
                },
                "retry_after": 1,
            }, status=503)
            return

        self.pairling_auth = None

        if u.path in INTERNAL_LOOPBACK_PATHS:
            # Internal hook tier — loopback IP AND minted token required.
            # Handled entirely outside device auth: a device Bearer never
            # grants access here, and the hook token never grants device
            # endpoints.
            client_ip = str(self.client_address[0] if self.client_address else "")
            presented = str(self.headers.get("X-Pairling-Internal-Token") or "").strip()
            if (
                client_ip not in ("127.0.0.1", "::1")
                or not INTERNAL_HOOK_TOKEN
                or not presented
                or not secrets.compare_digest(presented, INTERNAL_HOOK_TOKEN)
            ):
                admission.release()
                self._send_json({
                    "ok": False,
                    "error": {
                        "code": "internal_forbidden",
                        "message": "loopback internal token required",
                    },
                }, status=403)
                return
            try:
                if u.path == "/internal/session-register":
                    self._handle_internal_session_register(q)
                elif u.path == "/internal/session-heartbeat":
                    self._handle_internal_session_heartbeat(q)
                elif u.path == "/internal/session-close":
                    self._handle_internal_session_close(q)
                elif u.path == "/internal/active-sessions":
                    self._handle_internal_active_sessions(q)
                elif u.path == "/internal/permission-request":
                    self._handle_internal_permission_request(q)
            finally:
                admission.release()
            return

        required_scopes = _required_scopes_for_request(u.path, self.command)
        token = _bearer_token(self.headers)
        if token:
            if DEVICE_REGISTRY is None:
                admission.release()
                self._send_json({
                    "ok": False,
                    "error": {
                        "code": "auth_unavailable",
                        "message": "Pairling device registry is unavailable",
                    },
                }, status=503)
                return
            try:
                auth_result = _authenticate_device(
                    token,
                    required_scopes=required_scopes,
                    path=u.path,
                    method=self.command,
                )
            except Exception as exc:
                admission.release()
                self._send_json({
                    "ok": False,
                    "error": {
                        "code": "auth_unavailable",
                        "message": f"Pairling device auth failed: {type(exc).__name__}",
                    },
                }, status=503)
                return
            if auth_result is None:
                admission.release()
                self._send_json({
                    "ok": False,
                    "error": {
                        "code": "auth_unavailable",
                        "message": "Pairling device registry is unavailable",
                    },
                }, status=503)
                return
            if not auth_result.ok:
                admission.release()
                self._send_json({
                    "ok": False,
                    "error": {
                        "code": auth_result.reason,
                        "message": auth_result.reason.replace("_", " "),
                    },
                }, status=auth_result.status)
                return
            self.pairling_auth = auth_result
        elif u.path not in PUBLIC_ENDPOINTS:
            admission.release()
            self._send_json({
                "ok": False,
                "error": {
                    "code": "missing_token",
                    "message": "Authorization: Bearer token required",
                },
            }, status=401)
            return

        if _is_pairdrop_path(u.path) and not _pairdrop_gateway_provenance_ok(self.headers):
            admission.release()
            self._send_json({
                "ok": False,
                "error": {
                    "code": "pairdrop_connect_gateway_required",
                    "message": "PairDrop requires Pairling Connect gateway provenance",
                },
            }, status=403)
            return

        if u.path in POST_ONLY_ENDPOINTS and self.command != "POST":
            admission.release()
            self.send_error(405, "POST required")
            return
        if u.path.startswith("/pickers/mcp/") and u.path.endswith("/restart") and self.command != "POST":
            admission.release()
            self.send_error(405, "POST required")
            return

        if (
            self.pairling_auth is not None
            and _requires_request_proof(u.path, self.command)
        ):
            if verify_request_proof is None or _proof_replay_cache is None:
                admission.release()
                self._send_json({
                    "ok": False,
                    "error": {
                        "code": "proof_unavailable",
                        "message": "request proof verifier is unavailable",
                    },
                }, status=503)
                return
            body = self._read_body()
            local_install_id = str(getattr(PAIRING_STORE, "install_id", "") or getattr(self.pairling_auth, "install_id", "") or "")
            proof_result = verify_request_proof(
                headers=self.headers,
                method=self.command,
                path_and_query=_path_and_query(u),
                body=body,
                auth_result=self.pairling_auth,
                local_install_id=local_install_id,
                replay_cache=_proof_replay_cache,
            )
            if not proof_result.ok:
                admission.release()
                self._send_json({
                    "ok": False,
                    "error": {
                        "code": proof_result.code,
                        "message": proof_result.message,
                    },
                }, status=proof_result.status)
                return

        if self.pairling_auth is not None and _is_high_risk_endpoint(u.path) and DEVICE_REGISTRY is not None:
            max_per_min = _rate_limit_for_high_risk_endpoint(u.path)
            allowed, retry = _request_rate_check(f"{self.pairling_auth.device_id}:{u.path}", max_per_min=max_per_min)
            if not allowed:
                admission.release()
                self._send_json({
                    "ok": False,
                    "error": {
                        "code": "rate_limited",
                        "message": "too many mutating requests",
                    },
                    "retry_after": retry,
                }, status=429)
                return
            try:
                DEVICE_REGISTRY.record_audit(
                    "request.allowed",
                    device_id=self.pairling_auth.device_id,
                    outcome="ok",
                    path=u.path,
                    detail={"method": self.command, "scopes": sorted(required_scopes)},
                )
            except Exception:
                pass

        try:
            if u.path == "/health":
                self._handle_health(q)
            elif u.path == "/readyz":
                self._handle_readyz(q)
            elif u.path == "/routez":
                self._handle_routez(q)
            elif u.path == "/manifest":
                self._handle_manifest(q)
            elif u.path == "/pair/start":
                self._handle_pair_start(q)
            elif u.path == "/pair/claim":
                self._handle_pair_claim(q)
            elif u.path == "/pair/psk-claim":
                self._handle_pair_psk_claim(q)
            elif u.path == "/pair/reauth-challenge":
                self._handle_pair_reauth_challenge(q)
            elif u.path == "/pair/reauth-claim":
                self._handle_pair_reauth_claim(q)
            elif u.path == "/pair/revoke":
                self._handle_pair_revoke(q)
            elif u.path == "/pair/rotate-token":
                self._handle_pair_rotate_token(q)
            elif u.path == "/healthz":
                self._handle_healthz(q)
            elif u.path == "/power-state":
                self._handle_power_state(q)
            elif u.path == "/health-stream":
                self._handle_health_stream(q)
            elif u.path == "/open":
                self._handle_open(q)
            elif u.path == "/sessions":
                self._handle_sessions(q)
            elif u.path == "/sessions-visible":
                self._handle_sessions_visible(q)
            elif u.path == "/session-source-diagnostics":
                self._handle_session_source_diagnostics(q)
            elif u.path == "/recent-projects":
                self._handle_recent_projects(q)
            elif u.path == "/filesystem/directories":
                self._handle_filesystem_directories(q)
            elif u.path == "/transcript":
                self._handle_transcript(q)
            elif u.path == "/session-live-events":
                self._handle_session_live_events(q)
            elif u.path == "/transcript-stream":
                self._handle_transcript_stream(q)
            elif u.path == "/terminal-stream":
                self._handle_terminal_stream(q)
            elif u.path == "/terminal-stream-diagnostics":
                self._handle_terminal_stream_diagnostics(q)
            elif u.path == "/terminal-surface":
                self._handle_terminal_surface(q)
            elif u.path == "/terminal-surface-stream":
                self._handle_terminal_surface_stream(q)
            elif u.path == "/terminal-surface-v2":
                self._handle_terminal_surface_v2(q)
            elif u.path == "/terminal-surface-stream-v2":
                self._handle_terminal_surface_stream_v2(q)
            elif u.path == "/session-runtime-truth":
                self._handle_session_runtime_truth(q)
            elif u.path == "/session-runtime-truth-stream":
                self._handle_session_runtime_truth_stream(q)
            elif u.path == "/terminal-workspace":
                self._handle_terminal_workspace(q)
            elif u.path == "/terminal-workspace-stream":
                self._handle_terminal_workspace_stream(q)
            elif u.path == "/terminal-control":
                self._handle_terminal_control(q)
            elif u.path == "/corpus":
                self._handle_corpus(q)
            elif u.path == "/inject":
                self._handle_inject(q)
            elif u.path == "/inject-now":
                self._handle_inject_now(q)
            elif u.path == "/interrupt":
                self._handle_interrupt(q)
            elif u.path == "/session-meta":
                self._handle_session_meta(q)
            elif u.path == "/personal-context":
                self._handle_personal_context(q)
            elif u.path == "/llm-route":
                self._handle_llm_route(q)
            elif u.path == "/llm-route-stream":
                self._handle_llm_route_stream(q)
            elif u.path == "/pairling-tools/run":
                self._handle_pairling_tools_run(q)
            elif u.path == "/phone-tools/availability":
                self._handle_phone_tools_availability(q)
            elif u.path == "/phone-tools/next":
                self._handle_phone_tools_next(q)
            elif u.path == "/phone-tools/result":
                self._handle_phone_tools_result(q)
            elif u.path == "/worker-stats":
                self._handle_worker_stats(q)
            elif u.path == "/push/status":
                self._handle_push_status(q)
            elif u.path == "/push/preferences":
                self._handle_push_preferences(q)
            elif u.path == "/push/test":
                self._handle_push_test(q)
            elif u.path == "/push/permission/allow":
                self._handle_push_permission_allow(q)
            elif u.path == "/push/live-activity-token":
                self._handle_push_live_activity_token(q)
            elif u.path == "/push/live-activity-test":
                self._handle_push_live_activity_test(q)
            elif u.path == "/sentinel/status":
                self._handle_sentinel_status(q)
            elif u.path == "/sentinel/preferences":
                self._handle_sentinel_preferences(q)
            elif u.path == "/sentinel/snooze":
                self._handle_sentinel_snooze(q)
            elif u.path == "/sentinel/evaluate-now":
                self._handle_sentinel_evaluate_now(q)
            elif u.path == "/sentinel/events":
                self._handle_sentinel_events(q)
            elif u.path == "/workstate-feed":
                self._handle_workstate_feed(q)
            elif u.path == "/model-status":
                self._handle_model_status(q)
            elif u.path == "/substrate-status":
                self._handle_substrate_status(q)
            elif u.path == "/substrate-feed":
                self._handle_substrate_feed(q)
            elif u.path == "/workers":
                self._handle_workers(q)
            elif u.path == "/activity":
                self._handle_activity(q)
            elif u.path == "/activity-stream":
                self._handle_activity_stream(q)
            elif u.path == "/safety/status":
                self._handle_safety_status(q)
            elif u.path == "/safety/events":
                self._handle_safety_events(q)
            elif u.path == "/safety/ack":
                self._handle_safety_ack(q)
            elif u.path == "/safety/request-activation":
                self._handle_safety_request_activation(q)
            elif u.path == "/safety/open-full-disk-access":
                self._handle_safety_open_full_disk_access(q)
            elif u.path == "/safety/evidence-test":
                self._handle_safety_evidence_test(q)
            elif u.path == "/aperture-cli/status":
                self._handle_aperture_cli_status(q)
            elif u.path == "/aperture-cli/providers":
                self._handle_aperture_cli_providers(q)
            elif u.path == "/aperture-cli/launch-contexts":
                self._handle_aperture_cli_launch_contexts(q)
            elif u.path == "/aperture-cli/open":
                self._handle_aperture_cli_open(q)
            elif u.path == "/mirror/status":
                self._handle_mirror_status(q)
            elif u.path == "/mirror/projects":
                self._handle_mirror_projects(q)
            elif u.path == "/mirror/conflicts":
                self._handle_mirror_conflicts(q)
            elif u.path == "/mirror/flush":
                self._handle_mirror_flush(q)
            elif u.path == "/mirror/resume":
                self._handle_mirror_resume(q)
            elif u.path == ORCHESTRATIONS_ROUTE:
                if self.command == "POST":
                    self._handle_orchestrations_create(q)
                else:
                    self._handle_orchestrations_list(q)
            elif u.path.startswith(f"{ORCHESTRATIONS_ROUTE}/"):
                self._route_orchestration_path(u.path, q)
            elif u.path == "/worker-kill":
                self._handle_worker_kill(q)
            elif u.path == "/spawn-session":
                self._handle_spawn_session(q)
            elif u.path == "/onestream-handoff":
                self._handle_onestream_handoff(q)
            elif u.path == "/resume-session":
                self._handle_resume_session(q)
            elif u.path == "/cross-provider-action":
                self._handle_cross_provider_action(q)
            elif u.path == "/send-text":
                self._handle_send_text(q)
            elif u.path == "/sigint":
                self._handle_sigint(q)
            elif u.path == "/sigterm":
                self._handle_sigterm(q)
            elif u.path == "/tokens":
                self._handle_tokens(q)
            elif u.path.startswith("/pairdrop/"):
                self._route_pairdrop_path(u.path, q)
            elif u.path == "/upload":
                self._handle_upload(q)
            elif u.path == "/turn-state-stream":
                self._handle_turn_state_stream(q)
            elif u.path == "/sessions-stream":
                self._handle_sessions_stream(q)
            elif u.path == "/commands":
                self._handle_commands(q)
            elif u.path == "/commands-stream":
                self._handle_commands_stream(q)
            elif u.path == "/invocations":
                self._handle_invocations(q)
            elif u.path == "/invocations-stream":
                self._handle_invocations_stream(q)
            elif u.path == "/provider-status":
                self._handle_provider_status(q)
            elif u.path == "/status":
                self._handle_status(q)
            elif u.path == "/pickers/resume":
                self._handle_pickers_resume(q)
            elif u.path == "/pickers/resume/preview":
                self._handle_pickers_resume_preview(q)
            elif u.path == "/pickers/permissions":
                self._handle_pickers_permissions(q)
            elif u.path == "/pickers/hooks":
                self._handle_pickers_hooks(q)
            elif u.path == "/pickers/memory":
                self._handle_pickers_memory(q)
            elif u.path.startswith("/pickers/memory/"):
                self._handle_pickers_memory_one(q, u.path[len("/pickers/memory/"):])
            elif u.path == "/pickers/mcp":
                self._handle_pickers_mcp(q)
            elif u.path.startswith("/pickers/mcp/") and u.path.endswith("/restart"):
                name = u.path[len("/pickers/mcp/"):-len("/restart")]
                self._handle_pickers_mcp_restart(q, name)
            elif u.path == "/search":
                self._handle_search(q)
            elif u.path.startswith("/sessions/") and u.path.endswith("/export"):
                sid = unquote(u.path[len("/sessions/"):-len("/export")])
                self._handle_session_export(q, sid)
            else:
                self.send_error(404, "unknown path")
        except (ClientDisconnected, BrokenPipeError, ConnectionResetError):
            return
        except Exception as e:
            if DEVICE_REGISTRY is not None:
                DEVICE_REGISTRY.record_audit(
                    "request.error",
                    device_id=getattr(self.pairling_auth, "device_id", None),
                    outcome=type(e).__name__,
                    path=u.path,
                )
            self._send_json({
                "ok": False,
                "error": {
                    "code": "internal_error",
                    "message": "internal runtime error",
                },
            }, status=500)
        finally:
            admission.release()

    # ----- /internal/*: loopback hook tier (claude session registry) -----
    _CLAUDE_UUID_RE = re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    _INTERNAL_TTY_RE = re.compile(r"^/dev/ttys[0-9]{3,}$")

    def _internal_claude_uuid(self, payload: dict) -> str:
        uuid = str(payload.get("claude_uuid") or "").strip()
        return uuid if self._CLAUDE_UUID_RE.match(uuid) else ""

    def _internal_terminal_tty(self, payload: dict) -> str:
        tty = str(payload.get("terminal_tty") or "").strip()
        return tty if self._INTERNAL_TTY_RE.match(tty) else ""

    def _internal_claude_pid(self, payload: dict) -> int:
        try:
            pid = int(payload.get("claude_pid") or 0)
        except (TypeError, ValueError):
            return 0
        return pid if 0 < pid < 10 ** 8 else 0

    def _read_internal_json(self) -> dict | None:
        if self.command != "POST":
            self.send_error(405, "POST required")
            return None
        try:
            payload = json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            self._send_json({"ok": False, "error": {"code": "bad_json"}}, status=400)
            return None
        if not isinstance(payload, dict):
            self._send_json({"ok": False, "error": {"code": "bad_json"}}, status=400)
            return None
        return payload

    def _handle_internal_session_register(self, q):
        payload = self._read_internal_json()
        if payload is None:
            return
        session_id = str(payload.get("id") or "").strip()
        project = str(payload.get("project") or "").strip()
        if not _safe_session_id(session_id) or not project:
            self._send_json({
                "ok": False,
                "error": {"code": "bad_request", "message": "id and project required"},
            }, status=400)
            return
        claude_uuid = self._internal_claude_uuid(payload)
        ok = _agent_registry_upsert(
            "claude",
            session_id,
            project,
            pid=self._internal_claude_pid(payload),
            terminal_tty=self._internal_terminal_tty(payload),
            claude_uuid=claude_uuid,
            working_on=str(payload.get("working_on") or "")[:500],
        )
        # Mirrors the PG pg_notify('session_ready'): only fire once the row
        # carries a claude_uuid — that is what /turn-state-stream waits on.
        if ok and claude_uuid:
            _signal_session_ready(session_id)
        self._send_json({"ok": bool(ok)})

    def _handle_internal_session_heartbeat(self, q):
        payload = self._read_internal_json()
        if payload is None:
            return
        claude_uuid = self._internal_claude_uuid(payload)
        if not claude_uuid:
            self._send_json({
                "ok": False,
                "error": {"code": "bad_request", "message": "claude_uuid required"},
            }, status=400)
            return
        ok = _agent_registry_heartbeat_by_claude_uuid(
            "claude",
            claude_uuid,
            terminal_tty=self._internal_terminal_tty(payload),
            pid=self._internal_claude_pid(payload),
        )
        # ok=false simply means no row matched — same as the PG UPDATE no-op.
        self._send_json({"ok": bool(ok)})

    def _handle_internal_session_close(self, q):
        payload = self._read_internal_json()
        if payload is None:
            return
        claude_uuid = self._internal_claude_uuid(payload)
        if not claude_uuid:
            self._send_json({
                "ok": False,
                "error": {"code": "bad_request", "message": "claude_uuid required"},
            }, status=400)
            return
        closed = _agent_registry_mark_closed_by_claude_uuid("claude", claude_uuid)
        self._send_json({"ok": True, "closed": bool(closed)})

    def _handle_internal_active_sessions(self, q):
        project = q.get("project", [""])[0].strip()
        cutoff = _time.time() - 300
        items = []
        for row in _agent_registry_live("claude"):
            if float(row.get("last_heartbeat") or 0) < cutoff:
                continue
            if project and row.get("project") != project:
                continue
            items.append({
                "id": row.get("native_id"),
                "project": row.get("project"),
                "working_on": row.get("working_on") or None,
                "started_at": float(row.get("started_at") or 0),
                "last_heartbeat": float(row.get("last_heartbeat") or 0),
            })
        items.sort(key=lambda r: r["started_at"], reverse=True)
        self._send_json({"ok": True, "count": len(items), "sessions": items})

    def _handle_internal_permission_request(self, q):
        # PermissionRequest hook producer (claude + codex). Notify-only: record
        # the pending approval; the agent's native dialog is the durable block.
        # Phase 3 fires the APNs card + wires the Allow keystroke here.
        payload = self._read_internal_json()
        if payload is None:
            return
        provider = str(payload.get("provider") or "claude").strip().lower()
        if provider not in ("claude", "codex"):
            provider = "claude"
        session_id = str(payload.get("session_id") or "").strip()
        tool_name = str(payload.get("tool_name") or "").strip()
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict):
            tool_input = {}
        if not session_id or not tool_name:
            self._send_json({
                "ok": False,
                "error": {"code": "bad_request", "message": "session_id and tool_name required"},
            }, status=400)
            return
        request_nonce = str(payload.get("request_nonce") or "").strip() or secrets.token_hex(16)
        command_preview = _approval_command_preview(tool_name, tool_input)
        ok = _pending_approval_record(
            request_nonce=request_nonce,
            provider=provider,
            session_id=session_id,
            tool_name=tool_name,
            tool_input=tool_input,
            command_preview=command_preview,
            permission_mode=str(payload.get("permission_mode") or "")[:40],
            broker_id=str(payload.get("broker_session_id") or "").strip(),
        )
        self._send_json({
            "ok": bool(ok),
            "request_nonce": request_nonce,
            "command_preview": command_preview,
        })

    # ----- /open: open path on Mac (existing behavior) -----
    def _handle_open(self, q):
        path = q.get("path", [""])[0]
        app = q.get("app", ["sublime"])[0]
        if not path or not os.path.exists(path):
            self.send_error(404, "path not found")
            return
        if app == "finder":
            subprocess.run(["open", path], check=False)
        else:
            subprocess.run(["open", "-a", SUBLIME_APP, path], check=False)
        self._send_text(200, b"ok\n")

    # ----- /healthz + /power-state + /health-stream: coordinator health -----
    def _handle_health(self, q):
        self._send_json(_cached_health_payload(
            full_power=False,
            authenticated=self.pairling_auth is not None,
            auth_result=self.pairling_auth,
        ))

    def _handle_healthz(self, q):
        self._send_json(_cached_health_payload(
            full_power=False,
            authenticated=self.pairling_auth is not None,
            auth_result=self.pairling_auth,
        ))

    def _handle_readyz(self, q):
        self._send_json(_readyz_payload())

    def _handle_routez(self, q):
        self._send_json(_routez_payload(auth_result=self.pairling_auth))

    def _handle_manifest(self, q):
        runtime_info = _runtime_info_snapshot()
        if _build_manifest_payload is None:
            payload = {
                "ok": True,
                "schema_version": 1,
                "contract_version": RUNTIME_CONTRACT_VERSION,
                "runtime": runtime_info,
                "auth": {
                    "mode": RUNTIME_AUTH_MODE,
                    "required": True,
                    "legacy_global_token": False,
                    "authenticated": self.pairling_auth is not None,
                },
            }
        else:
            payload = _build_manifest_payload(
                runtime_info,
                authenticated=self.pairling_auth is not None,
                device_id=getattr(self.pairling_auth, "device_id", None),
                scopes=list(getattr(self.pairling_auth, "scopes", []) or []),
            )
        self._send_json(payload)

    def _read_json_object(self) -> dict:
        body = self._read_body()
        if not body:
            return {}
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("body must be a JSON object")
        return payload

    def _handle_pairling_tools_run(self, q):
        if run_pairling_tool is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "pairling_tools_unavailable",
                    "message": "Pairling tools router is unavailable",
                },
            }, status=503)
            return
        try:
            payload = self._read_json_object()
        except (json.JSONDecodeError, ValueError) as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return

        result = run_pairling_tool(payload)
        if DEVICE_REGISTRY is not None and audit_detail_for_tool_run is not None:
            error_payload = result.get("error") if isinstance(result.get("error"), dict) else {}
            DEVICE_REGISTRY.record_audit(
                "pairling_tools.run",
                device_id=getattr(self.pairling_auth, "device_id", None),
                outcome="ok" if result.get("ok") else str(error_payload.get("code") or "error"),
                path="/pairling-tools/run",
                detail=audit_detail_for_tool_run(payload, result),
            )
        error_payload = result.get("error") if isinstance(result.get("error"), dict) else {}
        status = 200
        if not result.get("ok"):
            status = 400 if error_payload.get("code") in {"bad_request", "invalid_tool", "invalid_strategy", "missing_input"} else 502
        self._send_json(result, status=status)

    def _handle_phone_tools_availability(self, q):
        if PHONE_TOOL_AVAILABILITY is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "phone_tools_availability_unavailable",
                    "message": "Phone tools availability store is unavailable",
                },
            }, status=503)
            return
        try:
            payload = self._read_json_object()
        except (json.JSONDecodeError, ValueError) as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        state = PHONE_TOOL_AVAILABILITY.update(payload)
        self._send_json({
            "ok": True,
            "schema_version": 1,
            "availability": state,
        })

    def _handle_phone_tools_next(self, q):
        if PHONE_TOOL_WORK_QUEUE is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "phone_tools_queue_unavailable",
                    "message": "Phone tools work queue is unavailable",
                },
            }, status=503)
            return
        try:
            payload = self._read_json_object()
        except (json.JSONDecodeError, ValueError) as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        tools = payload.get("tools") if isinstance(payload.get("tools"), list) else []
        wait_seconds = payload.get("wait_seconds") or 10
        request = PHONE_TOOL_WORK_QUEUE.next_request(
            device_id=getattr(self.pairling_auth, "device_id", None),
            tools=tools,
            wait_seconds=wait_seconds,
        )
        if PHONE_TOOL_AVAILABILITY is not None:
            PHONE_TOOL_AVAILABILITY.update({
                "listener_running": True,
                "port": 0,
                "tools": tools,
                "app_state": "foreground-worker",
                "expires_in_seconds": 30,
            })
        self._send_json({
            "ok": True,
            "schema_version": 1,
            "request": request,
            "worker": PHONE_TOOL_WORK_QUEUE.snapshot(),
        })

    def _handle_phone_tools_result(self, q):
        if PHONE_TOOL_WORK_QUEUE is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "phone_tools_queue_unavailable",
                    "message": "Phone tools work queue is unavailable",
                },
            }, status=503)
            return
        try:
            payload = self._read_json_object()
        except (json.JSONDecodeError, ValueError) as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        ok = PHONE_TOOL_WORK_QUEUE.complete(
            request_id=str(payload.get("request_id") or ""),
            ok=bool(payload.get("ok")),
            result=str(payload.get("result") or ""),
            error=str(payload.get("error") or ""),
        )
        self._send_json({
            "ok": ok,
            "schema_version": 1,
        }, status=200 if ok else 404)

    def _pairing_host_chain(self) -> list[str]:
        hosts: list[str] = []
        for route in self._pairling_connect_routes():
            host = route.get("host")
            if isinstance(host, str) and host:
                hosts.append(host)
        tailnet_name = os.environ.get("PAIRLING_TAILNET_HOST")
        if tailnet_name:
            hosts.append(tailnet_name)
        tailnet_ip = _tailnet_ip()
        if tailnet_ip:
            hosts.append(tailnet_ip)
        hosts.extend(_lan_ips()[:2])
        hostname = os.environ.get("PAIRLING_HOSTNAME") or os.uname().nodename.split(".")[0]
        if hostname:
            hosts.append(f"{hostname}.local")
        seen: set[str] = set()
        deduped: list[str] = []
        for host in hosts:
            if host and host not in seen:
                seen.add(host)
                deduped.append(host)
        return deduped or ["127.0.0.1"]

    def _pairling_connect_routes(self) -> list[dict]:
        if fetch_connectd_status is None or advertised_pairling_connect_routes is None:
            return []
        try:
            return advertised_pairling_connect_routes(fetch_connectd_status(timeout_seconds=0.7))
        except Exception:
            return []

    def _pairing_runtime_routes(self, host_chain: list[str]) -> list[dict]:
        routes: list[dict] = []
        seen_base_urls: set[str] = set()
        for route in self._pairling_connect_routes():
            base_url = route.get("base_url")
            if isinstance(base_url, str) and base_url not in seen_base_urls:
                seen_base_urls.add(base_url)
                routes.append(dict(route))
        for host in host_chain:
            if not host:
                continue
            base_url = f"http://{host}:{PORT}"
            if base_url in seen_base_urls:
                continue
            seen_base_urls.add(base_url)
            kind = "tailnet" if host.startswith("100.") or host.endswith(".ts.net") else "bonjour" if host.endswith(".local") else "lan"
            routes.append({
                "id": f"{kind}-fallback",
                "kind": kind,
                "source": "pairlingd",
                "priority": 30 if kind == "bonjour" else 40 if kind == "lan" else 60,
                "base_url": base_url,
                "host": host,
                "port": PORT,
                "status": "fallback",
            })
        routes.sort(key=lambda item: int(item.get("priority") or 0), reverse=True)
        return routes

    def _handle_pair_start(self, q):
        if PAIRING_STORE is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "pairing_unavailable",
                    "message": "Pairing store is unavailable",
                },
            }, status=503)
            return
        # P0-B: rate-limit unauthenticated pair starts per source IP so an
        # on-LAN attacker cannot mint a flood of invitations.
        allowed, retry_after = _request_rate_check(
            f"pair_start:{self.client_address[0]}", max_per_min=5
        )
        if not allowed:
            self.send_response(429)
            self.send_header("Retry-After", str(retry_after))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "ok": False,
                "error": {"code": "rate_limited", "message": "too many pair starts"},
            }).encode("utf-8"))
            return
        try:
            payload = self._read_json_object()
            ttl = int(payload.get("ttl_seconds") or DEFAULT_PAIR_TTL_SECONDS)
            started = PAIRING_STORE.start_pair(ttl_seconds=ttl)
            bonjour = (
                PAIRING_ADVERTISER.start(started, port=PORT)
                if PAIRING_ADVERTISER is not None
                else {"ok": False, "reason": "advertiser_unavailable"}
            )
            pairling_connect_routes = self._pairling_connect_routes()
        except ValueError as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        self._send_json({
            "ok": True,
            "pair_id": started.pair_id,
            "secret": started.secret,
            "attest_challenge": started.attest_challenge,
            "mac_ake_pub": started.mac_ake_pub,
            "expires_at": started.expires_at,
            "install_id": started.install_id,
            "runtime_port": PORT,
            "pair_service": {
                "type": started.service_type,
                "txt": started.txt,
                "runtime_api_advertised": bool(pairling_connect_routes),
                "bonjour": bonjour,
                "routes": pairling_connect_routes,
            },
            "claim": {
                "url": "pairling://pair",
                "pair_id": started.pair_id,
                "secret": started.secret,
                "pairing_nonce": started.pairing_nonce,
                "attest_challenge": started.attest_challenge,
                "mac_ake_pub": started.mac_ake_pub,
                "pv": "2" if started.mac_ake_pub else "1",
            },
        })

    def _handle_pair_claim(self, q):
        if PAIRING_STORE is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "pairing_unavailable",
                    "message": "Pairing store is unavailable",
                },
            }, status=503)
            return
        try:
            payload = self._read_json_object()
            host_chain = self._pairing_host_chain()
            claim = PAIRING_STORE.claim_pair(
                pair_id=str(payload.get("pair_id") or ""),
                secret=str(payload.get("secret") or ""),
                device_name=str(payload.get("device_name") or "Pairling iPhone"),
                host_chain=host_chain,
                cert_pin=None,
                pairing_nonce=str(payload.get("pairing_nonce") or ""),
                se_public_key_der=str(payload.get("se_public_key_der") or ""),
                attest_object=(payload.get("direct_attest_object") if isinstance(payload.get("direct_attest_object"), dict) else None),
                attest_key_id=str(payload.get("attest_key_id") or ""),
                attest_environment=str(payload.get("attest_environment") or ""),
                attested_claim_ticket=payload.get("attested_claim_ticket"),
                relay_device_id=payload.get("relay_device_id"),
                relay_required=bool(relay_claims_required and relay_claims_required()),
                relay_claim_verifier=RELAY_CLAIM_VERIFIER,
            )
            if PAIRING_ADVERTISER is not None:
                PAIRING_ADVERTISER.stop()
        except PairingError as exc:
            self._send_json({
                "ok": False,
                "error": {"code": exc.code, "message": exc.message},
            }, status=exc.status)
            return
        except ValueError as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        runtime_routes = self._pairing_runtime_routes(list(claim.host_chain))
        transport = "pairling-connect" if any(
            route.get("source") == "pairling_connectd" and route.get("status") == "ready"
            for route in runtime_routes
        ) else "http-local"
        self._send_json({
            "ok": True,
            "device": {
                "id": claim.device.device_id,
                "token": claim.device.token,
                "proof_secret": claim.device.proof_secret,
                "scopes": list(claim.device.scopes),
                "relay_device_id": claim.relay_device_id,
                "attestation_status": claim.attestation_status,
            },
            "install_id": claim.device.install_id,
            "runtime": {
                "port": claim.runtime_port,
                "host_chain": list(claim.host_chain),
                "cert_pin": claim.cert_pin,
                "transport": transport,
                "routes": runtime_routes,
            },
        })

    def _handle_pair_psk_claim(self, q):
        # WS3: PSK-authenticated ECDH claim. The secret is NEVER received; the
        # phone proves knowledge of it by completing the key exchange. The
        # bearer token is returned AES-GCM-sealed under K_token, so a passive
        # on-LAN sniffer learns nothing.
        if PAIRING_STORE is None:
            self._send_json({"ok": False, "error": {"code": "pairing_unavailable", "message": "Pairing store is unavailable"}}, status=503)
            return
        allowed, retry_after = _request_rate_check(f"pair_psk:{self.client_address[0]}", max_per_min=5)
        if not allowed:
            self.send_response(429)
            self.send_header("Retry-After", str(retry_after))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": False, "error": {"code": "rate_limited", "message": "too many psk claims"}}).encode("utf-8"))
            return
        try:
            payload = self._read_json_object()
            host_chain = self._pairing_host_chain()
            claim, k_token, aad, mac_confirm = PAIRING_STORE.psk_claim_pair(
                pair_id=str(payload.get("pair_id") or ""),
                b_pub_b64=str(payload.get("b_pub") or ""),
                confirm_b64=str(payload.get("confirm") or ""),
                device_name=str(payload.get("device_name") or "Pairling iPhone"),
                host_chain=host_chain,
                se_public_key_der=str(payload.get("se_public_key_der") or ""),
                attest_object=(payload.get("direct_attest_object") if isinstance(payload.get("direct_attest_object"), dict) else None),
                attest_key_id=str(payload.get("attest_key_id") or ""),
                attest_environment=str(payload.get("attest_environment") or ""),
                attested_claim_ticket=payload.get("attested_claim_ticket"),
                relay_device_id=payload.get("relay_device_id"),
                relay_required=bool(relay_claims_required and relay_claims_required()),
                relay_claim_verifier=RELAY_CLAIM_VERIFIER,
            )
            nonce, enc_token = PAIRING_STORE.seal_psk_token(k_token, claim.device.token, aad)
            if PAIRING_ADVERTISER is not None:
                PAIRING_ADVERTISER.stop()
        except PairingError as exc:
            self._send_json({"ok": False, "error": {"code": exc.code, "message": exc.message}}, status=exc.status)
            return
        except ValueError as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        runtime_routes = self._pairing_runtime_routes(list(claim.host_chain))
        transport = "pairling-connect" if any(
            route.get("source") == "pairling_connectd" and route.get("status") == "ready"
            for route in runtime_routes
        ) else "http-local"
        self._send_json({
            "ok": True,
            "device": {
                "id": claim.device.device_id,
                "proof_secret": claim.device.proof_secret,
                "scopes": list(claim.device.scopes),
                "relay_device_id": claim.relay_device_id,
                "attestation_status": claim.attestation_status,
            },
            "enc_token": base64.b64encode(enc_token).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "mac_confirm": base64.b64encode(mac_confirm).decode("ascii"),
            "install_id": claim.device.install_id,
            "runtime": {
                "port": claim.runtime_port,
                "host_chain": list(claim.host_chain),
                "cert_pin": claim.cert_pin,
                "transport": transport,
                "routes": runtime_routes,
            },
        })

    def _handle_pair_reauth_challenge(self, q):
        if REAUTH_STORE is None:
            self._send_json({"ok": False, "error": {"code": "pairing_unavailable", "message": "reauth unavailable"}}, status=503)
            return
        allowed, retry_after = _request_rate_check(f"pair_reauth:{self.client_address[0]}", max_per_min=10)
        if not allowed:
            self.send_response(429)
            self.send_header("Retry-After", str(retry_after))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": False, "error": {"code": "rate_limited", "message": "too many reauth attempts"}}).encode("utf-8"))
            return
        try:
            payload = self._read_json_object()
        except ValueError as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        device_id = str(payload.get("device_id") or "")
        if not device_id:
            self._send_json({"ok": False, "error": {"code": "device_id_required", "message": "device_id required"}}, status=400)
            return
        # A challenge is issued for ANY device_id (even unknown / revoked) so
        # this endpoint never reveals whether a device exists.
        challenge = REAUTH_STORE.issue_challenge(device_id)
        self._send_json({"ok": True, "challenge": challenge, "ttl_seconds": REAUTH_STORE.ttl_seconds})

    def _handle_pair_reauth_claim(self, q):
        if REAUTH_STORE is None or DEVICE_REGISTRY is None:
            self._send_json({"ok": False, "error": {"code": "pairing_unavailable", "message": "reauth unavailable"}}, status=503)
            return
        try:
            payload = self._read_json_object()
        except ValueError as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        device_id = str(payload.get("device_id") or "")
        challenge = str(payload.get("challenge") or "")
        signature_b64 = str(payload.get("signature") or "")
        try:
            signature = base64.b64decode(signature_b64) if signature_b64 else b""
        except Exception:
            signature = b""
        verified = REAUTH_STORE.verify_and_consume(device_id, challenge, signature)
        new_token = DEVICE_REGISTRY.rotate_token(device_id) if verified else None
        if not verified or not new_token:
            # Uniform failure: never distinguish unknown device / no SE key /
            # bad signature / expired-or-used challenge. No enumeration oracle.
            self._send_json({"ok": False, "error": {"code": "reauth_failed", "message": "reauth failed"}}, status=401)
            return
        self._send_json({"ok": True, "device": {"id": device_id, "token": new_token}})

    def _handle_pair_revoke(self, q):
        if DEVICE_REGISTRY is None:
            self._send_json({"ok": False, "error": {"code": "auth_unavailable"}}, status=503)
            return
        try:
            payload = self._read_json_object()
        except ValueError as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        device_id = str(payload.get("device_id") or "")
        if not device_id:
            self._send_json({"ok": False, "error": {"code": "device_id_required"}}, status=400)
            return
        revoked = DEVICE_REGISTRY.revoke_device(device_id, reason="api")
        self._send_json({"ok": revoked, "device_id": device_id}, status=200 if revoked else 404)

    def _handle_pair_rotate_token(self, q):
        if DEVICE_REGISTRY is None:
            self._send_json({"ok": False, "error": {"code": "auth_unavailable"}}, status=503)
            return
        try:
            payload = self._read_json_object()
        except ValueError as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        device_id = str(payload.get("device_id") or "")
        if not device_id:
            self._send_json({"ok": False, "error": {"code": "device_id_required"}}, status=400)
            return
        token = DEVICE_REGISTRY.rotate_token(device_id)
        if token is None:
            self._send_json({"ok": False, "error": {"code": "device_not_found"}}, status=404)
            return
        self._send_json({"ok": True, "device_id": device_id, "token": token})

    def _handle_power_state(self, q):
        self._send_json(_cached_health_payload(
            full_power=True,
            authenticated=self.pairling_auth is not None,
            auth_result=self.pairling_auth,
        ))

    def _handle_mirror_status(self, q):
        project = q.get("project", [None])[0]
        args = ["status"]
        if project:
            args.extend(["--project", project])
        code, payload = _mirror_cli_json(args, timeout=45)
        if code != 0 and not payload.get("projects"):
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            body = json.dumps(payload).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._send_json(payload)

    def _handle_mirror_projects(self, q):
        state = None
        try:
            state = json.loads(PROJECT_MIRROR_STATE.read_text())
        except Exception:
            pass
        if not isinstance(state, dict):
            code, state = _mirror_cli_json(["status"], timeout=45)
            if code != 0 and not state.get("projects"):
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                body = json.dumps(state).encode()
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        self._send_json({
            "contract_version": PROJECT_MIRROR_CONTRACT,
            "summary": state.get("summary") if isinstance(state, dict) else None,
            "projects": state.get("projects") if isinstance(state, dict) else [],
            "ts": _time.time(),
        })

    def _handle_mirror_conflicts(self, q):
        project = q.get("project", [None])[0]
        args = ["conflicts"]
        if project:
            args.extend(["--project", project])
        code, payload = _mirror_cli_json(args, timeout=45)
        if code not in (0, 1):
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            body = json.dumps(payload).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._send_json(payload)

    def _handle_mirror_flush(self, q):
        try:
            payload = json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "body must be JSON")
            return
        project = (payload.get("project") or q.get("project", [None])[0] or "").strip()
        timeout = int(payload.get("timeout") or q.get("timeout", ["60"])[0] or 60)
        args = ["flush", "--timeout", str(max(10, min(timeout, 300)))]
        if project:
            args.extend(["--project", project])
        else:
            args.append("--all")
        code, result = _mirror_cli_json(args, timeout=max(20, min(timeout + 20, 330)))
        if code != 0:
            self.send_response(409)
            self.send_header("Content-Type", "application/json")
            body = json.dumps(result).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._send_json(result)

    def _handle_mirror_resume(self, q):
        try:
            payload = json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "body must be JSON")
            return
        project = (payload.get("project") or q.get("project", [None])[0] or "").strip()
        args = ["resume"]
        if project:
            args.extend(["--project", project])
        else:
            args.append("--all")
        code, result = _mirror_cli_json(args, timeout=60)
        if code != 0:
            self.send_response(409)
            self.send_header("Content-Type", "application/json")
            body = json.dumps(result).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._send_json(result)

    def _handle_health_stream(self, q):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        last_hash: str | None = None
        last_keepalive = 0.0
        deadline = _time.time() + 600
        while _time.time() < deadline:
            payload = _cached_health_payload(
                full_power=False,
                authenticated=self.pairling_auth is not None,
                auth_result=self.pairling_auth,
            )
            digest = _health_diff_digest(payload)
            if digest != last_hash:
                try:
                    self.wfile.write(b"event: snapshot\ndata: " + json.dumps(payload).encode() + b"\n\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
                last_hash = digest
            if _time.time() - last_keepalive >= 15:
                try:
                    keepalive = json.dumps({"ts": _time.time()}).encode()
                    self.wfile.write(b"event: keepalive\ndata: " + keepalive + b"\n\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
                last_keepalive = _time.time()
            _time.sleep(5)
        try:
            self.wfile.write(b"event: done\ndata: {}\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        return

    # ----- /recent-projects: cheap project picker for new-session sheet -----
    def _handle_recent_projects(self, q):
        try:
            within_min = int(q.get("active_within_min", ["10080"])[0])
        except ValueError:
            within_min = 10080
        try:
            limit = int(q.get("limit", ["30"])[0])
        except ValueError:
            limit = 30

        within_min = max(1, min(within_min, 60 * 24 * 30))
        limit = max(1, min(limit, 100))

        payload = _cached_runtime_snapshot(
            ("recent-projects", within_min, limit),
            RECENT_PROJECTS_CACHE_SECONDS,
            lambda: self._recent_projects_payload(within_min, limit),
        )
        self._send_json(payload)

    def _recent_projects_payload(self, within_min: int, limit: int) -> dict:
        projects: dict[str, int] = {}
        sources: dict[str, set[str]] = {}

        def add_project(project: str | None, last_heartbeat: int | float | None, source: str) -> None:
            if not isinstance(project, str):
                return
            project = project.strip()
            if not project or not _is_recent_project_candidate(project):
                return
            last = int(last_heartbeat or 0)
            projects[project] = max(projects.get(project, 0), last)
            sources.setdefault(project, set()).add(source)

        # Keep this endpoint intentionally lightweight. /sessions enriches rows
        # with turn state, transcript signals, and first prompts; the spawn sheet
        # only needs recent project paths. The source is deliberately canonical:
        # Claude registry rows plus Codex rollouts/registry rows, so the picker
        # does not show a false empty state when only one provider has history.
        for project, last_heartbeat in _claude_sessions_backend().recent_project_rows(
            within_min, limit * 3
        ):
            add_project(project, last_heartbeat, "claude")

        for row in _list_codex_sessions(live_only=False, active_within_min=within_min):
            add_project(row.get("project"), row.get("last_heartbeat"), "codex")

        for row in _agent_registry_recent("codex", since_min=within_min, limit=500):
            add_project(row.get("project"), row.get("last_heartbeat"), "registry")

        for project, last_heartbeat in _filesystem_project_candidates(limit=limit * 4):
            add_project(project, last_heartbeat, "filesystem")

        sorted_projects = sorted(projects.items(), key=lambda kv: kv[1], reverse=True)
        filesystem_projects = [
            (project, heartbeat)
            for project, heartbeat in sorted_projects
            if "filesystem" in sources.get(project, set())
        ]
        history_projects = [
            (project, heartbeat)
            for project, heartbeat in sorted_projects
            if "filesystem" not in sources.get(project, set())
        ]
        filesystem_reserve = min(len(filesystem_projects), max(3, limit // 3), limit)
        selected: list[tuple[str, int]] = []
        selected.extend(history_projects[: max(0, limit - filesystem_reserve)])
        seen = {project for project, _ in selected}
        for project, heartbeat in filesystem_projects:
            if len(selected) >= limit:
                break
            if project in seen:
                continue
            selected.append((project, heartbeat))
            seen.add(project)
        if len(selected) < limit:
            for project, heartbeat in sorted_projects:
                if len(selected) >= limit:
                    break
                if project in seen:
                    continue
                selected.append((project, heartbeat))
                seen.add(project)

        items = [
            {
                "path": project,
                "name": os.path.basename(project.rstrip("/")) or project,
                "last_heartbeat": heartbeat,
            }
            for project, heartbeat in selected
        ]

        return {"count": len(items), "items": items, "ts": _time.time()}

    # ----- /filesystem/directories: folder-only browser for launch targets -----
    def _handle_filesystem_directories(self, q):
        raw_root = (q.get("root", [""])[0] or "").strip()
        try:
            offset = max(0, int(q.get("offset", ["0"])[0]))
        except (TypeError, ValueError):
            offset = 0
        try:
            limit = max(1, min(int(q.get("limit", ["100"])[0]), 250))
        except (TypeError, ValueError):
            limit = 100
        root = os.path.expanduser(raw_root) if raw_root else os.path.expanduser("~")
        root = os.path.abspath(root)
        home = os.path.abspath(os.path.expanduser("~"))
        tmp = os.path.abspath("/tmp")

        allowed = root == home or root.startswith(home + os.sep) or root == tmp or root.startswith(tmp + os.sep)
        if not allowed:
            self.send_error(403, "directory root must be under the user's home directory or /tmp")
            return
        if not os.path.isdir(root):
            self.send_error(404, f"directory not found: {root}")
            return

        try:
            payload = _cached_runtime_snapshot(
                ("filesystem-directories", root, offset, limit),
                FILESYSTEM_DIRECTORIES_CACHE_SECONDS,
                lambda: self._filesystem_directories_payload(root, home, tmp, offset, limit),
            )
        except PermissionError:
            self.send_error(403, f"permission denied: {root}")
            return
        except OSError as exc:
            self.send_error(500, f"could not list directory: {str(exc)[:160]}")
            return
        self._send_json(payload)

    def _filesystem_directories_payload(self, root: str, home: str, tmp: str, offset: int, limit: int) -> dict:
        try:
            names = os.listdir(root)
        except PermissionError:
            raise
        except OSError as exc:
            raise exc

        items = []
        for name in names:
            if name in {".", ".."}:
                continue
            path = os.path.join(root, name)
            try:
                is_dir = os.path.isdir(path)
            except OSError:
                is_dir = False
            if not is_dir:
                continue
            items.append({
                "name": name,
                "path": path,
            })

        items.sort(key=lambda item: (item["name"].startswith("."), item["name"].lower()))
        page = items[offset:offset + limit]
        next_offset = offset + len(page)
        has_more = next_offset < len(items)
        parent = None
        if root != home and root != tmp:
            candidate = os.path.dirname(root)
            if candidate and (candidate == home or candidate.startswith(home + os.sep) or candidate == tmp or candidate.startswith(tmp + os.sep)):
                parent = candidate

        return {
            "root": root,
            "parent": parent,
            "count": len(items),
            "items": page,
            "has_more": has_more,
            "next_offset": next_offset if has_more else None,
            "ts": _time.time(),
        }

    # ----- /sessions: list active sessions, enriched with first-prompt preview -----
    def _handle_sessions_visible(self, q):
        provider_filter = q.get("provider", ["all"])[0].lower()
        if not _valid_provider_filter(provider_filter):
            _send_unknown_provider(self, provider_filter)
            return
        try:
            within_min = int(q.get("active_within_min", [str(60 * 24 * 7)])[0])
        except ValueError:
            within_min = 60 * 24 * 7
        within_min = max(1, min(within_min, 60 * 24 * 14))

        payload = _cached_runtime_snapshot(
            ("sessions-visible", provider_filter, within_min, 200),
            RUNTIME_SNAPSHOT_CACHE_SECONDS,
            lambda: {
                "source": _sessions_stream_source(),
                "items": self._collect_visible_session_rows(provider_filter, active_within_min=within_min, limit=200),
                "ts": _time.time(),
            },
        )
        payload["count"] = len(payload.get("items") or [])
        self._send_json(payload)

    def _collect_visible_session_rows(self, provider_filter: str, active_within_min: int, limit: int = 200) -> list[dict]:
        rows: list[dict] = []
        if provider_filter in ("all", "claude"):
            for raw in self._collect_session_rows(
                since_min=active_within_min,
                live_only=False,
                limit=max(limit, 50),
                include_first_prompt=True,
            ):
                native_id = raw.get("id") or ""
                claude_pid = int(raw.get("claude_pid") or 0)
                terminal_tty = raw.get("terminal_tty") or ""
                claude_uuid = raw.get("claude_uuid") or ""
                row = dict(raw)
                _decorate_claude_session_row(row, native_id, claude_pid, terminal_tty)
                row.update(self._turn_state_summary(claude_uuid))
                _refresh_claude_observed_activity(row, row.get("project"), claude_uuid)
                signal = self._recent_session_signal(native_id, project=row.get("project"), claude_uuid=claude_uuid)
                row["recent_anomaly"] = signal.get("anomaly")
                row["latest_command"] = signal.get("latest_command")
                row["latest_edit"] = signal.get("latest_edit")
                rows.append(self._decorate_session_lifecycle_row(row))

        if provider_filter in ("all", "codex"):
            for row in _list_codex_sessions(live_only=False, active_within_min=active_within_min):
                rows.append(self._decorate_session_lifecycle_row(row))

        rows.sort(key=lambda r: int(r.get("last_heartbeat") or 0), reverse=True)
        rows = rows[:max(1, min(int(limit or 200), 500))]
        for row in rows:
            row["runtime_truth_summary"] = self._runtime_truth_summary_for_row(row)
        _record_sessions_scan(rows)
        return rows

    def _runtime_truth_summary_for_row(self, row: dict) -> dict:
        capabilities = set(row.get("capabilities") or [])
        terminal_backed = bool({"terminal_output", "terminal_surface", "terminal_control"} & capabilities)
        transcript_missing = terminal_backed and "transcript" not in capabilities
        transcript_message = "Live terminal only - not in transcript" if transcript_missing else ""
        attention = row.get("terminal_attention") if isinstance(row.get("terminal_attention"), dict) else None
        if attention and attention.get("needs_input"):
            return {
                "primary_label": "Terminal awaiting selection",
                "secondary_label": transcript_message,
                "tone": "attention",
                "requires_attention": True,
                "blocks_control": False,
                "selected_surface": "v2" if "terminal_surface" in capabilities else "unknown",
                "degradation_codes": ["transcript_missing"] if transcript_missing else [],
                "contradiction_codes": [],
            }
        secondary_label = transcript_message
        if not secondary_label and row.get("readable_state") == "stale":
            secondary_label = "Registry stale"
        return {
            "primary_label": row.get("working_on") or row.get("first_prompt") or "Session",
            "secondary_label": secondary_label,
            "tone": "muted" if row.get("readable_state") in {"closed", "offline"} else "normal",
            "requires_attention": False,
            "blocks_control": False,
            "selected_surface": "v2" if "terminal_surface" in capabilities else "none",
            "degradation_codes": ["transcript_missing"] if transcript_missing else [],
            "contradiction_codes": [],
        }

    def _sessions_backend_degradation(self) -> dict | None:
        """Cheap cached probe distinguishing "PG answered: zero sessions"
        from "PG unreachable" (Docker down). Without it the sessions stream
        emitted an empty snapshot during outages and the phone wiped its
        list — sessions looked deleted instead of unreadable.

        In sqlite mode the registry is in-process and cannot be "down", so
        there is no degradation axis — return None unconditionally."""
        if _session_backend() == "sqlite":
            return None

        def probe() -> dict:
            ok, _, _ = _run_text(
                ["docker", "exec", "continuous-claude-postgres",
                 "psql", "-U", "claude", "-d", "continuous_claude",
                 "-tAc", "SELECT 1"],
                timeout=4,
            )
            return {"ok": bool(ok)}

        result = _cached_probe("sessions_backend_pg", 10.0, probe)
        if result.get("ok"):
            return None
        return {
            "reason": "sessions_backend_unreachable",
            "detail": "Session database is unreachable on the Mac (is Docker running?).",
        }

    def _collect_sessions_stream_rows(self, provider_filter: str) -> list[dict]:
        payload = _cached_runtime_snapshot(
            ("sessions-stream-rows", provider_filter),
            RUNTIME_SNAPSHOT_CACHE_SECONDS,
            lambda: {
                "items": self._collect_visible_session_rows(
                    provider_filter,
                    active_within_min=60 * 24 * 7,
                    limit=200,
                )
            },
        )
        return list(payload.get("items") or [])

    def _decorate_session_lifecycle_row(self, row: dict) -> dict:
        row.setdefault("closed_at", None)
        if "turn_count" not in row:
            provider = row.get("provider") or "claude"
            native_id = row.get("native_id") or row.get("id") or ""
            transcript_path = None
            if provider == "codex" and native_id:
                transcript_path = _resolve_codex_transcript(native_id)
            elif row.get("project") and row.get("claude_uuid"):
                transcript_path = HOME / ".claude" / "projects" / _encode_project_dir(row["project"]) / f"{row['claude_uuid']}.jsonl"
            row["turn_count"] = _session_transcript_stats(transcript_path, provider, native_id).get("turn_count")
        decorated = self._decorate_visible_session_row(row)
        decorated.setdefault("closed_at", None)
        decorated.setdefault("turn_count", None)
        if decorated.get("readable_state") == "closed":
            decorated["state"] = decorated.get("state") or "terminated"
        return decorated

    def _decorate_visible_session_row(self, row: dict) -> dict:
        now = int(_time.time())
        last = int(row.get("last_heartbeat") or 0)
        closed_at = row.get("closed_at")
        age = max(0, now - last) if last else 0

        controllability = dict(row.get("controllability") or {})
        can_control = bool(
            not closed_at
            and (
                controllability.get("can_send_text")
                or controllability.get("can_interrupt")
                or controllability.get("can_terminate")
            )
        )

        if closed_at:
            readable_state = "closed"
        elif age <= 60 * 60:
            readable_state = "live"
        elif can_control or age <= 60 * 24 * 60:
            readable_state = "stale"
        else:
            readable_state = "offline"

        if can_control:
            control_state = "controllable"
            control_reason = None
        else:
            control_state = "read_only" if readable_state == "closed" or "transcript" in set(row.get("capabilities") or []) else "unavailable"
            if readable_state == "closed":
                control_reason = "Session is closed; transcript remains readable."
            elif readable_state in {"stale", "offline"}:
                control_reason = "Session is not live on the Mac; transcript remains readable."
            else:
                control_reason = controllability.get("reason") or "Live control metadata is unavailable; transcript remains readable."
            controllability = {
                "can_send_text": False,
                "can_interrupt": False,
                "can_terminate": False,
                "reason": control_reason,
            }
            row["capabilities"] = [cap for cap in (row.get("capabilities") or []) if cap in {"transcript", "export", "live_state"}]

        row["readable_state"] = readable_state
        row["control_state"] = control_state
        row["control_reason"] = control_reason
        row["controllability"] = controllability
        row["stale_seconds"] = age
        return row

    def _handle_sessions(self, q):
        # Live filter: ?live=true returns only currently-running terminals
        # (no tombstone AND heartbeat within 2 min). Uses partial index
        # idx_sessions_live for fast lookups. iOS Dashboard should pass live=true.
        # Without the param, legacy behavior is preserved (heartbeat-window only,
        # no tombstone awareness) for any existing callers.
        live_only = q.get("live", ["false"])[0].lower() in ("true", "1", "yes")
        provider_filter = q.get("provider", ["all"])[0].lower()
        if not _valid_provider_filter(provider_filter):
            _send_unknown_provider(self, provider_filter)
            return

        try:
            within_min = int(q.get("active_within_min", ["60"])[0])
        except ValueError:
            within_min = 60

        if provider_filter != "all" and provider_filter not in AGENT_PROVIDERS:
            self._send_json({"count": 0, "items": []})
            return

        if provider_filter == "codex":
            rows = [
                self._decorate_session_lifecycle_row(row)
                for row in _list_codex_sessions(live_only=live_only, active_within_min=within_min)
            ]
            _record_sessions_scan(rows)
            body = json.dumps({"count": len(rows), "items": rows}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Live filter semantics (live_only): not explicitly closed, has a
        # claude_uuid (proves hooks fired post-migration), AND heartbeat is
        # fresh enough. The freshness gate hides DORMANT zombies — claudes
        # whose process is technically alive but stopped firing hooks hours
        # or days ago (typical of sentinel-mode terminals whose hooks point
        # at the Sentinel daemon on :9100 instead of us). The kill -0 GC
        # below catches process-DEAD rows; this catches
        # process-alive-but-mute rows. Defaults to within_min=60.
        backend = _claude_sessions_backend()
        try:
            backend_rows = backend.sessions_rows(live_only, within_min)
        except RuntimeError as exc:
            self.send_error(502, str(exc)[:220])
            return

        rows = []
        zombie_ids: list[str] = []  # sessions whose claude_pid no longer exists
        for raw in backend_rows:
            session_id = raw["id"]
            project = raw["project"]
            if _is_excluded_project(project):
                continue
            claude_pid = int(raw.get("claude_pid") or 0)
            claude_uuid = raw.get("claude_uuid") or ""
            terminal_tty = raw.get("terminal_tty") or ""

            # Process-liveness GC for live=true: kill -0 the recorded pid.
            # If it's gone, mark the row closed and exclude from response.
            # Avoids stale buckets that fail every Send because the Terminal
            # tab is gone. Sessions without a recorded pid (predate migration)
            # are kept — they'll be backfilled on next hook fire.
            if live_only and claude_pid > 0:
                try:
                    os.kill(claude_pid, 0)
                except ProcessLookupError:
                    zombie_ids.append(session_id)
                    continue
                except PermissionError:
                    # process exists but we can't signal it (other uid).
                    # Treat as alive — same response either way.
                    pass

            row = {
                "id": session_id,
                "project": project,
                "working_on": raw.get("working_on") or None,
                "started_at": int(raw.get("started_at") or 0),
                "last_heartbeat": int(raw.get("last_heartbeat") or 0),
                "first_prompt": None,
            }
            _decorate_claude_session_row(row, session_id, claude_pid, terminal_tty)
            row.update(self._turn_state_summary(claude_uuid))
            _refresh_claude_observed_activity(row, project, claude_uuid)
            signal = self._recent_session_signal(session_id, project=project, claude_uuid=claude_uuid)
            row["recent_anomaly"] = signal.get("anomaly")
            row["latest_command"] = signal.get("latest_command")
            row["latest_edit"] = signal.get("latest_edit")
            # FAST PATH: derive the encoded project dir from the PG project
            # value and look up the most recent jsonl directly. Avoids walking
            # the entire ~/.claude/projects/ tree once per session row.
            encoded_dir = _encode_project_dir(project)
            target_dir = HOME / ".claude" / "projects" / encoded_dir
            if target_dir.is_dir():
                jsonls = sorted(
                    target_dir.glob("*.jsonl"),
                    key=lambda p: p.stat().st_mtime, reverse=True,
                )
                if jsonls:
                    row["first_prompt"] = _peek_first_prompt(jsonls[0])
            rows.append(row)

        # Tombstone any zombies discovered during process-liveness GC. One
        # batch write so /sessions stays fast even with several stale rows.
        if zombie_ids:
            backend.tombstone_sessions(zombie_ids)

        if provider_filter == "all":
            rows.extend(
                self._decorate_session_lifecycle_row(row)
                for row in _list_codex_sessions(live_only=live_only, active_within_min=within_min)
            )
            rows.sort(key=lambda r: int(r.get("last_heartbeat") or 0), reverse=True)
            rows = rows[:50]

        _record_sessions_scan(rows)
        body = json.dumps({"count": len(rows), "items": rows}).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_session_source_diagnostics(self, q):
        try:
            since_min = int(q.get("since_min", ["1440"])[0])
        except ValueError:
            since_min = 1440
        since_min = max(1, min(since_min, 60 * 24 * 14))

        claude_live = self._collect_session_rows(
            since_min=since_min,
            live_only=True,
            limit=500,
            include_first_prompt=False,
        )
        codex_registry = _agent_registry_recent("codex", since_min=since_min, limit=500)
        codex_live_registry = _agent_registry_live("codex")
        codex_rollouts = _codex_rollout_paths()
        now = int(_time.time())
        live_codex_rows = _list_codex_sessions(live_only=True, active_within_min=since_min)

        items = [
            {
                "id": "claude:postgres",
                "provider": "claude",
                "source": "postgres_sessions",
                "total": len(claude_live),
                "live": len(claude_live),
                "fresh": sum(1 for row in claude_live if now - int(row.get("last_heartbeat") or 0) < 120),
                "stale": sum(1 for row in claude_live if now - int(row.get("last_heartbeat") or 0) >= 120),
                "notes": [
                    "Requires closed_at null, claude_uuid present, and a recent heartbeat.",
                    "This is the canonical Claude dashboard source.",
                ],
            },
            {
                "id": "codex:registry",
                "provider": "codex",
                "source": "agent_registry",
                "total": len(codex_registry),
                "live": len(codex_live_registry),
                "fresh": sum(1 for row in codex_live_registry if now - int(row.get("last_heartbeat") or 0) < 120),
                "stale": sum(1 for row in codex_live_registry if now - int(row.get("last_heartbeat") or 0) >= 120),
                "notes": [
                    "Registry rows with a live pid stay visible even when heartbeat is stale.",
                    "These rows provide Codex control metadata.",
                ],
            },
            {
                "id": "codex:rollouts",
                "provider": "codex",
                "source": "codex_rollout_jsonl",
                "total": len(codex_rollouts),
                "live": len([row for row in live_codex_rows if row.get("provider") == "codex"]),
                "fresh": len([row for row in live_codex_rows if int(row.get("last_heartbeat") or 0) >= now - 120]),
                "stale": len([row for row in live_codex_rows if int(row.get("last_heartbeat") or 0) < now - 120]),
                "notes": [
                    "Read-only rollout transcripts backfill session history.",
                    "Registry overlay adds control when metadata exists.",
                ],
            },
        ]
        self._send_json({"count": len(items), "items": items, "ts": _time.time()})

    def _turn_state_summary(self, claude_uuid: str) -> dict:
        """Cheap status payload for session-list rows. The heavier branch,
        dirty-count, and cost fields stay in /status; dashboard rows only need
        enough to show whether a claude is thinking, using a tool, or idle."""
        if not claude_uuid:
            return {}
        try:
            path = HOME / ".claude" / "turn-state" / f"{claude_uuid}.json"
            if not path.is_file():
                return {}
            obj = json.loads(path.read_text())
        except Exception:
            return {}
        return {
            "state": obj.get("state"),
            "tool": obj.get("tool"),
            "turn_started_at": obj.get("started_at"),
            "turn_state_updated_at": obj.get("last_update"),
            "effort": obj.get("effort"),
            "model": obj.get("model"),
            "context_pct": obj.get("context_pct"),
        }

    # ----- /sessions-stream: live SSE feed of every active session -----
    def _handle_sessions_stream(self, q):
        """SSE stream of the live-sessions list. Polls PG every 1.5s, emits
        only when the result set changes (by hash). Powers a single
        SessionStore on the iPhone that every view binds to — replaces the
        Dashboard's on-appear + pull-to-refresh polling pattern.

        Event shapes:
          event: snapshot     data: {"items":[...], "ts":<epoch>}
          event: keepalive    data: {} (every 20s for NAT)
          event: done         data: {} (10-min cap; iOS reconnects)

        The full snapshot is re-sent on every diff — payload is small (<50
        rows × <500 bytes each), and computing per-session deltas would
        complicate iOS-side reconciliation for negligible bandwidth gain.
        """
        provider_filter = q.get("provider", ["all"])[0].lower()
        if not _valid_provider_filter(provider_filter):
            _send_unknown_provider(self, provider_filter)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        last_hash: str | None = None
        last_keepalive = _time.time()
        deadline = _time.time() + 600  # 10 min

        def collect_live() -> list[dict]:
            return self._collect_sessions_stream_rows(provider_filter)

        # Hash JUST the rows list, NOT the timestamp — otherwise the
        # diff detector triggers every tick because `ts` always changes.
        def hash_rows(rows: list[dict]) -> str:
            return hashlib.sha256(
                json.dumps(rows, sort_keys=True).encode()
            ).hexdigest()

        def snapshot_payload(rows: list[dict]) -> tuple[bytes, str]:
            degraded = self._sessions_backend_degradation()
            body: dict = {"source": _sessions_stream_source(), "items": rows, "ts": _time.time()}
            if degraded is not None:
                body["degraded"] = degraded
            digest = hashlib.sha256(
                json.dumps({"rows": rows, "degraded": degraded}, sort_keys=True).encode()
            ).hexdigest()
            return json.dumps(body).encode(), digest

        try:
            # Emit initial snapshot immediately so the iPhone never paints
            # an empty Dashboard while waiting for the first poll.
            initial = collect_live()
            payload, last_hash = snapshot_payload(initial)
            self.wfile.write(b"event: snapshot\ndata: " + payload + b"\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            pass

        try:
            while _time.time() < deadline:
                _time.sleep(1.5)
                rows = collect_live()
                payload, h = snapshot_payload(rows)
                if h != last_hash:
                    try:
                        self.wfile.write(b"event: snapshot\ndata: " + payload + b"\n\n")
                        self.wfile.flush()
                        last_hash = h
                    except (BrokenPipeError, ConnectionResetError):
                        return
                if _time.time() - last_keepalive >= 20:
                    try:
                        self.wfile.write(b"event: keepalive\ndata: {}\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    last_keepalive = _time.time()
            try:
                self.wfile.write(b"event: done\ndata: {}\n\n")
                self.wfile.flush()
            except Exception:
                pass
        except (BrokenPipeError, ConnectionResetError):
            return

    # ----- /transcript: stream JSONL by byte offset -----
    def _handle_transcript(self, q):
        session_id = q.get("session", [""])[0]
        if not session_id:
            self.send_error(400, "session required")
            return
        try:
            since = int(q.get("since", ["0"])[0])
        except ValueError:
            self.send_error(400, "since must be int bytes")
            return

        provider, native_id = _parse_agent_session_ref(session_id)
        launch_context = _session_launch_context_from_metadata(
            _registry_metadata_from_row(_agent_registry_get(provider, native_id))
        ) if native_id else None
        if provider == "codex":
            path = _resolve_codex_transcript(native_id)
        else:
            path = self._resolve_transcript(session_id)
        if path is None or not path.exists():
            self.send_error(404, f"no transcript resolvable for session={session_id}")
            return

        size = path.stat().st_size
        start = min(since, size)
        if since == 0 and size > TRANSCRIPT_INITIAL_STREAM_BYTES:
            start = max(0, size - TRANSCRIPT_INITIAL_STREAM_BYTES)
        with open(path, "rb") as f:
            f.seek(start)
            data = f.read()
        if start > 0:
            first_newline = data.find(b"\n")
            if first_newline >= 0:
                data = data[first_newline + 1:]
        if provider == "codex":
            data = _normalize_codex_ndjson(data, native_id).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("X-Total-Bytes", str(size))
        self.send_header("X-Bytes-Read", str(len(data)))
        self.send_header("X-Next-Since", str(size))
        self.send_header("X-Resolved-Path", path.name)
        self.end_headers()
        self.wfile.write(data)

    # ----- /transcript-stream: live SSE feed of a session's JSONL -----
    def _handle_transcript_stream(self, q):
        """SSE stream of one session's JSONL. Resolves the path ONCE at
        connect time, opens the file ONCE and keeps the handle, and polls
        os.fstat() every 100ms. On each tick that the size has grown,
        reads the new bytes and advances ONLY through the last complete
        '\\n' — trailing partial-line bytes are buffered server-side until
        the next tick completes them. Without that, mid-write reads would
        emit a partial JSONL line and the iOS-side per-line JSON decode
        would silently drop the half-formed entry's eventual content.

        Path resolution happens once per connection. If the JSONL rotates
        mid-stream (a /resume swap to a different claude_uuid, or an
        external truncate), the file size shrinks below our offset and
        we disconnect — the client reconnects via its outer auto-retry
        loop and we re-resolve on the new connection. Keeps this handler
        focused; rotation is a rare, fully-recoverable edge case.

        Worst-case end-to-end latency: 100ms (poll cadence) + network
        round-trip. Replaces the iPhone's 1500ms /transcript polling.

        Params:
          session — required; PG s-id or claude_uuid
          since   — initial byte offset (default 0)
        """
        session_id = q.get("session", [""])[0]
        if not session_id:
            self.send_error(400, "session required")
            return
        try:
            since = int(q.get("since", ["0"])[0])
        except ValueError:
            since = 0

        provider, native_id = _parse_agent_session_ref(session_id)
        if provider == "codex":
            path = _resolve_codex_transcript(native_id)
        else:
            path = self._resolve_transcript(session_id)
        if path is None or not path.exists():
            self.send_error(404, f"no transcript resolvable for session={session_id}")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        POLL_INTERVAL = 0.1
        KEEPALIVE_INTERVAL = 20.0
        MAX_DURATION = 600.0

        last_emitted_offset = since
        pending_partial = b""
        last_keepalive = _time.time()
        deadline = _time.time() + MAX_DURATION

        f = None
        try:
            f = open(path, "rb")
            opened_stat = os.fstat(f.fileno())
            last_emitted_offset = _bounded_transcript_stream_start(since=since, size=opened_stat.st_size)
            if last_emitted_offset > 0:
                f.seek(last_emitted_offset - 1)
                previous = f.read(1)
                if previous != b"\n":
                    skipped = f.readline()
                    last_emitted_offset = min(opened_stat.st_size, last_emitted_offset + len(skipped))
            f.seek(last_emitted_offset)

            def _emit_reset(total_bytes: int = 0):
                payload = {
                    "next_since": 0,
                    "total_bytes": max(0, total_bytes),
                    "ndjson": "",
                    "reset": True,
                }
                _sse_write_json_event(self.wfile, "tail", payload, max_bytes=SSE_TRANSCRIPT_MAX_EVENT_BYTES)

            def _emit_complete_lines():
                """Read what's currently available, accumulate into
                pending_partial, emit complete lines through the last
                '\\n', advance last_emitted_offset. Returns False on a
                broken pipe so the caller can clean up."""
                nonlocal last_emitted_offset, pending_partial, last_keepalive
                try:
                    new_data = f.read()
                except OSError:
                    return False
                if new_data:
                    pending_partial += new_data
                idx = pending_partial.rfind(b"\n")
                if idx < 0:
                    return True  # All trailing partial; nothing to emit yet.
                complete = pending_partial[:idx + 1]
                pending_partial = pending_partial[idx + 1:]
                new_offset = last_emitted_offset + len(complete)
                raw_lines = complete.splitlines(keepends=True)
                chunk = b""
                chunk_start_offset = last_emitted_offset
                final_total = new_offset + len(pending_partial)

                def _emit_raw_chunk(raw_chunk: bytes, next_offset: int) -> bool:
                    ndjson = raw_chunk.decode("utf-8", errors="replace")
                    if provider == "codex":
                        ndjson = _normalize_codex_ndjson(raw_chunk, native_id, include_event_fallback=False)
                    return _sse_write_json_event(
                        self.wfile,
                        "tail",
                        {
                            "next_since": next_offset,
                            "total_bytes": final_total,
                            "ndjson": ndjson,
                        },
                        max_bytes=SSE_TRANSCRIPT_MAX_EVENT_BYTES,
                    )

                for raw_line in raw_lines:
                    candidate = chunk + raw_line
                    ndjson = candidate.decode("utf-8", errors="replace")
                    if provider == "codex":
                        ndjson = _normalize_codex_ndjson(candidate, native_id, include_event_fallback=False)
                    _, diagnostic = _sse_json_event(
                        "tail",
                        {
                            "next_since": chunk_start_offset + len(candidate),
                            "total_bytes": final_total,
                            "ndjson": ndjson,
                        },
                        max_bytes=SSE_TRANSCRIPT_MAX_EVENT_BYTES,
                    )
                    if diagnostic and chunk:
                        if not _emit_raw_chunk(chunk, chunk_start_offset + len(chunk)):
                            return False
                        chunk_start_offset += len(chunk)
                        chunk = raw_line
                    elif diagnostic:
                        if not _sse_write_json_event(
                            self.wfile,
                            "tail",
                            {
                                "next_since": chunk_start_offset + len(raw_line),
                                "total_bytes": final_total,
                                "ndjson": raw_line.decode("utf-8", errors="replace"),
                            },
                            max_bytes=SSE_TRANSCRIPT_MAX_EVENT_BYTES,
                        ):
                            return False
                        chunk_start_offset += len(raw_line)
                        chunk = b""
                    else:
                        chunk = candidate
                if chunk and not _emit_raw_chunk(chunk, new_offset):
                    return False
                last_emitted_offset = new_offset
                last_keepalive = _time.time()
                return True

            # Initial snapshot — emit anything from `since` to current EOF
            # (through the last \n) so the client has a baseline even if
            # no new writes happen for a while.
            if not _emit_complete_lines():
                return

            while _time.time() < deadline:
                _time.sleep(POLL_INTERVAL)

                try:
                    size = os.fstat(f.fileno()).st_size
                except OSError:
                    return

                # Rotation/rebind: the path now points at a different JSONL
                # inode than the handle we opened. Tell the client to reset its
                # byte offset, then close so its reconnect re-resolves the path.
                try:
                    current_stat = path.stat()
                    if (current_stat.st_ino, current_stat.st_dev) != (opened_stat.st_ino, opened_stat.st_dev):
                        _emit_reset(current_stat.st_size)
                        return
                except OSError:
                    _emit_reset(0)
                    return

                # Rotation/truncate: shrunk below our position. Disconnect;
                # the client's auto-retry will reconnect and we'll re-resolve.
                if size < last_emitted_offset + len(pending_partial):
                    _emit_reset(size)
                    return

                if size > last_emitted_offset + len(pending_partial):
                    if not _emit_complete_lines():
                        return

                now = _time.time()
                if now - last_keepalive >= KEEPALIVE_INTERVAL:
                    try:
                        self.wfile.write(b"event: keepalive\ndata: {}\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    last_keepalive = now

            try:
                self.wfile.write(b"event: done\ndata: {}\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
        except (BrokenPipeError, ConnectionResetError):
            return
        except OSError as e:
            self.log_message("transcript-stream OSError for %s: %s", session_id, e)
            return
        finally:
            if f is not None:
                try:
                    f.close()
                except OSError:
                    pass

    # ----- /terminal-stream: live terminal output by byte offset -----
    def _session_live_event_envelope(
        self,
        *,
        event_seq: int,
        event_type: str,
        session_id: str,
        provider: str,
        native_id: str,
        payload: dict,
        truth: dict | None = None,
        source: str = "session-live-events",
        terminal_offset: int | None = None,
        transcript_offset: int | None = None,
    ) -> dict:
        truth = truth or {}
        runtime = truth.get("runtime") if isinstance(truth.get("runtime"), dict) else {}
        process = truth.get("process") if isinstance(truth.get("process"), dict) else {}
        terminal = truth.get("terminal") if isinstance(truth.get("terminal"), dict) else {}
        v2 = terminal.get("v2") if isinstance(terminal.get("v2"), dict) else {}
        return {
            "schema_version": 1,
            "event_seq": event_seq,
            "event_type": event_type,
            "observed_at": _time.time(),
            "source": source,
            "session_id": session_id,
            "provider": provider,
            "native_id": native_id,
            "broker_id": v2.get("broker_id") or process.get("broker_id"),
            "pid": process.get("pid"),
            "tty": process.get("terminal_tty") or v2.get("tty"),
            "terminal_generation": v2.get("generation"),
            "terminal_offset": terminal_offset,
            "transcript_offset": transcript_offset,
            "runtime_version": RUNTIME_CONTRACT_VERSION,
            "source_revision": runtime.get("source_revision") or runtime.get("app_source_revision"),
            "payload": payload,
        }

    def _session_live_transcript_tail(self, provider: str, native_id: str, raw_session: str, since: int) -> dict | None:
        path = _resolve_codex_transcript(native_id) if provider == "codex" else self._resolve_transcript(raw_session)
        if path is None or not path.exists():
            return None
        try:
            stat = path.stat()
        except OSError:
            return None
        size = max(0, int(stat.st_size))
        since = max(0, int(since or 0))
        if since > size:
            return {
                "next_since": 0,
                "total_bytes": size,
                "ndjson": "",
                "reset": True,
            }
        start = _bounded_transcript_stream_start(since=since, size=size)
        if start >= size:
            return None
        # Size the read window so the JSON-escaped ndjson plus the event
        # envelope stays under SSE_TRANSCRIPT_MAX_EVENT_BYTES — escaping can
        # roughly double the byte count, which used to overflow the writer
        # ("event_too_large") even though the raw read fit.
        read_cap = max(16 * 1024, SSE_TRANSCRIPT_MAX_EVENT_BYTES // 2 - 8 * 1024)
        try:
            with open(path, "rb") as f:
                f.seek(start)
                data = f.read(min(size - start, read_cap))
                idx = data.rfind(b"\n")
                if idx < 0 and len(data) >= read_cap:
                    # A single transcript line larger than the read window
                    # (giant tool dump). It can never fit in one SSE event;
                    # without this branch the tail re-read the same window
                    # forever and the live view wedged at "Connecting".
                    # Scan forward to the line end and skip past it.
                    scan_pos = start + len(data)
                    line_end = None
                    while scan_pos < size:
                        f.seek(scan_pos)
                        chunk = f.read(1024 * 1024)
                        if not chunk:
                            break
                        newline_at = chunk.find(b"\n")
                        if newline_at >= 0:
                            line_end = scan_pos + newline_at
                            break
                        scan_pos += len(chunk)
                    if line_end is None:
                        # Oversized line with no terminator yet — still being
                        # appended. Try again on a later pass.
                        return None
                    return {
                        "next_since": line_end + 1,
                        "total_bytes": size,
                        "ndjson": "",
                        "reset": start != since,
                        "skipped_oversized_bytes": line_end + 1 - start,
                    }
        except OSError:
            return None
        if idx < 0:
            return None
        complete = data[:idx + 1]
        if not complete:
            return None
        ndjson = complete.decode("utf-8", errors="replace")
        if provider == "codex":
            ndjson = _normalize_codex_ndjson(complete, native_id, include_event_fallback=False)
        return {
            "next_since": start + len(complete),
            "total_bytes": size,
            "ndjson": ndjson,
            "reset": start != since,
        }

    def _session_live_terminal_capture_path(self, provider: str, native_id: str, raw_session: str) -> Path | None:
        if provider == "claude":
            session_id = _claude_native_session_id(raw_session)
            if not session_id:
                return None
            tty = self._lookup_terminal_tty(session_id)
            project = self._lookup_pg_project(session_id)
            return _terminal_capture_for_tty(tty, project)
        if provider == "codex":
            reg = _agent_registry_get("codex", native_id) or {}
            try:
                metadata = json.loads(reg.get("metadata_json") or "{}")
            except Exception:
                metadata = {}
            return _terminal_capture_from_metadata(metadata)
        return None

    def _session_live_terminal_tail(self, raw_session: str, since: int) -> dict | None:
        provider, native_id = _parse_agent_session_ref(raw_session)
        since = max(0, int(since or 0))
        broker_found = self._broker_session_for(raw_session)
        if broker_found and PTY_BROKER:
            broker_id, _ = broker_found
            tail = PTY_BROKER.raw_tail(broker_id, since=since)
            if tail is None:
                return None
            data, next_offset, total_bytes, reset = tail
            if reset:
                return {
                    "next_since": 0,
                    "total_bytes": total_bytes,
                    "text": "",
                    "reset": True,
                    "backend": "pty_broker",
                    "broker_id": broker_id,
                }
            if not data:
                return None
            send_data, payload = _bounded_terminal_stream_chunk(
                data,
                last_offset=since,
                total_bytes=total_bytes,
                clean_text=lambda chunk: chunk.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n"),
            )
            payload["backend"] = "pty_broker"
            payload["broker_id"] = broker_id
            payload["raw_byte_count"] = len(send_data)
            return payload

        log_path = self._session_live_terminal_capture_path(provider, native_id, raw_session)
        if log_path is None or not _is_terminal_capture_path(log_path) or not log_path.exists():
            return None
        try:
            stat = log_path.stat()
        except OSError:
            return None
        size = max(0, int(stat.st_size))
        if since > size:
            return {
                "next_since": 0,
                "total_bytes": size,
                "text": "",
                "reset": True,
                "backend": "script_capture",
            }
        if since >= size:
            return None
        try:
            with open(log_path, "rb") as f:
                f.seek(since)
                data = f.read(min(size - since, SSE_TERMINAL_CHUNK_BYTES))
        except OSError:
            return None
        if not data:
            return None
        send_data, payload = _bounded_terminal_stream_chunk(
            data,
            last_offset=since,
            total_bytes=size,
            clean_text=lambda chunk: chunk.decode("utf-8", errors="replace")
                .replace("^D\x08\x08", "")
                .replace("\r\n", "\n")
                .replace("\r", "\n"),
        )
        payload["backend"] = "script_capture"
        payload["raw_byte_count"] = len(send_data)
        return payload

    def _handle_session_live_events(self, q):
        raw_session = q.get("session", [""])[0]
        provider, native_id = _parse_agent_session_ref(raw_session)
        if not native_id:
            self.send_error(400, "session required")
            return
        session_id = _qualified_session_id(provider, native_id)
        expected_source_revision = self._expected_source_revision_for_request(q)
        try:
            terminal_offset = int(q.get("since_terminal", ["0"])[0])
        except ValueError:
            terminal_offset = 0
        try:
            transcript_offset = int(q.get("since_transcript", ["0"])[0])
        except ValueError:
            transcript_offset = 0
        try:
            receipt_seq = int(q.get("client_event_seq", ["0"])[0])
        except ValueError:
            receipt_seq = 0

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        event_seq = 0
        last_truth_hash = ""
        last_truth: dict | None = None
        last_transcript_check = 0.0
        last_freshness_at = 0.0
        last_keepalive = _time.time()
        last_truth_error_message = ""
        terminal_line_buffer = ""
        deadline = _time.time() + 600.0

        # Runtime truth can block for seconds (terminal-surface probing runs
        # AppleScript against Terminal.app). Computing it inline starved the
        # transcript/terminal tails, which is exactly the "live view feels
        # delayed" failure. A per-connection worker refreshes truth on its own
        # cadence; the writer loop only ever reads the latest result, so tail
        # latency stays decoupled from probe latency.
        truth_stop = threading.Event()
        truth_slot: dict = {"result": None, "error": None, "fatal": False}

        def _truth_worker() -> None:
            while not truth_stop.is_set():
                try:
                    truth = self._session_runtime_truth(session_id, expected_source_revision=expected_source_revision)
                    # Digest the slimmed payload: screen-body churn should not
                    # re-emit truth — surface bytes ride their own streams.
                    slim = _session_runtime_truth_stream_payload(truth)
                    truth_slot["result"] = (truth, slim, _session_runtime_truth_stream_digest(slim))
                    truth_slot["error"] = None
                except ValueError as e:
                    truth_slot["error"] = ("bad_session", str(e)[:200])
                    truth_slot["fatal"] = True
                    return
                except Exception as e:
                    truth_slot["error"] = ("session_runtime_truth_unavailable", str(e)[:200])
                truth_stop.wait(1.0)

        truth_thread = threading.Thread(
            target=_truth_worker,
            name=f"live-events-truth-{native_id[:12]}",
            daemon=True,
        )

        def emit(event_type: str, payload: dict, *, source: str = "session-live-events") -> bool:
            nonlocal event_seq, last_keepalive
            event_seq += 1
            envelope = self._session_live_event_envelope(
                event_seq=event_seq,
                event_type=event_type,
                session_id=session_id,
                provider=provider,
                native_id=native_id,
                payload=payload,
                truth=last_truth,
                source=source,
                terminal_offset=terminal_offset,
                transcript_offset=transcript_offset,
            )
            max_bytes = SSE_TRANSCRIPT_MAX_EVENT_BYTES if event_type == "transcript_entries" else SSE_MAX_EVENT_BYTES
            ok = _sse_write_json_event(self.wfile, event_type, envelope, max_bytes=max_bytes)
            if ok:
                last_keepalive = _time.time()
            return ok

        try:
            if not emit("hello", {
                "session_id": session_id,
                "since_terminal": max(0, terminal_offset),
                "since_transcript": max(0, transcript_offset),
                "client_event_seq": max(0, receipt_seq),
                "stream": "session-live-events",
            }):
                return
            truth_thread.start()

            while _time.time() < deadline:
                now = _time.time()

                slot_result = truth_slot.get("result")
                slot_error = truth_slot.get("error")
                if slot_error is not None:
                    reason, message = slot_error
                    if truth_slot.get("fatal"):
                        emit("error", {"reason": reason, "message": message})
                        return
                    if message != last_truth_error_message:
                        last_truth_error_message = message
                        if not emit("error", {"reason": reason, "message": message}):
                            return
                if slot_result is not None:
                    truth, slim_truth, digest = slot_result
                    last_truth = truth
                    if digest != last_truth_hash:
                        last_truth_hash = digest
                        if not emit("truth", slim_truth, source="session-runtime-truth"):
                            return
                        turn = truth.get("turn") if isinstance(truth.get("turn"), dict) else {}
                        if turn:
                            if not emit("turn_state", turn, source="turn-state"):
                                return

                if last_truth is None:
                    # Preserve the original ordering guarantee: clients see the
                    # first truth event before any tail data, so reducers that
                    # gate terminal lines on transcript truth never drop bytes.
                    if now - last_keepalive >= 20.0:
                        if not emit("keepalive", {}):
                            return
                    _time.sleep(0.05)
                    continue

                for receipt_event in _session_live_control_receipts_since(session_id, receipt_seq):
                    receipt_seq = max(receipt_seq, int(receipt_event.get("receipt_seq") or 0))
                    if not emit("control_receipt", receipt_event, source="control-receipts"):
                        return

                terminal_payload = self._session_live_terminal_tail(session_id, terminal_offset)
                if terminal_payload is not None:
                    if terminal_payload.get("reset"):
                        terminal_offset = 0
                    else:
                        terminal_offset = int(terminal_payload.get("next_since") or terminal_offset)
                    if not emit("terminal_chunk", terminal_payload, source=str(terminal_payload.get("backend") or "terminal")):
                        return
                    text = _clean_terminal_display_text(str(terminal_payload.get("text") or ""))
                    if text:
                        terminal_line_buffer += text
                        while "\n" in terminal_line_buffer:
                            line, terminal_line_buffer = terminal_line_buffer.split("\n", 1)
                            if not emit("terminal_line", {
                                "text": line,
                                "line_id": f"{session_id}:{terminal_offset}:{event_seq}",
                                "terminal_offset": terminal_offset,
                            }, source=str(terminal_payload.get("backend") or "terminal")):
                                return

                if now - last_transcript_check >= 0.1:
                    transcript_payload = self._session_live_transcript_tail(provider, native_id, session_id, transcript_offset)
                    last_transcript_check = now
                    if transcript_payload is not None:
                        # ALWAYS advance to next_since — including on reset.
                        # `reset` tells the CLIENT to clear its accumulated
                        # entries; the tail's next_since is the correct server
                        # continuation in every reset case (bounded first-pass
                        # clamp, oversized-line skip, shrunk file → 0).
                        # Zeroing the offset here made the loop re-read the
                        # same tail window forever — and when that window
                        # began inside an oversized line, the skip pass
                        # repeated with empty ndjson and the phone never
                        # received any transcript content.
                        transcript_offset = int(transcript_payload.get("next_since") or 0)
                        if not emit("transcript_entries", transcript_payload, source="transcript"):
                            return

                if now - last_freshness_at >= 1.0:
                    truth_checked_at = None
                    if isinstance(last_truth, dict):
                        truth_checked_at = last_truth.get("checked_at")
                    transcript_state = None
                    if isinstance(last_truth, dict) and isinstance(last_truth.get("transcript"), dict):
                        transcript_state = last_truth["transcript"].get("state")
                    if not emit("freshness", {
                        "terminal_offset": terminal_offset,
                        "transcript_offset": transcript_offset,
                        "receipt_seq": receipt_seq,
                        "truth_age_seconds": max(0.0, now - float(truth_checked_at or now)),
                        "transcript_state": transcript_state,
                    }):
                        return
                    last_freshness_at = now

                if now - last_keepalive >= 20.0:
                    if not emit("keepalive", {}):
                        return

                _time.sleep(0.05)

            emit("done", {})
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as e:
            try:
                _sse_write_json_event(
                    self.wfile,
                    "error",
                    {"reason": "session_live_events_unavailable", "message": str(e)[:200]},
                    max_bytes=SSE_MAX_EVENT_BYTES,
                )
            except Exception:
                pass
        finally:
            truth_stop.set()

    def _transcript_truth_for_session(self, provider: str, native_id: str, raw_session: str) -> dict:
        if provider == "codex":
            path = _resolve_codex_transcript(native_id)
        else:
            path = self._resolve_transcript(raw_session)
        if path is None or not path.exists():
            return {
                "state": "missing",
                "http_status": 404,
                "reason": "no_transcript_resolvable",
                "durable": False,
                "searchable": False,
                "latest_offset": None,
                "path": None,
                "user_message": "Live terminal only - not in transcript",
            }
        try:
            stat = path.stat()
            latest_offset = stat.st_size
        except OSError:
            latest_offset = None
        return {
            "state": "live",
            "http_status": 200,
            "reason": None,
            "durable": True,
            "searchable": True,
            "latest_offset": latest_offset,
            "path": str(path),
            "user_message": None,
        }

    def _registry_truth_for_session(self, raw_session: str) -> dict:
        provider, native_id = _parse_agent_session_ref(raw_session)
        try:
            rows = self._collect_visible_session_rows(provider, active_within_min=60 * 24 * 14, limit=300)
            for row in rows:
                if row.get("id") == raw_session or row.get("native_id") == native_id:
                    return {
                        "state": row.get("state"),
                        "readable_state": row.get("readable_state"),
                        "control_state": row.get("control_state"),
                        "working_on": row.get("working_on"),
                        "stale_seconds": row.get("stale_seconds"),
                        "source_freshness": row.get("source_freshness"),
                        "last_seen_at": row.get("last_heartbeat"),
                        "project": row.get("project"),
                    }
        except Exception:
            pass
        return {
            "state": "unknown",
            "readable_state": "stale",
            "control_state": "unavailable",
            "working_on": None,
            "source_freshness": "unknown",
        }

    def _turn_truth_for_session(self, provider: str, native_id: str) -> dict:
        try:
            payload = _codex_turn_state_payload(native_id, apply_boundary=False) if provider == "codex" else {}
            if not payload and provider == "claude":
                payload = self._turn_state_summary(_lookup_claude_uuid_for_session(native_id))
            return {
                "state": payload.get("state"),
                "source": "turn-state-stream" if payload else "unavailable",
                "observed_at": payload.get("last_update") or payload.get("turn_state_updated_at"),
                "age_seconds": max(0, _time.time() - float(payload.get("last_update") or payload.get("turn_state_updated_at") or _time.time())) if payload else None,
            }
        except Exception:
            return {"state": "unknown", "source": "error"}

    def _terminal_stream_truth_for_session(self, raw_session: str) -> dict:
        provider, native_id = _parse_agent_session_ref(raw_session)
        source = _terminal_surface_source(raw_session)
        backend = source.get("source")
        byte_stream_available = bool(source.get("available")) and backend in {"broker_vt", "script_capture"}
        try:
            transcript_truth = self._transcript_truth_for_session(provider, native_id, raw_session)
        except Exception:
            transcript_truth = {"state": "unknown", "path": None}
        transcript_stream_available = bool(
            transcript_truth.get("state") in {"live", "archived", "stale"}
            and transcript_truth.get("path")
        )
        capacity_state = str(source.get("capacity_state") or "unknown")
        return {
            "byte_stream_available": bool(byte_stream_available),
            "surface_stream_available": bool(source.get("available")),
            "transcript_stream_available": transcript_stream_available,
            "source": backend,
            "backend": backend,
            "broker_id": source.get("broker_id"),
            "tty": source.get("tty"),
            "terminal_log": source.get("terminal_log"),
            "can_control": bool(source.get("can_control")),
            "last_chunk_at": None,
            "capacity_state": capacity_state,
            "capacity_verified": "capacity_state" in source,
            "fallback_reason": None if source.get("available") else source.get("reason"),
        }

    def _process_truth_for_session(self, provider: str, native_id: str) -> dict:
        if provider == "codex":
            reg = _agent_registry_get("codex", native_id)
            if not reg:
                return {
                    "state": "unknown",
                    "source": "agent_registry",
                    "reason": "registry_row_missing",
                }
            pid = int(reg.get("pid") or 0)
            closed_at = reg.get("closed_at")
            process_alive = bool(pid and _process_alive(pid))
            if closed_at:
                state = "closed"
            elif pid and process_alive:
                state = "alive"
            elif pid:
                state = "stale_pid"
            else:
                state = "registry_only"
            return {
                "state": state,
                "source": "agent_registry",
                "pid": pid or None,
                "process_alive": process_alive if pid else None,
                "registry_state": reg.get("state"),
                "last_heartbeat": reg.get("last_heartbeat"),
                "closed_at": closed_at,
                "terminal_tty": reg.get("terminal_tty") or None,
            }
        return {
            "state": "unknown",
            "source": "unverified",
            "reason": "process_truth_not_implemented_for_provider",
        }

    def _expected_source_revision_for_request(self, q) -> str | None:
        query_value = (
            q.get("expected_source_revision", [""])[0]
            or q.get("app_source_revision", [""])[0]
        ).strip()
        if query_value:
            return query_value
        try:
            header_value = str(self.headers.get("X-Pairling-App-Source-Revision") or "").strip()
        except Exception:
            header_value = ""
        return header_value or None

    def _session_runtime_truth(self, raw_session: str, expected_source_revision: str | None = None) -> dict:
        provider, native_id = _parse_agent_session_ref(raw_session)
        if not native_id:
            raise ValueError("session required")
        if provider not in AGENT_PROVIDERS:
            raise ValueError(f"unsupported provider: {provider}")
        session_id = _qualified_session_id(provider, native_id)
        v1 = None
        v2 = None
        terminal_probe_error = None
        try:
            v1 = self._broker_surface_snapshot(session_id)
        except Exception as e:
            terminal_probe_error = str(e)[:160]
            v1 = None
        if v1 is not None:
            try:
                v2 = self._broker_surface_v2_snapshot(session_id)
            except Exception:
                v2 = None
            if v2 is None:
                v2 = _terminal_surface_v2_degraded_from_v1(v1, provider=provider, native_id=native_id)
        else:
            try:
                v1 = self._terminal_app_surface_snapshot(
                    session_id,
                    osascript_timeout=TERMINAL_TRUTH_OSASCRIPT_TIMEOUT_SECONDS,
                )
                v2 = _terminal_surface_v2_degraded_from_v1(v1, provider=provider, native_id=native_id)
            except Exception as e:
                terminal_probe_error = str(e)[:160]
                v1 = None
                v2 = _terminal_surface_v2_unavailable(
                    provider=provider,
                    native_id=native_id,
                    reason=terminal_probe_error or "terminal surface unavailable",
                )
        return _session_runtime_truth_from_parts(
            session_id=session_id,
            registry=self._registry_truth_for_session(session_id),
            turn=self._turn_truth_for_session(provider, native_id),
            transcript=self._transcript_truth_for_session(provider, native_id, session_id),
            v1_surface=v1,
            v2_surface=v2,
            runtime=_runtime_freshness_truth(expected_source_revision=expected_source_revision),
            stream=self._terminal_stream_truth_for_session(session_id),
            process=self._process_truth_for_session(provider, native_id),
        )

    def _handle_session_runtime_truth(self, q):
        raw_session = q.get("session", [""])[0]
        expected_source_revision = self._expected_source_revision_for_request(q)
        try:
            truth = self._session_runtime_truth(raw_session, expected_source_revision=expected_source_revision)
        except ValueError as e:
            self.send_error(400, str(e))
            return
        except Exception as e:
            self._send_json({"ok": False, "error": "session_runtime_truth_unavailable", "message": str(e)[:200]}, status=502)
            return
        self._send_json({"ok": True, "truth": truth})

    def _handle_session_runtime_truth_stream(self, q):
        raw_session = q.get("session", [""])[0]
        if not raw_session:
            self.send_error(400, "session required")
            return
        expected_source_revision = self._expected_source_revision_for_request(q)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        last_hash = ""
        last_keepalive = _time.time()
        deadline = _time.time() + 600
        while _time.time() < deadline:
            try:
                truth = self._session_runtime_truth(raw_session, expected_source_revision=expected_source_revision)
                slim = _session_runtime_truth_stream_payload(truth)
                current_hash = _session_runtime_truth_stream_digest(slim)
                if current_hash != last_hash:
                    if not _sse_write_json_event(self.wfile, "snapshot", slim, max_bytes=SSE_MAX_EVENT_BYTES):
                        return
                    last_hash = current_hash
                    last_keepalive = _time.time()
                elif _time.time() - last_keepalive >= 20:
                    if not _sse_write_json_event(self.wfile, "keepalive", {}, max_bytes=SSE_MAX_EVENT_BYTES):
                        return
                    last_keepalive = _time.time()
            except ValueError as e:
                _sse_write_json_event(self.wfile, "error", {"reason": "bad_session", "message": str(e)[:200]}, max_bytes=SSE_MAX_EVENT_BYTES)
                return
            except Exception as e:
                _sse_write_json_event(self.wfile, "error", {"reason": "session_runtime_truth_unavailable", "message": str(e)[:200]}, max_bytes=SSE_MAX_EVENT_BYTES)
            _time.sleep(1.0)
        _sse_write_json_event(self.wfile, "done", {}, max_bytes=SSE_MAX_EVENT_BYTES)

    def _handle_terminal_workspace(self, q):
        raw_session = q.get("session", [""])[0]
        expected_source_revision = self._expected_source_revision_for_request(q)
        try:
            truth = self._session_runtime_truth(raw_session, expected_source_revision=expected_source_revision)
            workspace = _terminal_workspace_from_truth(truth)
        except ValueError as e:
            self.send_error(400, str(e))
            return
        except Exception as e:
            self._send_json({"ok": False, "error": "terminal_workspace_unavailable", "message": str(e)[:200]}, status=502)
            return
        self._send_json(workspace)

    def _handle_terminal_workspace_stream(self, q):
        raw_session = q.get("session", [""])[0]
        if not raw_session:
            self.send_error(400, "session required")
            return
        expected_source_revision = self._expected_source_revision_for_request(q)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        last_hash = ""
        last_keepalive = _time.time()
        deadline = _time.time() + 600
        while _time.time() < deadline:
            try:
                truth = self._session_runtime_truth(raw_session, expected_source_revision=expected_source_revision)
                workspace = _terminal_workspace_from_truth(truth)
                current_hash = _terminal_workspace_stream_digest(workspace)
                if current_hash != last_hash:
                    if not _sse_write_json_event(self.wfile, "snapshot", workspace, max_bytes=SSE_MAX_EVENT_BYTES):
                        return
                    last_hash = current_hash
                    last_keepalive = _time.time()
                elif _time.time() - last_keepalive >= 20:
                    if not _sse_write_json_event(self.wfile, "keepalive", {}, max_bytes=SSE_MAX_EVENT_BYTES):
                        return
                    last_keepalive = _time.time()
            except ValueError as e:
                _sse_write_json_event(self.wfile, "error", {"reason": "bad_session", "message": str(e)[:200]}, max_bytes=SSE_MAX_EVENT_BYTES)
                return
            except Exception as e:
                _sse_write_json_event(self.wfile, "error", {"reason": "terminal_workspace_unavailable", "message": str(e)[:200]}, max_bytes=SSE_MAX_EVENT_BYTES)
            # 0.35s keeps the phone's raw-terminal mirror near-realtime when
            # someone types on the Mac; truth composition is local state +
            # files, no PG, so the tighter cadence is cheap.
            _time.sleep(0.35)
        _sse_write_json_event(self.wfile, "done", {}, max_bytes=SSE_MAX_EVENT_BYTES)

    def _handle_terminal_stream_diagnostics(self, q):
        raw_session = q.get("session", [""])[0]
        expected_source_revision = self._expected_source_revision_for_request(q)
        try:
            truth = self._session_runtime_truth(raw_session, expected_source_revision=expected_source_revision)
        except ValueError as e:
            self.send_error(400, str(e))
            return
        except Exception as e:
            self._send_json({"ok": False, "error": "terminal_stream_diagnostics_unavailable", "message": str(e)[:200]}, status=502)
            return
        self._send_json(_terminal_stream_diagnostics_from_truth(truth))

    def _handle_terminal_stream(self, q):
        """SSE stream of the captured Terminal output for an app-spawned
        session. This is intentionally separate from /transcript-stream:
        transcript JSONL remains the durable semantic history, while this
        stream mirrors Claude Code's terminal output as bytes arrive.

        Params:
          session — provider-qualified or legacy Claude session id
          since   — initial byte offset in the terminal log (default 0)
        """
        raw_session = q.get("session", [""])[0]
        provider, native_id = _parse_agent_session_ref(raw_session)
        if not native_id:
            self.send_error(400, "session required")
            return
        raw_since = q.get("since", ["0"])[0]
        try:
            since = -1 if raw_since in ("end", "tail") else int(raw_since)
        except ValueError:
            since = 0
        start_at_end = since < 0
        since = max(0, since)

        broker_found = self._broker_session_for(raw_session)
        if broker_found:
            broker_id, _ = broker_found
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

            last_offset = since
            if start_at_end and PTY_BROKER:
                tail = PTY_BROKER.raw_tail(broker_id, since=0)
                last_offset = tail[1] if tail else 0
            last_keepalive = _time.time()
            deadline = _time.time() + 600

            while _time.time() < deadline and PTY_BROKER:
                tail = PTY_BROKER.raw_tail(broker_id, since=last_offset)
                if tail is None:
                    break
                data, next_offset, total_bytes, reset = tail
                if reset:
                    payload = {"next_since": 0, "total_bytes": total_bytes, "text": "", "reset": True}
                    last_offset = 0
                else:
                    send_data, payload = _bounded_terminal_stream_chunk(
                        data,
                        last_offset=last_offset,
                        total_bytes=total_bytes,
                        clean_text=lambda chunk: chunk.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n"),
                    )
                if data or reset:
                    if not _sse_write_json_event(self.wfile, "chunk", payload, max_bytes=SSE_MAX_EVENT_BYTES):
                        return
                    if data and not reset:
                        last_offset += len(send_data)
                    last_keepalive = _time.time()
                elif _time.time() - last_keepalive >= 20:
                    try:
                        self.wfile.write(b"event: keepalive\ndata: {}\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    last_keepalive = _time.time()
                _time.sleep(0.05)
            try:
                self.wfile.write(b"event: done\ndata: {}\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        log_path: Path | None = None
        if provider == "claude":
            session_id = _claude_native_session_id(raw_session)
            if not session_id:
                self.send_error(400, "invalid Claude session")
                return
            tty = self._lookup_terminal_tty(session_id)
            project = self._lookup_pg_project(session_id)
            log_path = _terminal_capture_for_tty(tty, project)
        elif provider == "codex":
            reg = _agent_registry_get("codex", native_id) or {}
            try:
                metadata = json.loads(reg.get("metadata_json") or "{}")
            except Exception:
                metadata = {}
            log_path = _terminal_capture_from_metadata(metadata)

        if log_path is None:
            self.send_error(404, "no terminal capture for session")
            return
        if not _is_terminal_capture_path(log_path):
            self.send_error(403, "terminal capture path rejected")
            return
        if not log_path.exists():
            self.send_error(404, "terminal capture log not found")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        POLL_INTERVAL = 0.05
        KEEPALIVE_INTERVAL = 20.0
        MAX_DURATION = 600.0
        last_emitted_offset = since
        last_keepalive = _time.time()
        deadline = _time.time() + MAX_DURATION

        def _clean_terminal_bytes(data: bytes) -> str:
            text = data.decode("utf-8", errors="replace")
            # Defensive cleanup for script logs produced from noninteractive
            # probes; real Terminal-launched captures do not include this.
            text = text.replace("^D\x08\x08", "")
            text = text.replace("\r\n", "\n").replace("\r", "\n")
            return text

        def _emit_chunk(data: bytes, total_bytes: int) -> int | None:
            send_data, payload = _bounded_terminal_stream_chunk(
                data,
                last_offset=last_emitted_offset,
                total_bytes=total_bytes,
                clean_text=_clean_terminal_bytes,
            )
            if not _sse_write_json_event(self.wfile, "chunk", payload, max_bytes=SSE_MAX_EVENT_BYTES):
                return None
            return len(send_data)

        def _emit_reset(total_bytes: int) -> bool:
            payload = {
                "next_since": 0,
                "total_bytes": max(0, total_bytes),
                "text": "",
                "reset": True,
            }
            return _sse_write_json_event(self.wfile, "chunk", payload, max_bytes=SSE_MAX_EVENT_BYTES)

        f = None
        try:
            f = open(log_path, "rb")
            opened_stat = os.fstat(f.fileno())
            size = opened_stat.st_size
            if start_at_end:
                last_emitted_offset = size
            if last_emitted_offset > size:
                if not _emit_reset(size):
                    return
                last_emitted_offset = 0
            f.seek(last_emitted_offset)
            if size > last_emitted_offset:
                data = f.read(min(size - last_emitted_offset, SSE_TERMINAL_CHUNK_BYTES))
                if data:
                    sent_len = _emit_chunk(data, size)
                    if sent_len is None:
                        return
                    last_emitted_offset += sent_len
                    f.seek(last_emitted_offset)

            while _time.time() < deadline:
                _time.sleep(POLL_INTERVAL)
                try:
                    current_stat = log_path.stat()
                    if (current_stat.st_ino, current_stat.st_dev) != (opened_stat.st_ino, opened_stat.st_dev):
                        _emit_reset(current_stat.st_size)
                        return
                    size = os.fstat(f.fileno()).st_size
                except OSError:
                    return

                if size < last_emitted_offset:
                    _emit_reset(size)
                    return
                if size > last_emitted_offset:
                    data = f.read(min(size - last_emitted_offset, SSE_TERMINAL_CHUNK_BYTES))
                    if data:
                        sent_len = _emit_chunk(data, size)
                        if sent_len is None:
                            return
                        last_emitted_offset += sent_len
                        f.seek(last_emitted_offset)
                        last_keepalive = _time.time()

                now = _time.time()
                if now - last_keepalive >= KEEPALIVE_INTERVAL:
                    try:
                        self.wfile.write(b"event: keepalive\ndata: {}\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    last_keepalive = now

            try:
                self.wfile.write(b"event: done\ndata: {}\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
        except (BrokenPipeError, ConnectionResetError):
            return
        except OSError as e:
            self.log_message("terminal-stream OSError for %s: %s", raw_session, e)
            return
        finally:
            if f is not None:
                try:
                    f.close()
                except OSError:
                    pass

    # ----- /terminal-surface: rendered terminal screen snapshot -----
    def _broker_session_for(self, raw_session: str):
        if PTY_BROKER is None:
            return None
        provider, native_id = _parse_agent_session_ref(raw_session)
        if not native_id:
            return None
        qualified = _qualified_session_id(provider, native_id)
        session = PTY_BROKER.get(qualified)
        if session:
            return qualified, session
        if provider == "codex":
            reg = _agent_registry_get("codex", native_id) or {}
            try:
                metadata = json.loads(reg.get("metadata_json") or "{}")
            except Exception:
                metadata = {}
            broker_id = str(metadata.get("broker_id") or "").strip()
            if broker_id:
                session = PTY_BROKER.get(broker_id)
                if session:
                    PTY_BROKER.register_alias(qualified, _broker_session_id(session))
                    return qualified, session
            tty = reg.get("terminal_tty") or ""
            if tty:
                session = PTY_BROKER.get_by_tty(tty)
                if session:
                    PTY_BROKER.register_alias(qualified, _broker_session_id(session))
                    return qualified, session
        if provider == "claude":
            session_id = _claude_native_session_id(raw_session)
            if not session_id:
                return None
            tty = self._lookup_terminal_tty(session_id)
            if tty:
                session = PTY_BROKER.get_by_tty(tty)
                if session:
                    qualified = _qualified_session_id("claude", session_id)
                    PTY_BROKER.register_alias(qualified, _broker_session_id(session))
                    return qualified, session
        return None

    def _broker_surface_snapshot(self, raw_session: str) -> dict | None:
        found = self._broker_session_for(raw_session)
        if not found:
            return None
        public_session_id, session = found
        return PTY_BROKER.snapshot(_broker_session_id(session), public_session_id=public_session_id) if PTY_BROKER else None

    def _broker_surface_v2_snapshot(self, raw_session: str) -> dict | None:
        found = self._broker_session_for(raw_session)
        if not found:
            return None
        public_session_id, session = found
        if PTY_BROKER is None or not hasattr(PTY_BROKER, "snapshot_v2"):
            return None
        return PTY_BROKER.snapshot_v2(_broker_session_id(session), public_session_id=public_session_id)

    def _terminal_surface_tty(self, raw_session: str) -> tuple[str, str, str]:
        provider, native_id = _parse_agent_session_ref(raw_session)
        if not native_id:
            return provider, "", ""
        if provider == "claude":
            session_id = _claude_native_session_id(raw_session)
            return provider, session_id, self._lookup_terminal_tty(session_id)
        if provider == "codex":
            reg = _agent_registry_get("codex", native_id) or {}
            tty = reg.get("terminal_tty") or ""
            if not tty:
                candidates = _codex_terminal_tty_candidates(reg)
                tty = candidates[0] if candidates else ""
            return provider, native_id, tty
        return provider, native_id, ""

    def _terminal_app_surface_snapshot(self, raw_session: str, *, osascript_timeout: float = 15.0) -> dict:
        provider, native_id, tty = self._terminal_surface_tty(raw_session)
        if not native_id:
            raise ValueError("session required")
        if not tty:
            raise FileNotFoundError("no terminal_tty for session")
        if not re.match(r'^/dev/ttys[0-9]{3,}$', tty):
            raise PermissionError("invalid terminal_tty")

        safe_tty = _as_escape(tty)
        # `contents of <tab>` broke on macOS 26 — the specifier resolves to
        # the ttab object itself and the text coercion fails with -1700
        # ("Can't make «class ttab» … into type text"). `history of <tab>`
        # still returns the scrollback text; the snapshot builder tails it
        # to the visible row count.
        script = f'''
        tell application "Terminal"
            repeat with w in windows
                repeat with t in tabs of w
                    if tty of t is "{safe_tty}" then
                        return "ok\t" & ((number of rows of t) as text) & "\t" & ((number of columns of t) as text) & "\t" & ((history of t) as text)
                    end if
                end repeat
            end repeat
        end tell
        return "no_window"
        '''
        result = _run_osascript(script, timeout=osascript_timeout)
        if not result.get("ok"):
            if result.get("reason") == "no matching Terminal window":
                raise FileNotFoundError("matching Terminal tab not found")
            raise RuntimeError(result.get("reason") or "terminal contents unavailable")
        stdout = str(result.get("stdout") or "")
        if not stdout.startswith("ok\t"):
            raise RuntimeError("terminal contents unavailable")
        parts = stdout.split("\t", 3)
        if len(parts) != 4:
            raise RuntimeError("malformed terminal contents response")
        try:
            rows = int(parts[1])
            columns = int(parts[2])
        except ValueError:
            rows, columns = 24, 80
        # History is the full scrollback; keep only a generous tail so a
        # megabyte buffer never rides through the snapshot pipeline.
        text = parts[3]
        if len(text) > 256 * 1024:
            text = text[-256 * 1024:]
        return _terminal_surface_snapshot_from_text(
            session_id=_qualified_session_id(provider, native_id),
            source="terminal_app_contents",
            text=text,
            columns=columns,
            rows=rows,
        )

    def _handle_terminal_surface(self, q):
        raw_session = q.get("session", [""])[0]
        try:
            payload = self._broker_surface_snapshot(raw_session) or self._terminal_app_surface_snapshot(raw_session)
        except ValueError as e:
            self.send_error(400, str(e))
            return
        except PermissionError as e:
            self.send_error(403, str(e))
            return
        except FileNotFoundError as e:
            self.send_error(404, str(e))
            return
        except Exception as e:
            self.send_error(502, str(e)[:200])
            return
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _terminal_surface_v2_snapshot(self, raw_session: str, *, osascript_timeout: float = 15.0) -> dict:
        provider, native_id = _parse_agent_session_ref(raw_session)
        if not native_id:
            raise ValueError("session required")
        if provider not in AGENT_PROVIDERS:
            raise ValueError(f"unsupported provider: {provider}")
        broker_payload = self._broker_surface_v2_snapshot(raw_session)
        if broker_payload is not None:
            return broker_payload
        try:
            v1 = self._terminal_app_surface_snapshot(raw_session, osascript_timeout=osascript_timeout)
        except (FileNotFoundError, RuntimeError) as e:
            return _terminal_surface_v2_unavailable(provider=provider, native_id=native_id, reason=str(e))
        return _terminal_surface_v2_degraded_from_v1(v1, provider=provider, native_id=native_id)

    def _terminal_surface_v2_delta(
        self,
        raw_session: str,
        *,
        since_generation: int | None,
        since_offset: int | None,
    ) -> dict:
        # The current VT adapter can expose a bounded semantic snapshot but not
        # a compact dirty-row delta yet. Keep the endpoint contract stable and
        # force a snapshot until the backend can prove delta correctness.
        return self._terminal_surface_v2_snapshot(raw_session)

    def _handle_terminal_surface_v2(self, q):
        raw_session = q.get("session", [""])[0]
        try:
            payload = self._terminal_surface_v2_snapshot(raw_session)
        except ValueError as e:
            self.send_error(400, str(e))
            return
        except PermissionError as e:
            self.send_error(403, str(e))
            return
        except FileNotFoundError as e:
            self.send_error(404, str(e))
            return
        except Exception as e:
            self.send_error(502, str(e)[:200])
            return
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_terminal_surface_stream_v2(self, q):
        raw_session = q.get("session", [""])[0]
        if not raw_session:
            self.send_error(400, "session required")
            return
        try:
            since_generation = int(q.get("since_generation", ["0"])[0])
        except ValueError:
            since_generation = None
        try:
            since_offset = int(q.get("since_offset", ["0"])[0])
        except ValueError:
            since_offset = None

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        last_hash = ""
        last_keepalive = _time.time()
        deadline = _time.time() + 600
        first = True

        while _time.time() < deadline:
            try:
                payload = self._terminal_surface_v2_delta(
                    raw_session,
                    since_generation=since_generation,
                    since_offset=since_offset,
                )
            except ValueError as e:
                _sse_write_json_event(self.wfile, "error", {
                    "schema_version": 2,
                    "event": "error",
                    "session_id": raw_session,
                    "reason": "bad_session",
                    "message": str(e)[:200],
                    "retryable": False,
                    "degraded_source_available": None,
                })
                _sse_write_json_event(self.wfile, "done", {})
                return
            except FileNotFoundError as e:
                _sse_write_json_event(self.wfile, "error", {
                    "schema_version": 2,
                    "event": "error",
                    "session_id": raw_session,
                    "reason": "terminal_surface_unavailable",
                    "message": str(e)[:200],
                    "retryable": True,
                    "degraded_source_available": None,
                })
                _sse_write_json_event(self.wfile, "done", {})
                return
            except Exception as e:
                _sse_write_json_event(self.wfile, "error", {
                    "schema_version": 2,
                    "event": "error",
                    "session_id": raw_session,
                    "reason": "terminal_surface_unavailable",
                    "message": str(e)[:200],
                    "retryable": True,
                    "degraded_source_available": "terminal_app_contents",
                })
                _time.sleep(1.0)
                continue

            current_hash = str(payload.get("screen_hash") or "")
            if first or current_hash != last_hash:
                if not _sse_write_json_event(self.wfile, "snapshot", payload, max_bytes=SSE_MAX_EVENT_BYTES):
                    return
                first = False
                last_hash = current_hash
                since_generation = int(payload.get("generation") or 0)
                since_offset = int(payload.get("raw_offset") or 0)
                last_keepalive = _time.time()
            elif _time.time() - last_keepalive >= 20:
                if not _sse_write_json_event(self.wfile, "keepalive", {}, max_bytes=SSE_MAX_EVENT_BYTES):
                    return
                last_keepalive = _time.time()
            _time.sleep(0.5)
        _sse_write_json_event(self.wfile, "done", {}, max_bytes=SSE_MAX_EVENT_BYTES)

    def _handle_terminal_surface_stream(self, q):
        raw_session = q.get("session", [""])[0]
        if not raw_session:
            self.send_error(400, "session required")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        last_hash = ""
        last_keepalive = _time.time()
        deadline = _time.time() + 600

        def emit(event: str, payload: dict) -> bool:
            return _sse_write_json_event(self.wfile, event, payload, max_bytes=SSE_MAX_EVENT_BYTES)

        while _time.time() < deadline:
            try:
                snap = self._broker_surface_snapshot(raw_session) or self._terminal_app_surface_snapshot(raw_session)
            except ValueError as e:
                emit("error", {"message": str(e)[:200], "reason": "bad_session"})
                emit("done", {})
                return
            except PermissionError as e:
                emit("error", {"message": str(e)[:200], "reason": "invalid_tty"})
                emit("done", {})
                return
            except FileNotFoundError as e:
                emit("error", {"message": str(e)[:200], "reason": "terminal_tab_not_found"})
                emit("done", {})
                return
            except Exception as e:
                if not emit("error", {"message": str(e)[:200]}):
                    return
                _time.sleep(1.0)
                continue

            if snap.get("screen_hash") != last_hash:
                if not emit("snapshot", snap):
                    return
                last_hash = str(snap.get("screen_hash") or "")
                last_keepalive = _time.time()
            elif _time.time() - last_keepalive >= 20:
                if not emit("keepalive", {}):
                    return
                last_keepalive = _time.time()
            _time.sleep(0.5)
        emit("done", {})

    def _terminal_control_target(self, raw_session: str) -> dict:
        if ":" not in raw_session:
            raise ValueError("provider-qualified session_id required")
        provider, native_id = _parse_agent_session_ref(raw_session)
        if not native_id:
            raise ValueError("provider-qualified session_id required")
        if not _valid_provider_filter(provider, allow_all=False):
            raise ValueError(f"unknown provider: {provider}")
        if provider not in AGENT_PROVIDERS:
            raise ValueError(f"unsupported provider: {provider}")
        broker_found = self._broker_session_for(raw_session)
        if broker_found:
            public_session_id, session = broker_found
            return {
                "source": "broker_vt",
                "provider": provider,
                "native_id": native_id,
                "session_id": public_session_id,
                "broker_id": _broker_session_id(session),
                "tty": _broker_slave_tty(session),
                "tty_candidates": [_broker_slave_tty(session)] if _broker_slave_tty(session) else [],
                "pid": _broker_pid(session),
            }

        if provider == "claude":
            session_id = _claude_native_session_id(raw_session)
            if not session_id:
                raise ValueError("session required")
            tty = self._lookup_terminal_tty(session_id)
            if not tty:
                raise FileNotFoundError("no terminal_tty for session")
            if not re.match(r'^/dev/ttys[0-9]{3,}$', tty):
                raise PermissionError("invalid terminal_tty")
            return {
                "provider": "claude",
                "source": "terminal_app_contents",
                "native_id": session_id,
                "session_id": _qualified_session_id("claude", session_id),
                "tty": tty,
                "tty_candidates": [tty],
                "pid": self._lookup_claude_pid(session_id) or 0,
            }

        reg = _agent_registry_get("codex", native_id)
        if not reg or reg.get("closed_at"):
            raise FileNotFoundError("no Codex control registry row for session")
        tty = reg.get("terminal_tty") or ""
        pid = int(reg.get("pid") or 0)
        if (not pid or not _process_alive(pid)) and tty:
            fresh_pid = _pid_for_tty_command(tty, "codex")
            if fresh_pid:
                pid = fresh_pid
                _agent_registry_update_control("codex", native_id, pid=pid, terminal_tty=tty, reopen=True)
        tty_candidates = _codex_terminal_tty_candidates({**reg, "pid": pid, "terminal_tty": tty})
        if not tty and tty_candidates:
            tty = tty_candidates[0]
            _agent_registry_update_control("codex", native_id, pid=pid, terminal_tty=tty, reopen=True)
        tty_candidates = tty_candidates or ([tty] if tty else [])
        if not tty:
            raise FileNotFoundError("no terminal_tty for Codex session")
        if not re.match(r'^/dev/ttys[0-9]{3,}$', tty):
            raise PermissionError("invalid terminal_tty")
        return {
            "provider": "codex",
            "source": "terminal_app_contents",
            "native_id": native_id,
            "session_id": _qualified_session_id("codex", native_id),
            "tty": tty,
            "tty_candidates": tty_candidates,
            "pid": pid,
        }

    def _terminal_control_signal(self, target: dict, sig: int, sig_name: str) -> dict:
        provider = target["provider"]
        native_id = target["native_id"]
        pid = int(target.get("pid") or 0)
        if provider == "codex" and (not pid or not _process_alive(pid)):
            pid = _pid_for_tty_command(str(target.get("tty") or ""), "codex")
        elif provider == "claude" and (not pid or not _process_alive(pid)):
            pid = self._lookup_claude_pid(native_id) or 0
        if not pid:
            return {"ok": False, "error": f"no {provider} pid for session", "status": 404}
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError, OSError) as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}", "pid": pid, "status": 502}
        if provider == "codex":
            _write_agent_turn_state("codex", native_id, "idle", event=sig_name.lower())
        return {"ok": True, "pid": pid, "signal": sig_name}

    def _terminal_control_run_in_terminal(self, target: dict, action: dict) -> dict:
        tty_candidates = target.get("tty_candidates") or [target.get("tty")]
        safe_ttys = "{" + ", ".join(f'"{_as_escape(candidate)}"' for candidate in tty_candidates if candidate) + "}"
        if action["type"] == "choice":
            safe_text = _as_escape(str(action["choice_id"]))
            payload_expr = f'"{safe_text}"'
        elif action["type"] == "text":
            safe_text = _as_escape(str(action["text"]))
            payload_expr = f'"{safe_text}"'
        elif action["type"] in {"key", "raw_key"}:
            if action["type"] == "key":
                key_code = TERMINAL_CONTROL_KEY_CODES.get(action["key"])
                if key_code is None:
                    return {"ok": False, "reason": "key requires signal path", "status": 400}
            else:
                key_code = int(action["key_code"])
            script = f'''
            tell application "Terminal"
                set targetTab to missing value
                set targetWindow to missing value
                set usedTTY to ""
                set candidateTTYs to {safe_ttys}
                repeat with w in windows
                    repeat with t in tabs of w
                        set tabTTY to tty of t
                        repeat with candidateTTY in candidateTTYs
                            if tabTTY is (candidateTTY as text) then
                                set targetTab to t
                                set targetWindow to w
                                set usedTTY to (candidateTTY as text)
                                exit repeat
                            end if
                        end repeat
                        if targetTab is not missing value then exit repeat
                    end repeat
                    if targetTab is not missing value then exit repeat
                end repeat
                if targetTab is missing value then
                    return "no_window"
                end if
                set selected tab of targetWindow to targetTab
                set index of targetWindow to 1
                activate
                delay 0.05
            end tell
            tell application "System Events"
                key code {key_code}
            end tell
            return "ok" & tab & usedTTY
            '''
            return _run_osascript(script)
        else:
            return {"ok": False, "reason": "unsupported action", "status": 400}

        script = f'''
        tell application "Terminal"
            set targetTab to missing value
            set usedTTY to ""
            set candidateTTYs to {safe_ttys}
            repeat with w in windows
                repeat with t in tabs of w
                    set tabTTY to tty of t
                    repeat with candidateTTY in candidateTTYs
                        if tabTTY is (candidateTTY as text) then
                            set targetTab to t
                            set usedTTY to (candidateTTY as text)
                            exit repeat
                        end if
                    end repeat
                    if targetTab is not missing value then exit repeat
                end repeat
                if targetTab is not missing value then exit repeat
            end repeat
            if targetTab is missing value then
                return "no_window"
            end if
            do script {payload_expr} in targetTab
        end tell
        return "ok" & tab & usedTTY
        '''
        return _run_osascript(script)

    def _handle_terminal_control(self, q):
        audit = {
            "ts": _time.time(),
            "path": "/terminal-control",
            "device_id": getattr(getattr(self, "pairling_auth", None), "device_id", None),
            "ok": False,
        }
        try:
            payload = self._read_json_object()
        except Exception as e:
            audit["error"] = "bad_json"
            _append_terminal_control_audit(audit)
            self._send_json(_terminal_control_error("bad_json", str(e), 400), status=400)
            return

        body_session = str(payload.get("session_id") or "").strip()
        query_session = str((q.get("session", [""]) or [""])[0] or "").strip()
        if body_session:
            audit["body_session_id"] = body_session
        if query_session:
            audit["query_session_id"] = query_session
        raw_session, session_err = _terminal_control_session_id(payload, q)
        audit["session_id"] = raw_session or body_session or query_session
        if session_err:
            audit["error"] = session_err["error"]["code"]
            _append_terminal_control_audit(audit)
            self._send_json(session_err, status=int(session_err["status"]))
            return
        if ":" not in raw_session:
            audit["error"] = "provider_required"
            _append_terminal_control_audit(audit)
            self._send_json(
                _terminal_control_error("provider_required", "session_id must be provider-qualified", 400),
                status=400,
            )
            return

        provider, native_id = _parse_agent_session_ref(raw_session)
        audit["provider"] = provider
        audit["native_id"] = native_id
        if not native_id or not _valid_provider_filter(provider, allow_all=False):
            audit["error"] = "bad_session"
            _append_terminal_control_audit(audit)
            self._send_json(
                _terminal_control_error("bad_session", "session_id must be provider-qualified", 400),
                status=400,
            )
            return
        if provider not in AGENT_PROVIDERS:
            audit["error"] = "unsupported_provider"
            _append_terminal_control_audit(audit)
            _send_unsupported_provider(self, provider, "terminal_control")
            return

        allowed, retry = _inject_rate_check(f"terminal-control:{_qualified_session_id(provider, native_id)}", max_per_min=60)
        if not allowed:
            audit["error"] = "rate_limited"
            _append_terminal_control_audit(audit)
            self._send_json({
                "ok": False,
                "error": {"code": "rate_limited", "message": "too many terminal control requests"},
                "retry_after": retry,
            }, status=429)
            return

        action, err = _terminal_control_normalize_action(payload)
        if err:
            audit["error"] = err["error"]["code"]
            _append_terminal_control_audit(audit)
            self._send_json(err, status=int(err["status"]))
            return
        audit["action"] = _terminal_control_audit_action(action)
        surface_schema_version, version_err = _terminal_control_surface_schema_version(payload)
        audit["surface_schema_version"] = surface_schema_version
        if version_err:
            audit["error"] = version_err["error"]["code"]
            _append_terminal_control_audit(audit)
            self._send_json(version_err, status=int(version_err["status"]))
            return
        client_action_id = str(payload.get("client_action_id") or self.headers.get("X-Pairling-Action-Id") or "").strip()
        device_id = audit.get("device_id")
        body_hash = _receipt_body_hash({"session_id": raw_session, "action": action, "surface_schema_version": surface_schema_version})
        deduped_receipt, conflict = _receipt_duplicate_response(device_id, raw_session, client_action_id, body_hash)
        if conflict:
            _store_action_receipt(
                device_id,
                raw_session,
                client_action_id,
                body_hash,
                conflict["receipt"],
                action_kind="terminal_control",
                audit_action=audit.get("action"),
                persist=False,
            )
            self._send_json(conflict, status=int(conflict["status"]))
            return
        if deduped_receipt:
            self._send_json({
                "ok": deduped_receipt.get("state") == "applied",
                "session_id": raw_session,
                "action": action,
                "receipt": deduped_receipt,
            })
            return

        try:
            target = self._terminal_control_target(raw_session)
            audit["tty"] = target.get("tty")
            audit["terminal_source"] = target.get("source")
            audit["broker_id"] = target.get("broker_id")
            if surface_schema_version == 2:
                snapshot = self._terminal_surface_v2_snapshot(raw_session)
            else:
                snapshot = self._broker_surface_snapshot(raw_session) or self._terminal_app_surface_snapshot(raw_session)
            audit["surface_source"] = snapshot.get("source")
            audit["surface_backend"] = snapshot.get("backend")
            audit["screen_hash"] = snapshot.get("screen_hash")
            audit["nonce"] = snapshot.get("nonce")
            audit["generation"] = snapshot.get("generation")
        except ValueError as e:
            audit["error"] = "bad_session"
            _append_terminal_control_audit(audit)
            self._send_json(_terminal_control_error("bad_session", str(e), 400), status=400)
            return
        except PermissionError as e:
            audit["error"] = "invalid_tty"
            _append_terminal_control_audit(audit)
            self._send_json(_terminal_control_error("invalid_tty", str(e), 403), status=403)
            return
        except FileNotFoundError as e:
            audit["error"] = "terminal_not_found"
            _append_terminal_control_audit(audit)
            self._send_json(_terminal_control_error("terminal_not_found", str(e), 404), status=404)
            return
        except Exception as e:
            audit["error"] = "surface_unavailable"
            _append_terminal_control_audit(audit)
            self._send_json(_terminal_control_error("surface_unavailable", str(e)[:200], 502), status=502)
            return

        stale = _terminal_control_v2_availability_error(snapshot) if surface_schema_version == 2 else None
        if stale is None:
            stale = _terminal_control_validate_screen(payload, snapshot, action)
        if stale:
            audit["error"] = stale["error"]["code"]
            _append_terminal_control_audit(audit)
            receipt = _make_action_receipt(
                client_action_id=client_action_id or None,
                state="rejected",
                phases=_receipt_phases(validated=False, applied=False, pty_written=False),
                backend=target.get("source"),
                tty=target.get("tty"),
                pid=target.get("pid"),
            )
            stale["session_id"] = target["session_id"]
            stale["receipt"] = receipt
            _store_action_receipt(device_id, target["session_id"], client_action_id or None, body_hash, receipt, action_kind="terminal_control", audit_action=audit.get("action"))
            self._send_json(stale, status=int(stale["status"]))
            return

        global LAST_HUMAN_ACTIVITY_AT
        LAST_HUMAN_ACTIVITY_AT = _time.time()
        _append_terminal_control_audit({**audit, "phase": "validated"})

        if target.get("source") == "broker_vt":
            result = PTY_BROKER.control(target["broker_id"], action) if PTY_BROKER else {"ok": False, "reason": "broker unavailable", "status": 503}
        elif action["type"] == "key" and action["key"] == "ctrl_c":
            result = self._terminal_control_signal(target, signal.SIGINT, "SIGINT")
        else:
            result = self._terminal_control_run_in_terminal(target, action)

        ok = bool(result.get("ok"))
        audit["ok"] = ok
        audit["phase"] = "applied"
        if not ok:
            audit["error"] = result.get("error") or result.get("reason") or "terminal_control_failed"
        _append_terminal_control_audit(audit)
        status = 200 if ok else int(result.get("status") or 502)
        used_tty = result.get("stdout", "").split("\t", 1)[1] if str(result.get("stdout") or "").startswith("ok\t") else target.get("tty")
        source_offset_after = None
        source_offset_reason = None
        if ok and target.get("source") == "broker_vt" and PTY_BROKER:
            tail = PTY_BROKER.raw_tail(target.get("broker_id"), since=0)
            if tail:
                source_offset_after = tail[1]
            else:
                source_offset_reason = "no_broker_log"
        receipt = _make_action_receipt(
            client_action_id=client_action_id or None,
            state="applied" if ok else "failed",
            phases=_receipt_phases(
                validated=True,
                applied=ok,
                pty_written=bool(ok and not (action.get("type") == "key" and action.get("key") == "ctrl_c")),
            ),
            backend=target.get("source"),
            tty=used_tty,
            pid=result.get("pid") or target.get("pid"),
            source_offset_after=source_offset_after,
            source_offset_reason=source_offset_reason,
        )
        _store_action_receipt(device_id, target["session_id"], client_action_id or None, body_hash, receipt, action_kind="terminal_control", audit_action=audit.get("action"))
        self._send_json({
            "ok": ok,
            "session_id": target["session_id"],
            "action": action,
            "screen_hash": snapshot.get("screen_hash"),
            "nonce": snapshot.get("nonce"),
            "tty": used_tty,
            "pid": result.get("pid"),
            "reason": result.get("reason") or result.get("error"),
            "receipt": receipt,
        }, status=status)

    def _resolve_transcript(self, session_id: str):
        """Map an iOS app session_id (which may be a Claude Code UUID OR a
        continuous-claude PG session id like 's-moj0ydy9') to the on-disk JSONL.

        Strategy:
          1. Direct filename match: `<session_id>.jsonl` anywhere under projects/
          2. **PG claude_uuid lookup**: for continuous-claude `s-…` ids, fetch
             claude_uuid + project from PG and exact-match `<claude_uuid>.jsonl`
             in the encoded project dir. This is essential when N sessions
             share a project (e.g. 4 terminals all in /Users/example) — without
             it, all N collide on the most-recent-JSONL fallback.
          3. Last-ditch: PG project lookup → most recent JSONL in dir. Only
             fires when claude_uuid is unknown (pre-migration zombie sessions).
        """
        native_id = _claude_native_session_id(session_id)
        if not native_id:
            return None
        session_id = native_id
        projects_root = HOME / ".claude" / "projects"

        if _safe_session_id(session_id) and session_id.startswith("s-"):
            claude_uuid = self._lookup_pg_field(session_id, "claude_uuid")
            project = self._lookup_pg_project(session_id)
            if claude_uuid and project:
                candidate = projects_root / _encode_project_dir(project) / f"{claude_uuid}.jsonl"
                if candidate.exists():
                    return candidate

        # Strategy 1: direct filename match.
        for project_dir in projects_root.iterdir():
            if not project_dir.is_dir():
                continue
            candidate = project_dir / f"{session_id}.jsonl"
            if candidate.exists():
                return candidate

        if not _safe_session_id(session_id):
            return None

        # Strategy 2: PG claude_uuid → exact JSONL match. Per-session unique.
        claude_uuid = self._lookup_pg_field(session_id, "claude_uuid")
        project = self._lookup_pg_project(session_id)
        if claude_uuid and project:
            encoded = _encode_project_dir(project)
            candidate = projects_root / encoded / f"{claude_uuid}.jsonl"
            if candidate.exists():
                return candidate

        # Strategy 3: most-recent in project dir. Last-ditch for sessions
        # whose claude_uuid was never captured (pre-migration). Will collide
        # for multi-session projects, but the caller should already be
        # filtering those out via /sessions?live=true requiring claude_uuid.
        if not project:
            return None
        encoded = _encode_project_dir(project)
        target_dir = projects_root / encoded
        if not target_dir.is_dir():
            return None
        jsonls = sorted(target_dir.glob("*.jsonl"),
                        key=lambda p: p.stat().st_mtime, reverse=True)
        return jsonls[0] if jsonls else None

    def _lookup_pg_project(self, session_id: str):
        """Query the continuous-claude PG for a session's project."""
        return self._lookup_pg_field(session_id, "project")

    def _lookup_pg_field(self, session_id: str, field: str):
        """Generic single-column read from the active claude session backend
        (name kept for grep-ability with the PG era; serves sqlite too)."""
        session_id = _claude_native_session_id(session_id)
        if not session_id or not field.replace("_", "").isalnum():
            return None
        return _claude_sessions_backend().lookup_field(session_id, field)

    # ----- /inject-now: AppleScript types text into matching Terminal window -----
    def _handle_inject_now(self, q):
        session_id = q.get("session", [""])[0]
        session_id = _claude_native_session_id(session_id)
        if not session_id:
            self.send_error(400, "session required")
            return
        text = self._read_body().decode("utf-8", errors="replace").strip()
        if not text:
            self.send_error(400, "empty body")
            return

        # Phase 4 A.3: rate limit. Reject 429 if the session is being spammed.
        allowed, retry = _inject_rate_check(_qualified_session_id("claude", session_id))
        if not allowed:
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", str(retry))
            body = json.dumps({"ok": False, "error": "rate_limited", "retry_after": retry}).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        text, sanitize_err = _sanitize_terminal_text_input(
            text,
            allow_newline=True,
            max_chars=4000,
        )
        if sanitize_err:
            self.send_error(int(sanitize_err["status"]), str(sanitize_err["message"]))
            return

        project = self._lookup_pg_project(session_id)
        if not project:
            transcript = self._resolve_transcript(session_id)
            if transcript:
                project = _peek_cwd_from_transcript(transcript)
        if not project:
            self.send_error(404, f"could not resolve project for session {session_id}")
            return

        project_basename = os.path.basename(project.rstrip("/")) or project
        result = self._applescript_inject(project_basename, text)

        if not result.get("ok"):
            # Fall back to the queue-file path so nothing is lost
            queue_file = QUEUE_DIR / f"{session_id}.txt"
            with open(queue_file, "a") as f:
                f.write(text + "\n")
            body = json.dumps({
                "ok": True, "injected": False, "queued": True,
                "fallback_reason": result.get("reason", "unknown"),
                "window_match": project_basename,
            }).encode()
        else:
            body = json.dumps({
                "ok": True, "injected": True,
                "window_match": project_basename,
            }).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /interrupt: AppleScript sends Esc keystroke to matching Terminal -----
    def _handle_interrupt(self, q):
        session_id = q.get("session", [""])[0]
        session_id = _claude_native_session_id(session_id)
        if not session_id:
            self.send_error(400, "session required")
            return
        project = self._lookup_pg_project(session_id) or ""
        if not project:
            transcript = self._resolve_transcript(session_id)
            if transcript:
                project = _peek_cwd_from_transcript(transcript) or ""
        if not project:
            self.send_error(404, f"could not resolve project for session {session_id}")
            return

        project_basename = os.path.basename(project.rstrip("/")) or project
        result = self._applescript_send_esc(project_basename)

        body = json.dumps({
            "ok": result.get("ok", False),
            "interrupted": result.get("ok", False),
            "window_match": project_basename,
            "reason": result.get("reason"),
        }).encode()
        self.send_response(200 if result.get("ok") else 502)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /session-meta: effort, model, type, sentinel mode, working_on, size -----
    def _handle_session_meta(self, q):
        session_id = q.get("session", [""])[0]
        session_id = _claude_native_session_id(session_id)
        if not session_id:
            self.send_error(400, "session required")
            return

        meta = {
            "sessionId": _qualified_session_id("claude", session_id),
            "provider": "claude",
            "nativeId": session_id,
            "project": self._lookup_pg_project(session_id),
            "workingOn": self._lookup_pg_field(session_id, "working_on"),
            "transcriptFile": None,
            "transcriptSize": 0,
            "lineCount": 0,
            "kind": "main",
            "sentinelMode": None,
            "effort": None,
            "model": None,
        }

        path = self._resolve_transcript(session_id)
        if path and path.exists():
            meta["transcriptFile"] = path.name
            meta["transcriptSize"] = path.stat().st_size
            with open(path, "rb") as f:
                meta["lineCount"] = sum(1 for _ in f)

            head = ""
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    head = "".join(line for _, line in zip(range(120), f))
            except Exception:
                head = ""

            sm = re.search(r"\.claude/sentinel/modes/([A-Za-z0-9_-]+)/", head)
            if not sm:
                sm = re.search(r"forge-id:[A-Za-z0-9-]+[\s\S]{0,80}?mode:([A-Za-z0-9_-]+)", head)
            if sm:
                mode = sm.group(1).replace("_", "-")
                meta["sentinelMode"] = mode
                meta["kind"] = f"sentinel:{mode}"

            em = re.findall(
                r"<command-name>/effort</command-name>[\s\S]{0,200}?<command-args>(\w+)</command-args>",
                head,
            )
            if em:
                meta["effort"] = em[-1]

            mm = re.search(r"(claude-(?:opus|sonnet|haiku)-[\d.\-a-z]+)", head)
            if mm:
                meta["model"] = mm.group(1)

            if not meta["project"]:
                meta["project"] = _peek_cwd_from_transcript(path)

            # Last assistant text: streaming-tail the file to find the most recent
            # role==assistant message with a text content block. Verbatim — no
            # truncation up to the cap (any single Sonnet response well under).
            meta["lastAssistantText"] = _peek_last_assistant_text(path, max_chars=200_000)
            meta["firstPrompt"] = _peek_first_prompt(path)

        body = json.dumps(meta).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /personal-context: serve ~/.claude/personal-context.md -----
    def _handle_personal_context(self, q):
        path = HOME / ".claude" / "personal-context.md"
        if not path.exists():
            body = b'{"present": false, "content": ""}'
        else:
            try:
                content = path.read_text(encoding="utf-8")
            except Exception:
                content = ""
            body = json.dumps({
                "present": True,
                "content": content,
                "mtime": path.stat().st_mtime,
                "size": path.stat().st_size,
            }).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _llm_route_model_family(model: str) -> str | None:
        if llm_route_model_family is not None:
            return llm_route_model_family(model)
        return None

    @staticmethod
    def _find_executable(candidates: list[Path | str]) -> Path | None:
        for candidate in candidates:
            path = Path(candidate)
            if path.exists() and os.access(path, os.X_OK):
                return path
        return None

    # ----- /llm-route: subscription-routed Claude/Codex one-shot -----
    def _handle_llm_route(self, q):
        """Forward a prompt through the user's local Claude or Codex CLI.

        Body: JSON {prompt, system?, max_chars?}
        Query: ?model=sonnet|haiku|opus|gpt-5.5|gpt-5.4|gpt-5.4-mini|gpt-5.3-codex
        """
        model = q.get("model", ["sonnet"])[0]
        family = self._llm_route_model_family(model)
        if family is None:
            self.send_error(400, "model must be sonnet|haiku|opus|gpt-5.5|gpt-5.4|gpt-5.4-mini|gpt-5.3-codex")
            return

        try:
            payload = json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "body must be JSON")
            return

        prompt = (payload.get("prompt") or "").strip()
        system = (payload.get("system") or "").strip()
        max_chars = int(payload.get("max_chars") or 8000)
        if not prompt:
            self.send_error(400, "prompt required")
            return
        if len(prompt) > max_chars:
            prompt = prompt[:max_chars]

        if run_local_llm is None:
            self.send_error(503, "local LLM route helper unavailable")
            return

        try:
            content = run_local_llm(model=model, prompt=prompt, system=system, timeout_seconds=120)
        except Exception as exc:
            status = int(getattr(exc, "status", 502) or 502)
            message = str(getattr(exc, "message", str(exc)) or str(exc))
            self.send_error(status, message)
            return

        body = json.dumps({
            "ok": True,
            "model": model,
            "content": content,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /activity + /workers: operator surfaces for the phone -----
    _WORKER_PATTERNS = (
        "biotech-labs/synth-synth-",
        "biotech-labs/crohns-research/scripts",
        "biotech-research-",
    )

    def _send_json(self, payload: dict, status: int = 200):
        body = json.dumps(payload).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError) as exc:
            raise ClientDisconnected() from exc

    def _collect_session_rows(self, since_min: int = 360, live_only: bool = False, limit: int = 100, include_first_prompt: bool = True) -> list[dict]:
        since_min = max(1, min(int(since_min), 60 * 24 * 14))
        limit = max(1, min(int(limit), 500))
        cache_key = ("collect-session-rows", since_min, bool(live_only), limit, bool(include_first_prompt))
        now = _time.time()
        with _runtime_snapshot_cache_lock:
            cached = _runtime_snapshot_cache.get(cache_key)
            if cached is not None and now - cached[0] < RUNTIME_SNAPSHOT_CACHE_SECONDS:
                return _copy_cache_value(cached[1])
        backend_rows = _claude_sessions_backend().collect_rows(since_min, live_only, limit)

        rows: list[dict] = []
        for raw in backend_rows:
            session_id, project = raw["id"], raw["project"]
            if _is_excluded_project(project):
                continue
            claude_uuid = raw.get("claude_uuid") or ""
            row = dict(raw)
            row["first_prompt"] = None
            row.update(self._turn_state_summary(claude_uuid))
            _refresh_claude_observed_activity(row, project, claude_uuid)
            if include_first_prompt:
                target_dir = HOME / ".claude" / "projects" / _encode_project_dir(project)
                if target_dir.is_dir():
                    try:
                        jsonls = sorted(target_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
                        if jsonls:
                            row["first_prompt"] = _peek_first_prompt(jsonls[0])
                    except OSError:
                        pass
            if project and claude_uuid:
                transcript = HOME / ".claude" / "projects" / _encode_project_dir(project) / f"{claude_uuid}.jsonl"
                row["turn_count"] = _session_transcript_stats(transcript, "claude", session_id).get("turn_count")
            rows.append(row)
        with _runtime_snapshot_cache_lock:
            _runtime_snapshot_cache[cache_key] = (_time.time(), _copy_cache_value(rows))
        return rows

    def _recent_session_signal(self, session_id: str, project: str | None = None, claude_uuid: str | None = None) -> dict:
        """Cheap parse of the tail of a transcript for Activity/Workers rows."""
        signal = {
            "anomaly": None,
            "latest_tool": None,
            "latest_command": None,
            "latest_edit": None,
            "latest_event_ts": None,
        }
        path = None
        if project and claude_uuid:
            candidate = HOME / ".claude" / "projects" / _encode_project_dir(project) / f"{claude_uuid}.jsonl"
            if candidate.exists():
                path = candidate
        if path is None:
            path = self._resolve_transcript(session_id)
        if not path or not path.exists():
            return signal
        try:
            lines = _tail_lines(path, max_lines=240, max_bytes=TRANSCRIPT_TAIL_SCAN_BYTES)
        except OSError:
            return signal
        for raw in reversed(lines):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except (ValueError, json.JSONDecodeError):
                continue
            ts = obj.get("timestamp")
            if signal["latest_event_ts"] is None and isinstance(ts, str):
                signal["latest_event_ts"] = ts
            msg = obj.get("message") or {}
            content = msg.get("content")
            if isinstance(content, list):
                for block in reversed(content):
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") != "tool_use":
                        continue
                    name = block.get("name")
                    inp = block.get("input") if isinstance(block.get("input"), dict) else {}
                    if signal["latest_tool"] is None and isinstance(name, str):
                        signal["latest_tool"] = name
                    if signal["latest_command"] is None and name == "Bash":
                        cmd = inp.get("command")
                        if isinstance(cmd, str) and cmd:
                            signal["latest_command"] = cmd[:240]
                    if signal["latest_edit"] is None and name in ("Edit", "MultiEdit", "Write"):
                        fp = inp.get("file_path") or inp.get("path")
                        if isinstance(fp, str) and fp:
                            signal["latest_edit"] = fp
            if signal["anomaly"] is None:
                line_type = obj.get("type")
                subtype = obj.get("subtype")
                if line_type in ("error", "system") and subtype not in {"stop_hook_summary", "turn_duration", "compact_boundary"}:
                    signal["anomaly"] = {
                        "kind": line_type,
                        "title": f"{line_type}: {subtype or 'event'}",
                        "detail": (obj.get("content") or obj.get("text") or "")[:240],
                    }
                sr = msg.get("stop_reason")
                if isinstance(sr, str) and sr not in ("end_turn", "tool_use"):
                    signal["anomaly"] = {
                        "kind": "stop_reason",
                        "title": f"Stopped: {sr}",
                        "detail": json.dumps(msg.get("stop_details") or {})[:240],
                    }
            if signal["anomaly"] and signal["latest_tool"] and (signal["latest_command"] or signal["latest_edit"]):
                break
        return signal

    def _is_worker_project(self, project: str) -> bool:
        return any(p in project for p in self._WORKER_PATTERNS)

    def _worker_row_from_session(self, row: dict, now_epoch: int | None = None) -> dict:
        now_epoch = now_epoch or int(_time.time())
        native_id = row["id"]
        heartbeat = int(row.get("last_heartbeat") or 0)
        started = int(row.get("started_at") or 0)
        stale_seconds = max(0, now_epoch - heartbeat) if heartbeat else 0
        runtime_seconds = max(0, now_epoch - started) if started else 0
        active = stale_seconds < 300
        stale = stale_seconds >= 3600
        signal = self._recent_session_signal(
            row["id"],
            project=row.get("project"),
            claude_uuid=row.get("claude_uuid"),
        )
        context_pct = float(row.get("context_pct") or 0.0)
        risk = 0
        reasons: list[str] = []
        if active:
            risk += 1
        if stale:
            risk += 4; reasons.append("idle >60m")
        if context_pct >= 85:
            risk += 3; reasons.append("high context")
        elif context_pct >= 70:
            risk += 2; reasons.append("context pressure")
        state = row.get("state")
        if state in ("thinking", "tool"):
            turn_started = row.get("turn_started_at")
            if isinstance(turn_started, (int, float)) and now_epoch - turn_started > 900:
                risk += 2; reasons.append("long turn")
        if signal.get("anomaly"):
            risk += 3; reasons.append("recent anomaly")
        return {
            "id": _qualified_session_id("claude", native_id),
            "provider": "claude",
            "native_id": native_id,
            "project": row.get("project") or "",
            "working_on": row.get("working_on"),
            "first_prompt": row.get("first_prompt"),
            "started_at": started,
            "last_heartbeat": heartbeat,
            "stale_seconds": stale_seconds,
            "runtime_seconds": runtime_seconds,
            "active": active,
            "stale": stale,
            "stale_reason": "idle >60 minutes" if stale else None,
            "risk_score": risk,
            "risk_reasons": reasons,
            "state": state,
            "tool": row.get("tool"),
            "model": row.get("model"),
            "effort": row.get("effort"),
            "context_pct": context_pct,
            "turn_started_at": row.get("turn_started_at"),
            "latest_tool": signal.get("latest_tool"),
            "latest_command": signal.get("latest_command"),
            "latest_edit": signal.get("latest_edit"),
            "recent_anomaly": signal.get("anomaly"),
        }

    def _registry_metadata(self, row: dict) -> dict:
        try:
            obj = json.loads(row.get("metadata_json") or "{}")
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}

    def _codex_worker_signal(self, metadata: dict) -> dict:
        signal = {
            "latest_tool": None,
            "latest_command": None,
            "latest_edit": None,
            "anomaly": None,
        }
        output_path = metadata.get("output_path")
        if isinstance(output_path, str):
            p = Path(output_path)
            if p.is_file():
                try:
                    lines = _tail_lines(p, max_lines=240, max_bytes=TRANSCRIPT_TAIL_SCAN_BYTES)
                except OSError:
                    lines = []
                for raw in reversed(lines):
                    for row in _normalize_codex_line(raw, metadata.get("native_id") or ""):
                        msg = row.get("message") or {}
                        for block in reversed(msg.get("content") or []):
                            if not isinstance(block, dict):
                                continue
                            if block.get("type") == "tool_use" and signal["latest_tool"] is None:
                                name = block.get("name")
                                inp = block.get("input") if isinstance(block.get("input"), dict) else {}
                                if isinstance(name, str):
                                    signal["latest_tool"] = name
                                command = inp.get("command") or inp.get("cmd")
                                if isinstance(command, str) and not signal["latest_command"]:
                                    signal["latest_command"] = command[:240]
                                fp = inp.get("file_path") or inp.get("path")
                                if isinstance(fp, str) and not signal["latest_edit"]:
                                    signal["latest_edit"] = fp
                    if signal["latest_tool"] and (signal["latest_command"] or signal["latest_edit"] or signal["anomaly"]):
                        break
        exit_code = metadata.get("exit_code")
        if signal["anomaly"] is None and isinstance(exit_code, int) and exit_code != 0:
            detail = ""
            stderr_path = metadata.get("stderr_path")
            if isinstance(stderr_path, str):
                try:
                    detail = Path(stderr_path).read_text(errors="replace")[-500:].strip()
                except OSError:
                    detail = ""
            signal["anomaly"] = {
                "kind": "exit_code",
                "title": f"Codex worker exited {exit_code}",
                "detail": detail[:240],
            }
        return signal

    def _codex_worker_row_from_registry(self, row: dict, now_epoch: int | None = None) -> dict | None:
        metadata = self._registry_metadata(row)
        if metadata.get("kind") not in {"worker", "orchestration_worker"}:
            return None
        now_epoch = now_epoch or int(_time.time())
        native_id = row.get("native_id") or metadata.get("native_id") or ""
        if not native_id:
            return None
        metadata.setdefault("native_id", native_id)
        heartbeat = int(row.get("last_heartbeat") or row.get("started_at") or 0)
        started = int(row.get("started_at") or heartbeat or now_epoch)
        pid = int(row.get("pid") or 0)
        closed_at = row.get("closed_at")
        process_alive = bool(pid and _process_alive(pid))
        if pid and not process_alive and not closed_at:
            _agent_registry_mark_closed("codex", native_id)
            closed_at = int(_time.time())
        stale_seconds = max(0, now_epoch - heartbeat) if heartbeat else 0
        runtime_seconds = max(0, now_epoch - started) if started else 0
        active = bool(process_alive and not closed_at)
        stale = bool(active and stale_seconds >= 3600)
        signal = self._codex_worker_signal(metadata)
        risk = 0
        reasons: list[str] = []
        if active:
            risk += 1
        if stale:
            risk += 4; reasons.append("idle >60m")
        if metadata.get("orchestration_id") and "orchestration" not in reasons:
            reasons.append("orchestration")
        if signal.get("anomaly"):
            risk += 3; reasons.append("recent anomaly")
        state = metadata.get("state") or row.get("state")
        if active:
            state = state or "running"
        elif metadata.get("exit_code") == 0:
            state = "idle"
        else:
            state = state or "terminated"
        return {
            "id": _qualified_session_id("codex", native_id),
            "provider": "codex",
            "native_id": native_id,
            "project": row.get("project") or metadata.get("project") or "",
            "working_on": metadata.get("title") or metadata.get("role") or metadata.get("prompt_preview"),
            "first_prompt": metadata.get("prompt_preview"),
            "started_at": started,
            "last_heartbeat": heartbeat,
            "stale_seconds": stale_seconds,
            "runtime_seconds": runtime_seconds,
            "active": active,
            "stale": stale,
            "stale_reason": "idle >60 minutes" if stale else None,
            "risk_score": risk,
            "risk_reasons": reasons,
            "state": state,
            "tool": metadata.get("tool"),
            "model": metadata.get("model"),
            "effort": metadata.get("effort"),
            "context_pct": None,
            "turn_started_at": None,
            "latest_tool": signal.get("latest_tool"),
            "latest_command": signal.get("latest_command"),
            "latest_edit": signal.get("latest_edit"),
            "recent_anomaly": signal.get("anomaly"),
        }

    def _orchestration_session_id_set(self) -> set[str]:
        ids: set[str] = set()
        for path in ORCHESTRATIONS_DIR.glob("orchestration-*.json"):
            try:
                run = json.loads(path.read_text())
            except Exception:
                continue
            for launch in run.get("launches") or []:
                sid = launch.get("session_id")
                if isinstance(sid, str) and sid:
                    ids.add(sid)
                    _, native = _parse_agent_session_ref(sid)
                    if native:
                        ids.add(native)
            for session in run.get("sessions") or []:
                sid = session.get("session_id")
                if isinstance(sid, str) and sid:
                    ids.add(sid)
                    _, native = _parse_agent_session_ref(sid)
                    if native:
                        ids.add(native)
        return ids

    def _collect_workers(self, since_min: int = 60 * 24, include_first_prompt: bool = True) -> list[dict]:
        now_epoch = int(_time.time())
        orchestration_ids = self._orchestration_session_id_set()
        workers = []
        for row in self._collect_session_rows(
            since_min=since_min,
            live_only=False,
            limit=300,
            include_first_prompt=include_first_prompt,
        ):
            first_prompt = row.get("first_prompt") or ""
            qualified_id = _qualified_session_id("claude", row.get("id") or "")
            is_orchestration = row.get("id") in orchestration_ids or qualified_id in orchestration_ids or "Pairling orchestration" in first_prompt
            if self._is_worker_project(row.get("project") or "") or is_orchestration:
                worker = self._worker_row_from_session(row, now_epoch)
                if is_orchestration and "orchestration" not in worker["risk_reasons"]:
                    worker["risk_reasons"].append("orchestration")
                workers.append(worker)
        return workers

    def _collect_codex_workers(self, since_min: int = 60 * 24) -> list[dict]:
        now_epoch = int(_time.time())
        workers: list[dict] = []
        for row in _agent_registry_recent("codex", since_min=since_min, limit=500):
            worker = self._codex_worker_row_from_registry(row, now_epoch)
            if worker:
                workers.append(worker)
        return workers

    @staticmethod
    def _activity_string_value(value) -> str:
        if value is None:
            return ""
        if isinstance(value, bool):
            return "Yes" if value else "No"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, list):
            return ", ".join(Handler._activity_string_value(v) for v in value[:6] if Handler._activity_string_value(v))
        if isinstance(value, dict):
            try:
                return json.dumps(value, sort_keys=True)
            except (TypeError, ValueError):
                return str(value)
        return str(value)

    @staticmethod
    def _bounded_raw_details(value, limit: int = 4000) -> str:
        try:
            raw = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            raw = str(value)
        if len(raw) > limit:
            return raw[:limit].rstrip() + "\n..."
        return raw

    @staticmethod
    def _first_nonempty_line(text: str, limit: int = 180) -> str:
        for line in str(text or "").splitlines():
            line = line.strip()
            if line:
                return line[:limit]
        return ""

    @staticmethod
    def _activity_tool_details(tool: str, inp: dict) -> dict[str, str]:
        labels = {
            "cmd": "Command",
            "command": "Command",
            "workdir": "Directory",
            "cwd": "Directory",
            "path": "Path",
            "file_path": "File",
            "files": "Files",
            "yield_time_ms": "Yield",
            "max_output_tokens": "Output cap",
            "timeout_ms": "Timeout",
            "session_id": "Session",
            "target": "Target",
            "chars": "Input",
        }
        details: dict[str, str] = {}
        for key, label in labels.items():
            if key not in inp:
                continue
            value = Handler._activity_string_value(inp.get(key))
            if value:
                details[label] = value[:240]
        if not details and inp:
            for key in sorted(inp.keys())[:4]:
                value = Handler._activity_string_value(inp.get(key))
                if value:
                    details[key.replace("_", " ").title()] = value[:240]
        if tool and "Tool" not in details:
            details = {"Tool": str(tool), **details}
        return details

    @staticmethod
    def _activity_tool_summary(tool: str, inp: dict) -> str:
        details = Handler._activity_tool_details(tool, inp)
        for key in ("Command", "File", "Path", "Directory", "Target"):
            if details.get(key):
                return f"{key}: {details[key]}"
        return "Tool call captured from session history."

    @staticmethod
    def _coerce_activity_tool(tool) -> tuple[str | None, dict]:
        if isinstance(tool, dict):
            name = tool.get("name") or tool.get("tool") or tool.get("type")
            return str(name) if name else None, tool
        if not isinstance(tool, str):
            return None, {}
        text = tool.strip()
        if not text:
            return None, {}
        if text.startswith("{"):
            try:
                obj = json.loads(text)
            except (TypeError, ValueError, json.JSONDecodeError):
                return text, {}
            if isinstance(obj, dict):
                name = obj.get("name") or obj.get("tool") or obj.get("type")
                if not name:
                    name = "exec_command" if "cmd" in obj else "tool"
                return str(name), obj
        return text, {}

    def _codex_activity_items(self, since_min: int = 360, limit: int = 80) -> list[dict]:
        cutoff = _time.time() - max(1, since_min) * 60
        items: list[dict] = []
        for path in _codex_rollout_paths()[:80]:
            try:
                st = path.stat()
            except OSError:
                continue
            if st.st_mtime < cutoff:
                continue
            meta = _codex_rollout_meta(path)
            if not meta:
                continue
            native_id = meta["id"]
            project = meta["cwd"]
            project_name = os.path.basename(project.rstrip("/")) or project
            try:
                lines = _tail_lines(path, max_lines=240, max_bytes=TRANSCRIPT_TAIL_SCAN_BYTES)
            except OSError:
                continue
            for raw in reversed(lines):
                for row in _normalize_codex_line(raw, native_id):
                    ts = _iso_to_epoch(row.get("timestamp")) or st.st_mtime
                    if ts < cutoff:
                        continue
                    msg = row.get("message") or {}
                    for block in msg.get("content") or []:
                        if not isinstance(block, dict):
                            continue
                        btype = block.get("type")
                        if btype == "tool_use":
                            tool = block.get("name") or "tool"
                            inp = block.get("input") if isinstance(block.get("input"), dict) else {}
                            details = self._activity_tool_details(str(tool), inp)
                            raw_details = self._bounded_raw_details(inp)
                            event_type = "running_tool"
                            title = f"{project_name}: {tool}"
                            if str(tool).lower() in {"apply_patch", "edit", "write", "multi_edit"}:
                                event_type = "file_edit"
                                title = f"{project_name}: edited file"
                            items.append({
                                "id": f"codex-tool-{row.get('uuid')}-{hashlib.sha256((str(tool) + raw_details).encode()).hexdigest()[:8]}",
                                "provider": "codex",
                                "type": event_type,
                                "severity": "info",
                                "timestamp": int(ts),
                                "session_id": _qualified_session_id("codex", native_id),
                                "project": project,
                                "title": title,
                                "subtitle": self._activity_tool_summary(str(tool), inp),
                                "details": details,
                                "raw_details": raw_details,
                                "state": None,
                                "tool": tool,
                                "context_pct": None,
                                "entry_id": row.get("uuid"),
                            })
                        elif btype == "tool_result":
                            content = block.get("content")
                            if isinstance(content, str) and ("error" in content.lower() or "traceback" in content.lower()):
                                summary = self._first_nonempty_line(content) or "Diagnostic output captured from Codex."
                                items.append({
                                    "id": f"codex-diagnostic-{row.get('uuid')}",
                                    "provider": "codex",
                                    "type": "diagnostic",
                                    "severity": "info",
                                    "timestamp": int(ts),
                                    "session_id": _qualified_session_id("codex", native_id),
                                    "project": project,
                                    "title": f"{project_name}: diagnostic tool output",
                                    "subtitle": summary,
                                    "details": {
                                        "Output": summary,
                                    },
                                    "raw_details": content[:4000] + ("\n..." if len(content) > 4000 else ""),
                                    "state": None,
                                    "tool": None,
                                    "context_pct": None,
                                    "entry_id": row.get("uuid"),
                                })
                if len(items) >= limit:
                    break
            if len(items) >= limit:
                break
        return items[:limit]

    @staticmethod
    def _terminal_source_diagnostic_event(provider: str, rows: list[dict], now_epoch: int) -> dict | None:
        if not rows:
            return None
        sources: dict[str, int] = {}
        unavailable = 0
        surface_count = 0
        control_count = 0
        needs_input = 0
        for row in rows:
            capabilities = set(row.get("capabilities") or [])
            has_surface = "terminal_surface" in capabilities
            has_control = "terminal_control" in capabilities
            surface_count += 1 if has_surface else 0
            control_count += 1 if has_control else 0
            if isinstance(row.get("terminal_attention"), dict) and row["terminal_attention"].get("needs_input"):
                needs_input += 1

            source = "unavailable"
            if provider == "codex":
                source_info = _terminal_surface_source(row.get("id") or "")
                source = str(source_info.get("source") or "unavailable")
            elif has_surface:
                source = "terminal_app_contents"
            sources[source] = sources.get(source, 0) + 1
            if source == "unavailable":
                unavailable += 1

        provider_label = "Codex" if provider == "codex" else "Claude"
        details = {
            "Live sessions": str(len(rows)),
            "Terminal surface": str(surface_count),
            "Terminal control": str(control_count),
            "Broker VT": str(sources.get("broker_vt", 0)),
            "Terminal.app": str(sources.get("terminal_app_contents", 0)),
            "Unavailable": str(unavailable),
            "Needs input": str(needs_input),
            "Raw screen rows": "Not included",
        }
        raw_details = {
            "provider": provider,
            "live_sessions": len(rows),
            "terminal_surface": surface_count,
            "terminal_control": control_count,
            "needs_input": needs_input,
            "sources": sources,
            "screen_rows_included": False,
        }
        return {
            "id": f"terminal-source-{provider}",
            "provider": provider,
            "type": "diagnostic",
            "severity": "warning" if unavailable and surface_count == 0 else "info",
            "timestamp": now_epoch,
            "session_id": f"{provider}:terminal-source-diagnostics",
            "project": "Pairling terminal diagnostics",
            "title": f"Terminal source diagnostics: {provider_label}",
            "subtitle": f"{surface_count}/{len(rows)} live sessions expose terminal surface; {control_count}/{len(rows)} expose safe controls.",
            "details": details,
            "raw_details": Handler._bounded_raw_details(raw_details),
            "state": None,
            "tool": None,
            "context_pct": None,
            "entry_id": None,
        }

    def _terminal_source_diagnostic_items(self, since_min: int, now_epoch: int) -> list[dict]:
        items: list[dict] = []
        try:
            claude_rows = self._collect_session_rows(
                since_min=since_min,
                live_only=True,
                limit=100,
                include_first_prompt=False,
            )
            claude_event = self._terminal_source_diagnostic_event("claude", claude_rows, now_epoch)
            if claude_event:
                items.append(claude_event)
        except Exception:
            pass
        try:
            codex_rows = _list_codex_sessions(live_only=True, active_within_min=since_min)
            codex_event = self._terminal_source_diagnostic_event("codex", codex_rows, now_epoch)
            if codex_event:
                items.append(codex_event)
        except Exception:
            pass
        return items

    def _activity_items(self, since_min: int = 360, limit: int = 120) -> list[dict]:
        now_epoch = int(_time.time())
        items: list[dict] = []
        for row in self._collect_session_rows(since_min=since_min, live_only=True, limit=100):
            sid = row["id"]
            project = row.get("project") or ""
            project_name = os.path.basename(project) or project
            state = row.get("state")
            turn_started = row.get("turn_started_at")
            ts = int(turn_started) if isinstance(turn_started, (int, float)) else int(row.get("last_heartbeat") or now_epoch)
            if state in ("thinking", "tool"):
                tool = row.get("tool")
                tool_name, tool_input = self._coerce_activity_tool(tool)
                tool_details = self._activity_tool_details(tool_name or "", tool_input) if tool_input else None
                tool_raw_details = self._bounded_raw_details(tool_input) if tool_input else None
                elapsed = max(0, now_epoch - ts)
                items.append({
                    "id": f"active-{sid}-{state}",
                    "provider": "claude",
                    "type": "running_tool" if state == "tool" else "thinking",
                    "severity": "warning" if elapsed > 900 else "info",
                    "timestamp": ts,
                    "session_id": sid,
                    "project": project,
                    "title": f"{project_name}: {tool_name or state}",
                    "subtitle": self._activity_tool_summary(tool_name or "", tool_input) if tool_input else (f"Running for {elapsed // 60}m {elapsed % 60}s" if elapsed >= 60 else f"Running for {elapsed}s"),
                    "details": tool_details,
                    "raw_details": tool_raw_details,
                    "state": state,
                    "tool": tool_name or tool,
                    "context_pct": row.get("context_pct"),
                    "entry_id": None,
                })
            context_pct = float(row.get("context_pct") or 0.0)
            if context_pct >= 70:
                items.append({
                    "id": f"context-{sid}",
                    "provider": "claude",
                    "type": "context_pressure",
                    "severity": "critical" if context_pct >= 95 else ("warning" if context_pct >= 85 else "info"),
                    "timestamp": int(row.get("last_heartbeat") or now_epoch),
                    "session_id": sid,
                    "project": project,
                    "title": f"{project_name}: {context_pct:.0f}% context",
                    "subtitle": "Consider summarizing, compacting, or starting a fresh session.",
                    "state": state,
                    "tool": row.get("tool"),
                    "context_pct": context_pct,
                    "entry_id": None,
                })
            sig = self._recent_session_signal(
                sid,
                project=row.get("project"),
                claude_uuid=row.get("claude_uuid"),
            )
            if sig.get("anomaly"):
                an = sig["anomaly"]
                items.append({
                    "id": f"anomaly-{sid}-{an.get('kind')}",
                    "provider": "claude",
                    "type": "anomaly",
                    "severity": "critical" if an.get("kind") == "error" else "warning",
                    "timestamp": int(row.get("last_heartbeat") or now_epoch),
                    "session_id": sid,
                    "project": project,
                    "title": f"{project_name}: {an.get('title')}",
                    "subtitle": an.get("detail") or "Open the transcript for details.",
                    "state": state,
                    "tool": row.get("tool"),
                    "context_pct": context_pct,
                    "entry_id": None,
                })
            if sig.get("latest_edit"):
                items.append({
                    "id": f"edit-{sid}-{hashlib.sha256(sig['latest_edit'].encode()).hexdigest()[:8]}",
                    "provider": "claude",
                    "type": "file_edit",
                    "severity": "info",
                    "timestamp": int(row.get("last_heartbeat") or now_epoch),
                    "session_id": sid,
                    "project": project,
                    "title": f"{project_name}: edited file",
                    "subtitle": sig["latest_edit"],
                    "state": state,
                    "tool": row.get("tool"),
                    "context_pct": context_pct,
                    "entry_id": None,
                })
        activity_workers = self._collect_workers(since_min=min(since_min, 360), include_first_prompt=False)
        activity_workers.extend(self._collect_codex_workers(since_min=min(since_min, 360)))
        for worker in activity_workers:
            if worker["stale"] or worker["risk_score"] >= 5:
                items.append({
                    "id": f"worker-{worker['id']}",
                    "provider": worker.get("provider") or "claude",
                    "type": "worker",
                    "severity": "critical" if worker["stale"] else "warning",
                    "timestamp": int(worker["last_heartbeat"] or now_epoch),
                    "session_id": worker["id"],
                    "project": worker["project"],
                    "title": f"Worker risk: {os.path.basename(worker['project'])}",
                    "subtitle": ", ".join(worker["risk_reasons"]) or "Worker needs review.",
                    "state": worker["state"],
                    "tool": worker["tool"],
                    "context_pct": worker["context_pct"],
                    "entry_id": None,
                })
        items.extend(self._codex_activity_items(since_min=since_min, limit=max(20, limit // 2)))
        items.extend(self._terminal_source_diagnostic_items(since_min=since_min, now_epoch=now_epoch))
        items.extend(self._safety_activity_items(limit=max(20, limit // 3)))
        items.sort(key=lambda x: (x.get("severity") == "critical", x.get("timestamp") or 0), reverse=True)
        return items[: max(1, min(limit, 300))]

    def _safety_activity_items(self, limit: int = 40) -> list[dict]:
        if SAFETY_MONITOR is None:
            return []
        items: list[dict] = []
        for event in SAFETY_MONITOR.events(limit=limit):
            severity = event.get("severity") or "info"
            if severity == "watch":
                severity = "warning"
            items.append({
                "id": f"safety-{event.get('id')}",
                "type": "safety",
                "severity": "critical" if severity == "critical" else ("warning" if severity == "warning" else "info"),
                "timestamp": int(event.get("timestamp") or _time.time()),
                "session_id": event.get("session_id") or "safety-monitor",
                "project": event.get("project") or "Pairling Safety Monitor",
                "title": event.get("title") or "Safety event",
                "subtitle": event.get("subtitle"),
                "state": event.get("state"),
                "tool": event.get("tool"),
                "context_pct": None,
                "entry_id": event.get("entry_id"),
            })
        return items

    def _handle_activity(self, q):
        try:
            since_min = int(q.get("since_min", ["360"])[0])
            limit = int(q.get("limit", ["120"])[0])
        except ValueError:
            since_min, limit = 360, 120
        items = self._activity_items(since_min=since_min, limit=limit)
        self._send_json({"count": len(items), "items": items, "ts": _time.time()})

    def _handle_activity_stream(self, q):
        try:
            since_min = int(q.get("since_min", ["360"])[0])
        except ValueError:
            since_min = 360
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        deadline = _time.time() + 10 * 60
        last_hash = None
        while _time.time() < deadline:
            items = self._activity_items(since_min=since_min, limit=120)
            digest = hashlib.sha256(json.dumps(items, sort_keys=True).encode()).hexdigest()
            if digest != last_hash:
                payload = json.dumps({"items": items, "ts": _time.time()}).encode()
                try:
                    self.wfile.write(b"event: snapshot\ndata: " + payload + b"\n\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
                last_hash = digest
            _time.sleep(2.0)
        try:
            self.wfile.write(b"event: done\ndata: {}\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return

    def _handle_safety_status(self, q):
        if SAFETY_MONITOR is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "safety_unavailable",
                    "message": "Safety monitor bridge is unavailable",
                },
            }, status=503)
            return
        self._send_json({"ok": True, "safety": SAFETY_MONITOR.status(), "ts": _time.time()})

    def _handle_push_status(self, q):
        if PUSH_DISPATCHER is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "push_unavailable",
                    "message": "Push dispatcher is unavailable",
                },
            }, status=503)
            return
        device_id = q.get("device_id", [getattr(self.pairling_auth, "device_id", None)])[0]
        self._send_json(PUSH_DISPATCHER.status(device_id=device_id))

    def _handle_push_preferences(self, q):
        if PUSH_DISPATCHER is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "push_unavailable",
                    "message": "Push dispatcher is unavailable",
                },
            }, status=503)
            return
        try:
            payload = self._read_json_object()
            device_id = str(payload.get("device_id") or getattr(self.pairling_auth, "device_id", "") or "")
            result = PUSH_DISPATCHER.update_preferences(device_id=device_id, payload=payload)
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        except PushDispatcherError as exc:
            self._send_json({"ok": False, "error": {"code": exc.code, "message": exc.message}}, status=exc.status)
            return
        self._send_json(result)

    def _handle_push_permission_allow(self, q):
        # "Allow" from the phone's Lock-Screen card: answer the waiting permission
        # dialog by injecting Enter into the broker PTY (the same key path
        # /terminal-control uses). Idempotent on request_nonce (duplicate Allow is a
        # no-op); deny lives in-app via "Open Session". NO timeout / NO auto-deny.
        try:
            payload = self._read_json_object()
        except Exception:
            self._send_json({"ok": False, "error": {"code": "bad_json", "message": "invalid JSON"}}, status=400)
            return
        request_nonce = str(payload.get("request_nonce") or "").strip()
        if not request_nonce:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": "request_nonce required"}}, status=400)
            return
        row = _pending_approval_get(request_nonce)
        if not row:
            self._send_json({"ok": False, "error": {"code": "not_found", "message": "unknown request_nonce"}}, status=404)
            return
        current_state = str(row.get("state") or "")
        if current_state == "allowed":
            self._send_json({
                "ok": False,
                "state": current_state,
                "error": {
                    "code": "approval_in_progress",
                    "message": "permission approval is already being injected",
                },
            }, status=409)
            return
        if current_state not in {"pending", "attention"}:
            # Already resolved (double-tap / re-delivery) — safe idempotent no-op.
            self._send_json({"ok": True, "state": str(row.get("state") or ""), "already_resolved": True})
            return
        if not _pending_approval_cas(request_nonce, current_state, "allowed"):
            latest = _pending_approval_get(request_nonce) or {}
            latest_state = str(latest.get("state") or "")
            if latest_state == "allowed":
                self._send_json({
                    "ok": False,
                    "state": latest_state,
                    "error": {
                        "code": "approval_in_progress",
                        "message": "permission approval is already being injected",
                    },
                }, status=409)
            else:
                self._send_json({"ok": True, "state": latest_state, "already_resolved": True})
            return
        provider = str(row.get("provider") or "claude")
        injected = {"ok": False, "reason": "no broker session"}
        # 1) Authoritative: the broker session id the hook captured from the broker's
        #    own PAIRLING_BROKER_SESSION_ID env — no fragile tty reconciliation.
        broker_id = str(row.get("broker_id") or "")
        if broker_id and PTY_BROKER is not None:
            try:
                injected = PTY_BROKER.control(broker_id, {"type": "key", "key": "enter"})
            except Exception as e:
                injected = {"ok": False, "reason": f"{type(e).__name__}: {str(e)[:120]}"}
        # 2) Fallback: resolve via /terminal-control's resolver (registry -> broker).
        if not injected.get("ok"):
            native_id = str(row.get("native_id") or "")
            if not native_id:
                native_id, _b, _t = _approval_resolve_session(provider, str(row.get("session_id") or ""))
            if native_id and PTY_BROKER is not None:
                try:
                    bid = self._terminal_control_target(_qualified_session_id(provider, native_id)).get("broker_id")
                    if bid:
                        injected = PTY_BROKER.control(bid, {"type": "key", "key": "enter"})
                except Exception:
                    pass
        if not injected.get("ok"):
            _pending_approval_cas(request_nonce, "allowed", current_state)
            latest = _pending_approval_get(request_nonce) or {}
            self._send_json({
                "ok": False,
                "state": str(latest.get("state") or current_state),
                "broker_id": broker_id,
                "injected": injected,
                "error": {
                    "code": "injection_failed",
                    "message": "permission approval could not be delivered to the broker PTY",
                },
            }, status=409)
            return
        if not _pending_approval_cas(request_nonce, "allowed", "released"):
            latest = _pending_approval_get(request_nonce) or {}
            latest_state = str(latest.get("state") or "")
            if latest_state == "released":
                self._send_json({"ok": True, "state": "released", "broker_id": broker_id, "injected": injected})
            else:
                self._send_json({
                    "ok": False,
                    "state": latest_state or "allowed",
                    "broker_id": broker_id,
                    "injected": injected,
                    "error": {
                        "code": "release_state_failed",
                        "message": "permission approval was injected but the state transition did not complete",
                    },
                }, status=409)
            return
        self._send_json({"ok": True, "state": "released", "broker_id": broker_id, "injected": injected})

    def _handle_push_test(self, q):
        if PUSH_DISPATCHER is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "push_unavailable",
                    "message": "Push dispatcher is unavailable",
                },
            }, status=503)
            return
        try:
            payload = self._read_json_object()
            device_id = str(payload.get("device_id") or getattr(self.pairling_auth, "device_id", "") or "")
            result = PUSH_DISPATCHER.record_test(device_id=device_id, payload=payload)
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        except PushDispatcherError as exc:
            self._send_json({"ok": False, "error": {"code": exc.code, "message": exc.message}}, status=exc.status)
            return
        self._send_json(result, status=200 if result.get("ok") else 202)

    def _handle_push_live_activity_token(self, q):
        if PUSH_DISPATCHER is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "push_unavailable",
                    "message": "Push dispatcher is unavailable",
                },
            }, status=503)
            return
        try:
            payload = self._read_json_object()
            device_id = str(payload.get("device_id") or getattr(self.pairling_auth, "device_id", "") or "")
            result = PUSH_DISPATCHER.record_live_activity_token(device_id=device_id, payload=payload)
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        except PushDispatcherError as exc:
            self._send_json({"ok": False, "error": {"code": exc.code, "message": exc.message}}, status=exc.status)
            return
        self._send_json(result)

    def _handle_push_live_activity_test(self, q):
        if PUSH_DISPATCHER is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "push_unavailable",
                    "message": "Push dispatcher is unavailable",
                },
            }, status=503)
            return
        try:
            payload = self._read_json_object()
            device_id = str(payload.get("device_id") or getattr(self.pairling_auth, "device_id", "") or "")
            result = PUSH_DISPATCHER.record_live_activity_test(device_id=device_id, payload=payload)
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        except PushDispatcherError as exc:
            self._send_json({"ok": False, "error": {"code": exc.code, "message": exc.message}}, status=exc.status)
            return
        self._send_json(result, status=200 if result.get("ok") else 202)

    def _handle_sentinel_status(self, q):
        if SENTINEL_NOTIFICATIONS is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "sentinel_unavailable",
                    "message": "Sentinel notification center is unavailable",
                },
            }, status=503)
            return
        try:
            since_min = int(q.get("since_min", ["60"])[0])
            human_idle = q.get("human_idle_minutes", [None])[0]
            human_idle_minutes = float(human_idle) if human_idle not in (None, "") else None
            worker_stats = self._worker_stats_payload(since_min)
        except ValueError:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": "numeric query is invalid"}}, status=400)
            return
        except RuntimeError as exc:
            self._send_json({"ok": False, "error": {"code": "worker_stats_unavailable", "message": str(exc)}}, status=502)
            return
        self._send_json(SENTINEL_NOTIFICATIONS.status(
            worker_stats=worker_stats,
            token_sessions=[],
            human_idle_minutes=human_idle_minutes,
        ))

    def _handle_sentinel_preferences(self, q):
        if SENTINEL_NOTIFICATIONS is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "sentinel_unavailable",
                    "message": "Sentinel notification center is unavailable",
                },
            }, status=503)
            return
        if self.command == "GET":
            self._send_json(SENTINEL_NOTIFICATIONS.preferences())
            return
        try:
            result = SENTINEL_NOTIFICATIONS.update_preferences(self._read_json_object())
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        except Exception as exc:
            code = getattr(exc, "code", "sentinel_preferences_failed")
            message = getattr(exc, "message", str(exc))
            status = getattr(exc, "status", 400)
            self._send_json({"ok": False, "error": {"code": code, "message": message}}, status=status)
            return
        self._send_json(result)

    def _handle_sentinel_snooze(self, q):
        if SENTINEL_NOTIFICATIONS is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "sentinel_unavailable",
                    "message": "Sentinel notification center is unavailable",
                },
            }, status=503)
            return
        try:
            payload = self._read_json_object()
            result = SENTINEL_NOTIFICATIONS.snooze(
                key=str(payload.get("key") or "*"),
                minutes=int(payload.get("minutes") or 60),
            )
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        self._send_json(result)

    def _handle_sentinel_evaluate_now(self, q):
        if SENTINEL_NOTIFICATIONS is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "sentinel_unavailable",
                    "message": "Sentinel notification center is unavailable",
                },
            }, status=503)
            return
        try:
            payload = self._read_json_object()
            since_min = int(payload.get("since_min") or q.get("since_min", ["60"])[0])
            worker_stats = payload.get("worker_stats")
            if not isinstance(worker_stats, dict):
                worker_stats = self._worker_stats_payload(since_min)
            token_sessions = payload.get("token_sessions")
            if not isinstance(token_sessions, list):
                token_sessions = []
            human_idle = payload.get("human_idle_minutes")
            human_idle_minutes = float(human_idle) if human_idle not in (None, "") else None
            device_id = str(payload.get("device_id") or getattr(self.pairling_auth, "device_id", "") or "")
            result = SENTINEL_NOTIFICATIONS.evaluate_now(
                worker_stats=worker_stats,
                token_sessions=token_sessions,
                human_idle_minutes=human_idle_minutes,
                device_id=device_id or None,
                force=bool(payload.get("force")),
            )
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        except RuntimeError as exc:
            self._send_json({"ok": False, "error": {"code": "worker_stats_unavailable", "message": str(exc)}}, status=502)
            return
        self._send_json(result)

    def _handle_sentinel_events(self, q):
        if SENTINEL_NOTIFICATIONS is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "sentinel_unavailable",
                    "message": "Sentinel notification center is unavailable",
                },
            }, status=503)
            return
        try:
            since = float(q.get("since", ["0"])[0] or 0)
            limit = int(q.get("limit", ["100"])[0])
        except ValueError:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": "since/limit must be numeric"}}, status=400)
            return
        events = SENTINEL_NOTIFICATIONS.events(since=since, limit=limit)
        self._send_json({"ok": True, "count": len(events), "items": events, "ts": _time.time()})

    def _handle_safety_events(self, q):
        if SAFETY_MONITOR is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "safety_unavailable",
                    "message": "Safety monitor bridge is unavailable",
                },
            }, status=503)
            return
        since = q.get("since", [""])[0]
        try:
            limit = int(q.get("limit", ["100"])[0])
        except ValueError:
            limit = 100
        events = SAFETY_MONITOR.events(since=since, limit=limit)
        self._send_json({"ok": True, "count": len(events), "items": events, "ts": _time.time()})

    def _handle_safety_ack(self, q):
        if SAFETY_MONITOR is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "safety_unavailable",
                    "message": "Safety monitor bridge is unavailable",
                },
            }, status=503)
            return
        try:
            payload = json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "invalid JSON")
            return
        ids = payload.get("ids") if isinstance(payload, dict) else None
        if ids is not None and not isinstance(ids, list):
            self.send_error(400, "ids must be a list")
            return
        self._send_json(SAFETY_MONITOR.ack(ids=ids))

    def _handle_safety_request_activation(self, q):
        if SAFETY_MONITOR is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "safety_unavailable",
                    "message": "Safety monitor bridge is unavailable",
                },
            }, status=503)
            return
        result = SAFETY_MONITOR.request_activation()
        self._send_json(result, status=200 if result.get("ok") else 404)

    def _handle_safety_open_full_disk_access(self, q):
        if SAFETY_MONITOR is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "safety_unavailable",
                    "message": "Safety monitor bridge is unavailable",
                },
            }, status=503)
            return
        result = SAFETY_MONITOR.open_full_disk_access()
        self._send_json(result, status=200 if result.get("ok") else 502)

    def _handle_safety_evidence_test(self, q):
        if SAFETY_MONITOR is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "safety_unavailable",
                    "message": "Safety monitor bridge is unavailable",
                },
            }, status=503)
            return
        try:
            payload = self._read_json_object()
            wait_seconds = float(payload.get("wait_seconds", 8))
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._send_json({"ok": False, "error": {"code": "bad_request", "message": str(exc)}}, status=400)
            return
        result = SAFETY_MONITOR.run_evidence_test(wait_seconds=wait_seconds)
        self._send_json(result, status=200 if result.get("ok") else 202)

    def _handle_aperture_cli_status(self, q):
        if _aperture_cli_status_payload is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "aperture_cli_integration_unavailable",
                    "message": "Aperture CLI integration is unavailable",
                },
            }, status=503)
            return
        self._send_json(_aperture_cli_status_payload(home=HOME, env=os.environ))

    def _handle_aperture_cli_providers(self, q):
        if _aperture_cli_provider_payload is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "aperture_cli_integration_unavailable",
                    "message": "Aperture CLI integration is unavailable",
                },
            }, status=503)
            return
        self._send_json(_aperture_cli_provider_payload(home=HOME, env=os.environ))

    def _handle_aperture_cli_launch_contexts(self, q):
        if _aperture_cli_contexts_payload is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "aperture_cli_integration_unavailable",
                    "message": "Aperture CLI integration is unavailable",
                },
            }, status=503)
            return
        self._send_json(_aperture_cli_contexts_payload(home=HOME, env=os.environ))

    def _handle_aperture_cli_open(self, q):
        if _aperture_cli_status_payload is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "aperture_cli_integration_unavailable",
                    "message": "Aperture CLI integration is unavailable",
                },
            }, status=503)
            return

        allowed, retry = _inject_rate_check("__aperture_cli_open__")
        if not allowed:
            self.send_response(429)
            self.send_header("Retry-After", str(retry))
            self.send_header("Content-Type", "application/json")
            body = json.dumps({
                "ok": False,
                "error": {"code": "rate_limited", "message": f"retry in {retry}s"},
            }).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        status_payload = _aperture_cli_status_payload(home=HOME, env=os.environ)
        binary = str(status_payload.get("binary_path") or "").strip()
        if not binary or not os.path.exists(binary) or not os.access(binary, os.X_OK):
            self._send_json({
                "ok": False,
                "error": {
                    "code": "aperture_cli_not_installed",
                    "message": "Aperture CLI binary was not found on this Mac.",
                },
            }, status=503)
            return

        shell_cmd = f"cd {shlex.quote(str(HOME))} && exec {shlex.quote(binary)}"
        as_escaped_cmd = _as_escape(shell_cmd)
        as_escaped_title = _as_escape("Aperture CLI")
        script = f'''
        tell application "Terminal"
            activate
            set newTab to do script "{as_escaped_cmd}"
            set custom title of newTab to "{as_escaped_title}"
            delay 0.5
            return "ok\t" & (tty of newTab)
        end tell
        '''
        result = _run_osascript(script)
        if not result.get("ok"):
            self._send_json({
                "ok": False,
                "error": {
                    "code": "terminal_open_failed",
                    "message": result.get("reason") or "Terminal could not open Aperture CLI.",
                },
            }, status=502)
            return

        stdout = result.get("stdout") or ""
        parts = stdout.split("\t")
        tty = parts[1].strip() if len(parts) >= 2 else ""
        try:
            audit_path = HOME / ".claude" / "audit" / "aperture-cli-open.jsonl"
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "ts": _time.time(),
                    "action": "aperture_cli_open",
                    "tty": tty or None,
                    "version": status_payload.get("version"),
                    "binary_path_source": status_payload.get("binary_path_source"),
                    "endpoint": (status_payload.get("settings") or {}).get("active_endpoint"),
                }, ensure_ascii=False) + "\n")
        except Exception:
            pass

        self._send_json({
            "ok": True,
            "tty": tty or None,
            "version": status_payload.get("version"),
            "endpoint": (status_payload.get("settings") or {}).get("active_endpoint"),
            "message": "Aperture CLI opened on Mac.",
        })

    def _handle_workers(self, q):
        try:
            since_min = int(q.get("since_min", ["1440"])[0])
        except ValueError:
            since_min = 1440
        provider_filter = q.get("provider", ["all"])[0].lower()
        if not _valid_provider_filter(provider_filter):
            _send_unknown_provider(self, provider_filter)
            return
        workers: list[dict] = []
        if provider_filter in ("all", "claude"):
            workers.extend(self._collect_workers(since_min=since_min))
        if provider_filter in ("all", "codex"):
            workers.extend(self._collect_codex_workers(since_min=since_min))
        workers.sort(key=lambda w: (w["risk_score"], w["last_heartbeat"]), reverse=True)
        active = sum(1 for w in workers if w["active"])
        stale = sum(1 for w in workers if w["stale"])
        self._send_json({
            "count": len(workers),
            "active": active,
            "stale": stale,
            "items": workers[:300],
            "ts": _time.time(),
        })

    # ----- /orchestrations: bounded multi-agent orchestration -----
    _ORCHESTRATION_MODES = {"research", "debug", "scaffold", "decide", "draft", "remember", "extend"}
    _ORCHESTRATION_AUTONOMY = {"review_first", "bounded_auto", "full_auto"}
    _ORCHESTRATION_PERMISSIONS = {"default", "accept_edits", "plan"}
    _ORCHESTRATION_STOP_CONDITIONS = {"first_findings", "tests_pass", "budget_hit", "time_limit", "manual_stop"}
    _ORCHESTRATION_ACTIVE_HEARTBEAT_SECONDS = 180

    def _route_orchestration_path(self, path: str, q):
        parts = [p for p in path.split("/") if p]
        if len(parts) < 2:
            self.send_error(404, "unknown orchestration path")
            return
        orchestration_id = parts[1]
        if not _safe_session_id(orchestration_id):
            self.send_error(400, "bad orchestration id")
            return
        if len(parts) == 2 and self.command == "GET":
            self._handle_orchestration_detail(orchestration_id)
        elif len(parts) == 3 and parts[2] == "stream" and self.command == "GET":
            self._handle_orchestration_stream(orchestration_id)
        elif len(parts) == 3 and parts[2] == "stop" and self.command == "POST":
            self._handle_orchestration_stop(orchestration_id)
        else:
            self.send_error(404, "unknown orchestration path")

    def _orchestration_path(self, orchestration_id: str) -> Path:
        return ORCHESTRATIONS_DIR / f"{orchestration_id}.json"

    def _orchestration_read(self, orchestration_id: str) -> dict | None:
        path = self._orchestration_path(orchestration_id)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())
        except Exception:
            return None

    def _orchestration_write(self, run: dict) -> None:
        run["updated_at"] = _time.time()
        path = self._orchestration_path(run["id"])
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(run, indent=2, sort_keys=True))
        tmp.replace(path)

    def _orchestration_event(self, run: dict, kind: str, title: str, detail: str | None = None) -> None:
        events = run.setdefault("events", [])
        events.append({
            "id": secrets.token_hex(6),
            "ts": _time.time(),
            "kind": kind,
            "title": title,
            "detail": detail,
        })
        del events[:-80]

    def _orchestration_validate_project(self, project: str) -> str | None:
        project = (project or "").strip()
        if not project:
            return "project required"
        if not project.startswith("/"):
            return "project must be absolute path"
        if ".." in project.split("/"):
            return "path traversal rejected"
        home = str(HOME)
        if project == home or project.startswith(home + "/") or project in ("/tmp", "/private/tmp") or project.startswith("/private/tmp/") or project.startswith("/tmp/"):
            pass
        else:
            return f"project path must be under $HOME or /tmp: {project}"
        if not os.path.isdir(project):
            return f"directory not found: {project}"
        return None

    def _orchestration_project_dirty(self, project: str) -> bool:
        try:
            proc = subprocess.run(
                ["git", "-C", project, "status", "--porcelain"],
                capture_output=True, text=True, timeout=4,
            )
            return proc.returncode == 0 and bool(proc.stdout.strip())
        except Exception:
            return False

    def _orchestration_claude_bin(self) -> Path | None:
        for candidate in (
            HOME / ".local" / "bin" / "claude",
            Path("/opt/homebrew/bin/claude"),
            Path("/usr/local/bin/claude"),
        ):
            if candidate.exists():
                return candidate
        return None

    def _orchestration_codex_bin(self) -> Path | None:
        for candidate in (
            Path("/usr/local/bin/codex"),
            Path("/opt/homebrew/bin/codex"),
            HOME / ".local" / "bin" / "codex",
        ):
            if candidate.exists():
                return candidate
        for prefix in os.environ.get("PATH", "").split(":"):
            p = Path(prefix) / "codex"
            if p.exists() and os.access(p, os.X_OK):
                return p
        return None

    def _orchestration_shell_quote(self, value: str) -> str:
        return "'" + value.replace("'", "'\\''") + "'"

    def _codex_worker_append_jsonl(self, path: Path, obj: dict) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
        except OSError:
            pass

    def _codex_worker_timestamp(self) -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def _codex_worker_metadata(self, run: dict, role: str, prompt_path: Path,
                               output_path: Path, stderr_path: Path, last_path: Path,
                               title: str, prompt_preview: str, pid: int | None = None,
                               extra: dict | None = None) -> dict:
        metadata = {
            "kind": "orchestration_worker",
            "provider": "codex",
            "native_id": f"worker-{run['id']}-{role}",
            "orchestration_id": run["id"],
            "role": role,
            "title": title,
            "project": run["project"],
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "stderr_path": str(stderr_path),
            "last_message_path": str(last_path),
            "prompt_preview": prompt_preview[:500],
            "state": "running",
            "model": run.get("model"),
        }
        if pid:
            metadata["pid"] = pid
        if extra:
            metadata.update(extra)
        return metadata

    def _orchestration_watch_codex_worker(self, run_id: str, native_id: str, proc: subprocess.Popen,
                                 output_path: Path, last_path: Path, stderr_path: Path) -> None:
        exit_code = None
        try:
            exit_code = proc.wait()
        except Exception:
            exit_code = -1
        reg = _agent_registry_get("codex", native_id) or {}
        metadata = self._registry_metadata(reg) if reg else {}
        metadata["exit_code"] = int(exit_code or 0)
        metadata["completed_at"] = _time.time()
        metadata["state"] = "idle" if exit_code == 0 else "error"
        last_text = ""
        try:
            last_text = last_path.read_text(errors="replace").strip()
        except OSError:
            last_text = ""
        if last_text:
            self._codex_worker_append_jsonl(output_path, {
                "type": "event_msg",
                "timestamp": self._codex_worker_timestamp(),
                "payload": {
                    "type": "agent_message",
                    "message": last_text,
                },
            })
        elif exit_code != 0:
            try:
                last_text = stderr_path.read_text(errors="replace")[-1000:].strip()
            except OSError:
                last_text = ""
            if last_text:
                self._codex_worker_append_jsonl(output_path, {
                    "type": "event_msg",
                    "timestamp": self._codex_worker_timestamp(),
                    "payload": {
                        "type": "agent_message",
                        "message": f"Codex worker exited {exit_code}:\n{last_text}",
                    },
                })
        self._codex_worker_append_jsonl(output_path, {
            "type": "event_msg",
            "timestamp": self._codex_worker_timestamp(),
            "payload": {
                "type": "worker_stop",
                "exit_code": exit_code,
            },
        })
        _agent_registry_upsert(
            "codex",
            native_id,
            metadata.get("project") or str(HOME),
            pid=int(metadata.get("pid") or proc.pid or 0),
            state=metadata["state"],
            metadata=metadata,
        )
        _agent_registry_mark_closed("codex", native_id)
        run = self._orchestration_read(run_id)
        if run:
            self._orchestration_event(
                run,
                "worker_finished",
                f"{metadata.get('role') or native_id} finished",
                f"exit {exit_code}",
            )
            self._orchestration_write(self._orchestration_refresh(run))

    def _orchestration_launch_role(self, run: dict, role: str, prompt_path: Path, title_suffix: str) -> dict:
        project = run["project"]
        claude_bin = self._orchestration_claude_bin()
        if not claude_bin:
            return {"role": role, "ok": False, "error": "claude CLI not found"}
        orchestration_id = run["id"]
        title = f"orchestration-{role}-{orchestration_id[:6]}"
        launch_script = prompt_path.with_suffix(".launch.sh")
        launch_script.write_text(
            "#!/bin/zsh\n"
            "set -e\n"
            f"cd {self._orchestration_shell_quote(project)}\n"
            f"export PAIRLING_ORCHESTRATION_ID={self._orchestration_shell_quote(orchestration_id)}\n"
            f"export PAIRLING_ORCHESTRATION_ROLE={self._orchestration_shell_quote(role)}\n"
            f"prompt=$(cat {self._orchestration_shell_quote(str(prompt_path))})\n"
            f"exec {self._orchestration_shell_quote(str(claude_bin))} --dangerously-skip-permissions \"$prompt\"\n",
            encoding="utf-8",
        )
        launch_script.chmod(0o700)
        shell_cmd = (
            f"/bin/zsh {self._orchestration_shell_quote(str(launch_script))}"
        )
        script = f'''
        tell application "Terminal"
            activate
            set newTab to do script "{_as_escape(shell_cmd)}"
            set custom title of newTab to "{_as_escape(title)}"
            delay 0.5
            return "ok\t" & (tty of newTab)
        end tell
        '''
        result = _run_osascript(script)
        tty = ""
        if result.get("ok"):
            parts = (result.get("stdout") or "").split("\t")
            if len(parts) >= 2:
                tty = parts[1].strip()
        pid = _pid_for_tty_command(tty, "claude") if tty else 0
        return {
            "provider": "claude",
            "role": role,
            "ok": bool(result.get("ok")),
            "error": result.get("reason"),
            "title": title,
            "prompt_path": str(prompt_path),
            "launch_script": str(launch_script),
            "title_suffix": title_suffix,
            "tty": tty,
            "pid": pid,
            "session_id": None,
        }

    def _orchestration_launch_codex_role(self, run: dict, role: str, prompt_path: Path, title_suffix: str) -> dict:
        project = run["project"]
        codex_bin = self._orchestration_codex_bin()
        if not codex_bin:
            return {"provider": "codex", "role": role, "ok": False, "error": "codex CLI not found"}
        orchestration_id = run["id"]
        native_id = f"worker-{orchestration_id}-{role}"
        title = f"codex-orchestration-{role}-{orchestration_id[:6]}"
        output_path = prompt_path.with_suffix(".codex.jsonl")
        stderr_path = prompt_path.with_suffix(".stderr.log")
        last_path = prompt_path.with_suffix(".last.txt")
        prompt_text = ""
        try:
            prompt_text = prompt_path.read_text(errors="replace")
        except OSError:
            prompt_text = ""
        self._codex_worker_append_jsonl(output_path, {
            "type": "session_meta",
            "timestamp": self._codex_worker_timestamp(),
            "payload": {
                "id": native_id,
                "cwd": project,
                "model": run.get("model"),
                "source": "Pairling Orchestration",
            },
        })
        self._codex_worker_append_jsonl(output_path, {
            "type": "event_msg",
            "timestamp": self._codex_worker_timestamp(),
            "payload": {
                "type": "user_message",
                "message": prompt_text,
            },
        })
        cmd = [
            str(codex_bin),
            "exec",
            "--json",
            "-C",
            project,
            "--dangerously-bypass-approvals-and-sandbox",
            "-o",
            str(last_path),
            "-",
        ]
        try:
            stdin_f = prompt_path.open("rb")
            stdout_f = output_path.open("ab")
            stderr_f = stderr_path.open("ab")
            proc = subprocess.Popen(
                cmd,
                cwd=project,
                stdin=stdin_f,
                stdout=stdout_f,
                stderr=stderr_f,
                start_new_session=True,
            )
            stdin_f.close()
            stdout_f.close()
            stderr_f.close()
        except Exception as e:
            return {
                "provider": "codex",
                "role": role,
                "ok": False,
                "error": f"{type(e).__name__}: {e}",
                "title": title,
                "prompt_path": str(prompt_path),
                "output_path": str(output_path),
            }
        metadata = self._codex_worker_metadata(
            run,
            role,
            prompt_path,
            output_path,
            stderr_path,
            last_path,
            title,
            prompt_text,
            pid=proc.pid,
        )
        _agent_registry_upsert(
            "codex",
            native_id,
            project,
            pid=proc.pid,
            state="running",
            metadata=metadata,
        )
        threading.Thread(
            target=self._orchestration_watch_codex_worker,
            args=(orchestration_id, native_id, proc, output_path, last_path, stderr_path),
            daemon=True,
        ).start()
        return {
            "provider": "codex",
            "role": role,
            "ok": True,
            "error": None,
            "title": title,
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "stderr_path": str(stderr_path),
            "last_message_path": str(last_path),
            "session_id": _qualified_session_id("codex", native_id),
            "native_id": native_id,
            "pid": proc.pid,
        }

    def _orchestration_prompt(self, run: dict, role: str, worker_index: int | None = None) -> str:
        stop_conditions = ", ".join(run.get("stop_conditions") or [])
        handoff_path = run.get("handoff_path")
        common = f"""You are part of a bounded Pairling orchestration launched from Pairling.

Orchestration id: {run['id']}
Role: {role}
Project: {run['project']}
Mode: {run['mode']}
Autonomy: {run['autonomy']}
Permission profile: {run['permission_profile']}
Max wall time: {run['max_minutes']} minutes
Stop conditions: {stop_conditions}
Source handoff file: {handoff_path or 'none'}

Objective:
{run['objective']}

Safety rules:
- Stay inside the stated project unless the task explicitly requires reading the handoff file.
- Do not spawn extra agents or background work beyond this role.
- Do not use bypass permissions unless already configured by the user outside this orchestration.
- Prefer evidence, file paths, and concrete commands over broad claims.
- Finish with a concise status block: outcome, changed files, tests run, open risks, next action.
"""
        if role == "planner":
            return common + """
Planner/Judge instructions:
- Inspect the repository and handoff context.
- Produce a bounded plan suitable for the worker count.
- Identify disjoint write scopes and verification gates.
- If the orchestration is review_first, do not make project edits; produce the plan and ask for review.
- If workers are already running, judge their output and summarize convergence.
"""
        return common + f"""
Worker instructions:
- You are worker {worker_index or 1} of {run['max_workers']}.
- Take one bounded slice of the objective and execute it end to end.
- Avoid overlapping files with other workers where possible.
- Run the most relevant local verification available within the time budget.
- Stop cleanly when the task is done, blocked, or a stop condition is reached.
"""

    def _orchestration_launch_background(self, run_id: str) -> None:
        run = self._orchestration_read(run_id)
        if not run:
            return
        try:
            run_dir = ORCHESTRATIONS_DIR / run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            provider = run.get("provider") or "claude"
            provider_mode = run.get("provider_mode") or provider

            def launch_for_role(role_name: str):
                if provider_mode == "all":
                    return "claude" if role_name == "planner" else ("codex" if role_name.endswith("-1") else "claude")
                return provider

            def launch_role_for(provider_name: str):
                return self._orchestration_launch_codex_role if provider_name == "codex" else self._orchestration_launch_role

            planner_prompt = run_dir / "planner.md"
            planner_prompt.write_text(self._orchestration_prompt(run, "planner"))
            planner_provider = launch_for_role("planner")
            run["launches"].append(launch_role_for(planner_provider)(run, "planner", planner_prompt, "planner"))
            run["launches"][-1]["provider"] = planner_provider
            for idx in range(1, int(run.get("max_workers") or 1) + 1):
                worker_prompt = run_dir / f"worker-{idx}.md"
                role = f"worker-{idx}"
                worker_prompt.write_text(self._orchestration_prompt(run, "worker", idx))
                role_provider = launch_for_role(role)
                run["launches"].append(launch_role_for(role_provider)(run, role, worker_prompt, f"worker {idx}"))
                run["launches"][-1]["provider"] = role_provider

            failed = [l for l in run["launches"] if not l.get("ok")]
            if failed:
                run["status"] = "launch_error"
                self._orchestration_event(run, "error", "One or more roles failed to launch", "; ".join((f.get("error") or "unknown") for f in failed)[:500])
            else:
                run["status"] = "running"
                surface = "mixed provider role(s)" if provider_mode == "all" else ("Codex exec job(s)" if provider == "codex" else "Terminal role(s)")
                self._orchestration_event(run, "launched", "Planner and workers launched", f"{len(run['launches'])} {surface} opened.")
        except Exception as e:
            run["status"] = "launch_error"
            self._orchestration_event(run, "error", "Orchestration launcher crashed", f"{type(e).__name__}: {e}")
        self._orchestration_write(run)

    def _orchestration_find_sessions(self, run: dict, rows: list[dict] | None = None) -> list[dict]:
        started = float(run.get("created_at") or 0)
        run_project_real = os.path.realpath(run.get("project") or "")
        provider = run.get("provider") or "claude"
        if provider == "codex":
            matches: list[dict] = []
            now_epoch = int(_time.time())
            for launch in run.get("launches") or []:
                native_id = launch.get("native_id")
                session_id = launch.get("session_id")
                if not native_id and isinstance(session_id, str):
                    _, native_id = _parse_agent_session_ref(session_id)
                if not native_id:
                    continue
                reg = _agent_registry_get("codex", native_id) or {}
                metadata = self._registry_metadata(reg) if reg else {}
                pid = int((reg or {}).get("pid") or launch.get("pid") or 0)
                process_alive = bool(pid and _process_alive(pid))
                closed_at = reg.get("closed_at")
                heartbeat = int(reg.get("last_heartbeat") or reg.get("started_at") or run.get("updated_at") or run.get("created_at") or 0)
                idle_seconds = max(0, now_epoch - heartbeat) if heartbeat else None
                if pid and not process_alive and not closed_at:
                    _agent_registry_mark_closed("codex", native_id)
                    closed_at = int(_time.time())
                is_active = bool(process_alive and not closed_at)
                state = metadata.get("state")
                if is_active:
                    state = state or "running"
                elif metadata.get("exit_code") == 0:
                    state = "idle"
                else:
                    state = state or "terminated"
                matches.append({
                    "provider": "codex",
                    "session_id": _qualified_session_id("codex", native_id),
                    "native_id": native_id,
                    "role": launch.get("role") or metadata.get("role"),
                    "title": launch.get("title") or metadata.get("title"),
                    "state": state,
                    "tool": metadata.get("tool"),
                    "last_heartbeat": heartbeat,
                    "started_at": int(reg.get("started_at") or run.get("created_at") or 0),
                    "closed_at": int(closed_at) if closed_at else None,
                    "is_active": is_active,
                    "idle_seconds": idle_seconds,
                    "process_alive": process_alive,
                    "context_pct": None,
                    "effort": metadata.get("effort"),
                    "model": metadata.get("model"),
                })
            return matches
        if rows is None:
            rows = self._collect_session_rows(since_min=60 * 24, live_only=False, limit=300, include_first_prompt=False)
        matches = []
        now_epoch = int(_time.time())
        launch_ids: set[str] = set()
        for launch in run.get("launches") or []:
            sid = launch.get("session_id")
            if isinstance(sid, str) and sid:
                launch_ids.add(sid)
                launch_ids.add(_claude_native_session_id(sid) or sid)
        for row in rows:
            if launch_ids:
                if row.get("id") not in launch_ids and _qualified_session_id("claude", row.get("id") or "") not in launch_ids:
                    continue
            else:
                if os.path.realpath(row.get("project") or "") != run_project_real:
                    continue
                if float(row.get("started_at") or 0) + 120 < started:
                    continue
            title = None
            role = None
            for launch in run.get("launches") or []:
                launch_sid = launch.get("session_id")
                launch_native = _claude_native_session_id(launch_sid) if isinstance(launch_sid, str) else ""
                if launch_sid == row.get("id") or launch_sid == _qualified_session_id("claude", row.get("id") or "") or launch_native == row.get("id"):
                    role = launch.get("role")
                    title = launch.get("title")
                    break
            heartbeat = int(row.get("last_heartbeat") or 0)
            idle_seconds = max(0, now_epoch - heartbeat) if heartbeat else None
            closed_at = row.get("closed_at")
            pid = row.get("claude_pid")
            process_alive = None
            if pid:
                try:
                    os.kill(int(pid), 0)
                    process_alive = True
                except ProcessLookupError:
                    process_alive = False
                    self._mark_session_closed(row.get("id") or "")
                    closed_at = closed_at or now_epoch
                except PermissionError:
                    process_alive = True
                except OSError:
                    process_alive = False
            is_active = bool(
                heartbeat and
                idle_seconds is not None and
                idle_seconds < self._ORCHESTRATION_ACTIVE_HEARTBEAT_SECONDS and
                not closed_at and
                process_alive is not False
            )
            matches.append({
                "provider": "claude",
                "session_id": _qualified_session_id("claude", row.get("id") or ""),
                "native_id": row.get("id"),
                "role": role,
                "title": title,
                "state": row.get("state") if is_active or not closed_at else "terminated",
                "tool": row.get("tool"),
                "last_heartbeat": row.get("last_heartbeat"),
                "started_at": row.get("started_at"),
                "closed_at": closed_at,
                "is_active": is_active,
                "idle_seconds": idle_seconds,
                "process_alive": process_alive,
                "context_pct": row.get("context_pct"),
                "effort": row.get("effort"),
                "model": row.get("model"),
            })
        if (run.get("provider_mode") or run.get("provider")) == "all":
            for launch in run.get("launches") or []:
                if launch.get("provider") != "codex":
                    continue
                native_id = launch.get("native_id")
                session_id = launch.get("session_id")
                if not native_id and isinstance(session_id, str):
                    _, native_id = _parse_agent_session_ref(session_id)
                if not native_id:
                    continue
                reg = _agent_registry_get("codex", native_id) or {}
                metadata = self._registry_metadata(reg) if reg else {}
                pid = int((reg or {}).get("pid") or launch.get("pid") or 0)
                process_alive = bool(pid and _process_alive(pid))
                closed_at = reg.get("closed_at")
                heartbeat = int(reg.get("last_heartbeat") or reg.get("started_at") or run.get("updated_at") or run.get("created_at") or 0)
                idle_seconds = max(0, now_epoch - heartbeat) if heartbeat else None
                if pid and not process_alive and not closed_at:
                    _agent_registry_mark_closed("codex", native_id)
                    closed_at = int(_time.time())
                is_active = bool(process_alive and not closed_at)
                state = metadata.get("state")
                if is_active:
                    state = state or "running"
                elif metadata.get("exit_code") == 0:
                    state = "idle"
                else:
                    state = state or "terminated"
                matches.append({
                    "provider": "codex",
                    "session_id": _qualified_session_id("codex", native_id),
                    "native_id": native_id,
                    "role": launch.get("role") or metadata.get("role"),
                    "title": launch.get("title") or metadata.get("title"),
                    "state": state,
                    "tool": metadata.get("tool"),
                    "last_heartbeat": heartbeat,
                    "started_at": int(reg.get("started_at") or run.get("created_at") or 0),
                    "closed_at": int(closed_at) if closed_at else None,
                    "is_active": is_active,
                    "idle_seconds": idle_seconds,
                    "process_alive": process_alive,
                    "context_pct": None,
                    "effort": metadata.get("effort"),
                    "model": metadata.get("model"),
                })
        return matches

    def _orchestration_refresh(self, run: dict, rows: list[dict] | None = None) -> dict:
        sessions = self._orchestration_find_sessions(run, rows=rows)
        known = {s["session_id"] for s in sessions if s.get("session_id")}
        run["sessions"] = sessions
        for launch in run.get("launches") or []:
            if launch.get("session_id"):
                continue
            for s in sessions:
                if s.get("role") is None:
                    launch["session_id"] = s.get("session_id")
                    s["role"] = launch.get("role")
                    s["title"] = launch.get("title")
                    break
        now = _time.time()
        active = [s for s in sessions if s.get("is_active")]
        idle = [s for s in sessions if s.get("session_id") and not s.get("is_active")]
        run["active_session_count"] = len(active)
        run["idle_session_count"] = len(idle)
        run["registered_session_count"] = len(known)
        run["stop_status"] = self._orchestration_stop_status(run, sessions)
        if run.get("status") == "running":
            created = float(run.get("created_at") or now)
            max_minutes = int(run.get("max_minutes") or 30)
            max_context = max([float(s.get("context_pct") or 0.0) for s in sessions] or [0.0])
            if "budget_hit" in (run.get("stop_conditions") or []) and max_context >= 95:
                run["status"] = "budget_hit"
                run["finished_reason"] = "budget_hit"
                run["finished_at"] = now
                run["status_detail"] = f"Highest observed context pressure reached {max_context:.0f}%."
                self._orchestration_event(run, "stop", "Budget hit", run["status_detail"])
            elif _time.time() - created > max_minutes * 60:
                run["status"] = "time_limit"
                run["finished_reason"] = "time_limit"
                run["finished_at"] = now
                run["status_detail"] = f"{max_minutes} minute cap elapsed."
                self._orchestration_event(run, "stop", "Time limit reached", f"{max_minutes} minute cap elapsed.")
            elif not active and known and now - created > 60:
                run["status"] = "quiet"
                run["finished_reason"] = "quiet"
                run["finished_at"] = now
                run["status_detail"] = "All registered orchestration sessions are idle; no explicit stop condition fired."
                self._orchestration_event(run, "status", "Orchestration finished quietly", run["status_detail"])
        elif run.get("status") in {"quiet", "time_limit", "budget_hit", "stopped"} and not run.get("status_detail"):
            run["finished_reason"] = run.get("finished_reason") or run.get("status")
            run["status_detail"] = self._orchestration_status_detail(run.get("status"), run)
            run["finished_at"] = run.get("finished_at") or run.get("updated_at") or now
        run["stop_status"] = self._orchestration_stop_status(run, sessions)
        return run

    def _orchestration_status_detail(self, status: str, run: dict) -> str:
        if status == "quiet":
            return "All registered orchestration sessions are idle; no explicit stop condition fired."
        if status == "time_limit":
            return f"{int(run.get('max_minutes') or 30)} minute cap elapsed."
        if status == "budget_hit":
            return "An orchestration session crossed the configured context budget threshold."
        if status == "stopped":
            return "Stopped manually from the phone."
        return ""

    def _orchestration_stop_status(self, run: dict, sessions: list[dict]) -> list[dict]:
        status = run.get("status")
        finished_reason = run.get("finished_reason") or status
        max_context = max([float(s.get("context_pct") or 0.0) for s in sessions] or [0.0])
        labels = {
            "first_findings": "First findings",
            "tests_pass": "Tests pass",
            "budget_hit": "Budget hit",
            "time_limit": "Time limit",
            "manual_stop": "Manual stop",
        }
        details = {
            "first_findings": "Armed only; workers must report findings in their final status.",
            "tests_pass": "Armed only; test success is shown in worker output.",
            "budget_hit": f"Highest observed context pressure: {max_context:.0f}%.",
            "time_limit": f"Cap: {int(run.get('max_minutes') or 30)}m.",
            "manual_stop": "Triggered when active orchestration sessions are stopped from the phone.",
        }
        items = []
        armed = set(run.get("stop_conditions") or [])
        if finished_reason == "quiet" or status == "quiet":
            items.append({
                "id": "quiet",
                "label": "Idle / complete",
                "state": "reached",
                "detail": "All registered orchestration sessions are idle. No configured stop condition was triggered.",
            })
        for condition in ["first_findings", "tests_pass", "budget_hit", "time_limit", "manual_stop"]:
            if condition not in armed and condition != "manual_stop":
                continue
            state = "armed"
            if condition == finished_reason or (condition == "manual_stop" and status == "stopped"):
                state = "reached"
            elif status in {"quiet", "time_limit", "budget_hit", "stopped", "launch_error"}:
                state = "not_reached"
            items.append({
                "id": condition,
                "label": labels[condition],
                "state": state,
                "detail": details[condition],
            })
        return items

    def _handle_orchestrations_create(self, q):
        try:
            payload = json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "body must be JSON")
            return
        project = (payload.get("project") or "").strip()
        project_error = self._orchestration_validate_project(project)
        if project_error:
            self.send_error(400, project_error)
            return
        objective = (payload.get("objective") or "").strip()
        if not objective:
            self.send_error(400, "objective required")
            return
        mode = payload.get("mode") or "research"
        autonomy = payload.get("autonomy") or "review_first"
        permission_profile = payload.get("permission_profile") or "default"
        provider_mode = (payload.get("provider") or "claude").lower()
        if provider_mode == "mixed":
            provider_mode = "all"
        if not _valid_provider_filter(provider_mode):
            _send_unknown_provider(self, provider_mode)
            return
        if provider_mode == "all":
            provider = None
        elif provider_mode in AGENT_PROVIDERS:
            provider = provider_mode
        else:
            _send_unsupported_provider(self, provider_mode, "orchestration_launch")
            return
        if mode not in self._ORCHESTRATION_MODES:
            self.send_error(400, "invalid orchestration mode")
            return
        if autonomy not in self._ORCHESTRATION_AUTONOMY:
            self.send_error(400, "invalid autonomy")
            return
        if permission_profile not in self._ORCHESTRATION_PERMISSIONS:
            self.send_error(400, "invalid permission profile")
            return
        try:
            max_workers = max(1, min(int(payload.get("max_workers") or 1), 4))
            max_minutes = max(5, min(int(payload.get("max_minutes") or 30), 180))
        except (TypeError, ValueError):
            self.send_error(400, "max_workers/max_minutes must be integers")
            return
        stop_conditions = payload.get("stop_conditions") or ["first_findings", "time_limit"]
        stop_conditions = [s for s in stop_conditions if s in self._ORCHESTRATION_STOP_CONDITIONS]
        if not stop_conditions:
            stop_conditions = ["time_limit"]
        if autonomy != "review_first" and self._orchestration_project_dirty(project) and not payload.get("allow_dirty_project"):
            self.send_error(409, "project has uncommitted changes; set allow_dirty_project to continue")
            return

        health = _health_payload(full_power=True)
        coordinator_meta, preflight_meta = _orchestration_preflight_from_health(health)
        if isinstance(payload.get("coordinator"), dict):
            coordinator_meta.update(payload["coordinator"])
        if isinstance(payload.get("preflight"), dict):
            preflight_meta.update(payload["preflight"])
        placement_meta = payload.get("placement") if isinstance(payload.get("placement"), dict) else None
        if not placement_meta:
            placement_meta = {
                "planner": "local",
                "workers": [
                    {"index": idx + 1, "target": "local"}
                    for idx in range(max_workers)
                ],
            }

        allowed, retry = _inject_rate_check("__orchestrations__")
        if not allowed:
            self.send_response(429)
            self.send_header("Retry-After", str(retry))
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"ok": False, "error": f"rate limited, retry in {retry}s"}).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        orchestration_id = "orchestration-" + secrets.token_hex(6)
        orchestration_dir = ORCHESTRATIONS_DIR / orchestration_id
        orchestration_dir.mkdir(parents=True, exist_ok=True)
        handoff_text = payload.get("handoff_text") or ""
        handoff_title = (payload.get("handoff_title") or "Manual Orchestration brief").strip()[:120]
        handoff_path = None
        if handoff_text.strip():
            handoff = {
                "schemaVersion": 1,
                "source": payload.get("handoff_source") or "Pairling",
                "title": handoff_title,
                "generatedAt": _time.time(),
                "workflowHint": mode,
                "suggestedPrompt": objective,
                "transcriptText": handoff_text,
            }
            handoff_path = HANDOFFS_DIR / f"{orchestration_id}.json"
            handoff_path.write_text(json.dumps(handoff, indent=2, sort_keys=True))

        run = {
            "id": orchestration_id,
            "status": "launching",
            "created_at": _time.time(),
            "updated_at": _time.time(),
            "provider": provider,
            "provider_mode": provider_mode,
            "providers": ["claude", "codex"] if provider_mode == "all" else [provider_mode],
            "project": project,
            "objective": objective[:8000],
            "mode": mode,
            "autonomy": autonomy,
            "permission_profile": permission_profile,
            "max_workers": max_workers,
            "max_minutes": max_minutes,
            "stop_conditions": stop_conditions,
            "handoff_title": handoff_title,
            "handoff_path": str(handoff_path) if handoff_path else None,
            "coordinator": coordinator_meta,
            "preflight": preflight_meta,
            "placement": placement_meta,
            "launches": [],
            "sessions": [],
            "events": [],
        }
        self._orchestration_event(run, "created", "Orchestration created", f"{provider_mode} · {mode} · {max_workers} worker(s) · {max_minutes}m")
        self._orchestration_event(run, "preflight", "Coordinator preflight captured", f"{preflight_meta.get('posture', 'unknown')} · {preflight_meta.get('route', 'unknown')} · {preflight_meta.get('summary') or 'no summary'}")
        self._orchestration_write(run)
        threading.Thread(target=self._orchestration_launch_background, args=(orchestration_id,), daemon=True).start()
        self._send_json({"ok": True, "orchestration": run, "ts": _time.time()})

    def _handle_orchestrations_list(self, q):
        try:
            limit = max(1, min(int(q.get("limit", ["30"])[0]), 500))
        except ValueError:
            limit = 30
        orchestrations = []
        rows = self._collect_session_rows(since_min=60 * 24, live_only=False, limit=500, include_first_prompt=False)
        for path in sorted(ORCHESTRATIONS_DIR.glob("orchestration-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]:
            try:
                run = json.loads(path.read_text())
                orchestrations.append(self._orchestration_refresh(run, rows=rows))
            except Exception:
                continue
        self._send_json({"count": len(orchestrations), "items": orchestrations, "ts": _time.time()})

    def _handle_orchestration_detail(self, orchestration_id: str):
        run = self._orchestration_read(orchestration_id)
        if not run:
            self.send_error(404, "orchestration not found")
            return
        run = self._orchestration_refresh(run)
        self._orchestration_write(run)
        self._send_json({"ok": True, "orchestration": run, "ts": _time.time()})

    def _handle_orchestration_stream(self, orchestration_id: str):
        run = self._orchestration_read(orchestration_id)
        if not run:
            self.send_error(404, "orchestration not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        last_hash = None
        deadline = _time.time() + 10 * 60
        while _time.time() < deadline:
            run = self._orchestration_read(orchestration_id)
            if not run:
                break
            run = self._orchestration_refresh(run)
            self._orchestration_write(run)
            payload_core = {"ok": True, "orchestration": run}
            payload = {**payload_core, "ts": _time.time()}
            digest = hashlib.sha256(json.dumps(payload_core, sort_keys=True).encode()).hexdigest()
            if digest != last_hash:
                try:
                    self.wfile.write(b"event: snapshot\ndata: " + json.dumps(payload).encode() + b"\n\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
                last_hash = digest
            _time.sleep(2.0)
        try:
            self.wfile.write(b"event: done\ndata: {}\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return

    def _handle_orchestration_stop(self, orchestration_id: str):
        run = self._orchestration_read(orchestration_id)
        if not run:
            self.send_error(404, "orchestration not found")
            return
        run = self._orchestration_refresh(run)
        client_action_id = str(self.headers.get("X-Pairling-Action-Id") or "").strip()
        device_id = getattr(getattr(self, "pairling_auth", None), "device_id", None)
        receipt_session_id = f"orchestration:{orchestration_id}:stop"
        body_hash = _receipt_body_hash({"orchestration_id": orchestration_id, "action": "stop_active_sessions"})
        deduped_receipt, conflict = _receipt_duplicate_response(device_id, receipt_session_id, client_action_id, body_hash)
        if conflict:
            _store_action_receipt(
                device_id,
                receipt_session_id,
                client_action_id,
                body_hash,
                conflict["receipt"],
                action_kind="orchestration_stop",
                audit_action={"type": "idempotency_conflict"},
            )
            self._send_json({
                "ok": False,
                "stopped": [],
                "errors": [conflict["error"]["message"]],
                "receipt": conflict["receipt"],
                "orchestration": run,
            }, status=409)
            return
        if deduped_receipt:
            self._send_json({
                "ok": deduped_receipt.get("state") == "applied",
                "stopped": [],
                "errors": [],
                "receipt": deduped_receipt,
                "orchestration": run,
            })
            return
        stopped = []
        errors = []
        for s in run.get("sessions") or []:
            sid = s.get("session_id")
            if not sid:
                continue
            if not s.get("is_active"):
                continue
            session_provider = s.get("provider") or run.get("provider") or "claude"
            if session_provider == "codex":
                _, native_id = _parse_agent_session_ref(sid)
                reg = _agent_registry_get("codex", native_id) if native_id else None
                pid = int((reg or {}).get("pid") or 0)
            else:
                pid = self._lookup_claude_pid(sid)
            if not pid:
                continue
            try:
                os.kill(pid, signal.SIGTERM)
                stopped.append(sid)
                if session_provider == "codex":
                    _, native_id = _parse_agent_session_ref(sid)
                    if native_id:
                        _agent_registry_mark_closed("codex", native_id)
            except Exception as e:
                errors.append(f"{sid}: {type(e).__name__}: {e}")
        stopped_set = set(stopped)
        for launch in run.get("launches") or []:
            launch_provider = launch.get("provider") or run.get("provider") or "claude"
            if launch_provider != "claude":
                continue
            sid = launch.get("session_id") or f"claude:{launch.get('role') or launch.get('title') or 'launch'}"
            if sid in stopped_set:
                continue
            pid = int(launch.get("pid") or 0)
            tty = launch.get("tty") or ""
            if (not pid or not _process_alive(pid)) and tty:
                pid = _pid_for_tty_command(tty, "claude")
            if not pid or not _process_alive(pid):
                continue
            try:
                os.kill(pid, signal.SIGTERM)
                stopped.append(sid)
                stopped_set.add(sid)
            except Exception as e:
                errors.append(f"{sid}: {type(e).__name__}: {e}")
        if stopped:
            run["status"] = "stopped"
            run["finished_reason"] = "manual_stop"
            run["finished_at"] = _time.time()
            run["status_detail"] = f"Stopped {len(stopped)} active session(s). Idle sessions were left untouched."
            self._orchestration_event(run, "stop", "Active orchestration sessions stopped from phone", run["status_detail"])
        else:
            run["status"] = run.get("status") or "quiet"
            run["status_detail"] = "No active orchestration sessions were running; idle sessions were left untouched."
            self._orchestration_event(run, "status", "No active orchestration sessions to stop", run["status_detail"])
        self._orchestration_write(run)
        receipt = _make_action_receipt(
            client_action_id=client_action_id or None,
            state="applied" if not errors else "failed",
            phases=_receipt_phases(validated=True, applied=not errors, pty_written=False),
            backend="process_signal",
        )
        _store_action_receipt(
            device_id,
            receipt_session_id,
            client_action_id or None,
            body_hash,
            receipt,
            action_kind="orchestration_stop",
            audit_action={"type": "stop_orchestration", "stopped_count": len(stopped), "error_count": len(errors)},
        )
        self._send_json({"ok": not errors, "stopped": stopped, "errors": errors, "receipt": receipt, "orchestration": run})

    # ----- /workstate-feed: read-only substrate feed for native context surfaces -----
    def _handle_workstate_feed(self, q):
        run = q.get("run", [""])[0].strip()
        if not run:
            self.send_error(400, "run is required")
            return
        since = q.get("since", [WORKSTATE_FEED_DEFAULT_SINCE])[0]
        try:
            limit = int(q.get("limit", ["50"])[0])
        except ValueError:
            self.send_error(400, "limit must be an integer")
            return
        event_types: list[str] = []
        for raw_value in q.get("type", []):
            event_types.extend(part.strip() for part in raw_value.split(",") if part.strip())
        try:
            payload = _fetch_workstate_feed(run, since=since, limit=limit, event_types=event_types)
        except WorkstateFeedError as exc:
            self.send_error(502, str(exc))
            return
        self._send_json(payload)

    # ----- /model-status: read-only substrate model arbiter status -----
    def _handle_model_status(self, q):
        run = q.get("run", [""])[0].strip()
        if not run:
            self.send_error(400, "run is required")
            return
        since = q.get("since", [MODEL_STATUS_DEFAULT_SINCE])[0]
        try:
            limit = int(q.get("limit", ["50"])[0])
        except ValueError:
            self.send_error(400, "limit must be an integer")
            return
        try:
            payload = _fetch_model_status(run, since=since, limit=limit)
        except ModelStatusError as exc:
            self.send_error(502, str(exc))
            return
        self._send_json(payload)

    # ----- /substrate-status and /substrate-feed: read-only operational substrate -----
    def _handle_substrate_status(self, q):
        run = q.get("run", [""])[0].strip()
        if not run:
            self.send_error(400, "run is required")
            return
        since = q.get("since", [SUBSTRATE_STATUS_DEFAULT_SINCE])[0]
        try:
            limit = int(q.get("limit", ["50"])[0])
        except ValueError:
            self.send_error(400, "limit must be an integer")
            return
        try:
            payload = _fetch_substrate_status(run, since=since, limit=limit)
        except SubstrateStatusError as exc:
            self.send_error(502, str(exc))
            return
        self._send_json(payload)

    def _handle_substrate_feed(self, q):
        run = q.get("run", [""])[0].strip()
        if not run:
            self.send_error(400, "run is required")
            return
        since = q.get("since", [SUBSTRATE_STATUS_DEFAULT_SINCE])[0]
        try:
            limit = int(q.get("limit", ["50"])[0])
        except ValueError:
            self.send_error(400, "limit must be an integer")
            return
        event_types: list[str] = []
        for raw_value in q.get("type", []):
            event_types.extend(part.strip() for part in raw_value.split(",") if part.strip())
        try:
            payload = _fetch_substrate_feed(run, since=since, limit=limit, event_types=event_types)
        except SubstrateStatusError as exc:
            self.send_error(502, str(exc))
            return
        self._send_json(payload)

    def _worker_stats_payload(self, since_min: int = 60) -> dict:
        return _worker_stats_payload(since_min)

    # ----- /worker-stats: count automated worker sessions -----
    def _handle_worker_stats(self, q):
        try:
            since_min = int(q.get("since_min", ["60"])[0])
            payload = self._worker_stats_payload(since_min)
        except ValueError:
            self.send_error(400, "since_min must be an integer")
            return
        except RuntimeError as exc:
            self.send_error(502, str(exc))
            return

        body = json.dumps(payload).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /worker-kill: SIGTERM workers, audit log -----
    def _handle_worker_kill(self, q):
        try:
            payload = json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "body must be JSON")
            return

        target_ids: list[str] = payload.get("session_ids") or []
        kill_filter = payload.get("filter")
        provider_filter = str(payload.get("provider") or "claude").lower()
        if not _valid_provider_filter(provider_filter):
            _send_unknown_provider(self, provider_filter)
            return
        client_action_id = str(self.headers.get("X-Pairling-Action-Id") or "").strip()
        device_id = getattr(getattr(self, "pairling_auth", None), "device_id", None)
        receipt_session_id = f"worker-kill:{provider_filter}:{kill_filter or 'ids'}"
        body_hash = _receipt_body_hash({
            "session_ids": sorted(str(item) for item in target_ids),
            "filter": kill_filter,
            "provider": provider_filter,
        })
        deduped_receipt, conflict = _receipt_duplicate_response(device_id, receipt_session_id, client_action_id, body_hash)
        if conflict:
            _store_action_receipt(
                device_id,
                receipt_session_id,
                client_action_id,
                body_hash,
                conflict["receipt"],
                action_kind="worker_kill",
                audit_action={"type": "idempotency_conflict"},
            )
            self._send_json({
                "killed": [],
                "skipped": [],
                "errors": [conflict["error"]["message"]],
                "receipt": conflict["receipt"],
                "deduped": True,
            }, status=409)
            return
        if deduped_receipt:
            self._send_json({
                "killed": [],
                "skipped": [],
                "errors": [],
                "receipt": deduped_receipt,
                "deduped": True,
            })
            return

        # If filter=stale, populate target_ids from /worker-stats logic
        if kill_filter == "stale" and not target_ids:
            if provider_filter in ("all", "claude"):
                worker_patterns = [
                    "biotech-labs/synth-synth-",
                    "biotech-labs/crohns-research/scripts",
                    "biotech-research-",
                ]
                for sid in _claude_sessions_backend().stale_session_ids():
                    sid = sid.strip()
                    if not sid:
                        continue
                    project = self._lookup_pg_project(sid) or ""
                    if any(p in project for p in worker_patterns):
                        target_ids.append(sid)
            if provider_filter in ("all", "codex"):
                for worker in self._collect_codex_workers(since_min=60 * 24):
                    if worker.get("stale"):
                        target_ids.append(worker.get("id") or "")

        # SAFETY: never kill anything with a recent heartbeat (<5 min)
        # SAFETY: refuse mass kills > 100 to avoid runaway
        if len(target_ids) > 100:
            self.send_error(400, f"too many ids ({len(target_ids)}); max 100")
            return

        killed: list[str] = []
        skipped: list[str] = []
        errors: list[str] = []

        for raw_sid in target_ids:
            provider, sid = _parse_agent_session_ref(str(raw_sid or ""))
            if provider_filter != "all" and provider != provider_filter:
                skipped.append(f"{raw_sid} (provider mismatch)")
                continue

            if provider == "codex":
                if not _safe_agent_native_id(sid):
                    skipped.append(str(raw_sid))
                    continue
                reg = _agent_registry_get("codex", sid)
                if not reg:
                    skipped.append(f"{raw_sid} (no Codex registry row)")
                    continue
                idle_seconds = int(max(0, _time.time() - float(reg.get("last_heartbeat") or 0)))
                if idle_seconds < 300:
                    skipped.append(f"{raw_sid} (active <5min)")
                    continue
                pid = int(reg.get("pid") or 0)
                tty = reg.get("terminal_tty") or ""
                if (not pid or not _process_alive(pid)) and tty:
                    pid = _pid_for_tty_command(tty, "codex")
                    if pid:
                        _agent_registry_upsert("codex", sid, reg.get("project") or str(HOME), pid=pid, terminal_tty=tty)
                if not pid or not _process_alive(pid):
                    _agent_registry_mark_closed("codex", sid)
                    killed.append(f"{raw_sid} (no live process; registry closed)")
                    continue
                try:
                    os.kill(pid, signal.SIGTERM)
                    _agent_registry_mark_closed("codex", sid)
                    killed.append(str(raw_sid))
                except (ProcessLookupError, PermissionError, OSError) as e:
                    errors.append(f"{raw_sid}: {type(e).__name__}: {str(e)[:100]}")
                continue

            if provider != "claude" or not _safe_session_id(sid):
                skipped.append(str(raw_sid))
                continue

            # Verify the session is actually idle
            idle_seconds = _claude_sessions_backend().idle_seconds(sid)

            if idle_seconds < 300:
                skipped.append(f"{sid} (active <5min)")
                continue

            # Resolve session id -> PID via process name
            # Continuous-claude PIDs run with the session id in the command line
            pkill_proc = subprocess.run(
                ["pkill", "-TERM", "-f", sid],
                capture_output=True, text=True, timeout=3,
            )
            if pkill_proc.returncode == 0:
                killed.append(str(raw_sid))
            elif pkill_proc.returncode == 1:
                # No process found — the session row exists but the process is gone
                killed.append(f"{raw_sid} (no live process; row remains)")
            else:
                errors.append(f"{raw_sid}: {pkill_proc.stderr.strip()[:100]}")

        # Audit log
        audit_dir = HOME / ".claude" / "audit"
        audit_dir.mkdir(parents=True, exist_ok=True)
        audit_file = audit_dir / "worker-kills.jsonl"
        with open(audit_file, "a") as f:
            f.write(json.dumps({
                "timestamp": _time.time(),
                "killer": "phone-companion",
                "filter": kill_filter,
                "provider": provider_filter,
                "target_count": len(target_ids),
                "killed": killed,
                "skipped": skipped,
                "errors": errors,
            }) + "\n")

        receipt = _make_action_receipt(
            client_action_id=client_action_id or None,
            state="applied" if not errors else "failed",
            phases=_receipt_phases(validated=True, applied=not errors, pty_written=False),
            backend="worker_kill",
        )
        _store_action_receipt(
            device_id,
            receipt_session_id,
            client_action_id or None,
            body_hash,
            receipt,
            action_kind="worker_kill",
            audit_action={
                "type": "worker_kill",
                "filter": kill_filter,
                "provider": provider_filter,
                "target_count": len(target_ids),
                "killed_count": len(killed),
                "skipped_count": len(skipped),
                "error_count": len(errors),
            },
        )
        body = json.dumps({
            "killed": killed,
            "skipped": skipped,
            "errors": errors,
            "receipt": receipt,
            "deduped": False,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_spawn_session_broker(self, project: str, provider: str, launch_context: dict | None = None,
                                     native_id_override: str | None = None) -> None:
        if PTY_BROKER is None:
            self._send_json({"ok": False, "error": "PTY broker unavailable"}, status=503)
            return

        capture_id = secrets.token_hex(12)
        native_id = native_id_override or ("pending-" + secrets.token_hex(8))
        broker_session_id = _qualified_session_id(provider, native_id)
        broker_env = None
        if launch_context is not None:
            generated = launch_context.get("generated") if isinstance(launch_context.get("generated"), dict) else {}
            broker_env = generated.get("env") if isinstance(generated.get("env"), dict) else None
            command = _aperture_cli_command_for_context(launch_context, project) if _aperture_cli_command_for_context else ""
        elif provider == "codex":
            # Inherit the user's OWN host posture (~/.codex/config.toml:
            # approval_policy + sandbox_mode). Pairling imposes NO permission flag
            # — we never twist the user's workspace to manufacture cards. The
            # approval card is opportunistic: it surfaces ONLY if the user's own
            # config prompts (codex approval detection is the Phase 5 screen-scrape,
            # which touches no config).
            command = (
                f"exec codex "
                f"-C {shlex.quote(project)} --add-dir {shlex.quote(project)}"
            )
        else:
            # Inherit the user's OWN host posture (~/.claude/settings.json). No
            # imposed permission flag. The PermissionRequest producer hook is
            # injected PER-SPAWN via --settings (phone sessions only) so the user's
            # global settings stay untouched; the hook is an observer, never a mode.
            command = f"exec claude --settings {shlex.quote(str(SPAWN_SETTINGS_PATH))}"
        if not command:
            self._send_json({"ok": False, "error": "Aperture CLI launch command unavailable"}, status=503)
            return

        if provider == "claude":
            # Headless PTY: nobody can answer the folder-trust prompt, so
            # accept it up front (the phone user's spawn IS the trust gesture).
            _pretrust_claude_project(project)

        ok = False
        reason = None
        session = None
        try:
            session = PTY_BROKER.spawn(
                session_id=broker_session_id,
                provider=provider,
                native_id=native_id,
                project=project,
                command=command,
                rows=30,
                columns=120,
                # Mark phone-spawned sessions so the global PermissionRequest hook
                # self-enables ONLY here (no-op for the user's own claude sessions).
                env={**(broker_env or {}), "PAIRLING_PHONE_SESSION": "1",
                     "PAIRLING_BROKER_SESSION_ID": broker_session_id},
            )
            ok = True
        except Exception as e:
            reason = f"{type(e).__name__}: {e}"

        if ok and session is not None:
            session_tty = _broker_slave_tty(session)
            session_log = _broker_raw_log_path(session)
            session_pid = _broker_pid(session)
            if session_tty and session_log:
                _write_terminal_capture_mapping(
                    session_tty,
                    session_log,
                    provider=provider,
                    project=project,
                    capture_id=capture_id,
                )
            if launch_context is not None:
                launch_meta = {
                    "spawned_by": "pairling",
                    "launch_strategy": "aperture_cli",
                    "client_id": provider,
                    "aperture_endpoint_url": (launch_context.get("endpoint") or {}).get("url"),
                    "aperture_endpoint_mode": (launch_context.get("endpoint") or {}).get("mode"),
                    "aperture_provider_id": (launch_context.get("provider") or {}).get("id"),
                    "aperture_backend_id": (launch_context.get("backend") or {}).get("id"),
                    "aperture_model": (launch_context.get("model") or {}).get("fqn") if launch_context.get("model") else None,
                    "aperture_cli_version": launch_context.get("aperture_cli_version"),
                    "danger_mode": bool((launch_context.get("danger_mode") or {}).get("enabled")),
                    "generated_env_redacted": (launch_context.get("generated") or {}).get("env_redacted"),
                    "generated_args": (launch_context.get("generated") or {}).get("args"),
                    "config_writes": (launch_context.get("generated") or {}).get("config_writes"),
                }
            else:
                launch_meta = {
                    "spawned_by": "pairling",
                    "launch_strategy": "direct_pairling",
                    "danger_mode": True,
                }
            _agent_registry_upsert(
                provider,
                native_id,
                project,
                pid=session_pid,
                terminal_tty=session_tty,
                metadata={
                    "terminal_log": str(session_log) if session_log else None,
                    "capture_backend": "pty_broker",
                    "capture_id": capture_id,
                    "broker_id": broker_session_id,
                    "broker_socket": str(PTY_BROKER_SOCKET),
                    **launch_meta,
                },
            )
            if provider == "codex":
                _write_agent_turn_state("codex", native_id, "idle", event="spawn")

        try:
            audit_path = HOME / ".claude" / "audit" / "spawn-sessions.jsonl"
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(audit_path, "a") as f:
                f.write(json.dumps({
                    "ts": _time.time(),
                    "project": project,
                    "provider": provider,
                    "native_id": native_id,
                    "tty": _broker_slave_tty(session) if session else "",
                    "pid": _broker_pid(session) if session else 0,
                    "terminal_log": str(_broker_raw_log_path(session)) if session and _broker_raw_log_path(session) else None,
                    "capture_backend": "pty_broker",
                    "broker_id": broker_session_id,
                    "broker_socket": str(PTY_BROKER_SOCKET),
                    "ok": ok,
                    "reason": reason,
                    "via": "pairling" if launch_context is not None else "phone-companion",
                    "launch_strategy": "aperture_cli" if launch_context is not None else "direct_pairling",
                    "aperture": {
                        "endpoint": (launch_context or {}).get("endpoint"),
                        "provider": (launch_context or {}).get("provider"),
                        "backend": (launch_context or {}).get("backend"),
                        "model": (launch_context or {}).get("model"),
                        "danger_mode": (launch_context or {}).get("danger_mode"),
                    } if launch_context is not None else None,
                }) + "\n")
        except Exception:
            pass

        if not ok or session is None:
            self._send_json({"ok": False, "error": reason or "PTY broker spawn failed"}, status=502)
            return

        self._send_json({
            "ok": True,
            "project": project,
            "provider": provider,
            "native_id": native_id,
            "session_id": broker_session_id,
            "tty": _broker_slave_tty(session),
            "pid": _broker_pid(session),
            "terminal_log": str(_broker_raw_log_path(session)) if _broker_raw_log_path(session) else None,
            "capture_backend": "pty_broker",
            "terminal_source": "broker_vt",
            "broker_id": broker_session_id,
            "broker_socket": str(PTY_BROKER_SOCKET),
            "launch_strategy": "aperture_cli" if launch_context is not None else "direct_pairling",
            "aperture": {
                "endpoint": (launch_context or {}).get("endpoint"),
                "provider": (launch_context or {}).get("provider"),
                "backend": (launch_context or {}).get("backend"),
                "model": (launch_context or {}).get("model"),
                "danger_mode": (launch_context or {}).get("danger_mode"),
                "generated": {"env_redacted": ((launch_context or {}).get("generated") or {}).get("env_redacted")},
            } if launch_context is not None else None,
            "attach_command": f"pairling attach {broker_session_id}",
        })

    # ----- /spawn-session: open a new broker-owned agent CLI session -----
    def _handle_onestream_handoff(self, q):
        """OneStream -> Pairling handoff ingestion (W1b).

        POST: validate (fail-closed, mirroring the iOS PairlingHandoffReader),
              compose the steering draft, and store the handoff under
              HANDOFFS_DIR using the schemaVersion-1 record shape. Returns the
              composed draft so the caller can confirm what a session would
              ingest.
        GET:  list pending (unconsumed) OneStream handoffs.

        Auth: POST requires session:spawn, GET requires sessions:read (see
        _required_scopes_for_request). Additive route — does not spawn directly
        (OneStream has no Mac project path); a consumer composes/spawns later.
        """
        if self.command == "GET":
            items = []
            try:
                paths = sorted(HANDOFFS_DIR.glob("onestream-*.json"))
            except OSError:
                paths = []
            for p in paths:
                try:
                    rec = json.loads(p.read_text())
                except (OSError, json.JSONDecodeError):
                    continue
                if not isinstance(rec, dict) or rec.get("consumed"):
                    continue
                items.append({
                    "handoff_id": rec.get("handoff_id") or p.stem,
                    "source": rec.get("source") or "OneStream",
                    "generatedAt": rec.get("generatedAt"),
                    "suggestedPrompt": rec.get("suggestedPrompt") or "",
                    "transcriptText": rec.get("transcriptText") or "",
                    "composeDraft": rec.get("composeDraft") or "",
                    "workflowHint": rec.get("workflowHint"),
                })
            self._send_json({"ok": True, "handoffs": items})
            return

        # POST — store a new handoff.
        try:
            payload = json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "body must be JSON")
            return
        if not isinstance(payload, dict):
            self.send_error(400, "body must be JSON object")
            return

        # Fail-closed validation — mirror iOS PairlingHandoffReader.decode().
        schema_version = payload.get("schemaVersion")
        if schema_version != 1:
            self._send_json(
                {"ok": False, "error": f"unsupported schemaVersion {schema_version!r} (expected 1)"},
                status=400,
            )
            return
        transcript_text = str(payload.get("transcriptText") or "").strip()
        if not transcript_text:
            self._send_json({"ok": False, "error": "handoff contains no transcript"}, status=400)
            return

        suggested_prompt = str(payload.get("suggestedPrompt") or "").strip()
        # composeDraft mirrors PairlingHandoffReader.composeDraft(from:).
        compose_draft = (
            f"{suggested_prompt}\n\n---\n{transcript_text}" if suggested_prompt else transcript_text
        )

        handoff_id = "onestream-" + secrets.token_hex(6)
        record = {
            "schemaVersion": 1,
            "handoff_id": handoff_id,
            "source": str(payload.get("source") or "OneStream")[:64],
            "generatedAt": payload.get("generatedAt"),
            "receivedAt": _time.time(),
            "workflowHint": payload.get("workflowHint"),
            "suggestedPrompt": suggested_prompt,
            "transcriptText": transcript_text,
            "segments": payload.get("segments") if isinstance(payload.get("segments"), list) else [],
            "composeDraft": compose_draft,
            "consumed": False,
        }
        try:
            (HANDOFFS_DIR / f"{handoff_id}.json").write_text(
                json.dumps(record, indent=2, sort_keys=True)
            )
        except OSError as exc:
            self._send_json({"ok": False, "error": f"could not store handoff: {exc}"}, status=500)
            return

        self._send_json({"ok": True, "handoff_id": handoff_id, "composeDraft": compose_draft})

    def _handle_spawn_session(self, q):
        """Spawn a new Claude/Codex session. Pairling-owned PTYs are the
        default path; Terminal.app can attach as a client via `pairling attach`.
        The legacy Terminal.app-owner path remains behind
        PAIRLING_SPAWN_BACKEND=terminal_app for rollback/debugging.

        Security:
        - Project path must be absolute and exist on disk.
        - Path must be under one of the allowed prefixes (no arbitrary fs).
        - Global rate limit reuses _inject_rate_check with a special key.
        - Every spawn (success or failure) appended to ~/.claude/audit/.
        """
        payload: dict = {}
        headers = getattr(self, "headers", {}) or {}
        header_content_type = headers.get("Content-Type") if hasattr(headers, "get") else ""
        content_type = (header_content_type or "").lower()
        if "application/json" in content_type:
            try:
                payload = json.loads(self._read_body() or b"{}")
                if not isinstance(payload, dict):
                    self.send_error(400, "body must be JSON object")
                    return
            except json.JSONDecodeError:
                self.send_error(400, "body must be JSON")
                return
        aperture_payload = payload.get("aperture") if isinstance(payload.get("aperture"), dict) else {}
        launch_strategy = str(payload.get("launch_strategy") or q.get("launch_strategy", ["direct_pairling"])[0] or "direct_pairling").strip().lower()
        project = str(payload.get("project") or q.get("project", [""])[0]).strip()
        provider = str(payload.get("provider") or aperture_payload.get("client_id") or q.get("provider", ["claude"])[0]).lower()
        if launch_strategy not in {"direct_pairling", "aperture_cli"}:
            self.send_error(400, "launch_strategy must be direct_pairling or aperture_cli")
            return
        if not _valid_provider_filter(provider, allow_all=False):
            _send_unknown_provider(self, provider)
            return
        if provider not in AGENT_PROVIDERS:
            _send_unsupported_provider(self, provider, "spawn")
            return
        if not project:
            self.send_error(400, "project required")
            return
        if not project.startswith("/"):
            self.send_error(400, "project must be absolute path")
            return
        if ".." in project.split("/"):
            self.send_error(400, "path traversal rejected")
            return

        home = str(HOME)
        # Allow $HOME itself plus anything under it; plus shared tmp dirs.
        # Phone-side path validation already blocks `..`, so we trust
        # canonical-prefix membership.
        if project == home:
            pass  # exactly $HOME — fine
        elif project.startswith(home + "/"):
            pass  # any subdir of $HOME — fine
        elif project.startswith("/private/tmp/") or project.startswith("/tmp/"):
            pass
        else:
            self.send_error(403, f"project path must be under $HOME or /tmp: {project}")
            return

        if not os.path.isdir(project):
            self.send_error(404, f"directory not found: {project}")
            return

        # Rate limit: single global key. _inject_rate_check enforces 30/min
        # AND a 1-second cooldown between consecutive calls. For spawn, that's
        # plenty — actual launch takes ~2-3s anyway.
        allowed, retry = _inject_rate_check("__spawn_session__")
        if not allowed:
            self.send_response(429)
            self.send_header("Retry-After", str(retry))
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"ok": False, "error": f"rate limited, retry in {retry}s"}).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        aperture_launch_context = None
        if launch_strategy == "aperture_cli":
            if _aperture_cli_validate_launch_context is None:
                self._send_json({
                    "ok": False,
                    "error": {
                        "code": "aperture_cli_integration_unavailable",
                        "message": "Aperture CLI launch integration is unavailable",
                    },
                }, status=503)
                return
            try:
                preview_native_id = "pending-" + secrets.token_hex(8)
                aperture_launch_context = _aperture_cli_validate_launch_context(
                    aperture_payload,
                    preview_native_id,
                    home=HOME,
                    env=os.environ,
                    write_config=True,
                )
            except Exception as exc:
                self._send_json({
                    "ok": False,
                    "error": {
                        "code": "invalid_aperture_launch_context",
                        "message": str(exc),
                    },
                }, status=400)
                return

        if os.environ.get("PAIRLING_SPAWN_BACKEND", "broker").lower() != "terminal_app":
            self._handle_spawn_session_broker(
                project,
                provider,
                launch_context=aperture_launch_context,
                native_id_override=preview_native_id if launch_strategy == "aperture_cli" else None,
            )
            return

        if launch_strategy == "aperture_cli":
            self._send_json({
                "ok": False,
                "error": "Aperture CLI launch strategy requires the Pairling PTY broker backend",
            }, status=400)
            return

        capture_id = ""
        capture_log_path: Path | None = None
        if provider == "codex":
            capture_id = secrets.token_hex(12)
            capture_log_path = TERMINAL_CAPTURE_DIR / f"codex-{capture_id}.log"
            inner = (
                f"cd {shlex.quote(project)} && "
                f"exec codex "
                f"-C {shlex.quote(project)} --add-dir {shlex.quote(project)}"
            )
            shell_cmd = _terminal_script_command(capture_log_path, inner, interactive_shell=True)
        else:
            capture_id = secrets.token_hex(12)
            capture_log_path = TERMINAL_CAPTURE_DIR / f"claude-{capture_id}.log"
            inner = f"cd {shlex.quote(project)} && claude"
            shell_cmd = _terminal_script_command(capture_log_path, inner)
        as_escaped_cmd = _as_escape(shell_cmd)

        # Set Terminal's custom title to the project basename so /inject-now's
        # window-title matcher can find this window later. Terminal's auto-
        # title shows running command + cwd (e.g. "project — claude") which
        # rarely contains the project name; explicit custom title fixes that.
        basename = os.path.basename(project.rstrip("/")) or provider
        title = f"{provider}:{basename}" if provider == "codex" else basename
        as_escaped_title = _as_escape(title)

        script = f'''
        tell application "Terminal"
            activate
            set newTab to do script "{as_escaped_cmd}"
            set custom title of newTab to "{as_escaped_title}"
            delay 0.5
            return "ok\t" & (tty of newTab)
        end tell
        '''
        result = _run_osascript(script)
        tty = ""
        if result.get("ok"):
            stdout = result.get("stdout") or ""
            parts = stdout.split("\t")
            if len(parts) >= 2:
                tty = parts[1].strip()
        pid = 0
        native_id = None
        if provider == "codex" and result.get("ok"):
            native_id = "pending-" + secrets.token_hex(8)
            _time.sleep(0.75)
            pid = _pid_for_tty_command(tty, "codex") if tty else 0
            if tty and capture_log_path is not None:
                _write_terminal_capture_mapping(
                    tty,
                    capture_log_path,
                    provider="codex",
                    project=project,
                    capture_id=capture_id,
                )
            _agent_registry_upsert(
                "codex",
                native_id,
                project,
                pid=pid,
                terminal_tty=tty,
                metadata={
                    "spawned_by": "phone-companion",
                    "terminal_log": str(capture_log_path) if capture_log_path else None,
                    "capture_backend": "script" if capture_log_path else None,
                    "capture_id": capture_id or None,
                },
            )
            _write_agent_turn_state("codex", native_id, "idle", event="spawn")
        elif provider == "claude" and result.get("ok") and tty and capture_log_path is not None:
            _write_terminal_capture_mapping(
                tty,
                capture_log_path,
                provider="claude",
                project=project,
                capture_id=capture_id,
            )

        # Audit log — append-only, JSONL, includes failures.
        try:
            audit_path = HOME / ".claude" / "audit" / "spawn-sessions.jsonl"
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(audit_path, "a") as f:
                f.write(json.dumps({
                    "ts": _time.time(),
                    "project": project,
                    "provider": provider,
                    "native_id": native_id,
                    "tty": tty,
                    "pid": pid,
                    "terminal_log": str(capture_log_path) if capture_log_path else None,
                    "capture_backend": "script" if capture_log_path else None,
                    "ok": result.get("ok", False),
                    "reason": result.get("reason"),
                    "via": "phone-companion",
                }) + "\n")
        except Exception:
            pass  # audit failure shouldn't break the spawn

        if not result.get("ok"):
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"ok": False, "error": result.get("reason", "unknown")}).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = json.dumps({
            "ok": True,
            "project": project,
            "provider": provider,
            "native_id": native_id,
            "tty": tty,
            "pid": pid,
            "terminal_log": str(capture_log_path) if capture_log_path else None,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _session_context_for_workflow(self, raw_session: str) -> dict | None:
        provider, native_id = _parse_agent_session_ref(raw_session)
        if provider == "codex":
            path = _resolve_codex_transcript(native_id)
            project = _codex_project_for_session(native_id)
            if not path or not project:
                return None
            history = _codex_history_map()
            first_prompt = _codex_first_prompt(path, native_id, history) or ""
            assistant_chunks: list[str] = []
            try:
                lines = _tail_lines(path, max_lines=400, max_bytes=TRANSCRIPT_TAIL_SCAN_BYTES)
                for raw in lines:
                    for row in _normalize_codex_line(raw, native_id):
                        msg = row.get("message") or {}
                        if msg.get("role") != "assistant":
                            continue
                        for block in msg.get("content") or []:
                            if isinstance(block, dict) and block.get("type") == "text":
                                text = block.get("text")
                                if isinstance(text, str) and text.strip():
                                    assistant_chunks.append(text.strip())
            except OSError:
                pass
            return {
                "provider": provider,
                "native_id": native_id,
                "session_id": _qualified_session_id(provider, native_id),
                "project": project,
                "first_prompt": first_prompt,
                "last_assistant": "\n\n".join(assistant_chunks[-2:])[-6000:],
                "transcript_path": str(path),
            }

        native_id = _claude_native_session_id(raw_session)
        if not native_id:
            return None
        path = self._resolve_transcript(native_id)
        project = self._lookup_pg_project(native_id) or (_peek_cwd_from_transcript(path) if path else "")
        if not path or not project:
            return None
        return {
            "provider": "claude",
            "native_id": native_id,
            "session_id": _qualified_session_id("claude", native_id),
            "project": project,
            "first_prompt": _peek_first_prompt(path) or "",
            "last_assistant": _peek_last_assistant_text(path, max_chars=6000) or "",
            "transcript_path": str(path),
        }

    def _launch_provider_prompt(self, provider: str, project: str, prompt_path: Path,
                                title_suffix: str, metadata: dict) -> dict:
        shell_safe_path = project.replace("'", "'\\''")
        shell_safe_prompt = str(prompt_path).replace("'", "'\\''")
        if provider == "codex":
            shell_cmd = (
                f"cd '{shell_safe_path}' && "
                f"codex -C '{shell_safe_path}' --add-dir '{shell_safe_path}' \"$(cat '{shell_safe_prompt}')\""
            )
        else:
            shell_cmd = (
                f"cd '{shell_safe_path}' && "
                f"claude \"$(cat '{shell_safe_prompt}')\""
            )
        script = f'''
        tell application "Terminal"
            activate
            set newTab to do script "{_as_escape(shell_cmd)}"
            set custom title of newTab to "{_as_escape(provider + ':' + title_suffix)}"
            delay 0.5
            return "ok\t" & (tty of newTab)
        end tell
        '''
        result = _run_osascript(script)
        tty = ""
        if result.get("ok"):
            parts = (result.get("stdout") or "").split("\t")
            if len(parts) >= 2:
                tty = parts[1].strip()
        pid = 0
        native_id = None
        if provider == "codex" and result.get("ok"):
            native_id = "pending-" + secrets.token_hex(8)
            _time.sleep(0.75)
            pid = _pid_for_tty_command(tty, "codex") if tty else 0
            reg_meta = dict(metadata)
            reg_meta.update({"spawned_by": "phone-companion", "prompt_path": str(prompt_path)})
            _agent_registry_upsert("codex", native_id, project, pid=pid, terminal_tty=tty, metadata=reg_meta)
            _write_agent_turn_state("codex", native_id, "thinking", event="cross_provider")
        return {
            "provider": provider,
            "ok": bool(result.get("ok")),
            "native_id": native_id,
            "session_id": _qualified_session_id(provider, native_id) if native_id else None,
            "tty": tty,
            "pid": pid,
            "error": None if result.get("ok") else result.get("reason", "unknown"),
        }

    def _handle_cross_provider_action(self, q):
        try:
            payload = json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "body must be JSON")
            return
        kind = str(payload.get("kind") or "").lower()
        if kind not in {"compare", "handoff", "arbitrate"}:
            self.send_error(400, "kind must be compare, handoff, or arbitrate")
            return
        source_ref = str(payload.get("source_session") or "").strip()
        source = self._session_context_for_workflow(source_ref)
        if not source:
            self.send_error(404, "source session context not found")
            return
        other = "codex" if source["provider"] == "claude" else "claude"
        target_provider = str(payload.get("target_provider") or other).lower()
        if not _valid_provider_filter(target_provider, allow_all=False):
            _send_unknown_provider(self, target_provider)
            return
        if target_provider not in AGENT_PROVIDERS:
            _send_unsupported_provider(self, target_provider, "cross_provider_action")
            return
        workflow_id = "xprov-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
        artifact_path = CROSS_PROVIDER_DIR / f"{workflow_id}.json"
        prompt_base = source.get("first_prompt") or source.get("last_assistant") or "Continue the work from the linked session."
        transcript_context = (source.get("last_assistant") or "")[-6000:]
        providers: list[str]
        if kind == "compare":
            providers = ["claude", "codex"]
            task_prompt = (
                "Run the same task independently for cross-provider comparison.\n\n"
                f"Original request:\n{prompt_base}\n\n"
                "Return concise findings, assumptions, and the next concrete implementation step."
            )
        elif kind == "handoff":
            providers = [target_provider]
            task_prompt = (
                f"Continue this {source['provider']} session in {target_provider}.\n\n"
                f"Source session: {source['session_id']}\n"
                f"Original request:\n{prompt_base}\n\n"
                f"Recent assistant context:\n{transcript_context}\n\n"
                "Pick up the work directly. Preserve intent, call out uncertainty, and continue in this project."
            )
        else:
            providers = [target_provider]
            task_prompt = (
                f"Review and arbitrate the recent output from {source['session_id']}.\n\n"
                f"Original request:\n{prompt_base}\n\n"
                f"Recent assistant output:\n{transcript_context}\n\n"
                "Find correctness issues, missing tests, weak assumptions, and the strongest alternative approach."
            )
        prompt_path = CROSS_PROVIDER_DIR / f"{workflow_id}.prompt.txt"
        prompt_path.write_text(task_prompt)
        artifact = {
            "id": workflow_id,
            "kind": kind,
            "source": source,
            "target_provider": target_provider,
            "prompt_path": str(prompt_path),
            "artifact_path": str(artifact_path),
            "created_at": _time.time(),
            "launches": [],
        }
        launches = []
        for provider in providers:
            launches.append(self._launch_provider_prompt(
                provider,
                source["project"],
                prompt_path,
                kind,
                {"kind": "cross_provider", "workflow_id": workflow_id, "workflow_kind": kind},
            ))
        artifact["launches"] = launches
        artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True))
        body = json.dumps({"ok": True, **artifact}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_resume_session_broker(self, *, provider: str, project: str, native_id: str, prompt: str) -> None:
        if PTY_BROKER is None:
            self._send_json({"ok": False, "error": "PTY broker unavailable"}, status=503)
            return
        broker_session_id = _qualified_session_id(provider, native_id)
        existing = PTY_BROKER.get(broker_session_id)
        if existing is not None:
            self._send_json({
                "ok": True,
                "provider": provider,
                "native_id": native_id,
                "session_id": broker_session_id,
                "project": project,
                "tty": _broker_slave_tty(existing),
                "pid": _broker_pid(existing),
                "terminal_log": str(_broker_raw_log_path(existing)) if _broker_raw_log_path(existing) else None,
                "capture_backend": "pty_broker",
                "terminal_source": "broker_vt",
                "broker_id": _broker_session_id(existing),
                "broker_socket": str(PTY_BROKER_SOCKET),
                "attach_command": f"pairling attach {broker_session_id}",
            })
            return

        command = (
            f"exec codex resume "
            f"-C {shlex.quote(project)} --add-dir {shlex.quote(project)} "
            f"{shlex.quote(native_id)}"
        )
        if prompt:
            command += f" {shlex.quote(prompt)}"
        session = None
        ok = False
        reason = None
        try:
            session = PTY_BROKER.spawn(
                session_id=broker_session_id,
                provider=provider,
                native_id=native_id,
                project=project,
                command=command,
                rows=30,
                columns=120,
                env={"PAIRLING_PHONE_SESSION": "1",
                     "PAIRLING_BROKER_SESSION_ID": broker_session_id},
            )
            ok = True
        except Exception as e:
            reason = f"{type(e).__name__}: {e}"

        if ok and session is not None:
            capture_id = secrets.token_hex(12)
            session_tty = _broker_slave_tty(session)
            session_log = _broker_raw_log_path(session)
            session_pid = _broker_pid(session)
            if session_tty and session_log:
                _write_terminal_capture_mapping(
                    session_tty,
                    session_log,
                    provider=provider,
                    project=project,
                    capture_id=capture_id,
                )
            _agent_registry_upsert(
                "codex",
                native_id,
                project,
                pid=session_pid,
                terminal_tty=session_tty,
                metadata={
                    "spawned_by": "phone-companion",
                    "resume_target": native_id,
                    "terminal_log": str(session_log) if session_log else None,
                    "capture_backend": "pty_broker",
                    "capture_id": capture_id,
                    "terminal_source": "broker_vt",
                    "broker_id": broker_session_id,
                    "broker_socket": str(PTY_BROKER_SOCKET),
                },
            )
            _write_agent_turn_state("codex", native_id, "idle", event="resume")

        try:
            audit_path = HOME / ".claude" / "audit" / "resume-sessions.jsonl"
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(audit_path, "a") as f:
                f.write(json.dumps({
                    "ts": _time.time(),
                    "provider": provider,
                    "project": project,
                    "native_id": native_id,
                    "tty": _broker_slave_tty(session) if session else "",
                    "pid": _broker_pid(session) if session else 0,
                    "terminal_log": str(_broker_raw_log_path(session)) if session and _broker_raw_log_path(session) else None,
                    "capture_backend": "pty_broker",
                    "terminal_source": "broker_vt",
                    "broker_id": broker_session_id,
                    "broker_socket": str(PTY_BROKER_SOCKET),
                    "ok": ok,
                    "reason": reason,
                    "via": "phone-companion",
                }) + "\n")
        except Exception:
            pass

        if not ok or session is None:
            self._send_json({"ok": False, "error": reason or "PTY broker resume failed"}, status=502)
            return

        self._send_json({
            "ok": True,
            "provider": provider,
            "native_id": native_id,
            "session_id": broker_session_id,
            "project": project,
            "tty": _broker_slave_tty(session),
            "pid": _broker_pid(session),
            "terminal_log": str(_broker_raw_log_path(session)) if _broker_raw_log_path(session) else None,
            "capture_backend": "pty_broker",
            "terminal_source": "broker_vt",
            "broker_id": broker_session_id,
            "broker_socket": str(PTY_BROKER_SOCKET),
            "attach_command": f"pairling attach {broker_session_id}",
        })

    def _handle_resume_session(self, q):
        """Provider-aware app resume. Claude keeps its existing in-terminal
        `/resume <id>` path; Codex resume launches a resumed interactive TUI
        in a fresh Terminal tab and records control metadata for the same
        provider-qualified session id.
        """
        try:
            payload = json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "body must be JSON")
            return
        provider = str(payload.get("provider") or "claude").lower()
        project = str(payload.get("project") or "").strip()
        native_id = str(payload.get("session_id") or payload.get("native_id") or "").strip()
        prompt = str(payload.get("prompt") or "").strip()
        if not _valid_provider_filter(provider, allow_all=False):
            _send_unknown_provider(self, provider)
            return
        if provider not in AGENT_PROVIDERS:
            _send_unsupported_provider(self, provider, "resume")
            return
        if provider != "codex":
            self.send_error(400, "Claude resume uses /send-text with /resume <id>")
            return
        if not project or not project.startswith("/") or not os.path.isdir(project):
            self.send_error(400, "valid absolute project required")
            return
        if ".." in project.split("/"):
            self.send_error(400, "path traversal rejected")
            return
        home = str(HOME)
        if not (project == home or project.startswith(home + "/") or project.startswith("/private/tmp/") or project.startswith("/tmp/")):
            self.send_error(403, f"project path must be under $HOME or /tmp: {project}")
            return
        if not _safe_agent_native_id(native_id):
            self.send_error(400, "bad Codex session id")
            return
        if not _resolve_codex_transcript(native_id):
            self.send_error(404, "no Codex transcript for session")
            return
        if len(prompt) > 4000:
            self.send_error(413, "prompt too long")
            return

        allowed, retry = _inject_rate_check("__resume_session__")
        if not allowed:
            self.send_response(429)
            self.send_header("Retry-After", str(retry))
            body = json.dumps({"ok": False, "error": f"rate limited, retry in {retry}s"}).encode()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if os.environ.get("PAIRLING_RESUME_BACKEND", "broker").lower() != "terminal_app":
            self._handle_resume_session_broker(provider=provider, project=project, native_id=native_id, prompt=prompt)
            return

        capture_id = secrets.token_hex(12)
        capture_log_path = TERMINAL_CAPTURE_DIR / f"codex-{capture_id}.log"
        inner = (
            f"cd {shlex.quote(project)} && "
            f"exec codex resume "
            f"-C {shlex.quote(project)} --add-dir {shlex.quote(project)} "
            f"{shlex.quote(native_id)}"
        )
        if prompt:
            inner += f" {shlex.quote(prompt)}"
        shell_cmd = _terminal_script_command(capture_log_path, inner, interactive_shell=True)
        as_escaped_cmd = _as_escape(shell_cmd)
        title = f"codex:{os.path.basename(project.rstrip('/')) or 'resume'}"
        script = f'''
        tell application "Terminal"
            activate
            set newTab to do script "{as_escaped_cmd}"
            set custom title of newTab to "{_as_escape(title)}"
            delay 0.5
            return "ok\t" & (tty of newTab)
        end tell
        '''
        result = _run_osascript(script)
        tty = ""
        if result.get("ok"):
            parts = (result.get("stdout") or "").split("\t")
            if len(parts) >= 2:
                tty = parts[1].strip()
        pid = 0
        if result.get("ok"):
            _time.sleep(0.75)
            pid = _pid_for_tty_command(tty, "codex") if tty else 0
            if tty:
                _write_terminal_capture_mapping(
                    tty,
                    capture_log_path,
                    provider="codex",
                    project=project,
                    capture_id=capture_id,
                )
            _agent_registry_upsert(
                "codex",
                native_id,
                project,
                pid=pid,
                terminal_tty=tty,
                metadata={
                    "spawned_by": "phone-companion",
                    "resume_target": native_id,
                    "terminal_log": str(capture_log_path),
                    "capture_backend": "script",
                    "capture_id": capture_id,
                },
            )
            _write_agent_turn_state("codex", native_id, "idle", event="resume")
        try:
            audit_path = HOME / ".claude" / "audit" / "resume-sessions.jsonl"
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(audit_path, "a") as f:
                f.write(json.dumps({
                    "ts": _time.time(),
                    "provider": provider,
                    "project": project,
                    "native_id": native_id,
                    "tty": tty,
                    "pid": pid,
                    "terminal_log": str(capture_log_path),
                    "capture_backend": "script",
                    "ok": result.get("ok", False),
                    "reason": result.get("reason"),
                    "via": "phone-companion",
                }) + "\n")
        except Exception:
            pass
        if not result.get("ok"):
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"ok": False, "error": result.get("reason", "unknown")}).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps({
            "ok": True,
            "provider": "codex",
            "native_id": native_id,
            "session_id": _qualified_session_id("codex", native_id),
            "project": project,
            "tty": tty,
            "pid": pid,
            "terminal_log": str(capture_log_path),
            "capture_backend": "script",
            "terminal_source": "terminal_app_contents",
            "attach_command": None,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text_to_codex_registry(self, native_id: str, text: str, receipt_context: dict | None = None) -> None:
        # Precondition: callers pass text through _sanitize_terminal_text_input.
        receipt_context = receipt_context or {}
        client_action_id = receipt_context.get("client_action_id")
        device_id = receipt_context.get("device_id")
        body_hash = receipt_context.get("body_hash") or _receipt_body_hash(text)
        receipt_session_id = receipt_context.get("session_id") or _qualified_session_id("codex", native_id)
        reg = _agent_registry_get("codex", native_id)
        if reg and reg.get("closed_at"):
            pid = int(reg.get("pid") or 0)
            if pid and _process_alive(pid):
                _agent_registry_update_control(
                    "codex",
                    native_id,
                    pid=pid,
                    terminal_tty=reg.get("terminal_tty") or "",
                    state="running",
                    reopen=True,
                )
                reg = _agent_registry_get("codex", native_id)
        if not reg or reg.get("closed_at"):
            reason = "no Codex control registry row for session"
            body = json.dumps({"ok": False, "error": reason, "reason": reason}).encode()
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        broker_found = self._broker_session_for(_qualified_session_id("codex", native_id))
        if broker_found and PTY_BROKER:
            broker_id, session = broker_found
            result = PTY_BROKER.send_text(broker_id, text)
            if result.get("ok"):
                _agent_registry_update_control(
                    "codex",
                    native_id,
                    pid=_broker_pid(session),
                    terminal_tty=_broker_slave_tty(session),
                    state="running",
                    reopen=True,
                )
                _write_agent_turn_state("codex", native_id, "thinking", started_at=_time.time(), event="send_text")
            source_offset_after = None
            if result.get("ok") and PTY_BROKER:
                tail = PTY_BROKER.raw_tail(broker_id, since=0)
                if tail:
                    source_offset_after = tail[1]
            receipt = _make_action_receipt(
                client_action_id=client_action_id,
                state="applied" if result.get("ok") else "failed",
                phases=_receipt_phases(validated=True, applied=bool(result.get("ok")), pty_written=bool(result.get("ok"))),
                backend="pty_broker",
                tty=_broker_slave_tty(session),
                pid=_broker_pid(session),
                source_offset_after=source_offset_after,
            )
            _store_action_receipt(device_id, receipt_session_id, client_action_id, body_hash, receipt, action_kind="send_text", audit_action={"type": "send_text", "chars": len(text)})
            body = json.dumps({
                "ok": bool(result.get("ok")),
                "tty": _broker_slave_tty(session),
                "pid": _broker_pid(session),
                "broker_id": _broker_session_id(session),
                "reason": result.get("reason"),
                "receipt": receipt,
            }).encode()
            self.send_response(200 if result.get("ok") else int(result.get("status") or 502))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        tty = reg.get("terminal_tty") or ""
        if not tty:
            reason = "no terminal_tty for Codex session"
            receipt = _make_action_receipt(
                client_action_id=client_action_id,
                state="rejected",
                phases=_receipt_phases(validated=False, applied=False, pty_written=False),
            )
            _store_action_receipt(device_id, receipt_session_id, client_action_id, body_hash, receipt, action_kind="send_text", audit_action={"type": "send_text", "chars": len(text)})
            body = json.dumps({"ok": False, "error": reason, "reason": reason, "receipt": receipt}).encode()
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if not re.match(r'^/dev/ttys[0-9]{3,}$', tty):
            self.send_error(500, f"invalid tty in registry: {tty[:40]}")
            return

        pid = int(reg.get("pid") or 0)
        if not pid or not _process_alive(pid):
            fresh_pid = _pid_for_tty_command(tty, "codex")
            if fresh_pid:
                pid = fresh_pid
                _agent_registry_update_control("codex", native_id, pid=pid, terminal_tty=tty, reopen=True)

        tty_candidates = _codex_terminal_tty_candidates({**reg, "pid": pid, "terminal_tty": tty}) or [tty]
        safe_ttys = "{" + ", ".join(f'"{_as_escape(candidate)}"' for candidate in tty_candidates) + "}"
        safe_text = _as_escape(text)
        is_slash = _is_direct_slash_invocation_text(text)
        if is_slash:
            payload_expr = f'"{safe_text}"'
        else:
            payload_expr = f'ESC & "[200~" & "{safe_text}" & ESC & "[201~"'
        script = f'''
        tell application "Terminal"
            set targetTab to missing value
            set usedTTY to ""
            set candidateTTYs to {safe_ttys}
            repeat with w in windows
                repeat with t in tabs of w
                    set tabTTY to tty of t
                    repeat with candidateTTY in candidateTTYs
                        if tabTTY is (candidateTTY as text) then
                            set targetTab to t
                            set usedTTY to (candidateTTY as text)
                            exit repeat
                        end if
                    end repeat
                    if targetTab is not missing value then exit repeat
                end repeat
                if targetTab is not missing value then exit repeat
            end repeat
            if targetTab is missing value then
                return "no_window"
            end if
            set ESC to (ASCII character 27)
            set wrapped to {payload_expr}
            do script wrapped in targetTab
        end tell
        return "ok" & tab & usedTTY
        '''
        result = _run_osascript(script)
        if (not result.get("ok")) and result.get("reason") == "no matching Terminal window":
            if pid and _process_alive(pid):
                body = json.dumps({
                    "ok": False,
                    "gone": False,
                    "tty": tty,
                    "tty_candidates": tty_candidates,
                    "reason": "Terminal tab not found, but Codex process is still alive.",
                }).encode()
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            _agent_registry_mark_closed("codex", native_id)
            body = json.dumps({
                "ok": False,
                "gone": True,
                "tty": tty,
                "reason": "Terminal tab is gone — Codex session marked closed.",
            }).encode()
            self.send_response(410)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if result.get("ok"):
            stdout = str(result.get("stdout") or "")
            used_tty = stdout.split("\t", 1)[1].strip() if stdout.startswith("ok\t") else tty
            tty = used_tty or tty
            _agent_registry_update_control("codex", native_id, pid=pid, terminal_tty=used_tty, state="running", reopen=True)
            _write_agent_turn_state("codex", native_id, "thinking", started_at=_time.time(), event="send_text")
        capture_path = _terminal_capture_for_tty(tty, reg.get("project")) if tty else None
        source_offset_after = None
        source_offset_reason = "no_capture_log"
        try:
            if capture_path and capture_path.is_file():
                source_offset_after = capture_path.stat().st_size
                source_offset_reason = None
        except OSError:
            pass
        receipt = _make_action_receipt(
            client_action_id=client_action_id,
            state="applied" if result.get("ok") else "failed",
            phases=_receipt_phases(validated=True, applied=bool(result.get("ok")), pty_written=bool(result.get("ok"))),
            backend="terminal_app",
            tty=tty,
            pid=pid,
            source_offset_after=source_offset_after,
            source_offset_reason=source_offset_reason,
        )
        _store_action_receipt(device_id, receipt_session_id, client_action_id, body_hash, receipt, action_kind="send_text", audit_action={"type": "send_text", "chars": len(text)})
        body = json.dumps({
            "ok": result.get("ok", False),
            "tty": tty,
            "pid": pid,
            "reason": result.get("reason"),
            "receipt": receipt,
        }).encode()
        self.send_response(200 if result.get("ok") else 502)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /send-text: write directly to a Terminal tab's pty (no keystrokes) -----
    def _handle_send_text(self, q):
        """Write text + Enter to the pty that the target session's claude is
        reading from. Uses Terminal.app's `do script ... in <tab>` Apple Event,
        which internally calls write() on the tab's pty master fd. Compared to
        the legacy /inject-now keystroke-synthesis path:
          - no Accessibility permission required
          - no System Events / focus shenanigans
          - target tab is identified by stable tty (e.g. /dev/ttys005), not
            by fragile window-title substring matching
          - works while Terminal.app is in the background, app is unfocused
          - text always lands in the right tab regardless of which tab is selected

        terminal_tty is populated for any session that has fired at least one
        hook event since the schema migration. Sessions started before then
        get backfilled on next hook fire (heartbeat opportunistically writes
        terminal_tty when it's NULL).
        """
        raw_session = q.get("session", [""])[0]
        provider, native_id = _parse_agent_session_ref(raw_session)
        if not native_id:
            self.send_error(400, "session required")
            return

        raw = self._read_body()
        text = raw.decode("utf-8", errors="replace")
        if not text:
            self.send_error(400, "empty body")
            return

        # Rate limit (same envelope as /inject-now)
        allowed, retry = _inject_rate_check(_qualified_session_id(provider, native_id))
        if not allowed:
            self.send_response(429)
            self.send_header("Retry-After", str(retry))
            body = json.dumps({"ok": False, "error": f"rate limited, retry in {retry}s"}).encode()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Embedded newlines are preserved for bracketed paste; client-supplied
        # terminal control bytes and paste delimiters are rejected centrally.
        text, sanitize_err = _sanitize_terminal_text_input(
            text,
            allow_newline=True,
            max_chars=TERMINAL_TEXT_MAX_CHARS,
        )
        if sanitize_err:
            self.send_error(int(sanitize_err["status"]), str(sanitize_err["message"]))
            return

        receipt_session_id = _qualified_session_id(provider, native_id)
        client_action_id = str(self.headers.get("X-Pairling-Action-Id") or "").strip()
        receipt_context = {
            "client_action_id": client_action_id or None,
            "device_id": getattr(getattr(self, "pairling_auth", None), "device_id", None),
            "session_id": receipt_session_id,
            "body_hash": _receipt_body_hash({"session_id": receipt_session_id, "text": text}),
        }
        deduped_receipt, conflict = _receipt_duplicate_response(
            receipt_context["device_id"],
            receipt_session_id,
            client_action_id,
            receipt_context["body_hash"],
        )
        if conflict:
            _store_action_receipt(
                receipt_context["device_id"],
                receipt_session_id,
                client_action_id,
                receipt_context["body_hash"],
                conflict["receipt"],
                action_kind="send_text",
                audit_action={"type": "send_text", "chars": len(text)},
                persist=False,
            )
            self._send_json(conflict, status=int(conflict["status"]))
            return
        if deduped_receipt:
            self._send_json({
                "ok": deduped_receipt.get("state") == "applied",
                "session_id": receipt_session_id,
                "receipt": deduped_receipt,
            })
            return

        global LAST_HUMAN_ACTIVITY_AT
        LAST_HUMAN_ACTIVITY_AT = _time.time()

        if provider == "codex":
            self._send_text_to_codex_registry(native_id, text, receipt_context)
            return

        session_id = _claude_native_session_id(raw_session)
        if not session_id:
            self.send_error(400, "session required")
            return

        tty = self._lookup_terminal_tty(session_id)
        if not tty:
            receipt = _make_action_receipt(
                client_action_id=receipt_context["client_action_id"],
                state="rejected",
                phases=_receipt_phases(validated=False, applied=False, pty_written=False),
            )
            _store_action_receipt(receipt_context["device_id"], receipt_session_id, receipt_context["client_action_id"], receipt_context["body_hash"], receipt, action_kind="send_text", audit_action={"type": "send_text", "chars": len(text)})
            body = json.dumps({
                "ok": False,
                "error": "no terminal_tty for session — wait for next hook fire to backfill, or re-spawn the session",
                "receipt": receipt,
            }).encode()
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Validate tty format before AppleScript embed.
        if not re.match(r'^/dev/ttys[0-9]{3,}$', tty):
            self.send_error(500, f"invalid tty in PG row: {tty[:40]}")
            return

        broker_found = self._broker_session_for(_qualified_session_id("claude", session_id))
        if broker_found and PTY_BROKER:
            broker_id, broker_session = broker_found
            result = PTY_BROKER.send_text(broker_id, text)
            source_offset_after = None
            if result.get("ok"):
                tail = PTY_BROKER.raw_tail(broker_id, since=0)
                if tail:
                    source_offset_after = tail[1]
            receipt = _make_action_receipt(
                client_action_id=receipt_context["client_action_id"],
                state="applied" if result.get("ok") else "failed",
                phases=_receipt_phases(validated=True, applied=bool(result.get("ok")), pty_written=bool(result.get("ok"))),
                backend="pty_broker",
                tty=_broker_slave_tty(broker_session),
                pid=_broker_pid(broker_session),
                source_offset_after=source_offset_after,
            )
            _store_action_receipt(receipt_context["device_id"], receipt_session_id, receipt_context["client_action_id"], receipt_context["body_hash"], receipt, action_kind="send_text", audit_action={"type": "send_text", "chars": len(text)})
            body = json.dumps({
                "ok": bool(result.get("ok")),
                "tty": _broker_slave_tty(broker_session),
                "pid": _broker_pid(broker_session),
                "broker_id": _broker_session_id(broker_session),
                "reason": result.get("reason"),
                "receipt": receipt,
            }).encode()
            self.send_response(200 if result.get("ok") else int(result.get("status") or 502))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Freshness gate: prompt_toolkit needs ~1-3s after claude bin start to
        # enable bracketed paste mode (DECSET 2004) and attach to the pty as
        # the input handler. Writing earlier lands bytes in cooked-mode buffer;
        # the bracketed-paste markers don't get interpreted, the trailing
        # newline may be eaten, and the user sees text appear without
        # submitting. Block until the row is at least MIN_AGE old.
        MIN_AGE_S = 3.0
        try:
            age = self._lookup_session_age_seconds(session_id)
            if age is not None and age < MIN_AGE_S:
                _time.sleep(MIN_AGE_S - age)
        except Exception:
            pass  # best effort — proceed even if the lookup fails

        safe_tty = _as_escape(tty)
        safe_text = _as_escape(text)
        # Slash commands (single-line, leading "/") bypass bracketed paste:
        # Claude Code's prompt-toolkit treats anything inside the paste markers
        # as literal input data and does NOT fire its slash-command handler, so
        # /model arrives as text in the buffer and Enter submits it as a plain
        # message rather than executing the command. Sending without the markers
        # makes the TUI treat each character as a typed keystroke, which is
        # what the slash dispatcher hooks into.
        #
        # Multi-line / non-slash text still gets bracketed paste so embedded
        # newlines stay together as a single paste event, not N submissions.
        is_slash = _is_direct_slash_invocation_text(text)
        if is_slash:
            payload_expr = f'"{safe_text}"'
        else:
            # Bracketed paste mode: ESC[200~ ... ESC[201~ around the payload.
            # Trailing newline auto-appended by `do script` lands AFTER the
            # paste-end marker and acts as a normal Enter, submitting the
            # prompt. ESC byte (0x1B) materialized via `(ASCII character 27)`
            # so we don't embed raw bytes in the f-string.
            payload_expr = f'ESC & "[200~" & "{safe_text}" & ESC & "[201~"'
        script = f'''
        tell application "Terminal"
            set targetTab to missing value
            repeat with w in windows
                repeat with t in tabs of w
                    if tty of t is "{safe_tty}" then
                        set targetTab to t
                        exit repeat
                    end if
                end repeat
                if targetTab is not missing value then exit repeat
            end repeat
            if targetTab is missing value then
                return "no_window"
            end if
            set ESC to (ASCII character 27)
            set wrapped to {payload_expr}
            do script wrapped in targetTab
            -- Double-tap return: when the paste lands while the TUI is busy
            -- re-rendering (mid-turn churn), the trailing newline from
            -- `do script` can be consumed without submitting — the text sits
            -- in the input box unsent. A delayed bare return is a no-op when
            -- the first submit landed (empty prompt) and a catch when it was
            -- eaten.
            delay 0.45
            do script "" in targetTab
        end tell
        return "ok"
        '''
        result = _run_osascript(script)

        # If no Terminal tab matches the recorded tty, the session is a zombie:
        # the user closed that tab. Auto-tombstone and tell the iPhone with a
        # 410 Gone so the bucket disappears on next /sessions?live=true poll.
        if (not result.get("ok")) and result.get("reason") == "no matching Terminal window":
            self._mark_session_closed(session_id)
            body = json.dumps({
                "ok": False,
                "gone": True,
                "tty": tty,
                "reason": "Terminal tab is gone — session marked closed.",
            }).encode()
            self.send_response(410)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        capture_path = _terminal_capture_for_tty(tty, self._lookup_pg_project(session_id)) if tty else None
        source_offset_after = None
        source_offset_reason = "no_capture_log"
        try:
            if capture_path and capture_path.is_file():
                source_offset_after = capture_path.stat().st_size
                source_offset_reason = None
        except OSError:
            pass
        receipt = _make_action_receipt(
            client_action_id=receipt_context["client_action_id"],
            state="applied" if result.get("ok") else "failed",
            phases=_receipt_phases(validated=True, applied=bool(result.get("ok")), pty_written=bool(result.get("ok"))),
            backend="terminal_app",
            tty=tty,
            source_offset_after=source_offset_after,
            source_offset_reason=source_offset_reason,
        )
        _store_action_receipt(receipt_context["device_id"], receipt_session_id, receipt_context["client_action_id"], receipt_context["body_hash"], receipt, action_kind="send_text", audit_action={"type": "send_text", "chars": len(text)})
        body = json.dumps({
            "ok": result.get("ok", False),
            "tty": tty,
            "reason": result.get("reason"),
            "receipt": receipt,
        }).encode()
        self.send_response(200 if result.get("ok") else 502)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _mark_session_closed(self, session_id: str) -> None:
        """Set closed_at for the given claude session id. Best effort —
        GC of dead sessions, called from /send-text and /sessions zombie scan."""
        session_id = _claude_native_session_id(session_id)
        if not session_id:
            return
        _claude_sessions_backend().tombstone_sessions([session_id])

    # ----- /sigint: send SIGINT to the session's claude process (cancel turn) -----
    def _handle_sigint(self, q):
        """Send SIGINT to claude_pid — cancels the current turn (analogous to
        the user pressing Ctrl+C in the terminal). Session stays alive.
        """
        self._send_signal_to_session(q, signal.SIGINT, "SIGINT")

    # ----- /sigterm: terminate the session's claude process -----
    def _handle_sigterm(self, q):
        """Send SIGTERM — the session ends. claude exits cleanly, the user
        gets their shell back. The SessionEnd hook fires, writing closed_at.
        """
        self._send_signal_to_session(q, signal.SIGTERM, "SIGTERM")

    def _send_signal_to_session(self, q, sig: int, sig_name: str) -> None:
        raw_session = q.get("session", [""])[0]
        provider, native_id = _parse_agent_session_ref(raw_session)
        if not native_id:
            self.send_error(400, "session required")
            return
        receipt_session_id = _qualified_session_id(provider, native_id)
        client_action_id = str(self.headers.get("X-Pairling-Action-Id") or "").strip()
        device_id = getattr(getattr(self, "pairling_auth", None), "device_id", None)
        body_hash = _receipt_body_hash({"session_id": receipt_session_id, "signal": sig_name})
        deduped_receipt, conflict = _receipt_duplicate_response(device_id, receipt_session_id, client_action_id, body_hash)
        if conflict:
            _store_action_receipt(
                device_id,
                receipt_session_id,
                client_action_id,
                body_hash,
                conflict["receipt"],
                action_kind="session_signal",
                audit_action={"type": "idempotency_conflict", "signal": sig_name},
            )
            self._send_json({
                "ok": False,
                "pid": None,
                "signal": sig_name,
                "error": conflict["error"]["message"],
                "receipt": conflict["receipt"],
            }, status=409)
            return
        if deduped_receipt:
            self._send_json({
                "ok": deduped_receipt.get("state") == "applied",
                "pid": deduped_receipt.get("pid"),
                "signal": sig_name,
                "error": None,
                "receipt": deduped_receipt,
            })
            return

        def send_signal_result(ok: bool, pid: int | None, err: str | None, status: int, broker_id: str | None = None) -> None:
            receipt = _make_action_receipt(
                client_action_id=client_action_id or None,
                state="applied" if ok else "failed",
                phases=_receipt_phases(validated=True, applied=ok, pty_written=False),
                backend="pty_broker" if broker_id else "process_signal",
                pid=pid,
            )
            _store_action_receipt(
                device_id,
                receipt_session_id,
                client_action_id or None,
                body_hash,
                receipt,
                action_kind="session_signal",
                audit_action={"type": sig_name.lower(), "provider": provider, "ok": ok},
            )
            body = {
                "ok": ok,
                "pid": pid,
                "signal": sig_name,
                "error": err,
                "receipt": receipt,
            }
            if broker_id:
                body["broker_id"] = broker_id
            self._send_json(body, status=status)

        if provider == "codex":
            broker_found = self._broker_session_for(_qualified_session_id("codex", native_id))
            if broker_found and PTY_BROKER:
                _, broker_session = broker_found
                broker_id = _broker_session_id(broker_session)
                if sig == signal.SIGINT:
                    result = PTY_BROKER.control(broker_id, {"type": "key", "key": "ctrl_c"})
                else:
                    result = PTY_BROKER.terminate(broker_id, sig)
                ok = bool(result.get("ok"))
                if ok:
                    _write_agent_turn_state("codex", native_id, "idle", event=sig_name.lower())
                if ok and sig == signal.SIGTERM:
                    _agent_registry_mark_closed("codex", native_id)
                send_signal_result(
                    ok,
                    result.get("pid") or _broker_pid(broker_session),
                    result.get("error") or result.get("reason"),
                    200 if ok else int(result.get("status") or 502),
                    broker_id=broker_id,
                )
                return

            reg = _agent_registry_get("codex", native_id)
            if not reg or reg.get("closed_at"):
                send_signal_result(False, None, "no Codex control registry row for session", 404)
                return
            pid = int(reg.get("pid") or 0)
            tty = reg.get("terminal_tty") or ""
            if (not pid or not _process_alive(pid)) and tty:
                pid = _pid_for_tty_command(tty, "codex")
                if pid:
                    _agent_registry_upsert("codex", native_id, reg.get("project") or str(HOME), pid=pid, terminal_tty=tty)
            if not pid:
                send_signal_result(False, None, "no codex pid for session", 404)
                return
            ok = True
            err: str | None = None
            try:
                if sig == signal.SIGTERM:
                    try:
                        os.killpg(os.getpgid(pid), sig)
                    except ProcessLookupError:
                        raise
                    except Exception:
                        os.kill(pid, sig)
                else:
                    os.kill(pid, sig)
            except (ProcessLookupError, PermissionError, OSError) as e:
                ok = False
                err = f"{type(e).__name__}: {e}"
            if ok:
                _write_agent_turn_state("codex", native_id, "idle", event=sig_name.lower())
            if ok and sig == signal.SIGTERM:
                _agent_registry_mark_closed("codex", native_id)
            send_signal_result(ok, pid, err, 200 if ok else 502)
            return

        session_id = _claude_native_session_id(raw_session)
        if not session_id:
            self.send_error(400, "session required")
            return

        broker_found = self._broker_session_for(_qualified_session_id("claude", session_id))
        if broker_found and PTY_BROKER:
            _, broker_session = broker_found
            broker_id = _broker_session_id(broker_session)
            if sig == signal.SIGINT:
                result = PTY_BROKER.control(broker_id, {"type": "key", "key": "ctrl_c"})
            else:
                result = PTY_BROKER.terminate(broker_id, sig)
            ok = bool(result.get("ok"))
            if ok and sig == signal.SIGTERM:
                self._mark_session_closed(session_id)
            send_signal_result(
                ok,
                result.get("pid") or _broker_pid(broker_session),
                result.get("error") or result.get("reason"),
                200 if ok else int(result.get("status") or 502),
                broker_id=broker_id,
            )
            return

        pid = self._lookup_claude_pid(session_id)
        if not pid:
            send_signal_result(False, None, "no claude_pid for session", 404)
            return

        ok = True
        err: str | None = None
        try:
            if sig == signal.SIGTERM:
                try:
                    os.killpg(os.getpgid(pid), sig)
                except ProcessLookupError:
                    raise
                except Exception:
                    os.kill(pid, sig)
            else:
                os.kill(pid, sig)
        except ProcessLookupError as e:
            self._mark_session_closed(session_id)
            if sig == signal.SIGTERM:
                err = None
            else:
                ok = False
                err = f"{type(e).__name__}: {e}"
        except (PermissionError, OSError) as e:
            ok = False
            err = f"{type(e).__name__}: {e}"
        if ok and sig == signal.SIGTERM:
            self._mark_session_closed(session_id)

        send_signal_result(ok, pid, err, 200 if ok else 502)

    # ----- /commands: snapshot catalog of slash commands across all sources -----
    def _handle_commands(self, q):
        """Returns the merged catalog of slash commands available to claude:
        built-ins (hardcoded) + ~/.claude/commands + <cwd>/.claude/commands +
        ~/.claude/plugins/.../commands + ~/.claude/skills/<n>/SKILL.md (where
        user-invocable is not explicitly false).

        iOS caches this catalog locally and filters on `/` keystroke. Pass
        `?cwd=<absolute-path>` to also include project-scoped commands.

        Future: SSE delta stream when files change. For v1 the phone fetches
        on session entry and pull-to-refresh.
        """
        cwd = q.get("cwd", [""])[0].strip()
        provider = q.get("provider", ["claude"])[0].lower()
        if not _valid_provider_filter(provider, allow_all=False):
            _send_unknown_provider(self, provider)
            return
        items = _build_command_catalog(cwd=cwd, provider=provider) if provider in AGENT_PROVIDERS else []
        body = json.dumps({"count": len(items), "items": items}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /invocations: snapshot catalog of slash commands and dollar skills -----
    def _handle_invocations(self, q):
        cwd = q.get("cwd", [""])[0].strip()
        provider = q.get("provider", ["claude"])[0].lower()
        trigger = q.get("trigger", [""])[0].strip() or None
        if not _valid_provider_filter(provider, allow_all=False):
            _send_unknown_provider(self, provider)
            return
        if trigger is not None and trigger not in {"/", "$"}:
            self.send_error(400, "trigger must be / or $")
            return
        items = _build_invocation_catalog(cwd=cwd, provider=provider, trigger=trigger) if provider in AGENT_PROVIDERS else []
        body = json.dumps({
            "schema_version": _INVOCATION_SCHEMA_VERSION,
            "provider": provider,
            "cwd": cwd,
            "count": len(items),
            "items": items,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /tokens: aggregate input + output tokens from the session transcript -----
    def _handle_tokens(self, q):
        """Sum `usage.input_tokens` and `usage.output_tokens` across every
        assistant message in the transcript JSONL. iOS spinner polls this
        every ~8s while a turn is in flight to display the running token
        total Claude Code shows in its terminal status line.
        """
        session_id = q.get("session", [""])[0]
        session_id = _claude_native_session_id(session_id)
        if not session_id:
            self.send_error(400, "session required")
            return

        path = self._resolve_transcript(session_id)
        if path is None or not path.exists():
            self.send_error(404, "no transcript")
            return

        # Walk the JSONL backwards: sum tokens for the CURRENT TURN only —
        # everything since the most recent user prompt. Mirrors what Claude
        # Code shows in its terminal status line. Whole-session totals
        # ballooned numbers misleadingly (60k vs 14k for the actual turn).
        out_total = 0
        in_total = 0
        try:
            lines = _tail_lines(path, max_lines=1000, max_bytes=TRANSCRIPT_STATS_MAX_SCAN_BYTES)
        except OSError:
            lines = []
        for raw in reversed(lines):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except (ValueError, json.JSONDecodeError):
                continue
            msg = obj.get("message") or {}
            role = msg.get("role")
            usage = msg.get("usage") or obj.get("usage") or {}
            # Stop at the most recent user prompt — that boundary is "turn start".
            if role == "user" and obj.get("type") == "user":
                break
            if not isinstance(usage, dict):
                continue
            out_total += int(usage.get("output_tokens") or 0)
            in_total += int(usage.get("input_tokens") or 0)

        body = json.dumps({
            "ok": True,
            "input_tokens": in_total,
            "output_tokens": out_total,
            "total": in_total + out_total,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /provider-status: provider-level health for Tools tab -----
    def _handle_provider_status(self, q):
        provider = q.get("provider", ["all"])[0].lower()
        registered_ids = set(_provider_registry_ids() if _provider_registry_ids else AGENT_PROVIDERS)
        known_ids = set(_provider_known_ids() if _provider_known_ids else registered_ids)
        if provider != "all" and provider not in registered_ids:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "unknown_provider",
                    "message": f"Unknown provider: {provider}",
                    "known_providers": sorted(registered_ids),
                    "known_future_providers": sorted(known_ids - registered_ids),
                },
            }, status=400)
            return

        def config_default_model(path: Path) -> str | None:
            if not path.is_file():
                return None
            try:
                text = path.read_text(errors="replace")
            except OSError:
                return None
            # Handles JSON-ish and TOML-ish config without adding a parser dependency.
            for key in ("model", "default_model", "MODEL"):
                m = re.search(rf'(?m)^\s*["\']?{re.escape(key)}["\']?\s*[:=]\s*["\']([^"\']+)["\']', text)
                if m:
                    return m.group(1).strip()[:80]
            return None

        def default_model_payload(path: Path) -> tuple[str | None, bool | None, str | None]:
            model = config_default_model(path)
            if not model:
                return None, None, None
            shorthand = model.lower() in {"opus", "sonnet", "haiku"}
            return model, not shorthand, "config"

        def exact_model_from_claude_sessions(family: str | None) -> str | None:
            if not family:
                return None
            wanted = family.lower()
            for state_path in sorted((HOME / ".claude" / "turn-state").glob("*.json"), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True):
                try:
                    obj = json.loads(state_path.read_text(errors="replace"))
                except Exception:
                    continue
                model = obj.get("model")
                if isinstance(model, str) and model and wanted in model.lower() and model.lower() != wanted:
                    return model[:120]
            for row in self._collect_session_rows(since_min=60 * 24 * 7, live_only=False, limit=100, include_first_prompt=False):
                sid = row.get("id")
                if not sid:
                    continue
                path = self._resolve_transcript(sid)
                if not path or not path.exists():
                    continue
                try:
                    lines = _tail_lines(path, max_lines=400, max_bytes=TRANSCRIPT_TAIL_SCAN_BYTES)
                except OSError:
                    continue
                for raw in reversed(lines):
                    try:
                        obj = json.loads(raw)
                    except Exception:
                        continue
                    msg = obj.get("message") or {}
                    model = msg.get("model")
                    if isinstance(model, str) and model and wanted in model.lower() and model.lower() != wanted:
                        return model[:120]
            aliases = {
                "opus": "claude-opus-4-7",
                "sonnet": "claude-sonnet-4-6",
                "haiku": "claude-haiku-4-5",
            }
            return aliases.get(wanted)

        def resolve_default_model_payload(provider_name: str, path: Path) -> tuple[str | None, bool | None, str | None]:
            model, is_exact, source = default_model_payload(path)
            if provider_name == "claude" and model and is_exact is False:
                exact = exact_model_from_claude_sessions(model)
                if exact:
                    return exact, True, "observed-session+config"
            return model, is_exact, source

        def registry_total(provider_name: str) -> int:
            try:
                with _agent_registry_conn() as conn:
                    cur = conn.execute("SELECT COUNT(*) FROM agent_sessions WHERE provider = ?", (provider_name,))
                    return int(cur.fetchone()[0] or 0)
            except Exception:
                return 0

        if _provider_probe_all is None or provider_detail_payload is None or provider_snapshot_payload is None:
            self._send_json({
                "ok": False,
                "error": {
                    "code": "provider_registry_unavailable",
                    "message": "Provider registry is unavailable",
                },
            }, status=503)
            return

        cache_key = ("provider-status", str(HOME), provider)
        now = _time.time()
        with _runtime_snapshot_cache_lock:
            cached = _runtime_snapshot_cache.get(cache_key)
            if cached is not None and now - cached[0] < PROVIDER_STATUS_CACHE_SECONDS:
                self._send_json(_copy_cache_value(cached[1]))
                return

        results = _cached_runtime_snapshot(
            ("provider-probe-all", str(HOME), provider),
            PROVIDER_STATUS_CACHE_SECONDS,
            lambda: _provider_probe_all(provider_filter=provider, home=HOME),
        )
        enriched_results = []
        default_models: dict[str, tuple[str | None, bool | None, str | None]] = {}
        for result in results:
            provider_name = result.availability.provider_id
            if provider_name == "claude":
                rows = self._collect_session_rows(since_min=60 * 24, live_only=True, limit=200, include_first_prompt=False)
                readable_rows = self._collect_session_rows(since_min=60 * 24, live_only=False, limit=200, include_first_prompt=False)
                config_path = HOME / ".claude" / "settings.json"
                default_model, default_model_is_exact, default_model_source = resolve_default_model_payload("claude", config_path)
                default_models[provider_name] = (default_model, default_model_is_exact, default_model_source)
                result = result.with_availability(
                    readable_sessions=len(readable_rows),
                    live_sessions=len(rows),
                    controllable_sessions=sum(1 for r in rows if r.get("claude_pid")),
                ).with_diagnostics(
                    registry_count=None,
                    registry_live_count=None,
                )
            elif provider_name == "codex":
                config_path = HOME / ".codex" / "config.toml"
                codex_rows = _list_codex_sessions(live_only=False, active_within_min=60 * 24)
                live_codex_rows = _list_codex_sessions(live_only=True, active_within_min=60 * 24)
                live_registry = _agent_registry_live("codex")
                default_model, default_model_is_exact, default_model_source = resolve_default_model_payload("codex", config_path)
                default_models[provider_name] = (default_model, default_model_is_exact, default_model_source)
                result = result.with_availability(
                    readable_sessions=len(codex_rows),
                    live_sessions=len(live_codex_rows),
                    controllable_sessions=sum(1 for r in codex_rows if (r.get("controllability") or {}).get("can_send_text")),
                ).with_diagnostics(
                    registry_count=registry_total("codex"),
                    registry_live_count=len(live_registry),
                )
            enriched_results.append(result)

        providers: list[dict] = []
        for result in enriched_results:
            payload = provider_detail_payload(result)
            default_model, default_model_is_exact, default_model_source = default_models.get(result.availability.provider_id, (None, None, None))
            payload["default_model"] = default_model
            payload["default_model_is_exact"] = default_model_is_exact
            payload["default_model_source"] = default_model_source
            providers.append(payload)

        ts = _time.time()
        payload = {
            "ok": True,
            "schema_version": 2,
            "providers": providers,
            "snapshot": provider_snapshot_payload(enriched_results, observed_at=ts),
            "ts": ts,
        }
        with _runtime_snapshot_cache_lock:
            _runtime_snapshot_cache[cache_key] = (ts, _copy_cache_value(payload))
        self._send_json(payload)

    # ----- /status: hybrid status snapshot (passthrough text + structured fields) -----
    def _handle_status(self, q):
        """One-shot status snapshot for the iPhone status drawer.

        Hybrid shape — both flavors of "what's the session doing right now":
          - `text`: stdout from the user's `statusLine.command` (~/.claude/settings.json
            `statusLine` block). Same payload Claude Code's terminal status
            line shows. iPhone renders verbatim in a monospaced footer.
          - structured fields: branch / dirty_count / effort / context_pct /
            model / cost_usd / session_id. Phone renders these as native
            iOS rows with SF Symbols and is free to localize / format / link.

        Source of truth per field:
          - branch / dirty_count: `git -C <cwd>` (live, no caching)
          - effort / model / tool: the per-uuid turn-state JSON written by
            ~/.claude/hooks/state-track.ts
          - context_pct: derived from /tokens turn total vs 200k context window
          - cost_usd: input/output tokens × published Sonnet/Opus pricing
          - statusLine text: spawned subprocess with the session's stdin JSON

        Best-effort: any field that fails returns `null`. The phone tolerates
        nulls — it just hides those rows.
        """
        session_id = q.get("session", [""])[0]
        provider, native_id = _parse_agent_session_ref(session_id)
        if provider == "codex":
            if not native_id:
                self.send_error(400, "session required")
                return
            reg = _agent_registry_get("codex", native_id) or {}
            metadata = {}
            try:
                metadata = json.loads(reg.get("metadata_json") or "{}")
                if not isinstance(metadata, dict):
                    metadata = {}
            except Exception:
                metadata = {}
            launch_context = _session_launch_context_from_metadata(metadata)

            transcript_path = _resolve_codex_transcript(native_id)
            meta = _codex_rollout_meta(transcript_path) if transcript_path else None
            cwd = (
                reg.get("project")
                or (meta or {}).get("cwd")
                or _codex_project_for_session(native_id)
                or None
            )
            working_on = metadata.get("working_on")
            if not working_on and transcript_path:
                working_on = _codex_first_prompt(transcript_path, native_id, _codex_history_map())

            branch = None
            dirty_count = None
            if cwd and os.path.isdir(cwd):
                try:
                    bp = subprocess.run(
                        ["git", "-C", cwd, "branch", "--show-current"],
                        capture_output=True, text=True, timeout=2,
                    )
                    if bp.returncode == 0:
                        branch = (bp.stdout or "").strip() or None
                    sp = subprocess.run(
                        ["git", "-C", cwd, "status", "--porcelain"],
                        capture_output=True, text=True, timeout=2,
                    )
                    if sp.returncode == 0:
                        dirty_count = sum(1 for ln in sp.stdout.splitlines() if ln.strip())
                except (OSError, subprocess.SubprocessError):
                    pass

            pid = int(reg.get("pid") or 0)
            alive = _process_alive(pid) if pid else False
            model = metadata.get("model") or (meta or {}).get("model")
            effort = metadata.get("effort")
            state = metadata.get("state") or reg.get("state") or ("running" if alive else "idle")
            tool = metadata.get("tool")
            tty = reg.get("terminal_tty") or None
            status_text = "Codex"
            if launch_context and launch_context.get("strategy") == "aperture_cli":
                status_text += " · Aperture CLI"
            if model:
                status_text += f" · {model}"
            if tty:
                status_text += f" · {tty}"

            self._send_json({
                "ok": True,
                "session_id": _qualified_session_id("codex", native_id),
                "provider": "codex",
                "native_id": native_id,
                "claude_uuid": None,
                "cwd": cwd,
                "branch": branch,
                "dirty_count": dirty_count,
                "model": model,
                "effort": effort,
                "tool": tool,
                "state": state,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "context_window": 200_000,
                "context_pct": 0.0,
                "cost_usd": None,
                "working_on": working_on,
                "text": status_text,
                "text_raw": status_text,
                "permissions_mode": None,
                "stop_reason": None,
                "stop_details": None,
                "system_anomaly": None,
                "launch_context": launch_context,
            })
            return

        session_id = _claude_native_session_id(session_id)
        if not session_id:
            self.send_error(400, "session required")
            return

        # ---- structured fields ------------------------------------------------

        cwd = self._lookup_pg_field(session_id, "project")
        claude_uuid = self._lookup_pg_field(session_id, "claude_uuid")
        working_on = self._lookup_pg_field(session_id, "working_on")
        terminal_tty = self._lookup_terminal_tty(session_id)
        launch_context = _session_launch_context_from_metadata(
            _registry_metadata_from_row(_agent_registry_get_by_tty("claude", terminal_tty))
        )

        branch = None
        dirty_count = None
        if cwd and os.path.isdir(cwd):
            try:
                bp = subprocess.run(
                    ["git", "-C", cwd, "branch", "--show-current"],
                    capture_output=True, text=True, timeout=2,
                )
                if bp.returncode == 0:
                    branch = (bp.stdout or "").strip() or None
                sp = subprocess.run(
                    ["git", "-C", cwd, "status", "--porcelain"],
                    capture_output=True, text=True, timeout=2,
                )
                if sp.returncode == 0:
                    dirty_count = sum(1 for ln in sp.stdout.splitlines() if ln.strip())
            except (OSError, subprocess.SubprocessError):
                pass

        # turn-state JSON (effort, model, tool, state). Hook writes it on
        # every event, so this is fresh within ~1s of the last activity.
        effort = None
        model = None
        tool = None
        state = None
        if claude_uuid:
            ts_path = HOME / ".claude" / "turn-state" / f"{claude_uuid}.json"
            try:
                if ts_path.exists():
                    with open(ts_path, "r") as f:
                        ts = json.load(f)
                    effort = ts.get("effort") or None
                    model = ts.get("model") or None
                    tool = ts.get("tool") or None
                    state = ts.get("state") or None
            except (OSError, ValueError, json.JSONDecodeError):
                pass

        # tokens + context_pct + cost. Walk transcript backwards for current
        # turn only — same accounting as /tokens. Also harvest the model id
        # from the most recent assistant message and any abnormal stop_reason
        # / system-error in the current turn so the phone can surface it.
        in_tokens = 0
        out_tokens = 0
        # stop_reason is "end_turn" / "tool_use" / "max_tokens" / "stop_sequence"
        # / "refusal" / "pause_turn" — first two are normal, rest are anomalies
        # the user wants to see. stop_details is sometimes a dict of additional
        # info (max_tokens detail, etc.). system_anomaly captures type=system|error
        # JSONL lines whose subtype is non-routine ("hook" / "duration" are routine).
        stop_reason: str | None = None
        stop_details: dict | None = None
        system_anomaly: dict | None = None
        path = self._resolve_transcript(session_id)
        if path and path.exists():
            try:
                lines = _tail_lines(path, max_lines=1000, max_bytes=TRANSCRIPT_STATS_MAX_SCAN_BYTES)
            except OSError:
                lines = []
            for raw in reversed(lines):
                if not raw.strip():
                    continue
                try:
                    obj = json.loads(raw)
                except (ValueError, json.JSONDecodeError):
                    continue
                line_type = obj.get("type")
                msg = obj.get("message") or {}
                role = msg.get("role")
                usage = msg.get("usage") or obj.get("usage") or {}
                # Stop conditions for the current turn — record the latest
                # observed before walking past the user-message turn boundary.
                if stop_reason is None and role == "assistant":
                    sr = msg.get("stop_reason")
                    if isinstance(sr, str) and sr:
                        stop_reason = sr
                    sd = msg.get("stop_details")
                    if isinstance(sd, dict):
                        stop_details = sd
                # System/error events from this turn — skip the routine
                # subtypes Claude Code emits as bookkeeping.
                if system_anomaly is None and line_type in ("system", "error"):
                    subtype = obj.get("subtype")
                    if subtype not in {"stop_hook_summary", "turn_duration"}:
                        system_anomaly = {
                            "type": line_type,
                            "subtype": subtype,
                            # Truncate to keep payload bounded. Phone can fetch
                            # the full transcript via /transcript if needed.
                            "content": (obj.get("content") or obj.get("text") or "")[:600],
                        }
                if model is None and role == "assistant":
                    m = msg.get("model")
                    if isinstance(m, str) and m:
                        model = m
                if role == "user" and line_type == "user":
                    break
                if isinstance(usage, dict):
                    out_tokens += int(usage.get("output_tokens") or 0)
                    in_tokens += int(usage.get("input_tokens") or 0)
        total_tokens = in_tokens + out_tokens
        # Model-aware context window. Opus 4.x ships with 1M-token context,
        # Sonnet / Haiku 4.x stay at 200k.
        context_window = 1_000_000 if (model and "opus" in model.lower()) else 200_000
        context_pct = round((total_tokens / context_window) * 100, 1) if total_tokens else 0.0

        # Rough cost — public per-MTok pricing as of 2026-Q2.
        # Opus 4.x: $15 input / $75 output. Sonnet 4.x: $3 / $15. Haiku 4.x: $1 / $5.
        cost_usd = None
        if model:
            ml = model.lower()
            if "opus" in ml:
                p_in, p_out = 15.0, 75.0
            elif "haiku" in ml:
                p_in, p_out = 1.0, 5.0
            else:  # default: sonnet pricing
                p_in, p_out = 3.0, 15.0
            cost_usd = round(
                (in_tokens / 1_000_000) * p_in + (out_tokens / 1_000_000) * p_out,
                4,
            )

        # ---- statusLine text passthrough -------------------------------------

        status_text_raw = None
        try:
            settings_path = HOME / ".claude" / "settings.json"
            if settings_path.exists():
                with open(settings_path, "r") as f:
                    settings = json.load(f)
                sl = settings.get("statusLine") or {}
                cmd = sl.get("command")
                if cmd:
                    payload = json.dumps({
                        "session_id": session_id,
                        "claude_uuid": claude_uuid,
                        "cwd": cwd,
                        "model": {"id": model, "display_name": model},
                        "transcript_path": str(path) if path else None,
                        "workspace": {"current_dir": cwd},
                    })
                    proc = subprocess.run(
                        ["bash", "-lc", cmd],
                        input=payload, capture_output=True, text=True, timeout=3,
                    )
                    if proc.returncode == 0:
                        status_text_raw = (proc.stdout or "").rstrip("\n") or None
        except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError):
            pass

        # Strip ANSI escapes (CSI / SGR / OSC) so the phone gets a clean text
        # line. The raw string is preserved separately for users who want to
        # re-render the colors themselves.
        ansi_re = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        status_text_clean = ansi_re.sub("", status_text_raw) if status_text_raw else None

        # Permissions / accept-edits / bypass mode is a Claude Code setting
        # the user toggles with shift+tab. The chosen mode is mirrored in
        # ~/.claude/settings.json under `permissions.defaultMode` (one of
        # "default", "acceptEdits", "plan", "bypassPermissions"). Surface
        # it so the phone can render the same banner the terminal shows.
        perm_mode = None
        try:
            settings_path = HOME / ".claude" / "settings.json"
            if settings_path.exists():
                with open(settings_path, "r") as f:
                    settings = json.load(f)
                perm_mode = (settings.get("permissions") or {}).get("defaultMode")
        except (OSError, ValueError, json.JSONDecodeError):
            pass

        body = json.dumps({
            "ok": True,
            "session_id": _qualified_session_id("claude", session_id),
            "provider": "claude",
            "native_id": session_id,
            "claude_uuid": claude_uuid,
            "cwd": cwd,
            "branch": branch,
            "dirty_count": dirty_count,
            "model": model,
            "effort": effort,
            "tool": tool,
            "state": state,
            "input_tokens": in_tokens,
            "output_tokens": out_tokens,
            "total_tokens": total_tokens,
            "context_window": context_window,
            "context_pct": context_pct,
            "cost_usd": cost_usd,
            "working_on": working_on,
            "text": status_text_clean,
            "text_raw": status_text_raw,
            "permissions_mode": perm_mode,
            "stop_reason": stop_reason,
            "stop_details": stop_details,
            "system_anomaly": system_anomaly,
            "launch_context": launch_context,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /pickers/*: native iOS argument-form pickers -----
    #
    # These power the phone's native UIs that replace Claude Code's in-memory
    # Ink TUI modals (which never reach the JSONL transcript so the iPhone
    # can't mirror them). The bridge of choice depends on whether the
    # underlying command has a CLI argument form:
    #
    #   has-arg form (/rename, /resume) → phone sends `/rename "<name>"` via
    #     /send-text bracketed paste; daemon doesn't need to do anything.
    #
    #   no arg form (/permissions, /hooks, /memory, /mcp) → daemon mutates
    #     the underlying state file directly (settings.json or memory dir).
    #     Claude Code's settings-watcher picks up the change automatically.
    #
    # All endpoints follow the same shape:
    #   GET  → return current state as JSON
    #   POST → JSON body, validate, write atomically (.tmp + rename), return updated state

    def _read_settings_json(self) -> dict:
        """Read ~/.claude/settings.json, returning {} on error or missing.
        Whole-file load — pyright-friendly, all keys preserved."""
        path = HOME / ".claude" / "settings.json"
        try:
            if not path.exists():
                return {}
            with open(path, "r") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError, json.JSONDecodeError):
            return {}

    def _write_settings_json(self, settings: dict) -> bool:
        """Atomic write: stage to .tmp in same dir, fsync, rename. Preserves
        whatever other keys live in settings.json that we don't touch."""
        path = HOME / ".claude" / "settings.json"
        tmp_path = path.with_suffix(".json.tmp")
        try:
            tmp_path.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp_path, "w") as f:
                json.dump(settings, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
            return True
        except OSError:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            return False

    # ----- /pickers/resume: list resumable sessions for a cwd -----
    def _handle_pickers_resume(self, q):
        """List the user's recent Claude Code sessions for a project so the
        phone can render a native picker. Each entry exposes:
          id      — claude_uuid (filename stem)
          mtime   — last-modified epoch seconds
          turns   — JSONL line count (rough)
          preview — first user-message text, truncated to ~120 chars
        Sorted newest-first. Filtered to the requested cwd via the same
        encoded-project-dir scheme Claude Code uses.
        """
        cwd = q.get("cwd", [""])[0]
        provider = q.get("provider", ["claude"])[0].lower()
        if not _valid_provider_filter(provider, allow_all=False):
            _send_unknown_provider(self, provider)
            return
        if provider not in AGENT_PROVIDERS:
            self._send_json({"ok": True, "sessions": [], "provider": provider})
            return
        if not cwd:
            self.send_error(400, "cwd required")
            return
        if provider == "codex":
            self._handle_codex_pickers_resume(cwd)
            return
        proj_dir = HOME / ".claude" / "projects" / _encode_project_dir(cwd)
        if not proj_dir.exists():
            body = json.dumps({"ok": True, "sessions": []}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        items: list[dict] = []
        try:
            for jsonl in proj_dir.glob("*.jsonl"):
                try:
                    stat = jsonl.stat()
                except OSError:
                    continue
                preview = ""
                turns = 0
                try:
                    with open(jsonl, "rb") as f:
                        for raw in f:
                            if not raw.strip():
                                continue
                            turns += 1
                            if not preview:
                                try:
                                    obj = json.loads(raw)
                                except (ValueError, json.JSONDecodeError):
                                    continue
                                if obj.get("type") == "user":
                                    msg = obj.get("message") or {}
                                    content = msg.get("content")
                                    if isinstance(content, str):
                                        preview = content
                                    elif isinstance(content, list):
                                        for blk in content:
                                            if isinstance(blk, dict) and blk.get("type") == "text":
                                                preview = blk.get("text") or ""
                                                break
                                    if preview:
                                        preview = preview.replace("\n", " ").strip()[:120]
                except OSError:
                    pass
                items.append({
                    "id": jsonl.stem,
                    "mtime": stat.st_mtime,
                    "turns": turns,
                    "preview": preview,
                    "bytes": stat.st_size,
                })
        except OSError:
            pass
        items.sort(key=lambda x: x["mtime"], reverse=True)
        body = json.dumps({"ok": True, "sessions": items[:80]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_codex_pickers_resume(self, cwd: str):
        items: list[dict] = []
        history = _codex_history_map()
        for path in _codex_rollout_paths():
            try:
                stat = path.stat()
            except OSError:
                continue
            meta = _codex_rollout_meta(path)
            if not meta or meta.get("cwd") != cwd:
                continue
            sid = meta["id"]
            preview = _codex_first_prompt(path, sid, history) or ""
            turns = 0
            try:
                with path.open(encoding="utf-8", errors="replace") as f:
                    for raw in f:
                        for row in _normalize_codex_line(raw, sid):
                            msg = row.get("message") or {}
                            if msg.get("role") == "user":
                                turns += 1
            except OSError:
                pass
            items.append({
                "id": sid,
                "mtime": stat.st_mtime,
                "turns": turns,
                "preview": preview.replace("\n", " ").strip()[:120],
                "bytes": stat.st_size,
            })
            if len(items) >= 80:
                break
        items.sort(key=lambda x: x["mtime"], reverse=True)
        body = json.dumps({"ok": True, "provider": "codex", "sessions": items[:80]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /pickers/resume/preview: last-N assistant outputs from a session -----
    def _handle_pickers_resume_preview(self, q):
        """Return the last N (default 2) full assistant text outputs from a
        session's JSONL. Walks the file once forward, splits into turns
        bounded by user messages, and returns the assistant text from the
        most recent N completed turns.

        Each preview is the concatenation of every assistant `text` block in
        the turn — that's "the full output". Tool blocks / thinking blocks
        are skipped. Truncated to ~2000 chars per turn so a long-output
        session doesn't ship megabytes over the wire.
        """
        cwd = q.get("cwd", [""])[0]
        provider = q.get("provider", ["claude"])[0].lower()
        session_id = q.get("id", [""])[0]
        try:
            n = int(q.get("n", ["2"])[0])
        except ValueError:
            n = 2
        n = max(1, min(n, 5))
        if not cwd or not session_id:
            self.send_error(400, "cwd and id required")
            return
        if not _valid_provider_filter(provider, allow_all=False):
            _send_unknown_provider(self, provider)
            return
        if provider not in AGENT_PROVIDERS:
            self._send_json({"ok": True, "session": None, "provider": provider, "preview": []})
            return
        if provider == "codex":
            self._handle_codex_pickers_resume_preview(cwd, session_id, n)
            return
        # session_id arrives as the JSONL filename stem (a UUID); guard
        # against path traversal.
        if "/" in session_id or "\\" in session_id or ".." in session_id:
            self.send_error(400, "invalid id")
            return
        proj_dir = HOME / ".claude" / "projects" / _encode_project_dir(cwd)
        target = proj_dir / f"{session_id}.jsonl"
        if not target.exists():
            self.send_error(404, "no such session in this project")
            return

        # Walk: collect text from each assistant message; reset accumulator
        # at every user message so we end up with a list of per-turn outputs.
        turns: list[str] = []
        current: list[str] = []
        try:
            with open(target, "rb") as f:
                for raw in f:
                    if not raw.strip():
                        continue
                    try:
                        obj = json.loads(raw)
                    except (ValueError, json.JSONDecodeError):
                        continue
                    if obj.get("type") == "user":
                        if current:
                            turns.append("\n\n".join(current))
                            current = []
                        continue
                    if obj.get("type") != "assistant":
                        continue
                    msg = obj.get("message") or {}
                    content = msg.get("content")
                    chunks: list[str] = []
                    if isinstance(content, str):
                        if content.strip():
                            chunks.append(content)
                    elif isinstance(content, list):
                        for blk in content:
                            if not isinstance(blk, dict):
                                continue
                            if blk.get("type") == "text":
                                t = blk.get("text") or ""
                                if t.strip():
                                    chunks.append(t)
                    if chunks:
                        current.append("\n\n".join(chunks))
                if current:
                    turns.append("\n\n".join(current))
        except OSError as e:
            self.send_error(500, f"read failed: {e}")
            return

        last_n = turns[-n:]
        # Per-turn cap so megachat sessions don't ship 5MB of preview
        capped = []
        for t in last_n:
            if len(t) > 2000:
                capped.append(t[:1000] + "\n\n…[truncated]…\n\n" + t[-1000:])
            else:
                capped.append(t)

        body = json.dumps({"ok": True, "turns": capped}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_codex_pickers_resume_preview(self, cwd: str, session_id: str, n: int):
        if not _safe_agent_native_id(session_id):
            self.send_error(400, "invalid id")
            return
        path = _resolve_codex_transcript(session_id)
        if not path:
            self.send_error(404, "no such Codex session")
            return
        meta = _codex_rollout_meta(path)
        if meta and meta.get("cwd") != cwd:
            self.send_error(404, "no such Codex session in this project")
            return
        turns: list[str] = []
        current: list[str] = []
        try:
            with path.open("rb") as f:
                for raw in f:
                    if not raw.strip():
                        continue
                    for row in _normalize_codex_line(raw, session_id):
                        msg = row.get("message") or {}
                        role = msg.get("role")
                        if role == "user":
                            if current:
                                turns.append("\n\n".join(current))
                                current = []
                            continue
                        if role != "assistant":
                            continue
                        chunks: list[str] = []
                        for blk in msg.get("content") or []:
                            if isinstance(blk, dict) and blk.get("type") == "text":
                                text = blk.get("text")
                                if isinstance(text, str) and text.strip():
                                    chunks.append(text)
                        if chunks:
                            current.append("\n\n".join(chunks))
                if current:
                    turns.append("\n\n".join(current))
        except OSError as e:
            self.send_error(500, f"read failed: {e}")
            return
        capped: list[str] = []
        for t in turns[-n:]:
            if len(t) > 2000:
                capped.append(t[:1000] + "\n\n...[truncated]...\n\n" + t[-1000:])
            else:
                capped.append(t)
        body = json.dumps({"ok": True, "provider": "codex", "turns": capped}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /pickers/permissions: read/write permission rules -----
    def _handle_pickers_permissions(self, q):
        """GET: returns current permissions block from settings.json.
        POST: replaces the permissions block with body, preserving everything
        else. Body shape: {"allow":[],"deny":[],"ask":[],"additionalDirectories":[],"defaultMode":"..."}
        """
        if self.command == "GET":
            settings = self._read_settings_json()
            perms = settings.get("permissions") or {}
            # effortLevel is a sibling top-level key, not nested under
            # permissions. Returning it inline so the phone can render the
            # Effort default control on the same screen.
            body = json.dumps({
                "ok": True,
                "permissions": {
                    "allow": perms.get("allow") or [],
                    "deny":  perms.get("deny")  or [],
                    "ask":   perms.get("ask")   or [],
                    "additionalDirectories": perms.get("additionalDirectories") or [],
                    "defaultMode": perms.get("defaultMode") or "default",
                    "effortLevel": settings.get("effortLevel") or "medium",
                },
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # POST: write
        try:
            raw = self._read_body()
            new_perms = json.loads(raw or b"{}")
            if not isinstance(new_perms, dict):
                self.send_error(400, "body must be a JSON object")
                return
        except (ValueError, json.JSONDecodeError):
            self.send_error(400, "invalid JSON body")
            return
        # Whitelist allowed keys + types so a typo can't poison settings.json.
        sanitized = {}
        for key in ("allow", "deny", "ask", "additionalDirectories"):
            v = new_perms.get(key)
            if isinstance(v, list):
                sanitized[key] = [str(x) for x in v if isinstance(x, (str, int))]
        dm = new_perms.get("defaultMode")
        if isinstance(dm, str) and dm in {"default", "acceptEdits", "plan", "bypassPermissions", "dontAsk"}:
            sanitized["defaultMode"] = dm
        settings = self._read_settings_json()
        settings["permissions"] = sanitized
        # effortLevel sits at top level, not under permissions — the phone
        # surfaces it on the same picker for convenience but on disk it's
        # a sibling key. Persist it whenever the body includes it.
        el = new_perms.get("effortLevel")
        if isinstance(el, str) and el in {"low", "medium", "high", "max"}:
            settings["effortLevel"] = el
        ok = self._write_settings_json(settings)
        # Echo the merged shape (permissions block + effortLevel) so the phone
        # can refresh its UI from the response without a follow-up GET.
        echo = dict(sanitized)
        echo["effortLevel"] = settings.get("effortLevel") or "medium"
        body = json.dumps({"ok": ok, "permissions": echo}).encode()
        self.send_response(200 if ok else 500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /pickers/hooks: read/write hook block -----
    def _handle_pickers_hooks(self, q):
        """GET: current hooks block. POST: replace it with the body.
        Hook event names recognized by Claude Code:
          PreToolUse, PostToolUse, PreCompact, PostCompact,
          Stop, Notification, SessionStart, PermissionRequest
        """
        valid_events = {
            "PreToolUse", "PostToolUse", "PreCompact", "PostCompact",
            "Stop", "Notification", "SessionStart", "PermissionRequest",
            "UserPromptSubmit",
        }
        if self.command == "GET":
            settings = self._read_settings_json()
            hooks = settings.get("hooks") or {}
            body = json.dumps({"ok": True, "hooks": hooks}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        try:
            raw = self._read_body()
            new_hooks = json.loads(raw or b"{}")
            if not isinstance(new_hooks, dict):
                self.send_error(400, "body must be a JSON object")
                return
        except (ValueError, json.JSONDecodeError):
            self.send_error(400, "invalid JSON body")
            return
        sanitized = {}
        for event_name, entries in new_hooks.items():
            if event_name not in valid_events:
                continue
            if not isinstance(entries, list):
                continue
            clean_entries = []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                hooks_list = entry.get("hooks")
                if not isinstance(hooks_list, list):
                    continue
                cleaned_hooks = []
                for h in hooks_list:
                    if not isinstance(h, dict):
                        continue
                    if not isinstance(h.get("command"), str):
                        continue
                    cleaned = {"type": h.get("type", "command"), "command": h["command"]}
                    if isinstance(h.get("timeout"), (int, float)):
                        cleaned["timeout"] = int(h["timeout"])
                    cleaned_hooks.append(cleaned)
                if not cleaned_hooks:
                    continue
                clean_entry = {"hooks": cleaned_hooks}
                if isinstance(entry.get("matcher"), str):
                    clean_entry["matcher"] = entry["matcher"]
                clean_entries.append(clean_entry)
            if clean_entries:
                sanitized[event_name] = clean_entries
        settings = self._read_settings_json()
        settings["hooks"] = sanitized
        ok = self._write_settings_json(settings)
        body = json.dumps({"ok": ok, "hooks": sanitized}).encode()
        self.send_response(200 if ok else 500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /pickers/memory: master-detail edit of project memory entries -----
    def _handle_pickers_memory(self, q):
        """List or create memory entries for a given project cwd.

        Memory layout (Claude Code's auto-memory convention):
          ~/.claude/projects/<encoded-cwd>/memory/
            MEMORY.md           index (one bullet per entry)
            <name>.md           per-entry file with YAML frontmatter
              ---
              name: ...
              description: ...
              type: user|feedback|project|reference
              ---
              <markdown body>

        GET  /pickers/memory?cwd=… → list (lightweight, no body)
        POST /pickers/memory?cwd=… → create new entry
        """
        cwd = q.get("cwd", [""])[0]
        if not cwd:
            self.send_error(400, "cwd required")
            return
        mem_dir = HOME / ".claude" / "projects" / _encode_project_dir(cwd) / "memory"

        if self.command == "GET":
            entries: list[dict] = []
            if mem_dir.exists():
                for md in sorted(mem_dir.glob("*.md")):
                    if md.name == "MEMORY.md":
                        continue
                    try:
                        text = md.read_text(encoding="utf-8")
                    except OSError:
                        continue
                    fm = _parse_md_frontmatter(text)
                    entries.append({
                        "filename": md.name,
                        "name": fm.get("name") or md.stem,
                        "description": fm.get("description") or "",
                        "type": fm.get("type") or "project",
                    })
            body = json.dumps({"ok": True, "entries": entries}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # POST: create new
        try:
            payload = json.loads(self._read_body() or b"{}")
        except (ValueError, json.JSONDecodeError):
            self.send_error(400, "invalid JSON body")
            return
        name = (payload.get("name") or "").strip()
        if not name or not re.match(r"^[A-Za-z0-9_\- ]{1,80}$", name):
            self.send_error(400, "name required (alnum/underscore/dash/space, 1-80 chars)")
            return
        mem_type = payload.get("type") or "project"
        if mem_type not in {"user", "feedback", "project", "reference"}:
            mem_type = "project"
        description = (payload.get("description") or "").strip()
        content = payload.get("content") or ""
        slug = re.sub(r"[^A-Za-z0-9_-]", "_", name.lower()).strip("_") or "memory"
        target = mem_dir / f"{slug}.md"
        # Avoid clobbering an existing entry with the same slug.
        if target.exists():
            counter = 2
            while (mem_dir / f"{slug}_{counter}.md").exists():
                counter += 1
            target = mem_dir / f"{slug}_{counter}.md"
        try:
            mem_dir.mkdir(parents=True, exist_ok=True)
            frontmatter = (
                "---\n"
                f"name: {name}\n"
                f"description: {description}\n"
                f"type: {mem_type}\n"
                "---\n\n"
            )
            target.write_text(frontmatter + content, encoding="utf-8")
            self._update_memory_index(mem_dir, target.name, name, description)
        except OSError as e:
            self.send_error(500, f"write failed: {e}")
            return
        body = json.dumps({"ok": True, "filename": target.name}).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_pickers_memory_one(self, q, filename: str):
        """GET / POST / DELETE a single memory entry by filename."""
        cwd = q.get("cwd", [""])[0]
        if not cwd:
            self.send_error(400, "cwd required")
            return
        # Sanitize: filename must be a single .md without path separators.
        if "/" in filename or "\\" in filename or not filename.endswith(".md") or filename == "MEMORY.md":
            self.send_error(400, "invalid filename")
            return
        mem_dir = HOME / ".claude" / "projects" / _encode_project_dir(cwd) / "memory"
        target = mem_dir / filename

        if self.command == "GET":
            if not target.exists():
                self.send_error(404, "no such entry")
                return
            try:
                text = target.read_text(encoding="utf-8")
            except OSError as e:
                self.send_error(500, f"read failed: {e}")
                return
            fm = _parse_md_frontmatter(text)
            # Body is everything after the closing `---` of frontmatter.
            body_text = text
            m = re.match(r"^---\n.*?\n---\n?", text, flags=re.DOTALL)
            if m:
                body_text = text[m.end():]
            body = json.dumps({
                "ok": True,
                "filename": filename,
                "name": fm.get("name") or target.stem,
                "description": fm.get("description") or "",
                "type": fm.get("type") or "project",
                "content": body_text,
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.command == "DELETE":
            try:
                if target.exists():
                    target.unlink()
                self._strip_memory_index(mem_dir, filename)
            except OSError as e:
                self.send_error(500, f"delete failed: {e}")
                return
            body = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # POST: update existing
        try:
            payload = json.loads(self._read_body() or b"{}")
        except (ValueError, json.JSONDecodeError):
            self.send_error(400, "invalid JSON body")
            return
        if not target.exists():
            self.send_error(404, "no such entry")
            return
        try:
            existing = target.read_text(encoding="utf-8")
        except OSError as e:
            self.send_error(500, f"read failed: {e}")
            return
        cur_fm = _parse_md_frontmatter(existing)
        name = (payload.get("name") or cur_fm.get("name") or target.stem).strip()
        description = (payload.get("description") or cur_fm.get("description") or "").strip()
        mem_type = payload.get("type") or cur_fm.get("type") or "project"
        if mem_type not in {"user", "feedback", "project", "reference"}:
            mem_type = "project"
        # Body: incoming `content` if provided, else preserve original body.
        body_part = payload.get("content")
        if body_part is None:
            m = re.match(r"^---\n.*?\n---\n?", existing, flags=re.DOTALL)
            body_part = existing[m.end():] if m else existing
        new_text = (
            "---\n"
            f"name: {name}\n"
            f"description: {description}\n"
            f"type: {mem_type}\n"
            "---\n\n"
            + body_part
        )
        try:
            target.write_text(new_text, encoding="utf-8")
            self._update_memory_index(mem_dir, filename, name, description)
        except OSError as e:
            self.send_error(500, f"write failed: {e}")
            return
        body = json.dumps({"ok": True, "filename": filename}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _update_memory_index(self, mem_dir, filename: str, name: str, description: str) -> None:
        """Add-or-update one bullet line in MEMORY.md. The convention from
        the auto-memory rules: `- [Title](file.md) — one-line hook`."""
        idx = mem_dir / "MEMORY.md"
        new_line = f"- [{name}]({filename}) — {description}"
        existing: str
        try:
            existing = idx.read_text(encoding="utf-8") if idx.exists() else ""
        except OSError:
            existing = ""
        lines: list[str] = list(existing.splitlines())
        # Replace any existing line referring to this filename, else append.
        replaced = False
        for i, ln in enumerate(lines):
            if f"]({filename})" in ln:
                lines[i] = new_line
                replaced = True
                break
        if not replaced:
            lines.append(new_line)
        try:
            idx.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        except OSError:
            pass

    def _strip_memory_index(self, mem_dir, filename: str) -> None:
        idx = mem_dir / "MEMORY.md"
        if not idx.exists():
            return
        try:
            existing = idx.read_text(encoding="utf-8")
        except OSError:
            return
        lines = [ln for ln in existing.splitlines() if f"]({filename})" not in ln]
        try:
            idx.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        except OSError:
            pass

    # ----- /pickers/mcp: list MCP servers + restart -----
    def _handle_pickers_mcp(self, q):
        """Run `claude mcp list` and parse the human-readable output into a
        structured list. Stdout shape per line:
          <name>: <command-or-url> - <status-text>
        Examples:
          plugin:semgrep:semgrep: semgrep mcp - ✓ Connected
          phone-tools: python3 /path/to/script.py - ✗ Failed: ...
        Returns whatever rows we can parse; un-parseable lines are skipped.
        """
        # Resolve `claude` binary — launchd-spawned daemon has a stripped PATH
        # so `which claude` may miss it. Try the known install locations the
        # user's shell would find via `which -a`.
        candidates = [
            HOME / ".local" / "bin" / "claude",
            "/usr/local/bin/claude",
            "/opt/homebrew/bin/claude",
        ]
        claude_bin: str | None = None
        for c in candidates:
            p = str(c)
            if os.path.exists(p) and os.access(p, os.X_OK):
                claude_bin = p
                break
        if claude_bin is None:
            body = json.dumps({"ok": True, "servers": []}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        servers: list[dict] = []
        try:
            proc = subprocess.run(
                [claude_bin, "mcp", "list"],
                capture_output=True, text=True, timeout=8,
            )
            if proc.returncode == 0:
                for raw in proc.stdout.splitlines():
                    line = raw.strip()
                    if not line:
                        continue
                    if line.startswith("Checking MCP"):
                        continue
                    # Pattern: name: cmd-or-url - status
                    m = re.match(r"^([^:]+):\s+(.*?)\s+-\s+(.*)$", line)
                    if not m:
                        continue
                    name = m.group(1).strip()
                    target = m.group(2).strip()
                    status_text = m.group(3).strip()
                    status: str
                    if "Connected" in status_text or "✓" in status_text:
                        status = "connected"
                    elif "Connecting" in status_text or "Pending" in status_text:
                        status = "connecting"
                    elif "Failed" in status_text or "Error" in status_text or "✗" in status_text:
                        status = "failed"
                    else:
                        status = "unknown"
                    servers.append({
                        "name": name,
                        "target": target,
                        "status": status,
                        "status_text": status_text,
                    })
        except (OSError, subprocess.SubprocessError):
            pass
        body = json.dumps({"ok": True, "servers": servers}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_pickers_mcp_restart(self, q, name: str):
        """POST /pickers/mcp/<name>/restart — try `claude mcp restart <name>`.
        Some Claude Code versions don't expose `restart`; if that fails, fall
        back to remove + re-add (caller has to confirm it's safe). Best-effort,
        return the captured stderr/stdout so the phone can show what happened.
        """
        if self.command != "POST":
            self.send_error(405, "POST required")
            return
        if not re.match(r"^[A-Za-z0-9_\-:.]+$", name):
            self.send_error(400, "invalid mcp server name")
            return
        candidates = [
            HOME / ".local" / "bin" / "claude",
            "/usr/local/bin/claude",
            "/opt/homebrew/bin/claude",
        ]
        claude_bin: str | None = None
        for c in candidates:
            p = str(c)
            if os.path.exists(p) and os.access(p, os.X_OK):
                claude_bin = p
                break
        if claude_bin is None:
            self.send_error(500, "claude binary not found")
            return
        try:
            proc = subprocess.run(
                [claude_bin, "mcp", "restart", name],
                capture_output=True, text=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as e:
            body = json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}).encode()
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps({
            "ok": proc.returncode == 0,
            "stdout": proc.stdout[:1000],
            "stderr": proc.stderr[:1000],
            "returncode": proc.returncode,
        }).encode()
        self.send_response(200 if proc.returncode == 0 else 500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /search: Spotlight-style cross-session text search -----
    def _handle_search(self, q):
        """Walk every JSONL in ~/.claude/projects/*/ and return the top
        matches for `q`. Substring + token match, scored by:
          - term frequency in the matching turn (×1)
          - recency boost (× decay over 30 days)
          - content-type weight (user prompts ×1.4, code ×1.2, assistant ×1.0)
        Result row: { session_id, project, project_basename, turn_index,
                      timestamp, snippet, kind, score }
        """
        query = (q.get("q", [""])[0] or "").strip()
        if not query:
            self.send_error(400, "q required")
            return
        try:
            limit = max(1, min(100, int(q.get("limit", ["30"])[0])))
        except ValueError:
            limit = 30
        kind_filter = q.get("kind", ["all"])[0]   # all | user | assistant | code
        provider_filter = q.get("provider", ["claude"])[0].lower()
        if not _valid_provider_filter(provider_filter):
            _send_unknown_provider(self, provider_filter)
            return

        # Cheap normalize — case-insensitive whole-substring match. Short
        # tokens get split for token coverage scoring.
        q_lower = query.lower()
        tokens = [t for t in re.split(r"\s+", q_lower) if len(t) >= 2]

        results: list[dict] = []
        projects_root = HOME / ".claude" / "projects"

        # Walk newest-modified first so we bail early on huge backlogs.
        all_jsonl: list[tuple[float, "Path", str]] = []
        if provider_filter in ("all", "claude") and projects_root.exists():
            for project_dir in projects_root.iterdir():
                if not project_dir.is_dir():
                    continue
                if _is_excluded_project_dir_name(project_dir.name):
                    continue
                for jp in project_dir.glob("*.jsonl"):
                    try:
                        st = jp.stat()
                    except OSError:
                        continue
                    all_jsonl.append((st.st_mtime, jp, project_dir.name))
        all_jsonl.sort(reverse=True)

        import time as _time
        now_ts = _time.time()

        # Hard cap on examined files to keep the endpoint snappy at scale.
        for mtime, jp, project_name in all_jsonl[:200]:
            try:
                with open(jp, "rb") as f:
                    line_idx = 0
                    for raw in f:
                        line_idx += 1
                        if not raw.strip():
                            continue
                        try:
                            obj = json.loads(raw)
                        except (ValueError, json.JSONDecodeError):
                            continue
                        line_kind = obj.get("type")
                        msg = obj.get("message") or {}
                        # Pull all text content out of this entry — strings or
                        # lists of {text, ...} blocks.
                        chunks: list[str] = []
                        is_code = False
                        content = msg.get("content")
                        if isinstance(content, str):
                            chunks.append(content)
                        elif isinstance(content, list):
                            for blk in content:
                                if not isinstance(blk, dict):
                                    continue
                                btype = blk.get("type")
                                t = blk.get("text") or blk.get("thinking") or ""
                                if btype == "tool_use":
                                    inp = blk.get("input")
                                    if inp is not None:
                                        try:
                                            t = json.dumps(inp)[:1000]
                                        except (TypeError, ValueError):
                                            t = ""
                                    is_code = True
                                elif btype == "tool_result":
                                    c = blk.get("content")
                                    if isinstance(c, str):
                                        t = c
                                    elif isinstance(c, list):
                                        try:
                                            t = "\n".join(
                                                (b.get("text") or "") for b in c
                                                if isinstance(b, dict)
                                            )
                                        except (TypeError, AttributeError):
                                            t = ""
                                    is_code = True
                                if t:
                                    chunks.append(t)
                        body = "\n".join(chunks)
                        if not body:
                            continue
                        body_lower = body.lower()
                        # Substring hit — required.
                        if q_lower not in body_lower:
                            # Token-coverage fallback: still match if all
                            # tokens appear individually.
                            if not tokens or not all(t in body_lower for t in tokens):
                                continue

                        # Apply kind filter
                        if kind_filter != "all":
                            if kind_filter == "user" and line_kind != "user":
                                continue
                            if kind_filter == "assistant" and line_kind != "assistant":
                                continue
                            if kind_filter == "code" and not is_code:
                                continue

                        # Score: substring count + recency decay
                        tf = body_lower.count(q_lower) or sum(body_lower.count(t) for t in tokens)
                        weight = 1.4 if line_kind == "user" else (1.2 if is_code else 1.0)
                        # 30-day half-life; turns within last day get full boost.
                        age_days = max(0.0, (now_ts - mtime) / 86_400.0)
                        recency = 1.0 / (1.0 + age_days / 30.0)
                        score = tf * weight * (0.5 + 0.5 * recency)

                        # Build a snippet around the first match.
                        idx = body_lower.find(q_lower)
                        if idx < 0 and tokens:
                            for t in tokens:
                                idx = body_lower.find(t)
                                if idx >= 0:
                                    break
                        if idx < 0:
                            idx = 0
                        start = max(0, idx - 60)
                        end = min(len(body), idx + len(query) + 80)
                        snippet = body[start:end].replace("\n", " ")
                        if start > 0:
                            snippet = "…" + snippet
                        if end < len(body):
                            snippet = snippet + "…"

                        results.append({
                            "session_id": _qualified_session_id("claude", jp.stem),
                            "provider": "claude",
                            "native_id": jp.stem,
                            "entry_id": obj.get("uuid"),
                            "project": project_name,
                            "turn_index": line_idx,
                            "timestamp": mtime,
                            "snippet": snippet,
                            "kind": "code" if is_code else (line_kind or "unknown"),
                            "score": round(score, 3),
                        })
            except OSError:
                continue
            # Stop scanning once we've gathered comfortably more than `limit`
            # so high-relevance early files dominate without scanning the
            # whole archive.
            if len(results) >= limit * 4:
                break

        if provider_filter in ("all", "codex"):
            for jp in _codex_rollout_paths()[:200]:
                try:
                    st = jp.stat()
                except OSError:
                    continue
                meta = _codex_rollout_meta(jp)
                if not meta:
                    continue
                native_id = meta["id"]
                project = meta["cwd"]
                try:
                    with open(jp, "rb") as f:
                        line_idx = 0
                        for raw in f:
                            line_idx += 1
                            if not raw.strip():
                                continue
                            for obj in _normalize_codex_line(raw, native_id):
                                line_kind = obj.get("type")
                                msg = obj.get("message") or {}
                                chunks: list[str] = []
                                is_code = False
                                content = msg.get("content")
                                if isinstance(content, str):
                                    chunks.append(content)
                                elif isinstance(content, list):
                                    for blk in content:
                                        if not isinstance(blk, dict):
                                            continue
                                        btype = blk.get("type")
                                        t = blk.get("text") or blk.get("thinking") or ""
                                        if btype == "tool_use":
                                            inp = blk.get("input")
                                            if inp is not None:
                                                try:
                                                    t = json.dumps(inp)[:1000]
                                                except (TypeError, ValueError):
                                                    t = ""
                                            is_code = True
                                        elif btype == "tool_result":
                                            c = blk.get("content")
                                            if isinstance(c, str):
                                                t = c
                                            elif isinstance(c, list):
                                                try:
                                                    t = "\n".join(
                                                        (b.get("text") or "") for b in c
                                                        if isinstance(b, dict)
                                                    )
                                                except (TypeError, AttributeError):
                                                    t = ""
                                            is_code = True
                                        if t:
                                            chunks.append(t)
                                body = "\n".join(chunks)
                                if not body:
                                    continue
                                body_lower = body.lower()
                                if q_lower not in body_lower:
                                    if not tokens or not all(t in body_lower for t in tokens):
                                        continue
                                if kind_filter != "all":
                                    if kind_filter == "user" and line_kind != "user":
                                        continue
                                    if kind_filter == "assistant" and line_kind != "assistant":
                                        continue
                                    if kind_filter == "code" and not is_code:
                                        continue
                                tf = body_lower.count(q_lower) or sum(body_lower.count(t) for t in tokens)
                                weight = 1.4 if line_kind == "user" else (1.2 if is_code else 1.0)
                                age_days = max(0.0, (now_ts - st.st_mtime) / 86_400.0)
                                recency = 1.0 / (1.0 + age_days / 30.0)
                                score = tf * weight * (0.5 + 0.5 * recency)
                                idx = body_lower.find(q_lower)
                                if idx < 0 and tokens:
                                    for t in tokens:
                                        idx = body_lower.find(t)
                                        if idx >= 0:
                                            break
                                if idx < 0:
                                    idx = 0
                                start = max(0, idx - 60)
                                end = min(len(body), idx + len(query) + 80)
                                snippet = body[start:end].replace("\n", " ")
                                if start > 0:
                                    snippet = "…" + snippet
                                if end < len(body):
                                    snippet = snippet + "…"
                                results.append({
                                    "session_id": _qualified_session_id("codex", native_id),
                                    "provider": "codex",
                                    "native_id": native_id,
                                    "entry_id": obj.get("uuid"),
                                    "project": project,
                                    "turn_index": line_idx,
                                    "timestamp": st.st_mtime,
                                    "snippet": snippet,
                                    "kind": "code" if is_code else (line_kind or "unknown"),
                                    "score": round(score, 3),
                                })
                except OSError:
                    continue
                if len(results) >= limit * 4:
                    break

        results.sort(key=lambda r: r["score"], reverse=True)
        self._json_response(200, {
            "ok": True,
            "count": min(len(results), limit),
            "results": results[:limit],
        })

    def _json_response(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /sessions/<id>/export: dump a session's JSONL as md / json / html -----
    def _handle_session_export(self, q, session_id: str):
        """Convert the session's JSONL into a portable transcript document.

        Formats:
          md   — opinionated cleanup pipeline (default `clean` verbosity):
                   - strip injected harness blocks (system-reminder, command-*,
                     local-command-*, task-notification)
                   - strip image filesystem paths + persisted-output refs
                   - drop tool_result blocks
                   - condense tool_use to one-liners
                   - merge consecutive same-role turns into one heading
                   - strip standalone "." lines (bracketed-paste flush hack)
          json — passthrough JSONL bytes
          html — TerminalTheme-styled self-contained page (uses md cleanup)

        Verbosity (md/html only):
          prose   — text-only, no tool calls at all
          clean   — text + condensed tool-use one-liners (default)
          full    — current behavior, full tool I/O preserved

        The phone uses iOS share sheet → AirDrop / Mail / Files / iMessage.
        """
        if not session_id or "/" in session_id or "\\" in session_id or ".." in session_id:
            self.send_error(400, "invalid session id")
            return
        fmt = (q.get("format", ["md"])[0] or "md").lower()
        if fmt not in {"md", "json", "html"}:
            self.send_error(400, "unsupported format")
            return
        verbosity = (q.get("verbosity", ["clean"])[0] or "clean").lower()
        if verbosity not in {"prose", "clean", "full"}:
            verbosity = "clean"

        provider, native_id = _parse_agent_session_ref(session_id)
        if provider == "codex":
            path = _resolve_codex_transcript(native_id)
        else:
            path = self._resolve_transcript(session_id)
        if path is None or not path.exists():
            self.send_error(404, "no transcript")
            return

        if provider == "codex":
            try:
                normalized = _normalize_codex_ndjson(path.read_bytes(), native_id)
            except OSError as e:
                self.send_error(500, f"read failed: {e}")
                return
            if fmt == "json":
                data = normalized.encode("utf-8")
                filename = f"codex-{native_id}.jsonl"
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

            sections: list[tuple[str, str]] = []
            first_ts: str | None = None
            last_ts: str | None = None
            for raw in normalized.splitlines():
                try:
                    obj = json.loads(raw)
                except (ValueError, json.JSONDecodeError):
                    continue
                role = obj.get("type")
                if role not in ("user", "assistant"):
                    continue
                ts = obj.get("timestamp")
                if isinstance(ts, str):
                    if first_ts is None:
                        first_ts = ts
                    last_ts = ts
                msg = obj.get("message") or {}
                content = msg.get("content") or []
                parts: list[str] = []
                if isinstance(content, str):
                    cleaned = _clean_transcript_export_text(content)
                    if cleaned:
                        parts.append(cleaned)
                elif isinstance(content, list):
                    for block in content:
                        if not isinstance(block, dict):
                            continue
                        btype = block.get("type")
                        if verbosity == "prose" and btype in ("tool_use", "tool_result"):
                            continue
                        if btype == "text":
                            t = block.get("text")
                            if isinstance(t, str) and t.strip():
                                cleaned = _clean_transcript_export_text(t)
                                if cleaned:
                                    parts.append(cleaned)
                        elif btype == "thinking" and verbosity == "full":
                            t = block.get("thinking") or block.get("text")
                            if isinstance(t, str) and t.strip():
                                cleaned = _clean_transcript_export_text(t)
                                if cleaned:
                                    parts.append(f"[thinking]\n{cleaned}")
                        elif btype == "tool_use":
                            name = block.get("name") or "tool"
                            if verbosity == "full":
                                parts.append(f"[tool use: {name}]\n```json\n{json.dumps(block.get('input') or {}, indent=2, sort_keys=True)}\n```")
                            elif verbosity == "clean":
                                parts.append(f"[tool use: {name}]")
                        elif btype == "tool_result" and verbosity == "full":
                            t = block.get("content")
                            if isinstance(t, str) and t.strip():
                                cleaned = _clean_transcript_export_text(t)
                                if cleaned:
                                    parts.append(f"[tool result]\n```\n{cleaned[:8000]}\n```")
                text = "\n\n".join(p for p in parts if p).strip()
                if text:
                    sections.append((role, text))

            title = f"Codex transcript {native_id}"
            md_lines = [
                "---",
                f"title: {title}",
                f"session_id: codex:{native_id}",
                "provider: codex",
                f"source_file: {path.name}",
            ]
            _append_launch_frontmatter(md_lines, launch_context)
            if first_ts:
                md_lines.append(f"started_at: {first_ts}")
            if last_ts:
                md_lines.append(f"last_event_at: {last_ts}")
            md_lines.extend(["---", ""])
            for role, text in sections:
                heading = "User" if role == "user" else "Assistant"
                md_lines.extend([f"## {heading}", "", text, ""])
            md = "\n".join(md_lines).rstrip() + "\n"
            if fmt == "md":
                data = md.encode("utf-8")
                filename = f"codex-{native_id}.md"
                self.send_response(200)
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

            body_html = html.escape(md)
            doc = (
                "<!doctype html><meta charset=\"utf-8\">"
                "<style>body{font:14px -apple-system,BlinkMacSystemFont,sans-serif;max-width:880px;margin:32px auto;padding:0 18px;line-height:1.45}"
                "pre{white-space:pre-wrap;background:#f6f6f6;padding:12px;border-radius:8px}"
                "</style>"
                f"<title>{html.escape(title)}</title><pre>{body_html}</pre>"
            )
            data = doc.encode("utf-8")
            filename = f"codex-{native_id}.html"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        # JSON: passthrough — fastest path, no transformation.
        if fmt == "json":
            try:
                data = path.read_bytes()
            except OSError as e:
                self.send_error(500, f"read failed: {e}")
                return
            filename = f"{session_id}.jsonl"
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        def clean_text(text: str) -> str:
            return _clean_transcript_export_text(text)

        # Walk JSONL once. For each turn collect text/tool/image fragments
        # transformed per verbosity. Track session metadata for front matter.
        sections: list[tuple[str, list[str]]] = []
        first_ts: str | None = None
        last_ts: str | None = None
        seen_model: str | None = None
        try:
            with open(path, "rb") as f:
                for raw in f:
                    if not raw.strip():
                        continue
                    try:
                        obj = json.loads(raw)
                    except (ValueError, json.JSONDecodeError):
                        continue
                    line_kind = obj.get("type")
                    ts = obj.get("timestamp")
                    if isinstance(ts, str):
                        if first_ts is None:
                            first_ts = ts
                        last_ts = ts
                    if line_kind not in ("user", "assistant"):
                        continue
                    msg = obj.get("message") or {}
                    if seen_model is None and line_kind == "assistant":
                        m = msg.get("model")
                        if isinstance(m, str) and m:
                            seen_model = m
                    content = msg.get("content")
                    parts: list[str] = []
                    if isinstance(content, str):
                        cleaned = clean_text(content)
                        if cleaned:
                            parts.append(cleaned)
                    elif isinstance(content, list):
                        for blk in content:
                            if not isinstance(blk, dict):
                                continue
                            btype = blk.get("type")
                            if btype == "text":
                                cleaned = clean_text(blk.get("text") or "")
                                if cleaned:
                                    parts.append(cleaned)
                            elif btype == "thinking":
                                if verbosity == "full":
                                    t = (blk.get("thinking") or blk.get("text") or "").strip()
                                    if t:
                                        parts.append(f"_(thinking)_\n\n> {t.replace(chr(10), chr(10) + '> ')}")
                                # prose / clean: drop thinking blocks
                            elif btype == "tool_use":
                                if verbosity == "prose":
                                    continue
                                name = blk.get("name") or "tool"
                                raw_inp = blk.get("input")
                                inp: dict = raw_inp if isinstance(raw_inp, dict) else {}
                                if verbosity == "full":
                                    try:
                                        args = json.dumps(inp, indent=2)[:2000]
                                    except (TypeError, ValueError):
                                        args = "{}"
                                    parts.append(f"**→ {name}**\n\n```json\n{args}\n```")
                                else:
                                    # clean: condense to a one-liner using
                                    # the most informative field available.
                                    desc = (
                                        inp.get("description")
                                        or inp.get("command")
                                        or inp.get("path")
                                        or inp.get("file_path")
                                        or inp.get("query")
                                        or inp.get("pattern")
                                        or ""
                                    )
                                    if isinstance(desc, str):
                                        desc = desc.replace("\n", " ").strip()[:120]
                                    else:
                                        desc = ""
                                    if desc:
                                        parts.append(f"*{name}: {desc}*")
                                    else:
                                        parts.append(f"*{name}*")
                            elif btype == "tool_result":
                                if verbosity == "full":
                                    c = blk.get("content")
                                    txt = ""
                                    if isinstance(c, str):
                                        txt = c
                                    elif isinstance(c, list):
                                        txt = "\n".join(
                                            (b.get("text") or "") for b in c
                                            if isinstance(b, dict)
                                        )
                                    txt = clean_text((txt or "")[:4000])
                                    if txt:
                                        parts.append(f"**← result**\n\n```\n{txt}\n```")
                                # prose / clean: drop tool_results entirely
                            elif btype == "image":
                                parts.append("*(image attached)*")
                    if parts:
                        sections.append((line_kind, parts))
        except OSError as e:
            self.send_error(500, f"read failed: {e}")
            return

        # Merge consecutive same-role turns into one section. This collapses
        # the pattern where Claude emits one assistant entry per text/tool
        # block — much more natural to read as "Claude ran three things,
        # then said this" rather than three separate ### Claude headers.
        merged: list[tuple[str, list[str]]] = []
        for role, parts in sections:
            if merged and merged[-1][0] == role:
                merged[-1][1].extend(parts)
            else:
                merged.append((role, list(parts)))

        if fmt == "md":
            lines: list[str] = []
            # YAML front matter — useful for tools that key on metadata.
            front = ["---", f"session: {session_id}"]
            if first_ts: front.append(f"started: {first_ts}")
            if last_ts:  front.append(f"ended: {last_ts}")
            front.append(f"turns: {len(merged)}")
            if seen_model: front.append(f"model: {seen_model}")
            _append_launch_frontmatter(front, launch_context)
            front.append(f"verbosity: {verbosity}")
            front.append("---")
            front.append("")
            lines.extend(front)
            lines.append(f"# Session {session_id}")
            lines.append("")
            for role, parts in merged:
                heading = "### You" if role == "user" else "### Claude"
                lines.append(heading)
                lines.append("")
                lines.append("\n\n".join(parts))
                lines.append("")
            data = ("\n".join(lines).rstrip() + "\n").encode("utf-8")
            filename = f"{session_id}.md"
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        # html path uses the merged structure too.
        sections = [(role, ["\n\n".join(parts)]) for role, parts in merged]

        # html — self-contained, terminal-styled
        css = """
        body { background:#000; color:#DFDFDF; font-family:Menlo,Monaco,monospace;
               padding:24px; max-width:920px; margin:0 auto; line-height:1.5; }
        h1 { color:#ECECEC; border-bottom:1px solid #1F2933; padding-bottom:8px; }
        h2 { color:#ECECEC; margin-top:32px; font-size:15px; }
        h2.user { color:#66B5EC; }
        h2.assistant { color:#7BCACD; }
        pre { background:#0A0A0A; padding:12px; overflow-x:auto;
              border:1px solid #1F2933; }
        code { color:#66B5EC; }
        blockquote { border-left:2px solid #465C6C; padding-left:12px;
                     color:#6B7680; font-style:italic; }
        strong { color:#ECECEC; }
        """
        def esc(s: str) -> str:
            return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        body_parts = [f"<h1>Session {esc(session_id)}</h1>"]
        for role, parts_list in sections:
            klass = "user" if role == "user" else "assistant"
            heading_text = "You" if role == "user" else "Claude"
            body_parts.append(f'<h2 class="{klass}">{heading_text}</h2>')
            # parts_list is now a list[str] per turn (post-cleanup). Join
            # them and run the same naive markdown→HTML pass we did before.
            text = esc("\n\n".join(parts_list))
            text = re.sub(
                r"```(\w*)\n(.*?)\n```",
                lambda m: f"<pre><code>{m.group(2)}</code></pre>",
                text, flags=re.DOTALL,
            )
            text = text.replace("\n\n", "</p><p>")
            body_parts.append(f"<p>{text}</p>")
        html_doc = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            f"<title>Session {esc(session_id)}</title>"
            f"<style>{css}</style></head><body>"
            + "\n".join(body_parts)
            + "</body></html>"
        )
        data = html_doc.encode("utf-8")
        filename = f"{session_id}.html"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ----- /commands-stream: SSE that pushes a fresh catalog snapshot on file change -----
    def _handle_commands_stream(self, q):
        """Subscribes the phone to live updates of the slash-command catalog.

        Polls the 5 source dirs every 5s and computes a stable signature
        (file path + mtime + size). When the signature changes — a command
        file was added, removed, or edited — we rebuild and emit a fresh
        full catalog snapshot. iOS replaces its cached array atomically.

        Why poll instead of fs.watch / FSEvents? Three reasons:
          1. No extra Python deps (watchdog isn't in stdlib).
          2. Plugin install / cd / homebrew updates often touch parent dirs
             without firing precise events; mtime polling catches everything.
          3. 5s cadence + ~5 dirs × ~200 files = ~1000 stat calls every 5s
             on the local fs. Trivial.

        Sends one initial `event: catalog` immediately on connect; then any
        change emits another. 20s keepalive. 30-min connection cap.
        """
        cwd = q.get("cwd", [""])[0].strip()
        provider = q.get("provider", ["claude"])[0].lower()
        if not _valid_provider_filter(provider, allow_all=False):
            _send_unknown_provider(self, provider)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        last_sig = ""
        last_keepalive = _time.time()
        deadline = _time.time() + 1800  # 30 min

        # Initial snapshot.
        try:
            items = _build_command_catalog(cwd=cwd, provider=provider)
            sig = _commands_signature(cwd, provider=provider)
            payload = json.dumps({"count": len(items), "items": items}).encode()
            self.wfile.write(b"event: catalog\ndata: " + payload + b"\n\n")
            self.wfile.flush()
            last_sig = sig
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            # If the initial scan blows up, send an error frame and bail.
            try:
                self.wfile.write(b"event: error\ndata: {}\n\n")
                self.wfile.flush()
            except Exception:
                pass
            return

        try:
            while _time.time() < deadline:
                _time.sleep(5)

                # Re-sign + re-emit only if it changed.
                try:
                    sig = _commands_signature(cwd, provider=provider)
                except Exception:
                    sig = last_sig

                if sig != last_sig:
                    try:
                        items = _build_command_catalog(cwd=cwd, provider=provider)
                        payload = json.dumps({"count": len(items), "items": items}).encode()
                        self.wfile.write(b"event: catalog\ndata: " + payload + b"\n\n")
                        self.wfile.flush()
                        last_sig = sig
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    except Exception:
                        pass

                if _time.time() - last_keepalive >= 20:
                    try:
                        self.wfile.write(b"event: keepalive\ndata: {}\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    last_keepalive = _time.time()

            try:
                self.wfile.write(b"event: done\ndata: {}\n\n")
                self.wfile.flush()
            except Exception:
                pass
        except (BrokenPipeError, ConnectionResetError):
                return

    # ----- /invocations-stream: SSE full invocation catalog snapshots -----
    def _handle_invocations_stream(self, q):
        cwd = q.get("cwd", [""])[0].strip()
        provider = q.get("provider", ["claude"])[0].lower()
        trigger = q.get("trigger", [""])[0].strip() or None
        if not _valid_provider_filter(provider, allow_all=False):
            _send_unknown_provider(self, provider)
            return
        if trigger is not None and trigger not in {"/", "$"}:
            self.send_error(400, "trigger must be / or $")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        last_sig = ""
        last_keepalive = _time.time()
        deadline = _time.time() + 1800

        def _payload() -> bytes:
            items = _build_invocation_catalog(cwd=cwd, provider=provider, trigger=trigger)
            return json.dumps({
                "schema_version": _INVOCATION_SCHEMA_VERSION,
                "provider": provider,
                "cwd": cwd,
                "count": len(items),
                "items": items,
            }).encode()

        try:
            sig = _invocations_signature(cwd=cwd, provider=provider, trigger=trigger)
            self.wfile.write(b"event: catalog\ndata: " + _payload() + b"\n\n")
            self.wfile.flush()
            last_sig = sig
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            try:
                self.wfile.write(b"event: error\ndata: {}\n\n")
                self.wfile.flush()
            except Exception:
                pass
            return

        try:
            while _time.time() < deadline:
                _time.sleep(5)
                try:
                    sig = _invocations_signature(cwd=cwd, provider=provider, trigger=trigger)
                except Exception:
                    sig = last_sig
                if sig != last_sig:
                    try:
                        self.wfile.write(b"event: catalog\ndata: " + _payload() + b"\n\n")
                        self.wfile.flush()
                        last_sig = sig
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    except Exception:
                        pass
                if _time.time() - last_keepalive >= 20:
                    try:
                        self.wfile.write(b"event: keepalive\ndata: {}\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    last_keepalive = _time.time()
            try:
                self.wfile.write(b"event: done\ndata: {}\n\n")
                self.wfile.flush()
            except Exception:
                pass
        except (BrokenPipeError, ConnectionResetError):
            return

    # ----- /pairdrop/*: private Mac-backed Pairling Connect file vault -----
    def _pairdrop_store(self):
        if PairDropStore is None:
            raise RuntimeError("PairDrop store unavailable")
        return PairDropStore(HOME / "Pairling" / "PairDrop" / "v1")

    def _pairdrop_source(self) -> tuple[str, str]:
        auth = getattr(self, "pairling_auth", None)
        return (
            str(getattr(auth, "device_id", "") or ""),
            str(getattr(auth, "install_id", "") or ""),
        )

    def _pairdrop_source_route(self) -> str:
        return str(self.headers.get("X-Pairling-Connect-Gateway") or "pairling-connectd")

    def _send_pairdrop_error(self, err, *, status: int = 400):
        code = getattr(err, "code", None) or str(err) or "pairdrop_error"
        self._send_json({
            "ok": False,
            "error": {
                "code": code,
                "message": code.replace("_", " "),
            },
        }, status=status)

    def _route_pairdrop_path(self, path: str, q):
        try:
            if path == "/pairdrop/files":
                if self.command == "GET":
                    self._handle_pairdrop_list(q)
                    return
                if self.command == "POST":
                    self._handle_pairdrop_upload(q)
                    return
                self.send_error(405, "method not allowed")
                return
            if path == "/pairdrop/events":
                if self.command != "GET":
                    self.send_error(405, "GET required")
                    return
                self._handle_pairdrop_events(q)
                return
            content_id = _pairdrop_file_content_id(path)
            if content_id is not None:
                if self.command != "GET":
                    self.send_error(405, "GET required")
                    return
                self._handle_pairdrop_content(content_id)
                return
            if path == "/pairdrop/maintenance/cleanup-partials":
                if self.command != "POST":
                    self.send_error(405, "POST required")
                    return
                self._handle_pairdrop_cleanup(q)
                return
            if path == "/pairdrop/uploads":
                if self.command != "POST":
                    self.send_error(405, "POST required")
                    return
                self._handle_pairdrop_upload_session_create()
                return
            upload_bytes_id = _pairdrop_upload_bytes_id(path)
            if upload_bytes_id is not None:
                if self.command != "PUT":
                    self.send_error(405, "PUT required")
                    return
                self._handle_pairdrop_upload_session_bytes(upload_bytes_id)
                return
            upload_complete_id = _pairdrop_upload_complete_id(path)
            if upload_complete_id is not None:
                if self.command != "POST":
                    self.send_error(405, "POST required")
                    return
                self._handle_pairdrop_upload_session_complete(upload_complete_id)
                return
            upload_id = _pairdrop_upload_id_from_path(path)
            if upload_id is not None:
                if self.command == "GET":
                    self._handle_pairdrop_upload_session_get(upload_id)
                    return
                if self.command == "DELETE":
                    self._handle_pairdrop_upload_session_cancel(upload_id)
                    return
                self.send_error(405, "method not allowed")
                return
            attach_id = _pairdrop_attach_file_id(path)
            if attach_id is not None:
                if self.command != "POST":
                    self.send_error(405, "POST required")
                    return
                self._handle_pairdrop_attach(attach_id, q)
                return
            file_id = _pairdrop_file_id_from_path(path)
            if file_id is not None:
                if self.command == "GET":
                    self._handle_pairdrop_get(file_id, q)
                    return
                if self.command == "DELETE":
                    self._handle_pairdrop_delete(file_id)
                    return
                self.send_error(405, "method not allowed")
                return
            self.send_error(404, "PairDrop route not found")
        except PairDropStoreError as e:
            self._send_pairdrop_error(e, status=404 if getattr(e, "code", "") in {"not_found", "deleted", "missing_object"} else 400)
        except Exception as e:
            self._send_json({"ok": False, "error": {"code": "pairdrop_failed", "message": str(e)}}, status=500)

    def _handle_pairdrop_upload(self, q):
        filename = q.get("filename", [""])[0]
        if not filename:
            self._send_json({"ok": False, "error": {"code": "filename_required"}}, status=400)
            return
        body = self._read_body()
        content_type = self.headers.get("Content-Type") or q.get("content_type", ["application/octet-stream"])[0]
        expected_sha256 = q.get("sha256", [""])[0].strip() or None
        session_hint = q.get("session", [""])[0].strip()
        device_id, install_id = self._pairdrop_source()
        item = self._pairdrop_store().upload_bytes(
            filename=filename,
            content_type=content_type,
            data=body,
            source_device_id=device_id,
            source_install_id=install_id,
            session_hint=session_hint,
            expected_sha256=expected_sha256,
        )
        item = {k: v for k, v in item.items() if k != "storage_relpath"}
        self._send_json({"ok": True, "file": item}, status=201)

    def _read_json_object(self) -> dict:
        body = self._read_body()
        if not body:
            return {}
        try:
            value = json.loads(body.decode("utf-8"))
        except Exception:
            raise PairDropStoreError("bad_json")
        if not isinstance(value, dict):
            raise PairDropStoreError("bad_json")
        return value

    def _public_upload_session(self, session: dict) -> dict:
        return {
            key: value for key, value in session.items()
            if key not in {"source_device_id", "source_install_id"}
        }

    def _handle_pairdrop_upload_session_create(self):
        payload = self._read_json_object()
        filename = str(payload.get("filename") or "").strip()
        if not filename:
            raise PairDropStoreError("filename_required")
        total = payload.get("total_byte_count", payload.get("byte_size", 0))
        expected_sha256 = str(payload.get("sha256") or payload.get("expected_sha256") or "").strip()
        content_type = str(payload.get("content_type") or "application/octet-stream")
        device_id, install_id = self._pairdrop_source()
        session = self._pairdrop_store().create_upload_session(
            filename=filename,
            content_type=content_type,
            total_byte_count=int(total or 0),
            expected_sha256=expected_sha256,
            source_device_id=device_id,
            source_install_id=install_id,
            source_route=self._pairdrop_source_route(),
        )
        self._send_json({"ok": True, "upload": self._public_upload_session(session)}, status=201)

    def _handle_pairdrop_upload_session_get(self, upload_id: str):
        session = self._pairdrop_store().get_upload_session(upload_id)
        self._send_json({"ok": True, "upload": self._public_upload_session(session)})

    def _pairdrop_chunk_offset(self, body_len: int) -> int:
        content_range = str(self.headers.get("Content-Range") or "").strip()
        if content_range:
            match = re.fullmatch(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", content_range)
            if not match:
                raise PairDropStoreError("bad_content_range")
            start = int(match.group(1))
            end = int(match.group(2))
            if end < start or (end - start + 1) != body_len:
                raise PairDropStoreError("content_range_mismatch")
            return start
        offset = str(self.headers.get("X-PairDrop-Offset") or "").strip()
        if offset:
            if not re.fullmatch(r"\d+", offset):
                raise PairDropStoreError("bad_offset")
            return int(offset)
        raise PairDropStoreError("offset_required")

    def _handle_pairdrop_upload_session_bytes(self, upload_id: str):
        body = self._read_body()
        chunk_sha256 = str(self.headers.get("X-PairDrop-Chunk-SHA256") or "").strip()
        idempotency_key = str(self.headers.get("Idempotency-Key") or "").strip()
        offset = self._pairdrop_chunk_offset(len(body))
        device_id, install_id = self._pairdrop_source()
        session = self._pairdrop_store().write_upload_chunk(
            upload_id,
            offset=offset,
            data=body,
            chunk_sha256=chunk_sha256,
            idempotency_key=idempotency_key,
            source_device_id=device_id,
            source_install_id=install_id,
        )
        self._send_json({"ok": True, "upload": self._public_upload_session(session)})

    def _handle_pairdrop_upload_session_complete(self, upload_id: str):
        device_id, install_id = self._pairdrop_source()
        result = self._pairdrop_store().complete_upload_session(
            upload_id,
            source_device_id=device_id,
            source_install_id=install_id,
        )
        file = {k: v for k, v in result["file"].items() if k != "storage_relpath"}
        self._send_json({"ok": True, "state": result["state"], "upload_id": upload_id, "file": file}, status=201)

    def _handle_pairdrop_upload_session_cancel(self, upload_id: str):
        device_id, install_id = self._pairdrop_source()
        session = self._pairdrop_store().cancel_upload_session(
            upload_id,
            source_device_id=device_id,
            source_install_id=install_id,
        )
        self._send_json({"ok": True, "upload": self._public_upload_session(session)})

    def _handle_pairdrop_list(self, q):
        include_deleted = q.get("include_deleted", ["false"])[0].lower() == "true"
        files = [
            {k: v for k, v in item.items() if k != "storage_relpath"}
            for item in self._pairdrop_store().list_files(include_deleted=include_deleted)
        ]
        self._send_json({"ok": True, "files": files})

    def _handle_pairdrop_get(self, file_id: str, q):
        if q.get("download", ["false"])[0].lower() in {"1", "true", "yes"}:
            self._handle_pairdrop_download(file_id)
            return
        item = self._pairdrop_store().get_file(file_id)
        item = {k: v for k, v in item.items() if k != "storage_relpath"}
        self._send_json({"ok": True, "file": item})

    def _handle_pairdrop_download(self, file_id: str):
        descriptor = self._pairdrop_store().download_descriptor(file_id)
        item = descriptor["item"]
        path = descriptor["path"]
        display_name = _pairdrop_attachment_filename(str(item.get("display_name") or "pairdrop-file"))
        content_type = _pairdrop_safe_content_type(str(item.get("content_type") or "application/octet-stream"))
        byte_size = int(item.get("byte_size") or path.stat().st_size)
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(byte_size))
        self.send_header("Content-Disposition", f'attachment; filename="{display_name}"')
        self.send_header("X-PairDrop-File-ID", str(item.get("id") or file_id))
        self.end_headers()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 256)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def _handle_pairdrop_content(self, file_id: str):
        descriptor = self._pairdrop_store().download_descriptor(file_id)
        item = descriptor["item"]
        path = descriptor["path"]
        total = int(item.get("byte_size") or path.stat().st_size)
        digest = str(item.get("sha256") or "")
        if not digest:
            raise PairDropStoreError("missing_sha256")

        range_header = str(self.headers.get("Range") or "").strip()
        if_range = str(self.headers.get("If-Range") or "").strip()
        if if_range and if_range != f'"{digest}"':
            range_header = ""

        try:
            start, end, partial = _parse_single_byte_range(range_header, total)
        except PairDropStoreError as exc:
            if exc.code == "range_not_satisfiable":
                body = b'{"ok":false,"error":{"code":"range_not_satisfiable","message":"range not satisfiable"}}'
                self.send_response(416)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Range", f"bytes */{total}")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            raise

        display_name = _pairdrop_attachment_filename(str(item.get("display_name") or "pairdrop-file"))
        content_type = _pairdrop_safe_content_type(str(item.get("content_type") or "application/octet-stream"))
        length = end - start + 1
        self.send_response(206 if partial else 200)
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("ETag", f'"{digest}"')
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Disposition", f'attachment; filename="{display_name}"')
        self.send_header("X-PairDrop-File-ID", str(item.get("id") or file_id))
        self.send_header("X-PairDrop-SHA256", digest)
        if partial:
            self.send_header("Content-Range", f"bytes {start}-{end}/{total}")
        self.end_headers()
        with path.open("rb") as handle:
            handle.seek(start)
            remaining = length
            while remaining > 0:
                chunk = handle.read(min(256 * 1024, remaining))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)

    def _handle_pairdrop_delete(self, file_id: str):
        self._send_json(self._pairdrop_store().delete_file(file_id))

    def _handle_pairdrop_attach(self, file_id: str, q):
        session_id = q.get("session", [""])[0].strip()
        self._send_json(self._pairdrop_store().attach_descriptor(file_id, session_id=session_id))

    def _handle_pairdrop_events(self, q):
        try:
            since = int(q.get("since", ["0"])[0] or "0")
        except ValueError:
            since = 0
        self._send_json({"ok": True, "events": self._pairdrop_store().events_since(since)})

    def _handle_pairdrop_cleanup(self, q):
        try:
            older = int(q.get("older_than_seconds", ["3600"])[0] or "3600")
        except ValueError:
            older = 3600
        self._send_json(self._pairdrop_store().cleanup_partials(older_than_seconds=older))

    # ----- /upload: save a file under ~/Pairling/uploads/<bucket>/ -----
    def _handle_upload(self, q):
        """Accept a raw POST body plus `?filename=<name>&session=<id>` query
        params. Save to ~/Pairling/uploads/<bucket>/<8-hex>-<name>
        where <bucket> is derived from the session's project path:

          - regular project (e.g. /Users/example/projects/proofforge)
            → bucket = "proofforge"
          - sentinel session (e.g. /Users/example/.claude/state/sentinel/projects/proofforge-079c4a/terminals/orange_team)
            → bucket = "proofforge"  (regex strips -<6hex> suffix)
          - fallback when session unknown
            → bucket = "misc"

        Returns the absolute path so the phone can append it to a prompt.
        Body capped at 100MB.
        """
        filename = q.get("filename", [""])[0].strip()
        if not filename:
            self.send_error(400, "filename required")
            return
        session_id = q.get("session", [""])[0].strip()

        # Defang: strip path components, keep only safe chars.
        base = os.path.basename(filename)
        safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', base) or "upload.bin"
        if len(safe_name) > 80:
            stem, dot, ext = safe_name.rpartition(".")
            if dot and len(ext) <= 8:
                safe_name = stem[: 80 - len(ext) - 1] + "." + ext
            else:
                safe_name = safe_name[:80]

        body = self._read_body()
        if len(body) > 100 * 1024 * 1024:
            self.send_error(413, "file too large (max 100MB)")
            return
        if not body:
            self.send_error(400, "empty body")
            return

        # Derive bucket folder from session's project (if session known).
        bucket = "misc"
        provider, native_id = _parse_agent_session_ref(session_id)
        if native_id:
            if provider == "codex":
                project = _codex_project_for_session(native_id)
            else:
                project = self._lookup_project(native_id)
            if project:
                bucket = _derive_bucket_folder(project)

        uploads_dir = HOME / "Pairling" / "uploads" / bucket
        try:
            uploads_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.send_error(500, f"can't create uploads dir: {e}")
            return

        target = uploads_dir / f"{secrets.token_hex(4)}-{safe_name}"
        try:
            target.write_bytes(body)
        except OSError as e:
            self.send_error(500, f"write failed: {e}")
            return

        resp = json.dumps({
            "ok": True,
            "path": str(target),
            "size": len(body),
            "filename": safe_name,
            "bucket": bucket,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def _lookup_project(self, session_id: str) -> str:
        session_id = _claude_native_session_id(session_id)
        if not session_id:
            return ""
        return str(_claude_sessions_backend().lookup_field(session_id, "project") or "")

    # ----- /turn-state-stream: SSE stream of per-session state transitions -----
    def _handle_turn_state_stream(self, q):
        """Server-Sent Events stream of {state, tool, started_at, effort} for
        one session. State events come from the state-track hook on Mac, which
        writes ~/.claude/turn-state/<claude_uuid>.json on every turn-relevant
        event (UserPromptSubmit / PreToolUse / PostToolUse / Stop).

        We poll the file's mtime at 250ms cadence and emit SSE only when the
        payload changes. 10-minute connection cap (iOS reconnects).

        SSE event types:
          event: state      data: {<full state JSON>}
          event: keepalive  data: {} (every 20s, prevents NAT timeout)
          event: done       data: {} (cap reached or session vanished)
        """
        raw_session = q.get("session", [""])[0]
        provider, session_id = _parse_agent_session_ref(raw_session)
        if not session_id:
            self.send_error(400, "session required")
            return

        if provider == "codex":
            self._handle_codex_turn_state_stream(session_id)
            return

        session_id = _claude_native_session_id(raw_session)
        if not session_id:
            self.send_error(400, "session required")
            return

        # Race-aware lookup: a freshly-spawned terminal may not have
        # claude_uuid in PG yet (claude bin + session-register hook + asyncpg
        # INSERT pipeline takes ~500ms-2s). LISTEN session_ready instead of
        # immediate 404 — session-register issues NOTIFY session_ready, '<id>'
        # the moment the row hits PG with claude_uuid populated. Falls back
        # to short polling if LISTEN doesn't fire (asyncpg unavailable etc.).
        uuid = self._lookup_claude_uuid(session_id)
        if not uuid:
            uuid = self._wait_for_session_ready(session_id, timeout_s=8.0)
        if not uuid:
            self.send_error(404, "no claude_uuid for session")
            return

        if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', uuid, re.IGNORECASE):
            self.send_error(500, "invalid claude_uuid in PG row")
            return

        state_path = _turn_state_path("claude", uuid)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        last_payload: bytes | None = None
        last_keepalive = _time.time()
        deadline = _time.time() + 600  # 10 min

        def provider_payload(raw: bytes) -> bytes:
            try:
                obj = json.loads(raw.decode("utf-8", errors="replace"))
                if isinstance(obj, dict):
                    obj["session_id"] = _qualified_session_id("claude", session_id)
                    obj["provider"] = "claude"
                    obj["native_id"] = session_id
                    return json.dumps(obj).encode()
            except Exception:
                pass
            return raw

        # Emit initial state immediately if file exists, so the client sees
        # current state without waiting for the next transition.
        try:
            if state_path.is_file():
                payload = provider_payload(state_path.read_bytes())
                self.wfile.write(b"event: state\ndata: " + payload + b"\n\n")
                self.wfile.flush()
                last_payload = payload
        except Exception:
            pass

        try:
            while _time.time() < deadline:
                _time.sleep(0.25)
                # Re-read file; emit only if content changed.
                try:
                    if state_path.is_file():
                        payload = provider_payload(state_path.read_bytes())
                        if payload and payload != last_payload:
                            self.wfile.write(b"event: state\ndata: " + payload + b"\n\n")
                            self.wfile.flush()
                            last_payload = payload
                except (BrokenPipeError, ConnectionResetError):
                    return
                except Exception:
                    pass

                if _time.time() - last_keepalive >= 20:
                    try:
                        self.wfile.write(b"event: keepalive\ndata: {}\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    last_keepalive = _time.time()

            try:
                self.wfile.write(b"event: done\ndata: {}\n\n")
                self.wfile.flush()
            except Exception:
                pass
        except (BrokenPipeError, ConnectionResetError):
            return

    def _handle_codex_turn_state_stream(self, native_id: str):
        if not _safe_agent_native_id(native_id):
            self.send_error(400, "bad Codex session id")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        last_payload: bytes | None = None
        last_keepalive = _time.time()
        deadline = _time.time() + 600

        def payload_bytes() -> bytes | None:
            obj = _codex_turn_state_payload(native_id)
            if not obj:
                return None
            return json.dumps(obj, sort_keys=True).encode()

        try:
            initial = payload_bytes()
            if initial:
                self.wfile.write(b"event: state\ndata: " + initial + b"\n\n")
                self.wfile.flush()
                last_payload = initial
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            pass

        try:
            while _time.time() < deadline:
                _time.sleep(0.25)
                try:
                    payload = payload_bytes()
                    if payload and payload != last_payload:
                        self.wfile.write(b"event: state\ndata: " + payload + b"\n\n")
                        self.wfile.flush()
                        last_payload = payload
                except (BrokenPipeError, ConnectionResetError):
                    return
                except Exception:
                    pass

                if _time.time() - last_keepalive >= 20:
                    try:
                        self.wfile.write(b"event: keepalive\ndata: {}\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    last_keepalive = _time.time()

            try:
                self.wfile.write(b"event: done\ndata: {}\n\n")
                self.wfile.flush()
            except Exception:
                pass
        except (BrokenPipeError, ConnectionResetError):
            return

    def _lookup_claude_uuid(self, session_id: str) -> str:
        return _lookup_claude_uuid_for_session(session_id)

    # ----- PG lookup helpers (used by send-text + sigint) -----
    def _wait_for_session_ready(self, session_id: str, timeout_s: float = 8.0) -> str:
        """Block up to timeout_s waiting for the session row to appear in PG
        with a populated claude_uuid. Subscribes to PG channel `session_ready`
        which session-register fires post-INSERT, falling back to short
        polling if asyncpg isn't importable. Returns the claude_uuid string
        on success, "" on timeout / PG unreachable."""
        session_id = _claude_native_session_id(session_id)
        if not session_id:
            return ""
        if _session_backend() == "sqlite":
            return self._wait_for_session_ready_sqlite(session_id, timeout_s)
        try:
            import asyncio
            import asyncpg  # type: ignore
        except Exception:
            # asyncpg missing — fall back to 200ms polling.
            deadline = _time.time() + timeout_s
            while _time.time() < deadline:
                _time.sleep(0.2)
                u = self._lookup_claude_uuid(session_id)
                if u:
                    return u
            return ""

        pg_url = (
            os.environ.get("CONTINUOUS_CLAUDE_DB_URL")
            or os.environ.get("DATABASE_URL")
        )
        if not pg_url:
            # Item-8 postgres hardening (2026-05-06): TCP auth on
            # localhost:5432 is scram-sha-256 with per-role secret files;
            # claude:claude_dev no longer authenticates. cc_app is the
            # designated application role.
            try:
                with open(
                    os.path.expanduser(
                        "~/.claude/secrets/postgres-cc_app-password"
                    ),
                    "r",
                    encoding="utf-8",
                ) as fh:
                    _cc_app_pw = fh.read().strip()
            except OSError:
                _cc_app_pw = ""
            if _cc_app_pw:
                from urllib.parse import quote as _pg_quote

                pg_url = (
                    "postgresql://cc_app:"
                    + _pg_quote(_cc_app_pw, safe="")
                    + "@localhost:5432/continuous_claude"
                )
            else:
                pg_url = "postgresql://claude:claude_dev@localhost:5432/continuous_claude"

        async def _wait() -> str:
            conn = await asyncpg.connect(pg_url)
            try:
                # Re-check after the connection is up: the row may have
                # arrived between the caller's first lookup and our LISTEN.
                row = await conn.fetchrow(
                    "SELECT claude_uuid FROM sessions WHERE id = $1", session_id
                )
                if row and row["claude_uuid"]:
                    return row["claude_uuid"]

                evt = asyncio.Event()
                hit = {"uuid": ""}

                def _cb(_c, _pid, _channel, payload):
                    if payload == session_id:
                        evt.set()

                await conn.add_listener("session_ready", _cb)
                try:
                    await asyncio.wait_for(evt.wait(), timeout=timeout_s)
                except asyncio.TimeoutError:
                    pass

                row = await conn.fetchrow(
                    "SELECT claude_uuid FROM sessions WHERE id = $1", session_id
                )
                if row and row["claude_uuid"]:
                    hit["uuid"] = row["claude_uuid"]
                return hit["uuid"]
            finally:
                try:
                    await conn.close()
                except Exception:
                    pass

        try:
            return asyncio.run(_wait())
        except Exception:
            return ""

    def _wait_for_session_ready_sqlite(self, session_id: str, timeout_s: float) -> str:
        """In-process replacement for the asyncpg LISTEN path: the internal
        register endpoint sets a threading.Event keyed by session id; we wake
        on it, with 200ms registry polling as the safety net (covers register
        landing between our registry check and the event subscription)."""
        evt = _session_ready_event(session_id)
        try:
            deadline = _time.time() + max(0.1, float(timeout_s))
            while True:
                row = _agent_registry_get("claude", session_id)
                if row and row.get("claude_uuid"):
                    return str(row["claude_uuid"])
                remaining = deadline - _time.time()
                if remaining <= 0:
                    return ""
                if evt.wait(timeout=min(0.2, remaining)):
                    evt.clear()
        finally:
            _discard_session_ready_event(session_id)

    def _lookup_session_age_seconds(self, session_id: str):
        """Returns seconds since the session row was inserted, or None if the
        row is missing / backend is unreachable. Used by /send-text to gate
        very-fresh terminals before bracketed-paste markers are honored."""
        session_id = _claude_native_session_id(session_id)
        if not session_id:
            return None
        return _claude_sessions_backend().session_age_seconds(session_id)

    def _lookup_terminal_tty(self, session_id: str) -> str:
        session_id = _claude_native_session_id(session_id)
        if not session_id:
            return ""
        return _claude_sessions_backend().terminal_tty(session_id)

    def _lookup_claude_pid(self, session_id: str) -> int:
        session_id = _claude_native_session_id(session_id)
        if not session_id:
            return 0
        return _claude_sessions_backend().claude_pid(session_id)

    # ----- /llm-route-stream: SSE streaming variant -----
    def _handle_llm_route_stream(self, q):
        """Same input as /llm-route but streams output via Server-Sent Events.
        SSE frames:
          event: chunk     data: <text fragment>
          event: done      data: {}
          event: error     data: {"message": "..."}
        """
        model = q.get("model", ["sonnet"])[0]
        if model not in ("sonnet", "haiku", "opus"):
            self.send_error(400, "model must be sonnet|haiku|opus")
            return

        try:
            payload = json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "body must be JSON")
            return

        prompt = (payload.get("prompt") or "").strip()
        system = (payload.get("system") or "").strip()
        max_chars = int(payload.get("max_chars") or 8000)
        if not prompt:
            self.send_error(400, "prompt required")
            return
        if len(prompt) > max_chars:
            prompt = prompt[:max_chars]

        claude_bin = HOME / ".local" / "bin" / "claude"
        if not claude_bin.exists():
            for candidate in ("/opt/homebrew/bin/claude", "/usr/local/bin/claude"):
                p = Path(candidate)
                if p.exists():
                    claude_bin = p
                    break
        if not claude_bin.exists():
            self.send_error(502, "claude CLI not found")
            return

        cmd = [
            str(claude_bin), "-p",
            "--output-format", "text",
            "--model", model,
            "--dangerously-skip-permissions",
        ]
        if system:
            cmd.extend(["--append-system-prompt", system])

        # SSE response headers
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        def write_sse(event: str, data: str):
            try:
                self.wfile.write(f"event: {event}\n".encode())
                # SSE multi-line data: each line prefixed with "data: "
                for line in data.split("\n"):
                    self.wfile.write(f"data: {line}\n".encode())
                self.wfile.write(b"\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                # Client disconnected; bail out
                raise

        # Initialize so Pyright sees `proc` as bound in the TimeoutExpired
        # branch even if Popen raises before assignment. None-check on every
        # pipe access — subprocess.Popen with PIPE returns non-None pipes,
        # but the type stub annotates them Optional[IO[str]].
        proc: subprocess.Popen | None = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                cwd="/tmp",
            )
            # Send the prompt
            assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
            proc.stdin.write(prompt)
            proc.stdin.close()

            while True:
                chunk = proc.stdout.read(64)  # small chunks for responsiveness
                if not chunk:
                    break
                try:
                    write_sse("chunk", chunk)
                except (BrokenPipeError, ConnectionResetError):
                    proc.terminate()
                    return

            proc.wait(timeout=120)
            if proc.returncode == 0:
                write_sse("done", json.dumps({"model": model}))
            else:
                err = (proc.stderr.read() or "").strip()[:300]
                write_sse("error", json.dumps({"message": err or "claude exited non-zero"}))
        except subprocess.TimeoutExpired:
            if proc is not None:
                try:
                    proc.kill()
                except Exception:
                    pass
            try:
                write_sse("error", json.dumps({"message": "claude timeout"}))
            except Exception:
                pass
        except Exception as e:
            try:
                write_sse("error", json.dumps({"message": f"{type(e).__name__}: {e}"}))
            except Exception:
                pass

    # ----- AppleScript helpers -----
    def _applescript_inject(self, window_match: str, text: str):
        safe_match = _as_escape(window_match)
        # Newlines submit prematurely in Claude's prompt — collapse to spaces.
        single_line = text.replace("\r", " ").replace("\n", " ").strip()
        safe_text = _as_escape(single_line)
        script = f'''
        tell application "Terminal"
          set targetWindow to missing value
          repeat with w in windows
            if name of w contains "{safe_match}" then
              set targetWindow to w
              exit repeat
            end if
          end repeat
          if targetWindow is missing value then
            return "no_window"
          end if
          activate
          set index of targetWindow to 1
          delay 0.25
        end tell
        tell application "System Events"
          keystroke "{safe_text}"
          delay 0.1
          keystroke return
        end tell
        return "ok"
        '''
        return _run_osascript(script)

    def _applescript_send_esc(self, window_match: str):
        safe_match = _as_escape(window_match)
        script = f'''
        tell application "Terminal"
          set targetWindow to missing value
          repeat with w in windows
            if name of w contains "{safe_match}" then
              set targetWindow to w
              exit repeat
            end if
          end repeat
          if targetWindow is missing value then
            return "no_window"
          end if
          activate
          set index of targetWindow to 1
          delay 0.2
        end tell
        tell application "System Events"
          key code 53
        end tell
        return "ok"
        '''
        return _run_osascript(script)

    # ----- /corpus: walk EVERY project dir under ~/.claude/projects/ -----
    def _handle_corpus(self, q):
        try:
            since = float(q.get("since", ["0"])[0])
        except ValueError:
            self.send_error(400, "since must be unix timestamp")
            return
        try:
            limit = int(q.get("limit", ["500"])[0])
        except ValueError:
            limit = 500

        projects_root = HOME / ".claude" / "projects"
        items = []
        for project_dir in projects_root.iterdir():
            if not project_dir.is_dir():
                continue
            if _is_excluded_project_dir_name(project_dir.name):
                continue
            for p in project_dir.glob("*.jsonl"):
                try:
                    st = p.stat()
                except OSError:
                    continue
                if st.st_mtime >= since:
                    items.append({
                        "session_id": p.stem,
                        "project_dir": project_dir.name,
                        "size": st.st_size,
                        "mtime": st.st_mtime,
                    })
        items.sort(key=lambda x: x["mtime"], reverse=True)
        items = items[:limit]
        body = json.dumps({"count": len(items), "items": items}).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- /inject: queue text for next user prompt -----
    def _handle_inject(self, q):
        session_id = q.get("session", [""])[0]
        session_id = _claude_native_session_id(session_id)
        if not session_id:
            self.send_error(400, "session required")
            return
        text = self._read_body().decode("utf-8", errors="replace").strip()
        if not text:
            self.send_error(400, "empty body")
            return

        queue_file = QUEUE_DIR / f"{session_id}.txt"
        with open(queue_file, "a") as f:
            f.write(text + "\n")

        self._send_text(200, b"queued\n")

    # ----- helpers -----
    def _send_text(self, code, body: bytes):
        try:
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError) as exc:
            raise ClientDisconnected() from exc

    def log_message(self, format, *args):
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")


class _PairlingThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = max(16, RUNTIME_MAX_ACTIVE_CONNECTIONS)

    def process_request(self, request, client_address):
        if not _CONNECTION_ADMISSION_SEMAPHORE.acquire(blocking=False):
            body = b'{"ok":false,"error":{"code":"connection_capacity_exceeded","message":"Pairling runtime is busy; retry shortly"},"retry_after":1}\n'
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Connection: close\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                    + body
                )
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            _CONNECTION_ADMISSION_SEMAPHORE.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            try:
                _CONNECTION_ADMISSION_SEMAPHORE.release()
            except ValueError:
                pass

    def handle_error(self, request, client_address):
        exc_type, exc, _ = sys.exc_info()
        if isinstance(exc, (BrokenPipeError, ConnectionResetError)) or exc_type in {BrokenPipeError, ConnectionResetError}:
            return
        super().handle_error(request, client_address)


def _maybe_backfill_claude_registry_from_pg() -> None:
    """One-time best-effort import of live PG session rows into the SQLite
    registry on the first sqlite-mode boot. Docker may be down — that is
    fine; live sessions re-register on their next hook fire. Never raises."""
    if _session_backend() != "sqlite":
        return
    if os.environ.get("PAIRLING_SKIP_PG_BACKFILL") == "1":
        return  # test harnesses / fresh installs skip the docker probe entirely
    try:
        if any(row.get("claude_uuid") for row in _agent_registry_live("claude")):
            return  # registry already has live claude rows — nothing to do
        sql = (
            "SELECT id, project, COALESCE(working_on, ''), "
            "COALESCE(claude_uuid, ''), COALESCE(terminal_tty, ''), "
            "COALESCE(claude_pid, 0), "
            "EXTRACT(EPOCH FROM started_at)::bigint, "
            "EXTRACT(EPOCH FROM last_heartbeat)::bigint "
            "FROM sessions "
            "WHERE closed_at IS NULL "
            "AND last_heartbeat > NOW() - INTERVAL '7 days' "
            "ORDER BY last_heartbeat DESC LIMIT 200;"
        )
        proc = subprocess.run(
            ["docker", "exec", "continuous-claude-postgres",
             "psql", "-U", "claude", "-d", "continuous_claude",
             "-A", "-F", "\t", "-t", "-c", sql],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            return
        imported = 0
        for line in (proc.stdout or "").strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 8 or not _safe_session_id(parts[0]):
                continue
            ok = _agent_registry_upsert(
                "claude",
                parts[0],
                parts[1],
                pid=int(parts[5]) if parts[5].isdigit() else 0,
                terminal_tty=parts[4],
                claude_uuid=parts[3],
                working_on=parts[2],
            )
            if ok:
                # Preserve the PG timeline instead of stamping "now": started_at
                # must survive for the bracketed-paste freshness guard, and a
                # fresh last_heartbeat would resurrect stale sessions as live.
                started_at = float(parts[6]) if parts[6].lstrip("-").isdigit() else 0
                heartbeat = float(parts[7]) if parts[7].lstrip("-").isdigit() else 0
                if started_at and heartbeat:
                    with _agent_registry_conn() as conn:
                        conn.execute(
                            "UPDATE agent_sessions SET started_at = ?, last_heartbeat = ? "
                            "WHERE provider = 'claude' AND native_id = ?",
                            (started_at, heartbeat, parts[0]),
                        )
                imported += 1
        if imported:
            print(
                f"[registry-backfill] imported {imported} live claude session rows from PG",
                file=sys.stderr, flush=True,
            )
    except Exception as exc:
        print(f"[registry-backfill] skipped: {type(exc).__name__}", file=sys.stderr, flush=True)


def _reconcile_broker_sessions_on_boot() -> None:
    if PTY_BROKER is None:
        return
    survivors: dict[str, dict] = {}
    deadline = _time.time() + 10
    last_error = ""
    while _time.time() < deadline:
        try:
            survivors = {
                str(item.get("session_id") or ""): item
                for item in PTY_BROKER.list_sessions()
                if isinstance(item, dict) and item.get("session_id")
            }
            break
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {str(exc)[:120]}"
            _time.sleep(0.25)
    if last_error and not survivors:
        print(f"[broker-reconcile] deferred: {last_error}", file=sys.stderr, flush=True)
        return

    for provider in ("claude", "codex"):
        for row in _agent_registry_live(provider):
            metadata = _registry_metadata_from_row(row)
            broker_id = str(metadata.get("broker_id") or "").strip()
            native_id = str(row.get("native_id") or "").strip()
            if not broker_id or not native_id:
                continue
            desc = survivors.get(broker_id)
            if desc is None:
                _agent_registry_mark_closed(provider, native_id)
                continue
            _agent_registry_update_control(
                provider,
                native_id,
                pid=_broker_pid(desc),
                terminal_tty=_broker_slave_tty(desc),
                state="running",
                reopen=True,
            )

    for approval in _pending_approvals_open():
        broker_id = str(approval.get("broker_id") or "").strip()
        request_nonce = str(approval.get("request_nonce") or "").strip()
        provider = str(approval.get("provider") or "").strip() or "claude"
        native_id = str(approval.get("native_id") or "").strip()
        if not native_id:
            _native, _broker, _tty = _approval_resolve_session(provider, str(approval.get("session_id") or ""))
            native_id = _native
        if broker_id and broker_id in survivors:
            if native_id:
                _write_agent_turn_state(
                    provider,
                    native_id,
                    "attention",
                    tool=str(approval.get("command_preview") or approval.get("tool_name") or "")[:80],
                    event="broker_reconcile",
                    request_nonce=request_nonce,
                    mac_install_id=getattr(PAIRING_STORE, "install_id", "") if PAIRING_STORE else "",
                )
            continue
        if request_nonce:
            _pending_approval_resolve_terminal(request_nonce, "session_gone")


if __name__ == "__main__":
    host = _bind_host()
    BOUND_HOST = host
    os.environ["PAIRLING_BOUND_HOST"] = host
    _maybe_backfill_claude_registry_from_pg()
    _reconcile_broker_sessions_on_boot()
    LIVE_ACTIVITY_PUBLISHER = _start_live_activity_publisher()
    STANDARD_TURN_PUSH_PUBLISHER = _start_standard_turn_push_publisher()
    MAC_HEALTH_PUSH_PUBLISHER = _start_mac_health_push_publisher()
    SENTINEL_PUSH_PUBLISHER = _start_sentinel_push_publisher()
    _start_codex_approval_scanner()
    server = _PairlingThreadingHTTPServer((host, PORT), Handler)
    server.daemon_threads = True
    print(f"pairlingd listening on {host}:{PORT}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
