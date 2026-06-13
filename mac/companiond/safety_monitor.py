"""Phase-0 bridge for a future Pairling Safety Monitor.

This module deliberately does not use Endpoint Security. It only exposes an
absent/simulated monitor contract so the runtime and iOS UI can integrate with
redacted safety summaries before a separately signed System Extension exists.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any


SAFETY_BRIDGE_CONTRACT_VERSION = "pairling-safety-v0"
SAFETY_CONTRACT_VERSION = "pairling-safety-v1"
SAFETY_STATUS_STALE_SECONDS = int(os.environ.get("PAIRLING_SAFETY_STATUS_STALE_SECONDS", str(24 * 60 * 60)))
SAFETY_EVENTS_MAX_READ_BYTES = max(
    64 * 1024,
    int(os.environ.get("PAIRLING_SAFETY_EVENTS_MAX_READ_BYTES", str(1024 * 1024))),
)
DEFAULT_STATUS = {
    "contract_version": SAFETY_BRIDGE_CONTRACT_VERSION,
    "mode": "absent",
    "installed": False,
    "approved": False,
    "running": False,
    "full_disk_access": "unknown",
    "visibility": "unavailable",
    "summary": "Pairling Safety Monitor is not installed.",
}
DEFAULT_EVIDENCE_TEST = {
    "status": "not_run",
    "process_observed": False,
    "file_observed": False,
    "message": "Evidence test has not been run.",
}

_ALLOWED_SEVERITIES = {"info", "watch", "warning", "critical", "danger"}
_SENSITIVE_PATH_RE = re.compile(
    r"(^|/)(\.ssh|\.gnupg|\.aws|\.config|Library/Keychains|Library/LaunchAgents)(/|$)"
)


def _now() -> float:
    return time.time()


def _safe_string(value: Any, fallback: str = "") -> str:
    if isinstance(value, str):
        return value[:500]
    if value is None:
        return fallback
    return str(value)[:500]


def _safe_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _severity(value: Any) -> str:
    raw = _safe_string(value, "info").lower()
    if raw == "danger":
        return "critical"
    if raw in _ALLOWED_SEVERITIES:
        return raw
    return "info"


def _redact_path(value: Any, home: Path) -> str | None:
    raw = _safe_string(value).strip()
    if not raw:
        return None
    if raw.startswith("~/"):
        return raw
    if raw == "~":
        return raw
    home_text = str(home)
    if raw == home_text:
        return "~"
    if raw.startswith(home_text + "/"):
        return "~/" + raw[len(home_text) + 1 :]
    return re.sub(r"^/Users/[^/]+", "/Users/<user>", raw)


def _safe_string_list(value: Any, *, limit: int = 12) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value[:limit]:
        text = _safe_string(item).strip()
        if text:
            items.append(text)
    return items


class SafetyMonitorBridge:
    def __init__(self, root: Path, home: Path | None = None) -> None:
        self.root = Path(root)
        self.home = Path(home or Path.home())
        self.dir = self.root / "safety"
        self.status_path = Path(os.environ.get("PAIRLING_SAFETY_STATUS_PATH", self.dir / "status.json"))
        self.events_path_env = os.environ.get("PAIRLING_SAFETY_EVENTS_PATH")
        self.events_path = Path(self.events_path_env or self.dir / "events.jsonl")
        self.system_events_path = Path(
            os.environ.get(
                "PAIRLING_SAFETY_SYSTEM_EVENTS_PATH",
                "/Library/Application Support/Pairling/safety/events.jsonl",
            )
        )
        self.acks_path = Path(os.environ.get("PAIRLING_SAFETY_ACKS_PATH", self.dir / "acks.jsonl"))
        self.evidence_test_path = Path(
            os.environ.get("PAIRLING_SAFETY_EVIDENCE_TEST_PATH", self.dir / "evidence-test.json")
        )

    def status(self) -> dict[str, Any]:
        status = dict(DEFAULT_STATUS)
        loaded, status_error = self._read_status_file_with_error()
        bridge_contract_version = SAFETY_BRIDGE_CONTRACT_VERSION
        if loaded:
            bridge_contract_version = _safe_string(
                loaded.get("contract_version"),
                SAFETY_BRIDGE_CONTRACT_VERSION,
            ) or SAFETY_BRIDGE_CONTRACT_VERSION
            for key in (
                "mode",
                "installed",
                "approved",
                "running",
                "full_disk_access",
                "full_disk_access_detail",
                "full_disk_access_probe",
                "visibility",
                "summary",
                "updated_at",
            ):
                if key in loaded:
                    status[key] = loaded[key]
        status["bridge_contract_version"] = bridge_contract_version
        status["contract_version"] = SAFETY_CONTRACT_VERSION
        if status_error:
            status["status_error"] = status_error
        status["status_stale"] = self._status_stale(status, loaded is not None)
        status["secure_mode_state"] = self._secure_mode_state(status)
        status["guarded_mode_state"] = "guarded_deferred"
        status["system_extension_status"] = self._system_extension_status(status)
        status["capabilities"] = self._capabilities(status)
        status["evidence_test"] = self._read_evidence_test()
        events = self.events(limit=200)
        status["event_count"] = len(events)
        status["high_risk_count"] = sum(
            1 for event in events if event.get("severity") in {"warning", "critical"}
        )
        status["updated_at"] = status.get("updated_at") or _now()
        return status

    def events(self, since: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for path in self._event_paths():
            if not path.exists():
                continue
            lines = self._recent_event_lines(path)
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(raw, dict):
                    continue
                event = self._normalize_event(raw)
                rows.append(event)
        if not rows:
            return []
        rows.sort(key=lambda item: (item.get("timestamp") or 0, item.get("id") or ""))
        if since:
            since_index = next((idx for idx, event in enumerate(rows) if event.get("id") == since), None)
            rows = rows[since_index + 1 :] if since_index is not None else []
        rows.sort(key=lambda item: (item.get("timestamp") or 0, item.get("id") or ""), reverse=True)
        return rows[: max(1, min(int(limit or 100), 300))]

    def _recent_event_lines(self, path: Path) -> list[str]:
        try:
            size = path.stat().st_size
            with path.open("rb") as fh:
                if size > SAFETY_EVENTS_MAX_READ_BYTES:
                    fh.seek(-SAFETY_EVENTS_MAX_READ_BYTES, os.SEEK_END)
                    fh.readline()
                data = fh.read(SAFETY_EVENTS_MAX_READ_BYTES)
        except OSError:
            return []
        return data.decode("utf-8", errors="replace").splitlines()

    def ack(self, ids: list[str] | None = None) -> dict[str, Any]:
        self.dir.mkdir(parents=True, exist_ok=True)
        normalized = [item for item in (ids or []) if isinstance(item, str) and item]
        record = {
            "ts": _now(),
            "ids": normalized,
            "scope": "selected" if normalized else "all_visible",
        }
        with self.acks_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return {"ok": True, "acknowledged": len(normalized), "scope": record["scope"]}

    def request_activation(self) -> dict[str, Any]:
        app_path = self._find_safety_app()
        if app_path is None:
            return {
                "ok": False,
                "state": "safety_app_missing",
                "error": {
                    "code": "safety_app_missing",
                    "message": "PairlingSafety.app is not installed on this Mac.",
                },
            }
        opener = shutil.which("open") or "/usr/bin/open"
        try:
            proc = subprocess.run(
                [opener, "-n", str(app_path), "--args", "--pairling-request-activation"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {
                "ok": False,
                "state": "activation_launch_failed",
                "error": {"code": "activation_launch_failed", "message": str(exc)[:300]},
            }
        if proc.returncode != 0:
            return {
                "ok": False,
                "state": "activation_launch_failed",
                "error": {
                    "code": "activation_launch_failed",
                    "message": (proc.stderr or proc.stdout or "open failed")[:300],
                },
            }
        return {
            "ok": True,
            "state": "approval_requested",
            "app_path": _redact_path(str(app_path), self.home),
            "message": "Open System Settings on the Mac to approve Pairling Safety Monitor.",
        }

    def open_full_disk_access(self) -> dict[str, Any]:
        opener = shutil.which("open") or "/usr/bin/open"
        uri = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
        try:
            proc = subprocess.run([opener, uri], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            return {
                "ok": False,
                "state": "settings_open_failed",
                "error": {"code": "settings_open_failed", "message": str(exc)[:300]},
            }
        if proc.returncode != 0:
            return {
                "ok": False,
                "state": "settings_open_failed",
                "error": {
                    "code": "settings_open_failed",
                    "message": (proc.stderr or proc.stdout or "open failed")[:300],
                },
            }
        return {
            "ok": True,
            "state": "settings_opened",
            "message": "Full Disk Access settings opened on the Mac.",
        }

    def run_evidence_test(self, wait_seconds: float = 8.0) -> dict[str, Any]:
        wait_seconds = max(0.0, min(float(wait_seconds), 8.0))
        test_id = f"evidence_test_{uuid.uuid4().hex[:12]}"
        before = {event.get("id") for event in self.events(limit=300)}
        started_at = _now()
        probe_dir = self.dir / "evidence-tests" / test_id
        process_ok = False
        file_ok = False
        error_message = ""
        try:
            probe_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(["/bin/echo", test_id], capture_output=True, text=True, timeout=5)
            probe_file = probe_dir / "probe.txt"
            probe_file.write_text(f"{test_id}\n", encoding="utf-8")
            probe_file.unlink(missing_ok=True)
            process_ok, file_ok = self._observe_evidence_events(before, started_at, wait_seconds)
        except (OSError, subprocess.SubprocessError) as exc:
            error_message = str(exc)[:300]
        finally:
            try:
                if probe_dir.exists():
                    for child in probe_dir.iterdir():
                        child.unlink(missing_ok=True)
                    probe_dir.rmdir()
            except OSError:
                pass
        secure_state = self.status().get("secure_mode_state", "secure_unavailable")
        if process_ok and file_ok:
            result_status = "passed"
            message = "Process and file evidence passed."
        elif process_ok:
            result_status = "limited"
            message = "Process evidence passed. File visibility is limited until Full Disk Access is granted."
        elif error_message:
            result_status = "failed"
            message = f"Evidence test failed: {error_message}"
        elif secure_state == "secure_unavailable":
            result_status = "failed"
            message = "Safety Monitor is unavailable, so no OS evidence was observed."
        else:
            result_status = "timed_out"
            message = "Evidence test timed out before matching OS evidence was observed."
        record = {
            "test_id": test_id,
            "last_run_at": started_at,
            "status": result_status,
            "secure_mode_state": secure_state,
            "process_observed": process_ok,
            "file_observed": file_ok,
            "message": message,
        }
        self._write_evidence_test(record)
        return {"ok": result_status in {"passed", "limited"}, **record}

    def _read_status_file(self) -> dict[str, Any] | None:
        payload, _ = self._read_status_file_with_error()
        return payload

    def _event_paths(self) -> list[Path]:
        paths = [self.events_path]
        if self.events_path_env:
            return paths
        default_user_root = self.home / "Library" / "Application Support" / "Pairling"
        if self.root == default_user_root and self.system_events_path != self.events_path:
            paths.append(self.system_events_path)
        return paths

    def _read_status_file_with_error(self) -> tuple[dict[str, Any] | None, str | None]:
        try:
            payload = json.loads(self.status_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None, None
        except json.JSONDecodeError:
            return None, "status_json_invalid"
        except OSError:
            return None, "status_unreadable"
        return (payload, None) if isinstance(payload, dict) else (None, "status_shape_invalid")

    def _normalize_event(self, raw: dict[str, Any]) -> dict[str, Any]:
        path_display = _redact_path(
            raw.get("path") or raw.get("path_display") or raw.get("redacted_path"),
            self.home,
        )
        project_root = _redact_path(raw.get("project_root") or raw.get("project"), self.home)
        severity = _severity(raw.get("severity") or raw.get("risk"))
        title = _safe_string(raw.get("title"), "Safety event").strip() or "Safety event"
        process_display = _safe_string(raw.get("process_display")).strip()
        subtitle = _safe_string(raw.get("summary") or raw.get("subtitle")).strip()
        if path_display and not subtitle:
            subtitle = path_display
        if process_display and not subtitle:
            subtitle = process_display
        event = {
            "contract_version": SAFETY_CONTRACT_VERSION,
            "id": _safe_string(raw.get("id")) or self._event_id(raw),
            "type": _safe_string(raw.get("type") or raw.get("event"), "safety") or "safety",
            "severity": severity,
            "timestamp": int(raw.get("timestamp") or raw.get("ts") or _now()),
            "session_id": _safe_string(raw.get("session_id"), "safety-monitor") or "safety-monitor",
            "project": _redact_path(raw.get("project"), self.home) or "Pairling Safety Monitor",
            "project_root": project_root,
            "orchestration_id": _safe_string(raw.get("orchestration_id")) or None,
            "worker_id": _safe_string(raw.get("worker_id")) or None,
            "provider_id": _safe_string(raw.get("provider_id")) or None,
            "pid": _safe_int(raw.get("pid")),
            "ppid": _safe_int(raw.get("ppid")),
            "title": title,
            "subtitle": subtitle or None,
            "state": _safe_string(raw.get("state")) or None,
            "tool": _safe_string(raw.get("tool")) or None,
            "context_pct": None,
            "entry_id": _safe_string(raw.get("entry_id")) or None,
            "path_display": path_display,
            "path_scope": _safe_string(raw.get("path_scope")) or self._path_scope(path_display, project_root),
            "process_display": process_display or None,
            "parent_chain": _safe_string_list(raw.get("parent_chain")),
            "code_signing_identity": _safe_string(raw.get("code_signing_identity")) or None,
            "source": _safe_string(raw.get("source"), "endpoint_security_notify") or "endpoint_security_notify",
            "raw_path_redacted": bool(raw.get("raw_path_redacted")) or bool(raw.get("path") or raw.get("project")),
            "notify_only": bool(raw.get("notify_only")),
            "file_contents_collected": False,
            "prompt_or_transcript_collected": False,
        }
        correlation = raw.get("correlation")
        if isinstance(correlation, dict):
            event["correlation"] = {
                "strategy": _safe_string(correlation.get("strategy")) or "unknown",
                "confidence": _safe_string(correlation.get("confidence")) or "unknown",
            }
        if path_display and _SENSITIVE_PATH_RE.search(path_display):
            event["severity"] = "critical" if severity == "warning" else severity
            if event["severity"] == "info":
                event["severity"] = "warning"
        return event

    def _event_id(self, raw: dict[str, Any]) -> str:
        stable = json.dumps(raw, sort_keys=True, default=str)
        digest = hashlib.sha256(stable.encode("utf-8")).hexdigest()[:16]
        return f"safety-{digest}"

    def _status_stale(self, status: dict[str, Any], loaded: bool) -> bool:
        if not loaded:
            return False
        updated_at = _safe_int(status.get("updated_at"))
        if updated_at is None:
            return True
        return (_now() - updated_at) > SAFETY_STATUS_STALE_SECONDS

    def _secure_mode_state(self, status: dict[str, Any]) -> str:
        if status.get("status_stale"):
            return "secure_unavailable"
        if not bool(status.get("installed")) or not bool(status.get("approved")) or not bool(status.get("running")):
            return "secure_unavailable"
        if _safe_string(status.get("full_disk_access")).lower() == "validated" or status.get("visibility") == "full":
            return "secure_full"
        return "secure_limited"

    def _system_extension_status(self, status: dict[str, Any]) -> str:
        if status.get("status_stale"):
            return "status_stale"
        if bool(status.get("running")):
            return "active"
        if bool(status.get("installed")) and not bool(status.get("approved")):
            return "approval_required"
        if bool(status.get("installed")):
            return "failed"
        return "not_installed"

    def _capabilities(self, status: dict[str, Any]) -> dict[str, Any]:
        secure_state = status.get("secure_mode_state") or self._secure_mode_state(status)
        running = secure_state in {"secure_limited", "secure_full"}
        full = secure_state == "secure_full"
        return {
            "notify_only": True,
            "auth_blocking": False,
            "process_lifecycle": "available" if running else "unavailable",
            "file_touches": "available" if full else ("limited" if running else "unavailable"),
            "process_tree": "available" if running else "unavailable",
            "sensitive_path_warnings": "available" if running else "unavailable",
        }

    def _read_evidence_test(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.evidence_test_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return dict(DEFAULT_EVIDENCE_TEST)
        if not isinstance(payload, dict):
            return dict(DEFAULT_EVIDENCE_TEST)
        return {
            "test_id": _safe_string(payload.get("test_id")) or None,
            "last_run_at": payload.get("last_run_at"),
            "status": _safe_string(payload.get("status"), "not_run") or "not_run",
            "secure_mode_state": _safe_string(payload.get("secure_mode_state")) or None,
            "process_observed": bool(payload.get("process_observed")),
            "file_observed": bool(payload.get("file_observed")),
            "message": _safe_string(payload.get("message"), DEFAULT_EVIDENCE_TEST["message"]),
        }

    def _write_evidence_test(self, record: dict[str, Any]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.evidence_test_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self.evidence_test_path)

    def _observe_evidence_events(
        self,
        before_ids: set[Any],
        started_at: float,
        wait_seconds: float,
    ) -> tuple[bool, bool]:
        deadline = _now() + wait_seconds
        process_ok = False
        file_ok = False
        while True:
            for event in self.events(limit=300):
                if event.get("id") in before_ids:
                    continue
                if float(event.get("timestamp") or 0) < started_at - 1:
                    continue
                event_type = _safe_string(event.get("type"))
                if event_type.startswith("process_"):
                    process_ok = True
                if event_type.startswith("file_"):
                    file_ok = True
            if process_ok and file_ok:
                return True, True
            if _now() >= deadline:
                return process_ok, file_ok
            time.sleep(0.25)

    def _find_safety_app(self) -> Path | None:
        candidates = []
        configured = os.environ.get("PAIRLING_SAFETY_APP_PATH", "").strip()
        if configured:
            candidates.append(Path(configured))
        repo_root = os.environ.get("PAIRLING_REPO_ROOT", "").strip()
        if repo_root:
            candidates.append(Path(repo_root) / "dist" / "safety-monitor" / "PairlingSafety.app")
        candidates.extend([
            Path("/Applications/PairlingSafety.app"),
            self.home / "Applications" / "PairlingSafety.app",
            self.home / "projects" / "Pairling" / "dist" / "safety-monitor" / "PairlingSafety.app",
        ])
        for candidate in candidates:
            if candidate.exists() and candidate.suffix == ".app":
                return candidate
        return None

    def _path_scope(self, path_display: str | None, project_root: str | None) -> str | None:
        if not path_display:
            return None
        if project_root and (path_display == project_root or path_display.startswith(project_root.rstrip("/") + "/")):
            return "inside_project"
        if path_display.startswith("~/") or path_display.startswith("/"):
            return "outside_project"
        return None
