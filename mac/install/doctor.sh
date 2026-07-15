#!/usr/bin/env bash
set -euo pipefail

export PYTHONDONTWRITEBYTECODE=1
if [[ -z "${PYTHONPYCACHEPREFIX:-}" ]]; then
  PYTHONPYCACHEPREFIX="${TMPDIR:-/tmp}/pairling-pycache-$(id -u)"
  mkdir -p "$PYTHONPYCACHEPREFIX" 2>/dev/null || true
  export PYTHONPYCACHEPREFIX
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCTOR_APP_SUPPORT="${PAIRLING_APP_SUPPORT_ROOT:-${COMPANION_APP_SUPPORT_ROOT:-$HOME/Library/Application Support/Pairling}}"

resolve_python_bin() {
  local explicit="${PAIRLING_DAEMON_PYTHON:-${COMPANION_DAEMON_PYTHON:-}}"
  local candidate
  if [[ -n "$explicit" ]]; then
    if [[ ! -x "$explicit" ]]; then
      printf 'ERROR: configured Pairling Python is not executable: %s\n' "$explicit" >&2
      return 1
    fi
    printf '%s\n' "$explicit"
    return 0
  fi
  candidate="$DOCTOR_APP_SUPPORT/runtime/current/python/bin/python3"
  if [[ -x "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  candidate="$(command -v python3 2>/dev/null || true)"
  if [[ -n "$candidate" && -x "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  if [[ -x /usr/bin/python3 ]]; then
    printf '/usr/bin/python3\n'
    return 0
  fi
  printf 'ERROR: Pairling could not resolve a Python 3 interpreter. Reinstall the Pairling runtime package.\n' >&2
  return 1
}

PYTHON3_BIN="$(resolve_python_bin)"
JSON_MODE="false"
FIRST_RUN_MODE="false"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)
      JSON_MODE="true"
      ;;
    --first-run)
      FIRST_RUN_MODE="true"
      ;;
    --ssh-print-key)
      # SPEC-p5 §6: re-display the SSH host fingerprint the phone pins,
      # without re-running setup. The authorized_keys line for a generated
      # client key is printed by `setup --ssh`.
      exec "$PYTHON3_BIN" "$REPO_ROOT/mac/install/ssh_gateway_setup.py" host-fingerprint
      ;;
    --help|-h)
      cat <<EOF
usage: pairling doctor [--json] [--first-run] [--ssh-print-key]

Validates the Pairling Mac runtime. --first-run adds a machine-readable
readiness contract for onboarding and pairing rehearsals. --ssh-print-key
re-displays the SSH host-key fingerprint the phone pins (SPEC-p5).
EOF
      exit 0
      ;;
    *)
      echo "usage: pairling doctor [--json] [--first-run] [--ssh-print-key]" >&2
      exit 2
      ;;
  esac
  shift
done

"$PYTHON3_BIN" - "$REPO_ROOT" "$JSON_MODE" "$FIRST_RUN_MODE" <<'PY'
from __future__ import annotations

import json
import os
import plistlib
import re
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import closing
from pathlib import Path

repo_root = Path(sys.argv[1])
json_mode = sys.argv[2] == "true"
first_run_mode = sys.argv[3] == "true"
home = Path.home()

PAIRLING_PORT = int(os.environ.get("PAIRLING_RUNTIME_PORT", "7773"))
PAIRLING_LABEL = "dev.pairling.companiond"
PAIRLING_CONNECTD_LABEL = "dev.pairling.connectd"
PAIRLING_PTYBROKER_LABEL = "dev.pairling.ptybroker"
INTERNAL_DEVICE_PURPOSES = ("runtime_truth_smoke", "local_mcp_bridge")
TEAM_ID = os.environ.get("PAIRLING_TEAM_ID", os.environ.get("PAIRLING_CONNECTD_TEAM_ID", "965AVD34A3"))
APP_SUPPORT = Path(os.environ.get("PAIRLING_APP_SUPPORT_ROOT", os.environ.get("COMPANION_APP_SUPPORT_ROOT", str(home / "Library" / "Application Support" / "Pairling"))))
LOGS_ROOT = Path(os.environ.get("PAIRLING_LOGS_ROOT", os.environ.get("COMPANION_LOGS_ROOT", str(home / "Library" / "Logs" / "Pairling"))))
CURRENT = APP_SUPPORT / "runtime" / "current"
MANIFEST_PATH = CURRENT / "manifest.json"
DEVICES_DB = APP_SUPPORT / "devices.sqlite"
MCP_CREDENTIAL = Path(os.environ.get("PAIRLING_MCP_CREDENTIAL", str(APP_SUPPORT / "mcp-bridge.json")))
MCP_ADAPTER = CURRENT / "mcp" / "phone_tools.py"
MCP_SHIM = home / ".claude" / "mcp-servers" / "phone-tools.py"
USER_PAIRLING = Path(os.environ.get("PAIRLING_USER_BIN_DIR", str(home / ".local" / "bin"))) / "pairling"
PAIR_ROOT = APP_SUPPORT / "pair"
USER_PLIST = home / "Library" / "LaunchAgents" / f"{PAIRLING_LABEL}.plist"
CONNECTD_USER_PLIST = home / "Library" / "LaunchAgents" / f"{PAIRLING_CONNECTD_LABEL}.plist"
PTYBROKER_USER_PLIST = home / "Library" / "LaunchAgents" / f"{PAIRLING_PTYBROKER_LABEL}.plist"
CLAUDE_INJECTOR = home / "Applications" / "ClaudeInjector.app" / "Contents" / "MacOS" / "ClaudeInjector"

sys.path.insert(0, str(repo_root / "mac" / "companiond"))
from pairling_connectd_status import fetch_connectd_status, redacted_connectd_summary
from runtime_manifest import (
    classify_ptybroker_identity,
    verified_managed_release_identity,
)

checks = []

READ_ONLY_DB_ATTEMPTS = 4
READ_ONLY_DB_INITIAL_DELAY_SECONDS = 0.05


def add(identifier, ok, severity, summary, evidence=None):
    checks.append({
        "id": identifier,
        "status": "ok" if ok else "fail",
        "severity": severity,
        "summary": summary,
        "evidence": evidence,
    })


def connect_read_only_database(path: Path) -> sqlite3.Connection:
    uri = path.resolve(strict=False).as_uri() + "?mode=ro"
    for attempt in range(READ_ONLY_DB_ATTEMPTS):
        try:
            return sqlite3.connect(uri, uri=True, timeout=1.0)
        except sqlite3.OperationalError:
            if attempt + 1 >= READ_ONLY_DB_ATTEMPTS:
                raise
            time.sleep(READ_ONLY_DB_INITIAL_DELAY_SECONDS * (2**attempt))
    raise AssertionError("read-only database retry loop exhausted")


def codesigning_identity_summary(output: str) -> dict:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    developer_id_lines = [line for line in lines if "Developer ID Application:" in line]
    expected_team_present = any(f"({TEAM_ID})" in line for line in developer_id_lines)
    valid_count = None
    for line in lines:
        match = re.search(r"(\d+)\s+valid identities found", line)
        if match:
            valid_count = int(match.group(1))
            break
    return {
        "valid_identity_count": valid_count,
        "developer_id_application_count": len(developer_id_lines),
        "expected_team_present": expected_team_present,
    }


def run(args, timeout=5):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except Exception as exc:
        return 127, "", f"{type(exc).__name__}: {exc}"


def developer_id_requirement(team_id: str) -> str:
    return (
        "anchor apple generic and "
        f'certificate leaf[subject.OU] = "{team_id}" and '
        "certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    )


def load_plist(path):
    with path.open("rb") as fh:
        return plistlib.load(fh)


def valid_install_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if len(candidate) > 256 or re.fullmatch(r"inst_[A-Za-z0-9_-]+", candidate) is None:
        return None
    return candidate


def read_identity_file(path: Path) -> str:
    for directory in {APP_SUPPORT, path.parent}:
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError(f"unsafe identity directory: {directory}")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError(f"unsafe identity file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(f"unsafe identity file: {path}")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            return handle.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def install_identity_coherence() -> tuple[bool, dict]:
    """Read every local install identity source without repairing any of them."""
    issues: list[str] = []

    config_install_id = None
    try:
        payload = json.loads(read_identity_file(APP_SUPPORT / "config.json"))
        candidate = valid_install_id(payload.get("install_id"))
        if candidate:
            config_install_id = candidate
        else:
            issues.append("config_install_id_invalid")
    except FileNotFoundError:
        issues.append("config_install_id_missing")
    except Exception:
        issues.append("config_install_id_unreadable")

    state_install_id = None
    try:
        candidate = valid_install_id(
            read_identity_file(APP_SUPPORT / "state" / "install-id")
        )
        if candidate:
            state_install_id = candidate
        else:
            issues.append("state_install_id_invalid")
    except FileNotFoundError:
        issues.append("state_install_id_missing")
    except Exception:
        issues.append("state_install_id_unreadable")

    active_install_ids: list[str] = []
    revoked_install_ids: list[str] = []
    invalid_active_install_id_count = 0
    if DEVICES_DB.exists() and not DEVICES_DB.is_symlink() and stat.S_ISREG(DEVICES_DB.stat().st_mode):
        try:
            with closing(connect_read_only_database(DEVICES_DB)) as db:
                columns = {
                    str(row[1])
                    for row in db.execute("PRAGMA table_info(devices)").fetchall()
                }
                if "install_id" not in columns:
                    issues.append("devices_install_id_column_missing")
                else:
                    active_where = ["revoked_at IS NULL"]
                    active_params: list[object] = []
                    if "activation_state" in columns:
                        active_where.append("COALESCE(activation_state, 'active') = 'active'")
                    if "purpose" in columns:
                        active_where.append("COALESCE(purpose, '') NOT IN (?, ?)")
                        active_params.extend(INTERNAL_DEVICE_PURPOSES)
                    active_rows = db.execute(
                        "SELECT DISTINCT install_id FROM devices WHERE "
                        + " AND ".join(active_where),
                        active_params,
                    ).fetchall()
                    normalized_active_install_ids = [valid_install_id(row[0]) for row in active_rows]
                    invalid_active_install_id_count = sum(
                        1 for install_id in normalized_active_install_ids if not install_id
                    )
                    active_install_ids = sorted({
                        install_id
                        for install_id in normalized_active_install_ids
                        if install_id
                    })
                    if invalid_active_install_id_count:
                        issues.append("active_install_id_invalid")
                    revoked_where = ["revoked_at IS NOT NULL"]
                    revoked_params: list[object] = []
                    if "purpose" in columns:
                        revoked_where.append("COALESCE(purpose, '') NOT IN (?, ?)")
                        revoked_params.extend(INTERNAL_DEVICE_PURPOSES)
                    revoked_rows = db.execute(
                        "SELECT DISTINCT install_id FROM devices WHERE "
                        + " AND ".join(revoked_where),
                        revoked_params,
                    ).fetchall()
                    revoked_install_ids = sorted(
                        install_id
                        for row in revoked_rows
                        if (install_id := valid_install_id(row[0])) is not None
                    )
        except Exception:
            issues.append("devices_install_ids_unreadable")
    else:
        issues.append("devices_database_missing")

    mcp_install_id = None
    try:
        payload = json.loads(read_identity_file(MCP_CREDENTIAL))
        candidate = valid_install_id(payload.get("install_id"))
        if candidate:
            mcp_install_id = candidate
        else:
            issues.append("mcp_install_id_invalid")
    except FileNotFoundError:
        issues.append("mcp_install_id_missing")
    except Exception:
        issues.append("mcp_install_id_unreadable")

    if config_install_id and state_install_id and state_install_id != config_install_id:
        issues.append("state_install_id_mismatch")
    if len(active_install_ids) > 1:
        issues.append("multiple_active_install_ids")
    elif config_install_id and active_install_ids and active_install_ids[0] != config_install_id:
        issues.append("active_install_id_mismatch")
    if config_install_id and mcp_install_id and mcp_install_id != config_install_id:
        issues.append("mcp_install_id_mismatch")

    other_revoked_install_ids = [
        install_id
        for install_id in revoked_install_ids
        if not config_install_id or install_id != config_install_id
    ]
    evidence = {
        "config_install_id": config_install_id,
        "state_install_id": state_install_id,
        "active_install_ids": active_install_ids,
        "active_install_id_count": len(active_install_ids),
        "invalid_active_install_id_count": invalid_active_install_id_count,
        "mcp_install_id": mcp_install_id,
        "revoked_other_install_ids": other_revoked_install_ids,
        "revoked_other_install_id_count": len(other_revoked_install_ids),
        "issue_codes": sorted(set(issues)),
    }
    return not issues, evidence


def writable_dir(path: Path) -> tuple[bool, str]:
    descriptor = -1
    probe = None
    try:
        path.mkdir(parents=True, exist_ok=True)
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise OSError("path is not a real directory")
        descriptor, raw_probe = tempfile.mkstemp(
            prefix=".pairling-doctor-write-",
            dir=path,
        )
        probe = Path(raw_probe)
        os.write(descriptor, b"ok")
        os.close(descriptor)
        descriptor = -1
        probe.unlink()
        return True, str(path)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if probe is not None:
            try:
                probe.unlink()
            except FileNotFoundError:
                pass


def port_listeners(port: int) -> list[str]:
    code, out, err = run(["/usr/sbin/lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"], timeout=3)
    if code != 0:
        return []
    return [line.strip() for line in out.splitlines()[1:] if line.strip()]


def tcp_accepts(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def detected_tailnet_ip() -> str | None:
    override = os.environ.get("PAIRLING_TEST_TAILSCALE_IP")
    if override is not None:
        value = override.strip()
        return value if value.startswith("100.") else None
    code, out, _ = run(["tailscale", "ip", "-4"], timeout=3)
    if code != 0:
        return None
    for line in out.splitlines():
        ip = line.strip()
        if ip.startswith("100."):
            return ip
    return None


def permission_readiness() -> dict:
    helper_installed = CLAUDE_INJECTOR.exists()
    grantee_path = str(CLAUDE_INJECTOR if helper_installed else Path("/usr/bin/osascript"))
    return {
        "ios_local_network": {
            "required_for": ["bonjour_pairing", "lan_route_validation"],
            "status": "requires_user_prompt",
        },
        "ios_camera": {
            "required_for": ["qr_scan"],
            "status": "not_requested",
        },
        "mac_accessibility": {
            "required_for": ["terminal_ui_synthesis"],
            "status": "not_required_until_terminal_control",
            "grantee_path": grantee_path,
            "helper_installed": helper_installed,
            "helper_path": str(CLAUDE_INJECTOR),
            "doctor_probe": "reports_required_grantee",
        },
        "mac_automation": {
            "required_for": ["terminal_app_control"],
            "status": "not_required_by_default",
            "grantee_path": grantee_path,
            "doctor_probe": "reports_required_grantee",
        },
        "privacy_database": "not_modified",
    }


def active_pair_records(pair_root: Path) -> list[dict]:
    now = time.time()
    records: list[dict] = []
    if not pair_root.exists():
        return records
    for path in pair_root.glob("*.json"):
        try:
            payload = json.loads(path.read_text())
            expires_at = float(payload.get("expires_at") or 0)
        except Exception:
            continue
        if expires_at <= now:
            continue
        records.append({
            "pair_id": payload.get("pair_id") or path.stem,
            "runtime_port": payload.get("runtime_port"),
            "expires_at": expires_at,
            "expires_in": max(0, int(expires_at - now)),
        })
    records.sort(key=lambda item: float(item["expires_at"]), reverse=True)
    return records


def desired_ptybroker_identity() -> dict:
    revision = None
    if manifest and manifest.get("source_revision"):
        revision = str(manifest.get("source_revision"))
    elif (CURRENT / "mac" / "SOURCE_REVISION").is_file():
        try:
            revision = (CURRENT / "mac" / "SOURCE_REVISION").read_text().strip() or None
        except Exception:
            revision = None
    desired_root = CURRENT.resolve() if CURRENT.exists() else CURRENT
    return {
        "runtime_root": str(desired_root),
        "script_path": str(desired_root / "companiond" / "pty_broker_service.py"),
        "source_revision": revision,
        "protocol_version": 1,
    }


def ptybroker_status_rpc() -> tuple[dict | None, str | None]:
    try:
        sys.path.insert(0, str(CURRENT / "companiond"))
        from pty_broker_client import PTYBrokerClient, ensure_pty_broker_token

        companion = home / ".claude" / "companion"
        client = PTYBrokerClient(companion / "pty-broker.sock", ensure_pty_broker_token(companion), timeout=1.0)
        status = client.status()
        return status if isinstance(status, dict) else {}, None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def safety_monitor_status() -> dict:
    # Report the live SafetyMonitorBridge status, not a guess from local files.
    # The bridge is imported from the staged companiond, the same copy the daemon
    # runs. When no runtime is staged or the import fails, report a structured
    # value with installed false, so the doctor JSON stays pure and never leaks a
    # traceback. The bridge itself defaults to installed false when the future
    # PairlingSafety.app is not present, which is today's true value.
    try:
        sys.path.insert(0, str(CURRENT / "companiond"))
        from safety_monitor import SafetyMonitorBridge
        bridge = SafetyMonitorBridge(APP_SUPPORT, home)
        status = bridge.status()
        return {
            "installed": bool(status.get("installed")),
            "full_disk_access": status.get("full_disk_access") or "unknown",
            "system_extension_status": status.get("system_extension_status"),
            "secure_mode_state": status.get("secure_mode_state"),
            "live_artifact": status.get("live_artifact"),
            "disk_usage_warning": status.get("disk_usage_warning"),
            "summary": status.get("summary") or "",
            "source": "live_bridge_status",
        }
    except Exception as exc:
        return {
            "installed": False,
            "full_disk_access": "unknown",
            "source": "live_bridge_status",
            "error": str(exc)[:200],
        }


def ptybroker_deployment_status(*, launchd_loaded: bool) -> dict:
    desired = desired_ptybroker_identity()
    base = {
        "label": PAIRLING_PTYBROKER_LABEL,
        "state": "unknown",
        "restart_deferred": False,
        "pid": None,
        "live_session_count": None,
        "live_source_revision": None,
        "desired_source_revision": desired.get("source_revision"),
        "desired_runtime_root": desired.get("runtime_root"),
        "desired_script_path": desired.get("script_path"),
        "evidence": None,
    }
    if not MANIFEST_PATH.is_file() and not CURRENT.exists():
        return {**base, "state": "not_installed", "evidence": "runtime/current is missing"}
    if not launchd_loaded:
        return {**base, "state": "not_running", "evidence": "launchd label is not running"}
    live, error = ptybroker_status_rpc()
    if live is None:
        return {**base, "state": "unreachable_socket", "evidence": error}
    state, reasons = classify_ptybroker_identity(live, desired)
    if not isinstance(live, dict):
        return {**base, "state": state, "reasons": reasons, "evidence": "status response is not an object"}
    live_root = live.get("runtime_root")
    live_script = live.get("script_path")
    live_revision = live.get("source_revision")
    pid = live.get("pid")
    live_session_count = live.get("live_session_count")
    return {
        **base,
        "state": state,
        "restart_deferred": state == "stale_deferred",
        "pid": pid,
        "live_session_count": live_session_count,
        "live_source_revision": live_revision,
        "live_runtime_root": live_root,
        "live_script_path": live_script,
        "protocol_version": live.get("protocol_version"),
        "code_version": live.get("code_version"),
        "started_at": live.get("started_at"),
        "reasons": reasons,
        "evidence": live,
    }


def first_run_stage(*, installed: bool, running: bool, pair_window_open: bool, remote_ready: bool) -> str:
    if not installed:
        return "helper_missing"
    if not running:
        return "runtime_not_ready"
    if remote_ready and pair_window_open:
        return "remote_ready"
    if pair_window_open:
        return "pair_window_open"
    if not remote_ready:
        return "remote_route_missing"
    return "helper_running"


def next_action_for_stage(stage: str, *, remote_status: str, pair_window_open: bool) -> dict:
    if stage == "remote_ready":
        return {
            "id": "pair_iphone",
            "label": "Pair iPhone",
            "message": "Open Pairling on iPhone and pair with this Mac.",
        }
    if pair_window_open and remote_status != "ready":
        return {
            "id": "pair_local_or_retry_connect",
            "label": "Pair locally or retry Connect",
            "message": "A local pairing invitation is open. Pair locally now, or retry Pairling Connect after this Mac is ready.",
        }
    if stage == "remote_route_missing":
        return {
            "id": "authenticate_pairling_connect",
            "label": "Authenticate Pairling Connect",
            "message": "Approve Pairling Connect in the browser, then recheck this Mac.",
        }
    if stage == "helper_running":
        return {
            "id": "open_pairing_invitation",
            "label": "Open pairing invitation",
            "message": "Run pairling pair to open a pairing invitation, then pair from the iPhone.",
        }
    if stage == "runtime_not_ready":
        return {
            "id": "start_runtime",
            "label": "Start the Pairling runtime",
            "message": "Run pairling setup and review the failing runtime checks.",
        }
    return {
        "id": "install_cli",
        "label": "Install the Pairling CLI",
        "message": "Run npm install -g pairling then pairling setup on this Mac before pairing.",
    }


manifest = None
release_root = None
managed_release_identity = None
managed_release_error = None
try:
    if not CURRENT.is_symlink():
        raise OSError("runtime/current is not a symlink")
    literal_target = Path(os.readlink(CURRENT))
    if not literal_target.is_absolute():
        raise OSError("runtime/current must use an absolute release target")
    releases_root = CURRENT.parent / "releases"
    current_before = CURRENT.resolve(strict=True)
    managed_release_identity = verified_managed_release_identity(
        literal_target,
        releases_root,
    )
    release_root = Path(managed_release_identity["root"])
    current_after = CURRENT.resolve(strict=True)
    if current_before != release_root or current_after != release_root:
        raise OSError("runtime/current changed during managed release verification")
    add(
        "current_release_link",
        True,
        "error",
        "runtime/current names a verified managed release directly.",
        {
            "target": str(literal_target),
            "runtime_version": managed_release_identity["runtime_version"],
            "source_revision": managed_release_identity["source_revision"],
            "source_dirty": managed_release_identity["source_dirty"],
        },
    )
except Exception as exc:
    managed_release_error = f"{type(exc).__name__}: {exc}"
    managed_release_identity = None
    release_root = None
    add(
        "current_release_link",
        False,
        "error",
        f"runtime/current is not a verified managed release: {managed_release_error}",
        str(CURRENT),
    )

verified_manifest_path = release_root / "manifest.json" if release_root is not None else MANIFEST_PATH
if verified_manifest_path.is_symlink():
    add("manifest_exists", False, "error", "Installed Pairling manifest must not be a symlink.", str(verified_manifest_path))
elif verified_manifest_path.is_file() and managed_release_identity is not None:
    try:
        manifest = json.loads(verified_manifest_path.read_text())
        add("manifest_exists", True, "error", "Installed Pairling manifest exists.", str(verified_manifest_path))
    except Exception as exc:
        add("manifest_exists", False, "error", f"Manifest is unreadable: {type(exc).__name__}: {exc}", str(verified_manifest_path))
else:
    add("manifest_exists", False, "error", "Installed Pairling manifest is missing or its managed release identity failed.", str(verified_manifest_path))

if managed_release_identity is not None:
    add(
        "runtime_release_sealed",
        True,
        "error",
        "Installed Pairling release passed the managed inventory, seal, and ACL proof.",
        managed_release_identity,
    )
else:
    add(
        "runtime_release_sealed",
        False,
        "error",
        "Installed Pairling release did not pass the managed inventory, seal, and ACL proof.",
        managed_release_error,
    )

if manifest and managed_release_identity is not None and release_root is not None:
    manifest_contract_ok = manifest.get("contract_version") == "pairling-runtime-v1" and manifest.get("schema_version") == 2
    add("manifest_contract", manifest_contract_ok, "error", "Manifest contract and schema are current.", {"contract_version": manifest.get("contract_version"), "schema_version": manifest.get("schema_version")})
    runtime = manifest.get("runtime") if isinstance(manifest.get("runtime"), dict) else {}
    add("runtime_port", runtime.get("port") == PAIRLING_PORT, "error", "Runtime port is locked to 7773.", runtime.get("port"))
    launchd = manifest.get("launchd") if isinstance(manifest.get("launchd"), dict) else {}
    launchd_evidence = {
        "daemon_label": launchd.get("daemon_label"),
        "ptybroker_label": launchd.get("ptybroker_label"),
        "connectd_label": launchd.get("connectd_label"),
    }
    add("launchd_labels", launchd.get("daemon_label") == PAIRLING_LABEL and launchd.get("ptybroker_label") == PAIRLING_PTYBROKER_LABEL and launchd.get("connectd_label") == PAIRLING_CONNECTD_LABEL, "error", "Manifest launchd labels are Pairling labels.", launchd_evidence)
    add(
        "manifest_hashes",
        True,
        "error",
        "Installed runtime exactly matches its schema 2 managed release manifest and identity stamps.",
        managed_release_identity,
    )
else:
    add("manifest_contract", False, "error", "Cannot validate contract without manifest.")
    add("runtime_port", False, "error", "Cannot validate runtime port without manifest.")
    add("launchd_labels", False, "error", "Cannot validate labels without manifest.")
    add("manifest_hashes", False, "error", "Cannot validate hashes without manifest.")

compile_targets = [
    repo_root / "mac" / "install" / "render-launchd.py",
]
compile_errors = []
for target in compile_targets:
    code, out, err = run([sys.executable, "-m", "py_compile", str(target)])
    if code != 0:
        compile_errors.append(f"{target}: {err or out}")
add("lifecycle_sources_compile", not compile_errors, "error", "Lifecycle sources compile." if not compile_errors else "Lifecycle compile failed.", compile_errors)

ok, evidence = writable_dir(APP_SUPPORT)
add("app_support_writable", ok, "error", "App support directory is writable.", evidence)
ok, evidence = writable_dir(LOGS_ROOT)
add("logs_writable", ok, "error", "Logs directory is writable.", evidence)

if DEVICES_DB.exists():
    try:
        with closing(connect_read_only_database(DEVICES_DB)) as db:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        add("devices_db", {"devices", "audit_events"}.issubset(tables), "error", "Devices database has required tables.", sorted(tables))
    except Exception as exc:
        add("devices_db", False, "error", f"Devices database is unreadable: {type(exc).__name__}: {exc}", str(DEVICES_DB))
else:
    add("devices_db", False, "error", "Devices database is missing.", str(DEVICES_DB))

identity_ok, identity_evidence = install_identity_coherence()
add(
    "install_identity_coherence",
    identity_ok,
    "error",
    (
        "Installer, state, active device, and MCP identities agree."
        if identity_ok
        else "Pairling install identities disagree or cannot be verified."
    ),
    identity_evidence,
)

try:
    sys.path.insert(0, str(repo_root / "mac" / "companiond"))
    from pairling_devices import DeviceRegistry
    from local_mcp_bridge import validate_local_mcp_bridge_credential

    valid, evidence = validate_local_mcp_bridge_credential(
        registry=DeviceRegistry(DEVICES_DB, LOGS_ROOT / "audit.jsonl"),
        credential_path=MCP_CREDENTIAL,
        install_id=str(identity_evidence.get("config_install_id") or ""),
    )
    add(
        "mcp_bridge_credential",
        valid,
        "error",
        (
            "Local Pairling MCP bridge credential is valid and scoped."
            if valid
            else f"Local Pairling MCP bridge credential is invalid: {evidence}"
        ),
        evidence,
    )
except Exception as exc:
    add(
        "mcp_bridge_credential",
        False,
        "error",
        f"Local Pairling MCP bridge credential is invalid: {type(exc).__name__}: {exc}",
        str(MCP_CREDENTIAL),
    )

if MCP_ADAPTER.exists():
    add("mcp_adapter_installed", True, "error", "Repo-owned Pairling MCP adapter is installed in runtime/current.", str(MCP_ADAPTER))
else:
    add("mcp_adapter_installed", False, "error", "Repo-owned Pairling MCP adapter is missing from runtime/current.", str(MCP_ADAPTER))

try:
    shim_text = MCP_SHIM.read_text()
    add(
        "mcp_adapter_shim",
        "Pairling daemon-first phone-tools MCP server" in shim_text and "PAIRLING_MCP_ADAPTER" in shim_text,
        "warning",
        "Installed phone-tools MCP shim points at Pairling.",
        str(MCP_SHIM),
    )
except Exception as exc:
    add("mcp_adapter_shim", False, "warning", f"Installed phone-tools MCP shim is missing: {type(exc).__name__}: {exc}", str(MCP_SHIM))

try:
    pairling_text = USER_PAIRLING.read_text()
    add(
        "shell_pairling_wrapper",
        "runtime/current/bin/pairling" in pairling_text
        and "--shim-print-env" in pairling_text
        and re.search(r"/Users/[^\\s'\"]+/projects/Pairling", pairling_text) is None,
        "error",
        "User pairling command resolves through Pairling without trapping npm setup on stale runtime/current.",
        str(USER_PAIRLING),
    )
except Exception as exc:
    add("shell_pairling_wrapper", False, "error", f"User pairling command is missing or unreadable: {type(exc).__name__}: {exc}", str(USER_PAIRLING))

if PAIR_ROOT.exists():
    mode = PAIR_ROOT.stat().st_mode & 0o777
    add("pair_storage_permissions", mode <= 0o700, "error", "Pair storage permissions are private.", oct(mode))
else:
    add("pair_storage_permissions", False, "error", "Pair storage directory is missing.", str(PAIR_ROOT))

try:
    payload = load_plist(USER_PLIST)
    args = payload.get("ProgramArguments") or []
    env = payload.get("EnvironmentVariables") or {}
    add("launchagent_plist", payload.get("Label") == PAIRLING_LABEL and any(str(CURRENT / "companiond" / "pairlingd.py") == value for value in args), "error", "Pairling LaunchAgent points at runtime/current.", {"label": payload.get("Label"), "args": args})
    add("launchagent_port_env", env.get("PAIRLING_RUNTIME_PORT") == str(PAIRLING_PORT), "error", "Pairling LaunchAgent advertises port 7773.", env)
except Exception as exc:
    add("launchagent_plist", False, "error", f"Pairling LaunchAgent plist unreadable: {type(exc).__name__}: {exc}", str(USER_PLIST))
    add("launchagent_port_env", False, "error", "Cannot validate Pairling LaunchAgent environment.", str(USER_PLIST))

try:
    payload = load_plist(CONNECTD_USER_PLIST)
    args = payload.get("ProgramArguments") or []
    env = payload.get("EnvironmentVariables") or {}
    add(
        "connectd_launchagent_plist",
        payload.get("Label") == PAIRLING_CONNECTD_LABEL and any(str(CURRENT / "connectd" / "pairling-connectd") == value for value in args),
        "error",
        "Pairling Connect LaunchAgent points at runtime/current.",
        {"label": payload.get("Label"), "args": args},
    )
    add(
        "connectd_launchagent_env",
        env.get("PAIRLING_RUNTIME_PORT") == str(PAIRLING_PORT),
        "error",
        "Pairling Connect LaunchAgent advertises port 7773.",
        env,
    )
except Exception as exc:
    add("connectd_launchagent_plist", False, "error", f"Pairling Connect LaunchAgent plist unreadable: {type(exc).__name__}: {exc}", str(CONNECTD_USER_PLIST))
    add("connectd_launchagent_env", False, "error", "Cannot validate Pairling Connect LaunchAgent environment.", str(CONNECTD_USER_PLIST))

try:
    payload = load_plist(PTYBROKER_USER_PLIST)
    args = payload.get("ProgramArguments") or []
    add(
        "ptybroker_launchagent_plist",
        payload.get("Label") == PAIRLING_PTYBROKER_LABEL and any(str(CURRENT / "companiond" / "pty_broker_service.py") == value for value in args),
        "error",
        "Pairling PTY broker LaunchAgent points at runtime/current.",
        {"label": payload.get("Label"), "args": args},
    )
except Exception as exc:
    add("ptybroker_launchagent_plist", False, "error", f"Pairling PTY broker LaunchAgent plist unreadable: {type(exc).__name__}: {exc}", str(PTYBROKER_USER_PLIST))

code, out, err = run(["launchctl", "print", f"gui/{os.getuid()}/{PAIRLING_LABEL}"])
add("launchagent_loaded", code == 0 and "state = running" in out, "error", "Pairling LaunchAgent is running." if code == 0 else "Pairling LaunchAgent is not loaded.", (out or err)[:2000])
add("launchagent_loaded_from_current", str(CURRENT / "companiond" / "pairlingd.py") in out, "error", "Loaded Pairling LaunchAgent uses runtime/current.", out[:2000])

code, out, err = run(["launchctl", "print", f"gui/{os.getuid()}/{PAIRLING_CONNECTD_LABEL}"])
connectd_launchd_pid_match = re.search(r"(?m)^\s*pid = ([0-9]+)\s*$", out)
connectd_launchd_pid = int(connectd_launchd_pid_match.group(1)) if connectd_launchd_pid_match else None
add("connectd_launchagent_loaded", code == 0 and "state = running" in out, "error", "Pairling Connect LaunchAgent is running." if code == 0 else "Pairling Connect LaunchAgent is not loaded.", (out or err)[:2000])
add("connectd_loaded_from_current", str(CURRENT / "connectd" / "pairling-connectd") in out, "error", "Loaded Pairling Connect LaunchAgent uses runtime/current.", out[:2000])

code, out, err = run(["launchctl", "print", f"gui/{os.getuid()}/{PAIRLING_PTYBROKER_LABEL}"])
ptybroker_launchd_loaded = code == 0 and "state = running" in out
add("ptybroker_launchagent_loaded", ptybroker_launchd_loaded, "error", "Pairling PTY broker LaunchAgent is running." if code == 0 else "Pairling PTY broker LaunchAgent is not loaded.", (out or err)[:2000])
add("ptybroker_loaded_from_current", str(CURRENT / "companiond" / "pty_broker_service.py") in out, "error", "Loaded Pairling PTY broker uses runtime/current.", out[:2000])
ptybroker_deployment = ptybroker_deployment_status(launchd_loaded=ptybroker_launchd_loaded)
add(
    "ptybroker_deployment_state",
    ptybroker_deployment["state"] == "current",
    "warning",
    f"Pairling PTY broker deployment state is {ptybroker_deployment['state']}.",
    ptybroker_deployment,
)
add(
    "ptybroker_activation_ready",
    ptybroker_deployment["state"] in {"current", "stale_deferred"},
    "error",
    "Pairling PTY broker answered its status check.",
    ptybroker_deployment,
)

listeners_7773 = port_listeners(PAIRLING_PORT)
listeners_7723 = port_listeners(7723)
add("port_7773_listener", bool(listeners_7773) or tcp_accepts("127.0.0.1", PAIRLING_PORT), "error", "Runtime is listening on 7773.", listeners_7773)
legacy_conflict = any("Python" in line or "python" in line for line in listeners_7723)
add("legacy_port_7723_clear", not legacy_conflict, "error", "Legacy 7723 daemon is not conflicting.", listeners_7723)

health = None
try:
    req = urllib.request.Request(f"http://127.0.0.1:{PAIRLING_PORT}/health")
    with urllib.request.urlopen(req, timeout=3) as resp:
        health = json.loads(resp.read().decode("utf-8"))
        add("health_endpoint", resp.status == 200, "error", "GET /health returned HTTP 200.", resp.status)
except Exception as exc:
    add("health_endpoint", False, "error", f"GET /health failed: {type(exc).__name__}: {exc}", f"http://127.0.0.1:{PAIRLING_PORT}/health")

if health:
    add("health_contract", health.get("contract_version") == "pairling-runtime-v1", "error", "/health reports Pairling runtime contract.", health.get("contract_version"))
else:
    add("health_contract", False, "error", "Cannot validate /health contract without response.")

# Session keep-awake truth (SPEC-p7): the daemon holds a caffeinate -i child
# only while supervised work runs. Informational — the honest limits are that
# idle sleep is prevented, never a closed lid.
keep_awake = None
try:
    req = urllib.request.Request(f"http://127.0.0.1:{PAIRLING_PORT}/power-state")
    with urllib.request.urlopen(req, timeout=3) as resp:
        keep_awake = (json.loads(resp.read().decode("utf-8")) or {}).get("keep_awake") or {}
except Exception:
    keep_awake = None
if keep_awake is None:
    add("keep_awake", False, "warning", "GET /power-state failed; keep-awake state unknown.")
elif not keep_awake.get("enabled"):
    add(
        "keep_awake",
        True,
        "warning",
        "Session keep-awake is disabled (PAIRLING_KEEP_AWAKE=0); the Mac follows its own sleep schedule even mid-run.",
        {"enabled": False},
    )
else:
    ka_reasons = keep_awake.get("reasons") or {}
    ka_active = bool(keep_awake.get("active"))
    ka_summary = "Keep-awake is holding the Mac awake" if ka_active else "Keep-awake is idle (no active work; the Mac may sleep)"
    add(
        "keep_awake",
        True,
        "warning",
        f"{ka_summary}: streams={ka_reasons.get('streams', 0)} sessions={ka_reasons.get('sessions', 0)} workers={ka_reasons.get('workers', 0)}.",
        {key: keep_awake.get(key) for key in ("enabled", "active", "reasons", "since", "caffeinate_pid")},
    )

connectd_status = fetch_connectd_status()
connectd_summary = redacted_connectd_summary(connectd_status)
add(
    "connectd_status_schema_v2",
    int(connectd_status.get("schema_version") or 0) >= 2,
    "error",
    "Pairling Connect status uses schema v2.",
    connectd_summary,
)
add(
    "connectd_status_redacted",
    re.search(r"https://login\.tailscale\.com/a/(?!\[redacted\])", json.dumps(connectd_status, sort_keys=True)) is None,
    "error",
    "Pairling Connect status does not expose browser auth URLs.",
    connectd_summary,
)
connectd_identity_evidence = {
    "launchd_pid": connectd_launchd_pid,
    "status_pid": connectd_status.get("pid"),
    "version": connectd_status.get("version"),
    "source_revision": connectd_status.get("source_revision"),
    "source_dirty": connectd_status.get("source_dirty"),
}
connectd_identity_ok = (
    managed_release_identity is not None
    and connectd_launchd_pid is not None
    and int(connectd_status.get("pid") or 0) == connectd_launchd_pid
    and connectd_status.get("version") == managed_release_identity.get("runtime_version")
    and connectd_status.get("source_revision") == managed_release_identity.get("source_revision")
    and connectd_status.get("source_dirty") is managed_release_identity.get("source_dirty")
)
add(
    "connectd_live_identity",
    connectd_identity_ok,
    "error",
    "Live Pairling Connect process matches launchd and the verified managed release.",
    connectd_identity_evidence,
)

provider_evidence = {}
for name in ["claude", "codex"]:
    code, out, _ = run(["/usr/bin/which", name], timeout=2)
    provider_evidence[name] = out.strip() if code == 0 else None
add("provider_clis_detected", True, "warning", "Provider CLI detection completed.", provider_evidence)

release_blockers = []
developer_id_identity = os.environ.get("PAIRLING_DEVELOPER_ID_IDENTITY")
code, out, err = run(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"], timeout=5)
identity_evidence = codesigning_identity_summary(out)
has_developer_id = code == 0 and (
    (developer_id_identity in out) if developer_id_identity else identity_evidence["expected_team_present"]
)
if not has_developer_id:
    release_blockers.append("Developer ID Application identity is missing from the login keychain for the expected team.")
add(
    "developer_id_identity",
    has_developer_id,
    "warning",
    "Developer ID Application identity is available for public helper signing.",
    identity_evidence if code == 0 else {"error": (err or "security find-identity failed")[:200]},
)

notary_profile = os.environ.get("PAIRLING_NOTARY_PROFILE", "pairling-notary")
code, out, err = run(["/usr/bin/xcrun", "notarytool", "history", "--keychain-profile", notary_profile], timeout=10)
has_notary_profile = code == 0
if not has_notary_profile:
    release_blockers.append(f"Notary credentials are missing or invalid for keychain profile: {notary_profile}")
add(
    "notary_profile",
    has_notary_profile,
    "warning",
    "Notary credentials are stored and can authenticate.",
    {"profile": notary_profile, "authenticated": has_notary_profile, "error": None if has_notary_profile else (err or out)[:200]},
)

# npm distribution: the staged pairling-connectd binary must be a valid
# Developer ID build from the pinned team. This replaces the retired dmg
# Gatekeeper check; the npm install path never sets com.apple.quarantine, so
# Gatekeeper assessment is not in the launch path, but signature + Team ID
# verification is the integrity equivalent and matches the fail-closed staging
# gate in install-runtime.sh.
expected_team = os.environ.get("PAIRLING_CONNECTD_TEAM_ID", "965AVD34A3")
staged_connectd = CURRENT / "connectd" / "pairling-connectd"
if staged_connectd.exists():
    vcode, vout, verr = run(["/usr/bin/codesign", "--verify", "--strict", str(staged_connectd)], timeout=8)
    rcode, rout, rerr = (0, "", "") if expected_team == "-" else run([
        "/usr/bin/codesign", "--verify", "--strict", "--verbose=2",
        f"-R={developer_id_requirement(expected_team)}", str(staged_connectd),
    ], timeout=8)
    icode, iout, ierr = run(["/usr/bin/codesign", "-dvv", str(staged_connectd)], timeout=8)
    team_line = next((l for l in ((iout or "") + (ierr or "")).splitlines() if l.startswith("TeamIdentifier=")), "")
    team_id = team_line.split("=", 1)[1] if "=" in team_line else ""
    signed_ok = vcode == 0 and rcode == 0 and (expected_team == "-" or team_id == expected_team)
    if not signed_ok:
        release_blockers.append("Staged pairling-connectd is not a valid Developer ID build from the expected team.")
    add(
        "connectd_signature",
        signed_ok,
        "warning",
        "Staged pairling-connectd passes codesign --verify --strict with the expected Team ID.",
        {"binary": str(staged_connectd), "team_id": team_id or None, "expected_team": expected_team, "verify": (vout or verr)[:1000], "developer_id_verify": (rout or rerr)[:1000]},
    )
else:
    release_blockers.append("Staged pairling-connectd is not present; run pairling setup.")
    add(
        "connectd_signature",
        False,
        "warning",
        "Staged pairling-connectd not present; signature verification unavailable until pairling setup runs.",
        {"binary": str(staged_connectd)},
    )

# P3 Python custody: when a vendored interpreter is staged, it must be a valid
# Developer ID build from the expected team with the dev.pairling.python
# identity — that scoping is the whole point (TCC grants attach to Pairling, not
# a generic interpreter). When no vendored Python is staged, this check is
# informational, not a blocker.
expected_python_identifier = os.environ.get("PAIRLING_PYTHON_IDENTIFIER", "dev.pairling.python")
staged_python = CURRENT / "python" / "bin" / "python3"
if staged_python.exists():
    pvcode, pvout, pverr = run(["/usr/bin/codesign", "--verify", "--strict", str(staged_python)], timeout=10)
    prcode, prout, prerr = (0, "", "") if expected_team == "-" else run([
        "/usr/bin/codesign", "--verify", "--strict", "--verbose=2",
        f"-R={developer_id_requirement(expected_team)}", str(staged_python),
    ], timeout=10)
    picode, piout, pierr = run(["/usr/bin/codesign", "-dvv", str(staged_python)], timeout=10)
    pinfo = (piout or "") + (pierr or "")
    p_team = next((l.split("=", 1)[1] for l in pinfo.splitlines() if l.startswith("TeamIdentifier=")), "")
    p_id = next((l.split("=", 1)[1] for l in pinfo.splitlines() if l.startswith("Identifier=")), "")
    python_signed_ok = (
        pvcode == 0
        and prcode == 0
        and (expected_team == "-" or p_team == expected_team)
        and p_id == expected_python_identifier
    )
    if not python_signed_ok:
        release_blockers.append("Staged vendored python is not a valid dev.pairling.python Developer ID build.")
    add(
        "python_runtime",
        python_signed_ok,
        "warning",
        "Staged vendored CPython is signed dev.pairling.python by the expected Team ID.",
        {"python": str(staged_python), "team_id": p_team or None, "identifier": p_id or None, "expected_identifier": expected_python_identifier, "developer_id_verify": (prout or prerr)[:1000]},
    )
else:
    add(
        "python_runtime",
        True,
        "warning",
        "No vendored CPython staged; daemon uses the resolved Python 3 interpreter (acceptable pre-P3-rollout).",
        {"python": str(staged_python), "vendored": False},
    )

errors = [c for c in checks if c["status"] != "ok" and c["severity"] == "error"]
warnings = [c for c in checks if c["status"] != "ok" and c["severity"] == "warning"]
checks_by_id = {c["id"]: c for c in checks}
active_pairs = active_pair_records(PAIR_ROOT)
runtime_installed = checks_by_id.get("manifest_exists", {}).get("status") == "ok"
runtime_running = checks_by_id.get("health_endpoint", {}).get("status") == "ok"
runtime_running_for_first_run = runtime_running or os.environ.get("PAIRLING_TEST_FIRST_RUN_RUNTIME_READY") == "1"
pair_window_open = bool(active_pairs)
tailnet_ip = detected_tailnet_ip()
remote_ready = bool(connectd_summary.get("route_ready"))
remote_status = "ready" if remote_ready else str(connectd_summary.get("status") or "missing_mac")
local_pairing_ready = runtime_installed and runtime_running_for_first_run and pair_window_open
product_ready = local_pairing_ready and remote_ready
stage = first_run_stage(
    installed=runtime_installed,
    running=runtime_running_for_first_run,
    pair_window_open=pair_window_open,
    remote_ready=remote_ready,
)
first_run = {
    "ok": local_pairing_ready,
    "schema_version": 2,
    "stage": stage,
    "product_ready": product_ready,
    "local_pairing_ready": local_pairing_ready,
    "helper": {
        "installed": runtime_installed,
        "running": runtime_running_for_first_run,
        "runtime_health_verified": runtime_running,
        "launchd_label": PAIRLING_LABEL,
        "artifact_release_blockers": release_blockers,
    },
    "runtime": {
        "installed": runtime_installed,
        "running": runtime_running_for_first_run,
        "health_verified": runtime_running,
        "port": PAIRLING_PORT,
        "launchd_label": PAIRLING_LABEL,
    },
    "remote_access": {
        "required_for_product_ready": True,
        "provider": "pairling_connect",
        "status": remote_status,
        "mac_tailnet_ip": (connectd_summary.get("route") or {}).get("host") if isinstance(connectd_summary.get("route"), dict) else None,
        "iphone_tailnet_detected": "unknown_until_route_used",
        "preferred_remote_route": (connectd_summary.get("route") or {}).get("base_url") if isinstance(connectd_summary.get("route"), dict) else None,
        "local_pairing_available": runtime_installed and runtime_running_for_first_run,
        "bonjour_available": pair_window_open,
        "standalone_tailnet_diagnostic_ip": tailnet_ip,
    },
    "connect": connectd_summary,
    "pairing": {
        "pair_window_open": pair_window_open,
        "active_pair_count": len(active_pairs),
        "active_pairs": active_pairs[:3],
        "expires_in": active_pairs[0]["expires_in"] if active_pairs else None,
        "bonjour": "advertised_by_pair_start_if_dns_sd_available" if pair_window_open else "open_pairing_invitation_to_advertise",
        "qr_fallback": "available_from_pairling_pair_qr",
        "manual_url_fallback": "available_from_pairling_pair_json",
    },
    "routes": {
        "localhost": tcp_accepts("127.0.0.1", PAIRLING_PORT),
        "lan": "verified_after_pair_claim_host_chain",
        "tailscale": remote_status,
        "pairling_connect": remote_status,
    },
    "permissions": permission_readiness(),
    "provider_readiness": {
        "status": "checked_by_runtime_after_pairing",
        "detected_clis": provider_evidence,
    },
    "next_action": next_action_for_stage(stage, remote_status=remote_status, pair_window_open=pair_window_open),
}
result = {
    "ok": not errors,
    "product": "Pairling",
    "safety_monitor": safety_monitor_status(),
    "schema_version": 1,
    "contract_version": "pairling-runtime-v1",
    "runtime": {
        "name": "pairlingd",
        "port": PAIRLING_PORT,
        "launchd_label": PAIRLING_LABEL,
    },
    "ptybroker": ptybroker_deployment,
    "paths": {
        "app_support": str(APP_SUPPORT),
        "logs": str(LOGS_ROOT),
        "current": str(CURRENT),
        "devices_db": str(DEVICES_DB),
        "pair_records": str(PAIR_ROOT),
    },
    "legacy": {
        "port": 7723,
        "listeners": listeners_7723,
    },
    "release_blockers": release_blockers,
    "checks": checks,
    "warnings": warnings,
    "errors": errors,
}
if first_run_mode:
    result["first_run"] = first_run

if json_mode:
    print(json.dumps(result, indent=2, sort_keys=True))
else:
    print(f"Pairling runtime doctor: {'ok' if result['ok'] else 'failed'}")
    if first_run_mode:
        print(f"First-run stage: {first_run['stage']}")
        next_action = first_run.get("next_action")
        if isinstance(next_action, dict):
            print(f"Next action: {next_action.get('message', next_action.get('label', 'Review first-run readiness.'))}")
        else:
            print(f"Next action: {next_action}")
    for item in checks:
        marker = "ok" if item["status"] == "ok" else item["severity"]
        print(f"[{marker}] {item['id']}: {item['summary']}")

raise SystemExit(0 if result["ok"] else 1)
PY
