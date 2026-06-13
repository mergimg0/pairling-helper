#!/usr/bin/env bash
set -euo pipefail

export PYTHONDONTWRITEBYTECODE=1
if [[ -z "${PYTHONPYCACHEPREFIX:-}" ]]; then
  PYTHONPYCACHEPREFIX="${TMPDIR:-/tmp}/pairling-pycache-$(id -u)"
  mkdir -p "$PYTHONPYCACHEPREFIX" 2>/dev/null || true
  export PYTHONPYCACHEPREFIX
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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
    --help|-h)
      cat <<EOF
usage: pairling doctor [--json] [--first-run]

Validates the Pairling Mac runtime. --first-run adds a machine-readable
readiness contract for onboarding and pairing rehearsals.
EOF
      exit 0
      ;;
    *)
      echo "usage: pairling doctor [--json] [--first-run]" >&2
      exit 2
      ;;
  esac
  shift
done

python3 - "$REPO_ROOT" "$JSON_MODE" "$FIRST_RUN_MODE" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

repo_root = Path(sys.argv[1])
json_mode = sys.argv[2] == "true"
first_run_mode = sys.argv[3] == "true"
home = Path.home()

PAIRLING_PORT = int(os.environ.get("PAIRLING_RUNTIME_PORT", "7773"))
PAIRLING_LABEL = "dev.pairling.companiond"
PAIRLING_GUARDIAN_LABEL = "dev.pairling.power-guardian"
PAIRLING_CONNECTD_LABEL = "dev.pairling.connectd"
LEGACY_LABEL = "com.mghome.notify-webhook"
APP_SUPPORT = Path(os.environ.get("PAIRLING_APP_SUPPORT_ROOT", os.environ.get("COMPANION_APP_SUPPORT_ROOT", str(home / "Library" / "Application Support" / "Pairling"))))
LOGS_ROOT = Path(os.environ.get("PAIRLING_LOGS_ROOT", os.environ.get("COMPANION_LOGS_ROOT", str(home / "Library" / "Logs" / "Pairling"))))
CURRENT = APP_SUPPORT / "runtime" / "current"
MANIFEST_PATH = CURRENT / "manifest.json"
DEVICES_DB = APP_SUPPORT / "devices.sqlite"
MCP_CREDENTIAL = Path(os.environ.get("PAIRLING_MCP_CREDENTIAL", str(APP_SUPPORT / "mcp-bridge.json")))
MCP_ADAPTER = CURRENT / "mcp" / "phone_tools.py"
MCP_SHIM = home / ".claude" / "mcp-servers" / "phone-tools.py"
USER_PAIRLING = home / ".local" / "bin" / "pairling"
PAIR_ROOT = APP_SUPPORT / "pair"
USER_PLIST = home / "Library" / "LaunchAgents" / f"{PAIRLING_LABEL}.plist"
CONNECTD_USER_PLIST = home / "Library" / "LaunchAgents" / f"{PAIRLING_CONNECTD_LABEL}.plist"
LEGACY_USER_PLIST = home / "Library" / "LaunchAgents" / f"{LEGACY_LABEL}.plist"
SYSTEM_PLIST = Path("/Library/LaunchDaemons") / f"{PAIRLING_GUARDIAN_LABEL}.plist"
LEGACY_SYSTEM_PLIST = Path("/Library/LaunchDaemons/com.mghome.companion-power-guardian.plist")

sys.path.insert(0, str(repo_root / "mac" / "companiond"))
from pairling_connectd_status import fetch_connectd_status, redacted_connectd_summary

checks = []


def add(identifier, ok, severity, summary, evidence=None):
    checks.append({
        "id": identifier,
        "status": "ok" if ok else "fail",
        "severity": severity,
        "summary": summary,
        "evidence": evidence,
    })


def run(args, timeout=5):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except Exception as exc:
        return 127, "", f"{type(exc).__name__}: {exc}"


def load_plist(path):
    with path.open("rb") as fh:
        return plistlib.load(fh)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def writable_dir(path: Path) -> tuple[bool, str]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".pairling-doctor-write-test"
        probe.write_text("ok")
        probe.unlink()
        return True, str(path)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


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
        },
        "mac_automation": {
            "required_for": ["terminal_app_control"],
            "status": "not_required_by_default",
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
if MANIFEST_PATH.is_file():
    try:
        manifest = json.loads(MANIFEST_PATH.read_text())
        add("manifest_exists", True, "error", "Installed Pairling manifest exists.", str(MANIFEST_PATH))
    except Exception as exc:
        add("manifest_exists", False, "error", f"Manifest is unreadable: {type(exc).__name__}: {exc}", str(MANIFEST_PATH))
else:
    add("manifest_exists", False, "error", "Installed Pairling manifest is missing.", str(MANIFEST_PATH))

if manifest:
    add("manifest_contract", manifest.get("contract_version") == "pairling-runtime-v1", "error", "Manifest contract is pairling-runtime-v1.", manifest.get("contract_version"))
    runtime = manifest.get("runtime") if isinstance(manifest.get("runtime"), dict) else {}
    add("runtime_port", runtime.get("port") == PAIRLING_PORT, "error", "Runtime port is locked to 7773.", runtime.get("port"))
    launchd = manifest.get("launchd") if isinstance(manifest.get("launchd"), dict) else {}
    add("launchd_labels", launchd.get("daemon_label") == PAIRLING_LABEL and launchd.get("connectd_label") == PAIRLING_CONNECTD_LABEL and launchd.get("guardian_label") == PAIRLING_GUARDIAN_LABEL, "error", "Manifest launchd labels are Pairling labels.", launchd)
    mismatches = []
    for item in manifest.get("files") or []:
        rel = item.get("path")
        expected = item.get("sha256")
        if not rel or not expected:
            mismatches.append(f"malformed file entry: {item}")
            continue
        path = CURRENT / rel
        if not path.is_file():
            mismatches.append(f"missing {rel}")
            continue
        actual = sha256_file(path)
        if actual != expected:
            mismatches.append(f"{rel}: {actual} != {expected}")
    add("manifest_hashes", not mismatches, "error", "Installed file hashes match manifest." if not mismatches else "Installed file hashes do not match manifest.", mismatches)
else:
    add("manifest_contract", False, "error", "Cannot validate contract without manifest.")
    add("runtime_port", False, "error", "Cannot validate runtime port without manifest.")
    add("launchd_labels", False, "error", "Cannot validate labels without manifest.")
    add("manifest_hashes", False, "error", "Cannot validate hashes without manifest.")

compile_targets = [
    repo_root / "mac" / "install" / "render-launchd.py",
    repo_root / "mac" / "guardian" / "guardian_contract.py",
    repo_root / "mac" / "guardian" / "companion-power-guardian.py",
]
compile_errors = []
for target in compile_targets:
    code, out, err = run(["python3", "-m", "py_compile", str(target)])
    if code != 0:
        compile_errors.append(f"{target}: {err or out}")
add("lifecycle_sources_compile", not compile_errors, "error", "Lifecycle/guardian sources compile." if not compile_errors else "Lifecycle/guardian compile failed.", compile_errors)

ok, evidence = writable_dir(APP_SUPPORT)
add("app_support_writable", ok, "error", "App support directory is writable.", evidence)
ok, evidence = writable_dir(LOGS_ROOT)
add("logs_writable", ok, "error", "Logs directory is writable.", evidence)

if DEVICES_DB.exists():
    try:
        with sqlite3.connect(f"file:{DEVICES_DB}?mode=ro", uri=True) as db:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        add("devices_db", {"devices", "audit_events"}.issubset(tables), "error", "Devices database has required tables.", sorted(tables))
    except Exception as exc:
        add("devices_db", False, "error", f"Devices database is unreadable: {type(exc).__name__}: {exc}", str(DEVICES_DB))
else:
    add("devices_db", False, "error", "Devices database is missing.", str(DEVICES_DB))

try:
    sys.path.insert(0, str(repo_root / "mac" / "companiond"))
    from pairling_devices import DeviceRegistry
    from local_mcp_bridge import validate_local_mcp_bridge_credential

    valid, evidence = validate_local_mcp_bridge_credential(
        registry=DeviceRegistry(DEVICES_DB, LOGS_ROOT / "audit.jsonl"),
        credential_path=MCP_CREDENTIAL,
    )
    add(
        "mcp_bridge_credential",
        valid,
        "error",
        "Local Pairling MCP bridge credential is valid and scoped.",
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
        and "/Users/mergimg0/projects/Pairling" not in pairling_text,
        "error",
        "User pairling command resolves through runtime/current unless PAIRLING_REPO_ROOT is explicitly set.",
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
    payload = load_plist(SYSTEM_PLIST)
    add("guardian_plist", payload.get("Label") == PAIRLING_GUARDIAN_LABEL, "warning", "Pairling guardian LaunchDaemon is rendered/installed.", {"label": payload.get("Label")})
except Exception as exc:
    add("guardian_plist", False, "warning", f"Pairling guardian LaunchDaemon is not installed: {type(exc).__name__}: {exc}", str(SYSTEM_PLIST))

code, out, err = run(["launchctl", "print", f"gui/{os.getuid()}/{PAIRLING_LABEL}"])
add("launchagent_loaded", code == 0 and "state = running" in out, "error", "Pairling LaunchAgent is running." if code == 0 else "Pairling LaunchAgent is not loaded.", (out or err)[:2000])
add("launchagent_loaded_from_current", str(CURRENT / "companiond" / "pairlingd.py") in out, "error", "Loaded Pairling LaunchAgent uses runtime/current.", out[:2000])

code, out, err = run(["launchctl", "print", f"gui/{os.getuid()}/{PAIRLING_CONNECTD_LABEL}"])
add("connectd_launchagent_loaded", code == 0 and "state = running" in out, "error", "Pairling Connect LaunchAgent is running." if code == 0 else "Pairling Connect LaunchAgent is not loaded.", (out or err)[:2000])
add("connectd_loaded_from_current", str(CURRENT / "connectd" / "pairling-connectd") in out, "error", "Loaded Pairling Connect LaunchAgent uses runtime/current.", out[:2000])

code, out, err = run(["launchctl", "print", f"gui/{os.getuid()}/{LEGACY_LABEL}"])
legacy_loaded = code == 0 and "state = running" in out
add("legacy_daemon_unloaded", not legacy_loaded, "error", "Old Pairling predecessor launchd label is not loaded.", (out or err)[:2000])
add("legacy_launchagent_removed", not LEGACY_USER_PLIST.exists(), "warning", "Legacy user LaunchAgent plist is absent.", str(LEGACY_USER_PLIST))
add("legacy_guardian_removed", not LEGACY_SYSTEM_PLIST.exists(), "warning", "Legacy guardian LaunchDaemon plist is absent.", str(LEGACY_SYSTEM_PLIST))

listeners_7773 = port_listeners(PAIRLING_PORT)
listeners_7723 = port_listeners(7723)
add("port_7773_listener", bool(listeners_7773) or tcp_accepts("127.0.0.1", PAIRLING_PORT), "error", "Runtime is listening on 7773.", listeners_7773)
legacy_conflict = any("notify-webhook" in line or "Python" in line or "python" in line for line in listeners_7723)
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

provider_evidence = {}
for name in ["claude", "codex"]:
    code, out, _ = run(["/usr/bin/which", name], timeout=2)
    provider_evidence[name] = out.strip() if code == 0 else None
add("provider_clis_detected", True, "warning", "Provider CLI detection completed.", provider_evidence)

release_blockers = []
developer_id_identity = os.environ.get("PAIRLING_DEVELOPER_ID_IDENTITY", "Developer ID Application: Mergim Gashi (965AVD34A3)")
code, out, err = run(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"], timeout=5)
has_developer_id = code == 0 and developer_id_identity in out
if not has_developer_id:
    release_blockers.append(f"Developer ID identity is missing from the login keychain: {developer_id_identity}")
add(
    "developer_id_identity",
    has_developer_id,
    "warning",
    "Developer ID Application identity is available for public helper signing.",
    (out or err)[:2000],
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
    (out or err)[:2000],
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
    icode, iout, ierr = run(["/usr/bin/codesign", "-dvv", str(staged_connectd)], timeout=8)
    team_line = next((l for l in ((iout or "") + (ierr or "")).splitlines() if l.startswith("TeamIdentifier=")), "")
    team_id = team_line.split("=", 1)[1] if "=" in team_line else ""
    signed_ok = vcode == 0 and (expected_team == "-" or team_id == expected_team)
    if not signed_ok:
        release_blockers.append("Staged pairling-connectd is not a valid Developer ID build from the expected team.")
    add(
        "connectd_signature",
        signed_ok,
        "warning",
        "Staged pairling-connectd passes codesign --verify --strict with the expected Team ID.",
        {"binary": str(staged_connectd), "team_id": team_id or None, "expected_team": expected_team, "verify": (vout or verr)[:1000]},
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
# a generic python3). When no vendored python is staged (the daemon runs under a
# system python3), this check is informational, not a blocker.
expected_python_identifier = os.environ.get("PAIRLING_PYTHON_IDENTIFIER", "dev.pairling.python")
staged_python = CURRENT / "python" / "bin" / "python3"
if staged_python.exists():
    pvcode, pvout, pverr = run(["/usr/bin/codesign", "--verify", "--strict", str(staged_python)], timeout=10)
    picode, piout, pierr = run(["/usr/bin/codesign", "-dvv", str(staged_python)], timeout=10)
    pinfo = (piout or "") + (pierr or "")
    p_team = next((l.split("=", 1)[1] for l in pinfo.splitlines() if l.startswith("TeamIdentifier=")), "")
    p_id = next((l.split("=", 1)[1] for l in pinfo.splitlines() if l.startswith("Identifier=")), "")
    python_signed_ok = (
        pvcode == 0
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
        {"python": str(staged_python), "team_id": p_team or None, "identifier": p_id or None, "expected_identifier": expected_python_identifier},
    )
else:
    add(
        "python_runtime",
        True,
        "warning",
        "No vendored CPython staged; daemon runs under a system python3 (acceptable pre-P3-rollout).",
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
    "schema_version": 1,
    "contract_version": "pairling-runtime-v1",
    "runtime": {
        "name": "pairlingd",
        "port": PAIRLING_PORT,
        "launchd_label": PAIRLING_LABEL,
        "guardian_label": PAIRLING_GUARDIAN_LABEL,
    },
    "paths": {
        "app_support": str(APP_SUPPORT),
        "logs": str(LOGS_ROOT),
        "current": str(CURRENT),
        "devices_db": str(DEVICES_DB),
        "pair_records": str(PAIR_ROOT),
    },
    "legacy": {
        "daemon_label": LEGACY_LABEL,
        "port": 7723,
        "loaded": legacy_loaded,
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
