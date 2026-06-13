#!/usr/bin/env python3
"""
Pairling power guardian.

Runs as a root LaunchDaemon in production. It samples macOS power, lid,
thermal, Tailscale, and pairlingd posture, then writes one atomic JSON snapshot
that pairlingd serves as /power-state. Optional enforcement can hold a
conservative `caffeinate -s -i -m` assertion and apply pmset posture, but the
default installed LaunchDaemon is observe-only.
"""
from __future__ import annotations

import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

try:
    from guardian_contract import build_guardian_info
except Exception:
    build_guardian_info = None


SCHEMA_VERSION = 1
PORT = int(os.environ.get("COMPANION_DAEMON_PORT", os.environ.get("PAIRLING_RUNTIME_PORT", "7773")))
STATE_PATH = Path(os.environ.get(
    "COMPANION_POWER_STATE_PATH",
    "/var/run/pairling-power-state.json",
))
INTERVAL_SECONDS = float(os.environ.get("COMPANION_POWER_INTERVAL_SECONDS", "20"))
ENFORCE_CAFFEINATE = os.environ.get("COMPANION_GUARDIAN_ENFORCE", "1") not in {"0", "false", "False"}
LOW_POWER_MODE_POLICY = os.environ.get("COMPANION_LOW_POWER_MODE_POLICY", "preserve").strip().lower()
CAFFEINATE_CMD = ["/usr/bin/caffeinate", "-s", "-i", "-m"]
PMSET_POSTURE = [
    ("sleep", "0"),
    ("displaysleep", "5"),
    ("disksleep", "0"),
    ("tcpkeepalive", "1"),
    ("womp", "1"),
    ("powernap", "1"),
    ("standby", "0"),
]
if LOW_POWER_MODE_POLICY in {"off", "disable", "disabled", "0"}:
    PMSET_POSTURE.append(("lowpowermode", "0"))
elif LOW_POWER_MODE_POLICY in {"on", "enable", "enabled", "1"}:
    PMSET_POSTURE.append(("lowpowermode", "1"))

caffeinate_proc: subprocess.Popen | None = None
stopping = False


def run_text(args: list[str], timeout: float = 3.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", f"{type(exc).__name__}: {exc}"


def first_match(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else None


def int_match(pattern: str, text: str) -> int | None:
    value = first_match(pattern, text)
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def bool_ioreg(name: str, text: str) -> bool | None:
    value = first_match(rf'"{re.escape(name)}"\s*=\s*(Yes|No|true|false)', text)
    if value is None:
        return None
    return value.lower() in {"yes", "true"}


def tailscale_ip() -> str | None:
    code, out, _ = run_text(["tailscale", "ip", "-4"], timeout=2)
    if code != 0:
        return None
    for line in out.splitlines():
        ip = line.strip()
        if ip.startswith("100."):
            return ip
    return None


def tailscale_status() -> str:
    code, out, err = run_text(["tailscale", "status", "--peers=false"], timeout=3)
    if code != 0:
        return (err or "missing").strip()[:120]
    first = next((line.strip() for line in out.splitlines() if line.strip()), "")
    return first or "ok"


def pairling_connect_state() -> tuple[bool, str | None]:
    """Probe the Pairling Connect embedded gateway (connectd) on loopback.

    Returns (route_ready, tailnet_ip). connectd is a userspace tsnet node
    with its own tailnet identity; when its gateway is healthy the iPhone
    has a working tailnet path to pairlingd even while the standalone
    Tailscale app is offline, so posture must treat it as a first-class
    tailnet axis rather than reporting critical on the standalone CLI alone.
    """
    try:
        import urllib.request

        with urllib.request.urlopen("http://127.0.0.1:7774/status", timeout=2) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return False, None
    if not isinstance(payload, dict):
        return False, None
    ready = bool(
        payload.get("auth_state") == "authenticated"
        and payload.get("listener_running")
        and payload.get("gateway_healthy")
        and payload.get("tailnet_ip")
    )
    ip = str(payload.get("tailnet_ip") or "").strip() or None
    return ready, ip


def default_interface() -> str | None:
    code, out, _ = run_text(["/sbin/route", "-n", "get", "default"], timeout=2)
    if code != 0:
        return None
    return first_match(r"^\s*interface:\s*(\S+)", out)


def lan_ips() -> list[str]:
    code, out, _ = run_text(["/sbin/ifconfig"], timeout=3)
    if code != 0:
        return []
    ips: list[str] = []
    for match in re.finditer(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\b", out):
        ip = match.group(1)
        if ip.startswith(("127.", "169.254.", "100.")):
            continue
        if ip not in ips:
            ips.append(ip)
    return ips


def tailscale_macos_plumbing() -> str:
    """Diagnose the standalone Tailscale app's macOS plumbing.

    `tailscale configure sysext status` (Standalone variant) reports whether
    the network system extension is activated. That separates "sysext
    disabled / app not installed correctly" from "running but logged out" —
    the two need different recovery actions (`tailscale configure sysext
    activate` + `tailscale configure mac-vpn install` vs. a browser login).
    Returned string is surfaced in the power-state network block and in the
    no-tailnet-route check message so the operator sees the recovery verb.
    """
    code, out, err = run_text(["tailscale", "configure", "sysext", "status"], timeout=3)
    text = (out or err or "").strip()
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    if not first:
        return "unavailable" if code != 0 else "unknown"
    return first[:120]


def docker_engine_alive() -> bool:
    """Ping the Docker engine socket. The session-visibility plane (Postgres
    reached via `docker exec`) dies silently when Docker Desktop is down —
    surfacing on the phone as empty dashboards and "spawned but no
    heartbeat". Naming it as a posture check turns that mystery into a
    one-line diagnosis."""
    import glob
    import socket as socket_mod

    candidates = ["/var/run/docker.sock"]
    candidates.extend(sorted(glob.glob("/Users/*/.docker/run/docker.sock")))
    for sock_path in candidates:
        if not os.path.exists(sock_path):
            continue
        try:
            with socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect(sock_path)
                sock.sendall(b"GET /_ping HTTP/1.0\r\nHost: docker\r\n\r\n")
                response = sock.recv(256)
            if b"200" in response.split(b"\r\n", 1)[0] or b"OK" in response:
                return True
        except OSError:
            continue
    return False


def listener_state(ts_ip: str | None) -> tuple[int | None, list[str], bool, bool]:
    code, out, _ = run_text(["/usr/sbin/lsof", "-nP", f"-iTCP:{PORT}", "-sTCP:LISTEN"], timeout=3)
    pid: int | None = None
    entries: list[str] = []
    if code == 0:
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit() and pid is None:
                pid = int(parts[1])
            if " TCP " in line:
                entry = line.split(" TCP ", 1)[1].replace(" (LISTEN)", "").strip()
                if entry and entry not in entries:
                    entries.append(entry)
    reachable_tailnet = tcp_accepts(ts_ip, PORT)
    reachable_local = bool(entries) or tcp_accepts("127.0.0.1", PORT)
    if not entries and ts_ip and reachable_tailnet:
        entries.append(f"{ts_ip}:{PORT}")
    return pid, entries, reachable_local, reachable_tailnet


def tcp_accepts(host: str | None, port: int, timeout: float = 0.5) -> bool:
    if not host:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def parse_assertions(text: str) -> dict[str, bool | None]:
    def flag(name: str) -> bool | None:
        value = int_match(rf"^\s*{re.escape(name)}\s+([01])\s*$", text)
        return bool(value) if value is not None else None

    return {
        "prevent_system_sleep": flag("PreventSystemSleep"),
        "prevent_user_idle_system_sleep": flag("PreventUserIdleSystemSleep"),
        "prevent_user_idle_display_sleep": flag("PreventUserIdleDisplaySleep"),
        "raw_contains_caffeinate": "caffeinate" in text.lower(),
    }


def enforce_pmset_posture() -> list[str]:
    if not ENFORCE_CAFFEINATE:
        return []
    errors: list[str] = []
    for key, value in PMSET_POSTURE:
        code, _, err = run_text(["pmset", "-a", key, value], timeout=5)
        if code != 0:
            errors.append(f"pmset {key} {value}: {(err or 'failed').strip()[:160]}")
    return errors


def pmset_drift(facts: dict[str, Any]) -> bool:
    expected = {
        "sleep_minutes": 0,
        "display_sleep_minutes": 5,
        "disk_sleep_minutes": 0,
    }
    for key, value in expected.items():
        if facts.get(key) is not None and facts.get(key) != value:
            return True
    if LOW_POWER_MODE_POLICY in {"off", "disable", "disabled", "0"} and facts.get("low_power_mode") is True:
        return True
    if LOW_POWER_MODE_POLICY in {"on", "enable", "enabled", "1"} and facts.get("low_power_mode") is False:
        return True
    return False


def sample(pmset_enforce_errors: list[str] | None = None) -> dict[str, Any]:
    now = time.time()
    code_live, pmset_live, pmset_live_err = run_text(["pmset", "-g", "live"])
    code_assert, assertions_text, assertions_err = run_text(["pmset", "-g", "assertions"])
    code_batt, batt_text, batt_err = run_text(["pmset", "-g", "batt"])
    code_therm, therm_text, therm_err = run_text(["pmset", "-g", "therm"])
    code_ioreg, ioreg_text, ioreg_err = run_text([
        "ioreg", "-r", "-k", "AppleClamshellState", "-d", "1",
    ])

    ac_power = "AC Power" in batt_text
    battery_percent = int_match(r"(\d+)%;", batt_text)
    low_power = int_match(r"^\s*lowpowermode\s+(\d+)\b", pmset_live)
    sleep_value = int_match(r"^\s*sleep\s+(\d+)\b", pmset_live)
    displaysleep_value = int_match(r"^\s*displaysleep\s+(\d+)\b", pmset_live)
    disksleep_value = int_match(r"^\s*disksleep\s+(\d+)\b", pmset_live)
    lid_closed = bool_ioreg("AppleClamshellState", ioreg_text)
    clamshell_causes_sleep = bool_ioreg("AppleClamshellCausesSleep", ioreg_text)
    cpu_speed_limit = int_match(r"CPU_Speed_Limit\s*=\s*(\d+)", therm_text)
    scheduler_limit = int_match(r"CPU_Scheduler_Limit\s*=\s*(\d+)", therm_text)
    available_cpus = int_match(r"CPU_Available_CPUs\s*=\s*(\d+)", therm_text)
    assertions = parse_assertions(assertions_text)
    ts_ip = tailscale_ip()
    ts_status = tailscale_status()
    ts_sysext = tailscale_macos_plumbing()
    pc_ready, pc_ip = pairling_connect_state()
    docker_alive = docker_engine_alive()
    notify_pid, listen_entries, daemon_reachable_local, daemon_reachable_tailnet = listener_state(ts_ip)
    enforce_errors = pmset_enforce_errors or []

    facts: dict[str, Any] = {
        "ac_power": ac_power,
        "battery_percent": battery_percent,
        "low_power_mode": bool(low_power) if low_power is not None else None,
        "sleep_minutes": sleep_value,
        "display_sleep_minutes": displaysleep_value,
        "disk_sleep_minutes": disksleep_value,
        "lid_closed": lid_closed,
        "clamshell_causes_sleep": clamshell_causes_sleep,
        "thermal_cpu_speed_limit": cpu_speed_limit,
        "thermal_cpu_scheduler_limit": scheduler_limit,
        "thermal_available_cpus": available_cpus,
        "tailscale_ip": ts_ip,
        "tailscale_status": ts_status,
        "tailscale_sysext_status": ts_sysext,
        "pairling_connect_ready": pc_ready,
        "pairling_connect_ip": pc_ip,
        "docker_engine_alive": docker_alive,
        "daemon_reachable": daemon_reachable_tailnet,
        "caffeinate_pid": caffeinate_proc.pid if caffeinate_proc and caffeinate_proc.poll() is None else None,
        **assertions,
    }

    # Power source is informational only: being on battery must never flip the
    # coordinator posture (the user can run the Mac on battery deliberately).
    # Real availability loss is still caught by tailscale_ip/daemon_reachable.
    # The pmset battery profile and the guardian's own caffeinate policy both
    # legitimately differ on battery, so those checks are also informational
    # while unplugged — they only enforce on AC.
    checks = [
        check("ac_power", True, "AC power is connected." if ac_power else "Running on battery power.", "", "ready"),
        check("lid_open", lid_closed is False, "Lid is open.", "Lid is closed; macOS clamshell sleep may cut networking.", "unsafe"),
        low_power_mode_check(low_power),
        check(
            "system_sleep",
            (sleep_value == 0) or not ac_power,
            "System sleep is disabled." if sleep_value == 0 else "System sleep follows the battery profile while unplugged (informational).",
            f"System sleep is set to {sleep_value if sleep_value is not None else 'unknown'}.",
            "unsafe",
        ),
        check(
            "disk_sleep",
            (disksleep_value == 0) or not ac_power,
            "Disk sleep is disabled." if disksleep_value == 0 else "Disk sleep follows the battery profile while unplugged (informational).",
            f"Disk sleep is set to {disksleep_value if disksleep_value is not None else 'unknown'}.",
            "warning",
        ),
        check(
            "prevent_system_sleep",
            (assertions.get("prevent_system_sleep") is True) or not ac_power,
            "A PreventSystemSleep assertion is active." if assertions.get("prevent_system_sleep") is True else "Sleep assertions are not enforced on battery power (informational).",
            "No PreventSystemSleep assertion is active.",
            "unsafe",
        ),
        check(
            "tailscale_ip",
            bool(ts_ip) or pc_ready,
            "Tailscale tailnet IP is present." if ts_ip else "Pairling Connect tailnet route is ready.",
            f"No tailnet route: standalone Tailscale is offline (sysext: {ts_sysext}) and Pairling Connect is not ready.",
            "unsafe",
        ),
        check(
            "daemon_reachable",
            daemon_reachable_tailnet or pc_ready,
            "pairlingd accepts TCP on the tailnet IP." if daemon_reachable_tailnet else "pairlingd is reachable via the Pairling Connect gateway.",
            "pairlingd is not reachable on any tailnet route.",
            "unsafe",
        ),
        check("thermal", thermal_ok(cpu_speed_limit, scheduler_limit), "Thermal limits are normal.", "macOS reports thermal throttling.", "warning"),
        check(
            "docker_engine",
            docker_alive,
            "Docker engine is running (session visibility healthy).",
            "Docker engine is not running — session lists and heartbeats are degraded. Open Docker Desktop (and enable 'Start when you sign in').",
            "warning",
        ),
    ]
    for idx, err in enumerate(enforce_errors, start=1):
        checks.append(check(f"pmset_enforce_{idx}", False, "pmset posture enforced.", err, "warning"))

    unsafe = [c for c in checks if not c["ok"] and c["severity"] == "unsafe"]
    warnings = [c for c in checks if not c["ok"] and c["severity"] == "warning"]
    if unsafe:
        posture = "unsafe"
        severity = "critical"
        ok = False
        summary = unsafe[0]["message"]
    elif warnings:
        posture = "warning"
        severity = "warning"
        ok = True
        summary = warnings[0]["message"]
    else:
        posture = "ready"
        severity = "ok"
        ok = True
        summary = "Mac is in always-on coordinator posture."

    return {
        "schema_version": SCHEMA_VERSION,
        "ok": ok,
        "generated_at": now,
        "guardian": build_guardian_info(__file__) if build_guardian_info else {
            "runtime_version": "legacy",
            "contract_version": "pairling-runtime-v1",
            "source_revision": "unknown",
            "launchd_label": "dev.pairling.power-guardian",
            "verified": False,
            "manifest_error": "guardian manifest helpers unavailable",
        },
        "host": {
            "name": os.environ.get("COMPANION_COORDINATOR_HOST", "pairling-mac"),
            "role": "primary_coordinator",
        },
        "posture": {
            "status": posture,
            "severity": severity,
            "summary": summary,
        },
        "power": {
            "ac_power": ac_power,
            "battery_percent": battery_percent,
            "low_power_mode": bool(low_power) if low_power is not None else None,
            "system_sleep_disabled": sleep_value == 0 if sleep_value is not None else None,
            "display_sleep_minutes": displaysleep_value,
            "disk_sleep_disabled": disksleep_value == 0 if disksleep_value is not None else None,
            "caffeinate_pid": facts["caffeinate_pid"],
            "prevent_system_sleep": assertions.get("prevent_system_sleep"),
            "prevent_idle_system_sleep": assertions.get("prevent_user_idle_system_sleep"),
            "prevent_display_sleep": assertions.get("prevent_user_idle_display_sleep"),
        },
        "lid": {
            "closed": lid_closed,
            "apple_clamshell_causes_sleep": clamshell_causes_sleep,
            "supported_posture": lid_closed is False,
        },
        "thermal": {
            "state": "nominal" if thermal_ok(cpu_speed_limit, scheduler_limit) else "warning",
            "cpu_speed_limit": cpu_speed_limit,
            "cpu_scheduler_limit": scheduler_limit,
        },
        "network": {
            "tailscale_installed": ts_ip is not None,
            "tailscale_variant": "standalone",
            "tailscale_ip": ts_ip,
            "tailscale_status": "ok" if ts_ip else ts_status,
            "tailscale_sysext_status": ts_sysext,
            "pairling_connect": {
                "route_ready": pc_ready,
                "tailnet_ip": pc_ip,
            },
            "default_interface": default_interface(),
            "lan_ips": lan_ips(),
        },
        "daemon": {
            "pairlingd_pid": notify_pid,
            "listen": listen_entries,
            "reachable_local": daemon_reachable_local,
            "reachable_tailnet": daemon_reachable_tailnet,
        },
        "warnings": [c["message"] for c in checks if not c["ok"]],
        "checks": {c["id"]: "ok" if c["ok"] else c["message"] for c in checks},
        "ts": now,
        "summary": summary,
        "severity": severity,
        "status": posture,
        "facts": facts,
        "actions": recommended_actions(checks),
        "command_errors": {
            "pmset_live": pmset_live_err if code_live else None,
            "pmset_assertions": assertions_err if code_assert else None,
            "pmset_batt": batt_err if code_batt else None,
            "pmset_therm": therm_err if code_therm else None,
            "ioreg": ioreg_err if code_ioreg else None,
            "pmset_enforce": enforce_errors or None,
        },
        "caffeinate": {
            "enforced": ENFORCE_CAFFEINATE,
            "command": " ".join(CAFFEINATE_CMD),
            "pid": facts["caffeinate_pid"],
        },
        "policy": {
            "low_power_mode": LOW_POWER_MODE_POLICY,
        },
    }


def check(identifier: str, ok: bool, good: str, bad: str, severity: str) -> dict[str, Any]:
    return {
        "id": identifier,
        "ok": bool(ok),
        "severity": "ready" if ok else severity,
        "message": good if ok else bad,
    }


def low_power_mode_check(value: int | None) -> dict[str, Any]:
    enabled = bool(value) if value is not None else None
    if LOW_POWER_MODE_POLICY in {"off", "disable", "disabled", "0"}:
        return check("low_power_mode", enabled is False, "Low Power Mode is off.", "Low Power Mode is enabled.", "warning")
    if LOW_POWER_MODE_POLICY in {"on", "enable", "enabled", "1"}:
        return check("low_power_mode", enabled is True, "Low Power Mode is on.", "Low Power Mode is off.", "warning")
    if enabled is True:
        return check("low_power_mode", True, "Low Power Mode is on and preserved for thermal control.", "", "ready")
    if enabled is False:
        return check("low_power_mode", True, "Low Power Mode is off and preserved.", "", "ready")
    return check("low_power_mode", True, "Low Power Mode state is unavailable.", "", "ready")


def thermal_ok(cpu_speed_limit: int | None, scheduler_limit: int | None) -> bool:
    if cpu_speed_limit is not None and cpu_speed_limit < 80:
        return False
    if scheduler_limit is not None and scheduler_limit < 80:
        return False
    return True


def recommended_actions(checks: list[dict[str, Any]]) -> list[str]:
    action_map = {
        "lid_open": "Keep the lid open, or use a proven clamshell setup with external display and power.",
        "system_sleep": "Set system sleep to Never with SleepToggle or pmset.",
        "prevent_system_sleep": "Start the guardian LaunchDaemon so caffeinate can hold a system-sleep assertion.",
        "tailscale_ip": "Start Tailscale and verify the standalone app is connected.",
        "daemon_reachable": "Restart dev.pairling.companiond and verify it binds to the selected route.",
        "thermal": "Reduce thermal load or disconnect hot external-display setups before long missions.",
    }
    actions: list[str] = []
    for item in checks:
        if not item.get("ok"):
            action = action_map.get(str(item.get("id")))
            if action and action not in actions:
                actions.append(action)
    return actions


def manage_caffeinate(ac_power: bool) -> None:
    global caffeinate_proc
    alive = caffeinate_proc is not None and caffeinate_proc.poll() is None
    if not ENFORCE_CAFFEINATE or not ac_power:
        if alive:
            caffeinate_proc.terminate()
            try:
                caffeinate_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                caffeinate_proc.kill()
        caffeinate_proc = None
        return
    if alive:
        return
    caffeinate_proc = subprocess.Popen(
        CAFFEINATE_CMD,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def write_state(payload: dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=STATE_PATH.name + ".", dir=str(STATE_PATH.parent))
    try:
        with os.fdopen(fd, "w") as fh:
            os.fchmod(fh.fileno(), 0o644)
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, STATE_PATH)
        os.chmod(STATE_PATH, 0o644)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def handle_signal(signum: int, frame: Any) -> None:
    global stopping
    stopping = True


def main() -> int:
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    next_pmset_enforce = 0.0
    pmset_enforce_errors: list[str] = []
    while not stopping:
        now = time.time()
        if ENFORCE_CAFFEINATE and now >= next_pmset_enforce:
            pmset_enforce_errors = enforce_pmset_posture()
            next_pmset_enforce = now + 300

        payload = sample(pmset_enforce_errors)
        if ENFORCE_CAFFEINATE and pmset_drift(payload.get("facts", {})):
            pmset_enforce_errors = enforce_pmset_posture()
            next_pmset_enforce = time.time() + 300
            payload = sample(pmset_enforce_errors)
        manage_caffeinate(bool(payload.get("facts", {}).get("ac_power")))
        payload = sample(pmset_enforce_errors)
        write_state(payload)
        deadline = time.time() + INTERVAL_SECONDS
        while not stopping and time.time() < deadline:
            time.sleep(0.5)
    manage_caffeinate(False)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"pairling-power-guardian fatal: {type(exc).__name__}: {exc}", file=sys.stderr)
        manage_caffeinate(False)
        raise
