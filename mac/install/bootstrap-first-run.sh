#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMESTAMP="${PAIRLING_FIRST_RUN_TIMESTAMP:-$(date -u +%Y-%m-%dT%H-%M-%SZ)}"
APP_SUPPORT="${PAIRLING_APP_SUPPORT_ROOT:-${COMPANION_APP_SUPPORT_ROOT:-$HOME/Library/Application Support/Pairling}}"
ARTIFACT_ROOT="${PAIRLING_FIRST_RUN_ARTIFACT_ROOT:-$APP_SUPPORT/audits/first-run-bootstrap-$TIMESTAMP}"
TTL="180"
JSON_MODE="false"
PLAN_ONLY="false"
SKIP_PAIR_WINDOW="false"

usage() {
  cat <<EOF
usage: bootstrap-first-run.sh [--json] [--plan-only] [--ttl seconds] [--skip-pairing-invitation]

Installs and starts the Pairling Mac runtime, verifies first-run readiness, and
opens a pairing invitation. It reports required privacy prompts but does
not pre-grant or reset macOS/iOS privacy permissions.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)
      JSON_MODE="true"
      ;;
    --plan-only)
      PLAN_ONLY="true"
      ;;
    --ttl)
      shift
      TTL="${1:-}"
      if [[ -z "$TTL" ]]; then
        usage >&2
        exit 2
      fi
      ;;
    --skip-pairing-invitation|--skip-pair-window)
      SKIP_PAIR_WINDOW="true"
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
  shift
done

plan_json() {
  python3 - <<'PY'
import json
print(json.dumps({
    "ok": True,
    "schema_version": 1,
    "mode": "plan",
    "steps": [
        "setup_runtime",
        "doctor_first_run",
        "open_pairing_invitation",
        "doctor_first_run_after_pairing_invitation",
        "report_ready_to_pair",
    ],
    "permissions": {
        "mac_automation": "not_required_by_default",
        "mac_accessibility": "not_required_until_terminal_control",
        "ios_local_network": "requires_user_prompt",
        "ios_camera": "requires_user_prompt_for_qr_fallback",
        "tcc_database": "not_modified",
    },
}, indent=2, sort_keys=True))
PY
}

if [[ "$PLAN_ONLY" == "true" ]]; then
  if [[ "$JSON_MODE" == "true" ]]; then
    plan_json
  else
    usage
  fi
  exit 0
fi

mkdir -p "$ARTIFACT_ROOT"

run_step() {
  local name="$1"
  shift
  local log_file="$ARTIFACT_ROOT/$name.log"
  set +e
  "$@" >"$log_file" 2>&1
  local status=$?
  set -e
  printf '%s' "$status"
}

run_json_step() {
  local name="$1"
  local output_file="$ARTIFACT_ROOT/$name.json"
  shift
  set +e
  "$@" >"$output_file" 2>"$ARTIFACT_ROOT/$name.err"
  local status=$?
  set -e
  printf '%s' "$status"
}

setup_status="$(run_step setup "$REPO_ROOT/mac/install/install-runtime.sh" setup)"
doctor_before_status="$(run_json_step doctor-before "$REPO_ROOT/mac/install/doctor.sh" --first-run --json)"

pair_status="0"
pair_json="$ARTIFACT_ROOT/pairing-invitation.json"
if [[ "$SKIP_PAIR_WINDOW" == "true" ]]; then
  printf '{"ok": true, "skipped": true}\n' >"$pair_json"
else
  pair_status="$(run_json_step pairing-invitation "$REPO_ROOT/mac/install/install-runtime.sh" pair --ttl "$TTL" --json)"
fi

doctor_after_status="$(run_json_step doctor-after "$REPO_ROOT/mac/install/doctor.sh" --first-run --json)"

python3 - "$ARTIFACT_ROOT" "$setup_status" "$doctor_before_status" "$pair_status" "$doctor_after_status" "$SKIP_PAIR_WINDOW" "$JSON_MODE" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

artifact_root = Path(sys.argv[1])
setup_status = int(sys.argv[2])
doctor_before_status = int(sys.argv[3])
pair_status = int(sys.argv[4])
doctor_after_status = int(sys.argv[5])
skip_pair_window = sys.argv[6] == "true"
json_mode = sys.argv[7] == "true"


def load_json(name: str) -> dict:
    path = artifact_root / name
    try:
        payload = json.loads(path.read_text())
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


doctor_after = load_json("doctor-after.json")
pair_payload = load_json("pairing-invitation.json")
first_run = doctor_after.get("first_run") if isinstance(doctor_after.get("first_run"), dict) else {}
pair_window_ready = skip_pair_window or bool((first_run.get("pairing") or {}).get("pair_window_open"))
next_action = first_run.get("next_action")
if isinstance(next_action, dict):
    next_action_summary = next_action
else:
    next_action_summary = {
        "id": "review_setup",
        "label": "Review setup",
        "message": str(next_action or "Open Pairling on iPhone and pair with this Mac."),
    }
payload = {
    "ok": setup_status == 0 and doctor_after_status == 0 and pair_status == 0 and pair_window_ready,
    "schema_version": 1,
    "mode": "execute",
    "artifact_root": str(artifact_root),
    "steps": {
        "setup_runtime": {"status": setup_status, "log": str(artifact_root / "setup.log")},
        "doctor_first_run": {"status": doctor_before_status, "json": str(artifact_root / "doctor-before.json")},
        "open_pairing_invitation": {
            "status": pair_status,
            "json": str(artifact_root / "pairing-invitation.json"),
            "skipped": skip_pair_window,
        },
        "doctor_first_run_after_pairing_invitation": {"status": doctor_after_status, "json": str(artifact_root / "doctor-after.json")},
    },
    "ready": {
        "stage": first_run.get("stage", "unknown"),
        "next_action": next_action_summary,
        "pairing_invitation_open": bool((first_run.get("pairing") or {}).get("pair_window_open")),
        "pair_window_open": bool((first_run.get("pairing") or {}).get("pair_window_open")),
        "pair_url": pair_payload.get("pair_url"),
        "product_ready": bool(first_run.get("product_ready")),
        "local_pairing_ready": bool(first_run.get("local_pairing_ready")),
        "remote_access": first_run.get("remote_access") if isinstance(first_run.get("remote_access"), dict) else {},
    },
    "permissions": {
        "mac_automation": "not_required_by_default",
        "mac_accessibility": "not_required_until_terminal_control",
        "ios_local_network": "requires_user_prompt",
        "ios_camera": "requires_user_prompt_for_qr_fallback",
        "tcc_database": "not_modified",
    },
}
if json_mode:
    print(json.dumps(payload, indent=2, sort_keys=True))
else:
    print("Pairling first-run bootstrap complete." if payload["ok"] else "Pairling first-run bootstrap needs attention.")
    print(f"Stage: {payload['ready']['stage']}")
    print(f"Next action: {payload['ready']['next_action'].get('message', payload['ready']['next_action'].get('label', 'Review setup'))}")
    if payload["ready"].get("pair_url"):
        print(f"Pair URL: {payload['ready']['pair_url']}")
    print(f"Artifacts: {artifact_root}")
raise SystemExit(0 if payload["ok"] else 1)
PY
