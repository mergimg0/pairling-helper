#!/usr/bin/env bash
set -euo pipefail
umask 077

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

prepare_artifact_root() {
  python3 - "$1" <<'PY'
import os
import stat
import sys

requested = os.path.abspath(os.path.expanduser(sys.argv[1]))
if requested == os.path.sep:
    raise SystemExit("first-run artifact root cannot be the filesystem root")
target = os.path.join(os.path.realpath(os.path.dirname(requested)), os.path.basename(requested))
components = [component for component in target.split(os.path.sep) if component]
current = os.path.sep
for component in components[:-1]:
    current = os.path.join(current, component)
    try:
        current_stat = os.lstat(current)
    except FileNotFoundError:
        os.mkdir(current, 0o700)
        current_stat = os.lstat(current)
    if stat.S_ISLNK(current_stat.st_mode) or not stat.S_ISDIR(current_stat.st_mode):
        raise SystemExit(f"first-run artifact parent is not a verified directory: {current}")
    if stat.S_IMODE(current_stat.st_mode) & 0o022:
        raise SystemExit(f"first-run artifact parent is writable by another user: {current}")
try:
    os.mkdir(target, 0o700)
except FileExistsError as exc:
    raise SystemExit("first-run artifact root must be created atomically and must not already exist") from exc
target_stat = os.lstat(target)
if (
    stat.S_ISLNK(target_stat.st_mode)
    or not stat.S_ISDIR(target_stat.st_mode)
    or target_stat.st_uid != os.geteuid()
    or stat.S_IMODE(target_stat.st_mode) != 0o700
):
    raise SystemExit("first-run artifact root must be an owned, non-symlink directory with mode 0700")
print(target)
PY
}

create_artifact_file() {
  python3 -c '
import os
import stat
import sys

path = os.path.abspath(sys.argv[1])
parent = os.path.dirname(path)
parent_stat = os.lstat(parent)
if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
    raise SystemExit("artifact parent must be a non-symlink directory")
if parent_stat.st_uid != os.geteuid() or stat.S_IMODE(parent_stat.st_mode) != 0o700:
    raise SystemExit("artifact parent must be owned by the current user with mode 0700")
if not hasattr(os, "O_NOFOLLOW"):
    raise SystemExit("platform cannot create artifacts without following symlinks")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
descriptor = os.open(path, flags, 0o600)
try:
    file_stat = os.fstat(descriptor)
    if file_stat.st_uid != os.geteuid() or stat.S_IMODE(file_stat.st_mode) != 0o600:
        raise SystemExit("artifact file was not created with mode 0600")
finally:
    os.close(descriptor)
' "$1"
}

redact_pairing_audit() {
  python3 -c '
import json
import re
import sys

sensitive = {"secret", "token", "proof_secret", "bearer_token", "auth_token"}

def redact(value):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            folded = str(key).casefold()
            if folded in sensitive or folded == "pair_url":
                result[key] = "<redacted>"
            else:
                result[key] = redact(item)
        return result
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value

label_pattern = re.compile(r"^(\s*(?:secret|token|proof_secret|bearer_token|auth_token):\s*).*$", re.IGNORECASE)
json_field_pattern = re.compile(r"^(\s*\"(?:secret|token|proof_secret|bearer_token|auth_token)\"\s*:\s*).*$", re.IGNORECASE)
sensitive_json_key = re.compile(r"\"(?:secret|token|proof_secret|bearer_token|auth_token)\"\s*:", re.IGNORECASE)
query_pattern = re.compile(r"([?&](?:secret|token|proof_secret|bearer_token|auth_token)=)[^&\s\"<>]*", re.IGNORECASE)
pair_url_prefix = re.compile(r"\"pair_url\"\s*:\s*\"$", re.IGNORECASE)

for line in sys.stdin:
    ending = "\n" if line.endswith("\n") else ""
    content = line[:-1] if ending else line
    try:
        payload = json.loads(content.strip())
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, (dict, list)):
        indentation = content[: len(content) - len(content.lstrip())]
        content = indentation + json.dumps(redact(payload), sort_keys=True)
    else:
        label_match = label_pattern.match(content)
        json_field_match = json_field_pattern.match(content)
        if label_match:
            content = label_match.group(1) + "<redacted>"
        elif json_field_match:
            comma = "," if content.rstrip().endswith(",") else ""
            content = json_field_match.group(1) + "\"<redacted>\"" + comma
        elif sensitive_json_key.search(content):
            indentation = content[: len(content) - len(content.lstrip())]
            content = indentation + "\"<redacted>\""
        elif "pairling://pair?" in content or "https://pairling.dev/pair/?" in content:
            marker = "https://pairling.dev/pair/?" if "https://pairling.dev/pair/?" in content else "pairling://pair?"
            prefix, _, _ = content.partition(marker)
            suffix = ""
            if pair_url_prefix.search(prefix):
                suffix = "\"," if content.rstrip().endswith(",") else "\""
            content = prefix + marker + "<redacted>" + suffix
        else:
            content = query_pattern.sub(lambda match: match.group(1) + "%3Credacted%3E", content)
    sys.stdout.write(content + ending)
'
}

redact_pairing_json() {
  python3 -c '
import json
import sys
import urllib.parse

sensitive = {"secret", "token", "proof_secret", "bearer_token", "auth_token"}

def redact_url(value):
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return "<redacted>"
    query = []
    for key, item in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        if key.casefold() in sensitive:
            query.append((key, "<redacted>"))
        else:
            query.append((key, item))
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), parsed.fragment))

def redact(value):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            folded = str(key).casefold()
            if folded in sensitive:
                result[key] = "<redacted>"
            elif folded == "pair_url" and isinstance(item, str):
                result[key] = redact_url(item)
            else:
                result[key] = redact(item)
        return result
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value

try:
    payload = json.load(sys.stdin)
except (json.JSONDecodeError, UnicodeDecodeError):
    payload = {"ok": False, "redacted": True, "error": {"code": "pairing_output_unavailable"}}
print(json.dumps(redact(payload), indent=2, sort_keys=True))
'
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

ARTIFACT_ROOT="$(prepare_artifact_root "$ARTIFACT_ROOT")"

run_step() {
  local name="$1"
  shift
  local log_file="$ARTIFACT_ROOT/$name.log"
  local status=0
  local -a pipe_status=()
  create_artifact_file "$log_file"
  set +e
  "$@" 2>&1 | redact_pairing_audit >"$log_file"
  pipe_status=("${PIPESTATUS[@]}")
  status="${pipe_status[0]}"
  if [[ "${pipe_status[1]}" != "0" ]]; then
    status=1
  fi
  set -e
  printf '%s' "$status"
}

run_step_setup() {
  # The setup step renders the guided screen, so its output must reach the
  # controlling terminal while a redacted copy is written to setup.log. The
  # command exit code always comes from PIPESTATUS, never tee or the redactor.
  local name="$1"
  shift
  local log_file="$ARTIFACT_ROOT/$name.log"
  local status=0
  local -a pipe_status=()
  create_artifact_file "$log_file"
  set +e
  if { : >/dev/tty; } 2>/dev/null; then
    # PAIRLING_WIZARD tells install-runtime.sh to render even though its stdout
    # is piped. tee sends the unredacted invitation only to the controlling
    # terminal; the copy that continues into the audit log is redacted.
    PAIRLING_WIZARD=1 "$@" 2>&1 | tee /dev/tty | redact_pairing_audit >"$log_file"
    pipe_status=("${PIPESTATUS[@]}")
    status="${pipe_status[0]}"
    if [[ "${pipe_status[1]}" != "0" || "${pipe_status[2]}" != "0" ]]; then
      status=1
    fi
  else
    "$@" 2>&1 | redact_pairing_audit >"$log_file"
    pipe_status=("${PIPESTATUS[@]}")
    status="${pipe_status[0]}"
    if [[ "${pipe_status[1]}" != "0" ]]; then
      status=1
    fi
  fi
  set -e
  printf '%s' "$status"
}

run_json_step() {
  local name="$1"
  local output_file="$ARTIFACT_ROOT/$name.json"
  local error_file="$ARTIFACT_ROOT/$name.err"
  shift
  local status=0
  local -a pipe_status=()
  create_artifact_file "$output_file"
  create_artifact_file "$error_file"
  set +e
  "$@" 2> >(redact_pairing_audit >"$error_file") | redact_pairing_audit >"$output_file"
  pipe_status=("${PIPESTATUS[@]}")
  status="${pipe_status[0]}"
  if [[ "${pipe_status[1]}" != "0" ]]; then
    status=1
  fi
  wait || status=1
  set -e
  printf '%s' "$status"
}

PAIR_OUTPUT=""
PAIR_STATUS=0
run_pairing_step() {
  local output_file="$ARTIFACT_ROOT/pairing-invitation.json"
  local error_file="$ARTIFACT_ROOT/pairing-invitation.err"
  local redaction_status=0
  create_artifact_file "$output_file"
  create_artifact_file "$error_file"
  set +e
  PAIR_OUTPUT="$("$@" 2> >(redact_pairing_audit >"$error_file"))"
  PAIR_STATUS=$?
  wait || PAIR_STATUS=1
  printf '%s' "$PAIR_OUTPUT" | redact_pairing_json >"$output_file"
  redaction_status="${PIPESTATUS[1]}"
  if [[ "$redaction_status" != "0" ]]; then
    PAIR_STATUS=1
  fi
  set -e
}

setup_status="$(run_step_setup setup "$REPO_ROOT/mac/install/install-runtime.sh" setup)"
doctor_before_status="$(run_json_step doctor-before "$REPO_ROOT/mac/install/doctor.sh" --first-run --json)"

pair_status="0"
pair_json="$ARTIFACT_ROOT/pairing-invitation.json"
if [[ "$SKIP_PAIR_WINDOW" == "true" ]]; then
  PAIR_OUTPUT='{"ok": true, "skipped": true}'
  create_artifact_file "$pair_json"
  printf '%s' "$PAIR_OUTPUT" | redact_pairing_json >"$pair_json"
else
  run_pairing_step "$REPO_ROOT/mac/install/install-runtime.sh" pair --ttl "$TTL" --json
  pair_status="$PAIR_STATUS"
fi

doctor_after_status="$(run_json_step doctor-after "$REPO_ROOT/mac/install/doctor.sh" --first-run --json)"

python3 - "$ARTIFACT_ROOT" "$setup_status" "$doctor_before_status" "$pair_status" "$doctor_after_status" "$SKIP_PAIR_WINDOW" "$JSON_MODE" 3< <(printf '%s' "$PAIR_OUTPUT") <<'PY'
from __future__ import annotations

import json
import os
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
try:
    with os.fdopen(3, "r", encoding="utf-8") as pair_stream:
        candidate = json.load(pair_stream)
    pair_payload = candidate if isinstance(candidate, dict) else {}
except Exception:
    pair_payload = {}
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
