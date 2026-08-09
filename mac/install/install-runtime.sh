#!/usr/bin/env bash
set -euo pipefail

export PYTHONDONTWRITEBYTECODE=1
unset PYTHONPYCACHEPREFIX

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
MANIFEST_REPO_PATH="$REPO_ROOT"
VERSION="$(tr -d '[:space:]' < "$REPO_ROOT/mac/VERSION")"
read_source_stamp() {
  local path="$1"
  if [[ -f "$path" ]]; then
    tr -d '[:space:]' < "$path"
  fi
}
REVISION="${PAIRLING_SOURCE_REVISION:-$(read_source_stamp "$REPO_ROOT/mac/SOURCE_REVISION")}"
if [[ -z "$REVISION" ]]; then
  REVISION="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || true)"
fi
REVISION="${REVISION:-unknown}"
BRANCH="${PAIRLING_SOURCE_BRANCH:-$(read_source_stamp "$REPO_ROOT/mac/SOURCE_BRANCH")}"
if [[ -z "$BRANCH" ]]; then
  BRANCH="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
fi
BRANCH="${BRANCH:-unknown}"
PACKAGED_SOURCE_PATHS=(
  "mac/VERSION"
  "mac/companiond"
  "mac/connectd/cmd"
  "mac/connectd/internal"
  "mac/connectd/go.mod"
  "mac/connectd/go.sum"
  "mac/install"
  "mac/mcp"
  "mac/packaging/bin/pairling"
  "mac/packaging/pairling_attach.py"
  "relay/app_attest_validator.py"
)
SOURCE_DIRTY="${PAIRLING_SOURCE_DIRTY:-$(read_source_stamp "$REPO_ROOT/mac/SOURCE_DIRTY")}"
if [[ -z "$SOURCE_DIRTY" ]]; then
  SOURCE_DIRTY="false"
  if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 && \
     [[ -n "$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all -- "${PACKAGED_SOURCE_PATHS[@]}" 2>/dev/null)" ]]; then
    SOURCE_DIRTY="true"
  fi
fi

PAIRLING_RUNTIME_PORT="${PAIRLING_RUNTIME_PORT:-7773}"
PAIRLING_DAEMON_LABEL="dev.pairling.companiond"
PAIRLING_CONNECTD_LABEL="dev.pairling.connectd"
PAIRLING_PTYBROKER_LABEL="dev.pairling.ptybroker"
AUTOMATION_HELPER_BUNDLE_ID="dev.pairling.automation"
AUTOMATION_LAUNCH_AGENT_LABEL="dev.pairling.automation"
APP_SUPPORT="${PAIRLING_APP_SUPPORT_ROOT:-${COMPANION_APP_SUPPORT_ROOT:-$HOME/Library/Application Support/Pairling}}"
while [[ "$APP_SUPPORT" != "/" && "$APP_SUPPORT" == */ ]]; do
  APP_SUPPORT="${APP_SUPPORT%/}"
done
RUNTIME_ROOT="$APP_SUPPORT/runtime"
RELEASES_ROOT="$RUNTIME_ROOT/releases"
SOURCE_SNAPSHOT_ROOT="$RUNTIME_ROOT/source-snapshots"
STATE_ROOT="$APP_SUPPORT/state"
PAIR_ROOT="$APP_SUPPORT/pair"
LOGS_ROOT="${PAIRLING_LOGS_ROOT:-${COMPANION_LOGS_ROOT:-$HOME/Library/Logs/Pairling}}"
while [[ "$LOGS_ROOT" != "/" && "$LOGS_ROOT" == */ ]]; do
  LOGS_ROOT="${LOGS_ROOT%/}"
done
if [[ "${PAIRLING_PAIRDROP_ROOT+x}" == "x" ]]; then
  PAIRDROP_ROOT_WAS_SET="1"
  PAIRDROP_ROOT_INPUT="$PAIRLING_PAIRDROP_ROOT"
else
  PAIRDROP_ROOT_WAS_SET="0"
  PAIRDROP_ROOT_INPUT=""
fi
PAIRDROP_ROOT="$PAIRDROP_ROOT_INPUT"
PLIST_BUILD_DIR="$RUNTIME_ROOT/plists"
CURRENT_LINK="$RUNTIME_ROOT/current"
PREVIOUS_LINK="$RUNTIME_ROOT/previous"
RELEASE_NAME="$VERSION-$REVISION"
RELEASE_ROOT=""
CONFIG_FILE="$APP_SUPPORT/config.json"
DEVICES_DB="$APP_SUPPORT/devices.sqlite"
MCP_CREDENTIAL="$APP_SUPPORT/mcp-bridge.json"
INSTALL_HISTORY="$STATE_ROOT/install-history.jsonl"
USER_PLIST="$HOME/Library/LaunchAgents/$PAIRLING_DAEMON_LABEL.plist"
CONNECTD_USER_PLIST="$HOME/Library/LaunchAgents/$PAIRLING_CONNECTD_LABEL.plist"
PTYBROKER_USER_PLIST="$HOME/Library/LaunchAgents/$PAIRLING_PTYBROKER_LABEL.plist"
AUTOMATION_ROOT="$APP_SUPPORT/automation"
AUTOMATION_APP_PATH="$AUTOMATION_ROOT/Pairling.app"
AUTOMATION_ROLLBACK_APP="$AUTOMATION_ROOT/.Pairling.rollback.app"
AUTOMATION_ABSENT_MARKER="$AUTOMATION_ROOT/.Pairling.rollback-absent"
AUTOMATION_USER_PLIST="$HOME/Library/LaunchAgents/$AUTOMATION_LAUNCH_AGENT_LABEL.plist"
AUTOMATION_AGENT_ACTIVATED=0
LEGACY_INJECTOR_APP="$HOME/Applications/ClaudeInjector.app"
MCP_SERVER_DIR="$HOME/.claude/mcp-servers"
MCP_SERVER_SHIM="$MCP_SERVER_DIR/phone-tools.py"
USER_PAIRLING_WRAPPER="${PAIRLING_USER_BIN_DIR:-$HOME/.local/bin}/pairling"

# Resolve no interpreter through installer-owned paths until their direct
# directory boundary has passed the same symlink check used before mutation.
if [[ -L "$APP_SUPPORT" ]]; then
  printf 'ERROR: Pairling app support path must not be a symlink: %s\n' "$APP_SUPPORT" >&2
  exit 1
fi
if [[ -L "$RUNTIME_ROOT" ]]; then
  printf 'ERROR: Pairling runtime path must not be a symlink: %s\n' "$RUNTIME_ROOT" >&2
  exit 1
fi

PYTHON_CODESIGN_IDENTIFIER="dev.pairling.python"

sha256_with_system_tools() {
  /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
}

verify_package_snapshot_before_execution() {
  local package_root="${PAIRLING_RUNTIME_PACKAGE_ROOT:-}"
  local payload_manifest="$(dirname "$REPO_ROOT")/payload-manifest.json"
  local snapshot_mode="${PAIRLING_PACKAGE_SNAPSHOT:-}"
  local snapshot_root resolved_repo resolved_runtime expected_payload expected_runtime actual_payload actual_runtime owner mode
  if [[ -z "$snapshot_mode" ]]; then
    if [[ -n "$package_root" && -f "$payload_manifest" ]]; then
      printf 'ERROR: npm package setup must enter through the verified Pairling shim snapshot.\n' >&2
      return 1
    fi
    return 0
  fi
  if [[ "$snapshot_mode" != "payload" && "$snapshot_mode" != "full" ]]; then
    printf 'ERROR: verified npm snapshot mode must be payload or full.\n' >&2
    return 1
  fi
  expected_payload="${PAIRLING_VERIFIED_PAYLOAD_MANIFEST_SHA256:-}"
  expected_runtime="${PAIRLING_VERIFIED_RUNTIME_MANIFEST_SHA256:-}"
  if [[ ! "$expected_payload" =~ ^[0-9a-f]{64}$ || ! "$expected_runtime" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'ERROR: verified npm snapshot manifest digests are missing or malformed.\n' >&2
    return 1
  fi
  if [[ -L "$REPO_ROOT" || ! -d "$REPO_ROOT" || -L "$package_root" || ! -d "$package_root" ]]; then
    printf 'ERROR: verified npm snapshot roots must be real directories.\n' >&2
    return 1
  fi
  snapshot_root="$(cd "$REPO_ROOT/../.." && pwd -P)"
  resolved_repo="$(cd "$REPO_ROOT" && pwd -P)"
  resolved_runtime="$(cd "$package_root" && pwd -P)"
  if [[ "$resolved_repo" != "$snapshot_root/pairling/payload" ]]; then
    printf 'ERROR: verified npm snapshot layout is not canonical.\n' >&2
    return 1
  fi
  if [[ "$snapshot_mode" == "full" && "$resolved_runtime" != "$snapshot_root/runtime" ]]; then
    printf 'ERROR: verified full npm snapshot runtime layout is not canonical.\n' >&2
    return 1
  fi
  if [[ "$snapshot_mode" == "payload" && "$resolved_runtime" == "$snapshot_root"/* ]]; then
    printf 'ERROR: verified payload npm snapshot must use the direct signed runtime package.\n' >&2
    return 1
  fi
  if [[ -L "$snapshot_root" || ! -d "$snapshot_root" ]]; then
    printf 'ERROR: verified npm snapshot root is missing or linked: %s\n' "$snapshot_root" >&2
    return 1
  fi
  owner="$(stat -f '%u' "$snapshot_root" 2>/dev/null || printf unknown)"
  mode="$(stat -f '%Lp' "$snapshot_root" 2>/dev/null || printf unknown)"
  if [[ "$owner" != "$(id -u)" || "$mode" != "700" ]]; then
    printf 'ERROR: verified npm snapshot root must be private and owned by this user: %s\n' "$snapshot_root" >&2
    return 1
  fi
  if [[ -L "$payload_manifest" || ! -f "$payload_manifest" || -L "$package_root/manifest.json" || ! -f "$package_root/manifest.json" ]]; then
    printf 'ERROR: verified npm snapshot manifests are missing or linked.\n' >&2
    return 1
  fi
  actual_payload="$(sha256_with_system_tools "$payload_manifest")"
  actual_runtime="$(sha256_with_system_tools "$package_root/manifest.json")"
  if [[ "$actual_payload" != "$expected_payload" || "$actual_runtime" != "$expected_runtime" ]]; then
    printf 'ERROR: verified npm snapshot manifest digest changed before installer execution.\n' >&2
    return 1
  fi
  if ! /usr/bin/python3 - "$payload_manifest" "$package_root/manifest.json" "$expected_runtime" <<'PY'
import json
import sys
from pathlib import Path

payload_path = Path(sys.argv[1])
runtime_path = Path(sys.argv[2])
expected_runtime_digest = sys.argv[3]
try:
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise SystemExit(f"verified npm snapshot manifest could not be parsed: {exc}") from exc

architecture = runtime.get("architecture")
if architecture not in ("arm64", "x64"):
    raise SystemExit("verified npm runtime architecture is missing or unsupported")
runtime_manifests = payload.get("runtime_manifests")
if not isinstance(runtime_manifests, dict) or set(runtime_manifests) != {"darwin-arm64", "darwin-x64"}:
    raise SystemExit("verified npm payload runtime manifest identities are incomplete")
platform_key = f"darwin-{architecture}"
if runtime_manifests.get(platform_key) != expected_runtime_digest:
    raise SystemExit("verified npm runtime manifest is not bound to the selected payload platform")
PY
  then
    printf 'ERROR: verified npm snapshot platform binding failed.\n' >&2
    return 1
  fi
}

resolve_python_bin() {
  local explicit="${PAIRLING_DAEMON_PYTHON:-${COMPANION_DAEMON_PYTHON:-}}"
  local candidate marker
  if [[ -n "$explicit" ]]; then
    if [[ ! -x "$explicit" ]]; then
      printf 'ERROR: configured Pairling Python is not executable: %s\n' "$explicit" >&2
      return 1
    fi
    marker="$("$explicit" -c 'print("pairling-python-ready")' 2>/dev/null || true)"
    if [[ "$marker" != "pairling-python-ready" ]]; then
      printf 'ERROR: configured Pairling Python is not functional: %s\n' "$explicit" >&2
      return 1
    fi
    printf '%s\n' "$explicit"
    return 0
  fi
  # Never execute through runtime/current while bootstrapping. The link and its
  # release have not passed managed-release verification or the install lock yet.
  for candidate in /usr/bin/python3; do
    [[ -n "$candidate" && -x "$candidate" ]] || continue
    marker="$("$candidate" -c 'print("pairling-python-ready")' 2>/dev/null || true)"
    if [[ "$marker" == "pairling-python-ready" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  printf 'ERROR: Pairling could not resolve a Python 3 interpreter. Reinstall the Pairling runtime package.\n' >&2
  return 1
}

verify_developer_id_application() {
  local path="$1" team="$2"
  /usr/bin/codesign --verify --strict --verbose=2 \
    -R="anchor apple generic and certificate leaf[subject.OU] = \"$team\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists" \
    "$path" >/dev/null 2>&1
}

verify_package_python_before_execution() {
  local explicit="${PAIRLING_DAEMON_PYTHON:-${COMPANION_DAEMON_PYTHON:-}}"
  local package_root="${PAIRLING_RUNTIME_PACKAGE_ROOT:-}"
  local resolved_root python_root identifier team required_team
  [[ -n "$explicit" && -n "$package_root" ]] || return 0
  case "$explicit" in
    */python/bin/python3) ;;
    *) return 0 ;;
  esac
  if [[ -L "$package_root" || ! -d "$package_root" || ! -f "$package_root/manifest.json" || -L "$package_root/manifest.json" ]]; then
    printf 'ERROR: npm runtime package root or manifest is missing or linked: %s\n' "$package_root" >&2
    return 1
  fi
  if [[ -L "$explicit" || ! -f "$explicit" || ! -x "$explicit" ]]; then
    printf 'ERROR: npm vendored Python must be a real executable file: %s\n' "$explicit" >&2
    return 1
  fi
  resolved_root="$(cd "$package_root" && pwd -P)"
  python_root="$(cd "$(dirname "$explicit")/../.." && pwd -P)"
  if [[ "$python_root" != "$resolved_root" ]]; then
    printf 'ERROR: npm vendored Python is outside its declared runtime package: %s\n' "$explicit" >&2
    return 1
  fi
  if ! /usr/bin/codesign --verify --strict "$explicit" >/dev/null 2>&1; then
    printf 'ERROR: npm vendored Python failed code signature verification before execution: %s\n' "$explicit" >&2
    return 1
  fi
  identifier="$(/usr/bin/codesign -dvv "$explicit" 2>&1 | sed -n 's/^Identifier=//p')"
  if [[ "$identifier" != "$PYTHON_CODESIGN_IDENTIFIER" ]]; then
    printf 'ERROR: npm vendored Python identifier is not %s: %s\n' "$PYTHON_CODESIGN_IDENTIFIER" "$explicit" >&2
    return 1
  fi
  required_team="${PAIRLING_CONNECTD_TEAM_ID:-965AVD34A3}"
  if [[ "$required_team" != "-" ]]; then
    if ! verify_developer_id_application "$explicit" "$required_team"; then
      printf 'ERROR: npm vendored Python is not signed with the expected Developer ID Application certificate: %s\n' "$explicit" >&2
      return 1
    fi
    team="$(/usr/bin/codesign -dvv "$explicit" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
    if [[ "$team" != "$required_team" ]]; then
      printf 'ERROR: npm vendored Python TeamIdentifier does not match %s: %s\n' "$required_team" "$explicit" >&2
      return 1
    fi
  fi
}

verify_package_snapshot_before_execution
verify_package_python_before_execution
PYTHON3_BIN="$(resolve_python_bin)"
CONTROL_PYTHON_BIN="$PYTHON3_BIN"

pin_control_python() {
  local resolved
  resolved="$("$PYTHON3_BIN" - "$PYTHON3_BIN" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
)"
  if [[ -z "$resolved" || ! -x "$resolved" ]]; then
    log "ERROR: Pairling could not pin its control interpreter before changing runtime/current." >&2
    return 1
  fi
  if [[ "$("$resolved" -B -c 'print("pairling-python-ready")' 2>/dev/null || true)" != "pairling-python-ready" ]]; then
    log "ERROR: Pairling control interpreter is not functional: $resolved" >&2
    return 1
  fi
  CONTROL_PYTHON_BIN="$resolved"
  PYTHON3_BIN="$resolved"
}
PAIRDROP_ROOT="$("$PYTHON3_BIN" - "$PAIRDROP_ROOT_WAS_SET" "$PAIRDROP_ROOT_INPUT" "$CONFIG_FILE" "$HOME/PairDrop" <<'PY'
import json
import sys
from pathlib import Path

was_set, configured, config_path, default = sys.argv[1:]
selected = configured
if was_set != "1":
    try:
        payload = json.loads(Path(config_path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        payload = None
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Pairling config cannot resolve PairDrop storage: {type(exc).__name__}") from exc
    paths = payload.get("paths") if isinstance(payload, dict) else None
    selected = str(paths.get("pairdrop") or "") if isinstance(paths, dict) else ""
    if not selected:
        selected = default
path = Path(selected).expanduser()
if not path.is_absolute():
    raise SystemExit("PAIRLING_PAIRDROP_ROOT must be an absolute path")
print(path.resolve(strict=False))
PY
)"
export PAIRLING_PAIRDROP_ROOT="$PAIRDROP_ROOT"
# P3 Python custody: the npm shim points PAIRLING_DAEMON_PYTHON at the vendored
# CPython inside the platform runtime package (…/python/bin/python3). When that
# is in play we stage the whole interpreter into the release tree and run the
# daemon under it, so a Pairling-signed python (identity dev.pairling.python),
# not a generic system python3, owns the daemon's TCC grants — and npm churn
# can't remove the running interpreter.
DRY_RUN="${PAIRLING_DRY_RUN:-0}"

log() {
  printf '%s\n' "$*"
}

display_path() {
  local path="$1"
  case "$path" in
    "$HOME"/*) printf '~/%s\n' "${path#"$HOME"/}" ;;
    "$HOME") printf '~\n' ;;
    *) printf '%s\n' "$path" ;;
  esac
}

is_dry_run() {
  [[ "$DRY_RUN" == "1" || "$DRY_RUN" == "true" || "$DRY_RUN" == "TRUE" ]]
}

# launchd_skipped is true when a testing smoke run asked us not to touch launchd,
# so a real setup can render the polished screen without booting the dev.pairling
# agents. is_dry_run already suppresses these launchctl calls in a preview. This
# adds the explicit testing skip on top of that, mirroring the pattern in
# mac/testing/reset-first-run-state.sh. A normal run leaves the variable unset,
# so the check is false and launchctl runs exactly as before.
launchd_skipped() {
  [ "${PAIRLING_TESTING_SKIP_LAUNCHD:-0}" = 1 ]
}

setup_intro() {
  # When the guided screen is on and this is not a dry run, draw the optional
  # one-shot splash tied to a real recheck. It is bash-only and skippable, and it
  # never aborts setup. The three plain log lines below are the WIZARD_TUI=0
  # fallback and they always print.
  if [ "${WIZARD_TUI:-0}" = 1 ] && ! is_dry_run; then
    wizard_splash || true
  fi
  log "Pairling setup"
  log "This stages the Mac runtime and opens a pairing code for the iPhone."
  log ""
}

# ----- Guided setup: TTY-aware stage/progress wrapper -----
# All guided output is plain printf and gated on one IS_TTY check, so it reads as
# a clear numbered flow in a normal terminal and degrades to plain prefixed lines
# in a pipe, in CI, or under the bootstrap-first-run.sh log capture. Setting
# PAIRLING_GUIDED_PLAIN=1 forces the ASCII form even on a TTY.
if [ -t 1 ] && [ "${PAIRLING_GUIDED_PLAIN:-0}" != "1" ]; then
  GUIDED_TTY=1
else
  GUIDED_TTY=0
fi
GUIDED_STAGE_TOTAL=8
GUIDED_STAGE_N=0
GUIDED_STAGE_CURRENT=""
GUIDED_COMPLETE=0
# Set to 1 only before an integrity or code signature exit so guided_on_exit
# shows the no-bypass fatal recovery menu instead of the recoverable one. It
# stays 0 for every recoverable failure. Declared here so it is always defined
# under set -u.
WIZARD_FATAL=0
INSTALL_TRANSACTION_ACTIVE=0
INSTALL_TRANSACTION_DIR=""
INSTALL_TRANSACTION_OPERATION=""
INSTALL_TRANSACTION_ROOT="$RUNTIME_ROOT/transactions"
INSTALL_TRANSACTION_PENDING="$INSTALL_TRANSACTION_ROOT/pending"
INSTALL_TRANSACTION_COMMITTED="$INSTALL_TRANSACTION_ROOT/committed"
INSTALL_TRANSACTION_RECOVERED="$INSTALL_TRANSACTION_ROOT/recovered"
INSTALL_LOCK_DIR="$RUNTIME_ROOT/.install.lock"
INSTALL_LOCK_HELD=0
ACTIVE_STAGING_DIR=""
ACTIVE_SOURCE_SNAPSHOT=""
GUIDED_FAILURE_SOURCE_PATH=""
GUIDED_FAILURE_PATH=""

validate_app_support_root() {
  if [[ "$APP_SUPPORT" != /* || "$APP_SUPPORT" == "/" || "$APP_SUPPORT" == "$HOME" ]]; then
    printf 'ERROR: Pairling app support path is unsafe: %s\n' "$APP_SUPPORT" >&2
    return 1
  fi
  case "/$APP_SUPPORT/" in
    */../*|*/./*)
      printf 'ERROR: Pairling app support path is not canonical: %s\n' "$APP_SUPPORT" >&2
      return 1
      ;;
  esac

  local path label owner
  while IFS='|' read -r path label; do
    [[ -n "$path" ]] || continue
    if [[ -L "$path" ]]; then
      printf 'ERROR: Pairling %s path must not be a symlink: %s\n' "$label" "$path" >&2
      return 1
    fi
    if [[ -e "$path" && ! -d "$path" ]]; then
      printf 'ERROR: Pairling %s path must be a directory: %s\n' "$label" "$path" >&2
      return 1
    fi
    if [[ -d "$path" ]]; then
      owner="$(stat -f '%u' "$path" 2>/dev/null || printf 'unknown')"
      if [[ "$owner" != "$(id -u)" ]]; then
        printf 'ERROR: Pairling %s path must be owned by the current user: %s\n' "$label" "$path" >&2
        return 1
      fi
    fi
  done <<EOF
$APP_SUPPORT|app support
$RUNTIME_ROOT|runtime
$RELEASES_ROOT|runtime releases
$INSTALL_TRANSACTION_ROOT|runtime transactions
$PLIST_BUILD_DIR|runtime plist staging
$STATE_ROOT|state
$PAIR_ROOT|pairing state
$APP_SUPPORT/modules|modules
$LOGS_ROOT|logs
EOF
}

install_lock_wait_seconds() {
  local raw="${PAIRLING_INSTALL_LOCK_WAIT_SECONDS:-30}"
  if [[ ! "$raw" =~ ^[0-9]+$ ]]; then
    printf 'ERROR: PAIRLING_INSTALL_LOCK_WAIT_SECONDS must be a whole number.\n' >&2
    return 2
  fi
  printf '%s\n' "$raw"
}

install_lock_age_seconds() {
  local modified now
  modified="$(stat -f '%m' "$INSTALL_LOCK_DIR" 2>/dev/null || printf '0')"
  now="$(date +%s)"
  if [[ "$modified" =~ ^[0-9]+$ && "$modified" -le "$now" ]]; then
    printf '%s\n' "$((now - modified))"
  else
    printf '0\n'
  fi
}

remove_stale_install_lock() {
  local owner="${1:-}"
  [[ -d "$INSTALL_LOCK_DIR" && ! -L "$INSTALL_LOCK_DIR" ]] || return 1
  if [[ -n "$owner" && "$owner" =~ ^[0-9]+$ ]] && kill -0 "$owner" 2>/dev/null; then
    return 1
  fi
  rm -f "$INSTALL_LOCK_DIR/pid" "$INSTALL_LOCK_DIR/started_at"
  rmdir "$INSTALL_LOCK_DIR" 2>/dev/null
}

acquire_install_lock() {
  local wait_seconds deadline owner age
  validate_app_support_root
  mkdir -p "$RUNTIME_ROOT"
  wait_seconds="$(install_lock_wait_seconds)" || return $?
  deadline="$(( $(date +%s) + wait_seconds ))"
  while true; do
    if mkdir "$INSTALL_LOCK_DIR" 2>/dev/null; then
      printf '%s\n' "$$" > "$INSTALL_LOCK_DIR/pid"
      date -u '+%Y-%m-%dT%H:%M:%SZ' > "$INSTALL_LOCK_DIR/started_at"
      INSTALL_LOCK_HELD=1
      return 0
    fi
    if [[ -L "$INSTALL_LOCK_DIR" || ! -d "$INSTALL_LOCK_DIR" ]]; then
      printf 'ERROR: Pairling install lock is not a real directory: %s\n' "$INSTALL_LOCK_DIR" >&2
      return 1
    fi
    owner="$(tr -dc '0-9' < "$INSTALL_LOCK_DIR/pid" 2>/dev/null || true)"
    age="$(install_lock_age_seconds)"
    if [[ -n "$owner" && "$owner" =~ ^[0-9]+$ ]] && ! kill -0 "$owner" 2>/dev/null; then
      remove_stale_install_lock "$owner" || true
      continue
    fi
    if [[ -z "$owner" && "$age" -ge 5 ]]; then
      remove_stale_install_lock || true
      continue
    fi
    if [[ "$(date +%s)" -ge "$deadline" ]]; then
      printf 'ERROR: another Pairling install operation owns %s (pid: %s).\n' "$INSTALL_LOCK_DIR" "${owner:-unknown}" >&2
      return 1
    fi
    sleep 0.2
  done
}

release_install_lock() {
  [[ "$INSTALL_LOCK_HELD" == 1 ]] || return 0
  local owner
  owner="$(tr -dc '0-9' < "$INSTALL_LOCK_DIR/pid" 2>/dev/null || true)"
  if [[ -n "$owner" && "$owner" != "$$" ]]; then
    printf 'ERROR: Pairling install lock ownership changed from %s to %s.\n' "$$" "$owner" >&2
    return 1
  fi
  rm -f "$INSTALL_LOCK_DIR/pid" "$INSTALL_LOCK_DIR/started_at"
  if ! rmdir "$INSTALL_LOCK_DIR" 2>/dev/null; then
    printf 'ERROR: Pairling could not release install lock %s.\n' "$INSTALL_LOCK_DIR" >&2
    return 1
  fi
  INSTALL_LOCK_HELD=0
}

cleanup_active_staging() {
  if [[ -n "$ACTIVE_STAGING_DIR" && -d "$ACTIVE_STAGING_DIR" ]]; then
    remove_release_tree "$ACTIVE_STAGING_DIR"
  fi
  ACTIVE_STAGING_DIR=""
}

cleanup_source_snapshot() {
  if [[ -n "$ACTIVE_SOURCE_SNAPSHOT" && -d "$ACTIVE_SOURCE_SNAPSHOT" ]]; then
    remove_source_snapshot_tree "$ACTIVE_SOURCE_SNAPSHOT"
    fsync_directory "$SOURCE_SNAPSHOT_ROOT"
  fi
  ACTIVE_SOURCE_SNAPSHOT=""
}

remove_source_snapshot_tree() {
  local target="$1"
  case "$target" in
    "$SOURCE_SNAPSHOT_ROOT"/.package.*) ;;
    *)
      log "ERROR: refusing to remove an unmanaged Pairling source snapshot: $target" >&2
      return 1
      ;;
  esac
  if [[ -L "$target" || ! -d "$target" ]]; then
    log "ERROR: Pairling source snapshot is not a real managed directory: $target" >&2
    return 1
  fi
  /bin/chmod -RN "$target" 2>/dev/null || true
  find -P "$target" -type d -exec chmod u+rwx {} +
  find -P "$target" -type f -exec chmod u+rw {} +
  rm -rf "$target"
  if [[ -e "$target" || -L "$target" ]]; then
    log "ERROR: Pairling could not remove source snapshot: $target" >&2
    return 1
  fi
}

cleanup_stale_source_snapshots() {
  local stale
  mkdir -p "$SOURCE_SNAPSHOT_ROOT"
  chmod 700 "$SOURCE_SNAPSHOT_ROOT"
  if [[ -L "$SOURCE_SNAPSHOT_ROOT" || ! -d "$SOURCE_SNAPSHOT_ROOT" ]]; then
    log "ERROR: Pairling source snapshot root must be a real directory: $SOURCE_SNAPSHOT_ROOT" >&2
    return 1
  fi
  while IFS= read -r -d '' stale; do
    remove_source_snapshot_tree "$stale"
  done < <(find -P "$SOURCE_SNAPSHOT_ROOT" -mindepth 1 -maxdepth 1 -name '.package.*' -print0)
  fsync_directory "$SOURCE_SNAPSHOT_ROOT"
}

# _machine_path_blocks: returns success when a machine condition should keep the
# polished screen off, so both gate functions share one authoritative guard list.
# It returns success for NO_COLOR, for CI, for a dry run, for the --json or
# --plan-only arguments, and for a dumb, unknown, or empty TERM. It returns
# failure when no machine condition blocks the screen. A future sixth guard is
# added here once, so want_tui and want_tui_tty stay authoritative on every path.
_machine_path_blocks() {
  [ -n "${NO_COLOR:-}" ] && return 0
  [ -n "${CI:-}" ] && return 0
  [ -n "${PAIRLING_DRY_RUN:-}" ] && return 0
  case " $* " in *" --json "*|*" --plan-only "*) return 0;; esac
  case "${TERM:-dumb}" in dumb|unknown|"") return 0;; esac
  return 1
}

# want_tui: the single decision that keeps the polished screen off every machine
# path. It returns success only when the guided screen should render. It returns
# failure for a non-terminal stdout and for every machine condition in
# _machine_path_blocks, which are NO_COLOR, CI, a dry run, the --json or
# --plan-only arguments, and a dumb or unknown terminal. The bash spine runs the
# plain numbered flow whenever this returns failure, so machine output stays
# byte-for-byte the same. The --json and --plan-only checks are defensive only,
# because those flags do not reach install_runtime on the setup arm today. The
# gate checks them so the function stays correct if a future caller ever threads
# them in.
want_tui() {
  [ -t 1 ] || return 1
  _machine_path_blocks "$@" && return 1
  return 0
}

# want_tui_tty: the first-run variant of the gate. The first-run flow pipes our
# stdout through tee, so [ -t 1 ] is false even though a controlling terminal
# still exists, and want_tui returns failure for that reason alone. This variant
# skips only the stdout tty check. It still fails for every machine condition in
# _machine_path_blocks, so NO_COLOR, CI, a dry run, --json, --plan-only, and a
# dumb or unknown TERM still disable the screen on the first-run path. It then
# proves a controlling terminal with a real write to /dev/tty, so only a true
# controlling terminal enables the screen. The device node can test as writable
# with no controlling terminal, so the guard writes one empty line instead of
# testing -w.
want_tui_tty() {
  _machine_path_blocks "$@" && return 1
  { : >/dev/tty; } 2>/dev/null || return 1
  return 0
}

# wizard_splash_verify: the real recheck the splash result is tied to. It runs a
# bounded integrity recheck of the staged release. Before staging there is no
# staged binary, so it returns 0, which means there is nothing to contradict yet.
# The splash runs in setup_intro, before copy_release, so this is bash-only and
# starts no python. A real per-file hash recheck happens later in the doctor gate,
# so the splash result is honest about what it can confirm at intro time.
wizard_splash_verify() {
  local binary="$CURRENT_LINK/connectd/pairling-connectd"
  if [ -x "$binary" ]; then
    /usr/bin/codesign --verify --strict "$binary" >/dev/null 2>&1 || return 1
  fi
  return 0
}

# wizard_splash: an optional one-shot brand beat under about 800 milliseconds.
# It is bash-only, because it runs before the python is staged. It draws a boxed
# brand header, the brand word in the accent-to-e-ink gradient and the tagline in
# paper, then a short non-interactive spinner with sleep 0.08, which bash
# 3.2.57 allows, then prints a result tied to the recheck. It renders only when
# GUIDED_TTY is 1, so it follows the same guided screen gate as the numbered
# stages. GUIDED_TTY is 1 exactly when WIZARD_TUI is 1 and PAIRLING_GUIDED_PLAIN
# is not 1, so the splash renders on the first-run path where GUIDED_TTY is 1 and
# the knob is unset, it honors the PAIRLING_GUIDED_PLAIN opt-out and stays plain
# when that knob is set, and it stays silent on every machine path where
# GUIDED_TTY is 0. Whether it drops the spinner is decided by reduced_motion_on,
# which honors PAIRLING_REDUCED_MOTION first and otherwise reads the macOS
# ReduceMotionEnabled setting. When reduce motion is on it skips the spinner and
# still prints the brand line and the result line. This
# is the most cuttable piece of the wizard. If it ever adds risk, drop it and keep
# the plain intro.
# reduced_motion_on: decide whether the splash should drop its spinner. The
# explicit PAIRLING_REDUCED_MOTION knob wins when set to any non-empty value,
# matching the prior behavior. When it is unset, fall back to the macOS system
# setting com.apple.Accessibility ReduceMotionEnabled. defaults exits non-zero
# and prints nothing when that key was never written, so a missing key reads as
# reduce motion off and the helper returns non-zero, so the spinner runs. A
# stored value of 1 means reduce motion
# is on. DEFAULTS_BIN defaults to the pinned /usr/bin/defaults and exists only
# so tests can point it at a stub.
reduced_motion_on() {
  if [ "${PAIRLING_REDUCED_MOTION:-}" != "" ]; then
    return 0
  fi
  [ "$("${DEFAULTS_BIN:-/usr/bin/defaults}" read com.apple.Accessibility ReduceMotionEnabled 2>/dev/null)" = 1 ]
}
# wizard_palette_init: detect the terminal color tier and set the brand palette
# variables the guided splash, the box helpers, and the stage markers read. It
# mirrors the tier detection in mac/docs/setup-wizard-mockup-bash.sh. The tier is
# true when COLORTERM is truecolor or 24bit, else 256 when tput reports at least
# 256 colors, else 16 when tput reports at least 8, else none. NO_COLOR forces the
# none tier. Each palette variable carries a real escape string spelled with the
# file's \033[ CSI prefix, and is empty in the none tier so a no-color terminal
# gets plain text. WZ_ERR is a clear error red for the splash failure marker, kept
# distinct from the warm brand accent and consistent across tiers, so a failure
# never reads as the brand. The function is idempotent through the WZ_PALETTE_READY guard
# and never prints, so the load-time call, the defensive call in wizard_splash, and
# the calls in the stage markers cost only one string test after the first.
wizard_palette_init() {
  [ "${WZ_PALETTE_READY:-0}" = 1 ] && return 0
  WZ_TIER="none"
  if [ -z "${NO_COLOR:-}" ]; then
    if [ "${COLORTERM:-}" = "truecolor" ] || [ "${COLORTERM:-}" = "24bit" ]; then
      WZ_TIER="true"
    elif [ "$(tput colors 2>/dev/null || echo 0)" -ge 256 ]; then
      WZ_TIER="256"
    elif [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
      WZ_TIER="16"
    fi
  fi
  case "$WZ_TIER" in
    true)
      WZ_ACCENT=$'\033[38;2;226;70;42m'; WZ_EINK=$'\033[38;2;168;51;28m'
      WZ_PAPER=$'\033[38;2;231;228;216m'; WZ_OK=$'\033[38;2;120;170;90m'
      WZ_GREY=$'\033[38;2;150;145;135m'; WZ_ERR=$'\033[38;2;208;48;48m' ;;
    256)
      WZ_ACCENT=$'\033[38;5;166m'; WZ_EINK=$'\033[38;5;130m'
      WZ_PAPER=$'\033[38;5;223m'; WZ_OK=$'\033[38;5;107m'; WZ_GREY=$'\033[38;5;244m'
      WZ_ERR=$'\033[38;5;160m' ;;
    16)
      WZ_ACCENT=$'\033[91m'; WZ_EINK=$'\033[31m'; WZ_PAPER=$'\033[37m'
      WZ_OK=$'\033[32m'; WZ_GREY=$'\033[90m'; WZ_ERR=$'\033[31m' ;;
    *)
      WZ_ACCENT=""; WZ_EINK=""; WZ_PAPER=""; WZ_OK=""; WZ_GREY=""; WZ_ERR="" ;;
  esac
  WZ_PALETTE_READY=1
  return 0
}

# wizard_gradient: print text in the brand gradient, accent (226,70,42) sweeping to
# e-ink (168,51,28), one color step per character. It ports the mockup gradient and
# runs the per-character sweep only in the true tier, where 24-bit color exists. In
# every other tier it prints the whole text in bold accent. bash 3.2.57 arithmetic
# evaluates the n>1 ternary, and the d guard keeps a single-character word from
# dividing by zero. It emits no trailing reset, so the caller closes the color.
wizard_gradient() {
  local text="$1"
  if [ "${WZ_TIER:-none}" != "true" ]; then
    printf '\033[1m%s%s\033[0m' "${WZ_ACCENT:-}" "$text"
    return 0
  fi
  local n=${#text} i=0 ch r g b d
  d=$(( n > 1 ? n - 1 : 1 ))
  while [ "$i" -lt "$n" ]; do
    ch="${text:$i:1}"
    r=$(( 226 - (58 * i / d) ))
    g=$(( 70 - (19 * i / d) ))
    b=$(( 42 - (14 * i / d) ))
    printf '\033[38;2;%d;%d;%dm\033[1m%s' "$r" "$g" "$b" "$ch"
    i=$((i + 1))
  done
  return 0
}

# wizard_progress_bar: print a fixed-width brand progress bar, accent-filled cells
# for the completed fraction and grey empty cells for the rest. It ports the bar in
# mac/docs/setup-wizard-mockup-bash.sh and reads the palette WZ_ACCENT and WZ_GREY,
# each with a set -u default so a direct caller before wizard_palette_init still
# runs. The fill glyph and the empty glyph are held in variables and appended as
# ${s}${glyph}, never as a glyph written right after a variable expansion, because
# bash 3.2.57 under set -u misparses a multibyte glyph placed directly after $var.
# The total is guarded to at least one so a zero total never divides by zero, even
# though every caller passes the fixed stage total. A single trailing reset closes
# the color, matching the stage header, which already emits escapes in its TTY branch.
wizard_progress_bar() {
  local done="$1" total="$2" width=34 fill i s='' full='█' empty='░'
  [ "$total" -gt 0 ] || total=1
  fill=$(( width * done / total ))
  i=0
  while [ "$i" -lt "$width" ]; do
    if [ "$i" -lt "$fill" ]; then
      s="${s}${WZ_ACCENT:-}${full}"
    else
      s="${s}${WZ_GREY:-}${empty}"
    fi
    i=$((i + 1))
  done
  printf '%s\033[0m' "$s"
}

# wizard_line_h: print one character repeated width times, used for the horizontal
# rules inside the box borders. It holds the repeat character in a variable and
# appends it as ${s}${c}, never as a literal glyph placed directly after $s, because
# bash 3.2.57 under set -u misparses a multibyte glyph written right after a
# variable expansion as part of the variable name.
wizard_line_h() {
  local w="$1" c="$2" s="" i=0
  while [ "$i" -lt "$w" ]; do s="${s}${c}"; i=$((i + 1)); done
  printf '%s' "$s"
}

# wizard_box_top / wizard_box_bot: draw the rounded top and bottom borders of the
# header box in e-ink. The box glyphs sit in the printf format string, not after a
# variable expansion, so the multibyte parse hazard does not apply here.
wizard_box_top() {
  printf '  %s╭%s╮\033[0m\n' "${WZ_EINK:-}" "$(wizard_line_h "$1" "─")"
}

wizard_box_bot() {
  printf '  %s╰%s╯\033[0m\n' "${WZ_EINK:-}" "$(wizard_line_h "$1" "─")"
}

# wizard_box_row: draw one content row of the header box. It takes the inner width,
# a plain copy of the text used only to size the right pad, and the styled text
# printed between the borders. It pads to the width with spaces so the right border
# lines up, and clamps a negative pad to zero when the text is wider than the box.
wizard_box_row() {
  local w="$1" plain="$2" styled="$3" pad
  pad=$(( w - 2 - ${#plain} )); [ "$pad" -lt 0 ] && pad=0
  printf '  %s│\033[0m %s%s %s│\033[0m\n' "${WZ_EINK:-}" "$styled" "$(wizard_line_h "$pad" " ")" "${WZ_EINK:-}"
}

# wizard_qr_open: head the pairing QR on the guided screen with a bold header only.
# A fixed-width e-ink rule cannot frame a variable-width QR and reads as
# disproportionate, so the header is the whole frame. It gates on GUIDED_TTY, so a
# machine path keeps GUIDED_TTY 0 and it prints nothing, and the QR and the pair URL
# render exactly as before. render_pair_qr itself is untouched.
wizard_qr_open() {
  [ "${GUIDED_TTY:-0}" = 1 ] || return 0
  wizard_palette_init
  printf '\n  \033[1m%sScan this in Pairling on your iPhone\033[0m\n' "${WZ_PAPER:-}"
}

wizard_splash() {
  [ "${GUIDED_TTY:-0}" = 1 ] || return 0
  wizard_palette_init
  local inner=54 row1 row2
  # printf turns \033 into a real escape byte, so the captured rows carry real
  # escapes for wizard_box_row to place between the borders. row1 is the gradient
  # brand word, a reset to drop the gradient bold, then the paper tagline. The
  # plain-copy arguments size the right pad and never reach the screen.
  row1="$(wizard_gradient "Pairling"; printf '\033[0m%s   Pair your iPhone with your coding agents' "$WZ_PAPER")"
  row2="${WZ_PAPER}           on this Mac."
  wizard_box_top "$inner"
  wizard_box_row "$inner" "Pairling   Pair your iPhone with your coding agents" "$row1"
  wizard_box_row "$inner" "           on this Mac." "$row2"
  wizard_box_bot "$inner"
  if ! reduced_motion_on; then
    local frames='⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏' f
    for f in $frames; do
      printf '\r  %s%s\033[0m %sVerifying the staged runtime\033[0m' "$WZ_ACCENT" "$f" "$WZ_GREY"
      sleep 0.08
    done
    printf '\r'
  fi
  if wizard_splash_verify; then
    printf '  %sok\033[0m Runtime verified.            \n' "$WZ_OK"
  else
    printf '  %sx\033[0m Runtime check failed. See the steps below.\n' "${WZ_ERR:-}"
  fi
  return 0
}

# safety_status_line: print the live SafetyMonitorBridge status as one parseable
# line. It runs as "$PYTHON3_BIN", the staged vendored python, and imports the
# bridge from the staged companiond, exactly as doctor.sh and pairlingd.py do. It
# constructs the bridge as SafetyMonitorBridge(APP_SUPPORT_ROOT, HOME), the same
# construction the daemon uses. It never reads a TCC store and never calls the
# safety HTTP routes, which need a device bearer token the local wizard does not
# have. Values are reduced to fixed tokens before they reach the shell.
safety_status_line() {
  "$PYTHON3_BIN" - "$CURRENT_LINK/companiond" "$APP_SUPPORT" <<'PY' 2>/dev/null || printf 'installed=unknown system_extension_status=status_unavailable full_disk_access=unknown\n'
import os
import sys
from pathlib import Path

companiond_dir = sys.argv[1]
app_support_root = Path(sys.argv[2])
sys.path.insert(0, companiond_dir)
try:
    from safety_monitor import SafetyMonitorBridge
    bridge = SafetyMonitorBridge(app_support_root, Path(os.path.expanduser("~")))
    status = bridge.status()
    installed = "true" if status.get("installed") else "false"
    extension = str(status.get("system_extension_status") or "status_unavailable")
    fda = str(status.get("full_disk_access") or "unknown")
except Exception:
    installed, extension, fda = "unknown", "status_unavailable", "unknown"
if extension not in {"active", "approval_required", "failed", "not_installed", "status_stale"}:
    extension = "status_unavailable"
if fda not in {"validated", "not_validated", "denied", "unknown", "unavailable", "limited"}:
    fda = "unknown"
print("installed=%s system_extension_status=%s full_disk_access=%s" % (installed, extension, fda))
PY
}

# safety_status_value reads one fixed key from safety_status_line without eval.
# The Python reader emits no spaces inside values, so each item is one shell word.
safety_status_value() {
  local line="$1" key="$2" item
  for item in $line; do
    case "$item" in
      "$key"=*) printf '%s\n' "${item#*=}"; return 0 ;;
    esac
  done
  return 1
}

# stage_begin: print the numbered header for one guided stage. The TTY branch keeps
# the bold [N/total] prefix, pads the title to a fixed field so the bar aligns across
# stages, then draws the brand progress bar filled to the current stage over the
# total, so the bar fills as the flow advances. It calls wizard_palette_init, which is
# idempotent, so the bar colors exist even if a caller reaches here first. The plain
# GUIDED_TTY=0 branch is unchanged and stays byte-identical, so every machine path
# keeps the exact \n[N/total] Title\n form with no bar and no escape byte.
stage_begin() {
  GUIDED_STAGE_N=$((GUIDED_STAGE_N + 1))
  GUIDED_STAGE_CURRENT="$1"
  if [ "$GUIDED_TTY" = 1 ]; then
    wizard_palette_init
    printf '\n\033[1m[%d/%d] %-30s\033[0m  %s\n' \
      "$GUIDED_STAGE_N" "$GUIDED_STAGE_TOTAL" "$1" \
      "$(wizard_progress_bar "$GUIDED_STAGE_N" "$GUIDED_STAGE_TOTAL")"
  else
    printf '\n[%d/%d] %s\n' "$GUIDED_STAGE_N" "$GUIDED_STAGE_TOTAL" "$1"
  fi
}

stage_ok() {
  if [ "$GUIDED_TTY" = 1 ]; then
    wizard_palette_init
    printf '  %sok\033[0m %s\n' "$WZ_OK" "$1"
  else
    printf '  ok: %s\n' "$1"
  fi
}

stage_skip() {
  if [ "$GUIDED_TTY" = 1 ]; then
    wizard_palette_init
    printf '  %s--\033[0m %s\n' "$WZ_GREY" "$1"
  else
    printf '  skip: %s\n' "$1"
  fi
}

stage_note() {
  printf '     %s\n' "$1"
}

# provider_setup_stage: print the detected coding agents (provider · version ·
# depth wording) from registry-data.json and record include/exclude choices in
# ~/.pairling/providers.json (SPEC-p1). Detection is read-only. Exclusion
# hides a provider from Pairling surfaces and never touches the provider's
# own config or processes. Machine paths never prompt: dry runs and non-TTY
# runs leave the visibility file untouched unless PAIRLING_PROVIDERS_EXCLUDE
# is set, so a re-run cannot silently reset a choice made earlier.
provider_setup_stage() {
  local setup_py="$REPO_ROOT/mac/companiond/provider_setup.py"
  if is_dry_run; then
    stage_ok "would detect providers; visibility would remain unchanged"
    return 0
  fi
  if [ -f "$CURRENT_LINK/companiond/provider_setup.py" ]; then
    setup_py="$CURRENT_LINK/companiond/provider_setup.py"
  fi
  if ! "$PYTHON3_BIN" "$setup_py" table; then
    stage_skip "provider detection unavailable; setup continues"
    return 0
  fi
  if [ -n "${PAIRLING_PROVIDERS_EXCLUDE+x}" ]; then
    if "$PYTHON3_BIN" "$setup_py" apply --exclude "$PAIRLING_PROVIDERS_EXCLUDE"; then
      stage_ok "provider visibility recorded from PAIRLING_PROVIDERS_EXCLUDE"
    else
      stage_skip "PAIRLING_PROVIDERS_EXCLUDE was invalid; visibility unchanged"
    fi
    return 0
  fi
  local current_excluded=""
  current_excluded="$("$PYTHON3_BIN" "$setup_py" current 2>/dev/null || true)"
  if [ "${WIZARD_TUI:-0}" != 1 ]; then
    if [ -n "$current_excluded" ]; then
      stage_ok "provider visibility unchanged (excluded: $current_excluded)"
    else
      stage_ok "every detected provider is included (change later in Settings on the iPhone)"
    fi
    return 0
  fi
  local answer=""
  if [ -n "$current_excluded" ]; then
    printf 'Providers to exclude (ids, comma-separated; Enter keeps %s excluded): ' "$current_excluded" >/dev/tty
  else
    printf 'Providers to exclude (ids, comma-separated; Enter includes all): ' >/dev/tty
  fi
  IFS= read -r answer </dev/tty || answer=""
  if [ -z "$answer" ]; then
    if [ -n "$current_excluded" ]; then
      stage_ok "provider visibility unchanged (excluded: $current_excluded)"
    else
      stage_ok "every detected provider is included"
    fi
    return 0
  fi
  if "$PYTHON3_BIN" "$setup_py" apply --exclude "$answer"; then
    stage_ok "provider visibility recorded (excluded: $answer)"
  else
    stage_skip "exclusions not recognized; visibility unchanged"
  fi
  return 0
}

# wizard_recovery_menu: a plain bash recovery menu. Generic setup failures never
# offer privacy settings because permissions cannot repair staging, ownership,
# disk, or service errors. The Safety-specific kind is the only path that can
# open Full Disk Access, and safety_step calls it only after the installed and
# active Safety Monitor reports limited file visibility.
wizard_recovery_menu() {
  local kind="$1" stage="$2"
  case "$kind" in
    fatal)
      stage_note "Pairling stopped to protect your Mac at the $stage step."
      stage_note "A file did not match its signed checksum, so setup will not continue. There is no way to skip this check."
      stage_note "Options: [1] reinstall from a verified copy   [2] inspect with pairling doctor --json   [q] quit"
      ;;
    safety_permissions)
      stage_note "Pairling Safety Monitor is active, but macOS is limiting its file evidence."
      stage_note "Options: [o] open Full Disk Access settings   [s] skip this optional feature   [q] quit"
      ;;
    setup)
      stage_note "Setup stopped at the $stage step."
      stage_note "Options: [1] inspect with pairling doctor --json   [2] retry pairling setup   [q] quit"
      ;;
    *)
      stage_note "Setup stopped with an unknown recovery state."
      return 1
      ;;
  esac
  # Off a terminal, print the options and return without blocking.
  [ -t 0 ] || return 0
  local choice=""
  while :; do
    printf '  Choose an option: '
    read -r choice || return 0
    case "$kind:$choice" in
      safety_permissions:o|safety_permissions:O) open_full_disk_access_pane ;;
      safety_permissions:s|safety_permissions:S) stage_note "Skipped. Pairing will continue without Safety Monitor file evidence."; return 0 ;;
      *:q|*:Q) stage_note "Quitting. Run pairling setup again to resume right here."; return 0 ;;
      fatal:1) stage_note "Reinstall Pairling from a verified copy, then run pairling setup again."; return 0 ;;
      fatal:2|setup:1) stage_note "Run pairling doctor --json and include its failed checks with the setup error above."; return 0 ;;
      setup:2) stage_note "Run pairling setup again. It will clean its private staging path before retrying."; return 0 ;;
      *) stage_note "Pick one of the listed options." ;;
    esac
  done
}

# safety_call_method: run one no-argument SafetyMonitorBridge method as the
# staged python and print whatever the method returns as a single status word.
# It imports the bridge from the staged companiond and constructs it the same
# way the daemon does. The method name is passed as argv, so the python source
# is fixed. It is used by request_safety_activation, open_full_disk_access_pane,
# and poll_evidence_test, so they all share one import path.
safety_call_method() {
  local method="$1"
  "$PYTHON3_BIN" - "$CURRENT_LINK/companiond" "$APP_SUPPORT" "$method" <<'PY' 2>/dev/null || printf 'error\n'
import os
import sys
from pathlib import Path

companiond_dir, app_support_root, method = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, companiond_dir)
try:
    from safety_monitor import SafetyMonitorBridge
    bridge = SafetyMonitorBridge(app_support_root, Path(os.path.expanduser("~")))
    result = getattr(bridge, method)()
    # request_activation returns "state", run_evidence_test returns "status",
    # open_full_disk_access returns "state". Print the first present one.
    word = result.get("status") or result.get("state") or ("ok" if result.get("ok") else "error")
    print(word)
except Exception:
    print("error")
PY
}

# request_safety_activation: guide System Extension approval through the bridge.
# It only runs when the app is installed, so the bridge launches
# PairlingSafety.app --pairling-request-activation. The wizard never claims it
# installed the app.
request_safety_activation() {
  local state
  state="$(safety_call_method request_activation)"
  if [ "$state" = "approval_requested" ]; then
    stage_note "Approve Pairling Safety Monitor in System Settings, then come back here."
  else
    stage_note "Could not request Safety Monitor approval right now. You can approve it later in System Settings."
  fi
}

# open_full_disk_access_pane: open the Full Disk Access settings page through the
# bridge open_full_disk_access method, which runs the open command for the
# Privacy_AllFiles anchor. The wizard does not change any privacy setting itself.
open_full_disk_access_pane() {
  safety_call_method open_full_disk_access >/dev/null 2>&1 || true
  stage_note "Turn on Full Disk Access for Pairling Safety Monitor, then come back here."
}

# poll_evidence_test: re-run the bridge run_evidence_test every two seconds until
# it reports passed or the time runs out. It uses sleep, not a fractional read,
# because bash 3.2.57 rejects a sub-second read timeout. It returns 0 on a passed
# result and 124 on timeout. A "limited" result means process evidence passed but
# file visibility still needs Full Disk Access, so the loop keeps waiting. The
# interval and timeout are overridable for tests. The step clamp keeps waited
# advancing even when the interval is 0, so an always-limited result cannot loop
# forever.
poll_evidence_test() {
  local interval="${PAIRLING_SAFETY_POLL_INTERVAL:-2}"
  local timeout="${PAIRLING_SAFETY_POLL_TIMEOUT:-300}"
  local step="$interval"
  [ "$step" -lt 1 ] && step=1
  local waited=0 result
  while [ "$waited" -le "$timeout" ]; do
    result="$(safety_call_method run_evidence_test)"
    if [ "$result" = "passed" ]; then
      return 0
    fi
    [ "$waited" -ge "$timeout" ] && break
    sleep "$interval"
    waited=$((waited + step))
  done
  return 124
}

# wizard_permissions_panel: draw the macOS-permissions advisory as a rounded e-ink
# box on the guided screen. $1 carries the Safety Monitor status line and shows its
# two rows only when it is non-empty, which is today's not-installed path. The
# panel does not print the argument text itself, it uses fixed rows that spell the
# same wording, so the box math is exact and the argument stays the canonical
# sentence safety_step also prints plain. The connection copy states the normal
# Pairling Connect requirement and is wrapped to fixed rows that fit the box so
# the right border lines up. It gates on GUIDED_TTY, so a machine path draws
# nothing.
wizard_permissions_panel() {
  [ "${GUIDED_TTY:-0}" = 1 ] || return 0
  wizard_palette_init
  local safety="$1" inner=60 b=$'\033[1m' r=$'\033[0m'
  wizard_box_top "$inner"
  wizard_box_row "$inner" "macOS permissions" "${b}${WZ_PAPER:-}macOS permissions${r}"
  wizard_box_row "$inner" "" ""
  if [ -n "$safety" ]; then
    wizard_box_row "$inner" "Pairling Safety Monitor is a future feature and is not" "${WZ_GREY:-}Pairling Safety Monitor is a future feature and is not${r}"
    wizard_box_row "$inner" "installed yet. Pairing works without it." "${WZ_GREY:-}installed yet. Pairing works without it.${r}"
    wizard_box_row "$inner" "" ""
  fi
  wizard_box_row "$inner" "Remote access needs no macOS sharing permission." "${WZ_PAPER:-}Remote access needs no macOS sharing permission.${r}"
  wizard_box_row "$inner" "Pairling Connect uses its private embedded route." "${WZ_PAPER:-}Pairling Connect uses its private embedded route.${r}"
  wizard_box_row "$inner" "Pairling needs one-time permission to control Terminal." "${WZ_PAPER:-}Pairling needs one-time permission to control Terminal.${r}"
  wizard_box_row "$inner" "macOS lists Pairling in Accessibility and Automation." "${WZ_PAPER:-}macOS lists Pairling in Accessibility and Automation.${r}"
  wizard_box_bot "$inner"
}

# safety_step: the one safety gate in v1. It reads the live SafetyMonitorBridge
# status. The bridge returns typed extension and file-access states. Only an
# installed, active monitor with limited file evidence may open Full Disk Access.
# Approval, failed, stale, missing, and already validated states never open that
# pane. Safety is optional and never blocks pairing.
safety_step() {
  local status_line installed_status extension_status full_disk_access
  status_line="$(safety_status_line)"
  installed_status="$(safety_status_value "$status_line" installed || printf 'unknown')"
  extension_status="$(safety_status_value "$status_line" system_extension_status || printf 'status_unavailable')"
  full_disk_access="$(safety_status_value "$status_line" full_disk_access || printf 'unknown')"
  if [ "$installed_status" = "false" ]; then
    extension_status="not_installed"
  elif [ "$installed_status" != "true" ]; then
    extension_status="status_unavailable"
  fi

  case "$extension_status" in
    active)
      case "$full_disk_access" in
        validated)
          stage_note "Pairling Safety Monitor is active and already has the file access it needs."
          ;;
        denied|limited|not_validated)
          stage_note "Pairling Safety Monitor is active, but macOS is limiting its optional file evidence."
          open_full_disk_access_pane
          stage_note "Checking that the Safety Monitor can see process and file evidence. We check every 2 seconds."
          if poll_evidence_test; then
            stage_note "The Safety Monitor sees full evidence. Thank you."
          else
            stage_note "The Safety Monitor did not reach full file evidence within the time limit."
            wizard_recovery_menu safety_permissions "macOS permissions" || true
          fi
          ;;
        *)
          stage_note "Pairling Safety Monitor is active, but its file-access status could not be confirmed. Pairing can continue."
          ;;
      esac
      ;;
    approval_required)
      stage_note "Pairling Safety Monitor is installed and needs System Extension approval. Pairing can continue without it."
      request_safety_activation
      ;;
    failed)
      stage_note "Pairling Safety Monitor is installed but is not running. Pairing can continue; open its app later to repair it."
      ;;
    status_stale)
      stage_note "Pairling Safety Monitor status is stale. Pairing can continue; reopen its app later to refresh it."
      ;;
    not_installed)
      # The not-installed advisory. This is today's path. It states the truth: the
      # Safety Monitor is a future feature, it is not installed, and pairing works
      # without it. It never claims setup installed anything. On the guided screen the
    # advisory and the connection copy render as one rounded panel. A machine
    # path keeps the two plain stage_note lines, byte identical.
    if [ "${GUIDED_TTY:-0}" = 1 ]; then
      wizard_permissions_panel "Pairling Safety Monitor is a future feature and is not installed yet. Pairing works without it."
    else
      stage_note "Pairling Safety Monitor is a future feature and is not installed yet. Pairing works without it."
        stage_note "Pairling Connect uses its private embedded route. Local Network access and the same Wi-Fi are not required for pairing."
      fi
      ;;
    *)
      stage_note "Pairling Safety Monitor status could not be read. Pairing can continue without it."
      ;;
  esac

  if [ "$extension_status" != "not_installed" ]; then
    # The Pairling Connect advisory. On the guided screen it renders as a rounded
    # panel. A machine path keeps the plain stage_note, byte identical.
    if [ "${GUIDED_TTY:-0}" = 1 ]; then
      wizard_permissions_panel ""
    else
      stage_note "Pairling Connect uses its private embedded route. Local Network access and the same Wi-Fi are not required for pairing."
    fi
  fi
  stage_note "If pairing stalls, run pairling doctor --json and confirm that Pairling Connect reports a ready route."
  stage_note "Pairling verifies Accessibility and Apple Terminal control before pairing. Run pairling setup again if either permission is revoked."
  return 0
}

# guided_on_exit — fires on ANY premature exit during setup (a set -e abort or an
# explicit exit 1 in staging, service startup, the QR, or auth), so a failure
# always leaves a clear recovery path. Suppressed once setup sets
# GUIDED_COMPLETE=1, so a clean run prints nothing here.
guided_on_exit() {
  local code=$? pairing_recovery_ready=0
  if [ "$code" != 0 ]; then
    if ! rollback_install_transaction; then
      code=1
    fi
  fi
  cleanup_active_staging || true
  if [ "$code" != 0 ] && runtime_ready_for_pairing_recovery; then
    pairing_recovery_ready=1
  fi
  cleanup_source_snapshot || true
  if ! release_install_lock; then
    code=1
  fi
  if [ "$GUIDED_COMPLETE" != 1 ] && [ "$code" != 0 ]; then
    if [ "${WIZARD_TUI:-0}" = 1 ]; then
      # Show the bash recovery menu. The kind is recoverable by default. The
      # caller sets WIZARD_FATAL=1 before a fatal integrity or signature exit, so
      # the menu drops retry and skip to mirror this script's no-bypass behavior.
      if [ "${WIZARD_FATAL:-0}" = 1 ]; then
        wizard_recovery_menu fatal "${GUIDED_STAGE_CURRENT:-startup}" || true
      else
        wizard_recovery_menu setup "${GUIDED_STAGE_CURRENT:-startup}" || true
      fi
    fi
    printf '\nSetup did not finish (stage: %s, exit %s).\n' "${GUIDED_STAGE_CURRENT:-startup}" "$code" >&2
    if [ -n "${GUIDED_FAILURE_SOURCE_PATH:-}" ]; then
      printf 'Failed source path: %s\n' "$GUIDED_FAILURE_SOURCE_PATH" >&2
    fi
    if [ -n "${GUIDED_FAILURE_PATH:-}" ]; then
      printf 'Failed path: %s\n' "$GUIDED_FAILURE_PATH" >&2
    fi
    printf 'Recovery: run `pairling doctor --json` to inspect, then re-run `pairling setup`.\n' >&2
    if [ "$pairing_recovery_ready" = 1 ]; then
      printf 'The verified runtime is healthy. Re-show pairing with `pairling pair --qr`. If Pairling Connect needs sign-in, run `pairling connect-auth-open`.\n' >&2
    else
      printf 'Pairing is unavailable until `pairling setup` finishes and the runtime is healthy.\n' >&2
    fi
  fi
  return "$code"
}

runtime_ready_for_pairing_recovery() {
  local target="" ready_json=""
  [[ -L "$CURRENT_LINK" ]] || return 1
  target="$(readlink "$CURRENT_LINK")"
  [[ -n "$target" ]] || return 1
  if ! "$CONTROL_PYTHON_BIN" - \
    "$MANIFEST_REPO_PATH/mac/companiond" "$target" "$RELEASES_ROOT" <<'PY' >/dev/null 2>&1
import sys

trusted_source, target, releases_root = sys.argv[1:]
sys.path.insert(0, trusted_source)
from runtime_manifest import verified_managed_release_identity

verified_managed_release_identity(target, releases_root)
PY
  then
    return 1
  fi
  ready_json="$(mktemp "${TMPDIR:-/tmp}/pairling-ready.XXXXXX")"
  if ! /usr/bin/curl -fsS --max-time 3 "http://127.0.0.1:$PAIRLING_RUNTIME_PORT/readyz" >"$ready_json" 2>/dev/null; then
    rm -f "$ready_json"
    return 1
  fi
  if ! "$CONTROL_PYTHON_BIN" - "$ready_json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("ok") is not True or payload.get("contract_version") != "pairling-runtime-v1":
    raise SystemExit(1)
PY
  then
    rm -f "$ready_json"
    return 1
  fi
  rm -f "$ready_json"
}

install_mutation_on_exit() {
  local code=$?
  if [[ "$code" != 0 ]]; then
    rollback_install_transaction || true
  fi
  cleanup_active_staging || true
  cleanup_source_snapshot || true
  if ! release_install_lock; then
    code=1
  fi
  return "$code"
}

# guided_permission_notice previews the mandatory local setup grants in a dry
# run. The live setup invokes request_terminal_permissions instead, so consent
# prompting remains confined to the explicit local setup path and blocks pairing
# until the helper's harmless Terminal probe succeeds.
guided_permission_notice() {
  if [ "${GUIDED_TTY:-0}" = 1 ]; then
    wizard_palette_init
    local inner=60 b=$'\033[1m' r=$'\033[0m'
    wizard_box_top "$inner"
    wizard_box_row "$inner" "macOS permissions" "${b}${WZ_PAPER:-}macOS permissions${r}"
    wizard_box_row "$inner" "" ""
    wizard_box_row "$inner" "Pairling setup will request Accessibility and Apple" "${WZ_PAPER:-}Pairling setup will request Accessibility and Apple${r}"
    wizard_box_row "$inner" "Terminal control before it shows a pairing code." "${WZ_PAPER:-}Terminal control before it shows a pairing code.${r}"
    wizard_box_row "$inner" "macOS will name Pairling in the permission prompt." "${WZ_GREY:-}macOS will name Pairling in the permission prompt.${r}"
    wizard_box_row "$inner" "" ""
    wizard_box_row "$inner" "Pairling Connect uses its private embedded route." "${WZ_PAPER:-}Pairling Connect uses its private embedded route.${r}"
    wizard_box_row "$inner" "Local Network access and the same Wi-Fi are not" "${WZ_PAPER:-}Local Network access and the same Wi-Fi are not${r}"
    wizard_box_row "$inner" "required for pairing." "${WZ_PAPER:-}required for pairing.${r}"
    wizard_box_row "$inner" "Remote Login, Screen Sharing, and Remote Management" "${WZ_PAPER:-}Remote Login, Screen Sharing, and Remote Management${r}"
    wizard_box_row "$inner" "are not required. Pairling will not enable them." "${WZ_PAPER:-}are not required. Pairling will not enable them.${r}"
    wizard_box_bot "$inner"
  else
    stage_note "Pairling setup will request Accessibility and Apple Terminal control before it shows a pairing code."
    stage_note "macOS will name Pairling in the permission prompt."
    stage_note "Pairling Connect uses its private embedded route. Local Network access and the same Wi-Fi are not required for pairing."
    stage_note "Remote Login, Screen Sharing, and Remote Management are not required. Pairling will not enable them."
  fi
}

# guided_connect_route_state makes one bounded, best-effort read of connectd
# /status and reduces it to the four states the setup copy can render. The
# finish summary captures it once and passes the same value to both proofs, so
# adjacent route and recovery messages cannot disagree.
guided_connect_route_state() {
  local python_bin="${PYTHON3_BIN:-}"
  if [[ -z "$python_bin" || ! -x "$python_bin" ]]; then
    python_bin="$(command -v python3 2>/dev/null || true)"
  fi
  if [[ -z "$python_bin" ]]; then
    printf 'degraded\n'
    return 0
  fi
  "$python_bin" - "$REPO_ROOT" 2>/dev/null <<'PY' || printf 'degraded\n'
import os
import sys

repo_root = sys.argv[1]
sys.path.insert(0, os.path.join(repo_root, "mac", "companiond"))
try:
    from pairling_connectd_status import fetch_connectd_status, redacted_connectd_summary
except Exception:
    print("degraded")
    sys.exit(0)

try:
    status = fetch_connectd_status(timeout_seconds=0.7) or {}
    summary = redacted_connectd_summary(status)
except Exception:
    print("degraded")
    sys.exit(0)

typed_status = str(summary.get("status") or "")
if typed_status == "ready":
    print("ready")
elif typed_status == "route_missing":
    print("starting")
elif typed_status == "auth_pending":
    print("needs_auth")
else:
    print("degraded")
PY
}

# guided_route_proof renders the captured Pairling Connect state. A missing
# embedded route is always a repair state, never an implicit nearby fallback.
guided_route_proof() {
  local route_state="${1:-degraded}"
  case "$route_state" in
    ready)
      printf '     Route check: Pairling Connect is ready. Same Wi-Fi is not required.\n'
      ;;
    starting)
      printf '     Route check: Pairling Connect is signed in and the remote route is still starting.\n'
      ;;
    needs_auth)
      printf '     Route check: Pairling Connect needs sign-in. Finish approval before using a new pairing code.\n'
      ;;
    degraded|*)
      printf '     Route check: Pairling Connect needs attention. Run pairling doctor --json before using a new pairing code.\n'
      ;;
  esac
}

# guided_pairing_seen_proof is one bounded, best-effort, read-only check of the
# devices database that tells the user whether this Mac has recorded the iPhone
# finishing pairing in this session. It takes the session-start epoch as its
# first argument, so a device paired in an earlier run does not read as seen on a
# re-run. It checks that the database already exists, then uses SQLite query-only
# mode so WAL coordination remains reliable without permitting SQL writes. A
# missing or empty database or any sqlite error means "not seen". It polls up to
# about 6 seconds at 1 second steps and exits early the moment a matching device
# appears, so a scanned phone is confirmed within about a second and only an
# unscanned run waits the full window. The whole probe is wrapped in `|| true`,
# so it never blocks or fails setup.
guided_pairing_seen_proof() {
  local since="${1:-0}" route_state="${2:-degraded}"
  local python_bin="${PYTHON3_BIN:-}"
  if [[ -z "$python_bin" || ! -x "$python_bin" ]]; then
    python_bin="$(command -v python3 2>/dev/null || true)"
  fi
  if [[ -z "$python_bin" ]]; then
    return 0
  fi
  PAIRLING_PAIRING_SEEN_POLL_STEPS="${PAIRLING_PAIRING_SEEN_POLL_STEPS:-6}" \
    "$python_bin" - "$DEVICES_DB" "$since" "$route_state" <<'PY' || true
import os
import sqlite3
import stat
import sys
import time

db_path = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    since = float(sys.argv[2])
except (IndexError, ValueError):
    since = 0.0
try:
    route_state = sys.argv[3]
except IndexError:
    route_state = "degraded"
if route_state not in {"ready", "starting", "needs_auth", "degraded"}:
    route_state = "degraded"
try:
    steps = int(os.environ.get("PAIRLING_PAIRING_SEEN_POLL_STEPS") or "6")
except ValueError:
    steps = 6
if steps < 1:
    steps = 1

def count_session_devices(created_since=None):
    # Refuse a missing, linked, or non-file path before opening normally. Query
    # only mode lets SQLite coordinate WAL side files without allowing writes.
    metadata = os.lstat(db_path)
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError("devices database is not a regular file")
    con = sqlite3.connect(db_path, timeout=0.5)
    try:
        con.execute("PRAGMA query_only=ON")
        columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(devices)").fetchall()
        }
        where = ["revoked_at IS NULL"]
        params = []
        if "purpose" in columns:
            where.extend([
                "COALESCE(activation_state, 'active') = 'active'",
                "COALESCE(purpose, '') NOT IN (?, ?)",
            ])
            params.extend(["runtime_truth_smoke", "local_mcp_bridge"])
        if created_since is not None:
            where.append("created_at >= ?")
            params.append(created_since)
        row = con.execute(
            "SELECT COUNT(*) FROM devices WHERE " + " AND ".join(where),
            tuple(params),
        ).fetchone()
        return int(row[0]) if row else 0
    finally:
        con.close()

seen = 0
try:
    for step in range(steps):
        try:
            seen = count_session_devices(since)
        except Exception:
            # A missing or empty database, or any sqlite error, means not seen.
            seen = 0
        if seen > 0:
            break
        if step < steps - 1:
            time.sleep(1)
    try:
        existing = count_session_devices()
    except Exception:
        existing = 0
    if seen > 0:
        print("     Pairing check: this Mac saw your iPhone connect and finish pairing.")
    elif existing > 0:
        print("     Pairing check: your existing paired iPhone remains registered.")
        print("     This new invitation has not been used. Use it only to add another iPhone or replace the saved pairing.")
    else:
        print("     Pairing check: this Mac has not recorded your iPhone finishing pairing yet.")
        print("     If you just scanned the code, give it a moment and it should appear.")
        if route_state == "ready":
            print("     Pairling Connect is ready, so same Wi-Fi is not required. Keep Pairling open on the iPhone and finish its sign-in if asked.")
        elif route_state == "starting":
            print("     Pairling Connect is still starting. Wait for a ready route, then scan a fresh code.")
        elif route_state == "needs_auth":
            print("     Pairling Connect needs sign-in. Run pairling connect-auth-open, finish approval, then scan a fresh code.")
        else:
            print("     Pairling Connect needs attention. Run pairling doctor --json before scanning a fresh code.")
except Exception:
    # Any unexpected error means not seen. Never raise, so setup continues.
    pass
sys.exit(0)
PY
}

# guided_finish_summary — the success and recovery surface. It states the next
# device step, proves the route, and prints the exact re-run commands for any
# step the operator may need to repeat.
guided_finish_summary() {
  local route_state="degraded" run_probes=0
  if ! is_dry_run; then
    route_state="$(guided_connect_route_state)"
    case "$route_state" in
      ready|starting|needs_auth|degraded) ;;
      *) route_state="degraded" ;;
    esac
    run_probes=1
  fi
  if [ "${GUIDED_TTY:-0}" = 1 ]; then
    # The guided screen frames the fixed guidance and the re-run command hints in a
    # rounded panel, with the commands in the brand accent. The route proof and the
    # seen probe stay below the box because their text is dynamic and could run
    # wider than the box. The guidance sentence is wrapped to fixed rows so the
    # right border lines up.
    wizard_palette_init
    local inner=60 b=$'\033[1m' r=$'\033[0m'
    wizard_box_top "$inner"
    wizard_box_row "$inner" "Setup complete" "${b}${WZ_OK:-}Setup complete${r}"
    wizard_box_row "$inner" "" ""
    wizard_box_row "$inner" "The pairing code is shown above. Open Pairling on your" "${WZ_PAPER:-}The pairing code is shown above. Open Pairling on your${r}"
    wizard_box_row "$inner" "iPhone, scan it, then approve this Mac." "${WZ_PAPER:-}iPhone, scan it, then approve this Mac.${r}"
    wizard_box_row "$inner" "" ""
    wizard_box_row "$inner" "Inspect status anytime:        pairling doctor --json" "${WZ_GREY:-}Inspect status anytime:        ${r}${WZ_ACCENT:-}pairling doctor --json${r}"
    wizard_box_row "$inner" "Re-show the pairing code:       pairling pair --qr" "${WZ_GREY:-}Re-show the pairing code:       ${r}${WZ_ACCENT:-}pairling pair --qr${r}"
    if [ "$run_probes" = 1 ] && [ "$route_state" = "needs_auth" ]; then
      wizard_box_row "$inner" "Start Pairling Connect:        pairling connect-auth-open" "${WZ_GREY:-}Start Pairling Connect:        ${r}${WZ_ACCENT:-}pairling connect-auth-open${r}"
    fi
    wizard_box_bot "$inner"
    if [ "$run_probes" = 1 ]; then
      guided_route_proof "$route_state" || true
      guided_pairing_seen_proof "${PAIRLING_PAIRING_STARTED_AT:-0}" "$route_state" || true
    fi
  else
    stage_note "The pairing code is shown above. Open Pairling on your iPhone, scan it, then approve this Mac."
    if [ "$run_probes" = 1 ]; then
      guided_route_proof "$route_state" || true
      guided_pairing_seen_proof "${PAIRLING_PAIRING_STARTED_AT:-0}" "$route_state" || true
    fi
    stage_note "Inspect status anytime:        pairling doctor --json"
    stage_note "Re-show the pairing code:       pairling pair --qr"
    if [ "$run_probes" = 1 ] && [ "$route_state" = "needs_auth" ]; then
      stage_note "Start Pairling Connect:        pairling connect-auth-open"
    fi
  fi
}

append_history() {
  local status="$1"
  local detail="$2"
  mkdir -p "$STATE_ROOT"
  "$PYTHON3_BIN" - "$INSTALL_HISTORY" "$status" "$detail" "$VERSION" "$REVISION" "$RELEASE_ROOT" <<'PY'
import json
import sys
import time
path, status, detail, version, revision, release_root = sys.argv[1:]
row = {
    "ts": time.time(),
    "status": status,
    "detail": detail,
    "runtime_version": version,
    "source_revision": revision,
    "release_root": release_root,
}
with open(path, "a") as fh:
    fh.write(json.dumps(row, sort_keys=True) + "\n")
PY
}

run_compile_checks() (
  local pycache_root provider_source
  local LC_ALL=C
  umask 077
  pycache_root="$(mktemp -d "${TMPDIR:-/tmp}/pairling-install-compile.XXXXXX")"
  trap 'rm -rf -- "$pycache_root"' EXIT

  compile_python_source() {
    PYTHONDONTWRITEBYTECODE= PYTHONPYCACHEPREFIX="$pycache_root" \
      "$PYTHON3_BIN" -m py_compile "$1"
  }

  compile_python_source "$REPO_ROOT/mac/companiond/pairlingd.py"
  compile_python_source "$REPO_ROOT/mac/companiond/safe_filesystem.py"
  compile_python_source "$REPO_ROOT/mac/companiond/runtime_contract.py"
  compile_python_source "$REPO_ROOT/mac/companiond/runtime_manifest.py"
  compile_python_source "$REPO_ROOT/mac/companiond/provider_runtime_assets.py"
  compile_python_source "$REPO_ROOT/mac/companiond/runtime_paths.py"
  compile_python_source "$REPO_ROOT/mac/companiond/pairdrop_store.py"
  compile_python_source "$REPO_ROOT/mac/companiond/compose_recording_store.py"
  compile_python_source "$REPO_ROOT/mac/companiond/pairling_connectd_status.py"
  compile_python_source "$REPO_ROOT/mac/companiond/local_control_client.py"
  compile_python_source "$REPO_ROOT/mac/companiond/pairling_devices.py"
  compile_python_source "$REPO_ROOT/mac/companiond/managed_provider_sessions.py"
  compile_python_source "$REPO_ROOT/mac/companiond/public_diagnostics.py"
  compile_python_source "$REPO_ROOT/mac/companiond/local_mcp_bridge.py"
  compile_python_source "$REPO_ROOT/mac/companiond/llm_route.py"
  compile_python_source "$REPO_ROOT/mac/companiond/pairling_tools.py"
  compile_python_source "$REPO_ROOT/mac/companiond/pairling_assurance_policy.py"
  compile_python_source "$REPO_ROOT/mac/companiond/pairling_pairing.py"
  compile_python_source "$REPO_ROOT/mac/companiond/pairling_psk.py"
  compile_python_source "$REPO_ROOT/mac/companiond/pairling_relay_claims.py"
  compile_python_source "$REPO_ROOT/mac/companiond/request_proof.py"
  compile_python_source "$REPO_ROOT/mac/companiond/codex_approval.py"
  compile_python_source "$REPO_ROOT/mac/companiond/pty_broker.py"
  compile_python_source "$REPO_ROOT/mac/companiond/pty_broker_client.py"
  compile_python_source "$REPO_ROOT/mac/companiond/pty_broker_service.py"
  compile_python_source "$REPO_ROOT/mac/companiond/terminal_screen_backend.py"
  compile_python_source "$REPO_ROOT/mac/companiond/session_events.py"
  compile_python_source "$REPO_ROOT/mac/companiond/session_event_log.py"
  compile_python_source "$REPO_ROOT/mac/companiond/session_event_ingest.py"
  compile_python_source "$REPO_ROOT/mac/companiond/terminal_text_sanitizer.py"
  compile_python_source "$REPO_ROOT/mac/companiond/push_dispatcher.py"
  compile_python_source "$REPO_ROOT/mac/companiond/push_event_catalog.py"
  compile_python_source "$REPO_ROOT/mac/companiond/live_activity_publisher.py"
  compile_python_source "$REPO_ROOT/mac/companiond/standard_push_publisher.py"
  compile_python_source "$REPO_ROOT/mac/companiond/fleet_tier.py"
  compile_python_source "$REPO_ROOT/mac/companiond/fleet_activity_publisher.py"
  compile_python_source "$REPO_ROOT/mac/companiond/fd_watchdog.py"
  compile_python_source "$REPO_ROOT/mac/companiond/safety_monitor.py"
  compile_python_source "$REPO_ROOT/mac/companiond/sentinel_notifications.py"
  compile_python_source "$REPO_ROOT/mac/companiond/workstate_feed_contract.py"
  compile_python_source "$REPO_ROOT/mac/companiond/model_status_contract.py"
  compile_python_source "$REPO_ROOT/mac/companiond/substrate_status_contract.py"
  compile_python_source "$REPO_ROOT/mac/companiond/integrations/__init__.py"
  compile_python_source "$REPO_ROOT/mac/companiond/integrations/aperture_cli/__init__.py"
  compile_python_source "$REPO_ROOT/mac/companiond/integrations/aperture_cli/launch.py"
  compile_python_source "$REPO_ROOT/mac/companiond/integrations/aperture_cli/status.py"
  for provider_source in "$REPO_ROOT/mac/companiond/providers/"*.py; do
    [[ -f "$provider_source" ]] || continue
    compile_python_source "$provider_source"
  done
  compile_python_source "$REPO_ROOT/mac/mcp/phone_tools.py"
  compile_python_source "$REPO_ROOT/mac/install/render-launchd.py"
  compile_python_source "$REPO_ROOT/mac/install/psk_dependency_check.py"
  compile_python_source "$REPO_ROOT/mac/install/ssh_gateway_setup.py"
)

run_psk_dependency_import_check() {
  local python_bin="$1"
  local companiond_path="$2"
  local label="$3"
  "$python_bin" "$REPO_ROOT/mac/install/psk_dependency_check.py" "$companiond_path" --label "$label"
}

run_psk_dependency_checks() {
  run_psk_dependency_import_check "$PYTHON3_BIN" "$REPO_ROOT/mac/companiond" "source-tree preflight"
}

app_attest_validator_source() {
  local candidate
  for candidate in \
    "$REPO_ROOT/relay/app_attest_validator.py" \
    "$REPO_ROOT/mac/companiond/app_attest_validator.py"; do
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  log "ERROR: App Attest validator source is missing; refusing to stage an incomplete runtime." >&2
  return 1
}

stage_app_attest_assets() {
  local destination="$1"
  local validator
  validator="$(app_attest_validator_source)" || {
    WIZARD_FATAL=1
    exit 1
  }
  if [[ ! -f "$REPO_ROOT/mac/companiond/apple-app-attest-root-ca.pem" || \
        ! -f "$REPO_ROOT/mac/companiond/relay-claim-2026-07-v1.pem" ]]; then
    log "ERROR: Pairling trust assets are missing; refusing to stage an incomplete runtime." >&2
    WIZARD_FATAL=1
    exit 1
  fi
  cp "$validator" "$destination/app_attest_validator.py"
  cp "$REPO_ROOT/mac/companiond/apple-app-attest-root-ca.pem" "$destination/"
  cp "$REPO_ROOT/mac/companiond/relay-claim-2026-07-v1.pem" "$destination/"
}

run_app_attest_import_check() {
  local python_bin="$1"
  local companiond_path="$2"
  local label="$3"
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$companiond_path" "$python_bin" - "$companiond_path" "$label" <<'PY'
import sys
from pathlib import Path

companiond_path, label = sys.argv[1:]
root = Path(companiond_path)
for name in (
    "app_attest_lan.py",
    "app_attest_validator.py",
    "apple-app-attest-root-ca.pem",
    "relay-claim-2026-07-v1.pem",
):
    if not (root / name).is_file():
        raise SystemExit(f"{label}: missing {name}")
import app_attest_lan
validator = app_attest_lan._load_validator()
if validator is None:
    raise SystemExit(f"{label}: App Attest validator import failed: {app_attest_lan._validator_error}")
PY
}

run_staged_psk_dependency_checks() {
  local tmp="$1"
  local staged_python="$PYTHON3_BIN"
  if [[ -x "$tmp/python/bin/python3" ]]; then
    staged_python="$tmp/python/bin/python3"
  fi
  run_psk_dependency_import_check "$staged_python" "$tmp/companiond" "staged runtime copy"
  run_app_attest_import_check "$staged_python" "$tmp/companiond" "staged runtime copy"
}

ensure_state_migrations() {
  PAIRLING_APP_SUPPORT_ROOT="$APP_SUPPORT" PAIRLING_LOGS_ROOT="$LOGS_ROOT" \
    "$PYTHON3_BIN" - "$REPO_ROOT" "$APP_SUPPORT" "$LOGS_ROOT" "$MCP_CREDENTIAL" "$PAIRLING_RUNTIME_PORT" <<'PY'
import sys
from pathlib import Path

repo_root, app_support, logs_root, credential_path, port = sys.argv[1:]
sys.path.insert(0, repo_root + "/mac/companiond")

from local_mcp_bridge import migrate_legacy_local_mcp_bridge_identity
from pairling_devices import (
    DeviceRegistry,
    InstallIdentityError,
    ensure_install_identity,
)

registry = DeviceRegistry(
    Path(app_support) / "devices.sqlite",
    Path(logs_root) / "audit.jsonl",
)
migrate_legacy_local_mcp_bridge_identity(
    registry=registry,
    credential_path=Path(credential_path),
)

try:
    ensure_install_identity(Path(app_support), runtime_port=int(port))
except InstallIdentityError as exc:
    raise SystemExit(f"{exc.code}: {exc}") from exc
PY
  mkdir -p "$RELEASES_ROOT" "$STATE_ROOT" "$PAIR_ROOT" "$LOGS_ROOT" "$PLIST_BUILD_DIR" "$APP_SUPPORT/modules"
  chmod 700 "$APP_SUPPORT" "$PAIR_ROOT" 2>/dev/null || true
  "$PYTHON3_BIN" - "$DEVICES_DB" <<'PY'
import sqlite3
import sys
path = sys.argv[1]
with sqlite3.connect(path) as db:
    db.executescript("""
    CREATE TABLE IF NOT EXISTS devices (
      device_id TEXT PRIMARY KEY,
      device_name TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      scopes_json TEXT NOT NULL,
      install_id TEXT NOT NULL,
      created_at REAL NOT NULL,
      last_seen_at REAL,
      revoked_at REAL
    );
    CREATE INDEX IF NOT EXISTS idx_devices_token_hash ON devices(token_hash);
    CREATE TABLE IF NOT EXISTS audit_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts REAL NOT NULL,
      event TEXT NOT NULL,
      device_id TEXT,
      outcome TEXT NOT NULL,
      path TEXT,
      detail_json TEXT NOT NULL
    );
    """)
PY
  chmod 600 "$DEVICES_DB" 2>/dev/null || true
  "$PYTHON3_BIN" - \
    "$REPO_ROOT/mac/companiond" \
    "$HOME/.claude/companion" \
    "$HOME/.claude/companion/terminal-capture" \
    "$HOME/.claude/audit" \
    "$LOGS_ROOT" <<'PY'
import sys
from pathlib import Path

module_root, companion, capture, audit, logs = sys.argv[1:]
sys.path.insert(0, module_root)
from pty_broker import secure_sensitive_local_storage

secure_sensitive_local_storage(
    Path(companion),
    Path(capture),
    audit_dir=Path(audit),
    logs_dir=Path(logs),
)
PY
}

ensure_local_mcp_bridge() {
  local transaction_journal=""
  if [[ "$INSTALL_TRANSACTION_ACTIVE" == 1 && "$INSTALL_TRANSACTION_DIR" == "$INSTALL_TRANSACTION_PENDING" ]]; then
    transaction_journal="$INSTALL_TRANSACTION_DIR/journal.json"
  fi
  PAIRLING_APP_SUPPORT_ROOT="$APP_SUPPORT" PAIRLING_MCP_CREDENTIAL="$MCP_CREDENTIAL" \
    "$PYTHON3_BIN" - "$REPO_ROOT" "$transaction_journal" <<'PY'
import json
import sys
from pathlib import Path

repo_root, journal_value = sys.argv[1:]
sys.path.insert(0, repo_root + "/mac/companiond")

from local_mcp_bridge import ensure_local_mcp_bridge_device

planned = None
if journal_value:
    journal = json.loads(Path(journal_value).read_text(encoding="utf-8"))
    planned = journal["mcp_credential"].get("planned")
kwargs = {}
if planned is not None:
    kwargs = {
        "planned_device_id": planned["device_id"],
        "planned_token": planned["token"],
        "planned_proof_secret": planned["proof_secret"],
    }
ensure_local_mcp_bridge_device(**kwargs)
PY
}

ensure_state() {
  ensure_state_migrations
  ensure_local_mcp_bridge
}

clear_release_quarantine() {
  local target="$1"
  if command -v xattr >/dev/null 2>&1; then
    xattr -dr com.apple.quarantine "$target" >/dev/null 2>&1 || true
  fi
}

remove_python_bytecode() {
  local root="$1"
  local residue
  if ! find "$root" -name '__pycache__' -prune -exec rm -rf {} +; then
    log "ERROR: unable to remove Python cache directories from the staged runtime." >&2
    WIZARD_FATAL=1
    exit 1
  fi
  if ! find "$root" -name '*.pyc' -delete; then
    log "ERROR: unable to remove Python bytecode files from the staged runtime." >&2
    WIZARD_FATAL=1
    exit 1
  fi
  if ! residue="$(find "$root" \( -name '__pycache__' -o -name '*.pyc' \) -print -quit)"; then
    log "ERROR: unable to verify Python bytecode cleanup in the staged runtime." >&2
    WIZARD_FATAL=1
    exit 1
  fi
  if [[ -n "$residue" ]]; then
    log "ERROR: Python bytecode remains in the staged runtime: $residue" >&2
    WIZARD_FATAL=1
    exit 1
  fi
}

verify_release_manifest() {
  local scan_root="$1" expected_install_root="$2"
  local expected_version="${3:-$VERSION}" expected_revision="${4:-$REVISION}" expected_dirty="${5:-$SOURCE_DIRTY}"
  "$PYTHON3_BIN" - \
    "$REPO_ROOT/mac/companiond" \
    "$scan_root" \
    "$expected_install_root" \
    "$expected_version" \
    "$expected_revision" \
    "$expected_dirty" <<'PY'
import json
import sys
from pathlib import Path

source_root, scan_value, install_value, version, revision, dirty = sys.argv[1:]
sys.path.insert(0, source_root)
from runtime_manifest import PROVIDER_RUNTIME_ASSET_RELATIVE_PATHS, _verify_runtime_payload

root = Path(scan_value)
manifest_path = root / "manifest.json"
if root.is_symlink() or not root.is_dir() or manifest_path.is_symlink():
    raise SystemExit("runtime release and manifest must be real paths")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
if manifest.get("schema_version") != 2:
    raise SystemExit("runtime manifest schema does not match the installer")
if manifest.get("provider_runtime_assets") != list(PROVIDER_RUNTIME_ASSET_RELATIVE_PATHS):
    raise SystemExit("runtime manifest provider asset inventory does not match the installer")
install_path = Path(install_value)
manifest_install_path = Path(str(manifest.get("install_root") or ""))
if not install_path.is_absolute() or not manifest_install_path.is_absolute():
    raise SystemExit("runtime manifest install root must be absolute")
expected_lexical = install_path.parent.resolve(strict=True) / install_path.name
manifest_lexical = manifest_install_path.parent.resolve(strict=True) / manifest_install_path.name
if manifest_lexical != expected_lexical:
    raise SystemExit("runtime manifest install root does not match the release")
if manifest.get("runtime_version") != version:
    raise SystemExit("runtime manifest version does not match the installer")
if manifest.get("source_revision") != revision:
    raise SystemExit("runtime manifest revision does not match the installer")
if manifest.get("source_dirty") is not (dirty == "true"):
    raise SystemExit("runtime manifest source state does not match the installer")
stamps = {
    "runtime_version": (root / "mac" / "VERSION").read_text(encoding="utf-8").strip(),
    "source_revision": (root / "mac" / "SOURCE_REVISION").read_text(encoding="utf-8").strip(),
    "source_dirty": (root / "mac" / "SOURCE_DIRTY").read_text(encoding="utf-8").strip().lower(),
}
if stamps["runtime_version"] != version or stamps["source_revision"] != revision:
    raise SystemExit("runtime identity stamps do not match the installer")
if stamps["source_dirty"] not in {"true", "false"} or (stamps["source_dirty"] == "true") is not (dirty == "true"):
    raise SystemExit("runtime source state stamp does not match the installer")
verified, error = _verify_runtime_payload(root, manifest, manifest_path)
if not verified:
    raise SystemExit(error or "runtime manifest verification failed")
PY
}

managed_release_identity() {
  local target="$1"
  "$PYTHON3_BIN" - "$REPO_ROOT/mac/companiond" "$target" "$RELEASES_ROOT" <<'PY'
import sys

source_root, target, releases_root = sys.argv[1:]
sys.path.insert(0, source_root)
from runtime_manifest import verified_managed_release_identity

identity = verified_managed_release_identity(target, releases_root)
values = (
    identity["root"],
    identity["runtime_version"],
    identity["source_revision"],
    "true" if identity["source_dirty"] else "false",
)
if any("\t" in value or "\n" in value for value in values):
    raise SystemExit("release identity contains an unsafe delimiter")
print("\t".join(values))
PY
}

remove_release_tree() {
  local root="$1"
  [[ -e "$root" || -L "$root" ]] || return 0
  if [[ -d "$root" && ! -L "$root" ]]; then
    # Published releases are read-only. Restore owner write access only inside
    # the tree that is about to be removed, without following symlinks.
    /bin/chmod -RN "$root" 2>/dev/null || true
    find -P "$root" -type d -exec chmod u+rwx {} +
    find -P "$root" -type f -exec chmod u+rw {} +
  fi
  rm -rf "$root"
}

seal_release_payload() {
  local root="$1"
  if ! /bin/chmod -RN "$root"; then
    log "ERROR: could not remove extended ACLs from the staged runtime: $root" >&2
    return 1
  fi
  "$PYTHON3_BIN" - "$root" <<'PY'
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
if not root.is_dir() or root.is_symlink():
    raise SystemExit(f"runtime release root is not a real directory: {root}")

for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        continue
    if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
        raise SystemExit(f"unsupported runtime release entry while sealing: {path}")
    os.chmod(path, stat.S_IMODE(metadata.st_mode) & ~0o222, follow_symlinks=False)

for path in root.rglob("*"):
    metadata = path.lstat()
    if not stat.S_ISLNK(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) & 0o222:
        raise SystemExit(f"runtime release entry remained writable: {path}")
PY
}

seal_release_root() {
  local root="$1"
  seal_release_payload "$root"
  chmod a-w "$root"
  if [[ -w "$root" ]]; then
    log "ERROR: runtime release root remained writable after sealing: $root" >&2
    return 1
  fi
}

atomic_symlink_switch() {
  local target="$1" destination="$2" directory base temporary="" attempts=0
  directory="$(dirname "$destination")"
  base="$(basename "$destination")"
  mkdir -p "$directory"
  while [[ "$attempts" -lt 32 ]]; do
    attempts="$((attempts + 1))"
    temporary="$directory/.${base}.pairling-$$-${RANDOM}"
    if ln -s "$target" "$temporary" 2>/dev/null; then
      break
    fi
    rm -f "$temporary"
  done
  if [[ ! -L "$temporary" ]]; then
    printf 'ERROR: could not create a temporary symlink for %s after %s attempts.\n' "$destination" "$attempts" >&2
    return 1
  fi
  if [[ "${PAIRLING_TEST_FAIL_ATOMIC_SYMLINK_BEFORE_RENAME:-}" == "$base" ]]; then
    rm -f "$temporary"
    return 1
  fi
  if ! "$PYTHON3_BIN" - "$temporary" "$destination" "$target" <<'PY'
import os
import sys
from pathlib import Path

temporary = Path(sys.argv[1])
destination = Path(sys.argv[2])
expected = sys.argv[3]
os.replace(temporary, destination)
if not destination.is_symlink() or os.readlink(destination) != expected:
    raise SystemExit(f"atomic symlink switch did not install the expected target: {destination}")
descriptor = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  then
    rm -f "$temporary"
    return 1
  fi
  if [[ ! -L "$destination" || "$(readlink "$destination")" != "$target" ]]; then
    printf 'ERROR: atomic symlink switch postcondition failed for %s.\n' "$destination" >&2
    return 1
  fi
}

snapshot_install_path() {
  local source="$1" name="$2"
  if [[ -L "$source" ]]; then
    printf 'symlink\n' > "$INSTALL_TRANSACTION_DIR/$name.kind"
    readlink "$source" > "$INSTALL_TRANSACTION_DIR/$name.target"
  elif [[ -f "$source" ]]; then
    printf 'file\n' > "$INSTALL_TRANSACTION_DIR/$name.kind"
    cp -p "$source" "$INSTALL_TRANSACTION_DIR/$name.file"
  elif [[ -e "$source" ]]; then
    log "ERROR: managed install path is not a file or symlink: $source" >&2
    return 1
  else
    printf 'absent\n' > "$INSTALL_TRANSACTION_DIR/$name.kind"
  fi
}

snapshot_pairdrop_directory() {
  "$PYTHON3_BIN" - "$PAIRDROP_ROOT" "$INSTALL_TRANSACTION_DIR/pairdrop.json" "$HOME" <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
output = Path(sys.argv[2])
home = Path(sys.argv[3])
if not root.is_absolute() or root in {Path("/"), home}:
    raise SystemExit(f"PairDrop storage is not a safe transaction target: {root}")
try:
    metadata = root.lstat()
except FileNotFoundError:
    payload = {"kind": "absent", "path": str(root)}
else:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit(f"PairDrop storage is not a real directory: {root}")
    if metadata.st_uid != os.geteuid():
        raise SystemExit(f"PairDrop storage is not owned by this user: {root}")
    payload = {
        "kind": "directory",
        "path": str(root),
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }
temporary = output.with_name(f".{output.name}.tmp-{os.getpid()}")
with temporary.open("x", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
    handle.flush()
    os.fchmod(handle.fileno(), 0o600)
    os.fsync(handle.fileno())
os.replace(temporary, output)
PY
}

prepare_install_transaction_root() {
  [[ "$INSTALL_LOCK_HELD" == 1 ]] || {
    log "ERROR: refusing to manage an install transaction without the install lock." >&2
    return 1
  }
  if [[ -L "$INSTALL_TRANSACTION_ROOT" ]]; then
    log "ERROR: Pairling install transaction root must not be a symlink: $INSTALL_TRANSACTION_ROOT" >&2
    return 1
  fi
  if [[ ! -e "$INSTALL_TRANSACTION_ROOT" ]]; then
    mkdir -m 700 "$INSTALL_TRANSACTION_ROOT"
    fsync_directory "$RUNTIME_ROOT"
  fi
  if [[ ! -d "$INSTALL_TRANSACTION_ROOT" ]]; then
    log "ERROR: Pairling install transaction root is not a directory: $INSTALL_TRANSACTION_ROOT" >&2
    return 1
  fi
  local owner mode
  owner="$(stat -f '%u' "$INSTALL_TRANSACTION_ROOT" 2>/dev/null || printf unknown)"
  mode="$(stat -f '%Lp' "$INSTALL_TRANSACTION_ROOT" 2>/dev/null || printf unknown)"
  if [[ "$owner" != "$(id -u)" || "$mode" != "700" ]]; then
    log "ERROR: Pairling install transaction root must be private and owned by this user: $INSTALL_TRANSACTION_ROOT" >&2
    return 1
  fi
}

remove_install_transaction_tree() {
  local target="$1" owner
  case "$target" in
    "$INSTALL_TRANSACTION_PENDING"|"$INSTALL_TRANSACTION_COMMITTED"|"$INSTALL_TRANSACTION_RECOVERED"|"$INSTALL_TRANSACTION_ROOT"/.pending.*) ;;
    *)
      log "ERROR: refusing to remove an unmanaged install transaction path: $target" >&2
      return 1
      ;;
  esac
  [[ -e "$target" || -L "$target" ]] || return 0
  if [[ -L "$target" || ! -d "$target" ]]; then
    log "ERROR: install transaction path is not a real directory: $target" >&2
    return 1
  fi
  owner="$(stat -f '%u' "$target" 2>/dev/null || printf unknown)"
  if [[ "$owner" != "$(id -u)" ]]; then
    log "ERROR: install transaction path is owned by another user: $target" >&2
    return 1
  fi
  /bin/chmod -RN "$target" 2>/dev/null || true
  find -P "$target" -type d -exec chmod u+rwx {} +
  find -P "$target" -type f -exec chmod u+rw {} +
  rm -rf "$target"
  if [[ -e "$target" || -L "$target" ]]; then
    log "ERROR: Pairling could not remove install transaction path: $target" >&2
    return 1
  fi
  fsync_directory "$INSTALL_TRANSACTION_ROOT"
}

cleanup_unpublished_install_transactions() {
  local stale owner mode
  while IFS= read -r -d '' stale; do
    if [[ -L "$stale" || ! -d "$stale" ]]; then
      log "ERROR: unpublished install transaction is not a real directory: $stale" >&2
      return 1
    fi
    owner="$(stat -f '%u' "$stale" 2>/dev/null || printf unknown)"
    mode="$(stat -f '%Lp' "$stale" 2>/dev/null || printf unknown)"
    if [[ "$owner" != "$(id -u)" || "$mode" != "700" ]]; then
      log "ERROR: unpublished install transaction is not private and user-owned: $stale" >&2
      return 1
    fi
    remove_install_transaction_tree "$stale"
  done < <(find -P "$INSTALL_TRANSACTION_ROOT" -mindepth 1 -maxdepth 1 -name '.pending.*' -print0)
}

validate_install_transaction_root_entries() {
  local entry name marker_count=0
  while IFS= read -r -d '' entry; do
    name="$(basename "$entry")"
    case "$name" in
      pending|committed|recovered)
        marker_count="$((marker_count + 1))"
        ;;
      *)
        log "ERROR: unexpected entry in Pairling install transaction root: $entry" >&2
        return 1
        ;;
    esac
  done < <(find -P "$INSTALL_TRANSACTION_ROOT" -mindepth 1 -maxdepth 1 -print0)
  if [[ "$marker_count" -gt 1 ]]; then
    log "ERROR: conflicting Pairling install transaction markers require manual inspection." >&2
    return 1
  fi
}

write_install_transaction_journal() {
  local operation="$1" expected_target="${2:-}"
  "$PYTHON3_BIN" - \
    "$INSTALL_TRANSACTION_DIR" "$operation" "$expected_target" "$RELEASE_NAME" \
    "$CONFIG_FILE" "$CURRENT_LINK" "$PREVIOUS_LINK" \
    "$USER_PLIST" "$CONNECTD_USER_PLIST" "$PTYBROKER_USER_PLIST" "$AUTOMATION_USER_PLIST" \
    "$MCP_SERVER_SHIM" "$USER_PAIRLING_WRAPPER" "$RELEASES_ROOT" \
    "$MCP_CREDENTIAL" "$DEVICES_DB" <<'PY'
import hashlib
import json
import os
import stat
import sys
import time
from pathlib import Path

(
    directory_value,
    operation,
    expected_target,
    expected_release_name,
    config,
    current,
    previous,
    companiond_plist,
    connectd_plist,
    ptybroker_plist,
    automation_plist,
    mcp_server_shim,
    shell_wrapper,
    releases_root,
    mcp_credential_value,
    devices_db_value,
) = sys.argv[1:]
directory = Path(directory_value)
metadata = directory.lstat()
if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit("install transaction staging path is not a real directory")
if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
    raise SystemExit("install transaction staging path is not private and user-owned")
if operation not in {"setup", "rollback"}:
    raise SystemExit(f"unsupported install transaction operation: {operation}")

mcp_credential = Path(mcp_credential_value)
try:
    credential_metadata = mcp_credential.lstat()
except FileNotFoundError:
    mcp_credential_preexisting = False
else:
    if stat.S_ISLNK(credential_metadata.st_mode) or not stat.S_ISREG(credential_metadata.st_mode):
        raise SystemExit("local MCP credential is not a regular file")
    if credential_metadata.st_uid != os.geteuid():
        raise SystemExit("local MCP credential is owned by another user")
    mcp_credential_preexisting = True

inventory = {}
for path in sorted(directory.iterdir(), key=lambda item: item.name):
    if path.name == "journal.json" or path.name.startswith(".journal.json.tmp-"):
        continue
    item = path.lstat()
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
        raise SystemExit(f"unsupported install transaction snapshot entry: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
        os.fsync(handle.fileno())
    inventory[path.name] = {
        "sha256": digest.hexdigest(),
        "mode": stat.S_IMODE(item.st_mode),
        "size": item.st_size,
    }

journal = {
    "schema_version": 1,
    "phase": "prepared",
    "operation": operation,
    "owner_uid": os.geteuid(),
    "created_at": time.time(),
    "expected_release_name": expected_release_name,
    "expected_target": expected_target or None,
    "expected_target_identity": None,
    "releases_root": releases_root,
    "destinations": {
        "config": config,
        "current": current,
        "previous": previous,
        "companiond_plist": companiond_plist,
        "connectd_plist": connectd_plist,
        "ptybroker_plist": ptybroker_plist,
        "automation_plist": automation_plist,
        "mcp_server_shim": mcp_server_shim,
        "shell_wrapper": shell_wrapper,
    },
    "mcp_credential": {
        "path": mcp_credential_value,
        "database": devices_db_value,
        "preexisting": mcp_credential_preexisting,
        "planned": None,
        "created": None,
    },
    "snapshots": inventory,
}
journal_path = directory / "journal.json"
temporary = directory / f".journal.json.tmp-{os.getpid()}"
with temporary.open("x", encoding="utf-8") as handle:
    json.dump(journal, handle, indent=2, sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fchmod(handle.fileno(), 0o600)
    os.fsync(handle.fileno())
os.replace(temporary, journal_path)
descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

validate_install_transaction_directory() {
  local directory="$1"
  "$PYTHON3_BIN" - \
    "$directory" "$CONFIG_FILE" "$CURRENT_LINK" "$PREVIOUS_LINK" \
    "$USER_PLIST" "$CONNECTD_USER_PLIST" "$PTYBROKER_USER_PLIST" "$AUTOMATION_USER_PLIST" \
    "$MCP_SERVER_SHIM" "$USER_PAIRLING_WRAPPER" "$RELEASES_ROOT" "$HOME" \
    "$MCP_CREDENTIAL" "$DEVICES_DB" <<'PY'
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

(
    directory_value,
    config,
    current,
    previous,
    companiond_plist,
    connectd_plist,
    ptybroker_plist,
    automation_plist,
    mcp_server_shim,
    shell_wrapper,
    releases_root_value,
    home_value,
    mcp_credential_value,
    devices_db_value,
) = sys.argv[1:]
directory = Path(directory_value)
metadata = directory.lstat()
if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit("install transaction is not a real directory")
if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
    raise SystemExit("install transaction is not private and user-owned")
journal_path = directory / "journal.json"
journal_metadata = journal_path.lstat()
if stat.S_ISLNK(journal_metadata.st_mode) or not stat.S_ISREG(journal_metadata.st_mode):
    raise SystemExit("install transaction journal is not a regular file")
if stat.S_IMODE(journal_metadata.st_mode) != 0o600:
    raise SystemExit("install transaction journal is not private")

def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate journal key: {key}")
        result[key] = value
    return result

with journal_path.open("r", encoding="utf-8") as handle:
    journal = json.load(handle, object_pairs_hook=strict_object)
if not isinstance(journal, dict) or journal.get("schema_version") != 1:
    raise SystemExit("install transaction journal schema is unsupported")
if journal.get("phase") != "prepared" or journal.get("operation") not in {"setup", "rollback"}:
    raise SystemExit("install transaction journal state is invalid")
if journal.get("owner_uid") != os.geteuid():
    raise SystemExit("install transaction journal owner does not match this user")
expected_destinations = {
    "config": config,
    "current": current,
    "previous": previous,
    "companiond_plist": companiond_plist,
    "connectd_plist": connectd_plist,
    "ptybroker_plist": ptybroker_plist,
    "automation_plist": automation_plist,
    "mcp_server_shim": mcp_server_shim,
    "shell_wrapper": shell_wrapper,
}
if journal.get("destinations") != expected_destinations:
    raise SystemExit("install transaction destinations do not match this install")
if journal.get("releases_root") != releases_root_value:
    raise SystemExit("install transaction release root does not match this install")

mcp_record = journal.get("mcp_credential")
if not isinstance(mcp_record, dict) or set(mcp_record) != {
    "path", "database", "preexisting", "planned", "created"
}:
    raise SystemExit("install transaction local MCP credential record is malformed")
if mcp_record.get("path") != mcp_credential_value or mcp_record.get("database") != devices_db_value:
    raise SystemExit("install transaction local MCP credential paths do not match this install")
if not isinstance(mcp_record.get("preexisting"), bool):
    raise SystemExit("install transaction local MCP credential presence is malformed")
planned_mcp = mcp_record.get("planned")
created_mcp = mcp_record.get("created")
if mcp_record["preexisting"] and (planned_mcp is not None or created_mcp is not None):
    raise SystemExit("install transaction cannot own a preexisting local MCP credential")
if planned_mcp is not None:
    expected_planned_keys = {"device_id", "token", "proof_secret", "token_hash"}
    if not isinstance(planned_mcp, dict) or set(planned_mcp) != expected_planned_keys:
        raise SystemExit("install transaction planned local MCP credential is malformed")
    for key in expected_planned_keys:
        if not isinstance(planned_mcp.get(key), str) or not planned_mcp[key]:
            raise SystemExit(f"install transaction planned local MCP credential {key} is malformed")
    if (
        not planned_mcp["device_id"].startswith("dev_local_mcp_")
        or not planned_mcp["token"].startswith("pld_")
        or not planned_mcp["proof_secret"].startswith("prf_")
        or len(planned_mcp["token_hash"]) != 64
        or hashlib.sha256(planned_mcp["token"].encode("utf-8")).hexdigest()
        != planned_mcp["token_hash"]
    ):
        raise SystemExit("install transaction planned local MCP credential identity is invalid")
if created_mcp is not None:
    expected_created_keys = {
        "device_id", "token_hash", "sha256", "mode", "uid", "device", "inode", "size"
    }
    if not isinstance(created_mcp, dict) or set(created_mcp) != expected_created_keys:
        raise SystemExit("install transaction created local MCP credential record is malformed")
    for key in ("device_id", "token_hash", "sha256"):
        if not isinstance(created_mcp.get(key), str) or not created_mcp[key]:
            raise SystemExit(f"install transaction created local MCP credential {key} is malformed")
    if len(created_mcp["token_hash"]) != 64 or len(created_mcp["sha256"]) != 64:
        raise SystemExit("install transaction created local MCP credential hashes are malformed")
    for key in ("mode", "uid", "device", "inode", "size"):
        if not isinstance(created_mcp.get(key), int) or isinstance(created_mcp.get(key), bool):
            raise SystemExit(f"install transaction created local MCP credential {key} is malformed")
    if created_mcp["uid"] != os.geteuid() or not 0 <= created_mcp["mode"] <= 0o7777:
        raise SystemExit("install transaction created local MCP credential ownership or mode is invalid")
    if planned_mcp is None or (
        created_mcp["device_id"] != planned_mcp["device_id"]
        or created_mcp["token_hash"] != planned_mcp["token_hash"]
    ):
        raise SystemExit("install transaction created local MCP credential does not match its plan")

releases_root = Path(releases_root_value)
target_value = journal.get("expected_target")
target_identity = journal.get("expected_target_identity")
if target_value is None:
    if target_identity is not None:
        raise SystemExit("install transaction target identity exists without a target")
else:
    if not isinstance(target_value, str) or not target_value:
        raise SystemExit("install transaction expected target is malformed")
    target = Path(target_value)
    if not target.is_absolute() or target.name in {"", ".", ".."}:
        raise SystemExit("install transaction expected target is unsafe")
    if target.parent.resolve(strict=True) != releases_root.resolve(strict=True):
        raise SystemExit("install transaction expected target is outside releases")
    if not isinstance(target_identity, dict) or set(target_identity) != {"device", "inode", "uid"}:
        raise SystemExit("install transaction expected target identity is malformed")
    if any(
        not isinstance(target_identity.get(key), int)
        or isinstance(target_identity.get(key), bool)
        for key in ("device", "inode", "uid")
    ):
        raise SystemExit("install transaction expected target identity values are malformed")
    if target_identity["uid"] != os.geteuid():
        raise SystemExit("install transaction expected target owner does not match this user")

install_names = tuple(expected_destinations)
required_names = {
    "pairdrop.json",
    "companiond.loaded",
    "connectd.loaded",
    "ptybroker.loaded",
    "automation.loaded",
}
for name in install_names:
    kind_path = directory / f"{name}.kind"
    kind = kind_path.read_text(encoding="utf-8").strip()
    if kind not in {"absent", "file", "symlink"}:
        raise SystemExit(f"install transaction snapshot kind is invalid: {name}")
    required_names.add(f"{name}.kind")
    file_path = directory / f"{name}.file"
    target_path = directory / f"{name}.target"
    if kind == "file":
        required_names.add(f"{name}.file")
        if target_path.exists() or target_path.is_symlink():
            raise SystemExit(f"install transaction has conflicting target snapshot: {name}")
    elif kind == "symlink":
        required_names.add(f"{name}.target")
        if file_path.exists() or file_path.is_symlink():
            raise SystemExit(f"install transaction has conflicting file snapshot: {name}")
        link_target = target_path.read_text(encoding="utf-8").rstrip("\n")
        if not link_target or "\n" in link_target or "\r" in link_target:
            raise SystemExit(f"install transaction symlink target is malformed: {name}")
        if name in {"current", "previous"}:
            release = Path(link_target)
            if not release.is_absolute() or release.parent.resolve(strict=True) != releases_root.resolve(strict=True):
                raise SystemExit(f"install transaction runtime link target is outside releases: {name}")
    elif file_path.exists() or file_path.is_symlink() or target_path.exists() or target_path.is_symlink():
        raise SystemExit(f"install transaction has data for an absent snapshot: {name}")

for name in ("companiond", "connectd", "ptybroker", "automation"):
    state = (directory / f"{name}.loaded").read_text(encoding="utf-8").strip()
    if state not in {"loaded", "absent", "skipped"}:
        raise SystemExit(f"install transaction launchd state is invalid: {name}")

pairdrop = json.loads((directory / "pairdrop.json").read_text(encoding="utf-8"), object_pairs_hook=strict_object)
if not isinstance(pairdrop, dict) or pairdrop.get("kind") not in {"absent", "directory"}:
    raise SystemExit("install transaction PairDrop snapshot is invalid")
pairdrop_path = Path(str(pairdrop.get("path") or ""))
if not pairdrop_path.is_absolute() or pairdrop_path in {Path("/"), Path(home_value)}:
    raise SystemExit("install transaction PairDrop path is unsafe")
if pairdrop.get("kind") == "directory":
    for key in ("mode", "uid", "device", "inode"):
        if not isinstance(pairdrop.get(key), int) or isinstance(pairdrop.get(key), bool):
            raise SystemExit(f"install transaction PairDrop {key} is invalid")
    if pairdrop["uid"] != os.geteuid() or not 0 <= pairdrop["mode"] <= 0o7777:
        raise SystemExit("install transaction PairDrop ownership or mode is invalid")

snapshot_inventory = journal.get("snapshots")
if not isinstance(snapshot_inventory, dict) or set(snapshot_inventory) != required_names:
    raise SystemExit("install transaction snapshot inventory is incomplete")
actual_names = {
    path.name
    for path in directory.iterdir()
    if path.name != "journal.json"
}
if actual_names != required_names:
    raise SystemExit("install transaction directory contains unexpected entries")
for name in sorted(required_names):
    path = directory / name
    item = path.lstat()
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
        raise SystemExit(f"install transaction snapshot is not a regular file: {name}")
    expected = snapshot_inventory.get(name)
    if not isinstance(expected, dict):
        raise SystemExit(f"install transaction snapshot metadata is invalid: {name}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    if (
        expected.get("sha256") != digest.hexdigest()
        or expected.get("mode") != stat.S_IMODE(item.st_mode)
        or expected.get("size") != item.st_size
    ):
        raise SystemExit(f"install transaction snapshot changed: {name}")
PY
}

publish_install_transaction() {
  "$PYTHON3_BIN" - "$INSTALL_TRANSACTION_DIR" "$INSTALL_TRANSACTION_PENDING" "$INSTALL_TRANSACTION_ROOT" <<'PY'
import os
import sys
from pathlib import Path

staging = Path(sys.argv[1])
pending = Path(sys.argv[2])
root = Path(sys.argv[3])
if pending.exists() or pending.is_symlink():
    raise SystemExit("an install transaction is already pending")
os.rename(staging, pending)
descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

move_install_transaction_marker() {
  local source="$1" destination="$2"
  "$PYTHON3_BIN" - "$source" "$destination" "$INSTALL_TRANSACTION_ROOT" <<'PY'
import os
import sys
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
root = Path(sys.argv[3])
if destination.exists() or destination.is_symlink():
    raise SystemExit(f"install transaction marker already exists: {destination}")
os.rename(source, destination)
descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

update_install_transaction_target() {
  local target="$1" source="$2"
  [[ "$INSTALL_TRANSACTION_ACTIVE" == 1 && "$INSTALL_TRANSACTION_DIR" == "$INSTALL_TRANSACTION_PENDING" ]] || {
    log "ERROR: no pending install transaction can accept a target." >&2
    return 1
  }
  validate_install_transaction_directory "$INSTALL_TRANSACTION_DIR"
  "$PYTHON3_BIN" - "$INSTALL_TRANSACTION_DIR/journal.json" "$target" "$source" "$RELEASES_ROOT" <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

journal_path = Path(sys.argv[1])
target = Path(sys.argv[2])
source = Path(sys.argv[3])
releases_root = Path(sys.argv[4])
if not target.is_absolute() or target.parent.resolve(strict=True) != releases_root.resolve(strict=True):
    raise SystemExit("install transaction target is outside releases")
if target.exists() or target.is_symlink():
    raise SystemExit("install transaction target already exists")
source_metadata = source.lstat()
if (
    source.parent.resolve(strict=True) != releases_root.resolve(strict=True)
    or not source.name.startswith(".")
    or ".staging." not in source.name
    or stat.S_ISLNK(source_metadata.st_mode)
    or not stat.S_ISDIR(source_metadata.st_mode)
    or source_metadata.st_uid != os.geteuid()
):
    raise SystemExit("install transaction source is not a managed staging directory")
payload = json.loads(journal_path.read_text(encoding="utf-8"))
payload["expected_target"] = str(target)
payload["expected_target_identity"] = {
    "device": source_metadata.st_dev,
    "inode": source_metadata.st_ino,
    "uid": source_metadata.st_uid,
}
temporary = journal_path.with_name(f".{journal_path.name}.tmp-{os.getpid()}")
with temporary.open("x", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fchmod(handle.fileno(), 0o600)
    os.fsync(handle.fileno())
os.replace(temporary, journal_path)
descriptor = os.open(journal_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  validate_install_transaction_directory "$INSTALL_TRANSACTION_DIR"
}

publish_install_transaction_target() {
  local source="$1" target="$2"
  [[ "$INSTALL_TRANSACTION_ACTIVE" == 1 && "$INSTALL_TRANSACTION_DIR" == "$INSTALL_TRANSACTION_PENDING" ]] || {
    log "ERROR: no pending install transaction can publish a target." >&2
    return 1
  }
  validate_install_transaction_directory "$INSTALL_TRANSACTION_DIR"
  "${CONTROL_PYTHON_BIN:-$PYTHON3_BIN}" - \
    "$INSTALL_TRANSACTION_DIR/journal.json" "$source" "$target" "$RELEASES_ROOT" <<'PY'
import ctypes
import errno
import json
import os
import stat
import sys
from pathlib import Path

journal_path = Path(sys.argv[1])
source = Path(sys.argv[2])
target = Path(sys.argv[3])
releases_root = Path(sys.argv[4])
journal = json.loads(journal_path.read_text(encoding="utf-8"))
identity = journal.get("expected_target_identity")

if (
    not source.is_absolute()
    or not target.is_absolute()
    or source.parent.resolve(strict=True) != releases_root.resolve(strict=True)
    or target.parent.resolve(strict=True) != releases_root.resolve(strict=True)
    or journal.get("expected_target") != str(target)
    or not isinstance(identity, dict)
    or set(identity) != {"device", "inode", "uid"}
):
    raise SystemExit("install transaction publication paths do not match the journal")

source_metadata = source.lstat()
expected = (identity["device"], identity["inode"], identity["uid"])
actual = (source_metadata.st_dev, source_metadata.st_ino, source_metadata.st_uid)
if (
    stat.S_ISLNK(source_metadata.st_mode)
    or not stat.S_ISDIR(source_metadata.st_mode)
    or actual != expected
):
    raise SystemExit("staging directory identity changed before publication")

# Deterministic regression mode for filesystems that reject renaming a
# non-writable source directory. The mode marker proves this branch ran.
if os.environ.get("PAIRLING_TEST_REJECT_NON_WRITABLE_RENAME") == "1":
    marker_value = os.environ.get("PAIRLING_TEST_RENAME_MODE_MARKER")
    if not marker_value:
        raise SystemExit("PAIRLING_TEST_RENAME_MODE_MARKER is required")
    marker = Path(marker_value)
    marker.write_text(f"{stat.S_IMODE(source_metadata.st_mode):03o}\n", encoding="utf-8")
    if not source_metadata.st_mode & stat.S_IWUSR:
        raise PermissionError(errno.EACCES, "simulated filesystem rejected non-writable source", str(source))

# Place a different directory at the final path immediately before rename to
# prove the exclusive publish cannot nest into, seal, or delete it.
if os.environ.get("PAIRLING_TEST_CREATE_PUBLISH_COLLISION") == "1":
    target.mkdir(mode=0o700)
    (target / "collision-sentinel").write_text("do-not-touch\n", encoding="utf-8")

libc = ctypes.CDLL(None, use_errno=True)
try:
    rename_exclusive = libc.renamex_np
except AttributeError as exc:
    raise SystemExit("macOS exclusive rename API is unavailable") from exc
rename_exclusive.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
rename_exclusive.restype = ctypes.c_int
result = rename_exclusive(os.fsencode(source), os.fsencode(target), 0x00000004)  # RENAME_EXCL
if result != 0:
    error_number = ctypes.get_errno()
    raise OSError(error_number, os.strerror(error_number), f"{source} -> {target}")

target_metadata = target.lstat()
published = (target_metadata.st_dev, target_metadata.st_ino, target_metadata.st_uid)
if (
    stat.S_ISLNK(target_metadata.st_mode)
    or not stat.S_ISDIR(target_metadata.st_mode)
    or published != expected
):
    raise SystemExit("published release identity does not match the recorded staging directory")
PY
}

install_transaction_created_target() {
  # rollback_install_transaction marks the transaction inactive before it starts
  # restoration so a second EXIT trap cannot enter it again. The pending marker,
  # not the in-memory active flag, is therefore the cleanup authority here.
  [[ "$INSTALL_TRANSACTION_DIR" == "$INSTALL_TRANSACTION_PENDING" ]] || return 0
  validate_install_transaction_directory "$INSTALL_TRANSACTION_DIR"
  "$PYTHON3_BIN" - "$INSTALL_TRANSACTION_DIR/journal.json" "$RELEASES_ROOT" <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

journal_path = Path(sys.argv[1])
releases_root = Path(sys.argv[2])
journal = json.loads(journal_path.read_text(encoding="utf-8"))
target_value = journal.get("expected_target")
if target_value is None:
    raise SystemExit(0)
target = Path(str(target_value))
release_name = str(journal.get("expected_release_name") or "")
target_identity = journal.get("expected_target_identity")
if (
    not target.is_absolute()
    or target.parent.resolve(strict=True) != releases_root.resolve(strict=True)
    or not release_name
    or not target.name.startswith(release_name + "-")
    or not isinstance(target_identity, dict)
    or set(target_identity) != {"device", "inode", "uid"}
):
    raise SystemExit("install transaction created target is outside its managed release name")
try:
    metadata = target.lstat()
except FileNotFoundError:
    metadata = None
if metadata is not None and (
    stat.S_ISLNK(metadata.st_mode)
    or not stat.S_ISDIR(metadata.st_mode)
    or metadata.st_uid != os.geteuid()
    or metadata.st_dev != target_identity.get("device")
    or metadata.st_ino != target_identity.get("inode")
    or metadata.st_uid != target_identity.get("uid")
):
    raise SystemExit("install transaction target identity does not match the published staging directory")
print(target)
PY
}

# Remove only a final release path that this transaction recorded before it
# published. Reused content-addressed releases leave expected_target empty, so
# rollback can never remove them. The old current and previous links are restored
# before this runs, and both are checked again before deletion.
cleanup_install_transaction_target() {
  local target="" owner="" link="" removed=0
  target="$(install_transaction_created_target)" || return 1
  [[ -n "$target" ]] || return 0
  for link in "$CURRENT_LINK" "$PREVIOUS_LINK"; do
    if [[ -L "$link" && "$(readlink "$link")" == "$target" ]]; then
      log "ERROR: refusing to remove a transaction release still referenced by $link: $target" >&2
      return 1
    fi
  done
  if [[ -e "$target" || -L "$target" ]]; then
    if [[ -L "$target" || ! -d "$target" ]]; then
      log "ERROR: transaction release is not a real directory: $target" >&2
      return 1
    fi
    owner="$(stat -f '%u' "$target" 2>/dev/null || printf unknown)"
    if [[ "$owner" != "$(id -u)" ]]; then
      log "ERROR: transaction release is owned by another user: $target" >&2
      return 1
    fi
    remove_release_tree "$target"
    if [[ -e "$target" || -L "$target" ]]; then
      log "ERROR: Pairling could not remove the incomplete transaction release: $target" >&2
      return 1
    fi
    removed=1
  fi
  # The parent must be synced even when the target is already absent. A prior
  # recovery may have removed it and then failed before that deletion became
  # durable. The pending journal is not safe to clear until this succeeds.
  if ! fsync_directory "$RELEASES_ROOT"; then
    log "ERROR: could not make transaction release cleanup durable: $RELEASES_ROOT" >&2
    return 1
  fi
  if [[ "$removed" == 1 ]]; then
    log "Removed the uncommitted runtime release created by this setup: $target" >&2
  fi
}

plan_install_transaction_mcp_credential() {
  [[ "$INSTALL_TRANSACTION_ACTIVE" == 1 && "$INSTALL_TRANSACTION_DIR" == "$INSTALL_TRANSACTION_PENDING" ]] || {
    log "ERROR: no pending install transaction can plan a local MCP credential." >&2
    return 1
  }
  validate_install_transaction_directory "$INSTALL_TRANSACTION_DIR"
  "$PYTHON3_BIN" - "$INSTALL_TRANSACTION_DIR/journal.json" <<'PY'
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

journal_path = Path(sys.argv[1])
journal = json.loads(journal_path.read_text(encoding="utf-8"))
record = journal["mcp_credential"]
if record["preexisting"] or record.get("planned") is not None:
    raise SystemExit(0)
token = "pld_" + secrets.token_urlsafe(32)
record["planned"] = {
    "device_id": "dev_local_mcp_" + secrets.token_hex(12),
    "token": token,
    "proof_secret": "prf_" + secrets.token_urlsafe(32),
    "token_hash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
}
temporary = journal_path.with_name(f".{journal_path.name}.tmp-{os.getpid()}")
with temporary.open("x", encoding="utf-8") as handle:
    json.dump(journal, handle, indent=2, sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fchmod(handle.fileno(), 0o600)
    os.fsync(handle.fileno())
os.replace(temporary, journal_path)
directory_descriptor = os.open(journal_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory_descriptor)
finally:
    os.close(directory_descriptor)
PY
  validate_install_transaction_directory "$INSTALL_TRANSACTION_DIR"
}

record_install_transaction_mcp_credential() {
  [[ "$INSTALL_TRANSACTION_ACTIVE" == 1 && "$INSTALL_TRANSACTION_DIR" == "$INSTALL_TRANSACTION_PENDING" ]] || {
    log "ERROR: no pending install transaction can record a local MCP credential." >&2
    return 1
  }
  validate_install_transaction_directory "$INSTALL_TRANSACTION_DIR"
  "$PYTHON3_BIN" - "$INSTALL_TRANSACTION_DIR/journal.json" "$MCP_CREDENTIAL" "$DEVICES_DB" <<'PY'
import hashlib
import json
import os
import sqlite3
import stat
import sys
from pathlib import Path

journal_path = Path(sys.argv[1])
credential_path = Path(sys.argv[2])
database_path = Path(sys.argv[3])
journal = json.loads(journal_path.read_text(encoding="utf-8"))
record = journal["mcp_credential"]
if record["preexisting"]:
    raise SystemExit(0)
planned = record.get("planned")
if not isinstance(planned, dict):
    raise SystemExit("local MCP credential creation was not planned durably")

metadata = credential_path.lstat()
if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
    raise SystemExit("new local MCP credential is not a regular file")
if metadata.st_uid != os.geteuid():
    raise SystemExit("new local MCP credential is owned by another user")
descriptor = os.open(credential_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
        raise SystemExit("new local MCP credential changed while being opened")
    content = bytearray()
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            break
        content.extend(chunk)
        if len(content) > 1024 * 1024:
            raise SystemExit("new local MCP credential is unexpectedly large")
finally:
    os.close(descriptor)
try:
    credential = json.loads(bytes(content).decode("utf-8"))
except (UnicodeError, json.JSONDecodeError) as exc:
    raise SystemExit("new local MCP credential is malformed") from exc
device_id = str(credential.get("device_id") or "")
token = str(credential.get("token") or "")
if device_id != planned["device_id"] or not token:
    raise SystemExit("new local MCP credential identity is malformed")
token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
if token_hash != planned["token_hash"]:
    raise SystemExit("new local MCP credential token does not match its durable plan")

database_metadata = database_path.lstat()
if stat.S_ISLNK(database_metadata.st_mode) or not stat.S_ISREG(database_metadata.st_mode):
    raise SystemExit("Pairling device registry is not a regular file")
if database_metadata.st_uid != os.geteuid():
    raise SystemExit("Pairling device registry is owned by another user")
with sqlite3.connect(database_path, timeout=5.0) as database:
    database.row_factory = sqlite3.Row
    database.execute("PRAGMA busy_timeout = 5000")
    row = database.execute(
        "SELECT device_name, token_hash, purpose, revoked_at FROM devices WHERE device_id = ?",
        (device_id,),
    ).fetchone()
if (
    row is None
    or str(row["device_name"] or "") != "Pairling MCP Bridge"
    or str(row["purpose"] or "") != "local_mcp_bridge"
    or str(row["token_hash"] or "") != token_hash
    or row["revoked_at"] is not None
):
    raise SystemExit("new local MCP credential does not match one active internal device row")

created = {
    "device_id": device_id,
    "token_hash": token_hash,
    "sha256": hashlib.sha256(content).hexdigest(),
    "mode": stat.S_IMODE(metadata.st_mode),
    "uid": metadata.st_uid,
    "device": metadata.st_dev,
    "inode": metadata.st_ino,
    "size": metadata.st_size,
}
existing = record.get("created")
if existing is not None and existing != created:
    raise SystemExit("install transaction already records a different local MCP credential")
record["created"] = created
temporary = journal_path.with_name(f".{journal_path.name}.tmp-{os.getpid()}")
with temporary.open("x", encoding="utf-8") as handle:
    json.dump(journal, handle, indent=2, sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fchmod(handle.fileno(), 0o600)
    os.fsync(handle.fileno())
os.replace(temporary, journal_path)
directory_descriptor = os.open(journal_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory_descriptor)
finally:
    os.close(directory_descriptor)
PY
  validate_install_transaction_directory "$INSTALL_TRANSACTION_DIR"
}

rollback_created_mcp_credential() {
  "$PYTHON3_BIN" - "$INSTALL_TRANSACTION_DIR/journal.json" <<'PY'
import hashlib
import json
import os
import sqlite3
import stat
import sys
import time
from pathlib import Path

journal = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
record = journal["mcp_credential"]
planned = record.get("planned")
created = record.get("created")
if planned is None:
    raise SystemExit(0)
credential_path = Path(record["path"])
database_path = Path(record["database"])

credential_exists = False
credential_identity = None
try:
    metadata = credential_path.lstat()
except FileNotFoundError:
    metadata = None
else:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit("created local MCP credential was replaced by a non-file")
    if metadata.st_uid != os.geteuid():
        raise SystemExit("created local MCP credential is owned by another user")
    if created is not None:
        actual_identity = (
            metadata.st_uid,
            metadata.st_dev,
            metadata.st_ino,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_size,
        )
        expected_identity = (
            created["uid"],
            created["device"],
            created["inode"],
            created["mode"],
            created["size"],
        )
        if actual_identity != expected_identity:
            raise SystemExit("created local MCP credential changed before rollback")
    descriptor = os.open(credential_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise SystemExit("created local MCP credential changed while being opened")
        content = bytearray()
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > 1024 * 1024:
                raise SystemExit("created local MCP credential is unexpectedly large")
    finally:
        os.close(descriptor)
    if created is not None and hashlib.sha256(content).hexdigest() != created["sha256"]:
        raise SystemExit("created local MCP credential content changed before rollback")
    credential = json.loads(bytes(content).decode("utf-8"))
    if (
        str(credential.get("device_id") or "") != planned["device_id"]
        or hashlib.sha256(str(credential.get("token") or "").encode("utf-8")).hexdigest()
        != planned["token_hash"]
    ):
        raise SystemExit("created local MCP credential identity changed before rollback")
    credential_exists = True
    credential_identity = (metadata.st_dev, metadata.st_ino)

database_metadata = database_path.lstat()
if stat.S_ISLNK(database_metadata.st_mode) or not stat.S_ISREG(database_metadata.st_mode):
    raise SystemExit("Pairling device registry is not a regular file")
if database_metadata.st_uid != os.geteuid():
    raise SystemExit("Pairling device registry is owned by another user")
with sqlite3.connect(database_path, timeout=5.0, isolation_level=None) as database:
    database.row_factory = sqlite3.Row
    database.execute("PRAGMA busy_timeout = 5000")
    database.execute("BEGIN IMMEDIATE")
    try:
        row = database.execute(
            "SELECT device_name, token_hash, purpose, revoked_at FROM devices WHERE device_id = ?",
            (planned["device_id"],),
        ).fetchone()
        if row is None and credential_exists:
            raise RuntimeError("planned local MCP credential file has no matching device row")
        if row is not None and (
            str(row["device_name"] or "") != "Pairling MCP Bridge"
            or str(row["purpose"] or "") != "local_mcp_bridge"
            or str(row["token_hash"] or "") != planned["token_hash"]
        ):
            raise RuntimeError("recorded local MCP device row changed before rollback")
        if row is not None and row["revoked_at"] is None:
            revoked_at = time.time()
            changed = database.execute(
                "UPDATE devices SET revoked_at = ? WHERE device_id = ? AND device_name = ? "
                "AND purpose = ? AND token_hash = ? AND revoked_at IS NULL",
                (
                    revoked_at,
                    planned["device_id"],
                    "Pairling MCP Bridge",
                    "local_mcp_bridge",
                    planned["token_hash"],
                ),
            ).rowcount
            if changed != 1:
                raise RuntimeError("recorded local MCP device row changed during rollback")
            database.execute(
                "INSERT INTO audit_events (ts, event, device_id, outcome, path, detail_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    revoked_at,
                    "device.revoked",
                    planned["device_id"],
                    "ok",
                    None,
                    json.dumps({"reason": "install_transaction_rollback"}, sort_keys=True),
                ),
            )
        database.execute("COMMIT")
    except BaseException:
        database.execute("ROLLBACK")
        raise

if credential_exists:
    parent_fd = os.open(
        credential_path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        latest = os.stat(credential_path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (latest.st_dev, latest.st_ino) != credential_identity:
            raise SystemExit("created local MCP credential changed before removal")
        os.unlink(credential_path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
PY
}

install_transaction_fault_point() {
  local point="$1"
  if [[ "${PAIRLING_TEST_KILL_AT_INSTALL_POINT:-}" == "$point" ]]; then
    kill -KILL "$$"
  fi
}

restore_pairdrop_directory() {
  "$PYTHON3_BIN" - "$INSTALL_TRANSACTION_DIR/pairdrop.json" <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

snapshot = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
root = Path(snapshot["path"])
if not root.is_absolute() or root == Path("/"):
    raise SystemExit(f"unsafe PairDrop rollback path: {root}")

try:
    parent_fd = os.open(root.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
except FileNotFoundError:
    if snapshot["kind"] == "absent":
        raise SystemExit(0)
    raise

try:
    try:
        current = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        if snapshot["kind"] == "absent":
            raise SystemExit(0)
        raise SystemExit(f"original PairDrop directory disappeared during rollback: {root}")
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode):
        raise SystemExit(f"PairDrop rollback target is not a real directory: {root}")
    if current.st_uid != os.geteuid():
        raise SystemExit(f"PairDrop rollback target is owned by another user: {root}")

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(root.name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(directory_fd)
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise SystemExit(f"PairDrop rollback target changed while being opened: {root}")
        if snapshot["kind"] == "directory":
            expected_identity = (snapshot["device"], snapshot["inode"])
            if (opened.st_dev, opened.st_ino) != expected_identity:
                raise SystemExit(f"PairDrop rollback target was replaced: {root}")
            os.fchmod(directory_fd, snapshot["mode"])
            os.fsync(directory_fd)
        else:
            if os.listdir(directory_fd):
                raise SystemExit(f"PairDrop rollback preserved a newly populated directory: {root}")
    finally:
        os.close(directory_fd)

    if snapshot["kind"] == "absent":
        latest = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        if (latest.st_dev, latest.st_ino) != (current.st_dev, current.st_ino):
            raise SystemExit(f"PairDrop rollback target changed before removal: {root}")
        os.rmdir(root.name, dir_fd=parent_fd)
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PY
}

verify_restored_pairdrop_directory() {
  "$PYTHON3_BIN" - "$INSTALL_TRANSACTION_DIR/pairdrop.json" <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

snapshot = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
root = Path(snapshot["path"])
try:
    metadata = root.lstat()
except FileNotFoundError:
    if snapshot["kind"] != "absent":
        raise SystemExit(f"PairDrop directory was not restored: {root}")
else:
    if snapshot["kind"] == "absent":
        raise SystemExit(f"new PairDrop directory remained after rollback: {root}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit(f"restored PairDrop path is not a real directory: {root}")
    expected = (snapshot["uid"], snapshot["device"], snapshot["inode"], snapshot["mode"])
    actual = (metadata.st_uid, metadata.st_dev, metadata.st_ino, stat.S_IMODE(metadata.st_mode))
    if actual != expected:
        raise SystemExit(f"restored PairDrop directory metadata does not match its snapshot: {root}")
PY
}

atomic_restore_file() {
  local source="$1" destination="$2"
  mkdir -p "$(dirname "$destination")"
  "$PYTHON3_BIN" - "$source" "$destination" <<'PY'
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
metadata = source.lstat()
if not stat.S_ISREG(metadata.st_mode):
    raise SystemExit(f"rollback source is not a regular file: {source}")
fd, temporary_value = tempfile.mkstemp(prefix=f".{destination.name}.pairling-", dir=destination.parent)
temporary = Path(temporary_value)
try:
    with source.open("rb") as input_handle, os.fdopen(fd, "wb", closefd=True) as output_handle:
        shutil.copyfileobj(input_handle, output_handle, 1024 * 1024)
        output_handle.flush()
        os.fchmod(output_handle.fileno(), stat.S_IMODE(metadata.st_mode))
        os.fsync(output_handle.fileno())
    os.replace(temporary, destination)
    descriptor = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
finally:
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
PY
}

remove_install_path() {
  local destination="$1"
  "$PYTHON3_BIN" - "$destination" <<'PY'
import os
import sys
from pathlib import Path

destination = Path(sys.argv[1])
try:
    destination.unlink()
except FileNotFoundError:
    pass
if not destination.parent.is_dir():
    raise SystemExit(0)
descriptor = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

restore_install_path() {
  local destination="$1" name="$2" kind target temporary
  kind="$(cat "$INSTALL_TRANSACTION_DIR/$name.kind" 2>/dev/null || printf 'absent')"
  case "$kind" in
    symlink)
      target="$(cat "$INSTALL_TRANSACTION_DIR/$name.target")"
      atomic_symlink_switch "$target" "$destination"
      ;;
    file)
      atomic_restore_file "$INSTALL_TRANSACTION_DIR/$name.file" "$destination"
      ;;
    *) remove_install_path "$destination" ;;
  esac
}

verify_restored_install_path() {
  local destination="$1" name="$2" kind expected
  kind="$(cat "$INSTALL_TRANSACTION_DIR/$name.kind" 2>/dev/null || printf 'absent')"
  case "$kind" in
    symlink)
      [[ -L "$destination" ]] || return 1
      expected="$(cat "$INSTALL_TRANSACTION_DIR/$name.target")"
      [[ "$(readlink "$destination")" == "$expected" ]]
      ;;
    file) [[ -f "$destination" && ! -L "$destination" ]] && cmp -s "$INSTALL_TRANSACTION_DIR/$name.file" "$destination" ;;
    *) [[ ! -e "$destination" && ! -L "$destination" ]] ;;
  esac
}

snapshot_launchd_loaded() {
  local label="$1" name="$2"
  if launchd_skipped || is_dry_run; then
    printf 'skipped\n' > "$INSTALL_TRANSACTION_DIR/$name.loaded"
  elif launchctl print "gui/$(id -u)/$label" >/dev/null 2>&1; then
    printf 'loaded\n' > "$INSTALL_TRANSACTION_DIR/$name.loaded"
  else
    printf 'absent\n' > "$INSTALL_TRANSACTION_DIR/$name.loaded"
  fi
}

restore_ptybroker_launchd_state() {
  local expected
  expected="$(cat "$INSTALL_TRANSACTION_DIR/ptybroker.loaded" 2>/dev/null || printf 'skipped')"
  [[ "$expected" != "skipped" ]] || return 0
  if [[ "$expected" == "absent" ]]; then
    launchctl bootout "gui/$(id -u)/$PAIRLING_PTYBROKER_LABEL" >/dev/null 2>&1 || true
    launchctl bootout "gui/$(id -u)" "$PTYBROKER_USER_PLIST" >/dev/null 2>&1 || true
    ! launchctl print "gui/$(id -u)/$PAIRLING_PTYBROKER_LABEL" >/dev/null 2>&1
    return
  fi
  # Preserve an already-running broker. Restarting it here would destroy live
  # PTYs, which is the state this rollback is meant to recover.
  if launchctl print "gui/$(id -u)/$PAIRLING_PTYBROKER_LABEL" >/dev/null 2>&1; then
    return 0
  fi
  [[ -f "$PTYBROKER_USER_PLIST" && ! -L "$PTYBROKER_USER_PLIST" ]] || return 1
  launchctl bootstrap "gui/$(id -u)" "$PTYBROKER_USER_PLIST" >/dev/null 2>&1 || true
  launchctl kickstart "gui/$(id -u)/$PAIRLING_PTYBROKER_LABEL" >/dev/null 2>&1 || true
  launchctl print "gui/$(id -u)/$PAIRLING_PTYBROKER_LABEL" >/dev/null 2>&1
}

restore_launch_agent_state() {
  local label="$1" plist="$2" name="$3" expected
  expected="$(cat "$INSTALL_TRANSACTION_DIR/$name.loaded" 2>/dev/null || printf 'skipped')"
  [[ "$expected" != "skipped" ]] || return 0
  if [[ "$expected" == "absent" ]]; then
    unload_launch_agent "$label"
    return
  fi
  [[ -f "$plist" && ! -L "$plist" ]] || return 1
  reload_launch_agent "$label" "$plist"
}

begin_install_transaction() {
  local operation="${1:-setup}" staging=""
  [[ "$INSTALL_LOCK_HELD" == 1 ]] || {
    log "ERROR: refusing to begin an install transaction without the install lock." >&2
    return 1
  }
  case "$operation" in
    setup|rollback) ;;
    *)
      log "ERROR: unsupported install transaction operation: $operation" >&2
      return 1
      ;;
  esac
  prepare_install_transaction_root
  cleanup_unpublished_install_transactions
  validate_install_transaction_root_entries
  if [[ -e "$INSTALL_TRANSACTION_PENDING" || -L "$INSTALL_TRANSACTION_PENDING" ||
        -e "$INSTALL_TRANSACTION_COMMITTED" || -L "$INSTALL_TRANSACTION_COMMITTED" ||
        -e "$INSTALL_TRANSACTION_RECOVERED" || -L "$INSTALL_TRANSACTION_RECOVERED" ]]; then
    log "ERROR: an earlier Pairling install transaction must be recovered before setup can continue." >&2
    return 1
  fi
  staging="$(mktemp -d "$INSTALL_TRANSACTION_ROOT/.pending.XXXXXX")"
  chmod 700 "$staging"
  INSTALL_TRANSACTION_DIR="$staging"
  INSTALL_TRANSACTION_OPERATION="$operation"

  if ! snapshot_install_path "$CONFIG_FILE" config ||
     ! snapshot_install_path "$CURRENT_LINK" current ||
     ! snapshot_install_path "$PREVIOUS_LINK" previous ||
	     ! snapshot_install_path "$USER_PLIST" companiond_plist ||
	     ! snapshot_install_path "$CONNECTD_USER_PLIST" connectd_plist ||
	     ! snapshot_install_path "$PTYBROKER_USER_PLIST" ptybroker_plist ||
	     ! snapshot_install_path "$AUTOMATION_USER_PLIST" automation_plist ||
     ! snapshot_install_path "$MCP_SERVER_SHIM" mcp_server_shim ||
     ! snapshot_install_path "$USER_PAIRLING_WRAPPER" shell_wrapper ||
     ! snapshot_pairdrop_directory ||
	     ! snapshot_launchd_loaded "$PAIRLING_DAEMON_LABEL" companiond ||
	     ! snapshot_launchd_loaded "$PAIRLING_CONNECTD_LABEL" connectd ||
	     ! snapshot_launchd_loaded "$PAIRLING_PTYBROKER_LABEL" ptybroker ||
	     ! snapshot_launchd_loaded "$AUTOMATION_LAUNCH_AGENT_LABEL" automation ||
     ! write_install_transaction_journal "$operation"; then
    remove_install_transaction_tree "$staging" || true
    INSTALL_TRANSACTION_DIR=""
    INSTALL_TRANSACTION_OPERATION=""
    return 1
  fi
  if ! publish_install_transaction; then
    remove_install_transaction_tree "$staging" || true
    INSTALL_TRANSACTION_DIR=""
    INSTALL_TRANSACTION_OPERATION=""
    return 1
  fi
  INSTALL_TRANSACTION_DIR="$INSTALL_TRANSACTION_PENDING"
  INSTALL_TRANSACTION_ACTIVE=1
  validate_install_transaction_directory "$INSTALL_TRANSACTION_DIR"
  install_transaction_fault_point transaction_pending
}

restore_install_transaction_snapshot() {
  local rollback_failed=0
  restore_automation_helper_promotion || rollback_failed=1
  restore_install_path "$CONFIG_FILE" config || rollback_failed=1
  restore_install_path "$CURRENT_LINK" current || rollback_failed=1
  restore_install_path "$PREVIOUS_LINK" previous || rollback_failed=1
  restore_install_path "$USER_PLIST" companiond_plist || rollback_failed=1
  restore_install_path "$CONNECTD_USER_PLIST" connectd_plist || rollback_failed=1
  restore_install_path "$PTYBROKER_USER_PLIST" ptybroker_plist || rollback_failed=1
  restore_install_path "$AUTOMATION_USER_PLIST" automation_plist || rollback_failed=1
  restore_install_path "$MCP_SERVER_SHIM" mcp_server_shim || rollback_failed=1
  restore_install_path "$USER_PAIRLING_WRAPPER" shell_wrapper || rollback_failed=1
  restore_pairdrop_directory || rollback_failed=1
  rollback_created_mcp_credential || rollback_failed=1
  verify_restored_install_path "$CONFIG_FILE" config || rollback_failed=1
  verify_restored_install_path "$CURRENT_LINK" current || rollback_failed=1
  verify_restored_install_path "$PREVIOUS_LINK" previous || rollback_failed=1
  verify_restored_install_path "$USER_PLIST" companiond_plist || rollback_failed=1
  verify_restored_install_path "$CONNECTD_USER_PLIST" connectd_plist || rollback_failed=1
  verify_restored_install_path "$PTYBROKER_USER_PLIST" ptybroker_plist || rollback_failed=1
  verify_restored_install_path "$AUTOMATION_USER_PLIST" automation_plist || rollback_failed=1
  verify_restored_install_path "$MCP_SERVER_SHIM" mcp_server_shim || rollback_failed=1
  verify_restored_install_path "$USER_PAIRLING_WRAPPER" shell_wrapper || rollback_failed=1
  verify_restored_pairdrop_directory || rollback_failed=1
  install_transaction_fault_point recovery_paths_restored
  restore_ptybroker_launchd_state || rollback_failed=1
  restore_launch_agent_state "$AUTOMATION_LAUNCH_AGENT_LABEL" "$AUTOMATION_USER_PLIST" automation || rollback_failed=1
  restore_launch_agent_state "$PAIRLING_DAEMON_LABEL" "$USER_PLIST" companiond || rollback_failed=1
  restore_launch_agent_state "$PAIRLING_CONNECTD_LABEL" "$CONNECTD_USER_PLIST" connectd || rollback_failed=1
  cleanup_install_transaction_target || rollback_failed=1
  [[ "$rollback_failed" == 0 ]]
}

commit_install_transaction() {
  if [[ "$INSTALL_TRANSACTION_ACTIVE" != 1 || "$INSTALL_TRANSACTION_DIR" != "$INSTALL_TRANSACTION_PENDING" ]]; then
    return
  fi
  validate_install_transaction_directory "$INSTALL_TRANSACTION_DIR"
  move_install_transaction_marker "$INSTALL_TRANSACTION_PENDING" "$INSTALL_TRANSACTION_COMMITTED"
  INSTALL_TRANSACTION_ACTIVE=0
  INSTALL_TRANSACTION_DIR="$INSTALL_TRANSACTION_COMMITTED"
  install_transaction_fault_point transaction_committed
  commit_automation_helper_promotion
  validate_install_transaction_directory "$INSTALL_TRANSACTION_DIR"
  remove_install_transaction_tree "$INSTALL_TRANSACTION_DIR"
  INSTALL_TRANSACTION_DIR=""
  INSTALL_TRANSACTION_OPERATION=""
}

rollback_install_transaction() {
  if [[ "$INSTALL_TRANSACTION_ACTIVE" != 1 || "$INSTALL_TRANSACTION_DIR" != "$INSTALL_TRANSACTION_PENDING" ]]; then
    return
  fi
  # The active runtime interpreter may live inside the release this rollback is
  # about to remove. Return all transaction work to the interpreter pinned before
  # runtime/current changed so cleanup and journal durability can finish.
  PYTHON3_BIN="${CONTROL_PYTHON_BIN:-$PYTHON3_BIN}"
  if ! validate_install_transaction_directory "$INSTALL_TRANSACTION_DIR"; then
    INSTALL_TRANSACTION_ACTIVE=0
    log "ERROR: refusing to restore a damaged Pairling install transaction." >&2
    return 1
  fi
  INSTALL_TRANSACTION_ACTIVE=0
  if ! restore_install_transaction_snapshot; then
    log "ERROR: incomplete runtime activation rollback needs manual repair; run pairling doctor --json." >&2
    return 1
  fi
  move_install_transaction_marker "$INSTALL_TRANSACTION_PENDING" "$INSTALL_TRANSACTION_RECOVERED"
  INSTALL_TRANSACTION_DIR="$INSTALL_TRANSACTION_RECOVERED"
  install_transaction_fault_point transaction_recovered
  validate_install_transaction_directory "$INSTALL_TRANSACTION_DIR"
  remove_install_transaction_tree "$INSTALL_TRANSACTION_DIR"
  INSTALL_TRANSACTION_DIR=""
  INSTALL_TRANSACTION_OPERATION=""
  log "Rolled back the incomplete runtime activation and PairDrop configuration." >&2
}

recover_pending_install_transaction() {
  [[ "$INSTALL_LOCK_HELD" == 1 ]] || {
    log "ERROR: refusing to recover an install transaction without the install lock." >&2
    return 1
  }
  if [[ ! -e "$INSTALL_TRANSACTION_ROOT" && ! -L "$INSTALL_TRANSACTION_ROOT" ]]; then
    return 0
  fi
  prepare_install_transaction_root
  cleanup_unpublished_install_transactions
  validate_install_transaction_root_entries

  if [[ -e "$INSTALL_TRANSACTION_COMMITTED" || -L "$INSTALL_TRANSACTION_COMMITTED" ]]; then
    validate_install_transaction_directory "$INSTALL_TRANSACTION_COMMITTED"
    commit_automation_helper_promotion
    remove_install_transaction_tree "$INSTALL_TRANSACTION_COMMITTED"
    log "Finished cleanup for a committed Pairling install transaction." >&2
    return 0
  fi
  if [[ -e "$INSTALL_TRANSACTION_RECOVERED" || -L "$INSTALL_TRANSACTION_RECOVERED" ]]; then
    validate_install_transaction_directory "$INSTALL_TRANSACTION_RECOVERED"
    remove_install_transaction_tree "$INSTALL_TRANSACTION_RECOVERED"
    log "Finished cleanup for a recovered Pairling install transaction." >&2
    return 0
  fi
  if [[ -e "$INSTALL_TRANSACTION_PENDING" || -L "$INSTALL_TRANSACTION_PENDING" ]]; then
    validate_install_transaction_directory "$INSTALL_TRANSACTION_PENDING"
    INSTALL_TRANSACTION_DIR="$INSTALL_TRANSACTION_PENDING"
    INSTALL_TRANSACTION_ACTIVE=1
    INSTALL_TRANSACTION_OPERATION="recovery"
    log "Recovering an interrupted Pairling install transaction." >&2
    rollback_install_transaction
  fi
}

ensure_pairdrop_folder() {
  if ! "$PYTHON3_BIN" - "$PAIRDROP_ROOT" <<'PY'
import os
import secrets
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
root.mkdir(mode=0o700, parents=True, exist_ok=True)
metadata = root.lstat()
if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit("PairDrop storage must be a real directory, not a link or file")

open_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
directory_fd = os.open(root, open_flags)
probe_name = f".pairling-write-test-{secrets.token_hex(16)}"
probe_fd = None
try:
    os.fchmod(directory_fd, 0o700)
    metadata = os.fstat(directory_fd)
    if metadata.st_uid != os.geteuid():
        raise SystemExit("PairDrop storage must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SystemExit("PairDrop storage could not be secured to mode 0700")
    probe_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    probe_fd = os.open(probe_name, probe_flags, 0o600, dir_fd=directory_fd)
    os.write(probe_fd, b"ok\n")
    os.fsync(probe_fd)
finally:
    if probe_fd is not None:
        os.close(probe_fd)
    try:
        os.unlink(probe_name, dir_fd=directory_fd)
    except FileNotFoundError:
        pass
    os.close(directory_fd)
PY
  then
    log "ERROR: PairDrop folder is not writable or cannot be secured: $PAIRDROP_ROOT" >&2
    exit 1
  fi
  log "PairDrop folder: $(display_path "$PAIRDROP_ROOT")"
}

persist_pairdrop_folder() {
  PAIRLING_APP_SUPPORT_ROOT="$APP_SUPPORT" "$PYTHON3_BIN" - "$REPO_ROOT" "$APP_SUPPORT" "$PAIRDROP_ROOT" <<'PY'
import sys
from pathlib import Path

repo_root, app_support, pairdrop_root = sys.argv[1:]
sys.path.insert(0, repo_root + "/mac/companiond")

from pairling_devices import InstallIdentityError, persist_pairdrop_root

try:
    persist_pairdrop_root(Path(app_support), Path(pairdrop_root))
except InstallIdentityError as exc:
    raise SystemExit(f"{exc.code}: {exc}") from exc
PY
}

persist_push_provider_defaults() {
  PAIRLING_APP_SUPPORT_ROOT="$APP_SUPPORT" "$PYTHON3_BIN" - "$REPO_ROOT" "$APP_SUPPORT" <<'PY'
import sys
from pathlib import Path

repo_root, app_support = sys.argv[1:]
sys.path.insert(0, repo_root + "/mac/companiond")

from pairling_devices import InstallIdentityError, persist_push_provider_defaults

try:
    persist_push_provider_defaults(Path(app_support))
except InstallIdentityError as exc:
    raise SystemExit(f"{exc.code}: {exc}") from exc
PY
}

payload_manifest_path() {
  local candidate="$REPO_ROOT/../payload-manifest.json"
  if [[ -f "$candidate" ]]; then
    printf '%s\n' "$candidate"
  fi
}

verify_payload_manifest() {
  local manifest
  manifest="$(payload_manifest_path)"
  if [[ -z "$manifest" ]]; then
    return 0
  fi
  log "Verifying npm payload manifest"
  if ! "$PYTHON3_BIN" "$REPO_ROOT/mac/install/verify-payload-manifest.py" "$REPO_ROOT" "$manifest"; then
    WIZARD_FATAL=1
    exit 1
  fi
}

verify_platform_runtime_manifest() {
  local prebuilt="${PAIRLING_CONNECTD_PREBUILT:-}" root="${PAIRLING_RUNTIME_PACKAGE_ROOT:-}"
  local provided_python="${PAIRLING_DAEMON_PYTHON:-}" python_root=""
  [[ -n "$prebuilt" ]] || return 0
  if [[ -z "$root" ]]; then
    root="$(cd "$(dirname "$prebuilt")/.." && pwd)"
  fi
  if [[ ! -f "$root/manifest.json" ]]; then
    if [[ -n "${PAIRLING_RUNTIME_PACKAGE_ROOT:-}" ]]; then
      log "ERROR: npm runtime package manifest is missing: $root/manifest.json" >&2
      WIZARD_FATAL=1
      exit 1
    fi
    return 0
  fi
  if [[ "$(cd "$(dirname "$prebuilt")/.." && pwd)" != "$(cd "$root" && pwd)" ]]; then
    log "ERROR: connectd is outside the declared npm runtime package: $prebuilt" >&2
    WIZARD_FATAL=1
    exit 1
  fi
  case "$provided_python" in
    */python/bin/python3)
      python_root="$(cd "$(dirname "$provided_python")/../.." && pwd)"
      if [[ "$python_root" != "$(cd "$root" && pwd)" ]]; then
        log "ERROR: vendored Python is outside the declared npm runtime package: $provided_python" >&2
        WIZARD_FATAL=1
        exit 1
      fi
      ;;
  esac
  if ! "$PYTHON3_BIN" "$REPO_ROOT/mac/install/verify-runtime-package-manifest.py" \
    "$root" "$VERSION" "$REVISION"; then
    WIZARD_FATAL=1
    exit 1
  fi
}

snapshot_packaged_sources() {
  local payload_manifest runtime_root snapshot_payload snapshot_runtime
  case "${PAIRLING_PACKAGE_SNAPSHOT:-}" in
    payload|full) return 0 ;;
  esac
  payload_manifest="$(payload_manifest_path)"
  runtime_root="${PAIRLING_RUNTIME_PACKAGE_ROOT:-}"
  [[ -n "$payload_manifest" && -n "$runtime_root" ]] || return 0
  if [[ -L "$REPO_ROOT" || ! -d "$REPO_ROOT" || -L "$runtime_root" || ! -d "$runtime_root" ]]; then
    log "ERROR: npm package sources must be real directories before setup can snapshot them." >&2
    WIZARD_FATAL=1
    return 1
  fi

  cleanup_stale_source_snapshots
  ACTIVE_SOURCE_SNAPSHOT="$(mktemp -d "$SOURCE_SNAPSHOT_ROOT/.package.XXXXXX")"
  chmod 700 "$ACTIVE_SOURCE_SNAPSHOT"
  fsync_directory "$SOURCE_SNAPSHOT_ROOT"
  snapshot_payload="$ACTIVE_SOURCE_SNAPSHOT/main/payload"
  snapshot_runtime="$ACTIVE_SOURCE_SNAPSHOT/runtime"
  mkdir -p "$snapshot_payload" "$snapshot_runtime"
  /bin/cp -R "$REPO_ROOT/." "$snapshot_payload/"
  /bin/cp -p "$payload_manifest" "$ACTIVE_SOURCE_SNAPSHOT/main/payload-manifest.json"
  /bin/cp -R "$runtime_root/." "$snapshot_runtime/"

  REPO_ROOT="$snapshot_payload"
  PAIRLING_RUNTIME_PACKAGE_ROOT="$snapshot_runtime"
  PAIRLING_CONNECTD_PREBUILT="$snapshot_runtime/bin/pairling-connectd"
  if [[ -x "$snapshot_runtime/python/bin/python3" ]]; then
    PAIRLING_DAEMON_PYTHON="$snapshot_runtime/python/bin/python3"
  fi
}

stage_provider_sdks() {
  local dest="$1"
  local runtime_root="${PAIRLING_RUNTIME_PACKAGE_ROOT:-}"
  local source architecture
  [[ -n "$runtime_root" ]] || return 0
  source="$runtime_root/provider-sdks"
  if [[ -L "$source" || ! -d "$source" || -e "$dest" || -L "$dest" ]]; then
    log "ERROR: verified provider SDK source is missing/linked or its destination already exists." >&2
    WIZARD_FATAL=1
    return 1
  fi
  architecture="$("$PYTHON3_BIN" - "$runtime_root/manifest.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    architecture = json.load(handle).get("architecture")
if architecture not in {"arm64", "x64"}:
    raise SystemExit("runtime package architecture is invalid")
print(architecture)
PY
  )" || {
    log "ERROR: could not read the verified provider SDK architecture." >&2
    WIZARD_FATAL=1
    return 1
  }
  mkdir -p "$dest/node_modules"
  /bin/cp -p "$source/package.json" "$dest/package.json"
  /bin/cp -p "$source/npm-shrinkwrap.json" "$dest/npm-shrinkwrap.json"
  /bin/cp -R "$source/packages/." "$dest/node_modules/"
  if ! "$PYTHON3_BIN" "$REPO_ROOT/mac/install/verify-runtime-package-manifest.py" --installed-provider-sdks "$dest" "$architecture"; then
    log "ERROR: staged provider SDK payload failed the reviewed dependency contract." >&2
    WIZARD_FATAL=1
    return 1
  fi
}
stage_automation_helper() {
  local destination="$1"
  local runtime_root="${PAIRLING_RUNTIME_PACKAGE_ROOT:-}"
  local source

  if [[ -z "$runtime_root" ]]; then
    if launchd_skipped; then
      return 0
    fi
    log "ERROR: verified runtime package does not provide the Pairling automation helper." >&2
    WIZARD_FATAL=1
    return 1
  fi
  source="$runtime_root/automation/Pairling.app"
  if [[ -L "$source" || ! -d "$source" || -e "$destination/Pairling.app" || -L "$destination/Pairling.app" ]]; then
    log "ERROR: verified Pairling automation helper source is missing, linked, or has an unsafe destination." >&2
    WIZARD_FATAL=1
    return 1
  fi

  mkdir -p "$destination"
  /usr/bin/ditto "$source" "$destination/Pairling.app"
}





stage_provider_runtime_assets() {
  local source="$1" destination="$2"
  local verifier="$REPO_ROOT/mac/install/verify-runtime-package-manifest.py"
  if ! "$PYTHON3_BIN" "$verifier" \
    --stage-provider-runtime-assets "$source" "$destination"; then
    log "ERROR: reviewed provider runtime asset inventory could not be staged safely." >&2
    WIZARD_FATAL=1
    return 1
  fi
}


adopt_snapshot_python() {
  local candidate="${PAIRLING_DAEMON_PYTHON:-}"
  case "$candidate" in
    "$ACTIVE_SOURCE_SNAPSHOT"/*/python/bin/python3)
      if [[ "$("$candidate" -B -c 'print("pairling-python-ready")' 2>/dev/null || true)" != "pairling-python-ready" ]]; then
        log "ERROR: verified package snapshot Python is not functional: $candidate" >&2
        WIZARD_FATAL=1
        return 1
      fi
      PYTHON3_BIN="$candidate"
      ;;
  esac
}

activate_provider_sdk_environment() {
  local release_root="$1"
  local claude_sdk_root copilot_sdk_root copilot_bin copilot_arm64_bin copilot_x64_bin
  unset PAIRLING_CLAUDE_AGENT_SDK_ROOT PAIRLING_COPILOT_SDK_ROOT PAIRLING_COPILOT_BIN
  claude_sdk_root="$release_root/provider-sdks/node_modules/@anthropic-ai/claude-agent-sdk"
  copilot_sdk_root="$release_root/provider-sdks/node_modules/@github/copilot-sdk"
  copilot_arm64_bin="$release_root/provider-sdks/node_modules/@github/copilot-darwin-arm64/copilot"
  copilot_x64_bin="$release_root/provider-sdks/node_modules/@github/copilot-darwin-x64/copilot"
  [[ -e "$release_root/provider-sdks" || -L "$release_root/provider-sdks" ]] || return 0
  if [[ -L "$release_root/provider-sdks" || ! -d "$release_root/provider-sdks" || \
        -L "$claude_sdk_root" || ! -d "$claude_sdk_root" || \
        -L "$claude_sdk_root/package.json" || ! -f "$claude_sdk_root/package.json" ]]; then
    log "ERROR: installed provider SDK root is incomplete or linked: $claude_sdk_root" >&2
    return 1
  fi
  if [[ -L "$copilot_sdk_root" || ! -d "$copilot_sdk_root" || \
        -L "$copilot_sdk_root/package.json" || ! -f "$copilot_sdk_root/package.json" || \
        -L "$copilot_sdk_root/dist/cjs/index.js" || ! -f "$copilot_sdk_root/dist/cjs/index.js" ]]; then
    log "ERROR: installed Copilot SDK root is incomplete or linked: $copilot_sdk_root" >&2
    return 1
  fi
  if [[ -e "$copilot_arm64_bin" || -L "$copilot_arm64_bin" ]]; then
    if [[ -e "$copilot_x64_bin" || -L "$copilot_x64_bin" ]]; then
      log "ERROR: installed Copilot CLI contains multiple platform binaries." >&2
      return 1
    fi
    copilot_bin="$copilot_arm64_bin"
  elif [[ -e "$copilot_x64_bin" || -L "$copilot_x64_bin" ]]; then
    copilot_bin="$copilot_x64_bin"
  else
    log "ERROR: installed Copilot CLI platform binary is missing." >&2
    return 1
  fi
  if [[ -L "$copilot_bin" || ! -f "$copilot_bin" || ! -x "$copilot_bin" ]]; then
    log "ERROR: installed Copilot CLI platform binary is linked or not executable: $copilot_bin" >&2
    return 1
  fi
  PAIRLING_CLAUDE_AGENT_SDK_ROOT="$claude_sdk_root"
  PAIRLING_COPILOT_SDK_ROOT="$copilot_sdk_root"
  PAIRLING_COPILOT_BIN="$copilot_bin"
  export PAIRLING_CLAUDE_AGENT_SDK_ROOT PAIRLING_COPILOT_SDK_ROOT PAIRLING_COPILOT_BIN
}

adopt_current_release_sources() {
  if [[ -z "$RELEASE_ROOT" || -L "$RELEASE_ROOT" || ! -d "$RELEASE_ROOT" ]]; then
    log "ERROR: Pairling cannot adopt an unverified runtime source root: $RELEASE_ROOT" >&2
    return 1
  fi
  REPO_ROOT="$RELEASE_ROOT"
  if [[ -x "$RELEASE_ROOT/python/bin/python3" ]]; then
    PYTHON3_BIN="$RELEASE_ROOT/python/bin/python3"
    PAIRLING_DAEMON_PYTHON="$PYTHON3_BIN"
    export PAIRLING_DAEMON_PYTHON
  fi
  activate_provider_sdk_environment "$RELEASE_ROOT" || return 1
  cleanup_source_snapshot
  unset PAIRLING_RUNTIME_PACKAGE_ROOT PAIRLING_CONNECTD_PREBUILT
}

release_content_digest() {
  "$PYTHON3_BIN" - "$1" <<'PY'
import hashlib
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
digest = hashlib.sha256()

def file_digest(path):
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.digest()

for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    relative = path.relative_to(root).as_posix()
    if relative == "manifest.json":
        continue
    metadata = path.lstat()
    if stat.S_ISDIR(metadata.st_mode):
        kind = b"d"
        payload = b""
    elif stat.S_ISLNK(metadata.st_mode):
        kind = b"l"
        payload = os.readlink(path).encode("utf-8")
    elif stat.S_ISREG(metadata.st_mode):
        kind = b"f"
        payload = None
    else:
        raise SystemExit(f"unsupported staged runtime entry: {relative}")
    digest.update(kind + b"\0")
    digest.update(f"{stat.S_IMODE(metadata.st_mode):04o}".encode("ascii") + b"\0")
    digest.update(relative.encode("utf-8") + b"\0")
    digest.update(file_digest(path) if payload is None else hashlib.sha256(payload).digest())
print(digest.hexdigest())
PY
}

copy_release() {
  local tmp content_digest existing_digest stale_staging
  if [[ "$INSTALL_LOCK_HELD" != 1 ]]; then
    log "ERROR: refusing to stage a runtime without the Pairling install lock." >&2
    return 1
  fi
  mkdir -p "$RELEASES_ROOT"
  while IFS= read -r -d '' stale_staging; do
    remove_release_tree "$stale_staging"
  done < <(find -P "$RELEASES_ROOT" -mindepth 1 -maxdepth 1 -type d -name '.*.staging.*' -print0)
  tmp="$(mktemp -d "$RELEASES_ROOT/.${RELEASE_NAME}.staging.XXXXXX")"
  ACTIVE_STAGING_DIR="$tmp"
  GUIDED_FAILURE_SOURCE_PATH="$tmp"
  GUIDED_FAILURE_PATH="$tmp"
  snapshot_packaged_sources
  verify_payload_manifest
  verify_platform_runtime_manifest
  adopt_snapshot_python
  mkdir -p "$tmp/bin" "$tmp/automation" "$tmp/companiond" "$tmp/companiond/providers" "$tmp/companiond/integrations/aperture_cli" "$tmp/connectd" "$tmp/mac" "$tmp/mcp"
  stage_automation_helper "$tmp/automation"
  stage_provider_sdks "$tmp/provider-sdks"
  cp "$REPO_ROOT/mac/companiond/pairlingd.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairling_automation.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/safe_filesystem.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/runtime_contract.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/runtime_manifest.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/provider_runtime_assets.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/runtime_paths.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairdrop_cli.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairdrop_store.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/compose_recording_store.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairling_connectd_status.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/local_control_client.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairling_devices.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/managed_provider_sessions.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/public_diagnostics.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/local_mcp_bridge.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/llm_route.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairling_tools.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairling_assurance_policy.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairling_pairing.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairling_psk.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairling_relay_claims.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/request_proof.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/codex_approval.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pty_broker.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pty_broker_client.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pty_broker_service.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/terminal_screen_backend.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/session_events.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/session_event_log.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/session_event_ingest.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/route_registry.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/terminal_text_sanitizer.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/push_dispatcher.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/push_event_catalog.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/live_activity_publisher.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/standard_push_publisher.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/fleet_tier.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/fleet_activity_publisher.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/fd_watchdog.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/safety_monitor.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/sentinel_notifications.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/workstate_feed_contract.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/model_status_contract.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/substrate_status_contract.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/provider_setup.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/keep_awake.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/postures.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/app_attest_lan.py" "$tmp/companiond/"
  stage_app_attest_assets "$tmp/companiond"
  cp "$REPO_ROOT/mac/companiond/integrations/__init__.py" "$tmp/companiond/integrations/"
  cp "$REPO_ROOT/mac/companiond/integrations/aperture_cli/"*.py "$tmp/companiond/integrations/aperture_cli/"
  cp "$REPO_ROOT/mac/companiond/providers/"*.py "$tmp/companiond/providers/"
  # registry-data.json is the provider source of truth (SPEC-p1); a release
  # without it silently degrades to the builtin fallbacks.
  cp "$REPO_ROOT/mac/companiond/providers/"*.json "$tmp/companiond/providers/"
  stage_provider_runtime_assets "$REPO_ROOT/mac/companiond/providers" "$tmp/companiond/providers"
  cp "$REPO_ROOT/mac/mcp/phone_tools.py" "$tmp/mcp/"
  build_connectd_binary "$tmp/connectd/pairling-connectd"
  stage_vendored_python "$tmp/python"
  run_staged_psk_dependency_checks "$tmp"
  copy_runtime_source_tree "$tmp/mac" "$tmp/connectd/pairling-connectd"
  write_installed_pairling_launcher "$tmp/bin/pairling"
  chmod 755 "$tmp/bin/pairling" "$tmp/companiond/pairlingd.py" "$tmp/mcp/phone_tools.py"
  chmod 755 "$tmp/connectd/pairling-connectd"
  chmod 644 "$tmp/companiond/"*.py "$tmp/mcp/"*.py
  chmod 644 "$tmp/companiond/providers/"*.py "$tmp/companiond/providers/"*.json
  chmod 644 "$tmp/companiond/integrations/"*.py "$tmp/companiond/integrations/aperture_cli/"*.py
  chmod 755 "$tmp/companiond/pairlingd.py" "$tmp/mcp/phone_tools.py"
  clear_release_quarantine "$tmp"
  remove_python_bytecode "$tmp"
  seal_release_payload "$tmp"
  content_digest="$(release_content_digest "$tmp")"
  RELEASE_ROOT="$RELEASES_ROOT/$RELEASE_NAME-${content_digest:0:16}"
  GUIDED_FAILURE_PATH="$RELEASE_ROOT"
  if [[ -e "$RELEASE_ROOT" || -L "$RELEASE_ROOT" ]]; then
    if [[ -L "$RELEASE_ROOT" || ! -d "$RELEASE_ROOT" ]]; then
      remove_release_tree "$tmp"
      log "ERROR: immutable runtime release path is not a real directory: $RELEASE_ROOT" >&2
      WIZARD_FATAL=1
      exit 1
    fi
    existing_digest="$(release_content_digest "$RELEASE_ROOT")"
    if [[ "$existing_digest" != "$content_digest" || ! -f "$RELEASE_ROOT/manifest.json" ]]; then
      remove_release_tree "$tmp"
      log "ERROR: immutable runtime release path is present with different or incomplete bytes: $RELEASE_ROOT" >&2
      WIZARD_FATAL=1
      exit 1
    fi
    if ! verify_release_manifest "$RELEASE_ROOT" "$RELEASE_ROOT"; then
      remove_release_tree "$tmp"
      log "ERROR: existing immutable runtime release failed manifest or seal verification: $RELEASE_ROOT" >&2
      WIZARD_FATAL=1
      exit 1
    fi
    remove_release_tree "$tmp"
    ACTIVE_STAGING_DIR=""
    GUIDED_FAILURE_SOURCE_PATH=""
  else
    write_manifest "$tmp" "$RELEASE_ROOT"
    if [[ "${PAIRLING_TEST_FAIL_AFTER_STAGED_MANIFEST:-0}" == 1 ]]; then
      log "ERROR: forced test failure after staged runtime manifest" >&2
      return 1
    fi
    # The staging root must remain owner-writable until it has been published.
    # Some macOS filesystems reject renaming a non-writable source directory.
    # Record the destination first so rollback can remove only a release created
    # by this transaction if publication or any later activation step fails.
    update_install_transaction_target "$RELEASE_ROOT" "$tmp"
    if ! publish_install_transaction_target "$tmp" "$RELEASE_ROOT"; then
      log "ERROR: could not publish staged runtime: $tmp -> $RELEASE_ROOT" >&2
      return 1
    fi
    ACTIVE_STAGING_DIR=""
    GUIDED_FAILURE_SOURCE_PATH=""
    if [[ "${PAIRLING_TEST_FAIL_AFTER_RUNTIME_PUBLISH:-0}" == 1 ]]; then
      log "ERROR: forced test failure after runtime publication: $RELEASE_ROOT" >&2
      return 1
    fi
    if ! seal_release_root "$RELEASE_ROOT"; then
      log "ERROR: could not seal the published runtime release: $RELEASE_ROOT" >&2
      return 1
    fi
    if ! verify_release_manifest "$RELEASE_ROOT" "$RELEASE_ROOT"; then
      log "ERROR: published runtime failed manifest or seal verification: $RELEASE_ROOT" >&2
      WIZARD_FATAL=1
      return 1
    fi
    fsync_release_tree "$RELEASE_ROOT"
    fsync_directory "$RELEASES_ROOT"
  fi
}

copy_runtime_source_tree() {
  local mac_root="$1"
  local connectd_binary="$2"
  mkdir -p \
    "$mac_root/companiond" \
    "$mac_root/companiond/providers" \
    "$mac_root/companiond/integrations/aperture_cli" \
    "$mac_root/connectd/bin" \
    "$mac_root/install" \
    "$mac_root/mcp" \
    "$mac_root/packaging/bin"
  cp "$REPO_ROOT/mac/VERSION" "$mac_root/"
  printf '%s\n' "$REVISION" > "$mac_root/SOURCE_REVISION"
  printf '%s\n' "$BRANCH" > "$mac_root/SOURCE_BRANCH"
  printf '%s\n' "$SOURCE_DIRTY" > "$mac_root/SOURCE_DIRTY"
  cp "$REPO_ROOT/mac/companiond/"*.py "$mac_root/companiond/"
  # WS2: keep the validator and its trust anchor inside every runtime copy.
  # Staging fails closed when either asset is absent or cannot import.
  stage_app_attest_assets "$mac_root/companiond"
  cp "$REPO_ROOT/mac/companiond/providers/"*.py "$mac_root/companiond/providers/"
  cp "$REPO_ROOT/mac/companiond/providers/"*.json "$mac_root/companiond/providers/"
  stage_provider_runtime_assets "$REPO_ROOT/mac/companiond/providers" "$mac_root/companiond/providers"
  cp "$REPO_ROOT/mac/companiond/integrations/__init__.py" "$mac_root/companiond/integrations/"
  cp "$REPO_ROOT/mac/companiond/integrations/aperture_cli/"*.py "$mac_root/companiond/integrations/aperture_cli/"
  cp "$REPO_ROOT/mac/connectd/go.mod" "$mac_root/connectd/"
  cp "$REPO_ROOT/mac/connectd/go.sum" "$mac_root/connectd/"
  cp -R "$REPO_ROOT/mac/connectd/cmd" "$mac_root/connectd/"
  cp -R "$REPO_ROOT/mac/connectd/internal" "$mac_root/connectd/"
  cp "$connectd_binary" "$mac_root/connectd/bin/pairling-connectd"
  cp "$REPO_ROOT/mac/install/"*.sh "$mac_root/install/"
  cp "$REPO_ROOT/mac/install/"*.py "$mac_root/install/"
  cp "$REPO_ROOT/mac/mcp/"*.py "$mac_root/mcp/"
  cp "$REPO_ROOT/mac/packaging/bin/pairling" "$mac_root/packaging/bin/"
  cp "$REPO_ROOT/mac/packaging/pairling_attach.py" "$mac_root/packaging/"
  chmod 755 "$mac_root/connectd/bin/pairling-connectd" "$mac_root/install/"*.sh "$mac_root/mcp/phone_tools.py" "$mac_root/packaging/bin/pairling"
  chmod 644 "$mac_root/VERSION" "$mac_root/SOURCE_REVISION" "$mac_root/SOURCE_BRANCH" "$mac_root/SOURCE_DIRTY"
}

write_installed_pairling_launcher() {
  local out="$1"
  cat >"$out" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT/mac/packaging/bin/pairling" "$@"
SH
}

# Stage the vendored CPython (P3 custody) into the release tree when the npm
# shim provided one via PAIRLING_DAEMON_PYTHON pointing at …/python/bin/python3.
# Fail-closed: the interpreter must carry a valid signature, the pinned Team ID,
# and the dev.pairling.python identifier. After runtime/current is switched,
# the installer adopts that stable interpreter path for every remaining step.
stage_vendored_python() {
  local dest="$1"
  local provided="${PAIRLING_DAEMON_PYTHON:-}"
  # Only act on a vendored interpreter living under a runtime package's python/
  # tree. A bare system python3 (no sibling python/ tree) is left as-is.
  case "$provided" in
    */python/bin/python3) : ;;
    *) return 0 ;;
  esac
  local src_tree
  src_tree="$(cd "$(dirname "$provided")/.." && pwd)"
  if [[ ! -x "$src_tree/bin/python3" ]]; then
    return 0
  fi
  local required_team="${PAIRLING_CONNECTD_TEAM_ID:-965AVD34A3}"
  # Always enforce signature integrity and the dev.pairling.python identity
  # (cert-independent defense in depth). Pin the Apple Team ID unless the dev
  # switch (-) disables that one check for local ad-hoc builds.
  if ! /usr/bin/codesign --verify --strict "$src_tree/bin/python3" >/dev/null 2>&1; then
    log "ERROR: vendored python failed codesign verification; refusing to stage: $src_tree/bin/python3" >&2
    WIZARD_FATAL=1
    exit 1
  fi
  local team identifier
  identifier="$(/usr/bin/codesign -dvv "$src_tree/bin/python3" 2>&1 | sed -n 's/^Identifier=//p')"
  if [[ "$identifier" != "$PYTHON_CODESIGN_IDENTIFIER" ]]; then
    log "ERROR: vendored python identifier '${identifier:-none}' is not '$PYTHON_CODESIGN_IDENTIFIER'; refusing to stage." >&2
    WIZARD_FATAL=1
    exit 1
  fi
  if [[ "$required_team" == "-" ]]; then
    log "WARNING: vendored python Team ID pin disabled (PAIRLING_CONNECTD_TEAM_ID=-). Dev builds only."
  else
    if ! verify_developer_id_application "$src_tree/bin/python3" "$required_team"; then
      log "ERROR: vendored python is not signed with the expected Developer ID Application certificate; refusing to stage." >&2
      WIZARD_FATAL=1
      exit 1
    fi
    team="$(/usr/bin/codesign -dvv "$src_tree/bin/python3" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
    if [[ "$team" != "$required_team" ]]; then
      log "ERROR: vendored python TeamIdentifier '${team:-none}' does not match required '$required_team'; refusing to stage." >&2
      WIZARD_FATAL=1
      exit 1
    fi
  fi
  if [[ "$("$src_tree/bin/python3" -c 'print("pairling-python-ready")' 2>/dev/null || true)" != "pairling-python-ready" ]]; then
    log "ERROR: vendored python is not functional; refusing to stage: $src_tree/bin/python3" >&2
    WIZARD_FATAL=1
    exit 1
  fi
  rm -rf "$dest"
  mkdir -p "$(dirname "$dest")"
  cp -R "$src_tree" "$dest"
  chmod 755 "$dest/bin/python3" 2>/dev/null || true
  if [[ "$("$dest/bin/python3" -c 'print("pairling-python-ready")' 2>/dev/null || true)" != "pairling-python-ready" ]]; then
    log "ERROR: staged vendored python is not functional; refusing to activate: $dest/bin/python3" >&2
    WIZARD_FATAL=1
    exit 1
  fi
  log "Staged vendored CPython (daemon will run under dev.pairling.python via $CURRENT_LINK/python/bin/python3)"
}

verify_connectd_prebuilt() {
  local prebuilt="$1" required_team team
  if [[ ! -f "$prebuilt" ]]; then
    log "ERROR: PAIRLING_CONNECTD_PREBUILT points at a missing file: $prebuilt" >&2
    return 1
  fi
  required_team="${PAIRLING_CONNECTD_TEAM_ID:-965AVD34A3}"
  if [[ "$required_team" == "-" ]]; then
    log "WARNING: connectd signature verification disabled (PAIRLING_CONNECTD_TEAM_ID=-). Dev builds only."
    return 0
  fi
  if ! /usr/bin/codesign --verify --strict "$prebuilt" >/dev/null 2>&1; then
    log "ERROR: connectd binary failed codesign verification; refusing to stage: $prebuilt" >&2
    WIZARD_FATAL=1
    return 1
  fi
  if ! verify_developer_id_application "$prebuilt" "$required_team"; then
    log "ERROR: connectd binary is not signed with the expected Developer ID Application certificate; refusing to stage: $prebuilt" >&2
    WIZARD_FATAL=1
    return 1
  fi
  team="$(/usr/bin/codesign -dvv "$prebuilt" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
  if [[ "$team" != "$required_team" ]]; then
    log "ERROR: connectd binary TeamIdentifier '${team:-none}' does not match required '$required_team'; refusing to stage: $prebuilt" >&2
    WIZARD_FATAL=1
    return 1
  fi
}

build_connectd_binary() {
  local out="$1"
  # npm-delivered binary: the shim points PAIRLING_CONNECTD_PREBUILT at the
  # platform runtime package. This path is fail-closed: the binary must carry
  # a valid signature from the pinned Team ID or setup refuses to stage it.
  local prebuilt_env="${PAIRLING_CONNECTD_PREBUILT:-}"
  if [[ -n "$prebuilt_env" ]]; then
    verify_connectd_prebuilt "$prebuilt_env" || exit 1
    cp "$prebuilt_env" "$out"
    chmod 755 "$out"
    return
  fi
  local prebuilt="$REPO_ROOT/mac/connectd/bin/pairling-connectd"
  if [[ -x "$prebuilt" ]]; then
    cp "$prebuilt" "$out"
    chmod 755 "$out"
    return
  fi
  local go_bin
  go_bin="$(command -v go || true)"
  if [[ -z "$go_bin" ]]; then
    for candidate in /opt/homebrew/bin/go /usr/local/go/bin/go /usr/local/bin/go; do
      if [[ -x "$candidate" ]]; then
        go_bin="$candidate"
        break
      fi
    done
  fi
  if [[ -z "$go_bin" ]]; then
    log "ERROR: go is required to build pairling-connectd" >&2
    exit 1
  fi
  (
    cd "$REPO_ROOT/mac/connectd"
    "$go_bin" build -buildvcs=false -trimpath \
      -ldflags "-s -w -buildid= -X main.buildVersion=$VERSION -X main.buildSourceRevision=$REVISION -X main.buildSourceDirty=$SOURCE_DIRTY" \
      -o "$out" ./cmd/pairling-connectd
  )
}

fsync_directory() {
  if [[ -n "${PAIRLING_TEST_FAIL_FSYNC_DIRECTORY:-}" && "${PAIRLING_TEST_FAIL_FSYNC_DIRECTORY}" == "$1" ]]; then
    log "ERROR: forced test failure while syncing directory: $1" >&2
    return 1
  fi
  "${CONTROL_PYTHON_BIN:-$PYTHON3_BIN}" - "$1" <<'PY'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

fsync_release_tree() {
  "$PYTHON3_BIN" - "$1" <<'PY'
import fcntl
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
if root.is_symlink() or not root.is_dir():
    raise SystemExit(f"release tree is not a real directory: {root}")

def flush(descriptor: int) -> None:
    if sys.platform == "darwin":
        try:
            fcntl.fcntl(descriptor, 51)  # F_FULLFSYNC
            return
        except OSError:
            pass
    os.fsync(descriptor)

paths = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
for path in paths:
    metadata = path.lstat()
    if stat.S_ISREG(metadata.st_mode):
        descriptor = os.open(path, os.O_RDONLY)
        try:
            flush(descriptor)
        finally:
            os.close(descriptor)
    elif not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit(f"unsupported release entry during durability flush: {path}")
for path in sorted(
    [root, *(item for item in paths if item.is_dir())],
    key=lambda item: len(item.parts),
    reverse=True,
):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        flush(descriptor)
    finally:
        os.close(descriptor)
PY
}

write_manifest() {
  local root="$1" recorded_install_root="${2:-$1}"
  "$PYTHON3_BIN" - "$MANIFEST_REPO_PATH" "$root" "$recorded_install_root" "$VERSION" "$REVISION" "$BRANCH" "$SOURCE_DIRTY" "$APP_SUPPORT" "$LOGS_ROOT" "$DEVICES_DB" "$PAIRLING_RUNTIME_PORT" "$PAIRDROP_ROOT" <<'PY'
import os
import getpass
import hashlib
import json
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

repo_root, scan_root, install_root, version, revision, branch, dirty, app_support, logs_root, devices_db, port, pairdrop_root = sys.argv[1:]
sys.path.insert(0, str(Path(repo_root) / "mac" / "companiond"))
from runtime_manifest import PROVIDER_RUNTIME_ASSET_RELATIVE_PATHS
root = Path(scan_root)
files = []
directories = []

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def visit(directory: Path) -> None:
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        rel = path.relative_to(root).as_posix()
        if rel == "manifest.json":
            continue
        if path.name == "__pycache__" or path.suffix == ".pyc":
            raise RuntimeError(f"forbidden Python bytecode in staged runtime: {rel}")
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError(f"symlinks are forbidden in staged runtime releases: {rel}")
        if stat.S_ISDIR(metadata.st_mode):
            directories.append({
                "path": rel,
                "mode": f"{stat.S_IMODE(metadata.st_mode) & ~0o222:04o}",
            })
            visit(path)
        elif stat.S_ISREG(metadata.st_mode):
            files.append({
                "path": rel,
                "kind": "file",
                "sha256": sha256_file(path),
                "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            })
        else:
            raise RuntimeError(f"unsupported entry in staged runtime: {rel}")

visit(root)

now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
manifest = {
    "schema_version": 2,
    "root_mode": f"{stat.S_IMODE(root.lstat().st_mode) & ~0o222:04o}",
    "manifest_mode": "0444",
    "runtime_name": "pairlingd",
    "runtime_version": version,
    "contract_version": "pairling-runtime-v1",
    "source_revision": revision,
    "source_branch": branch,
    "source_dirty": dirty == "true",
    "built_at": now,
    "installed_at": now,
    "installed_by": getpass.getuser(),
    "repo_path": repo_root,
    "install_root": install_root,
    "current_symlink": str(Path(install_root).parent.parent / "current"),
    "runtime": {
        "port": int(port),
        "auth": "per-device-scoped-bearer",
        "token_registry": devices_db,
    },
    "launchd": {
        "daemon_label": "dev.pairling.companiond",
        "ptybroker_label": "dev.pairling.ptybroker",
        "connectd_label": "dev.pairling.connectd",
    },
    "paths": {
        "app_support": app_support,
        "logs": logs_root,
        "pair_records": str(Path(app_support) / "pair"),
        "pairdrop": pairdrop_root,
    },
    "migration": {
        "legacy_port": 7723,
        "public_v1_dual_bind": False,
    },
    "packaging": {
        "helper_bundle_id": "dev.pairling.helper",
        "homebrew_tap": "pairling-app/tap",
        "homebrew_cask": "pairling-helper",
    },
    "provider_runtime_assets": list(PROVIDER_RUNTIME_ASSET_RELATIVE_PATHS),
    "directories": directories,
    "files": files,
}
manifest_path = root / "manifest.json"
temporary_path = root / f".manifest.json.tmp-{os.getpid()}"
with temporary_path.open("x", encoding="utf-8") as handle:
    handle.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    handle.flush()
    os.fsync(handle.fileno())
os.replace(temporary_path, manifest_path)
os.chmod(manifest_path, 0o444, follow_symlinks=False)
descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

switch_current() {
  if [[ -L "$CURRENT_LINK" && "$(readlink "$CURRENT_LINK")" == "$RELEASE_ROOT" ]]; then
    return
  fi
  if [[ -L "$CURRENT_LINK" ]]; then
    local old
    old="$(readlink "$CURRENT_LINK")"
    if [[ -n "$old" ]]; then
      atomic_symlink_switch "$old" "$PREVIOUS_LINK"
    fi
  fi
  atomic_symlink_switch "$RELEASE_ROOT" "$CURRENT_LINK"
}

install_mcp_adapter_shim() {
  local generated
  generated="$(mktemp "${TMPDIR:-/tmp}/pairling-mcp-shim.XXXXXX")"
  "$PYTHON3_BIN" - "$generated" "$CURRENT_LINK/mcp/phone_tools.py" <<'PY'
import os
import sys
from pathlib import Path

shim = Path(sys.argv[1])
adapter = Path(sys.argv[2])
shim.write_text(f'''#!/usr/bin/env python3
"""Installed shim for the Pairling daemon-first phone-tools MCP server."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

PAIRLING_MCP_ADAPTER = Path({str(adapter)!r})

if not PAIRLING_MCP_ADAPTER.is_file():
    print(
        f"FATAL: Pairling MCP adapter is missing at {{PAIRLING_MCP_ADAPTER}}. "
        "Run Pairling setup or restore the runtime install.",
        file=sys.stderr,
    )
    raise SystemExit(1)

runpy.run_path(str(PAIRLING_MCP_ADAPTER), run_name="__main__")
''')
os.chmod(shim, 0o755)
PY
  install_managed_file "$generated" "$MCP_SERVER_SHIM" 0755
  rm -f "$generated"
}

install_shell_wrapper() {
  local target="$USER_PAIRLING_WRAPPER"
  local tmp trusted_shim
  trusted_shim="${PAIRLING_TRUSTED_SHIM:-}"
  tmp="$(mktemp "${TMPDIR:-/tmp}/pairling-shell-wrapper.XXXXXX")"
  {
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail'
    printf 'TRUSTED_NPM_SHIM=%q\n\n' "$trusted_shim"
    cat <<'SH'
if [[ -n "${PAIRLING_REPO_ROOT:-}" ]]; then
  exec "$PAIRLING_REPO_ROOT/mac/packaging/bin/pairling" "$@"
fi

trusted_npm_pairling_shim() {
  local wrapper_path="$1"
  local candidate="$TRUSTED_NPM_SHIM"
  local canonical_dir canonical owner current_uid mode
  [[ "$candidate" == /* && -f "$candidate" && -x "$candidate" && "$candidate" != "$wrapper_path" ]] || return 1
  canonical_dir="$(cd "$(dirname "$candidate")" 2>/dev/null && pwd -P)" || return 1
  canonical="$canonical_dir/$(basename "$candidate")"
  [[ "$candidate" == "$canonical" ]] || return 1
  owner="$(/usr/bin/stat -f '%u' "$candidate" 2>/dev/null)" || return 1
  current_uid="$(/usr/bin/id -u)"
  [[ "$owner" == "0" || "$owner" == "$current_uid" ]] || return 1
  mode="$(/usr/bin/stat -f '%OLp' "$candidate" 2>/dev/null)" || return 1
  (( (8#$mode & 0022) == 0 )) || return 1
  "$candidate" --shim-print-env >/dev/null 2>&1 || return 1
  printf '%s\n' "$candidate"
}

case "${1:-}" in
  setup|install|update|upgrade)
    WRAPPER_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    if NPM_PAIRLING="$(trusted_npm_pairling_shim "$WRAPPER_PATH")"; then
      exec "$NPM_PAIRLING" "$@"
    fi
    ;;
esac

APP_SUPPORT="${PAIRLING_APP_SUPPORT_ROOT:-${COMPANION_APP_SUPPORT_ROOT:-$HOME/Library/Application Support/Pairling}}"
RUNTIME_PAIRLING="$APP_SUPPORT/runtime/current/bin/pairling"
if [[ -x "$RUNTIME_PAIRLING" ]]; then
  exec "$RUNTIME_PAIRLING" "$@"
fi

printf 'Pairling runtime command is not installed. Run:\n  npm install -g pairling\n  pairling setup\nor use a repo-local mac/packaging/bin/pairling.\n' >&2
exit 127
SH
  } >"$tmp"
  chmod 755 "$tmp"
  install_managed_file "$tmp" "$target" 0755
  rm -f "$tmp"
}

render_plists() {
  # Prefer the staged vendored interpreter whenever it exists, so start/
  # rollback (which don't re-stage) also run the daemon under dev.pairling.python.
  local daemon_python="$PYTHON3_BIN" installed_release_root=""
  if [[ -n "${RELEASE_ROOT:-}" && ! -L "$RELEASE_ROOT" && -d "$RELEASE_ROOT" ]]; then
    installed_release_root="$RELEASE_ROOT"
  elif [[ -e "$CURRENT_LINK" || -L "$CURRENT_LINK" ]]; then
    installed_release_root="$(cd "$CURRENT_LINK" 2>/dev/null && pwd -P)" || {
      log "ERROR: Pairling current runtime link cannot be resolved for provider activation." >&2
      return 1
    }
  fi
  if [[ -n "$installed_release_root" ]]; then
    activate_provider_sdk_environment "$installed_release_root" || return 1
  else
    unset PAIRLING_CLAUDE_AGENT_SDK_ROOT PAIRLING_COPILOT_SDK_ROOT PAIRLING_COPILOT_BIN
  fi
  if [[ -x "$CURRENT_LINK/python/bin/python3" ]]; then
    daemon_python="$CURRENT_LINK/python/bin/python3"
  fi
  local -a render_args=(
    --current-root "$CURRENT_LINK"
    --logs-root "$LOGS_ROOT"
    --output-dir "$PLIST_BUILD_DIR"
    --daemon-python "$daemon_python"
    --pairdrop-root "$PAIRDROP_ROOT"
  )
  # SPEC-p5 §2.1: `pairling setup --ssh` (or a prior enable) renders connectd
  # with the loopback SSH-tunnel gateway on. The flag persists in the
  # LaunchAgent env, so a plain `setup` re-run keeps a previously enabled
  # gateway unless the operator passes --no-ssh.
  if [ "${SSH_GATEWAY_ENABLED:-0}" = "1" ]; then
    render_args+=(--ssh-gateway)
  fi
  "$PYTHON3_BIN" "$REPO_ROOT/mac/install/render-launchd.py" "${render_args[@]}"
}

unload_launch_agent() {
  local label="$1" domain="gui/$(id -u)" target attempts=0
  target="$domain/$label"
  if launchctl print "$target" >/dev/null 2>&1; then
    if ! launchctl bootout "$target"; then
      if launchctl print "$target" >/dev/null 2>&1; then
        log "ERROR: could not unload $label before activation." >&2
        return 1
      fi
    fi
    while launchctl print "$target" >/dev/null 2>&1; do
      attempts="$((attempts + 1))"
      if [[ "$attempts" -ge 50 ]]; then
        log "ERROR: $label remained loaded after bootout." >&2
        return 1
      fi
      sleep 0.1
    done
  fi
}

reload_launch_agent() {
  local label="$1" plist="$2" domain="gui/$(id -u)" target
  target="$domain/$label"
  unload_launch_agent "$label" || return 1
  if ! launchctl bootstrap "$domain" "$plist"; then
    log "ERROR: could not bootstrap $label from $plist." >&2
    return 1
  fi
  if ! launchctl print "$target" >/dev/null 2>&1; then
    log "ERROR: $label was not registered after bootstrap." >&2
    return 1
  fi
  if ! launchctl kickstart -k "$target"; then
    log "ERROR: could not start $label after bootstrap." >&2
    return 1
  fi
}

install_managed_file() {
  local source="$1" destination="$2" mode="$3"
  mkdir -p "$(dirname "$destination")"
  "$PYTHON3_BIN" - "$source" "$destination" "$mode" <<'PY'
import os
import secrets
import shutil
import sys

from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
mode = int(sys.argv[3], 8)
temporary = destination.parent / f".{destination.name}.pairling-{os.getpid()}-{secrets.token_hex(8)}"
try:
    with source.open("rb") as reader, temporary.open("xb") as writer:
        shutil.copyfileobj(reader, writer, 1024 * 1024)
        writer.flush()
        os.fsync(writer.fileno())
    os.chmod(temporary, mode, follow_symlinks=False)
    os.replace(temporary, destination)
    descriptor = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
finally:
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
PY
}
automation_helper_architecture() {
  local app="$1"
  local executable="$app/Contents/MacOS/PairlingAutomation"
  local architecture

  if [[ -L "$app" || ! -d "$app" || -L "$executable" || ! -f "$executable" ]]; then
    log "ERROR: Pairling automation helper bundle is missing or linked." >&2
    return 1
  fi
  architecture="$(/usr/bin/lipo -archs "$executable" 2>/dev/null || true)"
  case "$architecture" in
    arm64|x86_64)
      printf '%s\n' "$architecture"
      ;;
    *)
      log "ERROR: Pairling automation helper has an unsupported architecture." >&2
      return 1
      ;;
  esac
}

install_stable_automation_helper() {
  local source="$RELEASE_ROOT/automation/Pairling.app"
  local lifecycle="$RELEASE_ROOT/mac/install/automation_helper_lifecycle.py"
  local architecture

  if launchd_skipped; then
    return 0
  fi
  architecture="$(automation_helper_architecture "$source")" || return 1
  if [[ -L "$lifecycle" || ! -f "$lifecycle" ]]; then
    log "ERROR: Pairling automation helper lifecycle module is missing or linked." >&2
    return 1
  fi
  install_managed_file "$PLIST_BUILD_DIR/$AUTOMATION_LAUNCH_AGENT_LABEL.plist" "$AUTOMATION_USER_PLIST" 0644
  if is_dry_run; then
    log "dry-run: would install $AUTOMATION_APP_PATH"
    return 0
  fi
  "$PYTHON3_BIN" "$RELEASE_ROOT/mac/install/automation_helper_lifecycle.py" install \
    --source "$RELEASE_ROOT/automation/Pairling.app" \
    --app-support "$APP_SUPPORT" \
    --architecture "$architecture" \
    --launch-agent-plist "$AUTOMATION_USER_PLIST"
  AUTOMATION_AGENT_ACTIVATED=1
}

start_automation_agent() {
  local lifecycle="$RELEASE_ROOT/mac/install/automation_helper_lifecycle.py"
  local architecture

  if launchd_skipped || [[ "$AUTOMATION_AGENT_ACTIVATED" == 1 ]]; then
    return 0
  fi
  architecture="$(automation_helper_architecture "$AUTOMATION_APP_PATH")" || return 1
  if [[ -L "$lifecycle" || ! -f "$lifecycle" ]]; then
    log "ERROR: Pairling automation helper lifecycle module is missing or linked." >&2
    return 1
  fi
  "$PYTHON3_BIN" "$lifecycle" verify \
    --bundle "$AUTOMATION_APP_PATH" \
    --architecture "$architecture"
  install_managed_file "$PLIST_BUILD_DIR/$AUTOMATION_LAUNCH_AGENT_LABEL.plist" "$AUTOMATION_USER_PLIST" 0644
  if is_dry_run; then
    log "dry-run: would start $AUTOMATION_LAUNCH_AGENT_LABEL"
    return 0
  fi
  reload_launch_agent "$AUTOMATION_LAUNCH_AGENT_LABEL" "$AUTOMATION_USER_PLIST"
  AUTOMATION_AGENT_ACTIVATED=1
}

terminal_permission_setup_command() {
  local operation="$1"
  local setup="$RELEASE_ROOT/mac/install/terminal_permission_setup.py"

  if [[ -L "$setup" || ! -f "$setup" ]]; then
    log "ERROR: Pairling Terminal permission setup module is missing or linked." >&2
    return 1
  fi
  "$PYTHON3_BIN" "$setup" "$operation" --app-support "$APP_SUPPORT"
}

terminal_permission_response_is_ready() {
  "$PYTHON3_BIN" - "$1" <<'PY'
import json
import sys

try:
    value = json.loads(sys.argv[1])
    capability = value["terminal_capability"]
except (KeyError, TypeError, ValueError):
    raise SystemExit(1)
raise SystemExit(0 if capability.get("terminal_control_ready") is True else 1)
PY
}

terminal_permission_response_reasons() {
  "$PYTHON3_BIN" - "$1" <<'PY'
import json
import sys

try:
    value = json.loads(sys.argv[1])
    capability = value["terminal_capability"]
    reasons = capability.get("blocking_reasons", [])
except (KeyError, TypeError, ValueError):
    reasons = []
if isinstance(reasons, list):
    print("; ".join(str(reason) for reason in reasons if isinstance(reason, str)))
PY
}

request_terminal_permissions() {
  local response reasons interval timeout step waited=0
  interval="${PAIRLING_TERMINAL_PERMISSION_POLL_INTERVAL:-2}"
  timeout="${PAIRLING_TERMINAL_PERMISSION_WAIT_SECONDS:-300}"
  case "$interval" in
    ''|*[!0-9]*) interval=2 ;;
  esac
  case "$timeout" in
    ''|*[!0-9]*) timeout=300 ;;
  esac
  [[ "$interval" -lt 1 ]] && interval=2
  step="$interval"

  stage_note "Pairling Connect uses its private embedded route. Remote Login, Screen Sharing, and Remote Management are not required and Pairling will not enable them."
  stage_note "Pairling needs one-time permission for Accessibility and to control Apple Terminal."
  stage_note "macOS will name Pairling in the permission prompt."
  if ! response="$(terminal_permission_setup_command request)"; then
    log "ERROR: Pairling could not request Mac permissions." >&2
    return 1
  fi
  if terminal_permission_response_is_ready "$response"; then
    stage_note "Pairling Accessibility, Terminal control, and the harmless Terminal probe are ready."
    return 0
  fi

  reasons="$(terminal_permission_response_reasons "$response")"
  stage_note "Finish Pairling permissions in System Settings, then return here. Pairling will check again without showing another prompt."
  [[ -z "$reasons" ]] || stage_note "$reasons"
  if [[ ! -t 0 ]]; then
    log "ERROR: Mac permissions are required. Finish Pairling setup in a local Terminal, then rerun pairling setup." >&2
    return 1
  fi

  while [[ "$waited" -lt "$timeout" ]]; do
    sleep "$interval"
    waited=$((waited + step))
    if ! response="$(terminal_permission_setup_command probe)"; then
      log "ERROR: Pairling could not recheck Mac permissions." >&2
      return 1
    fi
    if terminal_permission_response_is_ready "$response"; then
      stage_note "Pairling Accessibility, Terminal control, and the harmless Terminal probe are ready."
      return 0
    fi
  done

  log "ERROR: Mac permissions are still required. Finish Pairling setup locally, then rerun pairling setup." >&2
  return 1
}

stop_automation_agent() {
  if is_dry_run; then
    log "dry-run: would stop $AUTOMATION_LAUNCH_AGENT_LABEL"
    return 0
  fi
  launchctl bootout "gui/$(id -u)/$AUTOMATION_LAUNCH_AGENT_LABEL" >/dev/null 2>&1 || true
  launchctl bootout "gui/$(id -u)" "$AUTOMATION_USER_PLIST" >/dev/null 2>&1 || true
  AUTOMATION_AGENT_ACTIVATED=0
}

automation_helper_lifecycle_path() {
  local release_lifecycle="$RELEASE_ROOT/mac/install/automation_helper_lifecycle.py"
  if [[ -n "$RELEASE_ROOT" && -f "$release_lifecycle" && ! -L "$release_lifecycle" ]]; then
    printf '%s\n' "$release_lifecycle"
  else
    printf '%s\n' "$REPO_ROOT/mac/install/automation_helper_lifecycle.py"
  fi
}

prepare_automation_helper_promotion() {
  if is_dry_run || launchd_skipped; then return 0; fi
  local lifecycle
  lifecycle="$(automation_helper_lifecycle_path)"
  stop_automation_agent
  "$PYTHON3_BIN" "$lifecycle" prepare-promotion --app-support "$APP_SUPPORT"
}

restore_automation_helper_promotion() {
  if is_dry_run || launchd_skipped; then return 0; fi
  local lifecycle
  lifecycle="$(automation_helper_lifecycle_path)"
  stop_automation_agent
  "$PYTHON3_BIN" "$lifecycle" restore-promotion --app-support "$APP_SUPPORT"
}

commit_automation_helper_promotion() {
  if is_dry_run || launchd_skipped; then return 0; fi
  local lifecycle
  lifecycle="$(automation_helper_lifecycle_path)"
  "$PYTHON3_BIN" "$lifecycle" commit-promotion --app-support "$APP_SUPPORT"
}

migrate_verified_legacy_injector() {
  if is_dry_run || launchd_skipped; then return 0; fi
  local lifecycle result
  lifecycle="$(automation_helper_lifecycle_path)"
  result="$("$PYTHON3_BIN" "$lifecycle" migrate-legacy \
    --legacy-app "$LEGACY_INJECTOR_APP" \
    --app-support "$APP_SUPPORT")" || return 1
  case "$result" in
    *'"outcome":"migrated"'*)
      log "Archived the verified legacy ClaudeInjector wrapper."
      ;;
    *'"outcome":"legacy_helper_requires_manual_review"'*)
      log "Legacy ClaudeInjector.app was not recognized and was left untouched for manual review." >&2
      ;;
  esac
}


start_user_agent() {
  install_managed_file "$PLIST_BUILD_DIR/$PAIRLING_DAEMON_LABEL.plist" "$USER_PLIST" 0644
  if is_dry_run; then
    log "dry-run: rendered $USER_PLIST"
    return
  fi
  if launchd_skipped; then return 0; fi
  reload_launch_agent "$PAIRLING_DAEMON_LABEL" "$USER_PLIST"
}

start_connectd_agent() {
  install_managed_file "$PLIST_BUILD_DIR/$PAIRLING_CONNECTD_LABEL.plist" "$CONNECTD_USER_PLIST" 0644
  if is_dry_run; then
    log "dry-run: rendered $CONNECTD_USER_PLIST"
    return
  fi
  if launchd_skipped; then return 0; fi
  reload_launch_agent "$PAIRLING_CONNECTD_LABEL" "$CONNECTD_USER_PLIST"
}

ptybroker_live_session_count() {
  local status_json
  if status_json="$(ptybroker_status_json 2>/dev/null)"; then
    "$PYTHON3_BIN" - "$status_json" <<'PY'
import json
import sys

def load_json_arg(raw):
    text = str(raw or "").strip()
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "{[":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
            return value
        except json.JSONDecodeError:
            continue
    return {}

payload = load_json_arg(sys.argv[1])
status = payload.get("status") if isinstance(payload.get("status"), dict) else {}
print(status.get("live_session_count", "unknown"))
PY
  else
    printf '%s\n' "unknown"
  fi
}

ptybroker_status_json() {
  "$PYTHON3_BIN" - "$CURRENT_LINK" <<'PY'
import json
import sys
from pathlib import Path

current = Path(sys.argv[1])
sys.path.insert(0, str(current / "companiond"))
from pty_broker_client import PTYBrokerClient, ensure_pty_broker_token

companion = Path.home() / ".claude" / "companion"
client = PTYBrokerClient(companion / "pty-broker.sock", ensure_pty_broker_token(companion), timeout=1.0)
print(json.dumps({"ok": True, "status": client.status()}, sort_keys=True))
PY
}

ptybroker_desired_revision() {
  "$PYTHON3_BIN" - "$CURRENT_LINK" <<'PY'
import json
import sys
from pathlib import Path

current = Path(sys.argv[1])
for path in [current / "manifest.json", current / "mac" / "SOURCE_REVISION", current / "SOURCE_REVISION"]:
    try:
        if path.name == "manifest.json":
            print(json.loads(path.read_text()).get("source_revision") or "")
        else:
            print(path.read_text().strip())
        raise SystemExit(0)
    except FileNotFoundError:
        continue
    except Exception:
        continue
print("")
PY
}

ptybroker_live_revision() {
  "$PYTHON3_BIN" - "${1:-{}}" <<'PY'
import json
import sys

def load_json_arg(raw):
    text = str(raw or "").strip()
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "{[":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
            return value
        except json.JSONDecodeError:
            continue
    return {}

payload = load_json_arg(sys.argv[1])
status = payload.get("status") if isinstance(payload.get("status"), dict) else payload
print(status.get("source_revision") or "")
PY
}

ptybroker_deployment_state_json() {
  "$PYTHON3_BIN" - "$REPO_ROOT/mac/companiond" "${2:-$CURRENT_LINK}" "${1:-{}}" <<'PY'
import json
import sys
from pathlib import Path

module_root = Path(sys.argv[1])
current = Path(sys.argv[2])
sys.path.insert(0, str(module_root))
from runtime_manifest import classify_ptybroker_identity, ptybroker_payload_sha256

def load_json_arg(raw):
    text = str(raw or "").strip()
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "{[":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
            return value
        except json.JSONDecodeError:
            continue
    return {}

payload = load_json_arg(sys.argv[3])
live = payload.get("status") if isinstance(payload, dict) and isinstance(payload.get("status"), dict) else payload

def read_revision(root: Path):
    for path in [root / "manifest.json", root / "mac" / "SOURCE_REVISION", root / "SOURCE_REVISION"]:
        try:
            if path.name == "manifest.json":
                return json.loads(path.read_text()).get("source_revision")
            value = path.read_text().strip()
            return value or None
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return None

desired_root = current.resolve()
desired = {
    "runtime_root": str(desired_root),
    "script_path": str(desired_root / "companiond" / "pty_broker_service.py"),
    "source_revision": read_revision(desired_root),
    "protocol_version": 2,
    "code_version": "pty-broker-v2",
    "payload_sha256": ptybroker_payload_sha256(desired_root),
}
state, reasons = classify_ptybroker_identity(live, desired)
print(json.dumps({
    "state": state,
    "restart_deferred": state == "stale_deferred",
    "reasons": reasons,
    "desired": desired,
    "live": live,
}, sort_keys=True))
PY
}

ptybroker_report_deferred_restart() {
  local state_json
  state_json="$(ptybroker_deployment_state_json "$1")"
  "$PYTHON3_BIN" - "$state_json" <<'PY'
import json
import sys

def load_json_arg(raw):
    text = str(raw or "").strip()
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "{[":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
            return value
        except json.JSONDecodeError:
            continue
    return {}

state = load_json_arg(sys.argv[1])
if state.get("state") == "incompatible":
    reasons = ", ".join(str(item) for item in state.get("reasons") or []) or "invalid status"
    print(
        "ERROR: ptybroker status is incompatible with this runtime; "
        f"live PTYs were preserved; reasons={reasons}",
        file=sys.stderr,
    )
    raise SystemExit(1)
if state.get("state") != "stale_deferred":
    raise SystemExit(0)
live = state.get("live") if isinstance(state.get("live"), dict) else {}
desired = state.get("desired") if isinstance(state.get("desired"), dict) else {}
print(
    "WARNING: ptybroker is running a different verified payload; normal install preserved live PTYs; "
    "broker restart is deferred; "
    f"live_source_revision={live.get('source_revision')} "
    f"desired_source_revision={desired.get('source_revision')} "
    f"live_pid={live.get('pid')} "
    f"live_session_count={live.get('live_session_count')}"
)
PY
}

ptybroker_state_field() {
  "$PYTHON3_BIN" - "$1" "$2" <<'PY'
import json
import sys

def load_json_arg(raw):
    text = str(raw or "").strip()
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "{[":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
            return value
        except json.JSONDecodeError:
            continue
    return {}

payload = load_json_arg(sys.argv[1])
value = payload
for part in sys.argv[2].split("."):
    if isinstance(value, dict):
        value = value.get(part)
    else:
        value = None
print("" if value is None else value)
PY
}

ptybroker_restart_blocker_count() {
  "$PYTHON3_BIN" - "$1" "$2" <<'PY'
import json
import sys

raw = str(sys.argv[1] or "").strip()
payload = None
decoder = json.JSONDecoder()
for index, char in enumerate(raw):
    if char not in "{[":
        continue
    try:
        payload, _ = decoder.raw_decode(raw[index:])
        break
    except json.JSONDecodeError:
        continue
if not isinstance(payload, dict):
    raise SystemExit(1)
value = payload
for part in sys.argv[2].split(".") if sys.argv[2] else []:
    if not isinstance(value, dict):
        raise SystemExit(1)
    value = value.get(part)
if not isinstance(value, dict):
    raise SystemExit(1)

blockers = value.get("restart_blocker_count")
if type(blockers) is int and blockers >= 0:
    print(blockers)
    raise SystemExit(0)
raise SystemExit(1)
PY
}

require_idle_ptybroker_for_runtime_change() {
  if launchd_skipped || ! launchctl print "gui/$(id -u)/$PAIRLING_PTYBROKER_LABEL" >/dev/null 2>&1; then
    return 0
  fi
  local status_json state_json state live_count blocker_count
  if ! status_json="$(ptybroker_status_json 2>/dev/null)"; then
    log "ERROR: the loaded PTY broker cannot prove whether it owns live sessions; current runtime was not changed." >&2
    return 1
  fi
  state_json="$(ptybroker_deployment_state_json "$status_json" "$RELEASE_ROOT")"
  state="$(ptybroker_state_field "$state_json" "state")"
  live_count="$(ptybroker_state_field "$state_json" "live.live_session_count")"
  if ! blocker_count="$(ptybroker_restart_blocker_count "$state_json" "live")"; then
    log "ERROR: the loaded PTY broker returned an invalid restart-blocker count; current runtime was not changed." >&2
    return 1
  fi
  if [[ "$blocker_count" != "0" && "$state" != "current" ]]; then
    log "ERROR: Pairling cannot update the PTY broker while it owns active work (restart_blocker_count=$blocker_count live_session_count=${live_count:-unknown} live_pid=$(ptybroker_state_field "$status_json" "status.pid")). Finish or close those sessions, then run setup again. The current runtime was not changed." >&2
    return 1
  fi
}

ensure_ptybroker_agent() {
  mkdir -p "$HOME/Library/LaunchAgents"
  local rendered="$PLIST_BUILD_DIR/$PAIRLING_PTYBROKER_LABEL.plist"
  local changed=0
  if [[ -L "$PTYBROKER_USER_PLIST" || ! -f "$PTYBROKER_USER_PLIST" ]] || ! cmp -s "$rendered" "$PTYBROKER_USER_PLIST"; then
    changed=1
    install_managed_file "$rendered" "$PTYBROKER_USER_PLIST" 0644
  fi
  if is_dry_run; then
    if [[ "$changed" == "1" ]]; then
      log "dry-run: rendered $PTYBROKER_USER_PLIST"
    else
      log "dry-run: $PTYBROKER_USER_PLIST unchanged"
    fi
    return
  fi
  if launchd_skipped; then return 0; fi
  if ! launchctl print "gui/$(id -u)/$PAIRLING_PTYBROKER_LABEL" >/dev/null 2>&1; then
    reload_launch_agent "$PAIRLING_PTYBROKER_LABEL" "$PTYBROKER_USER_PLIST"
    return
  fi
  local status_json state_json state live_count blocker_count live_pid
  if status_json="$(ptybroker_status_json 2>/dev/null)"; then
    state_json="$(ptybroker_deployment_state_json "$status_json")"
    state="$(ptybroker_state_field "$state_json" "state")"
    live_count="$(ptybroker_state_field "$state_json" "live.live_session_count")"
    blocker_count="$(ptybroker_state_field "$state_json" "live.restart_blocker_count")"
    live_pid="$(ptybroker_state_field "$state_json" "live.pid")"
    if ! blocker_count="$(ptybroker_restart_blocker_count "$state_json" "live")"; then
      log "ERROR: ptybroker status did not prove its restart blockers." >&2
      return 1
    fi
    if [[ ( "$state" == "stale_deferred" || "$state" == "incompatible" ) && "$blocker_count" == "0" ]]; then
      local handover_state="$state"
      sleep 0.1
      status_json="$(ptybroker_status_json)"
      state_json="$(ptybroker_deployment_state_json "$status_json")"
      state="$(ptybroker_state_field "$state_json" "state")"
      live_count="$(ptybroker_state_field "$state_json" "live.live_session_count")"
      blocker_count="$(ptybroker_state_field "$state_json" "live.restart_blocker_count")"
      if ! blocker_count="$(ptybroker_restart_blocker_count "$state_json" "live")"; then
        log "ERROR: ptybroker status did not prove its restart blockers on the confirmation sample." >&2
        return 1
      fi
      if [[ "$state" != "$handover_state" || "$blocker_count" != "0" || "$(ptybroker_state_field "$state_json" "live.pid")" != "$live_pid" ]]; then
        log "ERROR: ptybroker stopped being safely idle before handover; preserving it and refusing activation: $state_json" >&2
        return 1
      fi
      log "Replacing idle non-current ptybroker now (state=$handover_state live_pid=$live_pid restart_blocker_count=0)"
      reload_launch_agent "$PAIRLING_PTYBROKER_LABEL" "$PTYBROKER_USER_PLIST"
      local attempt new_pid
      state=""
      for attempt in $(seq 1 50); do
        if status_json="$(ptybroker_status_json 2>/dev/null)"; then
          state_json="$(ptybroker_deployment_state_json "$status_json")"
          state="$(ptybroker_state_field "$state_json" "state")"
          new_pid="$(ptybroker_state_field "$state_json" "live.pid")"
          if [[ "$state" == "current" && "$new_pid" != "$live_pid" ]]; then
            break
          fi
        fi
        sleep 0.1
      done
      if [[ "$state" != "current" || -z "${new_pid:-}" || "$new_pid" == "$live_pid" ]]; then
        log "ERROR: idle ptybroker replacement did not activate a new current process: ${state_json:-unreachable}" >&2
        return 1
      fi
      log "Activated current ptybroker after an idle handover"
      return
    else
      ptybroker_report_deferred_restart "$status_json"
    fi
  else
    log "WARNING: ptybroker status unreachable_socket; normal install preserved live PTYs but broker freshness is unknown; broker restart is deferred"
  fi
  if [[ "$changed" == "1" ]]; then
    local live_count
    live_count="$(ptybroker_live_session_count)"
    log "ptybroker plist changed but broker is already loaded; preserving PTYs and deferring broker restart (live_sessions=$live_count)"
  fi
  if [[ ! -S "$HOME/.claude/companion/pty-broker.sock" ]]; then
    launchctl kickstart "gui/$(id -u)/$PAIRLING_PTYBROKER_LABEL" >/dev/null 2>&1 || true
  fi
}

reconcile_ptybroker() {
  local expected_pid=""
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --expected-pid)
        expected_pid="${2:-}"
        shift 2
        ;;
      *)
        log "ERROR: unknown reconcile-ptybroker option: $1" >&2
        return 2
        ;;
    esac
  done
  if [[ -n "$expected_pid" && ! "$expected_pid" =~ ^[0-9]+$ ]]; then
    log "ERROR: --expected-pid must be a positive process id." >&2
    return 2
  fi
  trap install_mutation_on_exit EXIT
  acquire_install_lock
  recover_pending_install_transaction
  ensure_state
  render_plists
  install_managed_file "$PLIST_BUILD_DIR/$PAIRLING_PTYBROKER_LABEL.plist" "$PTYBROKER_USER_PLIST" 0644
  if is_dry_run; then
    log "dry-run: would reconcile $PAIRLING_PTYBROKER_LABEL"
    release_install_lock
    trap - EXIT
    return
  fi
  if ! launchctl print "gui/$(id -u)/$PAIRLING_PTYBROKER_LABEL" >/dev/null 2>&1; then
    reload_launch_agent "$PAIRLING_PTYBROKER_LABEL" "$PTYBROKER_USER_PLIST"
    log "Started $PAIRLING_PTYBROKER_LABEL"
    release_install_lock
    trap - EXIT
    return
  fi
  local status_json state_json state live_count blocker_count live_pid
  if ! status_json="$(ptybroker_status_json 2>/dev/null)"; then
    log "ERROR: ptybroker is loaded but status RPC is unreachable; refusing reconcile until socket is reachable or broker is manually stopped." >&2
    exit 1
  fi
  state_json="$(ptybroker_deployment_state_json "$status_json")"
  state="$(ptybroker_state_field "$state_json" "state")"
  live_count="$(ptybroker_state_field "$state_json" "live.live_session_count")"
  blocker_count="$(ptybroker_state_field "$state_json" "live.restart_blocker_count")"
  live_pid="$(ptybroker_state_field "$state_json" "live.pid")"
  if ! blocker_count="$(ptybroker_restart_blocker_count "$state_json" "live")"; then
    log "ERROR: ptybroker status did not prove its restart blockers." >&2
    return 1
  fi
  if [[ "$state" == "current" ]]; then
    log "PTY broker is already current"
    release_install_lock
    trap - EXIT
    return
  fi
  if [[ "$state" != "stale_deferred" ]]; then
    log "ERROR: ptybroker reconcile requires exact stale_deferred identity, got $state: $state_json" >&2
    exit 1
  fi
  if [[ -n "$expected_pid" && "$live_pid" != "$expected_pid" ]]; then
    log "ERROR: ptybroker PID changed before reconcile (expected=$expected_pid live=$live_pid); refusing restart." >&2
    exit 1
  fi
  if [[ "$blocker_count" != "0" ]]; then
    log "ERROR: ptybroker restart deferred: restart_blocker_count=$blocker_count live_session_count=$live_count live_pid=$live_pid; close or drain live PTYs before broker code can be updated." >&2
    exit 1
  fi
  # Re-read under the install lock immediately before mutation. The daemon's
  # expected PID closes the gap between its idle observation and this reload.
  status_json="$(ptybroker_status_json)"
  state_json="$(ptybroker_deployment_state_json "$status_json")"
  state="$(ptybroker_state_field "$state_json" "state")"
  live_pid="$(ptybroker_state_field "$state_json" "live.pid")"
  live_count="$(ptybroker_state_field "$state_json" "live.live_session_count")"
  blocker_count="$(ptybroker_state_field "$state_json" "live.restart_blocker_count")"
  if ! blocker_count="$(ptybroker_restart_blocker_count "$state_json" "live")"; then
    log "ERROR: ptybroker status did not prove its restart blockers on the final sample." >&2
    return 1
  fi
  if [[ "$state" != "stale_deferred" || "$blocker_count" != "0" || ( -n "$expected_pid" && "$live_pid" != "$expected_pid" ) ]]; then
    log "ERROR: ptybroker handover state changed before reload; refusing restart: $state_json" >&2
    exit 1
  fi
  log "Reconciling idle ptybroker live_pid=$live_pid restart_blocker_count=0"
  reload_launch_agent "$PAIRLING_PTYBROKER_LABEL" "$PTYBROKER_USER_PLIST"
  local attempt new_pid
  state=""
  for attempt in $(seq 1 50); do
    if status_json="$(ptybroker_status_json 2>/dev/null)"; then
      state_json="$(ptybroker_deployment_state_json "$status_json")"
      state="$(ptybroker_state_field "$state_json" "state")"
      new_pid="$(ptybroker_state_field "$state_json" "live.pid")"
      if [[ "$state" == "current" && "$new_pid" != "$live_pid" ]]; then
        break
      fi
    fi
    sleep 0.1
  done
  if [[ "$state" != "current" || -z "${new_pid:-}" || "$new_pid" == "$live_pid" ]]; then
    log "ERROR: ptybroker restart completed without a new current process: ${state_json:-unreachable}" >&2
    exit 1
  fi
  log "Reconciled $PAIRLING_PTYBROKER_LABEL with current runtime"
  release_install_lock
  trap - EXIT
}

stop_user_agent() {
  if is_dry_run; then
    log "dry-run: would stop $PAIRLING_DAEMON_LABEL"
    return
  fi
  launchctl bootout "gui/$(id -u)/$PAIRLING_DAEMON_LABEL" >/dev/null 2>&1 || true
  launchctl bootout "gui/$(id -u)" "$USER_PLIST" >/dev/null 2>&1 || true
}

stop_connectd_agent() {
  if is_dry_run; then
    log "dry-run: would stop $PAIRLING_CONNECTD_LABEL"
    return
  fi
  launchctl bootout "gui/$(id -u)/$PAIRLING_CONNECTD_LABEL" >/dev/null 2>&1 || true
  launchctl bootout "gui/$(id -u)" "$CONNECTD_USER_PLIST" >/dev/null 2>&1 || true
}

run_doctor() {
  PAIRLING_DAEMON_PYTHON="$PYTHON3_BIN" "$REPO_ROOT/mac/install/doctor.sh"
}

verify_runtime_activation() {
  local expected_version="${1:-$VERSION}" expected_revision="${2:-$REVISION}" expected_dirty="${3:-$SOURCE_DIRTY}"
  local doctor_json doctor_error doctor_status=0
  if is_dry_run || launchd_skipped; then
    log "Skipping live activation proof because launchd is disabled for this run."
    return
  fi
  "$PYTHON3_BIN" - \
    "$PAIRLING_RUNTIME_PORT" \
    "${PAIRLING_CONNECTD_STATUS_PORT:-7774}" \
    "${PAIRLING_ACTIVATION_WAIT_SECONDS:-20}" \
    "$CURRENT_LINK" \
    "$RELEASE_ROOT" \
    "$expected_version" \
    "$expected_revision" \
    "$expected_dirty" \
    "$REPO_ROOT" \
    "$APP_SUPPORT" \
    "$LOGS_ROOT" <<'PY'
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

runtime_port, connectd_port, wait_seconds = map(int, sys.argv[1:4])
current = Path(sys.argv[4])
expected_root_path = Path(sys.argv[5])
if expected_root_path.is_symlink() or not expected_root_path.is_dir():
    raise SystemExit("staged release root is not a real directory")
expected_root = expected_root_path.resolve(strict=True)
expected_lexical_root = expected_root_path.parent.resolve(strict=True) / expected_root_path.name
expected_version = sys.argv[6]
expected_revision = sys.argv[7]
expected_dirty = sys.argv[8] == "true"
control_root = Path(sys.argv[9])
app_support = Path(sys.argv[10])
logs_root = Path(sys.argv[11])
if control_root.is_symlink() or not control_root.is_dir():
    raise SystemExit("runtime activation control root is missing or linked")
sys.path.insert(0, str(control_root / "mac" / "companiond"))

from pairling_devices import (
    DeviceRegistry,
    SMOKE_DEVICE_PURPOSE,
    generate_device_id,
    generate_proof_secret,
    generate_token,
    resolve_install_id,
)
from request_proof import (
    BODY_SHA256_HEADER,
    INSTALL_ID_HEADER,
    PROOF_HEADER,
    REQUEST_ID_HEADER,
    TIMESTAMP_HEADER,
    body_sha256_hex,
    canonical_request,
    proof_hex,
)
from pairling_connectd_status import fetch_connectd_status

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
deadline = time.monotonic() + max(1, wait_seconds)
last_error = "activation endpoints did not answer"

def fetch(url, *, credential=None):
    headers = {}
    if credential is not None:
        parsed = urllib.parse.urlsplit(url)
        path_and_query = parsed.path or "/"
        if parsed.query:
            path_and_query += "?" + parsed.query
        timestamp_ms = str(int(time.time() * 1000))
        request_id = str(uuid.uuid4()).lower()
        body_hash = body_sha256_hex(b"")
        canonical = canonical_request(
            method="GET",
            path_and_query=path_and_query,
            timestamp_ms=timestamp_ms,
            request_id=request_id,
            body_sha256=body_hash,
            install_id=credential["install_id"],
            device_id=credential["device_id"],
        )
        headers = {
            "Authorization": f"Bearer {credential['token']}",
            INSTALL_ID_HEADER: credential["install_id"],
            REQUEST_ID_HEADER: request_id,
            TIMESTAMP_HEADER: timestamp_ms,
            BODY_SHA256_HEADER: body_hash,
            PROOF_HEADER: proof_hex(
                secret=credential["proof_secret"],
                canonical=canonical,
            ),
        }
    request = urllib.request.Request(url, headers=headers)
    with opener.open(request, timeout=2) as response:
        if response.status != 200:
            raise RuntimeError(f"{url} returned HTTP {response.status}")
        return json.loads(response.read().decode("utf-8"))

registry = DeviceRegistry(app_support / "devices.sqlite", logs_root / "audit.jsonl")
install_id = resolve_install_id(app_support)
activation_device_id = generate_device_id()
credential = {
    "device_id": activation_device_id,
    "install_id": install_id,
    "token": generate_token(),
    "proof_secret": generate_proof_secret(),
}

def stop_for_signal(signum, _frame):
    raise SystemExit(f"runtime activation interrupted by signal {signum}")

for stop_signal in (signal.SIGTERM, signal.SIGHUP):
    signal.signal(stop_signal, stop_for_signal)

activation_ok = False
credential_was_accepted = False
revoked = False
cleanup_error = ""
try:
    created = registry.create_device(
        device_name="Pairling Installer Activation",
        install_id=install_id,
        scopes=("health:read",),
        token=credential["token"],
        proof_secret=credential["proof_secret"],
        device_id=activation_device_id,
        purpose=SMOKE_DEVICE_PURPOSE,
        lease_expires_at=time.time() + max(60, wait_seconds + 30),
    )
    if created.device_id != activation_device_id:
        raise RuntimeError("runtime activation credential identity changed while it was created")
    while time.monotonic() < deadline:
        try:
            if not current.is_symlink():
                raise RuntimeError("runtime/current is not a symlink")
            literal_target = Path(os.readlink(current))
            if not literal_target.is_absolute():
                raise RuntimeError("runtime/current does not use an absolute release target")
            literal_lexical_target = literal_target.parent.resolve(strict=True) / literal_target.name
            if literal_lexical_target != expected_lexical_root:
                raise RuntimeError("runtime/current does not name the staged release directly")
            if current.resolve(strict=True) != expected_root:
                raise RuntimeError("runtime/current does not resolve to the staged release")
            manifest = json.loads((expected_root / "manifest.json").read_text(encoding="utf-8"))
            if manifest.get("schema_version") != 2:
                raise RuntimeError("installed manifest schema does not match the staged release")
            if manifest.get("runtime_version") != expected_version:
                raise RuntimeError("installed manifest runtime version does not match the staged release")
            if manifest.get("source_revision") != expected_revision:
                raise RuntimeError("installed manifest source revision does not match the staged release")
            if manifest.get("source_dirty") is not expected_dirty:
                raise RuntimeError("installed manifest source state does not match the staged release")
            if Path(str(manifest.get("install_root") or "")).resolve(strict=False) != expected_root:
                raise RuntimeError("installed manifest root does not match the staged release")
            ready = fetch(f"http://127.0.0.1:{runtime_port}/readyz")
            health = fetch(
                f"http://127.0.0.1:{runtime_port}/health",
                credential=credential,
            )
            credential_was_accepted = True
            connectd = fetch_connectd_status(timeout_seconds=2, port=connectd_port)
            if ready.get("ok") is not True or ready.get("contract_version") != "pairling-runtime-v1":
                raise RuntimeError("/readyz did not report the Pairling runtime contract as ready")
            if health.get("contract_version") != "pairling-runtime-v1" or int(health.get("schema_version") or 0) < 1:
                raise RuntimeError("/health did not report the Pairling runtime contract")
            runtime = health.get("runtime") if isinstance(health.get("runtime"), dict) else {}
            if runtime.get("verified") is not True:
                raise RuntimeError("/health did not report a verified installed runtime")
            if runtime.get("runtime_version") != expected_version:
                raise RuntimeError("/health runtime version does not match the staged release")
            if runtime.get("source_revision") != expected_revision:
                raise RuntimeError("/health source revision does not match the staged release")
            if runtime.get("source_dirty") is not expected_dirty:
                raise RuntimeError("/health source state does not match the staged release")
            runtime_root_value = runtime.get("install_root")
            if not isinstance(runtime_root_value, str) or not runtime_root_value:
                raise RuntimeError("/health did not report the executing runtime root")
            runtime_root_path = Path(runtime_root_value)
            if not runtime_root_path.is_absolute() or runtime_root_path.resolve(strict=True) != expected_root:
                raise RuntimeError("/health executing runtime root does not match the staged release")
            if int(connectd.get("schema_version") or 0) < 2:
                raise RuntimeError("connectd /status did not report schema v2")
            if int(connectd.get("pid") or 0) < 1:
                raise RuntimeError("connectd /status did not report the serving process id")
            if connectd.get("version") != expected_version:
                raise RuntimeError("connectd /status version does not match the staged release")
            if connectd.get("source_revision") != expected_revision:
                raise RuntimeError("connectd /status source revision does not match the staged release")
            if connectd.get("source_dirty") is not expected_dirty:
                raise RuntimeError("connectd /status source state does not match the staged release")
            if connectd.get("upstream_reachable") is not True:
                raise RuntimeError("connectd /status did not prove the runtime upstream reachable")
            activation_ok = True
            break
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            time.sleep(0.5)
finally:
    try:
        revoked = registry.revoke_device(
            activation_device_id,
            reason=(
                "installer_activation_complete"
                if activation_ok
                else "installer_activation_failed"
            ),
        )
    except Exception as exc:
        cleanup_error = f"{type(exc).__name__}: {exc}"
rejection_deadline = time.monotonic() + (3 if credential_was_accepted else 0.5)
credential_rejected = False
while revoked and time.monotonic() < rejection_deadline:
    try:
        fetch(
            f"http://127.0.0.1:{runtime_port}/health",
            credential=credential,
        )
    except urllib.error.HTTPError as exc:
        exc.read()
        if exc.code == 403:
            credential_rejected = True
            break
    except Exception:
        pass
    time.sleep(0.25)
if not activation_ok:
    cleanup_detail = ""
    if not revoked:
        cleanup_detail = "; activation credential revocation was not confirmed"
    elif credential_was_accepted and not credential_rejected:
        cleanup_detail = "; revoked activation credential rejection was not confirmed"
    if cleanup_error:
        cleanup_detail += "; cleanup error: " + cleanup_error
    raise SystemExit(f"runtime activation proof failed: {last_error}{cleanup_detail}")
if cleanup_error:
    raise SystemExit("runtime activation credential cleanup failed: " + cleanup_error)
if not revoked:
    raise SystemExit("runtime activation credential could not be revoked")
if not credential_rejected:
    raise SystemExit("runtime activation credential remained usable after revocation")
PY

  doctor_json="$(mktemp "${TMPDIR:-/tmp}/pairling-doctor.XXXXXX")"
  doctor_error="$doctor_json.err"
  PAIRLING_DAEMON_PYTHON="$PYTHON3_BIN" "$REPO_ROOT/mac/install/doctor.sh" --json >"$doctor_json" 2>"$doctor_error" || doctor_status=$?
  if [[ "$doctor_status" != 0 ]]; then
    cat "$doctor_error" >&2
    log "ERROR: Pairling doctor exited $doctor_status during activation proof." >&2
    rm -f "$doctor_json" "$doctor_error"
    return 1
  fi
  if ! "$PYTHON3_BIN" - "$doctor_json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("contract_version") != "pairling-runtime-v1":
    raise SystemExit("doctor did not report the Pairling runtime contract")
checks = {str(row.get("id")): row for row in payload.get("checks", []) if isinstance(row, dict)}
required = {
    "current_release_link",
    "manifest_exists",
    "manifest_contract",
    "manifest_hashes",
    "runtime_release_sealed",
    "runtime_port",
    "launchd_labels",
    "lifecycle_sources_compile",
    "app_support_writable",
    "logs_writable",
    "devices_db",
    "pair_storage_permissions",
    "launchagent_plist",
    "launchagent_port_env",
    "connectd_launchagent_plist",
    "connectd_launchagent_env",
    "ptybroker_launchagent_plist",
    "launchagent_loaded",
    "launchagent_loaded_from_current",
    "connectd_launchagent_loaded",
    "connectd_loaded_from_current",
    "ptybroker_launchagent_loaded",
    "ptybroker_loaded_from_current",
    "ptybroker_deployment_state",
    "ptybroker_activation_ready",
    "port_7773_listener",
    "legacy_port_7723_clear",
    "health_endpoint",
    "health_contract",
    "mcp_adapter_installed",
    "mcp_adapter_shim",
    "shell_pairling_wrapper",
    "connectd_status_schema_v2",
    "connectd_live_identity",
}
failed = sorted(name for name in required if checks.get(name, {}).get("status") != "ok")
if failed:
    raise SystemExit("doctor activation checks failed: " + ", ".join(failed))
PY
  then
    cat "$doctor_error" >&2
    rm -f "$doctor_json" "$doctor_error"
    return 1
  fi
  rm -f "$doctor_json" "$doctor_error"
}

rollback() {
  local current_target previous_target current_identity previous_identity
  local current_root current_version current_revision current_dirty
  local rollback_root rollback_version rollback_revision rollback_dirty
  trap install_mutation_on_exit EXIT
  acquire_install_lock
  recover_pending_install_transaction
  if [[ ! -L "$CURRENT_LINK" || ! -L "$PREVIOUS_LINK" ]]; then
    log "ERROR: rollback requires verified current and previous runtime symlinks." >&2
    exit 1
  fi
  current_target="$(readlink "$CURRENT_LINK")"
  previous_target="$(readlink "$PREVIOUS_LINK")"
  if ! current_identity="$(managed_release_identity "$current_target")"; then
    log "ERROR: current runtime is not a verified rollback source: $current_target" >&2
    exit 1
  fi
  if ! previous_identity="$(managed_release_identity "$previous_target")"; then
    log "ERROR: previous runtime is not rollback eligible: $previous_target" >&2
    exit 1
  fi
  IFS=$'\t' read -r current_root current_version current_revision current_dirty <<<"$current_identity"
  IFS=$'\t' read -r rollback_root rollback_version rollback_revision rollback_dirty <<<"$previous_identity"
  if [[ -z "$rollback_root" || -z "$rollback_version" || -z "$rollback_revision" || -z "$rollback_dirty" ]]; then
    log "ERROR: previous runtime identity is incomplete: $previous_target" >&2
    exit 1
  fi
  if [[ -z "$current_root" || "$rollback_root" == "$current_root" ]]; then
    log "ERROR: current and previous runtime links name the same release." >&2
    exit 1
  fi
  RELEASE_ROOT="$rollback_root"
  pin_control_python
  begin_install_transaction rollback
  atomic_symlink_switch "$current_target" "$PREVIOUS_LINK"
  atomic_symlink_switch "$rollback_root" "$CURRENT_LINK"
  install_transaction_fault_point rollback_links_switched
  render_plists
  prepare_automation_helper_promotion
  install_stable_automation_helper
  start_automation_agent
  start_user_agent
  ensure_ptybroker_agent
  start_connectd_agent
  install_transaction_fault_point rollback_services_started
  verify_runtime_activation "$rollback_version" "$rollback_revision" "$rollback_dirty"
  install_transaction_fault_point rollback_activation_proved
  commit_install_transaction
  append_history "rollback" "rolled back to $rollback_root"
  release_install_lock
  trap - EXIT
}

install_runtime() {
  local setup_args=("$@")
  # SPEC-p5 §2.1: --ssh enables the SSH-tunnel gateway, --no-ssh disables it.
  # Absent either flag, keep whatever the currently rendered connectd plist
  # already carries, so a plain re-run never silently turns the gateway off.
  for _ssh_arg in "${setup_args[@]:-}"; do
    case "$_ssh_arg" in
      --ssh) SSH_GATEWAY_ENABLED=1 ;;
      --no-ssh) SSH_GATEWAY_ENABLED=0 ;;
    esac
  done
  if [ -z "${SSH_GATEWAY_ENABLED:-}" ]; then
    if grep -q "PAIRLING_SSH_GATEWAY" "$CONNECTD_USER_PLIST" 2>/dev/null; then
      SSH_GATEWAY_ENABLED=1
    else
      SSH_GATEWAY_ENABLED=0
    fi
  fi
  # Guard the empty-array expansion: install_runtime is called with no args
  # today, and under bash 3.2 with set -u "${setup_args[@]}" raises an unbound
  # variable error when the array is empty. The length check avoids that.
  # The first-run flow pipes our stdout through tee, so want_tui fails its
  # [ -t 1 ] check even with a real terminal present. When PAIRLING_WIZARD is set,
  # want_tui_tty re-enables the screen, but only when a /dev/tty write probe
  # succeeds and no machine condition blocks it, so NO_COLOR, CI, dry-run, --json,
  # --plan-only, and a dumb TERM still disable it on the first-run path too.
  if [ "${#setup_args[@]}" -gt 0 ]; then
    { want_tui "${setup_args[@]:-}" || { [ "${PAIRLING_WIZARD:-0}" = 1 ] && want_tui_tty "${setup_args[@]:-}"; }; } \
      && [ -x "$PYTHON3_BIN" ] && WIZARD_TUI=1 || WIZARD_TUI=0
  else
    { want_tui || { [ "${PAIRLING_WIZARD:-0}" = 1 ] && want_tui_tty; }; } \
      && [ -x "$PYTHON3_BIN" ] && WIZARD_TUI=1 || WIZARD_TUI=0
  fi
  # The stage color and the splash follow WIZARD_TUI, not raw stdout, because the
  # first-run flow pipes our stdout through tee to the terminal, so [ -t 1 ] is
  # false there even with a real terminal. A machine path keeps WIZARD_TUI 0, so
  # it stays plain and byte-stable. GUIDED_TTY follows WIZARD_TUI except when
  # PAIRLING_GUIDED_PLAIN forces the plain form, which keeps the user opt-out the
  # load-time GUIDED_TTY honors. The knob is unset on the first-run path, so
  # first-run rendering is unaffected.
  if [ "$WIZARD_TUI" = 1 ] && [ "${PAIRLING_GUIDED_PLAIN:-0}" != "1" ]; then GUIDED_TTY=1; else GUIDED_TTY=0; fi
  # Load the brand palette exactly when the guided screen turns on. It sits on its
  # own line, not inside the gate above, because a contract test extracts that gate
  # by its literal one-line form. The call is idempotent, so the later defensive
  # calls in wizard_splash and the stage markers cost only one string test.
  if [ "$GUIDED_TTY" = 1 ]; then wizard_palette_init; fi
  if is_dry_run; then GUIDED_STAGE_TOTAL=6; else GUIDED_STAGE_TOTAL=9; fi
  trap guided_on_exit EXIT
  setup_intro
  log "Pairling setup preview:"
  log "  app support: $(display_path "$APP_SUPPORT")"
  log "  logs: $(display_path "$LOGS_ROOT")"
  log "  LaunchAgent: $PAIRLING_DAEMON_LABEL"
  log "  PTY Broker LaunchAgent: $PAIRLING_PTYBROKER_LABEL"
  log "  Connect LaunchAgent: $PAIRLING_CONNECTD_LABEL"
  log "  runtime port: $PAIRLING_RUNTIME_PORT"

  if is_dry_run; then
    validate_app_support_root

    stage_begin "Preparing the Mac runtime"
    run_compile_checks
    run_psk_dependency_checks
    stage_ok "source checks passed; no Pairling state was changed"

    stage_begin "PairDrop folder"
    stage_ok "would secure $(display_path "$PAIRDROP_ROOT") at mode 0700"

    stage_begin "Staging runtime"
    verify_payload_manifest
    verify_platform_runtime_manifest
    if [[ -n "${PAIRLING_CONNECTD_PREBUILT:-}" ]]; then
      verify_connectd_prebuilt "$PAIRLING_CONNECTD_PREBUILT"
    fi
    stage_ok "package inputs verified; would stage $RELEASE_NAME"

    stage_begin "Starting Pairling services"
    stage_ok "would render and activate the three Pairling LaunchAgents"

    stage_begin "macOS permissions"
    guided_permission_notice
    stage_ok "would request Pairling Accessibility and Pairling control of Terminal before showing a pairing code"

    stage_begin "Providers"
    provider_setup_stage

    GUIDED_COMPLETE=1
    return 0
  fi

  acquire_install_lock
  recover_pending_install_transaction
  # When WIZARD_TUI is 1 the guided stages add the splash, the live safety step,
  # and the bash recovery menu, all behind a WIZARD_TUI check. When it is 0 the
  # existing plain printf flow runs unchanged.

  stage_begin "Preparing the Mac runtime"
  run_compile_checks
  run_psk_dependency_checks
  # These migrations only add or reconcile durable local identity and schema
  # state. They are idempotent and monotonic, so they intentionally run outside
  # the reversible file transaction. Never snapshot devices.sqlite: restoring a
  # whole database could erase device changes made by another live request. The
  # one reversible state action, local MCP credential creation, runs below after
  # the durable pending marker has been published.
  ensure_state_migrations
  stage_ok "checks passed and state is ready"

  begin_install_transaction setup
  plan_install_transaction_mcp_credential
  install_transaction_fault_point mcp_credential_planned
  ensure_local_mcp_bridge
  install_transaction_fault_point mcp_credential_created_unrecorded
  record_install_transaction_mcp_credential
  install_transaction_fault_point mcp_credential_ready

  stage_begin "PairDrop folder"
  GUIDED_FAILURE_PATH="$PAIRDROP_ROOT"
  ensure_pairdrop_folder
  install_transaction_fault_point pairdrop_ready
  stage_ok "$(display_path "$PAIRDROP_ROOT") is ready (private, mode 0700)"
  GUIDED_FAILURE_PATH=""

  stage_begin "Staging runtime"
  copy_release
  install_transaction_fault_point release_published
  persist_pairdrop_folder
  install_transaction_fault_point pairdrop_config_persisted
  persist_push_provider_defaults
  install_transaction_fault_point push_config_persisted
  if launchd_skipped && [[ "${PAIRLING_TEST_FAIL_AFTER_PAIRDROP_PERSIST:-0}" == 1 ]]; then
    log "ERROR: forced test failure after PairDrop configuration persistence" >&2
    false
  fi
  require_idle_ptybroker_for_runtime_change
  switch_current
  install_transaction_fault_point current_link_switched
  adopt_current_release_sources
  if [[ "${PAIRLING_TEST_FAIL_AFTER_RELEASE_ADOPT:-0}" == 1 ]]; then
    log "ERROR: forced test failure after adopting the published runtime" >&2
    false
  fi
  install_mcp_adapter_shim
  install_shell_wrapper
  install_transaction_fault_point launch_assets_installed
  stage_ok "staged $RELEASE_NAME"
  GUIDED_FAILURE_SOURCE_PATH=""
  GUIDED_FAILURE_PATH=""

  stage_begin "Starting Pairling services"
  render_plists
  prepare_automation_helper_promotion
  install_stable_automation_helper
  start_automation_agent
  start_user_agent
  ensure_ptybroker_agent
  start_connectd_agent
  install_transaction_fault_point services_started
  verify_runtime_activation
  install_transaction_fault_point activation_proved
  commit_install_transaction
  migrate_verified_legacy_injector
  stage_ok "companiond, connectd, and ptybroker passed live activation checks"

  append_history "installed" "installed $RELEASE_NAME"
  log "Installed Pairling runtime $RELEASE_NAME"

  if launchd_skipped; then
    GUIDED_COMPLETE=1
    return 0
  fi

  if ! is_dry_run; then
    stage_begin "Pairling Connect sign-in (Mac)"
    if ! require_pairling_connect_route; then
      log "Pairling installed, but its private Pairling Connect route is not ready. Finish browser approval, then rerun setup or run: pairling pair --qr" >&2
      exit 1
    fi
    stage_ok "Pairling Connect route is ready"
  fi

  stage_begin "macOS permissions"
  request_terminal_permissions
  if [ "${WIZARD_TUI:-0}" = 1 ] && ! is_dry_run; then
    # The Safety Monitor remains optional. It is assessed only after Pairling has
    # verified the mandatory Terminal-control permissions required for pairing.
    safety_step
  fi
  stage_ok "Pairling Mac permissions are ready for terminal control"

  stage_begin "Providers"
  provider_setup_stage

  if ! is_dry_run; then
    stage_begin "Pairing code for the iPhone"
    if [ "${WIZARD_TUI:-0}" = 1 ]; then
      stage_note "Open Pairling on your iPhone and scan this code. The pair address is printed below it too."
    fi
    # Record when this pairing attempt started, so the seen probe in
    # guided_finish_summary counts only a device paired during this session.
    export PAIRLING_PAIRING_STARTED_AT="$("$PYTHON3_BIN" -c 'import time;print(time.time())')"
    if ! PAIRLING_CONNECTD_ROUTE_WAIT_SECONDS="${PAIRLING_CONNECTD_ROUTE_WAIT_SECONDS:-5}" pair_runtime --qr; then
      log "Pairling installed, but setup could not generate a pairing invitation. Run: pairling doctor --json; pairling pair --qr" >&2
      exit 1
    fi
    stage_ok "pairing code displayed"
    log ""
    # Hold here on the guided screen so the pairing code stays in view until the
    # operator has scanned it, rather than being scrolled off by the stages
    # below. Gated on a terminal stdin like the recovery menu, so a piped, CI, or
    # captured run never blocks, and skipped in a dry run. The read tolerates EOF.
    if [ "${GUIDED_TTY:-0}" = 1 ] && [ -t 0 ] && ! is_dry_run; then
      wizard_palette_init
      printf '     %sScan the code above in Pairling on your iPhone, then press Enter to finish setup.\033[0m ' "${WZ_PAPER:-}"
      read -r _ || true
      log ""
    fi
    stage_begin "Finish and next steps"
    guided_finish_summary
    stage_ok "setup complete"
  fi
  release_install_lock
  GUIDED_COMPLETE=1
}

status_runtime() {
  PAIRLING_DAEMON_PYTHON="$PYTHON3_BIN" "$REPO_ROOT/mac/install/doctor.sh" --json || true
}

start_runtime() {
  ensure_state
  render_plists
  start_automation_agent
  start_user_agent
  ensure_ptybroker_agent
  start_connectd_agent
  log "Started $PAIRLING_DAEMON_LABEL"
}

stop_runtime() {
  stop_connectd_agent
  stop_automation_agent
  stop_user_agent
  log "Stopped $PAIRLING_DAEMON_LABEL"
}

pair_runtime() {
  local ttl="180"
  local show_qr="0"
  local json_requested="0"
  local role="reader"
  local role_explicit="0"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --json)
        json_requested="1"
        ;;
      --qr)
        show_qr="1"
        ;;
      --ttl)
        shift
        ttl="${1:-}"
        if [[ -z "$ttl" ]]; then
          log "usage: pairling pair [--ttl seconds] [--role reader|operator] [--json] [--qr]" >&2
          exit 2
        fi
        ;;
      --role)
        shift
        role="${1:-}"
        role_explicit="1"
        if [[ -z "$role" ]]; then
          log "usage: pairling pair [--ttl seconds] [--role reader|operator] [--json] [--qr]" >&2
          exit 2
        fi
        ;;
      --help|-h)
        log "usage: pairling pair [--ttl seconds] [--role reader|operator] [--json] [--qr]"
        return
        ;;
      *)
        log "usage: pairling pair [--ttl seconds] [--role reader|operator] [--json] [--qr]" >&2
        exit 2
        ;;
    esac
    shift
  done
  if [[ "$role_explicit" == "1" ]]; then
    case "$role" in
      reader|operator) ;;
      *)
        log "Invalid pairing role. Choose reader or operator." >&2
        exit 2
        ;;
    esac
  fi
  if [[ "$role_explicit" != "1" && "$json_requested" != "1" && "${GUIDED_TTY:-0}" == "1" && -t 0 ]]; then
    printf '\n  Pairing role\n'
    printf '  [r] Reader   Read sessions, transcripts, diagnostics, and files\n'
    printf '  [o] Operator Reader access plus send, interrupt, approval, and control\n'
    printf '  Choose r or o [r]: '
    local role_choice=""
    IFS= read -r role_choice </dev/tty || role_choice=""
    role_choice="$(printf '%s' "$role_choice" | tr '[:upper:]' '[:lower:]')"
    case "$role_choice" in
      ""|r|reader) role="reader" ;;
      o|operator) role="operator" ;;
      *)
        log "Pairing cancelled: choose reader or operator." >&2
        exit 2
        ;;
    esac
  fi
  local payload_file
  payload_file="$(mktemp)"
  if "$PYTHON3_BIN" - "$PAIRLING_RUNTIME_PORT" "$ttl" "$role" "$REPO_ROOT" >"$payload_file" <<'PY'
import json
import ipaddress
import os
import socket
import sys
import time
import urllib.parse

port, ttl_raw, role, repo_root = sys.argv[1:]
sys.path.insert(0, os.path.join(repo_root, "mac", "companiond"))
from pairling_connectd_status import advertised_pairling_connect_routes, fetch_connectd_status
from local_control_client import LocalControlClientError, control_socket_path, request_json

try:
    ttl = int(ttl_raw)
except ValueError:
    print(json.dumps({
        "ok": False,
        "error": {"code": "invalid_ttl", "message": "ttl must be an integer"},
    }, indent=2, sort_keys=True), file=sys.stderr)
    raise SystemExit(2)

body_payload = {"ttl_seconds": ttl, "role": role}
try:
    status, payload = request_json(
        "/pair/start",
        method="POST",
        payload=body_payload,
        socket_path=control_socket_path(),
        timeout_seconds=5,
    )
except LocalControlClientError as exc:
    print(json.dumps({
        "ok": False,
        "error": {
            "code": exc.code,
            "message": exc.message,
        },
        "repair": "Run `pairling start` or `pairling doctor --json`, then retry `pairling pair`.",
    }, indent=2, sort_keys=True), file=sys.stderr)
    raise SystemExit(1)
if not 200 <= status < 300:
    print(json.dumps(payload, indent=2, sort_keys=True), file=sys.stderr)
    raise SystemExit(1)

pair_id = str(payload.get("pair_id") or (payload.get("claim") or {}).get("pair_id") or "")
secret = str(
    payload.get("secret")
    or payload.get("secret_qr")
    or (payload.get("claim") or {}).get("secret")
    or ""
)
invited_role = str(payload.get("role") or (payload.get("claim") or {}).get("role") or "")
if invited_role != role:
    raise RuntimeError("Pairling runtime returned a different invitation role")
install_id = str(payload.get("install_id") or "")
mac_name = str(((payload.get("pair_service") or {}).get("txt") or {}).get("mac_name") or socket.gethostname())
# The Mac ephemeral ECDH public key from /pair/start is required in the QR or
# pairing link. The secret stays out of the network request and there is no
# plaintext downgrade path.
mac_ake_pub = str(payload.get("mac_ake_pub") or (payload.get("claim") or {}).get("mac_ake_pub") or "")
if not mac_ake_pub:
    print(json.dumps({
        "ok": False,
        "error": {
            "code": "pairing_protocol_unavailable",
            "message": "The Mac did not produce the v2 pairing key. Run setup again.",
        },
        "repair": "Run `pairling setup`, then retry `pairling pair`.",
    }, indent=2, sort_keys=True), file=sys.stderr)
    raise SystemExit(1)

def is_ats_local_ipv4(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    if addr.version != 4 or addr.is_loopback or addr.is_link_local:
        return False
    return (
        value.startswith("10.")
        or value.startswith("192.168.")
        or any(value.startswith(f"172.{i}.") for i in range(16, 32))
    )

def detected_lan_ip() -> str:
    override = os.environ.get("PAIRLING_TEST_LAN_IP")
    if override is not None:
        value = override.strip()
        return value if is_ats_local_ipv4(value) else ""
    if os.environ.get("PAIRLING_DISABLE_LAN") == "1" or os.environ.get("PAIRLING_TEST_DISABLE_LAN") == "1":
        return ""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
        finally:
            sock.close()
        return ip if is_ats_local_ipv4(ip) else ""
    except Exception:
        return ""

def connectd_route_wait_seconds() -> float:
    try:
        return min(max(float(os.environ.get("PAIRLING_CONNECTD_ROUTE_WAIT_SECONDS") or "0"), 0.0), 60.0)
    except ValueError:
        return 0.0

def connectd_route_poll_seconds() -> float:
    try:
        return min(max(float(os.environ.get("PAIRLING_CONNECTD_ROUTE_POLL_SECONDS") or "0.5"), 0.1), 2.0)
    except ValueError:
        return 0.5

def status_could_be_ready_soon(status: dict) -> bool:
    if not status:
        return True
    if status.get("auth_url_present"):
        return False
    return True

def ready_connectd_route():
    wait_seconds = connectd_route_wait_seconds()
    poll_seconds = connectd_route_poll_seconds()
    deadline = time.monotonic() + wait_seconds
    while True:
        status = fetch_connectd_status(timeout_seconds=0.7) or {}
        connect_routes = advertised_pairling_connect_routes(status)
        if connect_routes:
            return connect_routes[0]
        if wait_seconds <= 0 or time.monotonic() >= deadline or not status_could_be_ready_soon(status):
            return None
        time.sleep(min(poll_seconds, max(0.0, deadline - time.monotonic())))

def lan_base_serviceable(ip: str, port_number: int) -> bool:
    """Only advertise a LAN pairing base that something actually serves.

    A loopback-bound daemon leaves lan_ip:port with no listener, so a QR
    built on it sends the phone to a dead socket while a ready Pairling
    Connect route sits unused. Probe the exact address the phone would
    hit. Tests fabricate LAN IPs that can never be bound, so the test
    seam pins serviceability instead of probing."""
    flag = os.environ.get("PAIRLING_TEST_LAN_LISTENING")
    if flag is not None:
        return flag.strip() != "0"
    if os.environ.get("PAIRLING_TEST_LAN_IP") is not None:
        return True
    try:
        with socket.create_connection((ip, port_number), timeout=0.35):
            return True
    except OSError:
        return False

def default_pair_route(port_number: int) -> dict:
    for key in ("PAIRLING_PAIR_BASE_URL", "PAIRLING_PUBLIC_BASE_URL"):
        value = os.environ.get(key)
        if value:
            return {"base_url": value, "source": "explicit_override", "status": "override"}
    # The embedded route is the product boundary. Normal setup never emits a
    # nearby or standalone-Tailscale invitation when Pairling Connect is not
    # ready, because that code cannot satisfy the iPhone's pre-pair transport.
    route = ready_connectd_route()
    if route:
        return {
            "base_url": route["base_url"],
            "source": route["source"],
            "status": route["status"],
            "kind": route["kind"],
        }
    if os.environ.get("PAIRLING_ALLOW_LOCAL_PAIRING") != "1":
        return {}
    # Explicit recovery/testing only. This branch is never selected by normal
    # setup and is visibly marked degraded in the pair URL.
    lan_ip = detected_lan_ip()
    if lan_ip and lan_base_serviceable(lan_ip, port_number):
        return {"base_url": f"http://{lan_ip}:{port_number}", "source": "lan", "status": "fallback", "kind": "lan"}
    if os.environ.get("PAIRLING_DISABLE_BONJOUR") != "1" and os.environ.get("PAIRLING_TEST_DISABLE_BONJOUR") != "1":
        return {"base_url": f"http://{socket.gethostname()}.local:{port_number}", "source": "bonjour", "status": "fallback", "kind": "bonjour"}
    return {}

pair_route = default_pair_route(int(port))
if not pair_route:
    print(json.dumps({
        "ok": False,
        "error": {
            "code": "pairling_connect_required",
            "message": "Pairling Connect must be authenticated and advertising a ready embedded route before Pairling can create a pairing invitation.",
        },
        "repair": "Run `pairling connect-auth-open`, finish browser approval, check `pairling doctor --json`, then retry `pairling pair --qr`.",
    }, indent=2, sort_keys=True), file=sys.stderr)
    raise SystemExit(1)
base_url = str(pair_route.get("base_url") or "")
if pair_id and secret:
    pair_params = {
        "base": base_url,
        "pair_id": pair_id,
        "secret": secret,
    }
    attest_challenge = str(payload.get("attest_challenge") or "")
    if attest_challenge:
        pair_params["attest_challenge"] = attest_challenge
    pair_params["role"] = invited_role
    pair_params["mac_ake_pub"] = mac_ake_pub
    pair_params["pv"] = "2"
    if pair_route.get("source") == "pairling_connectd" and pair_route.get("status") == "ready":
        pair_params["route_source"] = "pairling_connectd"
        pair_params["route_status"] = "ready"
        pair_params["route_kind"] = str(pair_route.get("kind") or "tailnet")
        pair_params["route_contract"] = "pairling-runtime-v1"
    elif pair_route.get("status") == "fallback":
        pair_params["route_source"] = "local_fallback"
        pair_params["route_status"] = "degraded"
        pair_params["route_kind"] = str(pair_route.get("kind") or pair_route.get("source") or "local")
        pair_params["route_contract"] = "pairling-runtime-v1"
    manual = {
        "base_url": base_url,
        "pair_id": pair_id,
        "secret": secret,
        "role": invited_role,
    }
    if install_id:
        pair_params["install_id"] = install_id
        pair_params["mac_name"] = mac_name
        manual["install_id"] = install_id
        manual["mac_name"] = mac_name
    payload.setdefault("pair_url", "https://pairling.dev/pair/?" + urllib.parse.urlencode(pair_params))
    payload.setdefault("manual", manual)

print(json.dumps(payload, indent=2, sort_keys=True))
raise SystemExit(0 if payload.get("ok") else 1)
PY
  then
    :
  else
    local code=$?
    cat "$payload_file" >&2
    rm -f "$payload_file"
    exit "$code"
  fi

  if [[ "$show_qr" == "0" ]]; then
    cat "$payload_file"
    rm -f "$payload_file"
    return
  fi

  local pair_url
  pair_url="$("$PYTHON3_BIN" - "$payload_file" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1]))
print(payload.get("pair_url", ""))
PY
)"

  "$PYTHON3_BIN" - "$payload_file" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1]))
manual = payload.get("manual") or {}
print("Pairling pairing invitation ready")
if payload.get("role"):
    print("Role:", str(payload["role"]).title())
print("")
print("Scan this QR in Pairling, or paste the pair URL below.")
print("")
if payload.get("pair_url"):
    print("Pair URL:")
    print(payload["pair_url"])
    print("")
if manual:
    print("Manual values:")
    print("  base_url:", manual.get("base_url", ""))
    print("  pair_id:", manual.get("pair_id", ""))
    print("  secret:", manual.get("secret", ""))
    print("")
PY
  if [[ -n "$pair_url" ]]; then
    # The guided screen heads the QR with a bold header only. A machine path keeps
    # GUIDED_TTY 0, so the helper is silent and the QR renders exactly as before.
    # render_pair_qr itself is untouched.
    wizard_qr_open
    if ! render_pair_qr "$pair_url"; then
      log "QR rendering unavailable because Swift/CoreImage is not available. Use the pair URL above."
    fi
  fi
  if [[ "$json_requested" == "1" ]]; then
    log ""
    log "JSON:"
    cat "$payload_file"
  fi
  rm -f "$payload_file"
}

devices_runtime() {
  "$PYTHON3_BIN" - "$DEVICES_DB" <<'PY'
import json
import sqlite3
import sys
path = sys.argv[1]
try:
    with sqlite3.connect(path) as db:
        columns = {
            str(row[1])
            for row in db.execute("PRAGMA table_info(devices)").fetchall()
        }
        role_column = "role" if "role" in columns else "NULL AS role"
        query = (
            "SELECT device_id, device_name, scopes_json, "
            f"{role_column}, created_at, last_seen_at, revoked_at FROM devices"
        )
        params = ()
        if "purpose" in columns:
            query += " WHERE COALESCE(purpose, '') NOT IN (?, ?)"
            params = ("runtime_truth_smoke", "local_mcp_bridge")
        rows = db.execute(query + " ORDER BY created_at", params).fetchall()
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
    raise SystemExit(1)
print(json.dumps({
    "ok": True,
    "devices": [
        {
            "device_id": row[0],
            "device_name": row[1],
            "scopes": json.loads(row[2]),
            "role": row[3],
            "created_at": row[4],
            "last_seen_at": row[5],
            "revoked_at": row[6],
        }
        for row in rows
    ],
}, indent=2, sort_keys=True))
PY
}

unpair_runtime() {
  local device_id="${1:-}"
  if [[ -z "$device_id" ]]; then
    log "usage: pairling unpair <device_id>" >&2
    exit 2
  fi
  "$PYTHON3_BIN" - "$REPO_ROOT" "$DEVICES_DB" "$LOGS_ROOT/audit.jsonl" "$device_id" <<'PY'
import json
import sys
from pathlib import Path

repo_root, db_path, audit_path, device_id = sys.argv[1:]
sys.path.insert(0, str(Path(repo_root) / "mac" / "companiond"))
from pairling_devices import DeviceRegistry

registry = DeviceRegistry(Path(db_path), Path(audit_path))
ok = registry.revoke_device(device_id, reason="cli")
payload = {"ok": ok, "device_id": device_id}
if not ok:
    payload["error"] = {"code": "device_not_found", "message": "device was not found or is already revoked"}
print(json.dumps(payload, indent=2, sort_keys=True))
raise SystemExit(0 if ok else 1)
PY
}

rotate_runtime() {
  local device_id="${1:-}"
  if [[ -z "$device_id" ]]; then
    log "usage: pairling rotate-token <device_id>" >&2
    exit 2
  fi
  "$PYTHON3_BIN" - "$REPO_ROOT" "$DEVICES_DB" "$LOGS_ROOT/audit.jsonl" "$device_id" <<'PY'
import json
import sys
from pathlib import Path

repo_root, db_path, audit_path, device_id = sys.argv[1:]
sys.path.insert(0, str(Path(repo_root) / "mac" / "companiond"))
from pairling_devices import DeviceRegistry

registry = DeviceRegistry(Path(db_path), Path(audit_path))
token = registry.rotate_token(device_id)
payload = {"ok": token is not None, "device_id": device_id}
if token is None:
    payload["error"] = {"code": "device_not_found", "message": "device was not found"}
else:
    payload["token"] = token
print(json.dumps(payload, indent=2, sort_keys=True))
raise SystemExit(0 if token is not None else 1)
PY
}

logs_runtime() {
  log "$LOGS_ROOT"
}


connect_auth_open() {
  local json_mode="false"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --json)
        json_mode="true"
        ;;
      --help|-h)
        log "usage: pairling connect-auth-open [--json]"
        return
        ;;
      *)
        log "usage: pairling connect-auth-open [--json]" >&2
        exit 2
        ;;
    esac
    shift
  done
  local output helper_status=0 response_status=1
  output="$("$PYTHON3_BIN" "$REPO_ROOT/mac/companiond/local_control_client.py" \
    POST /connect/auth/open 2>/dev/null)" || helper_status=$?
  if [[ "$helper_status" == "0" ]] && \
    "$PYTHON3_BIN" -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("ok") else 1)' <<<"$output"; then
    response_status=0
  fi
  if [[ -z "$output" ]]; then
    output='{"ok":false,"opened":false,"auth_url_present":false,"error":{"code":"control_transport_error","message":"Pairling local control socket is unavailable."}}'
  fi
  if [[ "$json_mode" == "true" ]]; then
    printf '%s\n' "$output"
  else
    "$PYTHON3_BIN" -c 'import json,sys; data=json.load(sys.stdin); error=data.get("error"); message=error.get("message") if isinstance(error,dict) else error; print("Pairling Connect browser approval opened." if data.get("opened") else (message or "Pairling Connect browser approval is not available."))' <<<"$output" >&2
  fi
  exit "$response_status"
}

# Normal setup must have an authenticated embedded route before it creates a
# pairing invitation. This opens browser approval when needed, waits for the
# advertised semantic route, and fails with a clear repair step on timeout.
require_pairling_connect_route() {
  if is_dry_run; then
    return 0
  fi
  "$PYTHON3_BIN" - "$REPO_ROOT" <<'PY'
import os
import sys
import time

repo_root = sys.argv[1]
sys.path.insert(0, os.path.join(repo_root, "mac", "companiond"))
from pairling_connectd_status import advertised_pairling_connect_routes, fetch_connectd_status
from local_control_client import LocalControlClientError, control_socket_path, request_json


def readiness_wait_seconds() -> float:
    try:
        return min(max(float(os.environ.get("PAIRLING_CONNECTD_AUTH_WAIT_SECONDS") or "180"), 0.0), 600.0)
    except ValueError:
        return 180.0


def readiness_poll_seconds() -> float:
    try:
        return min(max(float(os.environ.get("PAIRLING_CONNECTD_AUTH_POLL_SECONDS") or "0.5"), 0.1), 2.0)
    except ValueError:
        return 0.5


def post_auth_open() -> bool:
    try:
        _status, payload = request_json(
            "/connect/auth/open",
            method="POST",
            socket_path=control_socket_path(),
            timeout_seconds=5,
        )
    except LocalControlClientError:
        return False
    return bool(payload.get("ok"))


def main() -> None:
    wait_seconds = readiness_wait_seconds()
    poll_seconds = readiness_poll_seconds()
    deadline = time.monotonic() + wait_seconds
    auth_open_attempted = False
    last_status = {}
    while True:
        status = fetch_connectd_status(timeout_seconds=0.7) or {}
        if status:
            last_status = status
        routes = advertised_pairling_connect_routes(status)
        if routes:
            route = routes[0]
            print(f"Pairling Connect is ready at {route.get('base_url', 'the embedded route')}.")
            return
        if status.get("auth_url_present") and not auth_open_attempted:
            auth_open_attempted = True
            if post_auth_open():
                print("Opened Pairling Connect approval in your browser. Finish sign-in while this setup waits for the private route.")
            else:
                print("Pairling Connect approval is available but could not be opened automatically. Run `pairling connect-auth-open` in another terminal.")
        if wait_seconds <= 0 or time.monotonic() >= deadline:
            auth_state = str(last_status.get("auth_state") or "unknown")
            backend_state = str(last_status.get("backend_state") or last_status.get("state") or "unknown")
            print(
                "ERROR: Pairling Connect did not advertise a ready embedded route "
                f"before setup timed out (auth_state={auth_state}, backend_state={backend_state}).",
                file=sys.stderr,
            )
            print(
                "Run `pairling connect-auth-open`, finish browser approval, then check `pairling doctor --json` before retrying.",
                file=sys.stderr,
            )
            raise SystemExit(1)
        time.sleep(min(poll_seconds, max(0.0, deadline - time.monotonic())))


main()
PY
}

render_pair_qr() {
  local pair_url="$1"
  if ! command -v swift >/dev/null 2>&1; then
    return 1
  fi
  (
    umask 077
    local source_dir=""
    local source_file=""
    cleanup_pair_qr_source() {
      if [[ -n "$source_file" ]]; then
        rm -f "$source_file"
      fi
      if [[ -n "$source_dir" ]]; then
        rmdir "$source_dir" 2>/dev/null || true
      fi
    }
    trap cleanup_pair_qr_source EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    source_dir="$(mktemp -d "/tmp/pairling-qr.XXXXXXXX")" || exit 1
    chmod 700 "$source_dir" || exit 1
    source_file="$source_dir/render.swift"
    cat >"$source_file" <<'SWIFT'
import CoreGraphics
import CoreImage
import Foundation

let message = FileHandle.standardInput.readDataToEndOfFile()
guard !message.isEmpty,
      let filter = CIFilter(name: "CIQRCodeGenerator") else {
    exit(2)
}

filter.setValue(message, forKey: "inputMessage")
filter.setValue("L", forKey: "inputCorrectionLevel")

guard let output = filter.outputImage else {
    exit(2)
}

let extent = output.extent.integral
let ciContext = CIContext(options: nil)
guard let cgImage = ciContext.createCGImage(output, from: extent) else {
    exit(2)
}

let width = cgImage.width
let height = cgImage.height
let bytesPerRow = width * 4
var raw = [UInt8](repeating: 255, count: height * bytesPerRow)
let colorSpace = CGColorSpaceCreateDeviceRGB()
let bitmapInfo = CGImageAlphaInfo.premultipliedLast.rawValue

guard let bitmapContext = CGContext(
    data: &raw,
    width: width,
    height: height,
    bitsPerComponent: 8,
    bytesPerRow: bytesPerRow,
    space: colorSpace,
    bitmapInfo: bitmapInfo
) else {
    exit(2)
}

bitmapContext.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
bitmapContext.fill(CGRect(x: 0, y: 0, width: width, height: height))
bitmapContext.draw(cgImage, in: CGRect(x: 0, y: 0, width: width, height: height))

func isDark(_ x: Int, _ y: Int) -> Bool {
    let index = y * bytesPerRow + x * 4
    return raw[index] < 128 && raw[index + 1] < 128 && raw[index + 2] < 128
}

// Half-block rendering: one column per module, and the upper half block packs two
// module rows into one terminal row, so a long pairing URL fits an 80-column
// terminal instead of overflowing at about 180 columns. The foreground colors the
// top module and the background colors the bottom module. A dark module is black
// (foreground 30, background 40) and a light module is white (foreground 37,
// background 47). This is the standard scannable qrencode ANSIUTF8 format. The quiet
// zone is 2 modules and the error correction is "L", the smaller settings that keep
// the QR under 80 columns.
let quietZone = 2
let reset = "\u{001B}[0m"

func moduleDark(_ x: Int, _ y: Int) -> Bool {
    return x >= 0 && y >= 0 && x < width && y < height && isDark(x, y)
}

func cell(_ topDark: Bool, _ bottomDark: Bool) -> String {
    let foreground = topDark ? "30" : "37"
    let background = bottomDark ? "40" : "47"
    return "\u{001B}[\(foreground);\(background)m\u{2580}"
}

var y = -quietZone
while y < height + quietZone {
    var line = ""
    for x in (-quietZone)..<(width + quietZone) {
        line += cell(moduleDark(x, y), moduleDark(x, y + 1))
    }
    print(line + reset)
    y += 2
}
SWIFT
    chmod 600 "$source_file" || exit 1
    printf '%s' "$pair_url" | swift "$source_file"
  )
}

diagnose_runtime() {
  PAIRLING_DAEMON_PYTHON="$PYTHON3_BIN" "$REPO_ROOT/mac/install/doctor.sh" --json \
    | "$PYTHON3_BIN" -c 'import json,sys; data=json.load(sys.stdin); print(json.dumps(data, indent=2, sort_keys=True))' || true
}

setup_usage() {
  cat <<EOF
usage: pairling setup [--first-run] [--ssh|--no-ssh]

Installs or updates the Pairling Mac runtime, checks Pairling Connect, detects
supported coding agents, and prepares an iPhone pairing invitation.

options:
  --first-run  Run the guided first-run flow.
  --ssh        Enable the optional SSH gateway.
  --no-ssh     Disable the optional SSH gateway.
  --help, -h   Show this help without changing the Mac.
EOF
}

usage() {
  cat <<EOF
usage: pairling <command>

commands:
  setup|install
  setup --first-run
  first-run
  start
  stop
  restart
  status
  doctor --json
  doctor --first-run --json
  reconcile-ptybroker
  pair
  devices
  unpair <device_id>
  rotate-token <device_id>
  logs
  diagnose --redact
  uninstall
  rollback
EOF
}

cmd="${1:-setup}"
shift || true
case "$cmd" in
  setup|install)
    case "${1:-}" in
      --help|-h)
        setup_usage
        ;;
      --first-run)
        shift
        "$REPO_ROOT/mac/install/bootstrap-first-run.sh" "$@"
        ;;
      *)
        install_runtime "$@"
        ;;
    esac
    ;;
  first-run)
    "$REPO_ROOT/mac/install/bootstrap-first-run.sh" "$@"
    ;;
  start)
    start_runtime
    ;;
  stop)
    stop_runtime
    ;;
  restart)
    stop_runtime
    start_runtime
    ;;
  status)
    status_runtime
    ;;
  doctor)
    PAIRLING_DAEMON_PYTHON="$PYTHON3_BIN" "$REPO_ROOT/mac/install/doctor.sh" "$@"
    ;;
  reconcile-ptybroker|--reconcile-ptybroker|--restart-ptybroker-if-idle)
    reconcile_ptybroker "$@"
    ;;
  pair)
    pair_runtime "$@"
    ;;
  devices)
    devices_runtime
    ;;
  unpair)
    unpair_runtime "$@"
    ;;
  rotate-token)
    rotate_runtime "$@"
    ;;
  logs)
    logs_runtime
    ;;
  connect-auth-open)
    connect_auth_open "$@"
    ;;
  diagnose)
    diagnose_runtime "$@"
    ;;
  uninstall)
    PAIRLING_DAEMON_PYTHON="$PYTHON3_BIN" "$REPO_ROOT/mac/install/uninstall-runtime.sh" "$@"
    ;;
  rollback|--rollback)
    rollback
    ;;
  help|--help|-h)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
