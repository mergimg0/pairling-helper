#!/usr/bin/env bash
set -euo pipefail

export PYTHONDONTWRITEBYTECODE=1
if [[ -z "${PYTHONPYCACHEPREFIX:-}" ]]; then
  PYTHONPYCACHEPREFIX="${TMPDIR:-/tmp}/pairling-pycache-$(id -u)"
  mkdir -p "$PYTHONPYCACHEPREFIX" 2>/dev/null || true
  export PYTHONPYCACHEPREFIX
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "$REPO_ROOT/mac/VERSION")"
read_source_stamp() {
  local path="$1"
  if [[ -f "$path" ]]; then
    tr -d '[:space:]' < "$path"
  fi
}
REVISION="${PAIRLING_SOURCE_REVISION:-$(read_source_stamp "$REPO_ROOT/mac/SOURCE_REVISION")}"
if [[ -z "$REVISION" ]]; then
  REVISION="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || true)"
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
  "mac/guardian"
  "mac/install"
  "mac/mcp"
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
PAIRLING_GUARDIAN_LABEL="dev.pairling.power-guardian"
PAIRLING_CONNECTD_LABEL="dev.pairling.connectd"
PAIRLING_PTYBROKER_LABEL="dev.pairling.ptybroker"
PAIRLING_MINTD_LABEL="dev.pairling.mintd"
APP_SUPPORT="${PAIRLING_APP_SUPPORT_ROOT:-${COMPANION_APP_SUPPORT_ROOT:-$HOME/Library/Application Support/Pairling}}"
RUNTIME_ROOT="$APP_SUPPORT/runtime"
RELEASES_ROOT="$RUNTIME_ROOT/releases"
STATE_ROOT="$APP_SUPPORT/state"
PAIR_ROOT="$APP_SUPPORT/pair"
LOGS_ROOT="${PAIRLING_LOGS_ROOT:-${COMPANION_LOGS_ROOT:-$HOME/Library/Logs/Pairling}}"
PLIST_BUILD_DIR="$RUNTIME_ROOT/plists"
CURRENT_LINK="$RUNTIME_ROOT/current"
PREVIOUS_LINK="$RUNTIME_ROOT/previous"
RELEASE_NAME="$VERSION-$REVISION"
RELEASE_ROOT="$RELEASES_ROOT/$RELEASE_NAME"
CONFIG_FILE="$APP_SUPPORT/config.json"
DEVICES_DB="$APP_SUPPORT/devices.sqlite"
MCP_CREDENTIAL="$APP_SUPPORT/mcp-bridge.json"
INSTALL_HISTORY="$STATE_ROOT/install-history.jsonl"
USER_PLIST="$HOME/Library/LaunchAgents/$PAIRLING_DAEMON_LABEL.plist"
CONNECTD_USER_PLIST="$HOME/Library/LaunchAgents/$PAIRLING_CONNECTD_LABEL.plist"
PTYBROKER_USER_PLIST="$HOME/Library/LaunchAgents/$PAIRLING_PTYBROKER_LABEL.plist"
SYSTEM_PLIST="/Library/LaunchDaemons/$PAIRLING_GUARDIAN_LABEL.plist"
MINTD_SYSTEM_PLIST="/Library/LaunchDaemons/$PAIRLING_MINTD_LABEL.plist"
MINTD_SYSTEM_ROOT="/Library/Application Support/Pairling"
MINTD_SECRET_DIR="$MINTD_SYSTEM_ROOT/mint"
MINTD_RUN_DIR="$MINTD_SYSTEM_ROOT/run/mintd"
MINTD_SYSTEM_BINARY="$MINTD_SECRET_DIR/pairling-tailnet-mintd"
MINTD_LOGS_DIR="/Library/Logs/Pairling"
MCP_SERVER_DIR="$HOME/.claude/mcp-servers"
MCP_SERVER_SHIM="$MCP_SERVER_DIR/phone-tools.py"
PYTHON3_BIN="${PAIRLING_DAEMON_PYTHON:-${COMPANION_DAEMON_PYTHON:-$(command -v python3)}}"
GUARDIAN_PYTHON_BIN="${PAIRLING_GUARDIAN_PYTHON:-${COMPANION_GUARDIAN_PYTHON:-/usr/bin/python3}}"
# P3 Python custody: the npm shim points PAIRLING_DAEMON_PYTHON at the vendored
# CPython inside the platform runtime package (…/python/bin/python3). When that
# is in play we stage the whole interpreter into the release tree and run the
# daemon under it, so a Pairling-signed python (identity dev.pairling.python),
# not a generic system python3, owns the daemon's TCC grants — and npm churn
# can't remove the running interpreter.
PYTHON_CODESIGN_IDENTIFIER="dev.pairling.python"
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

append_history() {
  local status="$1"
  local detail="$2"
  mkdir -p "$STATE_ROOT"
  python3 - "$INSTALL_HISTORY" "$status" "$detail" "$VERSION" "$REVISION" "$RELEASE_ROOT" <<'PY'
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

run_compile_checks() {
  local pycache_root
  pycache_root="$(mktemp -d)"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/pairlingd.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/runtime_contract.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/runtime_manifest.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/runtime_paths.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/pairdrop_store.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/pairling_connectd_status.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/pairling_devices.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/local_mcp_bridge.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/llm_route.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/pairling_tools.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/pairling_pairing.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/pairling_psk.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/pairling_relay_claims.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/request_proof.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/codex_approval.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/pty_broker.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/pty_broker_client.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/pty_broker_service.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/terminal_screen_backend.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/terminal_text_sanitizer.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/push_dispatcher.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/push_event_catalog.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/live_activity_publisher.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/standard_push_publisher.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/safety_monitor.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/sentinel_notifications.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/workstate_feed_contract.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/model_status_contract.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/substrate_status_contract.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/integrations/__init__.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/integrations/aperture_cli/__init__.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/integrations/aperture_cli/launch.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/integrations/aperture_cli/status.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/providers/__init__.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/providers/base.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/providers/claude.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/providers/codex.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/providers/external.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/providers/registry.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/mcp/phone_tools.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/guardian/companion-power-guardian.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/guardian/guardian_contract.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/install/render-launchd.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/install/psk_dependency_check.py"
  rm -rf "$pycache_root"
}

run_psk_dependency_import_check() {
  local python_bin="$1"
  local companiond_path="$2"
  local label="$3"
  "$python_bin" "$REPO_ROOT/mac/install/psk_dependency_check.py" "$companiond_path" --label "$label"
}

run_psk_dependency_checks() {
  run_psk_dependency_import_check "$PYTHON3_BIN" "$REPO_ROOT/mac/companiond" "source-tree preflight"
}

run_staged_psk_dependency_checks() {
  local tmp="$1"
  local staged_python="$PYTHON3_BIN"
  if [[ -x "$tmp/python/bin/python3" ]]; then
    staged_python="$tmp/python/bin/python3"
  fi
  run_psk_dependency_import_check "$staged_python" "$tmp/companiond" "staged runtime copy"
}

ensure_state() {
  mkdir -p "$RELEASES_ROOT" "$STATE_ROOT" "$PAIR_ROOT" "$LOGS_ROOT" "$PLIST_BUILD_DIR" "$APP_SUPPORT/modules"
  chmod 700 "$APP_SUPPORT" "$PAIR_ROOT" 2>/dev/null || true
  if [[ ! -f "$CONFIG_FILE" ]]; then
    python3 - "$CONFIG_FILE" "$PAIRLING_RUNTIME_PORT" <<'PY'
import json
import secrets
import sys
from datetime import datetime, timezone
path, port = sys.argv[1:]
payload = {
    "schema_version": 1,
    "product": "Pairling",
    "install_id": "inst_" + secrets.token_urlsafe(18),
    "runtime": {
        "label": "dev.pairling.companiond",
        "port": int(port),
    },
    "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
}
with open(path, "w") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
    chmod 600 "$CONFIG_FILE" 2>/dev/null || true
  fi
  python3 - "$DEVICES_DB" <<'PY'
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
  PAIRLING_APP_SUPPORT_ROOT="$APP_SUPPORT" PAIRLING_MCP_CREDENTIAL="$MCP_CREDENTIAL" python3 - "$REPO_ROOT" <<'PY'
import sys

repo_root = sys.argv[1]
sys.path.insert(0, repo_root + "/mac/companiond")

from local_mcp_bridge import ensure_local_mcp_bridge_device

ensure_local_mcp_bridge_device()
PY
}

clear_release_quarantine() {
  local target="$1"
  if command -v xattr >/dev/null 2>&1; then
    xattr -dr com.apple.quarantine "$target" >/dev/null 2>&1 || true
  fi
}

copy_release() {
  local tmp="$RELEASE_ROOT.tmp"
  rm -rf "$tmp"
  mkdir -p "$tmp/bin" "$tmp/companiond" "$tmp/companiond/providers" "$tmp/companiond/integrations/aperture_cli" "$tmp/connectd" "$tmp/guardian" "$tmp/mac" "$tmp/mcp"
  cp "$REPO_ROOT/mac/companiond/pairlingd.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/runtime_contract.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/runtime_manifest.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/runtime_paths.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairdrop_store.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairling_connectd_status.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairling_devices.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/local_mcp_bridge.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/llm_route.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairling_tools.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairling_pairing.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairling_psk.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairling_relay_claims.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/request_proof.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/codex_approval.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pty_broker.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pty_broker_client.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pty_broker_service.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/terminal_screen_backend.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/terminal_text_sanitizer.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/push_dispatcher.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/push_event_catalog.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/live_activity_publisher.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/standard_push_publisher.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/safety_monitor.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/sentinel_notifications.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/workstate_feed_contract.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/model_status_contract.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/substrate_status_contract.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/integrations/__init__.py" "$tmp/companiond/integrations/"
  cp "$REPO_ROOT/mac/companiond/integrations/aperture_cli/"*.py "$tmp/companiond/integrations/aperture_cli/"
  cp "$REPO_ROOT/mac/companiond/providers/"*.py "$tmp/companiond/providers/"
  cp "$REPO_ROOT/mac/mcp/phone_tools.py" "$tmp/mcp/"
  cp "$REPO_ROOT/mac/guardian/companion-power-guardian.py" "$tmp/guardian/"
  cp "$REPO_ROOT/mac/guardian/guardian_contract.py" "$tmp/guardian/"
  build_connectd_binary "$tmp/connectd/pairling-connectd"
  build_mintd_binary "$tmp/connectd/pairling-tailnet-mintd"
  stage_vendored_python "$tmp/python"
  run_staged_psk_dependency_checks "$tmp"
  copy_runtime_source_tree "$tmp/mac" "$tmp/connectd/pairling-connectd" "$tmp/connectd/pairling-tailnet-mintd"
  write_installed_pairling_launcher "$tmp/bin/pairling"
  chmod 755 "$tmp/bin/pairling" "$tmp/companiond/pairlingd.py" "$tmp/mcp/phone_tools.py" "$tmp/guardian/companion-power-guardian.py"
  chmod 755 "$tmp/connectd/pairling-connectd" "$tmp/connectd/pairling-tailnet-mintd"
  chmod 644 "$tmp/companiond/"*.py "$tmp/mcp/"*.py "$tmp/guardian/"*.py
  chmod 644 "$tmp/companiond/providers/"*.py
  chmod 644 "$tmp/companiond/integrations/"*.py "$tmp/companiond/integrations/aperture_cli/"*.py
  chmod 755 "$tmp/companiond/pairlingd.py" "$tmp/mcp/phone_tools.py" "$tmp/guardian/companion-power-guardian.py"
  clear_release_quarantine "$tmp"
  rm -rf "$RELEASE_ROOT"
  mv "$tmp" "$RELEASE_ROOT"
  write_manifest "$RELEASE_ROOT"
}

copy_runtime_source_tree() {
  local mac_root="$1"
  local connectd_binary="$2"
  local mintd_binary="$3"
  mkdir -p \
    "$mac_root/companiond" \
    "$mac_root/companiond/providers" \
    "$mac_root/companiond/integrations/aperture_cli" \
    "$mac_root/connectd/bin" \
    "$mac_root/guardian" \
    "$mac_root/install" \
    "$mac_root/mcp" \
    "$mac_root/packaging/bin"
  cp "$REPO_ROOT/mac/VERSION" "$mac_root/"
  printf '%s\n' "$REVISION" > "$mac_root/SOURCE_REVISION"
  printf '%s\n' "$BRANCH" > "$mac_root/SOURCE_BRANCH"
  printf '%s\n' "$SOURCE_DIRTY" > "$mac_root/SOURCE_DIRTY"
  cp "$REPO_ROOT/mac/companiond/"*.py "$mac_root/companiond/"
  # WS2: co-locate the canonical App Attest validator with the daemon so
  # app_attest_lan can import it in the staged runtime (the repo keeps the one
  # source of truth in relay/). Non-fatal if absent — the gate fails closed.
  cp "$REPO_ROOT/relay/app_attest_validator.py" "$mac_root/companiond/" 2>/dev/null || true
  cp "$REPO_ROOT/mac/companiond/providers/"*.py "$mac_root/companiond/providers/"
  cp "$REPO_ROOT/mac/companiond/integrations/__init__.py" "$mac_root/companiond/integrations/"
  cp "$REPO_ROOT/mac/companiond/integrations/aperture_cli/"*.py "$mac_root/companiond/integrations/aperture_cli/"
  cp "$REPO_ROOT/mac/connectd/go.mod" "$mac_root/connectd/"
  cp "$REPO_ROOT/mac/connectd/go.sum" "$mac_root/connectd/"
  cp -R "$REPO_ROOT/mac/connectd/cmd" "$mac_root/connectd/"
  cp -R "$REPO_ROOT/mac/connectd/internal" "$mac_root/connectd/"
  cp "$connectd_binary" "$mac_root/connectd/bin/pairling-connectd"
  cp "$mintd_binary" "$mac_root/connectd/bin/pairling-tailnet-mintd"
  cp "$REPO_ROOT/mac/guardian/"*.py "$mac_root/guardian/"
  cp "$REPO_ROOT/mac/install/"*.sh "$mac_root/install/"
  cp "$REPO_ROOT/mac/install/"*.py "$mac_root/install/"
  cp "$REPO_ROOT/mac/mcp/"*.py "$mac_root/mcp/"
  cp "$REPO_ROOT/mac/packaging/bin/pairling" "$mac_root/packaging/bin/"
  chmod 755 "$mac_root/connectd/bin/pairling-connectd" "$mac_root/connectd/bin/pairling-tailnet-mintd" "$mac_root/install/"*.sh "$mac_root/mcp/phone_tools.py" "$mac_root/packaging/bin/pairling"
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
# and the dev.pairling.python identifier. On success, repoint PYTHON3_BIN at the
# STAGED interpreter so the daemon plist never references the npm package path.
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
    exit 1
  fi
  local team identifier
  identifier="$(/usr/bin/codesign -dvv "$src_tree/bin/python3" 2>&1 | sed -n 's/^Identifier=//p')"
  if [[ "$identifier" != "$PYTHON_CODESIGN_IDENTIFIER" ]]; then
    log "ERROR: vendored python identifier '${identifier:-none}' is not '$PYTHON_CODESIGN_IDENTIFIER'; refusing to stage." >&2
    exit 1
  fi
  if [[ "$required_team" == "-" ]]; then
    log "WARNING: vendored python Team ID pin disabled (PAIRLING_CONNECTD_TEAM_ID=-). Dev builds only."
  else
    team="$(/usr/bin/codesign -dvv "$src_tree/bin/python3" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
    if [[ "$team" != "$required_team" ]]; then
      log "ERROR: vendored python TeamIdentifier '${team:-none}' does not match required '$required_team'; refusing to stage." >&2
      exit 1
    fi
  fi
  rm -rf "$dest"
  mkdir -p "$(dirname "$dest")"
  cp -R "$src_tree" "$dest"
  chmod 755 "$dest/bin/python3" 2>/dev/null || true
  # Point the daemon at the interpreter through the stable `current` symlink
  # (not $dest, which is the pre-move temp path) so the plist resolves after the
  # release is moved into place and after rollback — exactly like connectd.
  PYTHON3_BIN="$CURRENT_LINK/python/bin/python3"
  log "Staged vendored CPython (daemon will run under dev.pairling.python via $PYTHON3_BIN)"
}

build_connectd_binary() {
  local out="$1"
  # npm-delivered binary: the shim points PAIRLING_CONNECTD_PREBUILT at the
  # platform runtime package. This path is fail-closed: the binary must carry
  # a valid signature from the pinned Team ID or setup refuses to stage it.
  local prebuilt_env="${PAIRLING_CONNECTD_PREBUILT:-}"
  if [[ -n "$prebuilt_env" ]]; then
    if [[ ! -f "$prebuilt_env" ]]; then
      log "ERROR: PAIRLING_CONNECTD_PREBUILT points at a missing file: $prebuilt_env" >&2
      exit 1
    fi
    local required_team="${PAIRLING_CONNECTD_TEAM_ID:-965AVD34A3}"
    if [[ "$required_team" == "-" ]]; then
      log "WARNING: connectd signature verification disabled (PAIRLING_CONNECTD_TEAM_ID=-). Dev builds only."
    else
      if ! /usr/bin/codesign --verify --strict "$prebuilt_env" >/dev/null 2>&1; then
        log "ERROR: connectd binary failed codesign verification; refusing to stage: $prebuilt_env" >&2
        exit 1
      fi
      local team
      team="$(/usr/bin/codesign -dvv "$prebuilt_env" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
      if [[ "$team" != "$required_team" ]]; then
        log "ERROR: connectd binary TeamIdentifier '${team:-none}' does not match required '$required_team'; refusing to stage: $prebuilt_env" >&2
        exit 1
      fi
    fi
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
    "$go_bin" build -o "$out" ./cmd/pairling-connectd
  )
}

build_mintd_binary() {
  local out="$1"
  local prebuilt_env="${PAIRLING_MINTD_PREBUILT:-}"
  if [[ -n "$prebuilt_env" ]]; then
    if [[ ! -f "$prebuilt_env" ]]; then
      log "ERROR: PAIRLING_MINTD_PREBUILT points at a missing file: $prebuilt_env" >&2
      exit 1
    fi
    local required_team="${PAIRLING_MINTD_TEAM_ID:-${PAIRLING_CONNECTD_TEAM_ID:-965AVD34A3}}"
    if [[ "$required_team" != "-" ]]; then
      if ! /usr/bin/codesign --verify --strict "$prebuilt_env" >/dev/null 2>&1; then
        log "ERROR: mintd binary failed codesign verification; refusing to stage: $prebuilt_env" >&2
        exit 1
      fi
      local team
      team="$(/usr/bin/codesign -dvv "$prebuilt_env" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
      if [[ "$team" != "$required_team" ]]; then
        log "ERROR: mintd binary TeamIdentifier '${team:-none}' does not match required '$required_team'; refusing to stage: $prebuilt_env" >&2
        exit 1
      fi
    fi
    cp "$prebuilt_env" "$out"
    chmod 755 "$out"
    return
  fi
  local prebuilt="$REPO_ROOT/mac/connectd/bin/pairling-tailnet-mintd"
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
    log "ERROR: go is required to build pairling-tailnet-mintd" >&2
    exit 1
  fi
  (
    cd "$REPO_ROOT/mac/connectd"
    "$go_bin" build -o "$out" ./cmd/pairling-tailnet-mintd
  )
}

write_manifest() {
  local root="$1"
  python3 - "$REPO_ROOT" "$root" "$VERSION" "$REVISION" "$BRANCH" "$SOURCE_DIRTY" "$APP_SUPPORT" "$LOGS_ROOT" "$DEVICES_DB" "$PAIRLING_RUNTIME_PORT" <<'PY'
import getpass
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

repo_root, install_root, version, revision, branch, dirty, app_support, logs_root, devices_db, port = sys.argv[1:]
root = Path(install_root)
files = []
for rel in [
    "bin/pairling",
    "companiond/pairlingd.py",
    "companiond/runtime_contract.py",
    "companiond/runtime_manifest.py",
    "companiond/runtime_paths.py",
    "companiond/pairdrop_store.py",
    "companiond/pairling_connectd_status.py",
    "companiond/pairling_devices.py",
    "companiond/local_mcp_bridge.py",
    "companiond/llm_route.py",
    "companiond/pairling_tools.py",
    "companiond/pairling_pairing.py",
    "companiond/pairling_psk.py",
    "companiond/pairling_relay_claims.py",
    "companiond/request_proof.py",
    "companiond/codex_approval.py",
    "companiond/pty_broker.py",
    "companiond/pty_broker_client.py",
    "companiond/pty_broker_service.py",
    "companiond/terminal_screen_backend.py",
    "companiond/terminal_text_sanitizer.py",
    "companiond/push_dispatcher.py",
    "companiond/push_event_catalog.py",
    "companiond/live_activity_publisher.py",
    "companiond/standard_push_publisher.py",
    "companiond/safety_monitor.py",
    "companiond/sentinel_notifications.py",
    "companiond/workstate_feed_contract.py",
    "companiond/model_status_contract.py",
    "companiond/substrate_status_contract.py",
    "companiond/integrations/__init__.py",
    "companiond/integrations/aperture_cli/__init__.py",
    "companiond/integrations/aperture_cli/launch.py",
    "companiond/integrations/aperture_cli/status.py",
    "companiond/providers/__init__.py",
    "companiond/providers/base.py",
    "companiond/providers/claude.py",
    "companiond/providers/codex.py",
    "companiond/providers/external.py",
    "companiond/providers/registry.py",
    "connectd/pairling-connectd",
    "connectd/pairling-tailnet-mintd",
    "mcp/phone_tools.py",
    "guardian/companion-power-guardian.py",
    "guardian/guardian_contract.py",
]:
    path = root / rel
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    files.append({"path": rel, "sha256": digest})

now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
manifest = {
    "schema_version": 1,
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
    "install_root": str(root),
    "current_symlink": str(root.parent.parent / "current"),
    "runtime": {
        "port": int(port),
        "auth": "per-device-scoped-bearer",
        "token_registry": devices_db,
    },
    "launchd": {
        "daemon_label": "dev.pairling.companiond",
        "ptybroker_label": "dev.pairling.ptybroker",
        "connectd_label": "dev.pairling.connectd",
        "mintd_label": "dev.pairling.mintd",
        "guardian_label": "dev.pairling.power-guardian",
    },
    "paths": {
        "app_support": app_support,
        "logs": logs_root,
        "pair_records": str(Path(app_support) / "pair"),
        "guardian_state": "/var/run/pairling-power-state.json",
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
    "files": files,
}
(root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY
}

switch_current() {
  if [[ -L "$CURRENT_LINK" ]]; then
    local old
    old="$(readlink "$CURRENT_LINK")"
    if [[ -n "$old" ]]; then
      rm -f "$PREVIOUS_LINK"
      ln -s "$old" "$PREVIOUS_LINK"
    fi
  fi
  rm -f "$CURRENT_LINK"
  ln -s "$RELEASE_ROOT" "$CURRENT_LINK"
}

install_mcp_adapter_shim() {
  mkdir -p "$MCP_SERVER_DIR"
  python3 - "$MCP_SERVER_SHIM" "$CURRENT_LINK/mcp/phone_tools.py" <<'PY'
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
}

install_shell_wrapper() {
  local user_bin="${PAIRLING_USER_BIN_DIR:-$HOME/.local/bin}"
  local target="$user_bin/pairling"
  local tmp="$target.tmp"
  mkdir -p "$user_bin"
  cat >"$tmp" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${PAIRLING_REPO_ROOT:-}" ]]; then
  exec "$PAIRLING_REPO_ROOT/mac/packaging/bin/pairling" "$@"
fi

find_npm_pairling_shim() {
  local wrapper_path="$1"
  local old_ifs="$IFS"
  local dir candidate
  IFS=:
  for dir in $PATH; do
    [[ -n "$dir" ]] || dir="."
    candidate="$dir/pairling"
    if [[ -x "$candidate" && "$candidate" != "$wrapper_path" ]] && "$candidate" --shim-print-env >/dev/null 2>&1; then
      IFS="$old_ifs"
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  IFS="$old_ifs"
  return 1
}

case "${1:-}" in
  setup|install|update|upgrade)
    WRAPPER_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    if NPM_PAIRLING="$(find_npm_pairling_shim "$WRAPPER_PATH")"; then
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
  chmod 755 "$tmp"
  mv "$tmp" "$target"
}

mintd_provisioned() {
  # Architecture B (minting) is enabled in the companiond env once the
  # separate-uid mint broker has been installed by the explicit, consent-gated
  # `pairling enable-silent-join` flow. The broker's LaunchDaemon plist lives in
  # /Library/LaunchDaemons (root:wheel 0644, world-readable), so this steady-
  # state check needs no elevated privileges, and a plain setup never prompts
  # for a password. Architecture A (browser-login) stays the fallback whenever the
  # broker is absent; the credential gate is enforced at install time by
  # enable_silent_join + install_mintd_if_possible.
  if is_dry_run; then return 1; fi
  [[ -f "$MINTD_SYSTEM_PLIST" ]]
}

render_plists() {
  # Prefer the staged vendored interpreter whenever it exists, so start/
  # rollback (which don't re-stage) also run the daemon under dev.pairling.python.
  local daemon_python="$PYTHON3_BIN"
  if [[ -x "$CURRENT_LINK/python/bin/python3" ]]; then
    daemon_python="$CURRENT_LINK/python/bin/python3"
  fi
  local -a render_args=(
    --current-root "$CURRENT_LINK"
    --logs-root "$LOGS_ROOT"
    --output-dir "$PLIST_BUILD_DIR"
    --daemon-python "$daemon_python"
    --guardian-python "$GUARDIAN_PYTHON_BIN"
  )
  if mintd_provisioned; then
    render_args+=(--mint-enabled)
  fi
  python3 "$REPO_ROOT/mac/install/render-launchd.py" "${render_args[@]}"
}

start_user_agent() {
  mkdir -p "$HOME/Library/LaunchAgents"
  cp "$PLIST_BUILD_DIR/$PAIRLING_DAEMON_LABEL.plist" "$USER_PLIST"
  chmod 644 "$USER_PLIST"
  if is_dry_run; then
    log "dry-run: rendered $USER_PLIST"
    return
  fi
  launchctl bootout "gui/$(id -u)" "$USER_PLIST" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/$(id -u)" "$USER_PLIST" >/dev/null 2>&1 || true
  launchctl kickstart -k "gui/$(id -u)/$PAIRLING_DAEMON_LABEL"
}

start_connectd_agent() {
  mkdir -p "$HOME/Library/LaunchAgents"
  cp "$PLIST_BUILD_DIR/$PAIRLING_CONNECTD_LABEL.plist" "$CONNECTD_USER_PLIST"
  chmod 644 "$CONNECTD_USER_PLIST"
  if is_dry_run; then
    log "dry-run: rendered $CONNECTD_USER_PLIST"
    return
  fi
  launchctl bootout "gui/$(id -u)" "$CONNECTD_USER_PLIST" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/$(id -u)" "$CONNECTD_USER_PLIST" >/dev/null 2>&1 || true
  launchctl kickstart -k "gui/$(id -u)/$PAIRLING_CONNECTD_LABEL"
}

ptybroker_live_session_count() {
  local status_json
  if status_json="$(ptybroker_status_json 2>/dev/null)"; then
    python3 - "$status_json" <<'PY'
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
  python3 - "$CURRENT_LINK" <<'PY'
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
  python3 - "${1:-{}}" <<'PY'
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
  python3 - "$CURRENT_LINK" "${1:-{}}" <<'PY'
import json
import os
import sys
from pathlib import Path

current = Path(sys.argv[1])
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

payload = load_json_arg(sys.argv[2])
live = payload.get("status") if isinstance(payload.get("status"), dict) else payload

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
    "protocol_version": 1,
}
reasons = []
live_root = live.get("runtime_root")
if live_root:
    if os.path.realpath(str(live_root)) != str(desired_root):
        reasons.append("runtime_root_mismatch")
else:
    reasons.append("runtime_root_missing")
live_script = live.get("script_path")
if live_script:
    if os.path.realpath(str(live_script)) != str(desired["script_path"]):
        reasons.append("script_path_mismatch")
else:
    reasons.append("script_path_missing")
live_revision = live.get("source_revision")
if desired["source_revision"] and not live_revision:
    reasons.append("source_revision_missing")
elif live_revision and desired["source_revision"] and str(live_revision) != str(desired["source_revision"]):
    reasons.append("source_revision_mismatch")
try:
    live_protocol = int(live.get("protocol_version") or 0)
except (TypeError, ValueError):
    live_protocol = 0
if live_protocol != desired["protocol_version"]:
    if not live.get("protocol_version"):
        reasons.append("protocol_version_missing")
    else:
        reasons.append("protocol_version_mismatch")
state = "current" if not reasons else "stale_deferred"
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
  python3 - "$state_json" <<'PY'
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
if state.get("state") != "stale_deferred":
    raise SystemExit(0)
live = state.get("live") if isinstance(state.get("live"), dict) else {}
desired = state.get("desired") if isinstance(state.get("desired"), dict) else {}
print(
    "WARNING: ptybroker running older code; normal install preserved live PTYs; "
    "broker restart is deferred; "
    f"live_source_revision={live.get('source_revision')} "
    f"desired_source_revision={desired.get('source_revision')} "
    f"live_pid={live.get('pid')} "
    f"live_session_count={live.get('live_session_count')}"
)
PY
}

ptybroker_state_field() {
  python3 - "$1" "$2" <<'PY'
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

ensure_ptybroker_agent() {
  mkdir -p "$HOME/Library/LaunchAgents"
  local rendered="$PLIST_BUILD_DIR/$PAIRLING_PTYBROKER_LABEL.plist"
  local changed=0
  if [[ ! -f "$PTYBROKER_USER_PLIST" ]] || ! cmp -s "$rendered" "$PTYBROKER_USER_PLIST"; then
    cp "$rendered" "$PTYBROKER_USER_PLIST"
    chmod 644 "$PTYBROKER_USER_PLIST"
    changed=1
  fi
  if is_dry_run; then
    if [[ "$changed" == "1" ]]; then
      log "dry-run: rendered $PTYBROKER_USER_PLIST"
    else
      log "dry-run: $PTYBROKER_USER_PLIST unchanged"
    fi
    return
  fi
  if ! launchctl print "gui/$(id -u)/$PAIRLING_PTYBROKER_LABEL" >/dev/null 2>&1; then
    launchctl bootstrap "gui/$(id -u)" "$PTYBROKER_USER_PLIST" >/dev/null 2>&1 || true
    launchctl kickstart "gui/$(id -u)/$PAIRLING_PTYBROKER_LABEL" >/dev/null 2>&1 || true
    return
  fi
  local status_json
  if status_json="$(ptybroker_status_json 2>/dev/null)"; then
    ptybroker_report_deferred_restart "$status_json"
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
  ensure_state
  render_plists
  mkdir -p "$HOME/Library/LaunchAgents"
  cp "$PLIST_BUILD_DIR/$PAIRLING_PTYBROKER_LABEL.plist" "$PTYBROKER_USER_PLIST"
  chmod 644 "$PTYBROKER_USER_PLIST"
  if is_dry_run; then
    log "dry-run: would reconcile $PAIRLING_PTYBROKER_LABEL"
    return
  fi
  if ! launchctl print "gui/$(id -u)/$PAIRLING_PTYBROKER_LABEL" >/dev/null 2>&1; then
    launchctl bootstrap "gui/$(id -u)" "$PTYBROKER_USER_PLIST" >/dev/null 2>&1 || true
    launchctl kickstart "gui/$(id -u)/$PAIRLING_PTYBROKER_LABEL" >/dev/null 2>&1 || true
    log "Started $PAIRLING_PTYBROKER_LABEL"
    return
  fi
  local status_json state_json live_count live_pid
  if ! status_json="$(ptybroker_status_json 2>/dev/null)"; then
    log "ERROR: ptybroker is loaded but status RPC is unreachable; refusing reconcile until socket is reachable or broker is manually stopped." >&2
    exit 1
  fi
  state_json="$(ptybroker_deployment_state_json "$status_json")"
  live_count="$(ptybroker_state_field "$state_json" "live.live_session_count")"
  live_pid="$(ptybroker_state_field "$state_json" "live.pid")"
  if [[ "${live_count:-0}" != "0" ]]; then
    log "ERROR: ptybroker restart deferred: live_session_count=$live_count live_pid=$live_pid; close/drain live PTYs before broker code can be updated." >&2
    exit 1
  fi
  log "Operator requested idle ptybroker reconcile; restarting broker live_pid=$live_pid live_session_count=0"
  launchctl bootout "gui/$(id -u)/$PAIRLING_PTYBROKER_LABEL" >/dev/null 2>&1 || true
  launchctl bootout "gui/$(id -u)" "$PTYBROKER_USER_PLIST" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/$(id -u)" "$PTYBROKER_USER_PLIST" >/dev/null 2>&1 || true
  launchctl kickstart -k "gui/$(id -u)/$PAIRLING_PTYBROKER_LABEL"
  status_json="$(ptybroker_status_json)"
  state_json="$(ptybroker_deployment_state_json "$status_json")"
  if [[ "$(ptybroker_state_field "$state_json" "state")" != "current" ]]; then
    log "ERROR: ptybroker restart completed but status is not current: $state_json" >&2
    exit 1
  fi
  log "Reconciled $PAIRLING_PTYBROKER_LABEL with current runtime"
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

stop_mintd_daemon() {
  if is_dry_run; then
    log "dry-run: would stop $PAIRLING_MINTD_LABEL"
    return
  fi
  if sudo -n true >/dev/null 2>&1; then
    sudo launchctl bootout system "$MINTD_SYSTEM_PLIST" >/dev/null 2>&1 || true
  fi
}

install_guardian_if_possible() {
  local rendered="$PLIST_BUILD_DIR/$PAIRLING_GUARDIAN_LABEL.plist"
  if [[ "${PAIRLING_INSTALL_GUARDIAN:-0}" != "1" ]]; then
    log "Optional power guardian not installed; pairing can continue without the privileged sleep helper."
    return
  fi
  if is_dry_run; then
    log "dry-run: would install $PAIRLING_GUARDIAN_LABEL"
    return
  fi
  if sudo -n true >/dev/null 2>&1; then
    sudo cp "$rendered" "$SYSTEM_PLIST"
    sudo chown root:wheel "$SYSTEM_PLIST"
    sudo chmod 644 "$SYSTEM_PLIST"
    sudo launchctl bootout system "$SYSTEM_PLIST" >/dev/null 2>&1 || true
    sudo launchctl bootstrap system "$SYSTEM_PLIST" >/dev/null 2>&1 || true
    sudo launchctl kickstart -k "system/$PAIRLING_GUARDIAN_LABEL"
  else
    log "Skipping guardian install: passwordless sudo is unavailable. Re-run with privileges when ready."
  fi
}

mintd_uid_in_range() {
  local uid="$1"
  [[ "$uid" =~ ^[0-9]+$ && "$uid" -ge 450 && "$uid" -le 499 ]]
}

ensure_mintd_service_account() {
  if dscl . -read /Users/_pairling_mint >/dev/null 2>&1; then
    local uid real
    uid="$(dscl . -read /Users/_pairling_mint UniqueID | awk '{print $2}')"
    real="$(dscl . -read /Users/_pairling_mint RealName 2>/dev/null | sed '1d;s/^ //')"
    if ! mintd_uid_in_range "$uid"; then
      log "Skipping mintd install: _pairling_mint UID $uid is outside 450-499." >&2
      return 1
    fi
    if [[ "$real" != "Pairling Mint Broker" ]]; then
      log "Skipping mintd install: _pairling_mint RealName is not Pairling Mint Broker." >&2
      return 1
    fi
    return 0
  fi
  local uid=""
  for candidate in $(seq 450 499); do
    if ! dscl . -list /Users UniqueID | awk -v uid="$candidate" '$2 == uid {found=1} END {exit found ? 0 : 1}'; then
      uid="$candidate"
      break
    fi
  done
  if [[ -z "$uid" ]]; then
    log "Skipping mintd install: no free macOS role-account UID in 450-499." >&2
    return 1
  fi
  local pw
  pw="$(uuidgen)-$(uuidgen)"
  sudo sysadminctl -addUser _pairling_mint -fullName "Pairling Mint Broker" -UID "$uid" -GID 20 -shell /usr/bin/false -home /var/empty -password "$pw" -roleAccount >/dev/null
  unset pw
}

install_mintd_if_possible() {
  local rendered="$PLIST_BUILD_DIR/$PAIRLING_MINTD_LABEL.plist"
  local mintd_secret="$MINTD_SECRET_DIR/client_secret.json"
  if is_dry_run; then
    log "dry-run: would install $PAIRLING_MINTD_LABEL when privileged setup is available"
    return
  fi
  if ! sudo -n true >/dev/null 2>&1; then
    log "Skipping mintd install: passwordless sudo is unavailable. Architecture A fallback remains available."
    return
  fi
  if ! sudo test -f "$mintd_secret"; then
    log "Skipping mintd install: OAuth client secret is not provisioned at $mintd_secret."
    return
  fi
  ensure_mintd_service_account || return
  sudo chmod 0600 "$mintd_secret"
  sudo chown _pairling_mint:staff "$mintd_secret"
  sudo install -d -m 0700 -o _pairling_mint -g staff "$MINTD_SECRET_DIR"
  sudo install -d -m 0750 -o _pairling_mint -g staff "$MINTD_RUN_DIR"
  sudo install -d -m 0750 -o _pairling_mint -g staff "$MINTD_LOGS_DIR"
  sudo install -m 0755 -o root -g wheel "$CURRENT_LINK/connectd/pairling-tailnet-mintd" "$MINTD_SYSTEM_BINARY"
  sudo cp "$rendered" "$MINTD_SYSTEM_PLIST"
  sudo chown root:wheel "$MINTD_SYSTEM_PLIST"
  sudo chmod 644 "$MINTD_SYSTEM_PLIST"
  sudo launchctl bootout system "$MINTD_SYSTEM_PLIST" >/dev/null 2>&1 || true
  sudo launchctl bootstrap system "$MINTD_SYSTEM_PLIST" >/dev/null 2>&1 || true
  sudo launchctl kickstart -k "system/$PAIRLING_MINTD_LABEL"
}

enable_silent_join() {
  local client_secret_path=""
  local assume_yes="0"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --client-secret) shift; client_secret_path="${1:-}" ;;
      --yes) assume_yes="1" ;;
      --help|-h) log "usage: pairling enable-silent-join [--client-secret PATH] [--yes]"; return 0 ;;
      *) log "usage: pairling enable-silent-join [--client-secret PATH] [--yes]" >&2; exit 2 ;;
    esac
    shift
  done

  if is_dry_run; then
    log "dry-run: would explain the mint broker, request one-time consent, and install $PAIRLING_MINTD_LABEL under interactive sudo"
    return 0
  fi

  if [[ ! -x "$CURRENT_LINK/connectd/pairling-tailnet-mintd" ]]; then
    log "ERROR: the mint broker binary is not staged. Run 'pairling setup' first." >&2
    exit 1
  fi

  cat <<EOF

Enable silent tailnet join (Architecture B)
-------------------------------------------
This installs a small background service, the mint broker ($PAIRLING_MINTD_LABEL).
It runs under its own macOS account (_pairling_mint), not as the Pairling daemon
and not as you. It holds your Tailscale OAuth client secret so the Pairling
daemon never can: the daemon may ask it for one short-lived, single-use phone
key per pairing, and nothing more.

Installing a system service and a dedicated account needs administrator rights,
so you approve this one time now. After that, every future pairing joins your
tailnet silently, with no browser step.

You provide a Tailscale OAuth client (scope auth_keys, tag tag:pairling-phone)
that you create in your own Tailscale admin console. The secret is stored
readable only by _pairling_mint, is never committed, and is never read by the
Pairling daemon. If you skip this, pairing still works over the browser path
(Architecture A); silent join stays off.

EOF

  local secret_json=""
  if [[ -n "$client_secret_path" ]]; then
    [[ -f "$client_secret_path" ]] || { log "ERROR: --client-secret file not found: $client_secret_path" >&2; exit 1; }
    secret_json="$(cat "$client_secret_path")"
  elif [[ -t 0 ]]; then
    log "Paste the Tailscale OAuth client JSON (with client_id and client_secret), then press Ctrl-D:"
    secret_json="$(cat)"
  else
    log "ERROR: no Tailscale OAuth client provided. Re-run with --client-secret PATH (a JSON file with client_id and client_secret)." >&2
    exit 1
  fi

  if ! printf '%s' "$secret_json" | python3 -c 'import json,sys
d = json.load(sys.stdin)
sys.exit(0 if isinstance(d, dict) and d.get("client_id") and d.get("client_secret") else 1)' >/dev/null 2>&1; then
    log "ERROR: the provided credential is not valid JSON with non-empty client_id and client_secret." >&2
    exit 1
  fi

  if [[ "$assume_yes" != "1" ]]; then
    if [[ ! -t 0 ]]; then
      log "ERROR: enabling silent join needs explicit consent. Re-run with --yes to confirm." >&2
      exit 1
    fi
    printf 'Install the mint broker and enable silent join now? [y/N] '
    local reply=""
    read -r reply
    case "$reply" in
      y|Y|yes|YES) : ;;
      *) log "Silent join not enabled. Pairing continues over the browser path."; return 0 ;;
    esac
  fi

  if ! sudo -v; then
    log "Administrator approval was not granted. Silent join stays off; pairing still works over the browser path." >&2
    exit 1
  fi

  local mintd_secret="$MINTD_SECRET_DIR/client_secret.json"
  local tmp_secret
  tmp_secret="$(mktemp)"
  chmod 600 "$tmp_secret"
  printf '%s' "$secret_json" > "$tmp_secret"
  sudo install -d -m 0700 "$MINTD_SECRET_DIR"
  sudo install -m 0600 "$tmp_secret" "$mintd_secret"
  rm -f "$tmp_secret"

  install_mintd_if_possible
  if [[ ! -f "$MINTD_SYSTEM_PLIST" ]]; then
    log "ERROR: the mint broker did not install. Silent join is not enabled; pairing still works over the browser path." >&2
    exit 1
  fi

  render_plists
  start_user_agent
  log "Silent tailnet join is enabled. Run 'pairling pair --qr' to pair; future pairings join your tailnet with no browser step."
}

run_doctor() {
  "$REPO_ROOT/mac/install/doctor.sh"
}

rollback() {
  if [[ ! -L "$PREVIOUS_LINK" ]]; then
    log "ERROR: no previous runtime symlink exists at $PREVIOUS_LINK" >&2
    exit 1
  fi
  local current_target previous_target
  current_target="$(readlink "$CURRENT_LINK" 2>/dev/null || true)"
  previous_target="$(readlink "$PREVIOUS_LINK")"
  rm -f "$CURRENT_LINK"
  ln -s "$previous_target" "$CURRENT_LINK"
  rm -f "$PREVIOUS_LINK"
  if [[ -n "$current_target" ]]; then
    ln -s "$current_target" "$PREVIOUS_LINK"
  fi
  render_plists
  ensure_ptybroker_agent
  start_user_agent
  start_connectd_agent
  append_history "rollback" "rolled back to $previous_target"
  run_doctor
}

install_runtime() {
  log "Pairling setup preview:"
  log "  app support: $(display_path "$APP_SUPPORT")"
  log "  logs: $(display_path "$LOGS_ROOT")"
  log "  LaunchAgent: $PAIRLING_DAEMON_LABEL"
  log "  PTY Broker LaunchAgent: $PAIRLING_PTYBROKER_LABEL"
  log "  Connect LaunchAgent: $PAIRLING_CONNECTD_LABEL"
  log "  Mint LaunchDaemon: $PAIRLING_MINTD_LABEL"
  log "  runtime port: $PAIRLING_RUNTIME_PORT"
  run_compile_checks
  run_psk_dependency_checks
  ensure_state
  copy_release
  switch_current
  install_mcp_adapter_shim
  install_shell_wrapper
  render_plists
  ensure_ptybroker_agent
  start_user_agent
  start_connectd_agent
  install_guardian_if_possible
  append_history "installed" "installed $RELEASE_NAME"
  if is_dry_run; then
    log "dry-run: skipping doctor gate"
  else
    run_doctor || true
  fi
  log "Installed Pairling runtime $RELEASE_NAME"
  if ! mintd_provisioned; then
    log ""
    log "Silent tailnet join (no browser step) is available but not yet enabled."
    log "Turn it on once, using your own Tailscale account: pairling enable-silent-join"
  fi
  if ! is_dry_run; then
    log ""
    if ! PAIRLING_CONNECTD_ROUTE_WAIT_SECONDS="${PAIRLING_CONNECTD_ROUTE_WAIT_SECONDS:-35}" pair_runtime --qr; then
      log "Pairling installed, but setup could not generate a pairing invitation. Run: pairling doctor --json; pairling pair --qr" >&2
      exit 1
    fi
  fi
}

status_runtime() {
  "$REPO_ROOT/mac/install/doctor.sh" --json || true
}

start_runtime() {
  ensure_state
  render_plists
  ensure_ptybroker_agent
  start_user_agent
  start_connectd_agent
  log "Started $PAIRLING_DAEMON_LABEL"
}

stop_runtime() {
  stop_mintd_daemon
  stop_connectd_agent
  stop_user_agent
  log "Stopped $PAIRLING_DAEMON_LABEL"
}

pair_runtime() {
  local ttl="180"
  local show_qr="0"
  local json_requested="0"
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
          log "usage: pairling pair [--ttl seconds] [--json] [--qr]" >&2
          exit 2
        fi
        ;;
      --help|-h)
        log "usage: pairling pair [--ttl seconds] [--json] [--qr]"
        return
        ;;
      *)
        log "usage: pairling pair [--ttl seconds] [--json] [--qr]" >&2
        exit 2
        ;;
    esac
    shift
  done
  local payload_file
  payload_file="$(mktemp)"
  if python3 - "$PAIRLING_RUNTIME_PORT" "$ttl" "$REPO_ROOT" >"$payload_file" <<'PY'
import json
import ipaddress
import os
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.error
import urllib.request

port, ttl_raw, repo_root = sys.argv[1:]
sys.path.insert(0, os.path.join(repo_root, "mac", "companiond"))
from pairling_connectd_status import advertised_pairling_connect_routes, fetch_connectd_status

try:
    ttl = int(ttl_raw)
except ValueError:
    print(json.dumps({
        "ok": False,
        "error": {"code": "invalid_ttl", "message": "ttl must be an integer"},
    }, indent=2, sort_keys=True), file=sys.stderr)
    raise SystemExit(2)

url = f"http://127.0.0.1:{int(port)}/pair/start"
body = json.dumps({"ttl_seconds": ttl}).encode("utf-8")
request = urllib.request.Request(
    url,
    data=body,
    method="POST",
    headers={"Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.loads(response.read().decode("utf-8"))
except urllib.error.HTTPError as exc:
    try:
        payload = json.loads(exc.read().decode("utf-8"))
    except Exception:
        payload = {
            "ok": False,
            "error": {"code": "http_error", "message": str(exc)},
        }
    print(json.dumps(payload, indent=2, sort_keys=True), file=sys.stderr)
    raise SystemExit(1)
except Exception as exc:
    print(json.dumps({
        "ok": False,
        "error": {
            "code": "runtime_unreachable",
            "message": f"Pairling runtime is not reachable at {url}: {type(exc).__name__}: {exc}",
        },
        "repair": "Run `pairling start` or `pairling doctor --json`, then retry `pairling pair`.",
    }, indent=2, sort_keys=True), file=sys.stderr)
    raise SystemExit(1)

pair_id = str(payload.get("pair_id") or (payload.get("claim") or {}).get("pair_id") or "")
secret = str(
    payload.get("secret")
    or payload.get("secret_qr")
    or (payload.get("claim") or {}).get("secret")
    or ""
)
install_id = str(payload.get("install_id") or "")
mac_name = str(((payload.get("pair_service") or {}).get("txt") or {}).get("mac_name") or socket.gethostname())
# WS3: the Mac ephemeral ECDH public key (base64url) from /pair/start. Carrying it in the
# pair URL is what lets the phone run PSK-authenticated ECDH from the OUT-OF-BAND (QR/paste)
# payload — the secret never goes on the wire. Without it the phone falls back to the legacy
# plaintext claim, so this field is the bridge that actually makes WS3 engage.
mac_ake_pub = str(payload.get("mac_ake_pub") or (payload.get("claim") or {}).get("mac_ake_pub") or "")
# The daemon computes pv authoritatively (3 when minting is enabled server-side,
# 2 for PSK-only). Read it from the same top-level-or-claim shape as mac_ake_pub.
claim_pv = str(payload.get("pv") or (payload.get("claim") or {}).get("pv") or "")

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

def detected_tailnet_ip() -> str:
    override = os.environ.get("PAIRLING_TEST_TAILSCALE_IP")
    if override is not None:
        value = override.strip()
        return value if value.startswith("100.") else ""
    try:
        proc = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=3)
    except Exception:
        return ""
    if proc.returncode != 0:
        return ""
    for line in (proc.stdout or "").splitlines():
        ip = line.strip()
        if ip.startswith("100."):
            return ip
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
        status = fetch_connectd_status(timeout_seconds=0.7)
        connect_routes = advertised_pairling_connect_routes(status)
        if connect_routes:
            return connect_routes[0]
        if wait_seconds <= 0 or time.monotonic() >= deadline or not status_could_be_ready_soon(status):
            return None
        time.sleep(min(poll_seconds, max(0.0, deadline - time.monotonic())))

def default_pair_route(port_number: int) -> dict:
    for key in ("PAIRLING_PAIR_BASE_URL", "PAIRLING_PUBLIC_BASE_URL"):
        value = os.environ.get(key)
        if value:
            return {"base_url": value, "source": "explicit_override", "status": "override"}
    # Remote-first pairing: if connectd reports a ready Pairling Connect route,
    # the QR advertises that route and the iOS app claims it through the
    # embedded pre-pair transport. LAN/Bonjour are explicit degraded fallbacks
    # when Pairling Connect is not ready.
    route = ready_connectd_route()
    if route:
        return {
            "base_url": route["base_url"],
            "source": route["source"],
            "status": route["status"],
            "kind": route["kind"],
        }
    lan_ip = detected_lan_ip()
    if lan_ip:
        return {"base_url": f"http://{lan_ip}:{port_number}", "source": "lan", "status": "fallback", "kind": "lan"}
    if os.environ.get("PAIRLING_DISABLE_BONJOUR") != "1" and os.environ.get("PAIRLING_TEST_DISABLE_BONJOUR") != "1":
        return {"base_url": f"http://{socket.gethostname()}.local:{port_number}", "source": "bonjour", "status": "fallback", "kind": "bonjour"}
    tailnet_ip = detected_tailnet_ip()
    if tailnet_ip:
        return {"base_url": f"http://{tailnet_ip}:{port_number}", "source": "standalone_tailnet", "status": "fallback", "kind": "standalone_tailnet"}
    return {"base_url": f"http://{socket.gethostname()}.local:{port_number}", "source": "bonjour", "status": "fallback", "kind": "bonjour"}

pair_route = default_pair_route(int(port))
base_url = str(pair_route.get("base_url") or "")
if pair_id and secret:
    pair_params = {
        "base": base_url,
        "pair_id": pair_id,
        "secret": secret,
    }
    if mac_ake_pub:
        # WS3: out-of-band delivery of the Mac ECDH key + protocol marker. The phone routes
        # to PSK-authenticated ECDH (secret never transmitted) when both are present; their
        # absence is the legacy plaintext claim. pv=3 requests the B sealed-authkey
        # extension when minting is available; pv=2 remains the PSK-only marker.
        pair_params["mac_ake_pub"] = mac_ake_pub
        # Prefer the daemon's authoritative claim.pv so the QR can't downgrade to
        # pv=2 when the CLI shell lacks PAIRLING_MINT_ENABLED (the daemon has the
        # mint state, the CLI env may not). Fall back to the env marker only for a
        # legacy daemon that does not advertise pv.
        mint_enabled = os.environ.get("PAIRLING_MINT_ENABLED", "").strip().lower() in {"1", "true", "yes"}
        pair_params["pv"] = claim_pv if claim_pv in {"2", "3"} else ("3" if mint_enabled else "2")
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
    # D1: carry the silent-join capability so the phone can warn before the QR is
    # consumed. Only emitted when unavailable (e.g. under tailnet lock); the iOS
    # parser defaults to available when the param is absent.
    claim_block = payload.get("claim") or {}
    if claim_block.get("silent_join_available") is False:
        pair_params["silent_join_available"] = "false"
        reason = str(claim_block.get("silent_join_unavailable_reason") or "")
        if reason:
            pair_params["silent_join_unavailable_reason"] = reason
    manual = {
        "base_url": base_url,
        "pair_id": pair_id,
        "secret": secret,
    }
    if install_id:
        pair_params["install_id"] = install_id
        pair_params["mac_name"] = mac_name
        manual["install_id"] = install_id
        manual["mac_name"] = mac_name
    payload.setdefault("pair_url", "pairling://pair?" + urllib.parse.urlencode(pair_params))
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
  pair_url="$(python3 - "$payload_file" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1]))
print(payload.get("pair_url", ""))
PY
)"

  python3 - "$payload_file" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1]))
manual = payload.get("manual") or {}
print("Pairling pairing invitation ready")
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
  python3 - "$DEVICES_DB" <<'PY'
import json
import sqlite3
import sys
path = sys.argv[1]
try:
    with sqlite3.connect(path) as db:
        rows = db.execute("SELECT device_id, device_name, scopes_json, created_at, last_seen_at, revoked_at FROM devices ORDER BY created_at").fetchall()
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
            "created_at": row[3],
            "last_seen_at": row[4],
            "revoked_at": row[5],
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
  python3 - "$REPO_ROOT" "$DEVICES_DB" "$LOGS_ROOT/audit.jsonl" "$device_id" <<'PY'
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
  python3 - "$REPO_ROOT" "$DEVICES_DB" "$LOGS_ROOT/audit.jsonl" "$device_id" <<'PY'
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
  local output
  if output="$(/usr/bin/curl -sS --max-time 5 -X POST http://127.0.0.1:7774/auth/open 2>/dev/null)"; then
    local response_status
    if python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("ok") else 1)' <<<"$output"; then
      response_status=0
    else
      response_status=1
    fi
    if [[ "$json_mode" == "true" ]]; then
      printf '%s\n' "$output"
    else
      python3 -c 'import json,sys; data=json.load(sys.stdin); print("Pairling Connect browser approval opened." if data.get("opened") else data.get("error", "Pairling Connect browser approval is not available."))' <<<"$output"
    fi
    exit "$response_status"
  fi
  if [[ "$json_mode" == "true" ]]; then
    printf '{"ok":false,"opened":false,"auth_url_present":false,"error":"Pairling Connect auth endpoint unavailable."}\n'
  else
    printf 'Pairling Connect auth endpoint unavailable.\n' >&2
  fi
  exit 1
}

render_pair_qr() {
  local pair_url="$1"
  if ! command -v swift >/dev/null 2>&1; then
    return 1
  fi
  swift - "$pair_url" <<'SWIFT'
import CoreGraphics
import CoreImage
import Foundation

guard CommandLine.arguments.count > 1,
      let message = CommandLine.arguments[1].data(using: .utf8),
      let filter = CIFilter(name: "CIQRCodeGenerator") else {
    exit(2)
}

filter.setValue(message, forKey: "inputMessage")
filter.setValue("M", forKey: "inputCorrectionLevel")

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

let quietZone = 4
let reset = "\u{001B}[0m"
let black = "\u{001B}[40m  "
let white = "\u{001B}[47m  "

for y in (-quietZone)..<(height + quietZone) {
    var line = ""
    for x in (-quietZone)..<(width + quietZone) {
        let dark = x >= 0 && y >= 0 && x < width && y < height && isDark(x, y)
        line += dark ? black : white
    }
    print(line + reset)
}
SWIFT
}

diagnose_runtime() {
  "$REPO_ROOT/mac/install/doctor.sh" --json | python3 -c 'import json,sys; data=json.load(sys.stdin); print(json.dumps(data, indent=2, sort_keys=True))' || true
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
  connect-auth-open
  devices
  unpair <device_id>
  rotate-token <device_id>
  logs
  diagnose --redact
  enable-silent-join [--client-secret PATH] [--yes]
  uninstall
  rollback
EOF
}

cmd="${1:-setup}"
shift || true
case "$cmd" in
  setup|install)
    if [[ "${1:-}" == "--first-run" ]]; then
      shift
      "$REPO_ROOT/mac/install/bootstrap-first-run.sh" "$@"
    else
      install_runtime
    fi
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
    "$REPO_ROOT/mac/install/doctor.sh" "$@"
    ;;
  reconcile-ptybroker|--reconcile-ptybroker|--restart-ptybroker-if-idle)
    reconcile_ptybroker
    ;;
  pair)
    pair_runtime "$@"
    ;;
  enable-silent-join)
    enable_silent_join "$@"
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
    "$REPO_ROOT/mac/install/uninstall-runtime.sh" "$@"
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
