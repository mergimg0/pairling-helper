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
LEGACY_DAEMON_LABEL="com.mghome.notify-webhook"
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
LEGACY_USER_PLIST="$HOME/Library/LaunchAgents/$LEGACY_DAEMON_LABEL.plist"
SYSTEM_PLIST="/Library/LaunchDaemons/$PAIRLING_GUARDIAN_LABEL.plist"
LEGACY_SYSTEM_PLIST="/Library/LaunchDaemons/com.mghome.companion-power-guardian.plist"
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
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/pairling_relay_claims.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/request_proof.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/pty_broker.py"
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
  rm -rf "$pycache_root"
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
  cp "$REPO_ROOT/mac/companiond/pairling_relay_claims.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/request_proof.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pty_broker.py" "$tmp/companiond/"
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
  stage_vendored_python "$tmp/python"
  copy_runtime_source_tree "$tmp/mac" "$tmp/connectd/pairling-connectd"
  write_installed_pairling_launcher "$tmp/bin/pairling"
  chmod 755 "$tmp/bin/pairling" "$tmp/companiond/pairlingd.py" "$tmp/mcp/phone_tools.py" "$tmp/guardian/companion-power-guardian.py"
  chmod 755 "$tmp/connectd/pairling-connectd"
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
  cp "$REPO_ROOT/mac/companiond/providers/"*.py "$mac_root/companiond/providers/"
  cp "$REPO_ROOT/mac/companiond/integrations/__init__.py" "$mac_root/companiond/integrations/"
  cp "$REPO_ROOT/mac/companiond/integrations/aperture_cli/"*.py "$mac_root/companiond/integrations/aperture_cli/"
  cp "$REPO_ROOT/mac/connectd/go.mod" "$mac_root/connectd/"
  cp "$REPO_ROOT/mac/connectd/go.sum" "$mac_root/connectd/"
  cp -R "$REPO_ROOT/mac/connectd/cmd" "$mac_root/connectd/"
  cp -R "$REPO_ROOT/mac/connectd/internal" "$mac_root/connectd/"
  cp "$connectd_binary" "$mac_root/connectd/bin/pairling-connectd"
  cp "$REPO_ROOT/mac/guardian/"*.py "$mac_root/guardian/"
  cp "$REPO_ROOT/mac/install/"*.sh "$mac_root/install/"
  cp "$REPO_ROOT/mac/install/"*.py "$mac_root/install/"
  cp "$REPO_ROOT/mac/mcp/"*.py "$mac_root/mcp/"
  cp "$REPO_ROOT/mac/packaging/bin/pairling" "$mac_root/packaging/bin/"
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
    "companiond/pairling_relay_claims.py",
    "companiond/request_proof.py",
    "companiond/pty_broker.py",
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
        "connectd_label": "dev.pairling.connectd",
        "guardian_label": "dev.pairling.power-guardian",
        "legacy_daemon_label": "com.mghome.notify-webhook",
    },
    "paths": {
        "app_support": app_support,
        "logs": logs_root,
        "pair_records": str(Path(app_support) / "pair"),
        "guardian_state": "/var/run/pairling-power-state.json",
    },
    "migration": {
        "legacy_port": 7723,
        "legacy_daemon_unloaded_by_setup": True,
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

APP_SUPPORT="${PAIRLING_APP_SUPPORT_ROOT:-${COMPANION_APP_SUPPORT_ROOT:-$HOME/Library/Application Support/Pairling}}"
RUNTIME_PAIRLING="$APP_SUPPORT/runtime/current/bin/pairling"
if [[ -x "$RUNTIME_PAIRLING" ]]; then
  exec "$RUNTIME_PAIRLING" "$@"
fi

printf 'Pairling runtime command is not installed. Run: npm install -g pairling && pairling setup (or use a repo-local mac/packaging/bin/pairling).\n' >&2
exit 127
SH
  chmod 755 "$tmp"
  mv "$tmp" "$target"
}

render_plists() {
  # Prefer the staged vendored interpreter whenever it exists, so start/
  # rollback (which don't re-stage) also run the daemon under dev.pairling.python.
  local daemon_python="$PYTHON3_BIN"
  if [[ -x "$CURRENT_LINK/python/bin/python3" ]]; then
    daemon_python="$CURRENT_LINK/python/bin/python3"
  fi
  python3 "$REPO_ROOT/mac/install/render-launchd.py" \
    --current-root "$CURRENT_LINK" \
    --logs-root "$LOGS_ROOT" \
    --output-dir "$PLIST_BUILD_DIR" \
    --daemon-python "$daemon_python" \
    --guardian-python "$GUARDIAN_PYTHON_BIN"
}

unload_legacy_daemon() {
  if is_dry_run; then
    log "dry-run: would unload $LEGACY_DAEMON_LABEL"
    return
  fi
  launchctl bootout "gui/$(id -u)/$LEGACY_DAEMON_LABEL" >/dev/null 2>&1 || true
  launchctl bootout "gui/$(id -u)" "$LEGACY_USER_PLIST" >/dev/null 2>&1 || true
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

install_guardian_if_possible() {
  local rendered="$PLIST_BUILD_DIR/$PAIRLING_GUARDIAN_LABEL.plist"
  if [[ "${PAIRLING_INSTALL_GUARDIAN:-0}" != "1" ]]; then
    log "Guardian LaunchDaemon rendered but not installed. Set PAIRLING_INSTALL_GUARDIAN=1 to install it."
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

run_doctor() {
  "$REPO_ROOT/mac/install/doctor.sh" --json
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
  start_user_agent
  start_connectd_agent
  append_history "rollback" "rolled back to $previous_target"
  run_doctor
}

install_runtime() {
  log "Pairling setup preview:"
  log "  app support: $APP_SUPPORT"
  log "  logs: $LOGS_ROOT"
  log "  LaunchAgent: $PAIRLING_DAEMON_LABEL"
  log "  Connect LaunchAgent: $PAIRLING_CONNECTD_LABEL"
  log "  runtime port: $PAIRLING_RUNTIME_PORT"
  log "  old Pairling predecessor cleanup label: $LEGACY_DAEMON_LABEL"
  run_compile_checks
  ensure_state
  copy_release
  switch_current
  install_mcp_adapter_shim
  install_shell_wrapper
  render_plists
  unload_legacy_daemon
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
}

status_runtime() {
  "$REPO_ROOT/mac/install/doctor.sh" --json || true
}

start_runtime() {
  ensure_state
  render_plists
  unload_legacy_daemon
  start_user_agent
  start_connectd_agent
  log "Started $PAIRLING_DAEMON_LABEL"
}

stop_runtime() {
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
import os
import socket
import subprocess
import sys
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

def default_pair_route(port_number: int) -> dict:
    for key in ("PAIRLING_PAIR_BASE_URL", "PAIRLING_PUBLIC_BASE_URL"):
        value = os.environ.get(key)
        if value:
            return {"base_url": value, "source": "explicit_override", "status": "override"}
    connect_routes = advertised_pairling_connect_routes(fetch_connectd_status(timeout_seconds=0.7))
    if connect_routes:
        route = connect_routes[0]
        return {
            "base_url": route["base_url"],
            "source": route["source"],
            "status": route["status"],
            "kind": route["kind"],
        }
    tailnet_ip = detected_tailnet_ip()
    if tailnet_ip:
        return {"base_url": f"http://{tailnet_ip}:{port_number}", "source": "standalone_tailnet", "status": "fallback"}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
        finally:
            sock.close()
        if ip and not ip.startswith(("127.", "169.254.")):
            return {"base_url": f"http://{ip}:{port_number}", "source": "lan", "status": "fallback"}
    except Exception:
        pass
    return {"base_url": f"http://{socket.gethostname()}.local:{port_number}", "source": "bonjour", "status": "fallback"}

pair_route = default_pair_route(int(port))
base_url = str(pair_route.get("base_url") or "")
if pair_id and secret:
    pair_params = {
        "base": base_url,
        "pair_id": pair_id,
        "secret": secret,
    }
    if pair_route.get("source") == "pairling_connectd" and pair_route.get("status") == "ready":
        pair_params["route_source"] = "pairling_connectd"
        pair_params["route_status"] = "ready"
        pair_params["route_kind"] = str(pair_route.get("kind") or "tailnet")
        pair_params["route_contract"] = "pairling-runtime-v1"
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
  pair
  connect-auth-open
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
