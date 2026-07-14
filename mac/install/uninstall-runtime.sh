#!/usr/bin/env bash
set -euo pipefail

PAIRLING_DAEMON_LABEL="dev.pairling.companiond"
PAIRLING_CONNECTD_LABEL="dev.pairling.connectd"
PAIRLING_PTYBROKER_LABEL="dev.pairling.ptybroker"
APP_SUPPORT="${PAIRLING_APP_SUPPORT_ROOT:-${COMPANION_APP_SUPPORT_ROOT:-$HOME/Library/Application Support/Pairling}}"
while [[ "$APP_SUPPORT" != "/" && "$APP_SUPPORT" == */ ]]; do
  APP_SUPPORT="${APP_SUPPORT%/}"
done
RUNTIME_ROOT="$APP_SUPPORT/runtime"
LOGS_ROOT="${PAIRLING_LOGS_ROOT:-${COMPANION_LOGS_ROOT:-$HOME/Library/Logs/Pairling}}"
while [[ "$LOGS_ROOT" != "/" && "$LOGS_ROOT" == */ ]]; do
  LOGS_ROOT="${LOGS_ROOT%/}"
done
USER_PLIST="$HOME/Library/LaunchAgents/$PAIRLING_DAEMON_LABEL.plist"
CONNECTD_USER_PLIST="$HOME/Library/LaunchAgents/$PAIRLING_CONNECTD_LABEL.plist"
PTYBROKER_USER_PLIST="$HOME/Library/LaunchAgents/$PAIRLING_PTYBROKER_LABEL.plist"
# Legacy: the silent-join mint broker, removed from the product. Torn down below.
MINTD_SYSTEM_LABEL="dev.pairling.mintd"
MINTD_SYSTEM_PLIST="/Library/LaunchDaemons/$MINTD_SYSTEM_LABEL.plist"
MINTD_SYSTEM_DIR="/Library/Application Support/Pairling/mint"
MINTD_SERVICE_ACCOUNT="_pairling_mint"
YES="false"
DELETE_STATE="false"
DELETE_LOGS="false"
DRY_RUN="${PAIRLING_DRY_RUN:-0}"
INSTALL_LOCK_DIR="$RUNTIME_ROOT/.install.lock"
INSTALL_LOCK_HELD=0
APP_SUPPORT_PREEXISTED=0
RUNTIME_ROOT_PREEXISTED=0

usage() {
  cat <<EOF
usage: pairling uninstall [--yes] [--delete-state] [--delete-logs]

Default behavior stops Pairling and removes Pairling launchd plists while
preserving devices, state, logs, provider transcripts, and user projects.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y)
      YES="true"
      ;;
    --delete-state|--remove-runtime)
      DELETE_STATE="true"
      ;;
    --delete-logs)
      DELETE_LOGS="true"
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

is_dry_run() {
  [[ "$DRY_RUN" == "1" || "$DRY_RUN" == "true" || "$DRY_RUN" == "TRUE" ]]
}

launchd_skipped() {
  [[ "${PAIRLING_TESTING_SKIP_LAUNCHD:-0}" == "1" ]]
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

cleanup_created_lock_parents() {
  if [[ "$RUNTIME_ROOT_PREEXISTED" == 0 ]]; then
    rmdir "$RUNTIME_ROOT" 2>/dev/null || true
  fi
  if [[ "$APP_SUPPORT_PREEXISTED" == 0 ]]; then
    rmdir "$APP_SUPPORT" 2>/dev/null || true
  fi
}

fsync_directory() {
  local directory="$1"
  [[ -d "$directory" && ! -L "$directory" ]] || {
    printf 'ERROR: cannot flush unsafe directory: %s\n' "$directory" >&2
    return 1
  }
  if [[ -x /usr/bin/perl ]]; then
    /usr/bin/perl -MIO::Handle -MFcntl=O_RDONLY -e '
      my $path = shift @ARGV;
      sysopen(my $handle, $path, O_RDONLY) or die "open $path: $!\n";
      $handle->sync or die "fsync $path: $!\n";
    ' "$directory"
    return
  fi
  local python_bin
  python_bin="$(command -v python3 2>/dev/null || true)"
  if [[ -n "$python_bin" && -x "$python_bin" ]]; then
    "$python_bin" - "$directory" <<'PY'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
    return
  fi
  printf 'ERROR: Pairling could not find a system helper to flush directory changes.\n' >&2
  return 1
}

uninstall_on_exit() {
  local code=$?
  if ! release_install_lock; then
    code=1
  fi
  cleanup_created_lock_parents
  return "$code"
}

validate_state_target() {
  if [[ -L "$APP_SUPPORT" ]]; then
    if [[ "$DELETE_STATE" == "true" ]]; then
      printf 'ERROR: refusing to delete unsafe Pairling state path: %s\n' "$APP_SUPPORT" >&2
    else
      printf 'ERROR: Pairling app support path must not be a symlink: %s\n' "$APP_SUPPORT" >&2
    fi
    return 1
  fi
  if [[ "$APP_SUPPORT" != /* || "$APP_SUPPORT" == "/" || "$APP_SUPPORT" == "$HOME" ]]; then
    if [[ "$DELETE_STATE" == "true" ]]; then
      printf 'ERROR: refusing to delete unsafe Pairling state path: %s\n' "$APP_SUPPORT" >&2
    else
      printf 'ERROR: Pairling app support path is unsafe: %s\n' "$APP_SUPPORT" >&2
    fi
    return 1
  fi
  case "/$APP_SUPPORT/" in
    */../*|*/./*)
      printf 'ERROR: refusing to delete non-canonical Pairling state path: %s\n' "$APP_SUPPORT" >&2
      return 1
      ;;
  esac
  if [[ -L "$RUNTIME_ROOT" ]]; then
    printf 'ERROR: Pairling runtime path must not be a symlink: %s\n' "$RUNTIME_ROOT" >&2
    return 1
  fi
  if [[ -e "$RUNTIME_ROOT" && ! -d "$RUNTIME_ROOT" ]]; then
    printf 'ERROR: Pairling runtime path must be a directory: %s\n' "$RUNTIME_ROOT" >&2
    return 1
  fi
}

validate_logs_target() {
  [[ "$DELETE_LOGS" == "true" || "$DELETE_STATE" == "true" ]] || return 0
  if [[ "$LOGS_ROOT" != /* || "$LOGS_ROOT" == "/" || "$LOGS_ROOT" == "$HOME" ]]; then
    printf 'ERROR: refusing to delete unsafe Pairling logs path: %s\n' "$LOGS_ROOT" >&2
    return 1
  fi
  case "/$LOGS_ROOT/" in
    */../*|*/./*)
      printf 'ERROR: refusing to delete non-canonical Pairling logs path: %s\n' "$LOGS_ROOT" >&2
      return 1
      ;;
  esac
  if [[ -L "$LOGS_ROOT" ]]; then
    printf 'ERROR: refusing to delete a symlinked Pairling logs path: %s\n' "$LOGS_ROOT" >&2
    return 1
  fi
  case "$APP_SUPPORT/" in
    "$LOGS_ROOT/"*)
      printf 'ERROR: refusing to delete Pairling logs path containing app state: %s\n' "$LOGS_ROOT" >&2
      return 1
      ;;
  esac
  case "$LOGS_ROOT/" in
    "$APP_SUPPORT/"*)
      printf 'ERROR: refusing to delete Pairling logs path inside app state: %s\n' "$LOGS_ROOT" >&2
      return 1
      ;;
  esac
  if [[ -d "$APP_SUPPORT" && -d "$LOGS_ROOT" ]]; then
    local canonical_app_support canonical_logs_root
    canonical_app_support="$(cd "$APP_SUPPORT" && pwd -P)"
    canonical_logs_root="$(cd "$LOGS_ROOT" && pwd -P)"
    case "$canonical_app_support/" in
      "$canonical_logs_root/"*)
        printf 'ERROR: refusing to delete Pairling logs path overlapping app state: %s\n' "$LOGS_ROOT" >&2
        return 1
        ;;
    esac
    case "$canonical_logs_root/" in
      "$canonical_app_support/"*)
        printf 'ERROR: refusing to delete Pairling logs path overlapping app state: %s\n' "$LOGS_ROOT" >&2
        return 1
        ;;
    esac
  fi
  case "$HOME/" in
    "$LOGS_ROOT/"*)
      printf 'ERROR: refusing to delete Pairling logs path containing the home directory: %s\n' "$LOGS_ROOT" >&2
      return 1
      ;;
  esac
}

validate_stale_state_tombstones() {
  local parent base tombstone
  parent="$(dirname "$APP_SUPPORT")"
  base="$(basename "$APP_SUPPORT")"
  [[ -d "$parent" && ! -L "$parent" ]] || return 0
  while IFS= read -r -d '' tombstone; do
    validate_state_tombstone "$tombstone"
  done < <(find -P "$parent" -mindepth 1 -maxdepth 1 -name ".${base}.uninstalling.*" -print0)
}

validate_state_tombstone() {
  local tombstone="$1" parent base prefix suffix owner unexpected
  parent="$(dirname "$APP_SUPPORT")"
  base="$(basename "$APP_SUPPORT")"
  prefix="$parent/.${base}.uninstalling."
  case "$tombstone" in
    "$prefix"*) ;;
    *)
      printf 'ERROR: refusing to recover an unrelated uninstall path: %s\n' "$tombstone" >&2
      return 1
      ;;
  esac
  suffix="${tombstone#"$prefix"}"
  if [[ ! "$suffix" =~ ^[0-9]+$ ]]; then
    printf 'ERROR: refusing to recover a malformed Pairling uninstall path: %s\n' "$tombstone" >&2
    return 1
  fi
  if [[ -L "$tombstone" || ! -d "$tombstone" ]]; then
    printf 'ERROR: refusing to recover a linked or non-directory Pairling uninstall path: %s\n' "$tombstone" >&2
    return 1
  fi
  owner="$(stat -f '%u' "$tombstone" 2>/dev/null || printf 'unknown')"
  if [[ "$owner" != "$(id -u)" ]]; then
    printf 'ERROR: refusing to recover a Pairling uninstall path owned by another user: %s\n' "$tombstone" >&2
    return 1
  fi
  unexpected="$(find -P "$tombstone" -mindepth 1 -maxdepth 1 ! -name state -print -quit 2>/dev/null || true)"
  if [[ -n "$unexpected" ]]; then
    printf 'ERROR: refusing to recover a Pairling uninstall path with unexpected contents: %s\n' "$tombstone" >&2
    return 1
  fi
  if [[ -e "$tombstone/state" || -L "$tombstone/state" ]]; then
    if [[ -L "$tombstone/state" || ! -d "$tombstone/state" ]]; then
      printf 'ERROR: refusing to recover a linked or non-directory Pairling state tombstone: %s\n' "$tombstone/state" >&2
      return 1
    fi
    owner="$(stat -f '%u' "$tombstone/state" 2>/dev/null || printf 'unknown')"
    if [[ "$owner" != "$(id -u)" ]]; then
      printf 'ERROR: refusing to recover Pairling state owned by another user: %s\n' "$tombstone/state" >&2
      return 1
    fi
  fi
}

remove_state_tombstone() {
  local tombstone="$1" parent
  parent="$(dirname "$tombstone")"
  [[ -e "$tombstone" || -L "$tombstone" ]] || return 0
  /bin/chmod -RN "$tombstone" 2>/dev/null || true
  find -P "$tombstone" -type d -exec chmod u+rwx {} + 2>/dev/null || true
  find -P "$tombstone" -type f -exec chmod u+rw {} + 2>/dev/null || true
  rm -rf "$tombstone"
  if [[ -e "$tombstone" || -L "$tombstone" ]]; then
    printf 'ERROR: Pairling could not remove uninstall staging path: %s\n' "$tombstone" >&2
    return 1
  fi
  fsync_directory "$parent"
}

recover_stale_state_tombstones() {
  [[ "$INSTALL_LOCK_HELD" == 1 ]] || {
    printf 'ERROR: refusing to recover Pairling state without the install lock.\n' >&2
    return 1
  }
  local parent base tombstone
  parent="$(dirname "$APP_SUPPORT")"
  base="$(basename "$APP_SUPPORT")"
  while IFS= read -r -d '' tombstone; do
    validate_state_tombstone "$tombstone"
    remove_state_tombstone "$tombstone"
    printf 'Removed interrupted Pairling state deletion: %s\n' "$tombstone"
  done < <(find -P "$parent" -mindepth 1 -maxdepth 1 -name ".${base}.uninstalling.*" -print0)
}

delete_state_under_lock() {
  [[ "$INSTALL_LOCK_HELD" == 1 ]] || {
    printf 'ERROR: refusing to delete Pairling state without the install lock.\n' >&2
    return 1
  }
  [[ -d "$APP_SUPPORT" && ! -L "$APP_SUPPORT" ]] || {
    printf 'ERROR: Pairling state path is not a real directory: %s\n' "$APP_SUPPORT" >&2
    return 1
  }

  local parent base tombstone
  parent="$(dirname "$APP_SUPPORT")"
  base="$(basename "$APP_SUPPORT")"
  tombstone="$parent/.${base}.uninstalling.$$"
  if ! mkdir -m 700 "$tombstone" 2>/dev/null; then
    printf 'ERROR: Pairling could not reserve uninstall staging path: %s\n' "$tombstone" >&2
    return 1
  fi
  if ! mv "$APP_SUPPORT" "$tombstone/state"; then
    rmdir "$tombstone" 2>/dev/null || true
    printf 'ERROR: Pairling could not isolate state for deletion: %s\n' "$APP_SUPPORT" >&2
    return 1
  fi

  INSTALL_LOCK_DIR="$tombstone/state/runtime/.install.lock"
  fsync_directory "$parent"
  release_install_lock
  remove_state_tombstone "$tombstone"
}

confirm() {
  if [[ "$YES" == "true" ]]; then
    return
  fi
  printf 'This will stop Pairling and remove its LaunchAgent.\n'
  printf 'Preserve state: %s\n' "$APP_SUPPORT"
  printf 'Preserve logs:  %s\n' "$LOGS_ROOT"
  printf 'Type "uninstall Pairling" to continue: '
  local answer
  IFS= read -r answer
  if [[ "$answer" != "uninstall Pairling" ]]; then
    printf 'Cancelled.\n' >&2
    exit 1
  fi
}

bootout_user() {
  local label="$1"
  local plist="$2"
  if is_dry_run; then
    printf 'dry-run: would unload %s\n' "$label"
    return
  fi
  if launchd_skipped; then
    printf 'testing: skipped unloading %s\n' "$label"
    return
  fi
  launchctl bootout "gui/$(id -u)/$label" >/dev/null 2>&1 || true
  launchctl bootout "gui/$(id -u)" "$plist" >/dev/null 2>&1 || true
}

bootout_system() {
  local label="$1"
  local plist="$2"
  if [[ ! -f "$plist" ]]; then
    return
  fi
  if is_dry_run; then
    printf 'dry-run: would unload system/%s\n' "$label"
    return
  fi
  if launchd_skipped; then
    printf 'testing: skipped unloading system/%s\n' "$label"
    return
  fi
  if sudo -n true >/dev/null 2>&1; then
    sudo launchctl bootout "system/$label" >/dev/null 2>&1 || true
    sudo launchctl bootout system "$plist" >/dev/null 2>&1 || true
    sudo rm -f "$plist"
  else
    printf 'Skipping %s removal: passwordless sudo is unavailable.\n' "$plist" >&2
  fi
}

# Legacy teardown: the silent-join mint broker (dev.pairling.mintd) was removed
# from the product. Machines that ran the old `enable-silent-join` still carry a
# root LaunchDaemon, a stored Tailscale OAuth secret under the system mint dir,
# and the _pairling_mint role account. Remove all three. Best-effort, sudo-gated.
teardown_legacy_mintd() {
  if [[ ! -f "$MINTD_SYSTEM_PLIST" && ! -d "$MINTD_SYSTEM_DIR" ]] \
     && ! id -u "$MINTD_SERVICE_ACCOUNT" >/dev/null 2>&1; then
    return
  fi
  if is_dry_run; then
    printf 'dry-run: would remove the legacy silent-join mint broker (%s, %s, user %s)\n' \
      "$MINTD_SYSTEM_PLIST" "$MINTD_SYSTEM_DIR" "$MINTD_SERVICE_ACCOUNT"
    return
  fi
  if launchd_skipped; then
    printf 'testing: skipped legacy silent-join mint broker removal\n'
    return
  fi
  if sudo -n true >/dev/null 2>&1; then
    sudo launchctl bootout "system/$MINTD_SYSTEM_LABEL" >/dev/null 2>&1 || true
    sudo launchctl bootout system "$MINTD_SYSTEM_PLIST" >/dev/null 2>&1 || true
    sudo rm -f "$MINTD_SYSTEM_PLIST"
    sudo rm -rf "$MINTD_SYSTEM_DIR"
    sudo /usr/sbin/sysadminctl -deleteUser "$MINTD_SERVICE_ACCOUNT" >/dev/null 2>&1 || true
    printf 'Removed the legacy silent-join mint broker.\n'
  else
    printf 'Skipping legacy mint-broker removal: passwordless sudo is unavailable.\n' >&2
  fi
}

print_dry_run_plan() {
  printf 'dry-run: would acquire install lock %s\n' "$INSTALL_LOCK_DIR"
  bootout_user "$PAIRLING_DAEMON_LABEL" "$USER_PLIST"
  bootout_user "$PAIRLING_CONNECTD_LABEL" "$CONNECTD_USER_PLIST"
  bootout_user "$PAIRLING_PTYBROKER_LABEL" "$PTYBROKER_USER_PLIST"
  printf 'dry-run: would remove LaunchAgent plist %s\n' "$USER_PLIST"
  printf 'dry-run: would remove LaunchAgent plist %s\n' "$CONNECTD_USER_PLIST"
  printf 'dry-run: would remove LaunchAgent plist %s\n' "$PTYBROKER_USER_PLIST"
  teardown_legacy_mintd
  printf 'dry-run: would remove Pairling pairing state %s\n' "$APP_SUPPORT/pair"

  if [[ "$DELETE_LOGS" == "true" ]]; then
    printf 'dry-run: would delete Pairling logs %s\n' "$LOGS_ROOT"
  else
    printf 'dry-run: would preserve Pairling logs %s\n' "$LOGS_ROOT"
  fi

  if [[ "$DELETE_STATE" == "true" ]]; then
    printf 'dry-run: would delete Pairling state %s\n' "$APP_SUPPORT"
  else
    printf 'dry-run: would preserve Pairling state and devices %s\n' "$APP_SUPPORT"
  fi

  printf 'dry-run: provider transcripts and user projects would not be removed.\n'
}

confirm
validate_state_target
validate_logs_target
if is_dry_run; then
  if [[ "$DELETE_STATE" == "true" ]]; then
    validate_stale_state_tombstones
  fi
  print_dry_run_plan
  exit 0
fi
if [[ -e "$APP_SUPPORT" || -L "$APP_SUPPORT" ]]; then
  APP_SUPPORT_PREEXISTED=1
fi
if [[ -e "$RUNTIME_ROOT" || -L "$RUNTIME_ROOT" ]]; then
  RUNTIME_ROOT_PREEXISTED=1
fi
trap uninstall_on_exit EXIT
acquire_install_lock
if [[ "$DELETE_STATE" == "true" ]]; then
  recover_stale_state_tombstones
fi

bootout_user "$PAIRLING_DAEMON_LABEL" "$USER_PLIST"
bootout_user "$PAIRLING_CONNECTD_LABEL" "$CONNECTD_USER_PLIST"
bootout_user "$PAIRLING_PTYBROKER_LABEL" "$PTYBROKER_USER_PLIST"
rm -f "$USER_PLIST"
rm -f "$CONNECTD_USER_PLIST"
rm -f "$PTYBROKER_USER_PLIST"
teardown_legacy_mintd

rm -rf "$APP_SUPPORT/pair" 2>/dev/null || true

if [[ "$DELETE_LOGS" == "true" ]]; then
  rm -rf "$LOGS_ROOT"
  printf 'Deleted Pairling logs: %s\n' "$LOGS_ROOT"
else
  printf 'Preserved Pairling logs: %s\n' "$LOGS_ROOT"
fi

if [[ "$DELETE_STATE" == "true" ]]; then
  delete_state_under_lock
  printf 'Deleted Pairling state: %s\n' "$APP_SUPPORT"
else
  printf 'Preserved Pairling state and devices: %s\n' "$APP_SUPPORT"
  release_install_lock
fi

cleanup_created_lock_parents
trap - EXIT

printf 'Provider transcripts and user projects were not removed.\n'
printf 'Reinstall with: pairling setup\n'
