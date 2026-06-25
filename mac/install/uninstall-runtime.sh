#!/usr/bin/env bash
set -euo pipefail

PAIRLING_DAEMON_LABEL="dev.pairling.companiond"
PAIRLING_GUARDIAN_LABEL="dev.pairling.power-guardian"
PAIRLING_CONNECTD_LABEL="dev.pairling.connectd"
PAIRLING_PTYBROKER_LABEL="dev.pairling.ptybroker"
APP_SUPPORT="${PAIRLING_APP_SUPPORT_ROOT:-${COMPANION_APP_SUPPORT_ROOT:-$HOME/Library/Application Support/Pairling}}"
LOGS_ROOT="${PAIRLING_LOGS_ROOT:-${COMPANION_LOGS_ROOT:-$HOME/Library/Logs/Pairling}}"
USER_PLIST="$HOME/Library/LaunchAgents/$PAIRLING_DAEMON_LABEL.plist"
CONNECTD_USER_PLIST="$HOME/Library/LaunchAgents/$PAIRLING_CONNECTD_LABEL.plist"
PTYBROKER_USER_PLIST="$HOME/Library/LaunchAgents/$PAIRLING_PTYBROKER_LABEL.plist"
SYSTEM_PLIST="/Library/LaunchDaemons/$PAIRLING_GUARDIAN_LABEL.plist"
# Legacy: the silent-join mint broker, removed from the product. Torn down below.
MINTD_SYSTEM_LABEL="dev.pairling.mintd"
MINTD_SYSTEM_PLIST="/Library/LaunchDaemons/$MINTD_SYSTEM_LABEL.plist"
MINTD_SYSTEM_DIR="/Library/Application Support/Pairling/mint"
MINTD_SERVICE_ACCOUNT="_pairling_mint"
YES="false"
DELETE_STATE="false"
DELETE_LOGS="false"
DRY_RUN="${PAIRLING_DRY_RUN:-0}"

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

confirm

bootout_user "$PAIRLING_DAEMON_LABEL" "$USER_PLIST"
bootout_user "$PAIRLING_CONNECTD_LABEL" "$CONNECTD_USER_PLIST"
bootout_user "$PAIRLING_PTYBROKER_LABEL" "$PTYBROKER_USER_PLIST"
rm -f "$USER_PLIST"
rm -f "$CONNECTD_USER_PLIST"
rm -f "$PTYBROKER_USER_PLIST"
bootout_system "$PAIRLING_GUARDIAN_LABEL" "$SYSTEM_PLIST"
teardown_legacy_mintd

rm -rf "$APP_SUPPORT/pair" 2>/dev/null || true

if [[ "$DELETE_STATE" == "true" ]]; then
  rm -rf "$APP_SUPPORT"
  printf 'Deleted Pairling state: %s\n' "$APP_SUPPORT"
else
  printf 'Preserved Pairling state and devices: %s\n' "$APP_SUPPORT"
fi

if [[ "$DELETE_LOGS" == "true" ]]; then
  rm -rf "$LOGS_ROOT"
  printf 'Deleted Pairling logs: %s\n' "$LOGS_ROOT"
else
  printf 'Preserved Pairling logs: %s\n' "$LOGS_ROOT"
fi

printf 'Provider transcripts and user projects were not removed.\n'
printf 'Reinstall with: pairling setup\n'
