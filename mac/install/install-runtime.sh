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
PAIRLING_CONNECTD_LABEL="dev.pairling.connectd"
PAIRLING_PTYBROKER_LABEL="dev.pairling.ptybroker"
APP_SUPPORT="${PAIRLING_APP_SUPPORT_ROOT:-${COMPANION_APP_SUPPORT_ROOT:-$HOME/Library/Application Support/Pairling}}"
RUNTIME_ROOT="$APP_SUPPORT/runtime"
RELEASES_ROOT="$RUNTIME_ROOT/releases"
STATE_ROOT="$APP_SUPPORT/state"
PAIR_ROOT="$APP_SUPPORT/pair"
LOGS_ROOT="${PAIRLING_LOGS_ROOT:-${COMPANION_LOGS_ROOT:-$HOME/Library/Logs/Pairling}}"
PAIRDROP_ROOT="${PAIRLING_PAIRDROP_ROOT:-$HOME/PairDrop}"
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
MCP_SERVER_DIR="$HOME/.claude/mcp-servers"
MCP_SERVER_SHIM="$MCP_SERVER_DIR/phone-tools.py"
PYTHON3_BIN="${PAIRLING_DAEMON_PYTHON:-${COMPANION_DAEMON_PYTHON:-$(command -v python3)}}"
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
# have. The companiond dir and the app support root are passed as argv, so an
# install path with a space is passed whole. On any failure it prints
# installed=false, so the caller fails closed to the not-installed advisory.
safety_status_line() {
  "$PYTHON3_BIN" - "$CURRENT_LINK/companiond" "$APP_SUPPORT" <<'PY' 2>/dev/null || printf 'installed=false full_disk_access=unknown\n'
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
    fda = str(status.get("full_disk_access") or "unknown")
except Exception:
    installed, fda = "false", "unknown"
print("installed=%s full_disk_access=%s" % (installed, fda))
PY
}

# safety_status_installed: return 0 when the bridge reports installed true, 1
# when it reports installed false, and the not-installed advisory path handles
# both 1 and any read failure, which also prints installed=false. The reader is
# the single source of truth for whether the future PairlingSafety.app is present.
safety_status_installed() {
  case "$(safety_status_line)" in
    *"installed=true"*) return 0 ;;
    *) return 1 ;;
  esac
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
  if is_dry_run || [ "${WIZARD_TUI:-0}" != 1 ]; then
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

# wizard_recovery_menu: a plain bash recovery menu. It uses a plain blocking
# read with no timeout, which bash 3.2.57 supports, so it works without any
# python. The recoverable kind offers open Full Disk Access settings, skip, and
# quit and resume. The fatal kind, an integrity or signature failure,
# has no retry and no skip, which mirrors the install script that exits with no
# bypass on a hash mismatch or a code-signature failure. When stdin is not a
# terminal it prints the options and returns, so a headless or piped run never
# blocks. open_full_disk_access_pane is defined by the safety step and runs the
# bridge open_full_disk_access method.
wizard_recovery_menu() {
  local kind="$1" stage="$2"
  if [ "$kind" = "fatal" ]; then
    stage_note "Pairling stopped to protect your Mac at the $stage step."
    stage_note "A file did not match its signed checksum, so setup will not continue. There is no way to skip this check."
    stage_note "Options: [1] reinstall from a verified copy   [2] view logs   [q] quit"
  else
    stage_note "Setup needs your help at the $stage step."
    stage_note "Options: [o] open Full Disk Access settings   [s] skip for now   [q] quit and resume"
  fi
  # Off a terminal, print the options and return without blocking.
  [ -t 0 ] || return 0
  local choice=""
  while :; do
    printf '  Choose an option: '
    read -r choice || return 0
    case "$kind:$choice" in
      # Retry was removed here because no caller loops on the menu return today.
      # In guided_on_exit the process is already exiting, and in safety_step the
      # evidence poll has already timed out before the menu shows, so an [r] key
      # did nothing. When the future PairlingSafety.app makes the evidence poll
      # live, add a real retry loop in safety_step with a distinct menu return
      # code, then reinstate an [r] option that maps to it. An r keypress now
      # falls through to the reprompt below, which is correct.
      recoverable:o|recoverable:O) open_full_disk_access_pane ;;
      recoverable:s|recoverable:S) stage_note "Skipped. You can grant it later and run pairling setup again."; return 0 ;;
      *:q|*:Q) stage_note "Quitting. Run pairling setup again to resume right here."; return 0 ;;
      fatal:1) stage_note "Reinstall Pairling from a verified copy, then run pairling setup again."; return 0 ;;
      fatal:2) stage_note "The full details are in the setup log under the audit folder."; return 0 ;;
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
# sentence safety_step also prints plain. The Local Network copy makes clear that
# the permission and same-Wi-Fi requirement apply only to nearby pairing. It is
# the same sentence a machine path prints, wrapped to fixed rows that fit the box so
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
  wizard_box_row "$inner" "Your iPhone may ask for Local Network access. Allow it" "${WZ_PAPER:-}Your iPhone may ask for Local Network access. Allow it${r}"
  wizard_box_row "$inner" "for nearby pairing. Local Network and the same Wi-Fi are" "${WZ_PAPER:-}for nearby pairing. Local Network and the same Wi-Fi are${r}"
  wizard_box_row "$inner" "not required for Pairling Connect." "${WZ_PAPER:-}not required for Pairling Connect.${r}"
  wizard_box_bot "$inner"
}

# safety_step: the one safety gate in v1. It reads the live SafetyMonitorBridge
# status. Today the app is not installed, so the bridge reports installed false,
# and this prints one plain advisory line that the Safety Monitor is a future
# feature and is not installed, and that pairing works without it, then continues.
# It never claims it installed the app. It never shows or blocks on Full Disk
# Access when the app is absent. When a future PairlingSafety.app reports
# installed true, the same flow guides System Extension approval, then Full Disk
# Access, then polls the evidence test until file evidence passes, advancing on
# pass or showing the recovery menu on timeout. It never blocks pairing and
# always returns 0.
safety_step() {
  if safety_status_installed; then
    stage_note "Pairling Safety Monitor is installed. Setting it up so it can watch your agent sessions."
    request_safety_activation
    open_full_disk_access_pane
    stage_note "Checking that the Safety Monitor can see process and file evidence. We check every 2 seconds."
    if poll_evidence_test; then
      stage_note "The Safety Monitor sees full evidence. Thank you."
    else
      stage_note "The Safety Monitor did not reach full file evidence within the time limit."
      # A skip never blocks pairing. File visibility is the only thing limited
      # until Full Disk Access is granted.
      wizard_recovery_menu recoverable "macOS permissions" || true
    fi
    # The Local Network advisory. On the guided screen it renders as a rounded
    # panel. A machine path keeps the plain stage_note, byte identical.
    if [ "${GUIDED_TTY:-0}" = 1 ]; then
      wizard_permissions_panel ""
    else
      stage_note "Your iPhone may ask for Local Network access. Allow it for nearby pairing. Local Network and the same Wi-Fi are not required for Pairling Connect."
    fi
  else
    # The not-installed advisory. This is today's path. It states the truth: the
    # Safety Monitor is a future feature, it is not installed, and pairing works
    # without it. It never claims setup installed anything. On the guided screen the
    # advisory and the Local Network copy render as one rounded panel. A machine
    # path keeps the two plain stage_note lines, byte identical.
    if [ "${GUIDED_TTY:-0}" = 1 ]; then
      wizard_permissions_panel "Pairling Safety Monitor is a future feature and is not installed yet. Pairing works without it."
    else
      stage_note "Pairling Safety Monitor is a future feature and is not installed yet. Pairing works without it."
      stage_note "Your iPhone may ask for Local Network access. Allow it for nearby pairing. Local Network and the same Wi-Fi are not required for Pairling Connect."
    fi
  fi
  stage_note "If pairing stalls, run pairling doctor --json. Check Local Network access and the same Wi-Fi only when using nearby pairing."
  stage_note "Accessibility and Automation are only needed later if you enable typing into Terminal from the phone. Run pairling doctor --json to see the exact Mac grantee path before enabling it."
  return 0
}

# guided_on_exit — fires on ANY premature exit during setup (a set -e abort or an
# explicit exit 1 in staging, service startup, the QR, or auth), so a failure
# always leaves a clear recovery path. Suppressed once setup sets
# GUIDED_COMPLETE=1, so a clean run prints nothing here.
guided_on_exit() {
  local code=$?
  if [ "$GUIDED_COMPLETE" != 1 ] && [ "$code" != 0 ]; then
    if [ "${WIZARD_TUI:-0}" = 1 ]; then
      # Show the bash recovery menu. The kind is recoverable by default. The
      # caller sets WIZARD_FATAL=1 before a fatal integrity or signature exit, so
      # the menu drops retry and skip to mirror this script's no-bypass behavior.
      if [ "${WIZARD_FATAL:-0}" = 1 ]; then
        wizard_recovery_menu fatal "${GUIDED_STAGE_CURRENT:-startup}" || true
      else
        wizard_recovery_menu recoverable "${GUIDED_STAGE_CURRENT:-startup}" || true
      fi
    fi
    printf '\nSetup did not finish (stage: %s, exit %s).\n' "${GUIDED_STAGE_CURRENT:-startup}" "$code" >&2
    printf 'Recovery: run `pairling doctor --json` to inspect, then re-run `pairling setup`.\n' >&2
    printf 'Retry pairing only: `pairling pair --qr`. If doctor says Pairling Connect needs sign-in: `pairling connect-auth-open`.\n' >&2
  fi
}

# guided_permission_notice — advisory only. Surfaces ONLY the permissions the
# code actually uses (verified against doctor.sh permission_readiness): the
# iPhone shows a Local Network prompt on first pair, and this Mac needs no
# privacy permission for basic pairing. It never reads or modifies any privacy
# setting and never blocks setup.
guided_permission_notice() {
  if [ "${GUIDED_TTY:-0}" = 1 ]; then
    # The guided screen frames the no-permission line and the route-aware Local
    # Network copy in a rounded panel, matching the safety_step panel. The copy is
    # wrapped to fixed rows so the right border lines up. The stall and
    # Accessibility lines stay plain notes below the box.
    wizard_palette_init
    local inner=60 b=$'\033[1m' r=$'\033[0m'
    wizard_box_top "$inner"
    wizard_box_row "$inner" "macOS permissions" "${b}${WZ_PAPER:-}macOS permissions${r}"
    wizard_box_row "$inner" "" ""
    wizard_box_row "$inner" "This Mac needs no special privacy permission to pair." "${WZ_GREY:-}This Mac needs no special privacy permission to pair.${r}"
    wizard_box_row "$inner" "Your iPhone may ask for Local Network access. Allow it" "${WZ_PAPER:-}Your iPhone may ask for Local Network access. Allow it${r}"
    wizard_box_row "$inner" "for nearby pairing. Local Network and the same Wi-Fi are" "${WZ_PAPER:-}for nearby pairing. Local Network and the same Wi-Fi are${r}"
    wizard_box_row "$inner" "not required for Pairling Connect." "${WZ_PAPER:-}not required for Pairling Connect.${r}"
    wizard_box_bot "$inner"
    stage_note "If pairing stalls, run pairling doctor --json. Check Local Network access and the same Wi-Fi only when using nearby pairing."
    stage_note "Accessibility and Automation are only needed if you later enable typing into Terminal from the phone, and macOS prompts then."
  else
    stage_note "This Mac needs no special privacy permission to pair."
    stage_note "Your iPhone may ask for Local Network access. Allow it for nearby pairing. Local Network and the same Wi-Fi are not required for Pairling Connect."
    stage_note "If pairing stalls, run pairling doctor --json. Check Local Network access and the same Wi-Fi only when using nearby pairing."
    stage_note "Accessibility and Automation are only needed if you later enable typing into Terminal from the phone, and macOS prompts then."
  fi
}

# guided_connect_route_state makes one bounded, best-effort read of connectd
# /status and reduces it to the four states the setup copy can render. The
# finish summary captures it once and passes the same value to both proofs, so
# adjacent route and recovery messages cannot disagree.
guided_connect_route_state() {
  python3 - "$REPO_ROOT" 2>/dev/null <<'PY' || printf 'degraded\n'
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

# guided_route_proof renders the captured Pairling Connect state. Nearby pairing
# remains available when the remote route is not ready, but same Wi-Fi is never
# presented as a requirement for a ready Pairling Connect route.
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
      printf '     Route check: Pairling Connect needs sign-in. Nearby pairing is available on the same Wi-Fi.\n'
      ;;
    degraded|*)
      printf '     Route check: Pairling Connect needs attention. Run pairling doctor --json. Nearby pairing is available on the same Wi-Fi.\n'
      ;;
  esac
}

# guided_pairing_seen_proof is one bounded, best-effort, read-only check of the
# devices database that tells the user whether this Mac has recorded the iPhone
# finishing pairing in this session. It takes the session-start epoch as its
# first argument, so a device paired in an earlier run does not read as seen on a
# re-run. It opens the database read-only with mode=ro, so it never locks the
# file the daemon is writing, and it treats a missing or empty database or any
# sqlite error as "not seen". It polls up to about 6 seconds at 1 second steps
# and exits early the moment a matching device appears, so a scanned phone is
# confirmed within about a second and only an unscanned run waits the full
# window. The whole probe is wrapped in `|| true`, so it never blocks or fails
# setup.
guided_pairing_seen_proof() {
  local since="${1:-0}" route_state="${2:-degraded}"
  PAIRLING_PAIRING_SEEN_POLL_STEPS="${PAIRLING_PAIRING_SEEN_POLL_STEPS:-6}" \
    python3 - "$DEVICES_DB" "$since" "$route_state" <<'PY' || true
import os
import sqlite3
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

def count_session_devices():
    # Open read-only with mode=ro so this never locks or creates the database the
    # daemon is writing. Count only non-revoked rows created at or after the
    # session start, so a device from an earlier run does not read as seen.
    con = sqlite3.connect("file:" + db_path + "?mode=ro", uri=True, timeout=0.5)
    try:
        row = con.execute(
            "SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL AND created_at >= ?",
            (since,),
        ).fetchone()
        return int(row[0]) if row else 0
    finally:
        con.close()

seen = 0
try:
    for step in range(steps):
        try:
            seen = count_session_devices()
        except Exception:
            # A missing or empty database, or any sqlite error, means not seen.
            seen = 0
        if seen > 0:
            break
        if step < steps - 1:
            time.sleep(1)
    if seen > 0:
        print("     Pairing check: this Mac saw your iPhone connect and finish pairing.")
    else:
        print("     Pairing check: this Mac has not recorded your iPhone finishing pairing yet.")
        print("     If you just scanned the code, give it a moment and it should appear.")
        if route_state == "ready":
            print("     Pairling Connect is ready, so same Wi-Fi is not required. Keep Pairling open on the iPhone and finish its sign-in if asked.")
        elif route_state == "starting":
            print("     Pairling Connect is still starting. Wait a moment, then scan a fresh code. Nearby pairing still needs Local Network access and the same Wi-Fi.")
        elif route_state == "needs_auth":
            print("     Pairling Connect needs sign-in. Run pairling connect-auth-open, then scan a fresh code. Nearby pairing still needs Local Network access and the same Wi-Fi.")
        else:
            print("     Pairling Connect needs attention. Run pairling doctor --json before scanning a fresh code, or use nearby pairing with Local Network access and the same Wi-Fi.")
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
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/compose_recording_store.py"
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
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/session_events.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/session_event_log.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/session_event_ingest.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/terminal_text_sanitizer.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/push_dispatcher.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/push_event_catalog.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/live_activity_publisher.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/standard_push_publisher.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/fleet_tier.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/fleet_activity_publisher.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/companiond/fd_watchdog.py"
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
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/install/render-launchd.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/install/psk_dependency_check.py"
  PYTHONPYCACHEPREFIX="$pycache_root" python3 -m py_compile "$REPO_ROOT/mac/install/ssh_gateway_setup.py"
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

ensure_pairdrop_folder() {
  mkdir -p "$PAIRDROP_ROOT"
  chmod 700 "$PAIRDROP_ROOT" 2>/dev/null || true
  local probe="$PAIRDROP_ROOT/.pairling-write-test.$$"
  if ! printf 'ok\n' > "$probe" 2>/dev/null; then
    log "ERROR: PairDrop folder is not writable: $(display_path "$PAIRDROP_ROOT")" >&2
    exit 1
  fi
  rm -f "$probe"
  log "PairDrop folder: $(display_path "$PAIRDROP_ROOT")"
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

copy_release() {
  local tmp="$RELEASE_ROOT.tmp"
  rm -rf "$tmp"
  verify_payload_manifest
  mkdir -p "$tmp/bin" "$tmp/companiond" "$tmp/companiond/providers" "$tmp/companiond/integrations/aperture_cli" "$tmp/connectd" "$tmp/mac" "$tmp/mcp"
  cp "$REPO_ROOT/mac/companiond/pairlingd.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/runtime_contract.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/runtime_manifest.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/runtime_paths.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/pairdrop_store.py" "$tmp/companiond/"
  cp "$REPO_ROOT/mac/companiond/compose_recording_store.py" "$tmp/companiond/"
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
  cp "$REPO_ROOT/mac/companiond/integrations/__init__.py" "$tmp/companiond/integrations/"
  cp "$REPO_ROOT/mac/companiond/integrations/aperture_cli/"*.py "$tmp/companiond/integrations/aperture_cli/"
  cp "$REPO_ROOT/mac/companiond/providers/"*.py "$tmp/companiond/providers/"
  # registry-data.json is the provider source of truth (SPEC-p1); a release
  # without it silently degrades to the builtin fallbacks.
  cp "$REPO_ROOT/mac/companiond/providers/"*.json "$tmp/companiond/providers/"
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
  cp "$REPO_ROOT/mac/companiond/providers/"*.json "$mac_root/companiond/providers/"
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
    team="$(/usr/bin/codesign -dvv "$src_tree/bin/python3" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
    if [[ "$team" != "$required_team" ]]; then
      log "ERROR: vendored python TeamIdentifier '${team:-none}' does not match required '$required_team'; refusing to stage." >&2
      WIZARD_FATAL=1
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
        WIZARD_FATAL=1
        exit 1
      fi
      local team
      team="$(/usr/bin/codesign -dvv "$prebuilt_env" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
      if [[ "$team" != "$required_team" ]]; then
        log "ERROR: connectd binary TeamIdentifier '${team:-none}' does not match required '$required_team'; refusing to stage: $prebuilt_env" >&2
        WIZARD_FATAL=1
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
    "companiond/compose_recording_store.py",
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
    "companiond/session_events.py",
    "companiond/session_event_log.py",
    "companiond/session_event_ingest.py",
    "companiond/route_registry.py",
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
    "companiond/providers/builtin-commands.json",
    "companiond/providers/registry-data.json",
    "connectd/pairling-connectd",
    "mcp/phone_tools.py",
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
    },
    "paths": {
        "app_support": app_support,
        "logs": logs_root,
        "pair_records": str(Path(app_support) / "pair"),
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
  )
  # SPEC-p5 §2.1: `pairling setup --ssh` (or a prior enable) renders connectd
  # with the loopback SSH-tunnel gateway on. The flag persists in the
  # LaunchAgent env, so a plain `setup` re-run keeps a previously enabled
  # gateway unless the operator passes --no-ssh.
  if [ "${SSH_GATEWAY_ENABLED:-0}" = "1" ]; then
    render_args+=(--ssh-gateway)
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
  if launchd_skipped; then return 0; fi
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
  if launchd_skipped; then return 0; fi
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
  if launchd_skipped; then return 0; fi
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
  # When WIZARD_TUI is 1 the guided stages add the splash, the live safety step,
  # and the bash recovery menu, all behind a WIZARD_TUI check and the dry-run
  # guard. When it is 0 the existing plain printf flow runs unchanged.
  setup_intro
  log "Pairling setup preview:"
  log "  app support: $(display_path "$APP_SUPPORT")"
  log "  logs: $(display_path "$LOGS_ROOT")"
  log "  LaunchAgent: $PAIRLING_DAEMON_LABEL"
  log "  PTY Broker LaunchAgent: $PAIRLING_PTYBROKER_LABEL"
  log "  Connect LaunchAgent: $PAIRLING_CONNECTD_LABEL"
  log "  runtime port: $PAIRLING_RUNTIME_PORT"

  stage_begin "Preparing the Mac runtime"
  run_compile_checks
  run_psk_dependency_checks
  ensure_state
  stage_ok "checks passed and state is ready"

  stage_begin "PairDrop folder"
  ensure_pairdrop_folder
  stage_ok "$(display_path "$PAIRDROP_ROOT") is ready (private, mode 0700)"

  stage_begin "Staging runtime"
  copy_release
  switch_current
  install_mcp_adapter_shim
  install_shell_wrapper
  stage_ok "staged $RELEASE_NAME"

  stage_begin "Starting Pairling services"
  render_plists
  ensure_ptybroker_agent
  start_user_agent
  start_connectd_agent
  stage_ok "companiond, connectd, and ptybroker are running"

  append_history "installed" "installed $RELEASE_NAME"
  if is_dry_run; then
    log "dry-run: skipping doctor gate"
  else
    run_doctor || true
  fi
  log "Installed Pairling runtime $RELEASE_NAME"

  stage_begin "macOS permissions"
  if [ "${WIZARD_TUI:-0}" = 1 ] && ! is_dry_run; then
    # The safety step reads the live SafetyMonitorBridge status. Today it reports
    # not installed, so it prints one advisory line and continues. When a future
    # PairlingSafety.app is installed, it guides approval, Full Disk Access, and
    # the evidence test. It never blocks pairing. The plain advisory notice is the
    # WIZARD_TUI=0 fallback.
    safety_step
  else
    guided_permission_notice
  fi
  stage_ok "no Mac privacy permission is required to pair"

  stage_begin "Providers"
  provider_setup_stage

  if ! is_dry_run; then
    stage_begin "Pairing code for the iPhone"
    if [ "${WIZARD_TUI:-0}" = 1 ]; then
      stage_note "Open Pairling on your iPhone and scan this code. The pair address is printed below it too."
    fi
    # Record when this pairing attempt started, so the seen probe in
    # guided_finish_summary counts only a device paired during this session.
    export PAIRLING_PAIRING_STARTED_AT="$(python3 -c 'import time;print(time.time())')"
    if ! PAIRLING_CONNECTD_ROUTE_WAIT_SECONDS="${PAIRLING_CONNECTD_ROUTE_WAIT_SECONDS:-0}" pair_runtime --qr; then
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
    # Browser auth must not block or precede the first pairing code. The code may
    # already carry a ready Pairling Connect route; this later handoff only opens
    # approval when the Mac still needs it.
    stage_begin "Pairling Connect sign-in (Mac)"
    auto_open_connect_auth
    stage_ok "Pairling Connect sign-in handled"

    stage_begin "Finish and next steps"
    guided_finish_summary
    stage_ok "setup complete"
  fi
  GUIDED_COMPLETE=1
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
    # A ready embedded route is the preferred first-pair transport. Its route
    # metadata lets iOS claim the QR through PrePairEmbeddedTailnetTransport,
    # so the code remains usable away from the Mac's local network. Nearby LAN
    # pairing is only the fallback while Pairling Connect is not ready.
    route = ready_connectd_route()
    if route:
        return {
            "base_url": route["base_url"],
            "source": route["source"],
            "status": route["status"],
            "kind": route["kind"],
        }
    lan_ip = detected_lan_ip()
    if lan_ip and lan_base_serviceable(lan_ip, port_number):
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
        # absence is the legacy plaintext claim. pv=2 is the PSK-only marker.
        pair_params["mac_ake_pub"] = mac_ake_pub
        # pv is always 2 when the Mac ECDH key is present (PSK-authenticated ECDH).
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

# auto_open_connect_auth — kicked off by install_runtime after the first QR.
# Polls connectd /status for readiness (reusing fetch_connectd_status, the same
# helper pair_runtime imports). When connectd is in interactive mode and not yet
# authenticated (auth_url_present == true AND auth_state != "authenticated"), it
# POSTs http://127.0.0.1:7774/auth/open directly so connectd opens the browser
# sign-in server-side. We POST directly (not via connect_auth_open, which ends in
# `exit` and would terminate setup before the QR). Already-authenticated or
# already-tagged connectd is skipped silently. This never fails setup and never
# blocks indefinitely: the bounded poll falls through to pair_runtime regardless.
auto_open_connect_auth() {
  if is_dry_run; then
    return 0
  fi
  python3 - "$REPO_ROOT" <<'PY' || true
import json
import os
import sys
import time
import urllib.error
import urllib.request

repo_root = sys.argv[1]
sys.path.insert(0, os.path.join(repo_root, "mac", "companiond"))
from pairling_connectd_status import fetch_connectd_status

AUTH_OPEN_URL = "http://127.0.0.1:7774/auth/open"


def readiness_wait_seconds() -> float:
    try:
        return min(max(float(os.environ.get("PAIRLING_CONNECTD_AUTH_WAIT_SECONDS") or "20"), 0.0), 60.0)
    except ValueError:
        return 20.0


def readiness_poll_seconds() -> float:
    try:
        return min(max(float(os.environ.get("PAIRLING_CONNECTD_AUTH_POLL_SECONDS") or "0.5"), 0.1), 2.0)
    except ValueError:
        return 0.5


def decision(status: dict):
    """Return one of: ("open",), ("skip", reason), ("wait",)."""
    if not status:
        # connectd not reachable yet — keep waiting until the deadline.
        return ("wait",)
    auth_state = str(status.get("auth_state") or "")
    if auth_state == "authenticated":
        return ("skip", "already authenticated")
    tags = status.get("tags")
    if isinstance(tags, list) and tags:
        # Already-tagged connectd (machine identity established) — no browser step.
        return ("skip", "already tagged")
    if status.get("auth_url_present"):
        return ("open",)
    # Reachable but no interactive auth URL yet — give connectd a moment.
    return ("wait",)


def post_auth_open() -> bool:
    request = urllib.request.Request(AUTH_OPEN_URL, data=b"", method="POST")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # connectd answered but the auth URL is not ready (409) or similar.
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except Exception:
            payload = {}
        return bool(payload.get("opened"))
    except Exception:
        return False
    return bool(payload.get("opened"))


def main() -> None:
    wait_seconds = readiness_wait_seconds()
    poll_seconds = readiness_poll_seconds()
    deadline = time.monotonic() + wait_seconds
    while True:
        status = fetch_connectd_status(timeout_seconds=0.7)
        action = decision(status)
        if action[0] == "open":
            if post_auth_open():
                print("Opened the Tailscale sign-in in your browser. Finish sign-in to bring Pairling Connect online. The pairing code is already shown above.")
            else:
                print("Pairling Connect sign-in is not ready yet. The pairing code above remains available for nearby pairing. Run pairling doctor --json for the next remote-access step.")
            return
        if action[0] == "skip":
            # Already authenticated or tagged — no browser step needed.
            return
        if wait_seconds <= 0 or time.monotonic() >= deadline:
            print("Pairling Connect was not ready in time. The pairing code above remains available for nearby pairing. Run pairling doctor --json for the remote-route status.")
            return
        time.sleep(min(poll_seconds, max(0.0, deadline - time.monotonic())))


main()
PY
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
      install_runtime "$@"
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
