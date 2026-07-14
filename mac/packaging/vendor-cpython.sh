#!/usr/bin/env bash
set -euo pipefail

# Vendors a standalone CPython for one macOS arch into the Pairling runtime
# package, signed under our Developer ID with the dev.pairling.python identity.
#
# This is the P3 "Python custody" step: it removes the daemon's dependency on
# whatever python3 happens to be on the machine (Homebrew/Command Line Tools),
# and — crucially — makes the interpreter a Pairling-signed binary. TCC grants
# (Automation for AppleScript injection, etc.) then attach to a Pairling-scoped
# identity instead of a generic shared python3.
#
# Source: astral-sh/python-build-standalone "install_only" build (relocatable,
# pruned). The download is pinned by SHA-256.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Pinned upstream build (python-build-standalone). Bump deliberately.
PBS_TAG="20260610"
PY_VERSION="3.12.13"
PYTHON_CODESIGN_IDENTIFIER="dev.pairling.python"
CRYPTOGRAPHY_VERSION="45.0.7"

# SHA-256 of the install_only tarballs for PBS_TAG / PY_VERSION.
PBS_SHA_aarch64="e18ddd4c1e8f4a1d6c4590b37f423d76aec734447edc20ed08e93983d95f2132"
PBS_SHA_x86_64="ba02164e4db381af8c288c0bc1657584a835e9121a0fa2836b0f2e712ff8cdf5"

ARCH=""
OUT_DIR=""
SIGN_IDENTITY="${PAIRLING_SIGN_IDENTITY:-}"
NOTARIZE="0"
NOTARY_PROFILE="${PAIRLING_NOTARY_PROFILE:-pairling-notary}"

usage() {
  cat <<'EOF'
usage: mac/packaging/vendor-cpython.sh --arch arm64|x64 --out DIR [--notarize]

Downloads, prunes, and signs a standalone CPython into DIR (creating DIR/python
with bin/python3). DIR is the platform runtime package directory.

Environment:
  PAIRLING_SIGN_IDENTITY   Developer ID identity ("-" for local ad-hoc tests).
  PAIRLING_NOTARY_PROFILE  notarytool keychain profile (default pairling-notary).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch) ARCH="${2:-}"; shift 2 ;;
    --out) OUT_DIR="${2:-}"; shift 2 ;;
    --notarize) NOTARIZE="1"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
log() { printf '%s\n' "$*"; }

[[ -n "$ARCH" && -n "$OUT_DIR" ]] || { usage >&2; exit 2; }
case "$ARCH" in
  arm64) PBS_TRIPLE="aarch64-apple-darwin"; EXPECTED_SHA="$PBS_SHA_aarch64"; WHEEL_PLATFORM="macosx_11_0_arm64" ;;
  x64)   PBS_TRIPLE="x86_64-apple-darwin";  EXPECTED_SHA="$PBS_SHA_x86_64"; WHEEL_PLATFORM="macosx_10_9_x86_64" ;;
  *) fail "unsupported --arch: $ARCH (use arm64 or x64)" ;;
esac

ASSET="cpython-${PY_VERSION}+${PBS_TAG}-${PBS_TRIPLE}-install_only.tar.gz"
URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_TAG}/${ASSET}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log "Downloading $ASSET"
/usr/bin/curl -fsSL --max-time 180 -o "$WORK/$ASSET" "$URL" || fail "download failed: $URL"

ACTUAL_SHA="$(/usr/bin/shasum -a 256 "$WORK/$ASSET" | awk '{print $1}')"
[[ "$ACTUAL_SHA" == "$EXPECTED_SHA" ]] || fail "SHA-256 mismatch for $ASSET: got $ACTUAL_SHA expected $EXPECTED_SHA"
log "Verified SHA-256 $ACTUAL_SHA"

tar -xzf "$WORK/$ASSET" -C "$WORK"
[[ -x "$WORK/python/bin/python3" ]] || fail "extracted tree missing python/bin/python3"

# --- prune: shrink the payload, drop test trees and bytecode caches ---------
PY_LIB="$WORK/python/lib/python${PY_VERSION%.*}"
rm -rf \
  "$PY_LIB/test" \
  "$PY_LIB/idlelib" \
  "$PY_LIB/tkinter" \
  "$PY_LIB/turtledemo" \
  "$PY_LIB/lib2to3" \
  "$WORK/python/lib/pkgconfig" \
  "$WORK/python/share" 2>/dev/null || true
find "$WORK/python" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$WORK/python" -name '*.pyc' -delete 2>/dev/null || true
# tkinter native module + its bundled Tcl/Tk runtime are useless without the
# tkinter package pruned above; drop the dylibs and tcl script trees too.
find "$WORK/python" -name '_tkinter*.so' -delete 2>/dev/null || true
find "$WORK/python/lib" -maxdepth 1 \( \
  -name 'libtcl*' -o -name 'libtk*' -o -name 'libitcl*' -o -name 'libtclstub*' -o -name 'libtkstub*' \
  -o -name 'tcl*' -o -name 'tk*' -o -name 'itcl*' -o -name 'thread*' \
\) -exec rm -rf {} + 2>/dev/null || true

# npm pack drops symlinks entirely, so the bin/python3 -> python3.x symlink
# would vanish from the published package. Materialize bin/python3 as a real
# copy of the versioned interpreter (consumers reference the version-agnostic
# bin/python3). Drop the now-redundant bin/python symlink.
PY_REAL="$WORK/python/bin/python${PY_VERSION%.*}"
[[ -f "$PY_REAL" ]] || fail "missing versioned interpreter $PY_REAL"
rm -f "$WORK/python/bin/python3" "$WORK/python/bin/python"
cp "$PY_REAL" "$WORK/python/bin/python3"
chmod 755 "$WORK/python/bin/python3"

SITE_PACKAGES="$PY_LIB/site-packages"
mkdir -p "$SITE_PACKAGES"
log "Vendoring cryptography==$CRYPTOGRAPHY_VERSION for $ARCH"
python3 -m pip install \
  --quiet \
  --upgrade \
  --no-compile \
  --only-binary=:all: \
  --platform "$WHEEL_PLATFORM" \
  --implementation cp \
  --python-version "${PY_VERSION%.*}" \
  --abi cp312 \
  --target "$SITE_PACKAGES" \
  "cryptography==$CRYPTOGRAPHY_VERSION"
find "$WORK/python" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$WORK/python" -name '*.pyc' -delete 2>/dev/null || true

# Smoke: the pruned interpreter must still import the daemon's stdlib surface.
# Only executable when the vendored arch matches the host (cross-arch builds —
# e.g. x64 on Apple Silicon CI — can't reliably exec the other slice).
HOST_ARCH="$(/usr/bin/uname -m)"
HOST_NORM="x64"; [[ "$HOST_ARCH" == "arm64" ]] && HOST_NORM="arm64"
if [[ "$ARCH" == "$HOST_NORM" ]]; then
  "$WORK/python/bin/python3" -c "import json,sqlite3,ssl,hashlib,hmac,socket,subprocess,select,pty,termios,fcntl,struct,plistlib,urllib.request,cryptography,cffi; print('stdlib-ok')" \
    || fail "pruned CPython failed stdlib import smoke"
else
  log "Skipping exec smoke for cross-arch build ($ARCH on $HOST_NORM host)"
fi

# --- sign every Mach-O under our Developer ID -------------------------------
sign_one() {
  local f="$1" identifier="$2"
  if [[ "$SIGN_IDENTITY" == "-" ]]; then
    /usr/bin/codesign --force --options runtime --identifier "$identifier" --sign - "$f"
  else
    /usr/bin/codesign --force --timestamp --options runtime --identifier "$identifier" --sign "$SIGN_IDENTITY" "$f"
  fi
  /usr/bin/codesign --verify --strict "$f"
}

if [[ -z "$SIGN_IDENTITY" ]]; then
  log "WARNING: PAIRLING_SIGN_IDENTITY unset; CPython left unsigned. pairling setup will reject it under the default identity policy."
else
  log "Signing Mach-O objects with identity '$SIGN_IDENTITY' (identifier base $PYTHON_CODESIGN_IDENTIFIER)"
  # Sign leaf Mach-O objects first (dylibs, .so), then the interpreter binaries.
  count=0
  while IFS= read -r f; do
    # Identify Mach-O by magic; skip text/scripts.
    if /usr/bin/file "$f" | grep -q "Mach-O"; then
      base="$(basename "$f")"
      sign_one "$f" "$PYTHON_CODESIGN_IDENTIFIER.${base//[^A-Za-z0-9_.-]/_}"
      count=$((count + 1))
    fi
  done < <(/usr/bin/find "$WORK/python" -type f ! -name 'python3*' \( -name '*.so' -o -name '*.dylib' -o -perm -111 \) | LC_ALL=C sort)
  # Both interpreter binaries carry the canonical dev.pairling.python identity:
  # the versioned python3.x and the materialized version-agnostic python3 copy.
  for interp in "$WORK/python/bin/python3" "$PY_REAL"; do
    sign_one "$interp" "$PYTHON_CODESIGN_IDENTIFIER"
    count=$((count + 1))
  done
  log "Signed $count Mach-O objects"
fi

if [[ "$NOTARIZE" == "1" ]]; then
  [[ -n "$SIGN_IDENTITY" && "$SIGN_IDENTITY" != "-" ]] || fail "--notarize requires a real Developer ID identity"
  zip="$WORK/pairling-python-$ARCH.zip"
  (cd "$WORK" && /usr/bin/ditto -c -k --sequesterRsrc python "$zip")
  log "Submitting CPython to notary service"
  /usr/bin/xcrun notarytool submit "$zip" --keychain-profile "$NOTARY_PROFILE" --wait
fi

# --- install into the runtime package ---------------------------------------
mkdir -p "$OUT_DIR"
rm -rf "$OUT_DIR/python"
mv "$WORK/python" "$OUT_DIR/python"

PY_BIN="$OUT_DIR/python/bin/python3"
TEAM_ID=""
if [[ -n "$SIGN_IDENTITY" && "$SIGN_IDENTITY" != "-" ]]; then
  TEAM_ID="$(/usr/bin/codesign -dvv "$PY_BIN" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
fi
PY_SHA="$(/usr/bin/shasum -a 256 "$PY_BIN" | awk '{print $1}')"

log "Vendored CPython $PY_VERSION ($ARCH) into $OUT_DIR/python"
log "  python3 sha256: $PY_SHA"
log "  python3 identity: $PYTHON_CODESIGN_IDENTIFIER team=${TEAM_ID:-<unsigned>}"

# Emit machine-readable result for the caller (build-npm-packages.sh).
printf '{"arch":"%s","py_version":"%s","pbs_tag":"%s","identifier":"%s","team_id":"%s","python3_sha256":"%s"}\n' \
  "$ARCH" "$PY_VERSION" "$PBS_TAG" "$PYTHON_CODESIGN_IDENTIFIER" "$TEAM_ID" "$PY_SHA"
