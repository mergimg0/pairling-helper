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

PYTHON_CODESIGN_IDENTIFIER="dev.pairling.python"
INPUTS_FILE="${PAIRLING_PYTHON_RUNTIME_INPUTS:-$REPO_ROOT/mac/packaging/python-runtime-inputs.json}"

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
  arm64) WHEEL_PLATFORM="macosx_11_0_arm64" ;;
  x64)   WHEEL_PLATFORM="macosx_10_9_x86_64" ;;
  *) fail "unsupported --arch: $ARCH (use arm64 or x64)" ;;
esac

[[ -f "$INPUTS_FILE" && ! -L "$INPUTS_FILE" ]] \
  || fail "Python runtime inputs must be a real file: $INPUTS_FILE"
if ! INPUT_VALUES="$(python3 - "$INPUTS_FILE" "$ARCH" <<'PY'
import json, re, sys
from pathlib import Path

path, arch = Path(sys.argv[1]), sys.argv[2]
value = json.loads(path.read_text(encoding="utf-8"))
if set(value) != {"schema_version", "python_version", "python_build_standalone", "wheels"}:
    raise SystemExit("Python runtime inputs have unexpected top-level keys")
if value["schema_version"] != 1 or not re.fullmatch(r"3\.12\.[0-9]+", value["python_version"]):
    raise SystemExit("Python runtime inputs have an unsupported schema or Python version")
pbs = value["python_build_standalone"]
if set(pbs) != {"tag", "assets"} or set(pbs["assets"]) != {"arm64", "x64"}:
    raise SystemExit("Python build standalone inputs are incomplete")
wheels = value["wheels"]
if set(wheels) != {"cryptography", "cffi", "pycparser"}:
    raise SystemExit("Python wheel inputs are incomplete")
asset = pbs["assets"][arch]
fields = [value["python_version"], pbs["tag"], asset["filename"], asset["sha256"]]
for name in ("cryptography", "cffi", "pycparser"):
    row = wheels[name]
    if set(row) != {"version", "arm64", "x64"}:
        raise SystemExit(f"Python wheel input is incomplete: {name}")
    selected = row[arch]
    if set(selected) != {"filename", "sha256"}:
        raise SystemExit(f"Python wheel asset input is incomplete: {name}.{arch}")
    fields.extend((row["version"], selected["filename"], selected["sha256"]))
if any("\t" in str(field) or "\n" in str(field) for field in fields):
    raise SystemExit("Python runtime inputs contain unsafe text")
for digest in fields[3::3]:
    if not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
        raise SystemExit("Python runtime inputs contain an invalid digest")
print("\t".join(str(field) for field in fields))
PY
)"; then
  fail "could not validate pinned Python runtime inputs"
fi
IFS=$'\t' read -r PY_VERSION PBS_TAG ASSET EXPECTED_SHA \
  CRYPTOGRAPHY_VERSION CRYPTOGRAPHY_WHEEL CRYPTOGRAPHY_SHA \
  CFFI_VERSION CFFI_WHEEL CFFI_SHA \
  PYCPARSER_VERSION PYCPARSER_WHEEL PYCPARSER_SHA <<<"$INPUT_VALUES"
[[ -n "$PY_VERSION" && -n "$ASSET" && -n "$PYCPARSER_SHA" ]] \
  || fail "could not load pinned Python runtime inputs"
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
# These convenience links are unused by Pairling. npm drops symlinks while
# packing, so leaving them here would make the signed staging manifest differ
# from the published archive.
rm -f \
  "$WORK/python/bin/2to3" \
  "$WORK/python/bin/idle3" \
  "$WORK/python/bin/pydoc3" \
  "$WORK/python/bin/python3-config"
symlink_residue="$(find "$WORK/python" -type l -print -quit)"
[[ -z "$symlink_residue" ]] || fail "vendored CPython contains an unsupported symlink: $symlink_residue"

SITE_PACKAGES="$PY_LIB/site-packages"
mkdir -p "$SITE_PACKAGES"
WHEEL_DIR="$WORK/wheels"
mkdir -m 700 "$WHEEL_DIR"
log "Downloading the pinned Python wheels for $ARCH"
python3 -m pip download \
  --quiet \
  --disable-pip-version-check \
  --no-deps \
  --only-binary=:all: \
  --platform "$WHEEL_PLATFORM" \
  --implementation cp \
  --python-version "${PY_VERSION%.*}" \
  --abi "cp$(printf '%s' "${PY_VERSION%.*}" | tr -d '.')" \
  --dest "$WHEEL_DIR" \
  "cryptography==$CRYPTOGRAPHY_VERSION" \
  "cffi==$CFFI_VERSION" \
  "pycparser==$PYCPARSER_VERSION"
wheel_count="$(find "$WHEEL_DIR" -maxdepth 1 -type f | wc -l | tr -d '[:space:]')"
[[ "$wheel_count" == "3" ]] || fail "Python dependency download produced $wheel_count files instead of 3"
for wheel_record in \
  "$CRYPTOGRAPHY_WHEEL:$CRYPTOGRAPHY_SHA" \
  "$CFFI_WHEEL:$CFFI_SHA" \
  "$PYCPARSER_WHEEL:$PYCPARSER_SHA"; do
  wheel_name="${wheel_record%%:*}"
  wheel_sha="${wheel_record#*:}"
  [[ -f "$WHEEL_DIR/$wheel_name" && ! -L "$WHEEL_DIR/$wheel_name" ]] \
    || fail "pinned Python wheel was not downloaded: $wheel_name"
  actual_wheel_sha="$(/usr/bin/shasum -a 256 "$WHEEL_DIR/$wheel_name" | awk '{ print $1 }')"
  [[ "$actual_wheel_sha" == "$wheel_sha" ]] \
    || fail "SHA-256 mismatch for Python wheel $wheel_name"
done
log "Vendoring pinned Python wheels for $ARCH"
python3 -m pip install \
  --quiet \
  --upgrade \
  --disable-pip-version-check \
  --no-index \
  --no-deps \
  --no-compile \
  --only-binary=:all: \
  --platform "$WHEEL_PLATFORM" \
  --implementation cp \
  --python-version "${PY_VERSION%.*}" \
  --abi "cp$(printf '%s' "${PY_VERSION%.*}" | tr -d '.')" \
  --target "$SITE_PACKAGES" \
  "$WHEEL_DIR/$CRYPTOGRAPHY_WHEEL" \
  "$WHEEL_DIR/$CFFI_WHEEL" \
  "$WHEEL_DIR/$PYCPARSER_WHEEL"
find "$WORK/python" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$WORK/python" -name '*.pyc' -delete 2>/dev/null || true

INPUTS_SHA="$(/usr/bin/shasum -a 256 "$INPUTS_FILE" | awk '{ print $1 }')"
python3 - "$WORK/python/PAIRLING-BUILD.json" "$INPUTS_FILE" "$INPUTS_SHA" "$ARCH" <<'PY'
import json, sys
from pathlib import Path

output, inputs_path, inputs_sha, arch = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4]
inputs = json.loads(inputs_path.read_text(encoding="utf-8"))
pbs = inputs["python_build_standalone"]
value = {
    "schema_version": 1,
    "architecture": arch,
    "inputs_sha256": inputs_sha,
    "python_version": inputs["python_version"],
    "python_build_standalone": {
        "tag": pbs["tag"],
        **pbs["assets"][arch],
    },
    "wheels": {
        name: {
            "version": row["version"],
            **row[arch],
        }
        for name, row in sorted(inputs["wheels"].items())
    },
}
output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
output.chmod(0o644)
PY

# Smoke: the pruned interpreter must still import the daemon's stdlib surface.
# An Apple Silicon release Mac must prove the Intel slice through Rosetta. A
# cross-arch package that cannot execute is not a release artifact.
HOST_ARCH="$(/usr/bin/uname -m)"
case "$HOST_ARCH" in
  arm64) HOST_NORM="arm64" ;;
  x86_64) HOST_NORM="x64" ;;
  *) fail "cannot prove CPython execution on unsupported host architecture: $HOST_ARCH" ;;
esac
SMOKE_CODE="import json,sqlite3,ssl,hashlib,hmac,socket,subprocess,select,pty,termios,fcntl,struct,plistlib,urllib.request,cryptography,cffi,pycparser,platform,sys; expected='${ARCH}'; actual='arm64' if platform.machine() == 'arm64' else 'x64' if platform.machine() == 'x86_64' else platform.machine(); assert actual == expected, (actual, expected); assert platform.python_version() == '${PY_VERSION}'; assert cryptography.__version__ == '${CRYPTOGRAPHY_VERSION}'; assert cffi.__version__ == '${CFFI_VERSION}'; assert pycparser.__version__ == '${PYCPARSER_VERSION}'; print('stdlib-ok', actual)"
if [[ "$ARCH" == "$HOST_NORM" ]]; then
  PYTHONDONTWRITEBYTECODE=1 "$WORK/python/bin/python3" -B -c "$SMOKE_CODE" \
    || fail "pruned CPython failed stdlib import smoke"
elif [[ "$HOST_NORM" == "arm64" && "$ARCH" == "x64" ]]; then
  [[ -x /usr/bin/arch ]] || fail "Rosetta smoke requires /usr/bin/arch"
  PYTHONDONTWRITEBYTECODE=1 /usr/bin/arch -x86_64 "$WORK/python/bin/python3" -B -c "$SMOKE_CODE" \
    || fail "x64 CPython failed the required Rosetta stdlib import smoke"
else
  fail "cannot prove cross-arch CPython execution ($ARCH on $HOST_NORM host)"
fi
bytecode_residue="$(find "$WORK/python" \( -name '__pycache__' -o -name '*.pyc' \) -print -quit)"
[[ -z "$bytecode_residue" ]] \
  || fail "vendored CPython contains forbidden bytecode after smoke: $bytecode_residue"

# --- sign every Mach-O under our Developer ID -------------------------------
sign_one() {
  local f="$1" identifier="$2"
  if [[ "$SIGN_IDENTITY" == "-" ]]; then
    /usr/bin/codesign --force --options runtime --identifier "$identifier" --sign - "$f"
  else
    /usr/bin/codesign --force --timestamp --options runtime --identifier "$identifier" --sign "$SIGN_IDENTITY" "$f"
  fi
  /usr/bin/codesign --verify --strict "$f"
  if [[ "$SIGN_IDENTITY" != "-" ]]; then
    /usr/bin/codesign --verify --strict --verbose=2 \
      -R="anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists" \
      "$f" \
      || fail "Python Mach-O is not signed with a Developer ID Application certificate: $f"
  fi
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
