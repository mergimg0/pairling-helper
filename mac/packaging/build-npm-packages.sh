#!/usr/bin/env bash
set -euo pipefail

# Builds the three Pairling npm packages:
#   pairling                        (CLI shim + source payload + integrity manifest)
#   @pairling/runtime-darwin-arm64  (signed pairling-connectd, Apple Silicon)
#   @pairling/runtime-darwin-x64    (signed pairling-connectd, Intel)
#
# npm install of these packages runs no code (no lifecycle scripts); all
# mutation happens in the explicit `pairling setup` flow inside the payload.
# This script never publishes — it only assembles and packs.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="${PAIRLING_DIST_DIR:-$REPO_ROOT/dist}/npm"
SIGN_IDENTITY="${PAIRLING_SIGN_IDENTITY:-}"
NOTARY_PROFILE="${PAIRLING_NOTARY_PROFILE:-pairling-notary}"
EXPECTED_TEAM_ID="${PAIRLING_CONNECTD_TEAM_ID:-965AVD34A3}"
VERSION_OVERRIDE=""
NOTARIZE="0"
ALLOW_DIRTY="0"
RELEASE_MODE="0"
PREBUILT_ARM64=""
PREBUILT_X64=""
PREBUILT_PYTHON_ARM64=""
PREBUILT_PYTHON_X64=""
VENDOR_PYTHON="0"

usage() {
  cat <<'EOF'
usage: mac/packaging/build-npm-packages.sh [options]

Options:
  --version X.Y.Z         npm semver for all three packages.
                          Defaults to mac/VERSION, which must be semver.
  --release               Enforce release invariants: clean source tree,
                          Developer ID signing, semver version. Implies
                          --vendor-python.
  --vendor-python         Vendor a signed CPython (dev.pairling.python) into
                          each runtime package (P3 Python custody).
  --notarize              Notarize each connectd binary and (with
                          --vendor-python) each CPython, via xcrun notarytool
                          keychain profile pairling-notary.
  --prebuilt-arm64 PATH   Use an already-built/signed arm64 pairling-connectd
                          instead of building (CI assembly mode).
  --prebuilt-x64 PATH     Same for x64.
  --allow-dirty           Permit a dirty source tree (dev builds only).

Environment:
  PAIRLING_SIGN_IDENTITY     codesign identity ("-" for local ad-hoc tests).
  PAIRLING_CONNECTD_TEAM_ID  Expected TeamIdentifier (default 965AVD34A3,
                             "-" disables the check for dev builds).
  PAIRLING_DIST_DIR          Output root. Defaults to ./dist.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION_OVERRIDE="${2:-}"; shift 2 ;;
    --release) RELEASE_MODE="1"; shift ;;
    --notarize) NOTARIZE="1"; shift ;;
    --prebuilt-arm64) PREBUILT_ARM64="${2:-}"; shift 2 ;;
    --prebuilt-x64) PREBUILT_X64="${2:-}"; shift 2 ;;
    --prebuilt-python-arm64) PREBUILT_PYTHON_ARM64="${2:-}"; shift 2 ;;
    --prebuilt-python-x64) PREBUILT_PYTHON_X64="${2:-}"; shift 2 ;;
    --vendor-python) VENDOR_PYTHON="1"; shift ;;
    --allow-dirty) ALLOW_DIRTY="1"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

log() { printf '%s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

VERSION="${VERSION_OVERRIDE:-$(tr -d '[:space:]' < "$REPO_ROOT/mac/VERSION")}"
SEMVER_RE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
if [[ ! "$VERSION" =~ $SEMVER_RE ]]; then
  fail "version '$VERSION' is not npm semver. Move mac/VERSION to semver for npm releases, or pass --version X.Y.Z."
fi

BUILD_REVISION="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
REVISION="${PAIRLING_SOURCE_REVISION:-$BUILD_REVISION}"
BRANCH="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
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
  "npm"
  "relay/app_attest_validator.py"
)
SOURCE_DIRTY="false"
if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 && \
   [[ -n "$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all -- "${PACKAGED_SOURCE_PATHS[@]}" 2>/dev/null)" ]]; then
  SOURCE_DIRTY="true"
fi

require_release_source_traceability() {
  local tag="v$VERSION"
  local tagged_commit remote_tag_commit
  git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || fail "--release requires a git worktree"
  [[ "$BUILD_REVISION" != "unknown" ]] || fail "--release could not read git build revision"
  git -C "$REPO_ROOT" cat-file -e "$BUILD_REVISION^{commit}" 2>/dev/null \
    || fail "--release build revision does not resolve to a commit: $BUILD_REVISION"
  if [[ -n "${PAIRLING_SOURCE_REVISION:-}" ]]; then
    [[ "$REVISION" =~ ^[0-9a-f]{40}$ ]] || fail "--release PAIRLING_SOURCE_REVISION must be a full git sha"
  else
    git -C "$REPO_ROOT" cat-file -e "$REVISION^{commit}" 2>/dev/null \
      || fail "--release source revision does not resolve to a commit: $REVISION"
  fi
  git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/$tag^{tag}" >/dev/null \
    || fail "--release requires annotated tag $tag"
  tagged_commit="$(git -C "$REPO_ROOT" rev-list -n 1 "$tag" 2>/dev/null || true)"
  [[ "$tagged_commit" == "$BUILD_REVISION" ]] || fail "--release tag $tag does not point at HEAD $BUILD_REVISION"
  remote_tag_commit="$(git -C "$REPO_ROOT" ls-remote origin "refs/tags/$tag^{}" 2>/dev/null | awk '{ print $1; exit }')"
  [[ "$remote_tag_commit" == "$BUILD_REVISION" ]] || fail "--release tag $tag is not pushed to origin at $BUILD_REVISION"
}

require_release_version_unpublished() {
  local pkg out existing
  for pkg in "pairling" "@pairling/runtime-darwin-arm64" "@pairling/runtime-darwin-x64"; do
    if out="$(npm view "$pkg@$VERSION" version --json 2>&1)"; then
      existing="$(printf '%s' "$out" | tr -d '"[:space:]')"
      [[ "$existing" != "$VERSION" ]] \
        || fail "--release version $VERSION is already published for $pkg; bump mac/VERSION first."
    elif ! printf '%s' "$out" | grep -Eq 'E404|No match found'; then
      fail "--release could not verify npm registry state for $pkg@$VERSION"
    fi
  done
}

require_release_version_sources() {
  local source_version
  source_version="$(tr -d '[:space:]' < "$REPO_ROOT/mac/VERSION")"
  [[ "$VERSION" == "$source_version" ]] \
    || fail "--release version $VERSION does not match mac/VERSION $source_version."

  python3 - "$REPO_ROOT" "$VERSION" <<'PY' || fail "--release npm source package versions must all match $VERSION."
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
expected = sys.argv[2]
paths = (
    Path("npm/pairling/package.json"),
    Path("npm/runtime-darwin-arm64/package.json"),
    Path("npm/runtime-darwin-x64/package.json"),
)
errors = []
for relative in paths:
    try:
        actual = str(json.loads((root / relative).read_text())["version"])
    except Exception as exc:
        errors.append(f"{relative}: {type(exc).__name__}: {exc}")
        continue
    if actual != expected:
        errors.append(f"{relative}: version {actual!r} does not match release {expected!r}")
if errors:
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
}

if [[ "$RELEASE_MODE" == "1" ]]; then
  [[ "$ALLOW_DIRTY" != "1" ]] || fail "--allow-dirty is only for non-release builds."
  require_release_version_unpublished
  require_release_version_sources
  require_release_source_traceability
  [[ "$SOURCE_DIRTY" == "false" ]] || fail "source tree is dirty; commit first."
  [[ -n "$SIGN_IDENTITY" && "$SIGN_IDENTITY" != "-" ]] || [[ -n "$PREBUILT_ARM64" ]] || fail "--release requires PAIRLING_SIGN_IDENTITY (Developer ID) or prebuilt signed connectd binaries."
  # A release ships the vendored CPython (P3 custody) in the runtime packages.
  VENDOR_PYTHON="1"
  # Custody guard: CI has no Developer ID cert, so it MUST supply pre-signed
  # python tarballs (built+signed on the release Mac). Never ship unsigned.
  if [[ -z "$SIGN_IDENTITY" || "$SIGN_IDENTITY" == "-" ]]; then
    [[ -n "$PREBUILT_PYTHON_ARM64" && -n "$PREBUILT_PYTHON_X64" ]] \
      || fail "--release without a Developer ID identity requires --prebuilt-python-arm64 and --prebuilt-python-x64 (CI must not re-vendor/sign python)."
  fi
fi

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

STAGE="$WORK/stage"
BIN_BUILD="$WORK/bin"
mkdir -p "$STAGE" "$BIN_BUILD" "$DIST_DIR"
rm -f "$DIST_DIR"/*.tgz "$DIST_DIR/SHASUMS256.txt" 2>/dev/null || true

# --- payload assembly (mirrors build-helper-artifact.sh, minus the retired
# --- helper-assistant app; the npm path is CLI-first) -----------------------
PAYLOAD="$STAGE/pairling/payload"
MACPAY="$PAYLOAD/mac"
mkdir -p \
  "$MACPAY/companiond/providers" \
  "$MACPAY/companiond/integrations/aperture_cli" \
  "$MACPAY/connectd/cmd" \
  "$MACPAY/connectd/internal" \
  "$MACPAY/install" \
  "$MACPAY/mcp" \
  "$MACPAY/packaging/bin"

printf '%s\n' "$VERSION" > "$MACPAY/VERSION"
printf '%s\n' "$REVISION" > "$MACPAY/SOURCE_REVISION"
printf '%s\n' "$BRANCH" > "$MACPAY/SOURCE_BRANCH"
printf '%s\n' "$SOURCE_DIRTY" > "$MACPAY/SOURCE_DIRTY"
cp "$REPO_ROOT/mac/companiond/"*.py "$MACPAY/companiond/"
APP_ATTEST_VALIDATOR="$REPO_ROOT/relay/app_attest_validator.py"
if [[ ! -f "$APP_ATTEST_VALIDATOR" ]]; then
  APP_ATTEST_VALIDATOR="$REPO_ROOT/mac/companiond/app_attest_validator.py"
fi
if [[ ! -f "$APP_ATTEST_VALIDATOR" || ! -f "$REPO_ROOT/mac/companiond/apple-app-attest-root-ca.pem" ]]; then
  echo "ERROR: App Attest validator or Apple root certificate is missing" >&2
  exit 1
fi
cp "$APP_ATTEST_VALIDATOR" "$MACPAY/companiond/app_attest_validator.py"
cp "$REPO_ROOT/mac/companiond/apple-app-attest-root-ca.pem" "$MACPAY/companiond/"
cp "$REPO_ROOT/mac/companiond/providers/"*.py "$MACPAY/companiond/providers/"
cp "$REPO_ROOT/mac/companiond/providers/"*.json "$MACPAY/companiond/providers/"
cp "$REPO_ROOT/mac/companiond/integrations/__init__.py" "$MACPAY/companiond/integrations/"
cp "$REPO_ROOT/mac/companiond/integrations/aperture_cli/"*.py "$MACPAY/companiond/integrations/aperture_cli/"
cp "$REPO_ROOT/mac/mcp/"*.py "$MACPAY/mcp/"
cp "$REPO_ROOT/mac/install/"*.sh "$MACPAY/install/"
cp "$REPO_ROOT/mac/install/"*.py "$MACPAY/install/"
cp "$REPO_ROOT/mac/connectd/go.mod" "$REPO_ROOT/mac/connectd/go.sum" "$MACPAY/connectd/"
cp -R "$REPO_ROOT/mac/connectd/cmd" "$MACPAY/connectd/"
cp -R "$REPO_ROOT/mac/connectd/internal" "$MACPAY/connectd/"
cp "$REPO_ROOT/mac/packaging/bin/pairling" "$MACPAY/packaging/bin/"

chmod 755 "$MACPAY/packaging/bin/pairling" "$MACPAY/install/"*.sh "$MACPAY/mcp/phone_tools.py" \
  "$MACPAY/companiond/pairlingd.py"
chmod 644 "$MACPAY/companiond/providers/"*.py "$MACPAY/companiond/providers/"*.json
find "$MACPAY" -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true

PYCACHE="$(mktemp -d)"
PYTHONPYCACHEPREFIX="$PYCACHE" python3 -m py_compile \
  "$MACPAY/companiond/"*.py \
  "$MACPAY/companiond/providers/"*.py \
  "$MACPAY/companiond/integrations/"*.py \
  "$MACPAY/companiond/integrations/aperture_cli/"*.py \
  "$MACPAY/mcp/"*.py \
  "$MACPAY/install/"*.py
rm -rf "$PYCACHE"

# --- connectd binaries ------------------------------------------------------
sign_and_verify() {
  local binary="$1"
  local identifier="${2:-dev.pairling.connectd}"
  if [[ -n "$SIGN_IDENTITY" ]]; then
    if [[ "$SIGN_IDENTITY" == "-" ]]; then
      /usr/bin/codesign --force --options runtime --identifier "$identifier" --sign - "$binary"
    else
      /usr/bin/codesign --force --timestamp --options runtime --identifier "$identifier" --sign "$SIGN_IDENTITY" "$binary"
    fi
    /usr/bin/codesign --verify --strict --verbose=2 "$binary"
  else
    log "WARNING: $binary is unsigned (PAIRLING_SIGN_IDENTITY unset). pairling setup will reject it under the default Team ID policy."
  fi
}

verify_prebuilt() {
  local binary="$1"
  [[ -f "$binary" ]] || fail "prebuilt binary missing: $binary"
  /usr/bin/codesign --verify --strict "$binary" || fail "prebuilt binary failed codesign verification: $binary"
  if [[ "$EXPECTED_TEAM_ID" != "-" ]]; then
    local team
    team="$(/usr/bin/codesign -dvv "$binary" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
    [[ "$team" == "$EXPECTED_TEAM_ID" ]] || fail "prebuilt binary TeamIdentifier '$team' != expected '$EXPECTED_TEAM_ID': $binary"
  fi
}

build_arch() {
  local goarch="$1" out="$2" pkg="${3:-./cmd/pairling-connectd}"
  local identifier="dev.pairling.connectd"
  command -v go >/dev/null 2>&1 || fail "go toolchain is required to build $(basename "$pkg")"
  (
    cd "$REPO_ROOT/mac/connectd"
    CGO_ENABLED=0 GOOS=darwin GOARCH="$goarch" go build -trimpath -ldflags "-s -w -buildid=" \
      -o "$out" "$pkg"
  )
  sign_and_verify "$out" "$identifier"
}

notarize_binary() {
  local binary="$1" label="$2"
  local zip="$WORK/$label.zip"
  /usr/bin/ditto -c -k "$binary" "$zip"
  xcrun notarytool submit "$zip" --keychain-profile "$NOTARY_PROFILE" --wait
}

CONNECTD_ARM64="$BIN_BUILD/pairling-connectd-arm64"
CONNECTD_X64="$BIN_BUILD/pairling-connectd-x64"
if [[ -n "$PREBUILT_ARM64" ]]; then
  verify_prebuilt "$PREBUILT_ARM64"; cp "$PREBUILT_ARM64" "$CONNECTD_ARM64"
else
  build_arch arm64 "$CONNECTD_ARM64"
fi
if [[ -n "$PREBUILT_X64" ]]; then
  verify_prebuilt "$PREBUILT_X64"; cp "$PREBUILT_X64" "$CONNECTD_X64"
else
  build_arch amd64 "$CONNECTD_X64"
fi
chmod 755 "$CONNECTD_ARM64" "$CONNECTD_X64"
if [[ "$NOTARIZE" == "1" ]]; then
  notarize_binary "$CONNECTD_ARM64" pairling-connectd-arm64
  notarize_binary "$CONNECTD_X64" pairling-connectd-x64
fi

team_of() {
  /usr/bin/codesign -dvv "$1" 2>&1 | sed -n 's/^TeamIdentifier=//p'
}

# --- stage the three packages ----------------------------------------------
cp "$REPO_ROOT/npm/pairling/package.json" "$STAGE/pairling/package.json"
cp "$REPO_ROOT/npm/pairling/README.md" "$STAGE/pairling/README.md"
mkdir -p "$STAGE/pairling/bin"
cp "$REPO_ROOT/npm/pairling/bin/pairling.mjs" "$STAGE/pairling/bin/pairling.mjs"
chmod 755 "$STAGE/pairling/bin/pairling.mjs"

verify_prebuilt_python() {
  local py="$1"
  [[ -x "$py" ]] || fail "prebuilt python missing: $py"
  /usr/bin/codesign --verify --strict "$py" || fail "prebuilt python failed codesign verification: $py"
  local id team
  id="$(/usr/bin/codesign -dvv "$py" 2>&1 | sed -n 's/^Identifier=//p')"
  [[ "$id" == "dev.pairling.python" ]] || fail "prebuilt python identifier '$id' != dev.pairling.python: $py"
  if [[ "$EXPECTED_TEAM_ID" != "-" ]]; then
    team="$(team_of "$py")"
    [[ "$team" == "$EXPECTED_TEAM_ID" ]] || fail "prebuilt python TeamIdentifier '$team' != expected '$EXPECTED_TEAM_ID': $py"
  fi
}

stage_runtime() {
  local arch="$1" binary="$2" prebuilt_python="$3"
  local dir="$STAGE/runtime-darwin-$arch"
  mkdir -p "$dir/bin"
  cp "$REPO_ROOT/npm/runtime-darwin-$arch/package.json" "$dir/package.json"
  cp "$REPO_ROOT/npm/runtime-darwin-$arch/README.md" "$dir/README.md"
  cp "$binary" "$dir/bin/pairling-connectd"
  chmod 755 "$dir/bin/pairling-connectd"

  # P3 CPython. Custody rule (same as connectd): the Developer ID signing only
  # happens on the release Mac. A prebuilt python tarball (already signed +
  # notarized) is consumed verbatim and verified — never re-signed. CI MUST use
  # a prebuilt; only the local release Mac vendors+signs from scratch.
  local python_bin="" python_team="" python_id=""
  if [[ -n "$prebuilt_python" ]]; then
    local ptmp; ptmp="$(mktemp -d)"
    tar -xzf "$prebuilt_python" -C "$ptmp" || fail "could not extract prebuilt python: $prebuilt_python"
    [[ -d "$ptmp/python" ]] || fail "prebuilt python tarball missing top-level python/ dir: $prebuilt_python"
    verify_prebuilt_python "$ptmp/python/bin/python3"
    rm -rf "$dir/python"; mv "$ptmp/python" "$dir/python"; rm -rf "$ptmp"
    python_bin="$dir/python/bin/python3"
  elif [[ "$VENDOR_PYTHON" == "1" ]]; then
    local notarize_arg=""
    [[ "$NOTARIZE" == "1" ]] && notarize_arg="--notarize"
    "$REPO_ROOT/mac/packaging/vendor-cpython.sh" --arch "$arch" --out "$dir" $notarize_arg
    python_bin="$dir/python/bin/python3"
    [[ -x "$python_bin" ]] || fail "vendor-cpython.sh did not produce $python_bin"
    # Emit the signed python as a standalone release asset so CI can consume it
    # as a prebuilt (CI cannot sign). Deterministic tarball.
    ( cd "$dir" && find python -exec touch -h -t 202001010000 {} + && \
      tar -czf "$DIST_DIR/pairling-python-$arch.tar.gz" python )
  fi
  if [[ -n "$python_bin" ]]; then
    python_team="$(team_of "$python_bin")"
    python_id="$(/usr/bin/codesign -dvv "$python_bin" 2>&1 | sed -n 's/^Identifier=//p')"
  fi

  python3 - "$dir/manifest.json" "$dir/bin/pairling-connectd" "$VERSION" "$REVISION" "$(team_of "$dir/bin/pairling-connectd")" "${python_bin:-}" "${python_team:-}" "${python_id:-}" <<'PY'
import hashlib, json, sys
out, binary, version, revision, team, python_bin, python_team, python_id = sys.argv[1:]
def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()
files = [
    {"path": "bin/pairling-connectd", "sha256": sha(binary), "team_id": team or None},
]
if python_bin:
    files.append({
        "path": "python/bin/python3",
        "sha256": sha(python_bin),
        "team_id": python_team or None,
        "identifier": python_id or None,
    })
json.dump({
    "schema_version": 1,
    "package_version": version,
    "source_revision": revision,
    "files": files,
}, open(out, "w"), indent=2, sort_keys=True)
open(out, "a").write("\n")
PY
}
stage_runtime arm64 "$CONNECTD_ARM64" "$PREBUILT_PYTHON_ARM64"
stage_runtime x64 "$CONNECTD_X64" "$PREBUILT_PYTHON_X64"

# Set versions + pin optionalDependencies exactly (never mutates npm/ sources).
python3 - "$STAGE" "$VERSION" <<'PY'
import json, sys
from pathlib import Path
stage, version = Path(sys.argv[1]), sys.argv[2]
for rel in ("runtime-darwin-arm64", "runtime-darwin-x64"):
    path = stage / rel / "package.json"
    data = json.loads(path.read_text())
    data["version"] = version
    path.write_text(json.dumps(data, indent=2) + "\n")
path = stage / "pairling" / "package.json"
data = json.loads(path.read_text())
data["version"] = version
data["optionalDependencies"] = {
    "@pairling/runtime-darwin-arm64": version,
    "@pairling/runtime-darwin-x64": version,
}
path.write_text(json.dumps(data, indent=2) + "\n")
PY

# --- payload integrity manifest ---------------------------------------------
python3 - "$STAGE/pairling" "$VERSION" "$REVISION" "$SOURCE_DIRTY" "$(team_of "$CONNECTD_ARM64")" "$CONNECTD_ARM64" "$(team_of "$CONNECTD_X64")" "$CONNECTD_X64" <<'PY'
import hashlib, json, sys
from pathlib import Path
pkg, version, revision, dirty, team_arm, bin_arm, team_x64, bin_x64 = sys.argv[1:]
pkg = Path(pkg)
payload = pkg / "payload"
files = []
for path in sorted(payload.rglob("*")):
    if path.is_file():
        files.append({
            "path": str(path.relative_to(pkg)),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
manifest = {
    "schema_version": 1,
    "package": "pairling",
    "package_version": version,
    "source_revision": revision,
    "source_dirty": dirty == "true",
    "connectd": {
        "darwin-arm64": {"sha256": hashlib.sha256(open(bin_arm, "rb").read()).hexdigest(), "team_id": team_arm or None},
        "darwin-x64": {"sha256": hashlib.sha256(open(bin_x64, "rb").read()).hexdigest(), "team_id": team_x64 or None},
    },
    "files": files,
}
(pkg / "payload-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY

# --- deterministic pack ------------------------------------------------------
find "$STAGE" -exec touch -h -t 202001010000 {} +
for dir in pairling runtime-darwin-arm64 runtime-darwin-x64; do
  (cd "$STAGE/$dir" && npm pack --silent --pack-destination "$DIST_DIR" >/dev/null)
done
(cd "$DIST_DIR" && /usr/bin/shasum -a 256 *.tgz > SHASUMS256.txt)

# Keep the raw binaries next to the tarballs for the GitHub Release asset flow.
cp "$CONNECTD_ARM64" "$DIST_DIR/pairling-connectd-arm64"
cp "$CONNECTD_X64" "$DIST_DIR/pairling-connectd-x64"
(cd "$DIST_DIR" && /usr/bin/shasum -a 256 pairling-connectd-arm64 pairling-connectd-x64 > CONNECTD-SHASUMS256.txt)

log "Built npm packages $VERSION (source $REVISION, dirty=$SOURCE_DIRTY)"
log "  dist: $DIST_DIR"
cat "$DIST_DIR/SHASUMS256.txt"
