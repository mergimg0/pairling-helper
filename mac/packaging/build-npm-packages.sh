#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

# Builds the three Pairling npm packages:
#   pairling                        (CLI shim + source payload + integrity manifest)
#   @pairling/runtime-darwin-arm64  (signed connectd and automation helper)
#   @pairling/runtime-darwin-x64    (signed connectd and automation helper)
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
PREBUILT_AUTOMATION_ARM64=""
PREBUILT_AUTOMATION_X64=""
RELEASE_EVIDENCE="${PAIRLING_RELEASE_EVIDENCE:-}"
VENDOR_PYTHON="0"

usage() {
  cat <<'EOF'
usage: mac/packaging/build-npm-packages.sh [options]

Options:
  --version X.Y.Z         npm semver for all seven packages.
                          Defaults to mac/VERSION, which must be semver.
  --release               Enforce release invariants: clean source tree,
                          Developer ID signing, semver version. Implies
                          --vendor-python.
  --vendor-python         Vendor a signed CPython (dev.pairling.python) into
                          each runtime package (P3 Python custody).
  --notarize              Notarize each connectd binary, each Pairling
                          automation helper app, and (with --vendor-python)
                          each CPython via xcrun notarytool keychain profile.
  --prebuilt-arm64 PATH   Use an already-built/signed arm64 pairling-connectd
                          instead of building (CI assembly mode).
  --prebuilt-x64 PATH     Same for x64.
  --prebuilt-python-arm64 PATH
                          Use an already-signed arm64 CPython archive.
  --prebuilt-python-x64 PATH
                          Same for x64.
  --prebuilt-automation-arm64 PATH
                          Use a signed, stapled arm64 Pairling automation
                          helper archive from the release assets.
  --prebuilt-automation-x64 PATH
                          Same for x64.
  --release-evidence PATH Verify release revision, notarization, and all
                          prebuilt digests against RELEASE-BINARIES.json schema 6.
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
    --prebuilt-automation-arm64) PREBUILT_AUTOMATION_ARM64="${2:-}"; shift 2 ;;
    --prebuilt-automation-x64) PREBUILT_AUTOMATION_X64="${2:-}"; shift 2 ;;
    --release-evidence) RELEASE_EVIDENCE="${2:-}"; shift 2 ;;
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
EVIDENCE_SHA256=""
EVIDENCE_CONNECTD_ARM64_SHA=""
EVIDENCE_CONNECTD_X64_SHA=""
EVIDENCE_PYTHON_ARM64_SHA=""
EVIDENCE_PYTHON_X64_SHA=""
EVIDENCE_AUTOMATION_ARM64_SHA=""
EVIDENCE_AUTOMATION_X64_SHA=""
if [[ -n "$RELEASE_EVIDENCE" ]]; then
  evidence_identity="$(python3 "$REPO_ROOT/mac/packaging/npm-release-evidence.py" verify \
    --evidence "$RELEASE_EVIDENCE" --version "$VERSION" \
    --mirror-source-root "$REPO_ROOT")" \
    || fail "release evidence identity verification failed"
  EVIDENCE_REVISION="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["source_revision"])' <<<"$evidence_identity")"
  EVIDENCE_SHA256="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["evidence_sha256"])' <<<"$evidence_identity")"
  EVIDENCE_CONNECTD_ARM64_SHA="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["asset_sha256"]["binaries"]["arm64"])' <<<"$evidence_identity")"
  EVIDENCE_CONNECTD_X64_SHA="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["asset_sha256"]["binaries"]["x64"])' <<<"$evidence_identity")"
  EVIDENCE_PYTHON_ARM64_SHA="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["asset_sha256"]["python"]["arm64"])' <<<"$evidence_identity")"
  EVIDENCE_PYTHON_X64_SHA="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["asset_sha256"]["python"]["x64"])' <<<"$evidence_identity")"
  EVIDENCE_AUTOMATION_ARM64_SHA="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["asset_sha256"]["automation"]["arm64"])' <<<"$evidence_identity")"
  EVIDENCE_AUTOMATION_X64_SHA="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["asset_sha256"]["automation"]["x64"])' <<<"$evidence_identity")"
  if [[ -n "${PAIRLING_SOURCE_REVISION:-}" && "$PAIRLING_SOURCE_REVISION" != "$EVIDENCE_REVISION" ]]; then
    fail "PAIRLING_SOURCE_REVISION does not match verified release evidence"
  fi
  REVISION="$EVIDENCE_REVISION"
else
  REVISION="${PAIRLING_SOURCE_REVISION:-$BUILD_REVISION}"
fi
BRANCH="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
PACKAGED_SOURCE_PATHS=(
  "mac/VERSION"
  "mac/companiond"
  "mac/connectd/cmd"
  "mac/connectd/internal"
  "mac/connectd/go.mod"
  "mac/connectd/go.sum"
  "mac/automation-helper"
  "mac/install"
  "mac/mcp"
  "mac/packaging/bin/pairling"
  "mac/packaging/pairling_attach.py"
  "mac/packaging/build-npm-packages.sh"
  "mac/packaging/npm-release-evidence.py"
  "mac/packaging/python-runtime-inputs.json"
  "mac/packaging/verify-prebuilt-python-archive.py"
  "mac/packaging/vendor-cpython.sh"
  "npm"
  "relay/app_attest_validator.py"
  "thoughts/shared/specs/coding-agent-remote-control-capability-map.json"
  "project.yml"
)
SOURCE_DIRTY="false"
if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 && \
   [[ -n "$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all -- "${PACKAGED_SOURCE_PATHS[@]}" 2>/dev/null)" ]]; then
  SOURCE_DIRTY="true"
fi

require_release_source_traceability() {
  local tag="v$VERSION"
  local tagged_commit remote_tag_commit remote_main_commit local_tag_object remote_tag_object origin_url expected_repository_sha
  git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || fail "--release requires a git worktree"
  [[ "$BUILD_REVISION" != "unknown" ]] || fail "--release could not read git build revision"
  git -C "$REPO_ROOT" cat-file -e "$BUILD_REVISION^{commit}" 2>/dev/null \
    || fail "--release build revision does not resolve to a commit: $BUILD_REVISION"
  origin_url="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || true)"
  if [[ -n "$RELEASE_EVIDENCE" ]]; then
    expected_repository_sha="33abebc9c629f9877e31b8c9f39670427ad5055d80ccdc8a51588101087a042a"
  else
    expected_repository_sha="59d2705328edc11607151f8602e184148bb2f90dd12a55ace53f96ccaf1da0cf"
  fi
  python3 - "$origin_url" "$expected_repository_sha" <<'PY' \
    || fail "--release origin repository is not allowlisted"
import hashlib, re, sys, urllib.parse
raw, expected = sys.argv[1:]
if raw.startswith("git@github.com:"):
    path = raw.removeprefix("git@github.com:")
elif raw.startswith("ssh://git@github.com/"):
    path = urllib.parse.urlparse(raw).path.lstrip("/")
elif raw.startswith("https://github.com/"):
    parsed = urllib.parse.urlparse(raw)
    if parsed.netloc.casefold() != "github.com" or parsed.query or parsed.fragment:
        raise SystemExit(1)
    path = parsed.path.lstrip("/")
else:
    raise SystemExit(1)
parts = [part for part in path.split("/") if part]
if len(parts) != 2:
    raise SystemExit(1)
canonical = f"github.com/{parts[0].casefold()}/{parts[1].removesuffix('.git').casefold()}"
if hashlib.sha256(canonical.encode()).hexdigest() != expected:
    raise SystemExit(1)
PY
  if [[ -n "${PAIRLING_SOURCE_REVISION:-}" || -n "$RELEASE_EVIDENCE" ]]; then
    [[ "$REVISION" =~ ^[0-9a-f]{40}$ ]] || fail "--release PAIRLING_SOURCE_REVISION must be a full git sha"
  else
    git -C "$REPO_ROOT" cat-file -e "$REVISION^{commit}" 2>/dev/null \
      || fail "--release source revision does not resolve to a commit: $REVISION"
  fi
  git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/$tag^{tag}" >/dev/null \
    || fail "--release requires annotated tag $tag"
  local_tag_object="$(git -C "$REPO_ROOT" rev-parse "refs/tags/$tag")"
  remote_tag_object="$(git -C "$REPO_ROOT" ls-remote origin "refs/tags/$tag" 2>/dev/null | awk '{ print $1; exit }')"
  [[ "$remote_tag_object" == "$local_tag_object" ]] \
    || fail "--release annotated tag object $tag is not the exact object pushed to origin"
  tagged_commit="$(git -C "$REPO_ROOT" rev-list -n 1 "$tag" 2>/dev/null || true)"
  [[ "$tagged_commit" == "$BUILD_REVISION" ]] || fail "--release tag $tag does not point at HEAD $BUILD_REVISION"
  remote_tag_commit="$(git -C "$REPO_ROOT" ls-remote origin "refs/tags/$tag^{}" 2>/dev/null | awk '{ print $1; exit }')"
  [[ "$remote_tag_commit" == "$BUILD_REVISION" ]] || fail "--release tag $tag is not pushed to origin at $BUILD_REVISION"
  remote_main_commit="$(git -C "$REPO_ROOT" ls-remote origin refs/heads/main 2>/dev/null | awk '{ print $1; exit }')"
  [[ "$remote_main_commit" == "$BUILD_REVISION" ]] \
    || fail "--release commit must be the exact commit published at origin/main"
}

require_release_version_unpublished() {
  local pkg out existing
  for pkg in \
    "@pairling/runtime-claude-darwin-arm64" \
    "@pairling/runtime-claude-darwin-x64" \
    "@pairling/runtime-copilot-darwin-arm64" \
    "@pairling/runtime-copilot-darwin-x64" \
    "@pairling/runtime-darwin-arm64" \
    "@pairling/runtime-darwin-x64" \
    "pairling"; do
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
    Path("npm/runtime-claude-darwin-arm64/package.json"),
    Path("npm/runtime-claude-darwin-x64/package.json"),
    Path("npm/runtime-copilot-darwin-arm64/package.json"),
    Path("npm/runtime-copilot-darwin-x64/package.json"),
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

require_release_artifact_evidence() {
  local requires_evidence="0" output
  local -a evidence_args
  if [[ -n "${PAIRLING_SOURCE_REVISION:-}" || -n "$PREBUILT_ARM64" || -n "$PREBUILT_X64" || \
        -n "$PREBUILT_PYTHON_ARM64" || -n "$PREBUILT_PYTHON_X64" || \
        -n "$PREBUILT_AUTOMATION_ARM64" || -n "$PREBUILT_AUTOMATION_X64" ]]; then
    requires_evidence="1"
  fi
  if [[ "$requires_evidence" == "1" && -z "$RELEASE_EVIDENCE" ]]; then
    fail "--release source overrides and prebuilts require --release-evidence"
  fi
  [[ -n "$RELEASE_EVIDENCE" ]] || return 0
  evidence_args=(
    verify
    --evidence "$RELEASE_EVIDENCE"
    --version "$VERSION"
    --source-revision "$REVISION"
    --mirror-source-root "$REPO_ROOT"
  )
  [[ -z "$PREBUILT_ARM64" ]] || evidence_args+=(--connectd-arm64 "$PREBUILT_ARM64")
  [[ -z "$PREBUILT_X64" ]] || evidence_args+=(--connectd-x64 "$PREBUILT_X64")
  [[ -z "$PREBUILT_PYTHON_ARM64" ]] || evidence_args+=(--python-arm64 "$PREBUILT_PYTHON_ARM64")
  [[ -z "$PREBUILT_PYTHON_X64" ]] || evidence_args+=(--python-x64 "$PREBUILT_PYTHON_X64")
  [[ -z "$PREBUILT_AUTOMATION_ARM64" ]] || evidence_args+=(--automation-arm64 "$PREBUILT_AUTOMATION_ARM64")
  [[ -z "$PREBUILT_AUTOMATION_X64" ]] || evidence_args+=(--automation-x64 "$PREBUILT_AUTOMATION_X64")
  output="$(python3 "$REPO_ROOT/mac/packaging/npm-release-evidence.py" "${evidence_args[@]}")" \
    || fail "release evidence does not bind the selected prebuilt assets"
  [[ "$(python3 -c 'import json,sys; print(json.load(sys.stdin)["evidence_sha256"])' <<<"$output")" == "$EVIDENCE_SHA256" ]] \
    || fail "release evidence changed during build setup"
}

require_package_source_inputs() {
  python3 - "$REPO_ROOT" <<'PY' || fail "compile/package source inputs are incomplete or unreviewed"
import hashlib
import importlib.util
import sys
from pathlib import Path

root = Path(sys.argv[1])
errors = []
verifier_path = root / "mac/install/verify-payload-manifest.py"
spec = importlib.util.spec_from_file_location("_pairling_package_source_gate", verifier_path)
if spec is None or spec.loader is None:
    raise SystemExit("payload verifier cannot be loaded")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
for relative in verifier.CANONICAL_DAEMON_SOURCE_PATHS:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        errors.append(f"canonical daemon module missing: {relative}")
provider_root = root / "mac/companiond/providers"
for name, digest in verifier.PROVIDER_RUNTIME_ASSET_DIGESTS.items():
    path = provider_root / name
    if (
        path.is_symlink()
        or not path.is_file()
        or hashlib.sha256(path.read_bytes()).hexdigest() != digest
    ):
        errors.append(f"native provider runtime asset missing or unreviewed: {name}")

required_inputs = ("relay/app_attest_validator.py",)
for relative in required_inputs:
    path = root / relative
    if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0:
        errors.append(f"package source input missing or unsafe: {relative}")
if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)
PY
}




if [[ "$RELEASE_MODE" == "1" ]]; then
  [[ "$ALLOW_DIRTY" != "1" ]] || fail "--allow-dirty is only for non-release builds."
  require_release_version_unpublished
  require_release_version_sources
  require_package_source_inputs
  require_release_artifact_evidence
  require_release_source_traceability
  [[ "$SOURCE_DIRTY" == "false" ]] || fail "source tree is dirty; commit first."
  if [[ -z "$PREBUILT_ARM64" || -z "$PREBUILT_X64" || \
        -z "$PREBUILT_PYTHON_ARM64" || -z "$PREBUILT_PYTHON_X64" || \
        -z "$PREBUILT_AUTOMATION_ARM64" || -z "$PREBUILT_AUTOMATION_X64" ]]; then
    [[ -n "$SIGN_IDENTITY" && "$SIGN_IDENTITY" != "-" ]] \
      || fail "--release requires a real Developer ID identity for every locally created runtime asset."
    [[ "$NOTARIZE" == "1" ]] \
      || fail "--release must use --notarize whenever it creates runtime assets locally."
  fi
  # A release ships the vendored CPython (P3 custody) in the runtime packages.
  VENDOR_PYTHON="1"
  # Custody guard: CI has no Developer ID cert, so it MUST supply pre-signed
  # CPython and stapled helper archives built on the release Mac.
  if [[ -z "$SIGN_IDENTITY" || "$SIGN_IDENTITY" == "-" ]]; then
    [[ -n "$PREBUILT_PYTHON_ARM64" && -n "$PREBUILT_PYTHON_X64" && \
       -n "$PREBUILT_AUTOMATION_ARM64" && -n "$PREBUILT_AUTOMATION_X64" ]] \
      || fail "--release without a Developer ID identity requires prebuilt Python and Pairling automation helper archives."
  fi
  BRANCH="main"
else
  require_package_source_inputs
fi

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

SOURCE_ROOT="$REPO_ROOT"
if [[ "$RELEASE_MODE" == "1" ]]; then
  SOURCE_ROOT="$WORK/source"
  mkdir -m 700 "$SOURCE_ROOT"
  git -C "$REPO_ROOT" archive --format=tar "$BUILD_REVISION" \
    | /usr/bin/tar -xf - -C "$SOURCE_ROOT"
  [[ -f "$SOURCE_ROOT/mac/packaging/build-npm-packages.sh" ]] \
    || fail "release source archive is missing the npm package builder"
  if [[ -n "$RELEASE_EVIDENCE" ]]; then
    archived_evidence_identity="$(python3 "$SOURCE_ROOT/mac/packaging/npm-release-evidence.py" verify \
      --evidence "$RELEASE_EVIDENCE" --version "$VERSION" \
      --source-revision "$REVISION" \
      --mirror-source-root "$SOURCE_ROOT")" \
      || fail "release evidence does not bind the exact archived release source"
    [[ "$(python3 -c 'import json,sys; print(json.load(sys.stdin)["evidence_sha256"])' <<<"$archived_evidence_identity")" == "$EVIDENCE_SHA256" ]] \
      || fail "release evidence changed before archived-source verification"
  fi
fi

STAGE="$WORK/stage"
BIN_BUILD="$WORK/bin"
mkdir -p "$STAGE" "$BIN_BUILD" "$DIST_DIR"
rm -f \
  "$DIST_DIR"/*.tgz \
  "$DIST_DIR/SHASUMS256.txt" \
  "$DIST_DIR/CONNECTD-SHASUMS256.txt" \
  "$DIST_DIR/AUTOMATION-SHASUMS256.txt" \
  "$DIST_DIR/NOTARIZATION-RECEIPTS.json" \
  "$DIST_DIR"/pairling-connectd-* \
  "$DIST_DIR"/pairling-python-*.tar.gz \
  "$DIST_DIR"/pairling-automation-*.zip \
  2>/dev/null || true

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
cp "$SOURCE_ROOT/mac/companiond/"*.py "$MACPAY/companiond/"
APP_ATTEST_VALIDATOR="$SOURCE_ROOT/relay/app_attest_validator.py"
if [[ ! -f "$APP_ATTEST_VALIDATOR" || \
      ! -f "$SOURCE_ROOT/mac/companiond/apple-app-attest-root-ca.pem" || \
      ! -f "$SOURCE_ROOT/mac/companiond/relay-claim-2026-07-v1.pem" ]]; then
  echo "ERROR: Pairling runtime trust assets are missing" >&2
  exit 1
fi
cp "$APP_ATTEST_VALIDATOR" "$MACPAY/companiond/app_attest_validator.py"
cp "$SOURCE_ROOT/mac/companiond/apple-app-attest-root-ca.pem" "$MACPAY/companiond/"
cp "$SOURCE_ROOT/mac/companiond/relay-claim-2026-07-v1.pem" "$MACPAY/companiond/"
cp "$SOURCE_ROOT/mac/companiond/providers/"*.py "$MACPAY/companiond/providers/"
cp "$SOURCE_ROOT/mac/companiond/providers/"*.json "$MACPAY/companiond/providers/"
python3 "$SOURCE_ROOT/mac/install/verify-runtime-package-manifest.py" \
  --stage-provider-runtime-assets "$SOURCE_ROOT/mac/companiond/providers" \
  "$MACPAY/companiond/providers" \
  || fail "could not stage the reviewed provider runtime asset inventory"
cp "$SOURCE_ROOT/thoughts/shared/specs/coding-agent-remote-control-capability-map.json" \
  "$MACPAY/companiond/providers/provider-control-capability-map.json"
python3 - "$SOURCE_ROOT/mac/companiond/providers/operations.py" \
  "$MACPAY/companiond/providers/reviewed-operation-manifest.json" \
  "$SOURCE_ROOT" "$REVISION" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
output = Path(sys.argv[2])
source_root = Path(sys.argv[3])
source_revision = sys.argv[4]
spec = importlib.util.spec_from_file_location("_pairling_packaged_operations", source)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load reviewed provider operation module")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
payload = module.release_operation_manifest_payload(
    source_revision=source_revision,
    source_root=source_root,
)
output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
cp "$SOURCE_ROOT/mac/companiond/integrations/__init__.py" "$MACPAY/companiond/integrations/"
cp "$SOURCE_ROOT/mac/companiond/integrations/aperture_cli/"*.py "$MACPAY/companiond/integrations/aperture_cli/"
cp "$SOURCE_ROOT/mac/mcp/"*.py "$MACPAY/mcp/"
cp "$SOURCE_ROOT/mac/install/"*.sh "$MACPAY/install/"
cp "$SOURCE_ROOT/mac/install/"*.py "$MACPAY/install/"
cp "$SOURCE_ROOT/mac/connectd/go.mod" "$SOURCE_ROOT/mac/connectd/go.sum" "$MACPAY/connectd/"
cp -R "$SOURCE_ROOT/mac/connectd/cmd" "$MACPAY/connectd/"
cp -R "$SOURCE_ROOT/mac/connectd/internal" "$MACPAY/connectd/"
cp "$SOURCE_ROOT/mac/packaging/bin/pairling" "$MACPAY/packaging/bin/"
cp "$SOURCE_ROOT/mac/packaging/pairling_attach.py" "$MACPAY/packaging/"

find "$MACPAY" -type f -exec chmod 644 {} +
chmod 755 \
  "$MACPAY/companiond/pairlingd.py" \
  "$MACPAY/install/bootstrap-first-run.sh" \
  "$MACPAY/install/doctor.sh" \
  "$MACPAY/install/install-runtime.sh" \
  "$MACPAY/install/uninstall-runtime.sh" \
  "$MACPAY/mcp/phone_tools.py" \
  "$MACPAY/packaging/bin/pairling"
find "$MACPAY" -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true

PYCACHE="$(mktemp -d)"
PYTHONPYCACHEPREFIX="$PYCACHE" python3 -m py_compile \
  "$MACPAY/companiond/"*.py \
  "$MACPAY/companiond/providers/"*.py \
  "$MACPAY/companiond/integrations/"*.py \
  "$MACPAY/companiond/integrations/aperture_cli/"*.py \
  "$MACPAY/packaging/pairling_attach.py" \
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
    if [[ "$SIGN_IDENTITY" != "-" ]]; then
      /usr/bin/codesign --verify --strict --verbose=2 \
        -R="anchor apple generic and certificate leaf[subject.OU] = \"$EXPECTED_TEAM_ID\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists" \
        "$binary" \
        || fail "built binary is not signed with the expected Developer ID Application certificate: $binary"
    fi
  else
    log "WARNING: $binary is unsigned (PAIRLING_SIGN_IDENTITY unset). pairling setup will reject it under the default Team ID policy."
  fi
}

AUTOMATION_HELPER_BUNDLE_ID="dev.pairling.automation"
AUTOMATION_HELPER_APP_NAME="Pairling.app"
AUTOMATION_HELPER_EXECUTABLE="PairlingAutomation"

verify_automation_helper_bundle() {
  local app="$1" arch="$2" expected_arch bundle_id entitlement runtime_output
  local executable="$app/Contents/MacOS/$AUTOMATION_HELPER_EXECUTABLE"
  [[ -d "$app" && ! -L "$app" ]] || fail "automation helper bundle is missing or linked: $app"
  [[ -f "$app/Contents/Info.plist" && ! -L "$app/Contents/Info.plist" ]] \
    || fail "automation helper Info.plist is missing or linked: $app"
  [[ -f "$executable" && ! -L "$executable" ]] \
    || fail "automation helper executable is missing or linked: $app"
  bundle_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist" 2>/dev/null || true)"
  [[ "$bundle_id" == "$AUTOMATION_HELPER_BUNDLE_ID" ]] \
    || fail "automation helper bundle identifier is invalid: $bundle_id"
  expected_arch="$arch"
  [[ "$expected_arch" != "x64" ]] || expected_arch="x86_64"
  [[ "$(/usr/bin/lipo -archs "$executable" 2>/dev/null)" == "$expected_arch" ]] \
    || fail "automation helper architecture does not match $arch: $app"
  [[ -n "$SIGN_IDENTITY" ]] || return 0
  /usr/bin/codesign --verify --strict --verbose=2 "$app" \
    || fail "automation helper failed codesign verification: $app"
  bundle_id="$(/usr/bin/codesign -dvv "$app" 2>&1 | sed -n 's/^Identifier=//p')"
  [[ "$bundle_id" == "$AUTOMATION_HELPER_BUNDLE_ID" ]] \
    || fail "automation helper signing identifier is invalid: $bundle_id"
  runtime_output="$(/usr/bin/codesign -dvv "$app" 2>&1)"
  [[ "$runtime_output" == *"Runtime Version="* ]] \
    || fail "automation helper is missing the hardened runtime: $app"
  entitlement="$(/usr/bin/codesign -d --entitlements :- "$app" 2>/dev/null)"
  python3 -c '
import plistlib
import sys
value = plistlib.loads(sys.stdin.buffer.read())
raise SystemExit(0 if value.get("com.apple.security.automation.apple-events") is True else 1)
' <<<"$entitlement" \
    || fail "automation helper is missing the Apple Events entitlement: $app"
  if [[ "$SIGN_IDENTITY" != "-" ]]; then
    local team
    team="$(/usr/bin/codesign -dvv "$app" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
    [[ "$team" == "$EXPECTED_TEAM_ID" ]] \
      || fail "automation helper TeamIdentifier '$team' != expected '$EXPECTED_TEAM_ID': $app"
    /usr/bin/codesign --verify --strict --verbose=2 \
      -R="anchor apple generic and certificate leaf[subject.OU] = \"$EXPECTED_TEAM_ID\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists" \
      "$app" \
      || fail "automation helper is not signed with the expected Developer ID Application certificate: $app"
  fi
}

sign_automation_helper_bundle() {
  local app="$1"
  [[ -n "$SIGN_IDENTITY" ]] || {
    log "WARNING: $app is unsigned (PAIRLING_SIGN_IDENTITY unset). pairling setup will reject it under the default Team ID policy."
    return 0
  }
  if [[ "$SIGN_IDENTITY" == "-" ]]; then
    /usr/bin/codesign --force --options runtime \
      --entitlements "$SOURCE_ROOT/mac/automation-helper/PairlingAutomation.entitlements" \
      --identifier "$AUTOMATION_HELPER_BUNDLE_ID" --sign - "$app"
  else
    /usr/bin/codesign --force --timestamp --options runtime \
      --entitlements "$SOURCE_ROOT/mac/automation-helper/PairlingAutomation.entitlements" \
      --identifier "$AUTOMATION_HELPER_BUNDLE_ID" --sign "$SIGN_IDENTITY" "$app"
  fi
}

generate_automation_helper_project() {
  command -v xcodegen >/dev/null 2>&1 \
    || fail "xcodegen is required to build the Pairling automation helper"
  [[ -f "$SOURCE_ROOT/project.yml" && -d "$SOURCE_ROOT/mac/automation-helper" ]] \
    || fail "automation helper source is incomplete"
  (
    cd "$SOURCE_ROOT"
    xcodegen generate
  ) || fail "could not generate the Pairling automation helper project"
}

build_automation_helper() {
  local arch="$1" destination="$2" xcode_arch derived built
  xcode_arch="$arch"
  [[ "$xcode_arch" != "x64" ]] || xcode_arch="x86_64"
  derived="$WORK/automation-helper-$arch"
  /usr/bin/xcodebuild \
    -project "$SOURCE_ROOT/Pairling.xcodeproj" \
    -scheme PairlingAutomation \
    -configuration Release \
    -derivedDataPath "$derived" \
    ARCHS="$xcode_arch" \
    ONLY_ACTIVE_ARCH=NO \
    CODE_SIGNING_ALLOWED=NO \
    MARKETING_VERSION="$VERSION" \
    CURRENT_PROJECT_VERSION=1 \
    build \
    || fail "could not build the Pairling automation helper for $arch"
  built="$derived/Build/Products/Release/$AUTOMATION_HELPER_APP_NAME"
  [[ -d "$built" && ! -L "$built" ]] \
    || fail "automation helper build output is missing for $arch"
  mkdir -p "$(dirname "$destination")"
  /usr/bin/ditto "$built" "$destination"
  sign_automation_helper_bundle "$destination"
  verify_automation_helper_bundle "$destination" "$arch"
}

verify_prebuilt() {
  local binary="$1" arch="$2" expected_sha="${3:-}" expected_arch identifier actual_sha
  [[ -f "$binary" ]] || fail "prebuilt binary missing: $binary"
  [[ ! -L "$binary" ]] || fail "prebuilt binary must not be a symlink: $binary"
  if [[ -n "$expected_sha" ]]; then
    actual_sha="$(/usr/bin/shasum -a 256 "$binary" | awk '{ print $1 }')"
    [[ "$actual_sha" == "$expected_sha" ]] \
      || fail "prebuilt binary sha256 does not match loaded release evidence: $binary"
  fi
  /usr/bin/codesign --verify --strict --verbose=2 "$binary" || fail "prebuilt binary failed codesign verification: $binary"
  identifier="$(/usr/bin/codesign -dvv "$binary" 2>&1 | sed -n 's/^Identifier=//p')"
  [[ "$identifier" == "dev.pairling.connectd" ]] \
    || fail "prebuilt binary identifier '$identifier' != dev.pairling.connectd: $binary"
  expected_arch="$arch"
  [[ "$expected_arch" != "x64" ]] || expected_arch="x86_64"
  [[ "$(/usr/bin/lipo -archs "$binary" 2>/dev/null)" == "$expected_arch" ]] \
    || fail "prebuilt binary architecture does not match $arch: $binary"
  if [[ "$EXPECTED_TEAM_ID" != "-" ]]; then
    local team
    team="$(/usr/bin/codesign -dvv "$binary" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
    [[ "$team" == "$EXPECTED_TEAM_ID" ]] || fail "prebuilt binary TeamIdentifier '$team' != expected '$EXPECTED_TEAM_ID': $binary"
    /usr/bin/codesign --verify --strict --verbose=2 \
      -R="anchor apple generic and certificate leaf[subject.OU] = \"$EXPECTED_TEAM_ID\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists" \
      "$binary" \
      || fail "prebuilt binary is not signed with the expected Developer ID Application certificate: $binary"
  fi
}

build_arch() {
  local goarch="$1" out="$2" pkg="${3:-./cmd/pairling-connectd}"
  local identifier="dev.pairling.connectd"
  command -v go >/dev/null 2>&1 || fail "go toolchain is required to build $(basename "$pkg")"
  (
    cd "$SOURCE_ROOT/mac/connectd"
    CGO_ENABLED=0 GOOS=darwin GOARCH="$goarch" go build -buildvcs=false -trimpath \
      -ldflags "-s -w -buildid= -X main.buildVersion=$VERSION -X main.buildSourceRevision=$REVISION -X main.buildSourceDirty=$SOURCE_DIRTY" \
      -o "$out" "$pkg"
  )
  sign_and_verify "$out" "$identifier"
}

verify_connectd_build_info() {
  local binary="$1" arch="$2" output
  if [[ "$arch" == "x64" && "$(uname -m)" == "arm64" ]]; then
    output="$(/usr/bin/arch -x86_64 "$binary" --build-info-json)" \
      || fail "connectd $arch build-info smoke test failed"
  elif [[ "$arch" == "arm64" && "$(uname -m)" != "arm64" ]]; then
    fail "cannot smoke-test arm64 connectd on $(uname -m)"
  else
    output="$("$binary" --build-info-json)" || fail "connectd $arch build-info smoke test failed"
  fi
  python3 - "$output" "$VERSION" "$REVISION" "$SOURCE_DIRTY" "$arch" <<'PY' \
    || fail "connectd $arch build provenance does not match this package build"
import json, sys
raw, version, revision, dirty, arch = sys.argv[1:]
try:
    value = json.loads(raw)
except Exception as exc:
    raise SystemExit(f"connectd {arch} build info is not JSON: {exc}")
expected = {
    "schema_version": 1,
    "version": version,
    "source_revision": revision,
    "source_dirty": dirty == "true",
}
if value != expected:
    raise SystemExit(f"connectd {arch} build info mismatch: {value!r} != {expected!r}")
PY
}

tree_sha256() {
  python3 - "$1" <<'PY'
import hashlib, os, stat, sys
from pathlib import Path

root = Path(sys.argv[1])
if root.is_symlink() or not root.is_dir():
    raise SystemExit(f"tree is not a real directory: {root}")
digest = hashlib.sha256()
paths = [root, *sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())]
for path in paths:
    metadata = path.lstat()
    relative = "." if path == root else path.relative_to(root).as_posix()
    mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
    if stat.S_ISDIR(metadata.st_mode):
        record = f"{relative}\0D\0{mode}\n"
    elif stat.S_ISREG(metadata.st_mode):
        file_digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                file_digest.update(chunk)
        record = f"{relative}\0F\0{mode}\0{file_digest.hexdigest()}\n"
    else:
        raise SystemExit(f"unsupported entry in notarized tree: {relative}")
    digest.update(record.encode("utf-8"))
print(digest.hexdigest())
PY
}

record_notarization_receipt() {
  local label="$1" subject_kind="$2" subject_sha="$3" submitted="$4" raw_receipt="$5"
  python3 - "$DIST_DIR/NOTARIZATION-RECEIPTS.json" "$label" "$subject_kind" "$subject_sha" "$submitted" "$raw_receipt" "$VERSION" "$REVISION" <<'PY'
import hashlib, json, os, re, sys
from pathlib import Path

output, label, subject_kind, subject_sha, submitted_path, receipt_path, version, revision = sys.argv[1:]
output = Path(output)
receipt = json.loads(Path(receipt_path).read_text(encoding="utf-8"))
if not isinstance(receipt, dict) or receipt.get("status") != "Accepted":
    raise SystemExit(f"notary service did not accept {label}: {receipt!r}")
submission_id = receipt.get("id")
if not isinstance(submission_id, str) or not re.fullmatch(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    submission_id,
):
    raise SystemExit(f"notary service returned an invalid submission id for {label}")
submitted_digest = hashlib.sha256()
with Path(submitted_path).open("rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        submitted_digest.update(chunk)
submitted_sha = submitted_digest.hexdigest()
value = {
    "schema_version": 1,
    "version": version,
    "source_revision": revision,
    "assets": {},
}
if output.exists():
    value = json.loads(output.read_text(encoding="utf-8"))
if value.get("schema_version") != 1 or value.get("version") != version or value.get("source_revision") != revision:
    raise SystemExit("notarization receipt set does not match this package build")
assets = value.get("assets")
if not isinstance(assets, dict) or label in assets:
    raise SystemExit(f"notarization receipt label is invalid or duplicated: {label}")
assets[label] = {
    "status": "Accepted",
    "submission_id": submission_id.lower(),
    "subject_kind": subject_kind,
    "subject_sha256": subject_sha,
    "submitted_sha256": submitted_sha,
}
temporary = output.with_name(output.name + f".tmp.{os.getpid()}")
temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
temporary.chmod(0o600)
os.replace(temporary, output)
PY
}

notarize_subject() {
  local subject="$1" label="$2" subject_kind="$3" subject_sha="$4"
  local zip="$WORK/$label.zip" receipt="$WORK/$label.notary.json"
  if [[ "$subject_kind" == "file-sha256" ]]; then
    /usr/bin/ditto -c -k "$subject" "$zip"
  elif [[ "$subject_kind" == "tree-sha256" ]]; then
    (cd "$(dirname "$subject")" && /usr/bin/ditto -c -k --sequesterRsrc "$(basename "$subject")" "$zip")
  else
    fail "unsupported notarization subject kind: $subject_kind"
  fi
  /usr/bin/xcrun notarytool submit "$zip" \
    --keychain-profile "$NOTARY_PROFILE" \
    --wait \
    --output-format json > "$receipt" \
    || fail "notary submission failed for $label"
  record_notarization_receipt "$label" "$subject_kind" "$subject_sha" "$zip" "$receipt"
}

CONNECTD_ARM64="$BIN_BUILD/pairling-connectd-arm64"
CONNECTD_X64="$BIN_BUILD/pairling-connectd-x64"
if [[ -n "$PREBUILT_ARM64" ]]; then
  [[ ! -L "$PREBUILT_ARM64" ]] || fail "prebuilt binary must not be a symlink: $PREBUILT_ARM64"
  cp "$PREBUILT_ARM64" "$CONNECTD_ARM64"
  verify_prebuilt "$CONNECTD_ARM64" arm64 "$EVIDENCE_CONNECTD_ARM64_SHA"
else
  build_arch arm64 "$CONNECTD_ARM64"
fi
if [[ -n "$PREBUILT_X64" ]]; then
  [[ ! -L "$PREBUILT_X64" ]] || fail "prebuilt binary must not be a symlink: $PREBUILT_X64"
  cp "$PREBUILT_X64" "$CONNECTD_X64"
  verify_prebuilt "$CONNECTD_X64" x64 "$EVIDENCE_CONNECTD_X64_SHA"
else
  build_arch amd64 "$CONNECTD_X64"
fi
chmod 755 "$CONNECTD_ARM64" "$CONNECTD_X64"
verify_connectd_build_info "$CONNECTD_ARM64" arm64
verify_connectd_build_info "$CONNECTD_X64" x64
if [[ "$NOTARIZE" == "1" ]]; then
  notarize_subject "$CONNECTD_ARM64" pairling-connectd-arm64 file-sha256 \
    "$(/usr/bin/shasum -a 256 "$CONNECTD_ARM64" | awk '{ print $1 }')"
  notarize_subject "$CONNECTD_X64" pairling-connectd-x64 file-sha256 \
    "$(/usr/bin/shasum -a 256 "$CONNECTD_X64" | awk '{ print $1 }')"
fi

team_of() {
  local team
  team="$(/usr/bin/codesign -dvv "$1" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
  [[ "$team" != "not set" ]] || team=""
  printf '%s\n' "$team"
}

AUTOMATION_HELPER_ARM64="$BIN_BUILD/automation-helper-arm64/$AUTOMATION_HELPER_APP_NAME"
AUTOMATION_HELPER_X64="$BIN_BUILD/automation-helper-x64/$AUTOMATION_HELPER_APP_NAME"
AUTOMATION_ARCHIVE_ARM64="$DIST_DIR/pairling-automation-arm64.zip"
AUTOMATION_ARCHIVE_X64="$DIST_DIR/pairling-automation-x64.zip"
AUTOMATION_NOTARIZATION_TREE_ARM64=""
AUTOMATION_NOTARIZATION_TREE_X64=""

extract_prebuilt_automation_helper() {
  local archive="$1" arch="$2" expected_sha="$3" destination="$4" expected_arch extraction
  [[ -f "$archive" && ! -L "$archive" ]] \
    || fail "prebuilt Pairling automation helper archive is missing or linked: $archive"
  [[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] \
    || fail "prebuilt Pairling automation helper is not pinned by release evidence: $arch"
  expected_arch="$arch"
  [[ "$expected_arch" != "x64" ]] || expected_arch="x86_64"
  extraction="$WORK/prebuilt-automation-$arch"
  python3 "$SOURCE_ROOT/mac/install/automation_helper_lifecycle.py" extract-verify \
    --archive "$archive" \
    --destination "$extraction" \
    --expected-sha256 "$expected_sha" \
    --architecture "$expected_arch" \
    || fail "prebuilt Pairling automation helper archive failed safe extraction, signature, identity, architecture, entitlement, or notarization verification: $arch"
  mkdir -p "$(dirname "$destination")"
  /usr/bin/ditto "$extraction/$AUTOMATION_HELPER_APP_NAME" "$destination"
  verify_automation_helper_bundle "$destination" "$arch"
}

archive_automation_helper() {
  local helper="$1" archive="$2"
  rm -f "$archive"
  (
    cd "$(dirname "$helper")"
    /usr/bin/ditto -c -k --sequesterRsrc --keepParent "$(basename "$helper")" "$archive"
  ) || fail "could not archive the Pairling automation helper: $helper"
  [[ -f "$archive" && ! -L "$archive" ]] \
    || fail "Pairling automation helper archive is missing or linked: $archive"
}

if [[ -n "$PREBUILT_AUTOMATION_ARM64" || -n "$PREBUILT_AUTOMATION_X64" ]]; then
  [[ -n "$RELEASE_EVIDENCE" && -n "$PREBUILT_AUTOMATION_ARM64" && -n "$PREBUILT_AUTOMATION_X64" ]] \
    || fail "prebuilt Pairling automation helper archives require --release-evidence and both architectures."
  extract_prebuilt_automation_helper \
    "$PREBUILT_AUTOMATION_ARM64" arm64 "$EVIDENCE_AUTOMATION_ARM64_SHA" "$AUTOMATION_HELPER_ARM64"
  extract_prebuilt_automation_helper \
    "$PREBUILT_AUTOMATION_X64" x64 "$EVIDENCE_AUTOMATION_X64_SHA" "$AUTOMATION_HELPER_X64"
else
  generate_automation_helper_project
  build_automation_helper arm64 "$AUTOMATION_HELPER_ARM64"
  build_automation_helper x64 "$AUTOMATION_HELPER_X64"
fi

if [[ "$NOTARIZE" == "1" ]]; then
  for arch in arm64 x64; do
    case "$arch" in
      arm64) helper="$AUTOMATION_HELPER_ARM64" ;;
      x64) helper="$AUTOMATION_HELPER_X64" ;;
    esac
    helper_tree_sha="$(tree_sha256 "$helper")"
    notarize_subject "$helper" "pairling-automation-$arch" tree-sha256 "$helper_tree_sha"
    /usr/bin/xcrun stapler staple "$helper" \
      || fail "could not staple the notarization ticket to the Pairling automation helper: $arch"
    /usr/bin/xcrun stapler validate "$helper" \
      || fail "could not validate the stapled Pairling automation helper: $arch"
    verify_automation_helper_bundle "$helper" "$arch"
    case "$arch" in
      arm64) AUTOMATION_NOTARIZATION_TREE_ARM64="$helper_tree_sha" ;;
      x64) AUTOMATION_NOTARIZATION_TREE_X64="$helper_tree_sha" ;;
    esac
  done
fi

if [[ -n "$PREBUILT_AUTOMATION_ARM64" ]]; then
  /bin/cp -p "$PREBUILT_AUTOMATION_ARM64" "$AUTOMATION_ARCHIVE_ARM64"
  /bin/cp -p "$PREBUILT_AUTOMATION_X64" "$AUTOMATION_ARCHIVE_X64"
else
  archive_automation_helper "$AUTOMATION_HELPER_ARM64" "$AUTOMATION_ARCHIVE_ARM64"
  archive_automation_helper "$AUTOMATION_HELPER_X64" "$AUTOMATION_ARCHIVE_X64"
fi

# --- stage the seven inert packages -----------------------------------------
cp "$SOURCE_ROOT/npm/pairling/package.json" "$STAGE/pairling/package.json"
cp "$SOURCE_ROOT/npm/pairling/README.md" "$STAGE/pairling/README.md"
mkdir -p "$STAGE/pairling/bin"
cp "$SOURCE_ROOT/npm/pairling/bin/pairling.mjs" "$STAGE/pairling/bin/pairling.mjs"
chmod 755 "$STAGE/pairling/bin/pairling.mjs"

release_evidence_field() {
  local section="$1" arch="$2" field="$3"
  [[ "$field" == "sha256" ]] || fail "unsupported loaded release evidence field"
  case "$section:$arch" in
    python:arm64) printf '%s\n' "$EVIDENCE_PYTHON_ARM64_SHA" ;;
    python:x64) printf '%s\n' "$EVIDENCE_PYTHON_X64_SHA" ;;
    automation:arm64) printf '%s\n' "$EVIDENCE_AUTOMATION_ARM64_SHA" ;;
    automation:x64) printf '%s\n' "$EVIDENCE_AUTOMATION_X64_SHA" ;;
    *) fail "unsupported release evidence asset: $section/$arch" ;;
  esac
}

stage_provider_sdks() {
  local arch="$1" runtime_dir="$2"
  local source="$SOURCE_ROOT/npm/provider-sdks"
  local install_root="$WORK/provider-sdks-$arch"
  local dest="$runtime_dir/provider-sdks"
  if [[ -L "$source" || ! -d "$source" || \
        -L "$source/package.json" || ! -f "$source/package.json" || \
        -L "$source/package-lock.json" || ! -f "$source/package-lock.json" ]]; then
    fail "reviewed provider SDK lock/config is missing or linked"
  fi
  mkdir -m 700 "$install_root"
  cp "$source/package.json" "$source/package-lock.json" "$install_root/"
  python3 "$SOURCE_ROOT/mac/install/verify-runtime-package-manifest.py" \
    --provider-sdk-lock "$install_root" \
    || fail "provider SDK dependency lock/config is not the reviewed contract"
  (
    cd "$install_root"
    npm_config_ignore_scripts=true \
      npm_config_audit=false \
      npm_config_fund=false \
      npm_config_update_notifier=false \
      npm_config_cache="$WORK/npm-cache" \
      npm ci \
        --ignore-scripts \
        --omit=peer \
        --omit=dev \
        --no-audit \
        --no-fund \
        --no-bin-links \
        --os=darwin \
        --cpu="$arch"
  ) || fail "could not materialize the reviewed inert provider SDK closure for $arch"
  python3 "$SOURCE_ROOT/mac/install/verify-runtime-package-manifest.py" \
    --sanitize-provider-sdks "$install_root/node_modules" "$arch" \
    || fail "provider SDK lifecycle script inventory is not the reviewed inert contract for $arch"

  mkdir -p "$dest/packages"
  cp "$source/package.json" "$dest/package.json"
  cp "$source/package-lock.json" "$dest/npm-shrinkwrap.json"
  /bin/cp -R "$install_root/node_modules/." "$dest/packages/"
  rm -f "$dest/packages/.package-lock.json"
  python3 "$SOURCE_ROOT/mac/install/verify-runtime-package-manifest.py" \
    --provider-sdks "$dest" "$arch" \
    || fail "provider SDK payload failed the reviewed package/integrity/architecture contract for $arch"
}


stage_runtime() {
  local arch="$1" binary="$2" prebuilt_python="$3" automation_helper="$4" automation_archive="$5"
  local dir="$STAGE/runtime-darwin-$arch" automation_archive_sha=""
  [[ -f "$automation_archive" && ! -L "$automation_archive" ]] \
    || fail "Pairling automation helper archive is missing or linked: $automation_archive"
  automation_archive_sha="$(/usr/bin/shasum -a 256 "$automation_archive" | awk '{ print $1 }')"
  mkdir -p "$dir/bin" "$dir/automation"
  cp "$SOURCE_ROOT/npm/runtime-darwin-$arch/package.json" "$dir/package.json"
  cp "$SOURCE_ROOT/npm/runtime-darwin-$arch/README.md" "$dir/README.md"
  cp "$binary" "$dir/bin/pairling-connectd"
  chmod 755 "$dir/bin/pairling-connectd"
  /usr/bin/ditto "$automation_helper" "$dir/automation/$AUTOMATION_HELPER_APP_NAME"
  verify_automation_helper_bundle "$dir/automation/$AUTOMATION_HELPER_APP_NAME" "$arch"
  stage_provider_sdks "$arch" "$dir"

  # P3 CPython. Custody rule (same as connectd): the Developer ID signing only
  # happens on the release Mac. A prebuilt python tarball (already signed +
  # notarized) is consumed verbatim and verified — never re-signed. CI MUST use
  # a prebuilt; only the local release Mac vendors+signs from scratch.
  local python_bin="" python_team="" python_id="" python_archive_sha=""
  if [[ -n "$prebuilt_python" ]]; then
    local ptmp expected_python_sha verified_archive; ptmp="$(mktemp -d)"
    expected_python_sha="$(release_evidence_field python "$arch" sha256)"
    [[ ! -L "$prebuilt_python" ]] || fail "prebuilt Python archive must not be a symlink: $prebuilt_python"
    verified_archive="$WORK/prebuilt-python-$arch.tar.gz"
    cp "$prebuilt_python" "$verified_archive"
    python3 "$SOURCE_ROOT/mac/packaging/verify-prebuilt-python-archive.py" \
      --archive "$verified_archive" \
      --destination "$ptmp" \
      --expected-sha256 "$expected_python_sha" \
      --arch "$arch" \
      --team-id "$EXPECTED_TEAM_ID" \
      --identifier dev.pairling.python \
      >/dev/null || fail "prebuilt Python archive failed safe extraction, identity, architecture, or smoke verification: $prebuilt_python"
    rm -rf "$dir/python"; mv "$ptmp/python" "$dir/python"; rm -rf "$ptmp"
    if [[ "$NOTARIZE" == "1" ]]; then
      local prebuilt_tree_sha
      prebuilt_tree_sha="$(tree_sha256 "$dir/python")"
      notarize_subject "$dir/python" "pairling-python-$arch" tree-sha256 "$prebuilt_tree_sha"
      [[ "$(tree_sha256 "$dir/python")" == "$prebuilt_tree_sha" ]] \
        || fail "prebuilt Python tree changed during notarization: $arch"
    fi
    cp "$verified_archive" "$DIST_DIR/pairling-python-$arch.tar.gz"
    python_archive_sha="$(/usr/bin/shasum -a 256 "$verified_archive" | awk '{ print $1 }')"
    python_bin="$dir/python/bin/python3"
  elif [[ "$VENDOR_PYTHON" == "1" ]]; then
    "$SOURCE_ROOT/mac/packaging/vendor-cpython.sh" --arch "$arch" --out "$dir"
    python_bin="$dir/python/bin/python3"
    [[ -x "$python_bin" ]] || fail "vendor-cpython.sh did not produce $python_bin"
    local python_tree_sha=""
    if [[ "$NOTARIZE" == "1" ]]; then
      python_tree_sha="$(tree_sha256 "$dir/python")"
      notarize_subject "$dir/python" "pairling-python-$arch" tree-sha256 "$python_tree_sha"
      [[ "$(tree_sha256 "$dir/python")" == "$python_tree_sha" ]] \
        || fail "Python tree changed during notarization: $arch"
    fi
    # Emit the signed python as a standalone release asset so CI can consume it
    # as a prebuilt (CI cannot sign). Deterministic tarball.
    ( cd "$dir" && find python -exec touch -h -t 202001010000 {} + && \
      COPYFILE_DISABLE=1 tar -czf "$DIST_DIR/pairling-python-$arch.tar.gz" python )
    if [[ -n "$python_tree_sha" ]]; then
      [[ "$(tree_sha256 "$dir/python")" == "$python_tree_sha" ]] \
        || fail "Python tree changed before archive creation: $arch"
    fi
    local verify_tmp; verify_tmp="$(mktemp -d)"
    python3 "$SOURCE_ROOT/mac/packaging/verify-prebuilt-python-archive.py" \
      --archive "$DIST_DIR/pairling-python-$arch.tar.gz" \
      --destination "$verify_tmp" \
      --arch "$arch" \
      --team-id "$EXPECTED_TEAM_ID" \
      --identifier dev.pairling.python \
      >/dev/null || fail "new vendored Python archive failed safe extraction, identity, architecture, or smoke verification"
    python_archive_sha="$(/usr/bin/shasum -a 256 "$DIST_DIR/pairling-python-$arch.tar.gz" | awk '{ print $1 }')"
    rm -rf "$verify_tmp"
  fi
  if [[ -n "$python_bin" ]]; then
    python_team="$(team_of "$python_bin")"
    python_id="$(/usr/bin/codesign -dvv "$python_bin" 2>&1 | sed -n 's/^Identifier=//p')"
  fi
  local automation_app="$dir/automation/$AUTOMATION_HELPER_APP_NAME"
  local automation_executable="$automation_app/Contents/MacOS/$AUTOMATION_HELPER_EXECUTABLE"
  local automation_team automation_id automation_tree_sha
  automation_team="$(team_of "$automation_executable")"
  automation_id="$(/usr/bin/codesign -dvv "$automation_executable" 2>&1 | sed -n 's/^Identifier=//p')"
  automation_tree_sha="$(tree_sha256 "$automation_app")"


  python3 - "$dir/manifest.json" "$dir" "$VERSION" "$REVISION" "$arch" "$EVIDENCE_SHA256" "$(team_of "$dir/bin/pairling-connectd")" "${python_team:-}" "${python_id:-}" "$python_archive_sha" "$automation_team" "$automation_id" "$automation_archive_sha" "$automation_tree_sha" <<'PY'
import hashlib, json, stat, sys
from pathlib import Path

out, root_value, version, revision, architecture, evidence_sha256, team, python_team, python_id, python_archive_sha256, automation_team, automation_id, automation_archive_sha256, automation_tree_sha256 = sys.argv[1:]
root = Path(root_value)

def sha_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

files = []
directories = []
tops = [root / "bin", root / "provider-sdks", root / "automation"]
if (root / "python").exists():
    tops.append(root / "python")
for top in tops:
    if not top.is_dir() or top.is_symlink():
        raise SystemExit(f"required runtime package directory is missing or linked: {top}")
    directories.append({
        "path": top.relative_to(root).as_posix(),
        "mode": f"{stat.S_IMODE(top.lstat().st_mode):04o}",
    })
    for path in sorted(top.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if path.name == "__pycache__" or path.suffix == ".pyc":
            raise SystemExit(f"forbidden Python bytecode in runtime package: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            directories.append({
                "path": relative,
                "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            })
            continue
        elif stat.S_ISLNK(metadata.st_mode):
            raise SystemExit(f"symlinks are forbidden in runtime packages: {relative}")
        elif stat.S_ISREG(metadata.st_mode):
            entry = {
                "path": relative,
                "kind": "file",
                "sha256": sha_file(path),
                "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            }
        else:
            raise SystemExit(f"unsupported runtime package entry: {relative}")
        if relative == "bin/pairling-connectd":
            entry["team_id"] = team or None
            entry["identifier"] = "dev.pairling.connectd"
            entry["architecture"] = architecture
        elif relative == "python/bin/python3":
            entry["team_id"] = python_team or None
            entry["identifier"] = python_id or None
            entry["architecture"] = architecture
        elif relative == "automation/Pairling.app/Contents/MacOS/PairlingAutomation":
            entry["team_id"] = automation_team or None
            entry["identifier"] = automation_id or None
            entry["architecture"] = architecture
        files.append(entry)

json.dump({
    "schema_version": 2,
    "package_version": version,
    "source_revision": revision,
    "architecture": architecture,
    "release_evidence_sha256": evidence_sha256 or None,
    "python_archive_sha256": python_archive_sha256 or None,
    "automation_archive_sha256": automation_archive_sha256,
    "automation_tree_sha256": automation_tree_sha256,
    "directories": directories,
    "files": files,
}, open(out, "w"), indent=2, sort_keys=True)
open(out, "a").write("\n")
PY
}
stage_runtime arm64 "$CONNECTD_ARM64" "$PREBUILT_PYTHON_ARM64" "$AUTOMATION_HELPER_ARM64" "$AUTOMATION_ARCHIVE_ARM64"
stage_runtime x64 "$CONNECTD_X64" "$PREBUILT_PYTHON_X64" "$AUTOMATION_HELPER_X64" "$AUTOMATION_ARCHIVE_X64"

if [[ "$NOTARIZE" == "1" ]]; then
  python3 - "$DIST_DIR/NOTARIZATION-RECEIPTS.json" "$VERSION" "$REVISION" \
    "$(/usr/bin/shasum -a 256 "$CONNECTD_ARM64" | awk '{ print $1 }')" \
    "$(/usr/bin/shasum -a 256 "$CONNECTD_X64" | awk '{ print $1 }')" \
    "$(tree_sha256 "$STAGE/runtime-darwin-arm64/python")" \
    "$(tree_sha256 "$STAGE/runtime-darwin-x64/python")" \
    "$AUTOMATION_NOTARIZATION_TREE_ARM64" \
    "$AUTOMATION_NOTARIZATION_TREE_X64" <<'PY' \
    || fail "notarization receipts do not bind all final runtime subjects"
import json, re, sys
from pathlib import Path

path, version, revision, connectd_arm, connectd_x64, python_arm, python_x64, automation_arm, automation_x64 = sys.argv[1:]
value = json.loads(Path(path).read_text(encoding="utf-8"))
if set(value) != {"schema_version", "version", "source_revision", "assets"}:
    raise SystemExit("unexpected receipt-set keys")
if value["schema_version"] != 1 or value["version"] != version or value["source_revision"] != revision:
    raise SystemExit("receipt-set identity mismatch")
expected = {
    "pairling-connectd-arm64": ("file-sha256", connectd_arm),
    "pairling-connectd-x64": ("file-sha256", connectd_x64),
    "pairling-python-arm64": ("tree-sha256", python_arm),
    "pairling-python-x64": ("tree-sha256", python_x64),
    "pairling-automation-arm64": ("tree-sha256", automation_arm),
    "pairling-automation-x64": ("tree-sha256", automation_x64),
}
if set(value["assets"]) != set(expected):
    raise SystemExit("receipt-set asset labels mismatch")
for label, (kind, digest) in expected.items():
    row = value["assets"][label]
    if set(row) != {"status", "submission_id", "subject_kind", "subject_sha256", "submitted_sha256"}:
        raise SystemExit(f"receipt keys mismatch for {label}")
    if row["status"] != "Accepted" or row["subject_kind"] != kind or row["subject_sha256"] != digest:
        raise SystemExit(f"receipt subject mismatch for {label}")
    if not re.fullmatch(r"[0-9a-f]{64}", row["submitted_sha256"]):
        raise SystemExit(f"receipt submission digest is invalid for {label}")
PY
fi

verify_final_release_evidence_assets() {
  local output final_evidence_sha
  [[ -n "$RELEASE_EVIDENCE" ]] || return 0
  output="$(python3 "$SOURCE_ROOT/mac/packaging/npm-release-evidence.py" verify \
    --evidence "$RELEASE_EVIDENCE" \
    --version "$VERSION" \
    --source-revision "$REVISION" \
    --mirror-source-root "$SOURCE_ROOT" \
    --connectd-arm64 "$CONNECTD_ARM64" \
    --connectd-x64 "$CONNECTD_X64" \
    --python-arm64 "$DIST_DIR/pairling-python-arm64.tar.gz" \
    --python-x64 "$DIST_DIR/pairling-python-x64.tar.gz" \
    --automation-arm64 "$AUTOMATION_ARCHIVE_ARM64" \
    --automation-x64 "$AUTOMATION_ARCHIVE_X64")" \
    || fail "final package assets do not match loaded release evidence"
  final_evidence_sha="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["evidence_sha256"])' <<<"$output")"
  [[ "$final_evidence_sha" == "$EVIDENCE_SHA256" ]] \
    || fail "release evidence changed before final asset verification"
}
verify_final_release_evidence_assets

PYTHON_ARM64_ARCHIVE_SHA=""
PYTHON_X64_ARCHIVE_SHA=""
if [[ -f "$DIST_DIR/pairling-python-arm64.tar.gz" ]]; then
  PYTHON_ARM64_ARCHIVE_SHA="$(/usr/bin/shasum -a 256 "$DIST_DIR/pairling-python-arm64.tar.gz" | awk '{ print $1 }')"
fi
if [[ -f "$DIST_DIR/pairling-python-x64.tar.gz" ]]; then
  PYTHON_X64_ARCHIVE_SHA="$(/usr/bin/shasum -a 256 "$DIST_DIR/pairling-python-x64.tar.gz" | awk '{ print $1 }')"
fi
RUNTIME_ARM64_MANIFEST_SHA="$(/usr/bin/shasum -a 256 "$STAGE/runtime-darwin-arm64/manifest.json" | awk '{ print $1 }')"
RUNTIME_X64_MANIFEST_SHA="$(/usr/bin/shasum -a 256 "$STAGE/runtime-darwin-x64/manifest.json" | awk '{ print $1 }')"

# Set versions + pin optionalDependencies exactly (never mutates npm/ sources).
for rel in \
  runtime-claude-darwin-arm64 \
  runtime-claude-darwin-x64 \
  runtime-copilot-darwin-arm64 \
  runtime-copilot-darwin-x64; do
  mkdir -p "$STAGE/$rel"
  cp "$SOURCE_ROOT/npm/$rel/package.json" "$STAGE/$rel/package.json"
done

python3 - "$STAGE" "$VERSION" <<'PY'
import json, sys
from pathlib import Path
stage, version = Path(sys.argv[1]), sys.argv[2]
runtime_packages = (
    "runtime-darwin-arm64",
    "runtime-darwin-x64",
    "runtime-claude-darwin-arm64",
    "runtime-claude-darwin-x64",
    "runtime-copilot-darwin-arm64",
    "runtime-copilot-darwin-x64",
)
for rel in runtime_packages:
    path = stage / rel / "package.json"
    data = json.loads(path.read_text())
    data["version"] = version
    path.write_text(json.dumps(data, indent=2) + "\n")
path = stage / "pairling" / "package.json"
data = json.loads(path.read_text())
data["version"] = version
data["optionalDependencies"] = {
    "@pairling/runtime-claude-darwin-arm64": version,
    "@pairling/runtime-claude-darwin-x64": version,
    "@pairling/runtime-copilot-darwin-arm64": version,
    "@pairling/runtime-copilot-darwin-x64": version,
    "@pairling/runtime-darwin-arm64": version,
    "@pairling/runtime-darwin-x64": version,
}
path.write_text(json.dumps(data, indent=2) + "\n")
PY

for arch in arm64 x64; do
  python3 "$SOURCE_ROOT/mac/install/verify-runtime-package-manifest.py" --archive \
    "$STAGE/runtime-darwin-$arch" "$VERSION" "$REVISION" \
    || fail "complete runtime package failed verification before provider payload split: $arch"
done

stage_runtime_component() {
  local provider="$1" arch="$2" target_prefix="$3" runtime_manifest_sha="$4"
  local runtime_dir="$STAGE/runtime-darwin-$arch"
  local component_dir="$STAGE/runtime-$provider-darwin-$arch"
  local source="$runtime_dir/$target_prefix"
  local package_name="@pairling/runtime-$provider-darwin-$arch"
  [[ ! -L "$source" && -d "$source" ]] \
    || fail "runtime component source is missing or linked: $target_prefix"
  mv "$source" "$component_dir/payload"
  python3 - "$component_dir" "$package_name" "$VERSION" "$REVISION" "$arch" \
    "$provider" "$runtime_manifest_sha" "$target_prefix" <<'PY'
import hashlib
import json
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
package_name, version, revision, architecture, provider, runtime_digest, target_prefix = sys.argv[2:]
payload = root / "payload"

def sha_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

directories = [{
    "path": "payload",
    "mode": f"{stat.S_IMODE(payload.lstat().st_mode):04o}",
}]
files = []
for path in sorted(payload.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    relative = path.relative_to(root).as_posix()
    metadata = path.lstat()
    if path.name == "__pycache__" or path.suffix == ".pyc":
        raise SystemExit(f"forbidden Python bytecode in runtime component: {relative}")
    if stat.S_ISLNK(metadata.st_mode):
        raise SystemExit(f"symlinks are forbidden in runtime components: {relative}")
    if stat.S_ISDIR(metadata.st_mode):
        directories.append({
            "path": relative,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        })
    elif stat.S_ISREG(metadata.st_mode):
        files.append({
            "path": relative,
            "kind": "file",
            "sha256": sha_file(path),
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        })
    else:
        raise SystemExit(f"unsupported runtime component entry: {relative}")
if not files:
    raise SystemExit("runtime component payload is empty")
manifest = {
    "schema_version": 1,
    "package": package_name,
    "package_version": version,
    "source_revision": revision,
    "architecture": architecture,
    "provider": provider,
    "runtime_manifest_sha256": runtime_digest,
    "target_prefix": target_prefix,
    "directories": directories,
    "files": files,
}
(root / "component-manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}

stage_runtime_component \
  claude arm64 \
  "provider-sdks/packages/@anthropic-ai/claude-agent-sdk-darwin-arm64" \
  "$RUNTIME_ARM64_MANIFEST_SHA"
stage_runtime_component \
  claude x64 \
  "provider-sdks/packages/@anthropic-ai/claude-agent-sdk-darwin-x64" \
  "$RUNTIME_X64_MANIFEST_SHA"
stage_runtime_component \
  copilot arm64 \
  "provider-sdks/packages/@github/copilot-darwin-arm64" \
  "$RUNTIME_ARM64_MANIFEST_SHA"
stage_runtime_component \
  copilot x64 \
  "provider-sdks/packages/@github/copilot-darwin-x64" \
  "$RUNTIME_X64_MANIFEST_SHA"

# --- payload integrity manifest ---------------------------------------------
python3 - "$STAGE/pairling" "$VERSION" "$REVISION" "$SOURCE_DIRTY" "$EVIDENCE_SHA256" "$(team_of "$CONNECTD_ARM64")" "$CONNECTD_ARM64" "$(team_of "$CONNECTD_X64")" "$CONNECTD_X64" "$PYTHON_ARM64_ARCHIVE_SHA" "$PYTHON_X64_ARCHIVE_SHA" "$(/usr/bin/shasum -a 256 "$AUTOMATION_ARCHIVE_ARM64" | awk '{ print $1 }')" "$(/usr/bin/shasum -a 256 "$AUTOMATION_ARCHIVE_X64" | awk '{ print $1 }')" "$RUNTIME_ARM64_MANIFEST_SHA" "$RUNTIME_X64_MANIFEST_SHA" <<'PY'
import hashlib, json, stat, sys
from pathlib import Path
pkg, version, revision, dirty, evidence_sha256, team_arm, bin_arm, team_x64, bin_x64, python_arm_sha, python_x64_sha, automation_arm_sha, automation_x64_sha, runtime_arm_sha, runtime_x64_sha = sys.argv[1:]
pkg = Path(pkg)

payload = pkg / "payload"
files = []
directories = [{
    "path": "payload",
    "mode": f"{stat.S_IMODE(payload.lstat().st_mode):04o}",
}]
for path in sorted(payload.rglob("*"), key=lambda item: item.relative_to(pkg).as_posix()):
    relative = path.relative_to(pkg).as_posix()
    metadata = path.lstat()
    if path.name == "__pycache__" or path.suffix == ".pyc":
        raise SystemExit(f"forbidden Python bytecode in payload: {relative}")
    if stat.S_ISLNK(metadata.st_mode):
        raise SystemExit(f"symlinks are forbidden in the payload: {relative}")
    if stat.S_ISDIR(metadata.st_mode):
        directories.append({
            "path": relative,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        })
    elif stat.S_ISREG(metadata.st_mode):
        files.append({
            "path": relative,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        })
    else:
        raise SystemExit(f"unsupported payload entry: {relative}")
manifest = {
    "schema_version": 2,
    "package": "pairling",
    "package_version": version,
    "source_revision": revision,
    "source_dirty": dirty == "true",
    "release_evidence_sha256": evidence_sha256 or None,
    "python_archives": {
        "darwin-arm64": python_arm_sha or None,
        "darwin-x64": python_x64_sha or None,
    },
    "automation_archives": {
        "darwin-arm64": automation_arm_sha,
        "darwin-x64": automation_x64_sha,
    },
    "runtime_manifests": {
        "darwin-arm64": runtime_arm_sha,
        "darwin-x64": runtime_x64_sha,
    },
    "connectd": {
        "darwin-arm64": {
            "sha256": hashlib.sha256(open(bin_arm, "rb").read()).hexdigest(),
            "team_id": team_arm or None,
            "identifier": "dev.pairling.connectd",
            "architecture": "arm64",
        },
        "darwin-x64": {
            "sha256": hashlib.sha256(open(bin_x64, "rb").read()).hexdigest(),
            "team_id": team_x64 or None,
            "identifier": "dev.pairling.connectd",
            "architecture": "x64",
        },
    },
    "directories": directories,
    "files": files,
}
(pkg / "payload-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY
verify_runtime_component() {
  local root="$1" package_name="$2" arch="$3" provider="$4" runtime_manifest_sha="$5" target_prefix="$6"
  python3 - "$root" "$package_name" "$VERSION" "$REVISION" "$arch" "$provider" \
    "$runtime_manifest_sha" "$target_prefix" <<'PY'
import hashlib
import json
import re
import stat
import sys
from pathlib import Path, PurePosixPath

root = Path(sys.argv[1])
package_name, version, revision, architecture, provider, runtime_digest, target_prefix = sys.argv[2:]
expected_root = {"component-manifest.json", "package.json", "payload"}
if root.is_symlink() or not root.is_dir() or {path.name for path in root.iterdir()} != expected_root:
    raise SystemExit("runtime component package root shape is invalid")
for name in expected_root:
    path = root / name
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise SystemExit(f"runtime component root entry is linked: {name}")
    if name == "payload" and not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit("runtime component payload is not a directory")
    if name != "payload" and not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"runtime component root entry is not a file: {name}")

package = json.loads((root / "package.json").read_text(encoding="utf-8"))
required_package = {
    "name": package_name,
    "version": version,
    "files": ["payload", "component-manifest.json"],
    "os": ["darwin"],
    "cpu": [architecture],
    "engines": {"node": ">=20"},
    "publishConfig": {"access": "public"},
    "repository": {
        "type": "git",
        "url": "https://github.com/mergimg0/pairling-helper",
    },
}
for key, expected in required_package.items():
    if package.get(key) != expected:
        raise SystemExit(f"runtime component package.json {key} is invalid")
for key in (
    "bin", "scripts", "dependencies", "devDependencies", "peerDependencies",
    "optionalDependencies", "bundledDependencies", "bundleDependencies",
):
    if key in package:
        raise SystemExit(f"runtime component package.json {key} is forbidden")

manifest = json.loads((root / "component-manifest.json").read_text(encoding="utf-8"))
required_keys = {
    "schema_version", "package", "package_version", "source_revision",
    "architecture", "provider", "runtime_manifest_sha256", "target_prefix",
    "directories", "files",
}
if set(manifest) != required_keys:
    raise SystemExit("runtime component manifest keys are invalid")
identity = (
    manifest["schema_version"] == 1
    and manifest["package"] == package_name
    and manifest["package_version"] == version
    and manifest["source_revision"] == revision
    and manifest["architecture"] == architecture
    and manifest["provider"] == provider
    and manifest["runtime_manifest_sha256"] == runtime_digest
    and manifest["target_prefix"] == target_prefix
)
if not identity or not re.fullmatch(r"[0-9a-f]{40}", revision) or not re.fullmatch(r"[0-9a-f]{64}", runtime_digest):
    raise SystemExit("runtime component manifest identity is invalid")

def safe_relative(value):
    if not isinstance(value, str):
        return None
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or "\\" in value
        or not path.parts
        or path.parts[0] != "payload"
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        return None
    return path.as_posix()

def parse_mode(value, relative, directory):
    if not isinstance(value, str) or not re.fullmatch(r"[0-7]{4}", value):
        raise SystemExit(f"runtime component manifest mode is invalid: {relative}")
    mode = int(value, 8)
    if mode & 0o7022 or not mode & stat.S_IRUSR or (directory and not mode & stat.S_IXUSR):
        raise SystemExit(f"runtime component manifest mode is unsafe: {relative}")
    return mode

expected = {}
for directory in manifest["directories"]:
    if not isinstance(directory, dict):
        raise SystemExit("runtime component directory entry is invalid")
    relative = safe_relative(directory.get("path"))
    if relative is None or relative in expected:
        raise SystemExit("runtime component directory path is invalid or duplicated")
    expected[relative] = ("directory", None, parse_mode(directory.get("mode"), relative, True))
for item in manifest["files"]:
    if not isinstance(item, dict):
        raise SystemExit("runtime component file entry is invalid")
    relative = safe_relative(item.get("path"))
    digest = item.get("sha256")
    if (
        relative is None
        or relative in expected
        or item.get("kind") != "file"
        or not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or relative.endswith(".pyc")
        or "__pycache__" in PurePosixPath(relative).parts
    ):
        raise SystemExit("runtime component file entry is invalid or duplicated")
    expected[relative] = ("file", digest, parse_mode(item.get("mode"), relative, False))
if not manifest["files"]:
    raise SystemExit("runtime component payload is empty")

actual = {}
payload = root / "payload"
for path in [payload, *sorted(payload.rglob("*"))]:
    relative = path.relative_to(root).as_posix()
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise SystemExit(f"runtime component contains a symlink: {relative}")
    if stat.S_ISDIR(metadata.st_mode):
        kind, digest = "directory", None
    elif stat.S_ISREG(metadata.st_mode):
        kind = "file"
        digest_value = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest_value.update(chunk)
        digest = digest_value.hexdigest()
    else:
        raise SystemExit(f"runtime component entry type is unsupported: {relative}")
    actual[relative] = (kind, digest, stat.S_IMODE(metadata.st_mode))
if set(actual) != set(expected):
    raise SystemExit("runtime component inventory does not match its manifest")
for relative, (kind, digest, expected_mode) in expected.items():
    actual_kind, actual_digest, actual_mode = actual[relative]
    directory = kind == "directory"
    mode_ok = (
        actual_mode & 0o7022 == 0
        and actual_mode & ~expected_mode == 0
        and actual_mode & stat.S_IRUSR
        and (not directory or actual_mode & stat.S_IXUSR)
    )
    if actual_kind != kind or actual_digest != digest or not mode_ok:
        raise SystemExit(f"runtime component entry does not match its manifest: {relative}")
PY
}

verify_runtime_component \
  "$STAGE/runtime-claude-darwin-arm64" \
  "@pairling/runtime-claude-darwin-arm64" arm64 claude \
  "$RUNTIME_ARM64_MANIFEST_SHA" \
  "provider-sdks/packages/@anthropic-ai/claude-agent-sdk-darwin-arm64"
verify_runtime_component \
  "$STAGE/runtime-claude-darwin-x64" \
  "@pairling/runtime-claude-darwin-x64" x64 claude \
  "$RUNTIME_X64_MANIFEST_SHA" \
  "provider-sdks/packages/@anthropic-ai/claude-agent-sdk-darwin-x64"
verify_runtime_component \
  "$STAGE/runtime-copilot-darwin-arm64" \
  "@pairling/runtime-copilot-darwin-arm64" arm64 copilot \
  "$RUNTIME_ARM64_MANIFEST_SHA" \
  "provider-sdks/packages/@github/copilot-darwin-arm64"
verify_runtime_component \
  "$STAGE/runtime-copilot-darwin-x64" \
  "@pairling/runtime-copilot-darwin-x64" x64 copilot \
  "$RUNTIME_X64_MANIFEST_SHA" \
  "provider-sdks/packages/@github/copilot-darwin-x64"

# --- deterministic pack ------------------------------------------------------
PAYLOAD_VERIFY_ARGS=(--archive)
if [[ "$RELEASE_MODE" == "1" ]]; then
  PAYLOAD_VERIFY_ARGS=(--release --archive)
fi
python3 "$SOURCE_ROOT/mac/install/verify-payload-manifest.py" "${PAYLOAD_VERIFY_ARGS[@]}" \
  "$STAGE/pairling/payload" \
  "$STAGE/pairling/payload-manifest.json"
find "$STAGE" -exec touch -h -t 202001010000 {} +
for dir in \
  runtime-claude-darwin-arm64 \
  runtime-claude-darwin-x64 \
  runtime-copilot-darwin-arm64 \
  runtime-copilot-darwin-x64 \
  runtime-darwin-arm64 \
  runtime-darwin-x64 \
  pairling; do
  (cd "$STAGE/$dir" && npm pack --silent --pack-destination "$DIST_DIR" >/dev/null)
done

verify_archive_container() {
  local archive="$1"
  python3 - "$archive" <<'PY'
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath

archive = sys.argv[1]
if Path(archive).stat().st_size >= 250_000_000:
    raise SystemExit(f"npm archive exceeds the conservative 250 MB publish limit: {archive}")
seen = set()
with tarfile.open(archive, "r:gz") as handle:
    members = handle.getmembers()
    if not members:
        raise SystemExit(f"empty npm archive: {archive}")
    for member in members:
        raw_parts = member.name.split("/")
        path = PurePosixPath(member.name)
        if (
            path.is_absolute()
            or "\\" in member.name
            or any(part in ("", ".", "..") for part in raw_parts)
            or not path.parts
            or path.parts[0] != "package"
        ):
            raise SystemExit(f"unsafe npm archive path {member.name!r}: {archive}")
        normalized = path.as_posix()
        if normalized in seen:
            raise SystemExit(f"duplicate npm archive path {normalized!r}: {archive}")
        seen.add(normalized)
        if not (member.isdir() or member.isreg()):
            raise SystemExit(f"unsupported npm archive entry {normalized!r}: {archive}")
        mode = member.mode & 0o7777
        if mode & 0o7022 or not mode & stat.S_IRUSR:
            raise SystemExit(f"unsafe npm archive mode {mode:04o} for {normalized!r}: {archive}")
        if member.isdir() and not mode & stat.S_IXUSR:
            raise SystemExit(f"unsearchable npm archive directory {normalized!r}: {archive}")
        if any("acl" in key.lower() for key in member.pax_headers):
            raise SystemExit(f"npm archive carries ACL metadata for {normalized!r}: {archive}")
PY
}

for archive in \
  "$DIST_DIR/pairling-runtime-claude-darwin-arm64-$VERSION.tgz" \
  "$DIST_DIR/pairling-runtime-claude-darwin-x64-$VERSION.tgz" \
  "$DIST_DIR/pairling-runtime-copilot-darwin-arm64-$VERSION.tgz" \
  "$DIST_DIR/pairling-runtime-copilot-darwin-x64-$VERSION.tgz" \
  "$DIST_DIR/pairling-runtime-darwin-arm64-$VERSION.tgz" \
  "$DIST_DIR/pairling-runtime-darwin-x64-$VERSION.tgz" \
  "$DIST_DIR/pairling-$VERSION.tgz"; do
  verify_archive_container "$archive"
done
PACK_VERIFY_ROOT="$WORK/pack-verify"
mkdir -p "$PACK_VERIFY_ROOT"
for arch in arm64 x64; do
  extract="$PACK_VERIFY_ROOT/runtime-$arch"
  mkdir -p "$extract"
  tar -xzf "$DIST_DIR/pairling-runtime-darwin-$arch-$VERSION.tgz" -C "$extract"
  if [[ "$arch" == "arm64" ]]; then
    runtime_manifest_sha="$RUNTIME_ARM64_MANIFEST_SHA"
  else
    runtime_manifest_sha="$RUNTIME_X64_MANIFEST_SHA"
  fi
  for provider in claude copilot; do
    component_extract="$PACK_VERIFY_ROOT/runtime-$provider-$arch"
    mkdir -p "$component_extract"
    tar -xzf \
      "$DIST_DIR/pairling-runtime-$provider-darwin-$arch-$VERSION.tgz" \
      -C "$component_extract"
    if [[ "$provider" == "claude" ]]; then
      target_prefix="provider-sdks/packages/@anthropic-ai/claude-agent-sdk-darwin-$arch"
    else
      target_prefix="provider-sdks/packages/@github/copilot-darwin-$arch"
    fi
    verify_runtime_component \
      "$component_extract/package" \
      "@pairling/runtime-$provider-darwin-$arch" \
      "$arch" "$provider" "$runtime_manifest_sha" "$target_prefix"
    mkdir -p "$extract/package/$(dirname "$target_prefix")"
    mv "$component_extract/package/payload" "$extract/package/$target_prefix"
  done
  python3 "$SOURCE_ROOT/mac/install/verify-runtime-package-manifest.py" --archive \
    "$extract/package" "$VERSION" "$REVISION"
done
mkdir -p "$PACK_VERIFY_ROOT/pairling"
tar -xzf "$DIST_DIR/pairling-$VERSION.tgz" -C "$PACK_VERIFY_ROOT/pairling"
python3 "$SOURCE_ROOT/mac/install/verify-payload-manifest.py" "${PAYLOAD_VERIFY_ARGS[@]}" \
  "$PACK_VERIFY_ROOT/pairling/package/payload" \
  "$PACK_VERIFY_ROOT/pairling/package/payload-manifest.json"
rm -rf "$PACK_VERIFY_ROOT"
(cd "$DIST_DIR" && /usr/bin/shasum -a 256 *.tgz > SHASUMS256.txt)

# Keep the raw signed runtime assets next to the tarballs for the GitHub
# Release flow. The helper archives contain the signed, stapled app bundles.
cp "$CONNECTD_ARM64" "$DIST_DIR/pairling-connectd-arm64"
cp "$CONNECTD_X64" "$DIST_DIR/pairling-connectd-x64"
(cd "$DIST_DIR" && /usr/bin/shasum -a 256 pairling-connectd-arm64 pairling-connectd-x64 > CONNECTD-SHASUMS256.txt)
(cd "$DIST_DIR" && /usr/bin/shasum -a 256 pairling-automation-arm64.zip pairling-automation-x64.zip > AUTOMATION-SHASUMS256.txt)

log "Built npm packages $VERSION (source $REVISION, dirty=$SOURCE_DIRTY)"
log "  dist: $DIST_DIR"
cat "$DIST_DIR/SHASUMS256.txt"
