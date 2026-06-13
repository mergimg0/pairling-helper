# Pairling for Mac — payload mirror & npm publish pipeline

This repository is the public source mirror and publish pipeline for the
[`pairling`](https://www.npmjs.com/package/pairling) npm package — the Mac
companion for the [Pairling](https://pairling.dev) iOS app.

It exists so that:

- **npm provenance links resolve publicly.** Every release is published via
  npm Trusted Publishing (OIDC) from this repository's `release-npm` workflow,
  with provenance attestations you can verify: `npm audit signatures`.
- **Anyone can diff a published tarball against its sources.** The `pairling`
  package ships its runtime as readable Python/bash source; this repo contains
  exactly those sources plus the build script that packs them.

## Layout

```text
npm/                      Sources of the published packages
  pairling/               CLI shim + payload (the package users install)
  runtime-darwin-arm64/   @pairling/runtime-darwin-arm64 (signed binaries)
  runtime-darwin-x64/     @pairling/runtime-darwin-x64
  pairling-helper/        Brand-protection redirect package
  pairlingd/              Brand-protection redirect package
mac/                      The runtime payload sources (daemon, installer, CLI)
mac/packaging/build-npm-packages.sh   Assembles and packs the three packages
.github/workflows/release-npm.yml     OIDC publish with provenance
RELEASE-BINARIES.json     SHA-256 + Apple Team ID of the signed binaries for
                          the current release tag (committed before tagging)
```

## Trust & release model

1. `npm install -g pairling` runs **no code** — none of the packages contain
   lifecycle scripts, and installs work under `--ignore-scripts`. All system
   changes happen in the explicit, previewable `pairling setup`.
2. The compiled `pairling-connectd` binaries are built, **Developer ID-signed,
   and notarized on the maintainer's Mac** — the Apple signing key is never
   present in CI. Binaries are attached to the GitHub Release as assets, and
   their SHA-256 digests + Team ID are committed in `RELEASE-BINARIES.json`
   inside the tagged commit.
3. The `release-npm` workflow verifies each asset against the committed
   digests and the pinned Team ID (`965AVD34A3`), assembles the packages from
   the mirrored sources, and publishes to npm with `--provenance` — so the
   attestation pins the exact commit whose committed digests pin the binaries.
4. On the consuming Mac, `pairling setup` independently re-verifies the
   payload against `payload-manifest.json` and refuses any `pairling-connectd`
   that fails `codesign --verify --strict` or carries a different Team ID.

## Verifying a release

```sh
npm audit signatures                      # registry signatures + provenance
npm pack pairling --dry-run               # list exactly what ships
shasum -a 256 pairling-connectd-arm64     # compare against RELEASE-BINARIES.json
codesign -dvv pairling-connectd-arm64     # TeamIdentifier=965AVD34A3
```

## Development

This is a generated mirror — issues and PRs about the product belong at
[pairling.dev](https://pairling.dev). The mirror is synced from the private
product repository by `mac/packaging/sync-npm-mirror.sh`; the product's
contract tests (npm package invariants, fail-closed installer behavior) run
there before every sync.

## License

All rights reserved. Sources are published here for transparency and
verification. A formal license will be attached before the first stable
release.
