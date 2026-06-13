# Security Policy

Pairling's Mac runtime pairs your iPhone with agent sessions on your Mac, so
we treat its supply chain and local attack surface as product-critical.

## Reporting a vulnerability

Please report vulnerabilities privately:

- Use GitHub's **"Report a vulnerability"** (Security → Advisories) on this
  repository, or
- Email **security@pairling.dev**.

Please do not open public issues for security reports. You should receive an
acknowledgement within 72 hours.

## Scope

- The `pairling`, `@pairling/runtime-darwin-arm64`, `@pairling/runtime-darwin-x64`
  npm packages and this repository's publish pipeline.
- The Pairling Mac runtime (`pairlingd`, `pairling-connectd`, installer, CLI).
- Pairing, device-token, and local/tailnet transport behavior.

## Supply-chain guarantees you can hold us to

- No lifecycle scripts in any published package, ever.
- Releases publish only via npm Trusted Publishing (OIDC) from
  `.github/workflows/release-npm.yml` with provenance attestations.
- Compiled binaries are Developer ID-signed (Team `965AVD34A3`), notarized,
  hash-pinned in the tagged commit (`RELEASE-BINARIES.json`), and re-verified
  on the consuming Mac before staging.

A regression against any of these is itself a reportable vulnerability.
