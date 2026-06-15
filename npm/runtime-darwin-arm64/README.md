# @pairling/runtime-darwin-arm64

Pairling Mac runtime binaries for Apple Silicon:

- `bin/pairling-connectd` — the Pairling Connect route layer (embedded
  tailnet), Developer ID-signed and notarized.
- `python/` — (future releases) the vendored, signed CPython runtime that the
  Pairling daemon runs under (`dev.pairling.python` identity).
- `manifest.json` — SHA-256 digests and the expected codesign Team ID for every
  shipped binary.

**Do not install this package directly.** It is selected automatically as a
platform-filtered optional dependency of [`pairling`](https://www.npmjs.com/package/pairling).
The `pairling setup` flow independently verifies each binary's Developer ID
signature and Team ID before staging it — an unsigned or re-signed binary is
rejected, fail closed.

- Product: https://pairling.dev
- Source mirror & publish pipeline: https://pairling.dev
