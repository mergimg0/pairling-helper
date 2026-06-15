# pairling

Pair your iPhone with the AI coding agents running on your Mac.

`pairling` is the Mac companion for the [Pairling](https://pairling.dev) iOS
app: a local runtime that lets your iPhone watch, steer, and spawn Claude Code
and Codex sessions on your own machine — over your local network or your
tailnet, authenticated per device.

## Install

```sh
npm install -g pairling
pairling setup
```

`npm install` only copies files. **Nothing runs at install time** — this
package ships zero lifecycle scripts and works under `--ignore-scripts`. All
system changes happen inside the explicit `pairling setup` flow, which prints
a preview of every change, supports `PAIRLING_DRY_RUN=1`, and appends every
action to a local audit ledger.

Then open Pairling on your iPhone and scan the QR code that `setup` prints.

## What setup does (and nothing else)

- Stages the runtime under `~/Library/Application Support/Pairling/runtime/`
  (versioned releases, atomic `current` symlink flip, `pairling rollback`).
- Installs user-domain LaunchAgents (`dev.pairling.companiond`,
  `dev.pairling.connectd`). No root. The optional power guardian is a separate,
  explicit, sudo-gated step.
- Verifies the payload against the package's integrity manifest and verifies
  the Developer ID signature of the bundled `pairling-connectd` binary before
  staging — fail closed.

## Commands

```text
pairling setup | start | stop | restart | status
pairling doctor [--json]
pairling pair [--qr]
pairling devices | unpair <device_id> | rotate-token <device_id>
pairling logs | diagnose --redact
pairling rollback
pairling uninstall [--yes]
```

## Security posture

- **No install scripts, ever.** A release gate fails if any lifecycle script
  appears in a published manifest.
- **Provenance:** releases are published via npm Trusted Publishing (OIDC) with
  provenance attestations. Verify with `npm audit signatures`.
- **Readable payload:** the runtime is Python/bash source plus one signed Go
  binary; inspect it with `npm pack pairling --dry-run`.
- **Integrity chain:** CI records SHA-256 of every payload file in
  `payload-manifest.json`; `pairling setup` re-verifies before staging;
  `pairling doctor` re-verifies the staged runtime and the binary signature.
- **Local-first:** the daemon serves your devices with per-device scoped bearer
  tokens. npm being down can never affect an installed Mac.

## Platform packages

The compiled runtime binary ships as platform-filtered optional dependencies:
`@pairling/runtime-darwin-arm64` and `@pairling/runtime-darwin-x64` — signed,
notarized, and hash-pinned by this package's integrity manifest.

## Links

- Product: https://pairling.dev
- Get started: https://pairling.dev/start
- Source mirror & publish pipeline: https://pairling.dev
