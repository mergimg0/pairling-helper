#!/usr/bin/env node
// pairling — Mac companion CLI for the Pairling iPhone app (https://pairling.dev).
//
// This shim is a locator, not an installer. It resolves the package payload and
// the platform runtime package, exports their paths, and hands control to the
// bundled bash CLI. All system mutation happens in the explicit, previewable
// `pairling setup` flow implemented by the payload — never at npm install time
// (this package ships zero lifecycle scripts) and never inside this shim.
//
// Imports are restricted to node: builtins by contract
// (mac/tests/test_pairling_npm_shim_contract.py enforces this).

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import process from "node:process";

const PRODUCT_URL = "https://pairling.dev";
const START_URL = "https://pairling.dev/start";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const payloadRoot = join(packageRoot, "payload");
const payloadCli = join(payloadRoot, "mac", "packaging", "bin", "pairling");

function readPackageVersion() {
  try {
    const raw = readFileSync(join(packageRoot, "package.json"), "utf8");
    const parsed = JSON.parse(raw);
    return typeof parsed.version === "string" ? parsed.version : "unknown";
  } catch {
    return "unknown";
  }
}

function appSupportRoot() {
  return (
    process.env.PAIRLING_APP_SUPPORT_ROOT ||
    process.env.COMPANION_APP_SUPPORT_ROOT ||
    join(homedir(), "Library", "Application Support", "Pairling")
  );
}

function stagedCliPath() {
  const candidate = join(appSupportRoot(), "runtime", "current", "bin", "pairling");
  return existsSync(candidate) ? candidate : null;
}

function stagedRuntimeVersion() {
  try {
    const manifestPath = join(appSupportRoot(), "runtime", "current", "manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    return typeof manifest.runtime_version === "string" ? manifest.runtime_version : null;
  } catch {
    return null;
  }
}

function runtimePackageDir() {
  // Test/dev hook only. The installer independently re-verifies the binary's
  // Developer ID signature and TeamID before staging, so this override cannot
  // smuggle an unsigned binary into a real install.
  const override = process.env.PAIRLING_RUNTIME_PACKAGE_DIR;
  if (override) {
    return existsSync(override) ? override : null;
  }
  const arch = process.arch === "arm64" ? "arm64" : process.arch === "x64" ? "x64" : null;
  if (!arch) {
    return null;
  }
  try {
    const require = createRequire(import.meta.url);
    const manifest = require.resolve(`@pairling/runtime-darwin-${arch}/package.json`);
    return dirname(manifest);
  } catch {
    return null;
  }
}

function detectRosetta() {
  if (process.platform !== "darwin" || process.arch !== "x64") {
    return false;
  }
  const probe = spawnSync("/usr/sbin/sysctl", ["-in", "sysctl.proc_translated"], {
    encoding: "utf8",
  });
  return probe.status === 0 && probe.stdout.trim() === "1";
}

function shimEnv() {
  const runtimeDir = runtimePackageDir();
  const connectd = runtimeDir ? join(runtimeDir, "bin", "pairling-connectd") : null;
  const vendoredPython = runtimeDir ? join(runtimeDir, "python", "bin", "python3") : null;
  return {
    packageRoot,
    packageVersion: readPackageVersion(),
    payloadPresent: existsSync(payloadCli),
    payloadRoot,
    runtimePackageDir: runtimeDir,
    connectdPath: connectd && existsSync(connectd) ? connectd : null,
    vendoredPython: vendoredPython && existsSync(vendoredPython) ? vendoredPython : null,
    stagedCli: stagedCliPath(),
    stagedRuntimeVersion: stagedRuntimeVersion(),
    platform: process.platform,
    arch: process.arch,
    rosetta: detectRosetta(),
    node: process.version,
  };
}

function exitWithChild(result) {
  if (result.error) {
    process.stderr.write(`pairling: failed to launch CLI: ${result.error.message}\n`);
    process.exit(1);
  }
  if (result.signal) {
    // Re-raise so the caller observes the same termination signal.
    process.kill(process.pid, result.signal);
    return;
  }
  process.exit(result.status === null ? 1 : result.status);
}

function delegate(cli, args, extraEnv) {
  const env = { ...process.env };
  for (const [key, value] of Object.entries(extraEnv)) {
    // Caller-set values win: PAIRLING_REPO_ROOT et al. stay overridable for
    // development against a repo checkout.
    if (value && env[key] === undefined) {
      env[key] = value;
    }
  }
  exitWithChild(spawnSync(cli, args, { stdio: "inherit", env }));
}

function printPlaceholder() {
  const lines = [
    `pairling ${readPackageVersion()} — Pairling for Mac`,
    "",
    "This release reserves the package name while the full Mac runtime ships.",
    "It contains no runtime payload yet and makes no changes to your system.",
    "",
    `  Product:     ${PRODUCT_URL}`,
    `  Get started: ${START_URL}`,
    "",
    "When the runtime ships here, install/update will be:",
    "",
    "  npm install -g pairling",
    "  pairling setup",
    "",
  ];
  process.stdout.write(lines.join("\n"));
}

function main() {
  const args = process.argv.slice(2);

  if (args[0] === "--shim-print-env") {
    process.stdout.write(JSON.stringify(shimEnv(), null, 2) + "\n");
    process.exit(0);
  }

  if (process.platform !== "darwin") {
    process.stderr.write(
      "pairling: the Pairling Mac runtime only supports macOS.\n" +
        `Learn more: ${PRODUCT_URL}\n`,
    );
    process.exit(1);
  }

  if (args[0] === "--version" || args[0] === "-v") {
    const staged = stagedRuntimeVersion();
    process.stdout.write(
      `pairling ${readPackageVersion()}` + (staged ? ` (staged runtime ${staged})` : "") + "\n",
    );
    process.exit(0);
  }

  if (detectRosetta()) {
    process.stderr.write(
      "pairling: warning: x64 Node is running under Rosetta on Apple Silicon; " +
        "the x64 runtime will be selected. Install arm64 Node for the native runtime.\n",
    );
  }

  if (existsSync(payloadCli)) {
    const env = shimEnv();
    if (!env.runtimePackageDir || !env.connectdPath) {
      process.stderr.write(
        [
          "pairling: the platform runtime package is missing or incomplete.",
          "",
          `Expected: @pairling/runtime-darwin-${process.arch === "arm64" ? "arm64" : "x64"}`,
          "",
          "This usually means npm skipped optional dependencies (network hiccup",
          "or --no-optional / --omit=optional). Fix with:",
          "",
          "  npm install -g pairling",
          "",
        ].join("\n"),
      );
      process.exit(1);
    }
    delegate(payloadCli, args, {
      PAIRLING_REPO_ROOT: join(payloadRoot, "."),
      PAIRLING_CONNECTD_PREBUILT: env.connectdPath,
      PAIRLING_DAEMON_PYTHON: env.vendoredPython,
    });
    return;
  }

  // Placeholder mode: no payload in this release. If a staged runtime already
  // exists on this Mac (repo-local install), delegate so the command keeps
  // working; otherwise print what this package is.
  const staged = stagedCliPath();
  if (staged) {
    delegate(staged, args, {});
    return;
  }

  printPlaceholder();
  process.exit(args.length === 0 ? 0 : 1);
}

main();
