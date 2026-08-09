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
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import process from "node:process";

const PRODUCT_URL = "https://pairling.dev";
const START_URL = "https://pairling.dev/start";
const EXPECTED_TEAM_ID = "965AVD34A3";

const shimPath = fileURLToPath(import.meta.url);
const packageRoot = dirname(dirname(shimPath));
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

function resolvePackageRoot(name) {
  try {
    const require = createRequire(import.meta.url);
    return dirname(require.resolve(`${name}/package.json`));
  } catch {
    return null;
  }
}

function runtimeArchitecture() {
  return process.arch === "arm64" ? "arm64" : process.arch === "x64" ? "x64" : null;
}

function runtimePackageDir() {
  // Test/dev hook only. The installer independently re-verifies the binary's
  // Developer ID signature and TeamID before staging, so this override cannot
  // smuggle an unsigned binary into a real install.
  const override = process.env.PAIRLING_RUNTIME_PACKAGE_DIR;
  if (override) {
    return existsSync(override) ? override : null;
  }
  const architecture = runtimeArchitecture();
  return architecture
    ? resolvePackageRoot(`@pairling/runtime-darwin-${architecture}`)
    : null;
}

function runtimeComponentPackageDirs() {
  const architecture = runtimeArchitecture();
  if (!architecture) {
    return [];
  }
  const definitions = [
    {
      provider: "claude",
      label: "Claude runtime component",
      override: "PAIRLING_RUNTIME_CLAUDE_PACKAGE_DIR",
      packageName: `@pairling/runtime-claude-darwin-${architecture}`,
      targetPrefix: `provider-sdks/packages/@anthropic-ai/claude-agent-sdk-darwin-${architecture}`,
    },
    {
      provider: "copilot",
      label: "Copilot runtime component",
      override: "PAIRLING_RUNTIME_COPILOT_PACKAGE_DIR",
      packageName: `@pairling/runtime-copilot-darwin-${architecture}`,
      targetPrefix: `provider-sdks/packages/@github/copilot-darwin-${architecture}`,
    },
  ];
  const hasExplicitComponent = definitions.some(({ override }) => process.env[override]);
  if (process.env.PAIRLING_RUNTIME_PACKAGE_DIR && !hasExplicitComponent) {
    return [];
  }
  return definitions.map((definition) => {
    const override = process.env[definition.override];
    return {
      ...definition,
      root: override
        ? (existsSync(override) ? override : null)
        : resolvePackageRoot(definition.packageName),
    };
  });
}


function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

const UNSAFE_MODE_BITS = 0o7022;

function modeString(metadata) {
  return (metadata.mode & 0o7777).toString(8).padStart(4, "0");
}

function validateManifestMode(mode, path, { directory = false } = {}) {
  if (!/^[0-7]{4}$/.test(mode)) {
    throw new Error(`package manifest contains an invalid mode: ${path}`);
  }
  const value = Number.parseInt(mode, 8);
  if ((value & UNSAFE_MODE_BITS) !== 0) {
    throw new Error(`package manifest contains unsafe permissions: ${path}`);
  }
  if ((value & 0o400) === 0) {
    throw new Error(`package manifest omits owner read permission: ${path}`);
  }
  if (directory && (value & 0o100) === 0) {
    throw new Error(`package manifest directory is not owner-searchable: ${path}`);
  }
}

function safeReducedMode(expectedMode, actualMode, { directory = false } = {}) {
  const expected = Number.parseInt(expectedMode, 8);
  const actual = Number.parseInt(actualMode, 8);
  return (
    (actual & UNSAFE_MODE_BITS) === 0 &&
    (actual & ~expected) === 0 &&
    (actual & 0o400) !== 0 &&
    (!(directory || (expected & 0o111) !== 0) || (actual & 0o100) !== 0)
  );
}

function rejectExtendedAcls(root, label) {
  if (process.platform !== "darwin") {
    return;
  }
  for (const args of [["-lde", root], ["-leR", root]]) {
    const result = spawnSync("/bin/ls", args, {
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
    if (result.error || result.status !== 0) {
      const detail = result.error?.message || result.stderr?.trim() || `exit ${result.status}`;
      throw new Error(`${label} ACL inspection failed: ${detail}`);
    }
    if (/^\s+\d+:\s/m.test(result.stdout)) {
      throw new Error(`${label} contains extended ACLs`);
    }
  }
}

function readJsonDocument(path, label) {
  let parsed;
  let raw;
  try {
    if (lstatSync(path).isSymbolicLink()) {
      throw new Error("must not be a symlink");
    }
    raw = readFileSync(path);
    parsed = JSON.parse(raw.toString("utf8"));
  } catch (error) {
    throw new Error(`${label} cannot be read: ${error.message}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${label} is not an object`);
  }
  return { parsed, raw, digest: sha256(raw) };
}

function inventory(root, prefixes, { rejectBytecode = false } = {}) {
  const entries = new Map();

  function visit(path) {
    for (const name of readdirSync(path)) {
      const child = join(path, name);
      const rel = relative(root, child).split(sep).join("/");
      const metadata = lstatSync(child);
      if (rejectBytecode && (name === "__pycache__" || name.endsWith(".pyc"))) {
        throw new Error(`package contains forbidden Python bytecode: ${rel}`);
      }
      if (metadata.isSymbolicLink()) {
        throw new Error(`package contains a symlink: ${rel}`);
      } else if (metadata.isDirectory()) {
        entries.set(rel, {
          kind: "directory",
          target: null,
          sha256: null,
          mode: modeString(metadata),
        });
        visit(child);
      } else if (metadata.isFile()) {
        entries.set(rel, {
          kind: "file",
          target: null,
          sha256: sha256(readFileSync(child)),
          mode: modeString(metadata),
        });
      } else {
        throw new Error(`package contains an unsupported entry: ${rel}`);
      }
    }
  }

  for (const prefix of prefixes) {
    const path = join(root, prefix);
    if (!existsSync(path) || !lstatSync(path).isDirectory() || lstatSync(path).isSymbolicLink()) {
      throw new Error(`package directory is missing or linked: ${prefix}`);
    }
    entries.set(prefix, {
      kind: "directory",
      target: null,
      sha256: null,
      mode: modeString(lstatSync(path)),
    });
    visit(path);
  }
  return entries;
}

function validateManifestPath(path, { requiredPrefix = null, allowedPrefixes = null } = {}) {
  const parts = path.split("/");
  if (
    !path ||
    path.startsWith("/") ||
    path.includes("\\") ||
    parts.some((part) => !part || part === "." || part === "..") ||
    (requiredPrefix && parts[0] !== requiredPrefix) ||
    (allowedPrefixes && !allowedPrefixes.includes(parts[0]))
  ) {
    throw new Error(`package manifest contains an unsafe path: ${JSON.stringify(path)}`);
  }
  return parts;
}

function expectedEntries(
  rawFiles,
  {
    requiredPrefix = null,
    allowedPrefixes = null,
    rejectBytecode = false,
    requireMode = false,
  } = {},
) {
  if (!Array.isArray(rawFiles) || rawFiles.length === 0) {
    throw new Error("package manifest has no files");
  }
  const expected = new Map();
  for (const item of rawFiles) {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error("package manifest contains a non-object entry");
    }
    const path = typeof item.path === "string" ? item.path : "";
    const parts = validateManifestPath(path, { requiredPrefix, allowedPrefixes });
    if (rejectBytecode && (path.endsWith(".pyc") || parts.includes("__pycache__"))) {
      throw new Error(`package manifest contains forbidden Python bytecode: ${path}`);
    }
    if (expected.has(path)) {
      throw new Error(`package manifest contains a duplicate path: ${path}`);
    }
    const kind = item.kind || "file";
    const digest = typeof item.sha256 === "string" ? item.sha256.toLowerCase() : "";
    if (!/^[0-9a-f]{64}$/.test(digest) || kind !== "file") {
      throw new Error(`package manifest entry is invalid: ${path}`);
    }
    if ((requireMode || item.mode !== undefined) && !/^[0-7]{4}$/.test(item.mode)) {
      throw new Error(`package manifest contains an invalid mode: ${path}`);
    }
    if (requireMode) {
      validateManifestMode(item.mode, path);
    }
    expected.set(path, {
      kind,
      target: null,
      sha256: digest,
      mode: typeof item.mode === "string" ? item.mode : null,
    });
  }
  return expected;
}

function expectedDirectories(
  rawDirectories,
  { requiredPrefix = null, allowedPrefixes = null } = {},
) {
  if (!Array.isArray(rawDirectories) || rawDirectories.length === 0) {
    throw new Error("package manifest has no directories");
  }
  const expected = new Map();
  for (const item of rawDirectories) {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error("package manifest contains a non-object directory entry");
    }
    const path = typeof item.path === "string" ? item.path : "";
    validateManifestPath(path, { requiredPrefix, allowedPrefixes });
    if (expected.has(path)) {
      throw new Error(`package manifest contains a duplicate directory path: ${path}`);
    }
    validateManifestMode(item.mode, path, { directory: true });
    expected.set(path, {
      kind: "directory",
      target: null,
      sha256: null,
      mode: item.mode,
    });
  }
  return expected;
}

function mergeExpected(files, directories) {
  const merged = new Map(files);
  for (const [path, entry] of directories) {
    if (merged.has(path)) {
      throw new Error(`package manifest path is both a file and directory: ${path}`);
    }
    merged.set(path, entry);
  }
  return merged;
}

function requireExactInventory(expected, actual, label, { packageModePolicy = false } = {}) {
  for (const [path, entry] of expected) {
    const found = actual.get(path);
    if (!found) {
      throw new Error(`${label} file is missing: ${path}`);
    }
    let modeMismatch = entry.mode !== null && found.mode !== entry.mode;
    if (packageModePolicy) {
      modeMismatch = !safeReducedMode(entry.mode, found.mode, {
        directory: entry.kind === "directory",
      });
    }
    if (
      found.kind !== entry.kind ||
      found.target !== entry.target ||
      found.sha256 !== entry.sha256 ||
      modeMismatch
    ) {
      throw new Error(`${label} entry does not match its manifest: ${path}`);
    }
  }
  for (const path of actual.keys()) {
    if (!expected.has(path)) {
      throw new Error(`${label} entry is absent from its manifest: ${path}`);
    }
  }
}

function manifestEntriesMatch(left, right) {
  return (
    left?.kind === right?.kind &&
    left?.target === right?.target &&
    left?.sha256 === right?.sha256 &&
    left?.mode === right?.mode
  );
}

function verifyRuntimeSources(integrity) {
  if (sha256(readFileSync(join(integrity.runtimeRoot, "manifest.json"))) !== integrity.runtimeDocument.digest) {
    throw new Error("runtime package manifest changed after verification");
  }
  const coreActual = inventory(integrity.runtimeRoot, integrity.runtimePrefixes, {
    rejectBytecode: true,
  });
  rejectExtendedAcls(integrity.runtimeRoot, "runtime package");
  requireExactInventory(integrity.runtimeCoreEntries, coreActual, "runtime package", {
    packageModePolicy: true,
  });
  for (const component of integrity.runtimeComponents) {
    if (
      sha256(readFileSync(join(component.root, "component-manifest.json"))) !==
      component.document.digest
    ) {
      throw new Error(`${component.label} manifest changed after verification`);
    }
    const actual = inventory(component.root, ["payload"], { rejectBytecode: true });
    rejectExtendedAcls(join(component.root, "payload"), component.label);
    requireExactInventory(component.sourceEntries, actual, component.label, {
      packageModePolicy: true,
    });
  }
}

function verifyPackageIntegrity(env) {
  const packageVersion = readPackageVersion();
  const payloadDocument = readJsonDocument(
    join(packageRoot, "payload-manifest.json"),
    "payload manifest",
  );
  const payloadManifest = payloadDocument.parsed;
  if (
    payloadManifest.schema_version !== 2 ||
    payloadManifest.package_version !== packageVersion ||
    typeof payloadManifest.source_dirty !== "boolean" ||
    !/^[0-9a-f]{40}$/.test(payloadManifest.source_revision) ||
    !(
      payloadManifest.release_evidence_sha256 === null ||
      /^[0-9a-f]{64}$/.test(payloadManifest.release_evidence_sha256)
    )
  ) {
    throw new Error("payload manifest identity does not match the installed package");
  }
  const pythonArchives = payloadManifest.python_archives;
  if (
    !pythonArchives ||
    typeof pythonArchives !== "object" ||
    Array.isArray(pythonArchives) ||
    Object.keys(pythonArchives).sort().join(",") !== "darwin-arm64,darwin-x64" ||
    Object.values(pythonArchives).some((digest) => digest !== null && !/^[0-9a-f]{64}$/.test(digest))
  ) {
    throw new Error("payload manifest Python archive identities are invalid");
  }
  const automationArchives = payloadManifest.automation_archives;
  if (
    !automationArchives ||
    typeof automationArchives !== "object" ||
    Array.isArray(automationArchives) ||
    Object.keys(automationArchives).sort().join(",") !== "darwin-arm64,darwin-x64" ||
    Object.values(automationArchives).some((digest) => !/^[0-9a-f]{64}$/.test(digest))
  ) {
    throw new Error("payload manifest automation archive identities are invalid");
  }
  const runtimeManifests = payloadManifest.runtime_manifests;
  if (
    !runtimeManifests ||
    typeof runtimeManifests !== "object" ||
    Array.isArray(runtimeManifests) ||
    Object.keys(runtimeManifests).sort().join(",") !== "darwin-arm64,darwin-x64" ||
    Object.values(runtimeManifests).some((digest) => !/^[0-9a-f]{64}$/.test(digest))
  ) {
    throw new Error("payload manifest runtime identities are invalid");
  }
  const payloadExpected = expectedEntries(payloadManifest.files, {
    requiredPrefix: "payload",
    rejectBytecode: true,
    requireMode: true,
  });
  const payloadDirectories = expectedDirectories(payloadManifest.directories, {
    requiredPrefix: "payload",
  });
  const payloadEntries = mergeExpected(payloadExpected, payloadDirectories);
  const payloadActual = inventory(packageRoot, ["payload"], { rejectBytecode: true });
  rejectExtendedAcls(payloadRoot, "payload");
  requireExactInventory(payloadEntries, payloadActual, "payload", {
    packageModePolicy: true,
  });

  const runtimeDocument = readJsonDocument(
    join(env.runtimePackageDir, "manifest.json"),
    "runtime package manifest",
  );
  const runtimeManifest = runtimeDocument.parsed;
  const architecture = runtimeArchitecture();
  const platformKey = architecture ? `darwin-${architecture}` : null;
  if (
    runtimeManifest.schema_version !== 2 ||
    runtimeManifest.package_version !== packageVersion ||
    runtimeManifest.source_revision !== payloadManifest.source_revision ||
    runtimeManifest.release_evidence_sha256 !== payloadManifest.release_evidence_sha256 ||
    runtimeManifest.python_archive_sha256 !== pythonArchives[platformKey] ||
    runtimeManifest.automation_archive_sha256 !== automationArchives[platformKey] ||
    !/^[0-9a-f]{64}$/.test(runtimeManifest.automation_tree_sha256 || "") ||
    runtimeDocument.digest !== runtimeManifests[platformKey] ||
    runtimeManifest.architecture !== architecture
  ) {
    throw new Error("runtime package identity does not match the Pairling payload");
  }
  const runtimeExpected = expectedEntries(runtimeManifest.files, {
    allowedPrefixes: ["automation", "bin", "python", "provider-sdks"],
    rejectBytecode: true,
    requireMode: true,
  });
  const runtimeDirectories = expectedDirectories(runtimeManifest.directories, {
    allowedPrefixes: ["automation", "bin", "python", "provider-sdks"],
  });
  const runtimeEntries = mergeExpected(runtimeExpected, runtimeDirectories);
  const runtimeCoreEntries = new Map(runtimeEntries);
  const runtimeComponents = [];
  for (const definition of env.runtimeComponents) {
    const componentDocument = readJsonDocument(
      join(definition.root, "component-manifest.json"),
      `${definition.label} manifest`,
    );
    const componentManifest = componentDocument.parsed;
    if (
      componentManifest.schema_version !== 1 ||
      componentManifest.package !== definition.packageName ||
      componentManifest.package_version !== packageVersion ||
      componentManifest.source_revision !== payloadManifest.source_revision ||
      componentManifest.architecture !== architecture ||
      componentManifest.provider !== definition.provider ||
      componentManifest.runtime_manifest_sha256 !== runtimeDocument.digest ||
      componentManifest.target_prefix !== definition.targetPrefix
    ) {
      throw new Error(`${definition.label} identity does not match the Pairling runtime`);
    }
    const sourceFiles = expectedEntries(componentManifest.files, {
      requiredPrefix: "payload",
      rejectBytecode: true,
      requireMode: true,
    });
    const sourceDirectories = expectedDirectories(componentManifest.directories, {
      requiredPrefix: "payload",
    });
    const sourceEntries = mergeExpected(sourceFiles, sourceDirectories);
    const targetEntries = new Map();
    for (const [sourcePath, sourceEntry] of sourceEntries) {
      const suffix = sourcePath === "payload" ? "" : sourcePath.slice("payload/".length);
      const targetPath = suffix
        ? `${definition.targetPrefix}/${suffix}`
        : definition.targetPrefix;
      const runtimeEntry = runtimeCoreEntries.get(targetPath);
      if (!runtimeEntry || !manifestEntriesMatch(sourceEntry, runtimeEntry)) {
        throw new Error(
          `${definition.label} entry is not bound to the runtime manifest: ${targetPath}`,
        );
      }
      targetEntries.set(targetPath, { ...runtimeEntry, sourcePath });
      runtimeCoreEntries.delete(targetPath);
    }
    const component = {
      ...definition,
      document: componentDocument,
      manifest: componentManifest,
      sourceEntries,
      targetEntries,
    };
    const componentActual = inventory(definition.root, ["payload"], {
      rejectBytecode: true,
    });
    rejectExtendedAcls(join(definition.root, "payload"), definition.label);
    requireExactInventory(sourceEntries, componentActual, definition.label, {
      packageModePolicy: true,
    });
    runtimeComponents.push(component);
  }
  const prefixes = ["automation", "bin", "provider-sdks"];
  if (existsSync(join(env.runtimePackageDir, "python"))) {
    prefixes.push("python");
  }
  const runtimeActual = inventory(env.runtimePackageDir, prefixes, {
    rejectBytecode: true,
  });
  rejectExtendedAcls(env.runtimePackageDir, "runtime package");
  requireExactInventory(runtimeCoreEntries, runtimeActual, "runtime package", {
    packageModePolicy: true,
  });

  const payloadConnectd = platformKey ? payloadManifest.connectd?.[platformKey] : null;
  const runtimeConnectd = Array.isArray(runtimeManifest.files)
    ? runtimeManifest.files.find((entry) => entry?.path === "bin/pairling-connectd")
    : null;
  const cleanIdentity = (value) => (typeof value === "string" && value ? value : null);
  if (
    !payloadConnectd ||
    typeof payloadConnectd !== "object" ||
    !runtimeConnectd ||
    payloadConnectd.sha256 !== runtimeConnectd.sha256 ||
    cleanIdentity(payloadConnectd.team_id) !== cleanIdentity(runtimeConnectd.team_id) ||
    cleanIdentity(payloadConnectd.identifier) !== cleanIdentity(runtimeConnectd.identifier) ||
    payloadConnectd.architecture !== architecture ||
    runtimeConnectd.architecture !== architecture ||
    runtimeConnectd.identifier !== "dev.pairling.connectd"
  ) {
    throw new Error("selected connectd is not bound to the payload manifest");
  }

  const runtimeAutomation = Array.isArray(runtimeManifest.files)
    ? runtimeManifest.files.find(
        (entry) =>
          entry?.path === "automation/Pairling.app/Contents/MacOS/PairlingAutomation",
      )
    : null;
  if (
    !runtimeAutomation ||
    runtimeAutomation.identifier !== "dev.pairling.automation" ||
    runtimeAutomation.architecture !== architecture ||
    (runtimeConnectd.team_id && runtimeAutomation.team_id !== runtimeConnectd.team_id)
  ) {
    throw new Error("automation helper identity is incomplete or does not match connectd");
  }

  const runtimePython = Array.isArray(runtimeManifest.files)
    ? runtimeManifest.files.find((entry) => entry?.path === "python/bin/python3")
    : null;
  if (
    env.vendoredPython &&
    (!runtimePython ||
      !/^[0-9a-f]{64}$/.test(runtimeManifest.python_archive_sha256 || "") ||
      runtimePython.identifier !== "dev.pairling.python" ||
      runtimePython.architecture !== architecture ||
      (runtimeConnectd.team_id && runtimePython.team_id !== runtimeConnectd.team_id))
  ) {
    throw new Error("vendored Python identity is incomplete or does not match connectd");
  }
  if (!env.vendoredPython && runtimeManifest.python_archive_sha256 !== null) {
    throw new Error("runtime Python archive identity exists without vendored Python");
  }

  const integrity = {
    architecture,
    payloadDocument,
    payloadEntries,
    payloadManifest,
    runtimeComponents,
    runtimeCoreEntries,
    runtimeDocument,
    runtimeEntries,
    runtimeManifest,
    runtimePrefixes: prefixes,
    runtimeRoot: env.runtimePackageDir,
    runtimeConnectd,
    runtimePython,
    runtimeAutomation,
  };
  verifyRuntimeSources(integrity);
  return integrity;
}

function commandResult(command, args, label) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    const detail = result.error?.message || result.stderr?.trim() || `exit ${result.status}`;
    throw new Error(`${label} failed: ${detail}`);
  }
  return `${result.stdout || ""}${result.stderr || ""}`;
}

function codeIdentity(path) {
  const output = commandResult("/usr/bin/codesign", ["-dvv", path], `${path} identity inspection`);
  const fields = new Map();
  for (const line of output.split("\n")) {
    const separator = line.indexOf("=");
    if (separator > 0) {
      fields.set(line.slice(0, separator), line.slice(separator + 1));
    }
  }
  return fields;
}

function developerIdRequirement(teamId) {
  return (
    "anchor apple generic and " +
    `certificate leaf[subject.OU] = "${teamId}" and ` +
    "certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
  );
}

function verifyMachOIdentity(path, expected, architecture, label) {
  commandResult(
    "/usr/bin/codesign",
    ["--verify", "--strict", "--verbose=2", path],
    `${label} code signature verification`,
  );
  commandResult(
    "/usr/bin/codesign",
    [
      "--verify",
      "--strict",
      "--verbose=2",
      `-R=${developerIdRequirement(expected.team_id)}`,
      path,
    ],
    `${label} Developer ID certificate verification`,
  );
  const fields = codeIdentity(path);
  if (
    fields.get("Identifier") !== expected.identifier ||
    fields.get("TeamIdentifier") !== expected.team_id
  ) {
    throw new Error(`${label} code identity does not match its runtime manifest`);
  }
  const expectedMachArch = architecture === "x64" ? "x86_64" : architecture;
  const actualArchitectures = commandResult(
    "/usr/bin/lipo",
    ["-archs", path],
    `${label} architecture inspection`,
  )
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (actualArchitectures.length !== 1 || actualArchitectures[0] !== expectedMachArch) {
    throw new Error(`${label} architecture does not match its runtime package`);
  }
}

function verifyRuntimeCodeIdentity(env, integrity) {
  const expectedTeam = integrity.runtimeConnectd.team_id;
  if (!expectedTeam) {
    if (!integrity.payloadManifest.source_dirty) {
      throw new Error("unsigned runtime identity is forbidden for a clean package");
    }
    return;
  }
  if (!integrity.payloadManifest.source_dirty && expectedTeam !== EXPECTED_TEAM_ID) {
    throw new Error("clean runtime TeamIdentifier does not match Pairling release policy");
  }
  verifyMachOIdentity(
    env.connectdPath,
    integrity.runtimeConnectd,
    integrity.architecture,
    "connectd",
  );
  if (env.vendoredPython) {
    verifyMachOIdentity(
      env.vendoredPython,
      integrity.runtimePython,
      integrity.architecture,
      "vendored Python",
    );
  }
}

function copyManifestEntries(sourceRoot, destinationRoot, entries) {
  const sorted = [...entries.entries()].sort(([leftPath, left], [rightPath, right]) => {
    if (left.kind !== right.kind) {
      return left.kind === "directory" ? -1 : 1;
    }
    return leftPath.split("/").length - rightPath.split("/").length ||
      leftPath.localeCompare(rightPath);
  });
  for (const [path, entry] of sorted) {
    const sourcePath = entry.sourcePath || path;
    const source = join(sourceRoot, ...sourcePath.split("/"));
    const destination = join(destinationRoot, ...path.split("/"));
    const mode = Number.parseInt(entry.mode, 8);
    if (entry.kind === "directory") {
      mkdirSync(destination, { recursive: true, mode });
      chmodSync(destination, mode);
    } else {
      mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
      copyFileSync(source, destination);
      chmodSync(destination, mode);
    }
  }
}

function snapshotPrefix() {
  const uid = typeof process.getuid === "function" ? process.getuid() : "unknown";
  return `pairling-package-${uid}-`;
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code !== "ESRCH";
  }
}

function sweepDeadPackageSnapshots() {
  const directory = tmpdir();
  const prefix = snapshotPrefix();
  const owner = typeof process.getuid === "function" ? process.getuid() : null;
  let names;
  try {
    names = readdirSync(directory);
  } catch {
    return;
  }
  for (const name of names) {
    if (!name.startsWith(prefix)) {
      continue;
    }
    const match = name.slice(prefix.length).match(/^(\d+)-/);
    if (!match) {
      continue;
    }
    const path = join(directory, name);
    try {
      const metadata = lstatSync(path);
      if (
        metadata.isSymbolicLink() ||
        !metadata.isDirectory() ||
        (owner !== null && metadata.uid !== owner) ||
        processIsAlive(Number.parseInt(match[1], 10))
      ) {
        continue;
      }
      rmSync(path, { recursive: true, force: true });
    } catch {
      // A concurrent cleanup or rename is harmless. Never widen the target.
    }
  }
}

const SNAPSHOT_MODE_PAYLOAD = "payload";
const SNAPSHOT_MODE_FULL = "full";

function verifySnapshot(snapshotPairling, snapshotRuntime, integrity, mode) {
  if (sha256(readFileSync(join(snapshotPairling, "payload-manifest.json"))) !== integrity.payloadDocument.digest) {
    throw new Error("private payload snapshot manifest changed during creation");
  }
  const payloadActual = inventory(snapshotPairling, ["payload"], { rejectBytecode: true });
  requireExactInventory(integrity.payloadEntries, payloadActual, "private payload snapshot", {
    packageModePolicy: true,
  });
  rejectExtendedAcls(snapshotPairling, "private payload snapshot");
  if (mode === SNAPSHOT_MODE_FULL) {
    if (sha256(readFileSync(join(snapshotRuntime, "manifest.json"))) !== integrity.runtimeDocument.digest) {
      throw new Error("private runtime snapshot manifest changed during creation");
    }
    const runtimeActual = inventory(snapshotRuntime, integrity.runtimePrefixes, {
      rejectBytecode: true,
    });
    requireExactInventory(integrity.runtimeEntries, runtimeActual, "private runtime snapshot", {
      packageModePolicy: true,
    });
    rejectExtendedAcls(snapshotRuntime, "private runtime snapshot");
  } else if (mode === SNAPSHOT_MODE_PAYLOAD) {
    verifyRuntimeSources(integrity);
  } else {
    throw new Error(`unknown private package snapshot mode: ${mode}`);
  }
}

function createPrivatePackageSnapshot(integrity, mode) {
  if (mode !== SNAPSHOT_MODE_PAYLOAD && mode !== SNAPSHOT_MODE_FULL) {
    throw new Error(`unknown private package snapshot mode: ${mode}`);
  }
  sweepDeadPackageSnapshots();
  const root = mkdtempSync(join(tmpdir(), `${snapshotPrefix()}${process.pid}-`));
  chmodSync(root, 0o700);
  const snapshotPairling = join(root, "pairling");
  const snapshotRuntime = mode === SNAPSHOT_MODE_FULL
    ? join(root, "runtime")
    : integrity.runtimeRoot;
  mkdirSync(snapshotPairling, { mode: 0o700 });
  if (mode === SNAPSHOT_MODE_FULL) {
    mkdirSync(snapshotRuntime, { mode: 0o700 });
  }
  try {
    copyManifestEntries(packageRoot, snapshotPairling, integrity.payloadEntries);
    writeFileSync(
      join(snapshotPairling, "payload-manifest.json"),
      integrity.payloadDocument.raw,
      { mode: 0o600 },
    );
    if (mode === SNAPSHOT_MODE_FULL) {
      copyManifestEntries(
        integrity.runtimeRoot,
        snapshotRuntime,
        integrity.runtimeCoreEntries,
      );
      for (const component of integrity.runtimeComponents) {
        copyManifestEntries(
          component.root,
          snapshotRuntime,
          component.targetEntries,
        );
      }
      writeFileSync(
        join(snapshotRuntime, "manifest.json"),
        integrity.runtimeDocument.raw,
        { mode: 0o600 },
      );
    }
    verifySnapshot(snapshotPairling, snapshotRuntime, integrity, mode);
    return { root, pairling: snapshotPairling, runtime: snapshotRuntime, mode };
  } catch (error) {
    rmSync(root, { recursive: true, force: true });
    throw error;
  }
}

function packageSnapshotMode(args) {
  const command = args[0] || "setup";
  return new Set(["status", "doctor", "devices", "logs", "diagnose"]).has(command)
    ? SNAPSHOT_MODE_PAYLOAD
    : SNAPSHOT_MODE_FULL;
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
  const runtimeComponents = runtimeComponentPackageDirs();
  return {
    packageRoot,
    packageVersion: readPackageVersion(),
    payloadPresent: existsSync(payloadCli),
    payloadRoot,
    runtimePackageDir: runtimeDir,
    runtimeComponents,
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

function spawnDelegated(cli, args, extraEnv, { cwd = undefined, force = false } = {}) {
  const env = { ...process.env };
  for (const [key, value] of Object.entries(extraEnv)) {
    if (value !== null && value !== undefined && (force || env[key] === undefined)) {
      env[key] = value;
    }
  }
  return spawnSync(cli, args, { stdio: "inherit", env, cwd });
}

function delegate(cli, args, extraEnv, options = {}) {
  exitWithChild(spawnDelegated(cli, args, extraEnv, options));
}

function verifiedPackageEnvironment(pairlingRoot, runtimeRoot, integrity, snapshotMode) {
  const team = integrity.runtimeConnectd.team_id || "-";
  return {
    PAIRLING_REPO_ROOT: join(pairlingRoot, "payload"),
    PAIRLING_CONNECTD_PREBUILT: join(runtimeRoot, "bin", "pairling-connectd"),
    PAIRLING_DAEMON_PYTHON: join(runtimeRoot, "python", "bin", "python3"),
    PAIRLING_RUNTIME_PACKAGE_DIR: runtimeRoot,
    PAIRLING_RUNTIME_PACKAGE_ROOT: runtimeRoot,
    PAIRLING_TRUSTED_SHIM: shimPath,
    PAIRLING_CLAUDE_AGENT_SDK_ROOT: "",
    PAIRLING_NODE_BIN: process.execPath,
    PAIRLING_NODE_SHA256: sha256(readFileSync(process.execPath)),
    PAIRLING_SOURCE_REVISION: integrity.payloadManifest.source_revision,
    PAIRLING_SOURCE_DIRTY: integrity.payloadManifest.source_dirty ? "true" : "false",
    PAIRLING_CONNECTD_TEAM_ID: team,
    PAIRLING_PACKAGE_SNAPSHOT: snapshotMode,
    PAIRLING_VERIFIED_PAYLOAD_MANIFEST_SHA256: integrity.payloadDocument.digest,
    PAIRLING_VERIFIED_RUNTIME_MANIFEST_SHA256: integrity.runtimeDocument.digest,
  };
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
    const missingComponent = env.runtimeComponents.find((component) => !component.root);
    if (
      !env.runtimePackageDir ||
      !env.connectdPath ||
      !env.vendoredPython ||
      missingComponent
    ) {
      process.stderr.write(
        [
          "pairling: the platform runtime package is missing or incomplete.",
          "",
          `Expected: @pairling/runtime-darwin-${runtimeArchitecture()}` +
            (missingComponent ? ` and ${missingComponent.packageName}` : ""),
          "",
          "This usually means npm skipped optional dependencies (network hiccup",
          "or --no-optional / --omit=optional). Fix with:",
          "",
          "  npm install -g pairling --include=optional",
          "",
        ].join("\n"),
      );
      process.exit(1);
    }
    let integrity;
    try {
      sweepDeadPackageSnapshots();
      integrity = verifyPackageIntegrity(env);
      verifyRuntimeCodeIdentity(env, integrity);
    } catch (error) {
      process.stderr.write(`pairling: package integrity verification failed: ${error.message}\n`);
      process.stderr.write("Reinstall with: npm install -g pairling\n");
      process.exit(1);
    }
    const snapshotMode = packageSnapshotMode(args);
    let snapshot;
    try {
      snapshot = createPrivatePackageSnapshot(integrity, snapshotMode);
      const snapshotEnv = {
        ...env,
        runtimePackageDir: snapshot.runtime,
        connectdPath: join(snapshot.runtime, "bin", "pairling-connectd"),
        vendoredPython: join(snapshot.runtime, "python", "bin", "python3"),
      };
      verifyRuntimeCodeIdentity(snapshotEnv, integrity);
      const result = spawnDelegated(
        join(snapshot.pairling, "payload", "mac", "packaging", "bin", "pairling"),
        args,
        verifiedPackageEnvironment(
          snapshot.pairling,
          snapshot.runtime,
          integrity,
          snapshot.mode,
        ),
        { cwd: join(snapshot.pairling, "payload"), force: true },
      );
      rmSync(snapshot.root, { recursive: true, force: true });
      snapshot = null;
      exitWithChild(result);
    } catch (error) {
      if (snapshot?.root) {
        rmSync(snapshot.root, { recursive: true, force: true });
      }
      process.stderr.write(`pairling: private package snapshot failed: ${error.message}\n`);
      process.exit(1);
    }
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
