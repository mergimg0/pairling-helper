import { randomUUID } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const PROTOCOL = "pairling-qwen-sdk-v1";
const CLI_VERSION = "0.21.4";
const SDK_VERSION = "0.1.8";
const MAX_INPUT_BYTES = 256 * 1024;
const MAX_OUTPUT_BYTES = 1024 * 1024;
const MAX_SESSIONS = 16;
const SAFE_PERMISSION_MODES = new Set(["default", "plan"]);
const SAFE_EFFORTS = new Set(["low", "medium", "high", "xhigh", "max"]);
const PERMISSION_TIMEOUT_MS = 55_000;
const REQUIRED_METHODS = [
  "streamInput",
  "interrupt",
  "setPermissionMode",
  "setModel",
  "setEffort",
  "getContextUsage",
  "getAvailableModels",
  "getUsageInfo",
  "mcpServerStatus",
];
const SENSITIVE_KEY = /(?:api.?key|authorization|credential|password|secret|token)/i;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SAFE_MODEL_RE = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$/;

class ProtocolError extends Error {
  constructor(code, message = code) {
    super(message);
    this.code = code;
  }
}

class PushQueue {
  constructor() {
    this.values = [];
    this.waiters = [];
    this.closed = false;
  }

  push(value) {
    if (this.closed) throw new ProtocolError("session_closed");
    const waiter = this.waiters.shift();
    if (waiter) waiter({ value, done: false });
    else this.values.push(value);
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    for (const waiter of this.waiters.splice(0)) waiter({ done: true });
  }

  [Symbol.asyncIterator]() { return this; }

  next() {
    if (this.values.length) return Promise.resolve({ value: this.values.shift(), done: false });
    if (this.closed) return Promise.resolve({ done: true });
    return new Promise((resolveNext) => this.waiters.push(resolveNext));
  }
}

function exactObject(value, allowed, required = allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ProtocolError("invalid_request");
  }
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.includes(key)) || required.some((key) => !(key in value))) {
    throw new ProtocolError("invalid_request");
  }
  return value;
}

function safeString(value, maxLength, code = "invalid_request") {
  if (typeof value !== "string" || value.length < 1 || value.length > maxLength || value.includes("\0")) {
    throw new ProtocolError(code);
  }
  return value;
}

function boundedInteger(value, minimum, maximum, code = "invalid_request") {
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new ProtocolError(code);
  return value;
}

function manifestForEntry(entry, expectedName) {
  let current = dirname(realpathSync(entry));
  for (let depth = 0; depth < 5; depth += 1) {
    const candidate = join(current, "package.json");
    try {
      const manifest = JSON.parse(readFileSync(candidate, "utf8"));
      if (manifest?.name === expectedName) return { manifest, path: candidate };
    } catch {}
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  throw new ProtocolError(expectedName === "@qwen-code/sdk" ? "sdk_missing" : "cli_manifest_missing");
}

function sanitize(value, depth = 0, key = "") {
  if (SENSITIVE_KEY.test(key)) return "[redacted]";
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "string") return value.slice(0, 64 * 1024);
  if (depth >= 8) return "[truncated]";
  if (Array.isArray(value)) return value.slice(0, 256).map((item) => sanitize(item, depth + 1));
  if (value && typeof value === "object") {
    const result = {};
    for (const [childKey, childValue] of Object.entries(value).slice(0, 256)) {
      result[childKey.slice(0, 256)] = sanitize(childValue, depth + 1, childKey);
    }
    return result;
  }
  return String(value).slice(0, 1024);
}

function writeMessage(message) {
  const line = `${JSON.stringify(sanitize(message))}\n`;
  if (Buffer.byteLength(line) > MAX_OUTPUT_BYTES) {
    process.stdout.write(`${JSON.stringify({ type: "fatal", error: { code: "output_too_large", message: "output_too_large" } })}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(line);
}

function safeError(error) {
  const code = error instanceof ProtocolError ? error.code : "provider_error";
  return { code, message: code };
}

function initializationFailureCode(error) {
  const message = error instanceof Error ? error.message.toLowerCase() : "";
  if (message.includes("no auth type is selected")) {
    return "managed_provider_auth_unavailable";
  }
  return "session_initialize_failed";
}

function parseModels(payload) {
  const rows = payload && typeof payload === "object" && Array.isArray(payload.models) ? payload.models : [];
  const models = [];
  for (const row of rows.slice(0, 128)) {
    const value = typeof row === "string" ? row : row && typeof row.id === "string" ? row.id : null;
    if (value && SAFE_MODEL_RE.test(value) && !models.includes(value)) models.push(value);
  }
  return models;
}

const args = process.argv.slice(2);
if (args.length !== 3 || args[0] !== "--serve") {
  throw new ProtocolError("invalid_launch");
}
const sdkEntry = realpathSync(args[1]);
const cliEntry = realpathSync(args[2]);
if (!isAbsolute(sdkEntry) || !isAbsolute(cliEntry)) throw new ProtocolError("invalid_launch");
const sdkPackage = manifestForEntry(sdkEntry, "@qwen-code/sdk");
const cliPackage = manifestForEntry(cliEntry, "@qwen-code/qwen-code");
if (sdkPackage.manifest.version !== SDK_VERSION) throw new ProtocolError("sdk_version_unsupported");
if (cliPackage.manifest.version !== CLI_VERSION) throw new ProtocolError("cli_version_unsupported");
if (Number(process.versions.node.split(".")[0]) < 22) throw new ProtocolError("node_version_unsupported");

const sdk = await import(pathToFileURL(sdkEntry).href);
if (typeof sdk.query !== "function" || typeof sdk.Query !== "function") throw new ProtocolError("sdk_exports_missing");
const capabilityMethods = REQUIRED_METHODS.filter((name) => typeof sdk.Query.prototype[name] === "function");
if (capabilityMethods.length !== REQUIRED_METHODS.length) throw new ProtocolError("sdk_capabilities_missing");

const sessions = new Map();
const pendingApprovals = new Map();
let cursor = 0;

function emitEvent(sessionId, eventType, payload) {
  cursor += 1;
  const publicPayload = sanitize(payload);
  writeMessage({
    type: "event",
    cursor,
    event_id: randomUUID(),
    session_id: sessionId,
    provider: "qwen_code",
    event_type: eventType,
    observed_at: Date.now() / 1000,
    payload: publicPayload && typeof publicPayload === "object" && !Array.isArray(publicPayload)
      ? publicPayload
      : { value: publicPayload },
  });
}

function sessionFor(sessionId, { allowEnded = false } = {}) {
  const session = sessions.get(sessionId);
  if (!session || (!allowEnded && session.state !== "live")) throw new ProtocolError("session_not_live");
  return session;
}

function denySessionApprovals(sessionId, message) {
  for (const [approvalId, pending] of pendingApprovals) {
    if (pending.sessionId !== sessionId) continue;
    pendingApprovals.delete(approvalId);
    clearTimeout(pending.timer);
    pending.resolve({ behavior: "deny", message, interrupt: true });
    emitEvent(sessionId, "permission_resolved", { approval_id: approvalId, decision: "deny" });
  }
}

function permissionHandler(sessionId) {
  return async (toolName, input, options = {}) => {
    const approvalId = randomUUID();
    return new Promise((resolvePermission) => {
      const pending = {
        approvalId,
        sessionId,
        toolName: safeString(toolName, 256, "unsafe_tool_name"),
        input,
        resolve: resolvePermission,
        timer: null,
      };
      pendingApprovals.set(approvalId, pending);
      pending.timer = setTimeout(() => {
        if (!pendingApprovals.delete(approvalId)) return;
        resolvePermission({ behavior: "deny", message: "Permission request timed out", interrupt: true });
        emitEvent(sessionId, "permission_resolved", { approval_id: approvalId, decision: "deny" });
      }, PERMISSION_TIMEOUT_MS);
      emitEvent(sessionId, "permission_requested", {
        approval_id: approvalId,
        tool_name: pending.toolName,
        input: sanitize(input),
      });
      const signal = options?.signal;
      if (signal && typeof signal.addEventListener === "function") {
        signal.addEventListener("abort", () => {
          if (!pendingApprovals.delete(approvalId)) return;
          clearTimeout(pending.timer);
          resolvePermission({ behavior: "deny", message: "Permission request cancelled", interrupt: true });
          emitEvent(sessionId, "permission_resolved", { approval_id: approvalId, decision: "deny" });
        }, { once: true });
      }
    });
  };
}

async function consumeSession(session) {
  try {
    for await (const message of session.query) emitEvent(session.sessionId, "sdk_message", sanitize(message));
    if (session.state === "live") {
      session.state = "ended";
      emitEvent(session.sessionId, "session_ended", { reason: "provider_stream_closed" });
    }
  } catch {
    session.state = "failed";
    denySessionApprovals(session.sessionId, "Provider stream failed");
    emitEvent(session.sessionId, "session_failed", { code: "provider_stream_failed" });
  }
}

async function startSession(payload) {
  const allowed = [
    "session_id", "cwd", "first_prompt", "permission_mode", "sandbox", "safe_mode",
    "model", "effort", "max_session_turns", "max_tool_calls", "max_subagent_depth",
    "resume_session_id", "fork",
  ];
  exactObject(payload, allowed, ["session_id", "cwd", "permission_mode", "sandbox", "safe_mode"]);
  if ([...sessions.values()].filter((session) => session.state === "live").length >= MAX_SESSIONS) {
    throw new ProtocolError("session_limit_reached");
  }
  const sessionId = safeString(payload.session_id, 64);
  if (!UUID_RE.test(sessionId)) throw new ProtocolError("invalid_session_id");
  if (sessions.has(sessionId) && sessions.get(sessionId).state === "live") throw new ProtocolError("session_already_live");
  const cwd = realpathSync(safeString(payload.cwd, 4096));
  if (resolve(payload.cwd) !== cwd || !statSync(cwd).isDirectory()) throw new ProtocolError("unsafe_cwd");
  if (payload.sandbox !== true || payload.safe_mode !== true) throw new ProtocolError("unsafe_launch_mode");
  const permissionMode = safeString(payload.permission_mode, 32, "unsafe_permission_mode");
  if (!SAFE_PERMISSION_MODES.has(permissionMode)) throw new ProtocolError("unsafe_permission_mode");
  if (payload.model !== undefined && !SAFE_MODEL_RE.test(payload.model)) throw new ProtocolError("invalid_model");
  if (payload.effort !== undefined && !SAFE_EFFORTS.has(payload.effort)) throw new ProtocolError("invalid_effort");
  if (payload.first_prompt !== undefined) safeString(payload.first_prompt, 200_000);
  if (payload.resume_session_id !== undefined && !UUID_RE.test(payload.resume_session_id)) {
    throw new ProtocolError("invalid_resume_session_id");
  }
  if (payload.fork !== undefined && typeof payload.fork !== "boolean") throw new ProtocolError("invalid_request");

  const queue = new PushQueue();
  const options = {
    cwd,
    pathToQwenExecutable: cliEntry,
    permissionMode,
    canUseTool: permissionHandler(sessionId),
    abortController: new AbortController(),
    includePartialMessages: true,
    sandbox: true,
    safeMode: true,
    sessionId,
    timeout: { canUseTool: 60_000, controlRequest: 30_000, streamClose: 30_000 },
  };
  if (payload.model !== undefined) options.model = payload.model;
  if (payload.effort !== undefined) options.effort = payload.effort;
  if (payload.max_session_turns !== undefined) options.maxSessionTurns = boundedInteger(payload.max_session_turns, 1, 10_000);
  if (payload.max_tool_calls !== undefined) options.maxToolCalls = boundedInteger(payload.max_tool_calls, 1, 100_000);
  if (payload.max_subagent_depth !== undefined) options.maxSubagentDepth = boundedInteger(payload.max_subagent_depth, 1, 100);
  if (payload.resume_session_id !== undefined) options.resume = payload.resume_session_id;
  if (payload.fork === true) options.forkSession = true;

  const query = sdk.query({ prompt: queue, options });
  const session = { sessionId, query, queue, state: "starting", cwd, permissionMode, models: [] };
  sessions.set(sessionId, session);
  try {
    await query.initialized;
    session.state = "live";
    const availableModels = await query.getAvailableModels();
    session.models = parseModels(availableModels);
    void consumeSession(session);
    if (payload.first_prompt !== undefined) {
      queue.push({
        type: "user",
        session_id: sessionId,
        message: { role: "user", content: payload.first_prompt },
        parent_tool_use_id: null,
      });
    }
    emitEvent(sessionId, "session_started", {
      permission_mode: permissionMode,
      sandbox: true,
      safe_mode: true,
      resumed_from: payload.resume_session_id ?? null,
      forked: payload.fork === true,
    });
    return { session_id: sessionId, models: session.models, permission_mode: permissionMode };
  } catch (error) {
    sessions.delete(sessionId);
    queue.close();
    try { await query.close(); } catch {}
    throw new ProtocolError(initializationFailureCode(error));
  }
}

async function handleOperation(operation, payload) {
  if (operation === "handshake") {
    exactObject(payload, [], []);
    return {
      protocol: PROTOCOL,
      sdk_version: SDK_VERSION,
      cli_version: CLI_VERSION,
      node_version: process.versions.node,
      capability_methods: capabilityMethods,
      safe_permission_modes: [...SAFE_PERMISSION_MODES],
      schema_output: false,
      acp_fallback: false,
    };
  }
  if (operation === "session.start") return startSession(payload);

  const sessionAllowed = ["session_id", "action_id"];
  if (operation === "session.prompt.send" || operation === "session.turn.steer") {
    const field = operation === "session.prompt.send" ? "prompt" : "instruction";
    exactObject(payload, [...sessionAllowed, field], [...sessionAllowed, field]);
    const session = sessionFor(safeString(payload.session_id, 64));
    const text = safeString(payload[field], 200_000);
    safeString(payload.action_id, 512);
    session.queue.push({
      type: "user",
      session_id: session.sessionId,
      message: { role: "user", content: text },
      parent_tool_use_id: null,
    });
    return { accepted: true };
  }
  if (operation === "session.turn.interrupt") {
    exactObject(payload, sessionAllowed, sessionAllowed);
    const session = sessionFor(safeString(payload.session_id, 64));
    safeString(payload.action_id, 512);
    denySessionApprovals(session.sessionId, "Session interrupted");
    await session.query.interrupt();
    return { interrupted: true };
  }
  if (operation === "session.terminate") {
    exactObject(payload, sessionAllowed, sessionAllowed);
    const session = sessionFor(safeString(payload.session_id, 64));
    safeString(payload.action_id, 512);
    denySessionApprovals(session.sessionId, "Session terminated");
    session.state = "ended";
    session.queue.close();
    await session.query.close();
    emitEvent(session.sessionId, "session_ended", { reason: "terminated" });
    return { terminated: true };
  }
  if (operation === "session.model.set") {
    exactObject(payload, [...sessionAllowed, "model"], [...sessionAllowed, "model"]);
    const session = sessionFor(safeString(payload.session_id, 64));
    safeString(payload.action_id, 512);
    if (!SAFE_MODEL_RE.test(payload.model) || (session.models.length && !session.models.includes(payload.model))) {
      throw new ProtocolError("model_not_available");
    }
    await session.query.setModel(payload.model);
    return { model: payload.model };
  }
  if (operation === "session.reasoning.set") {
    exactObject(payload, [...sessionAllowed, "reasoning"], [...sessionAllowed, "reasoning"]);
    const session = sessionFor(safeString(payload.session_id, 64));
    safeString(payload.action_id, 512);
    if (!SAFE_EFFORTS.has(payload.reasoning)) throw new ProtocolError("invalid_effort");
    const applied = await session.query.setEffort(payload.reasoning);
    return { reasoning: payload.reasoning, applied: Boolean(applied) };
  }
  if (operation === "session.permissions.set") {
    exactObject(payload, [...sessionAllowed, "permissions"], [...sessionAllowed, "permissions"]);
    const session = sessionFor(safeString(payload.session_id, 64));
    safeString(payload.action_id, 512);
    if (!SAFE_PERMISSION_MODES.has(payload.permissions)) throw new ProtocolError("unsafe_permission_mode");
    await session.query.setPermissionMode(payload.permissions);
    session.permissionMode = payload.permissions;
    return { permissions: payload.permissions };
  }
  if (operation === "session.approval.decide") {
    exactObject(
      payload,
      [...sessionAllowed, "approval_id", "decision"],
      [...sessionAllowed, "approval_id", "decision"],
    );
    const session = sessionFor(safeString(payload.session_id, 64));
    safeString(payload.action_id, 512);
    const approvalId = safeString(payload.approval_id, 256);
    const decision = safeString(payload.decision, 16);
    if (decision !== "allow" && decision !== "deny") throw new ProtocolError("invalid_decision");
    const pending = pendingApprovals.get(approvalId);
    if (!pending || pending.sessionId !== session.sessionId) throw new ProtocolError("stale_approval");
    pendingApprovals.delete(approvalId);
    clearTimeout(pending.timer);
    if (decision === "allow") pending.resolve({ behavior: "allow", updatedInput: pending.input });
    else pending.resolve({ behavior: "deny", message: "User denied this tool request" });
    emitEvent(session.sessionId, "permission_resolved", { approval_id: approvalId, decision });
    return { approval_id: approvalId, decision };
  }
  if (operation === "provider.config.read") {
    exactObject(payload, ["session_id"], ["session_id"]);
    const session = sessionFor(safeString(payload.session_id, 64));
    const raw = await session.query.getAvailableModels();
    return { models: session.models, provider_data: sanitize(raw) };
  }
  if (operation === "provider.usage.read") {
    exactObject(payload, ["session_id"], ["session_id"]);
    const session = sessionFor(safeString(payload.session_id, 64));
    const [context, usage] = await Promise.all([
      session.query.getContextUsage(false),
      session.query.getUsageInfo("today"),
    ]);
    return { context: sanitize(context), usage: sanitize(usage) };
  }
  if (operation === "provider.mcp.read") {
    exactObject(payload, ["session_id"], ["session_id"]);
    const session = sessionFor(safeString(payload.session_id, 64));
    return { status: sanitize(await session.query.mcpServerStatus()) };
  }
  throw new ProtocolError("operation_not_supported");
}

let inputBuffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  inputBuffer += chunk;
  for (;;) {
    const newline = inputBuffer.indexOf("\n");
    if (newline < 0) break;
    const line = inputBuffer.slice(0, newline);
    inputBuffer = inputBuffer.slice(newline + 1);
    if (Buffer.byteLength(line) > MAX_INPUT_BYTES) {
      writeMessage({ type: "fatal", error: { code: "input_too_large", message: "input_too_large" } });
      process.exit(1);
    }
    if (!line) continue;
    void (async () => {
      let request;
      try {
        request = JSON.parse(line);
        exactObject(request, ["id", "operation", "payload"], ["id", "operation", "payload"]);
        const requestId = safeString(request.id, 128);
        const operation = safeString(request.operation, 128);
        const result = await handleOperation(operation, request.payload);
        writeMessage({ type: "response", id: requestId, ok: true, result });
      } catch (error) {
        const id = request && typeof request.id === "string" ? request.id.slice(0, 128) : "invalid";
        writeMessage({ type: "response", id, ok: false, error: safeError(error) });
      }
    })();
  }
  if (Buffer.byteLength(inputBuffer) > MAX_INPUT_BYTES) {
    writeMessage({ type: "fatal", error: { code: "input_too_large", message: "input_too_large" } });
    process.exit(1);
  }
});
process.stdin.on("end", async () => {
  for (const session of sessions.values()) {
    denySessionApprovals(session.sessionId, "Pairling sidecar disconnected");
    session.queue.close();
    try { await session.query.close(); } catch {}
  }
});
