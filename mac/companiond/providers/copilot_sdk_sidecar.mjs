import { readFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline";

const SIDECAR_PROTOCOL = 1;
const SDK_PACKAGE = "@github/copilot-sdk";
const SDK_VERSION = "1.0.8";
const CLI_VERSION = "1.0.78";
const SDK_PROTOCOL_VERSION = 3;
const CLI_CHANNEL = "stable";
const MAX_LINE_BYTES = 1024 * 1024;
const MAX_TEXT_BYTES = 64 * 1024;
const MAX_EVENTS = 512;
const MAX_REQUEST_ID_BYTES = 128;
const MAX_HISTORY_RESPONSE_FRAME_BYTES = MAX_LINE_BYTES;
const WORST_CASE_RESPONSE_ID = "\0".repeat(MAX_REQUEST_ID_BYTES);
const MAX_ATTACHMENTS = 8;
const MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024;
const MAX_ATTACHMENTS_BYTES = 8 * 1024 * 1024;

const REVIEWED_OPERATIONS = new Set([
  "handshake",
  "discover",
  "create_session",
  "resume_session",
  "events",
  "send",
  "steer",
  "abort",
  "set_model",
  "approval_decide",
  "read_usage",
  "read_mcp",
  "read_diagnostics",
]);

function parseArgs(argv) {
  const allowed = new Set([
    "--sdk-entry",
    "--sdk-version",
    "--cli-path",
    "--expected-cli-version",
    "--base-directory",
  ]);
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!allowed.has(flag) || typeof value !== "string" || value.length === 0) {
      throw new Error("invalid fixed sidecar arguments");
    }
    result[flag.slice(2)] = value;
  }
  if (Object.keys(result).length !== allowed.size || argv.length !== allowed.size * 2) {
    throw new Error("incomplete fixed sidecar arguments");
  }
  return result;
}

const args = parseArgs(process.argv.slice(2));
if (args["sdk-version"] !== SDK_VERSION || args["expected-cli-version"] !== CLI_VERSION) {
  throw new Error("unreviewed Copilot SDK or CLI version");
}

const sdkEntry = resolve(args["sdk-entry"]);
const sdkRoot = dirname(dirname(sdkEntry));
const sdkManifest = JSON.parse(await readFile(resolve(sdkRoot, "package.json"), "utf8"));
if (sdkManifest.name !== SDK_PACKAGE || sdkManifest.version !== SDK_VERSION) {
  throw new Error("Copilot SDK package identity mismatch");
}
const sdk = await import(pathToFileURL(sdkEntry).href);
if (typeof sdk.CopilotClient !== "function" || typeof sdk.RuntimeConnection?.forStdio !== "function") {
  throw new Error("Copilot SDK stable exports unavailable");
}

const baseDirectory = resolve(args["base-directory"]);
await mkdir(baseDirectory, { recursive: true, mode: 0o700 });

let client;
let canaries;
const sessions = new Map();
const sessionCwds = new Map();
const pendingApprovals = new Map();
const sessionControlCanaries = new Map();
let providerControlCanary;
const eventBuffer = [];
const usageBySession = new Map();
const mcpBySession = new Map();
const subagentsBySession = new Map();
const hooksBySession = new Map();
let cursor = 0;

function boundedString(value, limit = MAX_TEXT_BYTES) {
  if (typeof value !== "string") return undefined;
  const encoded = Buffer.from(value, "utf8");
  if (encoded.length <= limit) return value;
  return encoded.subarray(0, limit).toString("utf8") + "…";
}

function safeId(value, limit = 512) {
  const text = boundedString(value, limit);
  return text && text.length > 0 ? text : undefined;
}

function exactId(value, limit = MAX_REQUEST_ID_BYTES) {
  if (typeof value !== "string" || value.length === 0) return undefined;
  return Buffer.byteLength(value, "utf8") <= limit ? value : undefined;
}

function encodedFrame(message) {
  return Buffer.from(`${JSON.stringify(message)}\n`, "utf8");
}

function safeNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function redactErrorMessage(value) {
  return boundedString(value instanceof Error ? value.message : String(value), 512)
    .replace(/\b(bearer)\s+[a-z0-9._~+/=-]+/gi, "$1 [redacted]")
    .replace(/\b(token|secret|password|authorization|cookie|api[_-]?key|credential)\b(\s*[:=]\s*)([^\s,;]+)/gi, "$1$2[redacted]");
}

function sanitizeUnknown(value, key = "", depth = 0) {
  const lowered = key.toLowerCase().replaceAll("-", "_");
  if (["token", "secret", "password", "authorization", "cookie", "api_key", "apikey", "credential"].some((part) => lowered.includes(part))) {
    return "[redacted]";
  }
  if (depth > 6) return "[truncated]";
  if (Array.isArray(value)) return value.slice(0, 128).map((item) => sanitizeUnknown(item, "", depth + 1));
  if (value && typeof value === "object") {
    const output = {};
    for (const [childKey, childValue] of Object.entries(value).slice(0, 128)) {
      output[boundedString(childKey, 128)] = sanitizeUnknown(childValue, childKey, depth + 1);
    }
    return output;
  }
  if (typeof value === "string") return boundedString(value);
  if (value === null || typeof value === "boolean") return value;
  return safeNumber(value);
}

function permissionDetails(request) {
  const base = {
    permission_kind: safeId(request?.kind, 64),
    tool_call_id: safeId(request?.toolCallId, 256),
    intention: boundedString(request?.intention, 4096),
    sandbox_bypass_requested: request?.requestSandboxBypass === true,
  };
  switch (request?.kind) {
    case "shell":
      return {
        ...base,
        title: boundedString(request.intention || "Run shell command", 512),
        full_command_text: boundedString(request.fullCommandText),
        commands: Array.isArray(request.commands)
          ? request.commands.slice(0, 64).map((item) => ({ identifier: safeId(item?.identifier, 256), read_only: item?.readOnly === true }))
          : [],
        possible_paths: Array.isArray(request.possiblePaths) ? request.possiblePaths.slice(0, 64).map((item) => boundedString(item, 1024)) : [],
        possible_urls: Array.isArray(request.possibleUrls) ? request.possibleUrls.slice(0, 64).map((item) => boundedString(item?.url, 2048)) : [],
      };
    case "write":
      return { ...base, title: boundedString(request.intention || "Write file", 512), file_name: boundedString(request.fileName, 2048), diff: boundedString(request.diff) };
    case "read":
      return { ...base, title: boundedString(request.intention || "Read file", 512), path: boundedString(request.path, 2048) };
    case "mcp":
      return {
        ...base,
        title: boundedString(request.toolTitle || request.toolName || "Use MCP tool", 512),
        server_name: safeId(request.serverName, 256),
        tool_name: safeId(request.toolName, 256),
        read_only: request.readOnly === true,
        arguments: sanitizeUnknown(request.args),
      };
    case "url":
      return { ...base, title: boundedString(request.intention || "Open URL", 512), url: boundedString(request.url, 4096) };
    case "memory":
      return { ...base, title: "Change memory", action: safeId(request.action, 64), subject: boundedString(request.subject, 1024), fact: boundedString(request.fact) };
    case "custom-tool":
      return { ...base, title: boundedString(request.toolDescription || request.toolName || "Use custom tool", 512), tool_name: safeId(request.toolName, 256), arguments: sanitizeUnknown(request.args) };
    case "hook":
      return { ...base, title: boundedString(request.hookMessage || request.toolName || "Hook confirmation", 512), tool_name: safeId(request.toolName, 256), arguments: sanitizeUnknown(request.toolArgs) };
    default:
      return { ...base, title: "Unsupported permission request" };
  }
}

function metadataForEvent(event) {
  const type = safeId(event?.type, 128);
  const data = event?.data && typeof event.data === "object" ? event.data : {};
  if (!type) return undefined;
  if (type === "permission.requested") {
    const details = permissionDetails(data.permissionRequest);
    return {
      request_id: safeId(data.requestId, 256),
      ...details,
      resolved_by_hook: data.resolvedByHook === true,
      session_approval_available: sessionApprovalAvailable(data.permissionRequest),
    };
  }
  if (type === "permission.completed") {
    return { request_id: safeId(data.requestId, 256), tool_call_id: safeId(data.toolCallId, 256), result_kind: safeId(data.result?.kind, 128) };
  }
  if (type.startsWith("assistant.") || type === "user.message") {
    return {
      content: boundedString(data.content || data.deltaContent || data.message),
      message_id: safeId(data.messageId, 256),
      delivery: safeId(data.delivery, 64),
    };
  }
  if (type.includes("usage") || type === "session.usage_info" || type === "session.usage_checkpoint") {
    const output = {};
    for (const [key, value] of Object.entries(data)) {
      const number = safeNumber(value);
      if (number !== undefined && /token|cost|duration|multiplier|quota|limit/i.test(key)) output[key] = number;
    }
    return output;
  }
  if (type.startsWith("subagent.")) {
    return {
      agent_id: safeId(data.agentId || event.agentId, 256),
      name: safeId(data.name || data.agentName, 256),
      status: safeId(data.status, 64),
      model: safeId(data.model, 160),
      description: boundedString(data.description, 1024),
    };
  }
  if (type.startsWith("mcp.")) {
    return {
      server_name: safeId(data.serverName, 256),
      tool_name: safeId(data.toolName, 256),
      status: safeId(data.status, 128),
      error: data.error === undefined
        ? undefined
        : redactErrorMessage(data.error?.message || data.error),
    };
  }
  if (type.startsWith("hook.")) {
    return {
      hook_type: safeId(data.hookType || data.type, 128),
      tool_name: safeId(data.toolName, 256),
      status: safeId(data.status, 128),
    };
  }
  if (type.startsWith("session.") || type.startsWith("command.")) {
    return {
      model: safeId(data.model || data.modelId, 160),
      mode: safeId(data.mode, 64),
      title: boundedString(data.title, 512),
      status: safeId(data.status, 128),
      command: safeId(data.command || data.name, 256),
    };
  }
  return { unknown_extension: true };
}

function normalizeHistoryEvent(event, sessionId) {
  return {
    event_id: safeId(event?.id, 512),
    session_id: sessionId,
    kind: safeId(event?.type, 128),
    timestamp: boundedString(event?.timestamp, 128),
    payload: metadataForEvent(event),
  };
}

function historyCursor(value) {
  const candidate = value === undefined ? 0 : value;
  if (!Number.isSafeInteger(candidate) || candidate < 0 || candidate > MAX_EVENTS) {
    throw Object.assign(new Error("Copilot history cursor is invalid"), { code: "invalid_history_cursor" });
  }
  return candidate;
}

function historyPage(message, sessionId, events) {
  const history = events.slice(-MAX_EVENTS);
  const start = historyCursor(message.after_cursor);
  if (start > history.length) {
    throw Object.assign(new Error("Copilot history cursor is outside the retained history"), { code: "invalid_history_cursor" });
  }
  const providerOperationId = `events:${sessionId}`;
  const baseFrameBytes = encodedFrame({
    type: "response",
    id: WORST_CASE_RESPONSE_ID,
    ok: true,
    result: {
      provider_operation_id: providerOperationId,
      events: [],
      cursor: MAX_EVENTS,
      next_cursor: MAX_EVENTS,
      partial: false,
      total_events: MAX_EVENTS,
    },
  }).length;
  const page = [];
  let aggregateFrameBytes = baseFrameBytes;
  let nextCursor = start;
  while (nextCursor < history.length) {
    const event = normalizeHistoryEvent(history[nextCursor], sessionId);
    const eventBytes = Buffer.byteLength(JSON.stringify(event), "utf8") + (page.length > 0 ? 1 : 0);
    if (aggregateFrameBytes + eventBytes > MAX_HISTORY_RESPONSE_FRAME_BYTES) {
      if (page.length === 0) {
        throw Object.assign(new Error("Copilot history event exceeds the bounded JSONL response"), { code: "response_too_large" });
      }
      break;
    }
    page.push(event);
    aggregateFrameBytes += eventBytes;
    nextCursor += 1;
  }
  return {
    provider_operation_id: providerOperationId,
    events: page,
    cursor: start,
    next_cursor: nextCursor,
    partial: nextCursor < history.length,
    total_events: history.length,
  };
}

async function denySandboxBypass(session, requestId) {
  await session.rpc.permissions.handlePendingPermissionRequest({
    requestId,
    result: { kind: "reject", feedback: "Sandbox bypass is not available through Pairling." },
  });
}

function observeSession(session) {
  session.on((event) => {
    const eventId = safeId(event?.id, 512);
    const type = safeId(event?.type, 128);
    if (!eventId || !type) return;
    const metadata = metadataForEvent(event);
    if (!metadata) return;
    cursor += 1;
    const normalized = {
      event_id: eventId,
      session_id: session.sessionId,
      kind: type,
      payload: metadata,
      timestamp: boundedString(event.timestamp, 128),
      cursor,
    };
    eventBuffer.push(normalized);
    if (eventBuffer.length > MAX_EVENTS) eventBuffer.shift();

    if (type === "permission.requested") {
      const requestId = safeId(event.data?.requestId, 256);
      const request = event.data?.permissionRequest;
      if (!requestId || !request || event.data?.resolvedByHook === true) return;
      if (request.requestSandboxBypass === true) {
        void denySandboxBypass(session, requestId);
        return;
      }
      pendingApprovals.set(requestId, {
        sessionId: session.sessionId,
        toolCallId: safeId(request.toolCallId, 256),
        request,
      });
    } else if (type === "permission.completed") {
      const requestId = safeId(event.data?.requestId, 256);
      if (requestId) pendingApprovals.delete(requestId);
    }

    if (type.includes("usage")) usageBySession.set(session.sessionId, sanitizeUnknown(metadata));
    if (type.startsWith("mcp.")) {
      const rows = mcpBySession.get(session.sessionId) || [];
      rows.push(metadata);
      mcpBySession.set(session.sessionId, rows.slice(-128));
    }
    if (type.startsWith("subagent.")) {
      const rows = subagentsBySession.get(session.sessionId) || [];
      rows.push(metadata);
      subagentsBySession.set(session.sessionId, rows.slice(-128));
    }
    if (type.startsWith("hook.")) {
      const rows = hooksBySession.get(session.sessionId) || [];
      rows.push(metadata);
      hooksBySession.set(session.sessionId, rows.slice(-128));
    }

    emit({ type: "event", event: normalized });
  });
}

async function deferPermissionToPairling() {
  return { kind: "no-result" };
}

function sessionConfig(workingDirectory, model) {
  const config = {
    clientName: "Pairling",
    workingDirectory,
    onPermissionRequest: deferPermissionToPairling,
    availableTools: ["builtin:*"],
    enableConfigDiscovery: false,
    requestExtensions: false,
    requestCanvasRenderer: false,
    customAgentsLocalOnly: true,
    coauthorEnabled: false,
    manageScheduleEnabled: false,
    mcpOAuthTokenStorage: "in-memory",
    streaming: true,
    includeSubAgentStreamingEvents: true,
    enableSessionTelemetry: false,
    enableManagedSettings: false,
    skipEmbeddingRetrieval: true,
    embeddingCacheStorage: "in-memory",
  };
  if (model) config.model = model;
  return config;
}

async function liveCanaries() {
  if (!client) {
    client = new sdk.CopilotClient({
      connection: sdk.RuntimeConnection.forStdio({ path: resolve(args["cli-path"]) }),
      mode: "copilot-cli",
      workingDirectory: baseDirectory,
      baseDirectory,
      useLoggedInUser: true,
      logLevel: "error",
    });
    await client.start();
  }
  const [status, ping, auth, models] = await Promise.all([
    client.getStatus(),
    client.ping("pairling-sdk-canary"),
    client.getAuthStatus(),
    client.listModels(),
  ]);
  if (status.version !== args["expected-cli-version"] || status.protocolVersion !== SDK_PROTOCOL_VERSION || ping.protocolVersion !== SDK_PROTOCOL_VERSION) {
    throw new Error("Copilot CLI version or JSON-RPC protocol canary mismatch");
  }
  if (auth.isAuthenticated !== true || !Array.isArray(models) || models.length === 0) {
    throw new Error("Copilot auth or model discovery canary failed");
  }
  canaries = { status, auth, models, observedAt: new Date().toISOString() };
  return canaries;
}

function modelRows(models) {
  return models.slice(0, 128).flatMap((model) => {
    const id = safeId(model?.id, 160);
    const name = safeId(model?.name, 160);
    if (!id || !name) return [];
    return [{
      id,
      name,
      reasoning_efforts: Array.isArray(model.supportedReasoningEfforts)
        ? model.supportedReasoningEfforts.filter((item) => ["low", "medium", "high", "xhigh"].includes(item))
        : [],
      vision: model.capabilities?.supports?.vision === true,
      billing_multiplier: safeNumber(model.billing?.multiplier),
    }];
  });
}

function sessionCapabilities(session) {
  const capabilities = [];
  if (typeof client?.listSessions === "function" && typeof client?.resumeSession === "function") capabilities.push("sessions");
  if (typeof session?.getEvents === "function") capabilities.push("history", "events");
  if (typeof session?.send === "function") capabilities.push("message_enqueue", "message_immediate");
  if (typeof session?.abort === "function") capabilities.push("abort");
  if (typeof client?.listModels === "function") capabilities.push("models");
  if (typeof session?.setModel === "function") capabilities.push("set_model");
  if (typeof session?.rpc?.permissions?.handlePendingPermissionRequest === "function") capabilities.push("approval_response");
  capabilities.push("usage", "mcp_metadata", "subagent_metadata", "hook_metadata");
  return capabilities;
}

function normalizeSessionMetadata(item) {
  return {
    session_id: safeId(item?.sessionId, 512),
    start_time: item?.startTime instanceof Date ? item.startTime.toISOString() : boundedString(item?.startTime, 128),
    modified_time: item?.modifiedTime instanceof Date ? item.modifiedTime.toISOString() : boundedString(item?.modifiedTime, 128),
    summary: boundedString(item?.summary, 1024),
    working_directory: boundedString(item?.context?.workingDirectory, 4096),
  };
}

function validateWorkingDirectory(value) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) throw new Error("invalid session working directory");
  const path = resolve(value);
  if (path !== value) throw new Error("session working directory must be canonical and absolute");
  return path;
}

function validateAttachments(value) {
  if (!Array.isArray(value) || value.length > MAX_ATTACHMENTS) throw new Error("invalid SDK attachments");
  let total = 0;
  return value.map((item) => {
    if (!item || item.type !== "blob" || typeof item.data !== "string") throw new Error("only prepared blob attachments are accepted");
    if (Object.keys(item).some((key) => !["type", "data", "mimeType", "displayName"].includes(key))) throw new Error("unknown SDK attachment field");
    const mimeType = safeId(item.mimeType, 128);
    const displayName = item.displayName === undefined ? undefined : safeId(item.displayName, 128);
    if (!mimeType || (item.displayName !== undefined && !displayName)) throw new Error("invalid SDK attachment metadata");
    const data = Buffer.from(item.data, "base64");
    if (data.toString("base64") !== item.data || data.length > MAX_ATTACHMENT_BYTES) throw new Error("invalid SDK attachment encoding or size");
    total += data.length;
    if (total > MAX_ATTACHMENTS_BYTES) throw new Error("SDK attachments exceed aggregate bound");
    return {
      type: "blob",
      data: item.data,
      mimeType,
      ...(displayName ? { displayName } : {}),
    };
  });
}

function operationId(message, providerId) {
  return `${safeId(message.client_action_id, 256) || "pairling"}:${safeId(providerId, 256)}`;
}

function requireMutationCorrelation(message, requireSession = true) {
  if (
    !safeId(message.binding_id, 256) ||
    !Number.isSafeInteger(message.capability_generation) ||
    message.capability_generation < 1 ||
    !safeId(message.client_action_id, 512) ||
    (requireSession && !safeId(message.pairling_session_id, 512))
  ) {
    throw new Error("mutation lacks exact Pairling correlation");
  }
}

function controlCanary(message, sessionId, workingDirectory) {
  const bindingId = safeId(message.binding_id, 256);
  const generation = message.capability_generation;
  const pairlingSessionId = message.pairling_session_id === null
    ? null
    : safeId(message.pairling_session_id, 512);
  const expectedPairlingSessionId = sessionId ? `copilot:${sessionId}` : null;
  if (
    !bindingId ||
    !Number.isSafeInteger(generation) ||
    generation < 1 ||
    pairlingSessionId !== expectedPairlingSessionId
  ) {
    throw new Error("discovery lacks exact Pairling binding or session correlation");
  }
  return {
    bindingId,
    generation,
    pairlingSessionId,
    workingDirectory,
  };
}

function requireSessionControlCanary(message, sessionId) {
  requireMutationCorrelation(message);
  const expected = sessionControlCanaries.get(sessionId);
  if (
    !expected ||
    message.binding_id !== expected.bindingId ||
    message.capability_generation !== expected.generation ||
    message.pairling_session_id !== expected.pairlingSessionId ||
    sessionCwds.get(sessionId) !== expected.workingDirectory
  ) {
    throw new Error("session control canary is unavailable or stale");
  }
}

function requireProviderControlCanary(message) {
  requireMutationCorrelation(message, false);
  if (
    message.pairling_session_id !== null ||
    !providerControlCanary ||
    message.binding_id !== providerControlCanary.bindingId ||
    message.capability_generation !== providerControlCanary.generation
  ) {
    throw new Error("provider control canary is unavailable or stale");
  }
}

function sessionApprovalAvailable(request) {
  try {
    approvalResult({ request }, "session");
    return true;
  } catch {
    return false;
  }
}

function approvalResult(pending, decision) {
  if (decision === "once") return { kind: "approve-once" };
  if (decision === "deny") return { kind: "reject" };
  const request = pending.request;
  switch (request.kind) {
    case "shell": {
      const commandIdentifiers = Array.isArray(request.commands)
        ? request.commands.map((item) => safeId(item?.identifier, 256)).filter(Boolean)
        : [];
      if (commandIdentifiers.length === 0) throw new Error("shell session approval lacks exact command identifiers");
      return { kind: "approve-for-session", approval: { kind: "commands", commandIdentifiers } };
    }
    case "read": return { kind: "approve-for-session", approval: { kind: "read" } };
    case "write": return { kind: "approve-for-session", approval: { kind: "write" } };
    case "mcp": {
      const serverName = safeId(request.serverName, 256);
      if (!serverName) throw new Error("MCP session approval lacks an exact server");
      return {
        kind: "approve-for-session",
        approval: { kind: "mcp", serverName, toolName: safeId(request.toolName, 256) || null },
      };
    }
    case "memory": return { kind: "approve-for-session", approval: { kind: "memory" } };
    case "custom-tool": {
      const toolName = safeId(request.toolName, 256);
      if (!toolName) throw new Error("custom-tool session approval lacks an exact tool");
      return { kind: "approve-for-session", approval: { kind: "custom-tool", toolName } };
    }
    case "url": {
      const domain = new URL(request.url).hostname;
      if (!domain) throw new Error("URL session approval lacks exact domain");
      return { kind: "approve-for-session", domain };
    }
    default: throw new Error("session approval is unavailable for this permission kind");
  }
}

async function handle(message) {
  if (!message || typeof message !== "object" || !exactId(message.id) || !REVIEWED_OPERATIONS.has(message.op)) {
    throw Object.assign(new Error("unreviewed sidecar operation"), { code: "unsupported_operation" });
  }
  const live = await liveCanaries();
  switch (message.op) {
    case "handshake":
      if (
        message.sidecar_protocol !== SIDECAR_PROTOCOL ||
        message.expected_sdk_package !== SDK_PACKAGE ||
        message.expected_sdk_version !== SDK_VERSION ||
        message.expected_cli_version !== args["expected-cli-version"] ||
        message.expected_cli_channel !== CLI_CHANNEL ||
        message.expected_sdk_protocol !== SDK_PROTOCOL_VERSION
      ) throw new Error("sidecar handshake expectation mismatch");
      return {
        sidecar_protocol: SIDECAR_PROTOCOL,
        sdk_package: SDK_PACKAGE,
        sdk_version: SDK_VERSION,
        cli_version: live.status.version,
        cli_channel: CLI_CHANNEL,
        sdk_protocol_version: live.status.protocolVersion,
        transport: "stdio-jsonrpc",
      };
    case "create_session": {
      requireMutationCorrelation(message, false);
      const cwd = validateWorkingDirectory(message.working_directory);
      const model = message.model === undefined ? undefined : safeId(message.model, 160);
      if (message.model !== undefined && !modelRows(live.models).some((item) => item.id === model)) throw new Error("model not returned by live discovery");
      const session = await client.createSession(sessionConfig(cwd, model));
      sessions.set(session.sessionId, session);
      sessionCwds.set(session.sessionId, cwd);
      observeSession(session);
      sessionControlCanaries.delete(session.sessionId);
      return { native_session_id: session.sessionId, working_directory: cwd, provider_operation_id: session.sessionId };
    }
    case "resume_session": {
      requireMutationCorrelation(message);
      const sessionId = safeId(message.native_session_id, 512);
      const cwd = validateWorkingDirectory(message.working_directory);
      const sourceSessionId = message.source_native_session_id === undefined
        ? undefined
        : safeId(message.source_native_session_id, 512);
      if (message.source_native_session_id !== undefined) {
        if (!sourceSessionId) throw new Error("resume source session identity is invalid");
        requireSessionControlCanary(message, sourceSessionId);
      }
      if (!sessionId) throw new Error("invalid session identity");
      let session = sessions.get(sessionId);
      if (!session) {
        session = await client.resumeSession(sessionId, sessionConfig(cwd, undefined));
        sessions.set(sessionId, session);
        sessionCwds.set(sessionId, cwd);
        sessionControlCanaries.delete(sessionId);
        observeSession(session);
      }
      if (sessionCwds.get(sessionId) !== cwd) throw new Error("session working directory mismatch");
      sessionControlCanaries.delete(sessionId);
      return {
        native_session_id: sessionId,
        working_directory: cwd,
        session_capabilities: sanitizeUnknown(session.capabilities),
        provider_operation_id: sessionId,
      };
    }
    case "discover": {
      const sessionId = message.native_session_id === null ? undefined : safeId(message.native_session_id, 512);
      const session = sessionId ? sessions.get(sessionId) : undefined;
      if (sessionId && !session) throw new Error("session is not owned by this sidecar");
      const cwd = sessionId ? validateWorkingDirectory(message.working_directory) : null;
      if (sessionId && sessionCwds.get(sessionId) !== cwd) throw new Error("session cwd canary mismatch");
      const canary = controlCanary(message, sessionId, cwd);
      const listed = await client.listSessions();
      if (sessionId) {
        sessionControlCanaries.set(sessionId, canary);
      } else {
        providerControlCanary = canary;
      }
      return {
        cli_version: live.status.version,
        cli_channel: CLI_CHANNEL,
        sdk_version: SDK_VERSION,
        sdk_protocol_version: live.status.protocolVersion,
        transport: "stdio-jsonrpc",
        authenticated: live.auth.isAuthenticated === true,
        permission_policy: "scoped-pending",
        sandbox_bypass_allowed: false,
        binding_id: canary.bindingId,
        capability_generation: canary.generation,
        pairling_session_id: canary.pairlingSessionId,
        working_directory: cwd,
        native_session_id: sessionId || null,
        capabilities: sessionCapabilities(session),
        session_capabilities: sanitizeUnknown(session?.capabilities || {}),
        models: modelRows(live.models),
        sessions: listed.filter((item) => sessions.has(item?.sessionId)).slice(0, 256).map(normalizeSessionMetadata),
        usage: sanitizeUnknown(Object.fromEntries(usageBySession)),
        mcp_servers: sanitizeUnknown(Object.fromEntries(mcpBySession)),
        subagents: sanitizeUnknown(Object.fromEntries(subagentsBySession)),
        hooks: sanitizeUnknown(Object.fromEntries(hooksBySession)),
      };
    }
    case "events": {
      const sessionId = safeId(message.native_session_id, 512);
      const session = sessions.get(sessionId);
      requireSessionControlCanary(message, sessionId);
      if (!session) throw new Error("session is not owned by this sidecar");
      const events = await session.getEvents();
      return historyPage(message, sessionId, events);
    }
    case "send": {
      requireSessionControlCanary(message, safeId(message.native_session_id, 512));
      const session = sessions.get(safeId(message.native_session_id, 512));
      const prompt = boundedString(message.prompt);
      if (!session || !prompt) throw new Error("invalid owned session or prompt");
      const messageId = await session.send({ prompt, attachments: validateAttachments(message.attachments), mode: "enqueue" });
      return { provider_operation_id: operationId(message, messageId), message_id: messageId, delivery: "enqueue" };
    }
    case "steer": {
      requireSessionControlCanary(message, safeId(message.native_session_id, 512));
      const session = sessions.get(safeId(message.native_session_id, 512));
      const instruction = boundedString(message.instruction);
      if (!session || !instruction) throw new Error("invalid owned session or steering instruction");
      const messageId = await session.send({ prompt: instruction, mode: "immediate" });
      return { provider_operation_id: operationId(message, messageId), message_id: messageId, delivery: "immediate" };
    }
    case "abort": {
      requireSessionControlCanary(message, safeId(message.native_session_id, 512));
      const sessionId = safeId(message.native_session_id, 512);
      const session = sessions.get(sessionId);
      if (!session) throw new Error("session is not owned by this sidecar");
      await session.abort();
      return { provider_operation_id: operationId(message, `abort:${sessionId}`), aborted: true };
    }
    case "set_model": {
      requireSessionControlCanary(message, safeId(message.native_session_id, 512));
      const sessionId = safeId(message.native_session_id, 512);
      const session = sessions.get(sessionId);
      const model = safeId(message.model, 160);
      if (!session || !model || !modelRows(live.models).some((item) => item.id === model)) throw new Error("model is not live or session is not owned");
      await session.setModel(model);
      return { provider_operation_id: operationId(message, `model:${sessionId}`), model };
    }
    case "approval_decide": {
      requireSessionControlCanary(message, safeId(message.session_id, 512));
      const requestId = safeId(message.request_id, 256);
      const sessionId = safeId(message.session_id, 512);
      const pending = pendingApprovals.get(requestId);
      if (!requestId || !sessionId || !pending || pending.sessionId !== sessionId || pending.toolCallId !== (message.tool_call_id || undefined) || pending.request.kind !== message.permission_kind) {
        throw Object.assign(new Error("approval correlation mismatch"), { code: "approval_correlation" });
      }
      if (!["once", "session", "deny"].includes(message.decision)) throw new Error("approval decision is not reviewed");
      const session = sessions.get(sessionId);
      if (!session) throw new Error("approval session is not owned");
      await session.rpc.permissions.handlePendingPermissionRequest({ requestId, result: approvalResult(pending, message.decision) });
      pendingApprovals.delete(requestId);
      return { provider_operation_id: operationId(message, `approval:${requestId}`), decision: message.decision, approval_id: requestId };
    }
    case "read_usage":
      requireProviderControlCanary(message);
      return { provider_operation_id: operationId(message, "usage"), sessions: sanitizeUnknown(Object.fromEntries(usageBySession)) };
    case "read_mcp":
      requireProviderControlCanary(message);
      return { provider_operation_id: operationId(message, "mcp"), sessions: sanitizeUnknown(Object.fromEntries(mcpBySession)) };
    case "read_diagnostics":
      requireProviderControlCanary(message);
      return {
        provider_operation_id: operationId(message, "diagnostics"),
        sdk_version: SDK_VERSION,
        cli_version: live.status.version,
        sdk_protocol_version: live.status.protocolVersion,
        transport: "stdio-jsonrpc",
        last_canary_at: live.observedAt,
      };
    default:
      throw Object.assign(new Error("unreviewed sidecar operation"), { code: "unsupported_operation" });
  }
}

function emit(message) {
  let encoded = encodedFrame(message);
  if (encoded.length > MAX_LINE_BYTES) {
    const fallback = message?.type === "response"
      ? {
          type: "response",
          id: exactId(message.id) || "invalid",
          ok: false,
          error: {
            code: "response_too_large",
            message: "provider response exceeds the bounded JSONL limit",
          },
        }
      : {
          type: "event",
          event: {
            event_id: exactId(message?.event?.event_id, 512) || "copilot-provider-frame-truncated",
            session_id: exactId(message?.event?.session_id, 512) || "copilot-sidecar",
            kind: "lifecycle",
            payload: { subtype: "provider_frame_truncated", status: "degraded" },
          },
        };
    encoded = encodedFrame(fallback);
  }
  process.stdout.write(encoded);
}

function errorEnvelope(error) {
  return {
    code: safeId(error?.code, 128) || "sidecar_error",
    message: redactErrorMessage(error),
  };
}

const input = createInterface({ input: process.stdin, crlfDelay: Infinity, terminal: false });
input.on("line", async (line) => {
  let message;
  try {
    if (Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES) throw new Error("sidecar request exceeds bound");
    message = JSON.parse(line);
    const result = await handle(message);
    emit({ type: "response", id: message.id, ok: true, result });
  } catch (error) {
    emit({ type: "response", id: exactId(message?.id) || "invalid", ok: false, error: errorEnvelope(error) });
  }
});

async function stop() {
  input.close();
  if (client) {
    try { await client.stop(); } catch {}
  }
  process.exit(0);
}
process.once("SIGTERM", () => { void stop(); });
process.once("SIGINT", () => { void stop(); });
