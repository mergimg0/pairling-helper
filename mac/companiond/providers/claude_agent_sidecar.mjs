// Pairling's reviewed local wrapper for @anthropic-ai/claude-agent-sdk.
// The daemon owns this child over bounded JSONL stdio. No dynamic SDK method,
// shell command, auth mutation, plugin/config mutation, or file-read escape is
// accepted by this protocol.

import { createHash, randomUUID } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const PROTOCOL_VERSION = 2;
const SDK_PACKAGE = "@anthropic-ai/claude-agent-sdk";
const SDK_VERSION = "0.3.220";
const CLAUDE_CODE_VERSION = "2.1.220";
const MAX_LINE_BYTES = 256 * 1024;
const MAX_TEXT = 16_384;
const SAFE_PERMISSION_MODES = new Set(["default", "plan"]);
const APPROVAL_TTL_MS = 2 * 60 * 1000;
const APPROVAL_PREVIEW_TRUNCATION = " [TRUNCATED: approval preview exceeded display limit]";
const QUESTION_TTL_MS = 10 * 60 * 1000;
const MAX_APPROVAL_PREVIEW_BYTES = 4096;
const require = createRequire(import.meta.url);

let sdk = null;
let sdkPackage = null;
let sdkLoadError = null;
let activeQuery = null;
let inputQueue = null;
let activeSessionId = null;
let activeProject = null;
let activeTitle = null;
let activeBindingId = null;
let initialization = null;
let systemCapabilities = new Set();
let currentModel = null;
let currentPermissionMode = "default";
let queryConsumer = null;
let queryActivation = null;
let expectedSessionId = null;
let logicalSessionClosed = false;
let sessionReadyResolve = null;
let sessionReadyReject = null;
let sessionReadyPromise = null;
let sessionInitialized = false;
let cachedQueryCapabilities = [];
let currentMcpServers = [];
const permissionWaiters = new Map();
const questionWaiters = new Map();
const preInitEvents = [];
const resolvedApprovalIds = new Set();

const SECRET_KEY = /(?:authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret|credential|private[_-]?key)/i;
const SECRET_PATTERNS = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  /\bsk-(?:ant-)?[A-Za-z0-9_-]{12,}/g,
  /\b[A-Z][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD)\s*=\s*[^\s]+/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
];

class InputQueue {
  constructor(initialMessage = null) {
    this.values = initialMessage
      ? [{ value: initialMessage, resolve: null, reject: null }]
      : [];
    this.waiters = [];
    this.closed = false;
  }

  [Symbol.asyncIterator]() {
    return this;
  }

  next() {
    if (this.values.length > 0) {
      const entry = this.values.shift();
      entry.resolve?.();
      return Promise.resolve({ value: entry.value, done: false });
    }
    if (this.closed) return Promise.resolve({ value: undefined, done: true });
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  push(value) {
    if (this.closed) {
      return Promise.reject(new Error("input queue is closed"));
    }
    const waiter = this.waiters.shift();
    if (waiter) {
      waiter({ value, done: false });
      return Promise.resolve();
    }
    return new Promise((resolve, reject) => {
      this.values.push({ value, resolve, reject });
    });
  }

  close() {
    this.closed = true;
    for (const entry of this.values.splice(0)) {
      entry.reject?.(new Error("input queue closed before delivery"));
    }
    for (const resolve of this.waiters.splice(0)) {
      resolve({ value: undefined, done: true });
    }
  }
}

async function loadSDK() {
  if (sdk) return;
  if (sdkLoadError) throw sdkLoadError;
  try {
    if (Number.parseInt(process.versions.node.split(".")[0], 10) < 18) {
      throw new Error("Node 18 or newer is required");
    }
    let entry;
    let manifest = null;
    let configuredEntry = null;
    const configuredRoot = process.env.PAIRLING_CLAUDE_AGENT_SDK_ROOT;
    if (configuredRoot) {
      if (!isAbsolute(configuredRoot) || lstatSync(configuredRoot).isSymbolicLink()) {
        throw new Error("PAIRLING_CLAUDE_AGENT_SDK_ROOT must be an absolute real package directory");
      }
      const packageRoot = realpathSync(resolve(configuredRoot));
      manifest = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8"));
      if (manifest?.name !== SDK_PACKAGE) throw new Error("configured package is not the Claude Agent SDK");
      const exportRow = manifest.exports?.["."];
      const relativeEntry = typeof exportRow === "string"
        ? exportRow
        : exportRow?.import || manifest.module || manifest.main || "sdk.mjs";
      configuredEntry = realpathSync(join(packageRoot, relativeEntry));
      if (!configuredEntry.startsWith(`${packageRoot}/`)) throw new Error("configured SDK entry escapes its package root");
      entry = configuredEntry;
    } else {
      entry = require.resolve(SDK_PACKAGE);
      let directory = dirname(entry);
      for (let depth = 0; depth < 6 && manifest === null; depth += 1) {
        try {
          const candidate = JSON.parse(readFileSync(join(directory, "package.json"), "utf8"));
          if (candidate?.name === SDK_PACKAGE) manifest = candidate;
        } catch {
          // Walk upward to the package root; package exports may hide package.json.
        }
        directory = dirname(directory);
      }
    }
    if (!manifest) throw new Error("Claude Agent SDK package metadata not found");
    if (manifest.version !== SDK_VERSION) {
      throw new Error(`Claude Agent SDK ${SDK_VERSION} required`);
    }
    if (manifest.claudeCodeVersion !== CLAUDE_CODE_VERSION) {
      throw new Error(`Claude Code ${CLAUDE_CODE_VERSION} required`);
    }
    sdkPackage = manifest;
    sdk = configuredEntry ? await import(pathToFileURL(configuredEntry).href) : await import(SDK_PACKAGE);
    if (typeof sdk.query !== "function") throw new Error("Claude Agent SDK query() is unavailable");
  } catch (error) {
    sdkLoadError = new Error(safeError(error));
    throw sdkLoadError;
  }
}

function safeError(error) {
  return bounded(error instanceof Error ? error.message : String(error), 300) || "provider unavailable";
}

function bounded(value, limit = MAX_TEXT) {
  const text = String(value ?? "").replaceAll("\0", "");
  if (text.length <= limit) return text;
  return `${text.slice(0, Math.max(0, limit - 16))}…[truncated]`;
}

function historyLabel(value, fallback = "unknown", limit = 160) {
  if (typeof value !== "string") return fallback;
  const label = bounded(value, limit);
  return /^[A-Za-z0-9_.:-]+$/.test(label) ? label : fallback;
}

function historyMessageDTO(row, ordinal) {
  if (!row || typeof row !== "object" || Array.isArray(row)) return null;
  const message = row.message && typeof row.message === "object" && !Array.isArray(row.message)
    ? row.message
    : null;
  const content = Array.isArray(message?.content) ? message.content : [];
  const contentCounts = {
    text_blocks: 0,
    tool_use_blocks: 0,
    tool_result_blocks: 0,
    other_blocks: 0,
  };
  for (const block of content.slice(0, 256)) {
    const type = block && typeof block === "object" && !Array.isArray(block)
      ? block.type
      : null;
    if (type === "text") contentCounts.text_blocks += 1;
    else if (type === "tool_use") contentCounts.tool_use_blocks += 1;
    else if (type === "tool_result") contentCounts.tool_result_blocks += 1;
    else contentCounts.other_blocks += 1;
  }
  const dto = {
    ordinal,
    type: historyLabel(row.type || row.kind),
    subtype: historyLabel(row.subtype, "", 160),
    role: ["user", "assistant", "system", "tool"].includes(message?.role)
      ? message.role
      : "",
    content_counts: contentCounts,
    is_error: row.is_error === true,
  };
  const messageId = row.uuid || row.id || row.message_id || row.messageId;
  if (
    typeof messageId === "string"
    && messageId.length <= 256
    && /^[A-Za-z0-9_.:-]+$/.test(messageId)
  ) {
    dto.message_id = messageId;
  }
  const timestamp = row.timestamp || row.created_at || row.createdAt;
  if (
    (typeof timestamp === "number" && Number.isFinite(timestamp))
    || (
      typeof timestamp === "string"
      && timestamp.length <= 64
      && Number.isFinite(Date.parse(timestamp))
    )
  ) {
    dto.timestamp = timestamp;
  }
  const stopReason = message?.stop_reason || row.stop_reason || row.stopReason;
  if (typeof stopReason === "string") {
    dto.stop_reason = historyLabel(stopReason, "", 80);
  }
  return dto;
}

export function projectHistoryMessages(messages) {
  if (!Array.isArray(messages)) return [];
  const rows = [];
  const sliced = messages.slice(-100);
  for (let index = 0; index < sliced.length; index += 1) {
    const row = historyMessageDTO(sliced[index], messages.length - sliced.length + index);
    if (row) rows.push(row);
  }
  return rows;
}

function canonicalJSON(value, seen = new Set(), depth = 0) {
  if (depth > 64) throw new Error("tool input nesting exceeds the reviewed limit");
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("tool input contains a non-finite number");
    return Object.is(value, -0) ? "0" : JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value !== "object") throw new Error("tool input contains an unsupported value");
  if (seen.has(value)) throw new Error("tool input contains a cycle");
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const ownKeys = Reflect.ownKeys(value);
      if (
        ownKeys.some((key) => typeof key !== "string")
        || ownKeys.length !== value.length + 1
        || !ownKeys.includes("length")
      ) {
        throw new Error("tool input array contains hidden or extra values");
      }
      const items = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
          throw new Error("tool input array contains a hole or accessor");
        }
        items.push(canonicalJSON(descriptor.value, seen, depth + 1));
      }
      return `[${items.join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error("tool input contains a non-JSON object");
    }
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) {
      throw new Error("tool input contains a symbol key");
    }
    keys.sort();
    const entries = [];
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
        throw new Error("tool input contains a hidden value or accessor");
      }
      entries.push(`${JSON.stringify(key)}:${canonicalJSON(descriptor.value, seen, depth + 1)}`);
    }
    return `{${entries.join(",")}}`;
  } finally {
    seen.delete(value);
  }
}

function redactedCanonicalJSON(value, state, key = "", depth = 0) {
  if (SECRET_KEY.test(key)) {
    state.redacted = true;
    return JSON.stringify("[REDACTED:SECRET_VALUE]");
  }
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return canonicalJSON(value, new Set(), depth);
  }
  if (typeof value === "string") {
    let text = value;
    for (const pattern of SECRET_PATTERNS) {
      text = text.replace(pattern, () => {
        state.redacted = true;
        return "[REDACTED:SECRET_TEXT]";
      });
    }
    return JSON.stringify(text);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => redactedCanonicalJSON(item, state, "", depth + 1)).join(",")}]`;
  }
  const entries = Object.keys(value)
    .sort()
    .map((itemKey) => (
      `${JSON.stringify(itemKey)}:${redactedCanonicalJSON(value[itemKey], state, itemKey, depth + 1)}`
    ));
  return `{${entries.join(",")}}`;
}

function semanticInputLabel(key) {
  return {
    command: "Command",
    cmd: "Command",
    cwd: "Working directory",
    path: "Path",
    file_path: "File path",
    filepath: "File path",
    old_string: "Before",
    new_string: "After",
    patch: "Patch",
    diff: "Delta",
    delta: "Delta",
    content: "Content",
  }[key.toLowerCase()] || "Input";
}

function boundApprovalPreview(text) {
  if (Buffer.byteLength(text, "utf8") <= MAX_APPROVAL_PREVIEW_BYTES) {
    return { preview: text, truncated: false };
  }
  const budget = MAX_APPROVAL_PREVIEW_BYTES
    - Buffer.byteLength(APPROVAL_PREVIEW_TRUNCATION, "utf8");
  let low = 0;
  let high = text.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    const candidate = text.slice(0, middle);
    if (Buffer.byteLength(candidate, "utf8") <= budget) low = middle;
    else high = middle - 1;
  }
  let prefix = text.slice(0, low);
  if (prefix && /[\uD800-\uDBFF]/.test(prefix.at(-1))) prefix = prefix.slice(0, -1);
  while (prefix && Buffer.byteLength(prefix, "utf8") > budget) {
    prefix = prefix.slice(0, -1);
  }
  return {
    preview: `${prefix}${APPROVAL_PREVIEW_TRUNCATION}`,
    truncated: true,
  };
}

function bindToolInput(input) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("tool input is not a JSON object");
  }
  const canonical = canonicalJSON(input);
  const approvalDigest = createHash("sha256").update(canonical, "utf8").digest("hex");
  const redaction = { redacted: false };
  const keys = Object.keys(input).sort();
  const rendered = keys.length === 0
    ? "Input — input: {}"
    : keys.map((key) => (
        `${semanticInputLabel(key)} — ${JSON.stringify(key)}: `
        + redactedCanonicalJSON(input[key], redaction, key)
      )).join("; ");
  const boundedPreview = boundApprovalPreview(rendered);
  return {
    approvalDigest,
    preview: boundedPreview.preview,
    redacted: redaction.redacted,
    truncated: boundedPreview.truncated,
  };
}

function rememberResolvedApproval(approvalId) {
  resolvedApprovalIds.add(approvalId);
  while (resolvedApprovalIds.size > 1024) {
    resolvedApprovalIds.delete(resolvedApprovalIds.values().next().value);
  }
}

function releaseWaiter(approvalId, waiter) {
  if (permissionWaiters.get(approvalId) !== waiter) return false;
  permissionWaiters.delete(approvalId);
  rememberResolvedApproval(approvalId);
  clearTimeout(waiter.expiryTimer);
  waiter.signal?.removeEventListener?.("abort", waiter.abort);
  return true;
}

function denyWaiter(approvalId, waiter, message, { publish = true } = {}) {
  if (!releaseWaiter(approvalId, waiter)) return false;
  waiter.resolve({ behavior: "deny", message, toolUseID: waiter.toolUseId });
  if (publish) {
    event("permission.resolved", {
      approval_id: approvalId,
      tool_use_id: waiter.toolUseId,
      approval_digest: waiter.approvalDigest,
      decision: "deny",
    }, `${approvalId}:resolved`);
  }
  return true;
}

function releaseQuestionWaiter(questionRequestId, waiter) {
  if (questionWaiters.get(questionRequestId) !== waiter) return false;
  questionWaiters.delete(questionRequestId);
  clearTimeout(waiter.expiryTimer);
  waiter.signal?.removeEventListener?.("abort", waiter.abort);
  return true;
}

function denyQuestionWaiter(questionRequestId, waiter, message) {
  if (!releaseQuestionWaiter(questionRequestId, waiter)) return false;
  waiter.resolve({
    behavior: "deny",
    message,
    toolUseID: waiter.toolUseId,
  });
  event("question.resolved", {
    question_request_id: questionRequestId,
    tool_use_id: waiter.toolUseId,
    question_digest: waiter.questionDigest,
    decision: "deny",
  }, `${questionRequestId}:resolved`);
  return true;
}

function bindQuestionInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("AskUserQuestion input is not an object");
  }
  const source = input.questions;
  if (!Array.isArray(source) || source.length < 1 || source.length > 4) {
    throw new Error("AskUserQuestion must contain one to four questions");
  }
  const questions = source.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error("AskUserQuestion question is malformed");
    }
    const question = bounded(item.question, 10_000);
    const topic = bounded(item.header, 160);
    if (!question || !topic || item.multiSelect === true) {
      throw new Error("AskUserQuestion requires single-select titled questions");
    }
    if (!Array.isArray(item.options) || item.options.length < 2 || item.options.length > 4) {
      throw new Error("AskUserQuestion options are malformed");
    }
    const options = item.options.map((option) => {
      if (!option || typeof option !== "object" || Array.isArray(option)) {
        throw new Error("AskUserQuestion option is malformed");
      }
      const label = bounded(option.label, 512);
      if (!label) throw new Error("AskUserQuestion option label is empty");
      return label;
    });
    if (new Set(options).size !== options.length) {
      throw new Error("AskUserQuestion option labels must be unique");
    }
    return {
      index: index + 1,
      topic,
      question,
      options,
      answer: "",
    };
  });
  if (new Set(questions.map((item) => item.question)).size !== questions.length) {
    throw new Error("AskUserQuestion question text must be unique");
  }
  return {
    questions,
    questionDigest: createHash("sha256").update(canonicalJSON(input), "utf8").digest("hex"),
  };
}

function sanitize(value, depth = 0) {
  if (depth > 8) return "[truncated]";
  if (value === null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string") {
    let text = bounded(value);
    for (const pattern of SECRET_PATTERNS) text = text.replace(pattern, "[REDACTED]");
    return text;
  }
  if (Array.isArray(value)) return value.slice(0, 128).map((item) => sanitize(item, depth + 1));
  if (typeof value === "object" && value !== null) {
    const output = {};
    for (const [rawKey, item] of Object.entries(value).slice(0, 128)) {
      const key = bounded(rawKey, 160);
      if (!key) continue;
      output[key] = SECRET_KEY.test(key) ? "[REDACTED]" : sanitize(item, depth + 1);
    }
    return output;
  }
  return bounded(value, 500);
}

function writeFrame(frame) {
  let encoded = `${JSON.stringify(sanitize(frame))}\n`;
  if (Buffer.byteLength(encoded, "utf8") > MAX_LINE_BYTES) {
    const fallback = frame?.type === "response"
      ? {
          type: "response",
          id: typeof frame.id === "string" ? frame.id : "invalid",
          ok: false,
          error: { code: "response_too_large", message: "provider response exceeds the bounded JSONL limit" },
        }
      : {
          type: "event",
          event: {
            event_id: randomUUID(),
            session_id: activeSessionId,
            kind: "lifecycle",
            payload: { subtype: "provider_frame_truncated", status: "degraded" },
          },
        };
    encoded = `${JSON.stringify(fallback)}\n`;
  }
  process.stdout.write(encoded);
}

function reply(request, result = {}) {
  writeFrame({ type: "response", id: request.id, ok: true, result });
}

function reject(request, code, message) {
  writeFrame({
    type: "response",
    id: typeof request?.id === "string" ? request.id : "invalid",
    ok: false,
    error: { code: bounded(code, 96), message: bounded(message, 300) },
  });
}

function event(kind, payload = {}, eventId = randomUUID()) {
  const pending = {
    event_id: bounded(eventId, 256),
    kind,
    payload,
  };
  if (!activeSessionId) {
    if (preInitEvents.length < 64) preInitEvents.push(pending);
    return;
  }
  writeFrame({
    type: "event",
    event: {
      ...pending,
      session_id: activeSessionId,
    },
  });
}

function exactFields(request, fields) {
  if (!request || typeof request !== "object" || Array.isArray(request)) throw new Error("request must be an object");
  if (typeof request.id !== "string" || !request.id || request.id.length > 256) throw new Error("invalid request id");
  const allowed = new Set(["id", "op", ...fields]);
  for (const key of Object.keys(request)) {
    if (!allowed.has(key)) throw new Error(`unreviewed input: ${key}`);
  }
  for (const key of fields) {
    if (!(key in request)) throw new Error(`missing input: ${key}`);
  }
}

function requiredText(request, key, limit) {
  const value = request[key];
  if (typeof value !== "string" || !value || value.length > limit || value.includes("\0")) {
    throw new Error(`invalid ${key}`);
  }
  return value;
}

function optionalText(request, key, limit) {
  const value = request[key];
  if (typeof value !== "string" || value.length > limit || value.includes("\0")) {
    throw new Error(`invalid ${key}`);
  }
  return value;
}

async function requireSession(request) {
  const value = requiredText(request, "session_id", 256);
  if (value !== activeSessionId) throw new Error("stale session binding");
  const query = await ensureActiveQuery();
  if (value !== activeSessionId) throw new Error("stale session binding");
  return query;
}

function userMessage(text, sessionId = activeSessionId) {
  return {
    type: "user",
    message: { role: "user", content: text },
    parent_tool_use_id: null,
    uuid: randomUUID(),
    ...(sessionId ? { session_id: sessionId } : {}),
  };
}


function resetSessionReady() {
  sessionReadyPromise = new Promise((resolve, rejectPromise) => {
    sessionReadyResolve = resolve;
    sessionReadyReject = rejectPromise;
  });
  return sessionReadyPromise;
}

async function waitForSessionReady(ready) {
  let timer = null;
  try {
    return await Promise.race([
      ready,
      new Promise((_, rejectPromise) => {
        timer = setTimeout(
          () => rejectPromise(new Error("session initialization timed out")),
          20_000,
        );
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
}

function queryOptions({ resumeSessionId = null, newSessionId = null } = {}) {
  return {
    cwd: activeProject,
    title: activeTitle || undefined,
    permissionMode: currentPermissionMode,
    includePartialMessages: true,
    enableFileCheckpointing: true,
    canUseTool,
    ...(resumeSessionId ? { resume: resumeSessionId } : {}),
    ...(newSessionId ? { sessionId: newSessionId } : {}),
  };
}

async function activateQuery({
  firstPrompt = "",
  resumeSessionId = null,
  newSessionId = null,
} = {}) {
  if (resumeSessionId && newSessionId) {
    throw new Error("Claude SDK query identity is ambiguous");
  }
  const requiredSessionId = resumeSessionId || newSessionId;
  const deferredInitialization = Boolean(newSessionId && !firstPrompt);
  const ready = resetSessionReady();
  sessionInitialized = false;
  expectedSessionId = requiredSessionId;
  if (newSessionId) currentMcpServers = [];
  const queue = new InputQueue(
    firstPrompt ? userMessage(firstPrompt, requiredSessionId) : null,
  );
  const query = sdk.query({
    prompt: queue,
    options: queryOptions({ resumeSessionId, newSessionId }),
  });
  cachedQueryCapabilities = reviewedQueryCapabilities(query);
  inputQueue = queue;
  activeQuery = query;
  queryConsumer = consumeQuery(query);
  try {
    initialization = await query.initializationResult();
    if (newSessionId) {
      if (activeSessionId && activeSessionId !== newSessionId) {
        throw new Error("new SDK session identity changed");
      }
      activeSessionId = newSessionId;
    }
    if (deferredInitialization) {
      // The SDK resolves control initialization before it emits system/init.
      // Keep the one query input stream open until a real user prompt arrives.
      ready.catch(() => {});
      return query;
    }
    const nativeId = await waitForSessionReady(ready);
    if (typeof nativeId !== "string" || !nativeId) {
      throw new Error("SDK did not return a session id");
    }
    if (requiredSessionId && nativeId !== requiredSessionId) {
      throw new Error("resumed SDK session identity changed");
    }
    return query;
  } catch (error) {
    queue.close();
    query.close();
    if (activeQuery === query) activeQuery = null;
    if (newSessionId && activeSessionId === newSessionId && !sessionInitialized) {
      activeSessionId = null;
    }
    throw error;
  } finally {
    expectedSessionId = null;
  }
}

async function ensureActiveQuery() {
  if (logicalSessionClosed) throw new Error("Claude SDK session is closed");
  if (activeQuery) return activeQuery;
  if (!activeSessionId || !activeProject || !activeBindingId) {
    throw new Error("Claude SDK session is unavailable");
  }
  if (!queryActivation) {
    const resumeSessionId = activeSessionId;
    queryActivation = activateQuery({ resumeSessionId }).finally(() => {
      queryActivation = null;
    });
  }
  await queryActivation;
  if (!activeQuery || activeSessionId === null) {
    throw new Error("Claude SDK session resume failed");
  }
  return activeQuery;
}

async function requestClaudeQuestions(input, options, questionRequestId, toolUseId) {
  if (!activeSessionId || !activeBindingId) {
    return {
      behavior: "deny",
      message: "Question request is not session-bound",
      toolUseID: toolUseId,
    };
  }
  let binding;
  try {
    binding = bindQuestionInput(input);
  } catch (error) {
    event("question.rejected", {
      question_request_id: questionRequestId,
      tool_use_id: toolUseId,
      reason: safeError(error),
    }, `${questionRequestId}:rejected`);
    return {
      behavior: "deny",
      message: "Question request is not supported by Pairling",
      toolUseID: toolUseId,
    };
  }
  const current = questionWaiters.get(questionRequestId);
  if (current) {
    if (
      current.sessionId === activeSessionId
      && current.bindingId === activeBindingId
      && current.toolUseId === toolUseId
      && current.questionDigest === binding.questionDigest
    ) {
      return current.promise;
    }
    denyQuestionWaiter(
      questionRequestId,
      current,
      "Question request identity was reused",
    );
    return {
      behavior: "deny",
      message: "Question request identity was reused",
      toolUseID: toolUseId,
    };
  }
  let resolveAnswer;
  const promise = new Promise((resolve) => {
    resolveAnswer = resolve;
  });
  const expiresAt = Date.now() + QUESTION_TTL_MS;
  const waiter = {
    promise,
    resolve: resolveAnswer,
    sessionId: activeSessionId,
    bindingId: activeBindingId,
    toolUseId,
    questionDigest: binding.questionDigest,
    questions: binding.questions,
    input,
    expiresAt,
    signal: options?.signal,
    abort: null,
    expiryTimer: null,
  };
  waiter.abort = () => {
    denyQuestionWaiter(
      questionRequestId,
      waiter,
      "Question request was cancelled",
    );
  };
  waiter.expiryTimer = setTimeout(() => {
    denyQuestionWaiter(
      questionRequestId,
      waiter,
      "Question request expired",
    );
  }, QUESTION_TTL_MS);
  questionWaiters.set(questionRequestId, waiter);
  options?.signal?.addEventListener?.("abort", waiter.abort, { once: true });
  event("question.requested", {
    question_request_id: questionRequestId,
    tool_use_id: toolUseId,
    question_digest: binding.questionDigest,
    binding_id: activeBindingId,
    questions: binding.questions,
    expires_at: Math.floor(expiresAt / 1000),
  }, questionRequestId);
  return promise;
}

async function canUseTool(toolName, input, options) {
  const approvalId = requiredCallbackText(options?.requestId, "requestId");
  const toolUseId = requiredCallbackText(options?.toolUseID, "toolUseID");
  if (toolName === "AskUserQuestion") {
    return requestClaudeQuestions(input, options, approvalId, toolUseId);
  }
  if (resolvedApprovalIds.has(approvalId)) {
    return { behavior: "deny", message: "Permission request was already resolved", toolUseID: toolUseId };
  }
  if (!activeSessionId || !activeBindingId) {
    rememberResolvedApproval(approvalId);
    return { behavior: "deny", message: "Permission request is not session-bound", toolUseID: toolUseId };
  }
  let binding;
  try {
    binding = bindToolInput(input);
  } catch {
    event("permission.rejected", {
      approval_id: approvalId,
      tool_use_id: toolUseId,
      reason: "input_unrenderable",
    }, `${approvalId}:rejected`);
    rememberResolvedApproval(approvalId);
    return { behavior: "deny", message: "Tool input could not be bound exactly", toolUseID: toolUseId };
  }
  const current = permissionWaiters.get(approvalId);
  if (current) {
    if (
      current.sessionId === activeSessionId
      && current.bindingId === activeBindingId
      && current.toolUseId === toolUseId
      && current.approvalDigest === binding.approvalDigest
    ) {
      return current.promise;
    }
    denyWaiter(approvalId, current, "Permission request identity was reused");
    return { behavior: "deny", message: "Permission request identity was reused", toolUseID: toolUseId };
  }
  let resolveDecision;
  const promise = new Promise((resolve) => {
    resolveDecision = resolve;
  });
  const expiresAt = Date.now() + APPROVAL_TTL_MS;
  const waiter = {
    promise,
    resolve: resolveDecision,
    sessionId: activeSessionId,
    bindingId: activeBindingId,
    toolUseId,
    approvalDigest: binding.approvalDigest,
    input,
    allowSafe: !binding.truncated,
    expiresAt,
    signal: options?.signal,
    abort: null,
    expiryTimer: null,
  };
  waiter.abort = () => {
    denyWaiter(approvalId, waiter, "Permission request was cancelled");
  };
  waiter.expiryTimer = setTimeout(() => {
    denyWaiter(approvalId, waiter, "Permission request expired");
  }, APPROVAL_TTL_MS);
  waiter.expiryTimer.unref?.();
  permissionWaiters.set(approvalId, waiter);
  options?.signal?.addEventListener?.("abort", waiter.abort, { once: true });
  event("permission.request", {
    approval_id: approvalId,
    tool_use_id: toolUseId,
    approval_digest: binding.approvalDigest,
    binding_id: activeBindingId,
    tool_name: bounded(toolName, 160),
    title: bounded(options?.title || options?.displayName || `Use ${toolName}`, 500),
    description: bounded(options?.description || options?.decisionReason || "Approval required", 1000),
    input_preview: binding.preview,
    input_redacted: binding.redacted,
    input_truncated: binding.truncated,
    input_renderable: true,
    expires_at: Math.floor(expiresAt / 1000),
    persistent_permission_changes_available: false,
  }, approvalId);
  return promise;
}

function requiredCallbackText(value, name) {
  if (typeof value !== "string" || !value || value.length > 256) throw new Error(`invalid ${name}`);
  return value;
}

async function consumeQuery(query) {
  try {
    for await (const message of query) normalizeSDKMessage(message);
  } catch (error) {
    if (activeSessionId) {
      event("lifecycle", { subtype: "sdk_stream_error", status: "unavailable", reason: safeError(error) });
    }
    sessionReadyReject?.(new Error(safeError(error)));
  } finally {
    if (activeQuery === query) {
      activeQuery = null;
      inputQueue?.close();
      inputQueue = null;
      for (const [approvalId, waiter] of permissionWaiters) {
        denyWaiter(approvalId, waiter, "Claude query returned");
      }
      for (const [questionRequestId, waiter] of questionWaiters) {
        denyQuestionWaiter(
          questionRequestId,
          waiter,
          "Claude query returned",
        );
      }
      if (!activeSessionId) preInitEvents.length = 0;
      if (activeSessionId) {
        event("lifecycle", {
          subtype: logicalSessionClosed ? "session_closed" : "query_returned",
          status: logicalSessionClosed ? "closed" : "waiting",
        });
      }
    }
  }
}

function normalizeSDKMessage(message) {
  if (!message || typeof message !== "object") {
    event("lifecycle", { subtype: "unknown_sdk_message" });
    return;
  }
  if (message.type === "system" && message.subtype === "init") {
    const candidateSessionId = typeof message.session_id === "string" && message.session_id
      ? message.session_id
      : null;
    const requiredSessionId = expectedSessionId || activeSessionId;
    if (!candidateSessionId || (requiredSessionId && candidateSessionId !== requiredSessionId)) {
      const error = new Error("Claude SDK session identity changed");
      sessionReadyReject?.(error);
      throw error;
    }
    activeSessionId = candidateSessionId;
    sessionInitialized = true;
    for (const pending of preInitEvents.splice(0)) {
      writeFrame({
        type: "event",
        event: { ...pending, session_id: activeSessionId },
      });
    }
    if (Array.isArray(message.capabilities)) {
      systemCapabilities = new Set(message.capabilities.filter((item) => typeof item === "string"));
    }
    if (Array.isArray(message.mcp_servers)) currentMcpServers = message.mcp_servers;
    if (typeof message.model === "string") currentModel = message.model;
    if (typeof message.permissionMode === "string") currentPermissionMode = message.permissionMode;
    sessionReadyResolve?.(activeSessionId);
    event("lifecycle", {
      subtype: "session_initialized",
      status: "ready",
      model: currentModel,
      permission_mode: currentPermissionMode,
      capabilities: [...systemCapabilities].slice(0, 128),
    }, bounded(message.uuid || randomUUID(), 256));
    return;
  }
  if (message.type === "system" && message.subtype === "commands_changed") {
    if (Array.isArray(message.commands) && initialization) {
      initialization = { ...initialization, commands: message.commands };
    }
    event("lifecycle", {
      subtype: "commands_changed",
      status: "updated",
    }, message.uuid);
    return;
  }
  if (message.type === "stream_event") {
    const delta = message.event?.delta;
    if (typeof delta?.text === "string") event("stream_delta", { text: delta.text, role: "assistant" }, message.uuid);
    else if (typeof delta?.thinking === "string") event("thinking", { text: delta.thinking, role: "assistant" }, message.uuid);
    else event("lifecycle", { subtype: "stream_event" }, message.uuid);
    return;
  }
  if (message.type === "assistant") {
    const blocks = Array.isArray(message.message?.content) ? message.message.content : [];
    for (const block of blocks) {
      if (block?.type === "text" && typeof block.text === "string") {
        event("assistant_message", { text: block.text, role: "assistant" }, message.uuid);
      } else if (block?.type === "thinking" && typeof block.thinking === "string") {
        event("thinking", { text: block.thinking, role: "assistant" }, message.uuid);
      } else if (block?.type === "tool_use") {
        event("tool_use", {
          name: bounded(block.name, 160),
          call_id: bounded(block.id, 256),
          input: sanitize(block.input),
        }, block.id || message.uuid);
      }
    }
    return;
  }
  if (message.type === "user") {
    const blocks = Array.isArray(message.message?.content) ? message.message.content : [];
    for (const block of blocks) {
      if (block?.type === "tool_result") {
        event("tool_result", {
          call_id: bounded(block.tool_use_id, 256),
          content: sanitize(block.content),
          is_error: Boolean(block.is_error),
        }, message.uuid);
      } else if (typeof block === "string") {
        event("message", { text: block, role: "user" }, message.uuid);
      }
    }
    return;
  }
  if (message.type === "result") {
    event("lifecycle", {
      subtype: "turn_result",
      status: message.subtype === "success" ? "completed" : "failed",
      reason: typeof message.result === "string" ? message.result : undefined,
      total_cost_usd: typeof message.total_cost_usd === "number" ? message.total_cost_usd : undefined,
    }, message.uuid);
    return;
  }
  if (typeof message.type === "string" && message.type.startsWith("hook_")) {
    event("lifecycle", {
      subtype: `telemetry.${bounded(message.type, 80)}`,
      supplementary: true,
      status: bounded(message.status || message.type, 128),
    }, message.uuid || message.hook_id);
    return;
  }
  if (
    message.type === "system"
    && typeof message.subtype === "string"
    && message.subtype.startsWith("hook_")
  ) {
    event("lifecycle", {
      subtype: `telemetry.${bounded(message.subtype, 80)}`,
      supplementary: true,
      status: bounded(message.status || message.subtype, 128),
    }, message.uuid || message.hook_id);
    return;
  }
  if (
    message.type === "system"
    && typeof message.subtype === "string"
    && (message.subtype.startsWith("task_") || message.subtype === "background_tasks_changed")
  ) {
    event("lifecycle", {
      subtype: bounded(message.subtype, 96),
      status: bounded(message.status || message.patch?.status || "updated", 128),
      task_id: bounded(message.task_id, 256),
      summary: bounded(message.summary || message.description || "", 1000),
      active_task_count: Array.isArray(message.tasks) ? message.tasks.length : undefined,
    }, message.uuid || message.task_id);
    return;
  }
  if (message.type === "system" && message.subtype === "permission_denied") {
    event("lifecycle", {
      subtype: "permission_denied",
      status: "denied",
      tool_name: bounded(message.tool_name, 160),
      tool_use_id: bounded(message.tool_use_id, 256),
    }, message.uuid || message.tool_use_id);
    return;
  }
  event("lifecycle", {
    subtype: bounded(message.subtype || message.type || "sdk_message", 96),
    status: bounded(message.status || message.subtype || "updated", 128),
  }, message.uuid || message.id);
}

function reviewedQueryCapabilities(query) {
  const capabilities = [];
  const methods = [
    ["streamInput", "stream_input"],
    ["interrupt", "interrupt"],
    ["close", "close"],
    ["setModel", "set_model"],
    ["setPermissionMode", "set_permission_mode"],
    ["supportedCommands", "supported_commands"],
    ["supportedModels", "supported_models"],
    ["supportedAgents", "provider.agents.read"],
    ["mcpServerStatus", "mcp_status"],
    ["reconnectMcpServer", "provider.mcp.reconnect"],
    ["toggleMcpServer", "provider.mcp.set_enabled"],
    ["getContextUsage", "session.context.read"],
    ["accountInfo", "account_info"],
    ["initializationResult", "provider.status.read"],
    ["rewindFiles", "rewind_files"],
  ];
  for (const [method, capability] of methods) {
    if (typeof query?.[method] === "function") capabilities.push(capability);
  }
  if (typeof sdk.getSessionMessages === "function") capabilities.push("session.history.read");
  capabilities.push("ask_user_question");
  return capabilities;
}

async function discovery() {
  if (!activeSessionId || !initialization) {
    throw new Error("Claude SDK session is not initialized");
  }
  const commands = Array.isArray(initialization.commands) ? initialization.commands : [];
  const models = Array.isArray(initialization.models) ? initialization.models : [];
  const agents = Array.isArray(initialization.agents) ? initialization.agents : [];
  const mcp = Array.isArray(currentMcpServers) ? currentMcpServers : [];
  return {
    native_session_id: activeSessionId,
    capabilities: cachedQueryCapabilities,
    models: models.map((row) => ({
      value: bounded(row.value, 256),
      display_name: bounded(row.displayName || row.value, 500),
    })),
    commands: commands.map((row) => ({
      name: bounded(row.name, 256),
      description: bounded(row.description || row.name, 500),
      argument_hint: bounded(row.argumentHint || "", 500),
      aliases: Array.isArray(row.aliases) ? row.aliases.slice(0, 32).map((item) => bounded(item, 128)) : [],
    })),
    agents: agents.map((row) => ({
      name: bounded(row.name, 256),
      description: bounded(row.description || row.name, 500),
      model: bounded(row.model || "", 256),
    })),
    mcp_servers: mcp.map((row) => ({ name: bounded(row.name, 256), status: row.status })),
    permission_modes: ["default", "plan"],
    status: {
      model: currentModel,
      permission_mode: currentPermissionMode,
      sdk_version: SDK_VERSION,
      claude_code_version: CLAUDE_CODE_VERSION,
    },
  };
}

async function streamText(text) {
  await ensureActiveQuery();
  const ready = sessionInitialized ? null : sessionReadyPromise;
  const queue = inputQueue;
  if (!queue) throw new Error("Claude SDK input stream is unavailable");
  const message = userMessage(text);
  await queue.push(message);
  if (ready) {
    const nativeId = await waitForSessionReady(ready);
    if (nativeId !== activeSessionId) {
      throw new Error("Claude SDK session identity changed");
    }
  }
  return message.uuid;
}

function operationId(request, prefix) {
  return `${prefix}:${activeSessionId || "provider"}:${requiredText(request, "client_action_id", 512)}`;
}

async function handle(request) {
  if (!request || typeof request !== "object" || Array.isArray(request) || typeof request.op !== "string") {
    reject(request, "invalid_input", "request must include a reviewed operation");
    return;
  }
  try {
    switch (request.op) {
      case "handshake": {
        exactFields(request, ["protocol_version"]);
        if (request.protocol_version !== PROTOCOL_VERSION) throw new Error("unsupported protocol version");
        await loadSDK();
        reply(request, {
          protocol_version: PROTOCOL_VERSION,
          sdk_package: SDK_PACKAGE,
          sdk_version: sdkPackage.version,
          claude_code_version: sdkPackage.claudeCodeVersion,
          node_version: process.versions.node,
        });
        return;
      }
      case "launch": {
        exactFields(request, ["project", "title", "first_prompt", "binding_id"]);
        await loadSDK();
        if (activeQuery || activeSessionId) throw new Error("sidecar already owns a Claude session");
        activeProject = requiredText(request, "project", 4096);
        activeBindingId = requiredText(request, "binding_id", 256);
        activeTitle = optionalText(request, "title", 500);
        const firstPrompt = optionalText(request, "first_prompt", 200_000);
        currentPermissionMode = "default";
        logicalSessionClosed = false;
        const reservedSessionId = randomUUID();
        const query = await activateQuery({
          firstPrompt,
          newSessionId: reservedSessionId,
        });
        const nativeId = activeSessionId;
        if (!query || typeof nativeId !== "string" || !nativeId) {
          throw new Error("SDK did not return a session id");
        }
        reply(request, { native_session_id: nativeId, provider_operation_id: `launch:${nativeId}` });
        return;
      }
      case "discover": {
        exactFields(request, []);
        reply(request, await discovery());
        return;
      }
      case "prompt": {
        exactFields(request, ["session_id", "prompt", "client_action_id"]);
        await requireSession(request);
        const messageUuid = await streamText(requiredText(request, "prompt", 200_000));
        reply(request, { accepted: true, message_uuid: messageUuid, provider_operation_id: operationId(request, "prompt") });
        return;
      }
      case "steer": {
        exactFields(request, ["session_id", "instruction", "client_action_id"]);
        await requireSession(request);
        const messageUuid = await streamText(requiredText(request, "instruction", 200_000));
        reply(request, { accepted: true, message_uuid: messageUuid, provider_operation_id: operationId(request, "steer") });
        return;
      }
      case "interrupt": {
        exactFields(request, ["session_id", "client_action_id"]);
        const query = await requireSession(request);
        const receipt = await query.interrupt();
        reply(request, {
          still_queued: Array.isArray(receipt?.still_queued) ? receipt.still_queued : [],
          cancelled: Array.isArray(receipt?.cancelled) ? receipt.cancelled : [],
          provider_operation_id: operationId(request, "interrupt"),
        });
        return;
      }
      case "terminate": {
        exactFields(request, ["session_id", "client_action_id"]);
        const query = await requireSession(request);
        const providerOperationId = operationId(request, "terminate");
        logicalSessionClosed = true;
        for (const [approvalId, waiter] of permissionWaiters) {
          denyWaiter(approvalId, waiter, "Claude session terminated");
        }
        for (const [questionRequestId, waiter] of questionWaiters) {
          denyQuestionWaiter(
            questionRequestId,
            waiter,
            "Claude session terminated",
          );
        }
        inputQueue?.close();
        query.close();
        reply(request, { terminated: true, provider_operation_id: providerOperationId });
        return;
      }
      case "compact": {
        exactFields(request, ["session_id", "client_action_id"]);
        await requireSession(request);
        const commands = await activeQuery.supportedCommands();
        const supported = commands.some((row) => row.name?.replace(/^\//, "").toLowerCase() === "compact"
          || row.aliases?.some((alias) => alias.replace(/^\//, "").toLowerCase() === "compact"));
        if (!supported) throw new Error("compact command is not advertised by this session");
        const messageUuid = await streamText("/compact");
        reply(request, { accepted: true, message_uuid: messageUuid, provider_operation_id: operationId(request, "compact") });
        return;
      }
      case "rewind": {
        exactFields(request, ["session_id", "message_id", "client_action_id"]);
        await requireSession(request);
        const messageId = requiredText(request, "message_id", 256);
        const dryRun = await activeQuery.rewindFiles(messageId, { dryRun: true });
        if (!dryRun?.canRewind) throw new Error(bounded(dryRun?.error || "rewind dry-run rejected", 300));
        const applied = await activeQuery.rewindFiles(messageId, { dryRun: false });
        reply(request, {
          dry_run: dryRun,
          applied,
          provider_operation_id: operationId(request, "rewind"),
        });
        return;
      }
      case "set_model": {
        exactFields(request, ["session_id", "model", "client_action_id"]);
        await requireSession(request);
        const model = requiredText(request, "model", 256);
        const models = await activeQuery.supportedModels();
        if (!models.some((row) => row.value === model)) throw new Error("model is not in the live SDK catalog");
        await activeQuery.setModel(model);
        currentModel = model;
        reply(request, { model, provider_operation_id: operationId(request, "model") });
        return;
      }
      case "set_permission_mode": {
        exactFields(request, ["session_id", "mode", "client_action_id"]);
        await requireSession(request);
        const mode = requiredText(request, "mode", 64);
        if (!SAFE_PERMISSION_MODES.has(mode)) {
          reject(request, "safe_mode_required", "permission mode is not approved for remote control");
          return;
        }
        await activeQuery.setPermissionMode(mode);
        currentPermissionMode = mode;
        reply(request, { mode, provider_operation_id: operationId(request, "permission-mode") });
        return;
      }
      case "permission_decision": {
        exactFields(request, [
          "approval_id",
          "session_id",
          "binding_id",
          "tool_use_id",
          "approval_digest",
          "decision",
        ]);
        await requireSession(request);
        const approvalId = requiredText(request, "approval_id", 256);
        const bindingId = requiredText(request, "binding_id", 256);
        const toolUseId = requiredText(request, "tool_use_id", 256);
        const approvalDigest = requiredText(request, "approval_digest", 64);
        const decision = requiredText(request, "decision", 64);
        if (!/^[0-9a-f]{64}$/.test(approvalDigest)) throw new Error("invalid approval digest");
        if (!new Set(["allow", "deny"]).has(decision)) throw new Error("permission decision is not reviewed");
        const waiter = permissionWaiters.get(approvalId);
        if (!waiter) throw new Error("permission request is stale or already resolved");
        const exactProof = (
          waiter.sessionId === activeSessionId
          && waiter.bindingId === activeBindingId
          && bindingId === activeBindingId
          && waiter.toolUseId === toolUseId
          && waiter.approvalDigest === approvalDigest
          && Date.now() < waiter.expiresAt
        );
        if (!exactProof || (decision === "allow" && !waiter.allowSafe)) {
          denyWaiter(approvalId, waiter, "Permission proof was stale, hidden, or mismatched");
          throw new Error("permission proof is stale or mismatched");
        }
        releaseWaiter(approvalId, waiter);
        if (decision === "allow") {
          waiter.resolve({ behavior: "allow", updatedInput: waiter.input, toolUseID: waiter.toolUseId });
        } else {
          waiter.resolve({ behavior: "deny", message: "Denied from Pairling", toolUseID: waiter.toolUseId });
        }
        reply(request, { decision, provider_operation_id: `permission:${approvalId}` });
        return;
      }
      case "question_response": {
        exactFields(request, [
          "question_request_id",
          "session_id",
          "binding_id",
          "tool_use_id",
          "question_digest",
          "decision",
          "answers",
        ]);
        await requireSession(request);
        const questionRequestId = requiredText(
          request,
          "question_request_id",
          256,
        );
        const bindingId = requiredText(request, "binding_id", 256);
        const toolUseId = requiredText(request, "tool_use_id", 256);
        const questionDigest = requiredText(request, "question_digest", 64);
        const decision = requiredText(request, "decision", 32);
        if (!new Set(["accept", "cancel"]).has(decision)) {
          throw new Error("question decision is not reviewed");
        }
        if (!/^[0-9a-f]{64}$/.test(questionDigest)) {
          throw new Error("invalid question digest");
        }
        const waiter = questionWaiters.get(questionRequestId);
        if (!waiter) {
          throw new Error("question request is stale or already resolved");
        }
        const exactProof = (
          waiter.sessionId === activeSessionId
          && waiter.bindingId === activeBindingId
          && bindingId === activeBindingId
          && waiter.toolUseId === toolUseId
          && waiter.questionDigest === questionDigest
          && Date.now() < waiter.expiresAt
        );
        if (exactProof && decision === "cancel") {
          denyQuestionWaiter(
            questionRequestId,
            waiter,
            "Question request cancelled from Pairling",
          );
          reply(request, {
            question_request_id: questionRequestId,
            decision,
            answer_count: 0,
            provider_operation_id: `question:${questionRequestId}`,
          });
          return;
        }
        if (!exactProof || !Array.isArray(request.answers)) {
          denyQuestionWaiter(
            questionRequestId,
            waiter,
            "Question proof was stale or mismatched",
          );
          throw new Error("question proof is stale or mismatched");
        }
        if (request.answers.length !== waiter.questions.length) {
          throw new Error("question response is incomplete");
        }
        const submittedByIndex = new Map();
        for (const answer of request.answers) {
          if (
            !answer
            || typeof answer !== "object"
            || Array.isArray(answer)
            || !Number.isInteger(answer.index)
            || submittedByIndex.has(answer.index)
          ) {
            throw new Error("question response indexes are invalid");
          }
          submittedByIndex.set(answer.index, answer);
        }
        const updatedAnswers = {};
        for (const question of waiter.questions) {
          const answer = submittedByIndex.get(question.index);
          if (
            !answer
            || answer.topic !== question.topic
            || answer.question !== question.question
            || canonicalJSON(answer.options) !== canonicalJSON(question.options)
            || typeof answer.answer !== "string"
            || !question.options.includes(answer.answer)
          ) {
            throw new Error("question response does not match the pending form");
          }
          updatedAnswers[question.question] = answer.answer;
        }
        releaseQuestionWaiter(questionRequestId, waiter);
        waiter.resolve({
          behavior: "allow",
          updatedInput: {
            ...waiter.input,
            answers: updatedAnswers,
          },
          updatedPermissions: [],
          toolUseID: waiter.toolUseId,
        });
        event("question.resolved", {
          question_request_id: questionRequestId,
          tool_use_id: waiter.toolUseId,
          question_digest: waiter.questionDigest,
          decision: "answered",
        }, `${questionRequestId}:resolved`);
        reply(request, {
          question_request_id: questionRequestId,
          answer_count: waiter.questions.length,
          decision,
          provider_operation_id: `question:${questionRequestId}`,
        });
        return;
      }
      case "read_commands": {
        exactFields(request, []);
        await requireActiveQuery();
        const commands = await activeQuery.supportedCommands();
        reply(request, {
          commands: commands.map((row) => ({
            name: bounded(row.name, 256),
            description: bounded(row.description, 500),
            argument_hint: bounded(row.argumentHint || "", 500),
            aliases: Array.isArray(row.aliases) ? row.aliases.slice(0, 32).map((item) => bounded(item, 128)) : [],
          })),
        });
        return;
      }
      case "read_agents": {
        exactFields(request, ["session_id"]);
        await requireSession(request);
        const agents = await activeQuery.supportedAgents();
        reply(request, {
          agents: agents.map((row) => ({
            name: bounded(row.name, 256),
            description: bounded(row.description, 500),
            model: bounded(row.model || "", 256),
          })),
        });
        return;
      }
      case "read_status": {
        exactFields(request, ["session_id"]);
        await requireSession(request);
        const liveInitialization = await activeQuery.initializationResult();
        reply(request, {
          status: {
            session_id: activeSessionId,
            model: currentModel,
            permission_mode: currentPermissionMode,
            output_style: bounded(liveInitialization?.output_style || "", 256),
            fast_mode_state: liveInitialization?.fast_mode_state || null,
            sdk_version: SDK_VERSION,
            claude_code_version: CLAUDE_CODE_VERSION,
          },
        });
        return;
      }
      case "read_mcp": {
        exactFields(request, []);
        await requireActiveQuery();
        const status = await activeQuery.mcpServerStatus();
        reply(request, { servers: status.map((row) => ({ name: bounded(row.name, 256), status: row.status })) });
        return;
      }
      case "mcp_reconnect": {
        exactFields(request, ["session_id", "server_id", "client_action_id"]);
        await requireSession(request);
        const serverId = requiredText(request, "server_id", 256);
        const status = await activeQuery.mcpServerStatus();
        if (!status.some((row) => row.name === serverId)) throw new Error("MCP server is not in the live SDK catalog");
        await activeQuery.reconnectMcpServer(serverId);
        reply(request, { server_id: serverId, reconnected: true, provider_operation_id: operationId(request, "mcp-reconnect") });
        return;
      }
      case "mcp_set_enabled": {
        exactFields(request, ["session_id", "server_id", "enabled", "client_action_id"]);
        await requireSession(request);
        const serverId = requiredText(request, "server_id", 256);
        if (typeof request.enabled !== "boolean") throw new Error("enabled must be boolean");
        const status = await activeQuery.mcpServerStatus();
        if (!status.some((row) => row.name === serverId)) throw new Error("MCP server is not in the live SDK catalog");
        await activeQuery.toggleMcpServer(serverId, request.enabled);
        reply(request, {
          server_id: serverId,
          enabled: request.enabled,
          provider_operation_id: operationId(request, "mcp-set-enabled"),
        });
        return;
      }
      case "read_account": {
        exactFields(request, []);
        await requireActiveQuery();
        const account = await activeQuery.accountInfo();
        reply(request, {
          organization: bounded(account?.organization || "", 500),
          subscription_type: bounded(account?.subscriptionType || "", 160),
          api_provider: bounded(account?.apiProvider || "", 80),
        });
        return;
      }
      case "read_context": {
        exactFields(request, ["session_id"]);
        await requireSession(request);
        reply(request, { context: await activeQuery.getContextUsage() });
        return;
      }
      case "read_history": {
        exactFields(request, ["session_id"]);
        await requireSession(request);
        if (typeof sdk.getSessionMessages !== "function") throw new Error("session history is unavailable");
        const messages = await sdk.getSessionMessages(activeSessionId, { dir: activeProject });
        reply(request, { messages: projectHistoryMessages(messages) });
        return;
      }
      case "read_diagnostics": {
        exactFields(request, []);
        await requireActiveQuery();
        reply(request, {
          diagnostics: {
            session_id: activeSessionId,
            sdk_version: SDK_VERSION,
            claude_code_version: CLAUDE_CODE_VERSION,
            node_version: process.versions.node,
            sdk_capabilities: [...systemCapabilities].slice(0, 128),
          },
        });
        return;
      }
      default:
        reject(request, "unsupported_operation", "operation is not in the reviewed sidecar protocol");
    }
  } catch (error) {
    reject(request, "provider_rejected", safeError(error));
  }
}

async function requireActiveQuery() {
  if (!activeSessionId || !activeBindingId) {
    throw new Error("Claude SDK session is unavailable");
  }
  return ensureActiveQuery();
}

async function shutdown() {
  logicalSessionClosed = true;
  for (const [approvalId, waiter] of permissionWaiters) {
    denyWaiter(approvalId, waiter, "Claude sidecar closed");
  }
  for (const [questionRequestId, waiter] of questionWaiters) {
    denyQuestionWaiter(
      questionRequestId,
      waiter,
      "Claude sidecar closed",
    );
  }
  inputQueue?.close();
  activeQuery?.close();
  await Promise.race([queryConsumer || Promise.resolve(), new Promise((resolve) => setTimeout(resolve, 250))]);
  activeQuery = null;
}

process.once("SIGTERM", () => {
  void shutdown().finally(() => process.exit(0));
});
process.once("SIGINT", () => {
  void shutdown().finally(() => process.exit(0));
});

let input = Buffer.alloc(0);
try {
  for await (const chunk of process.stdin) {
    input = Buffer.concat([input, Buffer.from(chunk)]);
    let newline;
    while ((newline = input.indexOf(0x0a)) !== -1) {
      const line = input.subarray(0, newline);
      input = input.subarray(newline + 1);
      if (line.length === 0) continue;
      if (line.length > MAX_LINE_BYTES) throw new Error("oversized JSONL request");
      let request;
      try {
        request = JSON.parse(line.toString("utf8"));
      } catch {
        reject({ id: "invalid" }, "invalid_input", "malformed JSONL request");
        continue;
      }
      await handle(request);
    }
    if (input.length > MAX_LINE_BYTES) throw new Error("oversized JSONL request");
  }
} catch (error) {
  event("lifecycle", { subtype: "sidecar_protocol_error", status: "unavailable", reason: safeError(error) });
} finally {
  await shutdown();
}
