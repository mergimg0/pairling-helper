"""On-demand transcript ingestion into the session event log (contract v2).

A session starts ingesting when the first v2 subscriber asks for it. The
first drain backfills the whole existing transcript (that is the live and
archive unification: history is just earlier seq values), then a shared
FileWatcher wakes the single ingest thread on every append. Codex output is
normalized to the Claude line shape first, so one adapter serves both
providers. Parsed records store that normalized line inline. Beyond-cap
records preserve the exact source bytes outside SQLite.

Lines up to MAX_LINE_BYTES become normal provider-neutral events. Larger
records are never silently dropped: their exact source bytes are copied in
bounded chunks to the event log's private raw store and linked to an explicit
lifecycle event.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import threading
import time
from pathlib import Path

from session_event_log import (
    TOOL_DIFF_MAX_CHARS,
    VISIBLE_BLOCK_TEXT_MAX,
    SessionEventLog,
    error_line,
    parse_claude_transcript_line,
    source_file_version,
)

INGEST_TOPIC = "log-ingest"
MAX_LINE_BYTES = 32 * 1024 * 1024
READ_CHUNK = 1024 * 1024
CLAUDE_PARSER_VERSION = 5
CODEX_PARSER_VERSION = 6
OMP_PARSER_VERSION = 6
SUPPORTED_TRANSCRIPT_PROVIDERS = frozenset({"claude", "codex", "omp"})

_CODEX_TEXT_BLOCK_TYPES = {"text", "output_text", "input_text"}

# A command's own record of its output is not cut the way the text Codex hands
# the model is (about 40,000 characters). A longer one keeps the model's text.
CODEX_COMMAND_OUTPUT_MAX_CHARS = 64 * 1024
# An API error can carry a whole response body. Its first part says what failed.
FAILED_REQUEST_MAX_CHARS = 2_000

_JS_STRING = re.compile(r'"[^"\\\r\n]*(?:\\.[^"\\\r\n]*)*"')
_JS_NAME = r"[A-Za-z_]\w*"
_JS_VALUE = r'(?:""|-?\d+(?:\.\d+)?|true|false|null)'
_JS_PAIR = re.compile(rf'(""|{_JS_NAME}):({_JS_VALUE})')
_JS_EXEC_COMMAND = (
    r"await tools\.exec_command\((?P<args>\{"
    rf'(?:""|{_JS_NAME}):{_JS_VALUE}(?:,(?:""|{_JS_NAME}):{_JS_VALUE})*,?'
    r"\})\)"
)
# The whole program, with every string literal read as "" and no spacing
# beside punctuation. These are the only programs shown as what they run.
_CODEX_EXEC_COMMAND_JS = (
    re.compile(rf"text\({_JS_EXEC_COMMAND}\);?"),
    re.compile(
        rf"(?:const|let|var) (?P<result>{_JS_NAME})={_JS_EXEC_COMMAND};?"
        r"text\((?:(?P=result)(?:\.output)?|JSON\.stringify\((?P=result)\))\);?"
    ),
)
_CODEX_APPLY_PATCH_JS = (
    re.compile(r'text\(await tools\.apply_patch\(""\)\);?'),
    re.compile(
        rf'(?:const|let|var) (?P<patch>{_JS_NAME})="";?'
        r"text\(await tools\.apply_patch\((?P=patch)\)\);?"
    ),
    re.compile(
        rf'(?:const|let|var) (?P<patch>{_JS_NAME})="";?'
        rf"(?:const|let|var) (?P<result>{_JS_NAME})=await tools\.apply_patch\((?P=patch)\);?"
        r"text\((?P=result)\);?"
    ),
)
_UNIFIED_HUNK = re.compile(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class UnsupportedTranscriptProviderError(ValueError):
    """Raised when a non-deep provider reaches the transcript parser."""

    code = "unsupported_provider"
    capability = "session_transcript"

    def __init__(self, provider: str) -> None:
        self.provider = str(provider or "").strip().lower() or "unknown"
        super().__init__(
            f"Provider {self.provider} does not support deep transcript ingestion."
        )


def _bounded_text(value, limit: int = VISIBLE_BLOCK_TEXT_MAX) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError):
            value = str(value)
    if value.startswith("data:"):
        return "[inline data omitted]"
    if len(value) <= limit:
        return value
    return value[:max(0, limit - 3)] + "..."


def _codex_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        pieces = []
        for item in value:
            if isinstance(item, str):
                pieces.append(item)
            elif isinstance(item, dict):
                text = item.get("text") or item.get("content") or item.get("output_text")
                if isinstance(text, str):
                    pieces.append(text)
        return "\n".join(pieces)
    if isinstance(value, dict):
        for key in ("text", "message", "content", "output_text"):
            if isinstance(value.get(key), str):
                return value[key]
    return ""


def _codex_message_needs_sanitized_path(content) -> bool:
    if not isinstance(content, list):
        return False
    for item in content:
        if not isinstance(item, (dict, str)):
            return True
        if isinstance(item, str):
            continue
        block_type = str(item.get("type") or "")
        if block_type in _CODEX_TEXT_BLOCK_TYPES or block_type == "reasoning":
            continue
        text = item.get("text") or item.get("content")
        if (block_type != "input_image" and isinstance(text, str) and text
                and not text.startswith("data:")):
            continue
        return True
    return False


def _sanitized_codex_message_events(obj: dict, payload: dict) -> list[dict]:
    role = payload.get("role") if payload.get("role") in ("user", "assistant") else "assistant"
    blocks = []
    for item in payload.get("content") or []:
        if isinstance(item, str):
            blocks.append({"type": "text", "text": item})
            continue
        if not isinstance(item, dict):
            blocks.append({"type": "text", "text": "[Unsupported content block]"})
            continue
        block_type = str(item.get("type") or "")
        if block_type in _CODEX_TEXT_BLOCK_TYPES:
            text = item.get("text") or item.get("content") or ""
            if text:
                blocks.append({"type": "text", "text": str(text)})
        elif block_type == "reasoning":
            text = _codex_text(item.get("summary") or item.get("content"))
            if text:
                blocks.append({"type": "thinking", "thinking": text})
        elif block_type == "input_image":
            detail = _bounded_text(item.get("detail"), 40)
            suffix = f" ({detail})" if detail else ""
            blocks.append({"type": "text", "text": f"[Image attachment{suffix}]"})
        else:
            safe_type = _bounded_text(block_type or "unknown", 80)
            text = item.get("text") or item.get("content")
            if isinstance(text, str) and text:
                prefix = f"[Unsupported content block: {safe_type}] "
                label = prefix + _bounded_text(text, VISIBLE_BLOCK_TEXT_MAX - len(prefix))
            else:
                label = f"[Unsupported content block: {safe_type}]"
            blocks.append({"type": "text", "text": label})
    if not blocks:
        return []
    source = json.dumps({
        "type": role,
        "uuid": payload.get("id"),
        "timestamp": obj.get("timestamp"),
        "message": {"role": role, "content": blocks},
    }, ensure_ascii=False, separators=(",", ":"))
    return parse_claude_transcript_line(source)


def _sanitized_image_generation_events(line: str, obj: dict, payload: dict) -> list[dict]:
    stable = hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()[:16]
    call_id = payload.get("call_id") or payload.get("id") or f"codex-image-{stable}"
    tool_input = {}
    for key in ("prompt", "revised_prompt", "size", "quality", "background", "output_format"):
        value = payload.get(key)
        if value is not None:
            if isinstance(value, (str, int, float, bool)):
                tool_input[key] = _bounded_text(value)
            else:
                tool_input[key] = "[structured value omitted]"
    blocks = [{
        "type": "tool_use",
        "id": call_id,
        "name": "image_generation",
        "input": tool_input,
    }]
    status = str(payload.get("status") or "")
    has_result = payload.get("result") is not None
    if has_result or status in ("completed", "failed", "cancelled"):
        if has_result:
            content = "Generated image available."
        elif status:
            content = f"Image generation {status}."
        else:
            content = "Image generation finished."
        error = _bounded_text(payload.get("error"))
        if error:
            content = f"{content} {error}"
        blocks.append({
            "type": "tool_result",
            "tool_use_id": call_id,
            "content": content,
            "is_error": status == "failed" or bool(error),
        })
    source = json.dumps({
        "type": "assistant",
        "uuid": f"codex-{stable}",
        "timestamp": obj.get("timestamp"),
        "message": {"role": "assistant", "content": blocks},
    }, ensure_ascii=False, separators=(",", ":"))
    return parse_claude_transcript_line(source)


def codex_exec_call(source: str) -> tuple[str, dict] | None:
    """The tool name and input to show for an `exec` call whose JavaScript is
    exactly one command or one patch. None for every other program, and for
    any string literal that JSON does not read the way JavaScript does."""
    literals = _JS_STRING.findall(source)
    code = " ".join(_JS_STRING.sub('""', source).split())
    code = re.sub(r" (?=\W)|(?<=\W) ", "", code)
    try:
        for pattern in _CODEX_EXEC_COMMAND_JS:
            match = pattern.fullmatch(code)
            if match is None:
                continue
            # Every literal of these programs is inside the argument object.
            values = iter(literals)
            args: dict = {}
            for key, value in _JS_PAIR.findall(match["args"]):
                if key == '""':
                    key = json.loads(next(values))
                if key in args:
                    return None
                args[key] = json.loads(next(values)) if value == '""' else None
            command = args.get("cmd")
            if not isinstance(command, str) or not command.strip():
                return None
            command.encode("utf-8")
            return "exec", {"command": command}
        if len(literals) == 1 and any(
            pattern.fullmatch(code) for pattern in _CODEX_APPLY_PATCH_JS
        ):
            patch = json.loads(literals[0])
            patch.encode("utf-8")
            if patch.startswith("*** Begin Patch"):
                return "apply_patch", {"input": patch}
    except ValueError:  # Not a JSON string, or text that cannot be stored.
        pass
    return None


def _codex_numbered_change(path, change) -> list[str] | None:
    """One changed file as a header and numbered lines. None when the record
    is not in a known shape."""
    kind = change.get("type") if isinstance(change, dict) else None
    if kind in ("add", "delete"):
        content = change.get("content")
        if not isinstance(content, str):
            return None
        sign, title = ("+", "Add") if kind == "add" else ("-", "Delete")
        body = content.removesuffix("\n").split("\n") if content else []
        return [f"*** {title} File: {path}"] + [
            f"{sign}{number}|{text}" for number, text in enumerate(body, 1)
        ]
    unified = change.get("unified_diff") if kind == "update" else None
    if not isinstance(unified, str):
        return None
    lines = [f"*** Update File: {change.get('move_path') or path}"]
    old = new = None
    for line in unified.removesuffix("\n").split("\n"):
        header = _UNIFIED_HUNK.match(line)
        if header:
            if old is not None:
                lines.append("")
            old, new = int(header[1]), int(header[2])
            continue
        if old is None:
            continue  # File header lines before the first hunk.
        sign, text = line[:1], line[1:]
        if sign == "+":
            lines.append(f"+{new}|{text}")
            new += 1
        elif sign == "-":
            lines.append(f"-{old}|{text}")
            old += 1
        elif sign == " ":
            lines.append(f" {new}|{text}")
            old += 1
            new += 1
        elif sign != "\\":  # "\ No newline at end of file" is not a line.
            return None
    if old is None and unified.strip():
        return None  # Text with no hunk header this parser can read.
    return lines


def _codex_file_change_diff(items: list[dict]) -> str | None:
    """Every file the call changed, in the numbered shape an edit's diff has
    for the other providers, each file under a `*** ... File:` header."""
    files: list[str] = []
    for item in items:
        if item.get("type") != "FileChange" or item.get("status") != "completed":
            continue
        changes = item.get("changes")
        if not isinstance(changes, dict):
            return None
        for path, change in changes.items():
            lines = _codex_numbered_change(path, change)
            if lines is None:
                return None
            files.append("\n".join(lines))
    diff = "\n\n".join(files)
    return diff if 0 < len(diff) <= TOOL_DIFF_MAX_CHARS else None


def _codex_command_script(item: dict) -> str:
    argv = item.get("command")
    if isinstance(argv, str):
        return argv
    if not isinstance(argv, list):
        return ""
    argv = [str(part) for part in argv]
    return argv[2] if len(argv) == 3 and argv[1] == "-lc" else shlex.join(argv)


def _codex_output_has_running_command(output) -> bool:
    """True when the result names a command that had not finished. Its text
    so far and its session number are only in the result Codex wrote."""
    for part in output if isinstance(output, list) else []:
        text = part.get("text") if isinstance(part, dict) else None
        if not isinstance(text, str) or not text.startswith("{"):
            continue
        try:
            chunk = json.loads(text)
        except ValueError:
            continue
        if (isinstance(chunk, dict) and "chunk_id" in chunk
                and "session_id" in chunk and "exit_code" not in chunk):
            return True
    return False


def _codex_item_text(items: list[dict], shown_command) -> tuple[str, bool]:
    """What the call's commands and patches printed, and whether a command
    failed. A command is named on a `$` line unless it is the only item and
    the call already shows exactly that command."""
    alone = (len(items) == 1 and items[0].get("type") == "CommandExecution"
             and _codex_command_script(items[0]) == shown_command)
    parts: list[str] = []
    failed = False
    for item in items:
        output = None
        code = None
        if item.get("type") == "CommandExecution":
            if not alone:
                parts.append(f"$ {_codex_command_script(item)}")
            output = item.get("aggregated_output")
            code = item.get("exit_code")
        if not isinstance(output, str):
            output = "".join(
                value for value in (item.get("stdout"), item.get("stderr"))
                if isinstance(value, str)
            )
        output = output.rstrip("\n")
        if output:
            parts.append(output)
        if isinstance(code, int) and not isinstance(code, bool) and code != 0:
            parts.append(f"exit code {code}")
            failed = True
    return "\n".join(parts), failed


def _codex_track_call(obj: dict, events: list[dict], state: dict) -> None:
    """Codex records what a call ran and changed on lines of their own,
    between the call and its result and without the call's id. Keep those
    for the open call, then show the result as the other providers do."""
    payload = obj.get("payload")
    if not isinstance(payload, dict):
        return
    kind = (obj.get("type"), payload.get("type"))
    if kind == ("event_msg", "item_completed"):
        item = payload.get("item")
        if ("items" in state and isinstance(item, dict)
                and item.get("type") in ("CommandExecution", "FileChange")):
            # Keyed by id so a chunk that is read again adds nothing twice.
            key = item.get("id")
            if not isinstance(key, str):
                key = len(state["items"])
            state["items"].setdefault(key, item)
    elif kind == ("response_item", "custom_tool_call"):
        state.clear()
        state["call_id"] = payload.get("call_id")
        state["items"] = {}
        source = payload.get("input")
        calls = [event for event in events if event.get("kind") == "tool_call"]
        if payload.get("name") == "exec" and isinstance(source, str) and len(calls) == 1:
            shown = codex_exec_call(source)
            if shown is not None:
                calls[0]["name"], calls[0]["input"] = shown
                state["command"] = shown[1].get("command")
    elif kind == ("response_item", "custom_tool_call_output"):
        items = []
        if "items" in state and state.get("call_id") == payload.get("call_id"):
            items = list(state["items"].values())
        shown_command = state.get("command")
        state.clear()
        results = [event for event in events if event.get("kind") == "tool_result"]
        if not items or len(results) != 1:
            return
        diff = _codex_file_change_diff(items)
        if diff is not None:
            results[0]["diff"] = diff
        if _codex_output_has_running_command(payload.get("output")):
            return
        text, failed = _codex_item_text(items, shown_command)
        if len(text) <= CODEX_COMMAND_OUTPUT_MAX_CHARS and not text.startswith("data:"):
            results[0]["content"] = text
            if failed:
                results[0]["is_error"] = True


def _failed_request_block(message) -> dict | None:
    """Why a model request failed, in the provider's own words and set apart
    from what the agent wrote. OMP and Codex record it beside the turn, where
    no reader of the transcript would otherwise see it."""
    raw = str(message or "").strip()
    if not raw:
        return None
    line = error_line(raw)
    text = f"**The model request failed.** {line}"
    if line != raw:
        # A status, a response body, or more lines than the one above.
        text += f"\n\n````\n{raw[:FAILED_REQUEST_MAX_CHARS]}\n````"
    return {"type": "text", "text": text}


def parse_codex_transcript_line(line: str, native_id: str, normalize_codex, *,
                                state: dict | None = None) -> list[dict]:
    """Preserve Codex records the shared normalizer cannot safely express.

    With `state`, one dict kept for the session and passed with every line in
    file order, a command or patch call shows what it ran and what it printed
    or changed. Without it each line stands alone."""
    try:
        obj = json.loads(line)
    except (TypeError, ValueError, json.JSONDecodeError):
        obj = None
    if isinstance(obj, dict) and obj.get("type") == "response_item":
        payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
        item_type = str(payload.get("type") or "")
        if item_type == "message" and payload.get("role") not in ("user", "assistant"):
            return []
        if item_type == "image_generation_call":
            return _sanitized_image_generation_events(line, obj, payload)
        if item_type == "message" and _codex_message_needs_sanitized_path(payload.get("content")):
            return _sanitized_codex_message_events(obj, payload)
    if isinstance(obj, dict) and obj.get("type") == "event_msg":
        payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
        failed = _failed_request_block(payload.get("message")) if payload.get("type") == "error" else None
        if failed:
            stable = hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()[:16]
            return parse_claude_transcript_line(json.dumps({
                "type": "assistant",
                "uuid": f"codex-error-{stable}",
                "timestamp": obj.get("timestamp"),
                "message": {"role": "assistant", "content": [failed]},
            }, ensure_ascii=False, separators=(",", ":")))
    normalized = normalize_codex((line + "\n").encode("utf-8"), native_id)
    events: list[dict] = []
    for normalized_line in normalized.splitlines():
        if normalized_line.strip():
            events.extend(parse_claude_transcript_line(normalized_line))
    if state is not None and isinstance(obj, dict):
        _codex_track_call(obj, events, state)
    return events


def _omp_shown_reply(block: dict) -> str | None:
    """What an OMP agent wrote to its person in the middle of its work. OMP
    shows a `write` to an `out://` address as a reply, pictures included, and
    records it as a tool call."""
    arguments = block.get("arguments")
    if block.get("name") != "write" or not isinstance(arguments, dict):
        return None
    path, content = arguments.get("path"), arguments.get("content")
    if (isinstance(path, str) and path.startswith("out://")
            and isinstance(content, str) and content.strip()):
        return content
    return None


# OMP keeps a picture a tool returned outside the session file, under its
# SHA-256, and names it here.
_OMP_BLOB_IMAGE = re.compile(r"blob:sha256:[0-9a-f]{64}")


def _omp_result_images(content) -> list[dict]:
    """The pictures in an OMP tool result, in the order they appear. The phone
    asks the Mac for one by the `src` given here."""
    return [
        {"src": block["data"],
         "mime": block["mimeType"] if isinstance(block.get("mimeType"), str) else ""}
        for block in (content if isinstance(content, list) else [])
        if isinstance(block, dict) and block.get("type") == "image"
        and isinstance(block.get("data"), str) and _OMP_BLOB_IMAGE.fullmatch(block["data"])
    ]


def parse_omp_transcript_line(line: str) -> list[dict]:
    """Normalize one OMP v3 JSONL record into the shared transcript shape."""
    try:
        source = json.loads(line)
    except (TypeError, ValueError, json.JSONDecodeError):
        return parse_claude_transcript_line(line)
    if not isinstance(source, dict):
        return parse_claude_transcript_line(line)

    normalized = {
        "type": source.get("type"),
        "uuid": source.get("id"),
        "timestamp": source.get("timestamp"),
    }
    message = source.get("message")
    if source.get("type") != "message" or not isinstance(message, dict):
        return parse_claude_transcript_line(json.dumps(normalized))

    role = str(message.get("role") or "")
    details = message.get("details")
    images: list[dict] = []
    if (role == "toolResult" and message.get("toolName") == "write"
            and message.get("useless") is True and not message.get("isError")
            and isinstance(details, dict) and details.get("touchesNoFiles") is True):
        # The result of a reply written mid-turn says only that it was shown,
        # and OMP marks it useless. The reply itself is the row. A write to an
        # agent or a process touches no files either, but its result is not
        # marked useless and stays.
        return parse_claude_transcript_line(json.dumps(normalized))
    if role == "toolResult":
        tool_result = {
            "type": "tool_result",
            "tool_use_id": message.get("toolCallId"),
            "content": message.get("content"),
            "is_error": bool(message.get("isError")),
        }
        # An edit records the change it made as a line-numbered diff, which
        # says more than the text it returned to the model.
        diff = details.get("diff") if isinstance(details, dict) else None
        if isinstance(diff, str) and 0 < len(diff) <= TOOL_DIFF_MAX_CHARS:
            tool_result["diff"] = diff
        # An ask records each question beside the answer the person gave.
        if isinstance(details, dict) and isinstance(details.get("answers"), list):
            tool_result["answers"] = details["answers"]
        # A todo call records the whole list as it stood afterwards.
        if isinstance(details, dict) and isinstance(details.get("phases"), list):
            tool_result["plan"] = details["phases"]
        images = _omp_result_images(message.get("content"))
        normalized["type"] = "user"
        normalized["message"] = {"role": "user", "content": [tool_result]}
    else:
        blocks = []
        for block in message.get("content") or []:
            if not isinstance(block, dict):
                blocks.append(block)
            elif block.get("type") == "toolCall":
                reply = _omp_shown_reply(block)
                blocks.append({"type": "text", "text": reply} if reply else {
                    "type": "tool_use",
                    "id": block.get("id"),
                    "name": block.get("name"),
                    "input": block.get("arguments"),
                })
            elif block.get("type") == "thinking" and block.get("narration") is True:
                # A note the agent wrote to its person while working. OMP
                # records it as reasoning with this mark and shows it as a reply.
                blocks.append({"type": "text", "text": block.get("thinking")})
            else:
                blocks.append(block)
        failed = (
            _failed_request_block(message.get("errorMessage"))
            if role == "assistant" and message.get("stopReason") == "error" else None
        )
        if failed:
            blocks.append(failed)
        normalized["type"] = role if role in {"user", "assistant"} else "unknown"
        normalized["message"] = {"role": role or "unknown", "content": blocks}
    events = parse_claude_transcript_line(
        json.dumps(normalized, ensure_ascii=False, separators=(",", ":"))
    )
    # The shared parser turns a result into text, where a picture is only a
    # label. What the phone needs to ask for each one rides beside that text.
    if images:
        for event in events:
            if event.get("kind") == "tool_result":
                event["images"] = images
    return events


class SessionLogIngestor:
    def __init__(self, log: SessionEventLog, hub, watcher, *, normalize_codex=None,
                 claude_parser_version: int = CLAUDE_PARSER_VERSION,
                 codex_parser_version: int = CODEX_PARSER_VERSION,
                 omp_parser_version: int = OMP_PARSER_VERSION,
                 max_sessions: int = 128,
                 max_line_bytes: int = MAX_LINE_BYTES) -> None:
        self._log = log
        self._hub = hub
        self._watcher = watcher
        self._normalize_codex = normalize_codex
        self._claude_parser_version = max(1, int(claude_parser_version))
        self._codex_parser_version = max(1, int(codex_parser_version))
        self._omp_parser_version = max(1, int(omp_parser_version))
        self._max_sessions = max(1, int(max_sessions))
        self._max_line_bytes = max(READ_CHUNK, int(max_line_bytes))
        self._lock = threading.RLock()
        self._sessions: dict[str, dict] = {}
        self._by_path: dict[str, set[str]] = {}
        self._errors: dict[str, dict] = {}
        self._subscription = hub.subscribe(INGEST_TOPIC, max_queue=1024)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="session-log-ingest", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        self._subscription.close()
        self._thread.join(timeout=2)
        with self._lock:
            handles = [entry.get("watch") for entry in self._sessions.values()]
            self._sessions.clear()
            self._by_path.clear()
            self._errors.clear()
        for handle in handles:
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass

    def ensure(self, session_key: str, provider: str, native_id: str, transcript_path) -> bool:
        """Registers a session for ingestion. Returns True when registered
        (idempotent). The first drain backfills the whole file."""
        provider = str(provider or "").strip().lower()
        if provider not in SUPPORTED_TRANSCRIPT_PROVIDERS:
            return False
        if transcript_path is None:
            return False
        path = str(Path(transcript_path).expanduser().resolve(strict=False))
        created = False
        with self._lock:
            entry = self._sessions.get(session_key)
            if entry is None:
                drain_lock = threading.RLock()
                # Hold the binding lock before publishing the entry. A watcher
                # wake or a second subscriber cannot race the initial drain.
                drain_lock.acquire()
                entry = {
                    "session_key": session_key,
                    "provider": provider,
                    "native_id": native_id,
                    "path": path,
                    "watch": None,
                    "initialized": False,
                    "drain_lock": drain_lock,
                    "last_used_at": time.monotonic(),
                }
                self._sessions[session_key] = entry
                self._map_path_locked(path, session_key)
                created = True
        drain_lock = entry["drain_lock"]
        if created:
            try:
                result = self._ensure_locked(entry, provider, native_id, path)
            finally:
                drain_lock.release()
        else:
            with drain_lock:
                result = self._ensure_locked(entry, provider, native_id, path)
        self._evict_if_needed(excluding=session_key)
        return result

    def generation_for_open_source(
        self,
        session_key: str,
        provider: str,
        native_id: str,
        transcript_path,
        source_identity: tuple[int, int],
        observed_size: int,
    ) -> int | None:
        """Bind the durable generation to bytes from an already-open file.

        The caller must read from the same descriptor it used to obtain
        ``source_identity`` and ``observed_size``. This keeps a path replacement
        from tagging bytes from one inode with another inode's generation.
        """
        if not self.ensure(session_key, provider, native_id, transcript_path):
            return None
        resolved_path = str(Path(transcript_path).expanduser().resolve(strict=False))
        with self._lock:
            entry = self._sessions.get(session_key)
        if entry is None:
            return None
        with entry["drain_lock"]:
            with self._lock:
                if (
                    self._sessions.get(session_key) is not entry
                    or entry.get("path") != resolved_path
                ):
                    return None
                entry["last_used_at"] = time.monotonic()
            try:
                _offset, reset_generation = self._log.reconcile_ingest_source(
                    session_key,
                    (int(source_identity[0]), int(source_identity[1])),
                    observed_size=max(0, int(observed_size)),
                )
                generation = int(self._log.get_generation(session_key))
            except Exception as error:
                self._record_ingest_error(session_key, error)
                return None
            self._clear_ingest_error(session_key)
            if reset_generation is not None and self._hub is not None:
                self._hub.publish(f"log:{session_key}", {
                    "type": "log_reset",
                    "generation": reset_generation,
                    "last_seq": self._log.last_seq(session_key),
                })
            return generation if generation > 0 else None

    def _ensure_locked(self, entry: dict, provider: str, native_id: str, path: str) -> bool:
        if provider not in SUPPORTED_TRANSCRIPT_PROVIDERS:
            return False
        session_key = entry["session_key"]
        with self._lock:
            if self._sessions.get(session_key) is not entry:
                return False
            initialized = bool(entry.get("initialized"))
            binding_changed = initialized and (
                entry["path"] != path
                or entry["provider"] != provider
                or entry["native_id"] != native_id
            )
            if initialized and not binding_changed:
                entry["last_used_at"] = time.monotonic()
                return True
            old_watch = entry.get("watch") if binding_changed else None
            if binding_changed:
                self._unmap_path_locked(entry["path"], session_key)
                entry.update({
                    "provider": provider,
                    "native_id": native_id,
                    "path": path,
                    "watch": None,
                    "initialized": False,
                    "last_used_at": time.monotonic(),
                })
                self._map_path_locked(path, session_key)

        if old_watch is not None:
            try:
                old_watch.close()
            except Exception:
                pass

        if provider == "codex":
            parser_version = self._codex_parser_version
        elif provider == "claude":
            parser_version = self._claude_parser_version
        elif provider == "omp":
            parser_version = self._omp_parser_version
        else:  # Defensive guard for a corrupted in-memory binding.
            raise UnsupportedTranscriptProviderError(provider)
        reset_generation = None
        if binding_changed:
            # The same Pairling session can point at a new provider transcript
            # after /resume or after sibling resolution becomes exact. The old
            # durable rows must not survive that source change.
            reset_generation = self._log.reset_ingest(session_key)
        else:
            prior_generation = self._log.get_generation(session_key)
            self._log.prepare_ingest(session_key, parser_version)
            current_generation = self._log.get_generation(session_key)
            if current_generation != prior_generation:
                reset_generation = current_generation

        watch = None
        if self._watcher is not None:
            try:
                watch = self._watcher.watch(path, INGEST_TOPIC)
            except Exception:
                watch = None
        with self._lock:
            if self._sessions.get(session_key) is not entry or entry["path"] != path:
                if watch is not None:
                    watch.close()
                return False
            entry["watch"] = watch
            entry["initialized"] = True
            entry["last_used_at"] = time.monotonic()

        if reset_generation is not None and self._hub is not None:
            self._hub.publish(f"log:{session_key}", {
                "type": "log_reset",
                "generation": reset_generation,
                "last_seq": self._log.last_seq(session_key),
            })
        # Backfill can be hundreds of megabytes. Queue it on the one ingest
        # worker so opening an HTTP stream never waits for a full transcript.
        if self._hub is not None:
            self._hub.publish(INGEST_TOPIC, {
                "type": "ingest_requested",
                "path": path,
                "session_key": session_key,
            })
        return True

    def remove(self, session_key: str) -> bool:
        """Stop watching one session before its transcript is removed."""
        with self._lock:
            entry = self._sessions.get(session_key)
        if entry is None:
            return False
        with entry["drain_lock"]:
            with self._lock:
                if self._sessions.get(session_key) is not entry:
                    return False
                self._sessions.pop(session_key, None)
                self._unmap_path_locked(entry["path"], session_key)
                self._errors.pop(session_key, None)
                watch = entry.get("watch")
                entry["watch"] = None
                entry["initialized"] = False
            if watch is not None:
                try:
                    watch.close()
                except Exception:
                    pass
        return True

    def active_session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def _evict_if_needed(self, *, excluding: str) -> None:
        while True:
            with self._lock:
                if len(self._sessions) <= self._max_sessions:
                    return
                candidates = [
                    entry for key, entry in self._sessions.items()
                    if key != excluding
                ]
                if not candidates:
                    return
                candidate = min(
                    candidates,
                    key=lambda item: float(item.get("last_used_at") or 0.0),
                )
                candidate_key = candidate["session_key"]
            with candidate["drain_lock"]:
                with self._lock:
                    if self._sessions.get(candidate_key) is not candidate:
                        continue
                    if len(self._sessions) <= self._max_sessions:
                        return
                    self._sessions.pop(candidate_key, None)
                    self._unmap_path_locked(candidate["path"], candidate_key)
                    self._errors.pop(candidate_key, None)
                    watch = candidate.get("watch")
                    candidate["watch"] = None
                    candidate["initialized"] = False
                if watch is not None:
                    try:
                        watch.close()
                    except Exception:
                        pass

    def _map_path_locked(self, path: str, session_key: str) -> None:
        self._by_path.setdefault(path, set()).add(session_key)

    def _unmap_path_locked(self, path: str, session_key: str) -> None:
        mapped = self._by_path.get(path)
        if not mapped:
            return
        mapped.discard(session_key)
        if not mapped:
            self._by_path.pop(path, None)

    def current_error(self, session_key: str) -> dict | None:
        with self._lock:
            error = self._errors.get(session_key)
            return dict(error) if error is not None else None

    def drain_now(self, session_key: str) -> dict:
        """Synchronously align one durable log with its transcript head."""
        with self._lock:
            entry = self._sessions.get(session_key)
        if entry is None:
            return {"ok": False, "reason": "session_not_registered"}
        with entry["drain_lock"]:
            for _attempt in range(4):
                if not self._attempt_drain_locked(entry):
                    return {"ok": False, "reason": "transcript_ingest_failed"}
                try:
                    source_size = int(Path(entry["path"]).stat().st_size)
                    source_offset = self._log.get_ingest_offset(session_key)
                    last_seq = self._log.last_seq(session_key)
                    generation = self._log.get_generation(session_key)
                except Exception as error:
                    self._record_ingest_error(session_key, error)
                    return {"ok": False, "reason": "transcript_inspection_failed"}
                if source_offset >= source_size:
                    return {
                        "ok": True,
                        "transcript_offset": source_size,
                        "log_seq": last_seq,
                        "log_generation": generation,
                    }
                time.sleep(0.01)
        return {"ok": False, "reason": "transcript_changed_during_boundary"}

    def _record_ingest_error(self, session_key: str, error: Exception) -> None:
        try:
            generation = self._log.get_generation(session_key)
        except Exception:
            generation = None
        payload = {
            "type": "log_ingest_error",
            "code": "transcript_ingest_failed",
            "message": str(error)[:240] or type(error).__name__,
            "error_type": type(error).__name__,
            "retryable": True,
            "session_key": session_key,
            "generation": generation,
        }
        with self._lock:
            previous = self._errors.get(session_key)
            self._errors[session_key] = payload
        if previous != payload and self._hub is not None:
            self._hub.publish(f"log:{session_key}", payload)

    def _clear_ingest_error(self, session_key: str) -> None:
        with self._lock:
            previous = self._errors.pop(session_key, None)
        if previous is not None and self._hub is not None:
            try:
                generation = self._log.get_generation(session_key)
            except Exception:
                generation = None
            self._hub.publish(f"log:{session_key}", {
                "type": "log_ingest_recovered",
                "code": "transcript_ingest_recovered",
                "session_key": session_key,
                "generation": generation,
            })

    def _attempt_drain_locked(self, entry: dict, *, force_reset: bool = False,
                              publish: bool = True) -> bool:
        try:
            completed = self._drain_entry_locked(
                entry, force_reset=force_reset, publish=publish
            )
        except Exception as error:
            self._record_ingest_error(entry["session_key"], error)
            return False
        if completed:
            self._clear_ingest_error(entry["session_key"])
        return completed

    def _run(self) -> None:
        while not self._stop.is_set():
            event = self._subscription.get(timeout=1.0)
            due: dict[str, bool] = {}
            while event is not None:
                if event.get("type") == "queue_gap":
                    with self._lock:
                        for session_key in self._sessions:
                            due.setdefault(session_key, False)
                else:
                    with self._lock:
                        session_keys = tuple(self._by_path.get(str(event.get("path") or ""), ()))
                    for session_key in session_keys:
                        due[session_key] = due.get(session_key, False) or event.get("type") == "file_rotated"
                event = self._subscription.get(timeout=0)
            # A failed drain may have consumed the only file-change wake. Keep
            # retrying only the sessions in a typed error state so a transient
            # parser or SQLite failure can recover without waiting for another
            # provider write.
            with self._lock:
                for session_key in self._errors:
                    due.setdefault(session_key, False)
            for session_key, force_reset in due.items():
                self._drain(session_key, force_reset=force_reset)

    def _drain(self, session_key: str, *, force_reset: bool = False) -> None:
        with self._lock:
            entry = self._sessions.get(session_key)
        if entry is None:
            return
        with entry["drain_lock"]:
            self._attempt_drain_locked(entry, force_reset=force_reset)

    def _drain_entry_locked(self, entry: dict, *, force_reset: bool = False,
                            publish: bool = True) -> bool:
        session_key = entry["session_key"]
        provider = str(entry.get("provider") or "").strip().lower()
        if provider not in SUPPORTED_TRANSCRIPT_PROVIDERS:
            raise UnsupportedTranscriptProviderError(provider)
        if provider == "codex" and self._normalize_codex is None:
            raise RuntimeError("Codex transcript normalizer is unavailable")
        path = Path(entry["path"])
        try:
            handle = open(path, "rb")
        except OSError as error:
            raise OSError(f"cannot open transcript: {error}") from error
        with handle:
            try:
                stat = os.fstat(handle.fileno())
            except OSError as error:
                raise OSError(f"cannot inspect transcript: {error}") from error
            size = int(stat.st_size)
            source_identity = (int(stat.st_dev), int(stat.st_ino))
            source_version = source_file_version(stat)
            offset, reset_generation = self._log.reconcile_ingest_source(
                session_key,
                source_identity,
                observed_size=size,
                force_reset=force_reset,
            )
            appended_any = False
            while offset < size:
                handle.seek(offset)
                data = handle.read(min(size - offset, READ_CHUNK))
                newline = data.rfind(b"\n")
                if newline < 0:
                    if len(data) < READ_CHUNK:
                        break
                    # The log is the archive, so ordinary large lines ingest
                    # whole and become neutral events. A pathological record
                    # beyond the parse cap is preserved exactly in the private
                    # raw store without materializing it in this process.
                    end = self._scan_line_end(handle, offset + len(data), size)
                    if end is None:
                        break
                    if end - offset <= self._max_line_bytes:
                        handle.seek(offset)
                        complete = handle.read(end - offset)
                    else:
                        advanced = self._log.append_preserved_raw_and_advance(
                            session_key,
                            {
                                "kind": "lifecycle",
                                "subtype": "oversized_line",
                                "source_uuid": None,
                                "role": None,
                                "ts": None,
                                "start": offset,
                                "end": end,
                                "bytes": end - offset,
                                "raw": None,
                            },
                            end,
                            expected_byte_offset=offset,
                            expected_source_identity=source_identity,
                            source_handle=handle,
                            source_start=offset,
                            source_bytes=end - offset,
                            expected_source_version=source_version,
                        )
                        if advanced is None:
                            # Another reader moved the cursor after this drain
                            # opened the file. Resume at that durable cursor so
                            # a suffix appended during the race is not stranded
                            # until some future wake.
                            durable_offset = self._log.get_ingest_offset(session_key)
                            if offset < durable_offset <= size:
                                offset = durable_offset
                                continue
                            return False
                        appended_any = True
                        offset = end
                        continue
                else:
                    complete = data[:newline + 1]
                text = complete.decode("utf-8", errors="replace")
                events: list[dict] = []
                for line in text.splitlines():
                    if line.strip():
                        if provider == "codex":
                            events.extend(parse_codex_transcript_line(
                                line, entry["native_id"], self._normalize_codex,
                                state=entry.setdefault("codex_state", {}),
                            ))
                        elif provider == "claude":
                            events.extend(parse_claude_transcript_line(line))
                        elif provider == "omp":
                            events.extend(parse_omp_transcript_line(line))
                        else:  # Defensive guard for a corrupted in-memory binding.
                            raise UnsupportedTranscriptProviderError(provider)
                next_offset = offset + len(complete)
                advanced = self._log.append_and_advance(
                    session_key,
                    events,
                    next_offset,
                    expected_byte_offset=offset,
                    expected_source_identity=source_identity,
                )
                if advanced is None:
                    durable_offset = self._log.get_ingest_offset(session_key)
                    if offset < durable_offset <= size:
                        offset = durable_offset
                        continue
                    return False
                appended_any = appended_any or bool(events)
                offset = next_offset
        if publish and (appended_any or reset_generation is not None) and self._hub is not None:
            self._hub.publish(f"log:{session_key}", {
                "type": "log_reset" if reset_generation is not None else "log_appended",
                "generation": reset_generation,
                "last_seq": self._log.last_seq(session_key),
            })
        return True

    @staticmethod
    def _scan_line_end(handle, scan_from: int, size: int) -> int | None:
        position = scan_from
        while position < size:
            handle.seek(position)
            chunk = handle.read(READ_CHUNK)
            if not chunk:
                return None
            found = chunk.find(b"\n")
            if found >= 0:
                return position + found + 1
            position += len(chunk)
        return None
