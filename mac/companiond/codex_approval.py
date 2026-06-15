from __future__ import annotations

import re
from typing import Any


_APPROVAL_HEADER = re.compile(r"would you like to run|allow .* to run|run the following command", re.I)
_CMD_LINE = re.compile(r"^\s*\$\s+(?P<cmd>.+?)\s*$")
_RAW_YES = re.compile(r"(?:^|\s|[>›])1[.)]\s*Yes(?:,\s*)?\s*proceed\b|Yes,\s*proceed", re.I)
_PATCH_HINT = re.compile(r"\b(apply_patch|patch|modify|edit|write)\b", re.I)


def classify_codex_approval(pending: dict[str, Any] | None, rows: list[str], *, screen_key: str = "") -> dict[str, Any] | None:
    if pending and pending.get("state") not in {None, "awaiting_selection"}:
        return None
    rows = [str(row or "") for row in rows]
    choices = (pending or {}).get("choices") or []
    if not isinstance(choices, list):
        choices = []
    has_yes = any(_choice_is_yes_proceed(choice) for choice in choices if isinstance(choice, dict))
    raw_yes = any(_RAW_YES.search(row) for row in rows)
    if not has_yes:
        has_yes = raw_yes
    if not has_yes:
        return None

    header = any(_APPROVAL_HEADER.search(row) for row in rows)
    command = _extract_command(rows)
    patch_hint = any(_PATCH_HINT.search(row) for row in rows)
    if not header and not command and not patch_hint:
        return None

    summary = command or _approval_summary(rows, pending) or "codex approval"
    return {
        "command": command,
        "summary": summary[:300],
        "kind": "codex_exec_approval",
        "choices": choices,
        "dialog_key": screen_key,
    }


def _choice_is_yes_proceed(choice: dict[str, Any]) -> bool:
    label = str(choice.get("label") or "").strip().lower()
    choice_id = str(choice.get("id") or "").strip()
    return label.startswith("yes") and ("proceed" in label or choice_id == "1")


def _extract_command(rows: list[str]) -> str | None:
    for row in rows:
        match = _CMD_LINE.match(row or "")
        if match:
            command = match.group("cmd").strip()
            if command:
                return command[:300]
    return None


def _approval_summary(rows: list[str], pending: dict[str, Any] | None) -> str | None:
    prompt = str((pending or {}).get("prompt") or "").strip()
    if prompt:
        return prompt[:300]
    for row in rows:
        text = str(row or "").strip()
        if not text:
            continue
        if _APPROVAL_HEADER.search(text) or _PATCH_HINT.search(text):
            return text[:300]
    return None
