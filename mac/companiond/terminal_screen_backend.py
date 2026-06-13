from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Protocol


PENDING_INPUT_PARSER_VERSION = "terminal_pending_input_v2_2026_06_08"


@dataclass(frozen=True)
class TerminalCell:
    text: str
    width: int = 1
    fg: str = "default"
    bg: str = "default"
    bold: bool = False
    italic: bool = False
    underline: bool = False
    inverse: bool = False
    link_id: str | None = None


@dataclass(frozen=True)
class TerminalRow:
    index: int
    cells: tuple[TerminalCell, ...]
    wrapped: bool = False
    dirty_generation: int = 0


@dataclass(frozen=True)
class TerminalCursor:
    row: int | None
    column: int | None
    visible: bool = True
    style: str = "block"


def detect_terminal_pending_input(rows: list[str]) -> dict[str, Any] | None:
    choice_re = re.compile(r"^\s*(?P<selected>[>›]?)\s*(?P<id>\d+)[.)]\s+(?P<body>.+?)\s*$")
    choices: list[dict[str, Any]] = []
    prompt = ""
    for idx, row in enumerate(rows):
        match = choice_re.match(row)
        if not match:
            continue
        body = match.group("body").strip()
        label = body
        description = ""
        split = re.split(r"\s{2,}", body, maxsplit=1)
        if len(split) == 2:
            label, description = split[0].strip(), split[1].strip()
        choices.append({
            "id": match.group("id"),
            "label": label,
            "description": description,
            "selected": bool(match.group("selected")),
        })
        if not prompt:
            for prev in reversed(rows[:idx]):
                prev = prev.strip()
                if prev:
                    prompt = prev
                    break

    lowered = "\n".join(rows).lower()
    update_prompt = next((row.strip() for row in rows if "update available" in row.lower()), "")
    if update_prompt:
        return {
            "state": "maintenance_update",
            "confidence": "high" if choices else "medium",
            "prompt": update_prompt,
            "kind": "codex_update",
            "choices": choices,
        }

    if len(choices) >= 2:
        return {
            "state": "awaiting_selection",
            "confidence": "high",
            "prompt": prompt,
            "choices": choices,
        }

    if "press enter" in lowered or "confirm" in lowered:
        return {
            "state": "awaiting_confirmation",
            "confidence": "medium",
            "prompt": next((r.strip() for r in rows if r.strip()), ""),
            "choices": [],
        }

    text_prompt_markers = (
        "enter new goal",
        "new goal",
        "what should the goal be",
        "type your response",
        "resume from",
    )
    for row in rows:
        stripped = row.strip()
        lowered_row = stripped.lower()
        if not stripped:
            continue
        if any(marker in lowered_row for marker in text_prompt_markers) or (
            stripped.endswith(":") and any(marker in lowered for marker in ("goal", "resume", "prompt"))
        ):
            return {
                "state": "awaiting_text",
                "confidence": "medium",
                "prompt": stripped,
                "choices": [],
            }
    return None


@dataclass(frozen=True)
class TerminalScreenState:
    rows: int
    columns: int
    generation: int
    raw_offset: int
    source: str
    backend: str
    title: str | None
    alternate_screen: bool
    cursor: TerminalCursor
    visible_rows: tuple[TerminalRow, ...]
    dirty_row_indexes: tuple[int, ...]
    capabilities: tuple[str, ...]
    pending_input: dict[str, Any] | None = None
    pending_input_detection: dict[str, Any] | None = None
    degraded_reason: str | None = None
    links: dict[str, str] | None = None


class TerminalScreenBackend(Protocol):
    def feed(self, data: bytes, *, raw_offset: int) -> TerminalScreenState:
        ...

    def resize(self, rows: int, columns: int) -> TerminalScreenState:
        ...

    def snapshot(self) -> TerminalScreenState:
        ...

    def dirty_delta(self, *, since_generation: int) -> TerminalScreenState | None:
        ...


class VTScreenBackend:
    def __init__(self, screen: Any, *, source: str = "broker_vt", backend: str = "pty_broker") -> None:
        self.screen = screen
        self.source = source
        self.backend = backend
        self.generation = 0
        self.raw_offset = 0
        self._dirty_row_indexes: tuple[int, ...] = tuple(range(int(getattr(screen, "rows", 0) or 0)))

    def feed(self, data: bytes, *, raw_offset: int) -> TerminalScreenState:
        self.screen.feed(data)
        self.generation += 1
        self.raw_offset = max(self.raw_offset, int(raw_offset or 0))
        self._dirty_row_indexes = tuple(range(int(getattr(self.screen, "rows", 0) or 0)))
        return self.snapshot()

    def resize(self, rows: int, columns: int) -> TerminalScreenState:
        if hasattr(self.screen, "resize"):
            self.screen.resize(rows, columns)
        self.generation += 1
        self._dirty_row_indexes = tuple(range(int(getattr(self.screen, "rows", rows) or rows)))
        return self.snapshot()

    def snapshot(self) -> TerminalScreenState:
        if hasattr(self.screen, "cell_rows"):
            cell_rows = self.screen.cell_rows()
            text_rows = ["".join(str(cell.get("text", "")) for cell in row).rstrip() for row in cell_rows]
            row_count = int(getattr(self.screen, "rows", len(cell_rows)) or len(cell_rows))
            visible_rows = tuple(
                TerminalRow(
                    index=index,
                    cells=tuple(TerminalCell(**cell) for cell in row),
                    wrapped=bool(getattr(self.screen, "wrapped", [False] * len(cell_rows))[index]),
                    dirty_generation=self.generation,
                )
                for index, row in enumerate(cell_rows)
            )
        else:
            rows = list(self.screen.text_rows())
            text_rows = rows
            row_count = int(getattr(self.screen, "rows", len(rows)) or len(rows))
            visible_rows = tuple(
                TerminalRow(
                    index=index,
                    cells=tuple(TerminalCell(text=ch) for ch in row),
                    wrapped=False,
                    dirty_generation=self.generation,
                )
                for index, row in enumerate(rows)
            )
        capabilities = ["cells", "attributes", "cursor", "dirty_rows", "raw_offset", "control_receipts"]
        if getattr(self.screen, "title", None):
            capabilities.append("title")
        if getattr(self.screen, "links", None):
            capabilities.append("links")
        if getattr(self.screen, "alternate_screen", False):
            capabilities.append("alternate_screen")
        cursor = TerminalCursor(
            row=getattr(self.screen, "cursor_row", None),
            column=getattr(self.screen, "cursor_col", None),
            visible=True,
        )
        pending_input = detect_terminal_pending_input(text_rows)
        pending_detection = {
            "status": "ran",
            "parser_version": PENDING_INPUT_PARSER_VERSION,
            "surface": "v2",
            "confidence": pending_input.get("confidence") if pending_input else None,
            "reason": None,
        }
        return TerminalScreenState(
            rows=row_count,
            columns=int(getattr(self.screen, "columns", 0) or 0),
            generation=self.generation,
            raw_offset=self.raw_offset,
            source=self.source,
            backend=self.backend,
            title=getattr(self.screen, "title", None),
            alternate_screen=bool(getattr(self.screen, "alternate_screen", False)),
            cursor=cursor,
            visible_rows=visible_rows,
            dirty_row_indexes=self._dirty_row_indexes,
            capabilities=tuple(dict.fromkeys(capabilities)),
            pending_input=pending_input,
            pending_input_detection=pending_detection,
            links=dict(getattr(self.screen, "links", {}) or {}),
        )

    def dirty_delta(self, *, since_generation: int) -> TerminalScreenState | None:
        if self.generation <= int(since_generation or 0):
            return None
        return self.snapshot()


class DegradedTerminalScreenBackend:
    def __init__(self, fallback: TerminalScreenBackend, *, reason: str, requested_backend: str) -> None:
        self.fallback = fallback
        self.reason = reason
        self.requested_backend = requested_backend

    @property
    def generation(self) -> int:
        return int(getattr(self.fallback, "generation", 0) or 0)

    @property
    def raw_offset(self) -> int:
        return int(getattr(self.fallback, "raw_offset", 0) or 0)

    def feed(self, data: bytes, *, raw_offset: int) -> TerminalScreenState:
        return self._degrade(self.fallback.feed(data, raw_offset=raw_offset))

    def resize(self, rows: int, columns: int) -> TerminalScreenState:
        return self._degrade(self.fallback.resize(rows, columns))

    def snapshot(self) -> TerminalScreenState:
        return self._degrade(self.fallback.snapshot())

    def dirty_delta(self, *, since_generation: int) -> TerminalScreenState | None:
        state = self.fallback.dirty_delta(since_generation=since_generation)
        return self._degrade(state) if state is not None else None

    def _degrade(self, state: TerminalScreenState) -> TerminalScreenState:
        return TerminalScreenState(
            rows=state.rows,
            columns=state.columns,
            generation=state.generation,
            raw_offset=state.raw_offset,
            source=state.source,
            backend=state.backend,
            title=state.title,
            alternate_screen=state.alternate_screen,
            cursor=state.cursor,
            visible_rows=state.visible_rows,
            dirty_row_indexes=state.dirty_row_indexes,
            capabilities=state.capabilities,
            pending_input=state.pending_input,
            pending_input_detection=state.pending_input_detection,
            degraded_reason=self.reason,
            links=state.links,
        )


class PyteScreenBackend:
    def __init__(self, *, rows: int, columns: int, source: str = "broker_vt", backend: str = "pyte") -> None:
        if importlib.util.find_spec("pyte") is None or importlib.util.find_spec("wcwidth") is None:
            raise RuntimeError("parser_backend_unavailable")
        raise NotImplementedError("pyte backend is not selected until packaging proof exists")


def create_terminal_screen_backend(screen: Any, *, backend_name: str | None = None) -> TerminalScreenBackend:
    requested = (backend_name or os.environ.get("PAIRLING_TERMINAL_BACKEND") or "vt").strip().lower()
    fallback = VTScreenBackend(screen)
    if requested in {"", "vt", "vtscreen", "pty_broker"}:
        return fallback
    if requested == "pyte":
        try:
            return PyteScreenBackend(
                rows=int(getattr(screen, "rows", 30) or 30),
                columns=int(getattr(screen, "columns", 120) or 120),
            )
        except (RuntimeError, NotImplementedError):
            return DegradedTerminalScreenBackend(
                fallback,
                reason="parser_backend_unavailable",
                requested_backend="pyte",
            )
    return DegradedTerminalScreenBackend(
        fallback,
        reason="parser_backend_unavailable",
        requested_backend=requested,
    )


def semantic_hash(material: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
