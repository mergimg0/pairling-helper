from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
from collections import deque
from dataclasses import dataclass, replace
from typing import Any, Protocol


PENDING_INPUT_PARSER_VERSION = "terminal_pending_input_v3_2026_07_16"
TERMINAL_TITLE_MAX_CHARS = 1024
TERMINAL_LINK_URI_MAX_CHARS = 4096
TERMINAL_LINK_ID_MAX_CHARS = 64
TERMINAL_SCREEN_STATE_MAX_LINKS = 256


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
    choice_re = re.compile(r"^\s*(?P<selected>[>›❯]?)\s*(?P<id>\d+)[.)]\s+(?P<body>.+?)\s*$")
    active_progress_re = re.compile(
        r"^[•✻].*\besc to interrupt\b.*$",
        re.IGNORECASE,
    )

    def has_later_active_progress(index: int) -> bool:
        return any(
            active_progress_re.fullmatch(row.strip())
            for row in rows[index + 1:]
            if row.strip()
        )

    choices: list[dict[str, Any]] = []
    choice_indexes: list[int] = []
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
        choice_indexes.append(idx)
        if not prompt:
            for prev in reversed(rows[:idx]):
                prev = prev.strip()
                if prev:
                    prompt = prev
                    break

    choice_ids = [int(choice["id"]) for choice in choices]
    consecutive_choices = choice_ids == list(range(1, len(choice_ids) + 1))
    has_choice_cursor = any(choice["selected"] for choice in choices)

    update_pattern = re.compile(r"^update available(?:\s*:\s*.+)?$", re.IGNORECASE)
    update_match = next(
        (
            (index, row.strip())
            for index, row in enumerate(rows)
            if update_pattern.fullmatch(row.strip()) and not has_later_active_progress(index)
        ),
        None,
    )
    if update_match and len(choices) >= 2 and consecutive_choices and has_choice_cursor:
        return {
            "state": "maintenance_update",
            "confidence": "high",
            "prompt": update_match[1],
            "kind": "codex_update",
            "choices": choices,
        }

    # A real selector, not a coincidence of numbered text: code listings,
    # line-numbered output, and ordered prose all match the per-line choice
    # shape. Require the ids to be the consecutive run 1..n and either an
    # explicit selection cursor or a question-shaped prompt line before
    # treating the screen as awaiting a selection.
    if len(choices) >= 2:
        question_prompt = prompt.rstrip().endswith("?")
        if (
            consecutive_choices
            and (has_choice_cursor or question_prompt)
            and not has_later_active_progress(max(choice_indexes))
        ):
            return {
                "state": "awaiting_selection",
                "confidence": "high",
                "prompt": prompt,
                "choices": choices,
            }

    confirmation_patterns = (
        re.compile(r"^press enter(?:\s+to\s+(?:confirm|continue|proceed))?\s*[.!]?$", re.IGNORECASE),
        re.compile(r"^confirm to continue\s*[.!]?$", re.IGNORECASE),
    )
    confirmation_match = next(
        (
            (index, row.strip())
            for index, row in enumerate(rows)
            if any(pattern.fullmatch(row.strip()) for pattern in confirmation_patterns)
            and not has_later_active_progress(index)
        ),
        None,
    )
    if confirmation_match:
        return {
            "state": "awaiting_confirmation",
            "confidence": "medium",
            "prompt": confirmation_match[1],
            "choices": [],
        }

    text_prompt_patterns = (
        re.compile(r"^enter (?:a )?new goal\s*:\s*$", re.IGNORECASE),
        re.compile(r"^new goal\s*:\s*$", re.IGNORECASE),
        re.compile(r"^what should the (?:new )?goal be\s*[:?]\s*$", re.IGNORECASE),
        re.compile(r"^type your response\s*:\s*$", re.IGNORECASE),
        re.compile(r"^resume from\s*:\s*$", re.IGNORECASE),
    )
    for index, row in enumerate(rows):
        stripped = row.strip()
        if not stripped:
            continue
        if (
            any(pattern.fullmatch(stripped) for pattern in text_prompt_patterns)
            and not has_later_active_progress(index)
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


def _bounded_terminal_text(value: Any, *, max_chars: int) -> str | None:
    if value is None:
        return None
    text = str(value)
    if len(text) > max_chars:
        return None
    return text


def _bounded_screen_links(
    visible_rows: tuple[TerminalRow, ...],
    raw_links: Any,
) -> dict[str, str]:
    if not isinstance(raw_links, dict):
        return {}
    bounded: dict[str, str] = {}

    def remember(raw_link_id: Any) -> None:
        if raw_link_id is None or len(bounded) >= TERMINAL_SCREEN_STATE_MAX_LINKS:
            return
        link_id = str(raw_link_id)
        if not link_id or len(link_id) > TERMINAL_LINK_ID_MAX_CHARS or link_id in bounded:
            return
        raw_uri = raw_links.get(link_id)
        if raw_uri is None:
            return
        uri = str(raw_uri)
        if len(uri) > TERMINAL_LINK_URI_MAX_CHARS:
            return
        bounded[link_id] = uri

    # Preserve every mapping referenced by the live grid first. Any remaining
    # budget holds the newest mappings so recent scrollback links still work.
    for row in visible_rows:
        for cell in row.cells:
            remember(cell.link_id)
            if len(bounded) >= TERMINAL_SCREEN_STATE_MAX_LINKS:
                return bounded
    for link_id in reversed(raw_links):
        remember(link_id)
        if len(bounded) >= TERMINAL_SCREEN_STATE_MAX_LINKS:
            break
    return bounded


class VTScreenBackend:
    # Generations of dirty-row history retained for delta requests; a client
    # further behind than this receives a full delta (all rows) instead.
    DIRTY_HISTORY_GENERATIONS = 1024

    def __init__(self, screen: Any, *, source: str = "broker_vt", backend: str = "pty_broker") -> None:
        self.screen = screen
        self.source = source
        self.backend = backend
        self.generation = 0
        self.raw_offset = 0
        self._dirty_row_indexes: tuple[int, ...] = tuple(range(int(getattr(screen, "rows", 0) or 0)))
        self._dirty_history: deque[tuple[int, tuple[int, ...]]] = deque(maxlen=self.DIRTY_HISTORY_GENERATIONS)

    def _consume_screen_dirty(self) -> tuple[int, ...]:
        consume = getattr(self.screen, "consume_dirty", None)
        if callable(consume):
            return tuple(consume())
        return tuple(range(int(getattr(self.screen, "rows", 0) or 0)))

    def feed(self, data: bytes, *, raw_offset: int) -> TerminalScreenState:
        self.screen.feed(data)
        self.generation += 1
        self.raw_offset = max(self.raw_offset, int(raw_offset or 0))
        self._dirty_row_indexes = self._consume_screen_dirty()
        self._dirty_history.append((self.generation, self._dirty_row_indexes))
        return self.snapshot()

    def resize(self, rows: int, columns: int) -> TerminalScreenState:
        if hasattr(self.screen, "resize"):
            self.screen.resize(rows, columns)
        self.generation += 1
        self._dirty_row_indexes = self._consume_screen_dirty()
        self._dirty_history.append((self.generation, self._dirty_row_indexes))
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
        title = _bounded_terminal_text(
            getattr(self.screen, "title", None),
            max_chars=TERMINAL_TITLE_MAX_CHARS,
        )
        links = _bounded_screen_links(visible_rows, getattr(self.screen, "links", None))
        capabilities = ["cells", "attributes", "cursor", "dirty_rows", "raw_offset", "control_receipts"]
        if title:
            capabilities.append("title")
        if links:
            capabilities.append("links")
        if getattr(self.screen, "alternate_screen", False):
            capabilities.append("alternate_screen")
        cursor = TerminalCursor(
            row=getattr(self.screen, "cursor_row", None),
            column=getattr(self.screen, "cursor_col", None),
            visible=bool(getattr(self.screen, "cursor_visible", True)),
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
            title=title,
            alternate_screen=bool(getattr(self.screen, "alternate_screen", False)),
            cursor=cursor,
            visible_rows=visible_rows,
            dirty_row_indexes=self._dirty_row_indexes,
            capabilities=tuple(dict.fromkeys(capabilities)),
            pending_input=pending_input,
            pending_input_detection=pending_detection,
            links=links,
        )

    def dirty_delta(self, *, since_generation: int) -> TerminalScreenState | None:
        """State whose dirty_row_indexes is exactly the union of rows changed
        after since_generation. None when nothing changed. When the request
        predates retained history, every row reports dirty, which is a
        correct (full) delta rather than a silent gap."""
        since = int(since_generation or 0)
        if self.generation <= since:
            return None
        history = list(self._dirty_history)
        rows = int(getattr(self.screen, "rows", 0) or 0)
        if not history or history[0][0] > since + 1:
            union: set[int] = set(range(rows))
        else:
            union = set()
            for generation, dirty in history:
                if generation > since:
                    union.update(dirty)
        state = self.snapshot()
        return replace(state, dirty_row_indexes=tuple(sorted(index for index in union if index < rows)))


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
