from __future__ import annotations


TERMINAL_TEXT_MAX_CHARS = 8000
TERMINAL_TEXT_SUBMIT_MAX_CHARS = 2000
_BRACKETED_PASTE_START = "\x1b[200~"
_BRACKETED_PASTE_END = "\x1b[201~"
_BIDI_CONTROL_CODES = {
    0x061C,  # Arabic Letter Mark
    0x200E,  # Left-to-Right Mark
    0x200F,  # Right-to-Left Mark
    *range(0x202A, 0x202F),  # bidi embedding/override/pop controls
    *range(0x2066, 0x206A),  # bidi isolate/pop controls
}


def terminal_text_rejection_reason(text: str, *, allow_newline: bool) -> tuple[str, str] | None:
    if _BRACKETED_PASTE_START in text or _BRACKETED_PASTE_END in text:
        return "bracketed_paste_delimiter", "bracketed paste delimiters are not accepted from clients"
    for ch in text:
        code = ord(ch)
        if ch == "\n":
            if allow_newline:
                continue
            return "multi_line_text", "terminal text must be single-line"
        if ch == "\t" and allow_newline:
            continue
        if code == 0x1B:
            return "escape_not_allowed", "ESC is not accepted in terminal text"
        if code in _BIDI_CONTROL_CODES:
            return "bidi_control_not_allowed", "Unicode bidi controls are not accepted in terminal text"
        if code < 0x20:
            return "c0_not_allowed", "C0 control characters are not accepted in terminal text"
        if code == 0x7F or 0x80 <= code <= 0x9F:
            return "c1_or_del_not_allowed", "DEL and C1 control characters are not accepted in terminal text"
    return None


def sanitize_terminal_text_input(
    text: str,
    *,
    allow_newline: bool,
    max_chars: int,
) -> tuple[str | None, dict | None]:
    rejection = terminal_text_rejection_reason(text, allow_newline=allow_newline)
    if rejection:
        code, message = rejection
        return None, {"code": code, "message": message, "status": 400}
    cleaned = text.strip()
    if not cleaned:
        return None, {"code": "empty_text", "message": "terminal text cannot be empty", "status": 400}
    if len(cleaned) > max_chars:
        return None, {"code": "text_too_long", "message": f"terminal text exceeds {max_chars} chars", "status": 413}
    return cleaned, None
