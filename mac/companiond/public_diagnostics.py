#!/usr/bin/env python3
"""Redact secrets from public, audit, and support diagnostics.

This module is deliberately not used for terminal, transcript, or file payloads.
Stable API objects should use explicit allowlists instead; this redactor is the
last boundary for unstructured diagnostic values and exception text.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_REDACTED = "[REDACTED]"
_CAMEL_ACRONYM_BOUNDARY = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL_WORD_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
_SECRET_KEY = re.compile(
    r"(?:^|_)(?:authorization|auth|bearer|credentials?|password|secret|token|"
    r"api_?key|apns_?key|pair(?:ing)?_?(?:code|proof|secret|token)|"
    r"request_?proof|control_?proof|screen_?hash|private_?key|access_?key|nonce|"
    r"tailscale(?:_?(?:key|token))?|tskey|signature|signed_?url)"
    r"(?:$|_(?:bytes|data|digest|hash|header|id|material|proof|ref|reference|"
    r"signature|text|url|value)$)",
    re.IGNORECASE,
)
_LOCAL_PATH = re.compile(
    r"(?<![A-Za-z0-9])(?:file://)?(?:~/(?:[^\s\"'<>]+)|"
    r"/(?:Users|private|Volumes|var|tmp|home|Applications|Library|System|"
    r"opt|usr|etc)/(?:[^\s\"'<>]+))"
)
_AUTHORIZATION = re.compile(
    r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_TAILSCALE_KEY = re.compile(r"\btskey-[A-Za-z0-9-]{8,}\b", re.IGNORECASE)
_PROVIDER_KEY = re.compile(
    r"\b(?:sk|pk|rk|ghp|github_pat|xox[baprs]|AIza)[-_A-Za-z0-9]{12,}\b"
)
_NAMED_SECRET = re.compile(
    r"(?i)\b((?:pair(?:ing)?(?:[_ -]?(?:code|proof|secret|token))|"
    r"api[_ -]?key|apns[_ -]?token|tailscale[_ -]?(?:key|token)|"
    r"screen[_ -]?hash|nonce)\s*[:=]\s*)[^\s,;]+"
)
_SIGNED_QUERY_KEY = re.compile(
    r"(?i)(?:^|&)(?:x-amz-(?:signature|credential|security-token)|"
    r"signature|sig|token|access_token|auth|key|expires)="
)
_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _redact_url(match: re.Match[str]) -> str:
    raw = match.group(0)
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return _REDACTED
    tailscale_login = parsed.hostname == "login.tailscale.com"
    if tailscale_login:
        return f"{parsed.scheme}://{parsed.netloc}/[REDACTED]"
    if parsed.query and _SIGNED_QUERY_KEY.search(parsed.query):
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "[REDACTED]", ""))
    return raw


def redact_public_text(value: str) -> str:
    """Redact secret-shaped fragments from one diagnostic string."""

    text = str(value)
    text = _URL.sub(_redact_url, text)
    text = _AUTHORIZATION.sub(lambda match: match.group(1) + _REDACTED, text)
    text = _BEARER.sub("Bearer " + _REDACTED, text)
    text = _TAILSCALE_KEY.sub(_REDACTED, text)
    text = _PROVIDER_KEY.sub(_REDACTED, text)
    text = _NAMED_SECRET.sub(lambda match: match.group(1) + _REDACTED, text)
    return _LOCAL_PATH.sub(_REDACTED, text)


def _is_secret_key(value: str) -> bool:
    normalized = _CAMEL_ACRONYM_BOUNDARY.sub(r"\1_\2", value)
    normalized = _CAMEL_WORD_BOUNDARY.sub(r"\1_\2", normalized)
    normalized = re.sub(r"[^a-z0-9]+", "_", normalized.casefold()).strip("_")
    return bool(_SECRET_KEY.search(normalized))


def redact_public_diagnostic(value: Any, *, _key: str = "") -> Any:
    """Recursively redact a JSON-shaped public diagnostic value."""

    if _key and _is_secret_key(_key):
        return None if value is None else _REDACTED
    if isinstance(value, Mapping):
        return {
            str(key): redact_public_diagnostic(item, _key=str(key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_public_diagnostic(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_public_diagnostic(item) for item in value)
    if isinstance(value, str):
        return redact_public_text(value)
    return value
