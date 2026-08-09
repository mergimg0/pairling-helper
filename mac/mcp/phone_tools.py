#!/usr/bin/env python3
"""Pairling daemon-first MCP bridge for phone-tools."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import re
import sys
import time
from urllib.parse import urlparse
import uuid
from pathlib import Path
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except Exception as exc:  # pragma: no cover - exercised only in a broken MCP env
    print(f"FATAL: cannot import FastMCP: {exc}", file=sys.stderr)
    raise


PAIRLING_TOOLS_BASE_URL = os.environ.get("PAIRLING_TOOLS_BASE_URL", "http://127.0.0.1:7773").rstrip("/")
PAIRLING_TOOLS_TIMEOUT = float(os.environ.get("PAIRLING_TOOLS_TIMEOUT", "15"))
PAIRLING_MCP_CREDENTIAL = Path(
    os.environ.get(
        "PAIRLING_MCP_CREDENTIAL",
        str(Path.home() / "Library" / "Application Support" / "Pairling" / "mcp-bridge.json"),
    )
)

INSTALL_ID_HEADER = "Pairling-Install-ID"
REQUEST_ID_HEADER = "Pairling-Request-ID"
TIMESTAMP_HEADER = "Pairling-Timestamp"
BODY_SHA256_HEADER = "Pairling-Body-SHA256"
PROOF_HEADER = "Pairling-Proof"
AGENT_PROVIDER_PATTERN = re.compile(r"\A[a-z0-9_-]{1,48}\Z")
SESSION_IDENTITY_PATTERN = re.compile(r"\A[A-Za-z0-9._:-]{1,160}\Z")


class PairlingToolsClient:
    def __init__(
        self,
        *,
        base_url: str = PAIRLING_TOOLS_BASE_URL,
        credential_path: Path = PAIRLING_MCP_CREDENTIAL,
        timeout: float = PAIRLING_TOOLS_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.credential_path = credential_path
        self.timeout = timeout

    def run(self, tool: str, input_payload: dict[str, Any], *, strategy: str = "auto") -> str:
        request_payload: dict[str, Any] = {
            "tool": tool,
            "input": input_payload,
            "strategy": strategy,
        }
        request_payload.update(_agent_context_from_environment())
        body = json.dumps(request_payload, separators=(",", ":")).encode("utf-8")
        credential = self._load_credential()
        url = self.base_url + "/pairling-tools/run"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + credential["token"],
            **_proof_headers(
                credential=credential,
                method="POST",
                path_and_query="/pairling-tools/run",
                body=body,
            ),
        }
        try:
            status, reason, payload = self._post_json(url, body, headers)
        except Exception as exc:
            return f"[phone-tools] Pairling tools unavailable: cannot reach Pairling daemon at {self.base_url}: {type(exc).__name__}: {exc}"
        if not isinstance(payload, dict):
            return f"[phone-tools] Pairling tools unavailable: HTTP {status}: {reason}"

        if payload.get("ok"):
            return str(payload.get("result") or "")
        error = payload.get("error") if isinstance(payload.get("error"), dict) else {}
        message = error.get("message") or error.get("code") or "unknown error"
        iphone_reason = error.get("iphone_reason")
        mac_reason = error.get("mac_reason")
        detail = ""
        if iphone_reason or mac_reason:
            detail = f" iPhone={iphone_reason or 'not_attempted'} Mac={mac_reason or 'not_attempted'}."
        return f"[phone-tools] Pairling tools unavailable: {message}.{detail}"

    def _post_json(self, url: str, body: bytes, headers: dict[str, str]) -> tuple[int, str, dict[str, Any] | None]:
        parsed = urlparse(url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise RuntimeError("Pairling MCP adapter only connects to the local Pairling daemon")
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        conn = http.client.HTTPConnection(parsed.hostname, port, timeout=self.timeout)
        try:
            conn.request("POST", path, body=body, headers=headers)
            response = conn.getresponse()
            raw = response.read()
        finally:
            conn.close()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            payload = None
        return response.status, response.reason, payload

    def _load_credential(self) -> dict[str, str]:
        try:
            payload = json.loads(self.credential_path.read_text())
        except Exception as exc:
            raise RuntimeError(
                f"Pairling MCP bridge credential is missing. Run `pairling setup` or `pairling doctor --json`: {exc}"
            ) from exc
        required = ("device_id", "install_id", "token", "proof_secret")
        missing = [key for key in required if not str(payload.get(key) or "").strip()]
        if missing:
            raise RuntimeError("Pairling MCP bridge credential is incomplete: " + ", ".join(missing))
        return {key: str(payload[key]) for key in required}


def _agent_context_from_environment(
    environ: dict[str, str] | None = None,
) -> dict[str, str]:
    """Return only agent identity the launching MCP process states directly."""
    values = os.environ if environ is None else environ
    explicit_provider = str(values.get("PAIRLING_AGENT_PROVIDER") or "").strip().lower()
    explicit_session = str(values.get("PAIRLING_AGENT_SESSION_ID") or "").strip()

    provider = explicit_provider if AGENT_PROVIDER_PATTERN.fullmatch(explicit_provider) else ""
    session_identity = explicit_session if SESSION_IDENTITY_PATTERN.fullmatch(explicit_session) else ""
    if not provider and not session_identity:
        codex_thread = str(values.get("CODEX_THREAD_ID") or "").strip()
        claude_session = str(
            values.get("CLAUDE_CODE_SESSION_ID")
            or values.get("CLAUDE_SESSION_ID")
            or ""
        ).strip()
        if SESSION_IDENTITY_PATTERN.fullmatch(codex_thread):
            provider = "codex"
            session_identity = codex_thread
        elif SESSION_IDENTITY_PATTERN.fullmatch(claude_session):
            provider = "claude"
            session_identity = claude_session

    context: dict[str, str] = {}
    if provider:
        context["agent_provider"] = provider
    if session_identity:
        context["session_identity"] = session_identity
    return context


def _proof_headers(*, credential: dict[str, str], method: str, path_and_query: str, body: bytes) -> dict[str, str]:
    timestamp_ms = str(int(time.time() * 1000))
    request_id = str(uuid.uuid4()).lower()
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = "\n".join([
        method.upper(),
        path_and_query,
        timestamp_ms,
        request_id,
        body_hash,
        credential["install_id"],
        credential["device_id"],
    ])
    proof = hmac.new(
        credential["proof_secret"].encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        INSTALL_ID_HEADER: credential["install_id"],
        REQUEST_ID_HEADER: request_id,
        TIMESTAMP_HEADER: timestamp_ms,
        BODY_SHA256_HEADER: body_hash,
        PROOF_HEADER: proof,
    }




CLIENT = PairlingToolsClient()
mcp = FastMCP("phone-tools")


@mcp.tool()
def second_opinion(claim: str) -> str:
    """Get a skeptical second opinion on a claim."""
    return CLIENT.run("second_opinion", {"claim": claim})


@mcp.tool()
def vibe_check(draft: str) -> str:
    """Check whether a piece of writing matches the user's typical voice."""
    return CLIENT.run("vibe_check", {"draft": draft})


@mcp.tool()
def user_likely_prefers(option_a: str, option_b: str) -> str:
    """Predict which of two options the user is likely to prefer."""
    return CLIENT.run("user_likely_prefers", {"option_a": option_a, "option_b": option_b})


@mcp.tool()
def corpus_recall(query: str) -> str:
    """Search the user's past Pairling-accessible local session corpus."""
    return CLIENT.run("corpus_recall", {"query": query})


if __name__ == "__main__":
    mcp.run()
