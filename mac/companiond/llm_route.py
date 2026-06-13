#!/usr/bin/env python3
"""Local provider CLI runner shared by /llm-route and Pairling tools."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


HOME = Path.home()


@dataclass(frozen=True)
class LLMRouteError(Exception):
    code: str
    message: str
    status: int = 502

    def __str__(self) -> str:
        return self.message


def llm_route_model_family(model: str) -> str | None:
    if model in ("sonnet", "haiku", "opus"):
        return "claude"
    if model in ("gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex"):
        return "codex"
    return None


def find_executable(candidates: list[Path | str]) -> Path | None:
    for candidate in candidates:
        path = Path(candidate)
        if path.exists() and os.access(path, os.X_OK):
            return path
    return None


def run_local_llm(
    *,
    model: str,
    prompt: str,
    system: str | None = None,
    timeout_seconds: int = 120,
) -> str:
    family = llm_route_model_family(model)
    if family is None:
        raise LLMRouteError(
            "invalid_model",
            "model must be sonnet|haiku|opus|gpt-5.5|gpt-5.4|gpt-5.4-mini|gpt-5.3-codex",
            400,
        )

    if family == "claude":
        cli = find_executable([
            HOME / ".local" / "bin" / "claude",
            "/opt/homebrew/bin/claude",
            "/usr/local/bin/claude",
        ])
        if cli is None:
            raise LLMRouteError("claude_cli_not_found", "claude CLI not found", 502)
        cmd = [
            str(cli), "-p",
            "--output-format", "text",
            "--model", model,
            "--dangerously-skip-permissions",
        ]
        if system:
            cmd.extend(["--append-system-prompt", system])
        full_prompt = prompt
    else:
        cli = find_executable([
            HOME / ".local" / "bin" / "codex",
            "/opt/homebrew/bin/codex",
            "/usr/local/bin/codex",
        ])
        if cli is None:
            raise LLMRouteError("codex_cli_not_found", "codex CLI not found", 502)
        cmd = [
            str(cli), "exec",
            "--ephemeral",
            "--skip-git-repo-check",
            "--model", model,
            "--sandbox", "read-only",
            "--ask-for-approval", "never",
            "-C", "/tmp",
            "-",
        ]
        full_prompt = f"System instructions:\n{system}\n\nUser prompt:\n{prompt}" if system else prompt

    try:
        proc = subprocess.run(
            cmd,
            input=full_prompt,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd="/tmp",
        )
    except subprocess.TimeoutExpired as exc:
        raise LLMRouteError(f"{family}_cli_timeout", f"{family} CLI timeout", 504) from exc

    if proc.returncode != 0:
        err = (proc.stderr or "").strip()[:500]
        raise LLMRouteError(f"{family}_cli_failed", f"{family} CLI failed: {err}", 502)
    return (proc.stdout or "").strip()
