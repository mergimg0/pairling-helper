#!/usr/bin/env python3
"""Run the explicit local setup sequence for Pairling Terminal permissions.

This module is an installer-only bridge. It is the sole code path that creates a
short-lived local capability and asks the stable, launchd-managed Pairling helper
to show macOS consent UI. Remote daemon requests never import or invoke it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

from automation_helper_lifecycle import HelperLifecycleError, issue_setup_capability


ROOT = Path(__file__).resolve().parents[2]
for _candidate in (ROOT / "companiond", ROOT / "mac" / "companiond"):
    if _candidate.is_dir():
        sys.path.insert(0, str(_candidate))
        break

from pairling_automation import (  # noqa: E402
    AutomationHelperClient,
    AutomationHelperError,
    terminal_permission_failure_summary,
    terminal_permissions_summary,
)


def _unavailable_summary(error: Exception) -> dict[str, Any]:
    if isinstance(error, AutomationHelperError):
        return terminal_permission_failure_summary(
            code=error.code,
            safe_message=error.safe_message,
        )
    return terminal_permission_failure_summary(
        code="automation_helper_unreachable",
        safe_message="Pairling could not verify Mac permissions.",
    )


def current_terminal_permissions(
    *,
    client: AutomationHelperClient | None = None,
) -> dict[str, Any]:
    """Return the helper's non-prompting Terminal capability summary."""

    return terminal_permissions_summary(fresh=True, client=client)


def request_terminal_permissions(
    automation_root: Path,
    *,
    client: AutomationHelperClient | None = None,
    issue_capability: Callable[[Path], str] = issue_setup_capability,
) -> dict[str, Any]:
    """Request consent through the stable helper during explicit local setup."""

    helper_client = client or AutomationHelperClient(root=automation_root)
    try:
        capability = issue_capability(automation_root)
        helper_client.probe(prompt=True, setup_capability=capability)
    except (AutomationHelperError, HelperLifecycleError) as exc:
        return _unavailable_summary(exc)
    return current_terminal_permissions(client=helper_client)


def probe_terminal_permissions(
    *,
    client: AutomationHelperClient | None = None,
) -> dict[str, Any]:
    """Run a non-prompting harmless Terminal probe and return fresh status."""

    helper_client = client or AutomationHelperClient()
    try:
        helper_client.probe(prompt=False)
    except AutomationHelperError as exc:
        return _unavailable_summary(exc)
    return current_terminal_permissions(client=helper_client)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("status", "request", "probe"))
    parser.add_argument("--app-support", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    automation_root = args.app_support / "automation"
    if args.command == "status":
        summary = current_terminal_permissions(
            client=AutomationHelperClient(root=automation_root)
        )
    elif args.command == "request":
        summary = request_terminal_permissions(automation_root)
    elif args.command == "probe":
        summary = probe_terminal_permissions(
            client=AutomationHelperClient(root=automation_root)
        )
    else:  # argparse keeps this unreachable.
        raise AssertionError(f"unhandled command: {args.command}")
    print(
        json.dumps(
            {
                "schema_version": 1,
                "operation": args.command,
                "terminal_capability": summary,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
