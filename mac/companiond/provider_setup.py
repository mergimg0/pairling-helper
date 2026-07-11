#!/usr/bin/env python3
"""pairling setup's provider detection seam (SPEC-p1 §2.3).

Subcommands:
  table    print detected providers: id · version · depth wording · state
  current  print the comma-separated excluded ids (empty when none)
  apply    record exclusions declaratively: --exclude "codex,aider"
           (--exclude "" includes everything)

Depth is internal and automatic; the table prints it as honest wording
("recognized, not yet controllable"), never as a permission. Exclusion hides
a provider from Pairling surfaces and never touches the provider's own
config or processes (Law 3). This CLI never prompts — interactivity belongs
to the wizard that calls it.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from providers import registry_data, visibility  # noqa: E402
from providers.base import cli_version, is_valid_provider_id, normalize_provider_id, resolve_executable  # noqa: E402


DEPTH_WORDING = {
    "deep": "deep · full control",
    "standard": "standard · full control (raw terminal)",
    "recognized": "recognized · not yet controllable",
}


def _detect(home: Path, entries):
    detected = []
    missing = []
    for entry in entries:
        resolved = resolve_executable(
            entry.binary_name,
            registry_data.candidate_paths(entry, home=home),
            env_var=entry.env_override,
        )
        if resolved is None:
            missing.append(entry.provider_id)
            continue
        version = cli_version(resolved.path, list(entry.version_command)) or "version unknown"
        detected.append((entry, version))
    return detected, missing


def cmd_table(home: Path) -> int:
    entries = registry_data.load_entries()
    if not entries:
        # An empty registry means the data file is missing or invalid — say
        # so instead of claiming "nothing detected" (disclosure test).
        print("provider registry data unavailable (registry-data.json missing or invalid)", file=sys.stderr)
        return 1
    excluded = visibility.read_excluded(home=home)
    detected, missing = _detect(home, entries)
    if not detected:
        print("  No coding agents detected on this Mac.")
    else:
        print(f"  {'provider':<14}{'version':<28}{'access':<40}{'visibility'}")
        for entry, version in detected:
            state = "excluded" if entry.provider_id in excluded else "included"
            wording = DEPTH_WORDING.get(entry.adapter_depth, entry.adapter_depth)
            print(f"  {entry.provider_id:<14}{version[:26]:<28}{wording:<40}{state}")
    if missing:
        print(f"  not detected: {', '.join(sorted(missing))}")
    return 0


def cmd_current(home: Path) -> int:
    print(",".join(sorted(visibility.read_excluded(home=home))))
    return 0


def cmd_apply(home: Path, exclude: str) -> int:
    wanted: set[str] = set()
    for raw in (exclude or "").split(","):
        item = normalize_provider_id(raw)
        if not item:
            continue
        if not is_valid_provider_id(item):
            print(f"invalid provider id: {raw.strip()}", file=sys.stderr)
            return 2
        wanted.add(item)
    known = {entry.provider_id for entry in registry_data.load_entries()}
    unknown = sorted(wanted - known)
    if unknown:
        print(f"unknown providers: {', '.join(unknown)} (known: {', '.join(sorted(known))})", file=sys.stderr)
        return 2
    visibility.write_excluded(wanted, home=home)
    recorded = sorted(visibility.read_excluded(home=home))
    if recorded:
        print(f"excluded: {','.join(recorded)}")
    else:
        print("all providers included")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["table", "current", "apply"])
    parser.add_argument("--exclude", default=None, help="comma-separated provider ids for apply")
    parser.add_argument("--home", default=None, help="override the home directory (testing seam)")
    args = parser.parse_args(argv)
    home = Path(args.home).expanduser() if args.home else Path.home()
    if args.command == "table":
        return cmd_table(home)
    if args.command == "current":
        return cmd_current(home)
    if args.exclude is None:
        print("apply requires --exclude (use --exclude \"\" to include everything)", file=sys.stderr)
        return 2
    return cmd_apply(home, args.exclude)


if __name__ == "__main__":
    raise SystemExit(main())
