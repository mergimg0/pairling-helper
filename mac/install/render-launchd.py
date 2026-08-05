#!/usr/bin/env python3
"""Render Pairling launchd plists with absolute runtime paths."""

from __future__ import annotations
import json
import os
import re
import stat
import subprocess

import argparse
import plistlib
from pathlib import Path

PAIRLING_DAEMON_LABEL = "dev.pairling.companiond"
PAIRLING_CONNECTD_LABEL = "dev.pairling.connectd"
PAIRLING_PTYBROKER_LABEL = "dev.pairling.ptybroker"
PAIRLING_RUNTIME_PORT = "7773"
PAIRLING_RELAY_CLAIM_PUBLIC_KEY = "relay-claim-2026-07-v1.pem"
COPILOT_SDK_VERSION = "1.0.8"
COPILOT_CLI_VERSION = "1.0.78"


def canonical_pairdrop_root(value: Path | str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError("PairDrop root must be an absolute path")
    return path.resolve(strict=False)
def verified_claude_agent_sdk_root() -> Path | None:
    raw = os.environ.get("PAIRLING_CLAUDE_AGENT_SDK_ROOT")
    if not raw:
        return None
    root = Path(raw).expanduser()
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("Claude Agent SDK root must be an absolute real directory")
    manifest_path = root / "package.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("Claude Agent SDK package metadata is missing or linked")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        manifest.get("name") != "@anthropic-ai/claude-agent-sdk"
        or manifest.get("version") != "0.3.220"
        or manifest.get("claudeCodeVersion") != "2.1.220"
    ):
        raise ValueError("Claude Agent SDK must be the reviewed 0.3.220 / CLI 2.1.220 pair")
    entry = root / str(manifest.get("main") or "sdk.mjs")
    if entry.is_symlink() or not entry.is_file():
        raise ValueError("Claude Agent SDK entry point is missing or linked")
    return root.resolve(strict=True)


def verified_copilot_paths() -> tuple[Path, Path] | None:
    raw_sdk = os.environ.get("PAIRLING_COPILOT_SDK_ROOT")
    raw_bin = os.environ.get("PAIRLING_COPILOT_BIN")
    if not raw_sdk and not raw_bin:
        return None
    if not raw_sdk or not raw_bin:
        raise ValueError("Copilot SDK and CLI paths must be configured together")

    sdk_root = Path(raw_sdk).expanduser()
    cli_binary = Path(raw_bin).expanduser()
    if (
        not sdk_root.is_absolute()
        or sdk_root.is_symlink()
        or not sdk_root.is_dir()
        or not cli_binary.is_absolute()
        or cli_binary.is_symlink()
        or not cli_binary.is_file()
        or not os.access(cli_binary, os.X_OK)
    ):
        raise ValueError("Copilot SDK and CLI must be absolute real executable release paths")
    sdk_root = sdk_root.resolve(strict=True)
    cli_binary = cli_binary.resolve(strict=True)

    sdk_manifest_path = sdk_root / "package.json"
    if sdk_manifest_path.is_symlink() or not sdk_manifest_path.is_file():
        raise ValueError("Copilot SDK package metadata is missing or linked")
    sdk_manifest = json.loads(sdk_manifest_path.read_text(encoding="utf-8"))
    if (
        sdk_manifest.get("name") != "@github/copilot-sdk"
        or sdk_manifest.get("version") != COPILOT_SDK_VERSION
        or sdk_manifest.get("main") != "./dist/cjs/index.js"
        or sdk_manifest.get("type") != "module"
        or sdk_manifest.get("dependencies")
        != {
            "@github/copilot": "^1.0.73",
            "koffi": "^3.1.0",
            "vscode-jsonrpc": "^8.2.1",
            "zod": "^4.3.6",
        }
    ):
        raise ValueError("Copilot SDK must be the reviewed exact 1.0.8 package")
    main_value = sdk_manifest["main"]
    main_relative = Path(main_value)
    if (
        main_relative.is_absolute()
        or "\\" in main_value
        or any(part in {"", ".", ".."} for part in main_relative.parts)
    ):
        raise ValueError("Copilot SDK entry point is unsafe")
    sdk_entry = sdk_root
    for component in main_relative.parts:
        sdk_entry /= component
        if sdk_entry.is_symlink():
            raise ValueError("Copilot SDK entry point is missing or linked")
    if not sdk_entry.is_file():
        raise ValueError("Copilot SDK entry point is missing or linked")

    github_scope = sdk_root.parent
    cli_loader_root = github_scope / "copilot"
    cli_loader_manifest_path = cli_loader_root / "package.json"
    if (
        cli_loader_root.is_symlink()
        or not cli_loader_root.is_dir()
        or cli_loader_manifest_path.is_symlink()
        or not cli_loader_manifest_path.is_file()
    ):
        raise ValueError("Copilot CLI loader metadata is missing or linked")
    cli_loader_manifest = json.loads(cli_loader_manifest_path.read_text(encoding="utf-8"))
    if (
        cli_loader_manifest.get("name") != "@github/copilot"
        or cli_loader_manifest.get("version") != COPILOT_CLI_VERSION
        or cli_loader_manifest.get("bin") != {"copilot": "npm-loader.js"}
        or cli_loader_manifest.get("dependencies") != {"detect-libc": "^2.1.2"}
    ):
        raise ValueError("Copilot CLI loader must be the reviewed exact 1.0.78 package")

    platform_root = cli_binary.parent
    match = re.fullmatch(r"copilot-darwin-(arm64|x64)", platform_root.name)
    if match is None or platform_root.parent != github_scope or cli_binary.name != "copilot":
        raise ValueError("Copilot CLI must be the direct reviewed release platform binary")
    architecture = match.group(1)
    platform_manifest_path = platform_root / "package.json"
    if platform_manifest_path.is_symlink() or not platform_manifest_path.is_file():
        raise ValueError("Copilot CLI platform metadata is missing or linked")
    platform_manifest = json.loads(platform_manifest_path.read_text(encoding="utf-8"))
    platform_name = f"@github/copilot-darwin-{architecture}"
    if (
        platform_manifest.get("name") != platform_name
        or platform_manifest.get("version") != COPILOT_CLI_VERSION
        or platform_manifest.get("os") != ["darwin"]
        or platform_manifest.get("cpu") != [architecture]
        or platform_manifest.get("bin") != {platform_root.name: "copilot"}
    ):
        raise ValueError("Copilot CLI platform package must be the reviewed exact 1.0.78 build")
    if not stat.S_ISREG(cli_binary.stat().st_mode):
        raise ValueError("Copilot CLI must be a regular file")

    try:
        version_result = subprocess.run(
            [str(cli_binary), "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            env={"PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(f"Copilot CLI version identity could not be verified: {exc}") from exc
    version_output = (version_result.stdout or version_result.stderr or "").strip()
    version_matches = re.findall(
        r"(?<![\d.])v?(\d+\.\d+\.\d+)(?!\.\d)",
        version_output,
    )
    if (
        version_result.returncode != 0
        or version_matches != [COPILOT_CLI_VERSION]
    ):
        raise ValueError(
            "Copilot CLI executable must report exactly "
            f"version {COPILOT_CLI_VERSION}; returncode={version_result.returncode}, "
            f"output={version_output!r}"
        )
    return sdk_root, cli_binary


def verified_node_binary() -> Path | None:
    raw = os.environ.get("PAIRLING_NODE_BIN")
    if not raw:
        return None
    binary = Path(raw).expanduser()
    if (
        not binary.is_absolute()
        or binary.is_symlink()
        or not binary.is_file()
        or not os.access(binary, os.X_OK)
    ):
        raise ValueError("Pairling Node binary must be an absolute executable real file")
    return binary.resolve(strict=True)






def write_plist(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        plistlib.dump(payload, fh, sort_keys=False)


def daemon_plist(
    current: Path,
    logs: Path,
    python_bin: str,
    pairdrop_root: Path | None = None,
) -> dict:
    pairdrop_root = canonical_pairdrop_root(pairdrop_root or (Path.home() / "PairDrop"))
    env = {
        "PAIRLING_RUNTIME_PORT": PAIRLING_RUNTIME_PORT,
        "COMPANION_DAEMON_PORT": PAIRLING_RUNTIME_PORT,
        "PAIRLING_BIND_MODE": "loopback",
        "PAIRLING_APP_SUPPORT_ROOT": str(current.parent.parent),
        "PAIRLING_LOGS_ROOT": str(logs),
        "PAIRLING_PAIRDROP_ROOT": str(pairdrop_root),
        "PAIRLING_RELAY_PUBLIC_KEYS": str(
            current / "companiond" / PAIRLING_RELAY_CLAIM_PUBLIC_KEY
        ),
        "PAIRLING_RELAY_CLAIMS_REQUIRED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    }
    claude_sdk_root = verified_claude_agent_sdk_root()
    if claude_sdk_root is not None:
        env["PAIRLING_CLAUDE_AGENT_SDK_ROOT"] = str(claude_sdk_root)
    copilot_paths = verified_copilot_paths()
    if copilot_paths is not None:
        copilot_sdk_root, copilot_binary = copilot_paths
        env["PAIRLING_COPILOT_SDK_ROOT"] = str(copilot_sdk_root)
        env["PAIRLING_COPILOT_BIN"] = str(copilot_binary)
    node_binary = verified_node_binary()
    if node_binary is not None:
        env["PAIRLING_NODE_BIN"] = str(node_binary)
    return {
        "Label": PAIRLING_DAEMON_LABEL,
        "ProgramArguments": [
            python_bin,
            str(current / "companiond" / "pairlingd.py"),
        ],
        "EnvironmentVariables": env,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "Umask": 0o077,
        "StandardOutPath": str(logs / "companiond.log"),
        "StandardErrorPath": str(logs / "companiond.err"),
    }


def connectd_plist(current: Path, logs: Path, ssh_gateway: bool = False) -> dict:
    app_support = current.parent.parent
    connectd_env = {
        "PAIRLING_RUNTIME_PORT": PAIRLING_RUNTIME_PORT,
        "PAIRLING_APP_SUPPORT_ROOT": str(app_support),
        "PAIRLING_LOGS_ROOT": str(logs),
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    }
    if ssh_gateway:
        # SPEC-p5 §2.1: `pairling setup --ssh` flips this on. connectd opens
        # the loopback SSH-tunnel gateway on 7775; default stays off.
        connectd_env["PAIRLING_SSH_GATEWAY"] = "1"
    return {
        "Label": PAIRLING_CONNECTD_LABEL,
        "ProgramArguments": [
            str(current / "connectd" / "pairling-connectd"),
            "--upstream",
            f"http://127.0.0.1:{PAIRLING_RUNTIME_PORT}",
            "--listen",
            f":{PAIRLING_RUNTIME_PORT}",
            "--status-addr",
            "127.0.0.1:7774",
            "--control-socket",
            str(Path.home() / ".claude" / "companion" / "connectd-control.sock"),
            "--pairling-control-socket",
            str(Path.home() / ".claude" / "companion" / "control.sock"),
            "--state-dir",
            str(app_support / "connectd" / "tsnet-state"),
        ],
        "EnvironmentVariables": connectd_env,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "Umask": 0o077,
        "StandardOutPath": str(logs / "connectd.log"),
        "StandardErrorPath": str(logs / "connectd.err"),
    }


def ptybroker_plist(current: Path, logs: Path, python_bin: str) -> dict:
    app_support = current.parent.parent
    return {
        "Label": PAIRLING_PTYBROKER_LABEL,
        "ProgramArguments": [
            python_bin,
            str(current / "companiond" / "pty_broker_service.py"),
        ],
        "EnvironmentVariables": {
            "PAIRLING_APP_SUPPORT_ROOT": str(app_support),
            "PAIRLING_LOGS_ROOT": str(logs),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        },
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "Umask": 0o077,
        "StandardOutPath": str(logs / "ptybroker.log"),
        "StandardErrorPath": str(logs / "ptybroker.err"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--current-root", required=True)
    parser.add_argument("--logs-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--daemon-python", default="/usr/local/bin/python3")
    parser.add_argument("--mirror-python", default="/usr/local/bin/python3", help=argparse.SUPPRESS)
    parser.add_argument("--pairdrop-root")
    parser.add_argument("--ssh-gateway", action="store_true",
                        help="render connectd with the loopback SSH-tunnel gateway enabled (SPEC-p5)")
    args = parser.parse_args()

    current = Path(args.current_root)
    logs = Path(args.logs_root)
    out = Path(args.output_dir)

    try:
        pairdrop_root = canonical_pairdrop_root(args.pairdrop_root or (Path.home() / "PairDrop"))
    except ValueError as exc:
        parser.error(str(exc))
    write_plist(
        out / f"{PAIRLING_DAEMON_LABEL}.plist",
        daemon_plist(current, logs, args.daemon_python, pairdrop_root),
    )
    write_plist(out / f"{PAIRLING_PTYBROKER_LABEL}.plist", ptybroker_plist(current, logs, args.daemon_python))
    write_plist(out / f"{PAIRLING_CONNECTD_LABEL}.plist", connectd_plist(current, logs, ssh_gateway=args.ssh_gateway))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
