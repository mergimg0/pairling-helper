#!/usr/bin/env python3
"""Verify an npm platform runtime package and its publishable archive shape."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import stat
import tarfile
import tempfile
import sys
import urllib.parse
from pathlib import Path, PurePosixPath

COMPANIOND_ROOT = Path(__file__).resolve().parents[1] / "companiond"
sys.path.insert(0, str(COMPANIOND_ROOT))
from provider_runtime_assets import (  # noqa: E402
    PROVIDER_RUNTIME_ASSET_DIGESTS,
    PROVIDER_RUNTIME_ASSET_NAMES,
)


UNSAFE_MODE_BITS = 0o7022
CLAUDE_AGENT_SDK_VERSION = "0.3.220"
CLAUDE_CODE_VERSION = "2.1.220"
COPILOT_SDK_VERSION = "1.0.8"
COPILOT_CLI_VERSION = "1.0.78"
KOFFI_VERSION = "3.1.4"
PROVIDER_SDK_CONFIG_SHA256 = "12dcfb4d41f4439328fc92dd6e2fe3df4f0910ace2741b9f982791fddea38939"
PROVIDER_SDK_LOCK_SHA256 = "6cd6e31113f28f3a5ddd46442b570fcd0893958a967073ffcc8dc56aa98e6d0d"
PROVIDER_DIRECT_DEPENDENCIES = {
    "@anthropic-ai/claude-agent-sdk": CLAUDE_AGENT_SDK_VERSION,
    "@github/copilot": COPILOT_CLI_VERSION,
    "@github/copilot-sdk": COPILOT_SDK_VERSION,
}
CLAUDE_OPTIONAL_DEPENDENCIES = {
    "@anthropic-ai/claude-agent-sdk-linux-x64": CLAUDE_AGENT_SDK_VERSION,
    "@anthropic-ai/claude-agent-sdk-linux-arm64": CLAUDE_AGENT_SDK_VERSION,
    "@anthropic-ai/claude-agent-sdk-linux-x64-musl": CLAUDE_AGENT_SDK_VERSION,
    "@anthropic-ai/claude-agent-sdk-linux-arm64-musl": CLAUDE_AGENT_SDK_VERSION,
    "@anthropic-ai/claude-agent-sdk-darwin-x64": CLAUDE_AGENT_SDK_VERSION,
    "@anthropic-ai/claude-agent-sdk-darwin-arm64": CLAUDE_AGENT_SDK_VERSION,
    "@anthropic-ai/claude-agent-sdk-win32-x64": CLAUDE_AGENT_SDK_VERSION,
    "@anthropic-ai/claude-agent-sdk-win32-arm64": CLAUDE_AGENT_SDK_VERSION,
}
CLAUDE_PEER_DEPENDENCIES = {
    "@anthropic-ai/sdk": ">=0.93.0",
    "@modelcontextprotocol/sdk": "^1.29.0",
    "zod": "^4.0.0",
}
COPILOT_OPTIONAL_DEPENDENCIES = {
    "@github/copilot-linux-x64": COPILOT_CLI_VERSION,
    "@github/copilot-linux-arm64": COPILOT_CLI_VERSION,
    "@github/copilot-linuxmusl-x64": COPILOT_CLI_VERSION,
    "@github/copilot-linuxmusl-arm64": COPILOT_CLI_VERSION,
    "@github/copilot-darwin-x64": COPILOT_CLI_VERSION,
    "@github/copilot-darwin-arm64": COPILOT_CLI_VERSION,
    "@github/copilot-win32-x64": COPILOT_CLI_VERSION,
    "@github/copilot-win32-arm64": COPILOT_CLI_VERSION,
}
COPILOT_SDK_DEPENDENCIES = {
    "@github/copilot": "^1.0.73",
    "koffi": "^3.1.0",
    "vscode-jsonrpc": "^8.2.1",
    "zod": "^4.3.6",
}
KOFFI_OPTIONAL_DEPENDENCIES = {
    "@koromix/koffi-linux-arm64": KOFFI_VERSION,
    "@koromix/koffi-linux-ia32": KOFFI_VERSION,
    "@koromix/koffi-linux-x64": KOFFI_VERSION,
    "@koromix/koffi-linux-riscv64": KOFFI_VERSION,
    "@koromix/koffi-freebsd-ia32": KOFFI_VERSION,
    "@koromix/koffi-freebsd-x64": KOFFI_VERSION,
    "@koromix/koffi-freebsd-arm64": KOFFI_VERSION,
    "@koromix/koffi-openbsd-ia32": KOFFI_VERSION,
    "@koromix/koffi-openbsd-x64": KOFFI_VERSION,
    "@koromix/koffi-win32-ia32": KOFFI_VERSION,
    "@koromix/koffi-win32-x64": KOFFI_VERSION,
    "@koromix/koffi-win32-arm64": KOFFI_VERSION,
    "@koromix/koffi-darwin-x64": KOFFI_VERSION,
    "@koromix/koffi-darwin-arm64": KOFFI_VERSION,
    "@koromix/koffi-linux-loong64": KOFFI_VERSION,
}
LOCKED_PROVIDER_PACKAGES = {
    "@anthropic-ai/claude-agent-sdk": (CLAUDE_AGENT_SDK_VERSION, "sha512-glc7SdwPkOkLw8oxwLo9PKTdLJGqW/PIR4urWXFoRtX9YllwozsEVc5Tc1+EvLSkfrsxPJqQWqOgpjUOQXf1oA=="),
    "@anthropic-ai/claude-agent-sdk-darwin-arm64": (CLAUDE_AGENT_SDK_VERSION, "sha512-7VxlbEosK7DODiOnsjoVd0DSJzbnaPrM2jelMHI0y8zx1UnLS3WC6EFUXbvy74F2sXqEznh2tzn7EKWInaRN6Q=="),
    "@anthropic-ai/claude-agent-sdk-darwin-x64": (CLAUDE_AGENT_SDK_VERSION, "sha512-X9RwDsSmbF6ultKZroaip+DL8WRgC64gHbrAwrRlAFSPNZV7zmJyP2ur8rW7KrxqmtuehdMMkw8+SAC/6hD2PA=="),
    "@anthropic-ai/claude-agent-sdk-linux-arm64": (CLAUDE_AGENT_SDK_VERSION, "sha512-WkROPwWskqhKR9XgnmseHQ6rLi9zM9qt57IWoToIjL/eXOqDWipp7JXZ1L5ud+LrA42dunHPZfBwD/vXZ+A7LA=="),
    "@anthropic-ai/claude-agent-sdk-linux-arm64-musl": (CLAUDE_AGENT_SDK_VERSION, "sha512-OHoZOZ8Cf2TBr6oXIXPwyvUxj9jrq2w8E4poA8dMpacXszcPSPiCQCMuuOh4aWJzfeJE1+TtWxhKMVb2csXyZQ=="),
    "@anthropic-ai/claude-agent-sdk-linux-x64": (CLAUDE_AGENT_SDK_VERSION, "sha512-tkTJFnpR9VifvWX2fmkCAPkT6+8Wk/gVu8B5jsVekKZPiZoWRHmMXO30BnZn+f0TZhgYP+82PSX3S8crH1kn+w=="),
    "@anthropic-ai/claude-agent-sdk-linux-x64-musl": (CLAUDE_AGENT_SDK_VERSION, "sha512-K+FWj+LcGhC1Z7wqeWoLxm1iemcba5xKpLLFVwYm4V6HyMx3ruYd/2r2TiQtjT+JWeNFWIys0ScHiItR6vWAiA=="),
    "@anthropic-ai/claude-agent-sdk-win32-arm64": (CLAUDE_AGENT_SDK_VERSION, "sha512-rIwgq0UwQExWl6KrHUyC4w5KwpL9l6nd95aUTx6RitexaAuEw//xtfTVLnuE4hDDQZFkzEwpdKc3nxDWoGcUbA=="),
    "@anthropic-ai/claude-agent-sdk-win32-x64": (CLAUDE_AGENT_SDK_VERSION, "sha512-MuOuXhbr66HlGaWXD2f3w0k2PsvmnbkwcUZ0dAe2poFLdl72GC2dapwwOBefxm9QmoNqk9+jmv/dSKGOVWyvLw=="),
    "@github/copilot": (COPILOT_CLI_VERSION, "sha512-jn+8HLZC3R7d6K1/1g9L1iWNKzBVS3JdVcx40r3aWyS5r+MLV1OPNp0fo5OfRMCDIm3NmEaaoqypi9sQkCXuiQ=="),
    "@github/copilot-darwin-arm64": (COPILOT_CLI_VERSION, "sha512-P11+VyWg8ad0WlywGtO2d7AxqTLJv4hkUicFg6Ycth5lfk00aCu/74YOOZSPO6C2bBBJhAza7oAdmauM6KEojw=="),
    "@github/copilot-darwin-x64": (COPILOT_CLI_VERSION, "sha512-stimP3WDFs2GU8nJzTJbtRpZViV4bsf80yg7QrFq+G4RISQ3Nihg/3/H0U6UQF1+txMJ/Ohmb5RFYxSw1Hj2sw=="),
    "@github/copilot-linux-arm64": (COPILOT_CLI_VERSION, "sha512-K31PRKGTm252V1Lof7ypjg283R2QSm3BgoCvZfX2taos4wqC3SaTozSQKwW3dgrAx7A3G3SGEoilVCNqfigdZA=="),
    "@github/copilot-linux-x64": (COPILOT_CLI_VERSION, "sha512-QK3oMtAn9dIv+1u1kx0xNpZNtZxdI+uZVIyLl7myp+Oh2Uj8BLagVv6a7uP0cDphO3TgfIdlvpepCe5MIcx0fw=="),
    "@github/copilot-linuxmusl-arm64": (COPILOT_CLI_VERSION, "sha512-F/0cTMsz6ug4yiXn3RKaCAMsLR261U5Njb6G9Y/HeAI7ES/tKEo2t5SHuvgXaIH4mYiZsRvfDKdX7c0WgBX/Jg=="),
    "@github/copilot-linuxmusl-x64": (COPILOT_CLI_VERSION, "sha512-YMaJaeBGbArGAFYel+yFaFW/0rFgh0Oqki2f2mUtlonTX/xHr8EB4+mTnMJkHYMFy4gOTC3OtSEEe1NaW/cBXQ=="),
    "@github/copilot-sdk": (COPILOT_SDK_VERSION, "sha512-dbahVsyt2aX8qqtOOtmYNe40MnvzSvOSHYFFgoFK7gHZSTNz9QgOht8b1sCCJlcXaFAn/w+5qNc7CwWoCjpQ0g=="),
    "@github/copilot-win32-arm64": (COPILOT_CLI_VERSION, "sha512-ktDkFXaaecEKD3hpM6ydM9lKOdoCfsQsXCmzLzE7DCmSpbbMCdfPfWfZ7MOclmKmpZ5/MNfr4U2l8CUqGerzYA=="),
    "@github/copilot-win32-x64": (COPILOT_CLI_VERSION, "sha512-Gd8l2T4eqYEWlOEPd0SZznQ+YYgYrwOkE0QXodMkhCBbPdgu/uTzb7mnISWwnVAgqs7pONdF1GOpHkTo+ay8CQ=="),
    "@koromix/koffi-darwin-arm64": (KOFFI_VERSION, "sha512-/9o0uahf25sNXz7CczfMAsgdHrrrkDK3/d1W5ygJUC7QnpWo80103yTYpYahWP3vTABK5yjzKtURgssv1paskA=="),
    "@koromix/koffi-darwin-x64": (KOFFI_VERSION, "sha512-6IOhfAHbrySr6lYRU720Hg+IMQvtMpN08k9Ppf9WF8NxYRdHLnW1FJm7zCbClfrwudtjhS/piwDYwgAkO5u8cg=="),
    "@koromix/koffi-freebsd-arm64": (KOFFI_VERSION, "sha512-JKCWC0awdVvq7Nd/etn4PXFTa7uvyHn7IzqtaOZ3r4dJRdwQVby7Ai/wsQo8UUrJfAYlALkLYgFgU8wgsnAE/A=="),
    "@koromix/koffi-freebsd-ia32": (KOFFI_VERSION, "sha512-gU9pShDRLMZzftdGW+mTzyL8Cpa/7nzHPHe5vFakjGgtIzVFzdFBqwli4oB+tFsx44W1VqMMlvMMVlnz54ERiQ=="),
    "@koromix/koffi-freebsd-x64": (KOFFI_VERSION, "sha512-2kppLX97xBM3WoQET6noN4W02zT2fkFRXHYluAwcCcmkEax8AVJ1CYs6hxcZ3kaNPc+5P7yMw3V/b1lg2v3aMw=="),
    "@koromix/koffi-linux-arm64": (KOFFI_VERSION, "sha512-yYbypuGVGqrNchkAMY59kj+7TZ1c1u9lXRG1+74X9T8G4rOaushoVONNYLuu+ygpbwsKzz/NvEDtRioRU/dQlQ=="),
    "@koromix/koffi-linux-ia32": (KOFFI_VERSION, "sha512-IoA/8Qfc6ZEmwMw2Nf4aSp9RfJnxh0UHhdqD4FsVXm0vC797kLMuzj744vv5tll+waVfjrU10jREqjtnMVFoQw=="),
    "@koromix/koffi-linux-loong64": (KOFFI_VERSION, "sha512-ZUTdea+9dg6CV9J9CIGbhTh0FtSBgvcGKqDrlp9BVQF71jEDKOri1by/TrDe8yQUyC5kzWN8vWnkzES5wT0xDg=="),
    "@koromix/koffi-linux-riscv64": (KOFFI_VERSION, "sha512-CINyyhNYV/8MX52MGhYcik2G6PXH+KEU2JEO7dOONlsGol4lSGyW40RvYA4RQgNYk8q8imGSEScL08X8eOXnaA=="),
    "@koromix/koffi-linux-x64": (KOFFI_VERSION, "sha512-x3XnAy/tUTTCX/gMpV7VJNpOQIVQvzNhNYDrpyIeS9Q8/f1qLsE0vp0tj7A/YEDIfMVLqoJtyamfRJc04+vk4w=="),
    "@koromix/koffi-openbsd-ia32": (KOFFI_VERSION, "sha512-r9p/fffvmBm7+iT5BZ+c17gZJ280jvmbinrPZqjG14rF9I4lk7xrlV79YfsexkeN4mcPjF2hSPtbMNFBoQU3Dw=="),
    "@koromix/koffi-openbsd-x64": (KOFFI_VERSION, "sha512-SNp5AxOzheC2YaWPu3Y86wxRHHWf6V9NMl5Ot5nu9OpnP61Yinzug7JwsCeXtcZZTbKLsfsWoT7y4n17UYpOVA=="),
    "@koromix/koffi-win32-arm64": (KOFFI_VERSION, "sha512-oS8ETU35AelOD6DY7xmmz9qq26Xl38upXWiZbsdxbtH9UEIY0QpenQOuCK/0+q4CtfiLorRUlglGkO9YgPAIeA=="),
    "@koromix/koffi-win32-ia32": (KOFFI_VERSION, "sha512-zd7Qh8s4fzblD9zzuDf44XCbujYg3QrffhgcNJg79/YC6ABT2m0CUtX4yFic9EWm2ps8NPAM25kCTCXPpt3eaw=="),
    "@koromix/koffi-win32-x64": (KOFFI_VERSION, "sha512-BPeQXc1bRd0QBOklvsP+AjoRnUzKbPNE6rfx7VNxrebhh09MKld2ibstgKWn6ejQLEcfKEoUJ+WAWIhX4AOsIg=="),
    "detect-libc": ("2.1.2", "sha512-Btj2BOOO83o3WyH59e8MgXsxEQVcarkUOpEYrubB0urwnN10yQ364rsiByU11nZlqWYZm05i/of7io4mzihBtQ=="),
    "koffi": (KOFFI_VERSION, "sha512-KHX39XIg7afe8ds+0MHPoLiKR9dCzsVK4oAmBUSaeJlcX0xur22f15C2DILbZ6GJ9eyqC+e6Sb1cTG7M17z+Tg=="),
    "vscode-jsonrpc": ("8.2.1", "sha512-kdjOSJ2lLIn7r1rtrMbbNCHjyMPfRnowdKjBQ+mGq6NAW5QY2bEZC/khaC5OR8svbbjvLEaIXkOq45e2X9BIbQ=="),
    "zod": ("4.4.3", "sha512-ytENFjIJFl2UwYglde2jchW2Hwm4GJFLDiSXWdTrJQBIN9Fcyp7n4DhxJEiWNAJMV1/BqWfW/kkg71UDcHJyTQ=="),
}
LOCKED_PROVIDER_PEER_PACKAGES = {
    "@anthropic-ai/sdk",
    "@babel/runtime",
    "@hono/node-server",
    "@modelcontextprotocol/sdk",
    "@stablelib/base64",
    "accepts",
    "ajv",
    "ajv-formats",
    "body-parser",
    "body-parser/node_modules/content-type",
    "bytes",
    "call-bind-apply-helpers",
    "call-bound",
    "content-disposition",
    "content-type",
    "cookie",
    "cookie-signature",
    "cors",
    "cross-spawn",
    "debug",
    "depd",
    "dunder-proto",
    "ee-first",
    "encodeurl",
    "es-define-property",
    "es-errors",
    "es-object-atoms",
    "escape-html",
    "etag",
    "eventsource",
    "eventsource-parser",
    "express",
    "express-rate-limit",
    "fast-deep-equal",
    "fast-sha256",
    "fast-uri",
    "finalhandler",
    "forwarded",
    "fresh",
    "function-bind",
    "get-intrinsic",
    "get-proto",
    "gopd",
    "has-symbols",
    "hasown",
    "hono",
    "http-errors",
    "iconv-lite",
    "inherits",
    "ip-address",
    "ipaddr.js",
    "is-promise",
    "isexe",
    "jose",
    "json-schema-to-ts",
    "json-schema-traverse",
    "json-schema-typed",
    "math-intrinsics",
    "media-typer",
    "merge-descriptors",
    "mime-db",
    "mime-types",
    "ms",
    "negotiator",
    "object-assign",
    "object-inspect",
    "on-finished",
    "once",
    "parseurl",
    "path-key",
    "path-to-regexp",
    "pkce-challenge",
    "proxy-addr",
    "qs",
    "range-parser",
    "raw-body",
    "require-from-string",
    "router",
    "safer-buffer",
    "send",
    "serve-static",
    "setprototypeof",
    "shebang-command",
    "shebang-regex",
    "side-channel",
    "side-channel-list",
    "side-channel-map",
    "side-channel-weakmap",
    "standardwebhooks",
    "statuses",
    "toidentifier",
    "ts-algebra",
    "type-is",
    "type-is/node_modules/content-type",
    "unpipe",
    "vary",
    "which",
    "wrappy",
    "zod-to-json-schema",
}
CLAUDE_SDK_FILES = {
    "LICENSE.md", "README.md", "agentSdkTypes.d.ts", "bridge.d.ts", "bridge.mjs",
    "browser-sdk.d.ts", "browser-sdk.js", "extractFromBunfs.d.ts",
    "extractFromBunfs.js", "manifest.json", "manifest.zst.json", "package.json",
    "sdk-tools.d.ts", "sdk.d.ts", "sdk.mjs",
}
CLAUDE_BINARY_PACKAGE_FILES = {"LICENSE.md", "README.md", "claude", "package.json"}
COPILOT_PACKAGE_FILES = {"LICENSE.md", "README.md", "npm-loader.js", "package.json"}
COPILOT_SDK_FILES = {"README.md", "dist", "docs", "package.json"}
COPILOT_PLATFORM_FILES = {
    "LICENSE.md", "README.md", "app.js", "assets", "builtin", "builtin-skills",
    "changelog.json", "clipboard", "copilot", "copilot-sdk", "definitions",
    "foundry-local-sdk", "index.js", "napi-oop-runtime", "npm-loader.js",
    "package.json", "plugins", "prebuilds", "preloads", "pvrecorder", "queries",
    "ripgrep", "schemas", "sdk", "sea-loader.js", "tgrep", "tree-sitter-bash.wasm",
    "tree-sitter-c.wasm", "tree-sitter-c_sharp.wasm", "tree-sitter-cpp.wasm",
    "tree-sitter-css.wasm", "tree-sitter-go.wasm", "tree-sitter-html.wasm",
    "tree-sitter-java.wasm", "tree-sitter-javascript.wasm", "tree-sitter-json.wasm",
    "tree-sitter-php.wasm", "tree-sitter-python.wasm", "tree-sitter-ruby.wasm",
    "tree-sitter-rust.wasm", "tree-sitter-scala.wasm", "tree-sitter-tsx.wasm",
    "tree-sitter-typescript.wasm", "tree-sitter.wasm", "voice-engine.worker.js",
    "voice-installer.worker.js", "voice-server.js", "webview",
}
TRANSITIVE_PACKAGE_FILES = {
    "detect-libc": {"LICENSE", "README.md", "index.d.ts", "lib", "package.json"},
    "koffi": {
        "CHANGELOG.md", "LICENSE.txt", "README.md", "cnoke.cjs", "doc", "index.cjs",
        "index.d.ts", "index.js", "indirect.cjs", "indirect.js", "lib", "package.json",
        "src", "vendor",
    },
    "vscode-jsonrpc": {
        "License.txt", "README.md", "browser.d.ts", "browser.js", "lib", "node.cmd",
        "node.d.ts", "node.js", "package.json", "thirdpartynotices.txt", "typings",
    },
    "zod": {
        "LICENSE", "README.md", "index.cjs", "index.d.cts", "index.d.ts", "index.js",
        "locales", "mini", "package.json", "src", "v3", "v4", "v4-mini",
    },
    "koffi-platform": {"README.md", "darwin_{architecture}", "index.js", "package.json"},
}
COPILOT_PLATFORM_EXECUTABLES = {
    "copilot",
    "tree-sitter.wasm",
    "index.js",
    "npm-loader.js",
    "app.js",
    "tgrep/bin/darwin-{architecture}/tgrep",
    "napi-oop-runtime/node_modules/napi-oop-runtime/dist/codegen-cli.js",
    "ripgrep/bin/darwin-{architecture}/rg",
    "prebuilds/darwin-{architecture}/cli-native.node",
    "prebuilds/darwin-{architecture}/runtime.node",
    "prebuilds/darwin-{architecture}/mediaremote-adapter/mediaremote-adapter.pl",
    "prebuilds/darwin-{architecture}/mediaremote-adapter/MediaRemoteAdapter.framework/MediaRemoteAdapter",
    "webview/node_modules/@webviewjs/webview/cli/index.mjs",
    "plugins/computer-use/computer-use-mcp",
    "plugins/computer-use/Copilot Computer Use.app/Contents/CodeResources",
    "plugins/computer-use/Copilot Computer Use.app/Contents/Info.plist",
    "plugins/computer-use/Copilot Computer Use.app/Contents/PkgInfo",
    "plugins/computer-use/Copilot Computer Use.app/Contents/_CodeSignature/CodeResources",
    "plugins/computer-use/Copilot Computer Use.app/Contents/MacOS/Copilot Computer Use",
    "plugins/computer-use/Copilot Computer Use.app/Contents/Resources/icon.icns",
    "plugins/computer-use/Copilot Computer Use.app/Contents/Resources/Assets.car",
}
PROVIDER_LIFECYCLE_KEYS = {
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
    "dependencies",
}
REVIEWED_LIFECYCLE_SCRIPTS = {
    "koffi/package.json": {
        "install": "node ./cnoke.cjs -P . -D src/koffi --prebuild --release",
    },
    "@github/copilot-darwin-{architecture}/clipboard/node_modules/@teddyzhu/clipboard/package.json": {
        "prepare": "husky",
    },
    "@github/copilot-darwin-{architecture}/pvrecorder/node_modules/@picovoice/pvrecorder-node/package.json": {
        "prepare": "node copy.js",
    },
    "@github/copilot-darwin-{architecture}/foundry-local-sdk/node_modules/foundry-local-sdk/package.json": {
        "install": "node script/install-standard.cjs",
        "preinstall": "node script/preinstall.cjs",
    },
}
FORBIDDEN_DEPENDENCY_KEYS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "bundledDependencies",
    "bundleDependencies",
    "optionalDependencies",
)
ALLOWED_REPOSITORY_SHA256 = "33abebc9c629f9877e31b8c9f39670427ad5055d80ccdc8a51588101087a042a"

def valid_repository(value: object) -> bool:
    if not isinstance(value, dict) or value.get("type") != "git":
        return False
    url = value.get("url")
    if not isinstance(url, str):
        return False
    parsed = urllib.parse.urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    if not (
        parsed.scheme == "https"
        and parsed.hostname == "github.com"
        and parsed.netloc.casefold() == "github.com"
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
        and len(parts) == 2
    ):
        return False
    canonical = f"github.com/{parts[0].casefold()}/{parts[1].removesuffix('.git').casefold()}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest() == ALLOWED_REPOSITORY_SHA256


def fail(message: str) -> int:
    print(f"runtime package manifest verification failed: {message}", file=sys.stderr)
    return 1


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def valid_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def tree_sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("automation helper app is not a real directory")
    digest = hashlib.sha256()
    paths = [path, *sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix())]
    for item in paths:
        metadata = item.lstat()
        relative = "." if item == path else item.relative_to(path).as_posix()
        mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
        if stat.S_ISDIR(metadata.st_mode):
            record = f"{relative}\0D\0{mode}\n"
        elif stat.S_ISREG(metadata.st_mode):
            record = f"{relative}\0F\0{mode}\0{sha256_file(item)}\n"
        else:
            raise ValueError(f"automation helper app has an unsupported entry: {relative}")
        digest.update(record.encode("utf-8"))
    return digest.hexdigest()

def load_json_object(path: Path, label: str) -> tuple[dict[str, object] | None, str | None]:
    if path.is_symlink() or not path.is_file():
        return None, f"{label} must be a regular file, not a symlink"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"cannot read {label}: {exc}"
    if not isinstance(value, dict):
        return None, f"{label} must contain a JSON object"
    return value, None


def exact_directory_entries(root: Path, expected: set[str], label: str) -> str | None:
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        return f"cannot inspect {label}: {exc}"
    linked = sorted(path.name for path in entries if path.is_symlink())
    if linked:
        return f"{label} contains symlink entries: {', '.join(linked)}"
    actual = {path.name for path in entries}
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing:
        return f"{label} entries are missing: {', '.join(missing)}"
    if unexpected:
        return f"{label} has unexpected entries: {', '.join(unexpected)}"
    return None


def provider_runtime_asset_paths(root: Path) -> set[str]:
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.suffix in {".mjs", ".sb"}
    }


def same_open_directory(path: Path, descriptor: int) -> bool:
    current = path.lstat()
    opened = os.fstat(descriptor)
    return (
        stat.S_ISDIR(current.st_mode)
        and (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino)
    )


def verify_provider_runtime_assets(root: Path) -> str | None:
    if root.is_symlink() or not root.is_dir():
        return "provider runtime asset root must be a real directory"
    try:
        actual = provider_runtime_asset_paths(root)
    except OSError as exc:
        return f"cannot inspect provider runtime assets: {exc}"
    expected = set(PROVIDER_RUNTIME_ASSET_NAMES)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing:
        return "provider runtime assets are missing: " + ", ".join(missing)
    if unexpected:
        return "provider runtime assets are unexpected: " + ", ".join(unexpected)

    directory = None
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        if not same_open_directory(root, directory):
            raise OSError(errno.ESTALE, "provider runtime asset directory changed")
        for name, expected_digest in PROVIDER_RUNTIME_ASSET_DIGESTS.items():
            source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                metadata = os.fstat(source)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o644
                ):
                    raise OSError(
                        errno.EINVAL,
                        "asset is not a regular mode-0644 file",
                        name,
                    )
                digest = hashlib.sha256()
                while chunk := os.read(source, 1024 * 1024):
                    digest.update(chunk)
                if digest.hexdigest() != expected_digest:
                    raise OSError(errno.EBADMSG, "asset digest is not reviewed", name)
            finally:
                os.close(source)
        if not same_open_directory(root, directory):
            raise OSError(errno.ESTALE, "provider runtime asset directory changed")
    except OSError as exc:
        return f"cannot verify provider runtime assets: {exc}"
    finally:
        if directory is not None:
            os.close(directory)
    return None


def stage_provider_runtime_assets(source: Path, destination: Path) -> str | None:
    source_error = verify_provider_runtime_assets(source)
    if source_error:
        return source_error
    if destination.is_symlink() or not destination.is_dir():
        return "provider runtime asset destination must be a real directory"
    try:
        existing = sorted(provider_runtime_asset_paths(destination))
    except OSError as exc:
        return f"cannot inspect provider runtime asset destination: {exc}"
    if existing:
        return "provider runtime asset destination is not empty: " + ", ".join(existing)

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    source_directory = destination_directory = None
    created: list[str] = []
    try:
        source_directory = os.open(source, directory_flags)
        destination_directory = os.open(destination, directory_flags)
        if (
            not same_open_directory(source, source_directory)
            or not same_open_directory(destination, destination_directory)
        ):
            raise OSError(errno.ESTALE, "provider runtime asset directory changed")
        for name, expected_digest in PROVIDER_RUNTIME_ASSET_DIGESTS.items():
            source_file = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=source_directory,
            )
            try:
                metadata = os.fstat(source_file)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o644
                ):
                    raise OSError(
                        errno.EINVAL,
                        "source is not a regular mode-0644 file",
                        name,
                    )
                destination_file = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o644,
                    dir_fd=destination_directory,
                )
                created.append(name)
                try:
                    digest = hashlib.sha256()
                    while chunk := os.read(source_file, 1024 * 1024):
                        digest.update(chunk)
                        view = memoryview(chunk)
                        while view:
                            view = view[os.write(destination_file, view):]
                    if digest.hexdigest() != expected_digest:
                        raise OSError(errno.EBADMSG, "asset digest is not reviewed", name)
                    os.fchmod(destination_file, 0o644)
                finally:
                    os.close(destination_file)
            finally:
                os.close(source_file)
        if not same_open_directory(destination, destination_directory):
            raise OSError(errno.ESTALE, "provider runtime asset destination changed")
        destination_error = verify_provider_runtime_assets(destination)
        if destination_error:
            for name in created:
                try:
                    os.unlink(name, dir_fd=destination_directory)
                except OSError:
                    pass
            return destination_error
    except OSError as exc:
        if destination_directory is not None:
            for name in created:
                try:
                    os.unlink(name, dir_fd=destination_directory)
                except OSError:
                    pass
        return f"cannot stage provider runtime assets: {exc}"
    finally:
        if source_directory is not None:
            os.close(source_directory)
        if destination_directory is not None:
            os.close(destination_directory)

    return None


def locked_tarball_url(package: str, version: str) -> str:
    basename = package.rsplit("/", 1)[-1]
    return f"https://registry.npmjs.org/{package}/-/{basename}-{version}.tgz"


def verify_provider_lock(root: Path, *, lock_name: str = "npm-shrinkwrap.json") -> str | None:
    config_path = root / "package.json"
    lock_path = root / lock_name
    if config_path.is_symlink() or not config_path.is_file():
        return "provider SDK config must be a regular file, not a symlink"
    if lock_path.is_symlink() or not lock_path.is_file():
        return "provider SDK lock must be a regular file, not a symlink"
    if sha256_file(config_path) != PROVIDER_SDK_CONFIG_SHA256:
        return "provider SDK config digest does not match the reviewed contract"
    if sha256_file(lock_path) != PROVIDER_SDK_LOCK_SHA256:
        return "provider SDK lock digest does not match the reviewed contract"
    config, config_error = load_json_object(config_path, "provider SDK config")
    if config_error:
        return config_error
    expected_config = {
        "name": "@pairling/provider-sdks",
        "version": "0.0.0",
        "private": True,
        "dependencies": PROVIDER_DIRECT_DEPENDENCIES,
    }
    if config != expected_config:
        return "provider SDK config is not the reviewed exact dependency contract"

    lock, lock_error = load_json_object(lock_path, "provider SDK lock")
    if lock_error:
        return lock_error
    if (
        lock.get("name") != "@pairling/provider-sdks"
        or lock.get("version") != "0.0.0"
        or lock.get("lockfileVersion") != 3
        or lock.get("requires") is not True
    ):
        return "provider SDK lock metadata does not match the reviewed contract"
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        return "provider SDK lock package map is missing"
    expected_packages = set(LOCKED_PROVIDER_PACKAGES) | LOCKED_PROVIDER_PEER_PACKAGES
    expected_paths = {"", *(f"node_modules/{name}" for name in expected_packages)}
    if set(packages) != expected_paths:
        return "provider SDK lock package allowlist does not match the reviewed contract"
    root_entry = packages.get("")
    if (
        not isinstance(root_entry, dict)
        or root_entry.get("name") != "@pairling/provider-sdks"
        or root_entry.get("version") != "0.0.0"
        or root_entry.get("dependencies") != PROVIDER_DIRECT_DEPENDENCIES
    ):
        return "provider SDK lock direct dependency is not exact"
    for package, (version, integrity) in LOCKED_PROVIDER_PACKAGES.items():
        entry = packages.get(f"node_modules/{package}")
        if not isinstance(entry, dict):
            return f"provider SDK lock is missing {package}"
        if (
            entry.get("version") != version
            or entry.get("integrity") != integrity
            or entry.get("resolved") != locked_tarball_url(package, version)
        ):
            return f"provider SDK lock integrity does not match for {package}"
        permits_install = package == "koffi"
        if (
            ("hasInstallScript" in entry) != permits_install
            or (permits_install and entry.get("hasInstallScript") is not True)
        ):
            return f"provider SDK lock lifecycle declaration does not match for {package}"
        if "peer" in entry:
            return f"provider SDK materialized package is unexpectedly peer-only: {package}"
    for package in LOCKED_PROVIDER_PEER_PACKAGES:
        entry = packages.get(f"node_modules/{package}")
        if not isinstance(entry, dict):
            return f"provider SDK lock is missing peer-only package {package}"
        version = entry.get("version")
        package_name = package.rsplit("/node_modules/", 1)[-1]
        integrity = entry.get("integrity")
        if (
            entry.get("peer") is not True
            or not isinstance(version, str)
            or not isinstance(integrity, str)
            or not integrity.startswith("sha512-")
            or entry.get("resolved") != locked_tarball_url(package_name, version)
            or "hasInstallScript" in entry
        ):
            return f"provider SDK lock peer-omission contract does not match for {package}"
    return None


def package_lifecycle_scripts(
    manifest: dict[str, object],
    label: str,
) -> tuple[dict[str, str] | None, str | None]:
    scripts = manifest.get("scripts")
    if scripts is None:
        return {}, None
    if not isinstance(scripts, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in scripts.items()
    ):
        return None, f"{label} scripts declaration is malformed"
    return {
        key: value
        for key, value in scripts.items()
        if key in PROVIDER_LIFECYCLE_KEYS
    }, None


def sanitize_provider_lifecycle_scripts(package_store: Path, architecture: str) -> str | None:
    if architecture not in {"arm64", "x64"}:
        return "provider SDK architecture is unsupported"
    if package_store.is_symlink() or not package_store.is_dir():
        return "provider SDK package store must be a real directory"
    expected = {
        path.format(architecture=architecture): scripts
        for path, scripts in REVIEWED_LIFECYCLE_SCRIPTS.items()
    }
    found: dict[str, dict[str, str]] = {}
    manifests: dict[str, tuple[Path, dict[str, object]]] = {}
    for path in sorted(package_store.rglob("package.json")):
        relative = path.relative_to(package_store).as_posix()
        manifest, manifest_error = load_json_object(path, f"provider package {relative}")
        if manifest_error:
            return manifest_error
        lifecycle, lifecycle_error = package_lifecycle_scripts(manifest, relative)
        if lifecycle_error:
            return lifecycle_error
        manifests[relative] = (path, manifest)
        if lifecycle:
            found[relative] = lifecycle
    if found != expected:
        return "provider SDK lifecycle script inventory does not match the reviewed contract"
    for relative, (path, manifest) in sorted(manifests.items()):
        if "scripts" not in manifest:
            continue
        manifest.pop("scripts")
        temporary = path.with_name(f".{path.name}.pairling-inert")
        if temporary.exists() or temporary.is_symlink():
            return f"provider SDK lifecycle sanitizer destination already exists: {relative}"
        try:
            metadata = path.stat()
            payload = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                stat.S_IMODE(metadata.st_mode),
            )
            try:
                offset = 0
                while offset < len(payload):
                    written = os.write(descriptor, payload[offset:])
                    if written <= 0:
                        raise OSError("short write while sanitizing provider package metadata")
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
        except OSError as exc:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            return f"could not remove provider SDK package scripts: {exc}"
    return None


def provider_payload_inventory(
    root: Path,
    allowed_executables: set[Path],
) -> tuple[int, int, str | None]:
    files = 0
    directories = 0
    found_executables: set[Path] = set()
    paths = [root, *sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())]
    for path in paths:
        relative = "." if path == root else path.relative_to(root).as_posix()
        try:
            metadata = path.lstat()
        except OSError as exc:
            return 0, 0, f"cannot inspect provider SDK payload entry {relative}: {exc}"
        if stat.S_ISLNK(metadata.st_mode):
            return 0, 0, f"provider SDK payload contains a forbidden symlink: {relative}"
        mode = stat.S_IMODE(metadata.st_mode)
        if mode & UNSAFE_MODE_BITS:
            return 0, 0, f"provider SDK payload contains unsafe writable permissions: {relative}"
        if stat.S_ISDIR(metadata.st_mode):
            directories += 1
            if not mode & stat.S_IRUSR or not mode & stat.S_IXUSR:
                return 0, 0, f"provider SDK directory is not owner-readable/searchable: {relative}"
            continue
        if not stat.S_ISREG(metadata.st_mode):
            return 0, 0, f"provider SDK payload contains an unsupported entry: {relative}"
        files += 1
        if not mode & stat.S_IRUSR:
            return 0, 0, f"provider SDK file is not owner-readable: {relative}"
        if mode & 0o111:
            if path not in allowed_executables:
                return 0, 0, f"provider SDK data file is executable: {relative}"
            found_executables.add(path)
        elif path in allowed_executables:
            return 0, 0, f"provider SDK reviewed executable is not owner-executable: {relative}"
    if found_executables != allowed_executables:
        return 0, 0, "provider SDK executable inventory is incomplete"
    return files, directories, None


def verify_provider_sdks(
    root_input: Path,
    architecture: str,
    *,
    package_directory: str = "packages",
) -> tuple[int, int, str | None]:
    if architecture not in {"arm64", "x64"}:
        return 0, 0, "provider SDK architecture is unsupported"
    if root_input.is_symlink() or not root_input.is_dir():
        return 0, 0, "provider SDK root must be a real directory"
    root = root_input.resolve()
    if package_directory not in {"packages", "node_modules"}:
        return 0, 0, "provider SDK package directory policy is invalid"
    root_error = exact_directory_entries(
        root,
        {"package.json", "npm-shrinkwrap.json", package_directory},
        "provider SDK root",
    )
    if root_error:
        return 0, 0, root_error
    lock_error = verify_provider_lock(root)
    if lock_error:
        return 0, 0, lock_error

    package_store = root / package_directory
    if package_store.is_symlink() or not package_store.is_dir():
        return 0, 0, f"provider SDK {package_directory} must be a real directory"
    modules_error = exact_directory_entries(
        package_store,
        {"@anthropic-ai", "@github", "@koromix", "detect-libc", "koffi", "vscode-jsonrpc", "zod"},
        "provider SDK top-level packages",
    )
    if modules_error:
        return 0, 0, modules_error

    claude_scope = package_store / "@anthropic-ai"
    github_scope = package_store / "@github"
    koromix_scope = package_store / "@koromix"
    claude_platform_name = f"claude-agent-sdk-darwin-{architecture}"
    copilot_platform_name = f"copilot-darwin-{architecture}"
    koffi_platform_name = f"koffi-darwin-{architecture}"
    scope_contracts = (
        (claude_scope, {"claude-agent-sdk", claude_platform_name}, "Claude provider SDK package set"),
        (github_scope, {"copilot", "copilot-sdk", copilot_platform_name}, "Copilot provider SDK package set"),
        (koromix_scope, {koffi_platform_name}, "Koffi provider package set"),
    )
    for scope, expected, label in scope_contracts:
        if scope.is_symlink() or not scope.is_dir():
            return 0, 0, f"{label} scope must be a real directory"
        scope_error = exact_directory_entries(scope, expected, label)
        if scope_error:
            return 0, 0, scope_error

    claude_sdk_root = claude_scope / "claude-agent-sdk"
    claude_binary_root = claude_scope / claude_platform_name
    copilot_root = github_scope / "copilot"
    copilot_sdk_root = github_scope / "copilot-sdk"
    copilot_binary_root = github_scope / copilot_platform_name
    koffi_binary_root = koromix_scope / koffi_platform_name
    package_entries = (
        (claude_sdk_root, CLAUDE_SDK_FILES, "Claude Agent SDK package"),
        (claude_binary_root, CLAUDE_BINARY_PACKAGE_FILES, "Claude Agent SDK platform package"),
        (copilot_root, COPILOT_PACKAGE_FILES, "Copilot CLI loader package"),
        (copilot_sdk_root, COPILOT_SDK_FILES, "Copilot SDK package"),
        (copilot_binary_root, COPILOT_PLATFORM_FILES, "Copilot CLI platform package"),
        (package_store / "detect-libc", TRANSITIVE_PACKAGE_FILES["detect-libc"], "detect-libc package"),
        (package_store / "koffi", TRANSITIVE_PACKAGE_FILES["koffi"], "koffi package"),
        (package_store / "vscode-jsonrpc", TRANSITIVE_PACKAGE_FILES["vscode-jsonrpc"], "vscode-jsonrpc package"),
        (package_store / "zod", TRANSITIVE_PACKAGE_FILES["zod"], "zod package"),
        (
            koffi_binary_root,
            {entry.format(architecture=architecture) for entry in TRANSITIVE_PACKAGE_FILES["koffi-platform"]},
            "Koffi platform package",
        ),
    )
    for package_root, expected, label in package_entries:
        if package_root.is_symlink() or not package_root.is_dir():
            return 0, 0, f"{label} must be a real directory"
        entries_error = exact_directory_entries(package_root, expected, label)
        if entries_error:
            return 0, 0, entries_error

    allowed_executables = {
        claude_binary_root / "claude",
        copilot_root / "npm-loader.js",
        package_store / "koffi" / "cnoke.cjs",
        package_store / "koffi" / "src/koffi/src/trampolines.cjs",
        *(
            copilot_binary_root / relative.format(architecture=architecture)
            for relative in COPILOT_PLATFORM_EXECUTABLES
        ),
    }
    if architecture == "x64":
        # Copilot CLI 1.0.78's reviewed x64 package intentionally ships
        # arm64 helper binaries for Rosetta/remote compatibility.
        allowed_executables.update({
            copilot_binary_root / "tgrep/bin/darwin-arm64/tgrep",
            copilot_binary_root / "ripgrep/bin/darwin-arm64/rg",
        })
    files, directories, inventory_error = provider_payload_inventory(root, allowed_executables)
    if inventory_error:
        return 0, 0, inventory_error

    for manifest_path in sorted(package_store.rglob("package.json")):
        relative = manifest_path.relative_to(package_store).as_posix()
        manifest, manifest_error = load_json_object(manifest_path, f"provider package {relative}")
        if manifest_error:
            return 0, 0, manifest_error
        _, scripts_error = package_lifecycle_scripts(manifest, relative)
        if scripts_error:
            return 0, 0, scripts_error
        if "scripts" in manifest:
            return 0, 0, f"provider SDK payload contains package scripts: {relative}"

    manifests: dict[str, dict[str, object]] = {}
    manifest_roots = {
        "@anthropic-ai/claude-agent-sdk": claude_sdk_root,
        f"@anthropic-ai/{claude_platform_name}": claude_binary_root,
        "@github/copilot": copilot_root,
        "@github/copilot-sdk": copilot_sdk_root,
        f"@github/{copilot_platform_name}": copilot_binary_root,
        "detect-libc": package_store / "detect-libc",
        "koffi": package_store / "koffi",
        f"@koromix/{koffi_platform_name}": koffi_binary_root,
        "vscode-jsonrpc": package_store / "vscode-jsonrpc",
        "zod": package_store / "zod",
    }
    for name, package_root in manifest_roots.items():
        manifest, manifest_error = load_json_object(package_root / "package.json", f"{name} package.json")
        if manifest_error:
            return 0, 0, manifest_error
        manifests[name] = manifest

    claude_manifest = manifests["@anthropic-ai/claude-agent-sdk"]
    if (
        claude_manifest.get("name") != "@anthropic-ai/claude-agent-sdk"
        or claude_manifest.get("version") != CLAUDE_AGENT_SDK_VERSION
        or claude_manifest.get("main") != "sdk.mjs"
        or claude_manifest.get("type") != "module"
        or claude_manifest.get("claudeCodeVersion") != CLAUDE_CODE_VERSION
        or claude_manifest.get("peerDependencies") != CLAUDE_PEER_DEPENDENCIES
        or claude_manifest.get("optionalDependencies") != CLAUDE_OPTIONAL_DEPENDENCIES
    ):
        return 0, 0, "Claude Agent SDK package is not the reviewed name/version/runtime"
    if any(
        key in claude_manifest
        for key in ("dependencies", "devDependencies", "bundledDependencies", "bundleDependencies", "scripts")
    ):
        return 0, 0, "Claude Agent SDK required dependencies and scripts are forbidden"

    claude_binary_manifest = manifests[f"@anthropic-ai/{claude_platform_name}"]
    if (
        claude_binary_manifest.get("name") != f"@anthropic-ai/{claude_platform_name}"
        or claude_binary_manifest.get("version") != CLAUDE_AGENT_SDK_VERSION
        or claude_binary_manifest.get("os") != ["darwin"]
        or claude_binary_manifest.get("cpu") != [architecture]
        or claude_binary_manifest.get("files") != ["claude", "README.md", "LICENSE.md"]
    ):
        return 0, 0, "Claude Agent SDK platform package is not the reviewed architecture/version"
    if "scripts" in claude_binary_manifest or any(
        key in claude_binary_manifest for key in FORBIDDEN_DEPENDENCY_KEYS
    ):
        return 0, 0, "Claude Agent SDK platform package dependencies and scripts are forbidden"

    copilot_manifest = manifests["@github/copilot"]
    if (
        copilot_manifest.get("name") != "@github/copilot"
        or copilot_manifest.get("version") != COPILOT_CLI_VERSION
        or copilot_manifest.get("type") != "module"
        or copilot_manifest.get("bin") != {"copilot": "npm-loader.js"}
        or copilot_manifest.get("files") != ["npm-loader.js", "README.md"]
        or copilot_manifest.get("dependencies") != {"detect-libc": "^2.1.2"}
        or copilot_manifest.get("optionalDependencies") != COPILOT_OPTIONAL_DEPENDENCIES
    ):
        return 0, 0, "Copilot CLI loader is not the reviewed exact 1.0.78 package"

    copilot_sdk_manifest = manifests["@github/copilot-sdk"]
    if (
        copilot_sdk_manifest.get("name") != "@github/copilot-sdk"
        or copilot_sdk_manifest.get("version") != COPILOT_SDK_VERSION
        or copilot_sdk_manifest.get("main") != "./dist/cjs/index.js"
        or copilot_sdk_manifest.get("type") != "module"
        or copilot_sdk_manifest.get("files") != ["dist/**/*", "docs/**/*", "README.md"]
        or copilot_sdk_manifest.get("dependencies") != COPILOT_SDK_DEPENDENCIES
        or copilot_sdk_manifest.get("engines") != {"node": "^20.19.0 || >=22.12.0"}
    ):
        return 0, 0, "Copilot SDK is not the reviewed exact 1.0.8 dependency contract"
    copilot_sdk_entry = copilot_sdk_root / "dist/cjs/index.js"
    if copilot_sdk_entry.is_symlink() or not copilot_sdk_entry.is_file():
        return 0, 0, "Copilot SDK entry point is missing or linked"

    copilot_binary_manifest = manifests[f"@github/{copilot_platform_name}"]
    if (
        copilot_binary_manifest.get("name") != f"@github/{copilot_platform_name}"
        or copilot_binary_manifest.get("version") != COPILOT_CLI_VERSION
        or copilot_binary_manifest.get("type") != "module"
        or copilot_binary_manifest.get("os") != ["darwin"]
        or copilot_binary_manifest.get("cpu") != [architecture]
        or copilot_binary_manifest.get("bin") != {copilot_platform_name: "copilot"}
    ):
        return 0, 0, "Copilot CLI platform package is not the reviewed architecture/version"

    transitive_contracts = {
        "detect-libc": ("2.1.2", "lib/detect-libc.js"),
        "koffi": (KOFFI_VERSION, "./index.cjs"),
        "vscode-jsonrpc": ("8.2.1", "./lib/node/main.js"),
        "zod": ("4.4.3", "./index.cjs"),
    }
    for name, (version, main_entry) in transitive_contracts.items():
        manifest = manifests[name]
        if (
            manifest.get("name") != name
            or manifest.get("version") != version
            or manifest.get("main") != main_entry
        ):
            return 0, 0, f"{name} is not the reviewed transitive dependency"
    if manifests["koffi"].get("optionalDependencies") != KOFFI_OPTIONAL_DEPENDENCIES:
        return 0, 0, "koffi optional dependency declaration changed"
    koffi_binary_manifest = manifests[f"@koromix/{koffi_platform_name}"]
    if (
        koffi_binary_manifest.get("name") != f"@koromix/{koffi_platform_name}"
        or koffi_binary_manifest.get("version") != KOFFI_VERSION
        or koffi_binary_manifest.get("main") != "./index.js"
        or koffi_binary_manifest.get("os") != ["darwin"]
        or koffi_binary_manifest.get("cpu") != [architecture]
    ):
        return 0, 0, "Koffi platform package is not the reviewed architecture/version"

    expected_cpu = 0x0100000C if architecture == "arm64" else 0x01000007
    for label, executable in (
        ("Claude Agent SDK", claude_binary_root / "claude"),
        ("Copilot CLI", copilot_binary_root / "copilot"),
    ):
        try:
            with executable.open("rb") as handle:
                header = handle.read(8)
        except OSError as exc:
            return 0, 0, f"cannot read {label} platform binary: {exc}"
        if (
            len(header) != 8
            or int.from_bytes(header[:4], "little") != 0xFEEDFACF
            or int.from_bytes(header[4:], "little") != expected_cpu
        ):
            return 0, 0, f"{label} binary architecture does not match the runtime"

    try:
        acl_paths = extended_acl_paths(root)
    except OSError as exc:
        return 0, 0, f"could not inspect provider SDK ACLs: {exc}"
    if acl_paths:
        return 0, 0, "provider SDK payload contains extended ACLs: " + ", ".join(acl_paths[:5])
    return files, directories, None


def safe_relative(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    path = Path(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        return None
    if not path.parts or path.parts[0] not in {"automation", "bin", "python", "provider-sdks"}:
        return None
    return path.as_posix()


def parse_expected_mode(value: object, relative: str, *, directory: bool) -> tuple[int, str] | str:
    if (
        not isinstance(value, str)
        or len(value) != 4
        or any(character not in "01234567" for character in value)
    ):
        return f"manifest contains an invalid mode for {relative}"
    mode = int(value, 8)
    if mode & UNSAFE_MODE_BITS:
        return f"manifest contains unsafe permissions for {relative}"
    if not mode & stat.S_IRUSR:
        return f"manifest omits owner read permission for {relative}"
    if directory and not mode & stat.S_IXUSR:
        return f"manifest directory is not owner-searchable: {relative}"
    return mode, value


def reduced_mode_error(expected: int, actual: int, relative: str, *, directory: bool) -> str | None:
    if actual & UNSAFE_MODE_BITS:
        return f"runtime package contains unsafe permissions for {relative}"
    if actual & ~expected:
        return f"runtime package permissions exceed the manifest for {relative}"
    if not actual & stat.S_IRUSR:
        return f"runtime package omits owner read permission for {relative}"
    if (directory or expected & 0o111) and not actual & stat.S_IXUSR:
        return f"runtime package omits required owner execute permission for {relative}"
    return None


def extended_acl_paths(root: Path) -> list[str]:
    if sys.platform != "darwin":
        return []
    libc = ctypes.CDLL(None, use_errno=True)
    libc.acl_get_file.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.acl_get_file.restype = ctypes.c_void_p
    libc.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    libc.acl_get_entry.restype = ctypes.c_int
    libc.acl_free.argtypes = [ctypes.c_void_p]
    libc.acl_free.restype = ctypes.c_int

    found: list[str] = []
    paths = [root, *sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())]
    for path in paths:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            continue
        ctypes.set_errno(0)
        acl = libc.acl_get_file(os.fsencode(path), 0x00000100)
        if not acl:
            error = ctypes.get_errno()
            if error in (0, errno.ENOENT):
                continue
            raise OSError(error, os.strerror(error), path)
        try:
            entry = ctypes.c_void_p()
            if libc.acl_get_entry(acl, 0, ctypes.byref(entry)) == 0:
                found.append("." if path == root else path.relative_to(root).as_posix())
        finally:
            libc.acl_free(acl)
    return found


def inventory(
    root: Path,
    *,
    require_python: bool,
) -> tuple[dict[str, tuple[Path, int]], dict[str, tuple[Path, int]], str | None]:
    files: dict[str, tuple[Path, int]] = {}
    directories: dict[str, tuple[Path, int]] = {}
    tops = [root / "automation", root / "bin", root / "provider-sdks"]
    if require_python or (root / "python").exists():
        tops.append(root / "python")
    for top in tops:
        if not top.is_dir() or top.is_symlink():
            return {}, {}, f"required runtime directory is missing or linked: {top.name}"
        top_relative = top.relative_to(root).as_posix()
        directories[top_relative] = (top, stat.S_IMODE(top.lstat().st_mode))
        for path in sorted(top.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if path.name == "__pycache__" or path.suffix == ".pyc":
                return {}, {}, f"runtime package contains forbidden Python bytecode: {relative}"
            if stat.S_ISLNK(metadata.st_mode):
                return {}, {}, f"runtime package contains a forbidden symlink: {relative}"
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISDIR(metadata.st_mode):
                directories[relative] = (path, mode)
            elif stat.S_ISREG(metadata.st_mode):
                files[relative] = (path, mode)
            else:
                return {}, {}, f"runtime package contains an unsupported entry: {relative}"
    return files, directories, None


def verify_manifest_entries(root: Path, manifest: dict[str, object]) -> tuple[int, int, str | None]:
    raw_files = manifest.get("files")
    raw_directories = manifest.get("directories")
    if not isinstance(raw_files, list) or not raw_files:
        return 0, 0, "manifest has no files"
    if not isinstance(raw_directories, list) or not raw_directories:
        return 0, 0, "manifest has no directories"

    expected_files: dict[str, tuple[str, int]] = {}
    for item in raw_files:
        if not isinstance(item, dict):
            return 0, 0, "manifest file entry is not an object"
        relative = safe_relative(item.get("path"))
        if relative is None:
            return 0, 0, f"manifest contains an unsafe path: {item.get('path')!r}"
        if relative in expected_files:
            return 0, 0, f"manifest contains a duplicate path: {relative}"
        if relative.endswith(".pyc") or "__pycache__" in Path(relative).parts:
            return 0, 0, f"manifest contains forbidden Python bytecode: {relative}"
        if (item.get("kind") or "file") != "file":
            return 0, 0, f"manifest contains an unsupported kind for {relative}"
        digest = item.get("sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest.lower())
        ):
            return 0, 0, f"manifest contains an invalid hash for {relative}"
        parsed_mode = parse_expected_mode(item.get("mode"), relative, directory=False)
        if isinstance(parsed_mode, str):
            return 0, 0, parsed_mode
        expected_files[relative] = (digest.lower(), parsed_mode[0])

    expected_directories: dict[str, int] = {}
    for item in raw_directories:
        if not isinstance(item, dict):
            return 0, 0, "manifest directory entry is not an object"
        relative = safe_relative(item.get("path"))
        if relative is None:
            return 0, 0, f"manifest contains an unsafe directory path: {item.get('path')!r}"
        if relative in expected_directories:
            return 0, 0, f"manifest contains a duplicate directory path: {relative}"
        if relative in expected_files:
            return 0, 0, f"manifest path is both a file and directory: {relative}"
        parsed_mode = parse_expected_mode(item.get("mode"), relative, directory=True)
        if isinstance(parsed_mode, str):
            return 0, 0, parsed_mode
        expected_directories[relative] = parsed_mode[0]

    require_python = any(path == "python" or path.startswith("python/") for path in expected_directories)
    actual_files, actual_directories, inventory_error = inventory(root, require_python=require_python)
    if inventory_error:
        return 0, 0, inventory_error
    missing_files = sorted(set(expected_files) - set(actual_files))
    unexpected_files = sorted(set(actual_files) - set(expected_files))
    missing_directories = sorted(set(expected_directories) - set(actual_directories))
    unexpected_directories = sorted(set(actual_directories) - set(expected_directories))
    if missing_files:
        return 0, 0, "runtime package files are missing: " + ", ".join(missing_files[:5])
    if unexpected_files:
        return 0, 0, "runtime package files are absent from manifest: " + ", ".join(unexpected_files[:5])
    if missing_directories:
        return 0, 0, "runtime package directories are missing: " + ", ".join(missing_directories[:5])
    if unexpected_directories:
        return 0, 0, "runtime package directories are absent from manifest: " + ", ".join(unexpected_directories[:5])

    for relative, (expected_hash, expected_mode) in expected_files.items():
        path, actual_mode = actual_files[relative]
        mode_error = reduced_mode_error(expected_mode, actual_mode, relative, directory=False)
        if mode_error:
            return 0, 0, mode_error
        if sha256_file(path).lower() != expected_hash:
            return 0, 0, f"runtime package entry mismatch for {relative}"
    for relative, expected_mode in expected_directories.items():
        _, actual_mode = actual_directories[relative]
        mode_error = reduced_mode_error(expected_mode, actual_mode, relative, directory=True)
        if mode_error:
            return 0, 0, mode_error
    return len(expected_files), len(expected_directories), None


def safe_archive_entry(path: Path, *, directory: bool) -> str | None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        return f"archive entry must not be a symlink: {path.name}"
    expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_kind(metadata.st_mode):
        return f"archive entry has the wrong type: {path.name}"
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & UNSAFE_MODE_BITS:
        return f"archive entry has unsafe permissions: {path.name}"
    if not mode & stat.S_IRUSR:
        return f"archive entry is not owner-readable: {path.name}"
    if directory and not mode & stat.S_IXUSR:
        return f"archive directory is not owner-searchable: {path.name}"
    return None


def verify_package_json(path: Path, version: str) -> tuple[bool, str | None]:
    if path.is_symlink() or not path.is_file():
        return False, "package.json must be a regular file, not a symlink"
    try:
        package = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"cannot read package.json: {exc}"
    cpu = package.get("cpu")
    if cpu not in (["arm64"], ["x64"]):
        return False, "package.json cpu does not match the publish policy"
    arch = cpu[0]
    required = {
        "name": f"@pairling/runtime-darwin-{arch}",
        "version": version,
        "files": ["automation", "bin", "python", "provider-sdks", "manifest.json"],
        "os": ["darwin"],
        "engines": {"node": ">=20"},
        "publishConfig": {"access": "public"},
    }
    for key, expected in required.items():
        if package.get(key) != expected:
            return False, f"package.json {key} does not match the publish policy"
    if not valid_repository(package.get("repository")):
        return False, "package.json repository does not match the publish policy"
    if "bin" in package:
        return False, "runtime package must not expose commands"
    if "scripts" in package:
        return False, "package.json lifecycle scripts are forbidden"
    for key in FORBIDDEN_DEPENDENCY_KEYS:
        if key in package:
            return False, f"package.json {key} is forbidden"
    return True, None


def verify_archive_shape(root: Path, manifest: dict[str, object], version: str) -> str | None:
    has_python = any(
        isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and (item["path"] == "python" or item["path"].startswith("python/"))
        for item in manifest.get("directories", [])
    )
    expected_root = {
        "README.md",
        "automation",
        "bin",
        "manifest.json",
        "package.json",
        "provider-sdks",
    }
    if has_python:
        expected_root.add("python")
    actual_root = {path.name for path in root.iterdir()}
    missing = sorted(expected_root - actual_root)
    unexpected = sorted(actual_root - expected_root)
    if missing:
        return "archive root entries are missing: " + ", ".join(missing)
    if unexpected:
        return "archive root has unexpected entries: " + ", ".join(unexpected)
    checks = (
        (root, True),
        (root / "automation", True),
        (root / "bin", True),
        (root / "provider-sdks", True),
        (root / "README.md", False),
        (root / "manifest.json", False),
        (root / "package.json", False),
    )
    for path, directory in checks:
        entry_error = safe_archive_entry(path, directory=directory)
        if entry_error:
            return entry_error
    _, policy_error = verify_package_json(root / "package.json", version)
    if policy_error:
        return policy_error
    try:
        acl_paths = extended_acl_paths(root)
    except OSError as exc:
        return f"could not inspect archive ACLs: {exc}"
    if acl_paths:
        return "archive contains extended ACLs: " + ", ".join(acl_paths[:5])
    return None


def _runtime_archive_member_parts(name: str) -> tuple[str, ...] | None:
    raw_parts = name.split("/")
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or path.is_absolute()
        or any(part in ("", ".", "..") for part in raw_parts)
        or not path.parts
        or path.parts[0] != "package"
    ):
        return None
    return path.parts


def _open_regular_runtime_archive(archive_path: Path):
    descriptor = os.open(
        archive_path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("runtime archive is not a regular file")
        return os.fdopen(descriptor, "rb")
    except Exception:
        os.close(descriptor)
        raise


def _extract_runtime_archive(archive_path: Path, destination: Path) -> str | None:
    seen: set[str] = set()
    directory_modes: list[tuple[Path, int]] = []
    total_bytes = 0
    member_count = 0
    try:
        with _open_regular_runtime_archive(archive_path) as archive_file, tarfile.open(
            fileobj=archive_file,
            mode="r:gz",
        ) as archive:
            for member in archive:
                member_count += 1
                if member_count > 200_000:
                    return "runtime archive contains too many members"
                parts = _runtime_archive_member_parts(member.name)
                if parts is None:
                    return f"runtime archive contains an unsafe archive path: {member.name!r}"
                relative = "/".join(parts)
                if relative in seen:
                    return f"runtime archive contains a duplicate path: {relative}"
                seen.add(relative)
                if member.type not in {
                    tarfile.REGTYPE,
                    tarfile.AREGTYPE,
                    tarfile.DIRTYPE,
                }:
                    return (
                        "runtime archive member is not a regular file or directory: "
                        f"{relative}"
                    )
                mode = member.mode & 0o7777
                if mode & UNSAFE_MODE_BITS or not mode & stat.S_IRUSR:
                    return f"runtime archive member has unsafe permissions: {relative}"
                if member.isdir() and not mode & stat.S_IXUSR:
                    return f"runtime archive directory is not owner-searchable: {relative}"
                if any(
                    key.startswith(
                        (
                            "GNU.sparse",
                            "LIBARCHIVE.xattr",
                            "RHT.security",
                            "SCHILY.acl",
                            "SCHILY.xattr",
                        )
                    )
                    for key in member.pax_headers
                ):
                    return f"runtime archive member has forbidden metadata: {relative}"
                if member.size < 0:
                    return "runtime archive member has an invalid size"
                total_bytes += member.size
                if total_bytes > 4 * 1024 * 1024 * 1024:
                    return "runtime archive expands beyond the Pairling package limit"

                target = destination.joinpath(*parts)
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    directory_modes.append((target, mode))
                    continue
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    return f"runtime archive member is unreadable: {relative}"
                descriptor = None
                try:
                    descriptor = os.open(
                        target,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_NOFOLLOW", 0),
                        mode,
                    )
                    remaining = member.size
                    with os.fdopen(descriptor, "wb", closefd=False) as output:
                        while remaining:
                            chunk = source.read(min(1024 * 1024, remaining))
                            if not chunk:
                                return (
                                    "runtime archive member size is inconsistent: "
                                    f"{relative}"
                                )
                            output.write(chunk)
                            remaining -= len(chunk)
                    os.fchmod(descriptor, mode)
                finally:
                    source.close()
                    if descriptor is not None:
                        os.close(descriptor)
    except (OSError, tarfile.TarError) as exc:
        return f"cannot safely extract runtime archive: {type(exc).__name__}: {exc}"
    if not seen:
        return "runtime archive is empty"
    for path, mode in sorted(
        directory_modes,
        key=lambda item: len(item[0].parts),
        reverse=True,
    ):
        try:
            path.chmod(mode)
        except OSError as exc:
            return f"cannot apply runtime archive directory permissions: {type(exc).__name__}"
    return None


def extract_npm_archive(archive_path: Path, destination: Path) -> str | None:
    """Safely extract one npm package archive below a fresh destination."""
    return _extract_runtime_archive(Path(archive_path), Path(destination))


def verify_runtime_package_root(
    root_input: Path,
    expected_version: str,
    expected_revision: str,
    *,
    expected_architecture: str | None = None,
    archive_mode: bool = False,
    require_vendored_python: bool = False,
) -> tuple[int, int, str | None]:
    if root_input.is_symlink() or not root_input.is_dir():
        return 0, 0, "runtime package root must be a real directory"
    root = root_input.resolve()
    manifest_path = root / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        return 0, 0, "runtime package manifest must be a regular file, not a symlink"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return 0, 0, f"cannot read manifest: {exc}"
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 2:
        return 0, 0, "unsupported manifest schema"
    if manifest.get("package_version") != expected_version:
        return 0, 0, "package version does not match the Pairling payload"
    if manifest.get("source_revision") != expected_revision:
        return 0, 0, "source revision does not match the Pairling payload"
    architecture = manifest.get("architecture")
    if architecture not in ("arm64", "x64"):
        return 0, 0, "runtime package architecture is missing or unsupported"
    if expected_architecture is not None and architecture != expected_architecture:
        return 0, 0, "runtime package architecture does not match the expected package"
    evidence_sha256 = manifest.get("release_evidence_sha256")
    if evidence_sha256 is not None and not valid_sha256(evidence_sha256):
        return 0, 0, "runtime package release evidence digest is invalid"
    if "python_archive_sha256" not in manifest:
        return 0, 0, "runtime package Python archive digest is missing"
    python_archive_sha256 = manifest.get("python_archive_sha256")
    if python_archive_sha256 is not None and not valid_sha256(python_archive_sha256):
        return 0, 0, "runtime package Python archive digest is invalid"
    if "automation_archive_sha256" not in manifest:
        return 0, 0, "runtime package automation archive digest is missing"
    automation_archive_sha256 = manifest.get("automation_archive_sha256")
    if not valid_sha256(automation_archive_sha256):
        return 0, 0, "runtime package automation archive digest is invalid"
    if "automation_tree_sha256" not in manifest:
        return 0, 0, "runtime package automation helper tree digest is missing"
    automation_tree_sha256 = manifest.get("automation_tree_sha256")
    if not valid_sha256(automation_tree_sha256):
        return 0, 0, "runtime package automation helper tree digest is invalid"
    identity_entries = {
        item.get("path"): item
        for item in manifest.get("files", [])
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    connectd = identity_entries.get("bin/pairling-connectd")
    if (
        not isinstance(connectd, dict)
        or connectd.get("identifier") != "dev.pairling.connectd"
        or connectd.get("architecture") != architecture
    ):
        return (
            0,
            0,
            "connectd identity is missing or does not match the runtime architecture",
        )
    automation_entry = identity_entries.get(
        "automation/Pairling.app/Contents/MacOS/PairlingAutomation"
    )
    if (
        not isinstance(automation_entry, dict)
        or automation_entry.get("identifier") != "dev.pairling.automation"
        or automation_entry.get("architecture") != architecture
        or (
            connectd.get("team_id")
            and automation_entry.get("team_id") != connectd.get("team_id")
        )
    ):
        return (
            0,
            0,
            "automation helper identity is missing or does not match connectd",
        )
    python_entry = identity_entries.get("python/bin/python3")
    if require_vendored_python and python_entry is None:
        return 0, 0, "vendored Python is required in a release runtime package"
    if (python_entry is None) != (python_archive_sha256 is None):
        return (
            0,
            0,
            "runtime package Python archive digest does not match vendored Python presence",
        )
    if python_entry is not None and (
        not isinstance(python_entry, dict)
        or python_entry.get("identifier") != "dev.pairling.python"
        or python_entry.get("architecture") != architecture
        or (
            connectd.get("team_id")
            and python_entry.get("team_id") != connectd.get("team_id")
        )
    ):
        return 0, 0, "vendored Python identity is missing or does not match connectd"
    _, _, provider_error = verify_provider_sdks(root / "provider-sdks", architecture)
    if provider_error:
        return 0, 0, provider_error

    file_count, directory_count, entry_error = verify_manifest_entries(root, manifest)
    if entry_error:
        return 0, 0, entry_error
    try:
        actual_automation_tree_sha256 = tree_sha256(root / "automation" / "Pairling.app")
    except (OSError, ValueError) as exc:
        return 0, 0, f"cannot inspect automation helper tree: {exc}"
    if actual_automation_tree_sha256 != automation_tree_sha256:
        return 0, 0, "automation helper tree digest does not match the runtime manifest"
    scope_roots = [root / "automation", root / "bin", root / "provider-sdks"]
    if (root / "python").exists():
        scope_roots.append(root / "python")
    try:
        acl_paths = [
            f"{scope.name}/{relative}" if relative != "." else scope.name
            for scope in scope_roots
            for relative in extended_acl_paths(scope)
        ]
    except OSError as exc:
        return 0, 0, f"could not inspect runtime package ACLs: {exc}"
    if acl_paths:
        return (
            0,
            0,
            "runtime package contains extended ACLs: " + ", ".join(acl_paths[:5]),
        )
    if archive_mode:
        shape_error = verify_archive_shape(root, manifest, expected_version)
        if shape_error:
            return 0, 0, shape_error
    return file_count, directory_count, None


def verify_runtime_archive(
    archive_path: Path,
    expected_version: str,
    expected_revision: str,
    expected_architecture: str,
    *,
    require_vendored_python: bool = False,
) -> tuple[int, int, str | None]:
    if expected_architecture not in {"arm64", "x64"}:
        return 0, 0, "expected runtime package architecture is unsupported"
    archive_path = Path(archive_path)
    try:
        metadata = archive_path.lstat()
    except OSError as exc:
        return 0, 0, f"cannot inspect runtime archive: {type(exc).__name__}"
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return 0, 0, "runtime archive must be a regular file, not a symlink"
    with tempfile.TemporaryDirectory(prefix="pairling-runtime-verify-") as temporary:
        destination = Path(temporary)
        extraction_error = _extract_runtime_archive(archive_path, destination)
        if extraction_error:
            return 0, 0, extraction_error
        return verify_runtime_package_root(
            destination / "package",
            expected_version,
            expected_revision,
            expected_architecture=expected_architecture,
            archive_mode=True,
            require_vendored_python=require_vendored_python,
        )


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] == "--provider-runtime-assets":
        if len(args) != 2:
            return fail(
                "usage: verify-runtime-package-manifest.py --provider-runtime-assets "
                "<provider-directory>"
            )
        asset_error = verify_provider_runtime_assets(Path(args[1]))
        if asset_error:
            return fail(asset_error)
        print(
            "provider runtime assets verified: "
            + ", ".join(PROVIDER_RUNTIME_ASSET_NAMES)
        )
        return 0
    if args and args[0] == "--stage-provider-runtime-assets":
        if len(args) != 3:
            return fail(
                "usage: verify-runtime-package-manifest.py --stage-provider-runtime-assets "
                "<source-provider-directory> <destination-provider-directory>"
            )
        asset_error = stage_provider_runtime_assets(Path(args[1]), Path(args[2]))
        if asset_error:
            return fail(asset_error)
        print(
            "provider runtime assets staged and verified: "
            + ", ".join(PROVIDER_RUNTIME_ASSET_NAMES)
        )
        return 0
    if args and args[0] == "--provider-sdk-lock":
        if len(args) != 2:
            return fail(
                "usage: verify-runtime-package-manifest.py --provider-sdk-lock "
                "<provider-sdk-root>"
            )
        lock_error = verify_provider_lock(
            Path(args[1]),
            lock_name="package-lock.json",
        )
        if lock_error:
            return fail(lock_error)
        print("provider SDK lock verified")
        return 0
    if args and args[0] == "--sanitize-provider-sdks":
        if len(args) != 3:
            return fail(
                "usage: verify-runtime-package-manifest.py --sanitize-provider-sdks "
                "<node-modules-root> <architecture>"
            )
        lifecycle_error = sanitize_provider_lifecycle_scripts(Path(args[1]), args[2])
        if lifecycle_error:
            return fail(lifecycle_error)
        print("provider SDK package scripts removed from the reviewed inert payload")
        return 0
    if args and args[0] in {"--provider-sdks", "--installed-provider-sdks"}:
        mode = args[0]
        if len(args) != 3:
            return fail(
                f"usage: verify-runtime-package-manifest.py {mode} "
                "<provider-sdk-root> <architecture>"
            )
        file_count, directory_count, provider_error = verify_provider_sdks(
            Path(args[1]),
            args[2],
            package_directory="node_modules" if mode == "--installed-provider-sdks" else "packages",
        )
        if provider_error:
            return fail(provider_error)
        print(
            "provider SDK payload verified: "
            f"{file_count} files, {directory_count} directories"
        )
        return 0
    archive_mode = bool(args and args[0] == "--archive")
    if archive_mode:
        args = args[1:]
    if len(args) != 3:
        return fail(
            "usage: verify-runtime-package-manifest.py [--archive] "
            "<runtime-package-root> <expected-version> <expected-source-revision>"
        )
    root_input = Path(args[0])
    expected_version = args[1]
    expected_revision = args[2]
    file_count, directory_count, verification_error = verify_runtime_package_root(
        root_input,
        expected_version,
        expected_revision,
        archive_mode=archive_mode,
    )
    if verification_error:
        return fail(verification_error)
    print(
        "runtime package manifest verified: "
        f"{file_count} files, {directory_count} directories"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
