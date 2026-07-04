#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def fail(message: str) -> int:
    print(f"payload manifest verification failed: {message}", file=sys.stderr)
    return 1


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def payload_file(payload_root: Path, rel: str) -> Path | None:
    path = Path(rel)
    if path.is_absolute() or ".." in path.parts:
        return None
    parts = path.parts
    if not parts or parts[0] != "payload":
        return None
    return payload_root.joinpath(*parts[1:])


def main() -> int:
    if len(sys.argv) != 3:
        return fail("usage: verify-payload-manifest.py <payload-root> <payload-manifest.json>")
    payload_root = Path(sys.argv[1]).resolve()
    manifest_path = Path(sys.argv[2]).resolve()
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return fail(f"cannot read manifest: {exc}")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        return fail("unsupported manifest schema")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        return fail("manifest has no files")
    for item in files:
        if not isinstance(item, dict):
            return fail("manifest file entry is not an object")
        rel = str(item.get("path") or "")
        expected = str(item.get("sha256") or "")
        if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected.lower()):
            return fail(f"bad sha256 for {rel or '<missing path>'}")
        target = payload_file(payload_root, rel)
        if target is None:
            return fail(f"bad payload path {rel!r}")
        try:
            resolved = target.resolve(strict=True)
        except OSError:
            return fail(f"missing payload file {rel}")
        if payload_root not in (resolved, *resolved.parents):
            return fail(f"payload path escapes root {rel!r}")
        actual = sha256(resolved)
        if actual.lower() != expected.lower():
            return fail(f"sha256 mismatch for {rel}")
    print(f"payload manifest verified: {len(files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
