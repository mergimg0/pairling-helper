"""Posture store (SPEC-p6 §2.2): user-authored markdown instruction files.

A posture is one `.md` file under `~/.pairling/postures/` with optional
YAML-shaped frontmatter carrying `name` and `description`. The Mac is the
source of truth; the daemon reflects the directory read/write. Every opinion
in a posture is the user's own markdown — this module never rewrites or
augments content, it only stores and parses.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

POSTURE_MAX_BYTES = 8 * 1024
_SLUG_RE = re.compile(r"^[a-z0-9-]{1,64}$")
_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?", re.DOTALL)


class PostureTooLarge(ValueError):
    """The posture body exceeds POSTURE_MAX_BYTES."""


def default_root() -> Path:
    return Path(os.path.expanduser("~")) / ".pairling" / "postures"


def valid_slug(slug: str) -> bool:
    return bool(_SLUG_RE.match(slug or ""))


def slug_for_name(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return slug[:64]


def _parse_frontmatter(source: str) -> tuple[dict, str]:
    match = _FRONTMATTER_RE.match(source)
    if not match:
        return {}, source
    fields: dict = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip().lower()] = value.strip()
    return fields, source[match.end():]


def list_postures(root: Path) -> list[dict]:
    rows: list[dict] = []
    try:
        paths = sorted(root.glob("*.md"))
    except OSError:
        return rows
    for path in paths:
        slug = path.stem
        if not valid_slug(slug):
            continue
        try:
            source = path.read_text(encoding="utf-8")
            mtime = path.stat().st_mtime
        except OSError:
            continue
        fields, _body = _parse_frontmatter(source)
        rows.append({
            "slug": slug,
            "name": fields.get("name") or slug,
            "description": fields.get("description") or "",
            "mtime": mtime,
        })
    return rows


def read_posture(root: Path, slug: str) -> dict | None:
    if not valid_slug(slug):
        return None
    path = root / f"{slug}.md"
    try:
        source = path.read_text(encoding="utf-8")
        mtime = path.stat().st_mtime
    except OSError:
        return None
    fields, body = _parse_frontmatter(source)
    return {
        "slug": slug,
        "name": fields.get("name") or slug,
        "description": fields.get("description") or "",
        "body": body.strip(),
        "source": source,
        "mtime": mtime,
    }


def write_posture(root: Path, *, name: str, description: str, body: str) -> dict:
    slug = slug_for_name(name)
    if not valid_slug(slug):
        raise ValueError("posture name yields no usable slug")
    if len((body or "").encode("utf-8")) > POSTURE_MAX_BYTES:
        raise PostureTooLarge(f"posture body exceeds {POSTURE_MAX_BYTES} bytes")
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{slug}.md"
    overwrote = path.exists()
    source = f"---\nname: {name.strip()}\ndescription: {(description or '').strip()}\n---\n{(body or '').strip()}\n"
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(source)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    return {
        "slug": slug,
        "name": name.strip(),
        "description": (description or "").strip(),
        "overwrote": overwrote,
        "mtime": time.time(),
    }


def delete_posture(root: Path, slug: str) -> bool:
    if not valid_slug(slug):
        return False
    path = root / f"{slug}.md"
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False
