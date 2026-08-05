from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


APERTURE_CLI_KNOWN_VERSION = "v0.0.8"
APERTURE_CLI_STATUS_PATH = "/aperture-cli/status"
APERTURE_CLI_PROVIDER_PATH = "/aperture-cli/providers"
DEFAULT_ENDPOINT = "http://ai"
PROVIDER_TIMEOUT_SECONDS = 10


def _redact_home(path: Path, home: Path) -> str:
    try:
        return "~/" + str(path.resolve().relative_to(home.resolve()))
    except Exception:
        return str(path)


def _run_text(args: list[str], timeout: int = 3) -> tuple[bool, str]:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {str(exc)[:160]}"
    text = (proc.stdout or proc.stderr or "").strip()
    return proc.returncode == 0, text[:400]


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    result: list[Path] = []
    for path in paths:
        key = str(path.expanduser())
        if key in seen:
            continue
        seen.add(key)
        result.append(path.expanduser())
    return result


def _safe_str(value: Any, limit: int = 240) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    return value[:limit]


def _safe_bool(value: Any) -> bool:
    return bool(value) if isinstance(value, bool) else False


def _canonical_endpoint_url(raw: str) -> tuple[str, str | None, str | None, bool]:
    value = raw.strip().rstrip("/")
    if not value:
        return "", None, None, False
    normalized = value if "://" in value else f"http://{value}"
    parsed = urllib.parse.urlsplit(normalized)
    try:
        parsed.port
    except ValueError:
        return value, None, None, normalized != value
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        return value, None, None, normalized != value
    path = parsed.path.rstrip("/")
    canonical = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", "")).rstrip("/")
    return canonical, parsed.netloc, parsed.hostname, canonical != value


def _normalized_host(host: str) -> str:
    value = host.rstrip(".")
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        return value.encode("idna").decode("ascii").lower()


def _url_origin(url: str, *, redirect: bool = False) -> tuple[str, str, int]:
    label = "redirect" if redirect else "endpoint"
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
        host = _normalized_host(parsed.hostname or "")
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f"Aperture {label} URL is invalid.") from exc
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"Aperture {label} credentials are not allowed.")
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not host:
        raise ValueError(f"Aperture {label} must use HTTP or HTTPS with a host.")
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    return scheme, host, effective_port


def _resolve_destination_addresses(
    host: str,
    port: int,
) -> frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for family, _, _, _, sockaddr in socket.getaddrinfo(
        host,
        port,
        type=socket.SOCK_STREAM,
    ):
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        address = str(sockaddr[0]).split("%", 1)[0]
        addresses.add(ipaddress.ip_address(address))
    if not addresses:
        raise OSError(f"no IP addresses resolved for {host}")
    return frozenset(addresses)


def _is_private_destination(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    return address.is_private or address.is_loopback or address.is_link_local


class _ApertureRedirectError(urllib.error.URLError):
    pass


class _ValidatedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(
        self,
        original_url: str,
        original_addresses: frozenset[
            ipaddress.IPv4Address | ipaddress.IPv6Address
        ],
    ) -> None:
        self._original_origin = _url_origin(original_url)
        self._explicit_private_addresses = frozenset(
            address
            for address in original_addresses
            if _is_private_destination(address)
        )

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirect_url = urllib.parse.urljoin(req.full_url, newurl)
        try:
            redirect_origin = _url_origin(redirect_url, redirect=True)
        except ValueError as exc:
            raise _ApertureRedirectError(str(exc)) from exc
        if redirect_origin != self._original_origin:
            raise _ApertureRedirectError(
                "Aperture redirect origin must match the configured endpoint."
            )
        try:
            redirect_addresses = _resolve_destination_addresses(
                redirect_origin[1],
                redirect_origin[2],
            )
        except OSError as exc:
            raise _ApertureRedirectError(
                "Aperture redirect destination address resolution failed."
            ) from exc
        private_addresses = frozenset(
            address
            for address in redirect_addresses
            if _is_private_destination(address)
        )
        if not private_addresses.issubset(self._explicit_private_addresses):
            raise _ApertureRedirectError(
                "Aperture private redirect destination was not the explicit "
                "original endpoint."
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _normalize_endpoint(obj: Any) -> dict[str, Any] | None:
    if not isinstance(obj, dict):
        return None
    url = _safe_str(obj.get("url"))
    if not url:
        return None
    bridge_id = _safe_str(obj.get("bridgeId"), 96)
    normalized_url, display_host, host, normalized = _canonical_endpoint_url(url)
    if display_host is None or host is None:
        return None
    return {
        "url": normalized_url,
        "mode": "bridge" if bridge_id else "direct",
        "bridge_id": bridge_id,
        "runtime_url": normalized_url,
        "display_host": display_host or url.rstrip("/"),
        "normalized_url": normalized_url,
        "host": host,
        "normalized": normalized,
        "stale": False,
    }


def _dedupe_endpoints(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str | None]] = set()
    result: list[dict[str, Any]] = []
    for endpoint in endpoints:
        key = (
            str(endpoint.get("normalized_url") or endpoint.get("url") or ""),
            str(endpoint.get("mode") or "direct"),
            endpoint.get("bridge_id"),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(endpoint)
    return result


def _normalize_bridge(obj: Any) -> dict[str, Any] | None:
    if not isinstance(obj, dict):
        return None
    bridge_id = _safe_str(obj.get("id"), 96)
    name = _safe_str(obj.get("name"), 120)
    if not bridge_id:
        return None
    return {"id": bridge_id, "name": name or bridge_id}


def _parse_provider_items(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    items: list[dict[str, Any]] = []
    for obj in raw:
        if not isinstance(obj, dict):
            continue
        provider_id = _safe_str(obj.get("id"), 120)
        if not provider_id:
            continue
        compatibility = obj.get("compatibility")
        if not isinstance(compatibility, dict):
            compatibility = {}
        models = obj.get("models")
        if not isinstance(models, list):
            models = []
        items.append({
            "id": provider_id,
            "name": _safe_str(obj.get("name"), 160) or provider_id,
            "description": _safe_str(obj.get("description"), 500) or "",
            "models": [m[:240] for m in models if isinstance(m, str)],
            "compatibility": {str(k): bool(v) for k, v in compatibility.items()},
        })
    return items


class ApertureCLIProbe:
    """Read-only probe for Aperture CLI's local launcher state."""

    def __init__(
        self,
        home: Path | None = None,
        env: dict[str, str] | None = None,
        now: float | None = None,
    ) -> None:
        self.home = (home or Path.home()).expanduser()
        self.env = env if env is not None else os.environ
        self.now = now

    @property
    def config_root(self) -> Path:
        return self.home / "Library" / "Application Support" / "aperture"

    @property
    def settings_path(self) -> Path:
        return self.config_root / "settings.json"

    @property
    def launcher_path(self) -> Path:
        return self.config_root / "launcher.json"

    def resolve_binary(self) -> tuple[Path | None, str | None]:
        candidates: list[tuple[Path, str]] = [
            (self.home / "go" / "bin" / "aperture", "known_gopath"),
            (self.home / ".local" / "bin" / "aperture", "known_local"),
            (Path("/opt/homebrew/bin/aperture"), "known_homebrew"),
            (Path("/usr/local/bin/aperture"), "known_usr_local"),
        ]
        for prefix in self.env.get("PATH", "").split(":"):
            if prefix:
                candidates.append((Path(prefix) / "aperture", "path"))
        seen: set[str] = set()
        for path, source in candidates:
            path = path.expanduser()
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            if path.exists() and os.access(path, os.X_OK):
                return path, source
        return None, None

    def _read_json(self, path: Path) -> tuple[bool, dict[str, Any], str | None]:
        if not path.is_file():
            return False, {}, None
        try:
            obj = json.loads(path.read_text(errors="replace"))
        except Exception as exc:
            return True, {}, f"{type(exc).__name__}: {str(exc)[:160]}"
        if not isinstance(obj, dict):
            return True, {}, "JSON root is not an object"
        return True, obj, None

    def _settings_payload(self) -> dict[str, Any]:
        found, obj, error = self._read_json(self.settings_path)
        endpoints = []
        for item in obj.get("endpoints", []) if isinstance(obj.get("endpoints"), list) else []:
            endpoint = _normalize_endpoint(item)
            if endpoint:
                endpoints.append(endpoint)
        raw_endpoint_count = len(endpoints)
        endpoints = _dedupe_endpoints(endpoints)
        if not endpoints:
            endpoints = [_normalize_endpoint({"url": DEFAULT_ENDPOINT}) or {
                "url": DEFAULT_ENDPOINT,
                "mode": "direct",
                "bridge_id": None,
                "runtime_url": DEFAULT_ENDPOINT,
                "display_host": "ai",
                "normalized_url": DEFAULT_ENDPOINT,
                "host": "ai",
                "normalized": False,
                "stale": False,
            }]
            raw_endpoint_count = 0
        bridges = []
        for item in obj.get("bridges", []) if isinstance(obj.get("bridges"), list) else []:
            bridge = _normalize_bridge(item)
            if bridge:
                bridges.append(bridge)
        return {
            "found": found,
            "path_redacted": _redact_home(self.settings_path, self.home),
            "parse_error": error,
            "active_endpoint": endpoints[0],
            "endpoints": endpoints,
            "bridges": bridges,
            "endpoint_count": len(endpoints),
            "raw_endpoint_count": raw_endpoint_count,
            "bridge_count": len(bridges),
            "yolo_mode": _safe_bool(obj.get("yoloMode")),
        }

    def _last_launch_payload(self) -> dict[str, Any]:
        found, obj, error = self._read_json(self.launcher_path)
        return {
            "found": found,
            "path_redacted": _redact_home(self.launcher_path, self.home),
            "parse_error": error,
            "client_name": _safe_str(obj.get("lastClientName") or obj.get("lastProfileName"), 120),
            "backend_type": _safe_str(obj.get("lastBackendType"), 120),
            "provider_id": _safe_str(obj.get("lastProviderId"), 120),
            "model": _safe_str(obj.get("lastModel"), 240),
        }

    def fetch_providers(self, endpoint: dict[str, Any]) -> dict[str, Any]:
        raw_base_url = str(
            endpoint.get("runtime_url")
            or endpoint.get("normalized_url")
            or endpoint.get("url")
            or DEFAULT_ENDPOINT
        )
        base_url, display_host, host, _ = _canonical_endpoint_url(raw_base_url)
        if display_host is None or host is None:
            return {
                "reachable": False,
                "items": [],
                "count": 0,
                "compatibility_keys": [],
                "source_endpoint": {**endpoint, "stale": True},
                "last_error": "Aperture endpoint must use HTTP or HTTPS.",
            }
        url = base_url + "/api/providers"
        mode = endpoint.get("mode") or "direct"
        if mode == "bridge":
            return {
                "reachable": False,
                "items": [],
                "count": 0,
                "compatibility_keys": [],
                "source_endpoint": endpoint,
                "last_error": "Bridge endpoints require an active Aperture CLI tsnet proxy; Pairling native bridge probing is not enabled yet.",
            }
        try:
            original_origin = _url_origin(url)
            original_addresses = _resolve_destination_addresses(
                original_origin[1],
                original_origin[2],
            )
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                _ValidatedRedirectHandler(url, original_addresses),
            )
            with opener.open(url, timeout=PROVIDER_TIMEOUT_SECONDS) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                status = getattr(response, "status", 200)
                body = response.read(1024 * 1024)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            source_endpoint = {**endpoint, "stale": True}
            return {
                "reachable": False,
                "items": [],
                "count": 0,
                "compatibility_keys": [],
                "source_endpoint": source_endpoint,
                "last_error": f"{type(exc).__name__}: {str(exc)[:220]}",
            }
        if status < 200 or status >= 300:
            source_endpoint = {**endpoint, "stale": True}
            return {
                "reachable": False,
                "items": [],
                "count": 0,
                "compatibility_keys": [],
                "source_endpoint": source_endpoint,
                "last_error": f"unexpected status {status} from {url}",
            }
        try:
            raw = json.loads(body.decode("utf-8", errors="replace"))
        except Exception as exc:
            source_endpoint = {**endpoint, "stale": True}
            return {
                "reachable": False,
                "items": [],
                "count": 0,
                "compatibility_keys": [],
                "source_endpoint": source_endpoint,
                "last_error": f"provider JSON parse failed: {type(exc).__name__}: {str(exc)[:160]}",
            }
        items = _parse_provider_items(raw)
        compatibility_keys = sorted({
            key
            for item in items
            for key, enabled in item.get("compatibility", {}).items()
            if enabled
        })
        return {
            "reachable": True,
            "items": items,
            "count": len(items),
            "ids": [item["id"] for item in items],
            "compatibility_keys": compatibility_keys,
            "source_endpoint": endpoint,
            "last_error": None,
        }

    def status(self) -> dict[str, Any]:
        observed_at = self.now if self.now is not None else time.time()
        binary, source = self.resolve_binary()
        version = None
        help_text = ""
        help_flags: list[str] = []
        if binary:
            ok, text = _run_text([str(binary), "-version"], timeout=3)
            if ok:
                version = text
            ok, help_text = _run_text([str(binary), "--help"], timeout=3)
            if ok:
                for flag in ("-debug", "-version"):
                    if flag in help_text:
                        help_flags.append(flag)
        settings = self._settings_payload()
        last_launch = self._last_launch_payload()
        providers = self.fetch_providers(settings["active_endpoint"])
        warnings: list[str] = [
            "Aperture CLI is experimental; Pairling is using a version-pinned v0.0.8 contract."
        ]
        if binary is None:
            warnings.append("Aperture CLI binary was not found.")
        elif version and version != APERTURE_CLI_KNOWN_VERSION:
            warnings.append(f"Aperture CLI version {version} differs from tested {APERTURE_CLI_KNOWN_VERSION}.")
        if settings.get("parse_error"):
            warnings.append("Aperture CLI settings could not be parsed; Pairling is using the default endpoint.")
        return {
            "ok": True,
            "schema_version": 1,
            "installed": binary is not None,
            "version": version,
            "known_version": APERTURE_CLI_KNOWN_VERSION,
            "binary_path": str(binary) if binary else None,
            "binary_path_source": source,
            "help_flags": help_flags,
            "settings": settings,
            "last_launch": last_launch,
            "providers": {k: v for k, v in providers.items() if k != "items"},
            "capabilities": {
                "native_pairling_launch_supported": False,
                "raw_aperture_tui_supported": binary is not None,
                "bridge_probe_supported": False,
            },
            "warnings": warnings,
            "observed_at": observed_at,
        }

    def providers_payload(self) -> dict[str, Any]:
        settings = self._settings_payload()
        providers = self.fetch_providers(settings["active_endpoint"])
        return {
            "ok": True,
            "schema_version": 1,
            "source_endpoint": providers["source_endpoint"],
            "reachable": providers["reachable"],
            "items": providers["items"],
            "count": providers["count"],
            "ids": providers.get("ids", []),
            "compatibility_keys": providers["compatibility_keys"],
            "last_error": providers["last_error"],
            "observed_at": self.now if self.now is not None else time.time(),
        }


def status_payload(home: Path | None = None, env: dict[str, str] | None = None) -> dict[str, Any]:
    return ApertureCLIProbe(home=home, env=env).status()


def provider_payload(home: Path | None = None, env: dict[str, str] | None = None) -> dict[str, Any]:
    return ApertureCLIProbe(home=home, env=env).providers_payload()
