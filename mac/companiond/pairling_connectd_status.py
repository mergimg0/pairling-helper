from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any

CONNECTD_STATUS_URL = "http://127.0.0.1:7774/status"
PAIRLING_CONNECT_ROUTE_SOURCE = "pairling_connectd"
PAIRLING_CONNECT_ROUTE_KIND = "tailnet"
PAIRLING_CONNECT_FUNNEL_KIND = "funnel"
PAIRLING_CONNECT_PORT = 7773
PAIRLING_CONNECT_FUNNEL_PORT = 443


def fetch_connectd_status(timeout_seconds: float = 1.5) -> dict[str, Any]:
    fixture = os.environ.get("PAIRLING_TEST_CONNECTD_STATUS_JSON")
    if fixture:
        payload = json.loads(fixture)
        return payload if isinstance(payload, dict) else {}

    req = urllib.request.Request(CONNECTD_STATUS_URL, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def advertised_pairling_connect_routes(status: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(status, dict) or int(status.get("schema_version") or 0) < 2:
        return []
    routes = status.get("advertised_routes") or []
    if not isinstance(routes, list):
        return []

    valid_routes: list[dict[str, Any]] = []
    for route in routes:
        if not isinstance(route, dict):
            continue
        if route.get("source") != PAIRLING_CONNECT_ROUTE_SOURCE:
            continue
        kind = route.get("kind")
        if kind not in (PAIRLING_CONNECT_ROUTE_KIND, PAIRLING_CONNECT_FUNNEL_KIND):
            continue
        if route.get("status") != "ready":
            continue
        host = str(route.get("host") or "").strip()
        try:
            port = int(route.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if kind == PAIRLING_CONNECT_FUNNEL_KIND:
            # Funnel route: public https on a *.ts.net host, lowest priority. The
            # tailnet branch below is unchanged and not loosened.
            base_url = _sanitized_funnel_base_url(route.get("base_url"), host, port)
            default_id = "pairling-connect-funnel"
            default_priority = 10
        else:
            if port != PAIRLING_CONNECT_PORT or not _is_tailnet_host(host):
                continue
            base_url = _sanitized_base_url(route.get("base_url"), host, port)
            default_id = "pairling-connect-tailnet"
            default_priority = 100
        if not base_url:
            continue
        valid = {
            "id": str(route.get("id") or default_id),
            "kind": kind,
            "source": PAIRLING_CONNECT_ROUTE_SOURCE,
            "priority": int(route.get("priority") or default_priority),
            "base_url": base_url,
            "host": host,
            "port": port,
            "status": "ready",
        }
        valid_routes.append(valid)
    valid_routes.sort(key=lambda item: int(item.get("priority") or 0), reverse=True)
    return valid_routes


def preferred_pairling_connect_base_url(status: dict[str, Any]) -> str | None:
    routes = advertised_pairling_connect_routes(status)
    if not routes:
        return None
    return str(routes[0]["base_url"])


def redacted_connectd_summary(status: dict[str, Any]) -> dict[str, Any]:
    routes = advertised_pairling_connect_routes(status)
    return {
        "schema_version": int(status.get("schema_version") or 0) if isinstance(status, dict) else 0,
        "status": "ready" if routes else _degraded_status(status),
        "auth_state": str(status.get("auth_state") or "unknown") if isinstance(status, dict) else "unknown",
        "route_ready": bool(routes),
        "route": routes[0] if routes else None,
        "auth_url_present": bool(status.get("auth_url_present")) if isinstance(status, dict) else False,
        "tailnet_ip_count": int(status.get("tailnet_ip_count") or 0) if isinstance(status, dict) else 0,
        "tailnet_node_id": _identity_string(status.get("tailnet_node_id")) if isinstance(status, dict) else "",
        "tags": _identity_list(status.get("tags")) if isinstance(status, dict) else [],
        "tailnet_ips": _identity_list(status.get("tailnet_ips")) if isinstance(status, dict) else [],
        "listener_running": bool(status.get("listener_running")) if isinstance(status, dict) else False,
        "upstream_reachable": bool(status.get("upstream_reachable")) if isinstance(status, dict) else False,
        "local_pairing_available": True,
        "next_action": _next_action(status, bool(routes)),
    }


def _degraded_status(status: dict[str, Any]) -> str:
    if not status:
        return "connectd_unavailable"
    if status.get("auth_state") != "authenticated":
        return "auth_pending" if status.get("auth_url_present") else "auth_unknown"
    if not status.get("listener_running"):
        return "listener_down"
    if not status.get("upstream_reachable"):
        return "upstream_unreachable"
    if not status.get("tailnet_ip"):
        return "no_tailnet_ip"
    return "route_missing"


def _next_action(status: dict[str, Any], route_ready: bool) -> dict[str, str]:
    if route_ready:
        return {
            "id": "pair_iphone",
            "label": "Pair iPhone",
            "message": "Scan the Mac pairing code in Pairling.",
        }
    if status and status.get("auth_url_present"):
        return {
            "id": "authenticate_pairling_connect",
            "label": "Authenticate Pairling Connect",
            "message": "Approve Pairling Connect in the browser, then recheck this Mac.",
        }
    return {
        "id": "use_local_pairing",
        "label": "Use local pairing",
        "message": "Pair locally now, or retry Pairling Connect after this Mac is ready.",
    }


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, (str, int, float))]


_IDENTITY_SECRET_RE = re.compile(r"(tskey|authkey|client_secret|nlprivate)", re.I)


def _identity_string(value: Any) -> str:
    raw = str(value or "").strip()
    if _IDENTITY_SECRET_RE.search(raw):
        return "[redacted]"
    return raw


def _identity_list(value: Any) -> list[str]:
    return [_identity_string(item) for item in _string_list(value)]


def _sanitized_base_url(value: Any, host: str, port: int) -> str | None:
    raw = str(value or f"http://{host}:{port}").strip()
    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception:
        return None
    if parsed.scheme != "http" or parsed.hostname != host or parsed.port != port:
        return None
    return urllib.parse.urlunparse(("http", f"{host}:{port}", "", "", "", ""))


def _sanitized_funnel_base_url(value: Any, host: str, port: int) -> str | None:
    # A funnel route is accepted only as https on a *.ts.net host at port 443.
    if not host.endswith(".ts.net") or port != PAIRLING_CONNECT_FUNNEL_PORT:
        return None
    raw = str(value or f"https://{host}").strip()
    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception:
        return None
    if parsed.scheme != "https" or parsed.hostname != host or parsed.port not in (None, PAIRLING_CONNECT_FUNNEL_PORT):
        return None
    return urllib.parse.urlunparse(("https", host, "", "", "", ""))


def _is_tailnet_host(host: str) -> bool:
    if host.endswith(".ts.net"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10")
