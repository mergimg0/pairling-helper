#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import socket
import sys
from pathlib import Path
from typing import Any


DEFAULT_CONTROL_SOCKET_PATH = Path.home() / ".claude" / "companion" / "control.sock"
DEFAULT_CONNECTD_CONTROL_SOCKET_PATH = Path.home() / ".claude" / "companion" / "connectd-control.sock"
DEFAULT_MAX_REQUEST_BYTES = 1024 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$")


class LocalControlClientError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(str(self._socket_path))
        except Exception:
            connection.close()
            raise
        self.sock = connection


def control_socket_path() -> Path:
    return Path(os.environ.get("PAIRLING_CONTROL_SOCKET", str(DEFAULT_CONTROL_SOCKET_PATH))).expanduser()


def connectd_control_socket_path() -> Path:
    return Path(
        os.environ.get(
            "PAIRLING_CONNECTD_CONTROL_SOCKET",
            str(DEFAULT_CONNECTD_CONTROL_SOCKET_PATH),
        )
    ).expanduser()


def request_json(
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    socket_path: str | os.PathLike[str] | None = None,
    timeout_seconds: float = 5.0,
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> tuple[int, dict[str, Any]]:
    method = str(method or "").strip().upper()
    if method not in {"GET", "POST"}:
        raise LocalControlClientError("control_method_invalid", "local control method must be GET or POST")
    path = str(path or "")
    if _PATH_RE.fullmatch(path) is None or "#" in path:
        raise LocalControlClientError("control_path_invalid", "local control path is invalid")
    try:
        timeout_seconds = float(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise LocalControlClientError("control_timeout_invalid", "local control timeout is invalid") from exc
    if not 0 < timeout_seconds <= 30:
        raise LocalControlClientError("control_timeout_invalid", "local control timeout must be between 0 and 30 seconds")
    try:
        request_limit = int(max_request_bytes)
        response_limit = int(max_response_bytes)
    except (TypeError, ValueError) as exc:
        raise LocalControlClientError("control_limit_invalid", "local control byte limit is invalid") from exc
    if not 1 <= request_limit <= DEFAULT_MAX_REQUEST_BYTES:
        raise LocalControlClientError("control_request_limit_invalid", "local control request limit is invalid")
    if not 1 <= response_limit <= DEFAULT_MAX_RESPONSE_BYTES:
        raise LocalControlClientError("control_response_limit_invalid", "local control response limit is invalid")

    try:
        target = Path(socket_path) if socket_path is not None else control_socket_path()
        target = target.expanduser()
    except (TypeError, ValueError) as exc:
        raise LocalControlClientError("control_socket_invalid", "local control socket path is invalid") from exc
    if not target.is_absolute():
        raise LocalControlClientError("control_socket_invalid", "local control socket path must be absolute")

    if payload is None:
        body = None
    else:
        if not isinstance(payload, dict):
            raise LocalControlClientError("control_payload_invalid", "local control payload must be a JSON object")
        try:
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise LocalControlClientError("control_payload_invalid", "local control payload is not JSON encodable") from exc
        if len(body) > request_limit:
            raise LocalControlClientError("control_request_too_large", "local control request body exceeds the configured limit")

    connection = _UnixHTTPConnection(target, timeout_seconds)
    try:
        headers = {"Accept": "application/json", "Connection": "close"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        declared_length = response.getheader("Content-Length")
        if declared_length is not None:
            try:
                declared_bytes = int(declared_length)
            except ValueError as exc:
                raise LocalControlClientError(
                    "control_response_invalid",
                    "local control response has an invalid Content-Length",
                ) from exc
            if declared_bytes < 0 or declared_bytes > response_limit:
                raise LocalControlClientError(
                    "control_response_too_large",
                    "local control response exceeds the configured limit",
                )
        raw = response.read(response_limit + 1)
        status = int(response.status)
    except LocalControlClientError:
        raise
    except (OSError, http.client.HTTPException, TimeoutError) as exc:
        raise LocalControlClientError(
            "control_transport_error",
            f"local control socket is unavailable: {type(exc).__name__}",
        ) from exc
    finally:
        connection.close()

    if len(raw) > response_limit:
        raise LocalControlClientError(
            "control_response_too_large",
            "local control response exceeds the configured limit",
        )
    try:
        decoded = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LocalControlClientError(
            "control_response_invalid",
            "local control response is not a JSON object",
        ) from exc
    if not isinstance(decoded, dict):
        raise LocalControlClientError(
            "control_response_invalid",
            "local control response is not a JSON object",
        )
    return status, decoded


def _error_payload(error: LocalControlClientError) -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "code": error.code,
            "message": error.message,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Call the private Pairling local-control socket.")
    parser.add_argument("method", choices=("GET", "POST"))
    parser.add_argument("path")
    parser.add_argument("--json-body")
    parser.add_argument("--socket", dest="socket_path")
    args = parser.parse_args(argv)

    payload = None
    if args.json_body is not None:
        try:
            payload = json.loads(args.json_body)
        except json.JSONDecodeError:
            error = LocalControlClientError("control_payload_invalid", "--json-body must be valid JSON")
            print(json.dumps(_error_payload(error), separators=(",", ":")))
            return 2
        if not isinstance(payload, dict):
            error = LocalControlClientError("control_payload_invalid", "--json-body must be a JSON object")
            print(json.dumps(_error_payload(error), separators=(",", ":")))
            return 2

    try:
        _status, response = request_json(
            args.path,
            method=args.method,
            payload=payload,
            socket_path=args.socket_path,
        )
    except LocalControlClientError as error:
        print(json.dumps(_error_payload(error), separators=(",", ":")))
        return 1
    print(json.dumps(response, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
