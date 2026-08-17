from __future__ import annotations

import atexit
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import selectors
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from .base import cli_version, managed_child_environment


SUPPORTED_VERSIONS = frozenset({"1.15.10"})
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_SSE_EVENT_BYTES = 1024 * 1024
MAX_PUBLIC_EVENTS = 256
MAX_DEDUPLICATION_KEYS = 2048

# Last matching OpenCode rule wins. All tools ask, and host paths outside the
# bound workspace are denied rather than delegated to a remote decision.
PAIRLING_PERMISSION_RULESET = (
    {"permission": "*", "pattern": "*", "action": "ask"},
    {"permission": "external_directory", "pattern": "*", "action": "deny"},
)

_FOUNDATIONAL_OPERATION_IDS = frozenset(
    {
        "global.health",
        "event.subscribe",
        "session.list",
        "session.get",
        "session.status",
    }
)
_EXPERIMENTAL_PERMISSION_OPERATION_IDS = frozenset(
    {"permission.list", "permission.reply"}
)
_QUESTION_OPERATION_IDS = frozenset(
    {"question.list", "question.reply", "question.reject"}
)
_PAIRLING_OPERATION_REQUIREMENTS = {
    "session.prompt.send": frozenset({"session.prompt_async"}),
    "session.turn.steer": frozenset({"session.prompt"}),
    "session.turn.interrupt": frozenset({"session.abort"}),
    "session.resume": frozenset({"session.get", "session.update"}),
    "session.fork": frozenset({"session.fork", "session.update"}),
    "session.model.set": frozenset(
        {"provider.list", "config.providers", "session.prompt_async"}
    ),
    "session.reasoning.set": frozenset({"provider.list", "session.prompt_async"}),
    "session.approval.decide": frozenset(
        {"permission.respond", "event.subscribe"}
    ),
    "session.question.answer": frozenset(
        {"question.list", "question.reply", "question.reject", "event.subscribe"}
    ),
    "provider.auth.read": frozenset({"provider.list"}),
    "provider.usage.read": frozenset(
        {"session.list", "session.messages", "session.status"}
    ),
    "provider.diagnostics.read": frozenset({"global.health"}),
}

_RESOURCE_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,256}\Z")
_LISTEN_RE = re.compile(
    r"opencode server listening on http://127\.0\.0\.1:(\d+)\s*\Z"
)
_SECRET_RE = re.compile(
    r"(?i)(?:\b(?:sk|ghp|github_pat|xoxb|xoxp|xoxa|xoxr|AKIA)"
    r"[-_A-Za-z0-9]{8,}\b|\bBearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+)"
)
_SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "headers",
        "input",
        "output",
        "password",
        "secret",
        "stderr",
        "stdout",
        "token",
    }
)


class OpenCodeError(RuntimeError):
    code = "opencode_error"


class OpenCodeEndpointDenied(OpenCodeError):
    code = "opencode_endpoint_denied"


class OpenCodeAuthenticationError(OpenCodeError):
    code = "opencode_authentication_failed"


class OpenCodeCapabilityError(OpenCodeError):
    code = "opencode_capability_unavailable"

class OpenCodeEventCursorError(OpenCodeError):
    code = "provider_event_cursor_invalid"



class OpenCodeTransportError(OpenCodeError):
    code = "opencode_transport_failed"


class OpenCodeLaunchError(OpenCodeError):
    code = "opencode_launch_failed"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise OpenCodeTransportError("OpenCode redirect was refused")


@dataclass(frozen=True)
class OpenCodeProtocolProfile:
    version: str
    operation_ids: frozenset[str]
    experimental_operation_ids: frozenset[str]
    launch_digest: str
    capability_digest: str

    @classmethod
    def from_openapi(
        cls,
        *,
        version: str,
        document: Mapping[str, Any],
        launch_digest: str,
    ) -> "OpenCodeProtocolProfile":
        if version not in SUPPORTED_VERSIONS:
            raise OpenCodeCapabilityError(
                f"unsupported exact OpenCode version: {version}"
            )
        paths = document.get("paths") if isinstance(document, Mapping) else None
        if not isinstance(paths, Mapping):
            raise OpenCodeCapabilityError(
                "OpenCode capability document has no paths"
            )
        operation_ids: set[str] = set()
        for route in paths.values():
            if not isinstance(route, Mapping):
                continue
            for method in ("get", "post", "patch", "delete"):
                operation = route.get(method)
                operation_id = (
                    operation.get("operationId")
                    if isinstance(operation, Mapping)
                    else None
                )
                if isinstance(operation_id, str) and operation_id:
                    operation_ids.add(operation_id)
        missing = _FOUNDATIONAL_OPERATION_IDS - operation_ids
        if missing:
            raise OpenCodeCapabilityError(
                "OpenCode capability document is missing required operations: "
                + ", ".join(sorted(missing))
            )
        experimental_operations: set[str] = set()
        for operation_group in (
            _EXPERIMENTAL_PERMISSION_OPERATION_IDS,
            _QUESTION_OPERATION_IDS,
        ):
            if operation_group <= operation_ids:
                experimental_operations.update(operation_group)
        experimental = frozenset(experimental_operations)
        material = json.dumps(
            {
                "version": version,
                "operations": sorted(operation_ids),
                "experimental": sorted(experimental),
                "launch_digest": launch_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return cls(
            version=version,
            operation_ids=frozenset(operation_ids),
            experimental_operation_ids=experimental,
            launch_digest=launch_digest,
            capability_digest=hashlib.sha256(material).hexdigest(),
        )

    def supports_pairling_operation(self, operation_id: str) -> bool:
        required = _PAIRLING_OPERATION_REQUIREMENTS.get(operation_id)
        return required is not None and required <= self.operation_ids


class OpenCodeHTTPTransport:
    """Closed HTTP/SSE client for one Pairling-owned child server."""

    _ENDPOINTS = (
        ("GET", re.compile(r"/global/health\Z")),
        ("GET", re.compile(r"/doc\Z")),
        ("GET", re.compile(r"/event\Z")),
        ("GET", re.compile(r"/provider\Z")),
        ("GET", re.compile(r"/config/providers\Z")),
        ("GET", re.compile(r"/permission\Z")),
        ("GET", re.compile(r"/question\Z")),
        (
            "POST",
            re.compile(r"/question/[A-Za-z0-9_-]{1,256}/reply\Z"),
        ),
        (
            "POST",
            re.compile(r"/question/[A-Za-z0-9_-]{1,256}/reject\Z"),
        ),
        ("GET", re.compile(r"/session\Z")),
        ("POST", re.compile(r"/session\Z")),
        ("GET", re.compile(r"/session/status\Z")),
        ("GET", re.compile(r"/session/[A-Za-z0-9_-]{1,256}\Z")),
        ("PATCH", re.compile(r"/session/[A-Za-z0-9_-]{1,256}\Z")),
        (
            "GET",
            re.compile(r"/session/[A-Za-z0-9_-]{1,256}/message\Z"),
        ),
        (
            "POST",
            re.compile(r"/session/[A-Za-z0-9_-]{1,256}/message\Z"),
        ),
        (
            "POST",
            re.compile(
                r"/session/[A-Za-z0-9_-]{1,256}/prompt_async\Z"
            ),
        ),
        (
            "POST",
            re.compile(r"/session/[A-Za-z0-9_-]{1,256}/abort\Z"),
        ),
        (
            "POST",
            re.compile(r"/session/[A-Za-z0-9_-]{1,256}/fork\Z"),
        ),
        (
            "GET",
            re.compile(r"/session/[A-Za-z0-9_-]{1,256}/diff\Z"),
        ),
        (
            "POST",
            re.compile(
                r"/session/[A-Za-z0-9_-]{1,256}/permissions/"
                r"[A-Za-z0-9_-]{1,256}\Z"
            ),
        ),
    )

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        timeout: float = 10.0,
    ):
        parsed = urllib.parse.urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise OpenCodeEndpointDenied(
                "OpenCode child URL must be plain loopback HTTP"
            )
        try:
            host = ipaddress.ip_address(parsed.hostname or "")
        except ValueError as exc:
            raise OpenCodeEndpointDenied(
                "OpenCode child URL must use a loopback IP literal"
            ) from exc
        if not host.is_loopback or parsed.port is None:
            raise OpenCodeEndpointDenied(
                "OpenCode child URL needs a loopback address and explicit port"
            )
        if parsed.path not in {"", "/"}:
            raise OpenCodeEndpointDenied(
                "OpenCode child URL must not contain a path"
            )
        if not username or not password or len(password) < 16:
            raise OpenCodeAuthenticationError(
                "OpenCode child credential is missing or too short"
            )
        host_literal = (
            f"[{parsed.hostname}]" if host.version == 6 else parsed.hostname
        )
        self.base_url = f"http://{host_literal}:{parsed.port}"
        self.timeout = float(timeout)
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._authorization = f"Basic {encoded}"
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
        )
        self.profile: OpenCodeProtocolProfile | None = None

    def close(self) -> None:
        self._authorization = ""
        self.profile = None


    def negotiate(
        self,
        *,
        expected_version: str,
        launch_digest: str,
    ) -> OpenCodeProtocolProfile:
        health = self._request_json("GET", "/global/health")
        if not isinstance(health, Mapping) or health.get("healthy") is not True:
            raise OpenCodeCapabilityError("OpenCode health canary failed")
        version = health.get("version")
        if version != expected_version or version not in SUPPORTED_VERSIONS:
            raise OpenCodeCapabilityError(
                "OpenCode runtime version differs from the pinned executable"
            )
        document = self._request_json("GET", "/doc")
        if self._status("GET", "/global/health", authenticated=False) != 401:
            raise OpenCodeAuthenticationError(
                "OpenCode child accepted an unauthenticated request"
            )
        profile = OpenCodeProtocolProfile.from_openapi(
            version=version,
            document=document,
            launch_digest=launch_digest,
        )
        self.profile = profile
        return profile

    def list_sessions(self) -> list[dict[str, Any]]:
        payload = self._request_json("GET", "/session?scope=project")
        return list(payload) if isinstance(payload, list) else []

    def get_session(self, session_id: str) -> dict[str, Any]:
        payload = self._request_json(
            "GET", f"/session/{resource_id(session_id)}"
        )
        if not isinstance(payload, dict):
            raise OpenCodeTransportError(
                "OpenCode session response is not an object"
            )
        return payload

    def create_session(
        self,
        *,
        title: str,
        model: tuple[str, str] | None = None,
        parent_id: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "permission": [dict(rule) for rule in PAIRLING_PERMISSION_RULESET]
        }
        if title:
            body["title"] = safe_text_input(title, 512, "title")
        if model is not None:
            body["model"] = {
                "providerID": choice_token(model[0]),
                "id": choice_token(model[1]),
            }
        if parent_id is not None:
            body["parentID"] = resource_id(parent_id)
        payload = self._request_json("POST", "/session", body)
        if not isinstance(payload, dict):
            raise OpenCodeTransportError(
                "OpenCode create-session response is not an object"
            )
        return payload

    def update_permissions(self, session_id: str) -> dict[str, Any]:
        payload = self._request_json(
            "PATCH",
            f"/session/{resource_id(session_id)}",
            {
                "permission": [
                    dict(rule) for rule in PAIRLING_PERMISSION_RULESET
                ]
            },
        )
        if not isinstance(payload, dict):
            raise OpenCodeTransportError(
                "OpenCode update-session response is not an object"
            )
        return payload

    def fork_session(
        self,
        session_id: str,
        message_id: str | None = None,
    ) -> dict[str, Any]:
        body = {"messageID": resource_id(message_id)} if message_id else {}
        payload = self._request_json(
            "POST", f"/session/{resource_id(session_id)}/fork", body
        )
        if not isinstance(payload, dict):
            raise OpenCodeTransportError(
                "OpenCode fork response is not an object"
            )
        return payload

    def statuses(self) -> dict[str, Any]:
        payload = self._request_json("GET", "/session/status")
        return dict(payload) if isinstance(payload, Mapping) else {}

    def messages(
        self,
        session_id: str,
        *,
        limit: int = 100,
        before: str | None = None,
    ) -> list[dict[str, Any]]:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 500
        ):
            raise OpenCodeEndpointDenied(
                "OpenCode message limit is outside the safe range"
            )
        query = {"limit": str(limit)}
        if before is not None:
            query["before"] = resource_id(before)
        payload = self._request_json(
            "GET",
            f"/session/{resource_id(session_id)}/message?"
            + urllib.parse.urlencode(query),
        )
        return list(payload) if isinstance(payload, list) else []

    def diff(
        self,
        session_id: str,
        message_id: str | None = None,
    ) -> list[dict[str, Any]]:
        path = f"/session/{resource_id(session_id)}/diff"
        if message_id is not None:
            path += "?" + urllib.parse.urlencode(
                {"messageID": resource_id(message_id)}
            )
        payload = self._request_json("GET", path)
        return list(payload) if isinstance(payload, list) else []

    def providers(self) -> dict[str, Any]:
        payload = self._request_json("GET", "/provider")
        return dict(payload) if isinstance(payload, Mapping) else {}

    def config_providers(self) -> dict[str, Any]:
        payload = self._request_json("GET", "/config/providers")
        return dict(payload) if isinstance(payload, Mapping) else {}

    def pending_permissions(self) -> list[dict[str, Any]]:
        if (
            self.profile is None
            or "permission.list"
            not in self.profile.experimental_operation_ids
        ):
            return []
        payload = self._request_json("GET", "/permission")
        return list(payload) if isinstance(payload, list) else []
    def pending_questions(self) -> list[dict[str, Any]]:
        if (
            self.profile is None
            or not _QUESTION_OPERATION_IDS <= self.profile.operation_ids
        ):
            return []
        payload = self._request_json("GET", "/question")
        return list(payload) if isinstance(payload, list) else []

    def respond_question(
        self,
        question_id: str,
        *,
        decision: str,
        answers: list[list[str]],
    ) -> bool:
        if decision == "cancel":
            payload = self._request_json(
                "POST",
                f"/question/{resource_id(question_id)}/reject",
                {},
            )
        elif decision == "accept":
            payload = self._request_json(
                "POST",
                f"/question/{resource_id(question_id)}/reply",
                {"answers": answers},
            )
        else:
            raise OpenCodeEndpointDenied(
                "OpenCode question decision is outside the documented enum"
            )
        return payload is True


    def prompt_async(
        self,
        session_id: str,
        *,
        text: str,
        message_id: str,
        model: tuple[str, str] | None,
        variant: str | None,
    ) -> None:
        self._request_json(
            "POST",
            f"/session/{resource_id(session_id)}/prompt_async",
            message_body(
                text=text,
                message_id=message_id,
                model=model,
                variant=variant,
            ),
        )

    def queue_message(
        self,
        session_id: str,
        *,
        text: str,
        message_id: str,
        model: tuple[str, str] | None,
        variant: str | None,
    ) -> dict[str, Any]:
        body = message_body(
            text=text,
            message_id=message_id,
            model=model,
            variant=variant,
        )
        body["noReply"] = True
        payload = self._request_json(
            "POST", f"/session/{resource_id(session_id)}/message", body
        )
        return dict(payload) if isinstance(payload, Mapping) else {}

    def abort(self, session_id: str) -> bool:
        payload = self._request_json(
            "POST", f"/session/{resource_id(session_id)}/abort", {}
        )
        return payload is True

    def respond_permission(
        self,
        session_id: str,
        permission_id: str,
        decision: str,
    ) -> bool:
        if decision not in {"once", "always", "reject"}:
            raise OpenCodeEndpointDenied(
                "OpenCode permission decision is outside the documented enum"
            )
        payload = self._request_json(
            "POST",
            f"/session/{resource_id(session_id)}/permissions/"
            f"{resource_id(permission_id)}",
            {"response": decision},
        )
        return payload is True

    def _open_event_response(self) -> Any:
        request = self._request(
            "GET", "/event", accept="text/event-stream"
        )
        try:
            response = self._opener.open(
                request, timeout=max(self.timeout, 30.0)
            )
        except urllib.error.HTTPError as exc:
            try:
                raise OpenCodeTransportError(
                    "OpenCode SSE connection failed"
                ) from exc
            finally:
                exc.close()
        except (OSError, urllib.error.URLError) as exc:
            raise OpenCodeTransportError(
                "OpenCode SSE connection failed"
            ) from exc
        try:
            if (
                response.status != 200
                or response.headers.get_content_type()
                != "text/event-stream"
            ):
                raise OpenCodeTransportError(
                    "OpenCode SSE content-type canary failed"
                )
            return response
        except Exception:
            response.close()
            raise

    def _request_json(self, method: str, path: str, body: Any = None) -> Any:
        request = self._request(
            method, path, body=body, accept="application/json"
        )
        try:
            response = self._opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            try:
                detail = safe_http_error(exc)
                raise OpenCodeTransportError(
                    f"OpenCode request failed with HTTP {exc.code}{detail}"
                ) from exc
            finally:
                exc.close()
        except (OSError, urllib.error.URLError) as exc:
            raise OpenCodeTransportError("OpenCode request failed") from exc
        try:
            if response.status == 204:
                return None
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise OpenCodeTransportError(
                    "OpenCode response exceeded the safety limit"
                )
            if not raw:
                return None
            try:
                return json.loads(raw)
            except (TypeError, ValueError) as exc:
                raise OpenCodeTransportError(
                    "OpenCode returned invalid JSON"
                ) from exc
        finally:
            response.close()

    def _status(
        self,
        method: str,
        path: str,
        *,
        authenticated: bool,
    ) -> int:
        request = self._request(
            method, path, authenticated=authenticated
        )
        try:
            response = self._opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            try:
                return int(exc.code)
            finally:
                exc.close()
        except (OSError, urllib.error.URLError) as exc:
            raise OpenCodeTransportError(
                "OpenCode authentication canary failed"
            ) from exc
        try:
            return int(response.status)
        finally:
            response.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        accept: str | None = None,
        authenticated: bool = True,
    ) -> urllib.request.Request:
        method = str(method).upper()
        split = urllib.parse.urlsplit(path)
        if (
            split.scheme
            or split.netloc
            or split.fragment
            or not split.path.startswith("/")
        ):
            raise OpenCodeEndpointDenied(
                "OpenCode endpoint must be a relative absolute path"
            )
        if not any(
            allowed_method == method and pattern.fullmatch(split.path)
            for allowed_method, pattern in self._ENDPOINTS
        ):
            raise OpenCodeEndpointDenied(
                "OpenCode endpoint is outside the reviewed table"
            )
        self._validate_query(split.path, split.query)
        headers = {"Accept": accept or "application/json"}
        if authenticated:
            headers["Authorization"] = self._authorization
        data = None
        if body is not None:
            try:
                data = json.dumps(
                    body, separators=(",", ":")
                ).encode()
            except (TypeError, ValueError) as exc:
                raise OpenCodeEndpointDenied(
                    "OpenCode request body is not JSON"
                ) from exc
            headers["Content-Type"] = "application/json"
        return urllib.request.Request(
            self.base_url
            + split.path
            + (f"?{split.query}" if split.query else ""),
            data=data,
            headers=headers,
            method=method,
        )

    @staticmethod
    def _validate_query(path: str, query: str) -> None:
        if not query:
            return
        if path == "/session":
            allowed = frozenset({"limit", "scope"})
        elif path.endswith("/message"):
            allowed = frozenset({"before", "limit"})
        elif path.endswith("/diff"):
            allowed = frozenset({"messageID"})
        else:
            raise OpenCodeEndpointDenied(
                "OpenCode endpoint does not allow query parameters"
            )
        try:
            pairs = urllib.parse.parse_qsl(
                query,
                keep_blank_values=True,
                strict_parsing=True,
            )
        except ValueError as exc:
            raise OpenCodeEndpointDenied(
                "OpenCode query is malformed"
            ) from exc
        if not pairs or any(key not in allowed for key, _ in pairs):
            raise OpenCodeEndpointDenied(
                "OpenCode query contains an unreviewed parameter"
            )
        if any(
            key in {"directory", "workspace", "path"}
            for key, _ in pairs
        ):
            raise OpenCodeEndpointDenied(
                "OpenCode workspace routing is fixed by the owned child"
            )


class OpenCodeOwnedServer:
    """Owns a native child. There is deliberately no attach constructor."""

    def __init__(
        self,
        *,
        process: subprocess.Popen,
        transport: OpenCodeHTTPTransport,
        profile: OpenCodeProtocolProfile,
        cwd: Path,
        launch_digest: str,
        executable: Path,
        executable_digest: str,
        config_digest: str,
    ):
        self.process = process
        self.transport = transport
        self.profile = profile
        self.cwd = cwd
        self.launch_digest = launch_digest
        self.executable = executable
        self.executable_digest = executable_digest
        self.config_digest = config_digest
        self._closed = False
        self._close_lock = threading.Lock()
        atexit.register(self.close)

    @classmethod
    def start(
        cls,
        executable: Path,
        *,
        cwd: Path,
        expected_version: str,
        launch_timeout: float = 12.0,
    ) -> "OpenCodeOwnedServer":
        resolved_executable = executable.expanduser().resolve(strict=True)
        resolved_cwd = cwd.expanduser().resolve(strict=True)
        if (
            not resolved_executable.is_file()
            or not os.access(resolved_executable, os.X_OK)
        ):
            raise OpenCodeLaunchError(
                "OpenCode executable is not available"
            )
        if not resolved_cwd.is_dir():
            raise OpenCodeLaunchError(
                "OpenCode workspace is not a directory"
            )
        version = cli_version(resolved_executable, timeout=3)
        if version != expected_version or version not in SUPPORTED_VERSIONS:
            raise OpenCodeCapabilityError(
                "OpenCode executable version is not pinned and supported"
            )
        args = (
            str(resolved_executable),
            "serve",
            "--pure",
            "--hostname",
            "127.0.0.1",
            "--port",
            "0",
        )
        stat = resolved_executable.stat()
        executable_digest = file_sha256(resolved_executable)
        config_digest = configuration_digest(resolved_cwd)
        launch_material = {
            "executable": str(resolved_executable),
            "device": stat.st_dev,
            "inode": stat.st_ino,
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "content_sha256": executable_digest,
            "version": version,
            "cwd": str(resolved_cwd),
            "args": list(args[1:]),
            "config_digest": config_digest,
            "cleared_environment": [
                "OPENCODE_CONFIG",
                "OPENCODE_CONFIG_CONTENT",
                "OPENCODE_CONFIG_DIR",
                "OPENCODE_AUTO",
                "OPENCODE_YOLO",
                "OPENCODE_DANGEROUSLY_SKIP_PERMISSIONS",
                "OPENCODE_EXPERIMENTAL_TUI",
            ],
        }
        launch_digest = hashlib.sha256(
            json.dumps(
                launch_material,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        username = "pairling"
        password = secrets.token_urlsafe(48)
        environment = managed_child_environment(
            provider_settings={"OPENCODE_SERVER_USERNAME": username},
            private_runtime_settings={"OPENCODE_SERVER_PASSWORD": password},
        )
        try:
            process = subprocess.Popen(
                args,
                cwd=str(resolved_cwd),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as exc:
            raise OpenCodeLaunchError(
                "OpenCode child could not be started"
            ) from exc
        transport: OpenCodeHTTPTransport | None = None
        try:
            port = read_owned_server_port(process, launch_timeout)
            transport = OpenCodeHTTPTransport(
                f"http://127.0.0.1:{port}", username, password
            )
            profile = transport.negotiate(
                expected_version=expected_version,
                launch_digest=launch_digest,
            )
            if process.poll() is not None:
                raise OpenCodeLaunchError(
                    "OpenCode child exited during capability canaries"
                )
            return cls(
                process=process,
                transport=transport,
                profile=profile,
                cwd=resolved_cwd,
                launch_digest=launch_digest,
                executable=resolved_executable,
                executable_digest=executable_digest,
                config_digest=config_digest,
            )
        except Exception:
            if transport is not None:
                transport.close()
            terminate_owned_process(process)
            raise

    def verify_launch_inputs(self) -> bool:
        try:
            return (
                self.process.poll() is None
                and self.executable.resolve(strict=True)
                == self.executable
                and file_sha256(self.executable)
                == self.executable_digest
                and self.verify_config_inputs()
            )
        except (OSError, OpenCodeError):
            return False

    def verify_config_inputs(self) -> bool:
        try:
            return (
                configuration_digest(self.cwd)
                == self.config_digest
            )
        except (OSError, OpenCodeError):
            return False


    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
            atexit.unregister(self.close)
            try:
                self.transport.close()
            finally:
                terminate_owned_process(self.process)


class OpenCodeEventState:
    def __init__(self, cwd: Path):
        self.cwd = cwd.resolve(strict=False)
        self._lock = threading.RLock()
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._events: deque[tuple[int, dict[str, Any]]] = deque(
            maxlen=MAX_PUBLIC_EVENTS
        )
        self._dropped_event_cursor = 0
        self._pending_permissions: dict[str, dict[str, Any]] = {}
        self._pending_questions: dict[str, dict[str, Any]] = {}
        self._statuses: dict[str, dict[str, Any]] = {}
        self._cursor = 0

    @property
    def cursor(self) -> int:
        with self._lock:
            return self._cursor

    @property
    def pending_permissions(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {
                key: dict(value)
                for key, value in self._pending_permissions.items()
            }
    @property
    def pending_questions(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {
                key: dict(value)
                for key, value in self._pending_questions.items()
            }


    def public_events(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for _, item in self._events]

    def public_event_records(
        self,
        *,
        after_cursor: int,
    ) -> list[tuple[int, dict[str, Any]]]:
        with self._lock:
            if (
                isinstance(after_cursor, bool)
                or not isinstance(after_cursor, int)
                or after_cursor < 0
                or after_cursor > self._cursor
                or after_cursor < self._dropped_event_cursor
            ):
                raise OpenCodeEventCursorError(
                    "OpenCode provider event cursor is invalid"
                )
            return [
                (cursor, dict(item))
                for cursor, item in self._events
                if cursor > after_cursor
            ]

    def _append_public_event(self, event: dict[str, Any]) -> None:
        if len(self._events) == MAX_PUBLIC_EVENTS:
            self._dropped_event_cursor = max(
                self._dropped_event_cursor,
                self._events[0][0],
            )
        self._cursor += 1
        self._events.append((self._cursor, event))

    def status_for(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            status = self._statuses.get(session_id)
            return dict(status) if status is not None else None

    def ingest(self, event: Mapping[str, Any]) -> bool:
        safe = sanitize_event(event, self.cwd)
        if safe is None:
            return False
        digest = fingerprint(safe)
        with self._lock:
            if digest in self._seen:
                return False
            self._seen[digest] = None
            self._seen.move_to_end(digest)
            while len(self._seen) > MAX_DEDUPLICATION_KEYS:
                self._seen.popitem(last=False)
            event_type = safe.get("type")
            properties = safe.get("properties")
            if isinstance(properties, Mapping):
                if event_type == "permission.asked":
                    request_id = properties.get("id")
                    if isinstance(request_id, str):
                        self._pending_permissions[request_id] = dict(
                            properties
                        )
                elif event_type == "permission.replied":
                    request_id = (
                        properties.get("requestID")
                        or properties.get("id")
                    )
                    if isinstance(request_id, str):
                        self._pending_permissions.pop(request_id, None)
                elif event_type == "question.asked":
                    request_id = properties.get("id")
                    if isinstance(request_id, str):
                        self._pending_questions[request_id] = dict(properties)
                elif event_type in {"question.replied", "question.rejected"}:
                    request_id = properties.get("requestID")
                    if isinstance(request_id, str):
                        self._pending_questions.pop(request_id, None)
                elif event_type == "session.status":
                    session_id = properties.get("sessionID")
                    status = properties.get("status")
                    if (
                        isinstance(session_id, str)
                        and isinstance(status, Mapping)
                    ):
                        self._statuses[session_id] = dict(status)
            self._append_public_event(safe)
            return True

    def reconcile(
        self,
        *,
        permissions: Iterable[Mapping[str, Any]],
        statuses: Mapping[str, Any],
        questions: Iterable[Mapping[str, Any]] = (),
    ) -> bool:
        pending: dict[str, dict[str, Any]] = {}
        for raw in permissions:
            safe = sanitize_permission(raw, self.cwd)
            request_id = safe.get("id")
            if isinstance(request_id, str):
                pending[request_id] = safe
        pending_questions: dict[str, dict[str, Any]] = {}
        for raw in questions:
            safe = sanitize_question_request(raw, self.cwd)
            request_id = safe.get("id")
            if isinstance(request_id, str):
                pending_questions[request_id] = safe
        safe_statuses = {
            str(session_id): sanitize_status(status)
            for session_id, status in statuses.items()
            if isinstance(session_id, str)
            and isinstance(status, Mapping)
        }
        synthetic = [
            {
                "type": "permission.asked",
                "properties": permission,
            }
            for permission in pending.values()
        ]
        synthetic.extend(
            {
                "type": "question.asked",
                "properties": question,
            }
            for question in pending_questions.values()
        )
        synthetic.extend(
            {
                "type": "session.status",
                "properties": {
                    "sessionID": session_id,
                    "status": status,
                },
            }
            for session_id, status in safe_statuses.items()
        )
        with self._lock:
            before = fingerprint(
                {
                    "permissions": self._pending_permissions,
                    "questions": self._pending_questions,
                    "statuses": self._statuses,
                }
            )
            after = fingerprint(
                {
                    "permissions": pending,
                    "questions": pending_questions,
                    "statuses": safe_statuses,
                }
            )
            if before == after:
                return False
            self._pending_permissions = pending
            self._statuses = safe_statuses
            self._pending_questions = pending_questions
            appended = 0
            for safe in synthetic:
                digest = fingerprint(safe)
                if digest in self._seen:
                    continue
                self._seen[digest] = None
                self._seen.move_to_end(digest)
                self._append_public_event(safe)
                appended += 1
            while len(self._seen) > MAX_DEDUPLICATION_KEYS:
                self._seen.popitem(last=False)
            if appended == 0:
                self._cursor += 1
            return True

    def resolve_permission(self, permission_id: str) -> bool:
        with self._lock:
            if permission_id not in self._pending_permissions:
                return False
            self._pending_permissions.pop(permission_id, None)
            self._cursor += 1
            return True

    def resolve_question(self, question_id: str) -> bool:
        with self._lock:
            if question_id not in self._pending_questions:
                return False
            self._pending_questions.pop(question_id, None)
            self._cursor += 1
            return True


class OpenCodeEventStream:
    def __init__(
        self,
        transport: OpenCodeHTTPTransport,
        state: OpenCodeEventState,
    ):
        self.transport = transport
        self.state = state
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._response_lock = threading.Lock()
        self._response: Any | None = None

    def consume_lines(self, lines: Iterable[str]) -> int:
        accepted = 0
        data_lines: list[str] = []
        size = 0
        for line in lines:
            if not isinstance(line, str):
                line = str(line)
            if line in {"\n", "\r\n", ""}:
                if data_lines:
                    raw = "\n".join(data_lines)
                    data_lines = []
                    size = 0
                    try:
                        payload = json.loads(raw)
                    except (TypeError, ValueError):
                        continue
                    if (
                        isinstance(payload, Mapping)
                        and self.state.ingest(payload)
                    ):
                        accepted += 1
                continue
            if line.startswith("data:"):
                value = line[5:].lstrip(" ").rstrip("\r\n")
                size += len(value.encode("utf-8", errors="replace"))
                if size > MAX_SSE_EVENT_BYTES:
                    data_lines = []
                    size = 0
                    continue
                data_lines.append(value)
        return accepted

    def reconnect(self) -> bool:
        return self.state.reconcile(
            permissions=self.transport.pending_permissions(),
            statuses=self.transport.statuses(),
            questions=self.transport.pending_questions(),
        )

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run,
            name="pairling-opencode-events",
            daemon=True,
        )
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        response = self._take_response()
        if response is not None:
            self._close_response(response)
        if (
            self._thread is not None
            and self._thread is not threading.current_thread()
        ):
            self._thread.join(timeout=1.0)

    def _run(self) -> None:
        delay = 0.1
        while not self._stop.is_set():
            try:
                response = self.transport._open_event_response()
            except OpenCodeError:
                response = None
            if response is not None:
                if not self._adopt_response(response):
                    self._close_response(response)
                    return
                try:
                    self.consume_lines(self._iter_response_lines(response))
                except OpenCodeError:
                    pass
                finally:
                    self._release_response(response)
            if self._stop.is_set():
                return
            try:
                self.reconnect()
            except OpenCodeError:
                pass
            self._stop.wait(delay)
            delay = min(delay * 2, 2.0)

    def _adopt_response(self, response: Any) -> bool:
        with self._response_lock:
            if self._stop.is_set():
                return False
            self._response = response
            return True

    def _take_response(self) -> Any | None:
        with self._response_lock:
            response = self._response
            self._response = None
            return response

    def _release_response(self, response: Any) -> None:
        with self._response_lock:
            if self._response is not response:
                return
            self._response = None
        self._close_response(response)

    def _iter_response_lines(self, response: Any) -> Iterator[str]:
        while not self._stop.is_set():
            try:
                raw = response.readline(MAX_SSE_EVENT_BYTES + 1)
            except (OSError, ValueError) as exc:
                if self._stop.is_set():
                    return
                raise OpenCodeTransportError(
                    "OpenCode SSE read failed"
                ) from exc
            if not raw:
                return
            if len(raw) > MAX_SSE_EVENT_BYTES:
                raise OpenCodeTransportError(
                    "OpenCode SSE line exceeded the safety limit"
                )
            yield raw.decode("utf-8", errors="replace")

    @staticmethod
    def _close_response(response: Any) -> None:
        try:
            response.close()
        except OSError:
            pass


def sanitize_message_history(
    messages: Iterable[Mapping[str, Any]],
    cwd: Path,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for message in messages:
        if not isinstance(message, Mapping):
            continue
        info = message.get("info")
        safe_info: dict[str, Any] = {}
        if isinstance(info, Mapping):
            for key in ("id", "sessionID", "role"):
                value = info.get(key)
                if isinstance(value, str):
                    safe_info[key] = redact_text(value, cwd)
            if isinstance(info.get("cost"), (int, float)) and not isinstance(
                info.get("cost"), bool
            ):
                safe_info["cost"] = float(info["cost"])
            if isinstance(info.get("tokens"), Mapping):
                safe_info["tokens"] = sanitize_tokens(info["tokens"])
        parts = message.get("parts")
        safe_parts: list[dict[str, Any]] = []
        if isinstance(parts, list):
            for part in parts:
                if isinstance(part, Mapping):
                    safe = sanitize_part(part, cwd)
                    if safe is not None:
                        safe_parts.append(safe)
        result.append({"info": safe_info, "parts": safe_parts})
    return result


def sanitize_question_request(
    value: Mapping[str, Any],
    cwd: Path,
) -> dict[str, Any]:
    request_id = value.get("id")
    session_id = value.get("sessionID")
    raw_questions = value.get("questions")
    if (
        not isinstance(request_id, str)
        or _RESOURCE_ID_RE.fullmatch(request_id) is None
        or not isinstance(session_id, str)
        or _RESOURCE_ID_RE.fullmatch(session_id) is None
        or not isinstance(raw_questions, list)
        or not 1 <= len(raw_questions) <= 12
    ):
        return {}
    questions: list[dict[str, Any]] = []
    for raw in raw_questions:
        if not isinstance(raw, Mapping):
            return {}
        question = raw.get("question")
        header = raw.get("header")
        raw_options = raw.get("options")
        multiple = raw.get("multiple", False)
        custom = raw.get("custom", False)
        if (
            not isinstance(question, str)
            or not question
            or len(question) > 2_000
            or "\x00" in question
            or not isinstance(header, str)
            or len(header) > 160
            or "\x00" in header
            or not isinstance(raw_options, list)
            or len(raw_options) > 20
            or type(multiple) is not bool
            or type(custom) is not bool
        ):
            return {}
        options: list[str] = []
        for raw_option in raw_options:
            label = (
                raw_option.get("label")
                if isinstance(raw_option, Mapping)
                else None
            )
            if (
                not isinstance(label, str)
                or not label
                or len(label) > 512
                or "\x00" in label
                or label in options
                or redact_text(label, cwd) != label
            ):
                return {}
            options.append(label)
        questions.append({
            "question": redact_text(question, cwd),
            "header": redact_text(header, cwd),
            "options": options,
            "multiple": multiple,
            "custom": custom or not options,
        })
    result: dict[str, Any] = {
        "id": request_id,
        "sessionID": session_id,
        "questions": questions,
    }
    raw_tool = value.get("tool")
    if isinstance(raw_tool, Mapping):
        tool = {
            key: field
            for key in ("messageID", "callID")
            if isinstance((field := raw_tool.get(key)), str)
            and _RESOURCE_ID_RE.fullmatch(field) is not None
        }
        if tool:
            result["tool"] = tool
    return result


def sanitize_diff(
    diff: Iterable[Mapping[str, Any]],
    cwd: Path,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in diff:
        if not isinstance(item, Mapping):
            continue
        safe: dict[str, Any] = {}
        path = item.get("file") or item.get("path")
        if isinstance(path, str):
            safe["file"] = redact_path(path, cwd)
        for key in ("additions", "deletions"):
            value = item.get(key)
            if (
                isinstance(value, int)
                and not isinstance(value, bool)
                and value >= 0
            ):
                safe[key] = value
        if safe:
            result.append(safe)
    return result


def sanitize_event(
    event: Mapping[str, Any],
    cwd: Path,
) -> dict[str, Any] | None:
    event_type = event.get("type")
    properties = event.get("properties")
    if (
        not isinstance(event_type, str)
        or not event_type
        or not isinstance(properties, Mapping)
    ):
        return None
    if event_type == "permission.asked":
        safe_properties = sanitize_permission(properties, cwd)
    elif event_type == "permission.replied":
        safe_properties = {
            key: value
            for key in ("id", "requestID", "sessionID", "reply")
            if isinstance((value := properties.get(key)), str)
        }
    elif event_type == "question.asked":
        safe_properties = sanitize_question_request(properties, cwd)
        if not safe_properties:
            return None
    elif event_type in {"question.replied", "question.rejected"}:
        safe_properties = {
            key: value
            for key in ("requestID", "sessionID")
            if isinstance((value := properties.get(key)), str)
            and _RESOURCE_ID_RE.fullmatch(value) is not None
        }
        if set(safe_properties) != {"requestID", "sessionID"}:
            return None
    elif event_type == "session.status":
        session_id = properties.get("sessionID")
        status = properties.get("status")
        if not isinstance(session_id, str) or not isinstance(status, Mapping):
            return None
        safe_properties = {
            "sessionID": session_id,
            "status": sanitize_status(status),
        }
    elif event_type == "message.part.updated":
        part = properties.get("part")
        if not isinstance(part, Mapping):
            return None
        safe_part = sanitize_part(part, cwd)
        if safe_part is None:
            return None
        safe_properties = {"part": safe_part}
        part_session_id = (
            part.get("sessionID")
            or properties.get("sessionID")
        )
        if isinstance(part_session_id, str):
            safe_properties["sessionID"] = redact_text(
                part_session_id,
                cwd,
            )
        delta = properties.get("delta")
        if isinstance(delta, str) and safe_part.get("type") == "text":
            safe_properties["delta"] = redact_text(delta, cwd)
    elif event_type == "message.updated":
        info = properties.get("info")
        if not isinstance(info, Mapping):
            return None
        safe_properties = sanitize_message_history(
            [{"info": info, "parts": []}], cwd
        )[0]["info"]
    else:
        safe_properties = sanitize_unknown_properties(properties, cwd)
    return {"type": event_type, "properties": safe_properties}


def sanitize_part(
    part: Mapping[str, Any],
    cwd: Path,
) -> dict[str, Any] | None:
    part_type = part.get("type")
    if not isinstance(part_type, str):
        return None
    safe: dict[str, Any] = {"type": part_type}
    if isinstance(part.get("id"), str):
        safe["id"] = part["id"]
    if part_type == "text" and isinstance(part.get("text"), str):
        safe["text"] = redact_text(part["text"], cwd)
    elif part_type == "tool":
        if isinstance(part.get("tool"), str):
            safe["tool"] = safe_label(part["tool"])
        state = part.get("state")
        if isinstance(state, Mapping) and isinstance(
            state.get("status"), str
        ):
            safe["status"] = state["status"]
    elif part_type == "file":
        if isinstance(part.get("mime"), str):
            safe["mime"] = safe_label(part["mime"])
        if isinstance(part.get("filename"), str):
            safe["filename"] = redact_path(part["filename"], cwd)
    elif part_type in {"patch", "snapshot"}:
        files = part.get("files")
        if isinstance(files, list):
            safe["files"] = [
                redact_path(value, cwd)
                for value in files
                if isinstance(value, str)
            ][:200]
    elif part_type in {"step-start", "step-finish"}:
        if isinstance(part.get("cost"), (int, float)) and not isinstance(
            part.get("cost"), bool
        ):
            safe["cost"] = float(part["cost"])
        if isinstance(part.get("tokens"), Mapping):
            safe["tokens"] = sanitize_tokens(part["tokens"])
    elif part_type == "reasoning":
        safe["redacted"] = True
    return safe


def sanitize_permission(
    raw: Mapping[str, Any],
    cwd: Path,
) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key in ("id", "sessionID", "permission"):
        value = raw.get(key)
        if isinstance(value, str):
            safe[key] = redact_text(value, cwd)
    for key in ("patterns", "always"):
        value = raw.get(key)
        if isinstance(value, list):
            safe[key] = [
                redact_text(item, cwd)
                for item in value
                if isinstance(item, str)
            ][:100]
    tool = raw.get("tool")
    if isinstance(tool, Mapping):
        safe["tool"] = {
            key: value
            for key in ("messageID", "callID")
            if isinstance((value := tool.get(key)), str)
        }
    metadata = raw.get("metadata")
    if isinstance(metadata, Mapping) and isinstance(
        metadata.get("description"), str
    ):
        safe["metadata"] = {
            "description": redact_text(metadata["description"], cwd)
        }
    return safe


def sanitize_unknown_properties(
    properties: Mapping[str, Any],
    cwd: Path,
) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    allowed = {
        "id",
        "sessionID",
        "messageID",
        "partID",
        "requestID",
        "type",
        "status",
        "name",
    }
    for key, value in properties.items():
        lowered = str(key).lower()
        if lowered in _SENSITIVE_KEYS or any(
            token in lowered
            for token in ("token", "secret", "password", "credential")
        ):
            continue
        if key not in allowed:
            continue
        if isinstance(value, str):
            safe[str(key)] = redact_text(value, cwd)
        elif isinstance(value, Mapping) and key == "status":
            safe[str(key)] = sanitize_status(value)
    return safe


def sanitize_status(status: Mapping[str, Any]) -> dict[str, Any]:
    status_type = status.get("type")
    if status_type not in {"idle", "busy", "retry"}:
        return {"type": "unknown"}
    safe: dict[str, Any] = {"type": status_type}
    if status_type == "retry":
        attempt = status.get("attempt")
        next_at = status.get("next")
        if (
            isinstance(attempt, int)
            and not isinstance(attempt, bool)
            and attempt >= 0
        ):
            safe["attempt"] = attempt
        if isinstance(next_at, (int, float)) and not isinstance(
            next_at, bool
        ):
            safe["next"] = float(next_at)
    return safe


def sanitize_tokens(tokens: Mapping[str, Any]) -> dict[str, Any]:
    safe = {
        key: safe_int(tokens.get(key))
        for key in ("input", "output", "reasoning")
    }
    cache = tokens.get("cache")
    if isinstance(cache, Mapping):
        safe["cache"] = {
            "read": safe_int(cache.get("read")),
            "write": safe_int(cache.get("write")),
        }
    return safe


def sanitize_session(
    session: Mapping[str, Any],
    cwd: Path,
) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key in ("id", "parentID", "projectID", "title"):
        value = session.get(key)
        if isinstance(value, str):
            safe[key] = redact_text(value, cwd)
    if isinstance(session.get("directory"), str):
        safe["directory"] = redact_path(session["directory"], cwd)
    time_payload = session.get("time")
    if isinstance(time_payload, Mapping):
        safe["time"] = {
            key: float(value)
            for key in ("created", "updated", "archived")
            if isinstance((value := time_payload.get(key)), (int, float))
            and not isinstance(value, bool)
        }
    model = model_from_session(session)
    if model is not None:
        safe["model"] = {
            "providerID": model[0],
            "modelID": model[1],
        }
    return safe


def message_body(
    *,
    text: str,
    message_id: str,
    model: tuple[str, str] | None,
    variant: str | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "messageID": resource_id(message_id),
        "parts": [
            {
                "type": "text",
                "text": safe_text_input(text, 200_000, "message"),
            }
        ],
    }
    if model is not None:
        body["model"] = {
            "providerID": choice_token(model[0]),
            "modelID": choice_token(model[1]),
        }
    if variant is not None:
        body["variant"] = choice_token(variant)
    return body


def read_owned_server_port(
    process: subprocess.Popen,
    timeout: float,
) -> int:
    if process.stdout is None:
        raise OpenCodeLaunchError(
            "OpenCode child has no startup output pipe"
        )
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + max(1.0, timeout)
    lines = 0
    try:
        while time.monotonic() < deadline and lines < 64:
            if process.poll() is not None:
                raise OpenCodeLaunchError(
                    "OpenCode child exited before listening"
                )
            events = selector.select(
                timeout=min(
                    0.2,
                    max(0.0, deadline - time.monotonic()),
                )
            )
            if not events:
                continue
            line = process.stdout.readline()
            if not line:
                continue
            lines += 1
            match = _LISTEN_RE.search(line.strip())
            if match:
                port = int(match.group(1))
                if 1 <= port <= 65535:
                    return port
        raise OpenCodeLaunchError(
            "OpenCode child did not publish its random loopback port"
        )
    finally:
        selector.close()


def terminate_owned_process(process: subprocess.Popen) -> None:
    try:
        if process.poll() is None:
            try:
                if os.getpgid(process.pid) == process.pid:
                    os.killpg(process.pid, signal.SIGTERM)
                else:
                    process.terminate()
            except OSError:
                try:
                    process.terminate()
                except OSError:
                    pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    if (
                        process.poll() is None
                        and os.getpgid(process.pid) == process.pid
                    ):
                        os.killpg(process.pid, signal.SIGKILL)
                    elif process.poll() is None:
                        process.kill()
                except OSError:
                    try:
                        process.kill()
                    except OSError:
                        pass
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
        else:
            try:
                process.wait(timeout=0)
            except subprocess.TimeoutExpired:
                pass
    finally:
        closed: set[int] = set()
        for stream in (
            process.stdin,
            process.stdout,
            process.stderr,
        ):
            if stream is None or id(stream) in closed:
                continue
            closed.add(id(stream))
            try:
                stream.close()
            except (OSError, ValueError):
                pass


def resource_id(value: str) -> str:
    if not isinstance(value, str) or _RESOURCE_ID_RE.fullmatch(value) is None:
        raise OpenCodeEndpointDenied("OpenCode resource id is invalid")
    return value


def choice_token(value: str) -> str:
    if (
        not isinstance(value, str)
        or not safe_choice(value)
        or len(value) > 256
    ):
        raise OpenCodeEndpointDenied("OpenCode choice value is invalid")
    return value


def safe_choice(value: str) -> bool:
    return (
        bool(value)
        and "\x00" not in value
        and not any(ord(char) < 32 for char in value)
    )


def safe_text_input(value: str, maximum: int, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        raise OpenCodeEndpointDenied(f"OpenCode {name} is invalid")
    return value


def safe_label(value: str) -> str:
    text = " ".join(str(value).split())
    return (text[:157] + "...") if len(text) > 160 else (text or "OpenCode")


def safe_http_error(error: urllib.error.HTTPError) -> str:
    try:
        raw = error.read(4097)
    except OSError:
        return ""
    if len(raw) > 4096:
        return ""
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        return ""
    if isinstance(payload, Mapping):
        message = payload.get("message") or payload.get("error")
        if isinstance(message, str):
            return ": " + _SECRET_RE.sub("[redacted]", message)[:160]
    return ""


def redact_text(value: str, cwd: Path) -> str:
    text = _SECRET_RE.sub("[redacted]", value)
    workspace = str(cwd.resolve(strict=False))
    if workspace and workspace != "/":
        text = text.replace(workspace, "<workspace>")
    home = str(Path.home())
    if home and home != "/":
        text = text.replace(home, "<home>")
    text = re.sub(
        r"/(?:Users|home)/[^/\s]+(?:/[^\s,;]*)?",
        "[redacted-path]",
        text,
    )
    return text[:20_000]


def redact_path(value: str, cwd: Path) -> str:
    try:
        path = Path(value).expanduser().resolve(strict=False)
        workspace = cwd.resolve(strict=False)
        relative = path.relative_to(workspace)
        return (
            "<workspace>"
            if str(relative) == "."
            else f"<workspace>/{relative.as_posix()}"
        )
    except (OSError, ValueError):
        if Path(value).is_absolute() or value.startswith("file:"):
            return "[redacted-path]"
        safe = value.replace("\\", "/")
        if ".." in Path(safe).parts:
            return "[redacted-path]"
        return redact_text(safe, cwd)[:1024]


def session_matches_directory(
    session: Mapping[str, Any],
    cwd: Path,
) -> bool:
    directory = session.get("directory")
    if not isinstance(directory, str) or not directory:
        return False
    try:
        return (
            Path(directory).expanduser().resolve(strict=False)
            == cwd.resolve(strict=False)
        )
    except OSError:
        return False


def has_pairling_permission_rules(session: Mapping[str, Any]) -> bool:
    rules = session.get("permission")
    if not isinstance(rules, list):
        return False
    normalized = [
        {
            "permission": rule.get("permission"),
            "pattern": rule.get("pattern"),
            "action": rule.get("action"),
        }
        for rule in rules
        if isinstance(rule, Mapping)
    ]
    return normalized == list(PAIRLING_PERMISSION_RULESET)


def model_from_session(
    session: Mapping[str, Any],
) -> tuple[str, str] | None:
    model = session.get("model")
    if not isinstance(model, Mapping):
        return None
    provider_id = model.get("providerID")
    model_id = model.get("id") or model.get("modelID")
    if isinstance(provider_id, str) and isinstance(model_id, str):
        return provider_id, model_id
    return None


def safe_int(value: Any) -> int:
    return (
        value
        if isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
        else 0
    )


def safe_number(value: Any) -> float:
    return (
        float(value)
        if isinstance(value, (int, float))
        and not isinstance(value, bool)
        else 0.0
    )


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise OpenCodeLaunchError(
            "OpenCode launch input could not be fingerprinted"
        ) from exc
    return digest.hexdigest()


def configuration_digest(cwd: Path) -> str:
    """Fingerprint documented config inputs without retaining their contents."""
    candidates: list[Path] = []
    home = Path.home().resolve(strict=False)
    config_roots = [home / ".config" / "opencode"]
    xdg_root = os.environ.get("XDG_CONFIG_HOME")
    if xdg_root:
        if "\x00" in xdg_root:
            raise OpenCodeLaunchError(
                "OpenCode config root is invalid"
            )
        config_roots.append(
            Path(xdg_root).expanduser().resolve(strict=False)
            / "opencode"
        )
    for config_root in config_roots:
        for name in ("opencode.json", "opencode.jsonc"):
            candidates.append(config_root / name)
    current = cwd.resolve(strict=False)
    while True:
        for name in ("opencode.json", "opencode.jsonc"):
            candidates.append(current / name)
            candidates.append(current / ".opencode" / name)
        if current == current.parent:
            break
        current = current.parent
    records: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for candidate in candidates:
        normalized = candidate.resolve(strict=False)
        if normalized in seen:
            continue
        seen.add(normalized)
        try:
            exists = candidate.exists()
            is_file = candidate.is_file()
        except OSError as exc:
            raise OpenCodeLaunchError(
                "OpenCode config input could not be inspected"
            ) from exc
        if not exists:
            continue
        if not is_file:
            raise OpenCodeLaunchError(
                "OpenCode config input is not a regular file"
            )
        try:
            stat = candidate.stat()
        except OSError as exc:
            raise OpenCodeLaunchError(
                "OpenCode config input changed during inspection"
            ) from exc
        records.append(
            {
                "path": str(candidate),
                "device": stat.st_dev,
                "inode": stat.st_ino,
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "content_sha256": file_sha256(candidate),
            }
        )
    return fingerprint(records)


def fingerprint(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()
    ).hexdigest()
