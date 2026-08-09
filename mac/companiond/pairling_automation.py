"""Fail-closed client for the stable Pairling macOS automation helper.

The companion daemon remains the phone authorization and action-receipt boundary.
This module only authenticates that daemon to the launchd-managed helper. It
never runs AppleScript or selects an alternate Terminal requester.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import os
import plistlib
import socket
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Callable

try:
    from runtime_paths import app_support_root
except ImportError:
    app_support_root = None


AUTOMATION_HELPER_BUNDLE_ID = "dev.pairling.automation"
AUTOMATION_HELPER_TEAM_ID = "965AVD34A3"
AUTOMATION_HELPER_SCHEMA_VERSION = 1
AUTOMATION_HELPER_MAX_REQUEST_BYTES = 64 * 1024
AUTOMATION_HELPER_MAX_RESPONSE_BYTES = 512 * 1024
AUTOMATION_HELPER_DEFAULT_TIMEOUT_MILLISECONDS = 3_000
AUTOMATION_HELPER_MIN_TIMEOUT_MILLISECONDS = 250
AUTOMATION_HELPER_MAX_TIMEOUT_MILLISECONDS = 15_000
AUTOMATION_HELPER_CAPABILITY_CACHE_SECONDS = 3.0


class AutomationHelperError(RuntimeError):
    """A safe, typed failure at the local automation boundary."""

    def __init__(self, code: str, safe_message: str) -> None:
        super().__init__(safe_message)
        self.code = code
        self.safe_message = safe_message


class AutomationHelperUnavailableError(AutomationHelperError):
    """The stable helper cannot safely receive a request."""


class AutomationHelperMutationIndeterminate(AutomationHelperError):
    """A mutation may have reached the helper before its result was lost."""


def _unavailable(code: str = "automation_helper_unavailable") -> AutomationHelperUnavailableError:
    return AutomationHelperUnavailableError(code, "Pairling automation helper is unavailable.")


def _verify_signed_helper(app_path: Path) -> None:
    """Verify the immutable app identity before trusting its socket response."""

    try:
        app_stat = os.lstat(app_path)
        executable = app_path / "Contents" / "MacOS" / "PairlingAutomation"
        executable_stat = os.lstat(executable)
        info = plistlib.loads((app_path / "Contents" / "Info.plist").read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise _unavailable("automation_helper_missing") from exc
    if (
        not stat.S_ISDIR(app_stat.st_mode)
        or stat.S_ISLNK(app_stat.st_mode)
        or app_stat.st_uid != os.geteuid()
        or not stat.S_ISREG(executable_stat.st_mode)
        or stat.S_ISLNK(executable_stat.st_mode)
        or executable_stat.st_uid != os.geteuid()
        or not isinstance(info, dict)
        or info.get("CFBundleIdentifier") != AUTOMATION_HELPER_BUNDLE_ID
    ):
        raise _unavailable("automation_helper_invalid")

    verified = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", str(app_path)],
        capture_output=True,
        check=False,
        text=True,
    )
    details = subprocess.run(
        ["/usr/bin/codesign", "-dvv", str(app_path)],
        capture_output=True,
        check=False,
        text=True,
    )
    if verified.returncode != 0 or details.returncode != 0:
        raise _unavailable("automation_helper_invalid")
    metadata = f"{details.stdout}\n{details.stderr}"
    if (
        f"Identifier={AUTOMATION_HELPER_BUNDLE_ID}" not in metadata
        or f"TeamIdentifier={AUTOMATION_HELPER_TEAM_ID}" not in metadata
    ):
        raise _unavailable("automation_helper_invalid")


class AutomationHelperClient:
    """Typed, owner-only caller for the signed Pairling helper socket."""

    def __init__(
        self,
        *,
        root: Path | None = None,
        default_timeout_milliseconds: int = AUTOMATION_HELPER_DEFAULT_TIMEOUT_MILLISECONDS,
        identity_validator: Callable[[Path], None] = _verify_signed_helper,
    ) -> None:
        if not AUTOMATION_HELPER_MIN_TIMEOUT_MILLISECONDS <= default_timeout_milliseconds <= AUTOMATION_HELPER_MAX_TIMEOUT_MILLISECONDS:
            raise ValueError("invalid default automation helper timeout")
        if root is None:
            support_root = (
                app_support_root()
                if app_support_root
                else Path.home() / "Library" / "Application Support" / "Pairling"
            )
            root = support_root / "automation"
        self._root = Path(root).expanduser().resolve(strict=False)
        self._app_path = self._root / "Pairling.app"
        self._executable_path = self._app_path / "Contents" / "MacOS" / "PairlingAutomation"
        self._socket_path = self._root / "automation.sock"
        self._secret_path = self._root / "local-secret"
        self._default_timeout_milliseconds = default_timeout_milliseconds
        self._identity_validator = identity_validator
        self._capability_cache: tuple[float, dict[str, Any]] | None = None
        self._identity_verified_at = 0.0

    def capability(
        self,
        *,
        fresh: bool = False,
        timeout_ms: int | None = None,
    ) -> dict[str, Any]:
        now = time.monotonic()
        if not fresh and self._capability_cache is not None:
            cached_at, cached = self._capability_cache
            if now - cached_at <= AUTOMATION_HELPER_CAPABILITY_CACHE_SECONDS:
                return cached
        response = self._request(
            "status",
            {},
            timeout_ms=timeout_ms,
            fresh_identity=fresh,
        )
        self._capability_cache = (now, response)
        return response

    def probe(
        self,
        *,
        prompt: bool = False,
        setup_capability: str | None = None,
        timeout_ms: int | None = None,
    ) -> dict[str, Any]:
        if prompt:
            if not setup_capability:
                raise ValueError("setup capability is required to request permissions")
            return self._request(
                "requestPermissions",
                {"openAccessibilitySettings": True},
                timeout_ms=timeout_ms,
                setup_capability=setup_capability,
                fresh_identity=True,
            )
        return self._request("probeTerminal", {}, timeout_ms=timeout_ms, fresh_identity=True)

    def read_tab(self, tty: str, *, timeout_ms: int) -> dict[str, Any]:
        return self._request("readTerminalTab", {"tty": tty}, timeout_ms=timeout_ms)

    def send_text(
        self,
        tty: str,
        text: str,
        *,
        bracketed_paste: bool,
        timeout_ms: int,
    ) -> dict[str, Any]:
        if not isinstance(bracketed_paste, bool):
            raise ValueError("bracketed_paste must be a bool")
        if (blocked := self._fresh_mutation_capability(timeout_ms=timeout_ms)) is not None:
            return blocked
        return self._request(
            "sendTerminalText",
            {
                "tty": tty,
                "text": text,
                "bracketedPaste": bracketed_paste,
            },
            mutation=True,
            timeout_ms=timeout_ms,
            fresh_identity=True,
        )

    def send_escape(self, tty: str, *, timeout_ms: int) -> dict[str, Any]:
        if (blocked := self._fresh_mutation_capability(timeout_ms=timeout_ms)) is not None:
            return blocked
        return self._request(
            "sendSpecialKey",
            {"tty": tty, "key": "escape"},
            mutation=True,
            timeout_ms=timeout_ms,
            fresh_identity=True,
        )

    def send_special_key(self, tty: str, key: str, *, timeout_ms: int) -> dict[str, Any]:
        if (blocked := self._fresh_mutation_capability(timeout_ms=timeout_ms)) is not None:
            return blocked
        return self._request(
            "sendSpecialKey",
            {"tty": tty, "key": key},
            mutation=True,
            timeout_ms=timeout_ms,
            fresh_identity=True,
        )

    def start_session(
        self,
        command: str,
        ownership_marker: str,
        *,
        timeout_ms: int,
    ) -> dict[str, Any]:
        if (blocked := self._fresh_mutation_capability(timeout_ms=timeout_ms)) is not None:
            return blocked
        return self._request(
            "startPairlingSession",
            {"command": command, "ownershipMarker": ownership_marker},
            mutation=True,
            timeout_ms=timeout_ms,
            fresh_identity=True,
        )

    def inspect_tab(self, tty: str, *, timeout_ms: int) -> dict[str, Any]:
        return self._request("inspectTerminalTab", {"tty": tty}, timeout_ms=timeout_ms)

    def close_owned_session(
        self,
        tty: str,
        ownership_marker: str,
        *,
        timeout_ms: int,
    ) -> dict[str, Any]:
        if (blocked := self._fresh_mutation_capability(timeout_ms=timeout_ms)) is not None:
            return blocked
        return self._request(
            "closePairlingSession",
            {"tty": tty, "ownershipMarker": ownership_marker},
            mutation=True,
            timeout_ms=timeout_ms,
            fresh_identity=True,
        )

    def _fresh_mutation_capability(self, *, timeout_ms: int) -> dict[str, Any] | None:
        try:
            response = self.capability(fresh=True, timeout_ms=timeout_ms)
        except AutomationHelperError as exc:
            return {
                "requestID": None,
                "ok": False,
                "error": {"code": exc.code, "safeMessage": exc.safe_message},
                "mutationOutcome": "failed_before_mutation",
                "helper": None,
                "result": None,
            }
        if response.get("ok") is not True:
            return response
        result = response.get("result")
        capability = result.get("terminal_capability") if isinstance(result, dict) else None
        if isinstance(capability, dict) and capability.get("terminal_control_ready") is True:
            return None
        return {
            "requestID": response.get("requestID"),
            "ok": False,
            "error": {
                "code": "mac_permissions_needed",
                "safeMessage": "Finish Pairling setup on the Mac before controlling Terminal.",
            },
            "mutationOutcome": "failed_before_mutation",
            "helper": response.get("helper"),
            "result": result if isinstance(result, dict) else None,
        }
    def _request(
        self,
        operation: str,
        arguments: dict[str, Any],
        *,
        mutation: bool = False,
        timeout_ms: int | None = None,
        setup_capability: str | None = None,
        fresh_identity: bool = False,
    ) -> dict[str, Any]:
        timeout = self._resolve_timeout(timeout_ms)
        request_id = str(uuid.uuid4())
        try:
            self._verify_local_identity(fresh=fresh_identity)
            local_secret = self._load_local_secret()
            payload: dict[str, Any] = {
                "schemaVersion": AUTOMATION_HELPER_SCHEMA_VERSION,
                "requestID": request_id,
                "operation": operation,
                "arguments": arguments,
                "timeoutMilliseconds": timeout,
                "authentication": base64.urlsafe_b64encode(local_secret).decode("ascii").rstrip("="),
            }
            if setup_capability is not None:
                payload["setupCapability"] = setup_capability
            response = self._send(payload, timeout_ms=timeout)
            self._validate_response(response, request_id=request_id)
            return response
        except AutomationHelperMutationIndeterminate:
            raise
        except AutomationHelperError as exc:
            if mutation:
                raise AutomationHelperMutationIndeterminate(
                    exc.code,
                    "Pairling could not determine whether Terminal received the request.",
                ) from exc
            raise

    def _resolve_timeout(self, timeout_ms: int | None) -> int:
        timeout = self._default_timeout_milliseconds if timeout_ms is None else timeout_ms
        if not isinstance(timeout, int) or not AUTOMATION_HELPER_MIN_TIMEOUT_MILLISECONDS <= timeout <= AUTOMATION_HELPER_MAX_TIMEOUT_MILLISECONDS:
            raise ValueError("invalid automation helper timeout")
        return timeout

    def _verify_local_identity(self, *, fresh: bool) -> None:
        self._require_secure_directory(self._root)
        now = time.monotonic()
        if not fresh and now - self._identity_verified_at <= AUTOMATION_HELPER_CAPABILITY_CACHE_SECONDS:
            return
        try:
            self._identity_validator(self._app_path)
        except AutomationHelperError:
            raise
        except Exception as exc:
            raise _unavailable("automation_helper_invalid") from exc
        self._identity_verified_at = now

    def _load_local_secret(self) -> bytes:
        try:
            metadata = os.lstat(self._secret_path)
        except OSError as exc:
            raise _unavailable("automation_helper_missing") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise _unavailable("automation_helper_invalid")
        try:
            secret = self._secret_path.read_bytes()
        except OSError as exc:
            raise _unavailable("automation_helper_unreachable") from exc
        if len(secret) != 32:
            raise _unavailable("automation_helper_invalid")
        return secret

    @staticmethod
    def _require_secure_directory(path: Path) -> None:
        try:
            metadata = os.lstat(path)
        except OSError as exc:
            raise _unavailable("automation_helper_missing") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise _unavailable("automation_helper_invalid")

    def _require_secure_socket(self) -> None:
        try:
            metadata = os.lstat(self._socket_path)
        except OSError as exc:
            raise _unavailable("automation_helper_unreachable") from exc
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise _unavailable("automation_helper_invalid")

    def _send(self, payload: dict[str, Any], *, timeout_ms: int) -> dict[str, Any]:
        try:
            encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
        except (TypeError, ValueError) as exc:
            raise _unavailable("automation_helper_invalid") from exc
        if len(encoded) > AUTOMATION_HELPER_MAX_REQUEST_BYTES:
            raise _unavailable("automation_helper_invalid")

        self._require_secure_socket()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(timeout_ms / 1_000)
                connection.connect(str(self._socket_path))
                connection.sendall(encoded)
                response = bytearray()
                while True:
                    chunk = connection.recv(4_096)
                    if not chunk:
                        break
                    response.extend(chunk)
                    if len(response) > AUTOMATION_HELPER_MAX_RESPONSE_BYTES:
                        raise _unavailable("automation_helper_invalid")
                    if b"\n" in chunk:
                        break
        except AutomationHelperError:
            raise
        except (OSError, TimeoutError) as exc:
            raise _unavailable("automation_helper_unreachable") from exc

        line = bytes(response).split(b"\n", 1)[0]
        if not line:
            raise _unavailable("automation_helper_unreachable")
        try:
            parsed = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise _unavailable("automation_helper_invalid") from exc
        if not isinstance(parsed, dict):
            raise _unavailable("automation_helper_invalid")
        return parsed

    def _validate_response(self, response: dict[str, Any], *, request_id: str) -> None:
        if response.get("requestID") != request_id or not isinstance(response.get("ok"), bool):
            raise _unavailable("automation_helper_invalid")
        helper = response.get("helper")
        if (
            not isinstance(helper, dict)
            or helper.get("bundleID") != AUTOMATION_HELPER_BUNDLE_ID
            or helper.get("executablePath") != str(self._executable_path)
            or not isinstance(helper.get("version"), str)
        ):
            raise _unavailable("automation_helper_invalid")
        error = response.get("error")
        if error is not None and (
            not isinstance(error, dict)
            or not isinstance(error.get("code"), str)
            or not isinstance(error.get("safeMessage"), str)
        ):
            raise _unavailable("automation_helper_invalid")
        outcome = response.get("mutationOutcome")
        if outcome is not None and outcome not in {
            "confirmed",
            "failed_before_mutation",
            "outcome_unknown",
        }:
            raise _unavailable("automation_helper_invalid")
        if response.get("result") is not None and not isinstance(response.get("result"), dict):
            raise _unavailable("automation_helper_invalid")


def terminal_permission_failure_summary(
    *,
    code: str,
    safe_message: str,
) -> dict[str, Any]:
    """Return the stable, safe capability shape when the helper cannot answer."""
    helper_state = {
        "automation_helper_missing": "helper_missing",
        "automation_helper_invalid": "helper_invalid",
        "automation_helper_unreachable": "helper_unreachable",
    }.get(code, "unknown_error")
    return {
        "target": "Terminal",
        "helper": {"state": helper_state},
        "accessibility": {"state": "unknown_error"},
        "terminal_automation": {"state": "unknown_error"},
        "terminal_probe": {"state": "unknown_error", "checked_at": None},
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "blocking_reasons": [safe_message],
        "terminal_control_ready": False,
    }


def terminal_permissions_summary(
    *,
    fresh: bool = True,
    client: AutomationHelperClient | None = None,
) -> dict[str, Any]:
    """Read the helper's non-prompting Terminal capability in one shared shape."""
    try:
        response = (client or AutomationHelperClient()).capability(fresh=fresh)
    except AutomationHelperUnavailableError as exc:
        return terminal_permission_failure_summary(
            code=exc.code,
            safe_message=exc.safe_message,
        )
    except Exception:
        return terminal_permission_failure_summary(
            code="unknown_error",
            safe_message="Pairling could not verify Mac permissions.",
        )

    result = response.get("result") if isinstance(response, dict) else None
    capability = (
        result.get("terminal_capability")
        if isinstance(result, dict)
        else None
    )
    if response.get("ok") is True and isinstance(capability, dict):
        summary = dict(capability)
        summary["target"] = "Terminal"
        summary["terminal_control_ready"] = (
            summary.get("terminal_control_ready") is True
        )
        return summary

    error = response.get("error") if isinstance(response, dict) else None
    code = (
        str(error.get("code") or "unknown_error")
        if isinstance(error, dict)
        else "unknown_error"
    )
    safe_message = (
        str(error.get("safeMessage") or "Pairling could not verify Mac permissions.")
        if isinstance(error, dict)
        else "Pairling could not verify Mac permissions."
    )
    return terminal_permission_failure_summary(
        code=code,
        safe_message=safe_message,
    )
