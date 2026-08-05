#!/usr/bin/env python3
"""Local Pairling push registration and delivery state.

This is the Mac-side durable registry for APNs-capable paired devices. The
normal registry never stores raw APNs tokens; local development APNs sends use a
separate private secret store so delivery can be proven without leaking tokens
through status/audit responses.
"""

from __future__ import annotations

import json
import math
import os
import stat
import base64
import email.utils
import fcntl
import hashlib
import hmac
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
except Exception:  # pragma: no cover - provider status still works without sends.
    hashes = None
    serialization = None
    ec = None
    utils = None


CONTRACT_VERSION = "pairling-push-devices-v1"
DEFAULT_PREFERENCES = {
    "standard_push_enabled": False,
    "live_activity_enabled": False,
    "worker_sentinel_enabled": False,
    "turn_done_enabled": False,
    "push_diagnostics_enabled": True,
    "push_snoozed_until": None,
    "quiet_hours": None,
}
APNS_TOKEN_MIN_HEX_CHARS = 16
APNS_TOKEN_MAX_HEX_CHARS = 4096
DEFAULT_APNS_TOPIC = "dev.pairling.ios"
DEFAULT_TEAM_ID = "965AVD34A3"
APNS_ENVIRONMENTS = {"development", "sandbox", "production"}
APNS_KEY_ENVIRONMENTS = {"development", "sandbox", "production", "both"}

# The /health push axis (health_axis). OK means Apple accepted the delivery;
# neutral outcomes are the device's own choice and prove nothing about the
# plane, so they count neither for nor against it.
PUSH_HEALTH_CONTRACT_VERSION = "pairling-push-health-v1"
PUSH_HEALTH_OK_OUTCOMES = {"sent", "ok"}
PUSH_HEALTH_NEUTRAL_OUTCOMES = {"disabled", "snoozed"}
OUTBOX_SENDING_LEASE_SECONDS = 60.0
OUTBOX_TERMINAL_LIMIT = 200
OUTBOX_RETRY_PAYLOAD_CONTRACT = "pairling-push-retry-payload-v1"
OUTBOX_RETRY_REQUEST_CONTRACT_VERSION = 2
OUTBOX_RETRY_PAYLOAD_MAX_BYTES = 256 * 1024
OUTBOX_RETRY_DRAIN_LIMIT = 50
OUTBOX_ACTIVE_STATES = {"pending", "sending", "credential_blocked"}
OUTBOX_ACTIVE_GLOBAL_LIMIT = 256
OUTBOX_ACTIVE_DEVICE_LIMIT = 128
OUTBOX_ACTIVE_RETENTION_SECONDS = 24 * 60 * 60
RELAY_RESPONSE_MAX_BYTES = 64 * 1024
RELAY_NONTERMINAL_STATES = frozenset({"queued", "pending", "sending", "credential_blocked"})

KIND_CATEGORY = {
    "session_attention": "PAIRLING_SESSION_ATTENTION",
    "turn_done": "PAIRLING_TURN_DONE",
    "mac_health": "PAIRLING_MAC_HEALTH",
    "worker_sentinel": "PAIRLING_WORKER_SENTINEL",
    "action_required": "PAIRLING_SESSION_ATTENTION",
    "turn_result": "PAIRLING_TURN_DONE",
    "turn_failed": "PAIRLING_SESSION_ATTENTION",
    "tool_risk": "PAIRLING_SESSION_ATTENTION",
    "mac_route_risk": "PAIRLING_MAC_HEALTH",
    "worker_pressure": "PAIRLING_WORKER_SENTINEL",
    "deploy_result": "PAIRLING_TURN_DONE",
    "remote_join": "PAIRLING_REMOTE_JOIN",
    "push_diagnostic": "PAIRLING_PUSH_DIAGNOSTIC",
}
KIND_ALERT = {
    "session_attention": ("Pairling needs input", "A session is waiting for your decision."),
    "turn_done": ("Pairling result ready", "A useful turn result is ready."),
    "mac_health": ("Pairling Mac health", "The paired Mac helper needs attention."),
    "worker_sentinel": ("Pairling worker warning", "Worker automation needs review."),
    "action_required": ("Pairling needs approval", "Review the requested action before work continues."),
    "turn_result": ("Pairling result ready", "A useful turn result is ready."),
    "turn_failed": ("Pairling turn failed", "A turn failed and needs review."),
    "tool_risk": ("Pairling tool risk", "A tool signal needs review."),
    "mac_route_risk": ("Mac route timed out", "The paired Mac route needs attention."),
    "worker_pressure": ("Pairling worker pressure", "Worker or token pressure needs review."),
    "deploy_result": ("Deploy result ready", "A build or deploy result is available."),
    "remote_join": ("New device paired remotely", "A device joined your Mac over the internet."),
    "push_diagnostic": ("Pairling push test", "Push delivery is configured for this device."),
}
TIME_SENSITIVE_KINDS = {"session_attention", "mac_health", "worker_sentinel", "action_required", "turn_failed", "tool_risk", "mac_route_risk", "worker_pressure", "remote_join"}


class PushDispatcherError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


_PUSH_SECRET_LOCKS_GUARD = threading.Lock()
_PUSH_SECRET_LOCKS: dict[str, threading.RLock] = {}
_PUSH_REGISTRY_LOCKS_GUARD = threading.Lock()
_PUSH_REGISTRY_LOCKS: dict[str, threading.RLock] = {}


def _push_secret_thread_lock(path: Path) -> threading.RLock:
    key = os.path.abspath(os.fspath(path))
    with _PUSH_SECRET_LOCKS_GUARD:
        return _PUSH_SECRET_LOCKS.setdefault(key, threading.RLock())


def _push_registry_thread_lock(path: Path) -> threading.RLock:
    key = os.path.abspath(os.fspath(path))
    with _PUSH_REGISTRY_LOCKS_GUARD:
        return _PUSH_REGISTRY_LOCKS.setdefault(key, threading.RLock())


def _read_push_secrets_unlocked(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        data = {}
    except json.JSONDecodeError as exc:
        raise PushDispatcherError(
            "push_secret_store_corrupt",
            f"push secret store is corrupt: {exc}",
            500,
        ) from exc
    if not isinstance(data, dict) or not isinstance(data.get("devices", {}), dict):
        raise PushDispatcherError(
            "push_secret_store_corrupt",
            "push secret store must contain an object-valued devices field",
            500,
        )
    data.setdefault("schema_version", 1)
    data.setdefault("devices", {})
    delivery_payloads = data.setdefault("delivery_payloads", {})
    if not isinstance(delivery_payloads, dict):
        raise PushDispatcherError(
            "push_secret_store_corrupt",
            "push secret store delivery_payloads field is not an object",
            500,
        )
    pairing_notifications = data.setdefault("pairing_notifications", {})
    if not isinstance(pairing_notifications, dict):
        raise PushDispatcherError(
            "push_secret_store_corrupt",
            "push secret store pairing_notifications field is not an object",
            500,
        )
    revoked = data.setdefault("revoked_device_ids", [])
    if not isinstance(revoked, list):
        raise PushDispatcherError(
            "push_secret_store_corrupt",
            "push secret store revoked_device_ids field is not an array",
            500,
        )
    return data


def _with_push_secret_lock(path: Path, operation: Callable[[], Any]) -> Any:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, stat.S_IRWXU)
    except OSError:
        pass
    lock_path = path.with_name(f"{path.name}.lock")
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with _push_secret_thread_lock(path):
        lock_fd = os.open(lock_path, flags, 0o600)
        try:
            os.fchmod(lock_fd, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            return operation()
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)


def read_push_secrets(path: Path) -> dict[str, Any]:
    """Read the private push store without racing an atomic replacement."""
    try:
        return _with_push_secret_lock(path, lambda: _read_push_secrets_unlocked(path))
    except PushDispatcherError:
        raise
    except OSError as exc:
        raise PushDispatcherError(
            "push_secret_store_unavailable",
            "push secret store is unavailable",
            500,
        ) from exc


def mutate_push_secrets(
    path: Path,
    mutator: Callable[[dict[str, Any]], Any],
) -> Any:
    """Apply one current-state mutation and atomically replace the secret store.

    The process lock joins PairingStore and every dispatcher instance. The file
    lock extends the same boundary to another runtime process during upgrades.
    """
    def operation() -> Any:
        payload = _read_push_secrets_unlocked(path)
        result = mutator(payload)
        tmp = path.with_name(
            f"{path.name}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex}.tmp"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(tmp, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fd = -1
                json.dump(payload, fh, indent=2, sort_keys=True)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
            os.chmod(path, 0o600)
            try:
                parent_fd = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
            except OSError:
                pass
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
        return result

    try:
        return _with_push_secret_lock(path, operation)
    except PushDispatcherError:
        raise
    except OSError as exc:
        raise PushDispatcherError(
            "push_secret_store_unavailable",
            "push secret store is unavailable",
            500,
        ) from exc


class LocalAPNSProvider:
    """Small APNs HTTP/2 sender for local developer-device validation."""

    def __init__(self, *, config_path: Path | None = None, now_fn=time.time, run_fn=subprocess.run):
        self.config_path = config_path
        self.now_fn = now_fn
        self.run_fn = run_fn

    def status(self) -> dict[str, Any]:
        config = self._config()
        return {
            "mode": config["mode"],
            "configured": config["configured"],
            "local_apns_key_configured": config["local_apns_key_configured"],
            "relay_url_configured": bool(config["relay_url"]),
            "relay_url": config["relay_url"] or None,
            "topic": config["topic"],
            "environment": config["environment"],
            "key_environment": config["key_environment"],
            "key_id": config["key_id"] if config["local_apns_key_configured"] else None,
        }

    def send_alert(
        self,
        *,
        token: str,
        event_id: str,
        kind: str,
        route: str,
        title: str | None = None,
        body: str | None = None,
        thread_id: str | None = None,
        pairling_extra: dict[str, Any] | None = None,
        interruption_level: str | None = None,
        category: str | None = None,
    ) -> dict[str, Any]:
        config = self._config()
        if not config["local_apns_configured"]:
            raise PushDispatcherError("local_apns_not_configured", "local APNs provider is not configured", 503)
        _validate_apns_token(token, "apns_token")
        kind = kind if kind in KIND_CATEGORY else "push_diagnostic"
        default_title, default_body = KIND_ALERT[kind]
        title = _bounded_optional(title, 90) or default_title
        body = _bounded_optional(body, 220) or default_body
        pairling_payload = {
            "event_id": event_id,
            "kind": kind,
            "route": route,
        }
        if isinstance(pairling_extra, dict):
            for key, value in pairling_extra.items():
                if key in {"event_id", "kind", "route"}:
                    continue
                if isinstance(value, (str, int, float, bool)) or value is None:
                    pairling_payload[str(key)[:80]] = _bounded_optional(value, 180) if isinstance(value, str) else value
        resolved_category = (
            "PAIRLING_APPROVAL_DECISION"
            if category == "PAIRLING_APPROVAL_DECISION"
            else KIND_CATEGORY[kind]
        )
        payload = {
            "aps": {
                "alert": {"title": title, "body": body},
                "sound": "default",
                "category": resolved_category,
                "thread-id": _bounded_optional(thread_id, 120) or _thread_id(kind, route),
            },
            "pairling": pairling_payload,
        }
        level = str(interruption_level or "").strip()
        if level in {"passive", "active", "time-sensitive"}:
            payload["aps"]["interruption-level"] = level
        elif kind in TIME_SENSITIVE_KINDS:
            payload["aps"]["interruption-level"] = "time-sensitive"
        return self._send(
            token=token,
            payload=payload,
            push_type="alert",
            topic=config["topic"],
            priority="10",
            event_id=event_id,
            config=config,
        )

    def send_live_activity(
        self,
        *,
        token: str,
        event_id: str,
        event: str,
        content_state: dict[str, Any],
        stale_seconds: int = 75,
        dismissal_seconds: int = 300,
    ) -> dict[str, Any]:
        config = self._config()
        if not config["local_apns_configured"]:
            raise PushDispatcherError("local_apns_not_configured", "local APNs provider is not configured", 503)
        _validate_apns_token(token, "live_activity_token")
        now = int(self.now_fn())
        activity_event = "end" if event == "end" else "update"
        content = _bounded_content_state(content_state, event_id=event_id, now=now)
        aps: dict[str, Any] = {
            "timestamp": now,
            "event": activity_event,
            "content-state": content,
        }
        if activity_event == "end":
            aps["dismissal-date"] = now + max(0, int(dismissal_seconds))
        else:
            aps["stale-date"] = now + max(30, int(stale_seconds))
            if content["state"] in {"attention", "failed"}:
                aps["alert"] = {
                    "title": "Pairling",
                    "body": _live_activity_alert_body(content),
                }
        payload = {"aps": aps}
        return self._send(
            token=token,
            payload=payload,
            push_type="liveactivity",
            topic=config["live_activity_topic"],
            priority="10" if content["state"] in {"attention", "tool", "done", "failed"} else "5",
            event_id=event_id,
            config=config,
        )

    def probe_credentials(self) -> dict[str, Any]:
        """Probe APNs auth with a synthetic token without touching device tokens."""
        config = self._config()
        if not config["local_apns_configured"]:
            raise PushDispatcherError("local_apns_not_configured", "local APNs provider is not configured", 503)
        synthetic_token = "0" * 64
        result = self._send(
            token=synthetic_token,
            payload={
                "aps": {
                    "alert": {
                        "title": "Pairling APNs credential probe",
                        "body": "Synthetic-token credential probe.",
                    },
                    "sound": "default",
                },
                "pairling": {
                    "event_id": "apns_credential_probe",
                    "kind": "push_diagnostic",
                    "route": "pairling://settings/push",
                },
            },
            push_type="alert",
            topic=config["topic"],
            priority="10",
            event_id=f"apns_credential_probe_{int(self.now_fn() * 1000)}",
            config=config,
        )
        authenticated = result.get("apns_status") == 400 and result.get("apns_reason") == "BadDeviceToken"
        return {
            "ok": authenticated,
            "authenticated": authenticated,
            "expected_reason": "BadDeviceToken",
            "synthetic_token_used": True,
            "provider": self.status(),
            "result": {key: value for key, value in result.items() if key != "apns_id"},
            "apns_id_present": bool(result.get("apns_id")),
        }

    def _send(
        self,
        *,
        token: str,
        payload: dict[str, Any],
        push_type: str,
        topic: str,
        priority: str,
        event_id: str,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        jwt = self._jwt(config)
        apns_id = str(uuid.uuid4()).upper()
        host = "api.sandbox.push.apple.com" if config["environment"] in {"development", "sandbox"} else "api.push.apple.com"
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        with tempfile.NamedTemporaryFile("wb", delete=False) as payload_file:
            payload_file.write(body)
            payload_file.flush()
            os.fsync(payload_file.fileno())
            payload_path = payload_file.name
        with tempfile.NamedTemporaryFile("w", delete=False) as config_file:
            config_file.write("\n".join([
                "silent",
                "show-error",
                "http2",
                "request = \"POST\"",
                f"url = \"https://{host}/3/device/{token}\"",
                f"header = \"authorization: bearer {jwt}\"",
                f"header = \"apns-topic: {topic}\"",
                f"header = \"apns-push-type: {push_type}\"",
                f"header = \"apns-priority: {priority}\"",
                f"header = \"apns-id: {apns_id}\"",
                f"data-binary = \"@{payload_path}\"",
                "write-out = \"\\n%{http_code}\"",
                "connect-timeout = 10",
                "max-time = 20",
                "",
            ]))
            config_file.flush()
            os.fsync(config_file.fileno())
            config_path = config_file.name
        try:
            os.chmod(config_path, 0o600)
            os.chmod(payload_path, 0o600)
            proc = self.run_fn(
                ["/usr/bin/curl", "--config", config_path],
                capture_output=True,
                text=True,
                timeout=25,
            )
        finally:
            for path in [config_path, payload_path]:
                try:
                    os.unlink(path)
                except OSError:
                    pass
        response_text, http_status = _split_curl_status(proc.stdout)
        reason = None
        if response_text.strip():
            try:
                parsed = json.loads(response_text)
                reason = parsed.get("reason") if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                reason = response_text.strip()[:200]
        sent = proc.returncode == 0 and http_status == 200
        return {
            "sent": sent,
            "outcome": "sent" if sent else _apns_outcome(http_status, reason, proc.returncode),
            "apns_status": http_status,
            "apns_reason": reason,
            "curl_exit_code": proc.returncode,
            "apns_id": apns_id,
            "retryable": http_status in {429, 500, 503} or proc.returncode != 0,
            "invalid_token": http_status == 410 or reason in {"BadDeviceToken", "DeviceTokenNotForTopic", "Unregistered"},
        }

    def _jwt(self, config: dict[str, Any]) -> str:
        if not all([hashes, serialization, ec, utils]):
            raise PushDispatcherError("apns_signing_unavailable", "cryptography is required for APNs signing", 500)
        key_path = Path(config["auth_key_path"])
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or private_key.curve.name != "secp256r1":
            raise PushDispatcherError("invalid_apns_key", "APNs auth key must be a P-256 EC private key", 500)
        header = {"alg": "ES256", "kid": config["key_id"]}
        claims = {"iss": config["team_id"], "iat": int(self.now_fn())}
        signing_input = ".".join([
            _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")),
            _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")),
        ]).encode("ascii")
        signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(signature)
        raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return signing_input.decode("ascii") + "." + _b64url(raw_signature)

    def _config(self) -> dict[str, Any]:
        config = self._push_config()
        mode = self._setting(config, "PAIRLING_PUSH_PROVIDER_MODE", "provider_mode", "not_configured")
        relay_url = self._setting(config, "PAIRLING_PUSH_RELAY_URL", "relay_url", "")
        auth_key_path = self._setting(config, "PAIRLING_APNS_AUTH_KEY_PATH", "apns_auth_key_path", "")
        key_id = self._setting(config, "PAIRLING_APNS_KEY_ID", "apns_key_id", "") or _infer_apns_key_id(auth_key_path)
        team_id = self._setting(config, "PAIRLING_APNS_TEAM_ID", "apns_team_id", DEFAULT_TEAM_ID)
        topic = self._setting(config, "PAIRLING_APNS_TOPIC", "apns_topic", DEFAULT_APNS_TOPIC)
        live_activity_topic = self._setting(
            config,
            "PAIRLING_APNS_LIVE_ACTIVITY_TOPIC",
            "apns_live_activity_topic",
            topic + ".push-type.liveactivity",
        )
        environment = _normalize_apns_environment(
            self._setting(config, "PAIRLING_APNS_ENVIRONMENT", "apns_environment", "development")
        )
        key_environment = _normalize_apns_key_environment(
            self._setting(config, "PAIRLING_APNS_KEY_ENVIRONMENT", "apns_key_environment", environment)
        )
        local_ready = (
            mode == "local_apns"
            and bool(auth_key_path)
            and Path(auth_key_path).is_file()
            and bool(key_id)
            and bool(team_id)
            and bool(topic)
        )
        return {
            "mode": mode,
            "relay_url": relay_url,
            "configured": bool((mode == "relay" and relay_url) or local_ready),
            "local_apns_configured": local_ready,
            "local_apns_key_configured": local_ready,
            "auth_key_path": auth_key_path,
            "key_id": key_id,
            "team_id": team_id,
            "topic": topic,
            "live_activity_topic": live_activity_topic,
            "environment": environment,
            "key_environment": key_environment,
        }

    def _push_config(self) -> dict[str, Any]:
        if not self.config_path:
            return {}
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}
        push = data.get("push") if isinstance(data, dict) else None
        return push if isinstance(push, dict) else {}

    def _setting(self, config: dict[str, Any], env_key: str, config_key: str, default: str) -> str:
        value = os.environ.get(env_key)
        if value is None:
            value = config.get(config_key, default)
        return str(value or "").strip()


class RelayEventSender:
    """Mac-to-relay event client using the paired HMAC secret."""

    _APNS_ACCEPTED_STATES = frozenset({"sent"})
    _RETRYABLE_STATES = RELAY_NONTERMINAL_STATES
    _TERMINAL_FAILURE_STATES = frozenset({
        "dead_letter",
        "invalidated",
        "revoked",
        "superseded",
    })

    def __init__(self, *, now_fn=time.time, opener=urllib.request.urlopen):
        self.now_fn = now_fn
        self.opener = opener

    def submit_event(
        self,
        *,
        relay_url: str,
        relay_pair_secret: str,
        event_body: dict[str, Any],
    ) -> dict[str, Any]:
        body_hash = _b64url(hashlib.sha256(_json_dump(event_body).encode("utf-8")).digest())
        timestamp = int(self.now_fn())
        event_id = str(event_body.get("event_id") or "")
        canonical = f"POST\n/v1/events/submit\n{timestamp}\n{event_id}\n{body_hash}"
        signature = _b64url(hmac.new(
            relay_pair_secret.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).digest())
        payload = {
            "body": event_body,
            "body_hash": body_hash,
            "timestamp": timestamp,
            "event_id": event_id,
            "signature": signature,
        }
        data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        request = urllib.request.Request(
            relay_url.rstrip("/") + "/v1/events/submit",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self.opener(request, timeout=20) as response:
                status = int(getattr(response, "status", 200))
                response_headers = getattr(response, "headers", {})
                response_body = response.read(RELAY_RESPONSE_MAX_BYTES + 1)
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            response_headers = getattr(exc, "headers", {})
            response_body = exc.read(RELAY_RESPONSE_MAX_BYTES + 1)
        except Exception as exc:
            return {
                "accepted": False,
                "outcome": "relay_network_error",
                "relay_status": None,
                "relay_error": type(exc).__name__,
                "retryable": True,
                "invalid_token": False,
            }
        response_too_large = len(response_body) > RELAY_RESPONSE_MAX_BYTES
        try:
            if response_too_large:
                raise ValueError("relay response is too large")
            parsed = json.loads(response_body.decode("utf-8") or "{}")
        except Exception:
            parsed = {}
        http_ok = 200 <= status < 300
        response_ok = bool(parsed.get("ok"))
        reported_state = str(parsed.get("state") or "").strip()
        state = reported_state if http_ok and response_ok else ""
        accepted = bool(state in self._APNS_ACCEPTED_STATES)
        known_failure = state in self._RETRYABLE_STATES or state in self._TERMINAL_FAILURE_STATES
        error = parsed.get("error") if isinstance(parsed.get("error"), dict) else {}
        if response_too_large:
            outcome = "relay_response_too_large"
        elif accepted or known_failure:
            outcome = state
        elif http_ok and response_ok:
            outcome = "relay_state_unknown"
        elif error.get("code"):
            outcome = str(error["code"])
        else:
            outcome = f"relay_http_{status}"
        retry_after_seconds = _bounded_retry_after_seconds(
            response_headers.get("Retry-After") if hasattr(response_headers, "get") else None,
            now=self.now_fn(),
        )
        return {
            "accepted": accepted,
            "outcome": outcome,
            "state": state or None,
            "relay_status": status,
            "relay_error": "relay_response_too_large" if response_too_large else error.get("code") or (
                "unexpected_relay_state" if http_ok and response_ok and not known_failure and not accepted else None
            ),
            "retryable": (
                response_too_large
                or status in {408, 425, 429}
                or status >= 500
                or state in self._RETRYABLE_STATES
            ),
            "retry_after_seconds": retry_after_seconds,
            "invalid_token": state == "invalidated",
        }


class PairlingPushDispatcher:
    def __init__(
        self,
        registry_path: Path,
        *,
        secret_path: Path | None = None,
        now_fn=time.time,
        apns_sender=None,
        relay_sender=None,
    ):
        self.registry_path = registry_path
        self.secret_path = secret_path or registry_path.with_name("push-secrets.json")
        self.now_fn = now_fn
        self.apns_sender = apns_sender or LocalAPNSProvider(config_path=registry_path.parent / "config.json", now_fn=now_fn)
        self.relay_sender = relay_sender or RelayEventSender(now_fn=now_fn)

    @staticmethod
    def _pairing_notification_key(*, pair_id: str, device_id: str) -> str:
        return hashlib.sha256(f"{pair_id}\0{device_id}".encode("utf-8")).hexdigest()

    def mark_remote_pairing_notification_pending(self, *, pair_id: str, device_id: str) -> str:
        pair_id = _nonempty(pair_id, "pair_id")
        device_id = _nonempty(device_id, "device_id")
        key = self._pairing_notification_key(pair_id=pair_id, device_id=device_id)

        def mark(current: dict[str, Any]) -> None:
            now = self.now_fn()
            notifications = current["pairing_notifications"]
            expired = [
                candidate
                for candidate, record in notifications.items()
                if not isinstance(record, dict)
                or float(record.get("updated_at") or 0) < now - 86400.0
            ]
            for candidate in expired:
                del notifications[candidate]
            existing = notifications.get(key)
            if existing is not None and (
                not isinstance(existing, dict)
                or existing.get("pair_id") != pair_id
                or existing.get("device_id") != device_id
            ):
                raise PushDispatcherError(
                    "pairing_notification_conflict",
                    "pairing notification state conflicts with this activation",
                    409,
                )
            if existing is None and len(notifications) >= 512:
                raise PushDispatcherError(
                    "pairing_notification_capacity",
                    "pairing notification state is at capacity",
                    503,
                )
            notifications[key] = {
                "pair_id": pair_id,
                "device_id": device_id,
                "state": "pending",
                "created_at": (
                    existing.get("created_at")
                    if isinstance(existing, dict)
                    else now
                ),
                "updated_at": now,
            }

        mutate_push_secrets(self.secret_path, mark)
        return key

    def remote_pairing_notification_pending(self, *, pair_id: str, device_id: str) -> bool:
        key = self._pairing_notification_key(pair_id=pair_id, device_id=device_id)
        record = self._read_secrets().get("pairing_notifications", {}).get(key)
        return bool(
            isinstance(record, dict)
            and record.get("pair_id") == pair_id
            and record.get("device_id") == device_id
            and record.get("state") == "pending"
        )

    def complete_remote_pairing_notification(self, *, pair_id: str, device_id: str) -> None:
        key = self._pairing_notification_key(pair_id=pair_id, device_id=device_id)

        def complete(current: dict[str, Any]) -> None:
            record = current["pairing_notifications"].get(key)
            if record is None:
                return
            if (
                not isinstance(record, dict)
                or record.get("pair_id") != pair_id
                or record.get("device_id") != device_id
            ):
                raise PushDispatcherError(
                    "pairing_notification_conflict",
                    "pairing notification state conflicts with this activation",
                    409,
                )
            del current["pairing_notifications"][key]

        mutate_push_secrets(self.secret_path, complete)

    @staticmethod
    def _retry_payload_key(*, device_id: str, event_id: str, push_type: str) -> str:
        identity = json.dumps(
            [device_id, event_id, push_type],
            ensure_ascii=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    def _persist_retry_payload(
        self,
        *,
        device_id: str,
        event_id: str,
        push_type: str,
        audit_event: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Store the replay input before a public outbox row can be claimed."""
        try:
            payload_copy = json.loads(json.dumps(
                payload,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ))
        except (TypeError, ValueError) as exc:
            raise PushDispatcherError(
                "push_retry_payload_invalid",
                "push retry payload is not JSON serializable",
                400,
            ) from exc
        key = self._retry_payload_key(
            device_id=device_id,
            event_id=event_id,
            push_type=push_type,
        )
        created_at = self.now_fn()

        def encoded_payload(
            candidate: dict[str, Any],
            *,
            stable_time: float,
            existing_payload: dict[str, Any] | None,
        ) -> tuple[dict[str, Any], str, str]:
            normalized = _normalize_retry_payload_timing(
                candidate,
                push_type=push_type,
                stable_time=stable_time,
                existing_payload=existing_payload,
            )
            encoded = json.dumps(
                normalized,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            if len(encoded.encode("utf-8")) > OUTBOX_RETRY_PAYLOAD_MAX_BYTES:
                raise PushDispatcherError(
                    "push_retry_payload_too_large",
                    "push retry payload is too large",
                    413,
                )
            return normalized, encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()

        def persist(current: dict[str, Any]) -> dict[str, Any]:
            existing = current["delivery_payloads"].get(key)
            if existing is not None:
                if not isinstance(existing, dict) or any(
                    existing.get(field) != expected
                    for field, expected in (
                        ("device_id", device_id),
                        ("event_id", event_id),
                        ("push_type", push_type),
                        ("audit_event", audit_event),
                    )
                ):
                    raise PushDispatcherError(
                        "push_retry_payload_conflict",
                        "push retry payload identity or content conflicts with stored state",
                        409,
                    )
                stored_payload = existing.get("payload")
                if not isinstance(stored_payload, dict):
                    raise PushDispatcherError(
                        "push_retry_payload_conflict",
                        "push retry payload identity or content conflicts with stored state",
                        409,
                    )
                stored_encoded = json.dumps(
                    stored_payload,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                stored_hash = str(existing.get("payload_sha256") or "")
                computed_stored_hash = hashlib.sha256(stored_encoded.encode("utf-8")).hexdigest()
                if stored_hash and not hmac.compare_digest(stored_hash, computed_stored_hash):
                    raise PushDispatcherError(
                        "push_retry_payload_corrupt",
                        "stored push retry payload failed its integrity check",
                        500,
                    )
                stable_time = (
                    _positive_finite_float(existing.get("created_at"))
                    or created_at
                )
                normalized_stored, _, normalized_stored_hash = encoded_payload(
                    stored_payload,
                    stable_time=stable_time,
                    existing_payload=None,
                )
                normalized_candidate, _, candidate_hash = encoded_payload(
                    payload_copy,
                    stable_time=stable_time,
                    existing_payload=normalized_stored,
                )
                if not hmac.compare_digest(normalized_stored_hash, candidate_hash):
                    raise PushDispatcherError(
                        "push_retry_payload_conflict",
                        "push retry payload identity or content conflicts with stored state",
                        409,
                    )
                if (
                    existing.get("payload") != normalized_candidate
                    or existing.get("payload_sha256") != candidate_hash
                ):
                    existing["payload"] = normalized_candidate
                    existing["payload_sha256"] = candidate_hash
                    existing["updated_at"] = self.now_fn()
                return dict(existing)

            normalized_payload, _, payload_sha256 = encoded_payload(
                payload_copy,
                stable_time=created_at,
                existing_payload=None,
            )
            record = {
                "contract_version": OUTBOX_RETRY_PAYLOAD_CONTRACT,
                "request_contract_version": OUTBOX_RETRY_REQUEST_CONTRACT_VERSION,
                "key": key,
                "device_id": device_id,
                "event_id": event_id,
                "push_type": push_type,
                "audit_event": audit_event,
                "payload": normalized_payload,
                "payload_sha256": payload_sha256,
                "created_at": created_at,
                "updated_at": created_at,
            }
            current["delivery_payloads"][key] = record
            return dict(record)

        return mutate_push_secrets(self.secret_path, persist)

    def _delete_retry_payload(self, key: str) -> None:
        def delete(current: dict[str, Any]) -> None:
            current["delivery_payloads"].pop(key, None)

        mutate_push_secrets(self.secret_path, delete)

    def _delete_retry_payload_if_orphaned(
        self,
        *,
        device_id: str,
        event_id: str,
        push_type: str,
        retry_payload_key: str,
    ) -> bool:
        try:
            has_outbox = self._mutate_registry(
                lambda data: self._find_outbox(
                    data,
                    device_id=device_id,
                    event_id=event_id,
                    push_type=push_type,
                ) is not None
            )
        except Exception:
            return False
        if has_outbox:
            return False
        self._delete_retry_payload(retry_payload_key)
        return True

    def _bound_retry_delivery_target(
        self,
        *,
        retry_payload_key: str,
        candidate: dict[str, Any],
        allow_same_activity_rotation: bool,
    ) -> dict[str, Any]:
        """Bind one retry job to private token material before it can be sent."""
        candidate_token = str(candidate.get("token") or "")
        candidate_hash = str(candidate.get("token_hash") or "")
        candidate_activity_id = str(candidate.get("activity_id") or "") or None
        candidate_environment = _normalize_apns_environment(candidate.get("apns_environment"))
        if candidate_token and candidate_hash != _sha256_hex(candidate_token):
            raise PushDispatcherError(
                "push_retry_target_invalid",
                "push retry target token hash does not match its private token",
                500,
            )

        def bind(current: dict[str, Any]) -> dict[str, Any]:
            record = current["delivery_payloads"].get(retry_payload_key)
            if not isinstance(record, dict):
                raise PushDispatcherError(
                    "push_retry_payload_missing",
                    "push retry payload is missing before target binding",
                    500,
                )
            existing = record.get("delivery_target")
            if not isinstance(existing, dict) or not existing.get("token_hash"):
                if not candidate_token or not candidate_hash:
                    return {}
                target = {
                    "token": candidate_token,
                    "token_hash": candidate_hash,
                    "activity_id": candidate_activity_id,
                    "apns_environment": candidate_environment,
                    "bound_at": self.now_fn(),
                }
                record["delivery_target"] = target
                record["updated_at"] = self.now_fn()
                return dict(target)

            existing_token = str(existing.get("token") or "")
            existing_hash = str(existing.get("token_hash") or "")
            if not existing_token or existing_hash != _sha256_hex(existing_token):
                raise PushDispatcherError(
                    "push_retry_target_invalid",
                    "stored push retry target is incomplete or corrupt",
                    500,
                )
            existing_activity_id = str(existing.get("activity_id") or "") or None
            can_rotate = bool(
                allow_same_activity_rotation
                and candidate_token
                and candidate_hash
                and candidate_hash != existing_hash
                and existing_activity_id
                and existing_activity_id == candidate_activity_id
            )
            if can_rotate:
                target = {
                    "token": candidate_token,
                    "token_hash": candidate_hash,
                    "activity_id": candidate_activity_id,
                    "apns_environment": candidate_environment,
                    "bound_at": existing.get("bound_at") or self.now_fn(),
                    "retargeted_at": self.now_fn(),
                    "retargeted_from_token_hash": existing_hash,
                }
                record["delivery_target"] = target
                record["updated_at"] = self.now_fn()
                return dict(target)
            return dict(existing)

        return mutate_push_secrets(self.secret_path, bind)

    def _bound_retry_relay_target(
        self,
        *,
        retry_payload_key: str,
        device_id: str,
        device: dict[str, Any],
        allow_create: bool,
    ) -> dict[str, Any]:
        secret = self._secret_for_device(device_id)
        relay_pair_secret = str(secret.get("relay_pair_secret") or "").strip()
        candidate = {
            "relay_device_id": str(
                device.get("relay_device_id") or secret.get("relay_device_id") or ""
            ).strip(),
            "mac_install_id": str(
                secret.get("mac_install_id")
                or device.get("mac_install_id")
                or os.environ.get("PAIRLING_MAC_INSTALL_ID")
                or ""
            ).strip(),
            "relay_pair_secret_hash": _sha256_hex(relay_pair_secret) if relay_pair_secret else "",
        }

        def bind(current: dict[str, Any]) -> dict[str, Any]:
            record = current["delivery_payloads"].get(retry_payload_key)
            if not isinstance(record, dict):
                raise PushDispatcherError(
                    "push_retry_payload_missing",
                    "push retry payload is missing before relay target binding",
                    500,
                )
            existing = record.get("relay_target")
            if isinstance(existing, dict) and all(
                str(existing.get(field) or "").strip()
                for field in ("relay_device_id", "mac_install_id", "relay_pair_secret_hash")
            ):
                return dict(existing)
            if not allow_create:
                return {"unbound": True}
            if not all(candidate.values()):
                return {}
            target = {**candidate, "bound_at": self.now_fn()}
            record["relay_target"] = target
            record["updated_at"] = self.now_fn()
            return dict(target)

        return mutate_push_secrets(self.secret_path, bind)

    def _bound_retry_provider_target(
        self,
        *,
        retry_payload_key: str,
        provider: dict[str, Any],
        allow_create: bool,
    ) -> dict[str, Any]:
        mode = str(provider.get("mode") or "").strip()
        candidate = {
            "mode": mode,
            "relay_url": str(provider.get("relay_url") or "").strip() if mode == "relay" else "",
        }

        def bind(current: dict[str, Any]) -> dict[str, Any]:
            record = current["delivery_payloads"].get(retry_payload_key)
            if not isinstance(record, dict):
                raise PushDispatcherError(
                    "push_retry_payload_missing",
                    "push retry payload is missing before provider binding",
                    500,
                )
            existing = record.get("provider_target")
            if isinstance(existing, dict) and str(existing.get("mode") or "").strip():
                return dict(existing)
            if not allow_create:
                return {"unbound": True}
            if not candidate["mode"]:
                return {}
            target = {**candidate, "bound_at": self.now_fn()}
            record["provider_target"] = target
            record["updated_at"] = self.now_fn()
            return dict(target)

        return mutate_push_secrets(self.secret_path, bind)

    @staticmethod
    def _provider_target_conflict(
        *,
        target: dict[str, Any],
        provider: dict[str, Any],
    ) -> str | None:
        if target.get("unbound") is True:
            return "push_retry_provider_unbound"
        target_mode = str(target.get("mode") or "").strip()
        current_mode = str(provider.get("mode") or "").strip()
        if not target_mode:
            return "push_retry_provider_unbound"
        if current_mode != target_mode:
            return "push_retry_provider_changed"
        if target_mode == "relay" and str(provider.get("relay_url") or "").strip() != str(
            target.get("relay_url") or ""
        ).strip():
            return "relay_endpoint_changed"
        return None

    def _align_claimed_outbox_target(
        self,
        *,
        row: dict[str, Any],
        target: dict[str, Any],
        push_type: str,
    ) -> bool:
        """Align a claimed legacy or rotated row without crossing activities."""
        target_hash = str(target.get("token_hash") or "")
        if not target_hash:
            return not row.get("token_hash")
        row_hash = str(row.get("token_hash") or "")
        target_activity_id = str(target.get("activity_id") or "") or None
        row_activity_id = str(row.get("target_activity_id") or "") or None
        if not row_hash:
            row["token_hash"] = target_hash
            if target_activity_id:
                row["target_activity_id"] = target_activity_id
            row["target_bound_at"] = self.now_fn()
            return True
        if hmac.compare_digest(row_hash, target_hash):
            if push_type == "liveactivity" and not row_activity_id and target_activity_id:
                row["target_activity_id"] = target_activity_id
            return True
        if (
            push_type == "liveactivity"
            and row_activity_id
            and target_activity_id
            and row_activity_id == target_activity_id
        ):
            row["retargeted_from_token_hash"] = row_hash
            row["token_hash"] = target_hash
            row["retargeted_at"] = self.now_fn()
            return True
        return False

    def _cleanup_retry_payload_if_terminal(
        self,
        *,
        device_id: str,
        event_id: str,
        push_type: str,
        retry_payload_key: str,
    ) -> bool:
        identity = {
            "device_id": device_id,
            "event_id": event_id,
            "push_type": push_type,
        }

        def is_terminal(data: dict[str, Any]) -> bool:
            row = self._find_outbox(data, **identity)
            return bool(
                row is not None
                and row.get("state") not in OUTBOX_ACTIVE_STATES
                and (not row.get("retry_payload_key") or row.get("retry_payload_key") == retry_payload_key)
            )

        if not self._mutate_registry(is_terminal):
            return False
        self._delete_retry_payload(retry_payload_key)

        def mark_clean(data: dict[str, Any]) -> None:
            row = self._find_outbox(data, **identity)
            if (
                row is not None
                and row.get("state") not in OUTBOX_ACTIVE_STATES
                and (not row.get("retry_payload_key") or row.get("retry_payload_key") == retry_payload_key)
            ):
                row["retry_payload_key"] = retry_payload_key
                row["retry_payload_present"] = False
                self._prune_terminal_outbox(data)

        self._mutate_registry(mark_clean)
        return True

    def _valid_retry_payloads(self) -> dict[str, dict[str, Any]]:
        records = self._read_secrets().get("delivery_payloads", {})
        valid: dict[str, dict[str, Any]] = {}
        invalid: dict[str, Any] = {}
        for key, record in records.items():
            payload_hash_valid = False
            if isinstance(record, dict) and isinstance(record.get("payload"), dict):
                try:
                    encoded = json.dumps(
                        record["payload"],
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    expected_hash = str(record.get("payload_sha256") or "")
                    payload_hash_valid = bool(expected_hash) and hmac.compare_digest(
                        expected_hash,
                        hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
                    )
                except (TypeError, ValueError):
                    payload_hash_valid = False
            if (
                isinstance(key, str)
                and isinstance(record, dict)
                and record.get("contract_version") == OUTBOX_RETRY_PAYLOAD_CONTRACT
                and isinstance(record.get("payload"), dict)
                and record.get("key") == key
                and record.get("push_type") in {"alert", "liveactivity"}
                and payload_hash_valid
                and key == self._retry_payload_key(
                    device_id=str(record.get("device_id") or ""),
                    event_id=str(record.get("event_id") or ""),
                    push_type=str(record.get("push_type") or ""),
                )
            ):
                valid[key] = dict(record)
            elif isinstance(key, str):
                invalid[key] = record
        if invalid:
            def remove_unchanged_invalid(current: dict[str, Any]) -> None:
                for key, expected in invalid.items():
                    if current["delivery_payloads"].get(key) == expected:
                        del current["delivery_payloads"][key]

            mutate_push_secrets(self.secret_path, remove_unchanged_invalid)
        return valid

    def _reconcile_terminal_retry_payloads(self) -> int:
        rows = self._read().get("delivery_outbox", [])
        cleaned = 0
        for row in rows:
            if (
                not isinstance(row, dict)
                or row.get("state") in OUTBOX_ACTIVE_STATES
                or row.get("retry_payload_present") is not True
            ):
                continue
            key = str(row.get("retry_payload_key") or "")
            if not key:
                continue
            if self._cleanup_retry_payload_if_terminal(
                device_id=str(row.get("device_id") or ""),
                event_id=str(row.get("event_id") or ""),
                push_type=str(row.get("push_type") or ""),
                retry_payload_key=key,
            ):
                cleaned += 1
        return cleaned

    def _expire_active_outbox_current(self, data: dict[str, Any], *, now: float | None = None) -> int:
        current = self.now_fn() if now is None else float(now)
        expired = 0
        for row in data.setdefault("delivery_outbox", []):
            if (
                not isinstance(row, dict)
                or row.get("state") not in OUTBOX_ACTIVE_STATES
            ):
                continue
            try:
                created_at = float(row.get("created_at"))
            except (TypeError, ValueError):
                continue
            if current < created_at + OUTBOX_ACTIVE_RETENTION_SECONDS:
                continue
            row["state"] = "dead_letter"
            row["last_outcome"] = (
                "relay_delivery_expired"
                if row.get("provider_mode") == "relay"
                else "credential_delivery_expired"
            )
            row["next_attempt_at"] = None
            row["locked_at"] = None
            row["lock_id"] = None
            row["updated_at"] = current
            expired += 1
        if expired:
            data["updated_at"] = current
            self._prune_terminal_outbox(data)
        return expired

    def _expire_active_deliveries(self) -> tuple[int, int]:
        expired = self._mutate_registry(
            lambda data: self._expire_active_outbox_current(data, now=self.now_fn())
        )
        cleaned = self._reconcile_terminal_retry_payloads() if expired else 0
        return expired, cleaned

    def drain_due_deliveries(self, *, limit: int = OUTBOX_RETRY_DRAIN_LIMIT) -> dict[str, Any]:
        """Replay persisted jobs after restart without holding a file lock during I/O."""
        bounded_limit = max(1, min(int(limit), OUTBOX_RETRY_DRAIN_LIMIT))
        _, cleaned = self._expire_active_deliveries()
        cleaned += self._reconcile_terminal_retry_payloads()
        retry_payloads = self._valid_retry_payloads()

        snapshot = self._read()
        public_identities = {
            (
                str(row.get("device_id") or ""),
                str(row.get("event_id") or ""),
                str(row.get("push_type") or ""),
            )
            for row in snapshot.get("delivery_outbox", [])
            if isinstance(row, dict)
        }
        orphaned = [
            record
            for record in retry_payloads.values()
            if (
                str(record.get("device_id") or ""),
                str(record.get("event_id") or ""),
                str(record.get("push_type") or ""),
            ) not in public_identities
        ][:bounded_limit]

        completed = 0
        errors = 0
        for record in orphaned:
            try:
                self._dispatch_retry_record(record, claimed_lock_id=None)
                completed += 1
            except Exception:
                errors += 1

        remaining = bounded_limit - len(orphaned)
        claims: list[dict[str, Any]] = []
        if remaining > 0:
            retry_payloads = self._valid_retry_payloads()
            claims = self._mutate_registry(
                lambda data: self._claim_due_deliveries_current(
                    data,
                    retry_payloads=retry_payloads,
                    limit=remaining,
                )
            )
            cleaned += self._reconcile_terminal_retry_payloads()
            for claim in claims:
                record = retry_payloads.get(str(claim.get("retry_payload_key") or ""))
                if record is None:
                    continue
                try:
                    self._dispatch_retry_record(record, claimed_lock_id=str(claim["lock_id"]))
                    completed += 1
                except Exception as exc:
                    errors += 1
                    self._complete_claim_exception(claim, exc)

        return {
            "ok": errors == 0,
            "cleaned": cleaned,
            "orphaned": len(orphaned),
            "claimed": len(claims),
            "completed": completed,
            "errors": errors,
        }

    def _claim_due_deliveries_current(
        self,
        data: dict[str, Any],
        *,
        retry_payloads: dict[str, dict[str, Any]],
        limit: int,
    ) -> list[dict[str, Any]]:
        now = self.now_fn()
        self._expire_active_outbox_current(data, now=now)
        claims: list[dict[str, Any]] = []
        for row in data.setdefault("delivery_outbox", []):
            if len(claims) >= limit or not isinstance(row, dict):
                break
            state = str(row.get("state") or "")
            next_attempt_at = row.get("next_attempt_at")
            due = (
                state in {"pending", "credential_blocked"}
                and next_attempt_at is not None
                and float(next_attempt_at) <= now
            )
            stale = (
                state == "sending"
                and float(row.get("locked_at") or 0) <= now - OUTBOX_SENDING_LEASE_SECONDS
            )
            if not due and not stale:
                continue
            key = str(row.get("retry_payload_key") or self._retry_payload_key(
                device_id=str(row.get("device_id") or ""),
                event_id=str(row.get("event_id") or ""),
                push_type=str(row.get("push_type") or ""),
            ))
            if key not in retry_payloads:
                if row.get("retry_payload_present") is True:
                    row["state"] = "dead_letter"
                    row["last_outcome"] = "retry_payload_missing"
                    row["next_attempt_at"] = None
                    row["locked_at"] = None
                    row["lock_id"] = None
                    row["retry_payload_present"] = False
                    row["updated_at"] = now
                continue
            lock_id = uuid.uuid4().hex
            row["state"] = "sending"
            row["attempt_count"] = int(row.get("attempt_count") or 0) + 1
            row["locked_at"] = now
            row["lock_id"] = lock_id
            row["retry_payload_key"] = key
            row["retry_payload_present"] = True
            row["updated_at"] = now
            claims.append({
                "device_id": row.get("device_id"),
                "event_id": row.get("event_id"),
                "push_type": row.get("push_type"),
                "retry_payload_key": key,
                "lock_id": lock_id,
            })
        self._prune_terminal_outbox(data)
        return claims

    def _dispatch_retry_record(self, record: dict[str, Any], *, claimed_lock_id: str | None) -> dict[str, Any]:
        push_type = str(record.get("push_type") or "")
        kwargs = {
            "device_id": str(record.get("device_id") or ""),
            "payload": dict(record.get("payload") or {}),
            "audit_event": str(record.get("audit_event") or "push.event"),
            "default_event_prefix": "push" if push_type == "alert" else "la",
            "claimed_lock_id": claimed_lock_id,
            "retry_record": record,
        }
        if push_type == "alert":
            return self._record_alert_delivery(**kwargs)
        if push_type == "liveactivity":
            return self._record_live_activity_delivery(**kwargs)
        raise PushDispatcherError("push_retry_payload_invalid", "unsupported retry payload type", 500)

    def _retire_legacy_relay_retry(
        self,
        *,
        record: dict[str, Any],
        claimed_lock_id: str | None,
    ) -> dict[str, Any] | None:
        request_version = _bounded_int(
            record.get("request_contract_version"),
            default=0,
            minimum=0,
            maximum=OUTBOX_RETRY_REQUEST_CONTRACT_VERSION,
        )
        if request_version >= OUTBOX_RETRY_REQUEST_CONTRACT_VERSION:
            return None
        device_id = str(record.get("device_id") or "")
        event_id = str(record.get("event_id") or "")
        push_type = str(record.get("push_type") or "")
        audit_event = str(record.get("audit_event") or "push.event")
        retry_payload_key = str(record.get("key") or "")
        provider = self._provider_status()
        snapshot = self._read()
        row = self._find_outbox(
            snapshot,
            device_id=device_id,
            event_id=event_id,
            push_type=push_type,
        )
        provider_mode = str((row or {}).get("provider_mode") or provider.get("mode") or "")
        if provider_mode != "relay":
            return None
        if row is None:
            self._delete_retry_payload(retry_payload_key)
            return {
                "ok": False,
                "delivery": {
                    "event": audit_event,
                    "event_id": event_id,
                    "device_id": device_id,
                    "outcome": "relay_retry_contract_upgraded",
                    "sent": False,
                },
                "provider": provider,
            }

        def retire(data: dict[str, Any]) -> dict[str, Any]:
            current = self._find_outbox(
                data,
                device_id=device_id,
                event_id=event_id,
                push_type=push_type,
            )
            if current is None:
                return {
                    "ok": False,
                    "delivery": {"outcome": "superseded_delivery"},
                    "provider": provider,
                }
            if claimed_lock_id is not None and current.get("lock_id") != claimed_lock_id:
                return self._idempotent_delivery(
                    data,
                    device_id=device_id,
                    event_id=event_id,
                    push_type=push_type,
                    provider=provider,
                    audit_event=audit_event,
                ) or {
                    "ok": False,
                    "delivery": {"outcome": "superseded_delivery"},
                    "provider": provider,
                }
            self._complete_outbox(
                data,
                current,
                sent=False,
                outcome="relay_retry_contract_upgraded",
                delivery_extra={"retryable": False, "invalid_token": False},
            )
            event = {
                "event": audit_event,
                "event_id": event_id,
                "device_id": device_id,
                "sent": False,
                "outcome": "relay_retry_contract_upgraded",
                "provider_mode": "relay",
            }
            self._append_event(data, event)
            return {"ok": False, "delivery": event, "provider": provider}

        response = self._mutate_registry(retire)
        self._cleanup_retry_payload_if_terminal(
            device_id=device_id,
            event_id=event_id,
            push_type=push_type,
            retry_payload_key=retry_payload_key,
        )
        return response

    def _complete_claim_exception(self, claim: dict[str, Any], exc: Exception) -> None:
        def complete(data: dict[str, Any]) -> None:
            row = self._find_outbox(
                data,
                device_id=str(claim.get("device_id") or ""),
                event_id=str(claim.get("event_id") or ""),
                push_type=str(claim.get("push_type") or ""),
            )
            if row is None or row.get("lock_id") != claim.get("lock_id"):
                return
            self._complete_outbox(
                data,
                row,
                sent=False,
                outcome="provider_exception",
                delivery_extra={
                    "provider_error_type": type(exc).__name__,
                    "retryable": True,
                    "invalid_token": False,
                },
            )

        self._mutate_registry(complete)

    def broadcast_alert(
        self,
        *,
        exclude_device_id,
        event_id,
        kind,
        route,
        title,
        body,
        pairling_extra=None,
        exclude_device_ids=None,
    ):
        """Durably enqueue one alert per existing paired device."""
        data = self._read()
        excluded = {
            str(item)
            for item in (exclude_device_ids or [])
            if str(item)
        }
        excluded.add(str(exclude_device_id or ""))
        targets: list[str] = []
        for device in data.get("devices", []):
            device_id = str(device.get("device_id") or "")
            if not device_id or device_id in excluded:
                continue
            targets.append(device_id)

        sent = 0
        errors = 0
        persistence_errors = 0
        enqueued = 0
        extra = dict(pairling_extra) if isinstance(pairling_extra, dict) else {}
        for device_id in targets:
            target_suffix = hashlib.sha256(device_id.encode("utf-8")).hexdigest()[:16]
            target_event_id = f"{str(event_id)[:100]}:{target_suffix}"
            try:
                result = self.record_event(
                    device_id=device_id,
                    payload={
                        **extra,
                        "event_id": target_event_id,
                        "kind": kind,
                        "route": route,
                        "title": title,
                        "body": body,
                        "interruption_level": "time-sensitive",
                    },
                )
                enqueued += 1
                if isinstance(result, dict) and result.get("ok") is True:
                    sent += 1
                else:
                    errors += 1
            except Exception:
                errors += 1
                persistence_errors += 1
        return {
            "sent": sent,
            "errors": errors,
            "enqueued": enqueued,
            "persistence_errors": persistence_errors,
            "targets": len(targets),
        }

    def backfill_live_activity_environments(self, *, device_id: str | None = None) -> dict[str, Any]:
        """Repair older Live Activity token rows that predate explicit APNs environments."""
        secrets_payload = self._read_secrets()

        def backfill_public(data: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
            public_updates = 0
            snapshots = []
            for device in data.get("devices", []):
                current_device_id = str(device.get("device_id") or "")
                if not current_device_id or (device_id and current_device_id != device_id):
                    continue
                secret_device = secrets_payload.get("devices", {}).get(current_device_id, {})
                fallback = _normalize_apns_environment(
                    device.get("apns_environment") or secret_device.get("apns_environment")
                )
                has_live_activity = bool(device.get("live_activities")) or bool(
                    secret_device.get("live_activity_tokens")
                )
                if has_live_activity and not device.get("apns_environment"):
                    device["apns_environment"] = fallback
                    public_updates += 1
                for item in device.get("live_activities") or []:
                    if isinstance(item, dict) and not item.get("apns_environment"):
                        item["apns_environment"] = fallback
                        public_updates += 1
                snapshots.append({
                    "device_id": current_device_id,
                    "apns_environment": device.get("apns_environment") or fallback,
                    "has_live_activity": has_live_activity,
                })
            if public_updates:
                data["updated_at"] = self.now_fn()
            return public_updates, snapshots

        public_updates, public_devices = self._mutate_registry(backfill_public)

        secret_updates = 0

        def backfill_secrets(current: dict[str, Any]) -> None:
            nonlocal secret_updates
            revoked = set(current["revoked_device_ids"])
            for device in public_devices:
                current_device_id = str(device["device_id"])
                if current_device_id in revoked:
                    continue
                secret_device = current["devices"].setdefault(current_device_id, {})
                fallback = _normalize_apns_environment(
                    device.get("apns_environment") or secret_device.get("apns_environment")
                )
                has_live_activity = bool(device.get("has_live_activity")) or bool(
                    secret_device.get("live_activity_tokens")
                )
                if has_live_activity and not secret_device.get("apns_environment"):
                    secret_device["apns_environment"] = fallback
                    secret_updates += 1
                live_tokens = secret_device.get("live_activity_tokens")
                if isinstance(live_tokens, dict):
                    for item in live_tokens.values():
                        if isinstance(item, dict) and not item.get("apns_environment"):
                            item["apns_environment"] = fallback
                            secret_updates += 1

        mutate_push_secrets(self.secret_path, backfill_secrets)
        return {
            "ok": True,
            "public_updates": public_updates,
            "secret_updates": secret_updates,
        }

    def status(self, *, device_id: str | None = None) -> dict[str, Any]:
        payload = self._read()
        devices = payload.get("devices", [])
        try:
            secret_devices = self._read_secrets().get("devices", {})
        except PushDispatcherError:
            secret_devices = {}
        outbox = payload.get("delivery_outbox", [])
        deliveries = payload.get("deliveries", [])
        if device_id:
            devices = [item for item in devices if item.get("device_id") == device_id]
            outbox = [item for item in outbox if item.get("device_id") == device_id]
            deliveries = [item for item in deliveries if item.get("device_id") == device_id]
        return {
            "ok": True,
            "contract_version": CONTRACT_VERSION,
            "provider": self._provider_status(),
            "devices": [
                _public_push_device(
                    item,
                    secret_device=secret_devices.get(str(item.get("device_id") or "")),
                )
                for item in devices
            ],
            "delivery_outbox": outbox[-50:],
            "deliveries": deliveries[-100:],
            "events": payload.get("events", [])[-20:],
            "updated_at": payload.get("updated_at"),
        }

    def health_axis(self, *, device_id: str | None = None) -> dict[str, Any]:
        """The push-plane axis for /health: can this Mac deliver pushes, and
        how did the recent deliveries go?

        Provider health is Mac-wide. Credentials, attempts, and registration
        counts are limited to device_id when an authenticated phone asks.

        Exists because the APNs provider died silently for weeks (credentials
        stripped from re-rendered launchd env, then an FD-exhausted daemon)
        and no surface anywhere could say so. The phone renders a banner from
        this axis, which is the dead-man's switch for the whole class: any
        future cause of dead push delivery becomes visible at the next
        health read instead of never."""
        try:
            provider = self._provider_status()
        except Exception as exc:  # noqa: BLE001 - a broken provider read IS the finding
            return {
                "contract_version": PUSH_HEALTH_CONTRACT_VERSION,
                "provider_configured": False,
                "provider_mode": "unknown",
                "degraded": True,
                "reason": f"provider_status_failed:{type(exc).__name__}",
                "last_delivery_outcome": None,
                "last_delivery_at": None,
                "registered_devices": 0,
            }
        configured = bool(provider.get("configured"))
        data = self._read()
        try:
            secret_devices = self._read_secrets().get("devices", {})
        except PushDispatcherError:
            secret_devices = {}
        devices = [
            device
            for device in data.get("devices", [])
            if isinstance(device, dict)
            and (not device_id or device.get("device_id") == device_id)
        ]
        attempts = [
            event
            for event in data.get("events", [])
            if isinstance(event, dict)
            and isinstance(event.get("sent"), bool)
            and event.get("outcome")
            and event.get("outcome") not in PUSH_HEALTH_NEUTRAL_OUTCOMES
            and (not device_id or event.get("device_id") == device_id)
        ][-10:]
        last = attempts[-1] if attempts else None
        degraded = False
        reason = None
        relay_credentials_missing = (
            provider.get("mode") == "relay"
            and any(
                isinstance(device, dict)
                and (
                    bool(device.get("standard_push_enabled"))
                    or bool(device.get("live_activity_enabled"))
                )
                and (
                    not str(
                        device.get("relay_device_id")
                        or secret_devices.get(str(device.get("device_id") or ""), {}).get("relay_device_id")
                        or ""
                    ).strip()
                    or not str(
                        secret_devices.get(str(device.get("device_id") or ""), {}).get("relay_pair_secret")
                        or ""
                    ).strip()
                    or not str(
                        secret_devices.get(str(device.get("device_id") or ""), {}).get("relay_pair_secret_ref")
                        or ""
                    ).strip()
                    or not str(
                        secret_devices.get(str(device.get("device_id") or ""), {}).get("mac_install_id")
                        or device.get("mac_install_id")
                        or ""
                    ).strip()
                )
                for device in devices
            )
        )
        if not configured:
            degraded = True
            reason = "provider_not_configured"
        elif relay_credentials_missing:
            degraded = True
            reason = "relay_credentials_missing"
        elif last is not None and last.get("outcome") not in PUSH_HEALTH_OK_OUTCOMES:
            degraded = True
            reason = "deliveries_failing"
        registered = [
            device
            for device in devices
            if device.get("apns_token_hash")
        ]
        return {
            "contract_version": PUSH_HEALTH_CONTRACT_VERSION,
            "provider_configured": configured,
            "provider_mode": str(provider.get("mode") or "not_configured"),
            "degraded": degraded,
            "reason": reason,
            "last_delivery_outcome": (last or {}).get("outcome"),
            "last_delivery_at": (last or {}).get("ts"),
            "registered_devices": len(registered),
        }

    def drop_device(self, *, device_id: str, reason: str = "revoked") -> dict[str, Any]:
        """Remove a device's push registration and secrets entirely.

        Pairing revocation makes the tokens permanently undeliverable, but
        the records used to linger: every emit iterated them, stale tokens
        drew apns_410 noise into the audit, and the registry only healed one
        token at a time. Revocation now cascades here, and the boot sweep
        (gc_revoked) heals history."""
        device_id = _nonempty(device_id, "device_id")
        def drop_current(data: dict[str, Any]) -> bool:
            dropped = False

            def revoke_secret(current: dict[str, Any]) -> dict[str, Any]:
                removed_device = current["devices"].pop(device_id, None) is not None
                removed_payloads = [
                    key
                    for key, record in current["delivery_payloads"].items()
                    if isinstance(record, dict) and record.get("device_id") == device_id
                ]
                for key in removed_payloads:
                    del current["delivery_payloads"][key]
                revoked = [
                    item for item in current["revoked_device_ids"]
                    if isinstance(item, str) and item != device_id
                ]
                revoked.append(device_id)
                current["revoked_device_ids"] = revoked[-4096:]
                return {
                    "removed_device": removed_device,
                    "removed_payloads": set(removed_payloads),
                }

            removed = mutate_push_secrets(self.secret_path, revoke_secret)
            if removed["removed_device"] or removed["removed_payloads"]:
                dropped = True
            for row in data.get("delivery_outbox", []):
                if not isinstance(row, dict) or row.get("device_id") != device_id:
                    continue
                if row.get("retry_payload_key") in removed["removed_payloads"]:
                    row["retry_payload_present"] = False
                if row.get("state") in OUTBOX_ACTIVE_STATES:
                    row["state"] = "invalidated"
                    row["last_outcome"] = "device_revoked"
                    row["next_attempt_at"] = None
                    row["locked_at"] = None
                    row["lock_id"] = None
                    row["updated_at"] = self.now_fn()
                    dropped = True
            devices = data.get("devices", [])
            keep = [item for item in devices if item.get("device_id") != device_id]
            if len(keep) != len(devices):
                dropped = True
                data["devices"] = keep
                self._append_event(data, {
                    "event": "push.device.gc",
                    "device_id": device_id,
                    "outcome": "dropped",
                    "reason": reason,
                })
                data["updated_at"] = self.now_fn()
            self._prune_terminal_outbox(data)
            return dropped

        dropped = self._mutate_registry(drop_current)
        return {"ok": True, "device_id": device_id, "dropped": dropped}

    def gc_revoked(self, *, revoked_device_ids: list[str], reason: str = "revoked_sweep") -> dict[str, Any]:
        """Boot-time sweep: drop every push registration whose pairing was
        revoked, including revocations that never passed through the revoke
        endpoint (supersede-on-re-pair)."""
        revoked = {str(item).strip() for item in revoked_device_ids if str(item).strip()}
        if not revoked:
            return {"ok": True, "dropped": []}
        registered = {
            str(item.get("device_id") or "")
            for item in self._read().get("devices", [])
            if isinstance(item, dict)
        }
        dropped = []
        for device_id in sorted(revoked & registered):
            result = self.drop_device(device_id=device_id, reason=reason)
            if result.get("dropped"):
                dropped.append(device_id)
        # Secrets can outlive registry records; sweep them independently.
        def drop_revoked_secrets(current: dict[str, Any]) -> list[str]:
            stale = sorted(revoked & set(current["devices"].keys()))
            for stale_device_id in stale:
                del current["devices"][stale_device_id]
            stale_payloads = [
                key
                for key, record in current["delivery_payloads"].items()
                if isinstance(record, dict) and str(record.get("device_id") or "") in revoked
            ]
            for key in stale_payloads:
                del current["delivery_payloads"][key]
            tombstones = [
                item for item in current["revoked_device_ids"]
                if isinstance(item, str) and item not in revoked
            ]
            tombstones.extend(sorted(revoked))
            current["revoked_device_ids"] = tombstones[-4096:]
            return stale

        for stale_device_id in mutate_push_secrets(self.secret_path, drop_revoked_secrets):
            if stale_device_id not in dropped:
                dropped.append(stale_device_id)
        return {"ok": True, "dropped": dropped}

    def update_preferences(self, *, device_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        provider = self._provider_status()
        return self._mutate_registry(
            lambda data: self._update_preferences_current(
                data=data,
                device_id=device_id,
                payload=payload,
                provider=provider,
            )
        )

    def _update_preferences_current(
        self,
        *,
        data: dict[str, Any],
        device_id: str,
        payload: dict[str, Any],
        provider: dict[str, Any],
    ) -> dict[str, Any]:
        device_id = _nonempty(device_id, "device_id")
        if device_id in self._read_secrets()["revoked_device_ids"]:
            raise PushDispatcherError("push_device_revoked", "push device is revoked", 403)
        device = self._device_record(data, device_id, create=True)
        now = self.now_fn()
        device.setdefault("created_at", now)
        device["last_registered_at"] = now

        relay_device_id = payload.get("relay_device_id")
        if isinstance(relay_device_id, str):
            device["relay_device_id"] = relay_device_id.strip() or None

        mac_install_id = str(payload.get("mac_install_id") or "").strip()
        if mac_install_id:
            device["mac_install_id"] = mac_install_id

        apns_environment = _normalize_apns_environment(payload.get("apns_environment") or device.get("apns_environment"))
        if apns_environment:
            device["apns_environment"] = apns_environment

        apns_token = str(payload.get("apns_token") or "").strip().lower()
        secret_updates: dict[str, Any] = {}
        if apns_token:
            _validate_apns_token(apns_token, "apns_token")
            invalidated_reason = device.get("apns_invalidated_reason")
            device["apns_token_hash"] = _sha256_hex(apns_token)
            device["apns_environment"] = apns_environment
            device["apns_registered_at"] = now
            device.pop("apns_invalidated_at", None)
            device.pop("apns_invalidated_by_event_id", None)
            device.pop("apns_invalidated_reason", None)
            if device.get("last_delivery_error") in {invalidated_reason, "missing_token"}:
                device["last_delivery_error"] = None

            for row in data.get("delivery_outbox", []):
                if (
                    isinstance(row, dict)
                    and row.get("device_id") == device_id
                    and row.get("push_type") == "alert"
                    and row.get("state") == "credential_blocked"
                    and row.get("last_outcome") == "missing_token"
                ):
                    row["state"] = "pending"
                    row["next_attempt_at"] = now
                    row["updated_at"] = now
            secret_updates.update({
                "apns_token": apns_token,
                "apns_token_hash": device["apns_token_hash"],
                "apns_environment": apns_environment,
                "updated_at": now,
            })

        relay_pair_secret = str(payload.get("relay_pair_secret") or "").strip()
        if relay_pair_secret:
            relay_secret_ref = str(payload.get("relay_pair_secret_ref") or _sha256_hex(relay_pair_secret)).strip()
            mac_install_id = str(payload.get("mac_install_id") or device.get("mac_install_id") or os.environ.get("PAIRLING_MAC_INSTALL_ID") or "").strip()
            secret_updates.update({
                "relay_pair_secret": relay_pair_secret,
                "relay_pair_secret_ref": relay_secret_ref,
                "relay_device_id": device.get("relay_device_id"),
                "mac_install_id": mac_install_id,
                "updated_at": now,
            })
            device["relay_pair_secret_ref"] = relay_secret_ref
            if mac_install_id:
                device["mac_install_id"] = mac_install_id

        if secret_updates:
            def update_device_secrets(current: dict[str, Any]) -> None:
                if device_id in current["revoked_device_ids"]:
                    raise PushDispatcherError("push_device_revoked", "push device is revoked", 403)
                secret_device = current["devices"].setdefault(device_id, {})
                secret_device.update(secret_updates)
                if apns_token:
                    secret_device.pop("apns_invalidated_at", None)
                    secret_device.pop("apns_invalidated_reason", None)

            mutate_push_secrets(self.secret_path, update_device_secrets)

        for key in DEFAULT_PREFERENCES:
            if key in payload:
                if key == "quiet_hours":
                    device[key] = _quiet_hours(payload[key])
                elif key == "push_snoozed_until":
                    device[key] = _optional_epoch(payload[key])
                else:
                    device[key] = bool(payload[key])

        data["updated_at"] = now
        self._append_event(data, {
            "event": "push.preferences.updated",
            "device_id": device_id,
            "outcome": "ok",
        })
        return {"ok": True, "device": _public_push_device(device), "provider": provider}

    def record_event(self, *, device_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Record and dispatch a production standard APNs alert event."""
        return self._record_alert_delivery(
            device_id=device_id,
            payload=payload,
            audit_event="push.event",
            default_event_prefix="push",
        )

    def record_test(self, *, device_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._record_alert_delivery(
            device_id=device_id,
            payload=payload,
            audit_event="push.test",
            default_event_prefix="push_test",
        )

    def _record_alert_delivery(
        self,
        *,
        device_id: str,
        payload: dict[str, Any],
        audit_event: str,
        default_event_prefix: str,
        claimed_lock_id: str | None = None,
        retry_record: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        device_id = _nonempty(device_id, "device_id")
        payload = dict(payload)
        event_id = str(payload.get("event_id") or f"{default_event_prefix}_{int(self.now_fn() * 1000)}")[:120]
        payload["event_id"] = event_id
        if retry_record is None:
            self._expire_active_deliveries()
            retry_record = self._persist_retry_payload(
                device_id=device_id,
                event_id=event_id,
                push_type="alert",
                audit_event=audit_event,
                payload=payload,
            )
        retired = self._retire_legacy_relay_retry(
            record=retry_record,
            claimed_lock_id=claimed_lock_id,
        )
        if retired is not None:
            return retired
        retry_payload_key = str(retry_record.get("key") or "")
        payload = dict(retry_record.get("payload") or payload)
        audit_event = str(retry_record.get("audit_event") or audit_event)
        try:
            provider = self._provider_status()
            prepared = self._mutate_registry(
                lambda data: self._prepare_alert_delivery_current(
                    data=data,
                    device_id=device_id,
                    payload=payload,
                    event_id=event_id,
                    audit_event=audit_event,
                    provider=provider,
                    claimed_lock_id=claimed_lock_id,
                    retry_payload_key=retry_payload_key,
                )
            )
            self._reconcile_terminal_retry_payloads()
        except Exception:
            self._delete_retry_payload_if_orphaned(
                device_id=device_id,
                event_id=event_id,
                push_type="alert",
                retry_payload_key=retry_payload_key,
            )
            raise
        if prepared.get("response") is not None:
            response = prepared["response"]
            self._cleanup_retry_payload_if_terminal(
                device_id=device_id,
                event_id=event_id,
                push_type="alert",
                retry_payload_key=retry_payload_key,
            )
            return response

        context = prepared["context"]
        sent = False
        outcome = "not_configured"
        delivery_extra: dict[str, Any] = {}
        try:
            provider_target = self._bound_retry_provider_target(
                retry_payload_key=retry_payload_key,
                provider=provider,
                allow_create=(
                    int(context.get("attempt_count") or 0) <= 1
                    or not str(context.get("last_outcome") or "")
                ),
            )
            provider_conflict = self._provider_target_conflict(
                target=provider_target,
                provider=provider,
            )
            if provider_conflict:
                outcome = provider_conflict
                delivery_extra = {"retryable": False, "invalid_token": False}
            elif context["dispatch_mode"] == "local_apns":
                result = self.apns_sender.send_alert(
                    token=context["token"],
                    event_id=event_id,
                    kind=context["kind"],
                    route=context["route"],
                    title=context["title"],
                    body=context["body"],
                    thread_id=context["thread_id"],
                    pairling_extra=context["pairling_extra"],
                    interruption_level=context["interruption_level"],
                    category=context["category"],
                )
                sent = bool(result.get("sent"))
                outcome = str(result.get("outcome") or ("sent" if sent else "failed"))
                delivery_extra = {key: value for key, value in result.items() if key != "sent"}
            else:
                relay_target = self._bound_retry_relay_target(
                    retry_payload_key=retry_payload_key,
                    device_id=device_id,
                    device=context["device"],
                    allow_create=(
                        int(context.get("attempt_count") or 0) <= 1
                        or not str(context.get("last_outcome") or "")
                    ),
                )
                relay_extra = self._submit_relay_event(
                    device_id=device_id,
                    device=context["device"],
                    event_id=event_id,
                    kind=context["kind"],
                    route=context["route"],
                    push_type="alert",
                    provider_target=provider_target,
                    relay_target=relay_target,
                    extra_body={
                        "title": context["title"],
                        "body": context["body"],
                        "thread_id": context["thread_id"],
                        "interruption_level": context["interruption_level"],
                        "pairling_extra": context["pairling_extra"],
                        "category": context["category"],
                        **context["metadata"],
                    },
                )
                sent = bool(relay_extra.pop("accepted", False))
                outcome = str(relay_extra.pop("outcome", "queued" if sent else "relay_failed"))
                delivery_extra = relay_extra
        except Exception as exc:
            sent = False
            outcome = "provider_exception"
            delivery_extra = {
                "provider_error_type": type(exc).__name__,
                "retryable": True,
                "invalid_token": False,
            }

        response = self._mutate_registry(
            lambda data: self._finish_alert_delivery_current(
                data=data,
                context=context,
                sent=sent,
                outcome=outcome,
                delivery_extra=delivery_extra,
            )
        )
        self._cleanup_retry_payload_if_terminal(
            device_id=device_id,
            event_id=event_id,
            push_type="alert",
            retry_payload_key=retry_payload_key,
        )
        return response

    def _prepare_alert_delivery_current(
        self,
        *,
        data: dict[str, Any],
        device_id: str,
        payload: dict[str, Any],
        event_id: str,
        audit_event: str,
        provider: dict[str, Any],
        claimed_lock_id: str | None,
        retry_payload_key: str,
    ) -> dict[str, Any]:
        secrets_payload = self._read_secrets()
        if device_id in secrets_payload["revoked_device_ids"]:
            raise PushDispatcherError("push_device_revoked", "push device is revoked", 403)
        device = self._device_record(data, device_id, create=True)
        secret = secrets_payload.get("devices", {}).get(device_id, {})
        if not isinstance(secret, dict):
            secret = {}
        source_mac_install_id = str(
            payload.get("mac_install_id")
            or secret.get("mac_install_id")
            or device.get("mac_install_id")
            or os.environ.get("PAIRLING_MAC_INSTALL_ID")
            or ""
        ).strip()
        if source_mac_install_id:
            payload["mac_install_id"] = source_mac_install_id
        kind = str(payload.get("kind") or "push_diagnostic")[:80]
        route = str(payload.get("route") or "pairling://settings/push")[:300]
        context = {
            "audit_event": audit_event,
            "body": str(payload.get("body") or "")[:220] or None,
            "device": dict(device),
            "device_id": device_id,
            "category": (
                "PAIRLING_APPROVAL_DECISION"
                if payload.get("category") == "PAIRLING_APPROVAL_DECISION"
                else KIND_CATEGORY.get(kind, "PAIRLING_PUSH_DIAGNOSTIC")
            ),
            "dispatch_mode": None,
            "event_id": event_id,
            "interruption_level": str(payload.get("interruption_level") or "").strip()[:40] or None,
            "kind": kind,
            "metadata": _outbox_metadata_from_payload(payload, sent_at=self.now_fn()),
            "pairling_extra": _alert_pairling_extra(payload),
            "provider": provider,
            "route": route,
            "thread_id": str(payload.get("thread_id") or "")[:120] or None,
            "title": str(payload.get("title") or "")[:90] or None,
            "token": None,
            "token_hash": secret.get("apns_token_hash") or device.get("apns_token_hash"),
            "retry_payload_key": retry_payload_key,
        }
        outbox_row = self._find_outbox(
            data,
            device_id=device_id,
            event_id=event_id,
            push_type="alert",
        )
        if claimed_lock_id is not None:
            if (
                outbox_row is None
                or outbox_row.get("state") != "sending"
                or outbox_row.get("lock_id") != claimed_lock_id
            ):
                return {
                    "response": self._idempotent_delivery(
                        data,
                        device_id=device_id,
                        event_id=event_id,
                        push_type="alert",
                        provider=provider,
                        audit_event=audit_event,
                    ) or {
                        "ok": False,
                        "delivery": {"outcome": "superseded_delivery"},
                        "provider": provider,
                    }
                }
            context["delivery_lock_id"] = claimed_lock_id
        else:
            idempotent = self._idempotent_delivery(
                data,
                device_id=device_id,
                event_id=event_id,
                push_type="alert",
                provider=provider,
                audit_event=audit_event,
            )
            if idempotent:
                return {"response": idempotent}

        delivery_target = self._bound_retry_delivery_target(
            retry_payload_key=retry_payload_key,
            candidate={
                "token": secret.get("apns_token"),
                "token_hash": secret.get("apns_token_hash") or device.get("apns_token_hash"),
                "activity_id": None,
                "apns_environment": secret.get("apns_environment") or device.get("apns_environment"),
            },
            allow_same_activity_rotation=False,
        )
        if delivery_target:
            context["token"] = delivery_target.get("token")
            context["token_hash"] = delivery_target.get("token_hash")
        if claimed_lock_id is not None and not self._align_claimed_outbox_target(
            row=outbox_row,
            target=delivery_target,
            push_type="alert",
        ):
            return {
                "response": self._finish_alert_delivery_current(
                    data=data,
                    context=context,
                    sent=False,
                    outcome="delivery_target_conflict",
                    delivery_extra={"retryable": False, "invalid_token": False},
                )
            }

        outcome = "not_configured"
        delivery_extra: dict[str, Any] = {}
        if not _alert_enabled_for_device(device, kind):
            outcome = "disabled"
        elif kind != "push_diagnostic" and _future_epoch(device.get("push_snoozed_until"), self.now_fn()):
            outcome = "snoozed"
        elif provider["mode"] == "local_apns" and provider["configured"]:
            if not context["token"]:
                outcome = "missing_token"
            elif _key_environment_mismatch(provider):
                outcome = "key_environment_mismatch"
                delivery_extra = {
                    "provider_environment": _provider_environment(provider),
                    "key_environment": _key_environment(provider),
                    "retryable": False,
                    "invalid_token": False,
                }
            elif _token_environment(
                delivery_target.get("apns_environment")
                or secret.get("apns_environment")
                or device.get("apns_environment")
            ) != _provider_environment(provider):
                outcome = "token_environment_mismatch"
                delivery_extra = {
                    "provider_environment": _provider_environment(provider),
                    "token_environment": _token_environment(
                        delivery_target.get("apns_environment")
                        or secret.get("apns_environment")
                        or device.get("apns_environment")
                    ),
                    "retryable": False,
                    "invalid_token": False,
                }
            else:
                context["dispatch_mode"] = "local_apns"
        elif provider["mode"] == "relay" and provider["configured"]:
            context["dispatch_mode"] = "relay"

        if context["dispatch_mode"] is None:
            return {
                "response": self._finish_alert_delivery_current(
                    data=data,
                    context=context,
                    sent=False,
                    outcome=outcome,
                    delivery_extra=delivery_extra,
                )
            }

        if claimed_lock_id is None:
            outbox_row = self._upsert_outbox(
                data,
                event_id=event_id,
                device_id=device_id,
                push_type="alert",
                route=route,
                kind=kind,
                token_hash=context["token_hash"],
                provider=provider,
                state="sending",
                increment_attempt=True,
                metadata=context["metadata"],
                retry_payload_key=retry_payload_key,
            )
            context["delivery_lock_id"] = outbox_row.get("lock_id")
        else:
            outbox_row["provider_mode"] = provider.get("mode")
            outbox_row["provider_environment"] = provider.get("environment")
            outbox_row["key_environment"] = provider.get("key_environment")
            outbox_row["retry_payload_key"] = retry_payload_key
            outbox_row["retry_payload_present"] = True
        context["attempt_count"] = int(outbox_row.get("attempt_count") or 0)
        context["last_outcome"] = outbox_row.get("last_outcome")
        data["updated_at"] = self.now_fn()
        return {"context": context}

    def _finish_alert_delivery_current(
        self,
        *,
        data: dict[str, Any],
        context: dict[str, Any],
        sent: bool,
        outcome: str,
        delivery_extra: dict[str, Any],
    ) -> dict[str, Any]:
        outbox_row = self._find_outbox(
            data,
            device_id=context["device_id"],
            event_id=context["event_id"],
            push_type="alert",
        )
        expected_lock_id = context.get("delivery_lock_id")
        if expected_lock_id is not None and (
            outbox_row is None or expected_lock_id != outbox_row.get("lock_id")
        ):
            return self._idempotent_delivery(
                data,
                device_id=context["device_id"],
                event_id=context["event_id"],
                push_type="alert",
                provider=context["provider"],
                audit_event=context["audit_event"],
            ) or {"ok": False, "delivery": {"outcome": "superseded_delivery"}, "provider": context["provider"]}
        device = next(
            (
                item for item in data.get("devices", [])
                if isinstance(item, dict) and item.get("device_id") == context["device_id"]
            ),
            None,
        )
        token_is_current = bool(
            device is not None
            and context.get("token_hash")
            and device.get("apns_token_hash") == context.get("token_hash")
        )
        if token_is_current and delivery_extra.get("invalid_token"):
            failed_token_hash = str(context["token_hash"])

            def invalidate_secret(current: dict[str, Any]) -> bool:
                secret = current.get("devices", {}).get(context["device_id"])
                if not isinstance(secret, dict) or secret.get("apns_token_hash") != failed_token_hash:
                    return False
                secret.pop("apns_token", None)
                secret.pop("apns_token_hash", None)
                secret["apns_invalidated_at"] = self.now_fn()
                secret["apns_invalidated_reason"] = outcome
                return True

            if mutate_push_secrets(self.secret_path, invalidate_secret):
                device.pop("apns_token_hash", None)
                device["apns_invalidated_at"] = self.now_fn()
                device["apns_invalidated_by_event_id"] = context["event_id"]
                device["apns_invalidated_reason"] = outcome
        if device is not None and (
            not context.get("token_hash")
            or device.get("apns_token_hash") == context.get("token_hash")
            or token_is_current
        ):
            device["last_delivery_error"] = None if sent else outcome
        if outbox_row is None:
            outbox_row = self._upsert_outbox(
                data,
                event_id=context["event_id"],
                device_id=context["device_id"],
                push_type="alert",
                route=context["route"],
                kind=context["kind"],
                token_hash=context.get("token_hash"),
                provider=context["provider"],
                state=self._state_for_outcome(
                    sent=sent,
                    outcome=outcome,
                    delivery_extra=delivery_extra,
                ),
                increment_attempt=False,
                metadata=context["metadata"],
                retry_payload_key=context.get("retry_payload_key"),
            )
        self._complete_outbox(
            data,
            outbox_row,
            sent=sent,
            outcome=outcome,
            delivery_extra=delivery_extra,
        )
        _refresh_outbox_attempt_freshness(outbox_row)
        event = {
            "event": context["audit_event"],
            "event_id": context["event_id"],
            "device_id": context["device_id"],
            "kind": context["kind"],
            "route": context["route"],
            "sent": sent,
            "outcome": outcome,
            "provider_mode": context["provider"]["mode"],
            "provider_environment": context["provider"].get("environment"),
            **delivery_extra,
        }
        self._append_event(data, event)
        data["updated_at"] = self.now_fn()
        return {"ok": sent, "delivery": event, "provider": context["provider"]}

    def record_live_activity_token(self, *, device_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        provider = self._provider_status()
        return self._mutate_registry(
            lambda data: self._record_live_activity_token_current(
                data=data,
                device_id=device_id,
                payload=payload,
                provider=provider,
            )
        )

    def _record_live_activity_token_current(
        self,
        *,
        data: dict[str, Any],
        device_id: str,
        payload: dict[str, Any],
        provider: dict[str, Any],
    ) -> dict[str, Any]:
        device_id = _nonempty(device_id, "device_id")
        if device_id in self._read_secrets()["revoked_device_ids"]:
            raise PushDispatcherError("push_device_revoked", "push device is revoked", 403)
        token = _nonempty(str(payload.get("live_activity_token") or ""), "live_activity_token").lower()
        _validate_apns_token(token, "live_activity_token")
        session_id = _nonempty(str(payload.get("session_id") or ""), "session_id")[:120]
        activity_id = str(payload.get("activity_id") or "")[:160] or None
        apns_environment = _normalize_apns_environment(payload.get("apns_environment"))
        now = self.now_fn()
        device = self._device_record(data, device_id, create=True)
        if not apns_environment:
            apns_environment = _normalize_apns_environment(device.get("apns_environment"))
        device["apns_environment"] = apns_environment
        token_hash = _sha256_hex(token)
        activities = device.setdefault("live_activities", [])
        for item in activities:
            if (
                isinstance(item, dict)
                and item.get("session_id") == session_id
                and not item.get("invalidated_at")
            ):
                item["invalidated_at"] = now
                item["invalidated_reason"] = "superseded"
        activities.append({
            "session_id": session_id,
            "activity_id": activity_id,
            "token_hash": token_hash,
            "apns_environment": apns_environment,
            "registered_at": now,
            "invalidated_at": None,
        })
        del activities[:-20]

        def register_live_token(current: dict[str, Any]) -> None:
            if device_id in current["revoked_device_ids"]:
                raise PushDispatcherError("push_device_revoked", "push device is revoked", 403)
            secret_device = current["devices"].setdefault(device_id, {})
            live_tokens = secret_device.setdefault("live_activity_tokens", {})
            live_tokens[session_id] = {
                "token": token,
                "token_hash": token_hash,
                "activity_id": activity_id,
                "apns_environment": apns_environment,
                "updated_at": now,
            }

        mutate_push_secrets(self.secret_path, register_live_token)
        self._append_event(data, {
            "event": "push.live_activity_token.registered",
            "device_id": device_id,
            "session_id": session_id,
            "activity_id": activity_id,
            "token_hash": token_hash,
            "outcome": "ok",
        })
        data["updated_at"] = now
        return {"ok": True, "device": device, "provider": provider}

    def record_live_activity_event(self, *, device_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Record and dispatch a bounded production Live Activity update/end event."""
        return self._record_live_activity_delivery(
            device_id=device_id,
            payload=payload,
            audit_event="push.live_activity_event",
            default_event_prefix="la",
        )

    def record_live_activity_test(self, *, device_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._record_live_activity_delivery(
            device_id=device_id,
            payload=payload,
            audit_event="push.live_activity_test",
            default_event_prefix="la_test",
        )

    def _record_live_activity_delivery(
        self,
        *,
        device_id: str,
        payload: dict[str, Any],
        audit_event: str,
        default_event_prefix: str,
        claimed_lock_id: str | None = None,
        retry_record: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        device_id = _nonempty(device_id, "device_id")
        payload = dict(payload)
        self.backfill_live_activity_environments(device_id=device_id)
        session_id = _nonempty(str(payload.get("session_id") or ""), "session_id")[:120]
        activity_event = str(payload.get("event") or "update").strip()
        if activity_event not in {"update", "end"}:
            raise PushDispatcherError("invalid_live_activity_event", "event must be update or end")
        event_id = str(payload.get("event_id") or f"{default_event_prefix}_{int(self.now_fn() * 1000)}")[:120]
        payload["event_id"] = event_id
        if retry_record is None:
            self._expire_active_deliveries()
            retry_record = self._persist_retry_payload(
                device_id=device_id,
                event_id=event_id,
                push_type="liveactivity",
                audit_event=audit_event,
                payload=payload,
            )
        retired = self._retire_legacy_relay_retry(
            record=retry_record,
            claimed_lock_id=claimed_lock_id,
        )
        if retired is not None:
            return retired
        retry_payload_key = str(retry_record.get("key") or "")
        payload = dict(retry_record.get("payload") or payload)
        audit_event = str(retry_record.get("audit_event") or audit_event)
        session_id = _nonempty(str(payload.get("session_id") or ""), "session_id")[:120]
        activity_event = str(payload.get("event") or "update").strip()
        if activity_event not in {"update", "end"}:
            raise PushDispatcherError("invalid_live_activity_event", "event must be update or end")
        try:
            provider = self._provider_status()
            content_state = _live_activity_content_state(
                payload,
                activity_event=activity_event,
                event_id=event_id,
                now=int(self.now_fn()),
            )
            bounded_content_state = _bounded_content_state(content_state, event_id=event_id, now=int(self.now_fn()))
            prepared = self._mutate_registry(
                lambda data: self._prepare_live_activity_delivery_current(
                    data=data,
                    device_id=device_id,
                    payload=dict(payload),
                    session_id=session_id,
                    activity_event=activity_event,
                    event_id=event_id,
                    audit_event=audit_event,
                    provider=provider,
                    content_state=content_state,
                    bounded_content_state=bounded_content_state,
                    claimed_lock_id=claimed_lock_id,
                    retry_payload_key=retry_payload_key,
                )
            )
            self._reconcile_terminal_retry_payloads()
        except Exception:
            self._delete_retry_payload_if_orphaned(
                device_id=device_id,
                event_id=event_id,
                push_type="liveactivity",
                retry_payload_key=retry_payload_key,
            )
            raise
        if prepared.get("response") is not None:
            response = prepared["response"]
            self._cleanup_retry_payload_if_terminal(
                device_id=device_id,
                event_id=event_id,
                push_type="liveactivity",
                retry_payload_key=retry_payload_key,
            )
            return response

        context = prepared["context"]
        sent = False
        outcome = "not_configured"
        delivery_extra: dict[str, Any] = {}
        try:
            provider_target = self._bound_retry_provider_target(
                retry_payload_key=retry_payload_key,
                provider=provider,
                allow_create=(
                    int(context.get("attempt_count") or 0) <= 1
                    or not str(context.get("last_outcome") or "")
                ),
            )
            provider_conflict = self._provider_target_conflict(
                target=provider_target,
                provider=provider,
            )
            if provider_conflict:
                outcome = provider_conflict
                delivery_extra = {"retryable": False, "invalid_token": False}
            elif context["dispatch_mode"] == "local_apns":
                result = self.apns_sender.send_live_activity(
                    token=context["token"],
                    event_id=event_id,
                    event=activity_event,
                    content_state=content_state,
                    stale_seconds=int(payload.get("stale_seconds") or 75),
                    dismissal_seconds=int(payload.get("dismissal_seconds") or 300),
                )
                sent = bool(result.get("sent"))
                outcome = str(result.get("outcome") or ("sent" if sent else "failed"))
                delivery_extra = {key: value for key, value in result.items() if key != "sent"}
            else:
                relay_target = self._bound_retry_relay_target(
                    retry_payload_key=retry_payload_key,
                    device_id=device_id,
                    device=context["device"],
                    allow_create=(
                        int(context.get("attempt_count") or 0) <= 1
                        or not str(context.get("last_outcome") or "")
                    ),
                )
                relay_extra = self._submit_relay_event(
                    device_id=device_id,
                    device=context["device"],
                    event_id=event_id,
                    kind=context["kind"],
                    route=context["route"],
                    push_type="liveactivity",
                    provider_target=provider_target,
                    relay_target=relay_target,
                    extra_body={
                        "session_id": session_id,
                        "activity_event": activity_event,
                        "content_state": bounded_content_state,
                        "stale_seconds": _bounded_int(
                            payload.get("stale_seconds"),
                            default=75,
                            minimum=30,
                            maximum=3600,
                        ),
                        "dismissal_seconds": _bounded_int(
                            payload.get("dismissal_seconds"),
                            default=300,
                            minimum=0,
                            maximum=86400,
                        ),
                        **context["metadata"],
                    },
                )
                sent = bool(relay_extra.pop("accepted", False))
                outcome = str(relay_extra.pop("outcome", "queued" if sent else "relay_failed"))
                delivery_extra = relay_extra
        except Exception as exc:
            sent = False
            outcome = "provider_exception"
            delivery_extra = {
                "provider_error_type": type(exc).__name__,
                "retryable": True,
                "invalid_token": False,
            }

        response = self._mutate_registry(
            lambda data: self._finish_live_activity_delivery_current(
                data=data,
                context=context,
                sent=sent,
                outcome=outcome,
                delivery_extra=delivery_extra,
            )
        )
        self._cleanup_retry_payload_if_terminal(
            device_id=device_id,
            event_id=event_id,
            push_type="liveactivity",
            retry_payload_key=retry_payload_key,
        )
        return response

    def _prepare_live_activity_delivery_current(
        self,
        *,
        data: dict[str, Any],
        device_id: str,
        payload: dict[str, Any],
        session_id: str,
        activity_event: str,
        event_id: str,
        audit_event: str,
        provider: dict[str, Any],
        content_state: dict[str, Any],
        bounded_content_state: dict[str, Any],
        claimed_lock_id: str | None,
        retry_payload_key: str,
    ) -> dict[str, Any]:
        secrets_payload = self._read_secrets()
        if device_id in secrets_payload["revoked_device_ids"]:
            raise PushDispatcherError("push_device_revoked", "push device is revoked", 403)
        outbox_row = self._find_outbox(
            data,
            device_id=device_id,
            event_id=event_id,
            push_type="liveactivity",
        )
        if claimed_lock_id is not None:
            if (
                outbox_row is None
                or outbox_row.get("state") != "sending"
                or outbox_row.get("lock_id") != claimed_lock_id
            ):
                return {
                    "response": self._idempotent_delivery(
                        data,
                        device_id=device_id,
                        event_id=event_id,
                        push_type="liveactivity",
                        provider=provider,
                        audit_event=audit_event,
                    ) or {
                        "ok": False,
                        "delivery": {"outcome": "superseded_delivery"},
                        "provider": provider,
                    }
                }
        else:
            idempotent = self._idempotent_delivery(
                data,
                device_id=device_id,
                event_id=event_id,
                push_type="liveactivity",
                provider=provider,
                audit_event=audit_event,
            )
            if idempotent:
                return {"response": idempotent}

        device = self._device_record(data, device_id, create=True)
        secret_device = secrets_payload.get("devices", {}).get(device_id, {})
        token_record = (
            secret_device.get("live_activity_tokens", {}).get(session_id)
            if isinstance(secret_device, dict)
            else None
        )
        if not isinstance(token_record, dict):
            token_record = {}
        route = "pairling://session/" + session_id
        kind = "live_activity_" + activity_event
        context = {
            "activity_event": activity_event,
            "audit_event": audit_event,
            "content_state": content_state,
            "device": dict(device),
            "device_id": device_id,
            "dispatch_mode": None,
            "event_id": event_id,
            "kind": kind,
            "metadata": _live_activity_outbox_metadata(
                payload,
                content_state=bounded_content_state,
                sent_at=float(self.now_fn()),
            ),
            "payload": payload,
            "provider": provider,
            "route": route,
            "session_id": session_id,
            "token": token_record.get("token"),
            "token_hash": token_record.get("token_hash"),
            "retry_payload_key": retry_payload_key,
        }
        delivery_target = self._bound_retry_delivery_target(
            retry_payload_key=retry_payload_key,
            candidate={
                "token": token_record.get("token"),
                "token_hash": token_record.get("token_hash"),
                "activity_id": token_record.get("activity_id"),
                "apns_environment": token_record.get("apns_environment"),
            },
            allow_same_activity_rotation=True,
        )
        if delivery_target:
            context["token"] = delivery_target.get("token")
            context["token_hash"] = delivery_target.get("token_hash")
            context["target_activity_id"] = delivery_target.get("activity_id")
        else:
            context["target_activity_id"] = token_record.get("activity_id")
        if claimed_lock_id is not None:
            context["delivery_lock_id"] = claimed_lock_id
            if not self._align_claimed_outbox_target(
                row=outbox_row,
                target=delivery_target,
                push_type="liveactivity",
            ):
                return {
                    "response": self._finish_live_activity_delivery_current(
                        data=data,
                        context=context,
                        sent=False,
                        outcome="delivery_target_conflict",
                        delivery_extra={"retryable": False, "invalid_token": False},
                    )
                }
        outcome = "not_configured"
        delivery_extra: dict[str, Any] = {}
        if not device.get("live_activity_enabled"):
            outcome = "disabled"
        elif provider["mode"] == "local_apns" and provider["configured"]:
            if not context["token"]:
                outcome = "missing_live_activity_token"
            elif _key_environment_mismatch(provider):
                outcome = "key_environment_mismatch"
                delivery_extra = {
                    "provider_environment": _provider_environment(provider),
                    "key_environment": _key_environment(provider),
                    "retryable": False,
                    "invalid_token": False,
                }
            elif _token_environment(
                delivery_target.get("apns_environment") or token_record.get("apns_environment")
            ) != _provider_environment(provider):
                outcome = "token_environment_mismatch"
                delivery_extra = {
                    "provider_environment": _provider_environment(provider),
                    "token_environment": _token_environment(
                        delivery_target.get("apns_environment") or token_record.get("apns_environment")
                    ),
                    "retryable": False,
                    "invalid_token": False,
                }
            else:
                context["dispatch_mode"] = "local_apns"
        elif provider["mode"] == "relay" and provider["configured"]:
            context["dispatch_mode"] = "relay"

        if context["dispatch_mode"] is None:
            return {
                "response": self._finish_live_activity_delivery_current(
                    data=data,
                    context=context,
                    sent=False,
                    outcome=outcome,
                    delivery_extra=delivery_extra,
                )
            }

        if claimed_lock_id is None:
            outbox_row = self._upsert_outbox(
                data,
                event_id=event_id,
                device_id=device_id,
                push_type="liveactivity",
                route=route,
                kind=kind,
                token_hash=context.get("token_hash"),
                provider=provider,
                state="sending",
                increment_attempt=True,
                metadata=context["metadata"],
                retry_payload_key=retry_payload_key,
                target_activity_id=context.get("target_activity_id"),
            )
            context["delivery_lock_id"] = outbox_row.get("lock_id")
        else:
            outbox_row["provider_mode"] = provider.get("mode")
            outbox_row["provider_environment"] = provider.get("environment")
            outbox_row["key_environment"] = provider.get("key_environment")
            outbox_row["retry_payload_key"] = retry_payload_key
            outbox_row["retry_payload_present"] = True
        context["attempt_count"] = int(outbox_row.get("attempt_count") or 0)
        context["last_outcome"] = outbox_row.get("last_outcome")
        data["updated_at"] = self.now_fn()
        return {"context": context}

    def _finish_live_activity_delivery_current(
        self,
        *,
        data: dict[str, Any],
        context: dict[str, Any],
        sent: bool,
        outcome: str,
        delivery_extra: dict[str, Any],
    ) -> dict[str, Any]:
        outbox_row = self._find_outbox(
            data,
            device_id=context["device_id"],
            event_id=context["event_id"],
            push_type="liveactivity",
        )
        expected_lock_id = context.get("delivery_lock_id")
        if expected_lock_id is not None and (
            outbox_row is None or expected_lock_id != outbox_row.get("lock_id")
        ):
            return self._idempotent_delivery(
                data,
                device_id=context["device_id"],
                event_id=context["event_id"],
                push_type="liveactivity",
                provider=context["provider"],
                audit_event=context["audit_event"],
            ) or {"ok": False, "delivery": {"outcome": "superseded_delivery"}, "provider": context["provider"]}
        device = next(
            (
                item for item in data.get("devices", [])
                if isinstance(item, dict) and item.get("device_id") == context["device_id"]
            ),
            None,
        )
        secrets_payload = self._read_secrets()
        secret_device = secrets_payload.get("devices", {}).get(context["device_id"], {})
        current_token_record = (
            secret_device.get("live_activity_tokens", {}).get(context["session_id"])
            if isinstance(secret_device, dict)
            else None
        )
        current_token_hash = (
            current_token_record.get("token_hash")
            if isinstance(current_token_record, dict)
            else None
        )
        token_is_current = (
            not context.get("token_hash")
            or current_token_hash == context.get("token_hash")
        )
        retirement_reason = None
        if delivery_extra.get("invalid_token"):
            retirement_reason = outcome
        elif sent and context.get("activity_event") == "end":
            retirement_reason = "ended"
        retired_token_hash = str(context.get("token_hash") or "")
        if retirement_reason and retired_token_hash:
            self._remove_live_activity_secret_if_hash(
                device_id=context["device_id"],
                session_id=context["session_id"],
                token_hash=retired_token_hash,
            )
        if device is not None:
            if token_is_current:
                device["last_delivery_error"] = None if sent else outcome
            if retirement_reason and retired_token_hash:
                self._mark_live_activity_invalid(
                    device,
                    context["session_id"],
                    context["event_id"],
                    retirement_reason,
                    token_hash=retired_token_hash,
                )
        if outbox_row is None:
            outbox_row = self._upsert_outbox(
                data,
                event_id=context["event_id"],
                device_id=context["device_id"],
                push_type="liveactivity",
                route=context["route"],
                kind=context["kind"],
                token_hash=context.get("token_hash"),
                provider=context["provider"],
                state=self._state_for_outcome(
                    sent=sent,
                    outcome=outcome,
                    delivery_extra=delivery_extra,
                ),
                increment_attempt=False,
                metadata=context["metadata"],
                retry_payload_key=context.get("retry_payload_key"),
                target_activity_id=context.get("target_activity_id"),
            )
        self._complete_outbox(
            data,
            outbox_row,
            sent=sent,
            outcome=outcome,
            delivery_extra=delivery_extra,
        )
        completed_at = float(self.now_fn())
        _apply_outbox_metadata(
            outbox_row,
            _live_activity_outbox_metadata(
                context["payload"],
                content_state=context["content_state"],
                sent_at=completed_at,
                apns_outcome=outcome,
            ),
        )
        outbox_row["sent_at"] = completed_at
        _refresh_outbox_attempt_freshness(outbox_row)
        event = {
            "event": context["audit_event"],
            "event_id": context["event_id"],
            "device_id": context["device_id"],
            "session_id": context["session_id"],
            "activity_event": context["activity_event"],
            "sent": sent,
            "outcome": outcome,
            "provider_mode": context["provider"]["mode"],
            "provider_environment": context["provider"].get("environment"),
            **delivery_extra,
        }
        self._append_event(data, event)
        data["updated_at"] = self.now_fn()
        return {"ok": sent, "delivery": event, "provider": context["provider"]}

    def _idempotent_delivery(
        self,
        data: dict[str, Any],
        *,
        device_id: str,
        event_id: str,
        push_type: str,
        provider: dict[str, Any],
        audit_event: str | None = None,
    ) -> dict[str, Any] | None:
        self._expire_active_outbox_current(data, now=self.now_fn())
        row = self._find_outbox(
            data,
            device_id=device_id,
            event_id=event_id,
            push_type=push_type,
        )
        if not row:
            return None
        state = row.get("state")
        next_attempt_at = row.get("next_attempt_at")
        if (
            state in {"pending", "credential_blocked"}
            and next_attempt_at is not None
            and float(next_attempt_at) <= self.now_fn()
        ):
            return None
        if state == "sending":
            locked_at = float(row.get("locked_at") or 0)
            if locked_at <= self.now_fn() - OUTBOX_SENDING_LEASE_SECONDS:
                return None
        delivery = self._latest_delivery(
            data,
            device_id=device_id,
            event_id=event_id,
            push_type=push_type,
        ) or {}
        response = {
            **delivery,
            "event": audit_event or ("push.live_activity_test" if push_type == "liveactivity" else "push.test"),
            "event_id": event_id,
            "device_id": row.get("device_id"),
            "sent": state == "sent",
            "outcome": row.get("last_outcome") or delivery.get("outcome") or state,
            "provider_mode": row.get("provider_mode"),
            "provider_environment": row.get("provider_environment"),
            "idempotent": True,
        }
        return {"ok": state == "sent", "delivery": response, "provider": provider}

    def _find_outbox(
        self,
        data: dict[str, Any],
        *,
        device_id: str,
        event_id: str,
        push_type: str,
    ) -> dict[str, Any] | None:
        for item in data.setdefault("delivery_outbox", []):
            if (
                item.get("device_id") == device_id
                and item.get("event_id") == event_id
                and item.get("push_type") == push_type
            ):
                return item
        return None

    def _latest_delivery(
        self,
        data: dict[str, Any],
        *,
        device_id: str,
        event_id: str,
        push_type: str,
    ) -> dict[str, Any] | None:
        for item in reversed(data.setdefault("deliveries", [])):
            if (
                item.get("device_id") == device_id
                and item.get("event_id") == event_id
                and item.get("push_type") == push_type
            ):
                return item
        return None

    def _upsert_outbox(
        self,
        data: dict[str, Any],
        *,
        event_id: str,
        device_id: str,
        push_type: str,
        route: str,
        kind: str,
        token_hash: str | None,
        provider: dict[str, Any],
        state: str,
        increment_attempt: bool,
        metadata: dict[str, Any] | None = None,
        retry_payload_key: str | None = None,
        target_activity_id: str | None = None,
    ) -> dict[str, Any]:
        now = self.now_fn()
        self._expire_active_outbox_current(data, now=now)
        row = self._find_outbox(
            data,
            device_id=device_id,
            event_id=event_id,
            push_type=push_type,
        )
        if row is None:
            active_rows = [
                item
                for item in data.setdefault("delivery_outbox", [])
                if isinstance(item, dict) and item.get("state") in OUTBOX_ACTIVE_STATES
            ]
            active_for_device = sum(
                1 for item in active_rows if item.get("device_id") == device_id
            )
            if (
                len(active_rows) >= OUTBOX_ACTIVE_GLOBAL_LIMIT
                or active_for_device >= OUTBOX_ACTIVE_DEVICE_LIMIT
            ):
                raise PushDispatcherError(
                    "push_outbox_capacity",
                    "push delivery outbox is at capacity; retry after existing deliveries settle",
                    503,
                )
            row = {
                "event_id": event_id,
                "device_id": device_id,
                "push_type": push_type,
                "kind": kind,
                "route": route,
                "token_hash": token_hash,
                "target_activity_id": target_activity_id,
                "state": "pending",
                "next_attempt_at": now,
                "attempt_count": 0,
                "created_at": now,
                "updated_at": now,
                "provider_mode": provider.get("mode"),
                "provider_environment": provider.get("environment"),
                "key_environment": provider.get("key_environment"),
                "last_outcome": None,
            }
            data.setdefault("delivery_outbox", []).append(row)
        row["state"] = state
        row["updated_at"] = now
        row["token_hash"] = token_hash or row.get("token_hash")
        if target_activity_id and not row.get("target_activity_id"):
            row["target_activity_id"] = target_activity_id
        row["provider_mode"] = provider.get("mode")
        row["provider_environment"] = provider.get("environment")
        row["key_environment"] = provider.get("key_environment")
        if retry_payload_key:
            row["retry_payload_key"] = retry_payload_key
            row["retry_payload_present"] = True
        if metadata:
            for key in [
                "source",
                "phase",
                "project",
                "observed_at",
                "sent_at",
                "collapse_id",
                "freshness_seconds_at_send",
                "content_state_hash",
                "apns_outcome",
            ]:
                if key in metadata:
                    row[key] = metadata[key]
        if increment_attempt:
            row["attempt_count"] = int(row.get("attempt_count") or 0) + 1
            row["locked_at"] = now
            row["lock_id"] = uuid.uuid4().hex
        self._prune_terminal_outbox(data)
        return row

    def _prune_terminal_outbox(self, data: dict[str, Any]) -> None:
        rows = data.setdefault("delivery_outbox", [])
        excess = len(rows) - OUTBOX_TERMINAL_LIMIT
        if excess <= 0:
            return
        removable = {
            index
            for index, row in enumerate(rows)
            if (
                isinstance(row, dict)
                and row.get("state") not in OUTBOX_ACTIVE_STATES
                and row.get("retry_payload_present") is not True
            )
        }
        if not removable:
            return
        remove_count = min(excess, len(removable))
        removed = 0
        kept: list[Any] = []
        for index, row in enumerate(rows):
            if index in removable and removed < remove_count:
                removed += 1
                continue
            kept.append(row)
        data["delivery_outbox"] = kept

    def _complete_outbox(
        self,
        data: dict[str, Any],
        row: dict[str, Any],
        *,
        sent: bool,
        outcome: str,
        delivery_extra: dict[str, Any],
    ) -> None:
        attempt_count = int(row.get("attempt_count") or 0)
        state = self._state_for_outcome(
            sent=sent,
            outcome=outcome,
            delivery_extra={
                **delivery_extra,
                "attempt_count": attempt_count,
                "created_at": row.get("created_at"),
                "provider_mode": row.get("provider_mode"),
            },
        )
        now = self.now_fn()
        row["state"] = state
        row["updated_at"] = now
        row["last_outcome"] = outcome
        row["locked_at"] = None
        row["lock_id"] = None
        row["sent_at"] = now
        row["apns_outcome"] = outcome
        retryable = bool(delivery_extra.get("retryable"))
        if state in {"pending", "credential_blocked"} and retryable:
            exponent = min(5, max(0, attempt_count - 1))
            retry_after = delivery_extra.get("retry_after_seconds")
            delay = min(300, 15 * (2 ** exponent))
            if isinstance(retry_after, (int, float)) and retry_after > 0:
                delay = min(3600, float(retry_after))
            row["next_attempt_at"] = now + delay
        elif state == "dead_letter":
            row["next_attempt_at"] = None
        elif state != "pending":
            row["next_attempt_at"] = None
        final_outcome = (
            "waiting_for_relay_credentials"
            if state == "credential_blocked"
            else "retry_scheduled" if state == "pending" and retryable else outcome
        )
        data.setdefault("deliveries", []).append({
            "event_id": row.get("event_id"),
            "device_id": row.get("device_id"),
            "push_type": row.get("push_type"),
            "token_hash": row.get("token_hash"),
            "attempt_count": row.get("attempt_count") or 0,
            "state": state,
            "outcome": outcome,
            "final_outcome": final_outcome,
            "apns_id": delivery_extra.get("apns_id"),
            "apns_status": delivery_extra.get("apns_status"),
            "apns_reason": delivery_extra.get("apns_reason"),
            "apns_outcome": outcome,
            "retryable": retryable,
            "invalid_token": bool(delivery_extra.get("invalid_token")),
            "ts": now,
        })
        del data.setdefault("deliveries", [])[:-300]
        self._prune_terminal_outbox(data)

    def _state_for_outcome(self, *, sent: bool, outcome: str, delivery_extra: dict[str, Any]) -> str:
        if sent:
            return "sent"
        if delivery_extra.get("invalid_token"):
            return "invalidated"
        if outcome == "credential_blocked":
            if delivery_extra.get("provider_mode") == "relay":
                created_at = float(delivery_extra.get("created_at") or self.now_fn())
                if self.now_fn() >= created_at + OUTBOX_ACTIVE_RETENTION_SECONDS:
                    return "dead_letter"
            return "credential_blocked"
        if outcome in RELAY_NONTERMINAL_STATES:
            created_at = float(delivery_extra.get("created_at") or self.now_fn())
            if self.now_fn() < created_at + OUTBOX_ACTIVE_RETENTION_SECONDS:
                return "pending"
            return "dead_letter"
        if delivery_extra.get("retryable"):
            return "dead_letter" if int(delivery_extra.get("attempt_count") or 0) >= 3 else "pending"
        if outcome in {"disabled", "snoozed"}:
            return "suppressed"
        if outcome in {
            "not_configured",
            "missing_token",
            "missing_live_activity_token",
            "key_environment_mismatch",
            "token_environment_mismatch",
            "relay_pair_secret_missing",
            "relay_url_missing",
        }:
            return "credential_blocked"
        return "dead_letter"

    def _provider_status(self) -> dict[str, Any]:
        return self.apns_sender.status()

    def _submit_relay_event(
        self,
        *,
        device_id: str,
        device: dict[str, Any],
        event_id: str,
        kind: str,
        route: str,
        push_type: str,
        provider_target: dict[str, Any],
        relay_target: dict[str, Any],
        extra_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if relay_target.get("unbound") is True:
            return {
                "accepted": False,
                "outcome": "relay_retry_identity_unbound",
                "retryable": False,
                "invalid_token": False,
            }
        secret = self._secret_for_device(device_id)
        relay_pair_secret = str(secret.get("relay_pair_secret") or "").strip()
        current_relay_device_id = str(
            device.get("relay_device_id") or secret.get("relay_device_id") or ""
        ).strip()
        current_mac_install_id = str(
            secret.get("mac_install_id")
            or device.get("mac_install_id")
            or os.environ.get("PAIRLING_MAC_INSTALL_ID")
            or ""
        ).strip()
        relay_device_id = str(relay_target.get("relay_device_id") or "").strip()
        mac_install_id = str(relay_target.get("mac_install_id") or "").strip()
        expected_secret_hash = str(relay_target.get("relay_pair_secret_hash") or "").strip()
        if not relay_pair_secret or not relay_device_id or not mac_install_id or not expected_secret_hash:
            return {
                "accepted": False,
                "outcome": "relay_pair_secret_missing",
                "retryable": False,
                "invalid_token": False,
            }
        if (
            current_relay_device_id != relay_device_id
            or current_mac_install_id != mac_install_id
            or not hmac.compare_digest(_sha256_hex(relay_pair_secret), expected_secret_hash)
        ):
            return {
                "accepted": False,
                "outcome": "relay_identity_changed",
                "retryable": False,
                "invalid_token": False,
            }
        body: dict[str, Any] = {
            "relay_device_id": relay_device_id,
            "mac_install_id": mac_install_id,
            "event_id": event_id,
            "kind": kind,
            "severity": "warning" if kind in {
                "session_attention",
                "worker_sentinel",
                "mac_health",
                "action_required",
                "turn_failed",
                "tool_risk",
                "mac_route_risk",
                "worker_pressure",
            } else "info",
            "route": route,
            "dedupe_key": _thread_id(kind, route),
            "push_type": push_type,
        }
        if extra_body:
            body.update(extra_body)
        relay_url = str(provider_target.get("relay_url") or "").strip()
        if not relay_url:
            return {
                "accepted": False,
                "outcome": "relay_url_missing",
                "retryable": False,
                "invalid_token": False,
            }
        return self.relay_sender.submit_event(
            relay_url=relay_url,
            relay_pair_secret=relay_pair_secret,
            event_body=body,
        )

    def _device_record(self, data: dict[str, Any], device_id: str, *, create: bool) -> dict[str, Any]:
        devices = data.setdefault("devices", [])
        for item in devices:
            if item.get("device_id") == device_id:
                for key, value in DEFAULT_PREFERENCES.items():
                    item.setdefault(key, value)
                item.setdefault("relay_device_id", None)
                item.setdefault("last_delivery_error", None)
                return item
        if not create:
            raise PushDispatcherError("push_device_not_found", "push device is not registered", 404)
        item = {
            "device_id": device_id,
            "relay_device_id": None,
            "last_registered_at": self.now_fn(),
            "last_delivery_error": None,
            **DEFAULT_PREFERENCES,
        }
        devices.append(item)
        return item

    def _append_event(self, data: dict[str, Any], event: dict[str, Any]) -> None:
        events = data.setdefault("events", [])
        events.append({"ts": self.now_fn(), **event})
        del events[:-100]

    def _with_registry_lock(self, operation: Callable[[], Any]) -> Any:
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.registry_path.parent, stat.S_IRWXU)
        except OSError:
            pass
        lock_path = self.registry_path.with_name(f"{self.registry_path.name}.lock")
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        with _push_registry_thread_lock(self.registry_path):
            try:
                lock_fd = os.open(lock_path, flags, 0o600)
            except OSError as exc:
                raise PushDispatcherError(
                    "push_registry_unavailable",
                    "push registry lock is unavailable",
                    500,
                ) from exc
            try:
                os.fchmod(lock_fd, 0o600)
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                return operation()
            except PushDispatcherError:
                raise
            except OSError as exc:
                raise PushDispatcherError(
                    "push_registry_unavailable",
                    "push registry is unavailable",
                    500,
                ) from exc
            finally:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)

    def _read(self) -> dict[str, Any]:
        return self._with_registry_lock(self._read_registry_unlocked)

    def _mutate_registry(self, mutator: Callable[[dict[str, Any]], Any]) -> Any:
        def operation() -> Any:
            data = self._read_registry_unlocked()
            result = mutator(data)
            self._write_registry_unlocked(data)
            return result

        return self._with_registry_lock(operation)

    def _read_registry_unlocked(self) -> dict[str, Any]:
        try:
            raw = self.registry_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except FileNotFoundError:
            data = {}
        except json.JSONDecodeError as exc:
            data = self._recover_registry_json(raw, exc)
        if not isinstance(data, dict):
            raise PushDispatcherError("push_registry_corrupt", "push registry root is not an object", 500)
        data.setdefault("schema_version", 1)
        data.setdefault("contract_version", CONTRACT_VERSION)
        data.setdefault("devices", [])
        data.setdefault("events", [])
        data.setdefault("delivery_outbox", [])
        data.setdefault("deliveries", [])
        repaired = self._rehydrate_registry_from_quarantine_backup(data)
        if self._quarantine_malformed_registry_records(data):
            repaired = True
        if repaired:
            data["updated_at"] = self.now_fn()
            self._write_registry_unlocked(data)
        return data

    def _quarantine_malformed_registry_records(self, data: dict[str, Any]) -> bool:
        repaired = False
        devices = data.get("devices")
        if not isinstance(devices, list):
            self._append_quarantine(
                data,
                bucket="quarantined_devices",
                reason="devices_not_list",
                index=None,
                value=devices,
            )
            data["devices"] = []
            repaired = True
        else:
            valid_devices: list[dict[str, Any]] = []
            for index, item in enumerate(devices):
                if not isinstance(item, dict):
                    self._append_quarantine(
                        data,
                        bucket="quarantined_devices",
                        reason="device_record_not_object",
                        index=index,
                        value=item,
                    )
                    repaired = True
                    continue
                device_id = str(item.get("device_id") or "").strip()
                if not device_id:
                    self._append_quarantine(
                        data,
                        bucket="quarantined_devices",
                        reason="device_record_missing_device_id",
                        index=index,
                        value=item,
                    )
                    repaired = True
                    continue
                item["device_id"] = device_id
                valid_devices.append(item)
            if len(valid_devices) != len(devices):
                data["devices"] = valid_devices
                repaired = True

        for key in ("events", "delivery_outbox", "deliveries"):
            value = data.get(key)
            if isinstance(value, list):
                continue
            self._append_quarantine(
                data,
                bucket="quarantined_records",
                reason=f"{key}_not_list",
                index=None,
                value=value,
            )
            data[key] = []
            repaired = True

        if repaired:
            self._append_event(data, {
                "event": "push.registry.quarantined",
                "outcome": "repaired",
            })
        return repaired

    def _append_quarantine(
        self,
        data: dict[str, Any],
        *,
        bucket: str,
        reason: str,
        index: int | None,
        value: Any,
    ) -> None:
        records = data.get(bucket)
        if not isinstance(records, list):
            records = []
            data[bucket] = records
        entry: dict[str, Any] = {
            "ts": self.now_fn(),
            "reason": reason,
            "value_type": type(value).__name__,
            "value_preview": repr(value)[:1000],
        }
        if index is not None:
            entry["index"] = index
        records.append(entry)
        del records[:-100]

    def _recover_registry_json(self, raw: str, exc: json.JSONDecodeError) -> dict[str, Any]:
        decoder = json.JSONDecoder()
        try:
            data, end = decoder.raw_decode(raw)
        except json.JSONDecodeError:
            return self._quarantine_unreadable_registry(raw, exc)
        if not isinstance(data, dict):
            return self._quarantine_unreadable_registry(raw, exc)
        if raw[end:].strip() == "":
            return self._quarantine_unreadable_registry(raw, exc)

        self._backup_corrupt_registry(raw)
        self._write_registry_unlocked(data)
        return data

    def _quarantine_unreadable_registry(self, raw: str, exc: json.JSONDecodeError) -> dict[str, Any]:
        backup = self._backup_corrupt_registry(raw)
        salvaged, bucket_errors = self._salvage_registry_members(raw)
        data: dict[str, Any] = {
            "schema_version": 1,
            "contract_version": CONTRACT_VERSION,
            "devices": salvaged.get("devices") or [],
            "events": salvaged.get("events") or [],
            "delivery_outbox": salvaged.get("delivery_outbox") or [],
            "deliveries": salvaged.get("deliveries") or [],
            "updated_at": self.now_fn(),
        }
        self._append_quarantine(
            data,
            bucket="quarantined_records",
            reason="registry_json_decode_error",
            index=None,
            value={
                "message": exc.msg,
                "line": exc.lineno,
                "column": exc.colno,
                "position": exc.pos,
                "backup_path": str(backup) if backup else None,
            },
        )
        record = data["quarantined_records"][-1]
        record["line"] = exc.lineno
        record["column"] = exc.colno
        record["position"] = exc.pos
        if backup:
            record["backup_path"] = str(backup)
        for key, error in bucket_errors.items():
            self._append_quarantine(
                data,
                bucket="quarantined_records",
                reason=f"{key}_json_decode_error",
                index=None,
                value={
                    "message": error,
                    "backup_path": str(backup) if backup else None,
                },
            )
        self._append_event(data, {
            "event": "push.registry.quarantined",
            "outcome": "repaired",
            "reason": "registry_json_decode_error",
        })
        self._write_registry_unlocked(data)
        return data

    def _salvage_registry_members(self, raw: str) -> tuple[dict[str, Any], dict[str, str]]:
        salvaged: dict[str, Any] = {}
        errors: dict[str, str] = {}
        for key in ("devices", "events", "delivery_outbox", "deliveries"):
            value, error = self._extract_json_member(raw, key)
            if error:
                errors[key] = error
            elif isinstance(value, list):
                salvaged[key] = value
            elif value is not None:
                errors[key] = f"{key} is {type(value).__name__}, not list"
        return salvaged, errors

    def _extract_json_member(self, raw: str, key: str) -> tuple[Any | None, str | None]:
        needle = '"' + key + '"'
        pos = raw.find(needle)
        if pos < 0:
            return None, "missing"
        colon = raw.find(":", pos + len(needle))
        if colon < 0:
            return None, "missing colon"
        start = colon + 1
        while start < len(raw) and raw[start].isspace():
            start += 1
        if start >= len(raw):
            return None, "missing value"
        opener = raw[start]
        closer = {"[": "]", "{": "}"}.get(opener)
        if closer is None:
            return None, "value is not a JSON container"
        depth = 0
        in_string = False
        escape = False
        for index in range(start, len(raw)):
            char = raw[index]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == opener:
                depth += 1
            elif char == closer:
                depth -= 1
                if depth == 0:
                    text = raw[start:index + 1]
                    try:
                        return json.loads(text), None
                    except json.JSONDecodeError as exc:
                        return None, str(exc)
        return None, "unclosed container"

    def _rehydrate_registry_from_quarantine_backup(self, data: dict[str, Any]) -> bool:
        records = data.get("quarantined_records")
        if not isinstance(records, list):
            return False
        devices = data.setdefault("devices", [])
        if not isinstance(devices, list):
            return False
        existing_ids = {
            str(item.get("device_id") or "").strip()
            for item in devices
            if isinstance(item, dict)
        }
        for record in reversed(records):
            if not isinstance(record, dict):
                continue
            if record.get("reason") != "registry_json_decode_error":
                continue
            backup_path = str(record.get("backup_path") or "").strip()
            if not backup_path:
                continue
            try:
                raw = Path(backup_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            salvaged, _ = self._salvage_registry_members(raw)
            restored: list[dict[str, Any]] = []
            for item in salvaged.get("devices") or []:
                if not isinstance(item, dict):
                    continue
                device_id = str(item.get("device_id") or "").strip()
                if not device_id or device_id in existing_ids:
                    continue
                item["device_id"] = device_id
                devices.append(item)
                existing_ids.add(device_id)
                restored.append(item)
            if restored:
                self._append_quarantine(
                    data,
                    bucket="quarantined_records",
                    reason="devices_rehydrated_from_backup",
                    index=None,
                    value={
                        "backup_path": backup_path,
                        "device_count": len(restored),
                    },
                )
                self._append_event(data, {
                    "event": "push.registry.rehydrated",
                    "outcome": "repaired",
                    "device_count": len(restored),
                })
                return True
        return False

    def _backup_corrupt_registry(self, raw: str) -> Path | None:
        backup = self.registry_path.with_name(
            f"{self.registry_path.name}.corrupt-{int(self.now_fn())}-{uuid.uuid4().hex[:8]}"
        )
        try:
            backup.write_text(raw, encoding="utf-8")
            os.chmod(backup, 0o600)
            return backup
        except OSError:
            return None

    def _read_secrets(self) -> dict[str, Any]:
        return read_push_secrets(self.secret_path)

    def _secret_for_device(self, device_id: str) -> dict[str, Any]:
        try:
            data = self._read_secrets()
        except PushDispatcherError:
            return {}
        device = data.get("devices", {}).get(device_id)
        return device if isinstance(device, dict) else {}

    def _mark_live_activity_invalid(
        self,
        device: dict[str, Any],
        session_id: str,
        event_id: str,
        outcome: str,
        *,
        token_hash: str | None = None,
    ) -> None:
        for item in device.get("live_activities", []):
            if (
                item.get("session_id") == session_id
                and not item.get("invalidated_at")
                and (not token_hash or item.get("token_hash") == token_hash)
            ):
                item["invalidated_at"] = self.now_fn()
                item["invalidated_by_event_id"] = event_id
                item["invalidated_reason"] = outcome

    def _remove_live_activity_secret_if_hash(
        self,
        *,
        device_id: str,
        session_id: str,
        token_hash: str,
    ) -> bool:
        """Retire one captured token without deleting a concurrent replacement."""
        if not token_hash:
            return False

        def remove_if_current(current: dict[str, Any]) -> bool:
            secret = current.get("devices", {}).get(device_id)
            if not isinstance(secret, dict):
                return False
            live_tokens = secret.get("live_activity_tokens")
            if not isinstance(live_tokens, dict):
                return False
            token_record = live_tokens.get(session_id)
            if (
                not isinstance(token_record, dict)
                or token_record.get("token_hash") != token_hash
            ):
                return False
            live_tokens.pop(session_id, None)
            return True

        return bool(mutate_push_secrets(self.secret_path, remove_if_current))

    def _write_registry_unlocked(self, payload: dict[str, Any]) -> None:
        tmp = self.registry_path.with_name(
            f"{self.registry_path.name}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex}.tmp"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(tmp, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fd = -1
                json.dump(payload, fh, indent=2, sort_keys=True)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.registry_path)
            os.chmod(self.registry_path, 0o600)
            try:
                parent_fd = os.open(self.registry_path.parent, os.O_RDONLY)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
            except OSError:
                pass
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass


def _public_push_device(
    device: dict[str, Any],
    *,
    secret_device: Any = None,
) -> dict[str, Any]:
    public = dict(device)
    public.pop("relay_pair_secret_ref", None)
    private = secret_device if isinstance(secret_device, dict) else {}
    public["relay_pair_secret_configured"] = bool(
        str(private.get("relay_pair_secret") or "").strip()
        and str(private.get("relay_pair_secret_ref") or "").strip()
    )
    return public


def _nonempty(value: str | None, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise PushDispatcherError("missing_" + field, field.replace("_", " ") + " is required")
    return text


def _validate_apns_token(token: str, field: str) -> None:
    if len(token) < APNS_TOKEN_MIN_HEX_CHARS or len(token) > APNS_TOKEN_MAX_HEX_CHARS:
        raise PushDispatcherError("invalid_" + field, field.replace("_", " ") + " length is invalid")
    try:
        int(token, 16)
    except ValueError:
        raise PushDispatcherError("invalid_" + field, field.replace("_", " ") + " must be hex")


def _normalize_apns_environment(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text == "sandbox":
        return "development"
    if text in APNS_ENVIRONMENTS:
        return text
    return "development"


def _normalize_apns_key_environment(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"any", "all"}:
        return "both"
    if text == "sandbox":
        return "development"
    if text in APNS_KEY_ENVIRONMENTS:
        return text
    return "development"


def _token_environment(value: Any) -> str:
    return _normalize_apns_environment(value)


def _provider_environment(provider: dict[str, Any]) -> str:
    return _normalize_apns_environment(provider.get("environment"))


def _key_environment(provider: dict[str, Any]) -> str:
    return _normalize_apns_key_environment(provider.get("key_environment") or provider.get("environment"))


def _key_environment_mismatch(provider: dict[str, Any]) -> bool:
    key_environment = _key_environment(provider)
    return key_environment != "both" and key_environment != _provider_environment(provider)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _json_dump(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _infer_apns_key_id(path: str) -> str:
    name = Path(path).name
    if name.startswith("AuthKey_") and name.endswith(".p8"):
        return name[len("AuthKey_"):-len(".p8")]
    return ""


def _thread_id(kind: str, route: str) -> str:
    if "/session/" in route:
        return "pairling.session." + route.rsplit("/", 1)[-1][:80]
    if kind in {"mac_health", "mac_route_risk"}:
        return "pairling.health"
    if kind in {"worker_sentinel", "worker_pressure"}:
        return "pairling.workers"
    return "pairling.push"


def _alert_enabled_for_device(device: dict[str, Any], kind: str) -> bool:
    if not device.get("standard_push_enabled"):
        return False
    if kind == "push_diagnostic":
        return bool(device.get("push_diagnostics_enabled"))
    if kind in {"turn_done", "turn_result", "deploy_result"}:
        return bool(device.get("turn_done_enabled"))
    if kind in {"worker_sentinel", "worker_pressure"}:
        return bool(device.get("worker_sentinel_enabled"))
    return True


def _alert_pairling_extra(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "session_id",
        "provider",
        "source",
        "phase",
        "project",
        "observed_at",
        "collapse_id",
        "dedupe_key",
        "result_summary",
        "required_action",
        "risk_summary",
        "route_health",
        "worker_summary",
        "build_label",
        "sentinel_event_id",
        "sentinel_level",
        "sentinel_key",
        "health_posture",
        "health_severity",
        "health_summary",
        "mac_install_id",
        "request_nonce",
        "authorization_contract",
        "authorization_control",
        "authorization_device_id",
        "authorization_install_id",
        "authorization_issued_at",
        "authorization_expires_at",
        "notification_action_nonce",
        "notification_action_contract",
        "notification_action_control",
        "notification_action_device_id",
        "notification_action_install_id",
        "notification_action_session_id",
        "notification_action_action",
        "notification_action_issued_at",
        "notification_action_expires_at",
    }
    out: dict[str, Any] = {}
    for key in allowed:
        if key not in payload:
            continue
        value = payload[key]
        if isinstance(value, str):
            out[key] = value[:180]
        elif isinstance(value, (int, float, bool)) or value is None:
            out[key] = value
    return out


def _split_curl_status(stdout: str) -> tuple[str, int | None]:
    if "\n" not in stdout:
        return stdout, None
    response_text, status_text = stdout.rsplit("\n", 1)
    try:
        return response_text, int(status_text.strip())
    except ValueError:
        return stdout, None


def _apns_outcome(status: int | None, reason: str | None, curl_exit_code: int) -> str:
    if curl_exit_code != 0:
        return f"curl_error_{curl_exit_code}"
    if status is None:
        return "apns_unknown"
    if reason:
        return f"apns_{status}_{reason}"
    return f"apns_{status}"


def _bounded_content_state(content_state: dict[str, Any], *, event_id: str, now: int) -> dict[str, Any]:
    state = str(content_state.get("state") or "starting")[:40]
    if state not in {"starting", "thinking", "tool", "responding", "attention", "stale", "done", "failed", "idle"}:
        state = "starting"
    attention = content_state.get("attentionLevel")
    if attention is not None:
        attention = str(attention)[:20]
        if attention not in {"info", "warning", "critical"}:
            attention = None
    tokens = content_state.get("tokens")
    try:
        parsed_tokens = int(tokens) if tokens is not None else None
    except (TypeError, ValueError):
        parsed_tokens = None
    phase = str(content_state.get("phase") or state)[:32]
    if phase not in {"starting", "thinking", "tool", "responding", "attention", "stale", "done", "failed", "idle", "risk"}:
        phase = state
    return {
        "state": state,
        "phase": phase,
        "tool": _bounded_optional(content_state.get("tool"), 80),
        "effort": _bounded_optional(content_state.get("effort"), 40),
        "tokens": parsed_tokens,
        "verb": str(content_state.get("verb") or "Working")[:40],
        "attentionLevel": attention,
        "updatedAtEpoch": _positive_finite_float(content_state.get("updatedAtEpoch")) or float(now),
        "eventId": str(content_state.get("eventId") or event_id)[:120],
        "sessionTitle": _bounded_optional(content_state.get("sessionTitle"), 60),
        "provider": _bounded_optional(content_state.get("provider"), 32),
        "project": _bounded_optional(content_state.get("project"), 60),
        "currentStep": _bounded_optional(content_state.get("currentStep"), 60),
        "latestEvent": _bounded_optional(content_state.get("latestEvent"), 120),
        "resultSummary": _bounded_optional(content_state.get("resultSummary"), 120),
        "requiredAction": _bounded_optional(content_state.get("requiredAction"), 120),
        "freshness": _bounded_optional(content_state.get("freshness"), 40),
        "riskLevel": _bounded_optional(content_state.get("riskLevel"), 32),
        "riskSummary": _bounded_optional(content_state.get("riskSummary"), 120),
        "routeHealth": _bounded_optional(content_state.get("routeHealth"), 120),
        "workerSummary": _bounded_optional(content_state.get("workerSummary"), 120),
        "buildLabel": _bounded_optional(content_state.get("buildLabel"), 60),
        "actionRoute": _bounded_optional(content_state.get("actionRoute"), 300),
    }


def _live_activity_content_state(payload: dict[str, Any], *, activity_event: str, event_id: str, now: int) -> dict[str, Any]:
    content_state = payload.get("content_state")
    if isinstance(content_state, dict):
        return content_state
    state = str(payload.get("state") or ("done" if activity_event == "end" else "tool"))
    return {
        "state": state,
        "phase": payload.get("phase") or state,
        "tool": payload.get("tool"),
        "effort": payload.get("effort"),
        "tokens": payload.get("tokens"),
        "verb": str(payload.get("verb") or ("Done" if activity_event == "end" else "Using")),
        "attentionLevel": payload.get("attentionLevel"),
        "updatedAtEpoch": _positive_finite_float(payload.get("updatedAtEpoch")) or float(now),
        "eventId": event_id,
    }


def _bounded_optional(value: Any, limit: int) -> str | None:
    if value in (None, ""):
        return None
    return str(value)[:limit]


def _optional_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _positive_finite_float(value: Any) -> float | None:
    parsed = _optional_float(value)
    if parsed is None or not math.isfinite(parsed) or parsed <= 0:
        return None
    return parsed


def _normalize_retry_payload_timing(
    payload: dict[str, Any],
    *,
    push_type: str,
    stable_time: float,
    existing_payload: dict[str, Any] | None,
) -> dict[str, Any]:
    normalized = dict(payload)
    existing = existing_payload if isinstance(existing_payload, dict) else {}
    fallback_sent_at = (
        _positive_finite_float(existing.get("sent_at"))
        or _positive_finite_float(stable_time)
        or 1.0
    )
    sent_at = (
        _positive_finite_float(existing.get("sent_at"))
        or _positive_finite_float(normalized.get("sent_at"))
        or fallback_sent_at
    )
    observed_at = (
        _positive_finite_float(existing.get("observed_at"))
        or _positive_finite_float(normalized.get("observed_at"))
        or sent_at
    )
    normalized["sent_at"] = sent_at
    normalized["observed_at"] = observed_at

    if push_type != "liveactivity":
        return normalized

    content_state = normalized.get("content_state")
    existing_content_state = existing.get("content_state")
    if isinstance(content_state, dict):
        bounded_state = dict(content_state)
        existing_updated_at = (
            _positive_finite_float(existing_content_state.get("updatedAtEpoch"))
            if isinstance(existing_content_state, dict)
            else None
        )
        bounded_state["updatedAtEpoch"] = (
            existing_updated_at
            or _positive_finite_float(bounded_state.get("updatedAtEpoch"))
            or sent_at
        )
        normalized["content_state"] = bounded_state
    else:
        normalized["updatedAtEpoch"] = (
            _positive_finite_float(existing.get("updatedAtEpoch"))
            or _positive_finite_float(normalized.get("updatedAtEpoch"))
            or sent_at
        )
    return normalized


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _outbox_metadata_from_payload(
    payload: dict[str, Any],
    *,
    sent_at: float,
    content_state: dict[str, Any] | None = None,
    apns_outcome: str | None = None,
) -> dict[str, Any]:
    effective_sent_at = _positive_finite_float(payload.get("sent_at")) or sent_at
    observed = _positive_finite_float(payload.get("observed_at")) or effective_sent_at
    freshness = payload.get("freshness_seconds_at_send", payload.get("freshness_seconds"))
    if freshness is None:
        freshness_at_send = max(0.0, float(effective_sent_at) - float(observed))
    else:
        try:
            freshness_at_send = max(0.0, float(freshness))
        except (TypeError, ValueError):
            freshness_at_send = max(0.0, float(effective_sent_at) - float(observed))
    content_hash = None
    if isinstance(content_state, dict):
        content_hash = _sha256_hex(_json_dump(content_state))
    return {
        "source": _bounded_optional(payload.get("source"), 80),
        "phase": _bounded_optional(payload.get("phase"), 32),
        "project": _bounded_optional(payload.get("project"), 60),
        "observed_at": observed,
        "sent_at": float(effective_sent_at),
        "collapse_id": _bounded_optional(payload.get("collapse_id"), 160),
        "freshness_seconds_at_send": freshness_at_send,
        "content_state_hash": _bounded_optional(payload.get("content_state_hash"), 80) or content_hash,
        "apns_outcome": _bounded_optional(apns_outcome, 120),
    }


def _live_activity_outbox_metadata(
    payload: dict[str, Any],
    *,
    content_state: dict[str, Any],
    sent_at: float,
    apns_outcome: str | None = None,
) -> dict[str, Any]:
    effective_sent_at = _positive_finite_float(payload.get("sent_at")) or sent_at
    observed = _positive_finite_float(payload.get("observed_at")) or effective_sent_at
    freshness = payload.get("freshness_seconds")
    if freshness is None:
        freshness_at_send = max(0.0, float(effective_sent_at) - float(observed))
    else:
        try:
            freshness_at_send = float(freshness)
        except (TypeError, ValueError):
            freshness_at_send = max(0.0, float(effective_sent_at) - float(observed))
    bounded = _bounded_content_state(content_state, event_id=str(payload.get("event_id") or ""), now=int(sent_at))
    return {
        "source": _bounded_optional(payload.get("source"), 80),
        "phase": _bounded_optional(payload.get("phase") or bounded.get("phase"), 32),
        "project": _bounded_optional(payload.get("project") or bounded.get("project"), 60),
        "observed_at": observed,
        "sent_at": float(effective_sent_at),
        "collapse_id": _bounded_optional(payload.get("collapse_id"), 160),
        "freshness_seconds_at_send": freshness_at_send,
        "content_state_hash": _sha256_hex(_json_dump(bounded)),
        "apns_outcome": _bounded_optional(apns_outcome, 120),
    }


def _apply_outbox_metadata(row: dict[str, Any], metadata: dict[str, Any]) -> None:
    for key, value in metadata.items():
        if value is not None:
            row[key] = value


def _refresh_outbox_attempt_freshness(row: dict[str, Any]) -> None:
    sent_at = _positive_finite_float(row.get("sent_at"))
    observed_at = _positive_finite_float(row.get("observed_at"))
    if sent_at is not None and observed_at is not None:
        row["freshness_seconds_at_send"] = max(0.0, sent_at - observed_at)


def _live_activity_alert_body(content: dict[str, Any]) -> str:
    if content.get("state") == "attention":
        return "Pairling needs your attention."
    if content.get("state") == "failed":
        return "Pairling activity failed."
    return "Pairling activity updated."


def _quiet_hours(value: Any) -> dict[str, Any] | None:
    if value in (None, "", False):
        return None
    if not isinstance(value, dict):
        raise PushDispatcherError("invalid_quiet_hours", "quiet_hours must be an object or null")
    start = str(value.get("start") or "").strip()
    end = str(value.get("end") or "").strip()
    if not start or not end:
        return None
    return {"start": start[:5], "end": end[:5]}


def _optional_epoch(value: Any) -> float | None:
    if value in (None, "", False):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, parsed)


def _bounded_retry_after_seconds(value: Any, *, now: float) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.isdigit():
        return max(1, min(3600, int(text)))
    try:
        parsed = email.utils.parsedate_to_datetime(text)
        seconds = int(parsed.timestamp() - float(now))
    except (TypeError, ValueError, OverflowError):
        return None
    if seconds <= 0:
        return None
    return min(3600, seconds)


def _future_epoch(value: Any, now: float) -> bool:
    try:
        return float(value or 0) > float(now)
    except (TypeError, ValueError):
        return False
