#!/usr/bin/env python3
"""Local Pairling push registration and delivery state.

This is the Mac-side durable registry for APNs-capable paired devices. The
normal registry never stores raw APNs tokens; local development APNs sends use a
separate private secret store so delivery can be proven without leaking tokens
through status/audit responses.
"""

from __future__ import annotations

import json
import os
import stat
import base64
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
from typing import Any

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
    "push_diagnostic": ("Pairling push test", "Push delivery is configured for this device."),
}
TIME_SENSITIVE_KINDS = {"session_attention", "mac_health", "worker_sentinel", "action_required", "turn_failed", "tool_risk", "mac_route_risk", "worker_pressure"}


class PushDispatcherError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


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
        payload = {
            "aps": {
                "alert": {"title": title, "body": body},
                "sound": "default",
                "category": KIND_CATEGORY[kind],
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
            "configured": bool(relay_url or mode == "relay" or local_ready),
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
                response_body = response.read()
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            response_body = exc.read()
        except Exception as exc:
            return {
                "accepted": False,
                "outcome": "relay_network_error",
                "relay_status": None,
                "relay_error": type(exc).__name__,
                "retryable": True,
                "invalid_token": False,
            }
        try:
            parsed = json.loads(response_body.decode("utf-8") or "{}")
        except Exception:
            parsed = {}
        ok = 200 <= status < 300 and bool(parsed.get("ok"))
        error = parsed.get("error") if isinstance(parsed.get("error"), dict) else {}
        return {
            "accepted": ok,
            "outcome": str(parsed.get("state") or ("queued" if ok else error.get("code") or f"relay_http_{status}")),
            "state": parsed.get("state"),
            "relay_status": status,
            "relay_error": error.get("code"),
            "retryable": status >= 500,
            "invalid_token": False,
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
        self._lock = threading.RLock()

    def backfill_live_activity_environments(self, *, device_id: str | None = None) -> dict[str, Any]:
        """Repair older Live Activity token rows that predate explicit APNs environments."""
        data = self._read()
        secrets_payload = self._read_secrets()
        public_updates = 0
        secret_updates = 0
        for device in data.get("devices", []):
            current_device_id = str(device.get("device_id") or "")
            if not current_device_id or (device_id and current_device_id != device_id):
                continue
            secret_device = secrets_payload.setdefault("devices", {}).setdefault(current_device_id, {})
            fallback = _normalize_apns_environment(device.get("apns_environment") or secret_device.get("apns_environment"))
            has_live_activity = bool(device.get("live_activities")) or bool(secret_device.get("live_activity_tokens"))
            if has_live_activity and not device.get("apns_environment"):
                device["apns_environment"] = fallback
                public_updates += 1
            if has_live_activity and not secret_device.get("apns_environment"):
                secret_device["apns_environment"] = fallback
                secret_updates += 1
            for item in device.get("live_activities") or []:
                if isinstance(item, dict) and not item.get("apns_environment"):
                    item["apns_environment"] = fallback
                    public_updates += 1
            live_tokens = secret_device.get("live_activity_tokens")
            if isinstance(live_tokens, dict):
                for item in live_tokens.values():
                    if isinstance(item, dict) and not item.get("apns_environment"):
                        item["apns_environment"] = fallback
                        secret_updates += 1
        if public_updates:
            data["updated_at"] = self.now_fn()
            self._write(data)
        if secret_updates:
            self._write_secrets(secrets_payload)
        return {
            "ok": True,
            "public_updates": public_updates,
            "secret_updates": secret_updates,
        }

    def status(self, *, device_id: str | None = None) -> dict[str, Any]:
        payload = self._read()
        devices = payload.get("devices", [])
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
            "devices": devices,
            "delivery_outbox": outbox[-50:],
            "deliveries": deliveries[-100:],
            "events": payload.get("events", [])[-20:],
            "updated_at": payload.get("updated_at"),
        }

    def update_preferences(self, *, device_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        device_id = _nonempty(device_id, "device_id")
        data = self._read()
        device = self._device_record(data, device_id, create=True)
        now = self.now_fn()
        device.setdefault("created_at", now)
        device["last_registered_at"] = now

        relay_device_id = payload.get("relay_device_id")
        if isinstance(relay_device_id, str):
            device["relay_device_id"] = relay_device_id.strip() or None

        apns_environment = _normalize_apns_environment(payload.get("apns_environment") or device.get("apns_environment"))
        if apns_environment:
            device["apns_environment"] = apns_environment

        apns_token = str(payload.get("apns_token") or "").strip().lower()
        if apns_token:
            _validate_apns_token(apns_token, "apns_token")
            device["apns_token_hash"] = _sha256_hex(apns_token)
            device["apns_environment"] = apns_environment
            device["apns_registered_at"] = now
            secrets_payload = self._read_secrets()
            secret_device = secrets_payload.setdefault("devices", {}).setdefault(device_id, {})
            secret_device["apns_token"] = apns_token
            secret_device["apns_token_hash"] = device["apns_token_hash"]
            secret_device["apns_environment"] = apns_environment
            secret_device["updated_at"] = now
            self._write_secrets(secrets_payload)

        relay_pair_secret = str(payload.get("relay_pair_secret") or "").strip()
        if relay_pair_secret:
            relay_secret_ref = str(payload.get("relay_pair_secret_ref") or _sha256_hex(relay_pair_secret)).strip()
            mac_install_id = str(payload.get("mac_install_id") or os.environ.get("PAIRLING_MAC_INSTALL_ID") or "").strip()
            secrets_payload = self._read_secrets()
            secret_device = secrets_payload.setdefault("devices", {}).setdefault(device_id, {})
            secret_device["relay_pair_secret"] = relay_pair_secret
            secret_device["relay_pair_secret_ref"] = relay_secret_ref
            secret_device["relay_device_id"] = device.get("relay_device_id")
            secret_device["mac_install_id"] = mac_install_id
            secret_device["updated_at"] = now
            device["relay_pair_secret_ref"] = relay_secret_ref
            if mac_install_id:
                device["mac_install_id"] = mac_install_id
            self._write_secrets(secrets_payload)

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
        self._write(data)
        return {"ok": True, "device": device, "provider": self._provider_status()}

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
    ) -> dict[str, Any]:
        device_id = _nonempty(device_id, "device_id")
        data = self._read()
        device = self._device_record(data, device_id, create=True)
        kind = str(payload.get("kind") or "push_diagnostic")[:80]
        route = str(payload.get("route") or "pairling://settings/push")[:300]
        title = str(payload.get("title") or "")[:90] or None
        body = str(payload.get("body") or "")[:220] or None
        thread_id = str(payload.get("thread_id") or "")[:120] or None
        interruption_level = str(payload.get("interruption_level") or "").strip()[:40] or None
        pairling_extra = _alert_pairling_extra(payload)
        provider = self._provider_status()
        event_id = str(payload.get("event_id") or f"{default_event_prefix}_{int(self.now_fn() * 1000)}")[:120]
        metadata = _outbox_metadata_from_payload(payload, sent_at=self.now_fn())
        idempotent = self._idempotent_delivery(
            data,
            event_id=event_id,
            push_type="alert",
            provider=provider,
            audit_event=audit_event,
        )
        if idempotent:
            return idempotent
        sent = False
        outcome = "not_configured"
        delivery_extra: dict[str, Any] = {}
        token_hash = device.get("apns_token_hash")
        if not _alert_enabled_for_device(device, kind):
            outcome = "disabled"
        elif kind != "push_diagnostic" and _future_epoch(device.get("push_snoozed_until"), self.now_fn()):
            outcome = "snoozed"
        elif provider["mode"] == "local_apns" and provider["configured"]:
            secret = self._secret_for_device(device_id)
            token = secret.get("apns_token")
            token_hash = secret.get("apns_token_hash") or token_hash
            if not token:
                outcome = "missing_token"
            elif _key_environment_mismatch(provider):
                outcome = "key_environment_mismatch"
                delivery_extra = {
                    "provider_environment": _provider_environment(provider),
                    "key_environment": _key_environment(provider),
                    "retryable": False,
                    "invalid_token": False,
                }
            elif _token_environment(secret.get("apns_environment") or device.get("apns_environment")) != _provider_environment(provider):
                outcome = "token_environment_mismatch"
                delivery_extra = {
                    "provider_environment": _provider_environment(provider),
                    "token_environment": _token_environment(secret.get("apns_environment") or device.get("apns_environment")),
                    "retryable": False,
                    "invalid_token": False,
                }
            else:
                outbox_row = self._upsert_outbox(
                    data,
                    event_id=event_id,
                    device_id=device_id,
                    push_type="alert",
                    route=route,
                    kind=kind,
                    token_hash=token_hash,
                    provider=provider,
                    state="sending",
                    increment_attempt=True,
                    metadata=metadata,
                )
                data["updated_at"] = self.now_fn()
                self._write(data)
                apns_result = self.apns_sender.send_alert(
                    token=token,
                    event_id=event_id,
                    kind=kind,
                    route=route,
                    title=title,
                    body=body,
                    thread_id=thread_id,
                    pairling_extra=pairling_extra,
                    interruption_level=interruption_level,
                )
                sent = bool(apns_result.get("sent"))
                outcome = str(apns_result.get("outcome") or ("sent" if sent else "failed"))
                delivery_extra = {k: v for k, v in apns_result.items() if k != "sent"}
                if apns_result.get("invalid_token"):
                    device["last_delivery_error"] = outcome
                self._complete_outbox(
                    data,
                    outbox_row,
                    sent=sent,
                    outcome=outcome,
                    delivery_extra=delivery_extra,
                )
        elif provider["mode"] == "relay" and provider["configured"]:
            sent_at = float(self.now_fn())
            metadata = _outbox_metadata_from_payload(payload, sent_at=sent_at)
            relay_extra = self._submit_relay_event(
                device_id=device_id,
                device=device,
                event_id=event_id,
                kind=kind,
                route=route,
                push_type="alert",
                provider=provider,
                extra_body={
                    "title": title,
                    "body": body,
                    "thread_id": thread_id,
                    "interruption_level": interruption_level,
                    "pairling_extra": pairling_extra,
                    **metadata,
                },
            )
            sent = bool(relay_extra.pop("accepted", False))
            outcome = str(relay_extra.pop("outcome", "queued" if sent else "relay_failed"))
            delivery_extra = relay_extra
        device["last_delivery_error"] = None if sent else outcome
        outbox_row = self._find_outbox(data, event_id=event_id, push_type="alert")
        if outbox_row is None:
            outbox_row = self._upsert_outbox(
                data,
                event_id=event_id,
                device_id=device_id,
                push_type="alert",
                route=route,
                kind=kind,
                token_hash=token_hash,
                provider=provider,
                state=self._state_for_outcome(sent=sent, outcome=outcome, delivery_extra=delivery_extra),
                increment_attempt=False,
                metadata=metadata,
            )
            self._complete_outbox(
                data,
                outbox_row,
                sent=sent,
                outcome=outcome,
                delivery_extra=delivery_extra,
            )
        event = {
            "event": audit_event,
            "event_id": event_id,
            "device_id": device_id,
            "kind": kind,
            "route": route,
            "sent": sent,
            "outcome": outcome,
            "provider_mode": provider["mode"],
            "provider_environment": provider.get("environment"),
            **delivery_extra,
        }
        self._append_event(data, event)
        data["updated_at"] = self.now_fn()
        self._write(data)
        return {"ok": sent, "delivery": event, "provider": provider}

    def record_live_activity_token(self, *, device_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        device_id = _nonempty(device_id, "device_id")
        token = _nonempty(str(payload.get("live_activity_token") or ""), "live_activity_token").lower()
        _validate_apns_token(token, "live_activity_token")
        session_id = _nonempty(str(payload.get("session_id") or ""), "session_id")[:120]
        activity_id = str(payload.get("activity_id") or "")[:160] or None
        apns_environment = _normalize_apns_environment(payload.get("apns_environment"))
        now = self.now_fn()
        data = self._read()
        device = self._device_record(data, device_id, create=True)
        if not apns_environment:
            apns_environment = _normalize_apns_environment(device.get("apns_environment"))
        device["apns_environment"] = apns_environment
        token_hash = _sha256_hex(token)
        activities = device.setdefault("live_activities", [])
        activities.append({
            "session_id": session_id,
            "activity_id": activity_id,
            "token_hash": token_hash,
            "apns_environment": apns_environment,
            "registered_at": now,
            "invalidated_at": None,
        })
        del activities[:-20]
        secrets_payload = self._read_secrets()
        secret_device = secrets_payload.setdefault("devices", {}).setdefault(device_id, {})
        live_tokens = secret_device.setdefault("live_activity_tokens", {})
        live_tokens[session_id] = {
            "token": token,
            "token_hash": token_hash,
            "activity_id": activity_id,
            "apns_environment": apns_environment,
            "updated_at": now,
        }
        self._write_secrets(secrets_payload)
        self._append_event(data, {
            "event": "push.live_activity_token.registered",
            "device_id": device_id,
            "session_id": session_id,
            "activity_id": activity_id,
            "token_hash": token_hash,
            "outcome": "ok",
        })
        data["updated_at"] = now
        self._write(data)
        return {"ok": True, "device": device, "provider": self._provider_status()}

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
    ) -> dict[str, Any]:
        device_id = _nonempty(device_id, "device_id")
        self.backfill_live_activity_environments(device_id=device_id)
        session_id = _nonempty(str(payload.get("session_id") or ""), "session_id")[:120]
        activity_event = str(payload.get("event") or "update").strip()
        if activity_event not in {"update", "end"}:
            raise PushDispatcherError("invalid_live_activity_event", "event must be update or end")
        event_id = str(payload.get("event_id") or f"{default_event_prefix}_{int(self.now_fn() * 1000)}")[:120]
        provider = self._provider_status()
        idempotent = self._idempotent_delivery(
            data := self._read(),
            event_id=event_id,
            push_type="liveactivity",
            provider=provider,
            audit_event=audit_event,
        )
        if idempotent:
            return idempotent
        sent = False
        outcome = "not_configured"
        delivery_extra: dict[str, Any] = {}
        device = self._device_record(data, device_id, create=True)
        token_hash = None
        content_state = _live_activity_content_state(payload, activity_event=activity_event, event_id=event_id, now=int(self.now_fn()))
        bounded_content_state = _bounded_content_state(content_state, event_id=event_id, now=int(self.now_fn()))
        metadata = _live_activity_outbox_metadata(payload, content_state=bounded_content_state, sent_at=float(self.now_fn()))
        if not device.get("live_activity_enabled"):
            outcome = "disabled"
        elif provider["mode"] == "local_apns" and provider["configured"]:
            token_record = self._secret_for_device(device_id).get("live_activity_tokens", {}).get(session_id)
            token = token_record.get("token") if isinstance(token_record, dict) else None
            token_hash = token_record.get("token_hash") if isinstance(token_record, dict) else None
            if not token:
                outcome = "missing_live_activity_token"
            elif _key_environment_mismatch(provider):
                outcome = "key_environment_mismatch"
                delivery_extra = {
                    "provider_environment": _provider_environment(provider),
                    "key_environment": _key_environment(provider),
                    "retryable": False,
                    "invalid_token": False,
                }
            elif _token_environment(token_record.get("apns_environment")) != _provider_environment(provider):
                outcome = "token_environment_mismatch"
                delivery_extra = {
                    "provider_environment": _provider_environment(provider),
                    "token_environment": _token_environment(token_record.get("apns_environment")),
                    "retryable": False,
                    "invalid_token": False,
                }
            else:
                outbox_row = self._upsert_outbox(
                    data,
                    event_id=event_id,
                    device_id=device_id,
                    push_type="liveactivity",
                    route="pairling://session/" + session_id,
                    kind="live_activity_" + activity_event,
                    token_hash=token_hash,
                    provider=provider,
                    state="sending",
                    increment_attempt=True,
                    metadata=metadata,
                )
                data["updated_at"] = self.now_fn()
                self._write(data)
                apns_result = self.apns_sender.send_live_activity(
                    token=token,
                    event_id=event_id,
                    event=activity_event,
                    content_state=content_state,
                    stale_seconds=int(payload.get("stale_seconds") or 75),
                    dismissal_seconds=int(payload.get("dismissal_seconds") or 300),
                )
                sent = bool(apns_result.get("sent"))
                outcome = str(apns_result.get("outcome") or ("sent" if sent else "failed"))
                delivery_extra = {k: v for k, v in apns_result.items() if k != "sent"}
                if apns_result.get("invalid_token"):
                    self._mark_live_activity_invalid(device, session_id, event_id, outcome)
                self._complete_outbox(
                    data,
                    outbox_row,
                    sent=sent,
                    outcome=outcome,
                    delivery_extra=delivery_extra,
                )
        elif provider["mode"] == "relay" and provider["configured"]:
            sent_at = float(self.now_fn())
            metadata = _live_activity_outbox_metadata(payload, content_state=bounded_content_state, sent_at=sent_at)
            relay_extra = self._submit_relay_event(
                device_id=device_id,
                device=device,
                event_id=event_id,
                kind="live_activity_" + activity_event,
                route="pairling://session/" + session_id,
                push_type="liveactivity",
                provider=provider,
                extra_body={
                    "session_id": session_id,
                    "activity_event": activity_event,
                    "content_state": bounded_content_state,
                    "stale_seconds": _bounded_int(payload.get("stale_seconds"), default=75, minimum=30, maximum=3600),
                    "dismissal_seconds": _bounded_int(payload.get("dismissal_seconds"), default=300, minimum=0, maximum=86400),
                    **metadata,
                },
            )
            sent = bool(relay_extra.pop("accepted", False))
            outcome = str(relay_extra.pop("outcome", "queued" if sent else "relay_failed"))
            delivery_extra = relay_extra
        device["last_delivery_error"] = None if sent else outcome
        outbox_row = self._find_outbox(data, event_id=event_id, push_type="liveactivity")
        if outbox_row is None:
            outbox_row = self._upsert_outbox(
                data,
                event_id=event_id,
                device_id=device_id,
                push_type="liveactivity",
                route="pairling://session/" + session_id,
                kind="live_activity_" + activity_event,
                token_hash=token_hash,
                provider=provider,
                state=self._state_for_outcome(sent=sent, outcome=outcome, delivery_extra=delivery_extra),
                increment_attempt=False,
                metadata=metadata,
            )
            self._complete_outbox(
                data,
                outbox_row,
                sent=sent,
                outcome=outcome,
                delivery_extra=delivery_extra,
            )
        _apply_outbox_metadata(outbox_row, _live_activity_outbox_metadata(payload, content_state=content_state, sent_at=float(self.now_fn()), apns_outcome=outcome))
        event = {
            "event": audit_event,
            "event_id": event_id,
            "device_id": device_id,
            "session_id": session_id,
            "activity_event": activity_event,
            "sent": sent,
            "outcome": outcome,
            "provider_mode": provider["mode"],
            "provider_environment": provider.get("environment"),
            **delivery_extra,
        }
        self._append_event(data, event)
        data["updated_at"] = self.now_fn()
        self._write(data)
        return {"ok": sent, "delivery": event, "provider": provider}

    def _idempotent_delivery(
        self,
        data: dict[str, Any],
        *,
        event_id: str,
        push_type: str,
        provider: dict[str, Any],
        audit_event: str | None = None,
    ) -> dict[str, Any] | None:
        row = self._find_outbox(data, event_id=event_id, push_type=push_type)
        if not row:
            return None
        state = row.get("state")
        if state == "pending" and float(row.get("next_attempt_at") or 0) <= self.now_fn():
            return None
        delivery = self._latest_delivery(data, event_id=event_id, push_type=push_type) or {}
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

    def _find_outbox(self, data: dict[str, Any], *, event_id: str, push_type: str) -> dict[str, Any] | None:
        for item in data.setdefault("delivery_outbox", []):
            if item.get("event_id") == event_id and item.get("push_type") == push_type:
                return item
        return None

    def _latest_delivery(self, data: dict[str, Any], *, event_id: str, push_type: str) -> dict[str, Any] | None:
        for item in reversed(data.setdefault("deliveries", [])):
            if item.get("event_id") == event_id and item.get("push_type") == push_type:
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
    ) -> dict[str, Any]:
        now = self.now_fn()
        row = self._find_outbox(data, event_id=event_id, push_type=push_type)
        if row is None:
            row = {
                "event_id": event_id,
                "device_id": device_id,
                "push_type": push_type,
                "kind": kind,
                "route": route,
                "token_hash": token_hash,
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
        row["provider_mode"] = provider.get("mode")
        row["provider_environment"] = provider.get("environment")
        row["key_environment"] = provider.get("key_environment")
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
        del data.setdefault("delivery_outbox", [])[:-200]
        return row

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
            delivery_extra={**delivery_extra, "attempt_count": attempt_count},
        )
        now = self.now_fn()
        row["state"] = state
        row["updated_at"] = now
        row["last_outcome"] = outcome
        row["locked_at"] = None
        row["sent_at"] = now
        row["apns_outcome"] = outcome
        retryable = bool(delivery_extra.get("retryable"))
        if state == "pending" and retryable:
            row["next_attempt_at"] = now + min(300, 15 * (2 ** max(0, attempt_count - 1)))
        elif state == "dead_letter":
            row["next_attempt_at"] = None
        elif state != "pending":
            row["next_attempt_at"] = None
        final_outcome = "retry_scheduled" if state == "pending" and retryable else outcome
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

    def _state_for_outcome(self, *, sent: bool, outcome: str, delivery_extra: dict[str, Any]) -> str:
        if sent:
            return "sent"
        if delivery_extra.get("invalid_token"):
            return "invalidated"
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
        provider: dict[str, Any],
        extra_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        secret = self._secret_for_device(device_id)
        relay_pair_secret = str(secret.get("relay_pair_secret") or "").strip()
        relay_device_id = str(device.get("relay_device_id") or secret.get("relay_device_id") or "").strip()
        mac_install_id = str(secret.get("mac_install_id") or device.get("mac_install_id") or os.environ.get("PAIRLING_MAC_INSTALL_ID") or "").strip()
        if not relay_pair_secret or not relay_device_id or not mac_install_id:
            return {
                "accepted": False,
                "outcome": "relay_pair_secret_missing",
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
        relay_url = str(provider.get("relay_url") or "").strip()
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

    def _read(self) -> dict[str, Any]:
        with self._lock:
            try:
                raw = self.registry_path.read_text()
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
                self._write(data)
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
        self._write(data)
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
        self._write(data)
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
        try:
            data = json.loads(self.secret_path.read_text())
        except FileNotFoundError:
            data = {}
        except json.JSONDecodeError as exc:
            raise PushDispatcherError("push_secret_store_corrupt", f"push secret store is corrupt: {exc}", 500)
        if not isinstance(data, dict):
            raise PushDispatcherError("push_secret_store_corrupt", "push secret store root is not an object", 500)
        data.setdefault("schema_version", 1)
        data.setdefault("devices", {})
        return data

    def _secret_for_device(self, device_id: str) -> dict[str, Any]:
        try:
            data = self._read_secrets()
        except PushDispatcherError:
            return {}
        device = data.get("devices", {}).get(device_id)
        return device if isinstance(device, dict) else {}

    def _mark_live_activity_invalid(self, device: dict[str, Any], session_id: str, event_id: str, outcome: str) -> None:
        for item in device.get("live_activities", []):
            if item.get("session_id") == session_id and not item.get("invalidated_at"):
                item["invalidated_at"] = self.now_fn()
                item["invalidated_by_event_id"] = event_id
                item["invalidated_reason"] = outcome

    def _write(self, payload: dict[str, Any]) -> None:
        with self._lock:
            self.registry_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                # A push registry directory must be user-private; 0o700 is stricter than world-readable defaults.
                os.chmod(self.registry_path.parent, stat.S_IRWXU)
            except OSError:
                pass
            tmp = self.registry_path.with_name(
                f"{self.registry_path.name}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex}.tmp"
            )
            try:
                with tmp.open("w") as fh:
                    json.dump(payload, fh, indent=2, sort_keys=True)
                    fh.write("\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.registry_path)
            finally:
                try:
                    tmp.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
            try:
                os.chmod(self.registry_path, 0o600)
            except OSError:
                pass

    def _write_secrets(self, payload: dict[str, Any]) -> None:
        self.secret_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.secret_path.parent, stat.S_IRWXU)
        except OSError:
            pass
        tmp = self.secret_path.with_suffix(self.secret_path.suffix + ".tmp")
        with tmp.open("w") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.secret_path)
        try:
            os.chmod(self.secret_path, 0o600)
        except OSError:
            pass


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
        "updatedAtEpoch": float(content_state.get("updatedAtEpoch") or now),
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
        "updatedAtEpoch": payload.get("updatedAtEpoch") or now,
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
    observed = _optional_float(payload.get("observed_at")) or sent_at
    freshness = payload.get("freshness_seconds_at_send", payload.get("freshness_seconds"))
    if freshness is None:
        freshness_at_send = max(0.0, float(sent_at) - float(observed))
    else:
        try:
            freshness_at_send = max(0.0, float(freshness))
        except (TypeError, ValueError):
            freshness_at_send = max(0.0, float(sent_at) - float(observed))
    content_hash = None
    if isinstance(content_state, dict):
        content_hash = _sha256_hex(_json_dump(content_state))
    return {
        "source": _bounded_optional(payload.get("source"), 80),
        "phase": _bounded_optional(payload.get("phase"), 32),
        "project": _bounded_optional(payload.get("project"), 60),
        "observed_at": observed,
        "sent_at": float(sent_at),
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
    observed = _optional_float(payload.get("observed_at")) or sent_at
    freshness = payload.get("freshness_seconds")
    if freshness is None:
        freshness_at_send = max(0.0, float(sent_at) - float(observed))
    else:
        try:
            freshness_at_send = float(freshness)
        except (TypeError, ValueError):
            freshness_at_send = max(0.0, float(sent_at) - float(observed))
    bounded = _bounded_content_state(content_state, event_id=str(payload.get("event_id") or ""), now=int(sent_at))
    return {
        "source": _bounded_optional(payload.get("source"), 80),
        "phase": _bounded_optional(payload.get("phase") or bounded.get("phase"), 32),
        "project": _bounded_optional(payload.get("project") or bounded.get("project"), 60),
        "observed_at": observed,
        "sent_at": float(sent_at),
        "collapse_id": _bounded_optional(payload.get("collapse_id"), 160),
        "freshness_seconds_at_send": freshness_at_send,
        "content_state_hash": _sha256_hex(_json_dump(bounded)),
        "apns_outcome": _bounded_optional(apns_outcome, 120),
    }


def _apply_outbox_metadata(row: dict[str, Any], metadata: dict[str, Any]) -> None:
    for key, value in metadata.items():
        if value is not None:
            row[key] = value


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


def _future_epoch(value: Any, now: float) -> bool:
    try:
        return float(value or 0) > float(now)
    except (TypeError, ValueError):
        return False
