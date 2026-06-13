from __future__ import annotations

import json
import os
import shlex
import time
from pathlib import Path
from typing import Any

from .status import APERTURE_CLI_KNOWN_VERSION, ApertureCLIProbe


CLAUDE_MANAGED_ENV_VARS = [
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_MODEL",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_SKIP_BEDROCK_AUTH",
    "CLOUD_ML_REGION",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_SKIP_VERTEX_AUTH",
    "ANTHROPIC_VERTEX_PROJECT_ID",
    "ANTHROPIC_VERTEX_BASE_URL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    "API_TIMEOUT_MS",
    "ANTHROPIC_API_KEY",
]


CLIENTS: dict[str, dict[str, Any]] = {
    "claude": {
        "id": "claude",
        "display_name": "Claude Code",
        "binary_name": "claude",
        "common_paths": [".local/bin/claude"],
        "danger_arg": "--dangerously-skip-permissions",
        "backends": [
            {"id": "anthropic", "display_name": "Anthropic API", "compatibility_key": "anthropic_messages", "picks_model": True},
            {"id": "bedrock", "display_name": "AWS Bedrock", "compatibility_key": "bedrock_model_invoke", "picks_model": False},
            {"id": "vertex", "display_name": "Google Vertex", "compatibility_key": "google_raw_predict", "picks_model": True},
            {"id": "zai", "display_name": "z.ai", "compatibility_key": "anthropic_messages", "picks_model": True},
        ],
    },
    "codex": {
        "id": "codex",
        "display_name": "OpenAI Codex",
        "binary_name": "codex",
        "common_paths": [".local/bin/codex"],
        "danger_arg": "--dangerously-bypass-approvals-and-sandbox",
        "backends": [
            {"id": "openai", "display_name": "OpenAI Responses", "compatibility_key": "openai_responses", "picks_model": True},
        ],
    },
}


def _redact_home(path: Path, home: Path) -> str:
    try:
        return "~/" + str(path.resolve().relative_to(home.resolve()))
    except Exception:
        return str(path)


def _find_binary(home: Path, env: dict[str, str], name: str, common_paths: list[str]) -> tuple[Path | None, str | None]:
    candidates: list[tuple[Path, str]] = []
    for prefix in env.get("PATH", "").split(":"):
        if prefix:
            candidates.append((Path(prefix) / name, "path"))
    for rel in common_paths:
        candidates.append((home / rel, "client_common_path"))
    for rel_dir in [".local/bin", "bin", ".npm-global/bin"]:
        candidates.append((home / rel_dir / name, "common_bin_dir"))
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


def _compat_enabled(provider: dict[str, Any], key: str) -> bool:
    compatibility = provider.get("compatibility")
    return isinstance(compatibility, dict) and bool(compatibility.get(key))


def _provider_display(provider: dict[str, Any]) -> str:
    value = provider.get("name") or provider.get("id") or ""
    return str(value)


def _fqn_models(provider: dict[str, Any]) -> list[dict[str, Any]]:
    provider_id = str(provider.get("id") or "")
    models = provider.get("models")
    if not isinstance(models, list):
        return []
    result = []
    for model in models:
        if not isinstance(model, str) or not model:
            continue
        result.append({
            "fqn": f"{provider_id}/{model}",
            "provider_model": model,
            "selection_source": "phone",
        })
    return result


def _strip_provider_prefix(model: str) -> str:
    return model.split("/", 1)[1] if "/" in model else model


def _tier_model_env(provider: dict[str, Any]) -> dict[str, str]:
    models = sorted([m for m in provider.get("models") or [] if isinstance(m, str)], reverse=True)
    env: dict[str, str] = {}
    targets = [
        ("opus", "ANTHROPIC_DEFAULT_OPUS_MODEL"),
        ("sonnet", "ANTHROPIC_DEFAULT_SONNET_MODEL"),
        ("haiku", "ANTHROPIC_DEFAULT_HAIKU_MODEL"),
    ]
    for model in models:
        lower = model.lower()
        for needle, key in targets:
            if key not in env and needle in lower:
                env[key] = model
    return env


def _claude_env(endpoint_url: str, backend_id: str, provider: dict[str, Any], model: str | None) -> dict[str, str]:
    if backend_id == "anthropic":
        env = {"ANTHROPIC_BASE_URL": endpoint_url, "ANTHROPIC_AUTH_TOKEN": "-"}
    elif backend_id == "bedrock":
        env = {
            "ANTHROPIC_BEDROCK_BASE_URL": endpoint_url.rstrip("/") + "/bedrock",
            "CLAUDE_CODE_USE_BEDROCK": "1",
            "CLAUDE_CODE_SKIP_BEDROCK_AUTH": "1",
        }
        env.update(_tier_model_env(provider))
    elif backend_id == "vertex":
        env = {
            "CLOUD_ML_REGION": "_aperture_auto_vertex_region_",
            "CLAUDE_CODE_USE_VERTEX": "1",
            "CLAUDE_CODE_SKIP_VERTEX_AUTH": "1",
            "ANTHROPIC_VERTEX_PROJECT_ID": "_aperture_auto_vertex_project_id_",
            "ANTHROPIC_VERTEX_BASE_URL": endpoint_url.rstrip("/") + "/v1",
        }
    elif backend_id == "zai":
        env = {
            "ANTHROPIC_BASE_URL": endpoint_url,
            "ANTHROPIC_MODEL": "glm-5.1",
            "ANTHROPIC_DEFAULT_OPUS_MODEL": "glm-5.1",
            "ANTHROPIC_DEFAULT_SONNET_MODEL": "glm-5.1",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": "glm-5-turbo",
            "API_TIMEOUT_MS": "3000000",
            "ANTHROPIC_API_KEY": "-",
        }
    else:
        raise ValueError(f"unsupported Claude Code backend: {backend_id}")
    if model:
        env["ANTHROPIC_MODEL"] = _strip_provider_prefix(model)
    return env


def _codex_home(home: Path, native_id: str) -> Path:
    return home / "Library" / "Application Support" / "Pairling" / "aperture-cli" / "codex-home" / native_id


def _write_codex_config(home: Path, endpoint_url: str, native_id: str) -> list[Path]:
    codex_home = _codex_home(home, native_id)
    codex_home.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(codex_home, 0o700)
    auth_path = codex_home / "auth.json"
    auth_path.write_text(json.dumps({"auth_mode": "apikey", "OPENAI_API_KEY": "not-needed"}, indent=2, sort_keys=True) + "\n")
    os.chmod(auth_path, 0o600)
    config_path = codex_home / "config.toml"
    config_path.write_text(
        'model_provider = "aperture"\n\n'
        "[model_providers.aperture]\n"
        'name = "Aperture"\n'
        f"base_url = {json.dumps(endpoint_url.rstrip('/') + '/v1')}\n"
        'env_key = "OPENAI_API_KEY"\n'
        "supports_websockets = false\n"
    )
    os.chmod(config_path, 0o600)
    return [auth_path, config_path]


def _codex_env(home: Path, endpoint_url: str, native_id: str, model: str | None) -> dict[str, str]:
    env = {
        "OPENAI_BASE_URL": endpoint_url.rstrip("/") + "/v1",
        "OPENAI_API_KEY": "not-needed",
        "CODEX_HOME": str(_codex_home(home, native_id)),
    }
    if model:
        env["OPENAI_MODEL"] = _strip_provider_prefix(model)
    return env


def _redacted_env(env: dict[str, str], home: Path) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in sorted(env.items()):
        if key.endswith("API_KEY") or key.endswith("AUTH_TOKEN"):
            redacted[key] = "<placeholder>"
        elif key.endswith("_HOME") or key == "CODEX_HOME":
            redacted[key] = _redact_home(Path(value), home)
        else:
            redacted[key] = value
    return redacted


def _public_context(context: dict[str, Any]) -> dict[str, Any]:
    public = dict(context)
    generated = dict(public.get("generated") or {})
    generated.pop("env", None)
    public["generated"] = generated
    return public


def claude_settings_conflicts(home: Path) -> list[str]:
    path = home / ".claude" / "settings.json"
    if not path.is_file():
        return []
    try:
        obj = json.loads(path.read_text(errors="replace"))
    except Exception:
        return []
    env = obj.get("env") if isinstance(obj, dict) else None
    if not isinstance(env, dict):
        return []
    return [key for key in CLAUDE_MANAGED_ENV_VARS if key in env]


class ApertureLaunchPlanner:
    def __init__(self, home: Path | None = None, env: dict[str, str] | None = None, now: float | None = None) -> None:
        self.home = (home or Path.home()).expanduser()
        self.env = env if env is not None else os.environ
        self.now = now

    def _probe(self) -> ApertureCLIProbe:
        return ApertureCLIProbe(home=self.home, env=self.env, now=self.now)

    def _provider_payload(self) -> dict[str, Any]:
        return self._probe().providers_payload()

    def _client_payload(self, client_id: str) -> dict[str, Any]:
        client = CLIENTS[client_id]
        binary, source = _find_binary(self.home, self.env, client["binary_name"], client["common_paths"])
        return {
            "id": client_id,
            "display_name": client["display_name"],
            "binary_name": client["binary_name"],
            "binary_path": str(binary) if binary else None,
            "binary_path_source": source,
            "installed": binary is not None,
        }

    def _endpoint_payload(self, endpoint: dict[str, Any]) -> dict[str, Any]:
        url = str(endpoint.get("runtime_url") or endpoint.get("normalized_url") or endpoint.get("url") or "").rstrip("/")
        return {
            "url": url,
            "mode": endpoint.get("mode") or "direct",
            "bridge_id": endpoint.get("bridge_id"),
            "runtime_url": url,
            "display_host": endpoint.get("display_host"),
            "normalized_url": endpoint.get("normalized_url") or url,
            "host": endpoint.get("host"),
            "normalized": bool(endpoint.get("normalized")),
            "stale": bool(endpoint.get("stale")),
        }

    def _context(
        self,
        *,
        client_id: str,
        endpoint: dict[str, Any],
        provider: dict[str, Any],
        backend: dict[str, Any],
        model: dict[str, Any] | None,
        danger_mode: bool = False,
        native_id: str = "<session-id>",
        write_config: bool = False,
    ) -> dict[str, Any]:
        model_fqn = str((model or {}).get("fqn") or "")
        client = self._client_payload(client_id)
        endpoint_payload = self._endpoint_payload(endpoint)
        args: list[str] = []
        config_writes: list[str] = []
        if client_id == "codex":
            if write_config:
                config_writes = [_redact_home(path, self.home) for path in _write_codex_config(self.home, endpoint_payload["runtime_url"], native_id)]
            else:
                config_writes = [
                    _redact_home(_codex_home(self.home, native_id) / "auth.json", self.home),
                    _redact_home(_codex_home(self.home, native_id) / "config.toml", self.home),
                ]
            env = _codex_env(self.home, endpoint_payload["runtime_url"], native_id, model_fqn or None)
            if model_fqn:
                args.extend(["--model", model_fqn])
        else:
            env = _claude_env(endpoint_payload["runtime_url"], str(backend["id"]), provider, model_fqn or None)
        if danger_mode:
            args.append(str(CLIENTS[client_id]["danger_arg"]))
        return {
            "strategy": "aperture_cli",
            "client": client,
            "endpoint": endpoint_payload,
            "provider": {
                "id": provider["id"],
                "name": _provider_display(provider),
                "display_name": _provider_display(provider),
                "description": str(provider.get("description") or ""),
                "models": [m for m in provider.get("models") or [] if isinstance(m, str)],
                "compatibility": provider.get("compatibility") or {},
            },
            "backend": {
                "id": backend["id"],
                "display_name": backend["display_name"],
                "compatibility_key": backend["compatibility_key"],
            },
            "model": model,
            "danger_mode": {
                "enabled": bool(danger_mode),
                "arg": CLIENTS[client_id]["danger_arg"] if danger_mode else None,
                "source": "pairling",
            },
            "generated": {
                "env": env,
                "env_redacted": _redacted_env(env, self.home),
                "args": args,
                "config_writes": config_writes,
            },
            "aperture_cli_version": APERTURE_CLI_KNOWN_VERSION,
        }

    def contexts_payload(self) -> dict[str, Any]:
        providers_payload = self._provider_payload()
        endpoint = providers_payload.get("source_endpoint") or {"url": "http://ai", "mode": "direct", "bridge_id": None}
        contexts: list[dict[str, Any]] = []
        warnings: list[str] = []
        if endpoint.get("mode") == "bridge":
            warnings.append("Bridge endpoints are visible but native Pairling launch requires a direct local runtime URL.")
        for provider in providers_payload.get("items") or []:
            if not isinstance(provider, dict):
                continue
            for client_id, client in CLIENTS.items():
                seen_compat: set[str] = set()
                for backend in client["backends"]:
                    key = backend["compatibility_key"]
                    if key in seen_compat:
                        continue
                    seen_compat.add(key)
                    if not _compat_enabled(provider, key):
                        continue
                    models = _fqn_models(provider) if backend.get("picks_model") else []
                    if models:
                        for model in models:
                            contexts.append(_public_context(self._context(client_id=client_id, endpoint=endpoint, provider=provider, backend=backend, model=model)))
                    else:
                        contexts.append(_public_context(self._context(client_id=client_id, endpoint=endpoint, provider=provider, backend=backend, model=None)))
        return {
            "ok": True,
            "schema_version": 1,
            "launch_strategy": "aperture_cli",
            "source_endpoint": endpoint,
            "reachable": providers_payload.get("reachable", False),
            "last_error": providers_payload.get("last_error"),
            "clients": [self._client_payload(client_id) for client_id in CLIENTS],
            "contexts": contexts,
            "count": len(contexts),
            "warnings": warnings,
            "observed_at": self.now if self.now is not None else time.time(),
        }

    def validate_request(self, aperture: dict[str, Any], native_id: str, *, write_config: bool) -> dict[str, Any]:
        client_id = str(aperture.get("client_id") or aperture.get("client") or "").strip().lower()
        if client_id not in CLIENTS:
            raise ValueError("aperture.client_id must be claude or codex")
        endpoint_url = str(aperture.get("endpoint_url") or "").strip().rstrip("/")
        provider_id = str(aperture.get("provider_id") or "").strip()
        backend_id = str(aperture.get("backend_id") or "").strip()
        requested_model = str(aperture.get("model") or "").strip()
        danger_mode = bool(aperture.get("danger_mode") is True)

        providers_payload = self._provider_payload()
        endpoint = providers_payload.get("source_endpoint") or {"url": "http://ai", "mode": "direct", "bridge_id": None}
        if endpoint.get("mode") == "bridge":
            raise ValueError("Aperture CLI bridge endpoints are not supported for native Pairling launch yet")
        if endpoint_url and endpoint_url != str(endpoint.get("url") or "").rstrip("/"):
            raise ValueError("aperture.endpoint_url does not match active Aperture CLI endpoint")
        if not providers_payload.get("reachable"):
            raise ValueError(f"Aperture providers are not reachable: {providers_payload.get('last_error') or 'unknown error'}")

        provider = next((p for p in providers_payload.get("items") or [] if isinstance(p, dict) and p.get("id") == provider_id), None)
        if not provider:
            raise ValueError("aperture.provider_id is not available from the active Aperture endpoint")
        backend = next((b for b in CLIENTS[client_id]["backends"] if b["id"] == backend_id), None)
        if not backend:
            raise ValueError("aperture.backend_id is not supported for this client")
        if not _compat_enabled(provider, backend["compatibility_key"]):
            raise ValueError("selected provider does not support the requested client/backend")
        models = _fqn_models(provider)
        model = None
        if backend.get("picks_model"):
            if requested_model:
                model = next((m for m in models if m["fqn"] == requested_model), None)
                if model is None:
                    raise ValueError("aperture.model is not available for the selected provider")
            elif len(models) == 1:
                model = models[0]
            elif client_id == "codex":
                raise ValueError("aperture.model is required for Codex when multiple or zero models are present")
        elif requested_model:
            raise ValueError("aperture.model must be omitted for this backend")

        client_payload = self._client_payload(client_id)
        if not client_payload["installed"]:
            raise ValueError(f"{client_payload['display_name']} binary is not installed")
        if client_id == "claude":
            conflicts = claude_settings_conflicts(self.home)
            if conflicts:
                raise ValueError("~/.claude/settings.json conflicts with Aperture-managed Claude env: " + ", ".join(conflicts))

        return self._context(
            client_id=client_id,
            endpoint=endpoint,
            provider=provider,
            backend=backend,
            model=model,
            danger_mode=danger_mode,
            native_id=native_id,
            write_config=write_config,
        )


def contexts_payload(home: Path | None = None, env: dict[str, str] | None = None) -> dict[str, Any]:
    return ApertureLaunchPlanner(home=home, env=env).contexts_payload()


def validate_launch_context(aperture: dict[str, Any], native_id: str, *, home: Path | None = None, env: dict[str, str] | None = None, write_config: bool = True) -> dict[str, Any]:
    return ApertureLaunchPlanner(home=home, env=env).validate_request(aperture, native_id, write_config=write_config)


def command_for_context(context: dict[str, Any], project: str) -> str:
    client = context.get("client") if isinstance(context.get("client"), dict) else {}
    generated = context.get("generated") if isinstance(context.get("generated"), dict) else {}
    binary = str(client.get("binary_path") or client.get("binary_name") or "")
    args = [str(arg) for arg in generated.get("args") or []]
    if client.get("id") == "codex":
        args = ["-C", project, "--add-dir", project] + args
    return "exec " + " ".join([shlex.quote(binary), *[shlex.quote(arg) for arg in args]])
