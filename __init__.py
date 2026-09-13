from __future__ import annotations

import base64
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_REPO = "krakendigitex-hub/suppspro-portal"
DEFAULT_ENVIRONMENT = "production"
DEFAULT_ALLOWLIST = {"WP_SSH_PRIVATE_KEY"}
GITHUB_API_BASE = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
GITHUB_HTTP_TIMEOUT_SECONDS = 5


def _allowlist() -> set[str]:
    raw = os.environ.get("HERMES_GITHUB_SECRET_ALLOWLIST", "")
    vals = {x.strip() for x in raw.split(",") if x.strip()}
    return vals or set(DEFAULT_ALLOWLIST)


def _token() -> str:
    return (os.environ.get("HERMES_GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()


def _pynacl_available() -> bool:
    return importlib.util.find_spec("nacl.public") is not None


def _safe_config() -> dict[str, Any]:
    return {
        "token_configured": bool(_token()),
        "repo": os.environ.get("HERMES_GITHUB_REPO", DEFAULT_REPO),
        "environment": os.environ.get("HERMES_GITHUB_ENVIRONMENT", DEFAULT_ENVIRONMENT),
        "allowed_secrets": sorted(_allowlist()),
        "gh_available": bool(shutil.which("gh")),
        "github_rest_available": True,
        "pynacl_available": _pynacl_available(),
        "ssh_keygen_available": bool(shutil.which("ssh-keygen")),
        "github_probe_timeout_seconds": GITHUB_HTTP_TIMEOUT_SECONDS,
    }


def _github_api_request(method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, dict[str, Any] | None]:
    token = _token()
    if not token:
        raise RuntimeError("github_token_not_configured")
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        f"{GITHUB_API_BASE}/{path.lstrip('/')}", data=data, method=method,
        headers={
            "Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": "atlas-hermes-github-secret-writer", "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=GITHUB_HTTP_TIMEOUT_SECONDS) as response:
            raw = response.read()
            return response.status, json.loads(raw.decode("utf-8")) if raw else None
    except urllib.error.HTTPError as exc:
        return exc.code, None


def _get_public_key(repo: str, environment: str) -> tuple[bool, str | None, dict[str, str] | None]:
    if not _token():
        return False, "github_token_not_configured", None
    try:
        status, body = _github_api_request("GET", f"repos/{repo}/environments/{environment}/secrets/public-key")
    except TimeoutError:
        return False, "github_api_timeout", None
    except urllib.error.URLError as exc:
        if isinstance(getattr(exc, "reason", None), TimeoutError):
            return False, "github_api_timeout", None
        return False, "github_api_transport_error", None
    except Exception:
        return False, "github_api_transport_error", None
    if status != 200 or not isinstance(body, dict):
        return False, f"github_api_failed_{status}", None
    key_id, key = body.get("key_id"), body.get("key")
    if not isinstance(key_id, str) or not isinstance(key, str) or not key_id or not key:
        return False, "github_public_key_invalid", None
    return True, None, {"key_id": key_id, "key": key}


def _probe_github(repo: str, environment: str):
    ok, err, _ = _get_public_key(repo, environment)
    return ok, err


def _encrypt_secret(public_key_b64: str, value: str) -> str:
    from nacl import public
    sealed_box = public.SealedBox(public.PublicKey(base64.b64decode(public_key_b64)))
    return base64.b64encode(sealed_box.encrypt(value.encode("utf-8"))).decode("ascii")


def _set_environment_secret(repo: str, environment: str, name: str, value: str) -> tuple[bool, str | None]:
    if not _pynacl_available():
        return False, "pynacl_not_available"
    ok, err, key_data = _get_public_key(repo, environment)
    if not ok or key_data is None:
        return False, err or "github_public_key_unavailable"
    try:
        status, _ = _github_api_request("PUT", f"repos/{repo}/environments/{environment}/secrets/{name}", {
            "encrypted_value": _encrypt_secret(key_data["key"], value), "key_id": key_data["key_id"]})
    except TimeoutError:
        return False, "github_secret_write_timeout"
    except Exception:
        return False, "github_secret_write_transport_error"
    return (True, None) if status in (201, 204) else (False, f"github_secret_write_failed_{status}")


def _fingerprint(path: Path) -> str:
    result = subprocess.run(["ssh-keygen", "-lf", str(path)], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, timeout=10, check=True)
    parts = result.stdout.strip().split()
    return parts[1] if len(parts) >= 2 else "unknown"


def _rotate_wp_ssh_key(repo: str, environment: str) -> dict[str, Any]:
    name = "WP_SSH_PRIVATE_KEY"
    cfg = _safe_config()
    if name not in _allowlist(): return {"ok": False, "error": "secret_name_not_allowed", "secret_name": name}
    if not cfg["token_configured"]: return {"ok": False, "error": "github_token_not_configured"}
    if not cfg["pynacl_available"]: return {"ok": False, "error": "pynacl_not_available"}
    if not cfg["ssh_keygen_available"]: return {"ok": False, "error": "ssh_keygen_not_available"}
    ok, err = _probe_github(repo, environment)
    if not ok: return {"ok": False, "error": err or "github_probe_failed"}
    with tempfile.TemporaryDirectory(prefix="atlas-hermes-key-") as tmp:
        key = Path(tmp) / "id_ed25519"
        public = Path(str(key) + ".pub")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "atlas-hermes-wordpress-deploy", "-f", str(key)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True, timeout=20, check=True)
        private_key = key.read_text(encoding="utf-8")
        public_key = public.read_text(encoding="utf-8").strip()
        fingerprint = _fingerprint(public)
        written, write_error = _set_environment_secret(repo, environment, name, private_key)
        private_key = ""
        if not written:
            return {"ok": False, "error": write_error or "github_secret_write_failed", "secret_name": name, "secret_value_exposed": False}
        return {"ok": True, "status": "completed", "operation": "rotate_wp_ssh_key", "repo": repo,
                "environment": environment, "secret_name": name, "secret_value_exposed": False,
                "public_key": public_key, "public_key_fingerprint": fingerprint,
                "next_action": "Authorize this public key for the WordPress SSH user in Hostinger, then rerun the WordPress deploy."}


def atlas_github_secret_writer(params: Any = None, **kwargs: Any) -> str:
    del kwargs
    if params is None: operation = "status"
    elif isinstance(params, dict): operation = params.get("operation", "status")
    elif isinstance(params, str): operation = params
    else: return json.dumps({"ok": False, "error": "invalid_arguments"}, sort_keys=True)
    cfg = _safe_config(); repo = cfg["repo"]; environment = cfg["environment"]
    if operation == "status":
        access, err = (False, None)
        if cfg["token_configured"]: access, err = _probe_github(repo, environment)
        writer_ready = bool(cfg["token_configured"] and cfg["github_rest_available"] and cfg["pynacl_available"] and cfg["ssh_keygen_available"] and access)
        return json.dumps({"ok": True, "service": "atlas-hermes-github-secret-writer", **cfg,
                           "github_access": access, "writer_ready": writer_ready, "probe_error": err,
                           "secret_values_exposed": False}, sort_keys=True)
    if operation == "rotate_wp_ssh_key":
        try: return json.dumps(_rotate_wp_ssh_key(repo, environment), sort_keys=True)
        except subprocess.TimeoutExpired: return json.dumps({"ok": False, "error": "operation_timeout"})
        except subprocess.CalledProcessError: return json.dumps({"ok": False, "error": "ssh_key_generation_failed"})
        except Exception: return json.dumps({"ok": False, "error": "unexpected_writer_error"})
    return json.dumps({"ok": False, "error": "unsupported_operation", "allowed_operations": ["status", "rotate_wp_ssh_key"]}, sort_keys=True)


ATLAS_GITHUB_SECRET_WRITER_SCHEMA = {
    "name": "atlas_github_secret_writer",
    "description": "Atlas guarded GitHub Environment secret writer. status verifies readiness. rotate_wp_ssh_key generates a fresh Ed25519 key, encrypts the private key with GitHub's public key, stores only the PRIVATE key in GitHub Environment secret WP_SSH_PRIVATE_KEY, and returns only the PUBLIC key/fingerprint for Hostinger authorization. Never exposes the GitHub token or private key.",
    "parameters": {"type": "object", "properties": {"operation": {"type": "string", "enum": ["status", "rotate_wp_ssh_key"]}}, "required": ["operation"]},
}


def register(ctx):
    ctx.register_tool(name="atlas_github_secret_writer", toolset="atlas", schema=ATLAS_GITHUB_SECRET_WRITER_SCHEMA,
                      handler=atlas_github_secret_writer, description="Guarded Atlas GitHub Environment secret writer", emoji="🔐")
