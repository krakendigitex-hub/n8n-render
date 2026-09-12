from __future__ import annotations
import json, os, shutil, subprocess, tempfile
from pathlib import Path
from typing import Any

DEFAULT_REPO = "krakendigitex-hub/suppspro-portal"
DEFAULT_ENVIRONMENT = "production"
DEFAULT_ALLOWLIST = {"WP_SSH_PRIVATE_KEY"}


def _allowlist() -> set[str]:
    raw = os.environ.get("HERMES_GITHUB_SECRET_ALLOWLIST", "")
    vals = {x.strip() for x in raw.split(",") if x.strip()}
    return vals or set(DEFAULT_ALLOWLIST)


def _safe_config() -> dict[str, Any]:
    token = (os.environ.get("HERMES_GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    return {
        "token_configured": bool(token),
        "repo": os.environ.get("HERMES_GITHUB_REPO", DEFAULT_REPO),
        "environment": os.environ.get("HERMES_GITHUB_ENVIRONMENT", DEFAULT_ENVIRONMENT),
        "allowed_secrets": sorted(_allowlist()),
        "gh_available": bool(shutil.which("gh")),
        "ssh_keygen_available": bool(shutil.which("ssh-keygen")),
    }


def _gh_env() -> dict[str, str]:
    token = (os.environ.get("HERMES_GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    env = os.environ.copy()
    if token:
        env["GH_TOKEN"] = token
    env.pop("GITHUB_TOKEN", None)
    return env


def _probe_github(repo: str, environment: str):
    if not shutil.which("gh"):
        return False, "gh_not_available"
    if not _safe_config()["token_configured"]:
        return False, "github_token_not_configured"
    r = subprocess.run(
        ["gh", "api", f"repos/{repo}/environments/{environment}/secrets/public-key", "--silent"],
        env=_gh_env(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=20,
        check=False,
    )
    return (True, None) if r.returncode == 0 else (False, f"gh_api_failed_{r.returncode}")


def _fingerprint(p: Path) -> str:
    r = subprocess.run(
        ["ssh-keygen", "-lf", str(p)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=10,
        check=True,
    )
    parts = r.stdout.strip().split()
    return parts[1] if len(parts) >= 2 else "unknown"


def _rotate_wp_ssh_key(repo: str, environment: str) -> dict[str, Any]:
    name = "WP_SSH_PRIVATE_KEY"
    if name not in _allowlist():
        return {"ok": False, "error": "secret_name_not_allowed", "secret_name": name}
    if not _safe_config()["token_configured"]:
        return {"ok": False, "error": "github_token_not_configured"}
    if not shutil.which("gh"):
        return {"ok": False, "error": "gh_not_available"}
    if not shutil.which("ssh-keygen"):
        return {"ok": False, "error": "ssh_keygen_not_available"}

    ok, err = _probe_github(repo, environment)
    if not ok:
        return {"ok": False, "error": err or "github_probe_failed"}

    with tempfile.TemporaryDirectory(prefix="atlas-hermes-key-") as tmp:
        key = Path(tmp) / "id_ed25519"
        pub = Path(str(key) + ".pub")
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "atlas-hermes-wordpress-deploy", "-f", str(key)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=20,
            check=True,
        )
        private_key = key.read_text(encoding="utf-8")
        public_key = pub.read_text(encoding="utf-8").strip()
        fp = _fingerprint(pub)
        r = subprocess.run(
            ["gh", "secret", "set", name, "--env", environment, "--repo", repo],
            input=private_key,
            env=_gh_env(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30,
            check=False,
        )
        private_key = ""
        if r.returncode != 0:
            return {
                "ok": False,
                "error": f"gh_secret_set_failed_{r.returncode}",
                "secret_name": name,
                "secret_value_exposed": False,
            }
        return {
            "ok": True,
            "status": "completed",
            "operation": "rotate_wp_ssh_key",
            "repo": repo,
            "environment": environment,
            "secret_name": name,
            "secret_value_exposed": False,
            "public_key": public_key,
            "public_key_fingerprint": fp,
            "next_action": "Authorize this public key for the WordPress SSH user in Hostinger, then rerun the WordPress deploy.",
        }


def atlas_github_secret_writer(operation: str = "status") -> str:
    cfg = _safe_config()
    repo = cfg["repo"]
    environment = cfg["environment"]
    if operation == "status":
        access = False
        err = None
        if cfg["token_configured"] and cfg["gh_available"]:
            access, err = _probe_github(repo, environment)
        return json.dumps({
            "ok": True,
            "service": "atlas-hermes-github-secret-writer",
            **cfg,
            "github_access": access,
            "probe_error": err,
            "secret_values_exposed": False,
        }, sort_keys=True)
    if operation == "rotate_wp_ssh_key":
        try:
            return json.dumps(_rotate_wp_ssh_key(repo, environment), sort_keys=True)
        except subprocess.TimeoutExpired:
            return json.dumps({"ok": False, "error": "operation_timeout"})
        except subprocess.CalledProcessError:
            return json.dumps({"ok": False, "error": "ssh_key_generation_failed"})
        except Exception:
            return json.dumps({"ok": False, "error": "unexpected_writer_error"})
    return json.dumps({
        "ok": False,
        "error": "unsupported_operation",
        "allowed_operations": ["status", "rotate_wp_ssh_key"],
    }, sort_keys=True)


ATLAS_GITHUB_SECRET_WRITER_SCHEMA = {
    "name": "atlas_github_secret_writer",
    "description": "Atlas guarded GitHub Environment secret writer. status verifies readiness. rotate_wp_ssh_key generates a fresh Ed25519 key, stores only the PRIVATE key directly in GitHub Environment secret WP_SSH_PRIVATE_KEY, and returns only the PUBLIC key/fingerprint for Hostinger authorization. Never exposes the GitHub token or private key.",
    "parameters": {
        "type": "object",
        "properties": {
            "operation": {"type": "string", "enum": ["status", "rotate_wp_ssh_key"]}
        },
        "required": ["operation"],
    },
}


def register(ctx):
    ctx.register_tool(
        name="atlas_github_secret_writer",
        toolset="atlas",
        schema=ATLAS_GITHUB_SECRET_WRITER_SCHEMA,
        handler=atlas_github_secret_writer,
        description="Guarded Atlas GitHub Environment secret writer",
        emoji="🔐",
    )
