"""Credential storage and login/maintenance helpers for authentik-mcp.

The MCP server needs a long-lived Authentik API token (``intent=api``). The
``ak`` CLI can't produce one (its session tokens lack the ``goauthentik.io/api``
scope and it has no verb to mint a Token-model key), so the supported "login"
path mints one directly in the Authentik server pod via ``kubectl exec`` using
the ak-backed kubeconfig. A ``manual`` method is provided for environments
without cluster access.

Credentials are stored at ``$XDG_CONFIG_HOME/authentik-mcp/config.json``
(0600) and read back by the ``serve`` command.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("authentik-mcp.auth")

# Python executed inside the Authentik server pod via ``ak shell`` (Django
# management shell) to create/rotate a durable API token.
_AK_SHELL_SCRIPT = """\
from authentik.core.models import Token, TokenIntents, User
u = User.objects.get(username={username!r})
if {rotate}:
    Token.objects.filter(identifier={identifier!r}).delete()
t, _ = Token.objects.get_or_create(
    identifier={identifier!r},
    defaults=dict(user=u, intent=TokenIntents.INTENT_API, expiring=False,
                  description="authentik-mcp (Claude Code)"),
)
print("TOKENKEY=" + t.key)
"""


# --------------------------------------------------------------------------- #
# Credential file
# --------------------------------------------------------------------------- #
def config_dir() -> Path:
    """Directory holding the credential file (honours XDG_CONFIG_HOME)."""
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "authentik-mcp"


def creds_path() -> Path:
    return config_dir() / "config.json"


def load_credentials() -> dict[str, Any]:
    path = creds_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        logger.warning("could not read credentials at %s", path)
        return {}
    return data if isinstance(data, dict) else {}


def save_credentials(creds: dict[str, Any]) -> Path:
    config_dir().mkdir(parents=True, exist_ok=True)
    path = creds_path()
    path.write_text(json.dumps(creds, indent=2) + "\n")
    path.chmod(0o600)
    return path


def clear_credentials() -> bool:
    path = creds_path()
    if path.exists():
        path.unlink()
        return True
    return False


# --------------------------------------------------------------------------- #
# Autodetection from the ak CLI profile (best-effort, never fatal)
# --------------------------------------------------------------------------- #
def _ak_profile() -> dict[str, Any]:
    path = Path.home() / ".config" / "authentik" / "config.json"
    try:
        profiles = json.loads(path.read_text()).get("profiles", {})
    except (OSError, json.JSONDecodeError):
        return {}
    return profiles.get("default", {}) if isinstance(profiles, dict) else {}


def detect_base_url() -> str | None:
    """Read the Authentik instance URL from the ak CLI profile, if present."""
    return _ak_profile().get("authentik_url")


def detect_username() -> str | None:
    """Resolve the current user's username via ``ak whoami``."""
    if not shutil.which("ak"):
        return None
    try:
        proc = subprocess.run(
            ["ak", "-j", "whoami"],
            capture_output=True, text=True, timeout=15, check=True,
        )
        return json.loads(proc.stdout).get("preferred_username")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


# --------------------------------------------------------------------------- #
# Token minting via kubectl exec
# --------------------------------------------------------------------------- #
def find_server_pod(namespace: str, selector: str) -> str:
    """Return the first pod name in ``namespace`` whose name contains ``selector``."""
    proc = subprocess.run(
        ["kubectl", "-n", namespace, "get", "pods", "-o", "name"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    pods = [line.strip() for line in proc.stdout.splitlines() if selector in line]
    if not pods:
        msg = f"no pod matching {selector!r} in namespace {namespace!r}"
        raise RuntimeError(msg)
    return pods[0]


def mint_token_kube(
    namespace: str,
    selector: str,
    username: str,
    identifier: str,
    *,
    rotate: bool = False,
) -> str:
    """Create (or rotate) a durable API token inside the Authentik server pod."""
    if not shutil.which("kubectl"):
        msg = "kubectl not found on PATH; use --method manual or install kubectl"
        raise RuntimeError(msg)
    pod = find_server_pod(namespace, selector)
    script = _AK_SHELL_SCRIPT.format(
        username=username, identifier=identifier, rotate=bool(rotate),
    )
    proc = subprocess.run(
        ["kubectl", "-n", namespace, "exec", "-i", pod, "--", "ak", "shell"],
        input=script, capture_output=True, text=True, timeout=120, check=False,
    )
    output = proc.stdout + proc.stderr
    for line in output.splitlines():
        if line.startswith("TOKENKEY="):
            return line[len("TOKENKEY="):].strip()
    msg = f"could not mint token via 'kubectl exec' into {pod}:\n{output[-1500:]}"
    raise RuntimeError(msg)


# --------------------------------------------------------------------------- #
# Authentik API helpers
# --------------------------------------------------------------------------- #
def verify_token(base_url: str, token: str, *, verify_ssl: bool = True) -> bool:
    """Return True if the token authenticates against the Authentik API."""
    try:
        resp = httpx.get(
            base_url.rstrip("/") + "/api/v3/core/users/me/",
            headers={"Authorization": f"Bearer {token}"},
            verify=verify_ssl, timeout=15,
        )
    except httpx.HTTPError:
        return False
    return resp.status_code == httpx.codes.OK


def revoke_token(
    base_url: str,
    auth_token: str,
    identifier: str,
    *,
    verify_ssl: bool = True,
) -> bool:
    """Delete a token by identifier. Treats 'already gone' (404) as success."""
    try:
        resp = httpx.delete(
            base_url.rstrip("/") + f"/api/v3/core/tokens/{identifier}/",
            headers={"Authorization": f"Bearer {auth_token}"},
            verify=verify_ssl, timeout=15,
        )
    except httpx.HTTPError:
        return False
    return resp.status_code in (httpx.codes.NO_CONTENT, httpx.codes.NOT_FOUND)


# --------------------------------------------------------------------------- #
# Claude Code registration
# --------------------------------------------------------------------------- #
def register_claude(scope: str = "user") -> bool:
    """Register (replacing any existing) the 'authentik' MCP server in Claude.

    The registered command is ``authentik-mcp serve`` with no inline token, so
    the credential lives only in the 0600 creds file, not in Claude's config.
    """
    if not shutil.which("claude"):
        return False
    command = shutil.which("authentik-mcp") or "authentik-mcp"
    subprocess.run(
        ["claude", "mcp", "remove", "authentik", "-s", scope],
        capture_output=True, text=True, check=False,
    )
    proc = subprocess.run(
        ["claude", "mcp", "add", "authentik", "-s", scope, "--", command, "serve"],
        capture_output=True, text=True, check=False,
    )
    return proc.returncode == 0


def unregister_claude(scope: str = "user") -> bool:
    if not shutil.which("claude"):
        return False
    proc = subprocess.run(
        ["claude", "mcp", "remove", "authentik", "-s", scope],
        capture_output=True, text=True, check=False,
    )
    return proc.returncode == 0
