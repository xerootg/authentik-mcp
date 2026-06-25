"""Command-line entry point for authentik-mcp.

Subcommands:
  serve     run the MCP server (default; backward-compatible with the old
            ``authentik-mcp --base-url ... --token ...`` invocation)
  login     obtain and store a durable API token (kube-exec, or --method manual)
  rotate    mint a fresh token and revoke the previous one (kube method)
  logout    clear stored credentials (optionally revoke the token)
  status    show stored credentials and check them against the API
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys

from . import auth
from . import server as server_mod

SUBCOMMANDS = {"serve", "login", "rotate", "logout", "status"}

DEFAULT_IDENTIFIER = "claude-code-mcp"
DEFAULT_NAMESPACE = "authentik"
DEFAULT_SELECTOR = "authentik-server"


# --------------------------------------------------------------------------- #
# serve
# --------------------------------------------------------------------------- #
def _resolve(arg_val: str | None, env_key: str, creds: dict, creds_key: str) -> str | None:
    """Resolve a value with precedence: CLI arg > environment > creds file."""
    if arg_val:
        return arg_val
    if os.environ.get(env_key):
        return os.environ[env_key]
    return creds.get(creds_key)


def cmd_serve(args: argparse.Namespace) -> int:
    creds = auth.load_credentials()
    base_url = _resolve(args.base_url, "AUTHENTIK_BASE_URL", creds, "base_url")
    token = _resolve(args.token, "AUTHENTIK_TOKEN", creds, "token")
    verify_ssl = not args.no_verify_ssl
    if not args.no_verify_ssl and creds.get("verify_ssl") is False:
        verify_ssl = False

    missing = [n for n, v in (("base URL", base_url), ("token", token)) if not v]
    if missing:
        print(
            f"authentik-mcp: no {' or '.join(missing)} configured.\n"
            "Run `authentik-mcp login` to set up credentials, or pass "
            "--base-url/--token (or set AUTHENTIK_BASE_URL/AUTHENTIK_TOKEN).",
            file=sys.stderr,
        )
        return 1

    asyncio.run(server_mod.serve(base_url, token, verify_ssl=verify_ssl))
    return 0


# --------------------------------------------------------------------------- #
# login / rotate
# --------------------------------------------------------------------------- #
def cmd_login(args: argparse.Namespace, *, rotate: bool = False) -> int:
    creds = auth.load_credentials()
    verify_ssl = not args.no_verify_ssl
    identifier = args.identifier or creds.get("identifier") or DEFAULT_IDENTIFIER
    base_url = args.base_url or auth.detect_base_url() or creds.get("base_url")
    if not base_url:
        print(
            "authentik-mcp: could not determine the Authentik base URL; "
            "pass --base-url.",
            file=sys.stderr,
        )
        return 1

    if args.method == "manual":
        if rotate:
            print(
                "authentik-mcp: --method manual cannot rotate; use `login` to "
                "store a token you created.",
                file=sys.stderr,
            )
            return 1
        token = args.token or os.environ.get("AUTHENTIK_TOKEN")
        if not token and sys.stdin.isatty():
            token = getpass.getpass("Authentik API token: ").strip()
        if not token:
            print("authentik-mcp: no token provided for --method manual.", file=sys.stderr)
            return 1
    else:  # kube
        username = args.username or creds.get("username") or auth.detect_username()
        if not username:
            print(
                "authentik-mcp: could not determine username; pass --username.",
                file=sys.stderr,
            )
            return 1
        try:
            token = auth.mint_token_kube(
                args.namespace, args.pod_selector, username, identifier, rotate=rotate,
            )
        except (RuntimeError, OSError) as exc:
            print(f"authentik-mcp: {'rotate' if rotate else 'login'} failed: {exc}", file=sys.stderr)
            return 1
        creds["username"] = username

    if auth.verify_token(base_url, token, verify_ssl=verify_ssl):
        print("token validated against the API (200)")
    else:
        print("warning: the token did not validate against the API", file=sys.stderr)

    creds.update(
        {"base_url": base_url, "token": token, "identifier": identifier, "verify_ssl": verify_ssl},
    )
    path = auth.save_credentials(creds)
    print(f"stored credentials in {path}")

    if not args.no_claude:
        if auth.register_claude():
            print("registered 'authentik' MCP server in Claude user config (reads the creds file)")
        else:
            print("note: could not register in Claude config (claude CLI missing?)", file=sys.stderr)

    if rotate:
        print("rotated: the previous token has been revoked.")
    return 0


# --------------------------------------------------------------------------- #
# logout
# --------------------------------------------------------------------------- #
def cmd_logout(args: argparse.Namespace) -> int:
    creds = auth.load_credentials()
    if args.revoke:
        base_url, token = creds.get("base_url"), creds.get("token")
        identifier = creds.get("identifier", DEFAULT_IDENTIFIER)
        if base_url and token:
            ok = auth.revoke_token(base_url, token, identifier, verify_ssl=creds.get("verify_ssl", True))
            print("revoked token" if ok else "warning: token revoke failed", file=sys.stderr if not ok else sys.stdout)
        else:
            print("nothing to revoke (no stored token)")
    cleared = auth.clear_credentials()
    print("cleared stored credentials" if cleared else "no stored credentials to clear")
    if not args.keep_claude:
        auth.unregister_claude()
        print("removed 'authentik' from Claude user config")
    return 0


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #
def cmd_status(_args: argparse.Namespace) -> int:
    creds = auth.load_credentials()
    if not creds:
        print("no stored credentials (run `authentik-mcp login`)")
        return 0
    base_url, token = creds.get("base_url"), creds.get("token")
    print(f"creds file : {auth.creds_path()}")
    print(f"base_url   : {base_url}")
    print(f"identifier : {creds.get('identifier')}")
    print(f"token      : {f'set ({len(token)} chars)' if token else 'missing'}")
    if base_url and token:
        ok = auth.verify_token(base_url, token, verify_ssl=creds.get("verify_ssl", True))
        print(f"api check  : {'OK (200)' if ok else 'FAILED (token missing/invalid scope/expired)'}")
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def _add_serve_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base-url", help="Authentik base URL (overrides stored/env)")
    parser.add_argument("--token", help="Authentik API token (overrides stored/env)")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification")


def _add_login_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--method", choices=["kube", "manual"], default="kube",
        help="how to obtain the token (default: kube-exec into the Authentik pod)",
    )
    parser.add_argument("--base-url", help="Authentik base URL (default: from ak profile)")
    parser.add_argument("--token", help="token to store (--method manual)")
    parser.add_argument("--username", help="Authentik username to mint for (default: from `ak whoami`)")
    parser.add_argument("--identifier", help=f"token identifier (default: {DEFAULT_IDENTIFIER})")
    parser.add_argument("--namespace", default=DEFAULT_NAMESPACE, help="Kubernetes namespace")
    parser.add_argument("--pod-selector", default=DEFAULT_SELECTOR, help="substring matching the server pod")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification")
    parser.add_argument("--no-claude", action="store_true", help="do not register in the Claude config")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authentik-mcp",
        description="Authentik MCP server with built-in setup/maintenance (login, rotate, logout, status).",
    )
    sub = parser.add_subparsers(dest="command")

    _add_serve_args(sub.add_parser("serve", help="run the MCP server (default)"))
    _add_login_args(sub.add_parser("login", help="obtain and store a durable API token"))
    _add_login_args(sub.add_parser("rotate", help="mint a fresh token and revoke the old one"))

    logout = sub.add_parser("logout", help="clear stored credentials")
    logout.add_argument("--revoke", action="store_true", help="also revoke the token in Authentik")
    logout.add_argument("--keep-claude", action="store_true", help="leave the Claude config entry in place")

    sub.add_parser("status", help="show stored credentials and check the API")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Default to `serve` when no subcommand is given (e.g. the old
    # `authentik-mcp --base-url ... --token ...` form, or no args at all),
    # but let top-level `-h/--help` reach the parser so it lists subcommands.
    if not argv:
        argv = ["serve"]
    elif argv[0] not in SUBCOMMANDS and argv[0] not in {"-h", "--help"} and argv[0].startswith("-"):
        argv = ["serve", *argv]

    args = build_parser().parse_args(argv)
    command = args.command or "serve"
    if command == "serve":
        return cmd_serve(args)
    if command == "login":
        return cmd_login(args, rotate=False)
    if command == "rotate":
        return cmd_login(args, rotate=True)
    if command == "logout":
        return cmd_logout(args)
    if command == "status":
        return cmd_status(args)
    build_parser().print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
