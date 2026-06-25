#!/bin/sh
# Translate environment variables (see .env.example) into the CLI flags the
# authentik-mcp server requires, then exec it. Any extra args passed to the
# container are appended, so flags can still be supplied directly.
set -eu

flags=""
[ -n "${AUTHENTIK_BASE_URL:-}" ] && flags="$flags --base-url $AUTHENTIK_BASE_URL"
[ -n "${AUTHENTIK_TOKEN:-}" ] && flags="$flags --token $AUTHENTIK_TOKEN"
[ "${AUTHENTIK_VERIFY_SSL:-true}" = "false" ] && flags="$flags --no-verify-ssl"

# Word-splitting on $flags is intentional (values contain no spaces).
# shellcheck disable=SC2086
exec authentik-mcp $flags "$@"
