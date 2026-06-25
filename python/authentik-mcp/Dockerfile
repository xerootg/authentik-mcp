# syntax=docker/dockerfile:1
#
# Container image for the authentik-mcp management server.
# Built and pushed to the GitLab Container Registry by .gitlab-ci.yml,
# then consumable from Kubernetes.

# ---- builder: produce a wheel with uv ----
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

WORKDIR /src
COPY . .
RUN uv build --wheel --out-dir /dist

# ---- runtime: minimal image with the package installed ----
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="authentik-mcp" \
      org.opencontainers.image.description="MCP server for the Authentik API (full management: users, groups, applications, providers, outposts)"

# Install the built wheel, then drop the artifact.
COPY --from=builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

# Map AUTHENTIK_* env vars onto the CLI flags the server expects.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && useradd --create-home --uid 10001 appuser

USER appuser

# The server speaks MCP over stdio (no listening port). It is launched by an
# MCP client/gateway that attaches to stdin/stdout.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
