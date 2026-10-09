# Multi-stage build for scm-harbourmaster-mcp
# Stage 1: build the wheel with uv
# Stage 2: minimal runtime image (no build tools, no uv)
#
# Base images are pinned by digest; Dependabot (docker ecosystem) bumps them.

# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.11.21@sha256:ff07b86af50d4d9391d9daf4ff89ce427bc544f9aae87057e69a1cc0aa369946 /uv /usr/local/bin/uv

WORKDIR /build

# Version passed by CI (from git tag); fallback for manual builds
ARG SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${SETUPTOOLS_SCM_PRETEND_VERSION}

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock README.md ./
COPY src/ src/

# Build the wheel and install it plus its dependencies into /app/venv.
# UV_PROJECT_ENVIRONMENT is what points `uv sync` there; `--python` only picks
# the interpreter, so without it everything landed in /build/.venv and the
# runtime image shipped an empty venv.
ENV UV_PROJECT_ENVIRONMENT=/app/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
RUN uv sync --frozen --no-dev --no-editable

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f AS runtime

# tini runs as PID 1 so SIGTERM (docker stop, scm_restart) reaches the server:
# Python as PID 1 with no handler would ignore it.
RUN apt-get update && \
    apt-get install -y --no-install-recommends tini && \
    rm -rf /var/lib/apt/lists/*

# Non-root user with a fixed UID/GID so volume ownership is predictable
# (name matches the systemd service account).
RUN groupadd --system --gid 10001 scm-mcp && \
    useradd --system --uid 10001 --gid scm-mcp --no-create-home \
            --home-dir /data --shell /usr/sbin/nologin scm-mcp

# The venv stays root-owned: the server never writes to its own code.
COPY --from=builder /app/venv /app/venv

# Everything the server writes (backups, baselines, reports, plans, index,
# logs, caches) goes under /data. settings.toml and .secrets.toml are read
# from the working directory, so mount them read-only into /data. There is
# deliberately no in-image default: with no mount the server starts with no
# tenants and logs a default_tenant_auth_skipped warning, instead of quietly
# loading the example tenants.
RUN mkdir -p /data && chown scm-mcp:scm-mcp /data
ENV PATH="/app/venv/bin:${PATH}" \
    SCM_MCP_DATA_DIR=/data \
    HOME=/data \
    XDG_CACHE_HOME=/data/.cache \
    PYTHONUNBUFFERED=1
WORKDIR /data
VOLUME ["/data"]

USER scm-mcp

# Default: stdio transport (Claude Desktop / IDE)
# HTTP:  docker run -p 8080:8080 -e SCM_MCP_HTTP_API_KEY=... <image> scm-mcp-http
ENTRYPOINT ["tini", "--"]
CMD ["scm-mcp"]

# HTTP transport (scm-mcp-http, SCM_MCP_HTTP_PORT)
EXPOSE 8080

# Metadata
LABEL org.opencontainers.image.source="https://github.com/silverbacksecurity/scm-harbourmaster-mcp"
LABEL org.opencontainers.image.description="MCP server for Palo Alto Networks Strata Cloud Manager — MSSP edition"
LABEL org.opencontainers.image.licenses="Apache-2.0"
