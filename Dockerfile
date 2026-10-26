# Multi-stage build for scm-harbourmaster-mcp
#   builder        build the wheel with uv
#   mermaid-build  install the pinned mermaid-cli (deploy/mermaid) with npm
#   base           the server: venv, tini, non-root user, /data
#   full           base + Node, mermaid-cli and Chromium, so AS-BUILT/HLD
#                  diagrams render (tag :X.Y.Z-full; docker build --target full)
#   runtime        base as-is: the default (last) target, no browser
#
# Base images are pinned by digest; Dependabot (docker ecosystem) bumps them.

# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704 AS builder

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

# ── mermaid-cli build stage ───────────────────────────────────────────────────
# npm only lives here; the full image gets the installed node_modules and the
# Debian nodejs runtime. puppeteer is told never to download a browser.
FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704 AS mermaid-build
RUN apt-get update && \
    apt-get install -y --no-install-recommends nodejs npm && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /mermaid
COPY deploy/mermaid/package.json deploy/mermaid/package-lock.json ./
COPY deploy/mermaid/stubs ./stubs
ENV PUPPETEER_SKIP_DOWNLOAD=1
# Debian's npm 9 rejects the file: override for the extract-zip stub, so this
# throwaway stage installs with the npm that wrote the lockfile.
RUN npm install -g --no-audit --no-fund npm@11.17.0
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

# ── Base runtime stage ────────────────────────────────────────────────────────
FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704 AS base

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
    PYTHONUNBUFFERED=1 \
    SCM_MCP_CONTAINER=image
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

# ── Full image: diagrams render ───────────────────────────────────────────────
FROM base AS full
USER root
# Debian's Chromium (security-updated with the distro) instead of puppeteer's
# downloaded build; fonts so diagram labels aren't tofu.
RUN apt-get update && \
    apt-get install -y --no-install-recommends nodejs chromium fonts-dejavu-core && \
    rm -rf /var/lib/apt/lists/*
COPY --from=mermaid-build /mermaid/node_modules /app/mermaid/node_modules
# node_modules/extract-zip is a symlink to this local stub (see package.json)
COPY --from=mermaid-build /mermaid/stubs /app/mermaid/stubs
# Chromium's sandbox needs user namespaces, which a hardened container
# (cap_drop ALL, default seccomp) doesn't grant: run it without, as the only
# page it ever loads is mmdc's local diagram renderer.
RUN ln -s /app/mermaid/node_modules/.bin/mmdc /usr/local/bin/mmdc && \
    printf '%s\n' '{"executablePath": "/usr/bin/chromium", "args": ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"]}' \
        > /app/mermaid/puppeteer-config.json
ENV SCM_MCP_MMDC_PUPPETEER_CONFIG=/app/mermaid/puppeteer-config.json
USER scm-mcp

# ── Default image ─────────────────────────────────────────────────────────────
FROM base AS runtime
