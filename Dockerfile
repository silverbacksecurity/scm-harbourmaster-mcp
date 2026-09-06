# Multi-stage build for scm-harbourmaster-mcp
# Stage 1: build the wheel with uv
# Stage 2: minimal runtime image (no build tools, no uv)

# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /build

# Version passed by CI (from git tag); fallback for manual builds
ARG SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${SETUPTOOLS_SCM_PRETEND_VERSION}

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock README.md ./
COPY src/ src/

# Build wheel and install dependencies into /app/venv
RUN uv venv /app/venv && \
    uv sync --frozen --no-dev --no-editable \
      --python /app/venv/bin/python \
      --project /build

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Non-root user (matches systemd service account name)
RUN groupadd --system scm-mcp && \
    useradd --system --no-create-home --shell /usr/sbin/nologin \
            --gid scm-mcp scm-mcp

# Copy only the installed venv from the builder
COPY --from=builder --chown=scm-mcp:scm-mcp /app/venv /app/venv

WORKDIR /app

# Ship the example as the in-image default; operators mount their real
# settings.toml (tenant registry) and .secrets.toml at runtime.
COPY --chown=scm-mcp:scm-mcp settings.example.toml ./settings.toml

USER scm-mcp

# Default: stdio transport (Claude Desktop / IDE)
# For Copilot Studio / HTTP:  docker run -e SCM_MCP_HTTP_API_KEY=... scm-mcp-mssp scm-mcp-http
ENTRYPOINT ["/app/venv/bin/scm-mcp"]
CMD []

# HTTP/SSE port for Copilot Studio transport
EXPOSE 8000 8080

# Metadata
LABEL org.opencontainers.image.source="https://github.com/silverbacksecurity/scm-mcp-mssp"
LABEL org.opencontainers.image.description="MCP server for Palo Alto Networks Strata Cloud Manager — MSSP edition"
LABEL org.opencontainers.image.licenses="Apache-2.0"
