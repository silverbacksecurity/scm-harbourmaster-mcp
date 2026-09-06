---
name: Bug report
about: Something broken in a tool or the server
labels: bug
---

## Tool / area affected

<!-- e.g. scm_asbuilt_report, CLI menu, SD-WAN auth, HTTP/SSE transport -->

## What happened

<!-- Brief description of the bug -->

## Steps to reproduce

1.
2.
3.

## Expected behaviour

## Actual behaviour / error

```
paste error or log output here
```

## Environment

| Field | Value |
|-------|-------|
| scm-harbourmaster-mcp version | <!-- `uv run python -c "from importlib.metadata import version; print(version('scm-harbourmaster-mcp'))"` --> |
| pan-scm-sdk version | <!-- `uv run python -c "from importlib.metadata import version; print(version('pan-scm-sdk'))"` --> |
| MCP client | <!-- Claude Desktop / Cursor / VS Code / Copilot Studio / other --> |
| MCP client version | |
| Transport | <!-- stdio / HTTP/SSE --> |
| Python version | <!-- `python --version` --> |
| OS | <!-- macOS 14 / Ubuntu 24.04 / Windows 11 / etc. --> |

## Logs

<!-- Set `log_level = "DEBUG"` in `settings.toml` and paste relevant structured log lines.
     Redact any tenant IDs, client IDs, or secrets before pasting. -->

```json

```
