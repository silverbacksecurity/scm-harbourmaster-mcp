"""
MCP tools for PAN AIOps integration.

Tools:
    scm_aiops_bpa  — submit a PAN-OS device config XML to the AIOps BPA API
                     and return findings formatted as Markdown with severity
                     breakdown, category scores, and per-check recommendations.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import Any

import requests as _requests
from mcp.server.fastmcp import FastMCP

from ..utils.logging import get_logger
from ..utils.tool_decorator import scm_tool

logger = get_logger(__name__)

# Confirmed live path via probing: /aiops/bpa/v1 (not /bpa/v1)
_AIOPS_BPA_BASE = "https://api.stratacloud.paloaltonetworks.com/aiops/bpa/v1"
_POLL_INTERVAL = 10  # seconds between status polls

# Terminal job states returned by GET /jobs/{id}
_DONE_STATES = {"COMPLETED_WITH_SUCCESS", "COMPLETED_WITH_ERROR", "FAILED", "ERROR"}
_SUCCESS_STATES = {"COMPLETED_WITH_SUCCESS"}

_ERR_CSP_HINT = (
    "\n\nHint: The AIOps BPA API validates `requester_name` and `requester_email` "
    "against registered PANW Customer Support Portal (CSP) accounts. "
    "Ensure `requester_email` is the email address of a CSP user with access to this TSG. "
    "Contact bpa@paloaltonetworks.com if you need to register your account."
)


def _bpa_request(session: Any, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
    """Make an authenticated request to the AIOps BPA API."""
    url = f"{_AIOPS_BPA_BASE}{path}"
    resp = session.request(method, url, timeout=(10, 30), **kwargs)
    resp.raise_for_status()
    return resp.json() if resp.content else {}


def _severity_emoji(sev: str) -> str:
    return {"high": "🔴", "critical": "🔴", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(
        sev.lower(), "⚪"
    )


def _parse_bpa_report(report: Any, device_name: str) -> str:
    """Parse a BPA report payload into a Markdown report."""
    if not isinstance(report, dict):
        return f"```json\n{json.dumps(report, indent=2, default=str)[:4000]}\n```"

    lines: list[str] = []
    label = device_name or "Device"

    # Overall score / summary
    score = report.get("score") or report.get("overall_score") or report.get("summary", {})
    if isinstance(score, dict):
        overall = score.get("overall") or score.get("score") or score.get("total_score") or "—"
    elif isinstance(score, int | float):
        overall = score
    else:
        overall = "—"

    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines += [
        f"## AIOps BPA Report — {label}",
        "",
        f"**Generated:** {ts}  |  **Overall Score:** {overall}",
        "",
    ]

    # Category scores
    cat_scores = (
        report.get("category_scores")
        or report.get("categories")
        or (score.get("categories") if isinstance(score, dict) else None)
    )
    if isinstance(cat_scores, dict):
        lines += ["### Category Scores", "", "| Category | Score |", "|---|---|"]
        for cat, val in cat_scores.items():
            pct = f"{val}%" if isinstance(val, int | float) else str(val)
            lines.append(f"| {cat} | {pct} |")
        lines.append("")

    # Findings
    findings = (
        report.get("findings")
        or report.get("checks")
        or report.get("results")
        or report.get("recommendations")
        or []
    )
    if not isinstance(findings, list) and isinstance(findings, dict):
        flat: list[dict[str, Any]] = []
        for cat_items in findings.values():
            if isinstance(cat_items, list):
                flat.extend(cat_items)
        findings = flat

    if findings:
        fails = [
            f
            for f in findings
            if str(f.get("status", f.get("result", ""))).lower()
            in ("fail", "failed", "warning", "warn")
        ]
        passes = [f for f in findings if f not in fails]

        lines += [
            "### Findings Summary",
            "",
            f"Total checks: **{len(findings)}**  |  "
            f"Failing: **{len(fails)}**  |  Passing: **{len(passes)}**",
            "",
        ]

        if fails:
            by_sev: dict[str, list[dict[str, Any]]] = {}
            for f in fails:
                sev = str(f.get("severity") or f.get("risk_level") or "medium").lower()
                by_sev.setdefault(sev, []).append(f)

            for sev in ("critical", "high", "medium", "low", "info"):
                sev_fails = by_sev.get(sev, [])
                if not sev_fails:
                    continue
                emoji = _severity_emoji(sev)
                lines += [
                    f"#### {emoji} {sev.title()} — {len(sev_fails)} check(s)",
                    "",
                    "| Check | Category | Recommendation |",
                    "|---|---|---|",
                ]
                for f in sev_fails:
                    check_name = (
                        f.get("check_name") or f.get("name") or f.get("title") or f.get("id", "?")
                    )
                    category = f.get("category") or f.get("feature") or "—"
                    rec = f.get("recommendation") or f.get("description") or f.get("message") or "—"
                    rec = rec[:120] + "…" if len(rec) > 120 else rec
                    lines.append(f"| {check_name} | {category} | {rec} |")
                lines.append("")
    else:
        lines += [
            "### Raw Report Data",
            "",
            "```json",
            json.dumps(report, indent=2, default=str)[:3000],
            "```",
        ]

    return "\n".join(lines)


def register_aiops_tools(mcp: FastMCP, get_client: Any) -> None:
    """Register AIOps tools onto the MCP server."""
    tool = scm_tool(get_client)

    @mcp.tool()
    @tool
    def scm_aiops_bpa(
        client: Any,
        tenant_id: str,
        config_xml: str,
        requester_email: str,
        requester_name: str = "",
        device_serial: str = "UNKNOWN",
        device_family: str = "PA-VM",
        device_model: str = "PA-VM",
        device_version: str = "10.2.0",
        device_name: str = "",
        timeout: int = 120,
    ) -> str:
        """Submit a PAN-OS device config XML to the PAN AIOps BPA API for analysis.

        Runs PAN's first-party Best Practice Assessment engine against a live
        PAN-OS or Panorama configuration, complementing the 39 SCM-based BPA
        checks with PAN's own device-level analysis. Reports include per-category
        scores and a prioritised list of failing checks with recommendations.

        **IMPORTANT — requester identity:** The AIOps BPA API (`api.stratacloud
        .paloaltonetworks.com/aiops/bpa/v1`) validates `requester_email` against
        registered PANW Customer Support Portal (CSP) accounts linked to the TSG.
        Use the email address you use to log in to the PANW CSP / AIOps portal.
        Contact bpa@paloaltonetworks.com to enable BPA API access for your account.

        **How to obtain the config XML:**
        - PAN-OS CLI: `show config running | display xml` (copy full output)
        - Panorama: Device tab → select device → Export Config (XML)
        - SCM NGFW device: Admin UI → Devices → export running config

        **Workflow:** POST `/requests` with device metadata → signed S3 upload URL
        → PUT config XML → poll `/jobs/{id}` → GET download URL → fetch report.

        Args:
            config_xml: PAN-OS XML configuration string (full running config).
            requester_email: Email of a registered PANW CSP user with TSG access.
            requester_name: Display name for the requester (defaults to email prefix).
            device_serial: Device serial number (e.g. "007351000123456"). Use
                "UNKNOWN" if not available.
            device_family: Device family (e.g. "PA-VM", "PA-5200", "PA-3400").
            device_model: Device model (e.g. "PA-VM", "PA-5220", "PA-3420").
            device_version: PAN-OS version string (e.g. "10.2.9", "11.1.3").
            device_name: Optional label for the report header (e.g. "FW-NYC-01").
            timeout: Max seconds to wait for the BPA job to complete (default 120).
            tenant_id: SCM tenant ID for authentication. Defaults to active tenant.
        """
        session = getattr(client, "session", None)
        if session is None:
            return "Error: no HTTP session available on SCM client."

        if not config_xml or not config_xml.strip():
            return "Error: config_xml is required. Provide the PAN-OS running config XML."

        if not requester_email or "@" not in requester_email:
            return "Error: requester_email is required and must be a valid email address."

        xml_bytes = config_xml.strip().encode("utf-8")
        label = device_name or device_serial or "Device"
        name = requester_name or requester_email.split("@")[0]

        # ── Step 1: POST /requests — initiate BPA job ─────────────────────
        logger.info(
            "aiops_bpa_start",
            device=label,
            xml_size=len(xml_bytes),
            tenant_id=tenant_id,
            requester=requester_email,
        )
        request_body = {
            "serial": device_serial,
            "family": device_family,
            "model": device_model,
            "version": device_version,
            "requesterName": name,
            "requesterEmail": requester_email,
        }
        try:
            init = _bpa_request(session, "POST", "/requests", json=request_body)
        except _requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 400:
                body = exc.response.json() if exc.response.content else {}
                msg = body.get("message", body.get("description", str(body)))
                if "requesterName" in msg or "requesterEmail" in msg:
                    return (
                        f"BPA API rejected the requester identity.\n"
                        f"API message: {msg}{_ERR_CSP_HINT}"
                    )
            raise

        job_id = init.get("id") or init.get("job_id")
        upload_url = init.get("upload-url") or init.get("upload_url")

        if not job_id or not upload_url:
            return (
                f"Error: unexpected response from BPA API — missing job ID or upload URL.\n"
                f"Response: {json.dumps(init, default=str)}"
            )

        logger.info("aiops_bpa_job_created", job_id=job_id, device=label)

        # ── Step 2: PUT config XML to signed URL (no auth header) ─────────
        upload_resp = _requests.put(
            upload_url,
            data=xml_bytes,
            headers={"Content-Type": "text/xml"},
            timeout=(10, 60),
        )
        upload_resp.raise_for_status()
        logger.info("aiops_bpa_config_uploaded", job_id=job_id, status=upload_resp.status_code)

        # ── Step 3: Poll job status until complete or timeout ─────────────
        start = time.monotonic()
        status_str = "PENDING"
        while time.monotonic() - start < timeout:
            status_resp = _bpa_request(session, "GET", f"/jobs/{job_id}")
            status_str = (
                status_resp.get("status")
                or status_resp.get("state")
                or status_resp.get("job_status")
                or "UNKNOWN"
            )
            logger.info("aiops_bpa_poll", job_id=job_id, status=status_str)
            if status_str in _DONE_STATES:
                break
            time.sleep(_POLL_INTERVAL)

        if status_str not in _DONE_STATES:
            return (
                f"BPA job `{job_id}` still in state `{status_str}` after {timeout}s.\n"
                "The report may still be generating — check back later.\n"
                f"Fetch manually: `GET {_AIOPS_BPA_BASE}/reports/{job_id}`"
            )

        if status_str not in _SUCCESS_STATES:
            return (
                f"BPA job `{job_id}` completed with status `{status_str}`.\n"
                "The config may have been invalid or the BPA engine encountered an error.\n"
                "Verify the XML is a valid PAN-OS running config and retry."
            )

        # ── Step 4: GET /reports/{id} → signed download URL ───────────────
        report_meta = _bpa_request(session, "GET", f"/reports/{job_id}")
        download_url = report_meta.get("download-url") or report_meta.get("download_url")

        if not download_url:
            return (
                f"BPA job `{job_id}` succeeded but no download URL was returned.\n"
                f"Response: {json.dumps(report_meta, default=str)}"
            )

        # ── Step 5: Download report and parse ─────────────────────────────
        dl_resp = _requests.get(download_url, timeout=(10, 60))
        dl_resp.raise_for_status()
        report_data = dl_resp.json()

        logger.info("aiops_bpa_complete", job_id=job_id, device=label)
        return _parse_bpa_report(report_data, label)
