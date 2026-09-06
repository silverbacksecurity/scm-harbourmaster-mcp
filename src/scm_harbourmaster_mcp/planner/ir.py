"""
Planner Phase 3c — the IR trigger surface (incident-response triage).

Trigger surface #3: an alert (MT Monitor webhook, scm_incident_search hit,
or any bridge POSTing to /webhook/ir on the HTTP transport) is classified
into an incident class and its pre-built triage template runs through the
SAME PlannerLoop as every other trigger. Templates are read-only by
construction — the executor gets no approver, so even a poisoned alert
payload cannot make the triage run execute a write tool.

Classes and templates follow the epic's example (tunnel-down →
sdwan_wan_ip_summary, scm_ike_gateway_list, scm_list_jobs recent changes,
sdwan_events) extended with the incident classes this estate actually
produces, each ending in scm_incident_rca where temporal correlation of
pushes/expiries helps the operator.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

from ..utils.logging import get_logger
from .engine import StepDraft
from .executor import StepExecutor, ToolBackend
from .loop import PlannerLoop
from .manifest import Manifest, load_manifest
from .nightly import TemplateEngine
from .schema import Plan, TriggerType
from .store import PlanStore

logger = get_logger(__name__)

# Ordered — first match wins, most specific first.
_CLASS_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("licence-expiry", ("licence", "license", "subscription", "seat", "entitlement")),
    ("cert-expiry", ("certificate", "cert ", "cert-", "cert_", "x509", "tls expiry")),
    ("tunnel-down", ("tunnel", "ike", "ipsec", "vpn", "servicelink", "peer down")),
    ("config-change", ("config", "commit", "push", "drift", "unauthorized change")),
    (
        "connectivity-degraded",
        ("latency", "packet loss", "jitter", "degraded", "link down", "bandwidth", "health"),
    ),
]

GENERIC_CLASS = "generic"
INCIDENT_CLASSES = [c for c, _ in _CLASS_KEYWORDS] + [GENERIC_CLASS]


def classify_alert(alert: dict[str, Any]) -> str:
    """Map an alert payload to an incident class by keyword (first match wins).

    Looks at the fields alert sources actually populate (message, name,
    category, description, alert_type, severity context) plus the whole
    payload as a fallback, case-insensitively.
    """
    parts = [
        str(alert.get(k, ""))
        for k in ("message", "name", "category", "description", "alert_type", "type", "title")
    ]
    text = " ".join(parts).lower()
    if not text.strip():
        text = json.dumps(alert, default=str).lower()
    for incident_class, keywords in _CLASS_KEYWORDS:
        if any(kw in text for kw in keywords):
            return incident_class
    return GENERIC_CLASS


def alert_summary(alert: dict[str, Any], cap: int = 160) -> str:
    for k in ("message", "name", "description", "title"):
        val = str(alert.get(k, "")).strip()
        if val:
            return val[:cap]
    return json.dumps(alert, default=str)[:cap]


def triage_steps(
    incident_class: str, tenant_id: str, symptom: str, folder: str = "Prisma Access"
) -> list[StepDraft]:
    """The pre-built, read-only triage template for one incident class."""
    steps: list[StepDraft] = []

    def add(domain: str, tool: str, **params: Any) -> None:
        steps.append(StepDraft(domain=domain, tool=tool, params_json=json.dumps(params)))

    def add_rca() -> None:
        add(
            "operational_health",
            "scm_incident_rca",
            tenant_id=tenant_id,
            symptom=symptom,
            lookback_hours=24,
            include_drift=False,  # triage must be fast; drift is a follow-up
        )

    if incident_class == "tunnel-down":  # the epic's worked example
        add("sdwan", "sdwan_wan_ip_summary", tenant_id=tenant_id)
        add("deployment", "scm_ike_gateway_list", folder="Remote Networks", tenant_id=tenant_id)
        add("operational_health", "scm_list_jobs", tenant_id=tenant_id, limit=50)
        add("sdwan", "sdwan_events", tenant_id=tenant_id, hours=24)
        add_rca()
    elif incident_class == "cert-expiry":
        add("certificates", "scm_cert_scan", tenant_id=tenant_id, warn_days=30)
        add("operational_health", "scm_list_jobs", tenant_id=tenant_id, limit=50)
        add_rca()
    elif incident_class == "licence-expiry":
        add("licensing", "scm_license_info", tenant_id=tenant_id)
        add("licensing", "scm_licence_forecast", tenant_id=tenant_id, warn_days=90)
        add_rca()
    elif incident_class == "config-change":
        add("operational_health", "scm_list_jobs", tenant_id=tenant_id, limit=50)
        add("config_change", "scm_config_versions", tenant_id=tenant_id)
        add("config_change", "scm_drift_check", folder=folder, tenant_id=tenant_id)
        add_rca()
    elif incident_class == "connectivity-degraded":
        add("sdwan", "sdwan_link_health", tenant_id=tenant_id, hours=3)
        add("sdwan", "sdwan_app_health", tenant_id=tenant_id)
        add("operational_health", "scm_incident_summary", tenant_id=tenant_id, all_tenants=False)
        add("operational_health", "scm_list_jobs", tenant_id=tenant_id, limit=50)
    else:  # generic
        add("operational_health", "scm_incident_summary", tenant_id=tenant_id, all_tenants=False)
        add("operational_health", "scm_list_jobs", tenant_id=tenant_id, limit=50)
        add_rca()

    return steps


def run_ir_trigger(
    backend: ToolBackend,
    store: PlanStore,
    alert: dict[str, Any],
    tenant_id: str,
    folder: str = "Prisma Access",
    manifest: Manifest | None = None,
) -> Plan:
    """Classify the alert and run its triage template synchronously."""
    manifest = manifest or load_manifest()
    incident_class = classify_alert(alert)
    symptom = alert_summary(alert)
    steps = triage_steps(incident_class, tenant_id, symptom, folder)

    engine = TemplateEngine(steps)
    # No approver: triage is read-only by construction; any drift into a
    # write tool is denied, never executed.
    executor = StepExecutor(manifest, backend, approve_write=None)
    loop = PlannerLoop(manifest, engine, executor, store)
    logger.info("ir_trigger_started", incident_class=incident_class, tenant_id=tenant_id)
    return loop.run(
        goal=f"IR triage ({incident_class}): {symptom}",
        trigger_type=TriggerType.IR_WEBHOOK,
        trigger_payload=alert,
        tenant_scope=tenant_id or "all",
        persona="ir-webhook",
    )


def start_ir_run(
    backend: ToolBackend,
    store: PlanStore,
    alert: dict[str, Any],
    tenant_id: str,
    folder: str = "Prisma Access",
    wait_seconds: float = 5.0,
) -> tuple[str, str]:
    """Launch the triage on a daemon thread; return (plan_id, incident_class).

    Shared by the scm_ir_trigger MCP tool and the /webhook/ir HTTP route.
    plan_id comes from the loop's initial persist (empty string if it has
    not appeared within wait_seconds — the run itself continues regardless).
    """
    incident_class = classify_alert(alert)
    before = set(store.list_plans())
    thread = threading.Thread(
        target=lambda: run_ir_trigger(backend, store, alert, tenant_id, folder),
        daemon=True,
        name="planner-ir",
    )
    thread.start()

    plan_id = ""
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        new = set(store.list_plans()) - before
        if new:
            plan_id = sorted(new)[0]
            break
        time.sleep(0.1)
    return plan_id, incident_class
