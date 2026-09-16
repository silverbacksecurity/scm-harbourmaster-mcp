# Planner Agent — Tool Manifest

> Status: **implemented** (Phase 1, 2026-07-15). The manifest lives at
> `src/scm_harbourmaster_mcp/resources/tools_manifest.yaml` (ships in the wheel);
> the loader and safety rails live in `scm_harbourmaster_mcp/planner/manifest.py`.
> Coverage is CI-enforced: `tests/unit/test_planner_manifest.py` registers
> every MCP tool against a live FastMCP instance and fails when a tool
> lacks a manifest entry (or an entry goes stale). See Phase 1 of the
> "Planner Agent — Agentic Orchestration Layer" epic in
> [ROADMAP.md](../../ROADMAP.md).

## Location

`src/scm_harbourmaster_mcp/resources/tools_manifest.yaml` — loaded via
`scm_harbourmaster_mcp.planner.load_manifest()` (importlib.resources, cached per
process). The execution layer must resolve every tool through
`Manifest.policy()` — unknown tools raise `UnknownToolError` rather than
defaulting to unattended execution.

## Schema

One entry per MCP tool (currently 141):

```yaml
<tool_name>:
  access: read | write        # write ⇒ ALWAYS gated on explicit human
                              # approval, regardless of trigger type;
                              # requires_approval() takes only the tool
                              # name — no flag can disable this in v1
  domain: deployment | threat_coverage | operational_health |
          posture_compliance | config_change | licensing | sdwan |
          certificates | identity | pab | dlp
                              # mirrors PANW Expert Agent domains plus
                              # MSSP-specific ones
  scope: tenant | cross_tenant
  idempotent: true | false
  retry_policy: retry | fallback | fail_fast
  known_failure_modes: >      # free text; names the fallback tool if one
                              # exists
```

## Loader API (`scm_harbourmaster_mcp.planner`)

| Call | Purpose |
| --- | --- |
| `load_manifest()` | Load + validate the bundled YAML (raises `ManifestError` on bad enums) |
| `Manifest.policy(name)` | Full `ToolPolicy`; raises `UnknownToolError` for unclassified tools |
| `Manifest.requires_approval(name)` | **The v1 hard rule** — `True` for every write tool; signature has exactly one parameter, so there is no bypass |
| `Manifest.domain_tools(domain)` | The per-sub-plan context load (one domain's tools only) |
| `Manifest.write_tools()` / `cross_tenant_tools()` | Policy slices for planners/audit |
| `Manifest.coverage_gaps(registered)` | (unclassified, stale) vs a live registry — CI asserts both empty |

## Domain groupings (context-load budget)

Sub-plans load one domain's tools (~128-tool Copilot Studio ceiling; spec
target ≤ ~20 per domain, hard cap 25 enforced in tests):

| Domain | Tools |
| --- | --- |
| deployment | 20 |
| config_change | 20 |
| posture_compliance | 20 |
| sdwan | 21 |
| operational_health | 25 |
| threat_coverage | 14 |
| pab | 6 |
| dlp | 5 |
| identity | 4 |
| certificates | 3 |
| licensing | 3 |

## `access: write` tools (22)

Everything not listed here is `read`.

| Tool | Note |
| --- | --- |
| `scm_commit` | run `scm_commit_preview` first — commits *everything* pending in the folder |
| `scm_security_rule_create` | RBAC 403 surfaces as SDK "Invalid error response format" |
| `scm_security_rule_delete` | |
| `scm_address_create` | RBAC 403 surfaces as SDK "Invalid error response format" |
| `scm_address_delete` | |
| `dlp_restore` | overwrites live DLP profiles — not reversible |
| `scm_config_rollback` | `commit_immediately=true` pushes straight to running |
| `scm_config_push_track` | |
| `scm_config_clone` | |
| `mssp_onboard_tenant` | |
| `mssp_evict_tenant` | |
| `scm_cert_import` | |
| `scm_tls_profile_manager` | write in create mode only |
| `scm_apply_ncsc_baseline` | |
| `scm_attach_ncsc_profiles` | |
| `scm_create_ncsc_snippet` | |
| `scm_create_nist_snippet` | |
| `scm_reload` | also a Planner recovery action (with approval) |
| `scm_restart` | also a Planner recovery action (with approval) |
| `scm_ssr_execute` | the one idempotent write (already_present semantics; dry_run default) |
| `scm_adnsr_profile_create` | |
| `scm_compliance_framework` | Compliance Center framework CRUD — `delete` is permanent |
| `scm_planner_run` | Phase 3b conversational run — can orchestrate writes named in its approved_write_tools list |

## `scope: cross_tenant` tools (20)

`mssp_tenant_dashboard`, `mssp_list_tenants`, `mssp_tier_comparison`,
`mssp_snippet_catalogue`, `scm_tenant_dashboard`, `scm_cert_lifecycle`,
`scm_mt_analytics`, `scm_incident_summary`, `scm_discover_tenants`,
`scm_licence_forecast`, `scm_service_maintenance`, `scm_spn_bandwidth`,
`scm_renewal_brief`, `scm_drift_baseline`, `scm_drift_check`,
`scm_drift_result`, `scm_planner_run`, `scm_planner_status`, `scm_planner_result`,
`scm_estate_check`.

## `known_failure_modes`

Populated for the recurring traps (see the YAML for full text): the
`scm_remote_network_list` Pydantic failure (fallback:
`scm_ike_gateway_list`), `scm_zone_list` default_folder mismatches,
Insights RBAC 403s (`scm_mobile_user_stats`, `scm_spn_bandwidth`,
`scm_incident_rca` evidence gaps), SD-WAN `audit_logs`/`software_status`
403s and the `sdwan_events` v3.7 payload requirement, `scm_mt_analytics`
CDL-region drift, async job patterns (`scm_asbuilt_report`,
`scm_drift_check` all-tenants), baseline prerequisites
(`scm_commit_preview`, `scm_drift_check`), and the SDK's "Invalid error
response format" masking of write-path RBAC 403s.

## Remaining (moves to Phase 2)

- Wire the manifest into the Planner execution loop itself (the loader API
  and its guarantees exist now; the loop that calls it is Phase 2).
- Honour `retry_policy` in the loop: max 2 retries per step, manifest
  fallback on validation errors, fail-fast on writes.
