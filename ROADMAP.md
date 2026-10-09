# Roadmap

New Strata Cloud Manager / Prisma SASE API families land on
[pan.dev](https://pan.dev/sase/) faster than the SDK tracks them. This server
watches upstream automatically — the bundled endpoint catalog
(`resources/endpoint_catalog.json`) plus the **OpenAPI Spec Drift** section of
`scm_check_updates` flag new/changed spec files — and this file tracks what we
do about it.

## Recently shipped

- **Config Cleanup API + CIDR-aware rule-shadow detection** (2026-08-15) —
  `scm_zerohit_rules` (`tools/config_cleanup.py`) covers pan.dev's brand-new
  Config Cleanup API (zero-hit security/NAT rules, async analysis status
  disclosed, `posture` host — different from the usual `sase` host).
  `scm_rule_shadow_audit` (`tools/audit.py`) adds a standalone whole-rulebase
  shadow audit alongside the existing `scm_commit_preview` gate — no drift
  baseline or pending commit required. Both new tools ride a major upgrade
  to the shared shadow-detection engine (`audit/commit_preview.py`): real
  CIDR subnet containment (stdlib `ipaddress`, including hyphenated ranges)
  and recursive address-group resolution replace the old literal-string-set
  comparison, with FQDN/wildcard/dynamic-group/unresolvable addresses
  falling back to the old literal check rather than risking a false
  "shadowed" claim, and negated-field rule pairs skipped entirely from
  analysis. Also fixed a real gap in `scm_commit_preview`: pre-rulebase and
  post-rulebase rules were checked in two separate passes, so a pre-rule
  shadowing a later post-rule was never caught — now one combined-list pass,
  matching Panorama/SCM's actual pre-then-post evaluation order. An
  adversarial security-audit pass on this same-day upgrade caught a
  **critical** false-positive class before it shipped: Remote Networks and
  Mobile Users are mutually exclusive enforcement pipelines, but the merged
  rulebase list let a Remote-Networks-only rule be flagged as "shadowing" —
  safe to remove — a Mobile-Users-only rule it can never actually affect;
  fixed same-day with a scope-exclusion check, plus two related bugs the
  audit surfaced (rule metadata/offender-ranking keyed by bare name could
  misattribute a finding when a name repeats across the pre/post rulebase;
  `scm_commit_preview`'s `focus_names` could leak an unrelated pre-existing
  shadow across rulebases via the same name-collision path). 32 new tests
  (18 → 41 in `test_commit_preview.py`, plus 9 new in
  `test_config_cleanup_tools.py`).
- **MT Monitor round 3** (2026-07-17) — `scm_mt_analytics` now covers 24 views
  across 34 of 36 catalog paths: alerts, threat list/source, app source, incident
  list/trends/tenants/impacted, service health (CDL, gateway, outliers, unique
  users), URL summary, locations-tenants, tenant hierarchy, license setup/allocated,
  and app monitor. `applications/list` (400) and `locationsUsers` (500) remain
  blocked on PAN spec refresh.
- **Insights scheduled export** (2026-07-17) — `scm_insights_export` for the
  three-step schedule → poll → download pipeline. Fixed v3 export path bug
  (`/query/` prefix was incorrectly prepended to `export/` and `download` paths).
- **SD-WAN Depth Round 3** (2026-07-17) — 7 new tools: app QoS, interface status,
  IPFIX config, SNMP config, event correlation, performance management, and
  events summary. 28 total SD-WAN tools completing the depth roadmap.
- **Configuration Orchestration** (2026-07-17) — 3 SSR-pattern tools for the
  RNHP site-onboarding API: `scm_config_orch_remote_networks`, `_bandwidth`,
  `_profiles`. First write-heavy tool family — `dry_run` default, mandatory
  `ticket_ref`. The `sase/config-orch` family (32 endpoints) is now fully tooled.
- **Newly catalogued small families** (2026-07-17) — email-dlp, dns-security,
  cdl/logforwarding, and DLP incidents tools shipped. `family_probe.py` utility
  for pre-scaffold entitlement probing. `cloudngfw/aws` deferred.
- **Spec-schema request validation** (2026-07-17) — `jsonschema`-based pre-request
  validation layer injected at Insights chokepoints; gracefully degrades without
  a schema file.
- **Compliance Center API tools** (2026-07-15) — `scm_compliance_center` +
  `scm_compliance_framework` covering all 15 endpoints of PAN's new Compliance
  Center API (released 2026-07-14): framework CRUD, compliance scores by product
  + category, 30d/1y timeline, per-control pass/fail with severity, benchmark
  monitoring. 403 detection returns a licence-hint. 18 tests.
- **SSR — Simple Service Requests** (2026-07-15) — `scm_ssr_execute`:
  machine-first JSON tool for URL allow/block-list, threat exceptions, and SSL
  decrypt exclusions. Idempotent, dry-run default, mandatory ticket_ref,
  per-tenant `ssr_objects` allowlist. 21 tests.
- **Insights 2.0 general-purpose query** (2026-07-15) — `scm_insights_query`
  unlocks all 103 Insights paths (v1/v2/v3 + custom + exports) behind one
  interface. Auto-resolves CDL region. 13 tests.
- **MT Monitor round 2** (2026-07-15) — `scm_mt_analytics` gains 5 new views:
  app-usage, url-logs, upgrades, locations, licenses. GET/POST auto-detection.
- **CLI UX overhaul** (2026-07-15) — paginated 21-item menus (Config & Inventory
  5 pages, SD-WAN 3 pages) with N/P nav; 81 read-only ops no longer pause for
  Enter; confirmation prompts on Commit/Push/Rollback; Posture menu renumbered
  sequentially; MSSP Ops reorganised with SYSTEM section; "option 9" → "S".
- **Agentic ops layer: verify / sentinel / gate** (2026-07-15) — three tool
  groups built on one section-diff engine (`audit/asbuilt_verify.py`):
  `scm_asbuilt_verify` (doc-vs-live drift check for AS-BUILT documents
  before customer handover), the drift sentinel (`scm_drift_baseline` /
  `scm_drift_check` / `scm_drift_result` — disk-persisted known-good
  baselines, HIGH/MEDIUM/LOW-triaged overnight sweep with background
  all-tenants jobs), and `scm_commit_preview` (pre-commit blast-radius
  gate: pending-change diff vs baseline, rule-shadow detection on the
  touched rules, BPA introduced/resolved delta, HIGH RISK/REVIEW/LOW RISK
  verdict). Candidate-vs-pushed note: the config-versions API can list and
  *load* versions but not read their content, so the gate diffs candidate
  extraction against the drift baseline — roll it forward with
  `update_baseline=true` after each approved push. Plus `scm_renewal_brief`
  (licences + bandwidth + live connected-MU count → renewal-conversation
  brief with over/under-consumption signals). All live-validated on a lab
  tenant. Completed the set with `scm_incident_rca` (2026-07-15): incident →
  root-cause correlation ranking config pushes, cert expiries, and licence
  expiries by temporal proximity (drift shown separately as state evidence),
  ending in a customer-facing RFO draft with cited evidence and an explicit
  correlation-not-causation caveat. SD-WAN status and Insights alerts are
  disclosed as unchecked (RBAC) rather than silently skipped — add them as
  evidence sources when a monitor-role service account lands.

- **Cross-tenant analytics (mt-monitor)** (2026-07-13) — `scm_mt_analytics`
  over the aggregation API: apps/threats/connectivity/incidents rolled up
  across the tenant hierarchy (`agg_by=tenant`), with CDL-region discovery
  (insights_region mapped + eu/uk sibling fallback; the lab tenants store in `uk`).
  Query language: `{"filter":{"rules":[...]},"properties":[...]}` from the
  spec examples — but `applications/list` 400s and `locationsUsers` 500s
  on the spec's own examples; revisit on a spec refresh. mt-notifications
  gateway path found (`/mt/notifications/api/cloud/2.0/...`) but 403 for
  current service accounts — joins the RBAC-blocked list.

- **PAN service-status / maintenance awareness** (2026-07-13) —
  `scm_service_maintenance` over the public status.paloaltonetworks.com
  Statuspage API (no auth/licence/RBAC; works when tenant APIs are down).
  SASE-product filtering (26 raw windows → 6 relevant on first run),
  region matching against `TenantConfig.insights_region` (global windows
  always included), per-tenant grouping, plus the page's overall
  indicator and unresolved SASE incidents. Same day: `status_banner()`
  now renders on `scm_tenant_dashboard` when status degrades, SASE
  incidents are open, or maintenance is due within 7 days — fetched
  concurrently, silent on failure, absent when healthy.
- **PAB evidence in CE/NCSC CAF compliance** (2026-07-13) — BPA-PAB-001
  (browser device posture baseline: screen lock + disk encryption + host
  firewall → CAF-B5.a + new CE-SC-1 Secure Configuration control) and
  BPA-PAB-002 (stale enrolments >90 days → CAF-B5.a), skipping cleanly on
  unprovisioned tenants. Completes "PAB posture in tenant reporting".
  Also fixed a latent bug found on the way: `extract_browser` pointed at
  `/seb/api/v1` (404, silently empty) instead of `/seb-api/v1` — every
  browser_* snapshot field and the AS-BUILT §5 browser section had been
  empty since the extractor existed; real data now flows (14 users / 8
  devices / 100 apps on the lab MSSP tenant).
- **PAB in the NOC dashboard** (2026-07-13) — `scm_tenant_dashboard`
  gained a PAB column (`14u/8d (62%✓)` = users/devices/share of devices
  passing all three posture checks) from single-page `/seb-api` pulls
  inside the existing parallel poll. First live run flagged a lab tenant
  at 14% posture compliance. More tenants turned out to be
  PAB-provisioned than the licence API implies (5 of 9 serving data).
- **PAB tenant depth** (2026-07-13) — `scm_pab_inventory` /
  `scm_pab_apps` / `scm_pab_user_requests` over the previously untooled
  `access/browser-mgmt` family (33 paths, `/seb-api/v1/*`). Users,
  device inventory with endpoint posture (screen lock / disk encryption /
  firewall), groups, app catalog, and the user-request queue.
  Live-validated on a lab tenant (14 users, 8 devices across 4
  OSes — posture roll-up shows real gaps: 5/8 disk encryption). Base URL
  `api.sase.paloaltonetworks.com/seb-api/v1`, common SASE bearer;
  provisioning detected from the API (no `seb` license entry exists even
  on serving tenants — empty `/users` + "tenant not found" on
  `/applications` = unprovisioned). Feeds the remaining "PAB posture in
  tenant reporting" item (dashboard columns + CE/CAF evidence).
- **Standalone SaaS posture tool** (2026-07-13) — `scm_saas_posture`
  surfaces the SSPM data that was previously buried in compliance
  snapshots: onboarded apps with severity-ranked misconfig findings,
  Identity-SSPM IdP/NHI posture, and catalog capability counts, with
  manual JSON export (`save_to`) / offline import (`load_from`) using a
  format-tagged snapshot. Live-validated on a lab tenant (SSPM licensed,
  178-app catalog, zero apps onboarded — the tool renders the onboarding
  guidance path) and a second lab tenant (unlicensed → clear message). Also
  added to the CLI Posture menu.
- **Classic Prisma SD-WAN depth (round 2)** (2026-07-12) — three more
  read-only tools over the monitor API, live-validated on the 16-site lab:
  `sdwan_flows` (top talkers per site — sources/destinations/apps by bytes
  with appdef name resolution, path-type split, dropped-flow count; the
  flow monitor takes one site per request), `sdwan_app_health` (healthscore
  buckets for sites/circuits/anynet links via `healthscore_type` +
  `aggregation` — the payload schema the round-1 note flagged as unknown —
  plus top-N apps/sites by 17 selectable bases via `monitor/topn`, and
  per-app healthscore via `applicationsummary/query`), and
  `sdwan_cellular_status` (module config joined to live status on
  `cellular_module_id`: modem/SIM/signal/firmware per element). The CLI's
  SD-WAN sub-menu also gained a MONITORING section exposing all of round
  1 + 2 plus WAN IP summary and the site map, reusing the tool logic via
  `_call_mcp_tool` (which now primes the tenant-config cache first).
- **WAN IP enrichment layer 3 — record + cross-check** (2026-07-12) —
  enrichment lookups persist in a 30-day local JSON cache (repeat AS-BUILT
  runs cost zero third-party calls); every WAN IP record now resolves its
  circuit (`circuit_name`/`wan_network` via interface → site WAN interface →
  WAN network); advisory drift flags compare observed ISP vs the configured
  circuit label (token overlap) and IP geolocation vs the site's configured
  coordinates (>500 km) — a live lab run flagged 8/53 circuits whose
  generic labels hid a shared carrier egress; `scm_asbuilt_report` gained
  `enrich_wan_ips` (ISP/ASN/geo/drift columns in §4.2.1 and §3.4.7); and
  `sdwan_site_map` renders an interactive Leaflet/OSM HTML map from site
  lat/long (sites without configured coordinates are listed as skipped —
  12/16 in the main lab, which is also why geo-drift rarely fires there).
- **Classic Prisma SD-WAN depth (round 1)** — 5 new read-only tools on the
  existing `prisma-sase` session, live-validated against a 16-site lab
  tenant (2026-07-12): `sdwan_events` (alarm/alert feed with event-code
  resolution and severity summary), `sdwan_audit_logs` (403s gracefully on
  view-only roles), `sdwan_software_status` (per-ION version + staged
  upgrade state; found two stuck `download_cancelled` upgrades in the lab on
  first run), `sdwan_policy_rules` (path/QoS/NAT/NGFW-security rule
  contents + stacks), `sdwan_link_health` (per-path LQM latency/jitter/MOS
  + site bandwidth; the monitor API takes one path per LQM request, and
  `LqmPacketLoss` rejects every unit — omitted). Also fixed a latent bug:
  element software version is `software_version` not `sw_version`, so
  `sdwan_list_elements`, `sdwan_topology`, and the AS-BUILT §4.1 device
  table always showed it empty.
- **pan.dev endpoint catalog** — 1,593 endpoints / 23 families indexed with
  per-file blob SHAs; REST fallbacks resolve to exact documented URLs; spec
  drift surfaces in `scm_check_updates`.
- **Spec-driven tool scaffolding** — `scripts/gen_tool_from_spec.py` emits
  read-only tool scaffolds (typed params, docstrings) from any catalog family.
- **SP Interconnect visibility** — `scm_spi_status` (7 views: summary,
  interconnects, physical connections, regions, region connections, settings,
  IP-pool usage) over the `sase/mt-interconnect` family (Feb 2026). SPI is the
  service-provider backbone attach for Prisma Access (native-IP on-ramp).
- **Prisma Access Browser for MSP reporting** — `scm_pab_msp_summary`
  (users / tenants / CIE roll-ups per region) and `scm_pab_msp_report`
  (per-TSG blocked malware / websites / extensions and category breakdowns)
  over the `sase/pab-msp` family (Feb 2026).
- **Live WAN IP visibility** — `sdwan_wan_ip_summary` (public/private WAN IP
  per SD-WAN element interface, DHCP-leased included) and
  `scm_ngfw_wan_ip_summary` (NGFW interface IPs from running-config XML),
  plus AS-BUILT WAN IP tables (§4.2.1 SD-WAN with IP-annotated topology,
  §3.4.7 NGFW) — shipped 0.9.0.
- **SD-WAN geo + WAN IP ISP enrichment (layers 1–2)** — site `location`
  (lat/long) and full address surfaced in `sdwan_list_sites` and per-record
  in `sdwan_wan_ip_summary`; opt-in `enrich=true` on both WAN IP tools does
  a whatsmyip-style reverse lookup of each public IP (ISP, org, ASN, rDNS,
  geolocation) via `utils/ipenrich.py` — provider-pluggable (ip-api.com
  batch by default, ipinfo.io + token via `ip_enrichment_provider` /
  `ipinfo_token` settings), 6 h in-process cache, additive-only (failures
  degrade to warnings). Opt-in because it sends tenant public IPs to a
  third-party service (2026-07-11).
- **Detected post-NAT public IP per ION** — `sdwan_wan_ip_summary` now also
  returns `detected_public_ips`: the source address the cloud controller
  sees each element's config/events connection arriving from (element
  status `config_and_events_from`). Solves the NAT-hidden-WAN-IP case —
  live-validated: a lab branch holding an RFC1918 address on the wire
  resolved to its real ISP egress IP/ASN — without any on-device access
  (2026-07-11).
- **Widened endpoint catalog** — `gen_endpoint_catalog.py` previously only
  walked `openapi-specs/{sase,scm,access}`, three of ~19 top-level product
  dirs in the same pan.dev monorepo. Added `sdwan`, `dlp`, `dns-security`,
  `cloudngfw`, `cdl`, `email-dlp` (2026-07-09) — the adjacent security
  products an MSSP managing SASE/SCM tenants also touches. Catalog grew from
  1,593 endpoints / 23 families to **3,871 endpoints / 30 families**.
  Deliberately still excluded: `openapi-specs/mssp` (Prisma *Cloud's* MSSP
  backend — CSPM/CWPP tenant management, a different platform), and
  `compute`/`cwpp`/`cspm`/`dspm`/`iot`/`prisma-airs*` (thousands of files,
  different product lines entirely).

## Next

_Last pan.dev check: 2026-10-08. The endpoint catalog was regenerated
(pan.dev `b9122449` → `45052ce5`, 4,193 paths, 31 families). `prisma-sase`
6.8.1b1 (July 2026 Controller Release) and `pan-scm-sdk` 0.15.1 are both the
latest. The SD-WAN unified and legacy specs changed schemas only, with no
endpoint changes. Compliance Center dropped the `product` filter from the
`benchmark-monitoring` request body; we don't send it by default. The Prisma
Browser spec moved to its own `openapi-specs/prisma-browser` tree, and the
generator now follows it. The NGTS (TLS Protect Cloud) spec moved its paths
from `/ngts/outagedetection/v1/*` to `/ngts/v1/*`, which affects no current
code. New candidates are listed below._

- **Prisma Browser policy & integrations** — the moved spec doubled to 66
  paths. New: browser policy rulebases (`policy/access-and-data`,
  `security`, `sign-in`, `customization`, each with rules, sections and
  positions), IdP app-sync and cloud-storage integrations, branding assets
  and `configuration-management/draft/pending-changes`. The main value is
  in backup and restore: `scm_pab_backup`/`scm_pab_restore` don't cover
  policy rules yet. Read-only listing would come first.
- **MSP PAYG API** (`sase/msp-paygo`, `api.apps.paloaltonetworks.com/mt/paygo/v1`,
  17 paths) — pay-as-you-go child-tenant lifecycle (activate, update or
  delete a child tenant), packages and their regions, locations, and usage
  (totals, per-child summary, activity log, and mobile-user and site
  trends). The usage endpoints fit the MSR pack and the licence forecast.
  Needs a PAYG-enrolled MSP service account to live-test.
- **NGFW/SCM R3 config specs** — new `_R3` spec files add virtual routers
  and their BGP, OSPF, BFD and redistribution profiles, GRE tunnels,
  GP tunnel settings, software-upgrade rules, schedules, status and versions,
  device models, named snapshots (`:load`), application tags (with
  `bulk`), `config-versions:push`, and `sites:query` /
  `remote-networks:query` on the deployment API. Software-upgrade
  status and schedules are the most useful for MSSP ops; the rest feed
  config backup coverage.

- ✅ **Site Management (NGFW device onboarding)** — shipped 2026-07-31 as
  `scm_site_management` (`tools/site_management.py`), covering the new
  pan.dev API family (`config/setup/device-onboarding/v1`, added
  2026-06-26). One tool, `resource_type`-dispatched across all four
  resources — **sites** (device/HA pair + property values), **properties**
  (customer-defined site metadata), **onboarding-rules** (ordered
  variable-resolution logic, plus a `:move` reorder action), and
  **site-groups** (organisational containers) — with full CRUD (SSR
  write-safety pattern: `dry_run` default, mandatory `ticket_ref`, never
  injected into the request body). Site create transparently wraps the
  single-resource call into the live API's batch `{"sites": [...]}`
  envelope. 32 tests.
- ✅ **Monthly Service Review pack generator** — shipped 2026-07-17 as
  `scm_msr_report` (`tools/msr.py` + `audit/msr_report.py`): period-bounded
  incidents + config jobs, cumulative SSR provenance ledger, tier-gated
  compliance depth (Gold gets the 30d trend annex — tier gating since
  removed; every tenant now gets the full annex), licence/renewal posture,
  Insights bandwidth snapshot, mechanical MTTR/ack-rate/change-failure stats,
  ranked executive summary, per-section degradation with coverage disclosure,
  markdown/DOCX output. Live-validated bronze + gold paths incl. real DOCX.
  **Extended 2026-07-18**: RN bandwidth-vs-allocation comparison (Insights
  month window with honest last-N-days fallback — the v3 backend rejects a
  `between` filter — joined against SCM bandwidth allocations, with
  utilisation % and ≥90% exec-summary flag), unique mobile users in period
  + per-location breakdown, ADEM experience score summary (3-day telemetry
  window), commit-job count, and a threats detected/blocked security-events
  section from the Monitor API. Live-validated on both lab tenants.
  Follow-ups when useful: a Slides/deck variant for the customer meeting and
  a `scm-planner-nightly`-style console script dropping the whole estate's
  packs on the 1st of the month.
- ✅ **SD-WAN Depth Round 3** — shipped 2026-07-17.  7 new tools: `sdwan_app_qos`,
  `sdwan_interface_status`, `sdwan_ipfix_config`, `sdwan_snmp_config`,
  `sdwan_event_correlation`, `sdwan_perf_mgmt`, `sdwan_events_summary`.
  28 total SD-WAN tools.
- ✅ **Configuration Orchestration (site-based Remote Networks)** — shipped 2026-07-17.
  3 SSR-pattern tools: `scm_config_orch_remote_networks`, `_bandwidth`, `_profiles`.
- ✅ **Spec-schema request validation** — shipped 2026-07-17.  `jsonschema`-based
  validation layer, injected at Insights chokepoints; gracefully degrades.
- ✅ **Newly catalogued small families** — shipped 2026-07-17.  email-dlp,
  dns-security, cdl/logforwarding, and DLP incidents tools built. `cloudngfw/aws`
  deferred until a lab tenant with Cloud NGFW entitlement exists.
- ✅ **MT Monitor round 3** — shipped 2026-07-17.  24 views covering 34/36 catalog paths.
- ✅ **Insights export workflow** — shipped 2026-07-17.  `scm_insights_export` +
  v3 export path fix.
- ✅ **`GET /mt/pab/tenant/auth_profile`** — shipped 2026-07-31 as
  `scm_pab_msp_auth_profile` (`tools/pab_msp.py`), the one path in the
  already-tooled PAB-for-MSP family that had no consumer. `region`/`licenses`/
  `directories` are covered in the AS-BUILT extractor; `scm_pab_msp_summary`/
  `_report` cover the summary and report paths; the two POST paths (tenant
  creation, user-group creation) remain deliberately excluded as writes.
  Read-only, reuses the existing `_render` envelope.
- ✅ **ADEM path enrichment** — shipped 2026-07-20 as `scm_adem_query`
  (`tools/adem.py`): one consolidated tool over all 13 `access/adem` paths
  (`extract_adem` in the extractor still covers `agent_score`/`application_score`
  internally for AS-BUILT/MSR; this tool exposes those plus the 11 others for
  ad-hoc use). Per-view parameter support (endpoint-type/response-type enums,
  filter requirements) encoded per-endpoint against the live OpenAPI spec, not
  guessed — invalid combinations fail with a helpful message instead of a raw
  400. Live-validated on a lab tenant: 9 of 13 views return real `200`s
  (`application_metric`, `internet_metric`, `rum_metric`, `rum_score`,
  `zoom_participant_score`, `zoom_qos`, plus the two extractor-shared views);
  `agent_properties`/`route_hops` need a real `agent_uuid`/`site_id`/`probe_uuid`
  filter to return data (the tool correctly refuses without one);
  `zoom_participant` 400s on an upstream backend quirk (`Unrecognized name:
  office_location_tag`) unrelated to request params — a PAN-side issue, not
  ours. 23 tests.

- **Panorama → SCM migration tool (`scm_panorama_migrate`)** — proposed
  2026-09-16. Modelled on
  [PaloAltoNetworks/panos-to-scm](https://github.com/PaloAltoNetworks/panos-to-scm),
  which PAN archived on 2024-08-31 (it's read-only now, and the maintained
  version is internal-only). Goal: an MSSP-safe, multi-tenant replacement
  built on this server's existing pan-scm-sdk client cache and write-safety
  pattern.
  - **Input:** a Panorama device-group or local PAN-OS XML export (uploaded
    file path). Parsing is offline, so it needs no Panorama API access.
  - **Scope (parity with panos-to-scm):** tags, addresses/groups,
    services/groups, application filters/groups, EDLs, HIP objects/profiles,
    URL categories, security profiles + profile groups, and security, NAT,
    app-override and decryption rules, with source rule order preserved.
  - **Improvements over upstream:** `dry_run` by default with a mandatory
    `ticket_ref` (upstream has no dry run); an up-front migration plan that
    maps each item to its SCM folder/snippet and lists conflicts; dedupe
    against objects already in the target folder, reusing
    `scm_object_search`/config index; merge/replace/append/skip conflict
    modes (as upstream); an automatic `scm_config_backup` before the push,
    with `scm_config_rollback` as the undo; a post-migration `scm_config_diff`
    plus `scm_bpa_assess`/`scm_rule_shadow_audit` on the result.
  - **Known SCM API gaps to handle explicitly (from upstream):** SCM only
    accepts profile *groups* for rules, so single profiles get wrapped in a
    generated group. Antivirus/WildFire can't be created as one profile via
    the API, so they're flagged for manual creation. Security-rule schedules
    aren't supported by the API, so they're reported as dropped. Any
    unmapped PAN-OS feature is listed in the plan, never dropped silently.
  - **Out of scope for v1:** Cisco ASA/Firepower input (upstream WIP),
    device/network/template-stack config, Panorama API live pull.
  - **Open questions:** a single async job with `scm_job_status` progress
    (likely, for large rulebases) vs a synchronous call; and whether this
    joins the Planner epic as a multi-step plan.
- ✅ **Reference preflight for `scm_config_clone`** — shipped 2026-09-25
  (`audit/clone_preflight.py`). Found in a 2026-09 tenant-to-tenant restore
  where every create succeeded but each push (~40 min) failed on one dangling
  reference at a time. The clone now resolves every reference against the
  target before any write, with `on_missing_reference` (`fail`/`skip_object`/
  `strip_member`), "unverifiable" for 403 catalogues, and a forward-trust
  certificate check for enabled decrypt rules (`on_missing_trust_cert`).
  The "truncated applications list" turned out not to be truncation: the
  applications API lists leaf App-IDs only (each twice), and container apps
  are reachable only via the children's `container` field. Follow-ups:
  - The extractor's custom-app filter tests `snippet != "predefined"` but
    PAN content is `predefined-snippet`, so every backup carries the full
    ~11k-row App-ID catalogue. Fix the filter so custom apps are what's kept.
  - The backup carries no application filters, so a rule using one resolves
    only if the target already has it. Back them up and clone them.
  - `name_prefix` renames cloned objects but not the references to them; the
    preflight flags this, but the cloner should rewrite the references.
  - Not yet checked: address/address-group, zone and tag references.
  - SCM candidate validation (checked 2026-09-25 against pan.dev `1f192ff`):
    there is no public endpoint. The jobs schema lists a `Validate` job
    type (`type_str`), presumably the UI push dialog's Validate button, but
    no documented call starts one, and 1,334 lab-tenant jobs include none.
    `candidate:push` has no validate-only or dry-run field. The undocumented
    `GET config-versions/candidate` (used by pan-os-php) returns version
    metadata, not config. Probed 2026-09-29 on an empty lab tenant (no
    config versions or jobs): POSTs to `config-versions/candidate:validate`,
    `config-versions/validate`, `config-versions:validate`,
    `candidate:validate`, `jobs:validate` and `validate` on both the `sse`
    and `config/operations` bases all matched the responses for made-up
    paths (backend 404 under `config-versions/`, otherwise gateway 403).
    Probing GETs tells you nothing: anything under `config-versions/` hits
    `GET /{version}` (200 `[]`), and the gateway 403s every method without
    a route. The gateway 403 couldn't be confirmed as "no route" rather
    than RBAC without a positive control on a real POST route. Next step:
    capture the UI Validate request in the browser; until then the local
    resolver is the only pre-push check.

### Blocked

- **Branch NAT IP, PA side (IKE peer IP per circuit)** — blocked on a service
  account with an Insights/monitor read role (Insights `tunnel_list` 403 for
  view-only roles).
- **Multitenant Notifications** — `sase/mt-notifications`, 10 paths. Gateway path
  confirmed live but current service accounts get 403.
- **SPI in documents and dashboards** — AS-BUILT §3 + NOC dashboard SPI column.
  Blocked on SPI-enrolled MSP-mode service account (401 on `/mt/sp-interconnect/*`).
- **5G Manage/Monitor** — 47 paths.  Needs 5G-enrolled tenant.
- **cloudngfw/aws** — 135 paths.  Deferred until lab tenant with Cloud NGFW
  entitlement exists.
- **`applications/list` + `locationsUsers`** — both reject or 500 on PAN's own
  spec examples.  Blocked on upstream spec refresh.
- **Planner Phase 2 sub-plan delegation** — domain-scoped executor wiring exists
  (`build_catalog(domains=[...])`).  Live smoke pending Anthropic API key in
  `.secrets.toml`.

## Epic: Planner Agent — Agentic Orchestration Layer for scm-harbourmaster-mcp

**Goal** — build a Planner Agent layer above the existing 125-tool
scm-harbourmaster-mcp MCP server, following the PANW "NetSec Agents on SCM" taxonomy
(Persona → Planner → Expert Agents → Actions → Triggers), extended with an
MSSP cross-tenant orchestration layer that PANW's native single-tenant model
does not cover. The Planner decomposes high-level operator intent into
dynamic, persisted, auditable plans executed against the existing MCP tools.

**Architecture principle** — build the Planner loop once; expose three
trigger surfaces (scheduled/cron, conversational NLQ, IR/webhook) as entry
points into the same loop. Do not build three separate agents.

**Differentiation (do not cut)** — cross-tenant fan-out, cross-tenant anomaly
rules, and customer-specific reporting are the
defensible layer versus PANW's roadmap. Single-tenant planning polish is
secondary.

Spec/design docs live in `docs/planner-agent/` (ARCHITECTURE.md,
TOOL_MANIFEST.md).

### Phase 1 — Tool taxonomy & safety rails ✅ shipped 2026-07-15

Delivered as `src/scm_harbourmaster_mcp/resources/tools_manifest.yaml` (135 tools) +
the `scm_harbourmaster_mcp.planner` loader with the non-overridable write-approval
rule, and a CI coverage test that fails whenever a tool is registered
without a manifest entry. See docs/planner-agent/TOOL_MANIFEST.md for the
implemented schema, API, and domain groupings. The "enforce in the
execution layer" item is delivered at the API layer (`requires_approval()`
has no bypass; unknown tools raise) — the loop that calls it is Phase 2.

- [x] Create a tool manifest (`tools_manifest.yaml` or similar) covering all
  125 MCP tools with fields:
  - `access: read | write` — write tools: `scm_commit`,
    `scm_security_rule_create`, `scm_security_rule_delete`,
    `scm_address_create`, `scm_address_delete`, `dlp_restore`,
    `scm_config_rollback`, `scm_config_push_track`, `scm_config_clone`,
    `mssp_onboard_tenant`, `mssp_evict_tenant`, `scm_cert_import`,
    `scm_tls_profile_manager` (create mode), `scm_apply_ncsc_baseline`,
    `scm_attach_ncsc_profiles`, `scm_create_ncsc_snippet`,
    `scm_create_nist_snippet`, `scm_reload`, `scm_restart`. Everything else
    defaults to read.
  - `domain`: one of deployment | threat_coverage | operational_health |
    posture_compliance | config_change | licensing | sdwan | certificates |
    identity | pab | dlp (mirrors PANW Expert Agent domains plus
    MSSP-specific ones)
  - `scope: tenant | cross_tenant` — cross_tenant: `mssp_tenant_dashboard`,
    `mssp_list_tenants`, `scm_cert_lifecycle`, `scm_mt_analytics`,
    `scm_incident_summary`, `scm_discover_tenants`,
    `scm_licence_forecast`, `scm_service_maintenance`, `scm_spn_bandwidth`
    (all_tenants mode)
  - `idempotent: true | false` and `retry_policy: retry | fallback |
    fail_fast`
  - `known_failure_modes`: free text (e.g. `scm_remote_network_list` —
    Pydantic validation error on names with spaces and
    `bgp_peer.same_as_primary` field; fallback = `scm_ike_gateway_list`
    correlation)
- [x] Enforce a hard rule in the execution layer: `access: write` tools
  ALWAYS require explicit human approval before execution, regardless of
  trigger type. No config flag can disable this in v1.
- [x] Document per-domain tool groupings so the Planner loads only one
  domain's tools (~15–20) into context per sub-plan, keeping total loaded
  tools under the 128-tool Copilot Studio ceiling.

### Phase 2 — Planner loop core ✅ core shipped 2026-07-15

Delivered as the `scm_harbourmaster_mcp.planner` package: schema/store/executor/
engine/loop (see docs/planner-agent/ARCHITECTURE.md status note). Claude
Opus 4.8 with structured outputs is the reasoning engine; the in-process
FastMCP backend is the first ToolBackend (Streamable-HTTP later). The
sub-plan delegation item is partial: `build_catalog(domains=[...])`
scopes context per domain, but a dedicated domain-executor wiring lands
with the Phase 3a MVP. Live-engine smoke pending an anthropic_api_key
in .secrets.toml (same credential as scm_ai_compliance_advisor).

- [x] Implement the loop: Trigger → Intent parse → Plan generation →
  Execute step → Observe result → Revise plan → repeat → Synthesis →
  Report/notify.
- [x] Define a persisted Plan schema (JSON, stored per run): `plan_id`,
  `trigger_type`, `trigger_payload`, persona/service-account identity,
  `tenant_scope` (single ID, list, or "all"), `goal`, ordered `steps[]` each
  with `{step_id, domain, tool, params, status:
  pending|running|ok|failed|skipped, result_summary, retries, started_at,
  finished_at}`, `revision_history[]`, `final_report_ref`.
- [x] Use Claude via the Anthropic API (tool-use) as the reasoning engine;
  the existing scm-harbourmaster-mcp MCP server is the tool backend over Streamable
  transport (reuse the Copilot Studio transport work).
- [ ] Implement sub-plan delegation: Planner selects domain → domain-scoped
  executor runs with only that domain's tools loaded.
- [x] Failure policy in the loop: max 2 retries per step; on
  validation/schema errors use the manifest's fallback tool; on server
  timeout mark step failed and continue where the plan allows; always finish
  with a partial report rather than aborting the run. Plans must be
  resumable after MCP server restart (the server has known timeout/crash
  behaviour — treat this as a first-class scenario, and allow the Planner to
  invoke `scm_reload`/`scm_restart` as a recovery action with approval).
- [x] Full audit trail: every tool call, param set, and result summary
  persisted against the `plan_id`.

### Phase 3 — Trigger surfaces (priority order)

- [x] **3a. Scheduled ops agent (MVP — build first).** ✅ shipped 2026-07-15
  (`scm-planner-nightly`; acceptance findings fired on live estate data —
  see CHANGELOG). Email delivery still TODO (Slack webhook + file done).
  Original spec: Cron-triggered
  nightly run per tenant: tier assessment (`mssp_tier_assess`), cert scan
  (`scm_cert_scan`), licence expiry (`scm_license_info` /
  `scm_licence_forecast`), incident summary (`scm_incident_search`),
  job/change audit (`scm_list_jobs`). Output: ranked Markdown digest per
  tenant plus an estate-level summary, delivered via email/Slack. Findings
  ranked by severity then customer tier (Gold first — tier ranking since
  removed; findings now rank by severity then tenant name). Acceptance test: the
  agent must autonomously surface a finding of the class "NFR licences
  expiring within 90 days across multiple tenants" and "licensed-but-unused
  tenant shell".
- [x] **3b. Conversational copilot.** ✅ shipped 2026-07-15 as MCP tools —
  `scm_planner_run` (NLQ goal → the same PlannerLoop with Claude as the
  reasoning engine; write tools execute ONLY when named in
  approved_write_tools, the per-run explicit human approval),
  `scm_planner_status` (progress polling / run list), `scm_planner_result`
  (final synthesis). Any chat client on this server — Claude Desktop over
  stdio, Copilot Studio over the Streamable transport — is the frontend;
  a dedicated Slack/Teams bolt bridge posting NLQs into the same tools
  needs workspace credentials and remains open. Original spec: Slack/Teams frontend posting NLQ
  triggers into the same Planner loop; responses stream plan progress and
  final synthesis.
- [x] **3c. IR-triggered agent (last).** ✅ shipped 2026-07-16 — alert →
  keyword classifier → pre-built READ-ONLY triage template through the
  same PlannerLoop (tunnel-down runs exactly the spec's example set +
  scm_incident_rca; plus cert-expiry, licence-expiry, config-change,
  connectivity-degraded, generic). Surfaces: scm_ir_trigger MCP tool and
  POST /webhook/ir on the HTTP transport (behind the existing auth
  middleware). Templates are structurally write-free: the triage executor
  has no approver, and a test asserts no template names a write tool.
  Live-validated on a lab tenant. Original spec: Webhook from MT Monitor alerts /
  `scm_incident_search` into the Planner with pre-built triage plan
  templates (e.g. tunnel-down → `sdwan_wan_ip_summary`,
  `scm_ike_gateway_list`, `scm_list_jobs` recent changes, `sdwan_events`).
  Read-only triage in v1; remediation suggestions require approval.

### Phase 4 — MSSP cross-tenant layer ✅ shipped 2026-07-16

Delivered as `planner/estate.py` + `scm_estate_check` + the
`scm-planner-estate` console script: bounded-concurrency per-tenant
sub-plans at tier depth (bronze ⊂ silver ⊂ gold; Gold's BPA/NCSC/ISO
share one snapshot via the extractor TTL cache) — tier depth since removed;
every tenant now runs the full check set — plus the three
cross-tenant anomaly rules from the spec. Read-only by construction.

- [x] Estate fan-out: a single trigger (e.g. "morning estate check")
  generates per-tenant sub-plans across all loaded tenants
  (`mssp_list_tenants`), executes with bounded concurrency, aggregates
  results.
- [x] ~~Tier-aware planning: read contracted tier per tenant and scope check
  depth accordingly.~~ Removed — every tenant now runs the full check set:
  licensing + cert + connectivity basics, posture/compliance + change audit,
  BPA/NCSC/ISO27001 assessments + DLP/SSPM posture.
- [x] Cross-tenant anomaly rules: flag inconsistencies invisible to
  per-tenant analysis (e.g. tenant with SD-WAN topology but zero licences;
  duplicate NFR licence sets expiring across tenants; tenants with zero
  config jobs but full licence bundles).

### Constraints & risks

- Read-only operation for the first month of production use, even where
  approval gates exist. Write actions (`scm_commit` etc.) enabled only after
  the audit trail has been reviewed.
- PANW is building a native single-tenant Planner into SCM (NetSec Agents
  on SCM roadmap). Re-validate scope against PANW's timeline before
  investing beyond Phase 2 polish; keep investment weighted toward Phase 4
  (MSSP layer) and customer-specific reporting.
- MCP server stability is a known risk (timeouts, crashes, full disconnects
  observed); plan persistence + resumability is a hard requirement, not a
  nice-to-have.

### Estimate

- Credible scheduled-ops MVP (Phases 1, 2, 3a): ~4–6 weeks part-time given
  the Expert/tool layer already exists.

## Epic: Docker parity & multi-LLM integration

**Goal** — make the Docker image do everything a local install does, then
open the tool set to any LLM platform rather than only Claude: ChatGPT,
Microsoft Copilot, Gemini/Antigravity, DeepSeek, Qwen and Moonshot Kimi.
Two server surfaces cover them all: a Streamable HTTP MCP endpoint and an
OpenAI-compatible REST tool gateway, behind one auth and scope layer. No
platform-specific server code.

**Order** — Docker Phase 1 → A → B+C → Docker Phases 2–4 → D → E.

### Docker Phase 1 — Parity with a local install

The image builds, but the runtime user (`scm-mcp`, no home directory) can't
write to the root-owned `/app`. Every relative or home-based path therefore
fails. That covers `backups/`, `baselines/`, `reports/`, `logs/`, the plan
and index dirs, and `~/.cache`. Backup, drift, MSR, AS-BUILT, config-index
and planner tools all fail on write, without a clear error.

- One `data_dir()` helper behind every hardcoded `Path("backups")` /
  `Path("reports")` / `logs/`; the existing `SCM_MCP_*_DIR` variables stay as
  overrides.
- `WORKDIR /data` (fixed UID), `HOME` and `XDG_CACHE_HOME` under it;
  `settings.toml` + `.secrets.toml` mounted read-only into `/data`.
- `tini` entrypoint, so `scm_restart`'s SIGTERM isn't ignored by PID 1.
- Allowlist `.dockerignore` (today the build context includes `.env`,
  `.secrets.toml` and `backups/`), pin the `uv` image by version and digest,
  drop the stale `EXPOSE 8000`, and stop shipping `settings.example.toml` as
  the in-image default.
- The systemd unit (`security/hardening/scm-mcp.service`) has the same bug:
  it allows writes only to `logs/` and `/run/scm-mcp`. Fix both here.

### Docker Phases 2–4 — Full image, compose, CI smoke test

- **`full` build target** (`:X.Y.Z-full`): Node, `@mermaid-js/mermaid-cli`,
  system Chromium and a `--no-sandbox` puppeteer config. Without it,
  AS-BUILT/HLD diagrams are silently dropped. Needs a Trivy policy decision
  first, because the current gate fails the build on any HIGH or CRITICAL
  finding.
- **`deploy/docker-compose.yml`**: an `http` service with a `/health`
  healthcheck; a `planner` profile service run from host cron; a named `data`
  volume; hardening matching the systemd unit (`read_only`, `cap_drop: [ALL]`,
  `no-new-privileges`). Add a `docker run -i` stdio snippet for desktop
  clients.
- **Container awareness**: `scm_reload` and the CLI server menu (which calls
  `pgrep` and `uv run`) say "pull a new image" instead of failing. An optional
  `compose.dev.yml` bind-mounts `src/` for live reload.
- **CI smoke test** in `docker-build.yml`: `/health`, an MCP `initialize`
  over stdio, and one tool that writes a file.

### Phase A — Streamable HTTP at `/mcp` ✅ shipped 2026-10-09

`/mcp` (Streamable HTTP) now sits beside `/sse` on `scm-mcp-http`, behind
the same auth, with an optional stateless mode (`SCM_MCP_HTTP_STATELESS`).
Building it uncovered a bug in the existing server: FastMCP's localhost-only
Host check 421'd every remote client. `SCM_MCP_HTTP_ALLOWED_HOSTS` fixes it.
Still to verify against the real clients: Copilot Studio, ChatGPT connectors
(which need OAuth, Phase C), Gemini CLI and Antigravity.

### Phase B — REST tool gateway under `/v1`

- `GET /v1/tools?format=openai|gemini&toolset=…`: schemas generated from the
  live tool registry. `openai` covers DeepSeek, Qwen, Kimi, the OpenAI API,
  Ollama, vLLM and Groq.
- `POST /v1/tools/{name}/call`: runs in-process (the same path as
  `InProcessBackend`, made async-safe).
- `GET /v1/openapi.json`: OpenAPI 3 for ChatGPT custom GPT Actions;
  `?version=2` gives Swagger 2.0 for Power Platform connectors and
  Microsoft 365 Copilot.
- A toolset is required, with a small default profile; 177 tools is too
  many for most function-calling models. Large outputs are capped and
  return a continuation token.

### Phase C — Auth & safety (ships with B, never after it)

- REST is read-only by default; writes need `SCM_MCP_HTTP_REST_WRITE=1`
  (the SSR webhook precedent), and `scm_commit` is never exposed over REST.
- Per-key scopes: read/write, allowed tenant IDs and allowed toolsets. A key
  issued for one customer can't reach another tenant.
- OAuth 2.1 per the MCP authorization spec, alongside API keys and Entra ID.
  ChatGPT connectors are believed to need it (to verify).
- JSONL audit log (key, tool, tenant, argument hash, outcome) in the data
  dir; per-key rate limits.
- Data residency: tool output leaves our control once a third-party LLM has
  it. DeepSeek and Moonshot are China-hosted; Qwen depends on the Alibaba
  region. Customer-facing docs name the providers. An advisory per-tenant
  `allowed_llm_providers` setting is recorded in the audit log.

### Phase D — Examples & client config

`examples/openai_compatible_agent.py` (DeepSeek/Qwen/Kimi/OpenAI via
`base_url`), `examples/gemini_agent.py`, `deploy/copilot-studio/` (Power
Platform connector), plus MCP config snippets for ChatGPT, Gemini CLI,
Antigravity, Qwen Code, Kimi CLI and Claude. Placeholder tenants only, and
every snippet uses a toolset profile.

### Phase E — Advisor & planner on other models (optional)

`ai_advisor.py` and `planner/engine.py` are hardwired to the Anthropic SDK.
Add an `llm_provider` setting with an OpenAI-compatible backend and
`base_url`.

### To verify before building

- Copilot Studio: SSE status, and the `x-ms-agentic-protocol` connector field.
- Power Platform: is Swagger 2.0 still required?
- ChatGPT connectors: auth options (OAuth only?) and transport.
- Antigravity MCP config path and remote-server key.
- Which JSON Schema keywords Gemini function declarations reject.
- Tool count limits per platform, which set the default toolset size.

## Snippet template backlog

MSSP-helpful SCM snippet templates beyond the existing NCSC/NIST pair
(`scm_create_ncsc_snippet` / `scm_create_nist_snippet` in
`tools/ncsc_baseline.py`), ranked by value ÷ effort:

1. **ISO 27001:2022 snippet** — parity with NCSC/NIST; `audit/iso27001_controls.py`
   already has the Annex A catalogue + BPA mappings.
2. **NHS DSPT snippet** — same parity gap; `audit/dspt_controls.py` already maps
   Standards 7–10 to BPA checks.
3. **PCI DSS v4.0 CDE snippet** — net-new framework: zone protection + decryption
   exclusions for card-data flows, strict egress logging, no-decrypt rule for
   payment processors.
4. **Ransomware-readiness snippet** — WildFire ransomware detonation signatures,
   DNS Security C2/DGA sinkholing, decryption coverage for SMB lateral movement,
   backup-traffic isolation guidance.
5. **Zero Trust segmentation baseline snippet** — App-ID default-deny
   microsegmentation + dynamic-address-group tagging convention (NIST SP 800-207).
6. **Standalone SSL/TLS decryption best-practice snippet** — forward-proxy and
   inbound-inspection profiles plus a no-decrypt exclusion list, as one snippet.
7. **Standalone DNS Security / sinkhole snippet** — split out of anti-spyware
   so it's a shared building block across the frameworks above.
8. **GlobalProtect / remote-access hardening snippet** — HIP-based posture +
   MFA-enforcement checks; no existing snippet touches remote access today.
9. **"Day-1 Fast Start" onboarding snippet** — minimal safe-by-default bundle
    for a brand-new tenant before its full baseline is applied.

**Do this before framework #3**: extract a shared `build_and_create_snippet()`
helper — NCSC/NIST already duplicate ~130 lines of create/dry-run/error-handling
logic nearly verbatim; a third framework copying it verbatim is the point to
parameterize by a `TemplateSet`-like dataclass instead.

**Standing caveat for all 9**: `client.snippet.associate_folder()` /
`disassociate_folder()` raise `NotImplementedError` in the installed SDK
(0.15.1) — every future `scm_create_*_snippet` tool can create and populate a
snippet but cannot attach it to a tenant folder programmatically; that stays a
manual portal step until PAN ships the endpoint. Note `mssp_onboard_tenant`'s
current "associate" step doesn't even attempt the SDK call today — it just
logs success unconditionally (existing tech debt, not fixed here).

**Reusable references**: [pan-scm-sdk](https://github.com/cdot65/pan-scm-sdk)
([Snippet resource docs](https://cdot65.github.io/pan-scm-sdk/sdk/config/setup/snippet/)) ·
[paloaltonetworks-automation-examples](https://github.com/cdot65/paloaltonetworks-automation-examples) ·
[cdot65.scm Ansible collection](https://cdot65.github.io/pan-scm-ansible/) ·
[terraform-provider-scm](https://github.com/PaloAltoNetworks/terraform-provider-scm) /
[terraform-scm-access-modules](https://github.com/PaloAltoNetworks/terraform-scm-access-modules) ·
[Built-In Best Practices docs](https://docs.paloaltonetworks.com/cloud-management/administration/overview/built-in-best-practices) ·
[SCM API Best Practices](https://pan.dev/scm/docs/api-best-practices/).

## How additions happen

1. `scm_check_updates` (or the spec-drift section) flags a new family/file.
2. Regenerate the catalog: `uv run --with pyyaml python scripts/gen_endpoint_catalog.py`.
3. Scaffold: `uv run --with pyyaml python scripts/gen_tool_from_spec.py <family>`.
4. Curate: consolidate endpoints into few ergonomic tools (tool count is
   client-visible context), add graceful 401/403/404/5xx rendering, live-test
   against a lab tenant, then register in `server.py` and `tools/reload.py`.
