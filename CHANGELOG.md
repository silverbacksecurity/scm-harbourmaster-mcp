# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Dry-run default and mandatory `ticket_ref` on every write tool**
  (`utils/write_safety.py`, new file) — the SSR write-safety contract already
  used by `scm_ssr_execute`, `scm_config_orch_*` and `scm_site_management` now
  covers the address and security-rule create/delete tools, `scm_commit`,
  `scm_config_push_track`, `scm_config_rollback`, the NCSC/NIST baseline and
  snippet tools, the Compliance, ADNSR and DLP writes, `scm_cert_import` and
  `scm_tls_profile_manager`. `dry_run` defaults to true and describes the
  change without writing (fetching the existing object where one exists);
  `ticket_ref` is required on every call, dry run included, is written to the
  structured audit log before the mutating request, and is never sent to SCM.
  The CLI menus prompt for the ticket reference. **Breaking** for callers that
  relied on these tools writing immediately: pass `dry_run=False` and a
  `ticket_ref`
- **`mssp_tenant_capabilities`** (`utils/capabilities.py`,
  `tools/capabilities.py`, new files) — sends one cheap read-only request per
  API family and classifies each as available, forbidden (RBAC 403),
  unprovisioned (404/424 plus family-specific codes such as Email DLP 400) or
  error (inconclusive), cached per tenant for 6h. AS-BUILT and MSR reports
  consult the cache and skip known-forbidden or unprovisioned sections up
  front instead of discovering them mid-run; a tenant that was never probed
  behaves exactly as before. Part of the `mssp` toolset
- **Offline cassette integration suite** (`tests/integration/`) — drives
  registered tools through the real `requests` stack against recorded,
  placeholder-only responses for the known API quirks: Compliance region
  selection, Email DLP unprovisioned 400, Insights DATA10003/DATA10005, RBAC
  403, SDK `list()` limit, and the `/sse/config/v1` base. No credentials or
  network, so it runs in the default `uv run pytest` (`-m integration` to
  select). Adds `responses` as a dev dependency
- **Unit coverage for BPA checks and the deployment, MSSP, NCSC baseline and
  object/security write tools** — overall coverage 45% → 54%
- **GlobalProtect & network infrastructure in config backup/clone**
  (`tools/audit.py`, `audit/cloner.py`, `audit/extractor.py`, `cli_ops.py`) —
  `scm_config_backup` now persists the mobile-agent stack (auth settings,
  tunnel/agent/forwarding profiles, portal/gateway infrastructure settings,
  global GP settings), identity profiles (SAML/Radius/LDAP/authentication),
  and network infrastructure (IKE/IPSec crypto and QoS profiles, URL access
  profiles, internal DNS servers, bandwidth allocations, BGP routing config,
  GP IP-pool network locations). The two backup writers share one
  `backup_resource_payload()` helper so they can no longer drift apart.
  `scm_config_clone` restores the GP layer into the fixed `Mobile Users`
  folder — with the folder passed as a create() kwarg for the resources whose
  SDK models forbid a folder field in the payload — and identity/network
  infrastructure into the customer folder or `Remote Networks`. BGP routing
  and global GP settings are backup-only (singleton objects with no
  create path), and network locations have no SDK create method yet; both
  are documented in the tool docstrings. 7 tests
- **Toolset filtering and read-only mode** (`toolsets.py`, new file) — the
  server registers every tool on every client, ~164 names into every context
  window. Named toolsets — `core`, `objects`, `security`, `network`,
  `deployment`, `audit`, `compliance`, `ncsc`, `posture`, `insights`, `mssp`,
  `sase`, `ngfw`, `dlp`, `sdwan`, `ops`, `planner` — plus the `noc` / `grc` /
  `config` convenience profiles trim that down. Selectable via
  `enabled_toolsets` in `settings.toml`, the `SCM_MCP_ENABLED_TOOLSETS` env
  var, or `scm-mcp --toolsets a,b`; empty means all, so existing deployments
  are unchanged. `core` (tenant/folder discovery), `scm_reload` and
  `scm_restart` are always registered, and an unknown name fails at startup
  with the valid choices. `read_only` (`SCM_MCP_READ_ONLY=true` /
  `--read-only`) removes every write-capable tool after registration — the
  read/write split comes from the Planner tool manifest, the single
  classifier every registered tool already has, so read-only mode cannot
  drift from the planner's approval gates (a name/schema heuristic was tried
  first and missed `scm_compliance_framework` within one commit; the parity
  test that caught it stays). `scm_reload` re-applies the same filter on
  re-registration, and the active toolsets are logged at startup. 17 tests
- **MCP ToolAnnotations on every registered tool**
  (`utils/tool_annotations.py`, new file) — every tool now carries the MCP
  hint fields: `readOnlyHint` from the planner manifest's `access` (write
  tools that only save a local report file still count as read-only),
  `destructiveHint` and `idempotentHint` from explicit per-tool sets
  (deletes, rollbacks, SSR changes, planner runs, …), `openWorldHint` false
  only for tools that touch nothing but this server's own process state, and
  a human-readable `title` derived from the tool name. Applied centrally in
  `register_all_tools` so hot reload re-applies them, and a coverage test
  fails when a registered tool has no classification. 12 tests
- **Tenant label or settings-key as `tenant_id` on every tool**
  (`utils/tool_decorator.py`, `auth/oauth.py`) — every tool taking
  `tenant_id` now accepts the numeric TSG ID, a `settings.toml` tenant key,
  or a tenant label; the value resolves to the numeric ID before the client
  is looked up, so a label such as `acme-labs` works everywhere the raw TSG
  ID does. 17 tests
- **Compliance Center region handling** (`tools/compliance.py`,
  `config/settings.py`) — the Compliance API documents `X-PANW-Region` as
  required but does not enforce it: a missing or misspelled value returns
  HTTP 200 with an empty payload, so a report silently reads "this tenant is
  not compliant" when the truth is "we asked the wrong region" (the
  vocabulary is case-sensitive and differs from Insights: only `uk` works).
  Every Compliance Center request now carries the header from a new
  per-tenant `compliance_region` setting, validated against the four
  documented values so a typo fails at load; when unset, the region is
  auto-discovered once per tenant per process by probing
  `/overall-compliance` in each region (at most four extra GETs, cached,
  best-effort). Reports detect the all-empty case and state that the
  framework has not been assessed in that region instead of printing zeros,
  and carry a one-line provenance footer naming the region and how it was
  resolved. 24 tests
- **`scm_policy_optimizer_rules` / `scm_policy_optimizer_rule`**
  (`tools/policy_optimizer.py`, new file) — wraps the new Policy Optimizer API
  (`GET /policy-optimizer/v1/security-rules[/{id}]`, announced in the SCM API
  release notes for 2026-08 and split into its own pan.dev spec on 2026-08-18;
  not present in pan-scm-sdk 0.15.1). Same host and `_bearer_session_for`
  pattern as `tools/config_cleanup.py`. The list tool ranks analysed rules by
  recommendation count then traffic; the by-ID tool renders the original rule
  alongside the narrowed, application-specific replacements the optimizer
  suggests in its place — the API side of App-ID cleanup. Read-only: accepting
  or disabling a recommendation isn't exposed by this API family.
  Live-verified against three lab tenants, which surfaced three quirks now
  handled and documented: this API's manager sentinel is `"cloud_managed"`
  where the sibling Config Cleanup API wants `"SCM"` (the wrong one 404s
  "Manager not found"); `recommendation_count` under-reports in the list
  response (a rule listed as 0 returned 2 from the by-ID endpoint), so the
  renderer emits an explicit caveat rather than implying a clean rule; and
  `name`/`action`/`location` arrive as `""` rather than absent, so a
  placeholder helper keeps table cells from rendering blank. 20 tests
- **`scm_zerohit_rules`** (`tools/config_cleanup.py`, new file) — wraps
  pan.dev's brand-new Config Cleanup API (`GET /config-cleanup/v1/zerohit-rules`,
  first seen on pan.dev 2026-08-14, not present in pan-scm-sdk 0.15.1) at
  `api.strata.paloaltonetworks.com/posture` — a different host than the usual
  `api.sase.paloaltonetworks.com` — reusing the shared `_bearer_session_for`
  helper (`audit/extractor.py`) the same way `tools/mt_interconnect.py` does.
  Renders a markdown table of zero-hit security/NAT rules sorted by
  `days_with_zero_hits` descending, discloses the API's async-analysis
  status (`in_progress`/`failed`) so results aren't mistaken for live, and
  degrades gracefully on 401/403/404/500. Hand-written rather than
  scaffolded — a single endpoint wasn't worth running the generic scaffolder
  against the full 1,236-path `scm/config` family. 9 tests
- **`scm_rule_shadow_audit`** (`tools/audit.py`) — standalone whole-rulebase
  shadow audit, no drift baseline or pending commit required (unlike
  `scm_commit_preview`, which only checks rules a pending change touches).
  Extracts the live rulebase and checks every enabled security rule against
  every rule that evaluates before it, combining `security_rules_pre` +
  `security_rules_post` into one ordered list before calling
  `find_shadowed_rules`, matching Panorama/SCM's actual pre-then-post
  rulebase evaluation order. Rendered via the new `render_shadow_audit()`
  (`audit/commit_preview.py`), with an honest coverage-caveat section
  listing any addresses that couldn't be resolved to concrete IP ranges.
- **CIDR-aware rule-shadow detection** (`audit/commit_preview.py`) —
  `find_shadowed_rules` previously compared security-rule source/destination
  fields by literal string-set containment only (`"10.0.0.0/8"` didn't shadow
  `"10.1.2.0/24"` — different strings, same subnet, so real shadowing went
  undetected). Now resolves real CIDR containment via stdlib `ipaddress`
  (`_addr_covers`, `_is_subnet_of`, `_parse_ip_literal` — the latter also
  parses hyphenated ranges like `"10.0.0.1-10.0.0.4"` via
  `ipaddress.summarize_address_range`), plus recursive address-group
  membership resolution (`build_address_index`, handling nested groups and
  detecting membership cycles). FQDN addresses, `ip_wildcard` addresses
  (non-contiguous bit masks), dynamic (tag-filter) groups, and any other
  unresolvable name fall back to the old literal-string comparison for that
  pair rather than risk a false "shadowed" claim. Rule pairs where either
  rule negates source or destination are now skipped entirely from shadow
  analysis, since the containment math doesn't model inverted matching — a
  false claim there would tell an operator a rule is dead when it isn't. New
  keyword-only `addresses`/`address_groups`/`index` params on
  `find_shadowed_rules` default to `None`; omitting them disables
  address-*group* resolution only — a bare CIDR/IP literal in source/
  destination still gets real containment treatment either way, since
  parsing a literal needs no index. Also fixes a real gap in the pre-existing
  `scm_commit_preview`: it used to call `find_shadowed_rules` twice — once on
  `security_rules_pre` alone, once on `security_rules_post` alone — so a
  pre-rulebase rule shadowing a later post-rulebase rule was never caught,
  since the two separate calls never compared a pre-rule against a post-rule
  at all. Fixed to one call over the combined list, matching
  `scm_rule_shadow_audit`'s approach.
- **Remote Networks / Mobile Users scope-exclusion in shadow detection**
  (`audit/commit_preview.py`) — Remote Networks and Mobile Users are
  mutually exclusive Prisma Access enforcement pipelines (neither ever
  evaluates the other's traffic), but the rulebase extractor merges rules
  from both into one flat list for pre/post ordering. Before this fix,
  `find_shadowed_rules` compared rules purely by list position, so a
  Remote-Networks-only rule could be flagged as "shadowing" (making
  permanently dead) an unrelated Mobile-Users-only rule it can never
  actually affect — a false claim that `scm_rule_shadow_audit`/
  `scm_commit_preview` would have presented as "safe to remove", and that
  would additionally force `scm_commit_preview`'s verdict to 🔴 HIGH RISK.
  Found by an adversarial security-audit pass on this session's own CIDR
  upgrade (see below) and fixed the same day: rules whose folder is
  exclusively Remote Networks or Mobile Users are no longer compared across
  that boundary; a rule from the queried base folder (inherited by every
  child scope) still can. Also fixed: `scm_rule_shadow_audit`'s `rule_meta`
  and offender-ranking were keyed by bare rule name, so a name repeated
  across the pre-/post-rulebase (or across merged folders) could silently
  misattribute a shadow finding's folder/position/action to the wrong rule
  instance — now keyed by `rule_identity()` (SCM object id, falling back to
  a folder+rulebase+name composite), with the bare-name behaviour preserved
  as a fallback. And `scm_commit_preview`'s `focus_names` matched by bare
  name only, which could leak an unrelated, pre-existing shadow between two
  untouched same-named rules in the *other* rulebase into a commit-preview
  report just because a touched rule elsewhere happened to share that name
  — `focus` entries are now `(rulebase, name)` tuples. 32 new tests
  (18 → 41 in `test_commit_preview.py`, 9 new in `test_config_cleanup_tools.py`)

### Removed
- **Gold / Silver / Bronze service tiers** — the whole tier subsystem is gone as
  redundant with the compliance tooling that already reports the same posture
  per tenant (`scm_bpa_assess`, `scm_ncsc_assess`, `scm_iso27001_assess`,
  `scm_compliance_center`). Deleted `audit/tiers.py` (tier definitions, severity
  scoring, upgrade-gap analysis, `SNIPPET_TEMPLATES`) and its tests.
  - **Six MCP tools removed** (161 tools, down from 167): `mssp_tier_assess`,
    `mssp_tier_report`, `mssp_tier_comparison`, `mssp_upgrade_path`,
    `mssp_onboard_tenant`, `mssp_snippet_catalogue`. The last two were entirely
    defined by the tier snippet spec, so they had no content left once it went;
    `scm_folder_get` + `scm_snippet_list` cover what onboarding actually checked.
    `mssp_onboard_tenant` was also the only write tool in the MSSP domain, so the
    planner manifest's write-tool set shrinks by one.
  - **Breaking config change**: `TenantConfig.tier` is removed. `TenantConfig`
    is `extra="forbid"`, so a leftover `tier = "..."` line in `settings.toml`
    makes that whole tenant block fail validation and silently drop out of
    `load_all_tenant_configs()` — **delete the `tier` key from every
    `[tenants.*]` block** when upgrading.
  - **MSR pack**: compliance depth is no longer tier-gated. Every tenant now gets
    the framework score table *and* the 30-day trend annex; Bronze tenants
    previously got neither and an upsell note instead.
  - **Planner**: `estate.py`'s `tier_steps()` becomes `estate_steps()` — one
    uniform check set per tenant (licensing, certs, connectivity, BPA, change
    audit, NCSC CAF, ISO 27001, DLP/SSPM) rather than bronze ⊂ silver ⊂ gold
    depth, so previously-Bronze tenants now run the full sweep (~2-3 min each;
    the BPA/NCSC/ISO steps still share one snapshot via the extractor TTL cache).
    Nightly digests drop the `mssp_tier_assess` step and the `--no-tier-assess`
    flag, and rank findings by severity then tenant name rather than tier.
  - **CLI**: the MSSP Operations menu loses its "TIERS & MIGRATION" section
    (options 11-15 removed; Discover Tenants / PAN Service Status / Cross-Tenant
    Analytics renumber to 11/12/13). Tenant banners, listings, and
    `list-tenants` show the default folder where they showed the tier.

### Changed
- **Documented tool counts now derive from the live registry**
  (`scripts/check_tool_counts.py`, new file) — the "164 tools" figures in
  README.md and docs/ had drifted and are now placeholders regenerated from
  actually registering every tool on a throwaway FastMCP instance (no
  credentials needed), kept honest by a CI check and `test_tool_counts.py`.
- **Renamed the Python package and distribution** — `scm-mcp-mssp` is now
  **`scm-harbourmaster-mcp`**, and the import package `scm_mcp_mssp` is now
  `scm_harbourmaster_mcp`. A harbourmaster directs many independent vessels
  through one port without owning any of them, which is the MSSP shape this
  server has always had.
  - **Breaking for anything that imports the package directly**: update
    `import scm_mcp_mssp...` to `import scm_harbourmaster_mcp...`. Existing
    installs must be reinstalled, since the distribution name changed.
  - **Not breaking for MCP clients**: the console scripts keep their names
    (`scm-mcp`, `scm-mcp-http`, `scm-mcp-cli`, `scm-planner-nightly`,
    `scm-planner-estate`), so existing Claude Desktop / Cursor configs that
    invoke `scm-mcp` continue to work unchanged.
  - The `SCM_MCP_MSSP_MODE` environment variable is **unchanged**, so existing
    `.env` files and deployed units keep working.
  - SaaS-posture exports are now tagged `scm-harbourmaster-mcp/saas-posture@1`;
    the previous `scm-mcp-mssp/saas-posture@1` marker is still accepted on
    load, so older exports remain readable.
  - The IP-enrichment cache moved to `~/.cache/scm-harbourmaster-mcp/`. The old
    cache is not migrated and is simply re-populated on next use.
  - The GitHub repositories were renamed to `scm-harbourmaster-mcp` (public)
    and `scm-harbourmaster-mcp-dev` (private). GitHub redirects the old URLs,
    so existing clones and remotes keep working without changes.
  - The Docker/GHCR image name and the deployment paths under `/opt` and
    `/etc` are unchanged.

### Fixed
- **Commit preview and shadow audit flagged non-rules as shadowing**
  (`audit/commit_preview.py`, `tools/audit.py`) — snippet placeholder entries
  in a rulebase (id/name/folder only, which the SDK fills with allow/any
  defaults) and Internet-policy rules were compared as allow-all security
  rules, burying real findings under dozens of false shadows. Both are now
  skipped (placeholders identified from each folder's attached snippets), and
  `source_user`, `source_hip`, `destination_hip` and `category` now narrow
  coverage, so a HIP-, user- or category-scoped rule no longer "covers" an
  unscoped one
- **Config backups put every security rule in both pre and post**
  (`audit/extractor.py`) — cloud leaf folders (Mobile Users, Remote Networks,
  Explicit Proxy) ignore the position selector and return the whole effective
  rulebase for both queries, so a backup of any folder that includes them
  listed every rule twice and a clone recreated post rules as pre rules.
  Positions now come from container-folder queries (probing the defining
  folder of inherited rules, `Shared` → `Prisma Access`), with a leaf folder's
  own rules placed by their order relative to known post rules. The SDK
  validation-error REST fallback also forwarded `rulebase=`, which the API
  ignores; it now sends `position=`
- **Backups and clones missed profile groups and URL categories**
  (`audit/extractor.py`, `audit/cloner.py`) — rules and URL filtering profiles
  reference both by name, so a clone failed on every rule using a custom
  profile group. Backups now include `profile_groups` (REST, not wrapped by
  pan-scm-sdk 0.15.1); the cloner creates URL categories before URL profiles
  and profile groups before rules. The snippet object count read profile
  groups from a 404ing endpoint
- **Clone failures and silent duplicates found in a live tenant restore**
  (`audit/cloner.py`) — anti-spyware and vulnerability rules read back with
  `action: {}` (signature default) were rejected on create; the empty action
  is now omitted, which round-trips. SDK create models stricter than SCM (e.g.
  names with spaces) now retry the create over REST. Bandwidth allocations no
  longer send a `folder` the API rejects. GlobalProtect auth settings are
  checked for an existing name first: SCM accepts a duplicate under a
  generated `UserAuth_<ts>` name instead of reporting a conflict
- **BPA TP-007 read the grayware verdict before malware**
  (`audit/bpa_checks.py`) — a WildFire profile with `malware=block` and the
  usual `grayware=alert` was reported as not blocking malware
- **Insights skips the bare-body retry on DATA10003** (`tools/insights.py`) —
  a 400 carrying DATA10003 means the resource path is gone, so retrying
  without the time window could never succeed; the error now names the cause
- **Insights region-header normalisation** (`tools/insights.py`,
  `tools/ops.py`, `tools/msr.py`, `tools/mt_monitor.py`) — two vocabularies
  exist for the region: settings `insights_region` uses `eu`/`us`, the
  `X-PANW-Region` header wants `europe`/`americas` (`uk`/`sg`/`au` are
  both), and sending a settings key isn't rejected — the API answers 200
  with an empty result — so a mismatch is invisible. `tools/ops.py`
  hardcoded `eu` in one Insights path and passed the settings key raw into
  the header in another, so every call it made carried an unrecognised
  region; `msr.py` and `mt_monitor.py` quietly mapped a valid `americas` to
  `europe` via `dict.get` defaults. One normaliser now serves all four call
  sites (`insights.region_header()`, accepting either vocabulary). Also
  removed the dead `pa_bandwidth_consumption` candidate from
  `scm_spn_bandwidth`'s fallback chain (the resource name is gone upstream —
  DATA10003) and made `_insights_query` log non-200 responses instead of
  failing silently, which is how both defects went unnoticed. 10 tests
- **MSR compliance calls name the tenant** (`tools/msr.py`) — the MSR pack's
  two Compliance Center calls (`/summaries` and the per-framework
  `/overall-compliance-timeline`) did not pass `tenant_id`, so the pack's
  compliance sections could answer for the wrong tenant rather than the
  customer being reported on. Both calls now pass the TSG ID. 1 test
- **AS-BUILT §2.1 compute-location labels** (`audit/asbuilt_report.py`) — each
  location node was labelled with the network-locations API's `region` field,
  which holds the underlying cloud region rather than the Prisma location code,
  so two distinct locations could render identically (Ireland and UK both come
  back as `europe-west2`). Nodes now carry three lines: the display name, the
  location `value` that the Remote Network and Service Connection nodes already
  cite (`(eu-west-1)`), and the cloud region tagged with its provider
  (`GCP: europe-west2`). Which provider that field names varies by tenant — the
  same location returns GCP names for some and OCI (`uk-london-1`) or AWS
  (`eu-west-1`) names for others — so the provider is inferred from the
  region-name shape: AWS is `<geo>-<compass direction>-<n>`, OCI
  `<geo>-<city>-<n>`, and GCP has no hyphen before the trailing digit. Checked
  against all 67 distinct region values present in local backups: 38 GCP, 24
  OCI, 5 AWS, none falling through to the generic `Cloud:` prefix. §2.3's table
  was unaffected — it reads `aggregate_region`. 10 tests
- **`scm_config_versions` printed the wrong version number**
  (`tools/deployment.py`) — the Version column rendered the record's `version`
  field, which is the PAN-OS content release (`192-external`, near-constant
  across long runs of commits). The config version number lives in `id`, which
  is what `/running` reports and what `scm_config_rollback` loads, so the
  tool's own closing hint pointed at a value it never printed. The `◀ running`
  marker never appeared either: it looked up `running_by_scope[scope]`, but
  `scope` is a comma-separated list and the NGFW scope arrives separately in
  `ngfw_scope` — both forms are now split out and matched individually. Admin
  was also clipped to 10 characters, collapsing every account on a shared
  domain to one label; the first three columns are now sized to their content.
- **`scm_config_clone` could not create anything from a backup**
  (`audit/cloner.py`, `tools/audit.py`) — validating a real backup's sanitised
  objects against the SDK's own create models offline, 6 of 151 passed; the
  rest were rejected client-side before any API call. The rulebase was sent as
  `position`, but it is a `create()` kwarg the SDK spells per rule type
  (`rulebase=` for security/decryption/app-override, `position=` for NAT), and
  every `*CreateModel` is `extra="forbid"`, so the stray field rejected all 42
  security rules outright; it is now a per-type kwarg carried in `_RULE_ORDER`.
  `policy_type` and the extractor's `_folder`/`_position` provenance keys
  joined `_SYSTEM_FIELDS`; the source snippet/device is dropped before the
  target folder is set (it tripped "Exactly one of folder, snippet, or device"
  on every tag, HIP object, HIP profile and address); and PAN predefined
  objects are detected before sanitising and reported under their own
  "Skipped (PAN predefined)" row instead of counting as conflicts. Both backup
  writers also persisted the flat, always-empty `nat_rules` field rather than
  the extractor's `nat_rules_pre`/`nat_rules_post` split, losing every NAT
  rule; they now write the split keys, the flat one remains for older readers,
  and the cloner falls back to it only when neither split key is present. Same
  backup after the fixes: 106 of 125 cloneable objects valid, with the
  remaining deployment-family gaps reported per object.

## [0.13.0] - 2026-07-31

### Added
- **Site Management (NGFW device onboarding)** (`tools/site_management.py`,
  `scm_site_management`) — one `resource_type`-dispatched tool covering the
  new pan.dev API family (`config/setup/device-onboarding/v1`, added
  2026-06-26, previously zero tooling): **sites** (device/HA pair + property
  values), **properties** (customer-defined site metadata),
  **onboarding-rules** (ordered variable-resolution logic, plus a `:move`
  reorder action), and **site-groups** (organisational containers). Full
  CRUD on all four resource types via the same SSR write-safety pattern as
  `config_orch.py`: `dry_run=True` default with before/after diff, mandatory
  `ticket_ref` recorded via audit log + tool response only — never injected
  into the outgoing request body (the exact bug `config_orch.py` hit once
  already). Site `create` transparently wraps the tool's one-resource-per-call
  ergonomics into the live API's batch `{"sites": [...]}` envelope. Reuses
  the shared `_bearer_session_for` helper from `audit/extractor.py` rather
  than duplicating `config_orch.py`'s local copy. 32 tests
- **`scm_pab_msp_auth_profile`** (`tools/pab_msp.py`) — small addition
  filling the one gap in the already-tooled PAB-for-MSP family:
  `GET /mt/pab/tenant/auth_profile`. Read-only, reuses the existing
  `_render` envelope. 2 tests
- **SD-WAN WAN IP RFC1918 flagging + detected-public-IP ISP attribution** (`audit/asbuilt_report.py`, `audit/extractor.py`, `utils/ipenrich.py`) — AS-BUILT §4.2.1 now flags RFC1918 addresses on circuits marked `used_for=public` inline (independent of `enrich_wan_ips`, since it's a config-sanity check, not an external lookup). New §8.1.4 renders each ION's post-NAT detected public IP (previously only reachable via the standalone `sdwan_wan_ip_summary` tool, now shared via `extract_sdwan_detected_public_ips()` so the AS-BUILT pipeline gets the same data) with ISP/ASN attribution and flags configured-vs-detected mismatches (NAT/CGNAT). Also adds `"ripe"` (stat.ripe.net, free, no key) as a third `ip_enrichment_provider` alongside `ip-api`/`ipinfo`, deduplicated per /24 (v4) or /48 (v6) prefix since RIPE data is announced per-prefix. Live-tested against three lab tenants: one with no SD-WAN (confirms graceful degradation), one small SD-WAN deployment, and one larger multi-site SD-WAN deployment (16 sites, 53 WAN IP records) — including a real stat.ripe.net lookup to validate the RIPE response parsing against the actual API shape. 20 new tests (741 → 761)

### Changed
- Bumped `prisma-sase` dependency floor from `>=6.6.2b1` to `>=6.8.1b1`

## [0.12.0] - 2026-07-24

### Added
- **Non-interactive `scm-mcp-cli` subcommands + audit history log** (`cli_commands.py`, `cli_ops.py`, `history.py`) — `scm-mcp-cli backup|bpa|ncsc|asbuilt|audit-report --tenant KEY|--all-tenants` for cron/CI use, plus `list-tenants` and `history`. Report-generation logic is extracted out of the interactive menu handlers into Rich-free `run_*` functions in `cli_ops.py` so the menu and the new subcommands share one implementation instead of diverging. Also adds a local audit trail (`logs/cli_history.jsonl`, gitignored) recording backups, reports, tenant add/select, and server restarts from both the menu and the CLI, viewable via the new History (`H`) menu option or `scm-mcp-cli history`
- **`scm_adem_query`** (`tools/adem.py`) — general-purpose query tool over all 13 `access/adem` telemetry paths (agent properties/metrics/scores, application metrics/scores, internet metrics, nav traffic, route hops, RUM metrics/scores, Zoom participant/QoS), consolidating the family the way `scm_insights_query` did for Insights. `extract_adem` in the AS-BUILT/MSR extractor still covers `agent_score`/`application_score` internally; this tool adds ad-hoc access to those plus the 11 other paths. Per-view parameter support (`endpoint-type`/`response-type` enums, `filter` requirements) is encoded per-endpoint against the live OpenAPI spec rather than guessed, so an invalid combination fails with a helpful message instead of a raw 400. Live-validated on a lab tenant: 9 of 13 views return real `200`s with tenant-scoped data; `agent_properties`/`route_hops` correctly refuse without a real `agent_uuid`/`site_id`/`probe_uuid` filter; `zoom_participant` 400s on an upstream backend quirk unrelated to request params. 23 tests

### Fixed
- **Stale Dependabot cryptography cap + resolved SOC2 risk entry** — `dependabot.yml` ignored cryptography `>=47.0.0` forever (a leftover from when `pan-scm-sdk==0.15.0` pinned `cryptography<47`), silently blocking every legitimate update since `pan-scm-sdk==0.15.1` now requires `cryptography>=49.0.0,<50.0.0` (already installed). Cap updated to `>=50.0.0`. `soc2-controls.yaml` still listed the cryptography/OpenSSL CVE (GHSA-537c-gmf6-5ccf) as an open accepted risk long after the fix — moved to a new `resolved_risks` record documenting the resolution instead of silently deleting the audit trail
- **A lab tenant pair's `default_folder` mismatch** — two tenants were configured with `default_folder = "Shared"`, a folder that doesn't exist for either (`400 ObjectNotPresentError`), breaking every tool that defaults to the tenant's folder (`zone_list` and beyond). Live-verified the actual working folder is `ngfw-shared` for both — real zones, security rules, address objects, and NAT rules all live there. This is a `settings.toml` (git-ignored, live config) fix, not a code change

## [0.11.0] - 2026-07-20

### Added
- **MSR round 2 — bandwidth vs allocation, mobile users, ADEM, security events** (`audit/msr_report.py`, `tools/msr.py`) — the pack grows from 8 to 11 sections. §7 now compares per-RN-location bandwidth over the review window against the region's allocated bandwidth (SCM bandwidth allocations joined by normalised location name) with utilisation % per row and a ≥90% executive-summary flag; the Insights v3 backend rejects a `between` month filter (500s until the retry adapter gives up), so the query falls back to an honest `last_n_days` window and the section discloses which window was actually used — unmatched allocations still render as allocation-only rows so idle regions show. §8 Mobile Users: unique users connected in the window plus a per-location breakdown (deduplicated by username per location). §9 Digital Experience: ADEM agent experience scores (mobile users + remote networks; 3-day telemetry window, disclosed); a 401 renders the actionable ADEM-scope hint. §10 Security Events: threats detected vs blocked (Critical/High/Medium) from the Monitor API threat summary, with a blocked-count executive bullet. Service stats gain a commit-job count and the unique-MU row. Live-validated on both lab tenants: allocation-only join (50 Mbps europe-northwest), 2 ADEM agent scopes on one tenant / clean RBAC degradation on the other, and real threat counts (481 blocked of 1005; 156 of 372). 22 new tests (647 → 669)

### Fixed
- **Review sweep of the 2026-07-17 API-coverage sprint** — full-code review of the sprint's new modules with fixes and 57 new tests (596 → 647). `config_orch.py`: `delete` was unreachable in `scm_config_orch_bandwidth` and `scm_config_orch_profiles` (the create/update `body_json` gate fired before the delete branch), and all three tools injected `ticket_ref` into the RNHP request body — a field the API doesn't accept, which would have 400'd every applied create/update; the ticket reference now lives in a structured `config_orch_write` audit log and the tool response instead. `sdwan_interface_status`: an unknown `element_id` silently fell back to the **first element in the estate** and returned the wrong element's interfaces — now returns a not-found hint. `sdwan_app_qos`: name-map enrichment moved inside the error envelope. `utils/validation.py`: a missing `jsonschema` package would have raised `NameError` from the except clause instead of degrading to a no-op (import moved to module level with a guard), and `validate_body` now reports **all** schema violations via `iter_errors` instead of only the first. `tools/insights.py`: the tenant-region resolution block was deduplicated (3 copies → `_resolve_region`), and `scm_insights_export`'s `resource` parameter is now optional since status/download actions don't use it. `dlp_incidents_list` echoes the clamped limit. New test files: config_orch (16), validation (12), DLP incidents (6), SD-WAN round 3 (9), Insights export workflow (8)

### Added
- **MSR — Monthly Service Review pack generator** (`tools/msr.py`, `audit/msr_report.py`, `scm_msr_report`) — assembles the per-tenant monthly customer deliverable from sources the server already produces: period-bounded incidents (Incidents API) and config jobs (Jobs API), the cumulative SSR provenance ledger parsed from `ssr_objects` object descriptions, licence/renewal posture (expired >90d compress to a count; recently-expired stay in the table for the renewal conversation), per-location Insights bandwidth snapshot (24h window, disclosed as such), Compliance Center posture at tier-gated depth (Bronze: upgrade note; Silver: framework scores; Gold: + 30-day trend annex for the benchmarked framework — the `-1` scores unassessed frameworks report render as "not assessed", not a percentage), and mechanically computed service stats (MTTR from closed-incident timestamps — honestly n/a when the API carries no resolution times — ack rate, change failure rate). Executive summary leads with ranked worst-first bullets. Every source degrades per-section with a §8 coverage disclosure, never failing the pack. `month` param (YYYY-MM, default previous full month), markdown or DOCX via the bundled pypandoc pipeline. Live-validated on two lab tenants (bronze + gold paths) including a real DOCX; the gold run gathered all five sources with zero errors. Also fixed a latent `parse_any_ts` gap on the way: ISO timestamps with `Z`/offset suffixes (the Incidents API's `raised_time` format) previously parsed to None, which would have silently emptied incident-time correlation in `scm_incident_rca` too. 32 tests
- **SSR intake webhook** (`server_http.py`, `POST /webhook/ssr`) — form/flow front-ends (Power Automate, ITSM business rules) can now submit Simple Service Requests over HTTP. Payload mirrors `scm_ssr_execute` (`operation`, `target`, `ticket_ref` required; `tenant_id`, `folder`, `action`, `dry_run`, `requested_by` optional) with lenient string-bool coercion for form outputs — an unrecognized `dry_run` value always stays dry-run, never flips to execute. Two-phase contract: POST with `dry_run=true` (default) returns the before/after diff for the approval step; re-POST with `dry_run=false` after sign-off. Commit remains a separate `scm_commit` step. Status mapping: 200 planned/applied, 400 malformed request, 422 tool rejection. Because this endpoint can write (unlike the read-only-by-construction `/webhook/ir`), it is gated behind `SCM_MCP_HTTP_SSR_WEBHOOK=1` on top of the existing AuthMiddleware. Companion Power Automate flow design in `docs/ssr-intake-power-automate.md`. 17 tests
- **SD-WAN Depth Round 3** (`tools/sdwan.py`) — 7 new tools completing the SD-WAN depth roadmap: `sdwan_app_qos` (per-application latency/jitter/loss/MOS aggregates from the monitor API), `sdwan_interface_status` (interface operational state sweep across API versions v2.0–v4.21 with per-element fallback), `sdwan_ipfix_config` (IPFIX profiles, collector/filter contexts, templates, global/local prefixes, and per-element IPFIX — read-only with write operations gated behind the SSR pattern), `sdwan_snmp_config` (SNMP agents and trap destinations per element across v2.0/v2.1), `sdwan_event_correlation` (event correlation policy sets with per-set rules and correlation events query), `sdwan_perf_mgmt` (performance management policy sets, threshold profiles, and probe configs), and `sdwan_events_summary` (aggregated event counts by severity/category — a lighter alternative to `sdwan_events` for dashboard consumption). 28 total SD-WAN tools
- **Configuration Orchestration** (`tools/config_orch.py`) — 3 tools for the RNHP site-onboarding API (`sase/config-orch`, 32 endpoints, previously zero tooling): `scm_config_orch_remote_networks` (remote network CRUD + location informations), `scm_config_orch_bandwidth` (bandwidth allocation CRUD v1+v2), and `scm_config_orch_profiles` (IKE/IPSec crypto profile CRUD + IKE gateway reads). All write operations follow the SSR pattern: `dry_run=True` default with before/after diff, mandatory `ticket_ref` for provenance, commit is a separate explicit step. This is the first write-heavy tool family for site provisioning — a different API than the SCM Config API used by `scm_remote_network_list`
- **Newly catalogued small families** — 4 new tool modules scoped and built: `email_dlp.py` (`scm_email_dlp_incidents` — list incidents + retrieve reports from the Email DLP API), `dns_security.py` (`scm_dns_security_lookup` — domain category/reputation queries + change requests via the Advanced DNS Security API), `cdl_logforwarding.py` (`scm_cdl_logforwarding` — email/HTTPS/syslog log-forwarding profile listing from the CDL API), and 3 DLP incident tools added to existing `dlp.py` (`dlp_incidents_list`, `dlp_incidents_get`, `dlp_incidents_assignees` — v4 Beta + v1 GA DLP Incidents API). All degrade gracefully on unlicensed tenants. `cloudngfw/aws` (135 paths) deferred until a lab tenant with Cloud NGFW entitlement exists. Plus `family_probe.py` utility for scoping future families before scaffolding
- **Spec-schema request validation** (`utils/validation.py`) — pre-request validation layer using `jsonschema` (new dependency) to catch malformed query/body params before they hit the API (fewer opaque HTTP 400s). Validates against per-endpoint JSON Schemas from the OpenAPI catalog; gracefully degrades when no schema file exists. Injected at the Insights `_insights_call()` chokepoint (highest 400 rate per memory). V1 is advisory — logs warnings without blocking the call
- **MT Monitor round 3** (`tools/mt_monitor.py`) — 15 new views covering 22 previously unused catalog paths: alerts, threat-list, threat-source, app-source, incident-list, incident-trends, incident-tenants, incident-impacted, service-health (CDL status, gateway status, top outliers, unique users), url-summary, locations-tenants, tenant-hierarchy, license-setup, license-allocated, and app-monitor. 24 total views covering 34 of 36 catalog paths; `applications/list` (400) and `locationsUsers` (500) remain blocked on PAN spec refresh
- **Insights scheduled export workflow** (`tools/insights.py`) — `scm_insights_export` tool for the three-step Insights export pipeline: schedule → poll status → download. Supports v2 and v3 schedule endpoints; status/download use the v2 download endpoints. Also fixed a v3 path-building bug where `export/` and `download` paths incorrectly received a `/query/` prefix, making the two v3 export catalog paths unreachable through `scm_insights_query`

### Changed
- Planner manifest domain ceiling raised from 25 to 30 tools (sdwan domain grew to 28 with round 3)
- Tools manifest: 141 → 158 tools, 22 → 26 write tools across 11 domains

### Added (continued)
- **Planner Agent Phase 4 — MSSP cross-tenant layer** (`planner/estate.py`, `scm_estate_check`, console script `scm-planner-estate`) — the epic's differentiator over PANW's single-tenant model, completing the epic. One trigger fans out per-tenant sub-plans with bounded concurrency (default 3) through the same PlannerLoop; each tenant's contracted tier scopes its check depth — Bronze: licensing + certs + connectivity basics; Silver: + BPA posture + change audit; Gold: + NCSC CAF + ISO 27001 + DLP/SSPM posture (the three Gold assessments share one snapshot per tenant via the extractor's TTL cache). Cross-tenant anomaly rules flag what per-tenant analysis can't see: SD-WAN topology with zero active licences, duplicate NFR licence sets expiring across tenants (a real pattern on this estate), and provisioned-but-idle tenants (full bundles, zero config jobs) — each rule skips tenants whose facts couldn't be gathered rather than guessing. Read-only by construction (no approver wired); tests pin tier subsetting (bronze ⊂ silver ⊂ gold), the concurrency bound (peak-parallelism counter), and all three anomaly rules
- **Planner Agent Phase 3c — IR-triggered agent** (`planner/ir.py`, `scm_ir_trigger`, `POST /webhook/ir`) — the third and final trigger surface: an alert payload (MT Monitor webhook, incident search hit, or any bridge) is keyword-classified into an incident class and its pre-built triage template runs through the same PlannerLoop as every other trigger. tunnel-down runs exactly the epic's worked example (`sdwan_wan_ip_summary`, `scm_ike_gateway_list`, `scm_list_jobs`, `sdwan_events`) plus `scm_incident_rca` (drift off — triage stays fast); cert-expiry, licence-expiry, config-change, connectivity-degraded, and generic classes cover the rest. Templates are structurally write-free — the triage executor has no approver, and a test asserts no template names a write tool, so a forged alert cannot make the webhook execute a change. Runs in the background returning a plan_id (follow with `scm_planner_status`/`scm_planner_result`); the HTTP route sits behind the existing auth middleware and returns 202 with plan_id + incident class. Live-validated: a real tunnel-down triage ran all five steps against the lab tenant. This completes Phase 3 — all three trigger surfaces (scheduled, conversational, IR) now feed one loop

- **Compliance Center API tools** (`tools/compliance.py`) — `scm_compliance_center` (8 read actions: list frameworks, summaries with scores, overall compliance scoreboard, 30d/1y timeline, per-control pass/fail detail, assessed config counts, framework detail, benchmark monitoring) and `scm_compliance_framework` (6 write actions: create, update, delete, clone, benchmark, un-benchmark). Covers all 15 endpoints of PAN's new Compliance Center API (2026-07-14 release) at `api.strata.paloaltonetworks.com/posture/compliance-frameworks/v1`. 403 detection returns a licence-hint message matching the posture.py pattern. CLI: Posture menu item 3 (renumbered sequentially). 18 tests
- **SSR — Simple Service Requests** (`tools/ssr.py`) — `scm_ssr_execute`: machine-first JSON tool automating the three commonest MSSP customer change requests (URL allow/block-list, threat exceptions, SSL decrypt exclusions). All three reduce to add/remove in a designated SSR-managed object; never touches a rulebase. Idempotent (re-adding → `already_present`), dry-run default with before/after diff, mandatory `ticket_ref` echoed into descriptions for provenance. Per-tenant `ssr_objects` allowlist in settings.toml gates which objects the tool can touch. Commit stays a separate `scm_commit` step. 21 tests
- **Insights 2.0 — general-purpose query tool** (`tools/insights.py`) — `scm_insights_query` unlocks all 103 Insights paths (v1.0/v2.0/v3.0 + custom queries + scheduled exports) behind one interface with resource, body, api_version, and region parameters. Auto-resolves CDL region from tenant config; OAuth token refreshed before direct-session calls. 13 tests
- **MT Monitor round 2** (`tools/mt_monitor.py`) — `scm_mt_analytics` gains 5 new views: app-usage (applicationUsage), url-logs (urlLogs), upgrades (upgrades/list), locations (location/list — GET), and licenses (custom/license/quota + utilization — GET). Tool auto-detects GET vs POST based on view
- **CLI UX overhaul** — paginated 21-item Config & Inventory menu (5 section pages) and SD-WAN menu (3 section pages) with N/P navigation; 81 read-only leaf operations no longer pause for Enter (lists/reports flow continuously); confirmation prompts (y/N, default No) on Commit, Push, and Rollback; Posture menu renumbered sequentially 1-6 and MSSP Ops reorganised with SYSTEM section; "option 9" → "option S" in no-tenant messages; main menu Posture description updated

### Fixed
- **Insights rn_bw/sc_bw HTTP 400 — per-location RN/SC bandwidth was never extracted** (`audit/insights_extractor.py`) — `location_rn_bandwidth` and `location_sc_bandwidth` reject an empty request body with HTTP 400 GCP10002 ("Syntax error: Unexpected keyword AND" — the backend inlines the time predicate into a SQL template), and `extract_insights` sent `{}` to every location endpoint, so both bandwidth fields have been empty (and an error logged) on every AS-BUILT/Insights extraction since the extractor was added. The two bandwidth queries now send an explicit `event_time last_n_hours=24` filter; the status endpoints keep the empty body they accept. Live-validated on two lab tenants (region `uk`): both now return per-edge-location rows (`total_consumption`/`peak_consumption`/`rn_sites_up`) with zero extraction errors
- **Review sweep of the SSR / Insights / Compliance Center work** — `scm_ssr_execute` threat-exception now reports `status: "error"` when every configured profile fails, `commit_required` consistent across all handlers, explicit `tenant_id` with no match no longer falls back to another tenant's allowlist. `scm_insights_query` OAuth token refresh + no empty Prisma-Tenant header. Coverage: 13 insights tests, 4 SSR regression tests. Both live-validated read-only — `scm_ssr_execute` threat-exception now reports `status: "error"` when every configured profile fails (previously read "applied" with the failures tucked in `errors` — an orchestrator would have committed a no-op), `commit_required` is consistent across all handlers (True whenever a change is made or planned, False for pure no-ops), and an explicit `tenant_id` matching no configured tenant no longer falls back to *another tenant's* `ssr_objects` allowlist or default_folder (cross-tenant bleed). `scm_insights_query` now refreshes the OAuth token before direct-session calls (the stale-token trap every other Insights caller already guards) and no longer sends an empty `Prisma-Tenant` header. New coverage: 13 tests for the previously-untested `scm_insights_query` (URL construction per API version, region resolution, header rules, error pass-through) and 4 SSR regression tests. Both tools live-validated read-only: Insights returns real data and surfaces RBAC 403s cleanly; Compliance Center lists 7 real frameworks

### Added
- **Planner Agent Phase 3b — conversational copilot as MCP tools** (`tools/planner_tools.py`) — `scm_planner_run` feeds a natural-language operator goal into the same PlannerLoop with Claude (Opus 4.8) as the reasoning engine, running in the background and returning the plan_id immediately (asbuilt-job pattern); `scm_planner_status` streams progress by polling (per-step status/retries/summaries, or the run list); `scm_planner_result` returns the synthesized report. Write-tool approval in a conversation is the operator naming tools in `approved_write_tools` — explicit, per-run, default empty (fully read-only); anything unnamed is denied by the executor, never executed, and `scm_planner_run` itself is classified `access: write` in the manifest so no other planner can invoke it unattended. Any chat client connected to this server (Claude Desktop stdio, Copilot Studio Streamable) is the copilot frontend; a Slack/Teams bridge posts NLQs to the same tools. Also classified the new `scm_insights_query` tool in the manifest (the Phase 1 coverage test caught it unclassified — enforcement working as designed)
- **Planner Agent Phase 3a — scheduled ops agent** (`planner/nightly.py`, console script `scm-planner-nightly`) — the cron trigger surface: each tenant runs a deterministic template plan (tier assessment, cert scan, licence expiry ×2, incident summary, job audit) through the same PlannerLoop via a TemplateEngine (a nightly run's shape is policy, not reasoning — no LLM call), producing one estate digest with findings ranked severity → customer tier (Gold first) and per-tenant sections linking each full plan report. The epic's acceptance rules are computed mechanically from raw Subscription API rows and **both fired on live data**: the digest leads with "NFR/eval licences expiring within 90 days across 2 tenants (28 SKUs)" (estate CRITICAL), and the licensed-but-unused-shell rule is pinned in tests. Live-run lessons baked in: per-SKU findings aggregate per tenant (first estate run produced 176 findings; aggregation yields 5 readable ones) and estate findings lead their severity band (they previously sorted below the fold alphabetically). CLI: `--tenants` filter, `--no-tier-assess` fast path, `--slack-webhook`/`SCM_MCP_SLACK_WEBHOOK` delivery; cron example: `15 5 * * * cd /path/to/repo && uv run scm-planner-nightly`
- **Planner Agent Phase 2 — the loop core** (`planner/schema.py`, `store.py`, `executor.py`, `engine.py`, `loop.py`, `backend.py`) — Trigger → Plan → Execute → Observe → Revise → Synthesis → Report, implemented as a library invoked programmatically (Phase 3 adds the trigger surfaces). The persisted Plan matches the ARCHITECTURE.md schema exactly (plan_id, trigger, persona, tenant_scope, steps with status/result_summary/retries/timestamps, revision_history, final_report_ref) and every state change writes atomically to `plans/<plan_id>.json` (gitignored) with a JSONL audit log beside it — plans survive an MCP server restart and `resume()` re-queues only unfinished steps. The executor turns Phase 1's rails into runtime behavior: unclassified tools refused, write tools gated on an approval callback that **denies by default** when no approver is configured, manifest retry policy honoured (max 2 retries; fallback failures annotated with the documented fallback tool so revision can pick it up). The reasoning engine is Claude Opus 4.8 via `messages.parse()` structured outputs (Pydantic plan/revision drafts; params carried as JSON-string fields to satisfy strict schemas; refusal stop-reason handled) behind a Protocol — the 18 loop tests run on a scriptable fake, covering write-denial, bounded revision, retry semantics, resume-after-crash, and the always-finish-with-a-report guarantee (engine or synthesis failure degrades to a mechanical fallback report, never a silent abort). Credential convention matches `scm_ai_compliance_advisor` (`anthropic_api_key` in .secrets.toml)
- **Planner Agent Phase 1 — tool manifest & safety rails** (`resources/tools_manifest.yaml`, `planner/manifest.py`) — every registered MCP tool (135) classified with `access` (21 write tools), Expert-Agent `domain` (11 domains, each ≤ 21 tools so a sub-plan's context load stays well under the 128-tool Copilot Studio ceiling), `scope` (16 cross-tenant), `idempotent` (`scm_ssr_execute` is the sole idempotent write by design), `retry_policy`, and `known_failure_modes` populated from live-validated quirks (remote_network Pydantic fallback, zone_list default_folder trap, Insights/SD-WAN RBAC 403s, mt_analytics CDL-region drift, SDK "Invalid error response format" masking write-path 403s, async job + baseline prerequisites). The loader enforces the v1 hard rule: `requires_approval()` returns True for every write tool, takes only the tool name (no bypass flag), and raises `UnknownToolError` for unclassified tools rather than defaulting to unattended execution. Coverage is CI-enforced — `test_planner_manifest.py` registers all tools on a live FastMCP instance and fails if any tool lacks a manifest entry or an entry goes stale. New dependency: `pyyaml` (previously transitive)
- **`scm_incident_rca`** (`tools/audit.py`, `audit/incident_rca.py`) — incident → root-cause correlator: given an incident time (default now) and lookback window, ranks candidate causes by temporal proximity from config push/commit jobs (failed jobs rank ahead at equal distance; child jobs deduped via parent_id), certificate expiries (`expiry_epoch`), and licence expiries; config drift vs the drift baseline is presented separately as *state* evidence since extraction shows what differs, not when it changed. A 15-minute post-incident grace window catches clock skew/late symptom reports. Output ends with a customer-facing RFO draft citing the top candidate's evidence (job ID, cert CN, SKU) and an explicit correlation-not-causation caveat, plus a disclosure list of evidence sources the run could not check (Insights alerts RBAC, SD-WAN status, missing baseline). Live-validated: quiet window → honest "no correlated cause" RFO; anchored to a real licence-expiry date → 11 real expiries ranked with the top one cited in the draft
- **`scm_commit_preview`** (`tools/audit.py`, `audit/commit_preview.py`) — pre-commit blast-radius gate: extracts the current candidate config and compares it against the drift baseline (last known-good), reporting (1) every object the commit would add/remove/modify triaged HIGH/MEDIUM/LOW by enforcement impact, (2) rule shadowing introduced by new/changed security rules (conservative literal-value coverage check over from/to/source/destination/application/service — group/EDL membership not resolved, so flagged shadows are real; pre-existing shadows are filtered out via focus on the pending rules), and (3) the BPA delta — best-practice findings the change introduces or resolves, from running the check engine against both states. Verdict: 🔴 HIGH RISK (shadowing, new critical/high findings, or removals/modifications in enforcement sections) / 🟡 REVIEW / 🟢 LOW RISK / no-op, with next steps ending in `scm_commit` + `scm_drift_check(update_baseline=true)` to roll the baseline forward after an approved push. This is the governance gate the SSR/orchestration epics assume: the orchestrator owns sign-off, the gate gives sign-off something concrete to read
- **`scm_asbuilt_verify`** (`tools/audit.py`, `audit/asbuilt_verify.py`) — doc-vs-live verification for AS-BUILT documents: completed `scm_asbuilt_report` jobs now retain their extraction snapshot, and the verify tool re-extracts a fresh core snapshot (new `fresh=True` cache bypass on `extract_snapshot`) and diffs it section by section against the snapshot the document was built from. Reports per-section added/removed/modified objects with a ✅ DOCUMENT CURRENT / ⚠️ DRIFT DETECTED / ❓ PARTIALLY VERIFIED verdict, surfaces generation-time extraction gaps (e.g. RBAC 403s) separately from drift, and guards against live re-extraction failures reading as wholesale deletions. Live-validated on a lab tenant: clean baseline verdict across 23 sections, then all three drift directions (added rule, removed tag, modified service) detected and named after mutating the stored snapshot. Run it before handing a document to a customer
- **Drift sentinel** (`tools/audit.py`, `audit/drift_baseline.py`) — `scm_drift_baseline` captures known-good core config snapshots to disk (`SCM_MCP_BASELINE_DIR`, default `./baselines/`, gitignored — baselines hold full tenant config); `scm_drift_check` re-extracts live config and reports what changed since the baseline, triaged HIGH (security/NAT/decryption/auth rules, zones, VPN, identity, log forwarding) / MEDIUM (protection profiles, posture, EDLs) / LOW (address/service/tag plumbing) with the exact objects named. `all_tenants=true` sweeps every tenant as a background job (3 concurrent extractions; `scm_drift_result` fetches the digest) — designed as the overnight cross-tenant sentinel with `update_baseline=true` to accept explained changes as the new known-good. Baselines tolerate schema evolution (unknown fields dropped on load)
- **`scm_renewal_brief`** (`tools/ops.py`) — renewal-conversation brief combining subscription licences (contracted vs consumed seats, expiry), bandwidth allocations per compute location, and the live Insights v3.0 connected mobile-user count: renewal-window table for the chosen horizon (default 180 days), consumption-vs-contract signals (OVERSUBSCRIBED → true-up conversation, UNDERUSED → downsize risk), capacity snapshot, and generated talking points. `all_tenants=true` sweeps under the shared parallel poll budget. Live data drove two fixes: same-SKU bundles whose expirations differ only by seconds now group by expiry date (no duplicate rows/talking points), and pooled parent SKUs with `remaining > purchased` (negative consumption) read N/A instead of UNDERUSED
- **Planner Agent epic (roadmap + design stubs)** — new "Planner Agent — Agentic Orchestration Layer" epic in ROADMAP.md (PANW "NetSec Agents on SCM" taxonomy extended with an MSSP cross-tenant layer; four phases from tool manifest/safety rails through scheduled-ops MVP to estate fan-out), plus design stubs under `docs/planner-agent/`: ARCHITECTURE.md (taxonomy mapping table + persisted Plan JSON schema) and TOOL_MANIFEST.md (manifest spec with the write-tool and known-failure-mode entries populated; full 125-tool population TODO). Docs only — no implementation yet

### Fixed
- **CI green-up + PYSEC-2026-3447 (setuptools) suppression** — cleared 7 mypy errors and 2 unformatted files left over from the MSR round 2 push (mostly reused loop-local variable names — `rows`, `vals` — picking up a fixed type from their first use in a shared function scope; renamed each independently). `pan-scm-sdk==0.15.1`'s wheel metadata hard-pins `setuptools>=78.1.1,<79.0.0` (PYSEC-2026-3447); a `[tool.uv] override-dependencies` bump to a patched version was tried first but breaks pip's real dependency resolution against the SDK's own metadata (`ResolutionImpossible`), so it was reverted in favour of suppressing the CVE in the `pip-audit` CI step with a SOC2 accepted-risk entry — the same pattern already used for the cryptography/pan-scm-sdk CVE (GHSA-537c-gmf6-5ccf)

## [0.10.0] - 2026-07-13

### Added
- **CLI: traffic-light PAN cloud status on the main menu** (`cli.py`) — the main menu banner now shows a live status light from the public statuspage feed (🟢 operational / 🟡🟠🔴 degraded with unresolved SASE incident count and a pointer to MSSP Ops → PAN Service Status; ⚪ when the feed is unreachable). Cached 5 minutes so menu redraws never refetch; short timeouts so a slow feed can't delay the menu
- **`scm_mt_analytics`** (`tools/mt_monitor.py`) — cross-tenant analytics over the `sase/mt-monitor` aggregation API (`agg_by=tenant`: a parent MSSP tenant answers for itself and all children). Views: apps (total/risky/blocked counts — live: 277 apps, 127 risky), threats (total/blocked — live: 228/101), connectivity (site counts by node type and up/down state per child tenant), incidents (raised counts by severity). Data lives in a CDL region (`X-PANW-Region`); when no region is given the tenant's insights_region is mapped and its eu/uk sibling also tried — the lab tenants say `eu` but hold data in `uk`. `applications/list` and `locationsUsers` are omitted: both reject or 500 on the spec's own example payloads. CLI: "Cross-Tenant Analytics" in MSSP Operations. (mt-notifications probed too: gateway path is `/mt/notifications/api/cloud/2.0/...` but current service accounts get 403 — parked with the other RBAC-blocked items)
- **PAN status banner on `scm_tenant_dashboard`** (`tools/ops.py`, `tools/service_status.py`) — when the PAN cloud status indicator is degraded, unresolved SASE incidents exist, or SASE maintenance is due within 7 days, the NOC dashboard shows a banner between the header and the tenant table (`🟡 PAN cloud status … — N unresolved SASE incident(s)` / `🔧 Next SASE maintenance …`). Fetched concurrently with the tenant rows via the shared `status_banner()` helper (short timeouts, silent on failure), so a slow or unreachable status page can never delay or break the dashboard. Healthy + quiet = no banner
- **`scm_service_maintenance`** (`tools/service_status.py`) — maintenance-window awareness from the public status.paloaltonetworks.com feed (Atlassian Statuspage; no auth/licence/RBAC, works even when tenant APIs are down): upcoming + in-progress scheduled maintenance filtered to the SASE/SCM product families this server manages (drops Prisma Cloud/Cortex noise — 26 raw windows → 6 relevant on first live run), matched against tenant regions via `TenantConfig.insights_region` with global windows always included; also reports the page's overall indicator and unresolved SASE incidents (live run surfaced the current Cloud NGFW Azure/AWS degradations). `all_tenants=true` groups windows per configured tenant. CLI: "PAN Service Status" entry in MSSP Operations
- **PAB evidence in CE/NCSC CAF compliance** (`audit/bpa_checks.py`, `audit/ncsc_controls.py`):
  - **BPA-PAB-001** (high) — every enrolled Prisma Browser device must pass the endpoint posture baseline (screen lock + disk encryption + host firewall); maps to CAF-B5.a and the new **CE-SC-1** (Secure Configuration — Device Baseline) control
  - **BPA-PAB-002** (low) — active browser enrolments unseen for >90 days are flagged as stale trusted-device inventory; maps to CAF-B5.a
  - Both checks skip cleanly when PAB is not provisioned; findings flow into the NCSC/CE gap reports automatically. First live run: 3/8 lab devices failing posture, 5 stale enrolments
- **PAB column in `scm_tenant_dashboard`** (`tools/ops.py`) — the NOC dashboard now shows Prisma Access Browser adoption and posture per tenant: `<users>u/<devices>d (<pct>%✓)` where the percentage is the share of devices passing **all three** posture checks (screen lock + disk encryption + firewall); unprovisioned tenants show "—". Single-page pulls inside the existing parallel per-tenant poll, so the 25 s dashboard budget is unaffected. First live run immediately surfaced a real gap: one lab tenant at 14% device posture compliance
- **PAB tenant depth** (`tools/pab.py`) — three read-only tools over the previously untooled `access/browser-mgmt` family (`/seb-api/v1/*`, 33 paths):
  - **`scm_pab_inventory`** — enrolled browser users, device inventory with endpoint posture (screen lock / disk encryption / firewall, mapped to booleans), user/device groups, and a summary view with posture-compliance roll-up; cursor pagination followed automatically
  - **`scm_pab_apps`** — configured application catalog (type/name filters), application categories, and app groups
  - **`scm_pab_user_requests`** — pending end-user browser access requests (the admin approve/deny queue)
  - Live-validated: base URL is `api.sase.paloaltonetworks.com/seb-api/v1` with common SASE bearer auth; note the subscription licenses API shows no `seb` entry even on tenants where the API serves data — provisioning is detected from the API itself (unprovisioned tenants return empty `/users` but 404/500 "tenant not found" on `/applications`), and the tools surface that distinctly
  - CLI: "PAB Inventory" and "PAB User Requests" entries in the SSE, DLP & CASB menu
- **`scm_saas_posture`** (`tools/posture.py`) — standalone SaaS Security Posture tool: onboarded SSPM apps with severity-ranked misconfiguration findings, Identity-SSPM IdP/NHI posture, and supported-app catalog capability counts (previously this data was only extracted inside compliance snapshots). Supports **manual export/import**: `save_to` writes the raw posture snapshot to JSON (format-tagged `scm-mcp-mssp/saas-posture@1`) for archiving/diffing, `load_from` renders a previous export offline without touching the API. Unlicensed (HTTP 500) and unprovisioned (404) tenants report clearly instead of erroring. CLI: new "SaaS Posture (SSPM)" entry in the Posture, Incidents & NOC menu with import/export prompts
- **Classic SD-WAN depth (round 2)** (`tools/sdwan.py`):
  - **`sdwan_flows`** — top talkers per site from the flow log: top sources / destinations / applications by bytes (app IDs resolved via appdefs), per-path-type breakdown, and dropped-flow count. The flow monitor takes one site per request
  - **`sdwan_app_health`** — healthscore buckets (good/fair/poor) for sites, circuits, and anynet links; top-N applications and sites by a selectable basis (traffic volume, TCP/UDP flows, transaction failures, or media metrics like egress audio MOS); per-app healthscore detail where app monitoring is enabled
  - **`sdwan_cellular_status`** — LTE/5G module inventory joined to live status: modem state, carrier, technology, signal strength, per-slot SIM state, roaming, and active firmware, with element/site names resolved
- **CLI: SD-WAN monitoring menu** (`cli_menus.py`) — the Prisma SD-WAN sub-menu gains a MONITORING section exposing events, software status, link health, flows/top talkers, app health, cellular modules, WAN IP summary (with optional ISP enrichment), audit logs, and the HTML site map — all reusing the tested MCP tool logic via `_call_mcp_tool`, which now primes the per-tenant config cache so SD-WAN tools resolve `tenant_id` correctly from the CLI
- **WAN IP enrichment layer 3 — record + cross-check** (`utils/ipenrich.py`, `audit/extractor.py`, `audit/asbuilt_report.py`, `tools/audit.py`, `tools/sdwan.py`):
  - **Persistent enrichment cache** — lookups now survive server restarts via an atomic local JSON cache (`~/.cache/scm-mcp-mssp/ipenrich.json`, 30-day TTL, keyed provider+IP), so repeat AS-BUILT runs cost zero third-party lookups
  - **Circuit resolution on every WAN IP record** — `extract_sdwan_wan_ips` now joins interface → site WAN interface → WAN network, adding `circuit_name` and `wan_network` to each record
  - **Drift flags (advisory)** — enriched records are checked two ways: observed ISP vs the configured WAN network/circuit label (token overlap; catches mis-patched or mis-labelled circuits) and IP geolocation vs the site's configured coordinates (>500 km haversine). Live run flagged 8/53 lab circuits whose generic labels hid a shared carrier egress
  - **AS-BUILT enrichment columns** — new `enrich_wan_ips` opt-in on `scm_asbuilt_report` adds Observed ISP (ASN) / IP Geolocation / Drift columns to §4.2.1 (SD-WAN, plus per-flag notes) and §3.4.7 (NGFW); §4.2.1 also gains a Circuit / WAN Network column unconditionally
  - **`sdwan_site_map`** — interactive Leaflet/OSM HTML map of SD-WAN sites from their configured coordinates (hubs/DCs red, branches blue; popups with address, IONs, circuits); sites without coordinates are listed as skipped
- **Classic Prisma SD-WAN depth — 5 new tools** against the already-wired `prisma-sase` client, all live-validated on a 16-site lab tenant (`tools/sdwan.py`):
  - **`sdwan_events`** — alarm/alert feed (POST `events/query` v3.7) with severity/code/site filters, active-only mode, event codes resolved to display names via the tenant's event-code catalog, and a by-severity/by-code summary
  - **`sdwan_audit_logs`** — controller audit trail (who changed what); renders a clear RBAC hint on the HTTP 403 that view-only service accounts get
  - **`sdwan_software_status`** — per-ION running version, staged-upgrade state (surfaced two stuck `download_cancelled` upgrades in the lab on first run), machine claim state, unclaimed inventory, upgrade jobs, and an estate-wide version histogram
  - **`sdwan_policy_rules`** — rule contents for path/QoS/NAT/NGFW-security/legacy-security policy sets plus set stacks (complements `sdwan_list_policies`, which only names the sets)
  - **`sdwan_link_health`** — per-path LQM latency/jitter/MOS (min/avg/max) plus site-level ingress/egress bandwidth from the monitor API; the API takes one path per LQM request and latency rejects the direction view jitter/MOS require, so paths are queried admin-up-first two calls each, capped by `max_paths`. `LqmPacketLoss` omitted — the API rejects every unit for it

- **SD-WAN site geo locations** — `sdwan_list_sites` returns each site's `location` (latitude/longitude); `sdwan_wan_ip_summary` attaches `site_address` + `site_location` to every WAN IP record (`tools/sdwan.py`)
- **WAN IP enrichment (opt-in `enrich=true`)** on `sdwan_wan_ip_summary` and `scm_ngfw_wan_ip_summary` — whatsmyip-style reverse lookup of each public WAN IP (ISP, organisation, ASN, reverse DNS, IP geolocation) via the new `utils/ipenrich.py`. Provider-pluggable (`ip_enrichment_provider` setting: ip-api.com batch by default, ipinfo.io + `ipinfo_token` optional), 6 h in-process cache, additive-only (lookup failures degrade to warnings). Opt-in because it sends tenant public IPs to a third-party service
- **Detected post-NAT public IP per ION element** — `sdwan_wan_ip_summary` now also returns `detected_public_ips`: the source address the cloud controller sees each element's config/events connection arriving from (element status `config_and_events_from`), i.e. the branch's real public egress even when the WAN interface holds an RFC1918 address behind upstream NAT
- **Widened endpoint catalog** — `gen_endpoint_catalog.py` now walks `sdwan`, `dlp`, `dns-security`, `cloudngfw`, `cdl`, `email-dlp` pan.dev spec trees in addition to `sase`/`scm`/`access`; catalog grew from 1,593 endpoints / 23 families to 3,871 endpoints / 30 families

### Fixed
- **SD-WAN element software version was always null** — elements carry `software_version`, not `sw_version`; fixed in `sdwan_list_elements`, `sdwan_topology`, and the AS-BUILT §4.1 edge-device inventory table, which all silently showed empty/Unknown versions
- **`extract_browser` never returned data** (`audit/extractor.py`, `tools/mssp.py`) — `_BROWSER_BASE` pointed at `/seb/api/v1`, which 404s (silently treated as not-licensed), so every `browser_*` snapshot field and the AS-BUILT §5 Prisma Browser section have been empty since the extractor was added. The real path is `/seb-api/v1`; a data-rich tenant now extracts 14 users / 8 devices / 100 applications / 3 device groups

## [0.9.0] - 2026-07-09

### Added
- **`sdwan_wan_ip_summary`** / **`scm_ngfw_wan_ip_summary`** — live public/private WAN IP address per SD-WAN ION element interface, and NGFW interface IPs parsed from running-config XML (`tools/sdwan.py`, `tools/adnsr.py`)
- **AS-BUILT report** — SD-WAN WAN IP table (§4.2.1) with an IP-annotated topology diagram, and an NGFW WAN IP table (§3.4.7) (`audit/asbuilt_report.py`)

### Fixed
Found via a live sweep of all read-only tools across 8 tenants:
- **`security_rule.list()`'s rulebase kwarg is `rulebase`, not `position`** — 5 call sites, including the core audit extractor, silently ignored it, so every post-rulebase security rule was missing from every BPA/NCSC/ISO 27001/audit report
- **16 tools passed a dead `limit=` kwarg** into `pan-scm-sdk` `.list()` calls (silently swallowed into `**filters`) — always fetched the full result set regardless of the requested limit; now sliced client-side
- **`scm_remote_network_list`/`get` always 400'd** — the API requires `folder` to be literally `"Remote Networks"`, not the caller's folder
- **`sdwan_list_elements(site_id=...)` crashed** — the SDK method has no such kwarg
- **Cross-tenant dashboards** (`scm_incident_summary`/`search`) aborted entirely if one tenant had bad credentials instead of degrading per-tenant
- **`handle_scm_exception()` lost real error text for `APIError`** — its `__str__` omits `.message` when `details`/`status`/`error_code` are all unset

### Changed
- **`extract_snapshot()` now cached 120s per (tenant, folder)** — 8+ report tools each independently re-ran the same ~2 min / ~30-call extraction back-to-back
- Consolidated 3 duplicate tenant-config loaders and 6 duplicate `_fmt` JSON-formatting helpers into shared utils
- `docs/TOOL_REFERENCE.md` updated for the new tools

## [0.8.0] - 2026-07-04

### Added
- **`scm_spi_status`** — Service Provider Interconnect visibility (pan.dev `sase/mt-interconnect`, Feb 2026): one view-based tool covering interconnect summary/inventory, physical connections, SPI regions, tenant settings, and IP-pool usage monitoring; actionable 401/403/404/5xx messages for accounts without an MSP role (`tools/mt_interconnect.py`)
- **`scm_pab_msp_summary` / `scm_pab_msp_report`** — Prisma Access Browser for MSP reporting (pan.dev `sase/pab-msp`, Feb 2026): region-level user/tenant/CIE roll-ups and per-TSG security-event reports (blocked malware, websites, extensions, category breakdowns) — browser-control evidence for CE/NCSC reporting (`tools/pab_msp.py`)
- **`scripts/gen_tool_from_spec.py`** — spec-driven tool scaffolding: emits read-only MCP tool scaffolds (typed query params, docstrings, graceful 4xx/5xx rendering) for any endpoint-catalog family, fetching specs pinned to the catalog's pan.dev commit; scaffolds are curated into consolidated tools before registration
- **`ROADMAP.md`** — tracks new pan.dev API families and planned coverage (SPI in AS-BUILT/NOC, PAB posture columns, Config Orchestration site-based RN, mt-monitor aggregates, Insights 2.0, 5G)
- **pan.dev endpoint catalog** — bundled index of 1,593 endpoints across 23 API families generated from the MIT-licensed pan.dev OpenAPI specs (`sase`, `scm`, `access` trees) with per-file git blob SHAs (`resources/endpoint_catalog.json` + loader `resources/endpoint_catalog.py`, regenerate via `scripts/gen_endpoint_catalog.py`); REST fallbacks in `audit.extractor` now resolve SDK resource names to their exact documented URL (override → SDK `ENDPOINT` → catalog → naive slug) instead of guessing a slug; `scm_check_updates` gains an **OpenAPI Spec Drift** section that diffs the bundled catalog's blob SHAs against the live pan.dev tree (4 unauthenticated GitHub API calls) and reports new/changed/removed spec files — new API families like SP Interconnect or Prisma Browser for MSP now surface automatically

### Fixed
- **`docs/TOOL_REFERENCE.md` regenerated (84 → 108 tools)** — `scripts/gen_docs.py` silently skipped modules missing from its hardcoded section list; it now auto-discovers every `tools/*.py` with `@mcp.tool()` functions (curated titles with docstring-derived fallback), emits GitHub-correct heading anchors, escapes pipes in parameter tables, and is tracked in the repo

## [0.7.0] - 2026-07-03

First public release (squash-published snapshot; development history remains private).

### Added
- **DOCX works out of the box** — `pypandoc-binary` dependency bundles pandoc; `_find_pandoc()` resolves system pandoc first, bundled binary as fallback
- `settings.example.toml` template; the tenant registry (`settings.toml`) is git-ignored

### Fixed
- **AS-BUILT document quality** — SDK enums render as wire values (`model_dump(mode="json")`), empty table cells normalise to "—", dict/list cells unwrapped, §2.1 architecture diagram draws only compute locations actually in use, mmdc diagram rendering self-heals via Chrome discovery + `--no-sandbox` retry (DOCX embeds PNGs again)
- **CLI** — four menu ops called non-existent helpers (tenant/NOC dashboards, licence forecast, tier catalogue, config clone); config-versions API moved to `/config/operations/v1` with per-scope running-version tracking; DOCX conversion failure reports honestly and saves Markdown instead
- **CI type-check greened** — mypy 103 → 0 errors

## [0.6.0] - 2026-06-30

### Added
- **`scm_iso27001_assess`** — assessment of SCM/NGFW configuration against ISO/IEC 27001:2022 Annex A; maps all 39 BPA checks to 12 automatable controls (A.5.14 Information transfer, A.5.28 Collection of evidence, A.8.7 Malware protection, A.8.15 Logging, A.8.20 Network security, A.8.21 Network services/TLS, A.8.22 Network segregation, A.8.23 Web filtering, A.8.24 Cryptography, A.8.27 Secure architecture, A.8.28 Secure coding, A.8.29 Security testing); per-control compliance status with failing BPA checks and evidence guidance; overall verdict CONFORMING / MINOR NONCONFORMITY / MAJOR NONCONFORMITY; `clause_filter` parameter scopes to clause 5, 8, or specific control (e.g. 'A.8.22'); out-of-scope controls (governance, people, physical) explicitly noted; Markdown and JSON output (`tools/audit.py`, `audit/iso27001_controls.py`)
- **`scm_decrypt_policy_audit`** — deep-dive SSL/TLS decryption policy audit for a SCM folder; assesses profile quality (TLS min version ≥ 1.2, weak algorithm flags — 3DES, RC4, MD5, SHA-1, static RSA, forward-proxy block settings for expired/untrusted/unknown certs and unsupported versions), rule coverage (decrypt vs no-decrypt ratio, zone pairs, presence of any-any catch-all rule, disabled rules, rules missing a profile, inbound inspection), gap analysis with NCSC CAF D3.b and DSPT Standard 9 cross-references, and an overall verdict of ADEQUATE / PARTIAL / INSUFFICIENT; Markdown and JSON output (`tools/audit.py`)
- **`scm_dspt_assess`** — automated assessment of SCM/NGFW configuration against the NHS Data Security and Protection Toolkit (DSPT 2024-25 v5.1); covers technology Standards 7 (Continuity), 8 (Unsupported Systems), 9 (IT Protection), and 10 (Accountable Suppliers); maps all 39 BPA checks to 16 DSPT assertions; outputs per-assertion compliance status with DSPT-portal-ready evidence statements and overall level (Approaching / Meeting / Exceeding Standards); Markdown and JSON output with optional file save (`tools/audit.py`, `audit/dspt_controls.py`)
- **`scm_incident_search`** — search SCM security incidents via `POST /incidents/v1/search` with client-side filtering by severity (Critical/High/Medium/Low), status (Open/Closed/Acknowledged), product, and acknowledgement state; traffic-light emoji severity; multi-tenant `all_tenants=True` sweep (`tools/posture.py`)
- **`scm_incident_summary`** — cross-tenant NOC dashboard; counts Critical/High/Medium/Low/Total incidents per tenant with latest critical incident title; ideal for morning SLA briefings and MSSP weekly reports (`tools/posture.py`)
- **`scm_posture_report`** — retrieves Posture Management best-practice reports via `GET /posture/v1/reports`; graceful licence-gate handling (403 → actionable message) for tenants without the Posture Management add-on (`tools/posture.py`)
- **`scm_adnsr_list`** — list Advanced DNS Security Resolver resources (profiles, internal-domains, connection-sources, custom-fqdns, edl-definitions, misconfigured-domains, resolver-info, ca-certs) via `GET /adns-resolver/v1/{resource}`; licence-gate handling for tenants without the ADNSR subscription (`tools/adnsr.py`)
- **`scm_adnsr_profile_create`** — create an ADNSR DNS security profile with configurable default action (sinkhole/block/allow) and query logging via `POST /adns-resolver/v1/profiles` (`tools/adnsr.py`)
- **`scm_ngfw_local_config_list`** — list configuration versions pushed to a specific SCM-managed NGFW device via `GET /sse/config/v1/local-config/versions`; NGFW Operations entitlement required (`tools/adnsr.py`)
- **`scm_ngfw_local_config_get`** — fetch the XML configuration for a specific NGFW local config version (or `version="running"`) to enable automated BPA via `scm_aiops_bpa`; NGFW Operations entitlement required (`tools/adnsr.py`)
- **`scm_aiops_bpa`** — submit a PAN-OS device running config XML to the AIOps BPA API (`api.stratacloud.paloaltonetworks.com/aiops/bpa/v1`); implements the full 5-step workflow (POST `/requests` with device metadata → signed S3 upload URL → PUT XML → poll `/jobs/{id}` → GET `/reports/{id}` download URL → fetch and parse report); requires `requester_email` (a PANW CSP email registered in the AIOps BPA portal), `device_serial`, `device_family`, `device_model`, `device_version` as optional device metadata; renders findings as Markdown with overall score, per-category scores, and failing checks grouped by severity with recommendations; complements the 39 SCM SDK-based BPA checks with PAN's own device-level assessment engine (`tools/aiops.py`)
- **`scm_cert_lifecycle`** — multi-tenant TLS certificate lifecycle dashboard with `all_tenants=True` sweep across all MSSP tenants; identifies probable SSL inspection CA certs (name/CN heuristic) and flags them CRITICAL separately because expiry silently disables SSL decryption; produces cross-tenant summary table (total / flagged / SSL-CA critical / worst expiry) for NOC morning brief (`tools/ops.py`)
- **`scm_cert_import`** — import a PEM certificate into any SCM tenant folder via `POST /config/v1/certificates`; marks CA vs leaf type; prompts to commit after import (`tools/ops.py`)
- **`scm_tls_profile_manager`** — list (`action='list'`) or create (`action='create'`) TLS service profiles via `GET/POST /config/v1/tls-service-profiles`; created profiles default to TLS 1.2 minimum, AES-GCM only, no 3DES/RC4/SHA-1 — the NCSC-recommended cipher baseline (`tools/ops.py`)
- **BPA-SR-009** — NSF-ZT-1 zero trust rule specificity: flags allow rules where both `source=any` AND `destination=any`, giving zero network-level segmentation; distinct from BPA-SR-007 (which requires `app=any` too) and catches application-specific but location-unrestricted rules (`audit/bpa_checks.py`)
- **BPA-SR-010** — CE-FW-2 unauthenticated protocol exposure: flags allow rules that explicitly name unauthenticated or cleartext protocols (telnet, FTP, TFTP, rsh, rlogin, rexec, finger, SNMPv1/v2c, NetBIOS variants) with per-rule detail of which protocols are exposed and encrypted alternatives in remediation (`audit/bpa_checks.py`)
- NSF-ZT-1 and CE-FW-2 NCSC cross-references added to `BPA_TO_NCSC` for both new checks (`audit/ncsc_controls.py`)
- **`scm_config_versions`** — list all SCM config versions with commit timestamps, descriptions, admin, and human-readable age; marks the currently active running version; uses `GET /config/v1/config-versions` + `GET /config/v1/config-versions/running` (`tools/deployment.py`)
- **`scm_config_push_track`** — async config push with 10-second job polling, rich result table (duration, job ID, status %, warnings, device details), and optional `rollback_on_failure=True` that automatically loads the pre-push running version back to candidate if the job fails (`tools/deployment.py`)
- **`scm_config_rollback`** — load any saved config version back to candidate via `POST /config/v1/config-versions/{version}:load`; shows original commit metadata for confirmation; optional `commit_immediately=True` to push the rollback in one call (`tools/deployment.py`)
- **BPA-TP-007** — WildFire profile content coverage check: verifies profiles cover all high-risk file types (PE, PDF, MS-Office, JAR, ELF, APK, Flash) with direction=both and a block action on malicious verdicts; profiles with narrow file-type rules or missing block actions are flagged (`audit/bpa_checks.py`)
- **BPA-URL-002** — URL access profile block-category verification: checks that every URL access profile has explicit block rules for high-risk categories (malware, phishing, command-and-control, hacking, proxy-avoidance, dynamic-dns); profiles missing these blocks are listed as affected objects (`audit/bpa_checks.py`)
- **BPA-DEC-002** — Decryption rule coverage check: verifies that at least one decryption rule with `action=decrypt` is active in the rulebase; distinguishes between no profiles, no rules, and rules-but-only-exclusions failure modes (`audit/bpa_checks.py`)

### Changed
- **`scm_spn_bandwidth`** — now queries Prisma Access Insights v3.0 for live per-SPN throughput (Mbps in/out, 5-minute rolling average) and shows utilisation % against configured allocation; gracefully falls back to allocation-only mode if the tenant token lacks Insights scope (`tools/ops.py`, new `_insights_spn_throughput` helper)
- **`scm_tenant_dashboard`** — "Nearest Expiry" now excludes already-expired SKUs by default so the licence RAG reflects active renewal health rather than a long-dead legacy SKU (e.g. an old logging_service Production License) pinning every tenant to EXPIRED; new `include_expired=True` parameter restores the nearest-across-all-SKUs behaviour, and a tenant whose licences are all expired still flags red via a worst-SKU fallback (`tools/ops.py`, new `_nearest_licence_expiry` helper)
- **HTTP server** — bind address is now configurable via `SCM_MCP_HTTP_HOST` (defaults to `0.0.0.0` for containers) instead of being hardcoded (`server_http.py`)

### Tooling
- Re-enabled mypy type-checking on 7 of 8 previously-`ignore_errors` modules (only `audit/asbuilt_report` remains); fixed 3 latent type issues in `audit/insights_extractor` and `tools/mssp`
- Aligned the bandit SAST gate between CI and pre-commit (both fail on MEDIUM+); granted `pull-requests: read` to the PR-title and gitleaks CI jobs (previously 403-failing on every PR); resolved 5 MEDIUM bandit findings with real fixes / justified `nosec`
- Bumped all GitHub Actions to latest majors (`checkout` v7, `upload-artifact` v7, `setup-uv` v7, `build-push-action` v7, `setup-buildx-action` v4, `metadata-action` v6)
- Added 23 unit tests for the `tools/ops.py` pure helpers (cert/licence status thresholds, semver comparison, nearest-expiry selection)

### Added
- **`scm_cert_scan`** — scan all certificate objects across Shared, Remote Networks, Mobile Users, and Service Connections; flags CRITICAL (<30d), WARNING (<60d), CAUTION (<90d), EXPIRED; cross-references IKE gateways using cert auth vs PSK (`tools/ops.py`)
- **`scm_licence_forecast`** — licence expiry and seat utilisation per tenant; groups by app_id + expiry date, flags oversubscribed pools, `all_tenants=True` sweeps every MSSP tenant in one call (`tools/ops.py`)
- **`scm_tenant_dashboard`** — lightweight NOC wallboard; rules, remote networks, IKE tunnels, nearest licence expiry, and RAG status for every MSSP tenant in a single Markdown table; targeted REST calls only, no full snapshot extraction (`tools/ops.py`)
- **`scm_spn_bandwidth`** — SPN bandwidth allocation vs branch count; per-branch Mbps share, HIGH/MEDIUM/LOW oversubscription risk rating, QoS config, full branch roster per SPN, `all_tenants=True` mode (`tools/ops.py`)
- **`scm_gp_session_summary`** — live GP + Prisma Access Agent session count by country (GeoIP), compute node, client type, and GP version; compares connected sessions against licensed MU seat capacity and shows utilisation%; privacy-safe (aggregate counts only, no usernames or IPs) (`tools/ops.py`)
- **`scm_check_updates`** — checks PyPI for latest versions of `pan-scm-sdk`, `prisma-sase`, `mcp`, and `scm-mcp-mssp`; fetches `pan-scm-sdk` GitHub release notes and recent `pan.dev` SASE API commit log; shows 🟢/🟡/⚪ status per package (`tools/ops.py`)
- **`scm_restart`** — schedules a clean SIGTERM after returning the response so Claude Desktop or a supervisor can automatically reconnect; configurable `delay_seconds` (default 3, min 1) (`tools/reload.py`)
- **CLI: Check for Updates (`U`)** — new MANAGEMENT menu option; rich table of PyPI versions + pan-scm-sdk release notes + pan.dev SASE API recent commits (`cli.py`)
- **CLI: Restart MCP Server (`R`)** — new MANAGEMENT menu option; finds running `scm-mcp` / `scm-mcp-http` processes with `pgrep`, sends SIGTERM, offers to restart in background (`cli.py`)
- **Unique AS-BUILT Document ID** — every generated AS-BUILT now receives an `ASBUILT-YYYYMMDD-<8hex>` stamp shown in the document header and §1 Document Control table
- **Appendix E — SCM Configuration Change History** (§8.7) — last 20 SCM commits with date, user, type, result, and description automatically appended to every AS-BUILT

### Changed
- **HLD → AS-BUILT rebrand** — `hld_report.py` → `asbuilt_report.py`, `HLDReportBuilder` → `AsBuiltReportBuilder`, MCP tool `scm_hld_report` → `scm_asbuilt_report`, stamp prefix `HLD-` → `ASBUILT-`, output filenames `*-hld.*` → `*-asbuilt.*`; all docstrings, CLI labels, and docs updated
- **Reference architecture diagrams moved to Appendix F** (§8.8) — all four PAN Mermaid diagrams (Enterprise SASE, Prisma Access routing, SD-WAN dual-hub, MSSP hierarchy) removed from main body sections §2–§8; live AS-BUILT topology in §2.1 remains in the main body
- **Removed §8 MSSP Service & BAU Support Model** from AS-BUILT report — generic RACI/ITSM/escalation boilerplate replaced by live operational data tools; old §9 Appendices renumbered to §8

### Fixed
- **`oauth.token_expires_soon()` TypeError** — `token_expires_soon` is a `@property`, not a method; removed erroneous `()` call in `fetch_licenses`, `insights_extractor`, and `scm_mobile_user_stats` token-refresh paths

### Security
- **Purged customer report files from git history** — three previously committed report files removed from all commits using `git filter-repo`; force-pushed to GitHub
- **Hardened `.gitignore`** — `reports/`, `*.docx`, `*hld*.md`, `*asbuilt*.md`, `*bpa-*.md`, `*ncsc-*.md`, `tenant-*.md`, `backups/`, `ai-design-components/` (plus local-only customer-prefixed globs in `.git/info/exclude`); generated reports will never be accidentally committed

### Known Gaps


- `scm_aiops_bpa` integrated and working but requires **AIOps BPA portal registration**: the API (`/aiops/bpa/v1/requests`) validates `requesterEmail` against PAN's AIOps BPA user database independently of PANW CSP auth — service account emails (`.iam.panserviceaccount.com`) are rejected as the portal requires a registered human CSP user email; contact bpa@paloaltonetworks.com or register at aiops.paloaltonetworks.com to enable; once enabled the tool is fully functional
- No CRUD on: services, service groups, decryption rules, application override rules
- No identity/auth server profile CRUD (RADIUS, LDAP, SAML, TACACS+, Kerberos) — list only via extractor
- GlobalProtect Mobile Agent config resources (agent profiles, tunnel profiles) available in SDK v0.15.0 but no dedicated CRUD MCP tools yet
- `scm_posture_report`, `scm_adnsr_*`, and `scm_ngfw_local_config_*` are implemented but return 403 in non-subscribed tenants — Posture Management and Advanced DNS Security Resolver require separate PAN add-on subscriptions; NGFW Operations requires the NGFW Operations entitlement on the TSG

## [0.4.7] - 2026-06-22

### Added
- `scm_browser_list` — Prisma Browser (RBI) device/user/application group inventory via `/seb/api/v1/`
- `scm_airs_list` — Prisma AIRS (AI Runtime Security) customer apps, profiles, and deployment profiles
- `scm_ngfw_device_list` — NGFW managed devices with model, serial, HA state, and connection status
- GlobalProtect agent profile and tunnel profile sections in AS-BUILT report (§3 Mobile Users)
- NGFW health and HA status sections added to AS-BUILT report

### Fixed
- SD-WAN `sdwan_list_wan_interfaces` and `sdwan_debug_topology` API path corrections
- Mobile-agent REST fallback URLs corrected for GP agent/tunnel profile endpoints

## [0.4.6] - 2026-06-20

### Added
- `scm_ai_compliance_advisor` — AI-powered compliance advisor combining NCSC/NIST gap checks with Claude-generated executive summary and remediation playbook (`tools/ai_advisor.py`)
- `scm_nist_gap` — NIST CSF v2.0 / SP 800-53 Rev 5 gap analysis remapping NCSC structural checks to NIST control identifiers
- `scm_create_nist_snippet` — create reusable SCM snippet with NIST-compliant security profiles and NIST-Compliant tag

## [0.4.5] - 2026-06-19

### Added
- `scm_create_ncsc_snippet` — create a reusable SCM snippet containing NCSC-compliant security profiles (anti-spyware, vulnerability, WildFire, URL, log forwarding, tag); distinct from folder-scoped `scm_apply_ncsc_baseline`
- AS-BUILT report: Markdown-to-Word (docx) conversion via `python-docx`; `output_format='docx'` now works without pandoc

## [0.4.4] - 2026-06-19

### Added
- `scm_list_jobs` — list SCM commit/push jobs with username, type, result, and timestamps for commit audit history
- Tenant metadata cache: tenant label and region stored at auth time for use in AS-BUILT and tier reports

### Fixed
- `scm_asbuilt_report` §8 MSSP Service Model always rendered (was silently skipped on partial data)
- AS-BUILT VPN crypto tables always populated from IKE/IPSec objects

## [0.4.3] - 2026-06-18

### Added
- `scm_mobile_user_stats` — live Prisma Access connected user count and bandwidth allocation via Prisma Access Insights API
- `dlp_backup` and `dlp_restore` — export and restore both SCM inline DLP and Enterprise DLP configuration across tenants

### Fixed
- 5xx error suppression across all extractor paths — non-fatal API errors no longer abort full AS-BUILT/backup runs
- SSE REST fallback URLs corrected for mobile-agent resource endpoints

## [0.4.2] - 2026-06-18

### Added
- `scm_ztna_connector_list` — ZTNA Connector inventory via `/sse/connector/v2.0/api/`
- `scm_dlp_list` — SCM inline DLP data-filtering profiles and data objects
- `scm_casb_list` — CASB SaaS tenant restriction policies
- `dlp_enterprise_list` — Enterprise DLP data patterns and ML-based profiles from `api.dlp.paloaltonetworks.com`

## [0.4.1] - 2026-06-17

### Added
- `scm_license_info` — Prisma SASE subscription licence inventory with SKU, seat count, and expiry via `/subscription/v1/licenses`
- CLI management menu: tenant onboarding option (A) added

### Fixed
- `fetch_licenses` in `oauth.py` — corrected auth header construction for subscription API

## [0.3.0] - 2026-06-17

### Added

#### MSSP Tier System (`audit/tiers.py`)
- `TierDefinition` frozen dataclass — specifies required BPA check severities, NCSC framework scope, SCM snippet names, and commercial feature description per tier
- Three tier definitions:
  - **Bronze** — Cyber Essentials baseline: Critical-only BPA checks, CE v3.2 framework, 2 SCM snippets (`MSSP-Bronze-SecurityProfiles`, `MSSP-Bronze-Policies`)
  - **Silver** — Cyber Essentials Plus: Critical + High BPA checks, CE v3.2 + 10 Steps, 4 SCM snippets (adds WildFire, DNS security, log forwarding, zone protection)
  - **Gold** — NCSC CAF v4.0 full: All BPA checks (Critical + High + Medium + Low), all frameworks, 6 SCM snippets (adds SSL/TLS decryption profiles + policies)
- `score_findings_against_tier(findings, tier)` — separates findings into tier-required breaches vs out-of-scope advisory, returns compliance score percentage
- `upgrade_gap(findings, from_tier, to_tier)` — identifies blocking findings, new NCSC controls, and additional snippets needed to upgrade tier
- `SNIPPET_TEMPLATES` — content specifications for all 12 tier SCM snippets (Bronze ×2, Silver ×4, Gold ×6); used by onboarding tool to guide snippet creation
- `TIER_ORDER` list (`["bronze", "silver", "gold"]`) for ordered tier traversal
- Tier hierarchy is a strict superset chain: every Silver requirement is also a Gold requirement; every Bronze requirement is also a Silver requirement

#### MCP Tools — MSSP Tier Management (`tools/mssp.py`)
- `mssp_tier_assess` — score a folder against a contracted tier; returns JSON with `tier_compliant`, `compliance_score_pct`, `breaches`, `advisory`, and automatic upgrade gap count
- `mssp_tier_report` — customer-facing Markdown compliance report with visual compliance bar, breach remediation steps, advisory upsell context, and upgrade path section; optional `save_to` path
- `mssp_upgrade_path` — JSON gap analysis between any two tiers: blocking findings, additional NCSC controls, snippets to apply, new features
- `mssp_onboard_tenant` — checks which tier snippets exist in SCM, associates present ones with the customer folder; `dry_run=True` by default to preview before execution; `create_folder=True` creates the folder if needed
- `mssp_tenant_dashboard` — Markdown dashboard of all currently loaded MSSP tenants
- `mssp_snippet_catalogue` — Markdown catalogue of all tier snippet templates and content specifications, filterable by tier
- `mssp_tier_comparison` — side-by-side Gold / Silver / Bronze feature comparison table (suitable for sales / customer conversations)

#### TenantConfig additions (`config/settings.py`)
- `tier: ServiceTier` field (default `"bronze"`) — `Literal["gold", "silver", "bronze"]`; loaded from `settings.toml` `[tenants.*]` blocks
- `service_term_years: int` field (default `1`, range 1–3) — contract duration in years
- `account_ref: str` field — CRM / ticketing system reference for cross-system linking
- `ServiceTier` type alias exported from `config/settings.py`

#### Settings template (`settings.toml`)
- `[tenants.*]` block template extended with `tier`, `service_term_years`, and `account_ref` fields with inline documentation
- Tier descriptions added as comments explaining the three-tier NCSC framework mapping

#### Tests (`tests/unit/test_tiers.py`)
- 33 new unit tests across 5 test classes:
  - `TestTierDefinitions` — existence, hierarchy (superset chain), NCSC coverage, snippet non-empty
  - `TestTierScoring` — breach vs advisory separation at each tier, WARN counts as breach, compliance score maths
  - `TestUpgradeGap` — blocking detection, new snippet identification, NCSC control delta, two-tier skip
  - `TestTenantConfigTierField` — default values, accepted values, optional fields

## [0.2.0] - 2026-06-17

### Added

#### Audit Engine (`audit/` subpackage)
- `AuditSnapshot` dataclass — flat, SDK-agnostic representation of all auditable SCM config for a folder/tenant
- `AuditExtractor` (`audit/extractor.py`) — pulls 30+ resource types from SCM via the SDK into an `AuditSnapshot`; non-fatal per-resource error capture so partial data still produces findings
- `Finding` dataclass with `Severity` (critical/high/medium/low/info) and `Status` (fail/pass/warn/skip) enums
- `bpa_checks.py` — 21 PAN Best Practice Assessment checks across six categories:
  - **Security Rules** (SR-001–008): no-profile allow rules, permit-any-any, logging at session end, disabled rule hygiene, app-any allow rules, deny rule logging, unrestricted outbound, explicit deny-all
  - **Threat Prevention** (TP-001–006): anti-spyware with DNS sinkholing, DNS security profiles, vulnerability protection profiles, WildFire profiles, file blocking profiles, SSL/TLS decryption profiles
  - **URL Filtering** (URL-001): URL category configuration check
  - **Zone Protection** (ZP-001): zones without zone protection profiles
  - **Logging** (LOG-001–003): log forwarding profiles, syslog server profiles, allow rules missing log forwarding
  - **Network** (NET-001–002): minimum zone segmentation, remote network IPSec configuration
- `ncsc_controls.py` — 16 NCSC control definitions across four frameworks:
  - CAF v4.0 (August 2025): B2.a/b/c, B3.a/b, B4.a, C1.a/b
  - Cyber Essentials v3.2: CE-FW-1/2/3/4
  - 10 Steps to Cyber Security: 10S-NS-1/2/3, 10S-TP-1
  - Network Security Fundamentals: NSF-ZT-1, NSF-LOG-1
- `BPA_TO_NCSC` mapping — cross-references every BPA check ID to its applicable NCSC control IDs
- `ReportBuilder` (`audit/report.py`) — renders findings as structured JSON (SIEM-ingestible) or Markdown (AS-BUILT AS-IS document) with executive summary, config inventory table, severity-grouped findings with remediation, NCSC control index

#### MCP Tools — Audit (`tools/audit.py`)
- `scm_config_backup` — exports complete config snapshot to timestamped JSON file; records resource counts and non-fatal extraction errors; respects `SCM_MCP_BACKUP_DIR` env var
- `scm_bpa_assess` — runs all BPA checks against live SCM config; supports `severity_filter` and `failed_only` parameters; returns JSON findings with NCSC cross-references
- `scm_ncsc_assess` — control-by-control NCSC compliance view; filterable by framework (`caf`/`ce`/`10steps`/`all`); returns compliant/non-compliant/not-assessed per control with linked findings
- `scm_audit_report` — combined BPA + NCSC Markdown or JSON report (AS-BUILT); optional `save_to` path writes report to disk
- `scm_config_diff` — compares two backup JSON files; returns structured diff of added/removed/modified objects per resource type; suitable for pre/post change-window auditing

#### References
- pan.dev `aiops-ngfw-bpa` product directory identified as source for BPA API spec (`BPAReportAPI.yaml`)
- PAN AIOps BPA API endpoint documented: `api.stratacloud.paloaltonetworks.com/aiops/bpa/v1`
- NCSC CAF v4.0 (published August 2025), Cyber Essentials v3.2, NCSC 10 Steps, and Network Security Fundamentals used as compliance sources
- `panos-to-scm` (github.com/PaloAltoNetworks/panos-to-scm, archived Aug 2024) used as resource type completeness checklist

## [0.1.0] - 2026-06-17

### Added

#### Core Infrastructure
- `uv`-managed Python 3.12 project with `src/` layout and `hatchling` build backend
- `pyproject.toml` with `[project.scripts]` entry point (`scm-mcp`)
- `pydantic-settings` `Settings` class with `SCM_MCP_` env prefix for all server config
- Per-tenant `TenantConfig` (Pydantic model) with `SecretStr` client secret and field validation
- `dynaconf` integration for multi-tenant credential loading from `settings.toml` / `.secrets.toml`
- Thread-safe per-tenant `Scm` client cache in `auth/oauth.py` with `evict_tenant` for credential rotation
- Structured JSON logging via `structlog` with ISO timestamps and noisy-library suppression
- Custom exception hierarchy: `ScmMcpError`, `TenantNotFoundError`, `AuthenticationError`, `ResourceNotFoundError`, `ValidationError`

#### MCP Server (`server.py`)
- `FastMCP` server (`scm-mcp-mssp`) with `stdio` and `SSE` transport support (`--transport`, `--host`, `--port` flags)
- MSSP multi-tenant client resolver: routes `tenant_id` argument to correct cached `Scm` client in MSSP mode, falls back to default credentials in single-tenant mode
- Eager tenant pre-loading from `settings.toml` `[tenants.*]` blocks on startup when `SCM_MCP_MSSP_MODE=true`
- Startup authentication validation for default (single-tenant) credentials

#### MCP Tools — Objects (`tools/objects.py`)
- `scm_address_list` — list address objects with optional name filter
- `scm_address_get` — fetch single address object by name
- `scm_address_create` — create address object (ip_netmask / fqdn / ip_range)
- `scm_address_delete` — delete address object by name
- `scm_address_group_list` — list address groups
- `scm_service_list` — list service objects
- `scm_tag_list` — list tags
- `scm_edl_list` — list external dynamic lists

#### MCP Tools — Security (`tools/security.py`)
- `scm_security_rule_list` — list security rules with pre/post position support
- `scm_security_rule_get` — fetch single security rule by name
- `scm_security_rule_create` — create security rule (zones, addresses, applications, services, profile groups)
- `scm_security_rule_delete` — delete security rule by name
- `scm_anti_spyware_profile_list` — list anti-spyware profiles
- `scm_url_category_list` — list URL categories

#### MCP Tools — Network (`tools/network.py`)
- `scm_zone_list` — list security zones
- `scm_nat_rule_list` — list NAT rules with pre/post position support
- `scm_nat_rule_get` — fetch single NAT rule by name
- `scm_ike_gateway_list` — list IKE gateways
- `scm_ipsec_tunnel_list` — list IPSec tunnels
- `scm_dns_server_list` — list DNS server profiles

#### MCP Tools — Deployment (`tools/deployment.py`)
- `scm_remote_network_list` — list remote networks (branch / SD-WAN connections)
- `scm_remote_network_get` — fetch single remote network by name
- `scm_service_connection_list` — list service connections (cloud / DC interconnects)
- `scm_bandwidth_allocation_list` — list Prisma Access bandwidth allocations
- `scm_commit` — commit candidate config for one or more folders (synchronous, 300s timeout)
- `scm_job_status` — poll status of an async SCM job

#### MCP Tools — Setup & MSSP (`tools/setup.py`)
- `scm_folder_list` — list SCM folders (customer hierarchy)
- `scm_folder_get` — fetch single folder by name
- `scm_device_list` — list onboarded devices (firewalls, Panorama)
- `scm_snippet_list` — list configuration snippets
- `mssp_list_tenants` — list all currently loaded tenant IDs
- `mssp_evict_tenant` — remove cached client to force re-authentication after credential rotation

#### MCP Resources (`resources/tenant.py`)
- `scm://tenants` — index of all loaded tenants
- `scm://tenants/{tenant_id}` — per-tenant authentication status
- `scm://tenants/{tenant_id}/folders` — folder list for a given tenant

#### Configuration & Secrets
- `settings.toml` — dynaconf config with `[tenants.*]` multi-tenant block template
- `.secrets.toml.example` — per-tenant secret template (git-ignored at `.secrets.toml`)
- `.env.example` — all `SCM_MCP_*` environment variables documented

#### Developer Tooling
- `ruff` linting and formatting (line length 100, `E F I UP B SIM` rules)
- `mypy` strict type checking with `pydantic.mypy` plugin
- `pre-commit` hooks: ruff, ruff-format, trailing whitespace, YAML/TOML check, private key detection, no-commit-to-main
- GitHub Actions CI workflow: lint → format check → mypy → pytest on push/PR
- `pytest` with `pytest-asyncio` and `pytest-cov` configured
- Unit tests: `TestTenantConfig` (valid config, empty ID validation, secret not leaked in repr) and `TestSettings` (defaults, env override) and `TestClientCaching` (cache hit, eviction, unknown tenant error)

[Unreleased]: https://github.com/silverbacksec/scm-mcp-mssp/compare/v0.4.7...HEAD
[0.4.7]: https://github.com/silverbacksec/scm-mcp-mssp/compare/v0.4.6...v0.4.7
[0.4.6]: https://github.com/silverbacksec/scm-mcp-mssp/compare/v0.4.5...v0.4.6
[0.4.5]: https://github.com/silverbacksec/scm-mcp-mssp/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/silverbacksec/scm-mcp-mssp/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/silverbacksec/scm-mcp-mssp/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/silverbacksec/scm-mcp-mssp/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/silverbacksec/scm-mcp-mssp/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/silverbacksec/scm-mcp-mssp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/silverbacksec/scm-mcp-mssp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/silverbacksec/scm-mcp-mssp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/silverbacksec/scm-mcp-mssp/releases/tag/v0.1.0
