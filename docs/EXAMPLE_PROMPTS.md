# Example Prompts for Claude Desktop

A copy/paste library of natural-language requests you can drop straight into Claude Desktop (or Cursor, or any MCP client connected to this server) to drive **scm-harbourmaster-mcp**. No tool names or JSON required — just ask.

**255 examples** across 34 categories, mirroring [`TOOL_REFERENCE.md`](TOOL_REFERENCE.md).

## Before you start

- **Placeholders.** `Acme Corp`, `Contoso Ltd`, `Meridian Health`, `Customer-A`, `acme-corp`, and branch names like `Manchester-Branch-12` are stand-ins. Swap them for your own tenant labels and SCM folder names — Claude will pick the right `tenant_id`/`folder` from what you type as long as it roughly matches a configured tenant.
- **Single-tenant setups.** If you're not running in MSSP mode, drop the tenant name from any prompt below — every tool falls back to your default tenant automatically.
- **`folder` matters.** Most config-read/write tools scope to an SCM folder (`Shared`, `Prisma Access`, `Remote Networks`, or a per-customer folder). If you don't specify one, Claude will ask or use a sensible default — naming it up front avoids a back-and-forth.
- **Write operations are safe by default.** Anything that creates, deletes, or changes config (address objects, security rules, NCSC baselines, SSR changes, config-orch writes) defaults to a dry run and won't touch your tenant until you explicitly say "apply it" / "make it live" / "set dry_run to false".
- **Long-running jobs.** AS-BUILT reports, all-tenant drift sweeps, and Planner runs return a job ID and keep working in the background — just ask "check on that job" a minute later.

---

## Table of contents

1. [Objects](#1-objects) (10)
2. [Security Policy & Profiles](#2-security-policy--profiles) (10)
3. [Network](#3-network) (8)
4. [Deployment & Connectivity](#4-deployment--connectivity) (12)
5. [Setup & Tenant Management](#5-setup--tenant-management) (8)
6. [Audit & Reporting](#6-audit--reporting) (20)
7. [NCSC/NIST Baseline](#7-ncscnist-baseline) (8)
8. [Enterprise DLP](#8-enterprise-dlp) (8)
9. [MSSP Multi-Tenant](#9-mssp-multi-tenant) (16)
10. [Prisma SD-WAN](#10-prisma-sd-wan) (22)
11. [Operational Visibility](#11-operational-visibility) (14)
12. [Posture Management](#12-posture-management) (6)
13. [Advanced DNS Security & NGFW Operations](#13-advanced-dns-security--ngfw-operations) (8)
14. [AIOps](#14-aiops) (3)
15. [AI Compliance Advisor](#15-ai-compliance-advisor) (4)
16. [Service Provider Interconnect](#16-service-provider-interconnect) (4)
17. [Prisma Access Browser for MSP](#17-prisma-access-browser-for-msp) (4)
18. [Utility](#18-utility) (3)
19. [ADEM (Digital Experience)](#19-adem-digital-experience) (4)
20. [CDL Log Forwarding](#20-cdl-log-forwarding) (3)
21. [Compliance Center](#21-compliance-center) (6)
22. [Config Orchestration (Site Onboarding)](#22-config-orchestration-site-onboarding) (9)
23. [CSP Licensing](#23-csp-licensing) (3)
24. [DNS Security](#24-dns-security) (3)
25. [Email DLP](#25-email-dlp) (3)
26. [Insights](#26-insights) (6)
27. [Monthly Service Review (MSR)](#27-monthly-service-review-msr) (3)
28. [Cross-Tenant Monitoring (MT Monitor)](#28-cross-tenant-monitoring-mt-monitor) (5)
29. [Prisma Access Browser (Tenant)](#29-prisma-access-browser-tenant) (5)
30. [Planner (Autonomous Agent)](#30-planner-autonomous-agent) (8)
31. [Service Status](#31-service-status) (3)
32. [SSR (Simple Service Requests)](#32-ssr-simple-service-requests) (6)
33. [Cross-Tool Workflows](#33-cross-tool-workflows) (20)
34. [Rule Optimization & Cleanup](#34-rule-optimization--cleanup) (3)

---

## 1. Objects

_Addresses, address groups, services, tags, EDLs._

1. "List every address object in the Shared folder for Acme Corp."
2. "Show me all address objects whose name contains 'DC' in the Prisma Access folder."
3. "Create an address object called `HQ-Subnet` for 10.10.0.0/24 in the Customer-A folder, description 'Head office LAN'."
4. "Fetch the details of the address object `Branch-01-LAN`."
5. "Delete the address object `old-test-host` from the Shared folder — it's no longer needed."
6. "List all address groups configured for Contoso Ltd."
7. "What service objects exist in the Remote Networks folder?"
8. "Show me every tag defined in the Shared folder so I know what's already in use before I add a new one."
9. "List the external dynamic lists (EDLs) configured for Acme Corp — I want to check if our threat-intel feed is still there."
10. "Give me the address groups in the Customer-B folder and tell me which ones look unused (no obvious naming pattern match to current rules)."

## 2. Security Policy & Profiles

_Security rules (CRUD), Anti-Spyware profiles, URL categories._

11. "List all pre-rulebase security rules for Acme Corp's Prisma Access folder."
12. "Show me the post-rulebase security rules for Contoso Ltd."
13. "Fetch the full details of the security rule named `Allow-Web-Outbound`."
14. "Create a security rule called `Block-TOR-Egress` in the Shared folder that denies any source to any destination for the TOR application, logged."
15. "Add an allow rule `HQ-to-DC-SQL` from zone Trust to zone DMZ, source HQ-Subnet, destination DB-Servers, application mssql, service application-default."
16. "Delete the security rule `Temp-Testing-Rule` from the Customer-A folder."
17. "List the anti-spyware profiles configured for this tenant — I want to confirm cloud inline analysis is enabled."
18. "Show me every URL filtering category defined in the Shared folder."
19. "Are there any security rules with no security profile group attached? Check the pre-rulebase for Acme Corp."
20. "Compare the security rules in Customer-A's folder against Customer-B's and tell me what's structurally different."

## 3. Network

_Zones, NAT, IKE gateways, IPSec tunnels, internal DNS._

21. "List all security zones configured for Acme Corp."
22. "Show me every NAT rule in the Prisma Access folder."
23. "Fetch the NAT rule called `Outbound-SNAT-HQ` and show me its translation config."
24. "List the IKE gateways configured for Contoso Ltd — I need to check peer IP addresses."
25. "Show me all IPSec tunnels currently configured and their associated IKE gateways."
26. "What internal DNS servers are configured for this tenant?"
27. "List the zones in the Customer-A folder and check whether a `dmz` zone actually exists before I create a rule that references it."
28. "Give me a full inventory of IKE gateways and IPSec tunnels together so I can sanity-check the VPN topology."

## 4. Deployment & Connectivity

_Remote Networks, Service Connections, Bandwidth Allocations, config versions, jobs, commits._

29. "List all remote networks (branches) configured for Acme Corp."
30. "Fetch the details of the remote network called `Manchester-Branch-12`."
31. "Show me the service connections configured for Contoso Ltd — I need to see which data centres are attached."
32. "List the bandwidth allocations per compute location for this tenant."
33. "Commit the pending changes in the Shared and Prisma Access folders for Acme Corp, with the description 'CHG-4521 firewall rule update'."
34. "Check the status of job ID 8827391."
35. "List the last 20 SCM jobs for Contoso Ltd so I can see who committed what recently."
36. "Show me the config version history for Acme Corp — I need to see when the running config last changed."
37. "Push the candidate config in the Prisma Access folder for Customer-A with auto-rollback enabled if the push fails, description 'weekly change window'."
38. "Roll back Acme Corp's config to version 47 and commit it immediately, description 'reverting bad change from this morning'."
39. "Who triggered the last failed commit job for Contoso Ltd? Filter the job list to failures only."
40. "List remote networks and service connections together for Acme Corp so I have a single connectivity picture before the change call."

## 5. Setup & Tenant Management

_Folders, devices, snippets, tenant cache management._

41. "List all SCM folders for Acme Corp — I want to see the customer hierarchy."
42. "Fetch the folder details for `Customer-A`."
43. "List every device onboarded to SCM for Contoso Ltd, including Panorama."
44. "Show me all configuration snippets available for this tenant."
45. "List every MSSP tenant currently loaded and authenticated in this server."
46. "Evict the cached client for `contoso-ltd` — we just rotated their OAuth2 credentials."
47. "Check which folders exist for Acme Corp before I onboard `Customer-C` — I don't want to create a duplicate."
48. "List devices and snippets for Customer-B in one go so I can confirm what's already deployed."

## 6. Audit & Reporting

_Config backup, BPA, NCSC/NIST/DSPT/ISO 27001, AS-BUILT & HLD reports, drift, config diff & clone, RCA._

49. "Back up the full SCM configuration for Acme Corp's Prisma Access folder to a JSON snapshot."
50. "Run a Best Practice Assessment against Contoso Ltd's Shared folder and show me only the failed and warned checks."
51. "Run a BPA assessment for Acme Corp filtered to critical-severity findings only."
52. "Assess Acme Corp against NCSC CAF v4.0 for the Prisma Access folder."
53. "Run an NCSC compliance check against just the Cyber Essentials framework for Customer-A."
54. "Assess Meridian Health's config against the NHS DSPT standards 8 and 9, and save the report to `reports/meridian-dspt.md`."
55. "Run an ISO 27001:2022 Annex A assessment against Acme Corp's Shared folder, technological controls only."
56. "Do a deep-dive SSL/TLS decryption policy audit for Contoso Ltd and tell me whether decryption coverage is adequate."
57. "Generate a combined BPA + NCSC audit report for Customer-A and save it to `reports/customer-a-audit.md`."
58. "Generate a full AS-IS AS-BUILT document for Acme Corp's Prisma Access deployment, customer name 'Acme Corp', MSSP name 'Silverback Security', and include live SD-WAN data."
59. "Check on the AS-BUILT job I started for Contoso Ltd a few minutes ago."
60. "Verify the AS-BUILT document we generated for Acme Corp last week against their current live config — has anything drifted since?"
61. "Capture a config drift baseline for Acme Corp's Prisma Access folder now that the change window is closed."
62. "Run a drift check for Contoso Ltd against the last captured baseline and tell me if anything unexpected changed."
63. "Baseline every configured tenant overnight — kick off an all-tenants drift capture."
64. "Check the drift sweep job result for job ID `drift-88213`."
65. "Analyse the blast radius of the pending changes in Acme Corp's Prisma Access folder before I commit — what would this touch?"
66. "Run an incident root-cause analysis for Contoso Ltd — connectivity has been flaky since this morning, help me correlate config changes."
67. "Diff the current live config for Customer-A against the backup we took last month and tell me exactly what changed."
68. "Clone Acme Corp's golden-config backup into the new `Customer-D` folder, sanitising any pre-shared keys."

## 7. NCSC/NIST Baseline

_Apply compliant profiles, create reusable snippets, gap analysis._

69. "Show me what would be created if I applied the NCSC baseline to Acme Corp's Shared folder — dry run first."
70. "Apply the NCSC-compliant security baseline to Contoso Ltd's Customer-A folder for real, and attach our syslog profile `Syslog-EU-01`."
71. "Create an NCSC-compliant snippet called `NCSC-Baseline` that I can reuse across our managed customers."
72. "Create a NIST-compliant snippet named `NIST-CSF-Baseline` with description 'NIST CSF v2.0 baseline for US customers'."
73. "Attach the NCSC baseline profile group to every allow rule in Acme Corp's Prisma Access folder that's currently missing one — dry run first, please."
74. "Now actually apply that NCSC profile attachment for real, not just a dry run."
75. "Run an NCSC gap analysis against Contoso Ltd's pre-rulebase and tell me exactly which controls are failing."
76. "Run a NIST gap analysis against Customer-A covering both pre- and post-rulebase."

## 8. Enterprise DLP

_ML-based DLP patterns/profiles, inline data-filtering backup/restore, DLP incidents._

77. "List the Enterprise DLP data patterns and profiles configured for Acme Corp."
78. "Back up Contoso Ltd's full DLP configuration — both inline SCM data-filtering and Enterprise DLP patterns — to a JSON file."
79. "Restore that DLP backup onto Customer-B's folder as a dry run first, so I can see what would be created."
80. "Now apply the DLP restore for real onto Customer-B."
81. "List open DLP incidents for Acme Corp from the last 30 days, critical and high severity only."
82. "Get the full detail on DLP incident ID `dlp-99213`."
83. "Who are the available assignees for DLP incidents on this tenant?"
84. "Export Acme Corp's DLP config as a backup so I can redeploy the exact same patterns on their new EU tenant."

## 9. MSSP Multi-Tenant

_Tenant dashboard, licensing, CASB, ZTNA, Browser, NGFW, AIRS._

85. "Run a BPA assessment on Acme Corp's Prisma Access folder and show me the failing checks."
86. "Generate a customer-facing NCSC compliance report for Contoso Ltd, save it to `reports/contoso-ncsc-report.md`."
87. "What would Customer-A need to fix to close their outstanding NCSC CAF gaps?"
88. "List the configuration snippets already in SCM before I onboard a new customer folder."
89. "Apply the NCSC baseline to the new `Customer-E` folder — dry run first, then for real."
90. "Show me the dashboard of every MSSP tenant currently loaded, with their folder and service term."
91. "List the NCSC snippet templates so I know what the baseline includes before I onboard the next customer."
92. "List all Prisma SASE subscription licences for Acme Corp with their expiry dates."
93. "Show me Contoso Ltd's mobile user allocation vs current logged-in user count."
94. "Discover every sub-tenant visible to our super-user SP account."
95. "List the DLP data-filtering profiles configured in SCM for Customer-A — not the Enterprise DLP ones, the inline ones."
96. "List the CASB SaaS tenant restriction policies configured for Acme Corp."
97. "Show me the ZTNA connector inventory for Contoso Ltd — is ZTNA Connector even licensed for them?"
98. "List Prisma Browser (RBI) configuration for Customer-A, including device and user groups."
99. "Compare NCSC CAF coverage across Acme Corp and Contoso Ltd — I'm on a sales call in ten minutes."
100. "List NGFW managed devices onboarded to SCM for Acme Corp, and separately check if AI Runtime Security (AIRS) is licensed for them."

## 10. Prisma SD-WAN

_Sites, elements, WAN interfaces/networks, path groups, policies, topology, events, audit log, software, link health._

101. "List all Prisma SD-WAN sites for Acme Corp — branches, DCs, and hub sites."
102. "List the ION elements deployed at the Manchester branch site."
103. "Show me the WAN interfaces configured at the Leeds branch."
104. "Give me a live WAN IP summary across every SD-WAN element for Acme Corp, and enrich each public IP with ISP/ASN/geo info."
105. "List the WAN networks (ISP circuit definitions) configured for Contoso Ltd."
106. "Show me the path groups configured for policy-based path selection."
107. "List every SD-WAN policy set, network type."
108. "List the hub and spoke clusters configured for the HA topology."
109. "Show me BGP configuration and peer status for the Manchester branch element."
110. "Generate a Mermaid VPN overlay topology diagram for Acme Corp's SD-WAN and save it to `topology.md`."
111. "Give me the raw topology JSON for site `manchester-01` — I want to check the field names against what we expect."
112. "Generate a full SD-WAN topology summary for Contoso Ltd covering sites, elements, WAN networks, and clusters."
113. "Generate an interactive HTML map of Acme Corp's SD-WAN sites — save it as `acme-site-map.html`."
114. "List SD-WAN events from the last 24 hours for Contoso Ltd, critical and major severity only, active issues first."
115. "Show me the SD-WAN audit log for the last 48 hours — who changed what."
116. "Report ION software versions across the estate and flag any elements pending an upgrade."
117. "Show me the security policy rules inside SD-WAN policy set `sec-set-01`."
118. "Report link quality — latency, jitter, MOS — for the Manchester branch over the last 6 hours, including bandwidth."
119. "Give me the top talkers by bytes for the Leeds branch over the last hour."
120. "Show me application health buckets (good/fair/poor) across all sites for the last 24 hours."
121. "Check cellular module status across every ION element with an LTE/5G card."
122. "Give me an events summary — counts by severity and category — for the last 7 days across the SD-WAN estate."

## 11. Operational Visibility

_Certificate scan/lifecycle, TLS profiles, licence forecast, NOC dashboard, SPN bandwidth, GP sessions, device/user summaries._

123. "Scan all certificates in Acme Corp's Shared folder and flag anything expiring within 60 days."
124. "Run a multi-tenant certificate lifecycle sweep across every MSSP tenant and highlight any SSL inspection CAs about to expire."
125. "Import this PEM certificate as `SSL-Inspect-CA-2027` into Contoso Ltd's Shared folder, marked as a CA cert."
126. "List the TLS service profiles configured for Customer-A."
127. "Create a new TLS service profile called `TLS-Strict` with minimum TLS 1.2 and maximum TLS 1.3."
128. "Forecast licence expiry and seat utilisation for Acme Corp over the next 90 days."
129. "Run a licence forecast across every configured tenant so I can see what's expiring this quarter."
130. "Generate a renewal-conversation brief for Contoso Ltd — I've got a QBR next week and need to know what's oversubscribed and what's underused."
131. "Give me the NOC health dashboard across every MSSP tenant — rules, remote networks, tunnels, and nearest licence expiry."
132. "Show me SPN bandwidth allocation vs live throughput for Acme Corp, and flag anything at high oversubscription risk."
133. "Give me a live GlobalProtect and Prisma Access Agent session summary for Contoso Ltd, broken down by country and compute node."
134. "Check whether there are any pending SDK, dependency, or pan.dev spec updates I should know about."
135. "Give me a device inventory health summary for Customer-A — connected vs offline, HA state breakdown."
136. "How many users are live-connected right now across Prisma Access and NGFW for Acme Corp, and what's our licensed capacity?"

## 12. Posture Management

_SCM Incidents API and Posture Management Best Practice Report._

137. "Search for open critical and high SCM incidents raised for Acme Corp in the last 30 days."
138. "Give me a cross-tenant NOC-style incident summary across every MSSP tenant for the last 7 days."
139. "Retrieve the Posture Management best-practice report for Contoso Ltd's Shared folder."
140. "Show me SaaS Security Posture (SSPM) findings for Customer-A — onboarded apps, misconfiguration findings, and IdP posture."
141. "Include the supported SaaS app catalog when you pull SSPM posture for Acme Corp."
142. "Export Contoso Ltd's SSPM posture snapshot to a JSON file so I can diff it against next month's run."

## 13. Advanced DNS Security & NGFW Operations

_ADNSR profiles/resources and NGFW local-config/WAN IP operations._

143. "List the Advanced DNS Security Resolver profiles configured for Acme Corp."
144. "Show me the internal domain bypass rules configured in ADNSR for Contoso Ltd."
145. "List any misconfigured domains flagged by ADNSR for Customer-A."
146. "Create a new ADNSR profile called `DNS-Sinkhole-Malware` that sinkholes threat domains and logs all queries."
147. "List the local configuration versions pushed to NGFW device serial `007351000123456`."
148. "Fetch the running XML configuration for that NGFW device so I can feed it into a BPA assessment."
149. "Report the configured WAN/internet-facing IPs for every NGFW device onboarded for Acme Corp."
150. "Run that same NGFW WAN IP summary but enrich each public IP with ISP, ASN, and geolocation data."

## 14. AIOps

_PAN's first-party AIOps Best Practice Assessment engine._

151. "Submit this PAN-OS running config XML to PAN's AIOps BPA engine for analysis — device is a PA-5220 running 11.1.3, requester email is jane@acmecorp.com."
152. "Run AIOps BPA against the NGFW config we just pulled for device serial `007351000123456`, labelled 'FW-NYC-01'."
153. "Compare the AIOps BPA findings against our own 39-check BPA for the same device — where do they disagree?"

## 15. AI Compliance Advisor

_Claude-powered executive summary and remediation playbook from NCSC/NIST gaps._

154. "Give me an AI-generated executive summary and remediation playbook from Acme Corp's NCSC and NIST gap findings."
155. "Run the AI compliance advisor against Contoso Ltd's Shared folder, NCSC framework only, and label the report with their tenant name."
156. "Generate the AI compliance advisor output for Customer-A covering both pre- and post-rulebase positions."
157. "I need a plain-English executive summary I can paste straight into a customer report — run the AI compliance advisor for Acme Corp on both NCSC and NIST."

## 16. Service Provider Interconnect

_SP backbone attach to Prisma Access — interconnects, physical connections, regions, IP pool usage._

158. "Show me the Service Provider Interconnect summary for Acme Corp."
159. "List all SPI interconnects configured and their physical connections."
160. "Show me SPI-capable regions filtered to AWS as the cloud provider."
161. "Check IP pool usage for interconnect `spi-eu-01`."

## 17. Prisma Access Browser for MSP

_Region-level PAB summaries and per-TSG security-event reports (multitenant MSP API)._

162. "Give me the region-level PAB tenant summary for Europe."
163. "Show me the Cloud Identity Engine (CIE) summary for our UK region PAB deployment."
164. "Pull a PAB security-event report for Acme Corp — blocked malware count."
165. "Show me the website category breakdown from Contoso Ltd's PAB security report."

## 18. Utility

_Hot-reload and restart the running MCP server._

166. "Hot-reload the server — I just edited a tool's source code and want the change to take effect without a full restart."
167. "Reload just the `asbuilt_report` and `extractor` modules."
168. "Restart the MCP server process — a hot reload isn't picking up my dependency change."

## 19. ADEM (Digital Experience)

_Autonomous Digital Experience Management telemetry._

169. "Show me application experience scores for Acme Corp's users over the last 3 days."
170. "Give me the internet-path quality metrics for Contoso Ltd's remote-network agents."
171. "Pull Real User Monitoring (RUM) scores for our web apps over the last 7 days."
172. "Check Zoom meeting quality telemetry (QoS) for Customer-A's mobile-user agents over the last day."

## 20. CDL Log Forwarding

_CDL log-forwarding profile management (email, HTTPS, syslog)._

173. "List the syslog log-forwarding profiles configured for Acme Corp."
174. "Show me the HTTPS log-forwarding profiles for Contoso Ltd."
175. "Fetch the details of email log-forwarding profile ID `lf-email-04`."

## 21. Compliance Center

_PAN Compliance Center — framework summaries, scores, controls, benchmark monitoring._

176. "List all compliance frameworks available in the PAN Compliance Center for Acme Corp."
177. "Show me the compliance summaries for released frameworks, SASE product only."
178. "Give me the overall and per-category compliance scores for framework ID `pcf-caf-v4` for Contoso Ltd."
179. "Show me the 30-day and 1-year compliance score trend for that same framework."
180. "Break down per-control pass/fail counts for framework `pcf-caf-v4`, most severe findings first."
181. "Run live benchmark monitoring for Customer-A across all products and show me the severity breakdown."

## 22. Config Orchestration (Site Onboarding)

_RNHP site-onboarding API — remote networks, bandwidth allocations, IKE/IPSec crypto profiles._

182. "List remote network sites via the site-onboarding API for Acme Corp — I want to compare this against the SCM config view."
183. "Show me bandwidth allocations via the v2 site-onboarding API for Contoso Ltd."
184. "Dry-run creating a new remote network site via config-orch for `Bristol-Branch-05`, ticket ref CHG-7734 — show me what would be created."
185. "List the IKE crypto profiles available via the RNHP API for Customer-A."
186. "Read the IKE gateways exposed through the site-onboarding read API — I want to cross-check them against the SCM config API's IKE gateway list."
187. "Dry-run creating a new bandwidth allocation via the v2 site-onboarding API for Acme Corp's `uk-southeast` compute location at 500 Mbps, ticket ref CHG-7735 — don't apply it yet."
188. "Dry-run creating a new IKE crypto profile called `IKE-AES256-SHA256` via the RNHP API for Contoso Ltd, ticket ref CHG-7736."

## 23. CSP Licensing

_Customer Support Portal — Software NGFW flexible (credit-pool) licensing._

189. "List all credit pools on our CSP account for the flexible NGFW licensing program."
190. "Show me the deployment profiles (auth codes) inside credit pool `cp-88213`."
191. "List the firewall serial numbers registered against auth code `AUTH-4521`."

## 24. DNS Security

_Domain reputation lookups and category change requests._

192. "Look up the domain reputation and category for `suspicious-domain.example` on Acme Corp's tenant."
193. "Check the category for `internal-app.contoso.com` before I whitelist it."
194. "Submit a domain category change request to remove `false-positive-site.com` from the malware category, ticket ref INC-8821."

## 25. Email DLP

_Email DLP incident and report access._

195. "List open Email DLP incidents for Acme Corp from the last 50 events."
196. "Get the full detail on Email DLP incident `edlp-33210`."
197. "Pull the Email DLP report with ID `report-99012`."

## 26. Insights

_General-purpose Prisma Access Insights query interface (103 resource paths)._

198. "Query Prisma Access Insights for the current GlobalProtect connected-user count on Acme Corp."
199. "Pull the GP mobile-user list with locations for Contoso Ltd over the last 24 hours."
200. "Query per-SPN bandwidth consumption for Customer-A over the last 48 hours."
201. "Show me agent version distribution across Acme Corp's mobile-user fleet."
202. "Schedule an Insights export of the agent user list for Contoso Ltd, then check the download status."
203. "Once that export is ready, download it."

## 27. Monthly Service Review (MSR)

_Assembles the monthly customer deliverable from live tenant data._

204. "Generate the Monthly Service Review pack for Acme Corp for June 2026, MSSP name 'Silverback Security', output as Word."
205. "Build the MSR for Contoso Ltd for last month, skipping the Insights bandwidth section to keep it fast."
206. "Give me Customer-A's MSR for the previous calendar month and save it to `reports/customer-a-msr.docx`."

## 28. Cross-Tenant Monitoring (MT Monitor)

_MSP-hierarchy aggregate analytics — apps, threats, connectivity, incidents, licenses._

207. "Show me cross-tenant application usage aggregated over our whole MSP hierarchy for the last 7 days."
208. "Give me a threat summary — total, blocked, by severity — across every child tenant."
209. "Show me connectivity status by node type across the estate — how many sites are up vs down right now?"
210. "Pull the MSP tenant hierarchy tree so I can see the parent/child relationship structure."
211. "Show me license setup status and allocated service-connectivity licenses across the MSP hierarchy."

## 29. Prisma Access Browser (Tenant)

_Enrolled users, devices, app catalog, and helpdesk request queue._

212. "Give me a Prisma Access Browser summary for Acme Corp — users by status, devices by OS, posture compliance."
213. "List all PAB-enrolled devices for Contoso Ltd running macOS."
214. "Show me the PAB application catalog for Customer-A — I want to see what's already configured before adding a new app."
215. "List the app groups configured in Prisma Access Browser for Acme Corp."
216. "Show me the open helpdesk queue of user access requests in PAB for Contoso Ltd."

## 30. Planner (Autonomous Agent)

_Conversational goal-to-plan execution, incident triage, estate-wide checks._

217. "Run an autonomous check across all tenants: find which ones have certificates expiring this quarter and summarise per customer."
218. "Check the status of the Planner run I kicked off a minute ago."
219. "Fetch the final report from that Planner run once it's done."
220. "Trigger incident-response triage for this alert: an IPSec tunnel just went down on branch-12 for Acme Corp — here's the raw alert JSON: {\"message\": \"IPSec tunnel down on branch-12\"}."
221. "Run the estate check across every configured tenant."
222. "Run the estate check but limit it to just `acme-corp` and `contoso-ltd`, concurrency 2."
223. "Ask the Planner to investigate why Contoso Ltd's mobile users can't connect and, if it finds a fix that needs a commit, don't apply it — just report back what it would do."
224. "Run a Planner goal: 'audit every tenant for NCSC CAF gaps and rank them by how many critical findings each has' — read-only, no write tools approved."

## 31. Service Status

_Public PAN cloud maintenance windows and incident status._

225. "Are there any upcoming PAN cloud maintenance windows relevant to Acme Corp's region in the next 14 days?"
226. "Show me maintenance windows across every configured tenant, grouped per tenant, for the next 30 days."
227. "Check current PAN cloud status, including Prisma Cloud and Cortex, not just SASE products."

## 32. SSR (Simple Service Requests)

_Restricted, idempotent customer-change CRUD — URL allow/block lists, threat exceptions, decrypt exclusions._

228. "Add `partner-portal.example.com` to Acme Corp's SSR-managed URL allow list, ticket ref INC-8842 — dry run first."
229. "That looks right, apply it for real."
230. "Remove `known-bad-site.net` from Contoso Ltd's SSR URL block list, ticket ref INC-9011."
231. "Add threat ID `91234` to the threat-exception list for Customer-A's anti-spyware profile, ticket ref CHG-2210, and show me the before/after diff before applying."
232. "Exclude the `financial-services` URL category from SSL decryption on Customer-A's no-decrypt rule, ticket ref CHG-2211 — dry run first, please."

## 33. Cross-Tool Workflows

_Multi-step requests that chain several tools together — the kind of thing an MSSP engineer actually asks for._

233. "Give me a full health check across every MSSP tenant: NOC dashboard, incident summary, and licence forecast, all in one go."
234. "Before I hand this AS-BUILT to the customer, verify it against live config, and if anything drifted, tell me exactly what to regenerate."
235. "Run a BPA assessment for Acme Corp, then use the AI compliance advisor to turn the worst findings into a remediation playbook I can send them."
236. "Check Contoso Ltd's certificate expiry, licence forecast, and SD-WAN software status together — I want one combined risk picture before their renewal call."
237. "Capture a drift baseline for every tenant tonight, then email me a summary tomorrow of what changed — for now just run the baseline and the check back-to-back so I can see the diff mechanics work."
238. "Onboard Customer-F: check the folder doesn't already exist, then apply the NCSC baseline as a dry run — don't commit anything yet."
239. "Pull Acme Corp's SD-WAN topology, generate the Mermaid diagram, and also generate the HTML site map — I want both for the AS-BUILT appendix."
240. "Investigate a reported outage at Contoso Ltd's Manchester branch: check SD-WAN events, link health, and WAN IP status for that site, then tell me what's most likely wrong."
241. "Run the full compliance trio for Meridian Health — NCSC CAF, NHS DSPT standards 7-10, and ISO 27001 — and tell me which framework they're weakest against."
242. "Before this quarter's QBR with Acme Corp, pull their renewal brief, MSR for last month, and NCSC compliance report into one package."
243. "Check whether Customer-A's remote networks in SCM config match what the site-onboarding API shows — flag any discrepancy."
244. "Compare BPA findings between Acme Corp and Contoso Ltd and tell me which tenant is in worse shape and why."
245. "Run a decrypt policy audit and an NCSC gap analysis together for Customer-A, then tell me if the SSL decryption gaps are also NCSC control failures."
246. "For every tenant, run scm_bpa_assess and flag anyone who's fallen below 100% compliance since onboarding."
247. "Pull SD-WAN events and audit logs for the last 24 hours across Acme Corp and correlate — did a config change cause the tunnel flap?"
248. "Check licence forecast and mobile user stats together for Contoso Ltd — are we about to run out of GlobalProtect seats before the licence renews?"
249. "Do a pre-change risk check for Acme Corp: commit preview on the pending changes, plus a fresh drift check, before I let the engineer commit."
250. "Build a one-page exec summary combining the NOC dashboard, incident summary, and any tenants with critical BPA findings."
251. "Cross-check PAB posture compliance against SSPM findings for Customer-A — are the same risky devices showing up in both?"
252. "Kick off AS-BUILT generation for every tenant that doesn't have one on file yet, one at a time, and let me know as each finishes."

## 34. Rule Optimization & Cleanup

_Zero-hit rule detection, least-privilege App-ID recommendations, and CIDR-aware rule-shadow auditing._

253. "Show me every zero-hit security and NAT rule for Acme Corp's Prisma Access folder, worst offenders first — I want a cleanup list before the next change window."
254. "Run a full rule-shadow audit across Contoso Ltd's entire rulebase — I don't have a pending commit, I just want to know if any existing rule is silently dead because an earlier rule already covers it."
255. "Before I let the engineer commit Customer-A's pending changes, run scm_commit_preview for the blast radius, then scm_zerohit_rules to see if any of the rules being touched were already zero-hit — I want the full picture in one pass."
256. "Which of Acme Corp's security rules does the Policy Optimizer have App-ID recommendations for? Rank them by cleanup value, then pull the suggested replacement rules for the top one so I can see exactly what it wants to narrow `application: any` down to."
257. "For Contoso Ltd, list the optimizer's analysed rules that pushed more than a gigabyte of traffic, and for each one show me the recommended least-privilege replacements — I want to know how much of that traffic is unknown-tcp/unknown-udp before I commit to narrowing anything."

---

*Generated against the 163-tool surface documented in [`TOOL_REFERENCE.md`](TOOL_REFERENCE.md). If a prompt references a feature your tenant isn't licensed for (AIRS, ZTNA Connector, Compliance Center, ADNSR, NGFW Operations, Posture Management, SPI, PAB), the tool reports that clearly instead of failing silently.*
