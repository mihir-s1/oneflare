# DNS Tunneling / C2 Beaconing — Hyperautomation Response

Response playbook for OneFlare **scenario 08 (DNS tunneling / C2 beaconing)** — Cloudflare
Gateway DNS. Fires on the SentinelOne scheduled detection **CF-Gateway-DNSTunnel**
(rule id `2519102258169184569`, OCSF DNS Activity `class_uid 4003`). Authored against the
`sentinelone-hyperautomation` skill (workflow-schema + building-blocks-catalog + validation-rules)
and the repo house style in `hyperautomation/ctf/`.

**Author-only. Deploy pending.** This environment has **no SentinelOne credentials and no
`ha_*` (`s1-secops-mcp`) tools wired up** — the sandbox also blocks outbound to
`*.sentinelone.net`. The workflow JSON was validated statically (see Validation below) but has
**not** been imported/published to a live tenant. The deploy steps below are the procedure for
whoever holds a personal Console User token.

| File | Purpose |
|------|---------|
| `dns-tunneling.workflow.json` | The validated, importable Hyperautomation workflow (26 actions). |
| `README.md` | This file — trigger, block-by-block logic, connections/secrets, MITRE, catalog gaps. |

---

## Trigger

**Singularity Response alert**, one filter group (AND):

- `severity` **in** `["HIGH","CRITICAL"]`
- `name` **contains** `CF-Gateway-DNSTunnel`

`run_automatically: false` — the workflow surfaces as an analyst-approved action in the
Singularity Response console (flip to `true` for fully-automated response after testing).

The alert's coupling point is the detection rule's projected columns
(`detection_time, src_ip, host, zone, reason, total_queries, uniq_labels, long_labels,
txt_long, hi_entropy, max_label_len, evidence, device_uid, first_seen`). The workflow keys off
`zone` (the C2 base-domain — the block target), `src_ip`, `device_uid`, and the beacon-context
metrics. See **Assumptions** for the field-path caveat.

---

## Block-by-block logic

Shape: **trigger → extract → gate targets → parallel enrichment (S1 search + VT domain rep) →
two-stage decision → containment OR monitor → notify.**

| # | Action | Type | Purpose |
|---|--------|------|---------|
| 100 | Singularity Response Trigger | core | Fire on CF-Gateway-DNSTunnel HIGH/CRITICAL. |
| 99 | Source IP | variable | `src_ip` (rule column, = `src_endpoint.ip`); DEFAULT chain → `no-ip`. |
| 98 | C2 Base Domain | variable | `base_domain` = rule column `zone` (registered base-domain); the Gateway block target. |
| 97 | Query Evidence | variable | `evidence` = longest observed query name (strongest tunnel/exfil sample). |
| 96 | Beacon Context | variable | `reason, total_queries, uniq_labels, hi_entropy, txt_long, device_uid` — all independent trigger refs (one multi-var action is safe). |
| 95 | Targets Present | condition | Gate: proceed only when base-domain AND src_ip resolved (no fabricated block targets). |
| 94 | Related DNS PowerQuery | variable | Build the PQ body for the related-beacon search (own action — references `local_var.src_ip`). |
| 93 | Search Related DNS Beaconing | integration (S1 SDL Bearer) | **Enrichment (a):** SDL PowerQuery — same src_ip's DNS beaconing over 6h → sustained tunnel vs blip. |
| 92 | Related Beacon Count | variable | Extract `beacons` from the search; DEFAULT `0`. |
| 91 | Domain Reputation VirusTotal | core HTTP | **Enrichment (b):** VirusTotal DOMAIN report on the base-domain. Domain reputation is the load-bearing DNS-C2 verdict. |
| 90 | Domain Malicious | condition | **Primary gate:** VT `last_analysis_stats.malicious > 0`. TRUE → contain; FALSE → 79. |
| 79 | Sustained Beaconing | condition | **Secondary gate:** `related_beacon_count >= 20`. TRUE → contain (converges on 80); FALSE → monitor (57). |
| 80 | Block C2 Domain at Gateway | integration (Cloudflare) | **Native DNS-tunnel containment:** Cloudflare Gateway DNS policy blocking `dns.domains[*] == base_domain`. |
| 78 | Block Source IP Zone Rule | integration (Cloudflare) | Defence-in-depth: zone IP Access rule blocking the source IP. |
| 77 | Add S1 IOCs | integration (S1) | Create DNS (base-domain) + IPV4 (source) IOCs, `validUntil` 7d forward. |
| 76 | Device Bound to Asset | condition | Isolation gate: `device_uid != no-uid` (asset-binding caveat below). |
| 75 | Isolate Endpoint | integration (S1) | **Escalation (asset-bound only):** S1 EDR network-isolate the beaconing host. |
| 70 | Confirmed Note Body | variable | Assemble the contained-branch note (domain, volume, entropy, beacon persistence, reputation). |
| 74 | Add Confirmed Alert Note | integration (S1) | UAM GraphQL `addAlertNote` (modern flavor B6), HTML-encoded. |
| 73 | Raise Alert Verdict | integration (S1) | Raise analyst verdict to **SUSPICIOUS** (never auto-TRUE_POSITIVE — evidence discipline). |
| 72 | Notify SOC Contained | integration (Slack) | Containment summary to `#oneflare-soc`. |
| 71 | Email SOC Contained | core send_email | HTML containment receipt. |
| 57 | Monitor Note Body | variable | Assemble the monitor-only note (no block). |
| 56 | Add Monitor Alert Note | integration (S1) | UAM GraphQL `addAlertNote` — monitor path. |
| 55 | Notify SOC Monitor | integration (Slack) | Monitor summary to `#oneflare-soc`. |
| 54 | Email SOC Monitor | core send_email | HTML monitor receipt. |

### Why this shape (DNS-C2 specifics)

- **Block the base-domain, not the subdomain.** DGA / fast-flux rotates the leftmost labels;
  the registered `zone` is the durable indicator. The detection groups per zone for exactly this
  reason, and the Gateway DNS policy blocks the whole zone.
- **Domain reputation, not just IP.** For DNS C2 the domain is the primary IOC — VT domain report
  gates the destructive block; the source-IP zone block is defence-in-depth.
- **Two-stage gate (reputation OR persistence).** A confirmed-malicious domain contains
  immediately; an unrated-but-sustained tunnel (≥20 related beacons in 6h) also contains. Neither
  → monitor-only, no block. This keeps destructive actions gated on evidence.
- **Isolation is asset-bound.** See the caveat below — Cloudflare DNS alerts bind to
  "Unknown Device" until asset-enrichment runs, so isolate is gated and `continue_on_fail`.

---

## Required pre-configured console connections (Hyperautomation → Integrations)

Integration-backed actions (`"tag": "integration"`) will **not** run until these connections
exist. They cannot be created via API — configure them in the console first, then bind each
action's connection after import.

| Connection | Auth | Used by | Notes |
|------------|------|---------|-------|
| **SentinelOne SDL** | **Bearer** | Search Related DNS Beaconing (93) | An HTTP action running an SDL LRQ/PowerQuery needs the **Bearer** SDL connection, **not** the ApiToken S1 connection. |
| **SentinelOne** | ApiToken | Add S1 IOCs (77), Isolate Endpoint (75), Add/Monitor Note (74/56), Raise Verdict (73) | Standard console API token connection. |
| **Cloudflare** | API token | Block C2 Domain at Gateway (80), Block Source IP Zone Rule (78) | Token needs **Zero Trust → Gateway (edit)** for the DNS policy *and* **Zone Firewall Access Rules (edit)** for the IP rule. Connection must expose `{{Connection.account_id}}` and `{{Connection.zone_id}}` (or hardcode them post-import). |
| **Slack** | Bot token | Notify SOC (72/55) | `chat:write` to `#oneflare-soc`. |
| **Send Email** | platform mailer | Email SOC (71/54) | Core action — confirm a verified sender exists. |

**Non-integration core HTTP secret to set post-import:**
- **Domain Reputation VirusTotal** (91): set the `x-apikey` header (placeholder
  `<SET_VIRUSTOTAL_API_KEY>`) to a VirusTotal API key. **Do not commit the real key.**

---

## Catalog gaps (evidence discipline — no fictional building blocks)

The HA building-blocks catalog contains a generic `http_request` (core + integration-backed) but
**no native Cloudflare/S1-specific action types**. The following are therefore modeled as
integration-backed HTTP requests with **descriptive `public_action_id` placeholders** (matching
the repo house style in `hyperautomation/ctf/`); the real UUIDs come from each integration's
action catalog on the target tenant, and the console relinks them when you bind the connection.

| Action in JSON | `public_action_id` (placeholder) | Modeled how | Confirm on tenant |
|---|---|---|---|
| Block C2 Domain at Gateway (80) | `cloudflare-create-gateway-rule` | **No native HA Gateway-DNS block action exists in the catalog.** Modeled via the Cloudflare **Zero Trust Gateway rules API** (`POST /accounts/{account_id}/gateway/rules`, `action:"block"`, `filters:["dns"]`, `traffic: any(dns.domains[*] == "<zone>")`). | Confirm the Cloudflare integration exposes a Gateway-rule action or allow a raw HTTP call; confirm `account_id`. |
| Block Source IP Zone Rule (78) | `cloudflare-create-ip-access-rule` | Zone IP Access rules API (same as CTF Box1/2). | Confirm `zone_id`. |
| Add S1 IOCs (77) | `sentinelone-create-ioc` | `POST /threat-intelligence/iocs` (catalog B9). `DNS` IOC type for the domain. | Confirm `DNS` IOC type is accepted (vs `DOMAIN`). |
| Isolate Endpoint (75) | `sentinelone-disconnect-agent` | `POST /agents/actions/disconnect`. | Standard. |
| Add/Monitor Note (74/56) | `sentinelone-add-alert-note` | UAM GraphQL `addAlertNote` (catalog **B6**, modern flavor). | Catalog-backed. |
| Raise Alert Verdict (73) | `sentinelone-set-alert-verdict` | **Not in the catalog** — modeled from the same unifiedalerts GraphQL endpoint as B6, mutation `setAlertsAnalystVerdict(analystVerdict: SUSPICIOUS, …)`. | **Confirm the mutation name + enum on the tenant** (B6 only documents `addAlertNote`). If it doesn't resolve, drop action 73 — the confidence recommendation is already in the note body. |
| Search Related DNS Beaconing (93) | `sentinelone-sdl-powerquery` | Catalog **B8** DV PowerQuery shape (`POST /api/powerQuery`, single call). | The modern LRQ (`/sdl/v2/api/queries`) is a 3-call async launch/poll/cancel that a single HTTP action can't poll; the B8 synchronous endpoint is used for simplicity. If the tenant only offers async LRQ, replace with a launch → Delay → poll sub-graph and bind the SDL Bearer connection. |

Third-party reputation: the catalog's only domain/IP reputation building block is **VirusTotal**
(B10). **URLhaus / OTX / AbuseIPDB are not in the catalog** — they can be added as extra core-HTTP
enrichments (URLhaus `POST /v1/host/`, OTX `/api/v1/indicators/domain/{d}/general`) but were left
out to stay minimal-yet-sufficient and catalog-honest. VT domain report is the gate.

---

## MITRE ATT&CK

- **T1071.004** — Application Layer Protocol: DNS (C2 over DNS / beaconing).
- **T1048** — Exfiltration Over Alternative Protocol (data-in-DNS via long TXT labels).
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms (DGA).

Response tactic: **Command and Control** containment (Gateway DNS block) + **Impact** mitigation
(source-IP block, optional endpoint isolation).

---

## Validation

Validated statically against `references/validation-rules.md` (skill validator checklist):

- Top-level keys exactly `name`/`description`/`actions`; every action has
  `action`/`export_id`/`connected_to`/`parent_action`. **PASS**
- 26 unique `export_id`s; every `connected_to.target` references a valid id;
  all nodes reachable from the trigger. **PASS**
- Exactly one trigger (`singularity_response_trigger`), `parent_action: null`, non-empty
  `filter_groups` with `event_type`/`event_subtypes`/`condition`/`is_disabled`/`run_automatically`.
  **PASS**
- `type` == `data.action_type` on every action; `state: "active"` everywhere;
  `snippet_*` null. **PASS**
- All conditions `condition_type:"multi"` with a non-empty flat `conditions` array and
  `condition: null`; branches use `custom_handle` `"true"`/`"false"`; single-branch conditions
  (95 true-only) valid. **PASS**
- Convergence: both gate TRUE edges (90-true, 79-true) target the same block entry (80). **PASS**
- Integration actions import-ready: `connection_id:null`, `connection_name:""`,
  `integration_id:null`, `public_action_id` kept. **PASS**
- No loops/break_loop used (no loop rules to trip). Variable rule: no action defines a variable
  whose value references a `local_var` set in the **same** action (the related-PQ var is its own
  dedicated action referencing `src_ip` from an earlier action). **PASS**
- `send_email` uses `to` array + `mime_type` + `body`, no attachments. **PASS**
- Functions use `{{Function.NAME(...)}}` (DEFAULT / DATETIME_NOW / DELTA_NOW / HTML_ENCODE). **PASS**

`python3 -m json.tool` parses the file cleanly.

---

## Deploy (pending — run on a live tenant with a personal Console User token)

> Import lands as a **Private Draft owned by the token user**. **Publish in the same step** or
> humans can't see it. Use a **personal Console User token**, not a Service User token. No
> in-place update — re-import creates a new workflow.

```bash
SITE_ID=2433185103040607397   # OneFlare CTF site (matches the detection rule's siteIds)

# 1. Import (Private Draft) — capture top-level id + version_id from the response
curl -s -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/public/workflow-import-export/import?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" -H "Content-Type: application/json" \
  -d "{\"data\": $(cat hyperautomation/dns-tunneling/dns-tunneling.workflow.json)}"
# -> capture response.id (WORKFLOW_ID) and response.version_id (VERSION_ID)

# 2. Publish in the SAME step so the team can see it
curl -s -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/v1/workflows/$WORKFLOW_ID/publish?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" -d '{}'

# 3. Bind connections in the console UI: SentinelOne SDL (Bearer), SentinelOne (ApiToken),
#    Cloudflare (Gateway + Zone Firewall), Slack. Set the VirusTotal x-apikey on action 91.

# 4. Activate
curl -s -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/public/workflows/$WORKFLOW_ID/$VERSION_ID/activation?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" -H "Content-Type: application/json" -d '{"data":{}}'

# 5. Test-run: fire the attack (attack-scripts/scenarios/05_dns_tunnel.py with CF_GATEWAY_DOH_URL
#    set), wait one detection run-interval for a CF-Gateway-DNSTunnel alert, approve it in the
#    Singularity Response console, then confirm executions:
curl -s "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/public/workflow-execution?workflow_id=$WORKFLOW_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN"
```

Equivalent MCP path: `ha_import_workflow` → publish → bind connections → activate, using the
`ha_*` `s1-secops-mcp` tools.

---

## Assumptions that need a live tenant to finalize

- **Alert field paths.** The rule is a **scheduled PowerQuery** detection; exactly how its
  projected columns surface under `singularity-response-trigger.data.*` is the coupling point and
  is **not verifiable in this environment**. The extraction variables use `Function.DEFAULT`
  chains to sentinels (`no-ip`, `no-domain`, `no-uid`, `0`) so the workflow degrades safely, but
  **confirm the real paths post-import** using the console's expression evaluator
  (`POST /workflow-action-expressions/{id}/evaluate-expression`) against a live alert, and adjust
  `data.src_ip` / `data.zone` / `data.evidence` / `data.device_uid` etc. if they differ.
- **Asset binding (isolation).** Cloudflare Gateway DNS events do not natively carry the S1 agent
  id, so alerts bind to **"Unknown Device"** until the asset-enrichment solution populates
  `device.uid` (see `.claude/rules/s1-development.md` + `docs/solutions/asset-enrichment.md`). The
  Isolate Endpoint action (75) is gated on `device_uid != no-uid` and is `continue_on_fail`, so it
  no-ops when unbound while the Gateway block + IOCs + note still fire. Coordinate with
  `s1-platform-engineer` to enable asset enrichment before relying on isolation.
- **Related-beacon threshold.** The sustained gate uses `related_beacon_count >= 20` over 6h — tune
  to the tenant's baseline (the detection itself fires on 15/15 windows).
- **Verdict mutation** (action 73) and **Gateway-rule / IOC `public_action_id`s** — confirm/rebind
  on the tenant (see Catalog gaps).
- **Scope.** Import scoped to `siteIds=2433185103040607397` to match the detection rule; adjust for
  the target tenant.

---

## Coordinate

Consumes the confirmed **CF-Gateway-DNSTunnel** detection from `s1-detection-engineer`
(`detections/dns-tunneling/`). Cloudflare Gateway DNS-policy + zone-rule actions are co-designed
with `cloudflare-specialist`. Asset-enrichment (for isolation) is owned by `s1-platform-engineer`.
