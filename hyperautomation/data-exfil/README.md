# NovaMind Data-Exfil Response Playbook

Highest-severity scenario response for **OneFlare scenario 06 — data exfiltration via
`api.novamind.ai`** (bulk data pull / sensitive-endpoint enumeration). Alert-triggered
SentinelOne Hyperautomation workflow, authored against the workflow-schema and
building-blocks-catalog.

- **File:** `data-exfil.workflow.json`
- **Triggers on:** deployed scheduled STAR rule **CF-API-Exfil** (`2519093015733817725`) —
  `class_uid=4002` HTTP Requests, groups by `src_ip`, fires when
  `sensitive_hits >= 10 OR max_bytes >= 1 MiB`.
- **Author-only.** Not imported/published to a live tenant — no console token or `ha_*` MCP
  tool was reachable in this session (see Deploy status). Deploy steps below are the intended
  procedure.

---

## Trigger

Singularity Response trigger, one filter group (AND): alert `name` **contains** `CF-API-Exfil`
AND `severity` **in** `["HIGH","CRITICAL"]`, `event_type: alert`, subtype `CREATE`.
`run_automatically: false` → surfaces as an analyst-approved action in the Singularity Response
console. Flip to `true` for fully automated response after testing.

The `name`-contains value is the coupling point to the detection rule. Confirm the deployed
rule's alert name still contains `CF-API-Exfil` before enabling.

---

## Block-by-block logic

Shape: **trigger → enrichment (S1 search + IP reputation) → containment gate → Cloudflare block
+ S1 note/IOC/verdict → SOC notify → reputation escalation gate → account-wide block + credential
flag → email.**

| # (export_id) | Action | Tag | Purpose |
|---|---|---|---|
| 18 | Singularity Response Trigger | core | Fire on CF-API-Exfil HIGH/CRITICAL alert. |
| 17 | Attacker Source IP (variable) | core | `client_ip` = `DEFAULT(indicators[0].value, "no-ip")`. |
| 16 | Search Related API Activity | **integration (S1 SDL Bearer)** | Enrichment (a): LRQ PowerQuery — the same `src_ip`'s other API calls over 24h, the **authenticated caller** (`actor.user.name`), user-agents/tokens, distinct paths, total bytes. This is where the compromised user/token is resolved (see gap #1). |
| 15 | VirusTotal IP Report | core HTTP | Enrichment (b1): VT reputation of `src_ip`. |
| 14 | AbuseIPDB Check | core HTTP | Enrichment (b2): AbuseIPDB confidence-of-abuse of `src_ip`. |
| 13 | VT Malicious Count (variable) | core | `vt_malicious` = VT `last_analysis_stats.malicious` (default 0). |
| 12 | Abuse Confidence Score (variable) | core | `abuse_score` = AbuseIPDB `abuseConfidenceScore` (default 0). |
| 11 | IP Resolved (condition) | core | Gate containment on a real IP (`client_ip != no-ip`). TRUE → containment. |
| 10 | Block Exfil Routes For IP | integration (Cloudflare) | Zone firewall rule blocking `/export`, `/download`, `/api/v1/customers/export` for `src_ip`. |
| 9 | Block Source IP At Zone | integration (Cloudflare) | Zone IP access rule (block) for `src_ip`. |
| 8 | Add S1 Alert Note | integration (S1) | UAM `addAlertNote`: IP, VT/AbuseIPDB verdicts, CF actions, pointer to the LRQ for the caller. |
| 7 | Add S1 IOC | integration (S1) | IPV4 IOC, `exfiltration` category, risk 95, 7-day TTL. |
| 6 | Raise Analyst Verdict | integration (S1) | `alertTriggerActions` → verdict `suspicious` (pending TI confirmation). |
| 5 | Notify SOC Slack | integration (Slack) | Containment summary to `#novamind-soc` (DLP tap). |
| 4 | Escalate Confirmed Malicious (condition) | core | Second gate — `vt_malicious > 0` **OR** `abuse_score >= 50`. |
| 3 | Account Global Edge Block | integration (Cloudflare) | TRUE branch: account-level IP access rule — blocks across shop/portal/api zones. |
| 2 | Flag Compromised API Credential | core HTTP | TRUE branch: NovaMind Worker `/api/incident` — revoke/flag the API token + raise `/status` banner. |
| 0 | Send Email CRITICAL Escalation | core | TRUE branch terminal: SOC + DLP, TI-confirmed. |
| 1 | Send Email Contained | core | FALSE branch terminal: SOC, contained/monitoring (no account-wide block). |

### Evidence discipline (two gates)
- **Gate 1 (IP resolved, node 11)** guards *all* response. The detection's own volume floors
  (`sensitive_hits >= 10 OR max_bytes >= 1 MiB`) are the exfil evidence, so zone-scoped block +
  note + IOC run on a resolved IP without waiting for TI.
- **Gate 2 (reputation, node 4)** guards the *destructive, blast-radius* actions — the
  account-wide edge block and credential revoke run **only** on an independent threat-intel
  verdict (VT malicious > 0 OR AbuseIPDB ≥ 50). No global block or credential kill on a
  detection-engine alert alone. Max classification without TI is *SUSPICIOUS* — mirrored in the
  node-6 verdict (`suspicious`) and the two email severities.

### Why no true parallel fan-out
The catalog has no join primitive and `is_parallel` loops are rare/discouraged. The two
enrichment calls (S1 search + reputation) are *logically parallel* but wired sequentially
(nodes 16 → 15 → 14), all `continue_on_fail: true` so a slow/failed enrichment never blocks
containment. Documented as an intentional modeling choice, not an omission.

---

## Required pre-configured console connections (Hyperautomation → Integrations)

Integration-backed actions (`"tag": "integration"`) will NOT run until these connections exist.
They cannot be created via API — configure them in the console first, then bind each action's
connection after import.

| Connection | Used by | Notes |
|---|---|---|
| **SentinelOne SDL** (Bearer) | Search Related API Activity (node 16) | LRQ/PowerQuery needs the **SDL Bearer** connection, **not** the ApiToken one. Endpoint `/sdl/v2/api/queries`. |
| **SentinelOne** (ApiToken) | Add S1 Alert Note, Add S1 IOC, Raise Analyst Verdict (8/7/6) | Standard S1 console connection. |
| **Cloudflare** (API token) | Block Exfil Routes, Block Source IP At Zone, Account Global Edge Block (10/9/3) | Token needs Zone Firewall + Zone IP Access + **Account** IP Access Rules edit. `{{Connection.zone_id}}` / `{{Connection.account_id}}` are placeholders — confirm your connection exposes them or hardcode the api.novamind.ai zone ID and the account ID post-import. Co-designed with `cloudflare-specialist`. |
| **Slack** | Notify SOC Slack (5) | Bot token with `chat:write` to `#novamind-soc`. |
| **Send Email** (platform mailer) | Send Email × 2 (0/1) | Core action, platform SMTP; confirm a verified sender for `soc@`/`dlp@novamind.ai`. |

**Non-integration core HTTP secrets to set post-import (placeholders in JSON, no real keys committed):**
- **VirusTotal IP Report** (15): `x-apikey` header → `<set-VIRUSTOTAL_API_KEY-after-import>`.
- **AbuseIPDB Check** (14): `Key` header → `<set-ABUSEIPDB_API_KEY-after-import>`.
- **Flag Compromised API Credential** (2): `X-Incident-Key` header → `<set-INCIDENT_KEY-after-import>`
  (NovaMind Worker incident key).

---

## MITRE ATT&CK

| Technique | Tactic | Where |
|---|---|---|
| **T1530** Data from Cloud Storage | Collection | bulk `/customers/export` pull |
| **T1119** Automated Collection | Collection | sensitive-endpoint enumeration (`sensitive_hits >= 10`) |
| **T1567(.002)** Exfiltration Over Web Service / to Cloud Storage | Exfiltration | megabyte responses over the API edge |

Response tactics: contain (Cloudflare block/rate-limit), enrich (VT/AbuseIPDB/S1 LRQ),
credential-access response (flag/revoke token), and notify (SOC/DLP).

---

## Catalog gaps / honest caveats (evidence discipline)

1. **No `user` column on the alert.** The deployed CF-API-Exfil rule groups by `src_ip` only
   and projects `detection_time, src_ip, host, api_requests, sensitive_hits, distinct_paths,
   max_bytes, largest_uri, country, first_seen` — **no authenticated-user column** (entityMappings
   are a `_pending_feature` in the rule). The task lists `user` as an alert entity, but it is not
   emitted by the rule. The workflow therefore **resolves the compromised caller by search**
   (node 16 LRQ on `actor.user.name` for that `src_ip`) rather than reading it off the alert. The
   credential-flag action (node 2) references that LRQ, not a fabricated alert field.
2. **No native Cloudflare *rate-limit* or *token-revoke* action in the HA catalog.** The catalog
   has no first-class Cloudflare block/rate-limit action type at all — Cloudflare containment is
   modeled as integration-backed **HTTP requests** to the Cloudflare v4 API (firewall rules + IP
   access rules), consistent with the repo's CTF house style. There is likewise no S1/Cloudflare
   "revoke API token" action, so credential handling is delegated to the NovaMind Worker
   `/api/incident` endpoint. Both are documented, not invented.
3. **`public_action_id` values are descriptive placeholders** (`cloudflare-create-firewall-rules`,
   `cloudflare-create-ip-access-rule`, `cloudflare-create-account-ip-access-rule`,
   `sentinelone-create-ioc`, `sentinelone-add-alert-note`, `sentinelone-alert-trigger-actions`,
   `sentinelone-sdl-powerquery`, `slack-post-message`). The real UUIDs come from each integration's
   action catalog on the target tenant; the console resolves/relinks them when you bind the
   connection after import. Re-bind in the UI if an action doesn't auto-resolve.
4. **Alert field paths (`indicators[0].value`, `.data.id`, `.data.scopeId`) follow the repo's
   CTF house style but are unverified against a live CF-API-Exfil alert.** For a scheduled STAR
   rule the projected columns' exact position in the alert payload should be confirmed on the
   first real alert; the `DEFAULT(..., "no-ip")` fallback + node-11 gate keep the flow safe if
   `indicators[0].value` is empty.
5. **Analyst-verdict raise (node 6)** uses the `alertTriggerActions` envelope with action id
   `S1/alert/setAnalystVerdict`. Only `S1/alert/addNote` is corpus-confirmed; the setVerdict id
   should be confirmed on the target tenant (action is `continue_on_fail: true` so it never blocks).
6. **Asset binding.** Cloudflare logs bind to "Unknown Device" unless the asset-enrichment
   solution runs first (see `.claude/rules/s1-development.md`). This workflow's actions key off
   `src_ip` + alert id and do not depend on EDR asset binding, so they fire regardless.

---

## Validation

Validated against the skill's `references/validation-rules.md` and `workflow-schema.md`:

- Top-level keys exactly `name` / `description` / `actions`; every action has
  `action` / `export_id` / `connected_to` / `parent_action`. ✅
- 19 unique `export_id`s (0–18); every `connected_to.target` resolves to a real node;
  exactly one trigger (`parent_action: null`); two terminals (0, 1) with `connected_to: []`. ✅
- `type` == `data.action_type` on every action; every `tag` is `core_action` or `integration`;
  all `state: "active"`. ✅
- Both conditions use `condition_type: "multi"` (`condition: null`, non-empty `conditions`);
  branches use `custom_handle` `"true"`/`"false"`; node 11 has only a TRUE edge (valid). ✅
- Trigger `filter_groups` non-empty; each group has `event_type` / `event_subtypes` /
  `condition` / `is_disabled` / `run_automatically`; `in`-operator `compared_value` is a
  JSON-encoded array string (`"[\"HIGH\",\"CRITICAL\"]"`). ✅
- Every integration action is import-ready: `connection_id: null`, `connection_name: ""`,
  `integration_id: null`, `public_action_id` kept. ✅
- No loops → no `parent_action` / `inner` / `break_loop` concerns. Every `{{...}}` reference
  resolves to a real action slug, `local_var`, or `Function.*`. All functions used
  (`DEFAULT`, `DATETIME_NOW`, `DELTA_NOW`) exist in `functions-reference.md` — the invalid
  `STRING_CONCAT` was removed (note text now inlines `{{...}}` references directly). ✅
- One variable per Variable action for any chained reference; no cross-variable references in a
  single action (anti-pattern E1 avoided). ✅

`python3 -m json.tool` parses clean; a structural checker (unique ids, valid targets, single
trigger, condition handles, integration import-readiness) passed with no findings.

---

## Deploy status: PENDING (import not reachable)

No `S1_CONSOLE_URL` / API token was set and no `ha_*` MCP tool was bound in this session, and
the sandbox blocks outbound to `*.sentinelone.net`. The workflow is delivered **validated but
not imported**. Do not treat it as deployed.

### Deploy loop (with a live tenant + personal **Console User** token)

```bash
# 0. SITE_ID = 2433185103040607397 (the CF-API-Exfil rule's site)
#    Validate JSON shape first: python3 -m json.tool data-exfil.workflow.json >/dev/null

# 1. Import — lands as a PRIVATE DRAFT owned by the token user. Capture id + version_id.
curl -s -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/public/workflow-import-export/import?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" -H "Content-Type: application/json" \
  -d "{\"data\": $(cat data-exfil.workflow.json)}"

# 2. Publish in the SAME step so humans can see it (invisible otherwise)
curl -s -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/v1/workflows/$WORKFLOW_ID/publish?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" -d '{}'

# 3. Bind connections in the console UI: SentinelOne SDL (Bearer), SentinelOne (ApiToken),
#    Cloudflare, Slack, Send Email. Set the 3 core-HTTP secrets (VT, AbuseIPDB, INCIDENT_KEY).

# 4. Activate
curl -s -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/public/workflows/$WORKFLOW_ID/$VERSION_ID/activation?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" -H "Content-Type: application/json" -d '{"data":{}}'

# 5. Test: run attack-scripts data-exfil sim (or wait for a real CF-API-Exfil alert), then
#    confirm executions:
#    GET /hyper-automate/api/public/workflow-execution?workflow_id=$WORKFLOW_ID
```

Equivalent MCP path: `ha_import_workflow` → publish → bind connections → activate, using the
`ha_*` `s1-secops-mcp` tools.

### Operational rules (before deploying)
1. **Import lands as a Private Draft owned by the token user** → **publish in the same step**.
2. **Use a personal Console User token**, not a Service User token (service-token imports are
   invisible in the UI — the HA API has no ownership-transfer endpoint).
3. **No in-place update.** Re-import creates a *new* workflow; delete superseded ones with
   `DELETE /hyper-automate/api/v1/workflows/{id}?accountIds=…`.
4. **SDL LRQ actions need the SentinelOne SDL (Bearer) connection**, not ApiToken (node 16).
5. **Gate destructive actions on a threat-intel verdict** — kept at node 4 for the account-wide
   block + credential revoke. Preserve this if you extend the workflow.
6. `run_automatically: false` — keep it until tested, then flip for full automation.
```
