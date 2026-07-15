# OneFlare — Web-Attack (WAF) Hyperautomation Response

Response playbook for the three **Cloudflare WAF ML web-application detections** on the
`soledrop.co` zone (`shop.soledrop.co` / `*.lab.soledrop.co`):

| Scenario | Deployed rule id | Rule name (alert `name`) | MITRE |
|---|---|---|---|
| SQL injection | `2519092985434164473` | `CF-WAF-SQLi — SQL Injection against shop.novamind.ai (WAF ML score)` | T1190 |
| Cross-site scripting | `2519092991281024296` | `CF-WAF-XSS — Cross-Site Scripting against shop.novamind.ai (WAF ML score)` | T1059.007, T1190 |
| Path traversal / LFI | `2519092998092573998` | `CF-WAF-Traversal — Path Traversal / LFI against shop.novamind.ai` | T1190, T1083 |

**Author-only.** Nothing here has been imported or published to a live tenant — no console
credentials were present in this session and the sandbox blocks outbound to `*.sentinelone.net`.
The deploy commands below are the intended procedure for whoever holds a **Console User** token.

## Files
| File | Purpose |
|------|---------|
| `web-attacks.workflow.json` | The validated, importable workflow JSON (18 actions). |
| `README.md` | This file. |

---

## Design decision — ONE parametrized workflow (not three)

The response to SQLi, XSS, and traversal is near-identical (block/challenge the offending
`src_ip` at Cloudflare, enrich, correlate, note, notify), so this is **one parametrized
workflow** rather than three copies. The coupling point is the trigger filter:

> `name contains "CF-WAF-"` **AND** `severity in ["HIGH","CRITICAL"]`

`CF-WAF-` uniquely prefixes exactly the three web-application WAF rules above. The other lab
detections use distinct prefixes (`CF-Access-` cred, `CF-API-` exfil, `CF-Bot-` bot,
`CF-Gateway-` DNS), so this filter will not over-match. The per-scenario attack type is
surfaced dynamically through `{{local_var.alert_name}}` (the alert's own `name`), which is
carried verbatim into the S1 note, IOC description, Slack message, and email — so a demo shows
"CF-WAF-SQLi …" vs "CF-WAF-XSS …" without needing three separate workflows. If you prefer three
discrete workflows (e.g. different Cloudflare rule scoping per attack class), split the single
filter group into three exact-name filter groups and duplicate the file — the body is unchanged.

---

## Flow (block-by-block)

```
Singularity Response Trigger  (name contains CF-WAF-, HIGH/CRITICAL, run_automatically:false)
  → Attacker Source IP        (var: attacker_ip)
  → Alert Context             (vars: host, sample_uri, alert_name, lowest_score, attack_requests, country)
  → Search Related S1 Events  (SDL PowerQuery: count class_uid=4002 events from attacker_ip, 6h)   [enrich A]
  → Correlated Event Count    (var: correlated_count)
  → VirusTotal IP Report      (core HTTP GET /ip_addresses/{ip})                                    [enrich B]
  → VT Malicious Count        (var: vt_malicious)
  → Reputation And Correlation Gate  (vt_malicious > 0  OR  correlated_count > 3)
       TRUE  → Set Block Verdict → Block Attacker IP At Cloudflare (mode=block) → Add S1 IOC ┐
       FALSE → Set Challenge Verdict → Challenge Attacker IP At Cloudflare (mode=managed_challenge) ┤
                                                                                                    ↓ (converge)
  → Compose Alert Note → Add Alert Note (UAM GraphQL) → Raise Alert Verdict → Notify SOC Slack → Send Email
```

Block and challenge branches **reconverge** on `Compose Alert Note` — the shared note/verdict/
notify tail runs once, reading the `verdict` / `response` variables the executed branch set.

### Why the decision gate is an OR of two signals
- **VirusTotal malicious > 0** — external threat-intel confirmation of the `src_ip`.
- **correlated_count > 3** — the same IP produced >3 other Cloudflare security events
  (`class_uid=4002`) in the last 6h, i.e. multi-source corroboration from our own telemetry.

Either satisfies the evidence bar to escalate from a hypothesis to an actionable verdict. If
**neither** fires (VT clean/unavailable and the IP is a one-off), the workflow takes the
**non-destructive managed-challenge** path — it raises attacker cost without hard-blocking a
possible false positive. This mirrors the project's evidence discipline: no destructive block
without threat-intel or independent corroboration.

---

## Alert field paths — reconcile before enabling (important)

The `s1-detection-engineer` audit that was to confirm alert entity/enrichment readiness
(`hyperautomation/_DE_AUDIT/`) is **not present** in the repo this session, so the exact JSON
paths the scheduled-rule alert exposes to the workflow are **best-effort** and must be verified
against a real fired alert. The three rules project these columns:

`detection_time, src_ip, host, country, attack_requests, lowest_score, sample_uri, sample_ua, first_seen`
(traversal additionally: `waf_hits, path_hits`).

The workflow reads them via `{{Function.DEFAULT(singularity-response-trigger.data.<column>, …)}}`
chains with sentinels, so a wrong path degrades gracefully (`no-ip` / `unknown-*`) rather than
crashing. **Action for the deployer:** fire one test alert, inspect its JSON in
`GET /web/api/v2.1/unifiedalerts/graphql` (or the Singularity Response event payload), and correct
the paths in the `Attacker Source IP` and `Alert Context` variable actions if they differ. The
IP fallback path `data.indicators[0].value` follows the house convention in `hyperautomation/ctf/`.

---

## Required pre-configured console connections (Hyperautomation → Integrations)

Integration-backed actions (`"tag": "integration"`, 7 of 18) will **not run** until these
connections exist. They cannot be created via API — configure them in the console, then bind each
action's connection after import.

| Connection | Used by | Notes |
|------------|---------|-------|
| **Cloudflare** (API token) | Block / Challenge Attacker IP | Token needs **Zone → Firewall Services: Edit** on the `soledrop.co` zone. Uses `POST /client/v4/zones/{{Connection.zone_id}}/firewall/access_rules`. Confirm the connection exposes `{{Connection.zone_id}}` or hardcode the `soledrop.co` zone id post-import. |
| **SentinelOne SDL** (Bearer) | Search Related S1 Events | **Must be the SDL/Bearer connection, not the ApiToken one** — LRQ/PowerQuery requires `Authorization: Bearer`. |
| **SentinelOne** (ApiToken) | Add S1 IOC, Add Alert Note, Raise Alert Verdict | Standard S1 REST/UAM connection. |
| **Slack** | Notify SOC Slack | Bot token with `chat:write` to `#oneflare-soc`. |
| **Send Email** (platform mailer) | Send Email | Core action — uses platform SMTP; confirm a verified sender exists. |

**Non-integration core HTTP action with a secret to set post-import:**
- **VirusTotal IP Report** — set the `x-apikey` header to a VirusTotal API key. **Do not commit
  the real key** (placeholder `<set-VT_API_KEY-after-import>` is in the JSON). `continue_on_fail:true`,
  so an unset/failed VT lookup simply drops to the challenge path.

---

## Catalog gaps / things modeled around (evidence discipline — no fictional blocks)

The building-blocks catalog does **not** ship a native "Cloudflare block" action type or a
"search related S1 alerts" action. Everything here is composed from real catalog blocks
(`http_request`, `variable`, `condition`, `singularity_response_trigger`, `send_email`), so the
following are modeled as HTTP requests, called out honestly:

1. **Cloudflare block/challenge** → core catalog has no first-class CF action; the corpus
   (`building-blocks-catalog.md`) shows Cloudflare done as an integration-backed `http_request`.
   Modeled here as two `http_request` actions to the Cloudflare `firewall/access_rules` API
   (`mode: block` / `mode: managed_challenge`). `public_action_id: cloudflare-create-ip-access-rule`
   is a **descriptive placeholder** — the real UUID resolves from the Cloudflare integration's
   action catalog when you bind the connection.
2. **VirusTotal IP reputation** → catalog **B10** (IP variant `/api/v3/ip_addresses/{ip}`). Present
   in the catalog; used as-is. AbuseIPDB (`api.abuseipdb.com`) is also referenced by the catalog as
   an alternative but VirusTotal is the corpus/project default TI provider, so it's the one wired.
3. **S1 related-event search** → catalog **B8** (PowerQuery via DV API). The exact response-shape
   path for the count (`body.matches[0].related_events` vs `body.data.matchCount`) is provider-
   dependent, so `Correlated Event Count` uses a DEFAULT chain with a `0` sentinel.
4. **Add S1 IOC** → catalog **B9**, used verbatim (IPV4, 7-day validity).
5. **Add alert note** → catalog **B6** modern `addAlertNote` mutation, `HTML_ENCODE`d body — used
   verbatim.
6. **Raise alert verdict** → **not a documented catalog block.** Modeled as a UAM GraphQL
   `updateAlertAnalystVerdict` mutation. The exact mutation name is **best-effort and must be
   confirmed against the tenant's `unifiedalerts` GraphQL schema**; `continue_on_fail:true` so the
   workflow completes even if the mutation name differs. This is the one action most likely to need
   a post-import edit.
7. **Slack / Email** → catalog **A14** + `slack-post-message`, used verbatim.

`public_action_id` values on all integration actions are placeholders that the console re-resolves
on connection bind (per the catalog's import contract: `connection_id`/`connection_name`/
`integration_id` are all null/empty for import-ready JSON).

---

## Validation result

Validated against `references/validation-rules.md` with a structural checker
(`build_web_attacks.py`). Result: **0 errors, 0 warnings.** Checks passed:
- Top-level keys exactly `name` / `description` / `actions`.
- 18 unique `export_id`s; every `connected_to.target` resolves to a valid `export_id`.
- Exactly one trigger; `parent_action:null`; non-empty `filter_groups` with all required keys.
- Every action `type` == `data.action_type`; every `state` == `active`.
- Integration actions import-ready (`connection_id:null`, `connection_name:""`, `integration_id:null`);
  core actions have null connection/integration ids.
- Condition is `condition_type:"multi"` with a non-null `conditions` array and a `true` branch.
- No same-action `local_var` cross-reference in any Variable action (hard rule / anti-pattern E1).
- Terminal action (`export_id:0`) has `connected_to: []`.
- JSON round-trips cleanly.

---

## Deploy status: **PENDING**

Not imported/published — no Console User token was available this session and the sandbox blocks
`*.sentinelone.net`. Deliverable is validated, importable JSON + the commands below.

### Deploy loop (when a live tenant + Console User token are available)

Use a **personal Console User** token (not a Service User token) — the HA API has no ownership-
transfer endpoint, so a service-token import is invisible in the UI. Site scope is
`2433185103040607397` (the detection rules' `filter.siteIds`).

```bash
export S1_CONSOLE_URL="https://<region>-<tenant>.sentinelone.net"
export S1_CONSOLE_API_TOKEN="<console-user-personal-token>"
export SITE_ID="2433185103040607397"
WF=hyperautomation/web-attacks/web-attacks.workflow.json

# 1. Import (lands as a Private Draft owned by the token user). Capture id + version_id.
curl -s -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/public/workflow-import-export/import?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" -H "Content-Type: application/json" \
  -d "{\"data\": $(cat $WF)}"
# Read response.id and response.version_id at the TOP LEVEL (not response.data.id).

# 2. Publish in the SAME step so the team can see it (Private Draft -> Shared).
curl -s -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/v1/workflows/$WORKFLOW_ID/publish?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" -d '{}'

# 3. Bind connections in the console UI: Cloudflare, SentinelOne SDL (Bearer),
#    SentinelOne (ApiToken), Slack, Send Email. Set VT x-apikey on 'VirusTotal IP Report'.

# 4. Activate.
curl -s -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/public/workflows/$WORKFLOW_ID/$VERSION_ID/activation?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" -H "Content-Type: application/json" -d '{"data":{}}'

# 5. Test: let a CF-WAF-* detection fire (or approve one from Singularity Response),
#    then confirm the run:
curl -s "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/public/workflow-execution?workflow_id=$WORKFLOW_ID&siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN"
```

Equivalent MCP path: `ha_import_workflow` → publish → bind connections → activate, via the
`s1-secops-mcp` `ha_*` tools. Re-import creates a **new** workflow (no in-place update) — delete
superseded versions with `DELETE /hyper-automate/api/v1/workflows/{id}?siteIds=$SITE_ID`.

### Test-run trace
**Not captured — deploy is pending** (no reachable tenant this session). Once step 5 returns an
execution, the expected trace is: trigger → attacker_ip/context vars set → Search Related S1 Events
(200) → VirusTotal IP Report (200/clean or 4xx) → gate → one of {Block+IOC | Challenge} → note →
verdict → Slack → email. No fabricated execution ids are shown here per evidence discipline.

---

## Assumptions that need a live tenant to finalize
- **Alert field paths** (`data.src_ip`, `data.host`, `data.sample_uri`, `data.lowest_score`,
  `data.attack_requests`, `data.country`) — reconcile with a real fired alert (see section above).
- **`{{Connection.zone_id}}`** — confirm the Cloudflare connection exposes it, or hardcode the
  `soledrop.co` zone id.
- **`public_action_id` UUIDs** — placeholders; the console resolves them on connection bind.
- **`updateAlertAnalystVerdict` mutation name** — confirm against the tenant UAM GraphQL schema.
- **Asset binding** — Cloudflare logs bind to "Unknown Device" unless the asset-enrichment
  solution runs first; this workflow does not depend on EDR asset binding (it keys on `src_ip`),
  so it functions regardless, but the alert's Target Asset may show "Unknown Device".
- **`run_automatically:false`** — surfaces as an analyst-approved action in the Singularity
  Response console. Flip to `true` for fully-automated response only after testing.
