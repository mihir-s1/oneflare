# Bot / Scraper Response — Graduated Cloudflare Mitigation (BotScore)

SOAR response playbook for the OneFlare / NovaMind lab scenario **bot** (`CF-Bot-Scraper`,
BotScore-based). Fires on the deployed S1 scheduled detection and applies a graduated Cloudflare
containment that **keys on Cloudflare's ML BotScore verdict — not the spoofable User-Agent**.

- **Workflow JSON:** `bot-scraper.workflow.json`
- **Trigger detection:** `detections/bot-scraper/bot-scraper.rule.json` — rule id
  `2523842940840264774`, `CF-Bot-Scraper (BotScore)`, scheduled, Medium, Active.
- **MITRE:** ATT&CK **T1595** (Active Scanning), **T1071** (Application Layer Protocol);
  ATLAS **AML.T0002** (data reconnaissance via scraping).

---

## Why BotScore, not User-Agent

The detection fires when one `src_ip` produces ≥ 20 HTTP requests that Cloudflare's ML model
scored `BotScore <= 29` (lower = more bot-like) against the `soledrop.co` surface. The JA4 TLS
variant of this detection is **dead in this tenant** (`unmapped.JA4` / `JA4Signals` / `BotTags`
return 0), so BotScore is the working signal. The response therefore branches on the ML verdict
plus IP reputation — never on the User-Agent, which scrapers trivially spoof (validated hits
carried `Wrath-AIO`, `libwww-perl`, `PhantomJS`, `Go-http-client`).

## Graduated response (challenge-first)

| Decision | Cloudflare action | Rationale |
|---|---|---|
| VT `malicious ≥ 3` **OR** ≥ 200 lab requests/24h | **`block`** | Known-bad reputation or high-volume abuse → hard IP block |
| otherwise (automated but not yet known-bad) | **`managed_challenge`** | Reversible interstitial; real browsers pass, headless scrapers do not |

Challenge-first is the correct default for automated traffic: it contains the scraper without
risking a false-positive hard block on a mislabelled human. The hard block is reserved for the
reputation/volume-confirmed case.

---

## Flow (block-by-block)

```
Singularity Response Trigger (name contains "CF-Bot-Scraper", severity in MED/HIGH/CRIT)
  → Variable: Bot Source IP        (src_ip = DEFAULT(indicators[0].value, "no-ip"))
  → Condition: Valid Source IP     (src_ip != "no-ip")  ── false: dead-end (no-op)
    true
     → Variable: Related Activity Query   (build class_uid=4002 PowerQuery for this src_ip)
     → HTTP  : Search Related Activity     [S1 SDL]  re-derive bot metrics + repeat-offender volume
     → HTTP  : Check IP Reputation         [VirusTotal]  malicious count + AS owner/ASN
     → Variable: VT Malicious Count        (vt_malicious, reused by gate + note)
     → Variable: Related Events Count      (related_events, reused by gate + note)
     → Condition: Malicious or High Volume (vt_malicious>=3  OR  related_events>=200)
         true  → Variable: Response Mode Block      (cf_mode = "block")      ┐
         false → Variable: Response Mode Challenge  (cf_mode = "managed_challenge") ┘
                → HTTP: Apply CF IP Access Rule  [Cloudflare]  mode = {{cf_mode}}, target ip = src_ip
                → Variable: Note Body            (evidence summary, confidence = SUSPICIOUS)
                → HTTP: Add S1 Alert Note        [S1]  addAlertNote(HTML_ENCODE(note))
                → HTTP: Notify SOC Slack         [Slack] chat.postMessage
                → Send Email: Email SOC          [core SMTP]
```

The two decision branches **converge** on `Apply CF IP Access Rule` (a diamond): each branch only
sets the `cf_mode` variable, so the block/challenge/note/notify tail is written once, not
duplicated.

### Enrichment before decision (evidence discipline)

Two independent enrichments run before any containment:

1. **S1 search — repeat offender.** `Search Related Activity` re-runs the detection's own logic
   against `class_uid=4002 dataSource.name='Cloudflare'` for this `src_ip` over 24h, returning
   `related_events`, `distinct_hosts`, `distinct_paths`, `min_botscore`, `sample_ua`,
   `sample_path`, `country`. This answers "is this IP hammering the surface / crawling broadly?"
   using a schema we can cite, instead of trusting alert row-field paths.
2. **Reputation — bad hosting.** `Check IP Reputation` (VirusTotal IP report) yields
   `last_analysis_stats.malicious` and `as_owner` / `asn` — scrapers commonly ride known bad
   hosting/VPS ASNs, so the AS owner is a first-class signal in the note.

Both are `continue_on_fail: true`, so a lookup miss degrades safely to `managed_challenge` rather
than blocking the run. The destructive **block** action is gated on the reputation/volume verdict
(evidence discipline: no hard block on a spoofable signal alone).

---

## Required console connections (configure BEFORE import)

Integration-backed actions need pre-configured connections in **Hyperautomation → Integrations**.
These **cannot** be created via the import API — configure them first, then (if needed) update the
`connection_name` in the JSON.

| Integration | Used by | Notes |
|---|---|---|
| **Cloudflare** | Apply CF IP Access Rule | Needs API token + `zone_id` for `soledrop.co`. Uses `{{Connection.zone_id}}`. |
| **SentinelOne** (ApiToken) | Add S1 Alert Note | `unifiedalerts/graphql` — standard `ApiToken` connection. |
| **SentinelOne SDL** (Bearer) | Search Related Activity | LRQ/DV PowerQuery needs the **Bearer** SDL connection, not the ApiToken one. |
| **VirusTotal** | Check IP Reputation | Free-tier API key (injects `x-apikey`). |
| **Slack** | Notify SOC Slack | `chat:write` to `#oneflare-soc`. |
| _core SMTP_ | Email SOC | Not an integration — tenant email sender must be configured. |

---

## Catalog gaps (no fabricated blocks)

Honest accounting of where the vendored building-blocks catalog
(`reference/s1-secops-skills/skills/hyperautomation/references/building-blocks-catalog.md`) did
**not** provide a native block, and how each was modelled:

1. **Cloudflare has no native building block** in the catalog (grep = 0 hits). Modelled as
   integration-backed HTTP requests (`public_action_id: cloudflare-create-ip-access-rule`),
   matching the repo's CTF house style (`hyperautomation/ctf/box1-2-recon-bot-response.json`).
   Requires a Cloudflare console connection. Note: `firewall/access_rules/rules` is Cloudflare's
   legacy IP Access Rules API (still functional and supports `block` + `managed_challenge` modes);
   the modern equivalent is the Rulesets API — swap the URL/payload if the tenant has migrated.
2. **AbuseIPDB per-IP check is not a catalog action** — it appears only as an OSINT *blacklist*
   list source (recipe C2), not a lookup. Used **VirusTotal IP report (catalog B10)** instead,
   which also returns AS owner/ASN for the "bad hosting" signal. Swap to a core `api.abuseipdb.com`
   HTTP GET if AbuseIPDB is preferred (`api.abuseipdb.com` is in the A12 top-hostnames list).
3. **Programmatic confidence / analystVerdict set** — the catalog documents `addAlertNote`
   (B6) but **no verified verdict-set mutation id**. Confidence is therefore recorded in the note
   text (`Confidence: SUSPICIOUS`) and left for the analyst (trigger is `run_automatically: false`,
   so a human approves from the Singularity Response console anyway). Not fabricated.
4. **Scheduled-rule row columns → alert field paths.** The rule's `entityMappings` is a *pending
   feature* (`_entityMappings_pending_feature` in the rule JSON), so `bot_requests` / `min_botscore`
   / `sample_ua` / `distinct_paths` are **not** reliably present as alert indicator fields. Rather
   than guess field paths, the workflow **re-derives** these metrics in-flow via PowerQuery against
   the detection's own source (`class_uid=4002`). `src_ip` is taken from `indicators[0].value`
   (CTF-proven path) with a DEFAULT fallback. If/when a DE audit confirms the alert field paths,
   the re-derivation query can be dropped in favour of direct alert references.
5. **PowerQuery-via-DV endpoint token `<@powerQuery@>`** is kept exactly as catalog B8 specifies;
   it is resolved by the SentinelOne SDL connection at runtime. The modern LRQ alternative
   (`POST /sdl/v2/api/queries`, async launch→poll) is documented in `.claude/rules/s1-development.md`
   if a synchronous DV call is unavailable on the tenant.

---

## Validation

Validated against the skill's `references/validation-rules.md` — **PASS**:

- Top-level keys exactly `name` / `description` / `actions`; every action has
  `action` / `export_id` / `connected_to` / `parent_action`.
- 16 actions, unique `export_id`s `0..15`; every `connected_to.target` resolves; all nodes
  reachable from the single trigger.
- Exactly one trigger; `filter_groups` non-empty with `event_type` / `event_subtypes` /
  `condition` / `is_disabled` / `run_automatically`; `in`-operator `compared_value` is a
  JSON-encoded array string (`"[\"MEDIUM\",\"HIGH\",\"CRITICAL\"]"`).
- Both conditions use `condition_type: "multi"` (catalog: `simple` is unused); gate uses only a
  `true` handle, decision uses `true` + `false`.
- Every Variable action defines a single variable; **no** same-action `local_var` cross-reference
  (E1). Note body wraps text in `Function.HTML_ENCODE` (E2).
- All integration actions set `connection_id: null`, `connection_name: ""`, `integration_id: null`
  and keep their `public_action_id`; `retry_on_status_codes: [500]` on external calls (E7).
- No loops/snippets → `parent_action: null` throughout, `snippet_*: null`.

Re-run the structural check:

```bash
python3 - <<'PY'
import json,re
wf=json.load(open("hyperautomation/bot-scraper/bot-scraper.workflow.json"))
assert set(wf)=={"name","description","actions"}
ids=[a["export_id"] for a in wf["actions"]]; assert len(ids)==len(set(ids))
idset=set(ids)
for a in wf["actions"]:
    for e in a["connected_to"]: assert e["target"] in idset
print("PASS", len(wf["actions"]), "actions")
PY
```

---

## Deploy — status: PENDING (not deployed)

Import was **not** performed: this environment has no S1 credentials
(`S1_CONSOLE_URL` / `S1_CONSOLE_API_TOKEN` unset, no `credentials.json`), the `ha_*` MCP tools /
`ha_import_workflow` are not available here, and the sandbox blocks outbound to `*.sentinelone.net`.
Deliverable is the **validated, importable JSON** plus the commands below.

Import lands as a **Private Draft owned by the token user** and is invisible to other humans until
published — so **publish in the same step**, and use a **personal Console User token** (not a
Service User token; see catalog E8).

```bash
# 0) creds (personal Console User token)
export S1_CONSOLE_URL="https://<your-console>.sentinelone.net"
export S1_CONSOLE_API_TOKEN="<personal-console-user-jwt>"

# 1) import (via s1-secops-mcp ha_import_workflow, or raw API):
curl -sS -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/v1/workflows/import" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @hyperautomation/bot-scraper/bot-scraper.workflow.json
# -> capture the returned workflow {id}

# 2) publish IN THE SAME STEP (makes it visible / activatable):
curl -sS -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/v1/workflows/<id>/publish?accountIds=<acct>&siteIds=2433185103040607397" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN"
```

Then, in the console UI:
1. **Bind connections** for Cloudflare, SentinelOne, SentinelOne SDL, VirusTotal, Slack (and the
   SMTP sender) on each integration action.
2. **Activate** the workflow.
3. **Test:** trigger a test alert on rule `2523842940840264774` (run the bot/scraper attack
   script against `shop.soledrop.co` so a low-BotScore burst fires the detection), then confirm in
   the workflow run trace that: src_ip extracted → related-activity query ran → VT lookup returned
   → the decision picked `block` or `managed_challenge` → the Cloudflare IP Access rule was created
   → the S1 alert note posted → Slack + email sent. Verify the Cloudflare rule exists at
   **Security → WAF → Tools → IP Access Rules** for the `soledrop.co` zone.

> Re-import creates a **new** workflow (no in-place update). Manage versions deliberately.
