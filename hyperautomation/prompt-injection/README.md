# OneFlare — LLM Prompt-Injection Response Playbook

Hyperautomation response workflow for the **CF-AI-PromptInjection** detection — LLM
prompt-injection / jailbreak probing of the NovaMind **Pyxis** AI chat endpoint
(`api.one-flare.com` `POST /api/v1/chat`).

| | |
|---|---|
| **File** | `prompt-injection.workflow.json` |
| **Scenario** | 08 — Prompt Injection / LLM Jailbreak (AI Security) |
| **Detection trigger** | `CF-AI-PromptInjection` — scheduled rule **2519093028014740613** (Active) |
| **Alert entities used** | `src_ip` (indicator), `host`, `injection_posts`, `distinct_uas`, `sample_ua` |
| **MITRE ATLAS** | **AML.T0054** LLM Prompt Injection · **AML.T0057** LLM Data Leakage · ATT&CK **T1499** (resource abuse) |
| **run_automatically** | `false` — analyst approves from the Singularity Response console |
| **Status** | Authored + validated. **Deploy pending** (no live tenant / Console User token in this session). |

> **Author-only.** Nothing here has been imported or published to a live tenant — no
> credentials were assumed and the sandbox blocks outbound to `*.sentinelone.net`. The deploy
> steps below are the intended procedure for whoever holds a personal Console User token.

---

## Trigger

`singularity_response_trigger`, one filter group (AND):
`name contains "CF-AI-PromptInjection"` **and** `severity in ["HIGH","CRITICAL"]`,
`event_type: alert`, `event_subtypes: ["CREATE"]`, `run_automatically: false`.

The trigger name-match is the only coupling point to the detection rule — it matches the
deployed rule's alert `name`. The detection fires per row (`alertPerRow: true`) when one
`src_ip` issues ≥ 5 chat POSTs in the window, so each alert already represents a burst.

## Block-by-block logic

```
Singularity Response Trigger (CF-AI-PromptInjection, HIGH/CRITICAL)
  → Variable: Attacker Source IP          (client_ip = indicators[0].value | "no-ip")
  → Variable: AI Abuse Context            (ai_host, ai_endpoint=/api/v1/chat, ATLAS ids, alert markers)
  → Variable: Related Search Query        (PowerQuery, refs client_ip)
  → HTTP: S1 Related Chat Abuse Search    [enrich-a] PowerQuery over SDL — 24h chat POSTs from this IP
  → Variable: Related Chat Posts          (related_chat_posts = count from result | "0")
  → HTTP: VirusTotal IP Reputation        [enrich-b] core HTTP, src_ip reputation
  → Variable: VT Malicious Count          (vt_malicious = last_analysis_stats.malicious | "0")
  → Condition: IP Resolved  (client_ip != "no-ip")
       FALSE → Variable: No IP Note Text → HTTP: S1 Note No IP (manual review) ─ end
       TRUE  → Condition: Malicious Or Sustained   (vt_malicious > 0  OR  related_chat_posts >= 5)
                 TRUE  (confirmed → BLOCK):
                    → HTTP CF: Block IP On Chat Route   (WAF rule: path=/api/v1/chat AND ip.src=IP → block)
                    → HTTP CF: IP Access Block          (zone IP Access rule → block)
                    → Variable: Block Note Text
                    → HTTP S1: Note Block               (ATLAS technique + endpoint + correlated + reputation)
                    → HTTP S1: Raise Confidence         (TRUE_POSITIVE / HIGH)
                    → HTTP S1: Add IOC                  (IPV4, ml-attack, risk 90)
                    → HTTP: Notify AI Safety SOC Block  (Slack #ai-security-soc)
                    → Send Email Block                 ─ end
                 FALSE (unconfirmed single probe → CHALLENGE):
                    → HTTP CF: Challenge IP On Chat Route (WAF rule: managed_challenge on /api/v1/chat)
                    → Variable: Monitor Note Text
                    → HTTP S1: Note Monitor             (ATLAS technique + soft-containment rationale)
                    → HTTP S1: Set Suspicious           (SUSPICIOUS / MEDIUM — pending confirmation)
                    → HTTP: Notify AI Safety SOC Challenge (Slack) ─ end
```

### Enrichment arms (both run before the verdict gate)
- **(a) S1 related-alert search** — a PowerQuery counts *all* chat POSTs from the same
  `src_ip` over 24 h. A high count = a sustained jailbreak campaign; a low count = a one-off
  probe. Built in its own Variable action (it references `{{local_var.client_ip}}`).
- **(b) src_ip reputation** — VirusTotal IP report. `last_analysis_stats.malicious` feeds
  the verdict.

Both are `continue_on_fail: true` so an enrichment error still lets the analyst-approved
containment proceed.

### Decision gate (evidence discipline)
The destructive block path runs **only** when VirusTotal flags the IP malicious **or** the
src_ip shows a sustained campaign (≥ 5 chat POSTs / 24 h). A clean single probe gets a
**managed-challenge**, not a hard block, and the alert is set to *SUSPICIOUS — pending
confirmation* rather than TRUE_POSITIVE. This mirrors the project rule: no TRUE_POSITIVE
without independent TI/multi-source confirmation.

### How the ATLAS technique is "tagged"
S1 has no free-form alert-tag write in the HA catalog, so the **ATLAS technique is recorded
in the alert note** (`AML.T0054` / `AML.T0057`, spelled out on both branches). The
confidence/verdict is raised separately via the UAM analyst-verdict mutation.

---

## Required pre-configured console connections (Hyperautomation → Integrations)

Integration-backed actions (`"tag": "integration"`) will **not** run until these connections
exist. They cannot be created via API — configure them in the console first, then bind each
action's connection after import.

| Connection | Used by | Notes |
|------------|---------|-------|
| **SentinelOne SDL** (Bearer) | `S1 Related Chat Abuse Search` | **Bearer**, not the ApiToken connection — this action runs a PowerQuery/LRQ. Binding it to the ApiToken "SentinelOne" connection will fail auth. |
| **SentinelOne** (ApiToken) | `S1 Note *`, `S1 Raise Confidence` / `S1 Set Suspicious`, `Add S1 IOC` | Standard S1 REST + UAM GraphQL connection. |
| **Cloudflare** (API token) | `CF Block IP On Chat Route`, `CF IP Access Block`, `CF Challenge IP On Chat Route` | Token needs **Zone Firewall Services Edit** + **Firewall Access Rules Edit**. `{{Connection.zone_id}}` is a placeholder — confirm the connection exposes it or hardcode the `api.one-flare.com` zone id post-import. Co-designed with `cloudflare-specialist`. |
| **Slack** | `Notify AI Safety SOC *` | Bot token with `chat:write` to `#ai-security-soc`. |
| **Send Email** (platform mailer) | `Send Email Block` | Core action — uses platform SMTP; confirm a verified sender for `soc@one-flare.com`. |

**Non-integration core HTTP action (set a secret post-import):**
- **VirusTotal IP Reputation** — set the `x-apikey` header to a VirusTotal API key. Placeholder
  `<set-VT_API_KEY-after-import>` is in the JSON. **Do not commit the real key.**

---

## Catalog gaps & best-effort fields (evidence discipline — no invented blocks)

Everything below is modelled on real catalog blocks; these are the honest caveats to
reconcile against a live tenant. Nothing here is a fabricated action type.

1. **`public_action_id` values** (`cloudflare-create-firewall-rules`,
   `cloudflare-create-ip-access-rule`, `sentinelone-create-ioc`, `sentinelone-add-alert-note`,
   `sentinelone-set-analyst-verdict`, `sentinelone-sdl-powerquery`, `slack-post-message`) are
   **descriptive placeholders**. The real UUIDs come from each integration's action catalog on
   the target tenant; the console resolves/relinks them when you bind the connection after
   import. Re-bind in the UI if an action doesn't auto-resolve.
2. **Raise-confidence mutation** — `updateAlertAnalystVerdict(analystVerdict, confidenceLevel, alertId)`
   is a **best-effort UAM GraphQL placeholder**. The verified catalog block is the note mutation
   (`addAlertNote`, B6); reconcile the verdict mutation name/enum against the tenant's
   `unifiedalerts` GraphQL schema after import. If it doesn't exist under that name, the note
   still carries the analyst-facing verdict text.
3. **Scheduled-rule column projection** — the detection projects
   `src_ip, host, injection_posts, distinct_uas, sample_ua, …`, but how those columns surface
   in `singularity-response-trigger.data.*` is tenant/feature dependent (the rule's
   `entityMappings` are gated behind a pending feature). The **load-bearing** entity is
   `indicators[0].value` (the src_ip); every other alert field is read through
   `Function.DEFAULT(..., "<fallback>")` so a missing projection never breaks the flow.
4. **PowerQuery result path** — `s1-related-chat-abuse-search.body.data.values[0][1]` is the
   expected DV/LRQ response shape; confirm against the tenant's response and adjust if the
   PowerQuery action wraps results differently. `DEFAULT 0` keeps the gate safe on a miss.
5. **Rate-limiting** — the FLEET_BRIEF mentions block/challenge/**rate-limit**. Cloudflare rate
   limiting is a separate **Rulesets** API surface (`/rulesets/phases/http_ratelimit/entrypoint`),
   not the `firewall/rules` endpoint used here, so the workflow implements **block** (confirmed)
   and **managed-challenge** (unconfirmed). Adding a rate-limit rule is a clean extension via a
   core HTTP action to the Rulesets entrypoint — documented, not shipped, to avoid modelling an
   endpoint shape not exercised in this session.
6. **Parallel enrichment** — the two enrichment arms are logically parallel but wired
   **sequentially** in the graph (S1 search → VT), matching the corpus (`is_parallel` fan-out is
   rare and diamonds risk importer rejection). Order does not matter; both feed the gate.

---

## Complementary control (out of scope for this workflow)

This playbook is the **network/identity-level** response: it blocks/challenges the offending
`src_ip` at the Cloudflare edge, records evidence in S1, and notifies the SOC. It does **not**
inspect or filter the prompt content itself. **Content-level prompt-injection defense — input
filtering / guardrails at the Pyxis app or via Cloudflare Firewall for AI / AI Gateway — is
complementary and should be layered in front of this.** The two together give
defense-in-depth: the app rejects the malicious prompt; this workflow contains the source.

---

## Validation

Validated against the skill's `references/validation-rules.md` with a scripted checker
(structural keys, unique `export_id`s, valid `connected_to` targets, `type`↔`action_type`
match, integration import-ready fields, trigger/condition/variable rules, break-loop rules,
graph reachability, and `{{action-slug}}` reference resolution):

```
ACTIONS: 25   ERRORS: 0   WARNINGS: 0   → OK
```

Additional checks run this session:
- Every `payload` string parses as valid JSON after `{{…}}` templating (0 invalid).
- No `Function.HTML_ENCODE("string literal")` — note bodies live in their own Variable actions
  and are referenced **bare** (`HTML_ENCODE(local_var.x)`), the corpus B6 pattern, so raw
  quotes never break the GraphQL JSON body.
- One trigger, `parent_action: null`; no loops; both condition branches use `true`/`false`
  handles; every `{{local_var.*}}`-bearing variable is alone in its action.

---

## Deploy loop (when a live tenant + personal Console User token are available)

Import lands as a **Private Draft owned by the token user** → **publish in the same step** or
no human can see it. Use a **personal Console User token**, not a Service User token.

```bash
SITE_ID=2433185103040607397   # api.one-flare.com site (from the detection rule filter)
WF=hyperautomation/prompt-injection/prompt-injection.workflow.json

# 1. Import (Private Draft) — capture top-level id + version_id from the response
curl -s -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/public/workflow-import-export/import?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" -H "Content-Type: application/json" \
  -d "{\"data\": $(cat $WF)}"

# 2. Publish in the SAME step so humans can see it
curl -s -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/v1/workflows/$WORKFLOW_ID/publish?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" -d '{}'

# 3. Bind connections (SentinelOne SDL Bearer, SentinelOne ApiToken, Cloudflare, Slack) in the UI
#    and set the VirusTotal x-apikey header.

# 4. Activate
curl -s -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/public/workflows/$WORKFLOW_ID/$VERSION_ID/activation?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" -H "Content-Type: application/json" -d '{"data":{}}'

# 5. Fire a test alert matching name "CF-AI-PromptInjection" and confirm executions:
#    GET /hyper-automate/api/public/workflow-execution?workflow_id=$WORKFLOW_ID
```

Equivalent MCP path: `ha_import_workflow` → publish → bind → activate, using the `ha_*`
`s1-secops-mcp` tools (unavailable in this authoring session — sandbox blocks the console host).

## Test-run trace (pending deploy)

No live execution was performed — no tenant/token in this session. On deploy, a passing trace
is: trigger fires on a `CF-AI-PromptInjection` HIGH alert → `client_ip` extracted → S1 search +
VT return → `Malicious Or Sustained` = TRUE → CF block rule created (200) → zone IP Access
block (200) → S1 note + verdict + IOC written → Slack + email sent → `workflow-execution`
shows all block-path steps `success`.
