# NovaMind CTF — Hyperautomation Response Playbooks

Response workflows for **Operation Agentic AI Breakout** (the 4-box CTF in
`attack-scripts/campaigns/ctf.py`). Each file is a SentinelOne Hyperautomation workflow JSON
authored against the workflow-schema and building-blocks-catalog. Branding: **NovaMind
Technologies** / **Pyxis** rogue agentic AI.

**Author-only.** Nothing here has been imported or published to a live tenant — no creds were
assumed. Deploy steps below are the intended procedure for whoever has a Console User token.

## Files

| File | Box / scenario | S1 detection trigger (name `contains`) |
|------|----------------|----------------------------------------|
| `box1-2-recon-bot-response.json` | Box 1 recon sweep + Box 2 polymorphic bot (constant JA4) | `NovaMind-CTF-Box1-ReconSweep` OR `NovaMind-CTF-Box2-PolymorphicBot` |
| `box3-prompt-injection-response.json` | Box 3 prompt injection vs Pyxis (`/api/v1/chat`) | `NovaMind-CTF-Box3-PromptInjection` |
| `box4-agentic-breakout-response.json` | Box 4 agentic multi-vector breakout | `NovaMind-CTF-Box4-AgenticBreakout` |
| `exfil-training-data-response.json` | Training-data / customer-export exfil | `NovaMind-CTF-DataExfil` |

> The trigger filter `name`-contains values are the **assumed** detection-rule names. Align them
> with whatever `s1-detection-engineer` actually names the rules under `detections/`. The trigger
> matches on the alert `name` field, so the detection rule name is the only coupling point.

## Per-workflow detail

### Box 1/2 — Recon & Polymorphic Bot Response
- **Trigger**: Singularity Response alert (two filter groups = OR), `run_automatically: false`.
- **Actions**: extract ClientIP (real origin, not spoofed XFF) → set constant JA4 →
  Cloudflare **Get IP Overview** (enrich) → **Condition** gate (IP present) →
  Cloudflare **Create IP Access rule** (block IP, zone) → Cloudflare **Create firewall rule**
  (block constant JA4 `t13d1812h1_85036bcba153_b26ce05bbdd6`) → **S1 Add IOC** (IPV4) →
  **Slack** notify → **Send Email**.
- **Why JA4**: the bot rotates User-Agents but the Python-requests TLS fingerprint is constant —
  blocking the JA4 stops future UA-rotated requests regardless of source IP.

### Box 3 — Prompt Injection (Pyxis) Response
- **Trigger**: Singularity Response alert on the Firewall-for-AI detection
  (`FirewallForAIInjectionScore=100` on `POST /api/v1/chat`).
- **Actions**: extract ClientIP + targeted service account →
  Cloudflare **Create firewall rule** with `managed_challenge` scoped to
  `http.request.uri.path eq "/api/v1/chat"` (Turnstile / Under-Attack equivalent on the llm route)
  → **core HTTP** to the NovaMind Worker `POST /api/incident` to swap Pyxis to the restricted
  fallback model `pyxis-chat-v2-fast` and raise the `/status` banner → **Condition** (service
  account known) → **Disable service account** (Entra/M365 identity action) → **S1 Add IOC** →
  **Slack** + **Email**.
- **Restricted fallback**: the model swap is delivered to a Cloudflare Worker
  (`novamind-api.../api/incident`, key-gated by `INCIDENT_KEY`), matching the real-ready
  `env.PYXIS_LLM_*` design. Set the `X-Incident-Key` header value after import.

### Box 4 — Agentic Breakout Response
- **Trigger**: Singularity Response alert, **CRITICAL** only, `run_automatically: false`.
- **Actions**: extract ClientIP + agent UUID → **VirusTotal IP report** →
  **Condition** gate (`last_analysis_stats.malicious > 0`) — *destructive actions only run on a
  confirmed malicious verdict (evidence discipline)* → **S1 Isolate agent**
  (`/agents/actions/disconnect`) → Cloudflare **account-level IP Access rule** (global edge block)
  → Cloudflare **firewall rule** (block JA4) → **S1 Add IOC** (risk 100) → **Slack** page +
  **Email**.

### Exfil — Training/Customer Data Export Response
- **Trigger**: Singularity Response alert on the export-volume / unauthorized-pull anomaly.
- **Actions**: extract ClientIP → Cloudflare **Get IP Overview** → **Condition** (IP present) →
  Cloudflare **firewall rule** blocking `/api/v1/training-data` + `/api/v1/customers/export` for
  the IP → Cloudflare **zone IP Access rule** (block) → **core HTTP** raise NovaMind `/status`
  incident banner → **S1 Add IOC** → **Slack** + **Email**.

## Required pre-configured console connections (Hyperautomation → Integrations)

Integration-backed actions (`"tag": "integration"`) will NOT run until these connections exist.
They cannot be created via API — configure them in the console first, then bind each action's
connection after import.

| Connection | Used by | Notes |
|------------|---------|-------|
| **Cloudflare** (API token) | Get IP Overview, Create IP Access rule, Create firewall rules | Token needs Zone Firewall + Account Firewall Access Rules edit. `{{Connection.zone_id}}` / `{{Connection.account_id}}` are placeholders — confirm your connection exposes them or hardcode the zone/account IDs post-import. |
| **SentinelOne** (ApiToken) | Add IOC, Isolate agent | Standard S1 connection. |
| **Entra / M365** (or your IdP) | Lock Pyxis Service Account (Box 3) | Swap for Okta/other if NovaMind's IdP differs; the action is a generic identity `disable user`. |
| **Slack** | Notify Slack (all workflows) | Bot token with `chat:write` to `#novamind-soc`. |
| **Send Email** (platform mailer) | Send Email (all workflows) | Core action — uses the platform SMTP; confirm a verified sender exists. |

**Non-integration core HTTP actions** (no connection, but a secret to set post-import):
- **VT IP Report** (Box 4): set `x-apikey` header to a VirusTotal API key.
- **Swap Pyxis To Fallback Model** / **Raise Incident Banner**: set `X-Incident-Key` header to the
  NovaMind Worker `INCIDENT_KEY`. **Do not commit the real key** — placeholders are in the JSON.

## Critical operational rules (read before deploying)

1. **Import lands as a Private Draft owned by the token user** (invisible to other humans).
   **Publish in the same step** so the team can see it:
   `POST /hyper-automate/api/v1/workflows/{id}/publish?accountIds=…&siteIds=…` (bodyless, `{}`).
2. **Use a personal Console User API token**, not a Service User token. The HA API has no endpoint
   to transfer ownership — a service-token import is invisible in the UI ("where did my workflow go?").
3. **No in-place update.** Re-importing creates a *new* workflow. Manage versions deliberately;
   delete superseded ones with `DELETE /hyper-automate/api/v1/workflows/{id}?accountIds=…`.
4. **An HTTP action that runs an SDL LRQ / PowerQuery needs the "SentinelOne SDL" (Bearer)
   connection**, not the "SentinelOne" (ApiToken) connection. (None of these four workflows run an
   SDL query today — but if you add a PowerQuery enrichment step, bind it to the SDL Bearer
   connection, not the ApiToken one.)
5. **Gate destructive actions on a threat-intel verdict.** Box 4 isolate/quarantine + global edge
   block run only behind a VT-malicious condition. Keep that discipline if you extend the others.
6. `run_automatically` is **false** on every trigger — these surface as analyst-approved actions in
   the Singularity Response console. Flip to `true` only for fully-automated response after testing.

## Deploy loop (when a live tenant + Console User token are available)

```bash
# Validate JSON shape first (skill validator / the parse check below)
# 1. Import (lands as Private Draft) — capture top-level id + version_id from the response
curl -s -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/public/workflow-import-export/import?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" -H "Content-Type: application/json" \
  -d "{\"data\": $(cat box3-prompt-injection-response.json)}"

# 2. Publish in the SAME step so humans can see it
curl -s -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/v1/workflows/$WORKFLOW_ID/publish?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" -d '{}'

# 3. Bind connections (Cloudflare / SentinelOne / Entra / Slack) in the console UI

# 4. Activate
curl -s -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/public/workflows/$WORKFLOW_ID/$VERSION_ID/activation?siteIds=$SITE_ID" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" -H "Content-Type: application/json" -d '{"data":{}}'

# 5. Fire a test alert matching the trigger name and confirm executions:
#    GET /hyper-automate/api/public/workflow-execution?workflow_id=$WORKFLOW_ID
```

Equivalent MCP path: `ha_import_workflow` → publish → bind → activate, using the `ha_*`
`s1-secops-mcp` tools.

## Assumptions that need a live tenant to finalize

- **Detection rule names**: trigger filters assume `NovaMind-CTF-Box{1..4}-*` / `NovaMind-CTF-DataExfil`.
  Reconcile with `detections/` once the detection engineer's rules land.
- **`public_action_id` values** (e.g. `cloudflare-create-ip-access-rule`, `sentinelone-create-ioc`,
  `entra-disable-user`, `slack-post-message`) are descriptive placeholders. The real UUIDs come from
  each integration's action catalog on the target tenant; the console resolves/relinks them when you
  bind the connection after import. Re-bind in the UI if an action doesn't auto-resolve.
- **`{{Connection.zone_id}}` / `{{Connection.account_id}}`**: confirm the Cloudflare connection
  exposes these, or hardcode NovaMind's zone/account IDs post-import.
- **Asset binding**: Cloudflare logs bind to "Unknown Device" unless the asset-enrichment solution
  runs first (see `.claude/rules/s1-development.md`). Box 4's `asset.agentUuid` isolate only works if
  the alert carries an EDR-bound asset; otherwise the isolate action no-ops and the CF edge block +
  IOC still fire.
- **Service account identity**: Box 3 defaults the locked account to `pyxis-chat-svc@novamind.ai`;
  confirm the real Pyxis service-account UPN and the IdP integration before enabling.
