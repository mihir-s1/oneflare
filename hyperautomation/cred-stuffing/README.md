# Credential Stuffing / Brute-Force Response — `cred-stuffing.workflow.json`

Hyperautomation response playbook for OneFlare scenario **04 — Credential Attacks** on
`portal.novamind.ai`. Fires on the deployed **CF-Access-CredStuffing** scheduled STAR alert
(rule id `2519093004283366750`) and runs an **account-attack** response: enrich → decide →
contain-or-challenge → notify.

**Author-only.** Nothing here has been imported or published to a live tenant — no console
credentials were present in this environment and the sandbox blocks `*.sentinelone.net`.
Deploy is **pending**; the import/publish procedure is at the bottom.

---

## Trigger

- **Type:** Singularity Response Trigger (`alert` / `CREATE`), `run_automatically: false`.
- **Filter:** `severity in [HIGH, CRITICAL]` **AND** `name contains "CF-Access-CredStuffing"`.
- **Coupling:** matches the alert `name`. The deployed rule name is
  *"CF-Access-CredStuffing — Login Brute Force / Credential Stuffing on portal.novamind.ai"*;
  the `contains` substring is the only coupling point. `run_automatically:false` means the
  workflow surfaces as an analyst-approved action in the Singularity Response console — the
  destructive branch does **not** auto-fire.

## Alert entities actually available (evidence discipline)

The deployed rule groups by `src_ip, host` and projects these columns:
`detection_time, src_ip, host, failed_logins, distinct_uas, sample_status, sample_ua,
country, first_seen`. The workflow keys **only** off these plus enrichment it computes itself.

- **`src_ip`** is consumed via `singularity-response-trigger.data.indicators[0].value`. This
  depends on the rule's **`entityMappings` (src_ip) binding the value as an alert indicator**,
  which is currently `_entityMappings_pending_feature` on the deployed rule. Until
  entityMappings / the asset-enrichment solution are live, this resolves to `no-ip` and the
  workflow takes the **no-IP note branch** (a real finding, not a failure).
- **No `user`/`email`.** The fleet brief lists `user/email` as an alert entity, but the
  deployed rule reads the Cloudflare **HTTP Requests** dataset (`class_uid 4002`), which
  carries **no `UserEmail`**. Per-user blast-radius and per-user Access step-up are therefore
  **not possible from this alert** — documented as a gap below. (The Access *Audit* dataset
  would carry `UserEmail`; this rule does not use it.)
- **`failed_logins` / `distinct_uas` / `country`** live in the alert row, not as guaranteed
  structured trigger fields, so the workflow **recomputes** `failed_logins`/`distinct_uas`
  from SDL for the `src_ip` (action *S1 Auth Failure Recompute*) rather than trusting a
  templated field that may not exist.

## Both attack shapes

- **Brute force** (one IP, many passwords) and **credential stuffing** (one IP replaying many
  credentials with rotating User-Agents) both surface as a high `failed_logins` count for the
  `src_ip`. `distinct_uas` is the corroborating stuffing signal (many UAs from one IP = stuffing
  tooling). The note text calls out the interpretation explicitly.
- **Known lab limitation:** single lab host → `distinct_ips = 1` → the detection labels it
  *brute force*. The response does not depend on that label; it acts per `src_ip`, so it works
  for both the single-IP brute-force shape and (when multiple alerts fire, one per rotating IP)
  the stuffing shape.

## Block-by-block logic

| # (export_id) | Action | Type | Purpose |
|---|---|---|---|
| 30 | Singularity Response Trigger | core | Fire on CF-Access-CredStuffing (HIGH/CRITICAL). |
| 29 | Attacker Src IP | Variable | `client_ip = DEFAULT(indicators[0].value, "no-ip")`. |
| 28 | Src IP Resolved in Alert | Condition | Gate. TRUE → enrich/respond; FALSE → no-IP note branch (5). |
| 27 | Build S1 Search Queries | Variable | Two independent PowerQuery bodies (`pq_failed`, `pq_activity`) templated with `client_ip`. |
| 26 | S1 Auth Failure Recompute | HTTP (SDL) | **Search (a):** recompute `failed_logins` + `distinct_uas` for the IP over 24h. |
| 25 | S1 Cross-Surface Activity | HTTP (SDL) | **Search (b):** `login_successes` (successful login from the attacking IP = ATO foothold) + cross-surface blast radius. |
| 24 | AbuseIPDB IP Reputation | HTTP (core) | Independent TI verdict for `src_ip` (`abuseConfidenceScore`). |
| 23 | Malicious or High-Risk Src IP | Condition | **OR** gate → contain (22) vs challenge (13). |
| 22 | Create IP Access Rule Block | HTTP (CF) | **Contain:** Cloudflare IP Access rule `mode: block` on the portal zone. |
| 21 | Escalate Portal Zone Under Attack | HTTP (CF) | **Contain step-up:** `security_level = under_attack` (zone-wide JS interstitial). |
| 20 | Add IOC for Attacker IP | HTTP (S1) | **Contain:** S1 IPV4 threat-intel IOC (7-day `validUntil`). |
| 19 | Containment Note Body | Variable | Assemble the containment summary. |
| 18 | Add Containment Note to Alert | HTTP (S1) | **Contain:** UAM GraphQL `addAlertNote`. |
| 17 | Raise Alert Confidence | HTTP (S1) | **Contain:** set `analystVerdict = SUSPICIOUS` (capped — see discipline note). |
| 16 | Notify SOC Slack Contain | HTTP (Slack) | **Contain:** Slack summary. |
| 15 | Send SOC Email Contain | send_email | **Contain:** email receipt. *(terminal)* |
| 13 | Create IP Access Rule Challenge | HTTP (CF) | **Challenge:** Cloudflare IP Access `mode: managed_challenge` (step-up, not a hard block). |
| 12 | Challenge Note Body | Variable | Assemble the monitor-path summary. |
| 11 | Add Challenge Note to Alert | HTTP (S1) | **Challenge:** UAM GraphQL `addAlertNote`. |
| 10 | Notify SOC Slack Challenge | HTTP (Slack) | **Challenge:** Slack summary. *(terminal)* |
| 5 | No Source IP Note Body | Variable | Gap-path note body. |
| 4 | Add No Source IP Note to Alert | HTTP (S1) | Gap path: annotate why nothing fired. *(terminal)* |

**Decision (action 23, OR):** contain when **any** of —
`abuseConfidenceScore >= 50` (independent malicious verdict) **OR**
recomputed `failed_logins >= 20` **OR** `login_successes >= 1` (a login already succeeded from
the attacking IP = foothold). Otherwise apply a **managed challenge** and monitor. AbuseIPDB is
the reliable primary clause; the two SDL clauses (`values[0][*]`) are response-shape dependent,
and both SDL searches plus AbuseIPDB set `continue_on_fail: true` so a parse miss degrades to
the AbuseIPDB-only decision rather than breaking the flow.

**Why parallel enrichment is wired sequentially:** the two S1 searches and the AbuseIPDB lookup
are conceptually parallel enrichment, but they are chained sequentially into the single decision
node. HA convergence (multiple branches merging into one node) is avoided deliberately — the
production corpus rejects back-edges/odd merges at import (`422 "Invalid workflow data"`), so a
linear enrichment chain into one condition is the import-safe idiom.

## Required connections / secrets (configure BEFORE import)

Integration-backed actions need pre-configured console connections — these **cannot** be
created via API. Configure each at **Hyperautomation → Integrations → [name] → Add Connection**,
then (if the JSON's blank `connection_name` isn't auto-resolved) set the connection on each
action after import.

| Integration / secret | Used by | Notes |
|---|---|---|
| **SentinelOne** (ApiToken) | 20 (IOC), 18/11/4 (add-note), 17 (verdict) | Standard S1 Mgmt/UAM connection. |
| **SentinelOne SDL** (Bearer) | 26, 25 (PowerQuery) | **Distinct from the ApiToken connection.** An HTTP action running an SDL query needs the SDL **Bearer** connection, not the ApiToken one (per `s1-development.md`). |
| **Cloudflare** | 22, 21, 13 | API-token connection scoped to the `portal.novamind.ai` zone; provides `{{Connection.zone_id}}`. Needs Firewall/Zone-settings edit rights. |
| **Slack** | 16, 10 | `chat:write` to `#novamind-soc`. |
| **AbuseIPDB API key** | 24 | Free key in the `Key:` header — replace `<ABUSEIPDB_API_KEY>` (or store as a secret Variable). VirusTotal `/api/v3/ip_addresses/{ip}` is a drop-in equivalent. |
| **Platform mailer** | 15 | Built-in `send_email`; verify SMTP-out is enabled. `soc@novamind.ai` is a placeholder — set the real DL. |

## Catalog gaps (no fabricated blocks)

- **No native Cloudflare action in the HA building-blocks catalog.** Cloudflare block / challenge
  / edit-zone are modeled as **integration-backed HTTP requests** (matching the repo's existing
  `hyperautomation/ctf/` house style), with `public_action_id` slugs
  (`cloudflare-create-ip-access-rule`, `cloudflare-edit-zone-setting`). If your tenant has a real
  Cloudflare integration, align these slugs to its action catalog; otherwise convert them to
  `tag: "core_action"` HTTP calls to `api.cloudflare.com` with a bearer token in the header.
- **No per-user Access step-up / session-revoke.** The alert carries no `UserEmail` (HTTP
  Requests dataset), so a targeted Cloudflare Access session revoke isn't possible. The
  zone-wide `security_level = under_attack` escalation (action 21) is the step-up substitute.
- **`setAnalystVerdict` mutation (action 17)** — the exact UAM GraphQL mutation id/enum is
  tenant/version dependent; verify against the console's `unifiedalerts` schema. `continue_on_fail`
  keeps the flow intact if it differs.
- **PowerQuery response paths** (`body.data.values[0][*]`) are the DV `/sdl/api/powerQuery`
  shape; confirm the field path for your SDL connection. The AbuseIPDB clause carries the
  decision if they don't resolve.

## MITRE ATT&CK

- **T1110.004** — Brute Force: Credential Stuffing (Credential Access)
- **T1110.001** — Brute Force: Password Guessing (Credential Access)
- **T1078** — Valid Accounts (surfaced by `login_successes >= 1`, the account-takeover foothold
  signal that forces containment)

## Validation

Validated against the skill's `references/validation-rules.md` with a structural checker
(`json.load` + graph/branch checks). Result: **PASS**.

- 22 actions, `export_id`s unique, every `connected_to.target` resolves.
- Exactly one trigger; `parent_action: null`; non-empty `filter_groups` with all required keys.
- `type` == `action_type` on every action; `state: "active"` everywhere.
- Condition actions are `condition_type: "multi"` with non-null `conditions`, `condition: null`,
  and only `true`/`false` branch handles.
- Integration actions are import-ready: `connection_id: null`, `connection_name: ""`,
  `integration_id: null`, `public_action_id` preserved where meaningful.
- No Variable action defines a `local_var` whose value references another `local_var` set in the
  same action (HARD RULE E1). `pq_failed`/`pq_activity` reference `client_ip` from a **prior**
  action — allowed.
- All note bodies pass through `Function.HTML_ENCODE` (E2). Integration HTTP calls carry
  `retry_on_status_codes: [500]` (E7).
- Graph is fully reachable from the trigger; three terminals (contain=15, challenge=10, no-IP=4).

## Deploy status: PENDING

No `ha_*` MCP tools were reachable and no `S1_CONSOLE_URL` / `S1_CONSOLE_API_TOKEN` were set in
this session, and the sandbox blocks outbound to `*.sentinelone.net`. The workflow is delivered
as validated, import-ready JSON.

### Import + publish (run with a **personal Console User** token — not a service token)

```bash
# 0. Validate creds (URL health + token perm) — see references/api-integration.md
#    GET {S1_CONSOLE_URL}/web/api/v2.1/system  → {"data":{"health":"ok"}}

# 1. Import (lands as a Private Draft owned by the token user)
curl -sS -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/public/workflow-import-export/import?siteIds=2433185103040607397" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data @<(jq '{data: .}' hyperautomation/cred-stuffing/cred-stuffing.workflow.json)
# → capture data.id (workflow_id) and data.version_id

# 2. Activate the version (publish so humans can see/run it)
curl -sS -X POST \
  "$S1_CONSOLE_URL/web/api/v2.1/hyper-automate/api/public/workflows/<workflow_id>/<version_id>/activation?siteIds=2433185103040607397" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" \
  -H "Content-Type: application/json" -d '{"data":{}}'
```

Equivalent MCP path: `ha_import_workflow` (body `{data: <this JSON>}`) → then publish/activate
via the activation endpoint. Re-import creates a **new** workflow — there is no in-place update.

### After publish
1. Bind the 5 connections above to their actions (SentinelOne, SentinelOne SDL, Cloudflare,
   Slack; set the AbuseIPDB key).
2. Confirm the Cloudflare connection is scoped to the `portal.novamind.ai` zone (`zone_id`).
3. Set the real SOC email DL / Slack channel.
4. **Test-run:** trigger a full `attack-scripts/.../04_cred_stuffing.py` run so
   `failed_logins >= 10` and the STAR rule fires, then approve the workflow from the Singularity
   Response console and confirm in **Hyperautomation → Executions**: the enrichment ran, the
   decision branched, and the Cloudflare rule + S1 note landed. (This step is **pending** — not
   run in this session.)
