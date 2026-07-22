# CF1 — Alert Datapaths for Hyperautomation (Detection-Engineer audit)

**Purpose:** exact, copy-pasteable Hyperautomation reference expressions for every field each of the
7 Cloudflare alert-response playbooks can read, so multiple Cloudflare actions (not just "block IP")
can be fed real values. Derived from the 7 deployed `scheduled` detections in `detections/` and the
proven read pattern in `hyperautomation/cred-stuffing/cred-stuffing.workflow.json` +
`hyperautomation/ctf/ctf-campaign.workflow.json`.

Do **not** change detections to consume this — where a field is missing I give the minimal
`entityMappings`/query fix, but the workflow-side re-query path already covers almost everything
without touching the detection.

---

## The two datapaths that exist on a Cloudflare alert (read this first)

Cloudflare OCSF alerts are **thin**. There are exactly two ways to get a field into a workflow:

### Datapath A — directly off the alert trigger (`singularity-response-trigger.data.*`)
Only these are reliably populated on a Cloudflare scheduled-rule alert:

| Ref expression | Meaning | Reliability |
|---|---|---|
| `{{singularity-response-trigger.data.asset.name}}` | **The FIRST `entityMappings` column of the firing rule.** In all 7 deployed rules column 1 is `src_ip`, so this is the **attacker IP**. | PRESENT (primary datapath) |
| `{{singularity-response-trigger.data.id}}` | Alert / threat id (for notes, status, verdict actions) | PRESENT |
| `{{singularity-response-trigger.data.name}}` | Rule name (tells you which scenario fired → lets you hardcode the static host/path) | PRESENT |
| `{{singularity-response-trigger.data.scopeId}}` / `.scopeName` | Site scope | PRESENT |
| `{{singularity-response-trigger.data.observables[0]...}}` | — | **EMPTY on CF alerts** (author-verified). Do not use. |
| `{{singularity-response-trigger.data.indicators[0].value}}` | — | **EMPTY on CF alerts.** Do not use. |
| 2nd / 3rd `entityMappings` columns (host, country, device_uid, …) | — | **NOT addressable** as a distinct trigger variable. `asset.name` only ever exposes column 1. Get these via Datapath B. |

> Every workflow reads the attacker IP as
> `real_ip = {{Function.DEFAULT(singularity-response-trigger.data.asset.name, "0.0.0.0")}}`
> (with a `demo_override` literal for demos). Keep that pattern.

### Datapath B — the enrichment RE-QUERY (how everything else is obtained)
Each workflow already runs a **`Create Power Query`** action whose body (`pq_query`, defined in
`Set Context`) re-queries the **same OCSF logs filtered by the attacker IP**, returns rows inline in
`create-power-query.body.data.data`, and `Extract Enrichment` reads any column **positionally**:

```
# string field:
{{Function.DEFAULT(Function.JQ(create-power-query.body.data.data, "(.[0] // [])[N] | values", true), "N/A")}}
# numeric field (add | floor):
{{Function.DEFAULT(Function.JQ(create-power-query.body.data.data, "(.[0] // [])[N] | values | floor", true), "N/A")}}
```

`N` = zero-based position in the `pq_query`'s `columns` list. **You control `pq_query`,** so any OCSF
field present on the source logs can be projected and fed to a Cloudflare action. This is the real
mechanism for host / URI / method / JA3 / bytes / UA / RayID / queried-domain — none of them need a
detection change; they need a column added to the enrichment `pq_query`.

**OCSF field reference (from `detections/shared/field-contract.md`, live-verified v1.6.0):**

| Cloudflare-action needs | OCSF field to project (class 4002 HTTP) | Notes |
|---|---|---|
| attacker IP | `src_endpoint.ip` | also = `asset.name` (Datapath A) |
| target HOST | `http_request.url.hostname` | or hardcode — static per scenario |
| URI path | `http_request.url.path` (path) / `http_request.url.url_string` (path+query, carries payload) | |
| HTTP method | `http_request.http_method` | |
| JA3 hash | `tls.ja3_hash.value` | flat, queryable (JA4 array is NOT PQ-addressable) |
| bytes | `http_response.body_length` (int) or `number(unmapped.EdgeResponseBytes)` (str) | |
| user-agent | `http_request.user_agent` | |
| RayID | `metadata.uid` | evidence chain / CF log correlation |
| country | `src_endpoint.location.country` | |
| queried domain (DNS only) | `unmapped.QueryName`, derived `zone`, `query.type` | class 4003 only |
| username/email | — | **NOT in Cloudflare HTTP logs** (submitted creds live in the POST body, unlogged). Needs Access Audit logs, class_uid 3002 → `actor.user.email_addr` / `user.name`. Separate detection + data source. |

---

## Per-scenario datapaths

Legend for the action matrix: **A** = direct trigger, **B** = enrichment re-query (project the OCSF
field, then JQ-index), **N/A** = not meaningful for this log class, **GAP** = needs a detection/query
change (spelled out).

---

### 1. CF-Access-CredStuffing — `detections/cred-stuffing/cred-stuffing.rule.json`
- **Class:** 4002 (HTTP Requests). **entityMappings:** `[src_ip, host]` → `asset.name = src_ip`.
- **Rule columns:** `detection_time, src_ip, host, failed_logins, distinct_uas, sample_status, sample_ua, country, first_seen`.
- **Direct (A):** attacker IP = `{{singularity-response-trigger.data.asset.name}}`.
- **Recommended enrichment `pq_query` columns** (re-query `class_uid=4002 ... | filter src_ip=…`):
  `src_ip[0], failed_logins[1], distinct_uas[2], hosts[3], country[4]` — matches the shipped workflow.

| CF-action field | Status | Ref |
|---|---|---|
| attacker IP | A | `{{singularity-response-trigger.data.asset.name}}` |
| target HOST | B / static | project `host=any(http_request.url.hostname)` → JQ `[3]`; or hardcode `portal.soledrop.co` |
| user-agent | B | project `sample_ua=any(http_request.user_agent)` → JQ index |
| country | B | JQ `[4]` in shipped query |
| URI path | B | scope is `/login`; project `any(http_request.url.url_string)` if you need the exact path |
| HTTP method | B | project `any(http_request.http_method)` (POST expected) |
| RayID | B | project `any(metadata.uid)` |
| JA3 hash | B | project `any(tls.ja3_hash.value)` — usable for a JA3 WAF block |
| bytes | N/A | login responses are small; not meaningful |
| queried domain | N/A | HTTP scenario |
| **username / email** | **GAP** | **NOT-AVAILABLE.** Cloudflare HTTP logs don't carry the submitted username. Fix: add a companion detection on **Access Audit logs (class_uid 3002)** projecting `actor.user.email_addr` (or `user.name`) as an `entityMappings` column; then read via `asset.name` on that rule. Not fixable inside this HTTP rule. |

**Best CF actions here:** block IP (A), throttle/managed-challenge `portal.soledrop.co /login` (static host), optional JA3 block (B).

---

### 2. CF-WAF-WebAttack (SQLi / XSS / Traversal)
Three rules, identical shape: `detections/web-sqli/`, `detections/web-xss/`, `detections/web-traversal/`.
- **Class:** 4002. **entityMappings:** `[src_ip, host, country]` → `asset.name = src_ip`.
- **Rule columns (sqli/xss):** `detection_time, src_ip, host, country, attack_requests, lowest_score, sample_uri, sample_ua, first_seen`.
- **Rule columns (traversal):** `… attack_requests, waf_hits, path_hits, lowest_score, sample_uri, sample_ua, first_seen`.
- **Direct (A):** attacker IP = `asset.name`.
- **Recommended enrichment `pq_query` columns:** `src_ip[0], attack_requests[1], sample_uri[2], sample_ua[3], host[4], country[5], method[6], ray_id[7]` where
  `sample_uri = max_by(http_request.url.url_string, malice)` (the worst payload URL).

| CF-action field | Status | Ref |
|---|---|---|
| attacker IP | A | `{{singularity-response-trigger.data.asset.name}}` |
| **URI path (payload)** | B | project `sample_uri=max_by(http_request.url.url_string, malice)` → JQ `[2]`. This is the attack URL — feed to a WAF path/URI custom rule. |
| target HOST | B / static | `host=any(http_request.url.hostname)` → JQ `[4]`; or hardcode `shop.soledrop.co` |
| HTTP method | B | `method=any(http_request.http_method)` → JQ `[6]` |
| user-agent | B | `sample_ua=any(http_request.user_agent)` → JQ `[3]` |
| country | B | JQ `[5]` |
| RayID | B | `ray_id=any(metadata.uid)` → JQ `[7]` |
| JA3 hash | B | `any(tls.ja3_hash.value)` — usable for JA3 block |
| bytes | N/A | not meaningful for injection |
| queried domain | N/A | HTTP scenario |
| username/email | N/A | unauthenticated storefront traffic |

**Best CF actions here:** block IP (A), WAF custom rule on the exact `sample_uri`/method/host (B), country block (B).

---

### 3. CF-API-Exfil — `detections/data-exfil/data-exfil.rule.json`
- **Class:** 4002. **entityMappings:** `[src_ip, host]` → `asset.name = src_ip`.
- **Rule columns:** `detection_time, src_ip, host, api_requests, sensitive_hits, distinct_paths, max_bytes, largest_uri, country, first_seen`.
- **Direct (A):** attacker IP = `asset.name`.
- **Recommended enrichment `pq_query` columns:** `src_ip[0], sensitive_hits[1], max_bytes[2], largest_uri[3], distinct_paths[4], host[5], method[6], ray_id[7]` where
  `max_bytes=max(number(unmapped.EdgeResponseBytes))` and `largest_uri=max_by(http_request.url.url_string, number(unmapped.EdgeResponseBytes))`.

| CF-action field | Status | Ref |
|---|---|---|
| attacker IP | A | `{{singularity-response-trigger.data.asset.name}}` |
| **URI path (exfil route)** | B | `largest_uri=max_by(http_request.url.url_string, bytes)` → JQ `[3]`. Feed to a WAF rule blocking that `/export`/`/download` path for this IP. |
| **bytes** | B | `max_bytes=max(number(unmapped.EdgeResponseBytes))` → JQ `[2] … | floor`. (Or `http_response.body_length` int.) Drives severity / "large payload" gating. |
| target HOST | B / static | `host=any(http_request.url.hostname)` → JQ `[5]`; or hardcode `api.soledrop.co` |
| HTTP method | B | `method=any(http_request.http_method)` → JQ `[6]` |
| distinct paths | B | JQ `[4]` — enumeration breadth |
| RayID | B | `ray_id=any(metadata.uid)` → JQ `[7]` |
| user-agent | B | `any(http_request.user_agent)` |
| JA3 hash | B | `any(tls.ja3_hash.value)` |
| country | B | `any(src_endpoint.location.country)` |
| queried domain | N/A | HTTP scenario |
| username/email | GAP | API is authenticated, but Cloudflare HTTP logs don't carry the bearer/user identity. If the Worker logs an auth subject into a custom field it would land in `unmapped.*`; otherwise NOT-AVAILABLE (needs the Worker to emit it + a parser mapping). |

**Best CF actions here:** block IP (A), WAF rule blocking the specific exfil route/host (B), rate-limit `/export` (static host+path).

---

### 4. CF-Bot-Scraper — `detections/bot-scraper/bot-scraper.rule.json` (+ polymorphic variant `detections/ai-bot/ai-bot.rule.json`)
- **Class:** 4002. **entityMappings:** `[src_ip, host]` → `asset.name = src_ip`.
- **bot-scraper columns:** `detection_time, src_ip, host, bot_requests, min_botscore, avg_botscore, distinct_paths, sample_ua, country, first_seen`.
- **Direct (A):** attacker IP = `asset.name`.
- **Recommended enrichment `pq_query` columns:** `src_ip[0], bot_requests[1], min_botscore[2], distinct_uas[3], distinct_paths[4], sample_ua[5], host[6], ja3[7]`.

| CF-action field | Status | Ref |
|---|---|---|
| attacker IP | A | `{{singularity-response-trigger.data.asset.name}}` |
| **user-agent** | B | `sample_ua=any(http_request.user_agent)` → JQ `[5]`. UA-block or UA-log for triage. |
| **JA3 hash** | B | `ja3=any(tls.ja3_hash.value)` → JQ `[7]`. The stable actor key when UA rotates — feed a JA3 WAF block. |
| target HOST | B / static | `host=any(http_request.url.hostname)` → JQ `[6]`; or hardcode `shop.soledrop.co` |
| bot score | B | `min_botscore=min(number(unmapped.BotScore))` → JQ `[2] | floor` — severity gate |
| distinct paths | B | JQ `[4]` — crawl breadth |
| URI path | B | `any(http_request.url.path)` |
| HTTP method | B | `any(http_request.http_method)` |
| RayID | B | `any(metadata.uid)` |
| country | B | `any(src_endpoint.location.country)` |
| bytes | N/A | not a volume-exfil signal |
| queried domain | N/A | HTTP scenario |
| username/email | N/A | anonymous scraping |

**Best CF actions here:** block IP (A), managed-challenge / enable Bot Fight on host (static), JA3 WAF block (B).

---

### 5. CF-AI-PromptInjection — `detections/prompt-injection/prompt-injection.rule.json`
- **Class:** 4002. **entityMappings:** `[src_ip, host]` → `asset.name = src_ip`.
- **Rule columns:** `detection_time, src_ip, host, injection_posts, distinct_uas, sample_uri, sample_ua, country, first_seen`.
- **Scope:** `url_string contains '/chat'` AND `http_method='POST'`.
- **Direct (A):** attacker IP = `asset.name`.
- **Recommended enrichment `pq_query` columns:** `src_ip[0], injection_posts[1], distinct_uas[2], sample_uri[3], sample_ua[4], host[5], method[6], ray_id[7]`.

| CF-action field | Status | Ref |
|---|---|---|
| attacker IP | A | `{{singularity-response-trigger.data.asset.name}}` |
| **URI path** | B | `sample_uri=any(http_request.url.url_string)` → JQ `[3]` (the `/api/v1/chat` route). Feed a WAF rule / "Under Attack on chat route" action. |
| **HTTP method** | B | `method=any(http_request.http_method)` → JQ `[6]` (POST — the injection vector). |
| target HOST | B / static | `host=any(http_request.url.hostname)` → JQ `[5]`; or hardcode `api.soledrop.co` |
| user-agent | B | `sample_ua=any(http_request.user_agent)` → JQ `[4]` |
| RayID | B | `ray_id=any(metadata.uid)` → JQ `[7]` |
| JA3 hash | B | `any(tls.ja3_hash.value)` |
| country | B | `any(src_endpoint.location.country)` |
| bytes | N/A | prompt bodies not size-gated here |
| queried domain | N/A | HTTP scenario |
| **prompt text / payload** | GAP | The actual prompt is in the POST body, **not logged** by Cloudflare. `sample_uri` only gives the route, not the jailbreak string. NOT-AVAILABLE unless the Worker echoes the prompt into a logged field (→ `unmapped.*` + parser map). |
| username/email | GAP | Same as API-Exfil — auth subject not in HTTP logs. |

**Best CF actions here:** block IP (A), enable "Under Attack"/WAF on the `/chat` route (B/static), swap model / lock service account (S1-side, not CF).

---

### 6. CF-Gateway-DNSTunnel — `detections/dns-tunneling/dns-tunneling.rule.json`
- **Class:** 4003 (Gateway DNS) — **different log class; HTTP fields do not exist here.**
- **entityMappings:** `[src_ip, host, device_uid]` → `asset.name = src_ip`; `host = device.name`; `device_uid = device.uid` (this rule DOES bind a real asset via `device.uid`).
- **Rule columns:** `detection_time, src_ip, host, zone, reason, total_queries, uniq_labels, long_labels, txt_long, hi_entropy, max_label_len, evidence, device_uid, first_seen`.
- **Direct (A):** attacker IP = `asset.name`.
- **Recommended enrichment `pq_query`** (re-query `class_uid=4003 ... | filter src_ip=…`) columns:
  `src_ip[0], zone[1], evidence[2], total_queries[3], uniq_labels[4], max_label_len[5], query_type[6]`
  where `zone` = registered domain (block target), `evidence = max_by(unmapped.QueryName, label_len)` (worst full FQDN), `query_type = any(query.type)`.

| CF-action field | Status | Ref |
|---|---|---|
| attacker IP | A | `{{singularity-response-trigger.data.asset.name}}` |
| **queried domain (C2 zone)** | B | `zone` → JQ `[1]`. **This is the Gateway-block target** — feed a Cloudflare Gateway DNS policy blocking the domain. |
| **queried FQDN (evidence)** | B | `evidence=max_by(unmapped.QueryName, label_len)` → JQ `[2]`. The full worst subdomain (data-in-DNS). |
| query type (TXT/A/…) | B | `query_type=any(query.type)` → JQ `[6]` |
| device (asset) | A (bound) | rule binds real device via `device.uid`; also `host=device.name` available via re-query |
| target HOST | B | `host=any(device.name)` |
| URI path / method / bytes / UA / RayID / JA3 | N/A | DNS log class — none of these exist on 4003 |
| username/email | N/A | DNS resolver logs have no user identity here |

> **Note on `entityMappings` for the domain:** `zone`/`evidence` are **not** projected as entities
> (the 3 entity slots are full: `src_ip, host, device_uid`). That is fine — the workflow reads the
> domain via Datapath B, no detection change needed. Only if you wanted the domain to appear as the
> **primary alert asset** would you swap a column (e.g. `entityMappings: [zone, src_ip, device_uid]`),
> which is a design change I'm flagging, not making.

**Best CF actions here:** Gateway DNS policy block on `zone` (B), block source IP (A), isolate the bound device (S1-side via `device.uid`).

---

### 7. CF-Campaign-DropDaySwarm — `detections/ctf/box2-polymorphic-ja4.json` (deployed as `CF-Campaign-DropDaySwarm`)
- **Class:** 4002. **The signature is one JA3 fingerprint behind many rotating UAs across many IPs.**
- **Deployed `entityMappings` (per `hyperautomation/ctf/ctf-campaign.workflow.json`): `[src_ip, …]` → `asset.name = src_ip`.** The shipped workflow reads `asset.name` as the attacker IP and pulls **JA3 via the re-query** (`ja3=any(tls.ja3_hash.value)`). (The `box2` draft JSON proposes `entityMappings:[ja3, src_ip]`, i.e. `asset.name = JA3` — that is the alternative binding; the **deployed** contract is `src_ip` first. See GAP note below.)
- **Shipped enrichment `pq_query` columns (verbatim):**
  `src_ip[0], hits[1], distinct_uas[2], ja3[3], distinct_ja3[4], distinct_paths[5], recon_hits[6], injection_hits[7]`.

| CF-action field | Status | Ref |
|---|---|---|
| attacker IP | A | `{{singularity-response-trigger.data.asset.name}}` (this one IP; note the swarm rotates IPs — see JA3) |
| **JA3 hash** | B | `ja3=any(tls.ja3_hash.value)` → JQ `[3]`. **The durable actor key across rotating IPs** — feed a Cloudflare WAF custom rule matching `cf.tls_client_hello_...`/JA3 to block the whole swarm, not one IP. |
| distinct JA3 | B | JQ `[4] | floor` (should be 1 for the swarm — corroboration) |
| distinct UAs | B | JQ `[2] | floor` (the polymorphism) |
| target HOST | B / static | `any(http_request.url.hostname)` — `*.lab.soledrop.co` / `shop.soledrop.co` |
| URI path | B | `distinct_paths` breadth (`[5]`); project `any(http_request.url.url_string)` for exact path |
| user-agent | B | `any(http_request.user_agent)` (rotating — sample only) |
| HTTP method | B | `any(http_request.http_method)` |
| RayID | B | `any(metadata.uid)` |
| country | B | `any(src_endpoint.location.country)` |
| bytes | N/A | not a volume-exfil signal |
| queried domain | N/A | HTTP scenario |
| username/email | N/A | anonymous swarm |

> **GAP / design choice — JA3 as primary asset:** if you want the swarm's **JA3** to be the alert's
> primary entity (so `asset.name = JA3` and a JA3-block action can read it via Datapath A instead of
> re-querying), change the deployed rule's `entityMappings` to `[ja3, src_ip]` (≤3 cols, still valid)
> and add `ja3` as the first `columns` entry. **I am not changing it** — the shipped workflow already
> gets JA3 reliably via Datapath B `[3]`, which is sufficient for a JA3 WAF-block action.

**Best CF actions here:** JA3 WAF custom-rule block (B) — primary, survives IP rotation; block current IP (A); managed-challenge host (static).

---

## Summary table (one row per scenario)

| # | Scenario / rule | Class | `asset.name` (Datapath A) | Key extra fields for CF actions (Datapath B index) | Notable GAP |
|---|---|---|---|---|---|
| 1 | CF-Access-CredStuffing | 4002 | src_ip | host, UA, country[4] | username/email → needs Access Audit class 3002 |
| 2 | CF-WAF-WebAttack (SQLi/XSS/Trav) | 4002 | src_ip | sample_uri[2], method, host, RayID | none (payload URL available) |
| 3 | CF-API-Exfil | 4002 | src_ip | largest_uri[3], max_bytes[2], host, method | auth subject not logged |
| 4 | CF-Bot-Scraper | 4002 | src_ip | sample_ua[5], ja3[7], min_botscore[2] | none |
| 5 | CF-AI-PromptInjection | 4002 | src_ip | sample_uri[3], method[6], host | prompt text (POST body) not logged |
| 6 | CF-Gateway-DNSTunnel | 4003 | src_ip | **zone[1]** (block target), evidence[2], query_type | domain not a primary entity (by design) |
| 7 | CF-Campaign-DropDaySwarm | 4002 | src_ip | **ja3[3]** (swarm key), distinct_ja3[4] | JA3 not primary asset (optional entityMappings swap) |

**Global rule:** attacker IP is always `{{singularity-response-trigger.data.asset.name}}`. Everything
else a Cloudflare action needs comes from the `Create Power Query` → `Extract Enrichment` re-query
(`Function.JQ(create-power-query.body.data.data, "(.[0] // [])[N] | values", true)`); host is also
safely hardcodable per scenario. `observables[]`/`indicators[]` are empty — never read them. The only
truly unavailable fields are **username/email** (HTTP logs don't carry submitted/auth identity → needs
Access Audit class 3002) and **prompt/POST-body text** (never logged by Cloudflare).
</content>
