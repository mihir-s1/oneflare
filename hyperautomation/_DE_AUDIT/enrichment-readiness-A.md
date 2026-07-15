# Alert Entity / Enrichment-Readiness Audit — WAF + Bot scenarios (Set A)

**For:** HA workflow engineers building alert-response automations.
**Scope:** sqli, xss, traversal, bot scheduled STAR rules.
**Author:** s1-detection-engineer. **Date:** 2026-07-15.

## Evidence basis (what was VERIFIED live vs inferred)
- **VERIFIED (live, `ApiToken` GET `/web/api/v2.1/cloud-detection/rules?isLegacy=false`):** all four
  rules are `status=Active`; **`entityMappings == null`** on every one (both at rule level and inside
  `scheduledParams`); `alertPerRow=true`; alert counts below.
- **VERIFIED alert history:** sqli `generatedAlerts=3` (last 2026-07-14T19:07Z), xss `=6`
  (2026-07-15T04:10Z), traversal `=10` (2026-07-15T02:36Z), **bot `=0` — never fired**.
- **INFERRED (from rule JSON `scheduledParams.query`):** the emitted columns, field types, and
  enrichment semantics below. Column names are the literal `| columns …` projection.
- Did NOT sample a materialized alert object, so the exact alert-payload key path HA reads each column
  under (e.g. top-level vs a `columns`/`row` envelope) is not confirmed — HA engineers should read one
  real alert JSON before hard-coding paths. The **column NAMES** are authoritative.

---

## Cross-cutting facts (apply to ALL four)

1. **Asset binding = "Unknown Device". CONFIRMED.** `entityMappings` is `null` on all four deployed
   rules. The `_entityMappings_pending_feature` block in the repo JSON is an inert placeholder key — it
   was never sent as live `entityMappings`. Even if it were, Cloudflare HTTP-Requests events carry **no
   `device.uid` / `user.uid`**, only a source (attacker) IP. Per the asset-binding caveat in
   s1-development.md, these alerts bind to **Unknown Device** and have **no Target Asset**. Asset
   enrichment solution has NOT been run for these.
   - **HA impact:** Do NOT key workflows off the S1 Target Asset / endpoint entity — it will be empty.
     No agent-side actions (isolate host, network-quarantine, kill process) are possible. Response must
     be **network-edge only** (Cloudflare block/challenge on `src_ip` / `host`) plus notify/ticket.
2. **`alertPerRow=true`** → one alert per output row = per group key (`src_ip`+`host`+`country`, or
   `src_ip` for bot). Each alert is already one attacking source. HA can treat `src_ip` as the primary
   pivot without de-duping across rows.
3. **`src_ip` is the attacker's public client IP** (`src_endpoint.ip`), NOT an internal asset. It is the
   correct and only safe key for blocklist / rep-lookup / GeoIP actions.
4. **No user entity in any rule** — all four are pre-auth WAF/edge traffic. Any workflow step expecting a
   username/identity will get nothing.
5. **`sample_uri` / `sample_ua` are single representatives** (`any()` / `max_by()`), not the full set.
   Safe to display / branch coarsely; do NOT treat as the complete list of URIs/UAs the source used.

---

## 1. sqli — `2519092985434164473` (CF-WAF-SQLi)
**Emitted columns:** `detection_time, src_ip, host, country, attack_requests, lowest_score, sample_uri,
sample_ua, first_seen`
**entityMappings:** none (Unknown Device). **Alerts:** 3 (live).

| Field | Type | HA use |
|---|---|---|
| `src_ip` | string (public IP) | **primary key** — rep/GeoIP/TI lookup, Cloudflare IP block/challenge |
| `host` | string (`shop.…` hostname) | which property to scope the Cloudflare action to |
| `country` | string (ISO country) | geo-branch / allow-list logic |
| `attack_requests` | int (count) | severity/volume branch |
| `lowest_score` | int 1–20 | confidence branch (lower = worse) |
| `sample_uri` | string | display / regex-tag the injection; single sample only |
| `sample_ua` | string | tool fingerprint; single sample only |
| `first_seen` | epoch/ts | dwell-time context |

**Safe to enrich/branch on:** `src_ip`, `host`, `country`, `attack_requests`, `lowest_score`.
**Gaps:** no asset/user; `sample_uri`/`sample_ua` non-exhaustive.

## 2. xss — `2519092991281024296` (CF-WAF-XSS)
**Emitted columns:** identical set to sqli: `detection_time, src_ip, host, country, attack_requests,
lowest_score, sample_uri, sample_ua, first_seen`.
**entityMappings:** none (Unknown Device). **Alerts:** 6 (live).
Field semantics + HA guidance identical to sqli (score is `WAFXSSAttackScore`, same 1–20 band).
A shared HA workflow can consume sqli + xss with the **same column contract**.

## 3. traversal — `2519092998092573998` (CF-WAF-Traversal)
**Emitted columns:** `detection_time, src_ip, host, country, attack_requests, waf_hits, path_hits,
lowest_score, sample_uri, sample_ua, first_seen`
**entityMappings:** none (Unknown Device). **Alerts:** 10 (live).
Superset of sqli/xss + two extra:
- `waf_hits` (int) — count of rows that fired via the ML RCE score band.
- `path_hits` (int) — count of rows that fired via literal markers (`/etc/passwd`, `../`, `%2e%2e`).
  Use `waf_hits` vs `path_hits` to branch "ML-scored" vs "raw-signature" response.

**GAP — `lowest_score` can be NULL/absent.** The rule fires on `(rce_score 1–20) OR (path marker)`. On a
**pure path-marker** hit there is no RCE score, so `lowest_score` (min over a nulled `number()`) may be
null/empty. **HA must null-guard `lowest_score`** before any numeric compare — branch on `path_hits>0`
instead when the score is missing.

## 4. bot — `2523842940840264774` (CF-Bot-Scraper)
**Emitted columns:** `detection_time, src_ip, host, bot_requests, min_botscore, avg_botscore,
distinct_paths, sample_ua, country, first_seen`
**entityMappings:** none (Unknown Device). **Alerts:** 0 — **has never fired.**

| Field | Type | HA use |
|---|---|---|
| `src_ip` | string | primary key (grouped by `src_ip` ONLY — no host/country in group key) |
| `host` | string (`any()`) | representative hostname, not part of the key |
| `bot_requests` | int (≥20) | volume branch |
| `min_botscore` / `avg_botscore` | number (≤29) | confidence branch (lower = more bot) |
| `distinct_paths` | int **estimate** (`estimate_distinct`) | crawl-breadth signal — **approximate, do not use for exact-equality thresholds** |
| `sample_ua` | string | automation UA fingerprint; single sample |
| `country`, `first_seen` | string / ts | context |

**GAPS (bot-specific):**
- **0 alerts ever generated** → HA workflows for this scenario are **untested against real payload**.
  Fire a synthetic/attack run before trusting field paths.
- **Scope mismatch:** query filters `http_request.url.hostname contains "soledrop.co"` and
  `dataSource.name='Cloudflare'`, but the rule name says "against NovaMind". On a `novamind.ai`-only
  tenant this rule matches nothing — that likely explains the 0 alerts. Flag to the DE owner; HA can't
  fix it but should know the scenario surface is `soledrop.co`.
- Group key is `src_ip` only (unlike the WAF rules) → `host`/`country` are `any()` samples, so a single
  IP hitting two hosts collapses to one alert with one representative host.
- `distinct_paths` is a HyperLogLog estimate — fine for "breadth" branching, wrong for exact counts.

---

## Bottom line for HA engineers
- **Common contract:** every alert gives you `src_ip` + `host` + `country` + `sample_uri`/`sample_ua` +
  a volume count + a score. Build responses on **`src_ip` (Cloudflare edge block/challenge on `host`)**,
  never on an S1 asset.
- **No Target Asset, no user, no endpoint** on any of the four — Unknown Device is expected, not a bug;
  it will stay that way until the asset-enrichment solution is run and live `entityMappings` are added.
- **Null-guard `traversal.lowest_score`; treat `bot.distinct_paths` as approximate; bot rule is
  unvalidated (0 alerts) and scoped to soledrop.co, not novamind.ai.**
