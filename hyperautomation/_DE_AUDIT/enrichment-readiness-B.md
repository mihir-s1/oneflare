# Alert Entity / Enrichment-Readiness Audit — Set B

Audience: S1 Hyperautomation engineers building alert-response workflows for the OneFlare lab.
Purpose: tell workflow authors which alert fields are REAL and safe to key off, and where
asset binding will fail.

**Method / evidence discipline**
- Rule bodies read from deployed JSON in `detections/` AND re-fetched live from the console
  (`GET /web/api/v2.1/cloud-detection/rules?isLegacy=false`) — **verified**: all four rules
  are `queryType=scheduled`, `status=Active`, `alertPerRow=true`, `threshold {Greater, 0}`.
- Field availability probed live via LRQ (`run_lrq.py`) over 3–7 day windows — **verified**
  where noted below; anything not query-confirmed is marked **inferred**.
- Console/LRQ reachable this session (not Zscaler-blocked).

---

## CRITICAL cross-cutting finding — NO entity mappings, NO asset binding

All four deployed rules return **`entityMappings: null`** (verified live). The rule JSONs
carry only a placeholder key `_entityMappings_pending_feature` (src_ip/host/device_uid),
which the API **does not consume** — it was never applied.

Consequence for HA workflows:
- These scheduled Cloudflare alerts have **no projected S1 entity** → they bind to
  **"Unknown Device" / no Target Asset**. Do not build workflows that assume a resolved
  endpoint/agent (no isolate-endpoint, no agent-scoped action will have a target).
- Verified the underlying events carry no asset identity:
  - HTTP (class_uid **4002**): `device.uid` is **null** on every login/API event
    (live: `group by device.uid` → all `None`).
  - DNS (class_uid **4003**): `device.name` and `device.uid` are **empty strings** on
    Gateway DNS events (live).
- The only reliable cross-scenario pivot is **`src_ip`** (an IP, not an asset). Enrichment
  must be IP-centric (GeoIP, threat-intel/reputation, WHOIS/ASN, Cloudflare block/IP-list),
  not asset-centric. If asset binding is required, the **asset-enrichment solution must run
  first** (`docs/solutions/asset-enrichment.md`) and the rules must be re-deployed with a
  real `entityMappings` array (≤3 cols).

Every alert emits **`detection_time`** as the first column and **`country`**
(src GeoIP, HTTP scenarios) / GeoIP-derivable (DNS) for branching.

---

## 1. CRED — `2519093004283366750` (CF-Access-CredStuffing)

- **class_uid 4002** (HTTP Requests). Fires when one src_ip produces ≥10 `401/403/429`
  responses on a `/login` URI in the window, grouped **by src_ip + host**.
- **Emitted columns:** `detection_time, src_ip, host, failed_logins, distinct_uas,
  sample_status, sample_ua, country, first_seen`.
- **Safe to enrich / branch on:**
  - `src_ip` — primary pivot (IP reputation, ASN/WHOIS, GeoIP, Cloudflare IP-block list).
  - `host` — target FQDN (e.g. `shop.one-flare.com`, `portal…`) — verified login traffic
    hits multiple hosts; use to route by asset owner.
  - `failed_logins`, `distinct_uas` — numeric severity/branch signals (rotating UA = tooling).
  - `country`, `sample_status`, `sample_ua` — triage context.
- **Asset binding:** **Unknown Device** (see cross-cutting finding). No user entity.
- **GAP (important):** the **offending USER is NOT captured — only `src_ip`.** Probed
  `actor.user.name` on `/login` events live → **no populated user identity** returned. So a
  workflow **cannot** disable/step-up a specific account from this alert; it can only act on
  the IP (block/challenge) and the target `host`. If per-user response is required, the
  parser must surface the submitted username (POST body / JWT sub) — not available today.
  Also `distinct_uas` is a per-group estimate, not an enumerable UA list.

## 2. EXFIL — `2519093015733817725` (CF-API-Exfil)

- **class_uid 4002** (HTTP Requests). Scopes to `/api/v1/`; fires per src_ip when
  `sensitive_hits ≥ 10` OR `max_bytes ≥ 1048576`. Grouped **by src_ip**.
- **Emitted columns:** `detection_time, src_ip, host, api_requests, sensitive_hits,
  distinct_paths, max_bytes, largest_uri, country, first_seen`.
- **Safe to enrich / branch on:**
  - `src_ip` — primary pivot (reputation/GeoIP/ASN, block/rate-limit action).
  - `host` — API gateway FQDN (`any()` — single value, safe).
  - `max_bytes` — numeric; already `number()`-cast in-query, safe for volume thresholds.
  - `sensitive_hits`, `distinct_paths`, `api_requests` — numeric branch signals
    (enumeration vs bulk-pull).
  - `largest_uri` — the single biggest-response URI (`max_by(uri,bytes)`); a string for
    triage/route matching, **not** a full URI list.
- **Asset binding:** **Unknown Device.** No user/actor identity on the event.
- **GAP:** no user/API-key/token identity is emitted → cannot revoke a specific credential
  from the alert, only throttle/block the IP and flag the `host`/route. `bytes_out` is only
  the **single largest** response (`max_bytes`), not a summed exfil volume — don't treat it
  as total bytes exfiltrated.

## 3. PROMPTINJ — `2519093028014740613` (CF-AI-PromptInjection)

- **class_uid 4002** (HTTP Requests). `/chat` + `POST`; fires per src_ip on ≥5 chat POSTs.
  Grouped **by src_ip**.
- **Emitted columns:** `detection_time, src_ip, host, injection_posts, distinct_uas,
  sample_uri, sample_ua, country, first_seen`.
- **Safe to enrich / branch on:**
  - `src_ip` — primary pivot (reputation/GeoIP/ASN, block/challenge).
  - `host` — chat endpoint FQDN. `injection_posts`, `distinct_uas` — numeric branch signals.
  - `sample_uri`, `sample_ua`, `country` — triage context.
- **Asset binding:** **Unknown Device.** No user identity.
- **GAP:** volumetric only — **the prompt content / payload is NOT in the alert** (no body
  capture), so a workflow cannot classify jailbreak-vs-benign from alert fields; it can only
  rate-limit/block the IP. No authenticated user surfaced.

## 4. DNS — `2519102258169184569` (CF-Gateway-DNSTunnel)

- **class_uid 4003** (Gateway DNS) — note the class differs from the three HTTP rules (4002).
  Grouped **by src_ip + host + zone**. Uses `unmapped.QueryName` (OCSF `query.hostname`
  is empty for this source — confirmed by rule note).
- **Emitted columns:** `detection_time, src_ip, host, zone, reason, total_queries,
  uniq_labels, long_labels, txt_long, hi_entropy, max_label_len, evidence, device_uid,
  first_seen`.
- **Safe to enrich / branch on:**
  - `src_ip` — primary pivot. `reason` — human-readable classification string
    (DGA / long-label tunnel / TXT exfil) → good branch key.
  - `evidence` — the **full offending QueryName** (`max_by(QueryName,label_len)`), i.e. the
    longest FQDN seen. This is the field to feed a domain-reputation lookup (see gap).
  - Numerics (`total_queries, uniq_labels, long_labels, txt_long, hi_entropy,
    max_label_len`) — severity/branch signals.
- **Asset binding:** **Unknown Device.** Verified live: `device.name` = `''`,
  `device.uid` = `''`, and the emitted `host` (`device.name`) / `device_uid`
  (`any(device.uid)`) columns are therefore **empty** for Cloudflare Gateway DNS. The
  `device_uid` column exists but carries no value → do not key binding on it.
- **GAP (base-domain / registrable-domain for reputation lookup):** the `zone` column is
  computed with a fixed **3-label** regex `([^.]+\.[^.]+\.[^.]+)`. Live probe returned a
  single zone `acmecorp-lab.workers.dev`. Two problems for a domain-reputation lookup:
  1. For **public-suffix** domains (`workers.dev`, `*.azure.com`) the true *registrable*
     domain is `workers.dev` / `azure.com`, but the rule's `zone` is a **subdomain**
     (`acmecorp-lab.workers.dev`) — a naive reputation query on `zone` may miss/misattribute.
  2. The fixed 3-label window mis-slices 2-label domains and >3-label tunnels.
  **Recommendation:** HA workflows should **re-derive the base domain from `evidence`
  (full QueryName) using a public-suffix list**, not trust `zone` verbatim, before any
  domain-reputation / RDAP lookup.

---

## Quick reference for workflow authors

| Scenario | Rule ID | class_uid | Group/pivot | Real entity? | Best enrich key | Hard gap |
|---|---|---|---|---|---|---|
| cred | 2519093004283366750 | 4002 | src_ip+host | Unknown Device | src_ip, host | no offending USER — IP only |
| exfil | 2519093015733817725 | 4002 | src_ip | Unknown Device | src_ip, max_bytes | no credential/user; max_bytes ≠ total |
| promptinj | 2519093028014740613 | 4002 | src_ip | Unknown Device | src_ip | no prompt payload; no user |
| dns | 2519102258169184569 | 4003 | src_ip+host+zone | Unknown Device (device_uid empty) | src_ip, evidence | zone ≠ registrable domain; derive base from `evidence` |

**Bottom line:** build all four workflows **IP-centric**. `src_ip` + `country` + the
scenario numerics are the only fields safe to branch on across the board; `host`/`reason`/
`largest_uri`/`evidence` are safe strings for routing/triage. There is **no user, no
credential, no bound asset** in any alert — do not design account-disable or endpoint-isolate
steps off these alerts until (a) entity mappings are added and asset-enrichment runs, and
(b) the parser surfaces user identity. For DNS, re-derive the base domain from `evidence`
before reputation lookups.
