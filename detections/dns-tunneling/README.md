# DNS Tunneling / C2 Beaconing — Cloudflare Gateway DNS

Scheduled PowerQuery detection for OneFlare **scenario 05**
(`attack-scripts/scenarios/05_dns_tunnel.py`). Behaviour-based — it does **not**
hard-code `acmecorp-lab.workers.dev`; it keys on label length, digit-ratio
("entropy" proxy), unique-subdomain volume per zone, and TXT-with-long-label.

| File | Purpose |
|---|---|
| `dns-tunneling.hunt.pq` | Ad-hoc hunt. One row per (source, zone) with computed length/entropy/unique-count + sample labels (uses arrays for eyeballing). |
| `dns-tunneling.detection.pq` | Alert-safe scheduled-rule body (no arrays/subqueries). One row per finding. |
| `dns-tunneling.rule.json` | `POST /cloud-detection/rules` payload (scheduled, queryLang 2.0), JSON-escaped, with `entityMappings`. |

## What it catches (the three attack patterns)

1. **DGA beaconing** — ~20 A queries with random 12–24 char labels under
   `c2tunnel|beacon|update.acmecorp-lab.workers.dev`. Caught by `uniq_labels`
   (distinct leftmost labels under one zone) and `hi_entropy`.
2. **Data-in-DNS exfil** — TXT queries whose leftmost label is base32 data
   (each chunk ~20 chars). Caught by `txt_long` = TXT with leftmost label ≥ 20.
3. **Long-label tunneling (dnscat2/iodine)** — A queries with 40–60 char labels.
   Caught by `long_labels` (count of ≥40-char labels) gated by `uniq_labels`.

The three C2 prefixes all roll up to a single **zone** = the rightmost 3 labels
of the FQDN (`acmecorp-lab.workers.dev`), so the signal does not fragment across
`beacon.*` / `update.*` / `c2tunnel.*`.

## Exact fields used (verified from a live SDL export)

- `class_uid = 4003` (DNS Activity) + `dataSource.cloudflare_dataset = 'Gateway DNS'` — initial filter.
- **`unmapped.QueryName`** = the queried FQDN. **GOTCHA:** the OCSF `query.hostname`
  field is **empty** in this tenant — querying it returns zero rows. Always use
  `unmapped.QueryName`.
- `query.type` — A / AAAA / TXT (matched case-insensitively via `in:anycase`).
- `src_endpoint.ip`, `device.name`, `device.uid` — source identity / asset binding.
- `timestamp` — `oldest()` / `newest()` for the detection window.

Derived (all scalar, alert-safe — no bracket-indexed fields, no arrays in the rule body):
`label` = leftmost label (`replace(fqdn,'\.*','')`), `zone` = rightmost-3 labels,
`label_len` = `len(label)`, `digit_ratio` = digits / length (entropy proxy).
`actor.authorizations[0].policy.name` is deliberately **not** used — bracket-indexed
array fields can 500 in `group`/`columns`.

## Thresholds (and why)

Fires when ANY of these branches is true for a (source, zone) in the lookback
window. **Every branch requires *clustering*, not a single weak signal** — see the
Live validation note below for why:

| Branch | Condition | Rationale |
|---|---|---|
| DGA / beaconing | `uniq_labels >= 15` | ~20 distinct random subdomains under one zone; benign hosts rarely hit 15 distinct labels under a single registered zone in an hour. Strong enough to stand alone. |
| Long-label tunneling | `long_labels >= 5 AND uniq_labels >= 5` | dnscat2/iodine chunk data across **many long, unique** labels. Requiring ≥5 long **and** ≥5 unique kills the "one legit long SaaS label" false positive. |
| Data-in-DNS exfil | `txt_long >= 3` | Base32 exfil emits multiple long-label TXT queries; DKIM/ESNI put the long data in the **response**, not the query name, so they don't trip this. |
| High-entropy cluster | `hi_entropy >= 10 AND uniq_labels >= 5` | Automated digit-mixed labels, gated by variety so a single repeated hashed label can't accumulate. |

**`max_label_len` is intentionally NOT a trigger** — it is emitted as an evidence
column only. A DNS label is capped at **63 chars by spec**, so a lone long label
tops out around 63 and cannot be distinguished from a legit long SaaS/CDN host.

## Live validation (2026-07-07)

Ran the hunt against real Gateway DNS data in the SDL (10-min window, 75 raw
events). **Two rows returned** — a textbook true positive and false positive:

| src_ip | host | zone | total | uniq | max_len | long | txt | verdict |
|---|---|---|---|---|---|---|---|---|
| 104.28.153.15 | – | `acmecorp-lab.workers.dev` | 33 | **33** | 58 | **10** | **3** | ✅ **True positive** — the scenario. uniq==total (every query unique ⇒ DGA), 10 long tunnel labels, 3 base32 TXT exfil. Multiple independent branches fire. |
| 104.28.173.219 | DESKTOP-7D4RCAM | `saas.atlassian.com` | 2 | 1 | 61 | 2 | 0 | ⚠️ **False positive** — only under the *old* thresholds. A single legit Atlassian host with a 61-char label, queried twice (A+AAAA). |

**What the FP taught us:** the old `max_label_len >= 50` clause fired on Atlassian
(61-char label) with zero corroboration. Fix: drop the standalone long-label
clause; require long-label tunneling to show **≥5 long AND ≥5 unique** labels.
Re-checked against both real rows: attack → **ALERT**, Atlassian → **clear**. A
heavier benign SaaS user (4 long/4 unique) also stays clear.

Earlier static simulation against the raw attack payloads scored the malicious
group `uniq=33, long=10, maxLen=54, txtLong=3, hi=29` — consistent with the live TP.
Benign domains (`time.cloudflare.com`, `google`, `github`) did not fire.

### Tuning

- Raise `uniq_labels` / `hi_entropy` if a chatty legit host with many hashed CDN
  labels (Akamai/CloudFront style) produces noise. Because those labels are usually
  < 40 chars and appear under a different zone per vendor, they rarely clear the
  clustering thresholds — but if they do, lift `hi_entropy` to 15 first (it's the
  softest signal), keep `long_labels`/`txt_long` where they are.
- For a busier tenant, keep `runIntervalMinutes == lookbackWindowMinutes` (60/60)
  to avoid overlapping/duplicate alerts.
- If the group intermediate ever approaches the 1,000-row alert budget, tighten the
  initial filter (e.g. add `query.type in ('A','AAAA','TXT')`).

## FP risks

- **Legit long/hashed CDN or ESNI labels.** This is the real, *observed* FP class
  (see Live validation — `saas.atlassian.com`). Mitigated by requiring *clustering*
  (≥5 long **and** ≥5 unique labels / ≥10 high-entropy) rather than a single
  occurrence, and by grouping per registered-zone so a single vendor label doesn't
  accumulate. `max_label_len` alone never triggers.
- **DoH/DoT resolvers or telemetry hosts** that query many subdomains. Mitigated by
  the digit-ratio + length gates; pure-word subdomains (no digits, short) don't count.
- Verdict discipline: an alert here is **SUSPICIOUS — Pending Confirmation**, not a
  confirmed TP. Confirm the zone via threat-intel (domain age/attribution) before
  escalating.

## MITRE mapping

- **T1071.004** — Application Layer Protocol: DNS (C2 over DNS / beaconing).
- **T1048** — Exfiltration Over Alternative Protocol (data-in-DNS via TXT).
- Related: **T1568.002** — Dynamic Resolution: Domain Generation Algorithms.

## Asset binding

Scheduled rules do **not** auto-bind — the rule sets `entityMappings` on the
projected `src_ip`, `host`, and `device_uid` columns (≤3, per the rules file).
Cloudflare DNS events do not natively carry the console agent id, so **run the
asset-enrichment solution first** (`docs/solutions/asset-enrichment.md`) to
populate `device.uid`; until then the alert fires but shows "Unknown Device", and
the analyst pivots on `src_ip` / `host`. Coordinate with `s1-platform-engineer`.

---

## Deploy & validate (run on-tenant — no S1 creds in this environment)

> This repo has **no SentinelOne credentials / s1-secops-mcp tools wired up**
> (only Cloudflare MCP), so the queries below were **not** run live here. The
> logic was statically validated against the syntax reference and simulated
> against the attack payloads. Run these on the tenant to execute.

### 1. Validate the hunt (LRQ / MCP)

Via the MCP tool:
```
powerquery_run(query="<contents of dns-tunneling.hunt.pq>",
               start="2026-07-07T00:00:00Z", end="2026-07-07T06:00:00Z")
```
Or raw LRQ (three-call launch/poll/cancel; echo `X-Dataset-Query-Forward-Tag`):
```bash
curl -s -X POST "$S1_CONSOLE_URL/sdl/v2/api/queries" \
  -H "Authorization: Bearer $S1_CONSOLE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"queryType":"PQ","tenant":true,
       "startTime":"2026-07-07T00:00:00Z","endTime":"2026-07-07T06:00:00Z",
       "queryPriority":"HIGH",
       "pq":{"query":"<hunt PQ, escaped>","resultType":"TABLE"}}'
# capture {id} + X-Dataset-Query-Forward-Tag, then:
#   GET  $S1_CONSOLE_URL/sdl/v2/api/queries/{id}?lastStepSeen=0   (poll every 1-2s)
#   DELETE $S1_CONSOLE_URL/sdl/v2/api/queries/{id}
```
On 0 rows: check `matchCount` vs row count and widen the window last; confirm
`unmapped.QueryName` is populated (NOT `query.hostname`).

> **Must be a Scheduled rule.** This body is PowerQuery (it uses `|` pipes and
> aggregation — `group` / `count` / `estimate_distinct`). A single-event **STAR**
> rule validates as S1QL and rejects the pipe with *"Don't understand [|] — try
> enclosing it in quotes."* The SDL search box runs it fine (PowerQuery), but the
> rule must be created with `queryType:"scheduled"` + `queryLang:"2.0"` (as in
> `dns-tunneling.rule.json`). Rule of thumb: query has a `|` → Scheduled rule;
> no pipes (one event matches a filter) → STAR/single-event.

### 2. Create the rule

Replace `<ACCOUNT_ID>` in `dns-tunneling.rule.json`, then:
```bash
curl -s -X POST "$S1_CONSOLE_URL/web/api/v2.1/cloud-detection/rules" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data @detections/dns-tunneling/dns-tunneling.rule.json
# capture data.id from the response (authoritative)
```

### 3. Enable + poll until Active

```bash
curl -s -X PUT "$S1_CONSOLE_URL/web/api/v2.1/cloud-detection/rules/enable" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filter":{"ids":["<RULE_ID>"]}}'

# poll (isLegacy=false is MANDATORY or scheduled rules return 0):
curl -s "$S1_CONSOLE_URL/web/api/v2.1/cloud-detection/rules?ids=<RULE_ID>&accountIds=<ACCOUNT_ID>&isLegacy=false" \
  -H "Authorization: ApiToken $S1_CONSOLE_API_TOKEN"
# proceed only when data[0].status == "Active" (activation lag up to ~60 min,
# then evaluates on the runIntervalMinutes cadence).
```

### 4. End-to-end test

Run `attack-scripts/scenarios/05_dns_tunnel.py` (with `CF_GATEWAY_DOH_URL` set so
queries hit Gateway), wait one run interval after the rule is Active, and confirm a
`CF-Gateway-DNSTunnel` alert appears. Hand the confirmed detection to
`s1-hyperautomation-engineer` for the `Gateway-DNSTunnel-Sinkhole` response flow.
