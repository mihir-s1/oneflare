# OCSF Field Contract — Cloudflare → SentinelOne (for CTF detections)

Source of truth: `parsers/cloudflare-ocsf-parser/cloudflare-ocsf-parser.conf` (v1.6.0) +
`metadata.yaml`, **cross-checked against live `powerquery_schema_discover` output** on a real
tenant (`usea1-partners`, 2026-07-10) — the corrections below are confirmed, not guessed.

The CTF attack (`attack-scripts/campaigns/ctf.py`) generates **HTTP Requests** and **Firewall
events** Cloudflare Logpush datasets, both under `dataSource.name = 'Cloudflare'`, distinguished by
`dataSource.cloudflare_dataset` (`'HTTP Requests'` vs `'Firewall events'`).

> **Multi-tenant note:** a single S1 account can carry *other* Cloudflare integrations (e.g. a
> Gateway/Zero-Trust feed) under the same `dataSource.name='Cloudflare'`. Every query MUST also
> scope on host — for the per-attendee lab, `http_request.url.hostname contains '.lab.soledrop.co'`
> — or it drowns in unrelated traffic.

## Mapped fields (confirmed in parser v1.6.0)

### HTTP Requests dataset (`dataSource.cloudflare_dataset = 'HTTP Requests'`)

| Cloudflare raw field | OCSF field (queryable) | Type | Used by |
|---|---|---|---|
| (constant) | `dataSource.name = 'Cloudflare'` | str | all |
| (constant) | `dataSource.cloudflare_dataset = 'HTTP Requests'` | str | all |
| (constant) | `class_uid = 4002` | int | all (binding/class) |
| `ClientIP` | `src_endpoint.ip` | str | all (entity) |
| `ClientRequestPath` | `http_request.url.path` | str | Box1, Box4, Exfil |
| `ClientRequestURI` | `http_request.url.url_string` | str | Box1, Box3, Box4 (payload-in-URL) |
| `ClientRequestHost` | `http_request.url.hostname` | str | scoping — `contains '.lab.soledrop.co'` |
| `ClientRequestMethod` | `http_request.http_method` | str | Box3 (POST /chat), Box4 |
| `ClientRequestUserAgent` | `http_request.user_agent` | str | Box1 (scanner UA), Box2, Box3 (JNDI-in-UA) |
| `OriginResponseStatus` | `http_response.status` | str | Box1, Exfil |
| `OriginResponseBytes` | `http_response.body_length` | int | Exfil (response size) |
| `RayID` | `metadata.uid` | str | evidence / chain |
| `SecurityAction` | `action` | str | Box1, Box4 (block/managed_challenge) |
| `SecurityRuleDescription` | `firewall_rule.desc` | str | Box1, Box4 (rule name) |
| `SecurityRuleID` | `firewall_rule.uid` | str | Box1, Box4 |
| `WAFSQLiAttackScore` / `WAFRCEAttackScore` / `WAFXSSAttackScore` | `unmapped.WAFSQLiAttackScore` etc. | **str** — cast with `number()` | Box4 (per-category WAF score) |
| `JA3Hash` | `tls.ja3_hash.value` | str | **Box2 (signature)** — use this, not JA4 |
| `JA4` | *(not queryable)* `ja4_fingerprint_list[0].value` | str | **avoid** — PQ can't address the `[0]` array element (bracket errors; dot-index returns null) |
| `WorkerScriptName` | `actor.process.name` | str | scoping to SoleDrop Concierge worker |
| `EdgeStartTimestamp` | `time` / `start_time` | datetime | windowing |

> **⚠️ WAF score direction — confirmed on live tenant:** these scores run 1–99 where **LOWER =
> MORE malicious** (a confirmed SQLi attack scored 8–10; a confirmed RCE/breakout request scored 1;
> clean traffic scored ~97). This is the **opposite** of the intuitive reading — always guard with
> `score > 0 && score <= 20` for "this is an attack," never `>= 90`.

### Firewall Events dataset (`dataSource.cloudflare_dataset = 'Firewall Events'`)

| Cloudflare raw field | OCSF field | Type | Used by |
|---|---|---|---|
| (constant) | `class_uid = 4002` | int | all |
| `ClientIP` | `src_endpoint.ip` | str | entity |
| `ClientRequestPath` | `http_request.url.path` | str | Box1, Box4 |
| `ClientRequestQuery` | `http_request.url.query_string` | str | Box1/Box4 (payload-in-query) |
| `ClientRequestUserAgent` | `http_request.user_agent` | str | Box1, Box3 |
| `ClientRequestMethod` | `http_request.http_method` | str | Box4 |
| `Action` | `action` | str | block/challenge |
| `Description` | `firewall_rule.desc` | str | matched rule |
| `RuleID` | `firewall_rule.uid` | str | matched rule |
| `ClientASN` | `src_endpoint.owner.account.uid` | str | enrichment context |
| `ClientASNDescription` | `src_endpoint.owner.account.name` | str | enrichment context |

## Verified `unmapped.*` fields (confirmed via live schema discovery)

These promote to `unmapped.<Field>` exactly as named, all as **strings** — always wrap numeric ones
in `number()` before comparing/aggregating.

| Cloudflare raw field | Queryable name | Used by | Notes |
|---|---|---|---|
| `BotScore` | `unmapped.BotScore` | Box2 | needs the **Bot Management** entitlement to populate |
| `BotScoreSrc` | `unmapped.BotScoreSrc` | Box2 | e.g. `"Machine Learning"` |
| `FirewallForAIInjectionScore` | `unmapped.FirewallForAIInjectionScore` | Box3 | **higher = worse** (100 seen on a confirmed injection) — opposite direction from the WAF scores above |
| `WAFSQLiAttackScore` | `unmapped.WAFSQLiAttackScore` | Box4 | **lower = worse** (see the score-direction note above) |
| `WAFRCEAttackScore` | `unmapped.WAFRCEAttackScore` | Box4 | **lower = worse** |
| `WAFXSSAttackScore` | `unmapped.WAFXSSAttackScore` | Box4 | **lower = worse** (same family as SQLi/RCE — inferred, not separately fired in validation) |

`BotDetectionTags` / `AISecurityInjectionScore` were **not** observed on the live tenant — if you
need them, run `powerquery_schema_discover` first rather than assuming the name/casing.

## The CTF flag constant (verbatim, from ctf.py)

```
JA4 = t13d1812h1_85036bcba153_b26ce05bbdd6
```

This is the Python `requests` TLS fingerprint. It is **constant** across all CTF boxes regardless of
the rotating User-Agent — that invariance is exactly what Box 2 detects and what ties all 4 boxes to
one actor. **In practice, query on `tls.ja3_hash.value`** (JA4 isn't PQ-addressable per the note
above) — it carries the same one-fingerprint-many-user-agents signal.

## SoleDrop recon / sensitive paths (from ctf.py RECON_PATHS / BREAKOUT_ENDPOINTS)

Sensitive-file probes: `/.env`, `/.env.production`, `/.env.local`, `/.git/HEAD`, `/.git/config`,
`/.aws/credentials`, `/config.json`, `/secrets.json`, `/.DS_Store`.
Forced-browse / API recon: `/api/v1/admin` (always 401), `/api/v1/users`, `/api/v1/training-data`,
`/api/v1/models`, `/actuator/env`, `/admin`, `/admin/config`, `/phpmyadmin`, `/wp-login.php`.
Exfil targets: `/api/v1/training-data`, `/api/v1/models?include_weights=true`,
`/api/v1/customers/export`, `/api/v1/billing`.
SoleDrop Concierge AI target: `POST /api/v1/chat` (model `soledrop-concierge-v2`).
</content>
