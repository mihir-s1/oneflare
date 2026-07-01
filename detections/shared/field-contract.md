# OCSF Field Contract — Cloudflare → SentinelOne (for CTF detections)

Source of truth: `parsers/cloudflare-ocsf-parser/cloudflare-ocsf-parser.conf` (v1.6.0) +
`metadata.yaml`. This is the contract every rule in `detections/ctf/` depends on. Confirm against
live schema discovery (`powerquery_schema_discover` on `dataSource.name='Cloudflare'`) before deploy.

The CTF attack (`attack-scripts/campaigns/ctf.py`) generates **HTTP Requests** and **Firewall Events**
Cloudflare Logpush datasets. Both parse to OCSF **HTTP Activity, `class_uid = 4002`,
`category_uid = 4`**, `dataSource.name = 'Cloudflare'`.

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
| `ClientRequestHost` | `http_request.url.hostname` | str | scoping to NovaMind hosts |
| `ClientRequestMethod` | `http_request.http_method` | str | Box3 (POST /chat), Box4 |
| `ClientRequestUserAgent` | `http_request.user_agent` | str | Box1 (scanner UA), Box2, Box3 (JNDI-in-UA) |
| `OriginResponseStatus` | `http_response.status` | str | Box1, Exfil |
| `OriginResponseBytes` | `http_response.body_length` | int | Exfil (response size) |
| `RayID` | `metadata.uid` | str | evidence / chain |
| `SecurityAction` | `action` | str | Box1, Box4 (block/managed_challenge) |
| `SecurityRuleDescription` | `firewall_rule.desc` | str | Box1, Box4 (rule name) |
| `SecurityRuleID` | `firewall_rule.uid` | str | Box1, Box4 |
| `WAFAttackScore` | `risk_score` | int (cast) | Box4 (overall WAF score; wrap in `number()`) |
| `JA4` | `ja4_fingerprint_list[0].value` | str | **Box2 (signature)**, chain pivot |
| `JA3Hash` | `tls.ja3_hash.value` | str | Box2 (secondary) |
| `WorkerScriptName` | `actor.process.name` | str | scoping to Pyxis worker |
| `EdgeStartTimestamp` | `time` / `start_time` | datetime | windowing |

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

## Unmapped fields — TO-VERIFY (NOT in parser v1.6.0)

These are emitted by the CTF attack / Cloudflare but the parser does not rename them. With the
parser's `rename_tree → unmapped` they SHOULD be queryable under `unmapped.<Field>`, but the exact
promoted name/casing is **unconfirmed**. Do not treat as ground truth — run schema discovery.

| Cloudflare raw field | Expected queryable name (TO-VERIFY) | Used by | Fallback if absent |
|---|---|---|---|
| `BotScore` | `unmapped.BotScore` (int — wrap `number()`) | Box2 | rely on JA4 grouping alone |
| `BotScoreSrc` | `unmapped.BotScoreSrc` | Box2 | n/a |
| `BotDetectionTags` | `unmapped.BotDetectionTags` (array: `['scraper','python']`) | Box2, Box3 | UA-pattern match |
| `FirewallForAIInjectionScore` | `unmapped.FirewallForAIInjectionScore` (int) | Box3 | payload-text S1QL on URL/UA |
| `AISecurityInjectionScore` | `unmapped.AISecurityInjectionScore` (int) | Box3 | payload-text S1QL |
| `WAFSQLiAttackScore` | `unmapped.WAFSQLiAttackScore` (int) | Box4 | `risk_score` + SQLi markers |
| `WAFRCEAttackScore` | `unmapped.WAFRCEAttackScore` (int) | Box4 | `risk_score` + RCE markers (`jndi:`,`ognl`) |
| `WAFXSSAttackScore` | `unmapped.WAFXSSAttackScore` (int) | Box4 | `risk_score` + XSS markers |

**Recommended remediation (coordinate with `s1-log-parser-engineer`):** extend the Cloudflare parser
to promote these to stable fields, e.g. a `cloudflare.bot.*` / `cloudflare.waf.*` / `cloudflare.ai.*`
extension namespace, or map the AI injection score onto `risk_score` for the chat dataset. Until then,
every rule depending on a TO-VERIFY field also ships a payload-text fallback clause so it still fires.

## The CTF flag constant (verbatim, from ctf.py)

```
JA4 = t13d1812h1_85036bcba153_b26ce05bbdd6
```

This is the Python `requests` TLS fingerprint. It is **constant** across all CTF boxes regardless of
the rotating User-Agent — that invariance is exactly what Box 2 detects and what ties all 4 boxes to
one actor.

## NovaMind recon / sensitive paths (from ctf.py RECON_PATHS / BREAKOUT_ENDPOINTS)

Sensitive-file probes: `/.env`, `/.env.production`, `/.env.local`, `/.git/HEAD`, `/.git/config`,
`/.aws/credentials`, `/config.json`, `/secrets.json`, `/.DS_Store`.
Forced-browse / API recon: `/api/v1/admin` (always 401), `/api/v1/users`, `/api/v1/training-data`,
`/api/v1/models`, `/actuator/env`, `/admin`, `/admin/config`, `/phpmyadmin`, `/wp-login.php`.
Exfil targets: `/api/v1/training-data`, `/api/v1/models?include_weights=true`,
`/api/v1/customers/export`, `/api/v1/billing`.
Pyxis AI target: `POST /api/v1/chat` (model `pyxis-chat-v2`).
</content>
