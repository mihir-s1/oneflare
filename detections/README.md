# SoleDrop CTF Detections — SentinelOne Custom Detection (STAR) Content

Detection content for the **Operation Agentic AI Breakout** CTF (`attack-scripts/campaigns/ctf.py`)
and the AI / data-exfil scenarios of the ThreatOps merge. Company brand: **SoleDrop**;
rogue agentic AI product under attack: **SoleDrop Concierge** (`POST /api/v1/chat`).

**Status: AUTHOR-ONLY.** Nothing here has been deployed to a live tenant. No credentials assumed.
Every rule body has been authored against the OCSF field contract published by the
`cloudflare-ocsf-parser` (v1.6.0, `parsers/cloudflare-ocsf-parser/`). Field names that the parser
does NOT yet map are marked **TO-VERIFY** and require live-tenant schema discovery
(`powerquery_schema_discover` / `powerquery_enumerate_sources`) before deploy. See the
"Open assumptions" section at the bottom and the per-file `field_contract` blocks.

---

## File tree

```
detections/
├── README.md                          ← this file (index, deploy notes, open assumptions)
├── ctf/
│   ├── box1-recon-sweep.json          ← Box 1: scanner-UA / sensitive-file recon (single-event + scheduled)
│   ├── box2-polymorphic-ja4.json      ← Box 2: constant-JA4 / rotating-UA polymorphic bot (scheduled, SIGNATURE)
│   ├── box3-prompt-injection.json     ← Box 3: Firewall-for-AI prompt injection / jailbreak (single-event + scheduled)
│   ├── box4-agentic-breakout.json     ← Box 4: multi-vector RCE/SSRF/traversal breakout (correlation + scheduled)
│   └── exfil-training-data.json       ← model-weight / training-data / customer export exfiltration (scheduled)
└── shared/
    └── field-contract.md              ← the OCSF field map every rule depends on + TO-VERIFY list
```

Each `*.json` file contains one or more `rules[]` objects. Each rule object carries:
- `name`, `rule_type` (events / correlation / scheduled), `mitre`, `atlas`, `severity`
- `data_source` (the Cloudflare dataset queried)
- `ocsf_fields` (the exact fields used, each tagged mapped / TO-VERIFY)
- `hunt_query` (the PowerQuery hunt to validate the rule from, before wrapping as a rule body)
- `api_body` (the exact `POST /web/api/v2.1/cloud-detection/rules` payload — backslashes already
  double-escaped for JSON)
- `asset_binding` (how the alert binds a Target Asset)
- `deploy` (how-to-deploy note)

---

## Mapping table — box → rule → type → technique → primary signal

| Box / scenario | Rule name | Type | MITRE / ATLAS | Primary signal |
|---|---|---|---|---|
| Box 1 — Recon | `SoleDrop-CTF-Box1-ScannerRecon` | single-event | T1595.002 / AML.T0035 | scanner UA (`Nikto`,`sqlmap`,`Nuclei`…) OR sensitive path (`/.env`,`/.git/HEAD`,`/api/v1/admin`) |
| Box 1 — Recon | `SoleDrop-CTF-Box1-ReconSweep-Fanout` | scheduled | T1595.002 | one `src_endpoint.ip` hitting many distinct sensitive/recon paths in window |
| Box 2 — Bot evasion | `SoleDrop-CTF-Box2-PolymorphicJA4` | scheduled | T1036.005 / T1595.002 | **constant JA4 + many distinct User-Agents** from one fingerprint (the signature detection) |
| Box 3 — Prompt injection | `SoleDrop-CTF-Box3-ConciergePromptInjection` | single-event | AML.T0054 / AML.T0040 / T1190 | Firewall-for-AI injection score high on `POST /api/v1/chat`, OR JNDI/DAN payload markers |
| Box 3 — Prompt injection | `SoleDrop-CTF-Box3-ConciergeInjectionBurst` | scheduled | AML.T0054 / AML.T0040 | N injection-scored chat requests from one source in window |
| Box 4 — Breakout | `SoleDrop-CTF-Box4-AgenticBreakout` | correlation | T1190 / T1119 / T1020 / AML.T0054 | recon-or-injection THEN high-WAF-score RCE/SSRF/traversal from same source |
| Box 4 — Breakout | `SoleDrop-CTF-Box4-MultiVectorStorm` | scheduled | T1190 / T1213 | one source firing multiple distinct WAF attack classes (RCE+SQLi+XSS+traversal+SSRF) |
| Exfil | `SoleDrop-Exfil-TrainingData-ModelWeights` | scheduled | T1020 / T1213 / AML.T0035 / AML.T0024 | large/bulk responses on `/api/v1/training-data`, `/models?include_weights`, `/customers/export` |

The 4 boxes are designed to chain on a shared pivot: **same `src_endpoint.ip` + same
`ja4_fingerprint_list[0].value` (`t13d1812h1_85036bcba153_b26ce05bbdd6`)** ties recon → bot evasion
→ prompt injection → breakout into one actor. The constant-JA4 value is the CTF "flag".

---

## How to deploy (all rules) — author-only summary

All rules are created with the same endpoint and listed with the same param:

```
POST /web/api/v2.1/cloud-detection/rules        # body = the per-rule api_body
PUT  /web/api/v2.1/cloud-detection/rules/enable # {"filter": {"ids": ["<id>"]}}
GET  /web/api/v2.1/cloud-detection/rules?ids=<id>&isLegacy=false   # poll until status == "Active"
```

- `queryLang` is always `"2.0"`.
- single-event rules: `queryType:"events"`, body in `data.s1ql` (boolean S1QL, **no pipes**).
- correlation rules: `queryType:"correlation"`, body in `data.correlationParams`, `s1ql:""`.
- scheduled rules: `queryType:"scheduled"`, PowerQuery body in `data.scheduledParams.query`,
  `treatAsThreat:"UNDEFINED"`, `networkQuarantine:false`, plus `data.entityMappings`.
- New rules land Draft → enable → they go `Activating` then `Active` within ~1h. Scheduled rules
  additionally only evaluate on their `runIntervalMinutes` cadence; wait one full interval before
  judging them. **Always list with `isLegacy=false`** or scheduled/correlation rules silently return 0.
- Scope each rule via `filter.accountIds` (or `siteIds`) — left as `["<accountId>"]` placeholders.

### Backslash-escaping convention in these files (read before deploying)

The `s1ql` / `subQuery` / `scheduledParams.query` strings in the `api_body` blocks hold **single**
backslashes in their regexes (`\b`, `\$`, `\{`) — i.e. exactly what you get after `json.load`-ing
these files. When you POST a rule, your HTTP client's JSON serializer (`requests(json=...)`,
`json.dumps`, or the MCP `s1_api_post` tool) re-doubles each backslash on the wire to `\\b`, which is
the doubled form SentinelOne expects; the detection engine then receives one backslash — the contract
in `.claude/rules/s1-development.md`. **Deploy the `api_body` object as-is via a JSON serializer. Do
NOT hand-edit the wire body to add backslashes, and do NOT paste these regexes raw into the console UI
with their file-level escaping** (in the console UI you type a single backslash, same as the parsed
value here).

Hand confirmed detections to `s1-hyperautomation-engineer` (response automation off each alert) and
to `s1-platform-engineer` (dashboards). Cloudflare asset enrichment must be deployed FIRST — see
"Asset binding" below — coordinate with `s1-platform-engineer`.

---

## Asset binding (critical — Cloudflare is a third-party, non-OCSF-native source)

Cloudflare logs do NOT carry the SentinelOne console asset identity, so without enrichment every
alert binds to **"Unknown Device"** (`.claude/rules/s1-development.md`, asset-binding section). The
HTTP Requests / Firewall Events datasets map to OCSF **HTTP Activity, `class_uid=4002`** and carry
`src_endpoint.ip` as the only natural entity.

- **Scheduled rules:** set `data.entityMappings` (≤3 projected columns). These rules project
  `src_ip` (= `src_endpoint.ip`) and, where enrichment is present, `device_host` / `device_agentuuid`.
  Until the asset-enrichment solution runs, the bound entity is the source IP only (still useful for
  the HA block-IP playbook), and the device shows "Unknown Device".
- **single-event / correlation rules:** auto-bind from the matched event, but only if the event
  carries `device.uid` (numeric console agent id or unified asset id) + an endpoint `class_uid`.
  Cloudflare events do not, so these alert as "Unknown Device" until enrichment stamps
  `device.uid` + `class_uid` into the parsed event. The rule logic still fires correctly; only the
  Target Asset display is affected.

**Prerequisite:** run the asset-enrichment solution
(`reference/s1-secops-skills/.../docs/solutions/asset-enrichment.md`) so Cloudflare alerts map to
real assets. This is a `s1-platform-engineer` + `s1-log-parser-engineer` coordination item.

---

## Open assumptions requiring live-tenant validation (TO-VERIFY)

These are author-time assumptions. Validate each on a live tenant before relying on the detection.

1. **Unmapped Cloudflare bot / WAF / AI fields.** The parser v1.6.0 does NOT map:
   `BotScore`, `BotScoreSrc`, `BotDetectionTags`, `FirewallForAIInjectionScore`,
   `AISecurityInjectionScore`, `WAFSQLiAttackScore`, `WAFRCEAttackScore`, `WAFXSSAttackScore`.
   With the parser's `rename_tree → unmapped` behaviour these SHOULD land under `unmapped.<Field>`
   (e.g. `unmapped.BotScore`, `unmapped.FirewallForAIInjectionScore`). The exact promoted name and
   casing is **TO-VERIFY** via `powerquery_schema_discover` on `dataSource.name='Cloudflare'`.
   Two remediation paths, both `s1-log-parser-engineer` coordination items:
   (a) extend the parser to map these to stable OCSF/extension fields (preferred — e.g.
   `FirewallForAIInjectionScore → risk_score` or a `cloudflare.*` namespace), or
   (b) query them via `unmapped.*` as written here. Rules that depend on these fields carry a
   `payload_fallback` S1QL clause that detects the same behaviour from the **payload text**
   (`http_request.url.url_string` / `http_request.user_agent`) so the detection still fires if the
   score field is absent.
2. **`risk_score` numeric type.** `WAFAttackScore → risk_score` is cast `int` by the parser, but SDL
   columns are type-locked at first ingest. All arithmetic/comparison on `risk_score` (and any
   `unmapped.WAF*Score`) is wrapped in `number()` per the project rule. Confirm the column is numeric
   in live schema discovery.
3. **`dataSource.cloudflare_dataset` selectivity.** Rules filter `dataSource.name='Cloudflare'` plus
   `dataSource.cloudflare_dataset='HTTP Requests'` (or `'Firewall Events'`). Confirm both the field
   name and the literal dataset values exist post-ingest. If `cloudflare_dataset` is not queryable,
   fall back to `class_uid=4002` + presence of an HTTP field.
4. **JA4 array projection.** JA4 maps to `ja4_fingerprint_list[0].value`. Bracketed array fields work
   in `columns` and `group by` but **NOT as a filter predicate** (HTTP 400) per the PowerQuery rules.
   Box 2 therefore groups by the JA4 column rather than filtering on a literal; the single-event Box 2
   variant is intentionally NOT provided (can't predicate on the array). Confirm `[0]` is the correct
   index post-parse.
5. **POST body / prompt text visibility.** Cloudflare HTTP Requests logs do not include the request
   body by default, so the DAN/JNDI prompt *text* is only reliably visible when it rides in the URL
   (`http_request.url.url_string`) or the User-Agent (the Log4Shell-in-UA case the attack uses).
   Prompt-in-body detection depends on the Firewall-for-AI score field (assumption 1). Confirm what
   the live Logpush job actually carries for `POST /api/v1/chat`.
6. **`http_response.status` vs `http_response.code`.** HTTP Requests maps
   `OriginResponseStatus → http_response.status` (string) and there is no `EdgeResponseBytes`
   mapping; response size is `OriginResponseBytes → http_response.body_length` (int). The exfil rule
   uses `http_response.body_length`. Confirm these are populated for Worker responses.
7. **Account scope.** All `filter.accountIds` are `["<accountId>"]` placeholders. Set to the real
   SoleDrop account/site id at deploy.
</content>
</invoke>
