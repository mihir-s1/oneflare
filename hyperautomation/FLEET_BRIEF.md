# OneFlare Hyperautomation Fleet Brief (2026-07-15)

You are one of several S1 Hyperautomation engineers building **response workflows** for the
OneFlare / NovaMind detection-engineering lab. Each of you owns one attack scenario. A parallel
pair of S1 detection engineers is auditing alert entity/enrichment readiness — read their output
in `hyperautomation/_DE_AUDIT/` if present, but do not block on it.

## Read first (mandatory)
1. `.claude/rules/s1-development.md` — the project S1 dev protocol (esp. the **Hyperautomation**
   dev loop + credentials + asset-binding sections).
2. The **`sentinelone-hyperautomation` skill** — invoke it for workflow JSON schema, building-blocks
   catalog, validation rules, and the import/export API. THIS IS THE SOURCE OF TRUTH for JSON shape.
3. `reference/s1-secops-skills/skills/hyperautomation/` — references + examples.
4. Your scenario's **deployed detection rule** in `detections/<dir>/*.rule.json` — this defines the
   ALERT your workflow triggers on: its columns (`scheduledParams.query ... | columns ...`) are the
   fields available to your workflow. Also read the matching scenario object in
   `lab-ui/frontend/src/data/scenarios.js` for narrative + MITRE mapping.
5. `detections/ctf/` + `hyperautomation/ctf/` — an existing example set in this repo, for house style.

## Deployed detections (all Active; alert-trigger source for your workflow)
| Scenario | Rule id | Rule name | Key alert entities/columns |
|---|---|---|---|
| sqli | 2519092985434164473 | CF-WAF-SQLi | src_ip, host, path, waf_score, matched rule |
| xss | 2519092991281024296 | CF-WAF-XSS | src_ip, host, path, waf_score |
| traversal | 2519092998092573998 | CF-WAF-Traversal | src_ip, host, path |
| cred | 2519093004283366750 | CF-Access-CredStuffing | src_ip, user/email, host, failed_logins |
| exfil | 2519093015733817725 | CF-API-Exfil | src_ip, user, host, endpoint, bytes_out |
| bot | 2523842940840264774 | CF-Bot-Scraper (BotScore) | src_ip, host, bot_requests, min/avg BotScore, sample_ua, country |
| promptinj | 2519093028014740613 | CF-AI-PromptInjection | src_ip, user, host, /api/v1/chat prompt markers |
| dns | 2519102258169184569 | CF-Gateway-DNSTunnel | src_ip/device, query_name, query_type, subdomain entropy |

## What a good workflow does (compose from the building-blocks catalog)
Build an **alert-triggered** response playbook. Use ONLY blocks that exist in the HA building-blocks
catalog. Draw from three pools:
- **SentinelOne actions:** enrich the alert (add a **note/annotation** summarizing the finding),
  **search related alerts/events** (other alerts from same src_ip / same host / same user in a window),
  pull threat-intel/reputation, update alert status/confidence, add to a blocklist/watchlist where
  supported. Fabricate nothing — key off the real alert columns above.
- **Cloudflare integration actions** (if present in the catalog): create a **WAF custom rule / IP
  Access rule to block or challenge** the offending `src_ip` on the affected zone; for Access/cred
  scenarios, consider a block/step-up; for DNS, a Gateway policy note. If a native CF block action is
  NOT in the catalog, model it as an HTTP-request block calling the Cloudflare API (document the
  connection/secret needed) — do not invent a block-action type.
- **Free / open third-party integrations** the HA library offers: **VirusTotal** (IP/domain/hash
  reputation), **AbuseIPDB**, **URLhaus/OTX/Shodan** or similar — use whatever the catalog actually
  contains for IP/domain reputation enrichment of `src_ip`. Gate branching on the reputation verdict
  (e.g. malicious → block + raise confidence; clean → note + monitor).

Shape: **trigger → parallel enrichment (S1 search + reputation) → decision branch → response
(CF block/challenge + S1 note + status update) → notify (email/Slack/webhook if catalog supports)**.
Keep it demo-ready and realistic; annotate each block's purpose.

## Deliverables (write these)
- `hyperautomation/<scenario>/<scenario>.workflow.json` — the validated, importable workflow JSON.
- `hyperautomation/<scenario>/README.md` — trigger, block-by-block logic, required connections/secrets,
  MITRE mapping, and any catalog gaps you had to model around.
- If a block/integration you wanted is NOT in the catalog, say so explicitly in the README (evidence
  discipline — no fictional building blocks).

## Validate + deploy
- **Validate** the JSON against the skill's validation rules (schema, block refs, connection refs).
  Report the validation result honestly.
- **Import/publish is best-effort:** HA import lands as a **Private Draft owned by the token user** and
  UI visibility needs a **personal Console User token** (the lab's service token may not surface it).
  The sandbox also blocks outbound to `*.sentinelone.net`. So: attempt import via the
  `s1-secops-mcp` / `ha_import_workflow` tool IF reachable; if not, deliver validated JSON + clear
  import/publish instructions and report the deploy as pending. **Do not claim a deploy you didn't do.**

## House rules
- No fabrication. Every field/entity you enrich or branch on must exist in the alert columns or be a
  documented enrichment output. Empty/blocked results are findings — report them.
- Minimal-yet-sufficient. One cohesive workflow per scenario (the web-attack engineer may parametrize
  one workflow across sqli/xss/traversal if cleaner — your call, document it).
- Match repo house style from `hyperautomation/ctf/`.
