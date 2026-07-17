# SoleDrop CTF — Cloudflare products → attacks → detections

How each Cloudflare **security product** maps to a CTF box, what it does to the
**SoleDrop shop** (`shop.soledrop.co`), and which **SentinelOne detection** fires.
The CTF ("Operation Drop-Day Bot Swarm", `attack-scripts/campaigns/ctf.py`) is
hardcoded to the SoleDrop shop via `CAMPAIGNS['ctf']['target_url']`.

## Product → box → shop effect → detection

| Cloudflare product | CTF box | Attack traffic | SoleDrop shop effect | Detection that fires |
|---|---|---|---|---|
| **WAF — managed ruleset + ML attack scores** (Enterprise) | Box 1, Box 4 | SQLi in `?q=`/`?id=` on `/search`,`/products`,`/api/*`; RCE/traversal markers in query string | Malicious requests scored/blocked at the edge | `web-sqli` (WAFSQLiAttackScore band), `web-traversal` (WAFRCEAttackScore), Box-4 `MultiVectorStorm` corroboration (`risk_score`) |
| **WAF — custom rules** (`cloudflare/waf/rules.json`) | Box 1, Box 4 | SQLi / XSS / traversal signatures | Firewall-event block | `detections/ctf/box1-recon-sweep.json`; Firewall-events rows |
| **Bot Management — JA4 + bot score** (Enterprise) | Box 2 | Sneaker-bot swarm: ≥6 rotating User-Agents from one origin, constant JA4, hammering `/products`,`/api/v1/cart`,`/api/v1/checkout`,`/login` | Drop-day checkout swarm; Waiting Room / challenge is the response | `detections/ctf/box2-polymorphic-ja4.json` (distinct UAs ≥ 6 per JA4) + `ai-bot` |
| **Firewall for AI** (Enterprise) | Box 3 | Prompt injection POSTed to the SoleDrop concierge (`/api/v1/chat`) as real JSON, with a jailbreak/JNDI marker also in `?q=` | Concierge abuse; injection scored/blocked | `detections/ctf/box3-prompt-injection.json` (injection score **or** url/UA regex) + burst rule + `prompt-injection` |
| **Rate Limiting / Waiting Room** | Box 2, Box 4 | High-volume add-to-cart / checkout | Protects the drop; real customers queued instead of erroring | Response action (not a detection) — referenced in `hyperautomation/ctf/` |
| **Turnstile / managed challenge** | Box 3 (response) | — | `managed_challenge` applied to `/api/v1/chat` after Box 3 | Response action (`hyperautomation/ctf/box3-*`) |
| **Leaked Credential Check** | Box 3 | Credential stuffing on `/login` (combolist) | Account-takeover attempts on customer accounts | Signal available (`actor.authorizations[0].decision`); see caveat below |
| **Cross-box exfil** (WAF logs) | Box 4 | ≥10 bulk pulls of `/api/v1/customers`,`/api/v1/users`,`/api/v1/training-data`,`/api/v1/models` from one origin | Bulk customer/order-data scraping | `detections/ctf/exfil-training-data.json` (**volume** branch) + `data-exfil` (`/customers`) |

> **Access / Zero Trust** and **Gateway DNS** are exercised by the *other* lab
> pieces (portal credential-stuffing and the DNS-tunneling scenario), not by the
> SoleDrop CTF — listed here only for completeness.

## Structural caveats (read before relying on a detection)

1. **Cloudflare HTTP logs never include the POST body.** So the boxes place every
   attack marker in the **URL query string** or **User-Agent** — the fields the OCSF
   parser maps (`http_request.url.url_string`, `http_request.user_agent`). Box 3's
   prompt is sent as a real JSON body *and* mirrored into `?q=`; Box 4's RCE/SSRF/
   traversal markers ride the query string (and JNDI rides the UA).
2. **Score-based detection arms need licensed products.** `WAF*AttackScore`,
   `BotScore`/`JA4`, and `FirewallForAIInjectionScore` only populate with WAF ML,
   Bot Management, and Firewall for AI enabled (Enterprise — which the `soledrop.co`
   zone has). The behavioral/regex/volume arms fire regardless.
3. **SoleDrop `/login` returns HTTP 200 on a failed login** (it re-renders the login
   page with an error), not 401. The generic `cred-stuffing` rule keys on
   `401/403/429`, so Box 3's credential stuffing is **narrative + login volume**, not
   a reliable trip of that specific rule. (Box 3's real detection is prompt injection.)
4. **The exfil *byte* branch needs an authenticated large response.** SoleDrop gates
   `/api/v1/customers` etc. behind a session, so unauthenticated pulls return small
   bodies — the **volume branch** (≥10 requests) is the reliable exfil trigger.
5. **Detection rule names still say "SoleDrop"/"SoleDrop Concierge".** Those STAR rules
   (`detections/ctf/*`) are deployed as-is and key on paths/UAs/scores (not hostname),
   so they fire on `soledrop.co` traffic unchanged — but the alert names read
   `SoleDrop-CTF-Box*`. Renaming them is an optional follow-up (would require
   re-deploying the rules in S1).

## SentinelOne / Logpush wiring checklist (do this before a live run)

The CTF traffic hits the shop today; **alerts require the S1 side wired up:**

- [ ] **Logpush → S1 HEC** on the `soledrop.co` zone: enable **HTTP Requests** and
      **Firewall events** datasets, destination = your S1 HEC ingest URL + token.
      (Gateway DNS is only needed for the DNS scenario, not this CTF.)
- [ ] **Deploy the detections** as STAR rules in your S1 tenant: `detections/ctf/*.json`
      (Box 1–4 + `exfil-training-data`) plus `web-sqli`, `ai-bot`, `prompt-injection`,
      `data-exfil`. Scope each rule's `siteIds` to the site that receives the
      `soledrop.co` Logpush.
- [ ] **Enable the Enterprise products** on the `soledrop.co` zone: WAF managed
      ruleset (attack scores), Bot Management (JA4 + bot score), Firewall for AI.
- [ ] **Verify field mapping** with `powerquery_schema_discover` before relying on the
      score arms: confirm `unmapped.WAFSQLiAttackScore` / `unmapped.BotScore` /
      `unmapped.FirewallForAIInjectionScore` casing and that
      `ja4_fingerprint_list[0].value` is populated.
- [ ] **Incident flip auth:** set `INCIDENT_KEY` on the lab-ui/attack host equal to the
      SoleDrop worker's `INCIDENT_KEY` secret, so the `/status` flip authenticates
      (POST `shop.soledrop.co/api/incident`).

## Verifying each box triggers its detection

Run each box (ThreatOps → OneFlare CTF tab → select a box → Launch), then in S1:

| Box | Expected STAR rule | Quick check |
|---|---|---|
| 1 | `SoleDrop-CTF-Box1-ReconSweep-Fanout` | one `src_endpoint.ip` with ≥8 distinct recon paths |
| 2 | `SoleDrop-CTF-Box2-PolymorphicJA4` | one JA4 with ≥6 distinct User-Agents |
| 3 | `SoleDrop-CTF-Box3-ConciergePromptInjection` (+ burst) | injection markers in url_string/UA on `/api/v1/chat` |
| 4 | `SoleDrop-CTF-Box4-MultiVectorStorm` (+ correlation) | ≥2 attack classes per IP in url_string/UA |
| exfil | `SoleDrop-Exfil-TrainingData-ModelWeights` | ≥10 pulls of exfil paths from one IP |
