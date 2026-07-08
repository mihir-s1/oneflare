# OneFlare — Cloudflare Threat Detection dashboard

A SentinelOne SDL dashboard that turns the NovaMind lab's Cloudflare Logpush feed
(parsed to OCSF) into a live threat-detection view. Every panel is driven by real data
in the Singularity Data Lake — no synthetic values — and maps to the lab's attack
scenarios.

## Files
- `threat-detection.dashboard.json` — the dashboard definition. Import via the SDL
  dashboard UI, or deploy with `sdl_put_file` to `/dashboards/threat-detection`.

## Data sources (Cloudflare → OCSF, in the SDL)
| Dataset | OCSF class | Feeds |
|---|---|---|
| HTTP Requests | `class_uid 4002` | web attacks, credential, exfil, bot, prompt-injection |
| Firewall events | `class_uid 4002` | WAF blocks (`action = block`) |
| Gateway DNS | `class_uid 4003` | DNS tunneling / C2 |

Key fields used (live-verified): `http_request.url.{hostname,url_string,http_method}`,
`http_request.user_agent`, `src_endpoint.ip`, `src_endpoint.location.country`,
`unmapped.EdgeResponseStatus`, `unmapped.EdgeResponseBytes`,
`unmapped.WAF{SQLi,XSS,RCE}AttackScore` (strings; **lower = more malicious**, 1–99),
`unmapped.QueryName`, `query.type`.

## Tabs
1. **Threat Overview** — KPI row (requests, WAF blocks, likely attacks, attacker IPs,
   DNS queries, countries), requests-over-time by response class, attack-type donut,
   top attacker IPs, top source countries, WAF-block detail.
2. **Web App Attacks (WAF)** — SQLi / XSS / traversal-RCE tables ranked by WAF ML score,
   attacked-hosts donut. Attacks are flagged at **score ≤ 20** (near-certain), emitted on
   200s too — so it catches what slipped past the managed ruleset, not just blocked hits.
3. **Credential Attacks** — `/login` attempts over time by status, failed-login KPIs,
   failed-logins-by-source-IP table (credential stuffing / brute force → 401/403/429).
4. **DNS & C2 (Gateway)** — query volume, query-type donut, and the tunneling/DGA signal:
   query names whose leftmost label exceeds 25 chars (data-in-DNS exfil).
5. **Exfil, Bots & AI** — bulk `/export` volume + response bytes, top API data pulls,
   the polymorphic-bot tell (one source IP cycling many User-Agents), and
   prompt-injection POSTs to `/api/v1/chat`.

## Validation
All 40 PowerQuery panels were executed live via the LRQ API and confirmed to return
data over a 24h window. Notes:
- WAF attack scores are strings and null on benign traffic; the queries cast with
  `number()` and gate on `>= 1 and <= 20` so null (→0) benign rows are never counted.
- Array-indexed fields (e.g. a JA4 fingerprint stored under `...[0].value`) are not
  addressable by the PQ engine here, so the bot tell uses source-IP-vs-distinct-UA
  instead — a cleaner, equivalent signal.
- Panels follow the global 24h time picker; widen it if a panel is empty.
