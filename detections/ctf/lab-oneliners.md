# SoleDrop CTF — One-Liner Detections (attendee hunt pack)

Copy-paste **PowerQuery one-liners** for the Drop-Day Bot Swarm CTF, run in
**SentinelOne → Event Search / PowerQuery** (Singularity Data Lake). Each is a
single line. They're built so attendees fill in placeholders — some you know up
front, some you must **discover in an earlier query and paste into the next**.

## How to use

1. Replace **`<<SUBDOMAIN>>`** with *your* lab name — the part before `.lab.soledrop.co`.
   Example: lab `mihirpurple.lab.soledrop.co` → `<<SUBDOMAIN>>` = `mihirpurple`.
   (Leave it as `contains '.lab.soledrop.co'` with no subdomain to hunt across *everyone's* labs.)
2. Placeholders in **`<<CAPS>>`** other than `<<SUBDOMAIN>>` are **flags you have to find**:
   run the "finder" query in that box, read the answer out of the result, and paste
   it into the "flag" query to unlock the next answer.
3. All queries default to the last 24h in Event Search — widen the time picker if your run was earlier.

> **Facilitator note:** to turn any finder into a scored flag, wrap the value the
> attendee must submit — e.g. append `| columns flag = <the-column>` and have them
> submit that value. A `<<FLAG_PREFIX>>` (e.g. `S1CTF{`) can be prepended in a
> `let` if you want `S1CTF{…}`-style flags.

---

## Box 1 — Recon & WAF probing  (Cloudflare WAF)

**1a · Finder — who is sweeping your shop?**
```
dataSource.name='Cloudflare' http_request.url.hostname contains '<<SUBDOMAIN>>.lab.soledrop.co' src_endpoint.ip=* | group distinct_paths=estimate_distinct(http_request.url.path), scanner_hits=count(http_request.user_agent matches 'nikto|nuclei|sqlmap|masscan|wpscan|dirsearch|gobuster|feroxbuster|libwww-perl|python-requests|curl/'), noisiest_ua=max_by(http_request.user_agent, timestamp) by src_endpoint.ip | sort -distinct_paths | limit 20
```
*The top row's `src_endpoint.ip` is your recon attacker. Note its `noisiest_ua`.*

**1b · Flag — what secrets did that scanner reach for?**  (paste the scanner User-Agent into `<<SCANNER_UA>>`)
```
dataSource.name='Cloudflare' http_request.url.hostname contains '<<SUBDOMAIN>>.lab.soledrop.co' http_request.user_agent contains '<<SCANNER_UA>>' | group sensitive_paths=array_agg_distinct(http_request.url.path, 50), hits=count() by http_request.user_agent
```
*Flag = the count of distinct sensitive paths it probed.*

---

## Box 2 — Drop-day bot swarm  (Bot Management)

**2a · Finder — one fingerprint, many disguises.**
```
dataSource.name='Cloudflare' dataSource.cloudflare_dataset='HTTP Requests' http_request.url.hostname contains '<<SUBDOMAIN>>.lab.soledrop.co' tls.ja3_hash.value=* | group user_agents=estimate_distinct(http_request.user_agent), requests=count() by tls.ja3_hash.value | sort -user_agents | limit 10
```
*The top `tls.ja3_hash.value` (many UAs, one fingerprint) is the swarm. Copy it.*

**2b · Flag — unmask every disguise.**  (paste the fingerprint into `<<JA3>>`)
```
dataSource.name='Cloudflare' http_request.url.hostname contains '<<SUBDOMAIN>>.lab.soledrop.co' tls.ja3_hash.value='<<JA3>>' | group disguises=array_agg_distinct(http_request.user_agent, 80), requests=count(), src_ips=estimate_distinct(src_endpoint.ip) by tls.ja3_hash.value
```
*Flag = the number of `disguises` (user-agents) hiding behind that one fingerprint.*

---

## Box 3 — AI concierge abuse + account takeover  (Firewall for AI)

**3a · Finder — who is jailbreaking the concierge?**
```
dataSource.name='Cloudflare' http_request.url.hostname contains '<<SUBDOMAIN>>.lab.soledrop.co' http_request.url.path='/api/v1/chat' | group chat_hits=count(), max_injection_score=max(number(unmapped.FirewallForAIInjectionScore)), waf_blocks=count(action='block') by src_endpoint.ip | sort -chat_hits | limit 10
```
*Note the top `src_endpoint.ip` and its `max_injection_score` (100 = injection).*

**3b · Flag — the same crew is trying stolen keys.**  (paste that IP into `<<ATTACKER_IP>>`)
```
dataSource.name='Cloudflare' http_request.url.hostname contains '<<SUBDOMAIN>>.lab.soledrop.co' http_request.url.path='/login' http_request.http_method='POST' src_endpoint.ip='<<ATTACKER_IP>>' | group login_attempts=count(), first_seen=oldest(timestamp), last_seen=newest(timestamp) by src_endpoint.ip
```
*Flag = the number of `login_attempts` (credential-stuffing burst) from that IP.*

---

## Box 4 — Full breakout  (exploit + exfil correlation)

**4a · Finder — which requests scored as real attacks?**  (Cloudflare WAF attack score: **lower = worse**, 1 = certain)
```
dataSource.name='Cloudflare' dataSource.cloudflare_dataset='HTTP Requests' http_request.url.hostname contains '<<SUBDOMAIN>>.lab.soledrop.co' | let sqli=number(unmapped.WAFSQLiAttackScore), rce=number(unmapped.WAFRCEAttackScore) | filter (sqli>0 && sqli<=20) || (rce>0 && rce<=20) | group exploit_hits=count(), worst_sqli=min(sqli), worst_rce=min(rce), sample=array_agg_distinct(http_request.url.path,8) by src_endpoint.ip | sort -exploit_hits | limit 10
```
*Top `src_endpoint.ip` is your breakout attacker. Copy it.*

**4b · Flag — what did it try to walk out with?**  (paste the breakout IP into `<<ATTACKER_IP>>`)
```
dataSource.name='Cloudflare' http_request.url.hostname contains '<<SUBDOMAIN>>.lab.soledrop.co' src_endpoint.ip='<<ATTACKER_IP>>' http_request.url.path in ('/api/v1/customers','/api/v1/training-data','/api/v1/users','/api/v1/models') | group exfil_pulls=count(), endpoints=array_agg_distinct(http_request.url.path,10) by src_endpoint.ip
```
*Flag = the number of `exfil_pulls` against sensitive data endpoints.*

---

## Capstone — connect the whole chain (one query)

**Same source IP that both tripped the WAF and pulled bulk data** — the breakout, in one line:
```
dataSource.name='Cloudflare' http_request.url.hostname contains '<<SUBDOMAIN>>.lab.soledrop.co' | group waf_blocks=count(action='block'), exfil_pulls=count(http_request.url.path in ('/api/v1/customers','/api/v1/training-data','/api/v1/users','/api/v1/models')), distinct_paths=estimate_distinct(http_request.url.path), fingerprints=estimate_distinct(tls.ja3_hash.value) by src_endpoint.ip | filter waf_blocks >= 2 && exfil_pulls >= 3 | sort -exfil_pulls | limit 20
```
*Flag = the `src_endpoint.ip` that appears — the attacker who did everything.*

---

### Field cheat-sheet (OCSF, `marketplace-cloudflare-latest` parser)

| What | Field |
|---|---|
| Source IP | `src_endpoint.ip` |
| Host | `http_request.url.hostname` (scope: `contains '.lab.soledrop.co'`) |
| Path | `http_request.url.path` · Method `http_request.http_method` |
| User-Agent | `http_request.user_agent` |
| TLS fingerprint | `tls.ja3_hash.value` (JA4 array isn't PQ-addressable) |
| WAF action / rule | `action` (`log`/`block`) · `firewall_rule.desc` |
| WAF attack scores (string → `number()`) | `unmapped.WAFSQLiAttackScore` · `unmapped.WAFRCEAttackScore` (**lower = worse**) |
| AI injection score | `unmapped.FirewallForAIInjectionScore` (higher = worse) |
