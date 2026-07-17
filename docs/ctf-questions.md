# SoleDrop CTF — Attendee Question Pack

**Operation Drop-Day Bot Swarm.** You defend your own lab store at
`<name>.lab.soledrop.co`. Work box by box: each opens with a short primer, then a
mix of **concept** questions (know the control) and **hunt** questions (find the
answer in SentinelOne). Hunt questions map to
[`detections/ctf/lab-oneliners.md`](../detections/ctf/lab-oneliners.md) — replace
`<<SUBDOMAIN>>` with your lab name and go.

> **Answer style:** hunt answers are a concrete value from *your* lab (a count, an
> IP, a fingerprint). Concept answers are 1–3 sentences. A facilitator answer-key
> approach is at the bottom.

---

## Getting started (warm-up)

1. Where does the attack traffic live in SentinelOne? (Name the `dataSource.name`
   and the two `dataSource.cloudflare_dataset` values you'll query.)
2. Why must every query filter `http_request.url.hostname contains '.lab.soledrop.co'`
   before anything else? What noise does it remove?
3. Cloudflare HTTP logs **omit request bodies**. Where, then, must an attack marker
   ride so a WAF rule — or your detection — can match it?
4. The demo uses a *mixed* enforcement strategy. In one sentence: what gets
   **blocked** vs **logged**, and why let some attacks through at all?

---

## Box 1 — WAF (Recon & vulnerability scanning)

**Primer.** A Web Application Firewall (WAF) sits at Cloudflare's edge, in front of
your origin. It inspects each request and can **block**, **challenge**, or **log**
it. Two layers run: Cloudflare's **Managed Ruleset** (known-attack signatures) and
our **custom rules**. The WAF also emits an **Attack Score** (1–99).

5. What is a WAF, and what are the three things it can do to a request?
6. The WAF **Attack Score** runs 1–99. Which end means "almost certainly an
   attack" — and why is that the *opposite* of what most people guess?
7. **Hunt (1a):** which single `src_endpoint.ip` swept the most distinct paths on
   your shop? How many distinct paths?
8. **Hunt (1a):** how many of that IP's requests carried a known **scanner
   User-Agent** (nikto/nuclei/sqlmap/…)?
9. **Hunt (1b):** take the noisiest scanner UA and list the sensitive paths it
   probed. How many distinct sensitive paths did it reach for?
10. A probe to `/.env` came back **403** but `/robots.txt` came back **404**. Which
    layer produced the 403 — a custom rule or the managed ruleset — and why?
11. Why is a *single* recon request low-confidence, but *one IP touching 40+
    distinct paths* high-confidence? What field turns the second into a detection?
12. Name two things you would add to the recon detection to cut false positives
    (think: your own monitoring, legitimate crawlers).

---

## Box 2 — Bot Management (the drop-day swarm)

**Primer.** Sneaker bots flood a hyped drop. Each request rotates its
**User-Agent** to look like a different shopper — but the underlying client can't
change its **TLS fingerprint** (JA3 / JA4) mid-handshake. Cloudflare **Bot
Management** emits that fingerprint plus a **BotScore**.

13. What is a JA3/JA4 TLS fingerprint, and why can't a bot hide by rotating its
    User-Agent?
14. **Hunt (2a):** which single `tls.ja3_hash.value` sits behind the most distinct
    user-agents on your shop? (This is the swarm.)
15. **Hunt (2b):** paste that fingerprint back in — how many distinct **disguises**
    (user-agents) hid behind that one fingerprint?
16. **Hunt (2b):** name three real sneaker-bot User-Agents you see in the swarm.
17. Every bot-swarm request **passed** the WAF (200/404) instead of being blocked.
    Why? What does that tell you about signature-based blocking vs behavior?
18. BotScore runs 1–99 — which end means "likely automated"?
19. Write (in words) a detection for "one fingerprint, **many** user-agents" that
    works *without* knowing the fingerprint in advance. What do you group by, what
    do you count, where's the threshold?
20. Which Cloudflare entitlement must be on for `JA3`/`JA4`/`BotScore` to appear in
    the logs at all? What happens to Box 2's detection if it's off?

---

## Box 3 — Firewall for AI + Account Takeover

**Primer.** The shop has an AI concierge at `POST /api/v1/chat`. Attackers try
**prompt injection** (jailbreak it into leaking secrets) while separately running
**credential stuffing** against `POST /login`. Cloudflare **Firewall for AI**
scores prompts with `FirewallForAIInjectionScore`.

21. What is prompt injection? What is the attacker trying to make the concierge do?
22. **Hunt (3a):** which `src_endpoint.ip` sent the most `/api/v1/chat` requests,
    and what is its `max_injection_score`?
23. `FirewallForAIInjectionScore` maxes at **100**. Is *higher* worse or *lower*
    worse here — and how does that compare to the WAF **Attack Score** direction?
24. **Hunt (3b):** paste that IP in — how many `/login` POSTs did it make? (This is
    the credential-stuffing burst.)
25. Cloudflare omits POST bodies, so we can't read the prompt text. Which **two**
    signals let us detect concierge abuse anyway?
26. What is credential stuffing, and how is it different from brute-force or
    password spraying?
27. The `/login` stuffing shows up as **200 (logged)**, not 403. Why did we choose
    to log it rather than block it?
28. What single control would make prompt-injection detection *deterministic*
    instead of relying on the managed WAF's borderline ML score?
29. The same IP appears in both the chat abuse **and** the login burst. Why does
    correlating the two raise your confidence that it's one attacker?

---

## Box 4 — Full breakout (exploit + exfiltration)

**Primer.** The serious push: real exploit attempts (**Log4Shell**,
**Struts/OGNL**, **Spring4Shell**, **SSRF** to cloud metadata) *alongside* bulk
pulls of customer and training data. The high-fidelity signal is the
**correlation** — the same source doing both.

30. Name the three exploit families in the breakout, plus the SSRF target the
    attacker reaches for.
31. **Hunt (4a):** which `src_endpoint.ip` has the most requests in the malicious
    WAF-score band (1–20), and what's its worst SQLi/RCE score?
32. A request scores **1/99**. What does that tell you, versus a request that
    scores **95/99**?
33. **Hunt (4b):** paste that IP in — how many bulk **exfil pulls** did it make, and
    against which sensitive endpoints?
34. **Hunt (capstone):** which single `src_endpoint.ip` did recon **and** tripped
    the WAF **and** pulled bulk data? (That's your answer / flag.)
35. Why is "WAF blocks correlated with bulk data pulls from the same IP" a
    higher-fidelity detection than either signal on its own?
36. The exploit requests were **blocked (403)**. Are they still useful for
    detection — why or why not?
37. The `${jndi:}` RCE marker arrived **URL-encoded** in the query string. What
    must the WAF rule (and your PowerQuery) do to match it?
38. Map each box to its primary MITRE technique: Box 1 = ___, Box 2 = ___,
    Box 3 = ___, Box 4 = ___.

---

## Facilitator answer-key (approach, not lab-specific values)

Each hunt answer is a value from the attendee's own lab; grade by the *method*.

- **Warm-up:** `dataSource.name='Cloudflare'`; datasets `HTTP Requests` + `Firewall events`; the account's own Cloudflare Gateway feed is the noise the host filter removes; markers ride the **URL query string** or **User-Agent**; block exploits / log behavioral so the pattern (and shop impact) still surfaces.
- **Box 1:** WAF = block/challenge/log; **low** score = attack (1 = certain); 1a top row = recon IP + path count; 1b flag = distinct sensitive-path count; the 403 is the **managed ruleset** catching a known scanner/sensitive path; the field that upgrades confidence is `estimate_distinct(http_request.url.path)`; FP tuning = allowlist your own monitoring IPs/UAs.
- **Box 2:** JA3/JA4 is a TLS-handshake fingerprint the client can't change per-request; 2a = the swarm fingerprint; 2b flag = distinct-UA count (dozens); bots pass because each request looks individually legitimate; **low** BotScore = automated; detection = `group estimate_distinct(user_agent) by ja3 | filter >= N`; needs the **Bot Management** entitlement (JA/BotScore null without it).
- **Box 3:** injection tries to override the concierge's instructions; 3a = chat-abuse IP + score; injection score **higher = worse** (opposite of WAF score); 3b flag = login-POST count; detect via **chat volume + Firewall-for-AI score / WAF block**; stuffing = many stolen creds vs one account (brute force) or one password across many accounts (spraying); logged not blocked so the behavior surfaces; **Firewall for AI** makes it deterministic; correlation = same IP in two behaviors.
- **Box 4:** Log4Shell / Struts(OGNL) / Spring4Shell + SSRF to `169.254.169.254` / `metadata.google.internal`; 4a = breakout IP, worst score ~1; 1/99 = certain attack; 4b flag = exfil-pull count + endpoints; capstone = the single did-everything IP; correlation beats either alone (each is noisy); blocked events are **still logged with scores** so they detect fine; use `url_decode()` on the query; MITRE — Box1 T1595.002, Box2 T1595/T1036.005, Box3 ATLAS AML.T0051 + T1110.004, Box4 T1190 + T1119/T1020.
