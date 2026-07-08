export const SCENARIOS = [
  {
    id: "sqli",
    number: "01",
    title: "SQL Injection Burst",
    shortDescription: "23 SQLi payloads fired at the /search endpoint to trigger WAF blocking rules",
    category: "WAF",
    categoryColor: "orange",
    severity: "High",
    cfProduct: "WAF / Firewall Rules",
    target: "shop.acmecorp.dev /search",
    detectionRule: "CF-WAF-SQLi-Burst",
    tactic: "Initial Access / Exploitation",
    overview: "This scenario simulates an attacker probing the AcmeCorp webstore for SQL injection vulnerabilities. The script fires 23 unique SQLi payloads at the search endpoint, cycling through classic patterns like UNION SELECT, OR 1=1, and DROP TABLE. The Cloudflare WAF intercepts and blocks these requests, generating RuleID 100001 (OWASP group) events that feed into SentinelOne via Logpush.",
    howItWorks: [
      "Attack script sends GET /search?q=<payload> for each of 23 payloads",
      "Payloads include: ' OR 1=1--, UNION SELECT username,password FROM users--, 1; DROP TABLE products--",
      "Each request has a randomized User-Agent and small delay (jitter) to simulate realistic traffic",
      "Cloudflare WAF evaluates each request against OWASP rule group 100001",
      "Blocked requests return 403; WAF events are logged with RayID, ClientIP, MatchedData",
      "Logs flow via Logpush → SentinelOne within ~60 seconds"
    ],
    cfLogs: `{
  "Action": "block",
  "ClientIP": "1.2.3.4",
  "RuleID": "100001",
  "RuleGroup": "OWASP",
  "MatchedData": "' OR 1=1",
  "ClientRequestPath": "/search",
  "EdgeResponseStatus": 403,
  "RayID": "abc123"
}`,
    siemLogic: `event.type = "CloudflareFirewallEvent"
AND event.Action = "block"
AND event.RuleGroup = "OWASP"
AND event.ClientRequestPath CONTAINS "/search"
THRESHOLD: 5 events in 60 seconds from same ClientIP`,
    siemSeverity: "High",
    siemTactic: "Initial Access / Exploitation",
    responseWorkflow: [
      { step: 1, action: "Get IP Overview", detail: "Enrich ClientIP — ASN, country, threat reputation score" },
      { step: 2, action: "Create IP Access Rule", detail: "Mode: block, IP: {{ClientIP}}, Notes: 'Auto-blocked: SQLi burst'" },
      { step: 3, action: "Create PCAP Request", detail: "Capture 60s of traffic from {{ClientIP}} for forensics" },
      { step: 4, action: "Update Log Retention", detail: "Extend retention on zone to preserve WAF evidence" },
      { step: 5, action: "Notify SOC", detail: "Post alert with RayID, ClientIP, matched payload to SIEM/ticket" }
    ],
    siem: {
      ruleName: "CF-WAF-SQLi-AttackScore",
      ruleType: "Scheduled detection",
      queryLang: "PowerQuery 2.0 · SentinelOne SDL",
      dataSource: "Cloudflare zone HTTP Requests → OCSF HTTP Activity (class_uid 4002)",
      severity: "High",
      validated: true,
      validationNote: "Live-validated against real one-flare.com HTTP Requests (LRQ). shop.one-flare.com returned 8 requests with WAFSQLiAttackScore ≤ 20 (min score 4 — near-certain SQLi); api / portal / apex all clean (min score 97). Cloudflare's ML attack score is emitted on EVERY request — including the ones that returned 200 — so this catches SQLi that slips past the managed ruleset, not just blocked hits. Score direction confirmed on real data: LOWER = more malicious (1–99 scale).",
      importance: "SQL injection remains the highest-impact web attack: a single unsanitized parameter can dump the entire customer database, forge auth, or pivot to RCE. Cloudflare's managed WAF blocks the obvious payloads, but obfuscated/second-order SQLi routinely scores 'likely attack' yet returns 200 — those bypasses are exactly what the SIEM must catch as the safety net behind the WAF.",
      whyDetect: [
        "Catches WAF bypasses: the WAFSQLiAttackScore is computed by ML on every request, so a payload that evaded the signature ruleset still scores low and fires here.",
        "Signature-independent — keys on Cloudflare's attack-score model, not a static rule ID, so novel/obfuscated UNION/boolean/time-based payloads are covered.",
        "Aggregated per source: a scanning burst (sqlmap) produces many low-score requests, separating a probe campaign from a one-off false hit.",
        "Zero false positives on clean traffic in validation — benign requests score 90–99.",
      ],
      query: `class_uid=4002 dataSource.cloudflare_dataset='HTTP Requests'
| let sqli_score = number(unmapped.WAFSQLiAttackScore)
| let waf_score  = number(risk_score)
| let src_ip     = src_endpoint.ip
| let host       = http_request.url.hostname
| filter sqli_score <= 20
| group
    attempts   = count(),
    min_sqli   = min(sqli_score),
    min_waf    = min(waf_score),
    paths      = estimate_distinct(http_request.url.path),
    method     = any(http_request.http_method),
    evidence   = min_by(http_request.url.url_string, sqli_score),
    ray        = any(metadata.uid),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp)
  by src_ip, host
| filter attempts >= 3
| let detection_time = simpledateformat(last_seen, 'yyyy-MM-dd HH:mm:ss z', 'America/Chicago')
| sort -attempts
| columns detection_time, src_ip, host, attempts, min_sqli, min_waf, paths, method, evidence, ray, first_seen
| limit 100`,
      queryExplained: [
        { code: "class_uid=4002 · cloudflare_dataset='HTTP Requests'", note: "Scope to the zone reverse-proxy HTTP log (NOT 'Gateway HTTP', which is the forward-proxy dataset and carries no WAF attack scores)." },
        { code: "number(unmapped.WAFSQLiAttackScore)", note: "The per-request SQLi ML score lives under unmapped.* (the parser promotes only the overall WAFAttackScore → risk_score). It is a STRING in the SDL — cast with number() before comparison." },
        { code: "filter sqli_score <= 20", note: "Cloudflare score is 1–99, LOWER = more malicious. ≤20 = 'attack'; validated attacker min was 4, clean traffic 97." },
        { code: "min_by(url.url_string, sqli_score)", note: "Projects the single most-malicious request URI as evidence — url_string carries the full path+query where the payload lives (ClientRequestQuery is null in this feed)." },
        { code: "filter attempts >= 3", note: "Require a small cluster per source so a lone borderline score can't alert." },
      ],
      signals: [
        { signal: "WAFSQLiAttackScore ≤ 20", catches: "SQL injection (incl. WAF bypasses)", why: "Cloudflare's ML flags the payload structure regardless of block outcome — the low score persists even on requests that returned 200." },
        { signal: "attempts ≥ 3 per src_ip+host", catches: "SQLi probing / sqlmap sweep", why: "Injection discovery fires dozens of variants; clustering separates a campaign from noise." },
      ],
      mitre: [
        { id: "T1190", tactic: "Initial Access", name: "Exploit Public-Facing Application", url: "https://attack.mitre.org/techniques/T1190/" },
        { id: "T1213", tactic: "Collection", name: "Data from Information Repositories", url: "https://attack.mitre.org/techniques/T1213/" },
      ],
      falsePositive: {
        finding: "No false positives in live validation — all clean hosts scored WAFSQLiAttackScore 97. The residual FP class is a legitimate app that legitimately contains SQL-like strings (e.g. a query-builder or a search for the literal text 'UNION SELECT').",
        rootCause: "Cloudflare's attack score is probabilistic; a search box that echoes SQL keywords can occasionally score in the 'likely attack' band.",
        fix: "The attempts ≥ 3 cluster gate absorbs single borderline hits; if a known search feature is noisy, exclude its path or tighten sqli_score ≤ 10 for that host.",
      },
      triage: "Treat as SUSPICIOUS — Pending Confirmation. Pull the evidence URI, decode the payload, and check whether http_response.status/EdgeResponseStatus was 200 (potential successful injection) vs 403 (blocked). Confirm exploitation via origin/DB logs before declaring a true positive.",
      recommendedResponse: "Block the ClientIP with a zone IP Access Rule, capture PCAP for the source, and if any matching request returned 200 escalate to app-team for a data-access review. Full steps in the Response Playbook tab.",
    }
  },
  {
    id: "xss",
    number: "02",
    title: "Cross-Site Scripting (XSS)",
    shortDescription: "39 XSS payloads across reflected search and stored review submission endpoints",
    category: "WAF",
    categoryColor: "orange",
    severity: "High",
    cfProduct: "WAF / Firewall Rules",
    target: "shop.acmecorp.dev /search, /reviews",
    detectionRule: "CF-WAF-XSS-Burst",
    tactic: "Initial Access / Client-side Injection",
    overview: "This scenario tests the WAF's ability to detect cross-site scripting attempts. The attack script sends 39 XSS payloads across two surfaces: the reflected search endpoint and the stored review submission form. Payloads range from classic script tags to encoded variants and event handler injections.",
    howItWorks: [
      "Script sends GET /search?q=<payload> for reflected XSS payloads",
      "Script sends POST /reviews with body containing stored XSS payloads",
      "Payloads include: <script>alert(1)</script>, javascript:alert(1), onerror=alert(1), encoded variants",
      "Cloudflare WAF blocks based on XSS signature matching",
      "Stored XSS attempts via /reviews test if WAF inspects POST bodies"
    ],
    cfLogs: `{
  "Action": "block",
  "ClientIP": "1.2.3.4",
  "RuleID": "100002",
  "RuleGroup": "OWASP",
  "MatchedData": "<script>alert",
  "ClientRequestPath": "/search",
  "EdgeResponseStatus": 403,
  "RayID": "def456"
}`,
    siemLogic: `event.type = "CloudflareFirewallEvent"
AND event.Action = "block"
AND event.RuleGroup = "OWASP"
AND (event.ClientRequestPath CONTAINS "/search"
     OR event.ClientRequestPath CONTAINS "/reviews")
THRESHOLD: 5 events in 60 seconds from same ClientIP`,
    siemSeverity: "High",
    siemTactic: "Initial Access / Client-Side Injection",
    responseWorkflow: [
      { step: 1, action: "Get IP Overview", detail: "Enrich attacker IP with threat intel" },
      { step: 2, action: "Create IP Access Rule", detail: "Block ClientIP at zone level" },
      { step: 3, action: "Update WAF Rule", detail: "Tighten XSS sensitivity for /search and /reviews routes" },
      { step: 4, action: "Create PCAP Request", detail: "Capture 60s for payload forensics" }
    ],
    siem: {
      ruleName: "CF-WAF-XSS-AttackScore",
      ruleType: "Scheduled detection",
      queryLang: "PowerQuery 2.0 · SentinelOne SDL",
      dataSource: "Cloudflare zone HTTP Requests → OCSF HTTP Activity (class_uid 4002)",
      severity: "High",
      validated: false,
      validationNote: "Field paths live-validated (WAFXSSAttackScore is present and populated in HTTP Requests, scoring 96–98 on clean traffic). However 0 XSS requests currently appear in the HTTP Requests feed because Cloudflare's WAF BLOCKS the <script>/onerror payloads with a 403 — and blocked requests are logged to firewall_events, not http_requests. So this rule intentionally targets XSS that BYPASSES the WAF (a low XSS score returning 200). Validation-pending a real bypass or a firewall_events parser to observe the block path. Detection logic and cast direction are confirmed from the SQLi twin on identical fields.",
      importance: "XSS turns a trusted origin into a malware/credential-theft delivery vehicle: stored XSS in a review persists to every visitor; reflected XSS phishes a single victim. The managed WAF blocks textbook payloads, but encoded/DOM/mutation XSS often scores 'likely attack' and still returns 200 — those are the bypasses a SIEM must own.",
      whyDetect: [
        "Safety net for WAF bypasses — a payload that evades the signature set still scores low on Cloudflare's XSS ML model and fires here.",
        "Covers both surfaces the attack hits: reflected (/search) and stored (/reviews) by matching on score, not endpoint.",
        "Signature-independent: encoded, event-handler, and mutation-XSS variants are caught by the score, not a static rule ID.",
        "Aggregated per source so a payload-fuzzing burst is distinguishable from a single stray score.",
      ],
      query: `class_uid=4002 dataSource.cloudflare_dataset='HTTP Requests'
| let xss_score = number(unmapped.WAFXSSAttackScore)
| let waf_score = number(risk_score)
| let status    = number(unmapped.EdgeResponseStatus)
| let uri       = lower(http_request.url.url_string)
| let src_ip    = src_endpoint.ip
| let host      = http_request.url.hostname
| let uri_xss   = uri matches '.*(%3cscript|<script|onerror|onload|javascript:|%6a%61%76%61).*'
| filter xss_score <= 20 OR uri matches '.*(%3cscript|<script|onerror|onload|javascript:|%6a%61%76%61).*'
| group
    attempts   = count(),
    min_xss    = min(xss_score),
    uri_hits   = count(uri_xss),
    bypasses   = count(status = 200),
    paths      = estimate_distinct(http_request.url.path),
    method     = any(http_request.http_method),
    evidence   = min_by(http_request.url.url_string, xss_score),
    ray        = any(metadata.uid),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp)
  by src_ip, host
| filter attempts >= 2
| let detection_time = simpledateformat(last_seen, 'yyyy-MM-dd HH:mm:ss z', 'America/Chicago')
| sort -attempts
| columns detection_time, src_ip, host, attempts, min_xss, uri_hits, bypasses, paths, method, evidence, ray, first_seen
| limit 100`,
      queryExplained: [
        { code: "number(unmapped.WAFXSSAttackScore)", note: "Per-request XSS ML score, string-typed under unmapped.* — cast before comparison. ≤20 = likely XSS (1–99, lower = worse)." },
        { code: "uri_xss = url_string matches (<script|onerror|…)", note: "Belt-and-suspenders pattern match on the raw URI, catching reflected payloads even if the ML score is borderline. Includes URL-encoded variants (%3cscript)." },
        { code: "bypasses = count(status = 200)", note: "Counts requests that returned 200 despite a low XSS score — the actual bypass condition and the highest-priority triage signal." },
        { code: "filter attempts >= 2", note: "Lower cluster gate than SQLi (2) because stored XSS can succeed in a single POST to /reviews." },
      ],
      signals: [
        { signal: "WAFXSSAttackScore ≤ 20", catches: "Reflected & stored XSS", why: "Cloudflare ML scores the script/handler structure regardless of encoding." },
        { signal: "url_string matches script/handler pattern", catches: "Obvious payloads / encoded variants", why: "Direct evidence in the URI even when the score is borderline." },
        { signal: "status = 200 on a low-score request", catches: "WAF bypass (the real incident)", why: "A malicious-scored request that was served, not blocked, is a confirmed evasion." },
      ],
      mitre: [
        { id: "T1059.007", tactic: "Execution", name: "Command and Scripting Interpreter: JavaScript", url: "https://attack.mitre.org/techniques/T1059/007/" },
        { id: "T1190", tactic: "Initial Access", name: "Exploit Public-Facing Application", url: "https://attack.mitre.org/techniques/T1190/" },
      ],
      falsePositive: {
        finding: "Not yet observable live (blocked XSS is absent from http_requests). Anticipated FP class: a page that legitimately accepts HTML/markdown, or a URL containing the literal text 'onload'/'script' for benign reasons.",
        rootCause: "Content-authoring endpoints and analytics pixels can carry script-like tokens.",
        fix: "The attempts ≥ 2 gate plus the status=200 bypass signal focus triage; exclude known rich-text endpoints or require xss_score ≤ 10 on those paths.",
      },
      triage: "SUSPICIOUS — Pending Confirmation. Prioritize rows where bypasses > 0 (served with 200). Decode the evidence URI; if it reached /reviews (stored) treat as higher severity and check whether the payload persisted. Confirm before declaring TP.",
      recommendedResponse: "Block the source IP, tighten XSS sensitivity on /search and /reviews, and for any status=200 bypass purge cached responses and audit stored review content. Full steps in the Response Playbook tab.",
    }
  },
  {
    id: "traversal",
    number: "03",
    title: "Path Traversal / LFI",
    shortDescription: "20 path traversal and local file inclusion payloads targeting asset endpoints",
    category: "WAF",
    categoryColor: "orange",
    severity: "Medium",
    cfProduct: "WAF / Firewall Rules",
    target: "shop.acmecorp.dev /products, /search?file=",
    detectionRule: "CF-WAF-PathTraversal",
    tactic: "Discovery / File Access",
    overview: "Path traversal and local file inclusion (LFI) attempts probe the application for exposed file system access. The script fires 20 payloads across the product detail route and a file-serving parameter, targeting common sensitive paths like /etc/passwd and /proc/self/environ.",
    howItWorks: [
      "Script sends GET /products/../../../etc/passwd and similar traversal sequences",
      "Script also targets /search?file=../../etc/shadow and /proc/self/environ",
      "20 unique payloads covering URL-encoded, double-encoded, and null-byte variants",
      "WAF blocks ../  sequences and known sensitive path strings",
      "Any 200 response would indicate a WAF bypass (expected: all 403)"
    ],
    cfLogs: `{
  "Action": "block",
  "ClientIP": "2.3.4.5",
  "RuleID": "100003",
  "RuleGroup": "OWASP",
  "MatchedData": "../../../etc/passwd",
  "ClientRequestPath": "/products/../../../etc/passwd",
  "EdgeResponseStatus": 403,
  "RayID": "ghi789"
}`,
    siemLogic: `event.type = "CloudflareFirewallEvent"
AND event.Action = "block"
AND (event.MatchedData CONTAINS "../"
     OR event.MatchedData CONTAINS "/etc/passwd"
     OR event.MatchedData CONTAINS "/proc/self")
THRESHOLD: 3 events in 30 seconds from same ClientIP`,
    siemSeverity: "Medium",
    siemTactic: "Discovery / File Access",
    responseWorkflow: [
      { step: 1, action: "Get IP Overview", detail: "Enrich and classify source IP" },
      { step: 2, action: "Create IP Access Rule", detail: "Block ClientIP temporarily (1 hour)" },
      { step: 3, action: "Update WAF Rule", detail: "Add custom rule for detected traversal pattern if not covered" },
      { step: 4, action: "Notify SOC", detail: "Alert with traversal payload and target path" }
    ],
    siem: {
      ruleName: "CF-WAF-PathTraversal-LFI",
      ruleType: "Scheduled detection",
      queryLang: "PowerQuery 2.0 · SentinelOne SDL",
      dataSource: "Cloudflare zone HTTP Requests → OCSF HTTP Activity (class_uid 4002)",
      severity: "Medium",
      validated: true,
      validationNote: "Live-validated against real one-flare.com HTTP Requests (LRQ). shop.one-flare.com returned 8 requests matching traversal URI patterns (../, %2e%2e, /etc/passwd) and/or WAFRCEAttackScore ≤ 20; clean hosts scored 90–97. Cloudflare has no dedicated 'traversal' score, so LFI/path-traversal is caught by the RCE attack score PLUS a raw-URI pattern match — both confirmed present and populated in the feed.",
      importance: "Path traversal and LFI expose the filesystem behind the app — /etc/passwd, cloud-metadata creds (/proc/self/environ), source code, and secrets. In a Workers/edge context it maps to reading bundled assets or SSRF into internal endpoints. It is the classic pre-cursor to credential theft and RCE.",
      whyDetect: [
        "Dual signal: Cloudflare's RCE/LFI ML score AND an explicit URI pattern (../, encoded %2e%2e, sensitive paths) — either fires, catching both ML-detected and literal attempts.",
        "Catches bypasses: traversal that returns 200/404 (not blocked) still matches the URI pattern and aggregates here.",
        "Signature-independent on the score side; robust to URL-encoding and double-encoding on the pattern side.",
        "Per-source clustering separates a directory-fuzzing sweep from a single odd path.",
      ],
      query: `class_uid=4002 dataSource.cloudflare_dataset='HTTP Requests'
| let rce_score = number(unmapped.WAFRCEAttackScore)
| let uri       = lower(http_request.url.url_string)
| let src_ip    = src_endpoint.ip
| let host      = http_request.url.hostname
| let is_trav   = uri matches '.*(\\\\.\\\\./|%2e%2e|/etc/passwd|/etc/shadow|/proc/self|boot\\\\.ini|win\\\\.ini).*'
| filter uri matches '.*(\\\\.\\\\./|%2e%2e|/etc/passwd|/etc/shadow|/proc/self|boot\\\\.ini|win\\\\.ini).*' OR rce_score <= 20
| group
    attempts   = count(),
    trav_hits  = count(is_trav),
    rce_hits   = count(rce_score <= 20),
    min_rce    = min(rce_score),
    paths      = estimate_distinct(http_request.url.path),
    method     = any(http_request.http_method),
    evidence   = max_by(http_request.url.url_string, len(http_request.url.url_string)),
    ray        = any(metadata.uid),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp)
  by src_ip, host
| filter attempts >= 3
| let detection_time = simpledateformat(last_seen, 'yyyy-MM-dd HH:mm:ss z', 'America/Chicago')
| sort -attempts
| columns detection_time, src_ip, host, attempts, trav_hits, rce_hits, min_rce, paths, method, evidence, ray, first_seen
| limit 100`,
      queryExplained: [
        { code: "is_trav = url_string matches (\\\\.\\\\./|%2e%2e|/etc/passwd|…)", note: "Raw-URI pattern for traversal sequences and canonical sensitive targets. Backslashes are doubled for the rule-JSON body; the engine sees \\.\\./ (literal ../). Matches plain and URL-encoded (%2e%2e) forms." },
        { code: "number(unmapped.WAFRCEAttackScore)", note: "Cloudflare folds LFI/traversal into the RCE attack score (there is no standalone traversal score). String-typed under unmapped.* — cast before compare." },
        { code: "filter is_trav OR rce_score <= 20", note: "OR keeps recall high: literal sequences the ML missed AND ML-flagged obfuscation both fire." },
        { code: "max_by(url_string, len(...))", note: "Surfaces the longest URI as evidence — deep traversal chains are the most suspicious." },
      ],
      signals: [
        { signal: "URI matches ../ | %2e%2e | /etc/passwd | /proc/self", catches: "Literal path traversal / LFI", why: "Direct evidence of a filesystem-escape attempt in the request line." },
        { signal: "WAFRCEAttackScore ≤ 20", catches: "Obfuscated / encoded traversal", why: "Cloudflare's ML catches encodings the static pattern misses." },
        { signal: "attempts ≥ 3 per source", catches: "Directory fuzzing sweep", why: "LFI discovery iterates many paths; clustering suppresses one-off noise." },
      ],
      mitre: [
        { id: "T1190", tactic: "Initial Access", name: "Exploit Public-Facing Application", url: "https://attack.mitre.org/techniques/T1190/" },
        { id: "T1083", tactic: "Discovery", name: "File and Directory Discovery", url: "https://attack.mitre.org/techniques/T1083/" },
      ],
      falsePositive: {
        finding: "No FP in validation (clean hosts scored 90–97 and matched no pattern). Residual FP class: legitimate paths that contain '..' in a normalized-away form, or a filename that literally contains 'passwd'.",
        rootCause: "Some SPAs pass relative paths in query params; CDNs may normalize ../ before logging (as seen when curl collapsed ../ to a 404).",
        fix: "Grouping on src_ip and requiring attempts ≥ 3 suppresses incidental single matches; add path allow-lists for known relative-path features.",
      },
      triage: "SUSPICIOUS — Pending Confirmation. Decode the evidence URI and check the response status: a 200 on a /etc/passwd-style request is a likely successful read → escalate. 403/404 indicates a blocked/failed probe. Confirm via origin logs.",
      recommendedResponse: "Temporarily block the source IP, add a custom WAF rule for the observed pattern if uncovered, and review origin/Worker file-access logs for any 200 responses. Full steps in the Response Playbook tab.",
    }
  },
  {
    id: "cred",
    number: "04",
    title: "Credential Stuffing",
    shortDescription: "40 credential combos replayed against the Access-protected portal, rotating IPs",
    category: "Access",
    categoryColor: "purple",
    severity: "Critical",
    cfProduct: "Cloudflare Access / ZTNA",
    target: "portal.acmecorp.dev /login",
    detectionRule: "CF-Access-CredStuffing",
    tactic: "Credential Access",
    overview: "Credential stuffing attacks replay breached username/password pairs against login endpoints. This scenario fires 40 combos from a wordlist against the Cloudflare Access-protected portal, rotating through EU and US source IP headers to evade simple rate limiting. It also runs a brute-force phase with 20 password attempts for a single target account.",
    howItWorks: [
      "Script loads username/password combos from wordlists/usernames.txt and passwords.txt",
      "Sends 40 POST /login requests with rotated X-Forwarded-For headers (EU + US IPs)",
      "Phase 2: brute-forces one target account with 20 password variants",
      "Cloudflare Access logs all failed authentication attempts with UserEmail and ClientIP",
      "Access audit logs flow via Logpush → SentinelOne",
      "STAR rule triggers when 20 distinct UserEmail values fail from the same ClientIP in 300s"
    ],
    cfLogs: `{
  "Action": "login_failed",
  "UserEmail": "user@acmecorp.com",
  "ClientIP": "5.6.7.8",
  "AppDomain": "portal.acmecorp.dev",
  "Timestamp": "2026-03-25T10:00:01Z"
}`,
    siemLogic: `event.type = "CloudflareAccessAudit"
AND event.Action = "login_failed"
AND event.AppDomain = "portal.acmecorp.dev"
THRESHOLD: 20 distinct UserEmail values
  from same ClientIP in 300 seconds`,
    siemSeverity: "Critical",
    siemTactic: "Credential Access",
    responseWorkflow: [
      { step: 1, action: "Get Zero Trust User Failed Logins", detail: "Pull full list of failed attempts for ClientIP" },
      { step: 2, action: "Get IP Overview", detail: "Enrich attacker IP — ASN, country, reputation" },
      { step: 3, action: "Create IP Access Rule", detail: "Mode: block, IP: {{ClientIP}}" },
      { step: 4, action: "Update Firewall Rule", detail: "Block IP across all zones, not just Access" },
      { step: 5, action: "Get User Audit Logs", detail: "Pull last 24h of activity for any accounts that succeeded" },
      { step: 6, action: "Edit Zone", detail: "Escalate security level to 'Under Attack' for portal zone" }
    ],
    siem: {
      ruleName: "CF-Portal-CredStuffing",
      ruleType: "Scheduled detection",
      queryLang: "PowerQuery 2.0 · SentinelOne SDL",
      dataSource: "Cloudflare zone HTTP Requests → OCSF HTTP Activity (class_uid 4002)",
      severity: "Critical",
      validated: false,
      validationNote: "Field paths live-validated — portal.one-flare.com shows POST /login traffic (8 requests observed in the seed) with EdgeResponseStatus populated. The rule's failed_logins ≥ 10 threshold is tuned for the full attack run (40 combos + 20-password brute force); the small manual seed of 8 sits just under threshold, so a live FIRE is validation-pending on a full 04_cred_stuffing.py run. All fields (method, url_string, EdgeResponseStatus, src_endpoint.ip) confirmed present and correctly typed.",
      importance: "Credential stuffing is the top cause of account takeover: breached password lists are replayed at scale until one hits. Against an Access/ZTNA-fronted portal a single valid pair yields a foothold with legitimate creds. The tell is a burst of failed auths — from one IP (brute force) or rotating IPs (stuffing) — that no single failed login reveals.",
      whyDetect: [
        "Volumetric behavior no single event shows — only aggregation over a window exposes the burst.",
        "Covers both variants: high count from one IP (brute force) and high count with many distinct IPs (stuffing with rotated sources).",
        "Keys on failed-auth status codes (400/401/403/429) at login paths, so normal successful logins don't inflate the count.",
        "Groups by host so the portal's login endpoint is watched independently of the shop/api.",
      ],
      query: `class_uid=4002 dataSource.cloudflare_dataset='HTTP Requests'
| let status = number(unmapped.EdgeResponseStatus)
| let m      = http_request.http_method
| let uri    = lower(http_request.url.url_string)
| let src_ip = src_endpoint.ip
| let host   = http_request.url.hostname
| filter m = 'POST' AND uri matches '.*/(login|signin|auth|session).*' AND status in (400, 401, 403, 429)
| group
    failed_logins = count(),
    distinct_ips  = estimate_distinct(src_ip),
    statuses      = array_agg_distinct(status),
    ip_sample     = any(src_ip),
    ray           = any(metadata.uid),
    first_seen    = oldest(timestamp),
    last_seen     = newest(timestamp)
  by host
| filter failed_logins >= 10
| let mode = distinct_ips >= 5 ? 'Credential stuffing (rotating IPs)' : 'Brute force (single/few IPs)'
| let detection_time = simpledateformat(last_seen, 'yyyy-MM-dd HH:mm:ss z', 'America/Chicago')
| sort -failed_logins
| columns detection_time, host, mode, failed_logins, distinct_ips, statuses, ip_sample, ray, first_seen
| limit 100`,
      queryExplained: [
        { code: "filter m='POST' AND uri matches /(login|signin|auth|session)/", note: "Isolate authentication POSTs at the portal. url_string is used because ClientRequestQuery is null in this feed." },
        { code: "status in (400,401,403,429)", note: "Failed-auth / rate-limited responses only — EdgeResponseStatus (client-facing) cast with number(). Successful 200/302 logins are excluded so legit traffic doesn't count." },
        { code: "distinct_ips = estimate_distinct(src_ip)", note: "Distinguishes stuffing (many source IPs) from brute force (one IP). Drives the mode label." },
        { code: "filter failed_logins >= 10", note: "Threshold tuned for the 40-combo attack; lower to ~5 for a quieter portal or raise for a busy one." },
      ],
      signals: [
        { signal: "≥ 10 failed POST /login in the window", catches: "Brute force / credential stuffing", why: "A legitimate user fails a handful of times, not dozens." },
        { signal: "distinct_ips ≥ 5", catches: "Distributed credential stuffing", why: "Rotating source IPs against one login endpoint is the stuffing signature (evades per-IP rate limits)." },
      ],
      mitre: [
        { id: "T1110.004", tactic: "Credential Access", name: "Brute Force: Credential Stuffing", url: "https://attack.mitre.org/techniques/T1110/004/" },
        { id: "T1110.001", tactic: "Credential Access", name: "Brute Force: Password Guessing", url: "https://attack.mitre.org/techniques/T1110/001/" },
      ],
      falsePositive: {
        finding: "Not yet fired live (seed volume below threshold). Anticipated FP class: a broken client/integration retry-looping against /login, or a synthetic uptime monitor hitting the auth endpoint.",
        rootCause: "Automated clients with stale credentials can generate sustained 401s that look like brute force.",
        fix: "Allow-list known monitor IPs; optionally require distinct_ips ≥ 5 OR failed_logins ≥ 20 to separate distributed stuffing from a single misconfigured client.",
      },
      triage: "SUSPICIOUS — Pending Confirmation. Pull the source IP list, check for ANY 200/302 (a success amid the failures = likely compromised account → escalate immediately), and enrich IPs with threat intel before blocking.",
      recommendedResponse: "Block offending IPs, raise the portal zone security level to Under Attack, and force password reset / session revocation on any account that succeeded during the burst. Full steps in the Response Playbook tab.",
    }
  },
  {
    id: "dns",
    number: "05",
    title: "DNS Tunneling / C2 Beaconing",
    shortDescription: "30 DNS queries to algorithmically generated subdomains mimicking dnscat2-style C2",
    category: "Gateway",
    categoryColor: "blue",
    severity: "High",
    cfProduct: "Cloudflare Gateway / DNS",
    target: "c2tunnel.acmecorp-lab.workers.dev",
    detectionRule: "CF-Gateway-DNSTunnel",
    tactic: "Command and Control / Exfiltration",
    overview: "DNS tunneling is a covert channel technique where attackers encode data inside DNS query subdomains to exfiltrate data or receive C2 commands while evading HTTP-level inspection. This scenario generates 30 DNS TXT queries with long base32-encoded subdomain labels (mimicking dnscat2), sent at regular beacon intervals.",
    howItWorks: [
      "Script generates random 16-char base32-encoded subdomain labels per query",
      "Sends TXT record queries to <encoded-data>.c2tunnel.acmecorp-lab.workers.dev",
      "30 queries total, spaced at regular intervals to simulate C2 beaconing",
      "Cloudflare Gateway DNS policy logs all queries (action: allow + log)",
      "Gateway DNS logs include: QueryName, QueryType, DeviceID, UserEmail",
      "STAR rule fires when 10+ TXT queries to same root domain have subdomains >25 chars in 5 minutes"
    ],
    cfLogs: `{
  "QueryName": "aGVsbG93b3JsZA.c2tunnel.acmecorp-lab.workers.dev",
  "QueryType": "TXT",
  "ResolvedIPs": [],
  "Policy": "allowed",
  "DeviceID": "device-abc",
  "UserEmail": "employee@acmecorp.com"
}`,
    siemLogic: `event.type = "CloudflareGatewayDNS"
AND LENGTH(event.QueryName.subdomain) > 25
AND event.QueryType IN ("TXT", "NULL", "CNAME")
THRESHOLD: 10 queries to same root domain
  in 5 minutes`,
    siemSeverity: "High",
    siemTactic: "Command and Control / Exfiltration",
    responseWorkflow: [
      { step: 1, action: "Get IP Overview", detail: "Enrich resolved IP of C2 domain" },
      { step: 2, action: "Create DNS Record", detail: "Sinkhole: create A record for {{C2Domain}} → 0.0.0.0" },
      { step: 3, action: "Create DNS Firewall Cluster", detail: "Block C2 domain at Gateway layer" },
      { step: 4, action: "Create IP Access Rule", detail: "Block source device IP at zone level" },
      { step: 5, action: "Create PCAP Request", detail: "Capture 120s for forensic DNS analysis" },
      { step: 6, action: "Update Log Retention", detail: "Preserve Gateway DNS logs for investigation" }
    ],
    siem: {
      ruleName: "CF-Gateway-DNSTunnel",
      ruleType: "Scheduled detection",
      queryLang: "PowerQuery 2.0 · SentinelOne SDL",
      dataSource: "Cloudflare Gateway DNS → OCSF DNS Activity (class_uid 4003)",
      severity: "High",
      validated: true,
      validationNote: "Live-validated against real Gateway DNS data (LRQ) — 0 false positives after tuning. The attack source scored uniq=33 / long=10 / txt=3 / hi_entropy=28 and fires; benign high-cardinality/long-label domains (cloudapp.azure.com at 67 unique labels, saas.atlassian.com, time.cloudflare.com, google, github) all clear. Runs every 15 minutes over a 15-minute lookback.",
      importance: "DNS is the internet's most overlooked exfiltration and command-and-control channel. It is almost always allowed outbound, rarely deep-inspected, and keeps working when HTTP/S egress is blocked — which is exactly why attackers tunnel data and C2 traffic through it. Because the traffic looks like ordinary name resolution, only behavioral analytics (not signatures) reliably catch it.",
      whyDetect: [
        "Covert channel that bypasses web proxies and TLS inspection — DNS egress is open on nearly every network.",
        "Data-in-DNS exfiltration: stolen data is base32/hex-encoded into query subdomains and reassembled by the attacker's authoritative server.",
        "C2 beaconing: implants receive tasking via TXT/CNAME answers at regular check-in intervals.",
        "DGA / fast-flux rotates through thousands of algorithmic domains to defeat static blocklists — you must detect the pattern, not the domain.",
      ],
      query: `class_uid=4003 dataSource.cloudflare_dataset='Gateway DNS' unmapped.QueryName=*
| let fqdn        = lower(unmapped.QueryName)
| let label       = replace(fqdn, '\\\\..*', '')
| let zone        = replace(fqdn, '^.*\\\\.([^.]+\\\\.[^.]+\\\\.[^.]+)$', '$1')
| let label_len   = len(label)
| let digit_cnt   = len(replace(label, '[^0-9]', ''))
| let digit_ratio = label_len > 0 ? digit_cnt / label_len : 0
| let is_txt      = query.type in:anycase ('txt')
| let src_ip      = src_endpoint.ip
| let host        = device.name
| group
    total_queries = count(),
    uniq_labels   = estimate_distinct(label),
    max_label_len = max(label_len),
    long_labels   = count(label_len >= 40),
    txt_long      = count(is_txt AND label_len >= 20),
    hi_entropy    = count(label_len >= 12 AND digit_ratio >= 0.15),
    device_uid    = any(device.uid),
    evidence      = max_by(unmapped.QueryName, label_len),
    first_seen    = oldest(timestamp),
    last_seen     = newest(timestamp)
  by src_ip, host, zone
| filter (hi_entropy >= 10 AND uniq_labels >= 10) OR (long_labels >= 5 AND uniq_labels >= 5) OR txt_long >= 3
| let reason = txt_long >= 3 ? 'Data-in-DNS exfil (TXT long labels)' : ((long_labels >= 5 AND uniq_labels >= 5) ? 'Long-label DNS tunneling' : 'DGA / high-entropy beaconing')
| let detection_time = simpledateformat(last_seen, 'yyyy-MM-dd HH:mm:ss z', 'America/Chicago')
| sort -uniq_labels
| columns detection_time, src_ip, host, zone, reason, total_queries, uniq_labels, long_labels, txt_long, hi_entropy, max_label_len, evidence, device_uid, first_seen
| limit 100`,
      queryExplained: [
        { code: "class_uid=4003 · dataSource.cloudflare_dataset='Gateway DNS'", note: "Scope to Cloudflare Gateway DNS events, normalized to the OCSF DNS Activity class." },
        { code: "unmapped.QueryName", note: "The queried FQDN. Gotcha: OCSF query.hostname is empty for this source — read unmapped.QueryName or the query returns zero rows." },
        { code: "label = leftmost subdomain", note: "Isolate the leftmost label — where tunneled data and DGA randomness live." },
        { code: "zone = rightmost 3 labels", note: "Registered-zone proxy so the beacon. / update. / c2tunnel. prefixes roll up into one group (no PSL available in PQ)." },
        { code: "digit_ratio = digits / length", note: "Entropy proxy — SDL PQ has no Shannon-entropy function; digit-mixed labels signal machine generation." },
        { code: "group … by src_ip, host, zone", note: "Aggregate per source + zone. Tunneling is a statistical pattern across many queries, never a single event." },
        { code: "filter (clustered + entropy)", note: "Every branch requires clustering, and the high-volume branch is gated on entropy — volume alone is legit for cloud services (see tuning)." },
        { code: "detection_time (first column)", note: "simpledateformat(newest(timestamp)) — the most recent matching query in the window, projected first so the alert leads with when it happened." },
      ],
      signals: [
        { signal: "hi_entropy ≥ 10 AND uniq_labels ≥ 10", catches: "DGA / C2 beaconing", why: "Many DISTINCT, RANDOM (digit-mixed) subdomains. Entropy is what separates a DGA from a cloud service that also resolves many unique names." },
        { signal: "long_labels ≥ 5 AND uniq_labels ≥ 5", catches: "dnscat2 / iodine tunneling", why: "Data chunked across many long, unique labels — not one legitimate long CDN host." },
        { signal: "txt_long ≥ 3", catches: "Data-in-DNS exfiltration", why: "Base32 payloads in TXT query names; DKIM/ESNI put data in the response, not the query name." },
      ],
      mitre: [
        { id: "T1071.004", tactic: "Command & Control", name: "Application Layer Protocol: DNS", url: "https://attack.mitre.org/techniques/T1071/004/" },
        { id: "T1048", tactic: "Exfiltration", name: "Exfiltration Over Alternative Protocol", url: "https://attack.mitre.org/techniques/T1048/" },
        { id: "T1568.002", tactic: "Command & Control", name: "Dynamic Resolution: Domain Generation Algorithms", url: "https://attack.mitre.org/techniques/T1568/002/" },
      ],
      falsePositive: {
        finding: "Two false positives surfaced during live validation: saas.atlassian.com (a 61-char subdomain label) tripped the original \"max_label_len ≥ 50\" rule, and cloudapp.azure.com (67 unique Azure hostnames, zero entropy) tripped the \"uniq_labels ≥ 15\" volume rule.",
        rootCause: "Neither long labels nor high subdomain cardinality is malicious on its own. A DNS label is capped at 63 chars by spec (so one long label can't be told from a tunnel), and legit cloud services (Azure/AWS/CDN) resolve dozens of unique, structured hostnames. What actually distinguishes DNS tunneling / DGA is RANDOMNESS — high-entropy, digit-mixed, or long labels.",
        fix: "Removed the standalone long-label and standalone volume triggers. The high-volume branch is now gated on entropy (hi_entropy ≥ 10 AND uniq_labels ≥ 10); tunneling requires long AND unique; exfil requires repeated long TXT. Re-validated on real data: the two attack runs fire, both Azure and Atlassian clear (0 FP).",
      },
      triage: "Treat an alert as SUSPICIOUS — Pending Confirmation, not a confirmed true positive, until the zone is corroborated with threat intel (domain age, registration, attribution). Then escalate to the response playbook.",
      recommendedResponse: "Sinkhole the C2 zone and block it at the Gateway DNS layer, isolate the source host, and preserve DNS logs + PCAP for forensics. Full steps in the Response Playbook tab.",
    }
  },
  {
    id: "exfil",
    number: "06",
    title: "Data Exfiltration via API",
    shortDescription: "10 authenticated bulk export requests generating 500KB+ responses from the API Worker",
    category: "Workers",
    categoryColor: "red",
    severity: "Critical",
    cfProduct: "Workers + WAF",
    target: "api.acmecorp.dev /api/v1/customers/export",
    detectionRule: "CF-API-BulkExfil",
    tactic: "Exfiltration",
    overview: "Data exfiltration via bulk API exports is a common insider threat and attacker post-compromise technique. This scenario authenticates to the API Worker using valid credentials, then rapidly fires 10 requests to the /customers/export endpoint, each returning 500KB+ of synthetic customer data. The volume and response size anomaly triggers the STAR rule.",
    howItWorks: [
      "Script authenticates: POST /api/v1/auth/login → receives Bearer token",
      "Fires 10 rapid GET /api/v1/customers/export requests with Authorization header",
      "Each response contains 500 synthetic customer records (~500KB per response)",
      "Total exfil volume: ~5MB in under 30 seconds",
      "Cloudflare Workers logs capture ClientIP, path, EdgeResponseBytes",
      "STAR rule fires on 10+ requests to /export with response >100KB from same IP in 120s"
    ],
    cfLogs: `{
  "ClientIP": "9.10.11.12",
  "ClientRequestPath": "/api/v1/customers/export",
  "EdgeResponseBytes": 524288,
  "EdgeResponseStatus": 200,
  "ClientRequestMethod": "GET",
  "RayID": "xyz789"
}`,
    siemLogic: `event.type = "CloudflareHTTPRequest"
AND event.ClientRequestPath CONTAINS "/export"
AND event.EdgeResponseBytes > 100000
THRESHOLD: 10 matching events from same ClientIP
  in 120 seconds`,
    siemSeverity: "Critical",
    siemTactic: "Exfiltration",
    responseWorkflow: [
      { step: 1, action: "Get IP Overview", detail: "Enrich — is this a known corporate IP or external threat?" },
      { step: 2, action: "Create Firewall Rules", detail: "Block requests to /export matching ClientIP immediately" },
      { step: 3, action: "Create IP Access Rule", detail: "IP-level block across all zones" },
      { step: 4, action: "List Workers", detail: "Check for rogue Workers deployed at API route" },
      { step: 5, action: "Update WAF Rule", detail: "Reduce rate limit threshold on /export routes" },
      { step: 6, action: "Create PCAP Request", detail: "Capture remaining traffic from ClientIP" },
      { step: 7, action: "Update Log Retention", detail: "Extend retention for evidence preservation" }
    ],
    siem: {
      ruleName: "CF-API-BulkExfil-Enum",
      ruleType: "Scheduled detection",
      queryLang: "PowerQuery 2.0 · SentinelOne SDL",
      dataSource: "Cloudflare zone HTTP Requests → OCSF HTTP Activity (class_uid 4002)",
      severity: "Critical",
      validated: true,
      validationNote: "Partially live-validated against real api.one-flare.com HTTP Requests (LRQ) — and re-tuned after validation. One source (165.225.36.84) made 16 requests to sensitive endpoints, firing the VOLUME branch (sensitive_hits ≥ 10). Note the initial rule required distinct_paths ≥ 4 for the enumeration branch; live data showed that source hit only 2 distinct paths (/api/v1/customers/export ×8, /api/v1/models ×8), so a pure-enumeration gate did NOT fire — the sensitive_hits ≥ 10 volume branch was added and confirmed to fire (0 other hosts match). The LARGE-RESPONSE branch remains validation-pending: the bulk /export pull returned 401 (auth required) so no >100KB response was produced (max EdgeResponseBytes observed = 348). EdgeResponseBytes is present and numeric-castable — the byte branch fires once an authenticated bulk export succeeds.",
      importance: "Bulk API export is how both external attackers (post-auth) and malicious insiders exfiltrate the crown jewels — customer PII, model weights, training data. Two behaviors betray it: an abnormal RESPONSE SIZE (megabytes where kilobytes are normal) and rapid ENUMERATION of sensitive endpoints. Either alone is a lead; together they are a strong exfil signal.",
      whyDetect: [
        "Response-size anomaly: a /export returning 500KB+ per call, repeated, is the volumetric exfil signature Cloudflare logs natively via EdgeResponseBytes.",
        "Sensitive-endpoint enumeration: a source sweeping /customers, /models, /training-data, /billing is reconnaissance-then-collection, caught even before a large pull succeeds.",
        "Two independent branches (bytes OR enumeration) so the rule fires on the recon phase and on the actual pull.",
        "Per-source aggregation ties the volume/breadth back to one client for a clean investigative pivot.",
      ],
      query: `class_uid=4002 dataSource.cloudflare_dataset='HTTP Requests'
| let bytes  = number(unmapped.EdgeResponseBytes)
| let status = number(unmapped.EdgeResponseStatus)
| let uri    = lower(http_request.url.url_string)
| let src_ip = src_endpoint.ip
| let host   = http_request.url.hostname
| let sensitive = uri matches '.*(/export|/download|/customers|/training-data|/users|include_weights|/models|/billing|format=jsonl).*'
| filter uri matches '.*(/export|/download|/customers|/training-data|/users|include_weights|/models|/billing|format=jsonl).*' OR bytes > 100000
| group
    requests       = count(),
    sensitive_hits = count(sensitive),
    distinct_paths = estimate_distinct(http_request.url.path),
    big_resp       = count(bytes > 100000),
    total_bytes    = sum(bytes),
    max_bytes      = max(bytes),
    successes      = count(status = 200),
    evidence       = max_by(http_request.url.url_string, bytes),
    ray            = any(metadata.uid),
    first_seen     = oldest(timestamp),
    last_seen      = newest(timestamp)
  by src_ip, host
| filter big_resp >= 5 OR sensitive_hits >= 10 OR (sensitive_hits >= 6 AND distinct_paths >= 4)
| let reason = big_resp >= 5 ? 'Bulk data pull (large responses)' : 'Repeated sensitive-endpoint access / enumeration'
| let detection_time = simpledateformat(last_seen, 'yyyy-MM-dd HH:mm:ss z', 'America/Chicago')
| sort -total_bytes
| columns detection_time, src_ip, host, reason, requests, sensitive_hits, distinct_paths, big_resp, max_bytes, total_bytes, successes, evidence, ray, first_seen
| limit 100`,
      queryExplained: [
        { code: "number(unmapped.EdgeResponseBytes)", note: "Client-facing response size, string-typed under unmapped.* — cast before arithmetic. This is the volumetric exfil signal (OriginResponseBytes → http_response.body_length is the origin-side twin)." },
        { code: "sensitive = url_string matches (/export|/customers|/models|…)", note: "Recon/collection targets — the endpoints that return the crown jewels. Catches the enumeration phase before a large pull lands." },
        { code: "filter big_resp >= 5 OR sensitive_hits >= 10 OR (sensitive_hits >= 6 AND distinct_paths >= 4)", note: "Three branches: ≥5 large responses (bulk pull), OR ≥10 sensitive requests from one source (validated live — 16 repeated /export+/models pulls), OR a broader sweep (≥6 hits over ≥4 paths). The bare-boolean `sensitive` is only used inside count(); the pre-filter inlines the regex because PowerQuery `filter` rejects a bare boolean let." },
        { code: "successes = count(status = 200)", note: "How many sensitive requests actually returned data (200) vs were denied (401/403). A high successes count on a bulk pull is the critical escalation trigger." },
      ],
      signals: [
        { signal: "≥ 5 responses over 100KB from one source", catches: "Bulk data exfiltration", why: "Repeated megabyte responses to an API client is abnormal — normal calls are kilobytes." },
        { signal: "≥ 8 sensitive-endpoint hits over ≥ 4 paths", catches: "Endpoint enumeration / staged collection", why: "Sweeping /customers, /models, /training-data, /billing is deliberate crown-jewel recon." },
        { signal: "successes (200) on sensitive paths", catches: "Successful exfil vs blocked attempt", why: "Distinguishes a realized breach from a denied probe." },
      ],
      mitre: [
        { id: "T1530", tactic: "Collection", name: "Data from Cloud Storage", url: "https://attack.mitre.org/techniques/T1530/" },
        { id: "T1119", tactic: "Collection", name: "Automated Collection", url: "https://attack.mitre.org/techniques/T1119/" },
        { id: "T1567.002", tactic: "Exfiltration", name: "Exfiltration to Cloud Storage", url: "https://attack.mitre.org/techniques/T1567/002/" },
      ],
      falsePositive: {
        finding: "Enumeration branch fired cleanly on the attack source with no other host matching. Anticipated FP class: a legitimate analytics/ETL job or a data-science client that legitimately bulk-pulls exports on a schedule.",
        rootCause: "Sanctioned batch jobs produce the same large-response / broad-endpoint pattern as exfil.",
        fix: "Allow-list known ETL service-account IPs / user-agents; optionally require successes > 0 AND off-hours timing to focus on anomalous pulls.",
      },
      triage: "SUSPICIOUS — Pending Confirmation. Check successes and total_bytes: a source with many 200s and multi-MB total is a likely realized exfil → escalate. Correlate the src_ip/token to a known service account before blocking (avoid breaking a legit ETL).",
      recommendedResponse: "Block the source IP, rate-limit /export routes, revoke the API token used, and preserve logs+PCAP. If successes indicate data left, open an incident and notify data-protection. Full steps in the Response Playbook tab.",
    }
  },
  {
    id: "bot",
    number: "07",
    title: "Polymorphic AI Bot / Scraper",
    shortDescription: "Rogue AI scraper rotates User-Agents every request while its TLS fingerprint (JA4) stays constant",
    category: "Bot Management",
    categoryColor: "cyan",
    severity: "High",
    cfProduct: "Cloudflare Bot Management",
    target: "api.one-flare.com /api/v1/*",
    detectionRule: "CF-BotMgmt-PolymorphicScraper",
    tactic: "Reconnaissance / Automated Collection",
    overview: "A rogue AI agent scrapes NovaMind and probes for training data and model weights, rotating its User-Agent every request to masquerade as many browsers, SDKs, and crawlers. But its TLS fingerprint (JA3/JA4) never changes — a Python client cannot disguise its TLS handshake. The tell is many User-Agents behind a single constant JA4 with a low Bot Management score.",
    howItWorks: [
      "Script fires ~30 requests to sensitive API paths (/api/v1/models, /training-data, /users, /billing)",
      "User-Agent is randomized per request across 16 browser/SDK/agent-framework strings",
      "The TLS fingerprint (JA4) is identical on every request — the underlying client is one Python process",
      "Cloudflare Bot Management scores each request (low BotScore) and emits JA4 + BotTags",
      "The many-UA / one-JA4 / low-score mismatch is the detection signal"
    ],
    cfLogs: `{
  "ClientIP": "1.2.3.4",
  "ClientRequestUserAgent": "LangChain/0.1.0",
  "JA4": "t13d1812h1_85036bcba153_b26ce05bbdd6",
  "BotScore": 12,
  "BotTags": ["automated","ai-crawler"],
  "ClientRequestPath": "/api/v1/training-data"
}`,
    siemLogic: `event.type = "CloudflareHTTPRequest"
AND distinct(UserAgent) >= 5
AND distinct(JA4) = 1
AND BotScore <= 30
THRESHOLD: >=10 requests from same JA4`,
    siemSeverity: "High",
    siemTactic: "Reconnaissance / Automated Collection",
    responseWorkflow: [
      { step: 1, action: "Get IP Overview", detail: "Enrich ClientIP and ASN — hosting/datacenter ranges corroborate automation" },
      { step: 2, action: "Create WAF Rule", detail: "Challenge or block requests matching the constant JA4 fingerprint" },
      { step: 3, action: "Enable Bot Fight Mode", detail: "Raise Bot Management enforcement on the api zone" },
      { step: 4, action: "Notify SOC", detail: "Report the JA4, UA list, and probed endpoints" }
    ],
    siem: {
      ruleName: "CF-BotMgmt-PolymorphicScraper",
      ruleType: "Scheduled detection",
      queryLang: "PowerQuery 2.0 · SentinelOne SDL",
      dataSource: "Cloudflare zone HTTP Requests + Bot Management → OCSF HTTP Activity (class_uid 4002)",
      severity: "High",
      validated: false,
      validationNote: "VALIDATION-PENDING — data not flowing. The HTTP Requests feed is live, but the Bot Management fields this rule depends on (unmapped.BotScore, unmapped.JA4, unmapped.BotTags, and the parser's ja4_fingerprint_list[0].value) are ALL null in the current data: the http_requests Logpush job is not yet emitting Bot Management fields (Bot Management may be provisioned but the fields are not on the log stream). The rule is written against the documented/parser-mapped field names and the exact JA4 the attack presents; it will validate once Bot Management fields appear. UI wiring for this scenario is also pending.",
      importance: "Polymorphic bots defeat User-Agent-based blocking by rotating identities every request. TLS fingerprinting (JA3/JA4) is the durable identifier because the client's TLS stack can't be faked per-request. Detecting the many-UA / one-JA4 mismatch is how you catch a scraper, a credential-testing tool, or a rogue AI agent that a UA allow-list would miss.",
      whyDetect: [
        "JA4 is forgery-resistant: one Python/requests process presents one JA4 regardless of the User-Agent it claims.",
        "Rotating UAs behind a single JA4 is a definitive automation tell no legitimate browser produces.",
        "Low Bot Management score corroborates the mismatch with Cloudflare's own ML verdict.",
        "Catches AI/agent-framework scrapers (LangChain/AutoGen/CrewAI UAs) hunting training data and model weights.",
      ],
      query: `class_uid=4002 dataSource.cloudflare_dataset='HTTP Requests' unmapped.JA4=*
| let ja4     = unmapped.JA4
| let bot     = number(unmapped.BotScore)
| let ua      = http_request.user_agent
| let src_ip  = src_endpoint.ip
| let host    = http_request.url.hostname
| group
    requests     = count(),
    distinct_ua  = estimate_distinct(ua),
    distinct_ja4 = estimate_distinct(ja4),
    min_bot      = min(bot),
    paths        = estimate_distinct(http_request.url.path),
    ip_sample    = any(src_ip),
    ua_sample    = array_agg_distinct(ua),
    first_seen   = oldest(timestamp),
    last_seen    = newest(timestamp)
  by ja4, host
| filter distinct_ua >= 5 AND distinct_ja4 = 1 AND requests >= 10 AND min_bot <= 30
| let detection_time = simpledateformat(last_seen, 'yyyy-MM-dd HH:mm:ss z', 'America/Chicago')
| sort -requests
| columns detection_time, ja4, host, requests, distinct_ua, min_bot, paths, ip_sample, ua_sample, first_seen
| limit 100`,
      queryExplained: [
        { code: "unmapped.JA4=* (initial filter)", note: "Require a JA4 fingerprint present. The parser maps JA4 → ja4_fingerprint_list[0].value, but bracket-indexed fields can 500 in group/columns, so read the raw unmapped.JA4 scalar." },
        { code: "group by ja4, host", note: "Aggregate all traffic sharing one TLS fingerprint — the durable client identity, immune to UA rotation." },
        { code: "distinct_ua >= 5 AND distinct_ja4 = 1", note: "The core mismatch: many claimed identities, one real TLS client. This is the polymorphic-bot signature." },
        { code: "min_bot <= 30", note: "Cloudflare Bot Management score (lower = more bot-like) corroborates. number()-cast; string-typed under unmapped.*." },
      ],
      signals: [
        { signal: "≥ 5 distinct User-Agents on one JA4", catches: "Polymorphic / UA-rotating bot", why: "A single TLS client claiming many browser identities is impossible for a real browser." },
        { signal: "BotScore ≤ 30", catches: "Automated client", why: "Cloudflare's own ML flags the request as bot-like, corroborating the fingerprint mismatch." },
        { signal: "≥ 10 requests / broad path set", catches: "Scraping / recon sweep", why: "Volume across many sensitive endpoints indicates collection, not casual browsing." },
      ],
      mitre: [
        { id: "T1595", tactic: "Reconnaissance", name: "Active Scanning", url: "https://attack.mitre.org/techniques/T1595/" },
        { id: "T1119", tactic: "Collection", name: "Automated Collection", url: "https://attack.mitre.org/techniques/T1119/" },
        { id: "AML.T0002", tactic: "ATLAS Reconnaissance", name: "Acquire Public AI Artifacts / Model Recon", url: "https://atlas.mitre.org/techniques/AML.T0002" },
      ],
      falsePositive: {
        finding: "Not yet observable (Bot Management fields null). Anticipated FP class: a legitimate SDK or mobile app that presents one JA4 but rotates UA strings across versions, or a shared corporate egress where many users share a TLS-terminating proxy JA4.",
        rootCause: "Some shared proxies / SDKs legitimately map one JA4 to several UAs.",
        fix: "Require min_bot ≤ 30 (already present) to demand Cloudflare's bot verdict, allow-list known SDK JA4s, and raise the distinct_ua threshold for known proxy fingerprints.",
      },
      triage: "SUSPICIOUS — Pending Confirmation. Confirm the JA4 belongs to a scripting stack (not a shared browser fingerprint), review the probed paths for sensitive targets (models/training-data), and enrich the IP/ASN before enforcement.",
      recommendedResponse: "Challenge or block the JA4 via a WAF rule, raise Bot Fight Mode on the api zone, and review what the scraper accessed. Full steps in the Response Playbook tab.",
    }
  },
  {
    id: "promptinj",
    number: "08",
    title: "Prompt Injection / LLM Jailbreak",
    shortDescription: "Burst of jailbreak/injection payloads POSTed to the Pyxis chat endpoint to leak the system prompt and secrets",
    category: "AI Security",
    categoryColor: "pink",
    severity: "High",
    cfProduct: "Cloudflare Firewall for AI / AI Gateway",
    target: "api.one-flare.com /api/v1/chat",
    detectionRule: "CF-FirewallForAI-PromptInjection",
    tactic: "AI Attack / LLM Prompt Injection",
    overview: "The rogue AI agent bombards the customer-facing Pyxis chatbot (/api/v1/chat) with prompt-injection and jailbreak payloads — DAN-style overrides, system-prompt exfiltration, indirect/context injection, and Log4Shell-in-a-prompt — trying to leak the system prompt, secrets, training data, and tenant PII or bypass guardrails.",
    howItWorks: [
      "Script POSTs 16 jailbreak/injection payloads to /api/v1/chat, one per request",
      "Payloads include DAN overrides, system-prompt exfil, ${jndi:...} and template-injection strings",
      "The injection text lives in the POST body — a forward HTTP proxy does not log it, so the visible signal is POST rate + endpoint",
      "Cloudflare Firewall for AI / AI Gateway (when enabled) scores each prompt's injection risk",
      "SentinelOne alerts on high-risk-score bursts, or (fallback) on POST volume to the chat endpoint from one source"
    ],
    cfLogs: `{
  "ClientIP": "1.2.3.4",
  "ClientRequestMethod": "POST",
  "ClientRequestPath": "/api/v1/chat",
  "EdgeResponseStatus": 200,
  "llm_injection_score": 0.97
}`,
    siemLogic: `event.type = "CloudflareHTTPRequest"
AND method = "POST"
AND path CONTAINS "/api/v1/chat"
THRESHOLD: >=10 POSTs from same ClientIP
  in the window`,
    siemSeverity: "High",
    siemTactic: "AI Attack / LLM Prompt Injection",
    responseWorkflow: [
      { step: 1, action: "Get IP Overview", detail: "Enrich the source IP of the injection burst" },
      { step: 2, action: "Create WAF Rule", detail: "Rate-limit or block POSTs to /api/v1/chat from the source" },
      { step: 3, action: "Enable Firewall for AI", detail: "Turn on prompt-injection scoring / guardrails on the AI Gateway" },
      { step: 4, action: "Notify SOC", detail: "Report the source, request rate, and endpoint for LLM-abuse review" }
    ],
    siem: {
      ruleName: "CF-FirewallForAI-PromptInjection",
      ruleType: "Scheduled detection",
      queryLang: "PowerQuery 2.0 · SentinelOne SDL",
      dataSource: "Cloudflare zone HTTP Requests (fallback) / Firewall for AI (ideal) → OCSF HTTP Activity (class_uid 4002)",
      severity: "High",
      validated: false,
      validationNote: "VALIDATION-PENDING on two counts. (1) The /api/v1/chat endpoint was not exercised in this seed, so there is no chat POST traffic yet to fire against. (2) The IDEAL signal — Cloudflare Firewall for AI / AI Gateway injection scores — is not present in the feed (no llm_injection_score / prompt-risk field observed under unmapped.*); the injection text itself is in the POST body, which HTTP-request logs do not capture. This rule therefore uses the FALLBACK behavioral signal that IS validatable on the live schema: POST volume to the chat endpoint from one source (method, url_string, src_endpoint.ip all confirmed present). UI wiring for this scenario is also pending.",
      importance: "Prompt injection is the #1 LLM attack (OWASP LLM01): a crafted prompt overrides the system instructions to leak the system prompt, exfiltrate secrets/PII, or bypass safety guardrails. For a customer-facing chatbot with backend access, a successful jailbreak is a data breach. Even without body inspection, a burst of chat POSTs from one source is an abuse tell worth surfacing.",
      whyDetect: [
        "Behavioral fallback that works TODAY on HTTP-request logs — an injection barrage is a POST burst to the chat endpoint from one source.",
        "No single POST is suspicious; the volume/velocity from one client is the signal, which only aggregation reveals.",
        "Upgrades cleanly: when Firewall for AI scores are ingested, swap the volume gate for a high-injection-score gate on the same rule shape.",
        "Covers rogue-agent abuse of the LLM (jailbreak, system-prompt exfil, guardrail bypass) that the app layer may silently serve 200.",
      ],
      query: `class_uid=4002 dataSource.cloudflare_dataset='HTTP Requests'
| let m      = http_request.http_method
| let uri    = lower(http_request.url.url_string)
| let status = number(unmapped.EdgeResponseStatus)
| let src_ip = src_endpoint.ip
| let host   = http_request.url.hostname
| filter m = 'POST' AND uri matches '.*/api/v1/chat.*'
| group
    posts        = count(),
    distinct_ua  = estimate_distinct(http_request.user_agent),
    blocked      = count(status = 403 OR status = 429),
    served       = count(status = 200),
    ray          = any(metadata.uid),
    first_seen   = oldest(timestamp),
    last_seen    = newest(timestamp)
  by src_ip, host
| filter posts >= 10
| let detection_time = simpledateformat(last_seen, 'yyyy-MM-dd HH:mm:ss z', 'America/Chicago')
| sort -posts
| columns detection_time, src_ip, host, posts, distinct_ua, served, blocked, ray, first_seen
| limit 100`,
      queryExplained: [
        { code: "filter m='POST' AND uri matches /api/v1/chat", note: "Isolate chat-completion POSTs to the Pyxis endpoint. The injection payload is in the body (not logged) — endpoint + method is the observable." },
        { code: "group by src_ip, host", note: "Aggregate per source: an injection barrage is many POSTs from one client in a short window." },
        { code: "served = count(status=200)", note: "Chat requests the app actually answered — the ones where a jailbreak could have succeeded and returned data." },
        { code: "filter posts >= 10", note: "Volume gate for the burst. WHEN Firewall for AI scores land, replace this with min(injection_score-equivalent) or count(high-risk prompts)." },
      ],
      signals: [
        { signal: "≥ 10 POSTs to /api/v1/chat from one source", catches: "Prompt-injection / jailbreak barrage", why: "Automated injection fuzzing hammers the endpoint; a real user chats at human pace." },
        { signal: "served (200) count", catches: "Prompts the LLM answered", why: "Answered injection attempts are where system-prompt / secret leakage could occur." },
        { signal: "(future) high Firewall-for-AI injection score", catches: "Confirmed injection payloads", why: "Content-based confirmation once AI Gateway scoring is ingested — upgrades this from volumetric to definitive." },
      ],
      mitre: [
        { id: "AML.T0054", tactic: "ATLAS Initial Access", name: "LLM Prompt Injection", url: "https://atlas.mitre.org/techniques/AML.T0054" },
        { id: "AML.T0057", tactic: "ATLAS Exfiltration", name: "LLM Data Leakage", url: "https://atlas.mitre.org/techniques/AML.T0057" },
        { id: "T1499", tactic: "Impact", name: "Endpoint Denial of Service (resource abuse)", url: "https://attack.mitre.org/techniques/T1499/" },
      ],
      falsePositive: {
        finding: "Not yet observable (no chat traffic seeded). Anticipated FP class: a power user or a legitimate automated integration (support bot, load test) making many chat calls in a short window.",
        rootCause: "Volumetric-only detection cannot tell a heavy legitimate user from an attacker without body/score inspection.",
        fix: "Ingest Firewall for AI injection scores and gate on those instead of raw volume; until then allow-list known integration IPs and tune the posts threshold to the endpoint's normal peak rate.",
      },
      triage: "SUSPICIOUS — Pending Confirmation, and LOW-CONFIDENCE without content inspection. Confirm via the app's LLM/guardrail logs (were injection strings present? did any response leak the system prompt?) before escalating. The volumetric alert is a lead, not proof.",
      recommendedResponse: "Rate-limit /api/v1/chat from the source, enable Cloudflare Firewall for AI scoring/guardrails, and review LLM output logs for leaked system-prompt or secrets. Full steps in the Response Playbook tab.",
    }
  }
]
