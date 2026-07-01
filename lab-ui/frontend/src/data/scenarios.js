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
    target: "shop.novamind.ai /search",
    detectionRule: "CF-WAF-SQLi-Burst",
    tactic: "Initial Access / Exploitation",
    overview: "This scenario simulates an attacker probing the NovaMind webstore for SQL injection vulnerabilities. The script fires 23 unique SQLi payloads at the search endpoint, cycling through classic patterns like UNION SELECT, OR 1=1, and DROP TABLE. The Cloudflare WAF intercepts and blocks these requests, generating RuleID 100001 (OWASP group) events that feed into SentinelOne via Logpush.",
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
    ]
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
    target: "shop.novamind.ai /search, /reviews",
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
    ]
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
    target: "shop.novamind.ai /products, /search?file=",
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
    ]
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
    target: "portal.novamind.ai /login",
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
  "UserEmail": "user@novamind.ai",
  "ClientIP": "5.6.7.8",
  "AppDomain": "portal.novamind.ai",
  "Timestamp": "2026-03-25T10:00:01Z"
}`,
    siemLogic: `event.type = "CloudflareAccessAudit"
AND event.Action = "login_failed"
AND event.AppDomain = "portal.novamind.ai"
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
    ]
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
    target: "c2tunnel.novamind-lab.workers.dev",
    detectionRule: "CF-Gateway-DNSTunnel",
    tactic: "Command and Control / Exfiltration",
    overview: "DNS tunneling is a covert channel technique where attackers encode data inside DNS query subdomains to exfiltrate data or receive C2 commands while evading HTTP-level inspection. This scenario generates 30 DNS TXT queries with long base32-encoded subdomain labels (mimicking dnscat2), sent at regular beacon intervals.",
    howItWorks: [
      "Script generates random 16-char base32-encoded subdomain labels per query",
      "Sends TXT record queries to <encoded-data>.c2tunnel.novamind-lab.workers.dev",
      "30 queries total, spaced at regular intervals to simulate C2 beaconing",
      "Cloudflare Gateway DNS policy logs all queries (action: allow + log)",
      "Gateway DNS logs include: QueryName, QueryType, DeviceID, UserEmail",
      "STAR rule fires when 10+ TXT queries to same root domain have subdomains >25 chars in 5 minutes"
    ],
    cfLogs: `{
  "QueryName": "aGVsbG93b3JsZA.c2tunnel.novamind-lab.workers.dev",
  "QueryType": "TXT",
  "ResolvedIPs": [],
  "Policy": "allowed",
  "DeviceID": "device-abc",
  "UserEmail": "employee@novamind.ai"
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
    ]
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
    target: "api.novamind.ai /api/v1/customers/export",
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
    ]
  }
]
