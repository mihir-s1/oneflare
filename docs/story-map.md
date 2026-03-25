# OneFlare Story Map — Attack → Detection → Response

Each scenario is a self-contained story: attack script generates traffic → Cloudflare logs it → SentinelOne fires a detection → Hyperautomation runs a response workflow.

---

## Scenario 1: SQL Injection Attack on Webstore

**Target**: `shop.acmecorp.dev`
**Attack vector**: WAF

### Attack Script
```bash
# attack-scripts/sqli_attack.sh
# Sends SQLi payloads to the webstore search endpoint
# Generates WAF block events with RuleID 100001 (SQLi group)
```

Payloads:
- `?q=' OR 1=1--`
- `?q=1; DROP TABLE products--`
- `?q=UNION SELECT username,password FROM users--`

### Cloudflare Logs Generated
```json
{
  "Action": "block",
  "ClientIP": "1.2.3.4",
  "RuleID": "100001",
  "RuleGroup": "OWASP",
  "MatchedData": "' OR 1=1",
  "ClientRequestPath": "/search",
  "EdgeResponseStatus": 403,
  "RayID": "abc123"
}
```

### SentinelOne Detection (STAR Rule)
**Name**: `CF-WAF-SQLi-Burst`
**Logic**:
```
event.type = "CloudflareFirewallEvent"
AND event.Action = "block"
AND event.RuleGroup = "OWASP"
AND event.ClientRequestPath CONTAINS "/search"
THRESHOLD: 5 events in 60 seconds from same ClientIP
```
**Severity**: High
**Tactic**: Initial Access / Exploitation

### Hyperautomation Workflow: `WAF-SQLi-Auto-Block`
```
Trigger: S1 detection "CF-WAF-SQLi-Burst" fires
  │
  ├─ 1. Get IP Overview (ClientIP)
  │      → Enrich: ASN, country, threat reputation
  │
  ├─ 2. Create an IP Access rule
  │      → Mode: block, IP: {{ClientIP}}, Notes: "Auto-blocked: SQLi burst"
  │
  ├─ 3. Create PCAP request
  │      → Capture 60s of traffic from {{ClientIP}} for forensics
  │
  ├─ 4. Update log retention flag
  │      → Extend retention on zone to preserve evidence
  │
  └─ 5. [Notify] Post alert to SIEM/ticket with RayID, IP, payload
```

---

## Scenario 2: Credential Stuffing on Employee Portal

**Target**: `portal.acmecorp.dev`
**Attack vector**: Cloudflare Access / ZTNA

### Attack Script
```bash
# attack-scripts/cred_stuff.sh
# Replays a list of username:password combos against the Access login
# Generates Zero Trust failed login events
```

Pattern: 200+ unique usernames, rotating through 5 IPs over 10 minutes.

### Cloudflare Logs Generated
```json
{
  "Action": "login_failed",
  "UserEmail": "user@acmecorp.com",
  "ClientIP": "5.6.7.8",
  "AppDomain": "portal.acmecorp.dev",
  "Timestamp": "2026-03-25T10:00:01Z"
}
```

### SentinelOne Detection (STAR Rule)
**Name**: `CF-Access-CredStuffing`
**Logic**:
```
event.type = "CloudflareAccessAudit"
AND event.Action = "login_failed"
AND event.AppDomain = "portal.acmecorp.dev"
THRESHOLD: 20 distinct UserEmail values from same ClientIP in 300 seconds
```
**Severity**: Critical
**Tactic**: Credential Access

### Hyperautomation Workflow: `Access-CredStuff-Lockdown`
```
Trigger: S1 detection "CF-Access-CredStuffing" fires
  │
  ├─ 1. Get zero trust user failed logins
  │      → Pull full list of failed attempts for the ClientIP
  │
  ├─ 2. Get IP Overview (ClientIP)
  │      → Enrich attacker IP
  │
  ├─ 3. Create an IP Access rule
  │      → Mode: block, IP: {{ClientIP}}
  │
  ├─ 4. Update a firewall rule (or Create firewall rules)
  │      → Block the IP across all zones, not just Access
  │
  ├─ 5. Get user audit logs
  │      → Pull last 24h of activity for any accounts that succeeded
  │
  └─ 6. Edit Zone
         → Escalate zone security level to "Under Attack" for portal
```

---

## Scenario 3: Impossible Travel (Access)

**Target**: `portal.acmecorp.dev`
**Attack vector**: Cloudflare Access

### Attack Script
```bash
# attack-scripts/impossible_travel.sh
# Authenticates as the same user from two geographically distant IPs
# within a 5-minute window (e.g., US + EU simultaneously)
```

### Cloudflare Logs Generated
Two successful logins for the same `UserEmail`:
- `ClientIP: 104.x.x.x` (US) at T+0
- `ClientIP: 185.x.x.x` (Germany) at T+3min

### SentinelOne Detection (STAR Rule)
**Name**: `CF-Access-ImpossibleTravel`
**Logic**:
```
event.type = "CloudflareAccessAudit"
AND event.Action = "login_succeeded"
GROUP BY UserEmail
HAVING COUNT(DISTINCT GeoCountry) >= 2
WITHIN 10 minutes
```
**Severity**: Critical
**Tactic**: Initial Access / Account Takeover

### Hyperautomation Workflow: `Access-ImpossibleTravel-Response`
```
Trigger: S1 detection "CF-Access-ImpossibleTravel" fires
  │
  ├─ 1. Get zero trust users (filter: {{UserEmail}})
  │      → Confirm user identity and account state
  │
  ├─ 2. Get user audit logs
  │      → Pull full session history for the user
  │
  ├─ 3. Create an IP Access rule
  │      → Block BOTH IPs associated with the impossible travel
  │
  ├─ 4. Get zero trust user failed logins
  │      → Check if preceded by failed attempts
  │
  └─ 5. [Manual gate] Notify SOC analyst — require approval to
         suspend user account (out of scope for auto-revoke)
```

---

## Scenario 4: DNS Tunneling / C2 Beaconing

**Target**: Cloudflare Gateway (DNS)
**Attack vector**: Gateway DNS logs

### Attack Script
```bash
# attack-scripts/dns_tunnel.sh
# Generates high-frequency DNS queries to algorithmically generated subdomains
# Mimics DNS tunneling (dnscat2-style) and C2 beaconing
```

Pattern:
- 1 query every 30s to `<random-16char-subdomain>.c2tunnel.net`
- Subdomains contain base64-encoded "data" (simulated exfil)

### Cloudflare Logs Generated
```json
{
  "QueryName": "aGVsbG93b3JsZA.c2tunnel.net",
  "QueryType": "TXT",
  "ResolvedIPs": [],
  "Policy": "allowed",
  "DeviceID": "device-abc",
  "UserEmail": "employee@acmecorp.com"
}
```

### SentinelOne Detection (STAR Rule)
**Name**: `CF-Gateway-DNSTunnel`
**Logic**:
```
event.type = "CloudflareGatewayDNS"
AND LENGTH(event.QueryName.subdomain) > 25
AND event.QueryType IN ("TXT", "NULL", "CNAME")
THRESHOLD: 10 queries to same root domain in 5 minutes
```
**Severity**: High
**Tactic**: Command and Control / Exfiltration

### Hyperautomation Workflow: `Gateway-DNSTunnel-Sinkhole`
```
Trigger: S1 detection "CF-Gateway-DNSTunnel" fires
  │
  ├─ 1. Get IP Overview (resolved IP of C2 domain)
  │      → Enrich C2 infrastructure
  │
  ├─ 2. Create DNS Record
  │      → Sinkhole: create A record for {{C2Domain}} → 0.0.0.0
  │
  ├─ 3. Create DNS Firewall Cluster
  │      → Block the C2 domain at Gateway layer
  │
  ├─ 4. Create an IP Access rule
  │      → Block source device IP at zone level
  │
  ├─ 5. Create PCAP request
  │      → Capture 120s for forensic DNS analysis
  │
  └─ 6. Update log retention flag
         → Preserve Gateway DNS logs for investigation
```

---

## Scenario 5: Data Exfiltration via API

**Target**: `api.acmecorp.dev`
**Attack vector**: Workers logs + WAF

### Attack Script
```bash
# attack-scripts/data_exfil.sh
# Authenticates to the API then bulk-pulls data via /export endpoint
# Generates large response body events and high request rate
```

Pattern: 50 requests to `/api/v1/customers/export` in 2 minutes, each returning 500KB+ response.

### Cloudflare Logs Generated
```json
{
  "ClientIP": "9.10.11.12",
  "ClientRequestPath": "/api/v1/customers/export",
  "EdgeResponseBytes": 524288,
  "EdgeResponseStatus": 200,
  "ClientRequestMethod": "GET",
  "RayID": "xyz789"
}
```

### SentinelOne Detection (STAR Rule)
**Name**: `CF-API-BulkExfil`
**Logic**:
```
event.type = "CloudflareHTTPRequest"
AND event.ClientRequestPath CONTAINS "/export"
AND event.EdgeResponseBytes > 100000
THRESHOLD: 10 matching events from same ClientIP in 120 seconds
```
**Severity**: Critical
**Tactic**: Exfiltration

### Hyperautomation Workflow: `API-Exfil-Containment`
```
Trigger: S1 detection "CF-API-BulkExfil" fires
  │
  ├─ 1. Get IP Overview (ClientIP)
  │      → Enrich — is this a known corporate IP or external?
  │
  ├─ 2. Create firewall rules
  │      → Block requests to /export matching ClientIP immediately
  │
  ├─ 3. Create an IP Access rule
  │      → IP-level block across all zones
  │
  ├─ 4. List Workers
  │      → Check for rogue Workers deployed at the API route
  │
  ├─ 5. Update a WAF rule
  │      → Reduce rate limit threshold on /export routes
  │
  ├─ 6. Create PCAP request
  │      → Capture remaining traffic from ClientIP
  │
  └─ 7. Update log retention flag
         → Extend retention for evidence preservation
```

---

## Summary Matrix

| Scenario | CF Product | Log Type | S1 Detection | Key Response Actions |
|---|---|---|---|---|
| SQLi Attack | WAF | FirewallEvents | CF-WAF-SQLi-Burst | Block IP, PCAP, extend retention |
| Credential Stuffing | Access | AccessAudit | CF-Access-CredStuffing | Block IP, Zone Under Attack mode |
| Impossible Travel | Access | AccessAudit | CF-Access-ImpossibleTravel | Block IPs, audit user, SOC gate |
| DNS Tunneling | Gateway | GatewayDNS | CF-Gateway-DNSTunnel | Sinkhole DNS, DNS Firewall, PCAP |
| Data Exfiltration | Workers + WAF | HTTPRequest | CF-API-BulkExfil | Firewall rule, WAF tune, PCAP |
