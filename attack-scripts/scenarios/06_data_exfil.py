#!/usr/bin/env python3
"""Scenario 6 — Bulk data exfiltration via API export endpoint."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
from config import API_URL, API_USERNAME, API_PASSWORD, LOGS_DIR, TLS_VERIFY
from utils import print_banner, print_request, jitter, random_headers, SessionLog
from rich.console import Console

console = Console()


def run() -> dict:
    print_banner("Scenario 6 — Data Exfiltration", f"Target: {API_URL}/api/v1/customers/export")
    log = SessionLog("06_data_exfil", LOGS_DIR)
    blocked = passed = 0

    # Phase 1: Authenticate to get token.
    # Use a clean browser User-Agent for the login: a real exfil actor with
    # valid/stolen API creds authenticates through a normal client. random_headers()
    # rotates in scanner UAs (sqlmap/Nikto/masscan) that the WAF managed ruleset 403s,
    # which would abort the whole scenario before any exfil traffic is generated.
    # The *suspicious* signal lives in Phases 2–3 (enumeration + bulk export volume),
    # not in the login request.
    BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
    console.print("\n[yellow]Phase 1: Authenticate to obtain API token[/yellow]")
    token = None
    try:
        r = requests.post(f"{API_URL}/api/v1/auth/login",
                          json={"username": API_USERNAME, "password": API_PASSWORD},
                          headers=random_headers({"User-Agent": BROWSER_UA}), timeout=10, verify=TLS_VERIFY)
        if r.status_code == 200:
            token = r.json().get("token")
            console.print(f"  [green]AUTH OK[/green] — token: {token}")
            log.log("POST", f"{API_URL}/api/v1/auth/login", 200, f"{API_USERNAME}:****", "authenticated")
        else:
            console.print(f"  [red]AUTH FAILED[/red] {r.status_code}")
            log.log("POST", f"{API_URL}/api/v1/auth/login", r.status_code, "", "failed")
    except requests.RequestException as e:
        console.print(f"  [red]ERROR[/red] {e}")

    if not token:
        console.print("[red]Cannot proceed without token.[/red]")
        log.save()
        return {"scenario": "Data Exfil", "total": 1, "blocked": 1, "passed": 0, "detection": "CF-API-BulkExfil"}

    auth_headers = random_headers({"Authorization": f"Bearer {token}"})

    # Phase 2: Enumerate endpoints before exfil
    console.print("\n[yellow]Phase 2: API enumeration[/yellow]")
    for path in ["/api/v1/health", "/api/v1/customers?limit=5", "/api/v1/orders"]:
        try:
            r = requests.get(f"{API_URL}{path}", headers=auth_headers, timeout=10, verify=TLS_VERIFY)
            print_request("GET", path, r.status_code, f"{len(r.content)} bytes")
            log.log("GET", f"{API_URL}{path}", r.status_code, "", f"{len(r.content)} bytes")
            passed += 1 if r.status_code == 200 else 0
        except requests.RequestException as e:
            print_request("GET", path, 0, str(e))
        jitter(0.5, 1.0)

    # Phase 3: Bulk export — 10 rapid requests (generates burst in logs)
    console.print("\n[yellow]Phase 3: Bulk export — 10 rapid requests to /customers/export[/yellow]")
    for i in range(10):
        fmt = "csv" if i % 3 == 0 else "json"
        url = f"{API_URL}/api/v1/customers/export?format={fmt}"
        try:
            r = requests.get(url, headers=random_headers({"Authorization": f"Bearer {token}"}),
                             timeout=30, stream=True, verify=TLS_VERIFY)
            size = sum(len(chunk) for chunk in r.iter_content(8192))
            note = f"{size:,} bytes — {'WAF block' if r.status_code == 403 else 'exfil success'}"
            print_request("GET", f"/api/v1/customers/export?format={fmt}", r.status_code, note)
            log.log("GET", url, r.status_code, fmt, note)
            if r.status_code == 403:
                blocked += 1
            else:
                passed += 1
        except requests.RequestException as e:
            print_request("GET", url, 0, str(e))
        jitter(0.1, 0.5)

    log.save()
    return {"scenario": "Data Exfil", "total": 14, "blocked": blocked, "passed": passed,
            "detection": "CF-API-BulkExfil"}


if __name__ == "__main__":
    run()
