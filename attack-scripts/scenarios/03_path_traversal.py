#!/usr/bin/env python3
"""Scenario 3 — Path traversal and LFI on shop Worker."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
from config import SHOP_URL, LOGS_DIR, TLS_VERIFY
from utils import print_banner, print_request, jitter, random_headers, SessionLog

TRAVERSAL_PATHS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/shadow",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "../../../../windows/win.ini",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/../../../../../../etc/passwd",
]

QUERY_PAYLOADS = [
    "../etc/passwd",
    "../../../../etc/passwd",
    "....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "../../../proc/self/environ",
]


def run() -> dict:
    print_banner("Scenario 3 — Path Traversal / LFI", f"Target: {SHOP_URL}/products/ + query params")
    log = SessionLog("03_path_traversal", LOGS_DIR)
    blocked = passed = 0

    # Path traversal via product ID route
    for path in TRAVERSAL_PATHS:
        url = f"{SHOP_URL}/products/{path}"
        try:
            r = requests.get(url, headers=random_headers(), timeout=10, allow_redirects=False, verify=TLS_VERIFY)
            note = "WAF block" if r.status_code == 403 else "reached worker"
            print_request("GET", f"/products/{path[:40]}", r.status_code, note)
            log.log("GET", url, r.status_code, path, note)
            if r.status_code == 403:
                blocked += 1
            else:
                passed += 1
        except requests.RequestException as e:
            print_request("GET", url, 0, str(e))
        jitter(0.3, 1.0)

    # LFI via query string
    for payload in QUERY_PAYLOADS:
        url = f"{SHOP_URL}/search"
        try:
            r = requests.get(url, params={"q": payload, "file": payload},
                             headers=random_headers(), timeout=10, verify=TLS_VERIFY)
            note = "WAF block" if r.status_code == 403 else "reached worker"
            print_request("GET", f"/search?file={payload[:30]}", r.status_code, note)
            log.log("GET", url, r.status_code, payload, note)
            if r.status_code == 403:
                blocked += 1
            else:
                passed += 1
        except requests.RequestException as e:
            print_request("GET", url, 0, str(e))
        jitter(0.3, 1.0)

    log.save()
    total = len(TRAVERSAL_PATHS) + len(QUERY_PAYLOADS)
    return {"scenario": "Path Traversal", "total": total, "blocked": blocked, "passed": passed,
            "detection": "CF-WAF-PathTraversal"}


if __name__ == "__main__":
    run()
