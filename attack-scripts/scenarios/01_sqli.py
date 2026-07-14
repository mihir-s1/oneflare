#!/usr/bin/env python3
"""Scenario 1 — SQL Injection on webstore search endpoint."""
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
from config import SHOP_URL, LOGS_DIR, TLS_VERIFY
from utils import print_banner, print_request, jitter, random_headers, SessionLog

PAYLOADS = [
    # Union-based
    "' UNION SELECT null,null,null--",
    "' UNION SELECT username,password,null FROM users--",
    "1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
    # Error-based
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    # Boolean-based blind
    "' AND 1=1--",
    "' AND 1=2--",
    "' OR 1=1--",
    "' OR 'x'='x",
    "admin'--",
    "' OR 1=1#",
    # Time-based blind
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--",
    "1; SELECT SLEEP(5)--",
    # Stacked queries
    "'; DROP TABLE products--",
    "'; INSERT INTO users VALUES('hacked','hacked')--",
    "'; UPDATE users SET password='pwned' WHERE '1'='1",
    # Classic
    "1' OR '1'='1",
    "' OR ''='",
    "x' OR 1=1--",
    "x' AND email IS NULL; --",
    "'; exec xp_cmdshell('whoami')--",
    # Encoded variants
    "%27%20OR%201%3D1--",
    "1%27+UNION+SELECT+null%2Cnull--",
]


def run() -> dict:
    print_banner("Scenario 1 — SQL Injection", f"Target: {SHOP_URL}/search")
    log = SessionLog("01_sqli", LOGS_DIR)
    blocked = passed = 0

    for payload in PAYLOADS:
        url = f"{SHOP_URL}/search"
        params = {"q": payload}
        try:
            r = requests.get(url, params=params, headers=random_headers(), timeout=10, allow_redirects=False, verify=TLS_VERIFY)
            note = "WAF block" if r.status_code == 403 else "passed WAF" if r.status_code == 200 else ""
            print_request("GET", f"{url}?q={payload[:40]}...", r.status_code, note)
            log.log("GET", url, r.status_code, payload, note)
            if r.status_code == 403:
                blocked += 1
            else:
                passed += 1
        except requests.RequestException as e:
            print_request("GET", url, 0, str(e))
        jitter(0.3, 1.2)

    log.save()
    return {"scenario": "SQLi", "total": len(PAYLOADS), "blocked": blocked, "passed": passed,
            "detection": "CF-WAF-SQLi-Burst"}


if __name__ == "__main__":
    run()
