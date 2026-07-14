#!/usr/bin/env python3
"""Scenario 7 — Polymorphic AI Bot / Scraper (Cloudflare Bot Management).

A rogue AI agent scrapes NovaMind and probes for training data / model weights.
It rotates its User-Agent every request to look like a legit browser, SDK, or
crawler — but its TLS fingerprint (JA3/JA4) stays CONSTANT, because a Python
client can't disguise its TLS handshake no matter what User-Agent it sends.
That mismatch (many UAs, one JA4, low BotScore) is the Bot Management tell.

Maps to the doc's Box 2 (polymorphic bot). MITRE T1595 (Active Scanning) +
T1119 (Automated Collection); ATLAS AML.T0002 (AI model/ data reconnaissance).

Detection data path:
  - Best: Cloudflare zone HTTP requests Logpush with Bot Management fields
    (BotScore, JA4, BotTags) — the strongest signal.
  - Fallback (Gateway HTTP, forward proxy): rotating/suspicious User-Agents +
    high request volume to NovaMind endpoints (http_request.user_agent).
"""
import random
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
from config import API_URL, LOGS_DIR, TLS_VERIFY
from utils import print_banner, SessionLog
from rich.console import Console

console = Console()

# The constant JA4 a Python requests client presents regardless of User-Agent —
# the CTF clue used in Bot Management PowerQuery hunts.
JA4_CONSTANT = "t13d1812h1_85036bcba153_b26ce05bbdd6"

# User-Agents rotate to mimic browsers, SDKs, crawlers, and agentic frameworks
# (the rogue-AI narrative) — but the TLS fingerprint underneath never changes.
ROTATING_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "novamind-python-sdk/2.1.0",
    "novamind-node-sdk/1.4.2",
    "axios/1.6.2",
    "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
    "Twitterbot/1.0",
    "LinkedInBot/1.0",
    "facebookexternalhit/1.1",
    # Agentic framework signatures — the rogue AI showing its hand
    "LangChain/0.1.0",
    "AutoGen/0.2.0",
    "CrewAI/0.11.0",
    "AgentExecutor/1.0 (OpenAI-compatible)",
    "ReActAgent/2.0 (NovaMind-internal)",
]

# What the scraper goes after — training data, model weights, user lists, admin.
BOT_PROBE_PATHS = [
    "/api/v1/models",
    "/api/v1/training-data",
    "/api/v1/training-data?format=jsonl&export=true",
    "/api/v1/models?include_weights=true",
    "/api/v1/users?limit=1000",
    "/api/v1/billing",
    "/dashboard",
    "/admin",
]

REQUESTS = 30


def run() -> dict:
    print_banner("Scenario 7 — Polymorphic AI Bot / Scraper",
                 "Rotating User-Agents, constant JA3/JA4 — Cloudflare Bot Management")
    log = SessionLog("07_ai_bot", LOGS_DIR)
    console.print(
        f"[dim]TLS fingerprint stays constant across every request "
        f"(JA4 ≈ {JA4_CONSTANT}) even as the User-Agent rotates — the tell that a "
        f"single automated client is masquerading as many.[/dim]\n"
    )

    console.print(f"[yellow]Phase 1: High-frequency scraping sweep — {REQUESTS} requests, UA rotates each time[/yellow]")
    total = blocked = passed = 0
    for _ in range(REQUESTS):
        ua = random.choice(ROTATING_USER_AGENTS)
        path = random.choice(BOT_PROBE_PATHS)
        url = f"{API_URL}{path}"
        try:
            r = requests.get(url, headers={"User-Agent": ua, "Accept": "application/json"}, timeout=8, verify=TLS_VERIFY)
            status = r.status_code
            if status in (403, 429):
                console.print(f"  [red]BLOCKED[/red] {status}  {path}  [dim]{ua[:38]}[/dim]")
                blocked += 1
            else:
                console.print(f"  [dim]{status}[/dim]  {path}  [dim]{ua[:38]}[/dim]")
                passed += 1
            log.log("GET", url, status, ua, "bot-probe")
        except Exception as e:
            console.print(f"  [red]ERROR[/red] {path} — {e}")
            log.log("GET", url, 0, ua, f"ERROR: {e}")
        total += 1
        time.sleep(random.uniform(0.2, 0.8))

    log.save()
    return {
        "scenario": "Polymorphic AI Bot",
        "total": total,
        "blocked": blocked,
        "passed": passed,
        "detection": "CF-BotMgmt-PolymorphicScraper",
        "ja4": JA4_CONSTANT,
    }


if __name__ == "__main__":
    run()
