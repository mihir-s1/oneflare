#!/usr/bin/env python3
"""Scenario 11 — Operation HIPAA Breach (Healthcare campaign), streamed phase-by-phase.

Thin runner: imports the real campaign from campaigns/ and calls its own
fire_many() per phase — zero attack-logic duplication, so behavior matches
ThreatOps exactly. Prints a "── Phase N: <name> ──" banner before each phase,
then streams every request result as fire_many appends it to log_buffer.
"""
import os
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import config as cfg
from campaigns import CAMPAIGNS

CAMPAIGN_KEY = "healthcare"


def _resolve_target(entry):
    """CAMPAIGN_TARGET_OVERRIDE points this run at a specific host (e.g. your
    own lab). Otherwise resolves via config.py's role-based URL, which is
    itself override-aware (SHOP_URL_OVERRIDE / API_URL_OVERRIDE / domain)."""
    override = os.getenv("CAMPAIGN_TARGET_OVERRIDE")
    if override:
        return override.rstrip("/")
    role = entry.get("target_role", "api")
    return {"shop": cfg.SHOP_URL, "portal": cfg.PORTAL_URL, "api": cfg.API_URL}[role]


def run():
    entry = CAMPAIGNS[CAMPAIGN_KEY]
    target = _resolve_target(entry)
    count = int(os.getenv("CAMPAIGN_COUNT", "8"))
    delay = float(os.getenv("ATTACK_DELAY", "0.3"))
    jitter = float(os.getenv("ATTACK_JITTER", "0.2"))
    delay_range = (delay, delay + jitter)

    print(f"Campaign: {entry['name']}  ->  target {target}", flush=True)

    log_buffer, log_counter, stop_flag = [], [0], threading.Event()
    seen = 0
    for phase in entry["PHASES"]:
        print(f"\n── Phase {phase['number']}: {phase['name']} ──", flush=True)
        phase["fire_many"](count, delay_range, target, log_buffer, log_counter, stop_flag)
        while seen < len(log_buffer):
            e = log_buffer[seen]
            seen += 1
            if e.get("type") == "phase":
                continue  # banner already printed above
            mark = "BLOCKED" if e.get("blocked") else str(e.get("status"))
            print(f"  [{mark}] {e.get('method')} {e.get('url')} — {e.get('label')}", flush=True)

    print("\nCampaign complete.", flush=True)


if __name__ == "__main__":
    run()
