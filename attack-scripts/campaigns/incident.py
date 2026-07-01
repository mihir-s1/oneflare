"""
campaigns/incident.py — Incident webhook helper for NovaMind status page.

Posts to OUR novamind-api /api/incident endpoint using the INCIDENT_KEY env var.
The target URL is built from config.py — never an external host.

Usage (from backend engine or campaign code):
    from campaigns.incident import signal_incident
    signal_incident(active=True, severity="critical", affected=["Pyxis Chat API"])
    signal_incident(active=False)  # clear incident
"""

import sys
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add attack-scripts root to path so config imports cleanly when this module
# is loaded from any working directory.
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config import API_URL, INCIDENT_KEY  # noqa: E402


def signal_incident(
    active: bool,
    title: str = "Agentic AI Breakout",
    severity: str = "critical",
    affected: list = None,
    phase: int = 0,
    phase_name: str = "",
    message: str = "",
    timeout: int = 8,
) -> bool:
    """
    POST to novamind-api /api/incident to set or clear the Pyxis status banner.

    Parameters
    ----------
    active      : True = set incident active; False = clear
    title       : Incident title shown on /status page
    severity    : "critical" | "high" | "medium" | "low"
    affected    : list of affected service names, e.g. ["Pyxis Chat API"]
    phase       : current CTF box/phase number (0 = not phase-specific)
    phase_name  : human-readable phase name
    message     : additional context for the status page
    timeout     : request timeout in seconds

    Returns
    -------
    True if the POST succeeded (2xx), False otherwise.
    """
    if not INCIDENT_KEY:
        # Silently skip — lab may not have an incident webhook configured.
        return False

    target = f"{API_URL}/api/incident"

    # Field shape MUST match novamind-api POST /api/incident, which authenticates
    # via the body field `key` (data.key === env.INCIDENT_KEY) and reads
    # `affected_services` + `started_at`. See cloudflare/workers/api/src/index.js.
    import datetime
    payload = {
        "key": INCIDENT_KEY,
        "active": active,
        "title": title,
        "severity": severity if active else "none",
        "affected_services": affected or ["Pyxis Chat API"],
        "started_at": datetime.datetime.utcnow().isoformat() + "Z" if active else None,
        "phase": phase,
        "phase_name": phase_name,
        "message": message or (
            f"CTF campaign '{title}' active — Box {phase}: {phase_name}"
            if active else
            f"CTF campaign '{title}' stopped — incident cleared"
        ),
    }

    headers = {"Content-Type": "application/json"}

    try:
        resp = requests.post(
            target,
            json=payload,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
        )
        return resp.status_code < 300
    except requests.RequestException:
        return False
