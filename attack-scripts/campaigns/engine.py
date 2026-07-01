"""
campaigns/engine.py — Shared HTTP sender for all drip-flow campaigns.

Ported from cf-attack-sim-v2/attacks/engine.py and repointed at NovaMind
infrastructure. Import this module; do not invoke via subprocess.

AUTHORIZED LAB USE ONLY — targets are NovaMind workers on *.novamind-lab.workers.dev
(or a custom domain set via CLOUDFLARE_DOMAIN). Never target external hosts.
"""

import random
import time

import requests
import urllib3
from requests.exceptions import RequestException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Source-IP pool for X-Forwarded-For / X-Real-IP spoofing.
# These are well-known Tor exit / scanner ranges used in threat-intel feeds —
# their presence in WAF logs is what makes the signal detectable.
# ---------------------------------------------------------------------------
FAKE_IPS = [
    "185.220.101.47",   # Tor exit node
    "194.165.16.72",    # Eastern Europe
    "103.21.244.0",     # Asia Pacific
    "45.142.212.100",   # Russia
    "91.108.4.0",       # Telegram bot range
    "198.144.121.93",   # Known scanner range
    "212.102.63.0",
    "162.247.74.27",    # US Tor
    "77.247.181.162",   # Netherlands Tor
    "171.25.193.77",    # Sweden Tor
    "89.234.157.254",   # France
    "46.165.230.5",     # Germany
]

# Timing constants — override via fire_many delay_range arg.
# backend engine sets LIVE_INTERVAL_SECONDS=30, LIVE_BATCH_SIZE=5.
PRESEED_DELAY_RANGE = (0.05, 0.2)   # fast, low noise
LIVE_DELAY_RANGE    = (3.0, 8.0)    # realistic human/bot cadence


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _next_id(log_counter):
    """Increment a mutable [int] counter and return the new value."""
    log_counter[0] += 1
    return log_counter[0]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def send_request(
    url,
    method="GET",
    params=None,
    data=None,
    headers=None,
    label="",
    log_buffer=None,
    log_counter=None,
    stop_flag=None,
    phase=1,
    industry="",
):
    """
    Fire one HTTP request and append a structured result dict to log_buffer.

    Parameters
    ----------
    url          : full URL string
    method       : "GET" or "POST"
    params       : dict of query-string params (GET)
    data         : dict of form body (POST)
    headers      : dict merged on top of base headers
    label        : human-readable description for the log entry
    log_buffer   : collections.deque (or list) the caller owns; appended in-place
    log_counter  : mutable [int] list used as a shared counter; e.g. [0]
    stop_flag    : threading.Event — checked before every request
    phase        : integer phase / box number (1-indexed)
    industry     : campaign key string ("financial", "healthcare", "saas", "ctf")

    Returns
    -------
    HTTP status code (int), or 0 on connection error / stop.
    """
    if stop_flag and stop_flag.is_set():
        return 0

    fake_ip = random.choice(FAKE_IPS)
    base_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "X-Forwarded-For": fake_ip,
        "X-Real-IP": fake_ip,
    }
    if headers:
        base_headers.update(headers)

    try:
        if method == "POST":
            resp = requests.post(
                url,
                data=data,
                headers=base_headers,
                timeout=8,
                allow_redirects=False,
                verify=False,
            )
        else:
            resp = requests.get(
                url,
                params=params,
                headers=base_headers,
                timeout=8,
                allow_redirects=False,
                verify=False,
            )

        status = resp.status_code
        blocked = status in (403, 429, 444)

        entry = {
            "id":       _next_id(log_counter) if log_counter else 0,
            "type":     "blocked" if blocked else "passed",
            "method":   method,
            "url":      url,
            "status":   status,
            "blocked":  blocked,
            "label":    label or str(params or data or "")[:80],
            "ip":       fake_ip,
            "phase":    phase,
            "industry": industry,
        }
        if log_buffer is not None:
            log_buffer.append(entry)
        return status

    except RequestException as exc:
        entry = {
            "id":       _next_id(log_counter) if log_counter else 0,
            "type":     "error",
            "method":   method,
            "url":      url,
            "status":   0,
            "blocked":  False,
            "label":    f"Connection error: {exc}",
            "ip":       fake_ip,
            "phase":    phase,
            "industry": industry,
        }
        if log_buffer is not None:
            log_buffer.append(entry)
        return 0


def log_phase_event(message, phase, industry, log_buffer, log_counter, entry_type="phase"):
    """
    Append a non-request phase-transition marker to log_buffer.
    The frontend renders these as timeline banners between request rows.
    """
    entry = {
        "id":       _next_id(log_counter) if log_counter else 0,
        "type":     entry_type,
        "phase":    phase,
        "industry": industry,
        "message":  message,
        "url":      "",
        "method":   "",
        "status":   0,
        "blocked":  False,
        "label":    message,
        "ip":       "",
    }
    if log_buffer is not None:
        log_buffer.append(entry)


def sleep_between_requests(mode="preseed", custom_range=None):
    """
    Pause between individual requests.

    mode         : "preseed" (fast, 50-200ms) or "live" (3-8s)
    custom_range : (min, max) float tuple — overrides mode when provided
    """
    if custom_range:
        time.sleep(random.uniform(*custom_range))
    elif mode == "live":
        time.sleep(random.uniform(*LIVE_DELAY_RANGE))
    else:
        time.sleep(random.uniform(*PRESEED_DELAY_RANGE))
