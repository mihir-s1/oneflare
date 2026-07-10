"""
campaign_engine.py — Asyncio drip-flow engine for ThreatOps campaigns.

Design
------
- Module-level state (single uvicorn process, no threads race).
- Blocking campaign fire_* calls run via asyncio.to_thread so the event loop
  is never blocked.
- A threading.Event is used as the stop_flag (safe to check from both the
  campaign sync code and async wrappers without extra bridging).
- Log entries are collected in a collections.deque(maxlen=500) keyed by an
  ever-incrementing integer id so the frontend can poll with ?since=<id>.

Exported public API (consumed by main.py)
-----------------------------------------
  get_campaigns_meta()         → dict   (all campaign + phase data, no callables)
  launch(campaign, mode, ...)  → None   (raises ValueError if already running)
  stop()                       → None
  clear_incident()             → None
  get_logs(since)              → list[dict]
  get_status()                 → dict
"""

import asyncio
import os
import sys
import threading
from collections import deque
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# PYTHONPATH bootstrap — attack-scripts must be importable.
# Docker sets PYTHONPATH=/app/attack-scripts via docker-compose.
# For local dev we add the path here as a fallback.
# ---------------------------------------------------------------------------
_ATTACK_SCRIPTS = Path(__file__).parent.parent.parent / "attack-scripts"
# In-container the mount lands at /app/attack-scripts
_ATTACK_SCRIPTS_CONTAINER = Path("/app/attack-scripts")

for _p in (_ATTACK_SCRIPTS_CONTAINER, _ATTACK_SCRIPTS):
    if _p.exists() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# Delay campaign import until we know the path is set; catch ImportError
# gracefully so the rest of the API stays alive even if the package is absent.
try:
    from campaigns import CAMPAIGNS                          # noqa: E402
    from campaigns.incident import signal_incident           # noqa: E402
    _CAMPAIGNS_AVAILABLE = True
except ImportError as _e:
    CAMPAIGNS = {}
    _CAMPAIGNS_AVAILABLE = False
    _IMPORT_ERROR = str(_e)

# ---------------------------------------------------------------------------
# Timing constants (tunable)
# ---------------------------------------------------------------------------
LIVE_INTERVAL_SECONDS          = int(os.getenv("LIVE_INTERVAL_SECONDS",          "30"))
LIVE_PHASE_DURATION_SECONDS    = int(os.getenv("LIVE_PHASE_DURATION_SECONDS",    "180"))
CTF_LIVE_PHASE_DURATION_SECONDS= int(os.getenv("CTF_LIVE_PHASE_DURATION_SECONDS", "90"))
LIVE_BATCH_SIZE                = int(os.getenv("LIVE_BATCH_SIZE",                 "5"))

PRESEED_VOLUMES = {
    "low":    20,
    "medium": 60,
    "high":   150,
}

# ---------------------------------------------------------------------------
# Module-level shared state
# ---------------------------------------------------------------------------
_log_buffer: deque  = deque(maxlen=500)
_log_counter: list  = [0]           # mutable single-element list — engine increments it
_stop_event         = threading.Event()

_state = {
    "running":  False,
    "campaign": None,   # e.g. "ctf"
    "phase":    None,   # current phase number (int) or None
}

_task: Optional[asyncio.Task] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _signal_shop_incident(active: bool) -> bool:
    """
    Flip the SoleDrop shop /status page. The CTF is hardcoded to the SoleDrop
    shop (CAMPAIGNS['ctf']['target_url']), which owns its own /api/incident + KV
    — separate from the api/portal workers. Authenticated by the body `key`
    (INCIDENT_KEY); silently no-ops if that secret isn't set.
    """
    try:
        import datetime
        import requests
        import config as _cfg
        key = getattr(_cfg, "INCIDENT_KEY", "") or ""
        if not key:
            return False
        target = CAMPAIGNS.get("ctf", {}).get("target_url", "https://shop.soledrop.co")
        payload = {
            "key":      key,
            "active":   active,
            "title":    "Drop-Day Bot Swarm Detected" if active else "",
            "severity": "critical" if active else "none",
            "affected_services": ["Storefront", "Checkout API", "Customer Accounts"] if active else [],
            "started_at": datetime.datetime.utcnow().isoformat() + "Z" if active else None,
            "message":  ("Automated checkout traffic detected during the drop — mitigation in progress."
                         if active else "Incident cleared."),
        }
        requests.post(f"{target}/api/incident", json=payload,
                      timeout=8, allow_redirects=False, verify=False)
        return True
    except Exception:
        return False


def _resolve_target(campaign_key: str) -> str:
    """
    Build the base URL for a campaign. An explicit per-campaign `target_url`
    (e.g. the CTF's hardcoded SoleDrop shop) wins; otherwise `target_role`
    drives which shared worker we hit.
    """
    # A hardcoded target_url on the campaign entry overrides role-based routing.
    entry = CAMPAIGNS.get(campaign_key, {})
    if entry.get("target_url"):
        return entry["target_url"]
    # Import config lazily (it reads env vars / .env.local)
    try:
        import config as _cfg
        role = entry["target_role"]
        return {
            "shop":   _cfg.SHOP_URL,
            "portal": _cfg.PORTAL_URL,
            "api":    _cfg.API_URL,
        }.get(role, _cfg.API_URL)
    except ImportError:
        # Fallback: build from env directly
        domain = os.getenv("CLOUDFLARE_DOMAIN", "novamind-lab.workers.dev")
        if "workers.dev" in domain:
            return f"https://novamind-api.{domain}"
        return f"https://api.{domain}"


def _append_system_event(msg: str, campaign_key: str, phase: int):
    """Add a non-request system marker to the log buffer."""
    _log_counter[0] += 1
    _log_buffer.append({
        "id":       _log_counter[0],
        "type":     "system",
        "message":  msg,
        "campaign": campaign_key,
        "phase":    phase,
        "url":      "",
        "method":   "",
        "status":   0,
        "blocked":  False,
        "label":    msg,
        "ip":       "",
        "industry": campaign_key,
    })


# ---------------------------------------------------------------------------
# Async drip-flow runners
# ---------------------------------------------------------------------------

async def _run_fire_one(phase_obj, target, campaign_key):
    """Run one fire_one call off-thread so it doesn't block the event loop."""
    await asyncio.to_thread(
        phase_obj["fire_one"],
        target,
        _log_buffer,
        _log_counter,
        _stop_event,
    )


async def _live_loop(campaign_key: str, start_phase: int):
    """
    Live mode: cycle through phases.
    Each phase:
      - fire LIVE_BATCH_SIZE fire_one calls, ~3-8s apart (handled inside fire_one)
      - wait LIVE_INTERVAL_SECONDS
      - repeat until phase duration elapses
      - advance to next phase
    """
    import asyncio as _aio

    campaign  = CAMPAIGNS[campaign_key]
    phases    = campaign["PHASES"]
    target    = _resolve_target(campaign_key)
    is_ctf    = campaign_key == "ctf"
    phase_dur = CTF_LIVE_PHASE_DURATION_SECONDS if is_ctf else LIVE_PHASE_DURATION_SECONDS

    # Build the subset of phases to run
    phase_list = [p for p in phases if p["number"] >= start_phase]

    for phase_obj in phase_list:
        if _stop_event.is_set():
            break

        pnum = phase_obj["number"]
        _state["phase"] = pnum
        _append_system_event(
            f"Phase {pnum} started: {phase_obj['name']}",
            campaign_key, pnum,
        )

        phase_start = _aio.get_event_loop().time()
        phase_end   = phase_start + phase_dur

        while _aio.get_event_loop().time() < phase_end:
            if _stop_event.is_set():
                break

            # Fire a batch of LIVE_BATCH_SIZE fire_one calls
            for _ in range(LIVE_BATCH_SIZE):
                if _stop_event.is_set():
                    break
                await _run_fire_one(phase_obj, target, campaign_key)
                # Polite sleep inside the batch — fire_one already sleeps
                # internally (3-8s) but we add a tiny yield for the event loop
                await _aio.sleep(0)

            # Wait between batches
            try:
                await _aio.wait_for(
                    _aio.shield(_aio.sleep(LIVE_INTERVAL_SECONDS)),
                    timeout=LIVE_INTERVAL_SECONDS + 1,
                )
            except _aio.TimeoutError:
                pass
            except _aio.CancelledError:
                break

        _append_system_event(
            f"Phase {pnum} complete: {phase_obj['name']}",
            campaign_key, pnum,
        )


async def _preseed_loop(campaign_key: str, phase_selector, volume: str):
    """
    Preseed mode: fire_many across selected phases, fast batch.
    Volume budget is split evenly across selected phases.
    """
    campaign   = CAMPAIGNS[campaign_key]
    phases     = campaign["PHASES"]
    target     = _resolve_target(campaign_key)
    total      = PRESEED_VOLUMES.get(volume, PRESEED_VOLUMES["medium"])

    if phase_selector == "all":
        selected = phases
    else:
        selected = [p for p in phases if p["number"] == int(phase_selector)]

    per_phase  = max(1, total // len(selected)) if selected else total
    delay_range = (0.05, 0.2)   # fast preseed cadence

    for phase_obj in selected:
        if _stop_event.is_set():
            break
        pnum = phase_obj["number"]
        _state["phase"] = pnum
        _append_system_event(
            f"Preseed Phase {pnum}: {phase_obj['name']} ({per_phase} requests)",
            campaign_key, pnum,
        )
        await asyncio.to_thread(
            phase_obj["fire_many"],
            per_phase,
            delay_range,
            target,
            _log_buffer,
            _log_counter,
            _stop_event,
        )
        _append_system_event(
            f"Preseed Phase {pnum} complete",
            campaign_key, pnum,
        )


async def _engine_task(campaign_key: str, mode: str, phase, volume: str):
    """Top-level async task — manages CTF incident signalling and hands off."""
    is_ctf = campaign_key == "ctf"

    if is_ctf:
        await asyncio.to_thread(_signal_shop_incident, True)

    try:
        if mode == "live":
            start_phase = 1 if phase == "all" else int(phase)
            await _live_loop(campaign_key, start_phase)
        else:
            await _preseed_loop(campaign_key, phase, volume)
    finally:
        _state["running"]  = False
        _state["campaign"] = None
        _state["phase"]    = None
        _append_system_event("Campaign stopped", campaign_key, 0)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_campaigns_meta() -> dict:
    """
    Return all campaign + phase metadata, stripping out the callable fire_*
    functions (not JSON-serialisable).
    """
    result = {}
    for key, campaign in CAMPAIGNS.items():
        phases_meta = []
        for p in campaign["PHASES"]:
            phase_copy = {k: v for k, v in p.items() if k not in ("fire_one", "fire_many")}
            phases_meta.append(phase_copy)

        result[key] = {
            "key":         key,
            "name":        campaign["name"],
            "campaign":    campaign["campaign"],
            "description": campaign.get("description", ""),
            "color":       campaign["color"],
            "icon":        campaign["icon"],
            "target_role": campaign["target_role"],
            "target":      _resolve_target(key),
            "num_phases":  campaign["num_phases"],
            "phases":      phases_meta,
        }
    if not _CAMPAIGNS_AVAILABLE:
        result["_error"] = f"campaigns package not importable: {_IMPORT_ERROR}"
    return result


def launch(
    campaign_key: str,
    mode: str,
    phase,
    volume: str,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """
    Start the drip-flow engine.

    Raises
    ------
    ValueError  if a campaign is already running, the campaign_key is unknown,
                mode/volume is invalid, or the campaigns package is unavailable.
    """
    global _task

    if not _CAMPAIGNS_AVAILABLE:
        raise ValueError(f"campaigns package not available: {_IMPORT_ERROR}")
    if _state["running"]:
        raise ValueError("A campaign is already running")
    if campaign_key not in CAMPAIGNS:
        raise ValueError(f"Unknown campaign: {campaign_key!r}")
    if mode not in ("live", "preseed"):
        raise ValueError(f"mode must be 'live' or 'preseed', got {mode!r}")
    if volume not in PRESEED_VOLUMES and mode == "preseed":
        raise ValueError(f"volume must be low/medium/high, got {volume!r}")

    # Reset stop flag and state
    _stop_event.clear()
    _state["running"]  = True
    _state["campaign"] = campaign_key
    _state["phase"]    = 1

    _append_system_event(
        f"Campaign launched: {CAMPAIGNS[campaign_key]['name']} | mode={mode} | phase={phase} | volume={volume}",
        campaign_key, 1,
    )

    _task = loop.create_task(
        _engine_task(campaign_key, mode, phase, volume),
        name=f"drip-{campaign_key}",
    )


def stop() -> None:
    """Signal the running campaign to stop."""
    _stop_event.set()
    _state["running"]  = False
    campaign_key = _state.get("campaign")
    _state["campaign"] = None
    _state["phase"]    = None

    if campaign_key == "ctf":
        _signal_shop_incident(False)


def clear_incident() -> None:
    """Clear the SoleDrop shop status banner without stopping the campaign."""
    _signal_shop_incident(False)


def get_logs(since: int = 0) -> list:
    """Return log entries with id > since."""
    return [e for e in _log_buffer if e["id"] > since]


def get_status() -> dict:
    return {
        "running":  _state["running"],
        "phase":    _state["phase"],
        "campaign": _state["campaign"],
    }
