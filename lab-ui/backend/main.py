from fastapi import FastAPI, WebSocket, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
import sys
import json
import os
from pathlib import Path
from typing import Optional, Union

app = FastAPI(title="OneFlare Lab API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Campaign engine — imported at startup; non-fatal if attack-scripts absent
# ---------------------------------------------------------------------------
try:
    import campaign_engine as _ce
    _CAMPAIGN_ENGINE_OK = True
except Exception as _ce_err:
    _CAMPAIGN_ENGINE_OK = False
    _ce = None  # type: ignore[assignment]
    _CE_ERR = str(_ce_err)


class LaunchRequest(BaseModel):
    campaign: str
    mode: str = "live"                          # "live" | "preseed"
    phase: Union[int, str] = "all"              # int phase number or "all"
    volume: str = "medium"                      # "low" | "medium" | "high"

SCRIPTS_DIR = Path("/app/attack-scripts")

SCENARIO_SCRIPTS = {
    "sqli":       "scenarios.01_sqli",
    "xss":        "scenarios.02_xss",
    "traversal":  "scenarios.03_path_traversal",
    "cred":       "scenarios.04_cred_stuffing",
    "dns":        "scenarios.05_dns_tunnel",
    "exfil":      "scenarios.06_data_exfil",
    "bot":        "scenarios.07_ai_bot",
    "promptinj":  "scenarios.08_prompt_injection",
    "ctf":        "scenarios.09_ctf",
    "financial":  "scenarios.10_financial",
    "healthcare": "scenarios.11_healthcare",
    "saas":       "scenarios.12_saas",
    "all":        None,  # runs demo.py
}

# Requests fired per box/phase for the campaign scenarios (ctf/financial/
# healthcare/saas) — set as CAMPAIGN_COUNT for their scenarios.NN_x.py runner.
# The single-technique scenarios don't read this env var.
CAMPAIGN_VOLUME_COUNTS = {
    "low":    5,
    "medium": 15,
    "high":   30,
}


# ---------------------------------------------------------------------------
# Server-side, non-sensitive run configuration.
#
# These are the defaults that let ANYONE hitting the site run scenarios without
# configuring anything in their browser — they persist across users/browsers
# because they live on the server, not in localStorage. Everything here is
# non-sensitive (target hostnames, timing); NO API tokens or account/zone IDs.
# Each value is env-overridable so a partner can point their own deployment at
# their own NFR (LAB_CF_DOMAIN etc. in .env); the baked fallback is the shared
# reference instance (one-flare.com) so our instance works with zero config.
# ---------------------------------------------------------------------------
def build_server_config() -> dict:
    domain = os.getenv("LAB_CF_DOMAIN") or "one-flare.com"
    def _f(name, default):
        try:
            return float(os.getenv(name, default))
        except (TypeError, ValueError):
            return float(default)
    return {
        "domain": domain,
        "shop_url":   os.getenv("LAB_SHOP_URL")   or f"https://shop.{domain}",
        "portal_url": os.getenv("LAB_PORTAL_URL") or f"https://portal.{domain}",
        "api_url":    os.getenv("LAB_API_URL")    or f"https://api.{domain}",
        "gateway_doh_url": os.getenv("LAB_GATEWAY_DOH_URL", ""),
        "delay":  _f("LAB_ATTACK_DELAY", "0.5"),
        "jitter": _f("LAB_ATTACK_JITTER", "0.3"),
        "s1_console_url": os.getenv("LAB_S1_CONSOLE_URL", ""),  # display-only, non-secret
    }


SERVER_CONFIG = build_server_config()


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/config")
async def get_config():
    """Non-sensitive, server-side run defaults (domain, target URLs, DoH, timing).
    The frontend loads these so a fresh browser is pre-configured and can run
    scenarios immediately. NO tokens or account/zone IDs are ever returned here."""
    return SERVER_CONFIG


@app.post("/api/test-connection")
async def test_connection(body: dict):
    import httpx
    token = body.get("cf_api_token", "")
    if not token:
        return {"ok": False, "error": "No token provided"}
    async with httpx.AsyncClient() as client:
        r = await client.get(
            "https://api.cloudflare.com/client/v4/user/tokens/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
    data = r.json()
    return {"ok": data.get("success", False), "result": data.get("result")}


@app.websocket("/ws/run/{scenario_id}")
async def run_scenario(websocket: WebSocket, scenario_id: str):
    await websocket.accept()

    # Receive config from client
    config_msg = await websocket.receive_text()
    config = json.loads(config_msg)

    # Effective config = client-sent value (per-user override) → server default.
    # This means a browser that sends nothing still runs against the baked
    # SERVER_CONFIG (so anyone can generate data with zero configuration).
    env = os.environ.copy()
    env["CLOUDFLARE_DOMAIN"]   = config.get("domain")     or SERVER_CONFIG["domain"]
    env["SHOP_URL_OVERRIDE"]   = config.get("shop_url")   or SERVER_CONFIG["shop_url"]
    env["PORTAL_URL_OVERRIDE"] = config.get("portal_url") or SERVER_CONFIG["portal_url"]
    env["API_URL_OVERRIDE"]    = config.get("api_url")    or SERVER_CONFIG["api_url"]
    # delay/jitter can legitimately be 0, so fall back only when truly absent.
    delay  = config.get("delay")
    jitter = config.get("jitter")
    env["ATTACK_DELAY"]  = str(delay  if delay  is not None else SERVER_CONFIG["delay"])
    env["ATTACK_JITTER"] = str(jitter if jitter is not None else SERVER_CONFIG["jitter"])
    # Campaign scenarios (ctf/financial/healthcare/saas) fire CAMPAIGN_COUNT
    # requests per box/phase — the single-technique scenarios don't read this.
    volume = config.get("campaign_volume") or "medium"
    env["CAMPAIGN_COUNT"] = str(CAMPAIGN_VOLUME_COUNTS.get(volume, CAMPAIGN_VOLUME_COUNTS["medium"]))
    doh = config.get("gateway_doh_url") or SERVER_CONFIG["gateway_doh_url"]
    if doh:
        env["CF_GATEWAY_DOH_URL"] = doh

    if scenario_id == "all":
        cmd = [sys.executable, str(SCRIPTS_DIR / "demo.py")]
    else:
        script_module = SCENARIO_SCRIPTS.get(scenario_id)
        if not script_module:
            await websocket.send_text(
                json.dumps({"type": "error", "message": f"Unknown scenario: {scenario_id}"})
            )
            await websocket.close()
            return
        cmd = [sys.executable, "-m", script_module]

    await websocket.send_text(json.dumps({"type": "start", "scenario": scenario_id}))

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
            cwd=str(SCRIPTS_DIR),
        )

        async for line in process.stdout:
            text = line.decode("utf-8", errors="replace").rstrip()
            await websocket.send_text(json.dumps({"type": "output", "line": text}))

        await process.wait()
        await websocket.send_text(
            json.dumps({
                "type": "done",
                "exit_code": process.returncode,
                "scenario": scenario_id,
            })
        )
    except Exception as e:
        await websocket.send_text(
            json.dumps({"type": "error", "message": str(e)})
        )
    finally:
        await websocket.close()


@app.get("/api/scenarios")
async def list_scenarios():
    return {"scenarios": list(SCENARIO_SCRIPTS.keys())}


# ---------------------------------------------------------------------------
# Campaign endpoints (Wave 2 — ThreatOps drip-flow)
# ---------------------------------------------------------------------------

def _require_engine():
    """Raise 503 if the campaign engine failed to import."""
    if not _CAMPAIGN_ENGINE_OK:
        raise HTTPException(
            status_code=503,
            detail=f"Campaign engine unavailable: {_CE_ERR}",
        )


@app.get("/api/campaigns")
async def get_campaigns():
    """
    Return all campaign + phase metadata.
    Callables (fire_one / fire_many) are stripped — not JSON-serialisable.
    Response: dict[campaign_key -> {name, campaign, color, icon, target_role,
                                    num_phases, phases: [...phase_dicts]}]
    """
    _require_engine()
    return _ce.get_campaigns_meta()


@app.post("/api/campaign/launch")
async def campaign_launch(body: LaunchRequest):
    """
    Start a drip-flow campaign.

    Request  : {campaign, mode:"live"|"preseed", phase:int|"all", volume:"low"|"medium"|"high"}
    Response : {started:true, campaign, mode, phase, volume}
    Errors   : 400 if already running or unknown campaign/mode/volume
               503 if campaign engine unavailable
    """
    _require_engine()
    try:
        loop = asyncio.get_event_loop()
        _ce.launch(body.campaign, body.mode, body.phase, body.volume, loop)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "started":  True,
        "campaign": body.campaign,
        "mode":     body.mode,
        "phase":    body.phase,
        "volume":   body.volume,
    }


@app.get("/api/campaign/logs")
async def campaign_logs(since: int = Query(default=0, ge=0)):
    """
    Incremental log polling.

    Query param : since=<id>  (return only entries with id > since; default 0 = all)
    Response    : {entries:[...log_dicts], running:bool, phase:int|null, campaign:str|null}
    """
    _require_engine()
    status  = _ce.get_status()
    entries = _ce.get_logs(since)
    return {
        "entries":  entries,
        "running":  status["running"],
        "phase":    status["phase"],
        "campaign": status["campaign"],
    }


@app.get("/api/campaign/status")
async def campaign_status():
    """
    Current engine state snapshot.
    Response: {running:bool, phase:int|null, campaign:str|null}
    """
    _require_engine()
    return _ce.get_status()


@app.post("/api/campaign/stop")
async def campaign_stop():
    """
    Stop the running campaign.
    If the campaign is 'ctf', signal_incident(False) is called automatically.
    Response: {stopped:true}
    """
    _require_engine()
    _ce.stop()
    return {"stopped": True}


@app.post("/api/campaign/clear-incident")
async def campaign_clear_incident():
    """
    Clear the AcmeCorp/Pyxis status page banner via signal_incident(False).
    Idempotent — safe to call even when no campaign is running.
    Response: {cleared:true}
    """
    _require_engine()
    _ce.clear_incident()
    return {"cleared": True}
