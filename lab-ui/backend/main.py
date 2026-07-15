from fastapi import FastAPI, WebSocket, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import asyncio
import sys
import json
import os
from pathlib import Path
from typing import Optional, Union
from urllib.parse import quote

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

import lab_identity as _li


class LaunchRequest(BaseModel):
    campaign: str
    mode: str = "live"                          # "live" | "preseed"
    phase: Union[int, str] = "all"              # int phase number or "all"
    volume: str = "medium"                      # "low" | "medium" | "high"
    # Multi-user console: the subdomain to run against. Admins may pass any
    # registered tenant host (validated server-side); ignored for non-admins
    # (forced to their own). None = the admin's default (one-flare target).
    target_subdomain: Optional[str] = None


class LabRegisterRequest(BaseModel):
    name: str
    s1_hec_url: str
    s1_hec_token: str
    # site_label (S1 site) + account_label (S1 account) are required by the relay
    # and validated in lab_identity.register() (400 on missing). Optional here so
    # the failure surfaces as a friendly 400, not a pydantic 422.
    site_label: Optional[str] = None
    account_label: Optional[str] = None
    s1_console_url: Optional[str] = None


class AdminBatchDeleteRequest(BaseModel):
    subdomains: list[str]


class AuthLoginRequest(BaseModel):
    email: str
    password: str


class AuthInviteRequest(BaseModel):
    email: str
    role: str


class AuthInviteBulkRequest(BaseModel):
    emails: Union[str, list] = ""     # delimited string or list of emails
    role: str = "user"


class AuthAcceptInviteRequest(BaseModel):
    token: str
    password: str


class AuthRoleRequest(BaseModel):
    role: str


class AuthBootstrapRequest(BaseModel):
    email: str

SCRIPTS_DIR = Path("/app/attack-scripts")

SCENARIO_SCRIPTS = {
    "sqli":      "scenarios.01_sqli",
    "xss":       "scenarios.02_xss",
    "traversal": "scenarios.03_path_traversal",
    "cred":      "scenarios.04_cred_stuffing",
    "dns":       "scenarios.05_dns_tunnel",
    "exfil":     "scenarios.06_data_exfil",
    "bot":       "scenarios.07_ai_bot",
    "promptinj": "scenarios.08_prompt_injection",
    "all":       None,  # runs demo.py
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
        # Multi-tenant lab (feat/multi-tenant-relay): non-secret flags the UI reads
        # to decide whether to show the Lab Identity / Admin surfaces.
        "lab_domain": os.getenv("LAB_DOMAIN", "lab.soledrop.co"),
        "relay_configured": bool(os.getenv("RELAY_URL")),
        "admin_enabled": bool(os.getenv("ADMIN_TOKEN")),  # console deployment only
    }


SERVER_CONFIG = build_server_config()
# Snapshot of the un-overridden shop/portal/api defaults, taken before any lab
# identity is applied — used to restore SERVER_CONFIG when an instance's
# registration is torn down (see lab_get_identity's reset path below).
_DEFAULT_TARGET_URLS = {
    "shop_url": SERVER_CONFIG["shop_url"],
    "portal_url": SERVER_CONFIG["portal_url"],
    "api_url": SERVER_CONFIG["api_url"],
}

# Re-apply a persisted lab identity at startup so this instance keeps targeting
# its registered subdomain across restarts (and reflect it into the subprocess
# scenario default so /ws/run uses it too).
def _reflect_identity_urls(shop_url: str) -> None:
    """Collapse shop/portal/api server defaults onto the registered subdomain so
    the subprocess scenario runner (/ws/run) targets it for ALL scenarios."""
    if shop_url:
        SERVER_CONFIG["shop_url"] = shop_url
        SERVER_CONFIG["portal_url"] = shop_url
        SERVER_CONFIG["api_url"] = shop_url


def _reset_target_urls() -> None:
    """Restore SERVER_CONFIG shop/portal/api to their pre-identity defaults."""
    SERVER_CONFIG["shop_url"] = _DEFAULT_TARGET_URLS["shop_url"]
    SERVER_CONFIG["portal_url"] = _DEFAULT_TARGET_URLS["portal_url"]
    SERVER_CONFIG["api_url"] = _DEFAULT_TARGET_URLS["api_url"]


def _multi_user_mode() -> bool:
    """True on the shared console (many users, one backend). The console sets
    ADMIN_TOKEN; partner/local single-tenant instances do not. An explicit
    MULTI_USER env overrides for testing.

    In this mode the backend must NEVER mutate process-global target state
    (os.environ *_URL_OVERRIDE / SERVER_CONFIG) — that is single-tenant coupling
    that would make the last-registered subdomain everyone's attack target.
    Identity/target is resolved per request from the caller's session instead.
    """
    override = os.getenv("MULTI_USER")
    if override is not None:
        return override.strip().lower() in ("1", "true", "yes", "on")
    return _li.admin_enabled()


# ── Per-request identity resolution (multi-user console) ────────────────────
# The backend never decodes the session itself — it asks the relay (which owns
# sessions) via the cookie-forwarding proxy. Used to login-gate execution and to
# resolve each run's AUTHORITATIVE target (so a user can't attack another's site).
def _session_from_cookies(cookies: dict) -> Optional[dict]:
    status, data, _ = _li.auth_request("GET", "/auth/me", cookies=cookies or {})
    if status == 200 and isinstance(data, dict) and data.get("email"):
        return {"email": data["email"], "role": data.get("role")}
    return None


def _own_subdomain(cookies: dict) -> Optional[str]:
    status, data, _ = _li.auth_request("GET", "/auth/lab/identity", cookies=cookies or {})
    if status == 200 and isinstance(data, dict):
        ident = data.get("identity")
        if isinstance(ident, dict):
            return ident.get("subdomain")
    return None


def _resolve_run_target(cookies: dict, requested_subdomain: Optional[str]):
    """Authoritative target for an execution request (multi-user mode only).

    Returns (base_url_or_None, session). base_url None means "use the SERVER_CONFIG
    default" — an admin who picked no subdomain runs against the original one-flare
    targets (preserving prior behavior). Raises PermissionError when not logged in,
    ValueError on a bad/unknown selection.
      - admin: may target any REGISTERED subdomain (validated) or none (default).
      - user/viewer: forced to their OWN subdomain (client selection ignored).
    """
    session = _session_from_cookies(cookies)
    if not session:
        raise PermissionError("login required")
    role = session.get("role")
    if role == "admin":
        sub = (requested_subdomain or "").strip()
        if sub and sub.lower() not in ("default", "one-flare", "oneflare"):
            if _li.check_still_registered(sub) is not True:
                raise ValueError(f"unknown target subdomain: {sub}")
            return f"https://{sub}", session
        return None, session
    own = _own_subdomain(cookies)
    if not own:
        raise ValueError("Register your lab subdomain in Settings before running scenarios.")
    return f"https://{own}", session


# In single-tenant mode, re-pin this instance to its persisted subdomain at boot
# (and reflect it into the subprocess scenario default). In multi-user (console)
# mode we deliberately skip this — a global identity would clobber every user's
# target; targeting is resolved per-request instead (see Phase 2).
_BOOT_IDENTITY = None
if not _multi_user_mode():
    _BOOT_IDENTITY = _li.bootstrap()
    if _BOOT_IDENTITY and _BOOT_IDENTITY.get("shop_url"):
        _reflect_identity_urls(_BOOT_IDENTITY["shop_url"])


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
    doh = config.get("gateway_doh_url") or SERVER_CONFIG["gateway_doh_url"]
    if doh:
        env["CF_GATEWAY_DOH_URL"] = doh

    # Multi-user console: login-gate execution and resolve the target
    # AUTHORITATIVELY from the session — the client-sent shop_url/portal_url/api_url
    # are NOT trusted here (a user must never be able to attack another's site).
    if _multi_user_mode():
        try:
            target, _session = _resolve_run_target(dict(websocket.cookies), config.get("target_subdomain"))
        except PermissionError:
            await websocket.send_text(json.dumps({"type": "error", "message": "Please log in to run scenarios."}))
            await websocket.close()
            return
        except ValueError as exc:
            await websocket.send_text(json.dumps({"type": "error", "message": str(exc)}))
            await websocket.close()
            return
        if target:
            env["SHOP_URL_OVERRIDE"] = env["PORTAL_URL_OVERRIDE"] = env["API_URL_OVERRIDE"] = target
        else:
            # Admin with no selection → the original one-flare targets.
            env["SHOP_URL_OVERRIDE"]   = SERVER_CONFIG["shop_url"]
            env["PORTAL_URL_OVERRIDE"] = SERVER_CONFIG["portal_url"]
            env["API_URL_OVERRIDE"]    = SERVER_CONFIG["api_url"]

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
async def campaign_launch(request: Request, body: LaunchRequest):
    """
    Start a drip-flow campaign.

    Request  : {campaign, mode:"live"|"preseed", phase:int|"all", volume:"low"|"medium"|"high"}
    Response : {started:true, campaign, mode, phase, volume}
    Errors   : 400 if already running or unknown campaign/mode/volume
               503 if campaign engine unavailable
    """
    _require_engine()
    # Multi-user console: login-gate + resolve the authoritative target.
    target = None
    if _multi_user_mode():
        try:
            target, _session = _resolve_run_target(dict(request.cookies), body.target_subdomain)
        except PermissionError:
            raise HTTPException(status_code=401, detail="Please log in to run campaigns.")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    try:
        loop = asyncio.get_event_loop()
        _ce.launch(body.campaign, body.mode, body.phase, body.volume, loop, target=target)
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
async def campaign_stop(request: Request):
    """
    Stop the running campaign.
    If the campaign is 'ctf', signal_incident(False) is called automatically.
    Response: {stopped:true}
    """
    _require_engine()
    if _multi_user_mode() and _session_from_cookies(dict(request.cookies)) is None:
        raise HTTPException(status_code=401, detail="Please log in.")
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


# ---------------------------------------------------------------------------
# Multi-tenant lab identity (feat/multi-tenant-relay)
# ---------------------------------------------------------------------------
@app.get("/api/lab/identity")
def lab_get_identity(request: Request):
    """Current lab identity.

    Multi-user (console) mode: the CALLER's own tenant, resolved from their
    session via the relay (null if not logged in or not yet registered).
    Single-tenant mode: this instance's persisted identity, with the relay
    teardown self-check — sync def → the blocking relay call runs in a threadpool.
    """
    relay_configured = bool(os.getenv("RELAY_URL"))
    lab_domain = os.getenv("LAB_DOMAIN", "lab.soledrop.co")

    if _multi_user_mode():
        status, data, _ = _li.auth_request(
            "GET", "/auth/lab/identity", cookies=dict(request.cookies)
        )
        ident = data.get("identity") if (status == 200 and isinstance(data, dict)) else None
        return {
            "identity": ident,
            "relay_configured": relay_configured,
            "lab_domain": lab_domain,
            "multi_user": True,
        }

    ident = _li.load_identity()
    if ident and ident.get("subdomain"):
        still_registered = _li.check_still_registered(ident["subdomain"])
        if still_registered is False:
            _li.reset_identity()
            _reset_target_urls()
            return {
                "identity": None,
                "reset": True,
                "message": "This instance was reset by the admin — please register again.",
                "relay_configured": relay_configured,
                "lab_domain": lab_domain,
            }
    return {
        "identity": ident,
        "relay_configured": relay_configured,
        "lab_domain": lab_domain,
    }


@app.post("/api/lab/register")
def lab_register(request: Request, body: LabRegisterRequest):
    """Register a lab identity and enroll it with the relay.

    Multi-user (console) mode: session-gated — proxies the caller's cookie to the
    relay's /auth/lab/register, which stamps owner_email from the session (401 if
    not logged in). Does NOT mutate process-global target state. Single-tenant
    mode: legacy enroll-code registration that pins this instance's global target.
    """
    if _multi_user_mode():
        status, data, _ = _li.auth_request(
            "POST", "/auth/lab/register",
            cookies=dict(request.cookies), json_body=body.dict(),
        )
        if status >= 400 or not isinstance(data, dict):
            msg = (data.get("error") if isinstance(data, dict) else None) or f"relay error (HTTP {status})"
            raise HTTPException(status_code=status if 400 <= status < 600 else 502, detail=msg)
        subdomain = data.get("subdomain")
        # Reconstruct the identity for the UI from the submitted fields + the
        # relay-assigned subdomain (the relay never echoes the HEC token back).
        identity = {
            "name": body.name,
            "subdomain": subdomain,
            "shop_url": data.get("shop_url") or (f"https://{subdomain}" if subdomain else None),
            "enrolled": True,
            "s1_hec_url": body.s1_hec_url,
            "site_label": body.site_label,
            "account_label": body.account_label,
            "s1_console_url": body.s1_console_url,
        }
        return {"ok": True, "identity": identity}

    # Single-tenant: legacy enroll-code path that pins the process-global target.
    try:
        ident = _li.register(
            body.name, body.s1_hec_url, body.s1_hec_token,
            body.site_label, body.account_label, body.s1_console_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    if ident.get("shop_url"):
        _reflect_identity_urls(ident["shop_url"])
    return {"ok": True, "identity": ident}


@app.get("/api/lab/tenants")
def lab_tenants(request: Request):
    """All registered subdomains, for the admin Scenarios-page target selector.

    Proxies the relay's admin-gated /auth/tenants with the caller's cookie — a
    non-admin (or logged-out) caller gets the relay's 401/403 passed through.
    """
    if not _multi_user_mode():
        return {"tenants": []}
    status, data, _ = _li.auth_request("GET", "/auth/tenants", cookies=dict(request.cookies))
    if status != 200 or not isinstance(data, dict):
        return JSONResponse(status_code=status or 502,
                            content=data if isinstance(data, dict) else {"error": "relay error"})
    return {"tenants": data.get("tenants", [])}


# ---------------------------------------------------------------------------
# Admin console proxy → relay /admin/* (ONLY when ADMIN_TOKEN is configured,
# i.e. the one-flare.com deployment; partner instances get 403)
# ---------------------------------------------------------------------------
def _require_admin():
    if not _li.admin_enabled():
        raise HTTPException(status_code=403, detail="Admin is not enabled on this instance")


@app.get("/api/admin/registry")
def admin_registry():
    _require_admin()
    status, body = _li.admin_request("GET", "/admin/registry")
    return JSONResponse(status_code=status, content=body)


@app.get("/api/admin/history")
def admin_history():
    _require_admin()
    status, body = _li.admin_request("GET", "/admin/history")
    return JSONResponse(status_code=status, content=body)


@app.post("/api/admin/user/{subdomain}/{action}")
def admin_user_action(subdomain: str, action: str):
    _require_admin()
    if action not in ("enable", "disable"):
        raise HTTPException(status_code=400, detail="action must be 'enable' or 'disable'")
    status, body = _li.admin_request("POST", f"/admin/user/{subdomain}/{action}")
    return JSONResponse(status_code=status, content=body)


@app.delete("/api/admin/user/{subdomain}")
def admin_user_delete(subdomain: str):
    _require_admin()
    status, body = _li.admin_request("DELETE", f"/admin/user/{subdomain}")
    return JSONResponse(status_code=status, content=body)


@app.post("/api/admin/users/delete")
def admin_users_delete(body: AdminBatchDeleteRequest):
    """Batch teardown — deletes each subdomain's relay registry row in turn.

    Best-effort per-row: one failure doesn't stop the rest. Response:
    {ok, results: [{subdomain, status}]}.
    """
    _require_admin()
    results = []
    for subdomain in body.subdomains:
        status, _ = _li.admin_request("DELETE", f"/admin/user/{subdomain}")
        results.append({"subdomain": subdomain, "status": status})
    return {"ok": True, "results": results}


# ---------------------------------------------------------------------------
# RBAC admin user-management proxy → relay /auth/* (feat/multi-tenant-relay)
#
# Unlike /api/admin/* above (gated by ADMIN_TOKEN/admin_enabled — console
# deployment only), these routes are available on ANY lab-ui instance with
# RELAY_URL configured: the login layer itself is the gate. Cookies are
# forwarded both ways so the relay's HttpOnly session cookie round-trips
# through this proxy transparently. The ADMIN_TOKEN stays server-side only —
# used solely by /api/auth/bootstrap (break-glass, requires admin_enabled()).
# ---------------------------------------------------------------------------
def _proxy_auth(request: Request, method: str, path: str, body: Optional[dict] = None) -> JSONResponse:
    status, data, set_cookies = _li.auth_request(method, path, cookies=dict(request.cookies), json_body=body)
    out = JSONResponse(status_code=status, content=data)
    for cookie_header in set_cookies:
        out.headers.append("set-cookie", cookie_header)
    return out


@app.post("/api/auth/login")
def auth_login(request: Request, body: AuthLoginRequest):
    return _proxy_auth(request, "POST", "/auth/login", body.dict())


@app.post("/api/auth/logout")
def auth_logout(request: Request):
    return _proxy_auth(request, "POST", "/auth/logout")


@app.get("/api/auth/me")
def auth_me(request: Request):
    return _proxy_auth(request, "GET", "/auth/me")


@app.post("/api/auth/invite")
def auth_invite(request: Request, body: AuthInviteRequest):
    return _proxy_auth(request, "POST", "/auth/invite", body.dict())


@app.post("/api/auth/invite-bulk")
def auth_invite_bulk(request: Request, body: AuthInviteBulkRequest):
    return _proxy_auth(request, "POST", "/auth/invite-bulk", body.dict())


@app.post("/api/auth/accept-invite")
def auth_accept_invite(request: Request, body: AuthAcceptInviteRequest):
    return _proxy_auth(request, "POST", "/auth/accept-invite", body.dict())


@app.get("/api/auth/users")
def auth_users(request: Request):
    return _proxy_auth(request, "GET", "/auth/users")


@app.post("/api/auth/users/{email}/role")
def auth_user_role(request: Request, email: str, body: AuthRoleRequest):
    return _proxy_auth(request, "POST", f"/auth/users/{quote(email, safe='')}/role", body.dict())


@app.delete("/api/auth/users/{email}")
def auth_user_delete(request: Request, email: str):
    return _proxy_auth(request, "DELETE", f"/auth/users/{quote(email, safe='')}")


@app.post("/api/auth/bootstrap")
def auth_bootstrap(body: AuthBootstrapRequest):
    """Break-glass: mint the first admin invite using the server's ADMIN_TOKEN.

    Only available on the console deployment (admin_enabled()). Once any
    admin user exists on the relay, this returns 409 — see RBAC.md.
    """
    _require_admin()
    status, data = _li.admin_request("POST", "/auth/bootstrap", json_body=body.dict())
    return JSONResponse(status_code=status, content=data)
