from fastapi import FastAPI, WebSocket, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import asyncio
import sys
import json
import os
import time
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
    # BYOC: run against the caller's OWN Cloudflare host, verified server-side
    # against their CF token (see _byoc_decision). A custom shop_url triggers it.
    shop_url: Optional[str] = None
    portal_url: Optional[str] = None
    api_url: Optional[str] = None
    cf_api_token: Optional[str] = None


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


class AccountRequestReq(BaseModel):
    name: str = ""
    email: str


class AcceptRequestReq(BaseModel):
    token: str
    role: str = "user"


# ── Phase 2 "Deploy Knowledge Objects" ──────────────────────────────────────
class DeployConfigReq(BaseModel):
    # The caller's OWN SentinelOne console. api_token/sdl_write_key are optional
    # so a later save can update just the SDL fields without re-sending the token
    # (the relay preserves an existing secret when the field is null).
    console_url: str
    api_token: Optional[str] = None
    sdl_xdr_url: Optional[str] = None
    sdl_write_key: Optional[str] = None


class DeployObject(BaseModel):
    type: str                          # 'detection' | 'ha' | 'dashboard'
    key: str                           # stable id from the client manifest
    payload: Union[dict, str] = {}     # the artifact JSON (dict); dashboards may be a JSON string
    # base64(JSON) alternative — the client sends this so the raw artifact (full of
    # SQLi/XSS/traversal detection signatures) doesn't trip the zone's WAF managed
    # rules on the way in. Decoded into `payload` in deploy_run.
    payload_b64: Optional[str] = None


class DeployRunReq(BaseModel):
    objects: list[DeployObject] = []

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
    # Default attack target for the shared reference console. Post-CTF-cutover the
    # live lab surface is the single soledrop shop worker — ONE host serves the
    # shop/portal/api paths (see the multi-tenant relay design), and the old
    # shop|portal|api.one-flare.com hosts no longer resolve (NXDOMAIN). So the
    # baked default points all three services at that one live host; each remains
    # individually env-overridable (LAB_SHOP_URL / LAB_PORTAL_URL / LAB_API_URL)
    # so a partner can retarget their own deployment.
    ref_target = os.getenv("LAB_REF_TARGET_URL") or "https://shop.soledrop.co"
    def _f(name, default):
        try:
            return float(os.getenv(name, default))
        except (TypeError, ValueError):
            return float(default)
    return {
        "domain": domain,
        "shop_url":   os.getenv("LAB_SHOP_URL")   or ref_target,
        "portal_url": os.getenv("LAB_PORTAL_URL") or ref_target,
        "api_url":    os.getenv("LAB_API_URL")    or ref_target,
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
_SESSION_COOKIE = "oneflare_admin_session"
_session_cache: dict = {}          # sid -> (session_or_None, expires_at)
_SESSION_CACHE_TTL = 15.0          # seconds — campaign logs poll ~1/s; don't hit the relay every time


def _session_from_cookies(cookies: dict) -> Optional[dict]:
    sid = (cookies or {}).get(_SESSION_COOKIE) or ""
    now = time.time()
    if sid:
        cached = _session_cache.get(sid)
        if cached and cached[1] > now:
            return cached[0]
    status, data, _ = _li.auth_request("GET", "/auth/me", cookies=cookies or {})
    session = (
        {"email": data["email"], "role": data.get("role")}
        if (status == 200 and isinstance(data, dict) and data.get("email"))
        else None
    )
    if sid:
        if len(_session_cache) > 256:      # opportunistic prune of expired entries
            for k in [k for k, v in _session_cache.items() if v[1] <= now]:
                _session_cache.pop(k, None)
        _session_cache[sid] = (session, now + _SESSION_CACHE_TTL)
    return session


def _campaign_owner(request: Request) -> Optional[str]:
    """Owner key for the caller's campaign session. None in single-tenant mode
    (engine uses its default owner); the caller's email in multi-user mode; a
    fixed '__anon__' for logged-out demo viewers (their own empty buffer)."""
    if not _multi_user_mode():
        return None
    session = _session_from_cookies(dict(request.cookies))
    return session["email"] if session else "__anon__"


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


# ── Bring-Your-Own-Cloudflare (BYOC) targeting + Logpush configuration ────────
# The shared console pins lab users to their assigned *.lab.soledrop.co subdomain.
# BYOC lets any logged-in user ALSO target hosts inside a Cloudflare zone THEIR OWN
# API token controls — verified here so the console can never be pointed at a
# domain the caller can't authenticate to.
_LAB_HOST_SUFFIX = (os.getenv("LAB_DOMAIN") or "lab.soledrop.co").lower().lstrip(".")


def _hostname(url: str) -> str:
    h = (url or "").strip().lower()
    h = h.replace("https://", "").replace("http://", "")
    return h.split("/")[0].split("?")[0].split(":")[0]


def _is_lab_or_ref_host(url: str) -> bool:
    """True for a host that belongs to the shared lab (a *.lab.soledrop.co subdomain
    or one of the baked reference targets). Runs against these use the session-
    authoritative path; anything else is a BYOC custom target that must be verified."""
    h = _hostname(url)
    if not h:
        return True
    if h == _LAB_HOST_SUFFIX or h.endswith("." + _LAB_HOST_SUFFIX):
        return True
    for u in (SERVER_CONFIG.get("shop_url"), SERVER_CONFIG.get("portal_url"), SERVER_CONFIG.get("api_url")):
        if _hostname(u) and _hostname(u) == h:
            return True
    return False


async def _cf_zone_names_for_token(token: str):
    """Zone names the CF API token can access (lowercased), or None if the token is
    invalid — proof of control: you can only hold a token for zones in your account."""
    import httpx
    names = []
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            v = await client.get(
                "https://api.cloudflare.com/client/v4/user/tokens/verify",
                headers={"Authorization": f"Bearer {token}"},
            )
            if not (v.json() or {}).get("success"):
                return None
            page = 1
            while page <= 20:
                r = await client.get(
                    "https://api.cloudflare.com/client/v4/zones",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"per_page": 50, "page": page},
                )
                d = r.json() or {}
                if not d.get("success"):
                    break
                names += [(z.get("name") or "").lower() for z in (d.get("result") or []) if z.get("name")]
                info = d.get("result_info") or {}
                if page >= int(info.get("total_pages") or 1):
                    break
                page += 1
    except Exception:
        return None
    return names


def _host_controlled(url: str, zone_names) -> bool:
    h = _hostname(url)
    return bool(h) and any(h == z or h.endswith("." + z) for z in (zone_names or []))


async def _byoc_decision(cookies: dict, hosts_map: dict, cf_token: str):
    """Classify a run's targets in multi-user mode. `hosts_map` = {shop,portal,api}.
    Returns (kind, message, safe_targets):
      ('lab', None, None)  → no custom host → caller uses the session-authoritative
                             path (a user can't attack another's site).
      ('byoc', None, dict) → the caller's own CF token controls every custom host.
                             `safe_targets` is {shop,portal,api} with EVERY role set to
                             a VERIFIED controlled host — any lab/ref/blank role is
                             coerced to the primary controlled host, so a BYOC run can
                             never touch a lab tenant or the shared reference target.
      ('error', str, None) → a custom host the caller may not run against (reason in str)."""
    custom = {k: v for k, v in (hosts_map or {}).items() if v and not _is_lab_or_ref_host(v)}
    if not custom:
        return ("lab", None, None)
    if not _session_from_cookies(cookies):
        return ("error", "Please log in to run scenarios.", None)
    if not cf_token:
        return ("error", "To target your own Cloudflare host, add your Cloudflare API token in Settings → Cloudflare Configuration first.", None)
    zone_names = await _cf_zone_names_for_token(cf_token)
    if zone_names is None:
        return ("error", "Your Cloudflare API token is invalid or expired.", None)
    uncontrolled = sorted({_hostname(v) for v in custom.values() if not _host_controlled(v, zone_names)})
    if uncontrolled:
        return ("error", f"Your Cloudflare token doesn't control: {', '.join(uncontrolled)}. You can only target hosts in zones your token manages.", None)
    primary = next(iter(custom.values()))
    safe = {}
    for role in ("shop", "portal", "api"):
        v = (hosts_map or {}).get(role)
        safe[role] = v if (v and _host_controlled(v, zone_names)) else primary
    return ("byoc", None, safe)


@app.post("/api/cloudflare/logpush/configure")
async def configure_logpush(body: dict):
    """Create Logpush jobs on the caller's OWN Cloudflare zone that ship HTTP +
    firewall events to their OWN SentinelOne HEC. Single-tenant / BYOC self-service:
    the CF token + S1 HEC creds are supplied per call and used transiently (never
    stored). The CF token needs Logpush:Edit + access to the zone. S1's marketplace
    HEC raw collector is Splunk-HEC-compatible (auth `Authorization: Splunk <token>`),
    which is exactly what Cloudflare's native Splunk Logpush destination sends."""
    import httpx, uuid
    from urllib.parse import quote
    token = (body.get("cf_api_token") or "").strip()
    zone_id = (body.get("cf_zone_id") or "").strip()
    hec_url = (body.get("s1_hec_url") or "").strip()
    hec_token = (body.get("s1_hec_token") or "").strip()
    datasets = body.get("datasets") or ["http_requests", "firewall_events"]
    missing = [k for k, v in (("cf_api_token", token), ("cf_zone_id", zone_id),
                              ("s1_hec_url", hec_url), ("s1_hec_token", hec_token)) if not v]
    if missing:
        return {"ok": False, "error": f"Missing required field(s): {', '.join(missing)}"}

    host = _hostname(hec_url)
    dest_host = f"{host}:443"
    auth = quote(f"Splunk {hec_token}", safe="")
    FIELDS = {
        "http_requests": ["ClientIP", "ClientRequestHost", "ClientRequestMethod", "ClientRequestPath",
                          "ClientRequestURI", "EdgeResponseStatus", "EdgeResponseBytes", "RayID",
                          "ClientRequestUserAgent", "SecurityAction", "SecurityRuleID",
                          "WAFAttackScore", "WAFSQLiAttackScore", "WAFXSSAttackScore", "WAFRCEAttackScore"],
        "firewall_events": ["Action", "ClientIP", "ClientRequestHTTPHost", "ClientRequestPath",
                           "Datetime", "RayID", "RuleID", "Source", "UserAgent"],
    }
    results = []
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            for ds in datasets:
                channel = str(uuid.uuid4())
                dest = (f"splunk://{dest_host}/services/collector/raw?channel={channel}"
                        f"&insecure-skip-verify=false&sourcetype=cloudflare_{ds}"
                        f"&header_Authorization={auth}")
                job = {
                    "name": f"oneflare-{ds}-s1",
                    "dataset": ds,
                    "output_options": {"field_names": FIELDS.get(ds, []), "timestamp_format": "rfc3339"},
                    "destination_conf": dest,
                    "enabled": True,
                }
                r = await client.post(
                    f"https://api.cloudflare.com/client/v4/zones/{zone_id}/logpush/jobs",
                    headers={"Authorization": f"Bearer {token}"},
                    json=job,
                )
                d = r.json() or {}
                results.append({
                    "dataset": ds,
                    "ok": bool(d.get("success")),
                    "id": (d.get("result") or {}).get("id"),
                    "errors": d.get("errors"),
                })
    except Exception as exc:
        return {"ok": False, "error": f"Cloudflare API call failed: {exc}", "jobs": results}
    return {"ok": bool(results) and all(x["ok"] for x in results), "jobs": results}


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

    # Multi-user console: login-gate execution and resolve the target via one of two
    # SAFE paths:
    #   • Lab target (a *.lab.soledrop.co subdomain / the reference host) → resolved
    #     AUTHORITATIVELY from the session (a user can't attack another's site).
    #   • BYOC target (the caller's OWN Cloudflare host) → allowed ONLY after verifying
    #     the caller's OWN CF API token controls that host's zone. This is how the
    #     shared console extends beyond the lab without becoming an open launcher.
    if _multi_user_mode():
        kind, msg, safe = await _byoc_decision(
            dict(websocket.cookies),
            {"shop": config.get("shop_url"), "portal": config.get("portal_url"), "api": config.get("api_url")},
            (config.get("cf_api_token") or "").strip(),
        )
        if kind == "error":
            await websocket.send_text(json.dumps({"type": "error", "message": msg}))
            await websocket.close()
            return
        if kind == "byoc":
            env["SHOP_URL_OVERRIDE"]   = safe["shop"]
            env["PORTAL_URL_OVERRIDE"] = safe["portal"]
            env["API_URL_OVERRIDE"]    = safe["api"]
        if kind == "lab":
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
async def get_campaigns(request: Request):
    """
    Return all campaign + phase metadata.
    Callables (fire_one / fire_many) are stripped — not JSON-serialisable.
    Response: dict[campaign_key -> {name, campaign, color, icon, target_role,
                                    num_phases, phases: [...phase_dicts]}]
    """
    _require_engine()
    return _ce.get_campaigns_meta(_campaign_owner(request))


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
    # Multi-user console: login-gate + resolve the authoritative target + owner.
    target = None
    owner = None
    if _multi_user_mode():
        cookies = dict(request.cookies)
        kind, msg, safe = await _byoc_decision(
            cookies,
            {"shop": body.shop_url, "portal": body.portal_url, "api": body.api_url},
            (body.cf_api_token or "").strip(),
        )
        if kind == "error":
            raise HTTPException(status_code=401 if "log in" in msg.lower() else 400, detail=msg)
        if kind == "byoc":
            session = _session_from_cookies(cookies)
            target = safe["shop"]
            owner = session["email"]
        else:
            try:
                target, session = _resolve_run_target(cookies, body.target_subdomain)
            except PermissionError:
                raise HTTPException(status_code=401, detail="Please log in to run campaigns.")
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            owner = session["email"]
    try:
        loop = asyncio.get_event_loop()
        _ce.launch(owner, body.campaign, body.mode, body.phase, body.volume, loop, target=target)
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
async def campaign_logs(request: Request, since: int = Query(default=0, ge=0)):
    """
    Incremental log polling — scoped to the caller's own campaign session.

    Query param : since=<id>  (return only entries with id > since; default 0 = all)
    Response    : {entries:[...log_dicts], running:bool, phase:int|null, campaign:str|null}
    """
    _require_engine()
    owner   = _campaign_owner(request)
    status  = _ce.get_status(owner)
    entries = _ce.get_logs(owner, since)
    return {
        "entries":  entries,
        "running":  status["running"],
        "phase":    status["phase"],
        "campaign": status["campaign"],
    }


@app.get("/api/campaign/status")
async def campaign_status(request: Request):
    """
    Current engine state snapshot for the caller's own campaign session.
    Response: {running:bool, phase:int|null, campaign:str|null}
    """
    _require_engine()
    return _ce.get_status(_campaign_owner(request))


@app.post("/api/campaign/stop")
async def campaign_stop(request: Request):
    """
    Stop the caller's own running campaign.
    If the campaign is 'ctf', signal_incident(False) is called automatically.
    Response: {stopped:true}
    """
    _require_engine()
    owner = None
    if _multi_user_mode():
        session = _session_from_cookies(dict(request.cookies))
        if session is None:
            raise HTTPException(status_code=401, detail="Please log in.")
        owner = session["email"]
    _ce.stop(owner)
    return {"stopped": True}


@app.post("/api/campaign/clear-incident")
async def campaign_clear_incident(request: Request):
    """
    Clear the SoleDrop shop status banner via signal_incident(False).
    Idempotent — safe to call even when no campaign is running.
    Response: {cleared:true}
    """
    _require_engine()
    _ce.clear_incident(_campaign_owner(request))
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
    """admin_enabled() only — for the bootstrap break-glass (no caller session
    exists yet). Do NOT use for the registry proxy; use _require_console_admin."""
    if not _li.admin_enabled():
        raise HTTPException(status_code=403, detail="Admin is not enabled on this instance")


def _require_console_admin(request: Request, allow_viewer: bool = False):
    """Gate the ADMIN_TOKEN-backed relay proxy by the CALLER's role.

    These routes proxy to the relay using the console's break-glass ADMIN_TOKEN,
    so the relay can't distinguish who is calling — the console MUST verify the
    caller is themselves an admin (or viewer for read-only routes). Without this,
    any logged-in `user` could read/mutate the whole registry through the proxy.
    """
    if not _li.admin_enabled():
        raise HTTPException(status_code=403, detail="Admin is not enabled on this instance")
    if not _multi_user_mode():
        return  # single-operator console (no user sessions to distinguish)
    session = _session_from_cookies(dict(request.cookies))
    if not session:
        raise HTTPException(status_code=401, detail="login required")
    role = session.get("role")
    if role == "admin" or (allow_viewer and role == "viewer"):
        return
    raise HTTPException(status_code=403, detail="admin role required")


@app.get("/api/admin/registry")
def admin_registry(request: Request):
    _require_console_admin(request, allow_viewer=True)
    status, body = _li.admin_request("GET", "/admin/registry")
    return JSONResponse(status_code=status, content=body)


@app.get("/api/admin/history")
def admin_history(request: Request):
    _require_console_admin(request, allow_viewer=True)
    status, body = _li.admin_request("GET", "/admin/history")
    return JSONResponse(status_code=status, content=body)


@app.post("/api/admin/user/{subdomain}/{action}")
def admin_user_action(request: Request, subdomain: str, action: str):
    _require_console_admin(request)
    if action not in ("enable", "disable"):
        raise HTTPException(status_code=400, detail="action must be 'enable' or 'disable'")
    status, body = _li.admin_request("POST", f"/admin/user/{subdomain}/{action}")
    return JSONResponse(status_code=status, content=body)


@app.delete("/api/admin/user/{subdomain}")
def admin_user_delete(request: Request, subdomain: str):
    _require_console_admin(request)
    status, body = _li.admin_request("DELETE", f"/admin/user/{subdomain}")
    return JSONResponse(status_code=status, content=body)


@app.post("/api/admin/users/delete")
def admin_users_delete(request: Request, body: AdminBatchDeleteRequest):
    """Batch teardown — deletes each subdomain's relay registry row in turn.

    Best-effort per-row: one failure doesn't stop the rest. Response:
    {ok, results: [{subdomain, status}]}.
    """
    _require_console_admin(request)
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


@app.get("/api/auth/invite-info")
def auth_invite_info(request: Request, token: str = Query(...)):
    return _proxy_auth(request, "GET", f"/auth/invite-info?token={quote(token, safe='')}")


@app.post("/api/auth/accept-invite")
def auth_accept_invite(request: Request, body: AuthAcceptInviteRequest):
    return _proxy_auth(request, "POST", "/auth/accept-invite", body.dict())


# Self-service account requests. request-account is PUBLIC (a logged-out visitor,
# already past Cloudflare Access, asks for a console account) — the relay gates the
# rest on an admin session. Cookies are forwarded either way (harmless when absent).
@app.post("/api/auth/request-account")
def auth_request_account(request: Request, body: AccountRequestReq):
    return _proxy_auth(request, "POST", "/auth/request-account", body.dict())


@app.get("/api/auth/request-info")
def auth_request_info(request: Request, token: str = Query(...)):
    return _proxy_auth(request, "GET", f"/auth/request-info?token={quote(token, safe='')}")


@app.post("/api/auth/accept-request")
def auth_accept_request(request: Request, body: AcceptRequestReq):
    return _proxy_auth(request, "POST", "/auth/accept-request", body.dict())


@app.delete("/api/auth/requests/{token}")
def auth_decline_request(request: Request, token: str):
    return _proxy_auth(request, "DELETE", f"/auth/requests/{quote(token, safe='')}")


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


# ---------------------------------------------------------------------------
# Phase 2 — Deploy Knowledge Objects
#
# A logged-in user stores their OWN S1 console URL + API token (kept encrypted
# at rest on the relay, never returned to the browser). The backend reads the
# raw creds server-side (via lab_identity.s1_config_raw, ADMIN_TOKEN break-glass)
# and deploys selected STAR detections / HA workflows / SDL dashboards to THEIR
# own site, then activates them.
#
# Verified live contracts (reference console, site 2433185103040607397):
#   detection: POST /web/api/v2.1/cloud-detection/rules  {data(no _-keys), filter:{siteIds:[site]}}
#              → 200, id at data.id; enable via PUT .../rules/enable {filter:{ids:[id]}}
#   ha:        POST .../hyper-automate/api/public/workflow-import-export/import?siteIds=<s> {data:wf}
#              → 200, id+version_id top-level; publish via
#              POST .../hyper-automate/api/v1/workflows/{id}/publish?siteIds=<s>  (siteIds ONLY —
#              adding accountIds triggers "User Context Service Error" with a service token) → 204
#   dashboard: SDL POST {sdl_xdr_url}/api/putFile {path:/dashboards/<key>, content} Bearer sdl_write_key
# ---------------------------------------------------------------------------

def _s1_request(base: str, token: str, method: str, path: str,
                params: Optional[dict] = None, json_body=None, scheme: str = "ApiToken"):
    """One S1/SDL HTTP call. Returns (status_code, parsed_json_or_raw_dict).
    Never logs or returns the token. scheme is 'ApiToken' (mgmt/console) or
    'Bearer' (SDL config API)."""
    import httpx
    url = base.rstrip("/") + path
    headers = {"Authorization": f"{scheme} {token}", "Content-Type": "application/json"}
    try:
        with httpx.Client(timeout=45) as client:
            r = client.request(method, url, params=params, json=json_body, headers=headers)
    except httpx.HTTPError as exc:
        return 502, {"error": f"unreachable: {exc}"}
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {"_raw": r.text[:300]}


def _sdl_request(sdl_url: str, sdl_key: str, path: str, json_body: dict):
    """SDL config API call (Bearer auth, POST). sdl_key is the caller's console
    service-user token — on Mgmt Z SP5+ it unlocks all SDL config methods, so no
    separate SDL Config Write key is needed."""
    return _s1_request(sdl_url, sdl_key, "POST", path, json_body=json_body, scheme="Bearer")


def _derive_sdl_xdr_url(console_url: str) -> Optional[str]:
    """Best-effort SDL/XDR host from the console URL region. The console host is
    `<region>-<company>.sentinelone.net` (e.g. usea1-acme); the SDL host is
    `xdr.<dataRegion>.sentinelone.net` where dataRegion = the region's leading two
    letters + trailing digits (usea1→us1, euce1→eu1, apse2→ap2). Verified:
    usea1-partners → xdr.us1.sentinelone.net."""
    import re
    try:
        host = console_url.split("//", 1)[-1].split("/", 1)[0]
        region = host.split(".", 1)[0].split("-", 1)[0]  # usea1-partners → usea1
        m = re.match(r"^([a-z]{2})[a-z]*([0-9]+)$", region)
        if not m:
            return None
        return f"https://xdr.{m.group(1)}{m.group(2)}.sentinelone.net"
    except Exception:
        return None


def _resolve_sdl_url(cfg: dict) -> Optional[str]:
    """The SDL/XDR base URL: the operator's explicit override if set, else derived
    from the console region."""
    override = (cfg.get("sdl_xdr_url") or "").strip()
    return override.rstrip("/") if override else _derive_sdl_xdr_url(cfg.get("console_url") or "")


def _s1_err(status, body) -> str:
    """Compact human error string from an S1 response body."""
    if isinstance(body, dict):
        errs = body.get("errors")
        if isinstance(errs, list) and errs:
            e0 = errs[0] if isinstance(errs[0], dict) else {}
            return f"HTTP {status}: {e0.get('detail') or e0.get('title') or errs[0]}"
        detail = body.get("detail") or body.get("error") or body.get("message")
        if detail:
            return f"HTTP {status}: {detail}"
    return f"HTTP {status}"


def _audit(event: dict):
    """Best-effort admin audit-log write via the relay's ADMIN_TOKEN break-glass
    route (POST /admin/audit). Must never raise — an audit-log failure can never
    be allowed to break login/register/deploy."""
    try:
        _li.admin_request("POST", "/admin/audit", json_body=event)
    except Exception:
        pass


def _deploy_load_creds(request: Request):
    """Resolve the caller's session email, then pull their RAW S1 deploy creds
    from the relay (ADMIN_TOKEN break-glass). Raises HTTPException on any gap.
    Returns (email, cfg) where cfg has console_url/api_token/sdl_*."""
    if not _multi_user_mode():
        raise HTTPException(status_code=400, detail="Deploy is a multi-user console feature.")
    session = _session_from_cookies(dict(request.cookies))
    if not session:
        raise HTTPException(status_code=401, detail="login required")
    email = session["email"]
    status, cfg = _li.s1_config_raw(email)
    if status == 404:
        raise HTTPException(status_code=400,
                            detail="No SentinelOne console configured — save your console URL + API token first.")
    if status != 200 or not isinstance(cfg, dict) or not cfg.get("console_url") or not cfg.get("api_token"):
        msg = (cfg.get("error") if isinstance(cfg, dict) else None) or "could not read stored S1 config"
        raise HTTPException(status_code=502, detail=msg)
    return session, cfg


def _deploy_pick_site(cookies: dict, console: str, token: str, messages: list):
    """Pick the caller's target site: prefer the site whose name matches their
    tenant site_label (from /auth/lab/identity), else the token's first site."""
    st, data = _s1_request(console, token, "GET", "/web/api/v2.1/sites", params={"limit": 100})
    if st != 200 or not isinstance(data, dict):
        messages.append(f"could not list sites ({_s1_err(st, data)})")
        return None
    sites = (data.get("data") or {}).get("sites") or []
    if not sites:
        messages.append("this API token has access to no sites")
        return None
    label = None
    lst, ldata, _ = _li.auth_request("GET", "/auth/lab/identity", cookies=cookies)
    if lst == 200 and isinstance(ldata, dict):
        ident = ldata.get("identity")
        if isinstance(ident, dict):
            label = (ident.get("site_label") or "").strip().lower()
    chosen = None
    if label:
        for s in sites:
            if (s.get("name") or "").strip().lower() == label:
                chosen = s
                break
        if not chosen:
            messages.append(f"tenant site '{label}' not found for this token — using the first available site")
    if not chosen:
        chosen = sites[0]
    return {"id": chosen.get("id"), "name": chosen.get("name"), "accountId": chosen.get("accountId")}


def _deploy_detection(console: str, token: str, site: dict, obj: DeployObject) -> dict:
    payload = obj.payload if isinstance(obj.payload, dict) else {}
    data = {k: v for k, v in (payload.get("data") or {}).items() if not str(k).startswith("_")}
    name = data.get("name")
    if not name:
        return {"key": obj.key, "type": "detection", "status": "error", "message": "payload.data.name missing"}
    data.setdefault("queryLang", "2.0")
    site_id = site["id"]
    # Dedup: an existing rule with the same name on this site → don't duplicate.
    st, listing = _s1_request(console, token, "GET", "/web/api/v2.1/cloud-detection/rules",
                              params={"isLegacy": "false", "limit": 200, "siteIds": site_id})
    if st == 200 and isinstance(listing, dict):
        for r in listing.get("data", []):
            if (r.get("name") or "") == name:
                rid = r.get("id")
                _s1_request(console, token, "PUT", "/web/api/v2.1/cloud-detection/rules/enable",
                            json_body={"filter": {"ids": [rid]}})
                return {"key": obj.key, "type": "detection", "status": "skipped", "id": rid,
                        "message": "a rule with this name already exists on the site (ensured enabled)"}
    body = {"data": data, "filter": {"siteIds": [site_id]}}
    st, created = _s1_request(console, token, "POST", "/web/api/v2.1/cloud-detection/rules", json_body=body)
    if st != 200 or not isinstance(created, dict):
        return {"key": obj.key, "type": "detection", "status": "error", "message": _s1_err(st, created)}
    rid = (created.get("data") or {}).get("id")
    if not rid:
        return {"key": obj.key, "type": "detection", "status": "error", "message": "create returned no rule id"}
    est, _en = _s1_request(console, token, "PUT", "/web/api/v2.1/cloud-detection/rules/enable",
                           json_body={"filter": {"ids": [rid]}})
    return {"key": obj.key, "type": "detection", "status": "deployed", "id": rid,
            "message": "created + enabled" if est == 200 else f"created; enable returned HTTP {est}"}


def _deploy_ha(console: str, token: str, site: dict, obj: DeployObject) -> dict:
    wf = obj.payload if isinstance(obj.payload, dict) else {}
    name = wf.get("name")
    if not name:
        return {"key": obj.key, "type": "ha", "status": "error", "message": "payload.name missing"}
    site_id = site["id"]
    # Dedup by exact name (server-side name__eq filter).
    st, listing = _s1_request(console, token, "GET",
                              "/web/api/v2.1/hyper-automate/api/public/workflows",
                              params={"name__eq": name, "limit": 5, "siteIds": site_id})
    if st == 200 and isinstance(listing, dict) and (listing.get("data") or []):
        wid = (listing["data"][0] or {}).get("id")
        return {"key": obj.key, "type": "ha", "status": "skipped", "id": wid,
                "message": "a workflow with this name already exists on the site"}
    st, imp = _s1_request(console, token, "POST",
                          "/web/api/v2.1/hyper-automate/api/public/workflow-import-export/import",
                          params={"siteIds": site_id}, json_body={"data": wf})
    if st not in (200, 201) or not isinstance(imp, dict):
        return {"key": obj.key, "type": "ha", "status": "error", "message": _s1_err(st, imp)}
    # Import returns BOTH id and version_id at the top level (an imported workflow
    # is a Private Draft owned by the token's user — INVISIBLE in the console until
    # it is activated/published). Capture both so we can actually activate it.
    idata = imp.get("data") if isinstance(imp.get("data"), dict) else imp
    wid = imp.get("id") or (idata or {}).get("id")
    vid = imp.get("version_id") or (idata or {}).get("version_id")
    if not wid:
        return {"key": obj.key, "type": "ha", "status": "error", "message": "import returned no workflow id"}

    # ACTIVATE the imported version → state becomes Active (running) AND the draft
    # leaves Private, so it's visible to the team in the console. This is the step
    # that actually "uploads" a usable workflow. All HA ops scope with siteIds ONLY
    # (accountIds 400s "User Context Service Error" for service-user tokens).
    if vid:
        ast, abody = _s1_request(console, token, "POST",
                                 f"/web/api/v2.1/hyper-automate/api/public/workflows/{wid}/{vid}/activation",
                                 params={"siteIds": site_id}, json_body={"data": {}})
        if ast in (200, 204):
            return {"key": obj.key, "type": "ha", "status": "deployed", "id": wid,
                    "message": "imported + activated (Active in the console)"}
        act_err = _s1_err(ast, abody)
    else:
        act_err = "import returned no version_id"

    # Activation failed — at least publish so the workflow becomes a Shared Draft
    # (visible in the console, not yet running) rather than an invisible private one.
    pst, pbody = _s1_request(console, token, "POST",
                             f"/web/api/v2.1/hyper-automate/api/v1/workflows/{wid}/publish",
                             params={"siteIds": site_id}, json_body={})
    if pst in (200, 204):
        return {"key": obj.key, "type": "ha", "status": "deployed", "id": wid,
                "message": f"imported + published as a shared draft (visible but NOT running — "
                           f"activation failed: {act_err}). Activate it in the console."}
    return {"key": obj.key, "type": "ha", "status": "error", "id": wid,
            "message": f"imported but could not activate or publish — it's an invisible private draft "
                       f"(activation: {act_err}; publish: {_s1_err(pst, pbody)})."}


def _deploy_dashboard(cfg: dict, obj: DeployObject) -> dict:
    sdl_url = _resolve_sdl_url(cfg)
    if not sdl_url:
        return {"key": obj.key, "type": "dashboard", "status": "skipped",
                "message": "could not determine your SDL region — set the SDL XDR URL in Configure"}
    content = obj.payload if isinstance(obj.payload, str) else json.dumps(obj.payload)
    # The console service-user token doubles as the SDL Bearer (Mgmt Z SP5+).
    st, body = _sdl_request(sdl_url, cfg["api_token"], "/api/putFile",
                            {"path": f"/dashboards/{obj.key}", "content": content})
    ok = st == 200 and isinstance(body, dict) and str(body.get("status", "")).startswith("success")
    if ok:
        return {"key": obj.key, "type": "dashboard", "status": "deployed",
                "message": f"putFile /dashboards/{obj.key}"}
    return {"key": obj.key, "type": "dashboard", "status": "error", "message": _s1_err(st, body)}


@app.get("/api/deploy/config")
def deploy_config_get(request: Request):
    """Redacted status of the caller's stored S1 deploy config (proxies the relay
    with the session cookie). {configured, console_url, has_token, has_sdl, updated_at}."""
    return _proxy_auth(request, "GET", "/auth/s1/config")


@app.post("/api/deploy/config")
def deploy_config_post(request: Request, body: DeployConfigReq):
    """Upsert the caller's S1 deploy config. api_token / sdl_write_key are
    write-only (null preserves the stored secret). Returns the redacted status."""
    return _proxy_auth(request, "POST", "/auth/s1/config", body.dict())


@app.delete("/api/deploy/config")
def deploy_config_delete(request: Request):
    """Clear the caller's stored S1 deploy config."""
    return _proxy_auth(request, "DELETE", "/auth/s1/config")


@app.post("/api/deploy/validate")
def deploy_validate(request: Request):
    """Validate the caller's stored S1 creds: resolve their site + probe which
    object types can be deployed. Never echoes the token.
    Response: {ok, console_url, site:{id,name,accountId}, capabilities:{detections,ha,dashboards}, messages:[]}."""
    _session, cfg = _deploy_load_creds(request)
    console = cfg["console_url"].rstrip("/")
    token = cfg["api_token"]
    messages: list = []
    site = _deploy_pick_site(dict(request.cookies), console, token, messages)
    if not site:
        raise HTTPException(status_code=502, detail="; ".join(messages) or "no deployable site for this token")
    caps = {"detections": False, "ha": False, "dashboards": False}
    st, _ = _s1_request(console, token, "GET", "/web/api/v2.1/cloud-detection/rules",
                        params={"isLegacy": "false", "limit": 1, "siteIds": site["id"]})
    caps["detections"] = st == 200
    if st != 200:
        messages.append(f"detections probe returned HTTP {st}")
    st, _ = _s1_request(console, token, "GET", "/web/api/v2.1/hyper-automate/api/v1/workflows",
                        params={"limit": 1, "siteIds": site["id"]})
    caps["ha"] = st == 200
    if st != 200:
        messages.append(f"hyperautomation probe returned HTTP {st}")
    sdl_url = _resolve_sdl_url(cfg)
    if sdl_url:
        # The console token itself does SDL config ops — probe with it (no separate key).
        st, body = _sdl_request(sdl_url, token, "/api/listFiles", {"path": "/dashboards"})
        caps["dashboards"] = st == 200 and isinstance(body, dict) and str(body.get("status", "")).startswith("success")
        if caps["dashboards"]:
            messages.append(f"SDL region resolved to {sdl_url}")
        else:
            messages.append(f"SDL probe ({sdl_url}) returned HTTP {st} — your token needs the "
                            "SDL Dashboards + SDL Configuration Files permissions, or set the SDL XDR URL manually")
    else:
        messages.append("Could not auto-detect your SDL region — set the SDL XDR URL to deploy dashboards")
    return {"ok": True, "console_url": console, "site": site, "capabilities": caps, "messages": messages}


@app.post("/api/deploy/run")
def deploy_run(request: Request, body: DeployRunReq):
    """Deploy + activate the selected objects to the caller's own site. The
    frontend sends each artifact JSON as `payload` (manifest is client-side truth;
    the backend reads no repo files). Per-object result:
    {key, type, status:'deployed'|'skipped'|'error', id?, message}."""
    def _resolved_email():
        try:
            s = _session_from_cookies(dict(request.cookies))
            return s.get("email") if s else None
        except Exception:
            return None

    try:
        session, cfg = _deploy_load_creds(request)
    except HTTPException as exc:
        _audit({"type": "dko_deploy_failure", "status": "failure",
                "actor": _resolved_email(), "reason": exc.detail})
        raise
    if session.get("role") == "viewer":
        raise HTTPException(status_code=403, detail="viewers cannot deploy")
    console = cfg["console_url"].rstrip("/")
    token = cfg["api_token"]
    messages: list = []
    site = _deploy_pick_site(dict(request.cookies), console, token, messages)
    if not site:
        detail = "; ".join(messages) or "no deployable site for this token"
        _audit({"type": "dko_deploy_failure", "status": "failure",
                "actor": session.get("email"), "reason": detail})
        raise HTTPException(status_code=502, detail=detail)
    results = []
    for obj in body.objects:
        try:
            if obj.payload_b64:
                import base64
                obj.payload = json.loads(base64.b64decode(obj.payload_b64))
            if obj.type == "detection":
                results.append(_deploy_detection(console, token, site, obj))
            elif obj.type == "ha":
                results.append(_deploy_ha(console, token, site, obj))
            elif obj.type == "dashboard":
                results.append(_deploy_dashboard(cfg, obj))
            else:
                results.append({"key": obj.key, "type": obj.type, "status": "error",
                                "message": f"unknown object type '{obj.type}'"})
        except Exception as exc:  # one bad object must not abort the batch
            results.append({"key": obj.key, "type": obj.type, "status": "error", "message": str(exc)[:200]})
    deployed = sum(1 for r in results if r.get("status") == "deployed")
    skipped = sum(1 for r in results if r.get("status") == "skipped")
    failed = sum(1 for r in results if r.get("status") == "error")
    _audit({
        "type": "dko_deploy",
        "status": "success" if failed == 0 else "failure",
        "actor": session.get("email"),
        "site": site.get("name"),
        "site_id": site.get("id"),
        "deployed": deployed,
        "skipped": skipped,
        "failed": failed,
        "failures": [{"key": r["key"], "type": r["type"], "message": r.get("message")}
                     for r in results if r.get("status") == "error"],
    })
    return {"ok": True, "site": site, "results": results}
