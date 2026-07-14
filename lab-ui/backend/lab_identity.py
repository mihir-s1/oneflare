"""Multi-tenant lab identity + relay client (feat/multi-tenant-relay).

Each dockerized OneFlare instance has ONE lab identity: a name that maps to a
unique subdomain `<slug>.lab.soledrop.co`. Registering it (Settings → Lab
Identity) enrolls the instance with the shared logpush-relay Worker so this
instance's Cloudflare telemetry is routed to the user's OWN SentinelOne site.

Design:
- The identity is persisted to a writable JSON file (survives restarts) and its
  shop_url is applied to `os.environ["SHOP_URL_OVERRIDE"]` so every attack run
  (both the in-process campaign engine and the subprocess scenarios) targets the
  instance's own subdomain.
- Enrollment with the relay is best-effort: if RELAY_URL is unset (e.g. before
  the relay is deployed) the subdomain is still computed + applied locally so
  targeting works; only the remote registry write is skipped.
- Admin proxy helpers are gated by ADMIN_TOKEN presence — only the console
  deployment (one-flare.com) sets it, so partner instances expose no admin.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Optional

LAB_DOMAIN = os.getenv("LAB_DOMAIN", "lab.soledrop.co")

# Persist under the attack-scripts logs volume (writable + docker-persistent);
# overridable for tests/other layouts.
IDENTITY_FILE = Path(
    os.getenv("LAB_IDENTITY_FILE", "/app/attack-scripts/logs/lab_identity.json")
)

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(name: str) -> str:
    """Match the relay's slugify: lowercase, non-[a-z0-9] -> '-', collapse, trim."""
    s = _SLUG_RE.sub("-", str(name or "").lower()).strip("-")
    return re.sub(r"-{2,}", "-", s)


def admin_enabled() -> bool:
    return bool(os.getenv("ADMIN_TOKEN"))


def _relay_base() -> str:
    return (os.getenv("RELAY_URL") or "").rstrip("/")


# ── identity persistence ────────────────────────────────────────────────────

def load_identity() -> Optional[dict]:
    try:
        return json.loads(IDENTITY_FILE.read_text())
    except (OSError, ValueError):
        return None


def _save_identity(data: dict) -> None:
    try:
        IDENTITY_FILE.parent.mkdir(parents=True, exist_ok=True)
        IDENTITY_FILE.write_text(json.dumps(data, indent=2))
    except OSError:
        # Persistence is best-effort; the in-process override below still applies
        # for the current process lifetime.
        pass


def apply_identity(shop_url: str) -> None:
    """Point ALL scenario traffic (shop/portal/api) at this instance's subdomain.

    In the multi-tenant model every user has ONE host `<slug>.lab.soledrop.co`
    served by the SoleDrop shop worker, so shop/portal/api collapse onto it. This
    keeps all scenarios isolated to the user's site: Cloudflare WAF/Bot/AI scores
    and LOGS every request (incl. 404s) with the attack markers in the query
    string / UA, and detections key on those — not on the origin response — so
    they still fire even where the shop worker doesn't serve that exact path.
    (DNS tunneling is Gateway/DoH-based and account-level — not routed here.)"""
    if shop_url:
        u = shop_url.rstrip("/")
        os.environ["SHOP_URL_OVERRIDE"] = u
        os.environ["PORTAL_URL_OVERRIDE"] = u
        os.environ["API_URL_OVERRIDE"] = u


def bootstrap() -> Optional[dict]:
    """Re-apply a persisted identity at process startup. Returns it (or None)."""
    ident = load_identity()
    if ident and ident.get("shop_url"):
        apply_identity(ident["shop_url"])
    return ident


# ── registration (relay enrollment) ─────────────────────────────────────────

def register(name: str, s1_hec_url: str, s1_hec_token: str) -> dict:
    """Enroll this instance. Returns the identity dict.

    Raises ValueError on bad input, RuntimeError on a relay rejection.
    """
    slug = slugify(name)
    if not slug:
        raise ValueError("name did not produce a valid subdomain slug")
    if not s1_hec_url or not s1_hec_token:
        raise ValueError("s1_hec_url and s1_hec_token are required")

    subdomain = f"{slug}.{LAB_DOMAIN}"
    shop_url = f"https://{subdomain}"
    enrolled = False

    base = _relay_base()
    if base:
        import httpx

        enroll_code = os.getenv("LAB_ENROLL_CODE", "")
        try:
            resp = httpx.post(
                f"{base}/register",
                headers={"X-Enroll-Code": enroll_code},
                json={
                    "name": name,
                    "s1_hec_url": s1_hec_url,
                    "s1_hec_token": s1_hec_token,
                },
                timeout=15,
            )
        except httpx.HTTPError as exc:
            raise RuntimeError(f"could not reach relay at {base}: {exc}") from exc
        if resp.status_code >= 300:
            raise RuntimeError(
                f"relay rejected registration ({resp.status_code}): {resp.text[:200]}"
            )
        data = resp.json()
        # Trust the relay's assigned subdomain (authoritative slugify).
        subdomain = data.get("subdomain", subdomain)
        shop_url = data.get("shop_url", f"https://{subdomain}")
        enrolled = True

    ident = {
        "name": name,
        "subdomain": subdomain,
        "shop_url": shop_url,
        "enrolled": enrolled,
        # NOTE: the S1 HEC token is sent to the relay but intentionally NOT
        # persisted on this instance — the relay is the system of record.
        "s1_hec_url": s1_hec_url,
    }
    _save_identity(ident)
    apply_identity(shop_url)
    return ident


# ── admin proxy (console deployment only) ───────────────────────────────────

def admin_request(method: str, path: str) -> tuple[int, dict]:
    """Proxy an /admin/* call to the relay using this console's ADMIN_TOKEN.

    Returns (status_code, json). Callers must have already checked admin_enabled().
    """
    base = _relay_base()
    if not base:
        return 503, {"error": "RELAY_URL not configured"}
    token = os.getenv("ADMIN_TOKEN", "")
    import httpx

    try:
        resp = httpx.request(
            method,
            f"{base}{path}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
    except httpx.HTTPError as exc:
        return 502, {"error": f"relay unreachable: {exc}"}
    try:
        body = resp.json()
    except ValueError:
        body = {"error": resp.text[:300]}
    return resp.status_code, body
