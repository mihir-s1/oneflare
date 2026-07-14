import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env.local from project root
load_dotenv(Path(__file__).parent.parent / ".env.local")

# TLS verification for outbound attack traffic. Lab traffic often traverses a
# TLS-inspecting corporate proxy (Zscaler/Netskope/etc.) whose MITM cert the
# container's Python doesn't trust → CERTIFICATE_VERIFY_FAILED. Attack sims don't
# need cert validation, so default OFF (matches the campaign engine). A partner on
# a clean network can set LAB_TLS_VERIFY=true for realism.
TLS_VERIFY = os.getenv("LAB_TLS_VERIFY", "false").lower() in ("1", "true", "yes")
if not TLS_VERIFY:
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

# one-flare.com is the live attack surface (shop/portal/api.one-flare.com are
# Cloudflare-proxied with WAF + Bot Management + Logpush → S1). Guard against an
# empty env value (the backend may pass CLOUDFLARE_DOMAIN="") so URLs never
# collapse to "https://shop." — fall back to the live domain instead.
DOMAIN = os.getenv("CLOUDFLARE_DOMAIN") or "one-flare.com"

# Target URLs. An explicit *_URL_OVERRIDE (set by the lab-ui backend from the
# effective server/client config) wins; otherwise derive from the domain.
# workers.dev fallback uses the novamind-* worker names that cloudflare/setup.sh
# deploys; a custom domain uses shop|portal|api.<domain>.
def _derive_url(svc_workers: str, svc_custom: str) -> str:
    if "workers.dev" in DOMAIN:
        return f"https://{svc_workers}.{DOMAIN}"
    return f"https://{svc_custom}.{DOMAIN}"

SHOP_URL   = os.getenv("SHOP_URL_OVERRIDE")   or _derive_url("novamind-shop",   "shop")
PORTAL_URL = os.getenv("PORTAL_URL_OVERRIDE") or _derive_url("novamind-portal", "portal")
API_URL    = os.getenv("API_URL_OVERRIDE")    or _derive_url("novamind-api",    "api")

# Lab credentials (match Wrangler secrets or Worker defaults)
PORTAL_USERNAME = os.getenv("PORTAL_USERNAME", "admin@acmecorp.com")
PORTAL_PASSWORD = os.getenv("PORTAL_PASSWORD", "AcmeAdmin2026!")
API_USERNAME    = os.getenv("API_USERNAME",    "api_user@acmecorp.com")
API_PASSWORD    = os.getenv("API_PASSWORD",    "ApiUser2026!")

# Wordlists
WORDLIST_DIR = Path(__file__).parent / "wordlists"
USERNAMES = (WORDLIST_DIR / "usernames.txt").read_text().splitlines()
PASSWORDS = (WORDLIST_DIR / "passwords.txt").read_text().splitlines()

# DNS tunneling target — uses a domain we control to generate realistic C2-like queries
DNS_C2_DOMAIN = "c2tunnel.acmecorp-lab.workers.dev"

# Incident webhook — campaigns/incident.py posts to this endpoint
INCIDENT_KEY = os.getenv("INCIDENT_KEY", "")

# Logs output directory — best-effort. On ephemeral/read-only container
# filesystems (e.g. Cloudflare Containers with no persistent volume) this
# must never crash the app at import time; SessionLog.save() also guards
# each write independently.
LOGS_DIR = Path(__file__).parent / "logs"
try:
    LOGS_DIR.mkdir(exist_ok=True)
except OSError:
    pass

# Cloudflare Gateway DoH endpoint for the lab's Zero Trust location.
# Find it at: one.dash.cloudflare.com → Networks → Resolvers & Proxies → DNS locations
#             → [your location] → Edit → Setup instructions → DNS over HTTPS
# Format: https://<hex-id>.cloudflare-gateway.com/dns-query
# IMPORTANT: use the hex-subdomain URL, NOT your team name — the team-name URL
#            resolves DNS but does not log queries to Gateway activity or Logpush.
# Without this set, DNS queries bypass Gateway entirely — no logs will appear.
def _normalize_doh_url(raw: str) -> str:
    """Return a usable DoH endpoint from whatever the user pasted.

    httpx rejects a URL with no scheme ("Request URL is missing an
    'http://' or 'https://' protocol"), and a Cloudflare Gateway DoH
    endpoint lives at the /dns-query path. Accept a bare host
    ("team.cloudflareaccess.com"), a host+path, or a full URL and coerce
    it to "https://<host>/dns-query" so the scenario never crashes on a
    slightly-off value from .env.local or the Settings UI.
    """
    from urllib.parse import urlparse

    url = (raw or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.path in ("", "/"):
        url = url.rstrip("/") + "/dns-query"
    return url


CF_GATEWAY_DOH_URL = _normalize_doh_url(os.getenv("CF_GATEWAY_DOH_URL", ""))
