import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env.local from project root
load_dotenv(Path(__file__).parent.parent / ".env.local")

DOMAIN = os.getenv("CLOUDFLARE_DOMAIN", "novamind-lab.workers.dev")

# Target URLs — workers.dev by default, auto-swaps when CLOUDFLARE_DOMAIN is a custom domain
if "workers.dev" in DOMAIN:
    SHOP_URL   = f"https://novamind-shop.{DOMAIN}"
    PORTAL_URL = f"https://novamind-portal.{DOMAIN}"
    API_URL    = f"https://novamind-api.{DOMAIN}"
else:
    SHOP_URL   = f"https://shop.{DOMAIN}"
    PORTAL_URL = f"https://portal.{DOMAIN}"
    API_URL    = f"https://api.{DOMAIN}"

# Lab credentials (match Wrangler secrets or Worker defaults)
PORTAL_USERNAME = os.getenv("PORTAL_USERNAME", "admin@novamind.ai")
PORTAL_PASSWORD = os.getenv("PORTAL_PASSWORD", "AcmeAdmin2026!")
API_USERNAME    = os.getenv("API_USERNAME",    "api_user@novamind.ai")
API_PASSWORD    = os.getenv("API_PASSWORD",    "ApiUser2026!")

# Wordlists
WORDLIST_DIR = Path(__file__).parent / "wordlists"
USERNAMES = (WORDLIST_DIR / "usernames.txt").read_text().splitlines()
PASSWORDS = (WORDLIST_DIR / "passwords.txt").read_text().splitlines()

# DNS tunneling target — uses a domain we control to generate realistic C2-like queries
DNS_C2_DOMAIN = "c2tunnel.novamind-lab.workers.dev"

# Incident webhook — campaigns/incident.py posts to this endpoint
INCIDENT_KEY = os.getenv("INCIDENT_KEY", "")

# Logs output directory
LOGS_DIR = Path(__file__).parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# Cloudflare Gateway DoH endpoint for the lab's Zero Trust location.
# Find it at: one.dash.cloudflare.com → Networks → Resolvers & Proxies → DNS locations
#             → [your location] → Edit → Setup instructions → DNS over HTTPS
# Format: https://<hex-id>.cloudflare-gateway.com/dns-query
# IMPORTANT: use the hex-subdomain URL, NOT your team name — the team-name URL
#            resolves DNS but does not log queries to Gateway activity or Logpush.
# Without this set, DNS queries bypass Gateway entirely — no logs will appear.
CF_GATEWAY_DOH_URL = os.getenv("CF_GATEWAY_DOH_URL", "")
