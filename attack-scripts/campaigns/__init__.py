"""
campaigns/__init__.py — Campaign registry for the ThreatOps drip-flow engine.

CAMPAIGNS maps a campaign key to display metadata + the module's PHASES list.
Consumed by:
  - lab-ui/backend/main.py  GET /api/campaigns
  - The asyncio drip task that calls fire_one / fire_many per phase

target_role tells the backend which NovaMind worker to use as the base URL:
  "shop"   → config.SHOP_URL   (novamind-shop)
  "portal" → config.PORTAL_URL (novamind-portal)
  "api"    → config.API_URL    (novamind-api)
"""

from .financial  import PHASES as _FINANCIAL_PHASES
from .healthcare import PHASES as _HEALTHCARE_PHASES
from .saas       import PHASES as _SAAS_PHASES
from .ctf        import PHASES as _CTF_PHASES

CAMPAIGNS = {
    "financial": {
        "name":        "Operation Wire Fraud",
        "campaign":    "Financial Services",
        "color":       "#1a5276",
        "icon":        "bank",
        "target_role": "api",          # primary target: novamind-api
        "PHASES":      _FINANCIAL_PHASES,
        "num_phases":  len(_FINANCIAL_PHASES),
    },
    "healthcare": {
        "name":        "Operation HIPAA Breach",
        "campaign":    "Healthcare",
        "color":       "#1e8449",
        "icon":        "health",
        "target_role": "api",          # primary target: novamind-api
        "PHASES":      _HEALTHCARE_PHASES,
        "num_phases":  len(_HEALTHCARE_PHASES),
    },
    "saas": {
        "name":        "Operation Tenant Escape",
        "campaign":    "SaaS / Tech",
        "color":       "#6c3483",
        "icon":        "cloud",
        "target_role": "api",          # primary target: novamind-api
        "PHASES":      _SAAS_PHASES,
        "num_phases":  len(_SAAS_PHASES),
    },
    "ctf": {
        "name":        "Operation Agentic AI Breakout",
        "campaign":    "OneFlare CTF",
        "color":       "#7c2d12",
        "icon":        "brain",
        "target_role": "api",          # primary: novamind-api (/api/v1/chat etc.)
        "PHASES":      _CTF_PHASES,
        "num_phases":  len(_CTF_PHASES),
    },
}

__all__ = ["CAMPAIGNS"]
