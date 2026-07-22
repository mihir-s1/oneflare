#!/usr/bin/env python3
"""Reverse every OneFlare CF1-* demo artifact on the soledrop.co lab.

Mirrors the CF1-Reset-Demo Hyperautomation playbook, as a fast local CLI. Removes:
  1. Zone IP access rules  (notes contain "OneFlare")
  2. Custom-firewall Ruleset rules  (description contains "OneFlare")
  3. Zero-Trust Gateway rules  (name contains "OneFlare")
  4. Sinkhole DNS records  (comment contains "OneFlare", or name c2sink-demo.soledrop.co)
  5. Reverts zone security level (Under Attack → medium)

Dry-run by default; pass --apply to delete. Reads CLOUDFLARE_API_TOKEN from env or .env.local.

  python3 scripts/reset_cf1_demo.py           # show what would be reverted
  python3 scripts/reset_cf1_demo.py --apply    # revert
"""
import json, urllib.request, urllib.error, re, os, sys

ACCOUNT_ID = "b8e637d5097fff0c694c3290ba81563e"
ZONE_ID    = "cf4d15af4a7eb86b033f859aefec1047"   # soledrop.co
RULESET_ID = "47e1f8f7826b485498964c658c551f22"   # http_request_firewall_custom entrypoint
MARKER     = "oneflare"
BASE = "https://api.cloudflare.com/client/v4"
APPLY = "--apply" in sys.argv

def load_token():
    if os.environ.get("CLOUDFLARE_API_TOKEN"):
        return os.environ["CLOUDFLARE_API_TOKEN"]
    for p in (os.path.join(os.path.dirname(__file__), "..", ".env.local"),
              os.path.join(os.getcwd(), ".env.local")):
        if os.path.exists(p):
            m = re.search(r'^(?:export\s+)?CLOUDFLARE_API_TOKEN\s*=\s*(.+)$', open(p).read(), re.M)
            if m: return m.group(1).strip().strip('"').strip("'")
    sys.exit("CLOUDFLARE_API_TOKEN not found (env or .env.local)")

TOK = load_token()
def cf(path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
        headers={"Authorization": f"Bearer {TOK}", "Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=45); raw = r.read().decode()
        return r.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try: return e.code, json.loads(raw)
        except: return e.code, {"raw": raw[:400]}

def do(path, label, method="DELETE", body=None):
    if not APPLY:
        print(f"  [dry-run] {method} {label}"); return
    st, d = cf(path, method, body)
    ok = isinstance(d, dict) and d.get("success")
    print(f"  {'OK ' if ok else f'FAIL {st}'} {method} {label}")

n = 0
# 1. IP access rules
st, d = cf(f"/zones/{ZONE_ID}/firewall/access_rules/rules?per_page=100")
print(f"\n== IP access rules (HTTP {st}) ==")
for r in (d.get("result") or []):
    if MARKER in (r.get("notes") or "").lower():
        n += 1; do(f"/zones/{ZONE_ID}/firewall/access_rules/rules/{r['id']}",
                   f"access_rule {r.get('mode')} {(r.get('configuration') or {}).get('value')}")

# 2. Ruleset rules
st, d = cf(f"/zones/{ZONE_ID}/rulesets/{RULESET_ID}")
rules = ((d.get("result") or {}).get("rules")) or []
print(f"\n== Ruleset rules (HTTP {st}) ==")
for r in rules:
    if MARKER in (r.get("description") or "").lower():
        n += 1; do(f"/zones/{ZONE_ID}/rulesets/{RULESET_ID}/rules/{r['id']}",
                   f"ruleset rule '{r.get('description')}'")

# 3. Gateway rules
st, d = cf(f"/accounts/{ACCOUNT_ID}/gateway/rules")
print(f"\n== Gateway rules (HTTP {st}) ==")
for r in (d.get("result") or []):
    if MARKER in (r.get("name") or "").lower():
        n += 1; do(f"/accounts/{ACCOUNT_ID}/gateway/rules/{r['id']}", f"gateway rule '{r.get('name')}'")

# 4. Sinkhole DNS records
st, d = cf(f"/zones/{ZONE_ID}/dns_records?per_page=100")
print(f"\n== Sinkhole DNS records (HTTP {st}) ==")
for r in (d.get("result") or []):
    if MARKER in (r.get("comment") or "").lower() or (r.get("name") or "").startswith("c2sink-demo."):
        n += 1; do(f"/zones/{ZONE_ID}/dns_records/{r['id']}", f"DNS {r.get('type')} {r.get('name')}")

# 5. Revert Under Attack mode
st, d = cf(f"/zones/{ZONE_ID}/settings/security_level")
cur = (d.get("result") or {}).get("value")
print(f"\n== Security level (currently {cur}) ==")
if cur and cur != "medium":
    n += 1; do(f"/zones/{ZONE_ID}/settings/security_level", "security_level → medium",
               method="PATCH", body={"value": "medium"})
else:
    print("  already medium — no revert needed")

print(f"\n{'Reverted' if APPLY else 'Would revert'} {n} artifact(s)."
      + ("" if APPLY else "  Re-run with --apply."))
