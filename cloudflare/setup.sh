#!/usr/bin/env bash
# =============================================================================
# OneFlare — Cloudflare Lab Setup Script
# Deploys all three Workers and applies all Cloudflare configuration
# from scratch against a new domain/account.
#
# Usage:
#   1. Copy .env.example to .env.local and fill in all values
#   2. source .env.local
#   3. bash cloudflare/setup.sh
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${BLUE}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }
step()    { echo -e "\n${BOLD}━━━ $* ━━━${RESET}"; }

# ── Prerequisite checks ───────────────────────────────────────────────────────
step "Checking prerequisites"

command -v node    >/dev/null 2>&1 || error "Node.js not found. Install from https://nodejs.org"
command -v npx     >/dev/null 2>&1 || error "npx not found. Install Node.js from https://nodejs.org"
command -v curl    >/dev/null 2>&1 || error "curl not found."
command -v python3 >/dev/null 2>&1 || error "python3 not found."

success "Node $(node -v), npx available"

# ── Environment variable validation ──────────────────────────────────────────
step "Validating environment variables"

: "${CLOUDFLARE_API_TOKEN:?  Missing CLOUDFLARE_API_TOKEN — set it in .env.local}"
: "${CLOUDFLARE_ACCOUNT_ID:? Missing CLOUDFLARE_ACCOUNT_ID — set it in .env.local}"
: "${CLOUDFLARE_ZONE_ID:?    Missing CLOUDFLARE_ZONE_ID    — set it in .env.local}"
: "${CLOUDFLARE_DOMAIN:?     Missing CLOUDFLARE_DOMAIN     — set it in .env.local}"

# Verify the token and zone are valid
ZONE_STATUS=$(curl -s "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" | python3 -c "
import sys,json; d=json.load(sys.stdin)
if not d['success']: print('ERROR:' + str(d['errors']))
else: print(d['result']['status'] + ':' + d['result']['name'])
")

if [[ "$ZONE_STATUS" == ERROR* ]]; then
  error "Zone/token validation failed: $ZONE_STATUS\nCheck your CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID."
fi

ZONE_STATE=$(echo "$ZONE_STATUS" | cut -d: -f1)
ZONE_NAME=$(echo "$ZONE_STATUS"  | cut -d: -f2)

success "Token valid — zone: $ZONE_NAME (status: $ZONE_STATE)"

if [[ "$ZONE_STATE" == "pending" ]]; then
  warn "Zone is in PENDING state. DNS for custom subdomains won't resolve until"
  warn "nameservers are delegated. Workers.dev URLs will still work."
fi

# Resolve script directory regardless of where the script is called from
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Helper: CF API ────────────────────────────────────────────────────────────
cf_api() {
  local method="$1" path="$2"
  shift 2
  curl -s -X "$method" "https://api.cloudflare.com/client/v4$path" \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    -H "Content-Type: application/json" \
    "$@"
}

cf_ok() {
  python3 -c "import sys,json; d=json.load(sys.stdin); print('ok') if d['success'] else print('err:'+str(d['errors']))"
}

# ── Step 1: Patch wrangler.toml files with real domain ───────────────────────
step "Step 1/7 — Patching wrangler.toml with domain: $CLOUDFLARE_DOMAIN"

for worker in shop portal api; do
  TOML="$SCRIPT_DIR/workers/$worker/wrangler.toml"
  # Replace YOUR_DOMAIN placeholder with actual domain
  sed -i.bak "s/YOUR_DOMAIN/$CLOUDFLARE_DOMAIN/g" "$TOML" && rm "$TOML.bak"
  success "Patched workers/$worker/wrangler.toml → $worker.$CLOUDFLARE_DOMAIN"
done

# ── Step 2: Claim workers.dev subdomain ──────────────────────────────────────
step "Step 2/7 — Claiming workers.dev subdomain"

SUBDOMAIN_RESULT=$(cf_api POST "/accounts/$CLOUDFLARE_ACCOUNT_ID/workers/subdomain" \
  --data "{\"subdomain\":\"$(echo $CLOUDFLARE_DOMAIN | tr '.' '-' | tr '[:upper:]' '[:lower:]')-lab\"}" | python3 -c "
import sys,json; d=json.load(sys.stdin)
if d['success']: print('ok:' + d['result']['subdomain'])
elif any('already' in str(e) for e in d.get('errors',[])): print('ok:existing')
else: print('err:' + str(d['errors']))
")

if [[ "$SUBDOMAIN_RESULT" == err* ]]; then
  warn "Could not claim workers.dev subdomain (may already exist): $SUBDOMAIN_RESULT"
else
  success "workers.dev subdomain ready: $SUBDOMAIN_RESULT"
fi

# ── Step 3: Deploy Workers ────────────────────────────────────────────────────
step "Step 3/7 — Deploying Workers"

for worker in shop portal api; do
  info "Deploying novamind-$worker..."
  (cd "$SCRIPT_DIR/workers/$worker" && npx wrangler deploy --config wrangler.toml 2>&1 \
    | grep -E "Uploaded|Deployed|Error|error" || true)

  # Enable workers.dev route
  ENABLE=$(cf_api POST "/accounts/$CLOUDFLARE_ACCOUNT_ID/workers/scripts/novamind-$worker/subdomain" \
    --data '{"enabled":true}' | cf_ok)
  [[ "$ENABLE" == "ok" ]] && success "Deployed + workers.dev enabled: novamind-$worker" \
                           || warn "workers.dev enable returned: $ENABLE"
done

# ── Step 4: Create DNS records for custom subdomains ─────────────────────────
step "Step 4/7 — Creating DNS records"

for sub in shop portal api; do
  RESULT=$(cf_api POST "/accounts/$CLOUDFLARE_ACCOUNT_ID/workers/domains" \
    --data "{
      \"hostname\": \"$sub.$CLOUDFLARE_DOMAIN\",
      \"service\":  \"novamind-$sub\",
      \"environment\": \"production\",
      \"zone_id\": \"$CLOUDFLARE_ZONE_ID\"
    }" | python3 -c "
import sys,json; d=json.load(sys.stdin)
if d['success']: print('ok')
elif any('already' in str(e).lower() for e in d.get('errors',[])): print('ok:exists')
else: print('err:'+str(d['errors']))
")

  if [[ "$RESULT" == ok* ]]; then
    success "Custom domain mapped: $sub.$CLOUDFLARE_DOMAIN → novamind-$sub"
  else
    # Fallback: plain DNS record
    DNS=$(cf_api POST "/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
      --data "{\"type\":\"AAAA\",\"name\":\"$sub\",\"content\":\"100::\",\"proxied\":true}" \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok') if d['success'] else print('err:' + str(d['errors']))")
    [[ "$DNS" == "ok" ]] && success "DNS record created: $sub.$CLOUDFLARE_DOMAIN" \
                         || warn "DNS record: $DNS (may already exist)"
  fi
done

# ── Step 5: WAF firewall rules ────────────────────────────────────────────────
step "Step 5/7 — Creating WAF firewall rules"

RULES_JSON="$SCRIPT_DIR/waf/rules.json"

# Parse filters from rules.json and create them
FILTER_IDS=()
FILTER_COUNT=$(python3 -c "import json; d=json.load(open('$RULES_JSON')); print(len(d['filters']))")

for i in $(seq 0 $((FILTER_COUNT - 1))); do
  EXPR=$(python3    -c "import json; d=json.load(open('$RULES_JSON')); print(d['filters'][$i]['expression'])")
  DESC=$(python3    -c "import json; d=json.load(open('$RULES_JSON')); print(d['filters'][$i]['description'])")
  PAYLOAD=$(python3 -c "import json,sys; print(json.dumps([{'expression': sys.argv[1], 'description': sys.argv[2]}]))" "$EXPR" "$DESC")

  RESULT=$(cf_api POST "/zones/$CLOUDFLARE_ZONE_ID/filters" --data "$PAYLOAD" | python3 -c "
import sys,json; d=json.load(sys.stdin)
if d['success']: print(d['result'][0]['id'])
else: print('err:' + str(d['errors']))
")

  if [[ "$RESULT" == err* ]]; then
    warn "Filter $i: $RESULT"
    FILTER_IDS+=("SKIP")
  else
    FILTER_IDS+=("$RESULT")
    success "Filter created: $DESC"
  fi
done

# Create rules referencing the filters
RULE_COUNT=$(python3 -c "import json; d=json.load(open('$RULES_JSON')); print(len(d['rules']))")

for i in $(seq 0 $((RULE_COUNT - 1))); do
  FI=$(python3     -c "import json; d=json.load(open('$RULES_JSON')); print(d['rules'][$i]['filter_index'])")
  ACTION=$(python3 -c "import json; d=json.load(open('$RULES_JSON')); print(d['rules'][$i]['action'])")
  DESC=$(python3   -c "import json; d=json.load(open('$RULES_JSON')); print(d['rules'][$i]['description'])")
  PRIO=$(python3   -c "import json; d=json.load(open('$RULES_JSON')); print(d['rules'][$i]['priority'])")
  FID="${FILTER_IDS[$FI]}"

  [[ "$FID" == "SKIP" ]] && warn "Skipping rule (filter failed): $DESC" && continue

  PAYLOAD=$(python3 -c "import json,sys; print(json.dumps([{'filter':{'id':sys.argv[1]},'action':sys.argv[2],'description':sys.argv[3],'priority':int(sys.argv[4])}]))" "$FID" "$ACTION" "$DESC" "$PRIO")
  RESULT=$(cf_api POST "/zones/$CLOUDFLARE_ZONE_ID/firewall/rules" --data "$PAYLOAD" | cf_ok)

  [[ "$RESULT" == "ok" ]] && success "[$ACTION] $DESC" || warn "Rule failed: $RESULT"
done

# ── Step 6: Cloudflare Access app for portal ──────────────────────────────────
step "Step 6/7 — Configuring Cloudflare Access (portal)"

ACCESS_RESULT=$(cf_api POST "/accounts/$CLOUDFLARE_ACCOUNT_ID/access/apps" --data "{
  \"name\": \"NovaMind Employee Portal\",
  \"domain\": \"portal.$CLOUDFLARE_DOMAIN\",
  \"type\": \"self_hosted\",
  \"session_duration\": \"24h\",
  \"auto_redirect_to_identity\": false,
  \"http_only_cookie_attribute\": true
}" | python3 -c "
import sys,json; d=json.load(sys.stdin)
if d['success']: print('ok:' + d['result']['id'])
elif any('already' in str(e).lower() for e in d.get('errors',[])): print('ok:exists')
else: print('err:' + str(d['errors']))
")

if [[ "$ACCESS_RESULT" == err* ]]; then
  warn "Access app: $ACCESS_RESULT (may need Access enabled in Zero Trust dashboard)"
else
  APP_ID=$(echo "$ACCESS_RESULT" | cut -d: -f2)
  success "Access app created for portal.$CLOUDFLARE_DOMAIN"

  if [[ "$APP_ID" != "exists" ]]; then
    # Employees allowed into the portal by email domain. Override with
    # ACCESS_EMAIL_DOMAIN=yourcompany.com in your .env; defaults to the
    # NovaMind sample company.
    EMAIL_DOMAIN="${ACCESS_EMAIL_DOMAIN:-novamind.ai}"
    POLICY=$(cf_api POST "/accounts/$CLOUDFLARE_ACCOUNT_ID/access/apps/$APP_ID/policies" --data "{
      \"name\": \"Allow Employees\",
      \"decision\": \"allow\",
      \"precedence\": 1,
      \"include\": [{\"email_domain\": {\"domain\": \"$EMAIL_DOMAIN\"}}],
      \"require\": [],
      \"exclude\": []
    }" | cf_ok)
    [[ "$POLICY" == "ok" ]] && success "Access policy created" || warn "Policy: $POLICY"
  fi
fi

# ── Step 7: Gateway DNS logging policy ───────────────────────────────────────
step "Step 7/7 — Creating Gateway DNS logging policy"

GW_RESULT=$(cf_api POST "/accounts/$CLOUDFLARE_ACCOUNT_ID/gateway/rules" \
  --data @"$SCRIPT_DIR/gateway/dns-policy.json" | python3 -c "
import sys,json; d=json.load(sys.stdin)
if d['success']: print('ok:' + d['result']['id'])
elif any('already' in str(e).lower() for e in d.get('errors',[])): print('ok:exists')
else: print('err:' + str(d['errors']))
")

[[ "$GW_RESULT" == ok* ]] && success "Gateway DNS policy active" || warn "Gateway DNS: $GW_RESULT"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}${BOLD}  Setup complete!${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo "  Workers live at:"
echo "    Shop:   https://shop.$CLOUDFLARE_DOMAIN"
echo "    Portal: https://portal.$CLOUDFLARE_DOMAIN"
echo "    API:    https://api.$CLOUDFLARE_DOMAIN/api/v1/health"
echo ""
echo "  ⚠  Manual steps still required (dashboard only):"
echo "    1. Logpush — Zone:    HTTP requests, Firewall events, DNS logs"
echo "    2. Logpush — Zero Trust: Access requests, Gateway DNS,"
echo "                             Audit logs v2, Gateway HTTP"
echo "    3. Wrangler secrets for portal + api credentials:"
echo "       wrangler secret put PORTAL_USERNAME --name novamind-portal"
echo "       wrangler secret put PORTAL_PASSWORD --name novamind-portal"
echo "       wrangler secret put API_USERNAME    --name novamind-api"
echo "       wrangler secret put API_PASSWORD    --name novamind-api"
echo ""
