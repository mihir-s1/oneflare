# AcmeCorp — Cloudflare Infrastructure Plan

## Overview

Three linked Cloudflare Workers sites forming a mock company. All use the same zone.

```
YOUR_DOMAIN (your Cloudflare zone)
├── shop.YOUR_DOMAIN    → Workers: webstore
├── portal.YOUR_DOMAIN  → Workers: employee portal (behind Access)
└── api.YOUR_DOMAIN     → Workers: REST API gateway
```

## Setup Checklist

### Phase 1 — CLI / Wrangler (you run these)
- [ ] `npm install -g wrangler` — install Wrangler CLI
- [ ] `wrangler login` — authenticate to your account
- [ ] Deploy `workers/shop` → `wrangler deploy` from `workers/shop/`
- [ ] Deploy `workers/portal` → `wrangler deploy` from `workers/portal/`
- [ ] Deploy `workers/api` → `wrangler deploy` from `workers/api/`

### Phase 2 — DNS Records (CLI)
```bash
# Create subdomain DNS records pointing to Workers
wrangler dns create shop.acmecorp.dev CNAME shop.acmecorp.dev.workers.dev
# (or set via CF API — scripts in attack-scripts/setup/)
```

### Phase 3 — WAF Rules (CLI / API)
Create the following custom firewall rules on the zone:
1. `Block known bad bots` — cf.client.bot_score < 10 → block
2. `Log all /export requests` — http.request.uri.path contains "/export" → log
3. `Rate limit /search` — 20 req/10s per IP → challenge

### Phase 4 — Cloudflare Access (Console)
Portal requires console setup:
1. Go to Zero Trust → Access → Applications
2. Create application: `portal.acmecorp.dev`
3. Policy: Allow `@acmecorp.com` email domain
4. Enable Access audit logging

### Phase 5 — Gateway DNS Policy (Console)
1. Zero Trust → Gateway → DNS Policies
2. Create policy: Block category "Command and Control"
3. Create policy: Log all DNS queries (for detection data)

### Phase 6 — Logpush Verification
Confirm these datasets are flowing to SentinelOne:
- `http_requests` — WAF + HTTP logs
- `firewall_events` — WAF rule matches
- `access_requests` — Access auth events
- `gateway_dns` — Gateway DNS queries
- `workers_trace_events` — Workers invocations (optional)

## Wrangler Config Per Worker

### shop (webstore)
```toml
# workers/shop/wrangler.toml
name = "acmecorp-shop"
main = "src/index.js"
compatibility_date = "2024-01-01"
routes = [{ pattern = "shop.acmecorp.dev/*", zone_name = "acmecorp.dev" }]
```

### portal (employee portal)
```toml
# workers/portal/wrangler.toml
name = "acmecorp-portal"
main = "src/index.js"
compatibility_date = "2024-01-01"
routes = [{ pattern = "portal.acmecorp.dev/*", zone_name = "acmecorp.dev" }]
```

### api (REST API)
```toml
# workers/api/wrangler.toml
name = "acmecorp-api"
main = "src/index.js"
compatibility_date = "2024-01-01"
routes = [{ pattern = "api.acmecorp.dev/*", zone_name = "acmecorp.dev" }]
```

## Required Environment Variables
```bash
export CLOUDFLARE_API_TOKEN=<your-token>
export CLOUDFLARE_ZONE_ID=<your-zone-id>
export CLOUDFLARE_ACCOUNT_ID=<your-account-id>
```
