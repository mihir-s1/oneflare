<div align="center">

<img src="docs/assets/logo.png" alt="OneFlare" width="150" />

# OneFlare

**Cloudflare + SentinelOne detection lab**

Stand up a mock company across Cloudflare, generate realistic attack traffic from a web
console, and watch it flow end-to-end into SentinelOne detections and automated response.

[![Cloudflare](https://img.shields.io/badge/Cloudflare-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://cloudflare.com)
[![SentinelOne](https://img.shields.io/badge/SentinelOne-A855F7?style=for-the-badge&logo=sentinelone&logoColor=white)](https://sentinelone.com)
[![Docker](https://img.shields.io/badge/Docker-2D1B4E?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)

![WAF](https://img.shields.io/badge/WAF-F38020?style=flat-square)
![Access](https://img.shields.io/badge/Access-A855F7?style=flat-square)
![Gateway](https://img.shields.io/badge/Gateway-3B82F6?style=flat-square)
![Workers](https://img.shields.io/badge/Workers-EF4444?style=flat-square)
![OCSF](https://img.shields.io/badge/OCSF-1A0A2E?style=flat-square)
![Scenarios](https://img.shields.io/badge/scenarios-8-F38020?style=flat-square)

</div>

---

Built as a joint SentinelOne + Cloudflare demo you can replicate in **your own Cloudflare
NFR + your own SentinelOne console**.

```
Attack console (this repo)  ──▶  Cloudflare (WAF · Bot · Gateway · Access · Workers)
                                        │
                                   Logpush → SentinelOne SDL
                                        │
                                   OCSF parser → STAR / scheduled detections
                                        │
                                   Hyperautomation → Cloudflare response actions
```

> **Reference instance:** a live shared deployment runs at **https://one-flare.com**
> (maintained by the SentinelOne + Cloudflare teams). This repo is the template to run
> your **own**. The console is pre-configured per deployment, so anyone who opens it can
> launch scenarios with zero setup — no credentials are baked into the code.

---

## 📦 What gets deployed

Three linked Cloudflare Workers forming the mock company, plus the attack console:

| Component | URL | Attack surface |
|---|---|---|
| Shop | `shop.<your-domain>` | SQLi on `/search`, XSS on reviews, path traversal |
| Portal | `portal.<your-domain>` | Credential stuffing, brute force (Access-protected) |
| API | `api.<your-domain>` | Bulk data exfil, API enumeration, AI-bot scraping, prompt injection on `/api/v1/chat` |
| Console (this UI) | local `:3000` or your own Cloudflare domain | Runs the scenarios, streams output live |

Eight scenarios (`sqli`, `xss`, `traversal`, `cred`, `dns`, `exfil`, `bot`, `promptinj`)
— full narrative in [`docs/story-map.md`](docs/story-map.md).

---

## ✅ Prerequisites

| Need | Notes |
|---|---|
| Cloudflare account with a zone (domain) | Enterprise features (Bot Management, some WAF ML scores) require the matching entitlements; the core WAF/Gateway/Access scenarios work on lower tiers |
| SentinelOne console + SDL | Console URL, a service API token, and an HEC ingest URL + token |
| Docker + Docker Compose | to run the console locally |
| Node 18+ and Wrangler v4 (`npm i -g wrangler`) | to deploy the Workers / console |
| `python3`, `curl` | used by `cloudflare/setup.sh` |

---

## 🚀 Setup — five steps

### Step 1 — Configure `.env.local`
```bash
git clone https://github.com/amin-hamidi-s1/oneflare.git
cd oneflare
cp .env.example .env.local      # then edit it — see the grouped, commented vars
```
`.env.example` documents every variable (sensitive vs non-sensitive). At minimum set
`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_ZONE_ID`, `CLOUDFLARE_DOMAIN`.

**API token scopes** (dash.cloudflare.com → My Profile → API Tokens → Create Custom Token):

| Resource | Permission |
|---|---|
| Account · Workers Scripts | Edit |
| Account · Cloudflare Containers | Edit (only if deploying the console to Cloudflare) |
| Account · Account Rulesets | Edit |
| Account · Access: Apps and Policies | Edit |
| Account · Zero Trust | Edit |
| Account · Logs | Edit |
| Zone · Zone / Zone Settings / DNS / WAF / Workers Routes / Logs | Read / Edit |

### Step 2 — Provision Cloudflare (`cloudflare/setup.sh`)
```bash
bash cloudflare/setup.sh
```
Automates: claim a `workers.dev` subdomain → deploy `novamind-{shop,portal,api}` →
bind `shop|portal|api.<domain>` custom domains → create WAF rules
(`cloudflare/waf/rules.json`) → create the Access app + policy for the portal
(email domain via `ACCESS_EMAIL_DOMAIN`) → create the Gateway DNS logging policy.

**Manual steps the script does NOT do:**
1. **KV namespace** for the incident/status page:
   `wrangler kv namespace create INCIDENT_KV`, then paste the returned id into each
   `cloudflare/workers/*/wrangler.toml` (replace `placeholder_incident_kv_id`).
2. **Worker secrets** (optional; lab defaults exist):
   `wrangler secret put PORTAL_USERNAME --name novamind-portal` (and `PORTAL_PASSWORD`,
   `API_USERNAME`, `API_PASSWORD` on `novamind-api`).
3. **Logpush → SentinelOne** — see Step 3.

### Step 3 — Wire Cloudflare → SentinelOne
**a. Logpush jobs** (dash.cloudflare.com → your zone → Analytics → Logpush; and
one.dash.cloudflare.com → Logs → Logpush). Destination = **SentinelOne** (your HEC URL +
token):

| Dataset | Level | Scenarios |
|---|---|---|
| HTTP requests | Zone | exfil, login attacks, bot, prompt-injection, all web traffic |
| Firewall events | Zone | WAF blocks — SQLi / XSS / traversal |
| Gateway DNS | Zero Trust | DNS tunneling / C2 |
| Access requests, Audit logs v2, Gateway HTTP | Zero Trust | cred attacks, config-change, ZT-layer exfil |

For **HTTP requests**, include the ML/score fields the detections use:
`WAFAttackScore`, `WAFSQLiAttackScore`, `WAFXSSAttackScore`, `WAFRCEAttackScore`,
`FirewallForAIInjectionScore`, and — if you have the enterprise **Bot Management**
add-on — `BotScore`, `JA4`, `BotTags` (needed for the polymorphic-bot detection).

**b. OCSF parser** — deploy `parsers/cloudflare-ocsf-parser/` to your SDL so Cloudflare
logs normalize to OCSF (upload via the S1 parser pipeline / Marketplace).

**c. Detections / response (optional)** — `detections/`, `hyperautomation/`, and
`dashboards/` are JSON artifacts you import manually into SentinelOne; deployment calls
are documented in [`detections/README.md`](detections/README.md).

### Step 4 — Run the console
**Local (recommended for partners):**
```bash
cd lab-ui/frontend && npm install && npm run build && cd ..
docker compose up --build          # → http://localhost:3000
```
**Or deploy to your own Cloudflare** (edit the domain in `lab-ui/wrangler.jsonc` first):
```bash
cd lab-ui && npx wrangler deploy
```
Point the console at your NFR by setting `LAB_CF_DOMAIN` (+ optional `LAB_*`) in your
environment — the backend serves these from `GET /api/config` so every browser is
pre-configured. Sensitive tokens are entered per-browser in the Settings page and never
leave your backend.

### Step 5 — Run scenarios & confirm
Open the console → pick a scenario → **Run**. Watch live output, then confirm the data
landed in your SDL (PowerQuery over `class_uid` 4002/4003, `dataSource.name='Cloudflare'`).

---

## 🗺️ Docs map (for humans and AI agents)

| Path | What it covers |
|---|---|
| [`docs/story-map.md`](docs/story-map.md) | Every attack → detection → response scenario |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | 4-layer architecture, worker/route table, OCSF dataset→class map |
| [`docs/infrastructure.md`](docs/infrastructure.md) | Cloudflare infra plan / checklist |
| [`cloudflare/`](cloudflare/) | `setup.sh`, worker sources, `waf/rules.json`, `gateway/dns-policy.json` |
| [`attack-scripts/`](attack-scripts/) | Scenario scripts + `config.py` (targeting) + drip campaigns |
| [`parsers/`](parsers/) | Cloudflare→OCSF SDL parser |
| [`detections/`](detections/) | STAR / scheduled detection rules (+ deploy notes) |
| [`hyperautomation/`](hyperautomation/) | SOAR response workflow JSON |
| [`dashboards/`](dashboards/) | SDL dashboard definitions |
| [`lab-ui/`](lab-ui/) | The console: `frontend/` (Vite/React) + `backend/` (FastAPI) |

---

## 🧭 Repository structure
```
oneflare/
├── README.md · ARCHITECTURE.md · .env.example
├── cloudflare/       setup.sh · workers/{shop,portal,api} · waf · gateway
├── attack-scripts/   scenarios/*.py · campaigns/ · config.py · utils.py
├── lab-ui/           frontend/ (React) · backend/ (FastAPI) · wrangler.jsonc · docker-compose.yml
├── parsers/          cloudflare-ocsf-parser/
├── detections/       STAR + scheduled rule JSON
├── hyperautomation/  response workflow JSON
├── dashboards/       SDL dashboards
└── docs/             story-map · infrastructure · s1 action reference
```

## 🔒 Security notes
- Workers contain **intentional** vulnerabilities (reflected XSS, open export endpoint,
  mock chat) for WAF/detection testing. Deploy only to a lab/NFR account.
- No secrets are committed. `.env.local` is gitignored; the console never bakes tokens
  into code — they stay in your browser / backend env.
- CORS is intentionally permissive on the API Worker for testing.
