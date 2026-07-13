# OneFlare — Architecture Reference

## System Overview

OneFlare is a detection-engineering lab built around a mock company ("NovaMind") deployed on Cloudflare. It has three distinct layers: a simulated target infrastructure, a set of attack scripts, and a local control-plane UI that ties them together.

```
┌─────────────────────────────────────────┐
│           Lab UI (local)                │
│  React SPA  ←→  FastAPI backend         │
│  (Vite/Tailwind)   (WebSocket/HTTP)     │
└───────────────────┬─────────────────────┘
                    │ spawns
                    ▼
┌─────────────────────────────────────────┐
│         Attack Scripts (Python)         │
│  6 scenarios — requests, httpx, dnspy   │
└───────────────────┬─────────────────────┘
                    │ HTTP/DNS traffic
                    ▼
┌─────────────────────────────────────────┐
│          Cloudflare Edge                │
│  Workers · WAF · Access · Gateway DNS   │
└───────────────────┬─────────────────────┘
                    │ Logpush
                    ▼
┌─────────────────────────────────────────┐
│            SentinelOne                  │
│  OCSF Parser → STAR Detections          │
│  → Hyperautomation → CF response        │
└─────────────────────────────────────────┘
```

---

## Layer 1 — Lab UI (`lab-ui/`)

The control plane used to trigger attack scenarios and watch output in real time. Runs entirely locally via Docker Compose.

### Frontend

| Concern | Technology |
|---|---|
| Framework | React 18 |
| Build tool | Vite 5 |
| Styling | Tailwind CSS 3 |
| Routing | React Router v6 |
| Icons | Lucide React |
| Runtime | Served as a static build behind Nginx (Docker) |

**Pages:**
- `Dashboard` — scenario launcher with live terminal output
- `ScenarioDetail` — per-scenario documentation and controls
- `Architecture` — in-app architecture diagram
- `Detections` — STAR rule reference
- `History` — past run log
- `Settings` — URL overrides, API token, timing config
- `Parsers` — OCSF parser reference

The frontend communicates with the backend over:
- **REST** (`/api/health`, `/api/scenarios`, `/api/test-connection`)
- **WebSocket** (`/ws/run/{scenario_id}`) — streams live stdout from the attack script process

### Backend

> **Not Flask.** The backend is **FastAPI** running under **Uvicorn**.

| Concern | Technology |
|---|---|
| Framework | FastAPI 0.110 |
| Server | Uvicorn (ASGI, standard extras) |
| HTTP client | httpx 0.27 (HTTP/2 enabled) |
| Language | Python 3.11 |

**Key responsibilities:**
- Validates Cloudflare API tokens against `api.cloudflare.com/client/v4/user/tokens/verify`
- Launches attack scripts as subprocesses (`asyncio.create_subprocess_exec`) and streams their stdout line-by-line over a WebSocket connection to the frontend
- Passes runtime config (target URLs, delay, jitter, Gateway DoH endpoint) to scripts via environment variables

### Docker Compose

```
docker-compose.yml
  ├── frontend   — Vite build served by Nginx on :3000
  └── backend    — Uvicorn on :8000
                   volumes:
                     ../attack-scripts  (read-only mount)
                     attack_logs        (named volume — writable overlay)
```

The attack scripts directory is mounted read-only into the backend container; a named volume overlays the `logs/` subdirectory so scripts can write log files without hitting a read-only filesystem error.

---

## Layer 2 — Attack Scripts (`attack-scripts/`)

Six Python simulation scripts that generate realistic attack traffic against the Cloudflare Workers. They run as a Python module package (`python -m scenarios.01_sqli`, etc.) and are orchestrated by the lab UI backend or callable directly from a terminal.

| ID | Module | Scenario | Target |
|---|---|---|---|
| `sqli` | `scenarios/01_sqli.py` | SQL injection on `/search?q=` | `shop.*` |
| `xss` | `scenarios/02_xss.py` | XSS via product review form | `shop.*` |
| `traversal` | `scenarios/03_path_traversal.py` | Path traversal on asset routes | `shop.*` |
| `cred` | `scenarios/04_cred_stuffing.py` | Credential stuffing + brute force | `portal.*` |
| `dns` | `scenarios/05_dns_tunnel.py` | DNS tunneling / C2 beaconing | Cloudflare Gateway DoH |
| `exfil` | `scenarios/06_data_exfil.py` | Bulk data pull via `/export` | `api.*` |
| `all` | `demo.py` | Runs all six in sequence | all |

**Python dependencies:**

| Package | Purpose |
|---|---|
| `requests` | Synchronous HTTP for simple attack payloads |
| `httpx[http2]` | Async HTTP with HTTP/2 support (exfil scenario) |
| `dnspython[doh]` | DNS-over-HTTPS for Gateway DNS tunnel simulation |
| `rich` | Coloured terminal output / progress display |
| `python-dotenv` | `.env.local` loading for direct CLI execution |

**Runtime config** is injected via environment variables (set by the UI backend or manually sourced from `.env.local`):

| Variable | Effect |
|---|---|
| `CLOUDFLARE_DOMAIN` | Base domain — e.g. `novamind-lab.workers.dev` |
| `SHOP_URL_OVERRIDE` | Point `sqli`/`xss`/`traversal` at a custom URL |
| `PORTAL_URL_OVERRIDE` | Point `cred` at a custom URL |
| `API_URL_OVERRIDE` | Point `exfil` at a custom URL |
| `CF_GATEWAY_DOH_URL` | DoH endpoint for the DNS tunnel scenario |
| `ATTACK_DELAY` | Seconds between requests |
| `ATTACK_JITTER` | Random jitter added to each delay |

---

## Layer 3 — Cloudflare Infrastructure (`cloudflare/`)

Three Cloudflare Workers forming the mock "NovaMind" target. All deployed via the Wrangler CLI (`wrangler deploy`) and covered by a single setup script (`cloudflare/setup.sh`).

### Workers

| Worker name | Route | Purpose | Intentional vulnerabilities |
|---|---|---|---|
| `novamind-shop` | `shop.DOMAIN` | Public webstore | XSS via reflected `?q=` on `/search`; path traversal on `/products/` |
| `novamind-portal` | `portal.DOMAIN` | Employee portal (Access-protected) | Login endpoint generates Access audit logs — credential stuffing target |
| `novamind-api` | `api.DOMAIN` | REST API gateway | Open `/api/v1/customers/export` endpoint — data exfil target |

**Stack:** plain JavaScript (ES modules), no framework, deployed with Wrangler v4. Each Worker lives in `cloudflare/workers/<name>/src/index.js` with a `wrangler.toml` alongside it.

**Credentials** for the portal and API Workers are set as Wrangler secrets (not hardcoded) and fall back to lab defaults if unset.

### SoleDrop Shop — CTF target (`shop.soledrop.co`)

A **standalone** sneaker-drop shop Worker (its own `soledrop-worker` repo — *not* under `cloudflare/workers/`) is the live target for the **OneFlare CTF** (`campaigns/ctf.py`, hardcoded via `CAMPAIGNS['ctf']['target_url']`). Unlike the three workers above, it is **self-contained**: it owns its own `/api/incident` endpoint and its own `INCIDENT_KV` namespace — it does **not** share the api worker's KV.

- **Pages:** `/` (storefront), `/products`, `/status`, `/login`, `/dashboard`, `/admin` (Order Ops).
- **API:** `/api/v1/products|cart|checkout|customers|chat`, `/api/incident`.
- **Attack behavior:** when the CTF runs, the bot-swarm attack flips `shop.soledrop.co/status` into an incident and the shop **visibly degrades** — checkout returns `503`, the `/admin` Order Ops dashboard shows failed orders, and the storefront shows an incident banner. All of this is driven by the shared incident state, so it flips in lockstep with the attack.
- The CTF's incident flip targets this shop directly (`lab-ui/backend/campaign_engine.py::_signal_shop_incident`), independent of the NovaMind api worker's status page.

### WAF Rules (`cloudflare/waf/rules.json`)

Managed WAF rules and custom firewall rules covering:
- SQLi pattern matching on `/search`
- XSS signatures on review endpoints
- Path traversal patterns on asset routes
- High-volume export request rate limiting
- Login failure rate limiting (feeds impossible travel detection)

### Gateway DNS Policy (`cloudflare/gateway/dns-policy.json`)

A Zero Trust Gateway DNS logging policy that captures all DNS queries resolving through the Gateway location. This is the data source for the DNS tunneling detection scenario.

### CI/CD

GitHub Actions (`.github/workflows/deploy.yml`) deploys all three Workers on push to `main` using `wrangler-action@v3`. Required secrets: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`.

---

## Layer 4 — SentinelOne Integration

### Logpush → SentinelOne

Cloudflare Logpush is configured manually in the dashboards (cannot be automated via API). Datasets flowing to SentinelOne:

| Dashboard | Dataset | Scenarios |
|---|---|---|
| Zone | HTTP Requests | All web traffic, data exfil |
| Zone | Firewall Events | WAF blocks — SQLi, XSS, traversal |
| Zero Trust | Access Requests | Credential stuffing, impossible travel |
| Zero Trust | Gateway DNS | DNS tunneling, C2 beaconing |
| Zero Trust | Audit Logs v2 | Config change detection |
| Zero Trust | Gateway HTTP | Exfil through ZT layer |

### OCSF Parser (`parsers/cloudflare-ocsf-parser/`)

A SentinelOne Marketplace parser that normalises Cloudflare Logpush output to OCSF 1.6.0 before ingestion into Deep Visibility and AI SIEM.

Covers 15 Cloudflare datasets, mapping each to its OCSF class:

| Cloudflare dataset | OCSF class |
|---|---|
| HTTP Requests | HTTP Activity (4002) |
| Firewall Events | HTTP Activity (4002) |
| Gateway DNS / DNS Logs | DNS Activity (4003) |
| Access Requests | User Access Management (3005) |
| Audit Logs | Entity Management (3004) |
| Gateway Network / Zero Trust Network Sessions | Network Activity (4001) |
| Gateway HTTP | HTTP Activity (4002) |
| Network Analytics | Network Activity (4001) |
| SSH Logs | SSH Activity (4007) |
| Email Security Alerts | Email Activity (4009) |
| DLP Forensic Copies | Data Security Finding (2006) |
| CASB Findings | Data Security Finding (2006) |
| Device Posture Results | Application Security Posture Finding (2007) |
| Spectrum Events | Network Activity (4001) |

### STAR Detections (`detections/`)

SentinelOne STAR (Storyline Active Response) rules written against the OCSF-normalised fields. One rule per attack scenario, triggering on patterns generated by the attack scripts.

### Hyperautomation (`hyperautomation/`)

SentinelOne Hyperautomation workflows that fire on STAR detections and call back into Cloudflare to automate response: blocking IPs via WAF rules, sinkholing DNS domains, triggering zone lockdowns.

---

## Repository Layout

```
oneflare/
├── ARCHITECTURE.md            # This file
├── README.md                  # Setup and quick-start guide
├── .env.example               # Credential template
├── cloudflare/
│   ├── setup.sh               # One-shot setup script
│   ├── workers/
│   │   ├── shop/              # novamind-shop Worker (JS)
│   │   ├── portal/            # novamind-portal Worker (JS)
│   │   └── api/               # novamind-api Worker (JS)
│   ├── waf/
│   │   └── rules.json
│   └── gateway/
│       └── dns-policy.json
├── attack-scripts/
│   ├── config.py              # Shared config / env loading
│   ├── utils.py               # Shared HTTP helpers
│   ├── demo.py                # Runs all scenarios
│   └── scenarios/
│       ├── 01_sqli.py
│       ├── 02_xss.py
│       ├── 03_path_traversal.py
│       ├── 04_cred_stuffing.py
│       ├── 05_dns_tunnel.py
│       └── 06_data_exfil.py
├── lab-ui/
│   ├── docker-compose.yml
│   ├── backend/
│   │   ├── main.py            # FastAPI app (Uvicorn)
│   │   └── requirements.txt
│   └── frontend/
│       ├── package.json       # React 18 + Vite + Tailwind
│       ├── vite.config.js
│       └── src/
│           ├── App.jsx
│           ├── pages/
│           └── components/
├── parsers/
│   └── cloudflare-ocsf-parser/
│       └── metadata.yaml      # OCSF mapping manifest
├── detections/                # SentinelOne STAR rules
├── hyperautomation/           # Response workflow definitions
└── docs/
    ├── story-map.md
    ├── infrastructure.md
    └── s1-hyperautomation-actions.md
```
