<div align="center">

<img src="docs/assets/logo.png" alt="OneFlare" width="150" />

# OneFlare

**Cloudflare + SentinelOne detection-engineering lab, for partners**

[![Cloudflare](https://img.shields.io/badge/Cloudflare-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://cloudflare.com)
[![SentinelOne](https://img.shields.io/badge/SentinelOne-A855F7?style=for-the-badge&logo=sentinelone&logoColor=white)](https://sentinelone.com)
[![Docker](https://img.shields.io/badge/Docker-2D1B4E?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)

</div>

---

## What this is

OneFlare is a mock company ("NovaMind") wired end-to-end for detection engineering:

```
Attack scripts (console UI)
        │
Cloudflare — WAF · Bot/AI Security · Gateway (DNS) · Access · Workers
        │
Logpush → SentinelOne SDL
        │
OCSF parser → STAR / scheduled detections → Hyperautomation response
```

Eight core scenarios, run from a web console with live streaming output:

| Scenario | Cloudflare surface | What it hits |
|---|---|---|
| SQL injection | WAF | `shop` search endpoint, 23 payloads |
| XSS | WAF | `shop` search (reflected) + review form (stored) |
| Path traversal / LFI | WAF | `shop` asset/docs routes |
| Credential stuffing | Access / ZTNA | `portal` login (many users, brute force, impossible travel) |
| Data exfiltration | Workers | `api` bulk export / endpoint enumeration |
| Polymorphic bot / scraper | Bot Management | `api` scraping with low bot scores |
| Prompt injection / LLM jailbreak | AI Security | `api` mock chat endpoint |
| DNS tunneling / C2 beaconing | Gateway | DoH queries, algorithmic subdomains |

There are also four longer, multi-stage "campaign" scenarios (financial fraud,
healthcare breach, SaaS tenant escape, and a public CTF) layered on the same
infrastructure.

---

## Pick your path

You can run this lab two ways. Both get you to the same place — attacks landing
as SentinelOne detections with automated response — but they trade off setup
effort against isolation and control.

| | **Option A — Shared lab** | **Option B — Your own environment** |
|---|---|---|
| Cloudflare you bring | None — we host it | Your own account + zone |
| SentinelOne you bring | Your own tenant + HEC token | Your own tenant + HEC token |
| Setup effort | Minutes (request access, register, deploy detections) | Longer (clone, configure, provision, wire logs) |
| Isolation | Your traffic is routed to your S1 only, via a fan-out relay | Fully yours — nothing shared |
| Best for | Fast demos, trying the lab, no Cloudflare account needed | Persistent lab, custom targets, full control |

**Not sure?** Start with **Option A**. Switch to Option B later if you want your
own Cloudflare zone or need to point the attacks at a custom application.

---

## Option A — Shared lab (fastest)

Use the console we already host at **https://one-flare.com** and our shared
Cloudflare zone (`soledrop.co`). You bring only a SentinelOne tenant.

1. **Request access.** Open https://one-flare.com. The site sits behind a
   Cloudflare Access email-OTP gate — `@sentinelone.com` addresses are
   auto-allowed; external guests are allow-listed by the operator on request.
   Once past Access, if you don't have a console account yet, use **Request
   account** (account menu, or on the `/admin` login page) — enter your name
   and email, and an admin reviews and emails you an invite link to set a
   password. (Ask your SentinelOne contact if the guest allow-list step is
   needed for your email domain.)

2. **Log in, then register your lab identity.** Settings → **Lab Identity**:
   pick a name (becomes `<name>.lab.soledrop.co`), your SentinelOne region,
   an **S1 HEC write token** (console → Settings → AI-SIEM → API Keys → new
   Write key), and the **S1 Site** + **S1 Account** labels your telemetry
   should land in. Submitting enrolls you with the shared relay — from then on,
   scenarios you run target *your* subdomain, and a fan-out relay Worker
   routes only *your* traffic's Cloudflare logs to *your* SentinelOne HEC.
   Nobody else sees your data, and you don't see theirs.

3. **Run scenarios.** Scenarios page → pick one → **Run**. Watch the live
   output stream.

4. **Deploy the detections to your own SentinelOne.** Settings → **Add
   detections, workflows, and dashboards to console** ("Deploy to console"
   wizard). You need an S1 **service-user token** (console → Settings → Users
   → Service Users) with:
   - **STAR Custom Rules** — deploy detections
   - **Hyperautomation** — import & activate response workflows
   - **SDL Dashboards** + **SDL Configuration Files** — deploy dashboards (optional)

   One token covers all three. The wizard walks Configure → Validate → Select
   → Deploy, and shows per-object deployed/skipped/failed status.

5. **Confirm.** Run a scenario, then check your SentinelOne SDL for the
   matching alert. If rules enable but nothing fires, your SDL is likely
   missing the Cloudflare→OCSF parser — often already present if you onboarded
   Cloudflare via the SentinelOne Marketplace; otherwise install
   `parsers/cloudflare-ocsf-parser/` (see the parser note in Option B).

**Want to inspect the shared Cloudflare config** (WAF rules, Logpush jobs)
instead of just running attacks against it? That's read-only admin access to
our shared tenant — ask your SentinelOne contact to grant it; it isn't
self-service.

> **Known lab-fidelity limits on the shared path:** all partners' attack
> traffic originates from the same runtime, so Cloudflare sees one real
> source IP/TLS fingerprint. Credential-stuffing scenarios will show up as
> "many attempts from one IP" rather than genuinely distributed sources, and
> bot/JA4 signal doesn't vary the way it would across real distinct clients.
> DNS tunneling logs are pushed at the Cloudflare **account** level and are
> not currently routed through the relay to individual partner consoles
> (labeled as such in the product). Detection-fire correctness for all other
> scenarios is unaffected.

---

## Option B — Your own environment

Stand the whole thing up on your own Cloudflare account and your own
SentinelOne tenant.

### Prerequisites

| Need | Notes |
|---|---|
| Cloudflare account with a zone (domain) | Core WAF/Gateway/Access scenarios work on lower tiers; Bot Management/JA4 needs the enterprise add-on |
| SentinelOne console + SDL | Console URL, a service-user API token, and an HEC ingest URL + token |
| Docker + Docker Compose | to run the console locally |
| Node 18+ and Wrangler v4 (`npm i -g wrangler`) | to deploy the Workers / console |
| `python3`, `curl` | used by `cloudflare/setup.sh` |

### 1. Configure `.env.local`

```bash
git clone <this-repo-url>
cd oneflare
cp .env.example .env.local      # then edit — every var is commented
```

At minimum set `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`,
`CLOUDFLARE_ZONE_ID`, `CLOUDFLARE_DOMAIN`. See `.env.example` for the full
list (Gateway DoH URL, Access email domain, S1 credentials, worker secrets).

**API token scopes** (dash.cloudflare.com → My Profile → API Tokens → Create
Custom Token):

| Resource | Permission |
|---|---|
| Account · Workers Scripts | Edit |
| Account · Workers KV Storage | Edit |
| Account · Account Rulesets | Edit |
| Account · Access: Apps and Policies | Edit |
| Account · Zero Trust | Edit |
| Account · Logs | Edit |
| Zone · Zone / Zone Settings / DNS / WAF / Workers Routes / Logs | Read / Edit |

### 2. Provision Cloudflare

```bash
source .env.local
bash cloudflare/setup.sh
```

This automates, against **your own** zone:

- patches `workers/{shop,portal,api}/wrangler.toml` with your domain
- creates (or finds) the `INCIDENT_KV` namespace and injects its id into all
  three `wrangler.toml` files
- deploys `novamind-{shop,portal,api}` Workers and enables their
  `workers.dev` routes
- binds custom domains `shop|portal|api.<your-domain>`
- creates the WAF firewall rules in `cloudflare/waf/rules.json`
- creates the Cloudflare Access app + "Allow Employees" policy for
  `portal.<your-domain>` (email domain from `ACCESS_EMAIL_DOMAIN`, defaults
  to `novamind.ai`)
- creates the Gateway DNS logging policy from `cloudflare/gateway/dns-policy.json`

It **prints the remaining manual steps** at the end:

1. **Worker secrets** (optional — lab defaults exist):
   ```bash
   wrangler secret put PORTAL_USERNAME --name novamind-portal
   wrangler secret put PORTAL_PASSWORD --name novamind-portal
   wrangler secret put API_USERNAME    --name novamind-api
   wrangler secret put API_PASSWORD    --name novamind-api
   ```
2. **Logpush → SentinelOne** — see step 4 below.

### 3. Run the console

```bash
cd lab-ui/frontend && npm install && npm run build && cd ..
docker compose up --build          # → http://localhost:3000
```

Running the console locally with no `ADMIN_TOKEN` set puts it in
**single-tenant mode** — Cloudflare Configuration overrides in Settings
directly retarget the attacks (no multi-tenant relay involved).

In the console, **Settings → Cloudflare Configuration**: set your CF API
token, Account ID, Zone ID, and Domain. Shop/Portal/API URLs default to
`shop|portal|api.<domain>`; only override them if you're targeting a
different host than your own `novamind-*` Workers (e.g. a custom app —
Cloudflare verifies server-side that the host is in a zone your token
actually controls before letting a run target it).

If you point at a **custom app** instead of deploying the lab's Workers, it
must expose the endpoints the attacks hit:

| Target | Endpoints |
|---|---|
| Shop | `GET /search?q=`, `GET /products/<id>`, `POST /reviews`, `POST /login` |
| Portal | `POST /login` (401/403 on bad creds) |
| API | `POST /api/v1/auth/login`, `GET /api/v1/customers/export`, `GET /api/v1/orders`, `GET /api/v1/models`, `GET /api/v1/admin`, `POST /api/v1/chat` |

Easiest path: just deploy the lab's own Workers via `setup.sh` and skip this.

### 4. Wire Cloudflare → SentinelOne

**Configure Logpush** (Settings → Configure Logpush) is the fastest way:
enter your S1 HEC ingest URL + token, click **Configure Logpush** — it uses
the CF API token + Zone ID from Cloudflare Configuration above (needs
`Logpush:Edit`) to create two Logpush jobs — HTTP requests and firewall
events — pointed at your S1 HEC. This is new; it surfaces Cloudflare's raw
response on success/failure, so validate against your real S1 HEC ingest
after running it.

For full parity with the reference deployment (all datasets, not just the
two Configure Logpush creates), set up Logpush jobs manually in
dash.cloudflare.com → your zone → Analytics → Logpush (and
one.dash.cloudflare.com → Logs → Logpush for Zero Trust datasets):

| Dataset | Level | Scenarios |
|---|---|---|
| HTTP requests | Zone | exfil, login attacks, bot, prompt-injection, all web traffic |
| Firewall events | Zone | WAF blocks — SQLi / XSS / traversal |
| Gateway DNS | Zero Trust | DNS tunneling / C2 |
| Access requests, Audit logs v2, Gateway HTTP | Zero Trust | cred attacks, config-change, ZT-layer exfil |

For **HTTP requests**, include the ML/score fields the detections use:
`WAFAttackScore`, `WAFSQLiAttackScore`, `WAFXSSAttackScore`,
`WAFRCEAttackScore`, `FirewallForAIInjectionScore`, and — if you have the
enterprise **Bot Management** add-on — `BotScore`, `JA4`, `BotTags`.

### 5. Deploy the OCSF parser + detections

> **Your SDL needs the Cloudflare→OCSF parser.** Cloudflare logs only normalize
> into the queryable OCSF fields the detections use once this parser is present.
> If you onboarded Cloudflare through the SentinelOne **Marketplace**, it's
> typically already installed; otherwise deploy `parsers/cloudflare-ocsf-parser/`
> via the S1 parser pipeline before running detections. The in-app "Deploy to
> console" wizard pushes detections, Hyperautomation workflows, and dashboards —
> it does **not** push the parser. If a rule enables but never alerts, check this first.

With the parser in place, use the same **Deploy to console** wizard described
in Option A step 4 to push detections/HA/dashboards to your S1 (needs a
service-user token with STAR Custom Rules, Hyperautomation, and optionally
SDL Dashboards + SDL Configuration Files).

### 6. Run scenarios & confirm

Open the console → pick a scenario → **Run**. Confirm the data landed in your
SDL (PowerQuery over `class_uid` 4002/4003, `dataSource.name='Cloudflare'`).

---

## Getting help / next steps

- **Docs map:** [`docs/story-map.md`](docs/story-map.md) (attack → detection →
  response narrative), [`ARCHITECTURE.md`](ARCHITECTURE.md) (layer/worker/OCSF
  reference), [`docs/multi-tenant-relay.md`](docs/multi-tenant-relay.md) (how
  the shared-lab isolation works), [`docs/infrastructure.md`](docs/infrastructure.md)
  (Cloudflare infra checklist).
- **Repo layout:** `cloudflare/` (setup script, Workers, WAF, Gateway, relay),
  `attack-scripts/` (scenario scripts), `parsers/` (OCSF parser),
  `detections/`, `hyperautomation/`, `dashboards/` (deployable knowledge
  objects), `lab-ui/` (the console — `frontend/` React + `backend/` FastAPI).
- **Stuck?** Ask your SentinelOne contact — for Option A that's also who
  grants Cloudflare Access allow-listing and shared-tenant read-only access.

## Security notes

- Workers contain **intentional** vulnerabilities (reflected XSS, open export
  endpoint, mock chat) for WAF/detection testing. Deploy only to a lab/NFR
  account.
- No secrets are committed. `.env.local` is gitignored; the console never
  bakes tokens into code — they stay in your browser / backend env, or (for
  Lab Identity / Deploy-to-console) server-side behind your session.
- CORS is intentionally permissive on the API Worker for testing.
