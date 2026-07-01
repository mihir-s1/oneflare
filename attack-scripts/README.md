# OneFlare Attack Scripts

CLI reference for the NovaMind attack simulation suite.
All scripts target the OneFlare lab Workers only — **authorized lab use only**.

---

## Prerequisites

```bash
# From the attack-scripts/ directory
pip install -r requirements.txt

# Configure your lab domain in .env.local (project root)
cp ../.env.example ../.env.local
# Edit ../.env.local and set CLOUDFLARE_DOMAIN
```

---

## Master Runner (`demo.py`)

Runs all scenarios in sequence with narrated output and a final summary table.

```bash
# Run all 6 scenarios in sequence
python demo.py

# Run a single scenario by key
python demo.py --scenario sqli
python demo.py --scenario xss
python demo.py --scenario traversal
python demo.py --scenario cred
python demo.py --scenario dns
python demo.py --scenario exfil

# List available scenario keys
python demo.py --list

# Adjust delay between scenarios (default: 3s)
python demo.py --delay 5
```

---

## Individual Scenarios

### 01 — SQL Injection (`scenarios/01_sqli.py`)

Fires 23 SQLi payloads at the `/search` endpoint of the shop Worker.
Generates WAF block events (RuleID 100001, OWASP group).

```bash
python -m scenarios.01_sqli
```

**Expected output**: Mix of `403 Blocked` and `200 Passed` responses per payload.
**S1 Detection triggered**: `CF-WAF-SQLi-Burst` (threshold: 5 blocks in 60s from same IP)

---

### 02 — Cross-Site Scripting (`scenarios/02_xss.py`)

Sends 39 XSS payloads to `/search` (reflected) and `/reviews` (stored).
Generates WAF block events for script-injection attempts.

```bash
python -m scenarios.02_xss
```

**Expected output**: Blocked `<script>`, `javascript:`, and event-handler payloads.
**S1 Detection triggered**: `CF-WAF-XSS-Burst`

---

### 03 — Path Traversal / LFI (`scenarios/03_path_traversal.py`)

Attempts 20 path traversal and local file inclusion payloads via `/products/{path}` and `/search?file=`.

```bash
python -m scenarios.03_path_traversal
```

**Expected output**: `403` blocks on `../`, `/etc/passwd`, `/proc/self/environ` patterns.
**S1 Detection triggered**: `CF-WAF-PathTraversal`

---

### 04 — Credential Stuffing + Brute Force (`scenarios/04_cred_stuffing.py`)

Replays 40 username/password combos against `/login`, then brute-forces a single account with 20 passwords. Rotates through EU/US source IP headers.

```bash
python -m scenarios.04_cred_stuffing
```

**Expected output**: High-volume failed login events across multiple usernames.
**S1 Detection triggered**: `CF-Access-CredStuffing` (threshold: 20 distinct emails from same IP in 300s)

---

### 05 — DNS Tunneling / C2 Beaconing (`scenarios/05_dns_tunnel.py`)

Generates 30 DNS queries to algorithmically generated subdomains of `c2tunnel.novamind-lab.workers.dev`. Uses TXT record queries and base32-encoded subdomain labels to mimic dnscat2-style exfiltration.

```bash
python -m scenarios.05_dns_tunnel
```

**Expected output**: High-frequency TXT queries with long subdomain labels (>25 chars).
**S1 Detection triggered**: `CF-Gateway-DNSTunnel` (threshold: 10 queries to same root in 5 min)

---

### 06 — Data Exfiltration via API (`scenarios/06_data_exfil.py`)

Authenticates to the API Worker with valid credentials, then fires 10 rapid requests to `/api/v1/customers/export`, each returning 500KB+ payloads.

```bash
python -m scenarios.06_data_exfil
```

**Expected output**: Authenticated bulk export requests with large response bodies.
**S1 Detection triggered**: `CF-API-BulkExfil` (threshold: 10 requests >100KB to `/export` in 120s)

---

## Environment Variables

Set in `.env.local` at the project root:

| Variable | Default | Description |
|---|---|---|
| `CLOUDFLARE_DOMAIN` | `novamind-lab.workers.dev` | Your lab domain |
| `PORTAL_USERNAME` | `admin@novamind.ai` | Portal login username |
| `PORTAL_PASSWORD` | `AcmeAdmin2026!` | Portal login password |
| `API_USERNAME` | `api_user@novamind.ai` | API auth username |
| `API_PASSWORD` | `ApiUser2026!` | API auth password |

---

## Output & Logs

- All scenario results are logged as JSON to `attack-scripts/logs/`
- Each session creates a timestamped file: `logs/<scenario>_<timestamp>.json`
- Log fields: `timestamp`, `method`, `url`, `status`, `payload`, `notes`

---

## Scenario → Detection Matrix

| Key | Script | CF Product | S1 Detection Rule | Severity |
|---|---|---|---|---|
| `sqli` | `01_sqli.py` | WAF | `CF-WAF-SQLi-Burst` | High |
| `xss` | `02_xss.py` | WAF | `CF-WAF-XSS-Burst` | High |
| `traversal` | `03_path_traversal.py` | WAF | `CF-WAF-PathTraversal` | Medium |
| `cred` | `04_cred_stuffing.py` | Access | `CF-Access-CredStuffing` | Critical |
| `dns` | `05_dns_tunnel.py` | Gateway | `CF-Gateway-DNSTunnel` | High |
| `exfil` | `06_data_exfil.py` | Workers + WAF | `CF-API-BulkExfil` | Critical |
