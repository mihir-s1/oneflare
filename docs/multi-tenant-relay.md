# Multi-Tenant Logpush Relay

How OneFlare gives ~30 partners each their own SentinelOne console from a single
shared Cloudflare zone, without any partner seeing another partner's traffic.

Status: **deployed**. Relay Worker is live at
`https://oneflare-logpush-relay.acmecorp-lab.workers.dev` (also reachable via
`/ingest`, `/register`, `/admin/*`, `/health`). The SoleDrop shop worker fidelity
PR (`shop-soledrop-worker`) is merged and deployed, so scenarios run with
realistic responses on both the CTF host and every partner's lab subdomain.

---

## 1. The problem

Cloudflare **Logpush has no per-record routing**. A Logpush job is configured at
the **zone** level with exactly **one destination**. If you create N Logpush
jobs on the same zone (one per partner, each pointed at that partner's own
SentinelOne HEC endpoint), every one of those N jobs receives a **full copy of
every record on the zone** — not just the records for that partner's host.

Concretely: all ~30 partners each run their own dockerized OneFlare lab
instance, and all of those instances live on one shared zone, `soledrop.co`.
If we naively created 30 Logpush jobs (one per partner's SentinelOne HEC), each
partner's SentinelOne console would receive **all 30 partners' traffic**, not
just their own. Logpush's filter language can narrow a job to a *subset of
fields on a record* (e.g. "only where `ClientRequestHost` contains X"), but it
still fans that filtered stream out to that job's single destination — it
cannot say "send this record to destination A and that record to destination
B" within one job. Splitting per-partner filtered jobs would technically work,
but at partner-scale (adds/removes weekly) it means live Cloudflare API calls
(create/delete a Logpush job, provision DNS/routes) for every partner
enrollment and teardown — operationally heavy and easy to get wrong.

## 2. The design

Instead of N Logpush jobs, there is **one shared job per dataset**, filtered to
the lab's hostname pattern, pointed at a **relay Worker** that does the
per-record routing Logpush itself can't do.

- **One zone**: `soledrop.co`.
- **One subdomain per partner**: `<name>.lab.soledrop.co`, served by wildcard
  DNS (`*.lab.soledrop.co`) and a single wildcard Worker route
  (`*.lab.soledrop.co/*`) that both point at the same shared `shop-soledrop-worker`
  (the same worker that also serves the public CTF at `shop.soledrop.co`).
  Adding a partner requires **zero new Cloudflare config** — the wildcard
  already covers any slug.
- **Two shared Logpush jobs**, both filtered to `ClientRequestHost contains
  ".lab.soledrop.co"`: one for dataset `http_requests`, one for
  `firewall_events`. Both point at the relay Worker's `POST /ingest`.
- **The relay Worker** (`oneflare-logpush-relay`) receives every batch, reads
  the host each record actually belongs to (`ClientRequestHost` for
  `http_requests`, `ClientRequestHTTPHost` for `firewall_events`), looks that
  host up in a KV registry mapping subdomain → owning partner's SentinelOne
  HEC endpoint, and forwards **only that partner's records** on to **that
  partner's own** S1 HEC ingest URL, authenticated as
  `Authorization: Splunk <their token>`.

This gives **write-time isolation**: the fan-out happens once, inside the
relay, keyed on data already present in the record (the hostname), so each
partner's SentinelOne site only ever receives events whose `ClientRequestHost`
is *their* subdomain. No partner can see another partner's data, and
onboarding/offboarding a partner is a KV write, not a Cloudflare deploy.

### Data flow diagram

```
 partner's dockerized OneFlare instance
 (targets https://<slug>.lab.soledrop.co)
                 │
                 ▼
   Cloudflare edge — soledrop.co zone
   *.lab.soledrop.co  (wildcard DNS + wildcard Worker route)
                 │
                 ▼
        shop-soledrop-worker            ← same worker serves shop.soledrop.co (CTF)
   (WAF / Bot / AI Security scoring,
    request logged regardless of origin response)
                 │
                 ▼
   Logpush (2 shared jobs, filtered to
   ClientRequestHost contains ".lab.soledrop.co")
     • http_requests
     • firewall_events
                 │  gzip NDJSON POST
                 ▼
   ┌───────────────────────────────────────────┐
   │   relay Worker: oneflare-logpush-relay     │
   │   POST /ingest                             │
   │                                             │
   │   1. decompress + parse NDJSON             │
   │   2. group records by ClientRequestHost /  │
   │      ClientRequestHTTPHost                 │
   │   3. one KV lookup per DISTINCT host        │
   │        KV: REGISTRY  <host> -> tenant row  │
   │   4. drop unknown hosts / disabled tenants  │
   │   5. forward each tenant's records to       │
   │      THAT tenant's s1_hec_url only          │
   └───────────────────────────────────────────┘
        │ alice.lab.soledrop.co        │ bob.lab.soledrop.co
        ▼                              ▼
  Alice's SentinelOne HEC        Bob's SentinelOne HEC
  (Alice's console — only        (Bob's console — only
   Alice's traffic)               Bob's traffic)
```

`/ingest` acks Logpush with `200 OK` immediately; the KV lookups and outbound
HEC forwards run in the background (`ctx.waitUntil`) so the response path does
no per-record work.

## 3. The components

| Component | What it is | Notes |
|---|---|---|
| Wildcard DNS + route | `*.lab.soledrop.co` → `shop-soledrop-worker` | Shared, provisioned once; no per-partner Cloudflare config |
| Relay Worker | `oneflare-logpush-relay` (`cloudflare/workers/logpush-relay/src/index.js`) | Live at `oneflare-logpush-relay.acmecorp-lab.workers.dev` |
| Relay endpoints | `POST /ingest`, `POST /register`, `GET /admin/registry`, `GET /admin/history`, `POST /admin/user/:subdomain/{enable,disable}`, `DELETE /admin/user/:subdomain`, `GET /health` | `:subdomain` accepts bare slug or full host |
| KV registry | Binding `REGISTRY` | Tenant rows keyed by full host; reserved keys `__history__` (rolling audit log, capped at 200) and `__unknown__:<host>` (drop counters for unmatched hosts) |
| Logpush jobs | 2 shared jobs on `soledrop.co`: `http_requests` + `firewall_events` | Both filtered to `ClientRequestHost contains ".lab.soledrop.co"`, both pointed at the relay's `/ingest` |
| lab-ui Settings → Lab Identity | `lab-ui/frontend/src/pages/Settings.jsx` | Where a partner registers: name + S1 HEC URL/token + **required** `site_label` (S1 site) and `account_label` (S1 account) + optional `s1_console_url`. Calls backend `POST /api/lab/register` |
| lab-ui Admin page | `lab-ui/frontend/src/pages/Admin.jsx` | Tenant table (enable/disable/delete) + history log. Only renders admin data when the backend has `ADMIN_TOKEN` configured (console deployment only) |
| Backend relay client | `lab-ui/backend/lab_identity.py` | Persists this instance's identity, applies `SHOP_URL_OVERRIDE`/`PORTAL_URL_OVERRIDE`/`API_URL_OVERRIDE`, proxies admin calls |

**Secrets** (never logged, never shown in full in the UI):
- `LAB_ENROLL_CODE` — required on `POST /register` (header `X-Enroll-Code` or
  body `enroll_code`) to gate self-service enrollment.
- `ADMIN_TOKEN` — required on all `/admin/*` calls (`Authorization: Bearer
  <token>` or `X-Admin-Token`). Only set on the operator's own console
  deployment (one-flare.com); partner instances have no admin surface —
  `admin_enabled()` in `lab_identity.py` gates it on `ADMIN_TOKEN` presence.
- Each partner's `s1_hec_token` is stored in their KV registry row and is
  never persisted on their own lab-ui instance (`lab_identity.py` explicitly
  omits it from the local identity file — "the relay is the system of
  record"). `GET /admin/registry` redacts it to the last 4 characters.

## 4. The lifecycle

1. **Register** — partner opens their lab-ui console → Settings → Lab
   Identity → enters a name, their own SentinelOne HEC URL + token, and the
   **required** `site_label` (S1 site) + `account_label` (S1 account) that name
   the destination behind the opaque HEC token (plus an optional
   `s1_console_url` = the console/"purple" domain shown in the admin list) →
   frontend calls `POST /api/lab/register` on their backend, which calls
   `lab_identity.register()`, which POSTs to the relay's `/register` (gated by
   `LAB_ENROLL_CODE`). The relay rejects a registration missing either label
   with a 400 — the HEC token itself carries no account/site identity, so it
   must be captured here.
2. **Assign** — the relay slugifies the name, creates/updates the KV row keyed
   on `<slug>.lab.soledrop.co`, and returns that subdomain + `shop_url`. The
   backend applies it as `SHOP_URL_OVERRIDE`/`PORTAL_URL_OVERRIDE`/
   `API_URL_OVERRIDE` so every scenario (in-process campaign engine and
   subprocess scripts alike) now targets the partner's own subdomain, and
   persists the identity to a local JSON file so it survives container
   restarts.
3. **Run scenarios** — attack scripts hit `https://<slug>.lab.soledrop.co/...`.
   The shop worker scores/logs every request (WAF, Bot, AI Security) whether
   or not it serves that exact path with a realistic body.
4. **Flow to their console** — edge → shared filtered Logpush jobs → relay
   `/ingest` → KV lookup on the partner's host → forwarded only to their
   `s1_hec_url`.
5. **Teardown** — an admin (on the one-flare.com console, `ADMIN_TOKEN`
   present) hits Admin → deletes the tenant → `DELETE /admin/user/:subdomain`
   → the relay deletes the KV row. **No Cloudflare-side changes are made or
   needed** — DNS/route/zone config for `*.lab.soledrop.co` is wildcard and
   shared. After teardown, that host's traffic simply falls into the
   `__unknown__:<host>` drop bucket until the row is re-registered.
   Enable/disable (`POST /admin/user/:subdomain/{enable,disable}`) is the
   non-destructive version: disabled tenants' records are dropped at ingest
   without deleting their row or counters.

## 5. Isolation guarantees + what's NOT isolated

**Guaranteed:**
- One registered subdomain maps to exactly one KV row, which maps to exactly
  one `s1_hec_url` — a partner's console receives only records whose
  `ClientRequestHost`/`ClientRequestHTTPHost` is their own subdomain. No
  duplicate delivery, no cross-tenant leakage, verified end-to-end (forwarded
  counters increment correctly per tenant).
- The public CTF (`shop.soledrop.co`) and `one-flare.com` are **separate
  Logpush destinations on separate scopes** — the shared relay job is filtered
  to `.lab.soledrop.co` only, so CTF and one-flare.com traffic never reaches
  the relay or any partner's console. one-flare.com, if it wants its own
  scenario data, registers itself as a normal tenant (e.g. `oneflare-main`)
  like any partner would.

**NOT isolated — the one exception:**
- **Scenario 05 (DNS tunneling / C2 beaconing)** goes through Cloudflare
  **Gateway DoH**, and Gateway DNS logs are pushed at the **account level**,
  not per-hostname. There is no per-tenant Gateway Logpush filter available,
  so this scenario's logs land in the account's shared Gateway Logpush job and
  are **not routed through the relay to any individual partner's console**.
  This is labeled in-product as "shared / account-level — not routed to your
  console" rather than silently dropped or misrouted.

## 6. Known limitations

- **Single source host for all partners.** Every partner's dockerized
  instance (and the shared attack tooling in general) makes its outbound
  requests from wherever that container is actually running. Cloudflare logs
  the **real** connecting `ClientIP` — it does not trust or log a
  script-supplied `X-Forwarded-For` header. Practically this means:
  - **Credential stuffing** scenarios, which are designed to simulate many
    distinct source IPs, will show up in Cloudflare/SentinelOne logs as a
    **single source IP** — i.e. detections/analysts will see a "brute force
    from one IP" pattern rather than genuine distributed credential stuffing,
    because the real client IP for every request is the same host.
  - **Bot/JA4 signal** (scenario 07) is derived from the real client's TLS
    handshake fingerprint. Since all requests originate from the same
    container/runtime, the JA4 fingerprint is that runtime's fingerprint —
    it does not vary the way it would across genuinely distinct real-world
    clients.
- **TLS-inspecting proxies compound this.** If the traffic additionally
  transits a TLS-inspecting corporate proxy (e.g. Zscaler), the proxy
  terminates and re-originates the TLS handshake, so Cloudflare sees the
  proxy's fingerprint/IP instead of the true origin's — further flattening
  whatever IP/JA4 variance might otherwise exist, on top of the single-host
  limitation above.

These are lab-fidelity caveats to set expectations for, not relay bugs — the
relay's isolation guarantees (section 5) hold regardless; what's limited is
the *realism* of certain attack signals given a single source host.

## Reference

- Relay source + full endpoint/README: `cloudflare/workers/logpush-relay/`
- Backend relay client: `lab-ui/backend/lab_identity.py`
- Backend `/api/lab/*` and `/api/admin/*` routes: `lab-ui/backend/main.py`
- Frontend registration UI: `lab-ui/frontend/src/pages/Settings.jsx`
  ("Lab Identity" section)
- Frontend admin UI: `lab-ui/frontend/src/pages/Admin.jsx`
- Design/consolidation notes: `docs/scenario-consolidation-plan.md`
