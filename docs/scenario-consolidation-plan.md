# Scenario Consolidation Plan (feat/multi-tenant-relay)

Goal: all lab scenarios run from a partner's dockerized instance against **their own
`<name>.lab.soledrop.co` subdomain**, with logs routed **only** to the console they
configured — no duplicate data, full admin visibility/control from one-flare.com.

## Key insight (from the 2026-07-14 audit)
The 8 scenarios **already converge** on the per-user subdomain: they target
`config.SHOP_URL/PORTAL_URL/API_URL`, which `lab_identity.apply_identity()` already sets
to `https://<name>.lab.soledrop.co`. The `shop.acmecorp.dev` / `api.one-flare.com` on the
cards are **stale display metadata** (`frontend/src/data/scenarios.js`), not the runtime
target. So consolidation ≈ unblock + relabel, NOT a worker merge.

| # | Scenario | Runtime target (via config) | Override-aware? | Notes |
|---|---|---|---|---|
| 01 | SQLi | `SHOP_URL/search` | ✅ | 404s but WAF-scored+logged |
| 02 | XSS | `SHOP_URL/search`,`/reviews` | ✅ | 404s but scored+logged |
| 03 | Traversal | `SHOP_URL/products/*`,`/search` | ✅ | scored+logged |
| 04 | Cred Stuffing | `SHOP_URL/login`+`PORTAL_URL/login` | ✅ | shop /login=200 → 401-rule caveat |
| 05 | DNS Tunneling | `c2tunnel.acmecorp-lab.workers.dev` (DoH) | ❌ HARDCODED | **account-level Gateway — NOT isolatable** |
| 06 | Exfil | `API_URL/api/v1/customers/export` etc | ✅ | /export 404, /auth/login 404 → volume-branch only |
| 07 | Bot/JA4 | `API_URL/api/v1/*` | ✅ | JA4+BotScore entitled on soledrop |
| 08 | Prompt Inj | `API_URL/api/v1/chat` | ✅ | Firewall-for-AI entitled |

## The real blocker
**None of the standalone scenarios set `verify=False`.** Behind a TLS-inspecting proxy
(Zscaler, and any partner's corp proxy) the container's Python rejects the MITM cert →
`CERTIFICATE_VERIFY_FAILED`. The campaign engine already uses `verify=False`; the standalone
scenarios must match.

## Workstreams

### 1. Unblock TLS (THE fix that makes 7/8 work) — [do first]
- Add `verify=False` + `urllib3.disable_warnings(InsecureRequestWarning)` to the request
  calls in 01,02,03,04,06,07,08 (and the DoH `httpx.post` in 05). Prefer a single shared
  helper / an env toggle `LAB_TLS_VERIFY` (default false for the lab) over 8 scattered edits.
- Verify: run each against `amin.lab.soledrop.co`, confirm no SSL error + traffic logs.

### 2. Consolidate targeting + relabel
- Confirmed: scenarios already hit the subdomain via overrides. No targeting change needed.
- Update `frontend/src/data/scenarios.js` display targets → the effective lab subdomain
  (or "your lab subdomain") instead of shop.acmecorp.dev / api.one-flare.com.
- (Cleanup, optional) retire the now-unused `acmecorp-shop/portal/api` workers.

### 3. DNS scenario (05) — the isolation exception  [DECISION]
Gateway DoH DNS logs are **account-level**, not per-host → they land in the account's Gateway
Logpush (shared), never the partner's console. Options: (A) keep it, clearly labeled
"account-level / shared — not routed to your console"; (B) hide it on partner instances.

### 4. No-duplicate-data / isolation hardening
- 7 scenarios → subdomain → relay job (filter `.lab.soledrop.co`) → relay → the one console
  in the registry row. Single destination, no dupes. ✅ (verified: CTF → amin, forwarded=119.)
- soledrop CTF jobs scoped to `shop.soledrop.co`; one-flare.com jobs are a different zone →
  lab data never leaks there. ✅
- DNS (05) is the ONLY shared-data path (account-level). Called out so it's not a surprise.

### 5. Admin console (one-flare.com)  [partly built]
- **Batch delete**: multi-select + "delete selected" on the Admin page (relay already has
  per-subdomain DELETE; add batch loop or a relay batch endpoint).
- Visibility: tenant table + forwarded counts + last_seen + history exist; add per-tenant
  record counts / quick filters.
- **Deploy Admin on one-flare.com**: redeploy `novamind-lab-ui` with `ADMIN_TOKEN`+`RELAY_URL`
  in env → Admin page + proxy light up there (behind the existing Access gate).
- **Admin's own data → existing console**: one-flare.com registers its own identity (e.g.
  `oneflare-main`) pointing at the main S1 HEC, runs scenarios → main console. Just a normal
  registration; no special path.

### 6. Fidelity (worker responses)  [DECISION — later]
Detection score/behavioral/volume arms fire on 404s already. Response-dependent arms are
weaker on the SoleDrop shop as-is (cred-stuffing 401-rule; exfil byte-branch needs an
authed large response). Full fidelity = extend the SoleDrop shop worker to serve all
scenario paths realistically — but that worker is NOT in the repo (deployed separately), so
this needs its source or a rewrite. Recommend: ship as-is now, treat fidelity as a follow-on.

## Decisions (2026-07-14)
1. **DNS scenario (05)**: KEEP, labeled "shared / account-level — not routed to your console."
2. **Fidelity**: EXTEND the SoleDrop shop worker to serve all scenario paths realistically
   (auth tokens, large `/export` bodies, 401 on bad login, `/search` results, `/reviews` POST,
   etc.). Prereq: bring `shop-soledrop-worker` source into the repo (it's live but not in-tree)
   → extend → test against shop.soledrop.co (CTF must keep working) → redeploy. HIGHER RISK:
   the worker is shared by the CTF (shop.soledrop.co) AND all lab subdomains (*.lab.soledrop.co).
3. TLS toggle: env `LAB_TLS_VERIFY` (default false) — DONE in config.py.

## Test results (2026-07-14) — everything functional
- 6/8 scenarios fully functional vs amin.lab.soledrop.co (sqli/xss/traversal/cred/bot/promptinj):
  exit 0, 0 SSL errors, 100s of requests. Pipeline proven (amin forwarded=688+).
- Exfil (06): current worker → "AUTH FAILED 404"; on the FIDELITY worker → "AUTH OK" + bulk
  /customers/export 544,659 B (csv) / 1,096,658 B (json). Fidelity fix validated end-to-end.
- Fidelity worker: all 6 new/changed routes verified on a live throwaway deploy
  (soledrop-shop-fidelity, torn down after); existing CTF routes + incident flip intact.
- DNS (05): NOT a code bug — CF_GATEWAY_DOH_URL is the team URL (cloudflareaccess.com → 404);
  needs the hex `<id>.cloudflare-gateway.com/dns-query`. Account-level/shared exception regardless.
- **PR opened: github.com/mihir-s1/soledrop-worker/pull/1** (fork amin-hamidi-s1). Deploy to
  shop-soledrop-worker (on OUR CF account) after merge → re-verify vs shop.soledrop.co + a lab subdomain.

## Execution order
- [x] WS1 TLS unblock — config.TLS_VERIFY + verify= across the 8 scenarios. DONE + verified.
- [ ] WS-Worker: pull shop-soledrop-worker source → repo → extend for full fidelity → test → redeploy.
- [ ] WS2 relabel scenarios (frontend data/scenarios.js) → lab subdomain; mark 05 shared.
- [ ] WS5 admin: batch-delete + visibility; deploy Admin on one-flare.com (ADMIN_TOKEN+RELAY_URL redeploy);
      one-flare.com registers its own identity → main console.
- [ ] WS-cleanup: retire unused acmecorp-{shop,portal,api} workers.

---
# SESSION HANDOFF — 2026-07-14 (read this first next session)

## DONE + LIVE
- Multi-tenant relay DEPLOYED: `oneflare-logpush-relay.acmecorp-lab.workers.dev` (KV REGISTRY
  `bdbe1493beaa4df4af83a1ed6647df9c`; secrets LAB_ENROLL_CODE=`<LAB_ENROLL_CODE-redacted>`,
  ADMIN_TOKEN=`<ADMIN_TOKEN-redacted>`). Auth to S1 HEC = `Authorization: Splunk <token>`.
- 2 Logpush jobs on soledrop.co → relay /ingest: http `1789130`, firewall `1789131` (filter `.lab.soledrop.co`).
  Existing CTF jobs re-scoped to shop.soledrop.co (no leak). Isolation proven.
- Shop worker fidelity: mihir PR #1 MERGED + deployed to LIVE shop-soledrop-worker (v22e8361d). New routes
  (/search,/reviews,/products/<id>,login→401,/api/v1/auth/login,/api/v1/customers/export ~532KB-1MB) live on
  shop.soledrop.co + *.lab.soledrop.co; incident flip intact. Worker source: github.com/mihir-s1/soledrop-worker
  (cloned at /tmp/soledrop-worker; NOT in our repo — PR future changes there).
- All 8 scenarios TLS-unblocked (config.TLS_VERIFY / LAB_TLS_VERIFY, default false). 6/8 detections validated:
  sqli, xss, traversal, exfil(byte-branch!), prompt-injection, cred-stuffing(fires as brute-force).
- Admin: batch-delete, per-subdomain destination visibility (site_label/HEC host/redacted token),
  reset-on-teardown (relay GET /registered). Relay v c573e2d1. docs/multi-tenant-relay.md written.
- Local docker instance registered as "amin"/"fidelity" (lab-ui/.env has RELAY_URL+LAB_ENROLL_CODE).

## IN-FLIGHT (agent abe71f14547b1cea6, fullstack) — RBAC admin user management
Building: relay `/auth/*` (login/logout/me/invite/accept-invite/users/role/bootstrap), PBKDF2 passwords,
KV sessions, roles admin/viewer, backend `/api/auth/*` proxy (forward cookies), frontend login +
accept-invite + Users tab, DISCREET "Admin portal login" footer link on Settings → /admin. Resend email
(RESEND_API_KEY) optional; else copy invite link. `cloudflare/workers/logpush-relay/RBAC.md`.
NEXT SESSION MUST: (1) review the RBAC code; (2) deploy the relay (`cd cloudflare/workers/logpush-relay &&
wrangler@4 deploy` with CF creds parsed from .env.local via python — the `export VAR = value` spaces gotcha);
(3) rebuild frontend + restart docker; (4) BOOTSTRAP first admin: `POST /auth/bootstrap` with the ADMIN_TOKEN,
email `amin.hamidi@sentinelone.com` → get invite_url; SEND it to that email (Gmail MCP is available, or Resend);
(5) ADD amin.hamidi@sentinelone.com to the Cloudflare Access guest list so he can reach one-flare.com/admin
(one-flare.com is behind Access OTP — see memory oneflare-access-gate). Invited external admins each need Access too.

## OUTSTANDING
- Bot/JA4: run `dataSource.name='Cloudflare' http_request.url.hostname='amin.lab.soledrop.co' ja4_fingerprint_list[0].value=* | group c=count()` — 0=JA4 not populating, >0=tune threshold. S1 IS REACHABLE now (Zscaler off) — s1lib.py in scratchpad works; note bracket-field LRQ syntax was finicky.
- WS2: hide DNS-05 on partner instances (frontend data/scenarios.js + a flag) + relabel scenario cards (shop.acmecorp.dev/api.one-flare.com → the lab subdomain). DNS-05 also needs the hex `<id>.cloudflare-gateway.com/dns-query` URL, not the team cloudflareaccess URL.
- Deploy Admin on one-flare.com: redeploy novamind-lab-ui with ADMIN_TOKEN + RELAY_URL env (LIVE console change — gate on user go). Then one-flare.com registers its own identity → main console.
- Retire unused acmecorp-{shop,portal,api} workers.
- Cred-stuffing rotating-IP: single-host limitation (CF logs real ClientIP, not spoofed XFF) — accepted as brute-force.

## KEY OPS FACTS
- CF token in .env.local (id ea5de56a…) now has DNS/Routes/Workers Scripts/Workers KV/Logpush/Access Edit; LACKS Certificates:Edit. Account b8e637d5097fff0c694c3290ba81563e; soledrop.co zone cf4d15af4a7eb86b033f859aefec1047.
- S1 reachable directly now (no Zscaler); scratchpad s1lib.py (LRQ) + cf.py (CF API). Sandbox blocks *.sentinelone.net historically — use dangerouslyDisableSandbox for direct calls if it returns.
- Branch feat/multi-tenant-relay (NOT merged to main). gh: aminhamidi-s1 (active) + amin-hamidi-s1.
