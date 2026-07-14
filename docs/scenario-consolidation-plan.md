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
