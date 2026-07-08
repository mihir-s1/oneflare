# ThreatOps Merge — Execution Plan

Merge co-worker's cf-attack-sim-v2 (drip-flow + 4 campaigns) and novamind-cloudflare
(NovaMind AI app + Pyxis chat + incident/status) into OneFlare. Retire AcmeCorp ->
NovaMind/Pyxis. Keep our 6 scenarios working. Branch: threatops-merge.

Contract: tasks/threatops-merge-spec.md (every agent reads it first).

## Wave 0 — foundation (orchestrator) [DONE]
- [x] Analyze all 4 inputs (doc, 2 co-worker repos, our repo)
- [x] Decisions locked (NovaMind+Pyxis, include all campaigns, mock-real-ready chat, S1 author-only)
- [x] Feature branch threatops-merge
- [x] Build spec written

## Wave 1 — workers + attacks (parallel; separate dirs)
- [x] cloudflare-specialist: rebrand workers -> NovaMind; add Pyxis AI surface (/chat mock+real-ready,
      /models, /training-data, /users, /admin bait); incident /status page (KV); demo-ready visuals
      DONE: novamind-{shop,portal,api} workers complete. All routes validated (node --check passed).
- [ ] threat-simulation-engineer: port campaigns/ (engine+financial+healthcare+saas+ctf, importable
      with PHASES + drip metadata); repoint to OUR workers; rebrand config.py; incident webhook helper

## Wave 2 — backend + frontend (parallel; separate dirs)
- [ ] backend: drip-flow campaign engine (asyncio) + /api/campaign/* endpoints; keep /ws/run/{id} intact
- [ ] frontend: ThreatOps Campaigns console (/threatops) + 2-cluster nav separator; 4-box CTF grid;
      live countdown + talking points; poll /api/campaign/logs

## Wave 3 — S1 detection/response (parallel; separate dirs; author-only)
- [ ] s1-detection-engineer: detections/ for recon, bot/JA4, prompt-injection, breakout, exfil
- [ ] s1-hyperautomation-engineer: hyperautomation/ response playbooks for the above

## Wave 4 — integrate, test, validate (orchestrator + qa)
- [x] Rebrand sweep check — repo-wide acmecorp->NovaMind; 0 stray refs in active code
- [x] Frontend builds (vite, 1501 modules); backend imports; workers node --check (x3) + setup.sh
- [x] Existing 6 scenarios still run (regression) — IDs + SCENARIO_SCRIPTS intact
- [x] Incident contract fixed (key-in-body) + frontend<->backend route contract verified
- [x] CLAUDE.md / README / ARCHITECTURE / docs rebranded to NovaMind
- [ ] LIVE runtime e2e (drip flow hits deployed workers; incident page flips) — needs servers
      running + workers deployed (docker-compose up + wrangler dev / live CF). See deferred TODOs.

## Review (2026-06-30)
Merge complete and statically validated on branch threatops-merge. Summary:
- Workers (cloudflare/workers/{shop,portal,api}): rebranded NovaMind + Pyxis AI surface
  (/api/v1/chat mock+real-ready, /models, /training-data, /users, /admin bait, GET/POST /api/incident
  via KV), shop /chat + /status (4-phase breakout), portal /admin gate. All node --check pass.
- Attacks (attack-scripts/campaigns/): engine + financial/healthcare/saas/ctf drip campaigns
  (importable PHASES contract) + incident.py; our 6 scenarios kept, repointed to NovaMind.
- Backend (lab-ui/backend): asyncio drip-flow engine + /api/campaign/* endpoints; /ws/run/{id} kept.
- Frontend (lab-ui/frontend): /threatops console (4-box CTF grid, timeline, talking points, live
  countdown, polling) + two-cluster nav separator ("Lab Scenarios" | "ThreatOps").
- S1 (detections/ + hyperautomation/): 8 detection rules + 4 response playbooks (author-only).
- Branding: AcmeCorp retired repo-wide.
Not yet done: live runtime e2e + live deploys (deferred TODOs below; need creds).

## Deferred TODOs (do not lose)
- [ ] Wire Pyxis /api/v1/chat to a REAL LLM (Workers AI or Anthropic) behind env.PYXIS_LLM_*
      Code stub is in cloudflare/workers/api/src/index.js at the "TODO: Wire real LLM here" comment.
      Two paths to implement: (a) Workers AI binding env.AI + PYXIS_LLM_PROVIDER="workers-ai",
      (b) Anthropic Messages API via PYXIS_LLM_KEY + PYXIS_LLM_PROVIDER="anthropic".
- [ ] Replace placeholder_incident_kv_id in all 3 wrangler.toml with real KV namespace ID
      after running: wrangler kv:namespace create INCIDENT_KV
- [ ] Deploy + validate S1 detections/hyperautomation against a live tenant (needs creds/MCP)
- [ ] Deploy rebranded workers to live Cloudflare + reconfigure Logpush datasets for NovaMind
      (field contract unchanged: RayID, ClientIP, Action, RuleID, MatchedData still present)
- [ ] /status page INCIDENT_API_URL override: when shop/api are on different workers.dev subdomains,
      set window.INCIDENT_API_URL before the status page script runs (or use a custom domain).

## Review
(filled after each wave)

## Path A build — attack surface on one-flare.com (in progress 2026-07-07)

Goal: real WAF/Bot/AI detection data by hosting attacks under one-flare.com (Enterprise,
Bot Management provisioned) with HTTP requests + Firewall events Logpush → S1.

Verified: Bot Management ON (one-flare.com), AI Gateway available (0 gateways), Firewall-for-AI NOT deployed.
DNS tunneling scenario + campaigns: KEEP UNTOUCHED (per user).

- [x] Bind custom domains: shop/portal/api.one-flare.com -> acmecorp-shop/portal/api workers (proxied). Verified 200.
- [ ] BLOCKED: add S1_HEC_INGEST_URL + S1_HEC_INGEST_TOKEN to .env.local (not saved yet — file has 6 vars, no HEC)
- [ ] Create Logpush jobs on one-flare.com zone (HTTP requests + Firewall events) -> S1 HEC (replicate existing dest)
- [ ] Enable WAF managed rules (OWASP) on one-flare.com; flip bot_management ai_bots_protection
- [ ] Create AI Gateway; route Pyxis chat through it (locate real chat endpoint — api.one-flare.com/api/v1/chat = 404)
- [ ] New scenario scripts built: 07_ai_bot.py, 08_prompt_injection.py (committed c08b2a5) — repoint to *.one-flare.com
- [ ] Revise scenarios 01/02/06 target URLs -> *.one-flare.com; author + live-validate detections to 0 FP
- [ ] Deferred: deploy DNS-tunnel scheduled rule (blocked on tenant "Scheduled Detections" toggle)

Key facts: one-flare zone id e5ccbf98fa13d1ce5de36d999ddf6720; account b8e637d5097fff0c694c3290ba81563e;
S1 site OneFlare id 2433185103040607397. Only Gateway HTTP/DNS + ZT + Audit flow to S1 today.

## Config persistence + public partner repo (2026-07-08)

### Part A — non-sensitive config persists server-side [DONE + LIVE]
- [x] Backend `SERVER_CONFIG` (env-driven, baked fallback one-flare.com) + `GET /api/config`
      + `/ws/run` falls back to it. lab-ui/backend/main.py. Verified live:
      `curl https://one-flare.com/api/config` returns baked domain/urls/delay/jitter, no secrets.
- [x] Frontend fetches /api/config; isConfigured now true from server domain → a FRESH
      browser (no localStorage) can run scenarios. Settings shows a "pre-configured" banner.
      ScenarioDetail.jsx + Settings.jsx.
- [x] Fixed dead paths: config.py honors *_URL_OVERRIDE (+ novamind-* workers.dev names);
      utils.jitter() reads ATTACK_DELAY/ATTACK_JITTER (UI timing knobs now work).
- [x] DEPLOYED to one-flare (wrangler, container ccb916bc). GOTCHA: `set -a; source
      ../.env.local` does NOT export CLOUDFLARE_API_TOKEN (spaces around `=` in the file) →
      wrangler failed "non-interactive ... CLOUDFLARE_API_TOKEN". Fix: read creds via python
      command-substitution into env vars, then `npx wrangler@4.77.0 deploy`.

### Part B — public partner repo [PUBLISHED]
- [x] amin-hamidi-s1/oneflare is PUBLIC: https://github.com/amin-hamidi-s1/oneflare
      Built from a sanitized fresh-history snapshot (git archive HEAD minus internal paths →
      git init → single commit). 102 files. Verified: no account/zone IDs; only intentional
      forged-JWT attack payloads in campaigns/saas.py; internal paths excluded.
- [x] Excluded from public: reference/ (AGPL), .claude/, tasks/, .mcp.json, CLAUDE.md
      (also added to the public .gitignore to prevent future accidental commits).
- [x] Genericized: setup.sh Access email domain → ACCESS_EMAIL_DOMAIN; .env.example expanded
      (all vars, sensitive vs non-sensitive); README rewritten as 5-step self-setup guide
      (KV create + Logpush→S1 + OCSF parser steps added, docs map, clone URL); wrangler.jsonc
      route comment. Kept NovaMind branding; one-flare.com kept as reference-instance default.
- [ ] BLOCKED (needs user MFA): CI workflow .github/workflows/deploy.yml was DROPPED from the
      public repo — the amin-hamidi-s1 token lacks the `workflow` OAuth scope (push rejected).
      To restore CI: `gh auth refresh --user amin-hamidi-s1 --scopes workflow` (interactive/MFA),
      then re-add deploy.yml. Optional — partners use setup.sh + docker.

### Part C — deploy/update workflow [ESTABLISHED]
- Cloudflare Containers do NOT auto-pull from GitHub — backend is built by `wrangler deploy`
  from local source. Standing rule: every change → commit + (publish sanitized snapshot to
  public repo) + `wrangler deploy` to one-flare.
- REPO MODEL (user didn't answer the follow-up; chose recommended): public repo is the
  canonical shareable artifact; working dir stays private (aminhamidi-s1) WITH internal
  tooling and cannot push directly to public (would leak reference//.claude//tasks). Sync to
  public = re-run the sanitized snapshot export. OPEN: confirm whether to fully switch the
  primary dev remote or keep this private-dev + public-mirror split.

## Scenario repoint fixes (2026-07-08)
- [x] #1 Cred stuffing repointed to one-flare.com. Root cause: `.env.local` had
      `CLOUDFLARE_DOMAIN = us.sentinelone.cftenant.com` (that host has no shop/portal
      subdomains → DNS fail). The script already reads SHOP_URL/PORTAL_URL from config;
      config just derived them from the stale domain. Fixed .env.local → one-flare.com,
      and hardened `config.py` (`os.getenv(...) or "one-flare.com"`) + backend
      `main.py` (`config.get("domain") or "one-flare.com"`) to never collapse to
      "https://shop." on an empty domain. Cred now POSTs shop/portal.one-flare.com/login → 401.
      NOTE: the SHOP_URL_OVERRIDE/PORTAL_URL_OVERRIDE/API_URL_OVERRIDE env vars set by
      main.py are NOT read by config.py (dead plumbing, harmless) — domain drives all URLs.
      Advanced per-URL override fields in the Settings UI are therefore inert; leave blank.
- [x] #2 Data exfil auth 403 fixed. Root cause: `random_headers()` rotates in scanner
      UAs (sqlmap/Nikto/masscan) that the WAF managed ruleset 403s; when the Phase-1
      auth login drew one, the script got no token and aborted. Fixed: auth login now
      uses a clean browser UA (06_data_exfil.py). Verified end-to-end — AUTH OK, and
      Phase 3 bulk export now returns 85KB (csv) / 217KB (json) bodies → the exfil
      LARGE-RESPONSE detection branch fires (was maxed at 348 bytes / 401 before).
- [x] CONFIRMED IN S1 (LRQ, last-60m window, class_uid 4002):
      - Cred: /login → 89×401 + 17×403 (the failed-login signal is landing).
      - Exfil: api.one-flare.com /customers/export → 10 reqs (9×200 + 1×403).
      LRQ helper: scratchpad/run_lrq.py (body needs pq:{query,resultType:TABLE},
      queryPriority; NOT top-level query — that 400s "Invalid JSON").
- [ ] EXFIL DETECTION TUNING FINDING: `unmapped.EdgeResponseBytes` is the
      *compressed* edge transfer size, so the 217KB JSON export records as only
      ~50–85KB (max observed 85,458). The ">100KB EdgeResponseBytes" LARGE-RESPONSE
      branch will NOT fire on real data — rely on the `sensitive_hits ≥ 10` volume
      branch (one source made 10 /export hits) or lower the byte threshold to ~50KB.
      scenarios.js exfil validationNote (says "returned 401, max 348 bytes") is now
      STALE — update when re-validating the exfil detection.
- [x] Verified http_requests field paths (one-flare.com zone): host =
      `http_request.url.hostname`, path/query = `http_request.url.url_string`,
      status = `unmapped.EdgeResponseStatus` (string), bytes =
      `unmapped.EdgeResponseBytes` (string, compressed — cast with number()).
      `unmapped.ClientRequestHost` is NULL — use http_request.url.hostname.

## #3 + #4 (2026-07-08)
- [x] #3 Wired `bot` + `promptinj` into the backend runner. Added to
      SCENARIO_SCRIPTS in lab-ui/backend/main.py (bot→scenarios.07_ai_bot,
      promptinj→scenarios.08_prompt_injection) and to demo.py SCENARIOS (CLI "all").
      Both run cleanly via `python -m scenarios.0{7,8}_*` (the exact backend invocation)
      and generate edge traffic on api.one-flare.com: bot = 30 GETs (rotating UA,
      constant JA4) to /models,/training-data,/users,/admin bait paths; promptinj =
      16 POSTs to /api/v1/chat. NOTE: all return 404 — the acmecorp-api worker bound
      to api.one-flare.com lacks those bait routes AND /api/v1/chat (the latter is #6).
      404s still generate http_requests logs (the fallback volume/UA signal), so the
      data path is intact; bot DETECTION needs #4 (Bot Mgmt fields), promptinj needs #6.
      CONFIRMED IN S1 (LRQ, class_uid 4002): promptinj POST /api/v1/chat ×16;
      bot probe paths landed (/api/v1/models ×6, /admin ×5, ?include_weights ×4,
      /training-data ×2, /users ×2). Both scenarios' data reaches the SDL.
      NOTE: live site needs a backend redeploy to expose bot/promptinj (container
      still runs old main.py) — `cd lab-ui && set -a; source ../.env.local; set +a; npx wrangler@4.77.0 deploy`.
- [~] #4 Token permission RESOLVED (user added Zone·Logs·Edit — can now read/write
      Logpush job 1769149). BUT #4 is BLOCKED on a deeper ENTITLEMENT gap:
      **BotScore / JA3Hash / JA4 / JA4Signals / BotTags / BotDetectionIDs are NOT in
      the http_requests Logpush field catalog for this zone** (checked GET
      /zones/{zone}/logpush/datasets/http_requests/fields → 105 fields, none of them).
      The zone has **Super Bot Fight Mode** (bot_management config uses sbfm_* keys),
      NOT the enterprise **Bot Management add-on** that emits BotScore/JA to Logpush.
      You cannot add a field Cloudflare doesn't offer for the dataset — no token/job
      edit fixes this. Polymorphic-bot detection (low BotScore + constant JA4 across
      rotating UAs) cannot be fed via Logpush until the add-on is provisioned.
      → USER ACTION (2026-07-08): asked Cloudflare team to provision enterprise Bot
        Management on one-flare.com so BotScore/JA3Hash/JA4/JA4Signals/BotTags/
        BotDetectionIDs appear in the catalog. Awaiting their update. Then: re-run the
        fields query; if present, PATCH job 1769149 output_options.field_names.
      → Only bot signal available today: VerifiedBotCategory (already on the job).
        Bot scenario's documented fallback = VerifiedBotCategory + UA rotation + volume.
      DECISION: leave the Logpush job UNTOUCHED for now (user will return with updates).
      AVAILABLE-BUT-NOT-ADDED (for later, serves promptinj/#6, not bot): AISecurity
      InjectionScore, AISecurityPIICategories, AISecurityTokenCount,
      AISecurityUnsafeTopicCategories (FirewallForAIInjectionScore already on job).

## Path A — DATA PATH COMPLETE (2026-07-07, later)
- [x] HEC creds validated (S1_HEC_INGEST_URL 57ch, S1_HEC_INGEST_TOKEN 65ch) — read via python-dotenv (bash `source` chokes on file; use dotenv).
- [x] Logpush jobs created on one-flare.com -> S1 HEC (reused validated dest, no re-ownership):
      firewall_events job 1769148, http_requests job 1769149 (98 fields incl BotScore/JA/WAFAttackScore). Both enabled, healthy.
- [x] WAF managed rules ACTIVE on one-flare.com (XSS/traversal/sqlmap -> 403 confirmed).
- [x] Seeded real attack traffic (SQLi/XSS/traversal at shop.one-flare.com, bot probes at api.one-flare.com).
- [ ] ai_bots_protection toggle blocked: token needs Bot Management **Edit** (has Read). Optional (scoring works regardless).
- [ ] NEXT: verify seeded data lands in S1 SDL (query dataSource with one-flare.com host; ~few min Logpush propagation).
- [ ] Author + live-validate detections (WAF attack score, polymorphic bot BotScore/JA4) to 0 FP.
- [ ] Repoint scenario scripts 01/02/06/07/08 to *.one-flare.com (config override).
- [ ] AI Gateway: create + route Pyxis chat (locate real chat endpoint).
