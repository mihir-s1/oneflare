# Lessons

## 2026-07-20 — HA native actions: use the catalog's CANONICAL `data`, don't reconstruct it
**Context:** After setting `integration_id`, the nodes rendered native but FAILED at runtime
(400s). Root causes, all from reconstructing the action instead of copying the catalog's real
`data`:
- **`url` must keep the `<@/path@>` link form** where the catalog has it (Cloudflare
  `<@/client/v4/user/firewall/access_rules/rules@>`, AbuseIPDB `<@/api/v2/check@>`, Slack
  `<@/api/chat.postMessage@>`). Clones stripped it to a plain path → failure. NOT universal —
  the S1 `unifiedalerts/graphql` note/verdict actions use a PLAIN url and work; match whatever
  the catalog's `data.url` shows for that action id.
- **Params use `{parameter_name, parameter_value}`, NOT `{key, value}`.** Wrong shape = the
  param isn't sent → e.g. `"queryId: Missing data for required field"`.
- **Placeholder tokens** `<<ip>>`/`<<queryId>>` in the catalog `data` are inputs — replace with
  the workflow expression (`{{local_var.src_ip}}`, `{{create-power-query.body.data.queryId}}`).
- **S1 PowerQuery from HA:** the catalog `Create A Power Query` (`/dv/init-query`) does NOT work
  on this tenant. Working flow (verified live): POST `<@/web/api/v2.1/dv/events/pq@>` {query,
  fromDate, toDate} → returns `data.queryId` + `data.status` (RUNNING); then GET
  `<@/web/api/v2.1/dv/events/pq-ping@>?queryId=…` until `data.status=="FINISHED"`. Results are a
  **2D array** (`data.data` rows + `data.columns`) — you CANNOT reference a named field like
  `body.data[0].failed_logins`; index the array or don't reference it in messages.
- Make enrichment nodes `continue_on_fail:true` (best-effort; don't abort the response).
**Rule:** for every native node, copy the catalog action's `data` (`url`, `parameters`,
`payload`, `headers`) verbatim and only substitute the `<<…>>` inputs. See docs/s1-ha-integration-catalog.md. [[native-golden-playbooks]]

## 2026-07-20 — HA native action needs `integration_id` SET, not null (else renders as HTTP)
**Context:** The golden workflow imported but 6 nodes (Cloudflare block, S1 PowerQuery triad,
VirusTotal, AbuseIPDB) showed as plain **"Send HTTP Request"** on the canvas, not native
integrations — even though each had the correct `public_action_id`. Cause: they had
`integration_id: null`. The nodes that DID render native (Slack, S1 Add-Note) had a real
`integration_id`. My earlier catalog guidance ("leave integration_id null, the console resolves
it from connections") was WRONG.
**Rule:** a native integration action node needs BOTH `tag:"integration"`, the action's
`public_action_id`, AND the vendor's **`integration_id`** (from `docs/s1-ha-integration-catalog.md`
Connection matrix) populated. `public_action_id` alone is insufficient. `connection_id` MAY stay
null (node renders native, unbound; user binds after import). Fix: map each node's
`public_action_id` → its integration_id and set it. Corrected the catalog doc + applies to all 13
fan-out playbooks. [[ha-integration-action-catalog]]

## 2026-07-20 — HA workflow `notes` must be `[]` (or objects), never strings
**Context:** Importing the golden workflow failed with `Input should be a valid dictionary or
object to extract fields from at "body.data.notes.0" …notes.5`. The workflow-level `notes` array
was authored as 6 plain strings. The importer requires each `notes` entry to be an OBJECT
(canvas sticky-note), and the object shape is undocumented in the HA schema refs. The proven
reference (`Blocklist IP.json`) uses `notes: []`.
**Rule for every HA workflow we build:** set `"notes": []`. Put all per-step / setup narrative in
each node's `description` field (guaranteed-valid envelope key) — which is where it belongs
anyway (it shows on the node). Do NOT put human notes in the top-level `notes` array unless we
have a confirmed object shape from a real console export. Applies to all 13 fan-out playbooks.

## 2026-07-20 — PowerQuery has no `if()` — use the ternary `cond ? a : b`
**Context:** `box4-agentic-breakout` failed to launch with `400 invalid_argument "Unknown
function 'if'"`. It used `let is_rce = if(payload matches '…', 1, 0)`. PowerQuery has **no
`if(cond,a,b)` function** — the conditional is the ternary operator `cond ? a : b`. Fix:
`(payload matches '…' ? 1 : 0)`. Live-verified after fix (1 row, matchCount 42). Every other
rule in the repo already uses ternary. **When authoring any scheduled PQ that needs a
conditional/flag column, use `?:`, never `if(...)`,** and remember to fix BOTH the deployed
`scheduledParams.query` and the display/`powerquery` copy in the same file. Verify live before
calling a rule done — parse-time errors only surface on an actual LRQ launch.
**Tooling:** live read-only PQ verification runs via `scratchpad/lrq.py` (Bearer LRQ API,
`POST /sdl/v2/api/queries` + poll `stepsCompleted>=stepsTotal`), with Bash
`dangerouslyDisableSandbox:true` (sandbox blocks `*.sentinelone.net`). See [[ha-integration-action-catalog]].

## 2026-07-20 — Scheduled-rule `entityMappings`: activate to carry src_ip onto the alert
**Context:** Cloudflare alerts bind to "Unknown Device" and the alert JSON envelope does NOT
carry src_ip — the HA playbook had to re-run PowerQuery just to learn the attacker IP. Fix is
`data.entityMappings` on scheduled (PowerQuery) rules. Applied across all 9 scheduled rules
(converted the parked `_entityMappings_pending_feature` placeholders to the real field).
**The rules (apply to EVERY new scheduled detection going forward):**
- Shape is exactly `"entityMappings": [{"columnName": "<col>"}]` — NO `entityType`/identifier
  sub-field (that shape is invented and will fail). Cap **≤3 columns**.
- **Every projected `columnName` MUST be an output column of the query's `columns`/`group … by`
  stage.** Projecting a column the query doesn't emit binds nothing (silent). This is the #1 bug.
- Project `src_ip` (= `src_endpoint.ip`) FIRST — it's the attacker identity the response
  playbooks read. Add `host`/`country` only if the query actually emits them and they add pivot.
- **entityMappings binds the IP as an ENTITY only; the Target Asset still shows "Unknown Device"**
  until the asset-enrichment solution stamps `device.uid` + `class_uid` into the CF events.
  entityMappings and asset-enrichment are complementary, not either/or.
- Single-event/correlation rules do NOT use entityMappings (they auto-bind from the matched
  event). Only `queryType:"scheduled"` uses it.
**Also — a latent class of bug this surfaced:** the CTF rules aliased their group to `ja3`
(`by ja3=tls.ja3_hash.value`) after live-verifying JA4 isn't PQ-addressable, but left `ja4` in
both the `columns` clause and `entityMappings` — a half-done rename referencing a non-existent
column. When you rename a group alias, grep the WHOLE rule for the old token (columns,
entityMappings, prose) — the deployable fields (`scheduledParams.query`, `entityMappings`) are
what actually break.

## 2026-07-20 — HA actions: native-integration vs raw-HTTP is decided by `public_action_id`
**Context:** A built workflow had Slack + S1-addNote as proper native integration actions but
S1-PowerQuery-hydrate and Cloudflare-block as generic `http_request`. Why the split:
- What makes an action a **native integration action** (not raw HTTP): `tag:"integration"` +
  a **`public_action_id`** (UUID identifying the specific action in an installed integration's
  catalog) + a `url` using the `<@/path@>` action-reference token. On import `connection_id`/
  `integration_id` are often nulled and the console re-resolves them from the user's connections,
  but **`public_action_id` MUST be kept** — it's the catalog action identity.
- We could replicate Slack + S1-addNote natively ONLY because we had a real exported example
  (`Downloads/Blocklist IP.json`) with their real `public_action_id`s. Native action metadata
  lives ONLY in the tenant's HA console — the vendored catalog is generic.
- **S1 PowerQuery has NO native action** — catalog B8 "PowerQuery via DV API" IS a generic HTTP
  POST to `.../api/powerQuery`. So raw HTTP is CORRECT for hydration (bind it to an S1-SDL
  connection so token/URL come from the connection, not hardcoded). Don't "fix" it to native.
- **Cloudflare has NO integration in the vendored catalog** (0 mentions). If the tenant has a
  native CF integration installed, we need its exported `public_action_id`; if not, a bound-HTTP
  request to the CF API (IP Access Rules / Lists / WAF) is the correct and only approach.
**Lesson / to build these natively going forward:** the unlock is an **exported stub workflow**
(1 node per native action) from the tenant's console — same method that gave us Blocklist IP.json
— plus the list of installed HA integrations + connections. Without that we cannot invent a real
`public_action_id`; bound-HTTP is the honest fallback and is not wrong.

## 2026-07-02 — Cloudflare Containers deploy: don't containerize a static SPA
**Context:** Deploying lab-ui to Cloudflare Containers repeatedly failed. Root causes, in order:
(1) the frontend Docker build's `npm install` died on `ECONNRESET` because the host network
could not reach registry.npmjs.org at all (`curl` → HTTP 000), while PyPI was fine;
(2) the `CLOUDFLARE_API_TOKEN` could deploy Workers but lacked the **Cloudflare Containers**
permission (`GET /accounts/:id/containers/me` → 403; `/workers/scripts` → 200 — a clean way to
prove it's containers-scope-specific); (3) the frontend nginx container crash-looped because
`nginx.conf` had `proxy_pass http://backend:8000` and nginx refuses to start when an upstream
host is unresolvable; (4) even after fixing nginx, the frontend container instance sat
`inactive` on Cloudflare (never scheduled, never failed) though the image ran fine locally.
**Lesson:** A static SPA (Vite `dist/`) does not belong in a container. The correct Cloudflare
architecture is **Worker static assets for the frontend + a container only for the dynamic
backend**. wrangler.jsonc: `assets: { directory, binding: "ASSETS", not_found_handling:
"single-page-application", run_worker_first: true }`, Worker routes `/api`+`/ws` →
`getContainer(env.BACKEND,...).fetch()` and everything else → `env.ASSETS.fetch(request)`.
This removed the only failing component, is faster/cheaper, and has no cold-start.
**Also:** when a package registry is unreachable at build time but deps are already installed
on the host, build the artifact on the host (`npm run build` is fully local once node_modules
exists) and `COPY dist` into a single-stage nginx/static image — don't run `npm install` in the
image. `dist/` is platform-independent (safe to copy from macOS host → Linux image), unlike
node_modules. **Diagnose "which side" first:** `curl` npm/PyPI/CF endpoints separately, and hit
`/containers/me` vs `/workers/scripts` to localize an auth failure to a specific permission.

## 2026-06-30 — Scope rebrands repo-wide, not per-agent-directory
**Context:** During the ThreatOps merge I told each Wave-1 specialist to rebrand only its own
directory (e.g. "rebrand acmecorp->novamind in config.py ONLY"). QA then found acmecorp still
in scenario scripts, wordlists, setup.sh, demo.py, several frontend pages, main.py's fallback
domain, and docs — because no single agent owned the cross-cutting rename.
**Lesson:** A global rename/rebrand is a CROSS-CUTTING concern. Don't split it across
dir-scoped agents. Either (a) run one repo-wide mechanical pass myself
(`grep -rIli <term>` to collect, then perl -i across the list) BEFORE the feature agents run,
or (b) assign one agent explicitly to "rename X->Y everywhere" with whole-repo scope.
**Also:** when collecting files for a rename, use case-INSENSITIVE grep (`-i`) — `AcmeCorp`
and `acmecorp` both exist and a case-sensitive sweep silently misses half of them.

## 2026-06-30 — Pin cross-agent wire contracts in the spec, exactly
**Context:** incident.py (attack side) sent `Authorization: Bearer <key>` while the worker
checked `data.key` in the JSON body. Two agents, two reasonable interpretations, one mismatch.
**Lesson:** When two parallel agents share a wire protocol (auth header vs body field, exact
JSON shape, route paths), specify the EXACT contract in the shared spec — don't leave it to
each agent's judgment. The co-worker's original (body `key`) was the right reference; I should
have quoted it verbatim in the spec.

## 2026-06-30 — Parallel agents: one directory per agent prevents conflicts
**Context:** Running cloudflare/attacks, then backend/frontend, then S1 agents in waves with
strictly non-overlapping directories produced zero merge conflicts across ~8 agents.
**Lesson:** Dependency-ordered waves + one-dir-per-agent + a pinned spec is a reliable pattern
for multi-agent builds. Keep doing this; reconcile cross-cutting contracts between waves.