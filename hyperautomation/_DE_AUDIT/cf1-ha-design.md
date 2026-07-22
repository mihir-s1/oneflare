# CF1-* Hyperautomation Design Spec — functional, multi-action Cloudflare response playbooks

**Author:** s1-hyperautomation-engineer · **Date:** 2026-07-21 · **Status:** DESIGN ONLY (do not import/deploy from this doc)

This spec clones the 7 live `CF-*` alert-response playbooks into `CF1-*` and makes each one
**do multiple, portal-visible Cloudflare actions** (enrich → validate → act → optional evidence)
instead of the single "block IP". Every `CF1-*` keeps the existing 18-node backbone and the two
gates (analyst approval + threat-intel verdict) **intact**; new Cloudflare nodes are **inserted**
at named points. An 8th playbook, `CF1-Reset-Demo`, undoes every demo artifact.

---

## 0. Shared facts (apply to every CF node in every playbook)

### 0.1 Cloudflare connection envelope (identical on ALL Cloudflare http nodes)
```jsonc
"type": "http_request",
"tag": "integration",
"connection_id": "f1d111b8-d0c0-4ea7-8ae7-2891c16e9592",
"connection_name": "",
"use_connection_name": false,
"integration_id": "0dedd07c-0b9a-4205-9215-03ab1a95eb3a",
```
- **Raw endpoint** (no catalog action) → `data.public_action_id: null`.
- **Native action** (in catalog) → `data.public_action_id: "<id>"` and `url` uses the plain path
  form the catalog shows (Cloudflare catalog actions use a **plain** `url`, not the `<@…@>` link form).
- Every node also carries the proven defaults: `"retry_on_status_codes":[500]`, `"ssl_verification":true`,
  `"timeout":30`, `"use_authentication_data":true`, `"redirect_follow":true`, headers
  `{"Content-Type":"application/json","accept":"application/json"}`.

### 0.2 Hardcoded Cloudflare IDs (validated live this session)
| Token | Value |
|---|---|
| `{zone}` (soledrop.co) | `cf4d15af4a7eb86b033f859aefec1047` |
| `{acct}` | `b8e637d5097fff0c694c3290ba81563e` |
| `{ruleset}` (custom-firewall entrypoint) | `47e1f8f7826b485498964c658c551f22` |

### 0.3 The three WORKING raw endpoints (public_action_id: null)
| Purpose | method + url_path | body |
|---|---|---|
| **Zone IP access rule** (block / challenge an IP) | `POST /client/v4/zones/{zone}/firewall/access_rules/rules` | `{"mode":"block"\|"managed_challenge","configuration":{"target":"ip","value":"{{local_var.src_ip}}"},"notes":"OneFlare <scn> — alert {{singularity-response-trigger.data.id}}"}` |
| **Modern Ruleset rule** (route/JA3-scoped block or challenge) | `POST /client/v4/zones/{zone}/rulesets/{ruleset}/rules` | `{"action":"block"\|"managed_challenge","expression":"<cf filter expr>","description":"OneFlare <scn> — alert {{singularity-response-trigger.data.id}}","enabled":true}` |
| **Gateway DNS rule** (sinkhole a C2 domain) | `POST /client/v4/accounts/{acct}/gateway/rules` | `{"name":"OneFlare block C2 {{local_var.c2_domain}}","action":"block","enabled":true,"filters":["dns"],"traffic":"any(dns.domains[*] == \"{{local_var.c2_domain}}\")"}` |

### 0.4 The usable NATIVE actions (public_action_id set)
| Action | public_action_id | method + url_path | Use |
|---|---|---|---|
| Create DNS Record | `828d96cc-222b-48dd-ae76-6ac0a69679ca` | `POST /client/v4/zones/{zone}/dns_records` | sinkhole record (visible in DNS portal) |
| Edit Zone | `70c1ff7b-18f7-4946-895c-d0365a1bfd76` | `PATCH /client/v4/zones/{zone}` | set `security_level:"under_attack"` (visible in Overview) |
| Zone Details | `da54fc7f-5287-448c-b81a-c62dbd1e50d4` | `GET /client/v4/zones/{zone}` | enrich/validate current security_level |
| List DNS Records | `752058a2-44a7-4b01-a782-70ec1019e1fa` | `GET /client/v4/zones/{zone}/dns_records` | reset: find sinkhole record id |
| Get zero trust user failed logins | `a3620341-5c10-4c7e-bf3b-41167b7ad137` | `GET /client/v4/accounts/{acct}/access/users/<<user_id>>/failed_logins` | cred enrich (best-effort) |
| Cloudflare JD Cloud IP Details | `46eafa14-d54e-4d37-9147-ac0ac095e93e` | `GET /client/v4/ips` | bot enrich (Cloudflare IP ranges) |
| Get IP Overview | `170fef59-6471-4e65-8ccc-9d841fb33426` | `GET /client/v4/accounts/{acct}/intel/ip?ipv4={{local_var.src_ip}}` | enrich (BEST-EFFORT — token 403s standalone; may work via connection) |
| Create PCAP request | `d7b33eb1-e0c6-44ee-90ac-c0d99d5fe11f` | `POST /client/v4/accounts/{acct}/pcaps` | optional evidence capture |

### 0.5 ❌ DO NOT USE (validated dead/blocked)
- Native **Create firewall rules** (`2fb46ecc`, legacy `/zones/{zone}/firewall/rules`) → decommissioned (10020 maintenance_mode). Use the **Ruleset** raw endpoint (0.3) instead.
- Native **Create/List/Delete/Update IP Access rule** (`/user/...`) → 403 for API tokens. Use the **zone** raw endpoint (0.3) instead. (List/Delete for reset also use the **zone** raw endpoint, below.)

### 0.6 datapath resolution (the golden rule)
`src_ip` is already resolved in the existing **Extract Enrichment** node (backbone export_id 6) as
`{{Function.DEFAULT(local_var.demo_override, local_var.real_ip)}}` and referenced everywhere as
**`{{local_var.src_ip}}`**. Reuse it — do NOT re-derive. `real_ip` =
`DEFAULT(singularity-response-trigger.data.asset.name, "0.0.0.0")` (entity-mapped src_ip).

**`host` / `ja3` / `c2_domain`:** these are needed by the Ruleset/Gateway acts but are NOT
currently projected into local vars, and the **DE `cf1-datapaths.md` file was NOT present when this
spec was written** (polled ~90 s). Until it lands, this spec resolves them as **new literal vars
added to each backbone Set Context node** (safe: literals never cross-reference, so E1 holds), each
`DEFAULT()`-guarded to the demo value so demo mode is always portal-visible. **When `cf1-datapaths.md`
arrives, swap the literal for the real alert reference** (e.g. `host = DEFAULT(demo_host, <real host col>)`).

New Set Context vars to ADD per scenario (append to the existing `variables[]` array of node export_id 8):
| Scenario | new vars |
|---|---|
| cred | `target_host = "portal.soledrop.co"` |
| web | `target_host = "shop.soledrop.co"` |
| exfil | `target_host = "api.soledrop.co"`, `block_path = "/export"` |
| bot | `target_host = "shop.soledrop.co"` |
| prompt | `target_host = "api.soledrop.co"`, `block_path = "/chat"` |
| dns | `demo_domain = "c2tunnel-demo.net"`, and `c2_domain` is set in **Extract Enrichment** as `DEFAULT(local_var.demo_domain, <pq c2_domain>)` (mirror the src_ip pattern; the workflow already extracts `c2_domain` from PQ index[5]) |
| campaign | `ja3 = "0a80f68631b6e8b4634dbc261e8ba60b"` literal (the workflow's Extract Enrichment already sets `ja3` from PQ index[3]; for demo, wrap it `DEFAULT(local_var.demo_ja3, <pq ja3>)` with `demo_ja3` literal in Set Context) |

### 0.7 backbone node map (export_ids, from `cred-stuffing.workflow.json` — identical shape in all 7)
```
Trigger(9) → Set Context(8) → Create Power Query(5) → Extract Enrichment(6)
 → VirusTotal(16) → AbuseIPDB(0) → Send Interactive Message(7) → Wait For Slack(17)
 → Analyst Approved[condition](3)
      true  → Cloudflare Block IP(4) → Slack Update Approved(10) → Add Note Approved(1)
                → Threat Intel Malicious[condition](13)
                     true  → Verdict True Positive Malware(15)
                     false → Status In Progress(12)
      false → Slack Update Dismissed(11) → Add Note Dismissed(2) → Verdict False Positive Benign(14)
```
**Insertion points (used by every CF1-*):**
- **ENRICH** = splice between Extract Enrichment(6) and VirusTotal(16): `6 → [enrich…] → 16`. All `continue_on_fail:true`.
- **VALIDATE + ACT** = splice on the APPROVED edge, between Analyst Approved(3,true) and Cloudflare Block IP(4): `3(true) → [validate] → 4 → [extra act…] → 10`. Validate `continue_on_fail:true`; acts `continue_on_fail:false` (block is the load-bearing containment) except scenario-secondary acts which are `true`.
- **EVIDENCE** (optional) = between the last act and Slack Update Approved(10), `continue_on_fail:true`.
- New nodes get fresh unique `export_id`s (use 20,21,22… — value is arbitrary, only uniqueness matters). `parent_action:null` on all (none are inside a loop). Wire strictly via `connected_to.target`; update the upstream node's existing `connected_to.target` to point at the first inserted node.
- Reference a node's output by its slug (name lowercased, spaces→`-`): e.g. `Get IP Overview` → `{{get-ip-overview.body.result…}}`.

---

## 1. CF1-Access-CredStuffing  (managed_challenge + zero-trust enrich)

Demo IP `185.220.101.182` · host `portal.soledrop.co`. Differentiator: **challenge (not block)** an
IP that may be shared corporate egress, plus **Cloudflare Access failed-login enrichment**.

**ENRICH (after 6, before 16):**
- **N1 `CF Zone Details`** — native `da54fc7f`, `GET /client/v4/zones/{zone}`. `continue_on_fail:true`.
  Feeds Slack a "current security_level" line. Follows 6, precedes N2.
- **N2 `CF Access Failed Logins`** — native `a3620341`,
  `GET /client/v4/accounts/{acct}/access/users/<<user_id>>/failed_logins`. **BEST-EFFORT / FLAGGED:**
  the alert carries **no user identity** (enrichment-readiness-B §1 — cred alerts are IP-only), so
  `<<user_id>>` cannot be filled from the alert. Include only as a demo-narrative node hardcoded to a
  known Access user id, or **OMIT** and rely on N1. `continue_on_fail:true`. If kept: follows N1, precedes 16.

**VALIDATE + ACT (approved branch):**
- **N3 `CF List IP Rules (validate)`** — raw `GET /client/v4/zones/{zone}/firewall/access_rules/rules?notes=OneFlare`. `continue_on_fail:true`. Lets the note/Slack say "already-challenged? y/n". Follows 3(true), precedes 4.
- **MODIFY existing node 4 `Cloudflare Block IP` → `Cloudflare Challenge IP`:** change body `mode` to **`"managed_challenge"`**, notes `"OneFlare cred-stuffing managed-challenge — alert {{…id}}"`. Raw zone endpoint (unchanged url). Follows N3, precedes 10. `continue_on_fail:false`.

Rewire: `3.connected_to(true).target: N3`; `N3 → 4`; `4 → 10` (unchanged). `6 → N1 → (N2) → 16`.

---

## 2. CF1-WAF-WebAttack  (block IP + IP Overview enrich)

Demo IP `45.148.10.95` · host `shop.soledrop.co`. Differentiator: **threat-intel-style Cloudflare
enrichment** (Get IP Overview) layered on the block.

**ENRICH (after 6, before 16):**
- **N1 `CF Get IP Overview`** — native `170fef59`, `GET /client/v4/accounts/{acct}/intel/ip?ipv4={{local_var.src_ip}}`. **BEST-EFFORT** (token 403s standalone; may resolve via the bound connection). `continue_on_fail:true`. Slack shows `body.result[0].risk_types` / belongs-to-ASN. Follows 6, precedes 16.

**VALIDATE + ACT (approved branch):**
- **N2 `CF List IP Rules (validate)`** — raw `GET /client/v4/zones/{zone}/firewall/access_rules/rules?notes=OneFlare`, `continue_on_fail:true`. Follows 3(true), precedes 4.
- **Keep node 4 `Cloudflare Block IP`** as-is (`mode:"block"`), notes `"OneFlare web-attacks auto-block — alert {{…id}}"`. Follows N2, precedes N3.
- **N3 `CF Ruleset Block Signature (optional)`** — raw Ruleset rule, `POST /client/v4/zones/{zone}/rulesets/{ruleset}/rules`, body
  `{"action":"block","expression":"ip.src eq {{local_var.src_ip}} and http.host eq \"{{local_var.target_host}}\"","description":"OneFlare web-attacks host-scoped block — alert {{…id}}","enabled":true}`. Demonstrates the modern Rulesets surface distinct from the IP-access-rule. `continue_on_fail:true`. Follows 4, precedes 10.

Rewire: `6 → N1 → 16`; `3(true) → N2 → 4 → N3 → 10`.

---

## 3. CF1-API-Exfil  (route-block /export via Rulesets + IP block + PCAP evidence)

Demo IP `193.32.162.157` · host `api.soledrop.co` · path `/export`. Differentiator: **route-scoped
Ruleset block** + **evidence capture (PCAP)**.

**ENRICH (after 6, before 16):**
- **N1 `CF Get IP Overview`** — native `170fef59` (as §2 N1), `continue_on_fail:true`. Follows 6, precedes 16.

**VALIDATE + ACT (approved branch):**
- **N2 `CF List Ruleset Rules (validate)`** — raw `GET /client/v4/zones/{zone}/rulesets/{ruleset}`, `continue_on_fail:true` (checks whether a `/export` rule already exists). Follows 3(true), precedes 4.
- **Keep node 4 `Cloudflare Block IP`** (`mode:"block"`), notes `"OneFlare data-exfil auto-block — alert {{…id}}"`. Follows N2, precedes N3.
- **N3 `CF Ruleset Block /export`** — raw Ruleset rule, `POST /client/v4/zones/{zone}/rulesets/{ruleset}/rules`, body
  `{"action":"block","expression":"http.host eq \"{{local_var.target_host}}\" and starts_with(http.request.uri.path, \"{{local_var.block_path}}\")","description":"OneFlare data-exfil route-block {{local_var.block_path}} — alert {{…id}}","enabled":true}`. `continue_on_fail:false` (this is the exfil-specific containment). Follows 4, precedes N4.
- **N4 `CF Create PCAP (evidence)`** — native `d7b33eb1`, `POST /client/v4/accounts/{acct}/pcaps`, body
  `{"system":"magic-transit","type":"simple","time_limit":300,"packet_limit":10000,"filter_v1":{"source_address":"{{local_var.src_ip}}"}}`. **BEST-EFFORT / FLAGGED** — PCAP requires Magic Transit/relevant entitlement; likely 403 on this zone. `continue_on_fail:true`. Follows N3, precedes 10.

Rewire: `6 → N1 → 16`; `3(true) → N2 → 4 → N3 → N4 → 10`.

---

## 4. CF1-Bot-Scraper  (managed_challenge + JD Cloud IP Details enrich)

Demo IP `23.129.64.218` · host `shop.soledrop.co`. Differentiator: **challenge** (bots, not
outright block) + a **different enrichment surface** (JD Cloud / Cloudflare IP ranges).

**ENRICH (after 6, before 16):**
- **N1 `CF JD Cloud IP Details`** — native `46eafa14`, `GET /client/v4/ips`. Returns Cloudflare's own IP ranges (lets Slack note "is the source a Cloudflare egress?"). `continue_on_fail:true`. Follows 6, precedes 16.

**VALIDATE + ACT (approved branch):**
- **N2 `CF List IP Rules (validate)`** — raw `GET /client/v4/zones/{zone}/firewall/access_rules/rules?notes=OneFlare`, `continue_on_fail:true`. Follows 3(true), precedes 4.
- **MODIFY node 4 → `Cloudflare Challenge IP`:** body `mode:"managed_challenge"`, notes `"OneFlare bot-scraper managed-challenge — alert {{…id}}"`. Follows N2, precedes 10.

Rewire: `6 → N1 → 16`; `3(true) → N2 → 4 → 10`. Also fix the copy-paste bug in the current bot node notes (says "cred-stuffing").

---

## 5. CF1-AI-PromptInjection  (managed_challenge /chat via Rulesets)

Demo IP `89.234.157.254` · host `api.soledrop.co` · path `/chat`. Differentiator: **route-scoped
managed_challenge** on the chat endpoint (throttle abuse without hard-blocking the API).

**ENRICH (after 6, before 16):**
- **N1 `CF Get IP Overview`** — native `170fef59` (as §2 N1), `continue_on_fail:true`. Follows 6, precedes 16.

**VALIDATE + ACT (approved branch):**
- **N2 `CF List Ruleset Rules (validate)`** — raw `GET /client/v4/zones/{zone}/rulesets/{ruleset}`, `continue_on_fail:true`. Follows 3(true), precedes 4.
- **Keep node 4 `Cloudflare Block IP`** (`mode:"block"`) as the belt-and-suspenders IP containment, notes `"OneFlare prompt-injection auto-block — alert {{…id}}"` (fix current "cred-stuffing" copy-paste). Follows N2, precedes N3.
- **N3 `CF Ruleset Challenge /chat`** — raw Ruleset rule, `POST /client/v4/zones/{zone}/rulesets/{ruleset}/rules`, body
  `{"action":"managed_challenge","expression":"http.host eq \"{{local_var.target_host}}\" and starts_with(http.request.uri.path, \"{{local_var.block_path}}\")","description":"OneFlare prompt-injection challenge {{local_var.block_path}} — alert {{…id}}","enabled":true}`. `continue_on_fail:false`. Follows 4, precedes 10.

Rewire: `6 → N1 → 16`; `3(true) → N2 → 4 → N3 → 10`.

---

## 6. CF1-Gateway-DNSTunnel  (Gateway C2 block + Create DNS sinkhole record)

Demo IP `162.247.74.74` · C2 domain `c2tunnel-demo.net`. Differentiator: **two brand-new Cloudflare
surfaces** — a Zero-Trust **Gateway DNS block** and a **sinkhole DNS record** (both portal-visible),
plus keep the IP block.

**Set Context / Extract:** set `c2_domain = DEFAULT(local_var.demo_domain, <pq c2_domain>)` (Extract
Enrichment already reads `c2_domain` from PQ index[5]; add `demo_domain = "c2tunnel-demo.net"` literal
to Set Context, and add S1 Add-IOC as a bonus — see note).

**ENRICH (after 6, before 16):** none Cloudflare-specific required (VT/AbuseIPDB run on `src_ip`).
Optionally **N0 `CF Zone Details`** (`da54fc7f`) for a security_level line, `continue_on_fail:true`.

**VALIDATE + ACT (approved branch):**
- **N1 `CF List Gateway Rules (validate)`** — raw `GET /client/v4/accounts/{acct}/gateway/rules`, `continue_on_fail:true` (checks for an existing OneFlare C2 rule). Follows 3(true), precedes 4.
- **Keep node 4 `Cloudflare Block IP`** (`mode:"block"`), notes `"OneFlare DNS-tunnel auto-block — alert {{…id}}"`. Follows N1, precedes N2.
- **N2 `CF Gateway Block C2 Domain`** — raw, `POST /client/v4/accounts/{acct}/gateway/rules`, body
  `{"name":"OneFlare block C2 {{local_var.c2_domain}}","action":"block","enabled":true,"filters":["dns"],"traffic":"any(dns.domains[*] == \"{{local_var.c2_domain}}\")"}`. `continue_on_fail:false` (the DNS-scenario containment). Follows 4, precedes N3.
- **N3 `CF Create Sinkhole DNS Record`** — native `828d96cc`, `POST /client/v4/zones/{zone}/dns_records`, body
  `{"type":"A","name":"{{local_var.c2_domain}}","content":"192.0.2.1","ttl":300,"proxied":false,"comment":"OneFlare DNS-tunnel sinkhole — alert {{…id}}"}`. Sinks the C2 name to TEST-NET-1; visible in the DNS portal. **FLAG:** `c2tunnel-demo.net` is NOT a subdomain of soledrop.co, so Cloudflare will reject a record for an out-of-zone name — for the **demo, set `name` to a soledrop.co subdomain** e.g. `"c2sink-demo.soledrop.co"` (add as `sink_name` literal var) so the record actually creates. `continue_on_fail:true`. Follows N2, precedes 10.

Rewire: `6 → (N0) → 16`; `3(true) → N1 → 4 → N2 → N3 → 10`.
**Bonus (already in-catalog, not Cloudflare):** add S1 **Add IOCs** (`282ae683`, `POST /web/api/v2.1/threat-intelligence/iocs`, integration `ef645af9…`) to add `c2_domain` as a DOMAIN IOC — matches the story-map "add-IOC" intent. `continue_on_fail:true`.

---

## 7. CF1-Campaign-DropDaySwarm  (Rulesets JA3 block + Edit Zone under-attack)

Demo IP `104.244.73.29` · JA3 `0a80f68631b6e8b4634dbc261e8ba60b`. Differentiator: **JA3-scoped
Ruleset block** + **zone-wide Under Attack Mode** (the most visibly dramatic portal change).

**Set Context / Extract:** `ja3 = DEFAULT(local_var.demo_ja3, <pq ja3 index[3]>)`; add `demo_ja3 = "0a80f68631b6e8b4634dbc261e8ba60b"` literal.

**ENRICH (after 6, before 16):**
- **N1 `CF Zone Details`** — native `da54fc7f`, `continue_on_fail:true` (capture pre-incident `security_level` so the note can show the before/after). Follows 6, precedes 16.

**VALIDATE + ACT (approved branch):**
- **N2 `CF List Ruleset Rules (validate)`** — raw `GET /client/v4/zones/{zone}/rulesets/{ruleset}`, `continue_on_fail:true`. Follows 3(true), precedes 4.
- **Keep node 4 `Cloudflare Block IP`** (`mode:"block"`), notes `"OneFlare campaign auto-block — alert {{…id}}"`. Follows N2, precedes N3.
- **N3 `CF Ruleset Block JA3`** — raw Ruleset rule, `POST /client/v4/zones/{zone}/rulesets/{ruleset}/rules`, body
  `{"action":"block","expression":"cf.bot_management.ja3_hash eq \"{{local_var.ja3}}\"","description":"OneFlare campaign JA3 block — alert {{…id}}","enabled":true}`. **FLAG (uncertain):** `cf.bot_management.ja3_hash` requires the **Bot Management** entitlement; memory says one-flare.com has SBFM, not the Bot Mgmt add-on, so this expression may be rejected. `continue_on_fail:true` so the flow proceeds to N4 regardless; if it 400s, the IP block (4) + under-attack (N4) still land. Follows 4, precedes N4.
- **N4 `CF Edit Zone Under Attack`** — native `70c1ff7b`, `PATCH /client/v4/zones/{zone}`, body `{"value":{"security_level":"under_attack"}}` (Cloudflare `settings` PATCH shape is `{"value":"under_attack"}` on the `/settings/security_level` endpoint; the whole-zone PATCH used by native `Edit Zone` takes `{"security_level":"under_attack"}` — **verify the exact body against the bound connection**, both forms noted). `continue_on_fail:false` (the campaign headline action; visible in Overview). Follows N3, precedes 10.

Rewire: `6 → N1 → 16`; `3(true) → N2 → 4 → N3 → N4 → 10`.
**Note:** N4 is the artifact `CF1-Reset-Demo` reverts (security_level back to `medium`).

---

## 8. CF1-Reset-Demo  (manual_trigger — undo every demo artifact)

Purpose: after running the 7 demos, one click removes every OneFlare-tagged artifact so the portal is
clean for the next run. **Idempotent** — every node `continue_on_fail:true`; missing artifacts are no-ops.

### Node list (ordered)
1. **`Manual Trigger`** — core `manual_trigger`, `trigger_type:"static"`, `dynamic_properties:null`, `static_payload:"{}"`. → Set Context.
2. **`Set Context`** — core `variable`, `variables_scope:"local"`, literals:
   - `zone = "cf4d15af4a7eb86b033f859aefec1047"`, `account = "b8e637d5097fff0c694c3290ba81563e"`, `ruleset = "47e1f8f7826b485498964c658c551f22"`
   - `sink_name = "c2sink-demo.soledrop.co"` (matches §6 N3 demo record name)
   - (demo IPs are matched by the `notes=OneFlare` filter, so no IP list is strictly needed).
   → A) IP-access cleanup.

**A) Zone IP Access rules cleanup** (removes all 7 demo block/challenge rules)
3. **`List Zone IP Rules`** — raw CF `GET /client/v4/zones/{zone}/firewall/access_rules/rules?notes=OneFlare&per_page=100`. Response array at `body.result[]`, each `{id, notes}`. → Loop.
4. **`Loop IP Rules`** — core `loop`, `loop_type:"dynamic"`, `object_to_iterate:"{{list-zone-ip-rules.body.result}}"`, `is_parallel:false`.
   - `connected_to`: `{target: <5 Delete>, custom_handle:"inner"}` **and** `{target: <6 List Ruleset>, custom_handle:null}` (after-loop).
5. **`Delete IP Rule`** (inner; `parent_action` = Loop-4 export_id) — raw CF `DELETE /client/v4/zones/{zone}/firewall/access_rules/rules/{{loop.item.id}}`. **rule id from prior List:** `{{loop.item.id}}`. `connected_to:[]` (loop sink). `continue_on_fail:true`.

**B) Ruleset rules cleanup** (removes /export, /chat, JA3, host-scoped rules)
6. **`List Ruleset Rules`** — raw CF `GET /client/v4/zones/{zone}/rulesets/{ruleset}`. Rules array at `body.result.rules[]`, each `{id, description}`. → Loop.
7. **`Loop Ruleset Rules`** — core `loop` dynamic, `object_to_iterate:"{{list-ruleset-rules.body.result.rules}}"`. `connected_to`: `{target:<8 Condition>, custom_handle:"inner"}`, `{target:<10 List Gateway>, custom_handle:null}`.
8. **`Is OneFlare Rule`** (inner; parent=Loop-7) — core `condition` multi: `input_value:"{{loop.item.description}}"`, `compared_value:"OneFlare"`, `comparison_operator:"contains"`. `connected_to`: `{target:<9 Delete>, custom_handle:"true"}` (no false edge — loop auto-continues).
9. **`Delete Ruleset Rule`** (inner; parent=Loop-7) — raw CF `DELETE /client/v4/zones/{zone}/rulesets/{ruleset}/rules/{{loop.item.id}}`. **rule id:** `{{loop.item.id}}`. `connected_to:[]`. `continue_on_fail:true`.

**C) Gateway DNS rule cleanup**
10. **`List Gateway Rules`** — raw CF `GET /client/v4/accounts/{account}/gateway/rules`. Array at `body.result[]`, each `{id, name}`. → Loop.
11. **`Loop Gateway Rules`** — core `loop` dynamic, `object_to_iterate:"{{list-gateway-rules.body.result}}"`. `connected_to`: `{target:<12 Condition>, "inner"}`, `{target:<14 List DNS>, null}`.
12. **`Is OneFlare Gateway Rule`** (inner; parent=Loop-11) — core `condition` multi: `input_value:"{{loop.item.name}}"`, `compared_value:"OneFlare"`, `comparison_operator:"contains"`. `connected_to`: `{target:<13 Delete>, "true"}`.
13. **`Delete Gateway Rule`** (inner; parent=Loop-11) — raw CF `DELETE /client/v4/accounts/{account}/gateway/rules/{{loop.item.id}}`. **rule id:** `{{loop.item.id}}`. `connected_to:[]`. `continue_on_fail:true`.

**D) Sinkhole DNS record cleanup**
14. **`List DNS Records`** — native `752058a2`, `GET /client/v4/zones/{zone}/dns_records?name={{local_var.sink_name}}`. Array at `body.result[]`, each `{id, name}`. → Loop.
15. **`Loop DNS Records`** — core `loop` dynamic, `object_to_iterate:"{{list-dns-records.body.result}}"`. `connected_to`: `{target:<16 Delete>, "inner"}`, `{target:<17 Revert Zone>, null}`.
16. **`Delete DNS Record`** (inner; parent=Loop-15) — native `bd6c1c99`, `DELETE /client/v4/zones/{zone}/dns_records/{{loop.item.id}}`. **record id:** `{{loop.item.id}}`. `connected_to:[]`. `continue_on_fail:true`.

**E) Revert Under Attack Mode**
17. **`Revert Zone Security Level`** — native `70c1ff7b`, `PATCH /client/v4/zones/{zone}`, body `{"security_level":"medium"}` (verify body shape against the bound connection, as §7 N4). `continue_on_fail:true`. → 18.
18. **`Reset Complete`** (optional) — Slack native `Post Message` (`1a5289f8`, integration `43d27b10…`) to `channel_id` "OneFlare demo artifacts reset — portal clean." OR omit. `continue_on_fail:true`. `connected_to:[]`.

**Cataloged native `Delete an IP Access rule` (`0c2130ed`) is NOT used** — it hits `/user/...` (403). Reset uses the **zone** raw DELETE (node 5). Same reason native `Create firewall rules` is avoided.

`notes:[]` at the workflow level (never strings). `parent_action:null` on every non-loop node; loop-inner nodes set `parent_action` to their loop's export_id.

---

## 9. Cross-cutting build/deploy notes & flags

- **Gates preserved:** every CF1-* keeps `Analyst Approved`(3) and `Threat Intel Malicious`(13) exactly. No new act runs on the DISMISSED branch. New destructive acts sit only on the approved branch, downstream of node 3(true).
- **Enrichment nodes are `continue_on_fail:true`; primary containment (block/challenge/route-rule/gateway) is `continue_on_fail:false`; secondary/best-effort acts (PCAP, JA3, IP Overview, sinkhole record) are `true`.**
- **Slack + Add-Note bodies** should be extended to surface the new enrichment (security_level, IP Overview risk_types, "already-blocked?" from the validate list, and which acts fired). Reuse the existing `Function.DEFAULT(…, "N/A")` pattern so missing best-effort data degrades gracefully.
- **Connections to bind post-import (warn user):** Cloudflare (`f1d111b8…`), Slack, SentinelOne (Mgmt), SentinelOne (Unified Alerts), VirusTotal, AbuseIPDB. Same set the live CF-* need, plus nothing new for CF1-*.
- **Import recipe (per lessons):** raw import `{"data":{…}}` with a **personal Console User token** → **publish in the same step** (`POST /hyper-automate/api/v1/workflows/{id}/publish?accountIds=…&siteIds=…`) → bind connections → activate. Re-import = new workflow (no in-place update). `notes:[]`, `parent_action:null` except loop-inner, native nodes need `integration_id` SET (else render as plain HTTP), copy catalog `data` verbatim and only substitute `<<…>>` inputs.

### Explicit uncertainty flags (verify live before trusting)
1. **`cf.bot_management.ja3_hash`** (§7 N3) — needs Bot Management entitlement; may 400 on this zone. Guarded `continue_on_fail:true`; IP block + under-attack still land.
2. **`Get IP Overview`** (`170fef59`, §2/§3/§5 N1) — account-intel; token 403s standalone. Best-effort, `continue_on_fail:true`.
3. **`Create PCAP request`** (§3 N4) — needs Magic Transit / PCAP entitlement; likely 403. Best-effort.
4. **`Edit Zone` under-attack body shape** (§7 N4 / §8 node 17) — whole-zone PATCH `{"security_level":…}` vs `/settings/security_level` PATCH `{"value":…}`. Verify against the bound connection; native `Edit Zone` maps to the whole-zone PATCH.
5. **Sinkhole record out-of-zone name** (§6 N3) — Cloudflare rejects a DNS record for a name outside the zone; demo uses a `*.soledrop.co` sink name, not `c2tunnel-demo.net`. The **Gateway** block (§6 N2) can still target `c2tunnel-demo.net` (Gateway is account-scoped, not zone-bound).
6. **Access Failed Logins `<<user_id>>`** (§1 N2) — no user identity in cred alerts (enrichment-readiness-B §1); node is demo-narrative only or omitted.
7. **DE datapaths dependency** — `cf1-datapaths.md` was absent at authoring time; `host`/`ja3`/`c2_domain` are resolved via literal Set Context vars with demo defaults. Swap to the real alert references when that file lands (see §0.6).
