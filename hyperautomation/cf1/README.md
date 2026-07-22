# CF1-* — enriched, multi-action Cloudflare response playbooks

Clones of the 7 live `CF-*` alert-response workflows, extended so each one drives **multiple,
portal-visible Cloudflare actions** (enrich → validate → act) instead of a single "block IP",
plus a manual **reversal** playbook. All 8 are deployed + active on the console
(`usea1-partners.sentinelone.net`, site `2433185103040607397`). Built 2026-07-21 with the
s1-detection-engineer (datapaths) and s1-hyperautomation-engineer (design). See
`hyperautomation/_DE_AUDIT/cf1-datapaths.md`, `cf1-ha-design.md`, and `docs/cf1-validated-actions.md`.

## Backbone (unchanged from CF-*)
`Trigger → Set Context → Create Power Query → Extract Enrichment → VirusTotal → AbuseIPDB →
Slack interactive → Wait For Slack → **Analyst Approved** gate → Block/act → Slack update →
Add note → **Threat-Intel** gate → Verdict / Status`. Both gates preserved; every new Cloudflare
action sits on the **approved** branch.

## What each CF1-* adds (all endpoints live-validated; all differentiated)
| Playbook | Enrich | Validate | Act(s) — visible in the Cloudflare portal |
|---|---|---|---|
| CF1-Access-CredStuffing | Zone Details | List IP rules | **managed_challenge** the IP (Security→WAF→Tools) |
| CF1-WAF-WebAttack | JD Cloud IP Details | List IP rules | block IP + **host-scoped Ruleset rule** (Security→WAF→Custom rules) |
| CF1-API-Exfil | Zone Details | List Ruleset rules | block IP + **Ruleset route-block `/export`** |
| CF1-Bot-Scraper | JD Cloud IP Details | List IP rules | **managed_challenge** the IP |
| CF1-AI-PromptInjection | Zone Details | List Ruleset rules | block IP + **Ruleset managed_challenge `/api/v1/chat`** |
| CF1-Gateway-DNSTunnel | Zone Details | List Gateway rules | block IP + **Gateway DNS block** (Zero Trust) + **sinkhole DNS record** (DNS→Records) |
| CF1-Campaign-DropDaySwarm | Zone Details | List Ruleset rules | block IP + **JA3 Ruleset block** + **Under-Attack mode** (Overview) |

Every action node is `continue_on_fail:true` — a benign "already blocked" never aborts the run.

## Failure reporting + links (on every playbook)
The approved **Slack update** and **alert note** report each action's outcome —
`HTTP <status> <Cloudflare error message>` (a message after the code = the failure reason, e.g.
"already blocked") — followed by a link to the **Hyperautomation workflow**
(`/hyperautomation/workflows`) and to the **detection rule** (`/star-rules`, rule id in the text).

## Demo flow
1. Set Context in each playbook carries the scenario `demo_override` IP (+ JA3 / C2 domain / host)
   so a run is visible with demo data even if the alert's real IP is a shared edge IP.
2. Run the attack scenario → alert fires → approve in Slack → Cloudflare actions apply.
3. See the artifacts in the Cloudflare portal (WAF rules, DNS record, Under-Attack banner…).
4. Run **CF1-Reset-Demo** (manual) → every `OneFlare`-tagged artifact is removed and Under-Attack
   reverts to `medium` → portal clean for the next demo. (Local equivalent, proven end-to-end:
   `python3 scripts/reset_cf1_demo.py --apply`.)

## Demo values
cred 185.220.101.182 · web 45.148.10.95 · exfil 193.32.162.157 · bot 23.129.64.218 ·
prompt 89.234.157.254 · dns 162.247.74.74 (C2 `c2tunnel-demo.net`, sink `c2sink-demo.soledrop.co`) ·
campaign 104.244.73.29 (JA3 `0a80f68631b6e8b4634dbc261e8ba60b`).

## Prereqs / caveats
- Bind the same connections the CF-* need (Cloudflare, Slack, SentinelOne Mgmt + Unified Alerts,
  VirusTotal, AbuseIPDB). Runtime success of the Cloudflare acts depends on the bound Cloudflare
  connection's credential scope (validated here with a token holding Zone WAF/Rulesets + DNS +
  account Gateway; Intel/Get-IP-Overview is 403 and was intentionally left out).
- **Under-Attack mode is zone-wide** — it challenges every soledrop.co visitor until CF1-Reset-Demo
  (or reset script) reverts it.
- These playbooks hardcode the soledrop.co lab IDs (zone/account/ruleset); they are demo/console
  tools and are not exposed in the self-service wizard.
