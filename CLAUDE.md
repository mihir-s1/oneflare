# OneFlare — Cloudflare + SentinelOne Full Story Lab

## Project Overview

A mock company ("AcmeCorp") deployed across Cloudflare that serves as a detection engineering and SOC automation lab. The goal is a complete, demo-ready story:

```
Attack simulation scripts
        ↓
Cloudflare (WAF / Gateway / Access / Workers)
        ↓
Logpush → SentinelOne
        ↓
SentinelOne Detections (STAR Rules)
        ↓
Hyperautomation Workflows (Cloudflare actions)
```

## Mock Company Infrastructure ("AcmeCorp")

| Component | Cloudflare Product | Purpose |
|---|---|---|
| `shop.acmecorp.dev` | Workers + WAF | Public webstore — product pages, search, login, checkout |
| `portal.acmecorp.dev` | Workers + Access (ZTNA) | Employee portal — protected by Cloudflare Access |
| `api.acmecorp.dev` | Workers + WAF | Internal REST API gateway |

All three are deployed as Cloudflare Workers sites, protected by WAF rules, and route through Cloudflare Gateway for Zero Trust DNS/HTTP filtering.

## Attack Scenarios

### 1. Web Application Attacks (WAF)
Targets `shop.acmecorp.dev`. Scripts simulate:
- SQL injection on `/search?q=`
- XSS on product review forms
- Path traversal on asset endpoints
- LFI attempts on Workers routes

**Logs generated**: WAF logs (`RayID`, `ClientIP`, `Action`, `RuleID`, `MatchedData`)

### 2. Credential Attacks (Access / ZTNA)
Targets `portal.acmecorp.dev`. Scripts simulate:
- Credential stuffing (many users, fast)
- Brute force (one user, many passwords)
- Impossible travel (same user, two distant IPs in short window)

**Logs generated**: Access audit logs, Zero Trust failed login events

### 3. DNS Tunneling / C2 Beaconing (Gateway)
Simulated via scripts that generate:
- High-frequency DNS queries to algorithmically generated subdomains
- Regular beaconing intervals (mimicking C2 check-ins)
- Long subdomain labels (data-in-DNS exfil pattern)

**Logs generated**: Gateway DNS logs (`QueryName`, `QueryType`, `ResolvedIPs`, `Policy`)

### 4. Data Exfiltration (Workers)
Targets `api.acmecorp.dev`. Scripts simulate:
- Bulk data pull via authenticated API (large response bodies)
- Unexpected endpoint enumeration
- High-volume requests to `/export` or `/download` routes

**Logs generated**: Workers logs, HTTP response size anomalies

## Logpush → SentinelOne
Already configured. Datasets flowing:
- HTTP Request logs
- Firewall Events
- Gateway DNS logs
- Access logs (Audit)

## Agents Available
All 26 agents (10 CoralCollective + 16 GSD) are in `.claude/agents/`.

Key agents for this project:
- `security` — detection rule writing, attack simulation review
- `devops` — Wrangler/CLI deployment of Workers
- `backend` — Workers source code
- `architect` — story design and integration architecture
- `technical-writer` — runbook and demo script authoring

## Claude Working Instructions

### 1. Plan First Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately — don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy
- Use subagents liberally to keep the main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

### 3. Self-Improvement Loop
- After ANY correction from the user: update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant context

### 4. Verification Before Done
- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this?"
- Run tests, check logs, demonstrate correctness

### 5. Demand Elegance (Balanced)
- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes — don't over-engineer
- Challenge your own work before presenting it

### 6. Autonomous Bug Fixing
- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests — then resolve them
- Zero context switching required from the user
- Fix failing CI tests without being told how

## Task Management

Use `tasks/todo.md` with checkable items for all work tracking.

### Workflow
1. **Plan First** — write plan to `tasks/todo.md`
2. **Verify Plan** — check in before starting implementation
3. **Track Progress** — mark items complete as you go
4. **Explain Changes** — high-level summary at each step
5. **Document Results** — add review section to `tasks/todo.md`
6. **Capture Lessons** — update `tasks/lessons.md` after corrections

## Core Principles
- **Simplicity First** — make every change as simple as possible, impact minimal code
- **No Laziness** — find root causes, no temporary fixes, senior developer standards
