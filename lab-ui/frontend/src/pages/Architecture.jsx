import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight, Server, Shield, Database, Globe, Cpu,
  ChevronDown, ChevronUp, Copy, Check, Info, FileCode, CheckCircle,
  LayoutDashboard, Workflow, Plug, Terminal as TerminalIcon,
} from 'lucide-react'
import { SCENARIOS } from '../data/scenarios.js'
import { DETECTIONS, HA_WORKFLOWS, DASHBOARDS } from '../data/knowledgeObjects.js'
import Badge from '../components/Badge.jsx'
import DeployKnowledgeObjects from '../components/DeployKnowledgeObjects.jsx'
import { getMe, dnsAllowed } from '../lib/session.js'

// ── Detections inner content ────────────────────────────────────────────────
// Renders straight from knowledgeObjects.DETECTIONS — the ACTUAL deployed rule
// JSON — so what this card shows is exactly what deploys to the console.

function DetectionCopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(text).then(() => {
          setCopied(true)
          setTimeout(() => setCopied(false), 2000)
        })
      }}
      className="flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-lg border transition-all duration-200 shrink-0
        border-purple-500/30 text-purple-400 bg-purple-500/5 hover:bg-purple-500/15 hover:border-purple-400/40"
    >
      {copied ? (
        <><Check className="w-3.5 h-3.5 text-green-400" /><span className="text-green-400">Copied!</span></>
      ) : (
        <><Copy className="w-3.5 h-3.5" />Copy</>
      )}
    </button>
  )
}

function DetectionCard({ detection }) {
  const [open, setOpen] = useState(false)
  const scenario = SCENARIOS.find(s => s.id === detection.scenarioId)

  return (
    <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] p-4 transition-all duration-200 hover:-translate-y-0.5">
      <div className="flex items-start justify-between gap-3 flex-wrap mb-2">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-slate-100 leading-snug">{detection.name}</h3>
          {scenario && (
            <Link
              to={`/scenarios/${scenario.id}`}
              className="text-xs text-orange-400 hover:underline inline-flex items-center gap-1 mt-1"
            >
              {scenario.number} · {scenario.title}
            </Link>
          )}
        </div>
        <Badge type="severity" value={detection.severity} />
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 font-mono mb-3">
        <span className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-slate-400">
          {detection.queryType}
        </span>
        {detection.runIntervalMinutes != null && (
          <span>runs every {detection.runIntervalMinutes}m</span>
        )}
        {detection.lookbackWindowMinutes != null && (
          <span>· lookback {detection.lookbackWindowMinutes}m</span>
        )}
      </div>

      <div
        className="collapsible-header !p-2.5 !rounded-lg border border-[#2d1b4e]"
        onClick={() => setOpen(o => !o)}
        role="button"
        tabIndex={0}
        onKeyDown={e => e.key === 'Enter' && setOpen(o => !o)}
        aria-expanded={open}
      >
        <span className="text-xs font-semibold text-slate-300 flex items-center gap-2">
          <TerminalIcon className="w-3.5 h-3.5 text-purple-400" />
          PowerQuery
        </span>
        {open ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
      </div>

      {open && (
        <div className="mt-2">
          <div className="flex justify-end mb-1.5">
            <DetectionCopyButton text={detection.query} />
          </div>
          <pre
            className="text-xs leading-relaxed overflow-auto rounded-lg p-3 whitespace-pre-wrap max-h-72"
            style={{
              background: '#0a0a14',
              border: '1px solid #1e1235',
              fontFamily: '"JetBrains Mono", "Fira Code", monospace',
              color: '#c4b5fd',
            }}
          >
            <code>{detection.query}</code>
          </pre>
        </div>
      )}
    </div>
  )
}

function DetectionsContent() {
  const [allowDns, setAllowDns] = useState(false)
  useEffect(() => {
    let alive = true
    Promise.all([getMe(), fetch('/api/config').then(r => (r.ok ? r.json() : null)).catch(() => null)])
      .then(([me, cfg]) => {
        if (alive) setAllowDns(dnsAllowed({ adminEnabled: !!cfg?.admin_enabled, role: me?.role }))
      })
    return () => { alive = false }
  }, [])
  const visibleDetections = DETECTIONS.filter(d => d.scenarioId !== 'dns' || allowDns)

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4 flex gap-3">
        <Info className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-semibold text-blue-300 mb-1">SentinelOne STAR Rules</p>
          <p className="text-sm text-slate-400 leading-relaxed">
            Every rule below is deployed as a Scheduled detection against the SDL. Paste the PowerQuery into{' '}
            <strong className="text-slate-300">SentinelOne → Detection → Custom Rules</strong>, or use the
            Deploy button above to push it directly to your own console.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-start">
        {visibleDetections.map(detection => (
          <DetectionCard key={detection.key} detection={detection} />
        ))}
      </div>
    </div>
  )
}

// ── Hyperautomation inner content ───────────────────────────────────────────
// Compact index over knowledgeObjects.HA_WORKFLOWS. The full block diagram +
// copyable workflow JSON live on each scenario's Response Playbook tab —
// this section only points there, it never re-embeds the JSON.

function HaWorkflowCard({ workflow }) {
  const scenarios = workflow.scenarioIds.map(id => SCENARIOS.find(s => s.id === id)).filter(Boolean)
  const firstScenario = scenarios[0]

  return (
    <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] p-4 transition-all duration-200 hover:-translate-y-0.5">
      <div className="mb-2">
        <h3 className="text-sm font-semibold text-slate-100 leading-snug">{workflow.name}</h3>
        <p className="text-xs text-slate-400 mt-0.5">{workflow.detail}</p>
      </div>

      <div className="flex flex-wrap gap-1.5 mb-3">
        {scenarios.map(s => (
          <Link
            key={s.id}
            to={`/scenarios/${s.id}`}
            className="text-xs font-mono text-orange-400 bg-orange-500/5 border border-orange-500/20 rounded px-2 py-0.5 hover:bg-orange-500/15 transition-colors"
          >
            {s.number} · {s.title}
          </Link>
        ))}
      </div>

      <div className="flex items-center gap-1.5 flex-wrap mb-3">
        <Plug className="w-3.5 h-3.5 text-blue-400 shrink-0" />
        {workflow.connections.map(c => (
          <span
            key={c}
            className="inline-flex items-center rounded-full border border-[#2d1b4e] bg-white/5 px-2.5 py-0.5 text-xs font-mono text-slate-300"
          >
            {c}
          </span>
        ))}
      </div>

      {firstScenario && (
        <p className="text-xs text-slate-500 leading-relaxed">
          Full block diagram + copyable JSON on{' '}
          <Link to={`/scenarios/${firstScenario.id}?tab=playbook`} className="text-orange-400 hover:underline">
            {firstScenario.title}'s Response Playbook tab
          </Link>.
        </p>
      )}
    </div>
  )
}

function HyperautomationContent() {
  const [allowDns, setAllowDns] = useState(false)
  useEffect(() => {
    let alive = true
    Promise.all([getMe(), fetch('/api/config').then(r => (r.ok ? r.json() : null)).catch(() => null)])
      .then(([me, cfg]) => {
        if (alive) setAllowDns(dnsAllowed({ adminEnabled: !!cfg?.admin_enabled, role: me?.role }))
      })
    return () => { alive = false }
  }, [])
  const visibleWorkflows = HA_WORKFLOWS.filter(w => !w.scenarioIds.includes('dns') || allowDns)

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4 flex gap-3">
        <Info className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-semibold text-blue-300 mb-1">SentinelOne Hyperautomation</p>
          <p className="text-sm text-slate-400 leading-relaxed">
            Response workflows that fire off the STAR detections above — IP enrichment, Cloudflare block
            rules, PCAP capture, and SOC notification. Import into{' '}
            <strong className="text-slate-300">Hyperautomation → Workflows → Import</strong>, bind the
            connections, then activate.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-start">
        {visibleWorkflows.map(workflow => (
          <HaWorkflowCard key={workflow.key} workflow={workflow} />
        ))}
      </div>
    </div>
  )
}

// ── Dashboards inner content ────────────────────────────────────────────────
// Sourced from knowledgeObjects.DASHBOARDS (same JSON the Deploy wizard pushes).
// Per-tab "what it shows" copy is curated commentary, kept local since the
// dashboard JSON itself only carries tab names, not prose descriptions.

const DASHBOARD_TAB_SUMMARIES = {
  'threat-detection': {
    'Threat Overview': 'KPI row (requests, WAF blocks, likely attacks, attacker IPs, DNS queries, countries), requests-over-time by response class, attack-type donut, top attacker IPs / countries, WAF-block detail.',
    'Web App Attacks (WAF)': 'SQLi / XSS / traversal-RCE tables ranked by WAF ML score, attacked-hosts donut. Flags near-certain attacks (score ≤ 20), including ones that returned 200.',
    'Credential Attacks': '/login attempts over time by status, failed-login KPIs, failed-logins-by-source-IP — credential stuffing / brute force surfaced via 401/403/429.',
    'DNS & C2 (Gateway)': 'Query volume, query-type donut, and the tunneling/DGA signal — query names whose leftmost label exceeds 25 chars.',
    'Exfil, Bots & AI': 'Bulk /export volume + response bytes, top API data pulls, the polymorphic-bot tell (one source IP, many User-Agents), and prompt-injection POSTs to /api/v1/chat.',
  },
  'ingestion-inventory': {
    'Ingestion Inventory': 'One row per Data Source × Logpush dataset × OCSF class landing in the SDL — vendor, dataset, OCSF class + UID, parser, event count, first/last seen, sorted by volume. Confirms every Cloudflare Logpush source is arriving and correctly parsed to OCSF.',
  },
}

function DashboardCard({ entry }) {
  const [codeOpen, setCodeOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const pretty = JSON.stringify(entry.dashboard, null, 2)
  const tabs = (entry.dashboard.tabs || []).map(t => ({
    name: t.tabName,
    summary: DASHBOARD_TAB_SUMMARIES[entry.key]?.[t.tabName] || '',
  }))

  function copyJson() {
    navigator.clipboard.writeText(pretty).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div className="rounded-2xl border border-white/10 bg-white/3 overflow-hidden">
      <div className="p-5 border-b border-white/5">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-start gap-4">
            <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center shrink-0">
              <LayoutDashboard className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100">{entry.name}</h3>
              <p className="text-xs text-slate-400 mt-0.5 font-mono">
                SDL Dashboard · {entry.dashboard.duration} window · {tabs.length} tab{tabs.length > 1 ? 's' : ''}
              </p>
            </div>
          </div>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed mt-3">{entry.description}</p>
      </div>

      {/* What it shows */}
      <div className="p-5 border-b border-white/5 space-y-2.5">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">What it shows</span>
        <ul className="space-y-2">
          {tabs.map(tab => (
            <li key={tab.name} className="flex gap-2.5 items-start text-xs">
              <span className="shrink-0 mt-0.5 px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-300 font-semibold whitespace-nowrap">
                {tab.name}
              </span>
              <span className="text-slate-400 leading-relaxed">{tab.summary}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* How to import */}
      <div className="px-5 py-3 bg-blue-500/5 border-b border-blue-500/10 flex gap-2 text-xs text-slate-400">
        <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <span>
          <strong className="text-slate-300">How to import:</strong> SentinelOne console →{' '}
          <span className="text-slate-300">Dashboards → Import Dashboard</span>, paste the JSON below. Or deploy
          directly via the SDL API: <span className="font-mono text-slate-300">sdl_put_file</span> to{' '}
          <span className="font-mono text-slate-300">{entry.deployPath}</span>.
        </span>
      </div>

      {/* Collapsible JSON panel */}
      <div className="p-5">
        <div
          className="collapsible-header !p-3 !rounded-lg border border-[#2d1b4e]"
          onClick={() => setCodeOpen(o => !o)}
          role="button"
          tabIndex={0}
          onKeyDown={e => e.key === 'Enter' && setCodeOpen(o => !o)}
          aria-expanded={codeOpen}
        >
          <span className="text-sm font-semibold text-slate-200 flex items-center gap-2">
            <FileCode className="w-4 h-4 text-orange-400" />
            {entry.key}.dashboard.json
          </span>
          {codeOpen ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
        </div>

        {codeOpen && (
          <div className="relative mt-2">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Dashboard JSON</span>
              <button
                onClick={copyJson}
                className={`flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg border transition-all ${
                  copied
                    ? 'border-green-500/30 bg-green-500/10 text-green-400'
                    : 'border-white/10 bg-white/5 text-slate-400 hover:text-slate-200 hover:bg-white/10'
                }`}
              >
                {copied ? <CheckCircle className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <pre className="terminal-scroll bg-black/40 border border-white/5 rounded-xl p-4 text-xs font-mono text-slate-300 overflow-auto max-h-[500px] leading-relaxed">
              {pretty}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

function DashboardsContent() {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4 flex gap-3">
        <Info className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-semibold text-blue-300 mb-1">SentinelOne SDL Dashboards</p>
          <p className="text-sm text-slate-400 leading-relaxed">
            Ready-to-import Singularity Data Lake dashboards, built against the Cloudflare Logpush feed already
            parsed to OCSF in the SDL. Every panel is a live PowerQuery — no synthetic values.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 items-start">
        {DASHBOARDS.map(entry => (
          <DashboardCard key={entry.key} entry={entry} />
        ))}
      </div>
    </div>
  )
}

// ── Architecture page ────────────────────────────────────────────────────────

const WORKERS = [
  {
    name: 'SoleDrop Shop Worker',
    description: 'Single Worker serving every attack surface — web, API, and portal — at your per-user subdomain <name>.lab.soledrop.co. Self-contained with its own /api/incident + KV; attacks flip /status and degrade checkout/admin.',
    url: 'https://shop-soledrop-worker.workers.dev',
    routes: ['/search', '/products', '/reviews', '/login', '/dashboard', '/admin', '/api/v1/auth/login', '/api/v1/customers/export', '/api/v1/cart', '/api/v1/checkout', '/api/v1/chat', '/api/incident', '/status'],
    color: 'red',
    borderClass: 'border-red-500/30',
    bgClass: 'bg-red-500/5',
    textClass: 'text-red-400',
  },
  {
    name: 'Gateway DNS (admin-only)',
    description: 'Shared Cloudflare Gateway DoH resolver used by the DNS tunneling / C2 beaconing scenario. Admin-only — not scoped per-user like the shop Worker.',
    url: 'https://one.dash.cloudflare.com',
    routes: ['DNS over HTTPS query endpoint'],
    color: 'blue',
    borderClass: 'border-blue-500/30',
    bgClass: 'bg-blue-500/5',
    textClass: 'text-blue-400',
  },
]

const FLOW_NODES = [
  {
    label: 'Attack Scripts',
    sublabel: 'Python / FastAPI',
    items: ['demo.py', '01_sqli.py', '02_xss.py', '03_path_traversal.py', '04_cred_stuffing.py', '05_dns_tunnel.py', '06_data_exfil.py'],
    icon: Cpu,
    color: 'text-slate-400',
    borderClass: 'border-slate-600/40',
    bgClass: 'bg-slate-800/40',
    dotColor: 'bg-slate-500',
  },
  {
    label: 'Cloudflare',
    sublabel: 'Security Stack',
    items: ['WAF / Firewall Rules', 'Gateway (DNS)', 'Access (ZTNA)', 'Workers (Apps)', 'Logpush → SIEM'],
    icon: Shield,
    color: 'text-orange-400',
    borderClass: 'border-orange-500/30',
    bgClass: 'bg-orange-500/5',
    dotColor: 'bg-orange-400',
  },
  {
    label: 'SentinelOne',
    sublabel: 'Detection & Response',
    items: ['Logpush Ingestion', 'STAR Detections', 'Hyperautomation', 'CF API Actions', 'Incident Stories'],
    icon: Database,
    color: 'text-purple-400',
    borderClass: 'border-purple-500/30',
    bgClass: 'bg-purple-500/5',
    dotColor: 'bg-purple-400',
  },
]

function ArchCollapsible({ title, icon: Icon, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="collapsible-section">
      <div className="collapsible-header" onClick={() => setOpen(!open)}>
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-white/5 flex items-center justify-center">
            <Icon className="w-4 h-4 text-orange-400" />
          </div>
          <span className="text-sm font-semibold text-slate-200">{title}</span>
        </div>
        {open
          ? <ChevronUp className="w-4 h-4 text-slate-400" />
          : <ChevronDown className="w-4 h-4 text-slate-400" />
        }
      </div>
      {open && <div className="collapsible-body">{children}</div>}
    </div>
  )
}

export default function Architecture() {
  return (
    <div className="page-enter space-y-8 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Lab Architecture</h1>
        <p className="text-sm text-slate-400 mt-1">
          How attack scripts, Cloudflare controls, and SentinelOne detections connect
        </p>
      </div>

      {/* Architecture diagram */}
      <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] p-6">
        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-6 flex items-center gap-2">
          <Globe className="w-4 h-4 text-orange-400" />
          Data Flow Diagram
        </h2>

        {/* Three column layout with arrows */}
        <div className="flex flex-col md:flex-row items-stretch gap-0">
          {FLOW_NODES.map((node, i) => {
            const Icon = node.icon
            return (
              <div key={node.label} className="flex md:flex-row items-center flex-1">
                {/* Node card */}
                <div className={`flex-1 rounded-xl border p-4 ${node.borderClass} ${node.bgClass}`}>
                  <div className="flex items-center gap-2 mb-3">
                    <Icon className={`w-4 h-4 ${node.color}`} />
                    <div>
                      <div className={`text-sm font-bold ${node.color}`}>{node.label}</div>
                      <div className="text-xs text-slate-500">{node.sublabel}</div>
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    {node.items.map((item, j) => (
                      <div key={j} className="flex items-center gap-2 text-xs text-slate-400">
                        <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${node.dotColor}`} />
                        <span className="font-mono">{item}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Arrow between nodes */}
                {i < FLOW_NODES.length - 1 && (
                  <div className="flex items-center justify-center shrink-0 px-3 py-6 md:py-0 md:px-4">
                    <div className="flex flex-col md:flex-row items-center gap-1">
                      <div className="hidden md:block h-px w-8 bg-gradient-to-r from-orange-500/50 to-purple-500/50" />
                      <ArrowRight className="w-5 h-5 text-slate-500 md:text-orange-500/60 rotate-90 md:rotate-0" />
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>

        {/* Flow labels below */}
        <div className="hidden md:grid grid-cols-[1fr_auto_1fr_auto_1fr] gap-0 mt-3">
          <div className="text-center">
            <span className="text-xs text-slate-600 font-mono">HTTP/DNS requests</span>
          </div>
          <div />
          <div className="text-center">
            <span className="text-xs text-slate-600 font-mono">Logpush → S1 (~60s)</span>
          </div>
          <div />
          <div className="text-center">
            <span className="text-xs text-slate-600 font-mono">STAR → Response</span>
          </div>
        </div>
      </div>

      {/* Detailed flow */}
      <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] p-6">
        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-5 flex items-center gap-2">
          <ArrowRight className="w-4 h-4 text-purple-400" />
          End-to-End Attack Flow
        </h2>

        <div className="space-y-0">
          {[
            {
              step: '01',
              title: 'Attack Script Executes',
              desc: 'Python script sends malicious HTTP requests or DNS queries to your per-user SoleDrop shop Worker (<name>.lab.soledrop.co)',
              color: 'text-slate-400',
              bg: 'bg-slate-500/10',
              border: 'border-slate-500/20',
            },
            {
              step: '02',
              title: 'Cloudflare Intercepts',
              desc: 'WAF, Gateway DNS, or Access evaluates the request. Matching rules block or log the traffic and emit a structured event',
              color: 'text-orange-400',
              bg: 'bg-orange-500/10',
              border: 'border-orange-500/20',
            },
            {
              step: '03',
              title: 'Logpush Streams Events',
              desc: 'Cloudflare Logpush sends JSON log events to SentinelOne in near real-time (typically within 60 seconds)',
              color: 'text-yellow-400',
              bg: 'bg-yellow-500/10',
              border: 'border-yellow-500/20',
            },
            {
              step: '04',
              title: 'STAR Rule Fires',
              desc: 'SentinelOne STAR engine evaluates incoming log events against custom detection rules. Threshold breaches create an alert',
              color: 'text-purple-400',
              bg: 'bg-purple-500/10',
              border: 'border-purple-500/20',
            },
            {
              step: '05',
              title: 'Hyperautomation Responds',
              desc: 'SentinelOne Hyperautomation playbook executes: enriches IP, creates block rules via CF API, captures PCAP, notifies SOC',
              color: 'text-green-400',
              bg: 'bg-green-500/10',
              border: 'border-green-500/20',
            },
          ].map((item, i, arr) => (
            <div key={item.step} className="flex gap-3">
              <div className="flex flex-col items-center shrink-0">
                <div className={`w-9 h-9 rounded-xl flex items-center justify-center text-xs font-mono font-bold border ${item.bg} ${item.border} ${item.color}`}>
                  {item.step}
                </div>
                {i < arr.length - 1 && (
                  <div className="w-px flex-1 bg-gradient-to-b from-[#2d1b4e] to-transparent min-h-[28px] my-1" />
                )}
              </div>
              <div className="flex-1 pt-1 pb-5">
                <div className={`text-sm font-semibold mb-1 ${item.color}`}>{item.title}</div>
                <p className="text-sm text-slate-400 leading-relaxed">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Workers table */}
      <div className="rounded-xl border border-[#2d1b4e] overflow-hidden">
        <div className="px-5 py-4 bg-[#1a0a2e] border-b border-[#2d1b4e] flex items-center gap-2">
          <Server className="w-4 h-4 text-orange-400" />
          <h2 className="text-sm font-semibold text-slate-300">Lab Workers</h2>
        </div>
        <div className="divide-y divide-[#1e1235]">
          {WORKERS.map(worker => (
            <div key={worker.name} className="p-5 hover:bg-white/[0.02] transition-colors">
              <div className="flex items-start gap-4 flex-wrap">
                <div className={`shrink-0 rounded-xl px-3 py-2 border text-xs font-bold font-mono ${worker.borderClass} ${worker.bgClass} ${worker.textClass}`}>
                  {worker.name}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-slate-300 mb-1">{worker.description}</div>
                  <a href={worker.url} target="_blank" rel="noopener noreferrer"
                    className={`text-xs font-mono ${worker.textClass} mb-2 hover:underline inline-block`}>
                    {worker.url}
                  </a>
                  <div className="flex flex-wrap gap-2">
                    {worker.routes.map(route => (
                      <span key={route} className="text-xs font-mono text-slate-500 bg-white/5 border border-white/10 rounded px-2 py-0.5">
                        {route}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Deploy entry point */}
      <DeployKnowledgeObjects />

      {/* Detections collapsible */}
      <ArchCollapsible title="Detections — STAR Rules" icon={Shield}>
        <DetectionsContent />
      </ArchCollapsible>

      {/* Hyperautomation collapsible */}
      <ArchCollapsible title="Hyperautomation — Response Workflows" icon={Workflow}>
        <HyperautomationContent />
      </ArchCollapsible>

      {/* Dashboards collapsible */}
      <ArchCollapsible title="Dashboards — SDL Console Imports" icon={LayoutDashboard}>
        <DashboardsContent />
      </ArchCollapsible>
    </div>
  )
}
