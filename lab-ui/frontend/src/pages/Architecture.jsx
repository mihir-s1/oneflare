import { useState, useEffect } from 'react'
import {
  ArrowRight, Server, Shield, Database, Globe, Cpu, AlertCircle,
  ChevronDown, ChevronUp, Copy, Check, Info, FileCode, Download, CheckCircle,
} from 'lucide-react'
import { SCENARIOS } from '../data/scenarios.js'
import Badge from '../components/Badge.jsx'
import { getMe, dnsAllowed } from '../lib/session.js'

// ── Detections inner content ────────────────────────────────────────────────

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
      className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg border transition-all duration-200 shrink-0
        border-purple-500/30 text-purple-400 bg-purple-500/5 hover:bg-purple-500/15 hover:border-purple-400/40"
    >
      {copied ? (
        <><Check className="w-3.5 h-3.5 text-green-400" /><span className="text-green-400">Copied!</span></>
      ) : (
        <><Copy className="w-3.5 h-3.5" />Copy Rule</>
      )}
    </button>
  )
}

const DETECTION_CATEGORY_COLORS = {
  WAF:     'border-orange-500/20 bg-orange-500/5',
  Access:  'border-purple-500/20 bg-purple-500/5',
  Gateway: 'border-blue-500/20 bg-blue-500/5',
  Workers: 'border-red-500/20 bg-red-500/5',
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
  const visibleScenarios = SCENARIOS.filter(s => s.id !== 'dns' || allowDns)

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4 flex gap-3">
        <Info className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-semibold text-blue-300 mb-1">SentinelOne STAR Rules</p>
          <p className="text-sm text-slate-400 leading-relaxed">
            Paste these into the <strong className="text-slate-300">Custom STAR Rules editor</strong> in your S1 console
            to enable real-time detection and automated response against Cloudflare log events flowing via Logpush.
          </p>
        </div>
      </div>

      <div className="space-y-4">
        {visibleScenarios.map(scenario => (
          <div
            key={scenario.id}
            className={`rounded-xl border p-5 transition-all duration-200 hover:-translate-y-0.5 ${DETECTION_CATEGORY_COLORS[scenario.category] || 'border-[#2d1b4e] bg-[#1a0a2e]'}`}
          >
            <div className="flex items-start justify-between gap-3 mb-4 flex-wrap">
              <div className="flex items-center gap-3 flex-wrap">
                <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-white/5 border border-white/10 font-mono text-xs font-bold text-slate-400">
                  {scenario.number}
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-base font-semibold text-slate-100">{scenario.title}</h3>
                  </div>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    <Badge type="category" value={scenario.category} />
                    <Badge type="severity" value={scenario.siemSeverity} />
                    <span className="text-xs text-slate-500">{scenario.siemTactic}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-500 hidden sm:inline">{scenario.detectionRule}</span>
                <DetectionCopyButton text={scenario.siemLogic} />
              </div>
            </div>
            <pre
              className="text-xs leading-relaxed overflow-x-auto rounded-lg p-3 whitespace-pre-wrap"
              style={{
                background: '#0a0a14',
                border: '1px solid #1e1235',
                fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                color: '#c4b5fd',
              }}
            >
              <code>{scenario.siemLogic}</code>
            </pre>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Parsers inner content ───────────────────────────────────────────────────

const PARSER_DATASETS = [
  { name: 'Audit Logs V2',                predicate: 'AuditLogID && ActionTimestamp',    ocsf: 'Entity Management (3004)',                    category: 'Identity & Access Mgmt' },
  { name: 'Audit Logs (v1)',               predicate: 'ID && When',                        ocsf: 'Entity Management (3004)',                    category: 'Identity & Access Mgmt' },
  { name: 'Access Requests',              predicate: 'UserUID && CreatedAt',              ocsf: 'User Access Management (3005)',               category: 'Identity & Access Mgmt' },
  { name: 'HTTP Requests',                predicate: 'ClientRequestMethod && EdgeStartTimestamp', ocsf: 'HTTP Activity (4002)',               category: 'Network Activity' },
  { name: 'Firewall Events',              predicate: 'RuleID && Kind',                    ocsf: 'HTTP Activity (4002)',                        category: 'Network Activity' },
  { name: 'Gateway HTTP',                 predicate: 'HTTPHost && Datetime',              ocsf: 'HTTP Activity (4002)',                        category: 'Network Activity' },
  { name: 'Gateway DNS',                  predicate: 'QueryName && Datetime',             ocsf: 'DNS Activity (4003)',                         category: 'Network Activity' },
  { name: 'DNS Logs (Logpush)',           predicate: 'QueryName && Timestamp',            ocsf: 'DNS Activity (4003)',                         category: 'Network Activity' },
  { name: 'Gateway Network',             predicate: 'SNI && Datetime',                   ocsf: 'Network Activity (4001)',                     category: 'Network Activity' },
  { name: 'Network Analytics Logs',      predicate: 'AttackVector && Datetime',          ocsf: 'Network Activity (4001)',                     category: 'Network Activity' },
  { name: 'Zero Trust Network Sessions', predicate: 'EgressIP && SessionStartTime',      ocsf: 'Network Activity (4001)',                     category: 'Network Activity' },
  { name: 'Spectrum Events',             predicate: 'Event && Timestamp',                ocsf: 'Network Activity (4001)',                     category: 'Network Activity' },
  { name: 'SSH Logs',                    predicate: 'PTY && Datetime',                   ocsf: 'SSH Activity (4007)',                         category: 'Network Activity' },
  { name: 'Email Security Alerts',       predicate: 'From && Timestamp',                 ocsf: 'Email Activity (4009)',                       category: 'Network Activity' },
  { name: 'Device Posture Results',      predicate: 'PostureCheckName && Timestamp',     ocsf: 'App Security Posture Finding (2007)',         category: 'Findings' },
  { name: 'DLP Forensic Copies',         predicate: 'ForensicCopyID && Datetime',        ocsf: 'Data Security Finding (2006)',                category: 'Findings' },
  { name: 'CASB Findings',              predicate: 'AssetLink && DetectedTimestamp',     ocsf: 'Data Security Finding (2006)',                category: 'Findings' },
]

const PARSER_FIXES = [
  { field: 'SSH', detail: 'metadata.profiles[a] → metadata.profiles[0] — invalid literal index' },
  { field: 'Gateway HTTP', detail: 'SourcePort was mapped to dst_endpoint.port — corrected to src_endpoint.port' },
  { field: 'Gateway DNS', detail: 'QueryName in predicate but unmapped — added rename to query.hostname' },
  { field: 'Gateway DNS', detail: 'Duplicate DeviceName / device.type_id mappings removed' },
  { field: 'Network Analytics', detail: 'rename-from-already-mapped field replaced with copy+rename from unmapped.IPDestinationAddress' },
  { field: 'Spectrum', detail: "observables[1].name was 'src_endpoint.ip' — corrected to 'dst_endpoint.ip'" },
]

const PARSER_CATEGORY_COLORS = {
  'Identity & Access Mgmt': 'text-purple-400 bg-purple-500/10 border-purple-500/20',
  'Network Activity':        'text-blue-400   bg-blue-500/10   border-blue-500/20',
  'Findings':                'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
}

function ParserDatasetTable() {
  const [open, setOpen] = useState(true)
  return (
    <div className="collapsible-section">
      <div className="collapsible-header" onClick={() => setOpen(!open)}>
        <span className="text-sm font-semibold text-slate-200">Covered Datasets ({PARSER_DATASETS.length})</span>
        {open ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
      </div>
      {open && (
        <div className="collapsible-body overflow-x-auto p-0">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-white/5">
                <th className="text-left py-2 px-3 text-slate-400 font-semibold uppercase tracking-wider">Dataset</th>
                <th className="text-left py-2 px-3 text-slate-400 font-semibold uppercase tracking-wider">Predicate Fields</th>
                <th className="text-left py-2 px-3 text-slate-400 font-semibold uppercase tracking-wider">OCSF Class</th>
                <th className="text-left py-2 px-3 text-slate-400 font-semibold uppercase tracking-wider">Category</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {PARSER_DATASETS.map((d) => (
                <tr key={d.name} className="hover:bg-white/3 transition-colors">
                  <td className="py-2 px-3 font-medium text-slate-200">{d.name}</td>
                  <td className="py-2 px-3 font-mono text-slate-400">{d.predicate}</td>
                  <td className="py-2 px-3 text-slate-300">{d.ocsf}</td>
                  <td className="py-2 px-3">
                    <span className={`inline-block px-2 py-0.5 rounded border text-xs font-medium ${PARSER_CATEGORY_COLORS[d.category] || 'text-slate-400'}`}>
                      {d.category}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function ParserFixesList() {
  const [open, setOpen] = useState(false)
  return (
    <div className="collapsible-section">
      <div className="collapsible-header" onClick={() => setOpen(!open)}>
        <span className="text-sm font-semibold text-slate-200">Bug Fixes vs Upstream ({PARSER_FIXES.length})</span>
        {open ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
      </div>
      {open && (
        <div className="collapsible-body">
          <ul className="space-y-2 px-1">
            {PARSER_FIXES.map((f, i) => (
              <li key={i} className="flex gap-3 text-xs">
                <span className="shrink-0 px-1.5 py-0.5 rounded bg-orange-500/10 border border-orange-500/20 text-orange-400 font-semibold">
                  {f.field}
                </span>
                <span className="text-slate-400 leading-relaxed">{f.detail}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function ParsersContent() {
  const [parserContent, setParserContent] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [copied, setCopied] = useState(false)

  function copyParser() {
    if (!parserContent) return
    navigator.clipboard.writeText(parserContent).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  async function loadParser() {
    if (parserContent) return
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/parsers/cloudflare-ocsf-parser/cloudflare-ocsf-parser.conf')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const text = await res.text()
      setParserContent(text)
    } catch {
      setError('Could not load parser file — ensure the lab backend is running.')
    } finally {
      setLoading(false)
    }
  }

  function downloadParser() {
    if (!parserContent) return
    const blob = new Blob([parserContent], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'cloudflare-ocsf-parser.conf'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-4">
      {/* Parser card header */}
      <div className="rounded-2xl border border-white/10 bg-white/3 overflow-hidden">
        <div className="flex items-start justify-between gap-4 p-5 border-b border-white/5">
          <div className="flex items-start gap-4">
            <div className="w-10 h-10 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center shrink-0">
              <FileCode className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100">cloudflare-ocsf-parser</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                OCSF 1.6.0 · SentinelOne AI SIEM · {PARSER_DATASETS.length} datasets · v1.0.0
              </p>
              <div className="flex flex-wrap gap-1.5 mt-2">
                {['Identity & Access Mgmt', 'Network Activity', 'Findings'].map(cat => (
                  <span key={cat} className={`inline-block px-2 py-0.5 rounded border text-xs font-medium ${PARSER_CATEGORY_COLORS[cat]}`}>
                    {cat}
                  </span>
                ))}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {parserContent && (
              <>
                <button onClick={downloadParser} className="btn-ghost text-xs">
                  <Download className="w-3.5 h-3.5" />
                  Download
                </button>
                <button
                  onClick={copyParser}
                  className={`btn-ghost text-xs transition-colors ${copied ? 'text-green-400' : ''}`}
                >
                  {copied
                    ? <><CheckCircle className="w-3.5 h-3.5" /> Copied!</>
                    : <><Copy className="w-3.5 h-3.5" /> Copy</>
                  }
                </button>
              </>
            )}
            {!parserContent && (
              <button
                onClick={loadParser}
                disabled={loading}
                className="btn-ghost text-xs disabled:opacity-40"
              >
                {loading
                  ? <span className="flex items-center gap-1.5"><span className="w-3 h-3 border border-slate-400 border-t-transparent rounded-full animate-spin" /> Loading...</span>
                  : 'Load Parser'
                }
              </button>
            )}
          </div>
        </div>

        <div className="px-5 py-3 bg-blue-500/5 border-b border-blue-500/10 flex gap-2 text-xs text-slate-400">
          <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
          <span>
            Import this <span className="font-mono text-slate-300">.conf</span> file into SentinelOne AI SIEM under{' '}
            <span className="text-slate-300">Settings → Parsers → Import Parser</span>. The parser auto-detects Cloudflare
            datasets by predicate field matching and maps each to the correct OCSF class.
          </span>
        </div>

        <div className="p-5 space-y-4">
          <ParserDatasetTable />
          <ParserFixesList />

          {!parserContent && !loading && !error && (
            <div
              onClick={loadParser}
              className="rounded-xl border border-dashed border-white/10 bg-black/20 p-8 flex flex-col items-center justify-center gap-3 cursor-pointer hover:border-orange-500/30 hover:bg-orange-500/5 transition-all group"
            >
              <FileCode className="w-8 h-8 text-slate-600 group-hover:text-orange-400 transition-colors" />
              <p className="text-sm text-slate-500 group-hover:text-slate-300 transition-colors">
                Click to load and preview parser
              </p>
            </div>
          )}

          {error && (
            <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">
              {error}
            </div>
          )}

          {parserContent && (
            <div className="relative">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Parser Content</span>
                <button
                  onClick={copyParser}
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
              <pre className="terminal-scroll bg-black/40 border border-white/5 rounded-xl p-4 text-xs font-mono text-slate-300 overflow-auto max-h-[500px] leading-relaxed whitespace-pre-wrap">
                {parserContent}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Architecture page ────────────────────────────────────────────────────────

const WORKERS = [
  {
    name: 'Shop Worker',
    description: 'AcmeCorp webstore — WAF attack surface',
    url: 'https://acmecorp-shop.acmecorp-lab.workers.dev',
    routes: ['/search', '/products', '/reviews'],
    color: 'orange',
    borderClass: 'border-orange-500/30',
    bgClass: 'bg-orange-500/5',
    textClass: 'text-orange-400',
  },
  {
    name: 'Portal Worker',
    description: 'Cloudflare Access-protected admin portal',
    url: 'https://acmecorp-portal.acmecorp-lab.workers.dev',
    routes: ['/login', '/dashboard'],
    color: 'purple',
    borderClass: 'border-purple-500/30',
    bgClass: 'bg-purple-500/5',
    textClass: 'text-purple-400',
  },
  {
    name: 'API Worker',
    description: 'REST API with bulk export endpoint',
    url: 'https://acmecorp-api.acmecorp-lab.workers.dev',
    routes: ['/api/v1/auth/login', '/api/v1/customers/export'],
    color: 'blue',
    borderClass: 'border-blue-500/30',
    bgClass: 'bg-blue-500/5',
    textClass: 'text-blue-400',
  },
  {
    name: 'SoleDrop Shop',
    description: 'Standalone sneaker-drop shop — the OneFlare CTF target. Self-contained Worker with its own /api/incident + KV; attacks flip /status and degrade checkout/admin.',
    url: 'https://shop.soledrop.co',
    routes: ['/', '/products', '/status', '/login', '/dashboard', '/admin', '/api/v1/products', '/api/v1/cart', '/api/v1/checkout', '/api/v1/customers', '/api/v1/chat', '/api/incident'],
    color: 'red',
    borderClass: 'border-red-500/30',
    bgClass: 'bg-red-500/5',
    textClass: 'text-red-400',
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
              desc: 'Python script sends malicious HTTP requests or DNS queries to the target AcmeCorp Worker endpoint',
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
          <h2 className="text-sm font-semibold text-slate-300">AcmeCorp Lab Workers</h2>
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

      {/* Logpush note */}
      <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4 flex gap-3">
        <AlertCircle className="w-5 h-5 text-yellow-400 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-semibold text-yellow-300 mb-1">Logpush Configuration Required</p>
          <p className="text-sm text-slate-400 leading-relaxed">
            For detections to flow from Cloudflare to SentinelOne, configure a Logpush job in your Cloudflare dashboard:
            <strong className="text-slate-300"> Analytics → Logpush → Create job</strong>. Select HTTP Requests, Firewall Events, Gateway DNS, and Access Audit logs. Set the destination to your SentinelOne HTTP input endpoint.
          </p>
        </div>
      </div>

      {/* Detections collapsible */}
      <ArchCollapsible title="Detections — STAR Rules" icon={Shield}>
        <DetectionsContent />
      </ArchCollapsible>

      {/* Parsers collapsible */}
      <ArchCollapsible title="Parsers — OCSF Ingest Configs" icon={FileCode}>
        <ParsersContent />
      </ArchCollapsible>
    </div>
  )
}
