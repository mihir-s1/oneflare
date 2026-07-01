import { useState } from 'react'
import { Copy, CheckCircle, Download, FileCode, ChevronDown, ChevronUp, Info } from 'lucide-react'

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

const FIXES = [
  { field: 'SSH', detail: 'metadata.profiles[a] → metadata.profiles[0] — invalid literal index' },
  { field: 'Gateway HTTP', detail: 'SourcePort was mapped to dst_endpoint.port — corrected to src_endpoint.port' },
  { field: 'Gateway DNS', detail: 'QueryName in predicate but unmapped — added rename to query.hostname' },
  { field: 'Gateway DNS', detail: 'Duplicate DeviceName / device.type_id mappings removed' },
  { field: 'Network Analytics', detail: 'rename-from-already-mapped field replaced with copy+rename from unmapped.IPDestinationAddress' },
  { field: 'Spectrum', detail: "observables[1].name was 'src_endpoint.ip' — corrected to 'dst_endpoint.ip'" },
]

const CATEGORY_COLORS = {
  'Identity & Access Mgmt': 'text-purple-400 bg-purple-500/10 border-purple-500/20',
  'Network Activity':        'text-blue-400   bg-blue-500/10   border-blue-500/20',
  'Findings':                'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
}

function useCopy(text) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return [copied, copy]
}

function DatasetTable() {
  const [open, setOpen] = useState(true)
  return (
    <div className="collapsible-section">
      <div className="collapsible-header" onClick={() => setOpen(!open)}>
        <span className="text-sm font-semibold text-slate-200">Covered Datasets ({PARSER_DATASETS.length})</span>
        {open ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
      </div>
      {open && (
        <div className="overflow-x-auto">
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
                    <span className={`inline-block px-2 py-0.5 rounded border text-xs font-medium ${CATEGORY_COLORS[d.category] || 'text-slate-400'}`}>
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

function FixesList() {
  const [open, setOpen] = useState(false)
  return (
    <div className="collapsible-section">
      <div className="collapsible-header" onClick={() => setOpen(!open)}>
        <span className="text-sm font-semibold text-slate-200">Bug Fixes vs Upstream ({FIXES.length})</span>
        {open ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
      </div>
      {open && (
        <ul className="space-y-2 px-1">
          {FIXES.map((f, i) => (
            <li key={i} className="flex gap-3 text-xs">
              <span className="shrink-0 px-1.5 py-0.5 rounded bg-orange-500/10 border border-orange-500/20 text-orange-400 font-semibold">
                {f.field}
              </span>
              <span className="text-slate-400 leading-relaxed">{f.detail}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export default function Parsers() {
  const [parserContent, setParserContent] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [copied, copy] = useCopy(parserContent || '')

  async function loadParser() {
    if (parserContent) return
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/parsers/cloudflare-ocsf-parser/cloudflare-ocsf-parser.conf')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const text = await res.text()
      setParserContent(text)
    } catch (err) {
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
    <div className="page-enter space-y-5 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Parsers</h1>
        <p className="text-sm text-slate-400 mt-0.5">
          OCSF-mapped SentinelOne ingest parsers for Cloudflare Logpush datasets
        </p>
      </div>

      {/* Parser card */}
      <div className="rounded-2xl border border-white/10 bg-white/3 overflow-hidden">
        {/* Card header */}
        <div className="flex items-start justify-between gap-4 p-5 border-b border-white/5">
          <div className="flex items-start gap-4">
            <div className="w-10 h-10 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center shrink-0">
              <FileCode className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100">cloudflare-ocsf-parser</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                OCSF 1.6.0 · SentinelOne AI SIEM · {PARSER_DATASETS.length} datasets · v1.0.0
              </p>
              <div className="flex flex-wrap gap-1.5 mt-2">
                {['Identity & Access Mgmt', 'Network Activity', 'Findings'].map(cat => (
                  <span key={cat} className={`inline-block px-2 py-0.5 rounded border text-xs font-medium ${CATEGORY_COLORS[cat]}`}>
                    {cat}
                  </span>
                ))}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {parserContent && (
              <>
                <button
                  onClick={downloadParser}
                  className="btn-ghost text-xs"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download
                </button>
                <button
                  onClick={copy}
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

        {/* Info banner */}
        <div className="px-5 py-3 bg-blue-500/5 border-b border-blue-500/10 flex gap-2 text-xs text-slate-400">
          <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
          <span>
            Import this <span className="font-mono text-slate-300">.conf</span> file into SentinelOne AI SIEM under{' '}
            <span className="text-slate-300">Settings → Parsers → Import Parser</span>. The parser auto-detects Cloudflare
            datasets by predicate field matching and maps each to the correct OCSF class.
          </span>
        </div>

        <div className="p-5 space-y-4">
          <DatasetTable />
          <FixesList />

          {/* Parser preview */}
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
                  onClick={copy}
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
