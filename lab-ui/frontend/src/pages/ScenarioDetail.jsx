import { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate, useSearchParams, Link } from 'react-router-dom'
import {
  ArrowLeft, Copy, Check, Play, Square, AlertTriangle,
  ChevronRight, ChevronDown, Shield, Target, Layers, GitBranch, Terminal as TerminalIcon,
  Settings as SettingsIcon, Info, ExternalLink, ShieldCheck, CheckCircle2,
  Radar, Crosshair, Plug, Braces
} from 'lucide-react'
import { SCENARIOS } from '../data/scenarios.js'
import { detectionForScenario } from '../data/knowledgeObjects.js'
import Badge from '../components/Badge.jsx'
import Terminal from '../components/Terminal.jsx'
import RunSummary from '../components/RunSummary.jsx'
import TargetBar from '../components/TargetBar.jsx'
import HAPlaybookDiagram from '../components/HAPlaybookDiagram.jsx'
import { HA_PLAYBOOKS, loadHaWorkflowJson } from '../data/haPlaybooks.js'
import { getMe, getTenants, getRunTarget, dnsAllowed } from '../lib/session.js'

const TABS = [
  { id: 'run',       label: 'Run Attack',        icon: Play },
  { id: 'siem',      label: 'SIEM Detection',    icon: Shield },
  { id: 'playbook',  label: 'Response Playbook', icon: GitBranch },
]

// Legacy deep-links (?tab=overview / ?tab=how) point at tabs that were merged
// into Run Attack and SIEM Detection respectively — remap so old links resolve.
const TAB_REMAP = { overview: 'run', how: 'siem' }

function CopyButton({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return (
    <button
      onClick={handleCopy}
      className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 border border-slate-700/50 rounded-lg px-3 py-1.5 transition-all hover:border-slate-600"
    >
      {copied ? <><Check className="w-3.5 h-3.5 text-green-400" /><span className="text-green-400">Copied</span></> : <><Copy className="w-3.5 h-3.5" />{label}</>}
    </button>
  )
}

function MetaCard({ label, value, mono = false }) {
  return (
    <div className="rounded-xl bg-white/3 border border-[#2d1b4e] p-4">
      <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider">{label}</div>
      <div className={`text-sm text-slate-200 font-medium leading-snug ${mono ? 'font-mono' : ''}`}>
        {value}
      </div>
    </div>
  )
}

function saveRunToHistory(scenario, lines, exitCode) {
  try {
    const history = JSON.parse(localStorage.getItem('oneflare_run_history') || '[]')
    const entry = {
      id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now()),
      scenario: scenario.id,
      title: scenario.title,
      timestamp: new Date().toISOString(),
      lines,
      exitCode,
    }
    history.push(entry)
    // keep last 100
    const trimmed = history.slice(-100)
    localStorage.setItem('oneflare_run_history', JSON.stringify(trimmed))
  } catch {}
}

function SectionHeader({ icon: Icon, title, accent = 'purple' }) {
  const color = accent === 'orange' ? 'text-orange-400' : accent === 'green' ? 'text-green-400' : accent === 'blue' ? 'text-blue-400' : 'text-purple-400'
  return (
    <div className="flex items-center gap-2 mb-3">
      <Icon className={`w-4 h-4 ${color}`} />
      <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">{title}</h3>
    </div>
  )
}

// Raw workflow JSON is lazy-loaded on first expand (dynamic import — its own chunk),
// rather than bundled into the main app chunk, since most visitors never open it.
function WorkflowJsonPanel({ workflowKey, filename }) {
  const [open, setOpen] = useState(false)
  const [raw, setRaw] = useState(null)
  const [loading, setLoading] = useState(false)

  const handleToggle = () => {
    setOpen(o => !o)
    if (!raw && !loading) {
      setLoading(true)
      loadHaWorkflowJson(workflowKey).then(data => {
        setRaw(data)
        setLoading(false)
      })
    }
  }

  const pretty = raw ? JSON.stringify(raw, null, 2) : ''

  return (
    <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
      <button
        onClick={handleToggle}
        className="flex items-center justify-between w-full text-left"
        aria-expanded={open}
      >
        <div className="flex items-center gap-2">
          <Braces className="w-4 h-4 text-purple-400" />
          <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">Workflow JSON</h3>
        </div>
        {open ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
      </button>
      {open && (
        <div className="mt-4 space-y-3">
          {loading || !raw ? (
            <p className="text-xs text-slate-500">Loading workflow JSON&hellip;</p>
          ) : (
            <>
              <div className="flex items-center justify-between gap-3">
                <span className="text-xs text-slate-500 font-mono truncate">{filename}</span>
                <CopyButton text={pretty} label="Copy JSON" />
              </div>
              <pre className="code-block text-xs leading-relaxed overflow-auto" style={{ maxHeight: '28rem' }}>
                <code className="text-purple-300">{pretty}</code>
              </pre>
              <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 flex gap-2.5">
                <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                <p className="text-xs text-slate-400 leading-relaxed">
                  Import into SentinelOne &rarr; Hyperautomation &rarr; Workflows &rarr; Import (lands as a
                  Private Draft owned by the importing user — publish it, bind the connections above, then activate).
                </p>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}

// "Setup — before you import" — richer prerequisite panel for playbooks that define
// haPlaybook.setup (connections to bind + free third-party API keys to sign up for
// before importing). Falls back to the plain connections pill list (below) when a
// playbook hasn't been upgraded to the shared response `setup` shape yet.
function SetupPanel({ setup }) {
  return (
    <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
      <SectionHeader icon={Plug} title="Setup — before you import" accent="blue" />
      <p className="text-sm text-slate-300 leading-relaxed mb-4">{setup.intro}</p>
      <ul className="space-y-2.5">
        {setup.items.map((item, i) => (
          <li key={i} className="flex items-start gap-2.5">
            <CheckCircle2 className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
            <div className="text-sm leading-relaxed">
              <span className="font-semibold text-slate-100">{item.label}</span>
              {item.detail && <span className="text-slate-400"> — {item.detail}</span>}
              {item.url && (
                <a
                  href={item.url}
                  target="_blank"
                  rel="noreferrer"
                  aria-label={`Sign up for a free ${item.label} API key (opens in a new tab)`}
                  className="ml-1.5 inline-flex items-center gap-1 text-purple-400 hover:text-purple-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-purple-400/60 rounded"
                >
                  Get key <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>
          </li>
        ))}
      </ul>
      {setup.note && (
        <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 flex gap-2.5 mt-4">
          <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
          <p className="text-xs text-slate-400 leading-relaxed">{setup.note}</p>
        </div>
      )}
    </div>
  )
}

// Rich, detection-engineer-focused SIEM view (used when a scenario defines `siem`).
// Rule identity (name / severity / query) is sourced from the canonical
// knowledgeObjects.DETECTIONS entry — the ACTUAL deployed rule JSON — so what a
// user sees here matches exactly what the Architecture page shows and what
// deploys. All narrative fields (why-detect, MITRE, signals, tuning, triage)
// still come from the scenario's own `siem` content. Falls back to the
// scenario's local siem.* facts if no canonical detection is registered.
function RichSiemDetection({ scenario, detection }) {
  const s = scenario.siem
  const ruleName = detection?.name ?? s.ruleName
  const severity = detection?.severity ?? s.severity
  const query = detection?.query ?? s.query
  return (
    <div className="space-y-5">
      {/* The detection query — leads the tab; this is the point of the page */}
      <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
        <div className="flex items-center justify-between mb-3">
          <SectionHeader icon={TerminalIcon} title="PowerQuery Detection" />
          <CopyButton text={query} label="Copy Query" />
        </div>
        <pre className="code-block text-xs leading-relaxed overflow-x-auto">
          <code className="text-purple-300">{query}</code>
        </pre>
        <p className="text-xs text-slate-500 mt-2 leading-relaxed">
          Scheduled-rule body for the SentinelOne SDL. Runs on a cadence over the lookback window and
          emits one row per offending (source, zone).
        </p>
        <div className="mt-3 rounded-lg border border-amber-500/25 bg-amber-500/5 p-3 flex gap-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs text-slate-400 leading-relaxed">
            <span className="text-amber-300 font-medium">Deploy as a Scheduled rule</span>{' '}
            (<code className="text-amber-300/90">queryType: scheduled</code>,{' '}
            <code className="text-amber-300/90">queryLang: 2.0</code>). This is a PowerQuery — the{' '}
            <code className="text-amber-300/90">|</code> pipe is rejected by a single-event{' '}
            <span className="font-medium">STAR</span> rule with{' '}
            <span className="italic">“Don't understand [|] — try enclosing it in quotes.”</span>{' '}
            It requires aggregation (<code>group</code> / <code>count</code>), which only scheduled
            rules run. Rule of thumb: a query with a <code className="text-amber-300/90">|</code> →
            Scheduled rule; no pipes → STAR/single-event.
          </div>
        </div>
      </div>

      {/* Meta row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <MetaCard label="Detection Rule" value={ruleName} mono />
        <MetaCard label="Rule Type" value={`${s.ruleType} · ${s.queryLang}`} />
        <MetaCard label="Severity" value={<Badge type="severity" value={severity} />} />
        <MetaCard label="Data Source" value={s.dataSource} />
      </div>

      {/* Validation banner */}
      {s.validated && (
        <div className="rounded-xl border border-green-500/25 bg-green-500/5 p-4 flex gap-3">
          <CheckCircle2 className="w-5 h-5 text-green-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-green-300 font-medium mb-1">Validated — 0 false positives</p>
            <p className="text-xs text-slate-400 leading-relaxed">{s.validationNote}</p>
          </div>
        </div>
      )}

      {/* Why detect */}
      <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
        <SectionHeader icon={Info} title="Why detect this" accent="blue" />
        <p className="text-sm text-slate-300 leading-relaxed mb-3">{s.importance}</p>
        <ul className="space-y-1.5">
          {s.whyDetect.map((w, i) => (
            <li key={i} className="flex gap-2 text-sm text-slate-400 leading-relaxed">
              <ChevronRight className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
              <span>{w}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* MITRE ATT&CK */}
      <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
        <SectionHeader icon={Crosshair} title="MITRE ATT&CK" accent="orange" />
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {s.mitre.map((m) => (
            <a
              key={m.id}
              href={m.url}
              target="_blank"
              rel="noopener noreferrer"
              className="group rounded-lg border border-[#2d1b4e] bg-white/3 p-3 hover:border-orange-500/40 transition-all"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono text-sm text-orange-400 font-semibold">{m.id}</span>
                <ExternalLink className="w-3.5 h-3.5 text-slate-600 group-hover:text-orange-400 transition-colors" />
              </div>
              <div className="text-xs text-slate-500 mb-0.5">{m.tactic}</div>
              <div className="text-sm text-slate-300 leading-snug">{m.name}</div>
            </a>
          ))}
        </div>
      </div>

      {/* Additional detections — other rules verified alongside the headline query */}
      {s.additionalDetections && s.additionalDetections.length > 0 && (
        <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
          <SectionHeader icon={Shield} title={`Additional Detections (${s.additionalDetections.length})`} accent="green" />
          <p className="text-xs text-slate-500 -mt-2 mb-3 leading-relaxed">
            The headline query above is one of several rules verified together. Each of these fired independently against live data.
          </p>
          <div className="space-y-2">
            {s.additionalDetections.map((d, i) => (
              <details key={i} className="group rounded-lg border border-[#2d1b4e] bg-white/3 open:bg-white/5">
                <summary className="flex items-center gap-3 p-3 cursor-pointer list-none">
                  <ChevronRight className="w-4 h-4 text-slate-500 shrink-0 transition-transform group-open:rotate-90" />
                  <span className="text-sm font-semibold text-slate-200">{d.name}</span>
                  <Badge type="severity" value={d.severity} />
                  <span className="text-xs font-mono text-orange-400/80">{d.mitre}</span>
                </summary>
                <div className="px-3 pb-3 pl-10 space-y-2.5">
                  <p className="text-sm text-slate-400 leading-relaxed">{d.description}</p>
                  <div className="flex items-center justify-end" onClick={(e) => e.stopPropagation()}>
                    <CopyButton text={d.query} label="Copy Query" />
                  </div>
                  <pre className="code-block text-xs leading-relaxed overflow-x-auto">
                    <code className="text-purple-300">{d.query}</code>
                  </pre>
                </div>
              </details>
            ))}
          </div>
        </div>
      )}

      {/* How the query works */}
      <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
        <SectionHeader icon={Layers} title="How the query works" />
        <div className="space-y-2.5">
          {s.queryExplained.map((q, i) => (
            <div key={i} className="flex flex-col sm:flex-row sm:items-baseline gap-1 sm:gap-3">
              <code className="text-xs text-orange-300 font-mono bg-black/30 rounded px-2 py-1 shrink-0 sm:w-64 sm:whitespace-nowrap sm:overflow-hidden sm:text-ellipsis">{q.code}</code>
              <span className="text-sm text-slate-400 leading-relaxed">{q.note}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Detection signals */}
      <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
        <SectionHeader icon={Radar} title="Detection signals" accent="green" />
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-slate-500 uppercase tracking-wider border-b border-[#2d1b4e]">
                <th className="pb-2 pr-4 font-medium">Signal</th>
                <th className="pb-2 pr-4 font-medium">Catches</th>
                <th className="pb-2 font-medium">Why it works</th>
              </tr>
            </thead>
            <tbody>
              {s.signals.map((sig, i) => (
                <tr key={i} className="border-b border-[#2d1b4e]/50 last:border-0">
                  <td className="py-2.5 pr-4 align-top"><code className="text-xs text-purple-300 font-mono whitespace-nowrap">{sig.signal}</code></td>
                  <td className="py-2.5 pr-4 align-top text-slate-300 whitespace-nowrap">{sig.catches}</td>
                  <td className="py-2.5 align-top text-slate-400 leading-relaxed">{sig.why}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Tuning & false positives */}
      {s.falsePositive && (
        <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
          <SectionHeader icon={AlertTriangle} title="Tuning — how we reached 0 false positives" accent="orange" />
          <div className="space-y-3">
            <div>
              <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Observed false positive</div>
              <p className="text-sm text-slate-300 leading-relaxed">{s.falsePositive.finding}</p>
            </div>
            <div>
              <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Root cause</div>
              <p className="text-sm text-slate-300 leading-relaxed">{s.falsePositive.rootCause}</p>
            </div>
            <div>
              <div className="text-xs text-green-500/80 uppercase tracking-wider mb-1">The fix</div>
              <p className="text-sm text-slate-300 leading-relaxed">{s.falsePositive.fix}</p>
            </div>
          </div>
        </div>
      )}

      {/* Triage + response */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4">
          <SectionHeader icon={ShieldCheck} title="Triage discipline" accent="blue" />
          <p className="text-xs text-slate-400 leading-relaxed">{s.triage}</p>
        </div>
        <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-4">
          <SectionHeader icon={GitBranch} title="Recommended response" accent="orange" />
          <p className="text-xs text-slate-400 leading-relaxed">{s.recommendedResponse}</p>
        </div>
      </div>
    </div>
  )
}

// Scenario context, surfaced at the top of the Run Attack tab (was its own
// "Overview" tab). Gives an operator the what/why + key facts right before they
// fire the attack.
function ScenarioOverviewBlock({ scenario }) {
  return (
    <div className="space-y-5">
      <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Scenario Overview</h3>
        <p className="text-slate-300 leading-relaxed">{scenario.overview}</p>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <MetaCard label="CF Product" value={scenario.cfProduct} />
        <MetaCard label="Target" value={scenario.target} mono />
        <MetaCard label="Detection Rule" value={scenario.detectionRule} mono />
        <MetaCard label="Tactic" value={scenario.tactic} />
      </div>
    </div>
  )
}

// Attack mechanics, surfaced at the top of the SIEM Detection tab (was its own
// "How It Works" tab). Shows the attack flow + a sample Cloudflare log event so
// the detection logic below reads in context of what generates it.
function AttackFlowBlock({ scenario }) {
  return (
    <div className="space-y-5">
      <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Attack Flow</h3>
        <div className="space-y-0">
          {scenario.howItWorks.map((step, i) => (
            <div key={i} className="flex gap-3">
              <div className="flex flex-col items-center shrink-0">
                <div className="w-7 h-7 rounded-full bg-orange-500/10 border border-orange-500/30 flex items-center justify-center text-xs font-mono font-bold text-orange-400 shrink-0">
                  {i + 1}
                </div>
                {i < scenario.howItWorks.length - 1 && (
                  <div className="w-px flex-1 bg-gradient-to-b from-orange-500/20 to-transparent my-1 min-h-[24px]" />
                )}
              </div>
              <div className="pt-0.5 pb-4">
                <p className="text-sm text-slate-300 leading-relaxed">{step}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Sample CF Log Event</h3>
          <CopyButton text={scenario.cfLogs} label="Copy JSON" />
        </div>
        <pre className="code-block text-xs leading-relaxed overflow-x-auto">
          <code>{scenario.cfLogs}</code>
        </pre>
      </div>
    </div>
  )
}

export default function ScenarioDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const scenario = SCENARIOS.find(s => s.id === id)
  // Canonical detection identity for this scenario (name/severity/query as
  // ACTUALLY deployed) — see src/data/knowledgeObjects.js.
  const detection = detectionForScenario(id)
  // Deep-links (e.g. from the Architecture Hyperautomation index) can land
  // directly on a tab via ?tab=playbook.
  const requestedTab = searchParams.get('tab')
  const resolvedTab = TAB_REMAP[requestedTab] || requestedTab
  const [activeTab, setActiveTab] = useState(
    TABS.some(t => t.id === resolvedTab) ? resolvedTab : 'run'
  )

  // Run state
  const [lines, setLines] = useState([])
  const [isRunning, setIsRunning] = useState(false)
  const [runDone, setRunDone] = useState(false)
  const [exitCode, setExitCode] = useState(null)
  const [startTime, setStartTime] = useState(null)
  const [duration, setDuration] = useState(null)
  const [needsLogin, setNeedsLogin] = useState(false)
  const wsRef = useRef(null)
  const cancelRef = useRef(false)

  // Session (role) — decides whether a run targets the caller's own
  // subdomain (non-admin, forced server-side) or an admin-selected target
  // (including the scenario-only "__all__" fan-out).
  const [session, setSession] = useState(null)
  const [sessionLoaded, setSessionLoaded] = useState(false)
  useEffect(() => {
    let alive = true
    getMe().then(me => { if (alive) { setSession(me); setSessionLoaded(true) } })
    return () => { alive = false }
  }, [])

  // Campaign scenarios (ctf/financial/healthcare/saas) run a variable number
  // of requests per box/phase — only those runners read CAMPAIGN_COUNT.
  const [campaignVolume, setCampaignVolume] = useState('medium')

  // Non-sensitive run config is served by the backend (GET /api/config) so a
  // fresh browser is pre-configured and anyone can run scenarios with zero setup.
  // A per-user localStorage value still overrides the server default.
  const [serverConfig, setServerConfig] = useState(null)
  const [serverConfigLoaded, setServerConfigLoaded] = useState(false)
  useEffect(() => {
    let alive = true
    fetch('/api/config')
      .then(r => (r.ok ? r.json() : null))
      .then(cfg => { if (alive) { setServerConfig(cfg); setServerConfigLoaded(true) } })
      .catch(() => { if (alive) setServerConfigLoaded(true) })
    return () => { alive = false }
  }, [])

  // DNS uses account-level Gateway (shared, not per-tenant) — block direct
  // URL access for anyone who isn't an admin on the default console, same
  // gate applied to the scenario lists on Scenarios/Detections/Architecture.
  useEffect(() => {
    if (id !== 'dns') return
    if (!sessionLoaded || !serverConfigLoaded) return
    if (!dnsAllowed({ adminEnabled: !!serverConfig?.admin_enabled, role: session?.role })) {
      navigate('/scenarios', { replace: true })
    }
  }, [id, session, sessionLoaded, serverConfig, serverConfigLoaded, navigate])

  // Always open a scenario at the top of the page. SPA navigation (prev/next
  // links) otherwise preserves the previous scroll position.
  useEffect(() => {
    window.scrollTo(0, 0)
  }, [id])

  useEffect(() => {
    return () => {
      wsRef.current?.close()
    }
  }, [])

  // Effective config: localStorage override → server default → hardcoded.
  const ls = (k) => localStorage.getItem(k) || ''
  const domain = ls('oneflare_cf_domain') || serverConfig?.domain || ''
  const shopUrl = ls('oneflare_shop_url') || serverConfig?.shop_url || ''
  const portalUrl = ls('oneflare_portal_url') || serverConfig?.portal_url || ''
  const apiUrl = ls('oneflare_api_url') || serverConfig?.api_url || ''
  const attackDelay = ls('oneflare_attack_delay') || String(serverConfig?.delay ?? '0.5')
  const attackJitter = ls('oneflare_attack_jitter') || String(serverConfig?.jitter ?? '0.3')
  const gatewayDohUrl = ls('oneflare_cf_gateway_doh_url') || serverConfig?.gateway_doh_url || ''

  const isConfigured = !!domain

  if (!scenario) {
    return (
      <div className="page-enter flex flex-col items-center justify-center py-20 gap-4">
        <AlertTriangle className="w-10 h-10 text-orange-400" />
        <p className="text-slate-300">Scenario not found: <span className="font-mono text-orange-400">{id}</span></p>
        <button onClick={() => navigate('/scenarios')} className="btn-ghost">Back to Scenarios</button>
      </div>
    )
  }

  // Opens one WS run against `targetSubdomain` ('' = one-flare default; a
  // non-admin always sends '' and the backend forces their own subdomain
  // regardless). Resolves with the exit code once the socket closes.
  function runSingle(targetSubdomain, prefixLine) {
    return new Promise((resolve) => {
      const wsUrl = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/run/${scenario.id}`
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws
      let lastExitCode = null

      ws.onopen = () => {
        if (prefixLine) setLines(prev => [...prev, prefixLine])
        const config = {
          domain,
          shop_url: shopUrl,
          portal_url: portalUrl,
          api_url: apiUrl,
          delay: parseFloat(attackDelay),
          jitter: parseFloat(attackJitter),
          gateway_doh_url: gatewayDohUrl,
          target_subdomain: targetSubdomain,
          campaign_volume: campaignVolume,
          // Sent so the backend can verify BYOC targets (a host in a Cloudflare
          // zone this token controls) before running against a non-lab host.
          cf_api_token: ls('oneflare_cf_api_token'),
        }
        ws.send(JSON.stringify(config))
      }

      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data)
          if (msg.type === 'output') {
            setLines(prev => [...prev, msg.line])
          } else if (msg.type === 'start') {
            setLines(prev => [...prev, `► Starting scenario: ${msg.scenario}`])
          } else if (msg.type === 'done') {
            lastExitCode = msg.exit_code
          } else if (msg.type === 'error') {
            setLines(prev => [...prev, `ERROR: ${msg.message}`])
            if (String(msg.message || '').toLowerCase().includes('log in')) setNeedsLogin(true)
          }
        } catch {}
      }

      ws.onerror = () => {
        setLines(prev => [...prev, 'ERROR: WebSocket connection failed. Is the backend running?'])
      }

      ws.onclose = () => resolve(lastExitCode)
    })
  }

  async function handleRun() {
    if (isRunning) {
      cancelRef.current = true
      wsRef.current?.close()
      setIsRunning(false)
      return
    }

    const start = Date.now()
    cancelRef.current = false
    setLines([])
    setRunDone(false)
    setExitCode(null)
    setNeedsLogin(false)
    setStartTime(start)
    setIsRunning(true)

    const isAdmin = session?.role === 'admin'
    const storedTarget = isAdmin ? getRunTarget() : ''

    let finalExitCode = null

    if (isAdmin && storedTarget === '__all__') {
      const tenants = await getTenants()
      if (!tenants.length) {
        setLines(prev => [...prev, 'No registered tenants found — nothing to fan out to.'])
      } else {
        for (const t of tenants) {
          if (cancelRef.current) break
          finalExitCode = await runSingle(t.subdomain, `── [${t.subdomain}] ──`)
        }
      }
    } else {
      finalExitCode = await runSingle(isAdmin ? storedTarget : '', null)
    }

    const dur = ((Date.now() - start) / 1000).toFixed(1) + 's'
    setDuration(dur)
    setExitCode(finalExitCode)
    setRunDone(true)
    setIsRunning(false)
    setLines(prev => {
      saveRunToHistory(scenario, prev, finalExitCode)
      return prev
    })
  }

  const haPlaybook = HA_PLAYBOOKS[id]

  const allScenarios = SCENARIOS
  const currentIndex = allScenarios.findIndex(s => s.id === id)
  const prevScenario = allScenarios[currentIndex - 1]
  const nextScenario = allScenarios[currentIndex + 1]

  return (
    <div className="page-enter space-y-6 max-w-4xl mx-auto">
      {/* Breadcrumb + nav */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => navigate('/scenarios')}
          className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Scenarios
        </button>
        <div className="flex items-center gap-2">
          {prevScenario && (
            <Link
              to={`/scenarios/${prevScenario.id}`}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors flex items-center gap-1"
            >
              <ArrowLeft className="w-3 h-3" />
              {prevScenario.number}
            </Link>
          )}
          {nextScenario && (
            <Link
              to={`/scenarios/${nextScenario.id}`}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors flex items-center gap-1"
            >
              {nextScenario.number}
              <ChevronRight className="w-3 h-3" />
            </Link>
          )}
        </div>
      </div>

      {/* Header */}
      <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-6">
        <div className="flex items-start gap-4 flex-wrap">
          <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-white/5 border border-white/10 font-mono font-bold text-lg text-slate-300 shrink-0">
            {scenario.number}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap mb-2">
              <Badge type="category" value={scenario.category} size="md" />
              <Badge type="severity" value={scenario.severity} size="md" />
            </div>
            <h1 className="text-2xl md:text-3xl font-bold text-slate-100 leading-tight">
              {scenario.title}
            </h1>
            <p className="text-slate-400 mt-1.5 leading-relaxed">{scenario.shortDescription}</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-[#2d1b4e] flex gap-1 overflow-x-auto pb-0 -mb-px">
        {TABS.map(({ id: tid, label, icon: Icon }) => (
          <button
            key={tid}
            onClick={() => setActiveTab(tid)}
            className={`
              relative flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium whitespace-nowrap transition-all duration-200
              ${activeTab === tid
                ? 'text-orange-400 border-b-2 border-orange-400'
                : 'text-slate-400 hover:text-slate-200 border-b-2 border-transparent'
              }
            `}
          >
            <Icon className="w-3.5 h-3.5 shrink-0" />
            {label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="animate-[fadeIn_0.2s_ease-out]">

        {/* === SIEM DETECTION (with the merged-in attack mechanics on top) === */}
        {activeTab === 'siem' && (
          <div className="space-y-5">
            {scenario.siem ? (
              <RichSiemDetection scenario={scenario} detection={detection} />
            ) : (
          <div className="space-y-5">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <MetaCard label="Detection Rule" value={detection?.name ?? scenario.detectionRule} mono />
              <MetaCard label="SIEM Severity" value={<Badge type="severity" value={detection?.severity ?? scenario.siemSeverity} />} />
              <MetaCard label="MITRE Tactic" value={scenario.siemTactic} />
            </div>

            <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">STAR Detection Rule</h3>
                <CopyButton text={detection?.query ?? scenario.siemLogic} label="Copy Rule" />
              </div>
              <pre className="code-block text-xs leading-relaxed whitespace-pre-wrap">
                <code className="text-purple-300">{detection?.query ?? scenario.siemLogic}</code>
              </pre>
            </div>

            <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4 flex gap-3">
              <Shield className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-sm text-blue-300 font-medium mb-1">SentinelOne STAR Rule</p>
                <p className="text-xs text-slate-400 leading-relaxed">
                  This detection logic is designed for SentinelOne's STAR (Storyline-based Active Response) engine. Copy and paste it into the Custom STAR Rules editor in your SentinelOne console to enable real-time detection and automated response.
                </p>
              </div>
            </div>
          </div>
            )}

            {/* Attack mechanics live at the bottom now — the detection leads. */}
            <AttackFlowBlock scenario={scenario} />
          </div>
        )}

        {/* === RESPONSE PLAYBOOK === */}
        {activeTab === 'playbook' && (
          <div className="space-y-5">
            {haPlaybook && (
              <>
                {/* Diagram — lead with the workflow itself */}
                <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
                  <SectionHeader icon={GitBranch} title={`Hyperautomation workflow — ${haPlaybook.title}`} />
                  <HAPlaybookDiagram diagram={haPlaybook.diagram} />
                </div>

                {/* Why this response */}
                <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
                  <SectionHeader icon={GitBranch} title="Why this response" accent="orange" />
                  <p className="text-sm text-slate-300 leading-relaxed">{haPlaybook.why}</p>
                </div>

                {/* Setup — before you import (response playbooks) — falls back to the
                    plain connections pill list for playbooks that haven't defined `setup` yet. */}
                {haPlaybook.setup ? (
                  <SetupPanel setup={haPlaybook.setup} />
                ) : (
                  <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
                    <SectionHeader icon={Plug} title="Connections required" accent="blue" />
                    <div className="flex flex-wrap gap-2">
                      {haPlaybook.connections.map((c, i) => (
                        <span
                          key={i}
                          className="inline-flex items-center rounded-full border border-[#2d1b4e] bg-white/5 px-3 py-1 text-xs font-mono text-slate-300"
                        >
                          {c}
                        </span>
                      ))}
                    </div>
                    <p className="text-xs text-slate-500 mt-3 leading-relaxed">
                      Configure these under Hyperautomation &rarr; Integrations before importing —
                      integration-backed actions won't run without a bound connection.
                    </p>
                  </div>
                )}

                {/* Workflow JSON (collapsible, lazy-loaded) */}
                <WorkflowJsonPanel workflowKey={haPlaybook.workflowKey} filename={haPlaybook.workflowFile} />
              </>
            )}

            {/* Analyst steps (existing compact list) */}
            <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">
                {haPlaybook ? 'Analyst Steps' : 'Incident Response Workflow'}
              </h3>
              <div className="space-y-0">
                {scenario.responseWorkflow.map((item, i) => (
                  <div key={i} className="flex gap-3">
                    <div className="flex flex-col items-center shrink-0">
                      <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-xs font-mono font-bold text-purple-400">
                        {String(item.step).padStart(2, '0')}
                      </div>
                      {i < scenario.responseWorkflow.length - 1 && (
                        <div className="w-px flex-1 bg-gradient-to-b from-purple-500/30 to-transparent my-1 min-h-[28px]" />
                      )}
                    </div>
                    <div className="flex-1 pb-4">
                      <div className="playbook-step">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm font-semibold text-slate-100">{item.action}</span>
                          <span className="text-slate-600">—</span>
                        </div>
                        <p className="text-sm text-slate-400 leading-relaxed">{item.detail}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* === RUN ATTACK (with the merged-in scenario overview on top) === */}
        {activeTab === 'run' && (
          <div className="space-y-4">
            {/* Scenario context — what this attack is and why it matters */}
            <ScenarioOverviewBlock scenario={scenario} />

            {/* Run controls — target selection + run/stop + clear on one line, ABOVE the disclaimer */}
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex-1 min-w-[240px]"><TargetBar scope="scenario" /></div>
              <button
                onClick={handleRun}
                disabled={!isConfigured && !isRunning}
                className={`flex items-center gap-2 px-5 py-2.5 rounded-lg font-semibold text-sm transition-all duration-200 shrink-0 ${
                  isRunning
                    ? 'bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30'
                    : isConfigured
                    ? 'bg-gradient-to-r from-orange-500 to-orange-600 text-white hover:from-orange-600 hover:to-orange-700 shadow-lg shadow-orange-500/20'
                    : 'bg-white/5 text-slate-500 cursor-not-allowed border border-slate-700'
                }`}
              >
                {isRunning ? (
                  <><Square className="w-4 h-4" /> Stop Attack</>
                ) : (
                  <><Play className="w-4 h-4" /> Run Attack</>
                )}
              </button>
              {(isRunning || runDone) && (
                <button
                  onClick={() => { setLines([]); setRunDone(false); setExitCode(null) }}
                  className="btn-ghost text-xs shrink-0"
                  disabled={isRunning}
                >
                  Clear
                </button>
              )}
              {needsLogin && (
                <span className="text-xs text-amber-300 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Please log in to run scenarios.
                  <Link to="/admin" className="text-orange-400 underline hover:no-underline">Log in →</Link>
                </span>
              )}
            </div>

            {/* Warning banner */}
            <div className="rounded-xl border border-orange-500/30 bg-orange-500/5 p-4 flex gap-3">
              <AlertTriangle className="w-5 h-5 text-orange-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-semibold text-orange-400 mb-1">Real Attack Traffic</p>
                <p className="text-xs text-slate-400 leading-relaxed">
                  This will send real attack traffic to your configured lab endpoints. Only run against systems you own and have explicit permission to test. All traffic is logged by Cloudflare.
                </p>
              </div>
            </div>

            {/* Config check */}
            <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-4">
              <h4 className="text-sm font-semibold text-slate-300 mb-3">Current Configuration</h4>
              <div className="space-y-2">
                {[
                  { label: 'CF Domain', value: domain, required: true },
                  { label: 'Shop URL', value: shopUrl, fallback: 'https://shop.soledrop.co' },
                  { label: 'Portal URL', value: portalUrl, fallback: 'https://shop.soledrop.co' },
                  { label: 'API URL', value: apiUrl, fallback: 'https://shop.soledrop.co' },
                ].map(({ label, value, required, fallback }) => (
                  <div key={label} className="flex items-center gap-3">
                    <span className="text-xs text-slate-500 w-24 shrink-0">{label}</span>
                    {value ? (
                      <span className="text-xs font-mono text-green-400">{value}</span>
                    ) : required ? (
                      <span className="text-xs font-mono text-red-400">Not configured</span>
                    ) : (
                      <span className="text-xs font-mono text-slate-500">Using default: {fallback}</span>
                    )}
                  </div>
                ))}
                <div className="flex items-center gap-3">
                  <span className="text-xs text-slate-500 w-24 shrink-0">Delay / Jitter</span>
                  <span className="text-xs font-mono text-slate-300">{attackDelay}s / ±{attackJitter}s</span>
                </div>
              </div>
            </div>

            {/* Volume — campaign scenarios only (requests fired per box/phase) */}
            {scenario.category === 'Campaign' && (
              <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-4">
                <h4 className="text-sm font-semibold text-slate-300 mb-3">Volume</h4>
                <div className="grid grid-cols-3 gap-1.5">
                  {[
                    { val: 'low',    label: 'Low',    sub: '~5 / box' },
                    { val: 'medium', label: 'Medium', sub: '~15 / box' },
                    { val: 'high',   label: 'High',   sub: '~30 / box' },
                  ].map(({ val, label, sub }) => (
                    <button
                      key={val}
                      onClick={() => setCampaignVolume(val)}
                      disabled={isRunning}
                      className={`
                        rounded-lg border-2 py-2 text-center transition-all duration-150
                        ${campaignVolume === val
                          ? 'border-pink-500 text-pink-400 bg-pink-500/10'
                          : 'border-[#2d1b4e] text-slate-500 hover:border-slate-600'
                        }
                        ${isRunning ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                      `}
                    >
                      <div className="text-sm font-semibold">{label}</div>
                      <div className="text-[10px] text-slate-400">{sub}</div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {!isConfigured && (
              <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 flex items-center gap-3">
                <SettingsIcon className="w-4 h-4 text-red-400 shrink-0" />
                <p className="text-sm text-red-300">
                  Configure your Cloudflare domain in{' '}
                  <Link to="/settings" className="text-orange-400 underline hover:no-underline">Settings</Link>{' '}
                  before running attacks.
                </p>
              </div>
            )}

            {/* Terminal */}
            <Terminal
              lines={lines}
              isRunning={isRunning}
              title={`${scenario.id} — attack output`}
            />

            {/* Summary */}
            {runDone && exitCode !== null && (
              <RunSummary
                lines={lines}
                exitCode={exitCode}
                duration={duration}
                scenario={scenario.title}
              />
            )}
          </div>
        )}
      </div>
    </div>
  )
}
