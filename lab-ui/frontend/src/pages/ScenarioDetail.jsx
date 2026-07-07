import { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  ArrowLeft, Copy, Check, Play, Square, AlertTriangle,
  ChevronRight, Shield, Target, Layers, GitBranch, Terminal as TerminalIcon,
  Settings as SettingsIcon, Info, ExternalLink, ShieldCheck, CheckCircle2,
  Radar, Crosshair
} from 'lucide-react'
import { SCENARIOS } from '../data/scenarios.js'
import Badge from '../components/Badge.jsx'
import Terminal from '../components/Terminal.jsx'
import RunSummary from '../components/RunSummary.jsx'

const TABS = [
  { id: 'overview',  label: 'Overview',         icon: Info },
  { id: 'how',       label: 'How It Works',      icon: Layers },
  { id: 'siem',      label: 'SIEM Detection',    icon: Shield },
  { id: 'playbook',  label: 'Response Playbook', icon: GitBranch },
  { id: 'run',       label: 'Run Attack',        icon: Play },
]

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

// Rich, detection-engineer-focused SIEM view (used when a scenario defines `siem`).
function RichSiemDetection({ scenario }) {
  const s = scenario.siem
  return (
    <div className="space-y-5">
      {/* Meta row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <MetaCard label="Detection Rule" value={s.ruleName} mono />
        <MetaCard label="Rule Type" value={`${s.ruleType} · ${s.queryLang}`} />
        <MetaCard label="Severity" value={<Badge type="severity" value={s.severity} />} />
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

      {/* The detection query */}
      <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
        <div className="flex items-center justify-between mb-3">
          <SectionHeader icon={TerminalIcon} title="PowerQuery Detection" />
          <CopyButton text={s.query} label="Copy Query" />
        </div>
        <pre className="code-block text-xs leading-relaxed overflow-x-auto">
          <code className="text-purple-300">{s.query}</code>
        </pre>
        <p className="text-xs text-slate-500 mt-2 leading-relaxed">
          Scheduled-rule body for the SentinelOne SDL. Runs on a cadence over the lookback window and
          emits one row per offending (source, zone). Deploy via the Detection rules API or paste into
          a scheduled PowerQuery rule.
        </p>
      </div>

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

export default function ScenarioDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const scenario = SCENARIOS.find(s => s.id === id)
  const [activeTab, setActiveTab] = useState('overview')

  // Run state
  const [lines, setLines] = useState([])
  const [isRunning, setIsRunning] = useState(false)
  const [runDone, setRunDone] = useState(false)
  const [exitCode, setExitCode] = useState(null)
  const [startTime, setStartTime] = useState(null)
  const [duration, setDuration] = useState(null)
  const wsRef = useRef(null)

  // Settings
  const domain = localStorage.getItem('oneflare_cf_domain') || ''
  const shopUrl = localStorage.getItem('oneflare_shop_url') || ''
  const portalUrl = localStorage.getItem('oneflare_portal_url') || ''
  const apiUrl = localStorage.getItem('oneflare_api_url') || ''
  const attackDelay = localStorage.getItem('oneflare_attack_delay') || '0.5'
  const attackJitter = localStorage.getItem('oneflare_attack_jitter') || '0.3'
  const gatewayDohUrl = localStorage.getItem('oneflare_cf_gateway_doh_url') || ''

  const isConfigured = !!domain

  useEffect(() => {
    return () => {
      wsRef.current?.close()
    }
  }, [])

  if (!scenario) {
    return (
      <div className="page-enter flex flex-col items-center justify-center py-20 gap-4">
        <AlertTriangle className="w-10 h-10 text-orange-400" />
        <p className="text-slate-300">Scenario not found: <span className="font-mono text-orange-400">{id}</span></p>
        <button onClick={() => navigate('/scenarios')} className="btn-ghost">Back to Scenarios</button>
      </div>
    )
  }

  function handleRun() {
    if (isRunning) {
      wsRef.current?.close()
      setIsRunning(false)
      return
    }

    setLines([])
    setRunDone(false)
    setExitCode(null)
    setStartTime(Date.now())
    setIsRunning(true)

    const wsUrl = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/run/${scenario.id}`
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onopen = () => {
      const config = {
        domain,
        shop_url: shopUrl,
        portal_url: portalUrl,
        api_url: apiUrl,
        delay: parseFloat(attackDelay),
        jitter: parseFloat(attackJitter),
        gateway_doh_url: gatewayDohUrl,
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
          const dur = ((Date.now() - startTime) / 1000).toFixed(1) + 's'
          setDuration(dur)
          setExitCode(msg.exit_code)
          setRunDone(true)
          setIsRunning(false)
          setLines(prev => {
            saveRunToHistory(scenario, prev, msg.exit_code)
            return prev
          })
        } else if (msg.type === 'error') {
          setLines(prev => [...prev, `ERROR: ${msg.message}`])
          setIsRunning(false)
          setRunDone(true)
        }
      } catch {}
    }

    ws.onerror = () => {
      setLines(prev => [...prev, 'ERROR: WebSocket connection failed. Is the backend running?'])
      setIsRunning(false)
    }

    ws.onclose = () => {
      if (isRunning) setIsRunning(false)
    }
  }

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

        {/* === OVERVIEW === */}
        {activeTab === 'overview' && (
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
        )}

        {/* === HOW IT WORKS === */}
        {activeTab === 'how' && (
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
        )}

        {/* === SIEM DETECTION === */}
        {activeTab === 'siem' && (
          scenario.siem ? (
            <RichSiemDetection scenario={scenario} />
          ) : (
          <div className="space-y-5">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <MetaCard label="Detection Rule" value={scenario.detectionRule} mono />
              <MetaCard label="SIEM Severity" value={<Badge type="severity" value={scenario.siemSeverity} />} />
              <MetaCard label="MITRE Tactic" value={scenario.siemTactic} />
            </div>

            <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">STAR Detection Rule</h3>
                <CopyButton text={scenario.siemLogic} label="Copy Rule" />
              </div>
              <pre className="code-block text-xs leading-relaxed whitespace-pre-wrap">
                <code className="text-purple-300">{scenario.siemLogic}</code>
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
          )
        )}

        {/* === RESPONSE PLAYBOOK === */}
        {activeTab === 'playbook' && (
          <div className="space-y-4">
            <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5">
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Incident Response Workflow</h3>
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

        {/* === RUN ATTACK === */}
        {activeTab === 'run' && (
          <div className="space-y-4">
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
                  { label: 'Shop URL', value: shopUrl, fallback: `https://shop.${domain || 'acmecorp.dev'}` },
                  { label: 'Portal URL', value: portalUrl, fallback: `https://portal.${domain || 'acmecorp.dev'}` },
                  { label: 'API URL', value: apiUrl, fallback: `https://api.${domain || 'acmecorp.dev'}` },
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

            {/* Run button */}
            <div className="flex items-center gap-3">
              <button
                onClick={handleRun}
                disabled={!isConfigured && !isRunning}
                className={`flex items-center gap-2 px-5 py-2.5 rounded-lg font-semibold text-sm transition-all duration-200 ${
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
                  className="btn-ghost text-xs"
                  disabled={isRunning}
                >
                  Clear
                </button>
              )}
            </div>

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
