import { useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import {
  BookOpen, Play, ShieldCheck, Target, Zap, Clock,
  ArrowRight, Activity, ChevronRight, Swords,
  CheckCircle, XCircle,
} from 'lucide-react'
import { SCENARIOS } from '../data/scenarios.js'

function getRunHistory() {
  try {
    return JSON.parse(localStorage.getItem('oneflare_run_history') || '[]')
  } catch {
    return []
  }
}

function formatRelativeTime(isoString) {
  if (!isoString) return 'Never'
  const diff = Date.now() - new Date(isoString).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'Just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return new Date(isoString).toLocaleDateString()
}

function formatTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

// Compact pipeline diagram for the hero
function PipelineDiagram() {
  const steps = [
    { label: 'Attack Scripts', sublabel: 'Python / FastAPI', color: 'text-slate-300', border: 'border-slate-600/40', bg: 'bg-slate-800/40' },
    { label: 'Cloudflare', sublabel: 'WAF · Gateway · Access', color: 'text-orange-400', border: 'border-orange-500/30', bg: 'bg-orange-500/5' },
    { label: 'Logpush', sublabel: '~60s delivery', color: 'text-yellow-400', border: 'border-yellow-500/30', bg: 'bg-yellow-500/5' },
    { label: 'SentinelOne', sublabel: 'STAR · AI SIEM', color: 'text-purple-400', border: 'border-purple-500/30', bg: 'bg-purple-500/5' },
    { label: 'Hyperautomation', sublabel: 'Block · Enrich · Notify', color: 'text-green-400', border: 'border-green-500/30', bg: 'bg-green-500/5' },
  ]
  return (
    <div className="flex flex-wrap items-center gap-1 mt-6">
      {steps.map((s, i) => (
        <div key={s.label} className="flex items-center gap-1">
          <div className={`rounded-lg border px-3 py-1.5 ${s.border} ${s.bg}`}>
            <div className={`text-xs font-bold ${s.color}`}>{s.label}</div>
            <div className="text-[10px] text-slate-500 whitespace-nowrap">{s.sublabel}</div>
          </div>
          {i < steps.length - 1 && (
            <ArrowRight className="w-3.5 h-3.5 text-slate-600 shrink-0" />
          )}
        </div>
      ))}
    </div>
  )
}

export default function Dashboard() {
  const navigate = useNavigate()
  const [history, setHistory] = useState([])

  useEffect(() => {
    setHistory(getRunHistory())
  }, [])

  const today = new Date().toDateString()
  const runsToday = history.filter(r => new Date(r.timestamp).toDateString() === today).length
  const lastRun = history[history.length - 1]?.timestamp

  const totalRuns = history.length
  const blockedRuns = history.filter(r => r.exitCode === 0).length
  const blockRate = totalRuns > 0 ? Math.round((blockedRuns / totalRuns) * 100) : 0

  const categories = [...new Set(SCENARIOS.map(s => s.category))].length
  const recentRuns = [...history].reverse().slice(0, 5)

  return (
    <div className="page-enter space-y-8">
      {/* Hero */}
      <section className="relative rounded-2xl overflow-hidden" style={{ minHeight: '280px' }}>
        <div className="absolute inset-0 hero-gradient" />
        <div className="orange-blob" style={{ top: '-80px', right: '-60px', opacity: 0.8 }} />
        <div className="purple-blob" style={{ bottom: '-120px', left: '-80px', opacity: 0.7 }} />
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' stroke='%23a855f7' stroke-width='0.5' opacity='0.2'%3E%3Crect x='5' y='5' width='8' height='8'/%3E%3Crect x='25' y='5' width='8' height='8'/%3E%3Crect x='45' y='5' width='8' height='8'/%3E%3Crect x='5' y='25' width='8' height='8'/%3E%3Crect x='25' y='25' width='8' height='8'/%3E%3Crect x='45' y='25' width='8' height='8'/%3E%3Cline x1='13' y1='9' x2='25' y2='9'/%3E%3Cline x1='33' y1='9' x2='45' y2='9'/%3E%3Cline x1='13' y1='29' x2='25' y2='29'/%3E%3Cline x1='33' y1='29' x2='45' y2='29'/%3E%3Cline x1='9' y1='13' x2='9' y2='25'/%3E%3Cline x1='9' y1='33' x2='9' y2='45'/%3E%3Cline x1='29' y1='13' x2='29' y2='25'/%3E%3Cline x1='29' y1='33' x2='29' y2='45'/%3E%3Ccircle cx='13' cy='9' r='1' fill='%23f38020'/%3E%3Ccircle cx='33' cy='9' r='1' fill='%23a855f7'/%3E%3Ccircle cx='9' cy='29' r='1' fill='%23a855f7'/%3E%3Ccircle cx='29' cy='29' r='1' fill='%23f38020'/%3E%3C/g%3E%3C/svg%3E")`,
            backgroundSize: '60px 60px',
            opacity: 0.06,
          }}
        />

        <div className="relative z-10 p-8 md:p-10 flex flex-col gap-4" style={{ minHeight: '280px' }}>
          <div className="flex items-center gap-3 flex-wrap">
            <span className="px-3 py-1 rounded-full text-xs font-bold tracking-widest uppercase border border-orange-500/30 bg-orange-500/10 text-orange-400">
              CLOUDFLARE
            </span>
            <span className="text-slate-500">+</span>
            <span className="px-3 py-1 rounded-full text-xs font-bold tracking-widest uppercase border border-purple-500/30 bg-purple-500/10 text-purple-400">
              SENTINELONE
            </span>
          </div>

          <div>
            <h1 className="text-4xl md:text-5xl font-black tracking-tight leading-none mb-2">
              <span
                style={{
                  background: 'linear-gradient(135deg, #f38020 0%, #fbbf24 40%, #a855f7 100%)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                  backgroundClip: 'text',
                }}
              >
                OneFlare
              </span>
            </h1>
            <p className="text-lg text-slate-300 font-medium max-w-xl leading-relaxed">
              Cloudflare + SentinelOne Attack Simulation Lab
            </p>
            <p className="text-sm text-slate-400 mt-1 max-w-lg">
              Trigger real attack scenarios against a Cloudflare-protected environment. Watch the WAF, Gateway, and Access controls respond — then trace every event through to SentinelOne.
            </p>
          </div>

          <PipelineDiagram />
        </div>
      </section>

      {/* Stats row */}
      <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          {
            icon: BookOpen,
            value: SCENARIOS.length,
            label: 'Scenarios',
            color: 'text-orange-400',
            iconBg: 'bg-orange-500/10',
          },
          {
            icon: Target,
            value: categories,
            label: 'Attack Categories',
            color: 'text-purple-400',
            iconBg: 'bg-purple-500/10',
          },
          {
            icon: Activity,
            value: totalRuns,
            label: 'Total Runs',
            color: 'text-blue-400',
            iconBg: 'bg-blue-500/10',
          },
          {
            icon: ShieldCheck,
            value: totalRuns > 0 ? `${blockRate}%` : '—',
            label: 'Success Rate',
            color: 'text-green-400',
            iconBg: 'bg-green-500/10',
            smallValue: totalRuns > 0,
          },
        ].map(({ icon: Icon, value, label, color, iconBg, smallValue }) => (
          <div key={label} className="stat-card p-4 flex items-center gap-4">
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${iconBg}`}>
              <Icon className={`w-5 h-5 ${color}`} />
            </div>
            <div>
              <div className={`font-bold font-mono ${smallValue ? 'text-lg' : 'text-2xl'} ${color}`}>
                {value}
              </div>
              <div className="text-xs text-slate-400">{label}</div>
            </div>
          </div>
        ))}
      </section>

      {/* Quick-launch shortcuts */}
      <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Quick Scenarios card */}
        <div
          role="button"
          tabIndex={0}
          onClick={() => navigate('/scenarios')}
          onKeyDown={e => e.key === 'Enter' && navigate('/scenarios')}
          className="card-hover-orange rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-6 cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-orange-500/50"
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center">
              <Zap className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <div className="text-base font-bold text-slate-100">Quick Scenarios</div>
              <div className="text-xs text-slate-500">Single-technique attacks</div>
            </div>
          </div>
          <p className="text-sm text-slate-400 leading-relaxed mb-4">
            {SCENARIOS.length} focused attack scenarios — SQL injection, XSS, path traversal, credential stuffing, DNS tunneling, data exfiltration. Live WebSocket terminal per run.
          </p>
          <div className="flex items-center gap-1.5 text-sm font-semibold text-orange-400">
            Browse scenarios
            <ChevronRight className="w-4 h-4" />
          </div>
        </div>

        {/* Campaigns card */}
        <div
          role="button"
          tabIndex={0}
          onClick={() => navigate('/scenarios#campaigns')}
          onKeyDown={e => e.key === 'Enter' && navigate('/scenarios#campaigns')}
          className="card-hover-purple rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-6 cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-purple-500/50"
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
              <Swords className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <div className="text-base font-bold text-slate-100">Campaigns</div>
              <div className="text-xs text-slate-500">Multi-phase adversary storylines</div>
            </div>
          </div>
          <p className="text-sm text-slate-400 leading-relaxed mb-4">
            Industry drip-flow campaigns (financial, healthcare, SaaS) and the Agentic AI Breakout CTF — live pacing, phase timelines, and SOC talking points.
          </p>
          <div className="flex items-center gap-1.5 text-sm font-semibold text-purple-400">
            Browse campaigns
            <ChevronRight className="w-4 h-4" />
          </div>
        </div>
      </section>

      {/* Recent Runs */}
      <section>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-bold text-slate-100">Recent Runs</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Last {Math.min(5, recentRuns.length)} of {totalRuns} total — full history in Settings
            </p>
          </div>
          {totalRuns > 0 && (
            <div className="flex items-center gap-1.5 text-xs font-mono text-slate-500 border border-slate-700/50 rounded-full px-3 py-1">
              <Clock className="w-3.5 h-3.5" />
              {formatRelativeTime(lastRun)}
            </div>
          )}
        </div>

        {recentRuns.length === 0 ? (
          <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] p-10 flex flex-col items-center gap-3">
            <Play className="w-8 h-8 text-slate-600" />
            <div className="text-center">
              <p className="text-slate-400 font-medium">No runs yet</p>
              <p className="text-sm text-slate-600 mt-1">Run an attack from the Scenarios page to see history here.</p>
            </div>
            <button onClick={() => navigate('/scenarios')} className="btn-orange mt-2">
              <BookOpen className="w-4 h-4" />
              Browse Scenarios
            </button>
          </div>
        ) : (
          <div className="rounded-xl border border-[#2d1b4e] overflow-hidden">
            {recentRuns.map((entry, i) => {
              const success = entry.exitCode === 0
              return (
                <div
                  key={entry.id || i}
                  role="button"
                  tabIndex={0}
                  onClick={() => navigate(`/scenarios/${entry.scenario}`)}
                  onKeyDown={e => e.key === 'Enter' && navigate(`/scenarios/${entry.scenario}`)}
                  className="flex items-center gap-4 px-5 py-3.5 border-b border-[#1e1235] last:border-0 hover:bg-white/[0.02] transition-colors cursor-pointer group"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-slate-200 truncate">{entry.title}</span>
                    </div>
                    <span className="text-xs text-slate-500 font-mono">{entry.scenario}</span>
                  </div>

                  <span className="text-xs text-slate-500 font-mono whitespace-nowrap hidden sm:block">
                    {formatTime(entry.timestamp)}
                  </span>

                  <div className="shrink-0">
                    {success ? (
                      <div className="flex items-center gap-1 text-green-400 text-xs">
                        <CheckCircle className="w-3.5 h-3.5" />
                        <span className="hidden sm:inline">Done</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1 text-red-400 text-xs">
                        <XCircle className="w-3.5 h-3.5" />
                        <span className="hidden sm:inline">Error</span>
                      </div>
                    )}
                  </div>

                  <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-orange-400 transition-colors shrink-0" />
                </div>
              )
            })}
          </div>
        )}
      </section>
    </div>
  )
}
