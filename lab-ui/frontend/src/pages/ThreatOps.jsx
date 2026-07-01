import { useState, useEffect, useRef, useCallback } from 'react'
import {
  Swords, Play, Square, Trash2, RefreshCw,
  Radio, Moon, ChevronDown, Shield, Bot,
  Syringe, Zap, AlertTriangle, CheckCircle2, Clock,
} from 'lucide-react'

// ── Engine constants (mirror backend) ────────────────────────────────────────
const LIVE_BATCH_SECONDS = 30
const LIVE_PHASE_SECONDS = 180
const CTF_LIVE_PHASE_SECONDS = 90

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmtTime(s) {
  const m = Math.floor(s / 60)
  const sec = s % 60
  return `${m}:${String(sec).padStart(2, '0')}`
}

// ── Static CTF box metadata (rendered immediately; enriched from API) ─────────
const CTF_BOXES_META = [
  {
    num: 1,
    icon: Shield,
    name: 'CF WAF',
    sub: 'Recon + Rule Triggers',
    desc: 'Scanner recon, SQLi probes, and header anomalies that light up CF Managed Rules.',
  },
  {
    num: 2,
    icon: Bot,
    name: 'Bot Management',
    sub: 'Constant JA4, Rotating UA',
    desc: 'Polymorphic bot changes User-Agent every request — but JA4 fingerprint never changes.',
  },
  {
    num: 3,
    icon: Syringe,
    name: 'Firewall for AI',
    sub: 'Prompt Injection Attack',
    desc: 'Rogue AI fires prompt injection at /api/v1/chat — jailbreaks, DAN mode, JNDI in prompts.',
  },
  {
    num: 4,
    icon: Zap,
    name: 'Agentic Breakout',
    sub: 'Full Multi-Vector Storm',
    desc: 'All vectors combined at high volume — RCE, SQLi, XSS, AI injection across every endpoint.',
  },
]

// ── Sub-components ────────────────────────────────────────────────────────────

function SectionLabel({ children, className = '' }) {
  return (
    <div className={`flex items-center gap-2 mb-3 ${className}`}>
      <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-slate-500">
        {children}
      </span>
      <div className="flex-1 h-px bg-slate-800" />
    </div>
  )
}

/** Stats bar — 4 cells */
function StatsBar({ stats }) {
  const rate = stats.total > 0 ? Math.round((stats.blocked / stats.total) * 100) : 0
  return (
    <div className="grid grid-cols-4 gap-3 mb-6">
      {[
        { label: 'Requests Sent', value: stats.total,   color: 'text-blue-400' },
        { label: 'Blocked by WAF', value: stats.blocked, color: 'text-red-400' },
        { label: 'Passed Through', value: stats.passed,  color: 'text-orange-400' },
        { label: 'Block Rate',     value: rate + '%',    color: 'text-green-400' },
      ].map(({ label, value, color }) => (
        <div key={label} className="stat-card p-3 rounded-xl">
          <div className={`text-2xl font-bold font-mono ${color}`}>{value}</div>
          <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mt-0.5">
            {label}
          </div>
        </div>
      ))}
    </div>
  )
}

/** Phase timeline — done/active/pending nodes with connecting lines */
function PhaseTimeline({ phases, activePhase, campaignColor }) {
  if (!phases.length) return null
  const color = campaignColor || '#f38020'
  return (
    <div className="flex items-center gap-0 py-2 overflow-x-auto">
      {phases.map((ph, i) => {
        const num = i + 1
        const isDone = num < activePhase
        const isActive = num === activePhase
        return (
          <div key={num} className="flex items-center flex-1 min-w-0">
            <div className="flex flex-col items-center min-w-0">
              <div
                className={`
                  w-8 h-8 rounded-full border-2 flex items-center justify-center text-xs font-mono font-bold z-10 relative shrink-0 transition-all duration-300
                  ${isDone
                    ? 'bg-green-500/20 border-green-500 text-green-400'
                    : isActive
                    ? 'border-orange-400 text-orange-400 bg-orange-500/10'
                    : 'border-slate-700 text-slate-600 bg-bg-card'
                  }
                  ${isActive ? 'shadow-[0_0_0_4px_rgba(243,128,32,0.15)]' : ''}
                `}
                style={isActive ? { borderColor: color, color } : {}}
              >
                {isDone ? <CheckCircle2 className="w-3.5 h-3.5" /> : num}
              </div>
              <div
                className={`
                  text-[10px] text-center mt-1 max-w-[64px] font-medium leading-tight
                  ${isDone ? 'text-green-400' : isActive ? 'text-orange-400 font-bold' : 'text-slate-600'}
                `}
                style={isActive ? { color } : {}}
              >
                {ph.name.split(' ').slice(0, 2).join(' ')}
              </div>
            </div>
            {i < phases.length - 1 && (
              <div
                className={`
                  flex-1 h-0.5 mx-0.5 mb-4 transition-all duration-300
                  ${isDone ? 'bg-green-500' : isActive ? 'bg-gradient-to-r from-green-500 to-orange-400' : 'bg-slate-800'}
                `}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}

/** Talking-points panel */
function TalkingPoints({ phase, campaignColor }) {
  if (!phase) {
    return (
      <div className="text-center text-slate-600 text-sm py-8 font-mono">
        // Launch a campaign to see live talking points here
      </div>
    )
  }
  const color = campaignColor || '#f38020'
  return (
    <div className="rounded-xl border border-[#2d1b4e] overflow-hidden">
      <div
        className="px-4 py-2.5 text-sm font-bold text-white flex items-center justify-between"
        style={{ backgroundColor: color }}
      >
        <span>Phase {phase.number}</span>
        <span className="text-xs font-normal opacity-90">{phase.name}</span>
      </div>
      <div className="p-4 space-y-3 bg-[#1a0a2e]">
        {phase.description && (
          <p className="text-xs text-slate-500 italic leading-relaxed">{phase.description}</p>
        )}
        {[
          { key: 'what_fires',         label: 'What Fires',      badge: 'bg-blue-900/40 text-blue-300 border border-blue-800' },
          { key: 'cloudflare_story',   label: 'Cloudflare',      badge: 'bg-orange-900/30 text-orange-300 border border-orange-800/50' },
          { key: 'sentinelone_story',  label: 'SentinelOne AI',  badge: 'bg-purple-900/30 text-purple-300 border border-purple-800/50' },
          { key: 'hyperautomation',    label: 'Hyperautomation', badge: 'bg-green-900/30 text-green-300 border border-green-800/50' },
        ].map(({ key, label, badge }) => phase[key] ? (
          <div key={key} className="flex gap-2.5 items-start">
            <span className={`shrink-0 text-[10px] font-mono font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded mt-0.5 whitespace-nowrap ${badge}`}>
              {label}
            </span>
            {/* Check if the value contains a PowerQuery/code snippet */}
            {phase[key].includes('\n') || phase[key].includes('SELECT') || phase[key].includes('EventType') ? (
              <pre className="code-block text-xs leading-relaxed flex-1 overflow-x-auto whitespace-pre-wrap break-all">
                <code className="text-purple-300">{phase[key]}</code>
              </pre>
            ) : (
              <span className="text-xs text-slate-300 leading-relaxed flex-1">{phase[key]}</span>
            )}
          </div>
        ) : null)}
        {phase.ctf_hint && (
          <div className="flex gap-2.5 items-start border-t border-[#2d1b4e] pt-3 mt-1">
            <span className="shrink-0 text-[10px] font-mono font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded mt-0.5 bg-yellow-900/40 text-yellow-300 border border-yellow-800/50">
              CTF Hint
            </span>
            <span className="text-xs text-yellow-200/80 font-mono leading-relaxed flex-1">{phase.ctf_hint}</span>
          </div>
        )}
      </div>
    </div>
  )
}

/** Color-coded live log terminal */
function LogTerminal({ entries, onClear }) {
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [entries.length])

  const tagStyle = {
    BLOCKED: 'bg-red-500/20 text-red-400',
    PASSED:  'bg-green-500/20 text-green-400',
    PHASE:   'bg-orange-500/20 text-orange-400',
    ERROR:   'bg-white/5 text-slate-500',
    INFO:    'bg-blue-500/20 text-blue-400',
  }

  function getTag(entry) {
    if (entry.type === 'blocked') return 'BLOCKED'
    if (entry.type === 'passed')  return 'PASSED'
    if (entry.type === 'phase')   return 'PHASE'
    if (entry.type === 'error')   return 'ERROR'
    return 'INFO'
  }

  function getMsg(entry) {
    if (entry.type === 'blocked' || entry.type === 'passed') {
      return `[${entry.method || 'GET'}] ${entry.url || ''} — ${entry.label || ''} — HTTP ${entry.status || '?'} — src: ${entry.ip || ''}`
    }
    return entry.text || entry.line || entry.message || entry.label || ''
  }

  return (
    <div className="rounded-xl border border-[#2d1b4e] overflow-hidden flex flex-col" style={{ minHeight: 400 }}>
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#2d1b4e] bg-[#1a0a2e]">
        <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
          <Radio className="w-3 h-3 text-orange-400" />
          Live Attack Log
        </span>
        <button
          onClick={onClear}
          className="flex items-center gap-1 text-xs text-slate-600 hover:text-slate-300 transition-colors font-mono"
        >
          <Trash2 className="w-3 h-3" /> Clear
        </button>
      </div>
      <div
        className="terminal-scroll flex-1 overflow-y-auto p-3 font-mono text-xs leading-relaxed"
        style={{ backgroundColor: '#0a0a0a', height: 480 }}
      >
        {entries.length === 0 ? (
          <div className="text-slate-700 text-center pt-20">
            // Select a campaign + mode above, then press Launch
          </div>
        ) : (
          entries.map((entry, idx) => {
            const tag = getTag(entry)
            const msg = getMsg(entry)
            const ts = entry.ts || new Date().toLocaleTimeString('en-US', { hour12: false })
            return (
              <div key={idx} className="flex gap-2 items-baseline mb-0.5">
                <span className="text-slate-700 shrink-0 text-[10px]">{ts}</span>
                <span className={`shrink-0 w-16 text-center px-1 py-px rounded text-[10px] font-semibold ${tagStyle[tag] || tagStyle.INFO}`}>
                  {tag}
                </span>
                <span className="text-slate-400 break-all">{msg}</span>
              </div>
            )
          })
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

/** CTF 4-box grid */
function CTFBoxGrid({ activePhase, boxStates }) {
  // boxStates: { 1: 'waiting'|'firing'|'done', ... }
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
      {CTF_BOXES_META.map(({ num, icon: BoxIcon, name, sub, desc }) => {
        const state = boxStates[num] || 'waiting'
        const isFiring = state === 'firing'
        const isDone   = state === 'done'
        return (
          <div
            key={num}
            className={`
              rounded-xl border-2 p-4 transition-all duration-300
              ${isDone
                ? 'border-green-500/50 bg-green-500/5'
                : isFiring
                ? 'border-orange-500/70 bg-orange-500/5'
                : 'border-[#2d1b4e] bg-[#1a0a2e]'
              }
              ${isFiring ? 'shadow-[0_0_0_3px_rgba(243,128,32,0.15)] animate-pulse-slow' : ''}
            `}
          >
            <div className="text-[10px] font-mono font-bold uppercase tracking-widest text-orange-400/70 mb-1">
              Box {num}
            </div>
            <BoxIcon
              className={`w-7 h-7 mb-2 ${isDone ? 'text-green-400' : isFiring ? 'text-orange-400' : 'text-slate-600'}`}
              strokeWidth={1.5}
            />
            <div className="font-semibold text-sm text-slate-200 mb-0.5">{name}</div>
            <div className="text-[10px] font-mono text-orange-400/70 mb-1.5">{sub}</div>
            <div className="text-xs text-slate-500 leading-relaxed">{desc}</div>
            <div
              className={`mt-2 text-[10px] font-mono font-semibold ${
                isDone ? 'text-green-400' : isFiring ? 'text-orange-400' : 'text-slate-700'
              }`}
            >
              {isDone ? '✓ complete' : isFiring ? '▶ firing...' : 'waiting'}
            </div>
          </div>
        )
      })}
    </div>
  )
}

/** Live countdown strip */
function LiveCountdown({ mode, activePhase, phaseStart, batchCountdown, isCTF }) {
  if (mode !== 'live' || !activePhase) return null
  const phaseDur = isCTF ? CTF_LIVE_PHASE_SECONDS : LIVE_PHASE_SECONDS
  const elapsed = phaseStart ? Math.floor((Date.now() - phaseStart) / 1000) : 0
  const phaseRemaining = Math.max(0, phaseDur - elapsed)

  return (
    <div
      className="rounded-lg px-4 py-2.5 font-mono text-xs flex flex-wrap gap-4 mb-4"
      style={{ backgroundColor: '#1a1a2e', color: '#a0aec0' }}
    >
      <div className="flex flex-col gap-0.5">
        <span className="text-base font-medium text-slate-200">Phase {activePhase}</span>
        <span className="text-[10px] uppercase tracking-widest text-slate-600">Current Phase</span>
      </div>
      <div className="flex flex-col gap-0.5">
        <span className="text-base font-medium text-slate-200">{batchCountdown}s</span>
        <span className="text-[10px] uppercase tracking-widest text-slate-600">Next Batch</span>
      </div>
      <div className="flex flex-col gap-0.5">
        <span className="text-base font-medium text-slate-200">{fmtTime(phaseRemaining)}</span>
        <span className="text-[10px] uppercase tracking-widest text-slate-600">Phase Advances</span>
      </div>
    </div>
  )
}

// ── Campaign color/icon map (fallback before API load) ─────────────────────
const CAMPAIGN_COLORS = {
  financial:  '#1a5276',
  healthcare: '#1e8449',
  saas:       '#6c3483',
  ctf:        '#7c2d12',
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function ThreatOps() {
  // Campaign data from API
  const [campaigns, setCampaigns] = useState([])
  const [loadingCampaigns, setLoadingCampaigns] = useState(true)

  // Controls
  const [selectedCampaign, setSelectedCampaign] = useState(null) // campaign key
  const [mode, setMode] = useState('preseed')   // 'preseed' | 'live'
  const [phase, setPhase] = useState('all')      // 'all' | '1'..'N'
  const [volume, setVolume] = useState('medium') // 'low' | 'medium' | 'high'

  // Runtime
  const [running, setRunning] = useState(false)
  const [activePhase, setActivePhase] = useState(0)
  const [activeCampaignKey, setActiveCampaignKey] = useState(null)

  // Log + stats
  const [logEntries, setLogEntries] = useState([])
  const [stats, setStats] = useState({ total: 0, blocked: 0, passed: 0 })

  // CTF box states: { 1: 'waiting'|'firing'|'done' }
  const [ctfBoxStates, setCtfBoxStates] = useState({ 1: 'waiting', 2: 'waiting', 3: 'waiting', 4: 'waiting' })

  // Live countdown timers
  const [phaseStart, setPhaseStart] = useState(null)
  const [batchCountdown, setBatchCountdown] = useState(LIVE_BATCH_SECONDS)

  // Refs
  const pollRef   = useRef(null)
  const timerRef  = useRef(null)
  const lastIdRef = useRef(0)

  // ── Load campaigns on mount ──────────────────────────────────────────────
  useEffect(() => {
    fetch('/api/campaigns')
      .then(r => r.json())
      .then(data => {
        setCampaigns(Array.isArray(data) ? data : [])
        if (data.length > 0) setSelectedCampaign(data[0].key)
      })
      .catch(() => setCampaigns([]))
      .finally(() => setLoadingCampaigns(false))
  }, [])

  // ── Also load initial running status ────────────────────────────────────
  useEffect(() => {
    fetch('/api/campaign/status')
      .then(r => r.json())
      .then(data => {
        if (data.running) {
          setRunning(true)
          setActivePhase(data.phase || 0)
          setActiveCampaignKey(data.campaign)
          startPolling()
          if (mode === 'live') startLiveTimer(data.phase || 1)
        }
      })
      .catch(() => {})
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // ── Cleanup on unmount ──────────────────────────────────────────────────
  useEffect(() => {
    return () => {
      clearInterval(pollRef.current)
      clearInterval(timerRef.current)
    }
  }, [])

  // ── Helpers ──────────────────────────────────────────────────────────────
  const isCTF = (activeCampaignKey || selectedCampaign) === 'ctf'

  const activeCampaignData = campaigns.find(
    c => c.key === (activeCampaignKey || selectedCampaign)
  )
  const activePhaseData = activeCampaignData?.phases?.[activePhase - 1] || null
  const campaignColor = CAMPAIGN_COLORS[activeCampaignKey || selectedCampaign] || '#f38020'
  const phases = activeCampaignData?.phases || []

  function processEntry(entry) {
    const tag = entry.type
    if (tag === 'blocked') {
      setStats(s => ({ total: s.total + 1, blocked: s.blocked + 1, passed: s.passed }))
    } else if (tag === 'passed') {
      setStats(s => ({ total: s.total + 1, blocked: s.blocked, passed: s.passed + 1 }))
    }
    // Timestamp the entry for display
    const ts = new Date().toLocaleTimeString('en-US', { hour12: false })
    setLogEntries(prev => [...prev, { ...entry, ts }])
  }

  function updateCTFBoxStates(phaseNum) {
    setCtfBoxStates({
      1: phaseNum > 1 ? 'done' : phaseNum === 1 ? 'firing' : 'waiting',
      2: phaseNum > 2 ? 'done' : phaseNum === 2 ? 'firing' : 'waiting',
      3: phaseNum > 3 ? 'done' : phaseNum === 3 ? 'firing' : 'waiting',
      4: phaseNum > 4 ? 'done' : phaseNum === 4 ? 'firing' : 'waiting',
    })
  }

  const startLiveTimer = useCallback((initialPhase = 1) => {
    clearInterval(timerRef.current)
    setPhaseStart(Date.now())
    setBatchCountdown(LIVE_BATCH_SECONDS)
    timerRef.current = setInterval(() => {
      setBatchCountdown(prev => {
        if (prev <= 1) return LIVE_BATCH_SECONDS
        return prev - 1
      })
    }, 1000)
  }, [])

  const startPolling = useCallback(() => {
    clearInterval(pollRef.current)
    pollRef.current = setInterval(async () => {
      try {
        const res  = await fetch(`/api/campaign/logs?since=${lastIdRef.current}`)
        const data = await res.json()

        data.entries?.forEach(entry => {
          processEntry(entry)
          if (entry.id) lastIdRef.current = Math.max(lastIdRef.current, entry.id)

          if (entry.phase && entry.phase !== activePhase) {
            setActivePhase(entry.phase)
            if ((activeCampaignKey || selectedCampaign) === 'ctf') {
              updateCTFBoxStates(entry.phase)
            }
            if (mode === 'live') {
              setPhaseStart(Date.now())
              setBatchCountdown(LIVE_BATCH_SECONDS)
            }
          }
        })

        if (!data.running && lastIdRef.current > 0) {
          stopPolling()
          handleComplete(data)
        }
      } catch (_) { /* server briefly unavailable */ }
    }, 1000)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, activePhase, activeCampaignKey, selectedCampaign])

  function stopPolling() {
    clearInterval(pollRef.current)
    clearInterval(timerRef.current)
    pollRef.current = null
    timerRef.current = null
  }

  function handleComplete(data) {
    setRunning(false)
    if ((data?.campaign || activeCampaignKey) === 'ctf') {
      updateCTFBoxStates(5) // mark all done
    }
  }

  // ── Launch ────────────────────────────────────────────────────────────────
  async function handleLaunch() {
    if (!selectedCampaign) return

    // Check if already running
    try {
      const statusRes = await fetch('/api/campaign/status')
      const statusData = await statusRes.json()
      if (statusData.running) {
        setLogEntries(prev => [...prev, {
          type: 'error',
          text: 'A campaign is already running — press Stop first.',
          ts: new Date().toLocaleTimeString('en-US', { hour12: false })
        }])
        return
      }
    } catch (_) {}

    // Reset state
    setLogEntries([])
    setStats({ total: 0, blocked: 0, passed: 0 })
    lastIdRef.current = 0
    setActivePhase(0)
    setActiveCampaignKey(selectedCampaign)
    if (selectedCampaign === 'ctf') {
      setCtfBoxStates({ 1: 'waiting', 2: 'waiting', 3: 'waiting', 4: 'waiting' })
    }

    const body = {
      campaign: selectedCampaign,
      mode,
      phase: mode === 'preseed' ? phase : 'all',
      volume,
    }

    try {
      const res = await fetch('/api/campaign/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })

      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        setLogEntries([{
          type: 'error',
          text: err.error || `Launch failed (HTTP ${res.status})`,
          ts: new Date().toLocaleTimeString('en-US', { hour12: false })
        }])
        return
      }
    } catch (e) {
      setLogEntries([{
        type: 'error',
        text: 'Could not reach backend — is it running?',
        ts: new Date().toLocaleTimeString('en-US', { hour12: false })
      }])
      return
    }

    setRunning(true)
    startPolling()
    if (mode === 'live') startLiveTimer(1)
  }

  // ── Stop ──────────────────────────────────────────────────────────────────
  async function handleStop() {
    try { await fetch('/api/campaign/stop', { method: 'POST' }) } catch (_) {}
    stopPolling()
    setRunning(false)
    setLogEntries(prev => [...prev, {
      type: 'info',
      text: 'Campaign stopped by user.',
      ts: new Date().toLocaleTimeString('en-US', { hour12: false })
    }])
  }

  // ── Clear Pyxis incident ──────────────────────────────────────────────────
  const [clearingIncident, setClearingIncident] = useState(false)
  async function handleClearIncident() {
    setClearingIncident(true)
    try {
      await fetch('/api/campaign/clear-incident', { method: 'POST' })
      setLogEntries(prev => [...prev, {
        type: 'info',
        text: 'NovaMind/Pyxis status page incident cleared.',
        ts: new Date().toLocaleTimeString('en-US', { hour12: false })
      }])
    } catch (_) {
      setLogEntries(prev => [...prev, {
        type: 'error',
        text: 'Failed to reach clear-incident endpoint.',
        ts: new Date().toLocaleTimeString('en-US', { hour12: false })
      }])
    } finally {
      setClearingIncident(false)
    }
  }

  // ── Compute phase buttons for selected campaign ───────────────────────────
  const selectedCampaignData = campaigns.find(c => c.key === selectedCampaign)
  const numPhases = selectedCampaignData?.num_phases || selectedCampaignData?.phases?.length || 5
  const phaseButtons = ['all', ...Array.from({ length: numPhases }, (_, i) => String(i + 1))]

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="page-enter space-y-6 max-w-screen-xl mx-auto">

      {/* Page header */}
      <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5 flex items-start gap-4">
        <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-orange-500/10 border border-orange-500/20 shrink-0">
          <Swords className="w-6 h-6 text-orange-400" strokeWidth={1.5} />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-slate-100">ThreatOps Campaigns</h1>
          <p className="text-slate-400 text-sm mt-1 leading-relaxed">
            Drip-flow attack console — industry campaigns + Agentic AI Breakout CTF. Targets NovaMind Technologies on Cloudflare.
          </p>
        </div>
        <div className="ml-auto shrink-0 flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full transition-colors ${running ? 'bg-red-400 animate-pulse' : 'bg-green-500'}`} />
          <span className="text-xs font-mono text-slate-500">{running ? 'Running...' : 'Idle'}</span>
        </div>
      </div>

      {/* Stats bar */}
      <StatsBar stats={stats} />

      {/* Campaign picker */}
      <div>
        <SectionLabel>Step 1 — Select Campaign</SectionLabel>
        {loadingCampaigns ? (
          <div className="text-slate-600 text-sm font-mono animate-pulse">Loading campaigns...</div>
        ) : campaigns.length === 0 ? (
          <div className="rounded-xl border border-[#2d1b4e] p-6 text-center">
            <AlertTriangle className="w-6 h-6 text-orange-400 mx-auto mb-2" />
            <p className="text-slate-400 text-sm">
              Backend not reachable. Start the lab-ui backend to load campaign data.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {campaigns.map(c => {
              const color = CAMPAIGN_COLORS[c.key] || '#f38020'
              const isSelected = selectedCampaign === c.key
              return (
                <button
                  key={c.key}
                  onClick={() => { setSelectedCampaign(c.key); setPhase('all') }}
                  disabled={running}
                  className={`
                    text-left rounded-xl border-2 p-4 transition-all duration-200 cursor-pointer
                    ${isSelected ? 'shadow-lg' : 'border-[#2d1b4e] bg-[#1a0a2e] hover:border-slate-600'}
                    ${running ? 'opacity-50 cursor-not-allowed' : ''}
                  `}
                  style={isSelected ? {
                    borderColor: color,
                    backgroundColor: `${color}14`,
                  } : {}}
                >
                  <div className="text-2xl mb-2">{c.icon || '🎯'}</div>
                  <div className="font-bold text-sm text-slate-200 mb-0.5">{c.name}</div>
                  <div
                    className="text-[10px] font-mono font-semibold mb-1"
                    style={{ color }}
                  >
                    {c.campaign}
                  </div>
                  {isSelected && (
                    <div
                      className="absolute top-2 right-2 w-5 h-5 rounded-full flex items-center justify-center text-white text-[10px]"
                      style={{ backgroundColor: color }}
                    >
                      ✓
                    </div>
                  )}
                </button>
              )
            })}
          </div>
        )}
      </div>

      {/* CTF box grid — only shown when ctf is selected */}
      {selectedCampaign === 'ctf' && (
        <div>
          <SectionLabel>CTF Boxes — Highlights as each box fires</SectionLabel>
          <CTFBoxGrid activePhase={activePhase} boxStates={ctfBoxStates} />
        </div>
      )}

      {/* Step 2: Controls + right panel */}
      <div>
        <SectionLabel>Step 2 — Configure &amp; Launch</SectionLabel>
        <div className="grid grid-cols-1 lg:grid-cols-[380px_1fr] gap-4 items-start">

          {/* Left: controls */}
          <div className="space-y-4">

            {/* Mode card */}
            <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] overflow-hidden">
              <div className="px-4 py-2.5 border-b border-[#2d1b4e] bg-[#1f0d38]">
                <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-500">
                  Demo Mode
                </span>
              </div>
              <div className="p-4 space-y-4">

                {/* Mode buttons */}
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { val: 'preseed', label: 'Pre-seed',  sub: 'Fast · night before demo', icon: Moon },
                    { val: 'live',    label: 'Live Mode',  sub: 'Slow drip · during demo',  icon: Radio },
                  ].map(({ val, label, sub, icon: ModeIcon }) => (
                    <button
                      key={val}
                      onClick={() => setMode(val)}
                      disabled={running}
                      className={`
                        text-left rounded-lg border-2 px-3 py-2.5 transition-all duration-150
                        ${mode === val
                          ? 'border-orange-500 text-orange-400 bg-orange-500/10'
                          : 'border-[#2d1b4e] text-slate-400 hover:border-slate-600 hover:text-slate-200'
                        }
                        ${running ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                      `}
                    >
                      <div className="flex items-center gap-1.5 font-semibold text-sm mb-0.5">
                        <ModeIcon className="w-3.5 h-3.5" />
                        {label}
                      </div>
                      <div className="text-[10px] text-slate-600">{sub}</div>
                    </button>
                  ))}
                </div>

                {/* Pre-seed options */}
                {mode === 'preseed' && (
                  <div className="space-y-3">
                    <div>
                      <div className="text-[10px] font-mono font-semibold uppercase tracking-widest text-slate-600 mb-2">
                        Phase Selection
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {phaseButtons.map(p => (
                          <button
                            key={p}
                            onClick={() => setPhase(p)}
                            disabled={running}
                            className={`
                              rounded-lg border-2 px-3 py-1 text-sm font-semibold transition-all duration-150
                              ${phase === p
                                ? 'border-orange-500 text-orange-400 bg-orange-500/10'
                                : 'border-[#2d1b4e] text-slate-500 hover:border-slate-600 hover:text-slate-300'
                              }
                              ${running ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                            `}
                          >
                            {p === 'all' ? 'All Phases' : `Phase ${p}`}
                          </button>
                        ))}
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] font-mono font-semibold uppercase tracking-widest text-slate-600 mb-2">
                        Volume
                      </div>
                      <div className="grid grid-cols-3 gap-1.5">
                        {[
                          { val: 'low',    label: 'Low',    sub: '~40 reqs' },
                          { val: 'medium', label: 'Medium', sub: '~150 reqs' },
                          { val: 'high',   label: 'High',   sub: '~400 reqs' },
                        ].map(({ val, label, sub }) => (
                          <button
                            key={val}
                            onClick={() => setVolume(val)}
                            disabled={running}
                            className={`
                              rounded-lg border-2 py-2 text-center transition-all duration-150
                              ${volume === val
                                ? 'border-orange-500 text-orange-400 bg-orange-500/10'
                                : 'border-[#2d1b4e] text-slate-500 hover:border-slate-600'
                              }
                              ${running ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                            `}
                          >
                            <div className="text-sm font-semibold">{label}</div>
                            <div className="text-[10px] text-slate-600">{sub}</div>
                          </button>
                        ))}
                      </div>
                    </div>
                    <p className="text-xs text-slate-600">
                      Use <strong className="text-slate-400">High → All Phases</strong> the night before to seed 400+ WAF events.
                    </p>
                  </div>
                )}

                {/* Live mode info */}
                {mode === 'live' && (
                  <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-xs text-blue-300 leading-relaxed">
                    Fires <strong>5 requests every 30 seconds</strong> · phases advance every{' '}
                    <strong>{selectedCampaign === 'ctf' ? '1.5 minutes' : '3 minutes'}</strong> · all phases run sequentially.
                    <br />Best for live audience demos — slow enough to narrate each phase.
                    {selectedCampaign === 'ctf' && (
                      <span className="block mt-1 text-orange-300">
                        NovaMind status page will flip to <strong>Incident Detected</strong> automatically.
                      </span>
                    )}
                  </div>
                )}

                {/* Live countdown */}
                <LiveCountdown
                  mode={mode}
                  activePhase={activePhase}
                  phaseStart={phaseStart}
                  batchCountdown={batchCountdown}
                  isCTF={isCTF}
                />

                {/* Launch / Stop */}
                <div className="space-y-2">
                  {!running ? (
                    <button
                      onClick={handleLaunch}
                      disabled={!selectedCampaign}
                      className="btn-orange w-full justify-center py-2.5 text-sm font-bold tracking-wide disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      <Play className="w-4 h-4" />
                      {mode === 'live'
                        ? (selectedCampaign === 'ctf' ? 'Start Live CTF' : 'Start Live Demo')
                        : (selectedCampaign === 'ctf' ? 'Launch CTF Scenario' : 'Launch Campaign')}
                    </button>
                  ) : (
                    <button
                      onClick={handleStop}
                      className="w-full py-2.5 rounded-lg border-2 border-red-500/50 text-red-400 bg-red-500/5 hover:bg-red-500/10 text-sm font-bold tracking-wide flex items-center justify-center gap-2 transition-all"
                    >
                      <Square className="w-4 h-4" />
                      Stop Campaign
                    </button>
                  )}

                  {/* Clear Pyxis incident — CTF only */}
                  {selectedCampaign === 'ctf' && (
                    <button
                      onClick={handleClearIncident}
                      disabled={clearingIncident}
                      className="w-full py-2 rounded-lg border border-green-500/30 text-green-400 bg-transparent hover:bg-green-500/5 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all disabled:opacity-50"
                    >
                      {clearingIncident ? (
                        <><RefreshCw className="w-3 h-3 animate-spin" /> Clearing...</>
                      ) : (
                        <><CheckCircle2 className="w-3 h-3" /> Clear Pyxis Incident</>
                      )}
                    </button>
                  )}
                </div>
              </div>
            </div>

            {/* Phase timeline + talking points */}
            <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] overflow-hidden">
              <div className="px-4 py-2.5 border-b border-[#2d1b4e] bg-[#1f0d38]">
                <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-500">
                  Phase Timeline
                </span>
              </div>
              <div className="p-4 space-y-4">
                <PhaseTimeline
                  phases={phases}
                  activePhase={activePhase}
                  campaignColor={campaignColor}
                />
                <TalkingPoints
                  phase={activePhaseData}
                  campaignColor={campaignColor}
                />
              </div>
            </div>
          </div>

          {/* Right: live log */}
          <LogTerminal
            entries={logEntries}
            onClear={() => {
              setLogEntries([])
              setStats({ total: 0, blocked: 0, passed: 0 })
            }}
          />
        </div>
      </div>
    </div>
  )
}
