import { useState, useEffect, useRef, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Swords, Play, Square, Trash2, RefreshCw,
  Radio, Moon, Shield, Bot,
  Syringe, Zap, AlertTriangle, CheckCircle2, ExternalLink,
} from 'lucide-react'

// ── Engine constants (mirror backend) ────────────────────────────────────────
const LIVE_BATCH_SECONDS    = 30
const LIVE_PHASE_SECONDS    = 180
const CTF_LIVE_PHASE_SECONDS = 90

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmtTime(s) {
  const m = Math.floor(s / 60)
  const sec = s % 60
  return `${m}:${String(sec).padStart(2, '0')}`
}

// ── Static CTF box metadata ────────────────────────────────────────────────
const CTF_BOXES_META = [
  {
    num: 1,
    icon: Shield,
    name: 'CF WAF',
    sub: 'Drop Recon + Rule Triggers',
    desc: 'Bots enumerate hidden drop URLs and probe sensitive paths; scanner UAs and SQLi light up CF Managed Rules.',
  },
  {
    num: 2,
    icon: Bot,
    name: 'Bot Management',
    sub: 'Constant JA4, Rotating UA',
    desc: 'Drop-day sneaker-bot swarm changes User-Agent every request — but the JA4 fingerprint never changes.',
  },
  {
    num: 3,
    icon: Syringe,
    name: 'Firewall for AI + ATO',
    sub: 'Concierge Injection + Stuffing',
    desc: 'Bots hit the SoleDrop concierge (/api/v1/chat) with prompt injection and run credential stuffing on /login.',
  },
  {
    num: 4,
    icon: Zap,
    name: 'Full Breakout',
    sub: 'Multi-Vector Storm',
    desc: 'All vectors at drop-day volume — carding, RCE/SSRF/traversal, and bulk customer-data pulls across every endpoint.',
  },
]

// ── Industry campaign color map ────────────────────────────────────────────
const CAMPAIGN_COLORS = {
  financial:  '#1a5276',
  healthcare: '#1e8449',
  saas:       '#6c3483',
  ctf:        '#7c2d12',
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SectionLabel({ children }) {
  return (
    <div className="flex items-center gap-2 mb-3">
      <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-slate-500">
        {children}
      </span>
      <div className="flex-1 h-px bg-slate-800" />
    </div>
  )
}

/** Stats bar — 4 cells, exact emojis + colors from the original */
function StatsBar({ stats }) {
  const rate = stats.total > 0 ? Math.round((stats.blocked / stats.total) * 100) : 0
  const cells = [
    { emoji: '📡', label: 'Requests Sent',  value: stats.total,   color: 'text-blue-400'   },
    { emoji: '🛑', label: 'Blocked by WAF', value: stats.blocked, color: 'text-red-400'    },
    { emoji: '⚠️', label: 'Passed Through', value: stats.passed,  color: 'text-orange-400' },
    { emoji: '📊', label: 'Block Rate',     value: rate + '%',    color: 'text-green-400'  },
  ]
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
      {cells.map(({ emoji, label, value, color }) => (
        <div key={label} className="stat-card p-4 rounded-xl flex items-center gap-3">
          <span className="text-2xl leading-none">{emoji}</span>
          <div>
            <div className={`text-2xl font-bold font-mono ${color}`}>{value}</div>
            <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mt-0.5">{label}</div>
          </div>
        </div>
      ))}
    </div>
  )
}

/** Phase timeline — done/active/pending nodes with connecting lines */
function PhaseTimeline({ phases, activePhase, campaignColor, showStatus = false }) {
  if (!phases || !phases.length) return null
  const color = campaignColor || '#f38020'
  return (
    <div className="flex items-center gap-0 py-2 overflow-x-auto no-scrollbar">
      {phases.map((ph, i) => {
        const num    = i + 1
        const isDone   = num < activePhase
        const isActive = num === activePhase
        return (
          <div key={num} className="flex items-center flex-1 min-w-0">
            <div className="flex flex-col items-center min-w-0">
              <div
                className={`
                  w-8 h-8 rounded-full border-2 flex items-center justify-center text-xs font-mono font-bold z-10 relative shrink-0 transition-all duration-300
                  ${isDone   ? 'bg-green-500/20 border-green-500 text-green-400'  : ''}
                  ${isActive ? 'bg-orange-500/10'                                 : ''}
                  ${!isDone && !isActive ? 'border-slate-700 text-slate-600 bg-[#1a0a2e]' : ''}
                `}
                style={isActive ? { borderColor: color, color, boxShadow: `0 0 0 4px ${color}26` } : {}}
              >
                {isDone ? <CheckCircle2 className="w-3.5 h-3.5" /> : num}
              </div>
              <div
                className={`
                  text-[10px] text-center mt-1 max-w-[64px] font-medium leading-tight
                  ${isDone   ? 'text-green-400'            : ''}
                  ${isActive ? 'font-bold'                 : ''}
                  ${!isDone && !isActive ? 'text-slate-600' : ''}
                `}
                style={isActive ? { color } : {}}
              >
                {ph.name ? ph.name.split(' ').slice(0, 2).join(' ') : `Ph ${num}`}
              </div>
              {showStatus && (
                <div
                  className="text-[9px] mt-0.5 font-mono uppercase tracking-wide"
                  style={{ color: isDone ? '#4ade80' : isActive ? color : '#64748b' }}
                >
                  {isDone ? 'done' : isActive ? 'running' : 'queued'}
                </div>
              )}
            </div>
            {i < phases.length - 1 && (
              <div
                className={`
                  flex-1 h-0.5 mx-0.5 mb-4 transition-all duration-300
                  ${isDone   ? 'bg-green-500'                                  : ''}
                  ${isActive ? 'bg-gradient-to-r from-green-500 to-orange-400' : ''}
                  ${!isDone && !isActive ? 'bg-slate-800'                       : ''}
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
function TalkingPoints({ phase, campaignColor, emptyMsg }) {
  if (!phase) {
    return (
      <div className="text-center text-slate-400 text-sm py-8 font-mono">
        {emptyMsg || '// Launch a campaign to see live talking points here'}
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
        <span>{phase.number ? `Phase ${phase.number}` : ''}</span>
        <span className="text-xs font-normal opacity-90">{phase.name}</span>
      </div>
      <div className="p-4 space-y-3 bg-[#1a0a2e]">
        {phase.description && (
          <p className="text-xs text-slate-300 italic leading-relaxed">{phase.description}</p>
        )}
        {[
          { key: 'what_fires',        label: 'What Fires',      badge: 'bg-blue-900/40 text-blue-300 border border-blue-800/60'           },
          { key: 'cloudflare_story',  label: 'Cloudflare',      badge: 'bg-orange-900/30 text-orange-300 border border-orange-800/50'     },
          { key: 'sentinelone_story', label: 'SentinelOne AI',  badge: 'bg-purple-900/30 text-purple-300 border border-purple-800/50'     },
          { key: 'hyperautomation',   label: 'Hyperautomation', badge: 'bg-green-900/30 text-green-300 border border-green-800/50'        },
        ].map(({ key, label, badge }) => phase[key] ? (
          <div key={key} className="flex gap-2.5 items-start">
            <span className={`shrink-0 text-[10px] font-mono font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded mt-0.5 whitespace-nowrap ${badge}`}>
              {label}
            </span>
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
function LogTerminal({ entries, onClear, emptyMsg }) {
  const scrollRef = useRef(null)
  // Auto-scroll to the newest line. Keyed on the full entries array (not just
  // its length) and set imperatively on the scroll container, so batched
  // polling updates always pin the view to the bottom of the fixed-height box.
  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [entries])

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
    <div className="rounded-xl border border-[#2d1b4e] overflow-hidden flex flex-col">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#2d1b4e] bg-[#1a0a2e]">
        <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
          <Radio className="w-3 h-3 text-orange-400" />
          Live Attack Log
        </span>
        <button
          onClick={onClear}
          className="flex items-center gap-1 text-xs text-slate-400 hover:text-orange-400 transition-colors font-mono"
        >
          <Trash2 className="w-3 h-3" /> Clear
        </button>
      </div>
      <div
        ref={scrollRef}
        className="terminal-scroll overflow-y-auto p-3 font-mono text-xs leading-relaxed"
        style={{ backgroundColor: '#0a0a0a', minHeight: 280, maxHeight: 480 }}
      >
        {entries.length === 0 ? (
          <div className="text-slate-500 text-center pt-20">
            {emptyMsg || '// Select a campaign + mode above, then press Launch'}
          </div>
        ) : (
          entries.map((entry, idx) => {
            const tag = getTag(entry)
            const msg = getMsg(entry)
            const ts  = entry.ts || new Date().toLocaleTimeString('en-US', { hour12: false })
            return (
              <div key={idx} className="flex gap-2 items-baseline mb-0.5">
                <span className="text-slate-500 shrink-0 text-[10px]">{ts}</span>
                <span className={`shrink-0 w-16 text-center px-1 py-px rounded text-[10px] font-semibold ${tagStyle[tag] || tagStyle.INFO}`}>
                  {tag}
                </span>
                <span className="text-slate-200 break-all">{msg}</span>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}

/** CTF 4-box grid — informational, highlights as phases fire */
function CTFBoxGrid({ boxStates }) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
      {CTF_BOXES_META.map(({ num, icon: BoxIcon, name, sub, desc }) => {
        const state    = boxStates[num] || 'waiting'
        const isFiring = state === 'firing'
        const isDone   = state === 'done'
        return (
          <div
            key={num}
            className={`
              rounded-xl border-2 p-4 transition-all duration-300
              ${isDone   ? 'border-green-500/50 bg-green-500/5'     : ''}
              ${isFiring ? 'border-[#7c2d12]/70 bg-[#7c2d12]/5'     : ''}
              ${!isDone && !isFiring ? 'border-[#2d1b4e] bg-[#1a0a2e]' : ''}
              ${isFiring ? 'shadow-[0_0_0_3px_rgba(124,45,18,0.15)] animate-pulse' : ''}
            `}
          >
            <div className="text-[10px] font-mono font-bold uppercase tracking-widest text-[#7c2d12]/90 mb-1">
              Box {num}
            </div>
            <BoxIcon
              className={`w-7 h-7 mb-2 ${isDone ? 'text-green-400' : isFiring ? 'text-[#b22222]' : 'text-slate-600'}`}
              strokeWidth={1.5}
            />
            <div className="font-semibold text-sm text-slate-200 mb-0.5">{name}</div>
            <div className={`text-[10px] font-mono mb-1.5 ${isFiring ? 'text-[#b22222]' : 'text-[#7c2d12]/70'}`}>{sub}</div>
            <div className="text-xs text-slate-500 leading-relaxed">{desc}</div>
            <div
              className={`mt-2 text-[10px] font-mono font-semibold ${
                isDone ? 'text-green-400' : isFiring ? 'text-[#b22222]' : 'text-slate-700'
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

/** Live countdown strip for live mode */
function LiveCountdown({ mode, activePhase, phaseStart, batchCountdown, isCTF }) {
  if (mode !== 'live' || !activePhase) return null
  const phaseDur = isCTF ? CTF_LIVE_PHASE_SECONDS : LIVE_PHASE_SECONDS
  const elapsed  = phaseStart ? Math.floor((Date.now() - phaseStart) / 1000) : 0
  const phaseRemaining = Math.max(0, phaseDur - elapsed)
  return (
    <div
      className="rounded-lg px-4 py-2.5 font-mono text-xs flex flex-wrap gap-4 mb-4"
      style={{ backgroundColor: '#1a1a2e', color: '#a0aec0' }}
    >
      <div className="flex flex-col gap-0.5">
        <span className="text-base font-medium text-slate-200">Phase {activePhase}</span>
        <span className="text-[10px] uppercase tracking-widest text-slate-400">Current Phase</span>
      </div>
      <div className="flex flex-col gap-0.5">
        <span className="text-base font-medium text-slate-200">{batchCountdown}s</span>
        <span className="text-[10px] uppercase tracking-widest text-slate-400">Next Batch</span>
      </div>
      <div className="flex flex-col gap-0.5">
        <span className="text-base font-medium text-slate-200">{fmtTime(phaseRemaining)}</span>
        <span className="text-[10px] uppercase tracking-widest text-slate-400">Phase Advances</span>
      </div>
    </div>
  )
}

// ── Controls panel shared between tabs ────────────────────────────────────
function ControlsPanel({
  mode, setMode,
  phase, setPhase,
  volume, setVolume,
  phaseButtons,
  running,
  activePhase,
  phaseStart,
  batchCountdown,
  isCTF,
  onLaunch,
  onStop,
  launchLabel,
  children, // extra buttons (e.g. Clear Incident)
}) {
  return (
    <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] overflow-hidden">
      <div className="px-4 py-2.5 border-b border-[#2d1b4e] bg-[#1f0d38]">
        <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-500">
          Demo Mode
        </span>
      </div>
      <div className="p-4 space-y-4">
        {/* Mode row */}
        <div className="grid grid-cols-2 gap-2">
          {[
            { val: 'preseed', label: 'Pre-seed',  sub: 'Fast · night before demo', Icon: Moon  },
            { val: 'live',    label: 'Live Mode',  sub: 'Slow drip · during demo', Icon: Radio },
          ].map(({ val, label, sub, Icon }) => (
            <button
              key={val}
              onClick={() => setMode(val)}
              disabled={running}
              className={`
                text-left rounded-lg border-2 px-3 py-2.5 transition-all duration-150
                ${mode === val
                  ? isCTF
                    ? 'border-[#b22222] text-[#b22222] bg-[#7c2d12]/10'
                    : 'border-orange-500 text-orange-400 bg-orange-500/10'
                  : 'border-[#2d1b4e] text-slate-400 hover:border-slate-600 hover:text-slate-200'
                }
                ${running ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
              `}
            >
              <div className="flex items-center gap-1.5 font-semibold text-sm mb-0.5">
                <Icon className="w-3.5 h-3.5" />{label}
              </div>
              <div className="text-[10px] text-slate-400">{sub}</div>
            </button>
          ))}
        </div>

        {/* Pre-seed options */}
        {mode === 'preseed' && (
          <div className="space-y-3">
            <div>
              <div className="text-[10px] font-mono font-semibold uppercase tracking-widest text-slate-400 mb-2">
                {isCTF ? 'Pre-seed Target' : 'Phase Selection'}
              </div>
              {isCTF ? (
                /* CTF: "All Boxes" prominent + individual boxes */
                <div className="flex flex-col gap-2">
                  <button
                    onClick={() => setPhase('all')}
                    disabled={running}
                    className={`
                      rounded-lg border-2 px-3 py-2.5 text-sm font-semibold transition-all text-left
                      ${phase === 'all'
                        ? 'border-[#b22222] text-[#b22222] bg-[#7c2d12]/10'
                        : 'border-[#2d1b4e] text-slate-500 hover:border-slate-600 hover:text-slate-300'
                      }
                      ${running ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                    `}
                  >
                    🧠 All Boxes{' '}
                    <span className="text-xs font-normal opacity-70">— full CTF scenario (recommended)</span>
                  </button>
                  <div className="text-[10px] font-mono font-semibold uppercase tracking-widest text-slate-400 mt-1">
                    Troubleshoot individual box:
                  </div>
                  <div className="grid grid-cols-4 gap-1.5">
                    {['1','2','3','4'].map(n => (
                      <button
                        key={n}
                        onClick={() => setPhase(n)}
                        disabled={running}
                        className={`
                          rounded-lg border-2 py-2 text-center text-xs font-semibold transition-all
                          ${phase === n
                            ? 'border-[#b22222] text-[#b22222] bg-[#7c2d12]/10'
                            : 'border-[#2d1b4e] text-slate-500 hover:border-slate-600 hover:text-slate-300'
                          }
                          ${running ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                        `}
                      >
                        Box {n}
                        <span className="block text-[10px] opacity-65">
                          {n === '1' ? 'WAF' : n === '2' ? 'Bot Mgmt' : n === '3' ? 'AI Firewall' : 'Breakout'}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                /* Industry: phase buttons */
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
              )}
            </div>

            {/* Volume */}
            <div>
              <div className="text-[10px] font-mono font-semibold uppercase tracking-widest text-slate-400 mb-2">Volume</div>
              <div className="grid grid-cols-3 gap-1.5">
                {[
                  { val: 'low',    label: 'Low',    sub: '~40 reqs'  },
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
                        ? isCTF
                          ? 'border-[#b22222] text-[#b22222] bg-[#7c2d12]/10'
                          : 'border-orange-500 text-orange-400 bg-orange-500/10'
                        : 'border-[#2d1b4e] text-slate-500 hover:border-slate-600'
                      }
                      ${running ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                    `}
                  >
                    <div className="text-sm font-semibold">{label}</div>
                    <div className="text-[10px] text-slate-400">{sub}</div>
                  </button>
                ))}
              </div>
            </div>

            <p className="text-xs text-slate-400">
              {isCTF
                ? <>Use <strong className="text-slate-400">High → All Boxes</strong> to pre-seed all 4 CTF boxes before the event.</>
                : <>Use <strong className="text-slate-400">High → All Phases</strong> the night before to seed 400+ WAF events.</>
              }
            </p>
          </div>
        )}

        {/* Live mode info */}
        {mode === 'live' && (
          <div
            className="rounded-lg border p-3 text-xs leading-relaxed"
            style={{
              background: isCTF ? 'rgba(124,45,18,0.08)' : 'rgba(59,130,246,0.05)',
              borderColor: isCTF ? 'rgba(178,34,34,0.3)' : 'rgba(59,130,246,0.2)',
              color: isCTF ? '#fca5a5' : '#93c5fd',
            }}
          >
            Fires <strong>5 requests every 30 seconds</strong> · phases advance every{' '}
            <strong>{isCTF ? '1.5 minutes' : '3 minutes'}</strong> · all phases run sequentially.
            <br />Best for live audience demos — slow enough to narrate each phase.
            {isCTF && (
              <span className="block mt-1 text-orange-300">
                SoleDrop shop status will flip to <strong>Incident Detected</strong> automatically.
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
              onClick={onLaunch}
              className={`
                w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-bold tracking-wide text-white transition-all
                ${isCTF
                  ? 'bg-[#7c2d12] hover:bg-[#9a3412] shadow-[0_2px_8px_rgba(124,45,18,0.3)]'
                  : 'btn-orange'
                }
              `}
            >
              <Play className="w-4 h-4" />
              {launchLabel}
            </button>
          ) : (
            <button
              onClick={onStop}
              className={`
                w-full py-2.5 rounded-lg border-2 text-sm font-bold tracking-wide flex items-center justify-center gap-2 transition-all
                ${isCTF
                  ? 'border-[#b22222]/50 text-[#b22222] bg-[#b22222]/5 hover:bg-[#b22222]/10'
                  : 'border-red-500/50 text-red-400 bg-red-500/5 hover:bg-red-500/10'
                }
              `}
            >
              <Square className="w-4 h-4" />
              {isCTF ? 'Stop CTF' : 'Stop Campaign'}
            </button>
          )}
          {children}
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function ThreatOps() {
  const [searchParams] = useSearchParams()

  // ── Tab state ────────────────────────────────────────────────────────────
  // Respect ?tab= query param: 'ctf' → CTF tab, 'industry' → Industry tab
  const initialTab = searchParams.get('tab') === 'industry' ? 'industry' : 'ctf'
  const [activeTab, setActiveTab] = useState(initialTab)

  // ── Campaign data from API ────────────────────────────────────────────────
  const [campaigns, setCampaigns] = useState([])
  const [loadingCampaigns, setLoadingCampaigns] = useState(true)

  // ── Industry tab state ────────────────────────────────────────────────────
  // Respect ?campaign= query param for preselection (financial/healthcare/saas)
  const initialCampaign = searchParams.get('campaign') || 'financial'
  const [selectedIndustry, setSelectedIndustry] = useState(initialCampaign)
  const [indMode, setIndMode]   = useState('preseed')
  const [indPhase, setIndPhase] = useState('all')
  const [indVolume, setIndVolume] = useState('medium')

  // ── CTF tab state ─────────────────────────────────────────────────────────
  const [ctfMode, setCtfMode]   = useState('preseed')
  const [ctfPhase, setCtfPhase] = useState('all')
  const [ctfVolume, setCtfVolume] = useState('medium')

  // ── Runtime (shared) ─────────────────────────────────────────────────────
  const [running, setRunning]             = useState(false)
  const [activePhase, setActivePhase]     = useState(0)
  const [activeCampaignKey, setActiveCampaignKey] = useState(null)

  // ── Log + stats (each tab has its own log; stats are shared/global) ───────
  const [indLog, setIndLog]   = useState([])
  const [ctfLog, setCtfLog]   = useState([])
  const [stats, setStats]     = useState({ total: 0, blocked: 0, passed: 0 })

  // ── CTF box states ────────────────────────────────────────────────────────
  const [ctfBoxStates, setCtfBoxStates] = useState({ 1: 'waiting', 2: 'waiting', 3: 'waiting', 4: 'waiting' })

  // ── Live countdown ────────────────────────────────────────────────────────
  const [phaseStart, setPhaseStart]         = useState(null)
  const [batchCountdown, setBatchCountdown] = useState(LIVE_BATCH_SECONDS)

  // ── Clear incident ──────────────────────────────────────────────────
  const [clearingIncident, setClearingIncident] = useState(false)

  // ── Refs ──────────────────────────────────────────────────────────────────
  const pollRef   = useRef(null)
  const timerRef  = useRef(null)
  const lastIdRef = useRef(0)

  // ── Load campaigns ────────────────────────────────────────────────────────
  useEffect(() => {
    fetch('/api/campaigns')
      .then(r => r.json())
      .then(data => {
        // Backend returns a dict { key: {...} }; normalize to an array with `key`.
        const arr = Array.isArray(data)
          ? data
          : Object.entries(data || {})
              .filter(([k]) => k !== '_error')
              .map(([key, v]) => ({ key, ...v }))
        setCampaigns(arr)
      })
      .catch(() => setCampaigns([]))
      .finally(() => setLoadingCampaigns(false))
  }, [])

  // ── Resume on mount if already running ───────────────────────────────────
  useEffect(() => {
    fetch('/api/campaign/status')
      .then(r => r.json())
      .then(data => {
        if (data.running) {
          setRunning(true)
          setActivePhase(data.phase || 0)
          setActiveCampaignKey(data.campaign)
          doStartPolling(data.campaign)
        }
      })
      .catch(() => {})
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // ── Cleanup ───────────────────────────────────────────────────────────────
  useEffect(() => {
    return () => {
      clearInterval(pollRef.current)
      clearInterval(timerRef.current)
    }
  }, [])

  // ── Derived ───────────────────────────────────────────────────────────────
  const currentTabCampaignKey = activeTab === 'ctf' ? 'ctf' : selectedIndustry
  const isCTFTab = activeTab === 'ctf'

  const activeCampaignData = campaigns.find(c => c.key === (activeCampaignKey || currentTabCampaignKey))
  const activePhaseData    = activeCampaignData?.phases?.[activePhase - 1] || null
  const campaignColor      = CAMPAIGN_COLORS[activeCampaignKey || currentTabCampaignKey] || '#f38020'

  // Industry campaigns (all non-ctf)
  const industryCampaigns = campaigns.filter(c => c.key !== 'ctf')
  const selectedCampaignData = campaigns.find(c => c.key === selectedIndustry)
  const numPhases = selectedCampaignData?.phases?.length || 5
  const indPhaseButtons = ['all', ...Array.from({ length: numPhases }, (_, i) => String(i + 1))]

  const indPhases = campaigns.find(c => c.key === selectedIndustry)?.phases || []
  const ctfPhases = campaigns.find(c => c.key === 'ctf')?.phases            || []

  // ── Process incoming log entry ────────────────────────────────────────────
  function processEntry(entry, isCTF) {
    const tag = entry.type
    if (tag === 'blocked') {
      setStats(s => ({ total: s.total + 1, blocked: s.blocked + 1, passed: s.passed }))
    } else if (tag === 'passed') {
      setStats(s => ({ total: s.total + 1, blocked: s.blocked, passed: s.passed + 1 }))
    }
    const ts = new Date().toLocaleTimeString('en-US', { hour12: false })
    const enriched = { ...entry, ts }
    if (isCTF) {
      setCtfLog(prev => [...prev, enriched])
    } else {
      setIndLog(prev => [...prev, enriched])
    }
  }

  function updateCTFBoxStates(phaseNum) {
    setCtfBoxStates({
      1: phaseNum > 1 ? 'done' : phaseNum === 1 ? 'firing' : 'waiting',
      2: phaseNum > 2 ? 'done' : phaseNum === 2 ? 'firing' : 'waiting',
      3: phaseNum > 3 ? 'done' : phaseNum === 3 ? 'firing' : 'waiting',
      4: phaseNum > 4 ? 'done' : phaseNum === 4 ? 'firing' : 'waiting',
    })
  }

  const startLiveTimer = useCallback(() => {
    clearInterval(timerRef.current)
    setPhaseStart(Date.now())
    setBatchCountdown(LIVE_BATCH_SECONDS)
    timerRef.current = setInterval(() => {
      setBatchCountdown(prev => prev <= 1 ? LIVE_BATCH_SECONDS : prev - 1)
    }, 1000)
  }, [])

  function doStartPolling(campaignKey) {
    clearInterval(pollRef.current)
    const isCTFCampaign = campaignKey === 'ctf'
    pollRef.current = setInterval(async () => {
      try {
        const res  = await fetch(`/api/campaign/logs?since=${lastIdRef.current}`)
        const data = await res.json()

        data.entries?.forEach(entry => {
          processEntry(entry, isCTFCampaign)
          if (entry.id) lastIdRef.current = Math.max(lastIdRef.current, entry.id)
          if (entry.phase && entry.phase !== activePhase) {
            setActivePhase(entry.phase)
            if (isCTFCampaign) updateCTFBoxStates(entry.phase)
            setPhaseStart(Date.now())
            setBatchCountdown(LIVE_BATCH_SECONDS)
          }
        })

        if (!data.running && lastIdRef.current > 0) {
          stopPolling()
          handleComplete(isCTFCampaign)
        }
      } catch (_) {}
    }, 1000)
  }

  const startPolling = useCallback((campaignKey) => {
    doStartPolling(campaignKey)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activePhase])

  function stopPolling() {
    clearInterval(pollRef.current)
    clearInterval(timerRef.current)
    pollRef.current  = null
    timerRef.current = null
  }

  function handleComplete(isCTFCampaign) {
    setRunning(false)
    if (isCTFCampaign) updateCTFBoxStates(5) // all done
  }

  // ── Launch (industry) ─────────────────────────────────────────────────────
  async function handleIndLaunch() {
    try {
      const s = await fetch('/api/campaign/status').then(r => r.json())
      if (s.running) {
        setIndLog(prev => [...prev, {
          type: 'error',
          text: 'A campaign is already running — press Stop first.',
          ts: new Date().toLocaleTimeString('en-US', { hour12: false }),
        }])
        return
      }
    } catch (_) {}

    setIndLog([])
    setStats({ total: 0, blocked: 0, passed: 0 })
    lastIdRef.current = 0
    setActivePhase(0)
    setActiveCampaignKey(selectedIndustry)

    const body = {
      campaign: selectedIndustry,
      mode:     indMode,
      phase:    indMode === 'preseed' ? indPhase : 'all',
      volume:   indVolume,
    }

    try {
      const res = await fetch('/api/campaign/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        setIndLog([{ type: 'error', text: err.error || `Launch failed (HTTP ${res.status})`, ts: new Date().toLocaleTimeString('en-US', { hour12: false }) }])
        return
      }
    } catch (_) {
      setIndLog([{ type: 'error', text: 'Could not reach backend — is it running?', ts: new Date().toLocaleTimeString('en-US', { hour12: false }) }])
      return
    }

    setRunning(true)
    startPolling(selectedIndustry)
    if (indMode === 'live') startLiveTimer()
  }

  // ── Launch (CTF) ──────────────────────────────────────────────────────────
  async function handleCtfLaunch() {
    try {
      const s = await fetch('/api/campaign/status').then(r => r.json())
      if (s.running) {
        setCtfLog(prev => [...prev, {
          type: 'error',
          text: 'A campaign is already running — press Stop first.',
          ts: new Date().toLocaleTimeString('en-US', { hour12: false }),
        }])
        return
      }
    } catch (_) {}

    setCtfLog([])
    setStats({ total: 0, blocked: 0, passed: 0 })
    lastIdRef.current = 0
    setActivePhase(0)
    setActiveCampaignKey('ctf')
    setCtfBoxStates({ 1: 'waiting', 2: 'waiting', 3: 'waiting', 4: 'waiting' })

    const body = {
      campaign: 'ctf',
      mode:     ctfMode,
      phase:    ctfMode === 'preseed' ? ctfPhase : 'all',
      volume:   ctfVolume,
    }

    try {
      const res = await fetch('/api/campaign/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        setCtfLog([{ type: 'error', text: err.error || `Launch failed (HTTP ${res.status})`, ts: new Date().toLocaleTimeString('en-US', { hour12: false }) }])
        return
      }
    } catch (_) {
      setCtfLog([{ type: 'error', text: 'Could not reach backend — is it running?', ts: new Date().toLocaleTimeString('en-US', { hour12: false }) }])
      return
    }

    setRunning(true)
    startPolling('ctf')
    if (ctfMode === 'live') startLiveTimer()
  }

  // ── Stop ──────────────────────────────────────────────────────────────────
  async function handleStop() {
    try { await fetch('/api/campaign/stop', { method: 'POST' }) } catch (_) {}
    stopPolling()
    setRunning(false)
    const entry = { type: 'info', text: 'Campaign stopped by user.', ts: new Date().toLocaleTimeString('en-US', { hour12: false }) }
    setIndLog(prev => [...prev, entry])
    setCtfLog(prev => [...prev, { ...entry, text: 'CTF scenario stopped by user.' }])
    setCtfBoxStates({ 1: 'waiting', 2: 'waiting', 3: 'waiting', 4: 'waiting' })
  }

  // ── Clear incident ──────────────────────────────────────────────────
  async function handleClearIncident() {
    setClearingIncident(true)
    try {
      await fetch('/api/campaign/clear-incident', { method: 'POST' })
      setCtfLog(prev => [...prev, {
        type: 'info',
        text: 'SoleDrop shop status incident cleared.',
        ts: new Date().toLocaleTimeString('en-US', { hour12: false }),
      }])
    } catch (_) {
      setCtfLog(prev => [...prev, {
        type: 'error',
        text: 'Failed to reach clear-incident endpoint.',
        ts: new Date().toLocaleTimeString('en-US', { hour12: false }),
      }])
    } finally {
      setClearingIncident(false)
    }
  }

  // ── Industry campaign label map ────────────────────────────────────────────
  const indLaunchLabel = indMode === 'live' ? 'Start Live Demo' : 'Launch Campaign'
  const ctfLaunchLabel = ctfMode === 'live' ? 'Start Live CTF'  : '🧠 Launch CTF Scenario'

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="page-enter space-y-5 max-w-screen-xl mx-auto">

      {/* Page header */}
      <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5 flex items-start gap-4">
        <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-orange-500/10 border border-orange-500/20 shrink-0">
          <Swords className="w-6 h-6 text-orange-400" strokeWidth={1.5} />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-slate-100">ThreatOps Campaigns</h1>
          <p className="text-slate-300 text-sm mt-1 leading-relaxed">
            Drip-flow attack console — industry campaigns + the SoleDrop drop-day bot-swarm CTF. Live attacks against Cloudflare-protected targets.
          </p>
        </div>
        <div className="ml-auto shrink-0 flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full transition-colors ${running ? 'bg-red-400 animate-pulse' : 'bg-green-500'}`} />
          <span className="text-xs font-mono text-slate-500">{running ? 'Running...' : 'Idle'}</span>
        </div>
      </div>

      {/* Stats bar — always visible */}
      <StatsBar stats={stats} />

      {/* Two top tabs */}
      <div className="border-b border-[#2d1b4e] flex gap-0 mb-0">
        <button
          onClick={() => setActiveTab('industry')}
          className={`
            px-5 py-2.5 text-sm font-bold transition-all duration-150 border-b-2 -mb-px flex items-center gap-2
            ${activeTab === 'industry'
              ? 'text-orange-400 border-orange-400'
              : 'text-slate-500 border-transparent hover:text-slate-300 hover:border-slate-600'
            }
          `}
        >
          🏭 Industry Campaigns
        </button>
        <button
          onClick={() => setActiveTab('ctf')}
          className={`
            px-5 py-2.5 text-sm font-bold transition-all duration-150 border-b-2 -mb-px flex items-center gap-2
            ${activeTab === 'ctf'
              ? 'text-[#b22222] border-[#b22222]'
              : 'text-slate-500 border-transparent hover:text-slate-300 hover:border-slate-600'
            }
          `}
        >
          🧠 OneFlare CTF
        </button>
      </div>

      {/* ── INDUSTRY CAMPAIGNS TAB ── */}
      {activeTab === 'industry' && (
        <div className="space-y-5 pt-2">

          {/* Step 1: Select Industry */}
          <div>
            <SectionLabel>Step 1 — Select Industry</SectionLabel>
            {loadingCampaigns ? (
              <div className="text-slate-400 text-sm font-mono animate-pulse">Loading campaigns...</div>
            ) : industryCampaigns.length === 0 ? (
              <div className="rounded-xl border border-[#2d1b4e] p-6 text-center">
                <AlertTriangle className="w-6 h-6 text-orange-400 mx-auto mb-2" />
                <p className="text-slate-400 text-sm">Backend not reachable. Start the lab-ui backend to load campaign data.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {industryCampaigns.map(c => {
                  const color      = CAMPAIGN_COLORS[c.key] || '#f38020'
                  const isSelected = selectedIndustry === c.key
                  return (
                    <button
                      key={c.key}
                      onClick={() => { if (!running) setSelectedIndustry(c.key) }}
                      disabled={running}
                      className={`
                        relative text-left rounded-xl border-2 p-4 transition-all duration-200
                        ${isSelected ? 'shadow-lg' : 'border-[#2d1b4e] bg-[#1a0a2e] hover:border-slate-600'}
                        ${running ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer hover:-translate-y-px'}
                      `}
                      style={isSelected ? { borderColor: color, backgroundColor: `${color}14` } : {}}
                    >
                      {isSelected && (
                        <div
                          className="absolute top-2 right-2 w-5 h-5 rounded-full flex items-center justify-center text-white text-[10px] font-bold"
                          style={{ backgroundColor: color }}
                        >
                          ✓
                        </div>
                      )}
                      <span className="text-2xl mb-2 block">{c.icon || '🎯'}</span>
                      <div className="font-bold text-sm text-slate-200 mb-0.5">{c.name}</div>
                      <div className="text-[10px] font-mono font-semibold mb-1.5" style={{ color }}>
                        {c.campaign}
                      </div>
                      <div className="text-xs text-slate-500 leading-relaxed">{c.description}</div>
                    </button>
                  )
                })}
              </div>
            )}
          </div>

          {/* Step 2: Configure + Launch */}
          <div>
            <SectionLabel>Step 2 — Configure &amp; Launch</SectionLabel>
            <div className="grid grid-cols-1 lg:grid-cols-[380px_1fr] gap-4 items-start">

              {/* Left: controls + timeline */}
              <div className="space-y-4">
                <ControlsPanel
                  mode={indMode}         setMode={setIndMode}
                  phase={indPhase}       setPhase={setIndPhase}
                  volume={indVolume}     setVolume={setIndVolume}
                  phaseButtons={indPhaseButtons}
                  running={running && activeCampaignKey !== 'ctf'}
                  activePhase={activeCampaignKey !== 'ctf' ? activePhase : 0}
                  phaseStart={phaseStart}
                  batchCountdown={batchCountdown}
                  isCTF={false}
                  onLaunch={handleIndLaunch}
                  onStop={handleStop}
                  launchLabel={indLaunchLabel}
                />

                {/* Phase timeline + talking points */}
                <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] overflow-hidden">
                  <div className="px-4 py-2.5 border-b border-[#2d1b4e] bg-[#1f0d38]">
                    <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-500">Phase Timeline</span>
                  </div>
                  <div className="p-4 space-y-4">
                    <PhaseTimeline
                      phases={indPhases.length ? indPhases : Array.from({ length: 5 }, (_, i) => ({ name: `Phase ${i+1}` }))}
                      activePhase={activeCampaignKey !== 'ctf' ? activePhase : 0}
                      campaignColor={CAMPAIGN_COLORS[selectedIndustry] || '#f38020'}
                    />
                    <TalkingPoints
                      phase={activeCampaignKey !== 'ctf' ? activePhaseData : null}
                      campaignColor={CAMPAIGN_COLORS[selectedIndustry]}
                      emptyMsg="// Select an industry and launch a campaign to see live talking points here"
                    />
                  </div>
                </div>
              </div>

              {/* Right: live log */}
              <LogTerminal
                entries={indLog}
                onClear={() => { setIndLog([]); setStats({ total: 0, blocked: 0, passed: 0 }) }}
                emptyMsg="// Select industry + mode above, then press Launch"
              />
            </div>
          </div>
        </div>
      )}

      {/* ── ONEFLARE CTF TAB ── */}
      {activeTab === 'ctf' && (
        <div className="space-y-5 pt-2">

          {/* CTF intro panel */}
          <div
            className="rounded-xl border-l-4 p-4 text-sm leading-relaxed"
            style={{ background: '#fff5f0', borderColor: '#7c2d12', border: '1px solid #f5cba7', borderLeftColor: '#7c2d12', borderLeftWidth: 4, color: '#7c2d12' }}
          >
            <strong className="block mb-1" style={{ color: '#4a1404' }}>
              🤖 OneFlare ThreatOps CTF — Drop-Day Bot Swarm
            </strong>
            A sneaker-bot operation attacks the <strong>SoleDrop shop</strong> across 4 escalating boxes — drop recon,
            bot swarm, concierge injection + account takeover, and a full multi-vector breakout. Each box maps to a
            Cloudflare detection layer; hunt the clues in the <strong>Cloudflare dashboard</strong> and <strong>SentinelOne AI-SIEM</strong>.
            {' '}Target:{' '}
            <code className="text-xs bg-[#7c2d12]/10 px-1.5 py-0.5 rounded font-mono">
              {campaigns.find(c => c.key === 'ctf')?.target || 'shop.soledrop.co'}
            </code>
          </div>

          {/* SoleDrop live-target links */}
          <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] p-4">
            <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5 mb-3">
              <ExternalLink className="w-3 h-3 text-orange-400" /> Live target — SoleDrop shop
            </span>
            <div className="flex flex-wrap gap-2">
              {[
                ['Storefront',        'https://shop.soledrop.co/'],
                ['Status',            'https://shop.soledrop.co/status'],
                ['Admin (Order Ops)', 'https://shop.soledrop.co/admin'],
                ['Login',             'https://shop.soledrop.co/login'],
                ['Account',           'https://shop.soledrop.co/dashboard'],
              ].map(([label, href]) => (
                <a
                  key={href}
                  href={href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#2d1b4e] bg-[#1f0d38] text-xs font-semibold text-slate-200 hover:text-orange-400 hover:border-orange-500/40 transition-colors"
                >
                  {label} <ExternalLink className="w-3 h-3 opacity-60" />
                </a>
              ))}
            </div>
            <p className="text-[11px] text-slate-400 mt-2.5">
              During a run these flip live — <code className="font-mono">/status</code> shows the incident,
              {' '}<code className="font-mono">/admin</code> shows failed orders, and checkout returns errors.
            </p>
          </div>

          {/* CTF Boxes grid */}
          <div>
            <SectionLabel>CTF Boxes — Attack Progression (highlights as each box fires)</SectionLabel>
            <CTFBoxGrid boxStates={ctfBoxStates} />
          </div>

          {/* Step 2 CTF: Configure + Launch */}
          <div>
            <SectionLabel>Step 2 — Configure &amp; Launch CTF</SectionLabel>

            {/* Full-width horizontal box-progress timeline */}
            <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] overflow-hidden mb-4">
              <div className="px-4 py-2.5 border-b border-[#2d1b4e] bg-[#1f0d38] flex items-center justify-between">
                <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">CTF Box Timeline</span>
                <span className="text-xs font-mono text-slate-400">
                  {(() => {
                    const total = ctfPhases.length || 4
                    const ap = activeCampaignKey === 'ctf' ? activePhase : 0
                    if (!ap) return `${total} boxes · not started`
                    return `Box ${ap} of ${total} · ${total - ap} left`
                  })()}
                </span>
              </div>
              <div className="p-4">
                <PhaseTimeline
                  phases={ctfPhases.length ? ctfPhases : [
                    { name: 'Box 1 — CF WAF' },
                    { name: 'Box 2 — Bot Mgmt' },
                    { name: 'Box 3 — AI Firewall + ATO' },
                    { name: 'Box 4 — Breakout' },
                  ]}
                  activePhase={activeCampaignKey === 'ctf' ? activePhase : 0}
                  campaignColor="#7c2d12"
                  showStatus
                />
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-[380px_1fr] gap-4 items-start">

              {/* Left: controls + timeline */}
              <div className="space-y-4">
                <ControlsPanel
                  mode={ctfMode}     setMode={setCtfMode}
                  phase={ctfPhase}   setPhase={setCtfPhase}
                  volume={ctfVolume} setVolume={setCtfVolume}
                  phaseButtons={['all','1','2','3','4']}
                  running={running && activeCampaignKey === 'ctf'}
                  activePhase={activeCampaignKey === 'ctf' ? activePhase : 0}
                  phaseStart={phaseStart}
                  batchCountdown={batchCountdown}
                  isCTF={true}
                  onLaunch={handleCtfLaunch}
                  onStop={handleStop}
                  launchLabel={ctfLaunchLabel}
                >
                  {/* Clear Incident button */}
                  <button
                    onClick={handleClearIncident}
                    disabled={clearingIncident}
                    className="w-full py-2 rounded-lg border border-green-500/30 text-green-400 bg-transparent hover:bg-green-500/5 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all disabled:opacity-50"
                  >
                    {clearingIncident ? (
                      <><RefreshCw className="w-3 h-3 animate-spin" /> Clearing...</>
                    ) : (
                      <><CheckCircle2 className="w-3 h-3" /> Clear Incident</>
                    )}
                  </button>
                </ControlsPanel>

                {/* Hunt clues for the active box */}
                <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] overflow-hidden">
                  <div className="px-4 py-2.5 border-b border-[#2d1b4e] bg-[#1f0d38]">
                    <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">Hunt Clues</span>
                  </div>
                  <div className="p-4">
                    <TalkingPoints
                      phase={activeCampaignKey === 'ctf' ? activePhaseData : null}
                      campaignColor="#7c2d12"
                      emptyMsg="// Select a box and launch the CTF scenario to see hunt clues here"
                    />
                  </div>
                </div>
              </div>

              {/* Right: live log */}
              <LogTerminal
                entries={ctfLog}
                onClear={() => { setCtfLog([]); setStats({ total: 0, blocked: 0, passed: 0 }) }}
                emptyMsg="// Select a CTF box above, then press Launch CTF Scenario"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
