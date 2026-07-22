import { useState, useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import { X, Zap, Square, AlertTriangle, Settings as SettingsIcon, CheckCircle2 } from 'lucide-react'
import Terminal from './Terminal.jsx'
import TargetBar from './TargetBar.jsx'
import { getMe, getTenants, getRunTarget } from '../lib/session.js'
import { buildRunConfig, runScenarioWs, saveRunToHistory } from '../lib/runner.js'

/**
 * "Run All Attacks" — fires every scenario available to the caller concurrently
 * (all at once), streaming into a single terminal with per-scenario [id] prefixes. Admins still pick the console via
 * the shared TargetBar (including the "__all__" fan-out); non-admins are forced
 * to their own subdomain server-side, same as an individual scenario run.
 */
export default function RunAllModal({ scenarios, onClose }) {
  const [lines, setLines] = useState([])
  const [isRunning, setIsRunning] = useState(false)
  const [done, setDone] = useState(false)
  const [progress, setProgress] = useState({ current: 0, total: scenarios.length })
  const [needsLogin, setNeedsLogin] = useState(false)

  const [session, setSession] = useState(null)
  const [serverConfig, setServerConfig] = useState(null)
  const [ready, setReady] = useState(false)

  const socketsRef = useRef([])
  const cancelRef = useRef(false)

  const closeAllSockets = () => {
    socketsRef.current.forEach(ws => { try { ws?.close() } catch { /* noop */ } })
  }

  useEffect(() => {
    let alive = true
    Promise.all([
      getMe(),
      fetch('/api/config').then(r => (r.ok ? r.json() : null)).catch(() => null),
    ]).then(([me, cfg]) => {
      if (!alive) return
      setSession(me)
      setServerConfig(cfg)
      setReady(true)
    })
    return () => {
      alive = false
      cancelRef.current = true
      closeAllSockets()
    }
  }, [])

  // Close on Escape.
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') handleClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  })

  const config = buildRunConfig(serverConfig)
  const isConfigured = !!config.domain
  const append = (line) => setLines(prev => [...prev, line])

  async function handleRunAll() {
    if (isRunning) {
      cancelRef.current = true
      closeAllSockets()
      setIsRunning(false)
      return
    }

    cancelRef.current = false
    socketsRef.current = []
    setLines([])
    setDone(false)
    setNeedsLogin(false)
    setProgress({ current: 0, total: scenarios.length })
    setIsRunning(true)

    const isAdmin = session?.role === 'admin'
    const storedTarget = isAdmin ? getRunTarget() : ''
    const fanOut = isAdmin && storedTarget === '__all__'
    const tenants = fanOut ? await getTenants() : []

    append(`⚡ Launching all ${scenarios.length} attacks in parallel — output is interleaved and tagged [scenario].`)
    append('')

    // Run every scenario concurrently. Each streams into the shared terminal with
    // a [scenario-id] prefix so interleaved lines stay attributable. Progress
    // counts completions as they land (order is non-deterministic in parallel).
    let completed = 0
    const runOne = async (sc) => {
      const label = sc.id
      const handlers = {
        onLine: (line) => append(`[${label}] ${line}`),
        onStart: (name) => append(`► [${label}] ${name}`),
        onError: (message) => {
          append(`[${label}] ERROR: ${message}`)
          if (String(message || '').toLowerCase().includes('log in')) setNeedsLogin(true)
        },
        registerSocket: (ws) => { socketsRef.current.push(ws) },
      }
      try {
        if (fanOut) {
          if (!tenants.length) {
            append(`[${label}] No registered tenants found — nothing to fan out to.`)
          } else {
            for (const t of tenants) {
              if (cancelRef.current) break
              append(`[${label}] ── [${t.subdomain}] ──`)
              await runScenarioWs(sc.id, config, t.subdomain, handlers)
            }
          }
        } else {
          await runScenarioWs(sc.id, config, isAdmin ? storedTarget : '', handlers)
        }
      } finally {
        completed += 1
        setProgress({ current: completed, total: scenarios.length })
      }
    }

    await Promise.all(scenarios.map(runOne))

    append('')
    append(cancelRef.current
      ? `■ Stopped — ${completed}/${scenarios.length} scenario${scenarios.length === 1 ? '' : 's'} finished.`
      : `✓ Done — ran all ${scenarios.length} scenario${scenarios.length === 1 ? '' : 's'} in parallel.`)

    setIsRunning(false)
    setDone(true)
    setLines(prev => {
      saveRunToHistory({ scenario: 'run-all', title: 'Run All Attacks', lines: prev, exitCode: cancelRef.current ? 130 : 0 })
      return prev
    })
  }

  function handleClose() {
    cancelRef.current = true
    closeAllSockets()
    onClose()
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
      onMouseDown={(e) => { if (e.target === e.currentTarget) handleClose() }}
    >
      <div className="w-full max-w-3xl max-h-[90vh] flex flex-col rounded-2xl bg-[#150a26] border border-[#2d1b4e] shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-start justify-between gap-4 p-5 border-b border-[#2d1b4e]">
          <div className="flex items-start gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-orange-500/10 border border-orange-500/30 shrink-0">
              <Zap className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-100 leading-tight">Run All Attacks</h2>
              <p className="text-sm text-slate-400 mt-0.5">
                Fires every attack available to you ({scenarios.length}) at once, in parallel.
              </p>
            </div>
          </div>
          <button onClick={handleClose} className="text-slate-500 hover:text-slate-200 transition-colors shrink-0">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-4 overflow-y-auto">
          {/* Warning banner */}
          <div className="rounded-xl border border-orange-500/30 bg-orange-500/5 p-4 flex gap-3">
            <AlertTriangle className="w-5 h-5 text-orange-400 shrink-0 mt-0.5" />
            <p className="text-xs text-slate-400 leading-relaxed">
              This sends real attack traffic for every scenario to your configured lab endpoints, all at once.
              Only run against systems you own and have permission to test. All traffic is logged by Cloudflare.
            </p>
          </div>

          {/* Run target — admins pick the console; others see their own subdomain */}
          {ready && <TargetBar scope="scenario" />}

          {ready && !isConfigured && (
            <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 flex items-center gap-3">
              <SettingsIcon className="w-4 h-4 text-red-400 shrink-0" />
              <p className="text-sm text-red-300">
                Configure your Cloudflare domain in{' '}
                <Link to="/settings" className="text-orange-400 underline hover:no-underline" onClick={handleClose}>Settings</Link>{' '}
                before running attacks.
              </p>
            </div>
          )}

          {/* Controls */}
          <div className="flex items-center gap-3 flex-wrap">
            <button
              onClick={handleRunAll}
              disabled={(!isConfigured && !isRunning) || !ready}
              className={`flex items-center gap-2 px-5 py-2.5 rounded-lg font-semibold text-sm transition-all duration-200 ${
                isRunning
                  ? 'bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30'
                  : isConfigured
                  ? 'bg-gradient-to-r from-orange-500 to-orange-600 text-white hover:from-orange-600 hover:to-orange-700 shadow-lg shadow-orange-500/20'
                  : 'bg-white/5 text-slate-500 cursor-not-allowed border border-slate-700'
              }`}
            >
              {isRunning ? (
                <><Square className="w-4 h-4" /> Stop</>
              ) : (
                <><Zap className="w-4 h-4" /> Run All Attacks</>
              )}
            </button>

            {isRunning && (
              <span className="text-sm text-slate-400">
                Running <span className="text-orange-400 font-semibold">{progress.current}</span> / {progress.total}
              </span>
            )}
            {done && !isRunning && (
              <span className="flex items-center gap-1.5 text-sm text-green-400">
                <CheckCircle2 className="w-4 h-4" /> Complete
              </span>
            )}
            {needsLogin && (
              <span className="text-xs text-amber-300 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" />
                Please log in to run scenarios.
                <Link to="/admin" className="text-orange-400 underline hover:no-underline" onClick={handleClose}>Log in →</Link>
              </span>
            )}
          </div>

          {/* Terminal */}
          <Terminal lines={lines} isRunning={isRunning} title="run-all — attack output" />
        </div>
      </div>
    </div>
  )
}
