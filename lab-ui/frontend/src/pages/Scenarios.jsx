import { useState, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import ScenarioCard from '../components/ScenarioCard.jsx'
import { SCENARIOS } from '../data/scenarios.js'
import { getMe, dnsAllowed } from '../lib/session.js'

// Single-technique attacks live in Section A; the multi-phase campaigns
// (category 'Campaign') live in Section B — same ScenarioCard design so the
// two shelves read as one cohesive library.
const QUICK_SCENARIOS = SCENARIOS.filter(s => s.category !== 'Campaign')
const CAMPAIGN_SCENARIOS = SCENARIOS.filter(s => s.category === 'Campaign')

function SectionDivider({ label, accent = false }) {
  return (
    <div className="flex items-center gap-3">
      <span
        className={`text-[11px] font-mono font-bold uppercase tracking-widest shrink-0 ${
          accent ? 'text-purple-400' : 'text-slate-500'
        }`}
      >
        {label}
      </span>
      <div className={`flex-1 h-px ${accent ? 'bg-purple-500/20' : 'bg-slate-800'}`} />
    </div>
  )
}

export default function Scenarios() {
  const location = useLocation()
  const [allowDns, setAllowDns] = useState(false)

  // react-router doesn't auto-scroll to a hash on navigation — the homepage's
  // "Campaigns" tile links here with #campaigns, so scroll it into view.
  useEffect(() => {
    if (location.hash === '#campaigns') {
      document.getElementById('campaigns')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }, [location.hash])

  // DNS uses account-level Gateway (shared, not per-tenant) — only show it
  // to an admin on the default console.
  useEffect(() => {
    let alive = true
    Promise.all([getMe(), fetch('/api/config').then(r => (r.ok ? r.json() : null)).catch(() => null)])
      .then(([me, cfg]) => {
        if (alive) setAllowDns(dnsAllowed({ adminEnabled: !!cfg?.admin_enabled, role: me?.role }))
      })
    return () => { alive = false }
  }, [])

  const quickScenarios = QUICK_SCENARIOS.filter(s => s.id !== 'dns' || allowDns)

  return (
    <div className="page-enter space-y-8">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Attack Scenarios</h1>
        <p className="text-sm text-slate-400 mt-1">
          Single-technique quick runs and full multi-phase adversary campaigns — choose your depth.
        </p>
      </div>

      {/* Section A — Quick Scenarios */}
      <section className="space-y-4">
        <SectionDivider label="Single-technique Scenarios" />
        <p className="text-xs text-slate-500 -mt-1">
          Focused single-technique attacks with a live WebSocket terminal. Pick one, hit Run, watch the WAF respond.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {quickScenarios.map(scenario => (
            <ScenarioCard key={scenario.id} scenario={scenario} />
          ))}
        </div>
      </section>

      {/* Section B — Campaigns */}
      <section id="campaigns" className="space-y-4 scroll-mt-20">
        <SectionDivider label="Campaigns · multi-phase adversary storylines" accent />
        <p className="text-xs text-slate-500 -mt-1">
          Full write-up, live-verified detections, and a box/phase-by-phase Run Attack terminal.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {CAMPAIGN_SCENARIOS.map(scenario => (
            <ScenarioCard key={scenario.id} scenario={scenario} />
          ))}
        </div>
      </section>
    </div>
  )
}
