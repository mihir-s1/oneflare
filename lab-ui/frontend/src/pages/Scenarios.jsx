import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertTriangle, ChevronRight, Layers } from 'lucide-react'
import ScenarioCard from '../components/ScenarioCard.jsx'
import Badge from '../components/Badge.jsx'
import { SCENARIOS } from '../data/scenarios.js'
import { getMe, dnsAllowed } from '../lib/session.js'

// Campaign card — same visual language as ScenarioCard so the two shelves
// of the library read as one cohesive set.
function CampaignCard({ campaign, onOpen }) {
  const isCTF = campaign.key === 'ctf'
  const phases = campaign.phases?.length || campaign.num_phases || (isCTF ? 4 : 5)
  const phaseLabel = isCTF ? `${phases} boxes` : `${phases} phases`

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onOpen(campaign)}
      onKeyDown={(e) => e.key === 'Enter' && onOpen(campaign)}
      className="
        relative rounded-xl p-5 cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-amber-500/50
        bg-[#1a0a2e] border border-[#2d1b4e] flex flex-col gap-3
        hover:border-amber-500/40 hover:shadow-[0_0_0_1px_rgba(245,158,11,0.2),0_4px_24px_rgba(245,158,11,0.12)]
        transition-all duration-300 hover:-translate-y-0.5
      "
      style={{ minHeight: '220px' }}
    >
      {/* Top row */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2.5">
          <span className="inline-flex items-center justify-center w-8 h-8 rounded-lg text-base border bg-amber-500/10 border-amber-500/20 text-amber-400">
            {campaign.icon || <Layers className="w-4 h-4" />}
          </span>
          <Badge type="category" value="Campaign" />
        </div>
        <span className="inline-flex items-center rounded-full font-semibold font-mono tracking-wide px-2 py-0.5 text-xs bg-amber-500/15 text-amber-400 border border-amber-500/30">
          {phaseLabel}
        </span>
      </div>

      {/* Title + description */}
      <div className="flex-1">
        <h3 className="text-slate-100 font-semibold text-base leading-snug mb-1.5">
          {campaign.name}
        </h3>
        <p className="text-slate-400 text-sm leading-relaxed line-clamp-2">
          {campaign.description}
        </p>
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between pt-2 border-t border-white/5">
        <span className="text-xs text-slate-500 font-mono truncate max-w-[60%]" title={campaign.target || 'SoleDrop shop'}>
          {campaign.target || 'SoleDrop shop'}
        </span>
        <span className="flex items-center gap-1 text-xs font-semibold text-amber-400">
          Open console
          <ChevronRight className="w-3.5 h-3.5" />
        </span>
      </div>
    </div>
  )
}

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
  const navigate = useNavigate()
  const [campaigns, setCampaigns] = useState([])
  const [loadingCampaigns, setLoadingCampaigns] = useState(true)
  const [allowDns, setAllowDns] = useState(false)

  useEffect(() => {
    fetch('/api/campaigns')
      .then(r => r.json())
      .then(data => {
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

  const visibleScenarios = SCENARIOS.filter(s => s.id !== 'dns' || allowDns)

  function handleOpenCampaign(campaign) {
    if (campaign.key === 'ctf') {
      navigate('/threatops?tab=ctf')
    } else {
      navigate(`/threatops?tab=industry&campaign=${campaign.key}`)
    }
  }

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
          {visibleScenarios.map(scenario => (
            <ScenarioCard key={scenario.id} scenario={scenario} />
          ))}
        </div>
      </section>

      {/* Section B — Campaigns */}
      <section className="space-y-4">
        <SectionDivider label="Multi-phase Campaigns" accent />
        <p className="text-xs text-slate-500 -mt-1">
          Live drip pacing, phase timeline, and SOC talking points — opens the full ThreatOps console.
        </p>

        {loadingCampaigns ? (
          <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] p-8 flex items-center justify-center gap-3 text-slate-500 text-sm font-mono">
            <span className="w-4 h-4 border border-slate-500 border-t-transparent rounded-full animate-spin shrink-0" />
            Loading campaigns...
          </div>
        ) : campaigns.length === 0 ? (
          <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e] p-8 flex flex-col items-center gap-3">
            <AlertTriangle className="w-6 h-6 text-orange-400" />
            <p className="text-sm text-slate-400 text-center">
              Backend not reachable — start the lab-ui Docker stack to load campaign data.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {campaigns.map(campaign => (
              <CampaignCard
                key={campaign.key}
                campaign={campaign}
                onOpen={handleOpenCampaign}
              />
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
