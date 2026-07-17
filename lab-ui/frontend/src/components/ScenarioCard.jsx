import { useNavigate } from 'react-router-dom'
import { ArrowRight, ChevronRight } from 'lucide-react'
import Badge from './Badge.jsx'

const CATEGORY_GLOW = {
  WAF:      'card-hover-orange',
  Access:   'card-hover-purple',
  Gateway:  'hover:border-blue-500/40 hover:shadow-[0_0_0_1px_rgba(59,130,246,0.2),0_4px_24px_rgba(59,130,246,0.12)] transition-all duration-300 hover:-translate-y-0.5',
  Workers:  'hover:border-red-500/40 hover:shadow-[0_0_0_1px_rgba(239,68,68,0.2),0_4px_24px_rgba(239,68,68,0.12)] transition-all duration-300 hover:-translate-y-0.5',
  Campaign: 'hover:border-pink-500/40 hover:shadow-[0_0_0_1px_rgba(236,72,153,0.2),0_4px_24px_rgba(236,72,153,0.12)] transition-all duration-300 hover:-translate-y-0.5',
}

const CATEGORY_ICON_BG = {
  WAF:      'bg-orange-500/10 border-orange-500/20',
  Access:   'bg-purple-500/10 border-purple-500/20',
  Gateway:  'bg-blue-500/10 border-blue-500/20',
  Workers:  'bg-red-500/10 border-red-500/20',
  Campaign: 'bg-pink-500/10 border-pink-500/20',
}

const CATEGORY_ACCENT = {
  WAF:      'text-orange-400',
  Access:   'text-purple-400',
  Gateway:  'text-blue-400',
  Workers:  'text-red-400',
  Campaign: 'text-pink-400',
}

export default function ScenarioCard({ scenario }) {
  const navigate = useNavigate()
  const hoverClass = CATEGORY_GLOW[scenario.category] || CATEGORY_GLOW.WAF

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => navigate(`/scenarios/${scenario.id}`)}
      onKeyDown={(e) => e.key === 'Enter' && navigate(`/scenarios/${scenario.id}`)}
      className={`
        relative rounded-xl p-5 cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-orange-500/50
        bg-[#1a0a2e] border border-[#2d1b4e] flex flex-col gap-3
        ${hoverClass}
      `}
      style={{ minHeight: '220px' }}
    >
      {/* Top row */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2.5">
          <span className={`
            inline-flex items-center justify-center w-8 h-8 rounded-lg text-xs font-mono font-bold
            border ${CATEGORY_ICON_BG[scenario.category] || CATEGORY_ICON_BG.WAF}
            ${CATEGORY_ACCENT[scenario.category] || CATEGORY_ACCENT.WAF}
          `}>
            {scenario.number}
          </span>
          <Badge type="category" value={scenario.category} />
        </div>
        <Badge type="severity" value={scenario.severity} />
      </div>

      {/* Title + description */}
      <div className="flex-1">
        <h3 className="text-slate-100 font-semibold text-base leading-snug mb-1.5">
          {scenario.title}
        </h3>
        <p className="text-slate-400 text-sm leading-relaxed line-clamp-2">
          {scenario.shortDescription}
        </p>
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between pt-2 border-t border-white/5">
        <span className="text-xs text-slate-500 font-mono truncate max-w-[60%]" title={scenario.target}>
          {scenario.target}
        </span>
        <span className={`flex items-center gap-1 text-xs font-semibold ${CATEGORY_ACCENT[scenario.category] || CATEGORY_ACCENT.WAF} group-hover:gap-2 transition-all`}>
          Explore
          <ChevronRight className="w-3.5 h-3.5" />
        </span>
      </div>
    </div>
  )
}
