import { useState, useEffect } from 'react'
import { Copy, Check, Shield, Info } from 'lucide-react'
import { SCENARIOS } from '../data/scenarios.js'
import Badge from '../components/Badge.jsx'
import { getMe, dnsAllowed } from '../lib/session.js'

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(text).then(() => {
          setCopied(true)
          setTimeout(() => setCopied(false), 2000)
        })
      }}
      className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg border transition-all duration-200 shrink-0
        border-purple-500/30 text-purple-400 bg-purple-500/5 hover:bg-purple-500/15 hover:border-purple-400/40"
    >
      {copied ? (
        <><Check className="w-3.5 h-3.5 text-green-400" /><span className="text-green-400">Copied!</span></>
      ) : (
        <><Copy className="w-3.5 h-3.5" />Copy Rule</>
      )}
    </button>
  )
}

const CATEGORY_COLORS = {
  WAF:     'border-orange-500/20 bg-orange-500/5',
  Access:  'border-purple-500/20 bg-purple-500/5',
  Gateway: 'border-blue-500/20 bg-blue-500/5',
  Workers: 'border-red-500/20 bg-red-500/5',
}

export default function Detections() {
  const [allowDns, setAllowDns] = useState(false)
  useEffect(() => {
    let alive = true
    Promise.all([getMe(), fetch('/api/config').then(r => (r.ok ? r.json() : null)).catch(() => null)])
      .then(([me, cfg]) => {
        if (alive) setAllowDns(dnsAllowed({ adminEnabled: !!cfg?.admin_enabled, role: me?.role }))
      })
    return () => { alive = false }
  }, [])
  const visibleScenarios = SCENARIOS.filter(s => s.id !== 'dns' || allowDns)

  return (
    <div className="page-enter space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Detection Rules</h1>
        <p className="text-sm text-slate-400 mt-1">
          STAR detection rules for SentinelOne — one per attack scenario
        </p>
      </div>

      {/* Info banner */}
      <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4 flex gap-3">
        <Info className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-semibold text-blue-300 mb-1">SentinelOne STAR Rules</p>
          <p className="text-sm text-slate-400 leading-relaxed">
            These STAR rules are designed for SentinelOne. Paste them into the <strong className="text-slate-300">Custom STAR Rules editor</strong> in your S1 console to enable real-time detection and automated response against Cloudflare log events flowing via Logpush.
          </p>
        </div>
      </div>

      {/* Rules grid */}
      <div className="space-y-4">
        {visibleScenarios.map(scenario => (
          <div
            key={scenario.id}
            className={`rounded-xl border p-5 transition-all duration-200 hover:-translate-y-0.5 ${CATEGORY_COLORS[scenario.category] || 'border-[#2d1b4e] bg-[#1a0a2e]'}`}
          >
            {/* Card header */}
            <div className="flex items-start justify-between gap-3 mb-4 flex-wrap">
              <div className="flex items-center gap-3 flex-wrap">
                <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-white/5 border border-white/10 font-mono text-xs font-bold text-slate-400">
                  {scenario.number}
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-base font-semibold text-slate-100">{scenario.title}</h3>
                  </div>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    <Badge type="category" value={scenario.category} />
                    <Badge type="severity" value={scenario.siemSeverity} />
                    <span className="text-xs text-slate-500">{scenario.siemTactic}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-500 hidden sm:inline">{scenario.detectionRule}</span>
                <CopyButton text={scenario.siemLogic} />
              </div>
            </div>

            {/* Rule code */}
            <pre
              className="text-xs leading-relaxed overflow-x-auto rounded-lg p-3 whitespace-pre-wrap"
              style={{
                background: '#0a0a14',
                border: '1px solid #1e1235',
                fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                color: '#c4b5fd',
              }}
            >
              <code>{scenario.siemLogic}</code>
            </pre>
          </div>
        ))}
      </div>
    </div>
  )
}
