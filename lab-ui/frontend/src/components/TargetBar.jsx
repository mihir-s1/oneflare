import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, Info, Crosshair } from 'lucide-react'
import { getMe, getIdentity, getTenants, getRunTarget, setRunTarget } from '../lib/session.js'

function shopHost(shopUrl) {
  if (!shopUrl) return 'one-flare default'
  try {
    return new URL(shopUrl).host
  } catch {
    return shopUrl
  }
}

/**
 * Compact run-target bar shown above scenario/campaign run controls.
 *
 * - Logged out            → login-gated notice + link to /admin
 * - role 'user'/'viewer'  → static readout of the caller's own subdomain
 *                           (or a prompt to register one in Settings)
 * - role 'admin'          → a <select> to choose the run target, persisted
 *                           in localStorage under `oneflare_run_target`.
 *                           Scenarios only: also offers "__all__" fan-out.
 *
 * Renders nothing on single-tenant instances (`admin_enabled` false) — those
 * resolve targeting entirely server-side.
 */
export default function TargetBar({ scope = 'scenario' }) {
  const [loading, setLoading] = useState(true)
  const [adminEnabled, setAdminEnabled] = useState(false)
  const [shopUrl, setShopUrl] = useState('')
  const [me, setMe] = useState(null)
  const [identity, setIdentity] = useState(null)
  const [tenants, setTenants] = useState([])
  const [target, setTarget] = useState(getRunTarget())

  useEffect(() => {
    let alive = true
    ;(async () => {
      const [cfg, meData] = await Promise.all([
        fetch('/api/config').then(r => (r.ok ? r.json() : null)).catch(() => null),
        getMe(),
      ])
      if (!alive) return
      setAdminEnabled(!!cfg?.admin_enabled)
      setShopUrl(cfg?.shop_url || '')
      setMe(meData)

      if (meData) {
        const ident = await getIdentity()
        if (!alive) return
        setIdentity(ident)

        if (meData.role === 'admin') {
          const t = await getTenants()
          if (!alive) return
          setTenants(t)
        }
      }
      setLoading(false)
    })()
    return () => { alive = false }
  }, [])

  // Campaigns can't fan out — normalize a stale '__all__' selection to the
  // one-flare default so the <select> and localStorage stay in sync.
  useEffect(() => {
    if (scope === 'campaign' && target === '__all__') {
      setTarget('')
      setRunTarget('')
    }
  }, [scope, target])

  function handleSelect(v) {
    setTarget(v)
    setRunTarget(v)
  }

  if (loading || !adminEnabled) return null

  if (!me) {
    return (
      <div className="rounded-lg border border-amber-500/25 bg-amber-500/5 p-3 flex items-center gap-2.5 text-sm flex-wrap">
        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
        <span className="text-amber-300">Log in to run — execution is login-gated.</span>
        <Link to="/admin" className="text-orange-400 underline hover:no-underline ml-auto shrink-0">
          Log in →
        </Link>
      </div>
    )
  }

  if (me.role !== 'admin') {
    if (!identity) {
      return (
        <div className="rounded-lg border border-[#2d1b4e] bg-white/3 p-3 flex items-center gap-2.5 text-sm flex-wrap">
          <Info className="w-4 h-4 text-blue-400 shrink-0" />
          <span className="text-slate-300">No subdomain registered yet.</span>
          <Link to="/settings" className="text-orange-400 underline hover:no-underline ml-auto shrink-0">
            Register your subdomain in Settings →
          </Link>
        </div>
      )
    }
    return (
      <div className="rounded-lg border border-[#2d1b4e] bg-white/3 p-3 flex items-center gap-2.5 text-sm">
        <Crosshair className="w-4 h-4 text-purple-400 shrink-0" />
        <span className="text-slate-400">Targeting:</span>
        <span className="font-mono text-purple-300">{identity.subdomain}</span>
      </div>
    )
  }

  // Admin — selectable target.
  const effectiveTarget = scope === 'campaign' && target === '__all__' ? '' : target
  return (
    <div className="rounded-lg border border-[#2d1b4e] bg-white/3 p-3 flex items-center gap-3 flex-wrap text-sm">
      <Crosshair className="w-4 h-4 text-purple-400 shrink-0" />
      <span className="text-slate-400 shrink-0">Run target:</span>
      <select
        value={effectiveTarget}
        onChange={(e) => handleSelect(e.target.value)}
        className="lab-input py-1.5 text-sm w-auto min-w-[240px]"
      >
        <option value="">one-flare default ({shopHost(shopUrl)})</option>
        {tenants.map(t => (
          <option key={t.subdomain} value={t.subdomain}>
            {t.subdomain}{t.owner_email ? ` — ${t.owner_email}` : ''}
          </option>
        ))}
        {scope === 'scenario' && (
          <option value="__all__">All registered subdomains (fan-out)</option>
        )}
      </select>
      {scope === 'campaign' && (
        <span className="text-xs text-slate-500">Campaigns run one subdomain at a time.</span>
      )}
    </div>
  )
}
