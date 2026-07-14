import { useState, useEffect, useCallback } from 'react'
import {
  ShieldCheck, RefreshCw, Users, History as HistoryIcon,
  Power, PowerOff, Trash2, Lock, PlugZap, AlertTriangle, Clock,
} from 'lucide-react'

// ── Helpers ───────────────────────────────────────────────────────────────────
function formatTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function hecHost(url) {
  if (!url) return '—'
  try {
    return new URL(url).host
  } catch {
    return url
  }
}

function StatusBadge({ status }) {
  const active = status === 'active'
  return (
    <span className={`inline-flex items-center rounded-full font-semibold font-mono tracking-wide px-2 py-0.5 text-xs ${
      active
        ? 'bg-green-500/15 text-green-400 border border-green-500/30'
        : 'bg-slate-500/15 text-slate-400 border border-slate-500/30'
    }`}>
      {status || 'unknown'}
    </span>
  )
}

// ── Tenants table ─────────────────────────────────────────────────────────────
function TenantsTable({ registry, onToggle, onDelete, actionBusy, selected, onToggleSelect, onToggleSelectAll }) {
  if (registry.length === 0) {
    return (
      <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e]/50 p-12 flex flex-col items-center gap-4">
        <div className="w-12 h-12 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
          <Users className="w-6 h-6 text-slate-500" />
        </div>
        <div className="text-center">
          <p className="text-slate-300 font-medium">No tenants registered yet</p>
          <p className="text-sm text-slate-500 mt-1">Instances that register under Settings → Lab Identity will show up here.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="rounded-xl border border-[#2d1b4e] overflow-hidden">
      <div className="overflow-x-auto">
        <div className="min-w-[880px]">
          {/* Table header */}
          <div className="grid grid-cols-[auto_1fr_1fr_auto_auto_auto_1.2fr_auto] gap-4 px-5 py-3 bg-[#1a0a2e] border-b border-[#2d1b4e] text-xs font-semibold text-slate-500 uppercase tracking-wider items-center">
            <input
              type="checkbox"
              checked={registry.length > 0 && selected.size === registry.length}
              onChange={onToggleSelectAll}
              className="accent-orange-500"
              aria-label="Select all tenants"
            />
            <span>Name</span>
            <span>Subdomain</span>
            <span>Status</span>
            <span>Forwarded</span>
            <span>Last Seen</span>
            <span>S1 Destination</span>
            <span>Actions</span>
          </div>

          {registry.map((entry) => {
            const busy = actionBusy === entry.subdomain
            return (
              <div
                key={entry.subdomain}
                className="grid grid-cols-[auto_1fr_1fr_auto_auto_auto_1.2fr_auto] gap-4 px-5 py-3.5 border-b border-[#1e1235] last:border-0 hover:bg-white/[0.02] transition-colors items-center"
              >
                <input
                  type="checkbox"
                  checked={selected.has(entry.subdomain)}
                  onChange={() => onToggleSelect(entry.subdomain)}
                  className="accent-orange-500"
                  aria-label={`Select ${entry.subdomain}`}
                />
                <span className="text-sm font-medium text-slate-200 truncate">{entry.name || '—'}</span>
                <span className="text-xs font-mono text-purple-300 truncate">{entry.subdomain}</span>
                <StatusBadge status={entry.status} />
                <span className="text-xs font-mono text-slate-400">{entry.forwarded ?? 0}</span>
                <span className="text-xs font-mono text-slate-500 whitespace-nowrap">{formatTime(entry.last_seen)}</span>
                <div className="text-xs font-mono text-slate-400 truncate">
                  {entry.site_label && (
                    <div className="text-slate-300 truncate mb-0.5">{entry.site_label}</div>
                  )}
                  <span className="text-slate-300">{entry.s1_hec_token || '****'}</span>
                  <span className="text-slate-600"> @ </span>
                  <span>{hecHost(entry.s1_hec_url)}</span>
                </div>
                <div className="flex items-center gap-2 justify-end">
                  <button
                    onClick={() => onToggle(entry)}
                    disabled={busy}
                    className="btn-ghost text-xs px-2 py-1 disabled:opacity-40"
                    title={entry.status === 'active' ? 'Disable tenant' : 'Enable tenant'}
                  >
                    {entry.status === 'active'
                      ? <PowerOff className="w-3.5 h-3.5 text-yellow-400" />
                      : <Power className="w-3.5 h-3.5 text-green-400" />}
                    <span className="hidden lg:inline">{entry.status === 'active' ? 'Disable' : 'Enable'}</span>
                  </button>
                  <button
                    onClick={() => onDelete(entry)}
                    disabled={busy}
                    className="btn-ghost text-xs px-2 py-1 text-red-400 hover:text-red-300 hover:border-red-500/30 disabled:opacity-40"
                    title="Delete tenant"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span className="hidden lg:inline">Delete</span>
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

// ── History table ─────────────────────────────────────────────────────────────
function HistoryTable({ history }) {
  if (history.length === 0) {
    return (
      <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e]/50 p-12 flex flex-col items-center gap-4">
        <div className="w-12 h-12 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
          <HistoryIcon className="w-6 h-6 text-slate-500" />
        </div>
        <div className="text-center">
          <p className="text-slate-300 font-medium">No relay history yet</p>
          <p className="text-sm text-slate-500 mt-1">Registration and routing events will appear here.</p>
        </div>
      </div>
    )
  }

  // Newest first
  const sorted = [...history].sort((a, b) => new Date(b.ts || 0) - new Date(a.ts || 0))

  return (
    <div className="rounded-xl border border-[#2d1b4e] overflow-hidden">
      <div className="grid grid-cols-[auto_auto_1fr] gap-4 px-5 py-3 bg-[#1a0a2e] border-b border-[#2d1b4e] text-xs font-semibold text-slate-500 uppercase tracking-wider">
        <span>Timestamp</span>
        <span>Type</span>
        <span>Detail</span>
      </div>
      {sorted.map((entry, i) => (
        <div
          key={i}
          className="grid grid-cols-[auto_auto_1fr] gap-4 px-5 py-3 border-b border-[#1e1235] last:border-0 hover:bg-white/[0.02] transition-colors items-center"
        >
          <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono whitespace-nowrap">
            <Clock className="w-3 h-3 text-slate-600" />
            {formatTime(entry.ts)}
          </div>
          <span className="inline-flex items-center rounded-full font-semibold bg-white/5 border border-white/10 text-slate-300 px-2 py-0.5 text-xs whitespace-nowrap">
            {entry.type || 'event'}
          </span>
          <span className="text-xs font-mono text-slate-400 truncate">
            {entry.subdomain || entry.name || '—'}
          </span>
        </div>
      ))}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function Admin() {
  const [adminState, setAdminState] = useState('loading') // loading | disabled | no-relay | error | ready
  const [errorMsg, setErrorMsg] = useState('')
  const [registry, setRegistry] = useState([])
  const [history, setHistory] = useState([])
  const [activeTab, setActiveTab] = useState('tenants')
  const [refreshing, setRefreshing] = useState(false)
  const [actionBusy, setActionBusy] = useState(null)
  const [selected, setSelected] = useState(() => new Set())
  const [batchDeleting, setBatchDeleting] = useState(false)

  const loadRegistry = useCallback(async () => {
    try {
      const res = await fetch('/api/admin/registry')
      if (res.status === 403) { setAdminState('disabled'); return false }
      if (res.status === 503) { setAdminState('no-relay'); return false }
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setAdminState('error')
        setErrorMsg(data.detail || data.error || `Failed to load registry (HTTP ${res.status})`)
        return false
      }
      setRegistry(data.registry || [])
      setAdminState('ready')
      return true
    } catch (err) {
      setAdminState('error')
      setErrorMsg('Could not reach backend. Is Docker running?')
      return false
    }
  }, [])

  const loadHistory = useCallback(async () => {
    try {
      const res = await fetch('/api/admin/history')
      if (!res.ok) return
      const data = await res.json().catch(() => ({}))
      setHistory(data.history || [])
    } catch (err) {
      // Non-fatal — tenants table still works
    }
  }, [])

  useEffect(() => {
    (async () => {
      const ok = await loadRegistry()
      if (ok) await loadHistory()
    })()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function handleRefresh() {
    setRefreshing(true)
    const ok = await loadRegistry()
    if (ok) await loadHistory()
    setRefreshing(false)
  }

  async function handleToggle(entry) {
    const action = entry.status === 'active' ? 'disable' : 'enable'
    setActionBusy(entry.subdomain)
    try {
      await fetch(`/api/admin/user/${encodeURIComponent(entry.subdomain)}/${action}`, { method: 'POST' })
      await loadRegistry()
    } catch (err) {
      // best-effort — table refresh will reflect real state
    } finally {
      setActionBusy(null)
    }
  }

  async function handleDelete(entry) {
    if (!window.confirm(`Tear down ${entry.subdomain}? This stops routing its logs.`)) return
    setActionBusy(entry.subdomain)
    try {
      await fetch(`/api/admin/user/${encodeURIComponent(entry.subdomain)}`, { method: 'DELETE' })
      await loadRegistry()
    } catch (err) {
      // best-effort
    } finally {
      setActionBusy(null)
    }
  }

  function handleToggleSelect(subdomain) {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(subdomain)) next.delete(subdomain)
      else next.add(subdomain)
      return next
    })
  }

  function handleToggleSelectAll() {
    setSelected(prev =>
      prev.size === registry.length ? new Set() : new Set(registry.map(e => e.subdomain))
    )
  }

  async function handleBatchDelete() {
    const subdomains = [...selected]
    if (subdomains.length === 0) return
    if (!window.confirm(`Tear down ${subdomains.length} selected tenant${subdomains.length !== 1 ? 's' : ''}? This stops routing their logs.`)) return
    setBatchDeleting(true)
    try {
      await fetch('/api/admin/users/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subdomains }),
      })
      setSelected(new Set())
      await loadRegistry()
    } catch (err) {
      // best-effort — table refresh will reflect real state
    } finally {
      setBatchDeleting(false)
    }
  }

  return (
    <div className="page-enter space-y-5 max-w-screen-xl mx-auto">
      {/* Page header */}
      <div className="rounded-xl bg-[#1a0a2e] border border-[#2d1b4e] p-5 flex items-start gap-4">
        <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-orange-500/10 border border-orange-500/20 shrink-0">
          <ShieldCheck className="w-6 h-6 text-orange-400" strokeWidth={1.5} />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Relay Admin</h1>
          <p className="text-slate-300 text-sm mt-1 leading-relaxed">
            Manage multi-tenant relay registrations — enable, disable, or tear down partner instances routed through this relay.
          </p>
        </div>
        <div className="ml-auto shrink-0">
          <button onClick={handleRefresh} disabled={refreshing} className="btn-ghost text-xs disabled:opacity-40">
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {adminState === 'loading' && (
        <div className="text-slate-400 text-sm font-mono animate-pulse px-1">Loading admin data...</div>
      )}

      {adminState === 'disabled' && (
        <div className="rounded-xl border border-[#2d1b4e] p-8 flex flex-col items-center gap-3 text-center">
          <Lock className="w-8 h-8 text-slate-500" />
          <p className="text-slate-300 font-medium">Admin is not enabled on this instance</p>
          <p className="text-sm text-slate-500 max-w-md">This looks like a partner instance. Relay administration is only available on the operator's own console.</p>
        </div>
      )}

      {adminState === 'no-relay' && (
        <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-8 flex flex-col items-center gap-3 text-center">
          <PlugZap className="w-8 h-8 text-yellow-400" />
          <p className="text-slate-200 font-medium">Relay not configured</p>
          <p className="text-sm text-slate-400 max-w-md">Set <span className="font-mono text-slate-300">RELAY_URL</span> on the backend to enable multi-tenant relay administration.</p>
        </div>
      )}

      {adminState === 'error' && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-8 flex flex-col items-center gap-3 text-center">
          <AlertTriangle className="w-8 h-8 text-red-400" />
          <p className="text-slate-200 font-medium">Could not load admin data</p>
          <p className="text-sm text-red-400 max-w-md">{errorMsg}</p>
        </div>
      )}

      {adminState === 'ready' && (
        <>
          {/* Tabs */}
          <div className="border-b border-[#2d1b4e] flex gap-0 mb-0">
            <button
              onClick={() => setActiveTab('tenants')}
              className={`px-5 py-2.5 text-sm font-bold transition-all duration-150 border-b-2 -mb-px flex items-center gap-2 ${
                activeTab === 'tenants'
                  ? 'text-orange-400 border-orange-400'
                  : 'text-slate-500 border-transparent hover:text-slate-300 hover:border-slate-600'
              }`}
            >
              <Users className="w-3.5 h-3.5" /> Tenants
              <span className="text-xs font-mono text-slate-500">{registry.length}</span>
            </button>
            <button
              onClick={() => setActiveTab('history')}
              className={`px-5 py-2.5 text-sm font-bold transition-all duration-150 border-b-2 -mb-px flex items-center gap-2 ${
                activeTab === 'history'
                  ? 'text-orange-400 border-orange-400'
                  : 'text-slate-500 border-transparent hover:text-slate-300 hover:border-slate-600'
              }`}
            >
              <HistoryIcon className="w-3.5 h-3.5" /> History
              <span className="text-xs font-mono text-slate-500">{history.length}</span>
            </button>
          </div>

          <div className="pt-2 space-y-3">
            {activeTab === 'tenants' && (
              <div className="flex items-center justify-end">
                <button
                  onClick={handleBatchDelete}
                  disabled={selected.size === 0 || batchDeleting}
                  className="btn-ghost text-xs text-red-400 hover:text-red-300 hover:border-red-500/30 disabled:opacity-40"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  {batchDeleting ? 'Deleting...' : `Delete selected (${selected.size})`}
                </button>
              </div>
            )}
            {activeTab === 'tenants' ? (
              <TenantsTable
                registry={registry}
                onToggle={handleToggle}
                onDelete={handleDelete}
                actionBusy={actionBusy}
                selected={selected}
                onToggleSelect={handleToggleSelect}
                onToggleSelectAll={handleToggleSelectAll}
              />
            ) : (
              <HistoryTable history={history} />
            )}
          </div>
        </>
      )}
    </div>
  )
}
