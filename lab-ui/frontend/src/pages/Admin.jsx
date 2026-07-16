import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldCheck, RefreshCw, Users, History as HistoryIcon,
  Power, PowerOff, Trash2, Lock, PlugZap, AlertTriangle, Clock,
  LogOut, UserPlus, Copy, Check, Mail, KeyRound, UserCheck, X,
} from 'lucide-react'
import RequestAccountForm from '../components/RequestAccountForm'

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

// The relay redacts the HEC token to a long run of asterisks + a short tail
// (e.g. "****************M/NH"). Showing the full mask is useless and, in a
// fixed-width column, pushes the actual destination host out of view. Collapse
// it to just the identifying tail.
function tokenTail(tok) {
  if (!tok) return '—'
  const tail = tok.replace(/^[*•]+/, '')
  return tail ? `…${tail}` : '••••'
}

// The destination host to show: the operator's S1 console ("purple") domain if
// they provided one, else the region ingest host (all we can infer otherwise).
function destHost(entry) {
  return entry?.s1_console_url ? hecHost(entry.s1_console_url) : hecHost(entry?.s1_hec_url)
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

function RoleBadge({ role }) {
  const styles = role === 'admin'
    ? 'bg-orange-500/15 text-orange-400 border border-orange-500/30'
    : role === 'user'
      ? 'bg-blue-500/15 text-blue-400 border border-blue-500/30'
      : 'bg-slate-500/15 text-slate-400 border border-slate-500/30'
  return (
    <span className={`inline-flex items-center rounded-full font-semibold font-mono tracking-wide px-2 py-0.5 text-xs ${styles}`}>
      {role || 'viewer'}
    </span>
  )
}

// ── Login gate ────────────────────────────────────────────────────────────────
function LoginForm({ onLoggedIn }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [showRequest, setShowRequest] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setError(data.error || data.detail || 'Invalid credentials')
        return
      }
      onLoggedIn({ email: data.email, role: data.role })
    } catch (err) {
      setError('Could not reach backend. Is Docker running?')
    } finally {
      setBusy(false)
    }
  }

  if (showRequest) {
    return (
      <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e]/50 p-8 max-w-sm mx-auto flex flex-col items-center gap-4">
        <div className="w-12 h-12 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center">
          <UserPlus className="w-6 h-6 text-orange-400" />
        </div>
        <div className="text-center">
          <p className="text-slate-100 font-semibold">Request an account</p>
          <p className="text-sm text-slate-500 mt-1">An admin reviews your request and emails you an invite.</p>
        </div>
        <RequestAccountForm onCancel={() => setShowRequest(false)} />
      </div>
    )
  }

  return (
    <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e]/50 p-8 max-w-sm mx-auto flex flex-col items-center gap-4">
      <div className="w-12 h-12 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center">
        <Lock className="w-6 h-6 text-orange-400" />
      </div>
      <div className="text-center">
        <p className="text-slate-100 font-semibold">Sign in</p>
        <p className="text-sm text-slate-500 mt-1">Sign in to your OneFlare lab account.</p>
      </div>
      <form onSubmit={handleSubmit} className="w-full space-y-3">
        <div>
          <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Email</label>
          <input
            type="email"
            required
            autoFocus
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 w-full rounded-lg bg-[#12081f] border border-[#2d1b4e] px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-orange-500/50"
            placeholder="you@sentinelone.com"
          />
        </div>
        <div>
          <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Password</label>
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full rounded-lg bg-[#12081f] border border-[#2d1b4e] px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-orange-500/50"
            placeholder="••••••••••"
          />
        </div>
        {error && <p className="text-xs text-red-400">{error}</p>}
        <button type="submit" disabled={busy} className="btn-primary w-full text-sm justify-center disabled:opacity-40">
          {busy ? 'Signing in...' : 'Sign in'}
        </button>
      </form>
      <div className="w-full pt-3 border-t border-[#2d1b4e] text-center">
        <button
          onClick={() => setShowRequest(true)}
          className="text-xs text-slate-400 hover:text-orange-400 transition-colors inline-flex items-center gap-1.5"
        >
          <UserPlus className="w-3.5 h-3.5" />
          Don't have an account? Request one
        </button>
      </div>
    </div>
  )
}

// ── Tenants table ─────────────────────────────────────────────────────────────
const TENANTS_GRID_COLS = 'grid-cols-[auto_1fr_1fr_1fr_auto_auto_auto_1.2fr_auto]'

// Shared, EXPLICIT column widths for the Users + Invites tables. The header and
// each row are separate grids, so `auto` columns would size independently and the
// header labels would drift off their data columns — fixed widths keep them aligned.
// Email | Role | Created | Last Login | Actions.
const USERS_GRID_COLS = 'grid-cols-[minmax(9rem,1fr)_6rem_11rem_11rem_9.5rem]'
// Pending invite | Role | Expires.
const INVITES_GRID_COLS = 'grid-cols-[minmax(9rem,1fr)_6rem_11rem]'

function TenantsTable({ rows, onToggle, onDelete, actionBusy, selected, onToggleSelect, onToggleSelectAll, readOnly }) {
  if (rows.length === 0) {
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

  // Placeholder rows (users without a registered tenant yet) aren't
  // selectable for batch-delete — "select all" only ever counts real tenants.
  const selectableRows = rows.filter((r) => !r.__placeholder)

  return (
    <div className="rounded-xl border border-[#2d1b4e] overflow-hidden">
      <div className="overflow-x-auto">
        <div className="min-w-[1000px]">
          {/* Table header */}
          <div className={`grid ${TENANTS_GRID_COLS} gap-4 px-5 py-3 bg-[#1a0a2e] border-b border-[#2d1b4e] text-xs font-semibold text-slate-500 uppercase tracking-wider items-center`}>
            <input
              type="checkbox"
              checked={selectableRows.length > 0 && selected.size === selectableRows.length}
              onChange={onToggleSelectAll}
              disabled={readOnly || selectableRows.length === 0}
              className="accent-orange-500 disabled:opacity-30"
              aria-label="Select all tenants"
            />
            <span>Name</span>
            <span>Subdomain</span>
            <span>Owner</span>
            <span>Status</span>
            <span>Forwarded</span>
            <span>Last Seen</span>
            <span>S1 Destination</span>
            <span>Actions</span>
          </div>

          {rows.map((entry) => {
            const isPlaceholder = !!entry.__placeholder
            const rowKey = entry.subdomain || entry.owner_email
            const busy = actionBusy === entry.subdomain
            return (
              <div
                key={rowKey}
                className={`grid ${TENANTS_GRID_COLS} gap-4 px-5 py-3.5 border-b border-[#1e1235] last:border-0 hover:bg-white/[0.02] transition-colors items-center ${isPlaceholder ? 'opacity-50' : ''}`}
              >
                {isPlaceholder ? (
                  <span />
                ) : (
                  <input
                    type="checkbox"
                    checked={selected.has(entry.subdomain)}
                    onChange={() => onToggleSelect(entry.subdomain)}
                    disabled={readOnly}
                    className="accent-orange-500 disabled:opacity-30"
                    aria-label={`Select ${entry.subdomain}`}
                  />
                )}
                <span className="text-sm font-medium text-slate-200 truncate">{entry.name || '—'}</span>
                {isPlaceholder ? (
                  <span className="text-xs font-mono text-slate-600 italic truncate">not registered yet</span>
                ) : (
                  <span className="text-xs font-mono text-purple-300 truncate">{entry.subdomain}</span>
                )}
                <span className="text-xs font-mono text-slate-400 truncate">{entry.owner_email || '—'}</span>
                {isPlaceholder ? (
                  <span className="text-xs text-slate-600">—</span>
                ) : (
                  <StatusBadge status={entry.status} />
                )}
                <span className="text-xs font-mono text-slate-400">{isPlaceholder ? '—' : (entry.forwarded ?? 0)}</span>
                <span className="text-xs font-mono text-slate-500 whitespace-nowrap">{isPlaceholder ? '—' : formatTime(entry.last_seen)}</span>
                {isPlaceholder ? (
                  <span className="text-xs text-slate-600">—</span>
                ) : (
                  <div className="text-xs font-mono text-slate-400 min-w-0 space-y-0.5">
                    <div className="truncate">
                      <span className="text-slate-500">Site: </span>
                      <span className="text-slate-200">{entry.site_label || '—'}</span>
                    </div>
                    <div className="truncate">
                      <span className="text-slate-500">Account: </span>
                      <span className="text-slate-200">{entry.account_label || '—'}</span>
                    </div>
                    <div className="text-slate-400 truncate" title={entry.s1_console_url || entry.s1_hec_url || ''}>
                      {destHost(entry)}
                    </div>
                    <div className="text-slate-600 truncate" title="HEC token (redacted)">
                      token {tokenTail(entry.s1_hec_token)}
                    </div>
                  </div>
                )}
                <div className="flex items-center gap-2 justify-end">
                  {isPlaceholder ? (
                    <span className="text-xs text-slate-600">—</span>
                  ) : readOnly ? (
                    <span className="text-xs text-slate-600 italic">view only</span>
                  ) : (
                    <>
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
                    </>
                  )}
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

// ── Users tab (invite / list / role / remove admins) ──────────────────────────
function InviteUrlBanner({ invite, onDismiss }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(invite.invite_url)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // clipboard API unavailable — user can select the text manually
    }
  }
  return (
    <div className="rounded-xl border border-orange-500/30 bg-orange-500/5 p-5 flex flex-col gap-3">
      <p className="text-sm text-slate-200 leading-relaxed">
        Invite created for <span className="font-mono text-orange-300">{invite.email}</span> ({invite.role}).
        {' '}Resend isn't configured on this deployment — share this link manually:
      </p>
      <div className="flex items-center gap-2">
        <code className="flex-1 min-w-0 text-xs font-mono text-purple-300 bg-[#12081f] border border-[#2d1b4e] rounded-lg px-3 py-2 truncate">
          {invite.invite_url}
        </code>
        <button onClick={copy} className="btn-ghost text-xs px-2.5 py-2 shrink-0">
          {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
        </button>
        <button onClick={onDismiss} className="btn-ghost text-xs px-3 py-2 shrink-0">Dismiss</button>
      </div>
      <p className="text-xs text-yellow-400/80 leading-relaxed pt-1 border-t border-orange-500/10">
        Reminder: this deployment sits behind Cloudflare Access — the invitee's email must
        also be added to the Access allow-list, or the link/login page will be unreachable.
      </p>
    </div>
  )
}

function BulkResultRow({ result }) {
  const [copied, setCopied] = useState(false)
  const invited = result.status === 'invited'

  async function copy() {
    try {
      await navigator.clipboard.writeText(result.invite_url)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // clipboard API unavailable — user can select the text manually
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-3 px-4 py-2.5 border-b border-[#1e1235] last:border-0">
      <span className="text-xs font-mono text-slate-300 truncate flex-1 min-w-[140px]">{result.email}</span>
      <span className={`inline-flex items-center rounded-full font-semibold px-2 py-0.5 text-xs shrink-0 ${
        invited
          ? 'bg-green-500/15 text-green-400 border border-green-500/30'
          : 'bg-slate-500/15 text-slate-400 border border-slate-500/30'
      }`}>
        {result.status}
      </span>
      {invited && result.invite_url && (
        <div className="flex items-center gap-2 shrink-0">
          <code className="text-xs font-mono text-purple-300 bg-[#12081f] border border-[#2d1b4e] rounded-lg px-2.5 py-1.5 truncate max-w-[220px] sm:max-w-[280px]">
            {result.invite_url}
          </code>
          <button onClick={copy} className="btn-ghost text-xs px-2 py-1.5 shrink-0">
            {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
        </div>
      )}
    </div>
  )
}

function UsersTab({ role }) {
  const [users, setUsers] = useState([])
  const [invites, setInvites] = useState([])
  const [requests, setRequests] = useState([])
  const [reqBusy, setReqBusy] = useState(null) // token currently being accepted/declined
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState('viewer')
  const [inviting, setInviting] = useState(false)
  const [lastInvite, setLastInvite] = useState(null)
  const [busyEmail, setBusyEmail] = useState(null)

  const [bulkEmails, setBulkEmails] = useState('')
  const [bulkRole, setBulkRole] = useState('user')
  const [bulkInviting, setBulkInviting] = useState(false)
  const [bulkError, setBulkError] = useState('')
  const [bulkResults, setBulkResults] = useState([])

  const isAdmin = role === 'admin'

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/auth/users')
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setError(data.error || data.detail || 'Failed to load users')
        return
      }
      setUsers(data.users || [])
      setInvites(data.invites || [])
      setRequests(data.requests || [])
      setError('')
    } catch (err) {
      setError('Could not reach backend.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleInvite(e) {
    e.preventDefault()
    if (!inviteEmail) return
    setInviting(true)
    try {
      const res = await fetch('/api/auth/invite', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: inviteEmail, role: inviteRole }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setError(data.error || data.detail || 'Failed to create invite')
        return
      }
      setLastInvite(data)
      setInviteEmail('')
      await load()
    } catch (err) {
      setError('Could not reach backend.')
    } finally {
      setInviting(false)
    }
  }

  async function handleBulkInvite(e) {
    e.preventDefault()
    if (!bulkEmails.trim()) return
    setBulkInviting(true)
    setBulkError('')
    try {
      const res = await fetch('/api/auth/invite-bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ emails: bulkEmails, role: bulkRole }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setBulkError(data.error || data.detail || 'Failed to create invites')
        return
      }
      setBulkResults(data.results || [])
      setBulkEmails('')
      await load()
    } catch (err) {
      setBulkError('Could not reach backend.')
    } finally {
      setBulkInviting(false)
    }
  }

  async function handleAcceptRequest(token) {
    setReqBusy(token)
    try {
      const res = await fetch('/api/auth/accept-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, role: 'user' }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setError(data.error || data.detail || 'Failed to accept request')
        return
      }
      if (data.invite_url) setLastInvite(data)
      await load()
    } catch (err) {
      setError('Could not reach backend.')
    } finally {
      setReqBusy(null)
    }
  }

  async function handleDeclineRequest(token, email) {
    if (!window.confirm(`Decline the account request from ${email}?`)) return
    setReqBusy(token)
    try {
      await fetch(`/api/auth/requests/${encodeURIComponent(token)}`, { method: 'DELETE' })
      await load()
    } catch (err) {
      // best-effort
    } finally {
      setReqBusy(null)
    }
  }

  async function handleRoleChange(email, newRole) {
    setBusyEmail(email)
    try {
      await fetch(`/api/auth/users/${encodeURIComponent(email)}/role`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: newRole }),
      })
      await load()
    } catch (err) {
      // best-effort
    } finally {
      setBusyEmail(null)
    }
  }

  async function handleRemove(email) {
    if (!window.confirm(`Remove admin user ${email}?`)) return
    setBusyEmail(email)
    try {
      await fetch(`/api/auth/users/${encodeURIComponent(email)}`, { method: 'DELETE' })
      await load()
    } catch (err) {
      // best-effort
    } finally {
      setBusyEmail(null)
    }
  }

  if (loading) {
    return <div className="text-slate-400 text-sm font-mono animate-pulse px-1">Loading users...</div>
  }

  return (
    <div className="space-y-6">
      {error && (
        <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-xs text-red-400">{error}</div>
      )}

      {lastInvite && (
        <InviteUrlBanner invite={lastInvite} onDismiss={() => setLastInvite(null)} />
      )}

      {isAdmin && (
        <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e]/50 p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Users className="w-4 h-4 text-orange-400 shrink-0" />
            <div>
              <p className="text-sm font-semibold text-slate-200">ThreatOps users — bulk invite</p>
              <p className="text-xs text-slate-500 mt-0.5">
                Paste many emails (newline, comma, or space separated) to invite self-service tenants at once.
              </p>
            </div>
          </div>
          <form onSubmit={handleBulkInvite} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Emails
              </label>
              <textarea
                value={bulkEmails}
                onChange={(e) => setBulkEmails(e.target.value)}
                rows={4}
                placeholder={'alice@example.com\nbob@example.com, carol@example.com'}
                className="w-full rounded-lg bg-[#12081f] border border-[#2d1b4e] px-3 py-2.5 text-sm text-slate-200 font-mono focus:outline-none focus:border-orange-500/50"
              />
            </div>
            <div className="flex flex-wrap items-end gap-3">
              <div className="w-full sm:w-40">
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                  Role
                </label>
                <select
                  value={bulkRole}
                  onChange={(e) => setBulkRole(e.target.value)}
                  className="w-full rounded-lg bg-[#12081f] border border-[#2d1b4e] px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-orange-500/50"
                >
                  <option value="user">user</option>
                  <option value="viewer">viewer</option>
                  <option value="admin">admin</option>
                </select>
              </div>
              <button
                type="submit"
                disabled={bulkInviting || !bulkEmails.trim()}
                className="btn-primary text-sm shrink-0 disabled:opacity-40"
              >
                <UserPlus className="w-3.5 h-3.5" />
                {bulkInviting ? 'Inviting...' : 'Invite all'}
              </button>
            </div>
          </form>
          <p className="text-xs text-yellow-400/80 leading-relaxed pt-1 border-t border-[#2d1b4e]">
            Reminder: Resend isn't configured on this deployment — share links manually; invitees also need
            to be added to the Cloudflare Access allow-list.
          </p>
          {bulkError && <p className="text-xs text-red-400">{bulkError}</p>}
          {bulkResults.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Results</p>
              <div className="rounded-lg border border-[#2d1b4e] overflow-hidden">
                {bulkResults.map((r) => <BulkResultRow key={r.email} result={r} />)}
              </div>
            </div>
          )}
        </div>
      )}

      {isAdmin && (
        <form onSubmit={handleInvite} className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e]/50 p-5 flex flex-wrap items-end gap-4">
          <div className="flex-1 min-w-[220px]">
            <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1 mb-1.5">
              <Mail className="w-3 h-3" /> Invite admin by email
            </label>
            <input
              type="email"
              required
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              className="w-full rounded-lg bg-[#12081f] border border-[#2d1b4e] px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-orange-500/50"
              placeholder="name@sentinelone.com"
            />
          </div>
          <div className="w-full sm:w-40">
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">Role</label>
            <select
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value)}
              className="w-full rounded-lg bg-[#12081f] border border-[#2d1b4e] px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-orange-500/50"
            >
              <option value="user">user</option>
              <option value="viewer">viewer</option>
              <option value="admin">admin</option>
            </select>
          </div>
          <button type="submit" disabled={inviting} className="btn-primary text-sm shrink-0 disabled:opacity-40">
            <UserPlus className="w-3.5 h-3.5" />
            {inviting ? 'Inviting...' : 'Invite'}
          </button>
        </form>
      )}

      {isAdmin && requests.length > 0 && (
        <div className="rounded-xl border border-orange-500/30 bg-orange-500/[0.04] overflow-hidden">
          <div className="px-5 py-3 border-b border-orange-500/20 flex items-center gap-2">
            <UserCheck className="w-4 h-4 text-orange-400" />
            <p className="text-sm font-semibold text-slate-200">
              Account requests <span className="text-orange-400">({requests.length})</span>
            </p>
          </div>
          {requests.map((r) => (
            <div key={r.token} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 border-b border-orange-500/10 last:border-0">
              <div className="min-w-0">
                {r.name && <p className="text-sm text-slate-200 truncate">{r.name}</p>}
                <p className="text-xs font-mono text-slate-400 truncate">{r.email}</p>
                <p className="text-[11px] text-slate-600 mt-0.5">Requested {formatTime(r.created_at)}</p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => handleDeclineRequest(r.token, r.email)}
                  disabled={reqBusy === r.token}
                  className="btn-ghost text-xs px-2.5 py-1.5 text-slate-400 hover:text-red-300 hover:border-red-500/30 disabled:opacity-40"
                >
                  <X className="w-3.5 h-3.5" /> Decline
                </button>
                <button
                  onClick={() => handleAcceptRequest(r.token)}
                  disabled={reqBusy === r.token}
                  className="btn-primary text-xs px-2.5 py-1.5 disabled:opacity-40"
                >
                  {reqBusy === r.token ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <UserCheck className="w-3.5 h-3.5" />}
                  Accept &amp; invite
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="rounded-xl border border-[#2d1b4e] overflow-hidden">
        <div className="overflow-x-auto">
          <div className="min-w-[760px]">
            <div className={`grid ${USERS_GRID_COLS} gap-4 px-5 py-3 bg-[#1a0a2e] border-b border-[#2d1b4e] text-xs font-semibold text-slate-500 uppercase tracking-wider items-center`}>
              <span>Email</span>
              <span>Role</span>
              <span>Created</span>
              <span>Last Login</span>
              <span className="text-right">Actions</span>
            </div>
            {users.length === 0 && (
              <div className="px-5 py-6 text-sm text-slate-500">No admin users yet.</div>
            )}
            {users.map((u) => (
              <div key={u.email} className={`grid ${USERS_GRID_COLS} gap-4 px-5 py-3.5 border-b border-[#1e1235] last:border-0 items-center`}>
                <span className="text-sm font-mono text-slate-200 truncate">{u.email}</span>
                <RoleBadge role={u.role} />
                <span className="text-xs font-mono text-slate-500 whitespace-nowrap">{formatTime(u.created_at)}</span>
                <span className="text-xs font-mono text-slate-500 whitespace-nowrap">{formatTime(u.last_login)}</span>
                <div className="flex items-center gap-2 justify-end">
                  {isAdmin ? (
                    <>
                      <select
                        value={u.role}
                        disabled={busyEmail === u.email}
                        onChange={(e) => handleRoleChange(u.email, e.target.value)}
                        className="text-xs rounded-lg bg-[#12081f] border border-[#2d1b4e] px-2 py-1.5 text-slate-300 disabled:opacity-40"
                      >
                        <option value="user">user</option>
                        <option value="viewer">viewer</option>
                        <option value="admin">admin</option>
                      </select>
                      <button
                        onClick={() => handleRemove(u.email)}
                        disabled={busyEmail === u.email}
                        className="btn-ghost text-xs px-2 py-1.5 text-red-400 hover:text-red-300 hover:border-red-500/30 disabled:opacity-40"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </>
                  ) : (
                    <span className="text-xs text-slate-600 italic">view only</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-[#2d1b4e] overflow-hidden">
        <div className="overflow-x-auto">
          <div className="min-w-[480px]">
            <div className={`grid ${INVITES_GRID_COLS} gap-4 px-5 py-3 bg-[#1a0a2e] border-b border-[#2d1b4e] text-xs font-semibold text-slate-500 uppercase tracking-wider items-center`}>
              <span>Pending invite</span>
              <span>Role</span>
              <span>Expires</span>
            </div>
            {invites.length === 0 && (
              <div className="px-5 py-6 text-sm text-slate-500">No pending invites.</div>
            )}
            {invites.map((i) => (
              <div key={i.email} className={`grid ${INVITES_GRID_COLS} gap-4 px-5 py-3.5 border-b border-[#1e1235] last:border-0 items-center`}>
                <span className="text-sm font-mono text-slate-300 truncate">{i.email}</span>
                <RoleBadge role={i.role} />
                <span className="text-xs font-mono text-slate-500 whitespace-nowrap">{formatTime(i.expires_at)}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function Admin() {
  const [authState, setAuthState] = useState('checking') // checking | loggedout | loggedin
  const [session, setSession] = useState(null) // { email, role }

  const [adminState, setAdminState] = useState('loading') // loading | disabled | no-relay | error | ready
  const [errorMsg, setErrorMsg] = useState('')
  const [registry, setRegistry] = useState([])
  const [history, setHistory] = useState([])
  const [users, setUsers] = useState([]) // for Tenants tab "not registered yet" placeholder rows
  const [activeTab, setActiveTab] = useState('tenants')
  const [refreshing, setRefreshing] = useState(false)
  const [actionBusy, setActionBusy] = useState(null)
  const [selected, setSelected] = useState(() => new Set())
  const [batchDeleting, setBatchDeleting] = useState(false)

  const checkSession = useCallback(async () => {
    try {
      const res = await fetch('/api/auth/me')
      if (res.ok) {
        const data = await res.json()
        setSession({ email: data.email, role: data.role })
        setAuthState('loggedin')
      } else {
        setAuthState('loggedout')
      }
    } catch {
      setAuthState('loggedout')
    }
  }, [])

  useEffect(() => { checkSession() }, [checkSession])

  const loadRegistry = useCallback(async () => {
    try {
      const res = await fetch('/api/admin/registry')
      if (res.status === 401 || res.status === 403) { setAdminState('disabled'); return false }
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

  const loadUsers = useCallback(async () => {
    try {
      const res = await fetch('/api/auth/users')
      if (!res.ok) return
      const data = await res.json().catch(() => ({}))
      setUsers(data.users || [])
    } catch (err) {
      // Non-fatal — only affects the "not registered yet" placeholder rows
    }
  }, [])

  useEffect(() => {
    if (authState !== 'loggedin') return
    (async () => {
      const ok = await loadRegistry()
      if (ok) await loadHistory()
      await loadUsers()
    })()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authState])

  async function handleRefresh() {
    setRefreshing(true)
    const ok = await loadRegistry()
    if (ok) await loadHistory()
    await loadUsers()
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

  async function handleLogout() {
    try {
      await fetch('/api/auth/logout', { method: 'POST' })
    } catch {
      // best-effort
    } finally {
      setSession(null)
      setAuthState('loggedout')
    }
  }

  if (authState === 'checking') {
    return <div className="text-slate-400 text-sm font-mono animate-pulse px-1">Checking session...</div>
  }

  if (authState === 'loggedout') {
    return (
      <div className="page-enter max-w-screen-xl mx-auto">
        <LoginForm onLoggedIn={(s) => { setSession(s); setAuthState('loggedin') }} />
      </div>
    )
  }

  // Self-service tenants (`user` role) don't get the admin console at all —
  // they manage their own lab from Settings.
  if (session?.role === 'user') {
    return (
      <div className="page-enter max-w-screen-xl mx-auto">
        <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e]/50 p-12 mt-10 flex flex-col items-center gap-3 text-center">
          <Lock className="w-8 h-8 text-slate-500" />
          <p className="text-slate-300 font-medium">This area is for administrators.</p>
          <p className="text-sm text-slate-500 max-w-sm">
            Manage your lab in{' '}
            <Link to="/settings" className="text-orange-400 hover:text-orange-300 underline underline-offset-2">
              Settings
            </Link>.
          </p>
        </div>
      </div>
    )
  }

  const isViewer = session?.role === 'viewer'

  // Tenants tab: merge in users who haven't registered a lab yet, so admins
  // can see who was invited/self-serviced but hasn't spun up an instance.
  const ownerEmails = new Set(registry.map((e) => e.owner_email).filter(Boolean))
  const placeholderRows = users
    .filter((u) => (u.role === 'user' || u.role === 'admin') && u.email && !ownerEmails.has(u.email))
    .map((u) => ({ owner_email: u.email, subdomain: null, status: 'not registered', __placeholder: true }))
  const tenantRows = [...registry, ...placeholderRows]

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
        <div className="ml-auto shrink-0 flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <KeyRound className="w-3.5 h-3.5" />
            <span className="font-mono text-slate-400">{session?.email}</span>
            <RoleBadge role={session?.role} />
          </div>
          <button onClick={handleRefresh} disabled={refreshing} className="btn-ghost text-xs disabled:opacity-40">
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button onClick={handleLogout} className="btn-ghost text-xs">
            <LogOut className="w-3.5 h-3.5" />
            Sign out
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
            <button
              onClick={() => setActiveTab('users')}
              className={`px-5 py-2.5 text-sm font-bold transition-all duration-150 border-b-2 -mb-px flex items-center gap-2 ${
                activeTab === 'users'
                  ? 'text-orange-400 border-orange-400'
                  : 'text-slate-500 border-transparent hover:text-slate-300 hover:border-slate-600'
              }`}
            >
              <KeyRound className="w-3.5 h-3.5" /> Users
            </button>
          </div>

          <div className="pt-4 space-y-4">
            {activeTab === 'tenants' && !isViewer && (
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
            {activeTab === 'tenants' && (
              <TenantsTable
                rows={tenantRows}
                onToggle={handleToggle}
                onDelete={handleDelete}
                actionBusy={actionBusy}
                selected={selected}
                onToggleSelect={handleToggleSelect}
                onToggleSelectAll={handleToggleSelectAll}
                readOnly={isViewer}
              />
            )}
            {activeTab === 'history' && <HistoryTable history={history} />}
            {activeTab === 'users' && <UsersTab role={session?.role} />}
          </div>
        </>
      )}
    </div>
  )
}
