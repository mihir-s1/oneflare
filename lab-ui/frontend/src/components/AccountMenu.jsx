// Account menu — navbar affordance for sign-in / switch-account / sign-out.
//
// The core fix this component exists for: POST /api/auth/login REPLACES the
// current session cookie outright. So a `user`-role visitor who wants to act
// as `admin` doesn't need a "log out first" step — they just need a login
// form available *somewhere* that isn't gated behind already being an admin.
// Surfacing it here (next to Settings, always reachable) replaces the old
// discreet footer link in Settings.
import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { CircleUser, LogOut, ShieldCheck, RefreshCw, X, UserPlus } from 'lucide-react'
import { getMe } from '../lib/session'
import RequestAccountForm from './RequestAccountForm'

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

// Inline login form used both for "Sign in" (logged out) and
// "Switch account / sign in as admin" (logged in as someone else). Submitting
// always POSTs to /auth/login, which replaces whatever session is active.
function InlineLoginForm({ autoFocus = true }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

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
        setBusy(false)
        return
      }
      // Full reload so every part of the app (nav, pages, any cached role
      // checks) picks up the new session consistently.
      window.location.href = '/'
    } catch {
      setError('Could not reach backend.')
      setBusy(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-2.5 px-1 py-1">
      <div>
        <label className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Email</label>
        <input
          type="email"
          required
          autoFocus={autoFocus}
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="mt-1 w-full rounded-lg bg-[#12081f] border border-[#2d1b4e] px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-orange-500/50"
          placeholder="you@sentinelone.com"
        />
      </div>
      <div>
        <label className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Password</label>
        <input
          type="password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="mt-1 w-full rounded-lg bg-[#12081f] border border-[#2d1b4e] px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-orange-500/50"
          placeholder="••••••••••"
        />
      </div>
      {error && <p className="text-[11px] text-red-400">{error}</p>}
      <button type="submit" disabled={busy} className="btn-primary w-full text-xs justify-center py-1.5 disabled:opacity-40">
        {busy ? <RefreshCw className="w-3 h-3 animate-spin" /> : null}
        {busy ? 'Signing in...' : 'Sign in'}
      </button>
    </form>
  )
}

export default function AccountMenu() {
  const navigate = useNavigate()
  const containerRef = useRef(null)

  const [open, setOpen] = useState(false)
  const [me, setMe] = useState(null) // { email, role } | null
  const [adminEnabled, setAdminEnabled] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [showSwitch, setShowSwitch] = useState(false)
  const [showRequest, setShowRequest] = useState(false)

  const load = useCallback(async () => {
    const [meData, cfg] = await Promise.all([
      getMe(),
      fetch('/api/config').then(r => (r.ok ? r.json() : null)).catch(() => null),
    ])
    setMe(meData)
    setAdminEnabled(!!cfg?.admin_enabled)
    setLoaded(true)
  }, [])

  // Initial load (so the button can hide itself on single-tenant instances).
  useEffect(() => { load() }, [load])

  // Refresh whenever the dropdown is opened, so role/session changes made
  // elsewhere (e.g. another tab) are reflected.
  useEffect(() => {
    if (open) load()
    if (!open) { setShowSwitch(false); setShowRequest(false) }
  }, [open, load])

  // Close on outside click / Escape.
  useEffect(() => {
    if (!open) return
    function handlePointer(e) {
      if (containerRef.current && !containerRef.current.contains(e.target)) setOpen(false)
    }
    function handleKey(e) {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', handlePointer)
    document.addEventListener('keydown', handleKey)
    return () => {
      document.removeEventListener('mousedown', handlePointer)
      document.removeEventListener('keydown', handleKey)
    }
  }, [open])

  async function handleSignOut() {
    try {
      await fetch('/api/auth/logout', { method: 'POST' })
    } catch {
      // best-effort
    } finally {
      window.location.href = '/'
    }
  }

  // Single-tenant instance (no login system at all) with nobody signed in —
  // nothing meaningful to show.
  if (loaded && !adminEnabled && !me) return null

  const canSeeAdmin = adminEnabled && (me?.role === 'admin' || me?.role === 'viewer')

  return (
    <div className="relative shrink-0" ref={containerRef}>
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label="Account menu"
        aria-haspopup="menu"
        aria-expanded={open}
        className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-sm font-medium transition-all duration-200 shrink-0 ${
          open
            ? 'text-orange-400 bg-orange-500/10'
            : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
        }`}
      >
        <CircleUser className="w-4 h-4 shrink-0" />
      </button>

      {open && (
        <div
          role="menu"
          className="absolute right-0 top-full mt-2 w-72 bg-[#1a0a2e] border border-[#2d1b4e] rounded-lg shadow-xl shadow-black/40 p-3 z-50"
        >
          {me ? (
            <>
              <div className="flex items-center justify-between gap-2 px-1 pb-2 mb-2 border-b border-[#2d1b4e]">
                <span className="text-xs font-mono text-slate-300 truncate">{me.email}</span>
                <RoleBadge role={me.role} />
              </div>

              {canSeeAdmin && (
                <button
                  onClick={() => { setOpen(false); navigate('/admin') }}
                  role="menuitem"
                  className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg text-sm text-slate-300 hover:text-slate-100 hover:bg-white/5 transition-colors"
                >
                  <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
                  Admin console
                </button>
              )}

              <button
                onClick={() => setShowSwitch((v) => !v)}
                role="menuitem"
                aria-expanded={showSwitch}
                className={`w-full flex items-center gap-2 px-2 py-1.5 rounded-lg text-sm transition-colors ${
                  showSwitch ? 'text-orange-400 bg-orange-500/10' : 'text-slate-300 hover:text-slate-100 hover:bg-white/5'
                }`}
              >
                <RefreshCw className="w-3.5 h-3.5 shrink-0" />
                Switch account
              </button>

              {showSwitch && (
                <div className="mt-1 mb-1 rounded-lg bg-[#12081f]/60 border border-[#2d1b4e] p-2.5">
                  <div className="flex items-center justify-between mb-1.5">
                    <p className="text-[11px] text-slate-500 leading-snug">
                      Signing in replaces your current session.
                    </p>
                    <button
                      onClick={() => setShowSwitch(false)}
                      aria-label="Cancel switch account"
                      className="text-slate-500 hover:text-slate-300 shrink-0"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </div>
                  <InlineLoginForm />
                </div>
              )}

              <div className="mt-2 pt-2 border-t border-[#2d1b4e]">
                <button
                  onClick={handleSignOut}
                  role="menuitem"
                  className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg text-sm text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors"
                >
                  <LogOut className="w-3.5 h-3.5 shrink-0" />
                  Sign out
                </button>
              </div>
            </>
          ) : showRequest ? (
            <>
              <div className="flex items-center justify-between px-1 pb-2 mb-1 border-b border-[#2d1b4e]">
                <p className="text-xs font-semibold text-slate-300">Request an account</p>
                <button
                  onClick={() => setShowRequest(false)}
                  aria-label="Back to sign in"
                  className="text-slate-500 hover:text-slate-300 shrink-0"
                >
                  <X className="w-3 h-3" />
                </button>
              </div>
              <RequestAccountForm compact onCancel={() => setShowRequest(false)} />
            </>
          ) : (
            <>
              <p className="text-xs font-semibold text-slate-300 px-1 pb-2 mb-1 border-b border-[#2d1b4e]">
                Sign in
              </p>
              <InlineLoginForm />
              <div className="mt-2 pt-2 border-t border-[#2d1b4e]">
                <button
                  onClick={() => setShowRequest(true)}
                  className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg text-sm text-slate-300 hover:text-slate-100 hover:bg-white/5 transition-colors"
                >
                  <UserPlus className="w-3.5 h-3.5 shrink-0" />
                  Request an account
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
