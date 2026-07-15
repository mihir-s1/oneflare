import { useState, useEffect } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { KeyRound, CheckCircle, AlertTriangle } from 'lucide-react'

const ROLE_LABELS = {
  user: 'ThreatOps User',
  admin: 'Admin',
  viewer: 'Viewer',
}

// Accept-invite: reached via the link returned by POST /auth/invite (or
// /auth/bootstrap for the very first admin) — https://one-flare.com/admin/accept-invite?token=...
//
// NOTE: this page sits behind Cloudflare Access (OTP email gate) just like
// the rest of one-flare.com. The invitee's email must be on the Access
// allow-list or they can't reach this page at all — see RBAC.md and
// cloudflare/workers/logpush-relay/RBAC.md for the manual operator step.
export default function AcceptInvite() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const token = searchParams.get('token') || ''

  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [done, setDone] = useState(false)

  // Invite lookup — drives role-aware heading copy ("Set up your ThreatOps
  // User password" vs Admin/Viewer) and shows the invited email as context.
  const [invite, setInvite] = useState(null)      // { email, role, expires_at }
  const [inviteError, setInviteError] = useState('')
  const [inviteLoaded, setInviteLoaded] = useState(false)

  useEffect(() => {
    if (!token) { setInviteLoaded(true); return }
    let alive = true
    fetch(`/api/auth/invite-info?token=${encodeURIComponent(token)}`)
      .then(async (res) => {
        const data = await res.json().catch(() => ({}))
        if (!alive) return
        if (!res.ok) {
          setInviteError(data.error || 'This invite is invalid or expired.')
        } else {
          setInvite(data)
        }
      })
      .catch(() => { if (alive) setInviteError('This invite is invalid or expired.') })
      .finally(() => { if (alive) setInviteLoaded(true) })
    return () => { alive = false }
  }, [token])

  const roleLabel = ROLE_LABELS[invite?.role] || 'account'

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (!token) {
      setError('Missing invite token — use the link from your invite email.')
      return
    }
    if (password.length < 10) {
      setError('Password must be at least 10 characters.')
      return
    }
    if (password !== confirm) {
      setError('Passwords do not match.')
      return
    }
    setBusy(true)
    try {
      const res = await fetch('/api/auth/accept-invite', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, password }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setError(data.error || data.detail || 'Could not accept invite (it may have expired).')
        return
      }
      setDone(true)
      // Admins/viewers land in the admin console; a regular user lands on the
      // home page (the admin area would just show them "administrators only").
      const dest = (data.role === 'admin' || data.role === 'viewer') ? '/admin' : '/'
      setTimeout(() => navigate(dest), 1200)
    } catch (err) {
      setError('Could not reach backend. Is Docker running?')
    } finally {
      setBusy(false)
    }
  }

  if (done) {
    return (
      <div className="page-enter max-w-sm mx-auto rounded-xl border border-green-500/30 bg-green-500/5 p-8 flex flex-col items-center gap-3 text-center">
        <CheckCircle className="w-8 h-8 text-green-400" />
        <p className="text-slate-100 font-semibold">Account created</p>
        <p className="text-sm text-slate-400">Signing you in…</p>
      </div>
    )
  }

  return (
    <div className="page-enter max-w-sm mx-auto rounded-xl border border-[#2d1b4e] bg-[#1a0a2e]/50 p-8 flex flex-col items-center gap-4">
      <div className="w-12 h-12 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center">
        <KeyRound className="w-6 h-6 text-orange-400" />
      </div>
      <div className="text-center">
        <p className="text-slate-100 font-semibold">Set up your {roleLabel} password</p>
        <p className="text-sm text-slate-500 mt-1">Finish setting up your OneFlare console account.</p>
        {invite?.email && (
          <p className="text-xs text-slate-600 mt-2 font-mono">{invite.email}</p>
        )}
      </div>

      {!token && (
        <div className="w-full rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-3 flex gap-2 text-xs text-yellow-400">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          No invite token found in the URL — open the link from your invite email.
        </div>
      )}

      {token && inviteLoaded && inviteError && (
        <div className="w-full rounded-lg border border-red-500/20 bg-red-500/5 p-3 flex gap-2 text-xs text-red-400">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          {inviteError}
        </div>
      )}

      <form onSubmit={handleSubmit} className="w-full space-y-3">
        <div>
          <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Password</label>
          <input
            type="password"
            required
            minLength={10}
            autoFocus
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full rounded-lg bg-[#12081f] border border-[#2d1b4e] px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-orange-500/50"
            placeholder="At least 10 characters"
          />
        </div>
        <div>
          <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Confirm password</label>
          <input
            type="password"
            required
            minLength={10}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className="mt-1 w-full rounded-lg bg-[#12081f] border border-[#2d1b4e] px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-orange-500/50"
          />
        </div>
        {error && <p className="text-xs text-red-400">{error}</p>}
        <button type="submit" disabled={busy || !token || !!inviteError} className="btn-primary w-full text-sm justify-center disabled:opacity-40">
          {busy ? 'Creating account...' : 'Set password & sign in'}
        </button>
      </form>
    </div>
  )
}
