import { useState, useEffect } from 'react'
import { useSearchParams, useNavigate, Link } from 'react-router-dom'
import { UserCheck, CheckCircle, AlertTriangle, ShieldAlert } from 'lucide-react'

// Accept-request: an admin lands here from the "Review & accept" link emailed
// when someone submits the request-account form —
// https://one-flare.com/admin/accept-request?token=...
//
// This page sits behind Cloudflare Access AND requires an ADMIN console session:
// GET /api/auth/request-info is admin-gated, so a logged-out (or non-admin)
// visitor is shown a "sign in as an admin" prompt instead of the request. Accept
// turns the request into a `user` invite (emails the invitee + Access-allowlists
// them via the shared onboarding path).
export default function AcceptRequest() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const token = searchParams.get('token') || ''

  const [req, setReq] = useState(null)          // { name, email, created_at }
  const [loadState, setLoadState] = useState('loading') // loading | ready | unauth | error | missing
  const [loadError, setLoadError] = useState('')

  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState('')
  const [result, setResult] = useState(null)    // { email, role, email_sent }

  useEffect(() => {
    if (!token) { setLoadState('missing'); return }
    let alive = true
    fetch(`/api/auth/request-info?token=${encodeURIComponent(token)}`)
      .then(async (res) => {
        const data = await res.json().catch(() => ({}))
        if (!alive) return
        if (res.status === 401 || res.status === 403) { setLoadState('unauth'); return }
        if (!res.ok) {
          setLoadError(data.error || 'This request is invalid or has expired.')
          setLoadState('error')
          return
        }
        setReq(data)
        setLoadState('ready')
      })
      .catch(() => { if (alive) { setLoadError('Could not reach backend.'); setLoadState('error') } })
    return () => { alive = false }
  }, [token])

  async function handleAccept() {
    setBusy(true)
    setActionError('')
    try {
      const res = await fetch('/api/auth/accept-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, role: 'user' }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setActionError(data.error || data.detail || 'Could not accept the request.')
        setBusy(false)
        return
      }
      setResult({ email: data.email, role: data.role, email_sent: data.email_sent })
    } catch {
      setActionError('Could not reach backend.')
      setBusy(false)
    }
  }

  async function handleDecline() {
    setBusy(true)
    setActionError('')
    try {
      const res = await fetch(`/api/auth/requests/${encodeURIComponent(token)}`, { method: 'DELETE' })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        setActionError(data.error || 'Could not decline the request.')
        setBusy(false)
        return
      }
      navigate('/admin')
    } catch {
      setActionError('Could not reach backend.')
      setBusy(false)
    }
  }

  const shell = 'page-enter max-w-sm mx-auto rounded-xl border border-[#2d1b4e] bg-[#1a0a2e]/50 p-8 flex flex-col items-center gap-4'

  if (result) {
    return (
      <div className="page-enter max-w-sm mx-auto rounded-xl border border-green-500/30 bg-green-500/5 p-8 flex flex-col items-center gap-3 text-center">
        <CheckCircle className="w-8 h-8 text-green-400" />
        <p className="text-slate-100 font-semibold">Invite created</p>
        <p className="text-sm text-slate-400">
          <span className="font-mono text-slate-300">{result.email}</span> was invited as{' '}
          <span className="text-slate-200">{result.role}</span>.
          {result.email_sent
            ? ' We emailed them a link to set their password.'
            : ' Share their invite link from the Admin → Users tab (email delivery was unavailable).'}
        </p>
        <Link to="/admin" className="btn-primary text-sm justify-center mt-1">Back to Admin</Link>
      </div>
    )
  }

  if (loadState === 'loading') {
    return <div className={shell}><p className="text-sm text-slate-500">Loading request…</p></div>
  }

  if (loadState === 'unauth') {
    return (
      <div className={shell}>
        <div className="w-12 h-12 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center">
          <ShieldAlert className="w-6 h-6 text-orange-400" />
        </div>
        <div className="text-center">
          <p className="text-slate-100 font-semibold">Admin sign-in required</p>
          <p className="text-sm text-slate-500 mt-1">
            Sign in as an admin to review this account request.
          </p>
        </div>
        <Link to="/admin" className="btn-primary text-sm justify-center">Go to Admin sign-in</Link>
      </div>
    )
  }

  if (loadState === 'missing' || loadState === 'error') {
    return (
      <div className={shell}>
        <div className="w-full rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-3 flex gap-2 text-xs text-yellow-400">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          {loadState === 'missing'
            ? 'No request token in the URL — open the link from the request email.'
            : (loadError || 'This request is invalid or has expired.')}
        </div>
        <Link to="/admin" className="text-xs text-slate-400 hover:text-slate-200">Back to Admin</Link>
      </div>
    )
  }

  // ready
  return (
    <div className={shell}>
      <div className="w-12 h-12 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center">
        <UserCheck className="w-6 h-6 text-orange-400" />
      </div>
      <div className="text-center">
        <p className="text-slate-100 font-semibold">Account request</p>
        <p className="text-sm text-slate-500 mt-1">
          Accepting invites this person as a <span className="text-slate-300">ThreatOps User</span> and emails them a setup link.
        </p>
      </div>
      <div className="w-full rounded-lg border border-[#2d1b4e] bg-[#12081f]/60 p-3 text-sm">
        {req?.name && <p className="text-slate-200 font-medium">{req.name}</p>}
        <p className="text-slate-400 font-mono text-xs mt-0.5">{req?.email}</p>
      </div>
      {actionError && <p className="text-xs text-red-400">{actionError}</p>}
      <div className="w-full flex gap-2">
        <button
          onClick={handleDecline}
          disabled={busy}
          className="rounded-lg border border-[#2d1b4e] text-slate-400 hover:text-red-300 hover:border-red-500/30 text-sm px-3 py-2 disabled:opacity-40"
        >
          Decline
        </button>
        <button
          onClick={handleAccept}
          disabled={busy}
          className="btn-primary flex-1 text-sm justify-center disabled:opacity-40"
        >
          {busy ? 'Working…' : 'Accept & invite'}
        </button>
      </div>
    </div>
  )
}
