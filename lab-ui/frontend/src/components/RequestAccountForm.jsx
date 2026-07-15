// Request-account form — shown to a visitor who is past the Cloudflare Access
// OTP gate but doesn't yet have a console (RBAC) account. Submitting POSTs to
// /api/auth/request-account, which emails every admin a tokenized accept link.
// Used both in the navbar AccountMenu (logged-out) and under the /admin login
// form. Compact by default (`compact` prop) so it fits the account dropdown.
import { useState } from 'react'
import { RefreshCw, CheckCircle, UserPlus } from 'lucide-react'

export default function RequestAccountForm({ compact = false, onCancel }) {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [done, setDone] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const res = await fetch('/api/auth/request-account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setError(data.error || data.detail || 'Could not send your request.')
        setBusy(false)
        return
      }
      setDone(true)
    } catch {
      setError('Could not reach backend.')
      setBusy(false)
    }
  }

  const inputCls = compact
    ? 'mt-1 w-full rounded-lg bg-[#12081f] border border-[#2d1b4e] px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-orange-500/50'
    : 'mt-1 w-full rounded-lg bg-[#12081f] border border-[#2d1b4e] px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-orange-500/50'
  const labelCls = compact
    ? 'text-[10px] font-semibold text-slate-500 uppercase tracking-wider'
    : 'text-xs font-semibold text-slate-400 uppercase tracking-wider'

  if (done) {
    return (
      <div className={`flex flex-col items-center gap-2 text-center ${compact ? 'py-2' : 'py-4'}`}>
        <CheckCircle className={compact ? 'w-5 h-5 text-green-400' : 'w-7 h-7 text-green-400'} />
        <p className={`${compact ? 'text-xs' : 'text-sm'} text-slate-200 font-medium`}>Request sent</p>
        <p className={`${compact ? 'text-[11px]' : 'text-xs'} text-slate-500 leading-snug`}>
          An admin will review it. You'll get an email with a link to set your password once it's approved.
        </p>
      </div>
    )
  }

  return (
    <form onSubmit={handleSubmit} className={compact ? 'space-y-2.5 px-1 py-1' : 'w-full space-y-3'}>
      {!compact && (
        <p className="text-xs text-slate-500 leading-snug">
          Don't have an account? Request one — an admin reviews it and you'll get an invite by email.
        </p>
      )}
      <div>
        <label className={labelCls}>Name</label>
        <input
          type="text"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          className={inputCls}
          placeholder="Your name"
        />
      </div>
      <div>
        <label className={labelCls}>Email</label>
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className={inputCls}
          placeholder="you@sentinelone.com"
        />
      </div>
      {error && <p className={`${compact ? 'text-[11px]' : 'text-xs'} text-red-400`}>{error}</p>}
      <div className="flex gap-2">
        {onCancel && (
          <button
            type="button"
            onClick={onCancel}
            className={`rounded-lg border border-[#2d1b4e] text-slate-400 hover:text-slate-200 hover:bg-white/5 ${compact ? 'text-xs px-2.5 py-1.5' : 'text-sm px-3 py-2'}`}
          >
            Cancel
          </button>
        )}
        <button
          type="submit"
          disabled={busy}
          className={`btn-primary flex-1 justify-center disabled:opacity-40 ${compact ? 'text-xs py-1.5' : 'text-sm'}`}
        >
          {busy ? <RefreshCw className={compact ? 'w-3 h-3 animate-spin' : 'w-3.5 h-3.5 animate-spin'} /> : <UserPlus className={compact ? 'w-3 h-3' : 'w-3.5 h-3.5'} />}
          {busy ? 'Sending…' : 'Request account'}
        </button>
      </div>
    </form>
  )
}
