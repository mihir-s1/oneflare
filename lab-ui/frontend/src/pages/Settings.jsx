import { useState, useEffect } from 'react'
import {
  ChevronDown, ChevronUp, Shield, Globe, Eye, EyeOff,
  CheckCircle, XCircle, Download, Upload, Info, Zap, AlertTriangle,
  History as HistoryIcon, Trash2, Clock, X, Fingerprint,
} from 'lucide-react'
import Badge from '../components/Badge.jsx'
import { SCENARIOS } from '../data/scenarios.js'

const STORAGE_KEYS = {
  cf_api_token:        'oneflare_cf_api_token',
  cf_account_id:       'oneflare_cf_account_id',
  cf_zone_id:          'oneflare_cf_zone_id',
  cf_domain:           'oneflare_cf_domain',
  cf_gateway_doh_url:  'oneflare_cf_gateway_doh_url',
  shop_url:            'oneflare_shop_url',
  portal_url:          'oneflare_portal_url',
  api_url:             'oneflare_api_url',
  s1_api_url:          'oneflare_s1_api_url',
  s1_api_token:        'oneflare_s1_api_token',
  s1_mcp_url:          'oneflare_s1_mcp_url',
  attack_delay:        'oneflare_attack_delay',
  attack_jitter:       'oneflare_attack_jitter',
}

function loadSettings() {
  const out = {}
  for (const [key, storageKey] of Object.entries(STORAGE_KEYS)) {
    out[key] = localStorage.getItem(storageKey) || ''
  }
  return out
}

function saveField(key, value) {
  localStorage.setItem(STORAGE_KEYS[key], value)
}

function Section({ title, icon: Icon, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="collapsible-section">
      <div className="collapsible-header" onClick={() => setOpen(!open)}>
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-white/5 flex items-center justify-center">
            <Icon className="w-4 h-4 text-orange-400" />
          </div>
          <span className="text-sm font-semibold text-slate-200">{title}</span>
        </div>
        {open ? (
          <ChevronUp className="w-4 h-4 text-slate-400" />
        ) : (
          <ChevronDown className="w-4 h-4 text-slate-400" />
        )}
      </div>
      {open && <div className="collapsible-body">{children}</div>}
    </div>
  )
}

function Field({ label, fieldKey, value, onChange, type = 'text', placeholder = '', note, showToggle = false }) {
  const [show, setShow] = useState(false)
  const inputType = showToggle ? (show ? 'text' : 'password') : type

  return (
    <div className="space-y-1.5">
      <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">{label}</label>
      <div className="relative">
        <input
          type={inputType}
          value={value}
          onChange={(e) => onChange(fieldKey, e.target.value)}
          placeholder={placeholder}
          className="lab-input pr-8"
          spellCheck={false}
          autoComplete="off"
        />
        {showToggle && (
          <button
            type="button"
            onClick={() => setShow(!show)}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
          >
            {show ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          </button>
        )}
      </div>
      {note && <p className="text-xs text-slate-500 leading-relaxed">{note}</p>}
    </div>
  )
}

// ── History helpers ────────────────────────────────────────────────────────

function getHistory() {
  try {
    return JSON.parse(localStorage.getItem('oneflare_run_history') || '[]').reverse()
  } catch {
    return []
  }
}

function formatHistoryTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function getHistoryScenario(id) {
  return SCENARIOS.find(s => s.id === id)
}

function HistoryContent() {
  const [history, setHistory] = useState([])
  const [viewEntry, setViewEntry] = useState(null)

  useEffect(() => {
    setHistory(getHistory())
  }, [])

  function clearHistory() {
    if (window.confirm('Clear all run history?')) {
      localStorage.removeItem('oneflare_run_history')
      setHistory([])
    }
  }

  if (history.length === 0) {
    return (
      <div className="rounded-xl border border-[#2d1b4e] bg-[#1a0a2e]/50 p-12 flex flex-col items-center gap-4">
        <div className="w-12 h-12 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
          <HistoryIcon className="w-6 h-6 text-slate-500" />
        </div>
        <div className="text-center">
          <p className="text-slate-300 font-medium">No runs yet</p>
          <p className="text-sm text-slate-500 mt-1">Run an attack from the Scenario Detail page to see history here.</p>
        </div>
      </div>
    )
  }

  return (
    <>
      <div className="flex items-center justify-between mb-4">
        <span className="text-xs text-slate-500 font-mono">{history.length} run{history.length !== 1 ? 's' : ''} stored</span>
        <button
          onClick={clearHistory}
          className="btn-ghost text-xs text-red-400 hover:text-red-300 hover:border-red-500/30"
        >
          <Trash2 className="w-3.5 h-3.5" />
          Clear History
        </button>
      </div>

      <div className="rounded-xl border border-[#2d1b4e] overflow-hidden">
        {/* Table header */}
        <div className="grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-4 px-5 py-3 bg-[#1a0a2e] border-b border-[#2d1b4e] text-xs font-semibold text-slate-500 uppercase tracking-wider">
          <span>#</span>
          <span>Scenario</span>
          <span>Timestamp</span>
          <span>Status</span>
          <span className="hidden sm:block">Lines</span>
          <span>Log</span>
        </div>

        {history.map((entry, i) => {
          const sc = getHistoryScenario(entry.scenario)
          const success = entry.exitCode === 0
          return (
            <div
              key={entry.id || i}
              className="grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-4 px-5 py-3.5 border-b border-[#1e1235] last:border-0 hover:bg-white/[0.02] transition-colors items-center"
            >
              <span className="text-xs font-mono text-slate-600">{history.length - i}</span>

              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-medium text-slate-200">{entry.title}</span>
                  {sc && <Badge type="category" value={sc.category} />}
                </div>
                <span className="text-xs text-slate-500 font-mono">{entry.scenario}</span>
              </div>

              <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono whitespace-nowrap">
                <Clock className="w-3 h-3 text-slate-600" />
                {formatHistoryTime(entry.timestamp)}
              </div>

              <div>
                {success ? (
                  <div className="flex items-center gap-1 text-green-400 text-xs">
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>Done</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-1 text-red-400 text-xs">
                    <XCircle className="w-3.5 h-3.5" />
                    <span>Error</span>
                  </div>
                )}
              </div>

              <span className="hidden sm:block text-xs font-mono text-slate-500">
                {entry.lines?.length ?? 0}
              </span>

              <button
                onClick={() => setViewEntry(entry)}
                className="flex items-center gap-1 text-xs text-slate-400 hover:text-orange-400 transition-colors"
              >
                <Eye className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">View</span>
              </button>
            </div>
          )
        })}
      </div>

      {/* Log modal */}
      {viewEntry && (
        <div className="modal-backdrop" onClick={() => setViewEntry(null)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#2d1b4e]">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">{viewEntry.title}</h3>
                <p className="text-xs text-slate-500 font-mono mt-0.5">{formatHistoryTime(viewEntry.timestamp)}</p>
              </div>
              <button onClick={() => setViewEntry(null)} className="text-slate-500 hover:text-slate-300 transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div
              className="terminal-scroll overflow-y-auto p-4 flex-1"
              style={{ background: '#0a0a0a', fontFamily: '"JetBrains Mono", monospace', fontSize: '12px' }}
            >
              {viewEntry.lines?.map((line, i) => (
                <div key={i} className="text-slate-300 leading-5 whitespace-pre-wrap break-all">
                  {line || ' '}
                </div>
              ))}
              {!viewEntry.lines?.length && (
                <span className="text-slate-600">No output recorded.</span>
              )}
            </div>
            <div className="px-5 py-3 border-t border-[#2d1b4e] flex items-center justify-between">
              <span className="text-xs text-slate-500 font-mono">
                {viewEntry.lines?.length ?? 0} lines — exit code {viewEntry.exitCode}
              </span>
              <button
                onClick={() => {
                  const text = viewEntry.lines?.join('\n') || ''
                  navigator.clipboard.writeText(text)
                }}
                className="text-xs text-slate-400 hover:text-slate-200 transition-colors"
              >
                Copy all
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

// ── Lab Identity ─────────────────────────────────────────────────────────────
// Registers this instance under a unique subdomain (<name>.lab.soledrop.co) and
// routes its Cloudflare telemetry to the operator's own SentinelOne site. The S1
// HEC write token is never persisted client-side — it is only ever sent to our
// own backend on submit.
const LAB_NAME_KEY = 'oneflare_lab_name'
const LAB_SUBDOMAIN_KEY = 'oneflare_lab_subdomain'

function LabIdentitySection({ serverConfig }) {
  const [name, setName] = useState(() => localStorage.getItem(LAB_NAME_KEY) || '')
  const [s1HecUrl, setS1HecUrl] = useState('')
  const [s1HecToken, setS1HecToken] = useState('')
  const [siteLabel, setSiteLabel] = useState('')
  const [accountLabel, setAccountLabel] = useState('')
  const [s1ConsoleUrl, setS1ConsoleUrl] = useState('')
  const [identity, setIdentity] = useState(null)
  const [loading, setLoading] = useState(true)
  const [registering, setRegistering] = useState(false)
  const [error, setError] = useState('')
  const [resetNotice, setResetNotice] = useState('')

  const relayConfigured = serverConfig?.relay_configured ?? false
  const labDomain = serverConfig?.lab_domain || 'lab.soledrop.co'

  useEffect(() => {
    let alive = true
    fetch('/api/lab/identity')
      .then(r => (r.ok ? r.json() : null))
      .then(data => {
        if (!alive || !data) return
        if (data.reset) {
          setIdentity(null)
          setResetNotice(data.message || 'This instance was reset by the admin — please register again.')
          localStorage.removeItem(LAB_NAME_KEY)
          localStorage.removeItem(LAB_SUBDOMAIN_KEY)
          return
        }
        if (data.identity) {
          setIdentity(data.identity)
          setName(data.identity.name || '')
          setS1HecUrl(data.identity.s1_hec_url || '')
          setSiteLabel(data.identity.site_label || '')
          setAccountLabel(data.identity.account_label || '')
          setS1ConsoleUrl(data.identity.s1_console_url || '')
          localStorage.setItem(LAB_NAME_KEY, data.identity.name || '')
          if (data.identity.subdomain) localStorage.setItem(LAB_SUBDOMAIN_KEY, data.identity.subdomain)
        }
      })
      .catch(() => {})
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [])

  async function handleRegister(e) {
    e.preventDefault()
    setRegistering(true)
    setError('')
    try {
      const res = await fetch('/api/lab/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name, s1_hec_url: s1HecUrl, s1_hec_token: s1HecToken,
          site_label: siteLabel, account_label: accountLabel,
          s1_console_url: s1ConsoleUrl || undefined,
        }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setError(data.detail || `Registration failed (HTTP ${res.status})`)
        return
      }
      setIdentity(data.identity)
      setResetNotice('')
      setS1HecToken('')
      if (data.identity?.name) localStorage.setItem(LAB_NAME_KEY, data.identity.name)
      if (data.identity?.subdomain) localStorage.setItem(LAB_SUBDOMAIN_KEY, data.identity.subdomain)
    } catch (err) {
      setError('Could not reach backend. Is Docker running?')
    } finally {
      setRegistering(false)
    }
  }

  return (
    <Section title="Lab Identity" icon={Fingerprint} defaultOpen={true}>
      <div className="space-y-4">
        <p className="text-sm text-slate-400 leading-relaxed">
          Registering a name gives this instance a unique subdomain{' '}
          <span className="font-mono text-slate-300">&lt;name&gt;.{labDomain}</span> and routes its
          Cloudflare telemetry to <strong className="text-slate-200">your</strong> SentinelOne site.
        </p>

        {resetNotice && (
          <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-3 flex gap-2 text-sm text-yellow-400">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            {resetNotice}
          </div>
        )}

        {identity && (
          <div className="rounded-lg border border-purple-500/20 bg-purple-500/5 p-3 flex items-center justify-between flex-wrap gap-2">
            <div>
              <span className="text-xs text-slate-500 uppercase tracking-wider font-semibold block mb-0.5">Current subdomain</span>
              <span className="font-mono text-sm text-purple-300">{identity.subdomain}</span>
            </div>
            <span className={`inline-flex items-center rounded-full font-semibold px-2 py-0.5 text-xs ${
              identity.enrolled
                ? 'bg-green-500/15 text-green-400 border border-green-500/30'
                : 'bg-slate-500/15 text-slate-400 border border-slate-500/30'
            }`}>
              {identity.enrolled ? 'enrolled' : 'pending'}
            </span>
          </div>
        )}

        <form onSubmit={handleRegister} className="space-y-4">
          <Field
            label="Display Name"
            fieldKey="lab_name"
            value={name}
            onChange={(_, v) => setName(v)}
            placeholder="e.g. alice"
            note="Letters, numbers, and hyphens only — becomes the subdomain label."
          />
          <Field
            label="S1 HEC Ingest URL"
            fieldKey="lab_s1_hec_url"
            value={s1HecUrl}
            onChange={(_, v) => setS1HecUrl(v)}
            placeholder="https://ingest.<region>.sentinelone.net/services/collector/raw?sourcetype=marketplace-cloudflare-latest"
          />
          <Field
            label="S1 HEC Write Token"
            fieldKey="lab_s1_hec_token"
            value={s1HecToken}
            onChange={(_, v) => setS1HecToken(v)}
            showToggle
            placeholder="HEC write token from your SentinelOne console"
            note="Sent only to this backend on submit — never stored in your browser."
          />
          <Field
            label="S1 Site"
            fieldKey="lab_site_label"
            value={siteLabel}
            onChange={(_, v) => setSiteLabel(v)}
            placeholder="e.g. ahamidi"
            note="Required. The SentinelOne site this instance's logs land in — named in the admin tenant list (display only, not used for routing)."
          />
          <Field
            label="S1 Account"
            fieldKey="lab_account_label"
            value={accountLabel}
            onChange={(_, v) => setAccountLabel(v)}
            placeholder="e.g. SentinelOne"
            note="Required. The SentinelOne account that owns the site."
          />
          <Field
            label="S1 Console URL (optional)"
            fieldKey="lab_s1_console_url"
            value={s1ConsoleUrl}
            onChange={(_, v) => setS1ConsoleUrl(v)}
            placeholder="e.g. https://usea1-purple.sentinelone.net"
            note="Optional. Your console/'purple' domain — shown as the destination host in the admin list. Falls back to the ingest host if blank."
          />

          <div className="flex items-center gap-3 pt-1">
            <button
              type="submit"
              disabled={registering || !name || !s1HecUrl || !s1HecToken || !siteLabel || !accountLabel}
              className="btn-orange text-sm disabled:opacity-40"
            >
              {registering ? (
                <span className="flex items-center gap-2">
                  <span className="w-3.5 h-3.5 border-2 border-white/60 border-t-transparent rounded-full animate-spin" />
                  Registering...
                </span>
              ) : 'Register'}
            </button>
            {loading && <span className="text-xs text-slate-500 font-mono">Checking identity...</span>}
          </div>

          {error && (
            <div className="flex items-center gap-1.5 text-sm text-red-400">
              <XCircle className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}

          {!error && identity && !registering && (
            relayConfigured ? (
              <div className="flex items-center gap-1.5 text-sm text-green-400">
                <CheckCircle className="w-4 h-4 shrink-0" />
                enrolled with relay ✓
              </div>
            ) : (
              <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-3 flex gap-2 text-xs text-yellow-400">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                Relay not configured yet — subdomain assigned locally; enrollment will complete once RELAY_URL is set.
              </div>
            )
          )}
        </form>
      </div>
    </Section>
  )
}

export default function Settings() {
  const [settings, setSettings] = useState(loadSettings)
  const [testStatus, setTestStatus] = useState(null) // null | 'testing' | 'ok' | 'fail'
  const [testMsg, setTestMsg] = useState('')
  const [saved, setSaved] = useState(false)
  // Server-side non-sensitive defaults (GET /api/config) — this instance is
  // pre-configured so anyone can run scenarios; fields below are optional
  // per-browser overrides on top of these.
  const [serverConfig, setServerConfig] = useState(null)
  useEffect(() => {
    let alive = true
    fetch('/api/config')
      .then(r => (r.ok ? r.json() : null))
      .then(cfg => { if (alive) setServerConfig(cfg) })
      .catch(() => {})
    return () => { alive = false }
  }, [])

  function handleChange(key, value) {
    setSettings(prev => {
      const updated = { ...prev, [key]: value }
      saveField(key, value)
      return updated
    })
    setSaved(true)
    setTimeout(() => setSaved(false), 1500)
  }

  async function testConnection() {
    setTestStatus('testing')
    setTestMsg('')
    try {
      const res = await fetch('/api/test-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cf_api_token: settings.cf_api_token }),
      })
      const data = await res.json()
      if (data.ok) {
        setTestStatus('ok')
        setTestMsg(`Token valid — ${data.result?.status || 'active'}`)
      } else {
        setTestStatus('fail')
        setTestMsg(data.error || 'Token validation failed')
      }
    } catch (err) {
      setTestStatus('fail')
      setTestMsg('Could not reach backend. Is Docker running?')
    }
  }

  function exportSettings() {
    const exportable = { ...settings }
    delete exportable.cf_api_token
    delete exportable.s1_api_token
    const blob = new Blob([JSON.stringify(exportable, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'oneflare-settings.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  function importSettings() {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '.json'
    input.onchange = (e) => {
      const file = e.target.files[0]
      if (!file) return
      const reader = new FileReader()
      reader.onload = (ev) => {
        try {
          const data = JSON.parse(ev.target.result)
          for (const [key, value] of Object.entries(data)) {
            if (STORAGE_KEYS[key] && value) {
              saveField(key, value)
            }
          }
          setSettings(loadSettings())
        } catch {
          alert('Invalid JSON file')
        }
      }
      reader.readAsText(file)
    }
    input.click()
  }

  const delay = parseFloat(settings.attack_delay) || 0.5
  const jitter = parseFloat(settings.attack_jitter) || 0.3

  return (
    <div className="page-enter space-y-5 max-w-2xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Settings</h1>
          <p className="text-sm text-slate-400 mt-0.5">Configure your lab credentials and attack parameters</p>
        </div>
        <div className="flex items-center gap-2">
          {saved && (
            <span className="text-xs text-green-400 flex items-center gap-1 animate-[fadeIn_0.2s_ease]">
              <CheckCircle className="w-3.5 h-3.5" /> Saved
            </span>
          )}
          <button onClick={exportSettings} className="btn-ghost text-xs">
            <Download className="w-3.5 h-3.5" />
            Export
          </button>
          <button onClick={importSettings} className="btn-ghost text-xs">
            <Upload className="w-3.5 h-3.5" />
            Import
          </button>
        </div>
      </div>

      {/* Pre-configured banner — this instance ships server-side defaults */}
      {serverConfig?.domain && (
        <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-4 flex gap-3">
          <Info className="w-5 h-5 text-orange-400 shrink-0 mt-0.5" />
          <p className="text-sm text-slate-300 leading-relaxed">
            <strong className="text-orange-400">This instance is pre-configured.</strong>{' '}
            Scenarios target <span className="font-mono text-slate-200">{serverConfig.domain}</span> out of the box —
            you don't need to fill anything in to run them. The non-sensitive fields below are
            <strong className="text-slate-200"> optional per-browser overrides</strong> on top of the server defaults.
            API tokens are never baked in and always stay in your browser.
          </p>
        </div>
      )}

      {/* Privacy banner */}
      <div className="rounded-xl border border-green-500/20 bg-green-500/5 p-4 flex gap-3">
        <Shield className="w-5 h-5 text-green-400 shrink-0 mt-0.5" />
        <p className="text-sm text-slate-300 leading-relaxed">
          <strong className="text-green-400">Settings are stored in your browser only.</strong>{' '}
          Tokens are never sent to external servers — only to your local Docker backend when you explicitly run an attack or test connection.
        </p>
      </div>

      {/* Section 0: Lab Identity — multi-tenant relay registration */}
      <LabIdentitySection serverConfig={serverConfig} />

      {/* Section 1: Cloudflare */}
      <Section title="Cloudflare Configuration" icon={Shield} defaultOpen={true}>
        <div className="space-y-4">
          <Field
            label="CF API Token"
            fieldKey="cf_api_token"
            value={settings.cf_api_token}
            onChange={handleChange}
            showToggle
            placeholder="Bearer token from dash.cloudflare.com/profile/api-tokens"
            note="Required permissions: Zone Read, Firewall Write, Zone WAF Edit, Logpush Read"
          />
          <div className="grid grid-cols-2 gap-3">
            <Field
              label="Account ID"
              fieldKey="cf_account_id"
              value={settings.cf_account_id}
              onChange={handleChange}
              placeholder="32-char hex string"
            />
            <Field
              label="Zone ID"
              fieldKey="cf_zone_id"
              value={settings.cf_zone_id}
              onChange={handleChange}
              placeholder="32-char hex string"
            />
          </div>
          <Field
            label="Domain"
            fieldKey="cf_domain"
            value={settings.cf_domain}
            onChange={handleChange}
            placeholder={serverConfig?.domain || 'your-domain.com'}
            note={serverConfig?.domain
              ? `Server default: ${serverConfig.domain} — shop/portal/api.${serverConfig.domain} are Cloudflare-proxied with WAF + Logpush to SentinelOne. Leave blank to use it; set a value only to point YOUR browser at a different domain.`
              : 'Target domain for attacks. shop/portal/api.<domain> must be Cloudflare-proxied workers with WAF + Logpush configured.'}
          />

          <Field
            label="Gateway DoH URL"
            fieldKey="cf_gateway_doh_url"
            value={settings.cf_gateway_doh_url}
            onChange={handleChange}
            placeholder="https://<hex-id>.cloudflare-gateway.com/dns-query"
            note={
              <>
                Required for the DNS tunnel scenario to log in Gateway.{' '}
                Go to <strong className="text-slate-300">one.dash.cloudflare.com → Networks → Resolvers &amp; Proxies → DNS locations → [your location] → DNS over HTTPS</strong> and copy the endpoint (a <strong className="text-slate-300">hex subdomain</strong>, e.g. <span className="font-mono">https://4a7f0b2c.cloudflare-gateway.com/dns-query</span>).
                {' '}Use this location-specific URL — the <span className="font-mono">&lt;team&gt;.cloudflareaccess.com</span> team URL resolves DNS but does <strong className="text-slate-300">not</strong> log queries to Gateway activity or Logpush.
              </>
            }
          />

          {/* Test connection */}
          <div className="flex items-center gap-3 pt-1">
            <button
              onClick={testConnection}
              disabled={testStatus === 'testing' || !settings.cf_api_token}
              className="btn-ghost text-sm disabled:opacity-40"
            >
              {testStatus === 'testing' ? (
                <span className="flex items-center gap-2">
                  <span className="w-3.5 h-3.5 border-2 border-slate-400 border-t-transparent rounded-full animate-spin" />
                  Testing...
                </span>
              ) : 'Test Connection'}
            </button>
            {testStatus === 'ok' && (
              <span className="flex items-center gap-1.5 text-sm text-green-400">
                <CheckCircle className="w-4 h-4" />
                {testMsg}
              </span>
            )}
            {testStatus === 'fail' && (
              <span className="flex items-center gap-1.5 text-sm text-red-400">
                <XCircle className="w-4 h-4" />
                {testMsg}
              </span>
            )}
          </div>
        </div>
      </Section>

      {/* Section 2: Target URL Overrides */}
      <Section title="Target URL Overrides" icon={Globe}>
        <div className="space-y-4">
          <div className="rounded-lg bg-white/3 border border-white/10 p-3 flex gap-2 text-xs text-slate-400">
            <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
            Leave blank to use defaults constructed from your Domain setting above.
          </div>
          <Field
            label="Shop URL"
            fieldKey="shop_url"
            value={settings.shop_url}
            onChange={handleChange}
            placeholder={`https://shop.${settings.cf_domain || 'one-flare.com'}`}
          />
          <Field
            label="Portal URL"
            fieldKey="portal_url"
            value={settings.portal_url}
            onChange={handleChange}
            placeholder={`https://portal.${settings.cf_domain || 'one-flare.com'}`}
          />
          <Field
            label="API URL"
            fieldKey="api_url"
            value={settings.api_url}
            onChange={handleChange}
            placeholder={`https://api.${settings.cf_domain || 'one-flare.com'}`}
          />
        </div>
      </Section>

      {/* Section 3: SentinelOne */}
      <Section title="SentinelOne Configuration" icon={Shield}>
        <div className="space-y-4">
          <Field
            label="S1 API URL"
            fieldKey="s1_api_url"
            value={settings.s1_api_url}
            onChange={handleChange}
            placeholder="https://your-tenant.sentinelone.net"
          />
          <Field
            label="S1 API Token"
            fieldKey="s1_api_token"
            value={settings.s1_api_token}
            onChange={handleChange}
            showToggle
            placeholder="API token from SentinelOne console"
          />
          <Field
            label="S1 MCP Server URL"
            fieldKey="s1_mcp_url"
            value={settings.s1_mcp_url}
            onChange={handleChange}
            placeholder="http://localhost:3001"
            note="Used by Claude Code's SentinelOne Purple MCP integration for automated response actions."
          />
        </div>
      </Section>

      {/* Section 4: Attack Intensity */}
      <Section title="Attack Intensity" icon={Zap}>
        <div className="space-y-5">
          <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-3 flex gap-2 text-xs text-yellow-400">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            Increasing speed reduces realism. Slower requests are harder to detect as automated.
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Request Delay</label>
              <span className="text-sm font-mono text-orange-400 font-bold">{delay.toFixed(1)}s</span>
            </div>
            <input
              type="range"
              min="0.1"
              max="5"
              step="0.1"
              value={delay}
              onChange={(e) => handleChange('attack_delay', e.target.value)}
            />
            <div className="flex justify-between text-xs text-slate-600">
              <span>0.1s (aggressive)</span>
              <span>5.0s (stealthy)</span>
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Jitter</label>
              <span className="text-sm font-mono text-purple-400 font-bold">±{jitter.toFixed(1)}s</span>
            </div>
            <input
              type="range"
              min="0"
              max="2"
              step="0.1"
              value={jitter}
              onChange={(e) => handleChange('attack_jitter', e.target.value)}
            />
            <div className="flex justify-between text-xs text-slate-600">
              <span>0s (no jitter)</span>
              <span>2.0s (max jitter)</span>
            </div>
            <p className="text-xs text-slate-500">
              Jitter adds random variation to delays, making traffic appear more human-like. Passed to attack scripts via <span className="font-mono text-slate-400">ATTACK_DELAY</span> and <span className="font-mono text-slate-400">ATTACK_JITTER</span> environment variables.
            </p>
          </div>
        </div>
      </Section>

      {/* Section 5: Run History */}
      <Section title="Run History" icon={HistoryIcon}>
        <HistoryContent />
      </Section>

      {/* Discreet admin portal entry point — intentionally low-key, not a nav
          item. The real gate is the credential login on /admin itself; this
          just keeps it out of partners' faces. */}
      <div className="pt-2 pb-1 text-center">
        <a href="/admin" className="text-xs text-slate-600 hover:text-slate-400 transition-colors">
          Admin portal login &rarr;
        </a>
      </div>
    </div>
  )
}
