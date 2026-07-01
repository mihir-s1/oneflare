import { useState, useEffect } from 'react'
import {
  ChevronDown, ChevronUp, Shield, Globe, Eye, EyeOff,
  CheckCircle, XCircle, Download, Upload, Info, Zap, AlertTriangle
} from 'lucide-react'

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

export default function Settings() {
  const [settings, setSettings] = useState(loadSettings)
  const [testStatus, setTestStatus] = useState(null) // null | 'testing' | 'ok' | 'fail'
  const [testMsg, setTestMsg] = useState('')
  const [saved, setSaved] = useState(false)

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

      {/* Privacy banner */}
      <div className="rounded-xl border border-green-500/20 bg-green-500/5 p-4 flex gap-3">
        <Shield className="w-5 h-5 text-green-400 shrink-0 mt-0.5" />
        <p className="text-sm text-slate-300 leading-relaxed">
          <strong className="text-green-400">Settings are stored in your browser only.</strong>{' '}
          Tokens are never sent to external servers — only to your local Docker backend when you explicitly run an attack or test connection.
        </p>
      </div>

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
            placeholder="novamind-lab.workers.dev"
            note="Used to construct default target URLs. Example: novamind-lab.workers.dev"
          />

          <Field
            label="Gateway DoH URL"
            fieldKey="cf_gateway_doh_url"
            value={settings.cf_gateway_doh_url}
            onChange={handleChange}
            placeholder="https://<team>.cloudflareaccess.com/dns-query"
            note={
              <>
                Required for the DNS tunnel scenario to log in Gateway.{' '}
                Go to <strong className="text-slate-300">one.dash.cloudflare.com → Zero Trust → Settings → General</strong> and find your <strong className="text-slate-300">Team domain</strong> (e.g. <span className="font-mono">novamind.cloudflareaccess.com</span>).
                {' '}Your DoH URL is <span className="font-mono">https://&lt;team-domain&gt;/dns-query</span> — no location setup needed.
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
            placeholder={`https://shop.${settings.cf_domain || 'novamind-lab.workers.dev'}`}
          />
          <Field
            label="Portal URL"
            fieldKey="portal_url"
            value={settings.portal_url}
            onChange={handleChange}
            placeholder={`https://portal.${settings.cf_domain || 'novamind-lab.workers.dev'}`}
          />
          <Field
            label="API URL"
            fieldKey="api_url"
            value={settings.api_url}
            onChange={handleChange}
            placeholder={`https://api.${settings.cf_domain || 'novamind-lab.workers.dev'}`}
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
    </div>
  )
}
