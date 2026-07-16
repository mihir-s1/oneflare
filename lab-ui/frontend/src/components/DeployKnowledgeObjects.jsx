import { useState, useEffect } from 'react'
import {
  Rocket, X, CheckCircle2, XCircle, AlertTriangle, Loader2, Info,
  ChevronDown, ChevronUp, KeyRound, RefreshCw, Pencil, Unlink, Lock,
  Shield, Workflow, LayoutDashboard, ServerCog, Circle,
} from 'lucide-react'
import Badge from './Badge.jsx'
import { KNOWLEDGE_OBJECT_GROUPS } from '../data/knowledgeObjects.js'
import { loadHaWorkflowJson } from '../data/haPlaybooks.js'

// Deploy wizard — pushes the lab's canonical knowledge objects (detections,
// Hyperautomation workflows, dashboards — see src/data/knowledgeObjects.js)
// to a signed-in user's OWN SentinelOne console via the session-gated
// /api/deploy/* backend contract:
//   GET    /api/deploy/config    -> {configured, console_url, has_token, sdl_xdr_url, updated_at}
//   POST   /api/deploy/config    -> same shape (secrets write-only, never echoed back)
//   DELETE /api/deploy/config    -> {ok, deleted}
//   POST   /api/deploy/validate  -> {ok, console_url, site, capabilities, messages}
//   POST   /api/deploy/run       -> {ok, site, results:[{key,type,status,id?,message}]}
//
// Four steps: Configure -> Validate -> Select -> Deploy. Every fetch handles
// 401 (sign in) and 403 (read-only role) the same way everywhere via `gate`.

const STEPS = [
  { id: 'configure', label: 'Configure' },
  { id: 'validate', label: 'Validate' },
  { id: 'select', label: 'Select' },
  { id: 'deploy', label: 'Deploy' },
]

const GROUP_ICON = { detection: Shield, ha: Workflow, dashboard: LayoutDashboard }
const CAP_KEY = { detection: 'detections', ha: 'ha', dashboard: 'dashboards' }
const CAPABILITY_ROWS = [
  { key: 'detections', label: 'Detections' },
  { key: 'ha', label: 'Hyperautomation' },
  { key: 'dashboards', label: 'Dashboards' },
]

// Flat lookup of every deployable item by "type:key" — used to resolve a
// human-readable name for a deploy result row.
const ITEM_BY_ID = {}
for (const group of KNOWLEDGE_OBJECT_GROUPS) {
  for (const item of group.items) ITEM_BY_ID[`${group.type}:${item.key}`] = item
}
const idFor = (type, key) => `${type}:${key}`

function formatTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function hostOf(url) {
  if (!url) return ''
  try { return new URL(url).host } catch { return url }
}

// Turn an HTTP error into an actionable message: prefer the backend's own
// error/detail, else surface a trimmed snippet of the raw body (strips HTML from
// edge/Access/WAF blocks), plus a hint for common statuses.
function describeHttpError(status, data, rawText, verb = 'Request') {
  const detail = (data && (data.error || (typeof data.detail === 'string' ? data.detail : null))) || ''
  const snippet = !detail && rawText
    ? rawText.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 220)
    : ''
  const hints = {
    403: 'Permission denied. If you used a scoped service-user token, its role may be missing a required write permission — deploying needs STAR Custom Rules, Hyperautomation, and (for dashboards) SDL Dashboards + SDL Configuration Files. If it persists after a page reload, your Cloudflare Access session may have expired — reload and sign in again.',
    502: 'The backend could not reach your SentinelOne console — check the Console URL and that the token is valid.',
    500: 'The backend hit an unexpected error while deploying.',
  }
  const hint = hints[status] || ''
  const lead = detail || snippet || `${verb} failed`
  return `${lead} (HTTP ${status})${hint ? ` — ${hint}` : ''}`
}

// ── Small shared bits ───────────────────────────────────────────────────────

function Stepper({ activeId }) {
  const activeIdx = STEPS.findIndex((s) => s.id === activeId)
  return (
    <div className="flex items-center gap-1.5 px-5 pt-3.5 pb-2 flex-wrap">
      {STEPS.map((s, i) => {
        const done = i < activeIdx
        const active = i === activeIdx
        return (
          <div key={s.id} className="flex items-center gap-1.5">
            <div
              className={`flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold transition-colors ${
                active
                  ? 'bg-orange-500/15 text-orange-400 border border-orange-500/30'
                  : done
                    ? 'text-slate-400'
                    : 'text-slate-600'
              }`}
            >
              {done ? <CheckCircle2 className="w-3.5 h-3.5 text-slate-500" /> : <Circle className={`w-3.5 h-3.5 ${active ? 'fill-orange-400 text-orange-400' : ''}`} />}
              {s.label}
            </div>
            {i < STEPS.length - 1 && <div className={`w-4 h-px ${done ? 'bg-slate-600' : 'bg-[#2d1b4e]'}`} />}
          </div>
        )
      })}
    </div>
  )
}

function LoadingBlock({ text }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-12 text-center">
      <Loader2 className="w-6 h-6 text-orange-400 animate-spin" />
      <p className="text-sm text-slate-400">{text}</p>
    </div>
  )
}

function ErrorBlock({ text, onRetry }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-10 text-center">
      <AlertTriangle className="w-7 h-7 text-red-400" />
      <p className="text-sm text-red-400 max-w-sm">{text}</p>
      {onRetry && (
        <button onClick={onRetry} className="btn-ghost text-xs">
          <RefreshCw className="w-3.5 h-3.5" /> Retry
        </button>
      )}
    </div>
  )
}

function GateScreen({ kind }) {
  const signin = kind === 'signin'
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-14 text-center px-6">
      <div className="w-12 h-12 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center">
        <Lock className="w-6 h-6 text-orange-400" />
      </div>
      <p className="text-sm font-semibold text-slate-200">
        {signin ? 'Sign in to deploy' : 'Read-only role'}
      </p>
      <p className="text-xs text-slate-500 max-w-sm leading-relaxed">
        {signin
          ? 'Your session has expired or you are not signed in. Use the account menu in the top-right of the navbar to sign in, then reopen this wizard.'
          : 'Your account has the viewer role, which can browse the lab but cannot push knowledge objects to a console. Ask an admin to upgrade your role to user or admin.'}
      </p>
    </div>
  )
}

// ── Step 1: Configure ────────────────────────────────────────────────────────

function ConnectedBanner({ config, onSelectDatasets, onRevalidate, onEdit, onDisconnect, disconnecting }) {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-green-500/25 bg-green-500/5 p-4 flex items-start gap-3">
        <CheckCircle2 className="w-5 h-5 text-green-400 shrink-0 mt-0.5" />
        <div className="min-w-0">
          <p className="text-sm font-semibold text-slate-100">
            Connected to <span className="font-mono text-green-300">{hostOf(config.console_url) || config.console_url}</span>
          </p>
          <p className="text-xs text-slate-500 font-mono mt-0.5 truncate">{config.console_url}</p>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2 text-xs text-slate-400">
            <span className="flex items-center gap-1.5">
              <KeyRound className="w-3 h-3" /> API token stored
            </span>
            {config.sdl_xdr_url && (
              <span className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3 h-3 text-green-400" />
                SDL region override: <span className="font-mono">{hostOf(config.sdl_xdr_url)}</span>
              </span>
            )}
            {config.updated_at && <span className="text-slate-600">Updated {formatTime(config.updated_at)}</span>}
          </div>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <button onClick={onSelectDatasets} className="btn-primary text-xs">
          <ServerCog className="w-3.5 h-3.5" /> Select datasets
        </button>
        <button onClick={onRevalidate} className="btn-ghost text-xs">
          <RefreshCw className="w-3.5 h-3.5" /> Re-validate
        </button>
        <button onClick={onEdit} className="btn-ghost text-xs">
          <Pencil className="w-3.5 h-3.5" /> Edit
        </button>
        <button
          onClick={onDisconnect}
          disabled={disconnecting}
          className="btn-ghost text-xs text-red-400 hover:text-red-300 hover:border-red-500/30 disabled:opacity-40 ml-auto"
        >
          <Unlink className="w-3.5 h-3.5" /> {disconnecting ? 'Disconnecting...' : 'Disconnect'}
        </button>
      </div>
    </div>
  )
}

function ConfigForm({
  isEdit, hasStoredToken,
  consoleUrl, setConsoleUrl,
  apiToken, setApiToken,
  sdlXdrUrl, setSdlXdrUrl,
  saveError, onSubmit,
}) {
  const [showAdvanced, setShowAdvanced] = useState(false)

  return (
    <form id="deploy-config-form" onSubmit={onSubmit} className="space-y-4">
      <div className="rounded-lg border border-[#2d1b4e] bg-white/[0.02] p-3 flex gap-2.5">
        <Info className="w-4 h-4 text-orange-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-400 leading-relaxed space-y-1.5">
          <p>
            In your SentinelOne console: <strong className="text-slate-300">Settings → Users → Service Users → Create New Service User</strong> (or
            pick an existing one) and give its role these permissions, scoped to your site:
          </p>
          <ul className="space-y-0.5 pl-0.5">
            <li><span className="text-slate-300 font-semibold">STAR Custom Rules</span> — deploy detections</li>
            <li><span className="text-slate-300 font-semibold">Hyperautomation</span> — import &amp; activate workflows</li>
            <li><span className="text-slate-300 font-semibold">SDL Dashboards</span> + <span className="text-slate-300 font-semibold">SDL Configuration Files</span> — deploy dashboards <span className="text-slate-500">(optional)</span></li>
          </ul>
          <p>
            Then copy its API token. <strong className="text-slate-300">One service-user token covers all three</strong> — it also does SDL config, so no
            separate SDL key is needed. The token is stored securely server-side and is never shown back to you or anyone else.
          </p>
        </div>
      </div>

      <div>
        <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">Console URL</label>
        <input
          type="url"
          required
          autoFocus
          value={consoleUrl}
          onChange={(e) => setConsoleUrl(e.target.value)}
          placeholder="https://usea1-yourcompany.sentinelone.net"
          className="w-full rounded-lg bg-[#12081f] border border-[#2d1b4e] px-3 py-2 text-sm text-slate-200 font-mono focus:outline-none focus:border-orange-500/50"
        />
      </div>

      <div>
        <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">API Token</label>
        <input
          type="password"
          required={!isEdit || !hasStoredToken}
          value={apiToken}
          onChange={(e) => setApiToken(e.target.value)}
          placeholder={isEdit && hasStoredToken ? '•••••••• (leave blank to keep current token)' : 'Paste your S1 API token'}
          className="w-full rounded-lg bg-[#12081f] border border-[#2d1b4e] px-3 py-2 text-sm text-slate-200 font-mono focus:outline-none focus:border-orange-500/50"
        />
      </div>

      <div className="collapsible-section">
        <button
          type="button"
          onClick={() => setShowAdvanced((v) => !v)}
          className="collapsible-header w-full text-left"
        >
          <span className="text-xs font-semibold text-slate-300">Advanced — SDL dashboard region (optional)</span>
          {showAdvanced ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
        </button>
        {showAdvanced && (
          <div className="collapsible-body space-y-3">
            <p className="text-xs text-slate-500 leading-relaxed">
              Dashboards deploy with the <span className="text-slate-400">same service-user token</span> — no separate key. We auto-detect your SDL
              region from the Console URL, so leave this blank unless auto-detection fails.
            </p>
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">SDL XDR URL <span className="text-slate-600 normal-case font-normal">— override</span></label>
              <input
                type="url"
                value={sdlXdrUrl}
                onChange={(e) => setSdlXdrUrl(e.target.value)}
                placeholder="auto-detected · e.g. https://xdr.us1.sentinelone.net"
                className="w-full rounded-lg bg-[#12081f] border border-[#2d1b4e] px-3 py-2 text-sm text-slate-200 font-mono focus:outline-none focus:border-orange-500/50"
              />
              <p className="text-[11px] text-slate-500 mt-1 leading-relaxed">
                Your SDL/XDR host — the address of your Singularity Data Lake console (e.g. <span className="font-mono">xdr.us1.sentinelone.net</span>),
                also listed under SentinelOne's “Endpoint URLs by Region.”
              </p>
            </div>
          </div>
        )}
      </div>

      {saveError && <p className="text-xs text-red-400">{saveError}</p>}
    </form>
  )
}

// ── Step 2: Validate ─────────────────────────────────────────────────────────

function ValidateStepView({ validating, validateError, validateResult }) {
  if (validating) return <LoadingBlock text="Validating connection..." />
  if (validateError) return <ErrorBlock text={validateError} />
  if (!validateResult) return <ErrorBlock text="No validation result yet." />

  const caps = validateResult.capabilities || {}
  const site = validateResult.site || {}

  return (
    <div className="space-y-4">
      {validateResult.ok ? (
        <div className="rounded-xl border border-green-500/25 bg-green-500/5 p-4 flex items-start gap-3">
          <CheckCircle2 className="w-5 h-5 text-green-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-semibold text-slate-100">Connection validated</p>
            <p className="text-xs text-slate-500 font-mono mt-0.5">{validateResult.console_url}</p>
          </div>
        </div>
      ) : (
        <div className="rounded-xl border border-red-500/25 bg-red-500/5 p-4 flex items-start gap-3">
          <XCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <p className="text-sm text-slate-200">Validation failed. Check the console URL and API token in Configure, then retry.</p>
        </div>
      )}

      <div className="rounded-xl border border-[#2d1b4e] overflow-hidden">
        <div className="px-4 py-2.5 bg-[#1a0a2e] border-b border-[#2d1b4e] flex items-center gap-2">
          <ServerCog className="w-3.5 h-3.5 text-orange-400" />
          <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Resolved site</span>
        </div>
        <div className="p-4 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div>
            <p className="text-slate-500 uppercase tracking-wider mb-0.5">Name</p>
            <p className="text-slate-200 font-mono truncate">{site.name || '—'}</p>
          </div>
          <div>
            <p className="text-slate-500 uppercase tracking-wider mb-0.5">Site ID</p>
            <p className="text-slate-200 font-mono truncate">{site.id || '—'}</p>
          </div>
          <div>
            <p className="text-slate-500 uppercase tracking-wider mb-0.5">Account ID</p>
            <p className="text-slate-200 font-mono truncate">{site.accountId || '—'}</p>
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-[#2d1b4e] overflow-hidden">
        <div className="px-4 py-2.5 bg-[#1a0a2e] border-b border-[#2d1b4e]">
          <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Capabilities</span>
        </div>
        <div className="divide-y divide-[#1e1235]">
          {CAPABILITY_ROWS.map((row) => {
            const ok = !!caps[row.key]
            return (
              <div key={row.key} className="flex items-center gap-2.5 px-4 py-2.5 text-sm">
                {ok ? <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" /> : <XCircle className="w-4 h-4 text-slate-600 shrink-0" />}
                <span className={ok ? 'text-slate-200' : 'text-slate-500'}>{row.label}</span>
              </div>
            )
          })}
        </div>
      </div>

      {Array.isArray(validateResult.messages) && validateResult.messages.length > 0 && (
        <div className="rounded-lg border border-[#2d1b4e] bg-white/[0.02] p-3 space-y-1.5">
          {validateResult.messages.map((m, i) => (
            <p key={i} className="text-xs text-slate-400 flex items-start gap-2">
              <Info className="w-3.5 h-3.5 text-slate-500 shrink-0 mt-0.5" /> {m}
            </p>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Step 3: Select ───────────────────────────────────────────────────────────

function DetectionChip({ item }) {
  return (
    <div className="flex items-center gap-2 shrink-0">
      <Badge type="severity" value={item.severity} />
      <span className="text-[11px] font-mono text-slate-600">{item.queryType}</span>
    </div>
  )
}

function HaChip({ item }) {
  return <span className="text-[11px] font-mono text-slate-500 shrink-0">{item.connections?.length || 0} connections</span>
}

function DashboardChip({ item }) {
  return <span className="text-[11px] font-mono text-slate-500 shrink-0">{item.tabs} tab{item.tabs === 1 ? '' : 's'}</span>
}

function ItemRow({ group, item, checked, disabled, onToggle }) {
  const id = idFor(group.type, item.key)
  const detail = group.type === 'detection' ? item.description : group.type === 'ha' ? item.detail : item.description
  return (
    <label
      htmlFor={id}
      className={`flex items-center gap-3 px-4 py-2.5 border-b border-[#1e1235] last:border-0 transition-colors ${
        disabled ? 'opacity-40 cursor-not-allowed' : 'hover:bg-white/[0.02] cursor-pointer'
      }`}
    >
      <input
        id={id}
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={() => onToggle(group, item)}
        className="accent-orange-500 disabled:opacity-40 shrink-0"
      />
      <div className="min-w-0 flex-1">
        <p className="text-sm text-slate-200 truncate">{item.name}</p>
        {detail && <p className="text-xs text-slate-500 truncate">{detail}</p>}
      </div>
      {group.type === 'detection' && <DetectionChip item={item} />}
      {group.type === 'ha' && <HaChip item={item} />}
      {group.type === 'dashboard' && <DashboardChip item={item} />}
    </label>
  )
}

function GroupSection({ group, capabilities, selected, onToggleItem, onToggleGroup }) {
  const Icon = GROUP_ICON[group.type]
  const enabled = !!capabilities?.[CAP_KEY[group.type]]
  const itemIds = group.items.map((it) => idFor(group.type, it.key))
  const selectedCount = itemIds.filter((id) => selected.has(id)).length
  const allSelected = itemIds.length > 0 && selectedCount === itemIds.length

  return (
    <div className={`rounded-xl border overflow-hidden ${enabled ? 'border-[#2d1b4e]' : 'border-[#2d1b4e]/50'}`}>
      <div className="px-4 py-3 bg-[#1a0a2e] border-b border-[#2d1b4e] flex items-center gap-3 flex-wrap">
        <Icon className={`w-4 h-4 shrink-0 ${enabled ? 'text-orange-400' : 'text-slate-600'}`} />
        <span className={`text-sm font-semibold ${enabled ? 'text-slate-200' : 'text-slate-500'}`}>{group.label}</span>
        <span className="text-xs font-mono text-slate-500">{selectedCount}/{itemIds.length} selected</span>
        <button
          type="button"
          onClick={() => onToggleGroup(group)}
          disabled={!enabled}
          className="btn-ghost text-xs px-2 py-1 ml-auto disabled:opacity-30"
        >
          {allSelected ? 'Deselect all' : 'Select all'}
        </button>
      </div>
      {!enabled && (
        <div className="px-4 py-2 bg-yellow-500/5 border-b border-yellow-500/10 flex items-start gap-2">
          <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 shrink-0 mt-0.5" />
          <p className="text-xs text-yellow-400/80">
            {group.type === 'dashboard'
              ? 'Set the SDL XDR URL in Configure (or grant your token SDL Dashboards + SDL Configuration Files) to enable dashboards.'
              : `This console did not report the "${CAP_KEY[group.type]}" capability as available.`}
          </p>
        </div>
      )}
      <div>
        {group.items.map((item) => (
          <ItemRow
            key={item.key}
            group={group}
            item={item}
            checked={selected.has(idFor(group.type, item.key))}
            disabled={!enabled}
            onToggle={onToggleItem}
          />
        ))}
      </div>
    </div>
  )
}

// ── Step 4: Deploy ───────────────────────────────────────────────────────────

function ResultRow({ result }) {
  const item = ITEM_BY_ID[idFor(result.type, result.key)]
  const status = result.status
  const icon = status === 'deployed'
    ? <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />
    : status === 'skipped'
      ? <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" />
      : <XCircle className="w-4 h-4 text-red-400 shrink-0" />
  const statusClass = status === 'deployed'
    ? 'bg-green-500/15 text-green-400 border border-green-500/30'
    : status === 'skipped'
      ? 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30'
      : 'bg-red-500/15 text-red-400 border border-red-500/30'

  return (
    <div className="flex items-start gap-3 px-4 py-2.5 border-b border-[#1e1235] last:border-0">
      {icon}
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm text-slate-200 truncate">{item?.name || result.key}</span>
          <span className={`inline-flex items-center rounded-full font-semibold px-2 py-0.5 text-[11px] shrink-0 ${statusClass}`}>
            {status}
          </span>
        </div>
        {result.id && <p className="text-xs font-mono text-slate-500 mt-0.5 truncate">id: {result.id}</p>}
        {result.message && <p className="text-xs text-slate-500 mt-0.5">{result.message}</p>}
      </div>
    </div>
  )
}

function DeployStepView({ deploying, deployPhase, deployError, deployResults }) {
  if (deploying) return <LoadingBlock text={deployPhase || 'Deploying...'} />
  if (deployError) return <ErrorBlock text={deployError} />
  if (!deployResults) return <ErrorBlock text="No deploy results yet." />

  const deployed = deployResults.filter((r) => r.status === 'deployed').length
  const skipped = deployResults.filter((r) => r.status === 'skipped').length
  const failed = deployResults.filter((r) => r.status !== 'deployed' && r.status !== 'skipped').length

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-[#2d1b4e] bg-white/[0.02] px-3 py-2.5 text-xs text-slate-400 flex items-center gap-2.5">
        <Info className="w-3.5 h-3.5 text-orange-400 shrink-0" />
        <span>{deployed} deployed · {skipped} skipped · {failed} failed</span>
      </div>
      <div className="rounded-xl border border-[#2d1b4e] overflow-hidden">
        {deployResults.map((r, i) => <ResultRow key={`${r.type}:${r.key}:${i}`} result={r} />)}
      </div>
      <p className="text-xs text-slate-500 leading-relaxed">
        Deployed detections are enabled (Active) immediately. Hyperautomation workflows are imported and
        activated (Active + visible in your console). Dashboards are written to your SDL config store.
      </p>
    </div>
  )
}

// ── Main component ──────────────────────────────────────────────────────────

export default function DeployKnowledgeObjects() {
  const [open, setOpen] = useState(false)
  const [gate, setGate] = useState('none') // none | signin | readonly

  const [step, setStep] = useState('configure')

  // Configure
  const [configLoading, setConfigLoading] = useState(true)
  const [configError, setConfigError] = useState('')
  const [config, setConfig] = useState(null)
  const [editing, setEditing] = useState(false)
  const [consoleUrlInput, setConsoleUrlInput] = useState('')
  const [apiTokenInput, setApiTokenInput] = useState('')
  const [sdlXdrUrlInput, setSdlXdrUrlInput] = useState('')
  const [saveError, setSaveError] = useState('')
  const [saving, setSaving] = useState(false)
  const [disconnecting, setDisconnecting] = useState(false)

  // Validate
  const [validating, setValidating] = useState(false)
  const [validateError, setValidateError] = useState('')
  const [validateResult, setValidateResult] = useState(null)

  // Select
  const [selected, setSelected] = useState(() => new Set())

  // Deploy
  const [deploying, setDeploying] = useState(false)
  const [deployPhase, setDeployPhase] = useState('')
  const [deployError, setDeployError] = useState('')
  const [deployResults, setDeployResults] = useState(null)

  useEffect(() => {
    if (!open) return
    const onKeyDown = (e) => { if (e.key === 'Escape') setOpen(false) }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [open])

  useEffect(() => {
    if (!open) return
    setGate('none')
    setStep('configure')
    setEditing(false)
    setConfig(null)
    setConfigError('')
    setApiTokenInput('')
    setSdlXdrUrlInput('')
    setSaveError('')
    setValidateResult(null)
    setValidateError('')
    setSelected(new Set())
    setDeployResults(null)
    setDeployError('')
    initGate()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  // Gate on the caller's ACTUAL role up front (not by inferring from a stray 403):
  // logged-out → sign in; viewer → read-only; admin AND user → proceed. Deploy is
  // NOT admin-only — any non-viewer can push to their own console.
  async function initGate() {
    setConfigLoading(true)
    try {
      const meRes = await fetch('/api/auth/me')
      if (meRes.status === 401) { setGate('signin'); setConfigLoading(false); return }
      const me = await meRes.json().catch(() => ({}))
      if (me?.role === 'viewer') { setGate('readonly'); setConfigLoading(false); return }
    } catch {
      // fall through — fetchConfig will surface any reachability error
    }
    fetchConfig()
  }

  async function fetchConfig() {
    setConfigLoading(true)
    setConfigError('')
    try {
      const res = await fetch('/api/deploy/config')
      if (res.status === 401) { setGate('signin'); return }
      if (res.status === 403) { setConfigError('Your role cannot configure deployment.'); return }
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setConfigError(data.error || data.detail || `Failed to load configuration (HTTP ${res.status})`)
        return
      }
      setConfig(data)
      setConsoleUrlInput(data.console_url || '')
      setSdlXdrUrlInput(data.sdl_xdr_url || '')
    } catch {
      setConfigError('Could not reach backend.')
    } finally {
      setConfigLoading(false)
    }
  }

  async function handleSaveConfig(e) {
    e.preventDefault()
    setSaveError('')
    const url = consoleUrlInput.trim()
    if (!url) { setSaveError('Console URL is required.'); return }
    const token = apiTokenInput.trim()
    const isEdit = !!config?.configured
    if (!token && !(isEdit && config.has_token)) {
      setSaveError('API token is required.')
      return
    }
    setSaving(true)
    try {
      const body = { console_url: url, api_token: token || (isEdit ? null : undefined) }
      // SDL XDR URL is an optional region override; empty string clears it.
      body.sdl_xdr_url = sdlXdrUrlInput.trim()
      const res = await fetch('/api/deploy/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (res.status === 401) { setGate('signin'); return }
      const rawText = await res.text()
      let data = {}
      try { data = JSON.parse(rawText) } catch { /* non-JSON body */ }
      if (!res.ok) {
        setSaveError(describeHttpError(res.status, data, rawText, 'Save'))
        return
      }
      setConfig(data)
      setEditing(false)
      setApiTokenInput('')
        goToValidate()
    } catch {
      setSaveError('Could not reach backend.')
    } finally {
      setSaving(false)
    }
  }

  async function handleDisconnect() {
    if (!window.confirm('Disconnect this SentinelOne console? You will need to re-enter the API token to deploy again.')) return
    setDisconnecting(true)
    try {
      const res = await fetch('/api/deploy/config', { method: 'DELETE' })
      if (res.status === 401) { setGate('signin'); return }
      setConfig({ configured: false })
      setConsoleUrlInput('')
      setValidateResult(null)
      setSelected(new Set())
      setStep('configure')
      setEditing(false)
    } catch {
      // best-effort — form will reflect real state on next load
    } finally {
      setDisconnecting(false)
    }
  }

  async function runValidate() {
    setValidating(true)
    setValidateError('')
    try {
      const res = await fetch('/api/deploy/validate', { method: 'POST' })
      if (res.status === 401) { setGate('signin'); return }
      const rawText = await res.text()
      let data = {}
      try { data = JSON.parse(rawText) } catch { /* non-JSON body */ }
      if (!res.ok) {
        setValidateError(describeHttpError(res.status, data, rawText, 'Validation'))
        return
      }
      setValidateResult(data)
    } catch {
      setValidateError('Could not reach backend.')
    } finally {
      setValidating(false)
    }
  }

  function goToValidate() {
    setStep('validate')
    runValidate()
  }

  // "Select datasets" from the connected banner: validate silently (needed to know
  // capabilities), then jump straight to Select on success — no separate step click.
  async function goToSelectDatasets() {
    setStep('validate')
    setValidating(true)
    setValidateError('')
    try {
      const res = await fetch('/api/deploy/validate', { method: 'POST' })
      if (res.status === 401) { setGate('signin'); return }
      const rawText = await res.text()
      let data = {}
      try { data = JSON.parse(rawText) } catch { /* non-JSON body */ }
      if (!res.ok) { setValidateError(describeHttpError(res.status, data, rawText, 'Validation')); return }
      setValidateResult(data)
      const caps = data?.capabilities || {}
      const next = new Set()
      for (const group of KNOWLEDGE_OBJECT_GROUPS) {
        if (!caps[CAP_KEY[group.type]]) continue
        for (const item of group.items) next.add(idFor(group.type, item.key))
      }
      setSelected(next)
      setStep('select')
    } catch {
      setValidateError('Could not reach backend.')
    } finally {
      setValidating(false)
    }
  }

  function goToSelect() {
    const caps = validateResult?.capabilities || {}
    const next = new Set()
    for (const group of KNOWLEDGE_OBJECT_GROUPS) {
      if (!caps[CAP_KEY[group.type]]) continue
      for (const item of group.items) next.add(idFor(group.type, item.key))
    }
    setSelected(next)
    setStep('select')
  }

  function handleToggleItem(group, item) {
    const id = idFor(group.type, item.key)
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function handleToggleGroup(group) {
    const itemIds = group.items.map((it) => idFor(group.type, it.key))
    setSelected((prev) => {
      const allSelected = itemIds.every((id) => prev.has(id))
      const next = new Set(prev)
      if (allSelected) itemIds.forEach((id) => next.delete(id))
      else itemIds.forEach((id) => next.add(id))
      return next
    })
  }

  // UTF-8-safe base64 of a JSON payload. We send artifacts base64-encoded so the
  // raw SQLi/XSS/traversal/injection signatures inside detection rules + workflows
  // don't trip the Cloudflare zone's WAF managed rules on the deploy POST.
  function b64Payload(obj) {
    const bytes = new TextEncoder().encode(JSON.stringify(obj))
    let bin = ''
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
    return btoa(bin)
  }

  async function buildDeployObjects() {
    const objects = []
    for (const group of KNOWLEDGE_OBJECT_GROUPS) {
      for (const item of group.items) {
        if (!selected.has(idFor(group.type, item.key))) continue
        let payload
        if (group.type === 'ha') payload = await loadHaWorkflowJson(item.key)
        else if (group.type === 'detection') payload = item.rule
        else if (group.type === 'dashboard') payload = item.dashboard
        else continue
        objects.push({ type: group.type, key: item.key, payload_b64: b64Payload(payload) })
      }
    }
    return objects
  }

  async function handleDeploy() {
    setStep('deploy')
    setDeploying(true)
    setDeployPhase('Preparing workflow definitions...')
    setDeployResults(null)
    setDeployError('')
    try {
      const objects = await buildDeployObjects()
      setDeployPhase(`Deploying ${objects.length} object${objects.length === 1 ? '' : 's'} to ${hostOf(validateResult?.console_url || config?.console_url) || 'your console'}...`)
      const res = await fetch('/api/deploy/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ objects }),
      })
      if (res.status === 401) { setGate('signin'); return }
      const rawText = await res.text()
      let data = {}
      try { data = JSON.parse(rawText) } catch { /* non-JSON body (edge / Access / proxy) */ }
      if (!res.ok) {
        setDeployError(describeHttpError(res.status, data, rawText, 'Deploy'))
        return
      }
      setDeployResults(data.results || [])
    } catch {
      setDeployError('Could not reach the backend — check your connection and try again.')
    } finally {
      setDeploying(false)
      setDeployPhase('')
    }
  }

  function requestClose() { setOpen(false) }

  const configured = !!config?.configured
  const showConfigForm = editing || !configured

  return (
    <>
      <div className="rounded-xl border border-orange-500/25 bg-gradient-to-r from-orange-500/10 via-orange-500/5 to-transparent p-5 flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-4 min-w-0">
          <div className="w-11 h-11 rounded-xl bg-orange-500/15 border border-orange-500/30 flex items-center justify-center shrink-0">
            <Rocket className="w-5 h-5 text-orange-400" />
          </div>
          <div className="min-w-0">
            <h2 className="text-sm font-bold text-slate-100">Add detections, workflows, and dashboards to console</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Deploy the lab's knowledge objects to your own SentinelOne site.
            </p>
          </div>
        </div>
        <button onClick={() => setOpen(true)} className="btn-primary shrink-0">
          <Rocket className="w-4 h-4" />
          Add to console
        </button>
      </div>

      {open && (
        <div className="modal-backdrop" onClick={requestClose}>
          <div
            className="modal-content"
            style={{ maxWidth: '720px' }}
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-labelledby="deploy-wizard-title"
          >
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#2d1b4e]">
              <h3 id="deploy-wizard-title" className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Rocket className="w-4 h-4 text-orange-400" /> Deploy knowledge objects
              </h3>
              <button
                onClick={requestClose}
                className="text-slate-500 hover:text-slate-300 transition-colors"
                aria-label="Close deploy wizard"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {gate === 'none' && <Stepper activeId={step} />}

            <div className="overflow-y-auto p-5 flex-1">
              {gate !== 'none' && <GateScreen kind={gate} />}

              {gate === 'none' && step === 'configure' && (
                configLoading ? <LoadingBlock text="Loading configuration..." /> :
                configError ? <ErrorBlock text={configError} onRetry={fetchConfig} /> :
                showConfigForm ? (
                  <ConfigForm
                    isEdit={configured}
                    hasStoredToken={!!config?.has_token}
                    consoleUrl={consoleUrlInput} setConsoleUrl={setConsoleUrlInput}
                    apiToken={apiTokenInput} setApiToken={setApiTokenInput}
                    sdlXdrUrl={sdlXdrUrlInput} setSdlXdrUrl={setSdlXdrUrlInput}
                    saveError={saveError}
                    onSubmit={handleSaveConfig}
                  />
                ) : (
                  <ConnectedBanner
                    config={config}
                    onSelectDatasets={goToSelectDatasets}
                    onRevalidate={goToValidate}
                    onEdit={() => setEditing(true)}
                    onDisconnect={handleDisconnect}
                    disconnecting={disconnecting}
                  />
                )
              )}

              {gate === 'none' && step === 'validate' && (
                <ValidateStepView validating={validating} validateError={validateError} validateResult={validateResult} />
              )}

              {gate === 'none' && step === 'select' && (
                <div className="space-y-4">
                  <div className="rounded-lg border border-[#2d1b4e] bg-white/[0.02] px-3 py-2.5 text-xs text-slate-400 flex items-start gap-2.5">
                    <Info className="w-3.5 h-3.5 text-orange-400 shrink-0 mt-0.5" />
                    <span>
                      Deployed detections are enabled (Active) immediately, and Hyperautomation workflows are
                      imported and activated (Active + visible in your console).
                    </span>
                  </div>
                  {KNOWLEDGE_OBJECT_GROUPS.map((group) => (
                    <GroupSection
                      key={group.type}
                      group={group}
                      capabilities={validateResult?.capabilities}
                      selected={selected}
                      onToggleItem={handleToggleItem}
                      onToggleGroup={handleToggleGroup}
                    />
                  ))}
                </div>
              )}

              {gate === 'none' && step === 'deploy' && (
                <DeployStepView
                  deploying={deploying}
                  deployPhase={deployPhase}
                  deployError={deployError}
                  deployResults={deployResults}
                />
              )}
            </div>

            <div className="px-5 py-3 border-t border-[#2d1b4e] flex items-center justify-between gap-3">
              {gate !== 'none' && (
                <button onClick={requestClose} className="btn-ghost text-xs ml-auto">Close</button>
              )}

              {gate === 'none' && step === 'configure' && showConfigForm && (
                <>
                  {configured && (
                    <button type="button" onClick={() => { setEditing(false); setSaveError('') }} className="btn-ghost text-xs">
                      Cancel
                    </button>
                  )}
                  <button
                    type="submit"
                    form="deploy-config-form"
                    disabled={saving}
                    className="btn-primary text-xs ml-auto disabled:opacity-40"
                  >
                    {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                    {saving ? 'Saving...' : 'Save & Continue'}
                  </button>
                </>
              )}

              {gate === 'none' && step === 'validate' && (
                <>
                  <button onClick={() => setStep('configure')} className="btn-ghost text-xs">Back</button>
                  <div className="flex items-center gap-2 ml-auto">
                    <button onClick={runValidate} disabled={validating} className="btn-ghost text-xs disabled:opacity-40">
                      <RefreshCw className={`w-3.5 h-3.5 ${validating ? 'animate-spin' : ''}`} /> Retry
                    </button>
                    <button
                      onClick={goToSelect}
                      disabled={!validateResult?.ok}
                      className="btn-primary text-xs disabled:opacity-40"
                    >
                      Continue to Select
                    </button>
                  </div>
                </>
              )}

              {gate === 'none' && step === 'select' && (
                <>
                  <button onClick={() => setStep('validate')} className="btn-ghost text-xs">Back</button>
                  <button
                    onClick={handleDeploy}
                    disabled={selected.size === 0}
                    className="btn-primary text-xs ml-auto disabled:opacity-40"
                  >
                    <Rocket className="w-3.5 h-3.5" /> Deploy {selected.size} object{selected.size === 1 ? '' : 's'}
                  </button>
                </>
              )}

              {gate === 'none' && step === 'deploy' && (
                deploying ? (
                  <span className="text-xs text-slate-500 flex items-center gap-2 ml-auto">
                    <Loader2 className="w-3.5 h-3.5 animate-spin" /> Deploying...
                  </span>
                ) : (
                  <>
                    <button onClick={() => { setStep('select'); setDeployResults(null); setDeployError('') }} className="btn-ghost text-xs">
                      Deploy more
                    </button>
                    <button onClick={requestClose} className="btn-primary text-xs ml-auto">Done</button>
                  </>
                )
              )}
            </div>
          </div>
        </div>
      )}
    </>
  )
}
