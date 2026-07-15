// Shared session/auth + run-target helpers.
//
// Plain inline `fetch()` calls, matching the rest of the codebase (no API
// client abstraction). Every network helper swallows errors and resolves to
// a safe empty value (null / []) so callers never need try/catch.

const RUN_TARGET_KEY = 'oneflare_run_target'

/** GET /api/auth/me → {email, role} | null (401 / any error → null). */
export async function getMe() {
  try {
    const res = await fetch('/api/auth/me')
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

/** GET /api/lab/identity → the caller's own registered tenant, or null. */
export async function getIdentity() {
  try {
    const res = await fetch('/api/lab/identity')
    if (!res.ok) return null
    const data = await res.json()
    return data?.identity ?? null
  } catch {
    return null
  }
}

/** GET /api/lab/tenants → array of registered tenants (admin-only; [] otherwise). */
export async function getTenants() {
  try {
    const res = await fetch('/api/lab/tenants')
    if (!res.ok) return []
    const data = await res.json()
    return Array.isArray(data?.tenants) ? data.tenants : []
  } catch {
    return []
  }
}

/** Persisted admin run-target selection. '' = one-flare default. */
export function getRunTarget() {
  try {
    return localStorage.getItem(RUN_TARGET_KEY) || ''
  } catch {
    return ''
  }
}

export function setRunTarget(value) {
  try {
    localStorage.setItem(RUN_TARGET_KEY, value || '')
  } catch {
    // localStorage unavailable — no-op
  }
}

/**
 * Effective run target for a given scope. Campaigns run one subdomain at a
 * time, so the scenario-only `__all__` fan-out sentinel collapses to '' (the
 * one-flare default) when read in campaign scope.
 */
export function effectiveRunTarget(scope = 'scenario') {
  const v = getRunTarget()
  if (scope === 'campaign' && v === '__all__') return ''
  return v
}

/**
 * The DNS scenario uses account-level Gateway (shared across tenants, not
 * per-subdomain) — it must only be visible to an admin on the default
 * (one-flare) console, never to a non-admin or on a partner instance.
 */
export function dnsAllowed({ adminEnabled, role }) {
  return !!adminEnabled && role === 'admin'
}
