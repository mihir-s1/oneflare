// OneFlare Logpush Relay — oneflare-logpush-relay
//
// Multi-tenant fan-out relay. Cloudflare Logpush has no per-record routing, so
// all ~30 lab users' http_requests + firewall_events records (filtered to
// `ClientRequestHost contains ".lab.soledrop.co"`) land on ONE SHARED Logpush
// job pointed at this Worker's /ingest route. This Worker demultiplexes each
// record by its `ClientRequestHost` against a KV registry and forwards ONLY
// that user's records to that user's own SentinelOne HEC ingest endpoint —
// write-time tenant isolation without needing one Logpush job per user.
//
// Routes:
//   POST   /ingest                        — Logpush HTTP destination target
//                                            (handles the ownership/validation
//                                            ping too — see handleIngest)
//   POST   /register                      — self-service enrollment, gated by
//                                            LAB_ENROLL_CODE
//   GET    /registered?subdomain=<host>   — self-check "am I still registered?"
//                                            (LAB_ENROLL_CODE) — used by an
//                                            instance to detect a teardown
//   GET    /admin/registry                — list all tenants (admin session or ADMIN_TOKEN)
//   GET    /admin/history                 — audit/history log (admin session or ADMIN_TOKEN)
//   POST   /admin/user/:subdomain/enable  — flip status -> active (admin role required)
//   POST   /admin/user/:subdomain/disable — flip status -> disabled (admin role required)
//   DELETE /admin/user/:subdomain         — teardown: delete registry row (admin role required)
//   GET    /health                        — liveness, no auth
//
// RBAC admin user-management — see RBAC.md for the full model:
//   POST   /auth/login                    — email+password -> session cookie
//   POST   /auth/logout                   — clear session
//   GET    /auth/me                       — current session {email, role}
//   POST   /auth/invite                   — admin: invite a new admin/viewer by email
//   POST   /auth/accept-invite            — set password from an invite token -> session
//   GET    /auth/users                    — admin: list admin users + pending invites
//   POST   /auth/users/:email/role        — admin: change a user's role
//   DELETE /auth/users/:email             — admin: remove a user
//   POST   /auth/bootstrap                — ADMIN_TOKEN break-glass: mint the first admin invite
//
// :subdomain accepts either the bare slug ("alice") or the full host
// ("alice.lab.soledrop.co") — see resolveHost().

const LAB_DOMAIN = "lab.soledrop.co";
const HISTORY_KEY = "__history__";
const MAX_HISTORY = 200;
const UNKNOWN_PREFIX = "__unknown__:";
// Exact decompressed content of the gzip test file Cloudflare POSTs to validate
// a generic HTTP Logpush destination. See handleIngest() for the doc citation.
const VALIDATION_PING = '{"content":"tests"}';

// ── RBAC admin user-management (see RBAC.md) ─────────────────────────────────
// Reserved KV key prefixes for the admin-console auth layer. All are skipped
// by listRegistryRows() (it ignores every "__"-prefixed key), so they never
// leak into /admin/registry.
const ADMIN_USER_PREFIX = "__admin_user__:";
const INVITE_PREFIX = "__invite__:";
const SESSION_PREFIX = "__session__:";
// owner_email -> host index, so "which tenant does this user own?" is an O(1)
// point get (strongly read-after-write) rather than a list() scan (which lags a
// fresh write by up to ~60s). Also __-prefixed → excluded from listRegistryRows.
const OWNER_PREFIX = "__owner__:";
const PBKDF2_ITERATIONS = 100000;
const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
const SESSION_COOKIE = "oneflare_admin_session";
const ADMIN_CONSOLE_ORIGIN = "https://one-flare.com";
// RBAC roles: admin = manage everyone + run against any subdomain; viewer =
// read-only admin views; user = self-service tenant (owns & runs only their own
// lab). See RBAC.md.
const ROLES = ["admin", "viewer", "user"];

// Onboarding side-effects on invite (both best-effort, feature-flagged on secrets):
//   RESEND_API_KEY   → email the invite link (from LAB_INVITE_FROM).
//   CF_ACCESS_TOKEN  → append the invitee's email to the Cloudflare Access policy
//                      so they can reach one-flare.com (skips domain-covered ones).
// The Access app/policy the console lives behind (non-secret ids).
const CF_API_BASE = "https://api.cloudflare.com/client/v4";
const CF_ACCOUNT_ID = "b8e637d5097fff0c694c3290ba81563e";
const ACCESS_APP_ID = "0f47bf98-a5a6-4c4a-87a1-395bb9362ef8";
const ACCESS_POLICY_ID = "924daf05-16bc-43fb-9f51-aca3e271f699";

// ── Small helpers ─────────────────────────────────────────────────────────────

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// Lowercase, replace runs of non [a-z0-9] with "-", collapse dashes, trim ends.
function slugify(name) {
  return String(name || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^-+|-+$/g, "");
}

// Accept either a bare slug ("alice") or a full host ("alice.lab.soledrop.co")
// in admin path params and normalize to the full registry key.
function resolveHost(param) {
  const decoded = decodeURIComponent(param || "");
  return decoded.includes(".") ? decoded : `${decoded}.${LAB_DOMAIN}`;
}

// Constant-time-ish string compare — mitigates trivial timing side-channels
// when checking the enroll code / admin token. Good enough for a lab; not a
// substitute for a real secret-comparison primitive in a production system.
function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length === 0 || b.length === 0) {
    return false;
  }
  const enc = new TextEncoder();
  const aBytes = enc.encode(a);
  const bBytes = enc.encode(b);
  if (aBytes.length !== bBytes.length) return false;
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) diff |= aBytes[i] ^ bBytes[i];
  return diff === 0;
}

function checkAdminToken(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const xAdmin = request.headers.get("X-Admin-Token") || "";
  const supplied = bearer || xAdmin;
  return !!env.ADMIN_TOKEN && timingSafeEqual(supplied, env.ADMIN_TOKEN);
}

function checkEnrollCode(request, body, env) {
  const header = request.headers.get("X-Enroll-Code") || "";
  const fromBody = (body && body.enroll_code) || "";
  const supplied = header || fromBody;
  return !!env.LAB_ENROLL_CODE && timingSafeEqual(supplied, env.LAB_ENROLL_CODE);
}

// ── Password hashing (PBKDF2-HMAC-SHA256 via Web Crypto) ─────────────────────
// Random 16-byte salt, >=100000 iterations, base64-encoded salt+hash stored on
// the __admin_user__ row alongside the iteration count actually used (so a
// future bump to PBKDF2_ITERATIONS doesn't break verification of existing
// users — each row is self-describing).

function bytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// crypto.getRandomValues-backed random token, base64url (no padding) — used
// for both invite tokens and session ids. >=32 bytes per spec.
function randomToken(byteLen = 32) {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function pbkdf2Base64(password, saltBytes, iterations) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return bytesToBase64(new Uint8Array(bits));
}

async function createPasswordHash(password) {
  const saltBytes = new Uint8Array(16);
  crypto.getRandomValues(saltBytes);
  const hash = await pbkdf2Base64(password, saltBytes, PBKDF2_ITERATIONS);
  return {
    pass_salt: bytesToBase64(saltBytes),
    pass_hash: hash,
    iterations: PBKDF2_ITERATIONS,
  };
}

// Constant-time compare (via timingSafeEqual) against the stored hash — never
// short-circuits on a byte-by-byte match.
async function verifyPassword(password, userRow) {
  if (!userRow || !userRow.pass_salt || !userRow.pass_hash || !userRow.iterations) return false;
  const saltBytes = base64ToBytes(userRow.pass_salt);
  const computed = await pbkdf2Base64(password, saltBytes, userRow.iterations);
  return timingSafeEqual(computed, userRow.pass_hash);
}

// ── Session cookie helpers ────────────────────────────────────────────────────

function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const out = {};
  for (const pair of header.split(";")) {
    const idx = pair.indexOf("=");
    if (idx === -1) continue;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

function sessionSetCookie(sid, maxAgeSeconds) {
  return `${SESSION_COOKIE}=${sid}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}`;
}

function sessionClearCookie() {
  return `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

function withSessionCookie(response, sid) {
  response.headers.append("Set-Cookie", sessionSetCookie(sid, Math.floor(SESSION_TTL_MS / 1000)));
  return response;
}

function withClearedSessionCookie(response) {
  response.headers.append("Set-Cookie", sessionClearCookie());
  return response;
}

// Never expose a full S1 HEC token — show only the last 4 characters.
function redactToken(token) {
  if (!token) return null;
  const s = String(token);
  return s.length <= 4 ? "*".repeat(s.length) : "*".repeat(s.length - 4) + s.slice(-4);
}

// ── KV: audit/history log (rolling, capped) ───────────────────────────────────

async function appendHistory(env, entry) {
  const row = { ts: new Date().toISOString(), ...entry };
  try {
    const raw = await env.REGISTRY.get(HISTORY_KEY);
    const list = raw ? JSON.parse(raw) : [];
    list.push(row);
    // Lab-scale audit trail, not a durable log store — plain KV read-modify-
    // write with no locking. Fine at ~30 users' event rate; not safe under
    // heavy concurrent writers (last write wins).
    while (list.length > MAX_HISTORY) list.shift();
    await env.REGISTRY.put(HISTORY_KEY, JSON.stringify(list));
  } catch (err) {
    // History bookkeeping must never break the primary request path.
    console.error("appendHistory failed:", err && err.message);
  }
}

async function getHistory(env) {
  const raw = await env.REGISTRY.get(HISTORY_KEY);
  return raw ? JSON.parse(raw) : [];
}

// ── KV: unknown-host drop counters ────────────────────────────────────────────

async function bumpUnknownHost(env, host, incrementBy) {
  const key = UNKNOWN_PREFIX + host;
  try {
    const raw = await env.REGISTRY.get(key);
    const row = raw ? JSON.parse(raw) : { host, count: 0, first_seen: new Date().toISOString() };
    row.count += incrementBy;
    row.last_seen = new Date().toISOString();
    await env.REGISTRY.put(key, JSON.stringify(row));
  } catch (err) {
    console.error("bumpUnknownHost failed:", err && err.message);
  }
}

// ── KV: registry listing (skips reserved "__"-prefixed bookkeeping keys) ─────

async function listRegistryRows(env) {
  const out = [];
  let cursor;
  do {
    const page = await env.REGISTRY.list(cursor ? { cursor } : {});
    for (const k of page.keys) {
      if (k.name.startsWith("__")) continue; // reserved: history / unknown-host counters
      const raw = await env.REGISTRY.get(k.name);
      if (!raw) continue;
      try {
        out.push(JSON.parse(raw));
      } catch {
        // skip corrupt row rather than fail the whole listing
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return out;
}

// ── KV: admin users / invites / sessions (RBAC — see RBAC.md) ────────────────

async function listByPrefix(env, prefix) {
  const out = [];
  let cursor;
  do {
    const page = await env.REGISTRY.list(cursor ? { prefix, cursor } : { prefix });
    for (const k of page.keys) {
      const raw = await env.REGISTRY.get(k.name);
      if (!raw) continue;
      try {
        out.push({ key: k.name, row: JSON.parse(raw) });
      } catch {
        // skip corrupt row
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return out;
}

function normEmail(email) {
  return String(email || "").trim().toLowerCase();
}

async function getAdminUser(env, email) {
  const raw = await env.REGISTRY.get(ADMIN_USER_PREFIX + normEmail(email));
  return raw ? JSON.parse(raw) : null;
}

async function putAdminUser(env, row) {
  await env.REGISTRY.put(ADMIN_USER_PREFIX + normEmail(row.email), JSON.stringify(row));
}

async function deleteAdminUser(env, email) {
  await env.REGISTRY.delete(ADMIN_USER_PREFIX + normEmail(email));
}

async function listAdminUsers(env) {
  const rows = await listByPrefix(env, ADMIN_USER_PREFIX);
  return rows.map((r) => r.row);
}

async function countAdmins(env) {
  const users = await listAdminUsers(env);
  return users.filter((u) => u.role === "admin").length;
}

async function createInvite(env, email, role, invitedBy) {
  const token = randomToken(32);
  const now = Date.now();
  const row = {
    email: normEmail(email),
    role,
    created_at: new Date(now).toISOString(),
    expires_at: new Date(now + INVITE_TTL_MS).toISOString(),
    invited_by: invitedBy || null,
  };
  await env.REGISTRY.put(INVITE_PREFIX + token, JSON.stringify(row));
  return { token, row };
}

async function getInvite(env, token) {
  const raw = await env.REGISTRY.get(INVITE_PREFIX + token);
  return raw ? JSON.parse(raw) : null;
}

async function deleteInvite(env, token) {
  await env.REGISTRY.delete(INVITE_PREFIX + token);
}

async function listInvites(env) {
  const rows = await listByPrefix(env, INVITE_PREFIX);
  return rows.map(({ key, row }) => ({ ...row, token: key.slice(INVITE_PREFIX.length) }));
}

function isExpired(isoString) {
  const t = new Date(isoString).getTime();
  return !Number.isFinite(t) || t < Date.now();
}

async function createSession(env, email, role) {
  const sid = randomToken(32);
  const row = {
    email: normEmail(email),
    role,
    expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
  };
  await env.REGISTRY.put(SESSION_PREFIX + sid, JSON.stringify(row));
  return { sid, row };
}

async function deleteSession(env, sid) {
  if (sid) await env.REGISTRY.delete(SESSION_PREFIX + sid);
}

// Reads + validates the session cookie on `request`. Returns { sid, email,
// role } or null (missing/invalid/expired — an expired session is deleted).
async function currentSession(request, env) {
  const sid = parseCookies(request)[SESSION_COOKIE];
  if (!sid) return null;
  const raw = await env.REGISTRY.get(SESSION_PREFIX + sid);
  if (!raw) return null;
  let row;
  try {
    row = JSON.parse(raw);
  } catch {
    return null;
  }
  if (isExpired(row.expires_at)) {
    await deleteSession(env, sid);
    return null;
  }
  return { sid, email: row.email, role: row.role };
}

// Combined gate for /admin/* and /auth/* admin routes: a valid admin-console
// session (any role) OR the break-glass ADMIN_TOKEN (treated as role "admin",
// no email — used for scripted/CI access and the very first bootstrap call).
async function resolveAuth(request, env) {
  const session = await currentSession(request, env);
  if (session) return { email: session.email, role: session.role, viaToken: false };
  if (checkAdminToken(request, env)) return { email: null, role: "admin", viaToken: true };
  return null;
}

// Gate helper for handlers: returns { auth } on success or { error: Response }
// on failure. `allowViewer:true` lets a viewer-role session through (read-only
// routes); admin role (or the ADMIN_TOKEN break-glass) is always allowed.
async function requireAuthGate(request, env, { allowViewer = false } = {}) {
  const auth = await resolveAuth(request, env);
  if (!auth) return { error: json({ error: "unauthorized" }, 401) };
  if (auth.role !== "admin" && !(allowViewer && auth.role === "viewer")) {
    return { error: json({ error: "forbidden — admin role required" }, 403) };
  }
  return { auth };
}

// ── gzip decompression (Logpush always gzip-compresses the POST body) ────────

async function decompressGzipToText(request) {
  const clone = request.clone();
  try {
    const decompressed = request.body.pipeThrough(new DecompressionStream("gzip"));
    return await new Response(decompressed).text();
  } catch (err) {
    // Fallback for non-gzip manual test requests during setup verification.
    // Real Logpush traffic (both the validation ping and log batches) is
    // always gzip-compressed.
    return await clone.text();
  }
}

// ── POST /ingest — Logpush HTTP destination ───────────────────────────────────

async function handleIngest(request, env, ctx) {
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);

  const bodyText = await decompressGzipToText(request);
  const trimmed = bodyText.trim();

  // ── Logpush HTTP destination ownership/validation challenge ────────────────
  // Per developers.cloudflare.com/logs/get-started/enable-destinations/http/:
  // "The `ownership_challenge` parameter is not required to create a Logpush
  // job to an HTTP endpoint" (that manual /logpush/ownership round-trip is
  // only for S3/GCS/Azure-style bucket destinations). Instead, when the HTTP
  // destination is validated, Cloudflare POSTs a gzip-compressed `test.txt.gz`
  // whose decompressed content is the literal JSON string `{"content":"tests"}`
  // — the docs state the endpoint "needs to make sure that the file upload to
  // validate the destination accepts" this, "otherwise it will return an
  // error, like `error validating destination: error writing object: error
  // uploading`". Real log batches are always NDJSON (never a bare
  // `{"content":"tests"}` object), so we detect the ping by exact content
  // match and short-circuit with a 200 OK to satisfy validation.
  if (trimmed === VALIDATION_PING) {
    return new Response(trimmed, { status: 200, headers: { "Content-Type": "application/json" } });
  }

  const lines = trimmed.length ? trimmed.split("\n") : [];
  const byHost = new Map(); // original host -> array of JSON-stringified records
  const rewriteHost = String(env.REWRITE_HOST || "").toLowerCase() === "true";

  // Group records by host WITHOUT touching KV — one Logpush batch can carry
  // thousands of records, so registry lookups must not happen per-record on the
  // response path. Resolution is deduped to one KV read per distinct host in
  // finishIngest() below.
  for (const line of lines) {
    if (!line.trim()) continue;

    let record;
    try {
      record = JSON.parse(line);
    } catch {
      continue; // skip an unparseable line rather than fail the whole batch
    }

    // The request Host field differs by dataset: http_requests carries it in
    // `ClientRequestHost`, firewall_events in `ClientRequestHTTPHost`. Support
    // both so routing works across datasets. Grouping/registry lookup always
    // keys on the ORIGINAL host.
    const hostField = record.ClientRequestHost != null
      ? "ClientRequestHost"
      : record.ClientRequestHTTPHost != null
        ? "ClientRequestHTTPHost"
        : null;
    if (!hostField) continue;
    const host = record[hostField];
    if (!host) continue;

    // Optional: make the forwarded record look like it came from the canonical
    // shop.soledrop.co host instead of the per-user lab subdomain. Applied to
    // the record body only (the field that carried the host); the grouping key
    // stays the original host.
    if (rewriteHost) record[hostField] = "shop.soledrop.co";

    if (!byHost.has(host)) byHost.set(host, []);
    byHost.get(host).push(JSON.stringify(record));
  }

  // Ack Logpush immediately; resolve tenants (one KV read per DISTINCT host,
  // not per record) and forward in the background so /ingest returns fast and
  // does zero KV work on the critical path.
  ctx.waitUntil(finishIngest(env, byHost));

  return new Response("OK", { status: 200 });
}

async function finishIngest(env, byHost) {
  const unknownHosts = new Map(); // host -> record count dropped this batch

  for (const [host, records] of byHost) {
    const regRaw = await env.REGISTRY.get(host); // one read per distinct host
    if (!regRaw) {
      unknownHosts.set(host, records.length);
      continue;
    }
    let row;
    try {
      row = JSON.parse(regRaw);
    } catch {
      unknownHosts.set(host, records.length);
      continue;
    }
    if (row.status !== "active") continue; // disabled tenant — drop silently
    await forwardToTenant(env, host, row, records);
  }

  for (const [host, count] of unknownHosts) {
    await bumpUnknownHost(env, host, count);
  }
  if (unknownHosts.size > 0) {
    await appendHistory(env, {
      type: "dropped_unknown_host",
      hosts: Object.fromEntries(unknownHosts),
    });
  }
}

// `row` is the already-resolved registry row for `host` (read once in
// finishIngest) — no redundant KV read here.
async function forwardToTenant(env, host, row, records) {
  if (!row.s1_hec_url || !row.s1_hec_token) {
    await appendHistory(env, { type: "forward_error", subdomain: host, error: "missing s1_hec_url/token" });
    return;
  }

  const body = records.join("\n") + "\n";

  // The S1 marketplace HEC raw collector (/services/collector/raw) is
  // Splunk-HEC-compatible and authenticates with `Authorization: Splunk <token>`.
  // (Verified live: raw and Bearer both return 401 "Invalid authorization
  // header, code 3"; Splunk succeeds.) The user supplies the raw token at
  // /register (the full raw-collector URL incl. ?sourcetype=... goes in
  // s1_hec_url). If they paste a value that already carries a scheme (has a
  // space, e.g. "Splunk x" / "Bearer x"), pass it through unchanged.
  const authHeader = /\s/.test(row.s1_hec_token)
    ? row.s1_hec_token
    : `Splunk ${row.s1_hec_token}`;

  try {
    const resp = await fetch(row.s1_hec_url, {
      method: "POST",
      headers: {
        "Authorization": authHeader,
        "Content-Type": "application/json",
      },
      body,
    });

    if (!resp.ok) {
      const errText = await resp.text().catch(() => "");
      await appendHistory(env, {
        type: "forward_error",
        subdomain: host,
        status: resp.status,
        error: errText.slice(0, 200),
      });
      return;
    }

    // Persist counters, but re-read first so a teardown/disable that landed
    // during this in-flight batch wins — never resurrect a deleted row.
    const currentRaw = await env.REGISTRY.get(host);
    if (!currentRaw) return; // torn down mid-batch — drop the counter update
    let current;
    try {
      current = JSON.parse(currentRaw);
    } catch {
      return;
    }
    current.forwarded = (current.forwarded || 0) + records.length;
    current.last_seen = new Date().toISOString();
    await env.REGISTRY.put(host, JSON.stringify(current));
  } catch (err) {
    // Network/DNS/etc failure reaching the tenant's S1 HEC endpoint. Record
    // and move on — a failed destination must never crash the batch or take
    // down forwarding for other tenants.
    await appendHistory(env, {
      type: "forward_error",
      subdomain: host,
      error: String((err && err.message) || err).slice(0, 200),
    });
  }
}

// ── Tenant upsert (shared by /register and /auth/lab/register) ───────────────
//
// Validates the registration body and builds/updates the tenant row.
// `ownerEmail`: a string stamps the row's owner_email; `undefined` leaves any
// existing owner untouched (and defaults to null on create) — this lets the
// anonymous enroll-code path coexist with the session-gated owned path.
// Returns { error: Response } on invalid input, else { host, row, existed }.
async function buildTenantUpsert(env, body, ownerEmail) {
  const { name, s1_hec_url, s1_hec_token, site_label, account_label, s1_console_url } = body || {};
  // site_label (the S1 site) and account_label (the S1 account) are REQUIRED so
  // the admin console can always name the real destination behind the opaque HEC
  // token — the token itself carries no account/site identity. s1_console_url
  // (the console/"purple" domain) is optional display metadata.
  const label = String(site_label || "").trim().slice(0, 200);
  const account = String(account_label || "").trim().slice(0, 200);
  const consoleUrl = String(s1_console_url || "").trim().slice(0, 300) || null;
  if (!name || !s1_hec_url || !s1_hec_token || !label || !account) {
    return { error: json({
      error: "name, s1_hec_url, s1_hec_token, site_label, and account_label are all required",
    }, 400) };
  }

  const slug = slugify(name);
  if (!slug) {
    return { error: json({ error: "name did not produce a valid subdomain slug" }, 400) };
  }

  const host = `${slug}.${LAB_DOMAIN}`;
  const now = new Date().toISOString();

  const existingRaw = await env.REGISTRY.get(host);
  let row;
  if (existingRaw) {
    // Idempotent re-register: update the S1 destination + labels, preserve
    // counters and history rather than erroring.
    row = JSON.parse(existingRaw);
    row.name = name;
    row.s1_hec_url = s1_hec_url;
    row.s1_hec_token = s1_hec_token;
    row.site_label = label;
    row.account_label = account;
    row.s1_console_url = consoleUrl;
    if (ownerEmail !== undefined) row.owner_email = ownerEmail;
  } else {
    row = {
      name,
      subdomain: host,
      s1_hec_url,
      s1_hec_token,
      site_label: label,
      account_label: account,
      s1_console_url: consoleUrl,
      owner_email: ownerEmail === undefined ? null : ownerEmail,
      status: "active",
      created_at: now,
      forwarded: 0,
      last_seen: null,
    };
  }
  return { host, row, existed: !!existingRaw };
}

// The tenant row owned by `email`, or null — via the owner→host index (point
// get, so it reflects a just-written registration immediately). Self-heals a
// stale index whose host row was torn down.
async function findTenantByOwner(env, email) {
  const key = OWNER_PREFIX + normEmail(email);
  const host = await env.REGISTRY.get(key);
  if (!host) return null;
  const raw = await env.REGISTRY.get(host);
  if (!raw) {
    await env.REGISTRY.delete(key);
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// ── POST /register — anonymous, enroll-code-gated (partner/local instances) ──

async function handleRegister(request, env) {
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }

  if (!checkEnrollCode(request, body, env)) {
    return json({ error: "invalid or missing enroll code" }, 403);
  }

  // undefined owner → don't disturb an owner set via the session path.
  const built = await buildTenantUpsert(env, body, undefined);
  if (built.error) return built.error;
  const { host, row, existed } = built;

  await env.REGISTRY.put(host, JSON.stringify(row));
  await appendHistory(env, { type: existed ? "re-register" : "register", subdomain: host, name: row.name });

  return json({ ok: true, subdomain: host, shop_url: `https://${host}` });
}

// ── GET /registered — self-check, gated by LAB_ENROLL_CODE ───────────────────
// Partner instances hold the enroll code, not the admin token. This lets an
// instance ask "am I still in the registry?" so it can detect a teardown done
// from the admin console and reset itself locally.

async function handleRegistered(request, env) {
  const url = new URL(request.url);
  const subdomain = url.searchParams.get("subdomain") || "";
  if (!checkEnrollCode(request, null, env)) {
    return json({ error: "invalid or missing enroll code" }, 403);
  }
  if (!subdomain) return json({ error: "subdomain query param is required" }, 400);

  const host = resolveHost(subdomain);
  const raw = await env.REGISTRY.get(host);
  if (!raw) return json({ exists: false, status: null });

  let row;
  try {
    row = JSON.parse(raw);
  } catch {
    return json({ exists: false, status: null });
  }
  return json({ exists: true, status: row.status || null });
}

// ── /admin/* — gated by an admin-console session (any role) OR ADMIN_TOKEN
// (break-glass). Mutating routes (enable/disable/delete) require role
// "admin" — a viewer-role session gets 403. ────────────────────────────────

async function handleAdminRegistry(request, env) {
  const gate = await requireAuthGate(request, env, { allowViewer: true });
  if (gate.error) return gate.error;
  const rows = await listRegistryRows(env);
  const redacted = rows.map((r) => ({ ...r, s1_hec_token: redactToken(r.s1_hec_token) }));
  return json({ ok: true, count: redacted.length, registry: redacted });
}

async function handleAdminHistory(request, env) {
  const gate = await requireAuthGate(request, env, { allowViewer: true });
  if (gate.error) return gate.error;
  const history = await getHistory(env);
  return json({ ok: true, count: history.length, history });
}

async function handleAdminUserStatus(request, env, rawSubdomain, enable) {
  const gate = await requireAuthGate(request, env);
  if (gate.error) return gate.error;
  const host = resolveHost(rawSubdomain);
  const raw = await env.REGISTRY.get(host);
  if (!raw) return json({ error: "not found", subdomain: host }, 404);

  const row = JSON.parse(raw);
  row.status = enable ? "active" : "disabled";
  await env.REGISTRY.put(host, JSON.stringify(row));
  await appendHistory(env, { type: enable ? "enable" : "disable", subdomain: host });

  return json({ ok: true, subdomain: host, status: row.status });
}

async function handleAdminDeleteUser(request, env, rawSubdomain) {
  const gate = await requireAuthGate(request, env);
  if (gate.error) return gate.error;
  const host = resolveHost(rawSubdomain);
  const raw = await env.REGISTRY.get(host);
  if (!raw) return json({ error: "not found", subdomain: host }, 404);

  // Teardown: delete the registry row. No live Cloudflare API calls are made
  // here — DNS/route/zone config for *.lab.soledrop.co is wildcard and shared,
  // so removing the row is sufficient to stop this tenant's traffic from being
  // forwarded (it will fall into the unknown-host bucket and be dropped).
  await env.REGISTRY.delete(host);
  // Clear the owner→host index too so the owner can cleanly re-register.
  try {
    const owner = JSON.parse(raw).owner_email;
    if (owner) await env.REGISTRY.delete(OWNER_PREFIX + normEmail(owner));
  } catch {}
  await appendHistory(env, { type: "teardown", subdomain: host });

  return json({ ok: true, subdomain: host, deleted: true });
}

// ── /auth/* — RBAC admin user-management (see RBAC.md) ───────────────────────

async function handleAuthLogin(request, env) {
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  const email = normEmail(body && body.email);
  const password = String((body && body.password) || "");
  if (!email || !password) return json({ error: "email and password are required" }, 400);

  const user = await getAdminUser(env, email);
  const ok = await verifyPassword(password, user);
  if (!ok) return json({ error: "invalid credentials" }, 401);

  user.last_login = new Date().toISOString();
  await putAdminUser(env, user);

  const { sid } = await createSession(env, user.email, user.role);
  return withSessionCookie(json({ ok: true, email: user.email, role: user.role }), sid);
}

async function handleAuthLogout(request, env) {
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
  const sid = parseCookies(request)[SESSION_COOKIE];
  if (sid) await deleteSession(env, sid);
  return withClearedSessionCookie(json({ ok: true }));
}

async function handleAuthMe(request, env) {
  const session = await currentSession(request, env);
  if (!session) return json({ error: "not authenticated" }, 401);
  return json({ email: session.email, role: session.role });
}

// ── Invite onboarding side-effects (best-effort) ────────────────────────────

function inviteEmailHtml(invite_url, role) {
  return (
    `<p>You've been invited to the <strong>OneFlare ThreatOps lab</strong> as <strong>${role}</strong>.</p>` +
    `<ol>` +
    `<li><a href="${invite_url}">Accept your invite</a> to set a password.</li>` +
    `<li>Sign in at <a href="${ADMIN_CONSOLE_ORIGIN}/admin">one-flare.com/admin</a>.</li>` +
    `<li>In <strong>Settings → Lab Identity</strong>, register your subdomain + SentinelOne HEC ` +
    `destination, then run scenarios — your telemetry flows only to your own SentinelOne site.</li>` +
    `</ol>` +
    `<p style="color:#888">This link expires in 7 days.</p>`
  );
}

// Send one invite email via Resend (no-op without RESEND_API_KEY). Returns true if sent.
async function sendInviteEmail(env, email, invite_url, role) {
  if (!env.RESEND_API_KEY) return false;
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: env.LAB_INVITE_FROM || "OneFlare Lab <onboarding@one-flare.com>",
        to: [email],
        subject: "You're invited to the OneFlare ThreatOps lab",
        html: inviteEmailHtml(invite_url, role),
      }),
    });
    if (!res.ok) console.error("Resend invite email non-2xx:", res.status, (await res.text()).slice(0, 200));
    return res.ok;
  } catch (err) {
    console.error("Resend invite email failed:", err && err.message);
    return false;
  }
}

// Append invited emails to the Access allow-list (no-op without CF_ACCESS_TOKEN).
// Skips addresses already covered by an allowed email_domain (e.g. @sentinelone.com)
// or already present. One batched PUT for all new emails.
async function addToAccessAllowlist(env, emails) {
  const token = env.CF_ACCESS_TOKEN;
  const list = [...new Set((emails || []).map(normEmail).filter(Boolean))];
  if (!token || !list.length) return;
  const url = `${CF_API_BASE}/accounts/${CF_ACCOUNT_ID}/access/apps/${ACCESS_APP_ID}/policies/${ACCESS_POLICY_ID}`;
  try {
    const getRes = await fetch(url, { headers: { "Authorization": `Bearer ${token}` } });
    const pol = (await getRes.json()).result;
    if (!pol) return;
    const include = pol.include || [];
    const allowedDomains = new Set(
      include.filter((i) => i.email_domain).map((i) => String(i.email_domain.domain).toLowerCase())
    );
    const existing = new Set(
      include.filter((i) => i.email).map((i) => normEmail(i.email.email))
    );
    let changed = false;
    for (const email of list) {
      const domain = email.split("@")[1] || "";
      if (allowedDomains.has(domain) || existing.has(email)) continue;
      include.push({ email: { email } });
      existing.add(email);
      changed = true;
    }
    if (!changed) return;
    const putRes = await fetch(url, {
      method: "PUT",
      headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        name: pol.name, decision: pol.decision, include,
        exclude: pol.exclude || [], require: pol.require || [],
      }),
    });
    if (!putRes.ok) console.error("Access allowlist PUT non-2xx:", putRes.status, (await putRes.text()).slice(0, 200));
  } catch (err) {
    console.error("Access allowlist update failed:", err && err.message);
  }
}

// Fire both onboarding side-effects for a batch of freshly-created invites.
// entries: [{ email, invite_url, role }]. Returns the number of emails sent.
async function onboardInvites(env, entries) {
  if (!entries || !entries.length) return 0;
  await addToAccessAllowlist(env, entries.map((e) => e.email));
  const sent = await Promise.all(
    entries.map((e) => sendInviteEmail(env, e.email, e.invite_url, e.role))
  );
  return sent.filter(Boolean).length;
}

async function handleAuthInvite(request, env) {
  const gate = await requireAuthGate(request, env);
  if (gate.error) return gate.error;
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  const email = normEmail(body && body.email);
  const role = body && ROLES.includes(body.role) ? body.role : null;
  if (!email || !role) return json({ error: "email and role ('admin'|'viewer'|'user') are required" }, 400);

  if (await getAdminUser(env, email)) return json({ error: "user already exists" }, 409);

  const { token, row } = await createInvite(env, email, role, gate.auth.email);
  await appendHistory(env, { type: "invite_created", email, role, invited_by: gate.auth.email || "admin_token" });

  const invite_url = `${ADMIN_CONSOLE_ORIGIN}/admin/accept-invite?token=${token}`;

  // Best-effort onboarding — an email/allowlist failure must never fail the
  // invite; invite_url is always returned so the operator can share it manually.
  const sent = await onboardInvites(env, [{ email, invite_url, role }]);

  return json({ ok: true, invite_url, email, role, expires_at: row.expires_at, email_sent: sent > 0 });
}

// Bulk invite: a delimited list (or array) of emails → N invites in one shot.
// Skips emails that already have an account. Returns per-email {status, invite_url}.
async function handleAuthInviteBulk(request, env) {
  const gate = await requireAuthGate(request, env);
  if (gate.error) return gate.error;
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  const role = body && ROLES.includes(body.role) ? body.role : "user";
  const rawEmails = Array.isArray(body && body.emails)
    ? body.emails
    : String((body && body.emails) || "").split(/[\s,;]+/);
  const emails = [...new Set(rawEmails.map(normEmail).filter(Boolean))];
  if (!emails.length) return json({ error: "no valid emails provided" }, 400);

  // Pre-load pending invites once so a re-run doesn't mint duplicate tokens for
  // people already invited-but-not-yet-accepted; return their existing link.
  const pending = new Map();
  for (const inv of await listInvites(env)) {
    if (!isExpired(inv.expires_at)) pending.set(normEmail(inv.email), inv);
  }

  const results = [];
  for (const email of emails) {
    if (await getAdminUser(env, email)) {
      results.push({ email, status: "exists" });
      continue;
    }
    const existing = pending.get(email);
    if (existing) {
      results.push({
        email, status: "pending", role: existing.role,
        invite_url: `${ADMIN_CONSOLE_ORIGIN}/admin/accept-invite?token=${existing.token}`,
        expires_at: existing.expires_at,
      });
      continue;
    }
    const { token, row } = await createInvite(env, email, role, gate.auth.email);
    await appendHistory(env, { type: "invite_created", email, role, invited_by: gate.auth.email || "admin_token" });
    results.push({
      email, status: "invited", role,
      invite_url: `${ADMIN_CONSOLE_ORIGIN}/admin/accept-invite?token=${token}`,
      expires_at: row.expires_at,
    });
  }

  // Onboard everyone we have a link for — freshly invited AND already-pending
  // (re-running bulk should re-email + ensure allowlisting for pending invitees).
  const toOnboard = results.filter((r) => r.invite_url);
  const emailed = await onboardInvites(env, toOnboard);

  return json({ ok: true, count: results.length, emailed, results });
}

async function handleAuthAcceptInvite(request, env) {
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  const token = String((body && body.token) || "");
  const password = String((body && body.password) || "");
  if (!token) return json({ error: "token is required" }, 400);
  if (password.length < 10) return json({ error: "password must be at least 10 characters" }, 400);

  const invite = await getInvite(env, token);
  if (!invite) return json({ error: "invalid or expired invite" }, 400);
  if (isExpired(invite.expires_at)) {
    await deleteInvite(env, token);
    return json({ error: "invite has expired" }, 400);
  }
  if (await getAdminUser(env, invite.email)) {
    await deleteInvite(env, token);
    return json({ error: "user already exists" }, 409);
  }

  const { pass_salt, pass_hash, iterations } = await createPasswordHash(password);
  const now = new Date().toISOString();
  const user = { email: invite.email, role: invite.role, pass_salt, pass_hash, iterations, created_at: now, last_login: now };
  await putAdminUser(env, user);
  await deleteInvite(env, token);
  await appendHistory(env, { type: "admin_user_created", email: user.email, role: user.role });

  const { sid } = await createSession(env, user.email, user.role);
  return withSessionCookie(json({ ok: true, email: user.email, role: user.role }), sid);
}

async function handleAuthUsers(request, env) {
  const gate = await requireAuthGate(request, env, { allowViewer: true });
  if (gate.error) return gate.error;

  const users = await listAdminUsers(env);
  const invites = await listInvites(env);
  return json({
    ok: true,
    users: users
      .map((u) => ({ email: u.email, role: u.role, created_at: u.created_at, last_login: u.last_login || null }))
      .sort((a, b) => a.email.localeCompare(b.email)),
    invites: invites
      .filter((i) => !isExpired(i.expires_at))
      .map((i) => ({ email: i.email, role: i.role, expires_at: i.expires_at }))
      .sort((a, b) => a.email.localeCompare(b.email)),
  });
}

async function handleAuthUserRole(request, env, rawEmail) {
  const gate = await requireAuthGate(request, env);
  if (gate.error) return gate.error;
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  const role = body && ROLES.includes(body.role) ? body.role : null;
  if (!role) return json({ error: "role must be 'admin', 'viewer', or 'user'" }, 400);

  const email = normEmail(decodeURIComponent(rawEmail || ""));
  const user = await getAdminUser(env, email);
  if (!user) return json({ error: "not found" }, 404);

  if (user.role === "admin" && role !== "admin" && (await countAdmins(env)) <= 1) {
    return json({ error: "cannot demote the last admin" }, 400);
  }

  user.role = role;
  await putAdminUser(env, user);
  await appendHistory(env, { type: "admin_role_changed", email, role, changed_by: gate.auth.email || "admin_token" });
  return json({ ok: true, email, role });
}

async function handleAuthDeleteUser(request, env, rawEmail) {
  const gate = await requireAuthGate(request, env);
  if (gate.error) return gate.error;

  const email = normEmail(decodeURIComponent(rawEmail || ""));
  if (gate.auth.email && gate.auth.email === email) {
    return json({ error: "cannot remove yourself" }, 400);
  }

  const user = await getAdminUser(env, email);
  if (!user) return json({ error: "not found" }, 404);

  if (user.role === "admin" && (await countAdmins(env)) <= 1) {
    return json({ error: "cannot remove the last admin" }, 400);
  }

  await deleteAdminUser(env, email);
  await appendHistory(env, { type: "admin_user_removed", email, removed_by: gate.auth.email || "admin_token" });
  return json({ ok: true, email, deleted: true });
}

// Break-glass bootstrap: mints the FIRST admin invite (gated by ADMIN_TOKEN,
// not a session — there are no sessions possible yet). Refuses once any
// admin user exists; from then on invites happen in-app via /auth/invite.
async function handleAuthBootstrap(request, env) {
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
  if (!checkAdminToken(request, env)) return json({ error: "unauthorized" }, 401);

  const users = await listAdminUsers(env);
  if (users.length > 0) return json({ error: "admin users already exist — use /auth/invite" }, 409);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  const email = normEmail(body && body.email);
  if (!email) return json({ error: "email is required" }, 400);

  const { token, row } = await createInvite(env, email, "admin", "bootstrap");
  await appendHistory(env, { type: "bootstrap_invite_created", email });

  const invite_url = `${ADMIN_CONSOLE_ORIGIN}/admin/accept-invite?token=${token}`;
  const sent = await onboardInvites(env, [{ email, invite_url, role: "admin" }]);
  return json({ ok: true, invite_url, email, role: "admin", expires_at: row.expires_at, email_sent: sent > 0 });
}

// ── /auth/lab/* — session-gated, self-service tenant (the caller's OWN lab) ──
//
// Unlike /register (anonymous, enroll-code — used by partner/local instances),
// these tie a tenant to the logged-in user via owner_email resolved from the
// session. Any valid session may use them EXCEPT viewer (read-only). This is how
// the multi-user console links a user to their subdomain + S1 destination.

// Strip the opaque HEC token before returning a tenant to its owner (the relay
// is the system of record; the token is re-entered on change, never echoed).
function ownerIdentityView(row) {
  if (!row) return null;
  const { s1_hec_token, ...rest } = row;
  return rest;
}

async function handleAuthLabRegister(request, env) {
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
  const session = await currentSession(request, env);
  if (!session) return json({ error: "not authenticated" }, 401);
  if (session.role === "viewer") return json({ error: "viewers cannot register a lab" }, 403);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }

  const built = await buildTenantUpsert(env, body, session.email);
  if (built.error) return built.error;
  const { host, row, existed } = built;

  const ownerKey = OWNER_PREFIX + normEmail(session.email);
  // One subdomain per user: if the caller already owns a DIFFERENT host, this is
  // a rename — delete the old row so they don't accumulate orphaned subdomains.
  const prevHost = await env.REGISTRY.get(ownerKey);
  if (prevHost && prevHost !== host) {
    await env.REGISTRY.delete(prevHost);
    await appendHistory(env, { type: "lab_rename", from: prevHost, to: host, owner: session.email });
  }

  await env.REGISTRY.put(host, JSON.stringify(row));
  await env.REGISTRY.put(ownerKey, host);
  await appendHistory(env, {
    type: existed ? "re-register" : "register", subdomain: host, name: row.name, owner: session.email,
  });

  return json({ ok: true, subdomain: host, shop_url: `https://${host}`, identity: ownerIdentityView(row) });
}

async function handleAuthLabIdentity(request, env) {
  const session = await currentSession(request, env);
  if (!session) return json({ error: "not authenticated" }, 401);
  const row = await findTenantByOwner(env, session.email);
  return json({ ok: true, identity: ownerIdentityView(row), lab_domain: LAB_DOMAIN });
}

// Admin-only: all registered tenants (for the Scenarios-page subdomain selector).
async function handleAuthTenants(request, env) {
  const gate = await requireAuthGate(request, env);
  if (gate.error) return gate.error;
  const rows = await listRegistryRows(env);
  const tenants = rows
    .map((r) => ({
      subdomain: r.subdomain,
      name: r.name,
      owner_email: r.owner_email || null,
      site_label: r.site_label || null,
      account_label: r.account_label || null,
      status: r.status || null,
    }))
    .sort((a, b) => String(a.subdomain).localeCompare(String(b.subdomain)));
  return json({ ok: true, count: tenants.length, tenants });
}

// ── Router ─────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (path === "/health") return json({ status: "ok" });
    if (path === "/ingest") return handleIngest(request, env, ctx);
    if (path === "/register") return handleRegister(request, env);
    if (path === "/registered" && request.method === "GET") return handleRegistered(request, env);

    const userActionMatch = path.match(/^\/admin\/user\/([^/]+)\/(enable|disable)$/);
    if (userActionMatch && request.method === "POST") {
      const [, subdomain, action] = userActionMatch;
      return handleAdminUserStatus(request, env, subdomain, action === "enable");
    }

    const userDeleteMatch = path.match(/^\/admin\/user\/([^/]+)$/);
    if (userDeleteMatch && request.method === "DELETE") {
      return handleAdminDeleteUser(request, env, userDeleteMatch[1]);
    }

    if (path === "/admin/registry" && request.method === "GET") return handleAdminRegistry(request, env);
    if (path === "/admin/history" && request.method === "GET") return handleAdminHistory(request, env);

    // ── /auth/* — RBAC admin user-management ──────────────────────────────
    if (path === "/auth/login" && request.method === "POST") return handleAuthLogin(request, env);
    if (path === "/auth/logout" && request.method === "POST") return handleAuthLogout(request, env);
    if (path === "/auth/me" && request.method === "GET") return handleAuthMe(request, env);
    if (path === "/auth/invite" && request.method === "POST") return handleAuthInvite(request, env);
    if (path === "/auth/invite-bulk" && request.method === "POST") return handleAuthInviteBulk(request, env);
    if (path === "/auth/accept-invite" && request.method === "POST") return handleAuthAcceptInvite(request, env);
    if (path === "/auth/users" && request.method === "GET") return handleAuthUsers(request, env);
    if (path === "/auth/bootstrap" && request.method === "POST") return handleAuthBootstrap(request, env);

    // Session-gated self-service tenant (the caller's own lab) + admin tenant list.
    if (path === "/auth/lab/register" && request.method === "POST") return handleAuthLabRegister(request, env);
    if (path === "/auth/lab/identity" && request.method === "GET") return handleAuthLabIdentity(request, env);
    if (path === "/auth/tenants" && request.method === "GET") return handleAuthTenants(request, env);

    const userRoleMatch = path.match(/^\/auth\/users\/([^/]+)\/role$/);
    if (userRoleMatch && request.method === "POST") return handleAuthUserRole(request, env, userRoleMatch[1]);

    const userDeleteAuthMatch = path.match(/^\/auth\/users\/([^/]+)$/);
    if (userDeleteAuthMatch && request.method === "DELETE") return handleAuthDeleteUser(request, env, userDeleteAuthMatch[1]);

    return json({ error: "not found" }, 404);
  },
};
