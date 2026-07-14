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
//   GET    /admin/registry                — list all tenants (ADMIN_TOKEN)
//   GET    /admin/history                 — audit/history log (ADMIN_TOKEN)
//   POST   /admin/user/:subdomain/enable  — flip status -> active (ADMIN_TOKEN)
//   POST   /admin/user/:subdomain/disable — flip status -> disabled (ADMIN_TOKEN)
//   DELETE /admin/user/:subdomain         — teardown: delete registry row (ADMIN_TOKEN)
//   GET    /health                        — liveness, no auth
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

// ── POST /register ─────────────────────────────────────────────────────────

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

  const { name, s1_hec_url, s1_hec_token, site_label } = body || {};
  if (!name || !s1_hec_url || !s1_hec_token) {
    return json({ error: "name, s1_hec_url, and s1_hec_token are all required" }, 400);
  }

  const slug = slugify(name);
  if (!slug) {
    return json({ error: "name did not produce a valid subdomain slug" }, 400);
  }

  const host = `${slug}.${LAB_DOMAIN}`;
  const now = new Date().toISOString();
  const label = site_label != null ? String(site_label).trim().slice(0, 200) || null : null;

  const existingRaw = await env.REGISTRY.get(host);
  let row;
  if (existingRaw) {
    // Idempotent re-register: update the S1 destination, preserve counters
    // and history rather than erroring.
    row = JSON.parse(existingRaw);
    row.name = name;
    row.s1_hec_url = s1_hec_url;
    row.s1_hec_token = s1_hec_token;
    // Only overwrite site_label when the caller actually supplied one — an
    // idempotent re-register without a label shouldn't wipe an existing one.
    if (label) row.site_label = label;
  } else {
    row = {
      name,
      subdomain: host,
      s1_hec_url,
      s1_hec_token,
      site_label: label,
      status: "active",
      created_at: now,
      forwarded: 0,
      last_seen: null,
    };
  }

  await env.REGISTRY.put(host, JSON.stringify(row));
  await appendHistory(env, { type: existingRaw ? "re-register" : "register", subdomain: host, name });

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

// ── /admin/* — gated by ADMIN_TOKEN ───────────────────────────────────────────

async function handleAdminRegistry(request, env) {
  if (!checkAdminToken(request, env)) return json({ error: "unauthorized" }, 401);
  const rows = await listRegistryRows(env);
  const redacted = rows.map((r) => ({ ...r, s1_hec_token: redactToken(r.s1_hec_token) }));
  return json({ ok: true, count: redacted.length, registry: redacted });
}

async function handleAdminHistory(request, env) {
  if (!checkAdminToken(request, env)) return json({ error: "unauthorized" }, 401);
  const history = await getHistory(env);
  return json({ ok: true, count: history.length, history });
}

async function handleAdminUserStatus(request, env, rawSubdomain, enable) {
  if (!checkAdminToken(request, env)) return json({ error: "unauthorized" }, 401);
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
  if (!checkAdminToken(request, env)) return json({ error: "unauthorized" }, 401);
  const host = resolveHost(rawSubdomain);
  const raw = await env.REGISTRY.get(host);
  if (!raw) return json({ error: "not found", subdomain: host }, 404);

  // Teardown: delete the registry row. No live Cloudflare API calls are made
  // here — DNS/route/zone config for *.lab.soledrop.co is wildcard and shared,
  // so removing the row is sufficient to stop this tenant's traffic from being
  // forwarded (it will fall into the unknown-host bucket and be dropped).
  await env.REGISTRY.delete(host);
  await appendHistory(env, { type: "teardown", subdomain: host });

  return json({ ok: true, subdomain: host, deleted: true });
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

    return json({ error: "not found" }, 404);
  },
};
