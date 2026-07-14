# RBAC Admin User-Management

The relay's `/admin/*` tenant-management routes are gated by an admin-console
login layer (`/auth/*`) built directly on the same `REGISTRY` KV namespace as
the tenant registry, using three reserved key prefixes (already skipped by
`/admin/registry`'s listing, which ignores every `__`-prefixed key):

| Key | Value |
|---|---|
| `__admin_user__:<email>` | `{ email, role, pass_salt, pass_hash, iterations, created_at, last_login }` |
| `__invite__:<token>` | `{ email, role, created_at, expires_at, invited_by }` |
| `__session__:<sid>` | `{ email, role, expires_at }` |

## Roles

- **`admin`** — full access: manage subdomains (enable/disable/delete) AND
  manage other admin users (invite, list, change role, remove).
- **`viewer`** — read-only: may `GET /admin/registry`, `GET /admin/history`,
  `GET /auth/users`. Blocked (`403`) from every mutating route (enable/
  disable/delete a tenant, invite, role change, remove a user).

## Security choices

- **Password hashing**: PBKDF2-HMAC-SHA256 via Web Crypto (`crypto.subtle`),
  random 16-byte salt (`crypto.getRandomValues`), **100,000 iterations**.
  `pass_salt`/`pass_hash` are base64-encoded; `iterations` is stored on the
  row so a future bump to the constant doesn't break verification of
  existing users. Plaintext passwords are never stored or logged.
- **Verification**: constant-time compare (`timingSafeEqual`, byte-XOR
  accumulator) between the computed and stored hash — no early-exit
  short-circuit.
- **Invite tokens & session ids**: `crypto.getRandomValues`, 32 raw bytes,
  base64url-encoded (no padding). Invites expire in **7 days**, sessions in
  **12 hours** — both expiries are stored and checked on every read; an
  expired session is deleted on first use.
- **Session cookie**: `oneflare_admin_session`, set with
  `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=<seconds>`. Cleared
  (`Max-Age=0`) on logout.
- Password hashes/salts are **never** returned in any API response —
  `GET /auth/users` only ever returns `{email, role, created_at, last_login}`.

## Endpoints

| Method | Path | Auth | Notes |
|---|---|---|---|
| `POST` | `/auth/login` | none | `{email, password}` -> `{ok, email, role}` + session cookie. `401` on bad creds. |
| `POST` | `/auth/logout` | session | Deletes the session, clears the cookie. |
| `GET` | `/auth/me` | session | `{email, role}` or `401`. |
| `POST` | `/auth/invite` | admin | `{email, role}` -> creates an invite, returns `{ok, invite_url, email, role, expires_at}`. Sends via Resend if configured (best-effort — a send failure still returns `invite_url`). `409` if the user already exists. |
| `POST` | `/auth/accept-invite` | invite token | `{token, password}` (password >= 10 chars) -> creates the `__admin_user__` row, deletes the invite, logs the user in (session cookie). |
| `GET` | `/auth/users` | admin or viewer | Lists admin users (no hashes) + pending (non-expired) invites. |
| `POST` | `/auth/users/:email/role` | admin | `{role}` -> change role. Blocks demoting the last `admin`. |
| `DELETE` | `/auth/users/:email` | admin | Removes a user. Blocks removing yourself and removing the last `admin`. |
| `POST` | `/auth/bootstrap` | `ADMIN_TOKEN` (break-glass) | `{email}` -> if zero admin users exist, creates an `admin`-role invite and returns its `invite_url`. `409` once any admin user exists. |

`/admin/registry`, `/admin/history` (read) and `/admin/user/:subdomain/{enable,disable}`,
`DELETE /admin/user/:subdomain` (mutate) now accept **either** a valid admin-console
session cookie **or** the `ADMIN_TOKEN` header/bearer (break-glass, treated as
role `admin`). Viewer-role sessions may only reach the two read routes.

## Bootstrap flow

There is no seed data — the very first admin is created via a break-glass
step so the system never ships a default password:

1. Operator calls `POST /auth/bootstrap` with `Authorization: Bearer
   <ADMIN_TOKEN>` and `{"email": "amin.hamidi@sentinelone.com"}`.
2. Because zero `__admin_user__` rows exist yet, this mints an `admin`-role
   invite and returns its `invite_url`
   (`https://one-flare.com/admin/accept-invite?token=...`).
3. The operator opens that URL (or is emailed it, if `RESEND_API_KEY` is
   set — it isn't required for bootstrap since Resend is only wired into
   `/auth/invite`, so send the bootstrap `invite_url` manually), sets a
   password, and is logged in as the first admin.
4. From then on, `POST /auth/bootstrap` returns `409` — all further admins
   are invited in-app via `POST /auth/invite` by an existing admin.

## Environment variables

| Var | Required | Purpose |
|---|---|---|
| `ADMIN_TOKEN` | yes (existing) | Break-glass `/admin/*` + `/auth/*`-admin access; the only auth accepted by `/auth/bootstrap`. |
| `RESEND_API_KEY` | no | If set, `/auth/invite` sends the invite email via the [Resend API](https://resend.com/docs/api-reference/emails/send-email) (`POST https://api.resend.com/emails`). If unset, the invite is still created — the operator shares `invite_url` manually. |
| `LAB_INVITE_FROM` | no | `From:` address for invite emails (default: `OneFlare Lab <onboarding@one-flare.com>`). Only used when `RESEND_API_KEY` is set. |

## Cloudflare Access caveat (operational — not solved here)

`one-flare.com` is behind **Cloudflare Access** (OTP email gate) in front of
everything, including this admin console. This RBAC layer is a *second*,
independent login on top of that:

- An admin invited in-app (via `POST /auth/invite`) will hit the Cloudflare
  Access OTP challenge **before** they ever see the `/admin/accept-invite`
  page or the login form — Access has to let them through the edge first.
- **The operator must manually add each newly-invited admin's email to the
  Cloudflare Access policy's allowed/guest list** (Zero Trust dashboard ->
  Access -> Applications -> the one-flare.com app -> policy), otherwise the
  invite link and the login page are unreachable for that person.
- This is a manual, out-of-band step every time a new admin is invited — it
  is intentionally not automated by this RBAC layer (Access policy edits are
  a separate, higher-privilege Cloudflare operation).
