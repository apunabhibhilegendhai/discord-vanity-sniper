# Sniper dashboard

Next.js dashboard for editing the sniper config and inspecting the health sidecar. It is
designed to run on the same always-on host as Postgres, Redis, and the Go sniper, behind
the named Cloudflare Tunnel. It is not a Vercel deployment.

## Route contract

All `/api` responses are JSON with `Cache-Control: no-store`.

| Route | Auth | Behavior |
|---|---|---|
| `GET /api/config` | admin | Active config version, redacted config, and secret-presence metadata |
| `POST /api/config` | admin + same origin | Merge omitted secrets from the active version, validate the full config, atomically write a new version, return `201` |
| `GET /api/health` | admin | Missing/ok/degraded/stale view of `sniper_health` |
| `POST /api/restart` | admin + same origin | Run `/usr/bin/sudo -n /usr/local/sbin/sniper-restart`; fixed unit only |
| `POST /api/auth/login` | public, same origin | Supabase password grant, or the explicitly gated local dev token |
| `POST /api/auth/logout` | public, same origin | Clear the HttpOnly session cookie |

Pages:

- `/` — service status, active config, recent audit events.
- `/config` — structured editor; stored secrets are never rendered back.
- `/issues` — sidecar error state and audit history.

Unauthenticated API calls return `401`. An authenticated user who is not in
`sniper_admins` gets `403`. Cookie-backed writes require an `Origin` matching
`APP_ORIGIN` (or the request origin when `APP_ORIGIN` is unset).

## Auth and authorization

1. The browser posts email/password to `/api/auth/login`.
2. The server exchanges it at the self-hosted Supabase `/auth/v1/token?grant_type=password`
   endpoint using the **anon** key.
3. The resulting access token is stored in an `HttpOnly`, `SameSite=Lax` cookie.
4. Every protected request revalidates it with `GET /auth/v1/user` using the **anon** key.
5. The server then looks up the user id in `sniper_admins` with the **service-role** key.
6. Only an active `admin` row is allowed to read or write.

The service-role key exists only in the server process. It is never exported as a
`NEXT_PUBLIC_*` value and is not returned by an API route.

## Config validation and secrets

The editor sends a structured config. The server:

- rejects unknown fields at the top level, target level, and fingerprint level;
- validates Discord guild/user ids, vanity syntax, proxy URLs, Discord webhook URLs,
  base32 TOTP secrets, enum values, numeric ranges, duplicate guilds, and the
  token-or-email/password login path;
- merges secrets that the redacted GET omitted. An absent secret means “keep the
  current value”; an explicitly empty string means “clear it”;
- writes a new immutable `sniper_configs` version through
  `public.sniper_save_config(jsonb, uuid, text, inet)`, which serializes writers,
  deactivates the old row, inserts the new active row, and writes the audit entry in
  one transaction.

`GET /api/config` removes `webhook_url`, `password`, `totp_secret`, `backup_codes`, and
each target's `token`/`password`; it returns only booleans/counts in `secretStatus`.

Secret-at-rest encryption is **not** implemented in this pass. The config JSON is stored
in `sniper_configs.config` because `sniper-config-sync` reads that shape, and the
`sniper_secrets` table is reserved for a later renderer. The RLS model still prevents
anon/authenticated table access and the service-role key stays server-side, but this is a
real limitation, not equivalent to encryption.

## Health and restart boundary

The dashboard never inspects the Go process. It reads the row written by
`deploy/bin/sniper-health` and presents:

- `missing` — no sidecar row; explicitly not the same as “sniper down”;
- `stale` — heartbeat older than 90 seconds;
- `degraded` — non-active service status or a recorded error;
- `drift` — the stored active config version differs from the version the sidecar
  reports as applied;
- `ok` — active, fresh, and no config drift.

`sniper-health` publishes `applied_config_version` from
`$STATE_DIR/config.version`. `sniper-config-sync` writes that file only after a
successful restart, so it is the durable evidence of the version the running unit
loaded. A mismatch with the active stored version is rendered as `drift`, never
`ok`; the page also names both versions.

The only privileged action is `POST /api/restart`. It is disabled unless
`DASHBOARD_HOST_ACTIONS=1`, and it executes the fixed helper with `execFile`, never a
shell. The helper is the narrow sudoers rule in
[`../deploy/sudoers/sniper-deploy`](../deploy/sudoers/sniper-deploy). The unit deliberately
omits `NoNewPrivileges=`, because that setting would block the helper's setuid sudo
transition; the sudoers entry remains fixed-argument and fixed-unit. Config changes are
written to Supabase and applied by the existing `sniper-config-sync.timer`; the dashboard
does not run an unrestricted `systemctl`.

## Local proof mode

The dashboard supports a local-only file datastore and dev auth adapter. Both require
explicit flags; they are not selected by `NODE_ENV` alone.

```bash
cd dashboard
npm ci
DASHBOARD_STORE=file \
DASHBOARD_ALLOW_FILE_STORE=1 \
DASHBOARD_DATA_FILE=.local/proof.json \
DASHBOARD_AUTH_MODE=dev \
DASHBOARD_ALLOW_DEV_AUTH=1 \
DASHBOARD_DEV_TOKEN=local-proof-token-123 \
DASHBOARD_DEV_USER_ID=00000000-0000-4000-8000-000000000001 \
DASHBOARD_DEV_ADMIN=1 \
DASHBOARD_HOST_ACTIONS=0 \
APP_ORIGIN=http://127.0.0.1:3100 \
npm run dev -- -p 3100
```

`curl` with `Authorization: Bearer local-proof-token-123` exercises the API without a
browser cookie. The browser sign-in form accepts the same token in this mode. Never set
these flags on the production service.

Production environment names are in
[`../deploy/env/dashboard.env.example`](../deploy/env/dashboard.env.example).

## Commands

```bash
npm run typecheck
npm test
npm run build
npm start -- -p 3000
```

The deploy workflow expects the `next` runtime in `dependencies` (not
`devDependencies`) because the host install uses `npm ci --omit=dev`.

## Local verification performed (2026-10-20)

A production build (`npm run build` + `npm start`) was exercised against the file
store and dev auth adapter with `APP_ORIGIN=http://127.0.0.1:3100` and
`DASHBOARD_HOST_ACTIONS=0`. No Supabase table, host helper, or production
credential was used. Observed results:

| Case | Result |
|---|---|
| `GET`/`POST /api/config`, `GET /api/health`, `POST /api/restart` without a session | `401 unauthenticated` |
| Local sign-in, then `GET /api/config` | `200`; no config row initially |
| Invalid config (typo field, bad guild id, no login path) | `400 validation_failed`; no config version written |
| Valid config | `201`, version `1`; one active row; redacted `GET` returns no token, password, TOTP, webhook, or backup codes |
| `/` with no `sniper_health` row | `missing`, “No health sidecar data yet”; stored config still shown |
| `/` with a fresh active health row | `ok`, “Service is active and the heartbeat is fresh”; applied `v1` shown against stored `v1` |
| `/` with stored `v2` and sidecar applied `v1` | `drift`, red notice naming stored `v2` and applied `v1` |
| `POST /api/restart` with host actions disabled | `503 host_actions_disabled`; no helper executed |
| Cookie-backed config write with a foreign `Origin` | `403 bad_origin` |
| Sign-out, then `GET /api/config` | `401` |

The JSON and HTML evidence is under `dashboard/.local/`, which is ignored by Git and
is not a production datastore. Separately, `deploy/bin/sniper-health` was run against a
local capture endpoint: `STATE_DIR/config.version` containing `7` produced
`"applied_config_version":7`, and a missing version file produced `null`. The migration
file was syntax-parsed, but not applied: no Postgres/Supabase instance was available in
this environment.
