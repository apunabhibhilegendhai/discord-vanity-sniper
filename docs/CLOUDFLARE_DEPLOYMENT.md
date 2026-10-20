# Cloudflare Free-Plan Deployment Plan

**Status:** evidence and plan only. No Worker, Durable Object, D1 database, R2 bucket, Cron Trigger, secret, or route was created or deployed for this document.

> **Superseded as the deployment direction.** The current plan is GitHub Actions + self-hosted Supabase/Redis + a Cloudflare Tunnel dashboard in [GITHUB_ACTIONS_DEPLOYMENT.md](GITHUB_ACTIONS_DEPLOYMENT.md). This document remains the Cloudflare Workers Free feasibility record and is still the source for the workspace-runtime finding.

**Date:** 2026-10-20

**Scope:** the existing Go sniper and Vanity Guard in `internal/sniper`, and the Cloudflare account tied to the API token supplied for this task.

## 1. Verdict first

The existing binary cannot be deployed unchanged to Cloudflare Workers Free. The claim path depends on raw TCP sockets, a controllable TLS ClientHello (`utls`), pre-warmed HTTP/1.1 connections, HTTP/SOCKS5 proxy dialing, and a 5 ms polling loop. Workers Free provides none of those in a form that preserves the design.

There are three honest deployment shapes:

| Shape | What runs on Cloudflare | Claim / reclaim | Vanity Guard | Honest label |
|---|---|---|---|---|
| **A. `sniper-monitor` Worker + D1 + Cron** | A read-only monitor and alerting control plane | No | Alert only | **Deployable on Workers Free** |
| **B. Go runner on a host, Cloudflare free at the edge** | DNS, optional Tunnel/alert relay | Yes, full code path | Yes, full code path | **Full fidelity, but not Cloudflare compute** |
| **C. Worker/DO gateway + `fetch` PATCH** | Gateway and HTTP requests | Unverified and degraded | No reliable reclaim | **Experiment only; not recommended** |

A "full deploy" on Cloudflare Free can only mean **Shape A**. If "full" means the sniper actually claims and the Guard actually reclaims and punishes, the Go process must run somewhere with raw sockets and controllable TLS; that is **Shape B**, and Cloudflare is an edge/control surface, not the compute host. Shape C can send an HTTP PATCH, but it cannot reproduce the code path or the measured latency, and Discord's acceptance of a Worker-originated PATCH is unverified.

The rest of this document is the evidence for that verdict and the exact implementation plan for Shape A, plus the deployment contract for Shape B.

## 2. Account and token verification

### 2.1 What was verified

| Check | Result |
|---|---|
| Token class | Account API Token (account-owned, not a user-level API token) |
| Account-owned token verify: `GET /accounts/${CLOUDFLARE_ACCOUNT_ID}/tokens/verify` | **200**, `status: active` |
| User-level token verify: `GET /user/tokens/verify` | **401** `Invalid API Token` — expected for an account-owned token, not evidence of revocation |
| Account lookup: `GET /accounts/${CLOUDFLARE_ACCOUNT_ID}` | **200**, account type `standard`, created `2026-05-20T17:17:42Z` |
| Token record | name `sniper token`, status `active`, issued `2026-10-20T07:23:12Z`, last used `2026-10-20T07:45:18Z`, no expiry field |
| Token policies | 2 × `allow`, both scoped to `com.cloudflare.api.account.${CLOUDFLARE_ACCOUNT_ID}`; no zone resource |
| Permission groups | 391 entries across the two policies (384 unique names), including Workers Admin, Workers Editor, Workers Scripts Write, D1 Write, R2 Storage Write, Secrets Store Write, Account Settings Write, Queues Write, KV Write |
| Wrangler authentication | `wrangler 4.151.2 whoami` → **Account API Token**, account `${CLOUDFLARE_ACCOUNT_ID}` |
| Free-plan evidence | `GET /accounts/{id}/subscriptions` → **200**, empty result; billing profile endpoint → **404**. No paid subscription is visible, which is consistent with Workers Free, but the API does not return a definitive plan name |
| Zones | `GET /zones` → **200**, count `0` |
| Existing Workers | one script, `gofile-keepalive`; Workers subdomain `apunlegendhai` |
| D1 | `GET /d1/database` → **200**, zero databases |
| R2 | `GET /r2/buckets` → **403** “Please enable R2 through the Cloudflare dashboard” |
| Durable Objects | no namespace was provisioned; the account-level namespace route is not a valid list route. Wrangler creates namespaces from the `wrangler.toml` migration when a DO is first deployed |

The account id is stored in `.env` as `CLOUDFLARE_ACCOUNT_ID` and is deliberately not reproduced in this repository. The Workers dev hostname suffix is **`apunlegendhai.workers.dev`**.

The token is broad: it can create Workers, D1 databases, secrets, and account-level resources. It should be treated as a deployment credential, not a runtime application secret, and rotated after the deployment work is finished.

### 2.2 Where the token is stored

`./.env` contains only these names (values intentionally not reproduced here):

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
CLOUDFLARE_WORKERS_SUBDOMAIN
```

`./.gitignore` line 15 is `.env`; line 16 is `.dev.vars`. There is no Git repository in this extracted workspace, so there is nothing to commit; the ignore rules are in place for a future `git init` or copy into a repository.

Do not put the Cloudflare token in `wrangler.toml`, a Worker `vars` block, source code, logs, a URL, or a chat message. For local shell use only:

```bash
set -a
. ./.env
set +a
```

For Worker runtime credentials, use `wrangler secret put` (section 5). The Cloudflare deployment token is not a Worker secret and should not be bound to the Worker.

## 3. What the Go system actually requires

These are the load-bearing requirements in the current code, not a generic feature list.

| Requirement | Evidence in this repo | Why Workers Free cannot preserve it |
|---|---|---|
| Persistent Discord gateway WebSocket | `gateway.go:27-33` (gorilla dialer, TLS 1.2), `gateway.go:260-282` (fixed `wss://gateway.discord.gg/?v=10&encoding=json` or `resume_gateway_url`), `gateway.go:285-322` (IDENTIFY/RESUME), `gateway.go:362-509` (heartbeat and reconnect) | A Worker can make an outbound WebSocket, but a Durable Object's outbound connection prevents eviction for at most **15 minutes**; outbound WebSockets do not hibernate. That is not a durable gateway host without a reconnect/ownership design. |
| Chrome/Firefox TLS fingerprint (`utls`, JA3) | `tlsdial.go:36-54` (fresh ClientHello spec), `tlsdial.go:124-162` (raw TCP + uTLS to `discord.com:443`), `tlsdial.go:170-180` (uTLS over a proxy tunnel) | Workers `fetch()` uses Cloudflare's TLS stack. `connect()` offers `secureTransport: "on"` but no ClientHello, cipher-order, extension, or JA3 control. |
| Raw TCP with socket tuning | `tlsdial.go:133-145` (dial, `TCP_NODELAY`, 1 MiB read/write buffers), `pool.go:194-227` (pool dial path) | Workers expose stream-oriented `connect()` sockets, not arbitrary socket options, and do not expose raw packet or ClientHello control. The Workers TCP docs also block outbound TCP to Cloudflare IP ranges. |
| Warm connection pool | `pool.go:57-81` (one warm conn every 200 ms), `pool.go:83-172` (background rewarmer), `pool.go:267-283` (`maxIdleAge = 10s`), `config.go:42-54` (warm conns raised to `burst_count`) | No pre-warmed, user-owned TLS connection is available to a Worker/DO. `fetch()` connection reuse is opaque, and each invocation has a six-simultaneous-connection limit while waiting for headers. |
| HTTP/SOCKS5 proxy dialing and multi-IP burst | `pool.go:212-227` (`dialProxy` then uTLS), `config.go:116-121` (one proxy list per target), PRD §3.3 (one pool per proxy entry) | Workers `fetch()` does not accept an HTTP CONNECT or SOCKS5 proxy. There is no supported way to choose a source IP or route a subrequest through a user proxy. |
| Pre-armed sentries and pre-built PATCH bytes | `claimer.go:319` and surrounding sentry path; `prebuild.go:1-140`; PRD §3.3 | The whole point is to hold a writable, already-handshaked socket and publish bytes atomically. Workers only expose `fetch()`, which constructs and sends an HTTP request at call time. |
| 5 ms poller with one persistent socket | `poller.go:67-115` (5 ms cycle target, ±1 ms jitter), `poller.go:125-158` (one request in flight), `poller.go:202-213` (persistent `utls` conn), PRD §7 | Cron Triggers have a **one-minute** minimum. A 5 ms loop is 17,280,000 iterations/day; the free DO request allowance is 100,000/day. This is not a tuning gap; it is three orders of magnitude outside the plan. |
| MFA ticket → `/mfa/finish`, cookie continuity | `mfa.go:232-325` (ticket fetch, `__dcfduid`/`__sdcfduid`/`_cfuvid` merge), `mfa.go:329-356` (solve), `mfa.go:767-805` (raw POST `/api/v9/mfa/finish`) | A JS Worker can compute TOTP and POST `fetch()` requests, but it cannot reproduce the raw HTTP/TLS path or the exact cookie/fingerprint continuity. It would be a new, unproven client, not a port. |
| Email/password + TOTP token recovery | `login.go:67-129` (`/auth/login` → `/auth/mfa/totp`), `login.go:161` (`discordDialConn`) | Same problem: a new JS client with Cloudflare TLS and manually managed cookies. It is implementable in principle, but it is not the existing code path and is not evidence of claim viability. |
| Session/resume state on disk | `session.go:1-160` (`session_state.json`, atomic rename, 3 s autosave), `gateway.go:253-282` (resume) | DO SQLite/D1 can persist session fields, but the gateway host problem above remains. Do not mistake “state can be stored” for “the gateway can live there.” |
| Parallel arming with a 30 s lane budget | `orchestrator.go:124` (`armLaneTimeout`), `orchestrator.go:148-276` (parallel barrier), `orchestrator_arming_test.go` evidence: **3.02 s serial vs 1.003 s parallel** for 3 lanes × 5 warm connections | Arming is dominated by TCP/TLS handshakes and MFA priming. Workers have no user-controlled warm pool; cold-start behavior replaces arming rather than reproducing it. |
| Latency gates | `hotpath_test.go:21-24`: p50 **20 µs**, p95 **250 µs**, p99 **2 ms**; `prebuild_test.go:15`: poller median gap ≤ RTT + **3 ms** | These are local wake→wire gates, not network gates. Workers add invocation scheduling, `fetch()` overhead, and a one-minute cron floor; none of these gates can be asserted on Workers. |
| Vanity Guard audit log and kick/ban | `guard.go:122-169` (audit-log GET), `guard.go:346-382` (kick/ban request), `guard.go:384-390` (raw HTTP via pool) | The REST calls could be rewritten as `fetch()`, but the guard's purpose is to race the reclaim burst at claim speed. A one-minute monitor can notify, but it cannot defend the vanity. |
| Config and token persistence on disk | `config.go:14-127`, `run.go:79-202` (mint and rewrite `config.json`), `session.go:63-84` | Workers have no general filesystem. D1/DO storage is a different data model and would require a new implementation. |

The existing gateway already uses Go's standard `crypto/tls`, not `utls` (`gateway.go:5`, `gateway.go:32`). That is the one transport piece that is conceptually portable to a Worker WebSocket; it is not enough to port the claim path.

## 4. Cloudflare Free limits that decide the design

All figures are from the official Cloudflare docs read on 2026-10-20. Links are in section 8.

### 4.1 Workers Free

| Limit | Workers Free | Consequence for this system |
|---|---|---|
| Requests | 100,000/day | A one-minute cron is 1,440 invocations/day; fine for monitoring, not for a 5 ms loop |
| CPU per HTTP request | **10 ms** | Enough for parsing a few JSON responses; not enough for continuous gateway work or crypto-heavy loops |
| CPU per Cron Trigger | **10 ms** | The monitor must keep per-run work tiny; waiting on `fetch()` does not count, parsing/loops do |
| Memory | 128 MB per isolate | Not the constraint; the transport is |
| Subrequests | **50 external per invocation** | Caps a single monitor run at roughly 40 Discord GETs plus one webhook; D1 calls use the separate internal-service budget |
| Simultaneous outgoing connections waiting for headers | **6** | Fetches must be batched; 40 concurrent `fetch()` calls will queue after six |
| Duration, HTTP | No hard limit while the client remains connected | Does not create a place to host a persistent background process |
| Duration, Cron | 15 minutes wall time | A cron invocation can run long in wall time, but CPU is still 10 ms |
| Duration, DO alarm | 15 minutes wall time | Alarms are not a 5 ms scheduler |
| Workers per account | 100 | Plenty |
| Cron Triggers per account | **5** | At most five schedules; each can run every minute |
| Worker size / startup | 64 MiB / 1 s | Plenty for a monitor |
| Runtime update grace | up to 20 minutes for existing connections | Long-lived connections can be cut during platform updates; design for reconnect |

Sources: [Workers limits](https://developers.cloudflare.com/workers/platform/limits/), [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/), [Cron Triggers](https://developers.cloudflare.com/workers/configuration/cron-triggers/).

### 4.2 Durable Objects Free

| Limit | Workers Free | Consequence |
|---|---|---|
| Availability | SQLite-backed DOs only | A DO design must use SQLite storage, not the legacy KV backend |
| Requests | 100,000/day (HTTP, RPC, WebSocket messages, alarms) | A 5 ms loop is 17.28M/day; a one-minute alarm is 1,440/day |
| Duration | 13,000 GB-s/day | One 128 MB DO active continuously is 11,059 GB-s/day; it fits, but with little headroom and no room for a second always-on object |
| Storage | 5 GB total | More than enough for session/state |
| Classes | 100 | Plenty |
| Outbound WebSocket | Supported | A DO can connect to Discord, but outbound WebSockets do **not** hibernate |
| Outbound connection eviction protection | Max **15 minutes** per connection | After 15 minutes the standard 70–140 s inactivity window resumes; a gateway needs explicit reconnect/ownership handling and is not a guaranteed always-on host |
| WebSocket message size | 32 MiB received | Discord frames are far smaller |
| Simultaneous outgoing connections | 6 | Same batching constraint |

Sources: [DO limits](https://developers.cloudflare.com/durable-objects/platform/limits/), [DO pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/), [DO WebSockets](https://developers.cloudflare.com/durable-objects/best-practices/websockets/), [outbound connections and eviction](https://developers.cloudflare.com/changelog/post/2026-06-19-outbound-connections-keep-dos-alive/).

The DO limits page says DOs are Workers and Workers limits apply according to the plan. The 10 ms Free CPU budget is therefore the planning assumption; the larger 30 s DO default is not a Free allowance.

### 4.3 TCP sockets and TLS

Workers provide `connect()` from `cloudflare:sockets`:

- `secureTransport` is `"off"`, `"on"`, or `"starttls"`.
- `connect()` returns a `Socket` with `readable`, `writable`, `opened`, `closed`, `close()`, and `startTls()`.
- There is no API to supply a ClientHello, JA3/JA4 profile, cipher order, extension set, or a raw `net.Conn`.
- Outbound TCP to Cloudflare IP ranges is blocked.
- Sockets cannot be created in global scope and shared across requests.
- Each open socket counts toward the six-connection limit.
- Port 25 is blocked.

Source: [TCP sockets](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/).

Consequences:

1. `utls` cannot be used. The entire reason `tlsdial.go` exists is to present a browser ClientHello; Workers owns the TLS stack.
2. The direct raw TCP/TLS path to `discord.com` is not a supported deployment target, and the Cloudflare-IP block makes it worse.
3. TCP_NODELAY, 1 MiB buffers, and a pool of already-handshaked sockets have no Worker equivalent.
4. HTTP/SOCKS5 proxy dialing and multi-IP bursts cannot be implemented through `fetch()` or `connect()`.

### 4.4 Go/Wasm

Workers can run WebAssembly, and Go can be compiled to Wasm, but Workers are single-threaded and do not support the Web Worker API or threading. WASI support is experimental and only some syscalls are implemented. That is not a home for `utls`, `net.Conn`, `crypto/tls` with a custom ClientHello, goroutines that block, a filesystem, or persistent sockets.

Source: [WebAssembly](https://developers.cloudflare.com/workers/runtime-apis/webassembly/).

Even if a Go/Wasm build compiled, it would be a new runtime port with the same transport limits, not “the existing binary on Workers.”

### 4.5 What is genuinely available on Free

These are the pieces Shape A uses:

- Worker `fetch` and `scheduled` handlers.
- Cron Triggers, five fields, minimum every minute, five per account.
- `fetch()` to `https://discord.com/api/v9/...` for read-only REST calls.
- D1: 5 million rows read/day, 100,000 rows written/day, 5 GB total.
- Secrets via `wrangler secret put`.
- Workers Logs (Free: 200,000 events/day, 3-day retention).
- `*.workers.dev` hostname; the account has no zone, so no custom domain route.

D1 source: [D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/).

## 5. Shape A: `sniper-monitor` on Workers Free

### 5.1 What it is

A read-only monitor with a one-minute observation cadence:

1. Cron invokes a Worker every minute.
2. The Worker loads enabled targets from D1.
3. For each target it calls `GET /api/v9/guilds/{guild_id}/vanity-url` with the configured user token.
4. It compares `vanity_url_code` with the expected vanity and the previous state.
5. On a transition it writes an observation and posts a Discord webhook alert.
6. A protected status endpoint returns the current state.

It does **not** claim, reclaim, solve MFA, punish, or hold a gateway connection. “Guard” in this shape means “tell the operator the vanity is no longer held,” not “defend it.”

### 5.2 Exact files to create

Nothing in this table exists yet. These are the implementation targets for the next pass.

| Path | Purpose |
|---|---|
| `cloudflare/sniper-monitor/package.json` | Wrangler/Vitest scripts and pinned dev dependencies |
| `cloudflare/sniper-monitor/wrangler.toml` | Worker name, D1 binding, cron, observability, account id |
| `cloudflare/sniper-monitor/tsconfig.json` | TypeScript config for Workers types |
| `cloudflare/sniper-monitor/schema.sql` | D1 tables and indexes |
| `cloudflare/sniper-monitor/src/index.ts` | `fetch` and `scheduled` handlers; routes; transition logic |
| `cloudflare/sniper-monitor/src/discord.ts` | Read-only Discord REST client, timeout/abort, response parsing |
| `cloudflare/sniper-monitor/src/db.ts` | Prepared D1 queries and batch updates |
| `cloudflare/sniper-monitor/src/notify.ts` | Webhook sender and alert formatting |
| `cloudflare/sniper-monitor/src/state.ts` | Pure `held`/`free`/`other`/`error` transition function |
| `cloudflare/sniper-monitor/test/state.test.ts` | Unit tests for transitions and malformed responses |
| `cloudflare/sniper-monitor/test/discord.test.ts` | Mocked `fetch` tests for 200/null/401/429/timeout |
| `cloudflare/sniper-monitor/vitest.config.ts` | Workers Vitest pool config if the Workers test pool is used |
| `cloudflare/sniper-monitor/.dev.vars.example` | Local-only placeholder names; never real values |
| `cloudflare/sniper-monitor/README.md` | Local run, deploy, seed, rotate, rollback |
| `deploy/systemd/discord-sniper.service` | Shape B only: process supervision for the Go binary |
| `deploy/cloudflared/config.yml.example` | Shape B only: optional named Tunnel example; not usable without a zone |

### 5.3 `wrangler.toml` target

```toml
name = "sniper-monitor"
main = "src/index.ts"
compatibility_date = "2026-10-20"
account_id = "REPLACE_WITH_CLOUDFLARE_ACCOUNT_ID"
workers_dev = true

[[d1_databases]]
binding = "DB"
database_name = "sniper-state"
database_id = "REPLACE_WITH_OUTPUT_OF_WRANGLER_D1_CREATE"

[triggers]
crons = ["* * * * *"]

[observability]
enabled = true
```

No `vars` block contains a token. `account_id` is an identifier, not a credential. `workers_dev = true` is the only route because the account has no zone.

### 5.4 D1 schema target

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS targets (
  guild_id       TEXT PRIMARY KEY,
  vanity         TEXT NOT NULL,
  enabled        INTEGER NOT NULL DEFAULT 1,
  last_code      TEXT,
  last_state     TEXT NOT NULL DEFAULT 'unknown',
  last_checked_at TEXT,
  last_change_at TEXT
);

CREATE TABLE IF NOT EXISTS observations (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  guild_id    TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  code        TEXT,
  state       TEXT NOT NULL,
  http_status INTEGER,
  source      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS observations_by_guild_time
  ON observations (guild_id, observed_at DESC);
```

`targets` holds no secrets. Seed it with guild ids and expected vanities only. Delete or disable rows rather than storing tokens there.

### 5.5 Worker behavior contract

`scheduled(controller, env, ctx)`:

1. `SELECT guild_id, vanity, last_code, last_state FROM targets WHERE enabled = 1 ORDER BY guild_id LIMIT 40`.
2. Fetch in batches of at most six concurrent requests; every fetch has a 10 s abort timeout.
3. Send only the minimal read-only header set: `Authorization`, `User-Agent` (a fixed Chrome UA), `X-Super-Properties` if configured, and `Accept: application/json`. Do not log headers.
4. Treat only a complete `200` with parseable JSON as an observation. A timeout, 429, 401, HTML challenge, truncated body, or missing `vanity_url_code` is `error`, never `free`.
5. Transition function:
   - `held` → code equals the expected vanity.
   - `free` → complete 200 with `vanity_url_code` null or empty.
   - `other` → complete 200 with a different non-empty code (a steal).
   - `error` → anything not safely parseable.
6. Alert only on a state transition, not on every minute. Alert on `held → free`, `held → other`, and optionally `error` after N consecutive failures. Deduplicate with `last_state`.
7. Update `targets.last_code`, `last_state`, `last_checked_at`, and `last_change_at` in one D1 batch. Insert an `observations` row only on a change or on the first observation.
8. Keep each run under 50 **external** subrequests including the webhook. With 40 targets and one webhook, that is 41; D1 calls are internal-service subrequests, not part of that 50.

`fetch(request, env, ctx)`:

| Route | Method | Auth | Behavior |
|---|---|---|---|
| `/` | GET | none | Static status page with no secrets, `Cache-Control: no-store` |
| `/api/status` | GET | `Authorization: Bearer <STATUS_TOKEN>` | JSON snapshot of targets and last observations; `Cache-Control: no-store` |
| `/api/check` | POST | same bearer token; same-origin check | Run one check immediately; rate-limit to once per minute; no claim |
| anything else | any | n/a | 404 |

There is no `PATCH`, no `/claim`, no kick/ban endpoint, and no endpoint that reads the Discord token back.

### 5.6 Exact deployment commands

Run from the repository root after the files exist:

```bash
set -a
. ./.env
set +a

cd cloudflare/sniper-monitor
npm install
npx wrangler@4.151.2 d1 create sniper-state
# Copy the returned database_id into wrangler.toml.
npx wrangler@4.151.2 d1 execute sniper-state --remote --file=./schema.sql
npx wrangler@4.151.2 d1 execute sniper-state --remote \
  --command "INSERT INTO targets (guild_id, vanity) VALUES ('123456789012345678','example');"

npx wrangler@4.151.2 secret put DISCORD_USER_TOKEN
npx wrangler@4.151.2 secret put DISCORD_WEBHOOK_URL
npx wrangler@4.151.2 secret put STATUS_TOKEN

npx wrangler@4.151.2 deploy --dry-run --outdir dist
npx wrangler@4.151.2 deploy
npx wrangler@4.151.2 tail sniper-monitor
```

`wrangler secret put` prompts for the value; do not pass the value on the command line, do not paste it into chat, and do not put it in `wrangler.toml`. `STATUS_TOKEN` should be a fresh random value, independent of every other credential.

Local verification:

```bash
cd cloudflare/sniper-monitor
cp .dev.vars.example .dev.vars   # fill with local-only test values; .dev.vars is gitignored
npx wrangler@4.151.2 d1 execute sniper-state --local --file=./schema.sql
npx wrangler@4.151.2 dev
# In another shell:
curl -s http://localhost:8787/
curl -s -H "Authorization: Bearer $STATUS_TOKEN" http://localhost:8787/api/status
curl -s -X POST -H "Authorization: Bearer $STATUS_TOKEN" http://localhost:8787/api/check
```

To exercise transitions without live Discord, run the unit tests with mocked `fetch` and a local D1 binding. Do not test claims; this Worker has none.

Rollback and removal, if ever needed:

```bash
npx wrangler@4.151.2 deployments list
npx wrangler@4.151.2 rollback <VERSION_ID>
npx wrangler@4.151.2 delete sniper-monitor
```

Deleting the Worker does not delete the D1 database; remove it separately only after exporting anything needed.

### 5.7 Capacity and limits check

With one cron trigger and 40 targets:

| Item | Per day | Free limit | Headroom |
|---|---|---|---|
| Cron invocations | 1,440 | 100,000 Worker requests | Large |
| Discord GETs | 57,600 | 50 per invocation; no separate daily subrequest count | 40 per run, under 50 |
| D1 reads | ~57,600 rows | 5,000,000 rows/day | Large |
| D1 writes | ~57,600 rows if `last_checked_at` updates every run | 100,000 rows/day | ~58% used, 42% headroom; acceptable, but only on this target count |
| Webhook posts | transitions only | shares the 50 external-subrequest cap | Fine |

At 100 targets, do not simply raise the limit: 100 GETs plus one webhook exceeds the 50-subrequest cap. Shard targets across up to five cron triggers, with at most 40 per invocation, and measure CPU and D1 writes. At 200 targets, five shards at 40 each is possible on paper; each shard must run at a different `controller.cron` schedule or the Worker cannot tell which slice it owns. The free `10 ms` CPU budget per invocation is the real limit to measure; a run with 40 fetches may spend most of its wall time waiting but still has parsing and D1 work.

The one-minute cron is the detection ceiling. Worst-case notification time is roughly 60 s plus the Discord request RTT. That is monitoring, not sniping.

### 5.8 Security contract for Shape A

- The Discord user token is a Worker secret; never a `vars` entry, D1 row, URL, or log line.
- The webhook URL is a secret; webhook content contains guild ids and vanities, not tokens.
- `/api/status` and `/api/check` require `STATUS_TOKEN`; compare with a constant-time comparison and return `401` without detail.
- Set `Cache-Control: no-store` on every authenticated response.
- Do not add a browser CORS `*` policy to authenticated routes.
- Do not log request headers, tokens, cookies, or full Discord bodies; log only status, timing, target id, and parsed state.
- Rate-limit `/api/check`; a public unauthenticated check endpoint would burn the 100k request allowance.
- Discord ToS: automating a user account is prohibited. This plan does not make that risk disappear; it only avoids adding a second, weaker claim client.

## 6. Shape B: full fidelity with the Go binary on a host

This is the only shape that preserves the existing claim and Guard behavior. Cloudflare is not the compute host.

### 6.1 Host requirements

- Always-on Linux host (VPS, home server, or dedicated machine) with a stable outbound path to Discord.
- Outbound TCP 443 and the ability to reach the configured HTTP/SOCKS5 proxies.
- Go 1.24+ toolchain for the build (this repo declares `go 1.24`; the local toolchain is 1.26.9).
- Writable directory for `config.json` and `session_state.json`; the session store writes a temp file and renames it.
- Enough file descriptors for `warm_connections × proxies` plus MFA/guard sockets; set `LimitNOFILE=65535`.
- A process supervisor that restarts on failure. The binary handles SIGINT/SIGTERM and shuts down its runners (`run.go:55-63`), so `systemd` is a good fit.

### 6.2 Build and run

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w" -o sniper .

./sniper -config /etc/discord-sniper/config.json
```

No Go code changes are required for this shape. The existing build and test instructions remain in [PRD §13](PRD.md#13-build--run).

### 6.3 Exact service file target

`deploy/systemd/discord-sniper.service`:

```ini
[Unit]
Description=Discord vanity sniper
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sniper
Group=sniper
WorkingDirectory=/var/lib/discord-sniper
ExecStart=/opt/discord-sniper/sniper -config /etc/discord-sniper/config.json
Restart=always
RestartSec=2
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/discord-sniper /var/lib/discord-sniper
StateDirectory=discord-sniper
Environment=HOME=/var/lib/discord-sniper

[Install]
WantedBy=multi-user.target
```

The config and session paths must agree with the unit. `config.json` contains user tokens and the TOTP secret; make it `0600` and owned by `sniper`. It must remain writable because `run.go` rewrites it after minting a fresh token. `session_state.json` contains session ids and MFA tokens; the working directory is the writable state directory, so the default relative session path lands there; keep it `0600` as well. Do not put either in a Git repository.

### 6.4 Cloudflare's role in Shape B

Cloudflare Free can provide:

- DNS for a domain, if the operator adds one to the account. The account currently has **zero zones**.
- Cloudflare Tunnel for ingress, if a domain is available. A named Tunnel needs a hostname in a zone; a quick Tunnel is ephemeral and not a production control plane. Tunnel is ingress, not compute; it does not make the Go process run on Cloudflare.
- A separate `sniper-monitor` Worker (Shape A) for independent alerting if the Go host dies.

Cloudflare Free cannot provide:

- A place to run the Go binary.
- Raw TCP/TLS with `utls`.
- HTTP/SOCKS5 proxy egress.
- A guaranteed long-lived gateway host.
- A 5 ms poller.
- The measured wake→wire path.

If the operator insists on Cloudflare-only compute, Workers Paid would still not restore these invariants. Containers or external compute are outside Workers Free and outside this plan.

## 7. Shape C: what a Worker/DO claim experiment would and would not prove

This is documented only to close the design question, not recommended for deployment.

A Durable Object can act as a WebSocket client and connect to `wss://gateway.discord.gg`. It can persist `session_id`, `resume_url`, and sequence in SQLite. It can decode `GUILD_UPDATE` and alert. That part is technically plausible.

It still cannot:

- Present a browser ClientHello/JA3. Cloudflare owns the TLS stack.
- Hold a pre-warmed raw HTTP/1.1 socket. `fetch()` has no user-visible connection pool.
- Dial an HTTP CONNECT or SOCKS5 proxy. There is no proxy option.
- Run a 5 ms observation loop. The free request allowance is 100k/day, and cron is one-minute granularity.
- Guarantee a durable outbound gateway. Outbound connections prevent DO eviction for only 15 minutes; outbound WebSockets do not hibernate.
- Reproduce the arming and latency gates. A Worker invocation is not the Go sentry path.

A Worker can compute TOTP in JS and can issue `PATCH /api/v9/guilds/{id}/vanity-url` through `fetch()`. That is an HTTP request, not evidence that Discord accepts a Cloudflare-originated client with a Cloudflare TLS fingerprint and no proxy. It also has no pre-warmed connection, no `X-Discord-MFA-Authorization` ticket chain from this code, and no measured claim result. Do not describe such a Worker as “the sniper” until a controlled, non-destructive test proves acceptance and a live claim is measured end to end.

The only safe Worker experiment is read-only: a single `GET /users/@me` or vanity GET from a Worker, with the token in a secret, to observe status and latency. Even that does not justify a claim deployment.

## 8. Decision and next step

**If the goal is “something real running on Cloudflare Free now”:** implement Shape A. It is useful, honest, and fits the plan: one Worker, one D1 database, one cron, three secrets, read-only Discord GETs, and webhook alerts.

**If the goal is “the sniper and Vanity Guard actually claim and defend”:** implement Shape B. Keep the Go binary on an always-on host and, if desired, run Shape A beside it for independent monitoring. Cloudflare Free is the edge and alerting layer, not the sniper host.

**Do not** implement Shape C as a substitute. It would take longer than Shape A, lose the behaviors that make this codebase distinctive, and still not establish that a claim succeeds.

Before writing either implementation, the operator should choose A or B. The next pass can then create only the selected files and run the exact commands above. No Cloudflare resource has been created in this pass.

## 9. Sources

Cloudflare documentation read 2026-10-20:

- [Workers limits](https://developers.cloudflare.com/workers/platform/limits/)
- [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/)
- [Cron Triggers](https://developers.cloudflare.com/workers/configuration/cron-triggers/)
- [Durable Objects limits](https://developers.cloudflare.com/durable-objects/platform/limits/)
- [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/)
- [Durable Objects WebSockets](https://developers.cloudflare.com/durable-objects/best-practices/websockets/)
- [Outbound connections keep Durable Objects alive](https://developers.cloudflare.com/changelog/post/2026-06-19-outbound-connections-keep-dos-alive/)
- [TCP sockets](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/)
- [WebSockets API](https://developers.cloudflare.com/workers/runtime-apis/websockets/)
- [WebAssembly](https://developers.cloudflare.com/workers/runtime-apis/webassembly/)
- [D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/)

Repo evidence: [PRD](PRD.md), [deep-research-report](deep-research-report.md), and the Go files cited in section 3.
