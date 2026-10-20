# GitHub Actions, Supabase, Redis, and Cloudflare Tunnel

**Status:** workflow, deploy-script, dashboard, and dashboard-migration layer implemented and locally verified. No GitHub repository, workflow run, Supabase table, Redis key, Cloudflare tunnel, DNS record, Vercel deployment, host service, or live dashboard was created. The local proof used the file store and dev auth adapter only. The upstream inventory and adaptation record is [SUPABASE_ACTIONS_ADAPTATION.md](SUPABASE_ACTIONS_ADAPTATION.md).

**Date:** 2026-10-20

**Scope:** the Go sniper and Vanity Guard in `internal/sniper`, the supplied self-hosted Supabase/Postgres/Redis endpoints, and the supplied GitHub, Vercel, and Cloudflare credentials.

## 1. Verdict first

“Deployed in GitHub Actions” cannot mean “the sniper is always on.” GitHub Actions is a job runner, not a host:

- A standard GitHub-hosted job gets a fresh virtual machine and has a **6-hour maximum execution time**; the single-CPU `ubuntu-slim` container has a **15-minute** limit.
- A job has **no inbound service** and no stable public URL.
- Scheduled workflows have a **5-minute minimum interval**, run on the default branch, can be delayed or dropped under load, and are disabled after 60 days without activity in a public repository.
- A persistent Discord gateway WebSocket, a 5 ms poller, and a warm connection pool do not survive the end of a job.

The viable shape is:

1. **GitHub Actions** builds, tests, releases, and deploys.
2. **An always-on host** runs the Go sniper, the dashboard, and (optionally) a self-hosted runner.
3. **Supabase/Postgres/Redis** live on that host or another reachable service; `127.0.0.1` only works from the same host or the same Actions job.
4. **Cloudflare Tunnel** exposes the dashboard from that host.

An Actions-only shape can run for up to six hours and chain another run, as the supplied reference repositories do, but it is not a 24/7 sniper and it is not a permanent dashboard.

### Blockers found before implementation

| Blocker | Evidence | What must change |
|---|---|---|
| `DATABASE_URL` and `REDIS_URL` use `127.0.0.1` | Both `127.0.0.1:5432` and `127.0.0.1:6379` refused connections from this machine. They are loopback addresses, not public endpoints. | Run the dashboard, sniper, Postgres, and Redis on the same host/network namespace, or expose the services securely. A GitHub-hosted runner cannot reach them. |
| The Supabase/Postgres/Redis may be inside a six-hour Actions session | The supplied `DATABASE_URL` names `opendrive_app`, which matches the role created by the example `Supabase-Actions` workflow. That workflow runs Postgres and Redis inside `ubuntu-latest` and persists state through the Actions cache. | Move the services to a permanent host, or accept that they disappear when the job ends. A separate workflow cannot reach that job's loopback. |
| No Cloudflare zone or tunnel token | `.env` has the Cloudflare API token but no `CLOUDFLARE_TUNNEL_TOKEN` or dashboard hostname. The account has one tunnel named `supabase`, but it is **inactive**, has no connections, and has no ingress rules. The account has **zero zones**. | Add a zone/domain and a dashboard hostname. The supplied API token already has Tunnel Write, so a named tunnel and its token can be created; the public hostname still needs a zone. Alternatively use a non-Tunnel dashboard host. A quick `trycloudflare.com` URL is temporary and changes each run. |
| Supabase anon key reaches tables, not just Auth | `GET /rest/v1/` with the anon key returns `403 You cannot consume this service`, but table queries return `200`: `site_settings` returned one row, while `profiles`, `files`, `api_keys`, `user_premium`, `audit_events`, and `upload_sessions` returned zero rows. The `403` is an OpenAPI-root response, not a table authorization boundary. | Keep the service-role key server-side and do not ship a browser table client until RLS/grants are reviewed. If the public anon key should not read `site_settings`, revoke that grant or add RLS. A browser must never receive the service-role key. |
| Supabase keys do not match the published JWKS contract | The anon and service-role keys are **HS256**, `iss: supabase`, no `aud`. The JWKS publishes a single **ES256 P-256** key. The configured issuer URL and `authenticated` audience are not in those keys. | Verify dashboard sessions through Supabase `/auth/v1/user`, not by checking these keys against the JWKS. Do not build a local JWT verifier that assumes RS256/ES256 for the supplied keys. |
| No repository for this code | `GET /repos/apunabhibhilegendhai/discord-vanity-sniper` returns `404`. This workspace is not a Git repository. | Create/push a repository before any workflow can run. The supplied GitHub token can see `apunabhibhilegendhai/OpenDrive` and `apunabhibhilegendhai/Supabase-Actions`, but not a sniper repository. |

## 2. Credential verification

### 2.1 GitHub

| Check | Result |
|---|---|
| Token identity | `GET /user` → `200`; login `apunabhibhilegendhai` |
| Token scopes | Classic PAT with `repo`, `workflow`, `admin:org`, `admin:org_hook`, `admin:repo_hook`, `admin:public_key`, `admin:enterprise`, `admin:gpg_key`, `admin:ssh_signing_key`, `delete_repo`, `write:packages`, `delete:packages`, `audit_log`, `codespace`, `copilot`, `project`, `gist`, `notifications`, `user`, `write:discussion`, `write:network_configurations` |
| Repository visibility | 4 repositories returned: `apunabhibhilegendhai/OpenDrive`, `apunabhibhilegendhai/Supabase-Actions`, `lawdachuss/supabase-actions`, and private `lawdachuss/cam-clone-buddy` |
| Target example repo 1 | `lawdachuss/mercy-discord-bot` → `200`, public, default branch `master`, read permission |
| Target example repo 2 | `apunabhibhilegendhai/Supabase-Actions` → `200`, public, default branch `master`, admin permission |
| Sniper repo | `apunabhibhilegendhai/discord-vanity-sniper` → `404` |

The token is far more powerful than this deployment needs: its scopes include `delete_repo` and `admin:org`. It must not be used as a workflow runtime token. Use the built-in `GITHUB_TOKEN` with explicit `permissions` for CI and release, and keep this PAT out of repository files and workflow logs.

### 2.2 Vercel

| Check | Result |
|---|---|
| Identity | `GET /v2/user` → `200`; username `apunabhibhilegendhai`, user id present |
| Project visibility | `GET /v9/projects` → `200`; one project named `opendrive` |
| Implication | The token is authenticated and can see the `opendrive` project; no Vercel deployment was attempted. A Vercel function cannot reach `127.0.0.1` Postgres or Redis, so it could only use the public Supabase URL. |

Vercel is a viable **UI-only** fallback. It is not a host for the sniper, the local database, Redis, or a tunnel origin.

### 2.3 Supabase

The public URL answers: `GET https://supabase.opendrive.indevs.in/` returns `401` with `Server: cloudflare` and an `x-kong-request-id` header. That proves reachability, not authorization.

| Check | Result |
|---|---|
| JWKS endpoint | `200`; one key: `kty=EC`, `alg=ES256`, `use=sig`, `crv=P-256` |
| Anon key header | `HS256`, no `kid` |
| Service-role key header | `HS256`, no `kid` |
| Anon claims | `role=anon`, `iss=supabase`, no `aud`, `iat=1700000000`, `exp=2015360000` (2033-11-11) |
| Service-role claims | `role=service_role`, `iss=supabase`, no `aud`, `iat=1700000000`, `exp=2015360000` |
| Configured issuer/audience | `SUPABASE_JWT_ISSUER` is the project URL; `SUPABASE_JWT_AUDIENCE` is `authenticated` |
| Anon `GET /auth/v1/settings` | `200` |
| Anon `GET /rest/v1/` (OpenAPI root) | `403 You cannot consume this service` |
| Anon `GET /rest/v1/site_settings?select=*&limit=1` | `200`; one row returned |
| Anon `GET /rest/v1/{profiles,files,api_keys,user_premium,audit_events,upload_sessions}?select=*&limit=1` | `200` for each; zero rows returned (empty or RLS-filtered) |
| Service-role `GET /rest/v1/` | `200`; OpenAPI with 32 paths |
| Service-role `GET /auth/v1/admin/users` | `200`; the user list was returned (5 users at audit time) |
| Anon or service key as a user JWT on `/auth/v1/user` | `403 bad_jwt: invalid claim: missing sub claim` (expected: API keys are not user tokens) |
| OIDC discovery | `401` |

The supplied anon and service-role keys are **HS256-signed API keys** in Supabase's legacy JWT format. HS256 requires a shared signing secret; the public JWKS is an **ES256** verification key. They cannot be validated by feeding these HS256 tokens to that JWKS. The keys also do not carry the configured issuer URL or the `authenticated` audience.

Practical consequences:

- Use Supabase Auth for dashboard sign-in and validate the resulting user token with `GET /auth/v1/user`. Do not write a custom verifier that assumes the supplied anon/service keys match the JWKS.
- Do not put the service-role key in the browser. It bypasses RLS and returned an admin user list.
- The anon key is **not** blocked at the table layer. `/rest/v1/` is 403 because it is the OpenAPI root, but table queries return 200; `site_settings` returned one row and the other tested tables returned zero rows (empty or RLS-filtered). Treat the 403 as a root-endpoint fact, not an authorization boundary. Keep all dashboard data access server-side with the service-role key, and review RLS/grants before any browser table query.
- If the project intends to use asymmetric JWTs, rotate `JWT_SECRET` and the anon/service keys as a deliberate migration; that invalidates existing sessions. This pass does not change Supabase configuration.

### 2.4 Postgres and Redis

Both checks were run from this Windows workspace against the supplied URLs:

| Service | Address | Result |
|---|---|---|
| Postgres | `127.0.0.1:5432` | TCP connect failed: `ConnectionRefusedError` / WinError 10061 |
| Redis | `127.0.0.1:6379` | TCP connect failed: `ConnectionRefusedError` / WinError 10061 |

Because the TCP connection was refused, no authentication test was possible. This is a finding, not a pass.

Where a runner would have to live:

- **GitHub-hosted runner:** cannot reach these URLs. They are the runner's own loopback; another job is a different VM, and a workflow cannot join a previous job's network namespace.
- **Self-hosted runner on the same host:** can reach them if Postgres and Redis are listening on the host loopback. If they run in Docker with bridge networking, `127.0.0.1` may point at the runner container instead of the host; use a host-network runner, published ports, or the Docker service name on a shared network.
- **Dashboard in the same Actions job:** can reach them, but only until the job ends (six hours maximum). That is the pattern the `Supabase-Actions` workflow uses: Supabase, Postgres, and Redis are started inside `ubuntu-latest`, and state is restored from the Actions cache. It is not a permanent service.
- **Dashboard on Vercel or another machine:** cannot reach these URLs. It must use a public endpoint, which is not what was supplied.

The `opendrive_app` role name and the `Supabase-Actions` workflow's `Ensure the OpenDrive application role` step strongly suggest the URL was copied from that job's `.env`. If so, the database is session-local and the public URL is only as durable as that session's tunnel.

### 2.5 Cloudflare Tunnel capability

The existing Cloudflare API token was checked against the Tunnel APIs:

| Check | Result |
|---|---|
| Tunnel list | `200`; one tunnel named `supabase`, id present, status **inactive**, no connections, remote config true |
| Tunnel configuration | `200`; no ingress rules |
| Access applications | `403 access.api.error.not_enabled: Access is not enabled` |
| Zones | `200`; zero zones |
| Token permissions | Includes `Cloudflare Tunnel Read`, `Cloudflare Tunnel Write`, `Access: Apps Write`, `DNS Write` (zone), and related Zero Trust permissions |
| Tunnel token in `.env` | **Absent**. There is no `CLOUDFLARE_TUNNEL_TOKEN` or dashboard hostname. |

The token policy includes `Cloudflare Tunnel Write`/`Read`, so the token has permission to create one; this pass did not create a tunnel. That permission is not the same as a deployable tunnel. A **tunnel token** is the credential `cloudflared` uses, and a **public hostname** requires a domain in a Cloudflare zone plus a DNS record pointing at `<tunnel-id>.cfargotunnel.com`. The account currently has no zone.

Cloudflare's own guidance:

- Quick Tunnels create a temporary `trycloudflare.com` URL, require no account or domain, have no uptime guarantee, and **the hostname changes each time** they are created. They are for testing, not production. [Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)
- To publish a named application, the API guide says to add a website to Cloudflare, change nameservers to Cloudflare, create a tunnel, configure ingress, and create a CNAME to `<tunnel-id>.cfargotunnel.com`. It also requires a tunnel token to run `cloudflared`. [Create a tunnel (API)](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel-api/)

**Blocker:** no permanent dashboard link can be created from what was supplied. The user must provide:

1. A domain added to Cloudflare (with Cloudflare nameservers), or an already-working zone in this account.
2. A chosen dashboard hostname in that zone, e.g. `sniper.example.com`.
3. A tunnel token for the existing `supabase` tunnel, or use the supplied API token (Tunnel Write) to create a new named tunnel and capture its token. No tunnel token is in `.env`.
4. If login protection is wanted, Zero Trust Access enabled and an Access application/policy; Access is currently not enabled.

Without those, the only Tunnel option is a temporary quick tunnel, which is not a permanent link.

### 2.6 Credentials that must be rotated

All of these were pasted into chat and are now in `.env` only. Treat them as exposed:

| Credential | Why rotate |
|---|---|
| Cloudflare API token | Account-scoped policy including Tunnel Write and Access Write |
| GitHub PAT | Classic token with `repo`, `workflow`, `admin:org`, and `delete_repo` |
| Vercel token | Has access to the `opendrive` project; deployment was not attempted |
| Supabase service-role key | Bypasses RLS; returned admin user data |
| Postgres password embedded in `DATABASE_URL` | Shared in chat; grants `opendrive_app` access |
| Redis password embedded in `REDIS_URL` | Shared in chat; grants Redis access |
| Supabase anon key | Public by design, but shared; rotate with the JWT/key migration if the project treats it as compromised |

The Supabase JWT signing secret was not supplied. Rotating the anon/service keys may require rotating that secret and restarting Supabase, which invalidates existing sessions. Do that deliberately, not as part of a workflow run.

`.env` contains 13 keys: the three Cloudflare values from the previous plan plus the ten Supabase/GitHub/Vercel/Postgres/Redis values from this one. `.gitignore` already ignores `.env` and `.dev.vars`. No secret value belongs in this document or any tracked file.

## 3. GitHub Actions limits, quoted

These are the documented limits that decide the shape. They were checked against GitHub's docs on 2026-10-20.

### 3.1 Per-job and per-workflow time

GitHub Actions limits:

- “Each job in a workflow can run for up to **6 hours** of execution time” on **GitHub-hosted** runners.
- “Each job in a workflow can run for up to **5 days** of execution time” on **self-hosted** runners.
- “Workflow run time: **35 days / workflow run**.”
- “The job timeout for single-CPU runners is **15 minutes**.”

Sources: [Actions limits](https://docs.github.com/en/actions/reference/limits), [GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

The six-hour GitHub-hosted ceiling is the reason the reference workflows use `timeout-minutes: 355` or `360` and chain a successor. A chained session is still a sequence of short-lived VMs, not an always-on host.

### 3.2 A job is not an always-on host

From GitHub's runner documentation:

- “With the exception of single-CPU runners, each GitHub-hosted runner is a new virtual machine (VM) hosted by GitHub.”
- “GitHub will never require inbound connections to these machines.”
- GitHub-hosted runner IP ranges are numerous and dynamic; GitHub says it does “not recommend” using them as allowlists.
- The job filesystem is ephemeral; the docs say file paths on virtual machines are not static.

Sources: [GitHub-hosted runners](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners), [GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [Azure private networking](https://docs.github.com/en/organizations/managing-organization-settings/about-azure-private-networking-for-github-hosted-runners-in-your-organization).

There is no documented stable public URL for a job. The runner is a fresh VM (or, for `ubuntu-slim`, a fresh container) and GitHub requires only outbound communication. A gateway WebSocket, a 5 ms polling loop, and a warm TLS pool all die with the job.

### 3.3 Scheduled workflows

From GitHub's event documentation:

- “The shortest interval you can run scheduled workflows is once every **5 minutes**.”
- “Scheduled workflows run on the latest commit on the default branch.”
- “The `schedule` event can be delayed during periods of high loads... If the load is sufficiently high enough, some queued jobs may be dropped.”
- In a public repository, scheduled workflows are disabled after **60 days** without repository activity.

Source: [Events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).

A five-minute cron is not a 5 ms poller. A scheduled job also has no inbound URL, so it cannot be the dashboard server.

### 3.4 What the reference repositories actually demonstrate

The two supplied repositories were read at their default branches.

**`apunabhibhilegendhai/Supabase-Actions`** (`supabase-host.yml`, 1,333 lines):

- Runs the full Supabase stack in Docker on `ubuntu-latest`.
- Uses `timeout-minutes: 355`, leaving a five-minute buffer under the 360-minute hard limit.
- Runs an hourly `workflow_dispatch`/`schedule` at minute 23, with `concurrency` and `cancel-in-progress: false`.
- Starts `cloudflared` with `CF_TUNNEL_TOKEN` and retries with `--url http://localhost:8000` using the same token if ingress rules are missing; it parses a `trycloudflare.com` URL if one appears. It does not create a quick tunnel when the token is absent. It also downloads `bore` for a Redis TCP tunnel.
- Persists state through `actions/cache` archives, not a durable database.
- Self-dispatches the next run at the end because the six-hour session is ending.

This is a working example of **session chaining**, not a permanent backend. It also expects credentials the user did not supply: `CF_TUNNEL_TOKEN`, `CF_TUNNEL_DOMAIN` (a repository variable or secret), `POSTGRES_PASSWORD`, `JWT_SECRET`, and `DASHBOARD_PASSWORD`; `REDIS_PASSWORD` is optional and the workflow derives one if it is absent. Its `Ensure the OpenDrive application role` step creates `opendrive_app`, matching the supplied database user.

**`lawdachuss/mercy-discord-bot`** (`secure-rdp.yml`, 401 lines):

- Runs on `windows-latest` with `timeout-minutes: 360`.
- Has only `workflow_dispatch`; it deliberately avoids `schedule`.
- Uses `GITHUB_TOKEN` with `actions: write` to dispatch its successor.
- Uses Tailscale/RDP for access; no inbound runner URL.

This demonstrates the same ceiling from a different angle: a 360-minute job that re-queues itself. It is a remote session, not an always-on bot host.

Useful ideas to borrow: explicit `concurrency`, a timeout below the hard limit, and minimal `permissions`. Do not borrow cache-as-database, RDP/Tailscale, or self-dispatch as a substitute for an always-on host.

## 4. What can run where

| Piece | GitHub-hosted Actions | Self-hosted runner on always-on host | Always-on host (systemd) | Supabase | Vercel |
|---|---|---|---|---|---|
| Go build/test/vet | Yes | Yes | Yes | No | No |
| Go sniper process | Only as a short-lived 6-hour job | Yes, if installed as a service | **Yes** | No | No |
| Persistent gateway WebSocket | No | Yes, via service | **Yes** | No | No |
| 5 ms poller | No | Yes, via service | **Yes** | No | No |
| Raw TCP/uTLS claim path | Only inside the six-hour VM | Yes, via service | **Yes** | No | No |
| Proxy pools / warm sentries | Only for the job lifetime | Yes, via service | **Yes** | No | No |
| Vanity Guard reclaim/kick/ban | Only while job runs | Yes, via service | **Yes** | No | No |
| Dashboard server | Temporary at best | Yes, if installed as a service | **Yes** | No | Yes (UI only) |
| Dashboard behind Cloudflare Tunnel | No, no inbound | Yes, if tunnel token/domain exist | **Yes** | No | No |
| Postgres/Redis at `127.0.0.1` | Only inside the same job | Yes, if same host/namespace | **Yes** | No | No |
| Config edit + restart | No | Yes, through a host helper | **Yes** | Writes DB only | Writes DB only |
| Health/journald visibility | No | Yes, through a host sidecar | **Yes** | Stores events | Reads events |
| Scheduled health probe | Yes, 5-minute minimum | Yes | Yes | Probe target only | Not in this plan |

A Go binary can execute on an `ubuntu-latest` runner because the runner is a normal Linux VM with outbound networking. That does **not** make it a permanent host. The binary would lose its gateway, poller, warm pools, session state, and public identity when the job ends.

## 5. Only viable end-to-end shape

```text
GitHub (Actions)
  ├── ci.yml                 build / vet / test / tagged compile
  ├── release.yml            Linux binary artifact
  ├── deploy-sniper.yml      self-hosted runner: install + restart
  ├── deploy-dashboard.yml   self-hosted runner: build + restart
  └── migrate-supabase.yml   self-hosted runner: psql migrations
             |
             v
Always-on host
  ├── discord-sniper.service         Go binary, gateway, poller, claim, guard
  ├── sniper-dashboard.service       Next.js dashboard on 127.0.0.1:3000
  ├── sniper-config-sync.service     Supabase config -> config.json -> restart
  ├── sniper-health.service          journald -> Redis/Supabase health events
  ├── cloudflared.service            dashboard only, not Postgres/Redis
  ├── PostgreSQL :5432               local or reachable on this host
  └── Redis :6379                    local or reachable on this host
             |
             +--> https://supabase.opendrive.indevs.in (Auth/REST)
             +--> Cloudflare Tunnel hostname (dashboard)
```

Why a self-hosted runner:

- It is the only GitHub Actions runner that can be on the same host as `127.0.0.1` Postgres/Redis.
- It can install the binary and restart systemd without exposing SSH to GitHub-hosted IPs.
- The job itself is still short-lived; the sniper and dashboard are `systemd` services, not job processes.
- The runner must be treated as a production credential. Prefer an ephemeral runner, a dedicated host, environment approvals, and no pull-request jobs on that runner. A compromised self-hosted runner is a compromised host.
- The host needs `gh`, `rsync`, Node.js/npm, `psql`, `cloudflared`, `systemctl`, `systemd-journal` group membership for `journalctl`, and the narrow sudoers drop-in; register the `sniper-host` label. The deploy jobs do not install these.

If the user does not want a self-hosted runner, the deploy workflow must use SSH to the host with a dedicated deploy key and a restricted sudoers entry. That is still Actions-driven deployment, but the runtime is the host.

## 6. Implementation map

The six workflows, the `deploy/` layer, `dashboard/**`, and `supabase/migrations/0001_dashboard.sql` now exist in this repository. The remaining work is host provisioning, applying the migration, building the dashboard, and creating the Tunnel/DNS resources. Generated files such as `next-env.d.ts` are not listed.

| Path | Purpose |
|---|---|
| `.github/workflows/ci.yml` | Build, vet, test, and tagged compile on push/PR; no secrets |
| `.github/workflows/release.yml` | Build Linux amd64/arm64 binaries on a tag; upload artifacts/release |
| `.github/workflows/deploy-sniper.yml` | Self-hosted deploy of binary and systemd unit; protected environment |
| `.github/workflows/deploy-dashboard.yml` | Self-hosted build/deploy of the dashboard; protected environment |
| `.github/workflows/migrate-supabase.yml` | Self-hosted `psql` migration against the local Postgres only |
| `.github/workflows/health-check.yml` | Optional 5-minute public probe; no local DB/Redis access |
| `deploy/systemd/discord-sniper.service` | Runs the Go binary as an always-on service |
| `deploy/systemd/sniper-dashboard.service` | Runs the dashboard on `127.0.0.1:3000` |
| `deploy/systemd/sniper-config-sync.service` | Applies the active Supabase config to `config.json` |
| `deploy/systemd/sniper-config-sync.timer` | Polls for config changes every 30–60 seconds |
| `deploy/systemd/sniper-health.service` | Publishes heartbeat, last error, and applied config version |
| `deploy/systemd/cloudflared.service` | Runs the token-authenticated tunnel from a 0600 env file |
| `deploy/env/sniper.env.example` | Key names and non-secret defaults for the host |
| `deploy/env/dashboard.env.example` | Dashboard host env names; no secret values |
| `deploy/env/cloudflared.env.example` | Tunnel token file name and placeholder only |
| `deploy/scripts/install-host-deps.sh` | Read-only host/runner prerequisite check |
| `deploy/README.md` | Host user, directory, sudoers, env, and service setup order |
| `deploy/bin/sniper-config-sync` | Small host-side sync helper; writes config atomically and restarts the sniper |
| `deploy/bin/sniper-health` | Small host-side journald/health publisher |
| `deploy/bin/sniper-restart` | Narrow privileged helper for a fixed-unit restart |
| `deploy/sudoers/sniper-deploy` | Narrow sudoers drop-in for install, daemon-reload, and restart |
| `dashboard/package.json` | Next.js dashboard dependencies and scripts |
| `dashboard/package-lock.json` | Lockfile consumed by `npm ci` in build and deploy |
| `dashboard/tsconfig.json` | TypeScript configuration for the Next.js app |
| `dashboard/src/app/layout.tsx` | Dashboard shell |
| `dashboard/src/app/page.tsx` | Overview: process state, heartbeat, current targets |
| `dashboard/src/app/config/page.tsx` | Config editor with write-only secret fields |
| `dashboard/src/app/issues/page.tsx` | Health events, recent errors, last claim/guard events |
| `dashboard/src/app/api/config/route.ts` | Authenticated config read/write; server-side only |
| `dashboard/src/app/api/health/route.ts` | Authenticated health read |
| `dashboard/src/lib/supabase.ts` | Server-side Supabase client; service-role key never reaches the browser |
| `dashboard/src/lib/auth.ts` | Supabase session validation via `/auth/v1/user` |
| `dashboard/src/lib/validation.ts` | Strict config validation, secret merge/redaction, and error messages |
| `dashboard/src/lib/health.ts` | Missing/stale/degraded/ok health view (no direct process inspection) |
| `dashboard/src/lib/supabase-store.ts` | Server-only Supabase reads and the atomic `sniper_save_config` RPC |
| `supabase/migrations/0001_dashboard.sql` | Tables, indexes, RLS, and audit triggers |

The dashboard is a Next.js app because its server-side route handlers can hold the service-role key and it fits the supplied Vercel project. It is designed to run on the host, not on Vercel, because it needs loopback Postgres/Redis and filesystem/systemd access. Implementation notes, the route contract, and the local proof mode are in [../dashboard/README.md](../dashboard/README.md).

## 7. Workflow YAML shape

The following files now exist under `.github/workflows/`; these snippets reproduce their committed commands, with whitespace-only blank lines omitted. They use placeholders for hostnames and secret names; no credential belongs in YAML.

### 7.1 `ci.yml`

```yaml
name: CI
on:
  push:
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true
      - run: go build ./...
      - run: go vet ./...
      - run: go test -count=1 ./...
      - run: go test -tags=live -run '^$' ./...
      - run: go test -tags=realnet -run '^$' ./...
```

This workflow needs no secrets and must never run on the production self-hosted runner for pull requests.

### 7.2 `release.yml`

```yaml
name: Release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    strategy:
      matrix:
        goarch: [amd64, arm64]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true
      - run: |
          CGO_ENABLED=0 GOOS=linux GOARCH=${{ matrix.goarch }} \
            go build -ldflags="-s -w" -o sniper-linux-${{ matrix.goarch }} .
      - uses: actions/upload-artifact@v4
        with:
          name: sniper-linux-${{ matrix.goarch }}
          path: sniper-linux-${{ matrix.goarch }}
  release:
    needs: build
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: write
      actions: read
    steps:
      - uses: actions/download-artifact@v4
        with:
          path: dist
          merge-multiple: true
      - name: Publish release assets
        env:
          GH_TOKEN: ${{ github.token }}
          GH_REPO: ${{ github.repository }}
        run: |
          gh release create "${GITHUB_REF_NAME}" dist/* \
            --title "${GITHUB_REF_NAME}" --generate-notes
```

A release asset is not a deployment. `deploy-sniper.yml` downloads the named release asset; it does not use `download-artifact` across workflow runs, which only reads artifacts from the current run unless given an explicit run id.

### 7.3 `deploy-sniper.yml`

```yaml
name: Deploy sniper
on:
  workflow_dispatch:
    inputs:
      version:
        description: "Release tag (for example v1.2.3)"
        required: true
permissions:
  contents: read
concurrency:
  group: sniper-production
  cancel-in-progress: false
jobs:
  deploy:
    runs-on: [self-hosted, linux, x64, sniper-host]
    timeout-minutes: 15
    environment: production
    steps:
      - uses: actions/checkout@v4
      - name: Fetch release asset
        env:
          GH_TOKEN: ${{ github.token }}
          GH_REPO: ${{ github.repository }}
          VERSION: ${{ inputs.version }}
        run: |
          case "$VERSION" in
            v[0-9]*) ;;
            *) echo "::error::version must be a release tag such as v1.2.3"; exit 1 ;;
          esac
          mkdir -p ./artifact
          gh release download "$VERSION" \
            --pattern sniper-linux-amd64 --dir ./artifact
      - name: Stage binary and helpers
        run: |
          sudo install -d -m 0755 -o sniper -g sniper /opt/discord-sniper
          install -m 0755 ./artifact/sniper-linux-amd64 /opt/discord-sniper/sniper.new
          install -m 0755 deploy/bin/sniper-restart /opt/discord-sniper/sniper-restart
          install -m 0644 deploy/systemd/discord-sniper.service /opt/discord-sniper/discord-sniper.service
      - name: Install helper and unit
        run: |
          sudo install -m 0755 /opt/discord-sniper/sniper-restart /usr/local/sbin/sniper-restart
          sudo install -m 0644 /opt/discord-sniper/discord-sniper.service /etc/systemd/system/discord-sniper.service
          sudo systemctl daemon-reload
      - name: Install binary
        run: |
          sudo install -m 0755 /opt/discord-sniper/sniper.new /opt/discord-sniper/sniper
      - name: Restart and verify
        run: |
          sudo /usr/local/sbin/sniper-restart
          systemctl is-active --quiet discord-sniper.service
          journalctl -u discord-sniper.service -n 30 --no-pager
```

The `install` and `daemon-reload` commands are fixed-argument sudoers entries, not unrestricted `sudo`. The restart goes through `/usr/local/sbin/sniper-restart`, which restarts only `discord-sniper.service`; a raw `sudo mv` or `sudo systemctl restart` is deliberately absent because it cannot be constrained as narrowly. The production environment should require reviewers. The job does not run the sniper; it only stages, installs, and restarts the service.

### 7.4 `deploy-dashboard.yml`

```yaml
name: Deploy dashboard
on:
  workflow_dispatch:
  push:
    branches: [main, master]
    paths: ["dashboard/**"]
permissions:
  contents: read
concurrency:
  group: dashboard-production
  cancel-in-progress: false
jobs:
  deploy:
    runs-on: [self-hosted, linux, x64, sniper-host]
    timeout-minutes: 20
    environment: production
    steps:
      - uses: actions/checkout@v4
      - name: Require dashboard implementation
        run: |
          if [ ! -f dashboard/package.json ]; then
            echo "::error::dashboard/package.json is missing; the dashboard source was not checked out."
            exit 1
          fi
      - name: Build dashboard
        run: |
          cd dashboard
          npm ci
          npm run build
      - name: Install unit
        run: |
          install -d -m 0755 /opt/sniper-dashboard
          install -m 0644 deploy/systemd/sniper-dashboard.service /opt/sniper-dashboard/sniper-dashboard.service
          sudo install -m 0644 /opt/sniper-dashboard/sniper-dashboard.service /etc/systemd/system/sniper-dashboard.service
          sudo systemctl daemon-reload
      - name: Publish dashboard
        run: |
          rsync -a --delete dashboard/.next/ /opt/sniper-dashboard/.next/
          if [ -d dashboard/public ]; then
            rsync -a --delete dashboard/public/ /opt/sniper-dashboard/public/
          fi
          rsync -a dashboard/package.json dashboard/package-lock.json /opt/sniper-dashboard/
          cd /opt/sniper-dashboard && npm ci --omit=dev
          sudo systemctl restart sniper-dashboard.service
          systemctl is-active --quiet sniper-dashboard.service
```

This assumes the dashboard runs on the same host as Postgres/Redis. It does not deploy to Vercel. The job fails clearly if `dashboard/package.json` is missing, so a manual dispatch with an incomplete checkout cannot install an empty unit. Keep `next` (and anything the production server imports) in `dependencies`, not `devDependencies`, because the install step uses `npm ci --omit=dev`. The dashboard unit intentionally does not set `NoNewPrivileges=`, because the fixed `sniper-restart` helper runs through sudo and a setuid transition is required; the sudoers rule stays fixed-argument and fixed-unit. Provision `/opt/sniper-dashboard` writable by the runner user once, as in [../deploy/README.md](../deploy/README.md); the workflow only installs its unit and data through the narrow sudoers entries.

### 7.5 `migrate-supabase.yml`

```yaml
name: Migrate Supabase
on:
  workflow_dispatch:
permissions:
  contents: read
concurrency:
  group: supabase-migrations
  cancel-in-progress: false
jobs:
  migrate:
    runs-on: [self-hosted, linux, x64, sniper-host]
    timeout-minutes: 10
    environment: production
    steps:
      - uses: actions/checkout@v4
      - name: Require migration file
        run: |
          if [ ! -f supabase/migrations/0001_dashboard.sql ]; then
            echo "::error::supabase/migrations/0001_dashboard.sql is missing; the migration file was not checked out."
            exit 1
          fi
      - name: Apply migrations
        env:
          SUPABASE_DB_URL: ${{ secrets.SUPABASE_DB_URL }}
        run: |
          : "${SUPABASE_DB_URL:?missing SUPABASE_DB_URL}"
          psql "$SUPABASE_DB_URL" -v ON_ERROR_STOP=1 \
            -f supabase/migrations/0001_dashboard.sql
```

This cannot run on `ubuntu-latest`; the URL is `127.0.0.1`. It fails clearly until the dashboard migration exists. `SUPABASE_DB_URL` is a host-only secret and must be an environment-scoped secret with required reviewers, not a repository-wide secret exposed to every job.

### 7.6 `health-check.yml` (optional)

```yaml
name: Public health probe
on:
  schedule:
    - cron: "*/5 * * * *"
  workflow_dispatch:
permissions:
  contents: read
jobs:
  probe:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - name: Probe public Supabase
        env:
          SUPABASE_URL: ${{ vars.SUPABASE_URL || 'https://supabase.opendrive.indevs.in' }}
          SUPABASE_ANON_KEY: ${{ secrets.SUPABASE_ANON_KEY }}
        run: |
          : "${SUPABASE_ANON_KEY:?missing SUPABASE_ANON_KEY}"
          curl -fsS --max-time 15 \
            -H "apikey: ${SUPABASE_ANON_KEY}" \
            "${SUPABASE_URL}/auth/v1/settings" >/dev/null
```

This only proves the public Supabase Auth endpoint answers. It cannot see the host process, Postgres, Redis, or the dashboard. Do not give a scheduled GitHub-hosted workflow the service-role key. If DB health must be checked from Actions, use a dedicated read-only probe endpoint/role, not service_role.

## 8. Supabase schema and dashboard behavior

### 8.1 Tables

The migration should create, at minimum:

| Table | Purpose |
|---|---|
| `sniper_configs` | Versioned config documents, active flag, author, timestamps |
| `sniper_secrets` | Encrypted Discord token/TOTP/webhook values, referenced by config version |
| `sniper_admins` | Supabase user id to dashboard role; the authorization source of truth |
| `sniper_targets` | Guild id, expected vanity, enabled flag, display name |
| `sniper_audit` | Who changed what, before/after hashes, result, IP, timestamp |
| `sniper_health` | Heartbeat, process state, last error, last claim/guard event |
| `sniper_commands` | Optional queued restart/reload requests with state and expiry |

Use RLS deny-by-default. The dashboard server uses the service-role key; the browser never does. The anon key can query tables (200), even though `/rest/v1/` as the OpenAPI root is 403; `site_settings` exposed one row and the other tested tables returned zero rows (empty or RLS-filtered). A browser-side table client is therefore possible and unsafe by default: audit RLS/grants, and keep the dashboard's table access server-side.

### 8.2 Auth

- Browser: Supabase Auth with the anon key for sign-in only; do not use the anon key for table queries.
- Server: validate the user's access token with `GET /auth/v1/user`; do not verify the supplied HS256 API keys against the ES256 JWKS.
- Server data access: service-role key from a host environment file, never `NEXT_PUBLIC_*`, never a client bundle, never a workflow log.
- Encrypt secret fields with a host-only `CONFIG_ENCRYPTION_KEY` (32 bytes, 0600 env file); the key is never stored in Supabase, the browser bundle, or a workflow log. Rotation requires re-encrypting `sniper_secrets`. **Not implemented in the current dashboard pass:** config JSON is stored in `sniper_configs.config` because `sniper-config-sync` reads that shape; `sniper_secrets` is reserved, and the plaintext-at-rest gap is documented rather than hidden.
- Authorize by the explicit `sniper_admins` table, not just “any authenticated user.” The service-role key bypasses RLS, so the API route must enforce authorization itself.
- Bootstrap the first admin deliberately: after the operator's first Supabase sign-in, insert that user's `sub` into `sniper_admins` with a one-time service-role SQL/seed. Public sign-up must never grant admin.

### 8.3 Config sync

The Go binary has no HTTP config API and no hot reload. It reads `config.json` at startup and rewrites it when it mints a token. Therefore:

1. Dashboard validates the merged config and writes a new active `sniper_configs` version through `sniper_save_config`; it does not encrypt secret fields yet.
2. `sniper-config-sync.timer` polls the active version.
3. On a new version, it checks that the value is a JSON object, writes `config.json` atomically (`0600`), and calls the narrow restart helper.
4. Full Go-schema validation, health-gated rollback, and restore-on-failure in the sync helper are **not implemented**. If the restart fails, the state version is not advanced, so the timer retries; the previous file is not automatically restored.
5. The dashboard shows the stored version and the sidecar's `applied_config_version`, and reports `drift` when they disagree.

Do not give the dashboard root or unrestricted `systemctl`. The helper should accept only a validated config path/version and only restart the named unit.

### 8.4 Health and issues

The current binary has no HTTP stats server and no TUI (PRD FR-12). The dashboard cannot query internal counters directly. A host sidecar must:

- Check `systemctl is-active discord-sniper.service`.
- Read the last 100 `journalctl -u discord-sniper.service -o cat` lines for errors, claims, guard actions, and rate-limit messages; this is a polling sidecar, not a streaming JSON tail.
- Write a heartbeat to Redis with a short TTL and a durable health row to Supabase.
- Record status, last error, applied config version, and the last successful claim/guard timestamps when the sidecar can observe them. The current helper writes status, last error, and heartbeat, and publishes `applied_config_version` from `$STATE_DIR/config.version`, which `sniper-config-sync` updates only after a successful restart. The claim/guard timestamps remain nullable until a richer sidecar fills them.
- Compare the stored active version with the sidecar's applied version. When they differ the dashboard renders `drift` instead of `ok`, and names both versions. That is the visible evidence that config-sync has not applied the latest config; it does not attempt an automatic repair.

The dashboard distinguishes `missing`, `stale`, `degraded`, and `ok`. It cannot show the claimer's internal latency ring or goroutine state, and a missing health row is explicitly not treated as proof that the sniper is down.

### 8.5 Redis

Redis is useful for:

- A short-TTL heartbeat: `SET sniper:heartbeat <timestamp> EX 90`.
- A live status cache for the same-host dashboard.
- A queue for restart/reload commands, with idempotency keys.

Redis must not be exposed through the Tunnel. The dashboard server on the same host can reach it; Vercel cannot. If Redis is in Docker, use the compose service name or a host-network runner; do not assume `127.0.0.1` crosses container boundaries.

## 9. Cloudflare Tunnel deployment, once the missing inputs exist

### 9.1 Required inputs

- A Cloudflare-managed zone/domain. The account currently has none.
- A chosen dashboard hostname in that zone, e.g. `sniper.example.com`.
- A named tunnel token, or use the supplied API token (Tunnel Write) to create a new named tunnel and capture its token. The existing `supabase` tunnel is inactive and no token was supplied.
- Optional: Zero Trust Access enabled, with an Access application and policy. Access currently returns “not enabled.”

### 9.2 Exact commands after the inputs exist

Use the API token already supplied; do **not** put that API token in the `cloudflared` service. The API token creates the tunnel and its DNS record. The separate **tunnel token** (returned once when the tunnel is created) is what `cloudflared` runs with.

```bash
# Requires CLOUDFLARE_API_TOKEN with Cloudflare Tunnel Write and DNS Write,
# CLOUDFLARE_ACCOUNT_ID, a zone id, and a hostname that belongs to that zone.
curl -fsS -X POST \
  "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel" \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{"name":"sniper-dashboard","config_src":"cloudflare"}'
# Capture result.id (tunnel id) and result.token (tunnel token) from the response.

curl -fsS -X PUT \
  "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${TUNNEL_ID}/configurations" \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{"config":{"ingress":[{"hostname":"sniper.example.com","service":"http://127.0.0.1:3000"},{"service":"http_status:404"}]}}'

curl -fsS -X POST \
  "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{"type":"CNAME","name":"sniper.example.com","content":"'"${TUNNEL_ID}"'.cfargotunnel.com","proxied":true}'
```

Create the service account and put only the tunnel token in `/etc/cloudflared/tunnel.env` with mode `0600`:

```bash
id -u cloudflared >/dev/null 2>&1 || \
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin cloudflared
sudo install -d -m 0700 -o cloudflared -g cloudflared /etc/cloudflared
sudo install -m 0600 -o cloudflared -g cloudflared /dev/null /etc/cloudflared/tunnel.env
# Write CLOUDFLARE_TUNNEL_TOKEN into that file as root; never commit it.
```

```ini
CLOUDFLARE_TUNNEL_TOKEN=<tunnel-token-from-create-response>
```

Run it as `cloudflared.service`. This is a token-authenticated, remotely-managed tunnel, so there is no local ingress file and no `credentials-file`:

```ini
[Unit]
Description=Cloudflare Tunnel for sniper dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cloudflared
Group=cloudflared
EnvironmentFile=/etc/cloudflared/tunnel.env
ExecStart=/usr/local/bin/cloudflared tunnel --no-autoupdate run --token ${CLOUDFLARE_TUNNEL_TOKEN}
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

If you prefer a locally-managed tunnel instead, `cloudflared tunnel login` creates `cert.pem`, then `cloudflared tunnel create sniper-dashboard` writes a credentials JSON file and `cloudflared tunnel route dns` creates the CNAME. That is a different credential chain from the supplied API token; do not mix the two modes. The account currently has no zone, so the DNS request above cannot succeed until a zone exists.

### 9.3 If the domain/token cannot be supplied

- Use a **quick tunnel** only for a temporary test. Cloudflare says it has no uptime guarantee and the hostname changes each time; it is not a permanent link.
- Use **Vercel** for the UI if it only needs public Supabase. It cannot reach loopback Postgres/Redis and cannot restart the sniper.
- Use a **Cloudflare Worker** for a read-only status page, but it has the same no-raw-TCP/no-utls limitations described in [CLOUDFLARE_DEPLOYMENT.md](CLOUDFLARE_DEPLOYMENT.md).

There is no permanent Tunnel without a domain and a tunnel token.

## 10. What “deployed in GitHub Actions” can and cannot mean

### Can mean

- CI on every push/PR: build, vet, tests, tagged compile.
- Release artifacts for Linux.
- Actions-driven deployment to a self-hosted host: install binary, restart systemd, run migrations.
- Dashboard build/deploy to the same host.
- A five-minute public health probe.
- A six-hour, self-chaining session that runs a temporary stack, if the operator accepts the gaps and state loss.

### Cannot mean

- A 24/7 Go sniper with a persistent gateway WebSocket.
- A 5 ms poller.
- Warm TLS pools and pre-armed sentries across sessions.
- A stable public URL from a GitHub-hosted runner.
- A permanent dashboard with loopback Postgres/Redis access.
- A permanent Supabase/Postgres/Redis service created by a job.
- Vanity Guard that keeps defending while the job is queued or between chained sessions.

If the goal is “the sniper and Guard actually defend the vanity,” the process must run on an always-on host. Actions can deploy it; Actions cannot be it.

## 11. Prerequisites and next step

The workflow, deploy-script, dashboard, and migration layer is now written and locally verified. Before any live deployment:

1. **Move the runtime services to a permanent host.** Supabase, Postgres, and Redis need an always-on host or a managed service. If they remain inside a GitHub Actions job, the dashboard and sniper cannot survive the job.
2. **Make `DATABASE_URL` and `REDIS_URL` reachable from that host.** Use the host's loopback only if the dashboard and sniper are on the same host. Do not expose Postgres/Redis to the Internet; if remote access is required, use a private network or Tunnel with Access, not a public port.
3. **Supply the Tunnel inputs.** Add a domain to Cloudflare, choose the dashboard hostname, and create/reuse a named tunnel and capture its token. The supplied API token has Tunnel Write; no tunnel token is currently in `.env`. Enable Access if the dashboard is public.
4. **Create and push a repository.** The current workspace has no Git repository; `apunabhibhilegendhai/discord-vanity-sniper` does not exist. The supplied GitHub token has `repo` scope, the permission needed to create one, but this pass does not.
5. **Rotate every credential listed in §2.6** before using the host for production. The current `.env` is for local verification only.
6. **Decide dashboard placement.** Same host behind Tunnel is the only shape that can read Redis and restart the sniper without exposing either. Vercel is UI-only unless a host-side API is added.

The dashboard and migration exist; the next pass should provision the always-on host, apply `0001_dashboard.sql`, build the dashboard, register the runner, and create the named Tunnel/DNS records only after the domain and tunnel token are supplied. The host/runner setup order is in [../deploy/README.md](../deploy/README.md).

## 12. Sources

- [GitHub Actions limits](https://docs.github.com/en/actions/reference/limits)
- [GitHub-hosted runners](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners)
- [GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [Events that trigger workflows: schedule](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)
- [Azure private networking for GitHub-hosted runners](https://docs.github.com/en/organizations/managing-organization-settings/about-azure-private-networking-for-github-hosted-runners-in-your-organization)
- [Cloudflare Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)
- [Cloudflare Tunnel create (API)](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel-api/)
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)
- [Cloudflare Workers Free limits](https://developers.cloudflare.com/workers/platform/limits/)
- Reference workflows: [`lawdachuss/mercy-discord-bot`](https://github.com/lawdachuss/mercy-discord-bot), [`apunabhibhilegendhai/Supabase-Actions`](https://github.com/apunabhibhilegendhai/Supabase-Actions)
- Repo evidence: [PRD](PRD.md), [Cloudflare deployment plan](CLOUDFLARE_DEPLOYMENT.md), [Supabase-Actions adaptation](SUPABASE_ACTIONS_ADAPTATION.md), and the Go files cited there.
- Upstream: [`apunabhibhilegendhai/Supabase-Actions`](https://github.com/apunabhibhilegendhai/Supabase-Actions), `master` at `306437b`.
