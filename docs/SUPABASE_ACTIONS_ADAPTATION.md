# Supabase-Actions adaptation

**Source:** public repository `apunabhibhilegendhai/Supabase-Actions`, default
branch `master`, commit `306437b186a32591d271c9a03579c6e0b90ec84e`, cloned
read-only into a scratch directory outside this workspace.

This document records what the upstream repository actually contains and what
this repository kept, changed, dropped, or added while implementing the
workflow, deploy-script, dashboard, and migration layer. It does not claim a
deployment.

## 1. Upstream inventory

The upstream is a single-workflow Supabase host for GitHub-hosted runners, not a
self-hosted-runner project.

| Area | Upstream contents |
|---|---|
| Workflow | `.github/workflows/supabase-host.yml`, 1,333 lines, `runs-on: ubuntu-latest`, `timeout-minutes: 355` |
| Triggers | `workflow_dispatch` plus an hourly `schedule` at minute 23; `concurrency: supabase-host` with `cancel-in-progress: false` |
| Runner | GitHub-hosted `ubuntu-latest`; passwordless sudo; Docker; installs `cloudflared` and `bore` into `/usr/local/bin`; uses `/var/run/docker.sock` |
| Supabase | Full Docker Compose stack under `supabase/`, including Postgres, Auth, REST, Realtime, Storage, Studio, pooler, Redis, logs, and migrations |
| State | Restores and saves a full-state archive through `actions/cache`; state is not a durable external database |
| Tunnel | `cloudflared tunnel --no-autoupdate run --token "$CF_TUNNEL_TOKEN"`; retries with `--url http://localhost:8000` using the same token if ingress is missing; parses a `trycloudflare.com` URL if one appears, but does **not** create a quick tunnel when the token is absent |
| Extra tunnels | Root scripts `pg-tunnel.sh` and `redis-tunnel.sh` for manual TCP access through Cloudflare Access; root scripts `remote.sh`, `run.sh`, `reset.sh` for Compose and migration control |
| Chaining | End-of-run self-dispatch, plus `worker/workflow-watchman` (Cloudflare Worker, one-minute cron) to restart a dead session |
| Migrations | 14 files in `supabase/migrations/` spanning `001-...` through `104-...` (not sequential), plus `supabase/utils/` helpers |

### 1.1 Upstream file disposition

| Upstream path | Disposition | Reason |
|---|---|---|
| `.github/workflows/supabase-host.yml` | Rewritten as six workflows | Its six-hour, self-chaining job cannot host a 24/7 gateway or dashboard ([deployment plan §5](GITHUB_ACTIONS_DEPLOYMENT.md#5-only-viable-end-to-end-shape)); CI, release, deploy, migrate, and probe have different lifetimes |
| `supabase/docker-compose.yml`, `docker-compose.redis.yml`, `docker-compose.logs.yml`, `supabase/.env.example` | Dropped | This design assumes Postgres/Supabase and Redis already run on the always-on host; Actions does not manage their lifecycle |
| `supabase/migrations/001-...` through `104-...`, `supabase/migrations/README.md` | Dropped for this pass | They are the upstream OpenDrive application schema, not this sniper's tables; `supabase/migrations/0001_dashboard.sql` is a separate dashboard deliverable |
| `supabase/utils/add-new-auth-keys.sh`, `check-email-status.sql`, `cloudflare-backup.sh`, `confirm-all-users.sql`, `gen-token.py`, `generate-keys.sh`, `prune-caches.sh`, `snapshot-state.sh` | Dropped | OpenDrive/Supabase session helpers tied to the Compose stack and its cache backup, neither of which exists here |
| `run.sh`, `reset.sh`, `remote.sh` | Dropped | Remote Compose and migration control is replaced by host-owned systemd services and the guarded migration workflow |
| `pg-tunnel.sh`, `redis-tunnel.sh` | Dropped | Publishing Postgres/Redis through the Tunnel contradicts the dashboard-only ingress in [deployment plan §9](GITHUB_ACTIONS_DEPLOYMENT.md#9-cloudflare-tunnel-deployment-once-the-missing-inputs-exist) |
| `worker/workflow-watchman/` (`src/index.js`, `wrangler.toml`, `package.json`, `.dev.vars.example`) | Dropped | There is no six-hour session to watch; systemd restart policies and the health sidecar cover the always-on host |
| `supabase/volumes/` | Dropped | Runtime volume placeholders belong on the host, not in this repository |
| `README.md`, `.gitignore` | Not copied | The upstream README documents the Compose session; this repository keeps its own README and ignore rules |

### Secret and variable names observed

The workflow references:

`CF_TUNNEL_TOKEN`, `CF_TUNNEL_DOMAIN`, `POSTGRES_PASSWORD`, `JWT_SECRET`,
`DASHBOARD_PASSWORD`, `REDIS_PASSWORD`, `OPENDRIVE_APP_PASSWORD`,
`CLOUDFLARE_BACKUP_TOKEN`, `CF_BACKUP_ACCOUNT_ID`, `CF_BACKUP_KV_NAMESPACE_ID`,
`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_ADMIN_EMAIL`,
`SMTP_SENDER_NAME`, `GOOGLE_CLIENT_ID`, `GOOGLE_SECRET`, `GITHUB_CLIENT_ID`,
and `GITHUB_SECRET`.

`CF_TUNNEL_DOMAIN`, `CF_BACKUP_ACCOUNT_ID`, and `CF_BACKUP_KV_NAMESPACE_ID` are
read as repository variables with secret fallbacks. `REDIS_PASSWORD` is
optional; the workflow derives one when it is absent. The worker expects
`GITHUB_TOKEN` and optionally `DISCORD_WEBHOOK_URL` and `DASHBOARD_TOKEN`.

## 2. What this repository kept

- From `.github/workflows/supabase-host.yml`, the Cloudflare Tunnel pattern: a
  named tunnel token is the credential `cloudflared` runs with; the API token is
  not placed in the tunnel service.
- From the same workflow, explicit `concurrency`, a timeout below the
  GitHub-hosted limit, and minimal workflow permissions.
- From its health-check loop, the idea of an off-host health probe, without the
  six-hour session chain; the restart path itself is replaced by systemd and
  the fixed-unit helper.
- The upstream secret vocabulary that still describes the same inputs
  (`POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `JWT_SECRET`) as documentation only.
  This repository does not read those names directly: it uses `DATABASE_URL`,
  `REDIS_URL`, and the Supabase variables. The tunnel token is
  `CLOUDFLARE_TUNNEL_TOKEN` in the host unit. This pass creates no repository
  secrets.

## 3. What this repository changed

| Upstream | This repository |
|---|---|
| Supabase/Postgres/Redis run inside `ubuntu-latest` | They are assumed to run on the always-on host; the workflows deploy to a self-hosted runner labeled `sniper-host` |
| One 1,333-line session workflow | Six small workflows: CI, release, deploy sniper, deploy dashboard, migrate, health probe |
| `actions/cache` is the database | No cache-as-database; the host owns Postgres/Redis and the config file |
| `sudo` and Docker are assumed on the runner | Runner prerequisites are explicit; deploy commands use a narrow sudoers drop-in |
| `set -uo pipefail` appears only near the end of the long session | Every host script starts with `set -euo pipefail` and fails on the first unhandled error |
| Cloudflare Tunnel exposes the whole Supabase stack | The tunnel exposes only the loopback dashboard; Postgres and Redis are not published |
| Self-dispatch/watchman keep a six-hour session alive | systemd keeps the sniper, dashboard, config sync, health sidecar, and tunnel running |
| Workflow applies Supabase migrations itself | Migration is a separate manual workflow and is guarded until the dashboard migration exists |
| Runner installs `cloudflared` and `bore` on every session | Host installs `cloudflared` once; `bore` is dropped |

## 4. What this repository dropped

- The full `supabase/docker-compose*.yml` stack; this repository assumes the
  self-hosted Supabase/Postgres/Redis already exists.
- `run.sh`, `reset.sh`, `remote.sh`, `pg-tunnel.sh`, and `redis-tunnel.sh`.
  Publishing Postgres/Redis through the tunnel contradicts the deployment
  design; the dashboard is the only tunneled service.
- The `workflow-watchman` Cloudflare Worker. There is no six-hour session to
  watch.
- `actions/cache` snapshots, `bore`, session self-dispatch, and the upstream
  migration inventory.
- The upstream's six-hour runner assumptions: `ubuntu-latest`, Docker socket,
  passwordless sudo, and per-session binary installs.

## 5. What this repository added

- Six workflow files under `.github/workflows/`.
- `.github/actionlint.yaml`, which declares the custom `sniper-host` runner label so actionlint validates the workflows without an ignore flag.
- A host-side deploy layer under `deploy/`:
  - `bin/sniper-restart` — root-only fixed-unit restart.
  - `bin/sniper-config-sync` — fetches the active Supabase config and writes
    `config.json` atomically.
  - `bin/sniper-health` — systemd status, journal errors, Redis heartbeat, and
    optional Supabase health upsert.
  - `systemd/` units for the sniper, dashboard, config sync, health, and
    Cloudflare Tunnel.
  - `sudoers/sniper-deploy` — narrow install/restart entries.
  - `env/*.env.example` — key names only, no secret values.
  - `scripts/install-host-deps.sh` — read-only prerequisite check.
  - `README.md` — host and runner setup order.
- A Next.js dashboard under `dashboard/` with an authenticated route contract,
  server-side service-role access, strict config validation, redacted secret
  reads, and the fixed-unit restart helper boundary.
- `supabase/migrations/0001_dashboard.sql` with versioned configs, admins,
  audit, health, the optional command queue, and deny-by-default RLS.
- A documentation split: this adaptation record, the deployment plan, the
  dashboard contract, and the existing Cloudflare feasibility record.

## 6. Explicitly deferred

- Secret-at-rest encryption. The dashboard writes config JSON in the shape
  `sniper-config-sync` expects; `sniper_secrets` is reserved. Database access is
  still deny-by-default for anon/authenticated, but the config value is not
  encrypted.
- Full Go-schema validation, health-gated rollback, and restore-on-failure in
  `sniper-config-sync`. The dashboard validates before writing; the sync helper
  checks only that the active value is a JSON object.
- A richer health sidecar that fills `last_claim_at` and `last_guard_at`. The
  current helper writes status, last error, heartbeat, and whatever applied
  version the operator/host supplies.
- Any live deployment, repository secret, tunnel, DNS record, database, or
  Cloudflare resource.
