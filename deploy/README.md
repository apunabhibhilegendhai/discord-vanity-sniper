# Host and runner prerequisites

This directory is the always-on host layer from
[../docs/GITHUB_ACTIONS_DEPLOYMENT.md](../docs/GITHUB_ACTIONS_DEPLOYMENT.md).
The dashboard lives in [`../dashboard`](../dashboard/README.md) and its schema is
[`../supabase/migrations/0001_dashboard.sql`](../supabase/migrations/0001_dashboard.sql).
Apply the migration and build the dashboard before enabling those services.

## 0. GitHub-hosted Actions sessions (no always-on host needed)

The primary deployment shape does not need this directory at all: one workflow
([../.github/workflows/sniper.yml](../.github/workflows/sniper.yml)) runs
everything on GitHub-hosted runners, and the sniper config lives in Supabase —
never in Action secrets.

1. Host or register a Supabase instance and apply
   [`supabase/migrations/0001_dashboard.sql`](../supabase/migrations/0001_dashboard.sql).
2. Repository secrets (Settings → Secrets and variables → Actions):
   - `SUPABASE_URL` — the instance base URL
   - `SUPABASE_SERVICE_ROLE_KEY` — server-side key, RLS denies anon/authenticated
   - `SUPABASE_ANON_KEY` — public heartbeat key (health mode only)
3. Push the active config document (Go `Conf` JSON shape, snake_case keys) as a
   new versioned row through either the dashboard or:
   ```bash
   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... \
     ./deploy/bin/sniper-config-push config.json
   ```
4. Start a session: **Actions → Sniper → Run workflow → mode `run`**. Sessions
   chain themselves (~345m each, dispatch of the successor just before exit,
   prevented from queueing twice while one is alive); a 6-hour watchdog cron
   restarts the chain if it ever breaks, and an unexpected mid-session exit
   chains a recovery session after a 5-minute cool-off.
5. Job logs are public on a public repository: run mode sets
   `SNIPER_REDACT_LOGS=1`, so the sniper masks guild ids, vanity codes, tokens,
   proxies and other config-borne credentials in its log output. Local runs keep
   full detail unless the same variable is set.

Note the environment the Actions runner provides: an ephemeral,
GitHub-egress-IP host with a cold connection pool and fresh gateway session per
session start (no resume across sessions), and Discord sees datacenter-range
IPs — expect a higher anti-abuse baseline than a residential host, and configure
proxies in the Supabase config document if that matters for your targets.

The remainder of this file documents the optional always-on host layer
(systemd + tunnel + health sidecar) that complements — or replaces — the
Actions-hosted sessions.

## 1. Host packages

The self-hosted runner and the host services need:

- `git`, `curl`, `jq`, `rsync`
- Node.js 20+ and `npm`
- `psql` (`postgresql-client`)
- `redis-cli` (`redis-tools`)
- `gh` (GitHub CLI)
- `cloudflared` in `/usr/local/bin` (the tunnel unit uses that path)
- `systemctl`, `journalctl`, and `sudo`

Run the read-only check:

```bash
./deploy/scripts/install-host-deps.sh
```

On Debian/Ubuntu, the common package set is:

```bash
sudo apt-get update
sudo apt-get install -y curl jq rsync postgresql-client redis-tools nodejs npm
# Install gh from https://github.com/cli/cli/blob/trunk/docs/install_linux.md

# Install the architecture-matching cloudflared binary. The unit expects
# /usr/local/bin/cloudflared; download the release asset for this host
# (linux-amd64 for the sniper-host runner label).
curl -fsSL -o /tmp/cloudflared \
  https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
sudo install -m 0755 /tmp/cloudflared /usr/local/bin/cloudflared
cloudflared --version
```

## 2. Dedicated user and directories

The host services run as `sniper`:

```bash
sudo useradd --system --create-home --home-dir /opt/discord-sniper \
  --shell /usr/sbin/nologin sniper
id -u cloudflared >/dev/null 2>&1 || \
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin cloudflared
sudo install -d -m 0755 -o sniper -g sniper /opt/discord-sniper
sudo install -d -m 0755 -o sniper -g sniper /opt/sniper-dashboard
sudo install -d -m 0700 -o sniper -g sniper /etc/discord-sniper
sudo install -d -m 0700 -o sniper -g sniper /etc/sniper-dashboard
sudo install -d -m 0700 -o sniper -g sniper /opt/discord-sniper/state
```

Register the self-hosted runner as this user with the labels
`self-hosted`, `linux`, `x64`, and `sniper-host`. The deploy jobs will not match
without `sniper-host`.

The runner also reads the service journal after a restart. Add it to the
`systemd-journal` group and restart the runner service so the new membership is
picked up:

```bash
sudo usermod -aG systemd-journal sniper
# Restart the runner service (name depends on how it was registered).
```

## 3. Install the narrow sudoers rule and helpers

```bash
sudo install -m 0440 deploy/sudoers/sniper-deploy /etc/sudoers.d/sniper-deploy
sudo visudo -cf /etc/sudoers.d/sniper-deploy
sudo install -m 0755 deploy/bin/sniper-restart /usr/local/sbin/sniper-restart
sudo install -d -m 0755 /usr/local/lib/sniper
sudo install -m 0755 deploy/bin/sniper-config-sync /usr/local/lib/sniper/sniper-config-sync
sudo install -m 0755 deploy/bin/sniper-health /usr/local/lib/sniper/sniper-health
```

The sudoers file permits only the fixed install paths, `daemon-reload`, and the
fixed-unit restart helper used by the deploy toolchain; it does not grant unrestricted
`sudo`. The dashboard unit and the sniper unit both use the same fixed
`daemon-reload` entry. The dashboard unit intentionally omits
`NoNewPrivileges=` because the restart helper needs a setuid sudo transition;
do not add it back unless that helper is replaced.

## 4. Environment files

```bash
sudo install -m 0600 -o sniper -g sniper \
  deploy/env/sniper.env.example /etc/discord-sniper/sniper.env
sudo install -m 0600 -o sniper -g sniper \
  deploy/env/dashboard.env.example /etc/sniper-dashboard/dashboard.env
sudo install -d -m 0700 -o cloudflared -g cloudflared /etc/cloudflared
sudo install -m 0600 -o cloudflared -g cloudflared \
  deploy/env/cloudflared.env.example /etc/cloudflared/tunnel.env
```

Fill in the real values, then copy the current `config.json` to
`/etc/discord-sniper/config.json` with mode `0600` owned by `sniper` until the
migration is applied and an active config row exists. The config sync expects
`sniper_configs.config` to be a JSON object matching the Go `Conf` schema;
secret-at-rest encryption is deferred.

## 5. Install and start the services

```bash
sudo install -m 0644 deploy/systemd/*.service deploy/systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload

sudo systemctl enable --now discord-sniper.service
sudo systemctl enable --now sniper-health.service
sudo systemctl enable --now cloudflared.service

# After applying the migration and building the dashboard:
sudo systemctl enable --now sniper-dashboard.service
sudo systemctl enable --now sniper-config-sync.timer
```

`cloudflared.service` skips itself until `/etc/cloudflared/tunnel.env` exists.
Build the dashboard once (`cd dashboard && npm ci && npm run build`) when
setting the unit up. The config-sync timer fails until `sniper_configs`
exists, so apply the migration first. `sniper-health` reads
`$STATE_DIR/config.version` and publishes it as `applied_config_version`, so keep
`STATE_DIR` pointing at the directory `sniper-config-sync` writes.

## 6. Tunnel

Follow the Cloudflare API steps in
[../docs/GITHUB_ACTIONS_DEPLOYMENT.md](../docs/GITHUB_ACTIONS_DEPLOYMENT.md#92-exact-commands-after-the-inputs-exist).
The tunnel token from the create response goes into
`/etc/cloudflared/tunnel.env`; never put the Cloudflare API token there.

## 7. What is intentionally deferred

- Secret-at-rest encryption: the dashboard writes config JSON in the shape
  `sniper-config-sync` expects, and `sniper_secrets` is reserved. The database
  still denies anon/authenticated access, but this is not encryption.
- Full Go-schema validation and rollback in `sniper-config-sync`: it checks only
  that the active value is a JSON object, then writes and restarts. The dashboard
  performs the strict validation before writing.
- A real health-gated restore path in the sidecar. The dashboard distinguishes
  missing, stale, degraded, and ok rows but does not repair them.

## 8. Dashboard build note

The dashboard package is under [`../dashboard`](../dashboard/README.md). Its
`next` dependency is a production dependency because the host install uses
`npm ci --omit=dev`; do not move it to `devDependencies`.
