# Discord Vanity URL Sniper

Single-binary Go sniper. The executable entrypoint is deliberately thin; all
runtime code is one implementation package so the claim hot path, gateway, and
tests can keep using unexported state without exporting an artificial API.

## Layout

```
main.go                  package main; calls sniper.Main()
internal/sniper/         all runtime code and tests (package sniper)
.github/workflows/       CI, release, deploy, migrate, and health workflows
deploy/                  host scripts, systemd units, sudoers, env examples
dashboard/               Next.js config/status dashboard and local proof mode
supabase/migrations/     dashboard schema, RLS, and atomic config activation
docs/PRD.md              requirements, architecture, and test inventory
docs/deep-research-report.md   source-level comparison with other snipers
docs/GITHUB_ACTIONS_DEPLOYMENT.md  Actions + self-hosted Supabase/Redis + Tunnel plan
docs/SUPABASE_ACTIONS_ADAPTATION.md  what was kept/changed/dropped from upstream
docs/CLOUDFLARE_DEPLOYMENT.md  Cloudflare Free feasibility (superseded direction)
```

## Where to look

| Concern | File(s) in `internal/sniper/` |
|---|---|
| Process startup, flags, token bootstrap | `run.go`, `orchestrator.go` |
| Claim hot path, response parsing, recovery, sentries | `claimer.go`, `prebuild.go` |
| Gateway WebSocket, resume, GUILD_UPDATE filter | `gateway.go` |
| REST poller fallback | `poller.go` |
| TLS dialing and proxy support | `tlsdial.go`, `pool.go` |
| MFA ticket solve and claim MFA | `mfa.go`, `login.go` |
| Session persistence | `session.go` |
| Vanity Guard / audit log / punishment | `guard.go` |
| Config schema, browser profiles, shared types | `config.go`, `fingerprint.go`, `types.go` |
| Rate limiting | `ratelimit.go` |
| Webhook notifications | `webhook.go` |
| Stats latency ring | `latency.go` |

The package boundary is intentionally coarse. Splitting `gateway`, `claim`,
`pool`, or `config` into separate packages would require exporting identifiers
that are currently internal, qualifying them across every caller and test, and
duplicating shared test helpers (for example `fakeConn`). That is a rewrite, not
a move, so those concerns stay in `internal/sniper` with their own files.

## Start here

- Requirements, architecture, configuration, and build/test commands:
  [docs/PRD.md](docs/PRD.md). The build and test sections are §13.
- Measurements and comparison with other snipers:
  [docs/deep-research-report.md](docs/deep-research-report.md).
- GitHub Actions deployment plan for the dashboard and host services, self-hosted
  Supabase/Redis facts, Cloudflare Tunnel permanent link, implemented file map,
  and the honest Actions-vs-always-on split:
  [docs/GITHUB_ACTIONS_DEPLOYMENT.md](docs/GITHUB_ACTIONS_DEPLOYMENT.md).
- Host and self-hosted-runner setup order: [deploy/README.md](deploy/README.md).
- Dashboard route contract, auth/RLS model, config validation, host-helper
  boundary, and local proof mode: [dashboard/README.md](dashboard/README.md).
- Dashboard schema and deny-by-default RLS:
  [supabase/migrations/0001_dashboard.sql](supabase/migrations/0001_dashboard.sql).
- Upstream Supabase-Actions inventory and the kept/changed/dropped/added record:
  [docs/SUPABASE_ACTIONS_ADAPTATION.md](docs/SUPABASE_ACTIONS_ADAPTATION.md).
- Cloudflare Free deployment feasibility and the boundary between a
  Cloudflare-only monitor and the full Go runner (earlier direction, now
  superseded): [docs/CLOUDFLARE_DEPLOYMENT.md](docs/CLOUDFLARE_DEPLOYMENT.md).
