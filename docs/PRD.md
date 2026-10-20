# Product Requirements Document: Discord Vanity URL Sniper

## Version 1.3

### Changelog (1.2 → 1.3)

| Area | Change |
|---|---|
| Accuracy | Audited every performance and architecture claim against the current code. Corrected fingerprint, header, proxy, rate-limit, session, duplicate-event and polling claims; labeled unmeasured non-functional targets; refreshed measured values from the current harnesses. |

---

## 1. Executive Summary

A high-performance, low-latency Discord vanity URL sniper written in Go. The system monitors target guilds via the WebSocket gateway, with a gated REST poller as backup, and claims with pre-warmed TLS connections and a cached MFA token. The hot path is designed to avoid JSON encoding and header construction between wake and write; no allocation assertion currently enforces a zero-allocation claim path.

Recent local runs of `hotpath_test.go` (fake warm sockets, HPC clock, n=300/200) produced free→wire p50 **0.8–2.1µs**, availability-channel→wire p50 **2.8–8.9µs**, and five-sentry burst first-wire p50 **2.2–6.9µs**; run-to-run variance on this host is large. The tagged `realnet` harness measured the network floor on 2026-10-20: TCP connect p50 **102.6ms**, TLS total p50 **114.3ms**, and warm `GET /api/v9/gateway` TTFB p50 **52.1ms** (n=10 each). These are local spans; they exclude Discord queueing and do not prove claim acceptance. NFR-01 carries the end-to-end target and its evidence limits.

## 2. Core Requirements

### 2.1 Functional Requirements

| ID | Requirement | Priority |
|---|---|---|
| FR-01 | Monitor multiple guilds simultaneously | P0 |
| FR-02 | Detect vanity URL changes via Gateway WebSocket push | P0 |
| FR-03 | Claim available vanity URLs via PATCH endpoint | P0 |
| FR-04 | TOTP-based MFA for claims (optional password fallback if configured); optional email/password + TOTP auto-login can mint a fresh token | P0 |
| FR-05 | Support HTTP/SOCKS5 proxies | P0 |
| FR-06 | Pre-warm TLS connections so a burst normally pays no handshake (falls back to a synchronous dial when a pool is empty or stale) | P0 |
| FR-07 | Backup detection via a gated REST poller (5ms cycle target from request start, one observation per RTT) | P0 |
| FR-08 | Guard mode: re-claim if vanity is lost post-claim | P0 |
| FR-08a | Multi-IP burst: partition sentries round-robin across proxy pools; all pools fire when `burst_count` covers the proxy count, otherwise only the first `burst_count` pools fire (WS2) | P0 |
| FR-08b | Guard offender quarantine: audit-log lookup + kick/ban, owner-whitelisted (WS3) | P1 |
| FR-08c | Byte-scan vanity filter on GUILD_UPDATE to skip unmarshal for non-vanity edits (WS4) | P1 |
| FR-09 | Discord webhook notifications (startup, claim/re-claim, loss, guard actions, shutdown) | P1 |
| FR-10 | Gateway session resume (avoid re-authentication) | P1 |
| FR-11 | Rate limit tracking (header parsing, Retry-After, global flag, one retry bucket per guild; scope is parsed but not used to partition buckets) | P1 |
| FR-12 | Process-level stats counters (checks, claims, errors, latency) printed as a periodic terminal stats line and included in the shutdown webhook. No TUI or HTTP stats server in the Go binary. A separate Next.js config/status dashboard exists outside the binary; it reads host-side config and health rows and never exposes process internals. | P2 |

### 2.2 Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR-01 | End-to-end claim latency | **Target only; not measured.** Recent local free→wire p50 is 0.8–2.1µs, while the latest realnet TTFB p50 was 52.1ms. Claim-to-200 was not measured; there is no fixed 55.9ms reference and no evidence that 50ms is reachable from this host's current network path. |
| NFR-02 | Detection latency | **Measured locally:** raw GUILD_UPDATE frame scan **0.68–2.9µs/op, 3 allocs**; full envelope+payload JSON decode **15.8–59µs, 15 allocs** across recent runs. Poller observes once per RTT on links slower than its 4–6ms jittered floor. |
| NFR-03 | Concurrent targets | **Target: 100+ per instance. Not measured and not enforced.** The default suite exercises 3 concurrent targets. |
| NFR-04 | Uptime | **Target: 99.9% via gateway RESUME. Not measured.** RESUME and the 3-attempt fallback are implemented. |
| NFR-05 | Zero-allocation hot path | **Target: zero allocations in the steady-state claim path. Not measured.** No allocation assertion exists. |
| NFR-06 | Binary size | **Measured on this host:** 7,904,768 bytes (~7.9MB) for a `CGO_ENABLED=0` Windows amd64 build with `-ldflags="-s -w"`. Under the 15MB target. |
| NFR-07 | Session start consumption | **Target: ~1/day per target; not measured.** RESUME is used when a session exists. |

## 3. Architecture

### 3.1 Component Overview

The executable entrypoint is the root `main.go`; it only calls
`sniper.Main()`. Every implementation file named below lives in
`internal/sniper/` unless a full path says otherwise.

```
main.go (root) → internal/sniper/run.go → orchestrator.go → [target goroutines]
                                ├── gateway.go (WebSocket monitor)
                                │     └── byte-scan vanity filter (WS4)
                                ├── poller.go (gated REST backup)
                                ├── claimer.go (claim hot path)
                                │     ├── pre-armed sentry workers (WS1)
                                │     └── reclaim() → guard.Quarantine() (WS3)
                                ├── guard.go (audit-log lookup + kick/ban cascade)
                                ├── mfa.go (TOTP generator)
                                ├── pool.go (TLS connection pool) × N proxies (WS2)
                                ├── prebuild.go (pre-built requests)
                                ├── ratelimit.go (throttle)
                                └── webhook.go (alerts)
```

### 3.2 Detection Strategy

- **Primary**: Gateway WebSocket `GUILD_UPDATE` events (instant push)
- **Fast filter (WS4)**: every GUILD_UPDATE is `bytes.Contains`-scanned for
  `vanity_url_code` *before* any JSON unmarshal. A GUILD_UPDATE without that key
  is fully handled from the bytes, so the claimer is not woken. The repo has no
  dataset measuring the fraction of real GUILD_UPDATEs that omit the key;
  NFR-02 carries the measured scan cost.
- **Backup**: Gated REST poller (`poller.go`). It feeds the same `available`
  channel and `vanityFree` decision as the gateway; a gateway `RESUMED` also
  triggers one REST verification check. Gating and cadence are in §7.

### 3.3 Claim Strategy

**Pre-armed sentry workers (WS1):** Instead of spawning a worker per burst, the
claimer arms `burst_count` persistent "sentry" goroutines once the claim
template is built. Each sentry owns one warm TLS conn and blocks on a broadcast
`fire` channel. The hot path on a claim event is:

1. Publish pre-built PATCH bytes once (`atomic.Pointer[[]byte]` store).
2. Send one token to each sentry's buffered wake channel → the sentries wake
   (the channel is not closed; it is reused for every burst).
3. Each sentry: `atomic.Load` → `conn.Write`. In steady state there is no lock,
   probe, spawn, or template build between wake and wire. A conn held longer
   than 10s is refreshed through `pool.Get` before the write, and an empty pool
   falls back to a synchronous warm-up dial.

**Multi-IP burst (WS2):** Sentry workers are partitioned round-robin across
**one warm pool per configured proxy entry**. Each pool has its own rewarmer so
a burst that drains one pool doesn't force a synchronous TLS handshake on the
next burst's hot path. When `N` entries are configured and `burst_count >= N`,
the burst fires from all `N` entries at once. `burst_count` is the hard cap on
simultaneous PATCH writes: with `burst_count < N`, sentries are assigned
round-robin to pools `0..burst_count-1` and the remaining pools never fire.

`pools[0]` is the direct pool **only when the first proxy entry is `""`**. When
`proxies` is omitted, config injects `[""]`, so direct-only is the default. An
explicit non-empty proxy list does not receive an implicit direct pool; the
first entry is whatever the operator wrote. Include `""` as the first entry to
keep a direct lane.

**Other claim-strategy details:**

- The cached MFA JWT is spliced into the pre-built PATCH header at publish time, not generated per wire write
- First 200/204 response wins; remaining sentries drain (buffered send, no
  deadlock) and report their result so the burst count is correct.

## 4. API Endpoints Used

| Endpoint | Method | Purpose |
|---|---|---|
| `wss://gateway.discord.gg/?v=10&encoding=json` | WS | Receive real-time events (fixed URL; `/gateway` is not called by the sniper) |
| `GET /api/v9/guilds/{id}/vanity-url` | GET | Verify current vanity code (gateway `RESUMED` backup and poller) |
| `PATCH /api/v9/guilds/{id}/vanity-url` | PATCH | Claim vanity URL |
| `PATCH /api/v9/guilds/{id}` | PATCH | Legacy fallback when the vanity-url endpoint responds 404/405 |
| `GET /api/v9/users/@me` | GET | Validate a cached token before use; 2xx means usable |
| `POST /api/v9/auth/login` → `POST /api/v9/auth/mfa/totp` | POST | Optional startup token recovery (email + password + TOTP) |
| `POST /api/v9/mfa/finish` | POST | Action-elevation MFA for the claim (TOTP, optional password fallback) |
| `GET /api/v9/guilds/{id}/audit-logs?action_type=1&limit=5` | GET | Vanity Guard: identify offender of unauthorized vanity change (WS3) |
| `PUT /api/v9/guilds/{id}/bans/{uid}` | PUT | Vanity Guard: ban the offender (action=`ban`) (WS3) |
| `DELETE /api/v9/guilds/{id}/members/{uid}` | DELETE | Vanity Guard: kick the offender (action=`kick`, or ban→kick degrade) (WS3) |

## 5. MFA Handling

- **Claim MFA**: `POST /api/v9/mfa/finish` with a TOTP code; if a password is configured, a password body is tried as a fallback (one extra request)
- Optional `email` + `password` + `totp_secret` in config can mint a fresh user token through `/auth/login` → `/auth/mfa/totp` at startup; this is token recovery, not the claim MFA path
- Secret stored in config as base32
- The claim path does **not** generate a TOTP per fire. The solved MFA JWT is cached and spliced into the pre-built PATCH bytes; expiry is handled by the existing 401/challenge retry path

## 6. Session Reuse

- Gateway: Save `session_id`, `resume_url`, and a coalesced sequence checkpoint on READY
- On disconnect: RESUME (opcode 6) — consumes no session start limit
- After 3 failed resumable replies: fall back to fresh IDENTIFY. The attempt counter persists across `listen` reconnects and resets on a successful dispatch or a fresh identify
- Session state persisted to disk for crash recovery
- READY also captures the token owner's `user.id` into `Target.ownerID`, which the
  Vanity Guard whitelist reads (under the target mutex) so a legitimate change by
  the operator's own account is never punished.

## 7. Detection Backup: Gated Poller

- The gateway is the primary trigger; the poller is the backup for missed or
  delayed events.
- `startPoller` is gated on the claim template being built, so a lane never polls
  before it is armed.
- One persistent TLS socket, one GET in flight at a time, 5ms cycle target
  measured from request start with ±1ms jitter. The real cadence is one
  observation per RTT on links slower than the 4–6ms jittered floor; the 5ms
  target only binds on faster links. NFR-01 carries the current network floor.
- Poller and gateway share `available` and `vanityFree`; whichever observes first
  wins.
- There is no grace tracker and no grace burst. A legacy `grace_end` key in an
  existing config is ignored on load and does not fail startup.

## 8. Rate Limiting

Implemented:

- Parse `X-RateLimit-Limit`, `Remaining`, `Reset`, `Scope`, `Global`, and `Retry-After` headers
- Keep one retry bucket keyed by target guild id; share the global flag across targets
- On `429`, retry up to 3 times with backoff; a direct global `429` pauses the direct pool for 60s
- `scope` is parsed and stored but not used to partition buckets

Not implemented (despite earlier drafts describing them):

- Separate `user` (per-token), `shared` (per-guild), and `global` bucket types
- An IP-level invalid-request counter or 10k-invalid/10min self-throttle

## 9. Vanity Guard

Vanity Guard (FR-08) keeps defending a vanity *after* the first successful claim.
Without it, a competitor who steals the vanity back is never re-claimed (the
original behavior silently dropped every availability signal once `claimed` was
set). With it on, a GUILD_UPDATE showing the guild's vanity is no longer ours
triggers a reclaim burst.

### 9.1 Reclaim burst

On a loss signal, the claimer runs up to `guard_reclaim_max` bursts, each firing
up to `burst_count` sentries with whatever MFA token is cached, paced by
`guard_reclaim_backoff_ms`. A successful re-claim resets the attempt counter
(the cap applies *per loss episode*, not per session). If the cap is exhausted
without recovery, the target is marked `lost` and further signals are dropped to
avoid webhook spam and rate-limit burnout.

### 9.2 Offender quarantine (WS3)

In parallel with the very first reclaim burst (episode start), the guard runs a
**quarantine cascade** in its own goroutine so it never delays the snipe:

1. `GET /guilds/{id}/audit-logs?action_type=1&limit=5` → find the most recent
   GUILD_UPDATE whose `changes` include a `vanity_url_code` key; that entry's
   `user_id` is the offender.
2. **Whitelist check:** if the offender is the token owner (captured from the
   READY event into `Target.ownerID`) or in `guard_protected_user_ids`, skip
   punishment (a legitimate change by the operator or a trusted admin must never
   trigger a self-kick/self-ban).
3. **Punish** per `guard_action`:

   | `guard_action` | Sequence | On 403 |
   |---|---|---|
   | `reclaim_only` (default) | revert only, no punishment | n/a |
   | `kick` | `DELETE /guilds/{g}/members/{uid}` | log + rely on revert |
   | `ban` | `PUT /guilds/{g}/bans/{uid}` | degrade to `kick` |

A 403 (offender outranks the sniper account, or is the owner) is logged and the
revert is relied on — quarantine is best-effort; the reclaim burst is the
authoritative defense. Each landed kick/ban fires a webhook and bumps
`Quarantines`; a 403 or failure bumps `QuarantineFails` so the operator sees the
guard couldn't neutralize the offender.

### 9.3 Guard counters

| Stat | Meaning |
|---|---|
| `Claims` | first-time claims landed |
| `Reclaims` | successful re-claims after a loss |
| `Losses` | episodes where the reclaim cap was exhausted without recovery |
| `Quarantines` | kick/ban landed on an offender |
| `QuarantineFails` | 403 hierarchy block or other failure; revert was relied on |

Reclaims/losses/quarantines/quarantineFails are surfaced in the shutdown webhook
when guard was active this session.

## 10. Security & Detection Avoidance

- TLS fingerprint: uTLS `HelloChrome_Auto` (default profile) with ALPN forced to HTTP/1.1. The HTTP headers describe Chrome 143 but the ClientHello is uTLS's auto Chrome preset, not a pinned Chrome 143 capture. `firefox` selects `HelloFirefox_Auto`.
- Sec-CH-UA: **not sent.** No `sec-ch-ua`, `Sec-Fetch-*`, `Origin`, `Referer`, or `X-Discord-Locale` header is present on the claim PATCH.
- X-Super-Properties: generated from the selected browser profile at startup and static for the process
- Cookies: `__dcfduid` / `__sdcfduid` (and any harvested ticket cookies) are used on the MFA/ticket, login, and guard paths; the claim PATCH intentionally omits `Cookie` entirely
- Claim headers: exactly `Host`, `Authorization`, `X-Super-Properties`, `X-Discord-MFA-Authorization`, `Content-Type`, `Content-Length`, `User-Agent`, `Connection`
- Timing jitter: poller only, ±1ms on the 5ms cycle target; the claim path has no artificial delay

## 11. Config File Format

```json
{
  "webhook_url": "https://discord.com/api/webhooks/...",
  "totp_secret": "JBSWY3DPEHPK3PXP",
  "burst_count": 5,
  "warm_connections": 10,
  "guard_mode": false,
  "guard_action": "reclaim_only",
  "guard_reclaim_max": 5,
  "guard_reclaim_backoff_ms": 500,
  "guard_protected_user_ids": ["123456789012345678"],
  "targets": [
    {
      "guild_id": "123456789",
      "vanity": "coolname",
      "token": "user_token_here",
      "proxies": ["http://user:pass@ip:port", "socks5://ip:port"]
    }
  ],
  "fingerprint": {
    "dcfduid": "",
    "sdcfduid": "",
    "super_properties_b64": "",
    "user_agent": "Mozilla/5.0 ... Chrome/143.0.0.0"
  }
}
```

### 11.1 Field reference

| Field | Default | Notes |
|---|---|---|
| `burst_count` | 5 | Sentry worker count and hard cap on simultaneous PATCH writes. When both this and `warm_connections` are >1, `warm_connections` is raised to this value. Set either to 1 to opt out of the auto-raise. |
| `warm_connections` | 2 (→ raised to `burst_count`) | Conns kept warm **per proxy pool**. With N entries, total warm conns = N × `warm_connections`. |
| `browser` | `chrome` | `chrome` or `firefox`; selects the UA + super-props + uTLS preset as one consistent set. An explicit `fingerprint.user_agent` is ignored when it disagrees. |
| `fingerprint.dcfduid` / `sdcfduid` | generated | Device cookies. A configured value is preserved; generated values are persisted only if config is rewritten (for example after a token mint). |
| `guard_mode` | false | Opt-in. Adds claim pressure that can compound an active rate-limit lockout. |
| `guard_action` | `reclaim_only` | One of `reclaim_only` \| `kick` \| `ban`. Validated at startup — a typo fails instead of no-op'ing silently. |
| `guard_reclaim_max` | 5 | Max reclaim bursts per loss episode. Reset on recovery. |
| `guard_reclaim_backoff_ms` | 500 | Pause between reclaim attempts. |
| `guard_protected_user_ids` | [] | Extra ids never punished. The token owner is always implicitly protected. |
| `targets[].proxies` | `[""]` (direct) | One warm pool is built per entry, in order. `""` = direct. Omission injects the direct-only list; an explicit non-empty list gets no implicit direct pool. Multiple entries = multi-IP burst (WS2), capped by `burst_count`. |

`grace_end` is not a field and is ignored if present. There is no grace tracker or grace burst.

## 12. Edge Cases Handled

- Stale gateway resume loop → fallback after 3 unsuccessful resumable replies (counter persists across reconnects, resets on dispatch or fresh identify)
- Gateway event missed or delayed → gated poller observes on its next RTT
- Multiple targets share one process-wide rate-limit/global state; there is no cross-process coordination
- 204 No Content response (treated as success)
- MFA challenge (`60003`) / 401 during a claim → solve a fresh ticket and retry, up to the claim retry cap. There is no dedicated TOTP-expiry detector.
- **Duplicate GUILD_UPDATE events are not deduplicated by sequence.** After a successful claim, further signals are ignored unless guard mode is on, in which case a duplicate can trigger a reclaim burst.
- Zero proxies → direct connection fallback (`[""]` injected automatically)
- Unrelated GUILD_UPDATE (name/icon/description change) → byte-scan filter skips unmarshal + claim wake (WS4)
- Guard reclaim cap exhausted → target marked `lost`, signals dropped (no webhook spam)
- Offender outranks sniper account → 403, quarantine fails, revert relied on
- Token owner changes the vanity legitimately → owner in whitelist, never self-punished
- Poisoned pooled conn (empty read) → close + retry once on fresh conn so a bad pool entry doesn't lose the burst

## 13. Build & Run

Run from the repository root:

```bash
go build -ldflags="-s -w" -o sniper.exe
./sniper.exe -config config.json
```

Single binary, no separate runtime or sidecar. A cgo-disabled Windows amd64
build with `-ldflags="-s -w"` measured **7,904,768 bytes (~7.9MB)** on
2026-10-20; size varies by OS/arch. The only application flag is
`-config` (default `config.json`); Go's built-in `-h`/`-help` prints usage. One invocation starts every target in that
file; there is no menu, no per-target prompt, and no `--dry-run` mode.

### 13.1 Testing

File names in the tables below are under `internal/sniper/`; run commands from
the repository root. Default `go test ./...` runs without network access or
credentials:

| File | Covers |
|---|---|
| `detection_test.go` | Unified free/not-free decision, malformed payloads, gateway/REST/poller signaling |
| `config_test.go` | Defaults and legacy `grace_end` key still loading |
| `token_pass_test.go` | Concurrent token validation, mint coalescing, per-lane mint failure |
| `multi_target_test.go` | Every configured target starts, concurrent claims, five-sentry burst, final-vanity templates |
| `orchestrator_arming_test.go` | Parallel arming, serial-vs-parallel wall time, barrier timeout, tokenless lane rejection |
| `prebuild_test.go` | Request rendering, vanity parsing, malformed poll response, RTT cadence |
| `proxy_test.go` + `http_proxy_test.go` | Proxy URL parsing, SOCKS5 and HTTP CONNECT dial paths, auth handling |
| `pool_burst_test.go` | Pool exhaustion and burst behavior |
| `gateway_bench_test.go` | GUILD_UPDATE fast filter, raw-frame decode skip |
| `gateway_sequence_test.go` | Raw/JSON sequence-bookkeeping parity, resume-attempt cap |
| `hotpath_test.go` + `hotpath_clock_*` | Measured free→wire and burst-first-wire spans |
| `fingerprint_test.go` | Browser-profile resolution and consistency |
| `stats_test.go` | Observation counter and non-zero checks/s |

`go vet ./...` covers static analysis.

The free→wire tests assert **p50 ≤ 20µs**, **p95 ≤ 250µs**, and **p99 ≤ 2ms**;
the poller cadence test asserts a median observation gap **≤ simulated RTT + 3ms**.
Those are code constants chosen from repeated reference measurements, not config
knobs, so a wire-path or cadence regression fails the default `go test ./...`.

The `realnet` suite is excluded from the default build by its build tag and
needs only network access; no token or `config.json` is required:

```bash
go test -tags=realnet -count=1 -run TestRealMeasurement -v ./internal/sniper
```

It measures TCP connect, TLS total, and warm gateway TTFB against `discord.com`,
then reruns the local free→wire measurements with the same thresholds.

The live suite is excluded from the default build by the `live` tag and is not
part of `go test ./...`:

| File | Covers |
|---|---|
| `live_claim_test.go` | Production SessionStore → MFA → pool → Claimer → webhook path; needs `config.json`, a live token and network; mutates the target vanity and posts real webhooks |

Invoke explicitly with
`go test -tags=live -run=TestLiveClaim -v -timeout=120s ./internal/sniper`.
The test reads `config.json` from the repository root and resolves the configured
session path relative to it.

## 14. Constraints

- Discord ToS prohibits self-botting (user accounts). Use at own risk.
- Requires Level 3 server (14 boosts) for the vanity URL feature.
- Account should have 2FA configured: TOTP is the primary claim MFA, with a password fallback if configured. If Discord does not challenge a claim, a no-MFA request may be tried.

### 14.1 Permissions matrix

The sniper account (token holder) needs different permissions depending on which
features are enabled. A missing permission degrades gracefully (logged + relied
on elsewhere) rather than crashing — but the feature won't work.

| Feature | Required permission | Notes |
|---|---|---|
| Claim / re-claim vanity | `MANAGE_GUILD` | Core requirement. Without it the PATCH returns 403. |
| Gateway events | (none beyond being in the guild) | `GUILDS` intent (1) is requested in IDENTIFY. |
| Guard: identify offender | `VIEW_AUDIT_LOG` | Without it the audit-log GET 403s; guard logs "no offender" and relies on revert only. |
| Guard: `kick` action | `KICK_MEMBERS` | 403 hierarchy block → logged, revert relied on. |
| Guard: `ban` action | `BAN_MEMBERS` | 403 → degrades to kick; second 403 → revert only. |
| Punish an offender | Sniper's top role must rank **above** the offender's top role | Even with KICK/BAN_MEMBERS, a higher-ranked offender returns 403. The owner is always un-punishable. |

### 14.2 Recommendations

- Run the sniper account with an **admin or owner** role on the target guild so
  the guard can punish any offender regardless of hierarchy.
- Add trusted admins to `guard_protected_user_ids` so a legitimate vanity change
  they make isn't treated as an attack (the token owner is always auto-protected).
- Keep `guard_mode` off until the first claim lands if you want to avoid extra
  claim pressure during a rate-limit lockout; otherwise it's safe to leave on.
