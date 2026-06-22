# Product Requirements Document: Discord Vanity URL Sniper

## Version 1.1

### Changelog (1.0 → 1.1)

| Area | Change |
|---|---|
| Claim hot path | Restructured from spawn-on-event workers to **pre-armed sentry workers** (WS1) that block on a broadcast and write on wake — no goroutine spawn, no pool lock, no template build between event arrival and wire write. |
| Multi-IP | **Per-proxy connection pools** (WS2): each configured proxy gets its own warm pool + rewarmer, and the burst fires from every IP simultaneously instead of round-robining one pool. |
| Guard | Added **Vanity Guard offender quarantine** (WS3): after detecting an unauthorized change, look up the offender in the audit log and kick/ban them in parallel with the reclaim burst. Whitelist protects the token owner + configured ids. |
| Detection | GUILD_UPDATE now uses a **byte-scan vanity filter** (WS4): `bytes.Contains` on the raw payload skips the JSON unmarshal for the ~99% of GUILD_UPDATEs that don't touch `vanity_url_code`. |
| Perms | Documented the **permissions matrix** the sniper account needs for each feature (§14). |

---

## 1. Executive Summary

A high-performance, low-latency Discord vanity URL sniper written in Go. The system monitors target guilds via WebSocket gateway for real-time vanity URL changes and claims them within 50-150ms using pre-warmed TLS connections, TOTP-based MFA, and zero-allocation hot paths.

## 2. Core Requirements

### 2.1 Functional Requirements

| ID | Requirement | Priority |
|---|---|---|
| FR-01 | Monitor multiple guilds simultaneously | P0 |
| FR-02 | Detect vanity URL changes via Gateway WebSocket (push, not polling) | P0 |
| FR-03 | Claim available vanity URLs via PATCH endpoint | P0 |
| FR-04 | Support TOTP-based 2FA (no password flow) | P0 |
| FR-05 | Support HTTP/SOCKS5 proxies | P0 |
| FR-06 | Pre-warm TLS connections to eliminate handshake latency | P0 |
| FR-07 | Grace period tracker with burst mode | P0 |
| FR-08 | Guard mode: re-claim if vanity is lost post-claim | P0 |
| FR-08a | Multi-IP burst: fire all sentries from every proxy's warm pool at once (WS2) | P0 |
| FR-08b | Guard offender quarantine: audit-log lookup + kick/ban, owner-whitelisted (WS3) | P1 |
| FR-08c | Byte-scan vanity filter on GUILD_UPDATE to skip unmarshal for non-vanity edits (WS4) | P1 |
| FR-09 | Discord webhook notifications (success, failure, burst) | P1 |
| FR-10 | Gateway session resume (avoid re-authentication) | P1 |
| FR-11 | Rate limit tracking (per-token, per-guild, global) | P1 |
| FR-12 | Live stats dashboard (checks/s, claims, errors) | P2 |

### 2.2 Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR-01 | End-to-end claim latency | <150ms (target: 50-130ms) |
| NFR-02 | Detection latency | <50ms (WebSocket push) |
| NFR-03 | Concurrent targets | 100+ per instance |
| NFR-04 | Uptime | 99.9% via gateway resume |
| NFR-05 | Zero-allocation hot path | No GC pressure during claim |
| NFR-06 | Binary size | <15MB single static binary |
| NFR-07 | Session start consumption | ~1/day per target (RESUME preferred) |

## 3. Architecture

### 3.1 Component Overview

```
main.go → orchestrator.go → [target goroutines]
                                ├── gateway.go (WebSocket monitor)
                                │     └── byte-scan vanity filter (WS4)
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
  `vanity_url_code` *before* any JSON unmarshal. ~99% of GUILD_UPDATEs change an
  unrelated field (name, icon, description, features); skipping the unmarshal +
  availability signal for those avoids waking the claimer and spurious claim
  attempts. The scan is μs-class.
- **Backup**: None (eliminated for speed — WS only)
- **Grace burst**: REST polling at 25ms during grace window

### 3.3 Claim Strategy

**Pre-armed sentry workers (WS1):** Instead of spawning a worker per burst, the
claimer arms `burst_count` persistent "sentry" goroutines at startup. Each sentry
owns one warm TLS conn and blocks on a broadcast `fire` channel. The hot path on
a claim event is:

1. Publish pre-built PATCH bytes once (`atomic.Pointer[[]byte]` store).
2. Close the `fire` channel → every sentry wakes simultaneously.
3. Each sentry: `atomic.Load` → `conn.Write`. No lock, no probe, no spawn,
   no template build between wake and wire.

**Multi-IP burst (WS2):** Sentry workers are partitioned round-robin across
**one warm pool per proxy** (`pools[0]` is always the direct pool). Each pool has
its own rewarmer so a burst that drains one pool doesn't force a synchronous TLS
handshake on the next burst's hot path. When `N` proxies are configured, the
burst fires from all `N` IPs at once — this is the #1 win for stealing a dropped
vanity because Discord's anti-abuse throttles per-IP, different routes have
different RTT, and residential proxies look like real users.

**Other claim-strategy details:**

- TOTP code written directly into request buffer at byte offset
- All proxies fire simultaneously (staggered by TCP natural variance)
- First 200/204 response wins; remaining sentries drain (buffered send, no
  deadlock) and report their result so the burst count is correct.

## 4. API Endpoints Used

| Endpoint | Method | Purpose |
|---|---|---|
| `GET /api/v10/gateway` | GET | Get WebSocket URL |
| `wss://gateway.discord.gg/?v=10&encoding=json` | WS | Receive real-time events |
| `GET /api/v10/guilds/{id}/vanity-url` | GET | Verify current vanity code |
| `PATCH /api/v10/guilds/{id}/vanity-url` | PATCH | Claim vanity URL |
| `GET /api/v10/guilds/{id}/audit-logs?action_type=1&limit=5` | GET | Vanity Guard: identify offender of unauthorized vanity change (WS3) |
| `PUT /api/v10/guilds/{id}/bans/{uid}` | PUT | Vanity Guard: ban the offender (action=`ban`) (WS3) |
| `DELETE /api/v10/guilds/{id}/members/{uid}` | DELETE | Vanity Guard: kick the offender (action=`kick`, or ban→kick degrade) (WS3) |

## 5. MFA Handling

- **TOTP only** — no password-based MFA (too slow, requires extra round trip)
- Secret stored in config as base32
- Code generated at the last microsecond before wire write
- Cached: not needed (stateless, 30s window)

## 6. Session Reuse

- Gateway: Save `session_id`, `resume_url`, `seq` on READY
- On disconnect: RESUME (opcode 6) — consumes no session start limit
- After 3 failed resumes: fall back to fresh IDENTIFY
- Session state persisted to disk for crash recovery
- READY also captures the token owner's `user.id` into `Target.ownerID`, which the
  Vanity Guard whitelist reads (under the target mutex) so a legitimate change by
  the operator's own account is never punished.

## 7. Grace Period

- Grace = ~30 days from vanity loss
- Timer stored in `grace_state.json` (survives restarts)
- At T-1hr → lower monitoring threshold
- At T-10s → enter burst mode (25ms REST polling + all proxies firing)
- After burst window → return to normal monitoring

## 8. Rate Limiting

- Parse `X-RateLimit-Scope` to determine bucket type
- Three bucket types: `user` (per-token), `shared` (per-guild), `global` (all)
- Respect `Retry-After` header
- IP-level bans at 10k invalid/10min → count and self-throttle

## 9. Vanity Guard

Vanity Guard (FR-08) keeps defending a vanity *after* the first successful claim.
Without it, a competitor who steals the vanity back is never re-claimed (the
original behavior silently dropped every availability signal once `claimed` was
set). With it on, a GUILD_UPDATE showing the guild's vanity is no longer ours
triggers a reclaim burst.

### 9.1 Reclaim burst

On a loss signal, the claimer runs up to `guard_reclaim_max` bursts, each firing
all sentries with whatever MFA token is cached, paced by
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

- TLS fingerprint: Custom cipher suite ordering matching Chrome 125
- X-Super-Properties: Static per session (base64-encoded browser fingerprint)
- Cookies: Persistent `__dcfduid` + `__sdcfduid` (generated once)
- Headers: Full browser-like headers including Sec-CH-UA, Origin, Referer
- Timing jitter: ±10ms random variance

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
      "proxies": ["http://user:pass@ip:port", "socks5://ip:port"],
      "grace_end": "2026-07-18T14:30:00Z"
    }
  ],
  "fingerprint": {
    "dcfduid": "",
    "sdcfduid": "",
    "super_properties_b64": "",
    "user_agent": "Mozilla/5.0 ... Chrome/125.0.0.0"
  }
}
```

### 11.1 Field reference

| Field | Default | Notes |
|---|---|---|
| `burst_count` | 5 | Sentry worker count. Raised in config.go to ≥ `warm_connections` when both >1 so the burst never hits a synchronous TLS handshake. Set to 1 to opt out of the auto-raise. |
| `warm_connections` | 2 (→ raised to `burst_count`) | Conns kept warm **per proxy pool**. With N proxies, total warm conns = N × `warm_connections`. |
| `guard_mode` | false | Opt-in. Adds claim pressure that can compound an active rate-limit lockout. |
| `guard_action` | `reclaim_only` | One of `reclaim_only` \| `kick` \| `ban`. Validated at startup — a typo fails instead of no-op'ing silently. |
| `guard_reclaim_max` | 5 | Max reclaim bursts per loss episode. Reset on recovery. |
| `guard_reclaim_backoff_ms` | 500 | Pause between reclaim attempts. |
| `guard_protected_user_ids` | [] | Extra ids never punished. The token owner is always implicitly protected. |
| `targets[].proxies` | `[""]` (direct) | One warm pool is built per entry. `""` = direct; always first so `pools[0]` is the direct pool. Multiple entries = multi-IP burst (WS2). |

## 12. Edge Cases Handled

- Stale gateway resume loop → fallback after 3 attempts
- Grace period bypass via Server Web Page feature
- Shared guild rate limit across multiple tokens
- 204 No Content response (treated as success)
- TOTP code expiry mid-flight → retry immediately
- Duplicate GUILD_UPDATE events → dedup by seq
- Zero proxies → direct connection fallback (`[""]` injected automatically)
- Unrelated GUILD_UPDATE (name/icon/description change) → byte-scan filter skips unmarshal + claim wake (WS4)
- Guard reclaim cap exhausted → target marked `lost`, signals dropped (no webhook spam)
- Offender outranks sniper account → 403, quarantine fails, revert relied on
- Token owner changes the vanity legitimately → owner in whitelist, never self-punished
- Poisoned pooled conn (empty read) → close + retry once on fresh conn so a bad pool entry doesn't lose the burst

## 13. Build & Deploy

```bash
go build -ldflags="-s -w" -o sniper.exe
```

Single binary, zero runtime dependencies, ~10MB.

## 13. Testing

- `go test ./...` — unit tests for mfa, ratelimit, pool
- `go vet ./...` — static analysis
- Manual: dry-run mode with `--dry-run` flag (no actual claim)

## 14. Constraints

- Discord ToS prohibits self-botting (user accounts). Use at own risk.
- Requires Level 3 server (14 boosts) for the vanity URL feature.
- Account must have 2FA enabled with the TOTP secret available.

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
