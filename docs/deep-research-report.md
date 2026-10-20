# Discord Vanity Snipers: Source-Level Comparison

**Research date:** 2026-10-19; this repository’s measurements and code claims re-audited 2026-10-20. **Scope:** public GitHub repositories read at pinned commits (links below). No live Discord claim was made: this workspace has no `config.json`, token, or target guild. Star counts are not a speed ranking; every “fastest” label below is the author’s own wording unless a source line says otherwise. Figures marked *measured 2026-10-20* come from this workspace’s harnesses; they are local spans and network-floor observations, not claim-to-200 results.

**Verdict up front**

- There is no independent benchmark that ranks open-source vanity snipers. The public repos have 4–25 stars, and the self-described “fastest” ones are often 50-line scripts.
- Our **wire path** is ahead of the inspected rivals on code-path evidence: pre-built HTTP/1.1 bytes written by already-warm sentries, versus rivals that JSON-encode at claim time, open a fresh TLS socket per claim, or route through CycleTLS/Python. Local spans are in §3.
- Our **gateway detection** is equal on transport and ahead on decode: the raw `GUILD_UPDATE` frame scan is cheaper than the envelope+payload decode. Measured costs are in §3.
- Our **poller** was 5 ms behind S-pectral’s deadline-from-start cadence. That gap is now closed: the 5 ms target is measured from request start, so a slow link observes once per RTT instead of once per RTT+5 ms.
- **Multi-target arming:** the parallel-lane result is in §6.
- No claim is made that we beat anyone in a live race. The requirements for proving that are in §6.

## 1. Comparison table

| Repo | Detection | Connections / claim write | Auth, MFA, retries | Author-published number | Source |
|---|---|---|---|---|---|
| **S-pectral/UrlSniper** (9★) | Gateway `GUILD_UPDATE` plus a serial aggressive GET loop targeting a 30 ms interval; 25 ms grace burst | One `tls.connect` socket with `setNoDelay(true)`; claim passes `closeConnection=true`, so **every claim opens a new TLS socket**; Node string building at claim time | Password-based `/mfa/finish` flow; 3 socket-error retries with a fresh socket; dual endpoint `/vanity-url` then `/guilds/{id}` | README advertises 30 ms and 25 ms **intervals**, not end-to-end latency | [tls socket](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/advanced_sniper.js#L39) · [claim](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/advanced_sniper.js#L221) · [aggressive loop](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/advanced_sniper.js#L381) · [README](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/README.md#L10) |
| **mehdiffer/vanity-sniper** (17★) | Gateway `GUILD_UPDATE`/`GUILD_DELETE` only; no poller | Persistent **HTTP/2** session; **5 concurrent PATCH streams** per claim; keepalive GET every 1.9 s | MFA token loaded from `mfa.txt` and refreshed by a separate process every 4 min; no retry loop in the claim path | None published; per-claim `Date.now()` duration is logged | [h2 session](https://github.com/mehdiffer/vanity-sniper/blob/7ad774d3ca66aeae971661cefce857671516514e/main.js#L17) · [five streams](https://github.com/mehdiffer/vanity-sniper/blob/7ad774d3ca66aeae971661cefce857671516514e/main.js#L74) · [gateway](https://github.com/mehdiffer/vanity-sniper/blob/7ad774d3ca66aeae971661cefce857671516514e/main.js#L125) · [MFA refresh](https://github.com/mehdiffer/vanity-sniper/blob/7ad774d3ca66aeae971661cefce857671516514e/mfa.cjs#L127) |
| **onlycmd/onlysniper** (9★) | **No gateway**: 10 async workers poll `GET /invites/{vanity}`; 404 means free; `check_interval` 0.05 s after each response | `curl_cffi` `AsyncSession(impersonate="chrome110")`; one session per worker; claim on the same session | TOTP placed directly in `X-Discord-MFA`; multi-token/proxy lists; 429 sleeps `retry_after` | README says “millisecond-level” reaction; no number or method | [workers](https://github.com/onlycmd/onlysniper/blob/8d79c66b6243a1aa95af8995835f237e72a218a6/onlysniper.py#L205) · [404 check](https://github.com/onlycmd/onlysniper/blob/8d79c66b6243a1aa95af8995835f237e72a218a6/onlysniper.py#L223) · [claim](https://github.com/onlycmd/onlysniper/blob/8d79c66b6243a1aa95af8995835f237e72a218a6/onlysniper.py#L182) · [README config](https://github.com/onlycmd/onlysniper/blob/8d79c66b6243a1aa95af8995835f237e72a218a6/README.md#L38) |
| **yutomiwana/discord-vanity-sniper** (5★) | Gateway `GUILD_UPDATE`/`GUILD_DELETE` only; no poller | CycleTLS (JA3/UA control); a prewarm PATCH at startup and every 30 min; claim uses CycleTLS per request | MFA refresh every 3 min; claims the `vanity_url_code` from the event rather than a configured target | README claims **150–250 ms** claim latency | [prewarm](https://github.com/yutomiwana/discord-vanity-sniper/blob/6a0979514302b71b4a7b34e2ec6e207645f9f215/main.js#L295) · [claim timer](https://github.com/yutomiwana/discord-vanity-sniper/blob/6a0979514302b71b4a7b34e2ec6e207645f9f215/main.js#L318) · [gateway](https://github.com/yutomiwana/discord-vanity-sniper/blob/6a0979514302b71b4a7b34e2ec6e207645f9f215/main.js#L491) · [README](https://github.com/yutomiwana/discord-vanity-sniper/blob/6a0979514302b71b4a7b34e2ec6e207645f9f215/README.md#L38) |
| **0-don/Discord-Vanity-Url-Sniper** (25★, most-starred) | Polls `GET /invites/{vanity}`; sleeps **30 s** while taken | Synchronous requests through a rotating proxy | No MFA flow in the source | None | [check/sleep](https://github.com/0-don/Discord-Vanity-Url-Sniper/blob/95060e8ad2142d0ffdcda6bbb1120975ff01423d/main.py#L72) |

Excluded after source review: `Auth1337/Vanity-Sniper` (53-line aiohttp loop, no MFA/retry), `4lestero/Discord-Vanity-Sniper` (51-line discord.js v8 script), `imploded/low-latency-discord-vanity-sniper` (repository now contains only a Telegram link), and `kadinkatilii/vanity-sniper` (Turkish README claims “0.0001 ms” checks, unsupported by any code or measurement). They do not add a technique beyond the table.

## 2. What each rival actually does

### S-pectral/UrlSniper

The requested reference. It has three relevant modes: gateway, aggressive polling, and a scheduled grace burst.

- **Detection:** gateway `GUILD_UPDATE` compares `packet.d.vanity_url_code` against the active code and calls `tryClaim` directly ([gateway](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/advanced_sniper.js#L526)). Aggressive mode loops `GET /api/v9/guilds/{id}/vanity-url` serially ([loop](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/advanced_sniper.js#L390)). Its `CHECK_INTERVAL` is 30 ms and the sleep is computed from a deadline captured **before** the request ([deadline](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/advanced_sniper.js#L415)); on a link whose RTT exceeds 30 ms, the loop therefore runs at RTT cadence with no extra sleep.
- **Response framing:** the promise resolves on the TLS socket’s `end` event, not on `Content-Length` or a chunked terminator ([end handler](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/advanced_sniper.js#L133)). With `Connection: keep-alive`, the code has no explicit “body complete” condition; this is a correctness weakness the rival’s README does not mention.
- **Claim write:** `sendHttpRequest` JSON-stringifies the body and the headers at claim time, then writes them to the socket. The claim passes `closeConnection=true` ([claim call](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/advanced_sniper.js#L221)), and the sender destroys the socket after the response ([close](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/advanced_sniper.js#L150)). Every claim therefore pays a fresh TCP+TLS handshake; the `realnet` network floor in §3 makes that a much larger penalty than any CPU-side encoding difference.
- **MFA/retries:** it solves `60003` by POSTing `mfa_type: "password"` to `/api/v9/mfa/finish` and retrying the PATCH with `X-Discord-MFA-Authorization` ([MFA](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/advanced_sniper.js#L167)). Socket errors retry up to three times with a fresh socket ([retry](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/advanced_sniper.js#L122)). It also tries the legacy `/guilds/{id}` endpoint with both `code` and `vanity_code` after 10008/404.
- **Published number:** the README advertises a 30 ms monitoring interval and a 25 ms grace burst ([README](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/README.md#L10)). Those are loop intervals, not measured claim latency; the code contains no end-to-end timer.

### mehdiffer/vanity-sniper

The only inspected rival that uses HTTP/2 for the claim path.

- **Detection:** gateway only, with a `servers` map of guild id → vanity; on `GUILD_UPDATE` it claims the old vanity when the new code differs ([gateway](https://github.com/mehdiffer/vanity-sniper/blob/7ad774d3ca66aeae971661cefce857671516514e/main.js#L125)). No poller.
- **Connection/claim:** one persistent `http2.connect` session created at startup ([session](https://github.com/mehdiffer/vanity-sniper/blob/7ad774d3ca66aeae971661cefce857671516514e/main.js#L17)); each claim opens **five concurrent streams** on that session ([streams](https://github.com/mehdiffer/vanity-sniper/blob/7ad774d3ca66aeae971661cefce857671516514e/main.js#L74)). It sends a `GET /users/@me` every 1.9 s to keep the session alive ([keepalive](https://github.com/mehdiffer/vanity-sniper/blob/7ad774d3ca66aeae971661cefce857671516514e/main.js#L163)).
- **MFA/auth:** the claim reads a pre-solved token from `mfa.txt`; a separate CLI refreshes it by solving a password ticket on a new HTTP/2 session every 4 minutes ([refresh](https://github.com/mehdiffer/vanity-sniper/blob/7ad774d3ca66aeae971661cefce857671516514e/mfa.cjs#L127)).
- **Measurement:** it logs `Date.now()` from stream creation to response headers per claim ([timer](https://github.com/mehdiffer/vanity-sniper/blob/7ad774d3ca66aeae971661cefce857671516514e/main.js#L75)); it publishes no aggregate or comparison.
- **Assessment:** HTTP/2 does not reduce RTT, and a single PATCH gains nothing from multiplexing. Five streams share one TCP connection, so the requests are serialized at the frame layer; our five pre-warmed HTTP/1.1 sockets write in parallel and need no HPACK encoder. The h2 path is a reasonable fallback if HTTP/1.1 sockets are unavailable, but it is not a free→wire win here.

### onlycmd/onlysniper

A Python/`curl_cffi` poller with 10 workers and no gateway.

- **Detection:** each worker polls `GET /api/v10/invites/{vanity}` and treats **404** as free ([worker](https://github.com/onlycmd/onlysniper/blob/8d79c66b6243a1aa95af8995835f237e72a218a6/onlysniper.py#L205), [404](https://github.com/onlycmd/onlysniper/blob/8d79c66b6243a1aa95af8995835f237e72a218a6/onlysniper.py#L223)). The invite endpoint is not the guild’s vanity record; it is an indirect signal and may have different cache/propagation behavior.
- **Cadence:** the configured default is `threads: 10`, `check_interval: 0.05` ([config](https://github.com/onlycmd/onlysniper/blob/8d79c66b6243a1aa95af8995835f237e72a218a6/README.md#L38)). The sleep is **after** the response ([sleep](https://github.com/onlycmd/onlysniper/blob/8d79c66b6243a1aa95af8995835f237e72a218a6/onlysniper.py#L234)), so each worker’s cadence is roughly RTT+50 ms; the workers are all started in one loop without an explicit stagger ([start](https://github.com/onlycmd/onlysniper/blob/8d79c66b6243a1aa95af8995835f237e72a218a6/onlysniper.py#L260)). Concurrency raises throughput during a detection burst, but does not by itself produce a sub-RTT observation cadence.
- **Claim:** `PATCH /api/v10/guilds/{id}/vanity-url` with a TOTP in `X-Discord-MFA` ([claim](https://github.com/onlycmd/onlysniper/blob/8d79c66b6243a1aa95af8995835f237e72a218a6/onlysniper.py#L182)). That is a direct TOTP header rather than the ticket → `/mfa/finish` → JWT flow used by Discord’s current web client and by our code; it may work only for some accounts/API paths.
- **Published number:** “millisecond-level reaction” in the README, no number, no method.

### yutomiwana/discord-vanity-sniper

The only rival with an explicit end-to-end latency claim.

- **Detection:** gateway `GUILD_UPDATE`/`GUILD_DELETE` only; on an event it calls `tryClaim(d.vanity_url_code)` ([gateway](https://github.com/yutomiwana/discord-vanity-sniper/blob/6a0979514302b71b4a7b34e2ec6e207645f9f215/main.js#L491)). It claims the code carried by the event, not a configured target, which is surprising for a “watch this vanity” tool.
- **Connection/claim:** CycleTLS with JA3 and UA control; a prewarm PATCH at startup and every 30 minutes ([prewarm](https://github.com/yutomiwana/discord-vanity-sniper/blob/6a0979514302b71b4a7b34e2ec6e207645f9f215/main.js#L295)). The claim performs a `GET /guilds/{id}` for the guild name inside the timed section, then the PATCH ([timer](https://github.com/yutomiwana/discord-vanity-sniper/blob/6a0979514302b71b4a7b34e2ec6e207645f9f215/main.js#L321)). That extra GET is one full RTT before the PATCH.
- **MFA:** refreshes every 3 minutes ([refresh](https://github.com/yutomiwana/discord-vanity-sniper/blob/6a0979514302b71b4a7b34e2ec6e207645f9f215/main.js#L526)).
- **Published number:** “~150–250 ms claim latency” in the README ([README](https://github.com/yutomiwana/discord-vanity-sniper/blob/6a0979514302b71b4a7b34e2ec6e207645f9f215/README.md#L38)). Given the extra guild GET inside its own timer, that figure includes avoidable work; it is not a wire-only number.

### 0-don/Discord-Vanity-Url-Sniper

The most-starred repo is not a low-latency competitor: it polls the invite endpoint, sleeps **30 seconds** while the URL is taken, and recurses ([source](https://github.com/0-don/Discord-Vanity-Url-Sniper/blob/95060e8ad2142d0ffdcda6bbb1120975ff01423d/main.py#L72)). It is useful as a proxy-rotation example, not as a speed reference.

## 3. What this repository measurably does

Method: the QPC harness in [hotpath_test.go](../internal/sniper/hotpath_test.go) drives the real `tryClaim → fire → sentry → runOnce` path over a fake warm socket and stamps immediately after `conn.Write` returns. `time.Now` on this host steps in ~650 µs, so the harness uses `QueryPerformanceCounter`. 300 iterations (200 for the 5-sentry burst), repeated runs; medians below.

Recent default-harness runs (*2026-10-20*, n=300/200; values span the observed run-to-run range):

| Span | Result |
|---|---|
| signal-handler → wire, p50 | 0.8–2.1 µs |
| signal-handler → wire, mean | 2.2–6.4 µs |
| availability channel → wire, p50 | 2.8–8.9 µs (scheduler-dominated) |
| 5-sentry burst, first wire p50 | 2.2–6.9 µs |
| gateway raw `GUILD_UPDATE` frame scan | 0.68–2.9 µs/op, 3 allocs |
| gateway envelope + payload JSON decode | 15.8–59 µs, 15 allocs |

The latest `realnet` run reported local p50s of 700 ns (signal-handler → wire), 2.3 µs (5-sentry first wire), and 3.7 µs (availability channel → wire). These are separate runs, not a combined distribution.

The claim bytes are built ahead of the signal and published through `atomic.Pointer[[]byte]`; in steady state the sentry writes them with no JSON encode, no header concatenation, and no pool lock ([claimer.go](../internal/sniper/claimer.go#L319)). With the default five sentries, each normally holds a warm uTLS HTTP/1.1 connection, so a burst starts without a handshake ([pool.go](../internal/sniper/pool.go#L28)); a conn held over 10s is refreshed through the pool before the write, and an empty pool falls back to a synchronous dial.

Network floor measured from this host by `realnet` on 2026-10-20 (n=10 each): TCP connect p50 **102.6 ms** (p95 140.0 ms), TLS total p50 **114.3 ms** (p95 136.1 ms), `GET /api/v9/gateway` TTFB p50 **52.1 ms** (p95 101.0 ms). The local claim path is therefore under 0.01 ms of a >52 ms network budget on this run; there is no evidence that 50 ms end-to-end is reachable from this host without a faster path to Discord. The tagged `realnet` harness (`go test -tags=realnet -count=1 -run TestRealMeasurement -v ./internal/sniper`) re-measures these values and the local spans; it needs network access but no token or config.

## 4. The change made: poller cadence is now one RTT

S-pectral’s aggressive loop sets `nextCheckTime = now + 30 ms` before the request and sleeps `max(0, nextCheckTime - now)` afterwards ([lines 415–420](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/advanced_sniper.js#L415)). Once the RTT exceeds the interval, the next request leaves immediately, so the observation cadence is one RTT, not RTT+interval.

Our poller previously slept a fixed 5 ms **after** every response, so on this host its cadence was RTT+5 ms (~61 ms against the old 55.9 ms TTFB figure). [Poller.Run](../internal/sniper/poller.go#L67) now stamps the start of `poll()` and subtracts the elapsed time from the 5 ms cycle target; a slow response leaves no residual sleep. The 5 ms floor still applies on fast links, so the request rate does not rise there.

Measured with a fake socket that adds a simulated 20 ms RTT ([TestPollerCadenceTargetsOneRTT](../internal/sniper/prebuild_test.go#L186)):

| Before (recorded before the change) | Current run (2026-10-20) |
|---|---|
| median observation gap **26.00 ms** (n=22) | median observation gap **20.4–20.5 ms** (n=29) |

The ~5.5 ms difference is the fixed post-response sleep. At the TTFB measured in §3, the same code path removes the fixed 5 ms and yields a ~52 ms cadence instead of ~57 ms. This is a direct, measured adoption of the rival’s deadline-from-start technique, not a config knob.

## 5. Techniques skipped, and why

| Rival technique | Why it was not adopted |
|---|---|
| **New TLS socket per claim** (S-pectral, `closeConnection=true`) | Adds a full TCP+TLS handshake to every claim; the measured network floor is in §3. Our warm sentries already hold five authenticated sockets; adding a handshake would be a large regression. |
| **HTTP/2 claim session** (mehdiffer) | HTTP/2 does not reduce RTT. A single PATCH gains nothing from multiplexing; five streams on one TCP connection are serialized at the frame layer, and the h2 encoder adds work. Our five HTTP/1.1 sockets write pre-built bytes in parallel. Keep HTTP/1.1 for the claim. |
| **10-worker poller** (onlycmd) | Its workers poll the **invite** endpoint, sleep 50 ms *after* the response, and are started without stagger, so per-worker cadence is ~RTT+50 ms. With one token, ten workers multiply request rate and 429 risk. Our gateway push is the primary trigger, and our single poller now observes at RTT cadence. Concurrency would add load without evidence of a faster first observation. |
| **CycleTLS sidecar** (yutomiwana) | We already use uTLS with a browser profile, so the TLS fingerprint is covered without a second process/transport. The default profile is `HelloChrome_Auto` with Chrome-143 headers, not a pinned Chrome-143 ClientHello; the report does not claim otherwise. CycleTLS per claim adds serialization; its published 150–250 ms includes an extra guild GET inside its timer. |
| **Multi-token / proxy rotation** (onlycmd, 0-don) | A configuration/schema change, not a code tuning, and explicitly outside “no new config knobs.” Our per-target proxy list already provides multiple source IPs; multiple tokens for one guild would need a product decision and rate-limit modeling. |
| **Grace-period tracker** (S-pectral, yutomiwana) | Orthogonal to free→wire. This binary does not implement a grace tracker or grace burst and has no `grace_end` field (legacy keys are ignored on load); that is a separate feature gap, not a speed technique. |
| **Dual endpoint fallback** (S-pectral) | Already implemented in our sentries (`/vanity-url`, then `/guilds/{id}` with both keys). |

## 6. What a real head-to-head would require

No live claim was possible here (no token, no `config.json`, no target guild). To prove “faster than rival X”:

1. Two Discord accounts, each with Manage Server on a different level-3 guild, both targeting the **same** vanity code.
2. A controlled drop: the current holder removes the vanity at a known instant, with both clients already connected and armed.
3. Clients on the same network vantage/region, with independent timestamps at (a) the gateway frame or poll response that reports the drop and (b) the PATCH `write()` returning; a packet capture or server-side timestamp to break ties.
4. Repeated trials with randomized order and a shared clock; report detection cadence, free→wire, and claim-to-200 separately.
5. A third observer / audit log to confirm which guild actually received the vanity; a 200 alone is not proof if the client mis-parses.

**Where we stand on the three dimensions**

- **Detection cadence:** equal on gateway push; ahead on decode cost (measured in §3). Our poller is now at RTT cadence, matching S-pectral’s effective behavior and beating onlycmd’s RTT+50 ms. onlycmd’s 10 workers could produce more request throughput if the gateway were silent, but it has no gateway and no stagger.
- **Wire latency:** ahead on code-path evidence. Rivals build JSON at claim time, open a new TLS socket (S-pectral), use Python/curl_cffi (onlycmd), or pay CycleTLS plus an extra GET (yutomiwana). Our local free→wire p50 is in §3; a live head-to-head would still be needed to confirm the end-to-end difference is not lost in server-side queueing.
- **Arming time:** now parallel across lanes. [NewOrchestrator](../internal/sniper/orchestrator.go#L134) launches each target's arm work concurrently and waits on a single barrier; the latest test measured **3.02s serial vs 1.003s parallel** for 3 lanes × 5 warm connections. The remaining cost is per-lane MFA priming and pool warm-up, which is not avoidable by cross-lane scheduling alone.

## 7. Sources

- S-pectral/UrlSniper, commit `961b74e60103e5741b8111a2b1a349c304e79c53`: [README](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/README.md), [advanced_sniper.js](https://github.com/S-pectral/UrlSniper/blob/961b74e60103e5741b8111a2b1a349c304e79c53/advanced_sniper.js).
- mehdiffer/vanity-sniper, commit `7ad774d3ca66aeae971661cefce857671516514e`: [main.js](https://github.com/mehdiffer/vanity-sniper/blob/7ad774d3ca66aeae971661cefce857671516514e/main.js), [mfa.cjs](https://github.com/mehdiffer/vanity-sniper/blob/7ad774d3ca66aeae971661cefce857671516514e/mfa.cjs).
- onlycmd/onlysniper, commit `8d79c66b6243a1aa95af8995835f237e72a218a6`: [onlysniper.py](https://github.com/onlycmd/onlysniper/blob/8d79c66b6243a1aa95af8995835f237e72a218a6/onlysniper.py), [README](https://github.com/onlycmd/onlysniper/blob/8d79c66b6243a1aa95af8995835f237e72a218a6/README.md).
- yutomiwana/discord-vanity-sniper, commit `6a0979514302b71b4a7b34e2ec6e207645f9f215`: [main.js](https://github.com/yutomiwana/discord-vanity-sniper/blob/6a0979514302b71b4a7b34e2ec6e207645f9f215/main.js), [README](https://github.com/yutomiwana/discord-vanity-sniper/blob/6a0979514302b71b4a7b34e2ec6e207645f9f215/README.md).
- 0-don/Discord-Vanity-Url-Sniper, commit `95060e8ad2142d0ffdcda6bbb1120975ff01423d`: [main.py](https://github.com/0-don/Discord-Vanity-Url-Sniper/blob/95060e8ad2142d0ffdcda6bbb1120975ff01423d/main.py).
- This repo: [poller.go](../internal/sniper/poller.go#L67), [prebuild_test.go](../internal/sniper/prebuild_test.go#L186), [hotpath_test.go](../internal/sniper/hotpath_test.go#L19), [gateway.go](../internal/sniper/gateway.go#L494), [claimer.go](../internal/sniper/claimer.go#L319), [pool.go](../internal/sniper/pool.go#L28).
