# Load test results (2026-11-15)

**One server instance sustains about 250 attestation rounds/s with p95 under
10 ms. It breaks between 250 and 300 rounds/s; at the default 5-minute
interval that is about 75 000–90 000 devices.** The limit is not CPU: at the
knee the server uses about 1.3 of 28 cores. It is serialization: a global
lock around the token signing key, which reads SQLite on every round, while
every round also writes to SQLite through a fresh connection in rollback-journal
mode. Two things drop the knee well below that:

- **For one 5-minute cycle after every config change,** each round also writes
  the device's config watermark. The knee then falls to about **130 rounds/s
  (≈ 40 000 devices)**.
- **Registration** (a device's first round) saturates at **~50 new devices/s**.

Config fetches are light: 2 000 full fetches/s (p95 3 ms, a new TLS connection
each) and 500 narrowed fetches/s that each miss the signature cache (p95 4 ms,
1.1 cores) passed without errors.

Raw data: `results/*.jsonl` (one summary line per run) and
`results/*.server.csv` (server CPU % and RSS every 2 s). Tables made with
`perl loadtest/table.pl loadtest/results <label>`.

## Setup

- Machine: Apple M3 Ultra (28 cores, 256 GB), macOS, JBR 17.0.14. The server
  and the generator run on the same machine and talk over loopback. Other
  sessions' background load was about 1.5 cores, and no emulator ran during
  the measurements.
- Server: the `installDist` build of `security/review-2026-11-14`
  (unreleased), started with `loadtest/server.sh`: `ATTESTATION_KEY_POLICY=warn`
  with no chain, `strict` policy, ES256 tokens, local signing key, SQLite,
  request log on (the default). Per-address limits are off (one generator is
  one address); the per-device limit is at its default.
- Generator: open loop. Every round opens its own TLS connection with a fresh
  session (h2), so there are 2 handshakes' worth of round trips per round.
  Each step offers `rate` rounds/s over `rate × 300` devices, so each device
  attests about every 5 minutes, as in the field. Steps are 150 s (first ramp)
  or 120 s / 90 s (later ramps), after 20–30 s of warm-up at the same rate.
- Population: 150 000 registered devices. 4 818 were registered over HTTP;
  the rest were written with `seed`, i.e. the server's own
  `AttestedDeviceStore.register` with what a `warn` registration without a
  chain records.
- "Steady state" ramps: every device's stored config watermark equals the
  `currentIssuedAt` it sends (`--config-issued-at`). That is a fleet whose
  config has not changed since the devices' last rounds.

## Steady state, 512 MB heap (knee 250–300/s)

| offered/s | devices | ok/s | p50 ms | p95 ms | p99 ms | errors | server CPU avg / max (cores) | RSS max MB |
|---|---|---|---|---|---|---|---|---|
| 100 | 30000 | 100.0 | 9.18 | 10.78 | 11.63 | 0 % | 0.60 / 3.27 | 766 |
| 150 | 45000 | 149.9 | 7.38 | 8.45 | 9.34 | 0 % | 0.56 / 0.75 | 768 |
| 200 | 60000 | 199.9 | 6.86 | 8.14 | 14.06 | 0 % | 0.77 / 1.36 | 775 |
| 250 | 75000 | 249.9 | 6.68 | 7.79 | 9.19 | 0 % | 1.00 / 1.22 | 783 |
| **300** | 90000 | 277.3 | 923 | **7 807** | 11 969 | 0 % | 1.32 / 1.75 | 864 |

At 300/s the server keeps up for a while, falls behind, catches up and falls
behind again. A second 300/s run with JFR on managed 293/s with p95 1.7 s.
The generator stayed under 0.8 cores and at most 17 ms behind its schedule:
the generator was not the limit.

## Heap: 2 GB instead of 512 MB (no change in the knee)

| offered/s | ok/s | p50 ms | p95 ms | p99 ms | errors | server CPU avg (cores) | RSS max MB |
|---|---|---|---|---|---|---|---|
| 200 | 199.9 | 6.96 | 8.58 | 9.69 | 0 % | 0.99 | 1754 |
| 250 | 249.9 | 6.72 | 8.22 | 19.63 | 0 % | 1.04 | 1759 |
| **300** | 295.2 | 583 | **2 746** | 3 867 | 0 % | 1.31 | 1781 |

GC was never the issue. At 512 MB, live data after a young GC averaged
130 MB (max 258 MB); 394 young pauses took 0.7 s in all (one of 121 ms, the
rest a few ms), with no full GC. At 2 GB there were 60 young pauses (148 ms
in all, max 7 ms). RSS goes from ~0.78 GB to ~1.75 GB for the same
throughput: **512 MB is enough for a tenant at this load**. The larger heap
only shortens the overloaded tail a little.

## Smaller thread pools: `-XX:ActiveProcessorCount=2`, 512 MB (knee 300–400/s)

| offered/s | ok/s | p50 ms | p95 ms | p99 ms | errors | server CPU avg / max | RSS max MB |
|---|---|---|---|---|---|---|---|
| 250 | 249.9 | 6.63 | 8.12 | 11.97 | 0 % | 1.01 / 1.30 | 625 |
| 300 | 299.8 | 6.41 | 8.41 | 15.92 | 0 % | 1.20 / 1.48 | 632 |
| **400** | 306.9 | 12 689 | **13 566** | 13 812 | 16.6 % (generator in-flight cap) | 1.51 / 2.00 | 776 |

With 2 call threads instead of 28 the server does **better**: it is clean at
300/s and peaks at ~307/s. Fewer threads competing for the same SQLite lock
and the same monitor waste less time. That confirms the knee is contention,
not capacity. (This flag sizes the thread pools; it does not cap CPU. The
server here used up to 2 cores.)

## After a config change: every round writes its watermark (knee 100–200/s)

The first ramp ran on devices that had no stored watermark. That is what
every device looks like in the cycle after a config change: the next round
embeds the new config, and the round after that reports a higher
`currentIssuedAt` and writes it (`recordConfigWatermark`). That is a second
write transaction per round.

| offered/s | devices | ok/s | p50 ms | p95 ms | p99 ms | errors | server CPU avg / max | RSS max MB |
|---|---|---|---|---|---|---|---|---|
| 10 | 3000 | 10.0 | 22.9 | 31.18 | 32.43 | 0 % | 0.17 / 0.61 | 741 |
| 25 | 7500 | 25.0 | 16.32 | 21.26 | 22.43 | 0 % | 0.19 / 0.61 | 758 |
| 50 | 15000 | 50.0 | 13.61 | 17.58 | 18.61 | 0 % | 0.29 / 1.32 | 773 |
| 100 | 30000 | 100.0 | 9.48 | 10.95 | 11.8 | 0 % | 0.45 / 0.64 | 774 |
| 150 (separate run) | 45000 | 149.9 | 8.28 | 10.01 | – | 0 % | – | – |
| 180 (separate run) | 54000 | 121.6 | 20 103 | 40 436 | – | 7.1 % | – | – |
| **200** | 60000 | 129.5 | 27 558 | **39 485** | 45 122 | 23.6 % (generator in-flight cap 7474, timeouts 75) | 0.79 / 1.83 | 862 |

Peak throughput here is about 140/s, and the server uses under one core.
Under overload, challenges (which never touch the database) also wait
seconds: the 28 call threads are all busy in `POST /api/v1/attest`. Three
`SQLITE_BUSY` errors reached the log as `500`. The 150/s run was clean only
because it sat just under the peak.

**What this means in practice:** a fleet sized for the steady-state knee
(say 200 rounds/s) overloads for about one attestation interval after every
pin change, because every device writes its watermark in the same 5 minutes.
The safe sizing is the after-change knee, **~130 rounds/s ≈ 40 000 devices
per instance**, until the fixes below are in.

(The high p50 at 10–25/s is the latency of an idle machine: CPU frequency
and power states, cold caches. It falls as load rises.)

## Registration: ~50 new devices/s

200 new devices/s offered (fresh database, 12 000 new ids): **28.5/s
registered successfully on average, 45–50/s at best**, p95 39 s, 79 % of
the offered rounds failed (generator in-flight cap, client timeouts, one
`500` `SQLITE_BUSY`). The server used 0.6 cores on average. A registration
writes three times (insert, audit entry, verdict) and runs a `COUNT` of the
Config API's devices (`ATTESTATION_DEVICE_LIMIT`). For comparison,
`seed`, one uncontended writer through the same store, registered
**~1 140 devices/s** (145 182 in 128 s). The disk is not the limit; contention
is. Onboarding 100 000 devices at once (a new customer, an app update that
loses keys) takes more than half an hour, and the instance is saturated for
that whole time.

## Config fetches (2 GB server, 60 s each, a TLS connection per request)

| mix | offered/s | ok/s | p50 ms | p95 ms | p99 ms | server CPU avg |
|---|---|---|---|---|---|---|
| `config-full` | 1000 | 999.2 | 3.01 | 3.35 | 4.29 | – |
| `config-full` | 2000 | 1997.9 | 2.90 | 3.20 | 5.93 | – |
| `config-narrow`, 60 000 devices (every request a cache miss and a signing) | 200 | 199.8 | 4.98 | 5.62 | 6.20 | 0.47 |
| `config-narrow`, 60 000 devices | 500 | 499.6 | 3.62 | 4.14 | 4.74 | 1.12 |
| `config-narrow`, 400 devices (fits the 512-entry cache) | 1000 | 999.0 | 3.50 | 3.73 | 5.16 | 2.31 |

Errors: none. The full config is one cached envelope. A narrowed view is one
signature per device id, and with more than 512 devices the narrowed cache
misses on practically every request. With the local key a signing is cheap,
so this costs CPU, not latency. With an external signer (KMS/HSM) every
narrowed fetch would be a signer call; that was not measured. Higher config
rates were not tried: 2 000/s is far beyond what a fleet at the attestation
knee generates.

Pooled keep-alive connections (no handshakes) at 300 attestation rounds/s:
300/s, p50 5 ms, p95 328 ms. That is better than with a handshake per round
(p95 1.7–7.8 s), but already degrading: TLS costs CPU, the lock is what
breaks.

## Profile at the knee (JFR, 300/s steady state, and 180/s after a change)

Where the time goes is **waiting, not computing**:

- **`AttestationTokenSecretStore.active()`** (`@Synchronized`): at 300/s,
  **9 450 contended monitor entries in 90 s, average wait 50 ms, max
  634 ms**; at 180/s after a change, 9 643 entries averaging **160 ms**. In a
  thread dump under load, 11 of the 28 call threads were `BLOCKED` here. The
  holder runs `all()`, which opens a JDBC connection, reads every token key
  from SQLite and loads the active one, on every round, while SQLite's lock is
  held by a writer.
- SQLite native time at the 180/s overload (JFR native samples, by store
  method): `recordVerdict` 412, `recordConfigWatermark` 249,
  `AttestationTokenSecretStore.all` 144, `AttestationPolicyStore.get` 85,
  `ClientIdentityStore.isDeviceRevoked` 71, `AttestedDeviceStore.get` 50.
  Every one of those is a new connection: `prepare` (schema parse on a fresh
  connection) is a third of the SQLite time. The journal mode is `delete`
  (rollback journal) and no `busy_timeout` is set, so readers and writers
  block each other and back off in SQLite's busy handler.
- **Per round:** 4 reads (revocation, device row, policy, token keys) and 1
  write transaction (verdict), plus 1 write for the watermark after a config
  change. Each opens and closes its own connection.
- **CPU** (only ~1.3 cores at 300/s; JFR execution samples by subsystem):
  report ECDSA verification 42 %, TLS (handshakes, X25519, the certificate
  signature) 27 %, token ES256 signing and key loading 21 %, the per-device
  rate limiter's table scan 7 %, JSON 1 %. Nonces, policy evaluation and
  Netty/Ktor are negligible. That is about **4–5 ms of CPU per round including
  two TLS handshakes**: on a 1-vCPU tenant, CPU would cap a round rate in the
  low hundreds per second, about where the lock caps it now.
- **The per-device limiter's table is full.** `RateLimiter.maxKeys` is 10 000
  and the 10-minute windows stay live. With more than 10 000 devices, every
  round of a device outside the table scans all 10 000 entries under the
  limiter's lock and is let through **uncounted** (`FAIL_OPEN`). That is the
  7 % of CPU, and it means **the per-device limit silently stops applying for
  most devices of any fleet over 10 000.** This is a security-relevant finding
  as well as a cost.
- Not seen: the nonce replay cache was never full. Its ceiling is 100 000
  nonces per 120 s, ≈ 833 rounds/s, far above the knee. There was no GC
  pressure and no SQLite `locked` storm in the steady state (3 `SQLITE_BUSY`
  in all, all under overload).

## What would move the knee most (not implemented)

1. **Take the token signing key off the per-round path.** Keep the active
   signing key in memory and invalidate it on rotate and delete, the way
   `verificationKeys()` already caches for a few seconds. Expected effect:
   this removes the global monitor and one SQLite read from every round, and
   the profile's top contention site goes away. It weakens nothing: the same
   key signs, and a rotation still takes effect at once on this instance.
   Small, but it is key-handling code, so it should go through a review
   rather than land with the load test.
2. **SQLite: WAL mode, a `busy_timeout`, and reused connections** (a small
   pool, or one writer connection behind a queue for the attestation writes).
   With WAL, readers stop waiting on the writer; reused connections drop the
   per-call open and schema parse; one writer stops the busy-handler backoff.
   Evidence: one uncontended writer does ~1 140 transactions/s while the
   contended server collapses at ~140–300 rounds/s, and 2 call threads beat
   28. Of the two, this one matters most for the after-change and registration
   knees.

Also worth fixing, for correctness more than speed: the per-device limiter's
10 000-key table. Size it to the device limit, or count devices that do not
fit, so the limit actually holds for large fleets.

## Default per-address limits in a real deployment

Measured: with the default limits (`LIMITS=default`), 2 rounds/s from one
address over 1 000 devices. **The first 60 rounds passed, the next 60 got
`429 rate_limited`**, and the challenges kept passing until their own budget
of 120 ran out. `ATTESTATION_RATE_LIMIT=60` per address per 10 minutes is 0.1
rounds/s per address, which is **30 devices per address** at the 5-minute
interval. That is fine for phones on their own carrier addresses, tight
behind a carrier-grade NAT or a corporate Wi-Fi, and fatal behind a reverse
proxy or ingress unless `TRUSTED_PROXIES` names it. Without that, every device
has the proxy's address and **the whole tenant gets 30 devices' worth of
rounds**. A hosted tenant behind a shared ingress must set `TRUSTED_PROXIES`
(and the ingress must pass the client address). `CONFIG_VIEW_SIGN_RATE_LIMIT`
(120 narrowed signings per address per 10 minutes) behaves the same way.

## How representative this is

- **One machine, one generator process, loopback.** There is no network
  latency and no loss. A real network adds round-trip time per handshake;
  it adds client-side latency, but no server CPU, so it does not move the
  server's knee. The generator shares the machine; its CPU (≤ 0.8 cores
  below the knee) and its lag behind the schedule (≤ 17 ms) are reported per
  run, and it was not the limit.
- **macOS `fsync` does not flush the drive's cache** (SQLite does not ask for
  `F_FULLFSYNC`). A Linux host with a real `fsync`, especially on network
  storage, pays more per write transaction. Since the knee is set by how long
  the write lock is held, **expect it lower there**, possibly much lower on
  slow volumes. Re-measure on the target host with this tool. The write
  transactions per round (1, or 2 after a config change, 3 plus a `COUNT`
  for a registration) let the result be translated.
- **28 fast cores.** The knee here is contention, so more cores do not help
  (2 call threads did better than 28). A small tenant would hit CPU at about
  4–5 ms per round, so a 1-vCPU tenant would cap at a few hundred rounds/s,
  close to the same knee.
- **`warn` without a chain.** Under `enforce`, registration also verifies a
  chain (not measured; the verifier trusts only Google's roots). Steady-state
  rounds are the same.
- **The population was seeded,** not grown over months: the table has no
  history of key mismatches or old verdicts, and the audit log is small.
- Only the default Config API, one policy, no Play Integrity or App Attest
  verification. Those would add work per round.
