# Load test results (2026-11-15)

## After the fixes (re-measured 2026-11-15)

The fixes, made after the first measurement below:

- Identity-keyed rate limits never let a request through uncounted; tables
  are bounded and expire in O(1).
- The active token key is kept in memory, not read from SQLite under a lock
  on every round.
- SQLite runs in WAL mode with `busy_timeout=5000` and `synchronous=NORMAL`.
- One connection stays open for the life of the process, so the WAL is not
  checkpointed and deleted every time the last per-call connection closes.

The setup, the generator and the data are the same as before: 150 000
registered devices, a TLS connection per round, open loop, 512 MB heap,
steps of 90 s after 20 s of warm-up.

| | before | after, 28 cores | after, pools for 2 processors |
|---|---|---|---|
| Steady state (the device's config unchanged) | knee 250–300/s (≈ 75 000–90 000 devices) | **clean at 800/s** (≈ 240 000 devices); the next limit is the nonce cache at ~833/s (≈ 250 000 devices) | **clean at 300/s, p95 0.32 s at 400/s**, breaks at 500/s (≈ 120 000 devices at 400/s) |
| Every round also writes its watermark (the cycle after a config change) | knee 150–180/s (≈ 45 000–54 000 devices) | **clean at 800/s** | **clean at 300/s, p95 0.29 s at 400/s** |
| Registration (a device's first round) | ~50 new devices/s | **clean at 800 new devices/s** | **clean at 200/s**, ~360/s at most |

Device counts are rounds/s × 300 (the default 5-minute interval). The
28-core runs were made before the kept connection was added (it changes
nothing measurable with 28 call threads). The "pools for 2 processors" runs
(`-XX:ActiveProcessorCount=2`) include it.

### Steady state, 28 cores, 512 MB

| offered/s | devices | ok/s | p50 ms | p95 ms | p99 ms | errors | server CPU avg / max (cores) | RSS max MB |
|---|---|---|---|---|---|---|---|---|
| 250 | 75000 | 249.9 | 7.82 | 10.0 | 12.42 | 0 % | 1.58 / 6.32 | 795 |
| 300 | 90000 | 299.8 | 7.48 | 10.26 | 13.34 | 0 % | 1.57 / 1.84 | 804 |
| 400 | 120000 | 399.7 | 7.7 | 14.04 | 48.1 | 0 % | 1.93 / 2.31 | 815 |
| 500 | 150000 | 499.7 | 7.73 | 82.88 | 576.51 | 0 % | 2.27 / 5.28 | 832 |
| 600 | 180000 | 599.8 | 7.32 | 28.94 | 147.07 | 0 % | 2.64 / 3.21 | 848 |
| 800 | 240000 | 799.5 | 7.08 | 20.83 | 161.02 | 0 % | 3.62 / 5.98 | 870 |
| 1000 | 250000 | 888.4 | 6.62 | 10.56 | 14.74 | **11.1 % `503 attestation_busy`** | 4.11 / 5.09 | 875 |

At 1000/s the server answered fast (p95 11 ms) and refused 10 000 rounds
with `503 attestation_busy`. The nonce replay cache was full: it holds
100 000 nonces for the 120 s nonce lifetime, ≈ 833 rounds/s. That is a
deliberate fail-closed bound (a nonce is never forgotten while it could
still be presented), not a load problem. At 800/s the server used ~3.6 cores,
so CPU becomes the next limit on a smaller machine. (The 400–500/s p99
blips are single GC or checkpoint pauses; they do not repeat at 600–800/s.)

### Every round writes its watermark, 28 cores, 512 MB

Devices with no watermark on record and a freshly signed config: every round
writes `recordConfigWatermark` as well as the verdict. Checked in the
database: every device that attested had its watermark written.

| offered/s | devices | ok/s | p50 ms | p95 ms | p99 ms | errors | server CPU avg / max | RSS max MB |
|---|---|---|---|---|---|---|---|---|
| 150 | 45000 | 149.9 | 8.96 | 11.02 | 12.65 | 0 % | 1.11 / 4.29 | 779 |
| 200 | 60000 | 199.9 | 8.82 | 11.98 | 16.78 | 0 % | 1.25 / 1.52 | 786 |
| 300 | 90000 | 299.8 | 9.13 | 21.33 | 74.43 | 0 % | 1.69 / 2.00 | 798 |
| 400 | 120000 | 399.8 | 8.78 | 36.8 | 1 237 | 0 % | 2.02 / 3.50 | 810 |
| 600 | 180000 | 599.7 | 7.92 | 29.28 | 162.94 | 0 % | 2.94 / 3.50 | 828 |
| 800 | 240000 | 799.5 | 7.4 | 26.35 | 394.24 | 0 % | 3.77 / 4.53 | 850 |

### Registration, 28 cores, 512 MB (a fresh database, every device new)

| offered/s | new devices | ok/s | p50 ms | p95 ms | p99 ms | errors | server CPU avg / max |
|---|---|---|---|---|---|---|---|
| 100 | 6000 | 99.9 | 11.82 | 16.74 | 71.3 | 0 % | 1.06 / 3.42 |
| 200 | 12000 | 199.8 | 11.48 | 21.63 | 185.22 | 0 % | 1.43 / 1.93 |
| 400 | 24000 | 399.6 | 12.2 | 1 883 | 3 281 | 0 % | 2.45 / 5.26 |
| 400 (again) | 24000 | 399.6 | 10.13 | 18.61 | 31.94 | 0 % | – |
| 800 | 48000 | 798.5 | 9.22 | 31.71 | 81.22 | 0 % | 4.52 / 5.18 |

The first 400/s step had one 746 ms young-GC pause in the middle (G1, 512 MB
heap, a registration writes more garbage than a round); the same step again
was clean. 100 000 new devices register in a little over 2 minutes at 800/s,
against more than half an hour before.

### Thread pools sized for 2 processors, 512 MB (`-XX:ActiveProcessorCount=2`)

Steady state:

| offered/s | devices | ok/s | p50 ms | p95 ms | p99 ms | errors | server CPU avg / max | RSS max MB |
|---|---|---|---|---|---|---|---|---|
| 200 | 60000 | 199.9 | 6.2 | 7.58 | 12.39 | 0 % | 0.99 / 3.00 | 615 |
| 300 | 90000 | 299.8 | 5.82 | 7.24 | 13.71 | 0 % | 1.22 / 1.70 | 624 |
| 400 | 120000 | 399.6 | 5.74 | 318.72 | 347.14 | 0 % | 1.53 / 1.98 | 636 |
| **500** | 150000 | 499.1 | 2 019 | **4 293** | 4 903 | 0 % | 2.11 / 2.78 | 780 |

Every round writes its watermark:

| offered/s | devices | ok/s | p50 ms | p95 ms | p99 ms | errors | server CPU avg / max | RSS max MB |
|---|---|---|---|---|---|---|---|---|
| 200 | 60000 | 199.9 | 6.32 | 8.0 | 8.9 | 0 % | 1.05 / 3.07 | 600 |
| 300 | 90000 | 299.8 | 6.12 | 7.61 | 11.06 | 0 % | 1.25 / 1.56 | 609 |
| 400 | 120000 | 398.8 | 70.91 | 286.98 | 364.8 | 0 % | 1.57 / 1.87 | 630 |

Registration:

| offered/s | new devices | ok/s | p50 ms | p95 ms | p99 ms | errors | server CPU avg / max |
|---|---|---|---|---|---|---|---|
| 200 | 12000 | 199.8 | 7.58 | 9.61 | 25.94 | 0 % | 1.35 / 3.35 |
| **400** | 24000 | 360.4 | 5 415 | **11 960** | 12 526 | 0 % | 1.87 / 2.68 |

**Why the kept connection matters here.** Before it was added, the same
2-processor server did *worse* than before the fixes: 200/s clean, but 300/s
reached only 264/s with p95 26 s. The JFR profile showed no lock contention
and only crypto and TLS in Java code. The cost was in SQLite's native
`close` and `prepare`: with 2 call threads the number of open connections
often fell to zero, and in WAL mode the close of the last connection
checkpoints the whole WAL into the database file and deletes it, on nearly
every request. With one connection held open for the process
(`DatabaseManager(keepOpen = true)` in `Main`; closed at JVM shutdown, which
checkpoints once), 300/s is clean again with p95 7 ms.

### What a server instance with 512 MB heap and 1–2 vCPU should be sized for

- **CPU is the limit on a small instance.** The server spends about 4–5 ms
  of CPU per round, including two TLS handshakes (a new connection per
  round, as phones re-attest after their pooled connection is gone). At
  400 rounds/s it used 1.5–2 cores. `-XX:ActiveProcessorCount=2` only sizes
  the thread pools; a real 2-vCPU cap reaches its CPU limit about there.
- **2 vCPU:** plan for **~300 rounds/s ≈ 90 000 devices** at the 5-minute
  interval. That rate is clean (p95 under 10 ms) in both the steady state and
  the after-change cycle, and leaves room for the burst after a pin change.
  Registration bursts: ~200 new devices/s sustained.
- **1 vCPU:** plan for about half of that, **~150 rounds/s ≈ 45 000
  devices**. Not measured with a real 1-vCPU cap; this is the CPU per round
  scaled.
- **Memory:** 512 MB heap is enough (live data after a young GC 100–260 MB,
  no full GC). RSS was 600–870 MB, so the container's memory limit needs
  about **1 GB**.
- **Settings:**
  - `-XX:ActiveProcessorCount` equal to the vCPUs.
  - `DB_JOURNAL_MODE=wal` (the default) on a local disk, never a network
    filesystem.
  - `ATTESTATION_DEVICE_LIMIT` set to the expected fleet: it also sizes the
    per-device rate-limit table.
  - `TRUSTED_PROXIES` for the proxy in front, with `TRUSTED_PROXIES_LISTENERS`
    naming only the listeners behind it (usually `config-api`). Without them
    the per-address limits count the whole fleet as one address.
  - Back up the whole `data/db` directory, or with `sqlite3 .backup` while
    the server runs.
- **Re-measure on the target host.** This machine's `fsync` does not flush
  the drive (macOS), and the instance shared a 28-core machine with the
  generator. With WAL and `synchronous=NORMAL` there are far fewer syncs than
  before, but slow network storage would still lower the numbers.

Raw data for these runs: `results/a512*`, `w512*`, `g512*` (28 cores),
`k2*`, `w2*`, `g2*` (pools for 2 processors, kept connection), `t2*` (pools
for 2 processors, before the kept connection).

---

## Before the fixes (first measurement)

**One server instance sustains about 250 attestation rounds/s with p95 under
10 ms. It breaks between 250 and 300 rounds/s; at the default 5-minute
interval that is about 75 000–90 000 devices.** The limit is not CPU: at the
knee the server uses about 1.3 of 28 cores. It is serialization: a global
lock around the token signing key, which reads SQLite on every round, while
every round also writes to SQLite through a fresh connection in rollback-journal
mode. Two things drop the knee well below that:

- **A round whose device reports a newer config than before** also writes the
  device's config watermark. With the signature cache off (the default with a
  local key, `CONFIG_SIGNATURE_CACHE`), every config fetch is signed anew with
  a new `issuedAt`. So the first round after any fetch writes: an app start's
  fetch, the half-TTL refresh, and every device in the cycle after a config
  change. With every round writing, 150/s was clean, 180/s broke, and
  throughput under overload was ~120–140/s. That is a knee of **150–180
  rounds/s (≈ 45 000–54 000 devices)**.
- **Registration** (a device's first round) saturates at **~50 new devices/s**.

Config fetches are light: 2 000 full fetches/s (p95 3 ms, a new TLS connection
and a fresh signature each) and 500 narrowed fetches/s that each miss the
narrowed cache (p95 4 ms, 1.1 cores) passed without errors.

Smoke run first (20 devices, 30 s, 2 rounds/s): 60/60 rounds `pass` with a
token, twice (a fresh database, then a restart with the config preloaded).

Raw data: `results/*.jsonl` (one summary line per run) and
`results/*.server.csv` (server CPU % and RSS every 2 s). Tables made with
`perl loadtest/table.pl loadtest/results <label>`.

### Setup

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

### Steady state, 512 MB heap (knee 250–300/s)

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

### Heap: 2 GB instead of 512 MB (no change in the knee)

| offered/s | ok/s | p50 ms | p95 ms | p99 ms | errors | server CPU avg (cores) | RSS max MB |
|---|---|---|---|---|---|---|---|
| 200 | 199.9 | 6.96 | 8.58 | 9.69 | 0 % | 0.99 | 1754 |
| 250 | 249.9 | 6.72 | 8.22 | 19.63 | 0 % | 1.04 | 1759 |
| **300** | 295.2 | 583 | **2 746** | 3 867 | 0 % | 1.31 | 1781 |

GC was never the issue. At 512 MB, live data after a young GC averaged
130 MB (max 258 MB); 394 young pauses took 0.7 s in all (one of 121 ms, the
rest a few ms), with no full GC. At 2 GB there were 60 young pauses (148 ms
in all, max 7 ms). RSS goes from ~0.78 GB to ~1.75 GB for the same
throughput: **512 MB is enough for one instance at this load**. The larger heap
only shortens the overloaded tail a little.

### Smaller thread pools: `-XX:ActiveProcessorCount=2`, 512 MB (knee 300–400/s)

| offered/s | ok/s | p50 ms | p95 ms | p99 ms | errors | server CPU avg / max | RSS max MB |
|---|---|---|---|---|---|---|---|
| 250 | 249.9 | 6.63 | 8.12 | 11.97 | 0 % | 1.01 / 1.30 | 625 |
| 300 | 299.8 | 6.41 | 8.41 | 15.92 | 0 % | 1.20 / 1.48 | 632 |
| **400** | 306.9 | 12 689 | **13 566** | 13 812 | 16.6 % (generator in-flight cap) | 1.51 / 2.00 | 776 |

With the thread pools sized for 2 processors instead of 28, the server does
**better**: it is clean at 300/s and peaks at ~307/s. (How many call threads
Ktor made was not checked.) Fewer threads competing for the same SQLite lock
and the same monitor waste less time. That confirms the knee is contention,
not capacity. (This flag sizes the thread pools; it does not cap CPU. The
server here used up to 2 cores.)

### When every round writes its watermark (knee 150–180/s)

In the first ramp every round reported a newer `currentIssuedAt` than the
server had on record, so every round also wrote it (`recordConfigWatermark`):
a second write transaction per round. (The generator preloaded the envelope
the server served at the start of each run. With the signature cache off,
the default with a local key, every fetch is signed anew with a new
`issuedAt`.) In the field this is the first round after any fetch of a new
envelope: after an app start that fetches the config, after the half-TTL
refresh (12 h with the default 24 h TTL), and for every device in the cycle
after a config change (that round embeds the new config, and the next one
reports it). How often a real device fetches was not measured; it decides
what share of rounds pays this second write.

| offered/s | devices | ok/s | p50 ms | p95 ms | p99 ms | errors | server CPU avg / max | RSS max MB |
|---|---|---|---|---|---|---|---|---|
| 10 | 3000 | 10.0 | 22.9 | 31.18 | 32.43 | 0 % | 0.17 / 0.61 | 741 |
| 25 | 7500 | 25.0 | 16.32 | 21.26 | 22.43 | 0 % | 0.19 / 0.61 | 758 |
| 50 | 15000 | 50.0 | 13.61 | 17.58 | 18.61 | 0 % | 0.29 / 1.32 | 773 |
| 100 | 30000 | 100.0 | 9.48 | 10.95 | 11.8 | 0 % | 0.45 / 0.64 | 774 |
| 150 (separate run) | 45000 | 149.9 | 8.28 | 10.01 | – | 0 % | – | – |
| 180 (separate run) | 54000 | 121.6 | 20 103 | 40 436 | – | 7.1 % | – | – |
| **200** | 60000 | 129.5 | 27 558 | **39 485** | 45 122 | 23.6 % (generator in-flight cap 7474, timeouts 75) | 0.79 / 1.83 | 862 |

Throughput under overload was about 120–140/s (150/s was clean in one 90 s
run, 180/s broke), and the server used under one core.
Under overload, challenges (which never touch the database) also wait
seconds: the 28 call threads are all busy in `POST /api/v1/attest`. Three
`SQLITE_BUSY` errors reached the log as `500`.

**What this means in practice:** a fleet sized for the steady-state knee
(say 200 rounds/s) overloads for about one attestation interval after every
pin change, because every device writes its watermark in the same few
minutes. The safe sizing is below this knee, **~120–150 rounds/s ≈ 36 000–45 000
devices per instance**, until the fixes below are in.

(The high p50 at 10–25/s is the latency of an idle machine: CPU frequency
and power states, cold caches. It falls as load rises.)

### Registration: ~50 new devices/s

200 new devices/s offered (fresh database, 12 000 new ids): **28.5/s
registered successfully on average, 45–50/s at best**, p95 39 s, 79 % of
the offered rounds failed (generator in-flight cap, client timeouts, one
`500` `SQLITE_BUSY`). The server used 0.6 cores on average. A registration
writes four times (insert, audit entry, verdict, watermark) and runs a `COUNT`
of the Config API's devices (`ATTESTATION_DEVICE_LIMIT`). For comparison,
`seed`, one uncontended writer through the same store, registered
**~1 140 devices/s** (145 182 in 128 s). The disk is not the limit; contention
is. Onboarding 100 000 devices at once (a new customer, an app update that
loses keys) takes more than half an hour, and the instance is saturated for
that whole time.

### Config fetches (2 GB server, 60 s each, a TLS connection per request)

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

### Profile at the knee (JFR, 300/s steady state, and 180/s after a change)

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
  write transaction (verdict), plus 1 write for the watermark when the device reports a newer
  config (after any fetch of a new envelope). Each opens and closes its own connection.
- **CPU** (only ~1.3 cores at 300/s; JFR execution samples by subsystem. These
  cover threads running Java code only: time in SQLite's native code and in
  socket I/O is not in them):
  report ECDSA verification 42 %, TLS (handshakes, X25519, the certificate
  signature) 27 %, token ES256 signing and key loading 21 %, the per-device
  rate limiter's table scan 7 %, JSON 1 %. Nonces, policy evaluation and
  Netty/Ktor are negligible. That is about **4–5 ms of CPU per round including
  two TLS handshakes**: on a 1-vCPU instance, CPU would cap a round rate in the
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

### What would move the knee most (at the time; both are now done, see the top)

1. **Take the token signing key off the per-round path.** Keep the active
   signing key in memory and invalidate it on rotate and delete, the way
   `verificationKeys()` already caches for a few seconds. This removes
   the global monitor and one SQLite read from every round, so the profile's
   top contention site goes away. How far the knee moves was not measured: the
   thread holding that monitor is itself waiting on SQLite, so this alone may
   mostly move the queue to the database. It weakens nothing: the same
   key signs, and a rotation still takes effect at once on this instance.
   Small, but it is key-handling code, so it should go through a review
   rather than land with the load test.
2. **SQLite: WAL mode, a `busy_timeout`, and reused connections** (a small
   pool, or one writer connection behind a queue for the attestation writes).
   With WAL, readers stop waiting on the writer; reused connections drop the
   per-call open and schema parse; one writer stops the busy-handler backoff.
   Evidence: one uncontended writer does ~1 140 transactions/s while the
   contended server collapses at ~140–300 rounds/s, and pools sized for 2
   processors beat 28. This is probably the larger lever, certainly for the
   watermark-write and registration knees, but neither fix was tried here; the
   two together are what the evidence points at.

Also worth fixing, for correctness more than speed: the per-device limiter's
10 000-key table. Size it to the device limit, or count devices that do not
fit, so the limit actually holds for large fleets.

### Default per-address limits in a real deployment

Measured: with the default limits (`LIMITS=default`), 2 rounds/s from one
address over 1 000 devices. **The first 60 rounds passed, the next 60 got
`429 rate_limited`**, and the challenges kept passing until their own budget
of 120 ran out. `ATTESTATION_RATE_LIMIT=60` per address per 10 minutes is 0.1
rounds/s per address, which is **30 devices per address** at the 5-minute
interval. That is fine for phones on their own carrier addresses, tight
behind a carrier-grade NAT or a corporate Wi-Fi, and fatal behind a reverse
proxy or ingress unless `TRUSTED_PROXIES` names it. Without that, every device
has the proxy's address and **the whole instance gets 30 devices' worth of
rounds**. A server behind a shared proxy must set `TRUSTED_PROXIES`
(and the ingress must pass the client address). `CONFIG_VIEW_SIGN_RATE_LIMIT`
(120 narrowed signings per address per 10 minutes) behaves the same way.

### How representative this is

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
  (pools sized for 2 processors did better than 28). A small instance would hit CPU at about
  4–5 ms per round, so a 1-vCPU instance would cap at a few hundred rounds/s,
  close to the same knee.
- **`warn` without a chain.** Under `enforce`, registration also verifies a
  chain (not measured; the verifier trusts only Google's roots). Steady-state
  rounds are the same.
- **The population was seeded,** not grown over months: the table has no
  history of key mismatches or old verdicts, and the audit log is small.
- Only the default Config API, one policy, no Play Integrity or App Attest
  verification. Those would add work per round.
