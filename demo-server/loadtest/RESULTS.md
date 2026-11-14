# Load test results

Machine: Apple M3 Ultra (28 cores), macOS, JBR 17.0.14. Server and generator
on the same machine, over loopback. Server: `installDist` build of branch
`security/review-2026-11-14` (unreleased), `loadtest/server.sh`
(`ATTESTATION_KEY_POLICY=warn`, no chain, `ATTESTATION_POLICY_DEFAULT=strict`,
per-address limits off, ES256 tokens, local signing key, SQLite).

## Status (2026-11-15)

- **Smoke run: passed.** The ramp has **not been run yet**: an Android
  emulator (the E2E regression of the main checkout) was running, and a run
  heavier than a smoke test would make it flaky. The ramp, the profile and the
  heap comparison follow when the machine is free.

## Smoke runs (20 devices, 2 rounds/s, 30 s, a TLS connection per round)

| run | rounds ok | errors | round p50 / p95 / p99 (ms) | attest call p50 / p95 | challenge p50 / p95 | config embedded |
|---|---|---|---|---|---|---|
| `smoke` (fresh DB: first round of each device registers) | 60 / 60 | 0 | 29.1 / 50.5 / 313.9 | 11.7 / 18.6 | 13.1 / 27.1 | 20 (once per device, at registration) |
| `smoke-preload` (server restarted, devices hold the config) | 60 / 60 | 0 | 24.3 / 39.9 / 56.7 | 10.6 / 14.9 | 11.4 / 19.5 | 0 |

Every round: `result: pass`, a token, warning `key_unattested` (expected
under `warn` without a chain). Server stats agree: 60 passes, 0 rejects, 20
registered devices with `attestCount` 3. HTTP/2 was negotiated on every
connection. No `config_rollback` after a server restart with the preloaded
config. Generator: under 0.1 core, at most 6 ms behind its schedule.

The round's p50 (~25 ms at 2/s) is mostly two TLS handshakes' worth of round
trips plus ~10 ms of server time for the attest call — high for an idle
server; the profile is to show where it goes.

## Ramp

_Pending (machine busy)._ Per step: achieved rate, p50/p95/p99, errors by
kind, server CPU and RSS (`sample.sh`), GC log, SQLite contention.

## What reading the code predicts (to be confirmed by the ramp and the profile)

Per `POST /api/v1/attest` of a known device, the server does: a nonce MAC and
replay-cache insert; one ECDSA P-256 verify; a SQLite read of the device row;
the policy read; `AttestationTokenSecretStore.active()` (`@Synchronized`, a
SQLite read of every token key and an AES-GCM open of the active one, **on
every round**); one ES256 signature for the token; one SQLite write
transaction (`recordVerdict`, plus a watermark write when `currentIssuedAt`
rose). Every store call opens a new JDBC connection (`DatabaseManager`), with
no `journal_mode=WAL` and no `busy_timeout` set: the default rollback journal,
so each write transaction is several `fsync`s and writers serialize on the
database lock. A registration adds an `INSERT`, a `COUNT` of the Config API's
devices (`devices.counts`, for `ATTESTATION_DEVICE_LIMIT`) and an audit entry.

Hard ceilings independent of CPU:

- **Nonce replay cache: 100 000 entries kept for the 120 s nonce TTL →
  ~833 rounds/s**, above which rounds get `503 attestation_busy`
  (`AttestationNonces.maxCached`). At the 5-minute interval that is
  ~250 000 devices per instance.
- **Per-device limiter table: 10 000 live windows** (`RateLimiter.maxKeys`,
  10-minute windows). At the 5-minute interval every device attests within
  any 10 minutes, so a fleet of more than 10 000 devices (> ~33 rounds/s)
  keeps the table full of live windows: every round of a device not in it then runs
  `windows.values.removeIf {…}` over all 10 000 entries **inside the
  limiter's global lock**, and is let through uncounted (`FAIL_OPEN`) — the
  per-device limit silently stops applying to those devices, and the scan is
  a serialization point. Expected to show in the profile at the knee.
- **Narrowed config views** (`hosts` / `X-Device-Id`): one signed view per
  device id, held in a 512-entry cache (`SignedConfigService.MAX_ENTRIES`).
  A fleet with `wantPinsFor` larger than 512 devices misses the cache on
  practically every narrowed fetch and signs anew each time.

## Default per-address limits in a real deployment

`ATTESTATION_RATE_LIMIT=60` attestations per source address per 10 minutes
(challenges: 120) is 0.1 rounds/s per address. At the default 5-minute
interval a device makes 2 rounds per 10 minutes, so **30 devices per
address**. That is fine for phones on their own carrier addresses, tight for
a large carrier-grade NAT or a corporate Wi-Fi, and fatal behind a reverse
proxy or load balancer unless `TRUSTED_PROXIES` names it: then every device
has the proxy's address and the **whole fleet gets 30 devices' worth of
rounds**, the rest `429 rate_limited`. A hosted tenant behind a shared ingress
must set `TRUSTED_PROXIES` (or the ingress must preserve the client address).
`CONFIG_VIEW_SIGN_RATE_LIMIT=120` per address per 10 minutes limits narrowed
signings the same way. (Measuring this against a proxy is planned, not done.)

## Caveats

- One machine, one generator process, loopback network: no network latency,
  no packet loss, and the generator competes with the server for CPU and
  memory bandwidth (its CPU is reported per run).
- macOS `fsync` does not flush the drive's cache (SQLite does not use
  `F_FULLFSYNC` by default): SQLite write costs here are lower than on a Linux
  host with a real `fsync`. The write transactions per round are counted so
  the result can be translated.
- `-XX:ActiveProcessorCount` sizes the server's thread pools like a small
  tenant's but does not cap its CPU; a Docker `--cpus` run would.
