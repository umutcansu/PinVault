# Load test: attestation rounds and config fetches on one server

How many attestation rounds (and config fetches) one PinVault server instance
sustains, where it breaks, and why. Results: [RESULTS.md](RESULTS.md).

The generator is the `loadtest` source set of `demo-server`
(`src/loadtest/kotlin`). It is compiled against the server's own classes, so a
report is signed over `AttestationService.canonical(…)` — exactly the string
the server verifies — but it is not part of the server's jar, `installDist`
or Docker image.

## What it simulates

N devices, each with its own P-256 key and device id (`keys` command). A
**round** is what the Android library does every `attestIntervalSeconds`
(300 s by default):

1. `GET /api/v1/attest/challenge`
2. build a clean Android report (ATTESTATION.md §3, the sample app's package
   and signer), sign `pinvault-attest:v1:<nonce>:<deviceId>:<sha256(report)>`
   with SHA256withECDSA
3. `POST /api/v1/attest` with `currentConfigVersion` / `currentIssuedAt` of
   the config the device holds

A round counts as **ok only for `result: pass` with a `token`**; a reject is
also HTTP 200 and is counted as an error (`200:reject:<arc>`). Other errors
are counted by status and the body's `error` (`503:attestation_busy`,
`429:rate_limited`, …) or by exception (`io:…`).

The first round of a device the server has never seen **registers** it.
First-key policy under test: `ATTESTATION_KEY_POLICY=warn` with **no
attestation chain** (`keyAttested: false` in the report). `enforce` cannot be
run against a real server process: its verifier trusts only Google's hardware
roots, and there is (rightly) no setting to trust a test root. A chain is
checked once per device at registration and never again, so steady-state
rounds — what a fleet does all day — cost the same under `warn` and
`enforce`; only the registration burst differs.

Optional mix (`--mix`):

| entry | what |
|---|---|
| `attest` | a round, no `hosts` (the full config is embedded when the device is behind) |
| `attest-narrow` | a round with `hosts` (`wantPinsFor`): the embedded config is narrowed per device |
| `config-full` | `GET /api/v1/certificate-config` with `X-PinVault-Features: redelivery,multisig,keyset`, no scoping (served from the signature cache) |
| `config-narrow` | the same with `?hosts=…` and `X-Device-Id`: one signed view per device id |

Token-protected requests are not part of the mix: the PinVault server does
not verify tokens on its own paths (backends do, with the JWKS).

**Open loop.** Operations start on a fixed schedule (one every `1/rate` s)
whatever the server does; latency is measured from the scheduled start, so a
slow server shows up as latency, not as a lower offered rate. Latencies are
recorded per request in HdrHistogram (µs). The generator reports its own lag
behind the schedule, its peak in-flight count and its CPU, so a run where the
generator was the limit can be told apart.

**Connections.** `--conn per-round` (default): each round opens its own TLS
connection (challenge and attest on it, then closed), with a fresh TLS
session unless `--tls-resume true` — a phone that re-attests every 5 minutes
has usually lost its pooled connection. HTTP/2 is negotiated as the library's
OkHttp would. `--conn pooled`: one shared HTTP/1.1 keep-alive pool (no
handshakes; an upper bound, not a fleet).

**Fleet state.** `--preload-config true` (default): every device starts with
the version and `issuedAt` of the full config the server serves now — a
fleet that has been running holds it, so rounds do not embed it. A device
then remembers what an attest answer embedded.

## Running it

From `demo-server/`, JDK 17 (`export JAVA_HOME=$HOME/Library/Java/JavaVirtualMachines/jbr-17.0.14/Contents/Home`):

```sh
../gradlew installDist compileLoadtestKotlin

# 1. a server of its own: ports 7300 (management), 7301 (Config API, TLS), 7303 (recovery)
DATA=/some/empty/dir HEAP=512m ./loadtest/server.sh &

# 2. two pins on default-tls (the config the devices fetch)
curl -X PUT http://127.0.0.1:7300/api/v1/certificate-config \
  -H 'X-API-Key: loadtest-admin-key-0123456789abcdef' -H 'Content-Type: application/json' \
  -d '{"pins":[{"hostname":"api.example.com","sha256":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb="]},
              {"hostname":"cdn.example.com","sha256":["ccccccccccccccccccccccccccccccccccccccccccc=","ddddddddddddddddddddddddddddddddddddddddddd="]}]}'

# 3. device keys, a smoke run (every round must pass), registration of a population
../gradlew -q loadtest --args="keys --devices 20 --keys /tmp/keys-smoke.txt"
../gradlew -q loadtest --args="run --keys /tmp/keys-smoke.txt --rate 2 --duration 30 --label smoke"
../gradlew -q loadtest --args="keys --devices 120000 --keys /tmp/keys.txt"
../gradlew -q loadtest --args="run --keys /tmp/keys.txt --rate 200 --duration 600 --label register"

# 4. a ramp (stop the server, snapshot DATA after registration, restore it per heap setting)
KEYS=/tmp/keys.txt OUT=/tmp/lt ./loadtest/ramp.sh 10 25 50 100 200 400 800
```

Before any run longer than a smoke test, make sure no Android emulator is
running on the machine (`ps ax | grep qemu-system`): `ramp.sh` refuses to
start a step while one is.

### `run` knobs

| knob | default | meaning |
|---|---|---|
| `--target` | `https://127.0.0.1:7301` | the Config API listener |
| `--keys` | `loadtest-keys.txt` | device keys file (`keys` command); `--devices N` uses the first N |
| `--rate` | 10 | operations started per second (open loop) |
| `--duration` / `--warmup` | 30 / 0 | measured seconds; seconds at the same rate before them, not counted |
| `--mix` | `attest=1` | shares of the schedule, e.g. `attest=0.8,config-full=0.2` |
| `--hosts` | `api.example.com,cdn.example.com` | the `hosts` of narrowed requests |
| `--conn` | `per-round` | `per-round` (a TLS connection per round) or `pooled` (keep-alive, HTTP/1.1) |
| `--tls-resume` | false | per-round connections may resume an earlier TLS session |
| `--preload-config` | true | devices start holding the current full config |
| `--max-inflight` | 4000 | past it a slot is counted as `gen:max_inflight` instead of sent |
| `--stop-p95-ms` / `--stop-error-ratio` | 1000 / 0.01 | the step "broke": prints `KNEE`, exit code 3 |
| `--label` / `--out` | `run` / none | name of the run; JSON summary line appended to this file |
| `--report-every` | 10 | seconds between progress lines |

### `server.sh` knobs (environment)

`DATA` (required), `HEAP` (`-Xms`/`-Xmx`, default `512m`), `CPUS`
(`-XX:ActiveProcessorCount`: thread pools sized as on a small tenant; it does
not cap CPU), `BASE_PORT` (7300), `LIMITS=raised|default`,
`EXTRA_JAVA_OPTS` (JFR, async-profiler agent). GC log in `$DATA/gc.log`,
server log in `$DATA/server.log`.

`LIMITS=raised` (default) sets `ATTESTATION_RATE_LIMIT=0`,
`DEVICE_REFUSAL_RATE_LIMIT=0` and `CONFIG_VIEW_SIGN_RATE_LIMIT=0`: one
generator is one source address, and the per-address limits (60 attestations
/ 120 challenges / 120 narrowed signings per address per 10 minutes) would
refuse it long before the server is busy. Addresses are not faked. The
per-device limit (`ATTESTATION_DEVICE_RATE_LIMIT`, 30 per 10 min) stays at
its default: with a population of `rate × 300` devices each device attests
about twice per 10 minutes. `ATTESTATION_DEVICE_LIMIT=0` (no cap on
registered devices) so a large population can register.

`sample.sh PID OUT.csv` samples the server's CPU and RSS; `ramp.sh` runs it
for every step.
