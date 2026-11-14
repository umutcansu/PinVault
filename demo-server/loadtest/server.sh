#!/bin/sh
# Starts one PinVault server for the load test (loadtest/README.md): the
# installDist build, ports 7300 (management), 7301 (Config API, TLS) and 7303
# (recovery), its own data directory. Runs in the foreground; logs to
# $DATA/server.log, GC log to $DATA/gc.log.
#
#   DATA=/path/to/dir HEAP=512m ./loadtest/server.sh
#
# Knobs (environment): DATA (required), HEAP (default 512m), CPUS (JVM
# -XX:ActiveProcessorCount, default unset = all cores), BASE_PORT (7300),
# LIMITS=raised|default (raised: per-address limits off, see README),
# EXTRA_JAVA_OPTS (e.g. a JFR or async-profiler agent).
set -eu
: "${DATA:?set DATA to a data directory for this server}"
HEAP=${HEAP:-512m}
BASE_PORT=${BASE_PORT:-7300}
LIMITS=${LIMITS:-raised}
HERE=$(cd "$(dirname "$0")/.." && pwd)
BIN="$HERE/build/install/pinvault-demo-server/bin/pinvault-demo-server"
[ -x "$BIN" ] || { echo "build first: (cd demo-server && ../gradlew installDist)" >&2; exit 1; }
for p in $BASE_PORT $((BASE_PORT+1)) $((BASE_PORT+3)); do
  if lsof -nP -iTCP:$p -sTCP:LISTEN >/dev/null 2>&1; then echo "port $p is in use" >&2; exit 1; fi
done
mkdir -p "$DATA/db" "$DATA/certs" "$DATA/keys"

export PORT=$BASE_PORT HTTPS_PORT=$((BASE_PORT+1)) RECOVERY_PORT=$((BASE_PORT+3))
export MANAGEMENT_BIND=127.0.0.1
export DB_PATH="$DATA/db/pinvault.db" CERTS_DIR="$DATA/certs" SIGNING_KEY_PATH="$DATA/keys/signing-key.pem"
export ALLOW_DEMO_SECRETS=true API_KEY=${API_KEY:-loadtest-admin-key-0123456789abcdef}
# First-key policy: warn, no chain (README: the verifier trusts only Google's roots).
export ATTESTATION_KEY_POLICY=warn
export ATTESTATION_PACKAGE_NAMES=com.example.sampleclient
export ATTESTATION_SIGNER_SHA256=00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9
export ATTESTATION_DEVICE_LIMIT=${ATTESTATION_DEVICE_LIMIT:-0}
if [ "$LIMITS" = raised ]; then
  # One generator = one source address: the per-address limits would refuse it
  # long before the server is busy. Per-device limits stay at their defaults.
  export ATTESTATION_RATE_LIMIT=0 DEVICE_REFUSAL_RATE_LIMIT=0 CONFIG_VIEW_SIGN_RATE_LIMIT=0
fi
JAVA_OPTS="-Xms$HEAP -Xmx$HEAP -Xlog:gc*:file=$DATA/gc.log:time,uptime:filecount=2,filesize=20m"
[ -n "${CPUS:-}" ] && JAVA_OPTS="$JAVA_OPTS -XX:ActiveProcessorCount=$CPUS"
export JAVA_OPTS="$JAVA_OPTS ${EXTRA_JAVA_OPTS:-}"
export JAVA_HOME=${JAVA_HOME:-$HOME/Library/Java/JavaVirtualMachines/jbr-17.0.14/Contents/Home}
cd "$DATA"
exec "$BIN" >>"$DATA/server.log" 2>&1
