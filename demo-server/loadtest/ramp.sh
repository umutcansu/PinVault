#!/bin/sh
# One ramp against a running load-test server (loadtest/README.md):
#   KEYS=keys.txt OUT=dir ./loadtest/ramp.sh 10 25 50 100 200 400 …
# Each step offers RATE rounds/s for STEP seconds (after WARMUP s of the same
# rate) over RATE*INTERVAL devices of KEYS (each device about once per
# INTERVAL s, as in the field), samples the server's CPU and RSS, and stops
# after the first step whose p95 is over 1 s or whose errors are over 1 %.
# Knobs: STEP (180), WARMUP (30), INTERVAL (300), CONN (per-round), MIX
# (attest=1), TARGET (https://127.0.0.1:7301), LABEL (ramp).
set -eu
: "${KEYS:?KEYS=device keys file}" "${OUT:?OUT=results directory}"
STEP=${STEP:-180}; WARMUP=${WARMUP:-30}; INTERVAL=${INTERVAL:-300}
CONN=${CONN:-per-round}; MIX=${MIX:-attest=1}; TARGET=${TARGET:-https://127.0.0.1:7301}; LABEL=${LABEL:-ramp}
HERE=$(cd "$(dirname "$0")/.." && pwd)
PORT=$(echo "$TARGET" | sed -E 's#.*:([0-9]+).*#\1#')
PID=$(lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t)
mkdir -p "$OUT"
total=$(grep -c . "$KEYS")
for RATE in "$@"; do
  if ps ax | grep -q "[q]emu-system"; then echo "an emulator is running: stopping the ramp before $RATE/s" >&2; exit 4; fi
  devices=$(awk -v r="$RATE" -v i="$INTERVAL" -v t="$total" 'BEGIN { d = int(r * i); if (d > t) d = t; if (d < 1) d = 1; print d }')
  "$HERE/loadtest/sample.sh" "$PID" "$OUT/$LABEL-$RATE.server.csv" 2 & SAMPLER=$!
  set +e
  (cd "$HERE" && ../gradlew -q loadtest --args="run --target $TARGET --keys $KEYS --devices $devices --rate $RATE \
      --duration $STEP --warmup $WARMUP --conn $CONN --mix $MIX --label $LABEL-$RATE --out $OUT/$LABEL.jsonl") \
      | tee "$OUT/$LABEL-$RATE.log" | grep --line-buffered -E "SUMMARY|KNEE|t=[0-9]+s\]" | cut -c1-300
  rc=$(grep -q KNEE "$OUT/$LABEL-$RATE.log" && echo 3 || echo 0)
  set -e
  kill "$SAMPLER" 2>/dev/null || true
  if [ "$rc" = 3 ]; then echo "knee reached at $RATE/s"; break; fi
done
