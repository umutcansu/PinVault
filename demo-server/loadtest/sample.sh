#!/bin/sh
# Samples a process's CPU (% of one core) and RSS every few seconds:
#   ./loadtest/sample.sh PID OUT.csv [SECONDS]
# Columns: epoch_seconds,cpu_percent,rss_kb,threads
set -eu
PID=$1; OUT=$2; EVERY=${3:-5}
echo "epoch,cpu_percent,rss_kb,threads" >"$OUT"
while kill -0 "$PID" 2>/dev/null; do
  line=$(ps -o %cpu=,rss= -p "$PID" | awk '{print $1","$2}')
  threads=$(ps -M -p "$PID" | tail -n +2 | wc -l | tr -d ' ')
  echo "$(date +%s),$line,$threads" >>"$OUT"
  sleep "$EVERY"
done
