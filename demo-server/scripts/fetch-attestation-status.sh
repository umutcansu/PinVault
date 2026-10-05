#!/usr/bin/env sh
# Fetches Google's Android key attestation status list (revoked and suspended
# attestation certificates) into the file ATTESTATION_REVOKED_SERIALS_FILE
# points at. The server never goes to the network for it: it re-reads the file
# when its modification time changes (looked at every 10 minutes), and with
# ATTESTATION_STATUS_MAX_AGE_HOURS set it lets no attestation pass once the
# file is older than that — so run this from cron, e.g. every 6 hours:
#
#   0 */6 * * *  /opt/pinvault/scripts/fetch-attestation-status.sh /data/attestation-status.json
#
# The new list is written next to the target and moved over it in one rename,
# only after it downloaded completely and looks like the status list: the
# server never reads a half-written or error page. On any failure the old file
# stays as it is (and ages, which ATTESTATION_STATUS_MAX_AGE_HOURS notices).
#
# Usage: fetch-attestation-status.sh <target file> [url]
set -eu

TARGET="${1:?usage: fetch-attestation-status.sh <target file> [url]}"
URL="${2:-https://android.googleapis.com/attestation/status}"
DIR="$(dirname "$TARGET")"
TMP="$(mktemp "$DIR/.attestation-status.XXXXXX")"
trap 'rm -f "$TMP"' EXIT INT TERM

# --fail: an HTTP error is an error, not a file. No -R: the file's time is the
# time of this download, which is what the server measures the age by.
curl --silent --show-error --fail --location --proto '=https' --tlsv1.2 \
  --max-time 60 --retry 3 --retry-delay 5 \
  --header 'Cache-Control: no-cache' \
  --output "$TMP" "$URL"

# The list is a JSON object with an "entries" member; anything else (an empty
# body, a captive portal's HTML) is refused rather than installed.
if ! head -c 4096 "$TMP" | grep -q '"entries"'; then
  echo "fetch-attestation-status: $URL did not return the status list; keeping $TARGET" >&2
  exit 1
fi

chmod 0644 "$TMP"
mv -f "$TMP" "$TARGET"
trap - EXIT INT TERM
echo "fetch-attestation-status: $TARGET updated ($(wc -c < "$TARGET" | tr -d ' ') bytes)"
