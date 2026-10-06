#!/usr/bin/env sh
# INTEGRITY_VERIFIER_COMMAND for Google Play Integrity.
#
# The server runs this once per enrollment that carries an integrity token
# (INTEGRITY_VERIFICATION=warn|enforce). It reads one JSON object on stdin,
#   {"token": "<integrity token>", "requestHash": "<43 chars>", "deviceId": "..."}
# asks Google to decode the token (decodeIntegrityToken, with a service
# account), checks the verdict and prints one JSON object on stdout:
#   {"passed": true,  "summary": "MEETS_DEVICE_INTEGRITY, PLAY_RECOGNIZED"}
#   {"passed": false, "reason": "device_integrity", "summary": "..."}
# A failure of its own (no credentials, Google unreachable) is a non-zero exit
# with the reason on stderr: the server records it as `verifier_error` and,
# under enforce, refuses the enrollment without spending its token.
#
# NOT TESTED against Google from this repository: it follows the documented
# decodeIntegrityToken API (v1). Try it with a real device and a warn-mode
# server before enforcing.
#
# Settings (environment; every INTEGRITY_* variable reaches the command):
#   INTEGRITY_PLAY_PACKAGE               the app's package name (required)
#   INTEGRITY_PLAY_SERVICE_ACCOUNT_FILE  service account JSON key of the Google
#                                        Cloud project linked in Play Console
#                                        (required; keep it 0600, out of /data
#                                        backups)
#   INTEGRITY_PLAY_DEVICE_VERDICT        the device label that must be present:
#                                        MEETS_DEVICE_INTEGRITY (default),
#                                        MEETS_STRONG_INTEGRITY, MEETS_BASIC_INTEGRITY
#   INTEGRITY_PLAY_REQUIRE_LICENSED      true: the user must have the app from
#                                        Play (appLicensingVerdict LICENSED)
#   INTEGRITY_PLAY_MAX_AGE_SECONDS       oldest token accepted (default 300)
#   INTEGRITY_PLAY_CACHE_DIR             where the OAuth access token is kept
#                                        between runs (default ${TMPDIR:-/tmp})
#
# Needs curl, openssl and jq. Example server setting:
#   INTEGRITY_VERIFICATION=enforce
#   INTEGRITY_VERIFIER_COMMAND=/opt/pinvault/scripts/play-integrity-verify.sh
set -eu

die() { echo "play-integrity-verify: $*" >&2; exit 1; }
answer() { # $1 = passed (true|false), $2 = reason, $3 = summary
  jq -cn --argjson passed "$1" --arg reason "$2" --arg summary "$3" \
    '{passed: $passed} + (if $reason == "" then {} else {reason: $reason} end) + {summary: $summary}'
  exit 0
}

for tool in curl openssl jq; do command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"; done
PACKAGE="${INTEGRITY_PLAY_PACKAGE:?INTEGRITY_PLAY_PACKAGE is not set}"
SA_FILE="${INTEGRITY_PLAY_SERVICE_ACCOUNT_FILE:?INTEGRITY_PLAY_SERVICE_ACCOUNT_FILE is not set}"
DEVICE_VERDICT="${INTEGRITY_PLAY_DEVICE_VERDICT:-MEETS_DEVICE_INTEGRITY}"
REQUIRE_LICENSED="${INTEGRITY_PLAY_REQUIRE_LICENSED:-false}"
MAX_AGE="${INTEGRITY_PLAY_MAX_AGE_SECONDS:-300}"
CACHE_DIR="${INTEGRITY_PLAY_CACHE_DIR:-${TMPDIR:-/tmp}}"
[ -r "$SA_FILE" ] || die "cannot read $SA_FILE"
case "$PACKAGE" in *[!A-Za-z0-9._]*|'') die "INTEGRITY_PLAY_PACKAGE is not a package name" ;; esac

umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

# ── The request ──────────────────────────────────────────────────────────
INPUT="$(cat)"
TOKEN="$(printf '%s' "$INPUT" | jq -er '.token | strings')" || die "no token on stdin"
EXPECTED_HASH="$(printf '%s' "$INPUT" | jq -er '.requestHash | strings')" || die "no requestHash on stdin"

# ── An OAuth access token for the service account (cached ~50 minutes) ────
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
CACHE="$CACHE_DIR/pinvault-play-integrity-token"
NOW="$(date +%s)"
ACCESS=""
if [ -f "$CACHE" ]; then
  CACHED_UNTIL="$(sed -n 1p "$CACHE" 2>/dev/null || echo 0)"
  case "$CACHED_UNTIL" in *[!0-9]*|'') CACHED_UNTIL=0 ;; esac
  [ "$CACHED_UNTIL" -gt "$NOW" ] && ACCESS="$(sed -n 2p "$CACHE")"
fi
if [ -z "$ACCESS" ]; then
  EMAIL="$(jq -er '.client_email' "$SA_FILE")" || die "no client_email in the service account file"
  TOKEN_URI="$(jq -r '.token_uri // "https://oauth2.googleapis.com/token"' "$SA_FILE")"
  jq -er '.private_key' "$SA_FILE" > "$WORK/key.pem" || die "no private_key in the service account file"
  HEADER="$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)"
  CLAIMS="$(jq -cn --arg iss "$EMAIL" --arg aud "$TOKEN_URI" --argjson iat "$NOW" \
    '{iss: $iss, scope: "https://www.googleapis.com/auth/playintegrity", aud: $aud, iat: $iat, exp: ($iat + 3600)}' | b64url)"
  SIGNATURE="$(printf '%s.%s' "$HEADER" "$CLAIMS" | openssl dgst -sha256 -sign "$WORK/key.pem" -binary | b64url)"
  RESPONSE="$(curl --silent --show-error --fail --proto '=https' --max-time 15 \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
    --data-urlencode "assertion=$HEADER.$CLAIMS.$SIGNATURE" "$TOKEN_URI")" || die "could not get an access token"
  ACCESS="$(printf '%s' "$RESPONSE" | jq -er '.access_token')" || die "token endpoint answered without access_token"
  printf '%s\n%s\n' "$((NOW + 3000))" "$ACCESS" > "$CACHE.tmp" && mv -f "$CACHE.tmp" "$CACHE"
fi

# ── Decode the integrity token ───────────────────────────────────────────
jq -cn --arg t "$TOKEN" '{integrity_token: $t}' > "$WORK/body.json"
DECODED="$(curl --silent --show-error --fail --proto '=https' --max-time 15 \
  --header "Authorization: Bearer $ACCESS" --header 'Content-Type: application/json' \
  --data @"$WORK/body.json" \
  "https://playintegrity.googleapis.com/v1/$PACKAGE:decodeIntegrityToken")" || {
    rm -f "$CACHE"   # a revoked access token must not stay cached
    die "decodeIntegrityToken failed"
  }
P="$(printf '%s' "$DECODED" | jq -c '.tokenPayloadExternal // empty')"
[ -n "$P" ] || die "decodeIntegrityToken answered without tokenPayloadExternal"
field() { printf '%s' "$P" | jq -r "$1 // empty"; }

# ── The verdict ──────────────────────────────────────────────────────────
DEVICE_LABELS="$(printf '%s' "$P" | jq -r '(.deviceIntegrity.deviceRecognitionVerdict // []) | join(",")')"
APP="$(field '.appIntegrity.appRecognitionVerdict')"
LICENSE="$(field '.accountDetails.appLicensingVerdict')"
SUMMARY="device=[${DEVICE_LABELS}] app=${APP:-none} license=${LICENSE:-none}"

# Bound to this request: requestHash (standard request) or nonce (classic).
GOT_HASH="$(field '.requestDetails.requestHash')"
[ -n "$GOT_HASH" ] || GOT_HASH="$(field '.requestDetails.nonce')"
[ "$GOT_HASH" = "$EXPECTED_HASH" ] || answer false request_hash_mismatch "$SUMMARY"
[ "$(field '.requestDetails.requestPackageName')" = "$PACKAGE" ] || answer false package_mismatch "$SUMMARY"

ISSUED_MS="$(field '.requestDetails.timestampMillis')"
case "$ISSUED_MS" in *[!0-9]*|'') answer false token_time_missing "$SUMMARY" ;; esac
AGE=$(( NOW - ISSUED_MS / 1000 ))
[ "$AGE" -le "$MAX_AGE" ] || answer false token_too_old "$SUMMARY"
[ "$AGE" -ge -60 ] || answer false token_from_the_future "$SUMMARY"

[ "$APP" = "PLAY_RECOGNIZED" ] || answer false app_not_recognized "$SUMMARY"
case ",$DEVICE_LABELS," in *",$DEVICE_VERDICT,"*) ;; *) answer false device_integrity "$SUMMARY" ;; esac
if [ "$REQUIRE_LICENSED" = "true" ] && [ "$LICENSE" != "LICENSED" ]; then answer false app_not_licensed "$SUMMARY"; fi

answer true "" "$SUMMARY"
