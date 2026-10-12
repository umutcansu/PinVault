#!/bin/sh
# Makes a throwaway certificate for the emulator (10.0.2.2) and this Mac's
# addresses (delete wss-*.pem after a network change), prints the pin to pass as PINVAULT_WS_PIN, and starts the
# echo server on 8765.
set -eu
cd "$(dirname "$0")"
# Every IPv4 address of this Mac (the iOS simulator connects to the LAN one and
# checks the name), plus 10.0.2.2 for the Android emulator.
sans=$(ifconfig | awk '/inet / { print $2 }' | sort -u | sed 's/^/IP:/' | paste -sd, -)
[ -f wss-cert.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -keyout wss-key.pem -out wss-cert.pem -days 30 \
  -subj "/CN=pinvault-wss-test" -addext "subjectAltName=IP:10.0.2.2,$sans" 2>/dev/null
echo "PINVAULT_WS_PIN=$(openssl x509 -in wss-cert.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)"
exec dart run wss_echo_server.dart 8765
