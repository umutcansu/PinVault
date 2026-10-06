#!/bin/sh
# Regenerates the certificate / key fixtures of the DER, SPKI and X509 tests
# (LibreSSL 3.3 or OpenSSL 3). Private keys are made in a temporary directory
# and thrown away; only public material and fixtures.json (the values the
# tests expect, as openssl prints them) are written here.
#
#   sh pinvault-ios/Tests/PinVaultTests/Fixtures/generate.sh
set -eu
OUT=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

# CA: EC P-256, 30 years (notAfter after 2049 -> GeneralizedTime), serial 0x0a1b2c3d4e5f.
openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem
openssl req -x509 -new -key ca-key.pem -sha256 -days 10950 -set_serial 0x0a1b2c3d4e5f \
  -subj "/C=TR/O=PinVault Test/OU=Fixtures/CN=PinVault Test CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out ca.pem

# Leaf: EC P-256, 825 days (UTCTime), serial with the high bit set (DER adds 0x00), SANs.
openssl ecparam -name prime256v1 -genkey -noout -out leaf-key.pem
openssl req -new -key leaf-key.pem -subj "/O=PinVault Test/CN=mock-tls.sample" -out leaf.csr
cat > leaf.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:mock-tls.sample,DNS:*.example.com,IP:192.168.1.10,IP:fe80::1
EOF
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca-key.pem -set_serial 0x00ff00ff00ff00ff01 \
  -days 825 -sha256 -extfile leaf.ext -out leaf.pem

# RSA-2048 self-signed, a subject that needs RFC 2253 escaping.
openssl genrsa -out rsa-key.pem 2048 2>/dev/null
openssl req -x509 -new -key rsa-key.pem -sha256 -days 365 -set_serial 7 \
  -subj "/CN=RSA Fixture, Inc/O=Comma\, Quote \"Org\"" -out rsa.pem

for c in ca leaf rsa; do openssl x509 -in $c.pem -outform DER -out $c.der; done
openssl ec -in leaf-key.pem -pubout -outform DER -out leaf-spki.der 2>/dev/null
openssl ec -in ca-key.pem -pubout -outform DER -out ca-spki.der 2>/dev/null
openssl rsa -in rsa-key.pem -pubout -outform DER -out rsa-spki.der 2>/dev/null
openssl rsa -in rsa-key.pem -RSAPublicKey_out -outform DER -out rsa-pkcs1.der 2>/dev/null
# The pin format of Android: base64(sha256(SPKI DER)).
for k in leaf ca rsa; do
  openssl pkey -pubin -inform DER -in $k-spki.der -outform DER | openssl dgst -sha256 -binary | base64 > $k-spki.pin
done
# X9.63 point (04||X||Y) of the leaf key: the last 65 bytes of its SPKI.
tail -c 65 leaf-spki.der > leaf-point.bin

epoch() { date -j -u -f "%b %e %T %Y %Z" "$(openssl x509 -in "$1.pem" -noout "-$2" | sed 's/^[^=]*=//')" "+%s"; }
cat > fixtures.json <<EOF
{
  "ca": {
    "serialHex": "0a1b2c3d4e5f",
    "notBefore": $(epoch ca startdate),
    "notAfter": $(epoch ca enddate),
    "subject": "CN=PinVault Test CA,OU=Fixtures,O=PinVault Test,C=TR",
    "issuer": "CN=PinVault Test CA,OU=Fixtures,O=PinVault Test,C=TR",
    "spkiPin": "$(cat ca-spki.pin)"
  },
  "leaf": {
    "serialHex": "00ff00ff00ff00ff01",
    "notBefore": $(epoch leaf startdate),
    "notAfter": $(epoch leaf enddate),
    "subject": "CN=mock-tls.sample,O=PinVault Test",
    "issuer": "CN=PinVault Test CA,OU=Fixtures,O=PinVault Test,C=TR",
    "dnsNames": ["mock-tls.sample", "*.example.com"],
    "ipAddresses": ["192.168.1.10", "fe80::1"],
    "spkiPin": "$(cat leaf-spki.pin)"
  },
  "rsa": {
    "serialHex": "07",
    "notBefore": $(epoch rsa startdate),
    "notAfter": $(epoch rsa enddate),
    "subject": "O=Comma\\\\, Quote \\\\\"Org\\\\\",CN=RSA Fixture\\\\, Inc",
    "commonName": "RSA Fixture, Inc",
    "spkiPin": "$(cat rsa-spki.pin)"
  }
}
EOF

cp ca.pem ca.der leaf.pem leaf.der rsa.der ca-spki.der leaf-spki.der rsa-spki.der rsa-pkcs1.der leaf-point.bin fixtures.json "$OUT/"
echo "Fixtures written to $OUT"
