#!/bin/sh
# Regenerates the TLS fixtures of the handshake and trust tests (LibreSSL 3.3
# or OpenSSL 3). Test keys only: the P12 files (password "changeit") carry
# private keys that exist for these tests and nothing else.
#
#   sh pinvault-ios/Tests/PinVaultTests/Fixtures/tls/generate.sh
#
# Every certificate is EC P-256 / SHA-256. Leaves are valid for 800 days (Apple's
# SSL policy refuses TLS server certificates valid longer than 825 days), CAs for
# 20 years; the tests judge validity with an injected clock (notBefore + 1 day,
# from fixtures.json), so they do not depend on the day they run.
#
# Files (DER unless noted):
#   root, intermediate                 chain CA pair ("CN=Chain Test Root" / "Intermediate")
#   leaf                               localhost, 127.0.0.1, mock-tls.sample, api.chain.test — under intermediate
#   server.p12 / server-full.p12       leaf served as [leaf, intermediate] / [leaf, intermediate, root]
#   selfsigned + .p12                  self-signed localhost, 127.0.0.1 (SAN), CA:FALSE
#   nosan + .p12                       self-signed CN=localhost, no subjectAltName
#   wrongsan + .p12                    other.chain.test under intermediate, served as [leaf, intermediate]
#   expired + .p12                     localhost under intermediate, 2020-01-01 .. 2020-12-31
#   notyetvalid + .p12                 localhost under intermediate, 2090-01-01 .. 2091-01-01
#   forged                             CN/SAN api.chain.test, issuer name = intermediate, signed by an attacker key
#   notca, leaf-under-notca            CA:FALSE certificate under root, and a leaf it "issued"
#   expired-intermediate, leaf-under-expired-intermediate
#   stranger                           a CA under root that issued nothing here
#   other-host-leaf                    other.chain.test under intermediate
#   nosan-leaf                         CN=api.chain.test under intermediate, no subjectAltName
#   managed-root, other-root           managed trust roots tests
#   managed-leaf                       cdn.unpinned.test under managed-root
#   managed-elsewhere                  elsewhere.test under managed-root
#   pinned-under-managed               api.pinned.test under managed-root
#   door-ca, door.p12                  renewal door: localhost leaf signed by door-ca, served as [leaf, door-ca]
#   client-ca, client-a.p12, client-b.p12   client identities (CN=client-a / CN=client-b) under client-ca
#   backup.pin                         SPKI pin of a key that signs nothing (the backup pin)
#   fixtures.json                      pins and validity of the above
set -eu
OUT=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
PASS=changeit

key() { openssl ecparam -name prime256v1 -genkey -noout -out "$1-key.pem"; }

# ca NAME SUBJECT [ISSUER]: a CA certificate (self-signed without ISSUER).
ca() {
  key "$1"
  if [ $# -lt 3 ]; then
    openssl req -x509 -new -key "$1-key.pem" -sha256 -days 7300 -subj "$2" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -addext "subjectKeyIdentifier=hash" -out "$1.pem"
  else
    openssl req -new -key "$1-key.pem" -subj "$2" -out "$1.csr"
    printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$1.ext"
    openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3-key.pem" -set_serial "0x$(openssl rand -hex 8)" \
      -days 7300 -sha256 -extfile "$1.ext" -out "$1.pem"
  fi
}

# leaf NAME SUBJECT ISSUER EXTFILE-LINES...: a certificate issued by ISSUER (its key: ISSUER-key.pem).
leaf() {
  name=$1; subject=$2; issuer=$3; shift 3
  [ -f "$name-key.pem" ] || key "$name"
  openssl req -new -key "$name-key.pem" -subj "$subject" -out "$name.csr"
  : > "$name.ext"
  for line in "$@"; do echo "$line" >> "$name.ext"; done
  openssl x509 -req -in "$name.csr" -CA "$issuer.pem" -CAkey "$issuer-key.pem" -set_serial "0x$(openssl rand -hex 8)" \
    -days 800 -sha256 -extfile "$name.ext" -out "$name.pem"
}

# dated NAME SUBJECT ISSUER START END EXT...: like leaf, with explicit validity (openssl ca, YYYYMMDDHHMMSSZ).
dated() {
  name=$1; subject=$2; issuer=$3; start=$4; end=$5; shift 5
  key "$name"
  openssl req -new -key "$name-key.pem" -subj "$subject" -out "$name.csr"
  mkdir -p "ca-$name"; : > "ca-$name/index.txt"; openssl rand -hex 8 > "ca-$name/serial"
  {
    echo "[ca]"; echo "default_ca=d"
    echo "[d]"; echo "dir=ca-$name"; echo "database=ca-$name/index.txt"; echo "serial=ca-$name/serial"
    echo "new_certs_dir=ca-$name"; echo "default_md=sha256"; echo "policy=p"; echo "unique_subject=no"
    echo "copy_extensions=none"; echo "x509_extensions=e"
    echo "[p]"; echo "commonName=supplied"
    echo "[e]"; for line in "$@"; do echo "$line"; done
  } > "ca-$name.cnf"
  openssl ca -batch -config "ca-$name.cnf" -cert "$issuer.pem" -keyfile "$issuer-key.pem" \
    -startdate "$start" -enddate "$end" -in "$name.csr" -out "$name.raw" -notext 2>/dev/null
  openssl x509 -in "$name.raw" -out "$name.pem"
}

# p12 NAME CERT [CHAIN-CERTS...]: identity with the key of CERT.
p12() {
  name=$1; cert=$2; shift 2
  : > "$name-chain.pem"
  for c in "$@"; do cat "$c.pem" >> "$name-chain.pem"; done
  if [ -s "$name-chain.pem" ]; then
    openssl pkcs12 -export -inkey "$cert-key.pem" -in "$cert.pem" -certfile "$name-chain.pem" -name "$name" \
      -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 -passout "pass:$PASS" -out "$name.p12"
  else
    openssl pkcs12 -export -inkey "$cert-key.pem" -in "$cert.pem" -name "$name" \
      -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 -passout "pass:$PASS" -out "$name.p12"
  fi
}

server_leaf() { leaf "$1" "$2" "$3" "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" "extendedKeyUsage=serverAuth" "$4"; }

ca root "/O=PinVault Test/CN=Chain Test Root"
ca intermediate "/O=PinVault Test/CN=Chain Test Intermediate" root
server_leaf leaf "/O=PinVault Test/CN=localhost" intermediate \
  "subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:mock-tls.sample,DNS:api.chain.test"
p12 server leaf intermediate
p12 server-full leaf intermediate root

# Self-signed server certificates.
key selfsigned
openssl req -x509 -new -key selfsigned-key.pem -sha256 -days 800 -subj "/O=PinVault Test/CN=localhost" \
  -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -out selfsigned.pem
p12 selfsigned selfsigned
key nosan
openssl req -x509 -new -key nosan-key.pem -sha256 -days 800 -subj "/O=PinVault Test/CN=localhost" \
  -addext "basicConstraints=critical,CA:FALSE" -out nosan.pem
p12 nosan nosan

server_leaf wrongsan "/O=PinVault Test/CN=other.chain.test" intermediate "subjectAltName=DNS:other.chain.test"
p12 wrongsan wrongsan intermediate

dated expired "/CN=localhost" intermediate 20200101000000Z 20201231000000Z \
  "basicConstraints=critical,CA:FALSE" "subjectAltName=DNS:localhost,IP:127.0.0.1"
p12 expired expired intermediate
dated notyetvalid "/CN=localhost" intermediate 20900101000000Z 20910101000000Z \
  "basicConstraints=critical,CA:FALSE" "subjectAltName=DNS:localhost,IP:127.0.0.1"
p12 notyetvalid notyetvalid intermediate

# Chain matcher material.
key attacker
cp attacker-key.pem forged-issuer-key.pem
# The attacker's "intermediate": the genuine intermediate's subject, the attacker's key.
openssl req -x509 -new -key forged-issuer-key.pem -sha256 -days 7300 -subj "/O=PinVault Test/CN=Chain Test Intermediate" \
  -addext "basicConstraints=critical,CA:TRUE" -out forged-issuer.pem
server_leaf forged "/O=PinVault Test/CN=api.chain.test" forged-issuer "subjectAltName=DNS:api.chain.test"
leaf notca "/O=PinVault Test/CN=Not A CA" root "basicConstraints=critical,CA:FALSE"
server_leaf leaf-under-notca "/O=PinVault Test/CN=api.chain.test" notca "subjectAltName=DNS:api.chain.test"
dated expired-intermediate "/CN=Old Intermediate" root 20200101000000Z 20201231000000Z \
  "basicConstraints=critical,CA:TRUE" "keyUsage=critical,keyCertSign,cRLSign"
server_leaf leaf-under-expired-intermediate "/O=PinVault Test/CN=api.chain.test" expired-intermediate "subjectAltName=DNS:api.chain.test"
ca stranger "/O=PinVault Test/CN=Stranger CA" root
server_leaf other-host-leaf "/O=PinVault Test/CN=other.chain.test" intermediate "subjectAltName=DNS:other.chain.test"
leaf nosan-leaf "/O=PinVault Test/CN=api.chain.test" intermediate "basicConstraints=critical,CA:FALSE"

# Managed trust roots.
ca managed-root "/O=PinVault Test/CN=Managed Root"
ca other-root "/O=PinVault Test/CN=Other Root"
server_leaf managed-leaf "/O=PinVault Test/CN=cdn.unpinned.test" managed-root "subjectAltName=DNS:cdn.unpinned.test"
server_leaf managed-elsewhere "/O=PinVault Test/CN=elsewhere" managed-root "subjectAltName=DNS:elsewhere.test"
server_leaf pinned-under-managed "/O=PinVault Test/CN=api.pinned.test" managed-root "subjectAltName=DNS:api.pinned.test"

# The renewal door: a leaf signed by the backend's own CA, served with that CA.
ca door-ca "/O=PinVault Test/CN=Test Server CA"
server_leaf door "/O=PinVault Test/CN=localhost" door-ca "subjectAltName=DNS:localhost,IP:127.0.0.1"
p12 door door door-ca

# Client identities.
ca client-ca "/O=PinVault Test/CN=Client CA"
leaf client-a "/O=PinVault Test/CN=client-a" client-ca "basicConstraints=critical,CA:FALSE" \
  "keyUsage=critical,digitalSignature" "extendedKeyUsage=clientAuth"
leaf client-b "/O=PinVault Test/CN=client-b" client-ca "basicConstraints=critical,CA:FALSE" \
  "keyUsage=critical,digitalSignature" "extendedKeyUsage=clientAuth"
p12 client-a client-a client-ca
p12 client-b client-b client-ca

key backup

pin_of_key() { openssl ec -in "$1-key.pem" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 -binary | base64; }
epoch() { date -j -u -f "%b %e %T %Y %Z" "$(openssl x509 -in "$1.pem" -noout "-$2" | sed 's/^[^=]*=//')" "+%s"; }

CERTS="root intermediate leaf selfsigned nosan wrongsan expired notyetvalid forged notca leaf-under-notca
expired-intermediate leaf-under-expired-intermediate stranger other-host-leaf nosan-leaf managed-root other-root
managed-leaf managed-elsewhere pinned-under-managed door-ca door client-ca client-a client-b"

{
  echo "{"
  for c in $CERTS; do
    echo "  \"$c\": { \"pin\": \"$(pin_of_key "$c")\", \"notBefore\": $(epoch "$c" startdate), \"notAfter\": $(epoch "$c" enddate) },"
  done
  echo "  \"backup\": { \"pin\": \"$(pin_of_key backup)\" }"
  echo "}"
} > fixtures.json

for c in $CERTS; do openssl x509 -in "$c.pem" -outform DER -out "$OUT/$c.der"; done
cp server.p12 server-full.p12 selfsigned.p12 nosan.p12 wrongsan.p12 expired.p12 notyetvalid.p12 door.p12 \
  client-a.p12 client-b.p12 fixtures.json "$OUT/"
echo "TLS fixtures written to $OUT"
