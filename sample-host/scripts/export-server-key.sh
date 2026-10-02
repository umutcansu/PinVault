#!/usr/bin/env bash
# Sunucunun TLS anahtar ve sertifikasını PEM olarak dışa aktarır
# (data/proxy/server-key.pem, server-cert.pem). Yalnızca laboratuvar için:
# uçtan uca testlerdeki saldırgan proxy (SamplePinVaultE2E/lib/proxy.js)
# telefonun pinlediği anahtarla dinleyip yanıtları değiştirir; böylece
# kütüphanenin imza, replay ve sürüm kontrolleri gerçek bir araya girme
# altında gösterilir.
#
# keytool container'daki JRE'den çalışır (Mac'te JDK gerekmez); PKCS12 → PEM
# dönüşümü openssl ile. Çıktılar 0600 izinli ve git dışıdır.
#
# Kullanım: ./scripts/export-server-key.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
fi

PASS="${KEYSTORE_PASSWORD:-changeit}"
# Parola komut satırlarında (ps) görünmesin: keytool ve openssl ortamdan okur.
export PASS
[ -f data/certs/demo-server.jks ] || { echo "data/certs/demo-server.jks yok — önce 'docker compose up -d'." >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl gerekli" >&2; exit 1; }

mkdir -p data/proxy
chmod 700 data/proxy
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

# JKS → PKCS12 container içinde, sunucu kullanıcısıyla ve container'ın /tmp'sinde:
# data/ altına root'a ait ya da geçici bir anahtar dosyası düşmez, paket stdout'tan gelir.
docker compose exec -T -u pinvault -e PASS pinvault-host sh -c '
    keytool -importkeystore \
        -srckeystore /data/certs/demo-server.jks -srcstoretype JKS -srcstorepass:env PASS \
        -destkeystore /tmp/proxy-export.p12 -deststoretype PKCS12 -deststorepass:env PASS \
        -noprompt >/dev/null 2>&1 && cat /tmp/proxy-export.p12
    status=$?; rm -f /tmp/proxy-export.p12; exit "${status}"' > "${tmp}/proxy-export.p12"

# PKCS12 → PEM
openssl pkcs12 -in "${tmp}/proxy-export.p12" -passin env:PASS -nocerts -nodes \
    | openssl pkey -out data/proxy/server-key.pem
openssl pkcs12 -in "${tmp}/proxy-export.p12" -passin env:PASS -nokeys \
    | openssl x509 -out data/proxy/server-cert.pem
chmod 600 data/proxy/server-key.pem data/proxy/server-cert.pem

PIN="$(openssl x509 -in data/proxy/server-cert.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64)"
echo "Dışa aktarıldı: data/proxy/server-key.pem, data/proxy/server-cert.pem"
echo "Sertifika pin'i: ${PIN}"
grep -qx "${PIN}" data/certs/demo-server.pins && echo "Pin, data/certs/demo-server.pins ile eşleşiyor." \
    || echo "UYARI: pin, demo-server.pins içinde yok (sertifika yenilenmiş olabilir)." >&2
