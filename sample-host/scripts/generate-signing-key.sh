#!/usr/bin/env bash
# PinVault demo-server için signing-key.pem üretir.
#
# FORMAT: Server iki satır Base64 bekliyor (PEM header'sız):
#   Satır 1: PKCS8 encoded EC private key (DER → Base64)
#   Satır 2: X.509 SubjectPublicKeyInfo (DER → Base64)
# Algoritma: ECDSA P-256 (secp256r1)
#
# Public key Base64 stdout'a yazdırılır — Android client'a SPKI olarak gömülmek üzere.
#
# UYARI: Bu script geliştirme/sample içindir. Üretimde signing key bir HSM/KMS'te tutulmalı.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
KEY_PATH="${ROOT_DIR}/data/signing-key.pem"

if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl bulunamadı. Lütfen openssl yükleyin (macOS: brew install openssl)." >&2
    exit 1
fi

if [ -e "${KEY_PATH}" ]; then
    echo "ERROR: ${KEY_PATH} zaten mevcut." >&2
    echo "Yeniden üretmek istiyorsanız önce silin:" >&2
    echo "    rm '${KEY_PATH}'" >&2
    exit 1
fi

mkdir -p "${ROOT_DIR}/data"

TMP_PEM="$(mktemp -t pinvault-key.XXXXXX)"
trap 'rm -f "${TMP_PEM}"' EXIT

echo ">> ECDSA P-256 anahtar çifti üretiliyor..."
# `ecparam -name prime256v1` named curve OID üretir (JDK gerektiriyor: "Only named ECParameters supported")
openssl ecparam -name prime256v1 -genkey -noout -out "${TMP_PEM}" 2>/dev/null

# PKCS8 private key (DER → Base64, tek satır)
PRIV_B64="$(openssl pkcs8 -topk8 -nocrypt -in "${TMP_PEM}" -outform DER | base64 | tr -d '\n')"

# X.509 SubjectPublicKeyInfo (DER → Base64, tek satır)
PUB_B64="$(openssl pkey -in "${TMP_PEM}" -pubout -outform DER | base64 | tr -d '\n')"

{
    printf '%s\n' "${PRIV_B64}"
    printf '%s\n' "${PUB_B64}"
} > "${KEY_PATH}"
chmod 600 "${KEY_PATH}"

echo ">> Signing key yazıldı: ${KEY_PATH}"
echo ""
echo ">> Public key (X.509 SPKI, Base64) — Android client'a gömün:"
echo ""
echo "${PUB_B64}"
echo ""
echo ">> UYARI: Bu key sadece geliştirme/sample içindir. Üretimde KULLANMAYIN."
