#!/usr/bin/env bash
# Depoya anahtar ya da gizli değer girmesini engelleyen küçük denetim.
#
# Bu depo herkese açık bir depoya yansıyor; bir kez push edilen anahtar geri
# alınamaz (geçmişte kalır). .gitignore ilk engeldir, bu betik ikincisi:
# `git add -f` ile ya da yeni bir dosya adıyla kaçan şeyi yakalar.
#
#   ./sample-host/scripts/check-secrets.sh          # commit'e eklenmiş (staged) dosyalar
#   ./sample-host/scripts/check-secrets.sh --all    # depoda izlenen bütün dosyalar
#
# Bulgu varsa 1 ile çıkar ve dosyaları listeler.
#
# pre-commit kancası olarak (depo kökünde, bir kez):
#   printf '#!/bin/sh\nexec sample-host/scripts/check-secrets.sh\n' > .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
# CI'da: ./sample-host/scripts/check-secrets.sh --all
#
# Ne arar:
#   - adıyla anahtar ya da veri olan dosyalar: *.jks *.p12 *.pfx *.bks *.keystore
#     *.pem *.key *.der *.p8 *.db *.sqlite, .env (örnekler hariç), key.properties /
#     keystore.properties (Android imza anahtarı parolaları), offline-keys/ altı
#   - içinde özel anahtar başlığı olan dosyalar (-----BEGIN … PRIVATE KEY-----)
#   - adı ne olursa olsun, sunucunun başlıksız imza anahtarı biçimi: satırın
#     tamamı Base64 PKCS#8 özel anahtar (signing-key.pem'in ilk satırı; demo-server
#     LocalFileSigner böyle yazar) ya da şifreli hâli (ENCv1:…)
# Bilerek izlenmesi gereken bir dosya varsa (ör. herkese açık bir test
# sertifikası) depo kökündeki .secrets-allow dosyasına yolunu yaz (satır başına
# bir yol; # ile yorum).
#
# Bu, gitleaks gibi bir tarayıcının yerini tutmaz (API anahtarı, token gibi
# serbest biçimli değerleri aramaz); yalnızca en pahalı hatayı, anahtar dosyası
# commit'lemeyi durdurur.

set -euo pipefail

# macOS'ta Xcode lisansı kabul edilmemişse /usr/bin/git çalışmaz; Command Line
# Tools içindeki git denenir.
GIT="git"
if ! git --version >/dev/null 2>&1 && [ -x /Library/Developer/CommandLineTools/usr/bin/git ]; then
    GIT="/Library/Developer/CommandLineTools/usr/bin/git"
fi

ROOT="$("${GIT}" rev-parse --show-toplevel 2>/dev/null)" || { echo "check-secrets: bir git deposunun içinde çalıştır." >&2; exit 2; }
cd "${ROOT}"

MODE="staged"
case "${1:-}" in
    --all) MODE="all" ;;
    ""|--staged) ;;
    -h|--help) sed -n '2,31p' "$0"; exit 0 ;;
    *) echo "Bilinmeyen seçenek: $1 (--all)" >&2; exit 2 ;;
esac

allowed() { # $1 = yol
    [ -f .secrets-allow ] || return 1
    grep -v '^[[:space:]]*#' .secrets-allow | grep -qxF "$1"
}

# Dosyanın denetlenecek içeriği: commit'e girecek hâli (index), yoksa diskteki.
content() {
    "${GIT}" show ":$1" 2>/dev/null || cat "$1" 2>/dev/null || true
}

findings=0
report() { echo "  $1  →  $2"; findings=$((findings + 1)); }

check() {
    local path="$1" base lower
    allowed "${path}" && return 0
    base="${path##*/}"
    lower="$(printf '%s' "${base}" | tr 'A-Z' 'a-z')"
    case "${lower}" in
        *.jks|*.p12|*.pfx|*.bks|*.keystore) report "${path}" "anahtar deposu"; return 0 ;;
        *.db|*.sqlite|*.sqlite3) report "${path}" "veritabanı"; return 0 ;;
        *.pem|*.key|*.der|*.p8) report "${path}" "anahtar/sertifika dosyası"; return 0 ;;
        key.properties|keystore.properties) report "${path}" "imza anahtarı ayarları (parolalar)"; return 0 ;;
        .env|.env.*)
            case "${lower}" in
                .env.example|.env.production.example) ;;
                *) report "${path}" "ortam dosyası (gizli değerler)"; return 0 ;;
            esac
            ;;
    esac
    case "/${path}" in
        */offline-keys/*) report "${path}" "çevrimdışı anahtar dizini"; return 0 ;;
    esac
    # İçerik: özel anahtar başlığı. Betik ve belge dosyaları başlığı örnek olarak
    # anabilir; yalnızca satır başında duran gerçek bir başlık sayılır.
    if content "${path}" | LC_ALL=C grep -aqE '^-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----[[:space:]]*$'; then
        report "${path}" "içinde özel anahtar var"
        return 0
    fi
    # Başlıksız imza anahtarı (demo-server LocalFileSigner): ilk satır Base64 PKCS#8
    # özel anahtar, ikinci satır public key; şifreliyse tek satır "ENCv1:<Base64>".
    # PKCS#8 DER'i "30 81|82 … 02 01 00 30" ile başlar; Base64'te MIG?AgEAM… ya da
    # MII????IBADA…. Yalnızca satırın tamamı böyleyse sayılır (koddaki örnek değil).
    if content "${path}" | LC_ALL=C grep -aqE '^(MIG[A-Za-z0-9+/]AgEAM|MII[A-Za-z0-9+/]{3}IBADA)[A-Za-z0-9+/]{20,}={0,2}[[:space:]]*$'; then
        report "${path}" "içinde başlıksız özel anahtar var (Base64 PKCS#8, sunucunun signing-key.pem biçimi)"
        return 0
    fi
    if content "${path}" | LC_ALL=C grep -aqE '^ENCv1:[A-Za-z0-9+/]{40,}={0,2}[[:space:]]*$'; then
        report "${path}" "içinde şifreli imza anahtarı var (ENCv1:, parolası .env'de)"
    fi
    return 0
}

if [ "${MODE}" = "all" ]; then
    list() { "${GIT}" ls-files -z; }
    echo "check-secrets: izlenen bütün dosyalar denetleniyor…"
else
    list() { "${GIT}" diff --cached --name-only --diff-filter=ACMR -z; }
fi

while IFS= read -r -d '' file; do
    check "${file}"
done < <(list)

if [ "${findings}" -gt 0 ]; then
    cat >&2 <<EOF

check-secrets: ${findings} dosya anahtar ya da gizli veri gibi görünüyor (yukarıda).
Commit'ten çıkar:        git restore --staged <dosya>     (izleniyorsa: git rm --cached <dosya>)
Bilerek izlenecekse:     yolunu depo kökündeki .secrets-allow dosyasına yaz.
Zaten push edildiyse:    o anahtarı YENİLE; geçmişten silmek yetmez.
EOF
    exit 1
fi
[ "${MODE}" = "all" ] && echo "check-secrets: bulgu yok."
exit 0
