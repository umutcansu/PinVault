#!/bin/bash
# sample-host.properties → Sources/Generated/SampleHostConfig.swift
#
#   scripts/gen-host-config.sh [<sample-host.properties>] [<çıktı.swift>]
#
# Dosya verilmezse SAMPLE_HOST_PROPS, o da yoksa sample-client-ios/sample-host.properties.
# Göreli yol sample-client-ios'a göre çözülür. Xcode bunu her derlemeden önce çalıştırır
# (project.yml → preBuildScripts); içerik değişmediyse dosyaya dokunmaz.
#
# Android'deki BuildConfig alanlarının karşılığı. Her değer
# sample-client/app/build.gradle.kts ile aynı biçim kurallarından geçer: uymayan
# değer derlemeyi durdurur (dosya başka bir betikten ya da CI değişkeninden
# gelebilir; içine tırnak ya da satır sonu sızarsa derlenen koda istenmeyen bir
# şey girebilir). CONFIGURATION=Release ise demo değerleri de reddedilir
# (build.gradle.kts → preReleaseBuild).
set -eo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "$0")/.." && pwd)"
props="${1:-${SAMPLE_HOST_PROPS:-}}"
[ -n "$props" ] || props="$HERE/sample-host.properties"
case "$props" in /*) ;; *) props="$HERE/$props" ;; esac
out="${2:-$HERE/Sources/Generated/SampleHostConfig.swift}"
configuration="${CONFIGURATION:-Debug}"

# Xcode "error:" ile başlayan satırları hata olarak gösterir.
fail() {
    printf '%s\n' "$@" | sed '/./s/^/error: /' >&2
    exit 1
}

[ -f "$props" ] || fail "Host değerleri dosyası yok: $props"
echo "gen-host-config: host değerleri ← $props ($configuration)"

# ── Java Properties okuma ─────────────────────────────────────────────────────
# Yorum (#, !), devam satırı (\ ile biten), anahtar/değer ayırıcısı (=, : ya da
# boşluk) ve ters bölü kaçışları; aynı anahtar iki kez varsa sonuncusu geçer.
# \t \n \r \f kaçışları denetim karakteri olarak kalır (aşağıda reddedilir).
parsed="$(awk '
function unescape(c) {
    if (c == "t" || c == "n" || c == "r" || c == "f") return "\001"
    return c
}
function emit(s,   i, n, c, key, val, esc) {
    key = ""; esc = 0; n = length(s)
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (esc) { key = key unescape(c); esc = 0; continue }
        if (c == "\\") { esc = 1; continue }
        if (c == "=" || c == ":" || c == " " || c == "\t" || c == "\f") break
        key = key c
    }
    while (i <= n && index(" \t\f", substr(s, i, 1)) > 0) i++
    if (i <= n && index("=:", substr(s, i, 1)) > 0) {
        i++
        while (i <= n && index(" \t\f", substr(s, i, 1)) > 0) i++
    }
    val = ""; esc = 0
    for (; i <= n; i++) {
        c = substr(s, i, 1)
        if (esc) { val = val unescape(c); esc = 0; continue }
        if (c == "\\") { esc = 1; continue }
        val = val c
    }
    printf "%s\t%s\n", key, val
}
{
    line = $0
    sub(/\r$/, "", line)
    if (cont) {
        sub(/^[ \t\f]+/, "", line)
        buf = buf line
    } else {
        sub(/^[ \t\f]+/, "", line)
        if (line == "" || substr(line, 1, 1) == "#" || substr(line, 1, 1) == "!") next
        buf = line
    }
    slashes = 0
    for (j = length(buf); j > 0 && substr(buf, j, 1) == "\\"; j--) slashes++
    if (slashes % 2 == 1) { buf = substr(buf, 1, length(buf) - 1); cont = 1; next }
    cont = 0
    emit(buf)
}
END { if (cont) emit(buf) }
' "$props")"

# Anahtarın (kırpılmış) değeri; yoksa boş.
value() {
    local v
    v="$(printf '%s\n' "$parsed" | awk -v k="$1" '
        substr($0, 1, length(k) + 1) == k "\t" { v = substr($0, length(k) + 2); f = 1 }
        END { if (f) print v }')"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    printf '%s' "$v"
}

# ── Biçim kuralları (build.gradle.kts ile aynı) ──────────────────────────────
re_host='^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$'
re_port='^[0-9]{1,5}$'
re_scope='^[A-Za-z0-9._:-]{1,64}$'
re_pin='^[A-Za-z0-9+/]{43}=$'
re_url='^https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$'
re_bool='^(true|false)$'
re_digits='^[0-9]{1,20}$'
re_signatures='^[1-9]$'
re_key_body='^[A-Za-z0-9+/]+$'
re_key_tail='^={0,2}$'

# [A-Za-z0-9+/]{40,2048}={0,2}: POSIX regex 255'ten büyük tekrar sayısı almaz,
# uzunluk ayrıca denetlenir.
is_key() {
    local body="${1%%=*}" tail="${1#"${1%%=*}"}"
    [[ "$body" =~ $re_key_body ]] && [ ${#body} -ge 40 ] && [ ${#body} -le 2048 ] \
        && [[ "$tail" =~ $re_key_tail ]]
}

# Virgülle ayrılmış liste: boş öğe yok, her öğe [1] kuralına uyar.
is_list() {
    local kind="$1" v="$2" item items
    case "$v" in ,* | *, | *,,*) return 1 ;; esac
    IFS=',' read -r -a items <<<"$v"
    for item in "${items[@]}"; do
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"
        [ -n "$item" ] || return 1
        matches "$kind" "$item" || return 1
    done
}

matches() {
    case "$1" in
        host) [[ "$2" =~ $re_host ]] ;;
        port) [[ "$2" =~ $re_port ]] ;;
        scope) [[ "$2" =~ $re_scope ]] ;;
        pin) [[ "$2" =~ $re_pin ]] ;;
        pins) is_list pin "$2" ;;
        key) is_key "$2" ;;
        keys) is_list key "$2" ;;
        url) [[ "$2" =~ $re_url ]] ;;
        bool) [[ "$2" =~ $re_bool ]] ;;
        digits) [[ "$2" =~ $re_digits ]] ;;
        signatures) [[ "$2" =~ $re_signatures ]] ;;
        *) return 1 ;;
    esac
}

# checked <anahtar> <kural> <açıklama>: değer boşsa ya da kurala uyuyorsa yazdırır.
checked() {
    local v
    v="$(value "$1")"
    if [ -n "$v" ] && ! matches "$2" "$v"; then
        fail "$props: '$1' beklenen biçimde değil ($3). Değer: '${v:0:60}'"
    fi
    printf '%s' "$v"
}

# Swift string sabiti: ters bölü ve tırnak kaçışlanır, denetim karakteri kabul edilmez.
swift_string() {
    local v="$1"
    if [[ "$v" == *$'\n'* ]] || printf '%s' "$v" | grep -q '[[:cntrl:]]'; then
        fail "$props: değerlerden birinde denetim karakteri var; SampleHostConfig.swift'e yazılmadı."
    fi
    v="${v//\\/\\\\}"
    v="${v//\"/\\\"}"
    printf '"%s"' "$v"
}

# ── Değerler (sıra build.gradle.kts'teki gibi) ───────────────────────────────
target_require_ca_trust="$(checked target.requireCaTrust bool "true ya da false")" || exit 1
host_attestation="$(checked host.attestation bool "true ya da false")" || exit 1
# Android'in Play Integrity proje numarası: iOS'ta karşılığı App Attest (numara
# istemez). Aynı dosya iki platformda da geçsin diye yalnızca denetlenir.
checked host.playIntegrityProjectNumber digits "Cloud proje numarası (rakam)" >/dev/null || exit 1

fields=(
    "hostIp|host.ip|host|IP ya da alan adı"
    "hostHttpsPort|host.httpsPort|port|port"
    "hostMtlsPort|host.mtlsPort|port|port"
    "hostTlsScope|host.tlsScope|scope|Config API kimliği"
    "hostMtlsScope|host.mtlsScope|scope|Config API kimliği"
    "hostBootstrapPinPrimary|host.bootstrapPinPrimary|pin|Base64 SHA-256 pin"
    "hostBootstrapPinBackup|host.bootstrapPinBackup|pin|Base64 SHA-256 pin"
    "hostSigningPublicKey|host.signingPublicKey|key|Base64 public key"
    "hostSigningPublicKeys|host.signingPublicKeys|keys|virgülle ayrılmış Base64 public key'ler"
    "hostRecoveryPublicKeys|host.recoveryPublicKeys|keys|virgülle ayrılmış Base64 public key'ler"
    "hostRecoveryPort|host.recoveryPort|port|port"
    "hostRecoveryPins|host.recoveryPins|pins|virgülle ayrılmış pin'ler"
    "hostClientCaPins|host.clientCaPin|pins|virgülle ayrılmış pin'ler"
)
fields_after=(
    "targetHost|target.host|host|alan adı"
    "targetPins|target.pins|pins|virgülle ayrılmış pin'ler"
    "mockTlsHost|mock.tlsHost|host|alan adı"
    "mockTlsPort|mock.tlsPort|port|port"
    "mockMtlsHost|mock.mtlsHost|host|alan adı"
    "mockMtlsPort|mock.mtlsPort|port|port"
    "customBaseUrl|custom.baseUrl|url|https:// ile başlayan adres"
    "customBootstrapPins|custom.bootstrapPins|pins|virgülle ayrılmış pin'ler"
    "customSigningPublicKey|custom.signingPublicKey|key|Base64 public key"
)

lines=""
emit_fields() {
    local entry name key kind what v literal
    for entry in "$@"; do
        IFS='|' read -r name key kind what <<<"$entry"
        v="$(checked "$key" "$kind" "$what")" || exit 1
        literal="$(swift_string "$v")" || exit 1
        lines+="    /// \`$key\`"$'\n'"    static let $name = $literal"$'\n'
    done
}
emit_fields "${fields[@]}"
required_signatures="$(checked host.requiredSignatures signatures "1-9 arası sayı")" || exit 1
lines+="    /// \`host.requiredSignatures\` (boşsa 1)"$'\n'"    static let hostRequiredSignatures = ${required_signatures:-1}"$'\n'
emit_fields "${fields_after[@]}"

# Yalnızca açıkça "false" yazılırsa kapanır (boşsa true).
[ "$target_require_ca_trust" = "false" ] && ca_trust=false || ca_trust=true
[ "$host_attestation" = "false" ] && attestation=false || attestation=true

# ── Release kapısı (build.gradle.kts → preReleaseBuild) ──────────────────────
# Depodaki sample-host.properties bir demo dosyasıdır (tek imza, yedek ve
# kurtarma anahtarı yok); onunla derlenen bir uygulama telefona gitmemeli.
if [ "$configuration" = "Release" ]; then
    problems=()
    if [ "$ca_trust" = "false" ]; then
        problems+=("$props: target.requireCaTrust=false. Release derlemesi hedefin CA onayını kapatmaz: hedefin sertifikası herkesin güvendiği bir CA'dan olmalı (README → \"Yayın derlemesi\").")
    fi
    host_problems=()
    required="$(value host.requiredSignatures)"
    [[ "$required" =~ ^[0-9]+$ ]] || required=1
    if [ "$required" -lt 2 ]; then
        host_problems+=("host.requiredSignatures=$required: her config en az 2 ayrı imza taşımalı. Tek imzayla, imza anahtarını ele geçiren biri bütün telefonlara sahte pin gönderebilir.")
    fi
    trusted="$( { value host.signingPublicKey; echo; value host.signingPublicKeys | tr ',' '\n'; } \
        | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | { grep -v '^$' || true; } | sort -u | wc -l | tr -d ' ')"
    if [ "$trusted" -lt $((required + 1)) ]; then
        host_problems+=("host.signingPublicKeys: uygulama $trusted imza anahtarına güveniyor, $required imza istiyor. En az bir yedek anahtar ($((required + 1)) anahtar) gerekir: bir imzalayıcı kaybolunca telefonlar uygulama güncellemesi olmadan config almaya devam etsin.")
    fi
    if [ -z "$(value host.recoveryPublicKeys)" ]; then
        host_problems+=("host.recoveryPublicKeys boş: kurtarma anahtarı olmadan çalınan bir imza anahtarı telefonlarda iptal edilemez.")
    fi
    if [ -z "$(value host.clientCaPin)" ]; then
        host_problems+=("host.clientCaPin boş: uygulama kayıtta gelen ilk sertifika zincirine güvenirdi; yolu değiştiren biri kendi CA'sıyla imzaladığı sertifikayı kurdurabilir.")
    fi
    if [ -z "$(value host.tlsScope)" ] || [ -z "$(value host.mtlsScope)" ]; then
        host_problems+=("host.tlsScope / host.mtlsScope boş: uygulama config'in hangi Config API için imzalandığına bakmaz; aynı anahtarın başka bir Config API için imzaladığı config de kabul edilir.")
    fi
    if [ ${#host_problems[@]} -gt 0 ]; then
        block="$props üretim değerlerini taşımıyor (demo dosyası mı?):"
        for p in "${host_problems[@]}"; do block+=$'\n'"  - $p"; done
        block+=$'\n'"  Değerleri sample-host'un üretim profilinden üret (README → \"Yayın derlemesi\"):"
        block+=$'\n'"    ../sample-host/scripts/client-config.sh --properties > sample-host.properties"
        block+=$'\n'"  Uçtan uca testler ve deneme için: xcodebuild -configuration E2E (ya da Debug)."
        problems+=("$block")
    fi
    if [ ${#problems[@]} -gt 0 ]; then
        message="Release derlemesi durduruldu:"
        for p in "${problems[@]}"; do message+=$'\n\n'"$p"; done
        fail "$message"
    fi
fi

# ── Swift dosyası ────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$out")"
tmp="$(mktemp "${TMPDIR:-/tmp}/SampleHostConfig.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
{
    echo "// Üretildi: scripts/gen-host-config.sh ← $(basename "$props"). Elle düzenleme; depoya girmez."
    echo "// Android'deki BuildConfig alanlarının karşılığı (sample-client/app/build.gradle.kts)."
    echo
    echo "enum SampleHostConfig {"
    printf '%s' "$lines"
    echo "    /// \`target.requireCaTrust\` (yalnızca açıkça false yazılırsa kapalı)"
    echo "    static let targetRequireCaTrust = $ca_trust"
    echo "    /// \`host.attestation\` (boşsa true)"
    echo "    static let hostAttestation = $attestation"
    echo "}"
} >"$tmp"
if cmp -s "$tmp" "$out"; then
    echo "gen-host-config: SampleHostConfig.swift güncel"
else
    mv "$tmp" "$out"
    echo "gen-host-config: SampleHostConfig.swift yazıldı → $out"
fi
