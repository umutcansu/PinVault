# ─────────────────────────────────────────────────────────────────────────────
# SamplePinVaultHost — PinVault demo-server'ı tek container'da çalıştırır.
#
# Bilerek "# syntax=docker/dockerfile:…" satırı yok: o satır ön ucu her
# derlemede Docker Hub'dan çözdürür (kimlik yardımcısı dahil), yani yerelde
# hiçbir şey eksik değilken bile derlemeyi ağa ve Hub'a bağlar. Burada
# kullanılan tek ileri özellik adlandırılmış build context'inden kopyalama
# (COPY --from=pinvault-server); Docker 23+ içindeki yerleşik ön uç bunu
# destekler. Temel imajlar yerel depodaysa derleme Hub'a hiç gitmez.
#
# Sunucu kaynağı `pinvault-server` adlı build context'inden gelir
# (docker-compose.yml → build.additional_contexts). Bu context ya yerel bir
# PinVault checkout'unun demo-server/ dizinini ya da upstream git reposunu
# gösterir; image her zaman demo etmek istediğin sunucu sürümüyle birebir aynı
# olur. Compose kullanmadan:
#
#   docker buildx build --build-context pinvault-server=../PinVault/demo-server .
# ─────────────────────────────────────────────────────────────────────────────

# ---- Stage 1: build ----
FROM gradle:8.7-jdk17 AS build
WORKDIR /build/demo-server
# Yalnızca Gradle girdileri kopyalanır. Kaynak dizindeki yerel runtime state
# (pinvault.db, certs/, signing-key.pem, build/) asla image'a girmez.
COPY --from=pinvault-server settings.gradle.kts build.gradle.kts ./
COPY --from=pinvault-server src ./src
RUN gradle installDist --no-daemon

# ---- Stage 2: runtime ----
FROM eclipse-temurin:17-jre-noble

# - curl: healthcheck
# - netcat-openbsd + openssl: /api/v1/hosts/{host}/ping-remote bunları
#   subprocess olarak (argv ile, shell'siz) çağırır.
# - softhsm2 + opensc: isteğe bağlı HSM imzalayıcısı (CONFIG_SIGNERS=pkcs11).
#   SoftHSM, gerçek bir HSM'in PKCS#11 arayüzünü taklit eden yazılım token'ıdır;
#   aynı ayarlar gerçek bir HSM modülüyle de çalışır. pkcs11-tool (opensc) yalnızca
#   anahtarın özniteliklerini göstermek için (scripts/softhsm-init.sh).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates netcat-openbsd openssl softhsm2 opensc \
    && rm -rf /var/lib/apt/lists/*

# PKCS#11 imzalayıcısı JDK'nın SunPKCS11 sağlayıcısını kullanır; modül ve
# SoftHSM kütüphanesi yoksa derleme burada dursun, çalışırken değil.
RUN java --list-modules | grep -q jdk.crypto.cryptoki \
    && test -e /usr/lib/softhsm/libsofthsm2.so

COPY --from=build /build/demo-server/build/install/ /app/

# /app/<dist>/bin/<dist> binary'sini bul ve sabit bir yola link'le.
RUN set -eux; \
    DIST_DIR=$(find /app -mindepth 1 -maxdepth 1 -type d | head -n1); \
    test -n "${DIST_DIR}"; \
    BIN=$(find "${DIST_DIR}/bin" -mindepth 1 -maxdepth 1 -type f ! -name '*.bat' | head -n1); \
    test -n "${BIN}"; \
    ln -s "${BIN}" /usr/local/bin/pinvault-demo-server; \
    chmod +x "${BIN}"

# Sunucu bazı dosyaları çalışma dizinine göre yazar (certs/demo-server.pins);
# WORKDIR=/data olunca bunlar da mount edilen data/certs altına düşer.
WORKDIR /data
RUN mkdir -p /data/db /data/certs

# Sunucu root olarak çalışmaz: entrypoint.sh data/ bağlamasının sahipliğini bu
# kullanıcıya verip yetkileri bırakır (setpriv).
RUN groupadd --system --gid 10001 pinvault \
    && useradd --system --uid 10001 --gid pinvault --home-dir /data --no-create-home --shell /usr/sbin/nologin pinvault
COPY entrypoint.sh /usr/local/bin/pinvault-entrypoint
RUN chmod 755 /usr/local/bin/pinvault-entrypoint

ENV PORT=8080 \
    HTTPS_PORT=8081 \
    DB_PATH=/data/db/pinvault.db \
    CERTS_DIR=/data/certs \
    SIGNING_KEY_PATH=/data/signing-key.pem \
    ENROLLMENT_MODE=token \
    SOFTHSM2_CONF=/data/softhsm/softhsm2.conf

EXPOSE 8080 8081 8082

# Flyway migration ilk açılışta birkaç saniye sürebilir; start-period bunu absorbe eder.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://localhost:${PORT:-8080}/health" || exit 1

ENTRYPOINT ["/usr/local/bin/pinvault-entrypoint"]
CMD ["/usr/local/bin/pinvault-demo-server"]
