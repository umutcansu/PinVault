# syntax=docker/dockerfile:1.7

# ─────────────────────────────────────────────────────────────────────────────
# SamplePinVaultHost — PinVault demo-server'ı tek container'da çalıştırır.
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
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates netcat-openbsd openssl \
    && rm -rf /var/lib/apt/lists/*

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

ENV PORT=8080 \
    HTTPS_PORT=8081 \
    DB_PATH=/data/db/pinvault.db \
    CERTS_DIR=/data/certs \
    SIGNING_KEY_PATH=/data/signing-key.pem \
    ENROLLMENT_MODE=token

EXPOSE 8080 8081

# Flyway migration ilk açılışta birkaç saniye sürebilir; start-period bunu absorbe eder.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://localhost:${PORT:-8080}/health" || exit 1

ENTRYPOINT ["/usr/local/bin/pinvault-demo-server"]
