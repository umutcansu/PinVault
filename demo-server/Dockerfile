# ── Build stage ──────────────────────────────────────────
FROM gradle:8.7-jdk17 AS build
WORKDIR /build
COPY build.gradle.kts settings.gradle.kts ./
COPY src/ src/
RUN gradle installDist --no-daemon

# ── Runtime stage ────────────────────────────────────────
# jammy, not alpine: the alpine JRE tag has no arm64 image (Apple Silicon hosts)
FROM eclipse-temurin:17-jre-jammy
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# The server never needs root: it listens on high ports and writes only under
# /data. A fixed uid/gid so a bind-mounted ./data can be given to it
# (`chown -R 10001:10001 data`), or `user:` in compose can name another one.
RUN groupadd --system --gid 10001 pinvault \
    && useradd --system --uid 10001 --gid pinvault --home-dir /data --shell /usr/sbin/nologin pinvault

WORKDIR /data
COPY --from=build /build/build/install/pinvault-demo-server/ /app/

# Persistent data directories, writable by the server's user
RUN mkdir -p /data/db /data/certs /data/keys && chown -R pinvault:pinvault /data

ENV PORT=8080
ENV HTTPS_PORT=8081
ENV DB_PATH=/data/db/pinvault.db
ENV CERTS_DIR=/data/certs
ENV SIGNING_KEY_PATH=/data/signing-key.pem
ENV ENROLLMENT_MODE=token

EXPOSE 8080 8081

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

USER pinvault:pinvault
ENTRYPOINT ["/app/bin/pinvault-demo-server"]
