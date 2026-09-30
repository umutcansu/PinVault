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

WORKDIR /data
COPY --from=build /build/build/install/pinvault-demo-server/ /app/

# Persistent data directories
RUN mkdir -p /data/db /data/certs

ENV PORT=8080
ENV HTTPS_PORT=8081
ENV DB_PATH=/data/db/pinvault.db
ENV CERTS_DIR=/data/certs
ENV SIGNING_KEY_PATH=/data/signing-key.pem
ENV ENROLLMENT_MODE=token

EXPOSE 8080 8081

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/bin/pinvault-demo-server"]
