# PinVault Server Implementation Guide

Build a PinVault-compatible server in **any language**. The Android library communicates via standard HTTP/HTTPS — your server just needs to implement these endpoints.

## Quick Start

Your server needs **3 mandatory endpoints** to work:

```
GET  /health                              → {"status":"ok"}
GET  /api/v1/certificate-config           → pin config JSON
POST /api/v1/client-certs/enroll          → PKCS12 bytes
```

Everything else is optional.

---

## Endpoint Reference

### 1. Health Check (REQUIRED)

```
GET {configUrl}/health
```

**Response:**
```json
{"status": "ok"}
```

The library calls this after every pin update to verify the new pins work. Return `{"status": "ok"}` — nothing else is checked.

---

### 2. Certificate Config (REQUIRED)

```
GET {configUrl}/api/v1/certificate-config?currentVersion={int}
```

Returns the pin configuration. This is the core endpoint.

**Response (unsigned):**
```json
{
  "version": 1,
  "pins": [
    {
      "hostname": "api.example.com",
      "sha256": [
        "BBBBB/AAAA+CCCC1111DDDD2222EEEE3333FFFF4444GG==",
        "HHHHH/IIII+JJJJ5555KKKK6666LLLL7777MMMM8888NN=="
      ],
      "version": 1,
      "forceUpdate": false,
      "mtls": false,
      "clientCertVersion": null
    }
  ],
  "forceUpdate": false
}
```

**Rules:**
- Each host must have **at least 2 pins** (primary + backup for rotation). Client rejects entries with fewer pins; one malformed row no longer poisons the rest of the config (per-entry parsing).
- Each pin is Base64-encoded SHA-256 of the certificate's SubjectPublicKeyInfo (SPKI) — exactly 44 characters
- `mtls: true` means the host requires a client certificate
- `clientCertVersion` triggers client cert download when it changes

**Hostname patterns:**
- Exact match is case-insensitive: `api.example.com`
- Wildcards match a single sub-label only: `*.example.com` matches `api.example.com` but not `a.b.example.com` or the bare apex `example.com`
- **TLD-level wildcards are rejected by the client.** A pattern whose suffix has no dot (e.g. `*.com`, `*.tr`, `*.uk`) silently fails to match anything — the matcher treats it as a misconfiguration to avoid authorizing every domain under a TLD. Server admins should never publish such patterns; if you need them, the client won't honor them anyway.

**`forceUpdate` semantics:**
- The top-level `forceUpdate` flag is for **revocation events**, not routine rotation. When set, the client refuses to initialize against the previously cached config if your backend is unreachable — it treats the stored config as superseded.
- The flag now persists across client restarts (fixed in 2.0.8+). A backend admin pushing `forceUpdate=true` after a pin compromise can be confident the guarantee survives reboots; a restart no longer falls back to the revoked config silently.
- Availability trade-off: an attacker who can sustainably DoS your Config API can prevent affected devices from coming up. Keep the Config API behind diverse routes / CDN cache if you ever set this flag.

**How to generate a pin (any language):**
```
pin = base64(sha256(certificate.subjectPublicKeyInfo.bytes))
```

**Python example:**
```python
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import hashlib, base64

cert = x509.load_pem_x509_certificate(pem_bytes)
spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
pin = base64.b64encode(hashlib.sha256(spki).digest()).decode()
```

**Node.js example:**
```javascript
const crypto = require('crypto');
const forge = require('node-forge');

const cert = forge.pki.certificateFromPem(pemString);
const spki = forge.asn1.toDer(forge.pki.publicKeyToAsn1(cert.publicKey)).getBytes();
const pin = crypto.createHash('sha256').update(Buffer.from(spki, 'binary')).digest('base64');
```

**Go example:**
```go
import ("crypto/sha256"; "crypto/x509"; "encoding/base64")

cert, _ := x509.ParseCertificate(derBytes)
hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
pin := base64.StdEncoding.EncodeToString(hash[:])
```

---

### 3. Signed Config (REQUIRED — unless the client calls `allowUnsigned()`)

Wrap the config in a signed envelope:

```json
{
  "payload": "{\"version\":1,\"pins\":[...],\"issuedAt\":1715423456789,\"expiresAt\":1715509856789}",
  "signature": "MEUCIQD...base64..."
}
```

- `payload` — the config JSON as a **string** (not object)
- `signature` — ECDSA-SHA256 signature of the payload string, Base64-encoded

The payload JSON itself **MUST** include freshness fields (alongside the usual `version`, `pins`, `forceUpdate`):

| Field | Type | Required | Purpose |
|---|---|---|---|
| `issuedAt` | Long (Unix epoch **ms**) | Yes | Wall-clock moment the response was signed. Clients reject any new response whose `issuedAt` is not strictly greater than the previously applied config's `issuedAt` — guards against replay even when the signature is still cryptographically valid. |
| `expiresAt` | Long (Unix epoch **ms**) | Yes | Freshness window. Clients reject the response once the local clock crosses `expiresAt`, regardless of signature. Typical TTL: 24h (reference server's `CONFIG_TTL_SECONDS`). |

Missing or zero values for either field cause the client to refuse the response.

**Signing spec:**
- Algorithm: `SHA256withECDSA`
- Key: ECDSA P-256 (secp256r1)
- Input: UTF-8 bytes of `payload` string (which includes `issuedAt` / `expiresAt`)

**Python:**
```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import json, base64, time

now_ms = int(time.time() * 1000)
config_dict["issuedAt"] = now_ms
config_dict["expiresAt"] = now_ms + 24 * 60 * 60 * 1000  # 24h window

payload = json.dumps(config_dict)
signature = private_key.sign(payload.encode(), ec.ECDSA(hashes.SHA256()))
response = {"payload": payload, "signature": base64.b64encode(signature).decode()}
```

The Android library needs the **public key** (Base64 X.509 encoded) configured at build time:
```kotlin
PinVaultConfig.Builder()
    .configApi("api", "https://api.example.com/") {
        bootstrapPins(...)
        signaturePublicKey("MFkwEwYHKoZIzj0CAQYIKoZI...")  // REQUIRED
    }
    .build()
```

For dev/test setups against an unsigned endpoint, callers can opt out with `allowUnsigned()` inside the `configApi { }` block. Don't ship that to production — it disables signature, freshness, and replay protection together.

---

### 4. Client Certificate Enrollment (REQUIRED for mTLS)

```
POST {configUrl}/api/v1/client-certs/enroll
Content-Type: application/json
```

**Request body (token-based):**
```json
{
  "token": "one-time-token",
  "deviceAlias": "Warehouse Tablet #3",
  "deviceUid": "a1b2c3d4e5f6"
}
```

**Request body (auto-enrollment):**
```json
{
  "deviceId": "android-device-id",
  "deviceAlias": "Warehouse Tablet #3",
  "deviceUid": "a1b2c3d4e5f6"
}
```

**Response:** Raw PKCS12 bytes (`Content-Type: application/octet-stream`)

**Required response header:**
```
X-P12-SHA256: base64-encoded-sha256-of-response-body
```

The library refuses to install the P12 if this header is missing or its value doesn't match the computed SHA-256 of the body. Guards against a header-stripping MITM that drops the integrity check to inject an attacker-controlled P12. Compute it as `base64(sha256(p12Bytes))` with no padding stripping.

**PKCS12 requirements:**
- Must contain at least 1 private key + certificate entry
- Must be loadable with password `"changeit"` (configurable)
- Certificate must not be expired

---

### 5. Host Client Certificate Download (OPTIONAL)

```
GET {configUrl}/api/v1/client-certs/{hostname}/download
```

Called when a host has `mtls: true` and `clientCertVersion` changes. Returns PKCS12 bytes specific to that host.

---

### 6. Vault File Download (OPTIONAL)

```
GET {configUrl}/{custom-endpoint}
```

Returns raw bytes (any format). The endpoint path is user-defined:

```kotlin
.vaultFile("ml-model") {
    endpoint("api/v1/vault/ml-model")
}
```

**Optional response header:**
```
X-Vault-Version: 5
```

---

### 7. Vault File Report (OPTIONAL)

```
POST {configUrl}/api/v1/vault/report
Content-Type: application/json
```

```json
{
  "key": "ml-model",
  "version": 5,
  "status": "downloaded",
  "deviceManufacturer": "Samsung",
  "deviceModel": "Galaxy S24",
  "enrollmentLabel": "default",
  "deviceId": "a1b2c3d4e5f6",
  "deviceAlias": "Warehouse Tablet #3"
}
```

Status values: `"downloaded"`, `"cached"`, `"failed"`

Return `200 OK` — the library ignores the response body.

---

### 8. Connection Telemetry (OPTIONAL — only if you use `PinVaultBackendReporter`)

These two endpoints are **not part of the core library contract**. The
library never POSTs to them on its own — it only fires structured
events to the consumer's registered `PinVaultConnectionListener`. The
bundled `PinVaultBackendReporter` convenience class wires those events
to the schemas below; consumers who write their own listener can use
any schema they like.

If your backend is the bundled demo-server (or a fork keeping its
schema), implement these two routes. Otherwise, skip the section and
implement whatever wire format your custom listener emits.

**8a. Handshake Reports**
```
POST {managementUrl}/api/v1/connection-history/client-report
Content-Type: application/json
```

```json
{
  "hostname":           "api.example.com",
  "status":             "healthy",          // or "pin_mismatch"
  "responseTimeMs":     0,
  "pinMatched":         true,
  "pinVersion":         13,
  "deviceManufacturer": "Samsung",
  "deviceModel":        "Galaxy S24",
  "serverCertPin":      "AAAA…=",
  "storedPin":          "AAAA…="
}
```

Fired once per TLS handshake when `PinVaultBackendReporter` is
registered. Production fleets normally enable the reporter's
`dedupWindowMs` (heartbeat throttle) or `reportSuccessEvents = false`
(anomaly-only mode) to cut server load — handshake volume scales with
fleet size, not request volume.

**8b. Config-Rotation Reports**
```
POST {managementUrl}/api/v1/connection-history/config-update-report
Content-Type: application/json
```

```json
{
  "status":             "config_updated",   // or "config_unchanged" / "config_update_failed"
  "pinVersion":         22,
  "deviceManufacturer": "Xiaomi",
  "deviceModel":        "Mi9T",
  "failureReason":      "Backend unreachable"  // present only on config_update_failed
}
```

Fired by `PinVaultBackendReporter` whenever a config-update attempt
completes — periodic WorkManager refresh, explicit `updateNow()`, or
recovery-driven swap. The `reportSuccessEvents` flag suppresses
`config_updated` / `config_unchanged` reports but always lets
`config_update_failed` through.

Both endpoints should return `200 OK` on success; the reporter logs
any non-2xx at WARN and otherwise swallows the response. A missing
route (404) is logged once per failed POST and does not break the
listener pipeline — older demo-server forks without `8b` keep working.

**Authentication:** these endpoints are typically unauthenticated on
the demo-server (clients have no admin credential to present). M-04
input validation belongs on the server side: regex-validate
`hostname`, `deviceManufacturer`, `deviceModel` before any HTML render
of the admin UI.

---

## All Configurable Paths

| Config Method | Default Path | Purpose |
|---------------|-------------|---------|
| `configEndpoint()` | `api/v1/certificate-config` | Pin config |
| `healthEndpoint()` | `health` | Health check |
| `enrollmentEndpoint()` | `api/v1/client-certs/enroll` | Enrollment |
| `clientCertEndpoint()` | `api/v1/client-certs` | Host client cert base |
| `vaultReportEndpoint()` | `api/v1/vault/report` | Download reporting |
| `vaultFile("key") { endpoint("...") }` | User-defined | Vault files |

All paths are relative to `configUrl`. Leading `/` is stripped.

---

## TLS Requirements

- HTTPS required (TLS 1.2+)
- Server certificate must match the pins in the config
- For mTLS endpoints: require and validate client certificates
- Self-signed certificates work — the library pins by SPKI hash, not by CA

---

## Error Handling

| HTTP Status | Library Behavior |
|-------------|-----------------|
| 200 | Parse response |
| 4xx | Fail immediately (no retry) |
| 5xx | Retry with exponential backoff (2s, 4s, 6s...) |
| Network error | Retry up to `maxRetryCount` (default: 3) |

---

## Implementation Checklist

- [ ] `GET /health` returns `{"status":"ok"}`
- [ ] `GET /api/v1/certificate-config` returns valid pin config
- [ ] Every host has at least 2 SHA-256 pins
- [ ] Pins are Base64(SHA256(SPKI)) — 44 characters each
- [ ] Server certificate matches at least one pinned hash
- [ ] HTTPS with valid TLS (self-signed OK)
- [ ] `POST /api/v1/client-certs/enroll` returns PKCS12 (if using mTLS)
- [ ] Vault file endpoints return raw bytes (if using VaultFile feature)

---

## Reference Implementation

The `demo-server/` directory contains a complete Kotlin/Ktor reference implementation with:
- Docker support (`docker compose up`)
- API key authentication
- Web management dashboard
- Certificate generation and management
- Vault file distribution tracking
- Database migrations (Flyway + SQLite)
- OpenAPI documentation (`/docs`)

See `demo-server/README.md` for setup instructions.
