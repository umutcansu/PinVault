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
- Each host must have **at least 2 pins** (primary + backup for rotation)
- Each pin is Base64-encoded SHA-256 of the certificate's SubjectPublicKeyInfo (SPKI) — exactly 44 characters
- `mtls: true` means the host requires a client certificate
- `clientCertVersion` triggers client cert download when it changes

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

### 3. Signed Config (OPTIONAL)

If you want config integrity verification, wrap the config in a signed envelope:

```json
{
  "payload": "{\"version\":1,\"pins\":[...]}",
  "signature": "MEUCIQD...base64..."
}
```

- `payload` — the config JSON as a **string** (not object)
- `signature` — ECDSA-SHA256 signature of the payload string, Base64-encoded

**Signing spec:**
- Algorithm: `SHA256withECDSA`
- Key: ECDSA P-256 (secp256r1)
- Input: UTF-8 bytes of `payload` string

**Python:**
```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import json, base64

payload = json.dumps(config_dict)
signature = private_key.sign(payload.encode(), ec.ECDSA(hashes.SHA256()))
response = {"payload": payload, "signature": base64.b64encode(signature).decode()}
```

The Android library needs the **public key** (Base64 X.509 encoded) configured at build time:
```kotlin
PinVaultConfig.Builder("https://api.example.com/")
    .signaturePublicKey("MFkwEwYHKoZIzj0CAQYIKoZI...")
    .build()
```

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

**Optional response header:**
```
X-P12-SHA256: base64-encoded-sha256-of-response-body
```

If this header is present, the library verifies the P12 integrity.

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
