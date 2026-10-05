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
  "forceUpdate": false,
  "trustRoots": [
    "RRRRR/SSSS+TTTT9999UUUU0000VVVV1111WWWW2222XX=="
  ]
}
```

**Rules:**
- Each host must have **at least 2 pins** (primary + backup for rotation). Client rejects entries with fewer pins; one malformed row no longer poisons the rest of the config (per-entry parsing). Make them two *different* keys: the same pin written twice is no backup, and the reference server refuses it.
- A pin may name the leaf's key or the key of an issuer (intermediate or root CA) in the chain the host serves. The client accepts an issuer pin only when the leaf validly chains to that issuer, so pinning your CA lets a host renew its leaf with a new key; pinning the leaf is stricter.
- Each pin is Base64-encoded SHA-256 of the certificate's SubjectPublicKeyInfo (SPKI) — exactly 44 characters
- `mtls: true` means the host requires a client certificate
- `clientCertVersion` triggers client cert download when it changes
- `trustRoots` (optional, [ATTESTATION.md §10](ATTESTATION.md)): SHA-256 SPKI pins of root CAs, same format as a pin, at most 64, no duplicates. A client built with `managedTrustRoots()` accepts, for a host that has **no** pin entry, a chain the platform validates to one of these roots; hosts with a pin entry are still checked by their pins only. Omit the field (or send `[]`) when you do not use it — the reference server leaves it out of the payload when empty, so older clients see nothing new. It is part of the signed payload, so a change rolls out like a pin change. On `PUT /api/v1/certificate-config` a body that carries `trustRoots` replaces the list; a body without the field keeps the scope's current list.

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
| `issuedAt` | Long (Unix epoch **ms**) | Yes | Wall-clock moment the response was signed. Clients reject any response whose `issuedAt` is lower than the previously applied config's — and an equal `issuedAt` unless the content is identical (the same envelope served again, see below) — guarding against replay even when the signature is still cryptographically valid. |
| `expiresAt` | Long (Unix epoch **ms**) | Yes | Freshness window. Clients reject the response once the local clock crosses `expiresAt`, regardless of signature. Typical TTL: 24h (reference server's `CONFIG_TTL_SECONDS`). |

Missing or zero values for either field cause the client to refuse the response.

| Field | Type | Required | Purpose |
|---|---|---|---|
| `configApiId` | String | When clients set `serverScope(...)` | Names the Config API this config is for. One signing key often signs for several Config APIs (TLS and mTLS listeners, tenants, environments); without this field a config signed for one of them verifies for all of them. A client whose block calls `serverScope("<id>")` refuses a payload that lacks the field or carries another id; clients without `serverScope` ignore it. Put it in every signed payload — it costs nothing and lets apps turn the check on. The same id goes into v2 vault file signatures (section 6). The reference server (2.2.0) writes the listener's Config API id into every signed payload and leaves it out of unsigned ones. It is not part of a signing-key set: those are signed offline by the recovery keys and the library does not read a scope from them. |

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

**A transport of your own (`SignedConfigSource`).** An app that talks to your backend
through its own `CertificateConfigApi` (gRPC, a message bus, a file drop) hands the library
the envelope, not a parsed config: its API also implements `SignedConfigSource`
(`fetchSignedConfig(currentVersion)` → `SignedConfigResponse(payload, signature, …)`), and
the library verifies it exactly as above — signatures, `issuedAt` / `expiresAt`, replay,
key sets, `configApiId`. So whatever the transport, serve the same envelope and pass
`payload` on **byte for byte**: the signature covers its UTF-8 bytes, and re-serialising
the JSON on the way breaks it. A block with signing keys whose custom API does not
implement `SignedConfigSource` fails `PinVault.init` unless the app calls `allowUnsigned()`.

#### Optional envelope fields (library 2.1+)

All of these are optional and ignored by older clients. Clients announce what they understand on every signed-config request with `X-PinVault-Features: redelivery,multisig,keyset`.

```json
{
  "payload": "{…}",
  "signature": "<primary signer's signature — keep sending it for older clients>",
  "keyId": "<Base64 SHA-256 of the primary signer's SubjectPublicKeyInfo>",
  "signatures": [
    {"keyId": "…", "signature": "…"},
    {"keyId": "…", "signature": "…"}
  ],
  "signingKeys": {
    "payload": "{\"type\":\"pinvault-signing-keys\",\"version\":2,\"keys\":[\"MFkw…\",\"MFkw…\"],\"requiredSignatures\":1}",
    "signatures": [{"keyId": "<recovery key id>", "signature": "…"}]
  }
}
```

- **`signatures`: several signers (m-of-n).** Every signature is over the same `payload` bytes. A client configured with `requiredSignatures(n)` needs `n` valid signatures from distinct trusted keys. `keyId` is only a hint that tells the client which key to try first, and it is not signed. Keep putting the first signer's signature in `signature`: pre-2.1 clients only read that field.
- **`signingKeys`: key rotation and revocation.**
  - The operator signs this document **offline** with a recovery key, and the server relays it unchanged with every config.
  - A client configured with `recoveryPublicKeys(...)` checks four things: the recovery signatures, `type == "pinvault-signing-keys"`, a version higher than the one it holds, and a key list that contains no recovery key. It then replaces its trusted signing keys with `keys`.
  - An invalid set fails the whole response.
  - Before relaying a set, make sure your active signers are in it and cover `requiredSignatures`. A set they cannot satisfy makes every device that applies it reject every later config.
  - Signing the set: SHA256withECDSA over the UTF-8 payload, as for configs:

  ```bash
  printf '%s' "$KEYSET_PAYLOAD" | openssl dgst -sha256 -sign recovery.pem | openssl base64 -A
  ```

- **Vault files:** `X-Vault-Signature` carries the primary signature. With several signers, also send `X-Vault-Signatures: <keyId>:<signature>,<keyId>:<signature>`. Base64 never contains `:` or `,`. The v2 headers (`X-Vault-Signature-V2`, `X-Vault-Signatures-V2`, section 6) use the same encoding.

#### Serving the same signed config more than once

A backend may sign each distinct config **once** and serve the identical envelope until its content changes. This covers signing at publish time, an HSM or KMS that should not be called on every poll, and a CDN.

- Clients that send `X-PinVault-Features: redelivery` accept an envelope whose `issuedAt` equals the one they last applied, as long as it carries the same hosts, versions and pins. They treat it as "already current".
- Older clients reject the repeat as a replay, so give them a freshly signed envelope.
- `issuedAt` must still only ever grow. When content changes, including a change back to an earlier state (force on, then force off again), sign it anew. Never re-serve an older envelope: devices that applied a newer one reject it.

---

### 4. Client Certificate Enrollment (REQUIRED for mTLS)

```
POST {configUrl}/api/v1/client-certs/enroll
Content-Type: application/json
```

The device makes its own key in the Android Keystore and sends a certificate signing
request (library 2.1+). Issue the certificate over that key; do not generate keys for
devices. The library sends `X-PinVault-Features: p12password,csr`.

**Request body (a one-time token, or an enrollment code many devices share):**
```json
{
  "token": "one-time-token",
  "deviceAlias": "Warehouse Tablet #3",
  "deviceUid": "a1b2c3d4e5f6",
  "csr": "<Base64 DER PKCS#10>",
  "attestationChain": ["<Base64 DER, leaf>", "<Base64 DER>", "<Base64 DER, root>"]
}
```

**Request body (no token: open enrollment, or an application an administrator approves):**
```json
{
  "deviceId": "a1b2c3d4e5f6",
  "deviceAlias": "Warehouse Tablet #3",
  "deviceUid": "a1b2c3d4e5f6",
  "csr": "<Base64 DER PKCS#10>",
  "attestationChain": ["…"]
}
```

`deviceUid` is the device's ANDROID_ID and is sent on every path; `deviceId` is the same
value, sent only when there is no token. A device asking again for a request that waits
for approval sends `{"requestId": "…", "deviceAlias": …, "deviceUid": …, "csr": …,
"attestationChain": […]}` with a CSR over the same key.

**`deviceUid` is a claim.** Any holder of a token or an enrollment code can send any
value. Do not let a certificate act for a device id (vault tokens, key replacement,
per-device grants, lifting a revocation) unless that id is proven: the token was minted
for it (refuse a different one with `403 device_uid_mismatch` before spending the token),
it equals the client id, or the attestation above vouches for it with your app's package
and signer. The reference server stores this as `device_uid_proven`.

**Response.** Verify the CSR's self-signature, issue a certificate over its key (name it
after your own client id, not the CSR's subject) and answer JSON with
`X-PinVault-Cert-Format: pem-chain`:

```json
{ "clientId": "tablet-07", "chain": ["-----BEGIN CERTIFICATE-----…(leaf)", "-----BEGIN CERTIFICATE-----…(issuing CA)"] }
```

What the library holds the chain to before it stores it (next release):

- **at least two certificates** — the leaf, then the CA certificate that signed it. A leaf
  on its own is refused;
- the leaf is over the CSR's key, valid now, and its signature verifies under the next
  certificate;
- the leaf's lifetime is at most the app's `maxClientCertLifetimeDays` (default **825
  days**) — issue short-lived certificates (the reference server: 90 days) and let them
  renew;
- when the app pins your client CA (`clientCaPins`, the Base64 SHA-256 of the CA
  certificate's SubjectPublicKeyInfo), the leaf must be signed **directly** by a
  certificate of the chain whose key matches a pin. Publish that pin (and the next CA's,
  before you rotate) to app developers.

Renewals (`POST {clientCertEndpoint}/renew`, body `{"clientId": "…", "csr": "…"}`, the same
JSON answer) are held to the same rules; without pins a renewal must be signed by the CA
of the certificate it replaces.

**Key attestation (library and reference server 2.2.0).** A token says someone has the token; it does not say
the request comes from your app on a real phone. The library generates the device key
with an Android key attestation challenge and sends the chain the Keystore made for it:

- `attestationChain` — each certificate Base64 (standard, no line breaks) DER, **leaf
  first**, exactly as `KeyStore.getCertificateChain` returns it. Absent when the device
  could not attest the key (and for keys generated by library 2.1.x).
- **Challenge:** `SHA-256("pinvault-identity-key:v1:" + deviceUid)` over the UTF-8 bytes,
  where `deviceUid` is the value of the request's `deviceUid` field (or of `deviceId` when
  a request carries no `deviceUid`). 32 bytes, found in the leaf's attestation extension
  (OID `1.3.6.1.4.1.11129.2.1.17`, `attestationChallenge`).
- To rely on it, verify: the chain up to a Google hardware attestation root (and its
  revocation list); the challenge; that the leaf's public key **is the CSR's key**; the
  key's properties (security level TEE or StrongBox, origin GENERATED, purpose SIGN); the
  attested package name and signing certificate digest of your app; and a locked
  bootloader / verified boot state. Without the app binding any app can attest a key for
  any device id.
- Refuse with `403 {"error":"attestation_required"}` when a chain is needed and missing,
  or `403 {"error":"attestation_invalid","reason":"<why>"}`. Do not spend the token. The
  app sees `EnrollmentRefusal.ATTESTATION_FAILED` with your `reason`. On
  `attestation_required` for a key that has no chain (made by an earlier library
  version) the library makes a new key and sends the request once more, so the refusal
  must leave the token usable.
- Emulators attest with a software root: a server that enforces refuses them. Keep a
  non-enforcing mode for test fleets.
- Check it after the cheap refusals and **before** you spend anything (the token, a
  policy's device slot, a waiting request); on the code paths the chain comes with the
  first request and again with the pickup.

The reference server does all of this under `ENROLLMENT_ATTESTATION=off|warn|enforce`
(default `warn`: enroll either way, store the verdict with the identity and show it next
to every waiting request and certificate; `enforce`: the two `403`s above, and it does
not start without `ATTESTATION_PACKAGE_NAMES` + `ATTESTATION_SIGNER_SHA256`). Its
`reason` values: `chain_missing`, `chain_malformed`, `chain_too_long`, `key_mismatch`,
`untrusted_root`, `chain_broken`, `certificate_expired`, `certificate_revoked`,
`revocation_list_stale`, `challenge_mismatch`, `software_attestation`, `purpose_not_sign`,
`origin_not_generated`, `device_unlocked`, `boot_not_verified`, `patch_level_too_old`,
`package_not_allowed`, `signer_not_allowed`, `app_binding_not_configured`,
`device_id_missing`.

The user-auth key that seals `user_auth` vault files is attested the same way at its own
registration (`POST …/vault/devices/{deviceId}/public-key` with `"purpose":"user_auth"`
and `"attestationChain"`); its challenge is
`SHA-256("pinvault-user-auth-key:v1:" + deviceId)`, with the `deviceId` of the URL. The
two prefixes differ on purpose: a chain made for one key cannot be replayed for the
other. For that key also check that user authentication is required, and how: the
reference server refuses a time-bound key (`authTimeout` set) from Android 11 or newer,
and with `USER_AUTH_REQUIRE_PER_USE=true` from every version.

**A key the server makes (P12) — only for apps that ask for it.** Library versions before
2.1, and blocks that call `allowServerGeneratedKey()` on a device whose Keystore cannot
make a key, send no `csr`. Answer `403 {"error":"csr_required"}` unless you decide to
support them (the reference server: `ENROLLMENT_P12=on|off`, default `on` for older apps,
`off` in production; also refused under `ENROLLMENT_ATTESTATION=enforce`, since a key
you made cannot be attested); refuse before the token is spent. The app sees
`EnrollmentRefusal.CSR_REQUIRED`. If you do support it, issue the certificate from the
same client CA as CSR certificates (CA:false, client authentication only) — **never as a
self-signed certificate added to your truststore as its own trust anchor**: an anchor
that can sign lets its holder sign a leaf naming any other client id, and a server that
reads the identity from the CN accepts it. (The reference server did that until 2.2.0;
it now also checks on every mTLS request that the presented certificate is the one on
record for the id its CN names.) The answer is raw PKCS12 bytes
(`Content-Type: application/octet-stream`) with

```
X-P12-SHA256: base64-encoded-sha256-of-response-body
```

The library refuses to install the P12 if this header is missing or its value doesn't match the computed SHA-256 of the body. Guards against a header-stripping MITM that drops the integrity check to inject an attacker-controlled P12. Compute it as `base64(sha256(p12Bytes))` with no padding stripping.

**P12 password:** the library sends `X-PinVault-Features: p12password`. Wrap the bundle with a random password used for this response only and return it in `X-P12-Password`. Without that header the bundle must open with the app's `clientKeyPassword` (default `"changeit"`). Never use the password that protects your own keystores: every app would have to carry it. The same applies to `GET {clientCertEndpoint}/{hostname}/download`. The library (next release) imports the key from the bundle into the Android Keystore as a non-exportable key and keeps only the certificate chain.

**Never answer a request that carries a `csr` with a P12.** The library (next release)
refuses such an answer unless the block called `allowServerGeneratedKey()` — and by then
your one-time token is spent.

**Refusals (library 2.1).** Answer a refusal with a 4xx and a JSON body
`{"error": "<code>", "message": "<text>"}`; the app learns the reason from
`PinVault.enrollForResult`. The library maps `401` to *invalid token*, and the `error`
codes `device_already_enrolled`, `identity_already_enrolled`, `revoked`,
`enrollment_rejected`, `enrollment_limit_reached`, `enrollment_request_expired`,
`csr_required` and `attestation_required` / `attestation_invalid` (whose `reason` is shown
when there is no `message`) to their own reasons; anything else is shown with its status
and code. A 5xx is a failure to answer, not a refusal.

**Waiting for approval (library 2.1).** A server where an administrator approves devices
first answers the enrollment with `202`:

```json
{ "status": "pending", "requestId": "1d6b06d6…", "clientId": "field-tablets-9h5e3a", "message": "…" }
```

with an optional `Retry-After` (seconds). The library keeps its key and the request id
and asks again later — on the app's call, at `init` and on its periodic update — with the
same endpoint and `{"requestId": "…", "csr": "…"}` (no token): issue the certificate if the
device was approved, answer `202` again while it waits, or refuse. Check that the CSR is
signed by the key the request was made with; the request id is no secret. On
`404 enrollment_request_not_found`, `403 enrollment_request_mismatch`,
`403 enrollment_rejected` or `410 enrollment_request_expired` (nobody decided in time) the
library forgets the request and its key, so the device's next attempt is a new request.
(The reference server does this for enrollment policies — one code many devices share —
and for applications without a code: a token-less `{"deviceId": …, "csr": …}` while the
administrator lets devices apply; see the README.)

The device shows a verification code made from its own key, so put the same code next to
the request in your approval screen: the first **80 bits** (10 bytes) of the SHA-256 of the
CSR's SubjectPublicKeyInfo (DER), as sixteen Crockford base32 characters
(`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, five bits each, most significant first) in groups of
four, `XXXX-XXXX-XXXX-XXXX`. Check vectors: a digest starting with 80 zero bits →
`0000-0000-0000-0000`, with 80 one bits → `ZZZZ-ZZZZ-ZZZZ-ZZZZ`; the digest
SHA-256(`"pinvault"`) (`07691832165f0df081e6…`) → `0XMH-GCGP-BW6Z-10F6`. Return it as
`verificationCode` in the `202` if you like — the library shows the one it computes
itself.

Library 2.1.x showed the first 40 bits only (`0XMH-GCGP`, the first eight characters of
the code above). Forty bits can be matched on purpose: someone who watches a device wait
generates keys until one has the same code — minutes of work — and has their own request
approved in its place. Show and compare all sixteen characters; during a rollout an older
app's eight are the prefix of yours.

**Known limitation of the reference implementation — one-shot tokens.**
`demo-server` issues the certificate and marks the enrollment token used
*before* the response reaches the device. If the device then refuses the P12 —
a stripped `X-P12-SHA256` header, a truncated body, a mid-transfer network
failure — the token is already spent and the operator has to issue a new one.
The device is left unenrolled while the server believes it is enrolled, and the
certificate that was minted for it stays valid until it is revoked.

If you are designing your own enrollment flow, do not copy this shape. Either
mark the token used only after the device confirms the install (a second round
trip: `POST …/enroll/confirm` with the P12 hash the device computed) and expire
certificates that are never confirmed, or make the token valid for a short
window of repeated attempts rather than exactly one. `demo-server` keeps the
single-shot behaviour: the fix is a protocol change on both sides and this is a
reference server, not a production one.

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

**Response headers:**
```
X-Vault-Version: 5
X-Vault-Signature: <base64 ECDSA signature>
```

`X-Vault-Signature` is **required** (library 2.1+) when the client block has a
signing key: the device refuses an unsigned file. It signs
`pinvault-vault-file:v1:<key>:<version>:<lowercase sha256 hex of the plaintext>`
with the config signing key; see section 3 for `X-Vault-Signatures` (m-of-n).

**v2: the signature names the Config API (library and reference server 2.2.0).** The v1 string does not say
which Config API a file belongs to, so where one key signs for several, a file of one
verifies for another. Send, next to the v1 headers:

```
X-Vault-Signature-V2: <base64 ECDSA signature, primary signer>
X-Vault-Signatures-V2: <keyId>:<signature>,<keyId>:<signature>
```

over

```
pinvault-vault-file:v2:<configApiId>:<key>:<version>:<lowercase sha256 hex of the plaintext>
```

with the same keys and the same `configApiId` as in the signed config payload (section
3). A client whose block sets `serverScope("<configApiId>")` **requires** the v2 headers
and ignores v1; a client without it verifies v1 and ignores v2. Send both. The plaintext
is the file's content before any per-device encryption (`end_to_end`, `user_auth`), as
for v1. `X-Vault-Version` must be the version the signature names, and versions must not
jump: the library refuses a version more than 1,000,000 above the one it holds (or above
zero for a first copy).

The library keeps the signatures it accepted with the stored copy and verifies them again
each time the app reads the file, with the signing keys trusted at that moment — a key you
revoke with a signing-key set stops its files from being read, not only from being
downloaded. A `304 Not Modified` (or the same version again) is also what keeps a file
with an offline lifetime (`maxOfflineAge`) readable: answer it only to a device that may
still have the file.

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

### 9. Attestation and PinVault-Token (OPTIONAL — only if the app calls `attestation()`)

The contract is [ATTESTATION.md](ATTESTATION.md); this is the short form and
the part your **API** has to do.

The library talks to two endpoints on the config server:

| Endpoint | What it does |
|---|---|
| `GET /api/v1/attest/challenge` | Answers `{"nonce": "…", "expiresIn": 120, "serverTime": 1759660800000}`. The nonce is single-use and short-lived. |
| `POST /api/v1/attest` | Takes `{v: 1, nonce, deviceId, publicKey, attestationChain?, report, signature, currentConfigVersion?, currentIssuedAt?, hosts?}` where `signature` is `SHA256withECDSA` over the UTF-8 bytes of `pinvault-attest:v1:<nonce>:<deviceId>:<sha256-hex(report)>` with the device's EC P-256 Keystore key (the same key that signs mTLS CSRs). Answers `{"result": "pass"|"reject", "arc", "warnings", "rejectionReasons"?, "token"?, "tokenExpiresAt"?, "tokenTtlSeconds", "nextAttestIn", "configChanged", "config"?, "device": {...}, "policyVersion"}`. On `pass` the `token` is the `PinVault-Token`; on `reject` there is no token and no `config`. |

The reference server registers the device key on first sight (optionally
requiring an Android Key Attestation chain, `ATTESTATION_KEY_POLICY`),
evaluates the report against a per-Config-API policy and signs the token.
If you implement the server yourself, keep the order of checks in
ATTESTATION.md §2.2 and never answer a token to a rejected device.

**What your backend does on every request from the app** — the library adds
`PinVault-Token: <jwt>` to requests whose host is a token host. Verify it
locally; nothing calls the PinVault server on the request path:

```
header  { "alg": "HS256", "typ": "JWT", "kid": "2026-10-05-01" }
payload { "iss": "pinvault", "sub": "<deviceId>", "aud": "<configApiId>",
          "iat": 1759660800, "exp": 1759661100, "jti": "…",
          "did": "<deviceId>", "arc": "7f3a9c1e", "pol": 3,
          "anno": ["staff", "canary"] }        // only when the device has annotations
```

1. Load the secrets once (and again after a rotation):
   `GET /api/v1/attestation/token-secrets` on the management port (admin key;
   under two-person approval the requester sends the request again once it is
   approved) → `{"active": "<kid>", "secrets": [{"kid", "secret" (Base64, 32 bytes), "active", "createdAt"}]}`.
   Keep **every** listed secret keyed by `kid`: tokens signed before a
   rotation stay valid until they expire.
2. Pick the secret the header's `kid` names (unknown `kid` → refuse).
3. Verify the HS256 signature, `exp` with at most 60 s of leeway, and `aud`
   equal to your Config API id. Optionally require `anno` to contain a
   string (staff builds, canaries), or `pol` to be at least a version.
4. Refuse with `401` and `WWW-Authenticate: PinVault-Token error="invalid_token", error_description="…"`
   (body `{"error":"invalid_token","reason":"expired|signature|audience|missing|malformed|unknown_kid"}`).
   The library recognises a `401` that names `PinVault-Token`, attests once
   more and retries the request once.

The reference implementation is `demo-server/src/main/kotlin/com/example/pinvault/server/plugin/PinVaultTokenAuth.kt`
(the mock hosts install it with `MOCK_HOST_REQUIRE_TOKEN=true`). Snippets:

**Kotlin / Java (javax.crypto, no library)**

```kotlin
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.*

/** secrets: kid → 32 raw bytes, from GET /api/v1/attestation/token-secrets. */
fun verifyPinVaultToken(token: String, secrets: Map<String, ByteArray>, audience: String, leewaySeconds: Long = 60): JsonObject? {
    val parts = token.split('.')
    if (parts.size != 3) return null                                        // malformed
    val url = Base64.getUrlDecoder()
    val header = Json.parseToJsonElement(String(url.decode(parts[0]))).jsonObject
    if (header["alg"]?.jsonPrimitive?.content != "HS256") return null       // malformed
    val secret = secrets[header["kid"]?.jsonPrimitive?.content] ?: return null   // unknown_kid
    val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }
    val expected = mac.doFinal((parts[0] + "." + parts[1]).toByteArray(Charsets.US_ASCII))
    if (!java.security.MessageDigest.isEqual(expected, url.decode(parts[2]))) return null   // signature
    val payload = Json.parseToJsonElement(String(url.decode(parts[1]))).jsonObject
    val now = System.currentTimeMillis() / 1000
    if (now > payload["exp"]!!.jsonPrimitive.long + leewaySeconds) return null     // expired
    if (payload["aud"]?.jsonPrimitive?.content != audience) return null              // audience
    // Optional: payload["anno"]?.jsonArray must contain "staff"; payload["pol"] >= 3.
    return payload   // payload["did"] is the device id, payload["arc"] the result code
}
```

**Node (`jsonwebtoken`)**

```js
const jwt = require('jsonwebtoken');
// kid → Buffer of the 32 secret bytes (Base64-decoded from GET /api/v1/attestation/token-secrets)
const secrets = { '2026-10-05-01': Buffer.from(process.env.PINVAULT_SECRET_01, 'base64') };

function verifyPinVaultToken(token, audience) {
  return jwt.verify(token, (header, done) => {
    const secret = secrets[header.kid];
    done(secret ? null : new Error('unknown_kid'), secret);
  }, { algorithms: ['HS256'], audience, issuer: 'pinvault', clockTolerance: 60 });
}

// Express middleware
app.use((req, res, next) => {
  const token = req.get('PinVault-Token');
  if (!token) return refuse(res, 'missing');
  verifyPinVaultToken(token, 'default-tls', (err, claims) => {
    if (err) return refuse(res, err.name === 'TokenExpiredError' ? 'expired' : err.message === 'unknown_kid' ? 'unknown_kid' : 'signature');
    if (!(claims.anno || []).includes('staff')) { /* optional annotation rule */ }
    req.device = claims.did; req.arc = claims.arc;
    next();
  });
});
function refuse(res, reason) {
  res.set('WWW-Authenticate', `PinVault-Token error="invalid_token", error_description="${reason}"`);
  res.status(401).json({ error: 'invalid_token', reason });
}
```

**Python (`PyJWT`)**

```python
import base64, jwt
from jwt import InvalidTokenError, ExpiredSignatureError, InvalidAudienceError

# kid -> 32 raw bytes, from GET /api/v1/attestation/token-secrets
SECRETS = {"2026-10-05-01": base64.b64decode(SECRET_01_B64)}

def verify_pinvault_token(token: str, audience: str) -> dict:
    kid = jwt.get_unverified_header(token).get("kid")
    secret = SECRETS.get(kid)
    if secret is None:
        raise InvalidTokenError("unknown_kid")
    return jwt.decode(token, secret, algorithms=["HS256"], audience=audience,
                      issuer="pinvault", leeway=60)

# Flask
@app.before_request
def require_pinvault_token():
    token = request.headers.get("PinVault-Token")
    if not token:
        return refuse("missing")
    try:
        claims = verify_pinvault_token(token, "default-tls")
    except ExpiredSignatureError:
        return refuse("expired")
    except InvalidAudienceError:
        return refuse("audience")
    except InvalidTokenError as e:
        return refuse("unknown_kid" if "unknown_kid" in str(e) else "signature")
    if "staff" not in claims.get("anno", []):
        pass  # optional annotation rule
    g.device_id, g.arc = claims["did"], claims.get("arc")

def refuse(reason):
    resp = jsonify(error="invalid_token", reason=reason); resp.status_code = 401
    resp.headers["WWW-Authenticate"] = f'PinVault-Token error="invalid_token", error_description="{reason}"'
    return resp
```

Rotation: `POST /api/v1/attestation/token-secrets/rotate` makes a new active
secret; reload the list in your backends (the old `kid` keeps verifying
until you `DELETE /api/v1/attestation/token-secrets/{kid}`). Tokens live 5
minutes by default, so a rotation is complete a few minutes after every
backend has the new secret.

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
- [ ] Every host has at least 2 different SHA-256 pins
- [ ] Pins are Base64(SHA256(SPKI)) — 44 characters each
- [ ] Server certificate matches at least one pinned hash
- [ ] HTTPS with valid TLS (self-signed OK)
- [ ] `POST /api/v1/client-certs/enroll` issues over the device's CSR and answers leaf + CA certificate as `pem-chain` (if using mTLS); a request without a CSR gets `403 csr_required`
- [ ] The enrollment key's `attestationChain` is verified, bound to your app's package and signing certificate (challenge `SHA-256("pinvault-identity-key:v1:" + deviceUid)`)
- [ ] The verification code next to a waiting request is the 16-character, 80-bit one
- [ ] A claimed `deviceUid` is trusted only when proven (token bound to it, equal to the client id, or attested)
- [ ] Pin configs follow the library's rules before you sign them (hosts unique ignoring case, at most 2000 hosts, 2–32 pins each, LDH names with at most one leading `*.`): one bad entry makes every device refuse the whole config
- [ ] Signed payloads carry `configApiId`; vault files carry `X-Vault-Signature-V2` as well as `X-Vault-Signature`
- [ ] Vault file endpoints return raw bytes (if using VaultFile feature)
- [ ] If the app attests: `/api/v1/attest/challenge` and `/api/v1/attest` as in ATTESTATION.md, no token to a rejected device, and your API verifies `PinVault-Token` (HS256 by `kid`, `exp` ≤ 60 s leeway, `aud`) and answers `401` naming `PinVault-Token` otherwise

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
