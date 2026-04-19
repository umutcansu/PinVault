# Changelog

## 2.0.0 — 2026-04-17

**PinVault 2.0 — Multi-Config-API + Vault Scoping + Per-File Security.**

### Config / DSL

- **Multi-Config-API DSL**. `PinVaultConfig.Builder()` accepts one or more
  `.configApi(id, url) { … }` blocks. Each block has its own bootstrap pins,
  TLS/mTLS pipeline, and endpoint paths. Vault files bind to a specific
  block via `.vaultFile(key) { configApi(id); … }`.
- **Per-file access policies**: `PUBLIC`, `API_KEY`, `TOKEN`, `TOKEN_MTLS`.
  `TOKEN` is the default — admin issues per-(device, file) tokens via
  `POST /api/v1/vault/{key}/tokens`. Replaced or revoked tokens invalidate
  immediately.
- **End-to-end encryption**: `encryption(VaultFileEncryption.END_TO_END)`
  wraps content with the device's Android-Keystore-backed RSA 2048 key
  (StrongBox when available) using RSA-OAEP-SHA256 + AES-256-GCM hybrid.
- **Server-side pin scoping**: `wantPinsFor(...)` + per-device
  `device_host_acl` table. Server returns only pins for hostnames the
  device is authorized to see; unauthorized requests logged.

### Library

- **`VaultFileDecryptor`**: pure JCA decryption of E2E envelopes (no
  Android deps — runs in Robolectric and plain JVM).
- **`DeviceKeyProvider`**: Android Keystore backend + software fallback.
- **`ConfigApiClient` + `VaultFileRouter`**: internal runtime that routes
  each vault fetch to the correct per-block client. Per-Config-API
  `CertificateConfigStore` namespaces pin storage to prevent cross-API
  hostname collisions.
- **`CertificateConfigApi`** gained three new methods with default
  implementations:
  - `fetchScopedConfig(currentVersion, hosts, deviceId)` for pin scoping
  - `downloadVaultFileWithMeta(endpoint, currentVersion, deviceId, accessToken)`
    for policy + encryption support
  - `registerDevicePublicKey(deviceId, publicKeyPem)` for E2E
- **`VaultFileConfig`** gained `configApiId`, `accessPolicy`,
  `accessTokenProvider`, `encryption` fields.

### Demo server

- **Flyway V2 migration**: drops and recreates `vault_files` and
  `vault_distributions` with `config_api_id` scoping. Adds four new tables:
  `vault_file_tokens`, `device_public_keys`, `device_host_acl`,
  `default_host_acl`. Adds `config_apis.vault_enabled` column.
- **New stores**: `VaultFileTokenStore`, `DevicePublicKeyStore`,
  `DeviceHostAclStore`.
- **New services**: `VaultEncryptionService` (RSA-OAEP + AES-GCM hybrid),
  `VaultAccessTokenService` (SHA-256 hashed, constant-time validation).
- **`vaultRoutes(configApiId, …)`**: every route Config-API-scoped.
  Enforces access policy (public / api_key / token / token_mtls) and
  applies end-to-end encryption when configured.
- **`CertificateConfigRoutes`**: accepts `?hosts=` parameter, intersects
  with `device_host_acl`, logs unauthorized host requests.
- **`AdminVaultRoutes`**: `PUT /config-apis/{id}/vault-enabled`,
  per-device + default host ACL CRUD endpoints.

### Web UI

- File list shows access policy badge + encryption indicator.
- Upload dialog has policy/encryption dropdowns; default is `token` + `plain`.
- File detail page includes a **Token Management** card (list + issue token
  modal that shows plaintext once + revoke).
- Config API detail page has a **Vault (V2)** section with vault-enabled
  toggle and a "Cihaz ACL yönet" button opening the ACL manager (default
  ACL editor + per-device ACL editing).

### Demo app

- **New `VaultSecurityDemoActivity`** demonstrating multi-API + 3 files
  across public / token / E2E policies, with a token editor dialog.
- `VaultFileDemoActivity` and `BaseDemoActivity` migrated to the new DSL.

### Security

- Default vault file policy is `token` — unauthenticated fetch is no longer
  the path of least resistance. `public` must be explicitly chosen.
- Token plaintext is generated from `SecureRandom` (32 bytes → URL-safe
  base64), returned once, stored as SHA-256 only, validated with
  `MessageDigest.isEqual` (constant-time).
- `token_mtls` requires both a matching token and an mTLS cert whose CN
  equals `X-Device-Id`. Token leak alone does not grant access.
- Device RSA private key stays in Android Keystore; server never sees it.

### Tests

- **+38 server tests**: `VaultRoutesAccessPolicyTest` (11),
  `VaultEncryptionServiceTest` (7), `VaultFileTokenStoreTest` (9),
  `DeviceHostAclStoreTest` (9), existing suites migrated to scoped stores.
- **+17 library tests**: `VaultFileDecryptorTest` (6),
  `MultiConfigApiConfigTest` (10 DSL validations), `PinVaultConfigTest`
  updated to V2 DSL.
- Total: 143 library + 109 server = **252 tests, 0 failures**.
