package io.github.umutcansu.pinvault.api

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.EnrollmentResult
import io.github.umutcansu.pinvault.model.VaultDownloadReport
import io.github.umutcansu.pinvault.model.VaultFetchResponse

/**
 * Backend API interface for fetching SSL certificate configuration.
 *
 * Implement this to integrate PinVault with any backend (REST, gRPC, local files, etc.).
 * The default implementation [DefaultCertificateConfigApi] provides HTTP/Retrofit-based
 * communication. Override any method to customize behavior.
 *
 * Example custom implementation:
 * ```kotlin
 * class MyCertApi : CertificateConfigApi {
 *     override suspend fun fetchConfig(currentVersion: Int): CertificateConfig {
 *         return myBackend.getPins(currentVersion)
 *     }
 *     override suspend fun healthCheck(): Boolean = true
 *     // ... other methods
 * }
 * ```
 *
 * ## Signed configs
 * [fetchConfig] returns a parsed config: by then nothing is left to verify.
 * A Config API block with signing keys therefore needs the custom API to
 * implement [SignedConfigSource] as well — PinVault then fetches the signed
 * envelope and verifies it itself (signatures, `issuedAt` / `expiresAt`,
 * replay, signing-key sets, `serverScope`), exactly as for its own HTTP
 * client, and [fetchConfig] is not called. Without it `PinVault.init` fails
 * for that block unless it called `allowUnsigned()`. Whatever the mode, every
 * config is checked for well-formed host names and pins before it is applied.
 */
interface CertificateConfigApi {
    /**
     * Checks if the backend is reachable.
     * @return true if healthy, false otherwise.
     */
    suspend fun healthCheck(): Boolean

    /**
     * Fetches the latest certificate config from the backend.
     *
     * Called for blocks that run unsigned (`allowUnsigned()`). A block with
     * signing keys is served through [SignedConfigSource.fetchSignedConfig]
     * instead; see the class comment.
     *
     * @param currentVersion The version currently held by the client (0 if first call).
     * @throws Exception on network or server errors.
     */
    suspend fun fetchConfig(currentVersion: Int): CertificateConfig

    /**
     * V2 scoped fetch: the backend returns only pins for the intersection of
     * [hosts] and the device's server-side ACL. Omit [hosts] to let the
     * server decide based purely on device ACL (or return everything when
     * [deviceId] is also null — legacy behavior).
     *
     * Default implementation drops the extra parameters and delegates to
     * [fetchConfig] so existing backend impls continue to work.
     */
    suspend fun fetchScopedConfig(
        currentVersion: Int,
        hosts: List<String>? = null,
        deviceId: String? = null
    ): CertificateConfig {
        return fetchConfig(currentVersion)
    }

    /**
     * Downloads a host-specific PKCS12 client certificate for mTLS.
     * Called when [io.github.umutcansu.pinvault.model.HostPin.mtls] is true
     * and [io.github.umutcansu.pinvault.model.HostPin.clientCertVersion] has changed.
     *
     * @param hostname The host whose client cert to download.
     * @return PKCS12 bytes for the host's client certificate.
     */
    suspend fun downloadHostClientCert(hostname: String): ByteArray

    /**
     * Downloads a vault file from the given endpoint path.
     *
     * Legacy method (V1). New code should use [downloadVaultFileWithMeta] to
     * receive encryption metadata needed for [VaultFetchResponse.encryption] =
     * "end_to_end" files.
     *
     * @param endpoint Relative path to the file endpoint (e.g. "api/v1/vault/ml-model").
     * @return Raw file bytes.
     */
    suspend fun downloadVaultFile(endpoint: String): ByteArray

    /**
     * V2 download with full metadata — returns content + version + encryption
     * mode. Required for per-file policy (token) and encryption (end_to_end)
     * support introduced in V2.
     *
     * Default implementation wraps [downloadVaultFile] for backward
     * compatibility: callers that haven't overridden this get plain bytes
     * with unknown version.
     *
     * @param endpoint Relative path to the file.
     * @param currentVersion Version currently held by client (for 304 support).
     * @param deviceId Device identifier sent as X-Device-Id header.
     * @param accessToken Per-file token sent as X-Vault-Token header (required
     *                    when the file's access_policy is "token" or "token_mtls").
     */
    suspend fun downloadVaultFileWithMeta(
        endpoint: String,
        currentVersion: Int = 0,
        deviceId: String? = null,
        accessToken: String? = null
    ): VaultFetchResponse {
        // Default: fall through to legacy downloadVaultFile. Returns plain
        // bytes with version=0 — good enough for tests and custom backends
        // that haven't implemented the new endpoint.
        val bytes = downloadVaultFile(endpoint)
        return VaultFetchResponse(content = bytes, version = 0, encryption = "plain")
    }

    /**
     * Registers the device's RSA public key with a Config API. The server
     * uses this key to wrap session keys for encryption = "end_to_end" files.
     *
     * Default implementation is a no-op — custom backends without E2E support
     * can ignore this call.
     *
     * @param deviceId Device identifier.
     * @param publicKeyPem PEM-encoded RSA public key
     *        ("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----").
     */
    suspend fun registerDevicePublicKey(deviceId: String, publicKeyPem: String) {
        // Default: no-op.
    }

    /**
     * Registers the device's user-auth RSA public key: the key the server
     * wraps `encryption = "user_auth"` files with, whose private half the
     * hardware uses only after the screen lock or a strong biometric. The
     * reference server takes it at the same endpoint as the E2E key, with
     * `"purpose": "user_auth"`.
     *
     * [attestationChain] is the key's Android key attestation chain, each
     * certificate Base64 (standard, no line breaks) DER, leaf first — empty
     * when the device could not attest the key. The leaf's attestation
     * challenge is SHA-256 of `pinvault-user-auth-key:v1:<deviceId>`. A
     * backend that checks it can tell a hardware key of the app from a key
     * made in software with the app's credentials (the reference server:
     * `USER_AUTH_ATTESTATION=enforce`).
     *
     * Default implementation is a no-op — custom backends without
     * `user_auth` files can ignore this call. An implementation compiled
     * against PinVault 2.1.1 or earlier does not have this method; PinVault
     * then reports `user_auth` files as unsupported by the backend.
     */
    suspend fun registerUserAuthPublicKey(deviceId: String, publicKeyPem: String, attestationChain: List<String>) {
        // Default: no-op.
    }

    /**
     * Enrolls a device to obtain a PKCS12 client certificate whose key the
     * server generated. Called by [io.github.umutcansu.pinvault.PinVault.enroll]
     * and [io.github.umutcansu.pinvault.PinVault.autoEnroll] only for a
     * block that called `allowServerGeneratedKey()`, when the device could
     * not make its own key or the backend takes no CSR; every other
     * enrollment goes through [enrollWithCsr].
     *
     * Implement token-based or device-based enrollment depending on your backend.
     *
     * @param token One-time enrollment token (null for auto-enrollment).
     * @param deviceId Device identifier for auto-enrollment (null for token-based).
     * @param deviceAlias Human-readable device name (optional).
     * @param deviceUid Unique device identifier (optional).
     * @return [EnrollmentResult] containing P12 bytes and optional hash.
     * @throws io.github.umutcansu.pinvault.model.EnrollmentRefusedException when the
     *         server refuses (the app learns why from `PinVault.enrollForResult`);
     *         any other Exception on other failures.
     */
    suspend fun enroll(
        token: String?,
        deviceId: String?,
        deviceAlias: String? = null,
        deviceUid: String? = null
    ): EnrollmentResult

    /**
     * Enrolls with a certificate signing request over the device's own key
     * (the key never leaves the Android Keystore). Same authentication as
     * [enroll] — token or device id — plus the DER-encoded PKCS#10 [csrDer].
     *
     * Return the issued chain in [EnrollmentResult.certificateChainPem]: at
     * least the leaf and the CA certificate that signed it (a chain of one is
     * refused). A P12 result, or `null` ("this backend cannot take a CSR";
     * the library then calls [enroll]), is accepted only when the block
     * called `allowServerGeneratedKey()`; otherwise the enrollment fails.
     *
     * A backend where an administrator approves devices first throws
     * [io.github.umutcansu.pinvault.model.EnrollmentPendingException] with a
     * request id. The library calls again later with that [requestId] (and
     * no token), with a CSR signed by the same key: issue the certificate if
     * the device was approved, throw the pending exception again if it still
     * waits, or refuse ([io.github.umutcansu.pinvault.model.EnrollmentRefusedException]).
     *
     * Default: `null`.
     */
    suspend fun enrollWithCsr(
        token: String?,
        deviceId: String?,
        deviceAlias: String? = null,
        deviceUid: String? = null,
        csrDer: ByteArray,
        requestId: String? = null
    ): EnrollmentResult? = null

    /**
     * [enrollWithCsr] with the device key's Android key attestation: what
     * PinVault calls. [attestationChain] is the chain the Android Keystore
     * made for the key, each certificate Base64 (standard, no line breaks)
     * DER, leaf first — empty when the device could not attest the key. The
     * leaf's attestation challenge is SHA-256 of
     * `pinvault-identity-key:v1:<device id>` (UTF-8), where the device id is
     * the [deviceUid] of this request, or its [deviceId] when no `deviceUid`
     * is sent. A backend that verifies it (the chain up to a Google hardware
     * attestation root, the challenge, the app's package and signing
     * certificate, the leaf's key = the CSR's key) can tell a hardware key of
     * the real app on a real phone from a key made by a script, an emulator
     * or a repackaged app that got hold of a token. To refuse, throw
     * [io.github.umutcansu.pinvault.model.EnrollmentRefusedException] with
     * `attestation_required` or `attestation_invalid`.
     *
     * Default: drops the chain and calls [enrollWithCsr], so backends
     * written before this method keep working. An implementation compiled
     * against an earlier PinVault does not have it; PinVault then calls the
     * six-argument method itself.
     */
    suspend fun enrollWithCsr(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csrDer: ByteArray,
        requestId: String?,
        attestationChain: List<String>
    ): EnrollmentResult? = enrollWithCsr(token, deviceId, deviceAlias, deviceUid, csrDer, requestId)

    /**
     * [enrollWithCsr] with an integrity token as well: what PinVault calls
     * when the app set `integrityTokenProvider(...)` and the provider returned
     * a token. [integrityToken] is that token (a Play Integrity token, or a
     * RASP product's attestation), bound to this request by its request
     * hash; see [io.github.umutcansu.pinvault.model.IntegrityTokenProvider]
     * for how the hash is made. A backend that verifies it decodes the token
     * with its issuer, recomputes the hash from the request and checks the
     * verdict. To refuse, throw
     * [io.github.umutcansu.pinvault.model.EnrollmentRefusedException] with
     * `integrity_required` or `integrity_invalid` (reported to the app as
     * [io.github.umutcansu.pinvault.model.EnrollmentRefusal.ATTESTATION_FAILED]).
     *
     * Default: drops the token and calls the seven-argument [enrollWithCsr].
     * An implementation compiled against an earlier PinVault does not have
     * this method; PinVault then calls the seven-argument one itself.
     */
    suspend fun enrollWithCsr(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csrDer: ByteArray,
        requestId: String?,
        attestationChain: List<String>,
        integrityToken: String?
    ): EnrollmentResult? = enrollWithCsr(token, deviceId, deviceAlias, deviceUid, csrDer, requestId, attestationChain)

    /**
     * Renews the client certificate of a CSR-enrolled device.
     *
     * With [recoveryUrl] null the request goes over the block's own
     * connection, which presents the current (still valid) client
     * certificate. With [recoveryUrl] set the certificate has expired or was
     * refused: the request goes to that URL, presents no client certificate,
     * and the backend authenticates the CSR signature against the key it
     * registered for [clientId] at enrollment.
     *
     * Default: [io.github.umutcansu.pinvault.model.ClientCertRenewalResponse.Unsupported].
     */
    suspend fun renewClientCert(
        clientId: String,
        csrDer: ByteArray,
        recoveryUrl: String? = null
    ): io.github.umutcansu.pinvault.model.ClientCertRenewalResponse =
        io.github.umutcansu.pinvault.model.ClientCertRenewalResponse.Unsupported

    /**
     * Reports a vault file download to the server for analytics/tracking.
     * Fire-and-forget — failures are logged but don't affect vault file operations.
     *
     * @param report Download report with device and file metadata.
     */
    suspend fun reportVaultDownload(report: VaultDownloadReport) {
        // Default: no-op. Override to enable server-side tracking.
    }
}
