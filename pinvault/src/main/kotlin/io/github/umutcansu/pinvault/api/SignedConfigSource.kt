package io.github.umutcansu.pinvault.api

import io.github.umutcansu.pinvault.model.SignedConfigResponse

/**
 * Implemented by a custom [CertificateConfigApi] whose backend serves signed
 * configs. PinVault then asks for the envelope instead of a parsed config and
 * verifies it exactly as it does for its own HTTP client: the signatures
 * against the block's signing keys (`signaturePublicKey(s)`,
 * `requiredSignatures`, signing-key sets), `issuedAt` / `expiresAt`, the
 * replay checks, and `serverScope` when the block sets one. The verified
 * envelope is stored and checked again every time the stored config is read.
 *
 * A Config API block that has signing keys needs this from a custom API:
 * `fetchConfig` hands over an already parsed config that nothing can verify,
 * and a block that looks signed must not run unverified. `PinVault.init`
 * fails for such a block unless it called `allowUnsigned()`.
 *
 * ```kotlin
 * class MyConfigApi : CertificateConfigApi, SignedConfigSource {
 *     override suspend fun fetchSignedConfig(currentVersion: Int): SignedConfigResponse {
 *         val body = myTransport.get("pins?current=$currentVersion")   // {"payload": "...", "signature": "..."}
 *         return SignedConfigResponse(payload = body.payload, signature = body.signature)
 *     }
 *     // fetchConfig is not called for a block with signing keys; the other
 *     // CertificateConfigApi methods as before
 * }
 * ```
 *
 * The payload is the config JSON as signed — `version`, `pins`,
 * `forceUpdate`, `issuedAt`, `expiresAt` (both required, Unix epoch ms) and,
 * for `serverScope`, `configApiId`. Pass it on byte for byte: the signature
 * covers its UTF-8 bytes.
 */
interface SignedConfigSource {

    /**
     * The signed envelope of the latest config.
     *
     * @param currentVersion the version the device holds (0 on first call).
     * @throws Exception on network or server errors.
     */
    suspend fun fetchSignedConfig(currentVersion: Int): SignedConfigResponse

    /**
     * Scoped variant, used when the block declared `wantPinsFor(...)`: the
     * backend returns the pins for the intersection of [hosts] and the
     * device's ACL. Default: [fetchSignedConfig].
     */
    suspend fun fetchScopedSignedConfig(
        currentVersion: Int,
        hosts: List<String>? = null,
        deviceId: String? = null
    ): SignedConfigResponse = fetchSignedConfig(currentVersion)
}
