package io.github.umutcansu.pinvault.model

/**
 * Supplies an integrity verdict for an enrollment request, made by a
 * service the server can check: Google Play Integrity, or the attestation
 * of a RASP / app-shielding product.
 *
 * An Android key attestation (which every enrollment carries) proves where
 * the key was made: in this device's hardware, by this app. It does not say
 * whether the device is rooted or the app hooked right now. A Play Integrity
 * token says that, and the device cannot forge it: Google signs the verdict
 * and the server decodes it. That is why the server decides, not the app.
 *
 * PinVault calls [token] once per enrollment request, on a background
 * thread, so it may block (`Tasks.await(...)` on the Play Integrity task).
 * The [requestHash] binds the token to this request: pass it as the
 * Play Integrity `requestHash` (standard request) or `nonce` (classic
 * request). It is 43 characters of unpadded Base64url:
 *
 * ```
 * requestHash = base64url(SHA-256("pinvault-integrity:v1:" + deviceId + ":" + base64url(SHA-256(csrDer))))
 * ```
 *
 * where `deviceId` is the request's `deviceUid`, or its `deviceId` when it
 * carries no `deviceUid` (empty when it carries neither). A server that
 * verifies the token recomputes it from the request, so a token captured for
 * one request cannot be replayed with another CSR or another device id.
 *
 * Return `null` when no token can be had (no Play services, a quota error):
 * the request goes without one, and a server that requires it refuses
 * ([EnrollmentRefusal.ATTESTATION_FAILED], server error `integrity_required`)
 * without spending the token. An exception is treated the same way and logged.
 *
 * ```kotlin
 * val standard: StandardIntegrityTokenProvider = …   // prepared once at app start
 *
 * PinVaultConfig.Builder()
 *     .integrityTokenProvider { requestHash ->
 *         Tasks.await(
 *             standard.request(
 *                 StandardIntegrityTokenRequest.builder().setRequestHash(requestHash).build()
 *             ),
 *             10, TimeUnit.SECONDS
 *         ).token()
 *     }
 * ```
 */
fun interface IntegrityTokenProvider {
    /** An integrity token bound to [requestHash], or null when none can be had. */
    fun token(requestHash: String): String?
}
