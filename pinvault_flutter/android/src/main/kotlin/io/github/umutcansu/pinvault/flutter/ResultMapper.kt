package io.github.umutcansu.pinvault.flutter

import io.github.umutcansu.pinvault.api.PinVaultConnectionEvent
import io.github.umutcansu.pinvault.model.AttestationStatus
import io.github.umutcansu.pinvault.model.AttestationTokenResult
import io.github.umutcansu.pinvault.model.ClientCertEnrollmentResult
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.SigningStatus
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.model.VaultFileResult
import io.github.umutcansu.pinvault.model.VaultFileUnlockResult
import okio.ByteString.Companion.toByteString

/**
 * Native results → plain maps for Dart. `type` is the sealed subclass in
 * lowerCamel (`Ready` → `ready`), every other key is the Kotlin property name.
 * Every free-text field goes through [VaultTokenStore.redact]; vault file
 * content appears only in `unlocked` (after the native prompt) and in
 * `loadFile`, never in a download result or an event.
 */
internal class ResultMapper(private val tokens: VaultTokenStore) {

    private fun text(s: String?): String? = tokens.redact(s)

    fun exception(e: Throwable?): Map<String, Any?>? = e?.let {
        mapOf("name" to it.javaClass.simpleName.ifEmpty { "Exception" }, "message" to text(it.message))
    }

    fun init(r: InitResult): Map<String, Any?> = when (r) {
        is InitResult.Ready -> mapOf("type" to "ready", "version" to r.version)
        is InitResult.Failed -> mapOf("type" to "failed", "reason" to text(r.reason), "exception" to exception(r.exception))
    }

    fun update(r: UpdateResult): Map<String, Any?> = when (r) {
        is UpdateResult.Updated -> mapOf("type" to "updated", "newVersion" to r.newVersion)
        UpdateResult.AlreadyCurrent -> mapOf("type" to "alreadyCurrent")
        is UpdateResult.Failed -> mapOf("type" to "failed", "reason" to text(r.reason), "exception" to exception(r.exception))
    }

    fun enrollment(r: ClientCertEnrollmentResult): Map<String, Any?> = when (r) {
        is ClientCertEnrollmentResult.Enrolled -> mapOf(
            "type" to "enrolled",
            "alreadyEnrolled" to r.alreadyEnrolled,
            "keySecurityLevel" to r.keySecurityLevel?.name,
        )
        is ClientCertEnrollmentResult.Refused -> mapOf(
            "type" to "refused",
            "reason" to r.reason.name,
            "httpStatus" to r.httpStatus,
            "serverError" to text(r.serverError),
            "message" to text(r.message),
        )
        is ClientCertEnrollmentResult.Pending -> mapOf(
            "type" to "pending",
            "requestId" to r.requestId,
            "clientId" to r.clientId,
            "message" to text(r.message),
            "retryAfterSeconds" to r.retryAfterSeconds,
            "verificationCode" to r.verificationCode,
        )
        is ClientCertEnrollmentResult.Failed -> mapOf(
            "type" to "failed",
            "message" to text(r.message),
            "cause" to exception(r.cause),
        )
    }

    fun vaultFile(r: VaultFileResult): Map<String, Any?> = when (r) {
        // No bytes: the content is read with loadFile / unlockFile, on purpose.
        is VaultFileResult.Updated -> mapOf("type" to "updated", "key" to r.key, "version" to r.version)
        is VaultFileResult.AlreadyCurrent -> mapOf("type" to "alreadyCurrent", "key" to r.key, "version" to r.version)
        is VaultFileResult.Failed -> mapOf(
            "type" to "failed",
            "key" to r.key,
            "reason" to text(r.reason),
            "code" to r.code,
            "exception" to exception(r.exception),
        )
    }

    fun unlock(r: VaultFileUnlockResult, encoding: String): Map<String, Any?> = when (r) {
        is VaultFileUnlockResult.Unlocked -> mapOf(
            "type" to "unlocked",
            "key" to r.key,
            "version" to r.version,
            "content" to encode(r.bytes, encoding),
            "encoding" to encoding,
        )
        is VaultFileUnlockResult.NotFound -> mapOf("type" to "notFound", "key" to r.key)
        is VaultFileUnlockResult.Cancelled -> mapOf("type" to "cancelled", "key" to r.key)
        is VaultFileUnlockResult.Invalidated -> mapOf("type" to "invalidated", "key" to r.key)
        is VaultFileUnlockResult.Stale -> mapOf("type" to "stale", "key" to r.key)
        is VaultFileUnlockResult.Failed -> mapOf(
            "type" to "failed",
            "key" to r.key,
            "reason" to text(r.reason),
            "exception" to exception(r.exception),
        )
    }

    fun attestation(s: AttestationStatus): Map<String, Any?> = mapOf(
        "configApiId" to s.configApiId,
        "result" to s.result.name,
        "arc" to s.arc,
        "rejectionReasons" to s.rejectionReasons,
        "warnings" to s.warnings,
        "tokenExpiresAt" to s.tokenExpiresAt,
        "lastAttestedAt" to s.lastAttestedAt,
        "nextAttestAt" to s.nextAttestAt,
        "clockSkewMs" to s.clockSkewMs,
        "lastError" to text(s.lastError),
        "policyVersion" to s.policyVersion,
    )

    fun attestationToken(r: AttestationTokenResult): Map<String, Any?> = when (r) {
        is AttestationTokenResult.Token -> mapOf("type" to "token", "value" to r.value, "expiresAt" to r.expiresAt)
        is AttestationTokenResult.Rejected -> mapOf("type" to "rejected", "status" to attestation(r.status))
        is AttestationTokenResult.Failed -> mapOf("type" to "failed", "message" to text(r.message))
        AttestationTokenResult.Unsupported -> mapOf("type" to "unsupported")
    }

    fun signing(s: SigningStatus): Map<String, Any?> = mapOf(
        "configApiId" to s.configApiId,
        "trustedKeyIds" to s.trustedKeyIds,
        "requiredSignatures" to s.requiredSignatures,
        "keySetVersion" to s.keySetVersion,
        "recoveryKeyIds" to s.recoveryKeyIds,
        "lastConfigSignedBy" to s.lastConfigSignedBy,
    )

    /** Connection telemetry. The library puts no token in events; free text is redacted anyway. */
    fun event(e: PinVaultConnectionEvent): Map<String, Any?> = when (e) {
        is PinVaultConnectionEvent.Connection -> mapOf(
            "type" to "connection",
            "hostname" to e.hostname,
            "success" to e.success,
            "pinVersion" to e.pinVersion,
            "deviceManufacturer" to e.deviceManufacturer,
            "deviceModel" to e.deviceModel,
            "actualPin" to e.actualPin,
            "expectedPins" to e.expectedPins,
        )
        is PinVaultConnectionEvent.ConfigUpdate -> mapOf(
            "type" to "configUpdate",
            "status" to e.status.name,
            "newVersion" to e.newVersion,
            "deviceManufacturer" to e.deviceManufacturer,
            "deviceModel" to e.deviceModel,
            "failureReason" to text(e.failureReason),
        )
        is PinVaultConnectionEvent.ClientCertRenewal -> mapOf(
            "type" to "clientCertRenewal",
            "status" to e.status.name,
            "notAfterEpochMs" to e.notAfterEpochMs,
            "via" to e.via?.name,
            "configApiId" to e.configApiId,
            "deviceManufacturer" to e.deviceManufacturer,
            "deviceModel" to e.deviceModel,
            "failureReason" to text(e.failureReason),
        )
        is PinVaultConnectionEvent.Attestation -> mapOf(
            "type" to "attestation",
            "configApiId" to e.configApiId,
            "status" to e.status.name,
            "arc" to e.arc,
            "rejectionReasons" to e.rejectionReasons,
            "warnings" to e.warnings,
            "tokenExpiresAt" to e.tokenExpiresAt,
            "deviceManufacturer" to e.deviceManufacturer,
            "deviceModel" to e.deviceModel,
            "failureReason" to text(e.failureReason),
        )
    }

    companion object {
        const val UTF8 = "utf8"
        const val BASE64 = "base64"

        fun checkEncoding(encoding: String): String {
            if (encoding != UTF8 && encoding != BASE64) throw BridgeInputException("encoding: must be 'utf8' or 'base64'")
            return encoding
        }

        fun encode(bytes: ByteArray, encoding: String): String =
            // Okio, not android.util.Base64: it also runs in JVM unit tests (and java.util.Base64 needs API 26).
            if (encoding == BASE64) bytes.toByteString().base64() else bytes.toString(Charsets.UTF_8)
    }
}
