package io.github.umutcansu.pinvault.model

/**
 * Configuration for [io.github.umutcansu.pinvault.PinVault].
 *
 * ## Quick start (standard backend)
 * ```kotlin
 * val config = PinVaultConfig.Builder("https://api.example.com/")
 *     .bootstrapPins(listOf(
 *         HostPin("api.example.com", listOf("sha256/AAAA...", "sha256/BBBB..."))
 *     ))
 *     .build()
 *
 * PinVault.init(context, config)
 * ```
 *
 * ## Custom endpoints
 * ```kotlin
 * val config = PinVaultConfig.Builder("https://api.example.com/")
 *     .bootstrapPins(listOf(HostPin(...)))
 *     .configEndpoint("ssl/pins")       // default: "api/v1/certificate-config"
 *     .healthEndpoint("ping")           // default: "health"
 *     .maxRetryCount(5)                 // default: 3
 *     .updateIntervalHours(6)           // default: 12
 *     .build()
 * ```
 *
 * ## Fully custom backend
 * If your backend uses a completely different JSON format, skip this config
 * and pass a custom [io.github.umutcansu.pinvault.api.CertificateConfigApi] to
 * `PinVault.init()` instead.
 */
data class PinVaultConfig(
    /** Base URL for the certificate config backend (must end with /). */
    val configUrl: String,
    /** Bootstrap pins compiled into the APK for the initial config fetch. */
    val bootstrapPins: List<HostPin>,
    /** Relative path for the certificate config endpoint. */
    val configEndpoint: String = DEFAULT_CONFIG_ENDPOINT,
    /** Relative path for the health check endpoint. */
    val healthEndpoint: String = DEFAULT_HEALTH_ENDPOINT,
    /** Max retry attempts when backend is unreachable during init. */
    val maxRetryCount: Int = DEFAULT_MAX_RETRY,
    /** Interval for background periodic pin updates (hours). Ignored if [updateIntervalMinutes] is set. */
    val updateIntervalHours: Long = DEFAULT_UPDATE_INTERVAL_HOURS,
    /** Interval for background periodic pin updates (minutes). Takes precedence over [updateIntervalHours]. */
    val updateIntervalMinutes: Long? = null,
    /**
     * ECDSA P-256 public key (Base64, X.509 encoded) for config signature verification.
     * If set, every config response must include a valid signature — unsigned or
     * tampered configs are rejected and the library keeps the previous safe config.
     * If null, signature verification is skipped (backward compatible).
     */
    val signaturePublicKey: String? = null,
    /** PKCS12 client keystore bytes for mTLS. If set, client cert is sent during TLS handshake. */
    val clientKeystoreBytes: ByteArray? = null,
    /** Password for the client keystore. */
    val clientKeyPassword: String = "changeit",
    /** One-time enrollment token for automatic P12 download. */
    val enrollmentToken: String? = null,
    /** Enrollment endpoint path. */
    val enrollmentEndpoint: String = DEFAULT_ENROLLMENT_ENDPOINT,
    /**
     * Label for the client certificate in encrypted storage.
     * Different labels allow multiple client certificates on the same device.
     * Example: "config" for config API cert, "host" for host cert.
     */
    val clientCertLabel: String = DEFAULT_CERT_LABEL
) {

    class Builder(private val configUrl: String) {
        private var bootstrapPins: List<HostPin> = emptyList()
        private var configEndpoint: String = DEFAULT_CONFIG_ENDPOINT
        private var healthEndpoint: String = DEFAULT_HEALTH_ENDPOINT
        private var maxRetryCount: Int = DEFAULT_MAX_RETRY
        private var updateIntervalHours: Long = DEFAULT_UPDATE_INTERVAL_HOURS
        private var updateIntervalMinutes: Long? = null
        private var signaturePublicKey: String? = null
        private var clientKeystoreBytes: ByteArray? = null
        private var clientKeyPassword: String = "changeit"
        private var enrollmentToken: String? = null
        private var clientCertLabel: String = DEFAULT_CERT_LABEL

        fun bootstrapPins(pins: List<HostPin>) = apply { this.bootstrapPins = pins }
        fun configEndpoint(endpoint: String) = apply { this.configEndpoint = endpoint }
        fun healthEndpoint(endpoint: String) = apply { this.healthEndpoint = endpoint }
        fun maxRetryCount(count: Int) = apply { this.maxRetryCount = count }
        fun updateIntervalHours(hours: Long) = apply { this.updateIntervalHours = hours }
        fun updateIntervalMinutes(minutes: Long) = apply { this.updateIntervalMinutes = minutes }
        fun signaturePublicKey(key: String) = apply { this.signaturePublicKey = key }
        fun clientKeystore(bytes: ByteArray, password: String = "changeit") = apply {
            this.clientKeystoreBytes = bytes
            this.clientKeyPassword = password
        }
        fun enrollmentToken(token: String) = apply { this.enrollmentToken = token }
        fun clientCertLabel(label: String) = apply { this.clientCertLabel = label }

        fun build(): PinVaultConfig {
            require(configUrl.isNotBlank()) { "configUrl must not be blank" }
            require(bootstrapPins.isNotEmpty()) { "bootstrapPins must not be empty" }

            val normalizedUrl = if (configUrl.endsWith("/")) configUrl else "$configUrl/"
            return PinVaultConfig(
                configUrl = normalizedUrl,
                bootstrapPins = bootstrapPins,
                configEndpoint = configEndpoint.trimStart('/'),
                healthEndpoint = healthEndpoint.trimStart('/'),
                maxRetryCount = maxRetryCount,
                updateIntervalHours = updateIntervalHours,
                updateIntervalMinutes = updateIntervalMinutes,
                signaturePublicKey = signaturePublicKey,
                clientKeystoreBytes = clientKeystoreBytes,
                clientKeyPassword = clientKeyPassword,
                enrollmentToken = enrollmentToken,
                clientCertLabel = clientCertLabel
            )
        }
    }

    companion object {
        const val DEFAULT_CONFIG_ENDPOINT = "api/v1/certificate-config"
        const val DEFAULT_HEALTH_ENDPOINT = "health"
        const val DEFAULT_MAX_RETRY = 3
        const val DEFAULT_UPDATE_INTERVAL_HOURS = 12L
        const val DEFAULT_ENROLLMENT_ENDPOINT = "api/v1/client-certs/enroll"
        const val DEFAULT_CERT_LABEL = "default"
    }
}
