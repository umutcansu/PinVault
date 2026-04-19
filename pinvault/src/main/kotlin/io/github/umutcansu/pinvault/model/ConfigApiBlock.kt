package io.github.umutcansu.pinvault.model

/**
 * A single Config API endpoint registered on a [PinVaultConfig]. Each block
 * has its own TLS/mTLS pipeline, bootstrap pins, and vault endpoints.
 *
 * V2 introduces multi-Config-API support: a [PinVaultConfig] may hold one or
 * more blocks, and each [VaultFileConfig] binds to a specific block via
 * [VaultFileConfig.configApiId]. At runtime the library routes fetches to
 * the correct block's pin-verified OkHttpClient.
 *
 * Example:
 * ```kotlin
 * PinVaultConfig.Builder()
 *     .configApi("prod-tls", "https://host:8091") {
 *         bootstrapPins(listOf(HostPin("host:8091", listOf("…"))))
 *         wantPinsFor("cdn.example.com", "api.example.com")
 *     }
 *     .configApi("secure-mtls", "https://host:8092") {
 *         bootstrapPins(listOf(HostPin("host:8092", listOf("…"))))
 *         clientKeystore(p12Bytes, "changeit")
 *         wantPinsFor("internal.acme.com")
 *     }
 *     .vaultFile("feature-flags") { configApi("prod-tls"); ... }
 *     .vaultFile("ml-model") { configApi("secure-mtls"); storage(ENCRYPTED_FILE) }
 *     .build()
 * ```
 */
data class ConfigApiBlock(
    /** Block identifier used by [VaultFileConfig.configApiId]. */
    val id: String,
    /** Base URL (trailing slash enforced on build). */
    val configUrl: String,
    /** Bootstrap pins compiled into the APK for initial connection. */
    val bootstrapPins: List<HostPin>,
    /** Relative path for certificate config endpoint. */
    val configEndpoint: String = PinVaultConfig.DEFAULT_CONFIG_ENDPOINT,
    /** Relative path for health check. */
    val healthEndpoint: String = PinVaultConfig.DEFAULT_HEALTH_ENDPOINT,
    /** ECDSA P-256 signing key (Base64). Null = unsigned config accepted. */
    val signaturePublicKey: String? = null,
    /** PKCS12 client keystore bytes for mTLS. */
    val clientKeystoreBytes: ByteArray? = null,
    /** Keystore password. Default "changeit" is placeholder only. */
    val clientKeyPassword: String = "changeit",
    /** One-time enrollment token for auto P12 download. */
    val enrollmentToken: String? = null,
    /** Enrollment endpoint path. */
    val enrollmentEndpoint: String = PinVaultConfig.DEFAULT_ENROLLMENT_ENDPOINT,
    /** Client cert download base path. */
    val clientCertEndpoint: String = PinVaultConfig.DEFAULT_CLIENT_CERT_ENDPOINT,
    /** Vault download report path. */
    val vaultReportEndpoint: String = PinVaultConfig.DEFAULT_VAULT_REPORT_ENDPOINT,
    /** Cert label for encrypted storage isolation. */
    val clientCertLabel: String = PinVaultConfig.DEFAULT_CERT_LABEL,
    /**
     * V2: pin scoping. When non-empty, the library sends `?hosts=…` to
     * [configEndpoint] so the server returns only pins for the intersection
     * of this list and the device's server-side ACL.
     *
     * Empty list = legacy behavior (trust server to return what it will).
     */
    val wantPinsFor: List<String> = emptyList()
) {

    class Builder(private val id: String, private val configUrl: String) {
        private var bootstrapPins: List<HostPin> = emptyList()
        private var configEndpoint: String = PinVaultConfig.DEFAULT_CONFIG_ENDPOINT
        private var healthEndpoint: String = PinVaultConfig.DEFAULT_HEALTH_ENDPOINT
        private var signaturePublicKey: String? = null
        private var clientKeystoreBytes: ByteArray? = null
        private var clientKeyPassword: String = "changeit"
        private var enrollmentToken: String? = null
        private var enrollmentEndpoint: String = PinVaultConfig.DEFAULT_ENROLLMENT_ENDPOINT
        private var clientCertEndpoint: String = PinVaultConfig.DEFAULT_CLIENT_CERT_ENDPOINT
        private var vaultReportEndpoint: String = PinVaultConfig.DEFAULT_VAULT_REPORT_ENDPOINT
        private var clientCertLabel: String = PinVaultConfig.DEFAULT_CERT_LABEL
        private var wantPinsFor: List<String> = emptyList()

        fun bootstrapPins(pins: List<HostPin>) = apply { this.bootstrapPins = pins }
        fun configEndpoint(endpoint: String) = apply { this.configEndpoint = endpoint }
        fun healthEndpoint(endpoint: String) = apply { this.healthEndpoint = endpoint }
        fun signaturePublicKey(key: String) = apply { this.signaturePublicKey = key }

        /** mTLS client keystore. Default password "changeit" is placeholder only. */
        fun clientKeystore(bytes: ByteArray, password: String = "changeit") = apply {
            this.clientKeystoreBytes = bytes
            this.clientKeyPassword = password
        }
        fun enrollmentToken(token: String) = apply { this.enrollmentToken = token }
        fun enrollmentEndpoint(endpoint: String) = apply { this.enrollmentEndpoint = endpoint }
        fun clientCertEndpoint(endpoint: String) = apply { this.clientCertEndpoint = endpoint }
        fun vaultReportEndpoint(endpoint: String) = apply { this.vaultReportEndpoint = endpoint }
        fun clientCertLabel(label: String) = apply { this.clientCertLabel = label }

        /**
         * V2: declare which hostnames this device wants pins for. Server
         * filters its response to the intersection of this set and the
         * device's ACL. Least-privilege: cihaz istediği pin'leri açıkça
         * söylesin, hepsine erişemesin.
         */
        fun wantPinsFor(vararg hosts: String) = apply { this.wantPinsFor = hosts.toList() }

        internal fun build(): ConfigApiBlock {
            require(id.isNotBlank()) { "ConfigApi id must not be blank" }
            require(configUrl.isNotBlank()) { "ConfigApi configUrl must not be blank" }
            val normalizedUrl = if (configUrl.endsWith("/")) configUrl else "$configUrl/"
            return ConfigApiBlock(
                id = id,
                configUrl = normalizedUrl,
                bootstrapPins = bootstrapPins,
                configEndpoint = configEndpoint.trimStart('/'),
                healthEndpoint = healthEndpoint.trimStart('/'),
                signaturePublicKey = signaturePublicKey,
                clientKeystoreBytes = clientKeystoreBytes,
                clientKeyPassword = clientKeyPassword,
                enrollmentToken = enrollmentToken,
                enrollmentEndpoint = enrollmentEndpoint,
                clientCertEndpoint = clientCertEndpoint.trimStart('/'),
                vaultReportEndpoint = vaultReportEndpoint.trimStart('/'),
                clientCertLabel = clientCertLabel,
                wantPinsFor = wantPinsFor
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ConfigApiBlock) return false
        return id == other.id && configUrl == other.configUrl &&
                bootstrapPins == other.bootstrapPins &&
                configEndpoint == other.configEndpoint &&
                healthEndpoint == other.healthEndpoint &&
                signaturePublicKey == other.signaturePublicKey &&
                (clientKeystoreBytes?.contentEquals(other.clientKeystoreBytes) ?: (other.clientKeystoreBytes == null)) &&
                clientKeyPassword == other.clientKeyPassword &&
                enrollmentToken == other.enrollmentToken &&
                enrollmentEndpoint == other.enrollmentEndpoint &&
                clientCertEndpoint == other.clientCertEndpoint &&
                vaultReportEndpoint == other.vaultReportEndpoint &&
                clientCertLabel == other.clientCertLabel &&
                wantPinsFor == other.wantPinsFor
    }

    override fun hashCode(): Int {
        var r = id.hashCode()
        r = 31 * r + configUrl.hashCode()
        r = 31 * r + bootstrapPins.hashCode()
        r = 31 * r + configEndpoint.hashCode()
        r = 31 * r + healthEndpoint.hashCode()
        r = 31 * r + (signaturePublicKey?.hashCode() ?: 0)
        r = 31 * r + (clientKeystoreBytes?.contentHashCode() ?: 0)
        r = 31 * r + clientKeyPassword.hashCode()
        r = 31 * r + (enrollmentToken?.hashCode() ?: 0)
        r = 31 * r + enrollmentEndpoint.hashCode()
        r = 31 * r + clientCertEndpoint.hashCode()
        r = 31 * r + vaultReportEndpoint.hashCode()
        r = 31 * r + clientCertLabel.hashCode()
        r = 31 * r + wantPinsFor.hashCode()
        return r
    }

    companion object {
        const val DEFAULT_ID = "default"
    }
}
