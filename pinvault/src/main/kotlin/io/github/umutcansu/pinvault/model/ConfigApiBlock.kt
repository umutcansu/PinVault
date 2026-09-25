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
 *
 * ## Removed in V2: `enrollmentToken(token)`
 * The builder used to accept a one-time enrollment token and store it on the
 * block. Nothing ever read it — neither
 * [io.github.umutcansu.pinvault.PinVault.enroll] nor
 * [io.github.umutcansu.pinvault.PinVault.autoEnroll] consulted the block — so
 * a token set here silently did nothing while looking like enrollment was
 * configured. Holding a single-use secret in a long-lived config object was
 * the wrong lifetime for it too.
 *
 * Pass the token at the call site instead:
 * ```kotlin
 * PinVault.enroll(context, token)   // token-based enrollment
 * PinVault.autoEnroll(context)      // deviceId-based enrollment
 * ```
 */
data class ConfigApiBlock @JvmOverloads constructor(
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
    /**
     * ECDSA P-256 signing key (Base64). Null = unsigned config accepted.
     * With several keys this is the first of [signaturePublicKeys].
     */
    val signaturePublicKey: String? = null,
    /** PKCS12 client keystore bytes for mTLS. */
    val clientKeystoreBytes: ByteArray? = null,
    /** Keystore password. Default "changeit" is placeholder only. */
    val clientKeyPassword: String = "changeit",
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
    val wantPinsFor: List<String> = emptyList(),
    /**
     * Every key a config signature may come from (Base64 X.509, ECDSA P-256).
     * Empty = just [signaturePublicKey]. See [Builder.signaturePublicKeys].
     */
    val signaturePublicKeys: List<String> = emptyList(),
    /** Distinct trusted keys that must sign each config. See [Builder.requiredSignatures]. */
    val requiredSignatures: Int = 1,
    /**
     * Offline keys that may authorise a new signing-key set (rotation and
     * revocation over the air). Empty = disabled. See [Builder.recoveryPublicKeys].
     */
    val recoveryPublicKeys: List<String> = emptyList(),
    /** Distinct recovery keys that must sign a key set. See [Builder.requiredRecoverySignatures]. */
    val requiredRecoverySignatures: Int = 1
) {

    /**
     * The keys config signatures are checked against when no signing-key set
     * has been applied: [signaturePublicKeys], or [signaturePublicKey] alone
     * for blocks built through the primary constructor.
     */
    internal fun effectiveSignatureKeys(): List<String> =
        signaturePublicKeys.ifEmpty { listOfNotNull(signaturePublicKey) }

    class Builder(private val id: String, private val configUrl: String) {
        private var bootstrapPins: List<HostPin> = emptyList()
        private var configEndpoint: String = PinVaultConfig.DEFAULT_CONFIG_ENDPOINT
        private var healthEndpoint: String = PinVaultConfig.DEFAULT_HEALTH_ENDPOINT
        private var signaturePublicKeys: List<String> = emptyList()
        private var requiredSignatures: Int = 1
        private var recoveryPublicKeys: List<String> = emptyList()
        private var requiredRecoverySignatures: Int = 1
        private var allowUnsigned: Boolean = false
        private var clientKeystoreBytes: ByteArray? = null
        private var clientKeyPassword: String = "changeit"
        private var enrollmentEndpoint: String = PinVaultConfig.DEFAULT_ENROLLMENT_ENDPOINT
        private var clientCertEndpoint: String = PinVaultConfig.DEFAULT_CLIENT_CERT_ENDPOINT
        private var vaultReportEndpoint: String = PinVaultConfig.DEFAULT_VAULT_REPORT_ENDPOINT
        private var clientCertLabel: String = PinVaultConfig.DEFAULT_CERT_LABEL
        private var wantPinsFor: List<String> = emptyList()

        fun bootstrapPins(pins: List<HostPin>) = apply { this.bootstrapPins = pins }
        fun configEndpoint(endpoint: String) = apply { this.configEndpoint = endpoint }
        fun healthEndpoint(endpoint: String) = apply { this.healthEndpoint = endpoint }
        /** The config-signing public key: X.509 SubjectPublicKeyInfo, Base64, ECDSA P-256. */
        fun signaturePublicKey(key: String) = apply {
            this.signaturePublicKeys = listOf(normalizeKeyText(key)).filter { it.isNotEmpty() }
        }

        /**
         * Several config-signing keys, any of which may sign (unless
         * [requiredSignatures] asks for more than one). Replaces an earlier
         * [signaturePublicKey] call.
         *
         * Typical use: the backend's key plus a backup whose private half is
         * kept offline. If the primary is lost or stolen, the backend starts
         * signing with the backup and every installed app keeps accepting
         * configs — no app update. A stolen primary stays trusted, though,
         * until the app is updated or [recoveryPublicKeys] revokes it.
         */
        fun signaturePublicKeys(vararg keys: String) = apply {
            this.signaturePublicKeys = keys.map(::normalizeKeyText).filter { it.isNotEmpty() }.distinct()
        }

        /** [signaturePublicKeys] for a list (Java-friendly). */
        fun signaturePublicKeys(keys: List<String>) = signaturePublicKeys(*keys.toTypedArray())

        /**
         * How many DISTINCT keys from [signaturePublicKeys] must sign every
         * config (and every vault file of this block). Default 1.
         *
         * With 2 or more, and the keys held by different people or systems,
         * nobody — not a single administrator, not the config server itself —
         * can publish pins alone. The backend then sends all signatures in the
         * envelope's `signatures` field.
         */
        fun requiredSignatures(count: Int) = apply { this.requiredSignatures = count }

        /**
         * Offline recovery keys that may authorise a new set of signing keys.
         * Enables signing-key rotation and revocation without an app update:
         * the backend delivers a key set signed by these keys, and the device
         * from then on trusts exactly the signing keys that set lists.
         *
         * Recovery keys are only ever used for that — never to sign configs —
         * and must not also appear in [signaturePublicKeys]. Keep their private
         * halves offline and apart from the signing keys.
         */
        fun recoveryPublicKeys(vararg keys: String) = apply {
            this.recoveryPublicKeys = keys.map(::normalizeKeyText).filter { it.isNotEmpty() }.distinct()
        }

        /** [recoveryPublicKeys] for a list (Java-friendly). */
        fun recoveryPublicKeys(keys: List<String>) = recoveryPublicKeys(*keys.toTypedArray())

        /** How many distinct [recoveryPublicKeys] must sign a key set. Default 1. */
        fun requiredRecoverySignatures(count: Int) = apply { this.requiredRecoverySignatures = count }

        /**
         * Explicit opt-out from signed-config enforcement. Without this call,
         * [build] requires [signaturePublicKey] to be set — protects against
         * the common footgun of forgetting it in production, which would
         * disable signature *and* replay/freshness protection.
         *
         * SECURITY (audit L-8): unsigned mode does more than skip the
         * signature. It also disables ALL of the freshness machinery —
         * `issuedAt` / `expiresAt` stay `0`, so there is NO replay protection,
         * NO config-expiry window, and NO `issuedAt`-based downgrade rejection.
         * A MITM in front of an unsigned config endpoint can therefore serve
         * arbitrary or rolled-back pins. Use ONLY in tests, throwaway demos, or
         * transitional setups where the backend has no ECDSA signing key yet,
         * and document the risk wherever it is called.
         */
        fun allowUnsigned() = apply { this.allowUnsigned = true }

        /** mTLS client keystore. Default password "changeit" is placeholder only. */
        fun clientKeystore(bytes: ByteArray, password: String = "changeit") = apply {
            this.clientKeystoreBytes = bytes
            this.clientKeyPassword = password
        }
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
            require(signaturePublicKeys.isNotEmpty() || allowUnsigned) {
                "ConfigApi '$id': signaturePublicKey is required. Pass the ECDSA P-256 " +
                "public key (X.509-encoded, Base64) via signaturePublicKey(...) — this " +
                "is what guards against config tampering and replay attacks. If you are " +
                "intentionally running without signed configs (tests, demos, transitional " +
                "setup), call allowUnsigned() to opt out explicitly."
            }
            if (signaturePublicKeys.isNotEmpty()) {
                require(requiredSignatures in 1..signaturePublicKeys.size) {
                    "ConfigApi '$id': requiredSignatures($requiredSignatures) must be between 1 and " +
                    "the number of signing keys (${signaturePublicKeys.size})."
                }
            }
            if (recoveryPublicKeys.isNotEmpty()) {
                require(signaturePublicKeys.isNotEmpty()) {
                    "ConfigApi '$id': recoveryPublicKeys(...) rotates signing keys, so it needs " +
                    "signaturePublicKey(...) / signaturePublicKeys(...) as the starting set."
                }
                require(recoveryPublicKeys.none { it in signaturePublicKeys }) {
                    "ConfigApi '$id': a recovery key must not also be a signing key — keep the two " +
                    "roles on separate keys."
                }
                require(requiredRecoverySignatures in 1..recoveryPublicKeys.size) {
                    "ConfigApi '$id': requiredRecoverySignatures($requiredRecoverySignatures) must be " +
                    "between 1 and the number of recovery keys (${recoveryPublicKeys.size})."
                }
            }
            val normalizedUrl = if (configUrl.endsWith("/")) configUrl else "$configUrl/"
            return ConfigApiBlock(
                id = id,
                configUrl = normalizedUrl,
                bootstrapPins = bootstrapPins,
                configEndpoint = configEndpoint.trimStart('/'),
                healthEndpoint = healthEndpoint.trimStart('/'),
                // The first key keeps the single-key field meaningful for code
                // written before multi-key support.
                signaturePublicKey = signaturePublicKeys.firstOrNull(),
                clientKeystoreBytes = clientKeystoreBytes,
                clientKeyPassword = clientKeyPassword,
                enrollmentEndpoint = enrollmentEndpoint,
                clientCertEndpoint = clientCertEndpoint.trimStart('/'),
                vaultReportEndpoint = vaultReportEndpoint.trimStart('/'),
                clientCertLabel = clientCertLabel,
                wantPinsFor = wantPinsFor,
                signaturePublicKeys = signaturePublicKeys,
                requiredSignatures = requiredSignatures,
                recoveryPublicKeys = recoveryPublicKeys,
                requiredRecoverySignatures = requiredRecoverySignatures
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
                enrollmentEndpoint == other.enrollmentEndpoint &&
                clientCertEndpoint == other.clientCertEndpoint &&
                vaultReportEndpoint == other.vaultReportEndpoint &&
                clientCertLabel == other.clientCertLabel &&
                wantPinsFor == other.wantPinsFor &&
                signaturePublicKeys == other.signaturePublicKeys &&
                requiredSignatures == other.requiredSignatures &&
                recoveryPublicKeys == other.recoveryPublicKeys &&
                requiredRecoverySignatures == other.requiredRecoverySignatures
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
        r = 31 * r + enrollmentEndpoint.hashCode()
        r = 31 * r + clientCertEndpoint.hashCode()
        r = 31 * r + vaultReportEndpoint.hashCode()
        r = 31 * r + clientCertLabel.hashCode()
        r = 31 * r + wantPinsFor.hashCode()
        r = 31 * r + signaturePublicKeys.hashCode()
        r = 31 * r + requiredSignatures
        r = 31 * r + recoveryPublicKeys.hashCode()
        r = 31 * r + requiredRecoverySignatures
        return r
    }

    companion object {
        const val DEFAULT_ID = "default"

        /**
         * Strips PEM armour and whitespace so a key pasted as a PEM block, or
         * with a trailing newline from a properties file, is one key and not
         * two. The runtime additionally parses every key and compares the
         * parsed form (see SignatureTrust), which this pure-text step cannot.
         */
        internal fun normalizeKeyText(key: String): String =
            key.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("-----") }
                .joinToString("")
                .filterNot { it.isWhitespace() }
    }
}
