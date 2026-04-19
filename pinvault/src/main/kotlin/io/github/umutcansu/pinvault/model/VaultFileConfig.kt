package io.github.umutcansu.pinvault.model

import io.github.umutcansu.pinvault.store.VaultStorageProvider

/**
 * Configuration for a single vault file managed by PinVault.
 *
 * V2 additions:
 *  - [configApiId] binds the file to a specific [ConfigApiBlock]. When a
 *    PinVaultConfig has multiple Config APIs, this decides which one's
 *    pin-verified client handles the fetch. Default value
 *    [ConfigApiBlock.DEFAULT_ID] preserves single-API behavior.
 *  - [accessPolicy] mirrors the server's policy model. The library sends
 *    matching headers automatically (X-Device-Id, X-Vault-Token).
 *  - [accessTokenProvider] — called lazily on each fetch. Lets the host app
 *    refresh tokens from enrollment response without rebuilding config.
 *  - [encryption] drives local decryption: "end_to_end" routes the response
 *    body through VaultFileDecryptor before it hits storage.
 *
 * ```kotlin
 * .vaultFile("ml-model") {
 *     configApi("secure-mtls")
 *     endpoint("api/v1/vault/ml-model")
 *     storage(StorageStrategy.ENCRYPTED_FILE)
 *     accessPolicy(VaultFileAccessPolicy.TOKEN)
 *     accessToken { enrollmentResponse.tokens["ml-model"] ?: "" }
 *     encryption(VaultFileEncryption.END_TO_END)
 * }
 * ```
 */
data class VaultFileConfig(
    val key: String,
    val endpoint: String,
    val signaturePublicKey: String? = null,
    val updateWithPins: Boolean = false,
    val storageStrategy: StorageStrategy = StorageStrategy.ENCRYPTED_PREFS,
    val storageProvider: VaultStorageProvider? = null,
    /** V2: which [ConfigApiBlock] handles this file. */
    val configApiId: String = ConfigApiBlock.DEFAULT_ID,
    /** V2: server-side access policy the library must satisfy on fetch. */
    val accessPolicy: VaultFileAccessPolicy = VaultFileAccessPolicy.PUBLIC,
    /**
     * V2: token provider. Lazy so host apps can refresh tokens out-of-band
     * (e.g. from enrollment response) without rebuilding PinVaultConfig.
     *
     * Required when [accessPolicy] is [VaultFileAccessPolicy.TOKEN] or
     * [VaultFileAccessPolicy.TOKEN_MTLS]. Library throws on fetch if null.
     */
    val accessTokenProvider: (() -> String)? = null,
    /** V2: local decryption strategy. */
    val encryption: VaultFileEncryption = VaultFileEncryption.PLAIN
) {
    class Builder(private val key: String) {
        private var endpoint = ""
        private var signaturePublicKey: String? = null
        private var updateWithPins = false
        private var storageStrategy = StorageStrategy.ENCRYPTED_PREFS
        private var storageProvider: VaultStorageProvider? = null
        private var configApiId: String = ConfigApiBlock.DEFAULT_ID
        private var accessPolicy: VaultFileAccessPolicy = VaultFileAccessPolicy.PUBLIC
        private var accessTokenProvider: (() -> String)? = null
        private var encryption: VaultFileEncryption = VaultFileEncryption.PLAIN

        fun endpoint(ep: String) = apply { this.endpoint = ep }
        fun signaturePublicKey(key: String) = apply { this.signaturePublicKey = key }
        fun updateWithPins(v: Boolean) = apply { this.updateWithPins = v }
        fun storage(strategy: StorageStrategy) = apply { this.storageStrategy = strategy }
        fun storage(provider: VaultStorageProvider) = apply { this.storageProvider = provider }

        /** V2: bind this file to a specific Config API by id. */
        fun configApi(id: String) = apply { this.configApiId = id }

        /** V2: set per-file access policy. Default PUBLIC is demo-only. */
        fun accessPolicy(policy: VaultFileAccessPolicy) = apply { this.accessPolicy = policy }

        /**
         * V2: set a lazy token provider. Called on every fetch, so the host
         * app can return freshly refreshed tokens without rebuilding config.
         */
        fun accessToken(provider: () -> String) = apply { this.accessTokenProvider = provider }

        /** V2: set local decryption strategy. */
        fun encryption(e: VaultFileEncryption) = apply { this.encryption = e }

        fun build(): VaultFileConfig {
            require(endpoint.isNotBlank()) { "endpoint must not be blank for vault file: $key" }
            if (accessPolicy == VaultFileAccessPolicy.TOKEN ||
                accessPolicy == VaultFileAccessPolicy.TOKEN_MTLS) {
                require(accessTokenProvider != null) {
                    "accessToken { … } required when accessPolicy is TOKEN or TOKEN_MTLS (key: $key)"
                }
            }
            return VaultFileConfig(
                key = key,
                endpoint = endpoint.trimStart('/'),
                signaturePublicKey = signaturePublicKey,
                updateWithPins = updateWithPins,
                storageStrategy = storageStrategy,
                storageProvider = storageProvider,
                configApiId = configApiId,
                accessPolicy = accessPolicy,
                accessTokenProvider = accessTokenProvider,
                encryption = encryption
            )
        }
    }
}

/**
 * Built-in storage strategies for vault files.
 *
 * - [ENCRYPTED_PREFS]: Default. Uses EncryptedSharedPreferences. Best for small/medium files (<1MB).
 * - [ENCRYPTED_FILE]: Uses AES-256-GCM encrypted files on disk. Best for large files (ML models, etc.).
 *
 * Both strategies use Android Keystore for hardware-backed key management.
 */
enum class StorageStrategy {
    /** EncryptedSharedPreferences (default). Small/medium files. */
    ENCRYPTED_PREFS,
    /** AES-256-GCM encrypted file on disk. Large files. */
    ENCRYPTED_FILE
}

/**
 * V2: access policy the server enforces on a vault file. The library mirrors
 * these on the client side (sends the required headers). Values correspond
 * 1:1 with server `vault_files.access_policy`.
 */
enum class VaultFileAccessPolicy {
    /** No auth. Demo/test only; production should not use this. */
    PUBLIC,
    /** Requires X-API-Key (admin tooling, not device-facing). */
    API_KEY,
    /**
     * Per-device, per-file token. Library sends X-Device-Id + X-Vault-Token.
     * The token is bound to this exact (deviceId, vaultKey); cannot be
     * reused on another device or for another file.
     */
    TOKEN,
    /** TOKEN + mTLS cert where cert CN must match X-Device-Id. */
    TOKEN_MTLS
}

/**
 * V2: local decryption strategy for vault file content.
 *
 * - [PLAIN]: Server returns the content verbatim. Library stores as-is (or
 *   wraps in [StorageStrategy] encryption if configured).
 * - [AT_REST]: Same wire format as PLAIN; semantic marker only (server
 *   encrypts before storage but decrypts before sending).
 * - [END_TO_END]: Server wraps content with the device's registered RSA
 *   public key. Library decrypts via VaultFileDecryptor using the Android
 *   Keystore private key.
 */
enum class VaultFileEncryption {
    PLAIN,
    AT_REST,
    END_TO_END
}
