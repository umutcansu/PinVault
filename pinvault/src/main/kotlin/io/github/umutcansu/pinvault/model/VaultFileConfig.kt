package io.github.umutcansu.pinvault.model

import io.github.umutcansu.pinvault.store.VaultStorageProvider

/**
 * Configuration for a single vault file managed by PinVault.
 *
 * Register vault files via the DSL:
 * ```kotlin
 * PinVaultConfig.Builder("https://api.example.com/")
 *     .bootstrapPins(listOf(...))
 *     .vaultFile("ml-model") {
 *         endpoint("api/v1/vault/ml-model")
 *         storage(StorageStrategy.ENCRYPTED_FILE)
 *     }
 *     .vaultFile("feature-flags") {
 *         endpoint("api/v1/vault/flags")
 *         updateWithPins(true)
 *     }
 *     .build()
 * ```
 */
data class VaultFileConfig(
    /** Unique key identifying this file. */
    val key: String,
    /** Relative endpoint path to download the file from. */
    val endpoint: String,
    /** ECDSA P-256 public key for signature verification. Null = no verification. */
    val signaturePublicKey: String? = null,
    /** If true, file is synced automatically during periodic pin updates. */
    val updateWithPins: Boolean = false,
    /** Storage strategy. Determines how the file is stored locally. */
    val storageStrategy: StorageStrategy = StorageStrategy.ENCRYPTED_PREFS,
    /** Custom storage provider. Overrides [storageStrategy] when set. */
    val storageProvider: VaultStorageProvider? = null
) {
    class Builder(private val key: String) {
        private var endpoint = ""
        private var signaturePublicKey: String? = null
        private var updateWithPins = false
        private var storageStrategy = StorageStrategy.ENCRYPTED_PREFS
        private var storageProvider: VaultStorageProvider? = null

        fun endpoint(ep: String) = apply { this.endpoint = ep }
        fun signaturePublicKey(key: String) = apply { this.signaturePublicKey = key }
        fun updateWithPins(v: Boolean) = apply { this.updateWithPins = v }
        fun storage(strategy: StorageStrategy) = apply { this.storageStrategy = strategy }
        fun storage(provider: VaultStorageProvider) = apply { this.storageProvider = provider }

        fun build(): VaultFileConfig {
            require(endpoint.isNotBlank()) { "endpoint must not be blank for vault file: $key" }
            return VaultFileConfig(
                key = key,
                endpoint = endpoint.trimStart('/'),
                signaturePublicKey = signaturePublicKey,
                updateWithPins = updateWithPins,
                storageStrategy = storageStrategy,
                storageProvider = storageProvider
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
