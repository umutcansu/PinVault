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
    val encryption: VaultFileEncryption = VaultFileEncryption.PLAIN,
    /** Whether reading the stored copy needs the screen lock or a biometric; see [UserAuth]. */
    val userAuth: UserAuth = UserAuth.NONE,
    /**
     * How long the stored copy may be read without the server confirming it,
     * in milliseconds. Null = the config's default
     * ([PinVaultConfig.vaultFileMaxOfflineAgeMs]); 0 = no limit. See
     * [Builder.maxOfflineAge].
     */
    val maxOfflineAgeMs: Long? = null,
    /** Delete the stored copy once it is older than [maxOfflineAgeMs]. See [Builder.wipeWhenStale]. */
    val wipeWhenStale: Boolean = false
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
        private var userAuth: UserAuth = UserAuth.NONE
        private var maxOfflineAgeMs: Long? = null
        private var wipeWhenStale: Boolean = false

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

        /**
         * Lock the stored copy behind the screen lock or a biometric: read it
         * with PinVault.unlockFile, which shows the prompt. See [UserAuth];
         * with [VaultFileEncryption.USER_AUTH] the content never reaches the
         * app before the prompt.
         */
        fun userAuth(policy: UserAuth) = apply { this.userAuth = policy }

        /**
         * How long the stored copy may be read without the server confirming
         * it. `PinVault.loadFile` returns null and `PinVault.unlockFile`
         * returns [VaultFileUnlockResult.Stale] once the last successful
         * fetch of this file — a download, or the server's "you have the
         * current version" — is older than this; `PinVault.fileStatus` says
         * [VaultFileStatus.STALE]. The next successful fetch makes the copy
         * readable again.
         *
         * Why: a device the server has revoked learns of it from the
         * server's answer. One that stays offline never hears it and would
         * keep every cached file for ever. With a limit, a file is usable
         * offline for that long and no longer.
         *
         * The age is measured with the library's own clock, which does not
         * follow the device clock when that is set back. A copy stored before
         * a limit was set has no confirmation on record and counts as stale
         * until the next successful fetch. The default is the config's
         * `vaultFileMaxOfflineAge` (no limit unless set); `0` means no limit
         * for this file whatever the config says.
         */
        fun maxOfflineAge(amount: Long, unit: java.util.concurrent.TimeUnit) = apply {
            require(amount >= 0) { "maxOfflineAge must not be negative" }
            this.maxOfflineAgeMs = unit.toMillis(amount)
        }

        /**
         * Delete the stored copy when it is found older than [maxOfflineAge]:
         * at `loadFile` / `unlockFile`, at `init` and on every periodic
         * update. Without it a stale copy is kept (unreadable) and becomes
         * readable again after a successful fetch.
         */
        fun wipeWhenStale() = apply { this.wipeWhenStale = true }

        fun build(): VaultFileConfig {
            require(endpoint.isNotBlank()) { "endpoint must not be blank for vault file: $key" }
            require(encryption != VaultFileEncryption.USER_AUTH || userAuth != UserAuth.NONE) {
                "encryption(USER_AUTH) needs userAuth(UserAuth.REQUIRED) or userAuth(UserAuth.IF_SCREEN_LOCK) (key: $key)"
            }
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
                encryption = encryption,
                userAuth = userAuth,
                maxOfflineAgeMs = maxOfflineAgeMs,
                wipeWhenStale = wipeWhenStale
            )
        }
    }
}

/**
 * Built-in storage strategies for vault files.
 *
 * - [ENCRYPTED_PREFS]: Default. Encrypted preferences (AES-256-GCM, keys in the Android Keystore). Best for small/medium files (<1MB).
 * - [ENCRYPTED_FILE]: Uses AES-256-GCM encrypted files on disk. Best for large files (ML models, etc.).
 *
 * Both strategies use Android Keystore for hardware-backed key management.
 */
enum class StorageStrategy {
    /** Encrypted preferences, keys in the Android Keystore (default). Small/medium files. */
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

    /**
     * Requires the server's admin `X-API-Key`.
     *
     * **NOT USABLE FROM A DEVICE — server-side tooling only.** PinVault never
     * sends the admin key from a device and never will: an admin key shipped
     * inside an APK is extractable by anyone who downloads the app, so it
     * would be an admin key for everyone. A vault file declared with this
     * policy therefore fails with **HTTP 401 on every fetch**, with the only
     * visible trace being a `failed` row in the server's distribution history.
     * [io.github.umutcansu.pinvault.model.PinVaultConfig.Builder.build] logs a
     * warning when it sees one.
     *
     * Use it to mark files that only server-to-server tooling (a build
     * pipeline, an ops script) may read. For device-facing files use [TOKEN]
     * or [TOKEN_MTLS]; for genuinely public ones use [PUBLIC].
     */
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
 * - [END_TO_END]: per-device encryption. The server wraps the content with
 *   the device's registered RSA public key; the library decrypts it via
 *   VaultFileDecryptor with the Android Keystore private key. Relays, caches
 *   and other devices cannot read it. The name is historical: the server
 *   performs the encryption, so it sees the content (it keeps it encrypted on
 *   disk). To hide a file from the server too, encrypt it before upload.
 * - [USER_AUTH]: like [END_TO_END], but wrapped with the device's user-auth
 *   key (see [UserAuth]), which the hardware opens only after the screen lock
 *   or a strong biometric. The library stores the server's envelope as it
 *   came and opens it in `PinVault.unlockFile`, so the content never reaches
 *   the app before the prompt. The key is registered with its Android key
 *   attestation chain; against root running as the app this holds only when
 *   the server enforces that attestation (see [UserAuth]). Needs
 *   `userAuth(REQUIRED or IF_SCREEN_LOCK)`; server value `user_auth`.
 *   Adding this constant breaks an exhaustive `when` over the enum in
 *   callers compiled against 2.1.1.
 */
enum class VaultFileEncryption {
    PLAIN,
    AT_REST,
    END_TO_END,
    USER_AUTH
}
