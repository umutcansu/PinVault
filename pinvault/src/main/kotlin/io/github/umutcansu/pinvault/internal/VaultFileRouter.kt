package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.api.DefaultCertificateConfigApi
import io.github.umutcansu.pinvault.api.VaultFetchHttpException
import io.github.umutcansu.pinvault.crypto.SignatureTrust
import io.github.umutcansu.pinvault.crypto.VaultFileDecryptor
import io.github.umutcansu.pinvault.keystore.DeviceKeyProvider
import io.github.umutcansu.pinvault.keystore.UserAuthKeys
import io.github.umutcansu.pinvault.keystore.publicKeyToPem
import io.github.umutcansu.pinvault.model.ScreenLockRequiredException
import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.model.UserAuth
import io.github.umutcansu.pinvault.model.VaultDownloadReport
import io.github.umutcansu.pinvault.model.VaultFetchResponse
import io.github.umutcansu.pinvault.model.VaultFileAccessPolicy
import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.model.VaultFileEncryption
import io.github.umutcansu.pinvault.model.VaultFileResult
import io.github.umutcansu.pinvault.store.StoredSignatures
import io.github.umutcansu.pinvault.store.UnlockVerifier
import io.github.umutcansu.pinvault.store.UserAuthVaultStorage
import io.github.umutcansu.pinvault.store.UserAuthRegistrations
import io.github.umutcansu.pinvault.store.VaultStorageProvider
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber

/**
 * Routes vault file fetches to the right [ConfigApiClient] and applies
 * per-file decryption on the way back.
 *
 * Responsibilities:
 *   1. Look up `file.configApiId` in the per-block client map.
 *   2. Resolve deviceId + access token based on [VaultFileConfig.accessPolicy].
 *   3. Call `downloadVaultFileWithMeta` on the bound client's API impl.
 *   4. For `encryption = END_TO_END`, decrypt the envelope via
 *      [VaultFileDecryptor] using [deviceKeyProvider]'s private key.
 *   5. For `encryption = USER_AUTH`, make sure the server has the device's
 *      user-auth key, and store the envelope sealed as it came: it is opened
 *      (and its signature checked) only in `PinVault.unlockFile`.
 *   6. Persist via the file's [VaultStorageProvider] and return a
 *      [VaultFileResult].
 *
 * Storage/reporting is the caller's concern — router returns the VaultFileResult
 * for the caller to handle (PinVault orchestrates notify/listener/report).
 */
internal class VaultFileRouter(
    private val clients: Map<String, ConfigApiClient>,
    private val storageFor: (String) -> VaultStorageProvider,
    private val deviceKeyProvider: DeviceKeyProvider?,
    private val deviceIdProvider: () -> String,
    /** The device's user-auth key; null when no file uses [UserAuth]. */
    private val userAuthKeys: UserAuthKeys? = null,
    /** Every vault file of the config, for the key-replacement proof. */
    private val files: () -> Collection<VaultFileConfig> = { emptyList() },
    /**
     * Config API id → hex id of the user-auth key last registered there
     * successfully. Persisted in production: copies are stamped with it.
     */
    private val registrations: UserAuthRegistrations = UserAuthRegistrations.InMemory(),
    /**
     * Keeps, per stored file, the signatures it came with and when the
     * server last confirmed it, for the checks done when a file is read.
     * Null = not recorded (tests of the fetch path alone).
     */
    private val guard: VaultFileGuard? = null
) {

    /**
     * Serialises "make sure there is a key" + "register it": init registers in
     * the background while the app may already call fetchFile (`initialized`
     * is set before the init work runs), and two racing registrations could
     * otherwise generate twice or record a key the server never got.
     */
    private val userAuthRegistration = Mutex()

    /**
     * Perform the fetch. Does NOT send the distribution report — caller does
     * that once it has the final [VaultFileResult].
     */
    suspend fun fetchFile(file: VaultFileConfig): VaultFileResult {
        val client = clients[file.configApiId]
            ?: return VaultFileResult.Failed(
                file.key,
                "VaultFile '${file.key}' bound to unknown configApi '${file.configApiId}'"
            )

        return try {
            val storage = storageFor(file.key)
            val deviceId = deviceIdProvider()

            // Before the stored version is read: preparing may give up a copy
            // that was sealed for a key the server no longer has.
            val sealedByServer = file.encryption == VaultFileEncryption.USER_AUTH
            if (sealedByServer) prepareUserAuth(file, storage, deviceId)?.let { return it }

            val currentVersion = storage.getVersion(file.key)
            // A signed file stored without its signatures (by an earlier
            // version) is downloaded again: asking with its version would be
            // answered "not modified", and it could never be checked on read.
            // Likewise a locked copy whose approved unlock failed for a reason
            // that may be the copy itself: it is kept, not deleted on a
            // guess, and replaced by a whole download.
            val refetch = (storage as? UserAuthVaultStorage)?.needsFetch(file.key) == true
            val askedVersion = if (currentVersion > 0 && guard?.needsSignature(file, storedVerifier(file)) == true) {
                Timber.i("Vault file [%s] has no signature on record — downloading it again", file.key)
                0
            } else if (currentVersion > 0 && refetch) {
                Timber.i("Vault file [%s] did not open after an approved unlock — downloading it again", file.key)
                0
            } else currentVersion

            // A blank provider result means "the host app has no token yet",
            // not "the token is the empty string". Sending `X-Vault-Token: `
            // makes the server answer "invalid or revoked token" for what is
            // really a missing header, which sends operators hunting for a
            // revoked token that was never issued. Drop the header instead and
            // let the server report the accurate error.
            val token = when (file.accessPolicy) {
                VaultFileAccessPolicy.TOKEN,
                VaultFileAccessPolicy.TOKEN_MTLS ->
                    file.accessTokenProvider?.invoke()?.takeIf { it.isNotBlank() }
                else -> null
            }
            // Whether a token is sent, never any part of it.
            Timber.d("Vault fetch [%s] via %s (token present: %b)", file.key,
                file.accessPolicy.name.lowercase(), token != null)

            val download = suspend {
                client.api.downloadVaultFileWithMeta(
                    endpoint = file.endpoint,
                    currentVersion = askedVersion,
                    deviceId = deviceId.takeIf { it.isNotBlank() },
                    accessToken = token
                )
            }
            val response: VaultFetchResponse = try {
                download()
            } catch (e: VaultFetchHttpException) {
                // The server has no (or another) user-auth key for this
                // device: make sure there is a key, register it, try once more.
                if (!sealedByServer || e.code != 412 || e.body?.contains(USER_AUTH_KEY_REQUIRED) != true) throw e
                Timber.w("Vault fetch [%s]: server has no user-auth key for this device — registering and retrying", file.key)
                ensureUserAuthKeyRegistered(file.configApiId, deviceId, force = true)
                download()
            }

            if (response.notModified) {
                guard?.confirmed(file)
                return VaultFileResult.AlreadyCurrent(file.key, currentVersion)
            }

            // The version header is only as good as the response. A file whose
            // content is checked after the prompt (user_auth), or not at all
            // (an unsigned block), must not be able to plant a version so high
            // that the real file is answered "older" from then on: the same
            // bound as for pin versions.
            versionJumpProblem(file.key, response.version, currentVersion)?.let { return VaultFileResult.Failed(file.key, it) }

            val served = VaultFileEncryption.entries.find { it.name.equals(response.encryption, ignoreCase = true) }
            if (sealedByServer || served == VaultFileEncryption.USER_AUTH) {
                return storeSealedByServer(file, client, storage, currentVersion, response, served)
            }

            // Fail closed, as for user_auth: a file the app declared
            // end_to_end must not be taken as plain because the response says
            // so — that would let whoever answers skip the device-key layer.
            if (file.encryption == VaultFileEncryption.END_TO_END && served != null && served != VaultFileEncryption.END_TO_END) {
                return VaultFileResult.Failed(
                    file.key, "Vault file '${file.key}': the server answered encryption=${response.encryption} for an end_to_end file; refused"
                )
            }

            // Decrypt if E2E
            val plain: ByteArray = when (served ?: file.encryption) {
                VaultFileEncryption.END_TO_END -> {
                    val kp = deviceKeyProvider
                        ?: return VaultFileResult.Failed(
                            file.key,
                            "encryption=end_to_end requires DeviceKeyProvider; none configured"
                        )
                    kp.ensureKeyPair()
                    try {
                        VaultFileDecryptor.decrypt(response.content, kp.getPrivateKey())
                    } catch (e: Exception) {
                        Timber.e(e, "E2E decrypt failed: %s", file.key)
                        return VaultFileResult.Failed(file.key, "E2E decrypt failed: ${e.message}", e)
                    }
                }
                else -> response.content
            }

            // Integrity (default-on, fail-closed): vault files are signed by the
            // Config API's signing keys — the same ones the device already trusts
            // for config, including a rotated key set and an m-of-n requirement.
            // A per-file key overrides them with exactly that one key. Verify the
            // PLAINTEXT (post-E2E-decrypt) BEFORE persisting. No trust only for
            // allowUnsigned()/test setups → skip+warn.
            val trust = trustFor(file, client)
            // What the stored copy is checked against again whenever it is read.
            var accepted: StoredSignatures? = null
            if (trust != null && trust.isEnabled) {
                // A block that names its server-side Config API (serverScope)
                // takes only v2 signatures, which name it too: a file signed
                // for another Config API with the same key does not pass.
                val scope = client.block.serverScope
                val entries = signatureEntries(response, scope)
                if (entries.isEmpty()) {
                    return VaultFileResult.Failed(file.key, noSignatureMessage(file.key, scope))
                }
                val verification = trust.verifyVaultFile(
                    key = file.key,
                    version = response.version,
                    plaintext = plain,
                    entries = entries,
                    serverScope = scope
                )
                accepted = StoredSignatures(response.version, schemeOf(scope), entries)
                if (!verification.ok) {
                    return VaultFileResult.Failed(
                        file.key,
                        "Vault file '${file.key}' signature verification FAILED — " +
                            "possible tampering. Not saved.${verification.detail}"
                    )
                }
                // Downgrade guard: a validly-signed but OLDER version must not
                // overwrite a newer stored copy (replay of a stale signed file).
                if (response.version in 1 until currentVersion) {
                    return VaultFileResult.Failed(file.key, downgradeMessage(file.key, response.version, currentVersion))
                }
                Timber.d("Vault file signature verified ✓ [%s] v%d", file.key, response.version)
            } else {
                Timber.w(
                    "Vault file '%s' fetched WITHOUT signature verification " +
                        "(no signaturePublicKey / allowUnsigned). Set signaturePublicKey for integrity.",
                    file.key
                )
            }

            // Persist. Dedupe against stored to emit AlreadyCurrent when server
            // didn't 304 but the bytes match (e.g. legacy backend without
            // version-header support).
            val storedBytes = storage.load(file.key)
            if (storedBytes != null && plain.contentEquals(storedBytes)) {
                if (accepted != null && response.version > 0 && response.version != currentVersion) {
                    // Same content under a new version (the server bumps it when
                    // a file's policy changes): keep the label the signature
                    // names, or the copy would fail its check when read.
                    storage.save(file.key, plain, response.version)
                    guard?.stored(file, response.version, accepted)
                    return VaultFileResult.AlreadyCurrent(file.key, response.version)
                }
                // Signatures go on record here too: this is how a copy stored
                // by an earlier version gets them.
                if (accepted != null) guard?.stored(file, currentVersion, accepted) else guard?.confirmed(file)
                VaultFileResult.AlreadyCurrent(file.key, currentVersion)
            } else {
                val newVersion = if (response.version > 0) response.version else (currentVersion + 1)
                storage.save(file.key, plain, newVersion)
                guard?.stored(file, newVersion, accepted)
                Timber.d(
                    "Vault file updated [%s]: %s v%d → v%d (%d bytes, encryption=%s)",
                    file.configApiId, file.key, currentVersion, newVersion, plain.size, response.encryption
                )
                // A locked file's content is only handed out by unlockFile.
                VaultFileResult.Updated(file.key, newVersion, if (file.userAuth == UserAuth.NONE) plain else ByteArray(0))
            }
        } catch (e: Exception) {
            // Beklenen HTTP 4xx senaryoları (dosya yok / geçersiz token / yetkisiz)
            // genuine bug değil — policy enforcement'ı doğrulayan testler bu yolu
            // kasten tetikliyor. Stack trace olmadan W seviyesinde logla, üst katman
            // VaultFileResult.Failed ile zaten sinyal alıyor. 5xx veya ağ hatası gibi
            // gerçek problemler E olarak kalsın.
            val msg = e.message ?: ""
            val isExpected4xx = Regex("HTTP 4\\d{2}").containsMatchIn(msg)
            if (isExpected4xx) {
                Timber.w("Vault fetch rejected [%s]: %s — %s", file.configApiId, file.key, msg.take(120))
            } else {
                Timber.e(e, "Vault fetch failed [%s]: %s", file.configApiId, file.key)
            }
            VaultFileResult.Failed(file.key, e.message ?: "Unknown error", e)
        }
    }

    /**
     * Before a `user_auth` download: a screen lock, a device id and a
     * registered user-auth key. Returns the failure, or null to go ahead.
     */
    private suspend fun prepareUserAuth(file: VaultFileConfig, storage: VaultStorageProvider, deviceId: String): VaultFileResult? {
        if (storage !is UserAuthVaultStorage || userAuthKeys == null) {
            return VaultFileResult.Failed(
                file.key, "Vault file '${file.key}': encryption(USER_AUTH) needs userAuth(REQUIRED or IF_SCREEN_LOCK)"
            )
        }
        if (!userAuthKeys.isScreenLockSet()) {
            val error = if (file.userAuth == UserAuth.REQUIRED) ScreenLockRequiredException(file.key)
            else ScreenLockRequiredException(
                file.key,
                "Vault file '${file.key}' is sealed by the server for the screen lock (encryption = USER_AUTH) and the " +
                    "device has none, so it cannot be received; IF_SCREEN_LOCK cannot store this one unlocked"
            )
            return VaultFileResult.Failed(file.key, error.message ?: "Screen lock required", error)
        }
        if (deviceId.isBlank()) {
            return VaultFileResult.Failed(file.key, "Vault file '${file.key}': user_auth files need a device id (X-Device-Id); none is available")
        }
        try {
            ensureUserAuthKeyRegistered(file.configApiId, deviceId)
        } catch (e: Exception) {
            return VaultFileResult.Failed(
                file.key, "Vault file '${file.key}': could not register the user-auth key with '${file.configApiId}': ${e.message}", e
            )
        }
        // A copy sealed for a key other than the one the server has now can
        // never open, and the server would answer "already current" to its
        // version: give it up so this fetch downloads the file again.
        val registered = registrations.get(file.configApiId)
        val stamp = storage.sealedKeyId(file.key)?.let { hex(it) }
        if (stamp != null && registered != null && stamp != registered) {
            Timber.w("Vault file [%s] was sealed for user-auth key %s, the server now has %s — downloading it again",
                file.key, stamp, registered)
            storage.clear(file.key)
        }
        return null
    }

    /**
     * Stores a `user_auth` response as it came. Nothing is decrypted or
     * verified here — the content must not reach the app before the prompt —
     * but a missing signature and an older version are refused now.
     */
    private fun storeSealedByServer(
        file: VaultFileConfig,
        client: ConfigApiClient,
        storage: VaultStorageProvider,
        currentVersion: Int,
        response: VaultFetchResponse,
        served: VaultFileEncryption?
    ): VaultFileResult {
        if (file.encryption != VaultFileEncryption.USER_AUTH) {
            return VaultFileResult.Failed(
                file.key, "Vault file '${file.key}': the server sent a user_auth file, but the app did not declare encryption(USER_AUTH)"
            )
        }
        if (served != VaultFileEncryption.USER_AUTH) {
            // Fail closed: a copy not sealed for the screen lock would put the
            // content in the app's hands without the prompt.
            return VaultFileResult.Failed(
                file.key, "Vault file '${file.key}': the server answered encryption=${response.encryption} for a user_auth file; refused"
            )
        }
        val trust = trustFor(file, client)
        // The signatures the copy is checked with at unlock: v2 when the
        // block names its server-side Config API, else v1.
        val scope = client.block.serverScope
        val entries = if (trust != null && trust.isEnabled) signatureEntries(response, scope) else signatureEntries(response, null)
        if (trust != null && trust.isEnabled && entries.isEmpty()) {
            return VaultFileResult.Failed(file.key, noSignatureMessage(file.key, scope))
        }
        if (response.version in 1 until currentVersion) {
            return VaultFileResult.Failed(file.key, downgradeMessage(file.key, response.version, currentVersion))
        }
        val refetch = (storage as UserAuthVaultStorage).needsFetch(file.key)
        if (response.version > 0 && response.version == currentVersion && storage.exists(file.key) && !refetch) {
            guard?.confirmed(file)
            return VaultFileResult.AlreadyCurrent(file.key, currentVersion)
        }
        val newVersion = if (response.version > 0) response.version else (currentVersion + 1)
        // Stamped with the key the server was given (and sealed for), not
        // just whatever key the device holds now.
        val sealedFor = registrations.get(file.configApiId)?.let { unhex(it) }
        storage.saveSealedByServer(file.key, response.content, newVersion, entries, sealedFor)
        guard?.stored(file, newVersion, null)
        Timber.d("Vault file stored sealed [%s]: %s v%d → v%d (user_auth, opens with unlockFile)",
            file.configApiId, file.key, currentVersion, newVersion)
        return VaultFileResult.Updated(file.key, newVersion, ByteArray(0))
    }

    /**
     * Makes sure Config API [configApiId] has this device's user-auth key: a
     * key exists (made now if there was none or Android retired it) and was
     * registered there in this process. [force] registers again anyway (the
     * server said it has none). Throws when that fails.
     */
    suspend fun ensureUserAuthKeyRegistered(configApiId: String, deviceId: String, force: Boolean = false) =
        userAuthRegistration.withLock {
            val keys = userAuthKeys ?: throw IllegalStateException("No user-auth key: no vault file uses userAuth")
            val generated = keys.ensureKey()
            val publicKey = keys.publicKey()
            val keyId = hex(UserAuthKeys.keyId(publicKey))
            if (!force && !generated && registrations.get(configApiId) == keyId) return@withLock
            val client = clients[configApiId] ?: throw IllegalStateException("Unknown Config API '$configApiId'")
            val pem = publicKeyToPem(publicKey)
            // Leaf first, as the Keystore returns it; empty when the device
            // could not attest the key (older servers ignore the field).
            val chain = try {
                keys.attestationChain().map { android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP) }
            } catch (e: Exception) {
                Timber.w(e, "Could not read the user-auth key's attestation chain; registering without")
                emptyList()
            }
            val api = client.api
            if (api is DefaultCertificateConfigApi) {
                api.registerUserAuthPublicKey(deviceId, pem, chain, keyProof(configApiId, files()))
            } else {
                try {
                    api.registerUserAuthPublicKey(deviceId, pem, chain)
                } catch (e: AbstractMethodError) {
                    throw unsupportedBackend(api, e)
                } catch (e: NoSuchMethodError) {
                    throw unsupportedBackend(api, e)
                }
            }
            registrations.put(configApiId, keyId)
            Timber.d("User-auth key %s registered with [%s] (attestation chain: %d)", keyId, configApiId, chain.size)
        }

    /**
     * A custom [io.github.umutcansu.pinvault.api.CertificateConfigApi]
     * compiled against PinVault 2.1.1 or earlier has no
     * `registerUserAuthPublicKey`; calling it ends in a linkage error.
     */
    private fun unsupportedBackend(api: Any, e: LinkageError) = UnsupportedOperationException(
        "the app's CertificateConfigApi (${api.javaClass.name}) was built against an older PinVault and does not " +
            "implement registerUserAuthPublicKey, so encryption(USER_AUTH) files cannot be used with it", e
    )

    /**
     * Registers the user-auth key with every Config API that has a
     * `user_auth` file (at init). Needs a screen lock; never throws.
     */
    suspend fun registerUserAuthKeyEverywhere(deviceId: String) {
        val keys = userAuthKeys ?: return
        val ids = files().filter { it.encryption == VaultFileEncryption.USER_AUTH }.map { it.configApiId }.toSet()
        if (ids.isEmpty() || deviceId.isBlank()) return
        if (!keys.isScreenLockSet()) {
            Timber.w("No screen lock — user_auth files cannot be received until one is set")
            return
        }
        for (id in ids) {
            try {
                ensureUserAuthKeyRegistered(id, deviceId)
            } catch (e: Exception) {
                Timber.w(e, "User-auth key registration failed on [%s]", id)
            }
        }
    }

    /** After the key is deleted (a wipe): register again before the next `user_auth` fetch. */
    fun forgetUserAuthRegistrations() = registrations.clear()

    /**
     * After a copy of [configApiId] turned out to be sealed for another key:
     * register again before its next `user_auth` fetch.
     */
    fun forgetUserAuthRegistration(configApiId: String) = registrations.remove(configApiId)

    /**
     * What `unlockFile` checks a server-sealed copy with once it is open: the
     * same trust the fetch path uses for other files. For a Config API that
     * runs unsigned (`allowUnsigned()`) it checks nothing and logs a warning.
     * Null only when the file's Config API is unknown — the caller then
     * refuses to open the copy (fail closed).
     */
    fun unlockVerifier(file: VaultFileConfig): UnlockVerifier? {
        val client = clients[file.configApiId] ?: run {
            Timber.e("Vault file '%s' is bound to unknown Config API '%s'; it is not opened", file.key, file.configApiId)
            return null
        }
        val verifier = storedVerifier(file)
        if (verifier == null) {
            return { _, _, _ ->
                Timber.w("Vault file '%s' opened WITHOUT signature verification (allowUnsigned).", file.key)
                null
            }
        }
        return verifier.verify
    }

    /**
     * How a stored copy of [file] is checked when it is read: with the trust
     * of its Config API (or the file's own key), against v2 signatures when
     * the block set `serverScope`, else v1. Null when the block runs unsigned
     * (or is unknown): nothing to check a copy with.
     */
    fun storedVerifier(file: VaultFileConfig): StoredVerifier? {
        val client = clients[file.configApiId] ?: return null
        val trust = trustFor(file, client)?.takeIf { it.isEnabled } ?: return null
        val scope = client.block.serverScope
        return StoredVerifier(schemeOf(scope)) { plaintext, version, entries ->
            if (entries.isEmpty()) {
                "it carries no signature but a verifying key is configured"
            } else {
                val verification = trust.verifyVaultFile(file.key, version, plaintext, entries, scope)
                if (verification.ok) null else "signature verification failed — possible tampering.${verification.detail}"
            }
        }
    }

    private fun trustFor(file: VaultFileConfig, client: ConfigApiClient): SignatureTrust? =
        file.signaturePublicKey?.let { SignatureTrust.single(file.configApiId, it) } ?: client.signatureTrust

    /**
     * The signatures of the scheme the block verifies: the v2 headers when it
     * has a [serverScope], the v1 headers otherwise. Never one for the other:
     * a v1 signature does not say which Config API it was made for.
     */
    private fun signatureEntries(response: VaultFetchResponse, serverScope: String?): List<SignatureEntry> {
        val (several, single) = if (serverScope != null) response.signaturesV2 to response.signatureV2
        else response.signatures to response.signature
        return several?.takeIf { it.isNotEmpty() }
            ?: listOfNotNull(single?.takeIf { it.isNotBlank() }?.let { SignatureEntry(signature = it) })
    }

    private fun schemeOf(serverScope: String?) = if (serverScope != null) 2 else 1

    private fun noSignatureMessage(key: String, serverScope: String?) =
        if (serverScope != null) {
            "Vault file '$key' carries no X-Vault-Signature-V2, which this Config API block requires " +
                "(serverScope '$serverScope': the signature must name the Config API) — refusing (fail-closed)."
        } else {
            "Vault file '$key' carries no X-Vault-Signature but a verifying key is configured — refusing (fail-closed)."
        }

    /**
     * Why a served version is not believable, or null: more than
     * [MAX_VERSION_JUMP] above the stored one (or above zero for a first
     * copy). A file that is updated a million times is not a file.
     */
    private fun versionJumpProblem(key: String, served: Int, stored: Int): String? =
        if (served.toLong() - stored.coerceAtLeast(0) > MAX_VERSION_JUMP) {
            "Vault file '$key' refused: served v$served is more than $MAX_VERSION_JUMP above stored v$stored."
        } else null

    private fun downgradeMessage(key: String, served: Int, stored: Int) =
        "Vault file '$key' downgrade rejected: served v$served < stored v$stored."

    /** Ask the bound client's API to report the outcome. */
    suspend fun report(file: VaultFileConfig, report: VaultDownloadReport) {
        val client = clients[file.configApiId] ?: return
        try {
            client.api.reportVaultDownload(report)
        } catch (e: Exception) {
            Timber.e(e, "Report send failed [%s]: %s", file.configApiId, file.key)
        }
    }

    /**
     * Register this device's RSA public key with EVERY Config API (E2E support).
     *
     * A TLS listener keeps the first key it was given; replacing it (a new key
     * after the app's data was cleared) needs the device's token for one of
     * that API's end_to_end or user_auth files, so one goes along when
     * [files] has it.
     */
    suspend fun registerDevicePublicKey(deviceId: String, publicKeyPem: String, files: Collection<VaultFileConfig> = emptyList()) {
        for ((id, client) in clients) {
            try {
                val api = client.api
                if (api is DefaultCertificateConfigApi) {
                    api.registerDevicePublicKey(deviceId, publicKeyPem, keyProof(id, files))
                } else {
                    api.registerDevicePublicKey(deviceId, publicKeyPem)
                }
            } catch (e: Exception) {
                Timber.w(e, "Public-key registration failed on [%s]", id)
            }
        }
    }

    /**
     * The device's token for an end_to_end or user_auth file of Config API
     * [configApiId], or null when the app has none (yet). The server-side key
     * is the last segment of the file's endpoint.
     */
    internal fun keyProof(configApiId: String, files: Collection<VaultFileConfig>): io.github.umutcansu.pinvault.api.DeviceKeyProof? =
        files.asSequence()
            .filter {
                it.configApiId == configApiId &&
                    (it.encryption == VaultFileEncryption.END_TO_END || it.encryption == VaultFileEncryption.USER_AUTH) &&
                    (it.accessPolicy == VaultFileAccessPolicy.TOKEN || it.accessPolicy == VaultFileAccessPolicy.TOKEN_MTLS)
            }
            .mapNotNull { file ->
                val token = try { file.accessTokenProvider?.invoke() } catch (e: Exception) { null }
                val key = file.endpoint.substringBefore('?').trimEnd('/').substringAfterLast('/')
                if (token.isNullOrBlank() || key.isEmpty()) null
                else io.github.umutcansu.pinvault.api.DeviceKeyProof(key, token)
            }
            .firstOrNull()

    companion object {
        /** The `error` of a server's 412 for a `user_auth` file it has no key for. */
        const val USER_AUTH_KEY_REQUIRED = "user_auth_key_required"

        /** Largest accepted step of a file version over the stored one; the bound pin versions have. */
        const val MAX_VERSION_JUMP = 1_000_000L

        private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

        private fun unhex(hex: String): ByteArray? =
            if (hex.length % 2 != 0) null
            else runCatching { ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() } }.getOrNull()
    }
}
