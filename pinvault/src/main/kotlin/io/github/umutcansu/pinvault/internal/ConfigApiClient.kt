package io.github.umutcansu.pinvault.internal

import android.content.Context
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.api.DefaultCertificateConfigApi
import io.github.umutcansu.pinvault.api.SignedConfigSource
import io.github.umutcansu.pinvault.crypto.Pkcs10Csr
import io.github.umutcansu.pinvault.crypto.SignatureTrust
import io.github.umutcansu.pinvault.crypto.SignedConfigVerifier
import io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider
import io.github.umutcansu.pinvault.keystore.ImportedClientKeys
import io.github.umutcansu.pinvault.model.ConfigApiBlock
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import io.github.umutcansu.pinvault.ssl.HttpClientProvider
import io.github.umutcansu.pinvault.ssl.SSLCertificateUpdater
import io.github.umutcansu.pinvault.ssl.TrustedClock
import io.github.umutcansu.pinvault.store.CertificateConfigStore
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import io.github.umutcansu.pinvault.store.SigningKeyStore
import timber.log.Timber

/**
 * A self-contained bundle of "everything we need to talk to one Config API":
 *  - dedicated SSLManager + OkHttp client (its own pin verification stack)
 *  - namespaced [CertificateConfigStore] so pins don't collide between APIs
 *  - [CertificateConfigApi] impl bound to this block's URL
 *  - [SSLCertificateUpdater] driving init + periodic refresh
 *  - [ClientCertRenewer] keeping a CSR-enrolled client certificate alive
 *
 * One [ConfigApiClient] per [ConfigApiBlock]. PinVault owns a Map of these and
 * routes vault file fetches / scoped pin fetches to the correct one.
 *
 * Kept `internal` because callers should interact with PinVault's public API,
 * never with per-block clients directly.
 */
internal class ConfigApiClient(
    val block: ConfigApiBlock,
    context: Context,
    /** Optional explicit API override — used by tests / custom backends. */
    customApi: CertificateConfigApi? = null,
    /**
     * Callback fired when a pin-mismatch recovery updates config for THIS
     * block. PinVault forwards the [UpdateResult] to its public listener.
     */
    recoveryListener: (UpdateResult) -> Unit = { },
    /** The device identity key behind a CSR-enrolled certificate, per label. Tests pass a software key. */
    private val identityKeyFactory: (label: String) -> ClientIdentityKeyProvider = { ClientIdentityKeyProvider.androidKeystore(it) },
    /**
     * Told the server's reason when a request of this block is refused as
     * `reenroll_required` — once per client identity ([claimReenrollNotice]).
     */
    private val reenrollListener: (reason: String) -> Unit = { },
    /** `PinVaultConfig.expiredConfigGraceMs`: how long an expired config may still pin. */
    private val expiredConfigGraceMs: Long = 0L,
    /** `PinVaultConfig.caTrustHosts`: hosts whose chain must also pass the platform CAs. */
    caTrustHosts: List<String> = emptyList(),
    /** Where keys that arrive in a PKCS12 are kept: the Android Keystore, non-exportable. Tests pass a software one. */
    private val importedKeys: ImportedClientKeys = ImportedClientKeys.androidKeystore(),
    /**
     * Told when the server refuses THIS device's identity: a
     * `reenroll_required` answer on a connection that presented the
     * certificate loaded now, or the refusal of its renewal over that same
     * mTLS connection. Once per identity ([IdentityRevocation]). An
     * answer on a connection without it changes nothing on the device — any
     * 403 with that body would otherwise be enough to wipe a block's files.
     */
    private val onIdentityRevoked: () -> Unit = { },
    /** `PinVaultConfig.expectedSignerSha256`: what the attestation report's `app_integrity` is judged against on the device. */
    private val expectedSignerSha256: List<String> = emptyList(),
    /** `PinVaultConfig.integrityVerdictProvider`: a second opinion forwarded in the attestation report. */
    private val integrityVerdictProvider: io.github.umutcansu.pinvault.integrity.IntegrityVerdictProvider? = null,
    /** `PinVaultConfig.managedTrustRoots`: hosts without a pin entry may validate to a root the signed config lists. */
    managedTrustRoots: Boolean = false
) {
    /**
     * The block's store for the server it points at now: each server (scope,
     * or Config API URL) keeps its own config and watermarks, so a block
     * pointed at another server neither inherits that server's version space
     * nor loses its own when it comes back.
     */
    val configStore: CertificateConfigStore = CertificateConfigStore.forOrigin(
        context.applicationContext,
        CertificateConfigStore.prefsNameFor(block.id),
        block.serverScope?.let { scope -> "scope:$scope" } ?: "url:${block.configUrl.trimEnd('/').lowercase()}"
    )

    /**
     * The clock this block's config expiry is decided by. Its reference — the
     * highest time seen — lives in the block's config store, so setting the
     * device clock back does not bring an expired config back.
     */
    val trustedClock: TrustedClock = TrustedClock(
        load = { configStore.highestSeenTime() },
        persist = { configStore.setHighestSeenTime(it) }
    )

    val sslManager: DynamicSSLManager = DynamicSSLManager().apply {
        this.expiredConfigGraceMs = this@ConfigApiClient.expiredConfigGraceMs
        this.clock = trustedClock::now
        requireCaTrust(caTrustHosts)
        managedTrustRootsEnabled = managedTrustRoots
        // The client identity belongs to this block's own listeners (and to
        // hosts the config marks mtls); no other pinned host gets to see it.
        // A block that lists clientCertHosts has named every host itself:
        // mtls = true entries of the (server-signed) config add none.
        setIdentityHosts(
            listOf(block.configUrl, block.enrollmentUrl, block.renewalUrl) + block.clientCertHosts,
            onlyThese = block.clientCertHosts.isNotEmpty()
        )
    }
    val clientProvider: HttpClientProvider
    val certStore: ClientCertSecureStore = ClientCertSecureStore(context.applicationContext)

    /**
     * Which keys this block's configs and vault files must be signed by.
     * Null when the block runs unsigned. The key-set store is only opened when
     * the block enabled rotation (recovery keys), so apps that don't use it
     * never touch the extra encrypted key-set store.
     */
    val signatureTrust: SignatureTrust? = context.applicationContext.let { appContext ->
        SignatureTrust.forBlock(block) {
            if (block.recoveryPublicKeys.isNotEmpty()) SigningKeyStore(appContext) else null
        }
    }

    /**
     * Why this block must not be used, or null: an `http://` URL or no
     * bootstrap pins without `allowUnpinnedConfigApi()`, or signing keys with
     * a custom API that cannot hand over signed envelopes and no
     * `allowUnsigned()`. Init and every update of the block fail with it.
     */
    val configurationError: String? = configurationError(block, customApi)

    /**
     * Verifies this block's config envelopes — the default API's and those of
     * a custom API that implements [SignedConfigSource]. Null when the
     * block's configs are not verified: no signing keys, or a custom API
     * without envelopes under `allowUnsigned()`.
     */
    private val configVerifier: SignedConfigVerifier? = signatureTrust
        ?.takeIf { customApi == null || customApi is SignedConfigSource }
        ?.let {
            SignedConfigVerifier(
                it, block.serverScope,
                // "Already expired" by the trusted clock, so a clock set back
                // does not let an expired envelope in (see expiryNow).
                trustedNow = trustedClock::now,
                issuedAtWatermark = configStore::getCurrentIssuedAt
            )
        }

    /** True when the library checks the signatures of this block's configs. */
    val configsVerified: Boolean get() = configVerifier != null
    val api: CertificateConfigApi
    val updater: SSLCertificateUpdater
    val renewer: ClientCertRenewer

    /**
     * This block's attestation (`attestation()` on the block), or null when
     * the block does not attest. With a custom [CertificateConfigApi] the
     * manager exists but reports `UNSUPPORTED`: the attest endpoints are
     * reached through the library's own client only.
     */
    val attestation: AttestationManager?

    private val reenrollNotice = ReenrollNotice()
    private val revocation = IdentityRevocation { sslManager.defaultClientCertificate() }

    /** PKCS12 credentials of this block, kept as Keystore keys. */
    val importedIdentities: ImportedIdentities = ImportedIdentities(certStore, importedKeys)

    init {
        loadClientIdentity()

        clientProvider = HttpClientProvider(sslManager)

        api = customApi ?: DefaultCertificateConfigApi(
            configUrl = block.configUrl,
            configEndpoint = block.configEndpoint,
            healthEndpoint = block.healthEndpoint,
            clientCertEndpoint = block.clientCertEndpoint,
            enrollmentEndpoint = block.enrollmentEndpoint,
            vaultReportEndpoint = block.vaultReportEndpoint,
            bootstrapPins = block.bootstrapPins,
            sslManager = sslManager,
            signatureTrust = signatureTrust,
            clientKeyPassword = block.clientKeyPassword,
            enrollmentUrl = block.enrollmentUrl,
            onReenrollRequired = { reason, presented ->
                // The files go before the app hears of it.
                if (revocation.refusedOnConnection(presented)) onIdentityRevoked()
                if (claimReenrollNotice()) reenrollListener(reason)
            },
            serverScope = block.serverScope,
            allowUnpinned = block.allowUnpinnedConfigApi,
            allowServerGeneratedKey = block.allowServerGeneratedKey
        )
        if (customApi != null && signatureTrust != null && configVerifier == null && block.allowUnsigned) {
            Timber.w(
                "ConfigApiClient[%s]: custom CertificateConfigApi without SignedConfigSource under allowUnsigned() — " +
                    "its configs are NOT verified and the stored config has no integrity check", block.id
            )
        }

        val appContext = context.applicationContext
        updater = SSLCertificateUpdater(
            context = appContext,
            configApi = api,
            configStore = configStore,
            httpClientProvider = clientProvider,
            sslManager = sslManager,
            certStore = certStore,
            clientKeyPassword = block.clientKeyPassword,
            maxRetryCount = 3,
            // Pin scoping: forward the block's declared host list (and the
            // device identity the server ACL is keyed on) to every fetch.
            wantPinsFor = block.wantPinsFor,
            deviceIdProvider = { DeviceIdentity.androidId(appContext) },
            expiredConfigGraceMs = expiredConfigGraceMs,
            verifier = configVerifier,
            trustedClock = trustedClock,
            importedKeys = importedKeys
        )

        renewer = ClientCertRenewer(
            block = block,
            certStore = certStore,
            identityKeyFactory = identityKeyFactory,
            api = { api },
            reload = ::reloadClientIdentity,
            // A refusal of the renewal over mTLS wipes when that connection
            // presented the identity loaded now; one on the recovery door
            // (no client certificate) never does.
            onRefusedOverMtls = { leaf -> if (revocation.refusedOnConnection(leaf)) onIdentityRevoked() }
        )

        attestation = if (!block.attestationEnabled) {
            null
        } else {
            val probe = io.github.umutcansu.pinvault.integrity.DeviceIntegrityProbe(
                context = appContext,
                expectedSignerSha256 = expectedSignerSha256.toSet(),
                verdictProvider = integrityVerdictProvider
            )
            AttestationManager(
                block = block,
                api = api as? DefaultCertificateConfigApi,
                identityKey = ::identityKey,
                deviceId = { DeviceIdentity.androidId(appContext) },
                currentConfigVersion = { configStore.getCurrentVersion() },
                currentIssuedAt = { configStore.getCurrentIssuedAt() },
                liveConfig = { clientProvider.currentConfig },
                buildReport = { nonce, deviceId, key -> probe.report(nonce, key, deviceId).toJsonString() },
                // The embedded config takes the fetched config's road, minus the fetch.
                applyConfig = { signed -> updater.applySigned(signed) },
                // Reported like a recovery update: the app's update listener and the ConfigUpdate event.
                onConfigApplied = recoveryListener,
                onEvent = { event -> sslManager.dispatchEvent(event) }
            ).also { manager ->
                // Every client built for this block carries the token from now on.
                clientProvider.tokenInterceptor = io.github.umutcansu.pinvault.api.AttestationTokenInterceptor { listOf(manager) }
            }
        }

        // Pin mismatch recovery hooks into this block's updater only.
        clientProvider.recoveryUpdater = suspend {
            val before = clientProvider.currentConfig
            val wasExpired = before != null && before.expiresAt > 0L &&
                trustedClock.now() >= before.expiresAt + expiredConfigGraceMs
            val result = updateNow()
            recoveryListener(result)
            // An expired config refreshed in place (same pins, newer expiresAt)
            // is AlreadyCurrent, yet the retry now succeeds: try it too. Only
            // then: every fetch writes a fresher issuedAt back in place, so
            // "the config object changed" alone would call a real mismatch
            // repaired and retry it for ever.
            result is UpdateResult.Updated ||
                (result is UpdateResult.AlreadyCurrent && wasExpired && clientProvider.currentConfig !== before)
        }

        Timber.d("ConfigApiClient[%s] ready → %s", block.id, block.configUrl)
    }

    /** The identity key behind this block's client certificate. */
    fun identityKey(): ClientIdentityKeyProvider = identityKeyFactory(block.clientCertLabel)

    /**
     * True the first time the app is to be told that the identity loaded now
     * must re-enroll. A revoked identity is refused on every request and by
     * the renewal endpoint; all of those share this one notice.
     */
    fun claimReenrollNotice(): Boolean {
        val leaf = sslManager.defaultClientCertificate()
        return reenrollNotice.claim(leaf?.let { "${it.issuerX500Principal.name}#${it.serialNumber}" } ?: "none")
    }

    /**
     * Installs the block's client credentials into the SSL manager: the
     * enrolled credential under [ConfigApiBlock.clientCertLabel] — a
     * certificate chain over the device's Keystore key, or a server-made key
     * (`allowServerGeneratedKey()`) — and, only when nothing is enrolled, the
     * P12 bundled with the app (`clientKeystore(...)`, the bootstrap identity
     * for an mTLS Config API).
     *
     * A key that came in a P12 is presented from the Android Keystore, where
     * it was imported as non-exportable; a P12 an earlier version stored is
     * moved there now. Only where the platform refuses the import is the P12
     * itself still loaded.
     */
    private fun loadClientIdentity() {
        val label = block.clientCertLabel
        when (certStore.mode(label)) {
            ClientCertSecureStore.Mode.CHAIN -> loadEnrolledChain(label)
            ClientCertSecureStore.Mode.IMPORTED, ClientCertSecureStore.Mode.P12 -> {
                val imported = importedIdentities.loadOrMigrate(label, block.clientKeyPassword)
                val p12 = if (imported == null) certStore.load(label) else null
                when {
                    imported != null -> sslManager.loadClientKey(imported.privateKey, imported.chain)
                    p12 != null -> sslManager.loadClientKeystore(p12, block.clientKeyPassword)
                    else -> loadBundledKeystore()
                }
            }
            ClientCertSecureStore.Mode.NONE -> loadBundledKeystore()
        }
    }

    /**
     * A chain issued over the device's identity key. The enrollment is given
     * up (chain cleared, re-enrollment needed) only when it can never be
     * presented again: the chain does not parse, or its key is gone or
     * retired. A Keystore that merely fails right now — the encrypted store
     * cannot decrypt the chain, or the key cannot be read — says nothing
     * about either: everything is kept and no identity is presented until
     * the next load (the next start, or an enroll/renew/unenroll reload).
     */
    private fun loadEnrolledChain(label: String) {
        when (loadEnrolledChain(certStore, label, identityKeyFactory(label), sslManager::loadClientKey)) {
            EnrolledChain.LOADED -> Unit
            EnrolledChain.UNAVAILABLE -> sslManager.clearClientKeystore(includeHostCerts = false)
            EnrolledChain.DROPPED -> loadBundledKeystore()
        }
    }

    /** What [loadEnrolledChain] came to. */
    internal enum class EnrolledChain {
        /** Presented now. */
        LOADED,
        /** Kept, but cannot be read right now: present no identity until the next load. */
        UNAVAILABLE,
        /** Can never be presented again (does not parse, key gone or retired): cleared, re-enrollment needed. */
        DROPPED
    }

    /**
     * The keystore bundled with the app, presented from the Android Keystore:
     * its key is imported once per process (under an alias of its own, never
     * under the enrollment label — it is not an enrollment), so the key
     * manager holds a Keystore handle instead of the key itself. The bytes
     * the app bundled are the app's; see `clientKeystore(...)`.
     */
    private fun loadBundledKeystore() {
        val bundled = block.clientKeystoreBytes
        if (bundled == null) {
            sslManager.clearClientKeystore(includeHostCerts = false)
            return
        }
        val alias = ImportedClientKeys.aliasFor(BUNDLED_LABEL_PREFIX + block.id)
        try {
            val (key, chain) = ImportedIdentities.readP12(bundled, block.clientKeyPassword)
            val fingerprint = Pkcs10Csr.spkiSha256Base64(chain[0].publicKey)
            if (bundledImports[alias] != fingerprint || importedKeys.privateKey(alias) == null) {
                importedKeys.import(alias, key, chain)
                bundledImports[alias] = fingerprint
            }
            val imported = importedKeys.privateKey(alias) ?: throw IllegalStateException("imported key cannot be read back")
            sslManager.loadClientKey(imported, chain)
        } catch (e: Exception) {
            Timber.w(e, "ConfigApiClient[%s]: the bundled client keystore could not be imported into the Android Keystore — loading it as a PKCS12", block.id)
            sslManager.loadClientKeystore(bundled, block.clientKeyPassword)
        }
    }

    /**
     * Re-reads the stored credentials and rebuilds every client so the next
     * handshake presents them. Called after enroll, renew and unenroll.
     */
    fun reloadClientIdentity() {
        loadClientIdentity()
        (api as? DefaultCertificateConfigApi)?.rebuildBootstrapClient()
        clientProvider.currentConfig?.let { clientProvider.swap(it) }
    }

    /**
     * True when this block's Config API asks for a client certificate the
     * device does not have yet: the block names an `enrollmentUrl` (its own
     * URL is an mTLS listener) and no identity is loaded — nothing enrolled,
     * nothing bundled.
     */
    fun needsEnrollment(): Boolean = block.enrollmentUrl != null && sslManager.defaultClientCertificate() == null

    /**
     * Initial config load (from server or cache). Called during PinVault.init.
     * For static-pin offline mode this is bypassed at a higher level. A block
     * that [needsEnrollment] does not contact its backend.
     */
    suspend fun initializeAndUpdate(): InitResult {
        configurationError?.let { error ->
            Timber.e("ConfigApiClient[%s] refused: %s", block.id, error)
            return InitResult.Failed(reason = error, exception = IllegalStateException(error))
        }
        return updater.initializeAndUpdate(needsClientCertificate = needsEnrollment())
    }

    suspend fun updateNow(): UpdateResult {
        configurationError?.let { return UpdateResult.Failed(reason = it, exception = IllegalStateException(it)) }
        return updater.updateNow()
    }

    companion object {
        private const val BUNDLED_LABEL_PREFIX = "bundled_"

        /** Keystore alias → key fingerprint of the bundled keystore imported under it in this process. */
        private val bundledImports = java.util.concurrent.ConcurrentHashMap<String, String>()

        /** The decision behind the instance [loadEnrolledChain], apart from the SSL manager (unit tests). */
        internal fun loadEnrolledChain(
            certStore: ClientCertSecureStore,
            label: String,
            key: ClientIdentityKeyProvider,
            present: (java.security.PrivateKey, Array<java.security.cert.X509Certificate>) -> Unit
        ): EnrolledChain {
            val pems = certStore.loadChain(label)
                // The entry is there (mode is CHAIN) but did not read: a
                // Keystore failure of the non-strict store, not a missing
                // enrollment.
                ?: return unavailable(label, null)
            val chain = try {
                Pkcs10Csr.parsePemChain(pems).toTypedArray()
            } catch (e: Exception) {
                return drop(certStore, label, "does not parse", e)
            }
            val exists = try { key.exists() } catch (e: Exception) { return unavailable(label, e) }
            // The chain outlived its key (a restored backup, a wiped
            // Keystore): it cannot be presented, so start over.
            if (!exists) return drop(certStore, label, "has no Keystore key", null)
            return try {
                present(key.privateKey(), chain)
                EnrolledChain.LOADED
            } catch (e: Exception) {
                val gone = io.github.umutcansu.pinvault.keystore.UserAuthKeys.isRetired(e) ||
                    runCatching { !key.exists() }.getOrDefault(false)
                if (gone) drop(certStore, label, "has a retired or missing Keystore key", e) else unavailable(label, e)
            }
        }

        private fun drop(certStore: ClientCertSecureStore, label: String, why: String, e: Exception?): EnrolledChain {
            Timber.e(e, "Client cert [%s] %s — dropping it, re-enrollment needed", label, why)
            certStore.clear(label)
            return EnrolledChain.DROPPED
        }

        private fun unavailable(label: String, e: Exception?): EnrolledChain {
            Timber.e(e, "Client cert [%s] cannot be read right now (Keystore) — kept; no client certificate is presented until it can be", label)
            return EnrolledChain.UNAVAILABLE
        }

        /**
         * Why [block] must not be used with [customApi] (null = the library's
         * own HTTP client), or null when it is fine. On top of the block's own
         * rules ([ConfigApiBlock.configurationError]): a block with signing
         * keys looks signed, so its configs must be verified — a custom API
         * has to hand over signed envelopes ([SignedConfigSource]) or the
         * block has to say `allowUnsigned()`.
         */
        fun configurationError(block: ConfigApiBlock, customApi: CertificateConfigApi?): String? {
            block.configurationError()?.let { return it }
            val signed = block.effectiveSignatureKeys().isNotEmpty()
            return if (signed && customApi != null && customApi !is SignedConfigSource && !block.allowUnsigned) {
                "Config API '${block.id}' has signing keys, but its custom CertificateConfigApi cannot hand over " +
                    "signed configs, so nothing would be verified. Implement SignedConfigSource on it (PinVault " +
                    "then checks the signatures, issuedAt/expiresAt and key sets itself), or call allowUnsigned() " +
                    "on the block to accept unverified configs."
            } else {
                null
            }
        }
    }
}
