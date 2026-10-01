package io.github.umutcansu.pinvault.internal

import android.content.Context
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.api.DefaultCertificateConfigApi
import io.github.umutcansu.pinvault.crypto.Pkcs10Csr
import io.github.umutcansu.pinvault.crypto.SignatureTrust
import io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider
import io.github.umutcansu.pinvault.model.ConfigApiBlock
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import io.github.umutcansu.pinvault.ssl.HttpClientProvider
import io.github.umutcansu.pinvault.ssl.SSLCertificateUpdater
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
    private val identityKeyFactory: (label: String) -> ClientIdentityKeyProvider = { ClientIdentityKeyProvider.androidKeystore(it) }
) {
    val sslManager: DynamicSSLManager = DynamicSSLManager()
    val clientProvider: HttpClientProvider
    val configStore: CertificateConfigStore =
        CertificateConfigStore(context.applicationContext, CertificateConfigStore.prefsNameFor(block.id))
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

    /** True when the app supplied its own [CertificateConfigApi]: it verifies (or not) by itself. */
    val usesCustomApi: Boolean = customApi != null
    val api: CertificateConfigApi
    val updater: SSLCertificateUpdater
    val renewer: ClientCertRenewer

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
            enrollmentUrl = block.enrollmentUrl
        )

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
            deviceIdProvider = { DeviceIdentity.androidId(appContext) }
        )

        renewer = ClientCertRenewer(
            block = block,
            certStore = certStore,
            identityKeyFactory = identityKeyFactory,
            api = { api },
            reload = ::reloadClientIdentity
        )

        // Pin mismatch recovery hooks into this block's updater only.
        clientProvider.recoveryUpdater = suspend {
            val result = updater.updateNow()
            recoveryListener(result)
            result is UpdateResult.Updated
        }

        Timber.d("ConfigApiClient[%s] ready → %s", block.id, block.configUrl)
    }

    /** The identity key behind this block's client certificate. */
    fun identityKey(): ClientIdentityKeyProvider = identityKeyFactory(block.clientCertLabel)

    /**
     * Installs the block's client credentials into the SSL manager: the
     * enrolled credential under [ConfigApiBlock.clientCertLabel] — a
     * certificate chain over the device's Keystore key, or a server-made P12
     * — and, only when nothing is enrolled, the P12 bundled with the app
     * (`clientKeystore(...)`, the bootstrap identity for an mTLS Config API).
     */
    private fun loadClientIdentity() {
        val label = block.clientCertLabel
        when (certStore.mode(label)) {
            ClientCertSecureStore.Mode.CHAIN -> {
                val pems = certStore.loadChain(label)!!
                val key = identityKeyFactory(label)
                if (!key.exists()) {
                    // The chain outlived its key (a restored backup, a wiped
                    // Keystore): it cannot be presented, so start over.
                    Timber.w("Client cert [%s] has no Keystore key — dropping it, re-enrollment needed", label)
                    certStore.clear(label)
                    loadBundledKeystore()
                    return
                }
                try {
                    sslManager.loadClientKey(key.privateKey(), Pkcs10Csr.parsePemChain(pems).toTypedArray())
                } catch (e: Exception) {
                    Timber.e(e, "Client cert [%s] is unreadable — dropping it", label)
                    certStore.clear(label)
                    loadBundledKeystore()
                }
            }
            ClientCertSecureStore.Mode.P12 -> {
                val p12 = certStore.load(label)
                if (p12 != null) sslManager.loadClientKeystore(p12, block.clientKeyPassword) else loadBundledKeystore()
            }
            ClientCertSecureStore.Mode.NONE -> loadBundledKeystore()
        }
    }

    private fun loadBundledKeystore() {
        val bundled = block.clientKeystoreBytes
        if (bundled != null) {
            sslManager.loadClientKeystore(bundled, block.clientKeyPassword)
        } else {
            sslManager.clearClientKeystore(includeHostCerts = false)
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
    suspend fun initializeAndUpdate(): InitResult = updater.initializeAndUpdate(needsClientCertificate = needsEnrollment())

    suspend fun updateNow(): UpdateResult = updater.updateNow()
}
