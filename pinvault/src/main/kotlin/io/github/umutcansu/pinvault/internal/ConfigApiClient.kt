package io.github.umutcansu.pinvault.internal

import android.content.Context
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.api.DefaultCertificateConfigApi
import io.github.umutcansu.pinvault.model.ConfigApiBlock
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import io.github.umutcansu.pinvault.ssl.HttpClientProvider
import io.github.umutcansu.pinvault.ssl.SSLCertificateUpdater
import io.github.umutcansu.pinvault.store.CertificateConfigStore
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import timber.log.Timber

/**
 * A self-contained bundle of "everything we need to talk to one Config API":
 *  - dedicated SSLManager + OkHttp client (its own pin verification stack)
 *  - namespaced [CertificateConfigStore] so pins don't collide between APIs
 *  - [CertificateConfigApi] impl bound to this block's URL
 *  - [SSLCertificateUpdater] driving init + periodic refresh
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
    recoveryListener: (UpdateResult) -> Unit = { }
) {
    val sslManager: DynamicSSLManager = DynamicSSLManager()
    val clientProvider: HttpClientProvider
    val configStore: CertificateConfigStore =
        CertificateConfigStore(context.applicationContext, CertificateConfigStore.prefsNameFor(block.id))
    val certStore: ClientCertSecureStore = ClientCertSecureStore(context.applicationContext)
    val api: CertificateConfigApi
    val updater: SSLCertificateUpdater

    init {
        // mTLS: load client keystore for this block if available.
        val p12Bytes = block.clientKeystoreBytes ?: certStore.load(block.clientCertLabel)
        if (p12Bytes != null) {
            sslManager.loadClientKeystore(p12Bytes, block.clientKeyPassword)
        }

        clientProvider = HttpClientProvider(sslManager)

        api = customApi ?: DefaultCertificateConfigApi(
            configUrl = block.configUrl,
            configEndpoint = block.configEndpoint,
            healthEndpoint = block.healthEndpoint,
            clientCertEndpoint = block.clientCertEndpoint,
            enrollmentEndpoint = block.enrollmentEndpoint,
            vaultReportEndpoint = block.vaultReportEndpoint,
            signaturePublicKey = block.signaturePublicKey,
            bootstrapPins = block.bootstrapPins,
            sslManager = sslManager
        )

        updater = SSLCertificateUpdater(
            context = context.applicationContext,
            configApi = api,
            configStore = configStore,
            httpClientProvider = clientProvider,
            sslManager = sslManager,
            certStore = certStore,
            clientKeyPassword = block.clientKeyPassword,
            maxRetryCount = 3
        )

        // Pin mismatch recovery hooks into this block's updater only.
        clientProvider.recoveryUpdater = suspend {
            val result = updater.updateNow()
            recoveryListener(result)
            result is UpdateResult.Updated
        }

        Timber.d("ConfigApiClient[%s] ready → %s", block.id, block.configUrl)
    }

    /**
     * Initial config load (from server or cache). Called during PinVault.init.
     * For static-pin offline mode this is bypassed at a higher level.
     */
    suspend fun initializeAndUpdate(): InitResult = updater.initializeAndUpdate()

    suspend fun updateNow(): UpdateResult = updater.updateNow()
}
