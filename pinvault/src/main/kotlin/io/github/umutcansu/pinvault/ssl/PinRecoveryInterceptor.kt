package io.github.umutcansu.pinvault.ssl

import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import timber.log.Timber
import java.io.IOException
import java.security.cert.CertificateException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException

/**
 * OkHttp Application Interceptor that catches SSL pin mismatch errors
 * and automatically fetches updated pins, then retries the request.
 *
 * Flow:
 * 1. Request fails with SSL exception (pin mismatch)
 * 2. Triggers updater to fetch new pins from server
 * 3. If update succeeds → retries request with new client
 * 4. If update fails → throws original exception
 */
internal class PinRecoveryInterceptor(
    private val updater: () -> Boolean,
    private val newClientProvider: () -> okhttp3.OkHttpClient
) : Interceptor {

    private val lock = Any()

    override fun intercept(chain: Interceptor.Chain): Response {
        return try {
            chain.proceed(chain.request())
        } catch (e: IOException) {
            if (!isPinMismatch(e)) throw e

            Timber.w("Pin mismatch detected — attempting auto-recovery")

            val updated = synchronized(lock) { updater() }

            if (!updated) {
                Timber.e("Auto-recovery failed — update unsuccessful")
                throw e
            }

            Timber.d("Pins updated — retrying request with new client")
            retryWithNewClient(chain.request())
        }
    }

    private fun retryWithNewClient(request: Request): Response {
        val newClient = newClientProvider()
        return newClient.newCall(request).execute()
    }

    private fun isPinMismatch(e: IOException): Boolean {
        return e is SSLPeerUnverifiedException ||
            e is SSLHandshakeException && (
                e.cause is CertificateException ||
                e.message?.contains("Certificate pinning") == true
            )
    }
}
