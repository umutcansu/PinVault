package io.github.umutcansu.pinvault.api

import okhttp3.Interceptor
import okhttp3.Response
import timber.log.Timber

/**
 * Spots the server's "this identity is revoked" answer on any request of a
 * Config API — config, scoped config, vault files, device key registration,
 * reports — not only on renewal.
 *
 * An mTLS listener answers a revoked identity `403 {"error":"reenroll_required"}`
 * on every request. Only the renewal endpoint used to read it, so a revoked
 * device kept running on its stored config until its renewal came due.
 *
 * The listener also gets the client certificate the connection presented
 * (from the TLS handshake of the response), or null when it presented none.
 * The answer itself is not signed: what may follow from it depends on
 * whether the server was looking at this device's identity when it gave it
 * (see `ConfigApiClient`: vault files are wiped only then).
 *
 * The response goes on untouched: the body is peeked, not consumed.
 */
internal class ReenrollRequiredInterceptor(
    private val onReenrollRequired: (reason: String, presented: java.security.cert.X509Certificate?) -> Unit
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val response = chain.proceed(chain.request())
        if (response.code == 403) {
            reenrollReason(response)?.let { reason ->
                try {
                    val presented = response.handshake?.localCertificates?.firstOrNull() as? java.security.cert.X509Certificate
                    onReenrollRequired(reason, presented)
                } catch (e: Exception) {
                    Timber.w(e, "reenroll_required listener threw — ignoring")
                }
            }
        }
        return response
    }

    /** The server's message when [response] says `reenroll_required`; null for any other 403. */
    private fun reenrollReason(response: Response): String? = try {
        val json = org.json.JSONObject(response.peekBody(MAX_PEEK_BYTES).string())
        if (json.optString("error") == REENROLL_REQUIRED) {
            json.optString("message").ifBlank { REENROLL_REQUIRED }
        } else {
            null
        }
    } catch (_: Exception) {
        null
    }

    private companion object {
        const val MAX_PEEK_BYTES = 8L * 1024
    }
}
