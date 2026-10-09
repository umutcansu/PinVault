package io.github.umutcansu.pinvault.api

import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import timber.log.Timber

/**
 * Where the token interceptor gets its tokens: one per attesting Config API
 * block (`AttestationManager`). Kept as an interface so the interceptor can
 * be tested without a manager.
 */
internal interface AttestationTokenSource {
    /** True when requests to [host]:[port] carry this source's token. */
    fun handlesHost(host: String, port: Int): Boolean

    /**
     * The token for [host]:[port], or null when none can be had right now.
     * Without [forceRefresh] a held token with enough life left is returned
     * as it is; otherwise the source attests once (synchronously, bounded by
     * its single flight and its backoff) and returns what that brought.
     */
    fun token(host: String, port: Int, forceRefresh: Boolean): String?

    /**
     * The `PinVault-Proof` for [method] [url] carrying [token] (`ATTESTATION.md`
     * §5.1), or null when this source sends none (no `proofOfPossession()`,
     * or the device key cannot sign right now).
     */
    fun proof(method: String, url: okhttp3.HttpUrl, token: String): String? = null
}

/**
 * Application interceptor that adds `PinVault-Token` to requests whose host
 * is a token host of an attesting block (`ATTESTATION.md` §8), on every
 * client the library builds or configures.
 *
 * With `proofOfPossession()` each such request also carries a
 * `PinVault-Proof` made for it (`ATTESTATION.md` §5.1), and the retry a new one.
 *
 * Without a valid token it attests once, synchronously, and sends the
 * request without the header when that fails — the backend refuses it the
 * way it refuses any request without a token. A `401` that names the token
 * (`WWW-Authenticate` containing `PinVault-Token`, or a body naming
 * `invalid_token`) forces one re-attestation and one retry, tagged
 * [AttestationRetry] so the retry never retries again. Requests whose body
 * can be sent once only are not retried.
 */
internal class AttestationTokenInterceptor(
    private val sources: () -> List<AttestationTokenSource>
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        if (request.tag(AttestationRetry::class.java) != null) return chain.proceed(request)

        val host = request.url.host
        val port = request.url.port
        val source = sources().firstOrNull { it.handlesHost(host, port) } ?: return chain.proceed(request)

        val token = source.token(host, port, forceRefresh = false)
        val first = if (token != null) withToken(request, source, token) else request
        val response = chain.proceed(first)
        if (response.code != 401 || !namesToken(response)) return response

        if (request.body?.isOneShot() == true) {
            Timber.w("%s refused the token for %s, but the request body can be sent once only — not retried", HEADER, host)
            return response
        }
        val fresh = source.token(host, port, forceRefresh = true)
        if (fresh == null || fresh == token) {
            Timber.w("%s refused for %s and no new token could be had — returning the 401", HEADER, host)
            return response
        }
        response.close()
        Timber.d("%s refused for %s — re-attested, retrying once", HEADER, host)
        val retry = withToken(request, source, fresh).newBuilder()
            .tag(AttestationRetry::class.java, AttestationRetry)
            .build()
        return chain.proceed(retry)
    }

    /** [request] with [token] and, when the source makes one, a proof for this request and token. */
    private fun withToken(request: Request, source: AttestationTokenSource, token: String): Request {
        val builder = request.newBuilder().header(HEADER, token)
        val proof = try {
            source.proof(request.method, request.url, token)
        } catch (e: Exception) {
            Timber.w(e, "%s could not be made for %s — sent without", PROOF_HEADER, request.url.host)
            null
        }
        if (proof != null) builder.header(PROOF_HEADER, proof)
        return builder.build()
    }

    /** True when a 401 is about the token: the challenge header names it, or the body says `invalid_token`. */
    private fun namesToken(response: Response): Boolean {
        if (response.headers(WWW_AUTHENTICATE).any { it.contains(HEADER, ignoreCase = true) }) return true
        return try {
            response.peekBody(MAX_PEEK_BYTES).string().contains(INVALID_TOKEN)
        } catch (_: Exception) {
            false
        }
    }

    companion object {
        /** The request header the token travels in. */
        const val HEADER = "PinVault-Token"
        /** The request header the proof travels in. */
        const val PROOF_HEADER = io.github.umutcansu.pinvault.internal.TokenProof.HEADER
        private const val WWW_AUTHENTICATE = "WWW-Authenticate"
        private const val INVALID_TOKEN = "invalid_token"
        private const val MAX_PEEK_BYTES = 8L * 1024
    }
}

/** Marks the one retry after a forced re-attestation, so it does not start another. */
internal object AttestationRetry
