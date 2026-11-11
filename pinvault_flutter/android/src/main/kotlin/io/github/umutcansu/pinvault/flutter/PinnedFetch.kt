package io.github.umutcansu.pinvault.flutter

import io.github.umutcansu.pinvault.model.HttpConnectionSettings
import okhttp3.Headers
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okio.Buffer
import okio.ByteString.Companion.decodeBase64
import java.io.IOException
import java.io.InterruptedIOException
import java.net.ProtocolException
import java.util.concurrent.TimeUnit

/** A `fetch(url, init)` from Dart, checked. */
internal class FetchRequest(
    val url: HttpUrl,
    val method: String,
    val headers: Headers,
    val body: ByteArray?,
    val responseEncoding: String,
    val timeoutMs: Long?,
    val maxResponseBytes: Long,
    val settings: HttpConnectionSettings?,
)

/** The response was larger than the request allowed. */
internal class ResponseTooLargeException(limit: Long) : IOException("Response larger than $limit bytes")

/**
 * The plugin's own `fetch`: parsed strictly, sent through the pinned client
 * the library hands out (`PinVault.getClient()` or `getClient(settings)`),
 * HTTPS only, bounded in both directions. A redirect from `https` into plain
 * `http` is not followed (the 3xx comes back), as on iOS. A redirect to
 * another host or port takes only [CROSS_ORIGIN_HEADERS] along and never a
 * body ([followUp]).
 */
internal object PinnedFetch {

    const val MAX_REQUEST_BYTES = 10L * 1024 * 1024
    const val DEFAULT_MAX_RESPONSE_BYTES = 10L * 1024 * 1024
    const val MAX_RESPONSE_BYTES = 50L * 1024 * 1024
    private val METHODS = setOf("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
    private val TOKEN = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}")

    /** The attestation headers: only the library sets them, for its token hosts (and a proof only it can sign). */
    val LIBRARY_HEADERS = listOf("PinVault-Token", "PinVault-Proof")

    /** The HTTP client's own headers: the host the URL names, the connection and the body's framing. */
    val CLIENT_HEADERS = listOf(
        "Host", "Connection", "Keep-Alive", "Proxy-Connection", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Content-Length",
    )

    /**
     * The only request headers that follow a redirect to another host or port
     * (lower case): what the client accepts and what it is. Everything else
     * the caller set was meant for the host it named.
     */
    val CROSS_ORIGIN_HEADERS = setOf("accept", "accept-language", "user-agent")

    /** As OkHttp's own limit. */
    const val MAX_FOLLOW_UPS = 20
    private val REDIRECT_CODES = setOf(300, 301, 302, 303, 307, 308)

    /** Why a caller may not set request header [name], or null when it may: the library's and the HTTP client's own. */
    fun refusedHeader(name: String): String? = when {
        LIBRARY_HEADERS.any { it.equals(name, ignoreCase = true) } -> "set by PinVault itself (a token host's requests carry it)"
        CLIENT_HEADERS.any { it.equals(name, ignoreCase = true) } -> "set by the HTTP client (host, connection and framing headers)"
        else -> null
    }

    /**
     * [refusedHeader] for a WebSocket's upgrade request, which is an HTTP
     * request like any other (a caller's `Host` would name another site on the
     * pinned connection), plus the handshake's own `Sec-WebSocket-*` headers.
     */
    fun refusedSocketHeader(name: String): String? = refusedHeader(name)
        ?: if (name.startsWith("Sec-WebSocket-", ignoreCase = true)) "set by the WebSocket handshake" else null

    const val MAX_SOCKET_PROTOCOLS = 8
    const val MAX_SOCKET_PROTOCOL_LENGTH = 64

    /**
     * A WebSocket's subprotocols as the caller listed them, checked: the
     * bridge writes `Sec-WebSocket-Protocol` from this list itself (the header
     * is refused from the caller, [refusedSocketHeader]). Each entry is an
     * RFC 7230 token — so no comma, space or control character can add a
     * second value or a second header — of bounded length, and none twice
     * (RFC 6455 §4.1).
     */
    fun socketProtocols(raw: List<*>?): List<String> {
        if (raw == null) return emptyList()
        if (raw.size > MAX_SOCKET_PROTOCOLS) throw BridgeInputException("protocols: at most $MAX_SOCKET_PROTOCOLS")
        val seen = HashSet<String>()
        return raw.map { entry ->
            if (entry !is String || entry.length > MAX_SOCKET_PROTOCOL_LENGTH || !TOKEN.matches(entry)) {
                throw BridgeInputException("protocols: each must be a token (RFC 7230) of at most $MAX_SOCKET_PROTOCOL_LENGTH characters")
            }
            if (!seen.add(entry)) throw BridgeInputException("protocols: '$entry' is listed twice")
            entry
        }
    }

    fun parse(json: String): FetchRequest {
        // Base64 inflates by 4/3; leave room for the other fields.
        val f = StrictJson.parseObject(json, "request", maxChars = (MAX_REQUEST_BYTES * 4 / 3 + 64 * 1024).toInt())
        val urlText = f.requireString("url", 8192)
        val url = urlText.toHttpUrlOrNull() ?: throw BridgeInputException("request.url: not a valid URL")
        if (!url.isHttps) throw BridgeInputException("request.url: only https:// URLs go through the pinned client")
        val method = (f.string("method", 16) ?: "GET").uppercase()
        if (method !in METHODS) throw BridgeInputException("request.method: '$method' is not supported")
        val headers = Headers.Builder()
        f.stringMap("headers", 128, 256, 8192)?.forEach { (name, value) ->
            if (!TOKEN.matches(name)) throw BridgeInputException("request.headers: '${name.take(40)}' is not a header name")
            refusedHeader(name)?.let { why -> throw BridgeInputException("request.headers.$name: $why") }
            if (value.any { it == '\r' || it == '\n' || it.code == 0 }) {
                throw BridgeInputException("request.headers.$name: line breaks are not allowed")
            }
            headers.add(name, value)
        }
        val bodyText = f.text("body", (MAX_REQUEST_BYTES * 4 / 3 + 4).toInt())
        val bodyEncoding = ResultMapper.checkEncoding(f.string("bodyEncoding", 16) ?: ResultMapper.UTF8)
        val body = bodyText?.let {
            if (bodyEncoding == ResultMapper.BASE64) {
                it.decodeBase64()?.toByteArray() ?: throw BridgeInputException("request.body: not valid Base64")
            } else {
                it.toByteArray(Charsets.UTF_8)
            }
        }
        if (body != null && body.size > MAX_REQUEST_BYTES) throw BridgeInputException("request.body: larger than $MAX_REQUEST_BYTES bytes")
        if (body != null && (method == "GET" || method == "HEAD")) throw BridgeInputException("request.body: $method has no body")
        val responseEncoding = ResultMapper.checkEncoding(f.string("responseEncoding", 16) ?: ResultMapper.UTF8)
        val timeoutMs = f.long("timeoutMs", 1, 10 * 60 * 1000L)
        val maxResponse = f.long("maxResponseBytes", 1, MAX_RESPONSE_BYTES) ?: DEFAULT_MAX_RESPONSE_BYTES
        val settings = f.obj("settings")?.let { s ->
            val d = HttpConnectionSettings()
            val parsed = HttpConnectionSettings(
                connectTimeout = s.long("connectTimeout", 0, 600) ?: d.connectTimeout,
                readTimeout = s.long("readTimeout", 0, 600) ?: d.readTimeout,
                writeTimeout = s.long("writeTimeout", 0, 600) ?: d.writeTimeout,
                callTimeout = s.long("callTimeout", 0, 600) ?: d.callTimeout,
            )
            s.finish()
            parsed
        }
        f.finish()
        return FetchRequest(url, method, headers.build(), body, responseEncoding, timeoutMs, maxResponse, settings)
    }

    /** Runs [request] on [client] (a pinned client from the library); blocking. */
    fun execute(client: OkHttpClient, request: FetchRequest): Map<String, Any?> {
        // newBuilder shares the pool, the pinned socket factory and the
        // library's interceptors. Redirects are followed here, not by OkHttp:
        // OkHttp sends every header but Authorization — and the body of a
        // 307/308 — to whatever host the Location names (see followUp).
        val callClient = client.newBuilder().followRedirects(false).followSslRedirects(false).build()
        val contentType = request.headers["Content-Type"]?.toMediaTypeOrNull()
        val body = when {
            request.body != null -> request.body.toRequestBody(contentType)
            request.method in setOf("POST", "PUT", "PATCH") -> ByteArray(0).toRequestBody(contentType)
            else -> null
        }
        var okRequest = Request.Builder().url(request.url).headers(request.headers).method(request.method, body).build()
        // One time limit for the whole exchange, redirects included, as when OkHttp followed them.
        val deadline = request.timeoutMs?.let { System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(it) }
        var followUps = 0
        while (true) {
            val call = callClient.newCall(okRequest)
            if (deadline != null) {
                val left = deadline - System.nanoTime()
                if (left <= 0) throw InterruptedIOException("timeout")
                call.timeout().timeout(left, TimeUnit.NANOSECONDS)
            }
            val response = call.execute()
            // A client the app told not to follow redirects still does not.
            val next = if (client.followRedirects) followUp(okRequest, response) else null
            if (next == null) return read(response, request)
            response.close()
            followUps++
            if (followUps > MAX_FOLLOW_UPS) throw ProtocolException("Too many follow-up requests: $followUps")
            okRequest = next
        }
    }

    /**
     * The next request for a 3xx, or null when [response] is the answer.
     * Built from [sent] — the request as this class made it, not as the
     * library's interceptors completed it: what they add (the attestation
     * token of a token host) is added again for the next hop, for its host.
     *
     * To the same host and port everything goes along, as OkHttp does it
     * (301/302/303 turn a POST into a GET; 307/308 repeat method and body).
     * To another host or port only [CROSS_ORIGIN_HEADERS] go along — a fixed
     * list of credential names would miss an app's own session or API-key
     * header — and a body is not sent again: a 307/308 that would repeat it
     * there is the answer. A redirect into plain `http` is never followed.
     */
    internal fun followUp(sent: Request, response: Response): Request? {
        if (response.code !in REDIRECT_CODES) return null
        val location = response.header("Location") ?: return null
        val target = sent.url.resolve(location) ?: return null
        if (!target.isHttps) return null
        val next = sent.newBuilder().url(target)
        var repeatsBody = false
        if (sent.method != "GET" && sent.method != "HEAD") {
            if (response.code == 307 || response.code == 308) {
                repeatsBody = (sent.body?.contentLength() ?: 0L) != 0L
            } else {
                next.method("GET", null)
                listOf("Transfer-Encoding", "Content-Length", "Content-Type").forEach { next.removeHeader(it) }
            }
        }
        val sameOrigin = target.host == sent.url.host && target.port == sent.url.port
        if (!sameOrigin) {
            if (repeatsBody) return null
            sent.headers.names().filter { it.lowercase() !in CROSS_ORIGIN_HEADERS }.forEach { next.removeHeader(it) }
        }
        return next.build()
    }

    /** Reads [response] under the request's size limit and maps it for the bridge; closes it. */
    private fun read(response: Response, request: FetchRequest): Map<String, Any?> {
        response.use {
            val responseBody = response.body
            val declared = responseBody?.contentLength() ?: -1L
            if (declared > request.maxResponseBytes) throw ResponseTooLargeException(request.maxResponseBytes)
            val buffer = Buffer()
            if (responseBody != null) {
                val source = responseBody.source()
                while (true) {
                    val read = source.read(buffer, 64 * 1024L)
                    if (read == -1L) break
                    if (buffer.size > request.maxResponseBytes) throw ResponseTooLargeException(request.maxResponseBytes)
                }
            }
            val bytes = buffer.readByteArray()
            val headers = LinkedHashMap<String, String>()
            response.headers.names().forEach { name ->
                headers[name.lowercase()] = response.headers.values(name).joinToString(", ")
            }
            return mapOf(
                "status" to response.code,
                "url" to response.request.url.toString(),
                "headers" to headers,
                "body" to ResultMapper.encode(bytes, request.responseEncoding),
                "bodyEncoding" to request.responseEncoding,
            )
        }
    }
}
