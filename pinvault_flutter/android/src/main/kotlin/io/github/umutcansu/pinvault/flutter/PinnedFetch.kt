package io.github.umutcansu.pinvault.flutter

import io.github.umutcansu.pinvault.model.HttpConnectionSettings
import okhttp3.Headers
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okio.Buffer
import okio.ByteString.Companion.decodeBase64
import java.io.IOException
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
 * `http` is not followed (the 3xx comes back), as on iOS.
 */
internal object PinnedFetch {

    const val MAX_REQUEST_BYTES = 10L * 1024 * 1024
    const val DEFAULT_MAX_RESPONSE_BYTES = 10L * 1024 * 1024
    const val MAX_RESPONSE_BYTES = 50L * 1024 * 1024
    private val METHODS = setOf("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
    private val TOKEN = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}")

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
        // library's interceptors; it only stops https → http redirects.
        val callClient = client.newBuilder().followSslRedirects(false).build()
        val contentType = request.headers["Content-Type"]?.toMediaTypeOrNull()
        val body = when {
            request.body != null -> request.body.toRequestBody(contentType)
            request.method in setOf("POST", "PUT", "PATCH") -> ByteArray(0).toRequestBody(contentType)
            else -> null
        }
        val okRequest = Request.Builder().url(request.url).headers(request.headers).method(request.method, body).build()
        val call = callClient.newCall(okRequest)
        request.timeoutMs?.let { call.timeout().timeout(it, TimeUnit.MILLISECONDS) }
        call.execute().use { response ->
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
