package com.example.pinvault.server.plugin

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.application.hooks.ReceiveRequestBytes
import io.ktor.server.request.header
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.request.receiveChannel
import io.ktor.server.response.respondText
import io.ktor.util.AttributeKey
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writer
import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/**
 * Caps request bodies on the endpoints devices reach without an admin key.
 *
 * Those routes read the whole body before checking anything, yet need a few
 * hundred bytes at most — a CSR, a public key, a report. With no cap, one
 * request made the server buffer whatever it was sent: 100 MB was read in full
 * and only then refused with a 400, and the recovery door's rate limit runs
 * after that read too. A declared length above [ClientBodyLimitConfig.maxBytes]
 * is refused with 413 before the body is read, and a chunked body without a
 * declared length with 411: the library always sends a length for these
 * requests.
 *
 * Headers are not enough: over HTTP/2 a body needs neither `Content-Length`
 * nor `Transfer-Encoding`, and such a request passed both checks and was read
 * whole. So the cap is also enforced while reading: whatever a capped route
 * receives — however it receives it — is cut off one byte past the cap, and
 * the device routes read through [receiveLimitedText] / [receiveLimitedJson],
 * which answer 413 for a body that long.
 *
 * Admin endpoints are not covered (they need an admin key); vault uploads have
 * their own cap, `VAULT_MAX_FILE_BYTES`.
 */
class ClientBodyLimitConfig {
    var maxBytes: Long = DEFAULT_CLIENT_BODY_MAX_BYTES

    /** Which requests are capped; default: the endpoints open to devices ([isPublicEndpoint]). */
    var appliesTo: (path: String, method: HttpMethod) -> Boolean = { path, method -> isPublicEndpoint(path, method) }
}

/** The cap on a device request body unless the plugin is configured otherwise. */
const val DEFAULT_CLIENT_BODY_MAX_BYTES: Long = 64L * 1024

/**
 * The cap on an administrator's JSON body or upload (a keystore, a
 * certificate) unless `ADMIN_UPLOAD_MAX_BYTES` says otherwise: 1 MB. These are
 * read into memory whole — and, with two-person approval, stored with the
 * change request — so "an admin sent it" is no reason to read without limit.
 * Vault files have their own, larger cap (`VAULT_MAX_FILE_BYTES`).
 */
const val DEFAULT_ADMIN_BODY_MAX_BYTES: Long = 1L * 1024 * 1024

/** The cap [ClientBodyLimit] put on this call; absent on calls it does not cover. */
private val ClientBodyMaxKey = AttributeKey<Long>("PinVaultClientBodyMax")

val ClientBodyLimit = createApplicationPlugin(name = "ClientBodyLimit", ::ClientBodyLimitConfig) {
    val maxBytes = pluginConfig.maxBytes
    val appliesTo = pluginConfig.appliesTo

    onCall { call ->
        val method = call.request.httpMethod
        if (method != HttpMethod.Post && method != HttpMethod.Put && method != HttpMethod.Patch) return@onCall
        if (!appliesTo(call.request.path(), method)) return@onCall
        call.attributes.put(ClientBodyMaxKey, maxBytes)
        // Another plugin already answered (a cut-off address, a cleartext connection).
        if (call.response.isCommitted) return@onCall

        val declared = call.request.header(HttpHeaders.ContentLength)?.toLongOrNull()
        when {
            declared == null && call.request.header(HttpHeaders.TransferEncoding) != null ->
                call.respondText(
                    """{"error":"length_required","message":"Send a Content-Length of at most $maxBytes bytes."}""",
                    ContentType.Application.Json, HttpStatusCode.LengthRequired
                )
            declared != null && declared > maxBytes -> call.respondBodyTooLarge(maxBytes)
        }
    }

    // Whatever reads the body of a capped call gets at most one byte more than
    // the cap, enough for the reader to tell "too long" from "exactly the cap".
    on(ReceiveRequestBytes) { call, body ->
        val cap = call.attributes.getOrNull(ClientBodyMaxKey) ?: return@on body
        call.writer(Dispatchers.Unconfined) {
            val buffer = ByteArray(COPY_BUFFER_BYTES)
            var left = cap + 1
            while (left > 0) {
                val read = body.readAvailable(buffer, 0, minOf(buffer.size.toLong(), left).toInt())
                if (read < 0) break
                if (read == 0) {
                    if (!body.awaitContent()) break
                    continue
                }
                channel.writeFully(buffer, 0, read)
                left -= read
            }
        }.channel
    }
}

private const val COPY_BUFFER_BYTES = 8 * 1024

private suspend fun ApplicationCall.respondBodyTooLarge(maxBytes: Long) = respondText(
    """{"error":"body_too_large","message":"At most $maxBytes bytes."}""",
    ContentType.Application.Json, HttpStatusCode.PayloadTooLarge
)

/**
 * The request body, read from the channel up to [maxBytes]. A longer one —
 * declared or not — is answered with 413 and null is returned: the caller
 * stops. Never holds more than `maxBytes` + one buffer in memory, whatever
 * the headers said (see [ClientBodyLimit]).
 */
suspend fun ApplicationCall.receiveLimitedBytes(
    maxBytes: Long = attributes.getOrNull(ClientBodyMaxKey) ?: DEFAULT_CLIENT_BODY_MAX_BYTES
): ByteArray? {
    val declared = request.header(HttpHeaders.ContentLength)?.toLongOrNull()
    if (declared != null && declared > maxBytes) {
        respondBodyTooLarge(maxBytes)
        return null
    }
    val channel: ByteReadChannel = receiveChannel()
    // A declared length sizes the buffer, up to 1 MB: a header is a claim, not bytes received.
    val out = java.io.ByteArrayOutputStream(declared?.coerceIn(0, minOf(maxBytes, 1L shl 20))?.toInt() ?: COPY_BUFFER_BYTES)
    val buffer = ByteArray(COPY_BUFFER_BYTES)
    while (true) {
        val read = channel.readAvailable(buffer, 0, buffer.size)
        if (read < 0) break
        if (read == 0) {
            if (!channel.awaitContent()) break
            continue
        }
        out.write(buffer, 0, read)
        if (out.size() > maxBytes) {
            respondBodyTooLarge(maxBytes)
            return null
        }
    }
    return out.toByteArray()
}

/** [receiveLimitedBytes] as UTF-8 text; null after a 413. */
suspend fun ApplicationCall.receiveLimitedText(
    maxBytes: Long = attributes.getOrNull(ClientBodyMaxKey) ?: DEFAULT_CLIENT_BODY_MAX_BYTES
): String? = receiveLimitedBytes(maxBytes)?.toString(Charsets.UTF_8)

/**
 * The request body as a JSON object, read through [receiveLimitedText]. Null
 * after a 413 (too long) or a 400 `invalid_json` (not a JSON object): the
 * caller stops.
 */
suspend fun ApplicationCall.receiveLimitedJson(
    maxBytes: Long = attributes.getOrNull(ClientBodyMaxKey) ?: DEFAULT_CLIENT_BODY_MAX_BYTES
): JsonObject? {
    val text = receiveLimitedText(maxBytes) ?: return null
    val json = try { Json.parseToJsonElement(text) as? JsonObject } catch (_: Exception) { null }
    if (json == null) {
        respondText("""{"error":"invalid_json","message":"The body must be a JSON object."}""",
            ContentType.Application.Json, HttpStatusCode.BadRequest)
    }
    return json
}
