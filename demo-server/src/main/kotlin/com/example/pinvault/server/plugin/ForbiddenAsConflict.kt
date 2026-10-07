package com.example.pinvault.server.plugin

import io.ktor.http.ContentType
import io.ktor.http.Headers
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.application.hooks.ResponseBodyReadyForSend
import io.ktor.server.request.header
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel

/**
 * Sends a `403` as `409` (with `X-PinVault-Status: 403`) to a client that asks
 * for it with `X-PinVault-Features: forbidden-as-409`, on listeners that ask
 * for a client certificate.
 *
 * Why: on a connection where the server requested a client certificate,
 * Apple's URL loading system turns every HTTP 403 into a "client certificate
 * required" error (NSURLErrorClientCertificateRequired, -1206) and drops the
 * response. An iPhone would never see `403 {"error":"reenroll_required"}`, a
 * revoked identity, or why a vault file was refused — only a TLS failure. The
 * body is unchanged and the original status travels in the header, so the
 * iOS library reads the answer as the 403 it is. Clients that do not ask
 * (Android, curl, every other caller) get the 403 exactly as before.
 */
val ForbiddenAsConflict = createApplicationPlugin(name = "ForbiddenAsConflict") {
    on(ResponseBodyReadyForSend) { call, content ->
        val status = content.status ?: call.response.status()
        if (status != HttpStatusCode.Forbidden || !wantsForbiddenAsConflict(call.request.header(FEATURES_HEADER))) return@on
        call.response.status(HttpStatusCode.Conflict)
        call.response.headers.append(ORIGINAL_STATUS_HEADER, "403", safeOnly = false)
        transformBodyTo(withConflictStatus(content))
    }
}

/** The request header the library lists its features in. */
const val FEATURES_HEADER = "X-PinVault-Features"

/** The feature that asks for [ForbiddenAsConflict]. */
const val FORBIDDEN_AS_CONFLICT_FEATURE = "forbidden-as-409"

/** Carries the status a remapped response really has. */
const val ORIGINAL_STATUS_HEADER = "X-PinVault-Status"

internal fun wantsForbiddenAsConflict(features: String?): Boolean =
    features.orEmpty().split(',').any { it.trim().equals(FORBIDDEN_AS_CONFLICT_FEATURE, ignoreCase = true) }

/** [content] with its status replaced by 409; body, type and headers as they were. */
private fun withConflictStatus(content: OutgoingContent): OutgoingContent = when (content) {
    is OutgoingContent.ByteArrayContent -> object : OutgoingContent.ByteArrayContent() {
        private val bytes = content.bytes()
        override val status = HttpStatusCode.Conflict
        override val contentType: ContentType? = content.contentType
        override val contentLength: Long = bytes.size.toLong()
        override val headers: Headers = content.headers
        override fun bytes(): ByteArray = bytes
    }
    is OutgoingContent.ReadChannelContent -> object : OutgoingContent.ReadChannelContent() {
        override val status = HttpStatusCode.Conflict
        override val contentType: ContentType? = content.contentType
        override val contentLength: Long? = content.contentLength
        override val headers: Headers = content.headers
        override fun readFrom(): ByteReadChannel = content.readFrom()
    }
    is OutgoingContent.WriteChannelContent -> object : OutgoingContent.WriteChannelContent() {
        override val status = HttpStatusCode.Conflict
        override val contentType: ContentType? = content.contentType
        override val contentLength: Long? = content.contentLength
        override val headers: Headers = content.headers
        override suspend fun writeTo(channel: ByteWriteChannel) = content.writeTo(channel)
    }
    is OutgoingContent.NoContent -> object : OutgoingContent.NoContent() {
        override val status = HttpStatusCode.Conflict
        override val contentType: ContentType? = content.contentType
        override val contentLength: Long? = content.contentLength
        override val headers: Headers = content.headers
    }
    // A protocol upgrade is never a 403.
    else -> content
}
