package com.example.pinvault.server.plugin

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.request.header
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.respondText

/**
 * Caps request bodies on the endpoints devices reach without an admin key.
 *
 * Those routes read the whole body (`receiveText`) before checking anything,
 * yet need a few hundred bytes at most — a CSR, a public key, a report. With
 * no cap, one request made the server buffer whatever it was sent: 100 MB was
 * read in full and only then refused with a 400, and the recovery door's rate
 * limit runs after that read too. A declared length above
 * [ClientBodyLimitConfig.maxBytes] is now refused with 413 before the body is
 * read, and a body without a declared length (chunked) with 411: the library
 * always sends a length for these requests.
 *
 * Admin endpoints (vault uploads) are not covered; they need an admin key.
 */
class ClientBodyLimitConfig {
    var maxBytes: Long = 64L * 1024

    /** Which requests are capped; default: the endpoints open to devices ([isPublicEndpoint]). */
    var appliesTo: (path: String, method: HttpMethod) -> Boolean = { path, method -> isPublicEndpoint(path, method) }
}

val ClientBodyLimit = createApplicationPlugin(name = "ClientBodyLimit", ::ClientBodyLimitConfig) {
    val maxBytes = pluginConfig.maxBytes
    val appliesTo = pluginConfig.appliesTo

    onCall { call ->
        val method = call.request.httpMethod
        if (method != HttpMethod.Post && method != HttpMethod.Put && method != HttpMethod.Patch) return@onCall
        if (!appliesTo(call.request.path(), method)) return@onCall

        val declared = call.request.header(HttpHeaders.ContentLength)?.toLongOrNull()
        when {
            declared == null && call.request.header(HttpHeaders.TransferEncoding) != null ->
                call.respondText(
                    """{"error":"length_required","message":"Send a Content-Length of at most $maxBytes bytes."}""",
                    ContentType.Application.Json, HttpStatusCode.LengthRequired
                )
            declared != null && declared > maxBytes ->
                call.respondText(
                    """{"error":"body_too_large","message":"At most $maxBytes bytes."}""",
                    ContentType.Application.Json, HttpStatusCode.PayloadTooLarge
                )
        }
    }
}
