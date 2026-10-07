package com.example.pinvault.server.plugin

import com.example.pinvault.server.service.PinAffectingRoutes
import io.ktor.http.HttpMethod
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.bodylimit.RequestBodyLimit
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path

/**
 * Caps the request bodies of the administrator endpoints: Ktor's
 * [RequestBodyLimit], with the limit chosen per request.
 *
 * The device endpoints ([isPublicEndpoint]) read through [ClientBodyLimit]
 * and its 64 KB cap; the vault upload reads up to `VAULT_MAX_FILE_BYTES`;
 * and, with approvals on, [ApprovalGate] reads an approved operation's body
 * up to the same caps. Every other admin route, though, read its JSON with
 * `call.receive<JsonObject>()` or `receiveText()` — without any limit, so a
 * leaked or misused admin key could have the server buffer whatever it was
 * sent. Now the whole listener refuses, with 413, a body above
 * `ADMIN_UPLOAD_MAX_BYTES` on those routes: a declared `Content-Length`
 * above the cap before anything runs, a longer streamed body while it is
 * read. No existing cap is lowered: the device cap is left to [ClientBodyLimit]
 * (unlimited here), the vault upload keeps its own.
 *
 * Installed after [ClientBodyLimit] and before [ApprovalGate]: the gate's
 * own capped read then runs through a channel limited to the same value.
 */
fun Application.installAdminBodyLimit(adminMaxBytes: Long, vaultMaxBytes: Long) {
    install(RequestBodyLimit) {
        bodyLimit { call -> adminBodyLimit(call.request.httpMethod, call.request.path(), adminMaxBytes, vaultMaxBytes) }
    }
}

/** The cap for [method] [path]: `Long.MAX_VALUE` = not this plugin's (a device endpoint). */
internal fun adminBodyLimit(method: HttpMethod, path: String, adminMaxBytes: Long, vaultMaxBytes: Long): Long = when {
    isPublicEndpoint(path, method) -> Long.MAX_VALUE
    PinAffectingRoutes.match(method, PinAffectingRoutes.canonicalPath(path)) == "vault_upload" -> vaultMaxBytes
    else -> adminMaxBytes
}
