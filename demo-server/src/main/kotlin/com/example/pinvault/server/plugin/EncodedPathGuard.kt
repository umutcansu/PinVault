package com.example.pinvault.server.plugin

import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.request.path
import io.ktor.server.response.respondText

/**
 * Refuses (400) a request whose path, as sent, hides a separator or a dot in
 * an escape: `%2F`, `%5C`, `%2E`, `%25` (any case), or a literal backslash.
 *
 * Routing decodes each segment AFTER splitting the path, so
 * `/api/v1/config/x%2Fy/update` reached the `{configApiId}` handler while
 * anything that reads the path as a whole (the approval gate, the audit
 * target, the ApiKeyAuth allowlist) saw a different shape — and with a
 * `?configApiId=` next to it the handler wrote another scope's pins without
 * approval. No PinVault id, host name or vault key needs one of these
 * escapes, so nothing legitimate is refused. `%25` goes too: decoded twice
 * anywhere, it becomes one of the others.
 *
 * Install it on every listener, before any plugin that decides on the path.
 */
val EncodedPathGuard = createApplicationPlugin(name = "EncodedPathGuard") {
    onCall { call ->
        if (!isAmbiguousPath(call.request.path())) return@onCall
        call.respondText(
            """{"error":"invalid_path","message":"Encoded '/', '\\', '.' or '%' and backslashes are not accepted in the path."}""",
            ContentType.Application.Json, HttpStatusCode.BadRequest
        )
    }
}

private val AMBIGUOUS_ESCAPE = Regex("%(2[fFeE5]|5[cC])")

/** Whether the raw (undecoded) [path] carries an escape [EncodedPathGuard] refuses. */
fun isAmbiguousPath(path: String): Boolean = '\\' in path || AMBIGUOUS_ESCAPE.containsMatchIn(path)
