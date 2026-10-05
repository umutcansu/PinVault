package com.example.pinvault.server.plugin

import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.respondText

/**
 * `CONFIG_API_ADMIN_ROUTES=off`: a Config API listener answers device
 * endpoints only. Everything that is not on the [isPublicEndpoint]
 * allowlist — pin writes, host and certificate changes, probes, vault
 * administration — is refused before the admin key is even looked at, so
 * a leaked `API_KEY` is of no use from the internet-facing ports:
 * administration happens on the management listener alone.
 *
 * Installed ahead of [ApiKeyAuth], so the refusal is the same whether or
 * not the request carried a key: the device ports give no oracle on keys.
 */
val DeviceOnlyRoutes = createApplicationPlugin("DeviceOnlyRoutes") {
    onCall { call ->
        if (isPublicEndpoint(call.request.path(), call.request.httpMethod)) return@onCall
        call.respondText(
            """{"error":"admin_routes_disabled","message":"This listener serves devices only; administration is on the management port (CONFIG_API_ADMIN_ROUTES=off)."}""",
            ContentType.Application.Json, HttpStatusCode.Forbidden
        )
    }
}
