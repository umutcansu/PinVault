package com.example.pinvault.server.plugin

import com.example.pinvault.server.route.isValidIdentifier
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.calllogging.CallLogging
import io.ktor.server.plugins.calllogging.processingTimeMillis
import io.ktor.server.plugins.origin
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import org.slf4j.LoggerFactory

/**
 * One line per device request on a Config API listener (and the recovery
 * door): listener, status, method, path, client address, device id, time.
 *
 *     ConfigApiAccess - [default-tls :8091] 200 OK GET /api/v1/certificate-config from 203.0.113.7 device=6f1c2b6a in 4ms
 *
 * The path is logged without its query string, and the device id only when it
 * is a well-formed identifier (`X-Device-Id`): nothing a caller sends can add
 * a line or a token to the log. The address is `origin` — the client behind a
 * trusted proxy ([TrustedProxies]). `/health` is left out (load balancers and
 * tunnels poll it). Logger `ConfigApiAccess`: `LOG_LEVEL_CONFIG_API_ACCESS=OFF`
 * turns it off (logback.xml).
 */
fun Application.installRequestLog(listener: String) {
    install(CallLogging) {
        logger = LoggerFactory.getLogger("ConfigApiAccess")
        filter { call -> call.request.path() != "/health" }
        format { call ->
            val status = call.response.status()?.toString() ?: "-"
            val device = call.request.headers["X-Device-Id"]?.takeIf { isValidIdentifier(it) }?.let { " device=$it" } ?: ""
            "[$listener] $status ${call.request.httpMethod.value} ${call.request.path()} " +
                "from ${call.request.origin.remoteAddress}$device in ${call.processingTimeMillis()}ms"
        }
    }
}
