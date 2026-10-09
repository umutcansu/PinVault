package com.example.pinvault.server.plugin

import io.ktor.http.HttpHeaders
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.response.header

/**
 * Response-header hardening for the device-facing listeners (Config API and the
 * mock hosts), in place of the full [SecurityHeaders] used on the admin UI:
 * those listeners serve JSON/pin payloads to pinned clients, not HTML to a
 * browser, so the CSP/XFO/Referrer set would be noise. Two headers still earn
 * their place (review round 2026-10-05, S-8):
 *
 *  - `X-Content-Type-Options: nosniff` — a client or proxy must not re-sniff a
 *    JSON body into some other type.
 *  - `Strict-Transport-Security` — only on a response that actually leaves over
 *    TLS (`request.local.scheme == "https"`), never from a plain-HTTP port, and
 *    from the listener's own scheme, not a forwarded header. Reuses [HSTS]
 *    (one year, no `includeSubDomains`: one host).
 *
 * Both are added only when absent, so a route that set its own wins.
 */
val ApiSecurityHeaders = createApplicationPlugin("ApiSecurityHeaders") {
    onCallRespond { call, _ ->
        if (!call.response.headers.contains("X-Content-Type-Options")) {
            call.response.header("X-Content-Type-Options", "nosniff")
        }
        if (call.request.local.scheme == "https" &&
            !call.response.headers.contains(HttpHeaders.StrictTransportSecurity)
        ) {
            call.response.header(HttpHeaders.StrictTransportSecurity, HSTS)
        }
    }
}
