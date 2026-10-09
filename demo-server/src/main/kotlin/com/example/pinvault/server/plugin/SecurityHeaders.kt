package com.example.pinvault.server.plugin

import io.ktor.http.HttpHeaders
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.response.header
import io.ktor.http.toHttpDate
import io.ktor.util.date.GMTDate

/**
 * The response headers of the management listener (M-05), in place of Ktor's
 * `DefaultHeaders`: that plugin always adds `Server: Ktor/<version>`, which
 * names the framework and its exact version to whoever asks, and it cannot
 * be told not to. This one sends no `Server` header at all.
 *
 * CSP is intentionally permissive on 'style-src' because the admin UI inlines
 * a few utility styles; 'script-src self' still kills the H-02 stored-XSS
 * payload class. Markup that still slips into the page can neither submit a
 * form anywhere nor re-point relative URLs (form-action, base-uri); every
 * dashboard form is handled in script.
 *
 * `Strict-Transport-Security` goes out only on a response that leaves over
 * TLS (`MANAGEMENT_HTTPS_PORT`): a browser must never be told to insist on
 * HTTPS by the plain-HTTP port, which is the only one in a demo. The scheme
 * is the listener's own (`request.local`), not a forwarded header.
 */
val SecurityHeaders = createApplicationPlugin("SecurityHeaders") {
    val fixed = listOf(
        "X-Content-Type-Options" to "nosniff",
        "X-Frame-Options" to "DENY",
        "Referrer-Policy" to "no-referrer",
        // The admin UI needs no powerful browser features; deny them all so a
        // slipped-in payload cannot reach for the camera, mic, location, etc.
        "Permissions-Policy" to (
            "accelerometer=(), autoplay=(), camera=(), display-capture=(), " +
                "encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), " +
                "magnetometer=(), microphone=(), midi=(), payment=(), usb=()"
            ),
        "Content-Security-Policy" to (
            "default-src 'self'; script-src 'self'; " +
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
                "connect-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'"
            )
    )
    onCallRespond { call, _ ->
        fixed.forEach { (name, value) ->
            if (!call.response.headers.contains(name)) call.response.header(name, value)
        }
        if (call.request.local.scheme == "https" && !call.response.headers.contains(HttpHeaders.StrictTransportSecurity)) {
            call.response.header(HttpHeaders.StrictTransportSecurity, HSTS)
        }
        if (!call.response.headers.contains(HttpHeaders.Date)) {
            call.response.header(HttpHeaders.Date, GMTDate().toHttpDate())
        }
    }
}

/** One year; the management host alone, so no `includeSubDomains`. */
const val HSTS = "max-age=31536000"
