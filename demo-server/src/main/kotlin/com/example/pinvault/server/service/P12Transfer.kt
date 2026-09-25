package com.example.pinvault.server.service

import io.ktor.http.ContentType
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.header
import io.ktor.server.response.header
import io.ktor.server.response.respondBytes
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * How a P12 — a device's client certificate with its private key — leaves the
 * server.
 *
 * A client that announces `p12password` in `X-PinVault-Features` gets the
 * bundle wrapped with a random password used once, sent in `X-P12-Password`
 * on the same (pinned) TLS response; the library re-wraps it with its own
 * password before storing it. Everyone else — older library versions, an
 * operator downloading a P12 for a manual install — gets [legacyPassword]
 * (`CLIENT_P12_PASSWORD`, default "changeit").
 *
 * Neither is [CertificateService.KEYSTORE_PASSWORD]. That one protects the
 * server's own keystores and never has to be known to an app.
 */
object P12Transfer {
    const val FEATURE = "p12password"
    const val FEATURES_HEADER = "X-PinVault-Features"
    const val PASSWORD_HEADER = "X-P12-Password"

    val legacyPassword: String =
        System.getenv("CLIENT_P12_PASSWORD")?.takeIf { it.isNotBlank() } ?: "changeit"

    private val random = SecureRandom()

    /** The password a P12 for this caller is wrapped with; [negotiated] = sent along in [PASSWORD_HEADER]. */
    class Wrapping(val password: String, val negotiated: Boolean)

    fun wrappingFor(call: ApplicationCall): Wrapping =
        if (negotiated(call.request.header(FEATURES_HEADER))) Wrapping(newPassword(), true)
        else Wrapping(legacyPassword, false)

    fun negotiated(features: String?): Boolean =
        features.orEmpty().split(',').any { it.trim().equals(FEATURE, ignoreCase = true) }

    private fun newPassword(): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(24).also(random::nextBytes))

    /**
     * Sends a stored host client certificate re-wrapped for the caller. One the
     * server cannot open (uploaded before certificates were kept under
     * KEYSTORE_PASSWORD, with a password it never learned) goes out as stored.
     */
    suspend fun respondStored(call: ApplicationCall, certService: CertificateService?, stored: ByteArray) {
        val current = certService?.p12Password(
            stored, listOf(CertificateService.KEYSTORE_PASSWORD, CertificateService.LEGACY_KEYSTORE_PASSWORD, legacyPassword)
        )
        if (current == null) {
            call.respondBytes(stored, ContentType.Application.OctetStream)
            return
        }
        val wrapping = wrappingFor(call)
        respond(call, certService.rewrapP12(stored, current, wrapping.password), wrapping)
    }

    /** Answers with [p12], its integrity hash (`X-P12-SHA256`) and, when negotiated, its password. */
    suspend fun respond(call: ApplicationCall, p12: ByteArray, wrapping: Wrapping) {
        call.response.header("X-P12-SHA256", Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(p12)))
        if (wrapping.negotiated) call.response.header(PASSWORD_HEADER, wrapping.password)
        // A private key and the password that opens it: never cached anywhere.
        call.response.header("Cache-Control", "no-store")
        call.respondBytes(p12, ContentType.Application.OctetStream)
    }
}
