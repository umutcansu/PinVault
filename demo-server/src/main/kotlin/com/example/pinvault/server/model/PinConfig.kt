package com.example.pinvault.server.model

import kotlinx.serialization.Serializable

@Serializable
data class PinConfig(
    val version: Int = 0,
    val pins: List<HostPin>,
    val forceUpdate: Boolean = false,
    /**
     * Unix epoch ms when this config was signed. Set by the server right
     * before signing — clients reject replays where [issuedAt] is not
     * strictly greater than the previously applied config's [issuedAt].
     */
    val issuedAt: Long = 0L,
    /**
     * Unix epoch ms after which the signed config must not be applied.
     * Defines the freshness window. Clients reject configs once the wall
     * clock crosses this value.
     */
    val expiresAt: Long = 0L
) {
    fun computedVersion(): Int = pins.maxOfOrNull { it.version } ?: version
    /** Global forceUpdate = any host has forceUpdate */
    fun hasAnyForceUpdate(): Boolean = forceUpdate || pins.any { it.forceUpdate }
}

@Serializable
data class HostPin(
    val hostname: String,
    val sha256: List<String>,
    val version: Int = 1,
    val forceUpdate: Boolean = false,
    val mtls: Boolean = false,
    val clientCertVersion: Int? = null
)

@Serializable
data class SignedConfig(
    val payload: String,
    val signature: String
)

@Serializable
data class PinConfigHistoryEntry(
    val hostname: String = "",
    val version: Int,
    val timestamp: String,
    val event: String,
    val pinPrefix: String = ""
)

@Serializable
data class HostActionResponse(
    val hostname: String,
    val sha256Pins: List<String> = emptyList(),
    val certValidUntil: String? = null,
    val version: Int = 0
)

@Serializable
data class HostStatusResponse(
    val hostname: String,
    val keystorePath: String? = null,
    val certValidUntil: String? = null,
    val mockServerRunning: Boolean = false,
    val mockServerPort: Int? = null,
    val mockServerMode: String = "tls",
    val mockTlsPort: Int? = null,
    val mockMtlsPort: Int? = null,
    val createdAt: String? = null
)

@Serializable
data class MockServerResponse(
    val hostname: String,
    val port: Int? = null,
    val running: Boolean
)

@Serializable
data class CertInfoResponse(
    val subject: String,
    val issuer: String,
    val serialNumber: String,
    val validFrom: String,
    val validUntil: String,
    val signatureAlgorithm: String,
    val publicKeyAlgorithm: String,
    val publicKeyBits: Int,
    val subjectAltNames: List<String>,
    val sha256Fingerprint: String,
    val primaryPin: String,
    val backupPin: String
)
