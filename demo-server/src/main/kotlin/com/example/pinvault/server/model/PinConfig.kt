package com.example.pinvault.server.model

import kotlinx.serialization.Serializable

@Serializable
data class PinConfig(
    val version: Int = 0,
    val pins: List<HostPin>,
    val forceUpdate: Boolean = false
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
    val forceUpdate: Boolean = false
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
    val createdAt: String = ""
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
