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
    val expiresAt: Long = 0L,
    /**
     * The Config API this config was signed for, written into every SIGNED
     * payload (SignedConfigService.envelope). A library block that set
     * `serverScope(id)` refuses a payload naming another id — or none — so an
     * envelope signed for one Config API cannot be served for another that
     * shares the signing key. Left out of unsigned answers (null).
     */
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val configApiId: String? = null,
    /**
     * Managed trust roots: SHA-256 SPKI pins (Base64, like pins) of root CAs.
     * A library block with `managedTrustRoots()` accepts, for a host that has
     * NO pin entry, a chain the platform validates to one of these roots.
     * Left out of the payload when empty, so older clients see no new field.
     */
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val trustRoots: List<String> = emptyList(),
    /**
     * The request a narrowed SIGNED view answers (see [ConfigView]); null for
     * the full config, and then left out of the payload, which stays byte for
     * byte what it was before the field existed. Never in unsigned answers.
     */
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val view: ConfigView? = null
) {
    fun computedVersion(): Int = pins.maxOfOrNull { it.version } ?: version
    /** Global forceUpdate = any host has forceUpdate */
    fun hasAnyForceUpdate(): Boolean = forceUpdate || pins.any { it.forceUpdate }
}

/**
 * What narrowed a signed config view, inside the signed payload (`view`).
 *
 * Without it, whoever can answer as the Config API (a pinned TLS key, a
 * proxy or CDN in front — not the signing key) could hand a device that asked
 * for the full config a genuine, fresh, signed NARROW view: newer, so it
 * replaces the stored config, and every other host loses its pins. The client
 * compares this field with its own request (SERVER_IMPLEMENTATION_GUIDE.md §3, `view`).
 *
 * Present exactly when the request was scoped: `?hosts=` (or the attestation
 * body's `hosts`) was given, or a device id was claimed (`X-Device-Id`, or the
 * attested `deviceId` when `hosts` came with it). It records the REQUEST, not
 * what was granted: a request naming hosts carries the field even when the
 * result equals the full config.
 *
 * @property hosts the requested host names in canonical form
 *   ([canonicalHosts]); null when no host list was requested (device-only scoping).
 * @property deviceId the device id the request claimed, the one the ACL was
 *   resolved for; null when none was claimed (the ACL then used the client
 *   certificate's id or the default, which the client cannot check).
 */
@Serializable
data class ConfigView(
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val hosts: List<String>? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val deviceId: String? = null
) {
    companion object {
        /**
         * The canonical host set: every entry split at `,`, ASCII whitespace
         * trimmed, empty names dropped, ASCII `A-Z` lower-cased (nothing else
         * changes), duplicates removed, sorted by code point. The library
         * computes the same from its `wantPinsFor` list.
         */
        fun canonicalHosts(hosts: List<String>): List<String> =
            hosts.asSequence()
                .flatMap { it.split(',') }
                .map { it.trim(' ', '\t', '\n', '\r', '\u000B', '\u000C') }
                .filter { it.isNotEmpty() }
                .map { name -> buildString(name.length) { name.forEach { c -> append(if (c in 'A'..'Z') c + 32 else c) } } }
                .distinct()
                .sortedWith { a, b -> compareCodePoints(a, b) }
                .toList()

        /** The view a request with these parameters gets; null = the full config. */
        fun of(requestedHosts: List<String>?, claimedDeviceId: String?): ConfigView? =
            if (requestedHosts == null && claimedDeviceId == null) null
            else ConfigView(hosts = requestedHosts?.let(::canonicalHosts), deviceId = claimedDeviceId)

        private fun compareCodePoints(a: String, b: String): Int {
            var i = 0
            var j = 0
            while (i < a.length && j < b.length) {
                val ca = a.codePointAt(i)
                val cb = b.codePointAt(j)
                if (ca != cb) return ca.compareTo(cb)
                i += Character.charCount(ca)
                j += Character.charCount(cb)
            }
            return (a.length - i).compareTo(b.length - j)
        }
    }
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

/**
 * Signed config envelope. [payload] and [signature] are all a pre-2.1 client
 * reads; the other fields are optional additions older clients ignore:
 * [keyId] names the primary signer, [signatures] carries one entry per signer
 * when there is more than one (m-of-n), and [signingKeys] carries the latest
 * signing-key set uploaded by the operator (rotation / revocation).
 */
@Serializable
data class SignedConfig(
    val payload: String,
    val signature: String,
    val keyId: String? = null,
    val signatures: List<SignatureEntry>? = null,
    val signingKeys: SignedKeySetWire? = null
)

/** One signature: [keyId] = Base64 SHA-256 of the signer's SPKI (an unsigned hint). */
@Serializable
data class SignatureEntry(
    val keyId: String? = null,
    val signature: String
)

/**
 * A signing-key set as devices receive it: the JSON [payload] exactly as the
 * recovery key(s) signed it, and those signatures.
 */
@Serializable
data class SignedKeySetWire(
    val payload: String,
    val signatures: List<SignatureEntry>
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
    /** A keystore for the host is installed (its path on the server is not the caller's business). */
    val hasCertificate: Boolean = false,
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

/**
 * `GET /api/v1/signing-key`. [publicKey] is the primary signer's key (the
 * field every tool already reads); [signers] lists each key that signs, in
 * signing order; [keySetVersion] is the signing-key set devices currently
 * receive (0 = none).
 */
@Serializable
data class SigningKeyInfo(
    val publicKey: String,
    val keyId: String,
    val signers: List<Signer>,
    val keySetVersion: Int = 0
) {
    @Serializable
    data class Signer(val keyId: String, val publicKey: String)
}
