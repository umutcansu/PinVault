package com.example.pinvault.server.service.attestation

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import java.io.ByteArrayInputStream
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.Date

/**
 * Verifies Apple App Attest attestation objects and assertions on this
 * server (ATTESTATION.md §12), the way Apple's "Validating apps that connect
 * to your server" lays it out. Nothing is sent to Apple: the chain is checked
 * against Apple's App Attestation Root CA, which the operator downloads once
 * (`APP_ATTEST_ROOT_CA_FILE`).
 *
 * Attestation (a new key), checks in Apple's order, each with a fixed reason:
 *
 *  1. `malformed` / `unsupported_format` — not a CBOR
 *     `{fmt: "apple-appattest", attStmt: {x5c, receipt}, authData}`;
 *  2. `chain_invalid` — x5c (leaf, intermediate) does not chain to the root
 *     at this time;
 *  3. `nonce_mismatch` — the leaf's extension 1.2.840.113635.100.8.2 is not
 *     SHA-256(authData ‖ clientDataHash): made for another challenge;
 *  4. `key_id_mismatch` — the key id is not SHA-256 of the leaf's public key
 *     (the uncompressed point);
 *  5. `app_id_mismatch` — authData's RP id hash is not SHA-256 of one of
 *     [appIds] (`TEAMID.bundle.id`): another developer's or another app's key;
 *  6. `counter_not_zero`;
 *  7. `environment_mismatch` — aaguid is not [environment]'s
 *     (`appattestdevelop` / `appattest` + seven zero bytes);
 *  8. `credential_id_mismatch` — authData's credential id is not the key id.
 *
 * Assertion (a later round, with the key an attestation registered):
 * `malformed`, `app_id_mismatch`, `signature_invalid` (ECDSA P-256 over
 * SHA-256(authenticatorData ‖ clientDataHash) with the stored key),
 * `counter_replay` (not above the stored counter: a cloned key, or a replay).
 *
 * The receipt is not used (it is for Apple's fraud-metric service).
 */
class AppAttestVerifier(
    /** Apple's App Attestation Root CA (tests: their own root). */
    val roots: List<X509Certificate>,
    /** `TEAMID.bundle.id` of every app whose keys count. */
    appIds: Set<String>,
    val environment: Environment = Environment.PRODUCTION,
    /** A verified verdict covers the device's rounds this long before `app_attest_missing`. */
    val verdictMaxAgeSeconds: Long = DEFAULT_VERDICT_MAX_AGE_SECONDS,
    /**
     * `APP_ATTEST_REQUIRE_V2`: an attestation round's verdict must use the v2
     * client data hash ([roundClientDataHashV2], bound to the report); a v1
     * one (nonce and device id only) fails `client_data_v1`. Off = v1 still
     * verifies, with the warning `app_attest_v1`.
     */
    val requireV2: Boolean = false
) {
    /** `APP_ATTEST_ENVIRONMENT`: what the app's entitlement `com.apple.developer.devicecheck.appattest-environment` says. */
    enum class Environment(val wire: String, private val aaguidText: String) {
        PRODUCTION("production", "appattest"),
        DEVELOPMENT("development", "appattestdevelop");

        /** 16 bytes: the text, zero-padded. */
        val aaguid: ByteArray get() = aaguidText.toByteArray(Charsets.US_ASCII).copyOf(16)

        companion object {
            fun parse(value: String?): Environment = when (value?.trim()?.lowercase()) {
                null, "", "production" -> PRODUCTION
                "development" -> DEVELOPMENT
                else -> throw IllegalArgumentException("APP_ATTEST_ENVIRONMENT must be production or development (got '$value')")
            }
        }
    }

    /** What the device sent as the provider's token (PORTING.md §6); fields it lacks or that do not decode are null. */
    class Token(val keyId: ByteArray?, val attestation: ByteArray?, val assertion: ByteArray?) {
        /** A 32-byte key id and exactly one of attestation / assertion. */
        val wellFormed: Boolean get() = keyId?.size == 32 && ((attestation != null) != (assertion != null))
        val keyIdBase64: String? get() = keyId?.let { Base64.getEncoder().encodeToString(it) }
    }

    /** An attestation's outcome: with [passed], the key to store (SPKI DER) and the app id it was made for. */
    class Attestation(val passed: Boolean, val reason: String, val publicKey: ByteArray? = null, val appId: String? = null) {
        override fun toString() = "AppAttest(attestation ${if (passed) "pass" else "fail"}: $reason)"
    }

    /** An assertion's outcome: with [passed], the authenticator's new [counter]. */
    class Assertion(val passed: Boolean, val reason: String, val counter: Long? = null) {
        override fun toString() = "AppAttest(assertion ${if (passed) "pass" else "fail"}: $reason)"
    }

    val appIds: Set<String> = appIds.toSet()
    private val anchors: Set<TrustAnchor>
    /** SHA-256(app id) hex → app id. */
    private val rpIdHashes: Map<String, String> = this.appIds.associateBy { hex(sha256(it.toByteArray(Charsets.UTF_8))) }

    init {
        require(roots.isNotEmpty()) { "App Attest needs Apple's App Attestation Root CA (APP_ATTEST_ROOT_CA_FILE)" }
        require(this.appIds.isNotEmpty()) { "APP_ATTEST_APP_IDS names no app" }
        anchors = roots.map { TrustAnchor(it, null) }.toSet()
    }

    /**
     * Verifies [attestationObject] for the key [keyId] (SHA-256 of its public
     * key, as `DCAppAttestService.generateKey` returned it), made with
     * [clientDataHash]. Never throws.
     */
    fun verifyAttestation(attestationObject: ByteArray, keyId: ByteArray, clientDataHash: ByteArray, now: Instant = Instant.now()): Attestation =
        // Anyone can send these bytes: whatever slips past the checks below is a failed verdict, never a 500.
        try { attestation(attestationObject, keyId, clientDataHash, now) } catch (_: Exception) { Attestation(false, "malformed") }

    private fun attestation(attestationObject: ByteArray, keyId: ByteArray, clientDataHash: ByteArray, now: Instant): Attestation {
        val top = try { Cbor.decode(attestationObject) as? Map<*, *> } catch (_: Cbor.Malformed) { null }
            ?: return Attestation(false, "malformed")
        if (top["fmt"] != FORMAT) return Attestation(false, "unsupported_format")
        val statement = top["attStmt"] as? Map<*, *> ?: return Attestation(false, "malformed")
        val authData = top["authData"] as? ByteArray ?: return Attestation(false, "malformed")
        val x5c = (statement["x5c"] as? List<*>)?.map { it as? ByteArray ?: return Attestation(false, "malformed") }
            ?: return Attestation(false, "malformed")
        if (x5c.size !in 2..MAX_CHAIN) return Attestation(false, "malformed")
        val parsed = parseAuthData(authData, attested = true) ?: return Attestation(false, "malformed")

        // 1. The chain, to Apple's root, valid now.
        val leaf = try {
            val factory = CertificateFactory.getInstance("X.509")
            val certs = x5c.map { factory.generateCertificate(ByteArrayInputStream(it)) as X509Certificate }
            val params = PKIXParameters(anchors).apply { isRevocationEnabled = false; date = Date.from(now) }
            CertPathValidator.getInstance("PKIX").validate(factory.generateCertPath(certs), params)
            certs.first()
        } catch (_: Exception) {
            return Attestation(false, "chain_invalid")
        }
        // 2–4. nonce = SHA-256(authData ‖ clientDataHash), in the leaf's extension.
        val nonce = sha256(authData + clientDataHash)
        val inLeaf = leaf.getExtensionValue(NONCE_OID)?.let { nonceOf(it) } ?: return Attestation(false, "nonce_mismatch")
        if (!MessageDigest.isEqual(inLeaf, nonce)) return Attestation(false, "nonce_mismatch")
        // 5. The key id names the leaf's key.
        val leafKey = leaf.publicKey as? ECPublicKey ?: return Attestation(false, "key_id_mismatch")
        val point = uncompressedPoint(leafKey) ?: return Attestation(false, "key_id_mismatch")
        if (!MessageDigest.isEqual(sha256(point), keyId)) return Attestation(false, "key_id_mismatch")
        // 6. Made for one of our apps.
        val appId = rpIdHashes[hex(parsed.rpIdHash)] ?: return Attestation(false, "app_id_mismatch")
        // 7. A new key has used no counter.
        if (parsed.counter != 0L) return Attestation(false, "counter_not_zero")
        // 8. The environment the app was signed for.
        if (!parsed.aaguid!!.contentEquals(environment.aaguid)) return Attestation(false, "environment_mismatch")
        // 9. The credential is the key.
        if (!parsed.credentialId!!.contentEquals(keyId)) return Attestation(false, "credential_id_mismatch")
        return Attestation(true, "ok", leafKey.encoded, appId)
    }

    /**
     * Verifies [assertionObject] made with [clientDataHash] by the key
     * [publicKey] (SPKI DER, as [verifyAttestation] returned it), whose last
     * counter was [storedCounter]. Never throws.
     */
    fun verifyAssertion(assertionObject: ByteArray, clientDataHash: ByteArray, publicKey: ByteArray, storedCounter: Long): Assertion =
        try { assertion(assertionObject, clientDataHash, publicKey, storedCounter) } catch (_: Exception) { Assertion(false, "malformed") }

    private fun assertion(assertionObject: ByteArray, clientDataHash: ByteArray, publicKey: ByteArray, storedCounter: Long): Assertion {
        val top = try { Cbor.decode(assertionObject) as? Map<*, *> } catch (_: Cbor.Malformed) { null }
            ?: return Assertion(false, "malformed")
        val signature = top["signature"] as? ByteArray ?: return Assertion(false, "malformed")
        val authenticatorData = top["authenticatorData"] as? ByteArray ?: return Assertion(false, "malformed")
        val parsed = parseAuthData(authenticatorData, attested = false) ?: return Assertion(false, "malformed")
        val key: PublicKey = try {
            KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKey))
        } catch (_: Exception) {
            return Assertion(false, "malformed")
        }
        val nonce = sha256(authenticatorData + clientDataHash)
        val verified = try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(nonce)
                verify(signature)
            }
        } catch (_: Exception) {
            false
        }
        if (!verified) return Assertion(false, "signature_invalid")
        if (rpIdHashes[hex(parsed.rpIdHash)] == null) return Assertion(false, "app_id_mismatch")
        if (parsed.counter <= storedCounter) return Assertion(false, "counter_replay")
        return Assertion(true, "ok", parsed.counter)
    }

    private class AuthData(val rpIdHash: ByteArray, val counter: Long, val aaguid: ByteArray?, val credentialId: ByteArray?)

    /**
     * WebAuthn authenticator data: rpIdHash (32) ‖ flags (1) ‖ counter (4, big
     * endian) and, for an attestation, aaguid (16) ‖ credentialId length (2) ‖
     * credentialId ‖ the COSE key (not read: the leaf certificate carries the key).
     */
    private fun parseAuthData(data: ByteArray, attested: Boolean): AuthData? {
        if (data.size < 37) return null
        val counter = (33 until 37).fold(0L) { acc, i -> (acc shl 8) or (data[i].toLong() and 0xFF) }
        if (!attested) return AuthData(data.copyOfRange(0, 32), counter, null, null)
        if (data.size < 55) return null
        val length = ((data[53].toInt() and 0xFF) shl 8) or (data[54].toInt() and 0xFF)
        if (data.size < 55 + length) return null
        return AuthData(data.copyOfRange(0, 32), counter, data.copyOfRange(37, 53), data.copyOfRange(55, 55 + length))
    }

    companion object {
        /** `verdictProvider.name` and the token's `provider` (PORTING.md §6). */
        const val PROVIDER = "app-attest"
        const val FORMAT = "apple-appattest"
        const val NONCE_OID = "1.2.840.113635.100.8.2"
        const val DEFAULT_VERDICT_MAX_AGE_SECONDS = 86_400L
        const val ROOT_CA_URL = "https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem"
        private const val MAX_CHAIN = 4

        /** `TEAMID.bundle.id`: a 10-character team id, a dot, the bundle id. */
        private val APP_ID = Regex("^[A-Z0-9]{10}\\.[A-Za-z0-9][A-Za-z0-9.-]{0,254}$")

        /** An attestation round's client data hash, v1: SHA-256 of `pinvault-app-attest:v1:<nonce>:<deviceId>`. */
        fun roundClientDataHash(nonce: String, deviceId: String): ByteArray =
            sha256("pinvault-app-attest:v1:$nonce:$deviceId".toByteArray(Charsets.UTF_8))

        /**
         * An attestation round's client data hash, v2: SHA-256 of
         * `pinvault-app-attest:v2:` + [canonical], the string the device key
         * signs (`pinvault-attest:v1:<nonce>:<deviceId>:<sha256-hex(report)>`,
         * [AttestationService.canonical]). It binds Apple's verdict to the
         * report itself, so the report cannot carry the token: a v2 token
         * travels in the request body's own `verdictProvider`.
         */
        fun roundClientDataHashV2(canonical: String): ByteArray =
            sha256("pinvault-app-attest:v2:$canonical".toByteArray(Charsets.UTF_8))

        /** An enrollment's client data hash: SHA-256 of the integrity request hash (the 43-character string). */
        fun enrollmentClientDataHash(integrityRequestHash: String): ByteArray =
            sha256(integrityRequestHash.toByteArray(Charsets.UTF_8))

        /**
         * The token of PORTING.md §6, `{"provider":"app-attest","keyId":…,
         * "attestation"|"assertion":…}`; null when [text] is not one (not
         * JSON, or another provider).
         */
        fun parseToken(text: String): Token? {
            val json = try { Json.parseToJsonElement(text) as? JsonObject } catch (_: Exception) { null } ?: return null
            if (json.string("provider") != PROVIDER) return null
            return Token(json.string("keyId")?.let(::base64), json.string("attestation")?.let(::base64), json.string("assertion")?.let(::base64))
        }

        /**
         * From `APP_ATTEST_APP_IDS` (comma separated `TEAMID.bundle.id`); null
         * when it is empty. `APP_ATTEST_ROOT_CA_FILE` must then name a readable
         * PEM with Apple's App Attestation Root CA, or the server does not
         * start. `APP_ATTEST_ENVIRONMENT` production|development (default
         * production); `APP_ATTEST_MAX_AGE_SECONDS` (default 86400);
         * `APP_ATTEST_REQUIRE_V2` (default false).
         */
        fun fromEnv(env: Map<String, String> = com.example.pinvault.server.service.ServerEnv.all()): AppAttestVerifier? {
            val ids = env["APP_ATTEST_APP_IDS"]?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }?.toSet().orEmpty()
            if (ids.isEmpty()) return null
            ids.forEach {
                require(APP_ID.matches(it)) { "APP_ATTEST_APP_IDS: '$it' is not TEAMID.bundle.id (the 10-character team id, a dot, the bundle id)" }
            }
            val environment = Environment.parse(env["APP_ATTEST_ENVIRONMENT"])
            val maxAge = env["APP_ATTEST_MAX_AGE_SECONDS"]?.trim()?.takeIf { it.isNotEmpty() }?.let {
                it.toLongOrNull()?.takeIf { v -> v in 60..(30 * 86_400L) } ?: throw IllegalArgumentException("APP_ATTEST_MAX_AGE_SECONDS must be 60..2592000 (got '$it')")
            } ?: DEFAULT_VERDICT_MAX_AGE_SECONDS
            val requireV2 = when (env["APP_ATTEST_REQUIRE_V2"]?.trim()?.lowercase()) {
                null, "", "false", "off" -> false
                "true", "on" -> true
                else -> throw IllegalArgumentException("APP_ATTEST_REQUIRE_V2 must be true or false (got '${env["APP_ATTEST_REQUIRE_V2"]}')")
            }
            return AppAttestVerifier(loadRoots(env["APP_ATTEST_ROOT_CA_FILE"]), ids, environment, maxAge, requireV2)
        }

        /**
         * The root(s) in the PEM at [path]. Missing, unreadable or without a
         * certificate: the server refuses to start — App Attest configured
         * without the root would judge every iOS device by nothing.
         */
        fun loadRoots(path: String?): List<X509Certificate> {
            val advice = "Download Apple's App Attestation Root CA from $ROOT_CA_URL, put it where the server can read it and " +
                "set APP_ATTEST_ROOT_CA_FILE to its path (or leave APP_ATTEST_APP_IDS empty to turn App Attest off)."
            val file = path?.trim()?.takeIf { it.isNotEmpty() }?.let(::File)
            checkNotNull(file) { "APP_ATTEST_APP_IDS is set but APP_ATTEST_ROOT_CA_FILE is not. $advice" }
            val roots = try {
                file.inputStream().use { input -> CertificateFactory.getInstance("X.509").generateCertificates(input).map { it as X509Certificate } }
            } catch (e: Exception) {
                throw IllegalStateException("APP_ATTEST_ROOT_CA_FILE (${file.path}) cannot be read as a PEM certificate: ${e.message}. $advice")
            }
            check(roots.isNotEmpty()) { "APP_ATTEST_ROOT_CA_FILE (${file.path}) holds no certificate. $advice" }
            return roots
        }

        /** The one OCTET STRING inside the nonce extension: `SEQUENCE { [1] EXPLICIT OCTET STRING }`. */
        private fun nonceOf(extensionValue: ByteArray): ByteArray? = try {
            val sequence = ASN1Sequence.getInstance(ASN1OctetString.getInstance(extensionValue).octets)
            if (sequence.size() != 1) null else octets(sequence.getObjectAt(0).toASN1Primitive(), 0)
        } catch (_: Exception) {
            null
        }

        private fun octets(item: ASN1Primitive, depth: Int): ByteArray? = when {
            depth > 2 -> null
            item is ASN1OctetString -> item.octets
            item is ASN1TaggedObject -> octets(item.explicitBaseObject.toASN1Primitive(), depth + 1)
            else -> null
        }

        /** 0x04 ‖ x ‖ y of a P-256 key, as Apple hashes it into the key id. */
        private fun uncompressedPoint(key: ECPublicKey): ByteArray? {
            if (key.params.curve.field.fieldSize != 256) return null
            return byteArrayOf(0x04) + fixed(key.w.affineX) + fixed(key.w.affineY)
        }

        private fun fixed(v: BigInteger): ByteArray {
            val raw = v.toByteArray().let { if (it.size > 32 && it[0] == 0.toByte()) it.copyOfRange(it.size - 32, it.size) else it }
            return ByteArray(32 - raw.size) + raw
        }

        private fun base64(text: String): ByteArray? = try {
            val cleaned = text.trim()
            if (cleaned.contains('-') || cleaned.contains('_')) Base64.getUrlDecoder().decode(cleaned) else Base64.getDecoder().decode(cleaned)
        } catch (_: IllegalArgumentException) {
            null
        }

        internal fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

        private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

        private fun JsonObject.string(name: String): String? =
            (this[name] as? JsonPrimitive)?.takeIf { it !is JsonNull && it.isString }?.content
    }
}
