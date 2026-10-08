package com.example.pinvault.server.service.attestation

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Base64
import java.util.Date
import java.util.concurrent.atomic.AtomicLong

/**
 * Synthetic Apple App Attest for tests: a root and an intermediate standing in
 * for Apple's, a leaf over a fresh P-256 key carrying the nonce extension
 * (1.2.840.113635.100.8.2), the CBOR attestation object and assertions built
 * byte by byte as `DCAppAttestService` returns them. Inject [Pki.root] into
 * [AppAttestVerifier] in place of Apple's root.
 */
object AppAttestFixtures {

    const val TEAM_ID = "ABCDE12345"
    const val BUNDLE_ID = "com.example.sampleclient"
    const val APP_ID = "$TEAM_ID.$BUNDLE_ID"

    private val serials = AtomicLong(System.currentTimeMillis())
    private val notBefore = Date.from(Instant.parse("2020-01-01T00:00:00Z"))
    private val notAfter = Date.from(Instant.parse("2045-01-01T00:00:00Z"))

    class Pki(rootName: String = "CN=Test App Attestation Root CA") {
        val rootKey: KeyPair = ec("secp384r1")
        val root: X509Certificate = cert(X500Name(rootName), rootKey.public, X500Name(rootName), rootKey.private, ca = true, sigAlg = "SHA384withECDSA")
        val intermediateKey: KeyPair = ec("secp384r1")
        val intermediate: X509Certificate = cert(X500Name("CN=Test App Attestation CA 1"), intermediateKey.public,
            X500Name(rootName), rootKey.private, ca = true, sigAlg = "SHA384withECDSA")

        fun verifier(
            appIds: Set<String> = setOf(APP_ID),
            environment: AppAttestVerifier.Environment = AppAttestVerifier.Environment.PRODUCTION,
            verdictMaxAgeSeconds: Long = AppAttestVerifier.DEFAULT_VERDICT_MAX_AGE_SECONDS,
            requireV2: Boolean = false
        ) = AppAttestVerifier(listOf(root), appIds, environment, verdictMaxAgeSeconds, requireV2)

        /** The PEM of [root], as an operator stores Apple's. */
        fun rootPem(): String = "-----BEGIN CERTIFICATE-----\n" +
            Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(root.encoded) + "\n-----END CERTIFICATE-----\n"
    }

    /** One App Attest key, as the Secure Enclave holds it: [keyId] = SHA-256 of its uncompressed point. */
    class Key(val pair: KeyPair = ec("secp256r1")) {
        val keyId: ByteArray = sha256(point(pair.public as ECPublicKey))
        val keyIdBase64: String get() = Base64.getEncoder().encodeToString(keyId)
    }

    /**
     * An attestation object for [key] over [clientDataHash]. Each parameter
     * spoils one thing Apple's checks look at.
     */
    fun attestation(
        pki: Pki,
        key: Key,
        clientDataHash: ByteArray,
        appId: String = APP_ID,
        aaguid: ByteArray = AppAttestVerifier.Environment.PRODUCTION.aaguid,
        counter: Long = 0,
        credentialId: ByteArray = key.keyId,
        nonceFor: ByteArray? = null,
        fmt: String = "apple-appattest",
        leafKey: PublicKey = key.pair.public
    ): ByteArray {
        val authData = sha256(appId.toByteArray()) + byteArrayOf(0x40) + counterBytes(counter) + aaguid +
            byteArrayOf((credentialId.size ushr 8).toByte(), credentialId.size.toByte()) + credentialId + coseKey(key.pair.public as ECPublicKey)
        val nonce = sha256(authData + (nonceFor ?: clientDataHash))
        val leaf = cert(X500Name("CN=${hex(key.keyId)}"), leafKey, X500Name("CN=Test App Attestation CA 1"), pki.intermediateKey.private,
            ca = false, sigAlg = "SHA256withECDSA", nonce = nonce)
        return CborWriter.encode(linkedMapOf(
            "fmt" to fmt,
            "attStmt" to linkedMapOf("x5c" to listOf(leaf.encoded, pki.intermediate.encoded), "receipt" to ByteArray(64) { 7 }),
            "authData" to authData
        ))
    }

    /** An assertion by [key] over [clientDataHash] with authenticator [counter]. */
    fun assertion(key: Key, clientDataHash: ByteArray, counter: Long, appId: String = APP_ID, signer: PrivateKey = key.pair.private): ByteArray {
        val authenticatorData = sha256(appId.toByteArray()) + byteArrayOf(0x01) + counterBytes(counter)
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(signer)
            update(sha256(authenticatorData + clientDataHash))
            sign()
        }
        return CborWriter.encode(linkedMapOf("signature" to signature, "authenticatorData" to authenticatorData))
    }

    /** The provider token of PORTING.md §6. */
    fun token(keyId: String, attestation: ByteArray? = null, assertion: ByteArray? = null): String = buildJsonObject {
        put("provider", "app-attest")
        put("keyId", keyId)
        attestation?.let { put("attestation", Base64.getEncoder().encodeToString(it)) }
        assertion?.let { put("assertion", Base64.getEncoder().encodeToString(it)) }
    }.toString()

    fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    fun ec(curve: String): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair()

    private fun counterBytes(counter: Long) = ByteArray(4) { i -> (counter ushr (8 * (3 - i))).toByte() }

    private fun point(key: ECPublicKey): ByteArray = byteArrayOf(0x04) + fixed(key.w.affineX) + fixed(key.w.affineY)

    private fun fixed(v: BigInteger): ByteArray {
        val raw = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        return ByteArray(32 - raw.size) + raw
    }

    /** COSE_Key {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}, as WebAuthn authData carries it. */
    private fun coseKey(key: ECPublicKey): ByteArray =
        CborWriter.encode(linkedMapOf(1L to 2L, 3L to -7L, -1L to 1L, -2L to fixed(key.w.affineX), -3L to fixed(key.w.affineY)))

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private fun cert(
        subject: X500Name, key: PublicKey, issuer: X500Name, signer: PrivateKey,
        ca: Boolean, sigAlg: String, nonce: ByteArray? = null
    ): X509Certificate {
        val builder = JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(serials.incrementAndGet()), notBefore, notAfter, subject, key)
        if (ca) {
            builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
            builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
        }
        // Apple's leaf: SEQUENCE { [1] EXPLICIT OCTET STRING nonce }, not critical.
        nonce?.let { builder.addExtension(ASN1ObjectIdentifier(AppAttestVerifier.NONCE_OID), false, DERSequence(DERTaggedObject(true, 1, DEROctetString(it)))) }
        return JcaX509CertificateConverter().getCertificate(builder.build(JcaContentSignerBuilder(sigAlg).build(signer)))
    }

    /** A CBOR encoder for the fixtures: what [Cbor] decodes, definite lengths only. */
    object CborWriter {
        fun encode(item: Any): ByteArray = ByteArrayOutputStream().also { write(it, item) }.toByteArray()

        private fun write(out: ByteArrayOutputStream, item: Any) {
            when (item) {
                is Int -> write(out, item.toLong())
                is Long -> if (item >= 0) head(out, 0, item) else head(out, 1, -1 - item)
                is ByteArray -> { head(out, 2, item.size.toLong()); out.write(item) }
                is String -> item.toByteArray(Charsets.UTF_8).let { head(out, 3, it.size.toLong()); out.write(it) }
                is List<*> -> { head(out, 4, item.size.toLong()); item.forEach { write(out, it!!) } }
                is Map<*, *> -> { head(out, 5, item.size.toLong()); item.forEach { (k, v) -> write(out, k!!); write(out, v!!) } }
                else -> error("no CBOR for ${item::class}")
            }
        }

        /** The initial byte(s): major type and argument, in the shortest form. */
        fun head(out: ByteArrayOutputStream, major: Int, value: Long) {
            val m = major shl 5
            when {
                value < 24 -> out.write(m or value.toInt())
                value < 0x100 -> { out.write(m or 24); out.write(value.toInt()) }
                value < 0x10000 -> { out.write(m or 25); out.write((value ushr 8).toInt()); out.write(value.toInt() and 0xFF) }
                value < 0x100000000L -> { out.write(m or 26); for (i in 3 downTo 0) out.write(((value ushr (8 * i)) and 0xFF).toInt()) }
                else -> { out.write(m or 27); for (i in 7 downTo 0) out.write(((value ushr (8 * i)) and 0xFF).toInt()) }
            }
        }
    }
}
