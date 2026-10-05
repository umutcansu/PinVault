package com.example.pinvault.server.service

import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import java.util.concurrent.atomic.AtomicLong

/**
 * Builds Android Key Attestation chains for tests: a fake root and
 * intermediate (EC) and a leaf over the key under test, carrying a
 * KeyDescription extension encoded here field by field. Inject [Pki.root]'s
 * key into [AndroidKeyAttestation] in place of the Google roots.
 */
object TestAttestationChains {

    const val PACKAGE = "com.example.sampleclient"
    val SIGNER: ByteArray = ByteArray(32) { (it * 7).toByte() }
    val SIGNER_HEX: String = SIGNER.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private val serials = AtomicLong(System.currentTimeMillis())
    private const val DAY = 86_400_000L

    class Pki(rootNotAfter: Date = Date(System.currentTimeMillis() + 3650 * DAY), intermediateNotAfter: Date = Date(System.currentTimeMillis() + 3650 * DAY)) {
        val rootKey: KeyPair = ec()
        val root: X509Certificate = cert(X500Name("CN=Test Attestation Root"), rootKey.public, X500Name("CN=Test Attestation Root"),
            rootKey.private, notAfter = rootNotAfter, ca = true)
        val intermediateKey: KeyPair = ec()
        val intermediate: X509Certificate = cert(X500Name("CN=Test Attestation Intermediate"), intermediateKey.public,
            X500Name("CN=Test Attestation Root"), rootKey.private, notAfter = intermediateNotAfter, ca = true)

        /** A verifier trusting this PKI's root, with the sample package and signer. */
        fun verifier(
            packageNames: Set<String> = setOf(PACKAGE),
            signerDigests: Set<String> = setOf(SIGNER_HEX),
            revokedSerials: Set<String> = emptySet(),
            requirePerUse: Boolean = false,
            minPatchLevel: Int? = null,
            revocationList: RevocationList? = null
        ) = AndroidKeyAttestation(listOf(root), packageNames, signerDigests, revokedSerials = revokedSerials,
            requirePerUse = requirePerUse, minPatchLevel = minPatchLevel, revocationList = revocationList)
    }

    /** What an identity key's leaf says: a signing key with the identity challenge of [deviceUid], no user auth. */
    fun identityDescription(deviceUid: String) = Description(
        deviceId = deviceUid,
        challenge = AndroidKeyAttestation.identityChallengeFor(deviceUid),
        userAuthType = false,
        purposes = listOf(2)
    )

    /** What the leaf's KeyDescription says; the defaults describe a key that passes. */
    data class Description(
        val deviceId: String,
        val challenge: ByteArray = AndroidKeyAttestation.challengeFor(deviceId),
        val version: Int = 200,
        val attestationLevel: Int = 1,
        val keyMintLevel: Int = 1,
        val noAuthRequired: Boolean = false,
        val userAuthType: Boolean = true,
        val purposes: List<Int> = listOf(0, 1),
        val origin: Int = 0,
        val rootOfTrust: Boolean = true,
        val deviceLocked: Boolean = true,
        val verifiedBootState: Int = 0,
        val packages: List<String> = listOf(PACKAGE),
        val signers: List<ByteArray> = listOf(SIGNER),
        /** Hardware-enforced authTimeout (tag 505) in seconds; null = none (a per-use key). */
        val authTimeout: Int? = null,
        /** Software-enforced authTimeout; null = none. */
        val softwareAuthTimeout: Int? = null,
        /** noAuthRequired in the software-enforced list. */
        val softwareNoAuthRequired: Boolean = false,
        /** allowWhileOnBody (tag 506), hardware-enforced. */
        val allowWhileOnBody: Boolean = false,
        /** userAuthType value: bit 1 password, bit 2 fingerprint. */
        val userAuthTypeValue: Int = 2,
        /** osVersion (tag 705, MMmmpp); null = not listed. */
        val osVersion: Int? = null,
        /** osPatchLevel (tag 706, YYYYMM); null = not listed. */
        val osPatchLevel: Int? = null
    )

    fun rsa(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    fun pem(key: PublicKey): String {
        val body = Base64.getEncoder().encodeToString(key.encoded).chunked(64).joinToString("\n")
        return "-----BEGIN PUBLIC KEY-----\n$body\n-----END PUBLIC KEY-----"
    }

    /** Base64 DER, leaf first, as the library sends `attestationChain`. */
    fun chain(
        pki: Pki,
        leafKey: PublicKey,
        description: Description,
        /** Signs the leaf; default the PKI's intermediate (another key = a broken chain). */
        leafSigner: PrivateKey = pki.intermediateKey.private,
        leafNotAfter: Date = Date(System.currentTimeMillis() + 365 * DAY),
        includeRoot: Boolean = true,
        extensionOnIntermediate: Boolean = false
    ): List<String> {
        val leaf = cert(X500Name("CN=Android Keystore Key"), leafKey, X500Name("CN=Test Attestation Intermediate"), leafSigner,
            notAfter = leafNotAfter, extension = keyDescription(description))
        val intermediate = if (!extensionOnIntermediate) pki.intermediate else cert(
            X500Name("CN=Test Attestation Intermediate"), pki.intermediateKey.public, X500Name("CN=Test Attestation Root"),
            pki.rootKey.private, notAfter = Date(System.currentTimeMillis() + 3650 * DAY), ca = true, extension = keyDescription(description))
        return (listOf(leaf, intermediate) + if (includeRoot) listOf(pki.root) else emptyList())
            .map { Base64.getEncoder().encodeToString(it.encoded) }
    }

    fun keyDescription(d: Description): ASN1Encodable {
        val appId = DERSequence(arrayOf(
            DERSet(d.packages.map { DERSequence(arrayOf(DEROctetString(it.toByteArray()), ASN1Integer(1))) }.toTypedArray<ASN1Encodable>()),
            DERSet(d.signers.map { DEROctetString(it) }.toTypedArray<ASN1Encodable>())
        ))
        val software = ASN1EncodableVector().apply {
            add(DERTaggedObject(true, 701, ASN1Integer(System.currentTimeMillis())))
            add(DERTaggedObject(true, AndroidKeyAttestation.TAG_ATTESTATION_APPLICATION_ID, DEROctetString(appId.encoded)))
            if (d.softwareNoAuthRequired) add(DERTaggedObject(true, AndroidKeyAttestation.TAG_NO_AUTH_REQUIRED, DERNull.INSTANCE))
            d.softwareAuthTimeout?.let { add(DERTaggedObject(true, AndroidKeyAttestation.TAG_AUTH_TIMEOUT, ASN1Integer(it.toLong()))) }
        }
        val hardware = ASN1EncodableVector().apply {
            add(DERTaggedObject(true, AndroidKeyAttestation.TAG_PURPOSE, DERSet(d.purposes.map { ASN1Integer(it.toLong()) }.toTypedArray<ASN1Encodable>())))
            add(DERTaggedObject(true, 2, ASN1Integer(1)))
            add(DERTaggedObject(true, 3, ASN1Integer(2048)))
            if (d.noAuthRequired) add(DERTaggedObject(true, AndroidKeyAttestation.TAG_NO_AUTH_REQUIRED, DERNull.INSTANCE))
            if (d.userAuthType) add(DERTaggedObject(true, AndroidKeyAttestation.TAG_USER_AUTH_TYPE, ASN1Integer(d.userAuthTypeValue.toLong())))
            d.authTimeout?.let { add(DERTaggedObject(true, AndroidKeyAttestation.TAG_AUTH_TIMEOUT, ASN1Integer(it.toLong()))) }
            if (d.allowWhileOnBody) add(DERTaggedObject(true, AndroidKeyAttestation.TAG_ALLOW_WHILE_ON_BODY, DERNull.INSTANCE))
            add(DERTaggedObject(true, AndroidKeyAttestation.TAG_ORIGIN, ASN1Integer(d.origin.toLong())))
            d.osVersion?.let { add(DERTaggedObject(true, AndroidKeyAttestation.TAG_OS_VERSION, ASN1Integer(it.toLong()))) }
            d.osPatchLevel?.let { add(DERTaggedObject(true, AndroidKeyAttestation.TAG_OS_PATCH_LEVEL, ASN1Integer(it.toLong()))) }
            if (d.rootOfTrust) add(DERTaggedObject(true, AndroidKeyAttestation.TAG_ROOT_OF_TRUST, DERSequence(arrayOf(
                DEROctetString(ByteArray(32) { 1 }),
                ASN1Boolean.getInstance(d.deviceLocked),
                ASN1Enumerated(d.verifiedBootState),
                DEROctetString(ByteArray(32) { 2 })
            ))))
        }
        return DERSequence(arrayOf(
            ASN1Integer(d.version.toLong()),
            ASN1Enumerated(d.attestationLevel),
            ASN1Integer(d.version.toLong()),
            ASN1Enumerated(d.keyMintLevel),
            DEROctetString(d.challenge),
            DEROctetString(ByteArray(0)),
            DERSequence(software),
            DERSequence(hardware)
        ))
    }

    private fun ec(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun cert(
        subject: X500Name,
        key: PublicKey,
        issuer: X500Name,
        signer: PrivateKey,
        notAfter: Date,
        ca: Boolean = false,
        extension: ASN1Encodable? = null
    ): X509Certificate {
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(serials.incrementAndGet()),
            Date(now - 3650 * DAY), notAfter, subject, key)
        if (ca) builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        extension?.let { builder.addExtension(ASN1ObjectIdentifier(AndroidKeyAttestation.KEY_DESCRIPTION_OID), false, it) }
        return JcaX509CertificateConverter().getCertificate(builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(signer)))
    }
}
