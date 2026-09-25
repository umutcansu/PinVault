package com.example.pinvault.server.service.signing

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Provider
import java.security.Security
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date

/**
 * Signs with a key held in an HSM through PKCS#11 (JDK SunPKCS11 provider).
 *
 * The key is created INSIDE the token as sensitive, non-extractable and
 * sign-only (no decrypt, unwrap, sign-recover or derive), so it cannot be
 * copied off the device — not by this server, not by someone who
 * owns this server. Anyone who can drive the server can still ask the HSM for
 * signatures, which is why the reference server pairs this with an audit log
 * and, for the strongest setups, a second signer (`requiredSignatures(2)`).
 *
 * Tested with SoftHSM2; the same configuration works with any PKCS#11 module
 * (YubiHSM, Luna, CloudHSM, …). The SunPKCS11 key store exposes a private key
 * only together with a certificate, so on first use (`generateIfMissing`) a
 * self-signed certificate — signed by the HSM key itself — is stored next to
 * it under the same label. Devices never see that certificate.
 *
 * @param library path of the PKCS#11 module (`PKCS11_LIBRARY`)
 * @param slotListIndex which slot of the module to use (`PKCS11_SLOT_INDEX`)
 * @param pin user PIN of the token (`PKCS11_PIN`)
 * @param keyLabel label (key store alias) of the signing key (`PKCS11_KEY_LABEL`)
 * @param generateIfMissing create the key in the token when the label is absent (`PKCS11_GENERATE_KEY`)
 */
class Pkcs11Signer(
    override val name: String,
    library: String,
    slotListIndex: Int,
    pin: String,
    private val keyLabel: String,
    generateIfMissing: Boolean
) : ConfigSigner {

    private val provider: Provider
    private val privateKey: PrivateKey

    override val type: String = "pkcs11"
    override val publicKeyBase64: String
    override val description: String

    init {
        val config = """
            name = PinVault
            library = $library
            slotListIndex = $slotListIndex
            attributes(generate, CKO_PRIVATE_KEY, CKK_EC) = {
              CKA_TOKEN = true
              CKA_PRIVATE = true
              CKA_SENSITIVE = true
              CKA_EXTRACTABLE = false
              CKA_SIGN = true
              CKA_DECRYPT = false
              CKA_UNWRAP = false
              CKA_SIGN_RECOVER = false
              CKA_DERIVE = false
            }
            attributes(generate, CKO_PUBLIC_KEY, CKK_EC) = {
              CKA_TOKEN = true
              CKA_VERIFY = true
              CKA_ENCRYPT = false
              CKA_WRAP = false
              CKA_VERIFY_RECOVER = false
              CKA_DERIVE = false
            }
        """.trimIndent()
        val base = Security.getProvider("SunPKCS11")
            ?: error("The SunPKCS11 provider is not available in this JRE (module jdk.crypto.cryptoki)")
        provider = base.configure("--$config")

        val keyStore = KeyStore.getInstance("PKCS11", provider)
        keyStore.load(null, pin.toCharArray())
        if (!keyStore.containsAlias(keyLabel)) {
            check(generateIfMissing) {
                "PKCS#11 key '$keyLabel' not found in slot $slotListIndex. Create it in the HSM, or set " +
                    "PKCS11_GENERATE_KEY=true to have the server generate a non-extractable key there."
            }
            val generator = KeyPairGenerator.getInstance("EC", provider)
            generator.initialize(ECGenParameterSpec("secp256r1"))
            val pair = generator.generateKeyPair()
            val holder = JcaX509v3CertificateBuilder(
                X500Name("CN=PinVault config signing"),
                BigInteger.valueOf(System.currentTimeMillis()),
                Date(System.currentTimeMillis() - 60_000),
                Date(System.currentTimeMillis() + 20L * 365 * 24 * 60 * 60 * 1000),
                X500Name("CN=PinVault config signing"),
                pair.public
            ).build(JcaContentSignerBuilder("SHA256withECDSA").setProvider(provider).build(pair.private))
            val certificate = JcaX509CertificateConverter().getCertificate(holder)
            keyStore.setKeyEntry(keyLabel, pair.private, null, arrayOf(certificate))
            println("Pkcs11Signer: generated non-extractable P-256 key '$keyLabel' in slot $slotListIndex")
        }
        privateKey = keyStore.getKey(keyLabel, null) as? PrivateKey
            ?: error("PKCS#11 entry '$keyLabel' is not a private key")
        val certificate = keyStore.getCertificate(keyLabel) as X509Certificate
        publicKeyBase64 = SigningKeys.base64Of(certificate.publicKey)
        description = "PKCS#11 HSM key '$keyLabel' (slot $slotListIndex, ${library.substringAfterLast('/')})"
    }

    override fun sign(data: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA", provider).run {
        initSign(privateKey)
        update(data)
        sign()
    }
}
