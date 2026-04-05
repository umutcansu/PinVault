package com.example.pinvault.server.service

import java.io.File
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * ECDSA P-256 ile pin config response'larını imzalar.
 *
 * Startup'ta [keyFile]'dan keypair yükler; dosya yoksa yeni üretir.
 * Private key backend'de kalır, [publicKeyBase64] APK'ya gömülür.
 */
class ConfigSigningService(private val keyFile: File) {

    private val keyPair: KeyPair = loadOrGenerate()

    /** APK'ya gömülecek public key (Base64, X.509 encoded) */
    val publicKeyBase64: String =
        Base64.getEncoder().encodeToString(keyPair.public.encoded)

    /** Payload string'ini ECDSA-SHA256 ile imzalar, Base64 döner. */
    fun sign(payload: String): String {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(keyPair.private)
        sig.update(payload.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(sig.sign())
    }

    /** İmzayı doğrular (test/debug için). */
    fun verify(payload: String, signature: String): Boolean {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initVerify(keyPair.public)
        sig.update(payload.toByteArray(Charsets.UTF_8))
        return sig.verify(Base64.getDecoder().decode(signature))
    }

    private fun loadOrGenerate(): KeyPair {
        if (keyFile.exists()) return loadFromFile()
        val kp = generateKeyPair()
        saveToFile(kp)
        println("ConfigSigningService: New ECDSA P-256 keypair generated")
        return kp
    }

    private fun generateKeyPair(): KeyPair {
        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(ECGenParameterSpec("secp256r1"))
        return gen.generateKeyPair()
    }

    private fun saveToFile(kp: KeyPair) {
        keyFile.parentFile?.mkdirs()
        val data = Base64.getEncoder().encodeToString(kp.private.encoded) +
                "\n" +
                Base64.getEncoder().encodeToString(kp.public.encoded)
        keyFile.writeText(data)
    }

    private fun loadFromFile(): KeyPair {
        val lines = keyFile.readText().trim().split("\n")
        require(lines.size == 2) { "Invalid signing key file format" }

        val kf = KeyFactory.getInstance("EC")
        val privateKey = kf.generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(lines[0])))
        val publicKey = kf.generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(lines[1])))

        return KeyPair(publicKey, privateKey)
    }
}
