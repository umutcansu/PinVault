package com.example.pinvault.server.service

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.io.FileInputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import java.util.Date
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

data class CertGenResult(
    val keystorePath: String,
    val sha256Pins: List<String>,
    val validUntil: String
)

data class ClientCertResult(
    val p12Bytes: ByteArray,
    val fingerprint: String,
    val commonName: String,
    val validUntil: String
)

data class CertInfo(
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

data class FetchResult(
    val hostname: String,
    val sha256Pins: List<String>,
    val certInfo: CertInfo
)

class CertificateService(private val certsDir: File) {

    init {
        certsDir.mkdirs()
        // BouncyCastle provider'ı JVM'e register et — JDK 17+ varsayılan olarak
        // PBES2/AES kullanır, BC olmadan P12 Android 11 uyumsuz olur
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
        }
    }

    /**
     * Self-signed sertifika üretir.
     * Primary key TLS için kullanılır, backup key pin rotasyonu için ayrılır.
     */
    fun generateCertificate(id: String, hostname: String): CertGenResult {
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(2048)

        val primaryKeyPair = keyPairGen.generateKeyPair()
        val backupKeyPair = keyPairGen.generateKeyPair()

        val subject = X500Name("CN=$hostname, O=PinVault Demo, C=TR")
        val notBefore = Date()
        val notAfter = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)
        val serial = BigInteger.valueOf(System.currentTimeMillis())

        val certBuilder = JcaX509v3CertificateBuilder(
            subject, serial, notBefore, notAfter, subject, primaryKeyPair.public
        )

        // Subject Alternative Names
        certBuilder.addExtension(
            Extension.subjectAlternativeName, false, buildSanNames(hostname)
        )

        val signer = JcaContentSignerBuilder("SHA256withRSA").build(primaryKeyPair.private)
        val cert = JcaX509CertificateConverter().getCertificate(certBuilder.build(signer))

        // JKS keystore
        val keyStore = KeyStore.getInstance("JKS")
        keyStore.load(null, null)
        keyStore.setKeyEntry("server", primaryKeyPair.private, KEYSTORE_PASSWORD.toCharArray(), arrayOf(cert))

        val jksFile = File(certsDir, "$id.jks")
        jksFile.outputStream().use { keyStore.store(it, KEYSTORE_PASSWORD.toCharArray()) }

        val primaryHash = extractHash(cert)
        val backupHash = sha256Base64(backupKeyPair.public.encoded)

        return CertGenResult(
            keystorePath = jksFile.absolutePath,
            sha256Pins = listOf(primaryHash, backupHash),
            validUntil = notAfter.toInstant().toString()
        )
    }

    /**
     * Harici sertifika dosyasını import eder (JKS, PKCS12).
     */
    fun importCertificate(id: String, fileBytes: ByteArray, password: String, format: String): CertGenResult {
        val storeType = when (format.lowercase()) {
            "jks" -> "JKS"
            "pkcs12", "p12", "pfx" -> "PKCS12"
            else -> throw IllegalArgumentException("Desteklenmeyen format: $format (jks, pkcs12, p12, pfx)")
        }

        val sourceKs = KeyStore.getInstance(storeType)
        fileBytes.inputStream().use { sourceKs.load(it, password.toCharArray()) }

        val alias = sourceKs.aliases().asSequence().firstOrNull { sourceKs.isKeyEntry(it) }
            ?: throw IllegalArgumentException("Keystore'da private key entry bulunamadı")

        val key = sourceKs.getKey(alias, password.toCharArray())
            ?: throw IllegalArgumentException("Private key okunamadı")
        val chain = sourceKs.getCertificateChain(alias)
            ?: throw IllegalArgumentException("Sertifika zinciri bulunamadı")

        val cert = chain[0] as X509Certificate

        // JKS olarak kaydet
        val jksKs = KeyStore.getInstance("JKS")
        jksKs.load(null, null)
        jksKs.setKeyEntry("server", key, KEYSTORE_PASSWORD.toCharArray(), chain)

        val jksFile = File(certsDir, "$id.jks")
        jksFile.outputStream().use { jksKs.store(it, KEYSTORE_PASSWORD.toCharArray()) }

        val primaryHash = extractHash(cert)
        val backupHash = if (chain.size > 1) extractHash(chain[1]) else primaryHash

        return CertGenResult(
            keystorePath = jksFile.absolutePath,
            sha256Pins = listOf(primaryHash, backupHash),
            validUntil = cert.notAfter.toInstant().toString()
        )
    }

    /**
     * Uzak sunucuya TLS bağlantısı kurup sertifikayı çeker, hash hesaplar.
     */
    fun fetchFromUrl(url: String): FetchResult {
        val parsedUrl = java.net.URL(url)
        val hostname = parsedUrl.host
        val port = if (parsedUrl.port > 0) parsedUrl.port else 443

        // Tüm sertifikaları kabul eden TrustManager
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, java.security.SecureRandom())

        val factory = sslContext.socketFactory
        val socket = factory.createSocket(hostname, port) as javax.net.ssl.SSLSocket
        socket.use {
            it.startHandshake()
            val chain = it.session.peerCertificates
            if (chain.isEmpty()) throw RuntimeException("Sertifika zinciri boş")

            val leaf = chain[0] as X509Certificate
            val primaryHash = extractHash(leaf)
            val backupHash = if (chain.size > 1) extractHash(chain[1]) else primaryHash

            val pubKey = leaf.publicKey
            val keyBits = if (pubKey is RSAPublicKey) pubKey.modulus.bitLength() else 0

            val sanList = mutableListOf<String>()
            leaf.subjectAlternativeNames?.forEach { san ->
                val type = san[0] as Int
                val value = san[1].toString()
                sanList += when (type) {
                    2 -> "DNS: $value"
                    7 -> "IP: $value"
                    else -> value
                }
            }

            val fingerprint = MessageDigest.getInstance("SHA-256")
                .digest(leaf.encoded)
                .joinToString(":") { "%02X".format(it) }

            return FetchResult(
                hostname = hostname,
                sha256Pins = listOf(primaryHash, backupHash),
                certInfo = CertInfo(
                    subject = leaf.subjectX500Principal.name,
                    issuer = leaf.issuerX500Principal.name,
                    serialNumber = leaf.serialNumber.toString(16).uppercase(),
                    validFrom = leaf.notBefore.toInstant().toString(),
                    validUntil = leaf.notAfter.toInstant().toString(),
                    signatureAlgorithm = leaf.sigAlgName,
                    publicKeyAlgorithm = pubKey.algorithm,
                    publicKeyBits = keyBits,
                    subjectAltNames = sanList,
                    sha256Fingerprint = fingerprint,
                    primaryPin = primaryHash,
                    backupPin = backupHash
                )
            )
        }
    }

    /**
     * Keystore'dan sertifika bilgilerini okur.
     */
    fun readCertInfo(keystorePath: String, sha256Pins: List<String>): CertInfo {
        val keyStore = KeyStore.getInstance("JKS")
        FileInputStream(keystorePath).use { keyStore.load(it, KEYSTORE_PASSWORD.toCharArray()) }
        val cert = keyStore.getCertificate("server") as X509Certificate

        val sanList = mutableListOf<String>()
        cert.subjectAlternativeNames?.forEach { san ->
            val type = san[0] as Int
            val value = san[1].toString()
            sanList += when (type) {
                2 -> "DNS: $value"
                7 -> "IP: $value"
                else -> value
            }
        }

        val fingerprint = MessageDigest.getInstance("SHA-256")
            .digest(cert.encoded)
            .joinToString(":") { "%02X".format(it) }

        val pubKey = cert.publicKey
        val keyBits = if (pubKey is RSAPublicKey) pubKey.modulus.bitLength() else 0

        return CertInfo(
            subject = cert.subjectX500Principal.name,
            issuer = cert.issuerX500Principal.name,
            serialNumber = cert.serialNumber.toString(16).uppercase(),
            validFrom = cert.notBefore.toInstant().toString(),
            validUntil = cert.notAfter.toInstant().toString(),
            signatureAlgorithm = cert.sigAlgName,
            publicKeyAlgorithm = pubKey.algorithm,
            publicKeyBits = keyBits,
            subjectAltNames = sanList,
            sha256Fingerprint = fingerprint,
            primaryPin = sha256Pins.getOrElse(0) { "" },
            backupPin = sha256Pins.getOrElse(1) { "" }
        )
    }

    fun extractHashFromKeystore(keystorePath: String): String {
        val keyStore = KeyStore.getInstance("JKS")
        FileInputStream(keystorePath).use { keyStore.load(it, KEYSTORE_PASSWORD.toCharArray()) }
        return extractHash(keyStore.getCertificate("server"))
    }

    private fun extractHash(cert: Certificate): String = sha256Base64(cert.publicKey.encoded)

    private fun sha256Base64(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return Base64.getEncoder().encodeToString(digest)
    }

    private fun buildSanNames(hostname: String): GeneralNames {
        val host = hostname
        val names = mutableListOf<GeneralName>()
        names.add(GeneralName(GeneralName.dNSName, host))

        // Emülatör desteği: her sertifikaya 10.0.2.2 ve localhost ekle
        names.add(GeneralName(GeneralName.iPAddress, "10.0.2.2"))
        names.add(GeneralName(GeneralName.iPAddress, "127.0.0.1"))
        names.add(GeneralName(GeneralName.dNSName, "localhost"))

        if (host.matches(Regex("\\d+\\.\\d+\\.\\d+\\.\\d+"))) {
            names.add(GeneralName(GeneralName.iPAddress, host))
        }

        // Fiziksel cihaz desteği: makinanın tüm LAN IP'lerini ekle
        try {
            java.net.NetworkInterface.getNetworkInterfaces()?.toList()
                ?.flatMap { it.inetAddresses.toList() }
                ?.filter { it is java.net.Inet4Address && !it.isLoopbackAddress }
                ?.map { it.hostAddress }
                ?.forEach { ip ->
                    names.add(GeneralName(GeneralName.iPAddress, ip))
                }
        } catch (_: Exception) {}

        return GeneralNames(names.toTypedArray())
    }

    // ── mTLS Client Certificate ───────────────────────────

    private val trustStoreFile = File(certsDir, "client-truststore.jks")

    /**
     * Client sertifikası üretir (PKCS12 formatında).
     * Public cert'i truststore'a ekler (sunucu tarafı doğrulama için).
     */
    fun generateClientCertificate(clientId: String): ClientCertResult {
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(2048)
        val keyPair = keyPairGen.generateKeyPair()

        val cn = "PinVault Client: $clientId"
        val subject = X500Name("CN=$cn, O=PinVault Client, C=TR")
        val notBefore = Date()
        val notAfter = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)
        val serial = BigInteger.valueOf(System.currentTimeMillis())

        val certBuilder = JcaX509v3CertificateBuilder(
            subject, serial, notBefore, notAfter, subject, keyPair.public
        )

        val signer = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)
        val cert = JcaX509CertificateConverter().getCertificate(certBuilder.build(signer))

        // PKCS12 keystore — Android uyumlu format (legacy algorithm for Android 11 compat)
        val p12Bytes = buildAndroidCompatP12(clientId, keyPair.private, cert, KEYSTORE_PASSWORD)

        // Client cert'i truststore'a ekle
        addToTrustStore(clientId, cert)

        val fingerprint = sha256Base64(cert.encoded)

        return ClientCertResult(
            p12Bytes = p12Bytes,
            fingerprint = fingerprint,
            commonName = cn,
            validUntil = notAfter.toInstant().toString()
        )
    }

    /**
     * Dışarıdan client cert upload — PEM/DER formatında.
     * Truststore'a ekler.
     */
    fun importClientCertificate(clientId: String, certBytes: ByteArray): String {
        val cf = java.security.cert.CertificateFactory.getInstance("X.509")
        val cert = cf.generateCertificate(certBytes.inputStream()) as X509Certificate
        addToTrustStore(clientId, cert)
        return sha256Base64(cert.encoded)
    }

    fun removeFromTrustStore(clientId: String) {
        if (!trustStoreFile.exists()) return
        val ts = KeyStore.getInstance("JKS")
        FileInputStream(trustStoreFile).use { ts.load(it, KEYSTORE_PASSWORD.toCharArray()) }
        ts.deleteEntry(clientId)
        trustStoreFile.outputStream().use { ts.store(it, KEYSTORE_PASSWORD.toCharArray()) }
    }

    fun getTrustStore(): KeyStore? {
        if (!trustStoreFile.exists()) return null
        val ts = KeyStore.getInstance("JKS")
        FileInputStream(trustStoreFile).use { ts.load(it, KEYSTORE_PASSWORD.toCharArray()) }
        return ts
    }

    fun getTrustStoreFile(): File = trustStoreFile

    private fun addToTrustStore(alias: String, cert: X509Certificate) {
        val ts = KeyStore.getInstance("JKS")
        if (trustStoreFile.exists()) {
            FileInputStream(trustStoreFile).use { ts.load(it, KEYSTORE_PASSWORD.toCharArray()) }
        } else {
            ts.load(null, null)
        }
        ts.setCertificateEntry(alias, cert)
        trustStoreFile.outputStream().use { ts.store(it, KEYSTORE_PASSWORD.toCharArray()) }
    }

    /**
     * Android 11+ uyumlu PKCS12 üretir.
     * JDK 17+ varsayılan olarak PBES2/AES kullanır — Android 11 bunu desteklemez.
     * BouncyCastle PKCS12 KeyStore legacy algoritma kullanır:
     *   Key: pbeWithSHAAnd3_KeyTripleDES_CBC
     *   Cert: pbeWithSHAAnd40BitRC2_CBC
     *   MAC: SHA-1
     */
    private fun buildAndroidCompatP12(
        alias: String,
        privateKey: java.security.PrivateKey,
        cert: X509Certificate,
        password: String
    ): ByteArray {
        val ks = KeyStore.getInstance("PKCS12", "BC")
        ks.load(null, null)
        ks.setKeyEntry(alias, privateKey, password.toCharArray(), arrayOf(cert))

        val baos = java.io.ByteArrayOutputStream()
        ks.store(baos, password.toCharArray())
        return baos.toByteArray()
    }

    companion object {
        const val KEYSTORE_PASSWORD = "changeit"
    }
}
