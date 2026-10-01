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
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
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

/**
 * The site served its certificate alone. A fetched host's backup pin is the
 * issuer's (devices accept any leaf that chains to it), and the server holds
 * no key for a site it only looked at — so there is no second pin to offer.
 */
class NoSecondCertificateException(val host: String) : IllegalStateException(
    "$host serves a single certificate, so there is no issuer to pin as the backup. Enter the pins by hand: " +
        "the site's pin and the pin of a backup key its owner keeps."
)

class CertificateService(
    private val certsDir: File,
    /**
     * Extra Subject Alternative Names (IPv4 literals or DNS names) added to
     * every certificate this service generates. The interface scan in
     * [buildSanNames] only sees the machine the server runs on; inside a
     * container that is the container's private address, not the LAN IP a
     * phone connects to, so TLS hostname verification would fail on the
     * device. Defaults to the comma-separated `EXTRA_CERT_SANS` env var.
     */
    private val extraSans: List<String> = parseExtraSans(System.getenv("EXTRA_CERT_SANS"))
) {

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
     *
     * Primary key TLS için kullanılır. Backup key'in pin'i listeye girer ve
     * anahtarın kendisi `<id>.backup.jks` dosyasında saklanır: [rotateToBackup]
     * sertifikayı ona geçirdiğinde cihazlar pin'ini zaten tuttuğu için bağlantı
     * kesilmez. (Eskiden backup key üretilip atılıyordu; pin'i hiçbir zaman
     * kullanılamıyordu.)
     */
    fun generateCertificate(id: String, hostname: String): CertGenResult {
        val primaryKeyPair = newRsaKeyPair()
        val backupKeyPair = newRsaKeyPair()

        val (jksFile, cert) = writeServerKeystore(id, hostname, primaryKeyPair)
        writeBackupKey(id, hostname, backupKeyPair)

        return CertGenResult(
            keystorePath = jksFile.absolutePath,
            sha256Pins = listOf(extractHash(cert), sha256Base64(backupKeyPair.public.encoded)),
            validUntil = cert.notAfter.toInstant().toString()
        )
    }

    /**
     * Pin of the backup key stored for [id], or null when there is none —
     * the certificate was uploaded or fetched, or generated before backup
     * keys were kept.
     */
    fun backupPin(id: String): String? {
        val file = backupKeyFile(id)
        if (!file.exists()) return null
        val ks = KeyStore.getInstance("JKS")
        FileInputStream(file).use { ks.load(it, KEYSTORE_PASSWORD.toCharArray()) }
        return ks.getCertificate(BACKUP_ALIAS)?.let { extractHash(it) }
    }

    /**
     * Serves [hostname] from its stored backup key and prepares a new backup.
     *
     * Devices already hold the backup key's pin — it was published next to
     * the primary — so they keep connecting: no app update, no config
     * refresh. The returned pins (the old backup, now serving, and the new
     * backup) are what to publish next; the old primary drops out.
     */
    fun rotateToBackup(id: String, hostname: String): CertGenResult {
        val file = backupKeyFile(id)
        check(file.exists()) { "No stored backup key for $id" }
        val ks = KeyStore.getInstance("JKS")
        FileInputStream(file).use { ks.load(it, KEYSTORE_PASSWORD.toCharArray()) }
        val promoted = KeyPair(
            ks.getCertificate(BACKUP_ALIAS).publicKey,
            ks.getKey(BACKUP_ALIAS, KEYSTORE_PASSWORD.toCharArray()) as PrivateKey
        )
        val nextBackup = newRsaKeyPair()

        val (jksFile, cert) = writeServerKeystore(id, hostname, promoted)
        writeBackupKey(id, hostname, nextBackup)

        return CertGenResult(
            keystorePath = jksFile.absolutePath,
            sha256Pins = listOf(extractHash(cert), sha256Base64(nextBackup.public.encoded)),
            validUntil = cert.notAfter.toInstant().toString()
        )
    }

    private fun newRsaKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun backupKeyFile(id: String) = File(certsDir, "$id.backup.jks")

    private fun selfSignedCertificate(hostname: String, keyPair: KeyPair): X509Certificate {
        val subject = X500Name("CN=$hostname, O=PinVault Demo, C=TR")
        val notBefore = Date()
        val notAfter = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)
        val serial = BigInteger.valueOf(System.currentTimeMillis())

        val certBuilder = JcaX509v3CertificateBuilder(
            subject, serial, notBefore, notAfter, subject, keyPair.public
        )

        // Subject Alternative Names
        certBuilder.addExtension(
            Extension.subjectAlternativeName, false, buildSanNames(hostname)
        )

        val signer = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)
        return JcaX509CertificateConverter().getCertificate(certBuilder.build(signer))
    }

    /** The TLS keystore (`<id>.jks`, alias "server") serving [hostname] from [keyPair]. */
    private fun writeServerKeystore(id: String, hostname: String, keyPair: KeyPair): Pair<File, X509Certificate> {
        val cert = selfSignedCertificate(hostname, keyPair)
        val keyStore = KeyStore.getInstance("JKS")
        keyStore.load(null, null)
        keyStore.setKeyEntry("server", keyPair.private, KEYSTORE_PASSWORD.toCharArray(), arrayOf(cert))

        val jksFile = File(certsDir, "$id.jks")
        jksFile.outputStream().use { keyStore.store(it, KEYSTORE_PASSWORD.toCharArray()) }
        return jksFile to cert
    }

    // A separate file, not a second entry in `<id>.jks`: the TLS listeners
    // load that keystore and must only ever see the serving key. JKS keeps a
    // private key only with a certificate, so the backup carries a
    // self-signed placeholder that is never served.
    private fun writeBackupKey(id: String, hostname: String, keyPair: KeyPair) {
        val cert = selfSignedCertificate(hostname, keyPair)
        val keyStore = KeyStore.getInstance("JKS")
        keyStore.load(null, null)
        keyStore.setKeyEntry(BACKUP_ALIAS, keyPair.private, KEYSTORE_PASSWORD.toCharArray(), arrayOf(cert))
        backupKeyFile(id).outputStream().use { keyStore.store(it, KEYSTORE_PASSWORD.toCharArray()) }
    }

    /**
     * Harici sertifika dosyasını import eder (JKS, PKCS12).
     *
     * The backup pin belongs to a key generated here and kept in
     * `<id>.backup.jks`, as for a generated certificate, so [rotateToBackup]
     * works for uploaded certificates too. The uploaded chain's issuer is not
     * used: the server holds the uploaded key anyway, and its own backup key
     * does not widen trust to everything the issuer signs. [hostname] names
     * the backup's placeholder certificate.
     */
    fun importCertificate(id: String, fileBytes: ByteArray, password: String, format: String, hostname: String): CertGenResult {
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
        // Replaces any backup kept for an earlier certificate of this id.
        val backupKeyPair = newRsaKeyPair()
        writeBackupKey(id, hostname, backupKeyPair)

        return CertGenResult(
            keystorePath = jksFile.absolutePath,
            sha256Pins = listOf(extractHash(cert), sha256Base64(backupKeyPair.public.encoded)),
            validUntil = cert.notAfter.toInstant().toString()
        )
    }

    /**
     * Uzak sunucuya TLS bağlantısı kurup sertifikayı çeker, hash hesaplar.
     *
     * SECURITY (audit L-4): this is an ADMIN-ONLY diagnostic — reachable only
     * behind the API key (see ApiKeyAuth / H-1). It intentionally trusts ANY
     * server certificate, because its whole job is to inspect arbitrary (often
     * self-signed / internal lab) hosts and compute their pins. We require an
     * https URL, but deliberately do NOT block private/LAN targets: the demo's
     * purpose includes pinning internal mock hosts (e.g. 192.168.x.x). A
     * production deployment exposing this MUST add SSRF egress controls
     * (allowlist, reject RFC1918 / loopback / link-local, re-check after DNS).
     */
    fun fetchFromUrl(url: String): FetchResult {
        val parsedUrl = java.net.URL(url)
        require(parsedUrl.protocol.equals("https", ignoreCase = true)) {
            "fetch-from-url requires an https:// URL (got '${parsedUrl.protocol}')"
        }
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

            // The backup is the issuer's pin: devices accept a leaf that
            // chains to it, so the host survives a renewal by the same CA.
            if (chain.size < 2) throw NoSecondCertificateException(hostname)
            val leaf = chain[0] as X509Certificate
            val primaryHash = extractHash(leaf)
            val backupHash = extractHash(chain[1])

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

        // Operator-supplied names, e.g. the Docker host's LAN IP (EXTRA_CERT_SANS).
        extraSans.forEach { san ->
            names.add(
                if (IPV4_LITERAL.matches(san)) GeneralName(GeneralName.iPAddress, san)
                else GeneralName(GeneralName.dNSName, san)
            )
        }

        return GeneralNames(names.distinct().toTypedArray())
    }

    // ── mTLS Client Certificate ───────────────────────────

    private val trustStoreFile = File(certsDir, "client-truststore.jks")

    /**
     * Client sertifikası üretir (PKCS12 formatında).
     * Public cert'i truststore'a ekler (sunucu tarafı doğrulama için).
     */
    /**
     * `CN=<cn>, O=PinVault Client, C=TR`, built name part by name part: a
     * client id containing `,` or `=` cannot add parts of its own (string
     * parsing would have read `x, O=Evil` as two).
     */
    private fun clientSubject(cn: String): X500Name =
        org.bouncycastle.asn1.x500.X500NameBuilder(org.bouncycastle.asn1.x500.style.BCStyle.INSTANCE)
            .addRDN(org.bouncycastle.asn1.x500.style.BCStyle.CN, cn)
            .addRDN(org.bouncycastle.asn1.x500.style.BCStyle.O, "PinVault Client")
            .addRDN(org.bouncycastle.asn1.x500.style.BCStyle.C, "TR")
            .build()

    fun generateClientCertificate(clientId: String, p12Password: String): ClientCertResult {
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(2048)
        val keyPair = keyPairGen.generateKeyPair()

        val cn = "PinVault Client: $clientId"
        val subject = clientSubject(cn)
        val notBefore = Date()
        val notAfter = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000)
        val serial = BigInteger.valueOf(System.currentTimeMillis())

        val certBuilder = JcaX509v3CertificateBuilder(
            subject, serial, notBefore, notAfter, subject, keyPair.public
        )

        val signer = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)
        val cert = JcaX509CertificateConverter().getCertificate(certBuilder.build(signer))

        // PKCS12 keystore — Android uyumlu format (legacy algorithm for Android 11 compat).
        // Wrapped for its recipient (see P12Transfer), never with KEYSTORE_PASSWORD.
        val p12Bytes = buildAndroidCompatP12(clientId, keyPair.private, cert, p12Password)

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

    // ── Client CA: certificates over device-held keys (CSR enrollment) ──

    private val clientCaFile = File(certsDir, "client-ca.jks")

    fun clientCaFile(): File = clientCaFile

    /**
     * The client CA that signs every CSR-enrolled device certificate. Created
     * on first use (EC P-256, ten years) in `client-ca.jks` under
     * [KEYSTORE_PASSWORD], and its certificate is kept in the client
     * truststore under [CLIENT_CA_ALIAS] so the mTLS listeners accept what
     * it signs. Idempotent — safe to call at every start.
     */
    fun ensureClientCa(): X509Certificate {
        loadClientCa()?.let { (_, cert) ->
            if (getTrustStore()?.getCertificate(CLIENT_CA_ALIAS) == null) addToTrustStore(CLIENT_CA_ALIAS, cert)
            return cert
        }
        val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val name = X500Name("CN=PinVault Client CA, O=PinVault, C=TR")
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            name, randomSerial(), Date(now - CLOCK_SKEW_MS), Date(now + 3650L * DAY_MS), name, keyPair.public
        )
        val ext = org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils()
        builder.addExtension(Extension.basicConstraints, true, org.bouncycastle.asn1.x509.BasicConstraints(true))
        builder.addExtension(Extension.keyUsage, true,
            org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.keyCertSign or org.bouncycastle.asn1.x509.KeyUsage.cRLSign))
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(keyPair.public))
        val cert = JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.private))
        )

        val ks = KeyStore.getInstance("JKS").apply { load(null, null) }
        ks.setKeyEntry(CLIENT_CA_ALIAS, keyPair.private, KEYSTORE_PASSWORD.toCharArray(), arrayOf(cert))
        clientCaFile.outputStream().use { ks.store(it, KEYSTORE_PASSWORD.toCharArray()) }
        addToTrustStore(CLIENT_CA_ALIAS, cert)
        return cert
    }

    fun clientCaCertificate(): X509Certificate = loadClientCa()?.second ?: ensureClientCa()

    private fun loadClientCa(): Pair<PrivateKey, X509Certificate>? {
        if (!clientCaFile.exists()) return null
        val ks = KeyStore.getInstance("JKS")
        FileInputStream(clientCaFile).use { ks.load(it, KEYSTORE_PASSWORD.toCharArray()) }
        val key = ks.getKey(CLIENT_CA_ALIAS, KEYSTORE_PASSWORD.toCharArray()) as? PrivateKey ?: return null
        val cert = ks.getCertificate(CLIENT_CA_ALIAS) as? X509Certificate ?: return null
        return key to cert
    }

    /** A device's CSR after its proof of possession was checked. Only the key is taken from it. */
    class ParsedCsr(val publicKey: java.security.PublicKey, val spkiSha256: String)

    /**
     * Parses a DER PKCS#10 request and verifies its self-signature (proof
     * that the sender holds the private key). The subject is deliberately not
     * read: the certificate is named after the enrolled client id, never
     * after what the request asks for.
     *
     * @throws IllegalArgumentException when the request is malformed, its
     *         signature does not verify, or its key is too weak.
     */
    fun parseCsr(csrDer: ByteArray): ParsedCsr {
        val csr = try {
            org.bouncycastle.pkcs.PKCS10CertificationRequest(csrDer)
        } catch (e: Exception) {
            throw IllegalArgumentException("CSR is not a valid PKCS#10 request", e)
        }
        val verifier = org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
            .setProvider("BC").build(csr.subjectPublicKeyInfo)
        if (!csr.isSignatureValid(verifier)) throw IllegalArgumentException("CSR signature is invalid")

        val publicKey = org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().setProvider("BC").getPublicKey(csr.subjectPublicKeyInfo)
        when (publicKey) {
            is java.security.interfaces.ECPublicKey ->
                require(publicKey.params.order.bitLength() >= 256) { "EC key too small" }
            is RSAPublicKey ->
                require(publicKey.modulus.bitLength() >= 2048) { "RSA key too small" }
            else -> throw IllegalArgumentException("Unsupported key algorithm ${publicKey.algorithm}")
        }
        return ParsedCsr(publicKey, sha256Base64(publicKey.encoded))
    }

    data class IssuedClientCert(
        val leaf: X509Certificate,
        val issuer: X509Certificate,
        /** PEM, leaf first then the client CA. */
        val chainPem: List<String>,
        val commonName: String,
        val spkiSha256: String,
        val serialHex: String,
        val notBefore: java.time.Instant,
        val notAfter: java.time.Instant
    ) {
        /** SHA-256 of the leaf's DER, Base64 — the `client_certs.fingerprint` form. */
        val fingerprint: String get() = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(leaf.encoded))
    }

    /**
     * Signs a client certificate over [csr]'s key with the client CA.
     * `CN=PinVault Client: <clientId>`, a random serial, `notBefore` an hour
     * back for device clock skew, [ttl] of lifetime; client-auth only, no CA
     * bit. Touches neither the truststore nor the database.
     */
    fun issueClientCertificate(clientId: String, csr: ParsedCsr, ttl: java.time.Duration): IssuedClientCert {
        val (caKey, caCert) = loadClientCa() ?: (ensureClientCa().let { loadClientCa()!! })
        val cn = "PinVault Client: $clientId"
        val subject = clientSubject(cn)
        val now = System.currentTimeMillis()
        val notBefore = Date(now - CLOCK_SKEW_MS)
        val notAfter = Date(now + ttl.toMillis())
        val serial = randomSerial()

        val builder = JcaX509v3CertificateBuilder(caCert, serial, notBefore, notAfter, subject, csr.publicKey)
        val ext = org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils()
        builder.addExtension(Extension.basicConstraints, true, org.bouncycastle.asn1.x509.BasicConstraints(false))
        builder.addExtension(Extension.keyUsage, true, org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature))
        builder.addExtension(Extension.extendedKeyUsage, false,
            org.bouncycastle.asn1.x509.ExtendedKeyUsage(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth))
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(csr.publicKey))
        builder.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(caCert))

        val leaf = JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(caKey))
        )
        return IssuedClientCert(
            leaf = leaf,
            issuer = caCert,
            chainPem = listOf(toPem(leaf), toPem(caCert)),
            commonName = cn,
            spkiSha256 = csr.spkiSha256,
            serialHex = serial.toString(16),
            notBefore = notBefore.toInstant(),
            notAfter = notAfter.toInstant()
        )
    }

    /** SHA-256 of a key's SubjectPublicKeyInfo, Base64 — the pin form. */
    fun spkiSha256(publicKey: java.security.PublicKey): String = sha256Base64(publicKey.encoded)

    // ── Server CA: the recovery listener's trust anchor ──────────────────

    private val serverCaFile = File(certsDir, "server-ca.jks")
    private val serverCaBackupFile = File(certsDir, "server-ca.backup.jks")
    private val recoveryKeystoreFile = File(certsDir, "recovery.jks")

    fun serverCaFile(): File = serverCaFile
    fun serverCaBackupFile(): File = serverCaBackupFile
    fun recoveryKeystoreFile(): File = recoveryKeystoreFile

    /**
     * The CA that signs the certificate-renewal (recovery) listener's TLS
     * certificate — and nothing else. Apps pin this CA's key for that one
     * `host:port`, so the listener stays reachable however often its own
     * certificate is replaced; the Config API ports keep their leaf pins.
     *
     * Two keys, like every pinned identity here: the active CA
     * (`server-ca.jks`) and a backup (`server-ca.backup.jks`) whose pin apps
     * also carry, to switch to if the active CA key is lost. Both under
     * [KEYSTORE_PASSWORD]. EC P-256, ten years. Idempotent.
     *
     * @return the active CA certificate and both pins (active, backup).
     */
    fun ensureServerCa(): ServerCa {
        val active = loadCa(serverCaFile, SERVER_CA_ALIAS) ?: writeCa(serverCaFile, SERVER_CA_ALIAS, "PinVault Server CA")
        val backup = loadCa(serverCaBackupFile, SERVER_CA_ALIAS) ?: writeCa(serverCaBackupFile, SERVER_CA_ALIAS, "PinVault Server CA (backup)")
        return ServerCa(active.second, listOf(spkiSha256(active.second.publicKey), spkiSha256(backup.second.publicKey)))
    }

    data class ServerCa(val certificate: X509Certificate, val pins: List<String>)

    data class RecoveryCertificate(val keystore: File, val leaf: X509Certificate, val issuer: X509Certificate, val regenerated: Boolean)

    /**
     * The recovery listener's TLS keystore (`recovery.jks`, alias `server`):
     * a fresh EC key and a certificate signed by the server CA, stored with
     * the chain `[leaf, CA]` so the CA travels in the handshake — devices
     * pin the CA and need it in the served chain to check the leaf against.
     *
     * Reissued (new key) when missing, unreadable, not from the current CA,
     * or within [renewBeforeDays] of expiry; otherwise left as it is. Leaf
     * lifetime [leafDays]; SANs as for every server certificate here.
     */
    fun ensureRecoveryCertificate(hostname: String = "localhost", leafDays: Long = 397, renewBeforeDays: Long = 30): RecoveryCertificate {
        val (caKey, caCert) = loadCa(serverCaFile, SERVER_CA_ALIAS) ?: ensureServerCa().let { loadCa(serverCaFile, SERVER_CA_ALIAS)!! }

        runCatching {
            val ks = KeyStore.getInstance("JKS")
            FileInputStream(recoveryKeystoreFile).use { ks.load(it, KEYSTORE_PASSWORD.toCharArray()) }
            val chain = ks.getCertificateChain("server")?.map { it as X509Certificate }
            val leaf = chain?.firstOrNull()
            val fresh = leaf != null &&
                leaf.notAfter.time - System.currentTimeMillis() > renewBeforeDays * DAY_MS &&
                runCatching { leaf.verify(caCert.publicKey) }.isSuccess
            if (fresh) return RecoveryCertificate(recoveryKeystoreFile, leaf!!, caCert, regenerated = false)
        }

        val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            caCert, randomSerial(), Date(now - CLOCK_SKEW_MS), Date(now + leafDays * DAY_MS),
            X500Name("CN=$hostname, O=PinVault Recovery, C=TR"), keyPair.public
        )
        val ext = org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils()
        builder.addExtension(Extension.subjectAlternativeName, false, buildSanNames(hostname))
        builder.addExtension(Extension.basicConstraints, true, org.bouncycastle.asn1.x509.BasicConstraints(false))
        builder.addExtension(Extension.keyUsage, true, org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature))
        builder.addExtension(Extension.extendedKeyUsage, false,
            org.bouncycastle.asn1.x509.ExtendedKeyUsage(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth))
        builder.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(caCert))
        val leaf = JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(caKey))
        )
        val ks = KeyStore.getInstance("JKS").apply { load(null, null) }
        ks.setKeyEntry("server", keyPair.private, KEYSTORE_PASSWORD.toCharArray(), arrayOf(leaf, caCert))
        recoveryKeystoreFile.outputStream().use { ks.store(it, KEYSTORE_PASSWORD.toCharArray()) }
        return RecoveryCertificate(recoveryKeystoreFile, leaf, caCert, regenerated = true)
    }

    private fun loadCa(file: File, alias: String): Pair<PrivateKey, X509Certificate>? {
        if (!file.exists()) return null
        val ks = KeyStore.getInstance("JKS")
        FileInputStream(file).use { ks.load(it, KEYSTORE_PASSWORD.toCharArray()) }
        val key = ks.getKey(alias, KEYSTORE_PASSWORD.toCharArray()) as? PrivateKey ?: return null
        val cert = ks.getCertificate(alias) as? X509Certificate ?: return null
        return key to cert
    }

    private fun writeCa(file: File, alias: String, commonName: String): Pair<PrivateKey, X509Certificate> {
        val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val name = X500Name("CN=$commonName, O=PinVault, C=TR")
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            name, randomSerial(), Date(now - CLOCK_SKEW_MS), Date(now + 3650L * DAY_MS), name, keyPair.public
        )
        val ext = org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils()
        builder.addExtension(Extension.basicConstraints, true, org.bouncycastle.asn1.x509.BasicConstraints(0))
        builder.addExtension(Extension.keyUsage, true,
            org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.keyCertSign or org.bouncycastle.asn1.x509.KeyUsage.cRLSign))
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(keyPair.public))
        val cert = JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.private))
        )
        val ks = KeyStore.getInstance("JKS").apply { load(null, null) }
        ks.setKeyEntry(alias, keyPair.private, KEYSTORE_PASSWORD.toCharArray(), arrayOf(cert))
        file.outputStream().use { ks.store(it, KEYSTORE_PASSWORD.toCharArray()) }
        return keyPair.private to cert
    }

    private fun randomSerial(): BigInteger = BigInteger(63, java.security.SecureRandom())

    private fun toPem(cert: X509Certificate): String =
        "-----BEGIN CERTIFICATE-----\n" +
            Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(cert.encoded) +
            "\n-----END CERTIFICATE-----"

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

    /** The first of [candidates] that opens [p12], or null. */
    fun p12Password(p12: ByteArray, candidates: List<String>): String? = candidates.distinct().firstOrNull { candidate ->
        runCatching { KeyStore.getInstance("PKCS12", "BC").load(p12.inputStream(), candidate.toCharArray()) }.isSuccess
    }

    /** [p12] re-encrypted from [from] to [to], every entry and chain kept, in the Android-compatible format. */
    fun rewrapP12(p12: ByteArray, from: String, to: String): ByteArray {
        val source = KeyStore.getInstance("PKCS12", "BC").apply { load(p12.inputStream(), from.toCharArray()) }
        val target = KeyStore.getInstance("PKCS12", "BC").apply { load(null, null) }
        for (alias in source.aliases().toList()) {
            if (source.isKeyEntry(alias)) {
                target.setKeyEntry(alias, source.getKey(alias, from.toCharArray()), to.toCharArray(), source.getCertificateChain(alias))
            } else {
                target.setCertificateEntry(alias, source.getCertificate(alias))
            }
        }
        return java.io.ByteArrayOutputStream().also { target.store(it, to.toCharArray()) }.toByteArray()
    }

    companion object {
        /**
         * Password protecting the server's own keystores (`*.jks`), the client
         * truststore and the stored host client certificates. Sourced from the
         * `KEYSTORE_PASSWORD` env var. Never sent to devices: a P12 leaves the
         * server wrapped for its recipient (see [P12Transfer]).
         *
         * Falls back to [LEGACY_KEYSTORE_PASSWORD] when unset so a bare
         * development run works; the sample host's setup.sh generates one, and
         * [KeystoreRekey] moves keystores written under an older password to
         * it at startup. (audit L-2 / L-6)
         */
        val KEYSTORE_PASSWORD: String =
            System.getenv("KEYSTORE_PASSWORD")?.takeIf { it.isNotBlank() } ?: LEGACY_KEYSTORE_PASSWORD

        /** What every keystore was written with before `KEYSTORE_PASSWORD` existed. */
        const val LEGACY_KEYSTORE_PASSWORD = "changeit"

        /** Alias of the backup key in `<id>.backup.jks`. */
        private const val BACKUP_ALIAS = "backup"

        /** Alias of the client CA in `client-ca.jks` and in the client truststore. */
        const val CLIENT_CA_ALIAS = "client-ca"

        /** Alias of the server CA in `server-ca.jks` / `server-ca.backup.jks`. */
        const val SERVER_CA_ALIAS = "server-ca"

        /** How far back `notBefore` is set so a device with a slow clock accepts a fresh certificate. */
        const val CLOCK_SKEW_MS = 60 * 60_000L
        private const val DAY_MS = 24 * 60 * 60_000L

        private val IPV4_LITERAL = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
        private val DNS_NAME = Regex("""^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$""")

        /**
         * Parses `EXTRA_CERT_SANS`: a comma-separated list of IPv4 literals
         * and/or DNS names. Invalid entries are logged and skipped so a typo
         * cannot put garbage into a certificate or crash startup.
         */
        internal fun parseExtraSans(raw: String?): List<String> =
            raw.orEmpty()
                .split(',')
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .filter { entry ->
                    val valid = if (IPV4_LITERAL.matches(entry)) {
                        entry.split('.').all { it.toInt() in 0..255 }
                    } else {
                        DNS_NAME.matches(entry)
                    }
                    if (!valid) println("CertificateService: ignoring invalid EXTRA_CERT_SANS entry '$entry'")
                    valid
                }
                .distinct()
    }
}
