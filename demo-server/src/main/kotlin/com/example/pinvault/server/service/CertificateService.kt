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
    val validUntil: String,
    /** SHA-256 of the generated key's SubjectPublicKeyInfo, Base64 (recorded in `client_keys`). */
    val spkiSha256: String = "",
    /** Serial of the issued certificate, hex. */
    val serialHex: String = ""
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
    val certInfo: CertInfo,
    /** The address and port the handshake went to (the one the egress filter checked). */
    val fetchedFrom: String = ""
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
    private val extraSans: List<String> = parseExtraSans(com.example.pinvault.server.service.ServerEnv.get("EXTRA_CERT_SANS")),
    /** Where [fetchFromUrl] may connect (`FETCH_ALLOW_PRIVATE_TARGETS`). */
    private val egress: EgressFilter = EgressFilter.fromEnv()
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
    fun generateCertificate(id: String, hostname: String): CertGenResult = install(id, planGenerated(hostname))

    /**
     * A new certificate for [hostname] with a new backup key, worked out in
     * memory: nothing is written until [install]. See [CertPlan].
     */
    fun planGenerated(hostname: String): CertPlan {
        val primary = newRsaKeyPair()
        val (keystore, cert) = serverKeystoreBytes(hostname, primary)
        val backup = newRsaKeyPair()
        return certPlan("generated", hostname, cert, sha256Base64(backup.public.encoded), keystore, backupKeystoreBytes(hostname, backup))
    }

    /**
     * Pin of the backup key stored for [id], or null when there is none —
     * the certificate was uploaded or fetched, or generated before backup
     * keys were kept.
     */
    fun backupPin(id: String): String? {
        val file = backupKeyFile(id)
        if (!file.exists()) return null
        val ks = ServerKeyStores.load(file, KEYSTORE_PASSWORD.toCharArray())
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
    fun rotateToBackup(id: String, hostname: String): CertGenResult = install(id, planRotation(id, hostname))

    /** [rotateToBackup] as a plan: the stored backup key promoted, a new backup beside it. Nothing is written. */
    fun planRotation(id: String, hostname: String): CertPlan {
        val file = backupKeyFile(id)
        check(file.exists()) { "No stored backup key for $id" }
        val ks = ServerKeyStores.load(file, KEYSTORE_PASSWORD.toCharArray())
        val promoted = KeyPair(
            ks.getCertificate(BACKUP_ALIAS).publicKey,
            ks.getKey(BACKUP_ALIAS, KEYSTORE_PASSWORD.toCharArray()) as PrivateKey
        )
        val (keystore, cert) = serverKeystoreBytes(hostname, promoted)
        val nextBackup = newRsaKeyPair()
        return certPlan("rotated", hostname, cert, sha256Base64(nextBackup.public.encoded), keystore, backupKeystoreBytes(hostname, nextBackup))
    }

    /**
     * Writes the keystores of [plan] as `<id>.jks` and `<id>.backup.jks`:
     * exactly the certificate and backup key the plan names.
     */
    fun install(id: String, plan: CertPlan): CertGenResult {
        val keystore = requireNotNull(plan.keystore) { "A ${plan.source} certificate has no keystore to install" }
        val backup = requireNotNull(plan.backupKeystore) { "A ${plan.source} certificate has no backup key to install" }
        val jksFile = File(certsDir, "$id.jks")
        jksFile.writeBytes(Base64.getDecoder().decode(keystore))
        // Replaces any backup kept for an earlier certificate of this id.
        backupKeyFile(id).writeBytes(Base64.getDecoder().decode(backup))
        return CertGenResult(keystorePath = jksFile.absolutePath, sha256Pins = plan.pins, validUntil = plan.notAfter)
    }

    private fun certPlan(
        source: String, hostname: String, cert: X509Certificate, backupPin: String,
        keystore: ByteArray?, backupKeystore: ByteArray?, fetchedFrom: String? = null
    ) = CertPlan(
        source = source,
        hostname = hostname,
        pins = listOf(extractHash(cert), backupPin),
        subject = cert.subjectX500Principal.name,
        issuer = cert.issuerX500Principal.name,
        notBefore = cert.notBefore.toInstant().toString(),
        notAfter = cert.notAfter.toInstant().toString(),
        fingerprint = MessageDigest.getInstance("SHA-256").digest(cert.encoded).joinToString(":") { "%02X".format(it) },
        fetchedFrom = fetchedFrom,
        keystore = keystore?.let { Base64.getEncoder().encodeToString(it) },
        backupKeystore = backupKeystore?.let { Base64.getEncoder().encodeToString(it) }
    )

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

    /** The TLS keystore (`<id>.jks`, alias "server") serving [hostname] from [keyPair], as bytes. */
    private fun serverKeystoreBytes(hostname: String, keyPair: KeyPair): Pair<ByteArray, X509Certificate> {
        val cert = selfSignedCertificate(hostname, keyPair)
        val keyStore = ServerKeyStores.empty()
        keyStore.setKeyEntry("server", keyPair.private, KEYSTORE_PASSWORD.toCharArray(), arrayOf(cert))
        return java.io.ByteArrayOutputStream().also { keyStore.store(it, KEYSTORE_PASSWORD.toCharArray()) }.toByteArray() to cert
    }

    // A separate file, not a second entry in `<id>.jks`: the TLS listeners
    // load that keystore and must only ever see the serving key. A keystore
    // keeps a private key only with a certificate, so the backup carries a
    // self-signed placeholder that is never served. (The file is PKCS12 like
    // every server keystore; `.jks` is the historical name — ServerKeyStores.)
    private fun backupKeystoreBytes(hostname: String, keyPair: KeyPair): ByteArray {
        val cert = selfSignedCertificate(hostname, keyPair)
        val keyStore = ServerKeyStores.empty()
        keyStore.setKeyEntry(BACKUP_ALIAS, keyPair.private, KEYSTORE_PASSWORD.toCharArray(), arrayOf(cert))
        return java.io.ByteArrayOutputStream().also { keyStore.store(it, KEYSTORE_PASSWORD.toCharArray()) }.toByteArray()
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
    fun importCertificate(id: String, fileBytes: ByteArray, password: String, format: String, hostname: String): CertGenResult =
        install(id, planImported(fileBytes, password, format, hostname))

    /** [importCertificate] as a plan: the uploaded key and chain re-wrapped, a new backup key beside them. Nothing is written. */
    fun planImported(fileBytes: ByteArray, password: String, format: String, hostname: String): CertPlan {
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

        // Re-wrapped in the server's own (PKCS12) keystore form under KEYSTORE_PASSWORD.
        val jksKs = ServerKeyStores.empty()
        jksKs.setKeyEntry("server", key, KEYSTORE_PASSWORD.toCharArray(), chain)
        val keystore = java.io.ByteArrayOutputStream().also { jksKs.store(it, KEYSTORE_PASSWORD.toCharArray()) }.toByteArray()

        val backupKeyPair = newRsaKeyPair()
        return certPlan("uploaded", hostname, cert, sha256Base64(backupKeyPair.public.encoded), keystore, backupKeystoreBytes(hostname, backupKeyPair))
    }

    /**
     * Uzak sunucuya TLS bağlantısı kurup sertifikayı çeker, hash hesaplar.
     *
     * Admin only, and a TLS handshake only: nothing is sent or read beyond it.
     * It trusts ANY server certificate on purpose — its job is to look at a
     * host (often self-signed) and compute its pins. Where it may connect is
     * decided by [egress]: never link-local or cloud-metadata addresses, and
     * loopback / private networks only with `FETCH_ALLOW_PRIVATE_TARGETS=true`.
     * The name is resolved once and the connection goes to the address that
     * was checked (see [EgressFilter]).
     *
     * @throws EgressRefusedException when the target may not be reached.
     */
    fun fetchFromUrl(url: String): FetchResult {
        val parsedUrl = java.net.URL(url)
        require(parsedUrl.protocol.equals("https", ignoreCase = true)) {
            "fetch-from-url requires an https:// URL (got '${parsedUrl.protocol}')"
        }
        val hostname = parsedUrl.host.removePrefix("[").removeSuffix("]")
        require(hostname.isNotBlank()) { "fetch-from-url needs a host name" }
        val port = if (parsedUrl.port > 0) parsedUrl.port else 443
        val address = egress.resolveChecked(hostname)

        // Tüm sertifikaları kabul eden TrustManager
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, java.security.SecureRandom())

        // Connected to the address that was checked, never to the name again.
        val plain = java.net.Socket()
        plain.connect(java.net.InetSocketAddress(address, port), FETCH_TIMEOUT_MS)
        plain.soTimeout = FETCH_TIMEOUT_MS
        val socket = sslContext.socketFactory.createSocket(plain, hostname, port, true) as javax.net.ssl.SSLSocket
        socket.use {
            // A name gets SNI; an IP literal has none.
            if (hostname.any { c -> c.isLetter() } && ':' !in hostname) {
                it.sslParameters = it.sslParameters.apply { serverNames = listOf(javax.net.ssl.SNIHostName(hostname)) }
            }
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
                ),
                fetchedFrom = "${address.hostAddress}:$port"
            )
        }
    }

    /**
     * [fetchFromUrl] as a plan for [hostname] (default: the URL's host): the
     * pins the site serves NOW. There is no keystore — the server only looked.
     */
    fun planFetched(url: String, hostname: String? = null): CertPlan {
        val fetched = fetchFromUrl(url)
        return CertPlan(
            source = "fetched",
            hostname = hostname ?: fetched.hostname,
            pins = fetched.sha256Pins,
            subject = fetched.certInfo.subject,
            issuer = fetched.certInfo.issuer,
            notBefore = fetched.certInfo.validFrom,
            notAfter = fetched.certInfo.validUntil,
            fingerprint = fetched.certInfo.sha256Fingerprint,
            fetchedFrom = "${fetched.hostname} (${fetched.fetchedFrom})"
        )
    }

    /**
     * Keystore'dan sertifika bilgilerini okur.
     */
    fun readCertInfo(keystorePath: String, sha256Pins: List<String>): CertInfo {
        val keyStore = ServerKeyStores.load(File(keystorePath), KEYSTORE_PASSWORD.toCharArray())
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
        val keyStore = ServerKeyStores.load(File(keystorePath), KEYSTORE_PASSWORD.toCharArray())
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

    /**
     * A server-made client identity: a new RSA key and a certificate over it
     * issued by the CLIENT CA — `CN=PinVault Client: <clientId>`, CA:false,
     * client authentication only, a year of lifetime — in an
     * Android-compatible PKCS#12 (leaf, then the CA) wrapped with
     * [p12Password].
     *
     * Touches neither the truststore nor the database: the mTLS listeners
     * already trust the client CA. These certificates used to be self-signed
     * leaves without basicConstraints, each added to the truststore as its
     * own trust anchor; JSSE does not look at the CA flag of an anchor, so
     * the holder of such a P12 could sign a leaf naming ANOTHER client id
     * and be accepted as that device (the identity is read from the CN).
     * Anchors already in a truststore keep working until they expire or the
     * id enrolls again ([removeLegacyAnchor]); every mTLS request checks that
     * the presented leaf is the one on record (RevocationGate).
     */
    fun generateClientCertificate(clientId: String, p12Password: String): ClientCertResult {
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(2048)
        val keyPair = keyPairGen.generateKeyPair()
        // ensureClientCa every time: it also puts the CA back into the client truststore
        // when that file went missing (moved, deleted). Nothing else is added there any
        // more, so without this an mTLS listener stayed unstartable until a restart.
        val (caKey, caCert) = ensureClientCa().let { loadClientCa()!! }

        val cn = "PinVault Client: $clientId"
        val subject = clientSubject(cn)
        val now = System.currentTimeMillis()
        val notBefore = Date(now - CLOCK_SKEW_MS)
        val notAfter = Date(now + 365L * DAY_MS)
        val serial = randomSerial()

        val builder = JcaX509v3CertificateBuilder(caCert, serial, notBefore, notAfter, subject, keyPair.public)
        val ext = org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils()
        builder.addExtension(Extension.basicConstraints, true, org.bouncycastle.asn1.x509.BasicConstraints(false))
        builder.addExtension(Extension.keyUsage, true,
            org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature or org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment))
        builder.addExtension(Extension.extendedKeyUsage, false,
            org.bouncycastle.asn1.x509.ExtendedKeyUsage(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth))
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(keyPair.public))
        builder.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(caCert))
        val cert = JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(caKey))
        )

        // PKCS12 keystore — Android uyumlu format (legacy algorithm for Android 11 compat).
        // Wrapped for its recipient (see P12Transfer), never with KEYSTORE_PASSWORD.
        val p12Bytes = buildAndroidCompatP12(clientId, keyPair.private, arrayOf(cert, caCert), p12Password)

        return ClientCertResult(
            p12Bytes = p12Bytes,
            fingerprint = sha256Base64(cert.encoded),
            commonName = cn,
            validUntil = notAfter.toInstant().toString(),
            spkiSha256 = sha256Base64(keyPair.public.encoded),
            serialHex = serial.toString(16)
        )
    }

    /**
     * Removes the per-certificate trust anchor stored under [clientId] — a
     * self-signed P12 certificate issued before P12s came from the client CA,
     * or an uploaded certificate — when the id enrolls again: the new
     * identity replaces it (D1). Returns the removed certificate (its key is
     * then retired), or null when there was none. Never touches the client CA.
     * The running mTLS listeners keep the old truststore until they restart.
     */
    fun removeLegacyAnchor(clientId: String): X509Certificate? {
        if (clientId == CLIENT_CA_ALIAS) return null
        val ts = getTrustStore() ?: return null
        val cert = ts.getCertificate(clientId) as? X509Certificate ?: return null
        removeFromTrustStore(clientId)
        return cert
    }

    /**
     * Dışarıdan client cert upload — PEM/DER formatında.
     * Truststore'a ekler.
     */
    fun importClientCertificate(clientId: String, certBytes: ByteArray): String {
        // Never over the client CA (or another alias the server keeps): an upload
        // under its name replaced the CA every CSR identity chains to.
        require(!isReservedAlias(clientId)) { "'$clientId' is reserved by the server and cannot be a client id" }
        val cert = parseUploadedClientCertificate(certBytes)
        addToTrustStore(clientId, cert)
        return sha256Base64(cert.encoded)
    }

    /**
     * The certificate in [certBytes] when it may go into the mTLS truststore
     * as ONE client: a single end-entity certificate that is valid now.
     *
     * Refused: a CA (basicConstraints CA, or the keyCertSign usage) — in the
     * truststore it would vouch for every certificate its key signs, so one
     * upload would admit any number of clients nobody listed; a v1/v2
     * certificate (no extensions, so nothing says it is not a CA — JSSE lets
     * such an anchor sign); a certificate without an extended key usage that
     * includes client authentication; one that is expired or not yet valid;
     * anything that is not one X.509 certificate. Whatever is accepted is
     * still believed only as itself: every mTLS request must present the
     * certificate on record for the id its CN names (RevocationGate).
     *
     * @throws IllegalArgumentException with a message safe to show the admin.
     */
    fun parseUploadedClientCertificate(certBytes: ByteArray): X509Certificate {
        val certs = try {
            java.security.cert.CertificateFactory.getInstance("X.509").generateCertificates(certBytes.inputStream())
        } catch (e: java.security.cert.CertificateException) {
            throw IllegalArgumentException("Not an X.509 certificate (PEM or DER)")
        }
        require(certs.size == 1) { "Exactly one certificate is expected, found ${certs.size}" }
        val cert = certs.first() as X509Certificate
        // A v1/v2 certificate has no extensions: nothing says it is not a CA, and
        // JSSE lets such an anchor sign other certificates.
        require(cert.version >= 3) { "A version ${cert.version} certificate cannot be uploaded as a client certificate (it cannot say it is not a CA)" }
        require(cert.basicConstraints < 0) { "A CA certificate cannot be uploaded as a client certificate" }
        // keyUsage bit 5 = keyCertSign.
        require(cert.keyUsage?.getOrNull(5) != true) { "A certificate that may sign certificates (keyCertSign) cannot be uploaded as a client certificate" }
        // A leaf for client authentication, said so: the extension must be there.
        val eku = cert.extendedKeyUsage
        require(eku != null && CLIENT_AUTH_EKU in eku) {
            "The certificate's extended key usage must include client authentication (1.3.6.1.5.5.7.3.2)"
        }
        try {
            cert.checkValidity()
        } catch (e: java.security.cert.CertificateException) {
            throw IllegalArgumentException("The certificate is expired or not yet valid")
        }
        return cert
    }

    fun removeFromTrustStore(clientId: String) {
        // Revoking or forgetting an id named like the client CA removed the CA
        // itself: every CSR identity was then refused at the handshake.
        if (isReservedAlias(clientId)) return
        if (!trustStoreFile.exists()) return
        val ts = ServerKeyStores.load(trustStoreFile, KEYSTORE_PASSWORD.toCharArray())
        ts.deleteEntry(clientId)
        trustStoreFile.outputStream().use { ts.store(it, KEYSTORE_PASSWORD.toCharArray()) }
    }

    fun getTrustStore(): KeyStore? {
        if (!trustStoreFile.exists()) return null
        val ts = ServerKeyStores.load(trustStoreFile, KEYSTORE_PASSWORD.toCharArray())
        return ts
    }

    fun getTrustStoreFile(): File = trustStoreFile

    private fun addToTrustStore(alias: String, cert: X509Certificate) {
        val ts = if (trustStoreFile.exists()) ServerKeyStores.load(trustStoreFile, KEYSTORE_PASSWORD.toCharArray()) else ServerKeyStores.empty()
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

        val ks = ServerKeyStores.empty()
        ks.setKeyEntry(CLIENT_CA_ALIAS, keyPair.private, KEYSTORE_PASSWORD.toCharArray(), arrayOf(cert))
        clientCaFile.outputStream().use { ks.store(it, KEYSTORE_PASSWORD.toCharArray()) }
        addToTrustStore(CLIENT_CA_ALIAS, cert)
        return cert
    }

    fun clientCaCertificate(): X509Certificate = loadClientCa()?.second ?: ensureClientCa()

    private fun loadClientCa(): Pair<PrivateKey, X509Certificate>? {
        if (!clientCaFile.exists()) return null
        val ks = ServerKeyStores.load(clientCaFile, KEYSTORE_PASSWORD.toCharArray())
        val key = ks.getKey(CLIENT_CA_ALIAS, KEYSTORE_PASSWORD.toCharArray()) as? PrivateKey ?: return null
        val cert = ks.getCertificate(CLIENT_CA_ALIAS) as? X509Certificate ?: return null
        return key to cert
    }

    /** A device's CSR after its proof of possession was checked. Only the key is taken from it. */
    class ParsedCsr(val publicKey: java.security.PublicKey, val spkiSha256: String)

    /**
     * A CSR whose shape and key passed [inspectCsr]; its signature has NOT
     * been checked. Enough to look the key up ([spkiSha256]) before any
     * signature work is spent on it.
     */
    class CsrCandidate internal constructor(
        internal val request: org.bouncycastle.pkcs.PKCS10CertificationRequest,
        val publicKey: java.security.PublicKey,
        val spkiSha256: String
    ) {
        /** The request's DER, as signed (a renewal remembers its hash to refuse a replay). */
        val der: ByteArray get() = request.encoded
    }

    private val csrSignatureCounter = java.util.concurrent.atomic.AtomicLong()

    /** How many CSR signatures this instance has verified (tests assert that a refused key costs none). */
    val csrSignatureChecks: Long get() = csrSignatureCounter.get()

    /**
     * Parses a DER PKCS#10 request and verifies its self-signature (proof
     * that the sender holds the private key). The subject is deliberately not
     * read: the certificate is named after the enrolled client id, never
     * after what the request asks for.
     *
     * @throws IllegalArgumentException when the request is malformed, its
     *         signature does not verify, or its key is not one this server
     *         issues for ([inspectCsr]). Nothing else is thrown.
     */
    fun parseCsr(csrDer: ByteArray): ParsedCsr = verifyCsr(inspectCsr(csrDer))

    /** [parseCsr] of a Base64 request as it arrives in an enrollment or renewal body. */
    fun parseCsr(csrBase64: String): ParsedCsr = verifyCsr(inspectCsr(csrBase64))

    /** [inspectCsr] of a Base64 request; an over-long or undecodable one is refused before it is decoded. */
    fun inspectCsr(csrBase64: String): CsrCandidate {
        require(csrBase64.length <= MAX_CSR_BYTES * 4 / 3 + 4) { "CSR is larger than $MAX_CSR_BYTES bytes" }
        val der = try {
            Base64.getDecoder().decode(csrBase64)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("CSR is not valid Base64", e)
        }
        return inspectCsr(der)
    }

    /**
     * The structural half of [parseCsr]: size, DER shape and the key — and no
     * signature work. The signature used to be verified first and the key
     * looked at afterwards, so a request carrying a 16 000-bit RSA key (its
     * signature need not even be valid) cost seconds of CPU before it was
     * refused, to anyone who could reach an enrollment or renewal endpoint.
     *
     * Accepted keys: RSA of 2048 to 4096 bits with public exponent 65537, or
     * EC on the named curves P-256 and P-384. Everything else — larger or
     * smaller RSA, other exponents, other or explicitly parameterised curves,
     * other algorithms — is refused here.
     *
     * @throws IllegalArgumentException for anything it refuses.
     */
    fun inspectCsr(csrDer: ByteArray): CsrCandidate {
        require(csrDer.size <= MAX_CSR_BYTES) { "CSR is larger than $MAX_CSR_BYTES bytes" }
        val csr = try {
            org.bouncycastle.pkcs.PKCS10CertificationRequest(csrDer)
        } catch (e: Exception) {
            throw IllegalArgumentException("CSR is not a valid PKCS#10 request", e)
        }
        val spki = csr.subjectPublicKeyInfo
        val publicKey: java.security.PublicKey = when (spki.algorithm.algorithm) {
            org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.rsaEncryption -> {
                val rsa = try {
                    org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(spki.parsePublicKey())
                } catch (e: Exception) {
                    throw IllegalArgumentException("CSR carries a malformed public key", e)
                }
                require(rsa.modulus.signum() > 0 && rsa.modulus.bitLength() in 2048..4096) { "RSA key must be 2048 to 4096 bits" }
                require(rsa.publicExponent == java.math.BigInteger.valueOf(65537)) { "RSA public exponent must be 65537" }
                // The JDK's key, not Bouncy Castle's: BC tests the modulus for primality
                // when it builds one (modular exponentiations — signature-sized work),
                // and it still does, in verifyCsr, for a key that got that far.
                try {
                    java.security.KeyFactory.getInstance("RSA")
                        .generatePublic(java.security.spec.RSAPublicKeySpec(rsa.modulus, rsa.publicExponent))
                } catch (e: Exception) {
                    throw IllegalArgumentException("CSR carries a malformed public key", e)
                }
            }
            org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_ecPublicKey -> {
                val curve = spki.algorithm.parameters as? org.bouncycastle.asn1.ASN1ObjectIdentifier
                require(curve != null && curve in ALLOWED_CSR_CURVES) { "EC key must be on the named curve P-256 or P-384" }
                try {
                    org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().setProvider("BC").getPublicKey(spki)
                } catch (e: Exception) {
                    throw IllegalArgumentException("CSR carries a malformed public key", e)
                }
            }
            else -> throw IllegalArgumentException("Unsupported key algorithm ${spki.algorithm.algorithm.id}")
        }
        return CsrCandidate(csr, publicKey, sha256Base64(publicKey.encoded))
    }

    /**
     * The signature half of [parseCsr]: proof that the sender holds the
     * private key of an inspected request.
     *
     * @throws IllegalArgumentException when the signature does not verify.
     */
    fun verifyCsr(candidate: CsrCandidate): ParsedCsr {
        csrSignatureCounter.incrementAndGet()
        val valid = try {
            val verifier = org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                .setProvider("BC").build(candidate.request.subjectPublicKeyInfo)
            candidate.request.isSignatureValid(verifier)
        } catch (e: Exception) {
            // An algorithm the key cannot verify, a signature that is not one: all the same refusal.
            throw IllegalArgumentException("CSR signature is invalid", e)
        }
        if (!valid) throw IllegalArgumentException("CSR signature is invalid")
        return ParsedCsr(candidate.publicKey, candidate.spkiSha256)
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
        // ensureClientCa every time: it also puts the CA back into the client truststore
        // when that file went missing (moved, deleted). Nothing else is added there any
        // more, so without this an mTLS listener stayed unstartable until a restart.
        val (caKey, caCert) = ensureClientCa().let { loadClientCa()!! }
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

    /**
     * The certificate [leafPem] (one this CA issued to [clientId] over the key
     * [spkiSha256]) as an answer again, when at least half of its lifetime is
     * left: a device asking twice with the same key — a lost answer, a retry
     * loop — gets the certificate it already has instead of a new signature,
     * audit entry and webhook per request. Null when it does not qualify
     * (another key, another CA, expiring): the caller issues a new one.
     */
    fun reusableClientCertificate(clientId: String, spkiSha256: String, leafPem: String?): IssuedClientCert? {
        if (leafPem == null) return null
        return try {
            val leaf = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(leafPem.byteInputStream()) as X509Certificate
            val ca = clientCaCertificate()
            leaf.verify(ca.publicKey)
            val now = System.currentTimeMillis()
            val lifetime = leaf.notAfter.time - leaf.notBefore.time
            val cn = "PinVault Client: $clientId"
            if (sha256Base64(leaf.publicKey.encoded) != spkiSha256 || leaf.subjectX500Principal != clientSubject(cn).let { javax.security.auth.x500.X500Principal(it.encoded) } ||
                leaf.notAfter.time - now < lifetime / 2) return null
            IssuedClientCert(leaf, ca, listOf(toPem(leaf), toPem(ca)), cn, spkiSha256, leaf.serialNumber.toString(16),
                leaf.notBefore.toInstant(), leaf.notAfter.toInstant())
        } catch (_: Exception) {
            null
        }
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
            val ks = ServerKeyStores.load(recoveryKeystoreFile, KEYSTORE_PASSWORD.toCharArray())
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
        val ks = ServerKeyStores.empty()
        ks.setKeyEntry("server", keyPair.private, KEYSTORE_PASSWORD.toCharArray(), arrayOf(leaf, caCert))
        recoveryKeystoreFile.outputStream().use { ks.store(it, KEYSTORE_PASSWORD.toCharArray()) }
        return RecoveryCertificate(recoveryKeystoreFile, leaf, caCert, regenerated = true)
    }

    private fun loadCa(file: File, alias: String): Pair<PrivateKey, X509Certificate>? {
        if (!file.exists()) return null
        val ks = ServerKeyStores.load(file, KEYSTORE_PASSWORD.toCharArray())
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
        val ks = ServerKeyStores.empty()
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
        chain: Array<X509Certificate>,
        password: String
    ): ByteArray {
        val ks = KeyStore.getInstance("PKCS12", "BC")
        ks.load(null, null)
        ks.setKeyEntry(alias, privateKey, password.toCharArray(), chain)

        val baos = java.io.ByteArrayOutputStream()
        ks.store(baos, password.toCharArray())
        return baos.toByteArray()
    }

    /** The first of [candidates] that opens [p12], or null. */
    fun p12Password(p12: ByteArray, candidates: List<String>): String? = candidates.distinct().firstOrNull { candidate ->
        runCatching { KeyStore.getInstance("PKCS12", "BC").load(p12.inputStream(), candidate.toCharArray()) }.isSuccess
    }

    /**
     * The one key entry of a host's client P12 and its certificate.
     *
     * Devices use the key a P12 holds; with several, which one the TLS stack
     * picks is not what the approver was shown (the description took the first
     * alias, whatever it held). So an uploaded host client P12 must hold
     * exactly one private key, and that entry is what is described, recorded
     * and stored.
     *
     * @throws IllegalArgumentException with a message safe to show the admin.
     */
    fun hostClientKeyEntry(p12: ByteArray, password: String): Pair<String, X509Certificate> {
        val ks = try {
            KeyStore.getInstance("PKCS12").also { it.load(p12.inputStream(), password.toCharArray()) }
        } catch (e: Exception) {
            throw IllegalArgumentException("Gecersiz P12: ${e.message}")
        }
        val keys = ks.aliases().toList().filter { ks.isKeyEntry(it) }
        require(keys.size == 1) { "The P12 must hold exactly one private key (found ${keys.size})" }
        val cert = ks.getCertificate(keys.single()) as? X509Certificate
            ?: throw IllegalArgumentException("The P12's key entry has no X.509 certificate")
        return keys.single() to cert
    }

    /**
     * [p12] re-encrypted from [from] to [to], in the Android-compatible format:
     * every entry and chain kept, or with [keyEntryOnly] only its single key
     * entry and that entry's chain (a host client P12; more than one key is refused).
     */
    fun rewrapP12(p12: ByteArray, from: String, to: String, keyEntryOnly: Boolean = false): ByteArray {
        val source = KeyStore.getInstance("PKCS12", "BC").apply { load(p12.inputStream(), from.toCharArray()) }
        val target = KeyStore.getInstance("PKCS12", "BC").apply { load(null, null) }
        if (keyEntryOnly) {
            val keys = source.aliases().toList().count { source.isKeyEntry(it) }
            require(keys == 1) { "The P12 must hold exactly one private key (found $keys)" }
        }
        for (alias in source.aliases().toList()) {
            if (keyEntryOnly && !source.isKeyEntry(alias)) continue
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
         * Falls back to [LEGACY_KEYSTORE_PASSWORD] when unset — which the
         * server only reaches with `ALLOW_DEMO_SECRETS=true` ([StartupSecrets]
         * refuses to start otherwise); the sample host's setup.sh generates one, and
         * [KeystoreRekey] moves keystores written under an older password to
         * it at startup. (audit L-2 / L-6)
         */
        val KEYSTORE_PASSWORD: String =
            com.example.pinvault.server.service.ServerEnv.get("KEYSTORE_PASSWORD")?.takeIf { it.isNotBlank() } ?: LEGACY_KEYSTORE_PASSWORD

        /** What every keystore was written with before `KEYSTORE_PASSWORD` existed. */
        const val LEGACY_KEYSTORE_PASSWORD = "changeit"

        /** Extended key usages a client certificate may carry: clientAuth, or anyExtendedKeyUsage. */
        private const val CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2"

        /** Connect and read timeout of a certificate fetch. */
        private const val FETCH_TIMEOUT_MS = 10_000

        /** Alias of the backup key in `<id>.backup.jks`. */
        private const val BACKUP_ALIAS = "backup"

        /** Alias of the client CA in `client-ca.jks` and in the client truststore. */
        const val CLIENT_CA_ALIAS = "client-ca"

        /** Alias of the server CA in `server-ca.jks` / `server-ca.backup.jks`. */
        const val SERVER_CA_ALIAS = "server-ca"

        /**
         * Aliases the server's own keystores and the client truststore use. JKS
         * aliases ignore case, so `Client-CA` is the client CA too. None of them
         * may be a client id: revoke, forget and upload act on the truststore
         * entry named like the id.
         */
        private val RESERVED_ALIASES = setOf(CLIENT_CA_ALIAS, SERVER_CA_ALIAS, BACKUP_ALIAS, "server")

        /** Whether [alias] names one of the server's own entries ([RESERVED_ALIASES]), ignoring case. */
        fun isReservedAlias(alias: String): Boolean = alias.trim().lowercase() in RESERVED_ALIASES

        /** How far back `notBefore` is set so a device with a slow clock accepts a fresh certificate. */
        const val CLOCK_SKEW_MS = 60 * 60_000L
        private const val DAY_MS = 24 * 60 * 60_000L

        /** A CSR over an RSA-4096 key is under 2 KB of DER; nothing longer is parsed. */
        const val MAX_CSR_BYTES = 8 * 1024

        /** The named curves a CSR key may be on: P-256 and P-384. */
        private val ALLOWED_CSR_CURVES = setOf(
            org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp256r1,
            org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp384r1
        )

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
