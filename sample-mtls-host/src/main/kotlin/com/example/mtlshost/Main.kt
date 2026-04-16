package com.example.mtlshost

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.*

/**
 * Sample mTLS Host Server
 *
 * Bu sunucu mTLS gerektiren basit bir API sunar.
 * Başlatıldığında:
 * 1. Server sertifikası üretir (server.jks)
 * 2. Client sertifikası üretir (client.p12) — bu dosyayı Config API'ye yüklersin
 * 3. Client'ın public key'ini truststore'a ekler (truststore.jks)
 * 4. mTLS sunucuyu başlatır — sadece truststore'daki client cert ile bağlanabilirsin
 *
 * Kullanım:
 *   cd sample-mtls-host && ../gradlew run
 *
 * Test:
 *   curl -sk --cert-type P12 --cert certs/client.p12:changeit https://localhost:9443/api/data
 *   curl -sk https://localhost:9443/api/data  → REJECTED (client cert yok)
 */
fun main() {
    val certsDir = File("certs").also { it.mkdirs() }
    val password = "changeit"
    val host = System.getenv("HOST") ?: "0.0.0.0"
    val port = System.getenv("PORT")?.toIntOrNull() ?: 9443

    // ═══ 1. Server sertifikası üret ═══
    val serverJks = File(certsDir, "server.jks")
    if (!serverJks.exists()) {
        println("🔐 Server sertifikası üretiliyor...")
        generateServerCert(serverJks, password)
    }

    // ═══ 2. Client sertifikası üret ═══
    val clientP12 = File(certsDir, "client.p12")
    val trustJks = File(certsDir, "truststore.jks")
    if (!clientP12.exists()) {
        println("🔐 Client sertifikası üretiliyor...")
        generateClientCert(clientP12, trustJks, password)
    }

    // ═══ 3. Pin hash'leri göster ═══
    val serverPin = extractPin(serverJks, password, "JKS")
    val clientPin = extractPin(clientP12, password, "PKCS12")
    println("""
╔══════════════════════════════════════════════════════════╗
║  SAMPLE mTLS HOST                                       ║
╠══════════════════════════════════════════════════════════╣
║  Port: $port
║  Mode: mTLS (client cert required)                      ║
║                                                          ║
║  Server Pin: $serverPin
║  Client Pin: $clientPin
║                                                          ║
║  Dosyalar:                                               ║
║    certs/server.jks     — sunucu sertifikası             ║
║    certs/client.p12     — Config API'ye yükle            ║
║    certs/truststore.jks — kabul edilen client cert'ler   ║
║                                                          ║
║  Test:                                                   ║
║    curl -sk --cert-type P12 \                            ║
║      --cert certs/client.p12:changeit \                  ║
║      https://localhost:$port/api/data
╚══════════════════════════════════════════════════════════╝
    """.trimIndent())

    // ═══ 4. mTLS sunucuyu başlat ═══
    val serverKeyStore = KeyStore.getInstance("JKS")
    FileInputStream(serverJks).use { serverKeyStore.load(it, password.toCharArray()) }

    val clientTrustStore = KeyStore.getInstance("JKS")
    FileInputStream(trustJks).use { clientTrustStore.load(it, password.toCharArray()) }

    val environment = applicationEnvironment {}
    embeddedServer(Netty, environment, configure = {
        sslConnector(
            keyStore = serverKeyStore,
            keyAlias = "server",
            keyStorePassword = { password.toCharArray() },
            privateKeyPassword = { password.toCharArray() }
        ) {
            this.port = port
            this.host = host
            this.trustStore = clientTrustStore  // ← mTLS: client cert zorunlu
        }
    }) {
        routing {
            get("/health") {
                call.respondText(
                    """{"status":"ok","mtls":true,"port":$port,"serverPin":"$serverPin"}""",
                    ContentType.Application.Json
                )
            }

            get("/api/data") {
                // Client cert bilgisini al
                val clientCertInfo = try {
                    val certs = call.request.local.run {
                        // Ktor'da client cert'e erişim sınırlı — basit response
                        "authenticated"
                    }
                    certs
                } catch (_: Exception) { "unknown" }

                call.respondText(
                    """{
                        "message": "Gizli veri - sadece mTLS ile erişilebilir",
                        "client": "$clientCertInfo",
                        "timestamp": "${System.currentTimeMillis()}",
                        "serverPin": "$serverPin"
                    }""".trimIndent(),
                    ContentType.Application.Json
                )
            }

            get("/api/users") {
                call.respondText(
                    """[
                        {"id": 1, "name": "Ali", "role": "admin"},
                        {"id": 2, "name": "Ayşe", "role": "user"},
                        {"id": 3, "name": "Mehmet", "role": "user"}
                    ]""".trimIndent(),
                    ContentType.Application.Json
                )
            }
        }
    }.start(wait = true)
}

// ═══ Sertifika Üretim Fonksiyonları ═══

fun generateServerCert(jksFile: File, password: String) {
    val keyPairGen = KeyPairGenerator.getInstance("RSA")
    keyPairGen.initialize(2048)
    val keyPair = keyPairGen.generateKeyPair()

    // Tüm local IP'leri SAN'a ekle — hangi IP'den bağlanırsa bağlansın çalışsın
    val localIps = try {
        java.net.NetworkInterface.getNetworkInterfaces()?.toList()
            ?.flatMap { it.inetAddresses.toList() }
            ?.filter { it is java.net.Inet4Address }
            ?.map { it.hostAddress }
            ?: emptyList()
    } catch (_: Exception) { emptyList() }

    val sanList = mutableListOf(
        GeneralName(GeneralName.dNSName, "localhost"),
        GeneralName(GeneralName.dNSName, "sample-mtls-host"),
        GeneralName(GeneralName.iPAddress, "127.0.0.1"),
        GeneralName(GeneralName.iPAddress, "10.0.2.2"),
        GeneralName(GeneralName.iPAddress, "0.0.0.0")
    )
    // Makinanın tüm IP'lerini ekle (192.168.x.x vb.)
    localIps.filter { it != "127.0.0.1" }.forEach { ip ->
        sanList.add(GeneralName(GeneralName.iPAddress, ip))
    }

    val subject = X500Name("CN=sample-mtls-host, O=PinVault Demo, C=TR")
    val cert = JcaX509v3CertificateBuilder(
        subject,
        BigInteger.valueOf(System.currentTimeMillis()),
        Date(),
        Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000),
        subject,
        keyPair.public
    ).addExtension(
        Extension.subjectAlternativeName, false,
        GeneralNames(sanList.toTypedArray())
    ).build(JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private))
        .let { JcaX509CertificateConverter().getCertificate(it) }

    val ks = KeyStore.getInstance("JKS")
    ks.load(null, null)
    ks.setKeyEntry("server", keyPair.private, password.toCharArray(), arrayOf(cert))
    FileOutputStream(jksFile).use { ks.store(it, password.toCharArray()) }

    println("  ✅ Server cert: ${jksFile.absolutePath}")
    println("  📋 SAN IPs: ${localIps.joinToString(", ")}")
}

fun generateClientCert(p12File: File, trustFile: File, password: String) {
    val keyPairGen = KeyPairGenerator.getInstance("RSA")
    keyPairGen.initialize(2048)
    val keyPair = keyPairGen.generateKeyPair()

    val subject = X500Name("CN=PinVault Client, O=PinVault Demo, C=TR")
    val cert = JcaX509v3CertificateBuilder(
        subject,
        BigInteger.valueOf(System.currentTimeMillis()),
        Date(),
        Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000),
        subject,
        keyPair.public
    ).build(JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private))
        .let { JcaX509CertificateConverter().getCertificate(it) }

    // Client P12
    val p12Ks = KeyStore.getInstance("PKCS12")
    p12Ks.load(null, null)
    p12Ks.setKeyEntry("client", keyPair.private, password.toCharArray(), arrayOf(cert))
    FileOutputStream(p12File).use { p12Ks.store(it, password.toCharArray()) }
    println("  ✅ Client P12: ${p12File.absolutePath}")

    // Truststore (sunucu bu client'ı kabul etsin)
    val ts = KeyStore.getInstance("JKS")
    ts.load(null, null)
    ts.setCertificateEntry("client", cert)
    FileOutputStream(trustFile).use { ts.store(it, password.toCharArray()) }
    println("  ✅ Truststore: ${trustFile.absolutePath}")
}

fun extractPin(keystoreFile: File, password: String, type: String = "JKS"): String {
    val ks = KeyStore.getInstance(type)
    FileInputStream(keystoreFile).use { ks.load(it, password.toCharArray()) }
    val alias = ks.aliases().toList().firstOrNull() ?: return "?"
    val cert = ks.getCertificate(alias)
    val digest = MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded)
    return Base64.getEncoder().encodeToString(digest)
}
