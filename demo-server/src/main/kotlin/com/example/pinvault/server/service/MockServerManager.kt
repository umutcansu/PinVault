package com.example.pinvault.server.service

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.io.FileInputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * Her host için opsiyonel embedded HTTPS mock server yönetir.
 * Demo/test amaçlı — Android uygulamasını gerçek TLS bağlantısı ile test edebilmek için.
 *
 * Aynı hostname için hem TLS hem mTLS mock server çalıştırılabilir (farklı port'larda).
 * Server key: "hostname" (TLS) veya "hostname:mtls" (mTLS)
 */
class MockServerManager {

    private val servers = ConcurrentHashMap<String, EmbeddedServer<*, *>>()
    private val portMap = ConcurrentHashMap<String, Int>()
    private val modeMap = ConcurrentHashMap<String, String>()
    private val keystoreMap = ConcurrentHashMap<String, String>() // key → keystorePath

    private fun serverKey(hostname: String, mtls: Boolean = false): String =
        if (mtls) "$hostname:mtls" else hostname

    /**
     * Verilen keystore ile HTTPS mock server başlatır.
     * @param trustStorePath null ise TLS, değilse mTLS (client cert zorunlu)
     */
    fun start(hostname: String, port: Int, keystorePath: String, trustStorePath: String? = null): Int {
        val isMtls = trustStorePath != null
        val key = serverKey(hostname, isMtls)

        // Aynı key'de çalışan varsa durdur
        stop(key)

        // Port çakışması kontrolü
        portMap.entries.find { it.value == port }?.let { conflict ->
            stop(conflict.key)
        }

        val serverCertPin = extractPin(keystorePath)

        val environment = applicationEnvironment {}
        val server = embeddedServer(Netty, environment, configure = {
            sslConnector(
                keyStore = loadKeystore(keystorePath),
                keyAlias = "server",
                keyStorePassword = { CertificateService.KEYSTORE_PASSWORD.toCharArray() },
                privateKeyPassword = { CertificateService.KEYSTORE_PASSWORD.toCharArray() }
            ) {
                this.port = port
                if (isMtls) {
                    val ts = KeyStore.getInstance("JKS")
                    FileInputStream(trustStorePath!!).use {
                        ts.load(it, CertificateService.KEYSTORE_PASSWORD.toCharArray())
                    }
                    this.trustStore = ts
                }
            }
        }) {
            routing {
                get("/health") {
                    call.respondText(
                        """{"status":"ok","hostname":"$hostname","port":$port,"tls":true,"mtls":$isMtls,"serverCertPin":"$serverCertPin"}""",
                        ContentType.Application.Json
                    )
                }
                get("/") {
                    call.respondText(
                        """{"message":"PinVault Mock Server","hostname":"$hostname","mtls":$isMtls,"serverCertPin":"$serverCertPin"}""",
                        ContentType.Application.Json
                    )
                }
            }
        }

        server.start(wait = false)
        servers[key] = server
        portMap[key] = port
        modeMap[key] = if (isMtls) "mtls" else "tls"
        keystoreMap[key] = keystorePath
        val modeLabel = if (isMtls) "mTLS" else "TLS"
        println("Mock server started: $hostname on port $port ($modeLabel, pin: ${serverCertPin.take(16)}...)")
        return port
    }

    fun stop(key: String) {
        servers.remove(key)?.let { server ->
            server.stop(1500, 3000, TimeUnit.MILLISECONDS)
            portMap.remove(key)
            modeMap.remove(key)
            keystoreMap.remove(key)
            println("Mock server stopped: $key")
        }
    }

    /** Hostname bazlı stop — hem TLS hem mTLS durdurur */
    fun stopAll(hostname: String) {
        stop(hostname)
        stop("$hostname:mtls")
    }

    fun stopAll() {
        servers.keys.toList().forEach { stop(it) }
    }

    fun isRunning(hostname: String): Boolean =
        servers.containsKey(hostname) || servers.containsKey("$hostname:mtls")

    fun isTlsRunning(hostname: String): Boolean = servers.containsKey(hostname)

    fun isMtlsRunning(hostname: String): Boolean = servers.containsKey("$hostname:mtls")

    fun getPort(hostname: String): Int? = portMap[hostname] ?: portMap["$hostname:mtls"]

    fun getTlsPort(hostname: String): Int? = portMap[hostname]

    fun getMtlsPort(hostname: String): Int? = portMap["$hostname:mtls"]

    /**
     * Yeni client cert enrollment sonrası tüm mTLS mock server'ları yeniden başlatır.
     * Truststore güncellenmiş olduğundan yeni cert'ler kabul edilir.
     */
    fun restartMtlsServers(certService: CertificateService) {
        val trustPath = certService.getTrustStoreFile().absolutePath
        val mtlsKeys = servers.keys.filter { it.endsWith(":mtls") }
        for (key in mtlsKeys) {
            val port = portMap[key] ?: continue
            val ksPath = keystoreMap[key] ?: continue
            val hostname = key.removeSuffix(":mtls")
            println("Auto-restarting mTLS mock server: $hostname:$port (truststore updated)")
            start(hostname, port, ksPath, trustPath)
        }
    }

    fun getMode(hostname: String): String? {
        if (servers.containsKey("$hostname:mtls") && servers.containsKey(hostname)) return "both"
        if (servers.containsKey("$hostname:mtls")) return "mtls"
        if (servers.containsKey(hostname)) return "tls"
        return null
    }

    private fun loadKeystore(path: String): KeyStore {
        val ks = KeyStore.getInstance("JKS")
        FileInputStream(path).use { ks.load(it, CertificateService.KEYSTORE_PASSWORD.toCharArray()) }
        return ks
    }

    private fun extractPin(keystorePath: String): String {
        val ks = loadKeystore(keystorePath)
        val cert = ks.getCertificate("server")
        val digest = MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded)
        return Base64.getEncoder().encodeToString(digest)
    }
}
