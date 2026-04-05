package com.example.pinvault.server.service

import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.Json
import java.io.FileInputStream
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * Dinamik Config API sunucu yöneticisi.
 * Web UI'dan TLS veya mTLS config API'leri başlatılıp durdurulabilir.
 * Her instance farklı port ve güvenlik seviyesinde çalışır.
 */
class ConfigApiManager {

    data class ConfigApiInstance(
        val id: String,
        val port: Int,
        val mode: String, // "tls" veya "mtls"
        val keystorePath: String,
        val trustStorePath: String? = null
    )

    private val servers = ConcurrentHashMap<String, EmbeddedServer<*, *>>()
    private val instances = ConcurrentHashMap<String, ConfigApiInstance>()
    // Durdurulan API'lerin bilgisini sakla (yeniden başlatma için)
    private val stoppedInstances = ConcurrentHashMap<String, ConfigApiInstance>()

    /**
     * Config API sunucusu başlatır.
     * @param id benzersiz isim (örn: "tls-8091", "mtls-8092")
     * @param port dinlenecek port
     * @param mode "tls" veya "mtls"
     * @param keystorePath server sertifika keystore'u
     * @param trustStorePath client cert truststore'u (sadece mtls modunda)
     * @param configModule Ktor routing modülü (config endpoint'leri)
     */
    fun start(
        id: String,
        port: Int,
        mode: String,
        keystorePath: String,
        trustStorePath: String? = null,
        configModule: Application.() -> Unit
    ): ConfigApiInstance {
        // Aynı id'de çalışan varsa durdur
        stop(id)

        // Port çakışması kontrolü
        instances.entries.find { it.value.port == port }?.let { conflict ->
            stop(conflict.key)
        }

        val keyStore = KeyStore.getInstance("JKS")
        FileInputStream(keystorePath).use { keyStore.load(it, CertificateService.KEYSTORE_PASSWORD.toCharArray()) }

        val environment = applicationEnvironment {}
        val server = embeddedServer(Netty, environment, configure = {
            sslConnector(
                keyStore = keyStore,
                keyAlias = "server",
                keyStorePassword = { CertificateService.KEYSTORE_PASSWORD.toCharArray() },
                privateKeyPassword = { CertificateService.KEYSTORE_PASSWORD.toCharArray() }
            ) {
                this.port = port
                if (mode == "mtls" && trustStorePath != null) {
                    val ts = KeyStore.getInstance("JKS")
                    FileInputStream(trustStorePath).use { ts.load(it, CertificateService.KEYSTORE_PASSWORD.toCharArray()) }
                    this.trustStore = ts
                }
            }
        }) {
            install(ContentNegotiation) {
                json(Json {
                    prettyPrint = true
                    encodeDefaults = true
                    ignoreUnknownKeys = true
                })
            }
            configModule()
        }

        server.start(wait = false)
        val instance = ConfigApiInstance(id, port, mode, keystorePath, trustStorePath)
        servers[id] = server
        instances[id] = instance
        stoppedInstances.remove(id) // Artık çalışıyor, stopped'dan kaldır
        println("Config API started: $id on port $port (mode: $mode)")
        return instance
    }

    fun stop(id: String) {
        servers.remove(id)?.let { server ->
            val instance = instances.remove(id)
            if (instance != null) {
                stoppedInstances[id] = instance // Bilgiyi sakla
            }
            server.stop(1500, 3000, TimeUnit.MILLISECONDS)
            println("Config API stopped: $id")
        }
    }

    fun removeStopped(id: String) {
        stoppedInstances.remove(id)
    }

    fun stopAll() {
        servers.keys.toList().forEach { stop(it) }
    }

    fun isRunning(id: String): Boolean = servers.containsKey(id)

    fun getAll(): List<ConfigApiInstance> = instances.values.toList()

    fun getAllStopped(): List<ConfigApiInstance> = stoppedInstances.values.toList()

    fun get(id: String): ConfigApiInstance? = instances[id]

    fun getStopped(id: String): ConfigApiInstance? = stoppedInstances[id]
}
