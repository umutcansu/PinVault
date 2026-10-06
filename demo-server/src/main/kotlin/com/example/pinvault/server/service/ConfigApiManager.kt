package com.example.pinvault.server.service

import com.example.pinvault.server.plugin.ApiKeyAuth
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
class ConfigApiManager(
    /**
     * `CONFIG_API_ADMIN_ROUTES=off`: the listeners answer device endpoints
     * only ([com.example.pinvault.server.plugin.DeviceOnlyRoutes]); admin
     * routes exist on the management listener alone.
     */
    private val deviceOnly: Boolean = false
) {

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

    /** Invalid admin keys per source address, shared with the management listener (ADMIN_AUTH_FAILURE_LIMIT). */
    var adminFailureLimiter: RateLimiter? = null

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

        val keyStore = ServerKeyStores.load(java.io.File(keystorePath), CertificateService.KEYSTORE_PASSWORD.toCharArray())

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
                    this.trustStore = ServerKeyStores.load(java.io.File(trustStorePath), CertificateService.KEYSTORE_PASSWORD.toCharArray())
                }
            }
        }) {
            // First: no plugin or route may see a path that hides a '/' in an escape.
            install(com.example.pinvault.server.plugin.EncodedPathGuard)
            install(ContentNegotiation) {
                json(Json {
                    prettyPrint = true
                    encodeDefaults = true
                    ignoreUnknownKeys = true
                })
            }
            // Security (audit H-1): the Config API ports are the ones devices
            // actually connect to. Without this, every mutating admin endpoint
            // (PUT certificate-config, host mutations, vault PUT/DELETE, token
            // minting, fetch-from-url) was reachable unauthenticated here while
            // only the management server enforced the API key. ApiKeyAuth reuses
            // the same isPublicEndpoint allowlist, so client-facing GET/enroll/
            // report routes stay open and everything else requires X-API-Key.
            // Admin routes are served here too (with the admin key): the same
            // refusal of cross-site and form-posted writes as on the management
            // listener. Device endpoints are not touched.
            //
            // CONFIG_API_ADMIN_ROUTES=off takes that further: nothing but the
            // device endpoints is answered here, key or no key.
            if (deviceOnly) install(com.example.pinvault.server.plugin.DeviceOnlyRoutes)
            install(com.example.pinvault.server.plugin.AdminBrowserGuard)
            install(ApiKeyAuth) {
                // Without admin keys this port serves device endpoints only (anonymous
                // admin is the management listener's, from its own machine).
                anonymousAdminListener = false
                failureLimiter = adminFailureLimiter
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
