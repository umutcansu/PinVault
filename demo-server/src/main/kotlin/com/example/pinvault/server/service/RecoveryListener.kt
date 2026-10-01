package com.example.pinvault.server.service

import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.applicationEnvironment
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.netty.Netty
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import java.io.FileInputStream
import java.security.KeyStore
import java.security.cert.X509Certificate

/**
 * The certificate-renewal door for devices whose client certificate has
 * expired: a plain-TLS listener (no client certificate asked for) that serves
 * `POST /api/v1/client-certs/renew` and `/health`, and nothing else.
 *
 * Its own certificate is signed by the server CA ([CertificateService.ensureServerCa])
 * and apps pin that CA for this one `host:port`, so the door stays reachable
 * however often its certificate changes — while the Config API ports keep
 * their stricter leaf pins. [refresh] reissues the certificate before it
 * expires and restarts the listener; devices notice nothing.
 */
class RecoveryListener(
    private val certService: CertificateService,
    private val port: Int,
    private val host: String = "0.0.0.0",
    private val routes: Route.() -> Unit
) {
    @Volatile private var server: EmbeddedServer<*, *>? = null
    @Volatile var leaf: X509Certificate? = null
        private set

    val isRunning: Boolean get() = server != null

    fun start() {
        val cert = certService.ensureRecoveryCertificate()
        leaf = cert.leaf
        server = launch()
        println("Recovery listener on port $port (TLS, no client cert) — certificate valid until ${cert.leaf.notAfter.toInstant()}")
    }

    /** Reissues the certificate when it is close to expiry and, if it did, restarts the listener on it. */
    fun refresh(): Boolean {
        val cert = certService.ensureRecoveryCertificate()
        if (!cert.regenerated) return false
        leaf = cert.leaf
        stop()
        server = launch()
        println("Recovery listener certificate reissued — valid until ${cert.leaf.notAfter.toInstant()}")
        return true
    }

    fun stop() {
        server?.stop(500, 2000)
        server = null
    }

    private fun launch(): EmbeddedServer<*, *> {
        val keyStore = KeyStore.getInstance("JKS").apply {
            FileInputStream(certService.recoveryKeystoreFile()).use { load(it, CertificateService.KEYSTORE_PASSWORD.toCharArray()) }
        }
        val module: Application.() -> Unit = {
            // Everything here is open to anyone; a renewal body is a CSR of a few hundred bytes.
            install(com.example.pinvault.server.plugin.ClientBodyLimit) { appliesTo = { _, _ -> true } }
            routing {
                get("/health") { call.respondText("""{"status":"ok"}""", io.ktor.http.ContentType.Application.Json) }
                routes()
            }
        }
        return embeddedServer(Netty, applicationEnvironment {}, configure = {
            sslConnector(
                keyStore = keyStore,
                keyAlias = "server",
                keyStorePassword = { CertificateService.KEYSTORE_PASSWORD.toCharArray() },
                privateKeyPassword = { CertificateService.KEYSTORE_PASSWORD.toCharArray() }
            ) {
                this.port = this@RecoveryListener.port
                this.host = this@RecoveryListener.host
                // No trustStore: the door asks for no client certificate.
            }
        }, module = module).also { it.start(wait = false) }
    }
}
