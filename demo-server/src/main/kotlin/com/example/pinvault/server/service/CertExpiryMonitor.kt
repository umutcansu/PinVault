package com.example.pinvault.server.service

import com.example.pinvault.server.store.HostStore
import kotlinx.serialization.Serializable
import java.time.Instant
import java.time.temporal.ChronoUnit

/**
 * Something with a date it stops being valid: a host certificate (the
 * original monitor), the Config API's own certificate, the client or server
 * CA, a host's client certificate, a vault file with an expiry. [label] is
 * what the dashboard shows in the name column.
 */
data class ExpiryCandidate(
    val kind: String,
    val label: String,
    val configApiId: String,
    val validUntil: Instant
)

/**
 * Monitors expiry for every managed host certificate and whatever else is
 * registered as a source (`Main` adds the server's own certificates and the
 * vault files). Used by /api/v1/cert-expiry, /api/v1/health and the
 * background check.
 */
class CertExpiryMonitor(
    private val hostStore: HostStore,
    private val warnDays: Int = com.example.pinvault.server.service.ServerEnv.get("CERT_EXPIRY_WARN_DAYS")?.toIntOrNull() ?: 30,
    /** Further things with an expiry; a source that throws is skipped (its failure is logged once per check). */
    private val sources: List<() -> List<ExpiryCandidate>> = emptyList()
) {

    fun checkAll(): List<CertExpiryStatus> {
        val now = Instant.now()
        val hosts = hostStore.getAll().mapNotNull { host ->
            val validUntil = host.certValidUntil?.let {
                try { Instant.parse(it) } catch (_: Exception) { null }
            } ?: return@mapNotNull null
            ExpiryCandidate(KIND_HOST, host.hostname, host.configApiId, validUntil)
        }
        val extra = sources.flatMap { source ->
            try { source() } catch (e: Exception) {
                println("Expiry check: a source failed and was skipped: ${e.message}")
                emptyList()
            }
        }
        return (hosts + extra).map { c ->
            // Whole days, rounded down: something that ran out an hour ago is
            // -1 day and "expired" (DAYS.between would truncate it to 0).
            val daysRemaining = Math.floorDiv(java.time.Duration.between(now, c.validUntil).seconds, 86_400L).toInt()
            val level = when {
                c.validUntil.isBefore(now) -> "expired"
                daysRemaining <= warnDays -> "warning"
                else -> "ok"
            }
            CertExpiryStatus(
                hostname = c.label,
                configApiId = c.configApiId,
                validUntil = c.validUntil.toString(),
                daysRemaining = daysRemaining,
                level = level,
                kind = c.kind
            )
        }.sortedBy { it.daysRemaining }
    }

    fun getOverallStatus(): String {
        val statuses = checkAll()
        return when {
            statuses.any { it.level == "expired" } -> "critical"
            statuses.any { it.level == "warning" } -> "degraded"
            else -> "ok"
        }
    }

    fun logWarnings() {
        val issues = checkAll().filter { it.level != "ok" }
        issues.forEach { cert ->
            val what = if (cert.kind == KIND_HOST) "Certificate" else "${cert.kind.replace('_', ' ')} "
            when (cert.level) {
                "expired" -> println("CRITICAL: ${what.trim().replaceFirstChar { it.uppercase() }} EXPIRED for ${cert.hostname} (${cert.configApiId})")
                "warning" -> println("WARNING: ${what.trim().replaceFirstChar { it.uppercase() }} expires in ${cert.daysRemaining} days for ${cert.hostname} (${cert.configApiId})")
            }
        }
        if (issues.isEmpty()) {
            println("Cert expiry check: all certificates OK")
        }
    }

    companion object {
        const val KIND_HOST = "host"
        const val KIND_CONFIG_API = "config_api"
        const val KIND_CLIENT_CA = "client_ca"
        const val KIND_SERVER_CA = "server_ca"
        const val KIND_HOST_CLIENT_CERT = "host_client_cert"
        const val KIND_VAULT_FILE = "vault_file"
    }
}

@Serializable
data class CertExpiryStatus(
    /** The host name, or for the other kinds the label the dashboard shows. */
    val hostname: String,
    val configApiId: String,
    val validUntil: String,
    val daysRemaining: Int,
    val level: String, // "ok", "warning", "expired"
    /** `host` (a pinned host's certificate), `config_api`, `client_ca`, `server_ca`, `host_client_cert`, `vault_file`. */
    val kind: String = CertExpiryMonitor.KIND_HOST
)
