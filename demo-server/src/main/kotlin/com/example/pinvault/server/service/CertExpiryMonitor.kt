package com.example.pinvault.server.service

import com.example.pinvault.server.store.HostStore
import kotlinx.serialization.Serializable
import java.time.Instant
import java.time.temporal.ChronoUnit

/**
 * Monitors certificate expiry for all managed hosts.
 * Used by /api/v1/cert-expiry and background check.
 */
class CertExpiryMonitor(
    private val hostStore: HostStore,
    private val warnDays: Int = System.getenv("CERT_EXPIRY_WARN_DAYS")?.toIntOrNull() ?: 30
) {

    fun checkAll(): List<CertExpiryStatus> {
        val now = Instant.now()
        val allHosts = hostStore.getAll()

        return allHosts.mapNotNull { host ->
            val validUntil = host.certValidUntil?.let {
                try { Instant.parse(it) } catch (_: Exception) { null }
            } ?: return@mapNotNull null

            val daysRemaining = ChronoUnit.DAYS.between(now, validUntil).toInt()
            val level = when {
                daysRemaining < 0 -> "expired"
                daysRemaining <= warnDays -> "warning"
                else -> "ok"
            }

            CertExpiryStatus(
                hostname = host.hostname,
                configApiId = host.configApiId,
                validUntil = host.certValidUntil!!,
                daysRemaining = daysRemaining,
                level = level
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
            when (cert.level) {
                "expired" -> println("CRITICAL: Certificate EXPIRED for ${cert.hostname} (${cert.configApiId})")
                "warning" -> println("WARNING: Certificate expires in ${cert.daysRemaining} days for ${cert.hostname} (${cert.configApiId})")
            }
        }
        if (issues.isEmpty()) {
            println("Cert expiry check: all certificates OK")
        }
    }
}

@Serializable
data class CertExpiryStatus(
    val hostname: String,
    val configApiId: String,
    val validUntil: String,
    val daysRemaining: Int,
    val level: String // "ok", "warning", "expired"
)
