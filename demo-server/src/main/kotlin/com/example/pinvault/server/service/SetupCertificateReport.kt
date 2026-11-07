package com.example.pinvault.server.service

import java.time.Instant
import java.time.temporal.ChronoUnit

/**
 * What the setup wizard's "Certificates" step is built from: every
 * certificate and expiry an operator has to decide on before production —
 * public facts only (names, dates, pins, counts), never key material.
 */
data class SetupCertificateFacts(
    val configApiCert: ServerCertificate?,
    val listeners: List<Listener>,
    /** `SETUP_PUBLIC_HOST`; null = unknown. */
    val publicHost: String?,
    val clientCa: Authority?,
    val clientCertTtlDays: Long,
    val enrollmentMode: String,
    val activeIdentities: Int,
    val p12Enrollment: Boolean,
    val serverCa: Authority?,
    val recoveryPort: Int?,
    val recoveryRunning: Boolean,
    val hosts: List<Host>,
    val vaultFiles: List<VaultFile>,
    val warnDays: Int = 30,
    val now: Instant = Instant.now()
) {
    data class ServerCertificate(
        val subject: String,
        val issuer: String,
        val subjectAltNames: List<String>,
        val notAfter: String,
        val pins: List<String>,
        val backupKey: Boolean
    ) {
        val selfSigned: Boolean get() = subject == issuer
    }

    data class Listener(val id: String, val port: Int, val mode: String, val running: Boolean)

    data class Authority(val subject: String, val notAfter: String, val pin: String)

    data class Host(
        val hostname: String,
        val configApiId: String,
        /** `generated`, `uploaded`, `fetched`, `manual` (from the host's last history event). */
        val source: String,
        /** A mock listener of this server serves it. */
        val servedHere: Boolean,
        val notAfter: String?,
        val backupKey: Boolean,
        val pinCount: Int,
        val mtls: Boolean,
        val clientCertNotAfter: String?
    )

    data class VaultFile(val configApiId: String, val key: String, val expiresAt: String)
}

/**
 * The certificate checklist (same shape as [SetupReport.Check]): a row per
 * decision, with the panel action that gets the operator there.
 */
object SetupCertificateReport {

    /** [action]: `bootstrap` (the Config API's certificate), `mtls`, `host`, `vault`; null = nothing to open. */
    data class Check(
        val id: String,
        val level: SetupReport.Level,
        val current: String,
        val action: String? = null,
        val configApiId: String? = null,
        val hostname: String? = null,
        val key: String? = null
    )

    fun checks(f: SetupCertificateFacts): List<Check> {
        val out = mutableListOf<Check>()
        val ok = SetupReport.Level.OK
        val warn = SetupReport.Level.WARN
        val fail = SetupReport.Level.FAIL

        fun daysLeft(iso: String?): Int? = iso?.let { runCatching { ChronoUnit.DAYS.between(f.now, Instant.parse(it)).toInt() }.getOrNull() }
        fun validity(id: String, iso: String?, action: String?, api: String? = null, host: String? = null, key: String? = null): Check {
            val days = daysLeft(iso)
            return when {
                days == null -> Check(id, warn, "unknown", action, api, host, key)
                days < 0 -> Check(id, fail, "expired ${-days} day(s) ago", action, api, host, key)
                days <= f.warnDays -> Check(id, warn, "$days day(s) left", action, api, host, key)
                else -> Check(id, ok, "until ${iso!!.take(10)}", action, api, host, key)
            }
        }

        // ── The Config API's own certificate (the apps' bootstrap pins) ──
        val tlsApi = f.listeners.firstOrNull { it.mode == "tls" }?.id ?: f.listeners.firstOrNull()?.id
        val cert = f.configApiCert
        if (cert == null) {
            out += Check("config_api_cert", fail, "missing", "bootstrap", tlsApi)
        } else {
            out += validity("config_api_cert", cert.notAfter, "bootstrap", tlsApi)
            out += Check("config_api_cert_source", ok, if (cert.selfSigned) "self-signed, pinned" else "issued by ${cert.issuer.take(60)}", "bootstrap", tlsApi)
            out += if (cert.backupKey) Check("config_api_backup_key", ok, "stored", "bootstrap", tlsApi)
                else Check("config_api_backup_key", warn, "none", "bootstrap", tlsApi)
            val host = f.publicHost
            val names = cert.subjectAltNames.map { it.substringAfter(": ").trim() }
            out += when {
                host == null -> Check("config_api_cert_name", warn, "SETUP_PUBLIC_HOST not set", "bootstrap", tlsApi)
                names.any { it.equals(host, ignoreCase = true) } -> Check("config_api_cert_name", ok, host, "bootstrap", tlsApi)
                else -> Check("config_api_cert_name", warn, "$host not in ${names.joinToString().ifEmpty { "(no names)" }}", "bootstrap", tlsApi)
            }
        }

        // ── mTLS: the client CA, device certificates, the recovery door ──
        val mtlsApi = f.listeners.firstOrNull { it.mode == "mtls" }?.id
        val mtls = mtlsApi != null
        f.clientCa?.let { ca ->
            out += validity("client_ca", ca.notAfter, "mtls", mtlsApi)
        } ?: run { if (mtls) out += Check("client_ca", fail, "missing", "mtls", mtlsApi) }
        if (mtls) {
            out += when {
                f.clientCertTtlDays > 365 -> Check("client_cert_ttl", warn, "${f.clientCertTtlDays} days", "mtls", mtlsApi)
                else -> Check("client_cert_ttl", ok, "${f.clientCertTtlDays} days", "mtls", mtlsApi)
            }
            out += if (f.enrollmentMode == "open") Check("enrollment_mode", fail, "open", "mtls", mtlsApi)
                else Check("enrollment_mode", ok, f.enrollmentMode, "mtls", mtlsApi)
            out += if (f.p12Enrollment) Check("p12_enrollment", warn, "on", "mtls", mtlsApi) else Check("p12_enrollment", ok, "off", "mtls", mtlsApi)
            out += when {
                f.recoveryPort == null -> Check("recovery_door", warn, "off", "mtls", mtlsApi)
                !f.recoveryRunning -> Check("recovery_door", fail, "port ${f.recoveryPort}, not running", "mtls", mtlsApi)
                else -> Check("recovery_door", ok, "port ${f.recoveryPort}", "mtls", mtlsApi)
            }
            f.serverCa?.let { out += validity("server_ca", it.notAfter, "mtls", mtlsApi) }
            out += Check("enrolled_devices", ok, "${f.activeIdentities}", "mtls", mtlsApi)
        }

        // ── Pinned hosts ──
        f.hosts.forEach { h ->
            out += validity("host_cert", h.notAfter, "host", h.configApiId, h.hostname)
            out += when {
                h.pinCount < 2 -> Check("host_backup_pin", fail, "${h.pinCount} pin", "host", h.configApiId, h.hostname)
                h.backupKey -> Check("host_backup_pin", ok, "stored backup key", "host", h.configApiId, h.hostname)
                h.source == "fetched" -> Check("host_backup_pin", warn, "probably the issuing CA's pin", "host", h.configApiId, h.hostname)
                h.source == "manual" -> Check("host_backup_pin", warn, "entered by hand, origin unknown", "host", h.configApiId, h.hostname)
                else -> Check("host_backup_pin", warn, "no backup key stored", "host", h.configApiId, h.hostname)
            }
            if (h.servedHere) out += Check("host_served_here", warn, "mock listener of this server", "host", h.configApiId, h.hostname)
            if (h.mtls) {
                out += if (h.clientCertNotAfter != null) validity("host_client_cert", h.clientCertNotAfter, "host", h.configApiId, h.hostname)
                    else Check("host_client_cert", ok, "devices use their enrolled identity", "host", h.configApiId, h.hostname)
            }
        }

        // ── Vault files with an expiry ──
        f.vaultFiles.forEach { v ->
            out += validity("vault_file", v.expiresAt, "vault", v.configApiId, key = v.key)
        }
        return out
    }
}
