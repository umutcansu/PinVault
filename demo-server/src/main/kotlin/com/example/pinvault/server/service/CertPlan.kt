package com.example.pinvault.server.service

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

/**
 * A certificate change worked out in full before anything is written: the
 * pins devices will be given, the certificate behind the first of them and,
 * for a certificate this server serves itself, the keystores to install.
 *
 * With two-person approval the plan is made when the change is REQUESTED and
 * stored with the change request. The approver is shown these pins, and the
 * approval installs exactly this plan: nothing is fetched or generated a
 * second time, so what is applied cannot differ from what was approved (a
 * URL that serves another certificate an hour later, a key generated anew).
 * Without approvals the same plan is made and applied in one request.
 */
@Serializable
data class CertPlan(
    /** `generated`, `uploaded`, `rotated` (the stored backup key takes over) or `fetched`. */
    val source: String,
    /** The pinned host whose pins change. */
    val hostname: String,
    /** The pins to publish: the certificate's key first, the backup second. */
    val pins: List<String>,
    val subject: String,
    val issuer: String,
    val notBefore: String,
    val notAfter: String,
    /** SHA-256 of the certificate, hex with colons. */
    val fingerprint: String,
    /** `host:port` the certificate was read from (`fetched` only). */
    val fetchedFrom: String? = null,
    /** Base64 JKS for `<id>.jks` (null for `fetched`: the server holds no key). */
    val keystore: String? = null,
    /** Base64 JKS for `<id>.backup.jks`. */
    val backupKeystore: String? = null
) {
    /** What an approver is shown and the audit log keeps: everything but the keystores. */
    fun publicJson(): JsonObject = buildJsonObject {
        put("source", source)
        put("hostname", hostname)
        putJsonArray("pins") { pins.forEach { add(it) } }
        put("subject", subject)
        put("issuer", issuer)
        put("notBefore", notBefore)
        put("notAfter", notAfter)
        put("fingerprint", fingerprint)
        fetchedFrom?.let { put("fetchedFrom", it) }
    }

    fun encode(): ByteArray = Json.encodeToString(serializer(), this).toByteArray(Charsets.UTF_8)

    companion object {
        private val lenient = Json { ignoreUnknownKeys = true }

        fun decode(bytes: ByteArray): CertPlan = lenient.decodeFromString(serializer(), bytes.toString(Charsets.UTF_8))
    }
}
