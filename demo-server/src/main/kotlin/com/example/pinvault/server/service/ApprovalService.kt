package com.example.pinvault.server.service

import com.example.pinvault.server.plugin.ApprovalReplay
import com.example.pinvault.server.store.ChangeRequest
import com.example.pinvault.server.store.ChangeRequestStore
import io.ktor.http.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant

/**
 * Routes that change what devices trust, who counts as a device, or what
 * devices are handed: with approvals on, they wait for a second admin.
 */
object PinAffectingRoutes {
    /** Internal so the tests can walk every rule. */
    internal val rules: List<Triple<HttpMethod, Regex, String>> = listOf(
        Triple(HttpMethod.Put, Regex("^/api/v1/certificate-config/?$"), "pins_update"),
        Triple(HttpMethod.Post, Regex("^/api/v1/certificate-config/force-update(/[^/]+)?$"), "force_on"),
        Triple(HttpMethod.Post, Regex("^/api/v1/certificate-config/clear-force(/[^/]+)?$"), "force_off"),
        Triple(HttpMethod.Post, Regex("^/api/v1/config/[^/]+/update$"), "pins_update"),
        Triple(HttpMethod.Post, Regex("^/api/v1/pin-snapshots/[^/]+/restore$"), "pins_restore"),
        Triple(HttpMethod.Post, Regex("^/api/v1/management/hosts/[^/]+/generate-cert$"), "host_add"),
        Triple(HttpMethod.Post, Regex("^/api/v1/hosts/(generate-cert|fetch-from-url|upload-cert)$"), "host_add"),
        Triple(HttpMethod.Post, Regex("^/api/v1/hosts/[^/]+/(regenerate-cert|rotate-to-backup|upload-cert|fetch-cert-url|toggle-mtls|upload-client-cert)$"), "host_cert"),
        Triple(HttpMethod.Post, Regex("^/api/v1/config-apis/delete$"), "config_api_delete"),
        // Starting or stopping a listener decides which scope's pins a port
        // serves — stopping production and starting another scope on its port
        // would publish that scope's pins without touching a single pin.
        Triple(HttpMethod.Post, Regex("^/api/v1/config-apis/(start|stop)$"), "config_api_lifecycle"),
        Triple(HttpMethod.Post, Regex("^/api/v1/server-tls-pins/(regenerate|rotate-to-backup|upload|fetch-from-url)$"), "bootstrap_pins"),
        Triple(HttpMethod.Post, Regex("^/api/v1/signing-key/regenerate$"), "signing_key"),
        Triple(HttpMethod.Put, Regex("^/api/v1/signing-keyset$"), "signing_keyset"),
        // Server settings saved from the setup wizard: approvals, the live
        // check and the attestation modes among them. One admin must not
        // turn the two-person rule off alone.
        Triple(HttpMethod.Put, Regex("^/api/v1/server-settings$"), "server_settings"),
        // Which hosts a device's config lists (and so which it may reach):
        // granting a device a host it should not see is as good as adding a pin
        // for it. Revocation (DELETE /api/v1/client-certs/{id}) is deliberately
        // NOT here: an emergency revocation must take effect at once.
        Triple(HttpMethod.Put, Regex("^/api/v1/config-apis/[^/]+/default-host-acl$"), "host_acl"),
        Triple(HttpMethod.Put, Regex("^/api/v1/config-apis/[^/]+/devices/[^/]+/host-acl$"), "host_acl"),
        // Who the mTLS listeners let in. An uploaded certificate goes straight
        // into their truststore; a generated one is a new client identity; a
        // token, a code or the code-less switch lets a device make itself one.
        // Deciding on a device that asked (/enrollment-requests/{id}/approve)
        // is already a second person's act and is not gated again; stopping a
        // code and revoking are emergencies and take effect at once.
        Triple(HttpMethod.Post, Regex("^/api/v1/client-certs/upload$"), "client_cert_upload"),
        Triple(HttpMethod.Post, Regex("^/api/v1/client-certs/generate$"), "client_cert_generate"),
        Triple(HttpMethod.Post, Regex("^/api/v1/enrollment-policies$"), "enrollment_policy_create"),
        Triple(HttpMethod.Put, Regex("^/api/v1/enrollment-open$"), "enrollment_open"),
        Triple(HttpMethod.Post, Regex("^/api/v1/enrollment-tokens/generate$"), "enrollment_token"),
        // Vault files are applied by every device that may fetch them: their
        // content, who may fetch them, the tokens and keys that open them.
        Triple(HttpMethod.Put, Regex("^/api/v1/config-apis/[^/]+/vault/[^/]+$"), "vault_upload"),
        Triple(HttpMethod.Delete, Regex("^/api/v1/config-apis/[^/]+/vault/[^/]+$"), "vault_delete"),
        Triple(HttpMethod.Put, Regex("^/api/v1/config-apis/[^/]+/vault/[^/]+/policy$"), "vault_policy"),
        Triple(HttpMethod.Post, Regex("^/api/v1/config-apis/[^/]+/vault/[^/]+/tokens$"), "vault_token_issue"),
        Triple(HttpMethod.Delete, Regex("^/api/v1/config-apis/[^/]+/vault/tokens/[^/]+$"), "vault_token_revoke"),
        Triple(HttpMethod.Delete, Regex("^/api/v1/config-apis/[^/]+/vault/devices/[^/]+/public-key$"), "device_key_reset"),
        Triple(HttpMethod.Put, Regex("^/api/v1/config-apis/[^/]+/vault-enabled$"), "vault_enabled"),
        // Attestation (ATTESTATION.md §6): the policy decides which devices get
        // pins and a token; an override lets one device through (or none); a
        // forgotten key lets a new one register; the token secrets are what
        // every backend trusts.
        Triple(HttpMethod.Put, Regex("^/api/v1/config-apis/[^/]+/attestation/policy$"), "attestation_policy"),
        Triple(HttpMethod.Put, Regex("^/api/v1/config-apis/[^/]+/attestation/devices/[^/]+$"), "attestation_device"),
        Triple(HttpMethod.Delete, Regex("^/api/v1/config-apis/[^/]+/attestation/devices/[^/]+$"), "attestation_device"),
        Triple(HttpMethod.Delete, Regex("^/api/v1/config-apis/[^/]+/attestation/devices/[^/]+/anomaly$"), "attestation_device"),
        Triple(HttpMethod.Get, Regex("^/api/v1/attestation/token-secrets$"), "attestation_token_secrets"),
        Triple(HttpMethod.Post, Regex("^/api/v1/attestation/token-secrets/rotate$"), "attestation_token_secret_rotate"),
        Triple(HttpMethod.Delete, Regex("^/api/v1/attestation/token-secrets/[^/]+$"), "attestation_token_secret_delete")
    )

    /**
     * Operations whose answer carries a secret that is shown once: a client
     * P12, an enrollment token, an enrollment code, a vault token. Replaying
     * them on approval would hand the secret to the approver and leave a copy
     * in the change request. Instead the approval only unlocks the request:
     * the REQUESTER sends the very same request again and it runs once, the
     * answer going to them alone (see [ApprovalService.claim]).
     */
    val requesterRun: Set<String> = setOf("client_cert_generate", "enrollment_policy_create", "enrollment_token", "vault_token_issue",
        // The HS256 secrets every backend verifies PinVault-Token with.
        "attestation_token_secrets")

    /** The kind of change [method] + [path] makes, or null when it does not affect pins or keys. Pass a [canonicalPath]. */
    fun match(method: HttpMethod, path: String): String? =
        rules.firstOrNull { (m, pattern, _) -> m == method && pattern.matches(path) }?.third

    /** Every kind of change [match] can answer — the dashboard labels each one (`op_<name>`). */
    val operations: Set<String> get() = rules.mapTo(linkedSetOf()) { it.third }

    /**
     * [raw] as Ktor routing resolves it: empty segments dropped and each
     * segment percent-decoded. The gate must decide on this form — two
     * spellings that route to the same handler must get the same answer.
     *
     * An encoded slash stays `%2F` inside its segment: routing matches
     * `x%2Fy` as ONE segment, so decoding it into a separator gave the gate a
     * path with one segment too many, which no rule matched
     * (`POST /api/v1/config/x%2Fy/update` skipped approval). [EncodedPathGuard]
     * refuses such paths before this runs; this is the second line.
     */
    fun canonicalPath(raw: String): String =
        "/" + raw.split('/').filter { it.isNotEmpty() }.joinToString("/") { percentDecode(it) }

    /**
     * The Config API a gated request writes, read the way its handler reads
     * it: a `{configApiId}` path segment wins (handlers read it with
     * `pathParameters`, so a `?configApiId=` beside it changes nothing),
     * otherwise `?configApiId=`, otherwise the management server's default.
     * The approver must be shown the scope that will actually change.
     */
    fun scopeOf(canonicalPath: String, query: String): String =
        SCOPE_IN_PATH.firstNotNullOfOrNull { it.find(canonicalPath)?.groupValues?.get(1) }?.let(::segmentValue)
            ?: parseQueryString(query)["configApiId"]
            ?: "default-tls"

    /** The `{hostname}` segment of a host-scoped gated route, as its handler reads it; null when the route has none. */
    fun hostOf(canonicalPath: String): String? =
        HOST_IN_PATH.firstNotNullOfOrNull { it.find(canonicalPath)?.groupValues?.get(1) }?.let(::segmentValue)

    /** A canonical segment as routing hands it to the handler (the `%2F` [canonicalPath] keeps, decoded). */
    private fun segmentValue(segment: String): String = segment.replace("%2F", "/")

    private val SCOPE_IN_PATH = listOf(
        Regex("^/api/v1/config/([^/]+)/update$"),
        Regex("^/api/v1/management/hosts/([^/]+)/generate-cert$"),
        Regex("^/api/v1/config-apis/([^/]+)/(?:default-host-acl|devices/[^/]+/host-acl)$"),
        Regex("^/api/v1/config-apis/([^/]+)/(?:vault-enabled|vault/.+)$"),
        Regex("^/api/v1/config-apis/([^/]+)/attestation/.+$")
    )

    /** The `{deviceId}` of a per-device host ACL write, as its handler reads it; null for the default ACL. */
    fun deviceOf(canonicalPath: String): String? =
        DEVICE_IN_PATH.find(canonicalPath)?.groupValues?.get(1)?.let(::segmentValue)

    private val DEVICE_IN_PATH = Regex("^/api/v1/config-apis/[^/]+/devices/([^/]+)/host-acl$")

    /** What follows `/vault/` on a scoped vault admin route, each segment as its handler reads it; empty for any other route. */
    fun vaultSegments(canonicalPath: String): List<String> =
        VAULT_PATH.find(canonicalPath)?.groupValues?.get(1)?.split('/')?.map(::segmentValue).orEmpty()

    private val VAULT_PATH = Regex("^/api/v1/config-apis/[^/]+/vault/(.+)$")

    private val HOST_IN_PATH = listOf(
        Regex("^/api/v1/certificate-config/(?:force-update|clear-force)/([^/]+)$"),
        Regex("^/api/v1/hosts/([^/]+)/[^/]+$")
    )

    /** `%XX` escapes → UTF-8 text, as routing decodes a path segment ('+' stays '+'); `%2F` stays as it is. */
    private fun percentDecode(segment: String): String {
        if ('%' !in segment) return segment
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (i < segment.length) {
            val c = segment[i]
            if (c == '%' && i + 2 < segment.length) {
                val hex = segment.substring(i + 1, i + 3).toIntOrNull(16)
                if (hex == 0x2F) {
                    out.write("%2F".toByteArray())
                    i += 3
                    continue
                }
                if (hex != null) {
                    out.write(hex)
                    i += 3
                    continue
                }
            }
            out.write(c.toString().toByteArray(Charsets.UTF_8))
            i++
        }
        return out.toString(Charsets.UTF_8)
    }
}

/**
 * Two-person rule for pin and key changes (`PIN_CHANGE_APPROVALS`, default 1 = off).
 *
 * With `PIN_CHANGE_APPROVALS=2` a pin-affecting request is not executed: it
 * becomes a pending change request, and only when another admin approves it
 * does the server replay that exact request — as the requester — through its
 * own management API. `3` needs two approvers besides the requester, and so on.
 * Nobody can approve their own request; requests expire after
 * `APPROVAL_TTL_HOURS` (default 24).
 *
 * Needs named admins (`ADMIN_KEYS`): with a single shared key there is nobody
 * to approve.
 */
class ApprovalService(
    private val store: ChangeRequestStore,
    private val audit: AuditLog,
    val required: Int,
    private val ttlHours: Long = 24,
    private val managementPort: Int,
    private val describe: (ChangeInput) -> Description,
    /**
     * A fingerprint of a Config API's current pins. A request records it; the
     * approval re-checks it, so a full-config write approved late cannot undo
     * a change that was approved in between.
     */
    private val stateHash: (configApiId: String) -> String = { "" },
    private val replay: (ChangeRequest, ByteArray, String) -> Pair<Int, String> = { cr, body, token ->
        loopbackReplay(managementPort, cr, body, token)
    },
    /**
     * Operations an operator took OUT of the two-person rule on purpose
     * (`APPROVAL_EXEMPT_OPERATIONS`): they run at once, for any admin.
     */
    val exempt: Set<String> = emptySet(),
    /**
     * The current fingerprint of what a card names by reference
     * ([Description.stateRefs], [ChangeDescriber.stateOf]); null = it does
     * not exist (now).
     */
    private val stateOf: (ref: String) -> String? = { null }
) {
    val enabled: Boolean get() = required > 1

    /** A gated request as it arrived, for [describe]. [path] is the canonical path. */
    class ChangeInput(
        val op: String,
        val path: String,
        val query: String,
        val contentType: String,
        val body: ByteArray,
        val requestedBy: String = "",
        /** The HTTP method: one path can be gated for PUT and DELETE (an attestation device). */
        val method: String = "",
        /**
         * `X-PinVault-Base-State` of the request, when it was sent: the state
         * of the scope the requester's editor had loaded. A full-config write
         * computed from another state is refused when it is requested (409
         * `stale_config`), as its handler refuses it — not shown to an approver
         * as "removes the host the other admin just added".
         */
        val baseState: String? = null
    )

    /** What a pending change does, for the approver. */
    data class Description(
        val configApiId: String,
        val summary: String,
        val detail: JsonObject,
        /** Set for changes computed against the scope's current pins (see [stateHash]). */
        val baseHash: String? = null,
        /**
         * A fingerprint of whatever else the card was computed from — the
         * saved settings a save touches, the attestation policy, a device's
         * overrides. The request is described again when it is approved and
         * refused as stale if this differs: the card showed a difference from
         * a state that is no longer there.
         */
        val stateKey: String? = null,
        /**
         * Fingerprints of what the change acts on, by reference (see
         * [ChangeDescriber.stateOf]): the bootstrap certificate, which API a
         * port serves, a vault file's metadata, a device's key. Checked again,
         * cheaply, when the request is approved — without describing (and so
         * planning) it a second time.
         */
        val stateRefs: Map<String, String> = emptyMap(),
        /**
         * What the change will install, fixed now (a [CertPlan]): stored with
         * the request and handed to the handler when the approved request is
         * replayed, so nothing is fetched or generated a second time.
         */
        val prepared: ByteArray? = null
    )

    /** [body], when set, is answered as it is (a live-check refusal the dashboard knows how to show). */
    class Refused(val status: HttpStatusCode, message: String, val body: JsonObject? = null) : Exception(message)

    @Serializable
    data class Pending(
        val pendingApproval: Boolean = true,
        val changeRequestId: Long,
        val summary: String,
        val approvalsRequired: Int,
        val message: String,
        /** True when the requester has to send the request again after approval (its answer carries a secret). */
        val runAfterApproval: Boolean = false
    )

    /**
     * Stores a change request. [path] is the path as sent (the replay goes to
     * exactly the same handler); [canonicalPath] is what routing resolved it
     * to, which is what the description — and the approver — must look at.
     * A request that cannot be described is refused: an approver must never
     * be asked to approve something they cannot see.
     */
    fun submit(
        requestedBy: String,
        op: String,
        method: String,
        path: String,
        canonicalPath: String = path,
        query: String,
        contentType: String,
        body: ByteArray,
        baseState: String? = null
    ): Pending {
        val description = try {
            describe(ChangeInput(op, canonicalPath, query, contentType, body, requestedBy, method, baseState)).let { it.copy(summary = plainText(it.summary, MAX_SUMMARY)) }
        } catch (e: Refused) {
            throw e
        } catch (e: Exception) {
            throw Refused(HttpStatusCode.BadRequest, "This change cannot be described for approval: ${e.message ?: e.javaClass.simpleName}")
        }
        val now = Instant.now()
        val id = store.create(
            createdAt = now.toString(),
            expiresAt = now.plus(Duration.ofHours(ttlHours)).toString(),
            requestedBy = requestedBy,
            method = method,
            path = path,
            query = query,
            contentType = contentType,
            body = body,
            configApiId = description.configApiId,
            summary = description.summary,
            detail = JsonObject(
                description.detail + (description.baseHash?.let { mapOf("baseHash" to kotlinx.serialization.json.JsonPrimitive(it)) } ?: emptyMap()) +
                    (description.stateKey?.let { mapOf("stateKey" to kotlinx.serialization.json.JsonPrimitive(it)) } ?: emptyMap()) +
                    (description.stateRefs.takeIf { it.isNotEmpty() }?.let { refs ->
                        mapOf(STATE_REFS to JsonObject(refs.mapValues { kotlinx.serialization.json.JsonPrimitive(it.value) }))
                    } ?: emptyMap())
            ).toString(),
            prepared = description.prepared
        )
        audit.record(
            action = "change_requested",
            summary = "#$id ${description.summary}",
            configApiId = description.configApiId,
            target = "$method $path",
            detail = description.detail,
            actor = requestedBy
        )
        return Pending(
            changeRequestId = id,
            summary = description.summary,
            approvalsRequired = required,
            message = "Change #$id is waiting for approval by ${required - 1} other admin(s)." +
                if (op in PinAffectingRoutes.requesterRun) " Once approved, send the same request again to run it: its answer is shown only to you." else "",
            runAfterApproval = op in PinAffectingRoutes.requesterRun
        )
    }

    /** The plan stored with change request [id] (see [Description.prepared]); null when it has none. */
    fun prepared(id: Long): ByteArray? = store.prepared(id)

    /**
     * The approved request of [requestedBy] that this very request repeats —
     * same method, path, query and body — spent so that it runs exactly once;
     * null when there is none (the request then waits for approval like any
     * other). Only for [PinAffectingRoutes.requesterRun] operations.
     */
    @Synchronized
    fun claim(requestedBy: String, method: String, canonicalPath: String, query: String, body: ByteArray): ChangeRequest? {
        expireOverdue()
        val match = store.approvedOf(requestedBy).firstOrNull { cr ->
            cr.method.equals(method, ignoreCase = true) &&
                PinAffectingRoutes.canonicalPath(cr.path) == canonicalPath && cr.query == query &&
                java.security.MessageDigest.isEqual(store.body(cr.id) ?: ByteArray(0), body)
        } ?: return null
        return if (store.claimApproved(match.id, match.approvedBy.lastOrNull(), Instant.now().toString())) match else null
    }

    /** Records how a claimed request ended (see [claim]); its answer is not kept. */
    fun finishRun(cr: ChangeRequest, status: Int) {
        store.recordRun(cr.id, status)
        val applied = status in 200..299
        audit.record(
            action = if (applied) "change_applied" else "change_failed",
            summary = "#${cr.id} ${if (applied) "run by its requester" else "failed (HTTP $status)"} — ${cr.summary}",
            configApiId = cr.configApiId,
            target = "${cr.method} ${cr.path}",
            detail = buildJsonObject {
                put("requestedBy", cr.requestedBy)
                put("approvedBy", cr.approvedBy.joinToString(","))
                put("resultStatus", status)
            },
            actor = cr.requestedBy
        )
    }

    fun list(status: String?): List<ChangeRequest> {
        expireOverdue()
        return store.list(status)
    }

    fun get(id: Long): ChangeRequest? {
        expireOverdue()
        return store.get(id)
    }

    /**
     * Records [approver]'s approval; once enough distinct admins other than
     * the requester approved, replays the request and returns its outcome.
     * [approverIp] goes on the audit entries the replay writes.
     */
    @Synchronized
    fun approve(id: Long, approver: String, approverIp: String = ""): ChangeRequest {
        expireOverdue()
        val cr = store.get(id) ?: throw Refused(HttpStatusCode.NotFound, "Change request #$id not found")
        if (cr.status != "pending") throw Refused(HttpStatusCode.Conflict, "Change request #$id is ${cr.status}")
        if (Instant.parse(cr.expiresAt).isBefore(Instant.now())) {
            if (store.decideIfPending(id, "expired", null, Instant.now().toString(), "not approved within ${ttlHours}h", null, null)) {
                audit.record("change_expired", "#$id expired unapproved — ${cr.summary}", cr.configApiId, "${cr.method} ${cr.path}", actor = "system")
            }
            throw Refused(HttpStatusCode.Conflict, "Change request #$id expired")
        }
        // 409, not 403: the dashboard treats 401/403 as "wrong key" and prompts for another.
        if (approver == cr.requestedBy) {
            throw Refused(HttpStatusCode.Conflict, "The admin who requested a change cannot approve it — another admin must.")
        }
        if (approver == com.example.pinvault.server.plugin.AdminRegistry.LEGACY_NAME || approver == "anonymous") {
            throw Refused(
                HttpStatusCode.Conflict,
                "A shared key (API_KEY) cannot approve: it does not say WHO approves. Use a personal key from ADMIN_KEYS."
            )
        }
        val base = runCatching {
            kotlinx.serialization.json.Json.parseToJsonElement(cr.detail).let { it as JsonObject }["baseHash"]
                ?.let { (it as kotlinx.serialization.json.JsonPrimitive).content }
        }.getOrNull()
        // Every other Config API the change writes to, as recorded on its card.
        val staleScope = runCatching {
            ((kotlinx.serialization.json.Json.parseToJsonElement(cr.detail) as JsonObject)[SCOPE_HASHES] as? JsonObject)
                ?.entries?.firstOrNull { (scope, hash) -> (hash as kotlinx.serialization.json.JsonPrimitive).content != stateHash(scope) }?.key
        }.getOrNull()
        if (staleScope != null) {
            store.decideIfPending(id, "stale", approver, Instant.now().toString(), "pins of $staleScope changed since the request was made", null, null)
            audit.record("change_stale", "#$id not applied: $staleScope changed since it was requested — ${cr.summary}",
                cr.configApiId, "${cr.method} ${cr.path}", actor = approver)
            throw Refused(HttpStatusCode.Conflict, "The pins of $staleScope changed after #$id was requested. Ask for a fresh request.")
        }
        if (base != null && base != stateHash(cr.configApiId)) {
            store.decideIfPending(id, "stale", approver, Instant.now().toString(), "pins changed since the request was made", null, null)
            audit.record("change_stale", "#$id not applied: ${cr.configApiId} changed since it was requested — ${cr.summary}",
                cr.configApiId, "${cr.method} ${cr.path}", actor = approver)
            throw Refused(HttpStatusCode.Conflict, "The pins of ${cr.configApiId} changed after #$id was requested. Ask for a fresh request.")
        }
        // What the card names by reference (the bootstrap certificate, a port,
        // a vault file, a device key): fingerprinted again now.
        val movedRef = runCatching {
            ((kotlinx.serialization.json.Json.parseToJsonElement(cr.detail) as JsonObject)[STATE_REFS] as? JsonObject)
                ?.entries?.firstOrNull { (ref, then) -> (then as kotlinx.serialization.json.JsonPrimitive).content != (stateOf(ref) ?: MISSING_STATE) }?.key
        }.getOrElse { "(unreadable)" }
        if (movedRef != null) {
            store.decideIfPending(id, "stale", approver, Instant.now().toString(), "what the change acts on changed since the request was made ($movedRef)", null, null)
            audit.record("change_stale", "#$id not applied: ${describeRef(movedRef)} changed since it was requested — ${cr.summary}",
                cr.configApiId, "${cr.method} ${cr.path}", actor = approver)
            throw Refused(HttpStatusCode.Conflict, "${describeRef(movedRef).replaceFirstChar { it.uppercase() }} changed after #$id was requested: " +
                "its card no longer says what it would do. Ask for a fresh request.")
        }
        // Cards that are a difference from other state than pins (settings, an
        // attestation policy, a device's overrides): described again now, and
        // refused when the state they were computed from moved.
        val stateKey = runCatching {
            (kotlinx.serialization.json.Json.parseToJsonElement(cr.detail) as JsonObject)["stateKey"]
                ?.let { (it as kotlinx.serialization.json.JsonPrimitive).content }
        }.getOrNull()
        if (stateKey != null) {
            val now = runCatching {
                describe(ChangeInput(
                    operationOf(cr) ?: "", PinAffectingRoutes.canonicalPath(cr.path), cr.query, cr.contentType,
                    store.body(id) ?: ByteArray(0), cr.requestedBy, cr.method
                )).stateKey
            }.getOrNull()
            if (now != stateKey) {
                store.decideIfPending(id, "stale", approver, Instant.now().toString(), "what the change acts on changed since the request was made", null, null)
                audit.record("change_stale", "#$id not applied: what it changes was changed after it was requested — ${cr.summary}",
                    cr.configApiId, "${cr.method} ${cr.path}", actor = approver)
                throw Refused(HttpStatusCode.Conflict, "What #$id changes was changed after it was requested: its card no longer says what it would do. Ask for a fresh request.")
            }
        }
        // A request stored before the gate refused other charsets (see ApprovalGate): never replayed.
        if (namesAnotherCharset(cr.contentType)) {
            store.decideIfPending(id, "stale", approver, Instant.now().toString(), "the body is not UTF-8", null, null)
            throw Refused(HttpStatusCode.Conflict, "#$id was sent in a charset other than UTF-8 and cannot be approved. Ask for a fresh request.")
        }
        if (approver in cr.approvedBy) throw Refused(HttpStatusCode.Conflict, "$approver already approved #$id")

        store.addApproval(id, approver)
        val approvers = cr.approvedBy + approver
        if (approvers.size < required - 1) {
            audit.record("change_approved", "#$id approved by $approver (${approvers.size}/${required - 1}) — ${cr.summary}",
                cr.configApiId, "${cr.method} ${cr.path}", actor = approver)
            return store.get(id)!!
        }

        // An answer that carries a secret is not produced here: the requester
        // runs the request themselves, once (see claim).
        if (operationOf(cr) in PinAffectingRoutes.requesterRun) {
            store.markApproved(id)
            audit.record("change_approved", "#$id approved by ${approvers.joinToString(", ")} — ${cr.requestedBy} may now run it once: ${cr.summary}",
                cr.configApiId, "${cr.method} ${cr.path}", actor = approver)
            return store.get(id)!!
        }

        val actor = "${cr.requestedBy} (approved by ${approvers.joinToString(", ")})"
        val token = ApprovalReplay.issue(id, actor, cr.method, cr.path, cr.query, approverIp)
        val (status, body) = try {
            replay(cr, store.body(id) ?: ByteArray(0), token)
        } catch (e: Exception) {
            0 to (e.message ?: e.javaClass.simpleName)
        }
        val applied = status in 200..299
        store.decideIfPending(id, if (applied) "applied" else "failed", approver, Instant.now().toString(), null, status, body.take(2000))
        audit.record(
            action = if (applied) "change_applied" else "change_failed",
            summary = "#$id ${if (applied) "applied" else "failed (HTTP $status)"} — ${cr.summary}",
            configApiId = cr.configApiId,
            target = "${cr.method} ${cr.path}",
            detail = buildJsonObject {
                put("requestedBy", cr.requestedBy)
                put("approvedBy", approvers.joinToString(","))
                put("resultStatus", status)
                if (!applied) put("result", body.take(500))
            },
            actor = approver
        )
        return store.get(id)!!
    }

    /** Rejects a pending request; its requester may also withdraw it this way. */
    @Synchronized
    fun reject(id: Long, by: String, reason: String?): ChangeRequest {
        expireOverdue()
        val cr = store.get(id) ?: throw Refused(HttpStatusCode.NotFound, "Change request #$id not found")
        // An approved request that was not run yet can still be withdrawn or rejected.
        if (cr.status != "pending" && cr.status != "approved") throw Refused(HttpStatusCode.Conflict, "Change request #$id is ${cr.status}")
        store.decideIfPending(id, "rejected", by, Instant.now().toString(), reason, null, null)
        audit.record(
            action = "change_rejected",
            summary = "#$id ${if (by == cr.requestedBy) "withdrawn" else "rejected"} by $by" +
                (reason?.takeIf { it.isNotBlank() }?.let { ": $it" } ?: "") + " — ${cr.summary}",
            configApiId = cr.configApiId,
            target = "${cr.method} ${cr.path}",
            actor = by
        )
        return store.get(id)!!
    }

    /** The operation a stored request was filed under (its detail carries it). */
    private fun operationOf(cr: ChangeRequest): String? = runCatching {
        (kotlinx.serialization.json.Json.parseToJsonElement(cr.detail) as JsonObject)["operation"]
            ?.let { (it as kotlinx.serialization.json.JsonPrimitive).content }
    }.getOrNull() ?: PinAffectingRoutes.match(HttpMethod.parse(cr.method), PinAffectingRoutes.canonicalPath(cr.path))

    private fun expireOverdue() {
        val now = Instant.now()
        // Every overdue request, not just the newest page of pending ones; and
        // only a request still pending is expired (never an applied one).
        store.pendingExpiredBefore(now.toString()).forEach { cr ->
            if (store.decideIfPending(cr.id, "expired", null, now.toString(), "not approved within ${ttlHours}h", null, null)) {
                audit.record("change_expired", "#${cr.id} expired unapproved — ${cr.summary}", cr.configApiId,
                    "${cr.method} ${cr.path}", actor = "system")
            }
        }
    }

    companion object {
        /** Card detail: `{scope: stateHash}` of every further Config API a change writes to; each must still match at approval. */
        const val SCOPE_HASHES = "scopeHashes"

        /** Card detail: `{ref: fingerprint}` (see [Description.stateRefs]); each must still match at approval. */
        const val STATE_REFS = "stateRefs"

        /** The fingerprint of a reference whose object does not exist. */
        const val MISSING_STATE = "-"

        /** A reference ([ChangeDescriber.stateOf]) in words, for the refusal and the audit log. */
        fun describeRef(ref: String): String {
            val parts = ref.split('|')
            return when (parts.first()) {
                "bootstrap" -> "the Config API TLS certificate (bootstrap pins and backup key)"
                "port" -> "what listens on port ${parts.getOrNull(1)}"
                "vault" -> "vault file ${parts.getOrNull(2)} of ${parts.getOrNull(1)}"
                "device-key" -> "the ${if (parts.getOrNull(2) == "user_auth") "user-auth" else "E2E"} key of device ${parts.getOrNull(3)} in ${parts.getOrNull(1)}"
                else -> "what the change acts on"
            }.let { plainText(it, 160) }
        }

        private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()

        /** Sends the stored request to this server's own management port. */
        fun loopbackReplay(port: Int, cr: ChangeRequest, body: ByteArray, token: String): Pair<Int, String> {
            val uri = URI("http://127.0.0.1:$port${cr.path}${if (cr.query.isNotEmpty()) "?" + cr.query else ""}")
            val request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(120))
                .header(ApprovalReplay.HEADER, token)
                .apply { if (cr.contentType.isNotBlank()) header("Content-Type", cr.contentType) }
                .method(cr.method, HttpRequest.BodyPublishers.ofByteArray(body))
                .build()
            val response = client.send(request, HttpResponse.BodyHandlers.ofString())
            return response.statusCode() to response.body()
        }

        /**
         * `PIN_CHANGE_APPROVALS`: how many admins a gated change needs (1 = no
         * second admin; unset = 1). A value that is not a whole number from 1
         * to [MAX_REQUIRED] stops the start: it used to count as 1, so a typo
         * ("2 admins", "two") switched the two-person rule off without a word.
         */
        fun requiredFromEnv(env: Map<String, String> = com.example.pinvault.server.service.ServerEnv.all()): Int {
            val raw = env["PIN_CHANGE_APPROVALS"]?.trim().orEmpty()
            if (raw.isEmpty()) return 1
            return raw.toIntOrNull()?.takeIf { it in 1..MAX_REQUIRED }
                ?: error("PIN_CHANGE_APPROVALS must be a whole number from 1 to $MAX_REQUIRED (got '$raw')")
        }

        /**
         * Why [required] approvals cannot work with the admin keys in
         * [admins], or null when they can: every approver is a personal key
         * (`ADMIN_KEYS`), other than the requester's. The start-up refuses
         * such a server, and a settings save that would make one is refused
         * with this sentence (`ServerSettingsCatalog.startProblems`).
         */
        fun adminKeysProblem(required: Int, admins: com.example.pinvault.server.plugin.AdminRegistry): String? {
            if (required <= 1) return null
            if (admins.isEmpty) return "PIN_CHANGE_APPROVALS=$required cannot work without admin keys (anonymous admin mode)."
            val personal = admins.names.count { it != com.example.pinvault.server.plugin.AdminRegistry.LEGACY_NAME }
            return if (personal >= required - 1) null else
                "PIN_CHANGE_APPROVALS=$required needs at least ${required - 1} personal admin key(s) in " +
                    "ADMIN_KEYS to approve changes (found $personal). A shared API_KEY cannot approve."
        }

        /** The most admins a change can be made to need (the dashboard's settings page offers the same range). */
        const val MAX_REQUIRED = 5

        /**
         * `APPROVAL_EXEMPT_OPERATIONS`: operation names (comma-separated, as
         * the approval cards show them: `enrollment_token`, `vault_token_revoke`, …)
         * that do NOT wait for a second admin. An unknown name is a startup
         * error — a typo must not leave an operator believing something is exempt,
         * or gated.
         */
        fun exemptFromEnv(env: Map<String, String> = com.example.pinvault.server.service.ServerEnv.all()): Set<String> {
            val names = env["APPROVAL_EXEMPT_OPERATIONS"].orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()
            val unknown = names - PinAffectingRoutes.operations
            require(unknown.isEmpty()) {
                "APPROVAL_EXEMPT_OPERATIONS: unknown operation(s) ${unknown.joinToString()} — known: ${PinAffectingRoutes.operations.joinToString()}"
            }
            return names
        }

        /** Longest summary an approver is shown; the full request is in the detail. */
        const val MAX_SUMMARY = 300

        /**
         * [text] safe to put in one line of an approver's confirm() and the
         * audit log: control characters (newlines included), line/paragraph
         * separators and bidi overrides become spaces, runs of spaces one, and
         * at most [max] characters remain. Summaries carry request-body fields
         * (a host's `url`, `hostname`); a newline there used to draw a fake
         * line under the real one ("…\nPins unchanged").
         */
        /**
         * Whether a `Content-Type` header names a body charset other than
         * UTF-8, read the way Ktor reads it for the handler
         * (`request.contentCharset()`): the first `charset` parameter, any
         * spelling of the media type, an unknown charset name counting as
         * none. A header Ktor cannot parse is refused too.
         */
        fun namesAnotherCharset(contentTypeHeader: String?): Boolean {
            if (contentTypeHeader.isNullOrBlank()) return false
            val charset = try {
                io.ktor.http.ContentType.parse(contentTypeHeader).charset()
            } catch (_: Exception) {
                return true
            }
            return charset != null && charset != Charsets.UTF_8
        }

        fun plainText(text: String, max: Int = MAX_SUMMARY): String {
            val cleaned = text.map { c ->
                if (c.isISOControl() || c.code == 0x2028 || c.code == 0x2029 || c.code in 0x202A..0x202E || c.code in 0x2066..0x2069) ' ' else c
            }.joinToString("").replace(Regex(" {2,}"), " ").trim()
            return if (cleaned.length <= max) cleaned else cleaned.take(max - 1).trimEnd() + Char(0x2026)
        }
    }
}
