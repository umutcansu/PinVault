package com.example.pinvault.server.service

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.plugin.MultipartForm
import com.example.pinvault.server.route.LiveCheckRejection
import com.example.pinvault.server.route.isReservedClientId
import com.example.pinvault.server.route.isValidIdentifier
import com.example.pinvault.server.route.liveGateDecision
import com.example.pinvault.server.route.vaultUploadError
import com.example.pinvault.server.service.ApprovalService.ChangeInput
import com.example.pinvault.server.service.ApprovalService.Description
import com.example.pinvault.server.store.PinConfigStore
import com.example.pinvault.server.store.VaultFileStore
import com.example.pinvault.server.store.VaultFileTokenStore
import io.ktor.http.HttpStatusCode
import io.ktor.http.parseQueryString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.security.MessageDigest

/**
 * What a pending change does, in words — and numbers — an approver can judge.
 *
 * Built from the request as it was sent, with the SAME code its handler runs
 * ([CertChangePlanner] for certificates, [MultipartForm] for uploads): the
 * summary never shows a field the handler does not read. A certificate change
 * is planned here, in full, and the plan stored with the request
 * ([Description.prepared]); the approval installs that plan. A request that
 * cannot be described is refused — nobody is asked to approve what they
 * cannot see. (Moved out of Main.kt so the tests can cover it.)
 */
class ChangeDescriber(
    private val pinConfigStore: PinConfigStore,
    private val planner: CertChangePlanner,
    private val liveGate: LiveCertificateGate,
    /** A fingerprint of a Config API's current pins (see [ApprovalService]). */
    private val stateHash: (configApiId: String) -> String,
    private val vaultFiles: VaultFileStore? = null,
    private val vaultTokens: VaultFileTokenStore? = null,
    /** The scope the management listener writes when a request names none. */
    private val defaultScope: String = "default-tls",
    private val audit: AuditLog? = null,
    /**
     * Why a client certificate upload under an id would replace something that
     * exists (an active identity, a truststore entry), or null — the handler's
     * check, made when the upload is requested.
     */
    private val clientIdInUse: ((String) -> String?)? = null,
    /** The running Config API that listens on a port, or null (a start there stops it). */
    private val portHolder: ((Int) -> String?)? = null
) {
    private val lenient = Json { ignoreUnknownKeys = true }

    fun describe(input: ChangeInput): Description {
        val op = input.op
        val path = input.path
        // The scope and host the handler will act on — a path segment beats a
        // same-named query parameter there, so it must here too.
        val scope = PinAffectingRoutes.scopeOf(path, input.query)
        val detail = buildJsonObject { put("operation", op) }
        val json: JsonObject? by lazy { runCatching { Json.parseToJsonElement(input.body.decodeToString()).jsonObject }.getOrNull() }
        // Body fields are the requester's text: one line, bounded, before an approver sees them.
        fun bodyField(name: String): String? =
            (json?.get(name) as? JsonPrimitive)?.content?.let { ApprovalService.plainText(it, 120) }

        planner.kindOf(path)?.let { kind -> return describeCertificate(input, kind, scope, detail) }

        return when (op) {
            "pins_update" -> {
                val incoming = lenient.decodeFromString(PinConfig.serializer(), input.body.decodeToString())
                // The handler's rules, now: nobody is asked to approve a config devices would refuse.
                PinConfigRules.errors(incoming.pins).takeIf { it.isNotEmpty() }?.let { errors ->
                    throw ApprovalService.Refused(HttpStatusCode.BadRequest, errors.take(5).joinToString("; "))
                }
                val current = pinConfigStore.load(scope)
                val byHost = current.pins.associateBy { it.hostname }
                // The same versioning the write applies, so the diff shows real changes only.
                val versioned = incoming.copy(pins = incoming.pins.map { pin ->
                    val old = byHost[pin.hostname]
                    when {
                        old == null -> pin.copy(version = 1)
                        old.sha256 != pin.sha256 -> pin.copy(version = old.version + 1)
                        else -> pin.copy(version = old.version)
                    }
                })
                val diff = PinDiff.of(current, versioned)
                val live = if (liveGate.enabled) liveGate.check(current, versioned) else null
                Description(
                    configApiId = scope,
                    summary = "$scope: " + diff.summary().ifEmpty { "no pin change" },
                    detail = JsonObject(
                        detail + diff.toJson() + (live?.let {
                            mapOf("liveCheck" to Json.encodeToJsonElement(LiveCertificateGate.Result.serializer(), it))
                        } ?: emptyMap())
                    ),
                    baseHash = stateHash(scope)
                )
            }
            "force_on", "force_off" -> {
                val host = PinAffectingRoutes.hostOf(path)
                val what = if (op == "force_on") "Force update ON" else "Force update OFF"
                Description(scope, "$scope: $what for ${host ?: "every host"}", detail)
            }
            "host_cert" -> describeHostFlag(input, scope, detail)
            "config_api_delete" -> {
                // The handler's checks: an id that is not an identifier is refused, not described.
                com.example.pinvault.server.route.configApiRequestError(json, start = false)?.let { throw IllegalArgumentException(it) }
                Description(bodyField("id") ?: "", "Delete Config API ${bodyField("id")} and all of its pins", detail)
            }
            "config_api_lifecycle" -> {
                val start = path.endsWith("/start")
                com.example.pinvault.server.route.configApiRequestError(json, start)?.let { throw IllegalArgumentException(it) }
                val id = bodyField("id")
                if (!start) {
                    Description(id ?: "", "Stop Config API $id — devices on its port reach no config until it is started again", detail)
                } else {
                    val port = (json?.get("port") as? JsonPrimitive)?.intOrNull ?: 0
                    val mode = bodyField("mode") ?: "tls"
                    // Starting on a port another API holds stops that one: the port
                    // then serves THIS scope's pins — a change of what devices get
                    // there without one pin edited.
                    val holder = portHolder?.invoke(port)?.takeIf { it != id }
                    Description(
                        id ?: "",
                        "Start Config API ${id ?: "(new id)"} on port $port as ${mode.uppercase()}" +
                            (if (mode == "mtls") " (devices must present a client certificate)" else " (no client certificate asked)") +
                            (holder?.let { " — STOPS Config API $it, which holds that port now; the port then serves ${id ?: "the new"}'s pins" }
                                ?: " — that port serves this scope's pins"),
                        JsonObject(detail + mapOf("mode" to JsonPrimitive(mode), "port" to JsonPrimitive(port)) +
                            (holder?.let { mapOf("replaces" to JsonPrimitive(it)) } ?: emptyMap()))
                    )
                }
            }
            "signing_key" -> Description("", "Replace the primary config-signing key", detail)
            "host_acl" -> {
                val hosts = runCatching {
                    (json?.get("hostnames") as? JsonArray)?.map { it.jsonPrimitive.content }
                }.getOrNull() ?: throw IllegalArgumentException("'hostnames' string array required")
                val device = PinAffectingRoutes.deviceOf(path)
                val shown = hosts.take(10).joinToString(", ") { ApprovalService.plainText(it, 80) } +
                    if (hosts.size > 10) " … (+${hosts.size - 10})" else ""
                Description(
                    scope,
                    "$scope: ${device?.let { "hosts device $it may reach" } ?: "default hosts every device may reach"} = " +
                        shown.ifEmpty { "(none)" },
                    detail
                )
            }
            "signing_keyset" -> {
                val payload = bodyField("payload")
                val version = payload?.let { runCatching { Json.parseToJsonElement(it).jsonObject["version"]?.jsonPrimitive?.content }.getOrNull() }
                Description("", "Publish signing-key set v${version ?: "?"}", detail)
            }

            // ── Who the mTLS listeners let in ───────────────────────────
            "client_cert_upload" -> {
                val form = MultipartForm.parse(input.contentType, input.body)
                    ?: throw IllegalArgumentException("a multipart/form-data body with the certificate is required")
                val id = form.fields["clientId"]?.trim()?.takeIf { it.isNotEmpty() }
                require(id == null || isValidIdentifier(id)) { "clientId: letters, digits, '.', '_', ':' and '-' only, at most 64" }
                require(id == null || !isReservedClientId(id)) { "clientId '$id' is reserved by the server" }
                id?.let { clientIdInUse?.invoke(it) }?.let { throw ApprovalService.Refused(HttpStatusCode.Conflict, it) }
                // The same checks the handler makes: one end-entity client certificate, never a CA.
                val cert = planner.clientCertificate(form.file ?: throw IllegalArgumentException("the certificate file is missing"))
                val fingerprint = sha256Hex(cert.encoded)
                Description(
                    "", "Trust client certificate ${ApprovalService.plainText(cert.subjectX500Principal.name, 120)} as " +
                        "${id ?: "a new id"} on every mTLS listener (SHA-256 ${fingerprint.take(16)}…, valid until ${cert.notAfter.toInstant()})",
                    JsonObject(detail + mapOf("clientCertificate" to buildJsonObject {
                        id?.let { put("clientId", it) }
                        put("subject", cert.subjectX500Principal.name)
                        put("issuer", cert.issuerX500Principal.name)
                        put("fingerprint", fingerprint)
                        put("notBefore", cert.notBefore.toInstant().toString())
                        put("notAfter", cert.notAfter.toInstant().toString())
                    }))
                )
            }
            "client_cert_generate" -> {
                val id = bodyField("clientId")
                require(id == null || isValidIdentifier(id)) { "clientId: letters, digits, '.', '_', ':' and '-' only, at most 64" }
                require(id == null || !isReservedClientId(id)) { "clientId '$id' is reserved by the server" }
                Description("", "Generate a client certificate (P12 with its private key) for ${id ?: "a new client id"}: " +
                    "a new identity every mTLS listener accepts", detail)
            }
            "enrollment_policy_create" -> {
                val name = bodyField("name") ?: throw IllegalArgumentException("name is required")
                val maxDevices = (json?.get("maxDevices") as? JsonPrimitive)?.intOrNull ?: throw IllegalArgumentException("maxDevices is required")
                val validDays = (json?.get("validDays") as? JsonPrimitive)?.intOrNull ?: throw IllegalArgumentException("validDays is required")
                // The handler's default: approval unless turned off explicitly.
                val requireApproval = (json?.get("requireApproval") as? JsonPrimitive)?.booleanOrNull ?: true
                Description("", "Enrollment code $name: up to $maxDevices device(s) for $validDays day(s), " +
                    if (requireApproval) "each approved by an administrator" else "WITHOUT approval — every device that has the code gets a certificate",
                    JsonObject(detail + mapOf(
                        "maxDevices" to JsonPrimitive(maxDevices), "validDays" to JsonPrimitive(validDays),
                        "requireApproval" to JsonPrimitive(requireApproval)
                    )))
            }
            "enrollment_open" -> {
                val enabled = (json?.get("enabled") as? JsonPrimitive)?.booleanOrNull ?: throw IllegalArgumentException("enabled: true or false")
                Description("", if (enabled) "Turn code-less applications ON: any device that reaches a Config API may ask to enroll (each waits for approval)"
                else "Turn code-less applications OFF", JsonObject(detail + mapOf("enabled" to JsonPrimitive(enabled))))
            }
            "enrollment_token" -> {
                val id = bodyField("clientId")
                require(id == null || isValidIdentifier(id)) { "clientId: letters, digits, '.', '_', ':' and '-' only, at most 64" }
                require(id == null || !isReservedClientId(id)) { "clientId '$id' is reserved by the server" }
                val device = bodyField("deviceUid")
                require(device == null || isValidIdentifier(device)) { "deviceUid: letters, digits, '.', '_', ':' and '-' only, at most 64" }
                Description("", "One-time enrollment token for ${id?.let { "client id $it" } ?: "a new client id"}" +
                    (device?.let { " bound to device $it" } ?: "") + ": whoever holds it enrolls one device", detail)
            }

            // ── Vault: what devices are handed ──────────────────────────
            "vault_upload", "vault_delete", "vault_policy", "vault_token_issue", "vault_token_revoke", "device_key_reset" ->
                describeVault(input, scope, detail, json)
            "vault_enabled" -> {
                val enabled = (json?.get("enabled") as? JsonPrimitive)?.booleanOrNull ?: throw IllegalArgumentException("'enabled' boolean required")
                Description(scope, "$scope: turn vault downloads ${if (enabled) "ON" else "OFF"}", JsonObject(detail + mapOf("enabled" to JsonPrimitive(enabled))))
            }
            else -> Description(scope, "$op $path", detail)
        }
    }

    /**
     * A certificate change: planned now, in full. The approver sees the pins
     * (SPKI hashes), the certificate's subject and validity and the Config
     * APIs whose published pins change; the approval installs this plan.
     */
    private fun describeCertificate(input: ChangeInput, kind: CertChangePlanner.Kind, scope: String, detail: JsonObject): Description {
        val hostInPath = if (kind.host && !kind.adds) PinAffectingRoutes.hostOf(input.path) else null
        val plan = try {
            planner.check(kind, scope, hostInPath)
            planner.plan(kind, scope, hostInPath, input.contentType, input.body)
        } catch (e: PlanRefused) {
            throw ApprovalService.Refused(e.status, e.message ?: "refused", e.body)
        }
        val host = plan.hostname
        val pins = plan.pins.joinToString(", ") { it.take(12) + "…" }
        val certificate = "${plan.source} certificate ${ApprovalService.plainText(plan.subject, 80)}, valid until ${plan.notAfter.take(10)}" +
            (plan.fetchedFrom?.let { " (read from ${ApprovalService.plainText(it, 80)})" } ?: "")

        if (!kind.host) {
            return Description(
                "", "Config API TLS certificate → $certificate; bootstrap pins become $pins — apps hold them as bootstrap pins",
                JsonObject(detail + mapOf("certificate" to plan.publicJson())), prepared = plan.encode()
            )
        }

        // Every Config API that pins the host gets the new pins; a new host only its own scope.
        val scopes = if (kind.adds) listOf(scope) else planner.scopesPinning(host)
        val gateScope = (listOf(scope) + scopes).firstOrNull { s -> kind.adds || pinConfigStore.load(s).pins.any { it.hostname == host } } ?: scope
        val current = pinConfigStore.load(gateScope)
        val updated = if (kind.adds) current.copy(pins = current.pins + HostPin(host, plan.pins, version = 1))
        else current.copy(pins = current.pins.map { if (it.hostname == host) it.copy(sha256 = plan.pins, version = it.version + 1) else it })

        // The live gate, as the handler will run it — refused now rather than
        // after someone approved it. An override reason travels in the query.
        val decision = liveGateDecision(liveGate, current, updated, parseQueryString(input.query)["liveCheckOverride"])
        val live = decision.result
        if (decision.blocked && live != null) {
            audit?.record("live_check_blocked", live.describe(), gateScope, live.failures().joinToString(",") { it.hostname },
                Json.encodeToJsonElement(LiveCertificateGate.Result.serializer(), live), actor = input.requestedBy.ifEmpty { "unknown" })
            throw ApprovalService.Refused(
                HttpStatusCode.UnprocessableEntity, "Live certificate check failed: ${live.describe()}",
                Json.encodeToJsonElement(
                    LiveCheckRejection.serializer(),
                    LiveCheckRejection("Live certificate check failed: ${live.describe()}", live, liveGate.allowOverride)
                ).jsonObject
            )
        }

        val extra = buildMap<String, JsonElement> {
            put("certificate", plan.publicJson())
            put("scopes", JsonArray(scopes.map { JsonPrimitive(it) }))
            if (live != null && live.checks.isNotEmpty()) put("liveCheck", Json.encodeToJsonElement(LiveCertificateGate.Result.serializer(), live))
        }
        return Description(
            configApiId = scope,
            summary = "$host: ${if (kind.adds) "add host with " else ""}$certificate; pins become $pins — changes " +
                if (scopes.isEmpty()) "no published pins (no Config API pins this host)" else "Config API ${scopes.joinToString(", ")}",
            detail = JsonObject(detail + PinDiff.of(current, updated).toJson() + extra),
            // Pins changed in between: a plan made against the old state is not applied.
            baseHash = stateHash(scope),
            prepared = plan.encode()
        )
    }

    /** `host_cert` routes that change no certificate: the mTLS flag and the host's client certificate. */
    private fun describeHostFlag(input: ChangeInput, scope: String, detail: JsonObject): Description {
        val host = PinAffectingRoutes.hostOf(input.path) ?: "?"
        return when (input.path.substringAfterLast('/')) {
            "toggle-mtls" -> {
                val on = runCatching { Json.parseToJsonElement(input.body.decodeToString()).jsonObject["mtls"]?.jsonPrimitive?.booleanOrNull }.getOrNull() ?: false
                Description(scope, "$scope: mark $host as ${if (on) "mTLS (devices present a client certificate)" else "TLS only (no client certificate)"}", detail)
            }
            "upload-client-cert" -> {
                val form = MultipartForm.parse(input.contentType, input.body)
                    ?: throw IllegalArgumentException("a multipart/form-data body with the P12 is required")
                val p12 = form.file ?: throw IllegalArgumentException("the P12 file is missing")
                // The entry the handler stores: the P12's only private key (more than one is refused).
                val cert = planner.hostClientCertificate(p12, form.fields["password"] ?: "changeit")
                Description(
                    scope, "$scope: devices use client certificate ${ApprovalService.plainText(cert.subjectX500Principal.name, 100)} " +
                        "(key ${LiveCertificateGate.spkiPin(cert).take(12)}…, valid until ${cert.notAfter.toInstant().toString().take(10)}) for $host",
                    JsonObject(detail + mapOf("clientCertificate" to buildJsonObject {
                        put("subject", cert.subjectX500Principal.name)
                        put("fingerprint", sha256Hex(cert.encoded))
                        put("notAfter", cert.notAfter.toInstant().toString())
                    }))
                )
            }
            else -> Description(scope, "$host: ${input.path.substringAfterLast('/')}", detail)
        }
    }

    private fun describeVault(input: ChangeInput, scope: String, detail: JsonObject, json: JsonObject?): Description {
        val segments = PinAffectingRoutes.vaultSegments(input.path)
        val query = parseQueryString(input.query)
        return when (input.op) {
            "vault_upload" -> {
                val key = segments.first()
                val policy = query["policy"]
                val encryption = query["encryption"]
                vaultUploadError(key, policy, encryption)?.let { throw IllegalArgumentException(it) }
                val current = vaultFiles?.meta(scope, key)
                val digest = sha256Hex(input.body)
                // What the store does with an absent value: keep the file's own, else the defaults.
                val newPolicy = policy ?: current?.accessPolicy ?: "token"
                val newEncryption = encryption ?: current?.encryption ?: "plain"
                Description(
                    scope,
                    "$scope: ${if (current == null) "upload new vault file $key" else "replace vault file $key (v${current.version})"} — " +
                        "${input.body.size} bytes, SHA-256 ${digest.take(16)}…, access " +
                        (if (current != null && current.accessPolicy != newPolicy) "${current.accessPolicy} → $newPolicy" else newPolicy) +
                        ", encryption " + (if (current != null && current.encryption != newEncryption) "${current.encryption} → $newEncryption" else newEncryption),
                    JsonObject(detail + mapOf("vaultFile" to buildJsonObject {
                        put("key", key); put("size", input.body.size); put("sha256", digest)
                        put("accessPolicy", newPolicy); put("encryption", newEncryption)
                        current?.let { put("replacesVersion", it.version); put("previousAccessPolicy", it.accessPolicy); put("previousEncryption", it.encryption) }
                    }))
                )
            }
            "vault_delete" -> {
                val key = segments.first()
                val current = vaultFiles?.meta(scope, key)
                Description(scope, "$scope: delete vault file $key" + (current?.let { " (v${it.version}, ${it.accessPolicy})" } ?: " (no such file now)"), detail)
            }
            "vault_policy" -> {
                val key = segments.first()
                val policy = (json?.get("access_policy") as? JsonPrimitive)?.content ?: throw IllegalArgumentException("access_policy field required")
                val encryption = (json?.get("encryption") as? JsonPrimitive)?.content ?: throw IllegalArgumentException("encryption field required")
                vaultUploadError(key, policy, encryption)?.let { throw IllegalArgumentException(it) }
                val current = vaultFiles?.meta(scope, key)
                Description(
                    scope,
                    "$scope: vault file $key — access ${current?.accessPolicy ?: "?"} → $policy, encryption ${current?.encryption ?: "?"} → $encryption" +
                        if (policy == "public") " (anyone who reaches the Config API can download it)" else "",
                    JsonObject(detail + mapOf("vaultFile" to buildJsonObject {
                        put("key", key); put("accessPolicy", policy); put("encryption", encryption)
                        current?.let { put("previousAccessPolicy", it.accessPolicy); put("previousEncryption", it.encryption) }
                    }))
                )
            }
            "vault_token_issue" -> {
                val key = segments.first()
                val device = (json?.get("deviceId") as? JsonPrimitive)?.content ?: throw IllegalArgumentException("deviceId field required")
                require(isValidIdentifier(device)) { "deviceId: letters, digits, '.', '_', ':' and '-' only, at most 64" }
                Description(scope, "$scope: vault token for device $device to download $key (replaces the device's earlier token for it)", detail)
            }
            "vault_token_revoke" -> {
                val id = segments.last().toLongOrNull() ?: throw IllegalArgumentException("Invalid tokenId")
                val token = vaultTokens?.info(id)?.takeIf { it.configApiId == scope }
                Description(scope, "$scope: revoke vault token #$id" +
                    (token?.let { " (device ${it.deviceId}, file ${it.vaultKey})" } ?: " (no such token in this Config API)"), detail)
            }
            else -> { // device_key_reset
                val device = segments.getOrNull(1) ?: "?"
                val purpose = query["purpose"] ?: "e2e"
                require(purpose == "e2e" || purpose == "user_auth") { "purpose must be \"e2e\" or \"user_auth\"" }
                Description(scope, "$scope: forget the ${if (purpose == "user_auth") "user-auth key" else "E2E key"} of device " +
                    "${ApprovalService.plainText(device, 80)} — the next key registered for it counts as its first", detail)
            }
        }
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}
