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
import kotlinx.serialization.json.buildJsonArray
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
    private val portHolder: ((Int) -> String?)? = null,
    /** The stored pin sets a `pins_restore` brings back; null = the route is not mounted. */
    private val snapshots: com.example.pinvault.server.store.PinSnapshotStore? = null,
    /** The settings saved from the dashboard, as `PUT /api/v1/server-settings` reads them; null = not mounted. */
    private val settingsSaved: (() -> Map<String, String>)? = null,
    /** The policy an `attestation_policy` change starts from; null = not mounted. */
    private val attestation: com.example.pinvault.server.service.attestation.AttestationService? = null,
    /** The device an `attestation_device` change acts on; null = not mounted. */
    private val attestedDevices: com.example.pinvault.server.store.AttestedDeviceStore? = null,
    /** The lists a `host_acl` change is compared with; null = not mounted. */
    private val hostAcl: com.example.pinvault.server.store.DeviceHostAclStore? = null,
    /** A device's registered key (PEM) a `device_key_reset` drops: (scope, deviceId, userAuth) → key or null. */
    private val deviceKeyOf: ((scope: String, deviceId: String, userAuth: Boolean) -> String?)? = null
) {
    /** A gated operation nobody wrote a card for: refused, never shown as a bare name and path. */
    class Undescribed(op: String) : IllegalStateException("there is no approval card for '$op' yet")

    /**
     * How a card of each gated operation is kept from going stale. Every
     * operation must say (`ApprovalCardsTest` fails on one that does not), so
     * a new card cannot be added without deciding it.
     */
    enum class Staleness {
        /** Computed against the scope's pins: `baseHash` (+ `scopeHashes`). */
        PIN_STATE,
        /** Described again at approval and compared (`stateKey`). */
        STATE_KEY,
        /** Fingerprints of what it acts on, by reference (`stateRefs`, [stateOf]). */
        STATE_REFS,
        /** The card states the end state itself ("turn X on", "delete Y"): nothing it says can go out of date. */
        END_STATE,
        /** The requester sends it again after approval and it runs as it is then (its answer carries a secret). */
        REQUESTER_RUN
    }

    /**
     * The current fingerprint of a reference a card recorded in
     * [ApprovalService.Description.stateRefs], or null when its object does
     * not exist. Cheap: never plans, fetches or generates anything.
     */
    fun stateOf(ref: String): String? {
        val parts = ref.split('|')
        return when (parts.first()) {
            "bootstrap" -> planner.bootstrapState()
            "port" -> parts.getOrNull(1)?.toIntOrNull()?.let { portHolder?.invoke(it) }
            "vault" -> if (parts.size == 3) vaultState(parts[1], parts[2]) else null
            "device-key" -> if (parts.size == 4) deviceKeyOf?.invoke(parts[1], parts[3], parts[2] == "user_auth")?.let { sha256Hex(it.toByteArray(Charsets.UTF_8)) } else null
            else -> null
        }
    }

    private fun vaultState(scope: String, key: String): String? =
        vaultFiles?.meta(scope, key)?.let { "v${it.version}|${it.accessPolicy}|${it.encryption}|${it.expiresAt ?: "-"}" }

    /** [ref] with its current fingerprint, for [ApprovalService.Description.stateRefs]. */
    private fun ref(vararg parts: String): Pair<String, String> {
        val ref = parts.joinToString("|")
        return ref to (stateOf(ref) ?: ApprovalService.MISSING_STATE)
    }

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
                // The handler's precondition: an editor that says which state it
                // loaded is refused once the scope moved.
                if (input.baseState != null && input.baseState != PinDiff.stateHash(current)) {
                    throw ApprovalService.Refused(HttpStatusCode.Conflict, "stale_config",
                        com.example.pinvault.server.route.staleConfigBody(scope, PinDiff.stateHash(current)))
                }
                // By lower-cased name, as the handler matches them: an entry that
                // differs from a host only by case is that host.
                val byHost = current.pins.associateBy { it.hostname.lowercase() }
                // Managed trust roots, by the handler's rule: a body that carries
                // `trustRoots` replaces the scope's list, one without keeps it.
                val trustRoots = if (json?.containsKey("trustRoots") == true) incoming.trustRoots.map { it.trim() } else current.trustRoots
                PinConfigRules.trustRootErrors(trustRoots).takeIf { it.isNotEmpty() }?.let { errors ->
                    throw ApprovalService.Refused(HttpStatusCode.BadRequest, errors.take(5).joinToString("; "))
                }
                // The same versioning the write applies, so the diff shows real changes only.
                val versioned = incoming.copy(trustRoots = trustRoots, pins = incoming.pins.map { sent ->
                    val old = byHost[sent.hostname.lowercase()]
                    val pin = if (old != null) sent.copy(hostname = old.hostname) else sent
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
            "pins_restore" -> {
                // The handler's own checks, made now: the snapshot exists, its
                // scope is the request's, the set it would publish is valid.
                val id = path.removeSuffix("/restore").substringAfterLast('/').toLongOrNull()
                val snap = id?.let { snapshots?.get(it) }
                    ?: throw ApprovalService.Refused(HttpStatusCode.NotFound, "snapshot_not_found")
                if (parseQueryString(input.query)["configApiId"]?.let { it != snap.configApiId } == true) {
                    throw ApprovalService.Refused(HttpStatusCode.Conflict, "scope_mismatch")
                }
                // The host as the handler reads it — the same function on the same
                // bytes (the gate lets only UTF-8 through). A body it cannot read is
                // refused here and there; it is never a whole-scope restore.
                val host = try {
                    PinRestore.requestedHost(input.body)
                } catch (e: PinRestore.BadBody) {
                    throw ApprovalService.Refused(HttpStatusCode.BadRequest, e.message ?: "invalid body",
                        buildJsonObject { put("error", "invalid_body"); put("message", e.message ?: "invalid body") })
                }
                val current = pinConfigStore.load(snap.configApiId)
                val planned = try {
                    PinRestore.plan(current, snap, host)
                } catch (e: PinRestore.Refused) {
                    throw ApprovalService.Refused(HttpStatusCode.NotFound, ApprovalService.plainText(e.message ?: "refused", 200))
                }
                (PinConfigRules.errors(planned.pins) + PinConfigRules.trustRootErrors(planned.trustRoots)).takeIf { it.isNotEmpty() }?.let { errors ->
                    throw ApprovalService.Refused(HttpStatusCode.BadRequest, errors.take(5).joinToString("; "))
                }
                val diff = PinDiff.of(current, planned)
                val live = if (liveGate.enabled) liveGate.check(current, planned) else null
                Description(
                    configApiId = snap.configApiId,
                    summary = "${snap.configApiId}: restore ${host?.let { ApprovalService.plainText(it, 120) } ?: "the pin set"} from snapshot ${snap.id} (${snap.takenAt.take(19)}, by ${snap.actor}) — " +
                        diff.summary().ifEmpty { "no pin change" },
                    detail = JsonObject(
                        detail + diff.toJson() + mapOf(
                            "snapshotId" to JsonPrimitive(snap.id), "snapshotTakenAt" to JsonPrimitive(snap.takenAt)
                        ) + (live?.let {
                            mapOf("liveCheck" to Json.encodeToJsonElement(LiveCertificateGate.Result.serializer(), it))
                        } ?: emptyMap())
                    ),
                    baseHash = stateHash(snap.configApiId)
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
                            (holder?.let { mapOf("replaces" to JsonPrimitive(it)) } ?: emptyMap())),
                        // The card names what it stops (or that nothing is stopped): it must still be so.
                        stateRefs = mapOf(ref("port", port.toString()))
                    )
                }
            }
            "signing_key" -> Description("", "Replace the primary config-signing key", detail)
            "host_acl" -> describeHostAcl(scope, PinAffectingRoutes.deviceOf(path), detail, json)
            "signing_keyset" -> {
                val payload = bodyField("payload")
                val version = payload?.let { runCatching { Json.parseToJsonElement(it).jsonObject["version"]?.jsonPrimitive?.content }.getOrNull() }
                Description("", "Publish signing-key set v${version ?: "?"}", detail)
            }

            // ── Who the mTLS listeners let in ───────────────────────────
            "client_cert_upload" -> {
                val form = MultipartForm.parse(input.contentType, input.body)
                    ?: throw IllegalArgumentException("a multipart/form-data body with the certificate is required")
                // The same checks the handler makes: one end-entity client certificate, never a CA.
                val cert = planner.clientCertificate(form.file ?: throw IllegalArgumentException("the certificate file is missing"))
                // As the handler: without a clientId, the id the certificate's own CN carries.
                val id = form.fields["clientId"]?.trim()?.takeIf { it.isNotEmpty() }
                    ?: com.example.pinvault.server.route.clientIdOfSubject(cert.subjectX500Principal)
                require(id == null || isValidIdentifier(id)) { "clientId: letters, digits, '.', '_', ':' and '-' only, at most 64" }
                require(id == null || !isReservedClientId(id)) { "clientId '$id' is reserved by the server" }
                id?.let { clientIdInUse?.invoke(it) }?.let { throw ApprovalService.Refused(HttpStatusCode.Conflict, it) }
                // ...and the id it is recorded under is the id it authenticates as.
                com.example.pinvault.server.route.uploadedSubjectMismatch(cert, id ?: "")?.let { why ->
                    throw ApprovalService.Refused(HttpStatusCode.BadRequest, why,
                        buildJsonObject { put("error", "subject_mismatch"); put("message", why) })
                }
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

            // ── Settings and attestation: what the server enforces ──────
            "server_settings" -> describeSettings(detail, json)
            "attestation_policy" -> describeAttestationPolicy(input, scope, detail)
            "attestation_device" -> describeAttestationDevice(input, scope, detail, json)
            "attestation_token_secrets" ->
                Description("", "Read the PinVault-Token secrets: the keys every backend verifies tokens with are shown to the requester", detail)
            "attestation_token_secret_rotate" ->
                Description("", "Rotate the PinVault-Token key: new tokens are signed with a new key; the current one stays for verification until it is deleted", detail)
            "attestation_token_secret_delete" -> {
                val kid = ApprovalService.plainText(path.substringAfterLast('/'), 80)
                Description("", "Delete PinVault-Token key $kid: tokens signed with it no longer verify at any backend",
                    JsonObject(detail + mapOf("kid" to JsonPrimitive(kid))))
            }
            // An operation the gate knows and this class does not: refused
            // (ApprovalService answers 400), never a card that only names it.
            else -> throw Undescribed(op)
        }
    }

    /** `{"name": …, "before": …, "after": …}` rows the dashboard shows as a table (null = unset / the default). */
    private fun changesJson(changes: List<Triple<String, String?, String?>>): JsonElement = buildJsonArray {
        changes.forEach { (name, before, after) -> add(buildJsonObject { put("name", name); put("before", before); put("after", after) }) }
    }

    /** SHA-256 (hex) of the state a card was computed from (`Description.stateKey`). */
    private fun stateKey(vararg parts: String?): String = sha256Hex(parts.joinToString("\u0000") { it ?: "\u0001" }.toByteArray(Charsets.UTF_8))

    private fun errorBody(error: String, details: List<String>): JsonObject = buildJsonObject {
        put("error", error); putJsonArray("details") { details.forEach { add(it) } }
    }

    /**
     * A host ACL write — a device's list or the scope's default. The card is
     * the handler's own plan ([HostAclChange]): the summary used to show the
     * first ten names of a line cut at 300 characters while the handler
     * applied the whole array, so names past the cut were approved unseen.
     * Every name granted and taken away is in the detail, and the card is
     * stale once the list it was compared with moved.
     */
    private fun describeHostAcl(scope: String, device: String?, detail: JsonObject, json: JsonObject?): Description {
        val acl = hostAcl ?: throw IllegalStateException("host ACLs are not available on this server")
        val current = if (device != null) acl.listForDevice(scope, device) else acl.listDefault(scope)
        val change = try {
            HostAclChange.plan(current, json)
        } catch (e: HostAclChange.BadBody) {
            throw ApprovalService.Refused(HttpStatusCode.BadRequest, e.message ?: "invalid hostnames")
        }
        fun shown(names: List<String>) = names.take(10).joinToString(", ") + if (names.size > 10) " … (+${names.size - 10} more, all in the detail)" else ""
        return Description(
            scope,
            // The counts first: the line is cut at its end, the detail lists every name.
            "$scope: +${change.added.size} −${change.removed.size} " +
                (device?.let { "hosts device ${ApprovalService.plainText(it, 80)} may reach" } ?: "default hosts every device may reach") +
                " (${change.desired.size} after the change)" +
                (if (change.added.isNotEmpty()) " — added: ${shown(change.added)}" else "") +
                (if (change.removed.isNotEmpty()) " — removed: ${shown(change.removed)}" else "") +
                (if (change.isEmpty) " — no change" else ""),
            JsonObject(detail + mapOf(
                "added" to JsonArray(change.added.map { JsonPrimitive(it) }),
                "removed" to JsonArray(change.removed.map { JsonPrimitive(it) })
            ) + (device?.let { mapOf("deviceId" to JsonPrimitive(ApprovalService.plainText(it, 80))) } ?: emptyMap())),
            stateKey = stateKey("host_acl", scope, device, current.sorted().joinToString("\u0002"))
        )
    }

    /** A settings save: every key it changes, with the saved value before and after (`ServerSettingsChange`, the handler's plan). */
    private fun describeSettings(detail: JsonObject, json: JsonObject?): Description {
        val saved = settingsSaved ?: throw IllegalStateException("server settings are not available on this server")
        val values = json?.get("values") as? JsonObject
            ?: throw ApprovalService.Refused(HttpStatusCode.BadRequest, "Expected {\"values\": {...}}", errorBody("invalid_body", listOf("Expected {\"values\": {...}}")))
        val change = ServerSettingsChange.plan(saved(), values)
        if (change.errors.isNotEmpty()) {
            throw ApprovalService.Refused(HttpStatusCode.BadRequest, change.errors.take(5).joinToString("; "), errorBody("invalid_settings", change.errors))
        }
        if (change.startProblems.isNotEmpty()) {
            throw ApprovalService.Refused(HttpStatusCode.BadRequest, change.startProblems.take(5).joinToString("; "), errorBody("would_not_start", change.startProblems))
        }
        fun shown(value: String?) = value?.let { ApprovalService.plainText(it, 80) } ?: "(server default)"
        val rows = change.changed.map { (key, v) -> Triple(key, v.first, v.second) }
        // The saved value of every key the body names: the card is a difference
        // from these, and an approval after one of them moved is stale.
        val current = saved()
        return Description(
            "",
            // The count first: a long list is cut at the end of the line, never silently.
            "Server settings for the next start (${rows.size} change${if (rows.size == 1) "" else "s"}): " +
                rows.joinToString("; ") { (key, before, after) -> "$key: ${shown(before)} → ${shown(after)}" }.ifEmpty { "no change" },
            JsonObject(detail + mapOf("changes" to changesJson(rows))),
            stateKey = stateKey("settings", *values.keys.sorted().map { "$it=${current[it] ?: "\u0001"}" }.toTypedArray())
        )
    }

    /** An attestation policy change: every flag and number that moves, and whether it lowers the production floor. */
    private fun describeAttestationPolicy(input: ChangeInput, scope: String, detail: JsonObject): Description {
        val service = attestation ?: throw IllegalStateException("attestation is not available on this server")
        val current = service.policyFor(scope)
        val requested = com.example.pinvault.server.service.attestation.AttestationPolicy.parse(input.body.decodeToString(), current).getOrElse { e ->
            throw ApprovalService.Refused(HttpStatusCode.BadRequest, "invalid policy: ${e.message ?: "cannot be read"}",
                buildJsonObject { put("error", "invalid_policy"); put("message", e.message ?: "invalid policy") })
        }
        val reject = com.example.pinvault.server.service.attestation.FlagAction.REJECT.wire
        // The handler's floor rule: these flags stay reject unless a second admin approves — which is this card.
        val newlyLowered = service.policyFloor.filter { requested.flags[it] != reject } - current.approvedRelaxations.toSet()
        val rows = buildList {
            (current.flags.keys + requested.flags.keys).distinct().sorted().forEach { flag ->
                if (current.flags[flag] != requested.flags[flag]) add(Triple(flag, current.flags[flag], requested.flags[flag]))
            }
            if (current.revealReasons != requested.revealReasons) add(Triple("revealReasons", current.revealReasons.toString(), requested.revealReasons.toString()))
            if (current.tokenTtlSeconds != requested.tokenTtlSeconds) add(Triple("tokenTtlSeconds", current.tokenTtlSeconds.toString(), requested.tokenTtlSeconds.toString()))
            if (current.attestIntervalSeconds != requested.attestIntervalSeconds) {
                add(Triple("attestIntervalSeconds", current.attestIntervalSeconds.toString(), requested.attestIntervalSeconds.toString()))
            }
        }
        return Description(
            scope,
            // What matters most first: the line is cut at its end.
            "$scope: attestation policy" +
                (if (newlyLowered.isEmpty()) "" else " — LOWERS the production floor: ${newlyLowered.joinToString()} no longer reject") +
                " (${rows.size} change${if (rows.size == 1) "" else "s"}) — " +
                rows.joinToString("; ") { (name, before, after) -> "$name: ${before ?: "(unset)"} → ${after ?: "(unset)"}" }.ifEmpty { "no change" },
            JsonObject(detail + mapOf("changes" to changesJson(rows)) +
                (if (newlyLowered.isEmpty()) emptyMap() else mapOf("floorLowered" to JsonArray(newlyLowered.map { JsonPrimitive(it) })))),
            // The policy the body is laid over (the handler merges the body's flags onto
            // it) and the floor it is held to: a card computed on another policy is stale.
            stateKey = stateKey("policy", scope, current.toJson(), service.policyFloor.sorted().joinToString(","))
        )
    }

    /**
     * An attestation device change — three routes share the operation: an
     * override (PUT: forcePass / forceFail / annotations), forgetting the
     * device's key (DELETE) and clearing its token anomaly (DELETE …/anomaly).
     */
    private fun describeAttestationDevice(input: ChangeInput, scope: String, detail: JsonObject, json: JsonObject?): Description {
        val devices = attestedDevices ?: throw IllegalStateException("attestation is not available on this server")
        val segments = input.path.trim('/').split('/')   // api, v1, config-apis, {id}, attestation, devices, {deviceId}[, anomaly]
        val deviceId = segments.getOrNull(6)?.replace("%2F", "/") ?: throw IllegalArgumentException("the device id is missing")
        val shownId = ApprovalService.plainText(deviceId, 80)
        val before = devices.get(scope, deviceId)
        val withDevice = JsonObject(detail + mapOf("deviceId" to JsonPrimitive(shownId)))
        // What the three routes read or delete of the device: a card computed on
        // another key, override or anomaly than the device has at approval is stale.
        val deviceState = stateKey(
            "device", scope, deviceId,
            before?.let {
                listOf(it.registered, it.spkiSha256, it.forcePass, it.forceFail, it.annotations.joinToString("\u0002"), it.anomalyAt).joinToString("\u0003")
            }
        )
        if (segments.getOrNull(7) == "anomaly") {
            if (before?.anomalyAt == null) {
                throw ApprovalService.Refused(HttpStatusCode.NotFound, "no_anomaly", buildJsonObject { put("error", "no_anomaly") })
            }
            return Description(
                scope,
                "$scope: clear the token anomaly of device $shownId (${ApprovalService.plainText(before.anomalyReason ?: "no reason given", 80)}) — " +
                    "its attestations no longer raise token_anomaly",
                withDevice, stateKey = deviceState
            )
        }
        if (input.method.equals("DELETE", ignoreCase = true)) {
            before ?: throw ApprovalService.Refused(HttpStatusCode.NotFound, "device_not_found", buildJsonObject { put("error", "device_not_found") })
            // Forgetting deletes the device's whole row: say everything that goes with the key.
            val alsoDropped = buildList {
                if (before.forceFail) add("its forceFail override (the device is REJECTED today whatever it reports)")
                if (before.forcePass) add("its forcePass override")
                if (before.annotations.isNotEmpty()) add("its annotations (${before.annotations.joinToString()})")
                if (before.anomalyAt != null) add("its token anomaly")
            }
            return Description(
                scope,
                "$scope: forget attestation device $shownId — " +
                    (if (before.registered) "its registered key (${before.spkiSha256?.take(16) ?: "?"}…) is dropped and the NEXT key to attest under this id is accepted"
                    else "it has no registered key yet") +
                    (if (alsoDropped.isEmpty()) "" else "; ALSO dropped: ${alsoDropped.joinToString(", ")}") +
                    (if (before.keyMismatches > 0) " (${before.keyMismatches} key mismatch(es) seen)" else ""),
                JsonObject(withDevice + mapOf(
                    "registered" to JsonPrimitive(before.registered), "keyMismatches" to JsonPrimitive(before.keyMismatches),
                    "changes" to changesJson(buildList {
                        if (before.registered) add(Triple("registered key", before.spkiSha256?.take(16)?.plus("…") ?: "?", null))
                        if (before.forceFail) add(Triple("forceFail", "true", null))
                        if (before.forcePass) add(Triple("forcePass", "true", null))
                        if (before.annotations.isNotEmpty()) add(Triple("annotations", before.annotations.joinToString(), null))
                        if (before.anomalyAt != null) add(Triple("token anomaly", before.anomalyReason ?: "reported", null))
                    })
                )),
                stateKey = deviceState
            )
        }
        if (!com.example.pinvault.server.service.attestation.AttestationService.DEVICE_ID.matches(deviceId)) {
            throw ApprovalService.Refused(HttpStatusCode.BadRequest, "invalid_device_id", buildJsonObject {
                put("error", "invalid_device_id"); put("message", "Letters, digits, '.', '_', ':' and '-' only, at most 64.")
            })
        }
        val body = json ?: throw ApprovalService.Refused(HttpStatusCode.BadRequest, "invalid_json", buildJsonObject {
            put("error", "invalid_json"); put("message", "The body must be a JSON object.")
        })
        val set = when (val parsed = com.example.pinvault.server.route.DeviceOverride.parse(body, before)) {
            is com.example.pinvault.server.route.DeviceOverride.Invalid -> throw ApprovalService.Refused(HttpStatusCode.BadRequest, parsed.message, parsed.body())
            is com.example.pinvault.server.route.DeviceOverride.Set -> parsed
        }
        val wasPass = before?.forcePass ?: false
        val wasFail = before?.forceFail ?: false
        val wasAnnotations = before?.annotations ?: emptyList()
        val rows = buildList {
            if (wasPass != set.forcePass) add(Triple("forcePass", wasPass.toString(), set.forcePass.toString()))
            if (wasFail != set.forceFail) add(Triple("forceFail", wasFail.toString(), set.forceFail.toString()))
            if (wasAnnotations != set.annotations) add(Triple("annotations", wasAnnotations.joinToString().ifEmpty { "(none)" }, set.annotations.joinToString().ifEmpty { "(none)" }))
        }
        val effect = when {
            set.forcePass && !wasPass -> " — forcePass: this device PASSES attestation whatever it reports"
            set.forceFail && !wasFail -> " — forceFail: this device is REJECTED whatever it reports"
            else -> ""
        }
        return Description(
            scope,
            "$scope: attestation device $shownId${if (before == null) " (not seen yet)" else ""} — " +
                rows.joinToString("; ") { (name, old, new) -> "$name: $old → $new" }.ifEmpty { "no change" } + effect,
            JsonObject(withDevice + mapOf("changes" to changesJson(rows))),
            stateKey = deviceState
        )
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
                JsonObject(detail + mapOf("certificate" to plan.publicJson())), prepared = plan.encode(),
                // A rotate promotes the backup that is stored now; a regenerate approved in between replaces it.
                stateRefs = mapOf(ref("bootstrap"))
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
            // The other Config APIs the new pins go to: a change approved there in
            // between makes this plan stale too, not only one in [scope] (review
            // 2026-11-11). ApprovalService re-checks every one.
            val others = scopes.filter { it != scope }
            if (others.isNotEmpty()) put(ApprovalService.SCOPE_HASHES, JsonObject(others.associateWith { JsonPrimitive(stateHash(it)) }))
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
                val password = form.fields["password"]?.takeIf { it.isNotEmpty() }
                    ?: throw IllegalArgumentException("the P12's password is required")
                val cert = planner.hostClientCertificate(p12, password)
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
                val expiry = query["expiresAt"]?.let { VaultExpiry.parse(it) ?: "" }   // "" = cleared; null = kept
                val newExpiry = if (expiry != null) expiry.ifEmpty { null } else current?.expiresAt
                Description(
                    scope,
                    "$scope: ${if (current == null) "upload new vault file $key" else "replace vault file $key (v${current.version})"} — " +
                        "${input.body.size} bytes, SHA-256 ${digest.take(16)}…, access " +
                        (if (current != null && current.accessPolicy != newPolicy) "${current.accessPolicy} → $newPolicy" else newPolicy) +
                        ", encryption " + (if (current != null && current.encryption != newEncryption) "${current.encryption} → $newEncryption" else newEncryption) +
                        (newExpiry?.let { ", valid until ${it.take(10)}" } ?: ""),
                    JsonObject(detail + mapOf("vaultFile" to buildJsonObject {
                        put("key", key); put("size", input.body.size); put("sha256", digest)
                        put("accessPolicy", newPolicy); put("encryption", newEncryption)
                        newExpiry?.let { put("expiresAt", it) }
                        current?.let { put("replacesVersion", it.version); put("previousAccessPolicy", it.accessPolicy); put("previousEncryption", it.encryption) }
                    })),
                    // An absent ?policy / ?encryption keeps the file's own: the content
                    // would land under a policy changed in between (token → public).
                    stateRefs = mapOf(ref("vault", scope, key))
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
                // The handler's rule: absent keeps the file's expiry, null/"" clears it, a date sets it.
                val expiryField = json?.get("expires_at")
                val expiry = if (expiryField == null) null
                    else (VaultExpiry.parse((expiryField as? JsonPrimitive)?.takeIf { it !is kotlinx.serialization.json.JsonNull }?.content) ?: "")
                val expiryNote = when {
                    expiry == null -> ""
                    expiry.isEmpty() -> ", no expiry" + (current?.expiresAt?.let { " (was ${it.take(10)})" } ?: "")
                    else -> ", valid until ${expiry.take(10)}" + (current?.expiresAt?.let { " (was ${it.take(10)})" } ?: "")
                }
                Description(
                    scope,
                    "$scope: vault file $key — access ${current?.accessPolicy ?: "?"} → $policy, encryption ${current?.encryption ?: "?"} → $encryption" +
                        (if (policy == "public") " (anyone who reaches the Config API can download it)" else "") + expiryNote,
                    JsonObject(detail + mapOf("vaultFile" to buildJsonObject {
                        put("key", key); put("accessPolicy", policy); put("encryption", encryption)
                        expiry?.let { put("expiresAt", it) }
                        current?.let { put("previousAccessPolicy", it.accessPolicy); put("previousEncryption", it.encryption); it.expiresAt?.let { e -> put("previousExpiresAt", e) } }
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
                val keyRef = ref("device-key", scope, purpose, device)
                Description(scope, "$scope: forget the ${if (purpose == "user_auth") "user-auth key" else "E2E key"} of device " +
                    "${ApprovalService.plainText(device, 80)}" +
                    (if (keyRef.second == ApprovalService.MISSING_STATE) " (none registered now)" else " (key ${keyRef.second.take(12)}…)") +
                    " — the next key registered for it counts as its first",
                    JsonObject(detail + mapOf("keyFingerprint" to JsonPrimitive(keyRef.second))),
                    // The key the card names: a key registered in between is not the one approved for removal.
                    stateRefs = mapOf(keyRef))
            }
        }
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    companion object {
        /**
         * [Staleness] of every gated operation ([PinAffectingRoutes.operations]).
         * An operation whose routes differ says each way its routes use.
         */
        val STALENESS: Map<String, Set<Staleness>> = mapOf(
            "pins_update" to setOf(Staleness.PIN_STATE),
            "pins_restore" to setOf(Staleness.PIN_STATE),
            "force_on" to setOf(Staleness.END_STATE),
            "force_off" to setOf(Staleness.END_STATE),
            "host_add" to setOf(Staleness.PIN_STATE),
            // Certificate changes against the pins of every scope that pins the host;
            // toggle-mtls and upload-client-cert state the end state.
            "host_cert" to setOf(Staleness.PIN_STATE, Staleness.END_STATE),
            "config_api_delete" to setOf(Staleness.END_STATE),
            // Start: which API the port serves now (`port|n`); stop: the end state.
            "config_api_lifecycle" to setOf(Staleness.STATE_REFS, Staleness.END_STATE),
            "bootstrap_pins" to setOf(Staleness.STATE_REFS),
            "signing_key" to setOf(Staleness.END_STATE),
            "signing_keyset" to setOf(Staleness.END_STATE),
            "server_settings" to setOf(Staleness.STATE_KEY),
            "host_acl" to setOf(Staleness.STATE_KEY),
            // Checked again by its handler when it runs (an id in use is refused then).
            "client_cert_upload" to setOf(Staleness.END_STATE),
            "client_cert_generate" to setOf(Staleness.REQUESTER_RUN),
            "enrollment_policy_create" to setOf(Staleness.REQUESTER_RUN),
            "enrollment_open" to setOf(Staleness.END_STATE),
            "enrollment_token" to setOf(Staleness.REQUESTER_RUN),
            "vault_upload" to setOf(Staleness.STATE_REFS),
            "vault_delete" to setOf(Staleness.END_STATE),
            "vault_policy" to setOf(Staleness.END_STATE),
            "vault_token_issue" to setOf(Staleness.REQUESTER_RUN),
            "vault_token_revoke" to setOf(Staleness.END_STATE),
            "device_key_reset" to setOf(Staleness.STATE_REFS),
            "vault_enabled" to setOf(Staleness.END_STATE),
            "attestation_policy" to setOf(Staleness.STATE_KEY),
            "attestation_device" to setOf(Staleness.STATE_KEY),
            "attestation_token_secrets" to setOf(Staleness.REQUESTER_RUN),
            "attestation_token_secret_rotate" to setOf(Staleness.END_STATE),
            "attestation_token_secret_delete" to setOf(Staleness.END_STATE)
        )
    }
}
