package com.example.pinvault.server.service.attestation

import com.example.pinvault.server.model.SignedConfig
import com.example.pinvault.server.service.AndroidKeyAttestation
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.store.AttestationPolicyStore
import com.example.pinvault.server.store.AttestationTokenSecretStore
import com.example.pinvault.server.store.AttestedDevice
import com.example.pinvault.server.store.AttestedDeviceStore
import com.example.pinvault.server.store.KeyAttestation
import io.ktor.http.HttpStatusCode
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64

/**
 * `POST /api/v1/attest` (ATTESTATION.md §2.2): the checks in their order, the
 * policy evaluation of §4, the device registry, the token.
 *
 * The route owns what needs the call — rate limits, the body cap, the
 * signed config to embed — and hands the parsed body here; this returns
 * either a refusal to answer with, or a verdict to answer with (plus the
 * config the route adds on a pass).
 */
class AttestationService(
    private val policies: AttestationPolicyStore,
    private val devices: AttestedDeviceStore,
    private val secrets: AttestationTokenSecretStore,
    val nonces: AttestationNonces,
    private val defaults: AttestationPolicyDefaults,
    /** `ATTESTATION_KEY_POLICY`: what a first registration's chain must do. */
    val keyPolicy: AttestationKeyPolicy,
    verifier: () -> AndroidKeyAttestation,
    /** `client_identities` / `client_certs`: a device whose identity was revoked gets `403 device_revoked`. */
    private val isDeviceRevoked: (deviceId: String) -> Boolean = { false },
    private val audit: AuditLog? = null,
    /**
     * Summarises repeated rejections (`attestation_rejected`): a device whose
     * verdict did not change since its last rejection is counted, not written.
     * Null = every rejection is written as it is (tests).
     */
    private val rejections: AuthFailureRecorder? = null,
    private val clock: () -> Instant = Instant::now,
    /**
     * `ATTESTATION_DEVICE_LIMIT`: most registered devices one Config API
     * holds (0 = unlimited). `POST /api/v1/attest` asks for no credential, so
     * under `warn`/`off` anyone can register keys for invented device ids;
     * past the cap a new device gets `503 device_limit_reached` while known
     * devices keep attesting — the same shape as `DEVICE_KEY_LIMIT`.
     */
    private val deviceLimit: Int = 100_000
) {
    private val verifier by lazy(verifier)

    /** Device → start of the minute its last individually written key mismatch opened (bounded). */
    private val mismatchMinutes = object : LinkedHashMap<String, Long>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?) = size > 10_000
    }

    /** The server defaults for a Config API without a stored policy. */
    val defaultPolicy: AttestationPolicy get() = defaults.policy

    fun policyFor(configApiId: String): AttestationPolicy = policies.effective(configApiId, defaults.policy)

    sealed class Outcome {
        /** Answer [status] with `{"error": error, "reason"?: reason, "message": message}`. */
        class Refused(val status: HttpStatusCode, val error: String, val message: String, val reason: String? = null) : Outcome() {
            fun body(): String = buildJsonObject {
                put("error", error)
                reason?.let { put("reason", it) }
                put("message", message)
            }.toString()
        }

        /** A verdict; [toJson] builds the 200 answer, with the config the route may add. */
        class Decided(
            val passed: Boolean,
            val arc: String,
            val warnings: List<String>,
            val rejectionReasons: List<String>,
            val revealReasons: Boolean,
            val token: String?,
            val tokenExpiresAt: Long?,
            val tokenTtlSeconds: Int,
            val nextAttestIn: Int,
            val policyVersion: Int,
            val device: AttestedDevice,
            val firstSeen: Boolean,
            val keyAttestation: KeyAttestation?,
            /** What the device sent, for the route's "is it behind?" decision. */
            val deviceId: String,
            val hosts: List<String>?,
            val currentConfigVersion: Int?,
            val currentIssuedAt: Long?
        ) : Outcome() {
            fun toJson(config: SignedConfig?, configChanged: Boolean): JsonObject = buildJsonObject {
                put("result", if (passed) "pass" else "reject")
                put("arc", arc)
                put("warnings", buildJsonArray { warnings.forEach { add(JsonPrimitive(it)) } })
                if (revealReasons) put("rejectionReasons", buildJsonArray { rejectionReasons.forEach { add(JsonPrimitive(it)) } })
                token?.let { put("token", it) }
                tokenExpiresAt?.let { put("tokenExpiresAt", it) }
                put("tokenTtlSeconds", tokenTtlSeconds)
                put("nextAttestIn", nextAttestIn)
                put("configChanged", configChanged && config != null)
                config?.let { put("config", Json { encodeDefaults = true }.encodeToJsonElement(SignedConfig.serializer(), it)) }
                put("device", buildJsonObject {
                    put("registered", device.registered)
                    put("firstSeen", firstSeen)
                    put("keyAttestation", keyAttestation?.let { ka ->
                        buildJsonObject {
                            put("attested", ka.attested)
                            put("securityLevel", ka.securityLevel)
                            put("reason", ka.reason)
                        }
                    } ?: JsonNull)
                })
                put("policyVersion", policyVersion)
            }
        }
    }

    /**
     * Runs the checks of §2.2 on [body] for [configApiId]. [remote] is the
     * source address, for the audit entries.
     */
    fun attest(configApiId: String, body: JsonObject, remote: String): Outcome {
        // ── 1. Shape ───────────────────────────────────────────────────
        val version = (body["v"] as? JsonPrimitive)?.intOrNull
        if (version != 1) return Outcome.Refused(HttpStatusCode.BadRequest, "unsupported_version", "This server speaks attestation protocol v1 (send \"v\": 1).")
        val nonce = body.string("nonce") ?: return invalid("nonce is required")
        val deviceId = body.string("deviceId")?.takeIf { DEVICE_ID.matches(it) }
            ?: return invalid("deviceId must match ^[A-Za-z0-9._:-]{1,64}$")
        val publicKeyBase64 = body.string("publicKey") ?: return invalid("publicKey (Base64 DER SubjectPublicKeyInfo) is required")
        val report = body.string("report") ?: return invalid("report must be the report JSON as a string")
        if (report.toByteArray(Charsets.UTF_8).size > MAX_REPORT_BYTES) {
            return Outcome.Refused(HttpStatusCode.BadRequest, "report_too_large", "The report must be at most $MAX_REPORT_BYTES bytes.")
        }
        val reportJson = try { Json.parseToJsonElement(report) as? JsonObject } catch (_: Exception) { null }
            ?: return invalid("report is not a JSON object")
        val signature = body.string("signature") ?: return invalid("signature is required")
        val chain: List<String>? = when (val element = body["attestationChain"]) {
            null, JsonNull -> null
            is JsonArray -> element.map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: return invalid("attestationChain must be an array of Base64 strings") }
            else -> return invalid("attestationChain must be an array of Base64 strings")
        }
        val hosts: List<String>? = when (val element = body["hosts"]) {
            null, JsonNull -> null
            is JsonArray -> element.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content?.trim()?.takeIf { h -> h.isNotEmpty() } }.take(2000)
            else -> return invalid("hosts must be an array of host names")
        }
        val currentConfigVersion = (body["currentConfigVersion"] as? JsonPrimitive)?.intOrNull
        val currentIssuedAt = (body["currentIssuedAt"] as? JsonPrimitive)?.longOrNull

        // ── 2. Nonce ───────────────────────────────────────────────────
        when (nonces.consume(nonce)) {
            AttestationNonces.Check.Invalid -> return Outcome.Refused(HttpStatusCode.BadRequest, "nonce_invalid", "The nonce was not issued by this server. Ask for a new challenge.")
            AttestationNonces.Check.Expired -> return Outcome.Refused(HttpStatusCode.BadRequest, "nonce_expired", "The nonce is older than ${nonces.ttlSeconds} s. Ask for a new challenge.")
            AttestationNonces.Check.Replayed -> return Outcome.Refused(HttpStatusCode.BadRequest, "nonce_replayed", "This nonce was already used. Ask for a new challenge.")
            // Fail closed rather than forget a presentable nonce: the library backs off and asks again.
            AttestationNonces.Check.Overloaded -> return Outcome.Refused(HttpStatusCode.ServiceUnavailable, "attestation_busy", "Too many attestations in flight. Ask for a new challenge in a moment.")
            AttestationNonces.Check.Ok -> Unit
        }

        // ── 3. Signature ───────────────────────────────────────────────
        val publicKey = parseEcKey(publicKeyBase64)
        if (publicKey == null || !verifySignature(publicKey, canonical(nonce, deviceId, report), signature)) {
            return Outcome.Refused(HttpStatusCode.Unauthorized, "signature_invalid", "The signature over the canonical string does not verify with publicKey.")
        }

        // ── 4. Revoked ─────────────────────────────────────────────────
        if (isDeviceRevoked(deviceId)) {
            return Outcome.Refused(HttpStatusCode.Forbidden, "device_revoked", "This device's identity was revoked.")
        }

        // ── 5. Device key ──────────────────────────────────────────────
        val spki = sha256Hex(publicKey.encoded)
        val now = clock()
        var device = devices.get(configApiId, deviceId)
        var firstSeen = false
        var keyAttestation: KeyAttestation?
        if (device?.registered == true) {
            if (device.spkiSha256 != spki) {
                val mismatches = devices.recordKeyMismatch(configApiId, deviceId, now)
                auditKeyMismatch(configApiId, deviceId, remote, mismatches)
                return Outcome.Refused(HttpStatusCode.Forbidden, "key_mismatch",
                    "This device is registered with another key. An administrator can forget the device so it registers again.")
            }
            keyAttestation = device.keyAttestation
        } else {
            keyAttestation = when (val registration = checkRegistrationChain(chain, publicKey, deviceId)) {
                is Registration.Refuse -> return registration.outcome
                is Registration.Accept -> registration.attestation
            }
            // A Config API holds at most deviceLimit registered keys: an unauthenticated
            // endpoint must not let invented device ids grow the table without bound.
            if (deviceLimit > 0 && devices.counts(configApiId).registered >= deviceLimit) {
                return Outcome.Refused(HttpStatusCode.ServiceUnavailable, "device_limit_reached",
                    "This Config API already holds $deviceLimit registered devices (ATTESTATION_DEVICE_LIMIT). Known devices keep attesting; an administrator can forget stale ones.")
            }
            devices.register(configApiId, deviceId, spki, Base64.getEncoder().encodeToString(publicKey.encoded), keyAttestation, now)
            device = devices.get(configApiId, deviceId)!!
            firstSeen = true
            audit?.record("attestation_device_registered",
                "Device $deviceId registered its attestation key (${keyAttestation?.let { if (it.attested) "hardware-attested, ${it.securityLevel}" else "not attested: ${it.reason}" } ?: "attestation not checked"})",
                configApiId, deviceId, actor = deviceId, ip = remote,
                detail = buildJsonObject {
                    put("spkiSha256", spki)
                    put("keyAttested", keyAttestation?.attested ?: false)
                    keyAttestation?.securityLevel?.let { put("securityLevel", it) }
                    keyAttestation?.reason?.let { put("reason", it) }
                })
        }

        // ── 6. Policy ──────────────────────────────────────────────────
        val policy = policyFor(configApiId)
        val raised = raisedFlags(reportJson, device)
        val reasons: List<String>
        val warnings: List<String>
        val passed: Boolean
        when {
            device.forceFail -> {
                passed = false
                reasons = listOf("force_fail")
                warnings = raised.filter { policy.actionFor(it) != FlagAction.IGNORE }.map { it.wire }
            }
            device.forcePass -> {
                passed = true
                reasons = emptyList()
                warnings = raised.filter { policy.actionFor(it) != FlagAction.IGNORE }.map { it.wire }
            }
            else -> {
                reasons = raised.filter { policy.actionFor(it) == FlagAction.REJECT }.map { it.wire }
                warnings = raised.filter { policy.actionFor(it) == FlagAction.WARN }.map { it.wire }
                passed = reasons.isEmpty()
            }
        }
        val arc = nonces.arc(reasons, warnings)

        // ── 7. Token ───────────────────────────────────────────────────
        var token: String? = null
        var tokenExpiresAt: Long? = null
        if (passed) {
            val secret = secrets.active()
            val nowSeconds = now.epochSecond
            token = PinVaultToken.issue(secret.kid, secret.secret, deviceId, configApiId, arc, policy.version,
                policy.tokenTtlSeconds, device.annotations, nowSeconds)
            tokenExpiresAt = (nowSeconds + policy.tokenTtlSeconds) * 1000
        }

        val provider = reportJson["verdictProvider"] as? JsonObject
        devices.recordVerdict(
            configApiId, deviceId, if (passed) "pass" else "reject", arc, reasons, warnings, policy.version,
            trimmedReport = trimReport(reportJson), sdkVersion = reportJson.string("sdkVersion"),
            verdictProvider = provider?.string("name"), verdictToken = provider?.string("token")?.take(MAX_VERDICT_TOKEN), now = now
        )
        if (!passed) auditRejection(configApiId, deviceId, remote, arc, reasons, warnings, device)

        return Outcome.Decided(
            passed = passed, arc = arc, warnings = warnings, rejectionReasons = reasons, revealReasons = policy.revealReasons,
            token = token, tokenExpiresAt = tokenExpiresAt, tokenTtlSeconds = policy.tokenTtlSeconds,
            nextAttestIn = policy.attestIntervalSeconds, policyVersion = policy.version,
            device = device, firstSeen = firstSeen, keyAttestation = keyAttestation,
            deviceId = deviceId, hosts = hosts, currentConfigVersion = currentConfigVersion, currentIssuedAt = currentIssuedAt
        )
    }

    private sealed interface Registration {
        class Refuse(val outcome: Outcome.Refused) : Registration
        class Accept(val attestation: KeyAttestation?) : Registration
    }

    /** Step 5 for an unknown device: what `ATTESTATION_KEY_POLICY` makes of its chain. */
    private fun checkRegistrationChain(chain: List<String>?, publicKey: PublicKey, deviceId: String): Registration {
        if (keyPolicy == AttestationKeyPolicy.OFF) return Registration.Accept(KeyAttestation(false, null, NOT_CHECKED))
        val verdict = if (chain.isNullOrEmpty()) AndroidKeyAttestation.Verdict.MISSING else {
            val v = verifier.verifyIdentityKey(chain, publicKey, deviceId)
            // Without the package + signer binding a passing chain says nothing about which app made the key.
            if (v.passed && !verifier.bindsApp) AndroidKeyAttestation.Verdict(false, APP_BINDING_NOT_CONFIGURED, v.securityLevel) else v
        }
        if (verdict.passed) return Registration.Accept(KeyAttestation(true, verdict.securityLevel, verdict.reason))
        if (keyPolicy == AttestationKeyPolicy.ENFORCE) {
            return Registration.Refuse(if (verdict.reason == AndroidKeyAttestation.Verdict.MISSING.reason) {
                Outcome.Refused(HttpStatusCode.Forbidden, "attestation_required",
                    "This server registers only keys with an Android Key Attestation chain (attestationChain), made with the challenge of the deviceId.")
            } else {
                Outcome.Refused(HttpStatusCode.Forbidden, "attestation_invalid",
                    "The device key's Android Key Attestation did not pass: ${verdict.reason}.", reason = verdict.reason)
            })
        }
        return Registration.Accept(KeyAttestation(false, verdict.securityLevel, verdict.reason))
    }

    /**
     * Step 4 of §4: the flags the report raises, with the server-side ones
     * merged in — `app_integrity` from the signer/package check,
     * `software_key` / `key_unattested` from the device record, `old_patch_level`
     * from the report's patch level against `ATTESTATION_MIN_PATCH_LEVEL`.
     */
    internal fun raisedFlags(report: JsonObject, device: AttestedDevice): List<AttestationFlag> {
        val raised = LinkedHashSet<AttestationFlag>()
        (report["signals"] as? JsonObject)?.forEach { (name, value) ->
            val flag = AttestationFlag.of(name) ?: return@forEach
            if ((value as? JsonObject)?.get("flag")?.let { (it as? JsonPrimitive)?.booleanOrNull } == true) raised += flag
        }
        val app = report["app"] as? JsonObject
        if (verifier.packageNames.isNotEmpty()) {
            val packageName = app?.string("packageName")
            if (packageName == null || packageName !in verifier.packageNames) raised += AttestationFlag.APP_INTEGRITY
        }
        if (verifier.signerDigests.isNotEmpty()) {
            val signers = (app?.get("signerSha256") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
                ?.map { it.replace(":", "").lowercase() }.orEmpty()
            if (signers.none { it in verifier.signerDigests }) raised += AttestationFlag.APP_INTEGRITY
        }
        val keyAttested = device.keyAttestation?.attested == true
        if (!keyAttested) {
            raised += AttestationFlag.KEY_UNATTESTED
            val level = (report["device"] as? JsonObject)?.string("keySecurityLevel")?.lowercase()
            if (level == null || level == "software" || level == "unknown") raised += AttestationFlag.SOFTWARE_KEY
        }
        verifier.minPatchLevel?.let { min ->
            val patch = (report["device"] as? JsonObject)?.string("securityPatch")?.let { parsePatch(it) }
            if (patch == null || patch < min) raised += AttestationFlag.OLD_PATCH_LEVEL
        }
        return raised.toList()
    }

    private fun auditRejection(configApiId: String, deviceId: String, remote: String, arc: String, reasons: List<String>, warnings: List<String>, before: AttestedDevice) {
        val audit = audit ?: return
        // Written once per verdict: a rejected device re-attests every few minutes with the same answer.
        if (rejections == null || before.lastResult != "reject" || before.lastArc != arc) {
            audit.record("attestation_rejected", "Device $deviceId rejected (ARC $arc): ${reasons.joinToString()}" +
                (if (warnings.isEmpty()) "" else "; warnings ${warnings.joinToString()}"),
                configApiId, deviceId, actor = deviceId, ip = remote,
                detail = buildJsonObject {
                    put("arc", arc)
                    put("reasons", buildJsonArray { reasons.forEach { add(JsonPrimitive(it)) } })
                    put("warnings", buildJsonArray { warnings.forEach { add(JsonPrimitive(it)) } })
                })
        } else {
            rejections.count(remote)
        }
    }

    private fun auditKeyMismatch(configApiId: String, deviceId: String, remote: String, mismatches: Int) {
        val audit = audit ?: return
        val now = clock().toEpochMilli()
        val fresh = synchronized(mismatchMinutes) {
            val start = mismatchMinutes["$configApiId|$deviceId"]
            if (start == null || now - start >= 60_000) { mismatchMinutes["$configApiId|$deviceId"] = now; true } else false
        }
        if (fresh) {
            audit.record("attestation_key_mismatch", "Device $deviceId attested with a key other than its registered one ($mismatches mismatch(es) so far)",
                configApiId, deviceId, actor = deviceId, ip = remote, detail = buildJsonObject { put("keyMismatches", mismatches) })
        } else {
            rejections?.count(remote)
        }
    }

    /** The report's app, device and signals blocks, as stored for the dashboard. */
    private fun trimReport(report: JsonObject): String = buildJsonObject {
        report["sdkVersion"]?.let { put("sdkVersion", it) }
        report["reportTime"]?.let { put("reportTime", it) }
        report["app"]?.let { put("app", it) }
        report["device"]?.let { put("device", it) }
        report["signals"]?.let { put("signals", it) }
        (report["verdictProvider"] as? JsonObject)?.string("name")?.let { put("verdictProvider", buildJsonObject { put("name", it) }) }
    }.toString()

    private fun invalid(message: String) = Outcome.Refused(HttpStatusCode.BadRequest, "invalid_json", message)

    companion object {
        /** The report (a string) is at most this long. */
        const val MAX_REPORT_BYTES = 16 * 1024

        /** A verdict provider's token is stored up to this length. */
        const val MAX_VERDICT_TOKEN = 8 * 1024

        const val NOT_CHECKED = "not_checked"
        const val APP_BINDING_NOT_CONFIGURED = "app_binding_not_configured"

        val DEVICE_ID = Regex("^[A-Za-z0-9._:-]{1,64}$")

        private val PATCH = Regex("^(\\d{4})-(\\d{2})(?:-\\d{2})?$")

        /** `pinvault-attest:v1:<nonce>:<deviceId>:<sha256-hex(report)>`: what the device signs. */
        fun canonical(nonce: String, deviceId: String, report: String): String =
            "pinvault-attest:v1:$nonce:$deviceId:${sha256Hex(report.toByteArray(Charsets.UTF_8))}"

        fun sha256Hex(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

        /** `2026-09-05` → 202609; null when it is not a date. */
        fun parsePatch(securityPatch: String): Int? =
            PATCH.matchEntire(securityPatch.trim())?.let { it.groupValues[1].toInt() * 100 + it.groupValues[2].toInt() }

        /** A Base64 DER SubjectPublicKeyInfo of an EC P-256 key, or null. */
        fun parseEcKey(base64: String): PublicKey? = try {
            val der = Base64.getDecoder().decode(base64)
            val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der)) as ECPublicKey
            key.takeIf { it.params.curve.field.fieldSize == 256 }
        } catch (_: Exception) {
            null
        }

        /** SHA256withECDSA (DER) over the UTF-8 bytes of [text]. */
        fun verifySignature(key: PublicKey, text: String, signatureBase64: String): Boolean = try {
            val sig = Base64.getDecoder().decode(signatureBase64)
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(text.toByteArray(Charsets.UTF_8))
                verify(sig)
            }
        } catch (_: Exception) {
            false
        }

        internal fun JsonObject.string(name: String): String? =
            (this[name] as? JsonPrimitive)?.takeIf { it !is JsonNull && it.isString }?.content
    }
}
