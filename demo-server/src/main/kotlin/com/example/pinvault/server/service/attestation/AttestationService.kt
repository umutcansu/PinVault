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
    private val deviceLimit: Int = 100_000,
    /**
     * Play Integrity (§11): verifies the `play-integrity` verdict a report
     * carries and raises `play_integrity` / `play_integrity_missing`. Null
     * (no Play Console keys configured) = the token is stored, nothing raised.
     */
    val playIntegrity: PlayIntegrityVerifier? = null,
    /**
     * Apple App Attest (§12): verifies the `app-attest` verdict an iOS report
     * carries and raises `app_attest` / `app_attest_missing`; a verified one
     * lifts `key_unattested` for the iOS device. Null (`APP_ATTEST_APP_IDS`
     * empty) = the token is stored, nothing raised.
     */
    val appAttest: AppAttestVerifier? = null,
    /** `ATTESTATION_MIN_IOS_VERSION`, `ATTESTATION_IOS_TEAM_IDS`: what an iOS report is held to. */
    private val ios: IosAttestationRules = IosAttestationRules(),
    /**
     * The version of the server's signing-key set (0 = none). Devices drop
     * their config watermarks when a newer set arrives, so a device's
     * stored watermark counts only under the set it was stored with
     * (`config_rollback`).
     */
    private val keySetVersion: () -> Int = { 0 }
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
                            if (AppAttestAdmission.admitted(ka)) put("attestedBy", AppAttestAdmission.KIND)
                        }
                    } ?: JsonNull)
                })
                put("policyVersion", policyVersion)
            }
        }
    }

    /**
     * Runs the checks of §2.2 on [body] for [configApiId]. [remote] is the
     * source address, for the audit entries; [clientCertificate] the DER of
     * the verified client certificate the request came with (mTLS), which the
     * token then names in `cnf.x5t#S256`.
     */
    fun attest(configApiId: String, body: JsonObject, remote: String, clientCertificate: ByteArray? = null): Outcome {
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
        // The verdict provider: the body's own (a v2 verdict is made over the
        // report, so the report cannot carry it — §12, §11) or the report's.
        val bodyProvider = when (val element = body["verdictProvider"]) {
            null, JsonNull -> null
            is JsonObject -> element
            else -> return invalid("verdictProvider must be an object {\"name\", \"token\"}")
        }
        val provider = bodyProvider ?: reportJson["verdictProvider"] as? JsonObject
        val providerOutside = bodyProvider != null

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
        val canonical = canonical(nonce, deviceId, report)
        if (publicKey == null || !verifySignature(publicKey, canonical, signature)) {
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
        // The report's App Attest attestation, when it admitted an unknown device under enforce (verified once).
        var appAttestAdmitted: AppAttestAdmission.Result.Passed? = null
        var appAttestAdmittedV1 = false
        if (device?.registered == true) {
            if (device.spkiSha256 != spki) {
                val mismatches = devices.recordKeyMismatch(configApiId, deviceId, now)
                auditKeyMismatch(configApiId, deviceId, remote, mismatches)
                return Outcome.Refused(HttpStatusCode.Forbidden, "key_mismatch",
                    "This device is registered with another key. An administrator can forget the device so it registers again.")
            }
            keyAttestation = device.keyAttestation
        } else {
            // An Android report that says its key is attested, with no chain: the client
            // believes this server knows the key (it was forgotten meanwhile). Ask for the
            // chain again rather than register the key without the hardware's word.
            val claimsAttested = ((reportJson["device"] as? JsonObject)?.get("keyAttested") as? JsonPrimitive)?.booleanOrNull == true
            val claimsIos = (reportJson["device"] as? JsonObject)?.string("platform") == "ios"
            if (chain.isNullOrEmpty() && claimsAttested && !claimsIos && keyPolicy != AttestationKeyPolicy.OFF) {
                return Outcome.Refused(HttpStatusCode.Conflict, "key_unknown",
                    "This server has no record of the device key. Send its attestation chain again.")
            }
            val registration = when (val checked = checkRegistrationChain(chain, publicKey, deviceId, nonce, canonical, provider, providerOutside, now)) {
                is Registration.Refuse -> return checked.outcome
                is Registration.Accept -> checked
            }
            keyAttestation = registration.attestation
            // A Config API holds at most deviceLimit registered keys: an unauthenticated
            // endpoint must not let invented device ids grow the table without bound.
            if (deviceLimit > 0 && devices.counts(configApiId).registered >= deviceLimit) {
                return Outcome.Refused(HttpStatusCode.ServiceUnavailable, "device_limit_reached",
                    "This Config API already holds $deviceLimit registered devices (ATTESTATION_DEVICE_LIMIT). Known devices keep attesting; an administrator can forget stale ones.")
            }
            devices.register(configApiId, deviceId, spki, Base64.getEncoder().encodeToString(publicKey.encoded), keyAttestation, now,
                facts = registration.facts)
            appAttestAdmittedV1 = registration.appAttestV1
            // Admitted by App Attest (enforce, no chain): its key is on record from now on,
            // which also holds the device to platform ios.
            appAttestAdmitted = registration.appAttest?.also { passed ->
                devices.registerAppAttestKey(configApiId, deviceId, passed.keyId, Base64.getEncoder().encodeToString(passed.publicKey),
                    appAttestSummary(appAttest!!, "attestation", "ok", passed.keyId, passed.appId, 0, now), now)
            }
            device = devices.get(configApiId, deviceId)!!
            firstSeen = true
            val how = when {
                keyAttestation == null -> "attestation not checked"
                appAttestAdmitted != null -> "admitted by App Attest, ${appAttestAdmitted.appId}"
                keyAttestation.attested -> "hardware-attested, ${keyAttestation.securityLevel}"
                else -> "not attested: ${keyAttestation.reason}"
            }
            audit?.record("attestation_device_registered",
                "Device $deviceId registered its attestation key ($how)",
                configApiId, deviceId, actor = deviceId, ip = remote,
                detail = buildJsonObject {
                    put("spkiSha256", spki)
                    put("keyAttested", keyAttestation?.attested ?: false)
                    keyAttestation?.securityLevel?.let { put("securityLevel", it) }
                    keyAttestation?.reason?.let { put("reason", it) }
                    registration.facts?.let { facts ->
                        facts.deviceLocked?.let { put("deviceLocked", it) }
                        facts.verifiedBootState?.let { put("verifiedBootState", it) }
                        facts.osPatchLevel?.let { put("osPatchLevel", it) }
                    }
                    appAttestAdmitted?.let {
                        put("attestedBy", AppAttestAdmission.KIND)
                        put("appId", it.appId)
                    }
                })
        }

        // ── 6. Policy ──────────────────────────────────────────────────
        val policy = policyFor(configApiId)
        // The report names its platform itself, and a hooked app writes what it likes:
        // the claim is taken only while nothing the server verified or recorded
        // contradicts it. A contradiction is judged by the platform on record and
        // raises `app_integrity` (an Android-attested device claiming to be an
        // iPhone to skip the Android checks).
        val platform = effectivePlatform(platformOf(reportJson), device)
        val platformMismatch = platform != platformOf(reportJson)
        val isIos = platform == PLATFORM_IOS
        val appAttestRound = if (appAttestAdmitted != null) AppAttestRound(emptyList(), verified = true, unknownKey = false, v1 = appAttestAdmittedV1)
            else appAttestFlags(configApiId, deviceId, nonce, canonical, provider, providerOutside, device, isIos, now)
        val playRound = playIntegrityFlags(configApiId, deviceId, nonce, provider, providerOutside, device, now, isIos)
        val raised = (raisedFlags(reportJson, device, appAttestRound.verified, platform, registration = firstSeen) +
            (if (platformMismatch) listOf(AttestationFlag.APP_INTEGRITY) else emptyList()) +
            (if (configRollback(configApiId, deviceId, device, currentIssuedAt, now)) listOf(AttestationFlag.CONFIG_ROLLBACK) else emptyList()) +
            playRound.flags + appAttestRound.flags).distinct()
        val reasons: List<String>
        val policyWarnings: List<String>
        val passed: Boolean
        when {
            device.forceFail -> {
                passed = false
                reasons = listOf("force_fail")
                policyWarnings = raised.filter { policy.actionFor(it) != FlagAction.IGNORE }.map { it.wire }
            }
            device.forcePass -> {
                passed = true
                reasons = emptyList()
                policyWarnings = raised.filter { policy.actionFor(it) != FlagAction.IGNORE }.map { it.wire }
            }
            else -> {
                reasons = raised.filter { policy.actionFor(it) == FlagAction.REJECT }.map { it.wire }
                policyWarnings = raised.filter { policy.actionFor(it) == FlagAction.WARN }.map { it.wire }
                passed = reasons.isEmpty()
            }
        }
        // Not flags, whatever the policy does with `app_attest` / `play_integrity`:
        // an instruction (the server has no record of the key the assertion
        // names, so the app drops it and attests a new one next round,
        // PORTING.md §6), and notes that a verdict passed under the older
        // binding (v1: the round's nonce, not the report) — refused outright
        // with APP_ATTEST_REQUIRE_V2 / PLAY_INTEGRITY_REQUIRE_V2.
        val warnings = policyWarnings +
            listOfNotNull(
                APP_ATTEST_UNKNOWN_KEY.takeIf { appAttestRound.unknownKey },
                APP_ATTEST_V1.takeIf { appAttestRound.v1 },
                PLAY_INTEGRITY_V1.takeIf { playRound.v1 }
            )
        val arc = nonces.arc(reasons, warnings)

        // ── 7. Token ───────────────────────────────────────────────────
        var token: String? = null
        var tokenExpiresAt: Long? = null
        if (passed) {
            val secret = secrets.active()
            val nowSeconds = now.epochSecond
            // cnf: the key that signed this report and, over mTLS, the certificate it came with (§5).
            token = PinVaultToken.issue(secret.kid, secret.secret, deviceId, configApiId, arc, policy.version,
                policy.tokenTtlSeconds, device.annotations, nowSeconds,
                keyThumbprint = PinVaultToken.jwkThumbprint(publicKey as ECPublicKey),
                certThumbprint = clientCertificate?.let { PinVaultToken.certThumbprint(it) })
            tokenExpiresAt = (nowSeconds + policy.tokenTtlSeconds) * 1000
        }

        devices.recordVerdict(
            configApiId, deviceId, if (passed) "pass" else "reject", arc, reasons, warnings, policy.version,
            trimmedReport = trimReport(reportJson, provider?.string("name")), sdkVersion = reportJson.string("sdkVersion"),
            verdictProvider = provider?.string("name"), verdictToken = provider?.string("token")?.take(MAX_VERDICT_TOKEN), now = now,
            platform = platform
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
        /**
         * [appAttest]: the report's App Attest attestation that admitted the
         * device in place of a chain ([appAttestV1]: with the v1 client data
         * hash); [facts]: what a hardware-level chain said about the device.
         */
        class Accept(
            val attestation: KeyAttestation?,
            val appAttest: AppAttestAdmission.Result.Passed? = null,
            val facts: com.example.pinvault.server.service.KeyFacts? = null,
            val appAttestV1: Boolean = false
        ) : Registration
    }

    /**
     * Step 5 for an unknown device: what `ATTESTATION_KEY_POLICY` makes of its chain.
     *
     * Under enforce an iPhone has no chain: with App Attest configured, a
     * report whose `app-attest` verdict carries a fresh key's attestation made
     * for this round (client data hash v2 of the canonical string, or v1 of
     * the nonce and the device id, see [appAttestHashes]) is
     * verified here, first, and admits the device in place of the chain; a
     * failing one is refused `attestation_invalid` with the verifier's reason
     * (`app_attest_…`), an assertion (a key this server has no record of)
     * `attestation_required` with `app_attest_unknown_key`, so the app attests
     * a new key. Without such a verdict the refusal is the chain's, as before.
     */
    private fun checkRegistrationChain(
        chain: List<String>?, publicKey: PublicKey, deviceId: String, nonce: String, canonical: String,
        provider: JsonObject?, providerOutside: Boolean, now: Instant
    ): Registration {
        if (keyPolicy == AttestationKeyPolicy.OFF) return Registration.Accept(KeyAttestation(false, null, NOT_CHECKED))
        if (keyPolicy == AttestationKeyPolicy.ENFORCE && chain.isNullOrEmpty()) appAttest?.let { verifier ->
            val token = provider?.takeIf { it.string("name") == AppAttestVerifier.PROVIDER }?.string("token")
            if (token != null) {
                var v1 = false
                var result: AppAttestAdmission.Result = AppAttestAdmission.Result.Absent
                for ((version, hash) in appAttestHashes(nonce, deviceId, canonical, providerOutside)) {
                    result = AppAttestAdmission.verify(verifier, token, hash, now)
                    v1 = version == 1
                    if (result is AppAttestAdmission.Result.Passed) break
                }
                if (result is AppAttestAdmission.Result.Passed && v1 && verifier.requireV2) {
                    result = AppAttestAdmission.Result.Failed(AppAttestAdmission.REASON_PREFIX + CLIENT_DATA_V1)
                }
                return when (result) {
                    is AppAttestAdmission.Result.Passed -> Registration.Accept(AppAttestAdmission.record(), result, appAttestV1 = v1)
                    is AppAttestAdmission.Result.Failed -> Registration.Refuse(
                        if (result.reason == AppAttestAdmission.ATTESTATION_REQUIRED) {
                            Outcome.Refused(HttpStatusCode.Forbidden, "attestation_required",
                                "This server has no App Attest key on record for this device: it registers a device only with a " +
                                    "fresh App Attest key's attestation (or an Android Key Attestation chain). Attest a new key.",
                                reason = APP_ATTEST_UNKNOWN_KEY)
                        } else {
                            Outcome.Refused(HttpStatusCode.Forbidden, "attestation_invalid",
                                "The report's App Attest attestation did not pass: ${result.reason}.", reason = result.reason)
                        })
                    AppAttestAdmission.Result.Absent -> Registration.Refuse(attestationRequired())
                }
            }
        }
        val verdict = if (chain.isNullOrEmpty()) AndroidKeyAttestation.Verdict.MISSING else {
            val v = verifier.verifyIdentityKey(chain, publicKey, deviceId)
            // Without the package + signer binding a passing chain says nothing about which app made the key.
            if (v.passed && !verifier.bindsApp) AndroidKeyAttestation.Verdict(false, APP_BINDING_NOT_CONFIGURED, v.securityLevel, facts = v.facts) else v
        }
        if (verdict.passed) return Registration.Accept(KeyAttestation(true, verdict.securityLevel, verdict.reason), facts = verdict.facts)
        if (keyPolicy == AttestationKeyPolicy.ENFORCE) {
            return Registration.Refuse(if (verdict.reason == AndroidKeyAttestation.Verdict.MISSING.reason) {
                attestationRequired()
            } else {
                Outcome.Refused(HttpStatusCode.Forbidden, "attestation_invalid",
                    "The device key's Android Key Attestation did not pass: ${verdict.reason}.", reason = verdict.reason)
            })
        }
        // warn: registered unattested — with what the chain said about the device, if it got that far.
        return Registration.Accept(KeyAttestation(false, verdict.securityLevel, verdict.reason), facts = verdict.facts)
    }

    /**
     * The client data hashes an App Attest verdict of this round may use, in
     * the order tried: v2 ([AppAttestVerifier.roundClientDataHashV2] of the
     * canonical string), then — for a token inside the report, which cannot
     * be v2 — v1 ([AppAttestVerifier.roundClientDataHash]).
     */
    private fun appAttestHashes(nonce: String, deviceId: String, canonical: String, providerOutside: Boolean): List<Pair<Int, ByteArray>> =
        listOfNotNull(
            2 to AppAttestVerifier.roundClientDataHashV2(canonical),
            (1 to AppAttestVerifier.roundClientDataHash(nonce, deviceId)).takeIf { !providerOutside }
        )

    private fun attestationRequired() = Outcome.Refused(HttpStatusCode.Forbidden, "attestation_required",
        "This server registers only keys with an Android Key Attestation chain (attestationChain), made with the challenge of the deviceId" +
            (if (appAttest != null) ", or, from an iOS app, a report whose app-attest verdict carries a fresh App Attest key's attestation for this round." else "."))

    /**
     * Step 4 of §4: the flags the report raises, with the server-side ones
     * merged in — `app_integrity` from the signer/package check,
     * `software_key` / `key_unattested` from the device record, `old_patch_level`
     * from the report's patch level against `ATTESTATION_MIN_PATCH_LEVEL`.
     *
     * An iOS report (`device.platform` = `ios`) has no key attestation chain,
     * patch date or signer digest: `app_integrity` compares `app.bundleId`
     * and `app.teamId`, `key_unattested` is lifted by [appAttestVerified] (an
     * App Attest verdict verified for the device), `software_key` follows the
     * reported key level (`secure_enclave` is hardware), and `old_patch_level`
     * compares `device.osVersion` with `ATTESTATION_MIN_IOS_VERSION`.
     *
     * An Android device registered with a hardware-level chain is judged by
     * what the chain said ([AttestedDevice.keyFacts]) on every round:
     * `bootloader_unlocked`, `boot_not_verified`, `key_revoked` (its serials
     * against the revocation list as it is now), `old_patch_level` from the
     * attested osPatchLevel instead of the report's, and `report_mismatch`
     * when the report contradicts the record ([reportContradicts];
     * [registration] = this round registered the key).
     */
    internal fun raisedFlags(
        report: JsonObject, device: AttestedDevice, appAttestVerified: Boolean = false,
        platform: String = effectivePlatform(platformOf(report), device),
        registration: Boolean = false
    ): List<AttestationFlag> {
        val raised = LinkedHashSet<AttestationFlag>()
        (report["signals"] as? JsonObject)?.forEach { (name, value) ->
            val flag = AttestationFlag.of(name) ?: return@forEach
            if ((value as? JsonObject)?.get("flag")?.let { (it as? JsonPrimitive)?.booleanOrNull } == true) raised += flag
        }
        if (platform == PLATFORM_IOS) return raisedIosFlags(report, appAttestVerified, raised)
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
        // Only an Android chain attests the key itself (App Attest vouches for the app).
        val keyAttested = device.keyAttestation?.attested == true && !AppAttestAdmission.admitted(device.keyAttestation)
        if (!keyAttested) {
            raised += AttestationFlag.KEY_UNATTESTED
            val level = (report["device"] as? JsonObject)?.string("keySecurityLevel")?.lowercase()
            if (level == null || level == "software" || level == "unknown") raised += AttestationFlag.SOFTWARE_KEY
        }
        val facts = device.keyFacts
        if (facts != null) {
            if (facts.deviceLocked == false) raised += AttestationFlag.BOOTLOADER_UNLOCKED
            if (!verifier.bootTrusted(facts)) raised += AttestationFlag.BOOT_NOT_VERIFIED
        }
        // Revoked at registration, or since: Google's list grows, the device's chain does not change.
        if (device.keyAttestation?.reason == CERTIFICATE_REVOKED || facts?.chainSerials?.any { verifier.isRevoked(it) } == true) {
            raised += AttestationFlag.KEY_REVOKED
        }
        if (reportContradicts(report, device, registration)) raised += AttestationFlag.REPORT_MISMATCH
        verifier.minPatchLevel?.let { min ->
            // The hardware's word when there is one: it was this at registration, and a patch level does not go back.
            val patch = facts?.osPatchLevel ?: (report["device"] as? JsonObject)?.string("securityPatch")?.let { parsePatch(it) }
            if (patch == null || patch < min) raised += AttestationFlag.OLD_PATCH_LEVEL
        }
        return raised.toList()
    }

    /**
     * Whether an Android report says something the device's record refutes —
     * the report is the app's word, the record the secure hardware's:
     *
     *  - `device.verifiedBootState` `green` while the chain said the
     *    bootloader is unlocked or the boot not Verified (a hidden root
     *    rewrites the property; the genuine app on such a phone reports
     *    `orange` / `yellow`);
     *  - `device.securityPatch` more than [PATCH_TOLERANCE_MONTHS] older than
     *    the attested osPatchLevel (a patch level only rises);
     *  - on the round that registered the key: `keyAttested: true` while no
     *    chain came with it (the library sends the chain on the first round of
     *    every process whenever its key has one).
     *
     * A device without hardware facts (no chain, a software-level one) is
     * judged on the last point only.
     */
    private fun reportContradicts(report: JsonObject, device: AttestedDevice, registration: Boolean): Boolean {
        val block = report["device"] as? JsonObject
        val facts = device.keyFacts
        if (facts != null) {
            val claimsGreen = block?.string("verifiedBootState")?.trim()?.lowercase() == "green"
            if (claimsGreen && (facts.deviceLocked == false || facts.verifiedBootState != com.example.pinvault.server.service.KeyFacts.VERIFIED)) return true
            val reported = block?.string("securityPatch")?.let { parsePatch(it) }
            val attested = facts.osPatchLevel
            if (reported != null && attested != null && months(attested) - months(reported) > PATCH_TOLERANCE_MONTHS) return true
        }
        return registration && device.keyAttestation?.reason == AndroidKeyAttestation.Verdict.MISSING.reason &&
            (block?.get("keyAttested") as? JsonPrimitive)?.booleanOrNull == true
    }

    /**
     * `config_rollback` (AND-4): whether [reported] (`currentIssuedAt`) is
     * lower than the highest one this device reported before under the same
     * signing-key set; stores it as the new highest when it is. The library's
     * value never goes down (a health-check rollback keeps it, PinVault.reset
     * keeps it) except when a newer signing-key set resets its watermarks —
     * the server's own set version then differs from the stored one and the
     * comparison starts again. 0 or absent (no config held) is not compared;
     * a value more than an hour ahead of this server's clock is no config it
     * signed and is not stored (one bogus report would make every later one
     * a "rollback").
     *
     * Hook for periodic re-attestation: a client that later sends a fresh
     * chain for a new short-lived key would refresh [AttestedDevice.keyFacts]
     * here as well; the libraries do not do that yet.
     */
    private fun configRollback(configApiId: String, deviceId: String, device: AttestedDevice, reported: Long?, now: Instant): Boolean {
        val watermark = reported?.takeIf { it > 0 } ?: return false
        if (watermark > now.toEpochMilli() + MAX_WATERMARK_AHEAD_MS) return false
        val keySet = keySetVersion()
        val stored = device.configWatermark?.takeIf { device.configWatermarkKeySet == keySet }
        if (stored == null || watermark > stored) devices.recordConfigWatermark(configApiId, deviceId, watermark, keySet)
        return stored != null && watermark < stored
    }

    /** [raisedFlags] for an iOS report; [raised] holds the report's own signals. */
    private fun raisedIosFlags(report: JsonObject, appAttestVerified: Boolean, raised: LinkedHashSet<AttestationFlag>): List<AttestationFlag> {
        val app = report["app"] as? JsonObject
        val deviceBlock = report["device"] as? JsonObject
        if (verifier.packageNames.isNotEmpty()) {
            val bundleId = app?.string("bundleId")
            if (bundleId == null || bundleId !in verifier.packageNames) raised += AttestationFlag.APP_INTEGRITY
        }
        if (ios.teamIds.isNotEmpty()) {
            val teamId = app?.string("teamId")
            if (teamId == null || teamId !in ios.teamIds) raised += AttestationFlag.APP_INTEGRITY
        }
        // No Android chain on iOS: only App Attest (Apple vouching for the app on a real device) counts.
        if (!appAttestVerified) raised += AttestationFlag.KEY_UNATTESTED
        // App Attest does not vouch for the identity key itself: its level is what the genuine library reports.
        val level = deviceBlock?.string("keySecurityLevel")?.lowercase()
        if (level == null || level in SOFTWARE_LEVELS) raised += AttestationFlag.SOFTWARE_KEY
        if (ios.osVersionTooOld(deviceBlock?.string("osVersion"))) raised += AttestationFlag.OLD_PATCH_LEVEL
        return raised.toList()
    }

    /** [appAttestFlags]' answer: the flags, whether a verdict verified for the device, whether the key was unknown. */
    private class AppAttestRound(val flags: List<AttestationFlag>, val verified: Boolean, val unknownKey: Boolean, val v1: Boolean = false) {
        companion object {
            val NONE = AppAttestRound(emptyList(), verified = false, unknownKey = false)
        }
    }

    /**
     * §12: with a verifier configured, the report's `app-attest` token is
     * verified against this round's client data hash and the outcome stored
     * with the device; `app_attest` is raised when it fails. Without a token
     * this round, the stored verdict stands while it is younger than
     * `verdictMaxAgeSeconds` (a failed one keeps `app_attest` raised until a
     * fresh pass); older or absent → `app_attest_missing` on an iOS device.
     */
    private fun appAttestFlags(
        configApiId: String, deviceId: String, nonce: String, canonical: String, provider: JsonObject?, providerOutside: Boolean,
        device: AttestedDevice, isIos: Boolean, now: Instant
    ): AppAttestRound {
        val verifier = appAttest ?: return AppAttestRound.NONE
        val token = provider?.takeIf { it.string("name") == AppAttestVerifier.PROVIDER }?.string("token")
        if (token != null) {
            val checked = verifyAppAttest(verifier, configApiId, deviceId, nonce, canonical, providerOutside, token, now)
            return if (checked.reason == null) AppAttestRound(emptyList(), verified = true, unknownKey = false, v1 = checked.v1)
            else AppAttestRound(listOf(AttestationFlag.APP_ATTEST), verified = false, unknownKey = checked.reason == APP_ATTEST_UNKNOWN_KEY)
        }
        val verifiedAt = device.appAttestAt?.let { runCatching { Instant.parse(it) }.getOrNull() }
        // A device with an App Attest key on record can assert every round (no Apple
        // server is involved): a round without a token rides on the last verdict only
        // briefly, so leaving the token out does not borrow a day-old pass.
        val maxAge = if (device.appAttestKeyId != null) minOf(verifier.verdictMaxAgeSeconds, APP_ATTEST_ROUND_GRACE_SECONDS)
            else verifier.verdictMaxAgeSeconds
        val fresh = verifiedAt != null && !now.isAfter(verifiedAt.plusSeconds(maxAge))
        return when {
            !fresh -> if (isIos) AppAttestRound(listOf(AttestationFlag.APP_ATTEST_MISSING), false, false) else AppAttestRound.NONE
            device.appAttestResult == "pass" -> AppAttestRound(emptyList(), verified = true, unknownKey = false)
            else -> AppAttestRound(listOf(AttestationFlag.APP_ATTEST), verified = false, unknownKey = false)
        }
    }

    /** [verifyAppAttest]'s answer: [reason] null = passed; [v1] = it passed with the v1 client data hash. */
    private class AppAttestCheck(val reason: String?, val v1: Boolean = false)

    /**
     * Verifies one `app-attest` token and stores the outcome: an attestation
     * registers its key (counter 0), an assertion must come from the key on
     * record with a higher counter. The client data hash is tried as v2, then
     * (for a token inside the report) v1 — [appAttestHashes]; a v1 pass under
     * `APP_ATTEST_REQUIRE_V2` fails [CLIENT_DATA_V1]. A failure is reported
     * with the reason of the last hash tried (v1 for a token in the report:
     * what an older app made).
     */
    private fun verifyAppAttest(
        verifier: AppAttestVerifier, configApiId: String, deviceId: String, nonce: String, canonical: String, providerOutside: Boolean,
        text: String, now: Instant
    ): AppAttestCheck {
        val token = AppAttestVerifier.parseToken(text)
        val kind = if (token?.attestation != null) "attestation" else "assertion"
        fun fail(reason: String): AppAttestCheck {
            devices.recordAppAttestFailure(configApiId, deviceId, appAttestSummary(verifier, kind, reason, token?.keyIdBase64, null, null, now), now)
            return AppAttestCheck(reason)
        }
        if (token == null || !token.wellFormed) return fail("malformed")
        val hashes = appAttestHashes(nonce, deviceId, canonical, providerOutside)
        val keyId = token.keyIdBase64!!
        if (token.attestation != null) {
            var result: AppAttestVerifier.Attestation? = null
            var version = 0
            for ((v, hash) in hashes) {
                result = verifier.verifyAttestation(token.attestation, token.keyId!!, hash, now)
                version = v
                if (result.passed) break
            }
            if (!result!!.passed) return fail(result.reason)
            if (version == 1 && verifier.requireV2) return fail(CLIENT_DATA_V1)
            devices.registerAppAttestKey(configApiId, deviceId, keyId, Base64.getEncoder().encodeToString(result.publicKey),
                appAttestSummary(verifier, kind, "ok", keyId, result.appId, 0, now, version), now)
            return AppAttestCheck(null, v1 = version == 1)
        }
        // An assertion from a key this server has no record of (forgotten, never attested, another install's).
        val stored = devices.appAttestKey(configApiId, deviceId)?.takeIf { it.keyId == keyId } ?: return fail(APP_ATTEST_UNKNOWN_KEY)
        val publicKey = runCatching { Base64.getDecoder().decode(stored.publicKey) }.getOrNull() ?: return fail(APP_ATTEST_UNKNOWN_KEY)
        var result: AppAttestVerifier.Assertion? = null
        var version = 0
        for ((v, hash) in hashes) {
            result = verifier.verifyAssertion(token.assertion!!, hash, publicKey, stored.counter)
            version = v
            if (result.passed) break
        }
        if (!result!!.passed) return fail(result.reason)
        if (version == 1 && verifier.requireV2) return fail(CLIENT_DATA_V1)
        val summary = appAttestSummary(verifier, kind, "ok", keyId, null, result.counter, now, version)
        if (!devices.advanceAppAttestCounter(configApiId, deviceId, keyId, result.counter!!, summary, now)) return fail("counter_replay")
        return AppAttestCheck(null, v1 = version == 1)
    }

    /** The stored summary: what was checked and how it ended, never the token or the nonce. */
    private fun appAttestSummary(
        verifier: AppAttestVerifier, kind: String, reason: String, keyId: String?, appId: String?, counter: Long?, now: Instant,
        /** Which client data hash it verified with (1, 2); null = none / not known. */
        clientData: Int? = null
    ) =
        buildJsonObject {
            put("reason", reason)
            put("kind", kind)
            clientData?.let { put("clientData", "v$it") }
            put("environment", verifier.environment.wire)
            put("verifiedAt", now.toString())
            keyId?.let { put("keyId", it) }
            appId?.let { put("appId", it) }
            counter?.let { put("counter", it) }
        }.toString()

    /** [playIntegrityFlags]' answer: the flags, and whether a token passed with the v1 nonce. */
    private class PlayRound(val flags: List<AttestationFlag>, val v1: Boolean = false) {
        companion object {
            val NONE = PlayRound(emptyList())
        }
    }

    /**
     * §11: with a verifier configured, the `play-integrity` token is verified
     * against this round ([PlayIntegrityVerifier.verifyRound]: the v2 nonce of
     * [nonce] and [deviceId], else — for a token inside the report — [nonce]
     * itself) and the outcome stored with the device; `play_integrity` is
     * raised when it fails. Without a token this round, a stored pass stands
     * while it is younger than `stalePassSeconds`, a stored fail keeps
     * `play_integrity` raised while it is younger than `verdictMaxAgeSeconds`;
     * otherwise `play_integrity_missing`. A provider under another name is
     * stored as before and not judged.
     */
    private fun playIntegrityFlags(
        configApiId: String, deviceId: String, nonce: String, provider: JsonObject?, providerOutside: Boolean, device: AttestedDevice,
        now: Instant, isIos: Boolean = false
    ): PlayRound {
        val verifier = playIntegrity ?: return PlayRound.NONE
        val token = provider?.takeIf { it.string("name") == PLAY_INTEGRITY_PROVIDER }?.string("token")
        if (token != null) {
            val result = verifier.verifyRound(token, nonce, deviceId, now, v2Only = providerOutside)
            devices.recordPlayIntegrity(configApiId, deviceId, if (result.passed) "pass" else "fail", result.summary.toString(), now)
            return if (result.passed) PlayRound(emptyList(), v1 = result.nonceVersion == 1) else PlayRound(listOf(AttestationFlag.PLAY_INTEGRITY))
        }
        // An iPhone never has a Play Integrity verdict: its absence says nothing there,
        // but only while App Attest (its counterpart) is configured to judge it. Without
        // it an "iOS" claim is not a way out of `play_integrity_missing`.
        if (isIos && appAttest != null) return PlayRound.NONE
        val verifiedAt = device.playIntegrityAt?.let { runCatching { Instant.parse(it) }.getOrNull() }
        fun youngerThan(seconds: Long) = verifiedAt != null && !now.isAfter(verifiedAt.plusSeconds(seconds))
        return when {
            device.playIntegrityResult == "pass" && youngerThan(verifier.stalePassSeconds) -> PlayRound.NONE
            device.playIntegrityResult == "fail" && youngerThan(verifier.verdictMaxAgeSeconds) -> PlayRound(listOf(AttestationFlag.PLAY_INTEGRITY))
            else -> PlayRound(listOf(AttestationFlag.PLAY_INTEGRITY_MISSING))
        }
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

    /** The report's app, device and signals blocks, as stored for the dashboard; [providerName] the round's verdict provider (never its token). */
    private fun trimReport(report: JsonObject, providerName: String?): String = buildJsonObject {
        report["sdkVersion"]?.let { put("sdkVersion", it) }
        report["reportTime"]?.let { put("reportTime", it) }
        report["app"]?.let { put("app", it) }
        report["device"]?.let { put("device", it) }
        report["signals"]?.let { put("signals", it) }
        providerName?.let { put("verdictProvider", buildJsonObject { put("name", it) }) }
    }.toString()

    private fun invalid(message: String) = Outcome.Refused(HttpStatusCode.BadRequest, "invalid_json", message)

    companion object {
        /** The report (a string) is at most this long. */
        const val MAX_REPORT_BYTES = 16 * 1024

        /** A verdict provider's token is stored up to this length. */
        const val MAX_VERDICT_TOKEN = 8 * 1024

        /** `verdictProvider.name` of the Play Integrity provider (`pinvault-play-integrity`). */
        const val PLAY_INTEGRITY_PROVIDER = "play-integrity"

        /** A warning that tells the app to drop its App Attest key and attest a new one (PORTING.md §6). */
        const val APP_ATTEST_UNKNOWN_KEY = "app_attest_unknown_key"

        /** A warning: the round's App Attest verdict passed with the v1 client data hash (not bound to the report). */
        const val APP_ATTEST_V1 = "app_attest_v1"
        /** How long a round without an App Attest token rides on the last verdict, for a device whose key is on record. */
        const val APP_ATTEST_ROUND_GRACE_SECONDS = 600L

        /** A warning: the round's Play Integrity token passed with the v1 nonce (the round's, not bound to the device). */
        const val PLAY_INTEGRITY_V1 = "play_integrity_v1"

        /** The App Attest failure reason of a v1 verdict under `APP_ATTEST_REQUIRE_V2` (or outside the report). */
        const val CLIENT_DATA_V1 = "client_data_v1"

        /** The verifier's refusal of a chain with a revoked certificate. */
        const val CERTIFICATE_REVOKED = "certificate_revoked"

        /** How many months the report's security patch may trail the attested one before `report_mismatch`. */
        const val PATCH_TOLERANCE_MONTHS = 1

        /** A reported config watermark more than this far ahead of the server's clock is not stored. */
        private const val MAX_WATERMARK_AHEAD_MS = 3_600_000L

        /** YYYYMM → months since year 0. */
        private fun months(yyyymm: Int): Int = (yyyymm / 100) * 12 + yyyymm % 100

        /** `device.platform` of an iOS report; a report without one is from the Android library. */
        const val PLATFORM_IOS = "ios"
        const val PLATFORM_ANDROID = "android"
        private val PLATFORM = Regex("^[a-z0-9_-]{1,16}$")

        /** Key levels that are not hardware (`secure_enclave`, `tee`, `strongbox` are). */
        private val SOFTWARE_LEVELS = setOf("software", "unknown")

        /**
         * The platform [claimed] by a report, unless the device's record contradicts
         * it: a key whose Android Key Attestation chain verified, or an App Attest key
         * on record, fixes the platform; so does the platform of earlier verdicts.
         */
        fun effectivePlatform(claimed: String, device: AttestedDevice): String = when {
            // Admitted by App Attest in place of a chain: Apple hardware.
            AppAttestAdmission.admitted(device.keyAttestation) -> PLATFORM_IOS
            device.keyAttestation?.attested == true -> PLATFORM_ANDROID
            // A hardware chain that verified up to Google's root, even one refused under warn.
            device.keyFacts != null -> PLATFORM_ANDROID
            device.appAttestKeyId != null -> PLATFORM_IOS
            device.platform != null -> device.platform
            else -> claimed
        }

        /** What [report] ran on: its `device.platform` (lowercase), `android` when it names none. */
        fun platformOf(report: JsonObject): String =
            ((report["device"] as? JsonObject)?.string("platform")?.trim()?.lowercase()?.takeIf { PLATFORM.matches(it) }) ?: PLATFORM_ANDROID

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
