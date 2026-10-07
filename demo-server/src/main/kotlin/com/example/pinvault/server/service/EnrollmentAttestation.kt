package com.example.pinvault.server.service

import com.example.pinvault.server.service.attestation.AppAttestAdmission
import com.example.pinvault.server.service.attestation.AppAttestVerifier
import com.example.pinvault.server.store.KeyAttestation
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.PublicKey

/**
 * What `ENROLLMENT_ATTESTATION` asks of the key a device enrolls with over a
 * CSR (every path: one-time token, enrollment code, code-less application,
 * `ENROLLMENT_MODE=open`).
 *
 *  - [OFF]: the `attestationChain` is not looked at.
 *  - [WARN] (default): the chain is checked when there is one and the outcome
 *    is stored with the identity (and shown next to a waiting request), but
 *    the enrollment goes ahead either way.
 *  - [ENFORCE]: no certificate without a passing attestation — 403
 *    `attestation_required` without a chain, `attestation_invalid` with a
 *    `reason` for one that fails; a server-made key (P12) cannot be attested,
 *    so an enrollment without a CSR gets 403 `csr_required`. The server does
 *    not start without the app binding ([AndroidKeyAttestation.bindsApp]).
 *
 * With `APP_ATTEST_APP_IDS` an iPhone's `appAttestation` stands in for the
 * chain under [WARN] and [ENFORCE] ([EnrollmentAttestation]); without it an
 * iPhone is refused under [ENFORCE].
 */
enum class EnrollmentAttestationMode {
    OFF, WARN, ENFORCE;

    companion object {
        /** `ENROLLMENT_ATTESTATION`; empty = [WARN]. An unknown value is a start-up error. */
        fun parse(value: String?): EnrollmentAttestationMode = when (value?.trim()?.lowercase()) {
            null, "" -> WARN
            "off" -> OFF
            "warn" -> WARN
            "enforce" -> ENFORCE
            else -> throw IllegalArgumentException("ENROLLMENT_ATTESTATION must be off, warn or enforce (got '$value')")
        }

        /**
         * The start-up check of [mode] against [attestation]'s app binding, as
         * for user-auth keys ([UserAuthAttestationMode.startupCheck]): [ENFORCE]
         * without `ATTESTATION_PACKAGE_NAMES` and `ATTESTATION_SIGNER_SHA256`
         * refuses to start, [WARN] returns the warning to print.
         */
        fun startupCheck(mode: EnrollmentAttestationMode, attestation: AndroidKeyAttestation): String? {
            if (mode == OFF || attestation.bindsApp) return null
            val missing = listOfNotNull(
                "ATTESTATION_PACKAGE_NAMES".takeIf { attestation.packageNames.isEmpty() },
                "ATTESTATION_SIGNER_SHA256".takeIf { attestation.signerDigests.isEmpty() }
            ).joinToString(" and ")
            check(mode != ENFORCE) {
                "ENROLLMENT_ATTESTATION=enforce needs ATTESTATION_PACKAGE_NAMES and ATTESTATION_SIGNER_SHA256 " +
                    "($missing empty): without them any app on any locked phone can attest a key for any device id. " +
                    "Set both, or run ENROLLMENT_ATTESTATION=warn."
            }
            return "WARNING: ENROLLMENT_ATTESTATION=warn without $missing — no enrollment counts as hardware-attested on " +
                "this server. Set ATTESTATION_PACKAGE_NAMES and ATTESTATION_SIGNER_SHA256."
        }
    }
}

/**
 * Checks the `attestationChain` of a CSR enrollment against the CSR's key
 * ([AndroidKeyAttestation.verifyIdentityKey]). The challenge is made from the
 * request's `deviceUid`, or its `deviceId` when it sends none — exactly what
 * the library hashed into the key.
 *
 * An iPhone has no such chain. With App Attest configured ([appAttest],
 * `APP_ATTEST_APP_IDS`) a request without `attestationChain` that carries
 * `appAttestation` — a fresh App Attest key's attestation whose client data
 * hash is SHA-256 of the request's integrity hash (the CSR and the same
 * device id) — stands in for it (PORTING.md §6): a pass is stored as
 * [AppAttestAdmission.record], a failure is refused or recorded like a
 * failing chain, with the verifier's reason prefixed `app_attest_`. It says
 * the genuine app on genuine Apple hardware asked for this CSR, not where
 * the key lives.
 *
 * Callers run this after the CSR was parsed and BEFORE a token, a policy slot
 * or anything else is spent: a refusal costs the device nothing it would
 * need again.
 */
class EnrollmentAttestation(
    /** Read on every check (tests switch it; Main passes a fixed mode). */
    private val modeOf: () -> EnrollmentAttestationMode,
    /** Apple App Attest in place of the chain (iOS); null = `APP_ATTEST_APP_IDS` empty, an iPhone has no way in under enforce. */
    private val appAttest: AppAttestVerifier? = null,
    private val clock: () -> java.time.Instant = java.time.Instant::now,
    verifier: () -> AndroidKeyAttestation
) {
    constructor(
        mode: EnrollmentAttestationMode,
        appAttest: AppAttestVerifier? = null,
        verifier: () -> AndroidKeyAttestation
    ) : this({ mode }, appAttest, verifier = verifier)

    val mode: EnrollmentAttestationMode get() = modeOf()

    private val attestation by lazy(verifier)

    /** What [check] decided. */
    sealed class Outcome {
        /** Go on; [record] is stored with the identity (null = not checked: mode off). */
        data class Proceed(val record: KeyAttestation?) : Outcome() {
            /** For the audit log. */
            val note: String get() = when {
                record == null -> "attestation not checked"
                AppAttestAdmission.admitted(record) -> "admitted by App Attest"
                record.attested -> "hardware-attested (${record.securityLevel})"
                else -> "not attested: ${record.reason}"
            }
        }

        /** 403 with [error] (`attestation_required` / `attestation_invalid`) and, for the latter, [reason]. */
        data class Refuse(val error: String, val reason: String?, val message: String) : Outcome() {
            fun body(): String = kotlinx.serialization.json.buildJsonObject {
                put("error", JsonPrimitive(error))
                reason?.let { put("reason", JsonPrimitive(it)) }
                put("message", JsonPrimitive(message))
            }.toString()
        }
    }

    /** Server-made keys are refused: under [EnrollmentAttestationMode.ENFORCE] only a device key can be attested. */
    val refusesServerMadeKeys: Boolean get() = mode == EnrollmentAttestationMode.ENFORCE

    /**
     * The verdict for an enrollment body [json] whose CSR carries [csrKey].
     * Off: [Outcome.Proceed] with no record, the chain is not read.
     */
    fun check(json: JsonObject?, csrKey: PublicKey, deviceUid: String? = null): Outcome {
        val mode = this.mode
        if (mode == EnrollmentAttestationMode.OFF) return Outcome.Proceed(null)
        // An iPhone: App Attest in place of the chain (configured, and no chain came).
        when (val appAttested = appAttestVerdict(json, deviceUid)) {
            null, AppAttestAdmission.Result.Absent -> Unit
            is AppAttestAdmission.Result.Passed ->
                return Outcome.Proceed(AppAttestAdmission.record())
            is AppAttestAdmission.Result.Failed -> return when {
                mode != EnrollmentAttestationMode.ENFORCE -> Outcome.Proceed(KeyAttestation(false, null, appAttested.reason))
                appAttested.reason == NO_DEVICE_ID -> attestationRequired()
                else -> Outcome.Refuse("attestation_invalid", appAttested.reason,
                    "The request's App Attest attestation (appAttestation) did not pass: ${appAttested.reason}.")
            }
        }
        val verdict = verdictFor(json, csrKey, deviceUid)
        if (verdict.passed) return Outcome.Proceed(KeyAttestation(true, verdict.securityLevel, verdict.reason))
        if (mode == EnrollmentAttestationMode.ENFORCE) {
            return if (verdict.reason == AndroidKeyAttestation.Verdict.MISSING.reason || verdict.reason == NO_DEVICE_ID) {
                attestationRequired()
            } else {
                Outcome.Refuse("attestation_invalid", verdict.reason,
                    "The device key's Android Key Attestation did not pass: ${verdict.reason}.")
            }
        }
        return Outcome.Proceed(KeyAttestation(false, verdict.securityLevel, verdict.reason))
    }

    private fun attestationRequired() = Outcome.Refuse("attestation_required", null,
        "This server enrolls only keys with an Android Key Attestation chain (attestationChain), " +
            "made with the challenge of the request's deviceUid (or deviceId)" +
            (if (appAttest != null) ", or, from an iOS app, an App Attest attestation (appAttestation) bound to the request." else "."))

    /**
     * The device id the server records for the identity when the route
     * decided it (open mode: always the device id); otherwise the library's
     * rule — deviceUid, or deviceId when the request has none. A passing
     * attestation proves exactly the id that is stored.
     */
    private fun deviceIdOf(json: JsonObject?, effectiveDeviceUid: String?): String? =
        effectiveDeviceUid ?: (json?.get("deviceUid") as? JsonPrimitive)?.takeIf { it !is JsonNull && it.isString }?.content
            ?: (json?.get("deviceId") as? JsonPrimitive)?.takeIf { it !is JsonNull && it.isString }?.content

    /**
     * App Attest in place of the chain: null unless App Attest is configured,
     * the request carries no chain (absent, null or empty) and has an
     * `appAttestation`. Its client data hash is SHA-256 of the integrity
     * request hash over the CSR and the device id that is stored.
     */
    private fun appAttestVerdict(json: JsonObject?, effectiveDeviceUid: String?): AppAttestAdmission.Result? {
        val verifier = appAttest ?: return null
        val field = json?.get(AppAttestAdmission.FIELD)?.takeIf { it !is JsonNull } ?: return null
        when (val chain = json["attestationChain"]) {
            null, JsonNull -> Unit
            is JsonArray -> if (chain.isNotEmpty()) return null
            else -> return null
        }
        val id = deviceIdOf(json, effectiveDeviceUid)
        if (id.isNullOrBlank()) return AppAttestAdmission.Result.Failed(NO_DEVICE_ID)
        val csrDer = (json["csr"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?.let { runCatching { java.util.Base64.getDecoder().decode(it) }.getOrNull() }
            ?: return AppAttestAdmission.Result.Failed(
                AppAttestAdmission.REASON_PREFIX + "malformed")
        val clientDataHash = AppAttestVerifier.enrollmentClientDataHash(IntegrityRequestHash.of(id, csrDer))
        return AppAttestAdmission.verify(verifier, field, clientDataHash, clock())
    }

    private fun verdictFor(json: JsonObject?, csrKey: PublicKey, effectiveDeviceUid: String?): AndroidKeyAttestation.Verdict {
        val id = deviceIdOf(json, effectiveDeviceUid)
        val chain = when (val element = json?.get("attestationChain")) {
            null, JsonNull -> return AndroidKeyAttestation.Verdict.MISSING
            is JsonArray -> element.map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
            else -> return AndroidKeyAttestation.Verdict(false, "chain_malformed")
        }
        if (chain.isEmpty()) return AndroidKeyAttestation.Verdict.MISSING
        if (chain.any { it == null }) return AndroidKeyAttestation.Verdict(false, "chain_malformed")
        if (id.isNullOrBlank()) return AndroidKeyAttestation.Verdict(false, NO_DEVICE_ID)
        val verdict = attestation.verifyIdentityKey(chain.filterNotNull(), csrKey, id)
        // Without the package + signer binding a passing chain says nothing about
        // which app made the key: it never counts (enforce does not start so).
        return if (verdict.passed && !attestation.bindsApp) {
            AndroidKeyAttestation.Verdict(false, APP_BINDING_NOT_CONFIGURED, verdict.securityLevel)
        } else verdict
    }

    companion object {
        /** A chain came without a deviceUid or deviceId to check its challenge against. */
        const val NO_DEVICE_ID = "device_id_missing"

        /** A passing chain on a server without ATTESTATION_PACKAGE_NAMES + ATTESTATION_SIGNER_SHA256. */
        const val APP_BINDING_NOT_CONFIGURED = "app_binding_not_configured"
    }
}
