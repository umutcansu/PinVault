package com.example.pinvault.server.service.attestation

import com.example.pinvault.server.service.EnrollmentAttestationMode
import com.example.pinvault.server.service.UserAuthAttestationMode
import com.example.pinvault.server.store.KeyAttestation
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.time.Instant
import java.util.Base64

/**
 * Apple App Attest in place of an Android Key Attestation chain (PORTING.md
 * §6, ATTESTATION.md §12): an iPhone has no such chain, so where a setting
 * says `enforce` it sends an attestation of a FRESH App Attest key whose
 * client data hash binds it to what is being registered —
 *
 *  - an enrollment (`ENROLLMENT_ATTESTATION`): body field `appAttestation`,
 *    [AppAttestVerifier.enrollmentClientDataHash] of the integrity request
 *    hash (the CSR and the device id);
 *  - a screen-lock key (`USER_AUTH_ATTESTATION`, `purpose: user_auth`): body
 *    field `appAttestation`, [userAuthClientDataHash] of the device id and the
 *    key;
 *  - an attestation registration (`ATTESTATION_KEY_POLICY`): the report's
 *    `app-attest` verdict of the first round, the round's client data hash.
 *
 * Only with `APP_ATTEST_APP_IDS` configured (a verifier exists); without it
 * every one of them is refused as before. Each place verifies its own
 * attestation: the three hashes differ, so one made for a place does not pass
 * another, and a device admitted in one place is not admitted in the others.
 *
 * What it proves: the request came from the genuine app (its App ID) on
 * genuine Apple hardware. Not that the device is not jailbroken, and not where
 * the identity or the RSA key lives — the server stores such an admission as
 * [record] (`app_attest`), never as a hardware-attested key.
 */
object AppAttestAdmission {
    /** The body field that carries the token (a JSON string, as `integrityToken`; an object is read too). */
    const val FIELD = "appAttestation"

    /** [KeyAttestation.reason] and [KeyAttestation.keyKind] of a key or identity App Attest admitted. */
    const val KIND = "app_attest"

    /** Every failure reason starts with this, as at enrollment integrity (`app_attest_nonce_mismatch`, …). */
    const val REASON_PREFIX = "app_attest_"

    /** No App Attest key on record for an assertion: the app drops its key and attests a new one. */
    const val UNKNOWN_KEY = "app_attest_unknown_key"

    /** An assertion, or a token without an attestation: these places need a fresh key's attestation. */
    const val ATTESTATION_REQUIRED = "app_attest_attestation_required"

    /** Far above an attestation object (a few KB of Base64): anything larger is not one. */
    private const val MAX_TOKEN_CHARS = 16 * 1024

    /** What [verify] found. */
    sealed class Result {
        /** The field is absent: the request is judged as before. */
        data object Absent : Result()

        /** A fresh key's attestation verified for this request: the app it names, the key id (Base64), the key (SPKI DER). */
        class Passed(val appId: String, val keyId: String, val publicKey: ByteArray) : Result()

        /** It did not; [reason] starts with [REASON_PREFIX]. */
        data class Failed(val reason: String) : Result()
    }

    /** The record of a key or identity App Attest admitted: attested, no level (unknown), kind `app_attest`. */
    fun record(): KeyAttestation = KeyAttestation(attested = true, securityLevel = null, reason = KIND, keyKind = KIND)

    /** Whether [record] says App Attest (not an Android chain) admitted the key. Rows without a kind column carry it in the reason. */
    fun admitted(record: KeyAttestation?): Boolean =
        record?.attested == true && (record.keyKind == KIND || record.reason == KIND)

    /**
     * A screen-lock key's client data hash:
     * `SHA-256(UTF-8("pinvault-user-auth-key:v1:" + deviceId + ":" + base64(SHA-256(SPKI DER))))`.
     */
    fun userAuthClientDataHash(deviceId: String, spkiDer: ByteArray): ByteArray {
        val keyHash = Base64.getEncoder().encodeToString(AppAttestVerifier.sha256(spkiDer))
        return AppAttestVerifier.sha256("pinvault-user-auth-key:v1:$deviceId:$keyHash".toByteArray(Charsets.UTF_8))
    }

    /**
     * The token in [field] (the body's `appAttestation`, or a report's
     * provider token), verified as a fresh key's attestation made with
     * [clientDataHash]. Never throws.
     */
    fun verify(verifier: AppAttestVerifier, field: JsonElement?, clientDataHash: ByteArray, now: Instant = Instant.now()): Result {
        val text = when (field) {
            null, JsonNull -> return Result.Absent
            is JsonPrimitive -> if (field.isString) field.content else return Result.Failed(REASON_PREFIX + "malformed")
            is JsonObject -> field.toString()
            else -> return Result.Failed(REASON_PREFIX + "malformed")
        }
        return verify(verifier, text, clientDataHash, now)
    }

    /** [verify] of the token text itself. */
    fun verify(verifier: AppAttestVerifier, text: String, clientDataHash: ByteArray, now: Instant = Instant.now()): Result {
        if (text.length > MAX_TOKEN_CHARS) return Result.Failed(REASON_PREFIX + "malformed")
        val token = AppAttestVerifier.parseToken(text) ?: return Result.Failed(REASON_PREFIX + "malformed")
        val keyId = token.keyId
        if (!token.wellFormed || keyId == null) return Result.Failed(REASON_PREFIX + "malformed")
        val attestation = token.attestation ?: return Result.Failed(ATTESTATION_REQUIRED)
        val result = verifier.verifyAttestation(attestation, keyId, clientDataHash, now)
        if (!result.passed) return Result.Failed(REASON_PREFIX + result.reason)
        return Result.Passed(result.appId!!, token.keyIdBase64!!, result.publicKey!!)
    }

    /**
     * The start-up warning when an `enforce` setting would refuse every
     * iPhone because App Attest is not configured; null when none is on
     * `enforce` or [appAttestConfigured].
     */
    fun iosRefusedWarning(
        enrollment: EnrollmentAttestationMode,
        userAuth: UserAuthAttestationMode,
        keyPolicy: AttestationKeyPolicy,
        appAttestConfigured: Boolean
    ): String? {
        if (appAttestConfigured) return null
        val enforced = listOfNotNull(
            "ENROLLMENT_ATTESTATION=enforce (enrollment)".takeIf { enrollment == EnrollmentAttestationMode.ENFORCE },
            "USER_AUTH_ATTESTATION=enforce (screen-lock keys)".takeIf { userAuth == UserAuthAttestationMode.ENFORCE },
            "ATTESTATION_KEY_POLICY=enforce (attestation registration)".takeIf { keyPolicy == AttestationKeyPolicy.ENFORCE }
        )
        if (enforced.isEmpty()) return null
        return "WARNING: iOS devices will be refused under ${enforced.joinToString(", ")}: an iPhone has no Android Key " +
            "Attestation chain, and APP_ATTEST_APP_IDS is empty, so App Attest cannot stand in for it. Set APP_ATTEST_APP_IDS " +
            "(TEAMID.bundle.id) and APP_ATTEST_ROOT_CA_FILE (Apple's App Attestation Root CA) to admit iPhones (ATTESTATION.md §12)."
    }
}
