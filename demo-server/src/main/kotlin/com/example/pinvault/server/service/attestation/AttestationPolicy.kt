package com.example.pinvault.server.service.attestation

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject

/**
 * The signals a report can raise (ATTESTATION.md §3). The client measures
 * the first nine; `software_key`, `key_unattested` and `old_patch_level` are
 * set (or confirmed) by the server from its own records; `play_integrity*`
 * come from the Play Integrity verifier (§11) and are raised only when the
 * server has the Play Console keys configured, `app_attest*` from the App
 * Attest verifier (§12), only with `APP_ATTEST_APP_IDS` configured. The last
 * five are the server's own as well: `bootloader_unlocked`,
 * `boot_not_verified` and `key_revoked` from what a hardware-level Android
 * Key Attestation chain said at registration (never from a software-level
 * chain: emulators do not raise them), `report_mismatch` when the report
 * contradicts that record, `config_rollback` when a device reports an older
 * config than it did before.
 */
enum class AttestationFlag(val wire: String) {
    ROOTED("rooted"),
    EMULATOR("emulator"),
    DEBUGGER("debugger"),
    DEBUGGABLE("debuggable"),
    HOOKING_FRAMEWORK("hooking_framework"),
    APP_INTEGRITY("app_integrity"),
    CLONER("cloner"),
    UNKNOWN_INSTALLER("unknown_installer"),
    ADB_ENABLED("adb_enabled"),
    SOFTWARE_KEY("software_key"),
    KEY_UNATTESTED("key_unattested"),
    OLD_PATCH_LEVEL("old_patch_level"),
    /** Google's verdict did not meet the configured level, named another package or nonce, or the token did not verify. */
    PLAY_INTEGRITY("play_integrity"),
    /** No Play Integrity verdict verified for this device within `PLAY_INTEGRITY_MAX_AGE_SECONDS`. */
    PLAY_INTEGRITY_MISSING("play_integrity_missing"),
    /** An App Attest attestation or assertion the report carried did not verify (or the last one failed). */
    APP_ATTEST("app_attest"),
    /** An iOS device without an App Attest verdict verified within `APP_ATTEST_MAX_AGE_SECONDS`. */
    APP_ATTEST_MISSING("app_attest_missing"),
    /** The registration's hardware chain said the bootloader is unlocked (RootOfTrust `deviceLocked` = false). */
    BOOTLOADER_UNLOCKED("bootloader_unlocked"),
    /** The registration's hardware chain said the boot was not Verified (nor SelfSigned with a key in `ATTESTATION_TRUSTED_BOOT_KEYS`). */
    BOOT_NOT_VERIFIED("boot_not_verified"),
    /** A certificate of the registration's chain is on the attestation revocation list now (or was then). */
    KEY_REVOKED("key_revoked"),
    /** The report contradicts what the hardware said at registration: boot state, patch level, a chain it claims and did not send. */
    REPORT_MISMATCH("report_mismatch"),
    /** The device reports an older config (`currentIssuedAt`) than it reported before under the same signing-key set. */
    CONFIG_ROLLBACK("config_rollback");

    companion object {
        private val byWire = entries.associateBy { it.wire }
        fun of(wire: String): AttestationFlag? = byWire[wire]
        val names: List<String> = entries.map { it.wire }
    }
}

/** What a policy does with a raised flag. */
enum class FlagAction(val wire: String) {
    REJECT("reject"), WARN("warn"), IGNORE("ignore");

    companion object {
        fun of(wire: String): FlagAction? = entries.firstOrNull { it.wire == wire }
    }
}

/**
 * A Config API's attestation policy (ATTESTATION.md §4): an action per flag,
 * whether rejection reasons are told to the device, the token lifetime and
 * how soon the device should attest again.
 *
 * [version] is 0 for the server defaults (nothing stored) and grows with
 * every PUT; tokens carry it as `pol`.
 */
@Serializable
data class AttestationPolicy(
    val version: Int = 0,
    val flags: Map<String, String>,
    val revealReasons: Boolean = false,
    val tokenTtlSeconds: Int = DEFAULT_TOKEN_TTL_SECONDS,
    val attestIntervalSeconds: Int = DEFAULT_INTERVAL_SECONDS
) {
    /** The action for [flag]; a flag the stored map does not name is [FlagAction.WARN]. */
    fun actionFor(flag: AttestationFlag): FlagAction = flags[flag.wire]?.let { FlagAction.of(it) } ?: FlagAction.WARN

    /** This policy as JSON text, as stored and as GET returns it. */
    fun toJson(): String = json.encodeToString(serializer(), this)

    companion object {
        const val DEFAULT_TOKEN_TTL_SECONDS = 300
        const val DEFAULT_INTERVAL_SECONDS = 300
        val TOKEN_TTL_RANGE = 30..86_400
        val INTERVAL_RANGE = 60..86_400

        private val json = Json { encodeDefaults = true; ignoreUnknownKeys = true }

        /** The `strict` table of ATTESTATION.md §4. */
        val STRICT_FLAGS: Map<String, String> = linkedMapOf(
            "rooted" to "reject", "emulator" to "reject", "debugger" to "reject", "debuggable" to "reject",
            "hooking_framework" to "reject", "app_integrity" to "reject", "cloner" to "reject",
            "unknown_installer" to "warn", "adb_enabled" to "ignore", "software_key" to "warn",
            "key_unattested" to "warn", "old_patch_level" to "warn",
            // Warn until the fleet is measured: a reject here needs every app build to carry the provider.
            "play_integrity" to "warn", "play_integrity_missing" to "warn",
            "app_attest" to "warn", "app_attest_missing" to "warn",
            // What the hardware said, or a report that contradicts it: no false positive on a stock locked phone.
            "bootloader_unlocked" to "reject", "boot_not_verified" to "reject", "key_revoked" to "reject",
            "report_mismatch" to "reject", "config_rollback" to "reject"
        )

        /** `lenient`: everything a warning — what a first rollout measures the fleet with. */
        val LENIENT_FLAGS: Map<String, String> = AttestationFlag.names.associateWith { "warn" }

        fun strict(revealReasons: Boolean = false, tokenTtlSeconds: Int = DEFAULT_TOKEN_TTL_SECONDS, attestIntervalSeconds: Int = DEFAULT_INTERVAL_SECONDS) =
            AttestationPolicy(0, STRICT_FLAGS, revealReasons, tokenTtlSeconds, attestIntervalSeconds)

        fun lenient(revealReasons: Boolean = false, tokenTtlSeconds: Int = DEFAULT_TOKEN_TTL_SECONDS, attestIntervalSeconds: Int = DEFAULT_INTERVAL_SECONDS) =
            AttestationPolicy(0, LENIENT_FLAGS, revealReasons, tokenTtlSeconds, attestIntervalSeconds)

        /** A stored policy row. Unknown fields are ignored; a damaged row falls back to [defaults]. */
        fun fromStored(text: String, version: Int, defaults: AttestationPolicy): AttestationPolicy = try {
            val parsed = json.decodeFromString(serializer(), text)
            // Flags a later server knows and an older row does not: the default's action.
            parsed.copy(version = version, flags = defaults.flags + parsed.flags)
        } catch (_: Exception) {
            defaults.copy(version = version)
        }

        /**
         * What `PUT …/attestation/policy` accepts: every field optional (a
         * missing one keeps the [current] value), every flag name and action
         * known, the two durations within range. Returns the policy (version
         * untouched; the store bumps it) or the error to answer with 400.
         */
        fun parse(body: JsonObject, current: AttestationPolicy): Result<AttestationPolicy> {
            val flags = LinkedHashMap(current.flags)
            when (val element = body["flags"]) {
                null -> Unit
                is JsonObject -> for ((name, value) in element) {
                    AttestationFlag.of(name) ?: return Result.failure(IllegalArgumentException("unknown flag '$name' (known: ${AttestationFlag.names.joinToString()})"))
                    val action = (value as? JsonPrimitive)?.takeIf { it.isString }?.content?.let { FlagAction.of(it) }
                        ?: return Result.failure(IllegalArgumentException("flag '$name' must be reject, warn or ignore"))
                    flags[name] = action.wire
                }
                else -> return Result.failure(IllegalArgumentException("flags must be an object of flag → reject|warn|ignore"))
            }
            val reveal = when (val element = body["revealReasons"]) {
                null -> current.revealReasons
                else -> (element as? JsonPrimitive)?.booleanOrNull ?: return Result.failure(IllegalArgumentException("revealReasons must be true or false"))
            }
            val ttl = when (val element = body["tokenTtlSeconds"]) {
                null -> current.tokenTtlSeconds
                else -> (element as? JsonPrimitive)?.intOrNull?.takeIf { it in TOKEN_TTL_RANGE }
                    ?: return Result.failure(IllegalArgumentException("tokenTtlSeconds must be ${TOKEN_TTL_RANGE.first}..${TOKEN_TTL_RANGE.last}"))
            }
            val interval = when (val element = body["attestIntervalSeconds"]) {
                null -> current.attestIntervalSeconds
                else -> (element as? JsonPrimitive)?.intOrNull?.takeIf { it in INTERVAL_RANGE }
                    ?: return Result.failure(IllegalArgumentException("attestIntervalSeconds must be ${INTERVAL_RANGE.first}..${INTERVAL_RANGE.last}"))
            }
            return Result.success(AttestationPolicy(current.version, flags, reveal, ttl, interval))
        }

        fun parse(text: String, current: AttestationPolicy): Result<AttestationPolicy> {
            val body = try { Json.parseToJsonElement(text).jsonObject } catch (_: Exception) {
                return Result.failure(IllegalArgumentException("the body must be a JSON object"))
            }
            return parse(body, current)
        }
    }
}

/**
 * The server-wide defaults a Config API without a stored policy gets
 * (`ATTESTATION_POLICY_DEFAULT`, `ATTESTATION_TOKEN_TTL_SECONDS`,
 * `ATTESTATION_INTERVAL_SECONDS`, `ATTESTATION_REVEAL_REASONS`).
 */
class AttestationPolicyDefaults(
    val profile: String = "strict",
    val tokenTtlSeconds: Int = AttestationPolicy.DEFAULT_TOKEN_TTL_SECONDS,
    val attestIntervalSeconds: Int = AttestationPolicy.DEFAULT_INTERVAL_SECONDS,
    val revealReasons: Boolean = false
) {
    init {
        require(profile == "strict" || profile == "lenient") { "ATTESTATION_POLICY_DEFAULT must be strict or lenient (got '$profile')" }
    }

    val policy: AttestationPolicy = if (profile == "lenient") {
        AttestationPolicy.lenient(revealReasons, tokenTtlSeconds, attestIntervalSeconds)
    } else {
        AttestationPolicy.strict(revealReasons, tokenTtlSeconds, attestIntervalSeconds)
    }

    companion object {
        fun fromEnv(env: Map<String, String> = com.example.pinvault.server.service.ServerEnv.all()): AttestationPolicyDefaults {
            val profile = env["ATTESTATION_POLICY_DEFAULT"]?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: "strict"
            val ttl = (env["ATTESTATION_TOKEN_TTL_SECONDS"]?.trim()?.toIntOrNull() ?: AttestationPolicy.DEFAULT_TOKEN_TTL_SECONDS)
                .coerceIn(AttestationPolicy.TOKEN_TTL_RANGE)
            val interval = (env["ATTESTATION_INTERVAL_SECONDS"]?.trim()?.toIntOrNull() ?: AttestationPolicy.DEFAULT_INTERVAL_SECONDS)
                .coerceIn(AttestationPolicy.INTERVAL_RANGE)
            val reveal = when (env["ATTESTATION_REVEAL_REASONS"]?.trim()?.lowercase()) {
                null, "", "false", "off" -> false
                "true", "on" -> true
                else -> throw IllegalArgumentException("ATTESTATION_REVEAL_REASONS must be true or false (got '${env["ATTESTATION_REVEAL_REASONS"]}')")
            }
            return AttestationPolicyDefaults(profile, ttl, interval, reveal)
        }
    }
}

/**
 * `ATTESTATION_KEY_POLICY`: what a device's FIRST registration must show for
 * its key (Android Key Attestation of the identity key, challenge
 * `SHA-256("pinvault-identity-key:v1:" + deviceId)`).
 *
 *  - [OFF]: nothing is checked; the key is trusted on first use.
 *  - [WARN] (default): the chain is checked when there is one and the
 *    outcome stored with the device (`key_unattested` is then a signal).
 *  - [ENFORCE]: no registration without a passing chain (`403
 *    attestation_required` / `attestation_invalid`); the server does not
 *    start without the app binding. With `APP_ATTEST_APP_IDS` an iPhone's
 *    first-round App Attest attestation stands in for the chain
 *    ([AppAttestAdmission]); without it every iPhone is refused.
 */
enum class AttestationKeyPolicy {
    OFF, WARN, ENFORCE;

    companion object {
        fun parse(value: String?): AttestationKeyPolicy = when (value?.trim()?.lowercase()) {
            null, "" -> WARN
            "off" -> OFF
            "warn" -> WARN
            "enforce" -> ENFORCE
            else -> throw IllegalArgumentException("ATTESTATION_KEY_POLICY must be off, warn or enforce (got '$value')")
        }

        /** As [com.example.pinvault.server.service.EnrollmentAttestationMode.startupCheck]: enforce without the app binding refuses to start; warn returns the warning. */
        fun startupCheck(policy: AttestationKeyPolicy, attestation: com.example.pinvault.server.service.AndroidKeyAttestation, appAttest: Boolean = false): String? {
            if (policy == OFF || attestation.bindsApp) return null
            val missing = listOfNotNull(
                "ATTESTATION_PACKAGE_NAMES".takeIf { attestation.packageNames.isEmpty() },
                "ATTESTATION_SIGNER_SHA256".takeIf { attestation.signerDigests.isEmpty() }
            ).joinToString(" and ")
            if (policy == ENFORCE && appAttest) {
                return "WARNING: ATTESTATION_KEY_POLICY=enforce without $missing — Android devices are refused (their chains " +
                    "cannot be bound to your app); iPhones are admitted by App Attest (APP_ATTEST_APP_IDS)."
            }
            check(policy != ENFORCE) {
                "ATTESTATION_KEY_POLICY=enforce needs ATTESTATION_PACKAGE_NAMES and ATTESTATION_SIGNER_SHA256 " +
                    "($missing empty): without them any app on any locked phone can attest a key for any device id. " +
                    "Set both, or run ATTESTATION_KEY_POLICY=warn."
            }
            return "WARNING: ATTESTATION_KEY_POLICY=warn without $missing — no device key counts as hardware-attested on " +
                "this server (every device raises key_unattested). Set ATTESTATION_PACKAGE_NAMES and ATTESTATION_SIGNER_SHA256."
        }
    }
}
