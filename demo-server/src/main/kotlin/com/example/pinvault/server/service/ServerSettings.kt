package com.example.pinvault.server.service

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import java.io.File

/**
 * The server's settings, as the process reads them: the environment first,
 * then the values saved from the dashboard (`server-settings.json` next to
 * the database) for the settings the environment leaves empty. A setting the
 * environment sets is locked: the dashboard shows it and cannot change it, so
 * a deployment's fixed values (the production profile's) stay fixed.
 *
 * [overlay] is loaded once at start-up and never changes while the process
 * runs: saved values apply at the next start, as every setting is read at
 * start-up.
 */
object ServerEnv {
    @Volatile
    var overlay: Map<String, String> = emptyMap()

    /** `System.getenv(name)`, or the saved value when the environment leaves it empty. */
    fun get(name: String): String? {
        val env = System.getenv(name)
        if (!env.isNullOrBlank()) return env
        return overlay[name] ?: env
    }

    /** The environment with the saved values filled in where it is empty. */
    fun all(): Map<String, String> {
        val env = System.getenv()
        if (overlay.isEmpty()) return env
        val merged = LinkedHashMap(env)
        overlay.forEach { (k, v) -> if (env[k].isNullOrBlank()) merged[k] = v }
        return merged
    }

    /** Whether the environment itself sets [name] (the dashboard cannot change it). */
    fun lockedByEnvironment(name: String): Boolean = !System.getenv(name).isNullOrBlank()
}

/** One setting the dashboard may change. Every one applies at the next start. */
data class ServerSetting(
    val key: String,
    val group: String,
    val kind: Kind,
    /** What the server uses when the setting is not set. */
    val default: String,
    val choices: List<String> = emptyList(),
    val min: Long = 0,
    val max: Long = 0,
    /** TEXT: the whole value must match. */
    val pattern: Regex? = null
) {
    enum class Kind { BOOL, CHOICE, NUMBER, TEXT }

    /** Null when [value] is acceptable, else why not (English; the dashboard shows its own text by key). */
    fun problem(value: String): String? = when (kind) {
        Kind.BOOL -> if (value == "true" || value == "false") null else "must be true or false"
        Kind.CHOICE -> if (value in choices) null else "must be one of ${choices.joinToString()}"
        Kind.NUMBER -> when (val n = value.toLongOrNull()) {
            null -> "must be a whole number"
            in min..max -> null
            else -> "must be between $min and $max"
        }
        Kind.TEXT -> if (value.length <= 2000 && (pattern == null || pattern.matches(value))) null else "is not in the expected form"
    }
}

/**
 * The settings the setup wizard offers. Deliberately left out: secrets
 * (passwords, keys, the webhook secret), ports and paths, and the switches
 * that only exist for tests or demos (ALLOW_*) — they stay in the environment.
 */
object ServerSettingsCatalog {
    private val modes = listOf("off", "warn", "enforce")
    private val packageList = Regex("""[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+(\s*,\s*[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+)*""")
    private val digestList = Regex("""([0-9A-Fa-f]{2}:?){31}[0-9A-Fa-f]{2}(\s*,\s*([0-9A-Fa-f]{2}:?){31}[0-9A-Fa-f]{2})*""")
    private val hostName = Regex("""[A-Za-z0-9.\-]{1,253}""")
    private val portPairs = Regex("""\d{1,5}:\d{1,5}(\s*,\s*\d{1,5}:\d{1,5})*""")

    val all: List<ServerSetting> = listOf(
        // Change control and approval
        ServerSetting("PIN_CHANGE_APPROVALS", "governance", ServerSetting.Kind.NUMBER, "1", min = 1, max = 5),
        ServerSetting("PIN_LIVE_CHECK", "governance", ServerSetting.Kind.CHOICE, "off", modes),
        // Configs
        ServerSetting("CONFIG_TTL_SECONDS", "config", ServerSetting.Kind.NUMBER, "86400", min = 300, max = 2_592_000),
        ServerSetting("CONFIG_API_ADMIN_ROUTES", "config", ServerSetting.Kind.CHOICE, "off", listOf("off", "on")),
        // Devices and enrollment
        ServerSetting("ENROLLMENT_MODE", "devices", ServerSetting.Kind.CHOICE, "token", listOf("token", "open")),
        ServerSetting("CLIENT_CERT_TTL_DAYS", "devices", ServerSetting.Kind.NUMBER, "90", min = 1, max = 825),
        ServerSetting("HOST_CLIENT_CERT_REQUIRE_GRANT", "devices", ServerSetting.Kind.BOOL, "true"),
        ServerSetting("ENROLLMENT_ATTESTATION", "devices", ServerSetting.Kind.CHOICE, "warn", modes),
        ServerSetting("USER_AUTH_ATTESTATION", "devices", ServerSetting.Kind.CHOICE, "warn", modes),
        ServerSetting("INTEGRITY_VERIFICATION", "devices", ServerSetting.Kind.CHOICE, "off", modes),
        ServerSetting("ATTESTATION_PACKAGE_NAMES", "devices", ServerSetting.Kind.TEXT, "", pattern = packageList),
        ServerSetting("ATTESTATION_SIGNER_SHA256", "devices", ServerSetting.Kind.TEXT, "", pattern = digestList),
        // Attestation (the periodic check of the app and the phone)
        ServerSetting("ATTESTATION_ENABLED", "attestation", ServerSetting.Kind.BOOL, "true"),
        ServerSetting("ATTESTATION_KEY_POLICY", "attestation", ServerSetting.Kind.CHOICE, "warn", modes),
        ServerSetting("ATTESTATION_POLICY_DEFAULT", "attestation", ServerSetting.Kind.CHOICE, "strict", listOf("strict", "lenient", "production")),
        ServerSetting("ATTESTATION_TOKEN_TTL_SECONDS", "attestation", ServerSetting.Kind.NUMBER, "300", min = 30, max = 86_400),
        ServerSetting("ATTESTATION_INTERVAL_SECONDS", "attestation", ServerSetting.Kind.NUMBER, "300", min = 60, max = 86_400),
        ServerSetting("ATTESTATION_REVEAL_REASONS", "attestation", ServerSetting.Kind.BOOL, "false"),
        ServerSetting("ATTESTATION_FRESH_INTERVAL_SECONDS", "attestation", ServerSetting.Kind.NUMBER, "0", min = 0, max = 30L * 86_400),
        ServerSetting("ATTESTATION_FRESH_GRACE_SECONDS", "attestation", ServerSetting.Kind.NUMBER, "259200", min = 0, max = 30L * 86_400),
        ServerSetting("MOCK_HOST_REQUIRE_TOKEN", "attestation", ServerSetting.Kind.BOOL, "false"),
        ServerSetting("PINVAULT_TOKEN_ALG", "attestation", ServerSetting.Kind.CHOICE, "ES256", listOf("ES256", "HS256")),
        ServerSetting("MOCK_HOST_TOKEN_AUDIENCES", "attestation", ServerSetting.Kind.TEXT, "", pattern = Regex("[A-Za-z0-9._:-]+(,[A-Za-z0-9._:-]+)*")),
        ServerSetting("PINVAULT_TOKEN_REQUIRE_PROOF", "attestation", ServerSetting.Kind.BOOL, "true"),
        ServerSetting("PINVAULT_TOKEN_ANOMALY", "attestation", ServerSetting.Kind.CHOICE, "off", listOf("off", "warn", "refuse")),
        ServerSetting("PINVAULT_TOKEN_ANOMALY_MAX_ADDRESSES", "attestation", ServerSetting.Kind.NUMBER, "8", min = 1, max = 1000),
        ServerSetting("PINVAULT_TOKEN_ANOMALY_MAX_REQUESTS", "attestation", ServerSetting.Kind.NUMBER, "1200", min = 1, max = 1_000_000),
        ServerSetting("ATTESTATION_ANOMALY_TTL_SECONDS", "attestation", ServerSetting.Kind.NUMBER, "3600", min = 60, max = 30L * 86_400),
        // What the wizard writes into the app
        ServerSetting("SETUP_PUBLIC_HOST", "setup", ServerSetting.Kind.TEXT, "", pattern = hostName),
        ServerSetting("SETUP_PUBLIC_PORTS", "setup", ServerSetting.Kind.TEXT, "", pattern = portPairs)
    )

    private val byKey = all.associateBy { it.key }

    fun find(key: String): ServerSetting? = byKey[key]

    /**
     * What stops the server from starting with [effective] (the environment
     * with the saved values in): the settings that need another one. Empty
     * when it would start. English sentences, one per problem.
     */
    fun startProblems(effective: Map<String, String>): List<String> = buildList {
        fun v(key: String) = effective[key]?.trim().orEmpty()
        val bindsApp = v("ATTESTATION_PACKAGE_NAMES").isNotEmpty() && v("ATTESTATION_SIGNER_SHA256").isNotEmpty()
        // App Attest admits iPhones on its own; without the Android binding Android devices are refused (fail closed).
        val appAttest = v("APP_ATTEST_APP_IDS").isNotEmpty()
        for (key in listOf("ENROLLMENT_ATTESTATION", "USER_AUTH_ATTESTATION", "ATTESTATION_KEY_POLICY")) {
            if (v(key).lowercase() == "enforce" && !bindsApp && !appAttest) {
                add("$key=enforce needs ATTESTATION_PACKAGE_NAMES and ATTESTATION_SIGNER_SHA256 (or APP_ATTEST_APP_IDS for an iOS-only fleet)")
            }
        }
        // App Attest (iOS) verifies its own tokens; without either the server does not start.
        if (v("INTEGRITY_VERIFICATION").lowercase() == "enforce" && v("INTEGRITY_VERIFIER_COMMAND").isEmpty() && v("APP_ATTEST_APP_IDS").isEmpty()) {
            add("INTEGRITY_VERIFICATION=enforce needs INTEGRITY_VERIFIER_COMMAND (set in the environment)")
        }
        // Approvals need approvers: personal admin keys other than the requester's
        // (Main refuses to start otherwise). Saved from the dashboard on a server
        // with only a shared API_KEY, this used to pass the save and then stop
        // every start.
        v("PIN_CHANGE_APPROVALS").toIntOrNull()?.takeIf { it > 1 }?.let { required ->
            runCatching { com.example.pinvault.server.plugin.AdminRegistry.fromEnv(effective) }.getOrNull()
                ?.let { admins -> ApprovalService.adminKeysProblem(required, admins) }?.let { add(it) }
        }
        // 0 is off; a fresh key attestation more often than once a minute is refused at start.
        runCatching { com.example.pinvault.server.service.attestation.FreshAttestationSettings.fromEnv { effective[it] } }
            .exceptionOrNull()?.message?.let { add(it) }
    }
}

/**
 * `server-settings.json`: the values saved from the dashboard, and the last
 * set that stopped the server from starting (kept to show why, never applied).
 */
class ServerSettingsStore(private val file: File) {

    @Serializable
    data class Rejected(val values: Map<String, String>, val reason: String, val at: Long)

    @Serializable
    data class Content(
        val values: Map<String, String> = emptyMap(),
        val rejected: Rejected? = null,
        /** Starts in a row that failed while [values] were in force (see [startFailed]); 0 after a start that came up. */
        val failedStarts: Int = 0
    )

    /** What [startFailed] did: which consecutive failure this was, and whether the saved values were set aside. */
    data class FailedStart(val attempt: Int, val setAside: Boolean)

    private val json = Json { ignoreUnknownKeys = true; prettyPrint = true }

    @Synchronized
    fun read(): Content = try {
        if (file.isFile) json.decodeFromString(Content.serializer(), file.readText()) else Content()
    } catch (e: Exception) {
        System.err.println("server-settings.json is unreadable, ignored: ${e.message}")
        Content()
    }

    /** The saved values the catalog still knows and accepts; anything else is dropped. */
    fun values(): Map<String, String> =
        read().values.filter { (k, v) -> ServerSettingsCatalog.find(k)?.let { it.problem(v) == null } == true }

    @Synchronized
    fun save(values: Map<String, String>) = write(read().copy(values = values))

    /** The saved values stopped the server from starting: keep them as [Content.rejected], apply none. */
    @Synchronized
    fun reject(reason: String, now: Long = System.currentTimeMillis()) {
        val current = read()
        write(Content(values = emptyMap(), rejected = Rejected(current.values, reason.take(2000), now)))
    }

    @Synchronized
    fun clearRejected() = write(read().copy(rejected = null))

    /**
     * A start failed while saved values were in force, for a reason the
     * checks made before the start ([SavedSettingsCheck]) did not put on
     * them. Counted: one or two failures (a port still in use, a database
     * that was busy) leave the saved values alone; the [limit]th in a row
     * sets them aside with [reason] — a saved value that stops every start
     * in a way nobody modelled must not keep the server down for good, with
     * no dashboard to undo it. Nothing is counted when no value is saved.
     */
    @Synchronized
    fun startFailed(reason: String, limit: Int = MAX_FAILED_STARTS, now: Long = System.currentTimeMillis()): FailedStart {
        val current = read()
        if (current.values.isEmpty()) return FailedStart(0, false)
        val attempt = current.failedStarts + 1
        if (attempt < limit) {
            write(current.copy(failedStarts = attempt))
            return FailedStart(attempt, false)
        }
        // reject() starts the count again with the values it sets aside.
        reject("$attempt starts in a row failed with these settings in force; the last: $reason", now)
        return FailedStart(attempt, true)
    }

    /** The server came up (its listeners are bound): the failures before it were not the saved values' doing. */
    @Synchronized
    fun startSucceeded() {
        val current = read()
        if (current.failedStarts != 0) write(current.copy(failedStarts = 0))
    }

    private fun write(content: Content) {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(json.encodeToString(Content.serializer(), content))
        if (!tmp.renameTo(file)) {
            file.delete()
            tmp.renameTo(file)
        }
    }

    companion object {
        /** Consecutive failed starts after which the saved values are set aside. */
        const val MAX_FAILED_STARTS = 3

        /** Next to the database: the sample host keeps `/data/db` on a volume. */
        fun forDbPath(dbPath: String): ServerSettingsStore =
            ServerSettingsStore(File(File(dbPath).absoluteFile.parentFile, "server-settings.json"))
    }
}

/**
 * Whether the settings saved from the dashboard would stop the server from
 * starting — asked BEFORE anything is opened or listened on.
 *
 * It is decided by reading the values again with the parsers the start-up
 * uses, once with the saved values laid over the environment and once with
 * the environment alone: what fails only with the saved values is theirs.
 * The start-up used to set the saved values aside after ANY failure while
 * some were saved, so a port in use or a busy database wiped
 * `PIN_CHANGE_APPROVALS=2` along with everything else.
 */
object SavedSettingsCheck {
    /** The start-up's own readers of the settings a bad value stops the start for, by the setting they read. */
    private val startupParsers: List<Pair<String, (Map<String, String>) -> Unit>> = listOf(
        "PIN_CHANGE_APPROVALS" to { env -> ApprovalService.requiredFromEnv(env) },
        "PIN_LIVE_CHECK" to { env -> LiveCertificateGate.modeFromEnv(env) },
        "CONFIG_TTL_SECONDS" to { env -> SignedConfigService.ttlFromEnv(env) },
        "ENROLLMENT_ATTESTATION" to { env -> EnrollmentAttestationMode.parse(env["ENROLLMENT_ATTESTATION"]) },
        "USER_AUTH_ATTESTATION" to { env -> UserAuthAttestationMode.parse(env["USER_AUTH_ATTESTATION"]) },
        "INTEGRITY_VERIFICATION" to { env -> IntegrityVerificationMode.parse(env["INTEGRITY_VERIFICATION"]) },
        "ATTESTATION_KEY_POLICY" to { env -> com.example.pinvault.server.service.attestation.AttestationKeyPolicy.parse(env["ATTESTATION_KEY_POLICY"]) },
        // The package list and the signer digests (ATTESTATION_PACKAGE_NAMES, ATTESTATION_SIGNER_SHA256).
        "ATTESTATION_SIGNER_SHA256" to { env -> AndroidKeyAttestation.fromEnv(env) },
        // The default policy: profile, token lifetime, interval, ATTESTATION_REVEAL_REASONS.
        "ATTESTATION_POLICY_DEFAULT" to { env -> com.example.pinvault.server.service.attestation.AttestationPolicyDefaults.fromEnv(env) }
    )

    /**
     * Why the server would not start with [saved] (`server-settings.json`,
     * as stored), each line naming the setting; empty when the saved values
     * are not what stops it. A setting the environment sets is not looked
     * at: the saved value is not used. A value that is not applied at all
     * ([dropped]) stops nothing either.
     */
    fun problems(
        saved: Map<String, String>,
        env: Map<String, String> = System.getenv(),
        parsers: List<Pair<String, (Map<String, String>) -> Unit>> = startupParsers
    ): List<String> {
        // What ServerSettingsStore.values() applies, where the environment leaves room.
        val applied = saved.filter { (key, value) ->
            env[key].isNullOrBlank() && ServerSettingsCatalog.find(key)?.let { it.problem(value) == null } == true
        }
        val effective = LinkedHashMap(env).apply { putAll(applied) }
        fun failure(of: (Map<String, String>) -> Unit, with: Map<String, String>): String? =
            runCatching { of(with) }.exceptionOrNull()?.let { it.message ?: it.javaClass.simpleName }
        val refused = parsers.mapNotNull { (key, parse) ->
            // A value the environment alone already fails on is the environment's to fix.
            failure(parse, effective)?.takeIf { failure(parse, env) == null }?.let { "$key: $it" }
        }
        return refused + (ServerSettingsCatalog.startProblems(effective) - ServerSettingsCatalog.startProblems(env).toSet())
    }

    /**
     * The saved values that are not applied, one warning each: a key the
     * catalog no longer knows, or a value it no longer accepts (a hand-edited
     * file, a range that changed with an upgrade). Only THAT value is left
     * out — the rest of the saved settings stay in force; one stale number
     * must not take `PIN_CHANGE_APPROVALS=2` down with it.
     */
    fun dropped(saved: Map<String, String>): List<String> = saved.mapNotNull { (key, value) ->
        val setting = ServerSettingsCatalog.find(key) ?: return@mapNotNull "$key: not a setting the dashboard saves (any more); ignored"
        setting.problem(value)?.let { "$key: saved value '${value.take(80)}' $it; ignored, the server default applies" }
    }
}

/**
 * What a `PUT /api/v1/server-settings` body does to the saved values. The
 * route and the approval card (`ChangeDescriber`) both plan with this, so a
 * second admin reads exactly what the handler will save.
 */
class ServerSettingsChange(
    /** The saved values after the change. */
    val saved: Map<String, String>,
    /** Per changed key: the saved value before and after; null = the server default. */
    val changed: Map<String, Pair<String?, String?>>,
    /** Why the body is refused: a key the dashboard may not change, one the environment fixes, a bad value. */
    val errors: List<String>,
    /** Why the server would not start with [saved]; empty while [errors] is not. */
    val startProblems: List<String>
) {
    companion object {
        fun plan(current: Map<String, String>, values: JsonObject, env: Map<String, String> = System.getenv()): ServerSettingsChange {
            val saved = current.toMutableMap()
            val errors = mutableListOf<String>()
            val changed = linkedMapOf<String, Pair<String?, String?>>()
            for ((key, element) in values) {
                val setting = ServerSettingsCatalog.find(key)
                if (setting == null) { errors += "$key: not a setting the dashboard may change"; continue }
                if (ServerEnv.lockedByEnvironment(key)) { errors += "$key: set in the environment; change it there"; continue }
                val value = (element as? JsonPrimitive)?.takeIf { element !is JsonNull }?.contentOrNull?.trim().orEmpty()
                if (value.isEmpty()) {
                    val previous = saved.remove(key)
                    if (previous != null) changed[key] = previous to null
                    continue
                }
                val problem = setting.problem(value)
                if (problem != null) { errors += "$key: $problem"; continue }
                if (saved[key] != value) changed[key] = saved[key] to value
                saved[key] = value
            }
            if (errors.isNotEmpty()) return ServerSettingsChange(current, emptyMap(), errors, emptyList())
            // What the next start reads: the environment, saved values where it is empty.
            val effective = LinkedHashMap(env).apply { saved.forEach { (k, v) -> if (env[k].isNullOrBlank()) put(k, v) } }
            return ServerSettingsChange(saved, changed, emptyList(), ServerSettingsCatalog.startProblems(effective))
        }
    }
}
