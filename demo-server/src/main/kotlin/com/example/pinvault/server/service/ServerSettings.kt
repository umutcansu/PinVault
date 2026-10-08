package com.example.pinvault.server.service

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
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
        ServerSetting("CONFIG_API_ADMIN_ROUTES", "config", ServerSetting.Kind.CHOICE, "on", listOf("on", "off")),
        // Devices and enrollment
        ServerSetting("ENROLLMENT_MODE", "devices", ServerSetting.Kind.CHOICE, "token", listOf("token", "open")),
        ServerSetting("CLIENT_CERT_TTL_DAYS", "devices", ServerSetting.Kind.NUMBER, "90", min = 1, max = 825),
        ServerSetting("HOST_CLIENT_CERT_REQUIRE_GRANT", "devices", ServerSetting.Kind.BOOL, "false"),
        ServerSetting("ENROLLMENT_ATTESTATION", "devices", ServerSetting.Kind.CHOICE, "warn", modes),
        ServerSetting("USER_AUTH_ATTESTATION", "devices", ServerSetting.Kind.CHOICE, "warn", modes),
        ServerSetting("INTEGRITY_VERIFICATION", "devices", ServerSetting.Kind.CHOICE, "off", modes),
        ServerSetting("ATTESTATION_PACKAGE_NAMES", "devices", ServerSetting.Kind.TEXT, "", pattern = packageList),
        ServerSetting("ATTESTATION_SIGNER_SHA256", "devices", ServerSetting.Kind.TEXT, "", pattern = digestList),
        // Attestation (the periodic check of the app and the phone)
        ServerSetting("ATTESTATION_ENABLED", "attestation", ServerSetting.Kind.BOOL, "true"),
        ServerSetting("ATTESTATION_KEY_POLICY", "attestation", ServerSetting.Kind.CHOICE, "warn", modes),
        ServerSetting("ATTESTATION_POLICY_DEFAULT", "attestation", ServerSetting.Kind.CHOICE, "strict", listOf("strict", "lenient")),
        ServerSetting("ATTESTATION_TOKEN_TTL_SECONDS", "attestation", ServerSetting.Kind.NUMBER, "300", min = 30, max = 86_400),
        ServerSetting("ATTESTATION_INTERVAL_SECONDS", "attestation", ServerSetting.Kind.NUMBER, "300", min = 60, max = 86_400),
        ServerSetting("ATTESTATION_REVEAL_REASONS", "attestation", ServerSetting.Kind.BOOL, "false"),
        ServerSetting("MOCK_HOST_REQUIRE_TOKEN", "attestation", ServerSetting.Kind.BOOL, "false"),
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
    data class Content(val values: Map<String, String> = emptyMap(), val rejected: Rejected? = null)

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
        /** Next to the database: the sample host keeps `/data/db` on a volume. */
        fun forDbPath(dbPath: String): ServerSettingsStore =
            ServerSettingsStore(File(File(dbPath).absoluteFile.parentFile, "server-settings.json"))
    }
}
