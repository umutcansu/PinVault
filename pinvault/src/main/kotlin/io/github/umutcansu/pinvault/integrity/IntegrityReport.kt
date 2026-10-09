package io.github.umutcansu.pinvault.integrity

import org.json.JSONArray
import org.json.JSONObject

/**
 * One probe's finding: whether the flag is raised and what was seen. A probe
 * that could not run is raised with `error:<probe>` evidence: "could not
 * look" is never "clean" (an attacker who makes a probe throw must not get a
 * clean report), and the evidence tells the server it was an error.
 */
internal class Signal(val flag: Boolean, val evidence: List<String> = emptyList()) {
    fun toJson(): JSONObject = JSONObject().put("flag", flag).put("evidence", JSONArray(evidence))

    companion object {
        val CLEAN = Signal(false)
        fun raised(vararg evidence: String) = Signal(true, evidence.toList())
        fun error(probe: String) = Signal(true, listOf("error:$probe"))
    }
}

/** The `app` block of the report (`ATTESTATION.md` §3). */
internal class AppInfo(
    val packageName: String,
    val versionCode: Long,
    val versionName: String?,
    /** SHA-256 of each signing certificate, lowercase hex without separators. */
    val signerSha256: List<String>,
    val installer: String?,
    val debuggable: Boolean
) {
    fun toJson(): JSONObject = JSONObject()
        .put("packageName", packageName)
        .put("versionCode", versionCode)
        .put("versionName", versionName ?: JSONObject.NULL)
        .put("signerSha256", JSONArray(signerSha256.map(::colonHex)))
        .put("installer", installer ?: JSONObject.NULL)
        .put("debuggable", debuggable)
}

/** The `device` block of the report (`ATTESTATION.md` §3). */
internal class DeviceInfo(
    val manufacturer: String,
    val model: String,
    val brand: String,
    val device: String,
    val product: String,
    val hardware: String,
    val fingerprint: String,
    val sdkInt: Int,
    val securityPatch: String?,
    val verifiedBootState: String?,
    /** [io.github.umutcansu.pinvault.model.KeySecurityLevel.wireName] of the device key. */
    val keySecurityLevel: String,
    val keyAttested: Boolean
) {
    fun toJson(): JSONObject = JSONObject()
        .put("manufacturer", manufacturer)
        .put("model", model)
        .put("brand", brand)
        .put("device", device)
        .put("product", product)
        .put("hardware", hardware)
        .put("fingerprint", fingerprint)
        .put("sdkInt", sdkInt)
        .put("securityPatch", securityPatch ?: JSONObject.NULL)
        .put("verifiedBootState", verifiedBootState ?: JSONObject.NULL)
        .put("keySecurityLevel", keySecurityLevel)
        .put("keyAttested", keyAttested)
}

/**
 * The report the library signs and sends with an attestation request —
 * exactly the shape of `ATTESTATION.md` §3. Built by [DeviceIntegrityProbe];
 * serialised once with [toJsonString], and that string is what is sent and
 * hashed into the canonical string, so there is no canonicalisation.
 */
internal class IntegrityReport(
    val sdkVersion: String,
    val reportTime: Long,
    val app: AppInfo,
    val device: DeviceInfo,
    /** One entry per [SIGNAL_KEYS], in that order. */
    val signals: Map<String, Signal>,
    val verdict: IntegrityVerdict?
) {
    fun toJson(): JSONObject {
        val signalsJson = JSONObject()
        // Every key of §3 is present, raised or not: a missing key would read
        // as "not probed" on the server.
        SIGNAL_KEYS.forEach { key -> signalsJson.put(key, (signals[key] ?: Signal.error(key)).toJson()) }
        val json = JSONObject()
            .put("sdkVersion", sdkVersion)
            .put("reportTime", reportTime)
            .put("app", app.toJson())
            .put("device", device.toJson())
            .put("signals", signalsJson)
        verdict?.let { json.put("verdictProvider", JSONObject().put("name", it.name).put("token", it.token)) }
        return json
    }

    fun toJsonString(): String = toJson().toString()

    companion object {
        /** The library version the report names. */
        const val SDK_VERSION = "2.4.1"

        const val ROOTED = "rooted"
        const val EMULATOR = "emulator"
        const val DEBUGGER = "debugger"
        const val DEBUGGABLE = "debuggable"
        const val HOOKING_FRAMEWORK = "hooking_framework"
        const val APP_INTEGRITY = "app_integrity"
        const val CLONER = "cloner"
        const val UNKNOWN_INSTALLER = "unknown_installer"
        const val ADB_ENABLED = "adb_enabled"
        const val SOFTWARE_KEY = "software_key"
        const val KEY_UNATTESTED = "key_unattested"
        /** Decided by the server from `device.securityPatch`; the client always sends it down. */
        const val OLD_PATCH_LEVEL = "old_patch_level"

        /** The signal keys of `ATTESTATION.md` §3, in report order. */
        val SIGNAL_KEYS: List<String> = listOf(
            ROOTED, EMULATOR, DEBUGGER, DEBUGGABLE, HOOKING_FRAMEWORK, APP_INTEGRITY, CLONER,
            UNKNOWN_INSTALLER, ADB_ENABLED, SOFTWARE_KEY, KEY_UNATTESTED, OLD_PATCH_LEVEL
        )
    }
}

/** `3c4f…` → `3c:4f:…`, the form the report shows signer digests in. */
internal fun colonHex(hex: String): String = hex.chunked(2).joinToString(":")

/** Lowercase hex of [bytes], no separators. */
internal fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

/**
 * A signer digest as the app may pass it — with or without colons, any case,
 * an optional `sha256:` prefix — normalised to lowercase hex without
 * separators; null when it is not 32 bytes of hex.
 */
internal fun normalizeSha256Hex(value: String): String? {
    val cleaned = value.trim().removePrefix("sha256:").removePrefix("SHA256:").replace(":", "").lowercase()
    return cleaned.takeIf { it.length == 64 && it.all { c -> c in '0'..'9' || c in 'a'..'f' } }
}
