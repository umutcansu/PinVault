package io.github.umutcansu.pinvault.reactnative

import android.content.Context
import android.content.pm.ApplicationInfo
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import java.io.FileNotFoundException
import java.io.IOException

/**
 * The app's native security file: the trust anchors and relaxations of
 * `start(config)` declared outside the JS bundle, which an OTA update
 * (CodePush, Expo Updates) or an edited bundle can change. The file ships in
 * the APK (`src/main/assets/pinvault_security.json`, or a build type's own
 * `src/release/assets/`), which the APK signature seals.
 *
 * ```json
 * {
 *   "configApis": [{
 *     "id": "default-tls",
 *     "bootstrapPins": [{ "hostname": "api.example.com", "sha256": ["…", "…"] }],
 *     "signaturePublicKeys": ["…", "…"], "requiredSignatures": 2,
 *     "recoveryPublicKeys": ["…"], "requiredRecoverySignatures": 1,
 *     "serverScope": "default-tls", "clientCaPins": ["…"],
 *     "allowUnsigned": false, "allowUnpinnedConfigApi": false, "allowServerGeneratedKey": false
 *   }],
 *   "staticPins": { "pins": [ … ], "version": 1 }
 * }
 * ```
 *
 * When the file is there ([apply]):
 * - every Config API of the JS config must be declared in it (an OTA update
 *   cannot add a block with keys of its own), and JS `staticPins` must be
 *   declared too;
 * - a field the file declares is the value: JS may leave it out or repeat it,
 *   a different value is refused (`E_INVALID_CONFIG`);
 * - `allowUnsigned`, `allowUnpinnedConfigApi`, `allowServerGeneratedKey` from
 *   JS are refused unless the file allows them for that block.
 *
 * Without the file, release builds (the app is not debuggable) refuse those
 * three relaxations from JS; debug builds take them as before.
 */
internal class NativeSecurity(
    /** Where the file came from, for messages. */
    val source: String,
    val blocks: Map<String, Block>,
    val staticPins: CertificateConfig?,
) {

    class Block(
        val bootstrapPins: List<HostPin>?,
        val signaturePublicKeys: List<String>?,
        val requiredSignatures: Int?,
        val recoveryPublicKeys: List<String>?,
        val requiredRecoverySignatures: Int?,
        val serverScope: String?,
        val clientCaPins: List<String>?,
        val allowUnsigned: Boolean,
        val allowUnpinnedConfigApi: Boolean,
        val allowServerGeneratedKey: Boolean,
    )

    companion object {
        const val ASSET_NAME = "pinvault_security.json"
        private const val MAX_FILE_CHARS = 256 * 1024

        /** The file from the app's assets; null when the app ships none. A broken file throws [BridgeInputException]. */
        fun load(context: Context): NativeSecurity? {
            val text = try {
                context.assets.open(ASSET_NAME).bufferedReader(Charsets.UTF_8).use { it.readText() }
            } catch (_: FileNotFoundException) {
                return null
            } catch (e: IOException) {
                // There, but unreadable: fail closed.
                throw BridgeInputException("native security file assets/$ASSET_NAME: cannot be read (${e.javaClass.simpleName})")
            }
            return parse(text, "assets/$ASSET_NAME")
        }

        /** True for a release build of the app (not `android:debuggable`). */
        fun isReleaseBuild(context: Context): Boolean =
            (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) == 0

        fun parse(text: String, source: String): NativeSecurity {
            val root = try {
                StrictJson.parseObject(text, source, maxChars = MAX_FILE_CHARS)
            } catch (e: BridgeInputException) {
                throw BridgeInputException("native security file ${e.message}")
            }
            val blocks = LinkedHashMap<String, Block>()
            try {
                root.objList("configApis", ConfigParser.MAX_CONFIG_APIS)?.forEach { b ->
                    val id = b.requireString("id", 128)
                    if (id in blocks) throw BridgeInputException("${b.path}.id: '$id' is declared twice")
                    blocks[id] = Block(
                        bootstrapPins = b.objList("bootstrapPins", ConfigParser.MAX_PINS)?.map(ConfigParser::hostPin),
                        signaturePublicKeys = b.stringList("signaturePublicKeys", 16, ConfigParser.KEY_LENGTH, multiline = true),
                        requiredSignatures = b.int("requiredSignatures", 1, 16),
                        recoveryPublicKeys = b.stringList("recoveryPublicKeys", 16, ConfigParser.KEY_LENGTH, multiline = true),
                        requiredRecoverySignatures = b.int("requiredRecoverySignatures", 1, 16),
                        serverScope = b.string("serverScope", 128),
                        clientCaPins = b.stringList("clientCaPins", 16, 128),
                        allowUnsigned = b.bool("allowUnsigned") == true,
                        allowUnpinnedConfigApi = b.bool("allowUnpinnedConfigApi") == true,
                        allowServerGeneratedKey = b.bool("allowServerGeneratedKey") == true,
                    )
                    b.finish()
                }
                val staticPins = root.obj("staticPins")?.let(ConfigParser::staticPins)
                root.finish()
                if (blocks.isEmpty() && staticPins == null) {
                    throw BridgeInputException("$source: declares neither configApis nor staticPins")
                }
                return NativeSecurity(source, blocks, staticPins)
            } catch (e: BridgeInputException) {
                val message = e.message ?: ""
                throw BridgeInputException(if (message.startsWith("native security file")) message else "native security file $message")
            } catch (e: IllegalArgumentException) {
                // A builder / constructor rule (two pins per host, …).
                throw BridgeInputException("native security file $source: ${e.message}")
            }
        }

        // ── Comparison (order of lists does not matter) ─────────────────────

        fun sameKeys(a: List<String>, b: List<String>): Boolean = a.map(String::trim).toSet() == b.map(String::trim).toSet()

        private fun pinKey(p: HostPin) =
            listOf(p.hostname.lowercase(), p.sha256.sorted().joinToString(","), p.version, p.forceUpdate, p.mtls, p.clientCertVersion)
                .joinToString("|")

        fun samePins(a: List<HostPin>, b: List<HostPin>): Boolean = a.map(::pinKey).sorted() == b.map(::pinKey).sorted()

        fun sameStaticPins(a: CertificateConfig, b: CertificateConfig): Boolean =
            a.version == b.version && a.forceUpdate == b.forceUpdate && samePins(a.pins, b.pins)
    }
}

/** What JS asked for in one `configApis[i]` entry, before the native policy is applied. */
internal class SecurityFields(
    val bootstrapPins: List<HostPin>?,
    /** `signaturePublicKey` (one) or `signaturePublicKeys`; never both. */
    val oneKey: String?,
    val keys: List<String>?,
    val requiredSignatures: Int?,
    val recoveryKeys: List<String>?,
    val requiredRecovery: Int?,
    val serverScope: String?,
    val clientCaPins: List<String>?,
    val allowUnsigned: Boolean,
    val allowUnpinned: Boolean,
    val allowServerKey: Boolean,
)

/** The native policy applied to one block: the values that go to the builder, or a refusal. */
internal object SecurityPolicy {

    private const val RELAXATIONS_HINT =
        "a release build takes it only from the app's native security file (assets/${NativeSecurity.ASSET_NAME}, README \"Native security file\")"

    fun apply(path: String, id: String, js: SecurityFields, native: NativeSecurity?, release: Boolean): SecurityFields {
        if (native == null) {
            if (release) {
                if (js.allowUnsigned) throw BridgeInputException("$path.allowUnsigned: refused from JS; $RELAXATIONS_HINT")
                if (js.allowUnpinned) throw BridgeInputException("$path.allowUnpinnedConfigApi: refused from JS; $RELAXATIONS_HINT")
                if (js.allowServerKey) throw BridgeInputException("$path.allowServerGeneratedKey: refused from JS; $RELAXATIONS_HINT")
            }
            return js
        }
        val block = native.blocks[id]
            ?: throw BridgeInputException("$path: Config API '$id' is not declared in the app's native security file (${native.source})")

        fun fixed(key: String): Nothing =
            throw BridgeInputException("$path.$key: differs from the app's native security file (${native.source}); the native value is fixed")

        fun relaxation(key: String, js: Boolean, allowed: Boolean) {
            if (js && !allowed) throw BridgeInputException("$path.$key: refused; the app's native security file (${native.source}) does not allow it")
        }
        relaxation("allowUnsigned", js.allowUnsigned, block.allowUnsigned)
        relaxation("allowUnpinnedConfigApi", js.allowUnpinned, block.allowUnpinnedConfigApi)
        relaxation("allowServerGeneratedKey", js.allowServerKey, block.allowServerGeneratedKey)

        val pins = block.bootstrapPins?.also { n ->
            if (js.bootstrapPins != null && !NativeSecurity.samePins(js.bootstrapPins, n)) fixed("bootstrapPins")
        } ?: js.bootstrapPins

        val oneKey = js.oneKey
        var keys = js.keys
        block.signaturePublicKeys?.let { n ->
            val jsKeys = js.oneKey?.let { listOf(it) } ?: js.keys
            if (jsKeys == null) {
                keys = n
            } else if (!NativeSecurity.sameKeys(jsKeys, n)) {
                fixed(if (js.oneKey != null) "signaturePublicKey" else "signaturePublicKeys")
            }
        }

        fun <T> one(key: String, nativeValue: T?, jsValue: T?): T? {
            if (nativeValue == null) return jsValue
            if (jsValue != null && jsValue != nativeValue) fixed(key)
            return nativeValue
        }

        fun list(key: String, nativeValue: List<String>?, jsValue: List<String>?): List<String>? {
            if (nativeValue == null) return jsValue
            if (jsValue != null && !NativeSecurity.sameKeys(jsValue, nativeValue)) fixed(key)
            return nativeValue
        }

        return SecurityFields(
            bootstrapPins = pins,
            oneKey = oneKey,
            keys = keys,
            requiredSignatures = one("requiredSignatures", block.requiredSignatures, js.requiredSignatures),
            recoveryKeys = list("recoveryPublicKeys", block.recoveryPublicKeys, js.recoveryKeys),
            requiredRecovery = one("requiredRecoverySignatures", block.requiredRecoverySignatures, js.requiredRecovery),
            serverScope = one("serverScope", block.serverScope, js.serverScope),
            clientCaPins = list("clientCaPins", block.clientCaPins, js.clientCaPins),
            // The file is the source of truth for the relaxations too.
            allowUnsigned = block.allowUnsigned,
            allowUnpinned = block.allowUnpinnedConfigApi,
            allowServerKey = block.allowServerGeneratedKey,
        )
    }

    /** JS `staticPins` against the file: declared there or refused; the file's apply when JS has none. */
    fun staticPins(path: String, js: CertificateConfig?, native: NativeSecurity?): CertificateConfig? {
        if (native == null) return js
        val n = native.staticPins
        if (n == null) {
            if (js != null) throw BridgeInputException("$path: not declared in the app's native security file (${native.source})")
            return null
        }
        if (js != null && !NativeSecurity.sameStaticPins(js, n)) {
            throw BridgeInputException("$path: differs from the app's native security file (${native.source}); the native value is fixed")
        }
        return n
    }
}
