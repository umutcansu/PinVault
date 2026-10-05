package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import androidx.annotation.VisibleForTesting
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.ssl.PinConfigValidator
import timber.log.Timber
import java.security.MessageDigest

/**
 * A signed config as it arrived: the payload text and its signatures. Kept
 * next to the parsed config so the signatures can be checked again every time
 * the stored config is read (see [CertificateConfigStore.loadEnvelope]).
 */
internal data class StoredEnvelope(val payload: String, val signatures: List<SignatureEntry>)

/**
 * Encrypted local persistence for [CertificateConfig].
 *
 * Stored in [SecurePreferences] (keys in the Android Keystore): pin hashes
 * aren't readable even on rooted devices. Every Config API block keeps its
 * config in `pinvault_secure_config.xml`, in its own namespace, so the
 * library's backup rules cover every block whatever its id.
 *
 * Pins and version watermarks are written as JSON. Earlier versions joined
 * them with `|`, `,`, `=` and line breaks, so a host name carrying one of
 * those characters was read back as a different entry; that format is read
 * once (entries whose host name is not a host name are dropped) and rewritten.
 *
 * The store is opened strict: a Keystore failure surfaces as
 * [io.github.umutcansu.pinvault.model.StoreUnreadableException] from any
 * read, never as "nothing stored". Callers fail closed for that attempt.
 */
internal class CertificateConfigStore private constructor(
    private val prefs: SharedPreferences,
    /**
     * Where the trusted clock's reference lives: the block's own namespace,
     * shared by every origin of the block (see [forOrigin]), so pointing a
     * block at another server never sets its clock back.
     */
    private val clockPrefs: SharedPreferences = prefs
) {

    /** Default constructor — single shared namespace (legacy / single Config API). */
    constructor(context: Context) : this(context, DEFAULT_PREFS_NAME)

    /**
     * V2: per-Config-API namespaced constructor. Each Config API block gets
     * its own namespace ([prefsName]) so pins from different APIs never
     * collide even if they share a hostname.
     *
     * The raw [prefsName] is sanitized — non-alphanumeric chars replaced with
     * underscores — because it is also the name of the file PinVault 2.0.x
     * kept this block's config in; that file is migrated on first open.
     */
    constructor(context: Context, prefsName: String) : this(
        sanitize(prefsName).let { name ->
            SecurePreferences.openStrict(context, FILE_NAME, namespace = name, legacyName = name)
        }
    )

    /** Wall clock, for the expiry given to configs stored by earlier versions. Tests set it. */
    @VisibleForTesting
    internal var clock: () -> Long = System::currentTimeMillis

    fun getCurrentVersion(): Int = prefs.getInt(KEY_VERSION, 0)

    /**
     * The highest [CertificateConfig.issuedAt] this device ever accepted, or 0
     * if no config has ever been saved (or if the stored config predates the
     * freshness-tracking change).
     *
     * Used by the updater to reject replays: a freshly fetched config must
     * have `issuedAt > getCurrentIssuedAt()` before being persisted. It is a
     * watermark, not the active config's value: rolling a config back after
     * a failed health check restores the older pins but never lowers this.
     * Only [resetWatermarks] does.
     */
    fun getCurrentIssuedAt(): Long =
        maxOf(prefs.getLong(KEY_ISSUED_AT, 0L), prefs.getLong(KEY_WATERMARK_ISSUED_AT, 0L))

    /**
     * The highest per-host version this device accepted for each host
     * (lower-case host name), the active config's included. Like
     * [getCurrentIssuedAt], neither a rollback nor a config that drops the
     * host lowers it: a host that was dropped and comes back must come back
     * at its old version or higher.
     */
    fun getVersionWatermarks(): Map<String, Int> {
        val merged = storedWatermarks().toMutableMap()
        storedPins()?.forEach { pin ->
            val host = pin.hostname.lowercase()
            merged[host] = maxOf(merged[host] ?: 0, pin.version)
        }
        return merged
    }

    /**
     * Saves [config] as the active config, with the signed [envelope] it came
     * in (null for an unsigned block, static pins or a custom API without
     * envelopes — such a config has no integrity check when it is read back).
     *
     * No watermark is ever lowered here, whatever is saved: a newly accepted
     * config, a rollback to the previous one after a failed health check, or
     * freshness and flags written back. Hosts missing from [config] keep
     * their version watermark.
     */
    fun save(config: CertificateConfig, envelope: StoredEnvelope? = null) {
        val versions = getVersionWatermarks().toMutableMap()
        config.pins.forEach { pin ->
            val host = pin.hostname.lowercase()
            versions[host] = maxOf(versions[host] ?: 0, pin.version)
        }
        val issuedAtWatermark = maxOf(getCurrentIssuedAt(), config.issuedAt)
        prefs.edit().apply {
            putInt(KEY_VERSION, config.computedVersion())
            putLong(KEY_ISSUED_AT, config.issuedAt)
            putLong(KEY_EXPIRES_AT, config.expiresAt)
            putLong(KEY_WATERMARK_ISSUED_AT, issuedAtWatermark)
            putString(KEY_WATERMARK_VERSIONS_JSON, watermarksJson(versions))
            remove(KEY_WATERMARK_VERSIONS)
            putBoolean(KEY_FORCE_UPDATE, config.forceUpdate)
            putString(KEY_PINS_JSON, pinsJson(config.pins))
            remove(KEY_PINS)
            if (envelope != null) putString(KEY_ENVELOPE, envelopeJson(envelope)) else remove(KEY_ENVELOPE)
            apply()
        }
        Timber.d("Certificate config saved — version: %d, issuedAt: %d, expiresAt: %d, forceUpdate: %s, signed: %b",
            config.computedVersion(), config.issuedAt, config.expiresAt, config.forceUpdate, envelope != null)
    }

    /**
     * The active config as stored, with its `expiresAt` (0 = the config has
     * none: static pins, an unsigned block, a custom API that sets none).
     *
     * This is what the store holds, not yet what may be trusted: for a signed
     * block the updater checks [loadEnvelope] and uses the config inside it.
     *
     * Configs stored by PinVault 2.1.1 and earlier carry no `expiresAt`. They
     * get [LEGACY_LIFETIME_MS] (7 days) from the first time this version loads
     * them, written down so a restart does not extend it. Their `issuedAt` is
     * NOT a usable base: 2.1.1 never wrote it back when the pins stayed the
     * same, so on most upgraded devices it is days or weeks old and
     * `issuedAt + TTL` would already be past — an offline first start after
     * the update would fail closed at once. A successful fetch replaces the
     * estimate with the server's value.
     */
    fun load(): CertificateConfig? {
        val version = prefs.getInt(KEY_VERSION, 0)
        if (version == 0) return null

        val pins = storedPins() ?: return null
        if (pins.isEmpty()) return null

        val issuedAt = prefs.getLong(KEY_ISSUED_AT, 0L)
        val forceUpdate = prefs.getBoolean(KEY_FORCE_UPDATE, false)
        val expiresAt = if (prefs.contains(KEY_EXPIRES_AT)) {
            prefs.getLong(KEY_EXPIRES_AT, 0L)
        } else {
            (clock() + LEGACY_LIFETIME_MS).also { prefs.edit().putLong(KEY_EXPIRES_AT, it).apply() }
        }
        return CertificateConfig(
            version = version,
            pins = pins,
            forceUpdate = forceUpdate,
            issuedAt = issuedAt,
            expiresAt = expiresAt
        ).also {
            Timber.d("Certificate config loaded — version: %d, issuedAt: %d, expiresAt: %d, forceUpdate: %s, %d pins",
                it.version, it.issuedAt, it.expiresAt, it.forceUpdate, it.pins.size)
        }
    }

    /** The signed envelope the active config was saved with, or null when it has none (or it is unreadable as JSON). */
    fun loadEnvelope(): StoredEnvelope? {
        val json = prefs.getString(KEY_ENVELOPE, null) ?: return null
        return try {
            val obj = JsonParser.parseString(json).asJsonObject
            StoredEnvelope(
                payload = obj.get("payload").asString,
                signatures = obj.getAsJsonArray("signatures").map { element ->
                    val entry = element.asJsonObject
                    SignatureEntry(
                        keyId = entry.get("keyId")?.takeUnless { it.isJsonNull }?.asString,
                        signature = entry.get("signature").asString
                    )
                }
            )
        } catch (e: Exception) {
            Timber.w(e, "Stored config envelope is malformed — treating the stored config as unsigned")
            null
        }
    }

    /**
     * Remembers a config that was applied and then rolled back after a failed
     * health check. The updater may apply exactly that config again (it sits
     * at the issuedAt watermark, so it would otherwise look like a replay).
     */
    fun markRolledBack(config: CertificateConfig) {
        prefs.edit()
            .putLong(KEY_ROLLED_BACK_ISSUED_AT, config.issuedAt)
            .putString(KEY_ROLLED_BACK_DIGEST, shapeDigest(config))
            .remove(KEY_ROLLED_BACK_SHAPE)
            .apply()
    }

    /** True when [config] is the config [markRolledBack] recorded. */
    fun isRolledBack(config: CertificateConfig): Boolean =
        config.issuedAt > 0L &&
            prefs.getLong(KEY_ROLLED_BACK_ISSUED_AT, 0L) == config.issuedAt &&
            prefs.getString(KEY_ROLLED_BACK_DIGEST, null) == shapeDigest(config)

    /**
     * Drops the active config (its envelope included) but keeps the
     * watermarks: `PinVault.reset()`, a first config that failed its health
     * check, a stored config that no longer verifies. None of them may leave
     * the replay guard lower than the configs the device has already seen.
     *
     * [keepAsWatermarks] false: the active config's own issuedAt and host
     * versions are NOT made watermarks — for a config dropped because its
     * envelope no longer verifies (tampered, or signed by a key a newer key
     * set revoked: what such a key pushed up must not stick).
     */
    fun clearActive(keepAsWatermarks: Boolean = true) {
        val edit = prefs.edit()
        if (keepAsWatermarks) {
            // The active config's issuedAt and host versions were floors only
            // while it stayed (a config stored by 2.1.x has no watermark keys
            // at all): written down as watermarks before it goes, or the
            // replay guard would start again from zero.
            val issuedAt = getCurrentIssuedAt()
            val versions = storedWatermarks().toMutableMap()
            storedPins(clearIfCorrupt = false)?.forEach { pin ->
                val host = pin.hostname.lowercase()
                versions[host] = maxOf(versions[host] ?: 0, pin.version)
            }
            edit.putLong(KEY_WATERMARK_ISSUED_AT, issuedAt)
                .putString(KEY_WATERMARK_VERSIONS_JSON, watermarksJson(versions))
                .remove(KEY_WATERMARK_VERSIONS)
        }
        edit
            .remove(KEY_VERSION)
            .remove(KEY_PINS)
            .remove(KEY_PINS_JSON)
            .remove(KEY_ISSUED_AT)
            .remove(KEY_EXPIRES_AT)
            .remove(KEY_FORCE_UPDATE)
            .remove(KEY_ENVELOPE)
            .apply()
        Timber.d("Active certificate config cleared (watermarks kept)")
    }

    /**
     * Forgets every replay watermark — the highest `issuedAt`, the per-host
     * versions, the rolled-back marker — and records [keySetVersion] as the
     * signing-key set they were reset for. The one place watermarks go down.
     *
     * Called when a newer recovery-signed signing-key set has been applied:
     * whoever held a signing key that set revokes may have pushed the
     * watermarks far ahead (to lock honest configs out), and must not keep
     * that hold after the revocation. The active config's own values still
     * count as a floor while it stays; the updater drops it when the new set
     * does not vouch for it.
     */
    @android.annotation.SuppressLint("ApplySharedPref")
    fun resetWatermarks(keySetVersion: Int) {
        prefs.edit()
            .remove(KEY_WATERMARK_ISSUED_AT)
            .remove(KEY_WATERMARK_VERSIONS)
            .remove(KEY_WATERMARK_VERSIONS_JSON)
            .remove(KEY_ROLLED_BACK_ISSUED_AT)
            .remove(KEY_ROLLED_BACK_SHAPE)
            .remove(KEY_ROLLED_BACK_DIGEST)
            .putInt(KEY_KEY_SET_VERSION, keySetVersion)
            // commit(): the reset must not be lost to a crash after the key
            // set itself is already on disk.
            .commit()
        Timber.w("Replay watermarks reset for signing-key set v%d", keySetVersion)
    }

    /** The signing-key set version the watermarks were last reset for, or null when none was ever recorded. */
    fun keySetVersionSeen(): Int? =
        if (prefs.contains(KEY_KEY_SET_VERSION)) prefs.getInt(KEY_KEY_SET_VERSION, 0) else null

    /** Records the signing-key set version in force, without touching the watermarks. */
    fun setKeySetVersionSeen(version: Int) {
        prefs.edit().putInt(KEY_KEY_SET_VERSION, version).apply()
    }

    /**
     * The highest wall-clock time this block has observed, Unix ms (see
     * `TrustedClock`). 0 = none yet. Kept per block, not per origin; a value
     * an origin namespace may hold from before is taken into account too.
     */
    fun highestSeenTime(): Long =
        if (clockPrefs === prefs) prefs.getLong(KEY_CLOCK_HIGHEST_SEEN, 0L)
        else maxOf(clockPrefs.getLong(KEY_CLOCK_HIGHEST_SEEN, 0L), prefs.getLong(KEY_CLOCK_HIGHEST_SEEN, 0L))

    fun setHighestSeenTime(timeMs: Long) {
        clockPrefs.edit().putLong(KEY_CLOCK_HIGHEST_SEEN, timeMs).apply()
    }

    /**
     * Fingerprint of the trust anchors (compiled-in signing keys, their
     * threshold, recovery keys) the watermarks were set under, or null when
     * none was recorded yet. See `SSLCertificateUpdater.syncTrustAnchors`.
     */
    fun trustAnchorsSeen(): String? = prefs.getString(KEY_TRUST_ANCHORS, null)

    fun setTrustAnchorsSeen(fingerprint: String) {
        prefs.edit().putString(KEY_TRUST_ANCHORS, fingerprint).commit()
    }

    /** The server (scope or URL) this store's config and watermarks belong to; see [forOrigin]. */
    fun origin(): String? = prefs.getString(KEY_ORIGIN, null)

    /**
     * Wipes everything, watermarks and clock reference included. Not reachable
     * from the public API — `PinVault.reset()` keeps the watermarks — it is
     * for tests and tooling that need a truly clean store.
     */
    @VisibleForTesting
    internal fun wipeAll() {
        prefs.edit().clear().apply()
        Timber.d("Certificate config store wiped")
    }

    // ── Pins ────────────────────────────────────────────────────────────────

    /** The stored pin entries, or null when none are stored. Reads the pre-JSON format once and rewrites it. */
    private fun storedPins(clearIfCorrupt: Boolean = true): List<HostPin>? {
        val json = prefs.getString(KEY_PINS_JSON, null)
        if (json != null) return parsePinsJson(json, clearIfCorrupt)

        val legacy = prefs.getString(KEY_PINS, null) ?: return null
        val pins = parseLegacyPins(legacy)
        prefs.edit().putString(KEY_PINS_JSON, pinsJson(pins)).remove(KEY_PINS).apply()
        Timber.i("Stored pins rewritten as JSON — %d host(s)", pins.size)
        return pins
    }

    private fun pinsJson(pins: List<HostPin>): String = JsonArray().apply {
        pins.forEach { pin ->
            add(JsonObject().apply {
                addProperty("hostname", pin.hostname)
                addProperty("version", pin.version)
                add("sha256", JsonArray().apply { pin.sha256.forEach { add(it) } })
                addProperty("forceUpdate", pin.forceUpdate)
                addProperty("mtls", pin.mtls)
                pin.clientCertVersion?.let { addProperty("clientCertVersion", it) }
            })
        }
    }.toString()

    private fun parsePinsJson(json: String, clearIfCorrupt: Boolean = true): List<HostPin> = try {
        JsonParser.parseString(json).asJsonArray.mapNotNull { element ->
            // Per-entry try/catch so one malformed row only drops that row
            // rather than poisoning the whole cache.
            try {
                val entry = element.asJsonObject
                val hostname = entry.get("hostname").asString
                val hashes = entry.getAsJsonArray("sha256").map { it.asString }
                if (PinConfigValidator.hostPatternError(hostname) != null || hashes.size < 2) {
                    Timber.w("Skipping a stored pin entry that is not valid — other hosts preserved")
                    null
                } else {
                    HostPin(
                        hostname = hostname,
                        sha256 = hashes,
                        version = entry.get("version")?.asInt ?: 0,
                        forceUpdate = entry.get("forceUpdate")?.asBoolean ?: false,
                        mtls = entry.get("mtls")?.asBoolean ?: false,
                        clientCertVersion = entry.get("clientCertVersion")?.takeUnless { it.isJsonNull }?.asInt
                    )
                }
            } catch (e: Exception) {
                Timber.w(e, "Skipping malformed pin entry — other hosts preserved")
                null
            }
        }
    } catch (e: Exception) {
        // Drop the corrupt blob so subsequent loads don't loop on it (L-01).
        // The next fetch repopulates from the backend; in the meantime an
        // empty pin list is fail-safe (DynamicSSLManager refuses connections
        // when no pins are configured). The watermarks stay.
        Timber.e(e, "Failed to parse stored pins — clearing the corrupt config")
        if (clearIfCorrupt) clearActive()
        emptyList()
    }

    /**
     * The format written up to 2.1.x, one entry per line:
     * `hostname|version|hash1,hash2|forceUpdate` (the flag is absent in older
     * entries; `hostname|hash1,hash2` is older still). An entry whose host
     * name is not a host name — which is what an injected entry looks like —
     * is dropped.
     */
    private fun parseLegacyPins(data: String): List<HostPin> =
        data.split(LEGACY_ENTRY_SEPARATOR).mapNotNull { entry ->
            try {
                val parts = entry.split(LEGACY_FIELD_SEPARATOR)
                val pin = when {
                    parts.size >= 3 -> {
                        val hashes = parts[2].split(LEGACY_HASH_SEPARATOR).filter { it.isNotBlank() }
                        // Absent (3-field entry) or unparsable → false, the
                        // fail-safe value: a stale "true" would block an
                        // offline start-up forever.
                        val forceUpdate = parts.getOrNull(3)?.trim()?.toBooleanStrictOrNull() ?: false
                        if (hashes.size >= 2) HostPin(parts[0], hashes, parts[1].toIntOrNull() ?: 0, forceUpdate) else null
                    }
                    parts.size == 2 -> {
                        val hashes = parts[1].split(LEGACY_HASH_SEPARATOR).filter { it.isNotBlank() }
                        if (hashes.size >= 2) HostPin(parts[0], hashes, version = 0) else null
                    }
                    else -> null
                }
                pin?.takeIf { PinConfigValidator.hostPatternError(it.hostname) == null }
            } catch (e: Exception) {
                Timber.w(e, "Skipping malformed pin entry — other hosts preserved")
                null
            }
        }

    // ── Version watermarks ──────────────────────────────────────────────────

    private fun storedWatermarks(): Map<String, Int> {
        val json = prefs.getString(KEY_WATERMARK_VERSIONS_JSON, null)
        if (json != null) {
            return try {
                JsonParser.parseString(json).asJsonObject.entrySet().associate { (host, version) -> host to version.asInt }
            } catch (e: Exception) {
                Timber.e(e, "Stored version watermarks are malformed — ignoring them")
                emptyMap()
            }
        }
        // Up to 2.1.x: one `hostname=version` per line.
        val legacy = prefs.getString(KEY_WATERMARK_VERSIONS, null) ?: return emptyMap()
        val parsed = legacy.split(LEGACY_ENTRY_SEPARATOR).mapNotNull { entry ->
            val host = entry.substringBeforeLast('=', "")
            val version = entry.substringAfterLast('=', "").toIntOrNull()
            if (version == null || PinConfigValidator.hostPatternError(host) != null) null else host.lowercase() to version
        }.toMap()
        prefs.edit().putString(KEY_WATERMARK_VERSIONS_JSON, watermarksJson(parsed)).remove(KEY_WATERMARK_VERSIONS).apply()
        return parsed
    }

    private fun watermarksJson(versions: Map<String, Int>): String =
        JsonObject().apply { versions.forEach { (host, version) -> addProperty(host, version) } }.toString()

    // ── Envelope and rollback marker ────────────────────────────────────────

    private fun envelopeJson(envelope: StoredEnvelope): String = JsonObject().apply {
        addProperty("payload", envelope.payload)
        add("signatures", JsonArray().apply {
            envelope.signatures.forEach { entry ->
                add(JsonObject().apply {
                    entry.keyId?.let { addProperty("keyId", it) }
                    addProperty("signature", entry.signature)
                })
            }
        })
    }.toString()

    /** SHA-256 over the hosts, versions and pin sets of [config], whatever their order. */
    private fun shapeDigest(config: CertificateConfig): String {
        val shape = JsonArray().apply {
            config.pins.sortedBy { it.hostname.lowercase() }.forEach { pin ->
                add(JsonArray().apply {
                    add(pin.hostname.lowercase())
                    add(pin.version)
                    add(JsonArray().apply { pin.sha256.sorted().forEach { add(it) } })
                })
            }
        }.toString()
        return MessageDigest.getInstance("SHA-256").digest(shape.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    }

    companion object {
        /** Keep in sync with res/xml/pinvault_backup_rules.xml and pinvault_data_extraction_rules.xml. */
        internal const val FILE_NAME = "pinvault_secure_config"
        private const val DEFAULT_PREFS_NAME = "ssl_cert_config"

        /** The per-Config-API namespace (and the file name PinVault 2.0.x used). */
        fun prefsNameFor(configApiId: String): String =
            if (configApiId.isBlank()) DEFAULT_PREFS_NAME
            else "ssl_cert_config_$configApiId"

        /** [prefsName] as a namespace and 2.0.x file name: anything but `[A-Za-z0-9_-]` becomes `_`. */
        internal fun sanitize(prefsName: String): String = prefsName.replace(Regex("[^A-Za-z0-9_-]"), "_")

        /** The namespace block [configApiId] keeps its config in (two ids that sanitise alike would share it). */
        internal fun namespaceFor(configApiId: String): String = sanitize(prefsNameFor(configApiId))

        /**
         * The store of block [prefsName] for the server [origin] (its
         * `serverScope`, or its Config API URL): each origin has a namespace
         * of its own, so its config and watermarks never meet another
         * server's version space, and pointing the block back at a server
         * finds that server's watermarks where they were. Nothing is ever
         * wiped on a switch (switching away and back used to wipe the replay
         * guard), and the trusted clock stays in the block's namespace,
         * shared by all its origins. Only the app's compiled configuration
         * decides the origin; nothing a server sends does.
         *
         * The block's namespace itself belongs to the first origin it was
         * bound to — a store of 2.1.x (or 2.0.x, migrated) has none recorded
         * and is claimed by the origin the block has now — and every other
         * origin gets `<namespace>_<first 16 hex of SHA-256(origin)>`.
         */
        fun forOrigin(context: Context, prefsName: String, origin: String): CertificateConfigStore =
            forOrigin(sanitize(prefsName), origin) { namespace, migrateLegacy ->
                SecurePreferences.openStrict(
                    context, FILE_NAME, namespace = namespace, legacyName = namespace.takeIf { migrateLegacy }
                )
            }

        /** [forOrigin] over [open] (namespace, whether to migrate a 2.0.x file of that name) — unit tests. */
        internal fun forOrigin(
            namespace: String,
            origin: String,
            open: (namespace: String, migrateLegacy: Boolean) -> SharedPreferences
        ): CertificateConfigStore {
            val base = open(namespace, true)
            when (base.getString(KEY_ORIGIN, null)) {
                origin -> return CertificateConfigStore(base)
                null -> {
                    base.edit().putString(KEY_ORIGIN, origin).commit()
                    return CertificateConfigStore(base)
                }
            }
            val own = open(originNamespace(namespace, origin), false)
            if (own.getString(KEY_ORIGIN, null) == null) own.edit().putString(KEY_ORIGIN, origin).commit()
            Timber.d("Config store: block bound to another server than its first — using that server's own namespace")
            return CertificateConfigStore(own, clockPrefs = base)
        }

        internal fun originNamespace(namespace: String, origin: String): String =
            namespace + "_" + MessageDigest.getInstance("SHA-256").digest(origin.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it.toInt() and 0xFF) }.take(16)

        internal const val KEY_VERSION = "config_version"
        /** Pins in the pre-JSON format; read once, then replaced by [KEY_PINS_JSON]. */
        internal const val KEY_PINS = "config_pins"
        internal const val KEY_PINS_JSON = "config_pins_json"
        internal const val KEY_ISSUED_AT = "config_issued_at"
        internal const val KEY_FORCE_UPDATE = "config_force_update"
        internal const val KEY_EXPIRES_AT = "config_expires_at"
        internal const val KEY_ENVELOPE = "config_envelope"
        internal const val KEY_WATERMARK_ISSUED_AT = "watermark_issued_at"
        /** Version watermarks in the pre-JSON format; read once, then replaced by [KEY_WATERMARK_VERSIONS_JSON]. */
        internal const val KEY_WATERMARK_VERSIONS = "watermark_versions"
        internal const val KEY_WATERMARK_VERSIONS_JSON = "watermark_versions_json"
        internal const val KEY_ROLLED_BACK_ISSUED_AT = "rolled_back_issued_at"
        /** The pre-JSON rollback marker; no longer read. */
        internal const val KEY_ROLLED_BACK_SHAPE = "rolled_back_shape"
        internal const val KEY_ROLLED_BACK_DIGEST = "rolled_back_digest"
        internal const val KEY_KEY_SET_VERSION = "watermarks_key_set_version"
        internal const val KEY_CLOCK_HIGHEST_SEEN = "clock_highest_seen"
        /** The server (scope or Config API URL) the stored config and watermarks belong to. See [forOrigin]. */
        internal const val KEY_ORIGIN = "config_origin"
        /** Fingerprint of the compiled-in trust anchors the watermarks were set under. See [trustAnchorsSeen]. */
        internal const val KEY_TRUST_ANCHORS = "watermarks_trust_anchors"

        /**
         * Lifetime given to a config stored before expiresAt was kept, counted
         * from the first load by this version: long enough for an upgraded
         * device that is offline for a while to reach the server once.
         */
        internal const val LEGACY_LIFETIME_MS = 7L * 24 * 60 * 60 * 1000
        private const val LEGACY_ENTRY_SEPARATOR = "\n"
        private const val LEGACY_FIELD_SEPARATOR = "|"
        private const val LEGACY_HASH_SEPARATOR = ","

        @VisibleForTesting
        internal fun createForTest(prefs: SharedPreferences) = CertificateConfigStore(prefs)
    }
}
