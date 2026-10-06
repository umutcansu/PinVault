package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.SignatureEntry
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import androidx.test.core.app.ApplicationProvider

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class CertificateConfigStoreTest {

    private lateinit var prefs: SharedPreferences
    private lateinit var store: CertificateConfigStore

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        prefs = context.getSharedPreferences("test_cert_config", Context.MODE_PRIVATE)
        prefs.edit().clear().apply()
        store = CertificateConfigStore.createForTest(prefs)
    }

    @Test
    fun `managed trust roots are stored with the config, cleared with it, and malformed entries dropped`() {
        val rootA = "A".repeat(43) + "="
        val rootB = "B".repeat(43) + "="
        val config = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("api.example.com", listOf("hash1aaa", "hash2bbb"), version = 1)),
            trustRoots = listOf(rootA, rootB)
        )
        store.save(config)
        assertEquals(listOf(rootA, rootB), store.load()!!.trustRoots)

        // A config without roots removes them.
        store.save(config.copy(trustRoots = emptyList()))
        assertEquals(emptyList<String>(), store.load()!!.trustRoots)

        // Something that is not a pin in the stored list is ignored, not returned.
        store.save(config)
        prefs.edit().putString(CertificateConfigStore.KEY_TRUST_ROOTS_JSON, """["$rootA","garbage"]""").apply()
        assertEquals(listOf(rootA), store.load()!!.trustRoots)

        store.clearActive()
        assertNull(store.load())
        assertFalse(prefs.contains(CertificateConfigStore.KEY_TRUST_ROOTS_JSON))
    }

    @Test
    fun `save and load round-trip -- single host`() {
        val config = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("api.example.com", listOf("hash1aaa", "hash2bbb"), version = 1)
            )
        )

        store.save(config)
        val loaded = store.load()

        assertNotNull(loaded)
        assertEquals(1, loaded!!.pins.size)
        assertEquals("api.example.com", loaded.pins[0].hostname)
        assertEquals(listOf("hash1aaa", "hash2bbb"), loaded.pins[0].sha256)
        assertEquals(1, loaded.pins[0].version)
    }

    @Test
    fun `save and load round-trip -- multiple hosts`() {
        val config = CertificateConfig(
            version = 3,
            pins = listOf(
                HostPin("api.example.com", listOf("h1", "h2"), version = 1),
                HostPin("cdn.example.com", listOf("h3", "h4"), version = 2),
                HostPin("auth.example.com", listOf("h5", "h6"), version = 3)
            )
        )

        store.save(config)
        val loaded = store.load()

        assertNotNull(loaded)
        assertEquals(3, loaded!!.pins.size)
        assertEquals("api.example.com", loaded.pins[0].hostname)
        assertEquals("cdn.example.com", loaded.pins[1].hostname)
        assertEquals("auth.example.com", loaded.pins[2].hostname)
    }

    @Test
    fun `load returns null when nothing saved`() {
        assertNull(store.load())
    }

    @Test
    fun `getCurrentVersion returns 0 when empty`() {
        assertEquals(0, store.getCurrentVersion())
    }

    @Test
    fun `getCurrentVersion reflects saved config version`() {
        val config = CertificateConfig(
            version = 5,
            pins = listOf(
                HostPin("api.example.com", listOf("h1", "h2"), version = 5)
            )
        )

        store.save(config)
        assertEquals(5, store.getCurrentVersion())
    }

    @Test
    fun `wipeAll removes all data`() {
        val config = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("api.example.com", listOf("h1", "h2"), version = 1)
            )
        )

        store.save(config)
        assertNotNull(store.load())

        store.wipeAll()
        assertNull(store.load())
        assertEquals(0, store.getCurrentVersion())
    }

    @Test
    fun `save overwrites previous config`() {
        val v1 = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("old.example.com", listOf("h1", "h2"), version = 1))
        )
        val v2 = CertificateConfig(
            version = 2,
            pins = listOf(HostPin("new.example.com", listOf("h3", "h4"), version = 2))
        )

        store.save(v1)
        store.save(v2)

        val loaded = store.load()
        assertNotNull(loaded)
        assertEquals(1, loaded!!.pins.size)
        assertEquals("new.example.com", loaded.pins[0].hostname)
        assertEquals(2, store.getCurrentVersion())
    }

    @Test
    fun `backward compatible parsing -- old format`() {
        // Old format: hostname|hash1,hash2 (no version field)
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 1)
            .putString(CertificateConfigStore.KEY_PINS, "api.example.com|hashA,hashB")
            .apply()

        val loaded = store.load()
        assertNotNull(loaded)
        assertEquals(1, loaded!!.pins.size)
        assertEquals("api.example.com", loaded.pins[0].hostname)
        assertEquals(listOf("hashA", "hashB"), loaded.pins[0].sha256)
        assertEquals(0, loaded.pins[0].version) // old format defaults to version 0
    }

    @Test
    fun `malformed data returns null`() {
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 1)
            .putString(CertificateConfigStore.KEY_PINS, "")
            .apply()

        assertNull(store.load())
    }

    @Test
    fun `single hash host is filtered out`() {
        // Write entry with only 1 hash (HostPin requires >= 2)
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 1)
            .putString(CertificateConfigStore.KEY_PINS, "api.example.com|1|singlehash")
            .apply()

        // Should filter out the host since it has only 1 hash
        assertNull(store.load())
    }

    @Test
    fun `forceUpdate flag survives save and load`() {
        // Regression: save() used to drop forceUpdate, load() hardcoded it to
        // false. A restart then defeated the backend's revocation guarantee.
        val config = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("api.example.com", listOf("h1", "h2"), version = 1)),
            forceUpdate = true
        )

        store.save(config)
        val loaded = store.load()

        assertNotNull(loaded)
        assertTrue(
            "forceUpdate=true lost on round-trip — restart bypass regression",
            loaded!!.forceUpdate
        )
    }

    @Test
    fun `forceUpdate defaults to false when absent from prefs`() {
        // Old encrypted stores written before the flag was persisted should
        // still load — silent migration via getBoolean default.
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 1)
            .putString(CertificateConfigStore.KEY_PINS, "api.example.com|1|h1,h2")
            .apply()

        val loaded = store.load()

        assertNotNull(loaded)
        assertFalse("legacy entries without KEY_FORCE_UPDATE should load with false", loaded!!.forceUpdate)
    }

    @Test
    fun `per-host forceUpdate flag survives save and load`() {
        // Needed by the updater's change detection: "the operator switched
        // force off" can only be spotted if the stored copy remembers that it
        // was on (D04). Before this field was persisted, load() always
        // reported false and the comparison was a no-op.
        val config = CertificateConfig(
            version = 2,
            pins = listOf(
                HostPin("forced.example.com", listOf("h1", "h2"), version = 2, forceUpdate = true),
                HostPin("normal.example.com", listOf("h3", "h4"), version = 1, forceUpdate = false)
            )
        )

        store.save(config)
        val loaded = store.load()

        assertNotNull(loaded)
        val byHost = loaded!!.pins.associateBy { it.hostname }
        assertTrue("per-host forceUpdate=true lost on round-trip", byHost.getValue("forced.example.com").forceUpdate)
        assertFalse("per-host forceUpdate=false must stay false", byHost.getValue("normal.example.com").forceUpdate)
        // The other fields must be unaffected by the new trailing field.
        assertEquals(listOf("h1", "h2"), byHost.getValue("forced.example.com").sha256)
        assertEquals(2, byHost.getValue("forced.example.com").version)
    }

    @Test
    fun `entries written before the forceUpdate field still load`() {
        // Upgrading the library must not invalidate an existing store: rows
        // written in the 3-field format load with forceUpdate=false, which is
        // also the fail-safe value (a stale true would block offline start-up).
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 2)
            .putString(
                CertificateConfigStore.KEY_PINS,
                "legacy.example.com|2|oldA,oldB\n" +
                "fresh.example.com|1|newA,newB|true"
            )
            .apply()

        val loaded = store.load()

        assertNotNull(loaded)
        val byHost = loaded!!.pins.associateBy { it.hostname }
        assertEquals(2, byHost.size)
        assertEquals(listOf("oldA", "oldB"), byHost.getValue("legacy.example.com").sha256)
        assertFalse("3-field legacy row must default to false", byHost.getValue("legacy.example.com").forceUpdate)
        assertTrue("4-field row must keep its flag", byHost.getValue("fresh.example.com").forceUpdate)
    }

    @Test
    fun `single malformed entry does not poison the rest of the cache`() {
        // Regression: the outer try/catch around parsePins used to wipe the
        // whole prefs blob if *any* entry threw — most often a host shipped
        // with a single pin (HostPin's init requires >= 2). One sysadmin
        // misconfiguration could empty every cached host's pins and force a
        // full bootstrap refetch on every load.
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 5)
            .putString(
                CertificateConfigStore.KEY_PINS,
                "good.example.com|2|goodPinA,goodPinB\n" +
                "bad.example.com|3|loneHash\n" +                  // single pin -> HostPin throws
                "another.example.com|4|anotherA,anotherB"
            )
            .apply()

        val loaded = store.load()

        assertNotNull("good rows must still load even if one entry is malformed", loaded)
        val hostnames = loaded!!.pins.map { it.hostname }
        assertTrue("good.example.com lost: $hostnames", "good.example.com" in hostnames)
        assertTrue("another.example.com lost: $hostnames", "another.example.com" in hostnames)
        assertFalse("malformed bad.example.com must be dropped: $hostnames", "bad.example.com" in hostnames)
    }

    @Test
    fun `computedVersion uses max of host versions`() {
        val config = CertificateConfig(
            version = 0,
            pins = listOf(
                HostPin("a.com", listOf("h1", "h2"), version = 2),
                HostPin("b.com", listOf("h3", "h4"), version = 7),
                HostPin("c.com", listOf("h5", "h6"), version = 3)
            )
        )

        store.save(config)
        assertEquals(7, store.getCurrentVersion())
    }

    // ── expiresAt and watermarks (Y1) ───────────────────────────────────

    private fun hostConfig(version: Int, issuedAt: Long, expiresAt: Long = 0L, hosts: List<String> = listOf("a.com")) =
        CertificateConfig(
            version = version,
            pins = hosts.map { HostPin(it, listOf("h1", "h2"), version = version) },
            issuedAt = issuedAt,
            expiresAt = expiresAt
        )

    @Test
    fun `expiresAt survives save and load`() {
        store.save(hostConfig(1, issuedAt = 1_000L, expiresAt = 9_000L))
        assertEquals(9_000L, store.load()!!.expiresAt)

        store.save(hostConfig(2, issuedAt = 2_000L, expiresAt = 0L))
        assertEquals("0 = no expiry, kept as such", 0L, store.load()!!.expiresAt)
    }

    @Test
    fun `config stored before expiresAt was kept gets seven days from its first load, whatever its issuedAt`() {
        // 2.1.1 never wrote issuedAt back for unchanged pins: it is often weeks old.
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 3)
            .putString(CertificateConfigStore.KEY_PINS, "a.com|3|h1,h2|false")
            .putLong(CertificateConfigStore.KEY_ISSUED_AT, 1_000_000L)
            .apply()
        val firstLoad = 1_000_000L + 30L * 24 * 3_600_000
        store.clock = { firstLoad }

        assertEquals(7L * 24 * 3_600_000, CertificateConfigStore.LEGACY_LIFETIME_MS)
        assertEquals(firstLoad + CertificateConfigStore.LEGACY_LIFETIME_MS, store.load()!!.expiresAt)
        store.clock = { firstLoad + 3_600_000 }
        assertEquals("a restart does not extend it", firstLoad + CertificateConfigStore.LEGACY_LIFETIME_MS, store.load()!!.expiresAt)
        assertEquals("issuedAt itself is kept", 1_000_000L, store.load()!!.issuedAt)
    }

    @Test
    fun `config stored before expiresAt without issuedAt gets seven days from its first load`() {
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 3)
            .putString(CertificateConfigStore.KEY_PINS, "a.com|3|h1,h2|false")
            .apply()
        store.clock = { 5_000_000L }

        assertEquals(5_000_000L + CertificateConfigStore.LEGACY_LIFETIME_MS, store.load()!!.expiresAt)
        store.clock = { 9_000_000L }
        assertEquals("a restart does not extend it", 5_000_000L + CertificateConfigStore.LEGACY_LIFETIME_MS, store.load()!!.expiresAt)
    }

    @Test
    fun `saving an older config without lowering the watermarks`() {
        store.save(hostConfig(5, issuedAt = 2_000L, hosts = listOf("a.com", "b.com")))
        store.save(hostConfig(4, issuedAt = 1_000L))

        assertEquals(4, store.load()!!.pins.single().version)
        assertEquals(2_000L, store.getCurrentIssuedAt())
        assertEquals(mapOf("a.com" to 5, "b.com" to 5), store.getVersionWatermarks())
    }

    @Test
    fun `a host the server dropped keeps its version watermark`() {
        // It used to be forgotten: drop the host, add it again at any version
        // (Int.MAX_VALUE included), and nothing compared the two.
        store.save(hostConfig(5, issuedAt = 2_000L, hosts = listOf("a.com", "b.com")))
        store.save(hostConfig(6, issuedAt = 3_000L))

        assertEquals(mapOf("a.com" to 6, "b.com" to 5), store.getVersionWatermarks())
    }

    @Test
    fun `clearActive keeps the watermarks, wipeAll does not`() {
        store.save(hostConfig(5, issuedAt = 2_000L))
        store.clearActive()

        assertNull(store.load())
        assertEquals(2_000L, store.getCurrentIssuedAt())
        assertEquals(mapOf("a.com" to 5), store.getVersionWatermarks())

        store.wipeAll()
        assertEquals(0L, store.getCurrentIssuedAt())
        assertTrue(store.getVersionWatermarks().isEmpty())
    }

    // ── JSON format, legacy format read once ────────────────────────────

    @Test
    fun `pins are stored as JSON, ports and wildcards included`() {
        val odd = listOf("a.com", "b.com:8443", "*.c.example.com")
        store.save(hostConfig(3, issuedAt = 10L, hosts = odd))

        assertEquals(odd, store.load()!!.pins.map { it.hostname })
        assertEquals(odd.associate { it to 3 }, store.getVersionWatermarks())
        assertNull("the pre-JSON key is gone", prefs.getString(CertificateConfigStore.KEY_PINS, null))
        assertTrue(prefs.getString(CertificateConfigStore.KEY_PINS_JSON, "")!!.startsWith("["))
    }

    @Test
    fun `mtls and clientCertVersion survive save and load`() {
        store.save(CertificateConfig(version = 2, pins = listOf(
            HostPin("mtls.example.com", listOf("h1", "h2"), version = 2, mtls = true, clientCertVersion = 7),
            HostPin("plain.example.com", listOf("h1", "h2"), version = 1)
        )))

        val loaded = store.load()!!.pins
        assertTrue(loaded[0].mtls)
        assertEquals(7, loaded[0].clientCertVersion)
        assertFalse(loaded[1].mtls)
        assertNull(loaded[1].clientCertVersion)
    }

    @Test
    fun `the pre-JSON format is read once and rewritten`() {
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 4)
            .putString(CertificateConfigStore.KEY_PINS, "a.com|4|h1,h2|false\nb.com|2|h3,h4|true")
            .putString(CertificateConfigStore.KEY_WATERMARK_VERSIONS, "a.com=4\nb.com=9")
            .putLong(CertificateConfigStore.KEY_EXPIRES_AT, 0L)
            .apply()

        val loaded = store.load()!!
        assertEquals(listOf("a.com", "b.com"), loaded.pins.map { it.hostname })
        assertTrue(loaded.pins[1].forceUpdate)
        assertEquals(mapOf("a.com" to 4, "b.com" to 9), store.getVersionWatermarks())

        assertNull(prefs.getString(CertificateConfigStore.KEY_PINS, null))
        assertNull(prefs.getString(CertificateConfigStore.KEY_WATERMARK_VERSIONS, null))
        assertNotNull(prefs.getString(CertificateConfigStore.KEY_PINS_JSON, null))
        assertNotNull(prefs.getString(CertificateConfigStore.KEY_WATERMARK_VERSIONS_JSON, null))
        // A second read finds the JSON and the same content.
        assertEquals(loaded.pins, CertificateConfigStore.createForTest(prefs).load()!!.pins)
    }

    @Test
    fun `entries the pre-JSON format was tricked into are dropped on migration`() {
        // What a host named "x y|1|h1,h2" + line break + "z=5" left behind:
        // rows whose host is not a host name.
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 4)
            .putString(CertificateConfigStore.KEY_PINS, "good.example.com|4|h1,h2|false\nnot a host|1|h1,h2|false\n*.com|1|h1,h2")
            .putString(CertificateConfigStore.KEY_WATERMARK_VERSIONS, "good.example.com=4\nnot a host=2147483647\n=7")
            .putLong(CertificateConfigStore.KEY_EXPIRES_AT, 0L)
            .apply()

        assertEquals(listOf("good.example.com"), store.load()!!.pins.map { it.hostname })
        assertEquals(mapOf("good.example.com" to 4), store.getVersionWatermarks())
    }

    // ── Envelope, key-set marker, clock reference ───────────────────────

    @Test
    fun `the signed envelope is stored with the config and goes with it`() {
        val envelope = StoredEnvelope(
            payload = """{"version":5,"pins":[],"note":"quotes \" and | , = survive"}""",
            signatures = listOf(SignatureEntry("key-1", "c2ln"), SignatureEntry(null, "c2lnMg=="))
        )
        store.save(hostConfig(5, issuedAt = 2_000L), envelope)
        assertEquals(envelope, store.loadEnvelope())

        // A save without an envelope (an unsigned config) leaves none behind.
        store.save(hostConfig(6, issuedAt = 3_000L))
        assertNull(store.loadEnvelope())

        store.save(hostConfig(7, issuedAt = 4_000L), envelope)
        store.clearActive()
        assertNull(store.loadEnvelope())
    }

    @Test
    fun `resetWatermarks forgets the watermarks and records the key set it was for`() {
        store.save(hostConfig(5, issuedAt = 2_000L, hosts = listOf("a.com", "b.com")))
        store.markRolledBack(hostConfig(9, issuedAt = 9_000L))
        store.clearActive()
        assertNull(store.keySetVersionSeen())

        store.resetWatermarks(keySetVersion = 3)

        assertEquals(0L, store.getCurrentIssuedAt())
        assertTrue(store.getVersionWatermarks().isEmpty())
        assertFalse(store.isRolledBack(hostConfig(9, issuedAt = 9_000L)))
        assertEquals(3, store.keySetVersionSeen())
    }

    @Test
    fun `the clock reference survives clearActive`() {
        store.setHighestSeenTime(123_456L)
        store.save(hostConfig(5, issuedAt = 2_000L))
        store.clearActive()
        assertEquals(123_456L, store.highestSeenTime())
    }

    @Test
    fun `rolled-back config is recognised by issuedAt and pins`() {
        val rejected = hostConfig(5, issuedAt = 2_000L)
        store.markRolledBack(rejected)

        assertTrue(store.isRolledBack(rejected))
        assertFalse(store.isRolledBack(rejected.copy(issuedAt = 2_001L)))
        assertFalse(store.isRolledBack(hostConfig(6, issuedAt = 2_000L)))
    }

    // ── One namespace per server (origin) ───────────────────────────────

    private val originCipher = io.github.umutcansu.pinvault.util.SoftwarePrefsCipher()

    /** The block's store for [origin], over the test file, the way ConfigApiClient opens it. */
    private fun storeFor(origin: String) = CertificateConfigStore.forOrigin("ssl_cert_config_default", origin) { namespace, _ ->
        SecurePreferences(prefs, "test_cert_config", namespace, originCipher)
    }

    private fun mtlsConfig(version: Int, issuedAt: Long) =
        CertificateConfig(version = version, pins = listOf(HostPin("10.0.2.2", listOf("hash1aaa", "hash2bbb"), version = version)), issuedAt = issuedAt)

    @Test
    fun `each server keeps its own config and watermarks, and switching back finds them again`() {
        val tls = storeFor("scope:default-tls")
        tls.save(mtlsConfig(39, issuedAt = 5_000L))
        tls.setHighestSeenTime(9_000L)

        // The same block pointed at another server: nothing of the first one's
        // version space (no "downgrade" from v39), nothing wiped either.
        val mtls = storeFor("scope:sample-mtls")
        assertNull(mtls.load())
        assertNull("no cross-server refusal", mtls.getVersionWatermarks()["10.0.2.2"])
        assertEquals(0L, mtls.getCurrentIssuedAt())
        assertEquals("the trusted clock is the block's, not the server's", 9_000L, mtls.highestSeenTime())
        mtls.save(mtlsConfig(3, issuedAt = 6_000L))

        // Back to the first server: its watermarks are where they were, so an
        // older config of it is still a replay.
        val back = storeFor("scope:default-tls")
        assertEquals(39, back.getVersionWatermarks()["10.0.2.2"])
        assertEquals(5_000L, back.getCurrentIssuedAt())
        assertEquals(39, back.load()!!.version)
        // And the second server's are kept too.
        assertEquals(3, storeFor("scope:sample-mtls").getVersionWatermarks()["10.0.2.2"])
    }

    @Test
    fun `reset and a switch away and back do not lower the replay guard`() {
        val first = storeFor("url:https://a.test")
        first.save(mtlsConfig(7, issuedAt = 8_000L))
        first.clearActive()                                  // PinVault.reset()
        storeFor("url:https://b.test").clearActive()         // init against another URL, reset again
        val again = storeFor("url:https://a.test")
        assertEquals(8_000L, again.getCurrentIssuedAt())
        assertEquals(7, again.getVersionWatermarks()["10.0.2.2"])
    }

    @Test
    fun `a store without an origin (2_1_x) is claimed by the block's origin, nothing dropped`() {
        val legacy = CertificateConfigStore.createForTest(SecurePreferences(prefs, "test_cert_config", "ssl_cert_config_default", originCipher))
        legacy.save(mtlsConfig(12, issuedAt = 1_000L))

        val bound = storeFor("scope:prod")
        assertEquals("scope:prod", bound.origin())
        assertEquals(12, bound.load()!!.version)
        assertNotEquals(
            "every other origin has a namespace of its own",
            CertificateConfigStore.originNamespace("ssl_cert_config_default", "scope:a"),
            CertificateConfigStore.originNamespace("ssl_cert_config_default", "scope:b")
        )
    }

    // ── Watermarks survive clearActive (2.1.x stores have none) ─────────

    @Test
    fun `clearActive turns the active config's issuedAt and versions into watermarks`() {
        // What 2.1.x left: the config's own fields, no watermark keys.
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 4)
            .putLong(CertificateConfigStore.KEY_ISSUED_AT, 7_000L)
            .putString(CertificateConfigStore.KEY_PINS, "a.com|4|h1,h2|false\nb.com|9|h3,h4|false")
            .commit()
        assertFalse(prefs.contains(CertificateConfigStore.KEY_WATERMARK_ISSUED_AT))

        store.clearActive()   // e.g. a signed block discarding the envelope-less config

        assertNull(store.load())
        assertEquals(7_000L, store.getCurrentIssuedAt())
        assertEquals(mapOf("a.com" to 4, "b.com" to 9), store.getVersionWatermarks())
    }

    @Test
    fun `a config dropped for a bad envelope leaves no watermarks of its own`() {
        store.save(hostConfig(5, issuedAt = 2_000L))
        store.resetWatermarks(2)                              // a newer key set revoked its signer
        store.clearActive(keepAsWatermarks = false)
        assertEquals(0L, store.getCurrentIssuedAt())
        assertTrue(store.getVersionWatermarks().isEmpty())
    }
}
