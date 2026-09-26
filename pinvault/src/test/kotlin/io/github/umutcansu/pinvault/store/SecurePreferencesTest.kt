package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The Keystore-backed preferences that replaced EncryptedSharedPreferences.
 * Robolectric has no AndroidKeyStore, so a software [PrefsCipher] with the
 * same algorithms stands in; the real Keystore runs in the instrumented and
 * E2E tests.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class SecurePreferencesTest {

    /** AES-256-GCM + HMAC-SHA256 with keys in memory. */
    private class SoftwareCipher : PrefsCipher {
        private val aes: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        private val macKey: SecretKey = KeyGenerator.getInstance("HmacSHA256").generateKey()
        private val random = SecureRandom()

        override fun seal(plaintext: ByteArray, aad: ByteArray): ByteArray {
            val iv = ByteArray(12).also(random::nextBytes)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, aes, GCMParameterSpec(128, iv))
            cipher.updateAAD(aad)
            return iv + cipher.doFinal(plaintext)
        }

        override fun open(sealed: ByteArray, aad: ByteArray): ByteArray {
            if (sealed.size < 28) throw AEADBadTagException("short")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, aes, GCMParameterSpec(128, sealed, 0, 12))
            cipher.updateAAD(aad)
            return cipher.doFinal(sealed, 12, sealed.size - 12)
        }

        override fun mac(input: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run { init(macKey); doFinal(input) }
    }

    private lateinit var context: Context
    private lateinit var backing: SharedPreferences
    private val cipher = SoftwareCipher()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        backing = context.getSharedPreferences(FILE, Context.MODE_PRIVATE).also { it.edit().clear().commit() }
    }

    private fun prefs(namespace: String = "ns", cipher: PrefsCipher = this.cipher) = SecurePreferences(backing, FILE, namespace, cipher)

    @Test
    fun `every type round-trips and absent keys give the default`() {
        prefs().edit()
            .putString("s", "değer ✓")
            .putInt("i", -7)
            .putLong("l", Long.MAX_VALUE)
            .putFloat("f", 1.5f)
            .putBoolean("b", true)
            .putStringSet("set", mutableSetOf("a", "b"))
            .commit()

        val p = prefs()
        assertEquals("değer ✓", p.getString("s", null))
        assertEquals(-7, p.getInt("i", 0))
        assertEquals(Long.MAX_VALUE, p.getLong("l", 0))
        assertEquals(1.5f, p.getFloat("f", 0f), 0f)
        assertTrue(p.getBoolean("b", false))
        assertEquals(setOf("a", "b"), p.getStringSet("set", null))
        assertEquals("yok", p.getString("missing", "yok"))
        assertEquals(42, p.getInt("missing", 42))
        assertEquals(6, p.all.size)
    }

    @Test
    fun `nothing readable reaches the file`() {
        prefs().edit().putString("config_pins", "api.example.com|3|pinA,pinB|false").putInt("config_version", 3).commit()

        val raw = File(context.applicationInfo.dataDir, "shared_prefs/$FILE.xml").readText()
        for (secret in listOf("config_pins", "config_version", "api.example.com", "pinA")) {
            assertFalse("'$secret' is in the file", raw.contains(secret))
        }
        assertEquals(2, backing.all.size)
    }

    @Test
    fun `putString null and remove delete the entry`() {
        prefs().edit().putString("a", "1").putString("b", "2").commit()
        prefs().edit().putString("a", null).remove("b").commit()
        assertFalse(prefs().contains("a"))
        assertFalse(prefs().contains("b"))
        assertTrue(backing.all.isEmpty())
    }

    @Test
    fun `namespaces share a file without seeing each other and clear empties one`() {
        prefs("block-a").edit().putString("config_pins", "A").commit()
        prefs("block-b").edit().putString("config_pins", "B").commit()

        assertEquals("A", prefs("block-a").getString("config_pins", null))
        assertEquals("B", prefs("block-b").getString("config_pins", null))

        prefs("block-a").edit().clear().commit()
        assertNull(prefs("block-a").getString("config_pins", null))
        assertEquals("B", prefs("block-b").getString("config_pins", null))
        assertEquals(mapOf("config_pins" to "B"), prefs("block-b").all)
    }

    @Test
    fun `clear applies before the puts of the same edit`() {
        prefs().edit().putString("old", "x").commit()
        prefs().edit().putString("new", "y").clear().commit()
        assertEquals(mapOf("new" to "y"), prefs().all)
    }

    // An entry copied onto another key's name, or another file's, does not
    // open: the value is bound to its stored name and file.
    @Test
    fun `an entry moved to another key reads as absent and is dropped`() {
        prefs().edit().putString("pins_host_a", "attacker").putString("pins_host_b", "genuine").commit()
        // Swap the two sealed values under their stored names.
        val (first, second) = backing.all.keys.toList()
        val v1 = backing.getString(first, null)
        val v2 = backing.getString(second, null)
        backing.edit().putString(first, v2).putString(second, v1).commit()

        assertNull(prefs().getString("pins_host_a", null))
        assertNull(prefs().getString("pins_host_b", null))
        assertTrue("unopenable entries are removed", backing.all.isEmpty())
    }

    @Test
    fun `a tampered value reads as absent`() {
        prefs().edit().putString("k", "v").commit()
        val name = backing.all.keys.single()
        val sealed = backing.getString(name, null)!!
        val flipped = sealed.replaceRange(20, 21, if (sealed[20] == 'A') "B" else "A")
        backing.edit().putString(name, flipped).commit()

        assertEquals("fallback", prefs().getString("k", "fallback"))
        assertFalse(backing.contains(name))
    }

    @Test
    fun `another app's key cannot open the file`() {
        prefs().edit().putString("k", "v").commit()
        assertNull(prefs(cipher = SoftwareCipher()).getString("k", null))
    }

    @Test
    fun `reading with the wrong type throws like platform preferences`() {
        prefs().edit().putString("k", "text").commit()
        try {
            prefs().getInt("k", 0)
            fail("ClassCastException expected")
        } catch (e: ClassCastException) {
            // expected
        }
    }

    @Test
    fun `listeners hear the logical key`() {
        val heard = mutableListOf<String?>()
        val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key -> heard += key }
        val p = prefs()
        p.registerOnSharedPreferenceChangeListener(listener)
        p.edit().putInt("config_version", 5).commit()
        p.unregisterOnSharedPreferenceChangeListener(listener)
        p.edit().putInt("config_version", 6).commit()
        assertEquals(listOf<String?>("config_version"), heard)
    }

    // ── Migration from PinVault 2.0.x files ──────────────────────────────

    /** A legacy reader over a plain file, standing in for EncryptedSharedPreferences. */
    private fun plainLegacyReader(): (Context, String) -> Map<String, *>? = { ctx, name ->
        if (File(ctx.applicationInfo.dataDir, "shared_prefs/$name.xml").exists()) {
            ctx.getSharedPreferences(name, Context.MODE_PRIVATE).all
        } else {
            null
        }
    }

    @Test
    fun `a legacy file moves over once and is deleted`() {
        context.getSharedPreferences(LEGACY, Context.MODE_PRIVATE).edit()
            .putInt("config_version", 12).putLong("config_issued_at", 99L)
            .putBoolean("config_force_update", true).putString("config_pins", "h|12|a,b|false")
            .commit()

        val p = SecurePreferences.open(context, FILE, LEGACY, LEGACY, cipher, plainLegacyReader())
        assertEquals(12, p.getInt("config_version", 0))
        assertEquals(99L, p.getLong("config_issued_at", 0))
        assertTrue(p.getBoolean("config_force_update", false))
        assertEquals("h|12|a,b|false", p.getString("config_pins", null))
        assertFalse(File(context.applicationInfo.dataDir, "shared_prefs/$LEGACY.xml").exists())

        // A second start finds no legacy file and keeps what is there.
        p.edit().putInt("config_version", 13).commit()
        assertEquals(13, SecurePreferences.open(context, FILE, LEGACY, LEGACY, cipher, plainLegacyReader()).getInt("config_version", 0))
    }

    @Test
    fun `a legacy file that no longer opens is only deleted`() {
        context.getSharedPreferences(LEGACY, Context.MODE_PRIVATE).edit().putString("x", "unreadable").commit()
        val p = SecurePreferences.open(context, FILE, LEGACY, LEGACY, cipher) { _, _ -> emptyMap<String, Any?>() }
        assertTrue(p.all.isEmpty())
        assertFalse(File(context.applicationInfo.dataDir, "shared_prefs/$LEGACY.xml").exists())
    }

    @Test
    fun `stores work unchanged on top, two blocks in one file`() {
        val a = CertificateConfigStore.createForTest(prefs("ssl_cert_config_block-a"))
        val b = CertificateConfigStore.createForTest(prefs("ssl_cert_config_block-b"))
        val config = CertificateConfig(version = 4, pins = listOf(HostPin("api.example.com", listOf("p1", "p2"), version = 4)), issuedAt = 7L)
        a.save(config)
        b.save(config.copy(version = 9, pins = listOf(HostPin("cdn.example.com", listOf("p3", "p4"), version = 9))))

        val loaded = CertificateConfigStore.createForTest(prefs("ssl_cert_config_block-a")).load()!!
        assertEquals(4, loaded.version)
        assertEquals(config.pins, loaded.pins)
        assertEquals(7L, loaded.issuedAt)
        a.clear() // PinVault.reset() on block a
        assertNull(CertificateConfigStore.createForTest(prefs("ssl_cert_config_block-a")).load())
        assertEquals(9, CertificateConfigStore.createForTest(prefs("ssl_cert_config_block-b")).load()!!.version)
    }

    // The backup rules must name every file the stores write (audit M-07).
    @Test
    fun `backup rules exclude every store file`() {
        val files = listOf(
            CertificateConfigStore.FILE_NAME, ClientCertSecureStore.FILE_NAME,
            SigningKeyStore.FILE_NAME, VaultFileStore.FILE_NAME
        )
        for (rules in listOf("pinvault_backup_rules.xml", "pinvault_data_extraction_rules.xml")) {
            val xml = File("src/main/res/xml/$rules").readText()
            for (file in files) {
                val count = Regex("<exclude domain=\"sharedpref\" path=\"$file\\.xml\" />").findAll(xml).count()
                assertEquals("$file.xml in $rules", if (rules.startsWith("pinvault_data")) 2 else 1, count)
            }
        }
    }

    private companion object {
        const val FILE = "test_secure_prefs"
        const val LEGACY = "ssl_cert_config_legacy-block"
    }
}
