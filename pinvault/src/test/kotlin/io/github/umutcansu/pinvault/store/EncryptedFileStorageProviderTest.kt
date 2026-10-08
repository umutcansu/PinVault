package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The file store binds a file's name and version into what its GCM tag
 * covers, and reads the version from the file itself. Software AES keys stand
 * in for the per-file Android Keystore keys.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class EncryptedFileStorageProviderTest {

    private lateinit var dir: File
    private lateinit var prefs: SharedPreferences
    private lateinit var store: EncryptedFileStorageProvider
    private val keys = HashMap<String, SecretKey>()
    private var keystoreDown = false

    /** One key for every file unless a test says otherwise: the worst case for swapping copies. */
    private val sharedKey = SecretKeySpec(ByteArray(32).also { SecureRandom().nextBytes(it) }, "AES")

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        dir = File(context.cacheDir, "vault-file-test-${System.nanoTime()}")
        prefs = context.getSharedPreferences("vault-file-test", Context.MODE_PRIVATE).also { it.edit().clear().commit() }
        store = EncryptedFileStorageProvider.createForTest(dir, prefs) { key ->
            if (keystoreDown) throw java.security.ProviderException("Keystore operation failed")
            keys[key] ?: sharedKey
        }
    }

    private fun file(key: String) = File(dir, "$key.enc")

    @Test
    fun `the longest key and its pending copy are stored, a path is not`() {
        val longest = "k".repeat(64)
        store.save(longest, byteArrayOf(1), 1)
        store.save("$longest${UserAuthVaultStorage.PENDING_SUFFIX}", byteArrayOf(2), 2)
        assertArrayEquals(byteArrayOf(2), store.load("$longest${UserAuthVaultStorage.PENDING_SUFFIX}"))
        store.clear("$longest${UserAuthVaultStorage.PENDING_SUFFIX}")
        assertArrayEquals(byteArrayOf(1), store.load(longest))
        for (bad in listOf("../escape", "a/b", "..", "x".repeat(65))) {
            try {
                store.save(bad, byteArrayOf(0), 1)
                org.junit.Assert.fail("stored '$bad'")
            } catch (expected: IllegalArgumentException) {
            }
        }
        assertFalse(File(dir.parentFile, "escape.enc").exists())
    }

    @Test
    fun `a file round-trips with its version`() {
        val model = ByteArray(200_000).also { SecureRandom().nextBytes(it) }
        store.save("model", model, 12)

        assertArrayEquals(model, store.load("model"))
        assertEquals(12, store.getVersion("model"))
        assertTrue(store.exists("model"))
        assertEquals("the version is in the file, not in plain preferences", 0, prefs.all.size)
        assertFalse(String(file("model").readBytes(), Charsets.ISO_8859_1).contains(String(model.copyOf(64), Charsets.ISO_8859_1)))
    }

    @Test
    fun `a copy moved under another file's name does not open and is deleted`() {
        store.save("public-notes", "public".toByteArray(), 1)
        store.save("trusted-hosts", "trusted".toByteArray(), 1)

        file("public-notes").copyTo(file("trusted-hosts"), overwrite = true)

        assertNull(store.load("trusted-hosts"))
        assertFalse("it will never open: gone, so the next fetch starts from zero", store.exists("trusted-hosts"))
        assertEquals(0, store.getVersion("trusted-hosts"))
        assertArrayEquals("public".toByteArray(), store.load("public-notes"))
    }

    @Test
    fun `a copy given another version does not open and is deleted`() {
        store.save("flags", "flags".toByteArray(), 4)
        val bytes = file("flags").readBytes()
        // Bytes 4..7 are the version: 4 becomes 2,000,000,004.
        bytes[4] = 0x77
        file("flags").writeBytes(bytes)
        assertTrue(store.getVersion("flags") > 1_000_000)

        assertNull(store.load("flags"))
        assertFalse(store.exists("flags"))
        assertEquals(0, store.getVersion("flags"))
    }

    @Test
    fun `an older copy of the same file cannot be given the newer version's label`() {
        store.save("flags", "old".toByteArray(), 1)
        val old = file("flags").readBytes()
        store.save("flags", "new".toByteArray(), 2)

        // The old ciphertext with the version field of the new one.
        val relabelled = old.copyOf().also { it[7] = 2 }
        file("flags").writeBytes(relabelled)

        assertNull(store.load("flags"))
        assertFalse(store.exists("flags"))
    }

    @Test
    fun `a rewritten or truncated copy is deleted`() {
        store.save("flags", "flags".toByteArray(), 1)
        val bytes = file("flags").readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte()
        file("flags").writeBytes(bytes)
        assertNull(store.load("flags"))
        assertFalse(store.exists("flags"))

        store.save("flags", "flags".toByteArray(), 1)
        file("flags").writeBytes(file("flags").readBytes().copyOf(9))
        assertNull(store.load("flags"))
        assertFalse(store.exists("flags"))
    }

    /** What earlier versions wrote: `[IV length][IV][ciphertext]`, nothing bound, the version in preferences. */
    private fun writeLegacy(key: String, content: ByteArray, version: Int) {
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val encrypted = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, sharedKey, GCMParameterSpec(128, iv))
            doFinal(content)
        }
        dir.mkdirs()
        file(key).writeBytes(byteArrayOf(iv.size.toByte()) + iv + encrypted)
        prefs.edit().putInt("vault_file_ver_$key", version).commit()
    }

    @Test
    fun `a copy in the earlier form is read once and written again with name and version bound`() {
        writeLegacy("model", "legacy-model".toByteArray(), 9)
        assertEquals(9, store.getVersion("model"))

        assertArrayEquals("legacy-model".toByteArray(), store.load("model"))

        assertEquals("PVF2", String(file("model").readBytes().copyOf(4), Charsets.US_ASCII))
        assertEquals(9, store.getVersion("model"))
        assertFalse("the plain version entry is gone", prefs.contains("vault_file_ver_model"))
        assertArrayEquals("legacy-model".toByteArray(), store.load("model"))
        // From now on it is bound like any other copy.
        writeLegacy("other", "other".toByteArray(), 1)
        store.load("other")
        file("other").copyTo(file("model"), overwrite = true)
        assertNull(store.load("model"))
    }

    @Test
    fun `a Keystore failure keeps the copy, on load and on save`() {
        store.save("flags", "v1".toByteArray(), 1)

        keystoreDown = true
        assertNull(store.load("flags"))
        assertTrue("unreadable now is not damaged", store.exists("flags"))
        assertEquals(1, store.getVersion("flags"))
        // A save that cannot encrypt must not take the old copy with it.
        store.save("flags", "v2".toByteArray(), 2)
        assertTrue(store.exists("flags"))
        assertFalse(File(dir, "flags.enc.tmp").exists())

        keystoreDown = false
        assertArrayEquals("v1".toByteArray(), store.load("flags"))
        assertEquals(1, store.getVersion("flags"))
    }

    @Test
    fun `clear removes the file and its version`() {
        store.save("flags", "x".toByteArray(), 3)
        store.clear("flags")
        assertFalse(store.exists("flags"))
        assertEquals(0, store.getVersion("flags"))
        assertNull(store.load("flags"))
    }
}
