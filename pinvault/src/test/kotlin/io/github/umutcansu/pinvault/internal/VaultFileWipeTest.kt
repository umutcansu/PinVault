package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.model.UserAuth
import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.store.MemVaultStore
import io.github.umutcansu.pinvault.store.SoftwareUserAuthKeys
import io.github.umutcansu.pinvault.store.UserAuthVaultStorage
import io.github.umutcansu.pinvault.store.VaultStorageProvider
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Y4: a revoked (or unenrolled) Config API's vault files leave the device. */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class VaultFileWipeTest {

    private val inner = MemVaultStore()
    private val keys = SoftwareUserAuthKeys()
    private val locked = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED)

    private val revokedPlain = VaultFileConfig(key = "flags", endpoint = "e/flags", configApiId = "mtls")
    private val revokedLocked = VaultFileConfig(key = "statement", endpoint = "e/statement", configApiId = "mtls", userAuth = UserAuth.REQUIRED)
    private val otherPlain = VaultFileConfig(key = "public", endpoint = "e/public", configApiId = "tls")
    private val otherLocked = VaultFileConfig(key = "card", endpoint = "e/card", configApiId = "tls", userAuth = UserAuth.REQUIRED)

    private fun storageFor(key: String): VaultStorageProvider = if (key == "statement" || key == "card") locked else inner

    @Test
    fun `wipes the revoked Config API's files, locked ones and the key included`() {
        inner.save("flags", "f".toByteArray(), 1)
        locked.save("statement", "s".toByteArray(), 1)
        inner.save("public", "p".toByteArray(), 1)
        var keyDeleted = false

        val count = VaultFileWipe.wipe(setOf("mtls"), listOf(revokedPlain, revokedLocked, otherPlain), ::storageFor, keys) {
            keyDeleted = true
        }

        assertEquals(2, count)
        assertFalse(inner.exists("flags"))
        assertFalse(locked.exists("statement"))
        assertTrue("another Config API's file stays", inner.exists("public"))
        assertNull("no locked file left: the user-auth key goes too", keys.pair)
        assertTrue(keyDeleted)
    }

    @Test
    fun `keeps the device key while another Config API still has a locked file`() {
        locked.save("statement", "s".toByteArray(), 1)
        locked.save("card", "c".toByteArray(), 1)

        VaultFileWipe.wipe(setOf("mtls"), listOf(revokedLocked, otherLocked), ::storageFor, keys)

        assertFalse(locked.exists("statement"))
        assertTrue(locked.exists("card"))
        assertNotNull(keys.pair)
    }

    @Test
    fun `a storage error does not stop the rest`() {
        inner.save("flags", "f".toByteArray(), 1)
        val failing = object : VaultStorageProvider by inner {
            override fun clear(key: String) = throw IllegalStateException("disk")
        }

        val count = VaultFileWipe.wipe(setOf("mtls"), listOf(revokedLocked, revokedPlain), { if (it == "statement") failing else inner }, null)

        assertEquals(2, count)
        assertFalse(inner.exists("flags"))
    }

    @Test
    fun `unenroll wipes only the blocks that use the label for mTLS`() {
        fun block(id: String, label: String = "default_cert", enrollmentUrl: String? = null, renewalUrl: String? = null,
                  bundled: ByteArray? = null) = io.github.umutcansu.pinvault.model.ConfigApiBlock(
            id = id, configUrl = "https://$id.test/", bootstrapPins = emptyList(), clientCertLabel = label,
            enrollmentUrl = enrollmentUrl, renewalUrl = renewalUrl, clientKeystoreBytes = bundled
        )
        val blocks = listOf(
            block("tls"),                                                    // TLS only, same default label
            block("enrolls", enrollmentUrl = "https://enrolls.test:8091/"),
            block("renews", renewalUrl = "https://renews.test:8093/"),
            block("bundled", bundled = byteArrayOf(1)),
            block("by-file"),
            block("other-label", label = "other", enrollmentUrl = "https://x.test/")
        )
        val files = listOf(
            VaultFileConfig(key = "public", endpoint = "e/public", configApiId = "tls"),
            VaultFileConfig(key = "secret", endpoint = "e/secret", configApiId = "by-file",
                accessPolicy = io.github.umutcansu.pinvault.model.VaultFileAccessPolicy.TOKEN_MTLS)
        )

        assertEquals(setOf("enrolls", "renews", "bundled", "by-file"), VaultFileWipe.mtlsBlocksUsing("default_cert", blocks, files))
        assertEquals(setOf("other-label"), VaultFileWipe.mtlsBlocksUsing("other", blocks, files))
    }
}
