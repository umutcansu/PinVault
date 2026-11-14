package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.model.VaultFileStatus
import io.github.umutcansu.pinvault.store.MemVaultStore
import io.github.umutcansu.pinvault.store.VaultFileMeta
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.TimeUnit

/**
 * Review 2026-11-14: `loadFile` and its siblings read a key the config does
 * not declare straight from storage — no signature re-check, no offline
 * lifetime, no screen lock, all of which live in the file's declaration. An
 * app version (or a bundle, through the bridges) that dropped a file from
 * its config kept reading the copy an earlier one had stored. This is what
 * `PinVault.loadFile` / `fileStatus` / `hasFile` / `fileVersion` /
 * `isFileLocked` answer now.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class VaultFileReadsTest {

    private val storage = MemVaultStore()
    private val meta = VaultFileMeta.InMemory()
    private var now = 1_800_000_000_000L
    private val guard = VaultFileGuard(meta, { now })
    private var declared = mapOf<String, VaultFileConfig>()

    // An unsigned block: no verifier, so only the declaration's own rules are at play.
    private val reads = VaultFileReads(files = { declared }, storageFor = { storage }, guard = { guard }, verifierFor = { null })

    private fun file(key: String, maxOfflineAgeMs: Long? = null) = VaultFileConfig(
        key = key, endpoint = "api/v1/vault/$key", configApiId = "default", maxOfflineAgeMs = maxOfflineAgeMs
    )

    @Test
    fun `a key the config does not declare reads as no such file, and its copy stays`() {
        // Stored by an earlier app version that declared "old-secrets".
        storage.save("old-secrets", "left behind".toByteArray(), 4)

        assertNull(reads.load("old-secrets"))
        assertEquals(VaultFileStatus.NOT_STORED, reads.status("old-secrets"))
        assertFalse(reads.has("old-secrets"))
        assertEquals(0, reads.version("old-secrets"))
        assertFalse(reads.isLocked("old-secrets"))
        assertNull(reads.declared("old-secrets"))

        assertTrue("nothing is deleted on a read", storage.exists("old-secrets"))
        assertEquals(4, storage.getVersion("old-secrets"))
    }

    @Test
    fun `declared again, the copy is back under the declaration's rules`() {
        storage.save("flags", "flags".toByteArray(), 2)
        val sevenDays = TimeUnit.DAYS.toMillis(7)
        declared = mapOf("flags" to file("flags", maxOfflineAgeMs = sevenDays))

        // Never confirmed under a limit: it exists, and is not handed out —
        // exactly what the undeclared read used to skip.
        assertTrue(reads.has("flags"))
        assertEquals(2, reads.version("flags"))
        assertEquals(VaultFileStatus.STALE, reads.status("flags"))
        assertNull(reads.load("flags"))

        guard.confirmed(file("flags", maxOfflineAgeMs = sevenDays))
        assertArrayEquals("flags".toByteArray(), reads.load("flags"))
        assertEquals(VaultFileStatus.AVAILABLE, reads.status("flags"))
    }

    @Test
    fun `a declared file that was never fetched is simply not stored`() {
        declared = mapOf("flags" to file("flags"))

        assertNull(reads.load("flags"))
        assertEquals(VaultFileStatus.NOT_STORED, reads.status("flags"))
        assertFalse(reads.has("flags"))
        assertEquals(0, reads.version("flags"))
    }

    @Test
    fun `one file's declaration does not open another key`() {
        declared = mapOf("flags" to file("flags"))
        storage.save("flags", "flags".toByteArray(), 1)
        storage.save("old-secrets", "left behind".toByteArray(), 4)
        guard.confirmed(file("flags"))

        assertArrayEquals("flags".toByteArray(), reads.load("flags"))
        assertNull(reads.load("old-secrets"))
        assertFalse(reads.has("old-secrets"))
    }
}
