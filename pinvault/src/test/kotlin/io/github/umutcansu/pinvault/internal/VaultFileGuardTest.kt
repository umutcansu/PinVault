package io.github.umutcansu.pinvault.internal

import android.util.Base64
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.crypto.SignatureTrust
import io.github.umutcansu.pinvault.model.ConfigApiBlock
import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.model.StoreUnreadableException
import io.github.umutcansu.pinvault.model.VaultFetchResponse
import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.model.VaultFileResult
import io.github.umutcansu.pinvault.model.VaultFileStatus
import io.github.umutcansu.pinvault.store.MemVaultStore
import io.github.umutcansu.pinvault.store.StoredSignatures
import io.github.umutcansu.pinvault.store.VaultFileMeta
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.TimeUnit

/**
 * A stored vault file is checked every time it is read — its signature, the
 * Config API the signature names, how long ago the server confirmed it — and
 * not only when it was downloaded. Router and guard together, the way
 * `PinVault.fetchFile` / `loadFile` use them.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class VaultFileGuardTest {

    private val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val pubB64 = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)

    private val storage = MemVaultStore()
    private val meta = VaultFileMeta.InMemory()
    private var now = 1_800_000_000_000L
    private val removed = mutableListOf<Pair<String, String>>()
    private val asked = mutableListOf<Int>()
    private var response: VaultFetchResponse? = null

    private fun sha256Hex(bytes: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private fun signString(canonical: String): String = Signature.getInstance("SHA256withECDSA").run {
        initSign(keyPair.private)
        update(canonical.toByteArray(Charsets.UTF_8))
        Base64.encodeToString(sign(), Base64.NO_WRAP)
    }

    private fun v1(key: String, version: Int, content: ByteArray) =
        signString("pinvault-vault-file:v1:$key:$version:${sha256Hex(content)}")

    private fun v2(scope: String, key: String, version: Int, content: ByteArray) =
        signString("pinvault-vault-file:v2:$scope:$key:$version:${sha256Hex(content)}")

    private fun block(signed: Boolean = true, serverScope: String? = null) = ConfigApiBlock(
        id = "default", configUrl = "https://example.test/", bootstrapPins = emptyList(),
        signaturePublicKey = pubB64.takeIf { signed }, serverScope = serverScope
    )

    private inner class Fixture(val block: ConfigApiBlock, defaultMaxAgeMs: Long = 0L, meta: VaultFileMeta = this@VaultFileGuardTest.meta) {
        val guard = VaultFileGuard(meta, { now }, defaultMaxAgeMs) { key, reason -> removed += key to reason }
        val router: VaultFileRouter

        init {
            val api = mockk<CertificateConfigApi>()
            coEvery { api.downloadVaultFileWithMeta(any(), any(), any(), any()) } answers {
                asked += secondArg<Int>()
                response!!
            }
            val client = mockk<ConfigApiClient>()
            every { client.api } returns api
            every { client.block } returns block
            every { client.signatureTrust } returns SignatureTrust.forBlock(block, null)
            router = VaultFileRouter(
                clients = mapOf("default" to client), storageFor = { storage },
                deviceKeyProvider = null, deviceIdProvider = { "test-device" }, guard = guard
            )
        }

        suspend fun fetch(file: VaultFileConfig) = router.fetchFile(file)
        fun load(file: VaultFileConfig): ByteArray? =
            (guard.load(file, storage, router.storedVerifier(file)) as? VaultFileGuard.Read.Content)?.bytes
        fun status(file: VaultFileConfig) = guard.status(file, storage, router.storedVerifier(file))
    }

    private fun file(key: String = "flags", maxOfflineAgeMs: Long? = null, wipeWhenStale: Boolean = false) = VaultFileConfig(
        key = key, endpoint = "api/v1/vault/$key", configApiId = "default",
        maxOfflineAgeMs = maxOfflineAgeMs, wipeWhenStale = wipeWhenStale
    )

    private fun signedV1(key: String, version: Int, content: ByteArray) =
        VaultFetchResponse(content = content, version = version, signature = v1(key, version, content))

    // ── Signatures name the Config API (v2) ─────────────────────────────

    @Test
    fun `a block with a server scope takes a v2 signature for that scope`() = runTest {
        val content = "flags-v3".toByteArray()
        val f = Fixture(block(serverScope = "prod-tls"))
        response = VaultFetchResponse(
            content = content, version = 3,
            signature = v1("flags", 3, content),                 // the server sends both
            signatureV2 = v2("prod-tls", "flags", 3, content)
        )

        assertTrue(f.fetch(file()) is VaultFileResult.Updated)
        assertEquals("the v2 signature is what is kept with the copy", 2, meta.signatures("flags")!!.scheme)
        assertArrayEquals(content, f.load(file()))
    }

    @Test
    fun `a file signed for another Config API with the same key is refused`() = runTest {
        val content = "staging-flags".toByteArray()
        val f = Fixture(block(serverScope = "prod-tls"))
        response = VaultFetchResponse(content = content, version = 3, signatureV2 = v2("staging-tls", "flags", 3, content))

        val result = f.fetch(file()) as VaultFileResult.Failed

        assertTrue(result.reason, result.reason.contains("signature verification FAILED"))
        assertFalse(storage.exists("flags"))
    }

    @Test
    fun `a block with a server scope refuses a file that has only a v1 signature`() = runTest {
        val content = "flags-v3".toByteArray()
        val f = Fixture(block(serverScope = "prod-tls"))

        response = signedV1("flags", 3, content)
        val missing = f.fetch(file()) as VaultFileResult.Failed
        assertTrue(missing.reason, missing.reason.contains("X-Vault-Signature-V2"))

        // A v1 signature moved into the v2 header is not a v2 signature either.
        response = VaultFetchResponse(content = content, version = 3, signatureV2 = v1("flags", 3, content))
        assertTrue(f.fetch(file()) is VaultFileResult.Failed)
        // Nor are several of them.
        response = VaultFetchResponse(
            content = content, version = 3, signatures = listOf(SignatureEntry("k", v1("flags", 3, content))),
            signaturesV2 = listOf(SignatureEntry("k", v1("flags", 3, content)))
        )
        assertTrue(f.fetch(file()) is VaultFileResult.Failed)
        assertFalse(storage.exists("flags"))
    }

    @Test
    fun `without a server scope v1 is checked as before, whatever v2 headers come along`() = runTest {
        val content = "flags-v3".toByteArray()
        val f = Fixture(block())
        response = VaultFetchResponse(
            content = content, version = 3, signature = v1("flags", 3, content), signatureV2 = "bm90LWEtc2lnbmF0dXJl"
        )
        assertTrue(f.fetch(file()) is VaultFileResult.Updated)
        assertEquals(1, meta.signatures("flags")!!.scheme)

        // A v2 signature alone does not pass for v1.
        storage.clear("flags")
        response = VaultFetchResponse(content = content, version = 3, signature = v2("default", "flags", 3, content))
        assertTrue(f.fetch(file()) is VaultFileResult.Failed)
    }

    @Test
    fun `the several-signer v2 header is used like the v1 one`() = runTest {
        val content = "flags-v3".toByteArray()
        val f = Fixture(block(serverScope = "prod-tls"))
        response = VaultFetchResponse(
            content = content, version = 3,
            signaturesV2 = listOf(SignatureEntry("unknown-key", "AAAA"), SignatureEntry(null, v2("prod-tls", "flags", 3, content)))
        )
        assertTrue(f.fetch(file()) is VaultFileResult.Updated)
        assertEquals(2, meta.signatures("flags")!!.entries.size)
    }

    @Test
    fun `setting a server scope later sends a v1 copy back to the server`() = runTest {
        val content = "flags-v3".toByteArray()
        response = signedV1("flags", 3, content)
        assertTrue(Fixture(block()).fetch(file()) is VaultFileResult.Updated)

        // The app is updated: the block now names its Config API.
        val scoped = Fixture(block(serverScope = "prod-tls"))
        assertNull("a v1 signature says nothing about the Config API", scoped.load(file()))
        assertEquals(VaultFileStatus.NEEDS_FETCH, scoped.status(file()))
        assertTrue("not deleted: the next fetch replaces it", storage.exists("flags"))

        response = VaultFetchResponse(content = content, version = 3, signatureV2 = v2("prod-tls", "flags", 3, content))
        asked.clear()
        assertTrue(scoped.fetch(file()) is VaultFileResult.AlreadyCurrent)
        assertEquals("asked for the whole file, not 'newer than v3'", listOf(0), asked)
        assertArrayEquals(content, scoped.load(file()))
    }

    // ── The stored copy is verified when it is read ─────────────────────

    @Test
    fun `a fetched file is read back only while its stored signature still verifies`() = runTest {
        val content = "truststore".toByteArray()
        val f = Fixture(block())
        response = signedV1("ts", 1, content)
        assertTrue(f.fetch(file("ts")) is VaultFileResult.Updated)
        assertEquals(VaultFileStatus.AVAILABLE, f.status(file("ts")))
        assertArrayEquals(content, f.load(file("ts")))

        // Someone with access to the app's storage rewrites the copy.
        storage.blobs["ts"] = "attacker-truststore".toByteArray()

        assertNull(f.load(file("ts")))
        assertFalse("the copy is deleted", storage.exists("ts"))
        assertEquals(VaultFileStatus.INTEGRITY_FAILED, f.status(file("ts")))
        assertEquals("ts", removed.single().first)
        assertTrue(removed.single().second, removed.single().second.contains("signature verification failed"))

        // The next fetch brings the real file back and clears the mark.
        assertTrue(f.fetch(file("ts")) is VaultFileResult.Updated)
        assertEquals(VaultFileStatus.AVAILABLE, f.status(file("ts")))
        assertArrayEquals(content, f.load(file("ts")))
    }

    @Test
    fun `another file's signed copy under this file's name is refused`() = runTest {
        val f = Fixture(block())
        response = signedV1("public-notes", 1, "public".toByteArray())
        f.fetch(file("public-notes"))
        response = signedV1("trusted-hosts", 1, "trusted".toByteArray())
        f.fetch(file("trusted-hosts"))

        // Both validly signed — for their own names.
        storage.blobs["trusted-hosts"] = storage.blobs.getValue("public-notes")
        meta.saveSignatures("trusted-hosts", meta.signatures("public-notes"))

        assertNull(f.load(file("trusted-hosts")))
        assertFalse(storage.exists("trusted-hosts"))
        assertArrayEquals("public".toByteArray(), f.load(file("public-notes")))
    }

    @Test
    fun `a copy relabelled with another version is refused`() = runTest {
        val content = "flags".toByteArray()
        val f = Fixture(block())
        response = signedV1("flags", 4, content)
        f.fetch(file())

        // A version nobody signed, planted so that the server's file looks older.
        storage.versions["flags"] = 900_000

        assertNull(f.load(file()))
        assertFalse(storage.exists("flags"))
        assertTrue(removed.single().second, removed.single().second.contains("signed as v4"))
    }

    @Test
    fun `an older signed copy put back with its own signature is the limit of what a device can check`() = runTest {
        // Documented, not hidden: storage rolled back as a whole verifies. The
        // offline lifetime bounds it, and the next fetch replaces it.
        val f = Fixture(block())
        response = signedV1("flags", 1, "old".toByteArray())
        f.fetch(file())
        val oldBlob = storage.blobs.getValue("flags")
        val oldSignatures = meta.signatures("flags")
        response = signedV1("flags", 2, "new".toByteArray())
        f.fetch(file())

        storage.blobs["flags"] = oldBlob
        storage.versions["flags"] = 1
        meta.saveSignatures("flags", oldSignatures)

        assertArrayEquals("old".toByteArray(), f.load(file()))
        assertTrue("…until the server is asked again", f.fetch(file()) is VaultFileResult.Updated)
        assertArrayEquals("new".toByteArray(), f.load(file()))
    }

    @Test
    fun `a copy stored by an earlier version is not handed out until it is fetched again`() = runTest {
        val content = "flags".toByteArray()
        storage.save("flags", content, 7)                       // 2.1.x: verified at download, no signature kept
        val f = Fixture(block())

        assertNull(f.load(file()))
        assertEquals(VaultFileStatus.NEEDS_FETCH, f.status(file()))
        assertTrue("kept: an upgrade while offline loses nothing", storage.exists("flags"))
        assertTrue(removed.isEmpty())

        response = signedV1("flags", 7, content)
        assertEquals(VaultFileResult.AlreadyCurrent("flags", 7), f.fetch(file()))
        assertEquals("the device asks for the whole file: 'not modified' would bring no signature", listOf(0), asked)
        assertArrayEquals(content, f.load(file()))

        // From then on it asks with its version again.
        response = VaultFetchResponse(content = ByteArray(0), version = 7, notModified = true)
        f.fetch(file())
        assertEquals(listOf(0, 7), asked)
    }

    @Test
    fun `removing the signature record does not make a copy trusted`() = runTest {
        val f = Fixture(block())
        response = signedV1("flags", 1, "real".toByteArray())
        f.fetch(file())

        storage.blobs["flags"] = "attacker".toByteArray()
        meta.saveSignatures("flags", null)

        assertNull(f.load(file()))
        assertEquals(VaultFileStatus.NEEDS_FETCH, f.status(file()))
    }

    @Test
    fun `the same content under a new version keeps the version its signature names`() = runTest {
        val content = "flags".toByteArray()
        val f = Fixture(block())
        response = signedV1("flags", 1, content)
        f.fetch(file())

        // The server bumps the version when a file's policy changes.
        response = signedV1("flags", 2, content)
        assertEquals(VaultFileResult.AlreadyCurrent("flags", 2), f.fetch(file()))
        assertEquals(2, storage.getVersion("flags"))
        assertArrayEquals(content, f.load(file()))
    }

    @Test
    fun `files of an unsigned block are stored and read as before`() = runTest {
        val f = Fixture(block(signed = false))
        response = VaultFetchResponse(content = "plain".toByteArray(), version = 1)
        assertTrue(f.fetch(file()) is VaultFileResult.Updated)
        assertNull(meta.signatures("flags"))

        storage.blobs["flags"] = "changed".toByteArray()
        assertArrayEquals("no signature to hold it to", "changed".toByteArray(), f.load(file()))
        assertEquals(VaultFileStatus.AVAILABLE, f.status(file()))
    }

    @Test
    fun `nothing stored is not a failure`() {
        val f = Fixture(block())
        assertNull(f.load(file()))
        assertEquals(VaultFileStatus.NOT_STORED, f.status(file()))
        assertTrue(removed.isEmpty())
    }

    // ── A version nobody could have signed yet ──────────────────────────

    @Test
    fun `a version header far above the stored one is refused`() = runTest {
        val f = Fixture(block(signed = false))
        response = VaultFetchResponse(content = "x".toByteArray(), version = Int.MAX_VALUE)
        val first = f.fetch(file()) as VaultFileResult.Failed
        assertTrue(first.reason, first.reason.contains("more than 1000000 above"))
        assertFalse(storage.exists("flags"))

        response = VaultFetchResponse(content = "x".toByteArray(), version = 1_000_000)
        assertTrue("a first version up to the bound is fine", f.fetch(file()) is VaultFileResult.Updated)
        response = VaultFetchResponse(content = "y".toByteArray(), version = 2_000_001)
        assertTrue(f.fetch(file()) is VaultFileResult.Failed)
        response = VaultFetchResponse(content = "y".toByteArray(), version = 2_000_000)
        assertTrue(f.fetch(file()) is VaultFileResult.Updated)
    }

    // ── Offline lifetime ────────────────────────────────────────────────

    private val sevenDays = TimeUnit.DAYS.toMillis(7)

    @Test
    fun `a file is readable for its offline lifetime after the server last confirmed it`() = runTest {
        val content = "secret".toByteArray()
        val f = Fixture(block())
        val secret = file("secret", maxOfflineAgeMs = sevenDays)
        response = signedV1("secret", 1, content)
        f.fetch(secret)

        now += sevenDays - 1
        assertArrayEquals(content, f.load(secret))

        now += 2
        assertNull("a device that never came back online stops reading the file", f.load(secret))
        assertEquals(VaultFileStatus.STALE, f.status(secret))
        assertTrue("kept unless the file asks for a wipe", storage.exists("secret"))
        assertEquals(VaultFileStatus.STALE, f.guard.beforeUnlock(secret, storage)!!.status)

        // The server says "you have the current version": readable again.
        response = VaultFetchResponse(content = ByteArray(0), version = 1, notModified = true)
        assertTrue(f.fetch(secret) is VaultFileResult.AlreadyCurrent)
        assertArrayEquals(content, f.load(secret))
        assertNull(f.guard.beforeUnlock(secret, storage))
    }

    @Test
    fun `a failed fetch confirms nothing`() = runTest {
        val f = Fixture(block())
        val secret = file("secret", maxOfflineAgeMs = sevenDays)
        response = signedV1("secret", 1, "secret".toByteArray())
        f.fetch(secret)
        now += sevenDays + 1

        // An answer that does not verify is not the server's confirmation.
        response = VaultFetchResponse(content = "forged".toByteArray(), version = 2, signature = v1("secret", 2, "other".toByteArray()))
        assertTrue(f.fetch(secret) is VaultFileResult.Failed)
        assertNull(f.load(secret))
        assertEquals(VaultFileStatus.STALE, f.status(secret))
    }

    @Test
    fun `wipeWhenStale deletes the copy, on read or on the periodic sweep`() = runTest {
        val f = Fixture(block())
        val secret = file("secret", maxOfflineAgeMs = sevenDays, wipeWhenStale = true)
        val kept = file("kept", maxOfflineAgeMs = sevenDays)
        response = signedV1("secret", 1, "secret".toByteArray())
        f.fetch(secret)
        response = signedV1("kept", 1, "kept".toByteArray())
        f.fetch(kept)

        f.guard.sweep(listOf(secret, kept)) { storage }
        assertTrue("not stale yet", storage.exists("secret"))

        now += sevenDays + 1
        f.guard.sweep(listOf(secret, kept)) { storage }

        assertFalse(storage.exists("secret"))
        assertTrue("only files that asked for it are deleted", storage.exists("kept"))
        assertEquals("the app can tell why it is gone", VaultFileStatus.STALE, f.status(secret))
        assertEquals("secret", removed.single().first)

        // …and on read, for a file the sweep has not seen.
        response = signedV1("secret", 1, "secret".toByteArray())
        f.fetch(secret)
        now += sevenDays + 1
        assertNull(f.load(secret))
        assertFalse(storage.exists("secret"))
    }

    @Test
    fun `a copy with no confirmation on record counts as stale once a limit is set`() = runTest {
        storage.save("secret", "secret".toByteArray(), 1)       // stored before the app set a limit
        val f = Fixture(block(signed = false))
        assertArrayEquals("no limit: unlimited, as before", "secret".toByteArray(), f.load(file("secret")))
        assertNull(f.load(file("secret", maxOfflineAgeMs = sevenDays)))
        assertEquals(VaultFileStatus.STALE, f.status(file("secret", maxOfflineAgeMs = sevenDays)))
    }

    @Test
    fun `the config's default applies unless the file sets its own`() = runTest {
        val f = Fixture(block(signed = false), defaultMaxAgeMs = sevenDays)
        response = VaultFetchResponse(content = "a".toByteArray(), version = 1)
        f.fetch(file("a"))
        f.fetch(file("b"))
        f.fetch(file("c"))
        now += sevenDays + 1

        assertNull("the default", f.load(file("a")))
        assertArrayEquals("its own, longer limit", "a".toByteArray(), f.load(file("b", maxOfflineAgeMs = 2 * sevenDays)))
        assertArrayEquals("0 = no limit for this file", "a".toByteArray(), f.load(file("c", maxOfflineAgeMs = 0)))
    }

    @Test
    fun `a confirmation that lies ahead of the clock needs a new one, and deletes nothing`() = runTest {
        val f = Fixture(block(signed = false))
        val secret = file("secret", maxOfflineAgeMs = sevenDays, wipeWhenStale = true)
        response = VaultFetchResponse(content = "s".toByteArray(), version = 1)
        f.fetch(secret)                       // confirmed while the clock ran 30 days ahead
        now -= TimeUnit.DAYS.toMillis(30)     // the trusted clock was corrected downwards

        // Counted from a time in the future the copy would stay "fresh" for 37 days.
        assertNull(f.load(secret))
        assertEquals(VaultFileStatus.STALE, f.status(secret))
        assertEquals(VaultFileStatus.STALE, f.guard.beforeUnlock(secret, storage)!!.status)
        f.guard.sweep(listOf(secret)) { storage }
        assertTrue("a time that cannot be trusted proves no staleness: not wiped", storage.exists("secret"))
        assertTrue(removed.isEmpty())

        // The server confirms it again: the record is the clock's time, readable again.
        response = VaultFetchResponse(content = ByteArray(0), version = 1, notModified = true)
        f.fetch(secret)
        assertEquals(now, meta.confirmedAt("secret"))
        assertArrayEquals("s".toByteArray(), f.load(secret))
    }

    @Test
    fun `a trusted clock that restarts a little behind is not a confirmation in the future`() = runTest {
        val f = Fixture(block(signed = false))
        val secret = file("secret", maxOfflineAgeMs = sevenDays)
        response = VaultFetchResponse(content = "s".toByteArray(), version = 1)
        f.fetch(secret)
        // After a reboot the trusted clock resumes from its persisted reference, up to one step behind.
        now -= io.github.umutcansu.pinvault.ssl.TrustedClock.PERSIST_STEP_MS
        assertArrayEquals("s".toByteArray(), f.load(secret))
    }

    // ── A Keystore that cannot be read is not a verdict ─────────────────

    private class UnreadableMeta(private val inner: VaultFileMeta) : VaultFileMeta by inner {
        var unreadable = false
        private fun check() { if (unreadable) throw StoreUnreadableException("locked", null) }
        override fun signatures(key: String): StoredSignatures? { check(); return inner.signatures(key) }
        override fun confirmedAt(key: String): Long { check(); return inner.confirmedAt(key) }
        override fun problem(key: String): VaultFileStatus? { check(); return inner.problem(key) }
    }

    @Test
    fun `while the storage is unreadable nothing is handed out and nothing is deleted`() = runTest {
        val locked = UnreadableMeta(meta)
        val f = Fixture(block(), meta = locked)
        val secret = file("secret", maxOfflineAgeMs = sevenDays, wipeWhenStale = true)
        response = signedV1("secret", 1, "secret".toByteArray())
        f.fetch(secret)

        locked.unreadable = true
        assertNull(f.load(secret))
        assertEquals(VaultFileStatus.STORAGE_UNAVAILABLE, f.status(secret))
        assertEquals(VaultFileStatus.STORAGE_UNAVAILABLE, f.guard.beforeUnlock(secret, storage)!!.status)
        f.guard.sweep(listOf(secret)) { storage }
        assertTrue("'cannot read when it was confirmed' is not 'never confirmed'", storage.exists("secret"))
        assertTrue(removed.isEmpty())

        locked.unreadable = false
        assertArrayEquals("secret".toByteArray(), f.load(secret))
    }

    // ── The served encryption may not be weaker than the declared one ──

    @Test
    fun `an end_to_end file the server serves as plain is refused`() = runTest {
        val f = Fixture(block(signed = false))
        val e2e = VaultFileConfig(
            key = "e2e", endpoint = "api/v1/vault/e2e", configApiId = "default",
            encryption = io.github.umutcansu.pinvault.model.VaultFileEncryption.END_TO_END
        )
        for (served in listOf("plain", "at_rest", "PLAIN")) {
            response = VaultFetchResponse(content = "secret in the clear".toByteArray(), version = 1, encryption = served)
            val result = f.fetch(e2e) as VaultFileResult.Failed
            assertTrue(result.reason, result.reason.contains("for an end_to_end file; refused"))
            assertFalse(storage.exists("e2e"))
        }
    }
}
