package io.github.umutcansu.pinvault.keystore

import io.github.umutcansu.pinvault.model.HardwareBackedKeyRequiredException
import io.github.umutcansu.pinvault.model.KeySecurityLevel
import io.github.umutcansu.pinvault.model.UnlockedDeviceKeyRequiredException
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * `requireHardwareBackedKeys()`: what the Keystore reports decides, and a
 * refused key is deleted before the failure is raised.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class KeystoreOptionsTest {

    @After
    fun reset() {
        KeystoreOptions.hardwareBackedRequired = false
        KeystoreOptions.unlockedDeviceRequired = false
        KeystoreOptions.unlockedDeviceFallbackAllowed = false
    }

    // ── requireUnlockedDevice() ──────────────────────────────────────────

    @Test
    @Config(manifest = Config.NONE, sdk = [34])
    fun `an unlocked-device key the Keystore refuses is a refusal, not a silent fallback`() {
        KeystoreOptions.unlockedDeviceRequired = true
        val asked = mutableListOf<Boolean>()
        var cleaned = false
        try {
            KeystoreOptions.generating("Store encryption key", cleanUp = { cleaned = true }) { unlocked ->
                asked += unlocked
                throw java.security.ProviderException("Keystore: unlocked device required is not supported")
            }
            fail("the refusal must be reported, not worked around")
        } catch (e: UnlockedDeviceKeyRequiredException) {
            assertEquals("asked once, with the flag", listOf(true), asked)
            assertTrue("the failed attempt is cleaned up", cleaned)
            assertEquals("Store encryption key", e.keyKind)
            assertTrue(e.cause is java.security.ProviderException)
            assertTrue(e.message, e.message!!.contains("allowFallback"))
        }
    }

    @Test
    @Config(manifest = Config.NONE, sdk = [34])
    fun `with allowFallback the key is made without the requirement`() {
        KeystoreOptions.unlockedDeviceRequired = true
        KeystoreOptions.unlockedDeviceFallbackAllowed = true
        val asked = mutableListOf<Boolean>()
        var cleaned = false
        val key = KeystoreOptions.generating("Store encryption key", cleanUp = { cleaned = true }) { unlocked ->
            asked += unlocked
            if (unlocked) throw java.security.ProviderException("refused") else "key"
        }
        assertEquals("key", key)
        assertEquals("with the flag first, then without", listOf(true, false), asked)
        assertTrue(cleaned)
    }

    @Test
    @Config(manifest = Config.NONE, sdk = [34])
    fun `a key the Keystore did make but refused for its level is not retried without the flag`() {
        KeystoreOptions.unlockedDeviceRequired = true
        KeystoreOptions.unlockedDeviceFallbackAllowed = true
        val asked = mutableListOf<Boolean>()
        try {
            KeystoreOptions.generating("Device RSA key") { unlocked ->
                asked += unlocked
                throw HardwareBackedKeyRequiredException("Device RSA key", KeySecurityLevel.SOFTWARE)
            }
            fail("must be refused")
        } catch (e: HardwareBackedKeyRequiredException) {
            assertEquals("the level refusal is not the flag's doing: no second attempt", listOf(true), asked)
        }
    }

    @Test
    @Config(manifest = Config.NONE, sdk = [27])
    fun `before Android 9 the flag does not exist and nothing is refused`() {
        KeystoreOptions.unlockedDeviceRequired = true
        val asked = mutableListOf<Boolean>()
        assertEquals("key", KeystoreOptions.generating("Store encryption key") { unlocked -> asked += unlocked; "key" })
        assertEquals(listOf(false), asked)
    }

    @Test
    fun `without the option every level passes and is returned`() {
        for (level in KeySecurityLevel.entries) {
            var cleaned = false
            assertEquals(level, KeystoreOptions.checkLevel("Test key", level, cleanUp = { cleaned = true }))
            assertFalse("level $level must not be deleted", cleaned)
        }
    }

    @Test
    fun `with the option hardware levels pass and the rest are deleted and refused`() {
        KeystoreOptions.hardwareBackedRequired = true
        assertEquals(KeySecurityLevel.STRONGBOX, KeystoreOptions.checkLevel("Test key", KeySecurityLevel.STRONGBOX))
        assertEquals(KeySecurityLevel.TRUSTED_ENVIRONMENT, KeystoreOptions.checkLevel("Test key", KeySecurityLevel.TRUSTED_ENVIRONMENT))
        for (level in listOf(KeySecurityLevel.SOFTWARE, KeySecurityLevel.UNKNOWN)) {
            var cleaned = false
            try {
                KeystoreOptions.checkLevel("Client identity key", level, cleanUp = { cleaned = true })
                fail("$level must be refused")
            } catch (e: HardwareBackedKeyRequiredException) {
                assertTrue("the refused key is deleted first", cleaned)
                assertEquals(level, e.level)
                assertEquals("Client identity key", e.keyKind)
                assertTrue(e.message, e.message!!.contains(level.wireName))
            }
        }
    }

    @Test
    fun `a failing clean-up does not hide the refusal`() {
        KeystoreOptions.hardwareBackedRequired = true
        try {
            KeystoreOptions.checkLevel("Test key", KeySecurityLevel.SOFTWARE, cleanUp = { error("keystore gone") })
            fail("must be refused")
        } catch (e: HardwareBackedKeyRequiredException) {
            assertNull(e.cause)
        }
    }

    @Test
    fun `the software identity key provider reports itself as software, and refuses under the option`() {
        val provider = ClientIdentityKeyProvider.software("options-test")
        provider.clear()
        assertEquals(KeySecurityLevel.UNKNOWN, provider.securityLevel())
        provider.ensureKeyPair()
        assertEquals(KeySecurityLevel.SOFTWARE, provider.securityLevel())
        assertFalse(provider.securityLevel().hardwareBacked)
        provider.clear()
    }

    @Test
    fun `wire names round-trip`() {
        for (level in KeySecurityLevel.entries) assertEquals(level, KeySecurityLevel.fromWireName(level.wireName))
        assertEquals(KeySecurityLevel.UNKNOWN, KeySecurityLevel.fromWireName("hsm"))
        assertEquals(KeySecurityLevel.UNKNOWN, KeySecurityLevel.fromWireName(null))
        assertEquals(KeySecurityLevel.TRUSTED_ENVIRONMENT, KeySecurityLevel.fromWireName(" TEE "))
    }
}
