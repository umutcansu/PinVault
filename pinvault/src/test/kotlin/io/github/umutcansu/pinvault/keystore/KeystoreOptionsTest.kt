package io.github.umutcansu.pinvault.keystore

import io.github.umutcansu.pinvault.model.HardwareBackedKeyRequiredException
import io.github.umutcansu.pinvault.model.KeySecurityLevel
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
