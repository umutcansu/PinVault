package io.github.umutcansu.pinvault.internal

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReenrollNoticeTest {

    @Test
    fun `one notice per identity`() {
        val notice = ReenrollNotice()
        assertTrue(notice.claim("CN=PinVault Client CA#1"))
        // Every later request of the revoked identity, and the refused renewal, stay quiet.
        assertFalse(notice.claim("CN=PinVault Client CA#1"))
        assertFalse(notice.claim("CN=PinVault Client CA#1"))
    }

    @Test
    fun `a new identity is reported again`() {
        val notice = ReenrollNotice()
        assertTrue(notice.claim("CN=PinVault Client CA#1"))
        // Re-enrolled, then revoked again.
        assertTrue(notice.claim("CN=PinVault Client CA#2"))
        assertFalse(notice.claim("CN=PinVault Client CA#2"))
    }
}
