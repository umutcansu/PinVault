package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.util.TestCertUtil
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** HttpClientProvider: swap, reset, version tracking */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class HttpClientProviderTest {

    private lateinit var sslManager: DynamicSSLManager
    private lateinit var provider: HttpClientProvider

    private val pin1 = TestCertUtil.generateSelfSigned(cn = "host1")
    private val pin2 = TestCertUtil.generateSelfSigned(cn = "host2")

    @Before
    fun setUp() {
        sslManager = DynamicSSLManager()
        provider = HttpClientProvider(sslManager)
    }

    @Test
    fun `initial state — version 0, no config`() {
        assertEquals(0, provider.getVersion())
        assertNull(provider.currentConfig)
    }

    @Test
    fun `swap — updates version and config`() {
        val config = CertificateConfig(
            version = 5,
            pins = listOf(HostPin("a.com", listOf(pin1.sha256Pin, pin2.sha256Pin), version = 5))
        )
        provider.swap(config)
        assertEquals(5, provider.getVersion())
        assertNotNull(provider.currentConfig)
        assertEquals(1, provider.currentConfig!!.pins.size)
    }

    @Test
    fun `swap — multiple swaps, version updates each time`() {
        val config1 = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("a.com", listOf(pin1.sha256Pin, pin2.sha256Pin), version = 1))
        )
        val config2 = CertificateConfig(
            version = 3,
            pins = listOf(HostPin("a.com", listOf(pin1.sha256Pin, pin2.sha256Pin), version = 3))
        )
        provider.swap(config1)
        assertEquals(1, provider.getVersion())
        provider.swap(config2)
        assertEquals(3, provider.getVersion())
    }

    @Test
    fun `reset — version goes back to 0`() {
        val config = CertificateConfig(
            version = 5,
            pins = listOf(HostPin("a.com", listOf(pin1.sha256Pin, pin2.sha256Pin), version = 5))
        )
        provider.swap(config)
        assertEquals(5, provider.getVersion())

        provider.reset()
        assertEquals(0, provider.getVersion())
        assertNull(provider.currentConfig)
    }

    @Test
    fun `get — returns OkHttpClient`() {
        assertNotNull(provider.get())
    }
}
