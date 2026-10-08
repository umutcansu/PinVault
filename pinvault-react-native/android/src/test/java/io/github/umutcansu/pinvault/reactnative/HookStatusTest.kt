package io.github.umutcansu.pinvault.reactnative

import com.facebook.react.modules.network.CustomClientBuilder
import com.facebook.react.modules.network.NetworkingModule
import com.facebook.react.modules.network.OkHttpClientFactory
import com.facebook.react.modules.network.OkHttpClientProvider
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The replacement check against React Native 0.87's real classes: the private
 * static fields PinVaultNetworking.status() reads must exist under these names
 * (the consumer R8 rules keep them in release builds).
 */
class HookStatusTest {

    private val ours = OkHttpClientFactory { OkHttpClient() }
    private val ourBuilder = CustomClientBuilder { }

    @After fun clear() {
        OkHttpClientProvider.setOkHttpClientFactory(null)
        NetworkingModule.setCustomClientBuilder(null)
    }

    @Test fun `both hooks ours = pinned`() {
        OkHttpClientProvider.setOkHttpClientFactory(ours)
        NetworkingModule.setCustomClientBuilder(ourBuilder)
        val s = HookStatus.read(true, ours, ourBuilder)
        assertEquals(HookStatus(true, true, true), s)
        assertTrue(s.pinned)
    }

    @Test fun `another library's factory or builder is detected`() {
        OkHttpClientProvider.setOkHttpClientFactory(OkHttpClientFactory { OkHttpClient() })
        NetworkingModule.setCustomClientBuilder(ourBuilder)
        val s = HookStatus.read(true, ours, ourBuilder)
        assertEquals(false, s.factoryIsPinVault)
        assertFalse(s.pinned)
        assertTrue(s.describe(), s.describe().contains("OkHttpClientProvider's client factory was replaced"))

        OkHttpClientProvider.setOkHttpClientFactory(ours)
        NetworkingModule.setCustomClientBuilder { }
        val t = HookStatus.read(true, ours, ourBuilder)
        assertEquals(false, t.clientBuilderIsPinVault)
        assertTrue(t.describe().contains("custom client builder was replaced"))
    }

    @Test fun `cleared hooks and a missing install are not pinned`() {
        assertFalse(HookStatus.read(true, ours, ourBuilder).pinned)
        val notInstalled = HookStatus.read(false, ours, ourBuilder)
        assertFalse(notInstalled.pinned)
        assertTrue(notInstalled.describe().contains("NOT pinned"))
    }

    @Test fun `an unreadable hook counts as not pinned`() {
        val s = HookStatus(true, null, true)
        assertFalse(s.pinned)
        assertTrue(s.describe().contains("could not be read"))
    }
}
