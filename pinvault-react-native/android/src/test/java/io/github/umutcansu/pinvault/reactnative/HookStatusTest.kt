package io.github.umutcansu.pinvault.reactnative

import com.facebook.react.modules.network.CustomClientBuilder
import com.facebook.react.modules.network.NetworkingModule
import com.facebook.react.modules.network.OkHttpClientFactory
import com.facebook.react.modules.network.OkHttpClientProvider
import com.facebook.react.modules.websocket.WebSocketModule
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The replacement check against React Native's real classes: the private
 * static fields PinVaultNetworking.status() reads must exist under these names
 * (the consumer R8 rules keep them in release builds).
 */
class HookStatusTest {

    private val ours = OkHttpClientFactory { OkHttpClient() }
    private val ourBuilder = CustomClientBuilder { }
    private val ourSocketBuilder = CustomClientBuilder { }

    private fun read(installed: Boolean = true) = HookStatus.read(installed, ours, ourBuilder, ourSocketBuilder)

    private fun installOurs() {
        OkHttpClientProvider.setOkHttpClientFactory(ours)
        NetworkingModule.setCustomClientBuilder(ourBuilder)
        WebSocketModule.setCustomClientBuilder(ourSocketBuilder)
    }

    @After fun clear() {
        OkHttpClientProvider.setOkHttpClientFactory(null)
        NetworkingModule.setCustomClientBuilder(null)
        WebSocketModule.setCustomClientBuilder(null)
    }

    @Test fun `all hooks ours = pinned`() {
        installOurs()
        val s = read()
        assertEquals(HookStatus(true, true, true, true), s)
        assertTrue(s.pinned)
    }

    @Test fun `another library's factory or builder is detected`() {
        installOurs()
        OkHttpClientProvider.setOkHttpClientFactory(OkHttpClientFactory { OkHttpClient() })
        val s = read()
        assertEquals(false, s.factoryIsPinVault)
        assertFalse(s.pinned)
        assertTrue(s.describe(), s.describe().contains("OkHttpClientProvider's client factory was replaced"))

        OkHttpClientProvider.setOkHttpClientFactory(ours)
        NetworkingModule.setCustomClientBuilder { }
        val t = read()
        assertEquals(false, t.clientBuilderIsPinVault)
        assertTrue(t.describe().contains("NetworkingModule's custom client builder was replaced"))
    }

    @Test fun `a WebSocket builder set by another library is detected`() {
        // RN 0.81 builds each WebSocket client outside OkHttpClientProvider: this
        // hook alone decides its TLS, and a library could swap the socket factory in it.
        installOurs()
        WebSocketModule.setCustomClientBuilder { }
        val s = read()
        assertEquals(false, s.webSocketBuilderIsPinVault)
        assertFalse(s.pinned)
        assertTrue(s.describe(), s.describe().contains("WebSocketModule's custom client builder was replaced"))
    }

    @Test fun `cleared hooks and a missing install are not pinned`() {
        assertFalse(read().pinned)
        val notInstalled = read(installed = false)
        assertFalse(notInstalled.pinned)
        assertTrue(notInstalled.describe().contains("NOT pinned"))
    }

    @Test fun `an unreadable hook counts as not pinned`() {
        val s = HookStatus(true, null, true, true)
        assertFalse(s.pinned)
        assertTrue(s.describe().contains("could not be read"))
        assertFalse(HookStatus(true, true, true, null).pinned)
    }
}
