package com.example.pinvault.server.plugin

import io.ktor.http.*
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pins the shape of the unauthenticated allowlist. The rules used to be
 * prefix-based, which silently exposed admin reads on the Config API ports:
 * `/vault/distributions`, `/vault/stats` and `/certificate-config/history/{host}`
 * all matched a "public" pattern and were served without X-API-Key.
 */
class ApiKeyAuthAllowlistTest {

    private fun public(path: String, method: HttpMethod = HttpMethod.Get) = isPublicEndpoint(path, method)

    @Test
    fun `device-facing endpoints stay public`() {
        assertTrue(public("/health"))
        assertTrue(public("/api/v1/certificate-config"))
        assertTrue(public("/api/v1/signing-key"))
        assertTrue(public("/api/v1/client-certs/enroll", HttpMethod.Post))
        assertTrue(public("/api/v1/client-certs/192.168.1.217/download"))
        assertTrue(public("/api/v1/vault/ml-model"))
        assertTrue(public("/api/v1/vault/feature.flags_v2"))
        assertTrue(public("/api/v1/vault/report", HttpMethod.Post))
        assertTrue(public("/api/v1/vault/devices/abc/public-key", HttpMethod.Post))
        assertTrue(public("/api/v1/connection-history/client-report", HttpMethod.Post))
        assertTrue(public("/api/v1/enrollment-mode"))
    }

    @Test
    fun `admin reads under the vault prefix are not public`() {
        assertFalse(public("/api/v1/vault/distributions"))
        assertFalse(public("/api/v1/vault/stats"))
        assertFalse(public("/api/v1/vault/distributions/ml-model"))
        assertFalse(public("/api/v1/vault/distributions/device/abc"))
        assertFalse(public("/api/v1/vault/ml-model/tokens"))
        // GET on the report path is not a download
        assertFalse(public("/api/v1/vault/report"))
    }

    @Test
    fun `config sub-paths and mutations are not public`() {
        assertFalse(public("/api/v1/certificate-config/history/api.example.com"))
        assertFalse(public("/api/v1/certificate-config", HttpMethod.Put))
        assertFalse(public("/api/v1/certificate-config/force-update", HttpMethod.Post))
        assertFalse(public("/api/v1/hosts/x/ping-remote"))
        assertFalse(public("/api/v1/hosts/x/clients"))
        assertFalse(public("/api/v1/connection-history/api.example.com"))
        assertFalse(public("/api/v1/vault/ml-model", HttpMethod.Put))
        assertFalse(public("/api/v1/vault/ml-model", HttpMethod.Delete))
        assertFalse(public("/api/v1/vault/ml-model/policy", HttpMethod.Put))
    }

    @Test
    fun `malformed vault keys are not public`() {
        assertFalse(public("/api/v1/vault/"))
        assertFalse(public("/api/v1/vault/a b"))
        assertFalse(public("/api/v1/vault/../etc"))
        assertFalse(public("/api/v1/vault/" + "k".repeat(65)))
    }
}
