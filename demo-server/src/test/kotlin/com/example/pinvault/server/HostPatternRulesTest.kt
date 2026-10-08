package com.example.pinvault.server

import com.example.pinvault.server.service.HostPatternRules
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** The server refuses the host names the Android library would refuse a whole config for. */
class HostPatternRulesTest {

    @Test
    fun `accepts host names, addresses, single-label wildcards and ports`() {
        for (ok in listOf("api.example.com", "192.168.1.10", "10.0.2.2", "*.example.com", "mock-tls.sample", "api.example.com:8443", "*.provisionpay.com")) {
            assertNull(HostPatternRules.error(ok), ok)
        }
    }

    @Test
    fun `refuses public-suffix wildcards, junk and bad ports`() {
        for (bad in listOf("", "*.com", "*.co.uk", "*.com.tr", "*.1", "a..b", "api_x.example.com", "api.example.com|9|x", "host\nx",
                "*.*.example.com", "api.example.com:0", "api.example.com:70000", "-api.example.com")) {
            assertNotNull(HostPatternRules.error(bad), bad)
        }
    }
}
