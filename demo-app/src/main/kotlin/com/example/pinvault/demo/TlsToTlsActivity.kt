package com.example.pinvault.demo

import io.github.umutcansu.pinvault.model.HostPin

/**
 * Senaryo 1: TLS Config API → TLS Host
 * En basit senaryo — enrollment gerektirmez.
 */
class TlsToTlsActivity : BaseDemoActivity() {
    override val configServerUrl = "https://10.0.2.2:8091/"
    override val mockServerUrl = "https://10.0.2.2:8443/health"
    override val bootstrapPins = PINS
    override val activityTitle get() = getString(R.string.scenario_tls_tls_title)
    override val titleColorRes = R.color.status_success
    override val requiresEnrollment = false

    companion object {
        private val PINS = listOf(
            HostPin("10.0.2.2", listOf(
                "D5HroN1Y5KX/pPfa9QlLJje1m9UrliVZ7pzFnhtQ3Qs=",
                "acl5V9h0WBlYJ5UaKx9+aERE71QUfbrUE28kh6HbnUQ="
            ))
        )
    }
}
