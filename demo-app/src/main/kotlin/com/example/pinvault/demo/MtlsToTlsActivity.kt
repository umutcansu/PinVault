package com.example.pinvault.demo

import io.github.umutcansu.pinvault.model.HostPin

/**
 * Senaryo 3: mTLS Config API → TLS Host
 * Config çekmek için client cert lazım, hedef sunucu normal TLS.
 */
class MtlsToTlsActivity : BaseDemoActivity() {
    override val configServerUrl = "https://10.0.2.2:8092/"
    override val mockServerUrl = "https://10.0.2.2:8443/health"
    override val bootstrapPins = PINS
    override val activityTitle get() = getString(R.string.scenario_mtls_tls_title)
    override val titleColorRes = R.color.status_warning
    override val requiresEnrollment = true

    companion object {
        private val PINS = listOf(
            HostPin("10.0.2.2", listOf(
                "D5HroN1Y5KX/pPfa9QlLJje1m9UrliVZ7pzFnhtQ3Qs=",
                "acl5V9h0WBlYJ5UaKx9+aERE71QUfbrUE28kh6HbnUQ="
            ))
        )
    }
}
