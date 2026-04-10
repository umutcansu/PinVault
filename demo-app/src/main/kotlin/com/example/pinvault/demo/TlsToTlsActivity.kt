package com.example.pinvault.demo

/**
 * Senaryo 1: TLS Config API → TLS Host
 * En basit senaryo — enrollment gerektirmez.
 */
class TlsToTlsActivity : BaseDemoActivity() {
    override val configServerUrl get() = "https://${HOST_IP}:8091/"
    override val mockServerUrl get() = "https://${HOST_IP}:${TLS_HOST_PORT}/health"
    override val bootstrapPins get() = DEFAULT_BOOTSTRAP_PINS
    override val activityTitle get() = getString(R.string.scenario_tls_tls_title)
    override val titleColorRes = R.color.status_success
    override val requiresEnrollment = false
}
