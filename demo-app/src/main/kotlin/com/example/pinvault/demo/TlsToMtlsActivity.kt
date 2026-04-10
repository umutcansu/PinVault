package com.example.pinvault.demo

/**
 * Senaryo 2: TLS Config API → mTLS Host
 * Config TLS ile çekilir, ardından otomatik enrollment ile client cert alınır.
 * mTLS host'a client cert ile bağlanılır.
 */
class TlsToMtlsActivity : BaseDemoActivity() {
    override val configServerUrl get() = "https://${HOST_IP}:8091/"
    override val mockServerUrl get() = "https://${HOST_IP}:8444/health"
    override val bootstrapPins get() = DEFAULT_BOOTSTRAP_PINS
    override val activityTitle get() = getString(R.string.scenario_tls_mtls_title)
    override val titleColorRes = R.color.accent_cyan
    override val requiresEnrollment = false
    override val autoEnrollForHost = true
}
