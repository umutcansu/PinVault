package com.example.pinvault.demo

/**
 * Senaryo 4: mTLS Config API → mTLS Host
 * Hem config çekmek hem hedef sunucu için client cert lazım.
 */
class MtlsToMtlsActivity : BaseDemoActivity() {
    override val configServerUrl get() = "https://${HOST_IP}:8092/"
    override val mockServerUrl get() = "https://${HOST_IP}:8444/health"
    override val bootstrapPins get() = DEFAULT_BOOTSTRAP_PINS
    override val activityTitle get() = getString(R.string.scenario_mtls_mtls_title)
    override val titleColorRes = R.color.status_error
    override val requiresEnrollment = true
}
