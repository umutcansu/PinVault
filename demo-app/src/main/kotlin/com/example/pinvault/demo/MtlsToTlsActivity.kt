package com.example.pinvault.demo

/**
 * Senaryo 3: mTLS Config API → TLS Host
 * Config çekmek için client cert lazım, hedef sunucu normal TLS.
 */
class MtlsToTlsActivity : BaseDemoActivity() {
    override val configServerUrl get() = "https://${HOST_IP}:8092/"
    override val mockServerUrl get() = "https://${HOST_IP}:${TLS_HOST_PORT}/health"
    override val bootstrapPins get() = DEFAULT_BOOTSTRAP_PINS
    override val activityTitle get() = getString(R.string.scenario_mtls_tls_title)
    override val titleColorRes = R.color.status_warning
    override val requiresEnrollment = true
    /** Süresi dolmuş sertifika 8092'ye giremez; yenileme sunucunun kurtarma kapısından yapılır. */
    override val renewalUrl get() = "https://${HOST_IP}:${RECOVERY_PORT}/"
    /** Sertifikası olmayan cihaz 8092'ye giremez; ilk kayıt TLS portundan (8091) yapılır. */
    override val enrollmentUrl get() = "https://${HOST_IP}:8091/"
}
