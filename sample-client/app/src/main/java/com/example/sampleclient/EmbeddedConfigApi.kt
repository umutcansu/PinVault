package com.example.sampleclient

import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.EnrollmentResult
import io.github.umutcansu.pinvault.model.HostPin

/**
 * "Kendi backend'in" örneği: PinVault'un [CertificateConfigApi] arayüzünü
 * uygulayan, HTTP yapmayan bir kaynak. Gerçek uygulamada bu sınıf pin'leri
 * bir remote-config SDK'sından, kendi API'nden ya da imzalı bir asset'ten
 * okurdu. Kütüphane bu API'yi kullandığında kendi HTTP istemcisini hiç
 * çalıştırmaz; doğrulama, sürümleme ve periyodik yenileme aynen çalışır.
 *
 * Bu örnekte pin'ler derlemeye gömülü ([BuildConfig.TARGET_PINS]) ve sürüm
 * sabit 1'dir.
 */
class EmbeddedConfigApi(
    private val hostname: String,
    private val pins: List<String>,
) : CertificateConfigApi {

    override suspend fun healthCheck(): Boolean = true

    override suspend fun fetchConfig(currentVersion: Int): CertificateConfig =
        CertificateConfig(
            version = VERSION,
            pins = listOf(HostPin(hostname, pins, VERSION)),
        )

    override suspend fun downloadHostClientCert(hostname: String): ByteArray =
        throw UnsupportedOperationException("Gömülü API host'a özel istemci sertifikası sunmaz")

    override suspend fun downloadVaultFile(endpoint: String): ByteArray =
        throw UnsupportedOperationException("Gömülü API vault dosyası sunmaz")

    override suspend fun enroll(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
    ): EnrollmentResult = throw UnsupportedOperationException("Gömülü API kayıt desteklemez")

    companion object {
        const val VERSION = 1
    }
}
