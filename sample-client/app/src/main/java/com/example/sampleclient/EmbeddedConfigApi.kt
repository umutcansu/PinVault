package com.example.sampleclient

import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.EnrollmentResult
import io.github.umutcansu.pinvault.model.HostPin

/**
 * PinVault'un [CertificateConfigApi] arayüzünü uygulayan, HTTP yapmayan bir
 * kaynak: pin'ler derlemeye gömülü ([BuildConfig.TARGET_PINS]) ve sürüm sabit
 * 1'dir. Kütüphane bu API'yi kullandığında kendi HTTP istemcisini hiç
 * çalıştırmaz. Yalnızca test derlemelerinde seçilebilen "gömülü API" modunda
 * kullanılır.
 *
 * ## Ne doğrulanır, ne doğrulanmaz
 *
 * - **İmza DOĞRULANMAZ.** [fetchConfig] hazır, ayrıştırılmış bir
 *   [CertificateConfig] döndürür; ortada kütüphanenin doğrulayabileceği imzalı
 *   bir zarf yoktur. Bu yüzden bu API'yi kullanan blok `allowUnsigned()` ile
 *   kurulur (bkz. `App.startEmbeddedApi`): imza, `issuedAt`/`expiresAt`, tekrar
 *   oynatma (replay) ve sürüm düşürme kontrolleri YOKTUR, saklanan config'in de
 *   bütünlük kontrolü yoktur.
 * - Kütüphane yine de her config'te host adlarının ve pin'lerin biçimini
 *   denetler (en az iki farklı pin, geçerli Base64) ve pin'leri her bağlantıda
 *   uygular.
 * - Burada bu kabul edilebilir, çünkü pin'ler APK'nın içinden geliyor: güven
 *   APK'nın kendisine, yani uygulamanın imzasına dayanıyor. Pin'i değiştirmek
 *   isteyen APK'yı değiştirmek zorunda.
 *
 * ## Pin'leri uzaktan getiren kendi backend'in için
 *
 * Bu sınıfı kopyalayıp `fetchConfig` içinde bir remote-config SDK'sından ya da
 * kendi API'nden pin okumak YANLIŞTIR: o kaynağa yazabilen (ya da o kanalı
 * değiştirebilen) biri kendi pin'ini yayınlar ve bütün trafiği dinler; hiçbir
 * imza kontrolü onu durdurmaz. Doğrusu:
 *
 * 1. Backend config'i imzalı zarf olarak versin (`{"payload": "...",
 *    "signature": "..."}`; payload içinde `issuedAt` ve `expiresAt`).
 * 2. API sınıfın [io.github.umutcansu.pinvault.api.SignedConfigSource]'u da
 *    uygulasın ve zarfı bayt bayt aynen kütüphaneye versin.
 * 3. Blok `signaturePublicKey(...)` taşısın, `allowUnsigned()` çağrılmasın.
 *
 * O zaman kütüphane zarfı kendi HTTP istemcisinde yaptığı gibi doğrular. İmza
 * anahtarı olan bir blok, `SignedConfigSource` uygulamayan özel bir API ile
 * `allowUnsigned()` çağrılmadan kurulursa `PinVault.init` hata verir: imzalı
 * görünüp doğrulanmayan bir kurulum sessizce çalışmaz.
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
