package com.example.sampleclient

import android.content.Context
import android.util.Log
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.ClientCertEnrollmentResult
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.PinVaultConfig
import io.github.umutcansu.pinvault.model.ScheduledTaskInfo
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.model.VaultFileResult
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Gerçek uygulamadaki `PinManager`'ın sample karşılığı. İki görevi var:
 *
 *  1. PinVault'un suspend API'lerini Java'dan senkron çağrılabilir yapmak
 *     (arka plan thread'lerinde bloklamak güvenli).
 *  2. Yeni config geldiğinde [ProductionStyleClient]'a haber vermek (client
 *     pinleri canlı izler; açık bağlantıları boşaltır).
 */
object PinManagerLite {
    private const val TAG = "PinManagerLite"

    /**
     * `PinVault.updateNow()` sonucunu senkron döndürür. Zaman aşımında `null`.
     * PinVault henüz başlatılmadıysa [UpdateResult.Failed] döner.
     * UI thread'inden çağırma.
     */
    @JvmStatic
    @JvmOverloads
    fun updateNowBlocking(timeoutSeconds: Long = 10L): UpdateResult? = try {
        runBlocking {
            withTimeoutOrNull(timeoutSeconds * 1000) { PinVault.updateNow() }
        }
    } catch (e: IllegalStateException) {
        UpdateResult.Failed(e.message ?: "PinVault not initialized", e)
    }

    /**
     * `PinVault.enrollForResult` için senkron köprü: token ile istemci
     * sertifikası alır, doğrular, şifreli saklar ve pinli client'a yükler.
     * Olmazsa nedenini döndürür (token kullanılmış, cihaz başka kimlikle
     * kayıtlı, kimlik iptal edilmiş, sunucuya ulaşılamadı…).
     * UI thread'inden çağırma.
     */
    @JvmStatic
    fun enrollBlocking(context: Context, token: String): ClientCertEnrollmentResult =
        runBlocking { PinVault.enrollForResult(context, token) }

    /**
     * `PinVault.checkPendingEnrollment` için senkron köprü: kayıt kodu onay
     * bekliyorsa yönetici onayladı mı diye bir kez sorar. Onaylandıysa
     * sertifika saklanır ve pinli client'a yüklenir. UI thread'inden çağırma.
     */
    @JvmStatic
    fun checkPendingBlocking(context: Context): ClientCertEnrollmentResult =
        runBlocking { PinVault.checkPendingEnrollment(context) }

    /**
     * `PinVault.fetchFile` için senkron köprü. PinVault henüz başlatılmadıysa
     * [VaultFileResult.Failed] döner. UI thread'inden çağırma.
     */
    @JvmStatic
    fun fetchFileBlocking(key: String): VaultFileResult = try {
        runBlocking { PinVault.fetchFile(key) }
    } catch (e: IllegalStateException) {
        VaultFileResult.Failed(key, e.message ?: "PinVault not initialized", e)
    }

    /**
     * `PinVault.syncAllFiles` için senkron köprü: yalnızca `updateWithPins`
     * açık dosyalar çekilir. Anahtar → sonuç.
     */
    @JvmStatic
    fun syncAllBlocking(): Map<String, VaultFileResult> = try {
        runBlocking { PinVault.syncAllFiles() }
    } catch (e: IllegalStateException) {
        emptyMap()
    }

    /** `PinVault.getScheduledWorkInfo` için senkron köprü (WorkManager işleri). */
    @JvmStatic
    fun scheduledWorkBlocking(timeoutMs: Long = 5_000): List<ScheduledTaskInfo> {
        val latch = CountDownLatch(1)
        var result: List<ScheduledTaskInfo> = emptyList()
        PinVault.getScheduledWorkInfo { list ->
            result = list
            latch.countDown()
        }
        latch.await(timeoutMs, TimeUnit.MILLISECONDS)
        return result
    }

    /**
     * Sunucusuz (statik) PinVault yapılandırması: pin'ler APK'ya gömülü,
     * hiçbir sunucuya bağlanılmaz. [requireCaTrust] açıksa host'un sertifikası
     * pin'e ek olarak sistemin CA'larından da geçmeli (herkesin güvendiği bir
     * CA'dan sertifikası olan hedefler için).
     */
    @JvmStatic
    fun staticConfig(hostPattern: String, pins: List<String>, requireCaTrust: Boolean): PinVaultConfig =
        PinVaultConfig.Builder()
            .staticPins(CertificateConfig(pins = listOf(HostPin(hostPattern, pins)), forceUpdate = false))
            .apply { if (requireCaTrust) requireCaTrust(hostPattern) }
            .build()

    /**
     * Config'i hemen tazeler (örneğin kullanıcı "Yenile"ye bastığında).
     * Pin uyuşmazlığındaki otomatik kurtarma artık PinVault'un kendi
     * interceptor'ındadır ([ProductionStyleClient] de onu kullanır).
     *
     * @return yeni bir config uygulandıysa `true`; aksi halde `false`.
     */
    @JvmStatic
    @JvmOverloads
    fun refreshNowBlocking(timeoutSeconds: Long = 5L): Boolean =
        when (val result = updateNowBlocking(timeoutSeconds)) {
            is UpdateResult.Updated -> {
                Log.d(TAG, "refresh OK → updated to v${result.newVersion}")
                // setOnUpdateListener asenkron tetiklenir; açık bağlantılar
                // hemen boşalsın diye burada senkron haber ver.
                App.bridgePinsToProductionStyleClient()
                true
            }
            is UpdateResult.AlreadyCurrent -> {
                // Sunucu aynı config'i veriyorsa retry anlamsız: uyuşmazlık sürer.
                Log.d(TAG, "refresh OK → server returned the same version")
                false
            }
            is UpdateResult.Failed -> {
                Log.w(TAG, "refresh failed: ${result.reason}")
                false
            }
            null -> {
                Log.w(TAG, "refresh timed out after ${timeoutSeconds}s")
                false
            }
        }
}
