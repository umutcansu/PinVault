package com.example.sampleclient

import android.content.Context
import android.util.Log
import io.github.umutcansu.pinvault.PinVault
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
 *  2. Yeni config geldiğinde [ProductionStyleClient]'a yeni pin listesini
 *     aktarmak.
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
     * `PinVault.enroll` için senkron köprü: token ile istemci sertifikası
     * alır, doğrular, şifreli saklar ve pinli client'a yükler.
     * UI thread'inden çağırma.
     */
    @JvmStatic
    fun enrollBlocking(context: Context, token: String): Boolean =
        runBlocking { PinVault.enroll(context, token) }

    /**
     * `PinVault.autoEnroll` için senkron köprü: token yerine cihaz kimliğiyle
     * (ANDROID_ID) kayıt. Sunucu yalnızca `ENROLLMENT_MODE=open` iken kabul eder.
     */
    @JvmStatic
    fun autoEnrollBlocking(context: Context): Boolean =
        runBlocking { PinVault.autoEnroll(context) }

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
     * hiçbir sunucuya bağlanılmaz. Kotlin'deki `PinVaultConfig.static` Java'dan
     * çağrılamaz (`static` anahtar sözcük), köprü burada.
     */
    @JvmStatic
    fun staticConfig(hostPattern: String, pins: List<String>): PinVaultConfig =
        PinVaultConfig.static(HostPin(hostPattern, pins))

    /**
     * Pin uyuşmazlığında [ProductionStyleClient]'ın interceptor'ı çağırır.
     *
     * @return yeni bir config uygulandıysa `true` (interceptor isteği bir kez
     *         yeni pin'lerle tekrarlar); aksi halde `false`.
     */
    @JvmStatic
    @JvmOverloads
    fun refreshNowBlocking(timeoutSeconds: Long = 5L): Boolean =
        when (val result = updateNowBlocking(timeoutSeconds)) {
            is UpdateResult.Updated -> {
                Log.d(TAG, "refresh OK → updated to v${result.newVersion}")
                // setOnUpdateListener asenkron tetiklenir; retry yeni pin'lerle
                // yapılsın diye pinner'ı burada senkron güncelle.
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
