package com.example.sampleclient

import android.content.Context
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.ClientCertEnrollmentResult
import kotlinx.coroutines.runBlocking

/**
 * Yalnızca debug ve e2e derlemelerinde (src/testControls): token'sız
 * "otomatik kayıt" köprüsü. Release derlemesinde bu dosya yoktur; uygulama
 * yalnızca yöneticinin verdiği token ya da kayıt koduyla kayıt olur.
 */
object TestEnrollment {

    /**
     * `PinVault.autoEnrollForResult` için senkron köprü: token yerine cihaz
     * kimliğiyle (ANDROID_ID) kayıt. Sunucu yalnızca `ENROLLMENT_MODE=open`
     * ya da kodsuz başvurular açıkken kabul eder. UI thread'inden çağırma.
     */
    @JvmStatic
    fun autoEnrollBlocking(context: Context): ClientCertEnrollmentResult =
        runBlocking { PinVault.autoEnrollForResult(context) }
}
