package com.example.sampleclientrn

import android.os.Bundle
import android.view.WindowManager
import com.facebook.react.ReactActivity
import com.facebook.react.ReactActivityDelegate
import com.facebook.react.defaults.DefaultNewArchitectureEntryPoint.fabricEnabled
import com.facebook.react.defaults.DefaultReactActivityDelegate

class MainActivity : ReactActivity() {

  override fun getMainComponentName(): String = "SampleClientRN"

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(null)
    // Ekran görüntüsü / kayıt / son uygulamalar önizlemesi yok: ekranlarda kimlik
    // ve vault içeriği görünür (MASVS-PLATFORM). Kanıt görüntüleri için yalnız
    // debug'da -Psample.e2eScreenshots=true kapatır.
    if (!BuildConfig.E2E_SCREENSHOTS) {
      window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    }
  }

  override fun createReactActivityDelegate(): ReactActivityDelegate =
      DefaultReactActivityDelegate(this, mainComponentName, fabricEnabled)
}
