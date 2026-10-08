package com.example.sampleclientrn

import android.app.Application
import com.facebook.react.PackageList
import com.facebook.react.ReactApplication
import com.facebook.react.ReactHost
import com.facebook.react.ReactNativeApplicationEntryPoint.loadReactNative
import com.facebook.react.defaults.DefaultReactHost.getDefaultReactHost
import io.github.umutcansu.pinvault.reactnative.PinVaultNetworking

class MainApplication : Application(), ReactApplication {

  override val reactHost: ReactHost by lazy {
    getDefaultReactHost(
      context = applicationContext,
      packageList = PackageList(this).packages,
    )
  }

  override fun onCreate() {
    super.onCreate()
    // React Native'in kendi fetch / WebSocket istemcileri de PinVault'tan geçsin:
    // RN bunları bir kez kurar, bu yüzden React başlamadan önce. start() dönene
    // kadar https istekleri reddedilir (fail closed).
    PinVaultNetworking.install(this)
    loadReactNative(this)
  }
}
