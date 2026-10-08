package com.example.sampleclientrn

import android.app.Application
import com.facebook.react.PackageList
import com.facebook.react.ReactApplication
import com.facebook.react.ReactHost
import com.facebook.react.ReactNativeApplicationEntryPoint.loadReactNative
import com.facebook.react.defaults.DefaultReactHost.getDefaultReactHost

class MainApplication : Application(), ReactApplication {

  override val reactHost: ReactHost by lazy {
    getDefaultReactHost(
      context = applicationContext,
      packageList = PackageList(this).packages,
    )
  }

  override fun onCreate() {
    super.onCreate()
    // React Native'in kendi fetch / WebSocket / resim istemcileri PinVault'tan
    // geçer: eklentinin content provider'ı kancaları bu satırdan ÖNCE kurar
    // (PinVaultNetworking.install burada gerekmez). start() dönene kadar https
    // istekleri reddedilir (fail closed).
    loadReactNative(this)
  }
}
