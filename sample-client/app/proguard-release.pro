# Yalnızca release derlemesi (app/build.gradle.kts → buildTypes.release).
#
# Log'lar yayın derlemesinde SİLİNİR: teşhis satırları host adlarını, pin
# öneklerini, kimlikleri ve hata ayrıntılarını taşır; telefonda adb ya da log
# okuyabilen başka bir araç bunları görmesin. R8 aşağıdaki çağrıları yan
# etkisiz sayar ve koddan çıkarır (parametre olarak kurulan metinler de gider).
#
# Kalanlar: Log.w ve Log.e (gerçek hatalar). Uçtan uca testlerin derlemesi (e2e)
# bu dosyayı ALMAZ; senaryolar uygulamayı logcat'ten izler.

-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
}

# PinVault teşhis log'larını Timber ile yazar. Release'te ağaç (DebugTree) zaten
# dikilmez (App.onCreate); çağrıların kendisi de koddan çıkarılır.
-assumenosideeffects class timber.log.Timber {
    public static void v(...);
    public static void d(...);
    public static void i(...);
}
-assumenosideeffects class timber.log.Timber$Forest {
    public void v(...);
    public void d(...);
    public void i(...);
}
-assumenosideeffects class timber.log.Timber$Tree {
    public void v(...);
    public void d(...);
    public void i(...);
}
