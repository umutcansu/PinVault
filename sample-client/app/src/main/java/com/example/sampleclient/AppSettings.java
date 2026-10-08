package com.example.sampleclient;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Uygulamanın kendi ayarları: çalışma modu, telemetri seçenekleri, elle
 * yüklenen P12. Gizli bir şey içermez; düz SharedPreferences'ta tutulur ve
 * süreç yeniden başlayınca korunur.
 *
 * <p><b>Release derlemesinde</b> ({@code BuildConfig.TEST_CONTROLS == false})
 * buradaki tercihler güvenliği etkileyemez: mod her zaman {@link Mode#TLS},
 * gereken imza sayısı her zaman derlemeye gömülü değer, pin kapsamı ve elle
 * P12 kapalı, üç yerel sertleştirme katmanı (ortam kontrolü, kilitli cihaz,
 * donanım anahtarı) her zaman açıktır; tercih dosyasında ne yazdığına
 * bakılmaz. Onları değiştiren ekran (Ayarlar) da yalnızca test
 * derlemelerinde vardır.
 */
public final class AppSettings {

    /** PinVault'un nasıl kurulacağı. {@link App#startPinVault()} buna göre config üretir. */
    public enum Mode {
        /** TLS Config API'den imzalı config (varsayılan). Kayıtlıysa mTLS bloğu da eklenir. */
        TLS,
        /** Config mTLS Config API üzerinden, kayıtlı istemci sertifikasıyla çekilir. */
        MTLS_CONFIG,
        /** Özel uç yollarıyla başka bir backend (sample-e2e/lib/custom-backend.js). */
        CUSTOM_BACKEND,
        /** Kütüphaneden HTTP çıkmaz: config uygulama içindeki {@code CertificateConfigApi}'den. */
        EMBEDDED_API,
        /** Sunucusuz: APK'ya gömülü statik pin'ler. */
        STATIC;

        public String label() {
            switch (this) {
                case MTLS_CONFIG: return "mTLS config";
                case CUSTOM_BACKEND: return "özel backend";
                case EMBEDDED_API: return "gömülü API";
                case STATIC: return "statik pin'ler";
                default: return "TLS config";
            }
        }
    }

    private static final String PREFS = "sample_settings";
    private static final String KEY_MODE = "mode";
    private static final String KEY_REPORT_SUCCESS = "telemetry_report_success";
    private static final String KEY_DEDUP_MS = "telemetry_dedup_ms";
    private static final String KEY_MANUAL_P12 = "mtls_manual_p12";
    private static final String KEY_SCOPED_PINS = "scoped_pins";
    private static final String KEY_REQUIRED_SIGNATURES = "required_signatures";
    private static final String KEY_ENVIRONMENT_GUARD = "environment_guard";
    private static final String KEY_UNLOCKED_DEVICE = "require_unlocked_device";
    private static final String KEY_HARDWARE_KEYS = "require_hardware_keys";

    private AppSettings() {}

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    /**
     * Çalışma modu. Release'te her zaman {@link Mode#TLS}: diğer modlar
     * (statik, gömülü, özel backend) uygulamayı sunucunun pin güncellemelerinden
     * ve iptalden koparabildiği için yalnızca test derlemelerinde seçilebilir.
     */
    public static Mode mode(Context context) {
        if (!BuildConfig.TEST_CONTROLS) return Mode.TLS;
        try {
            return Mode.valueOf(prefs(context).getString(KEY_MODE, Mode.TLS.name()));
        } catch (IllegalArgumentException e) {
            return Mode.TLS;
        }
    }

    public static void setMode(Context context, Mode mode) {
        if (!BuildConfig.TEST_CONTROLS) return;
        prefs(context).edit().putString(KEY_MODE, mode.name()).apply();
    }

    /** Başarılı el sıkışmalar da dashboard'a raporlansın mı (varsayılan evet). */
    public static boolean reportSuccess(Context context) {
        return prefs(context).getBoolean(KEY_REPORT_SUCCESS, true);
    }

    /** Aynı host + pin + sürüm için tekrar eden raporların bastırılma penceresi (ms). */
    public static long dedupMs(Context context) {
        return prefs(context).getLong(KEY_DEDUP_MS, 0L);
    }

    public static void setTelemetry(Context context, boolean reportSuccess, long dedupMs) {
        prefs(context).edit()
                .putBoolean(KEY_REPORT_SUCCESS, reportSuccess)
                .putLong(KEY_DEDUP_MS, Math.max(0L, dedupMs))
                .apply();
    }

    /**
     * Config başına gereken imza sayısı (m-of-n). Taban, derlemeye gömülü
     * değerdir (sample-host.properties → host.requiredSignatures) ve hiçbir
     * derlemede altına inilmez: tercih yalnızca YÜKSELTEBİLİR. Release'te
     * tercih hiç okunmaz. Böylece telefondaki bir ayar (ya da tercih dosyasını
     * değiştirebilen biri) "iki imza" şartını bire düşüremez.
     */
    public static int requiredSignatures(Context context) {
        int floor = Math.max(1, BuildConfig.HOST_REQUIRED_SIGNATURES);
        if (!BuildConfig.TEST_CONTROLS) return floor;
        return Math.max(floor, prefs(context).getInt(KEY_REQUIRED_SIGNATURES, floor));
    }

    public static void setRequiredSignatures(Context context, int value) {
        if (!BuildConfig.TEST_CONTROLS) return;
        prefs(context).edit().putInt(KEY_REQUIRED_SIGNATURES, value).apply();
    }

    /**
     * Config çekilirken yalnızca hedef host'un pin'leri istensin mi
     * ({@code ConfigApiBlock.wantPinsFor}). Açıkken kütüphane isteğe
     * {@code ?hosts=<hedef>} ve {@code X-Device-Id} ekler; sunucu cihazın host
     * ACL'ine göre filtreler. ACL boşsa cihaz hiç pin alamaz ve config
     * reddedilir — pin kapsamının uçtan uca gösterimi. Test kontrolü.
     */
    public static boolean scopedPins(Context context) {
        return BuildConfig.TEST_CONTROLS && prefs(context).getBoolean(KEY_SCOPED_PINS, false);
    }

    public static void setScopedPins(Context context, boolean value) {
        if (!BuildConfig.TEST_CONTROLS) return;
        prefs(context).edit().putBoolean(KEY_SCOPED_PINS, value).apply();
    }

    // ── Yerel sertleştirme ──────────────────────────────────────────────────
    //
    // Üç katman release'te HER ZAMAN açıktır ve kapatılamaz. Test derlemelerinde
    // Ayarlar'dan açılıp kapanır ve varsayılan KAPALIdır: uçtan uca testler su
    // taşıyan userdebug emülatör imajlarında (ortam kontrolü onları "root'lu"
    // sayar) ve güvenli donanımı olmayan emülatörlerde koşar.

    /**
     * {@link DeviceShield} kararı PinVault'un {@code environmentGuard}'ına
     * gitsin mi: açıkken root / debugger / hooking görülen telefonda kayıt,
     * dosya indirme ve dosya açma reddedilir ({@code init} hep geçer).
     */
    public static boolean environmentGuard(Context context) {
        if (!BuildConfig.TEST_CONTROLS) return true;
        return prefs(context).getBoolean(KEY_ENVIRONMENT_GUARD, false);
    }

    public static void setEnvironmentGuard(Context context, boolean value) {
        if (!BuildConfig.TEST_CONTROLS) return;
        prefs(context).edit().putBoolean(KEY_ENVIRONMENT_GUARD, value).apply();
    }

    /**
     * {@code requireUnlockedDevice()}: bundan sonra üretilen Keystore anahtarları
     * yalnızca telefonun kilidi açıkken çalışır (Android 9+). Keystore böyle bir
     * anahtar yapamazsa işlem reddedilir, sessizce bayraksız anahtar üretilmez.
     */
    public static boolean requireUnlockedDevice(Context context) {
        if (!BuildConfig.TEST_CONTROLS) return true;
        return prefs(context).getBoolean(KEY_UNLOCKED_DEVICE, false);
    }

    public static void setRequireUnlockedDevice(Context context, boolean value) {
        if (!BuildConfig.TEST_CONTROLS) return;
        prefs(context).edit().putBoolean(KEY_UNLOCKED_DEVICE, value).apply();
    }

    /**
     * {@code requireHardwareBackedKeys()}: Keystore'un yazılımda ürettiği bir
     * anahtar silinir ve işlem reddedilir. Emülatörde güvenli donanım yoktur;
     * test derlemelerinde bu yüzden varsayılan kapalı.
     */
    public static boolean requireHardwareBackedKeys(Context context) {
        if (!BuildConfig.TEST_CONTROLS) return true;
        return prefs(context).getBoolean(KEY_HARDWARE_KEYS, false);
    }

    public static void setRequireHardwareBackedKeys(Context context, boolean value) {
        if (!BuildConfig.TEST_CONTROLS) return;
        prefs(context).edit().putBoolean(KEY_HARDWARE_KEYS, value).apply();
    }

    /** mTLS için kayıt yerine {@code files/manual-client.p12} kullanılsın mı. Test kontrolü. */
    public static boolean useManualP12(Context context) {
        return BuildConfig.TEST_CONTROLS && prefs(context).getBoolean(KEY_MANUAL_P12, false);
    }

    public static void setUseManualP12(Context context, boolean value) {
        if (!BuildConfig.TEST_CONTROLS) return;
        prefs(context).edit().putBoolean(KEY_MANUAL_P12, value).apply();
    }
}
