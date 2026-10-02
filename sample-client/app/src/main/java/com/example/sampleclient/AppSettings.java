package com.example.sampleclient;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Uygulamanın kendi ayarları: çalışma modu, telemetri seçenekleri, elle
 * yüklenen P12. Gizli bir şey içermez; düz SharedPreferences'ta tutulur ve
 * süreç yeniden başlayınca korunur.
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

    private AppSettings() {}

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public static Mode mode(Context context) {
        try {
            return Mode.valueOf(prefs(context).getString(KEY_MODE, Mode.TLS.name()));
        } catch (IllegalArgumentException e) {
            return Mode.TLS;
        }
    }

    public static void setMode(Context context, Mode mode) {
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
     * Config çekilirken yalnızca hedef host'un pin'leri istensin mi
     * ({@code ConfigApiBlock.wantPinsFor}). Açıkken kütüphane isteğe
     * {@code ?hosts=<hedef>} ve {@code X-Device-Id} ekler; sunucu cihazın host
     * ACL'ine göre filtreler. ACL boşsa cihaz hiç pin alamaz ve config
     * reddedilir — pin kapsamının uçtan uca gösterimi.
     */
    /**
     * Config başına gereken imza sayısı (m-of-n). Varsayılan
     * sample-host.properties'teki host.requiredSignatures (yoksa 1).
     */
    public static int requiredSignatures(Context context) {
        return prefs(context).getInt(KEY_REQUIRED_SIGNATURES, BuildConfig.HOST_REQUIRED_SIGNATURES);
    }

    public static void setRequiredSignatures(Context context, int value) {
        prefs(context).edit().putInt(KEY_REQUIRED_SIGNATURES, value).apply();
    }

    public static boolean scopedPins(Context context) {
        return prefs(context).getBoolean(KEY_SCOPED_PINS, false);
    }

    public static void setScopedPins(Context context, boolean value) {
        prefs(context).edit().putBoolean(KEY_SCOPED_PINS, value).apply();
    }

    /** mTLS için kayıt yerine {@code files/manual-client.p12} kullanılsın mı. */
    public static boolean useManualP12(Context context) {
        return prefs(context).getBoolean(KEY_MANUAL_P12, false);
    }

    public static void setUseManualP12(Context context, boolean value) {
        prefs(context).edit().putBoolean(KEY_MANUAL_P12, value).apply();
    }
}
