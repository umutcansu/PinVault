package com.example.sampleclient;

import android.util.Log;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;

import okhttp3.CertificatePinner;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Senin gerçek uygulamandaki <b>SoftPOSService</b> network katmanının
 * minimal aynası. Önemli kural: bu sınıf <i>PinVault import etmez</i> —
 * pin'leri dışarıdan {@code List&lt;String&gt;} olarak alır, kendi
 * {@link CertificatePinner}'ını kurar. PinVault entegrasyonu app
 * katmanında ({@link App} + {@link PinManagerLite}) yapılır.
 *
 * <p>Davranış:
 * <ul>
 *   <li>{@link #init(String, List, PinMismatchHandler)} — host + pin listesi +
 *       mismatch handler. Pinner'ı build eder, interceptor'ı ekler.</li>
 *   <li>{@link #updatePins(String, List)} — runtime'da yeni pin set'i ile
 *       client'ı yeniden kurar (atomic swap).</li>
 *   <li>{@link RecoveryInterceptor} — handshake fail olunca handler'a
 *       refresh fırsatı verir. Handler {@code true} dönerse, güncellenmiş
 *       client ile request'i bir kez retry'lar.</li>
 * </ul>
 */
public final class ProductionStyleClient {

    public interface PinMismatchHandler {
        /**
         * SSL handshake mismatch oldu. Handler yeni pin'leri çekip
         * {@link ProductionStyleClient#updatePins} ile push'lamalı.
         *
         * @return refresh başarılıysa {@code true} (interceptor retry eder);
         *         {@code false} ise interceptor orijinal exception'ı yukarı atar.
         */
        boolean refresh(String hostname);
    }

    private static final String TAG = "ProdStyleClient";

    /** Atomic referans — pin update'inde yarış olmadan eski client'tan yeniye geçiş. */
    private static final AtomicReference<OkHttpClient> CLIENT = new AtomicReference<>();
    private static volatile PinMismatchHandler handler;
    private static volatile String pinnedHost;

    private ProductionStyleClient() {}

    public static synchronized void init(String host, List<String> pins, PinMismatchHandler h) {
        pinnedHost = host;
        handler = h;
        rebuild(host, pins);
        Log.d(TAG, "Initialized — host=" + host + ", pins=" + pins.size());
    }

    public static synchronized void updatePins(String host, List<String> pins) {
        rebuild(host, pins);
        Log.d(TAG, "Pinner updated — host=" + host + ", pins=" + pins.size());
    }

    private static void rebuild(String host, List<String> pins) {
        CertificatePinner.Builder cpb = new CertificatePinner.Builder();
        for (String p : pins) cpb.add(host, "sha256/" + p);
        OkHttpClient newClient = new OkHttpClient.Builder()
                .dns(MockDns.INSTANCE)
                .certificatePinner(cpb.build())
                .addInterceptor(new RecoveryInterceptor())
                .build();
        CLIENT.set(newClient);
    }

    public static Response execute(Request req) throws IOException {
        OkHttpClient c = CLIENT.get();
        if (c == null) throw new IllegalStateException("ProductionStyleClient not initialized");
        return c.newCall(req).execute();
    }

    /**
     * Recovery retry, aynı interceptor zincirinden geçtiği için (newCall →
     * intercept), guard olmazsa fail edince yine RecoveryInterceptor tetiklenir
     * → sonsuz döngü. Thread-local boolean ile sadece request başına TEK retry'a
     * izin verir.
     */
    private static final ThreadLocal<Boolean> RETRYING = new ThreadLocal<>();

    private static final class RecoveryInterceptor implements Interceptor {
        @Override
        public Response intercept(Chain chain) throws IOException {
            Request req = chain.request();
            // Retry sırasındayız — recovery'i bir daha tetikleme, direkt proceed.
            if (Boolean.TRUE.equals(RETRYING.get())) {
                return chain.proceed(req);
            }
            try {
                return chain.proceed(req);
            } catch (SSLPeerUnverifiedException | SSLHandshakeException e) {
                Log.w(TAG, "TLS error — attempting auto-recovery: " + e.getMessage());
                PinMismatchHandler h = handler;
                String host = pinnedHost;
                if (h == null) {
                    Log.w(TAG, "No mismatch handler — surfacing error");
                    throw e;
                }
                boolean refreshed = h.refresh(host);
                if (!refreshed) {
                    Log.w(TAG, "Recovery refresh failed — surfacing original error");
                    throw e;
                }
                Log.d(TAG, "Pinner refreshed — retrying request once with new client");
                RETRYING.set(Boolean.TRUE);
                try {
                    return CLIENT.get().newCall(req).execute();
                } finally {
                    RETRYING.remove();
                }
            }
        }
    }
}
