package com.example.sampleclient;

import android.util.Log;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Senin gerçek uygulamandaki <b>SoftPOSService</b> network katmanının
 * minimal aynası. Önemli kural: bu sınıf <i>PinVault import etmez</i> —
 * kendi {@link OkHttpClient}'ını kurar, pinlemeyi dışarıdan verilen bir
 * {@link PinningInstaller} takar. PinVault entegrasyonu app katmanında
 * ({@link App}) yapılır: {@code App} buraya {@code PinVault::applyTo}'yu verir.
 *
 * <p><b>Neden artık {@code okhttp3.CertificatePinner} değil?</b> Önceki sürüm
 * PinVault'un pin listesini kendi {@code CertificatePinner}'ına kopyalıyordu.
 * O sınıf, Frida/objection'daki hazır "SSL pinning bypass" betiklerinin
 * doğrudan hedeflediği sınıftır ({@code CertificatePinner.check} tek hook ile
 * kapanır); üstelik pin kontrolü yalnızca el sıkışmada çalışır ve
 * {@code requireCaTrust} gibi kütüphane korumaları ona ulaşmaz. PinVault'un
 * kendi trust manager'ı özel bir sınıftır, her istekte yeniden kontrol eder
 * ve pin değişince client yeniden kurulmadan yeni pinleri izler. Bu yüzden
 * "PinVault'u import etmeyen network katmanı" deseni korunur, ama pinleme
 * mekanizması kütüphaneninki olur.
 *
 * <p>Davranış:
 * <ul>
 *   <li>{@link #init(PinningInstaller)} — pinlemeyi takan geri çağrı ile
 *       client'ı bir kez kurar. PinVault'un {@code applyTo}'su pin-kurtarma
 *       interceptor'ını da takar: pin uyuşmazlığında config tazelenir ve istek
 *       bir kez yinelenir, burada ayrıca bir retry mantığı gerekmez.</li>
 *   <li>{@link #updatePins()} — yeni config geldiğinde çağrılır; canlı client
 *       zaten yeni pinleri izlediği için yalnızca açık bağlantıları kapatır
 *       (açık bir bağlantı el sıkıştığı sertifikayı taşımaya devam eder;
 *       kütüphanenin istek başına kontrolü onu zaten reddeder, boşaltmak
 *       gecikmeyi kaldırır).</li>
 * </ul>
 */
public final class ProductionStyleClient {

    /**
     * Bir {@link OkHttpClient.Builder}'a pinleme takan geri çağrı. Uygulama
     * katmanı {@code PinVault.INSTANCE::applyTo} verir; bu sınıf PinVault'u
     * tanımaz.
     */
    public interface PinningInstaller {
        void install(OkHttpClient.Builder builder);
    }

    private static final String TAG = "ProdStyleClient";

    /** Atomic referans — yeniden kurulumda yarış olmadan eski client'tan yeniye geçiş. */
    private static final AtomicReference<OkHttpClient> CLIENT = new AtomicReference<>();
    private static volatile PinningInstaller installer;

    private ProductionStyleClient() {}

    public static synchronized void init(PinningInstaller pinning) {
        installer = pinning;
        rebuild();
        Log.d(TAG, "Initialized — pinning installed by the app layer");
    }

    /**
     * Yeni bir pin config'i uygulandı. Client pinleri canlı okuduğu için
     * yeniden kurulması gerekmez; havuzdaki bağlantılar boşaltılır ki bir
     * sonraki istek yeni pinlerle el sıkışsın.
     */
    public static synchronized void updatePins() {
        OkHttpClient c = CLIENT.get();
        if (c == null) return;
        c.connectionPool().evictAll();
        Log.d(TAG, "Pins updated — pooled connections evicted, the live client follows the new config");
    }

    private static void rebuild() {
        PinningInstaller p = installer;
        if (p == null) throw new IllegalStateException("ProductionStyleClient needs a PinningInstaller");
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .dns(MockDns.INSTANCE);
        p.install(builder);
        CLIENT.set(builder.build());
    }

    public static Response execute(Request req) throws IOException {
        OkHttpClient c = CLIENT.get();
        if (c == null) throw new IllegalStateException("ProductionStyleClient not initialized");
        return c.newCall(req).execute();
    }
}
