package com.example.sampleclient;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import io.github.umutcansu.pinvault.PinVault;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Ekranların ortak iskeleti: bir düğmeye basınca işi arka planda çalıştırır,
 * sonucu durum kutusuna yazar ve iş sürerken düğmeleri kilitler.
 *
 * <p>Her sonucun altına "#&lt;sıra&gt; · saat" eklenir. Aynı sonuç art arda
 * geldiğinde de ekranın güncellendiği görülür; uçtan uca testler
 * (SamplePinVaultE2E) yeni sonucu eskisinden bununla ayırır.
 */
public abstract class ActionActivity extends AppCompatActivity {

    protected final ExecutorService io = Executors.newSingleThreadExecutor();
    protected final Handler ui = new Handler(Looper.getMainLooper());

    protected TextView statusView;

    private int actionSeq;
    private boolean busy;

    /** Düğmelerin etkinliğini günceller; her zaman UI thread'inde çağrılır. */
    protected abstract void updateButtons();

    protected boolean isBusy() {
        return busy;
    }

    protected void setBusy(boolean value) {
        busy = value;
        updateButtons();
    }

    /**
     * [action]'ı arka planda çalıştırır; dönen metin durum kutusuna yazılır.
     * Beklenmeyen bir hata da sonuç olarak gösterilir.
     */
    protected void runAction(String pendingText, Callable<String> action) {
        setBusy(true);
        statusView.setText(pendingText);
        io.execute(() -> {
            String text;
            try {
                text = action.call();
            } catch (Exception e) {
                Log.e(App.TAG, "Action failed", e);
                text = "❌ " + e.getClass().getSimpleName() + "\n" + e.getMessage();
            }
            showResult(text);
        });
    }

    protected void showResult(String text) {
        ui.post(() -> {
            actionSeq++;
            String time = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
            statusView.setText(text + "\n\n#" + actionSeq + " · " + time);
            setBusy(false);
        });
    }

    /**
     * PinVault ile pinlenmiş bir OkHttpClient. Cihaz mTLS için kayıtlıysa
     * istemci sertifikasını da sunar. Pin'ler her el sıkışmada güncel
     * config'ten okunur; config yokken bağlantıyı reddeder. Mock host adları
     * {@link MockDns} ile host IP'sine gider.
     */
    protected static OkHttpClient pinnedClient() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder().dns(MockDns.INSTANCE);
        PinVault.INSTANCE.applyTo(builder);
        return builder.build();
    }

    /**
     * [url]'ye pinli GET; sonucu "✅ [okLabel] HTTP n" ya da "❌ [failLabel]
     * &lt;hata&gt;" olarak döndürür. Önemli olan TLS el sıkışmasının ve pin
     * doğrulamasının geçmesidir; gövdeye yalnızca mTLS dinleyicisinin iptal
     * cevabı için bakılır.
     */
    protected static String pinnedGet(OkHttpClient client, String url, String okLabel, String failLabel, String okNote) {
        Request req = new Request.Builder().url(url).build();
        try (Response resp = client.newCall(req).execute()) {
            Log.d(App.TAG, url + " → " + resp.code());
            // mTLS dinleyicisi iptal edilmiş kimliği el sıkışmada değil, her
            // istekte reddeder (403 reenroll_required): bağlantı kuruldu ama
            // sertifika kabul edilmedi. Bunu "başarılı" göstermek yanlış olurdu.
            if (resp.code() == 403 && resp.body() != null && resp.body().string().contains("reenroll_required")) {
                return "❌ " + failLabel + "\nHTTP 403\n(sertifika kabul edilmedi: kimlik iptal edilmiş, yeniden kayıt gerekli)";
            }
            return "✅ " + okLabel + "\nHTTP " + resp.code() + "\n(" + okNote + ")";
        } catch (Exception e) {
            Log.e(App.TAG, url + " failed", e);
            return "❌ " + failLabel + "\n" + e.getClass().getSimpleName() + "\n" + e.getMessage();
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        io.shutdown();
    }
}
