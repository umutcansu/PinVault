package com.example.sampleclient;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

import java.util.List;
import java.util.Map;

import io.github.umutcansu.pinvault.PinVault;
import io.github.umutcansu.pinvault.model.UpdateResult;
import okhttp3.Request;

/**
 * Ana ekran: PinVault'un durumu ve modu, hedefe iki farklı client'la pinli
 * istek, config yenileme ve kütüphanenin bağlantı olayları. mTLS, Vault,
 * Depolama ve Ayarlar ekranlarına buradan geçilir.
 *
 * <p>{@code --es mode <MOD>} intent ekiyle açılırsa mod değiştirilip PinVault
 * yeniden kurulur (uçtan uca testler ve kısayollar için).
 */
public class MainActivity extends ActionActivity {

    public static final String EXTRA_MODE = "mode";

    private Button testButton;
    private Button prodStyleButton;
    private Button refreshButton;
    private TextView eventLogView;

    private final Runnable eventLogObserver = () -> ui.post(this::renderEventLog);
    private final Runnable initObserver = () -> ui.post(this::renderInitState);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusView = findViewById(R.id.statusView);
        testButton = findViewById(R.id.testButton);
        prodStyleButton = findViewById(R.id.prodStyleButton);
        refreshButton = findViewById(R.id.refreshButton);
        eventLogView = findViewById(R.id.eventLogView);
        Button clearLogButton = findViewById(R.id.clearLogButton);
        Button mtlsButton = findViewById(R.id.mtlsButton);
        Button vaultButton = findViewById(R.id.vaultButton);
        Button storageButton = findViewById(R.id.storageButton);
        Button settingsButton = findViewById(R.id.settingsButton);

        testButton.setOnClickListener(v -> runPinnedRequest());
        prodStyleButton.setOnClickListener(v -> runProductionStyleRequest());
        refreshButton.setOnClickListener(v -> onRefreshClicked());
        clearLogButton.setOnClickListener(v -> App.EVENT_LOG.clear());
        mtlsButton.setOnClickListener(v -> startActivity(new Intent(this, MtlsActivity.class)));
        vaultButton.setOnClickListener(v -> startActivity(new Intent(this, VaultActivity.class)));
        storageButton.setOnClickListener(v -> startActivity(new Intent(this, StorageActivity.class)));
        settingsButton.setOnClickListener(v -> startActivity(new Intent(this, SettingsActivity.class)));

        // Kütüphane callback'leri arka plan thread'inden gelir; UI'ya geç.
        App.EVENT_LOG.setObserver(eventLogObserver);
        App.INIT.addObserver(initObserver);
        renderEventLog();
        renderInitState();
        applyModeExtra(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        applyModeExtra(intent);
    }

    /** Intent'te mod verildiyse ve aktif moddan farklıysa uygular. */
    private void applyModeExtra(Intent intent) {
        String raw = intent == null ? null : intent.getStringExtra(EXTRA_MODE);
        if (raw == null) return;
        AppSettings.Mode mode;
        try {
            mode = AppSettings.Mode.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return;
        }
        if (mode != AppSettings.mode(this)) ((App) getApplication()).applyMode(mode);
    }

    // ── Durum ────────────────────────────────────────────────────────────────

    private void renderInitState() {
        InitState.Snapshot s = App.INIT.get();
        String mode = App.ACTIVE_MODE.label();
        switch (s.phase) {
            case INITIALIZING:
                statusView.setText(getString(R.string.status_initializing, mode, App.configSourceLabel()));
                refreshButton.setText(R.string.refresh_config);
                break;
            case READY:
                statusView.setText(getString(R.string.status_ready,
                        s.detail, mode, App.TARGET_HOST, App.configSourceLabel(), describeHostVersions(),
                        describeSigning()));
                refreshButton.setText(R.string.refresh_config);
                break;
            case FAILED:
                statusView.setText(getString(R.string.status_failed, s.detail, mode, App.configSourceLabel()));
                refreshButton.setText(R.string.retry_init);
                break;
        }
        updateButtons();
    }

    @Override
    protected void updateButtons() {
        InitState.Phase phase = App.INIT.get().phase;
        boolean ready = phase == InitState.Phase.READY;
        testButton.setEnabled(ready && !isBusy());
        prodStyleButton.setEnabled(ready && !isBusy());
        refreshButton.setEnabled(phase != InitState.Phase.INITIALIZING && !isBusy());
    }

    /**
     * Kütüphanenin şu anki imza doğrulaması: gereken imza sayısı, güvendiği
     * anahtarlar, uyguladığı anahtar seti ve son config'i imzalayan anahtar
     * kimlikleri (SHA-256(SPKI) — sunucunun GET /api/v1/signing-key'te
     * gösterdiği kimliklerle karşılaştırılabilir).
     */
    static String describeSigning(android.content.Context context) {
        io.github.umutcansu.pinvault.model.SigningStatus st;
        try {
            st = PinVault.INSTANCE.signingStatus(null);
        } catch (IllegalStateException e) {
            st = null;
        }
        if (st == null) return context.getString(R.string.signing_status_none);
        StringBuilder signers = new StringBuilder();
        for (String id : st.getLastConfigSignedBy()) {
            if (signers.length() > 0) signers.append(", ");
            signers.append(id, 0, Math.min(12, id.length())).append("…");
        }
        return context.getString(R.string.signing_status, st.getRequiredSignatures(),
                st.getTrustedKeyIds().size(), st.getKeySetVersion(),
                signers.length() > 0 ? signers.toString() : "—");
    }

    private String describeSigning() {
        return describeSigning(this);
    }

    private String describeHostVersions() {
        Map<String, Integer> versions = PinVault.INSTANCE.hostPinVersions();
        if (versions.isEmpty()) return getString(R.string.status_no_pins);
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Integer> e : versions.entrySet()) {
            if (sb.length() > 0) sb.append('\n');
            sb.append("• ").append(e.getKey()).append(" → pin v").append(e.getValue());
        }
        return sb.toString();
    }

    private void renderEventLog() {
        List<String> entries = App.EVENT_LOG.snapshot();
        eventLogView.setText(entries.isEmpty()
                ? getString(R.string.event_log_empty)
                : String.join("\n", entries));
    }

    // ── Library client ───────────────────────────────────────────────────────

    /**
     * Kendi OkHttpClient'ına PinVault'u bağlama: {@code applyTo()} hem pin
     * doğrulayan TrustManager'ı hem de pin uyuşmazlığında config'i tazeleyip
     * isteği tekrarlayan interceptor'ı kurar.
     */
    private void runPinnedRequest() {
        runAction(getString(R.string.connecting_fmt, App.TARGET_URL), () ->
                pinnedGet(pinnedClient(), App.TARGET_URL,
                        "Pinned bağlantı başarılı", "Bağlantı başarısız",
                        "TLS el sıkışması + pin doğrulaması geçti"));
    }

    // ── Production-style client ──────────────────────────────────────────────

    /**
     * PinVault'u import etmeyen bir network katmanı: pin'leri PinVault'tan
     * alan kendi {@code CertificatePinner}'ı ve kendi recovery interceptor'ı
     * var (bkz. {@link ProductionStyleClient}).
     */
    private void runProductionStyleRequest() {
        runAction(getString(R.string.connecting_fmt, App.TARGET_URL), () -> {
            Request req = new Request.Builder().url(App.TARGET_URL).build();
            try (okhttp3.Response resp = ProductionStyleClient.execute(req)) {
                return "✅ Production-style bağlantı başarılı\nHTTP " + resp.code()
                        + "\n(OkHttp CertificatePinner, pin'ler PinVault'tan)";
            } catch (Exception e) {
                return "❌ Production-style bağlantı başarısız\n"
                        + e.getClass().getSimpleName() + "\n" + e.getMessage();
            }
        });
    }

    // ── Config yenileme ──────────────────────────────────────────────────────

    private void onRefreshClicked() {
        if (App.INIT.get().phase == InitState.Phase.FAILED) {
            ((App) getApplication()).startPinVault();
            return;
        }
        runAction(getString(R.string.refreshing), () -> {
            UpdateResult result = PinManagerLite.updateNowBlocking(10L);
            String text;
            if (result instanceof UpdateResult.Updated) {
                App.bridgePinsToProductionStyleClient();
                text = getString(R.string.refresh_updated, ((UpdateResult.Updated) result).getNewVersion());
            } else if (result instanceof UpdateResult.Failed) {
                text = getString(R.string.refresh_failed, ((UpdateResult.Failed) result).getReason());
            } else if (result == null) {
                text = getString(R.string.refresh_timeout);
            } else {
                text = getString(R.string.refresh_current);
            }
            return text + "\n\n" + describeHostVersions() + "\n" + describeSigning();
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        App.EVENT_LOG.setObserver(null);
        App.INIT.removeObserver(initObserver);
    }
}
