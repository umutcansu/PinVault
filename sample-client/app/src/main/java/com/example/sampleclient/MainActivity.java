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
 * <p>Depolama ve Ayarlar yalnızca test derlemelerinde (debug, e2e) vardır; aynı
 * derlemelerde {@code --es mode <MOD>} intent ekiyle açılırsa mod değiştirilip
 * PinVault yeniden kurulur ({@link TestControls}). Release derlemesi dışarıdan
 * gelen hiçbir intent ekini okumaz.
 */
public class MainActivity extends ActionActivity {

    private Button testButton;
    private Button prodStyleButton;
    private Button refreshButton;
    private Button attestButton;
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
        attestButton = findViewById(R.id.attestButton);
        eventLogView = findViewById(R.id.eventLogView);
        Button clearLogButton = findViewById(R.id.clearLogButton);
        Button mtlsButton = findViewById(R.id.mtlsButton);
        Button vaultButton = findViewById(R.id.vaultButton);

        testButton.setOnClickListener(v -> runPinnedRequest());
        prodStyleButton.setOnClickListener(v -> runProductionStyleRequest());
        refreshButton.setOnClickListener(v -> onRefreshClicked());
        attestButton.setOnClickListener(v -> runAttestation());
        clearLogButton.setOnClickListener(v -> App.EVENT_LOG.clear());
        mtlsButton.setOnClickListener(v -> startActivity(new Intent(this, MtlsActivity.class)));
        vaultButton.setOnClickListener(v -> startActivity(new Intent(this, VaultActivity.class)));
        // Depolama ve Ayarlar: test derlemelerinde gösterilir, release'te satır gizli kalır.
        TestControls.bindNavigation(this, findViewById(R.id.testControlsRow),
                findViewById(R.id.storageButton), findViewById(R.id.settingsButton));

        // Kütüphane callback'leri arka plan thread'inden gelir; UI'ya geç.
        App.EVENT_LOG.setObserver(eventLogObserver);
        App.INIT.addObserver(initObserver);
        renderEventLog();
        renderInitState();
        TestControls.applyLaunchIntent(this, getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        TestControls.applyLaunchIntent(this, intent);
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
                        describeSigning(), describeAttestation()));
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
        attestButton.setEnabled(ready && !isBusy() && BuildConfig.HOST_ATTESTATION);
    }

    // ── Atestasyon ───────────────────────────────────────────────────────────

    /**
     * Son atestasyon turu: geçti mi, kaldıysa ARC ve (politika açıklıyorsa)
     * nedenler, token'ın süresi. Kütüphane turu kendisi 5 dakikada bir yineler;
     * burada yalnızca okunur.
     */
    private String describeAttestation() {
        if (!BuildConfig.HOST_ATTESTATION) return getString(R.string.attestation_status_off);
        io.github.umutcansu.pinvault.model.AttestationStatus st = PinManagerLite.attestationStatusOrNull();
        if (st == null) return getString(R.string.attestation_status_none);
        switch (st.getResult()) {
            case PASS:
                return getString(R.string.attestation_status_pass, st.getArc(), time(st.getTokenExpiresAt()),
                        st.getWarnings().isEmpty() ? "" : " · uyarı: " + String.join(",", st.getWarnings()));
            case REJECT:
                return getString(R.string.attestation_status_reject, st.getArc(),
                        st.getRejectionReasons().isEmpty() ? "(sunucu açıklamıyor)" : String.join(",", st.getRejectionReasons()));
            case FAILED:
                return getString(R.string.attestation_status_failed, st.getLastError() == null ? "?" : st.getLastError());
            case UNSUPPORTED:
                return getString(R.string.attestation_status_unsupported);
            default:
                return getString(R.string.attestation_status_none);
        }
    }

    private static String time(Long epochMs) {
        if (epochMs == null) return "?";
        return new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(new java.util.Date(epochMs));
    }

    /**
     * Approov akışının tamamı tek düğmede: raporu şimdi ölçüp gönder, token'ı
     * al, token'lı isteği host'taki mock TLS hedefine at. Host
     * MOCK_HOST_REQUIRE_TOKEN=true ile çalışıyorsa token'sız (kalmış) bir
     * cihaz 401 alır; kütüphane token'ı kendisi eklediği için uygulama kodu
     * başlığa dokunmaz.
     */
    private void runAttestation() {
        runAction(getString(R.string.attesting), () -> {
            io.github.umutcansu.pinvault.model.AttestationStatus st = PinManagerLite.attestNowBlocking(20L);
            if (st == null) return getString(R.string.attestation_result_failed, "zaman aşımı ya da PinVault hazır değil");
            String mock = requestMockHost();
            switch (st.getResult()) {
                case PASS: {
                    io.github.umutcansu.pinvault.model.AttestationTokenResult tr = PinManagerLite.fetchTokenBlocking(null, 10L);
                    String token = tr instanceof io.github.umutcansu.pinvault.model.AttestationTokenResult.Token
                            ? ((io.github.umutcansu.pinvault.model.AttestationTokenResult.Token) tr).getValue() : "";
                    return getString(R.string.attestation_result_pass, st.getArc(),
                            st.getWarnings().isEmpty() ? "—" : String.join(",", st.getWarnings()),
                            token.length(), time(st.getTokenExpiresAt()),
                            token.length() > 24 ? token.substring(0, 24) : token,
                            App.MOCK_TLS_URL, mock);
                }
                case REJECT:
                    return getString(R.string.attestation_result_reject, st.getArc(),
                            st.getRejectionReasons().isEmpty() ? "(sunucu açıklamıyor)" : String.join(",", st.getRejectionReasons()),
                            App.MOCK_TLS_URL, mock);
                case UNSUPPORTED:
                    return getString(R.string.attestation_status_unsupported);
                default:
                    return getString(R.string.attestation_result_failed, st.getLastError() == null ? "?" : st.getLastError());
            }
        });
    }

    /** Kütüphanenin istemcisiyle mock TLS host'a bir istek; token varsa kütüphane ekler. */
    private String requestMockHost() {
        try (okhttp3.Response resp = PinVault.INSTANCE.getClient()
                .newCall(new Request.Builder().url(App.MOCK_TLS_URL).build()).execute()) {
            if (resp.isSuccessful()) return getString(R.string.attestation_mock_ok, resp.code());
            String why = resp.header("WWW-Authenticate");
            return getString(R.string.attestation_mock_refused, resp.code(), why == null ? "" : why);
        } catch (Exception e) {
            return getString(R.string.attestation_mock_unreachable, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
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
     * PinVault'u import etmeyen bir network katmanı: kendi OkHttpClient'ı
     * var, pinlemeyi uygulama katmanının verdiği geri çağrı
     * ({@code PinVault::applyTo}) takar (bkz. {@link ProductionStyleClient}).
     */
    private void runProductionStyleRequest() {
        runAction(getString(R.string.connecting_fmt, App.TARGET_URL), () -> {
            Request req = new Request.Builder().url(App.TARGET_URL).build();
            try (okhttp3.Response resp = ProductionStyleClient.execute(req)) {
                return "✅ Production-style bağlantı başarılı\nHTTP " + resp.code()
                        + "\n(kendi OkHttpClient'ı, pinleme PinVault.applyTo ile)";
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
