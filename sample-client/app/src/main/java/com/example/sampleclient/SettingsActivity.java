package com.example.sampleclient;

import android.os.Bundle;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;

import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

import io.github.umutcansu.pinvault.PinVault;
import io.github.umutcansu.pinvault.model.HttpConnectionSettings;
import io.github.umutcansu.pinvault.model.PinVaultConfig;
import io.github.umutcansu.pinvault.model.ScheduledTaskInfo;
import kotlin.Unit;
import okhttp3.OkHttpClient;

/**
 * Ayarlar: PinVault'un çalışma modu ve telemetri seçenekleri; "Gelişmiş"
 * altında kütüphanenin nadir kullanılan yolları: özel bağlantı ayarlı istemci,
 * sıfırlama (fail-closed gösterimi), tekrar init (ağ isteği yapmaz), planlı
 * arka plan işi.
 */
public class SettingsActivity extends ActionActivity {

    private static final long INIT_WAIT_MS = 60_000;

    private RadioGroup modeGroup;
    private CheckBox reportSuccessCheck;
    private CheckBox scopedPinsCheck;
    private CheckBox twoSignaturesCheck;
    private EditText dedupMsInput;
    private Button applyButton;
    private Button settingsClientButton;
    private Button resetButton;
    private Button reinitButton;
    private Button restartButton;
    private Button workInfoButton;
    private Button cancelWorkButton;
    private Button scheduleWorkButton;

    private final Runnable initObserver = () -> ui.post(this::updateButtons);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        statusView = findViewById(R.id.statusView);
        modeGroup = findViewById(R.id.modeGroup);
        reportSuccessCheck = findViewById(R.id.reportSuccessCheck);
        scopedPinsCheck = findViewById(R.id.scopedPinsCheck);
        twoSignaturesCheck = findViewById(R.id.twoSignaturesCheck);
        dedupMsInput = findViewById(R.id.dedupMsInput);
        applyButton = findViewById(R.id.applyButton);
        settingsClientButton = findViewById(R.id.settingsClientButton);
        resetButton = findViewById(R.id.resetButton);
        reinitButton = findViewById(R.id.reinitButton);
        restartButton = findViewById(R.id.restartButton);
        workInfoButton = findViewById(R.id.workInfoButton);
        cancelWorkButton = findViewById(R.id.cancelWorkButton);
        scheduleWorkButton = findViewById(R.id.scheduleWorkButton);

        ((RadioButton) findViewById(radioFor(AppSettings.mode(this)))).setChecked(true);
        reportSuccessCheck.setChecked(AppSettings.reportSuccess(this));
        scopedPinsCheck.setChecked(AppSettings.scopedPins(this));
        twoSignaturesCheck.setChecked(AppSettings.requiredSignatures(this) >= 2);
        dedupMsInput.setText(String.valueOf(AppSettings.dedupMs(this)));
        statusView.setText(getString(R.string.settings_intro, App.ACTIVE_MODE.label()));

        applyButton.setOnClickListener(v -> apply());
        settingsClientButton.setOnClickListener(v -> testSettingsClient());
        resetButton.setOnClickListener(v -> resetAndProbe());
        reinitButton.setOnClickListener(v -> reinit());
        restartButton.setOnClickListener(v -> restart());
        workInfoButton.setOnClickListener(v -> showWork());
        cancelWorkButton.setOnClickListener(v -> cancelWork());
        scheduleWorkButton.setOnClickListener(v -> scheduleWork());

        App.INIT.addObserver(initObserver);
        updateButtons();
    }

    private static int radioFor(AppSettings.Mode mode) {
        switch (mode) {
            case MTLS_CONFIG: return R.id.modeMtlsConfig;
            case CUSTOM_BACKEND: return R.id.modeCustomBackend;
            case EMBEDDED_API: return R.id.modeEmbeddedApi;
            case STATIC: return R.id.modeStatic;
            default: return R.id.modeTls;
        }
    }

    private AppSettings.Mode selectedMode() {
        int id = modeGroup.getCheckedRadioButtonId();
        if (id == R.id.modeMtlsConfig) return AppSettings.Mode.MTLS_CONFIG;
        if (id == R.id.modeCustomBackend) return AppSettings.Mode.CUSTOM_BACKEND;
        if (id == R.id.modeEmbeddedApi) return AppSettings.Mode.EMBEDDED_API;
        if (id == R.id.modeStatic) return AppSettings.Mode.STATIC;
        return AppSettings.Mode.TLS;
    }

    @Override
    protected void updateButtons() {
        boolean ready = App.INIT.get().phase == InitState.Phase.READY;
        boolean idle = !isBusy();
        applyButton.setEnabled(idle);
        restartButton.setEnabled(idle);
        reinitButton.setEnabled(idle);
        resetButton.setEnabled(idle && ready);
        settingsClientButton.setEnabled(idle && ready);
        workInfoButton.setEnabled(idle && ready);
        cancelWorkButton.setEnabled(idle && ready);
        scheduleWorkButton.setEnabled(idle && ready);
    }

    // ── Mod ve telemetri ─────────────────────────────────────────────────────

    private void apply() {
        AppSettings.Mode mode = selectedMode();
        long dedup;
        try {
            dedup = Long.parseLong(dedupMsInput.getText().toString().trim());
        } catch (NumberFormatException e) {
            dedup = 0L;
        }
        AppSettings.setTelemetry(this, reportSuccessCheck.isChecked(), dedup);
        // Pin kapsamı (wantPinsFor): config isteğine ?hosts=<hedef> ekler.
        AppSettings.setScopedPins(this, scopedPinsCheck.isChecked());
        final long dedupMs = dedup;
        final boolean scoped = scopedPinsCheck.isChecked();
        // m-of-n: işaretliyken her config iki ayrı anahtardan imza taşımalı.
        final int required = twoSignaturesCheck.isChecked() ? 2 : 1;
        AppSettings.setRequiredSignatures(this, required);
        runAction(getString(R.string.settings_applying, mode.label()), () -> {
            ((App) getApplication()).applyMode(mode);
            InitState.Snapshot s = App.INIT.awaitSettled(INIT_WAIT_MS);
            return getString(R.string.settings_applied, mode.label(),
                    reportSuccessCheck.isChecked() ? "evet" : "hayır", dedupMs,
                    scoped ? "yalnızca " + App.TARGET_HOST : "bütün host'lar",
                    describeInit(s), required);
        });
    }

    private String describeInit(InitState.Snapshot s) {
        switch (s.phase) {
            case READY: return "Hazır — config " + s.detail;
            case FAILED: return "başlatılamadı: " + s.detail;
            default: return "hâlâ başlatılıyor";
        }
    }

    // ── Gelişmiş ─────────────────────────────────────────────────────────────

    /** {@code getClient(HttpConnectionSettings)}: özel zaman aşımları, kurtarma interceptor'ı yok. */
    private void testSettingsClient() {
        runAction(getString(R.string.connecting_fmt, App.TARGET_URL), () -> {
            HttpConnectionSettings settings = new HttpConnectionSettings(5, 5, 5, 0, 5, 5, TimeUnit.SECONDS);
            OkHttpClient client = PinVault.INSTANCE.getClient(settings).newBuilder().dns(MockDns.INSTANCE).build();
            return pinnedGet(client, App.TARGET_URL,
                    "Özel ayarlı istemci bağlandı", "Özel ayarlı istemci başarısız",
                    "connect/read 5 s; pin uyuşmazlığında kurtarma yok");
        });
    }

    /** Sıfırla ve hemen pinli istek dene: config yokken TLS reddedilmeli (fail-closed). */
    private void resetAndProbe() {
        runAction(getString(R.string.settings_resetting), () -> {
            PinVault.INSTANCE.reset();
            App.INIT.set(InitState.Phase.FAILED, getString(R.string.settings_reset_state));
            String probe;
            try {
                probe = pinnedGet(pinnedClient(), App.TARGET_URL,
                        "İSTEK GEÇTİ (beklenmiyor)", "Pinli istek reddedildi", "");
            } catch (RuntimeException e) {
                probe = "❌ Pinli istek reddedildi\n" + e.getClass().getSimpleName() + "\n" + e.getMessage();
            }
            return getString(R.string.settings_reset_done) + "\n\n" + probe;
        });
    }

    /** init'i tekrar çağır: zaten başlatılmışsa kütüphane ağa çıkmadan hemen döner. */
    private void reinit() {
        runAction(getString(R.string.settings_reinit_pending), () -> {
            boolean wasReady = App.INIT.get().phase == InitState.Phase.READY;
            ((App) getApplication()).startPinVault();
            InitState.Snapshot s = App.INIT.awaitSettled(INIT_WAIT_MS);
            return getString(wasReady ? R.string.settings_reinit_skipped : R.string.settings_reinit_done, describeInit(s));
        });
    }

    private void restart() {
        runAction(getString(R.string.settings_restarting), () -> {
            ((App) getApplication()).restartPinVault();
            InitState.Snapshot s = App.INIT.awaitSettled(INIT_WAIT_MS);
            return getString(R.string.settings_restarted, describeInit(s));
        });
    }

    private void showWork() {
        runAction(getString(R.string.settings_work_pending), () -> describeWork());
    }

    private void cancelWork() {
        runAction(getString(R.string.settings_work_pending), () -> {
            PinVault.INSTANCE.cancelPeriodicUpdates();
            Thread.sleep(500);
            return getString(R.string.settings_work_cancelled) + "\n" + describeWork();
        });
    }

    private void scheduleWork() {
        runAction(getString(R.string.settings_work_pending), () -> {
            PinVault.INSTANCE.schedulePeriodicUpdates(PinVaultConfig.DEFAULT_UPDATE_INTERVAL_HOURS, scheduled -> Unit.INSTANCE);
            Thread.sleep(500);
            return getString(R.string.settings_work_scheduled) + "\n" + describeWork();
        });
    }

    private String describeWork() {
        List<ScheduledTaskInfo> work = PinManagerLite.scheduledWorkBlocking(5_000);
        if (work.isEmpty()) return getString(R.string.settings_work_none);
        StringBuilder sb = new StringBuilder(getString(R.string.settings_work_title));
        for (ScheduledTaskInfo info : work) {
            sb.append(String.format(Locale.US, "\n• %s — %s (deneme %d)",
                    info.getId(), info.getState(), info.getRunAttemptCount()));
        }
        return sb.toString();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        App.INIT.removeObserver(initObserver);
    }
}
