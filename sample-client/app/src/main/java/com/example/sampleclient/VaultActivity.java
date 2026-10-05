package com.example.sampleclient;

import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import io.github.umutcansu.pinvault.PinVault;
import io.github.umutcansu.pinvault.model.ScreenLockRequiredException;
import io.github.umutcansu.pinvault.model.VaultFileResult;
import io.github.umutcansu.pinvault.model.VaultFileUnlockPrompt;
import io.github.umutcansu.pinvault.model.VaultFileUnlockResult;
import kotlin.Unit;

/**
 * Vault: host dashboard'unda yüklenen dosyaları indirir ve yönetir.
 *
 * <p>Gizli olmayan dosyalar (TLS bloğu, herkes indirebilir):
 * <ul>
 *   <li>{@link App#VAULT_FLAGS} herkese açık demo dosyası.</li>
 *   <li>{@link App#VAULT_ATREST} sunucu diskinde şifreli durur ama herkese açıktır.</li>
 *   <li>{@link App#VAULT_ADMIN} yalnızca yönetim anahtarıyla inebilir; cihazdan
 *       her zaman reddedilir.</li>
 *   <li>{@link App#VAULT_MODEL} şifreli dosya deposunda tutulur ve config ile
 *       birlikte eşitlenir (Tümünü eşitle, arka plan görevi).</li>
 * </ul>
 *
 * <p>Gizli dosyalar ({@link App#LOCKED_VAULT_KEYS}: secret, e2e, mtls-secret):
 * mTLS bloğunda, cihaza özel token + istemci sertifikasıyla iner ve telefonda
 * ekran kilidinin arkasında durur. İndirme içerik göstermez; "Aç" telefonun
 * ekran kilidini (ya da parmak izini) sorar, ancak ondan sonra içerik görünür.
 * Açılan içerik ekranda gerektiğinden uzun kalmaz: ekran öne gelmeyi bıraktığı
 * anda (onPause) ya da {@link #UNLOCKED_VISIBLE_MS} dolunca silinir. Sonuç
 * kutusu seçilebilir değildir (panoya kopyalanamaz); uygulamanın bütün
 * ekranları ekran görüntüsüne kapalıdır (FLAG_SECURE, {@link App}).
 *
 * <p>Her dosyanın içeriği config imzalama anahtarıyla doğrulanır; imza tutmazsa
 * dosya kaydedilmez. "Bilgi" saklı dosyayı sunucuya gitmeden okur (kilitli
 * dosyanın içeriğini göstermez); "Sil" dosyayı ve (dosya deposundaysa)
 * Keystore anahtarını siler.
 */
public class VaultActivity extends ActionActivity {

    private static final int MAX_PREVIEW = 400;
    /** Kilidi açılan içerik ekranda en çok bu kadar durur, sonra silinir. */
    private static final long UNLOCKED_VISIBLE_MS = 60_000;

    private EditText keyInput;
    private EditText tokenInput;
    private Button saveTokenButton;
    private Button fetchFlagsButton;
    private Button fetchSecretButton;
    private Button fetchE2eButton;
    private Button fetchAtRestButton;
    private Button fetchAdminButton;
    private Button fetchModelButton;
    private Button fetchMtlsSecretButton;
    private Button syncAllButton;
    private Button unlockButton;
    private Button infoButton;
    private Button clearButton;

    /** Ekranda açılmış (kilidi açılan) bir dosyanın içeriği duruyor mu. */
    private boolean showingUnlocked;

    private final Runnable initObserver = () -> ui.post(this::updateButtons);
    private final Runnable relockTimer = this::relock;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_vault);

        statusView = findViewById(R.id.statusView);
        TextView deviceIdView = findViewById(R.id.deviceIdView);
        keyInput = findViewById(R.id.keyInput);
        tokenInput = findViewById(R.id.tokenInput);
        saveTokenButton = findViewById(R.id.saveTokenButton);
        fetchFlagsButton = findViewById(R.id.fetchFlagsButton);
        fetchSecretButton = findViewById(R.id.fetchSecretButton);
        fetchE2eButton = findViewById(R.id.fetchE2eButton);
        fetchAtRestButton = findViewById(R.id.fetchAtRestButton);
        fetchAdminButton = findViewById(R.id.fetchAdminButton);
        fetchModelButton = findViewById(R.id.fetchModelButton);
        fetchMtlsSecretButton = findViewById(R.id.fetchMtlsSecretButton);
        syncAllButton = findViewById(R.id.syncAllButton);
        unlockButton = findViewById(R.id.unlockButton);
        infoButton = findViewById(R.id.infoButton);
        clearButton = findViewById(R.id.clearButton);

        deviceIdView.setText(getString(R.string.vault_device_id, App.deviceId(this)));
        keyInput.setText(App.VAULT_SECRET);
        statusView.setText(R.string.vault_intro);

        saveTokenButton.setOnClickListener(v -> saveToken());
        fetchFlagsButton.setOnClickListener(v -> fetch(App.VAULT_FLAGS));
        fetchSecretButton.setOnClickListener(v -> fetch(App.VAULT_SECRET));
        fetchE2eButton.setOnClickListener(v -> fetch(App.VAULT_E2E));
        fetchAtRestButton.setOnClickListener(v -> fetch(App.VAULT_ATREST));
        fetchAdminButton.setOnClickListener(v -> fetch(App.VAULT_ADMIN));
        fetchModelButton.setOnClickListener(v -> fetch(App.VAULT_MODEL));
        fetchMtlsSecretButton.setOnClickListener(v -> fetch(App.VAULT_MTLS_SECRET));
        syncAllButton.setOnClickListener(v -> syncAll());
        unlockButton.setOnClickListener(v -> unlock());
        infoButton.setOnClickListener(v -> info());
        clearButton.setOnClickListener(v -> clear());

        App.INIT.addObserver(initObserver);
        updateButtons();
    }

    @Override
    protected void updateButtons() {
        boolean ready = App.INIT.get().phase == InitState.Phase.READY && !isBusy();
        saveTokenButton.setEnabled(!isBusy());
        for (Button b : new Button[]{fetchFlagsButton, fetchSecretButton, fetchE2eButton, fetchAtRestButton,
                fetchAdminButton, fetchModelButton, fetchMtlsSecretButton, syncAllButton, unlockButton,
                infoButton, clearButton}) {
            b.setEnabled(ready);
        }
    }

    @Override
    protected void showResult(String text) {
        showingUnlocked = false;
        ui.removeCallbacks(relockTimer);
        super.showResult(text);
    }

    @Override
    protected void onPause() {
        super.onPause();
        // Açılan içerik ekranda kalmasın: ekran öne gelmeyi bıraktığı anda silinir
        // (onStop'u beklemeden; üstüne başka bir pencerenin gelmesi de yeter).
        relock();
    }

    @Override
    protected void onStop() {
        super.onStop();
        relock();
    }

    /** Ekranda açık bir gizli dosya varsa içeriğini siler. UI thread'inde çağrılır. */
    private void relock() {
        ui.removeCallbacks(relockTimer);
        if (!showingUnlocked) return;
        showingUnlocked = false;
        statusView.setText(R.string.vault_relocked);
    }

    private String key() {
        String key = keyInput.getText().toString().trim();
        return key.isEmpty() ? App.VAULT_SECRET : key;
    }

    private void saveToken() {
        String key = key();
        VaultTokens.put(key, tokenInput.getText().toString().trim());
        tokenInput.setText("");
        showResult(getString(R.string.vault_token_saved, key));
    }

    private void fetch(String key) {
        // Gizli dosyalar mTLS bloğunda; cihaz kayıtlı değilse hiç tanımlanmadılar.
        if (App.isLockedVaultKey(key) && !App.LOCKED_FILES_ACTIVE) {
            showResult(getString(R.string.vault_needs_mtls, key));
            return;
        }
        runAction(getString(R.string.vault_fetching, key), () -> describe(key, PinManagerLite.fetchFileBlocking(key)));
    }

    private void syncAll() {
        runAction(getString(R.string.vault_syncing), () -> {
            Map<String, VaultFileResult> results = PinManagerLite.syncAllBlocking();
            if (results.isEmpty()) return getString(R.string.vault_sync_empty);
            StringBuilder sb = new StringBuilder(getString(R.string.vault_sync_title));
            for (Map.Entry<String, VaultFileResult> e : results.entrySet()) {
                sb.append("\n• ").append(summarize(e.getValue()));
            }
            return sb.toString();
        });
    }

    /**
     * "Aç": kilitli dosyayı ekran kilidi sorularak açar (kilitsiz dosya soru
     * sorulmadan gelir). Sonucun her hâli ele alınır: anahtar geçersiz olduysa
     * ya da saklı kopya yoksa dosya yeniden indirilir.
     */
    private void unlock() {
        String key = key();
        if (App.isLockedVaultKey(key) && !App.LOCKED_FILES_ACTIVE) {
            showResult(getString(R.string.vault_needs_mtls, key));
            return;
        }
        setBusy(true);
        statusView.setText(getString(R.string.vault_unlocking, key));
        VaultFileUnlockPrompt prompt = new VaultFileUnlockPrompt(
                getString(R.string.vault_unlock_prompt_title),
                key,
                getString(R.string.vault_unlock_prompt_description),
                getString(R.string.vault_unlock_prompt_cancel));
        try {
            PinVault.INSTANCE.unlockFile(this, key, prompt, result -> {
                onUnlockResult(key, result);
                return Unit.INSTANCE;
            });
        } catch (IllegalStateException e) {
            // PinVault henüz başlatılmadı.
            showResult(getString(R.string.vault_unlock_failed, key, e.getMessage()));
        }
    }

    private void onUnlockResult(String key, VaultFileUnlockResult result) {
        if (result instanceof VaultFileUnlockResult.Unlocked) {
            VaultFileUnlockResult.Unlocked u = (VaultFileUnlockResult.Unlocked) result;
            String text = getString(R.string.vault_unlocked, key, u.getVersion(),
                    preview(new String(u.getBytes(), StandardCharsets.UTF_8)));
            java.util.Arrays.fill(u.getBytes(), (byte) 0);
            ui.removeCallbacks(relockTimer);
            super.showResult(text);
            showingUnlocked = true;
            // Kullanıcı ekranda kalsa da içerik süresiz durmaz.
            ui.postDelayed(relockTimer, UNLOCKED_VISIBLE_MS);
        } else if (result instanceof VaultFileUnlockResult.Cancelled) {
            showResult(getString(R.string.vault_unlock_cancelled, key));
        } else if (result instanceof VaultFileUnlockResult.Invalidated) {
            // Ekran kilidi kaldırıldı/değişti ya da parmak izi eklendi: Android
            // anahtarı geçersiz saydı, saklı kopya silindi. Yeni anahtarla yeniden indir.
            refetchAfterUnlock(key, getString(R.string.vault_unlock_invalidated, key));
        } else if (result instanceof VaultFileUnlockResult.NotFound) {
            refetchAfterUnlock(key, getString(R.string.vault_unlock_not_found, key));
        } else if (result instanceof VaultFileUnlockResult.Stale) {
            // Sunucu kopyayı App.SECRET_MAX_OFFLINE_DAYS günden uzun süredir
            // onaylamadı: kopya açılmaz. Telefon ağdaysa yeniden indirip açar;
            // cihaz bu arada iptal edildiyse indirme reddedilir.
            refetchAfterUnlock(key, getString(R.string.vault_unlock_stale, key, App.SECRET_MAX_OFFLINE_DAYS));
        } else if (result instanceof VaultFileUnlockResult.Failed) {
            showResult(getString(R.string.vault_unlock_failed, key, ((VaultFileUnlockResult.Failed) result).getReason()));
        }
    }

    private void refetchAfterUnlock(String key, String why) {
        statusView.setText(why);
        io.execute(() -> {
            String fetched;
            try {
                fetched = describe(key, PinManagerLite.fetchFileBlocking(key));
            } catch (Exception e) {
                fetched = "❌ " + e.getClass().getSimpleName() + "\n" + e.getMessage();
            }
            showResult(why + "\n\n" + fetched);
        });
    }

    private void info() {
        String key = key();
        runAction(getString(R.string.vault_info_pending, key), () -> {
            boolean has = PinVault.INSTANCE.hasFile(key);
            int version = PinVault.INSTANCE.fileVersion(key);
            if (has && isLocked(key)) {
                return getString(R.string.vault_info, key, "var", version, getString(R.string.vault_info_locked));
            }
            String content = has ? PinVault.INSTANCE.loadFileAsString(key) : null;
            return getString(R.string.vault_info, key, has ? "var" : "yok", version,
                    content == null ? "(içerik yok)" : preview(content));
        });
    }

    private void clear() {
        String key = key();
        runAction(getString(R.string.vault_clear_pending, key), () -> {
            PinVault.INSTANCE.clearFile(key);
            return getString(R.string.vault_cleared, key, PinVault.INSTANCE.hasFile(key) ? "var" : "yok");
        });
    }

    /** Kilitli kopya ya da kilitli tanımlı dosya: içerik yalnızca "Aç" ile gösterilir. */
    private static boolean isLocked(String key) {
        if (App.isLockedVaultKey(key)) return true;
        try {
            return PinVault.INSTANCE.isFileLocked(key);
        } catch (IllegalStateException e) {
            return false;
        }
    }

    private String describe(String key, VaultFileResult result) {
        if (result instanceof VaultFileResult.Updated) {
            VaultFileResult.Updated u = (VaultFileResult.Updated) result;
            String body = isLocked(key)
                    ? getString(R.string.vault_locked_note)
                    : preview(new String(u.getBytes(), StandardCharsets.UTF_8));
            return getString(R.string.vault_updated, key, u.getVersion(), note(key), body);
        }
        if (result instanceof VaultFileResult.AlreadyCurrent) {
            VaultFileResult.AlreadyCurrent c = (VaultFileResult.AlreadyCurrent) result;
            String body = isLocked(key)
                    ? getString(R.string.vault_locked_note)
                    : preview(PinVault.INSTANCE.loadFileAsString(key));
            return getString(R.string.vault_current, key, c.getVersion(), body);
        }
        VaultFileResult.Failed f = (VaultFileResult.Failed) result;
        if (f.getException() instanceof ScreenLockRequiredException) {
            return getString(R.string.vault_failed, key, getString(R.string.vault_screen_lock_required));
        }
        return getString(R.string.vault_failed, key, f.getReason());
    }

    private String summarize(VaultFileResult result) {
        if (result instanceof VaultFileResult.Updated) {
            VaultFileResult.Updated u = (VaultFileResult.Updated) result;
            String size = isLocked(u.getKey()) ? "kilitli" : u.getBytes().length + " B";
            return u.getKey() + " → v" + u.getVersion() + " indirildi (" + size + ")";
        }
        if (result instanceof VaultFileResult.AlreadyCurrent) {
            VaultFileResult.AlreadyCurrent c = (VaultFileResult.AlreadyCurrent) result;
            return c.getKey() + " → güncel (v" + c.getVersion() + ")";
        }
        VaultFileResult.Failed f = (VaultFileResult.Failed) result;
        return f.getKey() + " → indirilemedi: " + f.getReason();
    }

    private String note(String key) {
        switch (key) {
            case App.VAULT_SECRET:
            case App.VAULT_MTLS_SECRET: return getString(R.string.vault_user_auth_note);
            case App.VAULT_E2E: return getString(R.string.vault_e2e_note);
            case App.VAULT_ATREST: return getString(R.string.vault_atrest_note);
            case App.VAULT_MODEL: return getString(R.string.vault_model_note);
            default: return "";
        }
    }

    private static String preview(String text) {
        if (text == null) return "";
        return text.length() > MAX_PREVIEW ? text.substring(0, MAX_PREVIEW) + "…" : text;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        ui.removeCallbacks(relockTimer);
        App.INIT.removeObserver(initObserver);
    }
}
