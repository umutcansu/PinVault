package com.example.sampleclient;

import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import io.github.umutcansu.pinvault.PinVault;
import io.github.umutcansu.pinvault.model.VaultFileResult;

/**
 * Vault: host dashboard'unda yüklenen dosyaları indirir ve yönetir.
 *
 * <ul>
 *   <li>{@link App#VAULT_FLAGS} herkese açık bir dosya.</li>
 *   <li>{@link App#VAULT_SECRET} bu cihaza ve bu dosyaya bağlı bir token ister;
 *       token dashboard'da "Cihaz ID" için üretilir ve burada girilir.</li>
 *   <li>{@link App#VAULT_E2E} cihazın Android Keystore'daki RSA anahtarıyla
 *       şifrelenmiş gelir; yalnızca bu cihaz çözebilir.</li>
 *   <li>{@link App#VAULT_ATREST} sunucuda şifreli saklanır, telefona ek şifreleme olmadan (TLS ile) gelir.</li>
 *   <li>{@link App#VAULT_ADMIN} yalnızca yönetim anahtarıyla inebilir; cihazdan
 *       her zaman reddedilir.</li>
 *   <li>{@link App#VAULT_MODEL} şifreli dosya deposunda tutulur ve config ile
 *       birlikte eşitlenir (Tümünü eşitle, arka plan görevi).</li>
 *   <li>{@link App#VAULT_MTLS_SECRET} mTLS bloğuna bağlıdır: istemci sertifikası
 *       ve cihaz token'ı ister.</li>
 * </ul>
 *
 * Her dosyanın içeriği config imzalama anahtarıyla doğrulanır; imza tutmazsa
 * dosya kaydedilmez. "Bilgi" saklı dosyayı sunucuya gitmeden okur; "Sil"
 * dosyayı ve (dosya deposundaysa) Keystore anahtarını siler.
 */
public class VaultActivity extends ActionActivity {

    private static final int MAX_PREVIEW = 400;

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
    private Button infoButton;
    private Button clearButton;

    private final Runnable initObserver = () -> ui.post(this::updateButtons);

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
                fetchAdminButton, fetchModelButton, fetchMtlsSecretButton, syncAllButton, infoButton, clearButton}) {
            b.setEnabled(ready);
        }
    }

    private String key() {
        String key = keyInput.getText().toString().trim();
        return key.isEmpty() ? App.VAULT_SECRET : key;
    }

    private void saveToken() {
        String key = key();
        VaultTokens.put(key, tokenInput.getText().toString().trim());
        showResult(getString(R.string.vault_token_saved, key));
    }

    private void fetch(String key) {
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

    private void info() {
        String key = key();
        runAction(getString(R.string.vault_info_pending, key), () -> {
            boolean has = PinVault.INSTANCE.hasFile(key);
            int version = PinVault.INSTANCE.fileVersion(key);
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

    private String describe(String key, VaultFileResult result) {
        if (result instanceof VaultFileResult.Updated) {
            VaultFileResult.Updated u = (VaultFileResult.Updated) result;
            return getString(R.string.vault_updated, key, u.getVersion(), note(key),
                    preview(new String(u.getBytes(), StandardCharsets.UTF_8)));
        }
        if (result instanceof VaultFileResult.AlreadyCurrent) {
            VaultFileResult.AlreadyCurrent c = (VaultFileResult.AlreadyCurrent) result;
            return getString(R.string.vault_current, key, c.getVersion(), preview(PinVault.INSTANCE.loadFileAsString(key)));
        }
        return getString(R.string.vault_failed, key, ((VaultFileResult.Failed) result).getReason());
    }

    private String summarize(VaultFileResult result) {
        if (result instanceof VaultFileResult.Updated) {
            VaultFileResult.Updated u = (VaultFileResult.Updated) result;
            return u.getKey() + " → v" + u.getVersion() + " indirildi (" + u.getBytes().length + " B)";
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
            case App.VAULT_E2E: return getString(R.string.vault_e2e_note);
            case App.VAULT_ATREST: return getString(R.string.vault_atrest_note);
            case App.VAULT_MODEL: return getString(R.string.vault_model_note);
            case App.VAULT_MTLS_SECRET: return getString(R.string.vault_mtls_note);
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
        App.INIT.removeObserver(initObserver);
    }
}
