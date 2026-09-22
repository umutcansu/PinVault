package com.example.sampleclient;

import android.os.Bundle;
import android.security.keystore.KeyInfo;
import android.util.Base64;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import io.github.umutcansu.pinvault.PinVault;

/**
 * Depolama: PinVault'un bu cihazda ne sakladığını ve nasıl sakladığını
 * gösterir. Uygulama yalnızca kendi dosyalarını okur; hiçbir şeyi çözmez.
 *
 * <ul>
 *   <li>Şifreli tercih dosyaları (EncryptedSharedPreferences): anahtar ve
 *       değerlerin şifreli olduğu, host adı / pin gibi düz metinlerin dosyada
 *       geçmediği gösterilir.</li>
 *   <li>Vault dosya deposu (files/vault_files/*.enc): boyut ve başlık.</li>
 *   <li>Android Keystore anahtarları: algoritma, boyut, güvenli donanım.</li>
 *   <li>İstemci sertifikası kaydı: ham değerin PKCS12 olarak açılamadığı.</li>
 * </ul>
 */
public class StorageActivity extends AppCompatActivity {

    private static final Pattern ENTRY = Pattern.compile("<string name=\"([^\"]*)\">([^<]*)</string>");
    private static final String KEYSET_ENTRY = "__androidx_security_crypto_encrypted_prefs_key_keyset__";

    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private TextView storageView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_storage);
        storageView = findViewById(R.id.storageView);
        Button refreshButton = findViewById(R.id.refreshStorageButton);
        refreshButton.setOnClickListener(v -> render());
        render();
    }

    private void render() {
        storageView.setText(R.string.storage_loading);
        io.execute(() -> {
            String text;
            try {
                text = describe();
            } catch (Exception e) {
                text = "❌ " + e.getClass().getSimpleName() + "\n" + e.getMessage();
            }
            String finalText = text;
            runOnUiThread(() -> storageView.setText(finalText));
        });
    }

    private String describe() throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("Mod: ").append(App.ACTIVE_MODE.label()).append('\n');
        sb.append("forceUpdate (kalıcı): ").append(forceUpdateState()).append("\n\n");

        sb.append("== Şifreli tercih dosyaları (EncryptedSharedPreferences, AES-256-GCM) ==\n");
        File prefsDir = new File(getApplicationInfo().dataDir, "shared_prefs");
        File[] prefs = prefsDir.listFiles((d, name) -> name.endsWith(".xml"));
        List<File> sorted = new ArrayList<>();
        if (prefs != null) Collections.addAll(sorted, prefs);
        Collections.sort(sorted);
        int pinvaultFiles = 0;
        for (File f : sorted) {
            String name = f.getName();
            boolean pinvault = name.startsWith("ssl_cert_config") || name.startsWith("pinvault_");
            if (!pinvault) continue;
            pinvaultFiles++;
            String xml = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
            if (name.equals("pinvault_vault_file_versions.xml")) {
                sb.append("• ").append(name).append(" — ").append(f.length()).append(" B, düz sürüm tablosu: ")
                        .append(plainEntries(xml)).append('\n');
                continue;
            }
            List<String[]> entries = entries(xml);
            boolean keyset = xml.contains(KEYSET_ENTRY);
            sb.append("• ").append(name).append(" — ").append(f.length()).append(" B, ")
                    .append(entries.size()).append(" kayıt, Tink keyset: ").append(keyset ? "var" : "yok").append('\n');
            if (!entries.isEmpty()) {
                String[] first = entries.get(0);
                sb.append("   örnek: ").append(shorten(first[0])).append(" → ").append(shorten(first[1])).append('\n');
            }
            sb.append("   düz metin sızıntısı (host adı, IP, pin): ")
                    .append(leaks(xml) ? "VAR ✗" : "yok ✓").append('\n');
        }
        if (pinvaultFiles == 0) sb.append("(PinVault tercih dosyası yok)\n");

        sb.append("\n== Vault dosya deposu (files/vault_files, AES-256-GCM, Keystore anahtarı) ==\n");
        File vaultDir = new File(getFilesDir(), "vault_files");
        File[] vaultFiles = vaultDir.listFiles();
        if (vaultFiles == null || vaultFiles.length == 0) {
            sb.append("(dosya yok)\n");
        } else {
            for (File f : vaultFiles) {
                byte[] head = Files.readAllBytes(f.toPath());
                int ivLen = head.length > 0 ? head[0] & 0xff : 0;
                sb.append("• ").append(f.getName()).append(" — ").append(f.length()).append(" B, başlık: [iv_len=")
                        .append(ivLen).append("] ").append(hex(head, 1, Math.min(ivLen, 12))).append(" …\n");
            }
        }

        sb.append("\n== Android Keystore ==\n");
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        int aliases = 0;
        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); ) {
            String alias = e.nextElement();
            if (!alias.startsWith("pinvault") && !alias.contains("security_master_key")) continue;
            aliases++;
            sb.append("• ").append(alias).append(": ").append(describeKey(ks, alias)).append('\n');
        }
        if (aliases == 0) sb.append("(PinVault anahtarı yok)\n");

        sb.append("\n== İstemci sertifikası (pinvault_client_cert) ==\n");
        boolean enrolled = PinVault.INSTANCE.isEnrolled(this, null);
        if (!enrolled) {
            sb.append("kayıtlı değil\n");
        } else {
            String cn = safeCn();
            sb.append("kayıtlı — CN=").append(cn == null ? "?" : cn).append('\n');
            File certPrefs = new File(prefsDir, "pinvault_client_cert.xml");
            if (certPrefs.isFile()) {
                String xml = new String(Files.readAllBytes(certPrefs.toPath()), StandardCharsets.UTF_8);
                sb.append("ham kayıt PKCS12 olarak açılıyor mu: ").append(rawRecordOpensAsP12(xml)
                        ? "EVET ✗ (şifresiz!)" : "hayır ✓ (şifreli)").append('\n');
            }
        }
        File manual = new File(getFilesDir(), App.MANUAL_P12_FILE);
        sb.append("elle yüklenen P12: ").append(manual.isFile() ? manual.length() + " B" : "yok")
                .append(AppSettings.useManualP12(this) ? " (kullanılıyor)" : "").append('\n');
        return sb.toString();
    }

    private String forceUpdateState() {
        try {
            return PinVault.INSTANCE.isForceUpdate() ? "açık" : "kapalı";
        } catch (IllegalStateException e) {
            return "(PinVault başlatılmadı)";
        }
    }

    private String safeCn() {
        try {
            return PinVault.INSTANCE.enrolledClientCN(this, null);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static List<String[]> entries(String xml) {
        List<String[]> out = new ArrayList<>();
        Matcher m = ENTRY.matcher(xml);
        while (m.find()) {
            if (KEYSET_ENTRY.equals(m.group(1))) continue;
            out.add(new String[]{m.group(1), m.group(2)});
        }
        return out;
    }

    private static String plainEntries(String xml) {
        StringBuilder sb = new StringBuilder();
        Matcher m = Pattern.compile("<(?:int|string|long) name=\"([^\"]*)\" value=\"([^\"]*)\"").matcher(xml);
        while (m.find()) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(m.group(1)).append('=').append(m.group(2));
        }
        return sb.length() == 0 ? "(boş)" : sb.toString();
    }

    private static boolean leaks(String xml) {
        for (String needle : new String[]{App.TARGET_HOST, App.SAMPLE_HOST_IP,
                BuildConfig.HOST_BOOTSTRAP_PIN_PRIMARY, BuildConfig.HOST_BOOTSTRAP_PIN_BACKUP,
                "BEGIN", "sha256/"}) {
            if (!needle.isEmpty() && xml.contains(needle)) return true;
        }
        return false;
    }

    private static boolean rawRecordOpensAsP12(String xml) {
        for (String[] entry : entries(xml)) {
            byte[] raw;
            try {
                raw = Base64.decode(entry[1], Base64.DEFAULT);
            } catch (IllegalArgumentException e) {
                continue;
            }
            try {
                KeyStore p12 = KeyStore.getInstance("PKCS12");
                p12.load(new ByteArrayInputStream(raw), App.MANUAL_P12_PASSWORD.toCharArray());
                if (p12.aliases().hasMoreElements()) return true;
            } catch (Exception e) {
                // Beklenen: şifreli değer PKCS12 değildir.
            }
        }
        return false;
    }

    private static String describeKey(KeyStore ks, String alias) {
        try {
            Key key = ks.getKey(alias, null);
            KeyInfo info;
            if (key instanceof PrivateKey) {
                KeyFactory kf = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
                info = kf.getKeySpec(key, KeyInfo.class);
                byte[] spki = ks.getCertificate(alias).getPublicKey().getEncoded();
                return String.format(Locale.US, "%s %d bit, güvenli donanım: %s, public key SHA-256: %s",
                        key.getAlgorithm(), info.getKeySize(), secureHardware(info), sha256Hex(spki));
            }
            if (key instanceof SecretKey) {
                SecretKeyFactory skf = SecretKeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
                info = (KeyInfo) skf.getKeySpec((SecretKey) key, KeyInfo.class);
                return String.format(Locale.US, "%s %d bit, güvenli donanım: %s",
                        key.getAlgorithm(), info.getKeySize(), secureHardware(info));
            }
            return key == null ? "(anahtar okunamadı)" : key.getAlgorithm();
        } catch (Exception e) {
            return "(bilgi alınamadı: " + e.getClass().getSimpleName() + ")";
        }
    }

    @SuppressWarnings("deprecation")
    private static String secureHardware(KeyInfo info) {
        return info.isInsideSecureHardware() ? "evet" : "hayır";
    }

    private static String sha256Hex(byte[] data) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(data), 0, 32);
    }

    private static String hex(byte[] data, int offset, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = offset; i < Math.min(data.length, offset + length); i++) {
            sb.append(String.format(Locale.US, "%02x", data[i]));
        }
        return sb.toString();
    }

    private static String shorten(String s) {
        return s.length() > 18 ? s.substring(0, 18) + "…" : s;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        io.shutdown();
    }
}
