package com.example.sampleclient;

import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.github.umutcansu.pinvault.PinVault;

/**
 * mTLS: istemci sertifikası alma ve kullanma.
 *
 * <ul>
 *   <li><b>Kayıt ol:</b> dashboard'da üretilen tek kullanımlık token ile
 *       istemci sertifikası alınır; {@code X-P12-SHA256} ile bütünlüğü
 *       doğrulanır, şifreli saklanır ve pinli client'a yüklenir.</li>
 *   <li><b>Otomatik kayıt:</b> token yerine cihaz kimliği (ANDROID_ID); sunucu
 *       yalnızca {@code ENROLLMENT_MODE=open} iken kabul eder.</li>
 *   <li><b>P12 içe aktar:</b> {@code files/manual-client.p12} dosyasındaki
 *       sertifika {@code clientKeystore(...)} ile kullanılır (kayıt yerine).</li>
 *   <li><b>mTLS ile test:</b> mTLS Config API'nin {@code /health} ucuna
 *       sertifikalı, pinli istek. <b>Mock host'lar:</b> host'taki TLS ve
 *       mTLS mock hedeflerine pinli istek.</li>
 *   <li><b>Kaydı sil:</b> sertifika depodan silinir ve PinVault yeniden
 *       kurulur.</li>
 * </ul>
 *
 * <p>Kayıttan sonra mTLS Config API bloğu bir sonraki PinVault kurulumunda
 * eklenir (Ayarlar → "Sıfırla ve yeniden başlat" ya da uygulamayı yeniden aç).
 */
public class MtlsActivity extends ActionActivity {

    private static final Pattern CN = Pattern.compile("CN=([^,]+)");

    private TextView enrollStateView;
    private EditText tokenInput;
    private Button enrollButton;
    private Button autoEnrollButton;
    private Button mtlsTestButton;
    private Button unenrollButton;
    private Button importP12Button;
    private Button mockTlsButton;
    private Button mockMtlsButton;

    private final Runnable initObserver = () -> ui.post(this::updateButtons);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_mtls);

        statusView = findViewById(R.id.statusView);
        enrollStateView = findViewById(R.id.enrollStateView);
        tokenInput = findViewById(R.id.tokenInput);
        enrollButton = findViewById(R.id.enrollButton);
        autoEnrollButton = findViewById(R.id.autoEnrollButton);
        mtlsTestButton = findViewById(R.id.mtlsTestButton);
        unenrollButton = findViewById(R.id.unenrollButton);
        importP12Button = findViewById(R.id.importP12Button);
        mockTlsButton = findViewById(R.id.mockTlsButton);
        mockMtlsButton = findViewById(R.id.mockMtlsButton);

        statusView.setText(getString(R.string.mtls_intro, App.MTLS_BASE_URL));
        enrollButton.setOnClickListener(v -> enroll());
        autoEnrollButton.setOnClickListener(v -> autoEnroll());
        mtlsTestButton.setOnClickListener(v -> testMtls());
        unenrollButton.setOnClickListener(v -> unenroll());
        importP12Button.setOnClickListener(v -> toggleManualP12());
        mockTlsButton.setOnClickListener(v -> connectMock(App.MOCK_TLS_URL, false));
        mockMtlsButton.setOnClickListener(v -> connectMock(App.MOCK_MTLS_URL, true));

        App.INIT.addObserver(initObserver);
        updateButtons();
    }

    private boolean enrolled() {
        return PinVault.INSTANCE.isEnrolled(getApplicationContext(), null);
    }

    @Override
    protected void updateButtons() {
        boolean ready = App.INIT.get().phase == InitState.Phase.READY;
        boolean enrolled = enrolled();
        boolean manual = AppSettings.useManualP12(this);
        boolean mtlsConfigMode = App.ACTIVE_MODE == AppSettings.Mode.MTLS_CONFIG;
        boolean idle = !isBusy();

        StringBuilder state = new StringBuilder(enrolled
                ? getString(R.string.mtls_enrolled, PinVault.INSTANCE.enrolledClientCN(getApplicationContext(), null))
                : getString(R.string.mtls_not_enrolled));
        if (manual) state.append('\n').append(getString(R.string.mtls_manual_active));
        enrollStateView.setText(state);

        tokenInput.setEnabled(!enrolled && idle);
        // Kayıt varsayılan blok üzerinden yapılır; mTLS config modunda o blok zaten sertifika ister.
        enrollButton.setEnabled(ready && !enrolled && idle && !mtlsConfigMode);
        autoEnrollButton.setEnabled(ready && !enrolled && idle && !mtlsConfigMode);
        mtlsTestButton.setEnabled(ready && idle);
        unenrollButton.setEnabled(idle && enrolled);
        importP12Button.setEnabled(idle);
        importP12Button.setText(manual ? R.string.mtls_manual_drop : R.string.mtls_manual_import);
        mockTlsButton.setEnabled(ready && idle);
        mockMtlsButton.setEnabled(ready && idle);
    }

    private void enroll() {
        String token = tokenInput.getText().toString().trim();
        if (token.isEmpty()) {
            showResult(getString(R.string.mtls_token_required));
            return;
        }
        runAction(getString(R.string.mtls_enrolling), () -> {
            if (!PinManagerLite.enrollBlocking(getApplicationContext(), token)) {
                return getString(R.string.mtls_enroll_failed);
            }
            String cn = PinVault.INSTANCE.enrolledClientCN(getApplicationContext(), null);
            return getString(R.string.mtls_enroll_success, cn == null ? "?" : cn);
        });
    }

    private void autoEnroll() {
        runAction(getString(R.string.mtls_auto_enrolling), () -> {
            if (!PinManagerLite.autoEnrollBlocking(getApplicationContext())) {
                return getString(R.string.mtls_auto_enroll_failed);
            }
            String cn = PinVault.INSTANCE.enrolledClientCN(getApplicationContext(), null);
            return getString(R.string.mtls_auto_enroll_success, cn == null ? "?" : cn);
        });
    }

    /** mTLS Config API'nin /health ucuna pinli ve (kayıtlıysa) sertifikalı istek. */
    private void testMtls() {
        runAction(getString(R.string.connecting_fmt, App.MTLS_BASE_URL), () ->
                pinnedGet(pinnedClient(), App.MTLS_BASE_URL + "health",
                        "mTLS bağlantısı başarılı", "mTLS bağlantısı reddedildi",
                        "istemci sertifikası kabul edildi"));
    }

    /** Host'taki mock hedef host'a pinli istek; mTLS mock'u istemci sertifikası da ister. */
    private void connectMock(String url, boolean mtls) {
        runAction(getString(R.string.connecting_fmt, url), () ->
                pinnedGet(pinnedClient(), url,
                        mtls ? "Mock mTLS host bağlantısı başarılı" : "Mock TLS host bağlantısı başarılı",
                        mtls ? "Mock mTLS host bağlantısı reddedildi" : "Mock TLS host bağlantısı reddedildi",
                        mtls ? "pin doğrulandı, istemci sertifikası kabul edildi" : "pin doğrulandı"));
    }

    private void unenroll() {
        runAction(getString(R.string.mtls_unenrolling), () -> {
            // Kütüphane sertifikayı depodan siler ve yüklü istemci anahtarını da
            // bellekten boşaltır; bağlantı aynı süreçte kesilir, yeniden kurmaya
            // gerek yok. (Eski sürümlerde anahtar bellekte kaldığı için burada
            // PinVault yeniden kuruluyordu.)
            PinVault.INSTANCE.unenroll(getApplicationContext(), null);

            // Tek istisna: config'in kendisi mTLS üzerinden çekiliyorsa o blok
            // sertifikasız çalışamaz, o yüzden TLS moduna dönülür.
            if (AppSettings.mode(this) == AppSettings.Mode.MTLS_CONFIG && !AppSettings.useManualP12(this)) {
                ((App) getApplication()).applyMode(AppSettings.Mode.TLS);
                InitState.Snapshot s = App.INIT.awaitSettled(60_000);
                if (s.phase == InitState.Phase.FAILED) {
                    return getString(R.string.mtls_unenrolled) + "\n\n❌ PinVault yeniden başlatılamadı: " + s.detail;
                }
            }
            return getString(R.string.mtls_unenrolled);
        });
    }

    /** files/manual-client.p12 dosyasını mTLS bloğunun istemci sertifikası yapar ya da bırakır. */
    private void toggleManualP12() {
        App app = (App) getApplication();
        if (AppSettings.useManualP12(this)) {
            runAction(getString(R.string.mtls_manual_dropping), () -> {
                AppSettings.setUseManualP12(this, false);
                app.restartPinVault();
                App.INIT.awaitSettled(60_000);
                return getString(R.string.mtls_manual_dropped);
            });
            return;
        }
        runAction(getString(R.string.mtls_manual_importing), () -> {
            byte[] p12 = app.readManualP12();
            if (p12 == null) return getString(R.string.mtls_manual_missing, App.MANUAL_P12_FILE);
            String cn = p12CommonName(p12);
            AppSettings.setUseManualP12(this, true);
            app.restartPinVault();
            InitState.Snapshot s = App.INIT.awaitSettled(60_000);
            String init = s.phase == InitState.Phase.READY ? "Hazır — config " + s.detail : "başlatılamadı: " + s.detail;
            return getString(R.string.mtls_manual_imported, cn, init);
        });
    }

    private static String p12CommonName(byte[] p12) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(p12), App.MANUAL_P12_PASSWORD.toCharArray());
        String alias = ks.aliases().nextElement();
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        Matcher m = CN.matcher(cert.getSubjectX500Principal().getName());
        return m.find() ? m.group(1) : cert.getSubjectX500Principal().getName();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        App.INIT.removeObserver(initObserver);
    }
}
