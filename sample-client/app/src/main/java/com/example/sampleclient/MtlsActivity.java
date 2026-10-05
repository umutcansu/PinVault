package com.example.sampleclient;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import io.github.umutcansu.pinvault.PinVault;
import io.github.umutcansu.pinvault.model.ClientCertEnrollmentResult;

/**
 * mTLS: istemci sertifikası alma ve kullanma.
 *
 * <ul>
 *   <li><b>Kayıt ol:</b> dashboard'da üretilen tek kullanımlık token ile
 *       istemci sertifikası alınır: anahtar telefonun Keystore'unda üretilir,
 *       sunucu CSR'ı imzalar (CSR bilmeyen sunucuda P12 gelir ve
 *       {@code X-P12-SHA256} ile doğrulanır). Olmazsa ekranda nedeni yazar.</li>
 *   <li><b>Otomatik kayıt</b> ve <b>P12 içe aktar</b> test kontrolleridir:
 *       yalnızca debug ve e2e derlemelerinde görünür ({@link TestControls}).
 *       Otomatik kayıt token yerine cihaz kimliğini (ANDROID_ID) kullanır;
 *       elle P12, {@code files/manual-client.p12} dosyasını kayıt yerine
 *       istemci sertifikası yapar. Release derlemesinde ikisi de yoktur: cihaz
 *       yalnızca yöneticinin verdiği token ya da kayıt koduyla kayıt olur ve
 *       özel anahtar telefonun Keystore'unda üretilir, dosyaya hiç düşmez.</li>
 *   <li><b>mTLS ile test:</b> mTLS Config API'nin {@code /health} ucuna
 *       sertifikalı, pinli istek. <b>Mock host'lar:</b> host'taki TLS ve
 *       mTLS mock hedeflerine pinli istek.</li>
 *   <li><b>Kaydı sil:</b> sertifika depodan silinir; mTLS bloğunun vault
 *       dosyaları (kilitli kopyalar dahil) da silinir.</li>
 * </ul>
 *
 * <p>Kayıttan sonra mTLS Config API bloğu bir sonraki PinVault kurulumunda
 * eklenir (uygulamayı yeniden aç; test derlemelerinde Ayarlar → "Sıfırla ve
 * başlat" da olur).
 */
public class MtlsActivity extends ActionActivity {

    /** Onay bekleyen kayıt kaç saniyede bir, en çok ne kadar sorulur. */
    private static final long APPROVAL_POLL_MS = 3_000;
    private static final long APPROVAL_WAIT_MS = 10 * 60_000;

    private TextView enrollStateView;
    private EditText tokenInput;
    private EditText p12PasswordInput;
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
        TextView deviceIdView = findViewById(R.id.mtlsDeviceIdView);
        tokenInput = findViewById(R.id.tokenInput);
        p12PasswordInput = findViewById(R.id.p12PasswordInput);
        enrollButton = findViewById(R.id.enrollButton);
        autoEnrollButton = findViewById(R.id.autoEnrollButton);
        mtlsTestButton = findViewById(R.id.mtlsTestButton);
        unenrollButton = findViewById(R.id.unenrollButton);
        importP12Button = findViewById(R.id.importP12Button);
        mockTlsButton = findViewById(R.id.mockTlsButton);
        mockMtlsButton = findViewById(R.id.mockMtlsButton);

        statusView.setText(getString(R.string.mtls_intro, App.MTLS_BASE_URL));
        // Yönetici panelde token üretirken bu kimliği yazarsa token yalnızca bu
        // telefona çalışır ve telefonun dosyaları/anahtarları sertifikasına bağlanır.
        deviceIdView.setText(getString(R.string.mtls_device_id, App.deviceId(this)));
        enrollButton.setOnClickListener(v -> enroll());
        mtlsTestButton.setOnClickListener(v -> testMtls());
        unenrollButton.setOnClickListener(v -> unenroll());
        mockTlsButton.setOnClickListener(v -> connectMock(App.MOCK_TLS_URL, false));
        mockMtlsButton.setOnClickListener(v -> connectMock(App.MOCK_MTLS_URL, true));
        if (BuildConfig.TEST_CONTROLS) {
            // Test kontrolleri: düzende gizli dururlar, yalnızca debug ve e2e
            // derlemeleri gösterir ve bağlar.
            autoEnrollButton.setVisibility(View.VISIBLE);
            p12PasswordInput.setVisibility(View.VISIBLE);
            importP12Button.setVisibility(View.VISIBLE);
            autoEnrollButton.setOnClickListener(v -> autoEnroll());
            importP12Button.setOnClickListener(v -> TestControls.toggleManualP12(this, p12PasswordInput));
        }

        App.INIT.addObserver(initObserver);
        updateButtons();
        // Kayıt kodu onay bekliyorsa ekran açılınca beklemeye devam eder.
        if (pending()) runAction(pendingState(), () -> awaitApproval(null));
    }

    private boolean enrolled() {
        return PinVault.INSTANCE.isEnrolled(getApplicationContext(), null);
    }

    /** Kayıt kodu gönderildi, yönetici henüz onaylamadı. */
    private boolean pending() {
        return PinVault.INSTANCE.isEnrollmentPending(getApplicationContext(), null);
    }

    /** "Kayıt onay bekliyor · <doğrulama kodu>": panelde isteğin yanında aynı kod yazar. */
    private String pendingState() {
        String code = PinVault.INSTANCE.enrollmentVerificationCode(getApplicationContext(), null);
        return getString(R.string.mtls_pending_state, code == null ? "?" : code);
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
                : pending() ? pendingState() : getString(R.string.mtls_not_enrolled));
        if (manual) state.append('\n').append(getString(R.string.mtls_manual_active));
        enrollStateView.setText(state);

        tokenInput.setEnabled(!enrolled && idle);
        // Kayıt varsayılan blok üzerinden yapılır; mTLS config modunda o blok zaten sertifika ister.
        enrollButton.setEnabled(ready && !enrolled && idle && !mtlsConfigMode);
        autoEnrollButton.setEnabled(ready && !enrolled && idle && !mtlsConfigMode);
        mtlsTestButton.setEnabled(ready && idle);
        unenrollButton.setEnabled(idle && enrolled);
        importP12Button.setEnabled(idle);
        p12PasswordInput.setEnabled(idle && !manual);
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
        // Token (ya da kayıt kodu) tek kullanımlık bir gizli değer: istek yola
        // çıkınca ekranda ve alanın belleğinde kalmasın. Kayıt olmazsa yeniden girilir.
        tokenInput.setText("");
        runAction(getString(R.string.mtls_enrolling), () -> {
            ClientCertEnrollmentResult result = PinManagerLite.enrollBlocking(getApplicationContext(), token);
            if (result instanceof ClientCertEnrollmentResult.Pending) {
                return awaitApproval((ClientCertEnrollmentResult.Pending) result);
            }
            return enrollOutcome(result);
        });
    }

    /** Kaydın sonucu, durum kutusunda gösterildiği gibi. */
    private String enrollOutcome(ClientCertEnrollmentResult result) {
        if (!(result instanceof ClientCertEnrollmentResult.Enrolled)) {
            return getString(R.string.mtls_enroll_failed_fmt, failureReason(result));
        }
        String cn = PinVault.INSTANCE.enrolledClientCN(getApplicationContext(), null);
        return getString(R.string.mtls_enroll_success, cn == null ? "?" : cn);
    }

    /**
     * Kayıt kodunun politikası onay istiyor: yönetici panelde onaylayana ya da
     * reddedene kadar birkaç saniyede bir sorar (kütüphane aynı anahtarla imzalı
     * CSR'ı istek numarasıyla yollar). Arka plan thread'inde çalışır; arada
     * durum kutusunda "onay bekleniyor" yazar. Onaylanınca sertifika yüklenir.
     */
    private String awaitApproval(ClientCertEnrollmentResult.Pending first) {
        String clientId = first != null && first.getClientId() != null ? first.getClientId() : "?";
        String code = PinVault.INSTANCE.enrollmentVerificationCode(getApplicationContext(), null);
        String waiting = getString(R.string.mtls_pending_fmt, clientId, code == null ? "?" : code);
        // Kayıt durumu satırı da "onay bekliyor"a döner (düğmeler iş bitene dek kilitli kalır).
        ui.post(() -> {
            statusView.setText(waiting);
            updateButtons();
        });
        long deadline = System.currentTimeMillis() + APPROVAL_WAIT_MS;
        while (System.currentTimeMillis() < deadline && !io.isShutdown()) {
            try {
                Thread.sleep(APPROVAL_POLL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            ClientCertEnrollmentResult result = PinManagerLite.checkPendingBlocking(getApplicationContext());
            if (result instanceof ClientCertEnrollmentResult.Pending) continue;
            // Sunucuya ulaşılamadı ama istek duruyor: sormaya devam.
            if (result instanceof ClientCertEnrollmentResult.Failed && pending()) continue;
            return enrollOutcome(result);
        }
        return getString(R.string.mtls_still_pending);
    }

    /** Test kontrolü (debug, e2e): token'sız kayıt. Release'te düğmesi de bu yol da yok. */
    private void autoEnroll() {
        runAction(getString(R.string.mtls_auto_enrolling), () -> {
            ClientCertEnrollmentResult result = TestControls.autoEnroll(getApplicationContext());
            // Sunucu kodsuz başvuruları açtıysa: yönetici onaylayana dek beklenir.
            if (result instanceof ClientCertEnrollmentResult.Pending) {
                return awaitApproval((ClientCertEnrollmentResult.Pending) result);
            }
            if (result instanceof ClientCertEnrollmentResult.Failed) {
                // Ret değil: sunucudan kullanılabilir bir cevap gelmedi.
                return getString(R.string.mtls_auto_enroll_not_completed_fmt, ((ClientCertEnrollmentResult.Failed) result).getMessage());
            }
            if (!(result instanceof ClientCertEnrollmentResult.Enrolled)) {
                return getString(R.string.mtls_auto_enroll_failed_fmt, failureReason(result));
            }
            String cn = PinVault.INSTANCE.enrolledClientCN(getApplicationContext(), null);
            return getString(R.string.mtls_auto_enroll_success, cn == null ? "?" : cn);
        });
    }

    /**
     * Kayıt neden olmadı: sunucunun reddi (ne yapılacağıyla birlikte) ya da
     * cevaba hiç ulaşılamaması. Eskiden her durumda "token geçersiz" yazıyordu.
     */
    private String failureReason(ClientCertEnrollmentResult result) {
        if (result instanceof ClientCertEnrollmentResult.Refused) {
            ClientCertEnrollmentResult.Refused refused = (ClientCertEnrollmentResult.Refused) result;
            switch (refused.getReason()) {
                case INVALID_TOKEN: return getString(R.string.mtls_refusal_invalid_token);
                case DEVICE_ALREADY_ENROLLED: return getString(R.string.mtls_refusal_device_already_enrolled);
                case REVOKED: return getString(R.string.mtls_refusal_revoked);
                case TOKEN_REQUIRED: return getString(R.string.mtls_refusal_token_required);
                case REJECTED: return getString(R.string.mtls_refusal_rejected);
                case LIMIT_REACHED: return getString(R.string.mtls_refusal_limit_reached);
                case EXPIRED: return getString(R.string.mtls_refusal_expired);
                default:
                    String error = refused.getServerError();
                    // Panelde token başka bir telefonun kimliğine bağlanmış (token harcanmadı).
                    if ("device_uid_mismatch".equals(error)) {
                        return getString(R.string.mtls_refusal_device_uid_mismatch, App.deviceId(this));
                    }
                    return getString(R.string.mtls_refusal_other, refused.getHttpStatus(), error == null ? "" : " " + error);
            }
        }
        if (result instanceof ClientCertEnrollmentResult.Failed) {
            return getString(R.string.mtls_enroll_not_completed, ((ClientCertEnrollmentResult.Failed) result).getMessage());
        }
        return "";
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
            // wipeVaultFiles=true: bu sertifikayla mTLS kullanan bloğun (sample-mtls)
            // vault dosyaları da gider, kilitli kopyalar dahil. Kaydı silinen cihazda
            // gizli dosya kalmamalı. TLS bloğunun herkese açık dosyaları kalır.
            PinVault.INSTANCE.unenroll(getApplicationContext(), null, true);
            // Vault token'ları bu cihaz kimliğine verilmişti; kayıt silinince onlar da
            // unutulur (sunucunun kimliği iptal ettiği durumda App de aynısını yapar).
            VaultTokens.clear();

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

    @Override
    protected void onDestroy() {
        super.onDestroy();
        App.INIT.removeObserver(initObserver);
    }
}
