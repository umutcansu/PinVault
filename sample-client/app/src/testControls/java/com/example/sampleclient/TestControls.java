package com.example.sampleclient;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.text.Editable;
import android.view.View;
import android.widget.EditText;

import androidx.annotation.Nullable;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import io.github.umutcansu.pinvault.model.ClientCertEnrollmentResult;
import io.github.umutcansu.pinvault.model.ConfigApiBlock;

/**
 * Test kontrolleri: yalnızca <b>debug</b> ve <b>e2e</b> derlemelerinde vardır
 * ({@code src/testControls}). Release derlemesi bu sınıfın yerine
 * {@code src/release} altındaki boş karşılığını alır; aşağıdakilerin hiçbiri
 * release APK'sında yoktur:
 *
 * <ul>
 *   <li>Ayarlar ve Depolama ekranları (mod değiştirme, gereken imza sayısını
 *       değiştirme, sıfırlama, planlı işi iptal etme, Keystore anahtar listesi),</li>
 *   <li>açılışta {@code mode} intent ekiyle mod seçme,</li>
 *   <li>token'sız otomatik kayıt,</li>
 *   <li>elle P12 içe aktarma.</li>
 * </ul>
 *
 * <p>Bunlar kütüphaneyi denemek ve uçtan uca testler içindir. Gerçek bir
 * kullanıcının telefonunda bulunmaları, uygulamayı pin güncellemelerinden ve
 * iptalden koparmanın ya da güvenliği düşürmenin yolu olurdu.
 */
final class TestControls {

    /**
     * {@code am start … --es mode <MOD>}: uçtan uca testler uygulamayı belli bir
     * modda açar. Ana ekran dışa açık olduğu için bu eki telefondaki herhangi bir
     * uygulama da gönderebilir; o yüzden yalnızca test derlemelerinde okunur.
     */
    static final String EXTRA_MODE = "mode";

    private TestControls() {}

    /** Açılışta bir kez: test derlemelerinde yapılacak bir şey yok. */
    static void onAppStart(Context context) {
        // Release karşılığı burada elle P12 kalıntılarını siler.
    }

    // ── Ana ekran ────────────────────────────────────────────────────────────

    /** Depolama ve Ayarlar düğmelerinin satırını gösterir ve bağlar. */
    static void bindNavigation(Activity activity, View row, View storageButton, View settingsButton) {
        row.setVisibility(View.VISIBLE);
        storageButton.setOnClickListener(v -> activity.startActivity(new Intent(activity, StorageActivity.class)));
        settingsButton.setOnClickListener(v -> activity.startActivity(new Intent(activity, SettingsActivity.class)));
    }

    /**
     * Intent'te mod verildiyse ve aktif moddan farklıysa uygular. Yalnızca tam
     * olarak bilinen bir mod adı (büyük harfle, {@link AppSettings.Mode}) kabul
     * edilir; başka her değer, bozuk ek paketi dahil, yok sayılır.
     */
    static void applyLaunchIntent(Activity activity, @Nullable Intent intent) {
        AppSettings.Mode mode = modeFrom(intent);
        if (mode == null || mode == AppSettings.mode(activity)) return;
        ((App) activity.getApplication()).applyMode(mode);
    }

    @Nullable
    static AppSettings.Mode modeFrom(@Nullable Intent intent) {
        if (intent == null) return null;
        String raw;
        try {
            raw = intent.getStringExtra(EXTRA_MODE);
        } catch (RuntimeException e) {
            // Bozuk ek paketi (başka bir uygulamadan): yok say.
            return null;
        }
        if (raw == null || raw.length() > 32) return null;
        for (AppSettings.Mode mode : AppSettings.Mode.values()) {
            if (mode.name().equals(raw)) return mode;
        }
        return null;
    }

    // ── Otomatik kayıt ───────────────────────────────────────────────────────

    /** Token yerine cihaz kimliğiyle kayıt; sunucu yalnızca açık kayıt ya da kodsuz başvuru modunda kabul eder. */
    static ClientCertEnrollmentResult autoEnroll(Context context) {
        return TestEnrollment.autoEnrollBlocking(context);
    }

    // ── Elle yüklenen P12 ────────────────────────────────────────────────────

    /** mTLS bloğunda kullanılacak elle yüklenmiş kimlik; yoksa {@code null}. */
    @Nullable
    static Object loadManualIdentity(Context context) {
        return AppSettings.useManualP12(context) ? ManualP12Store.load(context) : null;
    }

    /** {@link #loadManualIdentity}'nin döndürdüğü kimliği bloğa istemci sertifikası olarak verir. */
    static void applyManualIdentity(ConfigApiBlock.Builder block, @Nullable Object identity) {
        if (!(identity instanceof ManualP12Store.Identity)) return;
        ManualP12Store.Identity manual = (ManualP12Store.Identity) identity;
        // P12 telefonda Keystore anahtarıyla şifreli durur (ManualP12Store); parolası
        // içe aktarırken üretilen rastgele bir paroladır, sabit değil.
        block.clientKeystore(manual.p12, manual.password);
    }

    /**
     * Elle yüklenen P12'yi mTLS bloğunun istemci sertifikası yapar ya da bırakır.
     *
     * <p>İçe aktarma: {@code files/manual-client.p12} kullanıcının girdiği
     * parolayla açılır, Keystore anahtarıyla şifreli bir pakete çevrilir ve düz
     * dosya silinir ({@link ManualP12Store}). Parola saklanmaz. Bırakma: şifreli
     * paket ve anahtarı silinir; yeniden kullanmak için dosya tekrar konur.
     */
    static void toggleManualP12(MtlsActivity activity, EditText passwordInput) {
        App app = (App) activity.getApplication();
        Context context = activity.getApplicationContext();
        if (AppSettings.useManualP12(activity)) {
            activity.runAction(activity.getString(R.string.mtls_manual_dropping), () -> {
                AppSettings.setUseManualP12(context, false);
                ManualP12Store.clear(context);
                app.restartPinVault();
                App.INIT.awaitSettled(60_000);
                return activity.getString(R.string.mtls_manual_dropped);
            });
            return;
        }
        char[] password = readAndClear(passwordInput);
        if (password.length == 0 && !ManualP12Store.isImported(activity)) {
            activity.showResult(activity.getString(R.string.mtls_manual_password_required));
            return;
        }
        activity.runAction(activity.getString(R.string.mtls_manual_importing), () -> {
            String cn;
            if (ManualP12Store.hasInbox(context)) {
                if (password.length == 0) return activity.getString(R.string.mtls_manual_password_required);
                try {
                    cn = ManualP12Store.importFromInbox(context, password);
                } catch (ManualP12Store.WrongPasswordException e) {
                    return activity.getString(R.string.mtls_manual_wrong_password);
                }
            } else {
                // Daha önce içe aktarılmış (şifreli kopya duruyor): yeniden kullan.
                ManualP12Store.Identity identity = ManualP12Store.load(context);
                if (identity == null) return activity.getString(R.string.mtls_manual_missing, ManualP12Store.INBOX_FILE);
                cn = commonName(identity);
            }
            AppSettings.setUseManualP12(context, true);
            app.restartPinVault();
            InitState.Snapshot s = App.INIT.awaitSettled(60_000);
            String init = s.phase == InitState.Phase.READY ? "Hazır — config " + s.detail : "başlatılamadı: " + s.detail;
            return activity.getString(R.string.mtls_manual_imported, cn, init);
        });
    }

    /** Parola alanını okur ve hemen boşaltır: ekranda ve String olarak kalmasın. */
    private static char[] readAndClear(EditText input) {
        Editable text = input.getText();
        char[] out = new char[text.length()];
        text.getChars(0, text.length(), out, 0);
        text.clear();
        return out;
    }

    private static String commonName(ManualP12Store.Identity identity) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(identity.p12), identity.password.toCharArray());
        String alias = ks.aliases().nextElement();
        return ManualP12Store.commonName((X509Certificate) ks.getCertificate(alias));
    }
}
