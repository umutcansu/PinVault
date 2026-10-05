package com.example.sampleclient;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import android.view.View;
import android.widget.EditText;

import androidx.annotation.Nullable;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.KeyStore;

import io.github.umutcansu.pinvault.model.ClientCertEnrollmentResult;
import io.github.umutcansu.pinvault.model.ConfigApiBlock;

/**
 * Release derlemesindeki karşılık: test kontrollerinin hiçbiri yok.
 *
 * <p>Debug ve e2e derlemeleri bu sınıfın {@code src/testControls} altındaki
 * hâlini alır (Ayarlar ve Depolama ekranları, {@code mode} intent eki, otomatik
 * kayıt, elle P12). Burada hepsi boştur: ekranlar ve o kod yolları release
 * APK'sına hiç girmez, manifest'te de yer almaz.
 */
final class TestControls {

    /** Eski sürümlerin bıraktığı elle P12 dosyaları ve Keystore anahtarı. */
    private static final String[] MANUAL_P12_FILES = {"manual-client.p12", "manual-client.sealed", "manual-client.sealed.tmp"};
    private static final String MANUAL_P12_KEY_ALIAS = "sample_manual_p12";

    private TestControls() {}

    /**
     * Açılışta bir kez. Elle P12 release'te kullanılmaz; önceki bir derlemeden
     * kalmış düz ya da şifreli P12 dosyası ve onu açan Keystore anahtarı
     * varsa silinir: kullanılmayan bir özel anahtar telefonda durmasın.
     */
    static void onAppStart(Context context) {
        for (String name : MANUAL_P12_FILES) {
            wipe(new File(context.getFilesDir(), name));
        }
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (ks.containsAlias(MANUAL_P12_KEY_ALIAS)) ks.deleteEntry(MANUAL_P12_KEY_ALIAS);
        } catch (Exception e) {
            Log.w(App.TAG, "Leftover manual P12 key could not be deleted", e);
        }
    }

    /** Depolama ve Ayarlar ekranları release'te yok: satır gizli kalır. */
    static void bindNavigation(Activity activity, View row, View storageButton, View settingsButton) {
        row.setVisibility(View.GONE);
    }

    /** {@code mode} intent eki release'te okunmaz. */
    static void applyLaunchIntent(Activity activity, @Nullable Intent intent) {
        // Bilerek boş.
    }

    /** Otomatik kayıt release'te yok; düğmesi de gösterilmez. */
    static ClientCertEnrollmentResult autoEnroll(Context context) {
        throw new UnsupportedOperationException("Otomatik kayıt bu derlemede yok");
    }

    /** Elle P12 release'te yok. */
    @Nullable
    static Object loadManualIdentity(Context context) {
        return null;
    }

    static void applyManualIdentity(ConfigApiBlock.Builder block, @Nullable Object identity) {
        // Bilerek boş.
    }

    static void toggleManualP12(MtlsActivity activity, EditText passwordInput) {
        // Bilerek boş; düğmesi de gösterilmez.
    }

    /** Dosyanın üstünü sıfırlayıp siler (flash bellekte garanti değil, ama kopya kalmasın). */
    private static void wipe(File file) {
        if (!file.isFile()) return;
        try (RandomAccessFile raf = new RandomAccessFile(file, "rws")) {
            byte[] zeros = new byte[4096];
            long left = raf.length();
            while (left > 0) {
                int n = (int) Math.min(zeros.length, left);
                raf.write(zeros, 0, n);
                left -= n;
            }
        } catch (IOException e) {
            Log.w(App.TAG, "Could not overwrite " + file, e);
        }
        if (!file.delete()) Log.w(App.TAG, "Could not delete " + file);
    }
}
