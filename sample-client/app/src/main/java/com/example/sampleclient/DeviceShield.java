package com.example.sampleclient;

import android.os.Debug;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Locale;

import io.github.umutcansu.pinvault.model.GuardedOperation;

/**
 * Uygulamanın kendi "bu telefon güvenilir mi?" kontrolü; PinVault'a
 * {@code environmentGuard} olarak bağlanır ({@link App}).
 *
 * <p>Kütüphane atestasyon raporunda root, hooking ve hata ayıklayıcı
 * sinyallerini zaten ölçüp sunucuya gönderir ama cihazda kendi başına hiçbir
 * şeyi durdurmaz: yerel tepki uygulamanındır. Bu sınıf o tepkinin küçük bir
 * örneğidir — üç kontrol, hepsi düz Java, hepsi hook'lanabilir. Gerçek bir
 * uygulamada bunun yerine bir RASP ürünü ya da RootBeer kullan ve kararını
 * aynı yere bağla (README → "Bypass protection"). Sunucu tarafındaki
 * atestasyon politikası asıl karar yeridir; bu yalnızca bir hız kesici.
 *
 * <p>Kontroller:
 * <ul>
 *   <li><b>root</b>: bilinen yerlerde {@code su} ikilisi ya da Magisk /
 *       KernelSU / APatch dosyaları,</li>
 *   <li><b>hata ayıklayıcı</b>: sürece bağlı bir debugger ya da
 *       {@code /proc/self/status} içinde sıfırdan farklı {@code TracerPid},</li>
 *   <li><b>hooking</b>: {@code /proc/self/maps} içinde Frida / Xposed /
 *       Substrate / Dobby kütüphaneleri.</li>
 * </ul>
 * Emülatör kontrolü bilerek yok: örnek uygulama emülatörde de çalışır.
 * {@code test-keys} ve {@code ro.debuggable} de bakılmaz; emülatör imajlarında
 * ve bazı üretici derlemelerinde her zaman işaretlidir.
 *
 * <p>Dosya tabanlı kontrollerin sonucu {@value #CACHE_MS} ms önbelleğe alınır:
 * guard ana thread'de de sorulur ({@code unlockFile}), hızlı olmalı. Debugger
 * kontrolü her seferinde yapılır, ucuzdur ve sonradan bağlanabilir.
 */
final class DeviceShield {

    private static final long CACHE_MS = 30_000L;

    private static final String[] SU_PATHS = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
            "/system/su", "/system/bin/.ext/.su", "/vendor/bin/su", "/data/local/su",
            "/data/local/bin/su", "/data/local/xbin/su", "/system/sd/xbin/su",
            "/system/bin/failsafe/su", "/system/xbin/daemonsu"
    };

    private static final String[] ROOT_MANAGER_PATHS = {
            "/sbin/.magisk", "/sbin/.core", "/data/adb/magisk", "/data/adb/magisk.db",
            "/data/adb/ksu", "/data/adb/ksud", "/data/adb/ap", "/data/adb/apd"
    };

    private static final String[] HOOK_LIBRARIES = {
            "frida", "gadget", "xposed", "substrate", "dobby", "lsposed", "riru", "zygisk"
    };

    private static volatile long checkedAt = 0L;
    private static volatile boolean cachedVerdict = false;

    private DeviceShield() {}

    /**
     * PinVault'un sorduğu karar. {@code INIT} her zaman geçer: pinli trafik
     * çalışmaya devam etsin, sunucu atestasyonla kendi kararını versin.
     * Kayıt, dosya indirme ve dosya açma bozuk cihazda reddedilir; kütüphane
     * bunları {@code UntrustedEnvironmentException} nedeniyle {@code Failed}
     * döndürür, hiçbir şey gönderilmez, token harcanmaz.
     *
     * <p>Test derlemelerinde Ayarlar'daki "Ortam kontrolü" kapalıyken
     * ({@link AppSettings#environmentGuard}) hep {@code true}: uçtan uca
     * testler {@code su} taşıyan userdebug emülatör imajlarında koşar.
     */
    static boolean allows(android.content.Context context, GuardedOperation operation) {
        if (operation == GuardedOperation.INIT) return true;
        if (!AppSettings.environmentGuard(context)) return true;
        boolean compromised = isCompromised();
        if (compromised) Log.w(App.TAG, "Environment guard refused " + operation + ": device looks compromised");
        return !compromised;
    }

    /** Root, debugger ya da hooking izi var mı. */
    static boolean isCompromised() {
        if (debuggerAttached()) return true;
        long now = android.os.SystemClock.elapsedRealtime();
        if (now - checkedAt < CACHE_MS) return cachedVerdict;
        boolean verdict = rooted() || hooked();
        cachedVerdict = verdict;
        checkedAt = now;
        return verdict;
    }

    private static boolean rooted() {
        for (String path : SU_PATHS) {
            if (exists(path)) return true;
        }
        for (String path : ROOT_MANAGER_PATHS) {
            if (exists(path)) return true;
        }
        return false;
    }

    private static boolean debuggerAttached() {
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) return true;
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    return !"0".equals(line.substring("TracerPid:".length()).trim());
                }
            }
        } catch (IOException | RuntimeException e) {
            // Okunamıyorsa "temiz" demek değil; ama tek başına ret nedeni de değil.
        }
        return false;
    }

    private static boolean hooked() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                int slash = line.lastIndexOf('/');
                if (slash < 0) continue;
                String name = line.substring(slash + 1).toLowerCase(Locale.ROOT);
                for (String hook : HOOK_LIBRARIES) {
                    if (name.contains(hook)) return true;
                }
            }
        } catch (IOException | RuntimeException e) {
            // Aynı not.
        }
        return false;
    }

    private static boolean exists(String path) {
        try {
            return new File(path).exists();
        } catch (RuntimeException e) {
            return false;
        }
    }
}
