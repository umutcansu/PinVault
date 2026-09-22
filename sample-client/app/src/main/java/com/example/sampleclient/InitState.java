package com.example.sampleclient;

import androidx.annotation.Nullable;

import java.util.concurrent.CopyOnWriteArrayList;

/**
 * PinVault'un başlatılma durumunu ekranlara taşıyan küçük, gözlemlenebilir
 * holder. {@link App} init callback'inden yazar; ekranlar dinler.
 *
 * <p>Durum tek bir değişmez {@link Snapshot} olarak tutulur; okuyan taraf faz
 * ile açıklamayı her zaman tutarlı bir çift olarak görür. Birden fazla ekran
 * aynı anda dinleyebilir.
 */
public final class InitState {

    public enum Phase { INITIALIZING, READY, FAILED }

    public static final class Snapshot {
        public final Phase phase;
        /** READY: config sürümü ("v29"); FAILED: hata nedeni; aksi halde null. */
        @Nullable public final String detail;

        Snapshot(Phase phase, @Nullable String detail) {
            this.phase = phase;
            this.detail = detail;
        }
    }

    private volatile Snapshot current = new Snapshot(Phase.INITIALIZING, null);
    private final CopyOnWriteArrayList<Runnable> observers = new CopyOnWriteArrayList<>();

    public Snapshot get() {
        return current;
    }

    public void set(Phase phase, @Nullable String detail) {
        synchronized (this) {
            current = new Snapshot(phase, detail);
            notifyAll();
        }
        for (Runnable o : observers) o.run();
    }

    /** Her değişiklikte çağrılır (herhangi bir thread'den). */
    public void addObserver(Runnable observer) {
        observers.addIfAbsent(observer);
    }

    public void removeObserver(Runnable observer) {
        observers.remove(observer);
    }

    /**
     * Başlatma bitene (READY ya da FAILED) kadar bekler ve son durumu döndürür.
     * UI thread'inden çağırma.
     */
    public Snapshot awaitSettled(long timeoutMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        synchronized (this) {
            while (current.phase == Phase.INITIALIZING) {
                long left = deadline - System.currentTimeMillis();
                if (left <= 0) break;
                wait(left);
            }
            return current;
        }
    }
}
