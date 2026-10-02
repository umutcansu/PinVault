package com.example.sampleclient;

import androidx.annotation.Nullable;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import io.github.umutcansu.pinvault.api.PinVaultConnectionEvent;
import io.github.umutcansu.pinvault.api.PinVaultConnectionListener;

/**
 * {@link PinVaultConnectionEvent}'lerin uygulama içi halka tamponu;
 * {@link MainActivity} canlı olay listesi olarak gösterir.
 *
 * <p>Kütüphane listener'ı TLS el sıkışma thread'inin dışında, tek bir arka plan
 * thread'inde çağırır. {@link #observer} UI thread'ine geçişten sorumludur.
 *
 * <p>En yeni kayıt başta. Tampon {@link #MAX_ENTRIES} ile sınırlı.
 */
public class ConnectionEventLog implements PinVaultConnectionListener {

    private static final int MAX_ENTRIES = 50;

    private final List<String> entries = new ArrayList<>();

    @Nullable
    private volatile Runnable observer;

    @Override
    public void onEvent(PinVaultConnectionEvent event) {
        String time = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
        String line = null;

        if (event instanceof PinVaultConnectionEvent.Connection) {
            PinVaultConnectionEvent.Connection c = (PinVaultConnectionEvent.Connection) event;
            String hostname = c.getHostname().isEmpty() ? "?" : c.getHostname();
            String pin = c.getActualPin();
            String pinPreview = pin.length() > 12 ? pin.substring(0, 12) + "…" : pin;
            line = String.format(Locale.US, "%s [%s] %s  pin v%d  sha256/%s",
                    time, c.getSuccess() ? "✓" : "✗ UYUŞMAZLIK", hostname, c.getPinVersion(), pinPreview);
        } else if (event instanceof PinVaultConnectionEvent.ConfigUpdate) {
            PinVaultConnectionEvent.ConfigUpdate u = (PinVaultConnectionEvent.ConfigUpdate) event;
            String reason = u.getFailureReason() == null ? "" : " — " + u.getFailureReason();
            line = String.format(Locale.US, "%s [config] %s v%d%s",
                    time, u.getStatus().name(), u.getNewVersion(), reason);
        }

        if (line != null) {
            synchronized (this) {
                entries.add(0, line);
                while (entries.size() > MAX_ENTRIES) {
                    entries.remove(entries.size() - 1);
                }
            }
        }

        Runnable o = this.observer;
        if (o != null) o.run();
    }

    public synchronized List<String> snapshot() {
        return new ArrayList<>(entries);
    }

    public void clear() {
        synchronized (this) {
            entries.clear();
        }
        Runnable o = this.observer;
        if (o != null) o.run();
    }

    /** Her olaydan sonra çağrılır. {@code null} ile ayrılır. */
    public void setObserver(@Nullable Runnable observer) {
        this.observer = observer;
    }
}
