package com.example.sampleclient;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.List;

import okhttp3.Dns;

/**
 * Host'taki mock hedef host'ların adlarını ({@code mock-tls.sample},
 * {@code mock-mtls.sample}) host'un IP'sine çözümler. Adlar gerçek DNS'te yok;
 * sertifikaları bu adlara kesildiği için bağlantı ad ile kurulmalı. Diğer her
 * ad sistem DNS'ine gider.
 */
public final class MockDns implements Dns {

    public static final MockDns INSTANCE = new MockDns();

    private MockDns() {}

    @Override
    public List<InetAddress> lookup(String hostname) throws UnknownHostException {
        if (isMockHost(hostname)) {
            return Collections.singletonList(InetAddress.getByName(BuildConfig.HOST_IP));
        }
        return Dns.SYSTEM.lookup(hostname);
    }

    public static boolean isMockHost(String hostname) {
        return hostname.equalsIgnoreCase(BuildConfig.MOCK_TLS_HOST)
                || hostname.equalsIgnoreCase(BuildConfig.MOCK_MTLS_HOST);
    }
}
