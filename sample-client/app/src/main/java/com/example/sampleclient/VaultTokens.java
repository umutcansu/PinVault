package com.example.sampleclient;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Vault erişim token'ları. Yalnızca bellekte tutulur ve uygulama kapanınca
 * silinir; diske yazılmaz. PinVault token'ı her indirmede
 * {@code accessToken { … }} sağlayıcısı üzerinden buradan okur.
 */
public final class VaultTokens {

    private static final Map<String, String> TOKENS = new ConcurrentHashMap<>();

    private VaultTokens() {}

    public static void put(String key, String token) {
        if (token == null || token.isEmpty()) TOKENS.remove(key);
        else TOKENS.put(key, token);
    }

    /** Token yoksa boş dizi; sunucu bunu geçersiz token olarak reddeder. */
    public static String get(String key) {
        String token = TOKENS.get(key);
        return token == null ? "" : token;
    }
}
