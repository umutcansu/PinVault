package io.github.umutcansu.pinvault.internal

import java.io.ByteArrayOutputStream
import java.security.KeyStore

/**
 * Re-encrypts a PKCS12 bundle from the one-off password a server sent it with
 * to the block's own `clientKeyPassword`, so storing and reloading it works
 * exactly as before — and no app has to know a server-side password.
 */
internal object P12Rewrap {

    /** Request header value asking the server for a per-response P12 password. */
    const val FEATURE = "p12password"
    const val PASSWORD_HEADER = "X-P12-Password"

    fun rewrap(p12: ByteArray, from: String, to: String): ByteArray {
        val source = KeyStore.getInstance("PKCS12").apply { load(p12.inputStream(), from.toCharArray()) }
        val target = KeyStore.getInstance("PKCS12").apply { load(null, null) }
        for (alias in source.aliases().toList()) {
            if (source.isKeyEntry(alias)) {
                target.setKeyEntry(alias, source.getKey(alias, from.toCharArray()), to.toCharArray(), source.getCertificateChain(alias))
            } else {
                target.setCertificateEntry(alias, source.getCertificate(alias))
            }
        }
        return ByteArrayOutputStream().also { target.store(it, to.toCharArray()) }.toByteArray()
    }
}
