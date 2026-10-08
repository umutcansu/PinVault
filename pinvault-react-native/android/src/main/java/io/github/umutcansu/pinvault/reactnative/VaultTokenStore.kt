package io.github.umutcansu.pinvault.reactnative

import java.util.concurrent.ConcurrentHashMap

/**
 * Vault access tokens and the enrollment token of a running call, in memory
 * only: never written to disk, gone with the process. The vault files'
 * `accessToken { … }` providers read from here on every download. Every
 * string that goes back to JS is passed through [redact], so a token that a
 * native message happens to echo never reaches JS.
 */
internal class VaultTokenStore {

    private val tokens = ConcurrentHashMap<String, String>()
    private val transient = ConcurrentHashMap.newKeySet<String>()

    fun put(key: String, token: String?) {
        if (token.isNullOrEmpty()) tokens.remove(key) else tokens[key] = token
    }

    /** Empty when there is none: the server refuses that as an invalid token. */
    fun get(key: String): String = tokens[key] ?: ""

    fun clear(): Int {
        val n = tokens.size
        tokens.clear()
        return n
    }

    /** A secret that is not stored but must still be redacted while a call runs (enrollment token). */
    fun <T> withTransientSecret(secret: String, block: () -> T): T {
        if (secret.length >= MIN_REDACT_LENGTH) transient += secret
        try {
            return block()
        } finally {
            transient -= secret
        }
    }

    suspend fun <T> withTransientSecretSuspend(secret: String, block: suspend () -> T): T {
        if (secret.length >= MIN_REDACT_LENGTH) transient += secret
        try {
            return block()
        } finally {
            transient -= secret
        }
    }

    fun redact(text: String?): String? {
        if (text == null) return null
        var out: String = text
        for (secret in tokens.values + transient) {
            if (secret.length >= MIN_REDACT_LENGTH) out = out.replace(secret, "***")
        }
        return if (out.length > MAX_MESSAGE) out.take(MAX_MESSAGE) + "…" else out
    }

    companion object {
        /** Shorter values would redact ordinary words. */
        const val MIN_REDACT_LENGTH = 6
        const val MAX_MESSAGE = 1000
    }
}
