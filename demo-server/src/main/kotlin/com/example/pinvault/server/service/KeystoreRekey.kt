package com.example.pinvault.server.service

import com.example.pinvault.server.store.HostClientCertStore
import java.io.File
import java.security.KeyStore

/**
 * Moves the server's keystores to [CertificateService.KEYSTORE_PASSWORD] at
 * startup, so setting (or changing) the variable on an existing install also
 * protects what is already on disk — and rewrites any legacy JKS file as
 * PKCS12 ([ServerKeyStores]), so a key stays under JKS's SHA-1 protection
 * only until the first start of this version.
 *
 * A keystore that does not open with the current password is tried with
 * `KEYSTORE_PASSWORD_PREVIOUS` (for a change from one password to another)
 * and the old default, then written back under the current one. Only the
 * files the server owns are touched: its TLS keystore and backup key, each
 * host's keystore and backup key, the client truststore, the CAs, the
 * recovery key, and the stored host client certificates. Anything that opens
 * with none of the passwords is left alone and reported.
 */
class KeystoreRekey(
    private val certService: CertificateService,
    private val password: String = CertificateService.KEYSTORE_PASSWORD,
    previous: String? = System.getenv("KEYSTORE_PASSWORD_PREVIOUS")?.takeIf { it.isNotBlank() }
) {
    private val candidates = listOfNotNull(previous, CertificateService.LEGACY_KEYSTORE_PASSWORD, P12Transfer.legacyPassword)
        .distinct().filter { it != password }

    /**
     * [rekeyed]: written under the current password; [converted]: already
     * under it, but a legacy JKS rewritten as PKCS12; [unreadable]: opens
     * with no known password, left alone.
     */
    class Report(val rekeyed: List<String>, val unreadable: List<String>, val converted: List<String> = emptyList())

    fun run(keystores: Collection<File>, hostClientCerts: HostClientCertStore?): Report {
        val rekeyed = mutableListOf<String>()
        val converted = mutableListOf<String>()
        val unreadable = mutableListOf<String>()
        for (file in keystores.map { it.absoluteFile }.distinct().filter { it.isFile }) {
            when (rekey(file)) {
                Outcome.REKEYED -> rekeyed += file.name
                Outcome.CONVERTED -> converted += file.name
                Outcome.UNREADABLE -> unreadable += file.name
                Outcome.CURRENT -> Unit
            }
        }
        hostClientCerts?.allP12()?.forEach { (hostname, scope, p12) ->
            val current = certService.p12Password(p12, listOf(password) + candidates)
            when (current) {
                password -> Unit
                null -> unreadable += "host client certificate $hostname ($scope)"
                else -> {
                    hostClientCerts.replaceP12(hostname, scope, certService.rewrapP12(p12, current, password))
                    rekeyed += "host client certificate $hostname ($scope)"
                }
            }
        }
        return Report(rekeyed, unreadable, converted)
    }

    private enum class Outcome { CURRENT, REKEYED, CONVERTED, UNREADABLE }

    private fun rekey(file: File): Outcome {
        val bytes = file.readBytes()
        if (opens(bytes, password)) {
            // Current password; a legacy JKS still gets the PKCS12 form.
            return if (ServerKeyStores.convertLegacy(file, password.toCharArray())) Outcome.CONVERTED else Outcome.CURRENT
        }
        val old = candidates.firstOrNull { opens(bytes, it) } ?: return Outcome.UNREADABLE
        val source = ServerKeyStores.load(bytes, old.toCharArray())
        val target: KeyStore = ServerKeyStores.copy(source, old.toCharArray(), password.toCharArray())
        ServerKeyStores.writeAtomically(file, target, password.toCharArray())
        return Outcome.REKEYED
    }

    private fun opens(bytes: ByteArray, candidate: String): Boolean =
        runCatching { ServerKeyStores.load(bytes, candidate.toCharArray()) }.isSuccess
}
