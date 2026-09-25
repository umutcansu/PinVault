package com.example.pinvault.server.service

import com.example.pinvault.server.store.HostClientCertStore
import java.io.File
import java.security.KeyStore
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Moves the server's keystores to [CertificateService.KEYSTORE_PASSWORD] at
 * startup, so setting (or changing) the variable on an existing install also
 * protects what is already on disk.
 *
 * A keystore that does not open with the current password is tried with
 * `KEYSTORE_PASSWORD_PREVIOUS` (for a change from one password to another)
 * and the old default, then written back under the current one. Only the
 * files the server owns are touched: its TLS keystore and backup key, each
 * host's keystore and backup key, the client truststore, and the stored host
 * client certificates. Anything that opens with none of the passwords is
 * left alone and reported.
 */
class KeystoreRekey(
    private val certService: CertificateService,
    private val password: String = CertificateService.KEYSTORE_PASSWORD,
    previous: String? = System.getenv("KEYSTORE_PASSWORD_PREVIOUS")?.takeIf { it.isNotBlank() }
) {
    private val candidates = listOfNotNull(previous, CertificateService.LEGACY_KEYSTORE_PASSWORD, P12Transfer.legacyPassword)
        .distinct().filter { it != password }

    class Report(val rekeyed: List<String>, val unreadable: List<String>)

    fun run(keystores: Collection<File>, hostClientCerts: HostClientCertStore?): Report {
        val rekeyed = mutableListOf<String>()
        val unreadable = mutableListOf<String>()
        for (file in keystores.map { it.absoluteFile }.distinct().filter { it.isFile }) {
            when (rekeyJks(file)) {
                true -> rekeyed += file.name
                null -> unreadable += file.name
                false -> Unit
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
        return Report(rekeyed, unreadable)
    }

    /** true = rewritten, false = already current, null = opens with no known password. */
    private fun rekeyJks(file: File): Boolean? {
        if (opens(file, password)) return false
        val old = candidates.firstOrNull { opens(file, it) } ?: return null
        val source = KeyStore.getInstance("JKS").apply { file.inputStream().use { load(it, old.toCharArray()) } }
        val target = KeyStore.getInstance("JKS").apply { load(null, null) }
        for (alias in source.aliases().toList()) {
            if (source.isKeyEntry(alias)) {
                target.setKeyEntry(alias, source.getKey(alias, old.toCharArray()), password.toCharArray(), source.getCertificateChain(alias))
            } else {
                target.setCertificateEntry(alias, source.getCertificate(alias))
            }
        }
        // Write next to the file, then swap it in: a crash never leaves a half-written keystore.
        val temp = File(file.parentFile, ".${file.name}.rekey")
        temp.outputStream().use { target.store(it, password.toCharArray()) }
        Files.move(temp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        return true
    }

    private fun opens(file: File, candidate: String): Boolean = runCatching {
        KeyStore.getInstance("JKS").apply { file.inputStream().use { load(it, candidate.toCharArray()) } }
    }.isSuccess
}
