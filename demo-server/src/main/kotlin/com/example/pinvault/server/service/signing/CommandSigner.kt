package com.example.pinvault.server.service.signing

import java.io.InputStream
import java.security.PublicKey
import java.util.concurrent.TimeUnit

/**
 * Signs by running an external command — the hook for a cloud KMS, HashiCorp
 * Vault transit, a YubiHSM/PKCS#11 tool, or a signing service on another
 * host that enforces its own approvals. The private key never touches this
 * server.
 *
 * Contract: [command] runs through `/bin/sh -c`; the bytes to sign arrive on
 * stdin; stdout carries the signature as Base64 or raw bytes, DER or r||s
 * (see [SigningKeys.normalizeSignature]); exit code 0 means success. Every
 * signature is checked against [publicKey] before use, so a misconfigured or
 * compromised signer can never make this server hand devices a signature
 * they will reject — or one from a different key.
 *
 * The command gets this server's environment minus its own secrets (admin
 * keys, key passwords, the PKCS#11 PIN, the webhook secret): a separate signer
 * is only worth having if it cannot read what the server holds. On timeout the
 * whole process tree is killed.
 */
class CommandSigner(
    override val name: String,
    private val command: String,
    private val publicKey: PublicKey,
    private val timeoutMs: Long = 10_000,
    /**
     * `payload` (default): the signer receives the bytes to sign. `digest`:
     * it receives their SHA-256 (32 raw bytes) — for signers that sign a
     * pre-computed digest, such as AWS KMS with `--message-type DIGEST`.
     */
    private val input: String = "payload"
) : ConfigSigner {

    override val type: String = "command"

    override val publicKeyBase64: String = SigningKeys.base64Of(publicKey)

    // Only the program name: arguments may carry key ids or tokens.
    override val description: String =
        "External command ${command.trim().substringBefore(' ').substringAfterLast('/')}"

    override fun sign(data: ByteArray): ByteArray {
        val builder = ProcessBuilder("/bin/sh", "-c", command)
        builder.environment().keys.removeIf { SECRET_ENV.matches(it) }
        val process = builder.start()
        val toSign = if (input == "digest") java.security.MessageDigest.getInstance("SHA-256").digest(data) else data

        // stdin, stdout and stderr each on their own thread: a signer that
        // ignores stdin, or writes more than a pipe buffer before exiting,
        // must not block us past the timeout.
        var stdout = ByteArray(0)
        var stderr = ByteArray(0)
        val writer = Thread {
            try { process.outputStream.use { it.write(toSign) } } catch (_: java.io.IOException) { /* signer closed stdin */ }
        }.apply { isDaemon = true; start() }
        val outReader = Thread { stdout = readBounded(process.inputStream) }.apply { isDaemon = true; start() }
        val errReader = Thread { stderr = readBounded(process.errorStream) }.apply { isDaemon = true; start() }

        if (!process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
            // Kill the children too: `sh -c` would otherwise leave them running
            // (and, in a container where the JVM is PID 1, unreaped).
            process.descendants().forEach { it.destroyForcibly() }
            process.destroyForcibly()
            error("Signer '$name' timed out after ${timeoutMs}ms")
        }
        writer.join(1_000)
        outReader.join(1_000)
        errReader.join(1_000)
        if (process.exitValue() != 0) {
            // Logged by the caller; never returned to HTTP clients.
            error("Signer '$name' exited with ${process.exitValue()}: ${String(stderr).trim().take(200)}")
        }
        val signature = try {
            SigningKeys.normalizeSignature(stdout)
        } catch (e: IllegalArgumentException) {
            error("Signer '$name' printed no usable signature: ${e.message}")
        }
        check(SigningKeys.verify(publicKey, data, signature)) {
            "Signer '$name' returned a signature that does not verify with its configured public key"
        }
        return signature
    }

    /** At most [MAX_OUTPUT] bytes; the rest is drained and dropped. */
    private fun readBounded(stream: InputStream): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (true) {
            val n = stream.read(buffer)
            if (n < 0) break
            if (out.size() < MAX_OUTPUT) out.write(buffer, 0, minOf(n, MAX_OUTPUT - out.size()))
        }
        return out.toByteArray()
    }

    companion object {
        private const val MAX_OUTPUT = 64 * 1024

        /** This server's secrets, never passed to an external signer. */
        private val SECRET_ENV = Regex(
            "^(API_KEY|ADMIN_KEYS.*|SIGNING_KEY_PASSWORD.*|PKCS11_PIN.*|NOTIFY_WEBHOOK_SECRET|" +
                "VAULT_AT_REST_PASSWORD|KEYSTORE_PASSWORD)$"
        )
    }
}
