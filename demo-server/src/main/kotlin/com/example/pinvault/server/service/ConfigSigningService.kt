package com.example.pinvault.server.service

import com.example.pinvault.server.model.SignatureEntry
import com.example.pinvault.server.service.signing.CommandSigner
import com.example.pinvault.server.service.signing.ConfigSigner
import com.example.pinvault.server.service.signing.LocalFileSigner
import com.example.pinvault.server.service.signing.Pkcs11Signer
import com.example.pinvault.server.service.signing.SigningKeys
import java.io.File
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

/**
 * Signs everything a device verifies — config payloads and vault files —
 * with one or more [ConfigSigner]s.
 *
 * One signer (the default: a local key file) behaves exactly as this service
 * always has. Several signers produce one signature each; devices that set
 * `requiredSignatures(n)` accept a document only with n of them. The FIRST
 * signer is the primary: its signature goes into the legacy single-signature
 * fields, so older clients keep working.
 *
 * Signers are chosen with `CONFIG_SIGNERS` (see [fromEnv]).
 */
class ConfigSigningService(signers: List<ConfigSigner>) {

    /** Single local key file — the historical constructor. */
    constructor(keyFile: File) : this(listOf(LocalFileSigner(keyFile)))

    val signers: List<ConfigSigner> = signers.also { require(it.isNotEmpty()) { "at least one signer is required" } }

    val primary: ConfigSigner get() = signers.first()

    /** Public key of the primary signer (Base64, X.509) — what the app embeds. */
    val publicKeyBase64: String get() = primary.publicKeyBase64

    /** How many signatures this process has produced, across all signers. */
    val signaturesProduced = AtomicLong()

    /** True when the primary key can be replaced from the dashboard (local key file only). */
    val canRegenerate: Boolean get() = primary is LocalFileSigner

    /**
     * Replaces the primary key file with a fresh key, effective immediately.
     * Only for the local signer: an HSM or KMS key is rotated where it lives.
     */
    fun regenerate(): String {
        val local = primary as? LocalFileSigner
            ?: throw UnsupportedOperationException(
                "The primary signer (${primary.type}) is not a key file — rotate the key in the HSM/KMS " +
                    "and restart with the new key configured."
            )
        return local.regenerate()
    }

    /** Payload string'ini primary imzalayıcıyla ECDSA-SHA256 ile imzalar, Base64 döner. */
    fun sign(payload: String): String = signAll(payload, onlyPrimary = true).first().signature

    /** One signature per signer, primary first. */
    fun signAll(payload: String): List<SignatureEntry> = signAll(payload, onlyPrimary = false)

    private fun signAll(payload: String, onlyPrimary: Boolean): List<SignatureEntry> {
        val bytes = payload.toByteArray(Charsets.UTF_8)
        val chosen = if (onlyPrimary) listOf(primary) else signers
        return chosen.map { signer ->
            val signature = Base64.getEncoder().encodeToString(signer.sign(bytes))
            signaturesProduced.incrementAndGet()
            SignatureEntry(keyId = signer.keyId, signature = signature)
        }
    }

    /** True when [signature] verifies with ANY configured signer's key (test/debug). */
    fun verify(payload: String, signature: String): Boolean {
        val der = try { Base64.getDecoder().decode(signature) } catch (_: IllegalArgumentException) { return false }
        val bytes = payload.toByteArray(Charsets.UTF_8)
        return signers.any { SigningKeys.verify(SigningKeys.decodePublicKey(it.publicKeyBase64), bytes, der) }
    }

    /**
     * Signs vault file CONTENT so a device can verify integrity before trusting
     * it. The signature is over a canonical string binding key + version +
     * SHA-256(plaintext), NOT the wire bytes — so one signature works for
     * plain / at_rest / end_to_end (the device verifies the PLAINTEXT it ends up
     * with, after any per-device E2E decrypt) and is stable per version. Reuses
     * the same signing keys the client already trusts for config signing, so
     * no new key needs to be distributed.
     *
     * Canonical: `pinvault-vault-file:v1:<key>:<version>:<sha256HexLower(plaintext)>`
     * (must match ConfigSignatureVerifier.vaultCanonical on the client).
     */
    fun signVaultFile(key: String, version: Int, plaintext: ByteArray): String =
        sign(vaultCanonical(key, version, plaintext))

    /** [signVaultFile] with every signer, primary first. */
    fun signVaultFileAll(key: String, version: Int, plaintext: ByteArray): List<SignatureEntry> =
        signAll(vaultCanonical(key, version, plaintext))

    private fun vaultCanonical(key: String, version: Int, plaintext: ByteArray): String =
        "pinvault-vault-file:v1:$key:$version:${sha256HexLower(plaintext)}"

    private fun sha256HexLower(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    companion object {

        /**
         * Builds the signers named in `CONFIG_SIGNERS` (comma-separated,
         * default `local`). Each entry is `type` or `type:name`; a name gives
         * that signer its own env vars with the suffix `_<NAME>`:
         *
         *  - `local` — `SIGNING_KEY_PATH[_NAME]` (default [defaultKeyFile], or
         *    `signing-key-<name>.pem` next to it), `SIGNING_KEY_PASSWORD[_NAME]`.
         *  - `pkcs11` — `PKCS11_LIBRARY`, `PKCS11_PIN`, `PKCS11_SLOT_INDEX` (0),
         *    `PKCS11_KEY_LABEL` (pinvault-config-signing), `PKCS11_GENERATE_KEY` (false).
         *  - `command` — `SIGNER_COMMAND`, `SIGNER_PUBLIC_KEY` or
         *    `SIGNER_PUBLIC_KEY_FILE`, `SIGNER_TIMEOUT_MS` (10000),
         *    `SIGNER_INPUT` (`payload` or `digest`).
         *
         * Example, 2-of-2 with one key on this server and one in a KMS:
         * `CONFIG_SIGNERS=local,command:kms` + `SIGNER_COMMAND_KMS=…` +
         * `SIGNER_PUBLIC_KEY_KMS=…`.
         */
        fun fromEnv(defaultKeyFile: File, env: Map<String, String> = System.getenv()): ConfigSigningService {
            val specs = (env["CONFIG_SIGNERS"]?.takeIf { it.isNotBlank() } ?: "local")
                .split(',').map { it.trim() }.filter { it.isNotEmpty() }
            val signers = specs.map { spec -> buildSigner(spec, defaultKeyFile, env) }
            require(signers.map { it.keyId }.distinct().size == signers.size) {
                "CONFIG_SIGNERS lists the same key twice — every signer must hold a different key"
            }
            return ConfigSigningService(signers)
        }

        private fun buildSigner(spec: String, defaultKeyFile: File, env: Map<String, String>): ConfigSigner {
            val type = spec.substringBefore(':').lowercase()
            val name = spec.substringAfter(':', "").takeIf { it.isNotBlank() }
            val suffix = name?.let { "_" + it.uppercase().replace(Regex("[^A-Z0-9]"), "_") } ?: ""
            fun value(key: String): String? = env["$key$suffix"]?.takeIf { it.isNotBlank() }
            fun required(key: String): String = value(key)
                ?: error("CONFIG_SIGNERS entry '$spec' needs $key$suffix")

            return when (type) {
                "local" -> LocalFileSigner(
                    keyFile = value("SIGNING_KEY_PATH")?.let(::File)
                        ?: if (name == null) defaultKeyFile
                        else File(defaultKeyFile.absoluteFile.parentFile, "signing-key-$name.pem"),
                    password = value("SIGNING_KEY_PASSWORD") ?: env["SIGNING_KEY_PASSWORD"]?.takeIf { it.isNotBlank() },
                    name = spec
                )
                "pkcs11" -> Pkcs11Signer(
                    name = spec,
                    library = required("PKCS11_LIBRARY"),
                    slotListIndex = value("PKCS11_SLOT_INDEX")?.toIntOrNull() ?: 0,
                    pin = required("PKCS11_PIN"),
                    keyLabel = value("PKCS11_KEY_LABEL") ?: "pinvault-config-signing",
                    generateIfMissing = value("PKCS11_GENERATE_KEY") == "true"
                )
                "command" -> CommandSigner(
                    name = spec,
                    command = required("SIGNER_COMMAND"),
                    publicKey = SigningKeys.decodePublicKey(
                        value("SIGNER_PUBLIC_KEY")
                            ?: value("SIGNER_PUBLIC_KEY_FILE")?.let { File(it).readText() }
                            ?: error("CONFIG_SIGNERS entry '$spec' needs SIGNER_PUBLIC_KEY$suffix or SIGNER_PUBLIC_KEY_FILE$suffix")
                    ),
                    timeoutMs = value("SIGNER_TIMEOUT_MS")?.toLongOrNull() ?: 10_000,
                    input = (value("SIGNER_INPUT") ?: "payload").lowercase().also {
                        require(it == "payload" || it == "digest") { "SIGNER_INPUT$suffix must be payload or digest" }
                    }
                )
                else -> error("Unknown signer type '$type' in CONFIG_SIGNERS (use local, pkcs11 or command)")
            }
        }
    }
}
