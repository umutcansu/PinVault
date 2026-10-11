package com.example.pinvault.server.store

import com.example.pinvault.server.service.VaultAtRestCipher
import com.example.pinvault.server.service.VaultKeyMismatchException
import com.example.pinvault.server.service.attestation.PinVaultToken
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset

/** One signing key of PinVault-Token (V21 `attestation_token_secrets`, V29 `alg` / `public_key`). */
class TokenSecret(
    /** Names the key in the token header; `YYYY-MM-DD-NN`. */
    val kid: String,
    /** HS256: the 32 secret bytes; ES256: the PKCS#8 private key. In the clear here, sealed at rest. */
    val secret: ByteArray,
    val active: Boolean,
    val createdAt: String,
    val createdBy: String,
    /** [PinVaultToken.ALG_ES256] or [PinVaultToken.ALG_HS256]. */
    val alg: String = PinVaultToken.ALG_HS256,
    /** ES256: the X.509 SubjectPublicKeyInfo; null for HS256. */
    val publicKey: ByteArray? = null
) {
    /** What signs with this key. */
    fun signingKey(): PinVaultToken.SigningKey =
        if (alg == PinVaultToken.ALG_ES256) PinVaultToken.SigningKey.Es256(kid, KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(secret)) as ECPrivateKey)
        else PinVaultToken.SigningKey.Hs256(kid, secret)

    /** What verifies tokens of this key. */
    fun verificationKey(): PinVaultToken.VerificationKey =
        if (alg == PinVaultToken.ALG_ES256) PinVaultToken.VerificationKey.Es256(ecPublicKey()!!)
        else PinVaultToken.VerificationKey.Hs256(secret)

    /** The ES256 public key; null for HS256. */
    fun ecPublicKey(): ECPublicKey? =
        publicKey?.let { KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(it)) as ECPublicKey }
}

/**
 * The keys that sign and verify `PinVault-Token`: one active at a time, the
 * previous ones kept for verification until an operator deletes them. New
 * keys are made with [alg] (`PINVAULT_TOKEN_ALG`; ES256 unless HS256 is
 * asked for); when the active key has another algorithm, the next [active]
 * call rotates to one of [alg] and keeps the old one for verification.
 * Secrets and private keys are stored encrypted under
 * `VAULT_AT_REST_PASSWORD` ([cipher]; null = in the clear, tests only). The
 * first key is made on first use.
 */
class AttestationTokenSecretStore(
    private val db: DatabaseManager,
    private val cipher: VaultAtRestCipher? = null,
    private val clock: () -> Instant = Instant::now,
    val alg: String = PinVaultToken.ALG_ES256
) {
    init {
        require(alg == PinVaultToken.ALG_ES256 || alg == PinVaultToken.ALG_HS256) { "PINVAULT_TOKEN_ALG must be ES256 or HS256 (got '$alg')" }
    }

    private val random = SecureRandom()

    /** Verification keys by kid, refreshed every few seconds: the mock hosts verify a token per request. */
    @Volatile private var cached: Pair<Long, Map<String, PinVaultToken.VerificationKey>>? = null

    sealed interface Deletion {
        data object Deleted : Deletion
        data object NotFound : Deletion
        data object Active : Deletion
    }

    /** Every secret, newest first. */
    fun all(): List<TokenSecret> = db.connection().use { conn ->
        conn.prepareStatement("SELECT kid, secret, active, created_at, created_by, alg, public_key FROM attestation_token_secrets ORDER BY created_at DESC, kid DESC").use { stmt ->
            val rs = stmt.executeQuery()
            buildList {
                while (rs.next()) add(TokenSecret(
                    kid = rs.getString("kid"), secret = open(rs.getBytes("secret")), active = rs.getInt("active") == 1,
                    createdAt = rs.getString("created_at"), createdBy = rs.getString("created_by"),
                    alg = rs.getString("alg"), publicKey = rs.getBytes("public_key")
                ))
            }
        }
    }

    /**
     * The active key, made now when there is none yet — or when the active
     * one has another algorithm than [alg] (a server moved to ES256): the old
     * key stays for verification until it is deleted.
     */
    @Synchronized
    fun active(): TokenSecret = all().firstOrNull { it.active }?.takeIf { it.alg == alg }
        ?: rotate(if (all().any { it.active }) "system (PINVAULT_TOKEN_ALG=$alg)" else "system")

    /** Every key by kid, for verification (a few seconds stale at most). */
    fun verificationKeys(): Map<String, PinVaultToken.VerificationKey> {
        val now = System.currentTimeMillis()
        cached?.let { (at, map) -> if (now - at < CACHE_MS) return map }
        val fresh = all().associate { it.kid to it.verificationKey() }
        cached = now to fresh
        return fresh
    }

    /** The HS256 secrets by kid (what `GET /api/v1/attestation/token-secrets` hands to HS256 backends). */
    fun secretsByKid(): Map<String, ByteArray> = all().filter { it.alg == PinVaultToken.ALG_HS256 }.associate { it.kid to it.secret }

    /** A new active key of [alg]; the previous active one stays for verification. */
    @Synchronized
    fun rotate(createdBy: String): TokenSecret = db.connection().use { conn ->
        conn.autoCommit = false
        try {
            val now = clock()
            val day = LocalDate.ofInstant(now, ZoneOffset.UTC).toString()
            val taken = conn.prepareStatement("SELECT kid FROM attestation_token_secrets WHERE kid LIKE ?").use { stmt ->
                stmt.setString(1, "$day-%")
                val rs = stmt.executeQuery()
                buildSet { while (rs.next()) add(rs.getString(1)) }
            }
            var n = 1
            while ("$day-${"%02d".format(n)}" in taken) n++
            val kid = "$day-${"%02d".format(n)}"
            val (secret, publicKey) = if (alg == PinVaultToken.ALG_ES256) {
                val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1"), random) }.generateKeyPair()
                pair.private.encoded to pair.public.encoded
            } else {
                ByteArray(32).also(random::nextBytes) to null
            }
            conn.prepareStatement("UPDATE attestation_token_secrets SET active = 0 WHERE active = 1").use { it.executeUpdate() }
            conn.prepareStatement("INSERT INTO attestation_token_secrets (kid, secret, active, created_at, created_by, alg, public_key) VALUES (?, ?, 1, ?, ?, ?, ?)").use { stmt ->
                stmt.setString(1, kid)
                stmt.setBytes(2, seal(secret))
                stmt.setString(3, now.toString())
                stmt.setString(4, createdBy)
                stmt.setString(5, alg)
                stmt.setBytes(6, publicKey)
                stmt.executeUpdate()
            }
            conn.commit()
            cached = null
            TokenSecret(kid, secret, true, now.toString(), createdBy, alg, publicKey)
        } catch (e: Exception) {
            runCatching { conn.rollback() }
            throw e
        } finally {
            runCatching { conn.autoCommit = true }
        }
    }

    /** Drops a PREVIOUS secret; the active one cannot be deleted (rotate first). */
    @Synchronized
    fun delete(kid: String): Deletion = db.connection().use { conn ->
        // null = no such secret.
        val active: Boolean? = conn.prepareStatement("SELECT active FROM attestation_token_secrets WHERE kid = ?").use { stmt ->
            stmt.setString(1, kid)
            val rs = stmt.executeQuery()
            if (rs.next()) rs.getInt(1) == 1 else null
        }
        when (active) {
            null -> Deletion.NotFound
            true -> Deletion.Active
            false -> conn.prepareStatement("DELETE FROM attestation_token_secrets WHERE kid = ? AND active = 0").use { stmt ->
                stmt.setString(1, kid)
                if (stmt.executeUpdate() > 0) { cached = null; Deletion.Deleted } else Deletion.NotFound
            }
        }
    }

    /**
     * The start-up pass (Main), as VaultFileStore makes for vault files: every
     * secret must open with `VAULT_AT_REST_PASSWORD`. One that opens only with
     * a previous password (`VAULT_AT_REST_PASSWORD_PREVIOUS`, the demo
     * password) or sits in the clear is re-sealed under the current one; one
     * that nothing opens, or any sealed one when there is no cipher, stops
     * the start with an [IllegalStateException] naming
     * `VAULT_AT_REST_PASSWORD` — not a server that signs and verifies tokens
     * with bytes that are not the secret.
     */
    @Synchronized
    fun checkReadable() {
        if (cipher == null) { all(); return }
        db.connection().use { conn ->
            val rows = conn.prepareStatement("SELECT kid, secret FROM attestation_token_secrets").use { stmt ->
                val rs = stmt.executeQuery()
                buildList { while (rs.next()) add(rs.getString(1) to rs.getBytes(2)) }
            }
            for ((kid, stored) in rows) {
                val plaintext: ByteArray = if (!VaultAtRestCipher.isEncrypted(stored)) stored else when (val opened = cipher.open(stored)) {
                    VaultAtRestCipher.Opened.Current -> continue
                    is VaultAtRestCipher.Opened.Previous -> opened.plaintext
                    VaultAtRestCipher.Opened.Unreadable -> throw IllegalStateException(
                        "PinVault-Token secret $kid does not open with VAULT_AT_REST_PASSWORD or VAULT_AT_REST_PASSWORD_PREVIOUS: " +
                            "it was sealed under another password. Set the password it was sealed with, or delete the secret " +
                            "(every token signed with it is then refused)."
                    )
                }
                conn.prepareStatement("UPDATE attestation_token_secrets SET secret = ? WHERE kid = ?").use { stmt ->
                    stmt.setBytes(1, cipher.encrypt(plaintext))
                    stmt.setString(2, kid)
                    stmt.executeUpdate()
                }
                println("AttestationTokenSecretStore: secret $kid re-sealed under VAULT_AT_REST_PASSWORD")
            }
            cached = null
        }
    }

    private fun seal(secret: ByteArray): ByteArray = cipher?.encrypt(secret) ?: secret

    /**
     * A sealed value needs the cipher: without one the ciphertext used to be
     * handed back as if it were the secret, and tokens were silently signed
     * and verified with it. A value in the clear (written before the secrets
     * were sealed, or by a store without a cipher) is read as it is.
     */
    private fun open(stored: ByteArray): ByteArray = when {
        !VaultAtRestCipher.isEncrypted(stored) -> stored
        cipher == null -> throw IllegalStateException(
            "A PinVault-Token secret is sealed under VAULT_AT_REST_PASSWORD, but no password is configured to open it. " +
                "Set VAULT_AT_REST_PASSWORD to the one the secrets were sealed with."
        )
        else -> try {
            cipher.decrypt(stored)
        } catch (e: VaultKeyMismatchException) {
            throw IllegalStateException(
                "A PinVault-Token secret does not open with VAULT_AT_REST_PASSWORD: it was sealed under another password " +
                    "(a restart with the old one in VAULT_AT_REST_PASSWORD_PREVIOUS re-seals it).", e
            )
        }
    }

    companion object {
        private const val CACHE_MS = 5_000L
    }
}
