package com.example.pinvault.server.service

/**
 * Refuses to start with the secrets that are printed in the source code.
 *
 * Three passwords protect what the server keeps on disk, and each used to
 * fall back to a public default when unset: `KEYSTORE_PASSWORD` to
 * `changeit`, `VAULT_AT_REST_PASSWORD` to a demo key in the source, and
 * `SIGNING_KEY_PASSWORD` to "no encryption at all" for the key that signs
 * every config. A deployment copied from the compose file came up that way
 * and nothing said so but a line in the log.
 *
 * Now each of them must be set, or the operator must say that the demo
 * values are what they want: `ALLOW_DEMO_SECRETS=true` (local development,
 * the test hosts). `SIGNING_KEY_PASSWORD` is asked for only when a `local`
 * signer is configured — an HSM or KMS key has no key file to encrypt.
 */
object StartupSecrets {
    const val ALLOW = "ALLOW_DEMO_SECRETS"

    /** The required secrets [env] does not set. */
    fun missing(env: Map<String, String> = com.example.pinvault.server.service.ServerEnv.all()): List<String> = buildList {
        fun unset(name: String) = env[name].isNullOrBlank()
        if (unset("KEYSTORE_PASSWORD")) add("KEYSTORE_PASSWORD")
        if (unset("VAULT_AT_REST_PASSWORD")) add("VAULT_AT_REST_PASSWORD")
        // One per local signer: SIGNING_KEY_PASSWORD_<NAME>, or the shared SIGNING_KEY_PASSWORD.
        val signers = (env["CONFIG_SIGNERS"]?.takeIf { it.isNotBlank() } ?: "local").split(',').map { it.trim() }.filter { it.isNotEmpty() }
        for (spec in signers.filter { it.substringBefore(':').equals("local", ignoreCase = true) }) {
            val name = spec.substringAfter(':', "").takeIf { it.isNotBlank() }
            val own = name?.let { "SIGNING_KEY_PASSWORD_" + it.uppercase().replace(Regex("[^A-Z0-9]"), "_") }
            if (unset("SIGNING_KEY_PASSWORD") && (own == null || unset(own))) add(own ?: "SIGNING_KEY_PASSWORD")
        }
    }.distinct()

    /**
     * Throws when a required secret is unset and the demo values were not
     * asked for. Returns the warning to print when they were, or null when
     * every secret is set.
     */
    fun check(env: Map<String, String> = com.example.pinvault.server.service.ServerEnv.all()): String? {
        val missing = missing(env)
        if (missing.isEmpty()) return null
        check(env[ALLOW] == "true") {
            "${missing.joinToString()} ${if (missing.size == 1) "is" else "are"} not set. Refusing to start with the demo values " +
                "from the source code (keystores under \"changeit\", vault files under a public key, the signing key unencrypted). " +
                "Set ${if (missing.size == 1) "it" else "them"}, or — for local development only — set $ALLOW=true."
        }
        return "WARNING: $ALLOW=true — ${missing.joinToString()} not set; the demo values from the source code are in use. " +
            "Do not run this configuration with real devices."
    }
}

/**
 * The shared admin key must not be guessable: `API_KEY` shorter than
 * [MIN_API_KEY_LENGTH] characters is refused at start-up unless
 * `ALLOW_DEMO_SECRETS=true` (the Espresso server runs with `admin-key-123`).
 * Named admins (`ADMIN_KEYS`) are configured by their SHA-256, so their keys
 * are generated (`scripts/add-admin.sh`), not typed.
 */
object AdminKeyStrength {
    const val MIN_API_KEY_LENGTH = 16

    /** Throws when `API_KEY` is set but short and demo secrets were not asked for; the warning to print otherwise, or null. */
    fun check(env: Map<String, String> = com.example.pinvault.server.service.ServerEnv.all()): String? {
        val key = env["API_KEY"]?.takeIf { it.isNotBlank() } ?: return null
        if (key.length >= MIN_API_KEY_LENGTH) return null
        check(env[StartupSecrets.ALLOW] == "true") {
            "API_KEY has ${key.length} characters; at least $MIN_API_KEY_LENGTH are required (e.g. openssl rand -hex 24). " +
                "For local development only, ${StartupSecrets.ALLOW}=true accepts a short one."
        }
        return "WARNING: API_KEY has only ${key.length} characters (${StartupSecrets.ALLOW}=true). Do not run this configuration with real devices."
    }
}
