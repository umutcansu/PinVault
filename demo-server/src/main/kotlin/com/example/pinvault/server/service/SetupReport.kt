package com.example.pinvault.server.service

/**
 * The production-readiness checklist the dashboard's setup wizard shows.
 *
 * Read-only by design: every item is an environment setting the server reads
 * once at start-up, so the wizard says what is set and which line to change
 * in `.env`; it never writes the environment, keys or secrets. (An admin page
 * that could rewrite the server's secrets would be the most valuable target on
 * the server.)
 *
 * Values are reported as words (`enforce`, `3 signers`, `set`), never as
 * the secret or key itself.
 */
object SetupReport {

    enum class Level { OK, WARN, FAIL }

    /**
     * One item. [id] names the text the dashboard shows (`setup_<id>_*`);
     * [current] is what the server runs with; [fix] the `.env` line(s) that
     * make it [Level.OK], or null when it already is.
     */
    data class Check(val id: String, val level: Level, val current: String, val fix: String?)

    fun checks(env: Map<String, String>): List<Check> {
        fun v(name: String) = env[name]?.trim().orEmpty()
        fun mode(name: String, default: String) = v(name).lowercase().ifEmpty { default }
        val out = mutableListOf<Check>()

        // ── Who can administer ───────────────────────────────────────────
        val anonymous = v("ALLOW_ANONYMOUS_ADMIN") == "true"
        val namedAdmins = v("ADMIN_KEYS").split(',').count { it.isNotBlank() }
        out += when {
            anonymous -> Check("admin_auth", Level.FAIL, "anonymous", "ALLOW_ANONYMOUS_ADMIN=\nADMIN_KEYS=<name>:<sha256>,…   # scripts/add-admin.sh")
            namedAdmins >= 2 -> Check("admin_auth", Level.OK, "$namedAdmins named admins", null)
            namedAdmins == 1 -> Check("admin_auth", Level.WARN, "1 named admin", "ADMIN_KEYS=<name>:<sha256>,<name2>:<sha256>   # a second admin for approvals")
            else -> Check("admin_auth", Level.WARN, "shared API_KEY", "ADMIN_KEYS=<name>:<sha256>,…   # scripts/add-admin.sh")
        }
        val approvals = v("PIN_CHANGE_APPROVALS").toIntOrNull() ?: 1
        out += if (approvals >= 2) Check("approvals", Level.OK, "$approvals admins", null)
            else Check("approvals", Level.WARN, "1 admin", "PIN_CHANGE_APPROVALS=2")
        out += if (v("NOTIFY_WEBHOOK_URL").isNotEmpty()) Check("webhook", Level.OK, "set", null)
            else Check("webhook", Level.WARN, "not set", "NOTIFY_WEBHOOK_URL=https://…\nNOTIFY_WEBHOOK_SECRET=<random>")
        out += if (v("MANAGEMENT_HTTPS_PORT").isNotEmpty()) Check("management_tls", Level.OK, "port ${v("MANAGEMENT_HTTPS_PORT")}", null)
            else Check("management_tls", Level.WARN, "plain HTTP only", "MANAGEMENT_HTTPS_PORT=6655")
        if (v("ALLOW_TEST_HOOKS") == "true") out += Check("test_hooks", Level.FAIL, "on", "ALLOW_TEST_HOOKS=")
        val missingSecrets = StartupSecrets.missing(env)
        if (missingSecrets.isNotEmpty()) {
            out += Check("demo_secrets", Level.FAIL, "${missingSecrets.size} demo value(s)",
                missingSecrets.joinToString("\n") { "$it=<random>" } + "   # scripts/setup.sh fills these")
        }

        // ── Who decides the pins ─────────────────────────────────────────
        // `type` or `type:name` (CONFIG_SIGNERS=local,command:kms).
        val signers = v("CONFIG_SIGNERS").ifEmpty { "local" }.split(',').map { it.trim().lowercase() }.filter { it.isNotEmpty() }
        val offDisk = signers.count { it.substringBefore(':') in setOf("pkcs11", "command") }
        out += when {
            signers.size >= 2 && offDisk >= 1 -> Check("signers", Level.OK, "${signers.size} signers (${signers.joinToString()})", null)
            else -> Check("signers", Level.WARN, "${signers.size} signer (${signers.joinToString()})",
                "CONFIG_SIGNERS=pkcs11,command   # at least two, one not on this disk; SECURE_OPERATIONS.md")
        }
        out += if (v("RECOVERY_PUBLIC_KEYS").isNotEmpty()) Check("recovery_keys", Level.OK, "set", null)
            else Check("recovery_keys", Level.WARN, "not set", "RECOVERY_PUBLIC_KEYS=<Base64>   # scripts/offline-keygen.sh, on another machine")
        val ttl = v("CONFIG_TTL_SECONDS").toLongOrNull() ?: 86_400
        out += if (ttl <= 86_400) Check("config_ttl", Level.OK, "${ttl}s", null)
            else Check("config_ttl", Level.WARN, "${ttl}s", "CONFIG_TTL_SECONDS=86400")
        out += when (mode("PIN_LIVE_CHECK", "off")) {
            "enforce" -> Check("live_check", Level.OK, "enforce", null)
            "warn" -> Check("live_check", Level.WARN, "warn", "PIN_LIVE_CHECK=enforce")
            else -> Check("live_check", Level.WARN, "off", "PIN_LIVE_CHECK=enforce")
        }

        // ── Who may enroll ───────────────────────────────────────────────
        out += when (mode("ENROLLMENT_MODE", "token")) {
            "open" -> Check("enrollment_mode", Level.FAIL, "open", "ENROLLMENT_MODE=token")
            else -> Check("enrollment_mode", Level.OK, "token", null)
        }
        val appBound = v("ATTESTATION_PACKAGE_NAMES").isNotEmpty() && v("ATTESTATION_SIGNER_SHA256").isNotEmpty()
        val attestation = mode("ENROLLMENT_ATTESTATION", "warn")
        out += when {
            attestation == "enforce" && appBound -> Check("attestation", Level.OK, "enforce", null)
            attestation == "off" -> Check("attestation", Level.FAIL, "off",
                "ENROLLMENT_ATTESTATION=enforce\nATTESTATION_PACKAGE_NAMES=<package>\nATTESTATION_SIGNER_SHA256=<release signing cert SHA-256>")
            else -> Check("attestation", Level.WARN, if (appBound) attestation else "$attestation, app not bound",
                "ENROLLMENT_ATTESTATION=enforce" +
                    (if (appBound) "" else "\nATTESTATION_PACKAGE_NAMES=<package>\nATTESTATION_SIGNER_SHA256=<release signing cert SHA-256>"))
        }
        if (attestation != "off") {
            out += if (v("ATTESTATION_REVOKED_SERIALS_FILE").isNotEmpty() && v("ATTESTATION_STATUS_MAX_AGE_HOURS").isNotEmpty()) {
                Check("attestation_revocation", Level.OK, "set", null)
            } else {
                Check("attestation_revocation", Level.WARN, "not set",
                    "ATTESTATION_REVOKED_SERIALS_FILE=/data/attestation-status.json\nATTESTATION_STATUS_MAX_AGE_HOURS=24   # cron: scripts/fetch-attestation-status.sh")
            }
        }
        out += when (mode("ENROLLMENT_P12", "on")) {
            "off", "false" -> Check("p12", Level.OK, "off", null)
            else -> Check("p12", Level.WARN, "on", "ENROLLMENT_P12=off")
        }
        val integrity = mode("INTEGRITY_VERIFICATION", "off")
        val verifier = v("INTEGRITY_VERIFIER_COMMAND").isNotEmpty()
        out += when {
            integrity == "enforce" && verifier -> Check("integrity", Level.OK, "enforce", null)
            integrity == "warn" -> Check("integrity", Level.WARN, if (verifier) "warn" else "warn, no verifier",
                "INTEGRITY_VERIFICATION=enforce" + (if (verifier) "" else "\nINTEGRITY_VERIFIER_COMMAND=/opt/pinvault/scripts/play-integrity-verify.sh"))
            else -> Check("integrity", Level.WARN, "off",
                "INTEGRITY_VERIFICATION=warn   # then enforce, after a real phone passes\n" +
                    "INTEGRITY_VERIFIER_COMMAND=/opt/pinvault/scripts/play-integrity-verify.sh\n" +
                    "INTEGRITY_PLAY_PACKAGE=<package>\nINTEGRITY_PLAY_SERVICE_ACCOUNT_FILE=/data/play-integrity-sa.json")
        }
        return out
    }
}
