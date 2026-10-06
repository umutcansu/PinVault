package com.example.pinvault.server.service

import com.example.pinvault.server.service.signing.CommandSigner
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import java.io.InputStream
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.TimeUnit

/**
 * What `INTEGRITY_VERIFICATION` asks of the integrity token an enrollment
 * carries (`integrityToken`, sent by an app that set `integrityTokenProvider`):
 *
 *  - [OFF] (default): the token is not looked at.
 *  - [WARN]: the token is verified when there is one and the verdict goes to
 *    the audit log, but the enrollment goes ahead either way.
 *  - [ENFORCE]: no certificate without a passing verdict — 403
 *    `integrity_required` without a token, `integrity_invalid` with a
 *    `reason` for one that fails. The server does not start without
 *    `INTEGRITY_VERIFIER_COMMAND`.
 *
 * An Android key attestation (`ENROLLMENT_ATTESTATION`) proves where the key
 * was made. An integrity verdict (Google Play Integrity, or a RASP product's
 * attestation) says whether the device and the app can be trusted now: not
 * rooted, not hooked, installed from Play. The two answer different
 * questions; a production server runs both.
 */
enum class IntegrityVerificationMode {
    OFF, WARN, ENFORCE;

    companion object {
        /** `INTEGRITY_VERIFICATION`; empty = [OFF]. An unknown value is a start-up error. */
        fun parse(value: String?): IntegrityVerificationMode = when (value?.trim()?.lowercase()) {
            null, "", "off" -> OFF
            "warn" -> WARN
            "enforce" -> ENFORCE
            else -> throw IllegalArgumentException("INTEGRITY_VERIFICATION must be off, warn or enforce (got '$value')")
        }

        /**
         * [ENFORCE] without a verifier refuses to start; [WARN] without one
         * returns the warning to print (tokens arrive but nothing reads them).
         */
        fun startupCheck(mode: IntegrityVerificationMode, verifier: IntegrityVerifier?): String? {
            if (mode == OFF || verifier != null) return null
            check(mode != ENFORCE) {
                "INTEGRITY_VERIFICATION=enforce needs INTEGRITY_VERIFIER_COMMAND: a command that decodes the token " +
                    "(Play Integrity: scripts/play-integrity-verify.sh). Set it, or run INTEGRITY_VERIFICATION=warn."
            }
            return "WARNING: INTEGRITY_VERIFICATION=warn without INTEGRITY_VERIFIER_COMMAND — integrity tokens are " +
                "recorded as not verified."
        }
    }
}

/** Decodes an integrity token and judges its verdict. */
fun interface IntegrityVerifier {
    /**
     * The verdict for [token], which the device bound to [requestHash].
     * [deviceId] is the id the hash was made with (for the verifier's logs).
     */
    fun verify(token: String, requestHash: String, deviceId: String?): IntegrityVerdict
}

/**
 * A verifier's answer. [reason] is a short machine word when it failed
 * (`request_hash_mismatch`, `device_integrity`, `app_not_recognized`, …);
 * [summary] a short text for the audit log (no token content).
 */
data class IntegrityVerdict(val passed: Boolean, val reason: String? = null, val summary: String? = null) {
    companion object {
        val MISSING = IntegrityVerdict(false, "token_missing")
        val NOT_CONFIGURED = IntegrityVerdict(false, "verifier_not_configured")
    }
}

/**
 * The request hash the library binds a token to:
 *
 * ```
 * base64url(SHA-256("pinvault-integrity:v1:" + deviceId + ":" + base64url(SHA-256(csrDer))))
 * ```
 *
 * unpadded, where `deviceId` is the request's `deviceUid`, else its
 * `deviceId`, else empty — the request's own fields, as the library sent
 * them.
 */
object IntegrityRequestHash {
    private const val PREFIX = "pinvault-integrity:v1:"
    private val encoder = Base64.getUrlEncoder().withoutPadding()

    fun of(deviceId: String?, csrDer: ByteArray): String {
        val csrHash = encoder.encodeToString(sha256(csrDer))
        return encoder.encodeToString(sha256("$PREFIX${deviceId.orEmpty()}:$csrHash".toByteArray(Charsets.UTF_8)))
    }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
}

/**
 * Checks the `integrityToken` of a CSR enrollment ([IntegrityVerificationMode]).
 *
 * Callers run it after the CSR was parsed (and after the key attestation)
 * and BEFORE a token, a policy slot or anything else is spent: a refusal
 * costs the device nothing it would need again.
 */
class EnrollmentIntegrity(
    /** Read on every check (tests switch it; Main passes a fixed mode). */
    private val modeOf: () -> IntegrityVerificationMode,
    private val verifier: IntegrityVerifier?
) {
    constructor(mode: IntegrityVerificationMode, verifier: IntegrityVerifier?) : this({ mode }, verifier)

    val mode: IntegrityVerificationMode get() = modeOf()

    /** Under [IntegrityVerificationMode.ENFORCE] a server-made key (no CSR to bind a token to) is refused. */
    val refusesServerMadeKeys: Boolean get() = mode == IntegrityVerificationMode.ENFORCE

    /** What [check] decided. */
    sealed class Outcome {
        /** Go on; [verdict] is what was found (null = not checked: mode off). */
        data class Proceed(val verdict: IntegrityVerdict?) : Outcome() {
            /** For the audit log. */
            val note: String get() = when {
                verdict == null -> "integrity not checked"
                verdict.passed -> "integrity passed" + (verdict.summary?.let { " ($it)" } ?: "")
                else -> "integrity not verified: ${verdict.reason}"
            }
        }

        /** 403 with [error] (`integrity_required` / `integrity_invalid`) and, for the latter, [reason]. */
        data class Refuse(val error: String, val reason: String?, val message: String) : Outcome() {
            fun body(): String = buildJsonObject {
                put("error", error)
                reason?.let { put("reason", it) }
                put("message", message)
            }.toString()
        }
    }

    /**
     * The verdict for an enrollment body [json]. The request hash is
     * recomputed from the body's own `csr` and `deviceUid` / `deviceId`, so
     * a token made for another request does not pass. Off: [Outcome.Proceed]
     * with no verdict; the token is not read.
     */
    fun check(json: JsonObject?): Outcome {
        val mode = this.mode
        if (mode == IntegrityVerificationMode.OFF) return Outcome.Proceed(null)
        val verdict = verdictFor(json)
        if (verdict.passed) return Outcome.Proceed(verdict)
        if (mode == IntegrityVerificationMode.ENFORCE) {
            return if (verdict.reason == IntegrityVerdict.MISSING.reason) {
                Outcome.Refuse("integrity_required", null,
                    "This server enrolls only devices that send an integrity token (integrityToken), " +
                        "bound to the request's CSR and device id.")
            } else {
                Outcome.Refuse("integrity_invalid", verdict.reason,
                    "The device's integrity verdict did not pass: ${verdict.reason}.")
            }
        }
        return Outcome.Proceed(verdict)
    }

    private fun verdictFor(json: JsonObject?): IntegrityVerdict {
        val token = json.string("integrityToken")?.takeIf { it.isNotBlank() } ?: return IntegrityVerdict.MISSING
        if (token.length > MAX_TOKEN_CHARS) return IntegrityVerdict(false, "token_malformed")
        val csrDer = json.string("csr")?.let { runCatching { Base64.getDecoder().decode(it) }.getOrNull() }
            ?: return IntegrityVerdict(false, "csr_missing")
        val deviceId = json.string("deviceUid") ?: json.string("deviceId")
        val verifier = verifier ?: return IntegrityVerdict.NOT_CONFIGURED
        return try {
            verifier.verify(token, IntegrityRequestHash.of(deviceId, csrDer), deviceId)
        } catch (e: Exception) {
            // Never the token or the verifier's output in the answer: only the log.
            System.err.println("Integrity verifier failed: ${e.message}")
            IntegrityVerdict(false, "verifier_error")
        }
    }

    private fun JsonObject?.string(name: String): String? =
        (this?.get(name) as? JsonPrimitive)?.takeIf { it !is JsonNull && it.isString }?.content

    companion object {
        /** Play Integrity tokens are a few kilobytes; anything far larger is not one. */
        const val MAX_TOKEN_CHARS = 16 * 1024
    }
}

/**
 * Verifies by running an external command (`INTEGRITY_VERIFIER_COMMAND`):
 * the hook for Google Play Integrity (`scripts/play-integrity-verify.sh`) or
 * a RASP vendor's verification API.
 *
 * Contract: [command] runs through `/bin/sh -c`. Its stdin is one JSON
 * object `{"token": "...", "requestHash": "...", "deviceId": "..."}`; it
 * exits 0 and prints one JSON object
 * `{"passed": true|false, "reason": "...", "summary": "..."}`. The command
 * itself compares the decoded token's request hash (or nonce) with
 * `requestHash` and judges the verdict. Anything else (a non-zero exit,
 * output that is not such an object, a timeout) is a failed verdict,
 * `verifier_error`.
 *
 * Like [CommandSigner], the command gets an allowlisted environment: `PATH`,
 * `HOME`, `LANG`, `TZ`, every `INTEGRITY_*` variable, and what
 * `INTEGRITY_PASS_ENV` names (never one of the server's own secrets).
 */
class CommandIntegrityVerifier(
    private val command: String,
    private val timeoutMs: Long = 10_000,
    private val passEnv: Set<String> = emptySet()
) : IntegrityVerifier {

    override fun verify(token: String, requestHash: String, deviceId: String?): IntegrityVerdict {
        val input = buildJsonObject {
            put("token", token)
            put("requestHash", requestHash)
            deviceId?.let { put("deviceId", it) }
        }.toString().toByteArray(Charsets.UTF_8)

        val builder = ProcessBuilder("/bin/sh", "-c", command)
        builder.environment().keys.retainAll { passes(it, passEnv) }
        val process = builder.start()
        var stdout = ByteArray(0)
        var stderr = ByteArray(0)
        val writer = Thread {
            try { process.outputStream.use { it.write(input) } } catch (_: java.io.IOException) { /* closed stdin */ }
        }.apply { isDaemon = true; start() }
        val outReader = Thread { stdout = readBounded(process.inputStream) }.apply { isDaemon = true; start() }
        val errReader = Thread { stderr = readBounded(process.errorStream) }.apply { isDaemon = true; start() }

        if (!process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
            process.descendants().forEach { it.destroyForcibly() }
            process.destroyForcibly()
            error("integrity verifier timed out after ${timeoutMs}ms")
        }
        writer.join(1_000)
        outReader.join(1_000)
        errReader.join(1_000)
        if (process.exitValue() != 0) {
            error("integrity verifier exited with ${process.exitValue()}: ${String(stderr).trim().take(200)}")
        }
        val answer = try {
            Json.parseToJsonElement(String(stdout, Charsets.UTF_8).trim()).jsonObject
        } catch (e: Exception) {
            error("integrity verifier printed no JSON object")
        }
        val passed = (answer["passed"] as? JsonPrimitive)?.booleanOrNull
            ?: error("integrity verifier answer has no boolean 'passed'")
        val reason = (answer["reason"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.take(64)
            ?.filter { it.isLetterOrDigit() || it == '_' || it == '-' || it == '.' }
        val summary = (answer["summary"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.take(200)
            ?.filter { !it.isISOControl() }
        return IntegrityVerdict(passed, if (passed) null else reason?.ifBlank { null } ?: "verdict_failed", summary)
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
        private val PASSED_ENV = setOf("PATH", "HOME", "LANG", "TZ")

        /** Whether the environment variable [name] reaches the verifier command. */
        internal fun passes(name: String, passEnv: Set<String> = emptySet()): Boolean =
            name in PASSED_ENV || name.startsWith("INTEGRITY_") ||
                (name in passEnv && !CommandSigner.isServerSecret(name))

        /**
         * The verifier `INTEGRITY_VERIFIER_COMMAND` names, or null when it is
         * empty. `INTEGRITY_VERIFIER_TIMEOUT_MS` (default 10000) bounds one
         * run; `INTEGRITY_PASS_ENV` (comma separated) passes more variables.
         */
        fun fromEnv(env: (String) -> String?): CommandIntegrityVerifier? {
            val command = env("INTEGRITY_VERIFIER_COMMAND")?.trim()?.takeIf { it.isNotEmpty() } ?: return null
            val timeout = env("INTEGRITY_VERIFIER_TIMEOUT_MS")?.trim()?.takeIf { it.isNotEmpty() }?.let {
                it.toLongOrNull()?.takeIf { ms -> ms in 1_000..60_000 }
                    ?: throw IllegalArgumentException("INTEGRITY_VERIFIER_TIMEOUT_MS must be 1000..60000 (got '$it')")
            } ?: 10_000
            val passEnv = env("INTEGRITY_PASS_ENV")?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }?.toSet() ?: emptySet()
            return CommandIntegrityVerifier(command, timeout, passEnv)
        }
    }
}
