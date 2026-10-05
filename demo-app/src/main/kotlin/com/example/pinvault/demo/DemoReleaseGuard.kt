package com.example.pinvault.demo

import android.app.Activity
import android.util.Log
import androidx.appcompat.app.AlertDialog
import io.github.umutcansu.pinvault.model.ConfigApiBlock
import io.github.umutcansu.pinvault.reporter.PinVaultBackendReporter
import okhttp3.OkHttpClient

/**
 * Release guard (security review A-2).
 *
 * The debug build is a lab tool and takes three shortcuts: it reads the
 * demo-server's unsigned config (`?signed=false` + `allowUnsigned()`), its
 * second bootstrap pin is a placeholder, and it posts connection reports over
 * plain HTTP to the management port. `BuildConfig.DEMO_INSECURE_CHANNELS`
 * (true in debug, false in release — `demo-app/build.gradle.kts`) is the one
 * switch for all three; every call site goes through this object, so a
 * release build cannot take any of them:
 *
 *  - the config comes from the library's default (signed) endpoint and is
 *    verified with `BuildConfig.DEMO_SIGNING_PUBLIC_KEY` (`-Pdemo.signingPublicKey`),
 *    bound to the server's Config API id (`serverScope`) when one is known;
 *  - the second pin is `BuildConfig.DEMO_BACKUP_PIN` (`-Pdemo.backupPin`);
 *  - reports go to the pinned TLS Config API with a client that accepts only
 *    the bootstrap pins ([reportClient]).
 *
 * When a release build has no key or no pin it does not run half-secure: the
 * Gradle build already stops (`preReleaseBuild`), and should such an APK exist
 * anyway, [check] shows why and closes the app before PinVault is configured,
 * while [configApiPins] / [configureSigning] refuse to build a block.
 */
object DemoReleaseGuard {

    private const val TAG = "PinVaultDemo"

    /** Primary SPKI SHA-256 pin of the demo-server's default TLS certificate (ports 8091/8092). */
    const val CONFIG_API_PIN_PRIMARY = "ziA0hyMDbayVXZ0g8AkkJz+wmKPZYjMAwb+GdNg5HYM="

    /** The unsigned endpoint the DEBUG build reads; release keeps the library's default (signed) one. */
    private const val UNSIGNED_CONFIG_ENDPOINT = "api/v1/certificate-config?signed=false"

    /** True = this build may use the lab shortcuts (debug). */
    val insecureChannels: Boolean get() = BuildConfig.DEMO_INSECURE_CHANNELS

    /** The release values this build lacks, as Gradle properties; empty when the app may run. */
    fun missingReleaseValues(): List<String> {
        if (BuildConfig.DEMO_INSECURE_CHANNELS) return emptyList()
        val missing = mutableListOf<String>()
        if (BuildConfig.DEMO_SIGNING_PUBLIC_KEY.isEmpty()) {
            missing += "demo.signingPublicKey — the server's config-signing public key (GET /api/v1/signing-key → publicKey)"
        }
        if (BuildConfig.DEMO_BACKUP_PIN.isEmpty()) {
            missing += "demo.backupPin — the second SPKI pin of the Config API certificate"
        }
        return missing
    }

    /**
     * First thing in every activity's `onCreate`. Returns true when the app
     * may continue. Otherwise (a release build without its values) it logs
     * the reason, shows it in a dialog that closes the app, and returns false;
     * the caller must return without configuring PinVault.
     */
    fun check(activity: Activity): Boolean {
        val missing = missingReleaseValues()
        if (missing.isEmpty()) return true
        Log.e(TAG, "Release build refused to start — missing build values: ${missing.joinToString("; ")}")
        AlertDialog.Builder(activity)
            .setTitle(R.string.release_guard_title)
            .setMessage(activity.getString(R.string.release_guard_message, missing.joinToString("\n") { "• $it" }))
            .setCancelable(false)
            .setPositiveButton(android.R.string.ok) { _, _ -> activity.finishAffinity() }
            .show()
        return false
    }

    /**
     * The pins the Config API certificate is checked against: the primary pin
     * and, in debug, the placeholder second pin; in release the pin given at
     * build time. Throws in a release build that has none (see [check]).
     */
    fun configApiPins(): List<String> {
        val backup = BuildConfig.DEMO_BACKUP_PIN
        if (backup.isEmpty()) {
            throw IllegalStateException("Release build without demo.backupPin: no backup pin, PinVault not configured.")
        }
        return listOf(CONFIG_API_PIN_PRIMARY, backup)
    }

    /**
     * How the block's config is trusted. Debug: the unsigned demo endpoint
     * with `allowUnsigned()`, exactly as before. Release: the library's
     * default endpoint, whose signed envelope is verified with the embedded
     * key, and — when [serverScope] is not empty — accepted only when it was
     * signed for that Config API id. Throws in a release build without a key.
     */
    fun configureSigning(block: ConfigApiBlock.Builder, serverScope: String) {
        if (BuildConfig.DEMO_INSECURE_CHANNELS) {
            block.configEndpoint(UNSIGNED_CONFIG_ENDPOINT)
            // Lab only: no signature, no freshness, no replay protection.
            block.allowUnsigned()
            return
        }
        val key = BuildConfig.DEMO_SIGNING_PUBLIC_KEY
        if (key.isEmpty()) {
            throw IllegalStateException("Release build without demo.signingPublicKey: unsigned config refused, PinVault not configured.")
        }
        block.signaturePublicKey(key)
        if (serverScope.isNotEmpty()) block.serverScope(serverScope)
    }

    /**
     * The client that carries connection reports. Debug: a plain client for
     * the management port (cleartext, allowed for the lab hosts by the debug
     * network security config). Release: a client that accepts only the
     * bootstrap pins for [hostIp], for the TLS Config API's report endpoint.
     */
    fun reportClient(hostIp: String): OkHttpClient =
        if (BuildConfig.DEMO_INSECURE_CHANNELS) OkHttpClient()
        else PinVaultBackendReporter.pinnedClient(hostIp, configApiPins())
}
