package com.example.pinvault.demo

import android.graphics.Typeface
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.example.pinvault.demo.databinding.ActivityDemoBaseBinding
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import io.github.umutcansu.pinvault.model.StorageStrategy
import io.github.umutcansu.pinvault.model.VaultFileAccessPolicy
import io.github.umutcansu.pinvault.model.VaultFileEncryption
import io.github.umutcansu.pinvault.model.VaultFileResult
import kotlinx.coroutines.*
import java.text.SimpleDateFormat
import java.util.*

/**
 * V2 demo: multi-Config-API + per-file access policy + end-to-end encryption.
 *
 * Demonstrates:
 *   1. Two Config APIs registered via `.configApi(id, url) { ... }`
 *      — "default-tls" (port 8091) for public/token files
 *      — (optional) secondary Config API for higher-security flows
 *   2. Three vault files with different policies:
 *      - `demo-public-v2`      → accessPolicy(PUBLIC)  — no token
 *      - `demo-token-v2`       → accessPolicy(TOKEN)   — needs admin-issued token
 *      - `demo-e2e-v2`         → encryption(END_TO_END) + TOKEN
 *
 * Before running:
 *   - Demo-server must be running with V2 migration applied
 *   - Admin uploads demo-public-v2 / demo-token-v2 / demo-e2e-v2 via web UI
 *     with matching policies
 *   - Admin issues tokens for demo-token-v2 and demo-e2e-v2 bound to this
 *     device's ID, then hardcodes them in [tokenForKey] below (or reads them
 *     from a secure out-of-band channel)
 */
class VaultSecurityDemoActivity : AppCompatActivity() {

    companion object {
        private val HOST_IP: String by lazy {
            val isEmulator = android.os.Build.FINGERPRINT.contains("generic") ||
                android.os.Build.MODEL.contains("Emulator") ||
                android.os.Build.PRODUCT.contains("sdk")
            if (isEmulator) "10.0.2.2" else "192.168.1.80"
        }
        private val TLS_URL  get() = "https://$HOST_IP:8091/"

        private val DEVICE_SUFFIX: String by lazy {
            android.os.Build.MODEL.replace(" ", "-").lowercase()
        }
    }

    // Same bootstrap pin the library verifies against demo-server's cert.
    private val bootstrapPinsTls: List<HostPin> by lazy {
        listOf(HostPin(HOST_IP, listOf(
            "ziA0hyMDbayVXZ0g8AkkJz+wmKPZYjMAwb+GdNg5HYM=",
            "wmKPZYjMAwb+GdNg5HYMziA0hyMDbayVXZ0g8AkkJz8="
        )))
    }

    // Device-unique keys to avoid collisions in multi-device test runs.
    private val keyPublic = "demo-public-v2-$DEVICE_SUFFIX"
    private val keyToken  = "demo-token-v2-$DEVICE_SUFFIX"
    private val keyE2E    = "demo-e2e-v2-$DEVICE_SUFFIX"

    /**
     * Tokens must be issued by the admin (POST /api/v1/vault/.../tokens) and
     * delivered out-of-band (QR code, enrollment response, etc.). For the
     * demo, they're read from BuildConfig — set `VAULT_TOKEN_MI_9T` in local
     * gradle.properties. Returns "" when not configured → fetch returns 401.
     */
    private fun tokenForKey(key: String): String {
        // Minimal demo implementation: same token for both (set via adb / shared prefs).
        return getSharedPreferences("vault_security_demo", MODE_PRIVATE)
            .getString("token_$key", "") ?: ""
    }

    private lateinit var binding: ActivityDemoBaseBinding
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private val logEntries = mutableListOf<LogEntry>()

    private data class LogEntry(val time: String, val success: Boolean, val message: String)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Ensure Timber is planted so library-side logs reach logcat during
        // debug runs. Idempotent: repeated plants with DebugTree are safe but
        // we only plant once to avoid duplicate output.
        if (timber.log.Timber.forest().isEmpty()) {
            timber.log.Timber.plant(timber.log.Timber.DebugTree())
        }

        binding = ActivityDemoBaseBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.tvTitle.text = "Vault Security (V2)"
        binding.tvTitle.setTextColor(color(R.color.accent_cyan))
        binding.tvServer.text = "TLS  Config API : $TLS_URL\nFiles: public / token / end-to-end"
        binding.enrollmentCard.visibility = View.GONE
        binding.certInfoCard.visibility = View.GONE

        binding.btnTest.text = "Fetch All"
        binding.btnUpdate.text = "Save Tokens"
        binding.btnTest.setOnClickListener { fetchAll() }
        binding.btnUpdate.setOnClickListener { openTokenEditor() }

        initPinVault()
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }

    private fun initPinVault() {
        binding.tvStatus.text = "Initializing (multi-API)…"
        binding.tvStatus.setTextColor(color(R.color.status_warning))
        try { PinVault.reset() } catch (_: Exception) {}

        val deviceName = "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}"

        val config = PinVaultConfig.Builder()
            // V2: register one or more Config APIs. Here only the TLS one; a
            // real multi-API app would also add a "secure-mtls" block.
            .configApi("default-tls", TLS_URL) {
                bootstrapPins(bootstrapPinsTls)
                configEndpoint("api/v1/certificate-config?signed=false")
                wantPinsFor(HOST_IP)
            }
            // Public file — no token, no encryption
            .vaultFile(keyPublic) {
                configApi("default-tls")
                endpoint("api/v1/vault/$keyPublic")
                accessPolicy(VaultFileAccessPolicy.PUBLIC)
            }
            // Token-protected file — per-device token
            .vaultFile(keyToken) {
                configApi("default-tls")
                endpoint("api/v1/vault/$keyToken")
                accessPolicy(VaultFileAccessPolicy.TOKEN)
                accessToken { tokenForKey(keyToken) }
            }
            // End-to-end encrypted file — token + server encrypts with our RSA public key
            .vaultFile(keyE2E) {
                configApi("default-tls")
                endpoint("api/v1/vault/$keyE2E")
                storage(StorageStrategy.ENCRYPTED_FILE)
                accessPolicy(VaultFileAccessPolicy.TOKEN)
                accessToken { tokenForKey(keyE2E) }
                encryption(VaultFileEncryption.END_TO_END)
            }
            .deviceAlias(deviceName)
            .build()

        PinVault.init(applicationContext, config) { result ->
            when (result) {
                is InitResult.Ready -> {
                    binding.tvStatus.text = "Ready — v${result.version}"
                    binding.tvStatus.setTextColor(color(R.color.status_success))
                    binding.tvVersion.text = "Pin version: ${result.version} · RSA device key registered"
                    binding.btnTest.isEnabled = true
                    binding.btnUpdate.isEnabled = true
                    addLog(true, "Init OK — 3 files registered (public / token / e2e)")
                    PinVault.setOnFileUpdateListener { key, res ->
                        runOnUiThread { logResult(key, res) }
                    }
                }
                is InitResult.Failed -> {
                    binding.tvStatus.text = "Failed"
                    binding.tvStatus.setTextColor(color(R.color.status_error))
                    binding.tvVersion.text = result.reason
                    addLog(false, "Init failed: ${result.reason}")
                }
            }
        }
    }

    private fun fetchAll() {
        binding.btnTest.isEnabled = false
        binding.tvResult.text = "Fetching 3 files…"
        binding.tvResult.setTextColor(color(R.color.text_secondary))
        scope.launch {
            val keys = listOf(keyPublic, keyToken, keyE2E)
            val summary = StringBuilder()
            for (key in keys) {
                val policy = when (key) {
                    keyPublic -> "PUBLIC"
                    keyToken  -> "TOKEN"
                    else      -> "TOKEN+E2E"
                }
                val res = try { PinVault.fetchFile(key) }
                          catch (e: Exception) { VaultFileResult.Failed(key, e.message ?: "throw", e) }
                logResult(key, res)
                val line = when (res) {
                    is VaultFileResult.Updated       -> "$key [$policy] → v${res.version} (${res.bytes.size} B)"
                    is VaultFileResult.AlreadyCurrent -> "$key [$policy] → current v${res.version}"
                    is VaultFileResult.Failed        -> "$key [$policy] → FAIL: ${res.reason}"
                }
                summary.appendLine(line)
            }
            binding.tvResult.text = summary.toString().trimEnd()
            binding.tvResult.setTextColor(color(R.color.status_success))
            binding.btnTest.isEnabled = true
        }
    }

    private fun openTokenEditor() {
        // Minimal: show an AlertDialog with three EditTexts for the tokens.
        // In a real app these would come from enrollment response / QR.
        val prefs = getSharedPreferences("vault_security_demo", MODE_PRIVATE)
        val editTextToken = android.widget.EditText(this).apply {
            hint = "token (for demo-token + demo-e2e)"
            setText(prefs.getString("token_$keyToken", ""))
        }
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Set vault token (issued by admin)")
            .setView(editTextToken)
            .setPositiveButton("Save") { _, _ ->
                val t = editTextToken.text.toString().trim()
                prefs.edit().putString("token_$keyToken", t).putString("token_$keyE2E", t).apply()
                addLog(true, "Tokens saved (shared for token + e2e)")
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun logResult(key: String, res: VaultFileResult) {
        when (res) {
            is VaultFileResult.Updated       -> addLog(true, "$key → Updated v${res.version} (${res.bytes.size} B)")
            is VaultFileResult.AlreadyCurrent -> addLog(true, "$key → Current v${res.version}")
            is VaultFileResult.Failed        -> addLog(false, "$key → ${res.reason}")
        }
    }

    // ── Log plumbing (identical to VaultFileDemoActivity) ────

    private fun addLog(success: Boolean, message: String) {
        val time = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        logEntries.add(0, LogEntry(time, success, message))
        if (logEntries.size > 20) logEntries.removeAt(logEntries.lastIndex)
        runOnUiThread { renderLog() }
    }

    private fun renderLog() {
        binding.logContainer.removeAllViews()
        logEntries.forEach { entry ->
            binding.logContainer.addView(TextView(this).apply {
                val icon = if (entry.success) "✓" else "✗"
                text = "$icon ${entry.time} — ${entry.message}"
                setTextColor(color(if (entry.success) R.color.status_success else R.color.status_error))
                textSize = 12f
                typeface = Typeface.MONOSPACE
                setPadding(0, dpToPx(2), 0, dpToPx(2))
            })
        }
    }

    private fun color(resId: Int) = ContextCompat.getColor(this, resId)
    private fun dpToPx(dp: Int) = (dp * resources.displayMetrics.density).toInt()
}
