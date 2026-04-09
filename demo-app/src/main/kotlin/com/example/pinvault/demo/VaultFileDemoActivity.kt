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
import io.github.umutcansu.pinvault.model.VaultFileResult
import kotlinx.coroutines.*
import java.text.SimpleDateFormat
import java.util.*

/**
 * Demo activity for VaultFile feature.
 * Shows how to register, fetch, and manage remote versioned files via PinVault.
 */
class VaultFileDemoActivity : AppCompatActivity() {

    companion object {
        private val HOST_IP: String by lazy {
            val isEmulator = android.os.Build.FINGERPRINT.contains("generic") ||
                android.os.Build.MODEL.contains("Emulator") ||
                android.os.Build.PRODUCT.contains("sdk")
            if (isEmulator) "10.0.2.2" else "192.168.1.80"
        }
        private val CONFIG_SERVER_URL get() = "https://$HOST_IP:8091/"
        private val MANAGEMENT_URL get() = "http://$HOST_IP:8090/"
    }

    private lateinit var binding: ActivityDemoBaseBinding
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private val logEntries = mutableListOf<LogEntry>()

    private data class LogEntry(
        val time: String,
        val success: Boolean,
        val message: String
    )

    // Bootstrap pins for Config API server cert.
    // Config API (port 8091) uses demo-server's default TLS cert (CN=localhost).
    // Pin must match the actual SPKI hash of that cert, for both emulator and physical.
    private val bootstrapPins: List<HostPin> by lazy {
        listOf(HostPin(HOST_IP, listOf(
            "ziA0hyMDbayVXZ0g8AkkJz+wmKPZYjMAwb+GdNg5HYM=",
            "wmKPZYjMAwb+GdNg5HYMziA0hyMDbayVXZ0g8AkkJz8="  // backup (placeholder)
        )))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityDemoBaseBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupUI()
        initPinVault()
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }

    private fun setupUI() {
        binding.tvTitle.text = "Vault Files"
        binding.tvTitle.setTextColor(color(R.color.accent_cyan))

        binding.tvServer.text = "Config: $CONFIG_SERVER_URL\nVault: ${MANAGEMENT_URL}api/v1/vault/"

        binding.enrollmentCard.visibility = View.GONE
        binding.certInfoCard.visibility = View.GONE

        // Repurpose buttons for vault file operations
        binding.btnTest.text = "Fetch Files"
        binding.btnUpdate.text = "Sync All"

        binding.btnTest.setOnClickListener { fetchFiles() }
        binding.btnUpdate.setOnClickListener { syncAllFiles() }
    }

    private fun initPinVault() {
        binding.tvStatus.text = "Initializing..."
        binding.tvStatus.setTextColor(color(R.color.status_warning))

        try { PinVault.reset() } catch (_: Exception) {}

        val config = PinVaultConfig.Builder(CONFIG_SERVER_URL)
            .bootstrapPins(bootstrapPins)
            .configEndpoint("api/v1/certificate-config?signed=false")
            .vaultFile("feature-flags") {
                endpoint("api/v1/vault/feature-flags")
                updateWithPins(true)
            }
            .vaultFile("ml-model") {
                endpoint("api/v1/vault/ml-model")
                storage(StorageStrategy.ENCRYPTED_FILE)
            }
            .vaultFile("remote-config") {
                endpoint("api/v1/vault/remote-config")
                updateWithPins(true)
            }
            .build()

        PinVault.init(applicationContext, config) { result ->
            when (result) {
                is InitResult.Ready -> {
                    binding.tvStatus.text = "Ready — v${result.version}"
                    binding.tvStatus.setTextColor(color(R.color.status_success))
                    binding.tvVersion.text = "Pin version: ${result.version}"
                    binding.btnTest.isEnabled = true
                    binding.btnUpdate.isEnabled = true
                    addLog(true, "PinVault init OK v${result.version}")

                    // Show registered vault files
                    showVaultFileInfo()

                    // Set file update listener
                    PinVault.setOnFileUpdateListener { key, fileResult ->
                        runOnUiThread {
                            when (fileResult) {
                                is VaultFileResult.Updated ->
                                    addLog(true, "File '$key' updated → v${fileResult.version} (${fileResult.bytes.size} bytes)")
                                is VaultFileResult.AlreadyCurrent ->
                                    addLog(true, "File '$key' already current v${fileResult.version}")
                                is VaultFileResult.Failed ->
                                    addLog(false, "File '$key' failed: ${fileResult.reason}")
                            }
                        }
                    }
                }
                is InitResult.Failed -> {
                    binding.tvStatus.text = "Failed"
                    binding.tvStatus.setTextColor(color(R.color.status_error))
                    binding.tvVersion.text = result.reason
                    binding.btnTest.isEnabled = false
                    binding.btnUpdate.isEnabled = false
                    addLog(false, "Init failed: ${result.reason}")
                }
            }
        }
    }

    private fun fetchFiles() {
        binding.btnTest.isEnabled = false
        showResult("Fetching vault files...", R.color.text_secondary)

        scope.launch {
            val files = listOf("feature-flags", "ml-model", "remote-config")
            val results = mutableListOf<String>()

            for (key in files) {
                try {
                    val result = PinVault.fetchFile(key)
                    when (result) {
                        is VaultFileResult.Updated -> {
                            addLog(true, "'$key' → v${result.version} (${result.bytes.size} bytes)")
                            results.add("$key: Updated v${result.version}")
                        }
                        is VaultFileResult.AlreadyCurrent -> {
                            addLog(true, "'$key' → already current v${result.version}")
                            results.add("$key: Current v${result.version}")
                        }
                        is VaultFileResult.Failed -> {
                            addLog(false, "'$key' → ${result.reason}")
                            results.add("$key: FAILED")
                        }
                    }
                } catch (e: Exception) {
                    addLog(false, "'$key' → ${e.message}")
                    results.add("$key: ERROR")
                }
            }

            showResult(results.joinToString("\n"), R.color.status_success)
            showVaultFileInfo()
            binding.btnTest.isEnabled = true
        }
    }

    private fun syncAllFiles() {
        binding.btnUpdate.isEnabled = false
        showResult("Syncing all files...", R.color.text_secondary)

        scope.launch {
            try {
                val results = PinVault.syncAllFiles()
                val summary = results.map { (key, result) ->
                    when (result) {
                        is VaultFileResult.Updated -> "$key: Updated v${result.version}"
                        is VaultFileResult.AlreadyCurrent -> "$key: Current v${result.version}"
                        is VaultFileResult.Failed -> "$key: FAILED"
                    }
                }
                addLog(true, "Synced ${results.size} files")
                showResult(
                    if (summary.isEmpty()) "No files with updateWithPins=true" else summary.joinToString("\n"),
                    R.color.status_success
                )
                showVaultFileInfo()
            } catch (e: Exception) {
                addLog(false, "Sync failed: ${e.message}")
                showResult("Sync failed: ${e.message}", R.color.status_error)
            } finally {
                binding.btnUpdate.isEnabled = true
            }
        }
    }

    private fun showVaultFileInfo() {
        runOnUiThread {
            binding.certInfoCard.visibility = View.VISIBLE
            val sb = StringBuilder()
            sb.appendLine("── Vault Files ──")

            val files = listOf("feature-flags", "ml-model", "remote-config")
            for (key in files) {
                val exists = PinVault.hasFile(key)
                val version = PinVault.fileVersion(key)
                val size = PinVault.loadFile(key)?.size ?: 0
                val status = if (exists) "v$version ($size bytes)" else "not cached"
                sb.appendLine("$key: $status")
            }

            binding.tvCertInfo.text = sb.toString().trimEnd()
        }
    }

    // ── Log ──────────────────────────────────────────────

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

    private fun showResult(text: String, colorRes: Int) {
        runOnUiThread {
            binding.tvResult.text = text
            binding.tvResult.setTextColor(color(colorRes))
        }
    }

    private fun color(resId: Int) = ContextCompat.getColor(this, resId)
    private fun dpToPx(dp: Int) = (dp * resources.displayMetrics.density).toInt()
}
