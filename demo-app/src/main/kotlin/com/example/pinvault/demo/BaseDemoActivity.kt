package com.example.pinvault.demo

import android.graphics.Typeface
import android.os.Bundle
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.example.pinvault.demo.databinding.ActivityDemoBaseBinding
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import io.github.umutcansu.pinvault.model.UpdateResult
import kotlinx.coroutines.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import timber.log.Timber
import java.text.SimpleDateFormat
import java.util.*

/**
 * Base class for all demo activities.
 * Subclasses only define config URLs, bootstrap pins, and enrollment requirements.
 */
abstract class BaseDemoActivity : AppCompatActivity() {

    companion object {
        val IS_EMULATOR: Boolean by lazy {
            android.os.Build.FINGERPRINT.contains("generic") ||
                android.os.Build.FINGERPRINT.contains("emulator") ||
                android.os.Build.MODEL.contains("Emulator") ||
                android.os.Build.MODEL.contains("Android SDK") ||
                android.os.Build.MANUFACTURER.contains("Genymotion") ||
                android.os.Build.PRODUCT.contains("sdk") ||
                android.os.Build.PRODUCT.contains("emulator")
        }
        val HOST_IP: String by lazy { if (IS_EMULATOR) "10.0.2.2" else "192.168.1.80" }
        val TLS_HOST_PORT: Int by lazy { if (IS_EMULATOR) 8443 else 8444 }
        private val MANAGEMENT_URL get() = "http://$HOST_IP:8090/"

        /** Bootstrap pins — demo-server TLS cert */
        val DEFAULT_BOOTSTRAP_PINS: List<HostPin> by lazy {
            listOf(HostPin(HOST_IP, listOf(
                "ziA0hyMDbayVXZ0g8AkkJz+wmKPZYjMAwb+GdNg5HYM=",
                "vXC1UZ8OFlga9Ltwsa2Hyg2lqZkLUE+DbdBPvT3ah3o="
            )))
        }
    }

    // ── Abstract properties — subclasses override ────────
    abstract val configServerUrl: String
    abstract val mockServerUrl: String
    abstract val bootstrapPins: List<HostPin>
    abstract val activityTitle: String
    abstract val titleColorRes: Int
    /** true = config çekmeden önce enrollment zorunlu (mTLS config API) */
    abstract val requiresEnrollment: Boolean
    /** true = init sonrası otomatik enrollment yap (mTLS host için) */
    open val autoEnrollForHost: Boolean get() = false
    /** true = enrollment kartını göster (mTLS config) */
    open val showsEnrollmentCard: Boolean get() = requiresEnrollment

    protected lateinit var binding: ActivityDemoBaseBinding
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private val logEntries = mutableListOf<LogEntry>()
    private var autoEnrollAttempted = false

    private data class LogEntry(
        val time: String,
        val success: Boolean,
        val message: String,
        val durationMs: Long = 0
    )

    // ── Lifecycle ────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!Timber.forest().any { it is Timber.DebugTree }) {
            Timber.plant(Timber.DebugTree())
        }

        binding = ActivityDemoBaseBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupUI()

        if (showsEnrollmentCard) {
            binding.enrollmentCard.visibility = View.VISIBLE
            binding.btnEnroll.setOnClickListener { showEnrollDialog() }
            binding.btnUnenroll.setOnClickListener { unenroll() }
        } else {
            binding.enrollmentCard.visibility = View.GONE
        }

        if (requiresEnrollment) {
            updateEnrollmentUI()
        } else {
            if (showsEnrollmentCard) updateEnrollmentStatus()
            initPinVault()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }

    // ── Setup ────────────────────────────────────────────

    private fun setupUI() {
        binding.tvTitle.text = activityTitle
        binding.tvTitle.setTextColor(color(titleColorRes))

        val clientIp = getDeviceIp()
        binding.tvServer.text = "${getString(R.string.server_label, configServerUrl)}\n${getString(R.string.host_label, mockServerUrl)}\n${getString(R.string.client_ip_label, clientIp)}"

        binding.btnTest.setOnClickListener { testConnection() }
        binding.btnUpdate.setOnClickListener { updatePins() }
    }

    // ── Enrollment ───────────────────────────────────────

    private fun updateEnrollmentUI() {
        val enrolled = PinVault.isEnrolled(this)

        if (enrolled) {
            binding.tvEnrollStatus.text = getString(R.string.enrolled)
            binding.tvEnrollStatus.setTextColor(color(R.color.status_success))
            binding.btnEnroll.isEnabled = false
            binding.btnUnenroll.isEnabled = true
            addLog(true, getString(R.string.log_cert_exists))
            initPinVault()
        } else {
            binding.tvEnrollStatus.text = getString(R.string.not_enrolled)
            binding.tvEnrollStatus.setTextColor(color(R.color.status_error))
            binding.btnEnroll.isEnabled = true
            binding.btnUnenroll.isEnabled = false
            binding.btnTest.isEnabled = false
            binding.btnUpdate.isEnabled = false
            binding.tvStatus.text = getString(R.string.enrollment_required)
            binding.tvStatus.setTextColor(color(R.color.status_warning))
            binding.tvVersion.text = getString(R.string.enrollment_hint)
        }
    }

    /** Enrollment kartı durumunu günceller ama PinVault init'i engellemez */
    private fun updateEnrollmentStatus() {
        val enrolled = PinVault.isEnrolled(this)
        if (enrolled) {
            binding.tvEnrollStatus.text = getString(R.string.enrolled)
            binding.tvEnrollStatus.setTextColor(color(R.color.status_success))
            binding.btnEnroll.isEnabled = false
            binding.btnUnenroll.isEnabled = true
        } else {
            binding.tvEnrollStatus.text = getString(R.string.not_enrolled)
            binding.tvEnrollStatus.setTextColor(color(R.color.status_error))
            binding.btnEnroll.isEnabled = true
            binding.btnUnenroll.isEnabled = false
        }
    }

    private fun showEnrollDialog() {
        val input = android.widget.EditText(this).apply {
            hint = getString(R.string.enrollment_token_hint)
            inputType = android.text.InputType.TYPE_CLASS_TEXT
            setTextColor(color(R.color.text_primary))
            setHintTextColor(color(R.color.text_muted))
        }

        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(getString(R.string.enrollment_title))
            .setMessage(getString(R.string.enrollment_message))
            .setView(input)
            .setPositiveButton(getString(R.string.enroll)) { _, _ ->
                val token = input.text.toString().trim()
                if (token.isNotEmpty()) performEnrollment(token)
            }
            .setNegativeButton(getString(R.string.cancel), null)
            .show()
    }

    private fun performEnrollment(token: String) {
        binding.tvEnrollStatus.text = getString(R.string.enrolling)
        binding.tvEnrollStatus.setTextColor(color(R.color.status_warning))
        binding.btnEnroll.isEnabled = false
        addLog(true, getString(R.string.log_enrolling))

        try { PinVault.reset() } catch (_: Exception) {}

        val config = PinVaultConfig.Builder(configServerUrl)
            .bootstrapPins(bootstrapPins)
            .configEndpoint("api/v1/certificate-config?signed=false")
            .build()

        PinVault.init(applicationContext, config) { initResult ->
            if (initResult is InitResult.Failed) {
                addLog(false, getString(R.string.log_init_failed, initResult.reason))
                runOnUiThread {
                    binding.tvEnrollStatus.text = getString(R.string.enrollment_failed)
                    binding.tvEnrollStatus.setTextColor(color(R.color.status_error))
                    binding.btnEnroll.isEnabled = true
                }
                return@init
            }

            scope.launch {
                val success = PinVault.enroll(applicationContext, token)
                if (success) {
                    addLog(true, getString(R.string.log_enroll_success))
                    showResult(getString(R.string.enrollment_success), R.color.status_success)
                    try { PinVault.reset() } catch (_: Exception) {}
                    updateEnrollmentUI()
                } else {
                    addLog(false, getString(R.string.log_enroll_failed))
                    showResult(getString(R.string.enrollment_invalid_token), R.color.status_error)
                    runOnUiThread {
                        binding.tvEnrollStatus.text = getString(R.string.enrollment_failed)
                        binding.tvEnrollStatus.setTextColor(color(R.color.status_error))
                        binding.btnEnroll.isEnabled = true
                    }
                }
            }
        }
    }

    private fun unenroll() {
        try { PinVault.reset() } catch (_: Exception) {}
        PinVault.unenroll(applicationContext)
        addLog(true, getString(R.string.log_unenrolled))
        showResult(getString(R.string.unenrolled), R.color.accent_cyan)
        updateEnrollmentUI()
    }

    // ── PinVault Init ────────────────────────────────────

    private fun initPinVault() {
        binding.tvStatus.text = getString(R.string.initializing)
        binding.tvStatus.setTextColor(color(R.color.status_warning))
        addLog(true, "Config API: $configServerUrl")

        val enrolled = PinVault.isEnrolled(this)
        if (enrolled) addLog(true, "Client cert: enrolled ✓")

        try { PinVault.reset() } catch (_: Exception) {}

        val deviceName = "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}"
        val config = PinVaultConfig.Builder(configServerUrl)
            .bootstrapPins(bootstrapPins)
            .configEndpoint("api/v1/certificate-config?signed=false")
            .updateIntervalMinutes(15)
            .deviceAlias(deviceName)
            .build()

        PinVault.init(applicationContext, config) { result ->
            when (result) {
                is InitResult.Ready -> onInitReady(result.version)
                is InitResult.Failed -> onInitFailed(result.reason)
            }
        }
    }

    private fun onInitReady(version: Int) {
        binding.tvStatus.text = getString(R.string.ready, version)
        binding.tvStatus.setTextColor(color(R.color.status_success))
        binding.tvVersion.text = getString(R.string.pin_version, version)
        binding.btnTest.isEnabled = true
        binding.btnUpdate.isEnabled = true
        addLog(true, "Init OK v$version — ${if (PinVault.isEnrolled(this)) "cert ✓" else "no cert"}")

        // mTLS host için otomatik enrollment (sadece ilk seferde)
        if (autoEnrollForHost && !PinVault.isEnrolled(this) && !autoEnrollAttempted) {
            autoEnrollAttempted = true
            addLog(true, "Auto-enrolling from ${configServerUrl}api/v1/client-certs/enroll")
            scope.launch {
                val success = withContext(Dispatchers.IO) { PinVault.autoEnroll(applicationContext) }
                if (success) {
                    addLog(true, "Auto-enroll OK — cert stored, reinit...")
                    try { PinVault.reset() } catch (_: Exception) {}
                    runOnUiThread { initPinVault() }
                } else {
                    addLog(false, "Auto-enroll FAILED")
                }
            }
        }

        PinVault.setOnUpdateListener { result ->
            runOnUiThread {
                when (result) {
                    is UpdateResult.Updated -> {
                        binding.tvStatus.text = getString(R.string.ready, result.newVersion)
                        binding.tvVersion.text = getString(R.string.pin_version, result.newVersion)
                        addLog(true, getString(R.string.log_bg_update, result.newVersion))
                    }
                    is UpdateResult.AlreadyCurrent -> addLog(true, getString(R.string.log_bg_check))
                    is UpdateResult.Failed -> addLog(false, getString(R.string.log_bg_failed, result.reason))
                }
            }
        }
    }

    private fun onInitFailed(reason: String) {
        binding.tvStatus.text = getString(R.string.failed)
        binding.tvStatus.setTextColor(color(R.color.status_error))
        binding.tvVersion.text = reason
        binding.btnTest.isEnabled = false
        binding.btnUpdate.isEnabled = false
        addLog(false, getString(R.string.log_init_failed, reason))
    }

    // ── Test Connection ──────────────────────────────────

    private fun testConnection() {
        binding.btnTest.isEnabled = false
        showResult(getString(R.string.connecting), R.color.text_secondary)
        addLog(true, "Connecting to $mockServerUrl")

        scope.launch {
            val start = System.currentTimeMillis()
            try {
                val response = withContext(Dispatchers.IO) {
                    val client = PinVault.getClient()
                    val request = Request.Builder().url(mockServerUrl).build()
                    client.newCall(request).execute()
                }
                val elapsed = System.currentTimeMillis() - start
                val body = response.body?.string().orEmpty()

                // mTLS bilgisini response'dan çıkar
                val isMtls = body.contains("\"mtls\":true")
                val certInfo = if (PinVault.isEnrolled(this@BaseDemoActivity)) "cert presented" else "no cert"

                showResult(
                    getString(R.string.connection_success, response.code, elapsed, body.take(200)),
                    R.color.status_success
                )
                addLog(true, "HTTP ${response.code} — ${elapsed}ms — ${if (isMtls) "mTLS" else "TLS"} — $certInfo", elapsed)

                // Sertifika bilgilerini göster
                showCertInfo(body)
                sendReport(success = true, durationMs = elapsed)

            } catch (e: Exception) {
                val elapsed = System.currentTimeMillis() - start
                val errorType = when {
                    e.message?.contains("TLSV1_ALERT_CERTIFICATE_REQUIRED") == true -> "mTLS rejected (no cert)"
                    e.message?.contains("Certificate pinning") == true -> "Pin mismatch"
                    e.message?.contains("Socket closed") == true -> "Socket closed (cert not accepted?)"
                    else -> e.message?.take(60) ?: "Unknown"
                }
                val msg = when {
                    e.message?.contains("TLSV1_ALERT_CERTIFICATE_REQUIRED") == true ->
                        getString(R.string.mtls_no_cert_error)
                    e.message?.contains("Certificate pinning") == true ->
                        getString(R.string.pin_mismatch, e.cause?.message ?: e.message)
                    else ->
                        getString(R.string.connection_failed, e.message ?: "")
                }
                showResult(msg, R.color.status_error)
                addLog(false, "$errorType — ${elapsed}ms", elapsed)
                sendReport(success = false, durationMs = elapsed)

            } finally {
                binding.btnTest.isEnabled = true
            }
        }
    }

    // ── Update Pins ──────────────────────────────────────

    private fun updatePins() {
        binding.btnUpdate.isEnabled = false
        showResult(getString(R.string.updating_pins), R.color.text_secondary)

        scope.launch {
            try {
                when (val result = PinVault.updateNow()) {
                    is UpdateResult.Updated -> {
                        binding.tvStatus.text = getString(R.string.ready, result.newVersion)
                        binding.tvVersion.text = getString(R.string.pin_version, result.newVersion)
                        showResult(getString(R.string.pins_updated, result.newVersion), R.color.status_success)
                        addLog(true, getString(R.string.pins_updated, result.newVersion))
                    }
                    is UpdateResult.AlreadyCurrent -> {
                        showResult(getString(R.string.already_current), R.color.accent_cyan)
                        addLog(true, getString(R.string.log_bg_check))
                    }
                    is UpdateResult.Failed -> {
                        showResult(getString(R.string.update_failed, result.reason), R.color.status_error)
                        addLog(false, getString(R.string.update_failed, result.reason))
                    }
                }
            } catch (e: Exception) {
                showResult(getString(R.string.error_generic, e.message ?: ""), R.color.status_error)
                addLog(false, getString(R.string.error_generic, e.message ?: ""))
            } finally {
                binding.btnUpdate.isEnabled = true
            }
        }
    }

    // ── Log ──────────────────────────────────────────────

    protected fun addLog(success: Boolean, message: String, durationMs: Long = 0) {
        val time = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        logEntries.add(0, LogEntry(time, success, message, durationMs))
        if (logEntries.size > 20) logEntries.removeAt(logEntries.lastIndex)
        runOnUiThread { renderLog() }
    }

    private fun renderLog() {
        binding.logContainer.removeAllViews()
        logEntries.forEach { entry ->
            binding.logContainer.addView(TextView(this).apply {
                val icon = if (entry.success) "✓" else "✗"
                val dur = if (entry.durationMs > 0) " — ${entry.durationMs}ms" else ""
                text = "$icon ${entry.time}$dur — ${entry.message}"
                setTextColor(color(if (entry.success) R.color.status_success else R.color.status_error))
                textSize = 12f
                typeface = Typeface.MONOSPACE
                setPadding(0, dpToPx(2), 0, dpToPx(2))
            })
        }
    }

    // ── Certificate Info ─────────────────────────────────

    private fun showCertInfo(hostResponse: String) {
        runOnUiThread {
            binding.certInfoCard.visibility = View.VISIBLE

            val sb = StringBuilder()

            // Config API sertifika bilgisi
            sb.appendLine("── Config API ──")
            sb.appendLine("URL: $configServerUrl")
            val configPins = bootstrapPins.firstOrNull()
            if (configPins != null) {
                sb.appendLine("Pin: sha256/${configPins.sha256.firstOrNull()?.take(24)}...")
            }

            // Client cert bilgisi
            if (PinVault.isEnrolled(this)) {
                sb.appendLine()
                sb.appendLine("── Client Cert ──")
                sb.appendLine("Status: Enrolled ✓")
            }

            // Host sertifika bilgisi (response'dan)
            sb.appendLine()
            sb.appendLine("── Host ──")
            sb.appendLine("URL: $mockServerUrl")
            try {
                val json = org.json.JSONObject(hostResponse)
                val hostname = json.optString("hostname", "?")
                val port = json.optInt("port", 0)
                val mtls = json.optBoolean("mtls", false)
                val serverPin = json.optString("serverCertPin", "?")
                sb.appendLine("Hostname: $hostname:$port")
                sb.appendLine("Mode: ${if (mtls) "mTLS" else "TLS"}")
                sb.appendLine("Pin: sha256/${serverPin.take(24)}...")
            } catch (_: Exception) {
                sb.appendLine("(parse error)")
            }

            binding.tvCertInfo.text = sb.toString().trimEnd()
        }
    }

    // ── Report ───────────────────────────────────────────

    private fun sendReport(success: Boolean, durationMs: Long) {
        scope.launch(Dispatchers.IO) {
            try {
                val version = runCatching { PinVault.currentVersion() }.getOrDefault(0)
                val uri = java.net.URI(mockServerUrl)
                val mockHost = uri.host
                val mockPort = if (uri.port > 0) uri.port else 443
                val isMtlsHost = mockPort == 8444 // demo convention
                val json = """
                    {
                        "hostname": "$mockHost",
                        "port": $mockPort,
                        "hostMode": "${if (isMtlsHost) "mtls" else "tls"}",
                        "configMode": "${if (configServerUrl.contains(":8092")) "mtls" else "tls"}",
                        "status": "${if (success) "healthy" else "pin_mismatch"}",
                        "responseTimeMs": $durationMs,
                        "pinMatched": $success,
                        "pinVersion": $version,
                        "deviceManufacturer": "${android.os.Build.MANUFACTURER}",
                        "deviceModel": "${android.os.Build.MODEL}"
                    }
                """.trimIndent()

                okhttp3.OkHttpClient().newCall(
                    Request.Builder()
                        .url("${MANAGEMENT_URL}api/v1/connection-history/client-report")
                        .post(json.toRequestBody("application/json".toMediaType()))
                        .build()
                ).execute()
            } catch (e: Exception) {
                Timber.w(e, "Failed to send report")
            }
        }
    }

    // ── Helpers ──────────────────────────────────────────

    protected fun showResult(text: String, colorRes: Int) {
        runOnUiThread {
            binding.tvResult.text = text
            binding.tvResult.setTextColor(color(colorRes))
        }
    }

    protected fun color(resId: Int) = ContextCompat.getColor(this, resId)

    private fun dpToPx(dp: Int) = (dp * resources.displayMetrics.density).toInt()

    private fun getDeviceIp(): String {
        return try {
            java.net.NetworkInterface.getNetworkInterfaces()?.toList()
                ?.flatMap { it.inetAddresses.toList() }
                ?.firstOrNull { !it.isLoopbackAddress && it is java.net.Inet4Address }
                ?.hostAddress ?: "N/A"
        } catch (_: Exception) { "N/A" }
    }
}
