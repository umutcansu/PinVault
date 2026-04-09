package com.example.pinvault.demo

import android.graphics.Bitmap
import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry
import okhttp3.Request
import java.io.File
import java.io.FileOutputStream

/**
 * QA evidence helper — saves screenshots + server state to test app's internal storage.
 * After test run:
 *   adb shell "run-as com.example.pinvault.demo tar cf - qa-evidence/" | tar xf - -C /tmp/
 */
object AllureHelper {

    private val qaDir: File by lazy {
        // /data/local/tmp survives app uninstall and is accessible via adb
        File("/data/local/tmp/pinvault-qa-evidence").also { it.mkdirs() }
    }

    private var stepCounter = 0

    fun screenshot(name: String) {
        try {
            stepCounter++
            val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
            val bitmap = automation.takeScreenshot()
            if (bitmap != null) {
                val file = File(qaDir, "${String.format("%03d", stepCounter)}_${sanitize(name)}.png")
                FileOutputStream(file).use { bitmap.compress(Bitmap.CompressFormat.PNG, 80, it) }
                bitmap.recycle()
            }
        } catch (_: Exception) {}
    }

    fun attachServerStats(label: String = "server_state") {
        try {
            stepCounter++
            val stats = TestConfig.plainClient.newCall(
                Request.Builder().url("${TestConfig.VAULT_API_URL}/stats").build()
            ).execute().body?.string() ?: "{}"
            val dists = TestConfig.plainClient.newCall(
                Request.Builder().url("${TestConfig.VAULT_API_URL}/distributions").build()
            ).execute().body?.string() ?: "[]"
            File(qaDir, "${String.format("%03d", stepCounter)}_${sanitize(label)}.txt")
                .writeText("=== STATS ===\n$stats\n\n=== DISTRIBUTIONS ===\n$dists")
        } catch (_: Exception) {}
    }

    fun attachDeviceInfo() {
        try {
            File(qaDir, "000_device_info.txt").writeText(
                "Device: ${Build.MANUFACTURER} ${Build.MODEL}\nAndroid: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})\n"
            )
        } catch (_: Exception) {}
    }

    fun attachText(name: String, content: String) {
        try {
            stepCounter++
            File(qaDir, "${String.format("%03d", stepCounter)}_${sanitize(name)}.txt").writeText(content)
        } catch (_: Exception) {}
    }

    private fun sanitize(s: String) = s.replace(Regex("[^a-zA-Z0-9_-]"), "_")
}
