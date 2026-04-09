package com.example.sslpinning

import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import io.github.umutcansu.pinvault.model.UpdateResult
import kotlinx.coroutines.*
import okhttp3.Request

/**
 * PinVault kullanim ornegi.
 *
 * Akis:
 *   1. PinVaultConfig ile yapilandirma
 *   2. PinVault.init() ile baslat (stored config varsa yukler, remote'dan gunceller)
 *   3. PinVault.getClient() ile pinned OkHttpClient al
 *   4. PinVault.schedulePeriodicUpdates() ile arka plan guncellemesi planla
 */
class SslPinningExampleActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "PinVault_Example"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        CoroutineScope(Dispatchers.IO).launch {
            try {
                initializePinning()
            } catch (e: Exception) {
                Log.e(TAG, "Pinning baslatilamadi", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        this@SslPinningExampleActivity,
                        "SSL Pinning hatasi: ${e.message}",
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private suspend fun initializePinning() {
        // ── 1. Configure ────────────────────────────────────────────────────
        val config = PinVaultConfig.Builder("https://api.example.com/")
            .bootstrapPins(
                listOf(
                    HostPin(
                        hostname = "api.example.com",
                        sha256 = listOf(
                            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // primary
                            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="  // backup
                        )
                    )
                )
            )
            .updateIntervalHours(6)
            .maxRetryCount(3)
            .build()

        // ── 2. Initialize ───────────────────────────────────────────────────
        // Loads stored config if available, then fetches latest from backend.
        // Bootstrap pins protect the initial config fetch against MITM.
        val result = PinVault.init(applicationContext, config)

        when (result) {
            is InitResult.Ready -> {
                Log.d(TAG, "PinVault ready — version ${result.version}")
            }

            is InitResult.Failed -> {
                Log.e(TAG, "PinVault init failed: ${result.reason}", result.exception)
                return
            }
        }

        // ── 3. Schedule background updates ──────────────────────────────────
        PinVault.schedulePeriodicUpdates()

        // Optional: listen for background update results
        PinVault.setOnUpdateListener { updateResult ->
            when (updateResult) {
                is UpdateResult.Updated ->
                    Log.d(TAG, "Pins updated to v${updateResult.newVersion}")

                is UpdateResult.AlreadyCurrent ->
                    Log.d(TAG, "Pins already current")

                is UpdateResult.Failed ->
                    Log.e(TAG, "Background update failed: ${updateResult.reason}")
            }
        }

        // ── 4. Make API calls with the pinned client ────────────────────────
        // Pin mismatch triggers automatic recovery (update + retry).
        makeApiCall()
    }

    private fun makeApiCall() {
        val client = PinVault.getClient()

        try {
            val request = Request.Builder()
                .url("https://api.example.com/data")
                .build()
            val response = client.newCall(request).execute()
            Log.d(TAG, "API response: ${response.code}")
        } catch (e: Exception) {
            Log.e(TAG, "API call failed", e)
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// mTLS Ornegi — Karsilikli sertifika dogrulamasi gerektiren hostlar icin
// ══════════════════════════════════════════════════════════════════════════════

class MtlsExampleActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        CoroutineScope(Dispatchers.IO).launch {
            // mTLS config: client cert P12 dogrudan yukleme
            val config = PinVaultConfig.Builder("https://secure.example.com/")
                .bootstrapPins(
                    listOf(
                        HostPin(
                            hostname = "secure.example.com",
                            sha256 = listOf("hash1...", "hash2..."),
                            mtls = true
                        )
                    )
                )
                .clientKeystore(loadP12FromAssets(), "keystorePassword")
                .build()

            val result = PinVault.init(applicationContext, config)
            if (result is InitResult.Ready) {
                val client = PinVault.getClient()
                // Client automatically sends certificate during TLS handshake
            }
        }
    }

    private fun loadP12FromAssets(): ByteArray {
        return assets.open("client.p12").readBytes()
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Enrollment Ornegi — Sunucudan otomatik sertifika alma
// ══════════════════════════════════════════════════════════════════════════════

class EnrollmentExampleActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        CoroutineScope(Dispatchers.IO).launch {
            val config = PinVaultConfig.Builder("https://api.example.com/")
                .bootstrapPins(
                    listOf(
                        HostPin("api.example.com", listOf("hash1...", "hash2..."))
                    )
                )
                .build()

            val result = PinVault.init(applicationContext, config)
            if (result !is InitResult.Ready) return@launch

            // Token-based enrollment
            if (!PinVault.isEnrolled(applicationContext)) {
                val enrolled = PinVault.enroll(applicationContext, token = "one-time-token")
                Log.d("Enrollment", if (enrolled) "Enrolled" else "Failed")
            }

            // Or automatic enrollment (uses device ID)
            // val enrolled = PinVault.autoEnroll(applicationContext)
        }
    }
}
