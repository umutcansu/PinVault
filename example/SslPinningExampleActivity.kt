package com.example.sslpinning

import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import okhttp3.Request
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.X509TrustManager

// ══════════════════════════════════════════════════════════════════════════════
// Sıfırdan Dinamik SSL Pinning — Tek Dosya Örneği
//
// PinVault'un yaptığını 4 adımda implemente ediyoruz:
//   1. EncryptedSharedPreferences ile pin saklama (PinStore)
//   2. Custom X509ExtendedTrustManager ile pin doğrulama (PinnedClientBuilder)
//   3. Sunucudan dinamik pin çekme (fetchRemotePins)
//   4. Activity'de entegrasyon (onCreate akışı)
// ══════════════════════════════════════════════════════════════════════════════

// ── Data Models ──────────────────────────────────────────────────────────────

data class HostPin(
    val hostname: String,
    val sha256: List<String>   // Base64-encoded SHA-256 of SubjectPublicKeyInfo
)

data class PinConfig(
    val version: Int,
    val pins: List<HostPin>,
    @SerializedName("forceUpdate")
    val forceUpdate: Boolean = false
)

// ── 1. Encrypted Pin Storage ─────────────────────────────────────────────────
// PinVault'taki CertificateConfigStore'un basitleştirilmiş hali.
// AES-256-GCM ile şifreli — root'lu cihazda bile pin'ler okunamaz.

class PinStore(context: android.content.Context) {

    private val prefs by lazy {
        val masterKey = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
        EncryptedSharedPreferences.create(
            "ssl_pins",
            masterKey,
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun save(config: PinConfig) {
        // hostname|hash1,hash2\nhostname2|hash3,hash4
        val data = config.pins.joinToString("\n") { pin ->
            "${pin.hostname}|${pin.sha256.joinToString(",")}"
        }
        prefs.edit()
            .putInt("version", config.version)
            .putString("pins", data)
            .apply()
    }

    fun load(): PinConfig? {
        val version = prefs.getInt("version", 0)
        if (version == 0) return null

        val data = prefs.getString("pins", null) ?: return null
        val pins = data.split("\n").mapNotNull { line ->
            val parts = line.split("|", limit = 2)
            if (parts.size == 2) {
                val hashes = parts[1].split(",").filter { it.isNotBlank() }
                if (hashes.size >= 2) HostPin(parts[0], hashes) else null
            } else null
        }
        if (pins.isEmpty()) return null
        return PinConfig(version, pins)
    }

    fun clear() = prefs.edit().clear().apply()
}

// ── 2. Pinned OkHttpClient Builder ───────────────────────────────────────────
// PinVault'taki DynamicSSLManager'ın basitleştirilmiş hali.
// OkHttp CertificatePinner yerine custom TrustManager kullanıyoruz çünkü
// Android/Conscrypt'te SSLSession.getPeerCertificates() boş dönebiliyor.

object PinnedClientBuilder {

    /**
     * Verilen pin hash'leriyle korunan bir OkHttpClient döner.
     * TLS handshake sırasında Conscrypt, checkServerTrusted()'ı çağırır →
     * leaf sertifikanın public key SHA-256'sı kabul edilen hash'lerle karşılaştırılır.
     */
    fun build(pins: List<HostPin>): OkHttpClient {
        val acceptedHashes = pins.flatMap { it.sha256 }.toSet()
        val trustManager = createTrustManager(acceptedHashes)

        val sslContext = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(trustManager), null)
        }

        return OkHttpClient.Builder()
            .sslSocketFactory(sslContext.socketFactory, trustManager)
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()
    }

    private fun createTrustManager(acceptedHashes: Set<String>): X509TrustManager {
        return object : X509ExtendedTrustManager() {

            // Conscrypt handshake sırasında bu 3 overload'dan birini çağırır
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, socket: java.net.Socket) = verifyPin(chain)
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine) = verifyPin(chain)
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = verifyPin(chain)

            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, socket: java.net.Socket) = Unit
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine) = Unit
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

            private fun verifyPin(chain: Array<X509Certificate>) {
                if (chain.isEmpty()) throw CertificateException("Sertifika zinciri boş")

                val leaf = chain[0]

                // 1) Pin listesi boşsa bağlantıyı reddet
                if (acceptedHashes.isEmpty()) {
                    throw CertificateException("Pin listesi boş — bağlantı reddedildi")
                }

                // 2) Sertifika süre kontrolü
                try {
                    leaf.checkValidity()
                } catch (e: Exception) {
                    throw CertificateException("Sertifika süresi dolmuş: ${e.message}")
                }

                // 3) Public key'in SHA-256 hash'ini hesapla ve karşılaştır
                val hash = sha256Base64(leaf.publicKey.encoded)
                if (hash !in acceptedHashes) {
                    throw CertificateException(
                        "Pin uyuşmuyor!\n" +
                        "  Sertifika hash: sha256/$hash\n" +
                        "  Kabul edilen:   ${acceptedHashes.joinToString { "sha256/$it" }}"
                    )
                }

                Log.d("SSL_PIN", "Pin doğrulandı: sha256/${hash.take(16)}...")
            }
        }
    }

    private fun sha256Base64(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return Base64.encodeToString(digest, Base64.NO_WRAP)
    }
}

// ── 3. Activity Entegrasyonu ─────────────────────────────────────────────────

class SslPinningExampleActivity : AppCompatActivity() {

    private lateinit var pinStore: PinStore

    // APK'ya gömülü bootstrap pin'ler — ilk config fetch'ini korur
    private val bootstrapPins = listOf(
        HostPin(
            hostname = "api.example.com",
            sha256 = listOf(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // primary
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="  // backup
            )
        )
    )

    // Sunucudaki pin config endpoint'i
    private val configUrl = "https://api.example.com/ssl/pins.json"

    // Mevcut pinned client (dinamik olarak güncellenir)
    @Volatile
    private var pinnedClient: OkHttpClient? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pinStore = PinStore(applicationContext)

        CoroutineScope(Dispatchers.IO).launch {
            try {
                initializePinning()
            } catch (e: Exception) {
                Log.e("SSL_PIN", "Pinning başlatılamadı", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@SslPinningExampleActivity,
                        "SSL Pinning hatası: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    /**
     * Tam akış:
     * 1. Stored pin'leri yükle (varsa hemen kullan)
     * 2. Bootstrap client ile sunucudan güncel pin'leri çek
     * 3. Yeni pin'lerle asıl client'ı oluştur
     * 4. API çağrısı yap
     */
    private suspend fun initializePinning() {
        // ── Adım 1: Stored config varsa yükle ───────────────────────────────
        val storedConfig = pinStore.load()
        if (storedConfig != null) {
            Log.d("SSL_PIN", "Kayıtlı config yüklendi — v${storedConfig.version}")
            pinnedClient = PinnedClientBuilder.build(storedConfig.pins)
        }

        // ── Adım 2: Bootstrap client ile güncel pin'leri çek ────────────────
        // Bootstrap pin'ler APK'da gömülü → ilk fetch bile MITM'e karşı korumalı
        val bootstrapClient = PinnedClientBuilder.build(bootstrapPins)
        val remoteConfig = fetchRemotePins(bootstrapClient)

        if (remoteConfig != null) {
            // ── Adım 3: Yeni pin'leri kaydet ve client'ı güncelle ───────────
            pinStore.save(remoteConfig)
            pinnedClient = PinnedClientBuilder.build(remoteConfig.pins)
            Log.d("SSL_PIN", "Pin'ler güncellendi — v${remoteConfig.version}")
        } else if (storedConfig == null) {
            // Ne stored ne de remote config var → bootstrap ile devam et
            pinnedClient = bootstrapClient
            Log.w("SSL_PIN", "Config alınamadı — bootstrap pin'lerle devam ediliyor")
        }

        // ── Adım 4: Artık pinnedClient kullanıma hazır ─────────────────────
        makeApiCall()
    }

    /**
     * Sunucudan pin config JSON'ı çeker.
     *
     * Beklenen JSON formatı:
     * {
     *   "version": 3,
     *   "pins": [
     *     { "hostname": "api.example.com", "sha256": ["hash1...", "hash2..."] }
     *   ],
     *   "forceUpdate": false
     * }
     */
    private fun fetchRemotePins(client: OkHttpClient): PinConfig? {
        return try {
            val request = Request.Builder().url(configUrl).build()
            val response = client.newCall(request).execute()

            if (!response.isSuccessful) {
                Log.w("SSL_PIN", "Config fetch başarısız — HTTP ${response.code}")
                return null
            }

            val body = response.body?.string() ?: return null
            val config = Gson().fromJson(body, PinConfig::class.java)

            // Minimum 2 pin zorunlu (primary + backup rotation için)
            config.pins.forEach { pin ->
                require(pin.sha256.size >= 2) {
                    "${pin.hostname} için en az 2 pin gerekli"
                }
            }

            config
        } catch (e: Exception) {
            Log.e("SSL_PIN", "Config fetch hatası", e)
            null
        }
    }

    /**
     * Pinned client ile güvenli API çağrısı.
     * Pin uyuşmazlığında CertificateException fırlar → bağlantı otomatik kesilir.
     */
    private fun makeApiCall() {
        val client = pinnedClient ?: run {
            Log.e("SSL_PIN", "Client henüz hazır değil")
            return
        }

        try {
            val request = Request.Builder()
                .url("https://api.example.com/data")
                .build()
            val response = client.newCall(request).execute()
            Log.d("SSL_PIN", "API yanıtı: ${response.code}")
        } catch (e: Exception) {
            // javax.net.ssl.SSLHandshakeException → pin uyuşmadı, MITM olabilir!
            Log.e("SSL_PIN", "API çağrısı başarısız — olası MITM saldırısı?", e)
        }
    }
}
