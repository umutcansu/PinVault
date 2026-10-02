import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Host değerleri (IP, pin'ler, imza anahtarı) derlemede BuildConfig'e gömülür.
// Varsayılan dosya proje kökündeki sample-host.properties; -PsampleHostProps=<yol>
// ile başka bir dosya verilebilir (SamplePinVaultE2E kendi dosyasını verir).
val sampleHostFile: File = providers.gradleProperty("sampleHostProps").orNull
    ?.let { rootProject.file(it) }
    ?: rootProject.file("sample-host.properties")
val sampleHost = Properties().apply {
    require(sampleHostFile.isFile) { "Host değerleri dosyası yok: $sampleHostFile" }
    sampleHostFile.inputStream().use { load(it) }
}
println("PinVault sample: host değerleri ← $sampleHostFile")

fun hostValue(key: String): String = (sampleHost.getProperty(key) ?: "").trim()

android {
    namespace = "com.example.sampleclient"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.example.sampleclient"
        minSdk = 24
        targetSdk = 35
        versionCode = 3
        versionName = "3.0"

        fun field(name: String, key: String) = buildConfigField("String", name, "\"${hostValue(key)}\"")
        field("HOST_IP", "host.ip")
        field("HOST_HTTP_PORT", "host.httpPort")
        field("HOST_MGMT_TLS_PORT", "host.managementTlsPort")
        field("HOST_HTTPS_PORT", "host.httpsPort")
        field("HOST_MTLS_PORT", "host.mtlsPort")
        field("HOST_BOOTSTRAP_PIN_PRIMARY", "host.bootstrapPinPrimary")
        field("HOST_BOOTSTRAP_PIN_BACKUP", "host.bootstrapPinBackup")
        field("HOST_SIGNING_PUBLIC_KEY", "host.signingPublicKey")
        // İsteğe bağlı imza katmanları (boşsa yalnızca HOST_SIGNING_PUBLIC_KEY):
        // güvenilen bütün imza anahtarları (yedek dahil), kurtarma anahtarları
        // (anahtar seti = döndürme/iptal) ve config başına gereken imza sayısı.
        field("HOST_SIGNING_PUBLIC_KEYS", "host.signingPublicKeys")
        field("HOST_RECOVERY_PUBLIC_KEYS", "host.recoveryPublicKeys")
        // Kurtarma kapısı: süresi dolmuş istemci sertifikası mTLS portuna giremez,
        // buradan yenilenir. Pin'ler sunucu CA'sının (yalnızca bu port için).
        field("HOST_RECOVERY_PORT", "host.recoveryPort")
        field("HOST_RECOVERY_PINS", "host.recoveryPins")
        // -Psample.diagnosticLogs=true: release derlemesinde de PinVault teşhis
        // log'ları açılır (E2E, küçültülmüş derlemeyi log'lardan izler).
        buildConfigField("boolean", "DIAGNOSTIC_LOGS", providers.gradleProperty("sample.diagnosticLogs").orNull?.toBoolean()?.toString() ?: "false")
        buildConfigField("int", "HOST_REQUIRED_SIGNATURES", hostValue("host.requiredSignatures").ifEmpty { "1" })
        field("TARGET_HOST", "target.host")
        field("TARGET_PINS", "target.pins")
        field("MOCK_TLS_HOST", "mock.tlsHost")
        field("MOCK_TLS_PORT", "mock.tlsPort")
        field("MOCK_MTLS_HOST", "mock.mtlsHost")
        field("MOCK_MTLS_PORT", "mock.mtlsPort")
        field("CUSTOM_BASE_URL", "custom.baseUrl")
        field("CUSTOM_BOOTSTRAP_PINS", "custom.bootstrapPins")
        field("CUSTOM_SIGNING_PUBLIC_KEY", "custom.signingPublicKey")
    }

    buildFeatures {
        // BuildConfig.DEBUG ve yukarıdaki host alanları için.
        buildConfig = true
    }

    buildTypes {
        getByName("release") {
            // Gerçek uygulamalar gibi R8 ile küçültülür: kütüphanenin R8 kuralları
            // her sürümde bu derlemeyle sınanır. Örnek olduğu için debug anahtarıyla
            // imzalanır; kendi uygulamanda kendi imza anahtarını kullan.
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig = signingConfigs.getByName("debug")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // Sürüm gradle.properties → pinvault.version. pinvault.localPath doluysa
    // settings.gradle.kts bu bağımlılığı yerel PinVault kaynağıyla değiştirir.
    implementation("io.github.umutcansu:pinvault:${providers.gradleProperty("pinvault.version").get()}")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // PinManagerLite: PinVault'un suspend API'leri için Java'dan senkron köprü.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
