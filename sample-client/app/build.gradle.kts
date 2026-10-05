import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Host değerleri (IP, pin'ler, imza anahtarı) derlemede BuildConfig'e gömülür.
// Varsayılan dosya proje kökündeki sample-host.properties; -PsampleHostProps=<yol>
// ile başka bir dosya verilebilir (sample-e2e kendi dosyasını verir).
val sampleHostFile: File = providers.gradleProperty("sampleHostProps").orNull
    ?.let { rootProject.file(it) }
    ?: rootProject.file("sample-host.properties")
val sampleHost = Properties().apply {
    require(sampleHostFile.isFile) { "Host değerleri dosyası yok: $sampleHostFile" }
    sampleHostFile.inputStream().use { load(it) }
}
println("PinVault sample: host değerleri ← $sampleHostFile")

fun hostValue(key: String): String = (sampleHost.getProperty(key) ?: "").trim()

// ── Host değerlerinin denetimi ──────────────────────────────────────────────
// Bu değerler Java kaynak koduna (BuildConfig) yazılır. Dosya başka bir
// betikten ya da CI değişkeninden gelebilir; içine tırnak ya da satır sonu
// sızarsa derlenen koda istenmeyen bir şey girebilir. Her değer beklenen
// biçime uymak zorunda (uymazsa derleme durur), yazılırken de kaçışlanır.
val hostNamePattern = Regex("[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
val portPattern = Regex("[0-9]{1,5}")
val scopePattern = Regex("[A-Za-z0-9._:-]{1,64}")
val pinPattern = Regex("[A-Za-z0-9+/]{43}=")
val pinListPattern = Regex("${pinPattern.pattern}(\\s*,\\s*${pinPattern.pattern})*")
val keyPattern = Regex("[A-Za-z0-9+/]{40,2048}={0,2}")
val keyListPattern = Regex("${keyPattern.pattern}(\\s*,\\s*${keyPattern.pattern})*")
val httpsUrlPattern = Regex("https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?")

fun checkedValue(key: String, pattern: Regex, what: String): String {
    val value = hostValue(key)
    if (value.isNotEmpty() && !pattern.matches(value)) {
        throw GradleException("$sampleHostFile: '$key' beklenen biçimde değil ($what). Değer: '${value.take(60)}'")
    }
    return value
}

/** Java string sabiti: ters bölü ve tırnak kaçışlanır, denetim karakteri kabul edilmez. */
fun javaString(value: String): String {
    if (value.any { it.code < 0x20 || it.code == 0x7f }) {
        throw GradleException("$sampleHostFile: değerlerden birinde denetim karakteri var; BuildConfig'e yazılmadı.")
    }
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
}

// ── Test bayrakları ─────────────────────────────────────────────────────────
// Yalnızca debug ve e2e derlemelerinde anlamlıdır; release derlemesi bunlardan
// biri verilmişse durur (aşağıda releaseGuard).
val diagnosticLogs = providers.gradleProperty("sample.diagnosticLogs").orNull?.toBoolean() ?: false
val e2eScreenshots = providers.gradleProperty("sample.e2eScreenshots").orNull?.toBoolean() ?: false
val targetRequireCaTrust = checkedValue("target.requireCaTrust", Regex("true|false"), "true ya da false") != "false"

// ── Yayın imzası ────────────────────────────────────────────────────────────
// Anahtar deposu ve parolaları depoda DURMAZ. Gradle özelliği (~/.gradle/gradle.properties
// ya da -P) ya da ortam değişkeni olarak verilir; eksikse release derlemesi durur.
fun releaseSetting(property: String, environment: String): String? =
    (providers.gradleProperty(property).orNull ?: providers.environmentVariable(environment).orNull)
        ?.trim()?.takeIf { it.isNotEmpty() }

val releaseStoreFile = releaseSetting("sample.release.storeFile", "SAMPLE_RELEASE_STORE_FILE")
val releaseStorePassword = releaseSetting("sample.release.storePassword", "SAMPLE_RELEASE_STORE_PASSWORD")
val releaseKeyAlias = releaseSetting("sample.release.keyAlias", "SAMPLE_RELEASE_KEY_ALIAS")
val releaseKeyPassword = releaseSetting("sample.release.keyPassword", "SAMPLE_RELEASE_KEY_PASSWORD")
val releaseSigningReady = listOf(releaseStoreFile, releaseStorePassword, releaseKeyAlias, releaseKeyPassword).all { it != null }

android {
    namespace = "com.example.sampleclient"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.example.sampleclient"
        minSdk = 24
        targetSdk = 35
        versionCode = 3
        versionName = "3.0"

        fun field(name: String, key: String, pattern: Regex, what: String) =
            buildConfigField("String", name, javaString(checkedValue(key, pattern, what)))

        field("HOST_IP", "host.ip", hostNamePattern, "IP ya da alan adı")
        field("HOST_HTTPS_PORT", "host.httpsPort", portPattern, "port")
        field("HOST_MTLS_PORT", "host.mtlsPort", portPattern, "port")
        // Sunucudaki Config API kimlikleri (ör. default-tls, sample-mtls): blok imzalı
        // config'in bu kimlik için imzalanmış olmasını ister (serverScope). Boşsa bağlama yok.
        field("HOST_TLS_SCOPE", "host.tlsScope", scopePattern, "Config API kimliği")
        field("HOST_MTLS_SCOPE", "host.mtlsScope", scopePattern, "Config API kimliği")
        field("HOST_BOOTSTRAP_PIN_PRIMARY", "host.bootstrapPinPrimary", pinPattern, "Base64 SHA-256 pin")
        field("HOST_BOOTSTRAP_PIN_BACKUP", "host.bootstrapPinBackup", pinPattern, "Base64 SHA-256 pin")
        field("HOST_SIGNING_PUBLIC_KEY", "host.signingPublicKey", keyPattern, "Base64 public key")
        // İsteğe bağlı imza katmanları (boşsa yalnızca HOST_SIGNING_PUBLIC_KEY):
        // güvenilen bütün imza anahtarları (yedek dahil), kurtarma anahtarları
        // (anahtar seti = döndürme/iptal) ve config başına gereken imza sayısı.
        field("HOST_SIGNING_PUBLIC_KEYS", "host.signingPublicKeys", keyListPattern, "virgülle ayrılmış Base64 public key'ler")
        field("HOST_RECOVERY_PUBLIC_KEYS", "host.recoveryPublicKeys", keyListPattern, "virgülle ayrılmış Base64 public key'ler")
        // Kurtarma kapısı: süresi dolmuş istemci sertifikası mTLS portuna giremez,
        // buradan yenilenir. Pin'ler sunucu CA'sının (yalnızca bu port için).
        field("HOST_RECOVERY_PORT", "host.recoveryPort", portPattern, "port")
        field("HOST_RECOVERY_PINS", "host.recoveryPins", pinListPattern, "virgülle ayrılmış pin'ler")
        // İstemci sertifikalarını imzalayan sunucu CA'sının SPKI pin'i (birden çoksa virgülle:
        // CA değişecekse yenisi de). Kayıtta ve her yenilemede gelen zincir bu CA'nın imzasını
        // taşımalı (clientCaPins). Boşsa ilk zincire güvenilir, yenileme önceki CA'yı ister.
        field("HOST_CLIENT_CA_PINS", "host.clientCaPin", pinListPattern, "virgülle ayrılmış pin'ler")
        buildConfigField(
            "int", "HOST_REQUIRED_SIGNATURES",
            checkedValue("host.requiredSignatures", Regex("[1-9]"), "1-9 arası sayı").ifEmpty { "1" }
        )
        field("TARGET_HOST", "target.host", hostNamePattern, "alan adı")
        field("TARGET_PINS", "target.pins", pinListPattern, "virgülle ayrılmış pin'ler")
        // Hedefin sertifikası herkesin güvendiği bir CA'dan mı (www.example.com
        // gibi)? Öyleyse uygulama requireCaTrust ister: pin'i tutan ama sistemin
        // CA'larının onaylamadığı sertifika reddedilir, yani config imza anahtarı
        // çalınsa bile o host için sahte sertifika pinlenemez. Yalnızca açıkça
        // "false" yazılırsa kapanır (self-signed / kurum içi CA'lı hedef); release
        // derlemesi "false" ile derlenmez.
        buildConfigField("boolean", "TARGET_REQUIRE_CA_TRUST", targetRequireCaTrust.toString())
        field("MOCK_TLS_HOST", "mock.tlsHost", hostNamePattern, "alan adı")
        field("MOCK_TLS_PORT", "mock.tlsPort", portPattern, "port")
        field("MOCK_MTLS_HOST", "mock.mtlsHost", hostNamePattern, "alan adı")
        field("MOCK_MTLS_PORT", "mock.mtlsPort", portPattern, "port")
        field("CUSTOM_BASE_URL", "custom.baseUrl", httpsUrlPattern, "https:// ile başlayan adres")
        field("CUSTOM_BOOTSTRAP_PINS", "custom.bootstrapPins", pinListPattern, "virgülle ayrılmış pin'ler")
        field("CUSTOM_SIGNING_PUBLIC_KEY", "custom.signingPublicKey", keyPattern, "Base64 public key")
    }

    buildFeatures {
        // BuildConfig.DEBUG, TEST_CONTROLS ve yukarıdaki host alanları için.
        buildConfig = true
    }

    signingConfigs {
        if (releaseSigningReady) {
            create("release") {
                storeFile = file(releaseStoreFile!!)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    // Üç derleme türü:
    //   debug   : geliştirme. Test kontrolleri açık (TEST_CONTROLS = true).
    //   e2e     : release'in aynısı (R8, aynı keep kuralları, aynı applicationId)
    //             + test kontrolleri, debug anahtarıyla imzalı. Uçtan uca testler
    //             bunu kurar; önceki sample sürümünün üstüne kurulabilir (U01).
    //   release : telefona/mağazaya giden derleme. Test kontrolü yok, gerçek imza
    //             anahtarı şart, test bayraklarıyla derlenmez.
    buildTypes {
        getByName("debug") {
            buildConfigField("boolean", "TEST_CONTROLS", "true")
            // -Psample.diagnosticLogs=true: PinVault teşhis log'ları (debug'da zaten açık).
            buildConfigField("boolean", "DIAGNOSTIC_LOGS", diagnosticLogs.toString())
            // -Psample.e2eScreenshots=true: ekranlar FLAG_SECURE almaz (kanıt görüntüleri).
            buildConfigField("boolean", "E2E_SCREENSHOTS", e2eScreenshots.toString())
        }
        getByName("release") {
            // Gerçek uygulamalar gibi R8 ile küçültülür: kütüphanenin R8 kuralları
            // her sürümde bu derlemeyle sınanır.
            isMinifyEnabled = true
            isShrinkResources = true
            // Gerçek imza anahtarı (yukarıdaki sample.release.* / SAMPLE_RELEASE_*).
            // Yoksa null kalır ve releaseGuard derlemeyi açık bir mesajla durdurur;
            // debug anahtarına ASLA düşülmez.
            signingConfig = signingConfigs.findByName("release")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
                // Yalnızca release: Log.d/v/i ve kütüphanenin teşhis log çağrıları silinir.
                "proguard-release.pro"
            )
            buildConfigField("boolean", "TEST_CONTROLS", "false")
            buildConfigField("boolean", "DIAGNOSTIC_LOGS", "false")
            buildConfigField("boolean", "E2E_SCREENSHOTS", "false")
        }
        create("e2e") {
            initWith(getByName("release"))
            matchingFallbacks += listOf("release")
            signingConfig = signingConfigs.getByName("debug")
            // Release ile aynı keep kuralları; tek fark log'ların silinmemesi
            // (senaryolar uygulamayı logcat'ten izler).
            proguardFiles.clear()
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            buildConfigField("boolean", "TEST_CONTROLS", "true")
            buildConfigField("boolean", "DIAGNOSTIC_LOGS", diagnosticLogs.toString())
            buildConfigField("boolean", "E2E_SCREENSHOTS", e2eScreenshots.toString())
        }
    }

    // Test kontrolleri (Ayarlar ve Depolama ekranları, mod değiştirme, elle P12,
    // otomatik kayıt, `mode` intent eki) ayrı bir kaynak klasöründe durur ve
    // yalnızca debug ile e2e derlemelerine girer. Release derlemesi onların
    // yerine src/release altındaki boş karşılığı (TestControls) alır: o ekranlar
    // ve kod yolları release APK'sında hiç yoktur.
    sourceSets {
        listOf("debug", "e2e").forEach { type ->
            getByName(type) {
                java.srcDir("src/testControls/java")
                kotlin.srcDir("src/testControls/java")
                res.srcDir("src/testControls/res")
                manifest.srcFile("src/testControls/AndroidManifest.xml")
            }
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

// ── Release kapısı ──────────────────────────────────────────────────────────
// Release türünün her görevi preReleaseBuild'e bağlıdır; koşullar tutmuyorsa
// derleme orada, ne yapılacağını söyleyerek durur.
tasks.matching { it.name == "preReleaseBuild" }.configureEach {
    doFirst {
        val problems = mutableListOf<String>()
        if (!releaseSigningReady) {
            problems += """
                |Yayın imza anahtarı verilmedi. Release derlemesi debug anahtarıyla imzalanmaz.
                |  Gradle özelliği (~/.gradle/gradle.properties ya da -P…) ya da ortam değişkeni olarak ver:
                |    sample.release.storeFile      / SAMPLE_RELEASE_STORE_FILE       anahtar deposunun yolu
                |    sample.release.storePassword  / SAMPLE_RELEASE_STORE_PASSWORD
                |    sample.release.keyAlias       / SAMPLE_RELEASE_KEY_ALIAS
                |    sample.release.keyPassword    / SAMPLE_RELEASE_KEY_PASSWORD
                |  Bu değerleri depoya yazma. Uçtan uca testler için: ./gradlew :app:assembleE2e
                """.trimMargin()
        } else if (!file(releaseStoreFile!!).isFile) {
            problems += "Yayın anahtar deposu bulunamadı: ${file(releaseStoreFile).absolutePath}"
        }
        if (diagnosticLogs) {
            problems += "-Psample.diagnosticLogs=true bir test bayrağıdır; release derlemesinde kullanılamaz (assembleE2e kullan)."
        }
        if (e2eScreenshots) {
            problems += "-Psample.e2eScreenshots=true bir test bayrağıdır; release derlemesinde kullanılamaz (assembleE2e kullan)."
        }
        if (!targetRequireCaTrust) {
            problems += "$sampleHostFile: target.requireCaTrust=false. Release derlemesi hedefin CA onayını kapatmaz: " +
                "hedefin sertifikası herkesin güvendiği bir CA'dan olmalı (README → \"Yayın derlemesi\")."
        }
        // Host değerleri üretim kurulumundan mı? Depodaki sample-host.properties bir
        // demo dosyasıdır (tek imza, yedek ve kurtarma anahtarı yok); onunla derlenen
        // bir uygulama telefona gitmemeli. Değerler sample-host'un üretim profilinden:
        //   ../sample-host/scripts/client-config.sh --properties > sample-host.properties
        val hostProblems = mutableListOf<String>()
        val required = hostValue("host.requiredSignatures").toIntOrNull() ?: 1
        if (required < 2) {
            hostProblems += "host.requiredSignatures=$required: her config en az 2 ayrı imza taşımalı. Tek imzayla, " +
                "imza anahtarını ele geçiren biri bütün telefonlara sahte pin gönderebilir."
        }
        val trustedKeys = (listOf(hostValue("host.signingPublicKey")) + hostValue("host.signingPublicKeys").split(','))
            .map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        if (trustedKeys.size < required + 1) {
            hostProblems += "host.signingPublicKeys: uygulama ${trustedKeys.size} imza anahtarına güveniyor, $required imza istiyor. " +
                "En az bir yedek anahtar (${required + 1} anahtar) gerekir: bir imzalayıcı kaybolunca telefonlar " +
                "uygulama güncellemesi olmadan config almaya devam etsin."
        }
        if (hostValue("host.recoveryPublicKeys").isEmpty()) {
            hostProblems += "host.recoveryPublicKeys boş: kurtarma anahtarı olmadan çalınan bir imza anahtarı telefonlarda iptal edilemez."
        }
        if (hostValue("host.clientCaPin").isEmpty()) {
            hostProblems += "host.clientCaPin boş: uygulama kayıtta gelen ilk sertifika zincirine güvenirdi; yolu değiştiren biri " +
                "kendi CA'sıyla imzaladığı sertifikayı kurdurabilir."
        }
        if (hostValue("host.tlsScope").isEmpty() || hostValue("host.mtlsScope").isEmpty()) {
            hostProblems += "host.tlsScope / host.mtlsScope boş: uygulama config'in hangi Config API için imzalandığına bakmaz; " +
                "aynı anahtarın başka bir Config API için imzaladığı config de kabul edilir."
        }
        if (hostProblems.isNotEmpty()) {
            problems += "$sampleHostFile üretim değerlerini taşımıyor (demo dosyası mı?):\n" +
                hostProblems.joinToString("\n") { "  - $it" } +
                "\n  Değerleri sample-host'un üretim profilinden üret (README → \"Yayın derlemesi\"):\n" +
                "    ../sample-host/scripts/client-config.sh --properties > sample-host.properties\n" +
                "  Uçtan uca testler ve deneme için: ./gradlew :app:assembleE2e (ya da assembleDebug)."
        }
        if (problems.isNotEmpty()) {
            throw GradleException("Release derlemesi durduruldu:\n\n" + problems.joinToString("\n\n"))
        }
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
