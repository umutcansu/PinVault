plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// ── Release guard (security review A-2) ─────────────────────────────────────
// The debug build is a lab tool: it reads the demo-server's UNSIGNED config
// (`?signed=false` + allowUnsigned()), carries a placeholder second bootstrap
// pin and posts its connection reports over plain HTTP to the management port
// (network_security_config in src/debug). None of that goes into a release
// build: release has DEMO_INSECURE_CHANNELS = false, so the app verifies the
// signed config with the key below, pins with the pin below and reports over
// the pinned TLS Config API. The values come from Gradle properties
// (-P… or ~/.gradle/gradle.properties); the build stops (preReleaseBuild) and
// the app refuses to start (DemoReleaseGuard) while one is missing.
//
//   demo.signingPublicKey  demo-server's config-signing public key
//                          (GET /api/v1/signing-key → publicKey; X.509 SPKI, Base64)
//   demo.backupPin         second SPKI SHA-256 pin of the Config API certificate
//                          (its successor, or the server CA) — "sha256/" prefix off
//   demo.tlsScope          optional: Config API id of the TLS listener (default-tls)
//   demo.mtlsScope         optional: Config API id of the mTLS listener (empty = not bound)
//
// Every value is written into Java source (BuildConfig): it must match the
// expected shape or the build stops, and it is escaped when written.
fun demoProperty(name: String): String = providers.gradleProperty(name).orNull?.trim().orEmpty()

val pinPattern = Regex("[A-Za-z0-9+/]{43}=")
val keyPattern = Regex("[A-Za-z0-9+/]{40,2048}={0,2}")
val scopePattern = Regex("[A-Za-z0-9._:-]{1,64}")

fun checkedProperty(name: String, pattern: Regex, what: String): String {
    val value = demoProperty(name)
    if (value.isNotEmpty() && !pattern.matches(value)) {
        throw GradleException("-P$name is not $what. Value: '${value.take(60)}'")
    }
    return value
}

/** Java string literal: backslash and quote escaped, control characters refused. */
fun javaString(value: String): String {
    if (value.any { it.code < 0x20 || it.code == 0x7f }) {
        throw GradleException("A demo.* property contains a control character; not written into BuildConfig.")
    }
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
}

val demoSigningPublicKey = checkedProperty("demo.signingPublicKey", keyPattern, "a Base64 X.509 public key")
val demoBackupPin = checkedProperty("demo.backupPin", pinPattern, "a Base64 SHA-256 pin (43 characters + '=')")
val demoTlsScope = checkedProperty("demo.tlsScope", scopePattern, "a Config API id").ifEmpty { "default-tls" }
val demoMtlsScope = checkedProperty("demo.mtlsScope", scopePattern, "a Config API id")

// Second bootstrap pin of the DEBUG build only. It is not the pin of any
// certificate the demo-server serves: the primary pin (BaseDemoActivity) is
// the one that matches, this one merely keeps the list at two entries. A
// release build never gets it — it needs demo.backupPin.
val placeholderBackupPin = "vXC1UZ8OFlga9Ltwsa2Hyg2lqZkLUE+DbdBPvT3ah3o="

android {
    namespace = "com.example.pinvault.demo"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.example.pinvault.demo"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        testInstrumentationRunnerArguments["clearPackageData"] = "true"

        buildConfigField("String", "DEMO_SIGNING_PUBLIC_KEY", javaString(demoSigningPublicKey))
        buildConfigField("String", "DEMO_TLS_SCOPE", javaString(demoTlsScope))
        buildConfigField("String", "DEMO_MTLS_SCOPE", javaString(demoMtlsScope))
    }

    buildTypes {
        getByName("debug") {
            // Lab shortcuts on: unsigned config endpoint, plain-HTTP report channel
            // (src/debug/res/xml/network_security_config.xml), placeholder backup pin.
            buildConfigField("boolean", "DEMO_INSECURE_CHANNELS", "true")
            buildConfigField("String", "DEMO_BACKUP_PIN", javaString(demoBackupPin.ifEmpty { placeholderBackupPin }))
        }
        release {
            // Shrunk like a real app: the library's consumer R8 rules are what
            // keep its model classes; proguard-rules.pro only strips debug logs.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Lab shortcuts off. No placeholder: an empty pin means "not provided"
            // and DemoReleaseGuard stops the app before PinVault is configured.
            buildConfigField("boolean", "DEMO_INSECURE_CHANNELS", "false")
            buildConfigField("String", "DEMO_BACKUP_PIN", javaString(demoBackupPin))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        viewBinding = true
        // BuildConfig.DEBUG, DEMO_INSECURE_CHANNELS and the demo.* fields above.
        buildConfig = true
    }

    testOptions {
        execution = "ANDROIDX_TEST_ORCHESTRATOR"
        installation {
            installOptions("-g") // grant permissions
        }
    }
}

// A release build without the release values stops here, saying what to pass.
// The app checks the same values again at start-up (DemoReleaseGuard), for a
// build that reached BuildConfig some other way.
tasks.matching { it.name == "preReleaseBuild" }.configureEach {
    doFirst {
        val missing = mutableListOf<String>()
        if (demoSigningPublicKey.isEmpty()) missing += "  -Pdemo.signingPublicKey=<Base64 public key>   (GET http://<server>:8090/api/v1/signing-key → publicKey)"
        if (demoBackupPin.isEmpty()) missing += "  -Pdemo.backupPin=<Base64 SHA-256 pin>           (second SPKI pin of the Config API certificate)"
        if (missing.isNotEmpty()) {
            throw GradleException(
                "demo-app release build stopped: a release verifies the signed config and carries no placeholder pin, " +
                    "so it needs these Gradle properties (-P… or ~/.gradle/gradle.properties):\n" +
                    missing.joinToString("\n") +
                    "\nFor the lab flows (unsigned config, plain-HTTP reports) build debug: ./gradlew :demo-app:assembleDebug"
            )
        }
    }
}

dependencies {
    implementation(project(":pinvault"))

    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("com.jakewharton.timber:timber:5.0.1")
    implementation("androidx.security:security-crypto:1.1.0-alpha06") // audit L-12: encrypted token storage

    // Instrumented tests
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.work:work-runtime-ktx:2.10.0")
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation("androidx.security:security-crypto:1.1.0-alpha06")
    androidTestImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")

    // Allure reporting
    androidTestImplementation("io.qameta.allure:allure-kotlin-android:2.4.0")
    androidTestImplementation("io.qameta.allure:allure-kotlin-commons:2.4.0")
    androidTestImplementation("io.qameta.allure:allure-kotlin-junit4:2.4.0")

    // Test Orchestrator — prevents UiAutomation crashes from killing remaining tests
    androidTestUtil("androidx.test:orchestrator:1.5.1")
}
