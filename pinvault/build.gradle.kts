plugins {
    id("com.android.library")
    kotlin("android")
    id("com.vanniktech.maven.publish") version "0.30.0"
}

android {
    namespace = "io.github.umutcansu.pinvault"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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
        apiVersion = "1.9"
        languageVersion = "1.9"
        freeCompilerArgs += listOf("-Xsuppress-version-warnings")
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

mavenPublishing {
    publishToMavenCentral(com.vanniktech.maven.publish.SonatypeHost.CENTRAL_PORTAL)
    signAllPublications()

    coordinates("io.github.umutcansu", "pinvault", project.findProperty("VERSION_NAME") as? String ?: "1.0.0")

    pom {
        name.set("PinVault")
        description.set("Android library for dynamic SSL certificate pinning with remote config updates, ECDSA signature verification, and encrypted pin storage.")
        url.set("https://github.com/umutcansu/PinVault")

        licenses {
            license {
                name.set("The MIT License")
                url.set("http://www.opensource.org/licenses/mit-license.php")
            }
        }

        developers {
            developer {
                id.set("umutcansu")
                name.set("Umut Cansu")
                email.set("umutcansu@gmail.com")
            }
        }

        scm {
            connection.set("scm:git:git://github.com/umutcansu/PinVault.git")
            developerConnection.set("scm:git:ssh://github.com:umutcansu/PinVault.git")
            url.set("https://github.com/umutcansu/PinVault")
        }
    }
}

// PinVault emits Kotlin 1.9 metadata (see kotlinOptions above), so every
// kotlin-stdlib variant on the resolved graph must also be 1.9.x — otherwise
// consumer Kotlin 1.9.x compilers fail with
// "Unable to read Kotlin metadata due to unsupported metadata version".
configurations.all {
    resolutionStrategy.eachDependency {
        if (requested.group == "org.jetbrains.kotlin" &&
            requested.name.startsWith("kotlin-stdlib")
        ) {
            useVersion("1.9.25")
            because("Match languageVersion=1.9 metadata for consumer compatibility")
        }
    }
}

dependencies {
    // Pin kotlin-stdlib to a 1.9.x release so its bytecode metadata matches
    // PinVault's emitted 1.9 metadata. Auto-injection is disabled via
    // `kotlin.stdlib.default.dependency=false` in root gradle.properties.
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.9.25")

    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
    implementation("com.squareup.retrofit2:retrofit:2.11.0")
    implementation("com.squareup.retrofit2:converter-gson:2.11.0")
    implementation("androidx.work:work-runtime-ktx:2.10.0")
    // 1.1.0-alpha06 chosen over 1.0.0 stable: fixes master key corruption crash on backup restore.
    // The "alpha" label is misleading — this version is widely used in production.
    // See: https://issuetracker.google.com/issues/164901843
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("com.jakewharton.timber:timber:5.0.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("androidx.core:core-ktx:1.15.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("io.mockk:mockk:1.13.13")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    testImplementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("androidx.work:work-testing:2.10.0")

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:rules:1.6.1")
}