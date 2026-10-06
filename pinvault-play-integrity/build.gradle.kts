plugins {
    id("com.android.library")
    kotlin("android")
    id("com.vanniktech.maven.publish") version "0.30.0"
}

// PinVault's Play Integrity verdict provider: a separate artifact, so an app
// that does not want Google's Play Integrity client (and its Play Services
// dependency) in its APK does not get it. The core library knows only the
// IntegrityVerdictProvider interface.
android {
    namespace = "io.github.umutcansu.pinvault.playintegrity"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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
}

mavenPublishing {
    publishToMavenCentral(com.vanniktech.maven.publish.SonatypeHost.CENTRAL_PORTAL)
    signAllPublications()

    coordinates("io.github.umutcansu", "pinvault-play-integrity", project.findProperty("VERSION_NAME") as? String ?: "1.0.0")

    pom {
        name.set("PinVault Play Integrity")
        description.set("Play Integrity verdict provider for PinVault attestation: a Google-signed second opinion inside every attestation report.")
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

// Same rule as the core library: 1.9 metadata, so every kotlin-stdlib on the
// graph must be 1.9.x (see pinvault/build.gradle.kts).
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
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.9.25")

    // The interface this module implements (IntegrityVerdictProvider) reaches
    // consumers through this dependency.
    api(project(":pinvault"))
    // Google's Play Integrity client. Brings play-services-tasks (the Task the
    // request returns) and nothing else of Play Services.
    implementation("com.google.android.play:integrity:1.4.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("com.jakewharton.timber:timber:5.0.1")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
}
