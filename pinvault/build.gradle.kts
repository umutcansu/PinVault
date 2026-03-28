plugins {
    id("com.android.library")
    kotlin("android")
    id("maven-publish")
    signing
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
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = "io.github.umutcansu"
                artifactId = "pinvault"
                version = project.findProperty("VERSION_NAME") as? String ?: "1.0.0"

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
        }

        repositories {
            maven {
                name = "OSSRH"
                val releasesUrl = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
                val snapshotsUrl = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
                url = if ((version as String).endsWith("SNAPSHOT")) snapshotsUrl else releasesUrl
                credentials {
                    username = project.findProperty("mavenCentralUsername") as? String ?: System.getenv("OSSRH_USERNAME")
                    password = project.findProperty("mavenCentralPassword") as? String ?: System.getenv("OSSRH_PASSWORD")
                }
            }
        }
    }

    signing {
        sign(publishing.publications["release"])
    }
}

dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
    implementation("com.squareup.retrofit2:retrofit:2.11.0")
    implementation("com.squareup.retrofit2:converter-gson:2.11.0")
    implementation("androidx.work:work-runtime-ktx:2.10.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("com.jakewharton.timber:timber:5.0.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("androidx.core:core-ktx:1.15.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("io.mockk:mockk:1.13.13")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
}