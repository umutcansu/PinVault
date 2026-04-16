plugins {
    kotlin("jvm") version "2.1.10"
    application
}

application {
    mainClass.set("com.example.mtlshost.MainKt")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.ktor:ktor-server-netty:3.0.3")
    implementation("io.ktor:ktor-server-content-negotiation:3.0.3")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.0.3")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
    implementation("ch.qos.logback:logback-classic:1.4.14")
}

// No jvmToolchain() — use whichever JDK Gradle was started with (Java 11+).
// Bytecode target stays low so the same JAR runs on Java 11, 17, 21, 25...
java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
}
