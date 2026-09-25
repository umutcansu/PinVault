plugins {
    kotlin("jvm") version "2.1.0"
    kotlin("plugin.serialization") version "2.1.0"
    application
}

application {
    mainClass.set("com.example.pinvault.server.MainKt")
}

repositories {
    mavenCentral()
}

dependencies {
    // Ktor server
    implementation("io.ktor:ktor-server-core:3.0.3")
    implementation("io.ktor:ktor-server-netty:3.0.3")
    implementation("io.ktor:ktor-server-content-negotiation:3.0.3")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.0.3")
    implementation("io.ktor:ktor-server-status-pages:3.0.3")
    implementation("io.ktor:ktor-server-call-logging:3.0.3")
    implementation("io.ktor:ktor-server-default-headers:3.0.3")
    // Ktor 3.0.3 brings Netty 4.1.116, which has known advisories (HTTP/2 resets,
    // request smuggling, SNI handling): the newest 4.1 patch, same line as Ktor's.
    implementation(platform("io.netty:netty-bom:4.1.138.Final"))

    // Logging
    implementation("ch.qos.logback:logback-classic:1.5.38")

    // Kotlinx serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    // SQLite + Flyway migration
    implementation("org.xerial:sqlite-jdbc:3.45.1.0")
    implementation("org.flywaydb:flyway-core:12.3.0")
    implementation("org.flywaydb:flyway-database-nc-sqlite:12.3.0")
    // Flyway 12.3 brings Jackson 3.1.0 (databind/core advisories): the newest 3.1 patch.
    implementation(platform("tools.jackson:jackson-bom:3.1.7"))

    // Bouncy Castle (sertifika üretme)
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.86")

    // OkHttp (health check + URL'den sertifika çekme)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Test
    testImplementation("org.jetbrains.kotlin:kotlin-test:2.1.0")
    testImplementation("io.ktor:ktor-server-test-host:3.0.3")
    testImplementation("io.ktor:ktor-client-content-negotiation:3.0.3")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
}

kotlin {
    jvmToolchain(17)
}
