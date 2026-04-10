package com.example.pinvault.server.store

import org.flywaydb.core.Flyway

/**
 * Database migration using Flyway.
 *
 * On existing databases (pre-Flyway), `baselineOnMigrate=true` marks V1 as
 * already applied without executing it. On fresh databases, V1 creates all tables.
 */
object FlywayMigrator {

    fun migrate(dbPath: String) {
        val flyway = Flyway.configure()
            .dataSource("jdbc:sqlite:$dbPath", null, null)
            .locations("classpath:db/migration")
            .baselineOnMigrate(true)
            .baselineVersion("1")
            .load()

        val result = flyway.migrate()
        println("Flyway: ${result.migrationsExecuted} migrations applied (schema version: ${result.targetSchemaVersion})")
    }
}
