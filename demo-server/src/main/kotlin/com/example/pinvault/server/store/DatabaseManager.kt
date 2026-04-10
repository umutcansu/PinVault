package com.example.pinvault.server.store

import java.sql.Connection
import java.sql.DriverManager

class DatabaseManager(dbPath: String = "pinvault.db") {

    private val url = "jdbc:sqlite:$dbPath"

    init {
        // Run Flyway migrations (creates tables on fresh DB, no-op on existing)
        FlywayMigrator.migrate(dbPath)
    }

    fun connection(): Connection = DriverManager.getConnection(url)
}
