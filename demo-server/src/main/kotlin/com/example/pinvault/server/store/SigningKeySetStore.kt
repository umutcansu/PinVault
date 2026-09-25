package com.example.pinvault.server.store

import com.example.pinvault.server.model.SignatureEntry
import com.example.pinvault.server.model.SignedKeySetWire
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

/** A signing-key set as uploaded: see V9__signing_key_sets.sql. */
data class StoredKeySet(
    val version: Int,
    val payload: String,
    val signatures: List<SignatureEntry>,
    val uploadedBy: String,
    val uploadedAt: String
) {
    fun toWire() = SignedKeySetWire(payload, signatures)
}

class SigningKeySetStore(private val db: DatabaseManager) {

    private val json = Json { ignoreUnknownKeys = true }
    private val listSerializer = ListSerializer(SignatureEntry.serializer())

    fun latest(): StoredKeySet? = query("SELECT * FROM signing_key_sets ORDER BY version DESC LIMIT 1").firstOrNull()

    fun all(): List<StoredKeySet> = query("SELECT * FROM signing_key_sets ORDER BY version DESC")

    /** Inserts [set]; false when that version already exists. */
    fun add(set: StoredKeySet): Boolean = db.connection().use { conn ->
        conn.prepareStatement(
            "INSERT OR IGNORE INTO signing_key_sets (version, payload, signatures, uploaded_by, uploaded_at) VALUES (?, ?, ?, ?, ?)"
        ).use { stmt ->
            stmt.setInt(1, set.version)
            stmt.setString(2, set.payload)
            stmt.setString(3, json.encodeToString(listSerializer, set.signatures))
            stmt.setString(4, set.uploadedBy)
            stmt.setString(5, set.uploadedAt)
            stmt.executeUpdate() == 1
        }
    }

    private fun query(sql: String): List<StoredKeySet> = db.connection().use { conn ->
        conn.prepareStatement(sql).use { stmt ->
            val rs = stmt.executeQuery()
            buildList {
                while (rs.next()) add(
                    StoredKeySet(
                        version = rs.getInt("version"),
                        payload = rs.getString("payload"),
                        signatures = json.decodeFromString(listSerializer, rs.getString("signatures")),
                        uploadedBy = rs.getString("uploaded_by"),
                        uploadedAt = rs.getString("uploaded_at")
                    )
                )
            }
        }
    }
}
