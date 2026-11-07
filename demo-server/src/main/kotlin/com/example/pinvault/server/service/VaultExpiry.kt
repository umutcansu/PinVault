package com.example.pinvault.server.service

import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.format.DateTimeParseException

/**
 * The optional date a vault file stops being valid (`expires_at`). Taken as
 * an ISO instant (`2027-01-31T00:00:00Z`) or a date (`2027-01-31`, the end of
 * that day UTC); stored as an instant. The expiry monitor warns ahead of it.
 */
object VaultExpiry {

    class Invalid(message: String) : IllegalArgumentException(message)

    /** The stored form of [raw]; null for blank (no expiry). */
    fun parse(raw: String?): String? {
        val text = raw?.trim().orEmpty()
        if (text.isEmpty()) return null
        val instant = try {
            if (Regex("^\\d{4}-\\d{2}-\\d{2}$").matches(text)) {
                LocalDate.parse(text).atTime(23, 59, 59).toInstant(ZoneOffset.UTC)
            } else {
                Instant.parse(text)
            }
        } catch (e: DateTimeParseException) {
            throw Invalid("expiresAt must be a date (YYYY-MM-DD) or an ISO-8601 instant")
        }
        if (instant.isAfter(Instant.now().plusSeconds(100L * 365 * 86_400))) throw Invalid("expiresAt is more than 100 years away")
        return instant.toString()
    }
}
