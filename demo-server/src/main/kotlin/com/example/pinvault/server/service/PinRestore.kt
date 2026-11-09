package com.example.pinvault.server.service

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.store.PinSnapshot

/**
 * Bringing back a stored pin set. Devices refuse a version lower than the
 * one they hold, so a restore never re-publishes the old version: it is a
 * new version of every host whose entry differs from what is served now,
 * with the old pins. Hosts the snapshot lacks are removed (a whole-scope
 * restore) and hosts it has but the scope lost come back above their
 * watermark (the store bumps them).
 */
object PinRestore {

    class Refused(message: String) : IllegalArgumentException(message)

    /** The request body is not `{}` or `{"hostname": "…"}`. */
    class BadBody(message: String) : IllegalArgumentException(message)

    /**
     * The host a restore request names, or null for the whole scope. The
     * route and the approval card both read the body with this, as UTF-8
     * bytes. Only an empty body or an object without `hostname` means the
     * whole scope: a body that cannot be read, or a `hostname` that is not a
     * non-empty string, is refused — it used to be read as "the whole scope",
     * the widest thing the request can do.
     */
    fun requestedHost(body: ByteArray): String? {
        val text = body.toString(Charsets.UTF_8).trim()
        if (text.isEmpty()) return null
        val json = try {
            kotlinx.serialization.json.Json.parseToJsonElement(text) as? kotlinx.serialization.json.JsonObject
        } catch (_: Exception) {
            null
        } ?: throw BadBody("The body must be a JSON object: {} for the whole pin set, {\"hostname\": \"…\"} for one host")
        val element = json["hostname"] ?: return null
        val host = (element as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content?.trim()
        if (host.isNullOrEmpty()) throw BadBody("hostname must be a non-empty string (leave it out to restore the whole pin set)")
        return host
    }

    /**
     * The config to save: [snapshot]'s whole set, or, with [hostname], the
     * current set with only that host's entry taken from the snapshot.
     */
    fun plan(current: PinConfig, snapshot: PinSnapshot, hostname: String?): PinConfig {
        val byHost = current.pins.associateBy { it.hostname.lowercase() }
        val wanted: List<HostPin> = if (hostname == null) {
            snapshot.config.pins
        } else {
            val entry = snapshot.config.pins.firstOrNull { it.hostname.equals(hostname, ignoreCase = true) }
                ?: throw Refused("Snapshot ${snapshot.id} has no entry for $hostname")
            val others = current.pins.filterNot { it.hostname.equals(hostname, ignoreCase = true) }
            others + entry
        }
        val pins = wanted.map { pin ->
            val old = byHost[pin.hostname.lowercase()]
            when {
                old == null -> pin.copy(version = 1)   // re-added: the store continues above the watermark
                old.copy(version = 0) != pin.copy(version = 0) -> pin.copy(hostname = old.hostname, version = old.version + 1)
                else -> old
            }
        }
        return if (hostname == null) {
            current.copy(pins = pins, forceUpdate = snapshot.config.forceUpdate, trustRoots = snapshot.config.trustRoots)
        } else {
            current.copy(pins = pins)
        }
    }
}
