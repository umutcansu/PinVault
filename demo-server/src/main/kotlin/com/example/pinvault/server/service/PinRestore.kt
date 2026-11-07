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
