package com.example.pinvault.server.service

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.store.AuditEntry
import com.example.pinvault.server.store.AuditLogStore
import kotlinx.coroutines.asContextElement
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.time.Instant

/**
 * The admin call currently being served, for code that runs deep inside it
 * (the pin store's save listener) and has no `ApplicationCall` at hand.
 * Carried as a coroutine context element, so it follows the call across
 * threads; outside any admin call the actor is `system`.
 */
object AuditContext {
    class Scope(val actor: String, val ip: String) {
        /** Set once a specific entry (e.g. a pin diff) was written for this call. */
        @Volatile
        var recorded: Boolean = false
    }

    private val current = ThreadLocal<Scope?>()

    fun element(scope: Scope) = current.asContextElement(scope)

    fun scope(): Scope? = current.get()

    fun actor(): String = current.get()?.actor ?: "system"
}

/**
 * Writes the audit log and, for the events it is configured for, notifies the
 * webhook. Every security-relevant change passes through here.
 */
class AuditLog(private val store: AuditLogStore, val notifier: WebhookNotifier?) {

    fun record(
        action: String,
        summary: String,
        configApiId: String = "",
        target: String = "",
        detail: JsonElement? = null,
        actor: String = AuditContext.actor(),
        ip: String = AuditContext.scope()?.ip ?: "",
        notify: Boolean = action != HTTP_ACTION
    ): AuditEntry {
        val entry = store.append(
            at = Instant.now().toString(),
            actor = actor,
            action = action,
            configApiId = configApiId,
            target = target,
            summary = summary,
            detail = detail?.toString() ?: "",
            sourceIp = ip
        )
        if (action != HTTP_ACTION) AuditContext.scope()?.recorded = true
        if (notify) notifier?.notify(action, actor, summary, configApiId, target, entry.id, detail, entry.hash)
        return entry
    }

    /**
     * Records what changed in a Config API's pins, if anything did. Called by
     * the pin store after every save, so it sees every route that writes pins.
     */
    fun recordPinChange(configApiId: String, before: PinConfig?, after: PinConfig) {
        val diff = PinDiff.of(before, after)
        if (diff.isEmpty) return
        record(
            action = "pins_changed",
            summary = diff.summary(),
            configApiId = configApiId,
            target = diff.hosts().joinToString(","),
            detail = diff.toJson()
        )
    }

    companion object {
        /** Generic "an admin endpoint was called" entries; not pushed to the webhook. */
        const val HTTP_ACTION = "http"
    }
}

/** What changed between two pin configs of one scope. */
class PinDiff private constructor(
    val added: List<HostPin>,
    val removed: List<HostPin>,
    val changed: List<Pair<HostPin, HostPin>>,
    val globalForce: Pair<Boolean, Boolean>?
) {
    val isEmpty: Boolean get() = added.isEmpty() && removed.isEmpty() && changed.isEmpty() && globalForce == null

    fun hosts(): List<String> = (added + removed).map { it.hostname } + changed.map { it.second.hostname }

    fun summary(): String {
        val parts = mutableListOf<String>()
        added.forEach { parts += "${it.hostname} added (${it.sha256.size} pins)" }
        removed.forEach { parts += "${it.hostname} removed" }
        changed.forEach { (old, new) ->
            val what = buildList {
                if (old.sha256.toSet() != new.sha256.toSet()) add("pins v${old.version}→v${new.version}")
                if (old.forceUpdate != new.forceUpdate) add("force ${if (new.forceUpdate) "on" else "off"}")
                if (old.mtls != new.mtls) add("mTLS ${if (new.mtls) "on" else "off"}")
                if (old.clientCertVersion != new.clientCertVersion) add("client cert v${new.clientCertVersion}")
                if (isEmpty() && old.version != new.version) add("v${old.version}→v${new.version}")
            }
            parts += "${new.hostname}: ${what.joinToString(", ")}"
        }
        globalForce?.let { parts += "global force ${if (it.second) "on" else "off"}" }
        return parts.joinToString("; ")
    }

    fun toJson(): JsonObject = buildJsonObject {
        putJsonArray("added") { added.forEach { add(pinJson(it)) } }
        putJsonArray("removed") { removed.forEach { add(pinJson(it)) } }
        putJsonArray("changed") {
            changed.forEach { (old, new) ->
                add(buildJsonObject {
                    put("hostname", new.hostname)
                    put("from", pinJson(old))
                    put("to", pinJson(new))
                })
            }
        }
        globalForce?.let { putJsonObject("forceUpdate") { put("from", it.first); put("to", it.second) } }
    }

    private fun pinJson(pin: HostPin) = buildJsonObject {
        put("hostname", pin.hostname)
        put("version", pin.version)
        put("sha256", buildJsonArray { pin.sha256.forEach { add(it) } })
        put("forceUpdate", pin.forceUpdate)
        put("mtls", pin.mtls)
        pin.clientCertVersion?.let { put("clientCertVersion", it) }
    }

    companion object {
        fun of(before: PinConfig?, after: PinConfig): PinDiff {
            val old = before?.pins.orEmpty().associateBy { it.hostname }
            val new = after.pins.associateBy { it.hostname }
            val changed = new.values.mapNotNull { pin ->
                val prev = old[pin.hostname] ?: return@mapNotNull null
                val same = prev.sha256.toSet() == pin.sha256.toSet() && prev.version == pin.version &&
                    prev.forceUpdate == pin.forceUpdate && prev.mtls == pin.mtls &&
                    prev.clientCertVersion == pin.clientCertVersion
                if (same) null else prev to pin
            }
            val beforeForce = before?.forceUpdate ?: false
            return PinDiff(
                added = new.values.filter { it.hostname !in old },
                removed = old.values.filter { it.hostname !in new },
                changed = changed,
                globalForce = if (beforeForce != after.forceUpdate) beforeForce to after.forceUpdate else null
            )
        }
    }
}
