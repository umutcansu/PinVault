package com.example.pinvault.server.service

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * What a host ACL write (`PUT …/devices/{id}/host-acl`, `PUT …/default-host-acl`)
 * does to the list it replaces. The two handlers and the approval card
 * ([ChangeDescriber]) all plan with this, so a second admin reads exactly the
 * names the handler will grant and take away — every one of them — and no
 * handler stores a name the card's rules would have refused.
 */
class HostAclChange private constructor(
    /** The list after the change. */
    val desired: Set<String>,
    /** Names the change grants, sorted. */
    val added: List<String>,
    /** Names the change takes away, sorted. */
    val removed: List<String>
) {
    val isEmpty: Boolean get() = added.isEmpty() && removed.isEmpty()

    /** The body is not `{"hostnames": [...]}` with valid host names; [message] says what is wrong. */
    class BadBody(message: String) : IllegalArgumentException(message)

    companion object {
        /** As many names as a config may carry hosts: an ACL names hosts of the scope. */
        const val MAX_NAMES = PinConfigRules.MAX_HOSTS

        /**
         * The names a body asks for. Every element must be a host name the
         * server would accept as a pin entry ([HostPatternRules]): the list
         * used to be stored as sent — any string, any length, any number.
         */
        fun requested(body: JsonObject?): Set<String> {
            val array = body?.get("hostnames") as? JsonArray ?: throw BadBody("'hostnames' string array required")
            if (array.size > MAX_NAMES) throw BadBody("hostnames: at most $MAX_NAMES names")
            return array.mapTo(LinkedHashSet()) { element ->
                val name = (element as? JsonPrimitive)?.takeIf { it.isString }?.content
                    ?: throw BadBody("'hostnames' string array required")
                HostPatternRules.error(name)?.let { throw BadBody("hostnames: ${ApprovalService.plainText(it, 200)}") }
                name
            }
        }

        /** [body] laid over [current] (the stored list). Throws [BadBody]. */
        fun plan(current: Collection<String>, body: JsonObject?): HostAclChange {
            val desired = requested(body)
            val before = current.toSet()
            return HostAclChange(desired, (desired - before).sorted(), (before - desired).sorted())
        }
    }
}
