package io.github.umutcansu.pinvault.crypto

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import io.github.umutcansu.pinvault.model.ConfigViewMismatchException
import timber.log.Timber

/**
 * Binds a signed pin config to the request it answers (M6; wire format in
 * SERVER_IMPLEMENTATION_GUIDE.md §3, `view`).
 *
 * A server signs narrowed views of a scope's config — `?hosts=` from
 * `wantPinsFor(...)`, a device's host ACL from `X-Device-Id`, the config
 * inside an attestation answer — and writes into the signed payload what
 * narrowed it:
 *
 * ```json
 * "view": {"hosts": ["api.example.com", "cdn.example.com"], "deviceId": "a1b2c3"}
 * ```
 *
 * `hosts` is the REQUESTED set in canonical form ([canonicalHosts]),
 * `deviceId` the device id the request claimed; either may be absent, and a
 * full (un-narrowed) config carries no `view` at all.
 *
 * Decision ([check]), made from the block's own request alone:
 *
 * | request                       | payload `view`                         | outcome |
 * |-------------------------------|----------------------------------------|---------|
 * | full (no `wantPinsFor`)       | absent                                 | accept  |
 * | full                          | present (any)                          | REFUSE  |
 * | scoped (hosts H, device D)    | `hosts` = canonical(H), `deviceId` = D (absent when D is null) | accept |
 * | scoped                        | other hosts, other/missing/extra device id, unknown key, malformed | REFUSE |
 * | scoped                        | absent                                 | accept (a full view: a server before 2.9.0, or the full config) |
 *
 * The last row: a 2.9.0+ server never signs a narrowed view without the
 * field, so a view-less payload from it is the full config — more pins than
 * the ACL would give, never fewer (the low-harm direction). Refusing it would
 * cut scoped apps off older servers and custom backends that do not write the
 * field yet. Against such a server a scoped block has the pre-2.9.0
 * guarantee, no more.
 */
internal object ConfigViewBinding {

    /** The payload field. */
    const val FIELD = "view"

    /**
     * What a scoped request asked for: the canonical host set and the device
     * ids its view may name (one for a fetch; for a stored view also the form
     * an attestation request uses, which may differ for a device without a
     * usable ANDROID_ID). `null` in [deviceIds] = "no device id was sent".
     * A full request is represented by no [Expected] at all (null).
     */
    class Expected(hosts: List<String>, val deviceIds: Set<String?>) {
        val hosts: List<String> = canonicalHosts(hosts)

        override fun toString(): String =
            "hosts=" + hosts.joinToString(",", "[", "]") + ", deviceId=" +
                deviceIds.joinToString("|") { it?.let { id -> "'${id.take(64)}'" } ?: "(none)" }
    }

    /**
     * The request a block makes: null (full) without `wantPinsFor`, else its
     * canonical set with [deviceIds].
     */
    fun expected(wantPinsFor: List<String>, vararg deviceIds: String?): Expected? =
        if (wantPinsFor.isEmpty()) null else Expected(wantPinsFor, deviceIds.toSet())

    /**
     * The canonical host set: every entry split at `,` (the server reads
     * `?hosts=` that way), ASCII whitespace trimmed, empty names dropped,
     * ASCII `A-Z` lower-cased (nothing else changes: no locale rules),
     * duplicates removed, sorted by Unicode code point.
     */
    fun canonicalHosts(hosts: List<String>): List<String> =
        hosts.asSequence()
            .flatMap { it.split(',') }
            .map { it.trim(' ', '\t', '\n', '\r', '\u000B', '\u000C') }
            .filter { it.isNotEmpty() }
            .map { name -> buildString(name.length) { name.forEach { c -> append(if (c in 'A'..'Z') c + 32 else c) } } }
            .distinct()
            .sortedWith(::compareCodePoints)
            .toList()

    /**
     * Throws [ConfigViewMismatchException] when the signed [payload] does not
     * answer [expected] (null = the full config); see the table above. Call
     * after the signature verified and before anything is stored or applied.
     */
    fun check(payload: String, expected: Expected?) {
        val view = try {
            JsonParser.parseString(payload).asJsonObject.get(FIELD)?.takeUnless { it.isJsonNull }
        } catch (e: Exception) {
            throw ConfigViewMismatchException("Signed config rejected: its payload is not a JSON object.")
        }
        if (expected == null) {
            if (view != null) {
                throw ConfigViewMismatchException(
                    "Signed config rejected: it is a narrowed view (${describe(view)}), but this block asks for " +
                        "the full config. Applying it would drop the pins of every host it leaves out."
                )
            }
            return
        }
        if (view == null) {
            Timber.w("Signed config carries no '%s' — a full view or a server before 2.9.0; accepted for a scoped block", FIELD)
            return
        }
        val obj = view as? JsonObject ?: throw mismatch(expected, view, "'$FIELD' is not an object")
        obj.keySet().firstOrNull { it != "hosts" && it != "deviceId" }?.let {
            // A narrowing this client does not understand: it cannot tell what was left out.
            throw mismatch(expected, view, "unknown key '${it.take(32)}'")
        }
        val hosts = obj.get("hosts")?.takeUnless { it.isJsonNull }
            ?: throw mismatch(expected, view, "it names no host set")
        val names = (hosts.takeIf { it.isJsonArray }?.asJsonArray ?: throw mismatch(expected, view, "'hosts' is not an array"))
            .map { e -> e.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString ?: throw mismatch(expected, view, "'hosts' holds a non-string") }
        // Compared as sent: the server writes the canonical form, so anything else is another request.
        if (names != expected.hosts) throw mismatch(expected, view, "another host set")
        val deviceId = obj.get("deviceId")?.takeUnless { it.isJsonNull }?.let { e ->
            e.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString ?: throw mismatch(expected, view, "'deviceId' is not a string")
        }
        if (deviceId !in expected.deviceIds) throw mismatch(expected, view, if (deviceId == null) "it names no device id" else "another device id")
    }

    private fun mismatch(expected: Expected, view: JsonElement, why: String) = ConfigViewMismatchException(
        "Signed config rejected: it answers another request ($why). Asked for $expected; the payload's view is ${describe(view)}."
    )

    private fun describe(view: JsonElement): String = view.toString().let { if (it.length > 200) it.take(200) + "…" else it }

    private fun compareCodePoints(a: String, b: String): Int {
        var i = 0
        var j = 0
        while (i < a.length && j < b.length) {
            val ca = a.codePointAt(i)
            val cb = b.codePointAt(j)
            if (ca != cb) return ca.compareTo(cb)
            i += Character.charCount(ca)
            j += Character.charCount(cb)
        }
        return (a.length - i).compareTo(b.length - j)
    }
}
