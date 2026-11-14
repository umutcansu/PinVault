package com.example.pinvault.server.service

import io.ktor.http.Parameters
import io.ktor.http.decodeURLQueryComponent
import io.ktor.server.plugins.BadRequestException
import io.ktor.server.request.ApplicationRequest
import io.ktor.server.request.queryString
import io.ktor.util.AttributeKey

/**
 * A request's query string, read ONE way: by every handler, by the approval
 * card and by the audit log.
 *
 * Review 2026-11-14 (S1): the card read the stored query with Ktor's
 * `parseQueryString` — names matched ignoring case, nothing after the 1000th
 * `&` — while handlers read `call.request.queryParameters`, which on Netty is
 * `QueryStringDecoder`: names matched exactly, empty parameters skipped, a
 * limit of 1024. `PUT /api/v1/certificate-config?ConfigApiId=staging` got a
 * card for scope `staging` and, once approved, rewrote `default-tls`; a query
 * that began with 1000 `&` did the reverse. A test application never saw it:
 * its engine uses Ktor's parser on both sides.
 *
 * So no engine's parser is asked any more. The raw query is split here:
 * `&` separates, the first `=` divides name from value, both are
 * percent-decoded (`+` is a space), a part without a name is skipped, names
 * are matched EXACTLY and the first value of a name wins. A query that
 * cannot be decoded is a bad request, not an empty one.
 */
class ExactQuery private constructor(private val values: Map<String, List<String>>) {

    /** The first value given for [name], spelled exactly so; null when the query has no such parameter. */
    operator fun get(name: String): String? = values[name]?.firstOrNull()

    /** Every parameter, in the order first seen. */
    fun entries(): Map<String, List<String>> = values

    companion object {
        val EMPTY = ExactQuery(emptyMap())

        /** @throws MalformedQuery when a name or value is not valid percent-encoding. */
        fun parse(raw: String): ExactQuery {
            if (raw.isEmpty()) return EMPTY
            val values = LinkedHashMap<String, MutableList<String>>()
            for (part in raw.split('&')) {
                if (part.isEmpty()) continue
                val eq = part.indexOf('=')
                val name = decode(if (eq < 0) part else part.substring(0, eq))
                if (name.isEmpty()) continue
                values.getOrPut(name) { mutableListOf() } += if (eq < 0) "" else decode(part.substring(eq + 1))
            }
            return ExactQuery(values)
        }

        private fun decode(text: String): String = try {
            text.decodeURLQueryComponent(plusIsSpace = true)
        } catch (e: Exception) {
            throw MalformedQuery()
        }

        /**
         * Whether the engine read the same parameters from the request as
         * [parse] reads from its raw query — names exactly, values in order.
         * The approval gate asks: a query the two read differently is refused
         * there, so a handler that still asks the engine cannot be shown one
         * thing and do another. (A parameter without a value is `""` to some
         * parsers and no value at all to others: the same thing here.)
         */
        fun agreesWith(engine: Parameters, raw: String): Boolean = try {
            fun normal(all: Map<String, List<String>>) = all.mapValues { (_, v) -> v.ifEmpty { listOf("") } }
            normal(engine.entries().associate { it.key to it.value }) == normal(parse(raw).entries())
        } catch (e: Exception) {
            false
        }
    }

    /** A query string that is not valid percent-encoding. Answered with 400. */
    class MalformedQuery : BadRequestException("The query string is not valid percent-encoding")
}

private val ExactQueryKey = AttributeKey<ExactQuery>("ExactQuery")

/** This request's query, parsed once ([ExactQuery]). */
fun ApplicationRequest.exactQuery(): ExactQuery =
    call.attributes.getOrNull(ExactQueryKey) ?: ExactQuery.parse(queryString()).also { call.attributes.put(ExactQueryKey, it) }

/**
 * A query parameter of this request. Handlers read the query with this and
 * nothing else — never `queryParameters[…]`, whose answer depends on the
 * engine ([ExactQuery]); `QueryReadingTest` fails on a handler that does.
 */
fun ApplicationRequest.queryExact(name: String): String? = exactQuery()[name]
