package com.example.pinvault.server.service.attestation

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * The CBOR (RFC 8949) that Apple App Attest objects use, and nothing more:
 * unsigned and negative integers, byte and text strings, arrays and maps, all
 * of definite length. Tags, floats, simple values, indefinite lengths and
 * trailing bytes are refused — an attestation object or an assertion never
 * carries them, and the input comes from anyone who can reach the port.
 *
 * Items decode to [Long], [ByteArray], [String], [List] and [Map]
 * (insertion-ordered; a repeated key is refused).
 */
internal object Cbor {

    class Malformed(message: String) : Exception(message)

    /** Nesting deeper than this is no App Attest object. */
    private const val MAX_DEPTH = 16

    /** Decodes [bytes] as exactly one item. */
    fun decode(bytes: ByteArray): Any {
        val reader = Reader(bytes)
        val item = reader.item(0)
        if (reader.pos != bytes.size) throw Malformed("trailing bytes after the item")
        return item
    }

    private class Reader(private val b: ByteArray) {
        var pos = 0

        fun item(depth: Int): Any {
            if (depth > MAX_DEPTH) throw Malformed("nested too deeply")
            val initial = byte()
            val major = initial ushr 5
            val arg = argument(initial and 0x1f)
            return when (major) {
                0 -> nonNegative(arg)
                1 -> -1 - nonNegative(arg)
                2 -> take(length(arg))
                3 -> text(take(length(arg)))
                4 -> {
                    val n = length(arg)
                    List(n) { item(depth + 1) }
                }
                5 -> {
                    val n = length(arg)
                    val map = LinkedHashMap<Any, Any>(minOf(n, 64) * 2)
                    repeat(n) {
                        val key = item(depth + 1)
                        val value = item(depth + 1)
                        if (map.put(key, value) != null) throw Malformed("repeated map key")
                    }
                    map
                }
                else -> throw Malformed("unsupported major type $major")
            }
        }

        private fun byte(): Int {
            if (pos >= b.size) throw Malformed("truncated")
            return b[pos++].toInt() and 0xFF
        }

        /** The argument of an initial byte's additional information; as an unsigned 64-bit value in a Long. */
        private fun argument(info: Int): Long = when {
            info < 24 -> info.toLong()
            info == 24 -> byte().toLong()
            info == 25 -> (byte().toLong() shl 8) or byte().toLong()
            info == 26 -> (0 until 4).fold(0L) { acc, _ -> (acc shl 8) or byte().toLong() }
            info == 27 -> (0 until 8).fold(0L) { acc, _ -> (acc shl 8) or byte().toLong() }
            info == 31 -> throw Malformed("indefinite length")
            else -> throw Malformed("reserved additional information $info")
        }

        private fun nonNegative(arg: Long): Long {
            if (arg < 0) throw Malformed("integer beyond 63 bits")
            return arg
        }

        /** A length or count: never more than the bytes left (each element takes at least one). */
        private fun length(arg: Long): Int {
            if (arg < 0 || arg > (b.size - pos)) throw Malformed("length beyond the input")
            return arg.toInt()
        }

        private fun take(n: Int): ByteArray {
            val out = b.copyOfRange(pos, pos + n)
            pos += n
            return out
        }

        private fun text(bytes: ByteArray): String = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: CharacterCodingException) {
            throw Malformed("text string is not UTF-8")
        }
    }
}
