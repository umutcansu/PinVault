package io.github.umutcansu.pinvault.reactnative

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.json.JSONTokener

/**
 * A refusal of bridge input: unknown key, wrong type, value out of range,
 * oversized input. Its message names the path (`config.configApis[0].url`).
 */
class BridgeInputException(message: String) : IllegalArgumentException(message)

/**
 * Strict JSON for bridge input. JSON from JS → plain Kotlin values (Map, List,
 * String, Boolean, Number, null); then [Fields] reads an object key by key and
 * refuses every key it did not read ([Fields.finish]). Nothing is silently
 * ignored and nothing is coerced (a "1" is not a number, a 1 is not a boolean).
 */
internal object StrictJson {

    const val MAX_INPUT_CHARS = 256 * 1024
    const val MAX_DEPTH = 8

    fun parseObject(json: String, path: String, maxChars: Int = MAX_INPUT_CHARS): Fields {
        if (json.length > maxChars) throw BridgeInputException("$path: larger than $maxChars characters")
        val value = try {
            JSONTokener(json).nextValue()
        } catch (e: JSONException) {
            throw BridgeInputException("$path: not valid JSON")
        }
        if (value !is JSONObject) throw BridgeInputException("$path: must be an object")
        @Suppress("UNCHECKED_CAST")
        return Fields(path, toKotlin(value, path, 0) as Map<String, Any?>)
    }

    private fun toKotlin(value: Any?, path: String, depth: Int): Any? {
        if (depth > MAX_DEPTH) throw BridgeInputException("$path: nested too deeply")
        return when (value) {
            null, JSONObject.NULL -> null
            is JSONObject -> {
                val out = LinkedHashMap<String, Any?>()
                val keys = value.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    out[k] = toKotlin(value.opt(k), "$path.$k", depth + 1)
                }
                out
            }
            is JSONArray -> (0 until value.length()).map { toKotlin(value.opt(it), "$path[$it]", depth + 1) }
            is String, is Boolean -> value
            is Number -> {
                val d = value.toDouble()
                if (d.isNaN() || d.isInfinite()) throw BridgeInputException("$path: not a finite number")
                value
            }
            else -> throw BridgeInputException("$path: unsupported value")
        }
    }
}

/** One JSON object; every accessor marks its key as known. JSON `null` counts as absent. */
internal class Fields(val path: String, private val map: Map<String, Any?>) {

    private val known = mutableSetOf<String>()

    private fun raw(key: String): Any? {
        known += key
        return map[key]
    }

    fun has(key: String): Boolean {
        known += key
        return map[key] != null
    }

    /** Refuses every key no accessor asked for. */
    fun finish() {
        val unknown = map.keys.filter { it !in known }
        if (unknown.isNotEmpty()) {
            throw BridgeInputException(
                "$path: unknown key${if (unknown.size > 1) "s" else ""} ${unknown.joinToString { "'$it'" }}"
            )
        }
    }

    fun string(key: String, maxLength: Int = 2048, allowEmpty: Boolean = false, multiline: Boolean = false): String? {
        val v = raw(key) ?: return null
        if (v !is String) throw BridgeInputException("$path.$key: must be a string")
        if (v.length > maxLength) throw BridgeInputException("$path.$key: longer than $maxLength characters")
        if (!allowEmpty && v.isEmpty()) throw BridgeInputException("$path.$key: must not be empty")
        if (v.any { badChar(it, multiline) }) throw BridgeInputException("$path.$key: control characters are not allowed")
        return v
    }

    /** Free text (a request body): any characters, bounded length. */
    fun text(key: String, maxLength: Int): String? {
        val v = raw(key) ?: return null
        if (v !is String) throw BridgeInputException("$path.$key: must be a string")
        if (v.length > maxLength) throw BridgeInputException("$path.$key: longer than $maxLength characters")
        return v
    }

    private fun badChar(c: Char, multiline: Boolean): Boolean =
        (c.code < 0x20 || c.code == 0x7f) && !(multiline && (c == '\n' || c == '\r'))

    fun requireString(key: String, maxLength: Int = 2048): String =
        string(key, maxLength) ?: throw BridgeInputException("$path.$key: required")

    fun bool(key: String): Boolean? {
        val v = raw(key) ?: return null
        if (v !is Boolean) throw BridgeInputException("$path.$key: must be a boolean")
        return v
    }

    fun long(key: String, min: Long, max: Long): Long? {
        val v = raw(key) ?: return null
        if (v !is Number) throw BridgeInputException("$path.$key: must be a number")
        val d = v.toDouble()
        if (d != Math.floor(d)) throw BridgeInputException("$path.$key: must be a whole number")
        if (d < min || d > max) throw BridgeInputException("$path.$key: must be between $min and $max")
        return d.toLong()
    }

    fun int(key: String, min: Int, max: Int): Int? = long(key, min.toLong(), max.toLong())?.toInt()

    fun double(key: String, min: Double, max: Double): Double? {
        val v = raw(key) ?: return null
        if (v !is Number) throw BridgeInputException("$path.$key: must be a number")
        val d = v.toDouble()
        if (d < min || d > max) throw BridgeInputException("$path.$key: must be between $min and $max")
        return d
    }

    fun stringList(key: String, maxItems: Int = 64, maxLength: Int = 2048, multiline: Boolean = false): List<String>? {
        val v = raw(key) ?: return null
        if (v !is List<*>) throw BridgeInputException("$path.$key: must be a list of strings")
        if (v.size > maxItems) throw BridgeInputException("$path.$key: more than $maxItems items")
        return v.mapIndexed { i, item ->
            if (item !is String) throw BridgeInputException("$path.$key[$i]: must be a string")
            if (item.isEmpty() || item.length > maxLength) {
                throw BridgeInputException("$path.$key[$i]: must be 1 to $maxLength characters")
            }
            if (item.any { badChar(it, multiline) }) throw BridgeInputException("$path.$key[$i]: control characters are not allowed")
            item
        }
    }

    fun obj(key: String): Fields? {
        val v = raw(key) ?: return null
        if (v !is Map<*, *>) throw BridgeInputException("$path.$key: must be an object")
        @Suppress("UNCHECKED_CAST")
        return Fields("$path.$key", v as Map<String, Any?>)
    }

    fun objList(key: String, maxItems: Int): List<Fields>? {
        val v = raw(key) ?: return null
        if (v !is List<*>) throw BridgeInputException("$path.$key: must be a list of objects")
        if (v.size > maxItems) throw BridgeInputException("$path.$key: more than $maxItems items")
        return v.mapIndexed { i, item ->
            if (item !is Map<*, *>) throw BridgeInputException("$path.$key[$i]: must be an object")
            @Suppress("UNCHECKED_CAST")
            Fields("$path.$key[$i]", item as Map<String, Any?>)
        }
    }

    /** A string → string map (`ios.resolve`, request headers). */
    fun stringMap(key: String, maxItems: Int, maxKeyLength: Int, maxValueLength: Int): Map<String, String>? {
        val v = raw(key) ?: return null
        if (v !is Map<*, *>) throw BridgeInputException("$path.$key: must be an object")
        if (v.size > maxItems) throw BridgeInputException("$path.$key: more than $maxItems entries")
        return v.entries.associate { (k, value) ->
            val name = k as String
            if (name.isEmpty() || name.length > maxKeyLength) throw BridgeInputException("$path.$key: key '${name.take(40)}' has a bad length")
            if (value !is String) throw BridgeInputException("$path.$key.$name: must be a string")
            if (value.length > maxValueLength) throw BridgeInputException("$path.$key.$name: longer than $maxValueLength characters")
            name to value
        }
    }

    /** `enum` by its Kotlin constant name. */
    fun <E : Enum<E>> enum(key: String, values: Array<E>): E? {
        val v = string(key, 64) ?: return null
        return values.firstOrNull { it.name == v }
            ?: throw BridgeInputException("$path.$key: '$v' is not one of ${values.joinToString { it.name }}")
    }
}
