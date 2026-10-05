package com.example.pinvault.server.plugin

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.header
import io.ktor.server.response.respondText

/**
 * A `multipart/form-data` body an administrator uploaded (a keystore, a
 * certificate, with a few text fields), read from bytes that are already in
 * memory and already capped.
 *
 * One parser for both readers of such a body: the handler, and the
 * description an approver is shown before the handler runs. Two parsers
 * could read the same bytes differently, and the approver would then approve
 * something other than what is applied.
 */
class MultipartForm(
    /** Text fields by name; of two with the same name the last one counts. */
    val fields: Map<String, String>,
    /** The uploaded file (the last part that carries a file name), or null. */
    val file: ByteArray?
) {
    companion object {
        private val BOUNDARY = Regex("""boundary=(?:"([^"]+)"|([^;\s]+))""", RegexOption.IGNORE_CASE)
        private val NAME = Regex("""[;\s]name="([^"]*)"""", RegexOption.IGNORE_CASE)
        private val FILENAME = Regex("""[;\s]filename="([^"]*)"""", RegexOption.IGNORE_CASE)
        private val CRLF = "\r\n".toByteArray()
        private val HEADER_END = "\r\n\r\n".toByteArray()

        /** The form in [body], or null when [contentType] is not multipart or the body is not well formed. */
        fun parse(contentType: String?, body: ByteArray): MultipartForm? {
            if (contentType == null || !contentType.trim().startsWith("multipart/form-data", ignoreCase = true)) return null
            val boundary = BOUNDARY.find(contentType)?.let { it.groupValues[1].ifEmpty { it.groupValues[2] } } ?: return null
            val delimiter = "--$boundary".toByteArray(Charsets.ISO_8859_1)
            val fields = linkedMapOf<String, String>()
            var file: ByteArray? = null

            var at = indexOf(body, delimiter, 0)
            if (at < 0) return null
            while (true) {
                at += delimiter.size
                // "--" after a delimiter closes the body.
                if (startsWith(body, at, "--".toByteArray())) return MultipartForm(fields, file)
                if (!startsWith(body, at, CRLF)) return null
                at += CRLF.size
                val headersEnd = indexOf(body, HEADER_END, at)
                if (headersEnd < 0) return null
                val headers = String(body, at, headersEnd - at, Charsets.ISO_8859_1).split("\r\n")
                val contentStart = headersEnd + HEADER_END.size
                val next = indexOf(body, CRLF + delimiter, contentStart)
                if (next < 0) return null
                val content = body.copyOfRange(contentStart, next)
                val disposition = headers.firstOrNull { it.startsWith("content-disposition:", ignoreCase = true) }
                if (disposition != null) {
                    val name = NAME.find(disposition)?.groupValues?.get(1)
                    if (FILENAME.containsMatchIn(disposition)) file = content
                    else if (name != null) fields[name] = content.toString(Charsets.UTF_8)
                }
                at = next + CRLF.size
            }
        }

        private fun startsWith(data: ByteArray, at: Int, prefix: ByteArray): Boolean =
            at + prefix.size <= data.size && prefix.indices.all { data[at + it] == prefix[it] }

        private fun indexOf(data: ByteArray, pattern: ByteArray, from: Int): Int {
            var i = from
            while (i + pattern.size <= data.size) {
                if (data[i] == pattern[0] && startsWith(data, i, pattern)) return i
                i++
            }
            return -1
        }
    }
}

/**
 * The multipart form of an admin upload: at most [maxBytes] are read (413
 * beyond), and a body that is not a well-formed form is answered with 400.
 * Null after either answer — the caller stops.
 */
suspend fun ApplicationCall.receiveMultipartForm(maxBytes: Long = DEFAULT_ADMIN_BODY_MAX_BYTES): MultipartForm? {
    val bytes = receiveLimitedBytes(maxBytes) ?: return null
    val form = MultipartForm.parse(request.header(HttpHeaders.ContentType), bytes)
    if (form == null) {
        respondText("""{"error":"invalid_multipart","message":"A multipart/form-data body is required."}""",
            ContentType.Application.Json, HttpStatusCode.BadRequest)
    }
    return form
}
