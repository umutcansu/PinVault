package io.github.umutcansu.pinvault.internal

import okhttp3.ResponseBody
import okio.Buffer
import java.io.IOException

/**
 * Reads HTTP response bodies with a ceiling. `ResponseBody.bytes()` and
 * `string()` buffer whatever the server sends, so a hostile or broken server
 * (or whoever holds the TLS key) could answer a config or vault request with
 * gigabytes and take the app down with an `OutOfMemoryError`. Every body the
 * library reads goes through here instead.
 *
 * A declared `Content-Length` above the limit is refused before a byte of
 * the body is read; a body without one (chunked) is counted while it is read
 * and refused as soon as it passes the limit, with at most one byte over
 * the limit ever buffered.
 */
internal object BoundedBody {

    /** Config envelopes and other JSON the library parses: 1 MiB. */
    const val CONFIG_MAX_BYTES: Long = 1L shl 20

    /** Small answers: key registration, enrollment (a P12 or a PEM chain), renewal, attestation, error bodies: 256 KiB. */
    const val SMALL_MAX_BYTES: Long = 256L shl 10

    /**
     * A vault file: 64 MiB. The reference server caps uploads at
     * `VAULT_MAX_FILE_BYTES` (50 MB by default), so a file the server accepted
     * fits; the library has no per-file size in its config to be stricter with.
     */
    const val VAULT_MAX_BYTES: Long = 64L shl 20

    /** How much a read asks the source for at once. */
    private const val CHUNK_BYTES = 64L * 1024

    /**
     * The whole body, or [ResponseTooLargeException] once it is known to be
     * longer than [maxBytes]. [what] names the body in the message.
     */
    @Throws(IOException::class)
    fun readBytes(body: ResponseBody, maxBytes: Long, what: String): ByteArray {
        require(maxBytes > 0) { "maxBytes must be positive" }
        val declared = body.contentLength()
        if (declared > maxBytes) throw ResponseTooLargeException(what, maxBytes, declared)
        val source = body.source()
        val buffer = Buffer()
        var total = 0L
        while (true) {
            // Ask for at most one byte beyond the limit: enough to know the
            // body is too long, never enough to hold much more than the limit.
            val wanted = minOf(CHUNK_BYTES, maxBytes - total + 1)
            val read = source.read(buffer, wanted)
            if (read == -1L) break
            total += read
            if (total > maxBytes) throw ResponseTooLargeException(what, maxBytes, null)
        }
        return buffer.readByteArray()
    }

    /** [readBytes] decoded with the body's charset (UTF-8 when it names none). */
    @Throws(IOException::class)
    fun readString(body: ResponseBody, maxBytes: Long, what: String): String {
        val charset = body.contentType()?.charset(Charsets.UTF_8) ?: Charsets.UTF_8
        return String(readBytes(body, maxBytes, what), charset)
    }

    /**
     * The first [maxBytes] of the body as text, for error answers whose text
     * is only quoted (never parsed as a whole): a longer body is cut, not
     * refused, so the HTTP status it came with is still reported. Reads no
     * more than [maxBytes] plus one buffer segment.
     */
    fun readPrefix(body: ResponseBody, maxBytes: Long): String {
        val charset = body.contentType()?.charset(Charsets.UTF_8) ?: Charsets.UTF_8
        return try {
            val source = body.source()
            source.request(maxBytes)
            val available = minOf(source.buffer.size, maxBytes)
            String(source.buffer.readByteArray(available), charset)
        } catch (e: IOException) {
            ""
        }
    }
}

/**
 * A response body longer than the library reads for that kind of answer.
 * [declared] is the `Content-Length` when the refusal came from it, null
 * when the body was cut off while it was being read.
 */
internal class ResponseTooLargeException(what: String, val maxBytes: Long, val declared: Long?) : IOException(
    "The $what response body exceeds $maxBytes bytes" +
        (declared?.let { " (Content-Length: $it)" } ?: "") + "; refused"
)
