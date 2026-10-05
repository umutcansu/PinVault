package io.github.umutcansu.pinvault.internal

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.asResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/** [BoundedBody] on its own: declared lengths, counted lengths, the cut-off prefix. */
class BoundedBodyTest {

    private fun declared(bytes: ByteArray): ResponseBody = bytes.toResponseBody("application/octet-stream".toMediaType())

    /** A body of unknown length (chunked): the ceiling can only come from counting. */
    private fun chunked(bytes: ByteArray): ResponseBody = Buffer().write(bytes).asResponseBody(null, -1L)

    @Test
    fun `a body within the limit comes back whole`() {
        val bytes = ByteArray(10_000) { it.toByte() }
        assertArrayEquals(bytes, BoundedBody.readBytes(declared(bytes), 10_000, "test"))
        assertArrayEquals(bytes, BoundedBody.readBytes(chunked(bytes), 10_000, "test"))
    }

    @Test
    fun `a declared length over the limit is refused before the body is read`() {
        val body = declared(ByteArray(10_001))
        val e = assertThrows(ResponseTooLargeException::class.java) { BoundedBody.readBytes(body, 10_000, "config") }
        assertEquals(10_000L, e.maxBytes)
        assertEquals(10_001L, e.declared)
        assertEquals("nothing was read", 10_001L, body.source().buffer.size)
    }

    @Test
    fun `an undeclared body is cut off one byte past the limit`() {
        val source = Buffer().write(ByteArray(1_000_000))
        val body = source.asResponseBody(null, -1L)
        val e = assertThrows(ResponseTooLargeException::class.java) { BoundedBody.readBytes(body, 10_000, "config") }
        assertNull(e.declared)
        assertEquals("read stops at the first byte over the limit", 1_000_000L - 10_001L, source.size)
    }

    @Test
    fun `a string body honours the charset and the limit`() {
        val body = "héllo".toByteArray(Charsets.ISO_8859_1).toResponseBody("text/plain; charset=iso-8859-1".toMediaType())
        assertEquals("héllo", BoundedBody.readString(body, 100, "test"))
        assertThrows(ResponseTooLargeException::class.java) {
            BoundedBody.readString("too long".toResponseBody(null), 3, "test")
        }
    }

    @Test
    fun `a prefix is cut, never refused`() {
        assertEquals("abc", BoundedBody.readPrefix(chunked("abcdef".toByteArray()), 3))
        assertEquals("abcdef", BoundedBody.readPrefix(declared("abcdef".toByteArray()), 200))
        assertEquals("", BoundedBody.readPrefix(declared(ByteArray(0)), 200))
    }
}
