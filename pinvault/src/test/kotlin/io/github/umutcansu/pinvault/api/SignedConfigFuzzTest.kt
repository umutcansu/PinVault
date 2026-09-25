package io.github.umutcansu.pinvault.api

import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.JsonPrimitive
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.SignedConfigResponse
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import io.github.umutcansu.pinvault.util.TestCertUtil
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64
import kotlin.random.Random

/**
 * Robustness: the signed config response is untrusted input. Whatever a
 * broken proxy or an attacker does to it, the client must either reject it
 * with an exception (the updater keeps the previous config) or, when the
 * signed payload survived untouched, return exactly the original config.
 * Never a different config, and never an [Error] such as a stack overflow.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class SignedConfigFuzzTest {

    private lateinit var server: MockWebServer
    private lateinit var sslManager: DynamicSSLManager
    private val gson = Gson()

    private val keyPair = TestCertUtil.generateEcKeyPair()
    private val publicKey = Base64.getEncoder().encodeToString(keyPair.public.encoded)
    private val now = System.currentTimeMillis()
    private val original = CertificateConfig(
        version = 7,
        pins = listOf(
            HostPin("api.example.com", listOf("pinA", "pinB"), version = 7),
            HostPin("*.cdn.example.com", listOf("pinC", "pinD"), version = 3)
        ),
        issuedAt = now,
        expiresAt = now + 3_600_000L
    )
    private val payload = gson.toJson(original)
    private val signature = TestCertUtil.signPayload(payload, keyPair.private)
    private val envelope = gson.toJson(SignedConfigResponse(payload = payload, signature = signature))

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        sslManager = mockk()
        every { sslManager.buildBootstrapClient(any()) } returns OkHttpClient()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    private fun api() = DefaultCertificateConfigApi(
        configUrl = server.url("/").toString(),
        signaturePublicKey = publicKey,
        bootstrapPins = listOf(HostPin("test.com", listOf("h1", "h2"))),
        sslManager = sslManager
    )

    /** Serves [body] once; returns the config or the exception, failing on anything else. */
    private suspend fun serve(body: String, label: String): Result<CertificateConfig> {
        server.enqueue(MockResponse().setBody(body))
        val result = try {
            Result.success(api().fetchConfig(1))
        } catch (e: Exception) {
            Result.failure(e)
        } catch (e: Throwable) {
            throw AssertionError("$label: ${e::class.java.name} escaped (must be a plain rejection)\n$body", e)
        }
        result.onSuccess { assertEquals("$label: accepted a config other than the signed one\n$body", original, it) }
        return result
    }

    @Test
    fun `the untouched envelope is accepted`() = runTest {
        assertTrue(serve(envelope, "untouched").isSuccess)
    }

    @Test
    fun `targeted envelope edits are rejected unless the signed payload is intact`() = runTest {
        val other = gson.toJson(original.copy(pins = original.pins + HostPin("evil.example.com", listOf("x", "y"))))
        fun edit(change: JsonObject.() -> Unit): String =
            JsonParser.parseString(envelope).asJsonObject.apply(change).toString()

        val mustReject = mapOf(
            "empty body" to "",
            "JSON null" to "null",
            "array" to "[]",
            "number" to "42",
            "string" to "\"payload\"",
            "no payload" to edit { remove("payload") },
            "payload null" to edit { add("payload", JsonNull.INSTANCE) },
            "payload is an object" to edit { add("payload", JsonParser.parseString(payload)) },
            "payload replaced" to edit { addProperty("payload", other) },
            "payload with trailing space" to edit { addProperty("payload", "$payload ") },
            "no signature" to edit { remove("signature") },
            "empty signature" to edit { addProperty("signature", "") },
            "signature not base64" to edit { addProperty("signature", "%%%") },
            "signature of the other payload" to edit {
                addProperty("payload", other)
                addProperty("signature", signature)
            },
            "signatures list names only a bad one" to edit {
                add("signatures", JsonArray().apply { add(JsonObject().apply { addProperty("signature", "AAAA") }) })
            },
            "signatures list is a string" to edit { addProperty("signatures", "x") },
            "duplicate payload key, the last one altered" to envelope.replaceFirst("{", "{\"payload\":${JsonPrimitive(payload)},")
                .replace(",\"signature\"", ",\"payload\":${JsonPrimitive(other)},\"signature\""),
        )
        for ((label, body) in mustReject) {
            val result = serve(body, label)
            assertTrue("$label must be rejected", result.isFailure)
        }

        val mustAccept = mapOf(
            "unknown fields" to edit { addProperty("extra", 1); add("more", JsonArray()) },
            "empty signatures list falls back to signature" to edit { add("signatures", JsonArray()) },
            "keyId hint is wrong" to edit { addProperty("keyId", "not-the-key") },
        )
        for ((label, body) in mustAccept) assertTrue("$label must be accepted", serve(body, label).isSuccess)

        // Either outcome is fine here; serve() still checks nothing else gets through.
        val either = mapOf(
            "duplicate payload key, the last one intact" to envelope.replaceFirst("{", "{\"payload\":${JsonPrimitive(other)},"),
            "deeply nested unknown field" to envelope.replaceFirst("{", "{\"x\":" + "[".repeat(5000) + "]".repeat(5000) + ","),
        )
        for ((label, body) in either) serve(body, label)
    }

    // Random damage: byte flips, cuts, insertions, truncations, swapped
    // characters. Seeded, so a failure reproduces.
    @Test
    fun `randomly damaged envelopes never yield a different config`() = runTest {
        val random = Random(20260925)
        val junk = listOf("\"", "\\", "{", "}", "[", "]", ",", ":", "null", "0", "-1", "1e999", "\\u0000", "é", "\uD83D", " ", "true")
        var accepted = 0
        val rejected = sortedMapOf<String, Int>()
        repeat(600) { round ->
            val chars = StringBuilder(envelope)
            repeat(1 + random.nextInt(3)) {
                val at = random.nextInt(chars.length)
                when (random.nextInt(5)) {
                    0 -> chars.setCharAt(at, (chars[at].code xor (1 shl random.nextInt(7))).toChar())
                    1 -> chars.delete(at, minOf(chars.length, at + 1 + random.nextInt(8)))
                    2 -> chars.insert(at, junk[random.nextInt(junk.size)])
                    3 -> chars.setLength(maxOf(1, at))
                    else -> if (at + 1 < chars.length) {
                        val c = chars[at]; chars.setCharAt(at, chars[at + 1]); chars.setCharAt(at + 1, c)
                    }
                }
                if (chars.isEmpty()) chars.append('{')
            }
            serve(chars.toString(), "round $round")
                .onSuccess { accepted++ }
                .onFailure { rejected.merge(it::class.java.simpleName, 1, Int::plus) }
        }
        println("SignedConfigFuzzTest: 600 damaged envelopes → $accepted accepted unchanged, rejected: $rejected")
        assertTrue("most damage must be caught", rejected.values.sum() > 500)
    }
}
