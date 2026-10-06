package com.example.pinvault.server.service

import com.example.pinvault.server.route.serverSettingsRoutes
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Settings saved from the setup wizard: what is accepted, what is refused, what applies when. */
class ServerSettingsTest {

    private val dir: File = Files.createTempDirectory("server-settings").toFile()
    private val file = File(dir, "server-settings.json")

    @AfterTest
    fun reset() {
        ServerEnv.overlay = emptyMap()
        dir.deleteRecursively()
    }

    @Test
    fun `each kind accepts only its own values`() {
        val approvals = ServerSettingsCatalog.find("PIN_CHANGE_APPROVALS")!!
        assertNull(approvals.problem("2"))
        assertNotNull(approvals.problem("0"))
        assertNotNull(approvals.problem("two"))
        val live = ServerSettingsCatalog.find("PIN_LIVE_CHECK")!!
        assertNull(live.problem("enforce"))
        assertNotNull(live.problem("ENFORCE "))
        assertNull(ServerSettingsCatalog.find("ATTESTATION_ENABLED")!!.problem("false"))
        assertNotNull(ServerSettingsCatalog.find("ATTESTATION_ENABLED")!!.problem("no"))
        val packages = ServerSettingsCatalog.find("ATTESTATION_PACKAGE_NAMES")!!
        assertNull(packages.problem("com.example.app, com.example.other"))
        assertNotNull(packages.problem("com.example.app; rm -rf /"))
        val digests = ServerSettingsCatalog.find("ATTESTATION_SIGNER_SHA256")!!
        assertNull(digests.problem("ab".repeat(32)))
        assertNull(digests.problem(List(32) { "AB" }.joinToString(":")))
        assertNotNull(digests.problem("ab".repeat(31)))
        assertNull(ServerSettingsCatalog.find("SETUP_PUBLIC_PORTS")!!.problem("8081:6651,8092:6652"))
        assertNotNull(ServerSettingsCatalog.find("SETUP_PUBLIC_PORTS")!!.problem("8081=6651"))
    }

    @Test
    fun `secrets, ports and test switches are not offered`() {
        val keys = ServerSettingsCatalog.all.map { it.key }.toSet()
        listOf("API_KEY", "KEYSTORE_PASSWORD", "SIGNING_KEY_PASSWORD", "NOTIFY_WEBHOOK_SECRET", "PORT", "DB_PATH",
            "ALLOW_TEST_HOOKS", "ALLOW_ANONYMOUS_ADMIN", "ALLOW_DEMO_SECRETS", "INTEGRITY_VERIFIER_COMMAND", "ADMIN_KEYS")
            .forEach { assertFalse(it in keys, "$it must not be changeable from the dashboard") }
    }

    @Test
    fun `an enforce mode without the app it binds to would not start`() {
        assertEquals(1, ServerSettingsCatalog.startProblems(mapOf("ENROLLMENT_ATTESTATION" to "enforce")).size)
        assertTrue(ServerSettingsCatalog.startProblems(mapOf(
            "ENROLLMENT_ATTESTATION" to "enforce",
            "ATTESTATION_PACKAGE_NAMES" to "com.example.app",
            "ATTESTATION_SIGNER_SHA256" to "ab".repeat(32)
        )).isEmpty())
        assertEquals(1, ServerSettingsCatalog.startProblems(mapOf("INTEGRITY_VERIFICATION" to "enforce")).size)
    }

    @Test
    fun `saved values fill in only what the environment leaves empty`() {
        ServerEnv.overlay = mapOf("PIN_LIVE_CHECK" to "warn", "PATH" to "/nowhere")
        assertEquals("warn", ServerEnv.get("PIN_LIVE_CHECK"))
        assertEquals(System.getenv("PATH"), ServerEnv.get("PATH"))
        assertEquals("warn", ServerEnv.all()["PIN_LIVE_CHECK"])
        assertEquals(System.getenv("PATH"), ServerEnv.all()["PATH"])
    }

    @Test
    fun `a set that stopped the server is kept to show, never applied`() {
        val store = ServerSettingsStore(file)
        store.save(mapOf("PIN_LIVE_CHECK" to "warn", "NOT_A_SETTING" to "x", "PIN_CHANGE_APPROVALS" to "nine"))
        assertEquals(mapOf("PIN_LIVE_CHECK" to "warn"), store.values())
        store.reject("boom")
        assertEquals(emptyMap(), store.values())
        assertEquals("boom", store.read().rejected!!.reason)
        assertEquals("warn", store.read().rejected!!.values["PIN_LIVE_CHECK"])
        store.clearRejected()
        assertNull(store.read().rejected)
    }

    @Test
    fun `the dashboard saves for the next start and refuses what would not start`() = testApplication {
        val store = ServerSettingsStore(file)
        routing { serverSettingsRoutes(store, null, restartSupervised = false) }

        val saved = client.put("/api/v1/server-settings") {
            contentType(ContentType.Application.Json)
            setBody("""{"values":{"PIN_LIVE_CHECK":"warn","PIN_CHANGE_APPROVALS":"2"}}""")
        }
        assertEquals(HttpStatusCode.OK, saved.status)
        val view = Json.parseToJsonElement(saved.bodyAsText()).jsonObject
        assertTrue(view["pendingRestart"]!!.jsonPrimitive.boolean)
        val live = setting(view, "PIN_LIVE_CHECK")
        assertEquals("warn", live["saved"]!!.jsonPrimitive.content)
        assertTrue(live["pending"]!!.jsonPrimitive.boolean)
        assertEquals(mapOf("PIN_LIVE_CHECK" to "warn", "PIN_CHANGE_APPROVALS" to "2"), store.values())

        val bad = client.put("/api/v1/server-settings") {
            contentType(ContentType.Application.Json)
            setBody("""{"values":{"PIN_LIVE_CHECK":"maybe","API_KEY":"x"}}""")
        }
        assertEquals(HttpStatusCode.BadRequest, bad.status)
        assertEquals(2, Json.parseToJsonElement(bad.bodyAsText()).jsonObject["details"]!!.jsonArray.size)

        val wouldNotStart = client.put("/api/v1/server-settings") {
            contentType(ContentType.Application.Json)
            setBody("""{"values":{"ATTESTATION_KEY_POLICY":"enforce"}}""")
        }
        assertEquals(HttpStatusCode.BadRequest, wouldNotStart.status)
        assertTrue(wouldNotStart.bodyAsText().contains("would_not_start"))
        assertEquals(mapOf("PIN_LIVE_CHECK" to "warn", "PIN_CHANGE_APPROVALS" to "2"), store.values())

        val cleared = client.put("/api/v1/server-settings") {
            contentType(ContentType.Application.Json)
            setBody("""{"values":{"PIN_LIVE_CHECK":""}}""")
        }
        assertEquals(HttpStatusCode.OK, cleared.status)
        assertEquals(mapOf("PIN_CHANGE_APPROVALS" to "2"), store.values())

        assertEquals(HttpStatusCode.Conflict, client.post("/api/v1/server-settings/restart").status)
    }

    @Test
    fun `a supervised server exits to apply, and the rejected note can be dismissed`() = testApplication {
        val store = ServerSettingsStore(file)
        store.save(mapOf("PIN_LIVE_CHECK" to "warn"))
        store.reject("PIN_LIVE_CHECK broke it")
        val exited = CountDownLatch(1)
        routing { serverSettingsRoutes(store, null, restartSupervised = true) { exited.countDown() } }

        val view = Json.parseToJsonElement(client.get("/api/v1/server-settings").bodyAsText()).jsonObject
        assertEquals("PIN_LIVE_CHECK broke it", view["rejected"]!!.jsonObject["reason"]!!.jsonPrimitive.content)
        assertTrue(view["restartSupervised"]!!.jsonPrimitive.boolean)

        assertEquals(HttpStatusCode.OK, client.delete("/api/v1/server-settings/rejected").status)
        assertNull(store.read().rejected)

        assertEquals(HttpStatusCode.Accepted, client.post("/api/v1/server-settings/restart").status)
        assertTrue(exited.await(5, TimeUnit.SECONDS))
    }

    private fun setting(view: JsonObject, key: String): JsonObject =
        view["settings"]!!.jsonArray.map { it.jsonObject }.single { it["key"]!!.jsonPrimitive.content == key }
}
