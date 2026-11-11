package com.example.pinvault.server

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.route.BASE_STATE_HEADER
import com.example.pinvault.server.route.STATE_HEADER
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.managementConfigRoutes
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.LiveCertificateGate
import com.example.pinvault.server.service.PinDiff
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.*

/**
 * Pin writes were last-writer-wins (pre-production review, F-1) and host
 * names were compared with their case (F-2):
 *
 *  - a save took an existing host's version as given, so a writer working
 *    from an old copy could store a host below a version devices had seen;
 *  - load → (live gate) → save was not one piece, so two admins' changes
 *    could interleave and one be lost;
 *  - the dashboard PUTs every host and the trust roots from the copy its tab
 *    loaded: a host another admin added in between was removed without a word;
 *  - `Api.bank.com` after `api.bank.com` restarted at v1 — the same host to a
 *    device, which then refused the whole config as a downgrade.
 */
class PinWriteConcurrencyTest {

    private val api = "write-test"
    private val pinsA = listOf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=")
    private val pinsB = listOf("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=")

    private lateinit var dir: File
    private lateinit var db: DatabaseManager
    private lateinit var store: PinConfigStore
    private lateinit var history: PinConfigHistoryStore

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-writes-").toFile()
        db = DatabaseManager(File(dir, "db.sqlite").absolutePath)
        store = PinConfigStore(db)
        history = PinConfigHistoryStore(db)
    }

    @AfterTest
    fun tearDown() { dir.deleteRecursively() }

    private fun config(vararg pins: HostPin) = PinConfig(pins = pins.toList(), forceUpdate = false)

    // ── F-1 (a): the version floor holds for a host that is there ────────

    @Test
    fun `a host that stays is never stored below a version it has had`() {
        store.save(api, config(HostPin("a.example.com", pinsA, version = 7)))
        // A writer that computed its version from an old copy (v3 → v4), with other pins:
        // above the mark, not AT it — a device holding v7 would answer "already current"
        // and never take the changed pins.
        val saved = store.save(api, config(HostPin("a.example.com", pinsB, version = 4)))
        assertEquals(8, saved.pins.single().version)
        assertEquals(8, store.load(api).pins.single().version)
        assertEquals(pinsB, store.load(api).pins.single().sha256)
        // The same content sent with an old number keeps its place: no bump for nothing.
        assertEquals(8, store.save(api, config(HostPin("a.example.com", pinsB, version = 2))).pins.single().version)
        assertEquals(8, store.versionWatermark(api, "a.example.com"))
        // A changed flag below the mark is a change too.
        assertEquals(9, store.save(api, config(HostPin("a.example.com", pinsB, version = 3, mtls = true))).pins.single().version)
        // At the mark the caller's number stands (the force routes change a flag without a bump, on purpose).
        assertEquals(9, store.save(api, config(HostPin("a.example.com", pinsB, version = 9, forceUpdate = true, mtls = true))).pins.single().version)
        // Going up is still the caller's choice.
        assertEquals(12, store.save(api, config(HostPin("a.example.com", pinsA, version = 12))).pins.single().version)
    }

    // ── F-1 (b): load → save is one piece ────────────────────────────────

    @Test
    fun `a save over a state that moved is refused and writes nothing`() {
        store.save(api, config(HostPin("a.example.com", pinsA, version = 1)))
        val loadedByAlice = store.load(api)
        // Bob adds a host while Alice's change waits (the live gate probing).
        store.save(api, loadedByAlice.copy(pins = loadedByAlice.pins + HostPin("b.example.com", pinsB, version = 1)))

        assertFailsWith<StaleConfigException> {
            store.save(api, loadedByAlice.copy(pins = listOf(HostPin("a.example.com", pinsB, version = 2))), expected = loadedByAlice)
        }
        val now = store.load(api)
        assertEquals(setOf("a.example.com", "b.example.com"), now.pins.map { it.hostname }.toSet(), "Bob's host is still there")
        assertEquals(pinsA, now.pins.first { it.hostname == "a.example.com" }.sha256, "nothing of the stale write was stored")

        // On the state it was computed from, the same save goes through.
        val fresh = store.load(api)
        store.save(api, fresh.copy(pins = fresh.pins.map { if (it.hostname == "a.example.com") it.copy(sha256 = pinsB, version = 2) else it }), expected = fresh)
        assertEquals(pinsB, store.load(api).pins.first { it.hostname == "a.example.com" }.sha256)
    }

    @Test
    fun `writers that load and save under the scope lock never lose each other's host`() {
        val writers = 24
        val pool = Executors.newFixedThreadPool(8)
        val start = CountDownLatch(1)
        val done = CountDownLatch(writers)
        try {
            repeat(writers) { n ->
                pool.execute {
                    try {
                        start.await()
                        // What toggle-mtls, force-update and a certificate change do.
                        store.locked(api) {
                            val current = store.load(api)
                            store.save(api, current.copy(pins = current.pins + HostPin("host-$n.example.com", pinsA, version = 1)))
                        }
                    } finally {
                        done.countDown()
                    }
                }
            }
            start.countDown()
            assertTrue(done.await(60, TimeUnit.SECONDS))
        } finally {
            pool.shutdownNow()
        }
        assertEquals((0 until writers).map { "host-$it.example.com" }.toSet(), store.load(api).pins.map { it.hostname }.toSet())
    }

    // ── F-1 (c): the editor's precondition ───────────────────────────────

    private fun ApplicationTestBuilder.configureApp(liveGate: LiveCertificateGate? = null) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        routing {
            certificateConfigRoutes(api, store, history, ConnectionHistoryStore(db),
                ConfigSigningService(File(dir, "signing.pem")), ClientDeviceStore(db), liveGate = liveGate)
            managementConfigRoutes(store, history, HostStore(db), CertificateService(File(dir, "certs").also { it.mkdirs() }), liveGate)
        }
    }

    private fun body(vararg hosts: Pair<String, List<String>>, roots: List<String>? = null): String = buildJsonObject {
        put("version", 0)
        put("forceUpdate", false)
        putJsonArray("pins") {
            hosts.forEach { (host, pins) -> addJsonObject { put("hostname", host); putJsonArray("sha256") { pins.forEach { add(it) } } } }
        }
        roots?.let { r -> putJsonArray("trustRoots") { r.forEach { add(it) } } }
    }.toString()

    private suspend fun ApplicationTestBuilder.putPins(json: String, baseState: String? = null, path: String = "/api/v1/certificate-config"): HttpResponse =
        client.request(path) {
            method = if (path.endsWith("/update")) HttpMethod.Post else HttpMethod.Put
            contentType(ContentType.Application.Json)
            baseState?.let { header(BASE_STATE_HEADER, it) }
            setBody(json)
        }

    @Test
    fun `the management GET names the state and a full-config write from an older state is refused with 409`() = testApplication {
        configureApp()
        assertEquals(HttpStatusCode.OK, putPins(body("a.example.com" to pinsA)).status)

        // Two dashboard tabs load the same config.
        val loaded = client.get("/api/v1/config/$api")
        val state = assertNotNull(loaded.headers[STATE_HEADER], "the GET says which state it is")
        assertEquals(PinDiff.stateHash(store.load(api)), state)

        // Tab 1 adds a host; the answer names the new state.
        val first = putPins(body("a.example.com" to pinsA, "b.example.com" to pinsB), baseState = state)
        assertEquals(HttpStatusCode.OK, first.status, first.bodyAsText())
        assertEquals(PinDiff.stateHash(store.load(api)), first.headers[STATE_HEADER])

        // Tab 2 edits a.example.com from its old copy, which has no b.example.com:
        // it used to be saved, and tab 1's host was gone.
        val stale = putPins(body("a.example.com" to pinsB), baseState = state)
        assertEquals(HttpStatusCode.Conflict, stale.status, stale.bodyAsText())
        val answer = Json.parseToJsonElement(stale.bodyAsText()).jsonObject
        assertEquals("stale_config", answer["error"]!!.jsonPrimitive.content)
        assertEquals(PinDiff.stateHash(store.load(api)), answer["state"]!!.jsonPrimitive.content)
        assertEquals(setOf("a.example.com", "b.example.com"), store.load(api).pins.map { it.hostname }.toSet())
        assertEquals(pinsA, store.load(api).pins.first { it.hostname == "a.example.com" }.sha256)

        // The same holds for the scoped POST the management API offers…
        assertEquals(HttpStatusCode.Conflict, putPins(body("a.example.com" to pinsB), baseState = state, path = "/api/v1/config/$api/update").status)
        // …and for a moved trust-root list alone.
        val withRoot = putPins(body("a.example.com" to pinsA, "b.example.com" to pinsB, roots = listOf("RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRA=")),
            baseState = first.headers[STATE_HEADER])
        assertEquals(HttpStatusCode.OK, withRoot.status, withRoot.bodyAsText())
        assertEquals(HttpStatusCode.Conflict,
            putPins(body("a.example.com" to pinsA, "b.example.com" to pinsB, roots = emptyList()), baseState = first.headers[STATE_HEADER]).status)
        assertEquals(1, store.load(api).trustRoots.size, "the root another admin added is not withdrawn by a stale tab")

        // Without the header a write is unconditional, as before (scripts).
        assertEquals(HttpStatusCode.OK, putPins(body("a.example.com" to pinsB)).status)
        assertEquals(listOf("a.example.com"), store.load(api).pins.map { it.hostname })
    }

    @Test
    fun `a write that lands while the live gate probes is not written over`() = testApplication {
        store.save(api, config(HostPin("a.example.com", pinsA, version = 1)))
        // The gate's probe is where the handler waits on the network: another
        // admin's write lands exactly there.
        val gate = LiveCertificateGate(LiveCertificateGate.Mode.WARN, probe = { _, _, _, _ ->
            val current = store.load(api)
            if (current.pins.none { it.hostname == "b.example.com" }) {
                store.save(api, current.copy(pins = current.pins + HostPin("b.example.com", pinsB, version = 1)))
            }
            throw java.net.ConnectException("Connection refused")
        })
        configureApp(gate)

        val lost = putPins(body("a.example.com" to pinsB))
        assertEquals(HttpStatusCode.Conflict, lost.status, lost.bodyAsText())
        assertTrue(lost.bodyAsText().contains("stale_config"), lost.bodyAsText())
        val now = store.load(api)
        assertEquals(setOf("a.example.com", "b.example.com"), now.pins.map { it.hostname }.toSet())
        assertEquals(pinsA, now.pins.first { it.hostname == "a.example.com" }.sha256)
    }

    @Test
    fun `the dashboard sends the state it loaded and reloads when told the config changed`() {
        // Tests run with demo-server/ as the working directory.
        val js = File("src/main/resources/static/js")
        val hosts = File(js, "app-hosts.js").readText()
        // Both loads of `currentConfig` remember the state…
        assertEquals(2, Regex("""currentConfigState = res\.headers\.get\('X-PinVault-State'\)""").findAll(hosts).count())
        // …the full-config save sends it back…
        val save = hosts.substringAfter("async function saveFullConfig(").substringBefore("\n// ── Force Update")
        assertTrue("'X-PinVault-Base-State': currentConfigState" in save, "saveFullConfig sends the precondition")
        // …and a stale_config answer tells the admin and loads what is there now.
        val onStale = save.substringAfter("stale.error === 'stale_config'").substringBefore("return false")
        assertTrue("toast(t('configChangedElsewhere')" in onStale && "await loadConfig()" in onStale, onStale)
        // Every full-config PUT in the dashboard carries the precondition and knows the
        // 409 (the trust-roots card had its own PUT without either).
        val puts = js.listFiles { f -> f.name.endsWith(".js") }!!.flatMap { file ->
            Regex("""apiFetch\(`/api/v1/certificate-config\?configApiId=[^`]*`, \{\s*(?://[^\n]*\n\s*)*method: 'PUT'[^\n]*""")
                .findAll(file.readText()).map { m -> Triple(file.name, m.value, file.readText().substring(m.range.last, minOf(file.readText().length, m.range.last + 1500))) }.toList()
        }
        assertEquals(2, puts.size, "saveFullConfig and saveTrustRoots: ${puts.map { it.first }}")
        puts.forEach { (name, call, after) ->
            assertTrue("'X-PinVault-Base-State'" in call, "$name: a full-config PUT without the state it was built from: $call")
            assertTrue("stale.error === 'stale_config'" in after && "configChangedElsewhere" in after, "$name: the PUT does not handle stale_config")
        }
        val i18n = File(js, "app-i18n.js").readText()
        assertEquals(2, Regex("""\bconfigChangedElsewhere:""").findAll(i18n).count(), "Turkish and English")
    }

    // ── F-2: host names ignore case ──────────────────────────────────────

    @Test
    fun `a host re-added in another case continues its version sequence`() {
        store.save(api, config(HostPin("api.bank.com", pinsA, version = 7)))
        store.save(api, config())                                    // deleted
        val saved = store.save(api, config(HostPin("Api.Bank.com", pinsB, version = 1)))
        assertEquals(8, saved.pins.single().version, "the same host to a device: above everything it has had")
        assertEquals(8, store.versionWatermark(api, "API.BANK.COM"))
        assertEquals(8, store.versionWatermark(api, "api.bank.com"))
    }

    @Test
    fun `an entry that differs from a stored host only by case is that host`() {
        store.save(api, config(HostPin("api.bank.com", pinsA, version = 5)))
        val saved = store.save(api, config(HostPin("API.bank.com", pinsB, version = 1)))
        val pin = saved.pins.single()
        assertEquals("api.bank.com", pin.hostname, "it keeps the stored spelling")
        assertEquals(6, pin.version, "and goes on from its version: changed pins, one above")
        assertEquals(1, store.load(api).pins.size)
    }

    @Test
    fun `a scope that already holds one host under two spellings is merged once, and says which`() {
        // Written before names were compared ignoring case: straight into the table.
        store.ensureConfigExists(api)
        db.connection().use { conn ->
            conn.prepareStatement("INSERT INTO pin_hashes (config_api_id, hostname, sha256, version, force_update, mtls) VALUES (?, ?, ?, ?, 0, 0)").use { stmt ->
                for ((name, version, pins) in listOf(Triple("api.bank.com", 6, pinsA), Triple("Api.Bank.com", 2, pinsB), Triple("other.example.com", 1, pinsA))) {
                    pins.forEach { pin -> stmt.setString(1, api); stmt.setString(2, name); stmt.setString(3, pin); stmt.setInt(4, version); stmt.addBatch() }
                }
                stmt.executeBatch()
            }
        }
        assertEquals(3, store.load(api).pins.size)
        val merges = mutableListOf<Pair<String, List<String>>>()
        store.onCaseMerged = { scope, spellings -> merges += scope to spellings }

        // Any save of the scope — here a force flag on every host, as the route sends it.
        val current = store.load(api)
        val saved = store.save(api, current.copy(pins = current.pins.map { it.copy(forceUpdate = true) }))

        assertEquals(listOf(api to listOf("api.bank.com", "Api.Bank.com")), merges, "both spellings are named, once")
        assertEquals(setOf("api.bank.com", "other.example.com"), saved.pins.map { it.hostname }.toSet(), "the first stored spelling stays")
        val bank = store.load(api).pins.first { it.hostname == "api.bank.com" }
        assertEquals(6, bank.version, "the newer entry is the host")
        assertEquals(pinsA, bank.sha256)

        // One spelling is left: the next save has nothing to say.
        store.save(api, store.load(api))
        assertEquals(1, merges.size)
    }

    @Test
    fun `a PUT naming a host in another case edits that host, version included`() = testApplication {
        configureApp()
        assertEquals(HttpStatusCode.OK, putPins(body("api.bank.com" to pinsA)).status)
        assertEquals(HttpStatusCode.OK, putPins(body("api.bank.com" to pinsB)).status)       // v2

        val recased = putPins(body("Api.Bank.com" to pinsA))
        assertEquals(HttpStatusCode.OK, recased.status, recased.bodyAsText())
        val pin = store.load(api).pins.single()
        assertEquals("api.bank.com", pin.hostname)
        assertEquals(3, pin.version, "the changed entry goes on from v2 — it used to restart at v1")
        assertEquals(pinsA, pin.sha256)

        // Unchanged, in yet another case: no version move.
        assertEquals(HttpStatusCode.OK, putPins(body("API.BANK.COM" to pinsA)).status)
        assertEquals(3, store.load(api).pins.single().version)

        // Deleted and re-added in another case: above the old sequence.
        assertEquals(HttpStatusCode.OK, putPins(body()).status)
        assertEquals(HttpStatusCode.OK, putPins(body("API.bank.com" to pinsB)).status)
        assertEquals(4, store.load(api).pins.single().version)
    }

    // ── Two adds of one host (review of the fixes, R-5) ──────────────────

    @Test
    fun `of two concurrent adds of one host only the one whose pins were stored installs its keystore`() {
        // Both requests plan (each generates its own key), then wait in the live
        // gate — where the handler is off the lock — until both are there.
        val bothProbing = java.util.concurrent.CyclicBarrier(2)
        val gate = LiveCertificateGate(LiveCertificateGate.Mode.WARN, probe = { _, _, _, _ ->
            runCatching { bothProbing.await(10, TimeUnit.SECONDS) }
            throw java.net.ConnectException("Connection refused")
        })
        GovernanceHarness(dir, required = 1, liveGate = gate).use { h ->
            val host = "race.example.com"
            val pool = Executors.newFixedThreadPool(2)
            val answers = try {
                (1..2).map { pool.submit<GovernanceHarness.Answer> {
                    h.call("POST", "/api/v1/hosts/generate-cert", GovernanceHarness.ALICE, """{"hostname":"$host"}""")
                } }.map { it.get(60, TimeUnit.SECONDS) }
            } finally {
                pool.shutdownNow()
            }
            assertEquals(listOf(200, 409), answers.map { it.status }.sorted(), answers.joinToString { "${it.status} ${it.body}" })
            assertTrue(answers.first { it.status == 409 }.body.contains("stale_config"))

            // The keystore on disk is the one whose pins were published: the loser used to
            // install its key file before it found out, over the winner's.
            val published = assertNotNull(h.pinsOf(host))
            val record = assertNotNull(h.hosts.get(host, h.scope))
            val keystore = com.example.pinvault.server.service.ServerKeyStores.load(File(record.keystorePath!!), CertificateService.KEYSTORE_PASSWORD.toCharArray())
            val served = LiveCertificateGate.spkiPin(keystore.getCertificate("server") as java.security.cert.X509Certificate)
            assertEquals(published.first(), served, "the host's key file is the published leaf's")
            val winner = answers.first { it.status == 200 }.json["sha256Pins"]!!.jsonArray.map { it.jsonPrimitive.content }
            assertEquals(winner, published)
            assertEquals(1, h.pins.load(h.scope).pins.count { it.hostname == host })
        }
    }
}
