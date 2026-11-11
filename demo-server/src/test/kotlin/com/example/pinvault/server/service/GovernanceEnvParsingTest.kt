package com.example.pinvault.server.service

import com.example.pinvault.server.managementBindAddress
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pre-production review, F-3 / F-4 / F-5.
 *
 * F-3: a governance setting that did not parse used to turn its control off
 * without a word — `PIN_CHANGE_APPROVALS=two` meant no second admin,
 * `PIN_LIVE_CHECK=enforced` no live check, `PIN_LIVE_CHECK_ALLOW_OVERRIDE=False`
 * an open override. Now the start is refused, naming the setting.
 *
 * F-4: any start-up failure with dashboard settings saved used to set ALL of
 * them aside. Whether the saved settings are at fault is now decided by
 * reading them again ([SavedSettingsCheck]), before anything is listened on.
 *
 * F-5: the management listener (plain HTTP) binds this machine only unless
 * `MANAGEMENT_BIND` says otherwise, with admin keys as without.
 */
class GovernanceEnvParsingTest {

    private val dir: File = Files.createTempDirectory("governance-env").toFile()

    @AfterTest
    fun cleanUp() { dir.deleteRecursively() }

    private fun refused(setting: String, block: () -> Unit) {
        val e = assertFailsWith<IllegalStateException> { block() }
        assertTrue(e.message!!.contains(setting), "the message names the setting: ${e.message}")
    }

    // ── F-3 ──────────────────────────────────────────────────────────────

    @Test
    fun `PIN_CHANGE_APPROVALS - unset is 1, a number in range is taken, anything else stops the start`() {
        assertEquals(1, ApprovalService.requiredFromEnv(emptyMap()))
        assertEquals(1, ApprovalService.requiredFromEnv(mapOf("PIN_CHANGE_APPROVALS" to "  ")), "compose passes an empty value for unset")
        assertEquals(2, ApprovalService.requiredFromEnv(mapOf("PIN_CHANGE_APPROVALS" to " 2 ")))
        for (bad in listOf("two", "2 admins", "0", "-1", "6", "2.0", "0x2")) {
            refused("PIN_CHANGE_APPROVALS") { ApprovalService.requiredFromEnv(mapOf("PIN_CHANGE_APPROVALS" to bad)) }
        }
    }

    @Test
    fun `PIN_LIVE_CHECK - only off, warn and enforce, in any case`() {
        assertEquals(LiveCertificateGate.Mode.OFF, LiveCertificateGate.modeFromEnv(emptyMap()))
        assertEquals(LiveCertificateGate.Mode.OFF, LiveCertificateGate.modeFromEnv(mapOf("PIN_LIVE_CHECK" to "")))
        assertEquals(LiveCertificateGate.Mode.OFF, LiveCertificateGate.modeFromEnv(mapOf("PIN_LIVE_CHECK" to "Off")))
        assertEquals(LiveCertificateGate.Mode.WARN, LiveCertificateGate.modeFromEnv(mapOf("PIN_LIVE_CHECK" to " WARN ")))
        assertEquals(LiveCertificateGate.Mode.ENFORCE, LiveCertificateGate.modeFromEnv(mapOf("PIN_LIVE_CHECK" to "Enforce")))
        for (bad in listOf("enforced", "on", "true", "strict", "1")) {
            refused("PIN_LIVE_CHECK") { LiveCertificateGate.fromEnv(mapOf("PIN_LIVE_CHECK" to bad)) }
        }
    }

    @Test
    fun `PIN_LIVE_CHECK_ALLOW_OVERRIDE - only true and false, in any case`() {
        assertTrue(LiveCertificateGate.fromEnv(emptyMap()).allowOverride)
        assertTrue(LiveCertificateGate.fromEnv(mapOf("PIN_LIVE_CHECK_ALLOW_OVERRIDE" to "TRUE")).allowOverride)
        assertFalse(LiveCertificateGate.fromEnv(mapOf("PIN_LIVE_CHECK_ALLOW_OVERRIDE" to "false")).allowOverride)
        // "False" used to leave the override open: only the exact word closed it.
        assertFalse(LiveCertificateGate.fromEnv(mapOf("PIN_LIVE_CHECK_ALLOW_OVERRIDE" to " False ")).allowOverride)
        for (bad in listOf("no", "0", "off", "disabled")) {
            refused("PIN_LIVE_CHECK_ALLOW_OVERRIDE") { LiveCertificateGate.fromEnv(mapOf("PIN_LIVE_CHECK_ALLOW_OVERRIDE" to bad)) }
        }
    }

    @Test
    fun `CONFIG_TTL_SECONDS - a minute to thirty days`() {
        assertEquals(86_400_000L, SignedConfigService.ttlFromEnv(emptyMap()))
        assertEquals(60_000L, SignedConfigService.ttlFromEnv(mapOf("CONFIG_TTL_SECONDS" to "60")))
        assertEquals(2_592_000_000L, SignedConfigService.ttlFromEnv(mapOf("CONFIG_TTL_SECONDS" to " 2592000 ")))
        // 0 and negatives expired every config as it was signed; more than 30 days no device accepts.
        for (bad in listOf("0", "-60", "59", "2592001", "99999999999999999999", "1d", "24h")) {
            refused("CONFIG_TTL_SECONDS") { SignedConfigService.ttlFromEnv(mapOf("CONFIG_TTL_SECONDS" to bad)) }
        }
    }

    @Test
    fun `RECOVERY_REQUIRED_SIGNATURES - a number the configured keys can reach`() {
        val keys = mapOf("RECOVERY_PUBLIC_KEYS" to "k1,k2, k3")
        assertEquals(1, SigningKeySetService.recoveryThresholdFromEnv(keys))
        assertEquals(2, SigningKeySetService.recoveryThresholdFromEnv(keys + ("RECOVERY_REQUIRED_SIGNATURES" to " 2 ")))
        assertEquals(3, SigningKeySetService.recoveryThresholdFromEnv(keys + ("RECOVERY_REQUIRED_SIGNATURES" to "3")))
        // "2 of 3" written out used to count as 1 of 3.
        for (bad in listOf("two", "2/3", "0", "-1", "4")) {
            refused("RECOVERY_REQUIRED_SIGNATURES") { SigningKeySetService.recoveryThresholdFromEnv(keys + ("RECOVERY_REQUIRED_SIGNATURES" to bad)) }
        }
    }

    // ── F-4 ──────────────────────────────────────────────────────────────

    private val hash = "ab".repeat(32)
    private val sharedOnly = mapOf("API_KEY" to "shared-key-0123456789")
    private val twoAdmins = sharedOnly + ("ADMIN_KEYS" to "alice:$hash,bob:$hash")

    @Test
    fun `saved settings that read fine are not what stops a start, whatever else fails`() {
        // Approvals on and the live check enforced, saved from the dashboard: a port in
        // use or a busy database is not theirs, and nothing is set aside.
        val saved = mapOf("PIN_CHANGE_APPROVALS" to "2", "PIN_LIVE_CHECK" to "enforce", "CONFIG_TTL_SECONDS" to "43200")
        assertEquals(emptyList(), SavedSettingsCheck.problems(saved, env = twoAdmins))

        val store = ServerSettingsStore(File(dir, "server-settings.json"))
        store.save(saved)
        // What main() does before it listens: nothing to reject, the values stay.
        assertTrue(SavedSettingsCheck.problems(store.read().values, env = twoAdmins).isEmpty())
        assertEquals(saved, store.values())
        assertEquals(null, store.read().rejected)
    }

    @Test
    fun `approvals without a personal admin key to approve would not start - refused at the save and found before the start`() {
        // Main's own rule (ApprovalService.adminKeysProblem). Saved on a server with only a
        // shared API_KEY it used to pass the save, then stop every start — and the saved
        // settings were kept: a restart loop with no dashboard to undo it.
        assertTrue(ServerSettingsCatalog.startProblems(sharedOnly + ("PIN_CHANGE_APPROVALS" to "2")).single().contains("personal admin key"))
        assertTrue(ServerSettingsCatalog.startProblems(mapOf("PIN_CHANGE_APPROVALS" to "2")).single().contains("without admin keys"))
        assertEquals(emptyList(), ServerSettingsCatalog.startProblems(twoAdmins + ("PIN_CHANGE_APPROVALS" to "2")))
        assertEquals(emptyList(), ServerSettingsCatalog.startProblems(twoAdmins + ("PIN_CHANGE_APPROVALS" to "3")))
        assertEquals(1, ServerSettingsCatalog.startProblems(twoAdmins + ("PIN_CHANGE_APPROVALS" to "4")).size, "three approvers needed, two keys")
        assertEquals(emptyList(), ServerSettingsCatalog.startProblems(sharedOnly + ("PIN_CHANGE_APPROVALS" to "1")))

        // The save (PUT /api/v1/server-settings and its approval card plan with this): would_not_start.
        val values = kotlinx.serialization.json.buildJsonObject { put("PIN_CHANGE_APPROVALS", kotlinx.serialization.json.JsonPrimitive("2")) }
        val refusedSave = ServerSettingsChange.plan(emptyMap(), values, env = sharedOnly)
        assertTrue(refusedSave.errors.isEmpty())
        assertTrue(refusedSave.startProblems.single().contains("PIN_CHANGE_APPROVALS=2"), refusedSave.startProblems.toString())
        assertTrue(ServerSettingsChange.plan(emptyMap(), values, env = twoAdmins).startProblems.isEmpty())

        // A file saved before this rule (or with the admin keys taken away since): theirs, found before the start.
        val found = SavedSettingsCheck.problems(mapOf("PIN_CHANGE_APPROVALS" to "2", "PIN_LIVE_CHECK" to "warn"), env = sharedOnly)
        assertTrue(found.single().contains("PIN_CHANGE_APPROVALS=2"), found.toString())
        // Set in the environment the same mistake is the environment's: nothing saved is blamed.
        assertEquals(emptyList(), SavedSettingsCheck.problems(mapOf("PIN_LIVE_CHECK" to "warn"), env = sharedOnly + ("PIN_CHANGE_APPROVALS" to "2")))
    }

    @Test
    fun `a saved value the catalog no longer accepts is left out on its own, the rest stays in force`() {
        // A hand-edited file, or a range that changed with an upgrade (R-2): only that
        // value goes, with a warning — not PIN_CHANGE_APPROVALS=2 along with it.
        val store = ServerSettingsStore(File(dir, "server-settings.json"))
        store.save(mapOf("PIN_CHANGE_APPROVALS" to "2", "PIN_LIVE_CHECK" to "enforced", "CONFIG_TTL_SECONDS" to "5", "GONE_SETTING" to "x"))
        val saved = store.read().values

        val warnings = SavedSettingsCheck.dropped(saved)
        assertEquals(3, warnings.size, warnings.toString())
        assertTrue(warnings.any { it.startsWith("PIN_LIVE_CHECK:") } && warnings.any { it.startsWith("CONFIG_TTL_SECONDS:") } && warnings.any { it.startsWith("GONE_SETTING:") })
        assertEquals(emptyList(), SavedSettingsCheck.problems(saved, env = twoAdmins), "nothing is rejected for them")
        assertEquals(mapOf("PIN_CHANGE_APPROVALS" to "2"), store.values(), "the valid ones are what the start reads")
        assertEquals(null, store.read().rejected)
        assertEquals(emptyList(), SavedSettingsCheck.dropped(mapOf("PIN_LIVE_CHECK" to "warn")))
    }

    @Test
    fun `saved settings that would not start together are theirs, a failing environment is not`() {
        // enforce without the app it binds to: the saved settings' fault.
        val together = SavedSettingsCheck.problems(mapOf("ENROLLMENT_ATTESTATION" to "enforce"), env = emptyMap())
        assertEquals(1, together.size)
        assertTrue(together.single().contains("ENROLLMENT_ATTESTATION"))

        // The environment already fails on its own (F-3): the saved settings are not blamed for it…
        assertEquals(emptyList(), SavedSettingsCheck.problems(mapOf("CONFIG_TTL_SECONDS" to "600"), env = mapOf("PIN_CHANGE_APPROVALS" to "two")))
        // …and a saved value the environment overrides is not read at all.
        assertEquals(emptyList(), SavedSettingsCheck.problems(mapOf("PIN_LIVE_CHECK" to "warn"), env = mapOf("PIN_LIVE_CHECK" to "nonsense")))
        assertEquals(emptyList(), SavedSettingsCheck.problems(mapOf("PIN_LIVE_CHECK" to "enforce"), env = mapOf("PIN_LIVE_CHECK" to "warn")))
    }

    @Test
    fun `a parser that fails only with the saved values is attributed to them`() {
        val parsers: List<Pair<String, (Map<String, String>) -> Unit>> = listOf(
            "ATTESTATION_TOKEN_TTL_SECONDS" to { env -> check(env["ATTESTATION_TOKEN_TTL_SECONDS"] != "77") { "77 is not accepted here" } }
        )
        assertEquals(
            listOf("ATTESTATION_TOKEN_TTL_SECONDS: 77 is not accepted here"),
            SavedSettingsCheck.problems(mapOf("ATTESTATION_TOKEN_TTL_SECONDS" to "77"), env = emptyMap(), parsers = parsers)
        )
        assertEquals(emptyList(), SavedSettingsCheck.problems(mapOf("ATTESTATION_TOKEN_TTL_SECONDS" to "78"), env = emptyMap(), parsers = parsers))
    }

    @Test
    fun `every value the dashboard can save is read without complaint by the start-up's parsers`() {
        // The catalog's choices and ranges must stay inside what the start-up accepts:
        // a value the save takes and the start refuses is a restart loop.
        for (setting in ServerSettingsCatalog.all) {
            val samples = when (setting.kind) {
                ServerSetting.Kind.BOOL -> listOf("true", "false")
                ServerSetting.Kind.CHOICE -> setting.choices
                ServerSetting.Kind.NUMBER -> listOf(setting.min.toString(), setting.max.toString())
                ServerSetting.Kind.TEXT -> emptyList()
            }
            for (value in samples) {
                // Cross-setting rules (enforce needs the app binding, approvals need approvers) are
                // startProblems' business; here only "does a parser choke on this value".
                val env = twoAdmins + mapOf(
                    "ATTESTATION_PACKAGE_NAMES" to "com.example.app", "ATTESTATION_SIGNER_SHA256" to hash,
                    "INTEGRITY_VERIFIER_COMMAND" to "/bin/true", "ADMIN_KEYS" to "a:$hash,b:$hash,c:$hash,d:$hash"
                )
                val problems = SavedSettingsCheck.problems(mapOf(setting.key to value), env = env)
                    .filterNot { setting.key.startsWith("ATTESTATION_FRESH_") }   // its own rule: an interval under a minute
                assertEquals(emptyList(), problems, "${setting.key}=$value")
            }
        }
    }

    // ── The safety net: failed starts in a row (review of the fixes, R-1 b) ──

    @Test
    fun `one or two failed starts keep the saved settings, the third in a row sets them aside`() {
        val store = ServerSettingsStore(File(dir, "server-settings.json"))
        val saved = mapOf("PIN_CHANGE_APPROVALS" to "2", "PIN_LIVE_CHECK" to "enforce")
        store.save(saved)

        // A port still in use, twice: counted, nothing touched.
        assertEquals(ServerSettingsStore.FailedStart(1, false), store.startFailed("Address already in use"))
        assertEquals(ServerSettingsStore.FailedStart(2, false), store.startFailed("Address already in use"))
        assertEquals(saved, store.values())
        assertEquals(2, store.read().failedStarts)
        assertEquals(null, store.read().rejected)

        // Then the server comes up: the count starts again.
        store.startSucceeded()
        assertEquals(0, store.read().failedStarts)
        assertEquals(saved, store.values())

        // Three in a row — something a saved value does that no check models: set aside, as
        // any failure used to do at once, so the next start runs without them.
        assertEquals(1, store.startFailed("boom").attempt)
        assertEquals(2, store.startFailed("boom").attempt)
        assertEquals(ServerSettingsStore.FailedStart(3, true), store.startFailed("boom"))
        assertEquals(emptyMap(), store.values())
        val rejected = store.read().rejected!!
        assertEquals(saved, rejected.values, "kept to show")
        assertTrue(rejected.reason.contains("3 starts in a row") && rejected.reason.contains("boom"), rejected.reason)
        assertEquals(0, store.read().failedStarts)

        // With nothing saved there is nothing to protect or to blame: not counted.
        assertEquals(ServerSettingsStore.FailedStart(0, false), store.startFailed("boom"))
        assertEquals(0, store.read().failedStarts)
        // A new save after that starts from zero.
        store.save(mapOf("PIN_LIVE_CHECK" to "warn"))
        assertEquals(1, store.startFailed("boom").attempt)
    }

    @Test
    fun `the count survives the file as written and is reset by the listener coming up`() {
        val file = File(dir, "server-settings.json")
        ServerSettingsStore(file).apply { save(mapOf("PIN_LIVE_CHECK" to "warn")); startFailed("x") }
        // Another process (the next start) reads it back.
        assertEquals(1, ServerSettingsStore(file).read().failedStarts)

        // ServerReady is what main() resets the count on: raised once the connector is bound.
        val store = ServerSettingsStore(file)
        val up = java.util.concurrent.CountDownLatch(1)
        val server = io.ktor.server.engine.embeddedServer(io.ktor.server.netty.Netty, port = java.net.ServerSocket(0).use { it.localPort }, host = "127.0.0.1") {}
        server.monitor.subscribe(io.ktor.server.application.ServerReady) { store.startSucceeded(); up.countDown() }
        try {
            server.start(wait = false)
            assertTrue(up.await(20, java.util.concurrent.TimeUnit.SECONDS), "ServerReady was raised")
            assertEquals(0, store.read().failedStarts)
            assertEquals(mapOf("PIN_LIVE_CHECK" to "warn"), store.values())
        } finally {
            server.stop(100, 1000)
        }
    }

    // ── F-5 ──────────────────────────────────────────────────────────────

    @Test
    fun `the management listener binds this machine only unless MANAGEMENT_BIND says otherwise`() {
        assertEquals("127.0.0.1", managementBindAddress(null))
        assertEquals("127.0.0.1", managementBindAddress("  "))
        assertEquals("0.0.0.0", managementBindAddress(" 0.0.0.0 "))
        assertEquals("192.168.1.80", managementBindAddress("192.168.1.80"))
    }

    @Test
    fun `every setup that is reached from outside the process sets MANAGEMENT_BIND itself`() {
        // Tests run with demo-server/ as the working directory.
        val repo = File("..").canonicalFile
        val compose = File("docker-compose.yml").readText()
        assertTrue(Regex("""MANAGEMENT_BIND=\$\{MANAGEMENT_BIND:-0\.0\.0\.0}""").containsMatchIn(compose), "demo-server/docker-compose.yml")
        File(repo, "sample-host/docker-compose.yml").takeIf { it.isFile }?.let {
            assertTrue(Regex("""MANAGEMENT_BIND:\s*\$\{MANAGEMENT_BIND:-0\.0\.0\.0}""").containsMatchIn(it.readText()), "sample-host/docker-compose.yml")
        }
        // The Espresso server is reached by emulators on the LAN address.
        File(repo, ".claude/launch.json").takeIf { it.isFile }?.let { launch ->
            val espresso = launch.readText().substringAfter("\"demo-server-espresso\"").substringBefore("\"name\"")
            assertTrue("MANAGEMENT_BIND=0.0.0.0" in espresso, ".claude/launch.json demo-server-espresso")
        }
    }
}
