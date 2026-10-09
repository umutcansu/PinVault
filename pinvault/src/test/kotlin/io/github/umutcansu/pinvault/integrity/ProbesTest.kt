package io.github.umutcansu.pinvault.integrity

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider
import io.github.umutcansu.pinvault.model.KeySecurityLevel
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The integrity probes over fake readers — positive and negative evidence
 * for each — and the shape of the report they end up in (`ATTESTATION.md` §3).
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class ProbesTest {

    private val none: (String) -> Boolean = { false }
    private val noProp: (String) -> String? = { null }

    private val userBuild: (String) -> String? = { if (it == "ro.build.type") "user" else null }

    private fun build(
        fingerprint: String = "google/shiba/shiba:15/AP3A/12345:user/release-keys",
        model: String = "Pixel 8",
        manufacturer: String = "Google",
        brand: String = "google",
        device: String = "shiba",
        product: String = "shiba",
        hardware: String = "shiba",
        tags: String? = "release-keys"
    ) = BuildInfo(fingerprint, model, manufacturer, brand, device, product, hardware, board = "shiba", tags = tags)

    // ── rooted ──────────────────────────────────────────────────────────

    @Test
    fun `a clean device raises no root evidence`() {
        val signal = RootProbe(none, "release-keys", userBuild, none, { false }, "/system/bin:/vendor/bin").probe()
        assertFalse(signal.flag)
        assertTrue(signal.evidence.isEmpty())
    }

    @Test
    fun `properties that cannot be read are an error, not clean, and raise the flag`() {
        val signal = RootProbe(none, "release-keys", noProp, none, { false }, "/system/bin").probe()
        assertTrue(signal.flag)
        assertEquals(listOf("error:prop"), signal.evidence)
    }

    @Test
    fun `an unlocked bootloader goes along as a hint and raises nothing`() {
        val props = mapOf(
            "ro.build.type" to "user", "ro.boot.verifiedbootstate" to "orange",
            "ro.boot.vbmeta.device_state" to "unlocked", "ro.boot.flash.locked" to "0"
        )
        val signal = RootProbe(none, "release-keys", { props[it] }, none, { false }, "/system/bin").probe()
        // A dev phone or custom ROM is not rooted; the server judges the bootloader from key attestation.
        assertFalse(signal.flag)
        assertEquals(listOf(
            "hint:ro.boot.verifiedbootstate=orange", "hint:ro.boot.vbmeta.device_state=unlocked", "hint:ro.boot.flash.locked=0"
        ), signal.evidence)
        // GrapheneOS / CalyxOS: locked with their own key, "yellow" — not even a hint.
        val yellow = mapOf("ro.build.type" to "user", "ro.boot.verifiedbootstate" to "yellow")
        assertTrue(RootProbe(none, "release-keys", { yellow[it] }, none, { false }, "/system/bin").probe().evidence.isEmpty())
        // A hint beside real evidence: the evidence raises the flag.
        assertTrue(RootProbe({ it == "/sbin/su" }, "release-keys", { props[it] }, none, { false }, "/system/bin").probe().flag)
        val green = mapOf("ro.build.type" to "user", "ro.boot.verifiedbootstate" to "green", "ro.boot.vbmeta.device_state" to "locked", "ro.boot.flash.locked" to "1")
        assertFalse(RootProbe(none, "release-keys", { green[it] }, none, { false }, "/system/bin").probe().flag)
    }

    @Test
    fun `su binaries, Magisk files, test-keys, properties, a writable system and root managers are evidence`() {
        val files = setOf("/system/xbin/su", "/data/adb/magisk", "/data/local/tmp/su")
        val props = mapOf("ro.build.type" to "userdebug", "ro.debuggable" to "1", "ro.secure" to "0")
        val signal = RootProbe(
            fileExists = { it in files },
            buildTags = "test-keys",
            systemProperty = { props[it] },
            packageInstalled = { it == "com.topjohnwu.magisk" },
            systemWritable = { true },
            pathEnv = "/data/local/tmp:/system/bin"
        ).probe()
        assertTrue(signal.flag)
        assertTrue(signal.evidence.toString(), signal.evidence.containsAll(listOf(
            "file:/system/xbin/su", "file:/data/adb/magisk", "path:/data/local/tmp/su", "build:test-keys",
            "prop:ro.debuggable=1", "prop:ro.secure=0", "fs:/system-writable", "package:com.topjohnwu.magisk"
        )))
    }

    @Test
    fun `one su on PATH is enough`() {
        val signal = RootProbe({ it == "/sbin/su" }, null, userBuild, none, { false }, "/sbin:/system/bin").probe()
        assertTrue(signal.flag)
        // Found under its fixed path and on PATH: reported once each, no duplicates.
        assertEquals(listOf("file:/sbin/su", "path:/sbin/su"), signal.evidence)
    }

    // ── emulator ────────────────────────────────────────────────────────

    @Test
    fun `a phone is not an emulator`() {
        val signal = EmulatorProbe(build(), noProp, none).probe()
        assertFalse(signal.flag)
        assertTrue(signal.evidence.isEmpty())
    }

    @Test
    fun `the SDK emulator, Genymotion and QEMU leave traces`() {
        val sdk = EmulatorProbe(
            build(fingerprint = "google/sdk_gphone64_arm64/emu64a:14/UE1A/1:userdebug/dev-keys",
                model = "sdk_gphone64_arm64", hardware = "ranchu", product = "sdk_gphone64_arm64"),
            { if (it == "ro.kernel.qemu") "1" else null },
            { it == "/dev/qemu_pipe" }
        ).probe()
        assertTrue(sdk.flag)
        assertTrue(sdk.evidence.toString(), sdk.evidence.any { it.startsWith("hardware:ranchu") })
        assertTrue(sdk.evidence.contains("prop:ro.kernel.qemu=1"))
        assertTrue(sdk.evidence.contains("file:/dev/qemu_pipe"))
        assertTrue(sdk.evidence.any { it.startsWith("product:") })

        val geny = EmulatorProbe(build(manufacturer = "Genymotion", hardware = "vbox86", product = "vbox86p"), noProp, none).probe()
        assertTrue(geny.flag)
        assertTrue(geny.evidence.contains("manufacturer:Genymotion"))

        val generic = EmulatorProbe(build(fingerprint = "generic/sdk/generic:9/PSR1/1:user/test-keys", model = "Android SDK built for x86"), noProp, none).probe()
        assertTrue(generic.flag)
        assertTrue(generic.evidence.any { it.startsWith("fingerprint:generic") })
        assertTrue(generic.evidence.any { it.startsWith("model:") })
    }

    // ── debugger ────────────────────────────────────────────────────────

    @Test
    fun `TracerPid is parsed from proc status`() {
        val status = "Name:\tapp\nUmask:\t0077\nState:\tS (sleeping)\nTgid:\t1234\nPid:\t1234\nTracerPid:\t4321\nUid:\t10123\n"
        assertEquals(4321, DebuggerProbe.tracerPid(status))
        assertEquals(0, DebuggerProbe.tracerPid("TracerPid:\t0\n"))
        assertNull(DebuggerProbe.tracerPid(null))
        assertNull(DebuggerProbe.tracerPid("Name:\tapp\n"))
    }

    @Test
    fun `a debugger is a connected JDWP session, a wait for one, or a tracer`() {
        assertFalse(DebuggerProbe({ false }, { false }, { "TracerPid:\t0\n" }).probe().flag)
        assertEquals(listOf("jdwp:connected"), DebuggerProbe({ true }, { false }, { null }).probe().evidence)
        assertEquals(listOf("jdwp:waiting"), DebuggerProbe({ false }, { true }, { null }).probe().evidence)
        val traced = DebuggerProbe({ false }, { false }, { "TracerPid:\t77\n" }).probe()
        assertTrue(traced.flag)
        assertEquals(listOf("tracerpid:77"), traced.evidence)
    }

    // ── debuggable ──────────────────────────────────────────────────────

    @Test
    fun `debuggable follows the application flag`() {
        assertFalse(DebuggableProbe(0).probe().flag)
        val debuggable = DebuggableProbe(android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE or android.content.pm.ApplicationInfo.FLAG_HAS_CODE).probe()
        assertTrue(debuggable.flag)
        assertEquals(listOf("flag:debuggable"), debuggable.evidence)
    }

    // ── hooking_framework ───────────────────────────────────────────────

    private fun hooking(
        maps: List<String> = listOf("/system/lib64/libc.so", "/data/app/~~x/com.example-1/lib/arm64/libapp.so", "[anon:dalvik-main space]"),
        threads: List<String> = listOf("main", "RenderThread", "OkHttp Dispatcher", "Binder:1234_1"),
        vxp: String? = null,
        loadable: Set<String> = emptySet(),
        stack: List<String> = listOf("java.lang.Thread", "com.example.App"),
        ports: List<Int> = emptyList()
    ) = HookingProbe({ maps }, { threads }, { if (it == "vxp") vxp else null }, { it in loadable }, { stack }, { ports }).probe()

    @Test
    fun `an unhooked process shows nothing`() {
        val signal = hooking()
        assertFalse(signal.flag)
        assertTrue(signal.evidence.isEmpty())
    }

    @Test
    fun `Frida in the maps and its threads are evidence`() {
        val signal = hooking(
            maps = listOf("/system/lib64/libc.so", "/data/local/tmp/re.frida.server/frida-agent-64.so"),
            threads = listOf("main", "gmain", "gum-js-loop", "pool-frida")
        )
        assertTrue(signal.flag)
        assertEquals(listOf("maps:frida", "thread:gmain", "thread:gum-js-loop", "thread:pool-frida"), signal.evidence)
    }

    @Test
    fun `maps that cannot be read are an error, not clean, and raise the flag`() {
        val unread = HookingProbe({ null }, { listOf("main") }, { null }, { false }, { emptyList() }, { emptyList() }).probe()
        assertTrue(unread.flag)
        assertEquals(listOf("error:maps"), unread.evidence)
        val threads = HookingProbe({ null }, { listOf("gum-js-loop") }, { null }, { false }, { emptyList() }, { emptyList() }).probe()
        assertTrue(threads.flag)
    }

    @Test
    fun `a frida-server port open on loopback is evidence`() {
        val signal = hooking(ports = listOf(27042))
        assertTrue(signal.flag)
        assertEquals(listOf("port:27042"), signal.evidence)
    }

    @Test
    fun `the loopback port check reports only ports that accept a connection`() {
        java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1")).use { server ->
            val closed = java.net.ServerSocket(0).use { it.localPort }
            assertEquals(listOf(server.localPort), ProcReaders.listeningLoopbackPorts(listOf(server.localPort, closed)))
        }
    }

    @Test
    fun `Xposed, VirtualXposed and other frameworks are evidence`() {
        val signal = hooking(
            maps = listOf("/system/framework/XposedBridge.jar", "/data/adb/modules/zygisk_lsposed/lib/liblsposed.so", "/data/app/libsubstrate.so", "/x/libdobby.so", "/x/libriru.so"),
            vxp = "1",
            loadable = setOf("de.robv.android.xposed.XposedBridge"),
            stack = listOf("de.robv.android.xposed.XposedBridge", "com.example.App")
        )
        assertTrue(signal.flag)
        assertTrue(signal.evidence.toString(), signal.evidence.containsAll(listOf(
            "maps:xposed", "maps:lsposed", "maps:substrate", "maps:dobby", "maps:riru",
            "property:vxp", "class:de.robv.android.xposed.XposedBridge", "stack:xposed"
        )))
    }

    // ── app_integrity ───────────────────────────────────────────────────

    @Test
    fun `app_integrity is judged on the device only when the app named its signers`() {
        val signer = "a".repeat(64)
        assertFalse(AppIntegrityProbe(listOf(signer), emptySet()).probe().flag)
        assertFalse(AppIntegrityProbe(listOf(signer), setOf(signer)).probe().flag)
        assertFalse(AppIntegrityProbe(listOf("b".repeat(64), signer), setOf(signer, "c".repeat(64))).probe().flag)

        val wrong = AppIntegrityProbe(listOf("b".repeat(64)), setOf(signer)).probe()
        assertTrue(wrong.flag)
        assertEquals(listOf("signer:bbbbbbbbbbbbbbbb"), wrong.evidence)

        val unreadable = AppIntegrityProbe(emptyList(), setOf(signer)).probe()
        assertTrue(unreadable.flag)
        assertEquals(listOf("signer:unreadable"), unreadable.evidence)
    }

    // ── cloner ──────────────────────────────────────────────────────────

    @Test
    fun `the app in its own directories is not cloned`() {
        for (dataDir in listOf("/data/user/0/com.example.app", "/data/data/com.example.app", "/data/user/10/com.example.app/", "/data/user_de/0/com.example.app")) {
            val signal = ClonerProbe("com.example.app", dataDir, "$dataDir/files".replace("//", "/"), "/data/app/~~abc/com.example.app-xyz/lib/arm64").probe()
            assertFalse(dataDir, signal.flag)
        }
    }

    @Test
    fun `a cloner's directories are evidence`() {
        val signal = ClonerProbe(
            "com.example.app",
            dataDir = "/data/user/0/com.cloner.space/virtual/data/user/0/com.example.app",
            filesDir = "/data/user/0/com.cloner.space/virtual/data/user/0/com.example.app/files",
            nativeLibraryDir = "/data/user/0/com.cloner.space/virtual/data/app/com.example.app-1/lib/arm64"
        ).probe()
        assertTrue(signal.flag)
        assertTrue(signal.evidence.any { it.startsWith("datadir:") })
        assertTrue(signal.evidence.toString(), signal.evidence.any { it.startsWith("nativelib:") })

        val foreignFiles = ClonerProbe("com.example.app", "/data/user/0/com.example.app", "/data/user/0/com.other/files", null).probe()
        assertTrue(foreignFiles.flag)
        assertEquals(listOf("filesdir:/data/user/0/com.other/files"), foreignFiles.evidence)
    }

    // ── unknown_installer ───────────────────────────────────────────────

    @Test
    fun `stores are known, anything else is not, no installer is a sideload`() {
        assertFalse(InstallerProbe("com.android.vending").probe().flag)
        assertFalse(InstallerProbe("com.sec.android.app.samsungapps").probe().flag)
        assertFalse(InstallerProbe("com.huawei.appmarket").probe().flag)
        assertFalse(InstallerProbe("com.amazon.venezia").probe().flag)
        assertEquals(listOf("installer:com.example.store"), InstallerProbe("com.example.store").probe().evidence)
        assertEquals(listOf("sideload"), InstallerProbe(null).probe().evidence)
        assertEquals(listOf("sideload"), InstallerProbe("  ").probe().evidence)
        assertFalse(InstallerProbe("com.example.store", allowed = setOf("com.example.store")).probe().flag)
    }

    // ── adb_enabled ─────────────────────────────────────────────────────

    @Test
    fun `adb and developer settings`() {
        assertFalse(AdbProbe(0, 0).probe().flag)
        assertFalse(AdbProbe(null, null).probe().flag)
        assertEquals(listOf("settings:adb_enabled"), AdbProbe(1, 0).probe().evidence)
        assertEquals(listOf("settings:development_settings_enabled"), AdbProbe(0, 1).probe().evidence)
        assertEquals(2, AdbProbe(1, 1).probe().evidence.size)
    }

    // ── software_key / key_unattested ───────────────────────────────────

    @Test
    fun `key signals follow the key's level and chain`() {
        assertFalse(KeyProbe(KeySecurityLevel.STRONGBOX, true).softwareKey().flag)
        assertFalse(KeyProbe(KeySecurityLevel.TRUSTED_ENVIRONMENT, true).softwareKey().flag)
        assertEquals(listOf("key:software"), KeyProbe(KeySecurityLevel.SOFTWARE, true).softwareKey().evidence)
        assertEquals(listOf("key:unknown"), KeyProbe(KeySecurityLevel.UNKNOWN, true).softwareKey().evidence)
        assertFalse(KeyProbe(KeySecurityLevel.STRONGBOX, true).keyUnattested().flag)
        assertEquals(listOf("key:no-attestation-chain"), KeyProbe(KeySecurityLevel.STRONGBOX, false).keyUnattested().evidence)
    }

    // ── The report ──────────────────────────────────────────────────────

    @Test
    fun `the report has every block and every signal of the design, and a verdict when a provider gives one`() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val key = ClientIdentityKeyProvider.software("probes-test-${System.nanoTime()}")
        key.ensureKeyPair()
        var askedWith: String? = null
        val provider = object : IntegrityVerdictProvider {
            override suspend fun verdict(nonce: String): IntegrityVerdict? {
                askedWith = nonce
                return IntegrityVerdict("play-integrity", "eyJ.token")
            }
        }

        val report = DeviceIntegrityProbe(context, verdictProvider = provider, clock = { 1_759_660_801_234L }).report("nonce-1", key)
        val json = JSONObject(report.toJsonString())

        assertEquals("nonce-1", askedWith)
        assertEquals(IntegrityReport.SDK_VERSION, json.getString("sdkVersion"))
        assertEquals(1_759_660_801_234L, json.getLong("reportTime"))

        val app = json.getJSONObject("app")
        assertEquals(context.packageName, app.getString("packageName"))
        for (field in listOf("versionCode", "versionName", "signerSha256", "installer", "debuggable")) {
            assertTrue("app.$field", app.has(field))
        }
        assertNotNull(app.getJSONArray("signerSha256"))

        val device = json.getJSONObject("device")
        for (field in listOf("manufacturer", "model", "brand", "device", "product", "hardware", "fingerprint", "sdkInt",
            "securityPatch", "verifiedBootState", "keySecurityLevel", "keyAttested")) {
            assertTrue("device.$field", device.has(field))
        }
        assertEquals("software", device.getString("keySecurityLevel"))
        assertFalse(device.getBoolean("keyAttested"))

        val signals = json.getJSONObject("signals")
        assertEquals(IntegrityReport.SIGNAL_KEYS.toSet(), signals.keys().asSequence().toSet())
        IntegrityReport.SIGNAL_KEYS.forEach { name ->
            val signal = signals.getJSONObject(name)
            signal.getBoolean("flag")
            assertNotNull(signal.getJSONArray("evidence"))
        }
        // A software key without a chain: both key signals are up, with their evidence.
        assertTrue(signals.getJSONObject("software_key").getBoolean("flag"))
        assertTrue(signals.getJSONObject("key_unattested").getBoolean("flag"))
        // Decided by the server.
        assertFalse(signals.getJSONObject("old_patch_level").getBoolean("flag"))

        val verdict = json.getJSONObject("verdictProvider")
        assertEquals("play-integrity", verdict.getString("name"))
        assertEquals("eyJ.token", verdict.getString("token"))
    }

    @Test
    fun `a provider that fails or answers nothing leaves the report without a verdict`() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val failing = object : IntegrityVerdictProvider {
            override suspend fun verdict(nonce: String): IntegrityVerdict? = throw IllegalStateException("no play services")
        }
        assertFalse(JSONObject(DeviceIntegrityProbe(context, verdictProvider = failing).report("n", null).toJsonString()).has("verdictProvider"))
        assertFalse(JSONObject(DeviceIntegrityProbe(context).report("n", null).toJsonString()).has("verdictProvider"))
        // No key: unknown level, unattested — reported, not a crash.
        val device = JSONObject(DeviceIntegrityProbe(context).report("n", null).toJsonString()).getJSONObject("device")
        assertEquals("unknown", device.getString("keySecurityLevel"))
    }

    @Test
    fun `a provider built before verdict(nonce, deviceId) is asked with the nonce alone`() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val asked = mutableListOf<String>()
        val old = object : IntegrityVerdictProvider {
            override suspend fun verdict(nonce: String): IntegrityVerdict? { asked += nonce; return IntegrityVerdict("x", "t") }
            // What a provider compiled against the older interface does when the new method is called.
            override suspend fun verdict(nonce: String, deviceId: String): IntegrityVerdict? = throw AbstractMethodError()
        }
        val json = JSONObject(DeviceIntegrityProbe(context, verdictProvider = old).report("n", null, deviceId = "d").toJsonString())
        assertEquals(listOf("n"), asked)
        assertEquals("x", json.getJSONObject("verdictProvider").getString("name"))
    }

    @Test
    fun `app_integrity on the device follows expectedSignerSha256`() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        // Robolectric's package has no readable signer: with an expectation the flag is up ("unreadable"), without one it stays down.
        val judged = JSONObject(DeviceIntegrityProbe(context, expectedSignerSha256 = setOf("a".repeat(64))).report("n", null).toJsonString())
        assertTrue(judged.getJSONObject("signals").getJSONObject("app_integrity").getBoolean("flag"))
        val notJudged = JSONObject(DeviceIntegrityProbe(context).report("n", null).toJsonString())
        assertFalse(notJudged.getJSONObject("signals").getJSONObject("app_integrity").getBoolean("flag"))
    }

    @Test
    fun `digests are normalised and shown with colons`() {
        assertEquals("3c4f" + "ab".repeat(30), normalizeSha256Hex("3C:4F:" + "AB:".repeat(29) + "AB"))
        assertEquals("a".repeat(64), normalizeSha256Hex("sha256:" + "A".repeat(64)))
        assertNull(normalizeSha256Hex("not-a-digest"))
        assertNull(normalizeSha256Hex("a".repeat(63)))
        assertEquals("3c:4f:ab", colonHex("3c4fab"))
        assertEquals("00ff10", hex(byteArrayOf(0, -1, 16)))
    }
}
