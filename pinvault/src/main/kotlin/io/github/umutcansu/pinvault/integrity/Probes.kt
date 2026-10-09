package io.github.umutcansu.pinvault.integrity

import io.github.umutcansu.pinvault.model.KeySecurityLevel
import java.io.File

/*
 * The probes behind the report's `signals` (`ATTESTATION.md` §3). Each one is
 * a small class over plain inputs or reader lambdas, so the decision can be
 * tested without a device; `DeviceIntegrityProbe` wires the real readers in.
 * None of them throws on its own account, and none claims "clean" for what it
 * could not look at: a reader that fails is caught by the orchestrator and
 * becomes `error:<probe>` evidence.
 */

/**
 * `ro.*` system properties, read through `android.os.SystemProperties`, or
 * through `getprop` where reflection is refused; null when unreadable or empty.
 */
internal object SystemProperties {
    /** `ro.*` values never change while the process lives: read once each. */
    private val cache = java.util.concurrent.ConcurrentHashMap<String, Optional>()

    private class Optional(val value: String?)

    fun get(name: String): String? = cache.getOrPut(name) { Optional(read(name)) }.value

    /** Reflection first; `getprop` only where reflection is refused (not for a property that is merely absent). */
    private fun read(name: String): String? {
        val viaReflection = try {
            val clazz = Class.forName("android.os.SystemProperties")
            val get = clazz.getMethod("get", String::class.java)
            Result.success(get.invoke(null, name) as? String)
        } catch (e: Throwable) {
            Result.failure(e)
        }
        if (viaReflection.isSuccess) return viaReflection.getOrNull()?.trim()?.ifEmpty { null }
        return viaGetprop(name)
    }

    private fun viaGetprop(name: String): String? = try {
        if (!PROP_NAME.matches(name)) null
        else {
            val process = ProcessBuilder("getprop", name).redirectErrorStream(true).start()
            // Process.waitFor(timeout) is API 26; minSdk is 24.
            val deadline = System.nanoTime() + GETPROP_TIMEOUT_MS * 1_000_000
            var exit: Int? = null
            while (exit == null && System.nanoTime() < deadline) {
                exit = try { process.exitValue() } catch (_: IllegalThreadStateException) { Thread.sleep(10); null }
            }
            if (exit == null) {
                process.destroy()
                null
            } else {
                val value = process.inputStream.bufferedReader().use { it.readText() }
                if (exit == 0) value.trim().ifEmpty { null } else null
            }
        }
    } catch (_: Throwable) {
        null
    }

    private const val GETPROP_TIMEOUT_MS = 500L

    private val PROP_NAME = Regex("^[A-Za-z0-9._-]{1,92}$")
}

/** The `Build` fields the emulator probe looks at, and the report's `device` block. */
internal class BuildInfo(
    val fingerprint: String,
    val model: String,
    val manufacturer: String,
    val brand: String,
    val device: String,
    val product: String,
    val hardware: String,
    val board: String,
    val tags: String?
) {
    companion object {
        fun current() = BuildInfo(
            fingerprint = android.os.Build.FINGERPRINT ?: "",
            model = android.os.Build.MODEL ?: "",
            manufacturer = android.os.Build.MANUFACTURER ?: "",
            brand = android.os.Build.BRAND ?: "",
            device = android.os.Build.DEVICE ?: "",
            product = android.os.Build.PRODUCT ?: "",
            hardware = android.os.Build.HARDWARE ?: "",
            board = android.os.Build.BOARD ?: "",
            tags = android.os.Build.TAGS
        )
    }
}

/**
 * `rooted`: `su` in the usual places and on `PATH`, Magisk / KernelSU /
 * APatch files, `test-keys`, `ro.debuggable=1`, `ro.secure=0`, a writable
 * `/system`, a root manager installed.
 */
internal class RootProbe(
    private val fileExists: (String) -> Boolean,
    private val buildTags: String?,
    private val systemProperty: (String) -> String?,
    private val packageInstalled: (String) -> Boolean,
    private val systemWritable: () -> Boolean,
    private val pathEnv: String?
) {
    fun probe(): Signal {
        val evidence = mutableListOf<String>()
        SU_PATHS.filter(fileExists).forEach { evidence += "file:$it" }
        ROOT_FILES.filter(fileExists).forEach { evidence += "file:$it" }
        pathEnv?.split(':')?.filter { it.isNotBlank() }?.distinct()?.forEach { dir ->
            if (fileExists("$dir/su")) evidence += "path:$dir/su"
        }
        if (buildTags?.contains("test-keys") == true) evidence += "build:test-keys"
        // Every build sets ro.build.type: when even it reads as nothing, the
        // properties below were not looked at, which is not "clean".
        if (systemProperty("ro.build.type") == null) evidence += "error:prop"
        if (systemProperty("ro.debuggable") == "1") evidence += "prop:ro.debuggable=1"
        if (systemProperty("ro.secure") == "0") evidence += "prop:ro.secure=0"
        // An unlocked bootloader is not root: dev phones and custom ROMs have
        // one, and GrapheneOS / CalyxOS boot "yellow" with it locked. These go
        // along as hints that raise nothing; the server judges the same facts
        // from key attestation (bootloader_unlocked, boot_not_verified,
        // ATTESTATION_TRUSTED_BOOT_KEYS).
        systemProperty("ro.boot.verifiedbootstate")?.lowercase()?.takeIf { it in UNVERIFIED_BOOT_STATES }
            ?.let { evidence += "hint:ro.boot.verifiedbootstate=$it" }
        if (systemProperty("ro.boot.vbmeta.device_state")?.lowercase() == "unlocked") evidence += "hint:ro.boot.vbmeta.device_state=unlocked"
        if (systemProperty("ro.boot.flash.locked") == "0") evidence += "hint:ro.boot.flash.locked=0"
        if (systemWritable()) evidence += "fs:/system-writable"
        ROOT_PACKAGES.filter(packageInstalled).forEach { evidence += "package:$it" }
        // Only hints raise nothing; an `error:` (properties not read) raises, as a probe that threw does.
        return Signal(evidence.any { !it.startsWith("hint:") }, evidence.distinct())
    }

    companion object {
        /** `ro.boot.verifiedbootstate` values that mean an unlocked bootloader or a failed verification (not `yellow`: a locked custom key). */
        val UNVERIFIED_BOOT_STATES = setOf("orange", "red")
        val SU_PATHS = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su", "/su/bin/su", "/system/su",
            "/vendor/bin/su", "/odm/bin/su", "/product/bin/su", "/system/app/Superuser.apk", "/system/app/SuperSU.apk"
        )
        val ROOT_FILES = listOf(
            "/sbin/.magisk", "/data/adb/magisk", "/data/adb/magisk.db", "/data/adb/modules", "/data/adb/ksu",
            "/data/adb/ap", "/cache/.disable_magisk", "/dev/.magisk.unblock", "/system/addon.d/99-magisk.sh"
        )
        /** Root managers; listed in the library manifest's `<queries>` so they are visible on Android 11+. */
        val ROOT_PACKAGES = listOf(
            "com.topjohnwu.magisk", "io.github.vvb2060.magisk", "io.github.huskydg.magisk", "me.weishu.kernelsu",
            "me.bmax.apatch", "eu.chainfire.supersu", "com.noshufou.android.su", "com.koushikdutta.superuser",
            "com.thirdparty.superuser", "com.kingroot.kinguser", "com.kingo.root", "com.zachspong.temprootremovejb"
        )
    }
}

/** `emulator`: the usual `Build` tells, `ro.kernel.qemu`, the QEMU pipes. */
internal class EmulatorProbe(
    private val build: BuildInfo,
    private val systemProperty: (String) -> String?,
    private val fileExists: (String) -> Boolean
) {
    fun probe(): Signal {
        val evidence = mutableListOf<String>()
        val fp = build.fingerprint.lowercase()
        if (fp.startsWith("generic") || fp.startsWith("unknown")) evidence += "fingerprint:${build.fingerprint.take(32)}"
        val model = build.model.lowercase()
        if (model.contains("google_sdk") || model.contains("emulator") || model.contains("android sdk built for")) {
            evidence += "model:${build.model.take(32)}"
        }
        if (build.manufacturer.equals("Genymotion", ignoreCase = true)) evidence += "manufacturer:Genymotion"
        val hw = build.hardware.lowercase()
        if (hw == "goldfish" || hw == "ranchu" || hw.startsWith("vbox86") || hw.contains("goldfish")) evidence += "hardware:${build.hardware}"
        val product = build.product.lowercase()
        if (product.startsWith("sdk_gphone") || product == "vbox86p" || product.startsWith("sdk") || product.contains("emulator")) {
            evidence += "product:${build.product.take(32)}"
        }
        val brand = build.brand.lowercase()
        if (brand.startsWith("generic") && build.device.lowercase().startsWith("generic")) evidence += "brand:${build.brand}/${build.device}"
        if (systemProperty("ro.kernel.qemu") == "1") evidence += "prop:ro.kernel.qemu=1"
        QEMU_FILES.filter(fileExists).forEach { evidence += "file:$it" }
        return Signal(evidence.isNotEmpty(), evidence.distinct())
    }

    companion object {
        val QEMU_FILES = listOf("/dev/socket/qemud", "/dev/qemu_pipe", "/dev/socket/genyd", "/dev/socket/baseband_genyd")
    }
}

/** `debugger`: a JDWP debugger attached or awaited, or a `TracerPid` in `/proc/self/status`. */
internal class DebuggerProbe(
    private val debuggerConnected: () -> Boolean,
    private val waitingForDebugger: () -> Boolean,
    private val procSelfStatus: () -> String?
) {
    fun probe(): Signal {
        val evidence = mutableListOf<String>()
        if (debuggerConnected()) evidence += "jdwp:connected"
        if (waitingForDebugger()) evidence += "jdwp:waiting"
        tracerPid(procSelfStatus())?.takeIf { it != 0 }?.let { evidence += "tracerpid:$it" }
        return Signal(evidence.isNotEmpty(), evidence)
    }

    companion object {
        /** The `TracerPid:` line of `/proc/self/status`, or null when absent or unreadable. */
        fun tracerPid(status: String?): Int? = status?.lineSequence()
            ?.firstOrNull { it.startsWith("TracerPid:") }
            ?.substringAfter(':')?.trim()?.toIntOrNull()
    }
}

/** `debuggable`: `ApplicationInfo.FLAG_DEBUGGABLE`. */
internal class DebuggableProbe(private val applicationFlags: Int) {
    fun probe(): Signal =
        if (applicationFlags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0) Signal.raised("flag:debuggable") else Signal.CLEAN
}

/**
 * `hooking_framework`: Frida / Xposed / Substrate / Dobby / Riru / LSPosed /
 * Zygisk in the process maps, their thread names, the VirtualXposed property,
 * the Xposed bridge class, Xposed frames on the stack.
 */
internal class HookingProbe(
    /** Distinct mapped paths from `/proc/self/maps`; null when it could not be read. */
    private val mappedPaths: () -> List<String>?,
    /** Names of the process's threads (`/proc/self/task/<tid>/comm` and the JVM's). */
    private val threadNames: () -> List<String>,
    /** `System.getProperty(name)`. */
    private val javaProperty: (String) -> String?,
    private val classLoadable: (String) -> Boolean,
    /** Class names on the current stack. */
    private val stackClasses: () -> List<String>,
    /** Loopback ports among [FRIDA_PORTS] that accept a connection. */
    private val listeningPorts: () -> List<Int> = { emptyList() }
) {
    fun probe(): Signal {
        val evidence = mutableListOf<String>()
        val maps = mappedPaths()
        if (maps == null) evidence += "error:maps"
        maps?.forEach { path ->
            val name = path.substringAfterLast('/').lowercase()
            // Every marker a name carries (`liblsposed.so` is both `lsposed` and `xposed`).
            MAP_MARKERS.filter { name.contains(it) }.forEach { evidence += "maps:$it" }
        }
        threadNames().forEach { thread ->
            val name = thread.lowercase()
            if (THREAD_NAMES.any { name == it || name.startsWith(it) }) evidence += "thread:$thread"
        }
        if (javaProperty("vxp") != null) evidence += "property:vxp"
        XPOSED_CLASSES.filter(classLoadable).forEach { evidence += "class:$it" }
        if (stackClasses().any { frame -> STACK_MARKERS.any { frame.lowercase().contains(it) } }) evidence += "stack:xposed"
        // frida-server's default port. A renamed or re-ported server is not
        // seen here; its agent still shows in the maps and threads above.
        listeningPorts().forEach { evidence += "port:$it" }
        // Maps that could not be read raise too: hiding them is what a hooking framework would do.
        return Signal(evidence.isNotEmpty(), evidence.distinct())
    }

    companion object {
        val FRIDA_PORTS = listOf(27042, 27043)
        val MAP_MARKERS = listOf("frida", "gadget", "xposed", "substrate", "dobby", "riru", "lsposed", "zygisk")
        val THREAD_NAMES = listOf("gmain", "gum-js-loop", "gdbus", "pool-frida", "linjector")
        val XPOSED_CLASSES = listOf("de.robv.android.xposed.XposedBridge", "de.robv.android.xposed.XposedHelpers")
        val STACK_MARKERS = listOf("de.robv.android.xposed", "lsposed", "edxposed")
    }
}

/**
 * `app_integrity`: the client raises it only when the app named the signer
 * digests it expects ([io.github.umutcansu.pinvault.model.PinVaultConfig.Builder.expectedSignerSha256])
 * and none of the APK's signers matches; the server compares the digests
 * with its own list either way.
 */
internal class AppIntegrityProbe(
    /** SHA-256 of the APK's signing certificates, lowercase hex without separators. */
    private val signerSha256: List<String>,
    /** What the app expects, in the same form; empty = the client does not judge. */
    private val expected: Set<String>
) {
    fun probe(): Signal {
        if (expected.isEmpty()) return Signal.CLEAN
        if (signerSha256.isEmpty()) return Signal.raised("signer:unreadable")
        if (signerSha256.any { it in expected }) return Signal.CLEAN
        return Signal(true, signerSha256.map { "signer:${it.take(16)}" })
    }
}

/**
 * `cloner`: the app runs out of a data directory that is not its own —
 * `dataDir` outside `/data/user/<n>/<package>` and `/data/data/<package>`,
 * `filesDir` under another directory, native libraries under another app's data.
 */
internal class ClonerProbe(
    private val packageName: String,
    private val dataDir: String?,
    private val filesDir: String?,
    private val nativeLibraryDir: String?
) {
    fun probe(): Signal {
        val evidence = mutableListOf<String>()
        val own = Regex("^/data/(user(_de)?/\\d+|data)/${Regex.escape(packageName)}/?$")
        dataDir?.let { dir ->
            if (!own.matches(dir)) evidence += "datadir:${dir.take(64)}"
        }
        filesDir?.let { files ->
            val base = dataDir?.trimEnd('/')
            if (base != null && !files.startsWith("$base/")) evidence += "filesdir:${files.take(64)}"
            else if (base == null && !files.contains("/$packageName/")) evidence += "filesdir:${files.take(64)}"
        }
        nativeLibraryDir?.let { lib ->
            // Libraries loaded out of some app's private data directory — a
            // cloner's — rather than from the install location. Only that
            // case: install locations differ too much between ROMs to list.
            val underAppData = lib.startsWith("/data/data/") || lib.startsWith("/data/user/")
            if (underAppData && !lib.contains("/$packageName/")) evidence += "nativelib:${lib.take(64)}"
        }
        return Signal(evidence.isNotEmpty(), evidence)
    }
}

/** `unknown_installer`: not from an allowed store; no installer at all is a sideload. */
internal class InstallerProbe(
    private val installer: String?,
    private val allowed: Set<String> = DEFAULT_ALLOWED
) {
    fun probe(): Signal {
        val name = installer?.trim().orEmpty()
        return when {
            name.isEmpty() -> Signal.raised("sideload")
            name in allowed -> Signal.CLEAN
            else -> Signal.raised("installer:$name")
        }
    }

    companion object {
        /** Play, Samsung, Huawei and Amazon stores (and Play's older installer id). */
        val DEFAULT_ALLOWED = setOf(
            "com.android.vending", "com.google.android.feedback", "com.sec.android.app.samsungapps",
            "com.huawei.appmarket", "com.amazon.venezia"
        )
    }
}

/** `adb_enabled`: `Settings.Global.ADB_ENABLED` or `DEVELOPMENT_SETTINGS_ENABLED`. */
internal class AdbProbe(private val adbEnabled: Int?, private val developmentSettingsEnabled: Int?) {
    fun probe(): Signal {
        val evidence = mutableListOf<String>()
        if (adbEnabled == 1) evidence += "settings:adb_enabled"
        if (developmentSettingsEnabled == 1) evidence += "settings:development_settings_enabled"
        return Signal(evidence.isNotEmpty(), evidence)
    }
}

/** `software_key` and `key_unattested`, from the device key's level and attestation chain. */
internal class KeyProbe(private val level: KeySecurityLevel, private val attested: Boolean) {
    fun softwareKey(): Signal =
        if (level.hardwareBacked) Signal.CLEAN else Signal.raised("key:${level.wireName}")

    fun keyUnattested(): Signal =
        if (attested) Signal.CLEAN else Signal.raised("key:no-attestation-chain")
}

/** The `/proc` and filesystem readers the probes use on a device. */
internal object ProcReaders {
    fun fileExists(path: String): Boolean = try { File(path).exists() } catch (_: Throwable) { false }

    fun systemWritable(): Boolean = try { File("/system").canWrite() } catch (_: Throwable) { false }

    fun procSelfStatus(): String? = readSmall("/proc/self/status")

    /** The distinct mapped paths of this process, from `/proc/self/maps`. */
    fun mappedPaths(): List<String>? = try {
        File("/proc/self/maps").useLines { lines ->
            lines.mapNotNull { line ->
                val path = line.substringAfterLast(' ', "").trim()
                path.takeIf { it.startsWith('/') || it.startsWith('[') }
            }.distinct().take(MAX_ENTRIES).toList()
        }
    } catch (_: Throwable) {
        null
    }

    /** Native thread names from `/proc/self/task/<tid>/comm`, plus the JVM's threads. */
    fun threadNames(): List<String> {
        val names = LinkedHashSet<String>()
        try {
            File("/proc/self/task").listFiles()?.take(MAX_ENTRIES)?.forEach { task ->
                readSmall(File(task, "comm").path)?.trim()?.takeIf { it.isNotEmpty() }?.let { names += it }
            }
        } catch (_: Throwable) {
            // Not readable on this kernel: the JVM's view below still counts.
        }
        try {
            Thread.getAllStackTraces().keys.forEach { names += it.name }
        } catch (_: Throwable) {
            // Nothing more to add.
        }
        return names.toList()
    }

    /** The [ports] on 127.0.0.1 that accept a TCP connection within a short timeout. */
    fun listeningLoopbackPorts(ports: List<Int>): List<Int> = ports.filter { port ->
        try {
            java.net.Socket().use { it.connect(java.net.InetSocketAddress("127.0.0.1", port), 150) }
            true
        } catch (_: Throwable) {
            false
        }
    }

    fun classLoadable(name: String): Boolean = try {
        Class.forName(name)
        true
    } catch (_: Throwable) {
        false
    }

    fun stackClasses(): List<String> = try {
        Thread.currentThread().stackTrace.map { it.className }
    } catch (_: Throwable) {
        emptyList()
    }

    private fun readSmall(path: String): String? = try {
        val file = File(path)
        if (!file.exists()) null else file.inputStream().use { String(it.readBytes().take(MAX_SMALL_FILE).toByteArray(), Charsets.UTF_8) }
    } catch (_: Throwable) {
        null
    }

    private const val MAX_ENTRIES = 4096
    private const val MAX_SMALL_FILE = 64 * 1024
}
