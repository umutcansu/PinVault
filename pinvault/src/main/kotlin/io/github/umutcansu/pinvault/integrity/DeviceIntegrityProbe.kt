package io.github.umutcansu.pinvault.integrity

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider
import io.github.umutcansu.pinvault.model.KeySecurityLevel
import kotlinx.coroutines.withTimeout
import timber.log.Timber
import java.security.MessageDigest

/**
 * Builds the [IntegrityReport] of `ATTESTATION.md` §3 from the probes in
 * this package. Best effort throughout: a probe that throws contributes
 * `error:<probe>` evidence, never a crash, and never a false "clean"; a
 * reader of the app or device blocks that fails leaves its field empty.
 *
 * The report is a measurement by code the attacker can hook — see §3 of the
 * design for why it is still worth making. Apps that want a second opinion
 * plug in an [IntegrityVerdictProvider]; its token goes along verbatim.
 */
internal class DeviceIntegrityProbe(
    private val context: Context,
    /** Signer digests the app expects (lowercase hex, no separators); empty = the client does not judge `app_integrity`. */
    private val expectedSignerSha256: Set<String> = emptySet(),
    private val verdictProvider: IntegrityVerdictProvider? = null,
    private val clock: () -> Long = System::currentTimeMillis,
    private val systemProperty: (String) -> String? = SystemProperties::get,
    private val fileExists: (String) -> Boolean = ProcReaders::fileExists
) {

    /**
     * The report for this attestation round. [nonce] goes to the verdict
     * provider only; the report itself is bound to the nonce by the
     * signature over the canonical string. [key] is the block's device key,
     * for the key signals; null when it cannot be read (reported as unknown
     * and unattested).
     */
    suspend fun report(nonce: String, key: ClientIdentityKeyProvider?, deviceId: String? = null): IntegrityReport {
        val app = appInfo()
        val signers = app.signerSha256
        val keyLevel = try { key?.securityLevel() ?: KeySecurityLevel.UNKNOWN } catch (e: Exception) { KeySecurityLevel.UNKNOWN }
        val keyAttested = try { key?.attestationChain()?.isNotEmpty() == true } catch (e: Exception) { false } catch (e: LinkageError) { false }
        val device = deviceInfo(keyLevel, keyAttested)
        val keyProbe = KeyProbe(keyLevel, keyAttested)

        val signals = LinkedHashMap<String, Signal>()
        signals[IntegrityReport.ROOTED] = safe(IntegrityReport.ROOTED) {
            RootProbe(
                fileExists = fileExists,
                buildTags = Build.TAGS,
                systemProperty = systemProperty,
                packageInstalled = ::packageInstalled,
                systemWritable = ProcReaders::systemWritable,
                pathEnv = System.getenv("PATH")
            ).probe()
        }
        signals[IntegrityReport.EMULATOR] = safe(IntegrityReport.EMULATOR) {
            EmulatorProbe(BuildInfo.current(), systemProperty, fileExists).probe()
        }
        signals[IntegrityReport.DEBUGGER] = safe(IntegrityReport.DEBUGGER) {
            DebuggerProbe(
                debuggerConnected = { android.os.Debug.isDebuggerConnected() },
                waitingForDebugger = { android.os.Debug.waitingForDebugger() },
                procSelfStatus = ProcReaders::procSelfStatus
            ).probe()
        }
        signals[IntegrityReport.DEBUGGABLE] = safe(IntegrityReport.DEBUGGABLE) {
            DebuggableProbe(context.applicationInfo.flags).probe()
        }
        signals[IntegrityReport.HOOKING_FRAMEWORK] = safe(IntegrityReport.HOOKING_FRAMEWORK) {
            HookingProbe(
                mappedPaths = ProcReaders::mappedPaths,
                threadNames = ProcReaders::threadNames,
                javaProperty = { System.getProperty(it) },
                classLoadable = ProcReaders::classLoadable,
                stackClasses = ProcReaders::stackClasses,
                listeningPorts = { ProcReaders.listeningLoopbackPorts(HookingProbe.FRIDA_PORTS) }
            ).probe()
        }
        signals[IntegrityReport.APP_INTEGRITY] = safe(IntegrityReport.APP_INTEGRITY) {
            AppIntegrityProbe(signers, expectedSignerSha256).probe()
        }
        signals[IntegrityReport.CLONER] = safe(IntegrityReport.CLONER) {
            val info = context.applicationInfo
            ClonerProbe(
                packageName = context.packageName,
                dataDir = info.dataDir,
                filesDir = runCatching { context.filesDir?.absolutePath }.getOrNull(),
                nativeLibraryDir = info.nativeLibraryDir
            ).probe()
        }
        signals[IntegrityReport.UNKNOWN_INSTALLER] = safe(IntegrityReport.UNKNOWN_INSTALLER) {
            InstallerProbe(app.installer).probe()
        }
        signals[IntegrityReport.ADB_ENABLED] = safe(IntegrityReport.ADB_ENABLED) {
            val resolver = context.contentResolver
            AdbProbe(
                adbEnabled = Settings.Global.getInt(resolver, Settings.Global.ADB_ENABLED, 0),
                developmentSettingsEnabled = Settings.Global.getInt(resolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0)
            ).probe()
        }
        signals[IntegrityReport.SOFTWARE_KEY] = safe(IntegrityReport.SOFTWARE_KEY) { keyProbe.softwareKey() }
        signals[IntegrityReport.KEY_UNATTESTED] = safe(IntegrityReport.KEY_UNATTESTED) { keyProbe.keyUnattested() }
        // Decided by the server from device.securityPatch; sent down so the key is always present.
        signals[IntegrityReport.OLD_PATCH_LEVEL] = Signal.CLEAN

        return IntegrityReport(
            sdkVersion = IntegrityReport.SDK_VERSION,
            reportTime = clock(),
            app = app,
            device = device,
            signals = signals,
            verdict = verdict(nonce, deviceId)
        )
    }

    /** Runs one probe; a failure of any kind is evidence, not an exception. */
    private inline fun safe(name: String, probe: () -> Signal): Signal = try {
        probe()
    } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
    } catch (e: Throwable) {
        Timber.w(e, "Integrity probe '%s' failed", name)
        Signal.error(name)
    }

    private suspend fun verdict(nonce: String, deviceId: String?): IntegrityVerdict? {
        val provider = verdictProvider ?: return null
        return try {
            withTimeout(VERDICT_TIMEOUT_MS) { if (deviceId != null) provider.verdict(nonce, deviceId) else provider.verdict(nonce) }
        } catch (e: kotlinx.coroutines.CancellationException) {
            if (e is kotlinx.coroutines.TimeoutCancellationException) {
                Timber.w("Integrity verdict provider took longer than %d ms — attesting without it", VERDICT_TIMEOUT_MS)
                null
            } else {
                throw e
            }
        } catch (e: Exception) {
            Timber.w(e, "Integrity verdict provider failed — attesting without it")
            null
        }
    }

    private fun appInfo(): AppInfo {
        val packageName = context.packageName
        val pm = context.packageManager
        val info = try { pm.getPackageInfo(packageName, 0) } catch (e: Exception) { null }
        val versionCode = when {
            info == null -> 0L
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> info.longVersionCode
            else -> legacyVersionCode(info)
        }
        val debuggable = try {
            context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0
        } catch (e: Exception) {
            false
        }
        return AppInfo(
            packageName = packageName,
            versionCode = versionCode,
            versionName = info?.versionName,
            signerSha256 = try { signerDigests(pm, packageName) } catch (e: Exception) { emptyList() },
            installer = try { installer(pm, packageName) } catch (e: Exception) { null },
            debuggable = debuggable
        )
    }

    @Suppress("DEPRECATION")
    private fun legacyVersionCode(info: android.content.pm.PackageInfo): Long = info.versionCode.toLong()

    /**
     * SHA-256 of each current signing certificate, lowercase hex. On Android 9+
     * `apkContentsSigners`: the certificates that signed this APK, without the
     * past certificates a rotated app still proves it may use.
     */
    @Suppress("DEPRECATION", "PackageManagerGetSignatures")
    private fun signerDigests(pm: PackageManager, packageName: String): List<String> {
        val signatures: Array<android.content.pm.Signature>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo?.apkContentsSigners
        } else {
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures
        }
        return signatures.orEmpty().map { hex(MessageDigest.getInstance("SHA-256").digest(it.toByteArray())) }
    }

    @Suppress("DEPRECATION")
    private fun installer(pm: PackageManager, packageName: String): String? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(packageName).installingPackageName
        } else {
            pm.getInstallerPackageName(packageName)
        }

    private fun packageInstalled(name: String): Boolean = try {
        context.packageManager.getPackageInfo(name, 0)
        true
    } catch (e: Exception) {
        false
    }

    private fun deviceInfo(keyLevel: KeySecurityLevel, keyAttested: Boolean): DeviceInfo {
        val build = BuildInfo.current()
        return DeviceInfo(
            manufacturer = build.manufacturer,
            model = build.model,
            brand = build.brand,
            device = build.device,
            product = build.product,
            hardware = build.hardware,
            fingerprint = build.fingerprint,
            sdkInt = Build.VERSION.SDK_INT,
            securityPatch = try { Build.VERSION.SECURITY_PATCH?.ifBlank { null } } catch (e: Throwable) { null },
            verifiedBootState = systemProperty("ro.boot.verifiedbootstate"),
            keySecurityLevel = keyLevel.wireName,
            keyAttested = keyAttested
        )
    }

    companion object {
        /** How long an [IntegrityVerdictProvider] may take. */
        const val VERDICT_TIMEOUT_MS = 10_000L
    }
}
