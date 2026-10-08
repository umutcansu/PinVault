package io.github.umutcansu.pinvault.reactnative

import android.content.pm.ApplicationInfo
import android.provider.Settings
import androidx.fragment.app.FragmentActivity
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.WritableArray
import com.facebook.react.bridge.WritableMap
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.api.PinVaultConnectionListener
import io.github.umutcansu.pinvault.model.VaultFileStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The TurboModule (`RNPinVault`). Every method runs off the JS thread and
 * answers through its promise; every structured input is parsed strictly
 * ([ConfigParser], [PinnedFetch]); every result is mapped by [ResultMapper].
 * Nothing here pins, decrypts or stores anything itself: it calls the
 * `PinVault` object of the Android library.
 */
class PinVaultModule(reactContext: ReactApplicationContext) : NativePinVaultSpec(reactContext) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val app get() = reactApplicationContext.applicationContext
    private val mapper = ResultMapper(tokens)

    init {
        current = this
    }

    override fun getName(): String = NAME

    override fun invalidate() {
        scope.cancel()
        super.invalidate()
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private fun run(promise: Promise, block: suspend () -> Any?) {
        scope.launch {
            try {
                promise.resolve(toBridge(block()))
            } catch (_: AlreadyAnswered) {
                // The block rejected the promise itself.
            } catch (e: BridgeInputException) {
                promise.reject(E_INVALID_ARGUMENT, tokens.redact(e.message))
            } catch (e: IllegalStateException) {
                // The library throws this before init.
                promise.reject(E_NOT_STARTED, tokens.redact(e.message), exceptionInfo(e))
            } catch (e: Exception) {
                promise.reject(E_NATIVE, tokens.redact("${e.javaClass.simpleName}: ${e.message}"), exceptionInfo(e))
            }
        }
    }

    /** A getter that, like iOS, answers an empty value before `start()` instead of failing. */
    private fun <T> started(default: T, block: () -> T): T =
        if (!startedInProcess) default else try { block() } catch (_: IllegalStateException) { default }

    private fun exceptionInfo(e: Throwable): WritableMap = Arguments.createMap().apply {
        putString("exceptionName", e.javaClass.simpleName)
        putString("exceptionMessage", tokens.redact(e.message))
    }

    private fun emitGuard(requestId: String, operation: String) {
        emitOnGuardRequest(Arguments.createMap().apply {
            putString("requestId", requestId)
            putString("operation", operation)
        })
    }

    // The library outlives a JS reload: events and guard questions go to the live module.
    private val connectionListener = PinVaultConnectionListener { event ->
        try {
            val module = current ?: return@PinVaultConnectionListener
            module.emitOnConnectionEvent(toBridge(module.mapper.event(event)) as WritableMap)
        } catch (_: Exception) {
            // A JS runtime that is going away; telemetry must never break a handshake.
        }
    }

    // ── Start / config ───────────────────────────────────────────────────────

    override fun start(configJson: String, promise: Promise) {
        scope.launch {
            startLock.withLock {
                var newGuard: JsEnvironmentGuard? = null
                val parsed = try {
                    ConfigParser.parse(
                        configJson, tokens,
                        guardFactory = { timeout ->
                            JsEnvironmentGuard(timeout) { id, op -> current?.emitGuard(id, op) }.also { newGuard = it }
                        },
                        listener = connectionListener,
                        native = NativeSecurity.load(app),
                        release = NativeSecurity.isReleaseBuild(app),
                    )
                } catch (e: IllegalArgumentException) {
                    // The guard of the running config stays: a refused config changes nothing.
                    promise.reject(E_INVALID_CONFIG, tokens.redact(e.message))
                    return@launch
                }
                try {
                    if (!parsed.pinGlobalNetworking && PinVaultNetworking.isInstalled) {
                        promise.reject(
                            E_INVALID_CONFIG,
                            "config.android.pinGlobalNetworking: false, but React Native's networking is already pinned " +
                                "(the plugin's content provider, or PinVaultNetworking.install); opt out natively: " +
                                "remove the provider in the app's manifest (tools:node=\"remove\", README \"Networking\")",
                        )
                        return@launch
                    }
                    if (parsed.pinGlobalNetworking) PinVaultNetworking.install(app)
                    val hooks = PinVaultNetworking.warnIfNotPinned("PinVault.start")
                    if (parsed.networking.requirePinned && !hooks.pinned) {
                        promise.reject(E_NETWORKING_NOT_PINNED, "requirePinnedReactNativeNetworking: ${hooks.describe()}")
                        return@launch
                    }
                    guard = newGuard
                    // A second start applies the new config: the library keeps the
                    // first one otherwise (the samples restart the same way).
                    if (startedInProcess) {
                        PinVaultNetworking.pinning.deactivate()
                        PinVault.reset()
                    }
                    PinVaultNetworking.pinning.options = parsed.networking
                    val result = PinVault.init(app, parsed.config)
                    startedInProcess = true
                    if (PinVaultNetworking.isInstalled) {
                        try {
                            PinVaultNetworking.pinning.activate(parsed.networking)
                        } catch (_: IllegalStateException) {
                            // Setup failed (InitResult.Failed): RN's https stays refused.
                        }
                    }
                    promise.resolve(toBridge(mapper.init(result)))
                } catch (e: Exception) {
                    promise.reject(E_NATIVE, tokens.redact("${e.javaClass.simpleName}: ${e.message}"), exceptionInfo(e))
                }
            }
        }
    }

    override fun updateNow(promise: Promise) = run(promise) { mapper.update(PinVault.updateNow()) }

    override fun currentVersion(promise: Promise) = run(promise) { started(0) { PinVault.currentVersion() } }

    override fun hostPinVersions(promise: Promise) = run(promise) { started(emptyMap()) { PinVault.hostPinVersions() } }

    override fun pinsForHost(hostname: String, promise: Promise) = run(promise) {
        mapOf("pins" to started(null) { PinVault.pinsForHost(hostname) })
    }

    override fun signingStatus(configApiId: String?, promise: Promise) = run(promise) {
        started(null) { PinVault.signingStatus(configApiId) }?.let(mapper::signing)
    }

    override fun isForceUpdate(promise: Promise) = run(promise) { started(false) { PinVault.isForceUpdate() } }

    override fun reset(promise: Promise) = run(promise) {
        started(Unit) { PinVault.reset() }
        null
    }

    override fun schedulePeriodicUpdates(intervalHours: Double?, promise: Promise) {
        if (!startedInProcess) return promise.resolve(false)
        val hours = intervalHours?.toLong()
        if (hours != null && (hours < 1 || hours > 24L * 30)) {
            return promise.reject(E_INVALID_ARGUMENT, "intervalHours: must be between 1 and 720")
        }
        try {
            val callback: (Boolean) -> Unit = { promise.resolve(it) }
            if (hours == null) PinVault.schedulePeriodicUpdates(onScheduled = callback)
            else PinVault.schedulePeriodicUpdates(hours, callback)
        } catch (e: Exception) {
            promise.reject(E_NATIVE, tokens.redact(e.message), exceptionInfo(e))
        }
    }

    override fun cancelPeriodicUpdates(promise: Promise) = run(promise) {
        started(Unit) { PinVault.cancelPeriodicUpdates() }
        null
    }

    override fun enableDebugLogging(promise: Promise) = run(promise) {
        val debuggable = (app.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (debuggable) PinVault.enableDebugLogging()
        debuggable
    }

    // ── Pinned HTTP ──────────────────────────────────────────────────────────

    override fun fetch(requestJson: String, promise: Promise) {
        scope.launch {
            // RN's own fetch is pinned only while both hooks are PinVault's: say so when another library replaced one.
            if (PinVaultNetworking.isInstalled) PinVaultNetworking.warnIfNotPinned("PinVault.fetch")
            val request = try {
                PinnedFetch.parse(requestJson)
            } catch (e: IllegalArgumentException) {
                promise.reject(E_INVALID_ARGUMENT, tokens.redact(e.message))
                return@launch
            }
            val client = try {
                if (request.settings != null) PinVault.getClient(request.settings) else PinVault.getClient()
            } catch (e: IllegalStateException) {
                promise.reject(E_NOT_STARTED, "PinVault has not started: call start() first")
                return@launch
            }
            try {
                promise.resolve(toBridge(PinnedFetch.execute(client, request)))
            } catch (e: Exception) {
                val name = e.javaClass.simpleName
                promise.reject(E_FETCH, tokens.redact("$name: ${e.message}"), exceptionInfo(e))
            }
        }
    }

    // ── Enrollment ───────────────────────────────────────────────────────────

    override fun deviceId(promise: Promise) = run(promise) {
        @Suppress("HardwareIds")
        Settings.Secure.getString(app.contentResolver, Settings.Secure.ANDROID_ID)
    }

    override fun enrollForResult(token: String, label: String?, promise: Promise) = run(promise) {
        if (token.isEmpty() || token.length > 4096) throw BridgeInputException("token: must be 1 to 4096 characters")
        tokens.withTransientSecretSuspend(token) { mapper.enrollment(PinVault.enrollForResult(app, token, label)) }
    }

    override fun autoEnrollForResult(promise: Promise) = run(promise) { mapper.enrollment(PinVault.autoEnrollForResult(app)) }

    override fun checkPendingEnrollment(promise: Promise) = run(promise) { mapper.enrollment(PinVault.checkPendingEnrollment(app)) }

    override fun isEnrolled(label: String?, promise: Promise) = run(promise) { PinVault.isEnrolled(app, label) }

    override fun isEnrollmentPending(label: String?, promise: Promise) = run(promise) { PinVault.isEnrollmentPending(app, label) }

    override fun enrollmentVerificationCode(label: String?, promise: Promise) = run(promise) {
        PinVault.enrollmentVerificationCode(app, label)
    }

    override fun enrolledClientCN(label: String?, promise: Promise) = run(promise) { PinVault.enrolledClientCN(app, label) }

    override fun enrolledClientNotAfter(label: String?, promise: Promise) = run(promise) {
        PinVault.enrolledClientNotAfter(app, label)
    }

    override fun unenroll(label: String?, wipeVaultFiles: Boolean, promise: Promise) = run(promise) {
        if (wipeVaultFiles) PinVault.unenroll(app, label, true) else PinVault.unenroll(app, label)
        null
    }

    override fun identityKeySecurityLevel(label: String?, promise: Promise) = run(promise) {
        PinVault.identityKeySecurityLevel(label)?.name
    }

    // ── Vault files ──────────────────────────────────────────────────────────

    override fun setVaultToken(key: String, token: String?, promise: Promise) = run(promise) {
        checkKey(key)
        if (token != null && token.length > 4096) throw BridgeInputException("token: longer than 4096 characters")
        tokens.put(key, token)
        null
    }

    override fun clearVaultTokens(promise: Promise) = run(promise) { tokens.clear() }

    override fun fetchFile(key: String, token: String?, promise: Promise) = run(promise) {
        checkKey(key)
        if (token != null) {
            if (token.length > 4096) throw BridgeInputException("token: longer than 4096 characters")
            tokens.put(key, token)
        }
        mapper.vaultFile(PinVault.fetchFile(key))
    }

    override fun loadFile(key: String, encoding: String, promise: Promise) = run(promise) {
        checkKey(key)
        val enc = ResultMapper.checkEncoding(encoding)
        started(null) { PinVault.loadFile(key) }?.let { ResultMapper.encode(it, enc) }
    }

    override fun fileStatus(key: String, promise: Promise) = run(promise) {
        checkKey(key)
        started(VaultFileStatus.NOT_STORED) { PinVault.fileStatus(key) }.name
    }

    override fun unlockFile(key: String, promptJson: String, promise: Promise) = run(promise) {
        checkKey(key)
        val (prompt, encoding) = ConfigParser.unlockPrompt(promptJson)
        val activity = reactApplicationContext.currentActivity as? FragmentActivity
            ?: return@run rejectNow(promise, E_NO_ACTIVITY, "unlockFile needs a FragmentActivity in the foreground")
        // The library shows BiometricPrompt on the main thread itself.
        mapper.unlock(PinVault.unlockFile(activity, key, prompt), encoding)
    }

    override fun isFileLocked(key: String, promise: Promise) = run(promise) { checkKey(key); started(false) { PinVault.isFileLocked(key) } }

    override fun hasFile(key: String, promise: Promise) = run(promise) { checkKey(key); started(false) { PinVault.hasFile(key) } }

    override fun fileVersion(key: String, promise: Promise) = run(promise) { checkKey(key); started(0) { PinVault.fileVersion(key) } }

    override fun clearFile(key: String, promise: Promise) = run(promise) {
        checkKey(key)
        started(Unit) { PinVault.clearFile(key) }
        null
    }

    override fun syncAllFiles(promise: Promise) = run(promise) {
        PinVault.syncAllFiles().mapValues { (_, r) -> mapper.vaultFile(r) }
    }

    // ── Attestation ──────────────────────────────────────────────────────────

    override fun attestNow(configApiId: String?, promise: Promise) = run(promise) { mapper.attestation(PinVault.attestNow(configApiId)) }

    override fun fetchAttestationToken(host: String?, promise: Promise) = run(promise) {
        mapper.attestationToken(PinVault.fetchAttestationToken(host))
    }

    override fun attestationStatus(configApiId: String?, promise: Promise) = run(promise) {
        mapper.attestation(PinVault.attestationStatus(configApiId))
    }

    // ── environmentGuard ─────────────────────────────────────────────────────

    override fun answerGuard(requestId: String, allowed: Boolean) {
        guard?.answer(requestId, allowed)
    }

    private fun checkKey(key: String) {
        if (key.isEmpty() || key.length > 128) throw BridgeInputException("key: must be 1 to 128 characters")
    }

    private fun rejectNow(promise: Promise, code: String, message: String): Nothing {
        promise.reject(code, message)
        throw AlreadyAnswered()
    }

    /** Thrown after the promise was already rejected; [run] must not answer again. */
    private class AlreadyAnswered : RuntimeException()

    companion object {
        const val NAME = NativePinVaultSpec.NAME

        const val E_INVALID_CONFIG = "E_INVALID_CONFIG"
        const val E_INVALID_ARGUMENT = "E_INVALID_ARGUMENT"
        const val E_NOT_STARTED = "E_NOT_STARTED"
        const val E_FETCH = "E_FETCH"
        const val E_NO_ACTIVITY = "E_NO_ACTIVITY"
        const val E_NATIVE = "E_NATIVE"
        const val E_NETWORKING_NOT_PINNED = "E_NETWORKING_NOT_PINNED"

        /** Process-wide: the library is a process singleton, a JS reload makes a new module. */
        @Volatile private var current: PinVaultModule? = null
        @Volatile private var startedInProcess = false
        @Volatile private var guard: JsEnvironmentGuard? = null
        private val startLock = Mutex()
        private val tokens = VaultTokenStore()

        /** Plain values → bridge values (maps, lists, numbers as doubles). */
        internal fun toBridge(value: Any?): Any? = when (value) {
            null, is Unit -> null
            is String, is Boolean -> value
            is Int -> value
            is Long -> value.toDouble()
            is Number -> value.toDouble()
            is Map<*, *> -> Arguments.createMap().also { map ->
                value.forEach { (k, v) -> putInto(map, k as String, toBridge(v)) }
            }
            is List<*> -> Arguments.createArray().also { array -> value.forEach { pushInto(array, toBridge(it)) } }
            else -> value.toString()
        }

        private fun putInto(map: WritableMap, key: String, v: Any?) {
            when (v) {
                null -> map.putNull(key)
                is String -> map.putString(key, v)
                is Boolean -> map.putBoolean(key, v)
                is Int -> map.putInt(key, v)
                is Double -> map.putDouble(key, v)
                is WritableMap -> map.putMap(key, v)
                is WritableArray -> map.putArray(key, v)
                else -> map.putString(key, v.toString())
            }
        }

        private fun pushInto(array: WritableArray, v: Any?) {
            when (v) {
                null -> array.pushNull()
                is String -> array.pushString(v)
                is Boolean -> array.pushBoolean(v)
                is Int -> array.pushInt(v)
                is Double -> array.pushDouble(v)
                is WritableMap -> array.pushMap(v)
                is WritableArray -> array.pushArray(v)
                else -> array.pushString(v.toString())
            }
        }
    }
}
