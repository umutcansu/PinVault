package io.github.umutcansu.pinvault.flutter

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import androidx.annotation.NonNull
import androidx.fragment.app.FragmentActivity

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

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
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString

/**
 * The Flutter bridge (`pinvault_flutter`). Every method runs off the platform
 * thread and answers through its result; every structured input is parsed
 * strictly ([ConfigParser], [PinnedFetch]); every result is mapped by
 * [ResultMapper]. Nothing here pins, decrypts or stores anything itself: it
 * calls the `PinVault` object of the Android library.
 *
 * Keys, pins and tokens stay native: the config crosses as a JSON string and
 * is refused unless it is plain data the strict parser accepts.
 */
class PinVaultFlutterPlugin : FlutterPlugin, MethodCallHandler, ActivityAware {

    private lateinit var channel: MethodChannel
    private lateinit var eventsChannel: EventChannel
    private lateinit var guardChannel: EventChannel
    private lateinit var context: Context
    private lateinit var binding: FlutterPlugin.FlutterPluginBinding
    private var activity: FragmentActivity? = null

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mapper = ResultMapper(tokens)
    private val activeSockets = mutableMapOf<String, WebSocket>()

    private var eventSink: EventChannel.EventSink? = null
    private var guardSink: EventChannel.EventSink? = null

    private val mainHandler = Handler(Looper.getMainLooper())

    private fun postToMain(block: () -> Unit) {
        if (Looper.myLooper() == Looper.getMainLooper()) block() else mainHandler.post(block)
    }

    override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        current = this
        this.binding = flutterPluginBinding
        this.context = flutterPluginBinding.applicationContext
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "pinvault_flutter")
        channel.setMethodCallHandler(this)

        eventsChannel = EventChannel(flutterPluginBinding.binaryMessenger, "pinvault_flutter/events")
        eventsChannel.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                eventSink = events
            }
            override fun onCancel(arguments: Any?) {
                eventSink = null
            }
        })

        guardChannel = EventChannel(flutterPluginBinding.binaryMessenger, "pinvault_flutter/guard")
        guardChannel.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                guardSink = events
            }
            override fun onCancel(arguments: Any?) {
                guardSink = null
            }
        })
    }

    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        eventsChannel.setStreamHandler(null)
        guardChannel.setStreamHandler(null)
        scope.cancel()
        if (current == this) current = null
    }

    // ── ActivityAware ────────────────────────────────────────────────────────

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity as? FragmentActivity
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity as? FragmentActivity
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private fun run(result: Result, block: suspend () -> Any?) {
        scope.launch {
            try {
                val value = toBridge(block())
                postToMain { result.success(value) }
            } catch (_: AlreadyAnswered) {
                // The block rejected the result itself.
            } catch (e: BridgeInputException) {
                postToMain { result.error(E_INVALID_ARGUMENT, tokens.redact(e.message), null) }
            } catch (e: IllegalStateException) {
                // The library throws this before init.
                postToMain { result.error(E_NOT_STARTED, tokens.redact(e.message), exceptionInfo(e)) }
            } catch (e: Exception) {
                postToMain { result.error(E_NATIVE, tokens.redact("${e.javaClass.simpleName}: ${e.message}"), exceptionInfo(e)) }
            }
        }
    }

    /** A getter that, like iOS, answers an empty value before `start()` instead of failing. */
    private fun <T> started(default: T, block: () -> T): T =
        if (!startedInProcess) default else try { block() } catch (_: IllegalStateException) { default }

    private fun exceptionInfo(e: Throwable): Map<String, Any?> = mapOf(
        "exceptionName" to e.javaClass.simpleName,
        "exceptionMessage" to tokens.redact(e.message),
    )

    private fun emitGuard(requestId: String, operation: String) {
        postToMain { guardSink?.success(mapOf("requestId" to requestId, "operation" to operation)) }
    }

    private fun rejectNow(result: Result, code: String, message: String): Nothing {
        postToMain { result.error(code, message, null) }
        throw AlreadyAnswered()
    }

    /** The library outlives a hot reload: events and guard questions go to the live plugin. */
    private val connectionListener = PinVaultConnectionListener { event ->
        try {
            val plugin = current ?: return@PinVaultConnectionListener
            val mapped = plugin.mapper.event(event)
            plugin.postToMain { plugin.eventSink?.success(toBridge(mapped)) }
        } catch (_: Exception) {
            // A Dart runtime that is going away; telemetry must never break a handshake.
        }
    }

    // ── onMethodCall ─────────────────────────────────────────────────────────

    override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
        when (call.method) {
            // ── Start / config ──────────────────────────────────────────────
            "start" -> start(call, result)
            "updateNow" -> run(result) { mapper.update(PinVault.updateNow()) }
            "currentVersion" -> run(result) { started(0) { PinVault.currentVersion() } }
            "hostPinVersions" -> run(result) { started(emptyMap()) { PinVault.hostPinVersions() } }
            "pinsForHost" -> run(result) {
                val hostname = call.arguments as? String ?: throw BridgeInputException("hostname: required")
                mapOf("pins" to started(null) { PinVault.pinsForHost(hostname) })
            }
            "signingStatus" -> run(result) {
                val configApiId = call.arguments as? String
                started(null) { PinVault.signingStatus(configApiId) }?.let(mapper::signing)
            }
            "isForceUpdate" -> run(result) { started(false) { PinVault.isForceUpdate() } }
            "reset" -> run(result) {
                started(Unit) { PinVault.reset() }
                null
            }
            "schedulePeriodicUpdates" -> schedulePeriodicUpdates(call, result)
            "cancelPeriodicUpdates" -> run(result) {
                started(Unit) { PinVault.cancelPeriodicUpdates() }
                null
            }
            "enableDebugLogging" -> run(result) {
                val debuggable = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
                if (debuggable) PinVault.enableDebugLogging()
                debuggable
            }

            // ── Pinned HTTP ─────────────────────────────────────────────────
            "fetch" -> fetch(call, result)

            // ── Enrollment ──────────────────────────────────────────────────
            "deviceId" -> run(result) {
                @Suppress("HardwareIds")
                Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
            }
            "enrollForResult" -> run(result) {
                val token = call.argument<String>("token") ?: throw BridgeInputException("token: required")
                val label = call.argument<String?>("label")
                if (token.isEmpty() || token.length > 4096) throw BridgeInputException("token: must be 1 to 4096 characters")
                tokens.withTransientSecretSuspend(token) { mapper.enrollment(PinVault.enrollForResult(context, token, label)) }
            }
            "autoEnrollForResult" -> run(result) { mapper.enrollment(PinVault.autoEnrollForResult(context)) }
            "checkPendingEnrollment" -> run(result) { mapper.enrollment(PinVault.checkPendingEnrollment(context)) }
            "isEnrolled" -> run(result) { PinVault.isEnrolled(context, call.arguments as? String) }
            "isEnrollmentPending" -> run(result) { PinVault.isEnrollmentPending(context, call.arguments as? String) }
            "enrollmentVerificationCode" -> run(result) { PinVault.enrollmentVerificationCode(context, call.arguments as? String) }
            "enrolledClientCN" -> run(result) { PinVault.enrolledClientCN(context, call.arguments as? String) }
            "enrolledClientNotAfter" -> run(result) { PinVault.enrolledClientNotAfter(context, call.arguments as? String) }
            "unenroll" -> run(result) {
                val label = call.argument<String?>("label")
                val wipe = call.argument<Boolean>("wipeVaultFiles") == true
                if (wipe) PinVault.unenroll(context, label, true) else PinVault.unenroll(context, label)
                null
            }
            "identityKeySecurityLevel" -> run(result) { PinVault.identityKeySecurityLevel(call.arguments as? String)?.name }

            // ── Vault files ─────────────────────────────────────────────────
            "setVaultToken" -> run(result) {
                val key = call.argument<String>("key") ?: throw BridgeInputException("key: required")
                val token = call.argument<String?>("token")
                checkKey(key)
                if (token != null && token.length > 4096) throw BridgeInputException("token: longer than 4096 characters")
                tokens.put(key, token)
                null
            }
            "clearVaultTokens" -> run(result) { tokens.clear() }
            "fetchFile" -> run(result) {
                val key = call.argument<String>("key") ?: throw BridgeInputException("key: required")
                val token = call.argument<String?>("token")
                checkKey(key)
                if (token != null) {
                    if (token.length > 4096) throw BridgeInputException("token: longer than 4096 characters")
                    tokens.put(key, token)
                }
                mapper.vaultFile(PinVault.fetchFile(key))
            }
            "loadFile" -> run(result) {
                val key = call.argument<String>("key") ?: throw BridgeInputException("key: required")
                checkKey(key)
                val enc = ResultMapper.checkEncoding(call.argument<String>("encoding") ?: ResultMapper.UTF8)
                started(null) { PinVault.loadFile(key) }?.let { ResultMapper.encode(it, enc) }
            }
            "fileStatus" -> run(result) {
                val key = call.arguments as? String ?: throw BridgeInputException("key: required")
                checkKey(key)
                started(VaultFileStatus.NOT_STORED) { PinVault.fileStatus(key) }.name
            }
            "unlockFile" -> unlockFile(call, result)
            "isFileLocked" -> run(result) {
                val key = call.arguments as? String ?: throw BridgeInputException("key: required")
                checkKey(key)
                started(false) { PinVault.isFileLocked(key) }
            }
            "hasFile" -> run(result) {
                val key = call.arguments as? String ?: throw BridgeInputException("key: required")
                checkKey(key)
                started(false) { PinVault.hasFile(key) }
            }
            "fileVersion" -> run(result) {
                val key = call.arguments as? String ?: throw BridgeInputException("key: required")
                checkKey(key)
                started(0) { PinVault.fileVersion(key) }
            }
            "clearFile" -> run(result) {
                val key = call.arguments as? String ?: throw BridgeInputException("key: required")
                checkKey(key)
                started(Unit) { PinVault.clearFile(key) }
                null
            }
            "syncAllFiles" -> run(result) {
                PinVault.syncAllFiles().mapValues { (_, r) -> mapper.vaultFile(r) }
            }

            // ── Attestation ─────────────────────────────────────────────────
            "attestNow" -> run(result) { mapper.attestation(PinVault.attestNow(call.arguments as? String)) }
            "fetchAttestationToken" -> run(result) { mapper.attestationToken(PinVault.fetchAttestationToken(call.arguments as? String)) }
            "attestationStatus" -> run(result) { mapper.attestation(PinVault.attestationStatus(call.arguments as? String)) }

            // ── environmentGuard ────────────────────────────────────────────
            "answerGuard" -> {
                val requestId = call.argument<String>("requestId")
                val allowed = call.argument<Boolean>("allowed") == true
                if (requestId != null) guard?.answer(requestId, allowed)
                result.success(null)
            }

            // ── WebSocket ───────────────────────────────────────────────────
            "ws_connect" -> wsConnect(call, result)

            else -> result.notImplemented()
        }
    }

    // ── start ────────────────────────────────────────────────────────────────

    private fun start(call: MethodCall, result: Result) {
        val configJson = call.arguments as? String
            ?: return result.error(E_INVALID_CONFIG, "start: a JSON config string is required", null)
        scope.launch {
            startLock.withLock {
                var newGuard: DartEnvironmentGuard? = null
                val parsed = try {
                    ConfigParser.parse(
                        configJson, tokens,
                        guardFactory = { timeout ->
                            DartEnvironmentGuard(timeout) { id, op -> current?.emitGuard(id, op) }.also { newGuard = it }
                        },
                        listener = connectionListener,
                        native = NativeSecurity.load(context),
                        release = NativeSecurity.isReleaseBuild(context),
                        noFileAllowed = NativeSecurity.noFileAllowed(context),
                    )
                } catch (e: IllegalArgumentException) {
                    // The guard of the running config stays: a refused config changes nothing.
                    postToMain { result.error(E_INVALID_CONFIG, tokens.redact(e.message), null) }
                    return@withLock
                }
                try {
                    guard = newGuard
                    // A second start applies the new config: the library keeps the
                    // first one otherwise (the samples restart the same way).
                    if (startedInProcess) PinVault.reset()
                    val initResult = PinVault.init(context, parsed.config)
                    startedInProcess = true
                    // Says whether the anchors came from the native security file (README "Native security file").
                    postToMain {
                        result.success(toBridge(mapper.init(initResult) + ("nativeSecurityApplied" to parsed.nativeSecurityApplied)))
                    }
                } catch (e: Exception) {
                    postToMain { result.error(E_NATIVE, tokens.redact("${e.javaClass.simpleName}: ${e.message}"), exceptionInfo(e)) }
                }
            }
        }
    }

    private fun schedulePeriodicUpdates(call: MethodCall, result: Result) {
        scope.launch {
            if (!startedInProcess) {
                postToMain { result.success(false) }
                return@launch
            }
            val interval = (call.arguments as? Number)?.toLong()
            if (interval != null && (interval < 1 || interval > 24L * 30)) {
                postToMain { result.error(E_INVALID_ARGUMENT, "intervalHours: must be between 1 and 720", null) }
                return@launch
            }
            try {
                val callback: (Boolean) -> Unit = { postToMain { result.success(it) } }
                if (interval == null) PinVault.schedulePeriodicUpdates(onScheduled = callback)
                else PinVault.schedulePeriodicUpdates(interval, callback)
            } catch (e: Exception) {
                postToMain { result.error(E_NATIVE, tokens.redact(e.message), exceptionInfo(e)) }
            }
        }
    }

    // ── fetch ────────────────────────────────────────────────────────────────

    private fun fetch(call: MethodCall, result: Result) {
        val requestJson = call.arguments as? String
            ?: return result.error(E_INVALID_ARGUMENT, "fetch: a JSON request string is required", null)
        scope.launch {
            val request = try {
                PinnedFetch.parse(requestJson)
            } catch (e: IllegalArgumentException) {
                postToMain { result.error(E_INVALID_ARGUMENT, tokens.redact(e.message), null) }
                return@launch
            }
            val client = try {
                if (request.settings != null) PinVault.getClient(request.settings) else PinVault.getClient()
            } catch (e: IllegalStateException) {
                postToMain { result.error(E_NOT_STARTED, "PinVault has not started: call start() first", null) }
                return@launch
            }
            try {
                val response = PinnedFetch.execute(client, request)
                postToMain { result.success(toBridge(response)) }
            } catch (e: Exception) {
                val name = e.javaClass.simpleName
                postToMain { result.error(E_FETCH, tokens.redact("$name: ${e.message}"), exceptionInfo(e)) }
            }
        }
    }

    // ── unlockFile ───────────────────────────────────────────────────────────

    private fun unlockFile(call: MethodCall, result: Result) {
        val key = call.argument<String>("key")
        val promptJson = call.argument<String>("prompt")
        if (key == null || promptJson == null) {
            result.error(E_INVALID_ARGUMENT, "unlockFile: key and prompt are required", null)
            return
        }
        scope.launch {
            try {
                checkKey(key)
                val (prompt, encoding) = ConfigParser.unlockPrompt(promptJson)
                val act = activity
                    ?: return@launch rejectNow(result, E_NO_ACTIVITY, "unlockFile needs a FragmentActivity in the foreground")
                val value = mapper.unlock(PinVault.unlockFile(act, key, prompt), encoding)
                postToMain { result.success(toBridge(value)) }
            } catch (_: AlreadyAnswered) {
            } catch (e: BridgeInputException) {
                postToMain { result.error(E_INVALID_ARGUMENT, tokens.redact(e.message), null) }
            } catch (e: IllegalStateException) {
                postToMain { result.error(E_NOT_STARTED, tokens.redact(e.message), exceptionInfo(e)) }
            } catch (e: Exception) {
                postToMain { result.error(E_NATIVE, tokens.redact("${e.javaClass.simpleName}: ${e.message}"), exceptionInfo(e)) }
            }
        }
    }

    // ── WebSocket ────────────────────────────────────────────────────────────

    private fun wsConnect(call: MethodCall, result: Result) {
        val socketId = call.argument<String>("socketId")
        val url = call.argument<String>("url")
        if (socketId == null || url == null) {
            result.error(E_INVALID_ARGUMENT, "ws_connect: socketId and url are required", null)
            return
        }
        if (!url.startsWith("wss://")) {
            result.error(E_INVALID_ARGUMENT, "Security Violation: only wss:// is allowed by PinVault.", null)
            return
        }
        val headers = call.argument<Map<String, String>>("headers") ?: emptyMap()
        setupWebSocket(socketId, url, headers)
        result.success(null)
    }

    private fun setupWebSocket(socketId: String, url: String, headers: Map<String, String>) {
        val eventChannel = EventChannel(binding.binaryMessenger, "pinvault_flutter/ws/$socketId/events")
        val methodChannel = MethodChannel(binding.binaryMessenger, "pinvault_flutter/ws/$socketId/methods")

        var eventSink: EventChannel.EventSink? = null

        methodChannel.setMethodCallHandler { call, result ->
            when (call.method) {
                "send" -> {
                    val ws = activeSockets[socketId]
                    if (ws == null) {
                        result.error(E_NOT_STARTED, "socket is not open", null)
                        return@setMethodCallHandler
                    }
                    val data = call.argument<Any>("data")
                    when (data) {
                        is String -> ws.send(data)
                        is ByteArray -> ws.send(ByteString.of(*data))
                        else -> {
                            result.error(E_INVALID_ARGUMENT, "send: data must be a string or bytes", null)
                            return@setMethodCallHandler
                        }
                    }
                    result.success(null)
                }
                "close" -> {
                    val code = call.argument<Int>("code") ?: 1000
                    val reason = call.argument<String>("reason")
                    activeSockets[socketId]?.close(code, reason)
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }

        eventChannel.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                eventSink = events
                val client = try {
                    PinVault.getClient()
                } catch (e: IllegalStateException) {
                    events?.success(mapOf("type" to "error", "error" to "PinVault has not started: call start() first"))
                    return
                }
                val requestBuilder = Request.Builder().url(url)
                headers.forEach { (k, v) -> requestBuilder.addHeader(k, v) }
                val ws = client.newWebSocket(requestBuilder.build(), object : WebSocketListener() {
                    override fun onMessage(webSocket: WebSocket, text: String) {
                        postToMain { eventSink?.success(mapOf("type" to "message", "data" to text)) }
                    }

                    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                        postToMain { eventSink?.success(mapOf("type" to "message", "data" to bytes.toByteArray())) }
                    }

                    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                        postToMain { eventSink?.success(mapOf("type" to "closed", "code" to code, "reason" to reason)) }
                    }

                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        postToMain { eventSink?.success(mapOf("type" to "error", "error" to t.message)) }
                    }
                })
                activeSockets[socketId] = ws
            }

            override fun onCancel(arguments: Any?) {
                activeSockets.remove(socketId)?.close(1000, "Cancelled")
                eventSink = null
            }
        })
    }

    private fun checkKey(key: String) {
        if (!VAULT_KEY.matches(key) || key.all { it == '.' }) {
            throw BridgeInputException("key: must match [A-Za-z0-9._-]{1,64} and not be only dots")
        }
    }

    companion object {
        const val E_INVALID_CONFIG = "E_INVALID_CONFIG"
        const val E_INVALID_ARGUMENT = "E_INVALID_ARGUMENT"
        const val E_NOT_STARTED = "E_NOT_STARTED"
        const val E_FETCH = "E_FETCH"
        const val E_NO_ACTIVITY = "E_NO_ACTIVITY"
        const val E_NATIVE = "E_NATIVE"

        /** Process-wide: the library is a process singleton, a hot reload makes a new plugin. */
        @Volatile private var current: PinVaultFlutterPlugin? = null
        @Volatile private var startedInProcess = false
        @Volatile private var guard: DartEnvironmentGuard? = null
        private val startLock = Mutex()
        private val tokens = VaultTokenStore()

        /** Plain values → platform values (maps, lists, numbers). */
        internal fun toBridge(value: Any?): Any? = when (value) {
            null, is Unit -> null
            is String, is Boolean, is Int, is Long, is Double, is ByteArray -> value
            is Number -> value.toDouble()
            is Map<*, *> -> LinkedHashMap<String, Any?>().apply {
                value.forEach { (k, v) -> put(k?.toString() ?: "", toBridge(v)) }
            }
            is List<*> -> ArrayList<Any?>(value.size).apply { value.forEach { add(toBridge(it)) } }
            is CharSequence -> value.toString()
            else -> value.toString()
        }
    }

    /** Thrown after the result was already answered; [run] must not answer again. */
    private class AlreadyAnswered : RuntimeException()
}

private val VAULT_KEY = Regex("^[A-Za-z0-9._-]{1,64}$")
